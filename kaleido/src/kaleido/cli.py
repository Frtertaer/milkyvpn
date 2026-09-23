"""Command-line entry point for the Kaleido research tools."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import BinaryIO

from .config import ConfigError, EndpointConfig, generate_keys, load_config
from .fieldexport import (
    DEFAULT_MATERIAL_LIFETIME_SECONDS,
    FieldExportError,
    build_field_material_envelope,
)
from .runtime import Carrier, EventBus, make_client_ssl_context, make_server_ssl_context
from .selector import CarrierClass, Observation, score_carriers


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kaleido",
        description="Kaleido protocol research and measurement utilities",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    score = subparsers.add_parser("score", help="rank carriers from JSON observations")
    score.add_argument("input", type=Path, help="JSON array of observations")
    score.add_argument("--now", type=float, default=None)

    keygen = subparsers.add_parser("keygen", help="generate a PSK and Ed25519 identity")
    keygen.add_argument("--output", type=Path, required=True, help="new key directory")

    validate = subparsers.add_parser("validate", help="validate an endpoint config")
    validate.add_argument("--config", type=Path, required=True, help="JSON config file")

    server = subparsers.add_parser("server", help="launch one server carrier")
    server.add_argument("--config", type=Path, required=True, help="server JSON config")
    server.add_argument(
        "--allow-lab-protocol", action="store_true", help="explicitly permit lab protocol mode"
    )

    client = subparsers.add_parser("client", help="launch one client carrier")
    client.add_argument("--config", type=Path, required=True, help="client JSON config")
    client.add_argument(
        "--allow-lab-protocol", action="store_true", help="explicitly permit lab protocol mode"
    )
    client.add_argument(
        "--allow-insecure-lab",
        action="store_true",
        help="explicitly permit disabled TLS verification in lab mode",
    )

    field_export = subparsers.add_parser(
        "field-export-material",
        help="emit short-lived field material to stdout for a direct SSH pipe",
    )
    field_export.add_argument("--config", type=Path, required=True, help="server JSON config")
    field_export.add_argument(
        "--endpoint-ipv4", required=True, help="fixed public IPv4 carrier endpoint"
    )
    field_export.add_argument("--key-slot-id", required=True, help="opaque key-slot label")
    field_export.add_argument(
        "--lifetime-seconds",
        type=int,
        default=DEFAULT_MATERIAL_LIFETIME_SECONDS,
        help="envelope lifetime, at most 900 seconds",
    )
    return parser


def _score(path: Path, now: float | None) -> int:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("score input must be a JSON array")
    observations: list[Observation] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each observation must be an object")
        observations.append(
            Observation(
                carrier=str(item["carrier"]),
                carrier_class=CarrierClass(str(item["carrier_class"])),
                success=bool(item["success"]),
                handshake_ms=float(item["handshake_ms"])
                if item.get("handshake_ms") is not None
                else None,
                goodput_mbps=float(item["goodput_mbps"])
                if item.get("goodput_mbps") is not None
                else None,
                recovery_ms=float(item["recovery_ms"])
                if item.get("recovery_ms") is not None
                else None,
                battery_cost=float(item.get("battery_cost", 0.0)),
                observed_at=float(item["observed_at"]),
            )
        )
    print(  # noqa: T201 - CLI output is intentional.
        json.dumps(
            [
                {"carrier": score.carrier, "score": score.value, "samples": score.samples}
                for score in score_carriers(observations, now=now)
            ],
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _keygen(output: Path) -> int:
    paths, fingerprint = generate_keys(output)
    print(  # noqa: T201 - intentional CLI output; never contains private material.
        json.dumps(
            {
                "files": [str(path) for path in paths],
                "server_identity_fingerprint": fingerprint,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _validate(path: Path) -> int:
    endpoint = load_config(path)
    print(  # noqa: T201 - intentional non-secret CLI output.
        json.dumps(
            {
                "schema": "kaleido.runtime/v1",
                "role": endpoint.role,
                "protocol": endpoint.runtime.protocol_mode,
                "valid": True,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _export_field_material(
    path: Path,
    *,
    endpoint_ipv4: str,
    key_slot_id: str,
    lifetime_seconds: int,
    output: BinaryIO | None = None,
) -> int:
    if output is None and sys.stdout.isatty():
        raise FieldExportError("field material requires redirected stdout")
    endpoint = load_config(path, expected_role="server")
    envelope = build_field_material_envelope(
        endpoint,
        endpoint_ipv4=endpoint_ipv4,
        key_slot_id=key_slot_id,
        lifetime_seconds=lifetime_seconds,
    )
    stream = sys.stdout.buffer if output is None else output
    stream.write(envelope)
    stream.write(b"\n")
    stream.flush()
    return 0


def _check_launch_gates(
    endpoint: EndpointConfig, *, allow_lab_protocol: bool, allow_insecure_lab: bool
) -> None:
    is_lab = endpoint.runtime.protocol_mode == "lab"
    is_insecure = endpoint.runtime.insecure_outer_tls_for_lab
    if is_lab and not allow_lab_protocol:
        raise ConfigError("lab protocol requires --allow-lab-protocol")
    if allow_insecure_lab and not allow_lab_protocol:
        raise ConfigError("--allow-insecure-lab also requires --allow-lab-protocol")
    if is_insecure and not (allow_lab_protocol and allow_insecure_lab):
        raise ConfigError(
            "disabled TLS verification requires both --allow-lab-protocol "
            "and --allow-insecure-lab"
        )


async def _serve_endpoint(endpoint: EndpointConfig) -> None:
    events = EventBus()
    await events.start()
    if endpoint.role == "server":
        if endpoint.tls_certificate_file is None or endpoint.tls_private_key_file is None:
            raise ConfigError("server TLS files are missing")
        context = make_server_ssl_context(
            str(endpoint.tls_certificate_file), str(endpoint.tls_private_key_file)
        )
        carrier = Carrier(endpoint.runtime, context, events, role="server")
    else:
        if endpoint.server_endpoint is None:
            raise ConfigError("client server endpoint is missing")
        context = make_client_ssl_context(
            cafile=str(endpoint.tls_ca_file) if endpoint.tls_ca_file else None,
            insecure_lab=endpoint.runtime.insecure_outer_tls_for_lab,
        )
        carrier = Carrier(
            endpoint.runtime,
            context,
            events,
            role="client",
            server_endpoint=endpoint.server_endpoint,
        )
    try:
        await carrier.start()
        await asyncio.Event().wait()
    finally:
        await carrier.stop()
        await events.stop()


def _launch(
    path: Path,
    role: str,
    *,
    allow_lab_protocol: bool,
    allow_insecure_lab: bool,
) -> int:
    endpoint = load_config(path, expected_role=role)
    _check_launch_gates(
        endpoint,
        allow_lab_protocol=allow_lab_protocol,
        allow_insecure_lab=allow_insecure_lab,
    )
    print(  # noqa: T201 - mandatory honest warning.
        "WARNING: Kaleido is a research prototype: no production security, "
        "availability, censorship-resistance, or anonymity guarantee.",
        file=sys.stderr,
    )
    try:
        asyncio.run(_serve_endpoint(endpoint))
    except KeyboardInterrupt:
        return 130
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "score":
            return _score(args.input, args.now)
        if args.command == "keygen":
            return _keygen(args.output)
        if args.command == "validate":
            return _validate(args.config)
        if args.command == "field-export-material":
            return _export_field_material(
                args.config,
                endpoint_ipv4=args.endpoint_ipv4,
                key_slot_id=args.key_slot_id,
                lifetime_seconds=args.lifetime_seconds,
            )
        if args.command == "server":
            return _launch(
                args.config,
                "server",
                allow_lab_protocol=args.allow_lab_protocol,
                allow_insecure_lab=False,
            )
        if args.command == "client":
            return _launch(
                args.config,
                "client",
                allow_lab_protocol=args.allow_lab_protocol,
                allow_insecure_lab=args.allow_insecure_lab,
            )
        raise AssertionError("unreachable")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)  # noqa: T201
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
