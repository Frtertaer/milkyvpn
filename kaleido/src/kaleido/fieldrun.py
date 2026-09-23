"""Diskless orchestration for one minimal, evidence-bounded field attempt."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import math
import os
import re
import ssl
import struct
import subprocess  # noqa: S404  # nosec B404
import sys
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from .field import FieldMaterial, build_outer_tls_context
from .phonepath import (
    AddressVerifier,
    Connector,
    InterfaceBoundTcpRelay,
    RelayConfig,
    RelayStats,
    open_interface_connection,
)
from .runtime import Carrier, EventBus, RuntimeConfig

FIELD_RECORD_SCHEMA: Final = "kaleido-field/v1"
LOOPBACK_HOST: Final = "127.0.0.1"
HTTPS_PORT: Final = 443
MAX_INTERFACE_OUTPUT_BYTES: Final = 128
MAX_HTTP_RESPONSE_BYTES: Final = 16 * 1024
MAX_EGRESS_BODY_BYTES: Final = 128

PathType = Literal[
    "usb_tether_phone_underlay_wifi",
    "usb_tether_phone_underlay_lte",
]
AttemptOutcome = Literal["pass", "fail", "inconclusive"]
EgressScope = Literal["configured_path", "not_attempted"]

ATTEMPT_RECORD_KEYS: Final = frozenset(
    {
        "schema",
        "record_kind",
        "test_id",
        "attempt_id",
        "started_at_utc",
        "path_type",
        "egress_scope",
        "network_contexts",
        "runtime_profile",
        "case",
        "expected_capability",
        "measurements",
        "attempt_outcome",
        "failure_stage",
        "error_code",
        "evidence_refs",
        "evidence_retained",
        "causal_attribution",
        "key_slot_id",
        "cleanup_ok",
        "pending_cleanup",
    }
)

_PATH_TYPES: Final = frozenset(
    {
        "usb_tether_phone_underlay_wifi",
        "usb_tether_phone_underlay_lte",
    }
)
_SAFE_TOKEN_RE: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_ATTEMPT_ID_RE: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_OPERATOR_REF_RE: Final = re.compile(r"\AOP-[A-Z0-9][A-Z0-9._-]{0,31}\Z")
_ASN_REF_RE: Final = re.compile(r"\AAS-[A-Z0-9][A-Z0-9._-]{0,31}\Z")
_DNS_LABEL_RE: Final = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_RESERVED_DNS_SUFFIXES: Final = (
    ".example",
    ".invalid",
    ".local",
    ".localhost",
    ".test",
)

class FieldRunError(RuntimeError):
    """A field-run precondition or sanitized operation failed."""


class _PhaseFailure(FieldRunError):
    def __init__(self, stage: str | None, code: str) -> None:
        super().__init__(code)
        self.stage = stage
        self.code = code


@dataclass(frozen=True, slots=True, repr=False)
class FieldRunSettings:
    """Locally supplied, redaction-safe controls for one field run."""

    interface_index: int = field(repr=False)
    path_type: PathType = field(repr=False)
    expected_key_slot_id: str = field(repr=False)
    operator_ref: str = field(repr=False)
    asn_ref: str = field(repr=False)
    evidence_retained: bool = field(repr=False)
    egress_hostname: str = field(repr=False)
    attempt_id: str = field(repr=False)
    phase_timeout: float = field(default=15.0, repr=False)
    cleanup_timeout: float = field(default=5.0, repr=False)
    discovery_timeout: float = field(default=5.0, repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.interface_index, bool)
            or not isinstance(self.interface_index, int)
            or not 1 <= self.interface_index <= 0xFFFFFFFF
        ):
            raise FieldRunError("interface_index must be a fresh positive integer")
        if not isinstance(self.path_type, str) or self.path_type not in _PATH_TYPES:
            raise FieldRunError("path_type must explicitly identify phone Wi-Fi or LTE")
        if (
            not isinstance(self.expected_key_slot_id, str)
            or _SAFE_TOKEN_RE.fullmatch(self.expected_key_slot_id) is None
        ):
            raise FieldRunError("expected_key_slot_id must be a safe opaque token")
        if (
            not isinstance(self.operator_ref, str)
            or _OPERATOR_REF_RE.fullmatch(self.operator_ref) is None
        ):
            raise FieldRunError("operator_ref must be an opaque OP- reference")
        if (
            not isinstance(self.asn_ref, str)
            or _ASN_REF_RE.fullmatch(self.asn_ref) is None
        ):
            raise FieldRunError("asn_ref must be an opaque AS- reference")
        if not isinstance(self.evidence_retained, bool):
            raise FieldRunError("evidence_retained must be a boolean")
        _validate_public_hostname(self.egress_hostname)
        if (
            not isinstance(self.attempt_id, str)
            or _ATTEMPT_ID_RE.fullmatch(self.attempt_id) is None
        ):
            raise FieldRunError("attempt_id must be a safe local token")
        for value in (
            self.phase_timeout,
            self.cleanup_timeout,
            self.discovery_timeout,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0.001 <= float(value) <= 300.0
            ):
                raise FieldRunError("field-run timeouts must be finite and bounded")

    def __repr__(self) -> str:
        return "FieldRunSettings(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RequestObservation:
    """Private result of one SOCKS request; the IP must never be serialized."""

    socks_connected: bool = field(repr=False)
    https_status: int | None = field(repr=False)
    egress_ip: str | None = field(repr=False)

    def __repr__(self) -> str:
        return "RequestObservation(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FieldRunResult:
    """Two allow-listed attempt records plus a process exit recommendation."""

    records: tuple[dict[str, object], dict[str, object]] = field(repr=False)
    exit_code: int = field(repr=False)
    cleanup_ok: bool = field(repr=False)
    pending_cleanup: int = field(repr=False)

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def to_json_lines(self) -> str:
        lines: list[str] = []
        for record in self.records:
            if set(record) != ATTEMPT_RECORD_KEYS:
                raise FieldRunError("attempt record keys violate the output allow-list")
            lines.append(
                json.dumps(
                    record,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        return "\n".join(lines)

    def __repr__(self) -> str:
        return "FieldRunResult(<redacted>)"


class RelayLike(Protocol):
    @property
    def listen_port(self) -> int: ...

    @property
    def stats(self) -> RelayStats: ...

    async def start(self) -> None: ...

    async def wait_idle(self, *, timeout: float | None = None) -> None: ...

    async def stop(self) -> None: ...


class CarrierLike(Protocol):
    @property
    def socks_port(self) -> int: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


PowerShellRunner = Callable[[tuple[str, ...], float], bytes]
InterfaceDiscoverer = Callable[[int], str]
RelayFactory = Callable[[RelayConfig, AddressVerifier, Connector], RelayLike]
EventBusFactory = Callable[[], EventBus]
CarrierFactory = Callable[
    [RuntimeConfig, ssl.SSLContext, EventBus, tuple[str, int, str]], CarrierLike
]
RequestExecutor = Callable[[int, str, bool], Awaitable[RequestObservation]]
OuterTlsContextFactory = Callable[[FieldMaterial], ssl.SSLContext]
UtcClock = Callable[[], datetime]


def _validate_public_hostname(hostname: object) -> None:
    if (
        not isinstance(hostname, str)
        or not hostname.isascii()
        or hostname != hostname.lower()
        or not 3 <= len(hostname) <= 253
        or hostname.endswith(".")
    ):
        raise FieldRunError("egress_hostname must be a canonical public DNS hostname")
    with suppress(ValueError):
        ipaddress.ip_address(hostname)
        raise FieldRunError("egress_hostname must be a canonical public DNS hostname")
    labels = hostname.split(".")
    if (
        len(labels) < 2
        or any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels)
        or hostname in {"localhost", "localhost.localdomain"}
        or hostname.endswith(_RESERVED_DNS_SUFFIXES)
    ):
        raise FieldRunError("egress_hostname must be a canonical public DNS hostname")


def _validate_ifindex(interface_index: object) -> int:
    if (
        isinstance(interface_index, bool)
        or not isinstance(interface_index, int)
        or not 1 <= interface_index <= 0xFFFFFFFF
    ):
        raise FieldRunError("interface_index must be a fresh positive integer")
    return interface_index


def _run_hidden_powershell(command: tuple[str, ...], timeout: float) -> bytes:
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            list(command),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
        )
    except (OSError, subprocess.SubprocessError):
        raise FieldRunError("interface discovery failed") from None
    output = completed.stdout
    if completed.returncode != 0 or not isinstance(output, bytes):
        raise FieldRunError("interface discovery failed")
    if len(output) > MAX_INTERFACE_OUTPUT_BYTES:
        raise FieldRunError("interface discovery output exceeded its bound")
    return output


def discover_interface_ipv4(
    interface_index: int,
    *,
    runner: PowerShellRunner = _run_hidden_powershell,
    timeout: float = 5.0,
) -> str:
    """Read one preferred IPv4 from a Windows interface without logging it."""

    index = _validate_ifindex(interface_index)
    if sys.platform != "win32":
        raise FieldRunError("interface discovery requires Windows")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or not 0.001 <= float(timeout) <= 30.0
    ):
        raise FieldRunError("interface discovery timeout is invalid")
    powershell = (
        Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    script = (
        "$ErrorActionPreference='Stop';"
        f"$items=@(Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 "
        "-ErrorAction Stop|Where-Object {$_.AddressState -eq 'Preferred' -and "
        "-not $_.SkipAsSource}|Select-Object -ExpandProperty IPAddress -First 2);"
        "if($items.Count -ne 1){exit 4};"
        "$value=[string]$items[0];if($value.Length -gt 64){exit 5};"
        "[Console]::Out.Write($value)"
    )
    command = (
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-Command",
        script,
    )
    try:
        output = runner(command, float(timeout))
    except Exception:
        raise FieldRunError("interface discovery failed") from None
    if not isinstance(output, bytes) or len(output) > MAX_INTERFACE_OUTPUT_BYTES:
        raise FieldRunError("interface discovery output is invalid")
    try:
        value = output.decode("ascii").strip()
        address = ipaddress.IPv4Address(value)
    except (UnicodeError, ipaddress.AddressValueError):
        raise FieldRunError("interface discovery output is invalid") from None
    if (
        str(address) != value
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    ):
        raise FieldRunError("interface discovery output is invalid")
    return value


def _default_relay_factory(
    config: RelayConfig,
    verifier: AddressVerifier,
    connector: Connector,
) -> RelayLike:
    return InterfaceBoundTcpRelay(
        config,
        address_verifier=verifier,
        connector=connector,
    )


def _default_carrier_factory(
    config: RuntimeConfig,
    context: ssl.SSLContext,
    events: EventBus,
    endpoint: tuple[str, int, str],
) -> CarrierLike:
    return Carrier(
        config,
        context,
        events,
        role="client",
        server_endpoint=endpoint,
    )


async def _read_socks_reply(reader: asyncio.StreamReader) -> int:
    header = await reader.readexactly(4)
    if header[0] != 0x05:
        raise FieldRunError("SOCKS response was invalid")
    atyp = header[3]
    if atyp == 0x01:
        await reader.readexactly(6)
    elif atyp == 0x04:
        await reader.readexactly(18)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    else:
        raise FieldRunError("SOCKS response was invalid")
    return int(header[1])


async def _read_http_response(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await reader.read(min(4096, MAX_HTTP_RESPONSE_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_HTTP_RESPONSE_BYTES:
            raise FieldRunError("HTTPS response exceeded its bound")
    response = b"".join(chunks)
    header_end = response.find(b"\r\n\r\n")
    line_end = response.find(b"\r\n")
    if header_end < 0 or line_end <= 0:
        raise FieldRunError("HTTPS response was invalid")
    status_line = response[:line_end].split(b" ", 2)
    if len(status_line) < 2 or not status_line[0].startswith(b"HTTP/"):
        raise FieldRunError("HTTPS response was invalid")
    try:
        status = int(status_line[1])
    except ValueError:
        raise FieldRunError("HTTPS response was invalid") from None
    body = response[header_end + 4 :]
    if len(body) > MAX_EGRESS_BODY_BYTES:
        raise FieldRunError("HTTPS egress body exceeded its bound")
    return status, body


async def socks_https_request(
    socks_port: int,
    hostname: str,
    require_https: bool,
) -> RequestObservation:
    """Issue one async SOCKS request and optionally one HTTPS egress request."""

    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_connection(LOOPBACK_HOST, socks_port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise FieldRunError("SOCKS negotiation failed")
        encoded_host = hostname.encode("ascii")
        if not 1 <= len(encoded_host) <= 255:
            raise FieldRunError("SOCKS destination was invalid")
        writer.write(
            b"\x05\x01\x00\x03"
            + bytes([len(encoded_host)])
            + encoded_host
            + struct.pack(">H", HTTPS_PORT)
        )
        await writer.drain()
        reply = await _read_socks_reply(reader)
        if reply != 0:
            return RequestObservation(False, None, None)
        if not require_https:
            return RequestObservation(True, None, None)

        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        await writer.start_tls(context, server_hostname=hostname)
        request = (
            f"GET / HTTP/1.1\r\nHost: {hostname}\r\n"
            "Accept: text/plain\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await writer.drain()
        status, body = await _read_http_response(reader)
        try:
            observed_ip = body.decode("ascii").strip()
        except UnicodeDecodeError:
            observed_ip = None
        return RequestObservation(True, status, observed_ip)
    except asyncio.CancelledError:
        raise
    except FieldRunError:
        raise
    except Exception:  # noqa: BLE001
        raise FieldRunError("SOCKS HTTPS request failed") from None
    finally:
        if writer is not None:
            with suppress(Exception):
                writer.close()
            with suppress(asyncio.CancelledError, Exception):
                await writer.wait_closed()


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True, repr=False)
class FieldRunDependencies:
    """Injectable side-effect boundary for deterministic field-run tests."""

    discover_interface: InterfaceDiscoverer = field(
        default=discover_interface_ipv4,
        repr=False,
    )
    connector: Connector = field(default=open_interface_connection, repr=False)
    relay_factory: RelayFactory = field(default=_default_relay_factory, repr=False)
    event_bus_factory: EventBusFactory = field(default=EventBus, repr=False)
    carrier_factory: CarrierFactory = field(default=_default_carrier_factory, repr=False)
    request_executor: RequestExecutor = field(default=socks_https_request, repr=False)
    outer_tls_context_factory: OuterTlsContextFactory = field(
        default=build_outer_tls_context,
        repr=False,
    )
    utc_now: UtcClock = field(default=_utc_now, repr=False)

    def __repr__(self) -> str:
        return "FieldRunDependencies(<redacted>)"


@dataclass(slots=True)
class _CaseState:
    case: Literal["BADPSK", "HS"]
    expected_capability: str
    outcome: AttemptOutcome = "inconclusive"
    failure_stage: str | None = None
    error_code: str | None = "not_run"
    egress_scope: EgressScope = "not_attempted"
    measurements: dict[str, object] = field(default_factory=dict)

    def set_inconclusive(self, stage: str | None, code: str) -> None:
        self.outcome = "inconclusive"
        self.failure_stage = stage
        self.error_code = code

    def set_failure(self, stage: str, code: str) -> None:
        self.outcome = "fail"
        self.failure_stage = stage
        self.error_code = code

    def set_pass(self) -> None:
        self.outcome = "pass"
        self.failure_stage = None
        self.error_code = None


_RETAINED_TASKS: set[asyncio.Task[Any]] = set()


async def _resolve[T](awaitable: Awaitable[T]) -> T:
    return await awaitable


class _FieldOrchestrator:
    def __init__(
        self,
        material: FieldMaterial,
        settings: FieldRunSettings,
        dependencies: FieldRunDependencies,
    ) -> None:
        self.material = material
        self.settings = settings
        self.dependencies = dependencies
        self.cleanup_ok = True
        self.direct_tcp_ok = False
        self._retained: set[asyncio.Task[Any]] = set()
        self._negative_bus: EventBus | None = None
        self._resource_pending_cleanup = 0

    def _retain(self, task: asyncio.Task[Any]) -> None:
        if task.done():
            if not task.cancelled():
                task.exception()
            return
        self._retained.add(task)
        _RETAINED_TASKS.add(task)

        def done(completed: asyncio.Task[Any]) -> None:
            self._retained.discard(completed)
            _RETAINED_TASKS.discard(completed)
            if not completed.cancelled():
                completed.exception()

        task.add_done_callback(done)

    @staticmethod
    def _deadline(seconds: float) -> float:
        return asyncio.get_running_loop().time() + float(seconds)

    def _fresh_now(self) -> datetime:
        try:
            current = self.dependencies.utc_now()
            if (
                not isinstance(current, datetime)
                or current.tzinfo is None
                or current.utcoffset() != timedelta(0)
            ):
                raise ValueError
            return current.astimezone(UTC)
        except Exception:
            raise FieldRunError("field-run clock failed") from None

    def _require_material_fresh(self, required_seconds: float = 0.0) -> None:
        current = self._fresh_now()
        if current >= self.material.expires_at_utc:
            raise _PhaseFailure("auth", "field_material_expired")
        if self.material.expires_at_utc - current <= timedelta(seconds=required_seconds):
            raise _PhaseFailure("auth", "field_material_lifetime_insufficient")

    async def _run_until[T](
        self,
        awaitable: Awaitable[T],
        deadline: float,
        *,
        stage: str | None,
        code: str,
    ) -> T:
        task = asyncio.create_task(_resolve(awaitable))
        try:
            done, _pending = await asyncio.wait(
                {task},
                timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
            )
        except asyncio.CancelledError:
            task.cancel()
            self._retain(task)
            raise
        if task not in done:
            task.cancel()
            self._retain(task)
            raise _PhaseFailure(stage, code)
        try:
            return task.result()
        except _PhaseFailure:
            raise
        except asyncio.CancelledError:
            raise _PhaseFailure(stage, code) from None
        except Exception:
            raise _PhaseFailure(stage, code) from None

    async def _cleanup_until(self, awaitable: Awaitable[object], deadline: float) -> bool:
        task = asyncio.create_task(_resolve(awaitable))
        try:
            done, _pending = await asyncio.wait(
                {task},
                timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
            )
        except asyncio.CancelledError:
            task.cancel()
            self._retain(task)
            raise
        if task not in done:
            task.cancel()
            self._retain(task)
            return False
        if task.cancelled():
            return False
        try:
            task.result()
        except Exception:
            return False
        return True

    @staticmethod
    def _address_verifier(expected: str) -> AddressVerifier:
        expected_bytes = ipaddress.IPv4Address(expected).packed

        def verify(candidate: str) -> bool:
            try:
                candidate_bytes = ipaddress.IPv4Address(candidate).packed
            except ipaddress.AddressValueError:
                return False
            return hmac.compare_digest(expected_bytes, candidate_bytes)

        return verify

    async def _qualify_direct(self, expected_local: str) -> bool:
        writer: asyncio.StreamWriter | None = None
        try:
            _reader, writer, selected_local = await self.dependencies.connector(
                self.material.endpoint_ipv4,
                self.material.port,
                self.settings.interface_index,
                float(self.settings.phase_timeout),
            )
            return self._address_verifier(expected_local)(selected_local)
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()

    def _runtime_config(self, secret: bytes) -> RuntimeConfig:
        timeout = float(self.settings.phase_timeout)
        return RuntimeConfig(
            auth_secret=secret,
            socks_listen_host=LOOPBACK_HOST,
            socks_listen_port=0,
            tls_server_hostname=self.material.sni,
            protocol_mode="kal1",
            kal1_server_identity_public=self.material.server_identity_public,
            insecure_outer_tls_for_lab=False,
            handshake_timeout=timeout,
            carrier_read_timeout=timeout,
            inner_read_timeout=timeout,
            inner_idle_timeout=timeout,
            dial_timeout=timeout,
            socks_handshake_timeout=timeout,
            max_outer_sessions=1,
            max_socks_sessions=1,
        )

    async def _cleanup_case(
        self,
        carrier: CarrierLike | None,
        bus: EventBus | None,
        relay: RelayLike,
    ) -> bool:
        deadline = self._deadline(self.settings.cleanup_timeout)
        ok = True
        if carrier is not None:
            ok = await self._cleanup_until(carrier.stop(), deadline) and ok
        if bus is not None:
            ok = await self._cleanup_until(bus.stop(), deadline) and ok
        idle_timeout = max(0.001, deadline - asyncio.get_running_loop().time())
        ok = (
            await self._cleanup_until(
                relay.wait_idle(timeout=idle_timeout),
                deadline,
            )
            and ok
        )
        try:
            stats = relay.stats
        except Exception:
            return False
        if (
            stats.active != 0
            or stats.pending_cleanup != 0
            or stats.cleanup_failures != 0
            or stats.internal_failures != 0
            or stats.rejected != 0
            or stats.failed != 0
            or stats.cancelled != 0
        ):
            ok = False
        self._resource_pending_cleanup = max(
            self._resource_pending_cleanup,
            stats.pending_cleanup,
        )
        self.cleanup_ok = self.cleanup_ok and ok
        return ok

    @staticmethod
    def _event_types(bus: EventBus) -> tuple[str, ...]:
        return tuple(
            event_type
            for event in bus.records
            if isinstance((event_type := event.get("type")), str)
        )

    @staticmethod
    def _client_event_positions(bus: EventBus, event_type: str) -> tuple[int, ...]:
        return tuple(
            index
            for index, event in enumerate(bus.records)
            if event.get("type") == event_type and event.get("role") == "client"
        )

    async def _run_case(
        self,
        state: _CaseState,
        secret: bytes,
        relay: RelayLike,
        *,
        positive: bool,
    ) -> None:
        bus: EventBus | None = None
        carrier: CarrierLike | None = None
        observation: RequestObservation | None = None
        phase_failed = False
        try:
            self._require_material_fresh(float(self.settings.phase_timeout))
            try:
                bus = self.dependencies.event_bus_factory()
            except Exception:
                raise _PhaseFailure(None, "event_bus_creation_failed") from None
            if positive and bus is self._negative_bus:
                raise _PhaseFailure(None, "event_bus_not_isolated")
            if not positive:
                self._negative_bus = bus
            await self._run_until(
                bus.start(),
                self._deadline(self.settings.phase_timeout),
                stage=None,
                code="event_bus_start_failed",
            )
            try:
                context = self.dependencies.outer_tls_context_factory(self.material)
                config = self._runtime_config(secret)
                carrier = self.dependencies.carrier_factory(
                    config,
                    context,
                    bus,
                    (LOOPBACK_HOST, relay.listen_port, self.material.sni),
                )
            except Exception:
                raise _PhaseFailure("tls", "client_carrier_creation_failed") from None
            await self._run_until(
                carrier.start(),
                self._deadline(self.settings.phase_timeout),
                stage="socks",
                code="client_carrier_start_failed",
            )
            socks_port = carrier.socks_port
            if (
                isinstance(socks_port, bool)
                or not isinstance(socks_port, int)
                or not 1 <= socks_port <= 65535
            ):
                raise _PhaseFailure("socks", "client_socks_listener_invalid")
            observation = await self._run_until(
                self.dependencies.request_executor(
                    socks_port,
                    self.settings.egress_hostname,
                    positive,
                ),
                self._deadline(self.settings.phase_timeout),
                stage="socks",
                code="socks_request_failed",
            )
            if not isinstance(observation, RequestObservation):
                raise _PhaseFailure("socks", "request_observation_invalid")
        except _PhaseFailure as exc:
            state.set_inconclusive(exc.stage, exc.code)
            phase_failed = True
        finally:
            cleanup_ok = await self._cleanup_case(carrier, bus, relay)
            if not cleanup_ok and state.error_code == "not_run":
                state.set_inconclusive(None, "cleanup_incomplete")

        if phase_failed or bus is None or observation is None:
            return
        if bus.total_dropped != 0 or "eventbus.dropped" in self._event_types(bus):
            state.set_inconclusive("auth", "event_evidence_dropped")
            return
        event_types = self._event_types(bus)
        session_ended = "session.end" in event_types
        if not positive:
            auth_failed = bool(self._client_event_positions(bus, "auth.failed"))
            forbidden = "auth.success" in event_types or "dial.ok" in event_types
            state.measurements = {
                "direct_tcp_ok": self.direct_tcp_ok,
                "socks_unavailable": not observation.socks_connected,
                "auth_failed": auth_failed,
                "auth_success_absent": "auth.success" not in event_types,
                "dial_ok_absent": "dial.ok" not in event_types,
                "session_ended": session_ended,
                "event_drops": 0,
            }
            if (
                observation.socks_connected is not False
                or not auth_failed
                or forbidden
                or not session_ended
            ):
                state.set_failure("auth", "badpsk_control_failed")
                return
            state.set_pass()
            return

        auth_positions = self._client_event_positions(bus, "auth.success")
        dial_positions = self._client_event_positions(bus, "dial.ok")
        auth_success = bool(auth_positions)
        dial_ok = bool(dial_positions)
        events_ordered = bool(
            auth_positions and dial_positions and auth_positions[0] < dial_positions[0]
        )
        auth_failed = "auth.failed" in event_types
        status_ok = (
            isinstance(observation.https_status, int)
            and not isinstance(observation.https_status, bool)
            and observation.https_status == 200
        )
        egress_global = False
        if isinstance(observation.egress_ip, str):
            try:
                address = ipaddress.ip_address(observation.egress_ip)
            except ValueError:
                address = None
            if address is not None:
                egress_global = bool(
                    address.is_global
                    and not address.is_multicast
                    and not address.is_reserved
                    and not address.is_unspecified
                )
        state.measurements = {
            "direct_tcp_ok": self.direct_tcp_ok,
            "auth_success": auth_success,
            "dial_ok": dial_ok,
            "events_ordered": events_ordered,
            "session_ended": session_ended,
            "socks_connected": observation.socks_connected is True,
            "https_200": status_ok,
            "event_drops": 0,
        }
        if auth_failed or not auth_success:
            state.set_failure("auth", "positive_auth_failed")
        elif (
            not dial_ok
            or not events_ordered
            or not session_ended
            or observation.socks_connected is not True
        ):
            state.set_failure("socks", "positive_socks_failed")
        elif not status_ok or not egress_global:
            state.set_failure("payload", "https_egress_failed")
        else:
            state.egress_scope = "configured_path"
            state.set_pass()

    def _record(
        self,
        state: _CaseState,
        started_at: str,
        cleanup_ok: bool,
        pending_cleanup: int,
    ) -> dict[str, object]:
        test_id = f"KF-USBM-KAL-{state.case}"
        attempt_suffix = "badpsk" if state.case == "BADPSK" else "hs"
        record: dict[str, object] = {
            "schema": FIELD_RECORD_SCHEMA,
            "record_kind": "attempt",
            "test_id": test_id,
            "attempt_id": f"{self.settings.attempt_id}-{attempt_suffix}",
            "started_at_utc": started_at,
            "path_type": self.settings.path_type,
            "egress_scope": state.egress_scope,
            "network_contexts": [
                {
                    "segment": "configured_path",
                    "operator_ref": self.settings.operator_ref,
                    "asn_ref": self.settings.asn_ref,
                    "address_family": "ipv4",
                }
            ],
            "runtime_profile": {
                "transport": "tls_tcp_kal1",
                "endpoint_role": "client",
                "port": 18443,
                "tls_version": "TLSv1.3",
                "sni": "kaleido-lab",
                "address_family": "ipv4",
                "dns_mode": "remote_socks5",
                "max_relay_sessions": 1,
            },
            "case": state.case,
            "expected_capability": state.expected_capability,
            "measurements": dict(state.measurements),
            "attempt_outcome": state.outcome,
            "failure_stage": state.failure_stage,
            "error_code": state.error_code,
            "evidence_refs": [],
            "evidence_retained": self.settings.evidence_retained,
            "causal_attribution": "unknown",
            "key_slot_id": self.settings.expected_key_slot_id,
            "cleanup_ok": cleanup_ok,
            "pending_cleanup": pending_cleanup,
        }
        if set(record) != ATTEMPT_RECORD_KEYS:
            raise FieldRunError("attempt record keys violate the output allow-list")
        return record

    async def run(self) -> FieldRunResult:
        if not hmac.compare_digest(
            self.settings.expected_key_slot_id,
            self.material.key_slot_id,
        ):
            raise FieldRunError("field material key slot does not match local expectation")
        self._require_material_fresh(float(self.settings.phase_timeout))
        started = self._fresh_now().isoformat(timespec="seconds").replace("+00:00", "Z")
        negative = _CaseState("BADPSK", "kal1_auth_rejection")
        positive = _CaseState("HS", "kal1_socks_https_egress")
        relay: RelayLike | None = None
        try:
            discovered = await self._run_until(
                asyncio.to_thread(
                    self.dependencies.discover_interface,
                    self.settings.interface_index,
                ),
                self._deadline(self.settings.discovery_timeout),
                stage="tcp",
                code="interface_discovery_failed",
            )
            try:
                ipaddress.IPv4Address(discovered)
            except (TypeError, ipaddress.AddressValueError):
                raise _PhaseFailure("tcp", "interface_discovery_invalid") from None
            self.direct_tcp_ok = await self._run_until(
                self._qualify_direct(discovered),
                self._deadline(self.settings.phase_timeout),
                stage="tcp",
                code="direct_tcp_qualification_failed",
            )
            if not self.direct_tcp_ok:
                raise _PhaseFailure("tcp", "interface_source_mismatch")

            verifier = self._address_verifier(discovered)
            relay_config = RelayConfig(
                target_host=self.material.endpoint_ipv4,
                target_port=self.material.port,
                interface_index=self.settings.interface_index,
                max_sessions=1,
                connect_timeout=float(self.settings.phase_timeout),
                idle_timeout=float(self.settings.phase_timeout),
                session_timeout=float(self.settings.phase_timeout),
                shutdown_timeout=float(self.settings.cleanup_timeout),
            )
            try:
                relay = self.dependencies.relay_factory(
                    relay_config,
                    verifier,
                    self.dependencies.connector,
                )
            except Exception:
                raise _PhaseFailure("tcp", "relay_creation_failed") from None
            await self._run_until(
                relay.start(),
                self._deadline(self.settings.phase_timeout),
                stage="tcp",
                code="relay_start_failed",
            )
            await self._run_case(
                negative,
                bytes([self.material.psk[0] ^ 1]) + self.material.psk[1:],
                relay,
                positive=False,
            )
            if negative.outcome == "pass" and self.cleanup_ok:
                await self._run_case(
                    positive,
                    self.material.psk,
                    relay,
                    positive=True,
                )
            else:
                positive.set_inconclusive("auth", "badpsk_prerequisite_failed")
            if negative.outcome == "pass" and positive.outcome == "pass":
                try:
                    verified_sessions = relay.stats.interface_verified
                except Exception:
                    verified_sessions = 0
                if verified_sessions < 2:
                    positive.set_inconclusive("tcp", "interface_verification_missing")
        except _PhaseFailure as exc:
            if negative.error_code == "not_run":
                negative.set_inconclusive(exc.stage, exc.code)
            if positive.error_code == "not_run":
                positive.set_inconclusive(exc.stage, exc.code)
        except asyncio.CancelledError:
            negative.set_inconclusive(None, "field_run_cancelled")
            positive.set_inconclusive(None, "field_run_cancelled")
            raise
        except Exception:
            if negative.error_code == "not_run":
                negative.set_inconclusive(None, "field_run_internal_failure")
            if positive.error_code == "not_run":
                positive.set_inconclusive(None, "field_run_internal_failure")
        finally:
            if relay is not None:
                relay_ok = await self._cleanup_until(
                    relay.stop(),
                    self._deadline(self.settings.cleanup_timeout),
                )
                self.cleanup_ok = self.cleanup_ok and relay_ok
                try:
                    final_stats = relay.stats
                except Exception:
                    self.cleanup_ok = False
                else:
                    if (
                        final_stats.active != 0
                        or final_stats.pending_cleanup != 0
                        or final_stats.cleanup_failures != 0
                        or final_stats.internal_failures != 0
                    ):
                        self.cleanup_ok = False
                    self._resource_pending_cleanup = max(
                        self._resource_pending_cleanup,
                        final_stats.pending_cleanup,
                    )

        pending_cleanup = (
            sum(not task.done() for task in self._retained)
            + self._resource_pending_cleanup
        )
        final_cleanup_ok = self.cleanup_ok and pending_cleanup == 0
        if not final_cleanup_ok:
            negative.set_inconclusive(negative.failure_stage, "cleanup_incomplete")
            positive.set_inconclusive(positive.failure_stage, "cleanup_incomplete")
        records = (
            self._record(negative, started, final_cleanup_ok, pending_cleanup),
            self._record(positive, started, final_cleanup_ok, pending_cleanup),
        )
        exit_code = int(
            not (
                final_cleanup_ok
                and negative.outcome == "pass"
                and positive.outcome == "pass"
            )
        )
        return FieldRunResult(records, exit_code, final_cleanup_ok, pending_cleanup)


async def run_field_attempt(
    material: FieldMaterial,
    settings: FieldRunSettings,
    *,
    dependencies: FieldRunDependencies | None = None,
) -> FieldRunResult:
    """Run BADPSK then positive KAL/SOCKS/HTTPS under hard phase deadlines."""

    if not isinstance(material, FieldMaterial):
        raise FieldRunError("validated field material is required")
    if not isinstance(settings, FieldRunSettings):
        raise FieldRunError("validated field-run settings are required")
    selected = dependencies or FieldRunDependencies()
    if not isinstance(selected, FieldRunDependencies):
        raise FieldRunError("validated field-run dependencies are required")
    return await _FieldOrchestrator(material, settings, selected).run()


__all__ = [
    "ATTEMPT_RECORD_KEYS",
    "FIELD_RECORD_SCHEMA",
    "FieldRunDependencies",
    "FieldRunError",
    "FieldRunResult",
    "FieldRunSettings",
    "RequestObservation",
    "discover_interface_ipv4",
    "run_field_attempt",
    "socks_https_request",
]
