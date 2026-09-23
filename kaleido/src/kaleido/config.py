"""Strict file-based configuration for the Kaleido laboratory runtime."""

from __future__ import annotations

import base64
import csv
import hashlib
import ipaddress
import json
import os
import stat
import subprocess  # noqa: S404  # nosec B404
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .protocol import MAX_PAYLOAD as KAL1_MAX_PAYLOAD
from .runtime import RuntimeConfig, TargetPolicy

SCHEMA = "kaleido.runtime/v1"
MAX_CONFIG_BYTES = 64 * 1024
MAX_REFERENCED_FILE_BYTES = 1024 * 1024


class ConfigError(ValueError):
    """A configuration is malformed or violates a safety invariant."""


@dataclass(frozen=True)
class EndpointConfig:
    """Validated configuration for one independently launched endpoint."""

    path: Path
    role: Literal["server", "client"]
    runtime: RuntimeConfig
    tls_certificate_file: Path | None = None
    tls_private_key_file: Path | None = None
    tls_ca_file: Path | None = None
    server_endpoint: tuple[str, int, str] | None = None


@dataclass(frozen=True)
class _Timeouts:
    handshake: float
    carrier_read: float
    inner_read: float
    inner_idle: float
    dial: float
    socks_handshake: float
    max_frame_payload: int


@dataclass(frozen=True)
class _Limits:
    outer_sessions: int
    socks_sessions: int


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f"duplicate key: {key}")
        result[key] = value
    return result


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction is not None and isjunction(path))


def _reject_link_chain(path: Path, label: str) -> None:
    current = Path(os.path.abspath(path))
    while True:
        if current.exists() and _is_link_or_junction(current):
            raise ConfigError(f"{label} must not use symbolic links or junctions")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _regular_file(path: Path, label: str, *, limit: int) -> Path:
    absolute = Path(os.path.abspath(path))
    _reject_link_chain(absolute, label)
    try:
        info = absolute.stat()
    except OSError as exc:
        raise ConfigError(f"cannot read {label}: {absolute}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError(f"{label} must be a regular file")
    if info.st_size > limit:
        raise ConfigError(f"{label} exceeds {limit} bytes")
    return absolute


def _read_bytes(path: Path, label: str, *, limit: int = MAX_REFERENCED_FILE_BYTES) -> bytes:
    checked = _regular_file(path, label, limit=limit)
    try:
        data = checked.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read {label}: {checked}") from exc
    if len(data) > limit:
        raise ConfigError(f"{label} exceeds {limit} bytes")
    return data


def _expect_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _expect_keys(
    obj: dict[str, object], allowed: set[str], label: str, *, required: set[str] | None = None
) -> None:
    unknown = set(obj) - allowed
    if unknown:
        raise ConfigError(f"unknown {label} key(s): {', '.join(sorted(unknown))}")
    missing = (required or set()) - set(obj)
    if missing:
        raise ConfigError(f"missing {label} key(s): {', '.join(sorted(missing))}")


def _string(obj: dict[str, object], key: str, label: str, *, default: str | None = None) -> str:
    value = obj.get(key, default)
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ConfigError(f"{label}.{key} must be a non-empty string")
    return value


def _bool(obj: dict[str, object], key: str, label: str, *, default: bool) -> bool:
    value = obj.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{label}.{key} must be a boolean")
    return value


def _integer(
    obj: dict[str, object], key: str, label: str, *, default: int | None = None
) -> int:
    value = obj.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{label}.{key} must be an integer")
    return value


def _number(
    obj: dict[str, object], key: str, label: str, *, default: float
) -> float:
    value = obj.get(key, default)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"{label}.{key} must be a number")
    result = float(value)
    if not 0.1 <= result <= 3600.0:
        raise ConfigError(f"{label}.{key} must be between 0.1 and 3600")
    return result


def _port(obj: dict[str, object], key: str, label: str, *, allow_zero: bool) -> int:
    value = _integer(obj, key, label)
    minimum = 0 if allow_zero else 1
    if not minimum <= value <= 65535:
        raise ConfigError(f"{label}.{key} must be between {minimum} and 65535")
    return value


def _path_from_config(base: Path, value: str, label: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = base / candidate
    return _regular_file(candidate, label, limit=MAX_REFERENCED_FILE_BYTES)


def _load_psk(path: Path) -> bytes:
    value = _read_bytes(path, "protocol.psk_file", limit=32)
    if len(value) != 32:
        raise ConfigError("protocol.psk_file must contain exactly 32 binary bytes")
    return value


def _load_private_identity(path: Path) -> Ed25519PrivateKey:
    data = _read_bytes(path, "protocol.server_identity_private_file", limit=64 * 1024)
    if b"-----BEGIN PRIVATE KEY-----" not in data:
        raise ConfigError("server identity private key must be PEM PKCS8")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError) as exc:
        raise ConfigError("invalid unencrypted PEM PKCS8 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigError("server identity private key must be Ed25519")
    return key


def _load_public_identity(path: Path) -> Ed25519PublicKey:
    data = _read_bytes(path, "protocol.server_identity_public_file", limit=64 * 1024)
    if b"-----BEGIN PUBLIC KEY-----" not in data:
        raise ConfigError("server identity public key must be PEM SubjectPublicKeyInfo")
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise ConfigError("invalid PEM SubjectPublicKeyInfo public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigError("server identity public key must be Ed25519")
    return key


def _parse_protocol(
    root: dict[str, object], role: Literal["server", "client"], base: Path
) -> tuple[Literal["kal1", "lab"], bytes, Ed25519PrivateKey | None, Ed25519PublicKey | None]:
    obj = _expect_object(root.get("protocol"), "protocol")
    identity_key = (
        "server_identity_private_file" if role == "server" else "server_identity_public_file"
    )
    _expect_keys(
        obj,
        {"mode", "psk_file", identity_key},
        "protocol",
        required={"mode", "psk_file"},
    )
    mode_value = _string(obj, "mode", "protocol")
    if mode_value not in {"kal1", "lab"}:
        raise ConfigError("protocol.mode must be 'kal1' or 'lab'")
    mode = cast(Literal["kal1", "lab"], mode_value)
    psk = _load_psk(_path_from_config(base, _string(obj, "psk_file", "protocol"), "PSK"))
    private_key: Ed25519PrivateKey | None = None
    public_key: Ed25519PublicKey | None = None
    if mode == "kal1":
        if identity_key not in obj:
            raise ConfigError(f"protocol.{identity_key} is required in KAL/1 mode")
        identity_path = _path_from_config(
            base, _string(obj, identity_key, "protocol"), "server identity"
        )
        if role == "server":
            private_key = _load_private_identity(identity_path)
        else:
            public_key = _load_public_identity(identity_path)
    return mode, psk, private_key, public_key


def _parse_timeouts(root: dict[str, object]) -> _Timeouts:
    value = root.get("timeouts", {})
    obj = _expect_object(value, "timeouts")
    allowed = {
        "handshake_seconds",
        "carrier_read_seconds",
        "inner_read_seconds",
        "inner_idle_seconds",
        "dial_seconds",
        "socks_handshake_seconds",
        "max_frame_payload",
    }
    _expect_keys(obj, allowed, "timeouts")
    max_payload = _integer(obj, "max_frame_payload", "timeouts", default=KAL1_MAX_PAYLOAD)
    if not 1 <= max_payload <= KAL1_MAX_PAYLOAD:
        raise ConfigError(f"timeouts.max_frame_payload must be between 1 and {KAL1_MAX_PAYLOAD}")
    return _Timeouts(
        handshake=_number(obj, "handshake_seconds", "timeouts", default=10.0),
        carrier_read=_number(obj, "carrier_read_seconds", "timeouts", default=30.0),
        inner_read=_number(obj, "inner_read_seconds", "timeouts", default=60.0),
        inner_idle=_number(obj, "inner_idle_seconds", "timeouts", default=120.0),
        dial=_number(obj, "dial_seconds", "timeouts", default=10.0),
        socks_handshake=_number(obj, "socks_handshake_seconds", "timeouts", default=10.0),
        max_frame_payload=max_payload,
    )


def _parse_limits(root: dict[str, object]) -> _Limits:
    obj = _expect_object(root.get("limits", {}), "limits")
    _expect_keys(obj, {"outer_sessions", "socks_sessions"}, "limits")
    defaults = RuntimeConfig()
    outer = _integer(
        obj, "outer_sessions", "limits", default=defaults.max_outer_sessions
    )
    socks = _integer(
        obj, "socks_sessions", "limits", default=defaults.max_socks_sessions
    )
    for key, value in (("outer_sessions", outer), ("socks_sessions", socks)):
        if not 1 <= value <= 65535:
            raise ConfigError(f"limits.{key} must be between 1 and 65535")
    return _Limits(outer_sessions=outer, socks_sessions=socks)


def _parse_target_policy(root: dict[str, object]) -> TargetPolicy:
    obj = _expect_object(root.get("target_policy", {}), "target_policy")
    allowed = {
        "allow_hosts",
        "allow_ports",
        "allow_public",
        "deny_loopback",
        "deny_private",
        "deny_link_local",
        "deny_multicast",
        "deny_reserved",
    }
    _expect_keys(obj, allowed, "target_policy")
    raw_hosts = obj.get("allow_hosts", [])
    if not isinstance(raw_hosts, list) or not all(
        isinstance(host, str) and host for host in raw_hosts
    ):
        raise ConfigError("target_policy.allow_hosts must be an array of non-empty strings")
    raw_ports = obj.get("allow_ports", [])
    if not isinstance(raw_ports, list) or not all(
        isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
        for port in raw_ports
    ):
        raise ConfigError("target_policy.allow_ports must be an array of valid ports")
    return TargetPolicy(
        allow_hosts=set(cast(list[str], raw_hosts)),
        allow_ports=set(cast(list[int], raw_ports)),
        allow_public=_bool(obj, "allow_public", "target_policy", default=False),
        deny_loopback=_bool(obj, "deny_loopback", "target_policy", default=True),
        deny_private=_bool(obj, "deny_private", "target_policy", default=True),
        deny_link_local=_bool(obj, "deny_link_local", "target_policy", default=True),
        deny_multicast=_bool(obj, "deny_multicast", "target_policy", default=True),
        deny_reserved=_bool(obj, "deny_reserved", "target_policy", default=True),
    )


def _parse_socks_auth(
    root: dict[str, object], base: Path
) -> tuple[bool, bytes | None, bytes | None]:
    obj = _expect_object(root.get("socks_auth", {}), "socks_auth")
    _expect_keys(obj, {"required", "username", "secret_file"}, "socks_auth")
    required = _bool(obj, "required", "socks_auth", default=False)
    if not required:
        if "secret_file" in obj:
            raise ConfigError("socks_auth.secret_file is only valid when required is true")
        if "username" in obj:
            raise ConfigError("socks_auth.username is only valid when required is true")
        return False, None, None
    if "username" not in obj or "secret_file" not in obj:
        raise ConfigError("socks_auth.username and secret_file are required")
    try:
        username = _string(obj, "username", "socks_auth").encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ConfigError("socks_auth.username must be valid UTF-8") from exc
    if not 1 <= len(username) <= 255:
        raise ConfigError("socks_auth.username must encode to 1..255 bytes")
    path = _path_from_config(
        base, _string(obj, "secret_file", "socks_auth"), "SOCKS authentication secret"
    )
    secret = _read_bytes(path, "socks_auth.secret_file", limit=1024)
    if not 16 <= len(secret) <= 255:
        raise ConfigError("socks_auth.secret_file must contain 16..255 bytes")
    return True, username, secret


def _parse_server(root: dict[str, object], path: Path) -> EndpointConfig:
    _expect_keys(
        root,
        {
            "schema",
            "role",
            "listen",
            "tls",
            "protocol",
            "target_policy",
            "decoy",
            "timeouts",
            "limits",
        },
        "top-level",
        required={"schema", "role", "listen", "tls", "protocol"},
    )
    base = path.parent
    listen = _expect_object(root["listen"], "listen")
    _expect_keys(listen, {"host", "port"}, "listen", required={"host", "port"})
    tls = _expect_object(root["tls"], "tls")
    _expect_keys(
        tls,
        {"certificate_file", "private_key_file"},
        "tls",
        required={"certificate_file", "private_key_file"},
    )
    certificate = _path_from_config(
        base, _string(tls, "certificate_file", "tls"), "TLS certificate"
    )
    private_key = _path_from_config(
        base, _string(tls, "private_key_file", "tls"), "TLS private key"
    )
    mode, psk, identity_private, identity_public = _parse_protocol(root, "server", base)
    decoy = _expect_object(root.get("decoy", {}), "decoy")
    _expect_keys(decoy, {"status", "server", "body_file"}, "decoy")
    decoy_status = _integer(decoy, "status", "decoy", default=200)
    if not 100 <= decoy_status <= 599:
        raise ConfigError("decoy.status must be between 100 and 599")
    decoy_body = RuntimeConfig().decoy_body
    if "body_file" in decoy:
        body_path = _path_from_config(
            base, _string(decoy, "body_file", "decoy"), "decoy body"
        )
        decoy_body = _read_bytes(body_path, "decoy.body_file")
    timeouts = _parse_timeouts(root)
    limits = _parse_limits(root)
    runtime = RuntimeConfig(
        listen_host=_string(listen, "host", "listen"),
        listen_port=_port(listen, "port", "listen", allow_zero=True),
        auth_secret=psk,
        decoy_status=decoy_status,
        decoy_server=_string(decoy, "server", "decoy", default="nginx"),
        decoy_body=decoy_body,
        protocol_mode=mode,
        kal1_server_identity_private=identity_private,
        kal1_server_identity_public=identity_public,
        target_policy=_parse_target_policy(root),
        handshake_timeout=timeouts.handshake,
        carrier_read_timeout=timeouts.carrier_read,
        inner_read_timeout=timeouts.inner_read,
        inner_idle_timeout=timeouts.inner_idle,
        dial_timeout=timeouts.dial,
        socks_handshake_timeout=timeouts.socks_handshake,
        max_frame_payload=timeouts.max_frame_payload,
        max_outer_sessions=limits.outer_sessions,
        max_socks_sessions=limits.socks_sessions,
    )
    return EndpointConfig(
        path=path,
        role="server",
        runtime=runtime,
        tls_certificate_file=certificate,
        tls_private_key_file=private_key,
    )


def _parse_client(root: dict[str, object], path: Path) -> EndpointConfig:
    _expect_keys(
        root,
        {
            "schema",
            "role",
            "server",
            "socks",
            "tls",
            "protocol",
            "socks_auth",
            "timeouts",
            "limits",
        },
        "top-level",
        required={"schema", "role", "server", "socks", "tls", "protocol"},
    )
    base = path.parent
    server = _expect_object(root["server"], "server")
    _expect_keys(server, {"host", "port", "sni"}, "server", required={"host", "port", "sni"})
    socks = _expect_object(root["socks"], "socks")
    _expect_keys(socks, {"host", "port"}, "socks", required={"host", "port"})
    socks_host = _string(socks, "host", "socks")
    try:
        if not ipaddress.ip_address(socks_host).is_loopback:
            raise ConfigError("socks.host must be a loopback IP address")
    except ValueError as exc:
        raise ConfigError("socks.host must be a loopback IP address") from exc
    tls = _expect_object(root["tls"], "tls")
    _expect_keys(tls, {"ca_file", "insecure_lab"}, "tls")
    insecure = _bool(tls, "insecure_lab", "tls", default=False)
    ca_file = None
    if "ca_file" in tls:
        ca_file = _path_from_config(base, _string(tls, "ca_file", "tls"), "TLS CA file")
    mode, psk, identity_private, identity_public = _parse_protocol(root, "client", base)
    if insecure and mode != "lab":
        raise ConfigError("tls.insecure_lab is permitted only with protocol.mode='lab'")
    socks_required, socks_username, socks_secret = _parse_socks_auth(root, base)
    sni = _string(server, "sni", "server")
    timeouts = _parse_timeouts(root)
    limits = _parse_limits(root)
    runtime = RuntimeConfig(
        auth_secret=psk,
        socks_listen_host=socks_host,
        socks_listen_port=_port(socks, "port", "socks", allow_zero=True),
        tls_server_hostname=sni,
        protocol_mode=mode,
        kal1_server_identity_private=identity_private,
        kal1_server_identity_public=identity_public,
        insecure_outer_tls_for_lab=insecure,
        socks_auth_required=socks_required,
        socks_auth_username=socks_username,
        socks_auth_secret=socks_secret,
        handshake_timeout=timeouts.handshake,
        carrier_read_timeout=timeouts.carrier_read,
        inner_read_timeout=timeouts.inner_read,
        inner_idle_timeout=timeouts.inner_idle,
        dial_timeout=timeouts.dial,
        socks_handshake_timeout=timeouts.socks_handshake,
        max_frame_payload=timeouts.max_frame_payload,
        max_outer_sessions=limits.outer_sessions,
        max_socks_sessions=limits.socks_sessions,
    )
    endpoint = (
        _string(server, "host", "server"),
        _port(server, "port", "server", allow_zero=False),
        sni,
    )
    return EndpointConfig(
        path=path,
        role="client",
        runtime=runtime,
        tls_ca_file=ca_file,
        server_endpoint=endpoint,
    )


def load_config(path: Path | str, *, expected_role: str | None = None) -> EndpointConfig:
    """Load and fully validate one endpoint config without starting networking."""

    config_path = _regular_file(Path(path), "config", limit=MAX_CONFIG_BYTES)
    try:
        raw = config_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"cannot decode config: {config_path}") from exc
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    root = _expect_object(value, "config")
    if root.get("schema") != SCHEMA:
        raise ConfigError(f"schema must be {SCHEMA!r}")
    role = root.get("role")
    if role not in {"server", "client"}:
        raise ConfigError("role must be 'server' or 'client'")
    if expected_role is not None and role != expected_role:
        raise ConfigError(f"config role is {role!r}, expected {expected_role!r}")
    if role == "server":
        return _parse_server(root, config_path)
    return _parse_client(root, config_path)


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    """Return a stable SHA-256 fingerprint of canonical SPKI bytes."""

    public_der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(public_der).digest()
    return "SHA256:" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _write_exclusive(path: Path, data: bytes, *, secret: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600 if secret else 0o644)
    except OSError as exc:
        raise ConfigError(f"refusing to overwrite or create {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if secret:
            _harden_secret_file(path)
    except BaseException:
        with suppress(OSError):
            path.unlink()
        raise


def _windows_current_sid() -> str:
    whoami = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "whoami.exe"
    completed = subprocess.run(  # noqa: S603,S607  # nosec B603
        [str(whoami), "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    fields: list[str] = next(iter(csv.reader([completed.stdout.strip()])), [])
    if len(fields) != 2 or not fields[1].startswith("S-"):
        raise ConfigError("could not determine the current Windows SID")
    return str(fields[1])


def _harden_secret_file(path: Path) -> None:
    if os.name != "nt":
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return
    sid = _windows_current_sid()
    icacls = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "icacls.exe"
    try:
        subprocess.run(  # noqa: S603,S607  # nosec B603
            [str(icacls), str(path), "/inheritance:r", "/grant:r", f"*{sid}:(R,W)"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigError(f"could not apply a private ACL to {path}") from exc


def generate_keys(output: Path | str) -> tuple[tuple[Path, Path, Path], str]:
    """Create PSK and Ed25519 identity files without overwriting any path."""

    directory = Path(os.path.abspath(Path(output)))
    _reject_link_chain(directory, "output directory")
    if directory.exists() and not directory.is_dir():
        raise ConfigError("key output must be a directory")
    if not directory.exists():
        parent = directory.parent
        _reject_link_chain(parent, "output directory parent")
        if not parent.is_dir():
            raise ConfigError("key output parent directory does not exist")
        try:
            directory.mkdir(mode=0o700)
        except OSError as exc:
            raise ConfigError(f"cannot create key output directory: {directory}") from exc
    psk_path = directory / "kaleido.psk"
    private_path = directory / "server-identity-private.pem"
    public_path = directory / "server-identity-public.pem"
    paths = (psk_path, private_path, public_path)
    if any(path.exists() or path.is_symlink() for path in paths):
        raise ConfigError("key output already exists; refusing to overwrite")

    identity = Ed25519PrivateKey.generate()
    private_data = identity.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_data = identity.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    created: list[Path] = []
    try:
        for target, data, secret in (
            (psk_path, os.urandom(32), True),
            (private_path, private_data, True),
            (public_path, public_data, False),
        ):
            _write_exclusive(target, data, secret=secret)
            created.append(target)
    except BaseException:
        for target in created:
            with suppress(OSError):
                target.unlink()
        raise
    return paths, public_key_fingerprint(identity.public_key())


__all__ = [
    "ConfigError",
    "EndpointConfig",
    "MAX_CONFIG_BYTES",
    "SCHEMA",
    "generate_keys",
    "load_config",
    "public_key_fingerprint",
]
