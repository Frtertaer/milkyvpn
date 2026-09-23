"""Kaleido measurement harness.

Reads a JSON test plan and runs bounded network probes against each target,
recording JSONL measurement records. Pure Python 3.12 standard library only.

A test plan is a JSON object of the form::

    {
      "network": "lab-v4",
      "allow_private": false,
      "connect_timeout_ms": 3000,
      "read_timeout_ms": 5000,
      "stages": ["connect", "tls", "http"],
      "http_method": "GET",
      "path": "/",
      "headers": {"User-Agent": "kaleido-measure/0"},
      "egress_verify_url": "https://example.invalid/",
      "proxy": {
        "mode": "direct",            // direct | http_connect | socks5
        "host": "127.0.0.1",
        "port": 1080,
        "credentials": {"user": "u", "password": "p"}  // optional, never logged
      },
      "targets": [
        {"host": "example.com", "port": 443, "tls": true}
      ]
    }

Credential handling: proxy credentials are accepted in the plan and used only
for the on-the-wire proxy handshake. They are never written to JSONL output,
never placed into proxy command arguments, and never surfaced in exceptions.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import errno
import ipaddress
import json
import socket
import ssl
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack, suppress
from typing import Any

__all__ = [
    "Record",
    "ProbeError",
    "TargetValidationError",
    "MeasureConfig",
    "MeasureRunner",
    "ProxyConfig",
    "BoundedConn",
    "load_plan",
    "run_plan",
    "run_file",
    "main",
]

# ---------------------------------------------------------------------------
# Constants and small helpers
# ---------------------------------------------------------------------------

_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)


def _now_iso() -> str:
    """UTC timestamp in RFC 3339 / ISO 8601 with a ``Z`` suffix."""
    return _dt.datetime.now(tz=_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _monotonic() -> float:
    return time.monotonic()


# Stable error categories for JSONL consumers.
CAT_CONNECT_REFUSED = "connect_refused"
CAT_CONNECT_TIMEOUT = "connect_timeout"
CAT_CONNECT_UNREACHABLE = "connect_unreachable"
CAT_CONNECT_OTHER = "connect_error"
CAT_PROXY_HANDSHAKE = "proxy_handshake"
CAT_PROXY_AUTH = "proxy_auth"
CAT_TLS = "tls_error"
CAT_HTTP = "http_error"
CAT_READ_TIMEOUT = "read_timeout"
CAT_PROTOCOL = "protocol_error"
CAT_CONFIG = "config_error"
CAT_TARGET_REJECTED = "target_rejected"
CAT_EGRESS_MISMATCH = "egress_mismatch"
CAT_DNS = "dns_error"
CAT_UNKNOWN = "unknown_error"


class ProbeError(Exception):
    """Carries a stable ``category`` string alongside a human message."""

    def __init__(self, category: str, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.category = category
        self.cause = cause


class TargetValidationError(ProbeError):
    """A target resolved to a private address and allow_private was off."""

    def __init__(self, message: str) -> None:
        super().__init__(CAT_TARGET_REJECTED, message)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Record:
    """One JSONL measurement record. No credential field exists on it."""

    timestamp: str
    network: str
    target: str
    proxy_type: str
    stages: Mapping[str, float]
    status: str
    error_category: str | None
    error: str | None
    egress_ok: bool | None
    observed_egress: str | None
    plan_id: str
    egress_path: str | None = None
    egress_scope: str = "not_attempted"

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.timestamp,
            "network": self.network,
            "target": self.target,
            "proxy_type": self.proxy_type,
            "stages": dict(self.stages),
            "status": self.status,
            "error_category": self.error_category,
            "error": self.error,
            "egress_ok": self.egress_ok,
            "observed_egress": self.observed_egress,
            "plan_id": self.plan_id,
            "egress_path": self.egress_path,
            "egress_scope": self.egress_scope,
        }
        # Deterministic, single-line JSON for JSONL append-safety.
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
    )


def resolve_targets(host: str, port: int, *, allow_private: bool) -> list[tuple[str, int, str]]:
    """Resolve ``host`` to (ip, port, family) tuples, rejecting private addrs.

    Conservative: if any resolved address is private/loopback/etc. and
    ``allow_private`` is false, the entire target is rejected so a DNS-rebinding
    answer cannot sneak a 127.0.0.1 fallback in alongside a public address.
    """
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ProbeError(CAT_DNS, f"DNS resolution failed for {host!r}: {exc}") from exc
    if not infos:
        raise ProbeError(CAT_DNS, f"DNS returned no addresses for {host!r}")
    out: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()
    for family, _stype, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET:
            ip_str, port_int = str(sockaddr[0]), int(sockaddr[1])
            fam = "ipv4"
        elif family == socket.AF_INET6:
            ip_str, port_int = str(sockaddr[0]), int(sockaddr[1])
            fam = "ipv6"
        else:
            continue
        if (ip_str, port_int) in seen:
            continue
        seen.add((ip_str, port_int))
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise ProbeError(CAT_DNS, f"unparseable address {ip_str!r}") from exc
        if _is_private_ip(ip_obj) and not allow_private:
            raise TargetValidationError(
                f"target {host!r} resolves to private address {ip_str}; "
                "set allow_private=true to permit"
            )
        out.append((ip_str, port_int, fam))
    return out


def is_hostname(host: str) -> bool:
    """True if ``host`` looks like a DNS name rather than an IP literal."""
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Proxy configuration
# ---------------------------------------------------------------------------

PROXY_DIRECT = "direct"
PROXY_HTTP_CONNECT = "http_connect"
PROXY_SOCKS5 = "socks5"
_VALID_PROXY_MODES = {PROXY_DIRECT, PROXY_HTTP_CONNECT, PROXY_SOCKS5}


@dataclasses.dataclass(slots=True)
class ProxyConfig:
    mode: str = PROXY_DIRECT
    host: str | None = None
    port: int | None = None
    user: str | None = None
    password: str | None = None

    @property
    def type_label(self) -> str:
        return self.mode

    @property
    def has_credentials(self) -> bool:
        return bool(self.user) or bool(self.password)

    def redacted_dict(self) -> dict[str, Any]:
        """Anything written outside this method must never include credentials."""
        return {
            "mode": self.mode,
            "host": self.host,
            "port": self.port,
            "has_credentials": self.has_credentials,
        }


def parse_proxy(raw: Any) -> ProxyConfig:
    if raw is None:
        return ProxyConfig()
    if not isinstance(raw, Mapping):
        raise ProbeError(CAT_CONFIG, "proxy must be a JSON object")
    mode = str(raw.get("mode", PROXY_DIRECT)).lower()
    if mode not in _VALID_PROXY_MODES:
        raise ProbeError(CAT_CONFIG, f"unknown proxy mode {mode!r}")
    if mode == PROXY_DIRECT:
        return ProxyConfig(mode=mode)
    host = raw.get("host")
    port = raw.get("port")
    if not isinstance(host, str) or not host:
        raise ProbeError(CAT_CONFIG, f"proxy host required for mode {mode!r}")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ProbeError(CAT_CONFIG, f"proxy port must be 1..65535 for mode {mode!r}")
    creds = raw.get("credentials") or {}
    if creds and not isinstance(creds, Mapping):
        raise ProbeError(CAT_CONFIG, "proxy credentials must be a JSON object")
    user = creds.get("user")
    password = creds.get("password")
    if user is not None and not isinstance(user, str):
        raise ProbeError(CAT_CONFIG, "proxy credentials.user must be a string")
    if password is not None and not isinstance(password, str):
        raise ProbeError(CAT_CONFIG, "proxy credentials.password must be a string")
    return ProxyConfig(mode=mode, host=host, port=int(port), user=user, password=password)


def scrub_creds(text: str, fragments: Sequence[str | None]) -> str:
    """Remove credential bytes from a string before surfacing it."""
    out = text
    for f in fragments:
        if f:
            out = out.replace(f, "<redacted>")
    return out


# ---------------------------------------------------------------------------
# Bounded connection + I/O wrapper
# ---------------------------------------------------------------------------


def _is_timeout_exc(exc: BaseException) -> bool:
    return isinstance(exc, socket.timeout) or getattr(exc, "errno", None) == errno.ETIMEDOUT


def connect_tcp(ip: str, port: int, *, timeout: float, family: str) -> socket.socket:
    fam = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    sock = socket.socket(fam, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except TimeoutError as exc:
        sock.close()
        raise ProbeError(CAT_CONNECT_TIMEOUT, f"connect to {ip}:{port} timed out") from exc
    except ConnectionRefusedError as exc:
        sock.close()
        raise ProbeError(CAT_CONNECT_REFUSED, f"connect to {ip}:{port} refused") from exc
    except OSError as exc:
        sock.close()
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            raise ProbeError(
                CAT_CONNECT_UNREACHABLE, f"network unreachable to {ip}:{port}"
            ) from exc
        raise ProbeError(CAT_CONNECT_OTHER, f"connect to {ip}:{port} failed: {exc}") from exc
    return sock


class BoundedConn:
    """Read/write over a socket with a bounded read deadline."""

    def __init__(self, sock: socket.socket, *, read_timeout: float) -> None:
        self._sock = sock
        self._read_timeout = float(read_timeout)

    @property
    def socket(self) -> socket.socket:
        return self._sock

    def sendall(self, data: bytes) -> None:
        self._sock.settimeout(self._read_timeout)
        try:
            self._sock.sendall(data)
        except TimeoutError as exc:
            raise ProbeError(CAT_READ_TIMEOUT, "send timed out") from exc
        except OSError as exc:
            raise ProbeError(CAT_PROTOCOL, f"send failed: {exc}") from exc

    def recv_until(self, sentinel: bytes, *, max_bytes: int = 65536) -> tuple[bytes, bool]:
        buf = bytearray()
        deadline = _monotonic() + self._read_timeout
        while len(buf) < max_bytes:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                return bytes(buf), False
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(min(4096, max_bytes - len(buf)))
            except TimeoutError:
                return bytes(buf), False
            except OSError as exc:
                raise ProbeError(CAT_PROTOCOL, f"recv failed: {exc}") from exc
            if not chunk:
                return bytes(buf), sentinel in buf
            buf.extend(chunk)
            if sentinel in buf:
                return bytes(buf), True
        return bytes(buf), sentinel in buf

    def recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        deadline = _monotonic() + self._read_timeout
        while len(buf) < n:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                raise ProbeError(CAT_READ_TIMEOUT, f"recv_exact timeout after {len(buf)}/{n} bytes")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(n - len(buf))
            except TimeoutError as exc:
                raise ProbeError(
                    CAT_READ_TIMEOUT, f"recv_exact timeout after {len(buf)}/{n} bytes"
                ) from exc
            except OSError as exc:
                raise ProbeError(CAT_PROTOCOL, f"recv_exact failed: {exc}") from exc
            if not chunk:
                raise ProbeError(CAT_PROTOCOL, f"recv_exact EOF after {len(buf)}/{n} bytes")
            buf.extend(chunk)
        return bytes(buf)

    def close(self) -> None:
        with suppress(OSError):
            self._sock.close()


# ---------------------------------------------------------------------------
# HTTP CONNECT proxy
# ---------------------------------------------------------------------------


def _basic_auth_token(user: str, password: str) -> str:
    import base64

    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode("ascii")


def http_connect_tunnel(
    proxy: ProxyConfig, target_host: str, target_port: int, conn: BoundedConn
) -> None:
    """Perform an HTTP CONNECT handshake. Raises ProbeError on failure.

    Credentials are sent only inside the ``Proxy-Authorization`` header and the
    exception messages never include them.
    """
    headers: dict[str, str] = {}
    if proxy.has_credentials and proxy.user is not None and proxy.password is not None:
        headers["Proxy-Authorization"] = _basic_auth_token(proxy.user, proxy.password)
    target = f"{target_host}:{target_port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    conn.sendall("\r\n".join(lines).encode("latin-1"))
    buf, found = conn.recv_until(b"\r\n\r\n")
    if not found:
        raise ProbeError(CAT_PROXY_HANDSHAKE, "proxy CONNECT response header incomplete")
    nl = buf.find(b"\r\n")
    status_line = buf[:nl].decode("latin-1", "replace").strip()
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ProbeError(CAT_PROXY_HANDSHAKE, f"malformed proxy status line: {status_line!r}")
    try:
        code = int(parts[1])
    except ValueError as exc:
        raise ProbeError(CAT_PROXY_HANDSHAKE, f"non-numeric proxy status: {parts[1]!r}") from exc
    reason = parts[2] if len(parts) >= 3 else ""
    if code == 407:
        raise ProbeError(CAT_PROXY_AUTH, "proxy rejected credentials (407)")
    if code != 200:
        raise ProbeError(CAT_PROXY_HANDSHAKE, f"proxy CONNECT failed: {code} {reason}".strip())


# ---------------------------------------------------------------------------
# SOCKS5 (RFC 1928 + RFC 1929)
# ---------------------------------------------------------------------------


def _socks5_addr_field(host: str) -> tuple[bytes, bytes]:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if isinstance(ip, ipaddress.IPv4Address):
        return b"\x01", ip.packed
    if isinstance(ip, ipaddress.IPv6Address):
        return b"\x04", ip.packed
    enc = host.encode("idna")
    if len(enc) > 255:
        raise ProbeError(CAT_CONFIG, f"SOCKS5 target hostname too long: {host!r}")
    return b"\x03", bytes([len(enc)]) + enc


def socks5_connect(
    proxy: ProxyConfig, target_host: str, target_port: int, conn: BoundedConn
) -> None:
    """SOCKS5 CONNECT handshake. Auth methods: no-auth (0x00), user/pass (0x02)."""
    if proxy.has_credentials:
        conn.sendall(bytes([0x05, 0x02, 0x00, 0x02]))
    else:
        conn.sendall(bytes([0x05, 0x01, 0x00]))
    head = conn.recv_exact(2)
    if head[0] != 0x05:
        raise ProbeError(CAT_PROXY_HANDSHAKE, f"invalid SOCKS5 version in reply: {head[0]}")
    method = head[1]
    if method == 0xFF:
        raise ProbeError(CAT_PROXY_AUTH, "proxy offered no acceptable auth method")
    if method == 0x02:
        if not proxy.has_credentials or proxy.user is None or proxy.password is None:
            raise ProbeError(CAT_PROXY_AUTH, "proxy demanded auth but none configured")
        u = proxy.user.encode("utf-8")
        p = proxy.password.encode("utf-8")
        if len(u) > 255 or len(p) > 255:
            raise ProbeError(CAT_PROXY_AUTH, "SOCKS5 user/password too long (max 255 bytes each)")
        conn.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        auth_resp = conn.recv_exact(2)
        if auth_resp[0] != 0x01:
            raise ProbeError(
                CAT_PROXY_HANDSHAKE, f"invalid SOCKS5 auth-subnegotiation version: {auth_resp[0]}"
            )
        if auth_resp[1] != 0x00:
            raise ProbeError(CAT_PROXY_AUTH, "SOCKS5 username/password rejected")
    elif method == 0x00:
        pass
    else:
        raise ProbeError(CAT_PROXY_HANDSHAKE, f"unsupported SOCKS5 method: {method}")
    atyp, addr = _socks5_addr_field(target_host)
    port_bs = int(target_port).to_bytes(2, "big")
    conn.sendall(b"\x05\x01\x00" + atyp + addr + port_bs)
    reply_head = conn.recv_exact(4)
    if reply_head[0] != 0x05:
        raise ProbeError(CAT_PROXY_HANDSHAKE, f"invalid SOCKS5 reply version: {reply_head[0]}")
    rep = reply_head[1]
    atyp_reply = reply_head[3]
    if atyp_reply == 0x01:
        conn.recv_exact(4 + 2)
    elif atyp_reply == 0x04:
        conn.recv_exact(16 + 2)
    elif atyp_reply == 0x03:
        length = conn.recv_exact(1)[0]
        conn.recv_exact(length + 2)
    else:
        raise ProbeError(CAT_PROXY_HANDSHAKE, f"unknown SOCKS5 ATYP in reply: {atyp_reply}")
    if rep != 0x00:
        raise ProbeError(CAT_PROXY_HANDSHAKE, f"SOCKS5 CONNECT failed, REP=0x{rep:02x}")


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def default_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def tls_handshake(
    sock: socket.socket,
    server_hostname: str | None,
    *,
    context_factory: Callable[[], ssl.SSLContext] | None = None,
) -> ssl.SSLSocket:
    ctx = context_factory() if context_factory is not None else default_tls_context()
    try:
        return ctx.wrap_socket(sock, server_hostname=server_hostname)
    except ssl.SSLCertVerificationError as exc:
        raise ProbeError(CAT_TLS, f"TLS certificate verification failed: {exc}") from exc
    except ssl.SSLError as exc:
        raise ProbeError(CAT_TLS, f"TLS handshake failed: {exc}") from exc
    except OSError as exc:
        if _is_timeout_exc(exc):
            raise ProbeError(CAT_CONNECT_TIMEOUT, f"TLS handshake timed out: {exc}") from exc
        raise ProbeError(CAT_TLS, f"TLS transport error: {exc}") from exc


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------


def build_http_request(
    method: str,
    path: str,
    host: str,
    port: int,
    headers: Mapping[str, str] | None,
) -> bytes:
    is_default = port in (80, 443)
    host_header = host if is_default else f"{host}:{port}"
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}", "Connection: close"]
    if headers:
        for k, v in headers.items():
            if k.lower() in ("host", "connection", "proxy-authorization", "proxy-connection"):
                continue
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("latin-1")


def http_probe(
    conn: BoundedConn,
    *,
    method: str,
    path: str,
    host: str,
    port: int,
    headers: Mapping[str, str] | None,
) -> int:
    conn.sendall(build_http_request(method, path, host, port, headers))
    buf, _ = conn.recv_until(b"\r\n\r\n")
    if not buf:
        raise ProbeError(CAT_HTTP, "empty HTTP response")
    nl = buf.find(b"\r\n")
    status_line = buf[:nl].decode("latin-1", "replace").strip()
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ProbeError(CAT_HTTP, f"malformed HTTP status line: {status_line!r}")
    try:
        return int(parts[1])
    except ValueError as exc:
        raise ProbeError(CAT_HTTP, f"non-numeric HTTP status: {parts[1]!r}") from exc


# ---------------------------------------------------------------------------
# Config + runner
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class MeasureConfig:
    network: str = "default"
    allow_private: bool = False
    connect_timeout_ms: int = 3000
    read_timeout_ms: int = 5000
    stages: tuple[str, ...] = ("connect",)
    http_method: str = "HEAD"
    path: str = "/"
    headers: dict[str, str] | None = None
    egress_verify_url: str | None = None
    proxy: ProxyConfig = dataclasses.field(default_factory=ProxyConfig)
    plan_id: str = ""
    tls_context_factory: Callable[[], ssl.SSLContext] | None = None
    egress_verifier: Callable[[str], str | None] | None = None


def _empty_stages() -> dict[str, float]:
    return {"connect": 0.0, "proxy": 0.0, "tls": 0.0, "http": 0.0}


def _round_stages(d: Mapping[str, float]) -> dict[str, float]:
    return {k: round(v, 6) for k, v in d.items()}


class MeasureRunner:
    """Runs a single measurement plan against one or more targets."""

    def __init__(self, cfg: MeasureConfig) -> None:
        self.cfg = cfg
        self._cred_fragments: list[str | None] = [cfg.proxy.user, cfg.proxy.password]

    def measure_target(self, host: str, port: int, *, tls: bool) -> Record:
        cfg = self.cfg
        connect_timeout = max(0.001, cfg.connect_timeout_ms / 1000.0)
        read_timeout = max(0.001, cfg.read_timeout_ms / 1000.0)
        stages = _empty_stages()
        status = "ok"
        error_category: str | None = None
        error_msg: str | None = None
        egress_ok: bool | None = None
        observed_egress: str | None = None
        egress_path: str | None = None
        egress_scope = "not_attempted"
        target_str = f"{host}:{port}"

        connect_host = host
        connect_port = port
        if cfg.proxy.mode != PROXY_DIRECT:
            if cfg.proxy.host is None or cfg.proxy.port is None:
                return self._record(
                    target_str,
                    stages,
                    "error",
                    CAT_CONFIG,
                    "proxy endpoint is incomplete",
                    None,
                    None,
                )
            connect_host = cfg.proxy.host
            connect_port = cfg.proxy.port

        try:
            resolved = resolve_targets(
                connect_host,
                connect_port,
                # A locally running proxy is useful for controlled tests. In
                # field plans, allow_private remains false unless explicitly
                # opted in by the operator.
                allow_private=cfg.allow_private,
            )
        except ProbeError as exc:
            return self._record(target_str, stages, "error", exc.category, str(exc), None, None)

        base_sock: socket.socket | None = None
        tls_sock: ssl.SSLSocket | None = None
        conn: BoundedConn | None = None
        try:
            ip, _, family = resolved[0]
            t0 = _monotonic()
            base_sock = connect_tcp(ip, connect_port, timeout=connect_timeout, family=family)
            stages["connect"] = _monotonic() - t0
            conn = BoundedConn(base_sock, read_timeout=read_timeout)

            if cfg.proxy.mode != PROXY_DIRECT:
                p_t0 = _monotonic()
                if cfg.proxy.mode == PROXY_HTTP_CONNECT:
                    http_connect_tunnel(cfg.proxy, host, port, conn)
                elif cfg.proxy.mode == PROXY_SOCKS5:
                    socks5_connect(cfg.proxy, host, port, conn)
                else:
                    raise ProbeError(CAT_CONFIG, f"unsupported proxy mode {cfg.proxy.mode!r}")
                stages["proxy"] = _monotonic() - p_t0

            want_tls = ("tls" in cfg.stages) or tls
            if want_tls:
                # Passing an IP literal is still required for certificate IP
                # SAN verification. CPython/OpenSSL suppresses DNS SNI for IP
                # literals while retaining identity verification semantics.
                server_hostname = host
                t_t0 = _monotonic()
                # Handshake consumes base_sock on success; wrap a fresh BoundedConn.
                tls_sock = tls_handshake(
                    base_sock,
                    server_hostname,
                    context_factory=cfg.tls_context_factory,
                )
                stages["tls"] = _monotonic() - t_t0
                conn = BoundedConn(tls_sock, read_timeout=read_timeout)
                base_sock = None  # owned by tls_sock now

            if "http" in cfg.stages:
                h_t0 = _monotonic()
                code = http_probe(
                    conn,
                    method=cfg.http_method,
                    path=cfg.path,
                    host=host,
                    port=port,
                    headers=cfg.headers or {},
                )
                stages["http"] = _monotonic() - h_t0
                if not (200 <= code < 400):
                    status = "http_non_success"
                    error_category = CAT_HTTP
                    error_msg = f"HTTP status {code}"

            if cfg.egress_verify_url:
                egress_ok, observed_egress, egress_path, egress_scope = self._verify_egress()
        except ProbeError as exc:
            status = "error"
            error_category = exc.category
            error_msg = scrub_creds(str(exc), self._cred_fragments)
        except Exception as exc:  # noqa: BLE001 - last-resort guard so JSONL stays valid
            status = "error"
            error_category = CAT_UNKNOWN
            error_msg = scrub_creds(f"unexpected error: {exc}", self._cred_fragments)
        finally:
            if tls_sock is not None:
                with suppress(OSError):
                    tls_sock.close()
            if base_sock is not None:
                with suppress(OSError):
                    base_sock.close()

        return Record(
            timestamp=_now_iso(),
            network=cfg.network,
            target=target_str,
            proxy_type=cfg.proxy.type_label,
            stages=_round_stages(stages),
            status=status,
            error_category=error_category,
            error=error_msg,
            egress_ok=egress_ok,
            observed_egress=observed_egress,
            plan_id=cfg.plan_id,
            egress_path=egress_path,
            egress_scope=egress_scope,
        )

    def _verify_egress(self) -> tuple[bool | None, str | None, str, str]:
        cfg = self.cfg
        url = cfg.egress_verify_url
        if not url:
            return None, None, "unattributed", "not_attempted"
        # A legacy injected callback receives no path object, so its result
        # cannot prove that it used this plan's proxy/tunnel. Keep accepting
        # the callback for compatibility, but fail closed for path claims.
        if cfg.egress_verifier is not None:
            try:
                observed = cfg.egress_verifier(url)
            except Exception:  # noqa: BLE001 - verifier is an external hook
                return None, None, "unattributed", "unattributed"
            return None, observed, "unattributed", "unattributed"

        path = cfg.proxy.type_label
        try:
            observed = default_egress_verifier(
                url,
                connect_timeout=cfg.connect_timeout_ms / 1000.0,
                read_timeout=cfg.read_timeout_ms / 1000.0,
                proxy=cfg.proxy,
            )
        except ProbeError:
            return False, None, path, "configured_path"
        except Exception:  # noqa: BLE001
            return False, None, path, "configured_path"
        if observed is None:
            return False, None, path, "configured_path"
        return True, observed, path, "configured_path"

    def _record(
        self,
        target: str,
        stages: Mapping[str, float],
        status: str,
        error_category: str | None,
        error: str | None,
        egress_ok: bool | None,
        observed_egress: str | None,
    ) -> Record:
        return Record(
            timestamp=_now_iso(),
            network=self.cfg.network,
            target=target,
            proxy_type=self.cfg.proxy.type_label,
            stages=_round_stages(stages),
            status=status,
            error_category=error_category,
            error=scrub_creds(error or "", self._cred_fragments),
            egress_ok=egress_ok,
            observed_egress=observed_egress,
            plan_id=self.cfg.plan_id,
        )


def default_egress_verifier(
    url: str,
    *,
    connect_timeout: float,
    read_timeout: float,
    proxy: ProxyConfig | None = None,
) -> str | None:
    """HTTPS egress check routed through ``proxy`` when one is configured.

    The return value is only the observed IP; the caller owns path provenance.
    ``proxy=None`` preserves the historical host-direct call behaviour.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ProbeError(CAT_CONFIG, f"egress_verify_url must be https: {url!r}")
    host = parts.hostname or ""
    port = parts.port or 443
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    selected_proxy = proxy or ProxyConfig()
    connect_host = host if selected_proxy.mode == PROXY_DIRECT else selected_proxy.host
    connect_port = port if selected_proxy.mode == PROXY_DIRECT else selected_proxy.port
    if connect_host is None or connect_port is None:
        raise ProbeError(CAT_CONFIG, "proxy endpoint is incomplete")
    resolved = resolve_targets(connect_host, connect_port, allow_private=True)
    ip, _, family = resolved[0]
    sock = connect_tcp(ip, connect_port, timeout=connect_timeout, family=family)
    try:
        conn = BoundedConn(sock, read_timeout=read_timeout)
        if selected_proxy.mode == PROXY_HTTP_CONNECT:
            http_connect_tunnel(selected_proxy, host, port, conn)
        elif selected_proxy.mode == PROXY_SOCKS5:
            socks5_connect(selected_proxy, host, port, conn)
        elif selected_proxy.mode != PROXY_DIRECT:
            raise ProbeError(CAT_CONFIG, f"unsupported proxy mode {selected_proxy.mode!r}")
        tls_sock = tls_handshake(sock, host)
        tls_sock.settimeout(read_timeout)
        tls_sock.sendall(build_http_request("GET", path, host, port, None))
        buf = bytearray()
        deadline = _monotonic() + read_timeout
        # The small verifier body may arrive in a later TCP record than the
        # headers. Read until close/deadline instead of treating header arrival
        # as completion.
        while len(buf) < 8192:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                break
            tls_sock.settimeout(remaining)
            try:
                chunk = tls_sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
        body = bytes(buf).split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in buf else b""
        candidate = body.decode("utf-8", "replace").strip()
        if not candidate:
            return None
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise ProbeError(CAT_PROTOCOL, "egress verifier returned a non-IP body") from exc
    finally:
        with suppress(OSError):
            sock.close()


# ---------------------------------------------------------------------------
# Plan parsing
# ---------------------------------------------------------------------------


def _parse_stages(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ("connect",)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ProbeError(CAT_CONFIG, "stages must be a list of strings")
    out: list[str] = []
    for s in raw:
        if not isinstance(s, str):
            raise ProbeError(CAT_CONFIG, "stages must contain only strings")
        v = s.lower()
        if v not in ("connect", "tls", "http"):
            raise ProbeError(CAT_CONFIG, f"unknown stage {s!r}")
        out.append(v)
    if not out:
        raise ProbeError(CAT_CONFIG, "stages list is empty")
    return tuple(out)


def _parse_headers(raw: Any) -> dict[str, str] | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ProbeError(CAT_CONFIG, "headers must be a JSON object")
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ProbeError(CAT_CONFIG, "header keys and values must be strings")
        out[k] = v
    return out


def parse_plan(raw: Any) -> tuple[MeasureConfig, list[dict[str, Any]]]:
    if not isinstance(raw, Mapping):
        raise ProbeError(CAT_CONFIG, "plan must be a JSON object")
    network = str(raw.get("network", "default"))
    allow_private = bool(raw.get("allow_private", False))
    connect_timeout_ms = int(raw.get("connect_timeout_ms", 3000))
    read_timeout_ms = int(raw.get("read_timeout_ms", 5000))
    if connect_timeout_ms <= 0 or read_timeout_ms <= 0:
        raise ProbeError(CAT_CONFIG, "timeouts must be positive integers")
    stages = _parse_stages(raw.get("stages"))
    http_method = str(raw.get("http_method", "HEAD")).upper()
    if http_method not in ("HEAD", "GET"):
        raise ProbeError(CAT_CONFIG, f"unsupported http_method {http_method!r}")
    path = str(raw.get("path", "/"))
    headers = _parse_headers(raw.get("headers"))
    egress_verify_url = raw.get("egress_verify_url")
    if egress_verify_url is not None and not isinstance(egress_verify_url, str):
        raise ProbeError(CAT_CONFIG, "egress_verify_url must be a string")
    proxy = parse_proxy(raw.get("proxy"))
    targets_raw = raw.get("targets")
    if (
        not isinstance(targets_raw, Sequence)
        or isinstance(targets_raw, (str, bytes))
        or not targets_raw
    ):
        raise ProbeError(CAT_CONFIG, "targets must be a non-empty list")
    targets: list[dict[str, Any]] = []
    for t in targets_raw:
        if not isinstance(t, Mapping):
            raise ProbeError(CAT_CONFIG, "each target must be a JSON object")
        host = t.get("host")
        port = t.get("port")
        if not isinstance(host, str) or not host:
            raise ProbeError(CAT_CONFIG, "target.host required")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ProbeError(CAT_CONFIG, "target.port must be 1..65535")
        targets.append({"host": host, "port": int(port), "tls": bool(t.get("tls", False))})
    plan_id = str(raw.get("plan_id") or uuid.uuid4().hex)
    cfg = MeasureConfig(
        network=network,
        allow_private=allow_private,
        connect_timeout_ms=connect_timeout_ms,
        read_timeout_ms=read_timeout_ms,
        stages=stages,
        http_method=http_method,
        path=path,
        headers=headers,
        egress_verify_url=egress_verify_url,
        proxy=proxy,
        plan_id=plan_id,
    )
    return cfg, targets


def load_plan(plan_text: str) -> tuple[MeasureConfig, list[dict[str, Any]]]:
    try:
        raw = json.loads(plan_text)
    except json.JSONDecodeError as exc:
        raise ProbeError(CAT_CONFIG, f"invalid JSON plan: {exc}") from exc
    return parse_plan(raw)


def run_plan(
    plan_text: str,
    *,
    out: Any = None,
    egress_verifier: Callable[[str], str | None] | None = None,
    tls_context_factory: Callable[[], ssl.SSLContext] | None = None,
) -> list[Record]:
    cfg, targets = load_plan(plan_text)
    cfg.egress_verifier = egress_verifier
    cfg.tls_context_factory = tls_context_factory
    runner = MeasureRunner(cfg)
    records: list[Record] = []
    for t in targets:
        rec = runner.measure_target(t["host"], int(t["port"]), tls=bool(t["tls"]))
        records.append(rec)
        if out is not None:
            out.write(rec.to_json())
            out.write("\n")
            out.flush()
    return records


def run_file(
    plan_path: str,
    out_path: str,
    *,
    egress_verifier: Callable[[str], str | None] | None = None,
    tls_context_factory: Callable[[], ssl.SSLContext] | None = None,
) -> int:
    try:
        with open(plan_path, encoding="utf-8") as f:
            plan_text = f.read()
    except OSError as exc:
        raise ProbeError(CAT_CONFIG, f"could not read plan file {plan_path!r}: {exc}") from exc
    if out_path == "-":
        recs = run_plan(
            plan_text,
            out=sys.stdout,
            egress_verifier=egress_verifier,
            tls_context_factory=tls_context_factory,
        )
        return len(recs)
    with open(out_path, "a", encoding="utf-8") as f:
        recs = run_plan(
            plan_text,
            out=f,
            egress_verifier=egress_verifier,
            tls_context_factory=tls_context_factory,
        )
    return len(recs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kaleido-measure",
        description="Run a Kaleido measurement plan and emit JSONL records.",
    )
    p.add_argument("plan", help="path to a JSON test plan")
    p.add_argument(
        "-o",
        "--output",
        default="-",
        help='path to append JSONL records to, or "-" for stdout (default: -)',
    )
    p.add_argument(
        "--allow-private",
        action="store_true",
        help="permit targets that resolve to private/loopback addresses",
    )
    p.add_argument("--network", help="override the plan's network label")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        with open(args.plan, encoding="utf-8") as f:
            plan_text = f.read()
    except OSError as exc:
        sys.stderr.write(f"error: could not read plan {args.plan!r}: {exc}\n")
        return 2
    try:
        cfg, targets = load_plan(plan_text)
    except ProbeError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    if args.allow_private:
        cfg = dataclasses.replace(cfg, allow_private=True)
    if args.network:
        cfg = dataclasses.replace(cfg, network=args.network)
    runner = MeasureRunner(cfg)
    with ExitStack() as stack:
        out = (
            sys.stdout
            if args.output == "-"
            else stack.enter_context(open(args.output, "a", encoding="utf-8"))
        )
        for t in targets:
            rec = runner.measure_target(t["host"], int(t["port"]), tls=bool(t["tls"]))
            out.write(rec.to_json())
            out.write("\n")
            out.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
