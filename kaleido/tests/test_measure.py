"""Deterministic unit tests for kaleido.measure using local fake servers only.

No network access is required. Every server binds to 127.0.0.1 on an
ephemeral port. Targets use 127.0.0.1 literals and plans set allow_private=true.
Proxy credentials, when used, must never appear in JSONL output.
"""

from __future__ import annotations

import io
import json
import socket
import ssl
import threading
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kaleido.measure import (
    CAT_CONNECT_REFUSED,
    CAT_HTTP,
    CAT_PROXY_AUTH,
    CAT_TARGET_REJECTED,
    CAT_TLS,
    PROXY_DIRECT,
    PROXY_SOCKS5,
    BoundedConn,
    MeasureConfig,
    MeasureRunner,
    ProbeError,
    ProxyConfig,
    Record,
    TargetValidationError,
    build_http_request,
    default_egress_verifier,
    load_plan,
    parse_plan,
    run_plan,
    scrub_creds,
)

# ---------------------------------------------------------------------------
# Self-signed certificate helper (uses the project's cryptography dependency)
# ---------------------------------------------------------------------------


def _make_self_signed(common_name: str = "127.0.0.1") -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(tz=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(common_name),
                    x509.IPAddress(__import__("ipaddress").ip_address(common_name)),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem.decode("ascii"), key_pem.decode("ascii")


def _write_cert_files(tmp_path: Path, cn: str = "127.0.0.1") -> tuple[Path, Path]:

    cert_pem, key_pem = _make_self_signed(cn)
    cert_file = Path(tmp_path) / "cert.pem"
    key_file = Path(tmp_path) / "key.pem"
    # Suffix avoids the .pem/.key gitignore patterns only for git; files are
    # in tmp_path either way and are cleaned up by the test runner.
    cert_file.write_text(cert_pem, encoding="utf-8")
    key_file.write_text(key_pem, encoding="utf-8")
    return cert_file, key_file


# ---------------------------------------------------------------------------
# Fake server primitives
# ---------------------------------------------------------------------------


class _ServerThread(threading.Thread):
    def __init__(self, handler, *, host: str = "127.0.0.1") -> None:
        super().__init__(daemon=True)
        self.handler = handler
        self.host = host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.errors: list[str] = []

    def stop(self) -> None:
        self._stop.set()
        with suppress(OSError):
            self.sock.close()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            try:
                self.handler(conn)
            except Exception as exc:  # noqa: BLE001
                self.errors.append(repr(exc))
            finally:
                with suppress(OSError):
                    conn.close()


def _recv_until(
    sock: socket.socket, sentinel: bytes, *, timeout: float = 2.0, max_bytes: int = 65536
) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - len(buf)))
        except TimeoutError:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if sentinel in buf:
            break
    return bytes(buf)


# ---------------------------------------------------------------------------
# Plan helpers
# ---------------------------------------------------------------------------


def _plan(target_host: str, target_port: int, **overrides) -> str:
    plan = {
        "network": "test-net",
        "allow_private": True,
        "connect_timeout_ms": 1500,
        "read_timeout_ms": 2000,
        "stages": ["connect"],
        "plan_id": "plan-test-1",
        "targets": [{"host": target_host, "port": int(target_port), "tls": False}],
    }
    plan.update(overrides)
    return json.dumps(plan)


def _make_runner(plan_text: str, **overrides) -> tuple[MeasureRunner, MeasureConfig]:
    cfg, _targets = load_plan(plan_text)
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return MeasureRunner(cfg), cfg


# ---------------------------------------------------------------------------
# connect stage
# ---------------------------------------------------------------------------


def test_direct_connect_success_records_ok() -> None:
    server = _ServerThread(lambda c: None)
    server.start()
    try:
        runner, _ = _make_runner(_plan("127.0.0.1", server.port))
        rec = runner.measure_target("127.0.0.1", server.port, tls=False)
        assert rec.status == "ok"
        assert rec.error_category is None
        assert rec.proxy_type == PROXY_DIRECT
        assert rec.stages["connect"] >= 0.0
        assert rec.network == "test-net"
        assert rec.plan_id == "plan-test-1"
        assert rec.target == f"127.0.0.1:{server.port}"
        assert "egress_ok" in rec.to_json()
    finally:
        server.stop()


def test_connect_refused_is_categorized(monkeypatch) -> None:
    # Some Windows sandbox/WFP configurations silently drop a connect to a
    # closed loopback port instead of returning WSAECONNREFUSED. Inject the OS
    # condition so this category test remains deterministic; a separate test
    # covers real network timeouts.
    def refuse(self, address):
        raise ConnectionRefusedError(10061, "connection refused")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    runner, _ = _make_runner(_plan("127.0.0.1", 9, connect_timeout_ms=1000))
    rec = runner.measure_target("127.0.0.1", 9, tls=False)
    assert rec.status == "error"
    assert rec.error_category == CAT_CONNECT_REFUSED


def test_connect_timeout_is_categorized() -> None:
    # A non-routable TEST-NET address forces a connect timeout without DNS.
    runner, _ = _make_runner(_plan("192.0.2.1", 80, allow_private=True, connect_timeout_ms=300))
    rec = runner.measure_target("192.0.2.1", 80, tls=False)
    assert rec.status == "error"
    assert rec.error_category in ("connect_timeout", "connect_unreachable", "connect_error")


# ---------------------------------------------------------------------------
# private-target validation
# ---------------------------------------------------------------------------


def test_private_target_rejected_by_default() -> None:
    plan = {
        "network": "n",
        "stages": ["connect"],
        "targets": [{"host": "127.0.0.1", "port": 80, "tls": False}],
    }
    runner, _ = _make_runner(json.dumps(plan))
    rec = runner.measure_target("127.0.0.1", 80, tls=False)
    assert rec.status == "error"
    assert rec.error_category == CAT_TARGET_REJECTED
    assert "private" in (rec.error or "")


def test_allow_private_flag_permits_localhost() -> None:
    server = _ServerThread(lambda c: None)
    server.start()
    try:
        runner, _ = _make_runner(_plan("127.0.0.1", server.port, allow_private=True))
        rec = runner.measure_target("127.0.0.1", server.port, tls=False)
        assert rec.status == "ok"
    finally:
        server.stop()


def test_resolve_targets_raises_for_private_without_flag() -> None:
    from kaleido.measure import resolve_targets

    with pytest.raises(TargetValidationError):
        resolve_targets("127.0.0.1", 80, allow_private=False)


# ---------------------------------------------------------------------------
# HTTP probe stage
# ---------------------------------------------------------------------------


def _http_handler(response: bytes):
    def handle(c: socket.socket) -> None:
        _recv_until(c, b"\r\n\r\n")
        c.sendall(response)

    return handle


def test_http_stage_records_status_code() -> None:
    resp = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    server = _ServerThread(_http_handler(resp))
    server.start()
    try:
        runner, _ = _make_runner(
            _plan(
                "127.0.0.1", server.port, stages=["connect", "http"], http_method="HEAD", path="/"
            )
        )
        rec = runner.measure_target("127.0.0.1", server.port, tls=False)
        assert rec.status == "ok"
        assert rec.stages["http"] >= 0.0
    finally:
        server.stop()


def test_http_non_success_status_recorded() -> None:
    resp = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
    server = _ServerThread(_http_handler(resp))
    server.start()
    try:
        runner, _ = _make_runner(
            _plan("127.0.0.1", server.port, stages=["connect", "http"], http_method="GET")
        )
        rec = runner.measure_target("127.0.0.1", server.port, tls=False)
        assert rec.status == "http_non_success"
        assert rec.error_category == CAT_HTTP
        assert "503" in (rec.error or "")
    finally:
        server.stop()


def test_http_get_with_custom_headers_and_path() -> None:
    received: dict[str, bytes] = {}

    def handle(c: socket.socket) -> None:
        req = _recv_until(c, b"\r\n\r\n")
        received["req"] = req
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    server = _ServerThread(handle)
    server.start()
    try:
        runner, _ = _make_runner(
            _plan(
                "127.0.0.1",
                server.port,
                stages=["connect", "http"],
                http_method="GET",
                path="/healthz",
                headers={"User-Agent": "kaleido-test/1", "X-Trace": "abc"},
            )
        )
        rec = runner.measure_target("127.0.0.1", server.port, tls=False)
        assert rec.status == "ok"
        assert b"GET /healthz HTTP/1.1" in received["req"]
        assert b"User-Agent: kaleido-test/1" in received["req"]
        assert b"X-Trace: abc" in received["req"]
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# HTTP CONNECT proxy
# ---------------------------------------------------------------------------


def test_http_connect_proxy_tunnel_to_origin() -> None:
    seen_request: dict[str, bytes] = {}
    origin_handler_calls: list[int] = []

    def proxy_handler(c: socket.socket) -> None:
        head = _recv_until(c, b"\r\n\r\n")
        seen_request["connect"] = head
        # Parse the requested host:port from the CONNECT line.
        first_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        # "CONNECT 127.0.0.1:PORT HTTP/1.1"
        target = first_line.split()[1]
        host, port_s = target.rsplit(":", 1)
        port = int(port_s)
        # Open a tunnel to the origin and relay.
        upstream = socket.create_connection((host, port), timeout=2.0)
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        # Relay both directions until either side closes.
        c.settimeout(0.5)
        upstream.settimeout(0.5)
        import select

        socks = [c, upstream]
        while socks:
            r, _, _ = select.select(socks, [], [], 2.0)
            if not r:
                break
            for s in r:
                try:
                    data = s.recv(4096)
                except OSError:
                    data = b""
                if not data:
                    socks = [x for x in socks if x is not s]
                    continue
                other = upstream if s is c else c
                try:
                    other.sendall(data)
                except OSError:
                    socks = [x for x in socks if x is not other]

    def origin_handler(c: socket.socket) -> None:
        req = _recv_until(c, b"\r\n\r\n")
        origin_handler_calls.append(1)
        first = req.split(b"\r\n", 1)[0].decode("latin-1")
        body = first.encode()
        c.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )

    origin = _ServerThread(origin_handler)
    origin.start()
    proxy = _ServerThread(proxy_handler)
    proxy.start()
    try:
        plan = _plan(
            "127.0.0.1",
            origin.port,
            stages=["connect", "http"],
            http_method="GET",
            proxy={
                "mode": "http_connect",
                "host": "127.0.0.1",
                "port": proxy.port,
                "credentials": {"user": "proxyuser", "password": "proxypass"},
            },
        )
        runner, _ = _make_runner(plan)
        rec = runner.measure_target("127.0.0.1", origin.port, tls=False)
        assert rec.status == "ok", rec.error
        assert rec.proxy_type == "http_connect"
        assert rec.stages["proxy"] >= 0.0
        # The CONNECT request must carry Proxy-Authorization with credentials.
        assert b"Proxy-Authorization: Basic " in seen_request["connect"]
        # Credentials must never appear verbatim in the JSONL record.
        blob = rec.to_json()
        assert "proxypass" not in blob
        assert "proxyuser" not in blob
        assert origin_handler_calls, "origin server was not reached through the tunnel"
    finally:
        origin.stop()
        proxy.stop()


def test_http_connect_proxy_407_categorized_as_proxy_auth() -> None:
    def handler(c: socket.socket) -> None:
        _recv_until(c, b"\r\n\r\n")
        c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")

    proxy = _ServerThread(handler)
    proxy.start()
    try:
        plan = _plan(
            "127.0.0.1",
            443,
            stages=["connect"],
            proxy={
                "mode": "http_connect",
                "host": "127.0.0.1",
                "port": proxy.port,
                "credentials": {"user": "u", "password": "secret-pw"},
            },
        )
        runner, _ = _make_runner(plan)
        rec = runner.measure_target("127.0.0.1", 443, tls=False)
        assert rec.status == "error"
        assert rec.error_category == CAT_PROXY_AUTH
        assert "secret-pw" not in rec.to_json()
    finally:
        proxy.stop()


# ---------------------------------------------------------------------------
# SOCKS5 proxy
# ---------------------------------------------------------------------------


def test_socks5_proxy_no_auth_tunnel() -> None:
    origin_seen: list[bytes] = []

    def socks_handler(c: socket.socket) -> None:
        # Greeting
        head = c.recv(2)
        assert head[0] == 0x05
        nmethods = head[1]
        c.recv(nmethods)
        c.sendall(bytes([0x05, 0x00]))  # select no-auth
        # Request
        req_head = c.recv(4)
        assert req_head[0] == 0x05
        assert req_head[1] == 0x01  # CONNECT
        atyp = req_head[3]
        if atyp == 0x01:
            c.recv(4)
        elif atyp == 0x03:
            length = c.recv(1)[0]
            c.recv(length)
        elif atyp == 0x04:
            c.recv(16)
        else:
            return
        port_bytes = c.recv(2)
        port = int.from_bytes(port_bytes, "big")
        upstream = socket.create_connection(("127.0.0.1", port), timeout=2.0)
        c.sendall(b"\x05\x00\x00\x01" + bytes([127, 0, 0, 1]) + (port).to_bytes(2, "big"))
        import select

        socks = [c, upstream]
        while socks:
            r, _, _ = select.select(socks, [], [], 2.0)
            if not r:
                break
            for s in r:
                try:
                    data = s.recv(4096)
                except OSError:
                    data = b""
                if not data:
                    socks = [x for x in socks if x is not s]
                    continue
                other = upstream if s is c else c
                try:
                    other.sendall(data)
                except OSError:
                    socks = [x for x in socks if x is not other]

    def origin_handler(c: socket.socket) -> None:
        req = _recv_until(c, b"\r\n\r\n")
        origin_seen.append(req)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    origin = _ServerThread(origin_handler)
    origin.start()
    proxy = _ServerThread(socks_handler)
    proxy.start()
    try:
        plan = _plan(
            "127.0.0.1",
            origin.port,
            stages=["connect", "http"],
            http_method="GET",
            proxy={"mode": "socks5", "host": "127.0.0.1", "port": proxy.port},
        )
        runner, _ = _make_runner(plan)
        rec = runner.measure_target("127.0.0.1", origin.port, tls=False)
        assert rec.status == "ok", rec.error
        assert rec.proxy_type == "socks5"
        assert origin_seen, "origin not reached via SOCKS5"
    finally:
        origin.stop()
        proxy.stop()


def test_socks5_proxy_userpass_success_and_no_creds_in_jsonl() -> None:
    received_userpass: list[bytes] = []

    def socks_handler(c: socket.socket) -> None:
        head = c.recv(2)
        nmethods = head[1]
        c.recv(nmethods)
        c.sendall(bytes([0x05, 0x02]))  # select username/password
        # RFC 1929 sub-negotiation
        ver = c.recv(1)[0]
        assert ver == 0x01
        ulen = c.recv(1)[0]
        user = c.recv(ulen)
        plen = c.recv(1)[0]
        pw = c.recv(plen)
        received_userpass.append(user + b":" + pw)
        if user == b"socksuser" and pw == b"sockspass":
            c.sendall(bytes([0x01, 0x00]))
        else:
            c.sendall(bytes([0x01, 0x01]))
            return
        # CONNECT request
        req_head = c.recv(4)
        atyp = req_head[3]
        if atyp == 0x01:
            c.recv(4)
        elif atyp == 0x03:
            length = c.recv(1)[0]
            c.recv(length)
        elif atyp == 0x04:
            c.recv(16)
        port_bytes = c.recv(2)
        port = int.from_bytes(port_bytes, "big")
        upstream = socket.create_connection(("127.0.0.1", port), timeout=2.0)
        c.sendall(b"\x05\x00\x00\x01" + bytes([127, 0, 0, 1]) + port.to_bytes(2, "big"))
        upstream.close()
        c.close()

    def origin_handler(c: socket.socket) -> None:
        _recv_until(c, b"\r\n\r\n")
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    origin = _ServerThread(origin_handler)
    origin.start()
    proxy = _ServerThread(socks_handler)
    proxy.start()
    try:
        plan = _plan(
            "127.0.0.1",
            origin.port,
            # This case verifies RFC 1929 success and credential redaction.
            # HTTP relay is independently exercised by the no-auth SOCKS test.
            stages=["connect"],
            proxy={
                "mode": "socks5",
                "host": "127.0.0.1",
                "port": proxy.port,
                "credentials": {"user": "socksuser", "password": "sockspass"},
            },
        )
        runner, _ = _make_runner(plan)
        rec = runner.measure_target("127.0.0.1", origin.port, tls=False)
        assert rec.status == "ok", rec.error
        blob = rec.to_json()
        assert "socksuser" not in blob
        assert "sockspass" not in blob
        assert received_userpass == [b"socksuser:sockspass"]
    finally:
        origin.stop()
        proxy.stop()


def test_socks5_proxy_userpass_rejected_categorized() -> None:
    def socks_handler(c: socket.socket) -> None:
        head = c.recv(2)
        c.recv(head[1])
        c.sendall(bytes([0x05, 0x02]))
        c.recv(1)  # ver
        ulen = c.recv(1)[0]
        c.recv(ulen)
        plen = c.recv(1)[0]
        c.recv(plen)
        c.sendall(bytes([0x01, 0x01]))  # failure

    proxy = _ServerThread(socks_handler)
    proxy.start()
    try:
        plan = _plan(
            "127.0.0.1",
            443,
            stages=["connect"],
            proxy={
                "mode": "socks5",
                "host": "127.0.0.1",
                "port": proxy.port,
                "credentials": {"user": "u", "password": "leak-pw"},
            },
        )
        runner, _ = _make_runner(plan)
        rec = runner.measure_target("127.0.0.1", 443, tls=False)
        assert rec.status == "error"
        assert rec.error_category == CAT_PROXY_AUTH
        assert "leak-pw" not in rec.to_json()
    finally:
        proxy.stop()


# ---------------------------------------------------------------------------
# TLS stage
# ---------------------------------------------------------------------------


def test_tls_handshake_success_and_http_over_tls(tmp_path: Path) -> None:
    cert_file, key_file = _write_cert_files(tmp_path, "127.0.0.1")

    def handler(c: socket.socket) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        try:
            tls = ctx.wrap_socket(c, server_side=True)
        except ssl.SSLError:
            return
        req = _recv_until(tls, b"\r\n\r\n")
        first = req.split(b"\r\n", 1)[0].decode("latin-1") if req else ""
        body = first.encode()
        tls.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        with suppress(OSError):
            tls.close()

    server = _ServerThread(handler)
    server.start()
    try:
        # Client context that trusts our self-signed cert and matches the IP SAN.
        def client_ctx_factory() -> ssl.SSLContext:
            ctx = ssl.create_default_context(cafile=str(cert_file))
            return ctx

        plan = _plan(
            "127.0.0.1",
            server.port,
            stages=["connect", "tls", "http"],
            http_method="GET",
            tls_target=True,
            targets_override=None,
        )
        # Rebuild targets so tls flag is true for the runner.
        runner, cfg = _make_runner(plan, tls_context_factory=client_ctx_factory)
        rec = runner.measure_target("127.0.0.1", server.port, tls=True)
        assert rec.status == "ok", rec.error
        assert rec.stages["tls"] >= 0.0
        assert rec.stages["http"] >= 0.0
    finally:
        server.stop()


def test_tls_handshake_failure_categorized(tmp_path: Path) -> None:
    cert_file, key_file = _write_cert_files(tmp_path, "127.0.0.1")

    def handler(c: socket.socket) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        try:
            tls = ctx.wrap_socket(c, server_side=True)
            tls.close()
        except ssl.SSLError:
            pass

    server = _ServerThread(handler)
    server.start()
    try:
        # Default client context trusts system CAs, not our self-signed cert.
        runner, _ = _make_runner(
            _plan("127.0.0.1", server.port, stages=["connect", "tls"], connect_timeout_ms=2000)
        )
        rec = runner.measure_target("127.0.0.1", server.port, tls=True)
        assert rec.status == "error"
        assert rec.error_category == CAT_TLS
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Egress verification
# ---------------------------------------------------------------------------


def test_legacy_egress_callback_is_observed_but_not_attributed() -> None:
    server = _ServerThread(lambda c: None)
    server.start()
    try:
        runner, _ = _make_runner(
            _plan(
                "127.0.0.1",
                server.port,
                stages=["connect"],
                egress_verify_url="https://verifier.invalid/",
            ),
            egress_verifier=lambda url: "203.0.113.7",
        )
        rec = runner.measure_target("127.0.0.1", server.port, tls=False)
        assert rec.status == "ok"
        assert rec.egress_ok is None
        assert rec.observed_egress == "203.0.113.7"
        assert rec.egress_path == "unattributed"
        assert rec.egress_scope == "unattributed"
        blob = json.loads(rec.to_json())
        assert blob["egress_ok"] is None
        assert blob["observed_egress"] == "203.0.113.7"
        assert blob["egress_path"] == "unattributed"
        assert blob["egress_scope"] == "unattributed"
    finally:
        server.stop()


def test_legacy_egress_callback_failure_does_not_claim_configured_path() -> None:
    def verifier(url: str):
        raise RuntimeError("no egress")

    server = _ServerThread(lambda c: None)
    server.start()
    try:
        runner, _ = _make_runner(
            _plan(
                "127.0.0.1",
                server.port,
                stages=["connect"],
                egress_verify_url="https://verifier.invalid/",
            ),
            egress_verifier=verifier,
        )
        rec = runner.measure_target("127.0.0.1", server.port, tls=False)
        assert rec.status == "ok"  # probe itself succeeded
        assert rec.egress_ok is None
        assert rec.observed_egress is None
        assert rec.egress_path == "unattributed"
        assert rec.egress_scope == "unattributed"
    finally:
        server.stop()


@pytest.mark.parametrize(
    ("proxy", "expected_path"),
    [
        (ProxyConfig(), "direct"),
        (
            ProxyConfig(mode="http_connect", host="127.0.0.1", port=3128),
            "http_connect",
        ),
        (ProxyConfig(mode="socks5", host="127.0.0.1", port=1080), "socks5"),
    ],
)
def test_default_egress_verifier_attributes_the_configured_path(
    monkeypatch, proxy: ProxyConfig, expected_path: str
) -> None:
    seen: list[ProxyConfig | None] = []

    def verifier(url: str, *, connect_timeout: float, read_timeout: float, proxy=None):
        seen.append(proxy)
        return "198.51.100.9"

    monkeypatch.setattr("kaleido.measure.default_egress_verifier", verifier)
    cfg = MeasureConfig(
        egress_verify_url="https://verifier.invalid/",
        proxy=proxy,
    )
    result = MeasureRunner(cfg)._verify_egress()

    assert result == (True, "198.51.100.9", expected_path, "configured_path")
    assert seen == [proxy]


def test_proxy_plan_legacy_callback_cannot_create_false_positive() -> None:
    cfg = MeasureConfig(
        egress_verify_url="https://verifier.invalid/",
        proxy=ProxyConfig(mode="socks5", host="127.0.0.1", port=1080),
        egress_verifier=lambda _url: "198.51.100.9",
    )

    egress_ok, observed, path, scope = MeasureRunner(cfg)._verify_egress()

    assert egress_ok is None
    assert observed == "198.51.100.9"
    assert path == "unattributed"
    assert scope == "unattributed"


def test_default_egress_verifier_http_connect_uses_proxy_path(monkeypatch) -> None:
    requests: list[bytes] = []

    def proxy_handler(c: socket.socket) -> None:
        connect_request = _recv_until(c, b"\r\n\r\n")
        requests.append(connect_request)
        c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        verifier_request = _recv_until(c, b"\r\n\r\n")
        requests.append(verifier_request)
        c.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n198.51.100.9"
        )

    proxy_server = _ServerThread(proxy_handler)
    proxy_server.start()
    try:
        # This test isolates routing/attribution; TLS itself has dedicated
        # certificate tests above.
        monkeypatch.setattr("kaleido.measure.tls_handshake", lambda sock, _host: sock)
        observed = default_egress_verifier(
            "https://verifier.invalid/check",
            connect_timeout=1.0,
            read_timeout=1.0,
            proxy=ProxyConfig(
                mode="http_connect",
                host="127.0.0.1",
                port=proxy_server.port,
            ),
        )

        assert observed == "198.51.100.9"
        assert requests[0].startswith(b"CONNECT verifier.invalid:443 HTTP/1.1\r\n")
        assert requests[1].startswith(b"GET /check HTTP/1.1\r\n")
    finally:
        proxy_server.stop()


# ---------------------------------------------------------------------------
# JSONL output + credential hygiene
# ---------------------------------------------------------------------------


def test_run_plan_writes_jsonl() -> None:
    server = _ServerThread(_http_handler(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
    server.start()
    try:
        plan = _plan(
            "127.0.0.1",
            server.port,
            stages=["connect", "http"],
            http_method="GET",
            proxy={
                "mode": "http_connect",
                "host": "127.0.0.1",
                "port": server.port,
            },
        )
        # The proxy here points at the origin server (which is not a real
        # proxy); we only check JSONL shape, not the tunnel result.
        buf = io.StringIO()
        run_plan(plan, out=buf)
        line = buf.getvalue().strip()
        assert line.startswith("{") and line.endswith("}")
        record = json.loads(line)
        for key in (
            "timestamp",
            "network",
            "target",
            "proxy_type",
            "stages",
            "status",
            "error_category",
            "error",
            "egress_ok",
            "egress_path",
            "egress_scope",
            "observed_egress",
            "plan_id",
        ):
            assert key in record, f"missing {key}"
        # No credential-related field ever appears.
        assert "password" not in str(record)
        assert "user" not in {k.lower() for k in record}
    finally:
        server.stop()


def test_credentials_never_in_jsonl_even_on_errors() -> None:
    plan = {
        "network": "n",
        "allow_private": True,
        "connect_timeout_ms": 500,
        "stages": ["connect"],
        "proxy": {
            "mode": "socks5",
            "host": "127.0.0.1",
            "port": 1,  # connect will fail/refuse quickly
            "credentials": {"user": "u123", "password": "p456"},
        },
        "targets": [{"host": "127.0.0.1", "port": 1, "tls": False}],
    }
    runner, _ = _make_runner(json.dumps(plan))
    rec = runner.measure_target("127.0.0.1", 1, tls=False)
    blob = rec.to_json()
    assert "u123" not in blob
    assert "p456" not in blob


def test_jsonl_is_single_line_and_sorted() -> None:
    server = _ServerThread(lambda c: None)
    server.start()
    try:
        runner, _ = _make_runner(_plan("127.0.0.1", server.port, stages=["connect"]))
        rec = runner.measure_target("127.0.0.1", server.port, tls=False)
        line = rec.to_json()
        assert "\n" not in line
        # Sorted keys: "egress_ok" precedes "error" precedes "network" etc.
        keys = list(json.loads(line).keys())
        assert keys == sorted(keys)
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Plan parsing
# ---------------------------------------------------------------------------


def test_parse_plan_rejects_invalid_mode() -> None:
    with pytest.raises(ProbeError):
        parse_plan({"proxy": {"mode": "vpn", "host": "h", "port": 1}, "targets": []})


def test_parse_plan_rejects_empty_targets() -> None:
    with pytest.raises(ProbeError):
        parse_plan({"targets": []})


def test_parse_plan_rejects_unknown_stage() -> None:
    with pytest.raises(ProbeError):
        parse_plan({"stages": ["frobnicate"], "targets": [{"host": "1.1.1.1", "port": 80}]})


def test_parse_plan_rejects_bad_http_method() -> None:
    with pytest.raises(ProbeError):
        parse_plan({"http_method": "POST", "targets": [{"host": "1.1.1.1", "port": 80}]})


def test_load_plan_rejects_invalid_json() -> None:
    with pytest.raises(ProbeError):
        load_plan("{not json")


def test_parse_plan_assigns_plan_id_when_missing() -> None:
    cfg, _ = parse_plan({"targets": [{"host": "127.0.0.1", "port": 80, "tls": False}]})
    assert cfg.plan_id
    assert len(cfg.plan_id) >= 8


# ---------------------------------------------------------------------------
# Unit tests for pure helpers
# ---------------------------------------------------------------------------


def test_build_http_request_omits_hop_by_hop_headers() -> None:
    req = build_http_request(
        "GET", "/", "example.com", 443, {"Proxy-Authorization": "x", "X-Trace": "y"}
    )
    assert b"Proxy-Authorization" not in req
    assert b"X-Trace: y" in req
    assert req.startswith(b"GET / HTTP/1.1\r\n")
    assert b"Host: example.com\r\n" in req


def test_scrub_creds_removes_fragments() -> None:
    out = scrub_creds("connect failed for user=secret and pw=hunter2", ["secret", "hunter2"])
    assert "secret" not in out
    assert "hunter2" not in out
    assert "<redacted>" in out


def test_redacted_proxy_dict_has_no_credentials() -> None:
    p = ProxyConfig(
        mode=PROXY_SOCKS5,
        host="h",
        port=1,
        user="u",
        password="p",  # noqa: S106 - deliberately synthetic test credential
    )
    d = p.redacted_dict()
    assert "user" not in d
    assert "password" not in d
    assert d["has_credentials"] is True


def test_record_to_json_roundtrip() -> None:
    rec = Record(
        timestamp="2026-08-12T00:00:00Z",
        network="n",
        target="h:1",
        proxy_type="direct",
        stages={"connect": 0.1, "proxy": 0.0, "tls": 0.0, "http": 0.0},
        status="ok",
        error_category=None,
        error=None,
        egress_ok=True,
        observed_egress="1.2.3.4",
        plan_id="p",
    )
    blob = json.loads(rec.to_json())
    assert blob["status"] == "ok"
    assert blob["observed_egress"] == "1.2.3.4"
    assert blob["egress_path"] is None
    assert blob["egress_scope"] == "not_attempted"
    assert blob["stages"]["connect"] == 0.1


# ---------------------------------------------------------------------------
# BoundedConn unit test
# ---------------------------------------------------------------------------


def test_bounded_conn_recv_until_sentinel() -> None:
    a, b = socket.socketpair()
    try:
        BoundedConn(a, read_timeout=2.0).sendall(b"HTTP/1.1 200 OK\r\nHeader: v\r\n\r\nbody")
        bc = BoundedConn(b, read_timeout=2.0)
        buf, found = bc.recv_until(b"\r\n\r\n")
        assert found is True
        assert buf.startswith(b"HTTP/1.1 200 OK")
    finally:
        a.close()
        b.close()


def test_bounded_conn_recv_exact() -> None:
    a, b = socket.socketpair()
    try:
        a.sendall(b"abcdef")
        bc = BoundedConn(b, read_timeout=2.0)
        assert bc.recv_exact(3) == b"abc"
        assert bc.recv_exact(3) == b"def"
    finally:
        a.close()
        b.close()
