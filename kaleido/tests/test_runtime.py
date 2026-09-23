# Tests for kaleido.runtime (LAB ONLY).
# All loopback, self-signed TLS 1.3, no real credentials or network.

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import ssl
import struct
import sys
from contextlib import suppress
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kaleido import runtime as rt  # noqa: E402
from kaleido.protocol import SERVER_FLIGHT_SIZE, ClientHandshake  # noqa: E402

# --- Self-signed cert fixture ------------------------------------------------


@pytest_asyncio.fixture
async def cert(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "kaleido-lab"),
        ]
    )
    now = datetime.now(UTC)
    cert_obj = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("127.0.0.1")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return {"cert": str(cert_path), "key": str(key_path)}


def _server_ctx(cert):
    return rt.make_server_ssl_context(cert["cert"], cert["key"])


def _client_ctx():
    return rt.make_client_ssl_context(insecure_lab=True)


async def _echo_server(host="127.0.0.1", port=0):
    """Plain TCP echo server."""

    async def handle(reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            with suppress(OSError):
                writer.close()

    server = await asyncio.start_server(handle, host, port)
    return server, server.sockets[0].getsockname()[1]


def _basic_configs():
    secret = b"lab-test-secret-do-not-use-in-prod"
    server_cfg = rt.RuntimeConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        auth_secret=secret,
        protocol_mode="lab",
        insecure_outer_tls_for_lab=True,
        inner_idle_timeout=5.0,
        dial_timeout=3.0,
    )
    client_cfg = rt.RuntimeConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        auth_secret=secret,
        protocol_mode="lab",
        insecure_outer_tls_for_lab=True,
        socks_listen_host="127.0.0.1",
        socks_listen_port=0,
        inner_idle_timeout=5.0,
    )
    return client_cfg, server_cfg, secret


# --- Tests ------------------------------------------------------------------


def _kal1_configs():
    client_cfg, server_cfg, secret = _basic_configs()
    identity = Ed25519PrivateKey.generate()
    server_cfg.protocol_mode = "kal1"
    server_cfg.kal1_server_identity_private = identity
    client_cfg.protocol_mode = "kal1"
    client_cfg.kal1_server_identity_public = identity.public_key()
    return client_cfg, server_cfg, secret


async def _start_remote_carriers(client_cfg, server_cfg, cert, client_events, server_events):
    await client_events.start()
    await server_events.start()
    server = rt.Carrier(server_cfg, _server_ctx(cert), server_events, role="server")
    await server.start()
    client = rt.Carrier(
        client_cfg,
        _client_ctx(),
        client_events,
        role="client",
        server_endpoint=(server_cfg.listen_host, server.listen_port, "kaleido-lab"),
    )
    await client.start()
    return client, server


async def _stop_remote_carriers(client, server, client_events, server_events):
    await client.stop()
    await server.stop()
    await client_events.stop()
    await server_events.stop()


async def _request_loopback_via_socks(socks_port, target_port):
    reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
    writer.write(bytes([0x05, 0x01, 0x00]))
    await writer.drain()
    assert await reader.readexactly(2) == bytes([0x05, 0x00])
    writer.write(
        bytes([0x05, 0x01, 0x00, 0x01])
        + ipaddress.IPv4Address("127.0.0.1").packed
        + struct.pack(">H", target_port)
    )
    await writer.drain()
    return reader, writer, await reader.readexactly(10)


def test_client_tls_context_verifies_certificates_by_default():
    ctx = rt.make_client_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


@pytest.mark.asyncio
async def test_short_runtime_auth_secret_is_rejected(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    server_cfg.auth_secret = b"too-short"
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert))
    with pytest.raises(ValueError, match="at least 32 bytes"):
        await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_kal1_requires_pinned_server_identity(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    client_cfg.protocol_mode = "kal1"
    server_cfg.protocol_mode = "kal1"
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert))
    with pytest.raises(ValueError, match="Ed25519"):
        await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_insecure_client_context_requires_explicit_runtime_lab_flag(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    client_cfg.insecure_outer_tls_for_lab = False
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert))
    with pytest.raises(ValueError, match="insecure outer TLS"):
        await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_outer_sessions", 0, "max_outer_sessions"),
        ("max_outer_sessions", 1.5, "max_outer_sessions"),
        ("max_socks_sessions", False, "max_socks_sessions"),
        ("socks_handshake_timeout", 0.0, "socks_handshake_timeout"),
    ],
)
async def test_resource_limits_are_validated(cert, field, value, message):
    _client_cfg, server_cfg, _secret = _basic_configs()
    setattr(server_cfg, field, value)
    carrier = rt.Carrier(server_cfg, _server_ctx(cert), rt.EventBus(), role="server")
    with pytest.raises(ValueError, match=message):
        await carrier.start()


@pytest.mark.asyncio
async def test_socks_roundtrip(cert):
    client_cfg, server_cfg, secret = _basic_configs()
    echo, echo_port = await _echo_server()
    server_cfg.target_policy = rt.TargetPolicy(allow_hosts={"127.0.0.1"}, allow_ports={echo_port})
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    try:
        socks_port = runtime.client.socks_port
        reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
        # SOCKS5 greeting, no auth
        writer.write(bytes([0x05, 0x01, 0x00]))
        await writer.drain()
        resp = await reader.readexactly(2)
        assert resp == bytes([0x05, 0x00])
        # CONNECT 127.0.0.1:echo_port
        writer.write(
            bytes([0x05, 0x01, 0x00, 0x01])
            + ipaddress.IPv4Address("127.0.0.1").packed
            + struct.pack(">H", echo_port)
        )
        await writer.drain()
        rep = await reader.readexactly(10)
        assert rep[0] == 0x05 and rep[1] == 0x00, f"expected success, got {rep[1]:#x}"
        # Roundtrip data
        payload = b"kaleido-roundtrip-" + os.urandom(32)
        writer.write(payload)
        await writer.drain()
        received = await reader.readexactly(len(payload))
        assert received == payload
        writer.close()
        await writer.wait_closed()
    finally:
        await runtime.stop()
        echo.close()
        await echo.wait_closed()
    types = [e["type"] for e in events.records]
    assert "auth.success" in types
    assert "dial.ok" in types


@pytest.mark.asyncio
async def test_remote_client_event_bus_records_dial_ok_after_success(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    echo, echo_port = await _echo_server()
    server_cfg.target_policy = rt.TargetPolicy(
        allow_hosts={"127.0.0.1"}, allow_ports={echo_port}
    )
    client_events = rt.EventBus()
    server_events = rt.EventBus()
    client, server = await _start_remote_carriers(
        client_cfg, server_cfg, cert, client_events, server_events
    )
    try:
        reader, writer, reply = await _request_loopback_via_socks(
            client.socks_port, echo_port
        )
        assert reply[1] == rt.SOCKS_REPLY_SUCCESS
        payload = b"remote-client-event"
        writer.write(payload)
        await writer.drain()
        assert await reader.readexactly(len(payload)) == payload
        writer.close()
        await writer.wait_closed()
    finally:
        await _stop_remote_carriers(client, server, client_events, server_events)
        echo.close()
        await echo.wait_closed()

    client_dials = [event for event in client_events.records if event["type"] == "dial.ok"]
    assert len(client_dials) == 1
    assert client_dials[0]["role"] == "client"
    assert not ({"host", "port", "session"} & client_dials[0].keys())
    assert any(event["type"] == "dial.ok" for event in server_events.records)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_reply"),
    [
        ("dial", rt.SOCKS_REPLY_NOT_ALLOWED),
        ("auth", rt.SOCKS_REPLY_FAILURE),
    ],
)
async def test_remote_client_failures_never_emit_dial_ok(cert, failure, expected_reply):
    client_cfg, server_cfg, _secret = _basic_configs()
    server_cfg.target_policy = rt.TargetPolicy(allow_hosts={"127.0.0.1"}, allow_ports={1})
    if failure == "auth":
        client_cfg.auth_secret = b"different-lab-secret-with-at-least-32-bytes"
    client_events = rt.EventBus()
    server_events = rt.EventBus()
    client, server = await _start_remote_carriers(
        client_cfg, server_cfg, cert, client_events, server_events
    )
    try:
        _reader, writer, reply = await _request_loopback_via_socks(client.socks_port, 2)
        assert reply[1] == expected_reply
        writer.close()
        await writer.wait_closed()
    finally:
        await _stop_remote_carriers(client, server, client_events, server_events)

    assert not any(event["type"] == "dial.ok" for event in client_events.records)
    expected_event = "auth.failed" if failure == "auth" else "auth.success"
    assert any(event["type"] == expected_event for event in client_events.records)


@pytest.mark.asyncio
async def test_kal1_socks_roundtrip_uses_authenticated_record_layer(cert):
    client_cfg, server_cfg, _secret = _kal1_configs()
    echo, echo_port = await _echo_server()
    server_cfg.target_policy = rt.TargetPolicy(allow_hosts={"127.0.0.1"}, allow_ports={echo_port})
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    assert runtime.client._adapter.name == "kal1"
    assert runtime.server._adapter.name == "kal1"
    await runtime.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", runtime.client.socks_port)
        writer.write(bytes([0x05, 0x01, 0x00]))
        await writer.drain()
        assert await reader.readexactly(2) == bytes([0x05, 0x00])
        writer.write(
            bytes([0x05, 0x01, 0x00, 0x01])
            + ipaddress.IPv4Address("127.0.0.1").packed
            + struct.pack(">H", echo_port)
        )
        await writer.drain()
        assert (await reader.readexactly(10))[1] == rt.SOCKS_REPLY_SUCCESS
        payload = os.urandom(8192)
        writer.write(payload)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(payload)), timeout=3.0) == payload
        writer.close()
        await writer.wait_closed()
    finally:
        await runtime.stop()
        echo.close()
        await echo.wait_closed()
    assert any(e["type"] == "auth.success" for e in events.records)
    assert any(e["type"] == "dial.ok" for e in events.records)


@pytest.mark.asyncio
async def test_kal1_wrong_psk_gets_decoy_before_server_flight(cert):
    client_cfg, server_cfg, _secret = _kal1_configs()
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    try:
        reader, writer = await rt.dial_outer(
            client_cfg,
            _client_ctx(),
            "127.0.0.1",
            runtime.server.listen_port,
            server_hostname="kaleido-lab",
        )
        ok = await rt.client_authenticate(reader, writer, client_cfg, b"wrong-kal1-psk")
        assert ok is False
        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        # The client attempted to read a fixed-size KAL server flight, consuming
        # the beginning of the cover response. Its generic body must remain.
        assert b"OK</body>" in data
        writer.close()
        with suppress(ConnectionError, OSError):
            await writer.wait_closed()
    finally:
        await runtime.stop()
    assert any(e["type"] == "auth.failed" for e in events.records)


@pytest.mark.asyncio
async def test_kal1_replayed_first_flight_gets_only_decoy(cert):
    client_cfg, server_cfg, secret = _kal1_configs()
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    try:
        reader1, writer1 = await rt.dial_outer(
            client_cfg,
            _client_ctx(),
            "127.0.0.1",
            runtime.server.listen_port,
            server_hostname="kaleido-lab",
        )
        first = ClientHandshake(
            server_identity_pub=client_cfg.kal1_server_identity_public,
            psk=secret,
        ).start()
        writer1.write(first)
        await writer1.drain()
        server_flight = await reader1.readexactly(SERVER_FLIGHT_SIZE)
        assert not server_flight.startswith(b"HTTP/")
        writer1.close()
        with suppress(ConnectionError, OSError):
            await writer1.wait_closed()

        reader2, writer2 = await rt.dial_outer(
            client_cfg,
            _client_ctx(),
            "127.0.0.1",
            runtime.server.listen_port,
            server_hostname="kaleido-lab",
        )
        writer2.write(first)
        await writer2.drain()
        replay_response = await asyncio.wait_for(reader2.read(4096), timeout=3.0)
        assert replay_response.startswith(b"HTTP/1.1")
        writer2.close()
        with suppress(ConnectionError, OSError):
            await writer2.wait_closed()
    finally:
        await runtime.stop()


@pytest.mark.asyncio
async def test_wrong_auth_returns_decoy(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    server_cfg.auth_secret = b"correct-secret-for-lab-at-least-32b"
    client_cfg.auth_secret = b"correct-secret-for-lab-at-least-32b"
    server_cfg.inner_idle_timeout = 2.0
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    try:
        port = runtime.server.listen_port
        reader, writer = await rt.dial_outer(
            client_cfg, _client_ctx(), "127.0.0.1", port, server_hostname="kaleido-lab"
        )
        # Authenticate as client with WRONG secret.
        ok = await rt.client_authenticate(reader, writer, client_cfg, b"wrong-secret")
        assert ok is False
        # Server should now emit decoy HTTP. Note: client_authenticate read 1
        # ack byte; on auth failure that byte is the 'H' from "HTTP/1.1 ...",
        # so the remaining stream begins with "TTP/1.1 200 OK". Assert by body
        # marker and status code substring rather than startswith.
        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        assert b"200 OK" in data, data[:128]
        assert b"OK</body>" in data, data[:128]
        writer.close()
        await writer.wait_closed()
    finally:
        await runtime.stop()
    types = [e["type"] for e in events.records]
    assert "auth.failed" in types
    assert not any(e["type"] == "dial.ok" for e in events.records)


@pytest.mark.asyncio
async def test_forbidden_target_denied(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    # allow only port 1; asking for port 2 -> port_not_allowed
    server_cfg.target_policy = rt.TargetPolicy(allow_hosts={"127.0.0.1"}, allow_ports={1})
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    try:
        socks_port = runtime.client.socks_port
        reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
        writer.write(bytes([0x05, 0x01, 0x00]))
        await writer.drain()
        await reader.readexactly(2)
        writer.write(
            bytes([0x05, 0x01, 0x00, 0x01])
            + ipaddress.IPv4Address("127.0.0.1").packed
            + struct.pack(">H", 2)
        )
        await writer.drain()
        rep = await reader.readexactly(10)
        assert rep[1] == 0x02, f"expected not-allowed, got {rep[1]:#x}"
        writer.close()
        await writer.wait_closed()
    finally:
        await runtime.stop()
    denied = [e for e in events.records if e["type"] == "dial.denied"]
    assert denied, "expected dial.denied event"
    assert denied[0]["reason"] == "port_not_allowed"


@pytest.mark.asyncio
async def test_loopback_denied_by_default(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    # Default policy: no allow_hosts -> loopback denied
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    try:
        socks_port = runtime.client.socks_port
        reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
        writer.write(bytes([0x05, 0x01, 0x00]))
        await writer.drain()
        await reader.readexactly(2)
        writer.write(
            bytes([0x05, 0x01, 0x00, 0x01])
            + ipaddress.IPv4Address("127.0.0.1").packed
            + struct.pack(">H", 9)
        )
        await writer.drain()
        rep = await reader.readexactly(10)
        assert rep[1] == 0x02, f"expected not-allowed, got {rep[1]:#x}"
        writer.close()
        await writer.wait_closed()
    finally:
        await runtime.stop()
    denied = [e for e in events.records if e["type"] == "dial.denied"]
    assert denied
    assert denied[0]["reason"] == "loopback"


def test_allowlisted_hostname_cannot_resolve_to_private_address():
    policy = rt.TargetPolicy(allow_hosts={"allowed.example"})
    assert policy.evaluate("allowed.example", 443) == (True, "allow_host")
    assert policy.evaluate_resolved("allowed.example", "127.0.0.1", 443) == (
        False,
        "loopback",
    )
    assert policy.evaluate_resolved("allowed.example", "169.254.169.254", 443) == (
        False,
        "link_local",
    )


def test_public_targets_require_explicit_allow_public():
    default_policy = rt.TargetPolicy()
    assert default_policy.evaluate("1.1.1.1", 443) == (False, "not_allowlisted")
    public_policy = rt.TargetPolicy(allow_public=True)
    assert public_policy.evaluate("1.1.1.1", 443) == (True, "allow_public")
    assert public_policy.evaluate("127.0.0.1", 443) == (False, "loopback")
    assert public_policy.evaluate("100.64.0.1", 443) == (False, "non_global")
    assert public_policy.evaluate_resolved("allowed.example", "100.64.0.1", 443) == (
        False,
        "non_global",
    )


@pytest.mark.asyncio
async def test_clean_shutdown(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert))
    await runtime.start()
    sp = runtime.client.socks_port
    lp = runtime.server.listen_port
    reader, writer = await asyncio.open_connection("127.0.0.1", sp)
    writer.write(bytes([0x05, 0x01, 0x00]))
    await writer.drain()
    await reader.readexactly(2)
    await asyncio.wait_for(runtime.stop(), timeout=3.0)
    writer.close()
    with suppress(ConnectionError, OSError):
        await writer.wait_closed()
    # Ports should be free; rebinding to same port must succeed.
    s = socket.socket()
    s.bind(("127.0.0.1", lp))
    s.close()
    s2 = socket.socket()
    s2.bind(("127.0.0.1", sp))
    s2.close()


@pytest.mark.asyncio
async def test_shutdown_does_not_wait_forever_for_incomplete_tls_handshake(cert):
    """A raw TCP peer that never sends ClientHello is bounded by TLS timeout."""
    _client_cfg, server_cfg, _secret = _basic_configs()
    server_cfg.handshake_timeout = 0.2
    carrier = rt.Carrier(server_cfg, _server_ctx(cert), rt.EventBus(), role="server")
    await carrier.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", carrier.listen_port)
    try:
        await asyncio.wait_for(carrier.stop(), timeout=2.0)
    finally:
        writer.close()
        with suppress(ConnectionError, OSError):
            await writer.wait_closed()
        del reader


@pytest.mark.asyncio
async def test_oversize_frame_rejected(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    server_cfg.max_frame_payload = 1024
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    try:
        port = runtime.server.listen_port
        reader, writer = await rt.dial_outer(
            client_cfg, _client_ctx(), "127.0.0.1", port, server_hostname="kaleido-lab"
        )
        ok = await rt.client_authenticate(reader, writer, client_cfg, client_cfg.auth_secret)
        assert ok
        # Send a frame whose declared length exceeds max.
        writer.write(struct.pack(">I", 2048) + b"\x02" * 8)
        await writer.drain()
        with suppress(TimeoutError):
            await asyncio.wait_for(reader.read(64), timeout=3.0)
        writer.close()
        with suppress(ConnectionError, OSError):
            await writer.wait_closed()
    finally:
        await runtime.stop()
    assert not any(e["type"] == "dial.ok" for e in events.records)


@pytest.mark.asyncio
async def test_events_redacted_no_secret_leak(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    server_cfg.auth_secret = b"super-secret-value-for-lab-32bytes"
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    await runtime.stop()
    blob = repr(events.records)
    assert "super-secret-value-for-lab-32bytes" not in blob


@pytest.mark.asyncio
async def test_event_bus_retains_only_redacted_records():
    events = rt.EventBus()
    await events.start()
    await events.emit({"type": "test", "auth_secret": "must-not-remain"})
    await events.stop()
    assert events.records[0]["auth_secret"] == "<redacted>"  # noqa: S105


@pytest.mark.asyncio
async def test_event_bus_is_bounded_and_coalesces_flood_drops():
    sink_entered = asyncio.Event()
    release_sink = asyncio.Event()

    async def slow_sink(_event):
        sink_entered.set()
        await release_sink.wait()

    events = rt.EventBus(slow_sink, max_queue=2, max_records=3)
    await events.start()
    await events.emit({"type": "first"})
    await asyncio.wait_for(sink_entered.wait(), timeout=1.0)
    for index in range(20):
        await events.emit({"type": "flood", "index": index})
    assert events.total_dropped > 0
    release_sink.set()
    await events.stop()

    assert len(events.records) <= 3
    summaries = [event for event in events.records if event["type"] == "eventbus.dropped"]
    assert summaries
    assert sum(int(event["count"]) for event in summaries) == events.total_dropped


@pytest.mark.asyncio
async def test_event_bus_destination_metadata_is_opt_in():
    private = {
        "type": "dial.ok",
        "host": "private.example",
        "port": 443,
        "peer": "192.0.2.1:1234",
        "session": 123,
        "target": "private.example:443",
        "nested": {"host": "nested.example", "reason": "allowed"},
        "attempts": [{"url": "https://private.example/", "result": "denied"}],
        "auth_secret": "do-not-retain",
    }
    events = rt.EventBus()
    await events.start()
    await events.emit(private)
    await events.stop()
    record = events.records[0]
    assert not ({"host", "port", "peer", "session", "target"} & record.keys())
    assert record["nested"] == {"reason": "allowed"}
    assert record["attempts"] == [{"result": "denied"}]
    assert record["auth_secret"] == "<redacted>"  # noqa: S105

    detailed = rt.EventBus(detailed_metadata=True)
    await detailed.start()
    await detailed.emit(private)
    await detailed.stop()
    assert detailed.records[0]["target"] == "private.example:443"


@pytest.mark.asyncio
async def test_stalled_partial_socks_handshake_times_out_and_closes(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    client_cfg.socks_handshake_timeout = 0.05
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", runtime.client.socks_port
        )
        writer.write(b"\x05")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
        writer.close()
        with suppress(ConnectionError, OSError):
            await writer.wait_closed()
    finally:
        await runtime.stop()
    assert any(event["type"] == "socks.handshake_timeout" for event in events.records)


@pytest.mark.asyncio
async def test_socks_session_limit_rejects_excess_connection(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    client_cfg.max_socks_sessions = 1
    client_cfg.socks_handshake_timeout = 2.0
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    first_reader, first_writer = await asyncio.open_connection(
        "127.0.0.1", runtime.client.socks_port
    )
    try:
        first_writer.write(b"\x05")
        await first_writer.drain()
        for _ in range(100):
            if len(runtime.client._socks_tasks) == 1:
                break
            await asyncio.sleep(0)
        assert len(runtime.client._socks_tasks) == 1

        rejected_reader, rejected_writer = await asyncio.open_connection(
            "127.0.0.1", runtime.client.socks_port
        )
        assert await asyncio.wait_for(rejected_reader.read(1), timeout=1.0) == b""
        rejected_writer.close()
        with suppress(ConnectionError, OSError):
            await rejected_writer.wait_closed()
    finally:
        first_writer.close()
        with suppress(ConnectionError, OSError):
            await first_writer.wait_closed()
        del first_reader
        await runtime.stop()
    assert any(event["type"] == "session.rejected" for event in events.records)


@pytest.mark.asyncio
async def test_outer_session_limit_rejects_excess_connection(cert):
    client_cfg, server_cfg, _secret = _basic_configs()
    server_cfg.max_outer_sessions = 1
    server_cfg.handshake_timeout = 2.0
    events = rt.EventBus()
    runtime = rt.Runtime(client_cfg, server_cfg, _client_ctx(), _server_ctx(cert), events)
    await runtime.start()
    first_reader, first_writer = await rt.dial_outer(
        client_cfg,
        _client_ctx(),
        "127.0.0.1",
        runtime.server.listen_port,
        server_hostname="kaleido-lab",
    )
    try:
        for _ in range(100):
            if len(runtime.server._sessions) == 1:
                break
            await asyncio.sleep(0)
        assert len(runtime.server._sessions) == 1
        rejected_reader, rejected_writer = await rt.dial_outer(
            client_cfg,
            _client_ctx(),
            "127.0.0.1",
            runtime.server.listen_port,
            server_hostname="kaleido-lab",
        )
        assert await asyncio.wait_for(rejected_reader.read(1), timeout=1.0) == b""
        rejected_writer.close()
        with suppress(ConnectionError, OSError):
            await rejected_writer.wait_closed()
    finally:
        first_writer.close()
        with suppress(ConnectionError, OSError):
            await first_writer.wait_closed()
        del first_reader
        await runtime.stop()
    assert any(event["type"] == "session.rejected" for event in events.records)


@pytest.mark.asyncio
async def test_pipe_pair_cancels_sibling_promptly():
    cancelled = asyncio.Event()

    async def complete() -> None:
        return

    async def block() -> None:
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    first = asyncio.create_task(complete())
    second = asyncio.create_task(block())
    await asyncio.wait_for(rt._run_pipe_pair(first, second), timeout=1.0)
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_socks_userpass_checks_username_and_password():
    cfg = rt.RuntimeConfig(
        auth_secret=b"a" * 32,
        protocol_mode="lab",
        socks_auth_required=True,
        socks_auth_username=b"expected-user",
        socks_auth_secret=b"expected-password",
    )

    async def attempt(username: bytes, password: bytes) -> bytes:
        request = (
            b"\x01"
            + bytes([len(username)])
            + username
            + bytes([len(password)])
            + password
        )
        reader = asyncio.StreamReader()
        reader.feed_data(request)
        reader.feed_eof()
        output = bytearray()

        class Writer:
            def write(self, data: bytes) -> None:
                output.extend(data)

            async def drain(self) -> None:
                return

        carrier = rt.Carrier(cfg, _client_ctx(), rt.EventBus(), role="client")
        with suppress(rt.SOCKSError):
            await carrier._socks_userpass(reader, Writer())  # type: ignore[arg-type]
        return bytes(output)

    assert await attempt(b"wrong-user", b"expected-password") == b"\x01\x01"
    assert await attempt(b"expected-user", b"wrong-password-value") == b"\x01\x01"
    assert await attempt(b"expected-user", b"expected-password") == b"\x01\x00"
