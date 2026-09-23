from __future__ import annotations

import asyncio
import math
import socket
import sys
import traceback
from types import SimpleNamespace
from typing import cast

import pytest

import kaleido.phonepath as phonepath
from kaleido.phonepath import (
    IP_UNICAST_IF,
    Connector,
    InterfaceBoundTcpRelay,
    RelayCleanupError,
    RelayConfig,
    RelayError,
    RelayLimitError,
    configure_ipv4_unicast_interface,
    open_interface_connection,
)

_TARGET = "203.0.113.10"


async def _echo_server() -> tuple[asyncio.Server, int]:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while chunk := await reader.read(65536):
                writer.write(chunk)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    return server, int(server.sockets[0].getsockname()[1])


async def _stall_server() -> tuple[asyncio.Server, int, asyncio.Event, asyncio.Event]:
    connected = asyncio.Event()
    release = asyncio.Event()

    async def stall(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connected.set()
        try:
            await release.wait()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(stall, "127.0.0.1", 0)
    return server, int(server.sockets[0].getsockname()[1]), connected, release


def _connector(port: int, seen: list[tuple[str, int, int, float]]) -> Connector:
    async def connect(
        host: str, target_port: int, index: int, timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        seen.append((host, target_port, index, timeout))
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        return reader, writer, "phone-local"

    return connect


class _FakeSocket:
    def __init__(self) -> None:
        self.options: list[tuple[int, int, int]] = []

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))


class _ConnectorSocket(_FakeSocket):
    def __init__(self) -> None:
        super().__init__()
        self.blocking: bool | None = None
        self.closed = False

    def setblocking(self, value: bool) -> None:
        self.blocking = value

    def getsockname(self) -> tuple[str, int]:
        return "phone-local", 49152

    def close(self) -> None:
        self.closed = True


class _AbortTransport:
    def __init__(self) -> None:
        self.abort_count = 0

    def abort(self) -> None:
        self.abort_count += 1


class _ControlledWriter:
    def __init__(
        self,
        release: asyncio.Event,
        *,
        first_error: str | None = None,
    ) -> None:
        self.transport = _AbortTransport()
        self.release = release
        self.first_error = first_error
        self.wait_calls = 0
        self.close_calls = 0

    def is_closing(self) -> bool:
        return True

    def close(self) -> None:
        self.close_calls += 1

    async def wait_closed(self) -> None:
        self.wait_calls += 1
        if self.wait_calls == 1 and self.first_error is not None:
            raise RuntimeError(self.first_error)
        await self.release.wait()


class _CollectingWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.eof_written = False

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.eof_written = True


class _ListenerSocket:
    def getsockname(self) -> tuple[str, int]:
        return "127.0.0.1", 49153


class _ControlledListener:
    def __init__(self, release: asyncio.Event, first_error: str) -> None:
        self.sockets = (cast(socket.socket, _ListenerSocket()),)
        self.release = release
        self.first_error = first_error
        self.close_calls = 0
        self.wait_calls = 0

    def close(self) -> None:
        self.close_calls += 1

    async def wait_closed(self) -> None:
        self.wait_calls += 1
        if self.wait_calls == 1:
            raise RuntimeError(self.first_error)
        await self.release.wait()


class _CloseFailingListener:
    def __init__(self, release: asyncio.Event, first_error: str) -> None:
        self.sockets = (cast(socket.socket, _ListenerSocket()),)
        self.release = release
        self.first_error = first_error
        self.close_calls = 0
        self.wait_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        if self.close_calls == 1:
            raise RuntimeError(self.first_error)

    async def wait_closed(self) -> None:
        self.wait_calls += 1
        await self.release.wait()


def test_interface_option_uses_network_byte_order() -> None:
    fake = _FakeSocket()
    configure_ipv4_unicast_interface(cast(socket.socket, fake), 20)
    assert fake.options == [(socket.IPPROTO_IP, IP_UNICAST_IF, socket.htonl(20))]


def test_config_rejects_nonpositive_fields() -> None:
    with pytest.raises(ValueError):
        RelayConfig(_TARGET, 0, 20)
    with pytest.raises(ValueError):
        RelayConfig(_TARGET, 18443, 0)
    with pytest.raises(ValueError):
        RelayConfig(_TARGET, 18443, 20, max_sessions=0)
    with pytest.raises(ValueError):
        RelayConfig(_TARGET, 18443, 0x100000000)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_port", True),
        ("target_port", 18443.0),
        ("target_port", math.nan),
        ("target_port", math.inf),
        ("interface_index", True),
        ("interface_index", 20.0),
        ("interface_index", math.nan),
        ("interface_index", math.inf),
        ("listen_port", True),
        ("listen_port", 1.0),
        ("listen_port", math.nan),
        ("listen_port", math.inf),
        ("max_sessions", True),
        ("max_sessions", 1.0),
        ("max_sessions", math.nan),
        ("max_sessions", math.inf),
        ("max_bytes_per_direction", True),
        ("max_bytes_per_direction", 1.0),
        ("max_bytes_per_direction", math.nan),
        ("max_bytes_per_direction", math.inf),
    ],
)
def test_config_integer_fields_require_exact_integers(
    field: str, value: object
) -> None:
    values: dict[str, object] = {
        "target_host": _TARGET,
        "target_port": 18443,
        "interface_index": 20,
        "listen_port": 0,
        "max_sessions": 1,
        "max_bytes_per_direction": 1024,
    }
    values[field] = value
    with pytest.raises(ValueError):
        RelayConfig(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [True, 20.0, math.nan, math.inf])
def test_socket_option_index_requires_an_exact_integer(value: object) -> None:
    with pytest.raises(ValueError):
        configure_ipv4_unicast_interface(
            cast(socket.socket, _FakeSocket()), cast(int, value)
        )


def test_invalid_target_is_absent_from_error_and_traceback() -> None:
    invalid_target = "-".join(("invalid", "target", "marker"))
    with pytest.raises(ValueError) as caught:
        RelayConfig(invalid_target, 18443, 20)
    rendered = "".join(
        traceback.format_exception(caught.type, caught.value, caught.tb)
    )
    assert invalid_target not in str(caught.value)
    assert invalid_target not in rendered


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_config_rejects_nonfinite_timeouts(value: float) -> None:
    with pytest.raises(ValueError):
        RelayConfig(_TARGET, 18443, 20, connect_timeout=value)


def test_socket_option_rejects_oversized_interface_index() -> None:
    with pytest.raises(ValueError):
        configure_ipv4_unicast_interface(
            cast(socket.socket, _FakeSocket()), 0x100000000
        )


@pytest.mark.skipif(sys.platform != "win32", reason="requires Windows IP_UNICAST_IF")
@pytest.mark.asyncio
async def test_default_connector_applies_ip_unicast_if_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_socket = _ConnectorSocket()
    connected: list[tuple[object, tuple[str, int]]] = []
    loop = asyncio.get_running_loop()

    async def fake_sock_connect(sock: object, address: tuple[str, int]) -> None:
        connected.append((sock, address))

    fake_reader = asyncio.StreamReader()
    fake_writer = cast(asyncio.StreamWriter, object())

    async def fake_open_connection(
        *, sock: object
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        assert sock is fake_socket
        return fake_reader, fake_writer

    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: fake_socket)
    monkeypatch.setattr(loop, "sock_connect", fake_sock_connect)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    reader, writer, local_host = await open_interface_connection(
        _TARGET, 18443, 20, 0.5
    )

    assert reader is fake_reader
    assert writer is fake_writer
    assert local_host == "phone-local"
    assert connected == [(fake_socket, (_TARGET, 18443))]
    assert fake_socket.options == [
        (socket.IPPROTO_IP, IP_UNICAST_IF, socket.htonl(20))
    ]
    assert fake_socket.blocking is False
    assert not fake_socket.closed


@pytest.mark.skipif(sys.platform != "win32", reason="requires Windows IP_UNICAST_IF")
@pytest.mark.asyncio
async def test_default_connector_closes_raw_socket_when_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_socket = _ConnectorSocket()
    started = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def blocking_sock_connect(_sock: object, _address: tuple[str, int]) -> None:
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: fake_socket)
    monkeypatch.setattr(loop, "sock_connect", blocking_sock_connect)

    task = asyncio.create_task(
        open_interface_connection(_TARGET, 18443, 20, 10.0)
    )
    await asyncio.wait_for(started.wait(), timeout=1.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert fake_socket.closed


@pytest.mark.asyncio
async def test_default_connector_hard_timeout_closes_socket_before_cancelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_socket = _ConnectorSocket()
    started = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    loop = asyncio.get_running_loop()
    retained_before = set(phonepath._RETAINED_SOCKET_TASKS)

    async def resistant_sock_connect(
        _sock: object, _address: tuple[str, int]
    ) -> None:
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            assert fake_socket.closed
            cancelled.set()
            await release.wait()

    monkeypatch.setattr(phonepath.sys, "platform", "win32")
    fake_socket_module = SimpleNamespace(
        AF_INET=socket.AF_INET,
        SOCK_STREAM=socket.SOCK_STREAM,
        IPPROTO_IP=socket.IPPROTO_IP,
        htonl=socket.htonl,
        socket=lambda *_args, **_kwargs: fake_socket,
    )
    monkeypatch.setattr(phonepath, "socket", fake_socket_module)
    monkeypatch.setattr(loop, "sock_connect", resistant_sock_connect)

    began = loop.time()
    with pytest.raises(RelayError, match="outbound connect timeout"):
        await open_interface_connection(_TARGET, 18443, 20, 0.03)
    assert loop.time() - began < 0.2
    assert started.is_set()
    await asyncio.wait_for(cancelled.wait(), timeout=0.1)
    assert fake_socket.closed
    retained = phonepath._RETAINED_SOCKET_TASKS - retained_before
    assert retained
    assert all(not task.done() for task in retained)

    release.set()
    for _ in range(100):
        if not (phonepath._RETAINED_SOCKET_TASKS - retained_before):
            break
        await asyncio.sleep(0)
    assert not (phonepath._RETAINED_SOCKET_TASKS - retained_before)


@pytest.mark.asyncio
async def test_default_connector_sanitizes_underlying_socket_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "-".join(("socket", "failure", "marker"))
    fake_socket = _ConnectorSocket()
    loop = asyncio.get_running_loop()

    async def fail_sock_connect(_sock: object, _address: tuple[str, int]) -> None:
        raise OSError(marker)

    monkeypatch.setattr(phonepath.sys, "platform", "win32")
    fake_socket_module = SimpleNamespace(
        AF_INET=socket.AF_INET,
        SOCK_STREAM=socket.SOCK_STREAM,
        IPPROTO_IP=socket.IPPROTO_IP,
        htonl=socket.htonl,
        socket=lambda *_args, **_kwargs: fake_socket,
    )
    monkeypatch.setattr(phonepath, "socket", fake_socket_module)
    monkeypatch.setattr(loop, "sock_connect", fail_sock_connect)

    with pytest.raises(RelayError) as caught:
        await open_interface_connection(_TARGET, 18443, 20, 0.1)
    rendered = "".join(
        traceback.format_exception(caught.type, caught.value, caught.tb)
    )
    assert marker not in str(caught.value)
    assert marker not in rendered
    assert fake_socket.closed


@pytest.mark.asyncio
async def test_default_connector_sanitizes_socket_creation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "-".join(("socket", "creation", "marker"))

    def fail_socket_creation(*_args: object, **_kwargs: object) -> object:
        raise OSError(marker)

    fake_socket_module = SimpleNamespace(
        AF_INET=socket.AF_INET,
        SOCK_STREAM=socket.SOCK_STREAM,
        IPPROTO_IP=socket.IPPROTO_IP,
        htonl=socket.htonl,
        socket=fail_socket_creation,
    )
    monkeypatch.setattr(phonepath.sys, "platform", "win32")
    monkeypatch.setattr(phonepath, "socket", fake_socket_module)

    with pytest.raises(RelayError) as caught:
        await open_interface_connection(_TARGET, 18443, 20, 0.1)
    rendered = "".join(
        traceback.format_exception(caught.type, caught.value, caught.tb)
    )
    assert marker not in str(caught.value)
    assert marker not in rendered


@pytest.mark.asyncio
async def test_listener_binds_exactly_to_ipv4_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_start_server = asyncio.start_server
    hosts: list[str | None] = []

    async def capture_start_server(
        callback: object, host: str | None, port: int, **kwargs: object
    ) -> asyncio.Server:
        hosts.append(host)
        return await real_start_server(callback, host, port, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(asyncio, "start_server", capture_start_server)
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20),
        address_verifier=lambda _value: True,
        connector=_connector(9, []),
    )
    await relay.start()
    try:
        assert hosts == ["127.0.0.1"]
        assert relay._server is not None
        assert {sock.getsockname()[0] for sock in relay._server.sockets or ()} == {
            "127.0.0.1"
        }
    finally:
        await relay.stop()


@pytest.mark.asyncio
async def test_roundtrip_uses_fixed_target_and_cleans_up() -> None:
    echo, echo_port = await _echo_server()
    seen: list[tuple[str, int, int, float]] = []
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            connect_timeout=0.5,
            idle_timeout=1.0,
            session_timeout=3.0,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda value: value == "phone-local",
        connector=_connector(echo_port, seen),
    )
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
        payload = b"phone-path-roundtrip"
        writer.write(payload)
        await writer.drain()
        assert await reader.readexactly(len(payload)) == payload
        writer.close()
        await writer.wait_closed()
        await relay.wait_idle(timeout=2.0)
        assert seen == [(_TARGET, 18443, 20, 0.5)]
        stats = relay.stats
        assert stats.completed == 1
        assert stats.failed == 0
        assert stats.interface_verified == 1
        assert stats.bytes_client_to_target == len(payload)
        assert stats.bytes_target_to_client == len(payload)
    finally:
        await relay.stop()
        await relay.stop()
        echo.close()
        await echo.wait_closed()
    assert relay.stats.active == 0


@pytest.mark.asyncio
async def test_connector_failure_closes_client_without_fallback() -> None:
    async def fail(
        _host: str, _port: int, _index: int, _timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        raise OSError("synthetic failure")

    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, shutdown_timeout=1.0),
        address_verifier=lambda _value: True,
        connector=fail,
    )
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
        assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
        writer.close()
        await writer.wait_closed()
        await relay.wait_idle(timeout=1.0)
        assert relay.stats.failed == 1
        assert relay.stats.interface_verified == 0
    finally:
        await relay.stop()
    assert relay.stats.active == 0


@pytest.mark.asyncio
async def test_interface_verification_failure_is_fatal() -> None:
    echo, echo_port = await _echo_server()
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, shutdown_timeout=1.0),
        address_verifier=lambda _value: False,
        connector=_connector(echo_port, []),
    )
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
        assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
        writer.close()
        await writer.wait_closed()
        await relay.wait_idle(timeout=1.0)
        assert relay.stats.failed == 1
        assert relay.stats.interface_verified == 0
    finally:
        await relay.stop()
        echo.close()
        await echo.wait_closed()


@pytest.mark.asyncio
async def test_unexpected_verifier_error_is_sanitized_and_counted() -> None:
    echo, echo_port = await _echo_server()
    messages: list[str] = []
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(
        lambda _loop, context: messages.append(str(context.get("message", "")))
    )

    def explode(_value: str) -> bool:
        raise ValueError("synthetic verifier detail")

    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, shutdown_timeout=1.0),
        address_verifier=explode,
        connector=_connector(echo_port, []),
    )
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
        assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
        writer.close()
        await writer.wait_closed()
        await relay.wait_idle(timeout=1.0)
        assert relay.stats.failed == 1
        assert relay.stats.internal_failures == 1
        assert messages == ["phone relay session failed unexpectedly"]
    finally:
        loop.set_exception_handler(previous)
        await relay.stop()
        echo.close()
        await echo.wait_closed()


@pytest.mark.asyncio
async def test_byte_limit_terminates_session() -> None:
    stall, target_port, connected, release = await _stall_server()
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            max_bytes_per_direction=4,
            idle_timeout=1.0,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda value: value == "phone-local",
        connector=_connector(target_port, []),
    )
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
        await asyncio.wait_for(connected.wait(), timeout=1.0)
        writer.write(b"12345678")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
        writer.close()
        await writer.wait_closed()
        await relay.wait_idle(timeout=1.0)
        assert relay.stats.failed == 1
        assert relay.stats.completed == 0
        assert relay.stats.bytes_client_to_target == 4
    finally:
        release.set()
        await relay.stop()
        stall.close()
        await stall.wait_closed()


@pytest.mark.asyncio
async def test_pump_allows_exact_byte_bound_and_rejects_bound_plus_one() -> None:
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, max_bytes_per_direction=4),
        address_verifier=lambda _value: True,
        connector=_connector(9, []),
    )
    exact_reader = asyncio.StreamReader()
    exact_reader.feed_data(b"1234")
    exact_reader.feed_eof()
    exact_writer = _CollectingWriter()
    await relay._pump(
        exact_reader,
        cast(asyncio.StreamWriter, exact_writer),
        asyncio.Event(),
        client_to_target=True,
    )
    assert bytes(exact_writer.data) == b"1234"
    assert exact_writer.eof_written

    overflow_reader = asyncio.StreamReader()
    overflow_reader.feed_data(b"12345")
    overflow_reader.feed_eof()
    overflow_writer = _CollectingWriter()
    with pytest.raises(RelayLimitError, match="per-direction byte limit exceeded"):
        await relay._pump(
            overflow_reader,
            cast(asyncio.StreamWriter, overflow_writer),
            asyncio.Event(),
            client_to_target=True,
        )
    assert bytes(overflow_writer.data) == b"1234"
    assert not overflow_writer.eof_written
    assert relay.stats.bytes_client_to_target == 8


@pytest.mark.asyncio
async def test_idle_timeout_terminates_both_directions() -> None:
    stall, port, connected, release = await _stall_server()
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            idle_timeout=0.05,
            session_timeout=1.0,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(port, []),
    )
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
        await asyncio.wait_for(connected.wait(), timeout=1.0)
        assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
        writer.close()
        await writer.wait_closed()
        await relay.wait_idle(timeout=1.0)
        assert relay.stats.failed == 1
    finally:
        release.set()
        await relay.stop()
        stall.close()
        await stall.wait_closed()


@pytest.mark.asyncio
async def test_shared_idle_allows_sustained_one_way_transfer() -> None:
    async def send_only(
        _reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            for _ in range(10):
                writer.write(b"x")
                await writer.drain()
                await asyncio.sleep(0.03)
        finally:
            writer.close()
            await writer.wait_closed()

    target = await asyncio.start_server(send_only, "127.0.0.1", 0)
    port = int(target.sockets[0].getsockname()[1])
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            idle_timeout=0.08,
            session_timeout=2.0,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(port, []),
    )
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
        assert await asyncio.wait_for(reader.readexactly(10), timeout=1.0) == b"x" * 10
        writer.close()
        await writer.wait_closed()
        await relay.wait_idle(timeout=1.0)
        assert relay.stats.completed == 1
        assert relay.stats.failed == 0
    finally:
        await relay.stop()
        target.close()
        await target.wait_closed()


@pytest.mark.asyncio
async def test_half_close_preserves_reverse_response() -> None:
    received: list[bytes] = []

    async def reply_after_eof(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            received.append(await reader.read())
            writer.write(b"response-after-eof")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    target = await asyncio.start_server(reply_after_eof, "127.0.0.1", 0)
    target_port = int(target.sockets[0].getsockname()[1])
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            idle_timeout=1.0,
            session_timeout=3.0,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(target_port, []),
    )
    await relay.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    try:
        assert writer.can_write_eof()
        writer.write(b"request-before-eof")
        await writer.drain()
        writer.write_eof()
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), timeout=1.0) == b"response-after-eof"
        await relay.wait_idle(timeout=1.0)
        assert received == [b"request-before-eof"]
        assert relay.stats.completed == 1
    finally:
        writer.close()
        await writer.wait_closed()
        await relay.stop()
        target.close()
        await target.wait_closed()


@pytest.mark.asyncio
async def test_reverse_half_close_preserves_late_client_upload() -> None:
    received: list[bytes] = []

    async def half_close_then_read(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            assert writer.can_write_eof()
            writer.write(b"target-prefix")
            await writer.drain()
            writer.write_eof()
            await writer.drain()
            received.append(await reader.read())
        finally:
            writer.close()
            await writer.wait_closed()

    target = await asyncio.start_server(half_close_then_read, "127.0.0.1", 0)
    target_port = int(target.sockets[0].getsockname()[1])
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            idle_timeout=1.0,
            session_timeout=3.0,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(target_port, []),
    )
    await relay.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    try:
        assert await asyncio.wait_for(reader.readexactly(13), timeout=1.0) == b"target-prefix"
        assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
        assert writer.can_write_eof()
        writer.write(b"upload-after-target-eof")
        await writer.drain()
        writer.write_eof()
        await writer.drain()
        await relay.wait_idle(timeout=1.0)
        assert received == [b"upload-after-target-eof"]
        assert relay.stats.completed == 1
    finally:
        writer.close()
        await writer.wait_closed()
        await relay.stop()
        target.close()
        await target.wait_closed()


@pytest.mark.asyncio
async def test_concurrent_session_cap_rejects_extra_client() -> None:
    stall, port, connected, release = await _stall_server()
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            max_sessions=1,
            idle_timeout=5.0,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(port, []),
    )
    await relay.start()
    first_reader, first_writer = await asyncio.open_connection(
        "127.0.0.1", relay.listen_port
    )
    del first_reader
    try:
        await asyncio.wait_for(connected.wait(), timeout=1.0)
        second_reader, second_writer = await asyncio.open_connection(
            "127.0.0.1", relay.listen_port
        )
        assert await asyncio.wait_for(second_reader.read(1), timeout=1.0) == b""
        second_writer.close()
        await second_writer.wait_closed()
        assert relay.stats.accepted == 1
        assert relay.stats.rejected == 1
    finally:
        first_writer.close()
        await first_writer.wait_closed()
        release.set()
        await relay.stop()
        stall.close()
        await stall.wait_closed()
    stats = relay.stats
    assert stats.active == 0
    assert stats.completed == 1
    assert stats.cancelled == 0
    assert stats.accepted == stats.completed + stats.failed + stats.cancelled


@pytest.mark.asyncio
async def test_rejection_flood_does_not_accumulate_relay_cleanup_tasks() -> None:
    stall, port, connected, release = await _stall_server()
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            max_sessions=1,
            idle_timeout=5.0,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(port, []),
    )
    await relay.start()
    first_reader, first_writer = await asyncio.open_connection(
        "127.0.0.1", relay.listen_port
    )
    del first_reader
    try:
        await asyncio.wait_for(connected.wait(), timeout=1.0)
        for _ in range(100):
            if relay.stats.interface_verified == 1:
                break
            await asyncio.sleep(0)
        assert relay.stats.interface_verified == 1
        task_count = len(relay._tasks)
        writer_count = len(relay._writers)

        for _ in range(64):
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", relay.listen_port
            )
            assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
            writer.close()
            await writer.wait_closed()

        await asyncio.sleep(0)
        stats = relay.stats
        assert stats.accepted == 1
        assert stats.rejected == 64
        assert stats.active == 1
        assert len(relay._tasks) == task_count == 1
        assert len(relay._writers) == writer_count == 2
        assert stats.cleanup_failures == 0
    finally:
        first_writer.close()
        await first_writer.wait_closed()
        release.set()
        await relay.wait_idle(timeout=1.0)
        await relay.stop()
        stall.close()
        await stall.wait_closed()
    assert relay.stats.active == 0


@pytest.mark.asyncio
async def test_start_port_collision_leaves_no_relay_state() -> None:
    blocker = await asyncio.start_server(lambda _r, _w: None, "127.0.0.1", 0)
    port = int(blocker.sockets[0].getsockname()[1])
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, listen_port=port),
        address_verifier=lambda _value: True,
        connector=_connector(port, []),
    )
    try:
        with pytest.raises(OSError):
            await relay.start()
        await relay.stop()
        assert relay.stats.active == 0
    finally:
        blocker.close()
        await blocker.wait_closed()


@pytest.mark.asyncio
async def test_concurrent_start_is_serialized_without_listener_leak() -> None:
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20),
        address_verifier=lambda _value: True,
        connector=_connector(9, []),
    )
    await asyncio.gather(relay.start(), relay.start())
    port = relay.listen_port
    assert port > 0
    await relay.stop()
    replacement = await asyncio.start_server(lambda _r, _w: None, "127.0.0.1", port)
    replacement.close()
    await replacement.wait_closed()


@pytest.mark.asyncio
async def test_start_then_stop_race_is_serialized() -> None:
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20),
        address_verifier=lambda _value: True,
        connector=_connector(9, []),
    )
    start_task = asyncio.create_task(relay.start())
    await asyncio.sleep(0)
    stop_task = asyncio.create_task(relay.stop())
    await asyncio.gather(start_task, stop_task)
    assert relay.listen_port == 0
    assert relay.stats.active == 0


@pytest.mark.asyncio
async def test_stop_counts_cancelled_active_session() -> None:
    stall, port, connected, release = await _stall_server()
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, shutdown_timeout=1.0),
        address_verifier=lambda _value: True,
        connector=_connector(port, []),
    )
    await relay.start()
    _reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    try:
        await asyncio.wait_for(connected.wait(), timeout=1.0)
        await relay.stop()
        stats = relay.stats
        assert stats.cancelled == 1
        assert stats.active == 0
        assert stats.accepted == stats.completed + stats.failed + stats.cancelled
    finally:
        writer.close()
        await writer.wait_closed()
        release.set()
        stall.close()
        await stall.wait_closed()


@pytest.mark.asyncio
async def test_connector_deadline_is_hard_and_late_result_stays_owned() -> None:
    target, target_port = await _echo_server()
    connector_started = asyncio.Event()
    release_connector = asyncio.Event()
    cancellation_count = 0

    async def resistant_connector(
        _host: str, _port: int, _index: int, _timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        nonlocal cancellation_count
        connector_started.set()
        try:
            await release_connector.wait()
        except asyncio.CancelledError:
            cancellation_count += 1
            await release_connector.wait()
        reader, target_writer = await asyncio.open_connection(
            "127.0.0.1", target_port
        )
        return reader, target_writer, "phone-local"

    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            connect_timeout=0.03,
            idle_timeout=1.0,
            session_timeout=1.0,
            shutdown_timeout=0.05,
        ),
        address_verifier=lambda _value: True,
        connector=resistant_connector,
    )
    await relay.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    loop = asyncio.get_running_loop()
    began = loop.time()
    try:
        await asyncio.wait_for(connector_started.wait(), timeout=1.0)
        assert await asyncio.wait_for(reader.read(1), timeout=0.3) == b""
        assert loop.time() - began < 0.2
        for _ in range(100):
            if relay.stats.failed == 1:
                break
            await asyncio.sleep(0)
        stats = relay.stats
        assert stats.failed == 1
        assert stats.active == 0
        assert stats.pending_cleanup >= 1
        assert stats.accepted == (
            stats.completed + stats.failed + stats.cancelled + stats.active
        )
        assert cancellation_count == 1
        with pytest.raises(RelayError, match="relay did not become idle"):
            await relay.wait_idle(timeout=0.01)

        release_connector.set()
        await relay.wait_idle(timeout=1.0)
        assert relay.stats.pending_cleanup == 0
    finally:
        release_connector.set()
        writer.close()
        await writer.wait_closed()
        await relay.stop()
        target.close()
        await target.wait_closed()


@pytest.mark.asyncio
async def test_session_deadline_is_hard_and_resistant_bridge_stays_owned() -> None:
    stall, target_port, connected, release_target = await _stall_server()
    pumps_started = asyncio.Event()
    release_pumps = asyncio.Event()
    running_pumps = 0

    class ResistantPumpRelay(InterfaceBoundTcpRelay):
        async def _pump(
            self,
            _reader: asyncio.StreamReader,
            _writer: asyncio.StreamWriter,
            _activity: asyncio.Event,
            *,
            client_to_target: bool,
        ) -> None:
            nonlocal running_pumps
            del client_to_target
            running_pumps += 1
            if running_pumps == 2:
                pumps_started.set()
            try:
                try:
                    await release_pumps.wait()
                except asyncio.CancelledError:
                    await release_pumps.wait()
            finally:
                running_pumps -= 1

    relay = ResistantPumpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            idle_timeout=1.0,
            session_timeout=0.03,
            shutdown_timeout=0.05,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(target_port, []),
    )
    await relay.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    loop = asyncio.get_running_loop()
    began = loop.time()
    try:
        await asyncio.wait_for(connected.wait(), timeout=1.0)
        await asyncio.wait_for(pumps_started.wait(), timeout=1.0)
        assert await asyncio.wait_for(reader.read(1), timeout=0.3) == b""
        assert loop.time() - began < 0.2
        for _ in range(100):
            if relay.stats.failed == 1:
                break
            await asyncio.sleep(0)
        stats = relay.stats
        assert stats.failed == 1
        assert stats.active == 0
        assert stats.pending_cleanup >= 1
        with pytest.raises(RelayError, match="relay did not become idle"):
            await relay.wait_idle(timeout=0.01)

        release_pumps.set()
        await relay.wait_idle(timeout=1.0)
        assert running_pumps == 0
        assert relay.stats.pending_cleanup == 0
    finally:
        release_pumps.set()
        release_target.set()
        writer.close()
        await writer.wait_closed()
        await relay.stop()
        stall.close()
        await stall.wait_closed()


@pytest.mark.asyncio
async def test_writer_is_owned_until_wait_closed_physically_completes() -> None:
    release = asyncio.Event()
    controlled = _ControlledWriter(release)
    writer = cast(asyncio.StreamWriter, controlled)
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, shutdown_timeout=0.03),
        address_verifier=lambda _value: True,
        connector=_connector(9, []),
    )
    relay._register_writer(writer)
    assert relay._begin_writer_close(writer, abort=True, allow_retry=False)
    owned_close_task = relay._writer_close_tasks[writer]
    assert controlled.is_closing()
    assert writer in relay._writers
    assert relay.stats.pending_cleanup == 1
    with pytest.raises(RelayError, match="relay did not become idle"):
        await relay.wait_idle(timeout=0.01)
    with pytest.raises(RelayCleanupError, match="relay cleanup incomplete"):
        await relay.stop()
    assert writer in relay._writers
    assert relay._writer_close_tasks[writer] is owned_close_task
    assert not owned_close_task.done()
    assert relay.stats.pending_cleanup == 1

    release.set()
    await relay.wait_idle(timeout=1.0)
    assert writer not in relay._writers
    assert controlled.wait_calls == 1
    await relay.stop()


@pytest.mark.asyncio
async def test_writer_wait_closed_exception_is_sanitized_and_retryable() -> None:
    release = asyncio.Event()
    marker = "-".join(("writer", "close", "marker"))
    controlled = _ControlledWriter(release, first_error=marker)
    writer = cast(asyncio.StreamWriter, controlled)
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, shutdown_timeout=0.03),
        address_verifier=lambda _value: True,
        connector=_connector(9, []),
    )
    relay._register_writer(writer)
    assert relay._begin_writer_close(writer, abort=True, allow_retry=False)
    for _ in range(100):
        if controlled.wait_calls == 1:
            break
        await asyncio.sleep(0)
    assert controlled.wait_calls == 1
    assert writer in relay._writers
    failed_close_task = relay._writer_close_tasks[writer]
    assert failed_close_task.done()

    with pytest.raises(RelayCleanupError) as caught:
        await relay.stop()
    rendered = "".join(
        traceback.format_exception(caught.type, caught.value, caught.tb)
    )
    assert marker not in str(caught.value)
    assert marker not in rendered
    assert controlled.wait_calls == 2
    assert writer in relay._writers
    retry_close_task = relay._writer_close_tasks[writer]
    assert retry_close_task is not failed_close_task
    assert not retry_close_task.done()

    release.set()
    await relay.wait_idle(timeout=1.0)
    assert writer not in relay._writers
    await relay.stop()


@pytest.mark.asyncio
async def test_listener_wait_closed_error_and_resistance_remain_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = asyncio.Event()
    marker = "-".join(("listener", "close", "marker"))
    listener = _ControlledListener(release, marker)

    async def fake_start_server(*_args: object, **_kwargs: object) -> asyncio.Server:
        return cast(asyncio.Server, listener)

    monkeypatch.setattr(asyncio, "start_server", fake_start_server)
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, shutdown_timeout=0.03),
        address_verifier=lambda _value: True,
        connector=_connector(9, []),
    )
    await relay.start()

    with pytest.raises(RelayCleanupError) as first_error:
        await relay.stop()
    rendered = "".join(
        traceback.format_exception(
            first_error.type, first_error.value, first_error.tb
        )
    )
    assert marker not in str(first_error.value)
    assert marker not in rendered
    assert relay._server is cast(asyncio.Server, listener)
    assert relay.stats.pending_cleanup == 1
    assert listener.close_calls == 1
    assert listener.wait_calls == 1
    failed_listener_task = relay._listener_close_task
    assert failed_listener_task is not None
    assert failed_listener_task.done()

    with pytest.raises(RelayCleanupError, match="relay cleanup incomplete"):
        await relay.stop()
    assert relay._server is cast(asyncio.Server, listener)
    assert relay.stats.pending_cleanup == 1
    assert listener.close_calls == 1
    assert listener.wait_calls == 2
    retry_listener_task = relay._listener_close_task
    assert retry_listener_task is not None
    assert retry_listener_task is not failed_listener_task
    assert not retry_listener_task.done()

    release.set()
    await relay.wait_idle(timeout=1.0)
    assert relay._server is None
    assert relay.stats.pending_cleanup == 0
    await relay.stop()


@pytest.mark.asyncio
async def test_listener_close_exception_is_sanitized_and_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = asyncio.Event()
    marker = "-".join(("listener", "sync", "close", "marker"))
    listener = _CloseFailingListener(release, marker)

    async def fake_start_server(*_args: object, **_kwargs: object) -> asyncio.Server:
        return cast(asyncio.Server, listener)

    monkeypatch.setattr(asyncio, "start_server", fake_start_server)
    relay = InterfaceBoundTcpRelay(
        RelayConfig(_TARGET, 18443, 20, shutdown_timeout=0.03),
        address_verifier=lambda _value: True,
        connector=_connector(9, []),
    )
    await relay.start()

    with pytest.raises(RelayCleanupError) as first_error:
        await relay.stop()
    rendered = "".join(
        traceback.format_exception(
            first_error.type, first_error.value, first_error.tb
        )
    )
    assert marker not in str(first_error.value)
    assert marker not in rendered
    assert relay._server is cast(asyncio.Server, listener)
    assert relay.stats.pending_cleanup == 1
    assert listener.close_calls == 1
    assert listener.wait_calls == 0
    assert relay._listener_close_task is None

    with pytest.raises(RelayCleanupError, match="relay cleanup incomplete"):
        await relay.stop()
    assert relay._server is cast(asyncio.Server, listener)
    assert relay.stats.pending_cleanup == 1
    assert listener.close_calls == 2
    assert listener.wait_calls == 1
    retained_wait = relay._listener_close_task
    assert retained_wait is not None
    assert not retained_wait.done()

    release.set()
    await relay.wait_idle(timeout=1.0)
    assert relay._server is None
    assert relay.stats.pending_cleanup == 0
    await relay.stop()


@pytest.mark.asyncio
async def test_stop_has_hard_deadline_when_connector_resists_cancellation() -> None:
    target, target_port = await _echo_server()
    connector_started = asyncio.Event()
    cancellation_seen = asyncio.Event()
    release_connector = asyncio.Event()

    async def stubborn_connector(
        _host: str, _port: int, _index: int, _timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        connector_started.set()
        try:
            await release_connector.wait()
        except asyncio.CancelledError:
            cancellation_seen.set()
            await release_connector.wait()
        reader, writer = await asyncio.open_connection("127.0.0.1", target_port)
        return reader, writer, "phone-local"

    shutdown_timeout = 0.05
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            shutdown_timeout=shutdown_timeout,
        ),
        address_verifier=lambda _value: True,
        connector=stubborn_connector,
    )
    await relay.start()
    _reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    await asyncio.wait_for(connector_started.wait(), timeout=1.0)
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        with pytest.raises(RelayCleanupError, match="relay cleanup incomplete"):
            await relay.stop()
        elapsed = loop.time() - started
        assert elapsed < shutdown_timeout + 0.2
        assert cancellation_seen.is_set()
        assert relay.stats.active == 0
        assert relay.stats.pending_cleanup >= 1
        assert relay.stats.accepted == (
            relay.stats.completed
            + relay.stats.failed
            + relay.stats.cancelled
            + relay.stats.active
        )

        release_connector.set()
        await relay.wait_idle(timeout=1.0)
        assert relay.stats.cancelled == 1
        assert relay.stats.active == 0
        await relay.stop()
    finally:
        release_connector.set()
        writer.close()
        await writer.wait_closed()
        target.close()
        await target.wait_closed()


@pytest.mark.asyncio
async def test_stop_keeps_cancellation_resistant_pumps_owned() -> None:
    stall, target_port, connected, release_target = await _stall_server()
    pumps_started = asyncio.Event()
    release_pumps = asyncio.Event()
    running_pumps = 0

    class StubbornPumpRelay(InterfaceBoundTcpRelay):
        async def _pump(
            self,
            _reader: asyncio.StreamReader,
            _writer: asyncio.StreamWriter,
            _activity: asyncio.Event,
            *,
            client_to_target: bool,
        ) -> None:
            nonlocal running_pumps
            del client_to_target
            running_pumps += 1
            if running_pumps == 2:
                pumps_started.set()
            try:
                try:
                    await release_pumps.wait()
                except asyncio.CancelledError:
                    await release_pumps.wait()
            finally:
                running_pumps -= 1

    relay = StubbornPumpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            shutdown_timeout=0.05,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(target_port, []),
    )
    await relay.start()
    _reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    try:
        await asyncio.wait_for(connected.wait(), timeout=1.0)
        await asyncio.wait_for(pumps_started.wait(), timeout=1.0)
        with pytest.raises(RelayCleanupError, match="relay cleanup incomplete"):
            await relay.stop()
        assert relay.stats.active == 0
        assert relay.stats.pending_cleanup >= 1
        assert running_pumps == 2

        release_pumps.set()
        await relay.wait_idle(timeout=1.0)
        assert running_pumps == 0
        assert relay.stats.cancelled == 1
        await relay.stop()
    finally:
        release_pumps.set()
        release_target.set()
        writer.close()
        await writer.wait_closed()
        stall.close()
        await stall.wait_closed()


@pytest.mark.asyncio
async def test_cancelling_stop_caller_does_not_interrupt_cleanup() -> None:
    stall, target_port, connected, release_target = await _stall_server()
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            shutdown_timeout=1.0,
        ),
        address_verifier=lambda _value: True,
        connector=_connector(target_port, []),
    )
    await relay.start()
    _reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    try:
        await asyncio.wait_for(connected.wait(), timeout=1.0)
        stop_task = asyncio.create_task(relay.stop())
        for _ in range(100):
            if relay._state == "stopping":
                break
            await asyncio.sleep(0)
        assert relay._state == "stopping"
        owned_stop_task = relay._stop_task
        assert owned_stop_task is not None
        stop_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stop_task
        assert relay._stop_task is owned_stop_task
        assert owned_stop_task.done()
        assert not owned_stop_task.cancelled()

        stats = relay.stats
        assert stats.active == 0
        assert stats.cancelled == 1
        assert stats.cleanup_failures == 0
        assert not relay._writers
        await relay.stop()
    finally:
        release_target.set()
        writer.close()
        await writer.wait_closed()
        stall.close()
        await stall.wait_closed()


@pytest.mark.asyncio
async def test_concurrent_stop_callers_share_entry_deadline() -> None:
    target, target_port = await _echo_server()
    connector_started = asyncio.Event()
    release_connector = asyncio.Event()
    cancellation_count = 0

    async def stubborn_connector(
        _host: str, _port: int, _index: int, _timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        nonlocal cancellation_count
        connector_started.set()
        try:
            await release_connector.wait()
        except asyncio.CancelledError:
            cancellation_count += 1
            await release_connector.wait()
        reader, writer = await asyncio.open_connection("127.0.0.1", target_port)
        return reader, writer, "phone-local"

    shutdown_timeout = 0.08
    relay = InterfaceBoundTcpRelay(
        RelayConfig(
            _TARGET,
            18443,
            20,
            shutdown_timeout=shutdown_timeout,
        ),
        address_verifier=lambda _value: True,
        connector=stubborn_connector,
    )
    await relay.start()
    _reader, writer = await asyncio.open_connection("127.0.0.1", relay.listen_port)
    await asyncio.wait_for(connector_started.wait(), timeout=1.0)
    loop = asyncio.get_running_loop()

    async def measured_stop() -> tuple[float, RelayCleanupError | None]:
        started = loop.time()
        try:
            await relay.stop()
        except RelayCleanupError as exc:
            return loop.time() - started, exc
        return loop.time() - started, None

    try:
        first = asyncio.create_task(measured_stop())
        for _ in range(100):
            if relay._state == "stopping":
                break
            await asyncio.sleep(0)
        assert relay._state == "stopping"
        first_owned_stop = relay._stop_task
        assert first_owned_stop is not None
        await asyncio.sleep(shutdown_timeout / 2)
        second = asyncio.create_task(measured_stop())
        await asyncio.sleep(0)
        assert relay._stop_task is first_owned_stop
        (first_elapsed, first_error), (second_elapsed, second_error) = (
            await asyncio.gather(first, second)
        )
        assert isinstance(first_error, RelayCleanupError)
        assert isinstance(second_error, RelayCleanupError)
        assert first_elapsed < shutdown_timeout + 0.06
        assert second_elapsed < shutdown_timeout + 0.06
        assert first_owned_stop.done()
        assert cancellation_count == 1

        retry = asyncio.create_task(measured_stop())
        for _ in range(100):
            if relay._stop_task is not first_owned_stop:
                break
            await asyncio.sleep(0)
        retry_owned_stop = relay._stop_task
        assert retry_owned_stop is not None
        assert retry_owned_stop is not first_owned_stop
        retry_elapsed, retry_error = await retry
        assert isinstance(retry_error, RelayCleanupError)
        assert retry_elapsed < shutdown_timeout + 0.06
        assert cancellation_count == 1

        release_connector.set()
        await relay.wait_idle(timeout=1.0)
        await relay.stop()
    finally:
        release_connector.set()
        writer.close()
        await writer.wait_closed()
        target.close()
        await target.wait_closed()
