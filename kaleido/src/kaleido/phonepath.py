"""Bounded loopback TCP relay pinned to one Windows IPv4 interface."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import socket
import sys
from collections import deque
from collections.abc import Awaitable, Callable, Collection
from contextlib import suppress
from dataclasses import dataclass
from functools import partial
from typing import Any, Literal
from weakref import WeakSet

IP_UNICAST_IF = 31
_CHUNK_SIZE = 64 * 1024


class RelayError(RuntimeError):
    """Base error for the phone-path relay."""


class RelayLimitError(RelayError):
    """A configured byte or concurrency limit was reached."""


class RelayCleanupError(RelayError):
    """Relay resources could not be closed within the deadline."""


class _DeadlineExpired(RelayError):
    """An internal hard deadline expired."""


def _require_exact_int(
    value: object,
    *,
    minimum: int,
    maximum: int | None,
    message: str,
) -> None:
    if type(value) is not int:
        raise ValueError(message)
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(message)


def _require_positive_timeout(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("relay timeouts must be finite and positive")
    if not math.isfinite(value) or value <= 0:
        raise ValueError("relay timeouts must be finite and positive")


@dataclass(frozen=True, slots=True)
class RelayConfig:
    target_host: str
    target_port: int
    interface_index: int
    listen_port: int = 0
    max_sessions: int = 1
    max_bytes_per_direction: int = 2 * 1024 * 1024
    connect_timeout: float = 8.0
    idle_timeout: float = 20.0
    session_timeout: float = 90.0
    shutdown_timeout: float = 5.0

    def __post_init__(self) -> None:
        if not isinstance(self.target_host, str):
            raise ValueError("target_host must be a numeric IPv4 address") from None
        try:
            address = ipaddress.ip_address(self.target_host)
        except (TypeError, ValueError):
            raise ValueError("target_host must be a numeric IPv4 address") from None
        if address.version != 4:
            raise ValueError("target_host must be a numeric IPv4 address")
        _require_exact_int(
            self.target_port,
            minimum=1,
            maximum=65535,
            message="target_port must be 1..65535",
        )
        _require_exact_int(
            self.interface_index,
            minimum=1,
            maximum=0xFFFFFFFF,
            message="interface_index must fit an unsigned 32-bit value",
        )
        _require_exact_int(
            self.listen_port,
            minimum=0,
            maximum=65535,
            message="listen_port must be 0..65535",
        )
        _require_exact_int(
            self.max_sessions,
            minimum=1,
            maximum=None,
            message="max_sessions must be a positive integer",
        )
        _require_exact_int(
            self.max_bytes_per_direction,
            minimum=1,
            maximum=None,
            message="max_bytes_per_direction must be a positive integer",
        )
        for value in (
            self.connect_timeout,
            self.idle_timeout,
            self.session_timeout,
            self.shutdown_timeout,
        ):
            _require_positive_timeout(value)


@dataclass(frozen=True, slots=True)
class RelayStats:
    accepted: int
    rejected: int
    completed: int
    failed: int
    cancelled: int
    internal_failures: int
    interface_verified: int
    bytes_client_to_target: int
    bytes_target_to_client: int
    cleanup_failures: int
    active: int
    pending_cleanup: int


StreamPair = tuple[asyncio.StreamReader, asyncio.StreamWriter, str]
Connector = Callable[[str, int, int, float], Awaitable[StreamPair]]
AddressVerifier = Callable[[str], bool]
_SessionOutcome = Literal["completed", "failed", "cancelled"]
_SessionResult = tuple[_SessionOutcome, bool]


_RETAINED_SOCKET_TASKS: set[asyncio.Task[Any]] = set()
_RETAINED_ADOPTION_TASKS: set[
    asyncio.Task[tuple[asyncio.StreamReader, asyncio.StreamWriter]]
] = set()


def _socket_task_done(task: asyncio.Task[Any]) -> None:
    _RETAINED_SOCKET_TASKS.discard(task)
    if not task.cancelled():
        task.exception()


def _retain_socket_task(task: asyncio.Task[Any]) -> None:
    if task.done():
        _socket_task_done(task)
        return
    _RETAINED_SOCKET_TASKS.add(task)
    task.add_done_callback(_socket_task_done)


def _adoption_task_done(
    task: asyncio.Task[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
) -> None:
    _RETAINED_SOCKET_TASKS.discard(task)
    _RETAINED_ADOPTION_TASKS.discard(task)
    if task.cancelled() or task.exception() is not None:
        return
    _reader, writer = task.result()
    with suppress(Exception):
        writer.transport.abort()
    try:
        close_task = asyncio.create_task(writer.wait_closed())
    except Exception:
        return
    _retain_socket_task(close_task)


def _retain_adoption_task(
    task: asyncio.Task[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
) -> None:
    if task.done():
        _adoption_task_done(task)
        return
    _RETAINED_SOCKET_TASKS.add(task)
    _RETAINED_ADOPTION_TASKS.add(task)
    task.add_done_callback(_adoption_task_done)


def configure_ipv4_unicast_interface(sock: socket.socket, interface_index: int) -> None:
    """Pin a Windows IPv4 socket to one interface without changing routes."""

    _require_exact_int(
        interface_index,
        minimum=1,
        maximum=0xFFFFFFFF,
        message="interface_index must fit an unsigned 32-bit value",
    )
    sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, socket.htonl(interface_index))


async def open_interface_connection(
    host: str, port: int, interface_index: int, timeout: float
) -> StreamPair:
    """Open one nonblocking Windows TCP socket on the selected interface."""

    if sys.platform != "win32":
        raise RelayError("IP_UNICAST_IF relay requires Windows")
    _require_positive_timeout(timeout)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + float(timeout)
    raw: socket.socket | None = None
    connect_task: asyncio.Task[None] | None = None
    adoption_task: asyncio.Task[
        tuple[asyncio.StreamReader, asyncio.StreamWriter]
    ] | None = None

    def close_raw() -> None:
        nonlocal raw
        if raw is None:
            return
        with suppress(OSError):
            raw.close()
        raw = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw = sock
        configure_ipv4_unicast_interface(sock, interface_index)
        sock.setblocking(False)
        connect_task = asyncio.create_task(loop.sock_connect(sock, (host, port)))
        try:
            connect_done, _pending = await asyncio.wait(
                {connect_task}, timeout=max(0.0, deadline - loop.time())
            )
        except asyncio.CancelledError:
            close_raw()
            if connect_task.done():
                _socket_task_done(connect_task)
            else:
                connect_task.cancel()
                _retain_socket_task(connect_task)
            raise
        if connect_task not in connect_done:
            # Closing the pre-stream socket is synchronous and precedes cancellation.
            close_raw()
            connect_task.cancel()
            _retain_socket_task(connect_task)
            raise RelayError("outbound connect timeout") from None
        if connect_task.cancelled():
            raise RelayError("outbound connect failed") from None
        connect_task.result()
        local_host = str(sock.getsockname()[0])
        adoption_task = asyncio.create_task(asyncio.open_connection(sock=sock))
        try:
            adoption_done, _pending = await asyncio.wait(
                {adoption_task}, timeout=max(0.0, deadline - loop.time())
            )
        except asyncio.CancelledError:
            close_raw()
            if not adoption_task.done():
                adoption_task.cancel()
            _retain_adoption_task(adoption_task)
            raise
        if adoption_task not in adoption_done:
            close_raw()
            adoption_task.cancel()
            _retain_adoption_task(adoption_task)
            raise RelayError("outbound connect timeout") from None
        if adoption_task.cancelled():
            raise RelayError("outbound connect failed") from None
        reader, writer = adoption_task.result()
        raw = None
        return reader, writer, local_host
    except asyncio.CancelledError:
        raise
    except RelayError:
        raise
    except TimeoutError:
        raise RelayError("outbound connect timeout") from None
    except Exception:
        raise RelayError("outbound connect failed") from None
    finally:
        close_raw()


class InterfaceBoundTcpRelay:
    """Relay one fixed destination through a selected Windows interface."""

    def __init__(
        self,
        config: RelayConfig,
        *,
        address_verifier: AddressVerifier,
        connector: Connector | None = None,
    ) -> None:
        self.config = config
        self._address_verifier = address_verifier
        self._connector = connector or open_interface_connection
        self._server: asyncio.Server | None = None
        self._listener_closing = False
        self._listener_close_called = False
        self._listener_close_task: asyncio.Task[None] | None = None
        self._tasks: set[asyncio.Task[_SessionResult]] = set()
        self._connector_tasks: set[asyncio.Task[StreamPair]] = set()
        self._abandoned_connector_tasks: set[asyncio.Task[StreamPair]] = set()
        self._bridge_tasks: set[asyncio.Task[None]] = set()
        self._abandoned_bridge_tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._closing_writers: set[asyncio.StreamWriter] = set()
        self._closed_writers: WeakSet[asyncio.StreamWriter] = WeakSet()
        self._writer_close_tasks: dict[
            asyncio.StreamWriter, asyncio.Task[None]
        ] = {}
        self._rejected_writers: deque[asyncio.StreamWriter] = deque()
        self._rejection_cleanup_task: asyncio.Task[bool] | None = None
        self._cancel_requested: set[asyncio.Task[Any]] = set()
        self._lifecycle_lock = asyncio.Lock()
        self._lock_waiters: set[asyncio.Task[bool]] = set()
        self._abandoned_lock_waiters: set[asyncio.Task[bool]] = set()
        self._stop_task: asyncio.Task[None] | None = None
        self._state = "stopped"
        self._closing = False
        self._idle = asyncio.Event()
        self._idle.set()
        self._accepted = 0
        self._rejected = 0
        self._completed = 0
        self._failed = 0
        self._cancelled = 0
        self._internal_failures = 0
        self._verified = 0
        self._up = 0
        self._down = 0
        self._cleanup_failures = 0

    @property
    def listen_port(self) -> int:
        server = self._server
        if server is None or not server.sockets:
            return self.config.listen_port
        try:
            return int(server.sockets[0].getsockname()[1])
        except OSError:
            return self.config.listen_port

    @property
    def stats(self) -> RelayStats:
        return RelayStats(
            accepted=self._accepted,
            rejected=self._rejected,
            completed=self._completed,
            failed=self._failed,
            cancelled=self._cancelled,
            internal_failures=self._internal_failures,
            interface_verified=self._verified,
            bytes_client_to_target=self._up,
            bytes_target_to_client=self._down,
            cleanup_failures=self._cleanup_failures,
            active=len(self._tasks),
            pending_cleanup=self._pending_cleanup_count(),
        )

    def _pending_cleanup_count(self) -> int:
        cancelling_sessions = sum(
            task in self._cancel_requested for task in self._tasks
        )
        return (
            cancelling_sessions
            + len(self._abandoned_connector_tasks)
            + len(self._abandoned_bridge_tasks)
            + len(self._closing_writers)
            + len(self._rejected_writers)
            + len(self._abandoned_lock_waiters)
            + int(self._listener_closing)
        )

    def _resources_idle(self) -> bool:
        return not (
            self._tasks
            or self._connector_tasks
            or self._bridge_tasks
            or self._writers
            or self._closing_writers
            or self._rejected_writers
            or (
                self._rejection_cleanup_task is not None
                and not self._rejection_cleanup_task.done()
            )
            or self._abandoned_lock_waiters
            or self._listener_closing
        )

    def _resources_clean(self) -> bool:
        return self._resources_idle() and self._server is None

    def _refresh_idle(self) -> None:
        if self._resources_idle():
            self._idle.set()
        else:
            self._idle.clear()

    def _log_internal(self, message: str) -> None:
        asyncio.get_running_loop().call_exception_handler({"message": message})

    def _cancel_once(self, task: asyncio.Task[Any]) -> None:
        if task.done() or task in self._cancel_requested:
            return
        self._cancel_requested.add(task)
        task.cancel()

    @staticmethod
    def _task_succeeded(task: asyncio.Task[Any]) -> bool:
        if task.cancelled():
            return False
        return task.exception() is None

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._state == "running":
                return
            if self._state != "stopped" or not self._resources_clean():
                raise RelayError("relay lifecycle is not startable")
            self._state = "starting"
            try:
                await self._start_unlocked()
            except BaseException:
                self._state = "stopped" if self._resources_clean() else "failed"
                raise
            self._state = "running"

    async def _start_unlocked(self) -> None:
        self._closing = False
        server = await asyncio.start_server(
            self._on_client,
            "127.0.0.1",
            self.config.listen_port,
            backlog=self.config.max_sessions,
            limit=_CHUNK_SIZE,
        )
        self._server = server
        try:
            sockets = server.sockets or ()
            if not sockets or any(
                not ipaddress.ip_address(sock.getsockname()[0]).is_loopback
                for sock in sockets
            ):
                raise RelayError("relay listener is not loopback-only")
        except BaseException:
            self._closing = True
            self._begin_listener_close(allow_retry=True)
            deadline = asyncio.get_running_loop().time() + self.config.shutdown_timeout
            if not await self._await_listener_close(deadline):
                self._cleanup_failures += 1
                raise RelayCleanupError("listener cleanup incomplete") from None
            raise

    def _on_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        cleanup_blocks_admission = bool(
            self._abandoned_connector_tasks
            or self._abandoned_bridge_tasks
            or self._closing_writers
            or self._rejected_writers
        )
        if (
            self._closing
            or cleanup_blocks_admission
            or len(self._tasks) >= self.config.max_sessions
        ):
            self._rejected += 1
            self._reject_writer(writer)
            return
        self._accepted += 1
        self._register_writer(writer)
        task = asyncio.create_task(self._handle_session(reader, writer))
        self._tasks.add(task)
        self._refresh_idle()
        task.add_done_callback(self._session_done)

    def _session_done(self, task: asyncio.Task[_SessionResult]) -> None:
        if task not in self._tasks:
            return
        internal = False
        try:
            outcome, internal = task.result()
        except asyncio.CancelledError:
            outcome = "cancelled"
        except Exception:
            outcome = "failed"
            internal = True
        if outcome == "completed":
            self._completed += 1
        elif outcome == "cancelled":
            self._cancelled += 1
        else:
            self._failed += 1
        if internal:
            self._internal_failures += 1
            self._log_internal("phone relay session failed unexpectedly")
        self._tasks.discard(task)
        self._cancel_requested.discard(task)
        self._refresh_idle()

    def _register_writer(self, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        self._refresh_idle()

    def _reject_writer(self, writer: asyncio.StreamWriter) -> None:
        with suppress(Exception):
            writer.transport.abort()
        self._rejected_writers.append(writer)
        self._ensure_rejection_cleanup(allow_retry=True)
        self._refresh_idle()

    def _ensure_rejection_cleanup(self, *, allow_retry: bool) -> bool:
        task = self._rejection_cleanup_task
        if task is not None and task.done():
            self._rejection_cleanup_done(task)
            task = self._rejection_cleanup_task
        if not self._rejected_writers:
            return True
        if task is None or (allow_retry and task.done()):
            task = asyncio.create_task(self._drain_rejected_writers())
            self._rejection_cleanup_task = task
            task.add_done_callback(self._rejection_cleanup_done)
        self._refresh_idle()
        return True

    async def _drain_rejected_writers(self) -> bool:
        while self._rejected_writers:
            writer = self._rejected_writers[0]
            try:
                await writer.wait_closed()
            except asyncio.CancelledError:
                raise
            except Exception:
                return False
            self._rejected_writers.popleft()
            self._closed_writers.add(writer)
            self._refresh_idle()
        return True

    def _rejection_cleanup_done(self, task: asyncio.Task[bool]) -> None:
        if self._rejection_cleanup_task is not task:
            if not task.cancelled():
                task.exception()
            return
        succeeded = False
        if not task.cancelled() and task.exception() is None:
            succeeded = task.result()
        if succeeded:
            self._rejection_cleanup_task = None
        self._refresh_idle()

    def _begin_writer_close(
        self,
        writer: asyncio.StreamWriter,
        *,
        abort: bool,
        allow_retry: bool,
    ) -> bool:
        if writer in self._closed_writers:
            return True
        self._writers.add(writer)
        self._closing_writers.add(writer)
        close_ok = True
        try:
            if abort:
                writer.transport.abort()
            elif not writer.is_closing():
                writer.close()
        except Exception:
            close_ok = False

        task = self._writer_close_tasks.get(writer)
        if task is not None and task.done():
            self._writer_wait_done(writer, task)
            task = self._writer_close_tasks.get(writer)
        if task is None or (allow_retry and task.done()):
            try:
                task = asyncio.create_task(writer.wait_closed())
            except Exception:
                self._refresh_idle()
                return False
            self._writer_close_tasks[writer] = task
            task.add_done_callback(partial(self._writer_wait_done, writer))
        self._refresh_idle()
        return close_ok

    def _writer_wait_done(
        self, writer: asyncio.StreamWriter, task: asyncio.Task[None]
    ) -> None:
        if self._writer_close_tasks.get(writer) is not task:
            if task.done() and not task.cancelled():
                task.exception()
            return
        if not task.done() or not self._task_succeeded(task):
            self._refresh_idle()
            return
        self._writer_close_tasks.pop(writer, None)
        self._closing_writers.discard(writer)
        self._writers.discard(writer)
        self._closed_writers.add(writer)
        self._refresh_idle()

    async def _await_writer_close(
        self,
        writers: Collection[asyncio.StreamWriter],
        deadline: float,
    ) -> bool:
        tasks = {
            task
            for writer in writers
            if (task := self._writer_close_tasks.get(writer)) is not None
            and not task.done()
        }
        if tasks:
            await asyncio.wait(
                tasks,
                timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
            )
        for writer in writers:
            task = self._writer_close_tasks.get(writer)
            if task is not None and task.done():
                self._writer_wait_done(writer, task)
        return all(writer not in self._writers for writer in writers)

    def _begin_listener_close(self, *, allow_retry: bool) -> bool:
        server = self._server
        if server is None:
            return True
        self._listener_closing = True
        close_ok = True
        if not self._listener_close_called:
            try:
                server.close()
            except Exception:
                close_ok = False
            else:
                self._listener_close_called = True

        task = self._listener_close_task
        if task is not None and task.done():
            self._listener_wait_done(task)
            task = self._listener_close_task
        if self._listener_close_called and (
            task is None or (allow_retry and task.done())
        ):
            try:
                task = asyncio.create_task(server.wait_closed())
            except Exception:
                self._refresh_idle()
                return False
            self._listener_close_task = task
            task.add_done_callback(self._listener_wait_done)
        self._refresh_idle()
        return close_ok

    def _listener_wait_done(self, task: asyncio.Task[None]) -> None:
        if self._listener_close_task is not task:
            if task.done() and not task.cancelled():
                task.exception()
            return
        if not task.done() or not self._task_succeeded(task):
            self._refresh_idle()
            return
        self._listener_close_task = None
        self._listener_closing = False
        self._listener_close_called = False
        self._server = None
        self._refresh_idle()

    async def _await_listener_close(self, deadline: float) -> bool:
        task = self._listener_close_task
        if task is not None and not task.done():
            await asyncio.wait(
                {task},
                timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
            )
        task = self._listener_close_task
        if task is not None and task.done():
            self._listener_wait_done(task)
        return self._server is None

    async def _handle_session(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> _SessionResult:
        target_writer: asyncio.StreamWriter | None = None
        outcome: _SessionOutcome = "failed"
        internal = False
        hard_deadline_expired = False
        try:
            target_reader, target_writer, local_host = await self._connect_target()
            self._register_writer(target_writer)
            if self._closing:
                raise asyncio.CancelledError
            if not self._address_verifier(local_host):
                raise RelayError("outbound interface verification failed")
            self._verified += 1
            await self._run_bridge(
                client_reader,
                client_writer,
                target_reader,
                target_writer,
            )
            outcome = "completed"
        except asyncio.CancelledError:
            outcome = "cancelled"
        except _DeadlineExpired:
            hard_deadline_expired = True
        except (RelayError, TimeoutError, ConnectionError, OSError):
            pass
        except Exception:
            internal = True
        finally:
            writers = [client_writer]
            if target_writer is not None:
                writers.append(target_writer)
            abort = self._closing or outcome != "completed"
            close_started = True
            for writer in writers:
                close_started = (
                    self._begin_writer_close(
                    writer,
                    abort=abort,
                    allow_retry=False,
                )
                    and close_started
                )
            if not self._closing and not hard_deadline_expired:
                try:
                    closed = close_started and await self._await_writer_close(
                        writers,
                        asyncio.get_running_loop().time()
                        + self.config.shutdown_timeout,
                    )
                except asyncio.CancelledError:
                    outcome = "cancelled"
                else:
                    if not closed:
                        self._cleanup_failures += 1
                        outcome = "failed"
        return outcome, internal

    async def _connect_target(self) -> StreamPair:
        task: asyncio.Task[StreamPair] = asyncio.create_task(
            self._invoke_connector()
        )
        self._connector_tasks.add(task)
        self._refresh_idle()
        task.add_done_callback(self._connector_done)
        try:
            done, _pending = await asyncio.wait(
                {task}, timeout=self.config.connect_timeout
            )
        except asyncio.CancelledError:
            self._abandon_connector(task)
            raise
        if task not in done:
            self._abandon_connector(task)
            raise _DeadlineExpired("outbound connect timeout") from None
        self._connector_tasks.discard(task)
        self._cancel_requested.discard(task)
        self._refresh_idle()
        if task.cancelled():
            raise RelayError("outbound connect failed") from None
        return task.result()

    async def _invoke_connector(self) -> StreamPair:
        return await self._connector(
            self.config.target_host,
            self.config.target_port,
            self.config.interface_index,
            self.config.connect_timeout,
        )

    def _abandon_connector(self, task: asyncio.Task[StreamPair]) -> None:
        self._abandoned_connector_tasks.add(task)
        self._cancel_once(task)
        self._refresh_idle()
        if task.done():
            self._connector_done(task)

    def _connector_done(self, task: asyncio.Task[StreamPair]) -> None:
        if task not in self._connector_tasks:
            return
        if task not in self._abandoned_connector_tasks:
            if not task.cancelled():
                task.exception()
            return
        if not task.done():
            return
        if not task.cancelled() and task.exception() is None:
            _reader, writer, _local_host = task.result()
            self._register_writer(writer)
            self._begin_writer_close(writer, abort=True, allow_retry=False)
        self._connector_tasks.discard(task)
        self._abandoned_connector_tasks.discard(task)
        self._cancel_requested.discard(task)
        self._refresh_idle()

    async def _run_bridge(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_reader: asyncio.StreamReader,
        target_writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.create_task(
            self._bridge(
                client_reader,
                client_writer,
                target_reader,
                target_writer,
            )
        )
        self._bridge_tasks.add(task)
        self._refresh_idle()
        task.add_done_callback(self._bridge_done)
        try:
            done, _pending = await asyncio.wait(
                {task}, timeout=self.config.session_timeout
            )
        except asyncio.CancelledError:
            self._abandon_bridge(task)
            raise
        if task not in done:
            self._abandon_bridge(task)
            raise _DeadlineExpired("relay session timeout") from None
        self._bridge_tasks.discard(task)
        self._cancel_requested.discard(task)
        self._refresh_idle()
        if task.cancelled():
            raise RelayError("relay session interrupted") from None
        task.result()

    def _abandon_bridge(self, task: asyncio.Task[None]) -> None:
        self._abandoned_bridge_tasks.add(task)
        self._cancel_once(task)
        self._refresh_idle()
        if task.done():
            self._bridge_done(task)

    def _bridge_done(self, task: asyncio.Task[None]) -> None:
        if task not in self._bridge_tasks or not task.done():
            return
        if task not in self._abandoned_bridge_tasks:
            return
        if not task.cancelled():
            task.exception()
        self._bridge_tasks.discard(task)
        self._abandoned_bridge_tasks.discard(task)
        self._cancel_requested.discard(task)
        self._refresh_idle()

    async def _bridge(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_reader: asyncio.StreamReader,
        target_writer: asyncio.StreamWriter,
    ) -> None:
        activity = asyncio.Event()
        pumps = {
            asyncio.create_task(
                self._pump(
                    client_reader,
                    target_writer,
                    activity,
                    client_to_target=True,
                )
            ),
            asyncio.create_task(
                self._pump(
                    target_reader,
                    client_writer,
                    activity,
                    client_to_target=False,
                )
            ),
        }
        watchdog = asyncio.create_task(self._watch_activity(activity))
        remaining = set(pumps) | {watchdog}
        try:
            while remaining:
                done, _pending = await asyncio.wait(
                    remaining, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    remaining.discard(task)
                    await task
                if all(task.done() for task in pumps):
                    return
        finally:
            for task in remaining:
                task.cancel()
            if self._closing or any(task in pumps for task in remaining):
                for writer in (client_writer, target_writer):
                    with suppress(Exception):
                        writer.transport.abort()
            if remaining:
                await asyncio.gather(*remaining, return_exceptions=True)

    async def _watch_activity(self, activity: asyncio.Event) -> None:
        while True:
            activity.clear()
            waiter = asyncio.create_task(activity.wait())
            try:
                done, _pending = await asyncio.wait(
                    {waiter}, timeout=self.config.idle_timeout
                )
            except asyncio.CancelledError:
                waiter.cancel()
                await asyncio.gather(waiter, return_exceptions=True)
                raise
            if waiter not in done:
                waiter.cancel()
                await asyncio.gather(waiter, return_exceptions=True)
                raise RelayError("relay idle timeout") from None
            waiter.result()

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        activity: asyncio.Event,
        *,
        client_to_target: bool,
    ) -> None:
        transferred = 0
        limit = self.config.max_bytes_per_direction
        while True:
            remaining = limit - transferred
            chunk = await reader.read(min(_CHUNK_SIZE, remaining + 1))
            if not chunk:
                if writer.can_write_eof():
                    try:
                        writer.write_eof()
                        await writer.drain()
                    except (OSError, NotImplementedError):
                        pass
                return
            allowed = chunk[:remaining]
            if allowed:
                writer.write(allowed)
                await writer.drain()
                transferred += len(allowed)
                if client_to_target:
                    self._up += len(allowed)
                else:
                    self._down += len(allowed)
                activity.set()
            if len(chunk) > len(allowed):
                raise RelayLimitError("per-direction byte limit exceeded")

    async def wait_idle(self, *, timeout: float | None = None) -> None:
        duration = timeout if timeout is not None else self.config.session_timeout
        _require_positive_timeout(duration)
        waiter = asyncio.create_task(self._idle.wait())
        try:
            done, _pending = await asyncio.wait({waiter}, timeout=float(duration))
        except asyncio.CancelledError:
            waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
            raise
        if waiter not in done:
            waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
            raise RelayError("relay did not become idle") from None
        waiter.result()

    async def _acquire_lifecycle_until(self, deadline: float) -> bool:
        task = asyncio.create_task(self._lifecycle_lock.acquire())
        self._lock_waiters.add(task)
        task.add_done_callback(self._lock_waiter_done)
        try:
            done, _pending = await asyncio.wait(
                {task},
                timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
            )
        except asyncio.CancelledError:
            self._abandon_lock_waiter(task)
            raise
        if task not in done:
            self._abandon_lock_waiter(task)
            return False
        self._lock_waiters.discard(task)
        self._cancel_requested.discard(task)
        return task.result()

    def _abandon_lock_waiter(self, task: asyncio.Task[bool]) -> None:
        self._abandoned_lock_waiters.add(task)
        self._cancel_once(task)
        self._refresh_idle()
        if task.done():
            self._lock_waiter_done(task)

    def _lock_waiter_done(self, task: asyncio.Task[bool]) -> None:
        if task not in self._lock_waiters or not task.done():
            return
        abandoned = task in self._abandoned_lock_waiters
        acquired = False
        if not task.cancelled() and task.exception() is None:
            acquired = task.result()
        if abandoned and acquired:
            self._lifecycle_lock.release()
        if abandoned:
            self._lock_waiters.discard(task)
            self._abandoned_lock_waiters.discard(task)
            self._cancel_requested.discard(task)
            self._refresh_idle()

    async def stop(self) -> None:
        loop = asyncio.get_running_loop()
        entry_deadline = loop.time() + self.config.shutdown_timeout
        if not await self._acquire_lifecycle_until(entry_deadline):
            self._cleanup_failures += 1
            raise RelayCleanupError("relay cleanup incomplete") from None
        try:
            stop_task = self._stop_task
            if self._resources_clean() and (stop_task is None or stop_task.done()):
                self._state = "stopped"
                return
            if stop_task is None or stop_task.done():
                self._state = "stopping"
                reserve = min(0.002, self.config.shutdown_timeout / 20)
                attempt_deadline = max(loop.time(), entry_deadline - reserve)
                stop_task = asyncio.create_task(
                    self._run_stop_attempt(attempt_deadline)
                )
                self._stop_task = stop_task
                stop_task.add_done_callback(self._stop_task_done)
        finally:
            self._lifecycle_lock.release()
        await self._await_stop_task(stop_task, entry_deadline)

    def _stop_task_done(self, task: asyncio.Task[None]) -> None:
        if not task.cancelled():
            task.exception()

    async def _await_stop_task(
        self, task: asyncio.Task[None], deadline: float
    ) -> None:
        cancellation_requested = False
        while not task.done() and asyncio.get_running_loop().time() < deadline:
            shielded = asyncio.shield(task)
            try:
                done, _pending = await asyncio.wait(
                    {shielded},
                    timeout=max(
                        0.0, deadline - asyncio.get_running_loop().time()
                    ),
                )
            except asyncio.CancelledError:
                cancellation_requested = True
                continue
            finally:
                if not shielded.done():
                    shielded.cancel()
            if shielded in done:
                if not shielded.cancelled():
                    shielded.exception()
                break
            break
        if cancellation_requested:
            raise asyncio.CancelledError from None
        if not task.done():
            raise RelayCleanupError("relay cleanup incomplete") from None
        if task.cancelled():
            raise RelayCleanupError("relay cleanup incomplete") from None
        try:
            task.result()
        except RelayCleanupError:
            raise
        except Exception:
            self._internal_failures += 1
            self._log_internal("phone relay cleanup failed unexpectedly")
            raise RelayCleanupError("relay cleanup incomplete") from None

    async def _run_stop_attempt(self, deadline: float) -> None:
        try:
            await self._stop_unlocked(deadline)
        except asyncio.CancelledError:
            self._state = "failed"
            raise
        except RelayCleanupError:
            self._state = "failed"
            raise
        except Exception:
            self._state = "failed"
            self._internal_failures += 1
            self._log_internal("phone relay cleanup failed unexpectedly")
            raise RelayCleanupError("relay cleanup incomplete") from None
        self._state = "stopped"

    async def _stop_unlocked(self, deadline: float) -> None:
        self._closing = True
        close_calls_ok = self._begin_listener_close(allow_retry=True)
        close_calls_ok = (
            self._ensure_rejection_cleanup(allow_retry=True) and close_calls_ok
        )
        pending_sessions = {task for task in self._tasks if not task.done()}
        if pending_sessions:
            remaining = max(0.0, deadline - asyncio.get_running_loop().time())
            grace = min(0.05, remaining / 2)
            if grace > 0:
                await asyncio.wait(pending_sessions, timeout=grace)
        self._process_done_owned_tasks()

        for writer in tuple(self._writers):
            close_calls_ok = (
                self._begin_writer_close(
                    writer,
                    abort=True,
                    allow_retry=True,
                )
                and close_calls_ok
            )
        for task in tuple(self._tasks):
            self._cancel_once(task)

        while True:
            self._process_done_owned_tasks()
            for writer in tuple(self._writers - self._closing_writers):
                close_calls_ok = (
                    self._begin_writer_close(
                        writer,
                        abort=True,
                        allow_retry=False,
                    )
                    and close_calls_ok
                )
            pending = self._owned_pending_tasks()
            if not pending:
                break
            remaining = max(0.0, deadline - asyncio.get_running_loop().time())
            if remaining <= 0:
                break
            await asyncio.wait(pending, timeout=remaining)

        self._process_done_owned_tasks()
        close_tasks_ok = self._closure_tasks_succeeded()
        if not close_calls_ok or not close_tasks_ok or not self._resources_clean():
            self._cleanup_failures += 1
            raise RelayCleanupError("relay cleanup incomplete") from None

    def _owned_pending_tasks(self) -> set[asyncio.Task[Any]]:
        tasks: set[asyncio.Task[Any]] = set(self._tasks)
        tasks.update(self._connector_tasks)
        tasks.update(self._bridge_tasks)
        tasks.update(self._writer_close_tasks.values())
        if self._rejection_cleanup_task is not None:
            tasks.add(self._rejection_cleanup_task)
        if self._listener_close_task is not None:
            tasks.add(self._listener_close_task)
        return {task for task in tasks if not task.done()}

    def _process_done_owned_tasks(self) -> None:
        for session_task in tuple(self._tasks):
            if session_task.done():
                self._session_done(session_task)
        for connector_task in tuple(self._connector_tasks):
            if connector_task.done():
                self._connector_done(connector_task)
        for bridge_task in tuple(self._bridge_tasks):
            if bridge_task.done():
                self._bridge_done(bridge_task)
        for writer, writer_task in tuple(self._writer_close_tasks.items()):
            if writer_task.done():
                self._writer_wait_done(writer, writer_task)
        rejection_task = self._rejection_cleanup_task
        if rejection_task is not None and rejection_task.done():
            self._rejection_cleanup_done(rejection_task)
        listener_task = self._listener_close_task
        if listener_task is not None and listener_task.done():
            self._listener_wait_done(listener_task)

    def _closure_tasks_succeeded(self) -> bool:
        rejection_task = self._rejection_cleanup_task
        if self._rejected_writers or (
            rejection_task is not None
            and (
                not rejection_task.done()
                or rejection_task.cancelled()
                or rejection_task.exception() is not None
                or not rejection_task.result()
            )
        ):
            return False
        for writer in self._closing_writers:
            task = self._writer_close_tasks.get(writer)
            if task is None or not task.done() or not self._task_succeeded(task):
                return False
        task = self._listener_close_task
        return not self._listener_closing or (
            task is not None and task.done() and self._task_succeeded(task)
        )
