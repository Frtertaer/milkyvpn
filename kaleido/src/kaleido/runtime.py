# kaleido.runtime -- minimal benign VPN research carrier (LAB ONLY).
#
# Outer TLS 1.3 listener ("carrier"). Unauthenticated or non-Kaleido traffic
# gets a configurable static decoy HTTP response (no distinctive protocol
# error). Authenticated sessions expose SOCKS5 CONNECT to a local client and
# a server-side TCP dial with strict allow/deny target policy.
#
# MVP: one SOCKS connection per outer TLS connection (no multiplexing).
# No UDP, no TUN, no system route changes. No production auth defaults.

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import ssl
import struct
import time
from collections import deque
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .protocol import (
    CLIENT_AUTH_FLIGHT_SIZE,
    CLIENT_FIRST_FLIGHT_SIZE,
    FINISHED_SIZE,
    RECORD_HEADER_SIZE,
    SERVER_FLIGHT_SIZE,
    ClientHandshake,
    FramingError,
    HandshakeError,
    MessageType,
    ServerHandshake,
    Session,
    SessionRole,
    finished_value,
    parse_client_first_flight,
    record_ciphertext_length,
)
from .protocol import MAX_PAYLOAD as KAL1_MAX_PAYLOAD

_log = logging.getLogger("kaleido.runtime")

# --- Constants ---------------------------------------------------------------

TLS_HANDSHAKE_TIMEOUT = 10.0
CARRIER_READ_TIMEOUT = 30.0
AUTH_READ_TIMEOUT = 10.0
MAX_FRAME_PAYLOAD = KAL1_MAX_PAYLOAD
INNER_READ_TIMEOUT = 60.0
INNER_IDLE_TIMEOUT = 120.0
PIPE_CHUNK = KAL1_MAX_PAYLOAD
PIPE_BUFFER_LIMIT = 1 << 20  # asyncio stream write-buffer cap -> backpressure
KAL1_REPLAY_CACHE_TTL = 600.0
KAL1_REPLAY_CACHE_MAX = 8192
MAX_OUTER_SESSIONS = 256
MAX_SOCKS_SESSIONS = 128
SOCKS_HANDSHAKE_TIMEOUT = 10.0
EVENT_QUEUE_MAX = 1024
EVENT_HISTORY_MAX = 2048

SOCKS_VERSION = 0x05
SOCKS_METHOD_NO_AUTH = 0x00
SOCKS_METHOD_USERPASS = 0x02
SOCKS_METHOD_NONE_ACCEPTABLE = 0xFF
SOCKS_CMD_CONNECT = 0x01
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAIN = 0x03
SOCKS_ATYP_IPV6 = 0x04
SOCKS_USERPASS_VERSION = 0x01
SOCKS_USERPASS_SUCCESS = 0x00
SOCKS_USERPASS_FAIL = 0x01
SOCKS_REPLY_SUCCESS = 0x00
SOCKS_REPLY_FAILURE = 0x01
SOCKS_REPLY_NOT_ALLOWED = 0x02
SOCKS_REPLY_TTL_EXPIRED = 0x06
SOCKS_REPLY_CMD_UNSUP = 0x07
SOCKS_REPLY_ATYP_UNSUP = 0x08
SOCKS_REPLY_CONN_REFUSED = 0x05
SOCKS_REPLY_HOST_UNREACH = 0x04

_OP_HELLO = 0x00  # LAB-only auth op
_OP_DATA = 0x01  # LAB-only data op
_OP_DIAL = 0x02  # LAB-only dial request
_OP_DIAL_RESULT = 0x03  # LAB-only dial response


# --- Configuration -----------------------------------------------------------


@dataclass
class TargetPolicy:
    """Allow/deny policy for server-side TCP dials.

    Default posture is allowlist-only: loopback/private/link-local/multicast/
    reserved addresses are denied, and any other host must appear in
    ``allow_hosts``. Tests opt-in via ``allow_hosts``/``allow_ports``.
    """

    allow_hosts: set[str] = field(default_factory=set)
    allow_ports: set[int] = field(default_factory=set)
    allow_public: bool = False
    deny_loopback: bool = True
    deny_private: bool = True
    deny_link_local: bool = True
    deny_multicast: bool = True
    deny_reserved: bool = True

    def evaluate(self, host: str, port: int) -> tuple[bool, str]:
        if self.allow_ports and port not in self.allow_ports:
            return False, "port_not_allowed"
        try:
            normalized_ip = str(ipaddress.ip_address(host))
        except ValueError:
            if host in self.allow_hosts:
                return True, "allow_host"
            if self.allow_public:
                return True, "allow_public_domain"
            return False, "domain_not_allowlisted"
        if host in self.allow_hosts or normalized_ip in self.allow_hosts:
            return True, "allow_host"
        blocked = self._blocked_addr_reason(normalized_ip)
        if blocked is not None:
            return False, blocked
        return (True, "allow_public") if self.allow_public else (False, "not_allowlisted")

    def evaluate_resolved(
        self, original_host: str, resolved_ip: str, port: int
    ) -> tuple[bool, str]:
        """Re-check a resolved IP and never inherit a hostname's private-address privilege."""

        if self.allow_ports and port not in self.allow_ports:
            return False, "port_not_allowed"
        normalized_ip = str(ipaddress.ip_address(resolved_ip))
        if normalized_ip in self.allow_hosts:
            return True, "allow_resolved_ip"
        blocked = self._blocked_addr_reason(normalized_ip)
        if blocked is not None:
            return False, blocked
        if original_host in self.allow_hosts or self.allow_public:
            return True, "allow_resolved_public"
        return False, "not_allowlisted"

    def _blocked_addr_reason(self, host: str) -> str | None:
        ip = ipaddress.ip_address(host)
        if self.deny_loopback and (ip.is_loopback or ip.is_unspecified):
            return "loopback"
        if self.deny_link_local and ip.is_link_local:
            return "link_local"
        if self.deny_multicast and ip.is_multicast:
            return "multicast"
        if self.deny_reserved and (ip.is_reserved or ip.is_unspecified):
            return "reserved"
        if self.deny_private and (
            ip.is_private or (ip.version == 6 and getattr(ip, "is_site_local", False))
        ):
            return "private"
        if not ip.is_global:
            return "non_global"
        return None


def _validate_runtime_config(cfg: RuntimeConfig, role: str) -> None:
    if role not in {"client", "server"}:
        raise ValueError(f"unknown carrier role {role!r}")
    if cfg.auth_secret is None or len(cfg.auth_secret) < 32:
        raise ValueError("auth_secret must contain at least 32 bytes")
    if cfg.max_frame_payload <= 0 or cfg.max_frame_payload > KAL1_MAX_PAYLOAD:
        raise ValueError(f"max_frame_payload must be 1..{KAL1_MAX_PAYLOAD}")
    if not isinstance(cfg.max_outer_sessions, int) or isinstance(
        cfg.max_outer_sessions, bool
    ) or cfg.max_outer_sessions <= 0:
        raise ValueError("max_outer_sessions must be a positive integer")
    if not isinstance(cfg.max_socks_sessions, int) or isinstance(
        cfg.max_socks_sessions, bool
    ) or cfg.max_socks_sessions <= 0:
        raise ValueError("max_socks_sessions must be a positive integer")
    if cfg.socks_handshake_timeout <= 0:
        raise ValueError("socks_handshake_timeout must be positive")
    if cfg.protocol_mode == "kal1":
        if role == "server" and cfg.kal1_server_identity_private is None:
            raise ValueError("KAL/1 server requires an Ed25519 private identity")
        if role == "client" and cfg.kal1_server_identity_public is None:
            raise ValueError("KAL/1 client requires a pinned Ed25519 public identity")
    if cfg.socks_auth_required and (
        cfg.socks_auth_username is None
        or not 1 <= len(cfg.socks_auth_username) <= 255
        or cfg.socks_auth_secret is None
        or not 16 <= len(cfg.socks_auth_secret) <= 255
    ):
        raise ValueError("SOCKS authentication requires a username and a 16..255 byte secret")


@dataclass
class RuntimeConfig:
    """Runtime endpoint configuration.

    ``auth_secret`` MUST be supplied explicitly by the caller (test
    fixture). None means authentication always fails for that endpoint.
    """

    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    auth_secret: bytes | None = None
    socks_listen_host: str = "127.0.0.1"
    socks_listen_port: int = 0
    decoy_status: int = 200
    decoy_body: bytes = (
        b"<!doctype html><html><head><title>OK</title></head><body>OK</body></html>\n"
    )
    decoy_server: str = "nginx"
    tls_server_hostname: str | None = None
    protocol_mode: Literal["kal1", "lab"] = "kal1"
    kal1_server_identity_private: Ed25519PrivateKey | None = None
    kal1_server_identity_public: Ed25519PublicKey | None = None
    insecure_outer_tls_for_lab: bool = False
    target_policy: TargetPolicy = field(default_factory=TargetPolicy)
    max_frame_payload: int = MAX_FRAME_PAYLOAD
    inner_read_timeout: float = INNER_READ_TIMEOUT
    inner_idle_timeout: float = INNER_IDLE_TIMEOUT
    carrier_read_timeout: float = CARRIER_READ_TIMEOUT
    handshake_timeout: float = TLS_HANDSHAKE_TIMEOUT
    dial_timeout: float = 10.0
    socks_auth_required: bool = False
    socks_auth_username: bytes | None = None
    socks_auth_secret: bytes | None = None
    max_outer_sessions: int = MAX_OUTER_SESSIONS
    max_socks_sessions: int = MAX_SOCKS_SESSIONS
    socks_handshake_timeout: float = SOCKS_HANDSHAKE_TIMEOUT


# --- Structured events -------------------------------------------------------


_REDACTED_KEYS = ("auth", "secret", "token", "password", "credentials")
_PRIVATE_EVENT_KEYS = (
    "address",
    "destination",
    "domain",
    "host",
    "hostname",
    "ip",
    "peer",
    "peername",
    "port",
    "session",
    "sni",
    "target",
    "url",
)
Event = dict[str, object]


def _redact_dict(d: Event) -> Event:
    out: Event = {}
    for k, v in d.items():
        kl = str(k).lower()
        if any(r in kl for r in _REDACTED_KEYS):
            out[k] = "<redacted>"
        elif isinstance(v, dict):
            out[k] = _redact_dict(v)
        else:
            out[k] = v
    return out


def _remove_private_event_metadata(d: Event) -> Event:
    out: Event = {}
    for key, value in d.items():
        if str(key).lower() in _PRIVATE_EVENT_KEYS:
            continue
        if isinstance(value, dict):
            out[key] = _remove_private_event_metadata(value)
        elif isinstance(value, list):
            out[key] = [
                _remove_private_event_metadata(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            out[key] = value
    return out


class EventBus:
    """Bounded async event sink with privacy-preserving defaults.

    Emission never waits for a slow sink. When the bounded queue is full, new
    events are dropped and their count is coalesced into an ``eventbus.dropped``
    event. History is independently bounded. Destination/peer/session metadata
    is removed before queueing unless ``detailed_metadata`` is explicitly set.
    """

    def __init__(
        self,
        sink: Callable[[Event], Awaitable[None]] | None = None,
        *,
        max_queue: int = EVENT_QUEUE_MAX,
        max_records: int = EVENT_HISTORY_MAX,
        detailed_metadata: bool = False,
    ) -> None:
        if max_queue <= 0:
            raise ValueError("max_queue must be positive")
        if max_records <= 0:
            raise ValueError("max_records must be positive")
        self._sink = sink
        self._detailed_metadata = detailed_metadata
        self._queue: asyncio.Queue[Event | None] = asyncio.Queue(maxsize=max_queue)
        self._task: asyncio.Task[None] | None = None
        self._records: deque[Event] = deque(maxlen=max_records)
        self._dropped_pending = 0
        self.total_dropped = 0

    @property
    def records(self) -> list[Event]:
        """Return a snapshot of bounded, already-sanitized event history."""

        return list(self._records)

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="kaleido-eventbus")

    async def _run(self) -> None:
        while True:
            ev = await self._queue.get()
            await self._flush_drop_summary()
            if ev is None:
                return
            await self._deliver(ev)

    async def _flush_drop_summary(self) -> None:
        dropped = self._dropped_pending
        self._dropped_pending = 0
        if dropped:
            await self._deliver(
                {"type": "eventbus.dropped", "count": dropped, "ts": time.time()}
            )

    async def _deliver(self, event: Event) -> None:
        self._records.append(event)
        _log.debug("kaleido.event %s", json.dumps(event, sort_keys=True))
        if self._sink is None:
            return
        try:
            await self._sink(event)
        except Exception:  # noqa: BLE001
            _log.exception("event sink failed")

    def _prepare(self, event: Event) -> Event:
        prepared = _redact_dict(dict(event))
        if not self._detailed_metadata:
            prepared = _remove_private_event_metadata(prepared)
        if "ts" not in prepared:
            prepared["ts"] = time.time()
        return prepared

    async def emit(self, event: Event) -> None:
        prepared = self._prepare(event)
        try:
            self._queue.put_nowait(prepared)
        except asyncio.QueueFull:
            self._dropped_pending += 1
            self.total_dropped += 1

    async def stop(self) -> None:
        if self._task is not None and not self._task.done():
            try:
                self._queue.put_nowait(None)
            except asyncio.QueueFull:
                # Make shutdown nonblocking too. Evict one queued event and
                # account for it in the same coalesced drop metric.
                with suppress(asyncio.QueueEmpty):
                    self._queue.get_nowait()
                    self._dropped_pending += 1
                    self.total_dropped += 1
                self._queue.put_nowait(None)
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None


# --- Protocol adapter interface ---------------------------------------------


class StreamWrap:
    """Bridge between asyncio StreamReader/Writer and ProtocolAdapter.

    Exposes ``read_exactly``/``sendall`` so adapters need not touch asyncio
    directly.
    """

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: RuntimeConfig
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.cfg = cfg
        self.kal1_role: SessionRole | None = None

    @property
    def peer(self) -> str:
        pi = self.writer.get_extra_info("peername")
        return f"{pi[0]}:{pi[1]}" if pi else "?"

    async def read_exactly(self, n: int, timeout: float | None = None) -> bytes:
        try:
            return await asyncio.wait_for(
                self.reader.readexactly(n),
                timeout=timeout or self.cfg.carrier_read_timeout,
            )
        except asyncio.IncompleteReadError as e:
            raise ConnectionError("eof") from e

    async def sendall(self, data: bytes) -> None:
        transport = self.writer.transport
        transport.set_write_buffer_limits(high=PIPE_BUFFER_LIMIT, low=PIPE_BUFFER_LIMIT // 4)
        self.writer.write(data)
        await self.writer.drain()

    def close(self) -> None:
        with suppress(Exception):
            self.writer.close()


class ProtocolAdapter:
    """Abstract inner-protocol adapter.

    Owns framing + auth over an established TLS stream. The runtime owns the
    SOCKS5 (client) and TCP-dial (server) roles.
    """

    name = "abstract"

    async def authenticate(self, stream: StreamWrap, secret: bytes | None) -> bool:
        raise NotImplementedError

    async def authenticate_client(self, stream: StreamWrap, secret: bytes) -> bool:
        raise NotImplementedError

    async def send_frame(self, stream: StreamWrap, payload: bytes) -> None:
        raise NotImplementedError

    async def recv_frame(self, stream: StreamWrap) -> bytes | None:
        raise NotImplementedError


class LabDefaultAdapter(ProtocolAdapter):
    """LAB-ONLY fallback: length-prefixed frames + HMAC-SHA256 hello.

    Frame: uint32 BE length N, then N payload bytes (payload[0] is op).
    Auth: peer sends HELLO = op(0x00) || nonce(16) || HMAC-SHA256(secret,nonce)(32).
    Server replies a single 0x01 ack byte (read by client via authenticate_client).
    This is NOT a production protocol; replace via set_protocol_adapter().
    """

    name = "lab-default"

    def __init__(self, max_payload: int = MAX_FRAME_PAYLOAD) -> None:
        self.max_payload = max_payload

    async def authenticate(self, stream: StreamWrap, secret: bytes | None) -> bool:
        # Server side: read one frame, verify hello, ack.
        if secret is None:
            return False
        try:
            frame = await self._recv_raw(stream, timeout=stream.cfg.handshake_timeout)
        except (TimeoutError, ConnectionError):
            return False
        if frame is None or len(frame) < 1 + 16 + 32 or frame[0] != _OP_HELLO:
            return False
        nonce = frame[1:17]
        mac = frame[17:49]
        expected = hmac.new(secret, nonce, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            return False
        try:
            await stream.sendall(b"\x01")
        except (ConnectionError, OSError):
            return False
        return True

    async def authenticate_client(self, stream: StreamWrap, secret: bytes) -> bool:
        # Client side: send hello, read ack byte.
        nonce = os.urandom(16)
        mac = hmac.new(secret, nonce, hashlib.sha256).digest()
        frame = bytes([_OP_HELLO]) + nonce + mac
        try:
            await self.send_frame(stream, frame)
            ack = await stream.read_exactly(1, timeout=stream.cfg.handshake_timeout)
        except (TimeoutError, ConnectionError, OSError):
            return False
        return ack == b"\x01"

    async def recv_frame(self, stream: StreamWrap) -> bytes | None:
        try:
            return await self._recv_raw(stream, timeout=stream.cfg.inner_read_timeout)
        except (TimeoutError, ConnectionError):
            return None

    async def send_frame(self, stream: StreamWrap, payload: bytes) -> None:
        if len(payload) > self.max_payload:
            raise ValueError("payload too large")
        await stream.sendall(struct.pack(">I", len(payload)) + payload)

    async def _recv_raw(self, stream: StreamWrap, timeout: float | None) -> bytes | None:
        hdr = await stream.read_exactly(4, timeout=timeout)
        (n,) = struct.unpack(">I", hdr)
        if n == 0 or n > self.max_payload:
            raise ConnectionError("frame length out of range")
        return await stream.read_exactly(n, timeout=timeout)


class KAL1Adapter(ProtocolAdapter):
    """KAL/1 handshake and encrypted record layer over an outer byte stream.

    The server proves its pinned Ed25519 identity, the client proves knowledge
    of a high-entropy PSK before the server emits a KAL-specific flight, and
    both sides exchange direction-separated Finished values before application
    records are accepted.
    """

    name = "kal1"

    def __init__(self) -> None:
        self._first_flights: dict[bytes, float] = {}
        self._replay_lock = asyncio.Lock()

    async def authenticate(self, stream: StreamWrap, secret: bytes | None) -> bool:
        identity = stream.cfg.kal1_server_identity_private
        if secret is None or identity is None:
            return False
        try:
            first_flight = await stream.read_exactly(
                CLIENT_FIRST_FLIGHT_SIZE, timeout=stream.cfg.handshake_timeout
            )
            client_ephemeral = parse_client_first_flight(first_flight, secret)
            claim = await self._claim_first_flight(first_flight)
            if claim is None:
                return False
            try:
                handshake = ServerHandshake(identity_key=identity)
                server_flight = handshake.start(client_ephemeral)
                await stream.sendall(server_flight)
                client_auth = await stream.read_exactly(
                    CLIENT_AUTH_FLIGHT_SIZE, timeout=stream.cfg.handshake_timeout
                )
                session = handshake.create_session(secret, first_flight, server_flight)
                Session.validate_client_psk(
                    secret,
                    handshake.transcript,
                    handshake.salt,
                    client_auth[:32],
                )
                if not hmac.compare_digest(
                    client_auth[32:], finished_value(session.verify, "client")
                ):
                    return False
                stream.kal1_role = session.as_server()
                await stream.sendall(finished_value(session.verify, "server"))
            finally:
                await self._complete_first_flight(claim)
        except (HandshakeError, FramingError, TimeoutError, ConnectionError, OSError, ValueError):
            return False
        return True

    async def _claim_first_flight(self, first_flight: bytes) -> bytes | None:
        """Atomically reject captured first-flight replay before responding."""

        fingerprint = hashlib.sha256(first_flight).digest()
        now = time.monotonic()
        async with self._replay_lock:
            expired = [
                item
                for item, seen_at in self._first_flights.items()
                if now - seen_at >= KAL1_REPLAY_CACHE_TTL
            ]
            for item in expired:
                self._first_flights.pop(item, None)
            if fingerprint in self._first_flights:
                return None
            if len(self._first_flights) >= KAL1_REPLAY_CACHE_MAX:
                oldest = min(self._first_flights, key=self._first_flights.__getitem__)
                self._first_flights.pop(oldest, None)
            self._first_flights[fingerprint] = now
            return fingerprint

    async def _complete_first_flight(self, fingerprint: bytes) -> None:
        async with self._replay_lock:
            self._first_flights[fingerprint] = time.monotonic()

    async def authenticate_client(self, stream: StreamWrap, secret: bytes) -> bool:
        identity = stream.cfg.kal1_server_identity_public
        if identity is None:
            return False
        try:
            handshake = ClientHandshake(server_identity_pub=identity, psk=secret)
            await stream.sendall(handshake.start())
            server_flight = await stream.read_exactly(
                SERVER_FLIGHT_SIZE, timeout=stream.cfg.handshake_timeout
            )
            result = handshake.server_flight(server_flight)
            role = Session.from_client(result).as_client()
            await stream.sendall(
                handshake.client_mac() + finished_value(result.verify, "client")
            )
            server_finished = await stream.read_exactly(
                FINISHED_SIZE, timeout=stream.cfg.handshake_timeout
            )
            if not hmac.compare_digest(server_finished, finished_value(result.verify, "server")):
                return False
            stream.kal1_role = role
            return True
        except (HandshakeError, FramingError, TimeoutError, ConnectionError, OSError, ValueError):
            return False

    async def send_frame(self, stream: StreamWrap, payload: bytes) -> None:
        role = self._role(stream)
        if len(payload) > min(stream.cfg.max_frame_payload, KAL1_MAX_PAYLOAD):
            raise ValueError("payload too large")
        await stream.sendall(role.seal(MessageType.DATA, payload))

    async def recv_frame(self, stream: StreamWrap) -> bytes | None:
        role = self._role(stream)
        try:
            header = await stream.read_exactly(
                RECORD_HEADER_SIZE, timeout=stream.cfg.inner_read_timeout
            )
            ciphertext_len = record_ciphertext_length(header)
            ciphertext = await stream.read_exactly(
                ciphertext_len, timeout=stream.cfg.inner_read_timeout
            )
            record = role.open(header + ciphertext)
        except (TimeoutError, ConnectionError):
            return None
        if record.type == MessageType.CLOSE:
            return None
        if record.type != MessageType.DATA:
            raise ConnectionError("unexpected KAL/1 record type")
        if len(record.payload) > stream.cfg.max_frame_payload:
            raise ConnectionError("frame payload exceeds configured limit")
        return record.payload

    @staticmethod
    def _role(stream: StreamWrap) -> SessionRole:
        if stream.kal1_role is None:
            raise ConnectionError("KAL/1 session is not authenticated")
        return stream.kal1_role


_DEFAULT_ADAPTER: ProtocolAdapter | None = None


def set_protocol_adapter(adapter: ProtocolAdapter | None) -> None:
    """Wire in a future kaleido.protocol adapter (no-op safe otherwise)."""
    global _DEFAULT_ADAPTER
    _DEFAULT_ADAPTER = adapter


def _get_adapter(cfg: RuntimeConfig) -> ProtocolAdapter:
    if _DEFAULT_ADAPTER is not None:
        return _DEFAULT_ADAPTER
    if cfg.protocol_mode == "lab":
        return LabDefaultAdapter(max_payload=cfg.max_frame_payload)
    if cfg.protocol_mode == "kal1":
        return KAL1Adapter()
    raise ValueError(f"unknown protocol mode {cfg.protocol_mode!r}")


# --- Dial request/response (LAB-only adapter scope) --------------------------


def _encode_dial(host: str, port: int) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        b = host.encode("idna")
        return bytes([_OP_DIAL, SOCKS_ATYP_DOMAIN, len(b)]) + b + struct.pack(">H", port)
    if isinstance(ip, ipaddress.IPv4Address):
        return bytes([_OP_DIAL, SOCKS_ATYP_IPV4]) + ip.packed + struct.pack(">H", port)
    return bytes([_OP_DIAL, SOCKS_ATYP_IPV6]) + ip.packed + struct.pack(">H", port)


def _decode_dial(payload: bytes) -> tuple[str | None, int | None]:
    if not payload or payload[0] != _OP_DIAL:
        return None, None
    off = 1
    atyp = payload[off]
    off += 1
    if atyp == SOCKS_ATYP_IPV4:
        if len(payload) < off + 6:
            return None, None
        host = str(ipaddress.IPv4Address(payload[off : off + 4]))
        off += 4
    elif atyp == SOCKS_ATYP_IPV6:
        if len(payload) < off + 18:
            return None, None
        host = str(ipaddress.IPv6Address(payload[off : off + 16]))
        off += 16
    elif atyp == SOCKS_ATYP_DOMAIN:
        ln = payload[off]
        off += 1
        if len(payload) < off + ln + 2:
            return None, None
        host = payload[off : off + ln].decode("idna")
        off += ln
    else:
        return None, None
    port = struct.unpack(">H", payload[off : off + 2])[0]
    return host, port


def _encode_dial_result(ok: bool, socks_code: int) -> bytes:
    return bytes([_OP_DIAL_RESULT, 0x01 if ok else 0x00, socks_code])


def _decode_dial_result(payload: bytes) -> tuple[bool, int]:
    if not payload or payload[0] != _OP_DIAL_RESULT or len(payload) < 3:
        return False, SOCKS_REPLY_FAILURE
    return payload[1] == 0x01, payload[2]


# --- Decoy ------------------------------------------------------------------


def _http_status_text(code: int) -> str:
    return {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }.get(code, "OK")


def _decoy_response(cfg: RuntimeConfig) -> bytes:
    body = cfg.decoy_body
    head = (
        f"HTTP/1.1 {cfg.decoy_status} {_http_status_text(cfg.decoy_status)}\r\n"
        f"Server: {cfg.decoy_server}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return head + body


# --- TLS contexts -----------------------------------------------------------


def make_server_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_client_ssl_context(
    *, cafile: str | None = None, insecure_lab: bool = False
) -> ssl.SSLContext:
    """Build a TLS 1.3 client context.

    Certificate and hostname verification are on by default. Self-signed
    loopback fixtures must opt into ``insecure_lab=True`` and the matching
    runtime configuration flag; this prevents a test convenience from silently
    becoming a deployment default.
    """

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if insecure_lab:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _run_pipe_pair(
    first: asyncio.Task[None], second: asyncio.Task[None]
) -> None:
    """Stop a bidirectional stream promptly when either direction finishes."""

    done, pending = await asyncio.wait(
        {first, second}, return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    await asyncio.gather(*done, return_exceptions=True)


# --- Carrier (outer listener) -----------------------------------------------


class Carrier:
    """A carrier endpoint.

    role="server": outer TLS listener; for each authenticated outer stream it
    reads one dial request, applies target policy, dials, and pipes.
    role="client": exposes a local SOCKS5 listener; for each accepted SOCKS
    connection it dials a FRESH outer TLS connection to the server, runs the
    client-side auth handshake, sends the dial request, and pipes. One SOCKS
    connection per outer TLS connection (MVP, no multiplexing).
    """

    def __init__(
        self,
        cfg: RuntimeConfig,
        ctx: ssl.SSLContext,
        events: EventBus,
        role: str,
        server_endpoint: tuple[str, int, str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.ctx = ctx
        self.events = events
        self.role = role
        self.server_endpoint = server_endpoint  # (host, port, sni) for client role
        self._server: asyncio.Server | None = None
        self._socks_server: asyncio.Server | None = None
        self._sessions: set[asyncio.Task[None]] = set()
        self._adapter = _get_adapter(cfg)
        self._socks_tasks: set[asyncio.Task[None]] = set()

    @property
    def listen_port(self) -> int:
        if self._server is not None and self._server.sockets:
            return int(self._server.sockets[0].getsockname()[1])
        return self.cfg.listen_port

    @property
    def socks_port(self) -> int:
        if self._socks_server is not None and self._socks_server.sockets:
            return int(self._socks_server.sockets[0].getsockname()[1])
        return self.cfg.socks_listen_port

    async def start(self) -> None:
        _validate_runtime_config(self.cfg, self.role)
        if self.role == "server":
            self._server = await asyncio.start_server(
                self._on_outer,
                self.cfg.listen_host,
                self.cfg.listen_port,
                ssl=self.ctx,
                ssl_handshake_timeout=self.cfg.handshake_timeout,
                ssl_shutdown_timeout=min(self.cfg.handshake_timeout, 5.0),
            )
            await self.events.emit(
                {
                    "type": "carrier.listening",
                    "role": self.role,
                    "host": self.cfg.listen_host,
                    "port": self.listen_port,
                }
            )
        else:
            if self.server_endpoint is None:
                raise ValueError("client Carrier requires server_endpoint=(host,port,sni)")
            if (
                self.ctx.verify_mode == ssl.CERT_NONE
                and not self.cfg.insecure_outer_tls_for_lab
            ):
                raise ValueError(
                    "insecure outer TLS requires insecure_outer_tls_for_lab=True"
                )
            self._socks_server = await asyncio.start_server(
                self._on_socks, self.cfg.socks_listen_host, self.cfg.socks_listen_port
            )
            await self.events.emit(
                {
                    "type": "socks.listening",
                    "host": self.cfg.socks_listen_host,
                    "port": self.socks_port,
                }
            )

    async def stop(self) -> None:
        await self.events.emit({"type": "carrier.stopping", "role": self.role})
        socks_server = self._socks_server
        outer_server = self._server
        if self._socks_server is not None:
            self._socks_server.close()
            self._socks_server = None
        if self._server is not None:
            self._server.close()
            self._server = None
        # On Python 3.12 Server.wait_closed() also waits for active
        # connections. Cancel connection handlers first so their finally
        # blocks close the associated StreamWriters; waiting first deadlocks.
        for t in list(self._sessions):
            t.cancel()
        for t in list(self._sessions):
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(t, timeout=2.0)
        self._sessions.clear()
        for task in list(self._socks_tasks):
            task.cancel()
        for task in list(self._socks_tasks):
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(task, timeout=2.0)
        self._socks_tasks.clear()
        if socks_server is not None:
            await socks_server.wait_closed()
        if outer_server is not None:
            await outer_server.wait_closed()

    async def _on_outer(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if len(self._sessions) >= self.cfg.max_outer_sessions:
            await self.events.emit({"type": "session.rejected", "role": "server"})
            await _close_writer(writer)
            return
        task = asyncio.create_task(self._serve_session(reader, writer))
        self._sessions.add(task)
        task.add_done_callback(self._sessions.discard)

    async def _serve_session(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        sid = id(writer)
        stream = StreamWrap(reader, writer, self.cfg)
        await self.events.emit(
            {"type": "carrier.accept", "role": self.role, "peer": stream.peer, "session": sid}
        )
        try:
            try:
                ok = await asyncio.wait_for(
                    self._adapter.authenticate(stream, self.cfg.auth_secret),
                    timeout=self.cfg.handshake_timeout,
                )
            except (TimeoutError, ConnectionError, OSError, asyncio.IncompleteReadError):
                ok = False
            if not ok:
                await self.events.emit({"type": "auth.failed", "role": self.role, "session": sid})
                await self._decoy(writer)
                return
            await self.events.emit({"type": "auth.success", "role": self.role, "session": sid})
            # Server-only: client role has no outer listener.
            await self._run_server(stream, sid)
        except asyncio.CancelledError:
            raise
        except (TimeoutError, ConnectionError, OSError) as e:
            await self.events.emit(
                {
                    "type": "session.error",
                    "role": self.role,
                    "session": sid,
                    "error": type(e).__name__,
                }
            )
        except Exception as e:  # noqa: BLE001
            await self.events.emit(
                {
                    "type": "session.error",
                    "role": self.role,
                    "session": sid,
                    "error": type(e).__name__,
                }
            )
        finally:
            stream.close()
            await self.events.emit({"type": "session.end", "role": self.role, "session": sid})

    async def _decoy(self, writer: asyncio.StreamWriter) -> None:
        try:
            # Drain any pending client bytes so a normal HTTP probe completes.
            with suppress(TimeoutError, OSError):
                await asyncio.wait_for(writer.drain(), timeout=0.5)
            writer.write(_decoy_response(self.cfg))
            await writer.drain()
        except (ConnectionError, OSError):
            pass

    async def _run_server(self, stream: StreamWrap, sid: int) -> None:
        # Receive dial request, apply policy, dial target, pipe bidirectionally.
        req = await self._adapter.recv_frame(stream)
        if req is None:
            return
        host, port = _decode_dial(req)
        if host is None or port is None:
            await self._adapter.send_frame(stream, _encode_dial_result(False, SOCKS_REPLY_FAILURE))
            return
        allowed, reason = self.cfg.target_policy.evaluate(host, port)
        if not allowed:
            await self.events.emit(
                {
                    "type": "dial.denied",
                    "session": sid,
                    "host": host,
                    "port": port,
                    "reason": reason,
                }
            )
            await self._adapter.send_frame(
                stream, _encode_dial_result(False, _socks_code_for_reason(reason))
            )
            return
        try:
            connect_host = host
            try:
                ipaddress.ip_address(host)
            except ValueError:
                loop = asyncio.get_running_loop()
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
                    timeout=self.cfg.dial_timeout,
                )
                checked: list[str] = []
                for _family, _socktype, _proto, _canonname, sockaddr in infos:
                    resolved_ip = str(sockaddr[0])
                    resolved_ok, resolved_reason = self.cfg.target_policy.evaluate_resolved(
                        host, resolved_ip, port
                    )
                    if not resolved_ok:
                        await self.events.emit(
                            {
                                "type": "dial.denied",
                                "session": sid,
                                "host": host,
                                "port": port,
                                "reason": f"resolved_{resolved_reason}",
                            }
                        )
                        await self._adapter.send_frame(
                            stream,
                            _encode_dial_result(
                                False, _socks_code_for_reason(resolved_reason)
                            ),
                        )
                        return
                    if resolved_ip not in checked:
                        checked.append(resolved_ip)
                if not checked:
                    raise OSError("DNS returned no usable addresses") from None
                connect_host = checked[0]
            target_r, target_w = await asyncio.wait_for(
                asyncio.open_connection(connect_host, port), timeout=self.cfg.dial_timeout
            )
        except TimeoutError:
            await self._adapter.send_frame(
                stream, _encode_dial_result(False, SOCKS_REPLY_TTL_EXPIRED)
            )
            return
        except ConnectionRefusedError:
            await self._adapter.send_frame(
                stream, _encode_dial_result(False, SOCKS_REPLY_CONN_REFUSED)
            )
            return
        except OSError as e:
            code = (
                SOCKS_REPLY_HOST_UNREACH if "unreachable" in str(e).lower() else SOCKS_REPLY_FAILURE
            )
            await self._adapter.send_frame(stream, _encode_dial_result(False, code))
            return
        await self.events.emit({"type": "dial.ok", "session": sid, "host": host, "port": port})
        await self._adapter.send_frame(stream, _encode_dial_result(True, 0))
        # Pipe: outer -> target (DOWN from outer) and target -> outer (UP).
        t1 = asyncio.create_task(self._pipe_outer_to_target(stream, target_w))
        t2 = asyncio.create_task(self._pipe_target_to_outer(target_r, stream))
        await _run_pipe_pair(t1, t2)
        with suppress(Exception):
            target_w.close()
            await target_w.wait_closed()

    async def _run_client_session(
        self, sreader: asyncio.StreamReader, swriter: asyncio.StreamWriter, host: str, port: int
    ) -> None:
        # One outer TLS connection per SOCKS connection.
        shost, sport, sni = self.server_endpoint or (
            self.cfg.listen_host,
            self.cfg.listen_port,
            self.cfg.tls_server_hostname or self.cfg.listen_host,
        )
        try:
            outer_r, outer_w = await asyncio.wait_for(
                asyncio.open_connection(shost, sport, ssl=self.ctx, server_hostname=sni or shost),
                timeout=self.cfg.handshake_timeout,
            )
        except (TimeoutError, ConnectionError, OSError) as e:
            await self.events.emit({"type": "outer.dial_failed", "error": type(e).__name__})
            await _socks_reply(swriter, SOCKS_REPLY_FAILURE)
            return
        stream = StreamWrap(outer_r, outer_w, self.cfg)
        sid = id(outer_w)
        await self.events.emit(
            {
                "type": "carrier.connect",
                "role": "client",
                "peer": stream.peer,
                "session": sid,
                "target": f"{host}:{port}",
            }
        )
        try:
            secret = self.cfg.auth_secret
            if secret is None:
                ok = False
            else:
                try:
                    ok = await asyncio.wait_for(
                        self._adapter.authenticate_client(stream, secret),
                        timeout=self.cfg.handshake_timeout,
                    )
                except (TimeoutError, ConnectionError, OSError, asyncio.IncompleteReadError):
                    ok = False
            if not ok:
                await self.events.emit({"type": "auth.failed", "role": "client", "session": sid})
                await _socks_reply(swriter, SOCKS_REPLY_FAILURE)
                return
            await self.events.emit({"type": "auth.success", "role": "client", "session": sid})
            await self._adapter.send_frame(stream, _encode_dial(host, port))
            resp = await self._adapter.recv_frame(stream)
            if resp is None:
                await _socks_reply(swriter, SOCKS_REPLY_FAILURE)
                return
            ok_dial, code = _decode_dial_result(resp)
            if not ok_dial:
                await _socks_reply(swriter, code or SOCKS_REPLY_FAILURE)
                return
            await self.events.emit(
                {
                    "type": "dial.ok",
                    "role": "client",
                    "session": sid,
                    "host": host,
                    "port": port,
                }
            )
            await _socks_reply(swriter, SOCKS_REPLY_SUCCESS)
            t1 = asyncio.create_task(self._pipe_socks_to_outer(sreader, stream))
            t2 = asyncio.create_task(self._pipe_outer_to_socks(stream, swriter))
            await _run_pipe_pair(t1, t2)
        except asyncio.CancelledError:
            raise
        except (TimeoutError, ConnectionError, OSError) as e:
            await self.events.emit(
                {
                    "type": "session.error",
                    "role": "client",
                    "session": sid,
                    "error": type(e).__name__,
                }
            )
        except Exception as e:  # noqa: BLE001
            await self.events.emit(
                {
                    "type": "session.error",
                    "role": "client",
                    "session": sid,
                    "error": type(e).__name__,
                }
            )
        finally:
            stream.close()
            await self.events.emit({"type": "session.end", "role": "client", "session": sid})

    async def _pipe_outer_to_target(
        self, stream: StreamWrap, target_w: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                frame = await asyncio.wait_for(
                    self._adapter.recv_frame(stream), timeout=self.cfg.inner_idle_timeout
                )
                if frame is None:
                    break
                target_w.write(frame)
                await target_w.drain()
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            with suppress(Exception):
                target_w.close()

    async def _pipe_target_to_outer(
        self, target_r: asyncio.StreamReader, stream: StreamWrap
    ) -> None:
        try:
            while True:
                data = await target_r.read(PIPE_CHUNK)
                if not data:
                    break
                await self._adapter.send_frame(stream, data)
        except (ConnectionError, OSError):
            pass
        finally:
            stream.close()

    async def _pipe_socks_to_outer(self, sreader: asyncio.StreamReader, stream: StreamWrap) -> None:
        try:
            while True:
                data = await sreader.read(PIPE_CHUNK)
                if not data:
                    break
                await self._adapter.send_frame(stream, data)
        except (ConnectionError, OSError):
            pass

    async def _pipe_outer_to_socks(self, stream: StreamWrap, swriter: asyncio.StreamWriter) -> None:
        try:
            while True:
                frame = await asyncio.wait_for(
                    self._adapter.recv_frame(stream), timeout=self.cfg.inner_idle_timeout
                )
                if frame is None:
                    break
                swriter.write(frame)
                await swriter.drain()
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            with suppress(Exception):
                swriter.close()

    async def _on_socks(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if len(self._socks_tasks) >= self.cfg.max_socks_sessions:
            await self.events.emit({"type": "session.rejected", "role": "client"})
            await _close_writer(writer)
            return
        task = asyncio.create_task(self._socks_handle(reader, writer))
        self._socks_tasks.add(task)
        task.add_done_callback(self._socks_tasks.discard)

    async def _socks_handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            try:
                host, port = await asyncio.wait_for(
                    self._socks_handshake(reader, writer),
                    timeout=self.cfg.socks_handshake_timeout,
                )
            except TimeoutError:
                await self.events.emit({"type": "socks.handshake_timeout"})
                return
            except SOCKSError:
                return
            await self._run_client_session(reader, writer, host, port)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            with suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _socks_handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[str, int]:
        ver = await reader.readexactly(1)
        if ver != b"\x05":
            raise SOCKSError("bad_version")
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        if self.cfg.socks_auth_required and SOCKS_METHOD_USERPASS not in methods:
            writer.write(bytes([SOCKS_VERSION, SOCKS_METHOD_NONE_ACCEPTABLE]))
            await writer.drain()
            raise SOCKSError("no_acceptable_method")
        if self.cfg.socks_auth_required:
            writer.write(bytes([SOCKS_VERSION, SOCKS_METHOD_USERPASS]))
            await writer.drain()
            await self._socks_userpass(reader, writer)
        else:
            writer.write(bytes([SOCKS_VERSION, SOCKS_METHOD_NO_AUTH]))
            await writer.drain()
        head = await reader.readexactly(4)
        if head[0] != SOCKS_VERSION:
            raise SOCKSError("bad_request_version")
        if head[1] != SOCKS_CMD_CONNECT:
            await _socks_reply(writer, SOCKS_REPLY_CMD_UNSUP)
            raise SOCKSError("unsupported_command")
        atyp = head[3]
        if atyp == SOCKS_ATYP_IPV4:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif atyp == SOCKS_ATYP_IPV6:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        elif atyp == SOCKS_ATYP_DOMAIN:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode("idna")
        else:
            await _socks_reply(writer, SOCKS_REPLY_ATYP_UNSUP)
            raise SOCKSError("bad_atyp")
        port = struct.unpack(">H", await reader.readexactly(2))[0]
        return host, port

    async def _socks_userpass(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if await reader.readexactly(1) != bytes([SOCKS_USERPASS_VERSION]):
            raise SOCKSError("bad_userpass_version")
        ulen = (await reader.readexactly(1))[0]
        user = await reader.readexactly(ulen)
        plen = (await reader.readexactly(1))[0]
        pw = await reader.readexactly(plen)
        ok = (
            self.cfg.socks_auth_username is not None
            and self.cfg.socks_auth_secret is not None
            and hmac.compare_digest(user, self.cfg.socks_auth_username)
            and hmac.compare_digest(pw, self.cfg.socks_auth_secret)
        )
        writer.write(
            bytes([SOCKS_USERPASS_VERSION, SOCKS_USERPASS_SUCCESS if ok else SOCKS_USERPASS_FAIL])
        )
        await writer.drain()
        if not ok:
            raise SOCKSError("auth_failed")


class SOCKSError(Exception):
    pass


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    """Close a rejected connection without letting transport errors escape."""

    with suppress(ConnectionError, OSError, TimeoutError):
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)


def _socks_code_for_reason(reason: str) -> int:
    return SOCKS_REPLY_NOT_ALLOWED if reason else SOCKS_REPLY_FAILURE


async def _socks_reply(
    writer: asyncio.StreamWriter,
    code: int,
    # SOCKS BND.ADDR response value; this does not bind a listening socket.
    bind_host: str = "0.0.0.0",  # noqa: S104  # nosec B104
    bind_port: int = 0,
) -> None:
    try:
        ip = ipaddress.ip_address(bind_host)
    except ValueError:
        ip = ipaddress.IPv4Address(0)
    bnd = ip.packed
    atyp = SOCKS_ATYP_IPV4 if ip.version == 4 else SOCKS_ATYP_IPV6
    writer.write(bytes([SOCKS_VERSION, code, 0x00, atyp]) + bnd + struct.pack(">H", bind_port))
    with suppress(ConnectionError, OSError):
        await writer.drain()


# --- Top-level runtime supervisor ------------------------------------------


class Runtime:
    """Pairs a client Carrier and a server Carrier for lab tests."""

    def __init__(
        self,
        cfg_client: RuntimeConfig,
        cfg_server: RuntimeConfig,
        client_ctx: ssl.SSLContext,
        server_ctx: ssl.SSLContext,
        events: EventBus | None = None,
    ) -> None:
        self.events = events or EventBus()
        self.server = Carrier(cfg_server, server_ctx, self.events, role="server")
        # Wire the client to dial the server's outer TLS endpoint. We resolve
        # the actual port after the server starts; stored lazily via _ep.
        self.client = Carrier(
            cfg_client, client_ctx, self.events, role="client", server_endpoint=None
        )

    async def start(self) -> None:
        await self.events.start()
        try:
            await self.server.start()
            # Now that the server is listening, point the client at it.
            sni = (
                self.client.cfg.tls_server_hostname
                or self.server.cfg.tls_server_hostname
                or self.server.cfg.listen_host
            )
            self.client.server_endpoint = (
                self.server.cfg.listen_host,
                self.server.listen_port,
                sni,
            )
            await self.client.start()
        except BaseException:
            with suppress(Exception):
                await self.client.stop()
            with suppress(Exception):
                await self.server.stop()
            await self.events.stop()
            raise

    async def stop(self) -> None:
        await self.client.stop()
        await self.server.stop()
        await self.events.stop()


# --- Test helper: open an authenticated client outer connection -------------


async def dial_outer(
    cfg: RuntimeConfig,
    ctx: ssl.SSLContext,
    host: str,
    port: int,
    server_hostname: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(
        host, port, ssl=ctx, server_hostname=server_hostname or cfg.tls_server_hostname or host
    )


async def client_authenticate(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: RuntimeConfig, secret: bytes
) -> bool:
    adapter = _get_adapter(cfg)
    return await adapter.authenticate_client(StreamWrap(reader, writer, cfg), secret)


__all__ = [
    "RuntimeConfig",
    "TargetPolicy",
    "EventBus",
    "ProtocolAdapter",
    "LabDefaultAdapter",
    "StreamWrap",
    "Carrier",
    "Runtime",
    "SOCKSError",
    "make_server_ssl_context",
    "make_client_ssl_context",
    "dial_outer",
    "client_authenticate",
    "set_protocol_adapter",
]
