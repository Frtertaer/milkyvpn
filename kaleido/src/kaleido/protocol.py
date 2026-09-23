"""Kaleido inner session protocol.

A versioned, transport-independent inner session protocol layered on top of an
outer protected byte stream. The protocol:

  * Negotiates a single version (``VERSION``) up front; mismatches abort the
    handshake before any cryptographic state is consumed.
  * Performs an X25519 ephemeral Diffie-Hellman exchange.
  * Authenticates the server with an Ed25519 identity signature over the
    transcript so far (magic, version, both ephemeral keys).
  * Authenticates the client with an HMAC over the transcript keyed by a
    pre-shared secret (PSK).
  * Derives direction-specific ChaCha20-Poly1305 record keys and a per-direction
    nonce counter using HKDF-SHA256 bound to the full transcript.
  * Frames records with a 1-byte type, 8-byte big-endian sequence number, and a
    4-byte big-endian payload length (chunked to the nearest padding bucket).
  * Rejects replay and out-of-order delivery by tracking sequence numbers in a
    bounded window per direction.

No custom cryptographic primitives are implemented here; everything comes from
the ``cryptography`` library or the standard library. The public API supports
both deterministic in-memory tests and the asynchronous TLS stream adapter.

The module deliberately avoids touching the outer transport. Byte framing
describes records only; how they are carried over the wire (TLS, KCP, obfs4, a
pipe, an in-memory queue) is out of scope.
"""

from __future__ import annotations

import hmac as stdlib_hmac
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = [
    "VERSION",
    "MAGIC",
    "MAX_PAYLOAD",
    "PAD_BUCKET_SIZE",
    "MAX_PAD_BUCKETS_ABOVE",
    "MIN_PAD_BYTES",
    "CLIENT_FIRST_FLIGHT_SIZE",
    "SERVER_FLIGHT_SIZE",
    "CLIENT_AUTH_FLIGHT_SIZE",
    "FINISHED_SIZE",
    "RECORD_HEADER_SIZE",
    "MAX_RECORD_CIPHERTEXT",
    "MessageType",
    "ProtocolError",
    "HandshakeError",
    "ReplayError",
    "FramingError",
    "SessionState",
    "Record",
    "HandshakeResult",
    "ServerHandshake",
    "ClientHandshake",
    "Session",
    "SessionRole",
    "parse_client_first_flight",
    "finished_value",
    "record_ciphertext_length",
    "next_padding_length",
    "pad",
    "unpad",
    "run_handshake_in_memory",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Inner protocol version. Bumped only for wire-incompatible changes to the
#: handshake or record format.
VERSION: int = 1

#: Magic bytes that prefix every handshake transcript. A PSK pre-authenticator
#: prevents the server from returning a protocol flight to an unauthenticated
#: probe. The bytes remain a cross-protocol/downgrade disambiguator, not a claim
#: of undetectability.
MAGIC: bytes = b"KLDO-in-v"

#: Maximum plaintext payload carried inside a single record frame.
MAX_PAYLOAD: int = 1 << 16  # 64 KiB

#: Records are padded to a multiple of this many bytes.
PAD_BUCKET_SIZE: int = 1 << 8  # 256

#: Padding may step up at most this many buckets above the nearest one. Keeps
#: traffic-shaping overhead bounded while still hiding exact sizes.
MAX_PAD_BUCKETS_ABOVE: int = 1

#: Absolute minimum number of random padding bytes appended to any record, even
#: when the payload already lands on a bucket boundary. Defeats exact-size
#: trimming attacks at the cost of one bucket.
MIN_PAD_BYTES: int = 16

# Fixed handshake flight sizes keep the stream parser bounded. The first flight
# includes a PSK pre-authenticator, so an active probe without the high-entropy
# client secret receives the ordinary decoy behavior instead of a KAL response.
_EPHEMERAL_KEY_SIZE: int = 32
_PREAUTH_SIZE: int = 32
CLIENT_FIRST_FLIGHT_SIZE: int = len(MAGIC) + 1 + _EPHEMERAL_KEY_SIZE + _PREAUTH_SIZE
SERVER_FLIGHT_SIZE: int = 32 + 64  # X25519 public key + Ed25519 signature
FINISHED_SIZE: int = 32
CLIENT_AUTH_FLIGHT_SIZE: int = 32 + FINISHED_SIZE  # PSK MAC + client Finished


class MessageType:
    """Inner-session record types.

    The values are stable on the wire; do not renumber. ``MIGRATE`` is a
    placeholder for a future re-key / re-bind flow; the current stream runtime
    does not accept it as application data.
    """

    OPEN: int = 0x01
    DATA: int = 0x02
    CLOSE: int = 0x03
    PING: int = 0x04
    PONG: int = 0x05
    MIGRATE: int = 0x06

    _ALL: tuple[int, ...] = (OPEN, DATA, CLOSE, PING, PONG, MIGRATE)

    @classmethod
    def is_valid(cls, value: int) -> bool:
        return value in cls._ALL

    @classmethod
    def name(cls, value: int) -> str:
        return {
            cls.OPEN: "OPEN",
            cls.DATA: "DATA",
            cls.CLOSE: "CLOSE",
            cls.PING: "PING",
            cls.PONG: "PONG",
            cls.MIGRATE: "MIGRATE",
        }.get(value, f"UNKNOWN({value:#x})")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ProtocolError(Exception):
    """Base class for all inner-protocol errors."""


class HandshakeError(ProtocolError):
    """Raised when the handshake fails (version, PSK, server identity)."""


class ReplayError(ProtocolError):
    """Raised on replay, out-of-order, or duplicate sequence detection."""


class FramingError(ProtocolError):
    """Raised when an inbound record cannot be parsed or authenticated."""


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------


def next_padding_length(
    payload_len: int,
    rng: Callable[[int], bytes] = os.urandom,
) -> int:
    """Return the number of random padding bytes to append for ``payload_len``.

    The padded record on the wire is ``plaintext || uint16_le(pad_len) ||
    pad_bytes``. We choose ``pad_len`` so the *total* length is a multiple of
    ``PAD_BUCKET_SIZE``, with an optional single extra bucket chosen with
    probability ~1/2 so same-length plaintexts do not always produce
    same-length ciphertexts. A ``MIN_PAD_BYTES`` floor is enforced.
    """
    if payload_len < 0:
        raise ValueError("payload_len must be non-negative")

    bucket = PAD_BUCKET_SIZE
    # The two-byte length prefix is itself part of the padded record, so it has
    # to be counted toward the bucket boundary.
    target = payload_len + 2
    extra = (-target) % bucket
    if extra < MIN_PAD_BYTES:
        extra += bucket

    roll = rng(1)[0]
    if roll >= 128 and MAX_PAD_BUCKETS_ABOVE >= 1:
        extra += bucket
    return extra


def pad(plaintext: bytes, rng: Callable[[int], bytes] = os.urandom) -> bytes:
    """Append one length-delimited random padding block to ``plaintext``.

    The padding is encoded as ``uint16 LE length || random_bytes``; ``unpad``
    strips it. The total ``len(plaintext) + len(padding_field)`` is a multiple
    of ``PAD_BUCKET_SIZE`` (after the floor is enforced), so ciphertexts reveal
    only the bucket, not the exact payload length. The AEAD tag and record
    header are not counted toward bucket alignment; observers see ciphertext
    lengths that vary in 256-byte steps plus the fixed 13-byte header and the
    16-byte Poly1305 tag outside the bucket structure.
    """
    pad_len = next_padding_length(len(plaintext), rng=rng)
    pad_bytes = rng(pad_len)
    # Layout: plaintext || random padding || uint16_le(pad_len). The trailing
    # length lets the receiver strip without knowing the plaintext length.
    return plaintext + pad_bytes + struct.pack("<H", pad_len)


def unpad(padded: bytes) -> bytes:
    """Strip padding that :func:`pad` added. Raises on malformed input."""
    return _strip(padded)


def _strip(padded: bytes) -> bytes:
    if len(padded) < 2:
        raise FramingError("padded payload too short for length prefix")
    pad_len = struct.unpack("<H", padded[-2:])[0]
    body_end = len(padded) - 2 - pad_len
    if body_end < 0:
        raise FramingError("declared padding exceeds payload length")
    return padded[:body_end]


# ---------------------------------------------------------------------------
# Record codec
# ---------------------------------------------------------------------------

# Record frame, AEAD-encrypted, on the wire:
#   1 byte  type
#   8 bytes big-endian sequence number
#   4 bytes big-endian ciphertext length
#   N bytes AEAD ciphertext (plaintext || pad-block, with 16-byte Poly1305 tag)
# All integers are network order. The AEAD "additional data" is exactly the
# 13-byte header so bitflips in type/seq/length are caught by the Poly1305 tag.
_HEADER = struct.Struct(">BQI")
RECORD_HEADER_SIZE = _HEADER.size  # 13
_AEAD_TAG = 16
MAX_RECORD_CIPHERTEXT = (
    MAX_PAYLOAD
    + 2
    + PAD_BUCKET_SIZE * (MAX_PAD_BUCKETS_ABOVE + 2)
    + _AEAD_TAG
)


@dataclass(frozen=True)
class Record:
    """A decrypted inbound record."""

    type: int
    seq: int
    payload: bytes

    @property
    def type_name(self) -> str:
        return MessageType.name(self.type)


def _encode_header(type_: int, seq: int, ct_len: int) -> bytes:
    if not 0 <= seq <= 0xFFFFFFFFFFFFFFFF:
        raise FramingError("sequence number out of range")
    if not 0 <= ct_len <= 0xFFFFFFFF:
        raise FramingError("ciphertext length out of range")
    return _HEADER.pack(type_, seq, ct_len)


def _decode_header(buf: bytes) -> tuple[int, int, int]:
    if len(buf) < RECORD_HEADER_SIZE:
        raise FramingError("record shorter than header")
    type_, seq, ct_len = _HEADER.unpack(buf[:RECORD_HEADER_SIZE])
    return type_, seq, ct_len


def record_ciphertext_length(header: bytes) -> int:
    """Return a bounded ciphertext length from one complete record header."""

    type_, _seq, ct_len = _decode_header(header)
    if not MessageType.is_valid(type_):
        raise FramingError(f"invalid message type {type_:#x}")
    if ct_len < _AEAD_TAG + 2 or ct_len > MAX_RECORD_CIPHERTEXT:
        raise FramingError("record ciphertext length out of range")
    return ct_len


# ---------------------------------------------------------------------------
# Transcript and key derivation
# ---------------------------------------------------------------------------

# Domain-separation labels for HKDF. Each is unique within this module so the
# same transcript cannot produce duplicate keys for distinct roles.
_LABEL_BASE = b"kaleido-in-v1/transcript"
_LABEL_CLIENT_RECORD = b"kaleido-in-v1/record/client"
_LABEL_SERVER_RECORD = b"kaleido-in-v1/record/server"
_LABEL_SERVER_SIG = b"kaleido-in-v1/server-sig-input"
_LABEL_CLIENT_PSK = b"kaleido-in-v1/client-psk-input"
_LABEL_CLIENT_PREAUTH = b"kaleido-in-v1/client-preauth"
_LABEL_HANDSHAKE_VERIFY = b"kaleido-in-v1/handshake-verify"
_LABEL_FINISHED = b"kaleido-in-v1/finished"
_LABEL_NONCE_BASE = b"kaleido-in-v1/nonce-base"

# Length of each derived record key, in bytes. ChaCha20-Poly1305 wants a 32-byte
# key; we derive exactly that.
_KEY_LEN = 32
_NONCE_BASE_LEN = 4


def _transcript(magic: bytes, version: int, client_pub: bytes, server_pub: bytes) -> bytes:
    """Canonical handshake transcript: ``magic || version || client_pub || server_pub``.

    The ephemeral keys are encoded in their X25519 raw 32-byte form and ordered
    client-then-server. The byte-identical transcript is what both sides feed to
    HKDF, the server signs, and the client's PSK-HMAC covers, so any tampering
    is caught by the signature/HMAC and again by the AEAD on the first record.
    """
    return magic + bytes([version]) + client_pub + server_pub


def _hkdf(info: bytes, shared_secret: bytes, transcript: bytes, length: int) -> bytes:
    transcript_hash = hashes.Hash(hashes.SHA256())
    transcript_hash.update(transcript)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=transcript_hash.finalize(),
        info=_LABEL_BASE + b"/" + info + b"/" + transcript,
    )
    return hkdf.derive(shared_secret)


def _derive_record_key(direction: str, transcript: bytes, salt: bytes) -> bytes:
    if direction == "client":
        info = _LABEL_CLIENT_RECORD
    elif direction == "server":
        info = _LABEL_SERVER_RECORD
    else:
        raise ValueError(f"unknown direction {direction!r}")
    return _hkdf(info, salt, transcript, _KEY_LEN)


def _server_sig_input(transcript: bytes, salt: bytes) -> bytes:
    return _hkdf(_LABEL_SERVER_SIG, salt, transcript, 32)


def _client_psk_input(transcript: bytes, salt: bytes) -> bytes:
    return _hkdf(_LABEL_CLIENT_PSK, salt, transcript, 32)


def _handshake_verify(transcript: bytes, salt: bytes) -> bytes:
    return _hkdf(_LABEL_HANDSHAKE_VERIFY, salt, transcript, 32)


def _nonce_base(transcript: bytes, salt: bytes) -> bytes:
    return _hkdf(_LABEL_NONCE_BASE, salt, transcript, _NONCE_BASE_LEN)


def _client_preauth(psk: bytes, client_eph_raw: bytes) -> bytes:
    return _hmac(psk, _LABEL_CLIENT_PREAUTH + MAGIC + bytes([VERSION]) + client_eph_raw)


def parse_client_first_flight(first_flight: bytes, psk: bytes) -> bytes:
    """Authenticate and return the X25519 key from a client first flight.

    The pre-authenticator lets a server reject unauthenticated active probes
    before emitting a KAL-specific server flight. Callers should map every
    failure to the same ordinary cover response.
    """

    if len(first_flight) != CLIENT_FIRST_FLIGHT_SIZE:
        raise HandshakeError("client first flight has invalid length")
    if first_flight[: len(MAGIC)] != MAGIC:
        raise HandshakeError("magic mismatch")
    if first_flight[len(MAGIC)] != VERSION:
        raise HandshakeError("unsupported version")
    key_start = len(MAGIC) + 1
    key_end = key_start + _EPHEMERAL_KEY_SIZE
    client_eph_raw = first_flight[key_start:key_end]
    preauth = first_flight[key_end:]
    if not stdlib_hmac.compare_digest(preauth, _client_preauth(psk, client_eph_raw)):
        raise HandshakeError("client pre-authentication failed")
    return client_eph_raw


def finished_value(verify_key: bytes, role: str) -> bytes:
    """Return a role-separated Finished value for the completed transcript."""

    if role not in {"client", "server"}:
        raise ValueError(f"unknown Finished role {role!r}")
    return _hmac(verify_key, _LABEL_FINISHED + b"/" + role.encode("ascii"))


def _serialize_x25519_pub(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _load_x25519_pub(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


def _hmac(key: bytes, msg: bytes) -> bytes:
    m = crypto_hmac.HMAC(key, hashes.SHA256())
    m.update(msg)
    return m.finalize()


def _compute_salt(shared_secret: bytes, transcript: bytes) -> bytes:
    """Return the per-handshake master secret used as HKDF input key material.

    The historical ``record_salt`` field name is retained for API compatibility;
    this value is the X25519 shared secret. Each expansion in :func:`_hkdf`
    performs conventional extract with SHA-256(transcript) as salt and this
    secret as IKM, then expands under a distinct label.
    """

    del transcript
    return shared_secret


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


@dataclass
class HandshakeResult:
    """Output of a completed handshake on either side."""

    transcript: bytes
    record_salt: bytes
    client_key: bytes
    server_key: bytes
    verify: bytes


@dataclass
class ServerHandshake:
    """Server-side inner-session handshake.

    The outer transport is expected to deliver bytes from the client and accept
    bytes destined to the client. This object only emits/consumes the
    handshake messages; it is single-use.
    """

    identity_key: Ed25519PrivateKey

    _ephemeral: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate, init=False)
    _transcript: bytes | None = None
    _salt: bytes | None = None

    def public_ephemeral_raw(self) -> bytes:
        return _serialize_x25519_pub(self._ephemeral.public_key())

    def start(self, client_eph_raw: bytes) -> bytes:
        """Accept the client's ephemeral public key and return the server flight.

        Returns ``server_ephemeral_pub (32) || Ed25519 signature (64)``.

        Raises :class:`HandshakeError` on malformed input.
        """
        if len(client_eph_raw) != 32:
            raise HandshakeError("client ephemeral must be 32 raw bytes")
        try:
            client_pub = _load_x25519_pub(client_eph_raw)
        except Exception as exc:
            raise HandshakeError("invalid client ephemeral key") from exc

        self._transcript = _transcript(MAGIC, VERSION, client_eph_raw, self.public_ephemeral_raw())
        shared = self._ephemeral.exchange(client_pub)
        self._salt = _compute_salt(shared, self._transcript)
        sig_input = _server_sig_input(self._transcript, self._salt)
        signature = self.identity_key.sign(sig_input)
        return self.public_ephemeral_raw() + signature

    def create_session(
        self,
        psk: bytes,
        client_first_flight: bytes,
        server_flight_reply: bytes,
    ) -> Session:
        """Create the server's session using this handshake's live ephemeral."""

        return Session.from_server(
            identity_key=self.identity_key,
            psk=psk,
            client_first_flight=client_first_flight,
            server_flight_reply=server_flight_reply,
            server_ephemeral_priv=self._ephemeral,
        )

    @property
    def transcript(self) -> bytes:
        if self._transcript is None:
            raise HandshakeError("handshake not started")
        return self._transcript

    @property
    def salt(self) -> bytes:
        if self._salt is None:
            raise HandshakeError("handshake not started")
        return self._salt


@dataclass
class ClientHandshake:
    """Client-side inner-session handshake."""

    server_identity_pub: Ed25519PublicKey
    psk: bytes

    _ephemeral: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate, init=False)
    _transcript: bytes | None = None
    _salt: bytes | None = None
    _server_eph_raw: bytes | None = None

    def public_ephemeral_raw(self) -> bytes:
        return _serialize_x25519_pub(self._ephemeral.public_key())

    def start(self) -> bytes:
        """Return ``magic || version || client_ephemeral || PSK preauth``."""

        ephemeral = self.public_ephemeral_raw()
        return MAGIC + bytes([VERSION]) + ephemeral + _client_preauth(self.psk, ephemeral)

    def server_flight(self, server_msg: bytes) -> HandshakeResult:
        """Consume the server's reply (ephemeral+signature), produce session material.

        Validates the Ed25519 identity signature. Raises :class:`HandshakeError`
        if the server is impersonating a different identity, the signature is
        malformed, or the message is the wrong length.
        """
        if len(server_msg) != 32 + 64:
            raise HandshakeError("server flight must be 32+64 bytes")
        server_eph_raw = server_msg[:32]
        signature = server_msg[32:]
        self._server_eph_raw = server_eph_raw
        transcript = MAGIC + bytes([VERSION]) + self.public_ephemeral_raw() + server_eph_raw
        self._transcript = transcript
        try:
            shared = self._ephemeral.exchange(_load_x25519_pub(server_eph_raw))
        except Exception as exc:
            raise HandshakeError("invalid server ephemeral key") from exc
        self._salt = _compute_salt(shared, transcript)
        sig_input = _server_sig_input(transcript, self._salt)
        try:
            self.server_identity_pub.verify(signature, sig_input)
        except InvalidSignature as exc:
            raise HandshakeError("server identity signature invalid") from exc

        client_key = _derive_record_key("client", transcript, self._salt)
        server_key = _derive_record_key("server", transcript, self._salt)
        verify = _handshake_verify(transcript, self._salt)
        return HandshakeResult(
            transcript=transcript,
            record_salt=self._salt,
            client_key=client_key,
            server_key=server_key,
            verify=verify,
        )

    def client_mac(self) -> bytes:
        """Compute the PSK-HMAC authenticating the client over the transcript."""
        if self._transcript is None or self._salt is None:
            raise HandshakeError("server_flight() must be called first")
        psk_input = _client_psk_input(self._transcript, self._salt)
        mac_key = _hmac(self.psk, psk_input)
        return _hmac(mac_key, self._transcript)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class SessionState:
    """Per-direction record state with strict O(1) ordered replay defense."""

    def __init__(self, key: bytes, transcript: bytes, salt: bytes):
        if len(key) != _KEY_LEN:
            raise FramingError("record key must be 32 bytes")
        self._aead = ChaCha20Poly1305(key)
        self._send_seq = 0
        self._recv_highest = -1
        self._nonce_base = _nonce_base(transcript, salt)

    # -- sending ------------------------------------------------------------

    def seal_record(
        self, type_: int, plaintext: bytes, rng: Callable[[int], bytes] = os.urandom
    ) -> bytes:
        if not MessageType.is_valid(type_):
            raise FramingError(f"invalid message type {type_:#x}")
        if len(plaintext) > MAX_PAYLOAD:
            raise FramingError("payload exceeds MAX_PAYLOAD")
        padded = pad(plaintext, rng=rng)
        seq = self._send_seq
        header = _encode_header(type_, seq, len(padded) + _AEAD_TAG)
        nonce = self._nonce(seq)
        ct = self._aead.encrypt(nonce, padded, header)
        frame = header + ct
        self._send_seq += 1
        return frame

    def _nonce(self, seq: int) -> bytes:
        # IETF ChaCha20-Poly1305 96-bit nonce = transcript-bound 4-byte base
        # || 8-byte big-endian sequence. Sequence uniqueness across a session
        # gives nonce uniqueness within a direction; the base ensures the same
        # sequence number in two different sessions does not produce a reused
        # (key, nonce) pair because the keys themselves are also distinct.
        return self._nonce_base + struct.pack(">Q", seq)

    # -- receiving ---------------------------------------------------------

    def open_record(self, frame: bytes) -> Record:
        if len(frame) < RECORD_HEADER_SIZE + _AEAD_TAG:
            raise FramingError("frame too short")
        type_, seq, ct_len = _decode_header(frame)
        if ct_len > MAX_RECORD_CIPHERTEXT:
            raise FramingError("record ciphertext length out of range")
        ct = frame[RECORD_HEADER_SIZE:]
        if len(ct) != ct_len:
            raise FramingError("declared ciphertext length does not match frame")
        if not MessageType.is_valid(type_):
            raise FramingError(f"invalid message type {type_:#x}")
        self._check_replay(seq)
        header = frame[:RECORD_HEADER_SIZE]
        nonce = self._nonce(seq)
        try:
            padded = self._aead.decrypt(nonce, ct, header)
        except InvalidTag as exc:
            raise FramingError("AEAD authentication failed") from exc
        self._commit_replay(seq)
        plaintext = _strip(padded)
        return Record(type=type_, seq=seq, payload=plaintext)

    def _check_replay(self, seq: int) -> None:
        expected = self._recv_highest + 1
        if seq != expected:
            reason = "replayed" if seq <= self._recv_highest else "out-of-order"
            raise ReplayError(f"sequence {seq} is {reason} (expected={expected})")

    def _commit_replay(self, seq: int) -> None:
        self._recv_highest = seq

    @property
    def send_seq(self) -> int:
        return self._send_seq

    @property
    def recv_highest(self) -> int:
        return self._recv_highest


class Session:
    """A finished inner session with two direction-specific record states.

    Construct via :meth:`from_client` / :meth:`from_server` (or
    :func:`run_handshake_in_memory`); do not instantiate directly. The role
    helpers :meth:`as_client` / :meth:`as_server` expose the right send/recv
    pair so neither side ever installs the wrong key for a direction.
    """

    def __init__(
        self,
        transcript: bytes,
        salt: bytes,
        client_key: bytes,
        server_key: bytes,
        verify: bytes,
    ):
        self.transcript = transcript
        self.salt = salt
        self.verify = verify
        # Client sends with the client key, server receives with the client key,
        # and vice versa. Each direction gets its own SessionState so the nonce
        # counters and replay windows are independent per direction per peer.
        self._client_send = SessionState(client_key, transcript, salt)
        self._server_recv = SessionState(client_key, transcript, salt)
        self._server_send = SessionState(server_key, transcript, salt)
        self._client_recv = SessionState(server_key, transcript, salt)

    # -- factories ---------------------------------------------------------

    @classmethod
    def from_client(cls, result: HandshakeResult) -> Session:
        return cls(
            transcript=result.transcript,
            salt=result.record_salt,
            client_key=result.client_key,
            server_key=result.server_key,
            verify=result.verify,
        )

    @classmethod
    def from_server(
        cls,
        identity_key: Ed25519PrivateKey,
        psk: bytes,
        client_first_flight: bytes,
        server_flight_reply: bytes,
        server_ephemeral_priv: X25519PrivateKey,
    ) -> Session:
        """Reconstruct a server-side :class:`Session` from handshake bytes.

        ``client_first_flight`` is what the client produced via
        :meth:`ClientHandshake.start`; ``server_flight_reply`` is what the
        server returned from :meth:`ServerHandshake.start`;
        ``server_ephemeral_priv`` is the live X25519 private key the server
        used to compute the shared secret. The PSK is validated against any
        accompanying client MAC via :meth:`validate_client_psk` by the caller.
        """
        client_eph_raw = parse_client_first_flight(client_first_flight, psk)
        if len(server_flight_reply) != 32 + 64:
            raise HandshakeError("server flight must be 32+64 bytes")
        server_eph_raw = server_flight_reply[:32]
        signature = server_flight_reply[32:]
        transcript = _transcript(MAGIC, VERSION, client_eph_raw, server_eph_raw)
        shared = server_ephemeral_priv.exchange(_load_x25519_pub(client_eph_raw))
        salt = _compute_salt(shared, transcript)
        sig_input = _server_sig_input(transcript, salt)
        try:
            identity_key.public_key().verify(signature, sig_input)
        except InvalidSignature as exc:
            raise HandshakeError("server signature did not round-trip") from exc
        client_key = _derive_record_key("client", transcript, salt)
        server_key = _derive_record_key("server", transcript, salt)
        verify = _handshake_verify(transcript, salt)
        return cls(
            transcript=transcript,
            salt=salt,
            client_key=client_key,
            server_key=server_key,
            verify=verify,
        )

    # -- role helpers ------------------------------------------------------

    def as_client(self) -> SessionRole:
        return SessionRole(send=self._client_send, recv=self._client_recv, role="client")

    def as_server(self) -> SessionRole:
        return SessionRole(send=self._server_send, recv=self._server_recv, role="server")

    @staticmethod
    def validate_client_psk(psk: bytes, transcript: bytes, salt: bytes, client_mac: bytes) -> None:
        """Verify the client's PSK-HMAC against the expected PSK.

        Raises :class:`HandshakeError` on mismatch. Called by the server after
        it has the transcript and salt, using the same derivation as the client.
        """
        psk_input = _client_psk_input(transcript, salt)
        mac_key = _hmac(psk, psk_input)
        verify = crypto_hmac.HMAC(mac_key, hashes.SHA256())
        verify.update(transcript)
        try:
            verify.verify(client_mac)
        except InvalidSignature as exc:
            raise HandshakeError("client PSK authentication failed") from exc


@dataclass
class SessionRole:
    send: SessionState
    recv: SessionState
    role: str

    def seal(
        self, type_: int, payload: bytes, rng: Callable[[int], bytes] = os.urandom
    ) -> bytes:
        return self.send.seal_record(type_, payload, rng=rng)

    def open(self, frame: bytes) -> Record:
        return self.recv.open_record(frame)


# ---------------------------------------------------------------------------
# Test harness helper
# ---------------------------------------------------------------------------


def run_handshake_in_memory(
    identity_key: Ed25519PrivateKey,
    server_identity_pub: Ed25519PublicKey,
    psk: bytes,
) -> tuple[Session, Session, bytes]:
    """Run a full client/server handshake purely in memory.

    Returns ``(client_session, server_session, client_mac)`` after the server
    has validated the PSK. Raises on any failure. Intended for tests and demos.
    """
    client_hs = ClientHandshake(server_identity_pub=server_identity_pub, psk=psk)
    server_hs = ServerHandshake(identity_key=identity_key)

    client_flight = client_hs.start()
    client_eph_raw = parse_client_first_flight(client_flight, psk)
    server_flight = server_hs.start(client_eph_raw)

    result = client_hs.server_flight(server_flight)
    client_mac = client_hs.client_mac()
    Session.validate_client_psk(psk, result.transcript, result.record_salt, client_mac)

    client_session = Session.from_client(result)
    server_session = server_hs.create_session(psk, client_flight, server_flight)
    return client_session, server_session, client_mac
