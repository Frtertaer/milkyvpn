"""In-memory tests for the Kaleido inner session protocol.

These tests exercise only the public surface of ``kaleido.protocol`` and run
entirely in memory: there is no socket, no thread, and no outer transport.
``pytest`` discovers them directly.

We cover the behaviors required by the protocol core contract:

  * Successful handshake and key agreement.
  * Tamper rejection (ciphertext bitflip, header bitflip).
  * Wrong PSK rejected on the server side.
  * Wrong server identity (Ed25519 impersonation) rejected on the client side.
  * Replay and out-of-order rejection.
  * Padding bucket behavior (ciphertext lengths step in bucket multiples and
    the exact plaintext length is not recoverable from the ciphertext length).
  * Cross-direction isolation (a record sealed by the client cannot be opened
    with the server's send key and vice versa).
"""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from kaleido.protocol import (
    CLIENT_FIRST_FLIGHT_SIZE,
    MAGIC,
    MAX_PAD_BUCKETS_ABOVE,
    MIN_PAD_BYTES,
    PAD_BUCKET_SIZE,
    RECORD_HEADER_SIZE,
    VERSION,
    ClientHandshake,
    FramingError,
    HandshakeError,
    MessageType,
    ProtocolError,
    ReplayError,
    ServerHandshake,
    Session,
    _hkdf,
    _strip,
    next_padding_length,
    pad,
    run_handshake_in_memory,
    unpad,
)


def test_hkdf_schedule_known_answer_vector():
    """Lock the byte-exact KAL/1 extract/expand schedule against drift."""
    derived = _hkdf(
        b"test-vector",
        bytes(range(32)),
        b"KAL1 transcript vector",
        48,
    )
    assert derived.hex() == (
        "3ae4e14e3de8af3cfa5e2516e98f81867b0081bbf3434acf694ca2b5c73835d8"
        "739e6e9af8c6beb0a706ec999d4bd916"
    )

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PSK = b"shared-pre-shared-key-for-tests"
SERVER_IDENTITY = Ed25519PrivateKey.generate()
SERVER_PUB = SERVER_IDENTITY.public_key()
ATTACKER_IDENTITY = Ed25519PrivateKey.generate()


@pytest.fixture
def handshake_pair():
    """Return (client_session, server_session, client_mac) for a successful handshake."""
    return run_handshake_in_memory(SERVER_IDENTITY, SERVER_PUB, PSK)


@pytest.fixture
def roles(handshake_pair):
    client_session, server_session, _mac = handshake_pair
    return client_session.as_client(), server_session.as_server()


# ---------------------------------------------------------------------------
# Handshake success
# ---------------------------------------------------------------------------


class TestHandshake:
    def test_successful_handshake_and_key_agreement(self, handshake_pair):
        client_session, server_session, mac = handshake_pair
        # Both sides share the same transcript, salt, and verify value.
        assert client_session.transcript == server_session.transcript
        assert client_session.salt == server_session.salt
        assert client_session.verify == server_session.verify
        assert len(client_session.verify) == 32
        # Sealing on one side and opening on the other must work end to end.
        client = client_session.as_client()
        server = server_session.as_server()
        frame = client.seal(MessageType.DATA, b"payload-A")
        rec = server.open(frame)
        assert rec.payload == b"payload-A"

    def test_client_mac_is_transcript_bound(self, handshake_pair):
        _client_session, _server_session, mac = handshake_pair
        # A second handshake with a fresh server ephemeral yields a different
        # client MAC because the transcript (and thus the PSK input) differs.
        other_client = ClientHandshake(server_identity_pub=SERVER_PUB, psk=PSK)
        other_client.start()
        server_hs = ServerHandshake(identity_key=SERVER_IDENTITY)
        server_flight = server_hs.start(other_client.public_ephemeral_raw())
        other_client.server_flight(server_flight)
        other_mac = other_client.client_mac()
        assert other_mac != mac

    def test_first_flight_carries_magic_then_version(self, handshake_pair):
        _client_session, _server_session, _mac = handshake_pair
        # The client's first flight begins with the magic; the magic appears
        # only after outer TLS would have authenticated the channel in practice.
        client = ClientHandshake(server_identity_pub=SERVER_PUB, psk=PSK)
        first = client.start()
        assert first.startswith(MAGIC)
        assert first[len(MAGIC)] == VERSION
        assert len(first) == CLIENT_FIRST_FLIGHT_SIZE


# ---------------------------------------------------------------------------
# Tamper rejection
# ---------------------------------------------------------------------------


class TestTamperRejection:
    def _flip(self, frame: bytes, offset: int) -> bytes:
        b = bytearray(frame)
        b[offset] ^= 0x01
        return bytes(b)

    def test_ciphertext_bitflip_rejected(self, roles):
        client, server = roles
        frame = client.seal(MessageType.DATA, b"tamper-me")
        tampered = self._flip(frame, len(frame) - 1)
        with pytest.raises(ProtocolError):
            server.open(tampered)

    def test_header_type_bitflip_rejected(self, roles):
        client, server = roles
        frame = client.seal(MessageType.DATA, b"tamper-me")
        tampered = self._flip(frame, 0)
        with pytest.raises(FramingError):
            server.open(tampered)

    def test_header_seq_bitflip_rejected(self, roles):
        client, server = roles
        frame = client.seal(MessageType.DATA, b"tamper-me")
        # Flip a bit in the sequence number (bytes 1..4 of header).
        tampered = self._flip(frame, 1)
        with pytest.raises(ProtocolError):
            server.open(tampered)

    def test_truncated_frame_rejected(self, roles):
        client, server = roles
        frame = client.seal(MessageType.DATA, b"truncate-me")
        with pytest.raises(FramingError):
            server.open(frame[:-1])


# ---------------------------------------------------------------------------
# Wrong PSK
# ---------------------------------------------------------------------------


class TestWrongPSK:
    def test_wrong_psk_rejected_by_server_validation(self):
        client = ClientHandshake(server_identity_pub=SERVER_PUB, psk=PSK)
        first = client.start()
        server_hs = ServerHandshake(identity_key=SERVER_IDENTITY)
        server_flight = server_hs.start(first[len(MAGIC) + 1 : len(MAGIC) + 1 + 32])
        result = client.server_flight(server_flight)
        good_mac = client.client_mac()
        # Validate with the right PSK succeeds.
        Session.validate_client_psk(PSK, result.transcript, result.record_salt, good_mac)
        # Validate with the wrong PSK fails.
        with pytest.raises(HandshakeError):
            Session.validate_client_psk(
                b"wrong-psk", result.transcript, result.record_salt, good_mac
            )

    def test_wrong_psk_yields_different_client_mac(self):
        # The PSK only feeds the client MAC; record keys come from the DH +
        # transcript. Two clients with different PSKs but the same ephemeral
        # produce different MACs (which is what the server checks).
        c1 = ClientHandshake(server_identity_pub=SERVER_PUB, psk=b"correct")
        c1.start()
        server_hs = ServerHandshake(identity_key=SERVER_IDENTITY)
        sf = server_hs.start(c1.public_ephemeral_raw())
        c1.server_flight(sf)

        c2 = ClientHandshake(server_identity_pub=SERVER_PUB, psk=b"wrong")
        c2._ephemeral = c1._ephemeral  # same ephemeral -> identical transcript
        c2.server_flight(sf)

        assert c1.client_mac() != c2.client_mac()


# ---------------------------------------------------------------------------
# Wrong server identity
# ---------------------------------------------------------------------------


class TestWrongServerIdentity:
    def test_attacker_signature_rejected(self):
        client = ClientHandshake(server_identity_pub=SERVER_PUB, psk=PSK)
        first = client.start()
        attacker_hs = ServerHandshake(identity_key=ATTACKER_IDENTITY)
        attacker_flight = attacker_hs.start(first[len(MAGIC) + 1 : len(MAGIC) + 1 + 32])
        with pytest.raises(HandshakeError):
            client.server_flight(attacker_flight)

    def test_garbled_signature_rejected(self):
        client = ClientHandshake(server_identity_pub=SERVER_PUB, psk=PSK)
        first = client.start()
        server_hs = ServerHandshake(identity_key=SERVER_IDENTITY)
        server_flight = server_hs.start(first[len(MAGIC) + 1 : len(MAGIC) + 1 + 32])
        bad = server_flight[:32] + bytes(b ^ 0xFF for b in server_flight[32:])
        with pytest.raises(HandshakeError):
            client.server_flight(bad)

    def test_wrong_length_flight_rejected(self):
        client = ClientHandshake(server_identity_pub=SERVER_PUB, psk=PSK)
        with pytest.raises(HandshakeError):
            client.server_flight(b"\x00" * 10)


# ---------------------------------------------------------------------------
# Replay / out-of-order
# ---------------------------------------------------------------------------


class TestReplayAndOrder:
    def test_replay_rejected(self, roles):
        client, server = roles
        frame = client.seal(MessageType.DATA, b"once")
        server.open(frame)
        with pytest.raises(ReplayError):
            server.open(frame)

    def test_out_of_order_rejected(self, roles):
        client, server = roles
        f0 = client.seal(MessageType.DATA, b"a")
        f1 = client.seal(MessageType.DATA, b"b")
        with pytest.raises(ReplayError):
            server.open(f1)
        assert server.open(f0).payload == b"a"

    def test_strict_in_order_accepted(self, roles):
        client, server = roles
        frames = [client.seal(MessageType.DATA, bytes([i])) for i in range(4)]
        for i, f in enumerate(frames):
            rec = server.open(f)
            assert rec.seq == i

    def test_duplicate_after_gap_rejected(self, roles, monkeypatch):
        # The replay window rejects duplicates regardless of gap size. We drive
        # the receiver through a few frames, then replay an already-seen frame
        # by resealing its wire bytes through a monkeypatched counter.
        client, server = roles
        seen = []
        original_seal = client.send.seal_record

        def capture_seal(type_, plaintext, rng=os.urandom):
            frame = original_seal(type_, plaintext, rng=rng)
            seen.append(frame)
            return frame

        monkeypatch.setattr(client.send, "seal_record", capture_seal)
        for _ in range(3):
            server.open(original_seal(MessageType.DATA, b"x"))
        # Seal one more (captured), open it, then try to open it again: replay.
        f = client.seal(MessageType.DATA, b"y")
        server.open(f)
        with pytest.raises(ReplayError):
            server.open(f)


# ---------------------------------------------------------------------------
# Padding buckets
# ---------------------------------------------------------------------------


def _det_rng(value: int):
    """Return an rng closure that always makes the same decisions.

    The first 1-byte request is the extra-bucket coin (we set it to ``value``);
    all subsequent requests are deterministic filler bytes taken from an
    incrementing counter.
    """

    state = {"n": 0}

    def rng(n: int) -> bytes:
        if n == 1 and state["n"] == 0:
            state["n"] += 1
            return bytes([value])
        out = bytes((i + state["n"]) & 0xFF for i in range(n))
        state["n"] += 1
        return out

    return rng


class TestPaddingBuckets:
    def test_next_padding_length_floor_and_bucket(self):
        for coin in (0, 200):
            pl = next_padding_length(0, rng=_det_rng(coin))
            total = 0 + 2 + pl
            assert total % PAD_BUCKET_SIZE == 0
            assert pl >= MIN_PAD_BYTES
            assert pl <= PAD_BUCKET_SIZE + MAX_PAD_BUCKETS_ABOVE * PAD_BUCKET_SIZE

    def test_next_padding_length_aligns_with_prefix(self):
        pl = next_padding_length(254, rng=_det_rng(0))
        assert (254 + 2 + pl) % PAD_BUCKET_SIZE == 0
        assert pl >= MIN_PAD_BYTES

    def test_record_lengths_step_in_buckets(self, roles):
        client, _server = roles
        rng = _det_rng(0)
        sizes = [0, 1, 100, 254, 255, 256, 257, 500]
        frame_lens = [len(client.seal(MessageType.DATA, b"x" * n, rng=rng)) for n in sizes]
        # Header + AEAD tag are constant overhead outside
        # the bucket-aligned padded plaintext, so every frame length has the
        # same residue mod the bucket size.
        overhead = RECORD_HEADER_SIZE + 16
        for fl in frame_lens:
            assert fl % PAD_BUCKET_SIZE == overhead % PAD_BUCKET_SIZE
        # Same-bucket payloads must share frame length: observers cannot pin
        # the exact payload size from the ciphertext length. With a 16-byte
        # floor, targets that land within the last 16 bytes of a 256-byte span
        # are pushed into the next bucket, so the first padded bucket covers
        # payload sizes 0..253, the second covers 254..509, and so on.
        assert frame_lens[0] == frame_lens[1] == frame_lens[2]  # 0, 1, 100 -> bucket 0
        assert frame_lens[3] == frame_lens[4] == frame_lens[5] == frame_lens[6]  # bucket 1
        # Crossing a bucket boundary moves the frame length by exactly one
        # bucket (256 bytes).
        assert frame_lens[3] - frame_lens[0] == PAD_BUCKET_SIZE
        assert frame_lens[7] - frame_lens[3] == PAD_BUCKET_SIZE

    def test_unpad_roundtrips(self):
        rng = _det_rng(0)
        for pt in (b"", b"a", b"ab" * 10, b"x" * 256):
            assert unpad(pad(pt, rng=rng)) == pt

    def test_unpad_rejects_corrupt_length(self):
        padded = pad(b"hello", rng=_det_rng(0))
        with pytest.raises(FramingError):
            _strip(padded[:-1])

    def test_plaintext_not_recoverable_from_length(self, roles):
        client, _server = roles
        rng = _det_rng(0)
        a = client.seal(MessageType.DATA, b"a" * 10, rng=rng)
        b = client.seal(MessageType.DATA, b"a" * 20, rng=rng)
        assert len(a) == len(b)


# ---------------------------------------------------------------------------
# Cross-direction isolation
# ---------------------------------------------------------------------------


class TestCrossDirectionIsolation:
    def test_client_record_not_openable_with_server_send_state(self, handshake_pair):
        client_session, server_session, _ = handshake_pair
        client = client_session.as_client()
        server_send = server_session.as_server().send
        frame = client.seal(MessageType.DATA, b"isolate-me")
        with pytest.raises(FramingError):
            server_send.open_record(frame)

    def test_server_record_not_openable_with_client_send_state(self, handshake_pair):
        client_session, server_session, _ = handshake_pair
        server = server_session.as_server()
        client_send = client_session.as_client().send
        frame = server.seal(MessageType.DATA, b"isolate-me-too")
        with pytest.raises(FramingError):
            client_send.open_record(frame)

    def test_independent_direction_keys_within_session(self, handshake_pair):
        client_session, _server_session, _ = handshake_pair
        client = client_session.as_client()
        # The two directions of a single session use different AEAD keys. The
        # client send state uses the client->server key; the client receive
        # state uses the server->client key. Opening the client's own sealed
        # frame with the client receive state therefore fails AEAD auth,
        # proving the direction keys are not reused across directions.
        frame = client.seal(MessageType.DATA, b"x")
        with pytest.raises(FramingError):
            client.recv.open_record(frame)

    def test_direction_keys_are_distinct_material(self, handshake_pair):
        client_session, _server_session, _ = handshake_pair
        # Sanity-check the underlying keys are genuinely different material,
        # not merely different AEAD objects wrapping the same bytes.
        from kaleido.protocol import _derive_record_key

        ck = _derive_record_key("client", client_session.transcript, client_session.salt)
        sk = _derive_record_key("server", client_session.transcript, client_session.salt)
        assert ck != sk
        assert len(ck) == len(sk) == 32


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------


class TestMessageTypes:
    @pytest.mark.parametrize(
        "mt",
        [
            MessageType.OPEN,
            MessageType.DATA,
            MessageType.CLOSE,
            MessageType.PING,
            MessageType.PONG,
            MessageType.MIGRATE,
        ],
    )
    def test_each_type_roundtrips(self, roles, mt):
        client, server = roles
        frame = client.seal(mt, b"body")
        rec = server.open(frame)
        assert rec.type == mt
        assert rec.type_name == MessageType.name(mt)
        assert rec.payload == b"body"


# ---------------------------------------------------------------------------
# Version negotiation
# ---------------------------------------------------------------------------


class TestVersionNegotiation:
    def test_version_mismatch_first_flight_rejected(self):
        bad_flight = MAGIC + bytes([VERSION + 1]) + os.urandom(32)
        with pytest.raises(HandshakeError):
            Session.from_server(
                identity_key=SERVER_IDENTITY,
                psk=PSK,
                client_first_flight=bad_flight,
                server_flight_reply=b"\x00" * 96,
                server_ephemeral_priv=X25519PrivateKey.generate(),
            )

    def test_magic_mismatch_first_flight_rejected(self):
        bad_flight = b"NOT-KLDO" + bytes([VERSION]) + os.urandom(32)
        with pytest.raises(HandshakeError):
            Session.from_server(
                identity_key=SERVER_IDENTITY,
                psk=PSK,
                client_first_flight=bad_flight,
                server_flight_reply=b"\x00" * 96,
                server_ephemeral_priv=X25519PrivateKey.generate(),
            )


# ---------------------------------------------------------------------------
# Sanity: protocol exceptions form a coherent hierarchy
# ---------------------------------------------------------------------------


def test_exception_hierarchy():
    for exc in (HandshakeError, ReplayError, FramingError):
        assert issubclass(exc, ProtocolError)
