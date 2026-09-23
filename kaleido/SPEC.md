# KAL/1 protocol sketch

Status: research draft with a runnable laboratory subset. This document defines
the target inner session; sections explicitly marked as future work are not yet
implemented. The current runtime has one TLS 1.3/TCP carrier and no migration.

## 1. Goals

KAL/1 provides a mutually authenticated, replay-resistant byte-stream session.
The implemented runtime carries it over TLS/TCP. HTTP semantics, QUIC, WebRTC,
and datagram transports are architectural candidates, not current features. A
PSK pre-authenticator is checked before the server emits a KAL-specific flight;
failure is mapped to the carrier's ordinary decoy behavior.

## 2. Cryptographic construction

- Server identity: Ed25519 public key pinned in client configuration today;
  short-lived signed descriptors are future work.
- Ephemeral agreement: X25519 on every carrier attachment.
- Client authorization: high-entropy per-user PSK via HMAC-SHA256 over the full
  transcript. A future public-key client credential can replace this field.
- Implemented key schedule: HKDF-SHA256 with the transcript hash as salt and
  distinct labels for client-to-server, server-to-client, nonce bases,
  handshake verification, server signature input, and client PSK proof.
  Migration and exporter outputs are future wire-version work.
- Records: ChaCha20-Poly1305 with the encoded header as associated data.
- Sequence numbers: monotonic unsigned 64-bit integers per direction. Reuse,
  replay, or reordering fails closed in the implemented ordered-stream profile.

No 0-RTT application data is accepted in KAL/1. A future design for resumption
and migration tokens requires single-use, short-lived, server-encrypted
capabilities bound to the client credential, session, carrier class, and
expiry; the current runtime does not issue or accept such tokens.

## 3. Handshake

The logical transcript is:

1. Client flight: magic, version, ephemeral X25519 key, and a PSK
   pre-authenticator over that flight.
2. Server flight: ephemeral X25519 key and Ed25519 signature over the negotiated
   transcript and transcript-bound key material.
3. Both peers derive direction-separated traffic keys from X25519 and the
   transcript using HKDF-SHA256.
4. Client PSK MAC plus client `Finished`, then server `Finished`, prove both
   authorization and possession of derived key material before application data.

The TLS lab carrier also keeps a bounded ten-minute replay cache for valid first
flights and returns only the decoy on replay. A standardized TLS 1.3
`tls-exporter` channel binding (RFC 9266) is not exposed by this Python runtime;
therefore exporter-bound pre-authentication is a requirement for a future native
carrier and a release gate, not a property claimed by this lab adapter.

Feature bitmaps, negotiated padding profiles, session IDs, and client public-key
credentials remain future wire-version work.

The concrete byte encoding is length-delimited binary with hard maximums. Outer
carriers may wrap or fragment it, but may not rewrite transcript fields.

## 4. Record layer

Record types:

| Type | Meaning |
|---|---|
| `OPEN` | Reserved for multiplexed stream opening (future runtime work) |
| `DATA` | Ordered application bytes; carries dial control in the lab runtime |
| `CLOSE` | Half-close or close with a generic reason code |
| `PING` / `PONG` | Liveness and path measurement |
| `MIGRATE` | Reserved for a future single-use migration capability |

Plaintext is padded to a negotiated bucket with randomized selection among
several profiles. Padding is a traffic-analysis cost, not a promise of
undetectability. Cover traffic is rate-limited and disabled on battery-sensitive
profiles.

## 5. Carrier contract

The target carrier interface exposes:

- `probe(deadline) -> observations`
- `connect(descriptor, deadline) -> authenticated byte stream`
- `network_changed(fingerprint)`
- `close(reason)`

Only the TLS stream adapter exists today. It returns a configurable HTTP decoy
after failed inner pre-authentication. Operational parity with a real cover
service (certificate, ALPN, headers, timing, close behavior) has not yet been
established and is a release blocker for field claims.

## 6. Adaptive selection

Implemented scores decay quickly but are not yet scoped to a salted local
network fingerprint.
The score combines recent connection success, handshake time, sustained goodput,
loss/reset class, battery cost, and carrier independence. Exploration is kept
small but non-zero so a previously blocked carrier can recover.

No live failover controller is implemented yet. When it is added, it must never
treat a successful TCP connect as tunnel success. The minimum success state is:
authenticated KAL handshake, tunneled egress proof, and a small bidirectional
transfer.

## 7. Impossibility boundary

KAL/1 cannot guarantee reachability through a complete shutdown, a strict
allowlist excluding every rendezvous, or universal IP/ASN blocking. Such states
must be reported explicitly rather than disguised as a protocol timeout.
