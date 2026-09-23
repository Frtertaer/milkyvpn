# Milky Core — KAL/2 protocol

KAL/2 is the second wire version of the Kaleido research session, redesigned
around what actually survives Russian filtering in 2026. The Python KAL/1
prototype in `kaleido/` remains the lab reference; `milky-core` is the Go
implementation intended for servers and for mobile embedding (gomobile AAR).

## Field research summary (Sept 2026)

Findings driving the design, with sources:

1. **Signature DPI at the border (TSPU).** WireGuard's 148-byte init, OpenVPN,
   IKEv2, plain VLESS (incl. Reality without Vision), SOCKS5, obfs4/meek are
   fingerprinted and dropped in seconds. Entropy profiling flags
   random-looking streams that match no known protocol. Active probing: a
   suspicious listener gets probed and must answer like a real service.
   (habr.com/articles/990236, fexyn.com TSPU 2026, ateo.digital guides)

2. **Real TLS 1.3 to a real host is the working baseline.** Reality+Vision
   ~95% success. Anything performing a genuine handshake to a domain whose
   DNS actually points at the server IP survives; borrowed-SNI REALITY to
   big-name targets (microsoft/apple/*.ru) is now detected by IP-ASN mismatch
   and bulk-blocked (XTLS/Xray-core#6508). → KAL/2 uses **own domain + real
   cert + real site**, never borrowed identities.

3. **Port-443 heuristics.** Since Feb 2026 TSPU experiments drop "TLS 1.3 +
   aggressive packet rate" on :443 while deep-inspecting less on high ports;
   empty SNI / default fingerprint evaded it. xHTTP-style request/response
   shape does not match the heuristic. → KAL/2's secondary `drift` carrier is
   HTTP-shaped on purpose.

4. **Whitelist regime.** Mobile shutdowns allow only whitelisted
   domestic endpoints; Cloudflare ranges are on the list; domestic RU traffic
   is filtered far less than border transit. → chain-relay carrier
   (domestic hop → foreign egress) and CDN-fronted drift are first-class.

5. **App telemetry IP blocking.** RU super-apps report VPN usage; exit IPs
   die in batches. → protocol must not depend on a single IP: endpoint
   agility (multi-port, multi-domain, CDN) is part of the client contract.

## KAL/2 inner session (evolution of KAL/1)

Crypto unchanged and deliberately boring: X25519 ephemeral, Ed25519 server
identity pin, HKDF-SHA256 transcript key schedule, ChaCha20-Poly1305 records,
PSK client pre-authenticator, finished-MACs, bounded replay cache.

New in v2:

- **Exporter binding**: when the carrier provides a TLS channel binding
  (RFC 9266 `tls-exporter`), it is mixed into the HKDF salt — the inner
  session is bound to the exact outer TLS session.
- **Multiplexing**: record header gains a 32-bit stream id; OPEN/DATA/CLOSE/RST
  carry many TCP streams over one session. Needed for a real client core.
  Scheduling: a two-lane emitter sends control records (OPEN/ACK/CLOSE/RST/
  PING/PONG) ahead of queued DATA so stream control never starves behind bulk
  transfer; DATA writers block on a bounded lane for backpressure. On receive,
  each stream owns a bounded queue drained by its own pump — a consumer that
  stalls fills its queue and is reset (peer gets RST) instead of wedging the
  session demux.
- **Variable first-flight padding**: client flight length is randomized so no
  fixed-size signature exists.
- **Record types**: OPEN, DATA, CLOSE, RST, PING, PONG, MIGRATE(reserved),
  CHALLENGE(reserved).

## Carriers

| Carrier | Shape | Use |
|---|---|---|
| `veil` | real TLS 1.3 termination, own LE cert, decoy splice on failed auth | primary, port 443 |
| `drift` | HTTP/1.1+H2 request/response pairs inside TLS (POST up / GET long-poll down) | anti-"hammering" heuristic, CDN-compatible |
| `relay` | TCP splice hop on a domestic VPS | whitelist/domestic chain |
| `quic` | future (Hysteria-style UDP) | lossy networks |

**Veil details.** The listener peeks the ClientHello: SNI matching our domain
→ terminate TLS with the real cert and run KAL/2 pre-auth inside; anything
else → TCP-splice the connection to the decoy upstream, so probes see a real
HTTPS site (or the real origin). Failed inner pre-auth likewise splices the
post-handshake stream to a local decoy site — no KAL bytes are ever emitted
to an unauthenticated peer.

**Drift details.** Upload `POST /<path>?seq=N` bodies, download `GET /<path>?seq=N`
long-poll; benign param names (config), Chrome UA, X/Z-style padding, rotates
POST/PUT/PATCH, h1/h2 negotiated. Over CDN this is ordinary API traffic.

## Application core shape

- `kal2-server`: multi-carrier listener (veil+drift+relay modes), user
  registry (id→PSK), egress allow/deny policy, systemd unit.
- `kal2-client`: local SOCKS5 entry (loopback), one muxed session,
  endpoint list with failover scoring, optional chain via relay.
- `mobile`: gomobile API `Start(configJSON) → {socksPort, error}` for the
  Flutter app; Xray keeps serving legacy protocols side-by-side.
- `subparse`: `kal2://` share link + generic subscription decoding
  (base64 line lists, JSON) consumed by the app parser.

## Out of scope v1

UDP forwarding, TUN, session migration tokens, QUIC carrier, 0-RTT.
The impossibility boundary from KAL/1 stands: full shutdown / strict
whitelist without any reachable rendezvous is reported, not disguised.
