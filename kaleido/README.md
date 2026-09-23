# Kaleido

Kaleido is a research prototype for a censorship-resilient tunnel. The current
runnable subset is an authenticated KAL/1 inner session over one laboratory TLS
1.3/TCP carrier with a local SOCKS5 entry point. Multi-carrier movement is the
target architecture, not an implemented capability yet.

It is **not** an "unblockable VPN". No protocol can cross a physical outage,
an allowlist that excludes every reachable rendezvous, or an explicit block of
all known endpoint IPs. The engineering target is measurable resilience:
automatic recovery, low endpoint exposure, and several carriers whose failure
modes are not identical.

## What is new

Kaleido does not invent cryptographic primitives. The KAL/1 inner session uses
X25519, Ed25519, HKDF-SHA256, HMAC-SHA256, and ChaCha20-Poly1305. The research
direction is:

- carrier-neutral authenticated sessions (implemented for the TLS lab carrier);
- per-network carrier scoring and failover (offline scoring only today);
- signed, short-lived carrier descriptors (future work);
- session migration without publishing a permanent endpoint list (future work);
- a measurement method that separates ingress, tunnel, DNS, and egress health.

The first and only implemented carrier is a lab TLS 1.3 stream with a decoy HTTP
response. Future adapters are evaluated independently (REALITY/XHTTP,
AmneziaWG, QUIC/Hysteria, WebTunnel-like HTTPS) rather than treated as permanent
dependencies.

## Safety and scope

- Research and authorized network testing only.
- No custom cryptographic algorithms.
- No credentials, server addresses, or proxy passwords in the repository.
- No traffic logging by default.
- Private, loopback, link-local, and metadata destinations are denied by the
  server unless a test explicitly opts in.
- Residential HTTP/SOCKS proxies are web vantage points, not evidence that a
  raw VPN transport crossed TSPU from that subscriber network.

See [SPEC.md](SPEC.md), [THREAT_MODEL.md](THREAT_MODEL.md), and
[TESTING.md](TESTING.md).

## Local commands

Install the project in a Python 3.12 virtual environment, then:

```text
kaleido keygen --output secrets
kaleido validate --config examples/server.example.json
kaleido server --config server.json
kaleido client --config client.json
kaleido score examples/observations.json
```

Server and client configs contain paths to PSK/private-key/password files, not
the secret values. Relative paths are resolved from the config directory. See
the example JSON files for the strict schema. The client exposes SOCKS5/TCP on
loopback only; there is still no TUN adapter, UDP forwarding, tunneled DNS,
migration, or automatic failover.
