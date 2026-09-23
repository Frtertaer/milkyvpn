# Test and measurement plan

The list below is the field-validation target. The current automated harness
implements bounded `connect`, proxy negotiation, TLS, HTTP, and optional egress
checks plus a loopback KAL/1 SOCKS roundtrip. An egress observation counts only
for the path explicitly recorded with it; a separate host-direct HTTPS check is
never tunnel or proxy proof. The harness does not yet automate tunneled DNS,
carrier handover, recovery, or the full field matrix.

## Measurement layers

Every run records these stages separately:

1. client network and route selection;
2. DNS bootstrap;
3. direct carrier reachability;
4. authenticated KAL handshake;
5. tunneled DNS, if enabled;
6. egress proof;
7. bidirectional reliability and throughput;
8. handover and recovery.

Server ingress, server egress, and client path are independent health states.

## Vantage types

| Vantage | Valid evidence | Invalid inference |
|---|---|---|
| German server | service, listener, DNS, and server egress health | Russian client reachability |
| Residential HTTP/SOCKS proxy | regional web availability, HTTPS CONNECT, observed exit ASN | raw KAL/TCP/UDP survival through subscriber TSPU |
| Android USB tether | direct mobile path, NAT, DPI, UDP/TCP behavior | other carriers/regions |
| Home Wi-Fi | that fixed ISP and access network | national availability |

DataImpulse targeting is encoded in the proxy username. Country is supported;
city/state/ZIP/ASN filters are best-effort paid filters. SOCKS5 primarily carries
TCP; UDP requires separate approval. Never embed those credentials in a plan.

## Required negative controls

- plain WireGuard;
- OpenVPN TCP and UDP;
- current REALITY/XHTTP profile;
- AmneziaWG;
- Hysteria2;
- one HTTPS-native carrier;
- direct internet without a tunnel.

## Minimum field matrix before a claim

- two weeks continuous observation;
- at least two mobile and two fixed/Wi-Fi networks;
- cold start, sustained transfer, idle resume, captive portal, and Wi-Fi/LTE
  handover;
- verified egress on every run;
- exact client/runtime profile validated before traffic tests;
- packet metadata capture where lawful and authorized, with payloads excluded.

## Result schema

JSONL records contain timestamp, pseudonymous network label, carrier, descriptor
version, target class, stage timings, status, normalized error category, byte
counts, and verified egress ASN/country. They never contain credentials, full
subscriber IPs, browsing destinations, or payloads.
