# Threat model

Date: 2026-08-12

## Adversary

An in-path censor can observe addresses, ports, transport, packet lengths,
direction, timing, cleartext DNS, TLS ClientHello fields not protected by ECH,
and long-lived flow behavior. It can drop, reset, delay, throttle, inject,
replay captured first flights, actively probe endpoints, enumerate public
configuration channels, and block destination IPs or entire hosting ranges.

The first release does not claim protection from a global passive adversary,
endpoint compromise, device malware, or legal/physical coercion.

## Principal failure modes

1. Endpoint discovery makes wire mimicry irrelevant.
2. A single carrier becomes a cheap classifier target.
3. Fully encrypted/random first packets become a class signature.
4. An unauthenticated probe distinguishes the server from its cover service.
5. Long-lived VPN traffic differs statistically from normal cover traffic.
6. UDP is blocked or heavily shaped on a mobile carrier.
7. Mobile NAT rebinding, sleep, captive portals, or Wi-Fi/LTE handover kills a
   carrier that worked in a desktop lab.
8. A test reports success even though it measured a web proxy rather than the
   direct subscriber-to-server path.

## Non-negotiable field-release guardrails

The current lab build does not yet satisfy the first, second, fifth, or seventh
items below. They are gates for field-resilience claims, not statements about
features already present.

- At least two outer carriers with materially different blocking surfaces.
- No static endpoint list in a public binary.
- No distinctive response to unauthenticated active probes.
- No raw long-term secret in command arguments, logs, telemetry, or result files.
- Opt-in, coarse telemetry only; network labels are salted locally.
- Every performance result includes verified egress and exact path type.
- A transport is disabled remotely when its fingerprint is burned.

## Kill criteria

Do not claim field resilience when any condition holds:

- a classifier separates the carrier from its claimed cover at operationally
  acceptable false-positive rates;
- active probes identify the endpoint;
- one transport is the only working path on multiple major mobile networks;
- endpoint rotation requires an app-store update;
- a simulated carrier failure cannot recover within the documented SLO;
- field evidence covers only a foreign VPS or residential HTTP proxy.

## Current laboratory boundary

Implemented: one TLS/TCP carrier, KAL/1 mutual authentication and encrypted
records, local SOCKS5 TCP ingress, strict server target policy, offline carrier
scoring, and bounded direct/HTTP CONNECT/SOCKS5 measurement probes.

Not implemented: a second independent carrier, live failover, session migration,
descriptor/rendezvous distribution, Android TUN/VPN integration, UDP forwarding,
verified cover-service parity, or standardized TLS 1.3 exporter-bound
pre-authentication. The TLS lab carrier uses a bounded in-memory replay cache,
which is not a substitute for exporter binding across restart/distributed
instances. Therefore this repository is not evidence of TSPU resistance or
nationwide availability.
