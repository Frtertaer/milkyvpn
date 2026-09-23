# Kaleido field test matrix

This preregistration measures the current TLS/TCP carrier and KAL/SOCKS behavior on authorized paths. It does not claim unblockability or operation everywhere in Russia. Existing services on ports 80/443 are out of scope and must not be changed.

## Record contract

Write one JSONL `record_kind=attempt` per attempt with `schema=kaleido-field/v1`, `test_id`, `attempt_id`, `started_at_utc`, `path_type`, `egress_scope`, `network_contexts`, `runtime_profile`, `case`, `expected_capability`, `measurements`, `attempt_outcome`, `failure_stage`, `error_code`, `evidence_refs`, `evidence_retained`, and `causal_attribution`.

After three attempts, write a separate `record_kind=aggregate` that references their `attempt_id` values and contains `verdict`. Never put a 3-attempt verdict in an attempt record.

Attempt outcomes are `pass`, `fail`, `inconclusive`, or `not_supported`. Failure stages are `tcp`, `tls`, `auth`, `socks`, `payload`, `idle`, `handover`, or null. `egress_scope` distinguishes direct client egress, Kaleido server egress, listener-only evidence, and not attempted.

## Runtime profile

Before the first attempt, freeze a redacted canonical-JSON manifest and its SHA-256. Include client/server build digests; certificate and Ed25519 identity public-key fingerprints; OS, Python, OpenSSL, and cryptography versions; commands and flags; transport, endpoint role, port, TLS version, SNI, ALPN, and certificate policy; address family, DNS mode, MTU, timeouts, retries, keepalive; protocol-native settings; and harness versions.

Embed the manifest plus `profile_id` and `manifest_sha256`. Refer to authentication only by an opaque key-slot ID. A missing or changed required field invalidates the attempt. Public certificate fingerprints may be retained; private keys, PSKs, and secret-derived hashes may not.

## Paths and test IDs

Canonical ID: `KF-<PATH>-<PROFILE>-<CASE>`.

- `USBM`: direct USB mobile tether; disable phone Wi-Fi and unrelated host adapters, then verify the default route and direct public-HTTPS control.
- `HWF`: home Wi-Fi; disable Ethernet and USB tether, then verify the default route.
- `W2M`: forced home-Wi-Fi to direct-mobile transition while periodic traffic is active; store both origin and destination contexts.
- `SRVLOOP`, `OVERLAY`, and `ETH4` are legacy controls only and use `LEG-*` IDs.

Each context records `segment`, `operator_ref`, `asn_ref`, and address family. Use registry-assigned opaque labels such as `OP-M01` and `AS-M01`; never invent labels for missing historical data. Record DNS mode because Kaleido does not provide a general tunneled VPN DNS plane.

## Profiles and cases

Profiles are `KAL`, `HTTPS-CAR` (carrier-matched control), `HTTPS-DIR` (ordinary HTTPS), `WG`, `OVPN-TCP`, `OVPN-UDP`, `AWG`, and `HY2`. Do not alter services on 80/443 for parity; record every endpoint, port, and TLS mismatch.

Cases are `COLD`, `HS`, `BI1M`, `IDLE`, `HAND`, and KAL-only `BADPSK`. Run `COLD`, `HS`, `BI1M`, and `IDLE` for each configured profile on `USBM` and `HWF`; run `HAND` on `W2M`. An incomplete profile is `inconclusive`, not a transport failure. UDP-control failure after TCP controls pass is transport-specific evidence, not a KAL result.

## Execution order and gates

Run: immutable profile -> path qualification -> `HTTPS-DIR` -> matched carrier/control handshake -> native or KAL handshake -> `BI1M` -> `IDLE` -> `HAND`.

If `HTTPS-DIR` fails, stop that path suite as inconclusive. If direct HTTPS passes but the matched carrier fails, allow one diagnostic KAL attempt but do not classify repeated KAL failure as KAL-specific. Do not run payload, idle, or handover after its handshake fails. Restore and requalify routes between VPN profiles; never run routing VPN controls concurrently.

For KAL, run `BADPSK` before the valid handshake. It passes only when client `auth.failed` appears, no client `auth.success` appears, and SOCKS access remains unavailable.

## Timing and verdicts

Use three independent attempt records per case, then derive one aggregate verdict. Defaults: TCP 10 s; TLS 15 s; KAL/native auth 10 s after TLS; cold ready 30 s; bidirectional transfer 60 s; idle exactly 5 min with resume within 15 s; handover observation 30 s.

Aggregate verdict:

- `pass`: 3/3 meet integrity and timing criteria.
- `flaky`: 1/3 or 2/3 pass.
- `fail`: 0/3 while prerequisites pass.
- `inconclusive`: path, profile, or prerequisite control is invalid.
- `not_supported`: outside the current profile contract.

For `BI1M`, transfer exactly 1,048,576 bytes in each direction, preferably concurrently, and record exact counts plus expected and observed SHA-256 for both payloads.

## Abort and evidence rules

Abort on payload corruption, certificate bypass/mismatch, unexpected egress, unintended route or DNS change, manifest-hash mismatch, cleanup timeout or orphan, resource-safety breach, or any secret in output. Every attempt records `cleanup_ok`; false makes the attempt nonzero and `inconclusive`. Also mark `inconclusive` when path identity or a prerequisite cannot be established.

Keep exact clocks and evidence references. Never store PSKs, private material, raw subscriber IPs, or reversible secret hashes. Authentication uses only an opaque key-slot reference. Operator/ASN mappings stay in a separate restricted file.

## Interpretation limits

- This is not a complete VPN: no TUN, UDP carrier, general VPN DNS plane, migration, live failover, multiplexing, or seamless Wi-Fi/LTE handover.
- For `HAND`, set `session_continuity=not_supported`; record `old_session_outcome`, `fresh_reconnect_on_destination`, and `reacquisition_seconds`. A clean disconnect plus fresh cold connection is not seamless handover.
- Legacy controls in `results/lab-de-20260814.jsonl` are excluded from canonical aggregates because exact observation times and complete manifests were not retained.
- Do not infer TSPU behavior, operator intent, geographic coverage, nationwide stability, or unblockability. Use `causal_attribution=unknown` unless independent evidence supports something narrower.
