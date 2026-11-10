# MilkyVPN (Pandora / KAL2) — threat model

Repository: `Frtertaer/milkyvpn` (single repo; ops/infra lives in-repo under `deploy/`, `.github/workflows/`, systemd units). No separate infrastructure repository exists. Builds on `kaleido/THREAT_MODEL.md` (censor adversary) and `milky-core/DESIGN.md` ("Active-scan resistance", "Binary protection").

## System overview and trust boundaries
Censorship-resistant VPN: clients (Android, Windows, iOS/macOS) dial a self-hosted server over pluggable carriers (veil TLS, drift WS, cdn/mosaic via fronts, quasar UDP/KCP, quic2, rtc). Inner session = KAL2 Noise-like handshake (ed25519 server identity + per-user PSK), AEAD records. A web panel manages users, PSKs, links and subscriptions.

Trust boundaries:
1. Internet / censor ↔ server listeners (:443 veil+decoy, :20443-20445 UDP, :8081/:8880 front HTTP, :80 ACME).
2. Internet ↔ kal2-panel (:9443 HTTPS, `/api/*` admin, `/sub/<token>` public, `/releases/`).
3. Authenticated VPN subscriber ↔ server egress (server dials arbitrary targets for the subscriber, incl. potentially 127.0.0.1 / private ranges / loopback-only ops API 127.0.0.1:9449).
4. Untrusted subscription URL / pasted link ↔ app parser and config builders.
5. Local device (other apps, other local users) ↔ client loopback SOCKS (127.0.0.1:11808 etc.), JNI/method channels, stored secrets.
6. Fronts (Cloudflare Worker, Yandex Cloud function) ↔ server plain-HTTP front leg.
7. CI/CD (GitHub Actions, DEPLOY_SSH_KEY) ↔ production servers.

## Components
| Name | Code | Platform |
|---|---|---|
| Protocol core | `milky-core/internal/kal2`, `internal/carrier`, `internal/core`, `internal/cutproxy`, `internal/tun`, `pkg/kal2core`, `pkg/kal2mobile`, `cmd/kal2native`, `cmd/milkynative`, `cmd/genvec` | all |
| Server | `milky-core/cmd/kal2-server`, `cmd/kal2-relay`, `cmd/kal2-udpmux`, server sides of carriers (`veil_server.go`, `mosaic_server.go`) | server |
| Panel | `milky-core/cmd/kal2-panel` (admin API, TOTP, `/sub/`, ops API, `/releases/`) | server |
| Flutter app | `lib/` (subscription parser/repository, URL policy, updater, VPN controller, secure store), `test/` | android/windows/ios |
| Android | `android/` (MilkyVpnService, XrayConfigBuilder, NativeBridge, KeystoreSealedStore) | android |
| Windows desktop | `windows/`, `installer/`, `packaging/`, `milky-core/cmd/kal2-client` (local SOCKS client, system proxy janitor) | windows |
| Apple | `ios/`, `macos/`, `apple/` (PacketTunnel, plugins) | ios |
| Ops & CI | `deploy/` (tg-bot.py, canary, backup, server-deploy.sh, fronts `deploy/front/`, decoy-site), `.github/workflows/`, `scripts/`, `testing/`, `tool/`, `research/`, `kaleido/` | server |

## Entry points and who can reach them
- Server listeners: anyone on the internet, including the censor's active probers. Unauthenticated traffic must be indistinguishable from the decoy site / spliced foreign site (tarpit, per-IP cap).
- Front leg `-front-listen` (plain HTTP): anyone who finds the port, plus the CF/Yandex fronts.
- Panel `/api/login`: anyone on the internet (admin token + optional TOTP); session cookie = HMAC(token, exp). `/sub/<token>`: anyone with a sub token. `/releases/`: public.
- Ops API (`-ops-listen`, no auth, loopback only): any local process on the US box — and any VPN subscriber if server egress can reach 127.0.0.1.
- tg-bot: Telegram updates from the allowed chat id only.
- App: subscription URLs / share links (`pandora://`, `kal2://`, vless/vmess/etc.) pasted or fetched by users; update metadata from GitHub / panel mirror.
- Client local SOCKS on loopback: any local app/process on the device.

## Assets (user-ranked)
1. **Undetectability of server/protocol by the censor** (critical — user-named): server must not be identifiable by active probes, fingerprints, or leaked endpoints/identifiers; no static endpoint list.
2. **User PSKs, server identity key, sub tokens** (critical — user-named): leakage = impersonation, decryption of future sessions via fake server, or full link list disclosure.
3. **Admin access to panel and servers** (critical — user-named): panel token/TOTP, SSH ops/deploy keys (`DEPLOY_SSH_KEY`, `milky_ops_plain`), TG bot token/chat, CF/Yandex tokens. Compromise = full control of all users.
4. User traffic confidentiality/integrity on the device and in transit; device-side secret storage.
5. Server availability (DoS on listeners/panel).

## Attacker profiles (user: all in scope)
- **A1 Censor / TSPU**: in-path observer + active prober + replayer (see `kaleido/THREAT_MODEL.md`). Goal: identify and block.
- **A2 Internet attacker vs panel / sub / fronts / front leg**: unauthenticated remote.
- **A3 Malicious or compromised VPN subscriber** (holds a valid PSK): abuses server egress (SSRF to loopback ops API, cloud metadata, private nets), attacks other users, escalates to admin.
- **A4 Malicious subscription/link source**: crafted links/subscriptions/update feeds fed into the app (injection into Xray/kal2 JSON, SSRF from app, path traversal, parser DoS).
- **A5 Local attacker on the user's device**: other apps using the open loopback SOCKS, reading stored secrets/logs, abusing exported Android components.
- **A6 Supply chain / CI**: workflow injection, leaked secrets in repo/PR bodies, unsigned updates.

## Existing controls
- Decoy-through + SNI splice, keyed drift path, tarpit, per-IP pre-auth cap, mimicry padding (`DESIGN.md`).
- Panel: constant-time token compare, HMAC session cookie, TOTP, audit log, ops API bound to loopback, sub tokens compared constant-time, per-user PSK rekey.
- App: `lib/core/security/subscription_url_policy.dart` (SSRF URL guard), `redactor.dart`, `SafeLog.kt`, Keystore-sealed storage, FallbackSecureStore on macOS.
- Server egress destination guard (`internal/core/egress_guard.go`): subscriber egress refuses non-public targets (loopback, private, link-local, CGNAT, the host's own addresses, NAT64/6to4-embedded equivalents) on the TCP, UDP and upstream-SOCKS5 paths, with a resolved-address `Dialer.Control` check so DNS names and rebinding to private ranges are covered too. Closes the A3 SSRF-to-ops-API path; `AllowPrivate` opts out for lab use only.
- Panel ops API (`/ops/users`): PSKs and sub tokens are stripped from responses on the unauthenticated loopback listener.
- Windows `-tun` elevation (`windows_vpn_bridge.dart`): subscription fields never enter the PowerShell source — the exe path and a `CommandLineToArgvW`-quoted argv line pass through env vars, so a crafted link cannot inject flags into the elevated spawn (A4).
- Releases: garble-obfuscated libcore.so, stripped binaries; gitleaks + PR-body scan in CI.

## Out of scope / accepted risk (user)
- Nothing excluded: user said all repo paths (incl. `kaleido/`, `research/`, `testing/`, `tool/`, `scripts/`, iOS/macOS) and all attackers above are in scope.
- From `kaleido/THREAT_MODEL.md`: global passive adversary, endpoint compromise / device malware with root, legal/physical coercion are not claimed to be defended. IP/domain blocking by a determined censor is an acknowledged limit (handled by agility, not by code).

## Resolved (2026-11)
- Server egress now blocks loopback/private/link-local/own-host targets (`internal/core/egress_guard.go`), so the unauthenticated ops API 127.0.0.1:9449 is no longer reachable by a subscriber. Was: "egress does NOT block non-public targets" (2026-11 scan of `internal/core/egress.go`).

## Open questions
- Is the panel :9443 exposed publicly or only via restricted IPs?
