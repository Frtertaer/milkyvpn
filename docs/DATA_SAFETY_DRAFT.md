# Data Safety form — DRAFT

> **OWNER MUST VERIFY every answer against the actual build before submitting.** This draft reflects the code in v0.1.0 (`homes.milky.vpn`): no analytics, no ads, no accounts, no crash reporting SDK.

## Overview questions

| Question | Answer | Basis |
|---|---|---|
| Does your app collect or share any of the required user data types? | **Yes** (see below — minimal, device‑to‑server functional traffic only) | Subscription URL & server params are sent to servers the user configures; treat conservatively as "collected" for transparency |
| Is all of the user data collected by your app encrypted in transit? | **Yes** | HTTPS to `sub.milky.homes`; VPN protocols are TLS/Reality/QUIC‑encrypted |
| Do you provide a way for users to request that their data is deleted? | **Yes** | In‑app "Удалить подписку"; uninstall removes everything; no server‑side account exists |
| Independent security review | No | — |

## Data types

### Personal info
- Name / Email / User IDs / Address / Phone / … → **Not collected.**

### Financial info → Not collected. (No billing in app.)
### Health & fitness → Not collected.
### Messages → Not collected.
### Photos & videos / Audio / Files & docs / Calendar / Contacts → Not collected.

### App activity
- App interactions → **Not collected** (no analytics).
- In‑app search history / Installed apps / Other user‑generated content / Other actions → Not collected.

### Web browsing → **Not collected.** The VPN tunnel carries traffic but the app does not read, log or store it.

### App info and performance
- Crash logs → **Not collected** (no crash SDK).
- Diagnostics → **Not collected automatically.** Redacted diagnostics text is generated only when the user taps "Скопировать диагностику" and is shared by the user manually (outside the app). Play guidance: user‑initiated, off‑device sharing by the user is not "collection" by the app. If unsure, declare *Diagnostics — Collected, optional, App functionality, not shared*.

### Device or other IDs → **Not collected.** (No advertising ID, no Firebase Installation ID.)

### Other — Subscription URL / VPN credentials
- Play's taxonomy has no direct category. They are sent only to the user's own configured servers as part of the core function. Recommended declaration: none of the listed categories apply; describe in the privacy policy (done).

## Security practices
- Data encrypted in transit: **Yes**
- Users can request deletion: **Yes**
- Committed to Play Families Policy: **No** (not a kids' app)

## Sharing
- No data is shared with third parties. No third‑party SDKs.

## Checklist before submission
- [ ] Re‑run `grep -r "firebase\|analytics\|admob\|crashlytics" pubspec.yaml android/` → must be empty.
- [ ] Confirm `PRIVACY_POLICY_*` URL is live.
- [ ] Confirm the answers above match the *uploaded* AAB.
