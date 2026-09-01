# Play Release Checklist — MilkyVPN 0.1.0+1

## A. Code & build gates (must be green)
- [x] `flutter analyze` — no issues
- [x] `flutter test` — 27/27 passed
- [x] `cd android && ./gradlew :app:testDebugUnitTest` — 10/10 passed
- [x] `flutter build appbundle --release` — AAB produced
- [ ] **REAL_DEVICE_VPN_TEST** — see section D (REQUIRED, not yet done)

## B. Signing
- [ ] Create upload key (see `docs/SIGNING.md`); never commit `key.properties` / `*.jks`
- [ ] Enrol in **Play App Signing** on first upload
- [ ] Rebuild AAB with the upload key (`flutter build appbundle --release` with `android/key.properties` present)
- [ ] Verify: `jarsigner -verify -verbose -certs build/app/outputs/bundle/release/app-release.aab`

## C. Play Console
- [ ] Create app: name **MilkyVPN**, default language Russian, app (not game), free
- [ ] App content → **Privacy policy** URL (publish `docs/PRIVACY_POLICY_RU.md` / `_EN.md`)
- [ ] App content → **App access**: "All functionality is available without special access"? → **No**: reviewer needs a subscription URL. Provide a *test* subscription link with instructions (`docs/PLAY_REVIEW_VIDEO_SCRIPT.md` §Reviewer notes)
- [ ] App content → **Ads**: No
- [ ] App content → **Content rating** (IARC)
- [ ] App content → **Target audience**: 18+ (or 16+), not for children
- [ ] App content → **Data safety**: from `docs/DATA_SAFETY_DRAFT.md` (verify!)
- [ ] App content → **VpnService declaration**: from `docs/VPN_SERVICE_DECLARATION.md`
- [ ] App content → **Foreground service permissions** (FGS `specialUse`): describe "VPN tunnel must stay alive while user is connected; persistent notification shown"; attach review video
- [ ] Store listing RU + EN (`docs/PLAY_STORE_LISTING_*.md`), icon 512, feature graphic, ≥2 screenshots per form factor
- [ ] **Internal testing** track → upload AAB → add testers → verify install & connect on ≥2 devices (Android 14 and 15/16)
- [ ] Closed testing (recommended ≥14 days for new personal dev accounts) → Production

## D. REAL_DEVICE_VPN_TEST (mandatory before any track)
Device with Android 14+ (ideally 15/16), real Milky subscription:
1. Fresh install → onboarding 3 screens → "Добавить подписку" → paste URL → list loaded (16 profiles, count shown).
2. Tap **Подключить** → system VPN consent → allow → state "Подключение…" → **"Подключено"** with timer; key icon in status bar; notification present.
3. Open a browser: https://ifconfig.me shows server IP (FI/US). DNS leak test passes (dns.google/… shows non‑ISP resolvers).
4. Switch Wi‑Fi ↔ mobile: connection survives or reconnects; no permanent "Подключение…".
5. **Отключить** → state "Не подключено", notification gone, internet works directly.
6. Revoke via another VPN app / Settings → app shows "Не подключено" (onRevoke).
7. Deny VPN consent → app returns to "Не подключено" with a clear message, no crash.
8. Deep link: `adb shell am start -a android.intent.action.VIEW -d "milkyvpn://import?url=https%3A%2F%2Fsub.milky.homes%2Fs%2FTOKEN"` → confirmation screen, token hidden, no auto‑connect.
9. Reject test: `milkyvpn://import?url=http://evil/…` → rejected.
10. Auto mode with the first server unreachable (e.g. blocked host) → falls back, bounded (≤4 attempts), ends in either Connected or a visible error.
11. Always‑on: Settings → VPN → MilkyVPN → Always‑on → toggle → app connects at boot.
12. Kill app from recents while connected → tunnel survives (FGS) → notification "Отключить" works.
13. Android 15/16: no FGS start crash (`ForegroundServiceStartNotAllowedException`), no `SecurityException` for `specialUse`.

Record results in `BUILD_RESULT.md` → `REAL_DEVICE_VPN_TEST = PASSED (device, Android version, date)`.

## E. Pre‑upload hygiene
- [ ] `git status` clean; no `key.properties`, no `*.jks`, no real subscription tokens in repo (`grep -r "sub.milky.homes/s/" --include=*.dart --include=*.kt --include=*.md .` shows only placeholders/fixtures)
- [ ] `docs/THIRD_PARTY_LICENSES.md` up to date; LGPL‑3.0 notice for AndroidLibXrayLite satisfied (source link + dynamic linking via AAR)
- [ ] versionCode bumped for every upload (`pubspec.yaml` → `version: 0.1.0+N`)
