# BUILD_RESULT

STATUS = NOT_READY — REAL_DEVICE_VPN_TEST has not been performed (no Android device/emulator in the build sandbox) and no Play upload key exists yet; all code, tests, docs and the release AAB build are complete.

REAL_DEVICE_VPN_TEST = REQUIRED

## Artifact
- AAB: `build/app/outputs/bundle/release/app-release.aab`
- Size: 99.6 MB (three ABIs: arm64-v8a, armeabi-v7a, x86_64; Play delivers one per device)
- SHA-256: `d17db1e8037a9254f28ecf9187a5462520f4f987e47075e64ee0e0b4444e6a6a`
- Signing: **debug keystore** (no `android/key.properties` present) — must be rebuilt with the upload key before Play upload, see `docs/SIGNING.md`
- R8: minify + resource shrink enabled; mapping at `build/app/outputs/mapping/release/mapping.txt` (upload to Play for deobfuscation)
- Contains: `libgojni.so` (Xray-core), `BIND_VPN_SERVICE`, `foregroundServiceType=specialUse`, `SUPPORTS_ALWAYS_ON`, `milkyvpn://import` intent filter, applicationId `homes.milky.vpn`

## App identity
| Field | Value |
|---|---|
| applicationId | `homes.milky.vpn` |
| versionName / versionCode | `0.1.0` / `1` |
| minSdk / targetSdk / compileSdk | 26 / 36 / 36 |
| Flutter / Dart | 3.35.4 / 3.9.2 |
| AGP / Kotlin / Gradle | 8.9.1 / 2.1.0 / 8.12 |
| VPN core | Xray-core v1.260327.1 (MPL-2.0) via AndroidLibXrayLite v26.8.20 `libv2ray.aar` (LGPL-3.0) |

## Build gates
| Gate | Result |
|---|---|
| `flutter pub get` | OK |
| `flutter analyze` | **No issues found** |
| `flutter test` | **27 passed, 0 failed** (subscription parser, URL policy, redactor, repository/secure store, ProfileSelector, VpnController fallback, UI smoke) |
| `./gradlew :app:testDebugUnitTest` | **10 passed, 0 failed** (XrayConfigBuilderTest ×8, SafeLogTest ×2) |
| `./gradlew` release build (R8) | OK |
| `flutter build appbundle --release` | **OK** — 322 s |

## Protocol support (as built)
| Profile type | Parsed | Executable in tunnel | Notes |
|---|---|---|---|
| VLESS + Reality + TCP (vision) | yes | **yes** (priority) | `security=reality`, pbk/sid/sni/fp/spx mapped |
| VLESS + WS + TLS | yes | yes | path/host mapped |
| VLESS + XHTTP (TLS/Reality) | yes | yes | path/host/mode mapped |
| Hysteria2 / hy2 | yes | yes | Xray `hysteria` outbound v2, salamander obfs |
| vmess / trojan / ss / grpc / kcp / other | yes | **no — ignored** | counted as "несовместимые" in diagnostics |

## What was verified in the sandbox
- Static: analyzer, 37 unit/widget tests, Kotlin config-builder tests producing valid Xray JSON for every supported transport.
- Packaging: AAB contents, manifest flags, native libs for all 3 ABIs, R8 completes with keep rules for `go.**`/`libv2ray.**`.
- Fixture: 16 synthetic profiles (9 FI / 7 US, fake credentials) parse to the expected kinds and locations.

## What was NOT verified (blockers for PLAY_INTERNAL_TEST_READY)
1. **REAL_DEVICE_VPN_TEST** — the sandbox has no Android device/emulator and no network path to the real subscription. Untested at runtime: VPN consent dialog, TUN establishment, Xray `startLoop` with the TUN fd on Android 14/15/16, HTTPS verification through the tunnel, Wi‑Fi↔cellular transition, `onRevoke`, Always‑on, FGS `specialUse` start on API 34+, notification "Отключить" action. Follow `docs/PLAY_RELEASE_CHECKLIST.md` §D and record the result here.
2. **Upload key** — create per `docs/SIGNING.md`, add `android/key.properties`, rebuild AAB.
3. **Owner inputs** — operator name/e‑mail and published privacy‑policy URL (`docs/PRIVACY_POLICY_*`), reviewer test subscription token (`docs/PLAY_REVIEW_VIDEO_SCRIPT.md`), Data Safety answers verification (`docs/DATA_SAFETY_DRAFT.md`).

## Known limitations / follow‑ups (non‑blocking)
- IPv6 inside the tunnel is not routed (IPv4‑only TUN); IPv6 server addresses are supported.
- Locale is fixed to Russian; English strings exist in `S` but no runtime switch.
- In‑app open‑source licenses page is a static "О приложении" text; full `showLicensePage` could be added.
- `mocktail` dev dependency is unused and can be removed.

## How to flip STATUS to PLAY_INTERNAL_TEST_READY
1. Run §D of `docs/PLAY_RELEASE_CHECKLIST.md` on a real device (Android 14 and 15/16), all 13 steps pass.
2. Set `REAL_DEVICE_VPN_TEST = PASSED (<device>, Android <ver>, <date>)` here.
3. Rebuild with the upload key; update SHA‑256 above.
4. Change the first line to `STATUS = PLAY_INTERNAL_TEST_READY`.
