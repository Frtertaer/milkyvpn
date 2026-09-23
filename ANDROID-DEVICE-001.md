# ANDROID-DEVICE-001

Updated: 2026-09-07. Physical-device evidence only; emulator results are not used.
The accepted Milky Orb V2 design is preserved. No website or production-server changes.
The computer's Hiddify process and network configuration were not changed.

## Current status

**BLOCKED — the latest normal release still times out at POST_CONNECT_PROBE in all three modes on the mobile uplink, including profiles that carried real traffic in earlier controlled tests. The same installed release connects and carries real application traffic on Wi-Fi. The mobile-network requirement is not met.**

The original native startup failure is fixed. This report does not claim every connection problem is resolved. A successful native outbound probe alone is not evidence that Android application traffic passed through TUN.

## REAL DEVICE

- Model: realme RMX3834 (RE5C9F), physical ADB device.
- Android: 15 / API 35.
- ABI: arm64-v8a; device also supports armeabi-v7a/armeabi.
- App: homes.milky.vpn, 0.1.0+1, target SDK 36, minimum SDK 26.
- Core: Lib v40 / Xray-core v26.7.28, embedded in process.
- APK ABIs: arm64-v8a, armeabi-v7a, x86_64.
- Core loading and native startup were observed on the ARM64 phone. No observed UnsatisfiedLinkError, dlopen failure, missing-symbol or ABI-mismatch failure.
- Updates installed with adb install -r; subscription was retained.

## SUBSCRIPTION

| Measure | Actual value |
|---|---:|
| Entries received | 16 |
| Parsed | 16 |
| Post-dedupe | 16 |
| Compatible (static native contract) | 16 |
| Duplicates dropped | 0 |
| Malformed | 0 |
| Counts trusted | true |

PARSED_PROFILE_COUNT = 16  
DEDUPED_PROFILE_COUNT = 16  
COMPATIBLE_PROFILE_COUNT = 16

The real encrypted subscription was read by the application. Counts were not synthesized. The parser and its compatibility rules were not changed in this device-failure task.

The actual transport inventory explains the previous selection problem: Finland has 4 Reality TCP, 2 XHTTP, 2 WS/TLS and 1 Hysteria2 profiles; USA has 4 Reality TCP, 2 WS/TLS and 1 Hysteria2. Compatibility means the bridge accepts the structural contract, not a guarantee of current network reachability.

## FAILURE BEFORE FIX

- Requested reproduction: Finland / FI Helsinki-4.
- Original sanitized native evidence: go.Universe$proxyerror; config error -> failed to build routing configuration -> illegal geoip:private rule -> geoip.dat missing in the app's Xray asset directory.
- Root cause: the generated routing JSON required geoip.dat, but the embedded Android application did not ship that optional file.
- LAST_SUCCESSFUL_STAGE = TUN_FD_RECEIVED
- FIRST_FAILED_STAGE = CONFIG_VALIDATED
- These original milestones are reconstructed from the original native exception and Android TUN logs; the old build did not emit the new deterministic stage markers.
- Xray did not complete startup. This was a configuration-asset failure, not proof of a broken VpnService or ABI.
- Xray exit code: NOT_APPLICABLE; the core is an in-process library, not a child process.

A second error-handling bug hid the useful native failure: a cleanup disconnect could throw after the service stopped itself, replacing the primary config/probe code with an unrelated cleanup error.

## FIX

1. XrayConfigBuilder.kt replaces geoip:private with the same upstream private/local CIDR set, preserving local bypass routing without an external geodata dependency. Both TUN and SOCKS-only configurations are covered.
2. ConnectionTrace.kt and MilkyVpnService.kt record deterministic lifecycle milestones, the last successful stage, and the failed stage. Native validation is only marked successful after startLoop accepts the exact JSON.
3. SafeLog.kt preserves sanitized native exception class/cause/stack evidence, maps missing geodata to config_asset_missing, and maps deadline errors to timeout. No secret field values are required.
4. VpnStateStore.kt and vpn_bridge.dart carry the milestone fields to Diagnostics.
5. vpn_controller.dart preserves the primary failure if cleanup disconnect also fails.
6. Native callbacks are guarded by the active connection generation; stale callbacks cannot publish state or change the newer connection's underlying network.
7. ProfileSelector no longer spends all four attempts on the same family. It tries one profile per available family before repeated family members, in this order: XHTTP, Hysteria2, WS/TLS, Reality TCP. Auto also balances locations: the current subscription produces Finland XHTTP, USA Hysteria2, Finland WS/TLS, USA Reality as its first four candidates. Explicit country filtering and the bounded attempt limit remain intact. The first two families carried real application traffic in the controlled mobile tests; this preference is not an assertion that they are always reachable.
8. Diagnostics long codes use selectable, horizontally safe text. The rest of the accepted design is unchanged.

No VPN engine replacement, parser count manipulation, TLS-validation relaxation, fake CONNECTED state, or reduction of the original post-connect probe was introduced.

### Files changed for this task

- android/app/src/main/kotlin/homes/milky/vpn/core/XrayConfigBuilder.kt
- android/app/src/main/kotlin/homes/milky/vpn/vpn/MilkyVpnService.kt
- android/app/src/main/kotlin/homes/milky/vpn/vpn/ConnectionTrace.kt
- android/app/src/main/kotlin/homes/milky/vpn/vpn/SafeLog.kt
- android/app/src/main/kotlin/homes/milky/vpn/vpn/VpnStateStore.kt
- lib/core/vpn/vpn_bridge.dart
- lib/core/vpn/vpn_controller.dart
- lib/core/errors/milky_error.dart
- lib/features/settings/diagnostics_screen.dart
- Corresponding Kotlin and Dart regression tests.
- tool/device001_main.dart: explicit test entry point, not referenced by normal lib/main.dart.
- tool/device001_probe.ps1: accessibility-tree-driven physical-device reproduction.
- ANDROID-DEVICE-001.md

The workspace also contains earlier accepted redesign changes. They are not new redesign work in this task.

## FI HELSINKI-4 CONFIG / SUPPORT CONTRACT

Observed native validation and startup passed after the geodata fix, followed by two successful outbound probes (1267 ms and 143 ms).

Sanitized structural inspection of the exact selected profile:

| Field | Observed shape |
|---|---|
| Protocol / transport / security | vless / tcp / reality |
| Address / port | Present / valid |
| UUID credential | Present; value not reported |
| Flow | xtls-rprx-vision |
| SNI | Present; value not reported |
| Reality public key | Present, length 43; value not reported |
| shortId | Present, length 16; value not reported |
| Fingerprint | chrome |
| Path / host | Not applicable to this TCP profile |
| allowInsecure | false |
| Routing / DNS / inbounds | Present / present / 2 |
| TUN bridge | TUN inbound; valid fd passed to startLoop(config, fd) |

The bridge executed this exact config after the fix. No evidence justified reclassifying it as statically incompatible. General mobile application traffic through this family nevertheless failed in later tests.

## POST-CONNECT VERIFICATION AND LIMITS

The existing HTTPS probe remains mandatory before CONNECTED. No success is published merely because VpnService exists, TUN exists, or isRunning is true.

Source inspection confirms that AndroidLibXrayLite measureDelay calls core.Dial on the running instance. Xray dispatches that request through its routing and selected default proxy. It bypasses the Android TUN and SOCKS inbounds. Therefore a successful probe is real outbound evidence, but cannot independently establish TUN dataplane success. [AndroidLibXrayLite implementation](https://github.com/2dust/AndroidLibXrayLite/blob/v26.8.20/libv2ray_utils.go), [Xray core.Dial](https://raw.githubusercontent.com/XTLS/Xray-core/5ca6f4b7d4dc/core/functions.go).

The false-positive limitation was observed, not hidden: on mobile, Reality and WS/TLS could pass the short probe while Telegram and both literal-IP and hostname HTTPS failed. The precise reason those transports failed general traffic has not been proven. Handshake/MTU/sniffing changes were not made speculatively.

A localhost SOCKS control through the phone's real Hysteria2 core returned HTTP 204 in 3.025 s. A later Reality SOCKS control overlapped a failed native retry and is inconclusive. Neither is presented as TUN proof.

## AFTER FIX — REAL TRAFFIC MATRIX

User checks were performed on the same physical phone. HTTPS checks used a literal-IP page and a hostname page. Raw browser content and IP addresses are not included here.

| Build / network / selection | Native probe | Telegram + both HTTPS pages | Reconnect |
|---|---|---|---|
| Earlier normal / Wi-Fi / USA Reality | PASS | PASS, user reported USA external-IP country | Native reconnect PASS |
| Earlier normal / Wi-Fi / Auto | PASS | Not separately confirmed for each run | Native reconnect PASS |
| Earlier normal / Wi-Fi / Finland | FAIL: 4 timeouts | Not verified | Not verified |
| Earlier normal / mobile / Finland Reality, cold start | PASS | FAIL | General traffic not verified |
| Earlier normal / mobile / USA Reality, cold start | PASS | FAIL | General traffic not verified |
| Controlled exact family / mobile / Finland XHTTP | PASS | PASS | Not yet fully verified |
| Controlled exact family / mobile / USA WS/TLS | PASS | FAIL | Not verified |
| Controlled exact family / mobile / USA Hysteria2 | PASS | PASS | Not yet fully verified |
| Final normal release / mobile / Auto | FAIL: 4 timeouts across families | Not verified | Not verified |
| Final normal release / mobile / USA after cold restart | FAIL: 4 timeouts across families | Not verified | Not verified |
| Normal release / Wi-Fi / USA Hysteria2 | PASS | PASS, user confirmed all three checks | Native reconnect PASS, one failed candidate before successful fallback |
| Normal release / Wi-Fi / Finland XHTTP | PASS | Final per-mode manual check pending | Native reconnect PASS |
| Normal release / Wi-Fi / Auto | PASS | Final per-mode manual check pending | Native reconnect PASS |
| Latest delivered release / mobile / Auto with country balancing | FAIL: 4 timeouts | Not verified | No false CONNECTED |
| Latest delivered release / mobile / Finland | FAIL: 4 timeouts | Not verified | No false CONNECTED |
| Latest delivered release / mobile / USA | FAIL: 4 timeouts | Not verified | No false CONNECTED |
| Latest delivered release / Wi-Fi / Auto selecting Finland | PASS | PASS: user confirmed Telegram and both HTTPS pages | Connection left enabled; earlier native reconnect PASS |

AUTO:
- Final mobile connect / post-connect probe: FAIL, 4 attempts split across Finland and USA.
- Final Wi-Fi native connect and actual Telegram/literal-IP HTTPS/hostname HTTPS traffic: PASS; earlier native reconnect PASS.
- VPN_IP_CHANGED: NOT_VERIFIED; no paired original-IP baseline is claimed.

FINLAND:
- Mobile XHTTP connect / probe / real application traffic: PASS in controlled build.
- Exact FI Helsinki-4 native config/start/probe: PASS after original fix.
- Final normal-release mobile connect: FAIL, 4 attempts. Wi-Fi native connect/reconnect PASS; full final traffic matrix incomplete.
- VPN_IP_CHANGED: NOT_VERIFIED.

USA:
- Mobile Hysteria2 connect / probe / real application traffic: PASS in controlled build.
- Latest normal-release mobile connect / probe: FAIL.
- Latest normal-release Wi-Fi connect / probe: PASS.
- VPN_IP_CHANGED: NOT_VERIFIED against an original-IP baseline; earlier user observed USA country.

Latest mobile attempts in all three modes:

LAST_SUCCESSFUL_STAGE = OUTBOUND_READY  
FIRST_FAILED_STAGE = POST_CONNECT_PROBE  
SANITIZED_NATIVE_CODE = timeout  
SANITIZED_NATIVE_EXCEPTION_CLASS = go.Universe$proxyerror  
USER_DIAGNOSTIC_CODE = SERVER_UNREACHABLE

Native configuration validation, TUN establishment and core startup passed. These latest failures differ from the original missing-geoip startup error. No CONNECTED event was published for the failed attempts.

## NETWORK / TUN / DNS / IPv6

- Wi-Fi: available and actually connected in Wi-Fi-labelled runs.
- Mobile data: enabled; airplane mode disabled in the final mobile failures.
- Android Data Saver: disabled.
- MilkyVPN UID 10029: INTERNET granted, background app-ops allowed; netpolicy effective blocked reasons NONE while foreground. No proven Android app-level mobile prohibition was found.
- This evidence does not prove carrier filtering or a server-side root cause. No production server was changed.
- The user reports current operator/TSPU restrictions. The screen they asked to inspect contained an emergency-service warning, not a VPN error. That warning alone does not identify the filtering mechanism.
- A separate read-only test from the actual app UID on the mobile interface resolved and opened TCP to all 8 distinct TCP endpoints in the subscription (275–554 ms); the Wi-Fi control also passed (249–621 ms). The UDP-only Hysteria endpoint was intentionally excluded from a TCP test. No address values were logged. Thus complete endpoint/IP unreachability is not supported by this evidence; the VPN/data failure occurs after basic DNS/TCP reachability. It does not distinguish DPI, TLS/protocol filtering, remote path issues or other application-layer causes.
- VpnService.prepare permission, foreground startup and Builder.establish succeeded on Android 15.
- TUN fd: valid and received by native startLoop.
- MTU: 1500, unchanged.
- IPv4: TUN address /30 and default IPv4 route.
- DNS servers: 1.1.1.1 and 8.8.8.8, with port-53 traffic routed into the core DNS outbound; query strategy UseIPv4.
- Real traffic: Chrome route selected tun0; TUN byte counters increased on a successful Wi-Fi session. User-confirmed Telegram and both HTTPS pages also worked on mobile XHTTP and Hysteria2 sessions.
- protect(socket): not the bridge's loop-avoidance mechanism. The app package is excluded through addDisallowedApplication; its own core uplink sockets bypass TUN. Failure to establish this exclusion now fails closed.
- Own app subscription refresh also bypasses TUN by this design.
- DNS: hostname HTTPS resolution worked on successful sessions. Failures include DNS deadlines on unsuccessful sessions. A comprehensive DNS-leak test was not performed.
- IPv6: no IPv6 TUN address; Android's VPN route state showed ::/0 unreachable. IPv6 is blocked by the current implementation, not tunnelled. No leak-proof claim is made.

## RELEASE MANIFEST

The built release manifest was inspected: INTERNET, ACCESS_NETWORK_STATE, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE and notification permission are present. MilkyVpnService is non-exported, requires BIND_VPN_SERVICE and declares specialUse foreground service type. Foreground startup and notification worked on API 35. No manifest change was needed for the observed failure.

## TESTS

- flutter analyze: PASS, no issues.
- flutter test: PASS, 130 passed / 1 intentionally skipped icon-export test.
- Android release unit tests: PASS, 27 tests / 0 failures / 0 errors.
- Parser 16-to-10 regression and mutation/control tests remain passing.
- Native missing-geodata regression verifies exact literal CIDRs and absence of geoip/geosite asset references for both build modes.
- Milestone tests reject premature config/start/connected claims and preserve the actual static-build failure stage.
- Primary native error plus failing cleanup disconnect regression passes.
- Long diagnostic codes remain selectable at large text scale.
- Selector controls reproduce both the old four-Reality starvation and the all-Finland Auto starvation; new selection covers families and locations within the same budget, preserves stable tie order and strict explicit country selection.
- Existing UI goldens pass; redesign unchanged.
- git diff --check: PASS (only Windows line-ending notices).

## BUILD

Normal entry point lib/main.dart was used for delivery. Temporary exact-profile/family test entry points are not used in this APK.

- APK: D:/vpnapp/MilkyVPN-ANDROID-DEVICE-001.apk
- APK size: 163,656,326 bytes.
- APK SHA-256: F3F4A3C15A211AC69AAF8EA707858C58A3F2F7B4585021BBC4A3F0FA52204197
- Release APK build: PASS; installed on physical phone, subscription retained.
- AAB: D:/vpnapp/MilkyVPN-ANDROID-DEVICE-001.aab; build PASS; size 99,624,676 bytes.
- AAB SHA-256: E0E87216CF4382A5FB002E560E8D7DBCC64C0CF1F464111F6574605EB709BB49
- Existing local fallback debug certificate is retained for device-update continuity; no owner upload key was provided. These artifacts are not claimed Play-ready.
- Nothing was published to Google Play.
- The final normal APK is installed on the phone. Wi-Fi and Auto/Finland are enabled; the temporary ADB localhost forward was removed. No diagnostic-filter APK was left installed.

## PRIVACY / LOCAL EVIDENCE

Raw logcat, connectivity dumps and UI XML remain under the ignored build/device001 directory. Do not upload that directory. User URLs/tokens, UUIDs, key material, passwords and public IP addresses are absent from this report.

Automated ADB browser-launch checks were rejected by automatic approval review with "blocked by policy". They were not bypassed; the user performed browser checks manually. The later localhost SOCKS control tested the existing native gstatic canary, not browser launching.

## CQ REFERENCES

| Knowledge unit | Confidence at consultation | Application |
|---|---:|---|
| ku_895e26df5f8a4c1fb638b536bfba7397 | 90% | TUN-up is not dataplane proof; its separate two-backend experiment was not repeated here. |
| ku_993b5f6ae4aa42a5b55c29e619f053e6 | 70% | Correlate attempts and await native teardown. |
| ku_4371172dd9b7444eadee7d4ac9fdfb48 | 50% | Preserve the primary error when cleanup fails. |

## REQUIRED FINAL FIELDS

PARSER_16_TO_10_REMAINS_FIXED = YES  
UI_REDESIGN_UNCHANGED = YES  
DIAGNOSTICS_LONG_CODE_LAYOUT_FIXED = YES  
REAL_DEVICE_TESTED = YES  
TUN_ESTABLISHED = YES  
REAL_TRAFFIC_VERIFIED_ON_SOME_SESSIONS = YES  
ALL_REQUIRED_FINAL_MODE_AND_NETWORK_RECONNECT_TESTS_VERIFIED = NO  
STATUS = BLOCKED
