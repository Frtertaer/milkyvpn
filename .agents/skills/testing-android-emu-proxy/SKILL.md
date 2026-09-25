---
name: testing-android-emu-proxy
description: End-to-end test the MilkyVPN Android app on the test35 emulator routed through a residential proxy (hostile-region simulation); UI coords, logcat stage names, :kal2 process diagnostics, SOCKS-port traffic checks.
---

# MilkyVPN Android emulator + residential-proxy testing

## Harness (host)
- AVD `test35` (Android 15 x86_64) MUST be launched with `-http-proxy http://127.0.0.1:12345` so all guest TCP goes through the local shim `~/auth_proxy.py` (injects DataImpulse `Proxy-Authorization`, upstream `gw.dataimpulse.com:10000`, RU residential exit). Start shim first: `setsid python3 ~/auth_proxy.py > ~/auth_proxy.log 2>&1 &`. Verify exit geo host-side: `curl -s --proxy http://127.0.0.1:12345 "http://ip-api.com/json/?fields=country,city,isp,query"`.
- `export PATH=$HOME/android-sdk/platform-tools:$PATH`; `adb devices` → emulator-5554.
- `~/auth_proxy.log` shows every guest CONNECT/GET + upstream status (`UPSTREAM: 200 OK` vs `502 NO_HOST_CONNECTION` / `400 HOST_NOT_ALLOWED`); correlate VPN-server CONNECTs with connect attempts.

## App control (Russian UI)
- Launch: `adb shell monkey -p vpn.milky.app -c android.intent.category.LAUNCHER 1`
- Orb = connect/disconnect toggle at center `adb shell input tap 540 799` (orb node bounds ≈ `[184,401][896,1198]`). If VPN consent dialog appears, tap OK (~540,1340). Orb taps are IGNORED while a connect is in-flight or while the error sheet is up — always check state via `adb shell uiautomator dump` (Flutter app: text lives in `content-desc`, not `text=`).
- Error sheet ("Не удалось подключиться"): "Попробовать снова" ≈ 540,1882; "Выбрать страну" ≈ 540,2056; back key (`input keyevent 4`) returns to main screen. Country chips row ≈ y1536 (Авто 220 / Финляндия 540 / США 860 in a picker, or ~1589 on main screen — dump to confirm, layout shifts with banners).
- Reset app state fully (kills BOTH processes incl. `:kal2`): `adb shell am force-stop vpn.milky.app`. Needed because a plain disconnect leaves :kal2 cached.
- Screencap: `adb shell screencap -p /sdcard/x.png && adb pull /sdcard/x.png <local>`.

## Verifying the :kal2 bound-service fix
- Stage lines: `adb logcat -d | grep MilkyVPN` — healthy order: PROFILE_SELECTED → VPN_PERMISSION_GRANTED → KAL2_SESSION_STARTING → KAL2_SESSION_STARTED → CONFIG_BUILT → TUN_CREATED → XRAY_PROCESS_STARTED → OUTBOUND_READY → POST_CONNECT_PROBE `result=OK delayMs=N` (RU path ~800–2500ms) → CONNECTED.
- Process state while connected: `adb shell dumpsys activity processes | grep -B2 -A8 "vpn.milky.app:kal2"` — expect `fg T/ /BTOP ... (service)` bound via `ConnectionRecord ... Kal2Service ... flags=0x41`. After disconnect expect `cch-empty` (unbound) — that is correct; `cch-empty`/freezing WHILE UI says connected is the bug class.
- Binder-side failures only show in server-process logs: grep `JavaBinder` for `NativeBridge$StartException` — AIDL exceptions do NOT propagate to the caller, so a thrown `start()` still logs `KAL2_SESSION_STARTED result=OK`; always cross-check with JavaBinder lines.
- Live traffic check while session is up: `adb forward tcp:11808 tcp:11808` (kal2/Mirage SOCKS) and `adb forward tcp:10808 tcp:10808` (Xray SOCKS, full chain); `curl -s -m 12 --socks5-hostname 127.0.0.1:11808 https://ifconfig.me` should return the VPN exit IP (NOT the RU underlay IP). Session exists only during/after a successful connect; a healthy listener returns in ~1–4s, a stale one refuses in <0.1s.
- Android guest has no curl; use adb forwards + host curl instead.

## Devin Secrets Needed
- none — DataImpulse creds are embedded in `~/auth_proxy.py` on the box.
