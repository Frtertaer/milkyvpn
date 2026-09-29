# MilkyVPN Windows verification — build 27 + fix branch

Box: Windows Server 2022 21H2, Administrator, VirtIO NIC. EnableLUA=0 (UAC off), no sleep states, no global IPv6, box egress 140.232.64.5.
Build A: windows-test-27 (integ 3fa81d3). Build B: rebuilt from devin/1790651401-win-app-ux-bugs-port @ 71f9a58 → 97d2ed8 (BUG-09) → 11a7fb3 (BUG-10/11) → c1f1a31 (BUG-12, final verified build).
Test profile: kal2://…@23.133.88.167:443 sni=kal.mergescribe.dev carrier=veil ech=AE3-… (US server).

## Phase A — build 27

| Scn | Result | Evidence |
|-----|--------|----------|
| A CLI sanity | PASS — `session up via veil`, curl --socks5 → 23.133.88.167 | A_client_ctl.log |
| B BUG-01 -ech on cmdline | PASS — CommandLine contains `-ech AE3-…` | (transcript) |
| C -tun mode | PASS w/ caveat — adapter+0.0.0.0/1+128.0.0.0/1+/32 up, traffic flows; taskkill /F → /1 routes & adapter gone but **/32 host route survives** (→ BUG-09). Graceful ctl 'stop' → clean revert, /32 also survives on b27. Reconnect recovers. | C_tun_adapter.txt, C_tun_ctl.log, C_tun_postkill.txt |
| D GUI | connect→disconnect→reconnect OK; net flap (Disable/Enable-NetAdapter) — recovered via watchdog; sleep N/A (no sleep states); «Полный туннель» fails: "запуск был отклонён" (→ BUG-drift root cause below); rapid -tun reconnect → orphan/bind wedge (BUG-08) | screenshots/ss_*.png |
| E BUG-03 repro | CONFIRMED — reinstall-over-live: PrepareToInstall ctl 'stop' then taskkill /F both images, no drain; processes die hard; /32 route leftover | E_reinstall.log |
| E2 IPv6 leak | UNTESTABLE — box has no IPv6 connectivity (curl -6 fails before connect) | — |
| F RSS smoke 10min | PASS — 20 samples: RSS 17.0–19.3MB flat, handles 290 stable, threads 12–14, ~20–30MB/s per fetch | rss_build27.csv |
| G BUG-02 confirm | CONFIRMED — no logs dir; bogus -psk crash leaves no trace | (transcript) |
| G2 BUG-04 | CONFIRMED — Настройки shows «Always-on VPN» row → opens Windows proxy settings | screenshots/ |
| G2 BUG-05 | CONFIRMED — «Обновить» on link-imported profile → «Подписка не добавлена» | screenshots/ |
| G3 BUG-06 | CONFIRMED — seeded fake.corp:8080+Enable=1 → connect→disconnect → ProxyEnable=0 & ProxyServer=socks=127.0.0.1:11808; corp proxy destroyed | (transcript) |
| H BUG-08 | CONFIRMED — orphaned elevated helper on :11909; single-accept ctl dead to later 'stop'; new -tun helper dies on net.Listen(:11909) EADDRINUSE | (transcript) |
| H2 BUG-07 | CONFIRMED — suspended elevated helper + reinstall as medium-IL user (lowpriv): installer's `taskkill /F` → "Access is denied"; helper survives; b27 proceeds, "Installation process succeeded". Same-profile install → file-replace failure/mixed install | H2_b27_lowpriv.log, H2_lowpriv_kill.txt |

New bugs found (build 27 / general):
1. MINOR → **BUG-09** (fixed @97d2ed8) — stale /32 host route (server IP → physical gw) after hard kill AND graceful -tun stop. C_tun_postkill.txt.
2. MAJOR → **BUG-12** (fixed @c1f1a31) — GUI «Полный туннель» unusable for profiles without drift path: `_argsFor` emits `-drift ''` → bridge builds `-ArgumentList ...,''` → PowerShell ParameterBindingValidation "argument is null or empty" → exit 1 → `tun_uac_denied` ("запуск был отклонён"). Repro: `Start-Process -Verb RunAs -ArgumentList '-addr','x','-drift',''`. Fails on ANY Windows box, not EnableLUA-related. Diagnostics shows only PERMISSION_DENIED (powershell stderr hidden inside exception — suggest logging it).
3. MAJOR → **BUG-11** (fixed @11a7fb3) — system proxy applied at spawn before SOCKS listener/session; on client startup failure (e.g. :11808 already bound → «Туннель не поднялся») proxy stayed on dead listener → all user traffic blackholed/misrouted.
4. MEDIUM → **BUG-10** (fixed @11a7fb3) — elevated helper's -log file shows only the '=== started ===' banner: `io.MultiWriter(os.Stderr, file)` — invalid stderr on elevated GUI-subsystem process → first Write fails → file + ctl mirror get nothing after banner. (Once observed on 71f9a58; did not reproduce on 97d2ed8 — fix per coordinator.)

## Phase B — build & regression (fix branch)

- `go test ./cmd/kal2-client` — PASS (0.2–0.3s)
- `python tool/check_installer.py` — PASS (drain-before-kill gate)
- `flutter test test/core/windows_vpn_bridge_test.dart test/features/settings_refresh_test.dart` — PASS 13/13
- Toolchain: Go 1.27.1, Flutter 3.47.5 stable, VS BuildTools 2022 (+VC.ATLMFC — flutter_secure_storage_windows needs atlstr.h), InnoSetup 6.7.1, wintun.dll 0.14.1 sha-verified

## Fix verification (on rebuilt installer/client)

| Bug | Verdict | Evidence |
|-----|---------|----------|
| BUG-01 -ech | **FIXED** — `-ech AE3-…` on cmdline | transcript |
| BUG-02 logs | **FIXED** — `-log` on cmdline; logs\kal2-client.log exists w/ banner+'session up via auto'; bogus-psk error lands (`dial: server flight: EOF`) | B02_error_log.log |
| BUG-03 drain | **FIXED** — healthy elevated helper + /VERYSILENT reinstall → install succeeds fast (~34s), helper drained via ctl 'stop' (Wait-Process 20s), adapter+/1 routes clean, no orphan | fix_reinstall2.log |
| BUG-04 Always-on | **FIXED** — Настройки: Автоподключение/Полный туннель/Тема/Обновить/Диагностика — no Always-on row | screenshots/ss_baa0a9db.png |
| BUG-05 refresh | **FIXED** — «Импортированные профили нельзя обновить» | screenshots/ss_9b03957c.png |
| BUG-06 proxy | **FIXED** both cases — seeded fake.corp:8080+1 restored verbatim after disconnect; clean-box → our socks= deleted, Enable=0 | transcript |
| BUG-07 wedged helper | **FIXED** — suspended elevated helper + lowpriv /VERYSILENT → `PrepareToInstall failed: Milky VPN tunnel is still active — disconnect and run setup again.` + OK dialog; nothing installed | H2_fix_lowpriv.log, screenshots/ss_e831d288.png |
| BUG-08 orphan ctl | **FIXED** — conn2 'stop' reaches orphaned helper (loop-accept): exits, adapter+routes reverted, :11909 freed | transcript |
| BUG-09 stale /32 | **FIXED** @97d2ed8 — ctl 'stop' → helper exits, /32 host-route removed, adapter gone | transcript |
| BUG-10 helper log | **FIXED** (verified @c1f1a31) — elevated GUI -tun helper's -log has full lines after banner: session up / socks5 / tun requested / adapter up; empty-log case from 71f9a58 did not reproduce; failsoft guarantees sinks | kal2-client.log excerpt |
| BUG-11 proxy-on-death | **FIXED** (verified @c1f1a31) — occupied :11808 (dead listener) + GUI SOCKS connect → «Не удалось подключиться — Туннель не поднялся»; client log: `listen tcp 127.0.0.1:11808: bind:`; registry after: ProxyEnable=0, no ProxyServer — no stale socks= left | screenshots/ss_fef73bb6.png, kal2-client.log |
| BUG-12 tun_uac_denied | **FIXED** (verified @c1f1a31) — GUI -tun connect w/ path-less profile: elevated helper spawned (cmdline: `-ech AE3-`, `-tun`, `-ctl :11909`, `-log`; no `-drift ''`), adapter MilkyVPN-TUN Up @10.85.0.1, /1 routes + /32 host route, ifconfig.me → 23.133.88.167; disconnect clean (helper+adapter+routes gone, ProxyEnable=0); helper auto-removed orphaned "MilkyVPN-TUN 1" adapter | screenshots/ss_0219969b.png |

## Phase C — 30-min soak (97d2ed8 client, SOCKS + 3 parallel fetch loops)

**PASS** — 60 samples / 30 min, 32mb.bin loop + parallel fetches: RSS 17.3→18.3MB flat (GC noise, no monotonic climb), handles constant 306, threads 12–14, ~25–29MB/s per fetch. No crash. After soak: ctl 'stop' → client exited within ~3s (ctl listener closed first, then process), :11808 freed. Evidence: rss_fixed.csv, soak_client.log.
