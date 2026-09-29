# BUGS — реестр известных багов

Правило проекта: **баг не считается закрытым, пока нет регрессионного теста.**
Каждая запись ссылается на GitHub Issue (создаётся по шаблону
`.github/ISSUE_TEMPLATE/bug_report.yml`); фикс → PR с тестом → запись
переводится в `FIXED` со ссылкой на PR и тест.

## Формат записи

```
### BUG-<YYYY-MM-DD>-<nn> — <короткое название>
- Severity: block | major | minor
- Platform: android | ios | windows | linux | macos | core | protocol
- Status: open | fixing | fixed-in-PR | verified
- Repro: <минимальные шаги>
- Found by: <сессия/трек/CI-джоба>
- Issue: #N   PR: #M   Regression test: <путь::тест>
```

## Открытые

### BUG-2026-09-29-01 — Windows: `ech=` теряется при импорте kal2:// профиля
- Severity: major (stealth-регрессия: veil hello светит реальный SNI)
- Platform: windows (+ любой клиент на общем `subscription_parser`)
- Status: fixed-in-tree (`5df3cc9`), needs release rebuild ≥ `5df3cc9`
- Repro: импортировать kal2-ссылку с `ech=` → экспорт/лог клиента показывает
  запуск `kal2-client` без `-ech` → внешний SNI = `kal.mergescribe.dev`
  вместо cover-имени
- Found by: windows-track verification session
- Issue: —  PR: —  Regression test: subscription_parser round-trip

### BUG-2026-09-29-02 — Windows: клиент нигде не пишет логи
- Severity: major (полевая диагностика невозможна)
- Platform: windows
- Status: fixed-in-PR
- Repro: любой сбой `kal2-client.exe` — stderr проглатывается родителем,
  в `%APPDATA%\homes.milky\milkyvpn` логов нет
- Fix: `kal2-client -log <path>` пишет собственный лог (ротация .1 > 1 МБ);
  мост передаёт `%APPDATA%\homes.milky\milkyvpn\logs\kal2-client.log`
  в обоих режимах (SOCKS и elevated -tun helper)
- Found by: windows-track verification session
- Issue: —  PR: —  Regression test: `milky-core/cmd/kal2-client/main_test.go`,
  `test/core/windows_vpn_bridge_test.dart`

### BUG-2026-09-29-03 — Windows: silent-переустановка убивает живой туннель
- Severity: minor
- Platform: windows
- Status: fixed-in-PR
- Repro: при активном соединении запустить `MilkyVPN-Setup.exe /VERYSILENT`
  → taskkill по kal2-client без drain'а сессий
- Fix: `PrepareToInstall` шлёт ctl `stop` и ждёт `Wait-Process` (kal2-client
  до 20 с, milkyvpn до 15 с после graceful WM_CLOSE); `/F` только как fallback
- Found by: windows-track verification session
- Issue: —  PR: —  Regression test: `tool/check_installer.py`,
  `milky-core/cmd/kal2-client/main_test.go::TestCtlMirrorAndStop`

### BUG-2026-09-29-04 — Windows: Android-only строка «Always-on VPN» в настройках
- Severity: minor (misleading UI; на Windows tap открывал ms-settings:network-proxy)
- Platform: windows (+ любые non-Android платформы)
- Status: fixed-in-PR
- Repro: Настройки → группа «Подключение» → строка «Always-on VPN /
  Системные настройки Android» показана и на Windows
- Fix: строка рендерится только на `Platform.isAndroid`
- Found by: windows-track verification session (build 25)
- Issue: —  PR: —  Regression test: `test/features/settings_refresh_test.dart`

### BUG-2026-09-29-05 — «Обновить» на link-only профиле показывает «Подписка не добавлена»
- Severity: minor (misleading UX: профили есть, обновлять просто нечего)
- Platform: all (android | ios | windows | macos | linux)
- Status: fixed-in-PR
- Repro: импортировать kal2:// ссылку текстом → Настройки/Подписка → «Обновить»
  → snackbar «Подписка не добавлена», хотя профили есть
- Fix: при `refresh()==null` различаем «вообще ничего не импортировано»
  (`noSubscription`) и «профили из ссылки, обновлять нечего» (`notRefreshable`)
- Found by: windows-track verification session (build 25)
- Issue: —  PR: —  Regression test: `test/features/settings_refresh_test.dart`

### BUG-2026-09-29-06 — Windows: disconnect затирает чужой системный прокси
- Severity: major (для пользователей за корпоративным прокси: их прокси
  теряется безвозвратно после первого disconnect)
- Platform: windows
- Status: fixed-in-PR
- Repro: иметь ProxyEnable=1 + ProxyServer=corp → connect → disconnect →
  ProxyEnable=0 и ProxyServer=оставлен наш `socks=127.0.0.1:11808`
- Fix: при connect снимок `ProxyEnable`/`ProxyServer` через `reg query`;
  на disconnect `restoreProxyPlan` возвращает прежние значения (или
  удаляет наш `ProxyServer`, если его не было); PAC/AutoConfigURL не трогаем.
  Снапшот равный нашему `socks=` значению = маркер утечки после краша —
  считается «не было прокси» (delete + enable=0), иначе утечка вечная
- Found by: static review windows_vpn_bridge (windows track)
- Issue: —  PR: —  Regression test:
  `test/core/windows_vpn_bridge_test.dart::proxy restore plan`

### BUG-2026-09-29-07 — Windows: silent-reinstall при живом elevated -tun helper'е → полу-замена файлов
- Severity: minor (edge: требуется зависший ctl elevated-процесс)
- Platform: windows
- Status: fixed-in-PR
- Repro: elevated -tun helper жив, но ctl не отвечает → `/VERYSILENT`
  reinstall: ctl-stop молчит, `taskkill /F` из non-elevated инсталлятора
  получает Access denied → файлы пишутся поверх работающего exe →
  смешанная старая/новая установка (или ошибка file-in-use)
- Fix: после fallback'а инсталлятор проверяет `Get-Process kal2-client`;
  если жив — PrepareToInstall возвращает сообщение и setup чистно
  абортается («disconnect and run setup again»)
- Found by: static review windows.iss (windows track)
- Issue: —  PR: —  Regression test: `tool/check_installer.py` (guard+
  abort ordering)

### BUG-2026-09-29-08 — Windows: ctl-сокет принимает только одно соединение → orphan -tun helper не остановить
- Severity: major (edge: после краша приложения -tun ломается до taskkill/reboot)
- Platform: windows
- Status: fixed-in-PR
- Repro: GUI -tun connect → elevated helper слушает :11909, app держит conn.
  Краш/убийство приложения → conn умирает БЕЗ 'stop'. Helper жив. Любая
  новая попытка -tun connect: `_stopCtl` пишет 'stop' в backlog (accept уже
  израсходован — одно-разовый), новый helper падает на `net.Listen(:11909)`
  address-in-use → `log.Fatalf`. Также мёртв log-mirror.
- Fix: ctl-accept в цикле — каждая новая conn замещает старую (закрывая её),
  'stop' срабатывает от любого пира; `sync.Once` против двойного close(stopCh)
- Found by: static review kal2-client ctl (windows track)
- Issue: —  PR: —  Regression test:
  `milky-core/cmd/kal2-client/main_test.go::TestCtlSecondPeerCanStop`
  (fails на старом коде — 2.1s timeout)

### BUG-2026-09-29-09 — Windows: `stop` по ctl оставляет /32 host-маршруты (graceful -tun stop)
- Severity: minor
- Platform: windows
- Status: fixed-in-PR
- Repro: -tun connect → ctl 'stop' → `route print`: /32 маршрут до сервера
  через физический шлюз остаётся (подтверждено в поле на build 27). /1
  умирают вместе с адаптером, host-маршрут — нет.
- Fix: `waitForTun` — ctl-'stop' теперь канселит tun-ctx и ждёт (≤15s) пока
  goroutine дойдёт до deferred `dev.Restore()`/`dev.Close()`; раньше `return`
  из main убивал goroutine до defer'ов
- Found by: windows verify session (build 27)
- Issue: —  PR: —  Regression test:
  `milky-core/cmd/kal2-client/main_test.go::TestWaitForTun*`

### BUG-2026-09-29-10 — Windows: лог elevated helper'а пуст после баннера (MultiWriter голод на invalid stderr)
- Severity: medium
- Platform: windows
- Status: fixed-in-PR
- Repro: elevated -tun helper (GUI-subsystem) → `-log` файл содержал только
  '=== started ===' (однажды на 71f9a58; на 97d2ed8 лог писался полностью —
  stderr там был валиден). Причина-механизм: `io.MultiWriter(os.Stderr,
  logFile)` — невалидный stderr handle у спавненного процесса → первый Write
  падает → все последующие sink'и голодают.
- Fix: `failsoft` — wrapper, глотающий Write-ошибку каждого sink'а
  независимо (stderr/file/ctl)
- Found by: windows verify session (fix-билд)
- Issue: —  PR: —  Regression test:
  `milky-core/cmd/kal2-client/main_test.go::TestFailsoftKeepsChainAlive`

### BUG-2026-09-29-11 — Windows: прокси остаётся на мёртвом listener'е при фейле коннекта
- Severity: major
- Platform: windows
- Status: fixed-in-PR
- Repro: клиент умирает ПОСЛЕ 'session up' но во время `_applyProxy`
  (напр. :11808 занят → ServeSocks fatal): exit-handler'овский `_restoreProxy`
  срабатывает no-op до `_proxySet=true` → `socks=` остаётся выставленным на
  мёртвый/чужой листенер → трафик юзера в refused/blackhole
- Fix: после `_applyProxy` — проверка `_proc == null` → синхронный
  `_restoreProxy` + `core_exit` (раньше `_set(connected)` шёл без проверки)
- Found by: windows verify session (build 27)
- Issue: —  PR: —  Regression test: `tool/check_windows_bridge.py`
  (ordering-gate: applyProxy → alive-check → connected)

### BUG-2026-09-29-12 — Windows: GUI -tun падает с tun_uac_denied у профилей без path
- Severity: critical (GUI -tun мёртв для любого профиля без drift-path)
- Platform: windows
- Status: fixed-in-PR
- Repro: профиль без `path` → `-drift ''` в arg list → tun path через
  `Start-Process -Verb RunAs -ArgumentList` → PowerShell
  ParameterBindingValidation («argument is null or empty») → exit 1 → мост
  маппит в `tun_uac_denied`. Не UAC, не EnableLUA — ломается на любом боксе.
- Fix: `_argsFor` опускает пары flag+value с пустым value (все флаги
  клиента дефолтятся в ""; Go flag pkg к тому же съел бы следующий токен
  как значение пустого флага)
- Found by: windows verify session (fix-билд, уточнение «EnableLUA» диагноза)
- Issue: —  PR: —  Regression test:
  `test/core/windows_vpn_bridge_test.dart` — path-less → нет ''/-drift;
  drift path → сохраняется

## Закрытые

(перенос сюда после merge фикса с регрессионным тестом)

---

# BUGS — emulator-matrix findings

Track: Android emulator matrix (API 26/29/31/34/35), `testing/` stand on
`devin/1790629023-testing-stand`. Status: **FIXED** (fix + regression test in
this change set), **OPEN**, **DOC** (documented limitation).

## BUG-1 — net_loss / dns_flip: tunnel never recovered within 90s — FIXED

- Symptom: `svc wifi disable && svc data disable` for 15s → restore → no
  CONNECTED within 90s; private-DNS flip behaved the same.
- Root cause, two layers:
  1. **Go core**: `kal2.Session` had no liveness detection. A blackholed
     carrier (packets dropped, no RST — exactly what `svc` network kill and
     many real mobile handoffs produce) keeps `WaitClosed()` silent forever:
     the read loop blocks on a socket that never errors and writes just back
     up. `EnableReconnect` therefore never redialed.
  2. **Android**: `registerNetworkCallback.onLost` ran a single reverify
     probe, then `teardownLocked()` + terminal `ERROR`. No reconnect loop.
- Fix:
  - `kal2.Session.Kill(err)` — fails streams and closes the carrier (a plain
    `Close` leaves stream readers hanging on undrained queues).
  - `kal2core.Client.EnableLiveness(every, pongTimeout, misses)` — watchdog
    that pings the live session (Ping runs in a goroutine under an outer
    deadline so a wedged outbound queue counts as a miss, not a hang) and
    `Kill`s after N misses → the existing reconnect loop redials. Wired in
    `kal2mobile` with 4s/4s/2.
  - `Client.pingMu` serializes Ping callers — the session routes each PONG to
    a single registered channel, so concurrent pings (cover + liveness) used
    to clobber each other.
  - `MilkyVpnService`: `wantsConnected` + `tunnelSupervisor` — probes the
    tunnel with a real fetch every ~10s while connected; failures flip to
    CONNECTING, ~90s of failure escalates to a fresh full connect (≤3, linear
    backoff), then honest `ERROR`. Recoverable connect() failures also retry
    the same way.
- Regression test: `milky-core/pkg/kal2core/api_test.go:
  TestLivenessRedialsBlackhole` (blackholes the carrier socket, expects kill
  + redial + working ping). CI scenarios `net_loss`, `wifi_lte`, `dns_change`.

## BUG-2 — fgs_doze: `:kal2` process dropped out of foreground under doze — FIXED

- Symptom: `dumpsys deviceidle force-idle` → `dumpsys activity processes`
  showed `:kal2` no longer in `fg` state.
- Root cause: `Kal2Service` was a bound-only service; binder importance
  (BIND_IMPORTANT from a foreground client) does not survive device idle —
  the system demotes bound secondary processes, freezing the SOCKS listener
  (TCP accepts at kernel level, no thread to accept() → wedged outbound).
- Fix: `Kal2Service` promotes itself to a real foreground service while a
  session is live (`startForeground`, `specialUse` type on API 34+,
  `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` in the manifest), demoted on `stop()`.
- Regression: CI scenarios `fgs_doze`, `battery_opt`.

## BUG-3 — verify_tunnel accepted an empty reply — FIXED (test-stand)

- The SOCKS probe `curl --socks5-hostname … ifconfig.me/ip` returning empty
  was counted as pass — "real traffic through tunnel" was never asserted.
- Fix: strict non-empty + `verify_tunnel_wait` polling window.

## BUG-4 — wait_state matched stale logcat lines — FIXED (test-stand)

- `wait_state CONNECTED` grepped the whole `logcat -d` buffer — a CONNECTED
  line written by an earlier scenario matched instantly after a disruption;
  `logcat -c` then destroyed the evidence the failure report needed, and the
  device ring buffer wraps MilkyVPN lines out on noisy APIs anyway.
- Fix: `run_emu_ci.sh` streams `adb logcat -v threadtime` into
  `ci-artifacts/logcat-full.txt` for the whole job; waits run on byte-offset
  marks (`mark_log`/`log_since`) into that file — fresh lines only, nothing
  lost. Pattern is `'[= ]CONNECTED'` so `stage=CONNECTED` and
  `attempt=N CONNECTED` both match but `DISCONNECTED` never does.

## BUG-5 — `adb install` raced emulator boot — FIXED (test-stand)

- `run_emu_ci.sh` installed immediately while adbd was up but the system was
  half-booted → install failures. Now waits for `sys.boot_completed` + `pm`.

## BUG-6 — connect had no retry for the transient first-connect EOF — FIXED

- `server flight: unexpected EOF` on the first connect after a server restart
  was a hard fail (observed CI-wide). The scenario now retries the connect
  once, and the app itself retries recoverable connect failures (≤3, 2/4/6s
  backoff) — both belts live behind the error vocabulary.

## BUG-7 — missing scenario coverage — FIXED (test-stand)

- Added `on_revoke` (`appops set PKG ACTIVATE_VPN deny` → expects `onRevoke`
  log + teardown + dead tunnel; restores `allow`). On API <29 the op does not
  exist — the scenario logs `SKIP` and reports pass-with-note.
- Added `battery_opt` (deviceidle whitelist + forced doze → tunnel must live).
- All scenarios now gate the CI job (previously everything after `connect`
  was `|| true` best-effort).

## BUG-8 — wifi_lte assumed cellular on every API — FIXED (test-stand)

- The API35 emulator image ships no telephony at all (no rild, zero
  `TRANSPORT_CELLULAR` in dumpsys): `svc data enable` is a no-op, so after
  `svc wifi disable` there is no underlay and a "wifi→LTE" claim is false.
  The API26 image has goldfish rild but MOBILE attach takes 10-30s and
  raced the 90s recovery window.
- Fix: capability check via `pm list features telephony`, then `svc data
  enable` + up-to-45s wait for a CONNECTED cellular network BEFORE cutting
  wifi. No telephony / no attach → logged SKIP and an honest wifi off/on
  flap (still exercises underlay-loss reconnect) instead of a fake fail.
- Confirmed working on 29/31/34: kal2 `core:` log shows
  `redial failed: tcp dial: network is unreachable` during the outage then
  recovery — the liveness-kill→redial path fires as designed.

## BUG-9 — `$( ... | grep ...)` assignments killed scenarios under set -e — FIXED

- `wl=$(dumpsys deviceidle | grep whitelist | grep $PKG)` in `battery_opt`
  and the `svc`/`settings` toggles all returned non-zero in normal cases
  (no match, radio absent) — with `set -euo pipefail` the scenario aborted
  before its own assertions. Also the deviceidle whitelist prints the
  header and the package on different lines, so the chained grep could
  never match anyway.
- Fix: toggles run `|| true` (assertions decide pass/fail), whitelist
  check greps the package directly, dns/grep assignments guarded the same.

## BUG-10 — `svc wifi`/`svc data` throw SecurityException on API <=28 — FIXED

- On API 26 the shell user (2000) lacks `CHANGE_WIFI_STATE`, so
  `svc wifi disable` dies with
  `SecurityException: WifiService: Neither user 2000 nor current process has
  android.permission.CHANGE_WIFI_STATE` — wifi stayed up, the tunnel never
  dropped, and `wifi_lte` reported a fake "session never recovered".
- Fix: `wifi_toggle` tries `svc wifi`, verifies the real state via
  `dumpsys wifi` ("Wi-Fi is enabled/disabled"), and falls back to the legacy
  `settings put global wifi_on 0/1` (writable by shell, still honored on
  API <29). `mobile_data` gets the same fallback. If neither path toggles,
  the scenario logs SKIP honestly instead of failing.

## BUG-11 — data→wifi asserted a fresh CONNECTED that never comes — FIXED

- Re-enabling wifi after running on cellular does NOT kill the VPN session:
  the carrier socket either migrates or keeps running, so no redial and no
  new `CONNECTED` line is logged. Requiring `wait_state CONNECTED` made the
  second half of `wifi_lte` fail even on a perfectly healthy tunnel
  (seen on API 35, run 36525073239).
- Fix: the data→wifi half now asserts only that traffic still passes
  (`verify_tunnel_wait 75`). The wifi→data half keeps the CONNECTED
  requirement — losing the underlay really does force a redial.

## BUG-12 — fgs_doze checked the wrong dumpsys section — FIXED

- `dumpsys activity processes | grep -B2 -A6 :kal2` lands on the LRU
  `*APP* UID ... ProcessRecord` block which carries no fg/svc label — the
  check could never see "fg" and reported ":kal2 not foreground" although
  `ActivityManager` had logged `Background started FGS: Allowed` for
  Kal2Service.
- Fix: assert on `isForeground=true` inside the Kal2Service record of
  `dumpsys activity services $PKG` (authoritative for FGS state), with
  `dumpsys activity lru` `fg` as fallback; both dumps print on failure.

## OPEN / documented limitations

- **API 29 uiautomator empty-tree flake** (run 36515454841): Flutter renders,
  no crash, but `uiautomator dump` returned no nodes for 90s. Mitigations in
  this change: `ui_ready` gate before onboarding, longer `ui_tap_desc_wait`,
  empty-dump diagnostics (window focus dump). If it still fires, the run log
  now distinguishes "empty tree" from "wrong screen".
- **`on_revoke` on API 26**: `ACTIVATE_VPN` appop doesn't exist there — SKIP.
- **`on_revoke` on API 31 (and any API without the framework
  OnOpChangedListener)**: `appops set ACTIVATE_VPN deny` is only consulted
  at `prepare()` time — denying a live session does not call
  `VpnService.onRevoke()` and the tunnel stays up. The scenario detects the
  missing signal and records a SKIP instead of a fake fail.
- **`dns_leak`** remains partially observational: it asserts the VPN link
  carries the tunnel resolvers (1.1.1.1/8.8.8.8) and that resolution through
  the tunnel works; the raw `dumpsys connectivity` snapshot is also logged
  into ci-artifacts for manual review.
- **`tls_cutoff`** stays skipped in CI (needs a `-http-proxy` emulator plus a
  host-side cutproxy); runnable manually via `--proxy`.
- **`soak30`** stays out of CI (30 min vs the 45-min job budget); runnable
  manually.
