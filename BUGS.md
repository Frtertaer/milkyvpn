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

### BUG-2026-09-29-13 — mux: конкурентные Ping гонятся за pongReg → ложный pong-timeout
- Severity: major (сторож lanes читает таймаут как смерть lane →
  ложный kill живого лейна; под -race — data race на поле сессии)
- Platform: core (kal2 mux — все платформы, все lanes-клиенты)
- Status: fixed-in-PR
- Repro: `client.Ping(...)` из двух+ горутин одновременно:
  `registerPong` без синхронизации перезаписывает `s.pongReg` — второй
  caller перехватывает канал ответа, первый получает `pong timeout`
  на живой сессии. `go test -race` — гонка readLoop(dispatch/pongCh) ×
  Ping(registerPong/unregisterPong)
- Fix: `pongQ []chan []byte` — FIFO-очередь waiters под `pongMu`;
  каждый входящий PONG удовлетворяет самый старый ожидающий Ping
  (упорядоченный carrier возвращает эхо в порядке запросов)
- Found by: carrier-track stress session (recon + repro-тест)
- Issue: —  PR: —  Regression test:
  `milky-core/internal/kal2/stress_test.go::TestMuxConcurrentPings`

### BUG-2026-09-29-14 — lanes: задушенный lane собирает все новые стримы
  (kill-vs-quarantine инверсия)
- Severity: major (scorecard-контракт нарушен: живой-но-задушенный lane
  не подпадает под kill-путь — pong приходит — но монополизирует роутинг)
- Platform: core (kal2core Client lanes)
- Status: fixed-in-PR
- Repro: два lanes: здоровый и задушенный (pong приходит, но медленно).
  `Session()` выбирал least-`SentBytes` → у задушенного почти нет emitted
  байт → он выглядит «свежим» и получает ВСЕ новые стримы, ползая на
  черепашьей скорости, пока здоровый простаивает
- Fix: `laneRTT` scorecard — сторож записывает RTT последнего успешного
  pong на lane; `Session()` пропускает lanes с `laneRTT > laneQuarantineRTT`
  (3s), пока жив хотя бы один здоровый; все задушены → fallback на
  least-loaded. Убитый lane (2 реальных ping-фейла) kill'ается и
  редиалится как раньше — kill-vs-quarantine разведены
- Found by: carrier-track stress session (contract review + repro-тест)
- Issue: —  PR: —  Regression test:
  `milky-core/pkg/kal2core/lanes_test.go::TestLaneStrangledQuarantinedNotKilled`,
  `TestLaneDeadKilledAndRedialed`, `TestLaneAllQuarantinedFallback`

### BUG-2026-09-29-15 — mux: карта streams течёт на remote close
- Severity: major (unbounded leak: долгоживущая сессия накапливает zombie-
  entry на каждый закрытый пиром стрим → рост RSS на длинном soak'е;
  15-мин -race soak был убит OOM-киллером через ~6.5 мин)
- Platform: core (kal2 mux — все платформы)
- Status: fixed-in-PR
- Repro: пир закрывает стрим (`MsgClose`) или сбрасывает (`MsgRst`):
  `remoteClose()`/`reset()` помечали stream closed, но НИКОГДА не удаляли
  запись из `s.streams`. Локальный `Stream.Close()` удалял — удалённый
  конец нет. Server-side за churn-прогон скапливал по записи на стрим
- Fix: evict в терминальной точке жизненного цикла — pump удаляет запись
  после EOF-дрейна (graceful), `reset()` удаляет немедленно (abrupt);
  half-close ordering сохранён (данные до MsgClose доставляются)
- Found by: carrier-track mux -race soak (killed at ~395s) + map audit
- Issue: —  PR: —  Regression test:
  `milky-core/internal/kal2/stress_test.go::TestMuxRemoteCloseEvicts`

### BUG-2026-09-29-16 — mux: SetReadDeadline/SetWriteDeadline были no-op
- Severity: major (net.Conn-контракт сломан: любой код, полагающийся на
  deadline — SOCKS idle timeout, churn-читатели — блокируется навсегда;
  15-мин soak завис именно так: ReadFull в churn-воркере никогда не
  возвращался)
- Platform: core (kal2 mux — все платформы)
- Status: fixed-in-PR
- Repro: `st.SetReadDeadline(now+300ms); st.Read(buf)` без входящих данных
  → блок навсегда вместо timeout-ошибки; `SetWriteDeadline` + переполненная
  data-lane → блок навсегда на slot-токене
- Fix: `readDeadline`/`writeDeadline` (atomic ns) на stream; Read ждёт
  recvCh/closedCh/timer → `os.ErrDeadlineExceeded`; Write гонит чанки через
  `sendRecordDeadline` — timeout-селект на slot/ctrlCh enqueue
- Found by: carrier-track mux -race soak (hang at ~20m dump)
- Issue: —  PR: —  Regression test:
  `milky-core/internal/kal2/stress_test.go::TestMuxReadDeadlineReal`,
  `TestMuxWriteDeadlineReal`

### BUG-2026-09-29-17 — carrier tests: VeilListener logf вызывал t.Logf после конца теста
- Severity: minor (test-only data race: `-race` FAIL на пакете carrier;
  per-conn goroutine `v.Serve` переживает `tRunner`, лог ловит гонку на
  testing internals / может паниковать «Log after test completed»)
- Platform: core (test harness — internal/carrier e2e helpers)
- Status: fixed-in-PR
- Repro: `go test -race ./internal/carrier` — фоновый TLS-handshake
  handler логирует через `VeilConfig.Logf → t.Logf` после завершения
  теста (детектed на TestVeilSPKIPin teardown × late conn goroutine)
- Fix: `newTestServerWith` буферит строки лога под мьютексом и флашит
  через `t.Log` внутри `t.Cleanup` (пока t валиден); поздние строки дроп
- Found by: carrier-track `go test -race` suite rerun после merge universal
- Issue: —  PR: —  Regression test: `go test -race ./internal/carrier/`
  (ранее флаковал DATA RACE на testing.(*common).destination)

## Закрытые

(перенос сюда после merge фикса с регрессионным тестом)
