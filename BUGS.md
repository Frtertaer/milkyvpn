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

## Трек PROTOCOL — conformance SPEC v2.1

### BUG-2026-09-29-13 — vectors.json: ключевой материал выведен не по формуле §2

- **Severity:** High (test oracle)
- **Platform:** all
- **Status:** FIXED (spec-side)
- **Found by:** `TestVectorHandshakeKeys` / `TestVectorFlights`
- **Issue:** в testdata/vectors.json все HKDF-производные (signature,
  clientRecordKey, serverRecordKey, nonceBase, handshakeVerify, finished,
  resumeSecret, record ciphertext, resume.*, ticket) вычислены с
  `info = mxs-in-v2/transcript/<label>` — без суффикса `/<transcript>`,
  который прямо записан в §2 (`info = mxs-in-v2/transcript/<label>/<transcript>`).
  Реализация соответствует тексту спеки → вектор-файл был непригоден как
  conformance-оракул (любая корректная реализация «не проходила» его).
- **Fix:** `milky-core/cmd/genvec` — генератор векторов по формулам спеки
  (восстановлен удалённый «временный» генератор); vectors.json регенерирован.
  Дескриптор/openTargets/transcript/preauth/migrate совпали байт-в-байт.
- **PR:** spec-side PR в `devin/1790623610-kal2-spec-v2`
- **Regression test:** conformance_test.go — все `keys.*` сверяются с
  спек-формулой в тестовом коде (независимая реализация HKDF).

### BUG-2026-09-29-14 — vectors.json: ticketLen закодирован big-endian

- **Severity:** Medium (test oracle)
- **Status:** FIXED (spec-side)
- **Issue:** `resume.resumeFlight` содержит `ticketLen = 0x004e` (BE 78),
  спека §9.2 требует `[2,LE]` (`0x4e00`). Код PR #7 (`ParseResumeHead`)
  читает LE — вектор непарсабелен спек-имплементацией.
- **Fix:** регенерация vectors.json с LE.
- **Regression test:** `TestVectorResume` — парсинг полёта по LE.

### BUG-2026-09-29-15 — спека §3: порядок payload/padLen/pad в тексте неверен

- **Severity:** Medium (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** текст §3: `ct = AEAD(payload || padLen[2,LE] || pad[padLen])`.
  Имплементация и вектор кладут длину **в конец**: `payload || pad || padLen`.
  Реальное значение несовместимо с текстом.
- **Fix:** правка SPEC.md §3 (spec-side PR).
- **Regression test:** `TestVectorRecord` — impl дешифрует векторную запись.

### BUG-2026-09-29-16 — спека §9.2/9.4: nStreams помечен LE, вектор+код — BE

- **Severity:** Low (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** `nStreams[2,LE]` в тексте против BE в vectors.json
  (`migrate.payload`) и коде PR #7 (checkpoint). Весь wire-формат BE —
  правим текст, не байты.
- **Fix:** SPEC.md §9.2, §9.4 → `[2,BE]`/`[4,BE]`.
- **Regression test:** `TestVectorResume`/`TestVectorMigrate` — BE-парсинг.

### BUG-2026-09-29-17 — неизвестные типы записей <0x80 убивали сессию

- **Severity:** High (forward-compat)
- **Status:** FIXED (code)
- **Issue:** `readRecord` возвращал `ErrFraming` на любой неизвестный тип →
  v2.1-записи (TICKET 0x0A, будущие <0x80) рвали v2-сессию. §12 требует:
  <0x80 — пропускать (AEAD+seq-учёт сохраняется), ≥0x80 — разрыв.
- **Fix:** `session.go` — пропуск неизвестных <0x80 после AEAD-open;
  `protocol.go` — `MsgTicket = 0x0A`.
- **PR:** code PR → `devin/1790199091-kal2-universal-subscriptions`
- **Regression test:** `TestForwardCompatTypes` (0x40/0x0A skip, 0x81 kill).

### BUG-2026-09-29-18 — bound-клиент против unbound-сервера: разрыв вместо фолбэка

- **Severity:** High (interop, проверка (d))
- **Status:** FIXED (code)
- **Issue:** клиент всегда биндил к TLS-exporter; сервер с `binding=∅`
  (спека: «носитель без binding → binding=∅») выдавал signature/handshake
  mismatch → разрыв. Фолбэка на клиенте не было вовсе.
- **Fix:** `ClientConfig.AllowUnboundFallback` (opt-in, дефолт строгий —
  иначе stripping-MitM мог бы молча понизить binding) — один redial
  unbound при падении KAL/2-рукопожатия; `VeilConfig.IgnoreBinding` —
  серверный unbound-режим для смешанных флитов.
- **Regression test:** `TestDialVeilBoundClientUnboundServer`,
  `TestDialVeilUnboundClient` (tolerant / RequireBinding).

### BUG-2026-09-29-19 — §9/§10: resumption/migration и descriptor-публикация не реализованы на impl-ветке

- **Severity:** High (feature gap; проверки (b-resumption), (c), (e-server))
- **Status:** fixed-in-PR #7 (merged) для resumption/migration —
  resume.go, TICKET/MIGRATE, `ResumeAttach`, freeze/migGate/replay
  присутствуют на базе; проверки (b-resumption), (c) выполняются там.
  Остаётся OPEN: §10 server-publish/fetch descriptor'ов (rendezvous
  серверная часть) нигде не реализована.
- **Частично закрыто здесь:** `descriptor.go` — §10.1 парсер (подпись/pin/TTL)
  + `RendezvousPath` (§10.2 keyed path) + тесты против векторов; билет-
  формат и re-key проверены `TestVectorResume` по спек-формулам.

### BUG-2026-09-29-20 — спека: третий полёт (ClientAuthFlight) не описан; §10.2 epoch-энкодинг не определён

- **Severity:** Low (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** impl шлёт `pskMAC(32) || finished(32)` после server flight —
  в §2 не задокументировано; `epoch` в `kal2-rdvs/` || epoch без типа
  сериализации. Обе дыры делают cross-impl conformance недетерминированным.
- **Fix:** SPEC.md — описание третьего полёта + `epoch` как десятичное ASCII.
