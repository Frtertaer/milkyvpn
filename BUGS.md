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

## Закрытые

(перенос сюда после merge фикса с регрессионным тестом)
