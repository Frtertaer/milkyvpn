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
- Status: open
- Repro: любой сбой `kal2-client.exe` — stderr проглатывается родителем,
  в `%APPDATA%\homes.milky\milkyvpn` логов нет
- Found by: windows-track verification session
- Issue: —  PR: —  Regression test: —

### BUG-2026-09-29-03 — Windows: silent-переустановка убивает живой туннель
- Severity: minor
- Platform: windows
- Status: open
- Repro: при активном соединении запустить `MilkyVPN-Setup.exe /VERYSILENT`
  → taskkill по kal2-client без drain'а сессий
- Found by: windows-track verification session

## Закрытые

(перенос сюда после merge фикса с регрессионным тестом)
