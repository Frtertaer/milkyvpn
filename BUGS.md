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

BUG-2026-09-29-01…12 — Windows-трек, заведены в BUGS.md на ветках
`devin/1790651308-win-app-ux-bugs` / `devin/1790651401-win-app-ux-bugs-port`
(PR #22/#23). Carrier-трек продолжает нумерацию.

## Открытые

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

## Закрытые

_(пока нет — записи переезжают сюда после verified)_
