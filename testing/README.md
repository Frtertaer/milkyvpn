# testing/ — MilkyVPN test stand

Эмуляторная матрица и сценарии живучести для KAL/2.

## Состав

| Файл | Что делает |
|---|---|
| `scenarios.sh` | Android-эмулятор: коннект, Wi-Fi↔LTE, потеря сети, смена DNS, DNS-leak, TLS-cutoff, soak 30 мин, FGS/doze |
| `desktop_headless.sh` | Linux/macOS/Windows headless: handshake-бюджет, SOCKS-liveness, обрыв потока TSPU + восстановление, DNS/egress, soak |
| `ios_sim.sh` | iOS Simulator: build+install+launch приложения, лог-проба (только macOS) |
| `../.github/workflows/android-emu-matrix.yml` | CI-матрица API 26/29/31/34/35, сценарная батарея на каждом уровне |

## Использование

```bash
# Android (эмулятор уже загружен)
./testing/scenarios.sh --apk build/app/outputs/flutter-apk/app-debug.apk \
  --serial emulator-5554 --scenario connect        # или wifi_lte / net_loss / ...

# Desktop (с любой машины, достаточно go + curl)
./testing/desktop_headless.sh --link 'kal2://<psk>@<addr>?sni=..&pub=..' --scenario all

# iOS (macOS + Xcode)
KAL2_TEST_LINK='kal2://...' ./testing/ios_sim.sh 'iPhone 15'
```

`KAL2_TEST_LINK` — тестовый `kal2://` профиль. В CI лежит в `secrets.KAL2_TEST_LINK`.

## Сценарии

- **connect** — handshake ≤ бюджет, туннельный выход != прямой
- **wifi_lte / net_loss** — эмулятор `svc wifi`/`svc data`: сессия должна пережить переключение носителя и вернуться после blackout
- **dns_change / dns_leak** — private_dns переключение; снимок резолвера для ручной проверки
- **tls_cutoff** — поток через cut-proxy (truncate > N bytes); watchdog должен поднять свежую сессию
- **fgs_doze** — `deviceidle force-idle`, `:kal2` сервис остаётся в FG
- **soak30** — 30 мин под нагрузкой cover-трафиком
