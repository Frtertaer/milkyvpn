# Mirage core (KAL/2)

Ядро Mirage — реализация протокола KAL/2 на Go: клиент + сервер + релей +
SOCKS5/UDP-эгресс + carriers (veil/drift).

**Здесь два пути:**

- **Просто запустить** (готовые бинарники, ничего собирать не нужно) →
  смотри `dist/` и инструкции `INSTALL_CLIENT_RU.md` (ПК/телефон-клиент) и
  `INSTALL_SERVER_RU.md` (свой сервер за 15 минут).
- **Собрать из исходников** → `milky-core/` (Go-модуль), сборка ниже.

## Что внутри

```
milky-core/        исходники Go-модуля
  cmd/kal2-client  CLI-клиент (SOCKS5 + -fetch)
  cmd/kal2-server  сервер (autocert/decoy/steal/эгресс-политика)
  cmd/kal2-relay   прозрачный релей (домашний входной узел)
  cmd/kal2native   обёртка для мобильной сборки
  internal/        kal2 (протокол), carrier (veil/drift/steal), core (эгресс+socks5)
  pkg/kal2core     встраиваемое Go API
  pkg/kal2mobile   gomobile-фасад (JSON-конфиг, для приложений)
  DESIGN.md, CONSUMING.md
dist/              готовые бинарники (Windows/Linux x64)
```

## Быстрая сборка

```bash
cd milky-core
go build -o kal2-client ./cmd/kal2-client
go build -o kal2-server ./cmd/kal2-server
go build -o kal2-relay  ./cmd/kal2-relay
```

Кросс-сборка под Linux с Windows:

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o kal2-server ./cmd/kal2-server
```

## Быстрый запуск клиента (готовый бинарник)

```bash
kal2-client \
  -addr <ip-сервера>:443 \
  -sni  <ваш-домен> \
  -pub  <ed25519-pub-сервера, hex> \
  -psk  <ваш-PSK> \
  -drift /api/v2/stream \
  -carrier auto \
  -socks 127.0.0.1:10808
```

Потом направьте браузер/приложения на SOCKS5 `127.0.0.1:10808`.

Всё остальное — в `INSTALL_CLIENT_RU.md` (пошагово, для чайника) и
`INSTALL_SERVER_RU.md` (VPS → сертификат → systemd → ключи).
