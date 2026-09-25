# Свой сервер KAL/2 за ~15 минут — пошагово (для чайника)

Нужно: Linux VPS (Ubuntu 22.04/24.04 подойдёт) с белым IP и домен,
указывающий на этот IP (A-запись). Дальше всё по шагам — просто копируйте
команды в SSH-терминал сервера (`ssh root@<ip>`).

## Шаг 0. Домен

В панели вашего DNS сделайте A-запись: `kal.вашдомен.зона → IP сервера`.
Подождите 1–5 минут, проверьте: `ping kal.вашдомен.зона` — должен идти на
IP сервера.

## Шаг 1. Установите бинарник

```bash
mkdir -p /opt/kal2 /etc/kal2
# загрузите dist/kal2-server-linux-x64 на сервер (scp или wget) и:
mv kal2-server-linux-x64 /opt/kal2/kal2-server
chmod +x /opt/kal2/kal2-server
```

## Шаг 2. Сгенерируйте ключи и PSK

```bash
/opt/kal2/kal2-server -keygen
# выведет:
#   priv: <64 hex>   ← секрет сервера, не публикуйте
#   pub:  <64 hex>   ← отдаётся клиентам
```

Придумайте PSK для пользователя: `openssl rand -hex 32` (или тот же
формат 64 hex). Пара `id=psk` задаёт пользователя.

## Шаг 3. Сайт-прикрытие (decoy)

```bash
mkdir -p /var/www/kal2-decoy
echo '<h1>Notes</h1><p>Small personal blog.</p>' > /var/www/kal2-decoy/index.html
```

## Шаг 4. systemd-юнит

`/etc/systemd/system/kal2.service`:

```ini
[Unit]
Description=KAL/2 Mirage core server
After=network.target

[Service]
ExecStart=/opt/kal2/kal2-server \
  -listen 0.0.0.0:443 \
  -domain kal.вашдомен.зона \
  -autocert /etc/kal2/acme \
  -autocert-addr :80 \
  -identity <priv-из-шага-2> \
  -user <имя>=<psk-из-шага-2> \
  -decoy /var/www/kal2-decoy \
  -drift /api/v2/stream \
  -egress-family prefer4
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now kal2
journalctl -u kal2 -f   # смотреть логи
```

Let's Encrypt сам выпустит сертификат по HTTP-01 — порты 80 и 443 должны
быть открыты снаружи (проверьте firewall/VPS-панель).

## Шаг 5. Проверка снаружи

С домашней машины:

```bash
curl https://kal.вашдомен.зона   # должен отдать decoy-сайт
kal2-client -addr <ip>:443 -sni kal.вашдомен.зона \
  -pub <pub> -psk <psk> -drift /api/v2/stream \
  -fetch https://api.ipify.org?format=json
# {"ip":"<ip-сервера>"} — готово
```

## Полезные флаги сервера

| флаг | зачем |
|------|-------|
| `-egress-family dual|prefer4|only4` | исходящие IP: `only4` полностью запрещает v6 (если v6-диапазон VPS «грязный» у CDN) |
| `-upstream socks5://u:p@h:port` | пускать исходящий трафик через другой SOCKS5 (спасает эгресс-репутацию) |
| `-upstream-only chatgpt.com,...` | через upstream только перечисленные домены |
| `-steal 127.0.0.1:8443` | чужое SNI сплайсится на указанный сайт (маскировка) |
| `-user name=psk` (повторяется) | несколько пользователей |

## Отдельный релей (опционально, «домашний вход»)

Если IP сервера заблокируют, поставьте на любой РУ-хост:

```bash
kal2-relay -listen :443 -upstream <ip-сервера>:443
```

Клиенты подключаются `-addr <ip-релея>:443` — трафик идёт внутри РФ до
релея, а дальше прозрачно на сервер. В `-addr` можно перечислить
несколько входов через запятую.
