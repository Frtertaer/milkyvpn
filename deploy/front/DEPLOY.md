# MilkyVPN fronting — фронтинг через whitelisted/edge-домен

`front=` в `pandora://`/`kal2://`-ссылке заставляет HTTP-носители (drift/cdn/mosaic)
звонить не на IP сервера, а на домен фронта — тупой релей в облаке, который
пересылает запросы на plain-HTTP порт сервера. Снаружи это обычный HTTPS к
разрешённому/edge-домену; PSK-авторизация и шифрование Pandora — внутри, релей
ничего не видит и не может открыть.

Когда помогает:
- IP сервера заблокирован волной ТСПУ → фронт на ЛЮБОМ доступном домене.
- Whitelist-режим оператора (беспилотная опасность) → фронт на домене из
  белого списка (Яндекс и т.п.). Это единственный известный обход, и он
  зависит от того, что домен фронта в списке — проверяй на месте.

## 1. Сервер: plain-HTTP порт для фронта

```bash
kal2-server ... -front-listen 0.0.0.0:8081            # один порт
kal2-server ... -front-listen 0.0.0.0:8081,0.0.0.0:8880  # несколько через запятую
```

На нём поднимается тот же mux (drift/mosaic endpoints + decoy 404), без TLS —
TLS живёт на фронте. Тело запросов — зашифрованные kal2-блобы по HMAC-путям,
путь не угадывается. Для паранойи — файрволом резать по egress-диапазонам
облака фронта.

## 2. Развернуть релей (бесплатные варианты)

### A. Yandex Cloud Function — whitelist-grade (free tier: 1M invocations/мес)

```bash
yc serverless function create --name milky-front
zip fn.zip yandex_function.py
yc serverless function version create \
  --function-name milky-front --runtime python312 \
  --entrypoint yandex_function.handler --memory 256m --execution-timeout 60s \
  --environment UPSTREAM=http://<server-ip>:8081 --source-path fn.zip
yc serverless function allow-unauthenticated-invoke --name milky-front
# → https://functions.yandexcloud.net/<id> — это и есть front=
```

Учётка Яндекс.Облака бесплатная, на старте ~4000₽ гранта; функция в free tier
(~1M вызовов/мес) — трафик считается отдельно и дёшев для личного VPN.

Carrier: только `mosaic` (функция буферизует запрос — drift-дуплекс умрёт).

### B. Cloudflare Worker — blocked-IP-grade (100k req/день free)

```bash
npm i -g wrangler && wrangler login
wrangler deploy --name milky-front cloudflare_worker.js \
  --var UPSTREAM:http://<server-hostname>:8880
# → https://milky-front.<acct>.workers.dev
```

Ограничения воркера: `UPSTREAM` обязан быть именем хоста — fetch на голый IP
Cloudflare рубит (error 1003); и порт из разрешённого списка для http://:
80, 8080, 8880, 2052, 2082, 2086, 2095 (для https://: 443, 8443, 2053, 2083,
2087, 2096). Под это выделен `-front-listen 0.0.0.0:8880`.

Workers прозрачно проксируют WebSocket → carriers: `cdn` (WS-drift, стрим) и
`mosaic`. workers.dev НЕ в белых списках — покрывает волны блокировки IP,
но не whitelist-режим.

## 3. Ссылка

```
pandora://<psk>@<server>:443?sni=<domain>&pub=<hex>&carrier=mosaic&front=https%3A%2F%2F<fn-or-worker-url>
```

- `front=` кодируется URL-encoded (внутри `&`/`/`).
- `carrier=mosaic` обязателен для функций (request/response только);
  `cdn` — для WS-фронтов; `auto` также допустим — hedge-диал сам выберет
  живой носитель (veil напрямую vs mosaic через фронт).
- `alt=` работает вместе с `front=`: фронт — ортогональный слой.

## Ограничения

- Raw drift через функции не работает (двунаправленный запрос буферизуется).
- Скорость: +1 хоп и запрос/ответ per-tile — mosaic через фронт медленнее
  прямого drift; это аварийный режим, не основной.
- Фронт видит только: что клиент ходит на его домен (размеры/тайминги HTTPS
  запросов). IP сервера фронту известен (UPSTREAM), но РКН его не видит.
- Гейтвеи функций (проверено на Яндексе) отвергают пути в URL вызова — логический
  путь носителя едет в заголовке `X-Milky-Path`, релей разворачивает его в path
  upstream'а. По той же причине фронт-нога говорит HTTP/1.1 (h2 ALPN в Chrome-
  фингерпринте переписывается, иначе edge отвечает h2-префейсом).
