# KAL/2 — спецификация протокола (wire spec)

Версия протокола: **2** (`Version = 0x02`, magic `KLDO-in-`).
Статус: реализовано в Mirage core (`milky-core/`, эталонная реализация на Go).

KAL/2 — транспорт для обхода цензуры: один TLS- или h2-канал несёт
мультиплексированные зашифрованные потоки с взаимной аутентификацией
(сервер — по Ed25519-ключу, клиент — по PSK). Поверх сессии работают
SOCKS5 (CONNECT + UDP ASSOCIATE) и любой TCP/UDP трафик.

---

## 1. Носители (carriers)

Сессия KAL/2 живёт внутри одного из двух «носителей»:

| Carrier | Транспорт | Что видит DPI |
|---------|-----------|---------------|
| **veil** | TLS 1.3-подобный канал с отпечатком Chrome (uTLS `HelloChrome_Auto`, включая X25519MLKEM768 keyshare, GREASE, ALPS, ECH-grease). SNI = домен сервера. | Обычное HTTPS-подключение к реальному сайту. Чужие SNI/не-KAL байты прозрачно сплайсятся на decoy-сайт (REALITY-style steal). |
| **drift** | HTTP/2 `POST <path>` поверх обычного TLS (Go `x/net/http2`). Тело — поток KAL-записей. Path задаётся ключом от PSK. | Длинный HTTP/2 POST к сайту; может стоять за любым h2-совместимым CDN/edge. |

`carrier = auto` на клиенте запускает оба параллельно (hedged dial) и берёт
тот, что поднялся первым; проигравший отменяется.

**Channel binding**: когда носитель — TLS, в ключевое расписание мешается
TLS exporter (RFC 9266) — внутренняя сессия криптографически привязана к
именно этому TLS-сеансу (анти-MitM/relay).

## 2. Рукопожатие

Обмен «клиентский полёт → серверный полёт», затем готовые AEAD-ключи.

### Клиентский полёт

```
magic[8]        = "KLDO-in-"
version[1]      = 0x02
clientEph[32]   = X25519 ephemeral public
preauth[32]     = HMAC-SHA256(psk, labelClientPreauth || magic || version || clientEph || binding?)
padLen[2, LE]   = 0..512
pad[padLen]     = случайные байты (не в транскрипте)
```

Размер минимального полёта — 75 байт + паддинг. Сервер парсит строго:
неверный magic → ответ как decoy-сайт; неверная версия/preauth →
покрытое поведение (не «отказ KAL-сервера»).

### Серверный полёт

```
serverEph[32]   = X25519 ephemeral public
signature[64]   = Ed25519(serverIdentity, HKDF(labelServerSig, salt, transcript, 32))
```

Сервер проверяет preauth (constant-time), считает shared =
X25519(serverEphPriv, clientEph), отклоняет low-order точки.

### Транскрипт и ключи

```
transcript = magic || version || clientEph || serverEph
salt       = shared                        (binding пуст)
           = HMAC-SHA256(labelExporterBind, shared || binding)  (иначе)
```

HKDF-SHA256(ikm = salt, salt = SHA256(transcript), info =
`mxs-in-v2/transcript/<label>/<transcript>`) выводит:

| label | назначение |
|-------|-----------|
| `mxs-in-v2/record/client` | клиентский record-ключ (32B, ChaCha20-Poly1305) |
| `mxs-in-v2/record/server` | серверный record-ключ |
| `mxs-in-v2/nonce-base` | база nonce (8B) |
| `mxs-in-v2/handshake-verify` | finished-проверка |
| `mxs-in-v2/client-preauth`, `server-sig-input`, `finished`, `exporter-bind` | служебные |

Nonce записи = `nonce-base[8] || seq[8, BE]` ⊕ / concat как в эталонной
реализации; `seq` монотонен на направление, повтор/внепорядок = `ErrReplay`
→ разрыв сессии.

## 3. Записи (records)

Сессия — поток записей. Заголовок 17 байт = AEAD additional data (в открытом
виде), тело — ChaCha20-Poly1305 ciphertext.

```
type[1]      — тип сообщения
seq[8, BE]   — монотонный счётчик (replay window: строго по порядку)
streamID[4, BE] — мультиплексированный поток (0 = контрольный)
ctLen[4, BE] — длина ciphertext
ct[ctLen]    = AEAD(payload || padLen[2,LE] || pad[padLen])
```

**Паддинг**: `payload || padLen || pad` добивается до кратного 256
(`PadBucketSize`), с вероятностью 1/2 — ещё один бакет сверху
(`MaxPadBucketsAbove = 1`). Макс. payload — 64 КиБ.

### Типы

| код | имя | смысл |
|-----|-----|-------|
| 0x01 | OPEN | открыть поток; payload = цель (см. §4) |
| 0x02 | DATA | данные потока (упорядоченная доставка) |
| 0x03 | CLOSE | закрытие; payload = причина |
| 0x04 | PING | liveness/замер пути |
| 0x05 | PONG | ответ на PING |
| 0x06 | MIGRATE | зарезервировано |
| 0x07 | RST | аварийный разрыв потока |
| 0x08 | OPEN_ACK | результат dial на сервере; payload = код (0x00 ок, 0x05 отказ) |
| 0x09 | CHALLENGE | зарезервировано (anti-replay расширение) |

## 4. Цель OPEN (SOCKS5-подобный адрес)

v1 (TCP подразумевается):
```
atyp[1] = 0x01 IPv4 | 0x03 domain | 0x04 IPv6
(domain: +len[1])
host, port[2, BE]
```

v2 (явная сеть): `atyp | 0x80`, затем `netTag` = `'t'` (tcp) или `'u'` (udp),
далее как v1. Маркер 0x80 позволяет старым серверам отвергать чисто.

## 5. UDP-потоки

На открытом `netTag='u'` потоке каждая дейтаграмма кадрируется:
`len[2,LE] || atyp || addr || port || payload`. Сервер держит wildcard
UDP-сокет и возвращает адрес фактического источника в ответном кадре.
Это — путь для QUIC/HTTP3 и DNS поверх KAL/2 (через SOCKS5 UDP ASSOCIATE).

## 6. Мультиплексирование и потоки

- Клиент открывает нечётные ID (`nextID += 2`), сервер — чётные.
- На поток: per-stream приёмная очередь (cap 256), DATA строго упорядочены
  линией данных; CLOSE едет по той же линии (нельзя обогнать DATA).
- Глобальные очереди: dataCh 1024, ctrlCh 512, streamQueueMax 512 записей.
- Сервер по OPEN делает исходящее соединение и отвечает OPEN_ACK.
- RST/таймаут открытия освобождает слот (см. реализацию — утечка слотов
  исправлена в d3de5a0).

## 7. Эгресс и серверная политика

Флаги сервера (`kal2-server`):

| флаг | смысл |
|------|-------|
| `-egress-family dual|prefer4|only4` | семейство исходящих IP (only4 запрещает любой v6 — против «грязного» v6-диапазона хостера) |
| `-upstream socks5://[u:p@]h:p` | цепочка исходящих через SOCKS5 (remote DNS) |
| `-upstream-only dom1,dom2` | через upstream только эти суффиксы доменов |
| `-steal host:port` | сплайс чужого SNI на decoy-апстрим |
| `-decoy dir` | статика прикрытия для не-KAL запросов |

## 8. Мульт-эндпоинты и переподключение

`-addr a,b,c` — список эндпоинтов (IP сервера, домашний релей `kal2-relay`,
CDN edge для drift). Dial ротирует список; watchdog переподключается с
backoff+jitter (cap 30с) и восстанавливает SOCKS-листенер.

## 9. Возобновление и миграция сессии (v2.1)

Цель: потеря транспорта (RST от ТСПУ, роуминг Wi-Fi↔LTE, смена endpoint)
не должна рвать SOCKS5-соединения локальных приложений. Клиент
перезванивает — возможно, другим carrier'ом и другим endpoint — и
**возобновляет ту же сессию**: таблица потоков переживает своп носителя,
недоставленные DATA переигрываются из чекпоинта.

### 9.1 Resume-секрет и тикет

После хендшейка выводится отдельный секрет:

```
resumeSecret = HKDF(salt, transcript, "mxs-in-v2/resume-secret", 32)
```

Он доказывает владение сессией, но не является traffic-ключом — украденный
тикет не расшифровывает записанный ранее трафик (PFS сохраняется).

Сервер периодически (и при первом полёте) присылает запись `TICKET`
(0x0A, поток 0):

```
payload = sessionID[8] || ticketLen[2,LE] || ticket[ticketLen]

ticketPlain (внутри AEAD):
  version[1]   = 0x01
  sessionID[8]
  userID[16]   — идентификатор per-user PSK (тикет жёстко к юзеру)
  expires[4,BE unix]
  flags[1]     — bit0: migration между carriers разрешена
  resumeSecret[32]

ticket = ChaCha20-Poly1305(ticketKey, ticketPlain)
```

`ticketKey` — серверный ротируемый ключ (T-rotation 24h, старое поколение
принимается ещё 24h). Клиенту тикет **непрозрачен**; sessionID
выносится отдельным полем, чтобы клиент мог его эхом вернуть.
Тикеты одноразовые: сервер кэширует принятые ticketID до их expiry
(переиспользование тикета → отказ как replay).

### 9.2 Полёт возобновления

На новом транспорте клиент шлёт вместо `KLDO-in-` полёт:

```
magic[8]      = "KLDO-rs-"
version[1]    = 0x02
sessionID[8]
clientEph[32]
ticketLen[2,LE] || ticket[ticketLen]
resumePreauth[32] = HMAC-SHA256(resumeSecret,
                    "mxs-in-v2/resume-preauth" || magic || version ||
                    sessionID || clientEph || ticket || binding?)
checkpoint:  lastRecvSeq[8] || nStreams[2,LE] ||
             { streamID[4], flags[1] }*   (flags bit0 = write-сторона закрыта)
```

Сервер: AEAD-открытие тикета → проверка expiry/userID/one-time →
проверка resumePreauth (constant-time) → shared2 =
X25519(serverEphPriv, clientEph). Серверный полёт тот же, что в §2
(`serverEph || signature`), но подпись считается по transcript2.

### 9.3 Re-key возобновлённой сессии

```
transcript2 = "KLDO-rs-" || version || sessionID || clientEph || serverEph
salt2       = HMAC-SHA256(labelExporterBind, shared2 || binding2 || resumeSecret)
```

Record-ключи выводятся тем же расписанием меток, но из `(salt2,
transcript2)` — новые эфемерные ключи на каждое возобновление.
Счётчики seq каждого направления **продолжаются** с чекпоинта
(переустановка на 0 запрещена — иначе nonce reuse).

### 9.4 Синхронизация потоков — MIGRATE (0x06)

Первой записью после resume-хендшейка каждая сторона шлёт MIGRATE
(поток 0):

```
payload = lastRecvSeq[8] || nStreams[2,LE] ||
          { streamID[4], flags[1] }*   — снапшот живых потоков
```

Правила примирения:

1. Все записи, влияющие на состояние потоков (OPEN/DATA/CLOSE/RST/
   OPEN_ACK), с seq > peer lastRecvSeq переигрываются в исходном порядке.
   PING/PONG не переигрываются.
2. Поток есть у пира, но нет локально → RST (peer чистит мёртвый слот).
3. Поток есть локально, но нет у пира → локальная сторона закрывает
   чтение и шлёт RST.
4. Дублированные DATA (seq ≤ lastRecvSeq, но пришедшие повторно)
   отбрасываются молча — защита от гонки «старое соединение ещё живо».

SOCKS5-листенер и локальные соединения не затрагиваются никогда:
миграция — чисто внутренняя операция сессии.

### 9.5 Ограничения

- Тикет TTL ≤ 72h; рекомендуемый 24h. Перевыпуск каждые ≤TTL/2.
- Resume-попытки учитываются в tarpit/per-IP лимите наравне с
  first-flight.
- Сервер вправе отказать в возобновлении (истёк, неизвестен,
  запретная смена юзера) — клиент обязан откатиться на полный
  `KLDO-in-` полёт **без** убийства SOCKS-листенера (потоки тогда
  пересоздаются по требованию: OPEN намертво занятых id считается
  ошибкой, приложение увидит connect reset на новых сессиях, живые —
  уже мёртвы и честно репортятся).

## 10. Подписанные дескрипторы носителей (v2.1)

Серверная идентичность подписывает короткоживущий дескриптор — список
эндпоинтов с их carrier-профилями. Клиент верит дескриптору только если
подпись сходится с pinned `pub` сервера и не истёк TTL: подмена
endpoint-листа прослушивателем невозможна без Ed25519-ключа сервера.

### 10.1 Формат

```
descriptorPlain =
  version[1] = 0x01
  expires[4,BE unix]
  serverPub[32]              — Ed25519 identity (pin)
  nEndpoints[1]
  endpoints[] = {
    addrLen[1] addr[addrLen]          — домен или IP-литерал
    port[2,BE]
    carriers[1] bitmap: bit0 veil, bit1 drift, bit2 cdn, bit3 mosaic
    sniLen[1] sni[sniLen]
    echLen[1] ech[echLen]             — ECHConfigList, может быть пустым
    flags[1]                          — bit0: preferred, bit1: relay-hop
  }
signature[64] = Ed25519(serverIdentity, "kal2-desc-v1" || descriptorPlain)
descriptor = descriptorPlain || signature
```

Wire-перенос: base64url(descriptor) в параметре `cd=` ссылки `kal2://`,
или полем `cd` в JSON-подписке.

### 10.2 Рандеву без энумерации

Сервер периодически (эпоха = 6 часов) публикует свежий дескриптор по
детерминированному пути, вычислимому только владельцем PSK:

```
epoch = unix / 21600
path  = "/r/" + hex16(HMAC-SHA256(psk, "kal2-rdvs/" || epoch))
```

Клиент опрашивает текущую и предыдущую эпоху обычным GET поверх любого
доступного транспорта (прямой veil/pin, CDN-фронт, drift endpoint):
успех → обновление endpoint-листа; 404 в обеих эпохах → работать по
текущему дескриптору до истечения. Сканер без PSK не может отличить
«существующий ключевой путь» от любого другого 404 — энумерация
закрыта, а fetch выглядит обычным API-вызовом.

Ротация эндпоинтов (сгоревший IP → новый relay/CDN edge) сводится к
перевыпуску подписанного дескриптора — ссылки пользователей не меняются.

## 11. Формальный анализ безопасности

### 11.1 Ключевое расписание — что к чему привязано

| выход | чем доказывается |
|-------|------------------|
| `client-preauth` | владение PSK **до** любого KAL-байта сервера |
| `server-sig-input` → Ed25519 | владение identity-ключом, подпись накрывает transcript (eph-пара от этого полёта) |
| `exporter-bind` в salt | криптографическая привязка к конкретному TLS-сеансу носителя (RFC 9266); носитель без binding → binding=∅ |
| `record/{client,server}` | разделение направлений, одна сессия не переиспользует ключ другой |
| `nonce-base` + монотонный seq | nonce уникален на (направление, seq) — AEAD-безопасность |
| `resume-secret` | дериват не-трафик-секрета: тикет-кража ≠ расшифровка истории |

Инвариант: любые две сессии имеют разные transcript (эфемерные ключи
рандомны) → разные record-ключи. Пересечение сессий (cross-session
key reuse) исключено конструкцией.

### 11.2 Свойства

- **PFS**: ephemeral X25519 per session и per resumption; компрометация
  долгоживущего PSK/identity-ключа не открывает записанный трафик.
- **Взаимная аутентификация**: сервер — Ed25519-подписью транскрипта,
  клиент — HMAC-PSK preauth.
- **Anti-downgrade**: `version` входит в transcript и в preauth;
  старые версии сервер отвечает покрытым поведением, а не ошибкой.
- **Replay**: (а) серверный replay-cache первых полётов (10 мин, 8192);
  (б) монотонные seq записей с strict-order приёмом; (в) одноразовые
  тикеты с кэшем использованных ID до expiry; (г) MIGRATE-чекпоинт
  исключает повторную обработку данных.
- **Сопротивление активным пробам**: до корректной magic+preauth сервер
  не испускает ни байта протокола — весь чужой трафик получает ответы
  decoy-сайта (steal-splice), различия в поведении у пробы нет.
- **Сопротивление DPI-классификации**: ротируемый ClientHello
  (несколько Chrome-пресетов incl. PQ-keyshare), per-session бакеты
  паддинга, cover-трафик с джиттером; статистические сигнатуры —
  признанная остаточная поверхность (см. THREAT_MODEL).
- **Сопротивление энумерации**: keyed drift-path и keyed rendezvous
  делают обнаружение дверей невозможным без PSK.

### 11.3 Остаточные риски (честные границы)

- Украденный **непросроченный тикет** = угон сессии в пределах TTL
  (митигация: одноразовость, короткий TTL, привязка к userID).
- Украденный PSK = полная имперсонация клиента и чтение rendezvous —
  per-user PSK ограничивает радиус поражения.
- Пассивный наблюдатель с доступом к обеим сторонам канала может
  коррелировать объёмы/тайминги — вне модели (см. THREAT_MODEL).

## 12. Матрица версий и совместимость

| Возможность | v2 (Version=0x02) | v2.1 |
|---|---|---|
| first flight, записи, потоки, veil/drift/cdn/mosaic | ✓ | ✓ |
| TICKET + `KLDO-rs-` + MIGRATE | — | ✓ |
| подписанные дескрипторы, rendezvous | — | ✓ |

Правила мешанины:
- v2-сервер, встретив `KLDO-rs-`, ведёт себя как при неверном magic →
  decoy-ответ. v2.1-клиент обязан откатиться на полный полёт.
- v2.1-клиент без тикета (сервер не прислал TICKET) ведёт себя как
  v2: reconnect = полный хендшейк.
- Неизвестные типы записей игнорируются (forward-compat) кроме
  диапазона ≥0x80 (обязательные → разрыв сессии).

Конформанс-векторы — `testdata/`: golden handshake transcripts,
record-encodings, OPEN-target, дескрипторы, resume-полёт, MIGRATE.
