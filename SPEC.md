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

## 9. Безопасность — кратко

- Взаимная аутентификация: Ed25519-идентичность сервера + per-user PSK.
- PFS: ephemeral X25519 на сессию; low-order отклоняются.
- Replay: монотонный seq + серверный replay-cache первых полётов (10 мин,
  8192) + таймаут полёта + tarpit сканеров (per-IP лимит 16).
- Покрытие: любой несоответствующий трафик получает ответ настоящего
  decoy-сайта — активная проба не отличает сервер от мелкого сайта.

Полная модель угроз — `THREAT_MODEL.md`.
