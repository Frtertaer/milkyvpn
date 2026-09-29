# MilkyVPN

> VPN, которому не нужен «список протоколов, которые уже заблокировали».

Клиент на подписку Milky (`https://sub.milky.homes/s/{token}`): Flutter UI + нативный VPN-сервис. По умолчанию ездит на **собственном протоколе Pandora** (`milky-core`, Go; внутреннее имя кодовой базы — KAL/2) — спроектирован под враждебные сети с активным DPI/ТСПУ: маскировка под обычный HTTPS, автоматический обход деградации, живая сессия при смене сети. Xray-core остаётся запасным движком для внешних профилей (VLESS/Reality, Hysteria2, XHTTP).

## Скачать

| Платформа | Файл | Скачать |
|---|---|---|
| Android (arm64 — большинство телефонов) | `MilkyVPN-android-arm64-v8a.apk` | [⬇ Скачать](../../releases/latest/download/MilkyVPN-android-arm64-v8a.apk) |
| Android (32-бит / старые телефоны, API 24+) | `MilkyVPN-android-armeabi-v7a.apk` | [⬇ Скачать](../../releases/latest/download/MilkyVPN-android-armeabi-v7a.apk) |
| Android (эмулятор/x86) | `MilkyVPN-android-x86_64.apk` | [⬇ Скачать](../../releases/latest/download/MilkyVPN-android-x86_64.apk) |
| Windows 10/11 x64 (установщик, без админа) | `MilkyVPN-Setup.exe` | [⬇ Скачать](../../releases/latest/download/MilkyVPN-Setup.exe) |

iOS и macOS — в активной доводке (см. `BUGS.md`); сборки появятся в [Releases](https://github.com/Frtertaer/milkyvpn/releases).

## Почему Pandora, а не очередной VPN-протокол

| | **Pandora** | Hysteria2 | VLESS+Reality | WireGuard | OpenVPN |
|---|---|---|---|---|---|
| Транспорт | TCP **и** UDP (выбор карьера) | только UDP | только TCP | только UDP | TCP/UDP |
| UDP-полисинг глушит | нет — TCP-карьеры | **да, полностью** | нет | **да, полностью** | да (UDP) |
| Ответ на активную пробу | настоящий decoy-сайт | отбой | чужой сайт (steal) | нет | нет |
| Отпечаток TLS | uTLS Chrome + **ECH** | QUIC (браузерный) | Chrome/FF | своя сигнатура | своя сигнатура |
| Протокольная блокировка в РФ (2023–25) | не детектируется | DPI видит QUIC | частично | **да, заблокирован ТСПУ** | **да, заблокирован ТСПУ** |
| Выживание при смене сети | миграция сессии без разрыва стримов | переподключение | переподключение | переподключение | переподключение |
| Запасной путь при деградации | авто-failover veil→mosaic→cdn→drift + score-quarantine | нет | нет | нет | нет |
| Замедление «толстого» потока для интерактива | SFQ-планировщик записи | stream-мультиплекс | нет | — | — |
| Параллельные линии к одному выходу | lanes-пул (least-loaded) | — | — | — | — |
| Запас при полном убийстве UDP | quasar (KCP+AEAD+FEC) — запасной карьер | сам такой | — | — | — |

Ключевая разница: **один протокол = несколько взаимозаменяемых карьеров**. Хендшейк и ключи общие; когда сеть режет один вид транспорта, сессия переезжает на другой карьер без разрыва ваших соединений.

### Измерено, а не обещано

Путь RU→US, входящий UDP на краю полисится 25–85% потерь (типичное «тревожное» состояние сети):

| метрика | Pandora cdn+lanes=4 | hy2 |
|---|---|---|
| dl US 256MB | **10.7–11.1 MB/s** | 0.03–5.6 MB/s |
| dl Cloudflare 20MB | **6.9–9.3 MB/s** | 0.02–0.18 MB/s |
| TTFB медиана | **0.31–0.37 s** | 0.66–2.18 s |
| LUL p50/p95 (пробы под нагрузкой) | **0–0.33 / 0.36–0.77 s** | 0.58–1.76 / 0.94–3.78 s |

Тот же стенд на чистом пути (UDP не тронут): Pandora veil **18.3–22.8 MB/s** против hy2 13.9–18.2 MB/s — обгон даже без полисинга. Методика и сырые таблицы — в PR [#15](https://github.com/Frtertaer/milkyvpn/pull/15).

### Сколько стоит замедление

Что реально теряется под ТСПУ-полисингом/блокировкой (тариф-эквивалент: 600 ₽/мес за 100 Мбит):

| | Pandora | Hysteria2 | VLESS+Reality | WireGuard | OpenVPN |
|---|---|---|---|---|---|
| Доля полосы под полисингом | ~50–90% | ~0–30% | ~50–80% | **0%** | **0%** |
| Потеря за месяц | ~60–300 ₽ | ~420–600 ₽ | ~120–300 ₽ | **весь тариф** | **весь тариф** |
| Полная блокировка | нужен только смена карьера (бесплатно) | смена сервера/протокола | частично спасает steal-сайт | переезд на другой протокол | переезд на другой протокол |
| Стоимость восстановления после блока | 0 ₽ (переключение в настройках) | ~300–500 ₽/мес за новый VPN или VPS | 0–500 ₽ | ~300–500 ₽/мес | ~300–500 ₽/мес |

Цифры Pandora и hy2 — измерения на нашем стенде; остальные — оценка по открытым отчётам о протокольных блокировках РФ (OpenVPN/WireGuard/IKEv2 режутся ТСПУ на уровне протокола с 2023–2025). Pandora выигрывает именно там, где остальные умирают: задушенный UDP → TCP-карьер, убитый длинный поток → mosaic-плитки, мёртвый lane → пересадка без разрыва.

### Карьеры (carriers)

| Карьер | Вид трафика | Когда нужен |
|---|---|---|
| `veil` | TLS-стрим с ECH, ответы decoy-сайта | по умолчанию — быстрый и незаметный |
| `drift` | долгоживущий HTTP-туннель | сети, режущие «лишний» TLS |
| `cdn` | через edge-кэш CDN | самые жёсткие фильтры: egress через IP CDN |
| `mosaic` | сессия, нарезанная на короткие HTTPS-плитки | per-flow cutoff: длинные соединения режут |
| `quasar` | UDP/KCP + ChaCha20-Poly1305 + FEC | запасной, когда TCP убит, а UDP чист |

Выбор — вручную в настройках («Транспорт») или `Авто`: scorecard следит за здоровьем и сам уводит сессию на живой карьер.

## Приложение

- **Android**: API 24+ (проверено вживую на Android 7.0 — старые телефоны в поддержке), APK для arm64-v8a / armeabi-v7a / x86_64. FGS-сервис, выживание при смене Wi-Fi↔LTE.
- **Windows**: установщик per-user (без админа), системный прокси или полный туннель через wintun (опционально, с UAC).
- **Linux / macOS / iOS**: общий C ABI (`milky_start(config_json)`), TUN-режим — в активной доводке (см. `BUGS.md` и треки CI).

## Как начать

1. Скачать сборку под свою ОС из таблицы выше или со страницы [Releases](https://github.com/Frtertaer/milkyvpn/releases).
2. Вставить ссылку профиля `pandora://…` (или подписку Milky; старые ссылки `kal2://` тоже принимаются) в поле импорта.
3. Нажать «Подключить». Всё.

## Честное состояние подключения

`CONNECTING → (prepare → resolve → establish TUN → engine start → measureDelay через туннель) → CONNECTED`. Любой сбой ⇒ teardown + `ERROR(code)` — без вечного «Подключение…».

## Безопасность

- URL подписки: только `https://sub.milky.homes/s/<token>`; `http`, `file`, `javascript`, `localhost`, приватные IP, `@userinfo`, редиректы — отклоняются.
- Deep link `milkyvpn://import?url=…` → экран подтверждения, токен скрыт, автоподключения нет.
- Секреты: только OS keystore (Android Keystore / Keychain); `allowBackup=false`.
- Логи и диагностика проходят через `Redactor`/`SafeLog` — секреты не утекают в репорты.
- Pandora: X25519+Ed25519+HKDF, ChaCha20-Poly1305, PFS, replay-cache, TLS-exporter binding (RFC 9266), replay-safe optimistic open. Спека — `kaleido/SPEC.md` (ветка `kal2-protocol`).

## Поддерживаемые внешние протоколы (через Xray)

| Профиль из подписки | Статус | Как исполняется |
|---|---|---|
| VLESS + Reality + TCP (`flow=xtls-rprx-vision`) | **Приоритет, исполняется** | Xray `vless`, `security=reality` |
| VLESS + WS + TLS | Исполняется | Xray `vless` + `ws` + `tls` |
| VLESS + XHTTP (+TLS/Reality) | Исполняется | Xray `vless` + `xhttp` |
| Hysteria2 (`hysteria2://`, `hy2://`) | Исполняется | Xray `hysteria` v2 (+ salamander obfs) |
| Остальное (vmess, trojan, ss, grpc, kcp…) | Парсится, игнорируется | «N несовместимых» в диагностике |

Авто-режим ранжирует: Reality → XHTTP → WS → Hysteria2, до 4 попыток по 40 с.

## Дизайн — «Milky Glass»

Стеклянная дизайн-система в `lib/design/` (орб подключения, error-sheets), шрифт Manrope с кириллицей, честные счётчики подписки («N найдено / M совместимых»). Превью: `design/preview.html`, `design/screens/*.png`.

## Сборка

```bash
flutter pub get
flutter analyze
flutter test                                   # Dart-тесты
(cd android && ./gradlew :app:testDebugUnitTest)
flutter build appbundle --release
# ядро: scripts/check.sh  (unit+race+fuzz-smoke+crossbuild)
# релиз: git tag vX.Y.Z && git push --tags  →  CI соберёт APK×3 + Windows-установщик в GitHub Release
```

Без `android/key.properties` сборка подписывается debug-ключом (см. `docs/SIGNING.md`).

## Документы для Google Play

`docs/PRIVACY_POLICY_RU.md`, `PRIVACY_POLICY_EN.md`, `PLAY_STORE_LISTING_*.md`, `VPN_SERVICE_DECLARATION.md`, `DATA_SAFETY_DRAFT.md` (**OWNER MUST VERIFY**), `PLAY_RELEASE_CHECKLIST.md`, `SIGNING.md`, `THIRD_PARTY_LICENSES.md`.

Баги — через [Issues](https://github.com/Frtertaer/milkyvpn/issues) (шаблон: платформа/severity/repro); реестр известных — `BUGS.md`. Поддержка: https://t.me/MilkyVPNbot
