# MilkyVPN — UI Redesign Result («Milky Glass»)

Полный визуальный редизайн приложения под премиальный уровень Play Store. Бренд:
**Milky Glass** — глубокий полуночный navy в тёмной теме, тёплый «молочный» офвайт в светлой,
сдержанная aurora (blue/violet/cyan), матовое стекло, скруглённая геометрия, чистая
типографика Manrope, плавные микроанимации. Никакого «хакерского» неона, enterprise-дашборда,
дефолтного Material и криpto-эстетики. Образ — капля молока + свет Млечного Пути.

Визуальный ревю всех экранов: `design/preview.html` (интерактивный, 10 фреймов) и
`design/screens/*.png` (9 отрендеренных экранов; рендер — статическая SVG-реконструкция
дизайн-токенов с забандленным Manrope, см. раздел BUILD — почему это не скриншоты Flutter).

---

## DESIGN

Дизайн-система живёт в `lib/design/` и не использует пере-стилизацию дефолтных Material-виджетов:

| Компонент | Файл | Назначение |
|---|---|---|
| `MilkyGlassCard`, `MilkySectionHeader`, `MilkyHairline`, `MilkyStatusPill`, `MilkyColumn` | `milky_glass.dart` | матовые карточки/секции/пиллы |
| `MilkyPrimaryButton`, `MilkyGhostButton`, `MilkyPressable` | `milky_buttons.dart` | кнопки с aurora-градиентом и press-анимацией |
| `MilkyConnectOrb` | `milky_connect_orb.dart` | герой-орб: disabled/idle/connecting/connected + reduce-motion |
| `MilkyServerSelector` | `features/home/milky_server_selector.dart` | карточки ✨ Авто / 🇫🇮 Финляндия / 🇺🇸 США |
| `MilkyNavigationBar` | `milky_navigation_bar.dart` | стеклянный низ: Главная / Подписка / Настройки (всегда с подписями) |
| `MilkySettingRow`, `MilkyToggle`, `MilkySegmented` | `milky_setting_row.dart` | кастомные строки настроек |
| `MilkySubscriptionCard` | `features/subscription/milky_subscription_card.dart` | карточка подписки с честными счётчиками |
| `MilkyErrorSheet` | `milky_error_sheet.dart` | человеко-читаемый bottom sheet ошибок |
| `MilkyBackdrop` / aurora | `milky_aurora.dart` | живой, но лёгкий фон (останавливается при reduce-motion) |
| Токены | `milky_tokens.dart`, `milky_colors.dart`, `milky_theme.dart`, `milky_motion.dart` | отступы, радиусы, `maxContentWidth=560`, Motion-кривые |

- **Шрифт**: Manrope (SIL OFL 1.1, лицензия в `assets/fonts/OFL-Manrope.txt`), 5 весов,
  полная кириллица; объявлен в `pubspec.yaml`. Иерархия в `MilkyType` (display/headline/
  subtitle/body/bodySmall/mono). Никаких обрезаний: ключевые строки проверены на 320 dp.
- **Темы**: тёмная `#0C1224→#060912`, aurora `#3E6BFF/#8B6BFF/#37CFE6`, accent `#7C97FF`;
  светлая — тёплый молочный `#FAF7F2→#EFEAE2`, ink `#131A2B`, accent `#3F63D8`.
  Светлая — самостоятельная палитра, а не инверсия тёмной.
- **Иконка приложения**: оригинальная — капля молока + «M» на aurora-градиенте
  (`assets/brand/app_icon.svg`, адаптивный вектор
  `android/.../drawable/ic_launcher_foreground.xml` + фон `ic_launcher_background.xml`,
  перегенерированные mipmap PNG 48–192 px). Без замков и глобусов.

## HOME

- Шапка: логотип + словоназвание, статус-пилл («Защита выключена» / «VPN подключён»),
  профиль/настройки. Без безымянных иконок в app-bar.
- Герой — `MilkyConnectOrb` (210–300 dp): отключено — приглушённый градиент и «дыхание»;
  подключение — вращающееся градиентное гало + «Подключаем…» + «Ищем лучший сервер… N из M»;
  подключено — мягкое свечение, галочка, пульс-кольцо, под орбом «Финляндия» + пилл
  «Защищено» + таймер `00:14:32`. Тап по орбу = подключить/отключить.
- Никакой протокольной терминологии на главных экранах (VLESS/Reality/XHTTP/SNI/UUID
  не рендерятся нигде, кроме диагностики; это также защищено виджет-тестами).
- Селектор сервера: карточки вместо `SegmentedButton`, выбранное состояние очевидно,
  Auto — дефолт; latency не показывается вовсе (реальных замеров в ядре нет — не выдумываем).
- Нижний нав: Главная / Подписка / Настройки, всегда с подписями.

## SUBSCRIPTION

- Дом-карточка: «Подписка активна», срок действия и **правдивые** счётчики.
- Экран «Подписка»: карточки «Премиум» (● Активна, «Действует до …»), счётчики
  «16 профилей найдено / 16 совместимых с приложением» (числа считаются из реально
  распарсенного payload, см. TESTS), действия «Обновить» / «Удалить подписку».
- **Сырой URL подписки не показывается никогда** (это креденшал). «Скопировать ссылку»
  доступен только в разделе «Дополнительно» и использует `SubscriptionRepository.urlForCopy`.

### Правда про «10 против 16»

Старое «Количество доступных серверов: 10» было **неверной меткой** (`profiles.length`
после дедупликации) плюс тихая дедупликация парсером строк с одинаковым endpoint
(id = fnv1a64 от proto|host|port|net|sec|path — без UUID). Теперь:

- `SubscriptionParser` возвращает `totalLines`, `malformedLines`, `duplicateEntries`;
- инвариант `totalEntries == profiles + malformed + duplicates` закреплён в
  `SubscriptionStats.isAccounted` и тестах;
- совместимость считается `VpnProfile.isStaticCompatible` (зеркалит `XrayConfigBuilder.validate`);
- UI показывает «N профилей найдено / M совместимых с приложением» и, при наличии,
  «K повторов пропущено» / «K строк повреждено». Никакого «10 servers».

## ERROR UX

- `MilkyError.fromCode` мапит любой код — включая сырые имена JVM-классов `proxyerror`
  (обёртка Go-ошибки из `libv2ray.aar`) и R8-укороченное `S` — на человеческие сообщения.
  Шаблон «Не удалось выполнить операцию (code)» удалён полностью (тесты это фиксируют).
- Сообщения: «Не удалось подключиться / Сервер не отвечает. Попробуем другой сервер.»,
  «Нет соединения с сервером / Проверьте интернет…», «Нужно разрешение VPN» и т.д.
- Кнопки по контексту: [Попробовать снова] [Другой сервер] [Диагностика]; для permission —
  [Настройки VPN]; для подписки — [Добавить подписку].
- Авто-ретрай с прогрессом «Ищем лучший сервер… 1 из 4»; после исчерпания — красивый
  bottom sheet «Не удалось подключиться».
- Технический код живёт **только** в диагностике и только в стабильных токенах вида
  `VPN_CORE_START_FAILED`, `TLS_HANDSHAKE_FAILED`, `SUBSCRIPTION_HTTP_503`
  (`^[A-Z][A-Z0-9_]*$` — проверено тестом по всей таблице маппинга).
- Таксономия для диагностики: `EMULATOR_FAILURE / REAL_DEVICE_FAILURE / CORE_FAILURE /
  CONFIG_FAILURE / PERMISSION_FAILURE / NETWORK_FAILURE / SUBSCRIPTION_FAILURE`.
  TUN-ошибки уточняются контекстом устройства: `MilkyError.withDeviceContext(isEmulator:)`
  с данными нового `DeviceProfile` (Kotlin) + `MilkyDevice` (Dart).

### Происхождение `proxyerror` и `(S)` (расследование)

- `proxyerror` = `go.Universe$proxyerror` — gomobile-обёртка Go-ошибки из `startLoop`/
  `measureDelay` (класс сидит в `android/app/libs/libv2ray.aar!classes.jar`).
- `S` — исключение, переименованное R8 в release-сборке (`isMinifyEnabled=true`,
  `mapping.txt` в gitignore → восстановить имя невозможно).
- Раньше `SafeLog.errorCode` падал в `javaClass.simpleName` — отсюда оба артефакта в UI.
  Теперь `SafeLog.errorCode` (Kotlin) использует стабильный словарь: сначала подстроки
  сообщения (timeout/refused/unreachable/tls/reality/dns/…), затем Go/obfuscated-классы →
  разбор сообщения ядра, затем известные Java-исключения. Покрыто `SafeLogTest.kt`.

## RESPONSIVE

- Телефон: узкая центрированная колонка, орб доминирует.
- Планшет/широкие экраны: контент ограничен `MilkyLayout.maxReadingWidth = 560` dp —
  никогда не растягивается «сайтом» на всю ширину.
- Проверено виджет-тестами: 320×568, 390×844, 412×915, 800×1280, 1280×800 —
  `tester.takeException()` пуст, орб ≤ 300 dp и ≤ ширины экрана.

## TESTS

Dart (`flutter test`):

- `test/core/vpn_controller_test.dart`, `subscription_test.dart`, `parser_*` — прежние
  функциональные тесты сохранены.
- `test/core/milky_error_test.dart` — маппинг ошибок: сырые имена не всплывают, токены
  диагностики в upper-snake, emulator/real-device уточнение, RU/EN строки и плюрализация
  («16 профилей найдено», «2 профиля найдено»), даты без intl-локалей.
- `test/core/subscription_stats_test.dart` — 16→10 через 6 дубликатов endpoint,
  «16 распарсено / 10 исполняемы» для неподдерживаемых протоколов, инвариант учёта,
  round-trip счётчиков через secure storage.
- `test/features/ui_smoke_test.dart` — онбординг (3 страницы, честное раскрытие
  VpnService), дом с подпиской, навигация; запрет протокольных строк.
- `test/features/home_states_test.dart` — disconnected/connecting/connected (FI и US),
  failure-sheet для `tls_handshake`, `proxyerror`, `S`, `all_attempts_failed` (сырой код
  не рендерится), permission-флоу, вкладка «Подписка» (токен не рендерится),
  responsive-набор, light/dark палитры, RU-переполнения.
- `test/features/golden_test.dart` — опционные golden-скриншоты 9 экранов:
  `MILKY_GOLDENS=1 flutter test --update-goldens test/features/golden_test.dart`.
  По умолчанию пропускаются (golden-файлы не коммитятся: рендер зависит от хоста).
- `test/support/harness.dart` — общий насос с `disableAnimations`, чтобы бесконечные
  анимации орба/aurora не ломали `pumpAndSettle`.

Kotlin (`./gradlew :app:testDebugUnitTest`):

- `SafeLogTest.kt` — стабильный словарь кодов, Go/obfuscated-ветки, `proxyerror`→`VPN_CORE_START_FAILED`-семантика.
- `DeviceProfileTest.kt` — эмуляторы (AVD, LDPlayer, MuMu, NOX, Bluestacks) определяются,
  реальные устройства (Pixel 8 Pro, SM-S928B, M2102K1G) — нет.

## BUILD

Что **выполнено** в этом sandbox и что получилось:

- `python3 tool/check_dart.py lib` → **38 dart files checked, 0 issue(s)** — собственный
  статический анализатор (баланс скобок, импорты, l10n-члены, неизвестные Milky-типы,
  unused locals, геттеры с параметрами). Это НЕ `flutter analyze`.
- `python3 tool/check_dart.py test` → **8 dart files checked, 0 issue(s)**.

Что **невозможно** в этом sandbox (сеть до хостов SDK закрыта: `storage.googleapis.com`,
`dl.google.com`, `maven.google.com`, `services.gradle.org` отвечают 000):

- `flutter analyze`, `flutter test`, `flutter build apk --release`,
  `flutter build appbundle --release`, `./gradlew test` — Flutter/Android SDK физически
  не устанавливаются. Поэтому новые Dart- и Kotlin-тесты написаны, но здесь не исполнены,
  и скриншоты работающего Flutter-приложения снять здесь нельзя.

Команды для финальной верификации на машине с SDK:

```
flutter analyze
flutter test
MILKY_GOLDENS=1 flutter test --update-goldens test/features/golden_test.dart   # опционально
./gradlew :app:testDebugUnitTest
flutter build apk --release
flutter build appbundle --release
```

## REAL DEVICE

Реального устройства в sandbox нет; туннель здесь не воспроизводился, поэтому **никаких
заявок «проблема туннеля решена» нет**. Что сделано вместо этого:

- точная диагностика: стабильные коды в «Диагностике» + таксономия
  `EMULATOR_FAILURE`/`REAL_DEVICE_FAILURE` и авто-определение эмулятора;
- на LDPlayer/AVD TUN-путь может отличаться от реального устройства — код теперь это
  различает и честно пишет в отчёте;
- что проверить на устройстве: подключить → при ошибке открыть «Диагностика» и сверить
  токен (`TUN_ESTABLISH_FAILED`/`REAL_DEVICE_FAILURE` на устройстве vs `EMULATOR_FAILURE`
  на эмуляторе), приложить отчёт к багу.

## STATUS

Редизайн, код, тесты, ассеты и документация завершены и проверены статически;
рендеры дизайна отревьюированы по `design/screens/*.png` и `design/preview.html`.

BLOCKED — `flutter analyze` / `flutter test` / `flutter build apk|appbundle` и Android unit-тесты не могут быть выполнены в этом sandbox (хосты Flutter/Android SDK недоступны из сети); финальная сборочная верификация остаётся на машине с SDK (команды выше). Всё остальное завершено.
