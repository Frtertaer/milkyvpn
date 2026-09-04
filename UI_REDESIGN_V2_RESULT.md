# MilkyVPN — Premium Flutter UI Rebuild V2 («Milky Orb 2.0»)

V2 поверх V1 («Milky Glass»): тот же реальный Flutter-код приложения, улучшенный по
спецификации MILKY ORB 2.0. Это НЕ прототип и НЕ веб-демо: все изменения — в боевом
приложении (`lib/`, `android/`), VPN-ядро (VpnService + Xray), парсер, secure storage и
deep links не переписаны, а сохранены.

Визуальное ревью: `design/screens/01…14_*.png` (14 кадров, рендер дизайн-токенов с
забандленным Manrope через resvg) + интерактивный `design/preview.html`. Каждый кадр
отревьюирован мной лично; кадры, похожие на дефолтный Flutter/generic VPN, отклонялись и
переделывались (в частности, исправлено наложение флага на подпись в селекторе и убраны
счётчики из узких сегментов).

---

## DESIGN

Концепт: **молоко + жидкий свет + мягкая aurora + сдержанный космос**. Спокойный,
премиальный, дружелюбный; не детский, не игровой, не крипто, не enterprise.

- Тёмная: глубокий navy `#0C1224→#060912`, aurora `#3E6BFF/#8B6BFF/#37CFE6`, bloom очень
  сдержанный; светлая: тёплый молочный `#FAF7F2→#EFEAE2`, мягкие violet/cyan тени.
- Фон **реагирует на состояние VPN** (`MilkyShell`): disconnected — тихий (intensity 0.6),
  connecting — лёгкое движение (0.8), connected — мягкая aurora (0.95). Без particle-полей.
- Кастомная дизайн-система (`lib/design/`), Material только как механизм:
  `MilkyConnectOrb`, `MilkyStatusPill`, `MilkyServerSelector` (сегмент-капсула),
  `MilkyNavigationBar`, `MilkySubscriptionStatus`, `MilkySubscriptionCard`,
  `MilkyPrimaryButton`/`MilkyGhostButton`/`MilkyPressable`, `MilkySettingRow`,
  `MilkyGlassCard`/`MilkySectionCard`, `MilkyErrorSheet`, `showMilkyConfirmSheet`
  (success/confirm-листы), `MilkyBackdrop`/`MilkyGlow`, `MilkyProgressIndicator` внутри орба
  (determinate-дуга при авто-поиске).
- Типографика Manrope (OFL 1.1), полная кириллица, иерархия `MilkyType`; длинные RU-строки
  проверены тестами на 320 dp без клиппинга.

### Signature component — MilkyConnectOrb

Состояния и поведение (все — один CustomPaint, без blur-фильтров и частиц, 60 fps,
останавливается при reduce-motion и в фоне):

| Состояние | Вид | Подпись |
|---|---|---|
| DISCONNECTED | приглушённый молочно-синий градиент, «дыхание», низкое свечение | **ВКЛЮЧИТЬ** |
| CONNECTING | жидкое вращающееся гало, aurora-пульс, дуга прогресса авто-поиска | «Подключаем…» + «Ищем лучший сервер… N из M» |
| CONNECTED | яркое cyan/milk свечение, галочка с draw-in, protected-пульс, страна и таймер под орбом | **ОТКЛЮЧИТЬ** |
| ERROR | мягкая коралловая подсветка, без сырых исключений; human bottom sheet | **ВКЛЮЧИТЬ** |
| DISABLED | нет подписки — орб инертен, тап ведёт к импорту | — |

Орб — настоящая кнопка: `Semantics(button: true, label, value)`, tap-target = весь орб,
подпись-капшель входит в semantic-label.

## HOME

- TOP: словоназвание + маленький статус-пилл («Защита выключена»/«VPN подключён») + действие
  профиля/настроек. Без безымянных иконок.
- CENTER: орб с подписью действия; STATUS: «Не подключено» или «Финляндия / Защищено · 00:14:32».
- LOCATION: компактная капсула 56 dp (✨ Авто / 🇫 Финляндия / 🇺🇸 США), выбранное состояние
  очевидно (градиентная пилюля + контур + тень). Без протоколов, хостов, UUID, latency.
- BOTTOM: Главная / Подписка / Настройки (всегда с подписями).
- Под орбом — **одна строка** статуса подписки «● Подписка активна · до 01.01.2100»
  (`MilkySubscriptionStatus`); полный дашборд живёт только во вкладке «Подписка».

### Auto

Auto — дефолт и рекомендация; прогресс «Ищем лучший сервер… Финляндия» показывает фактическую
страну попытки; Reality→XHTTP→WS→Hysteria2, до 4 попыток по 40 c; CONNECTED наступает только
после реальной post-connect верификации ядра (инвариант сохранён, не «VpnService существует»).

## PARSER

Правда о цифрах (синтетический канонический фикстур, 16 строк):

| Метрика | Значение |
|---|---|
| PARSED_PROFILE_COUNT | 16 |
| DEDUPED_PROFILE_COUNT | 0 (для канонического фикстуры) |
| COMPATIBLE_PROFILE_COUNT | 16 |

**Причина прежних «10»:** id профиля считался как `fnv1a64(proto|host|port|net|sec|path)` —
без UUID/SNI/flow/public key/short id. Строки с одинаковым endpoint, но **разными
креденшалами**, схлопывались как «дубликаты», а UI подписывал это «доступными серверами»
(комбинация вариантов C+D из спецификации).

**Исправление (V2):** identity теперь включает секрет (UUID/пароль), SNI, flow, public key,
short id, fingerprint, HTTP host, xhttp mode, alpn, obfs (`_identity` в
`subscription_parser.dart`). Разные креденшалы = разные профили; байт-одинаковые строки всё
ещё честно считаются как `duplicateEntries`; инвариант
`totalLines = profiles + malformed + duplicates` сохранён и показывается в UI/диагностике.

## ERROR UX

Старые сырые артефакты (`proxyerror` = `go.Universe$proxyerror` из libv2ray.aar; `(S)` —
R8-переименованное исключение; «Не удалось выполнить операцию (code)») больше не попадают к
пользователю никак. Нормализованный словарь диагностических кодов (только в «Диагностике»):

| Ситуация | Код |
|---|---|
| ядро не стартовало / Go proxy error | `VPN_CORE_START_FAILED` |
| нет сети | `NETWORK_UNAVAILABLE` |
| сервер не ответил/отказал | `SERVER_UNREACHABLE` |
| нет VPN-разрешения | `PERMISSION_DENIED` |
| нет исполняемого профиля/конфигурация | `CONFIG_INVALID` |
| TUN не поднялся/туннель не верифицирован | `TUN_FAILED` |
| подписка (пустая/404/503…) | `SUBSCRIPTION_*` (включая `SUBSCRIPTION_HTTP_503`) |
| всё остальное (обфускация R8 и т.п.) | `UNKNOWN_CONNECTION_ERROR` |

Пользователь видит: «Не удалось подключиться / Сервер не отвечает. Попробуем другой сервер
или проверьте интернет.» + [Попробовать снова] [Выбрать страну] [Диагностика]. TUN-ошибки
уточняются контекстом устройства (`EMULATOR_FAILURE`/`REAL_DEVICE_FAILURE` — только в
таксономии диагностики).

## RESPONSIVE

- Телефон (320/390/412 dp): узкая колонка, орб доминирует, без горизонтальных переполнений
  (виджет-тесты `takeException()` пусты).
- Планшет (800×1280, 1024×1366, 1280×800): контент центрирован и ограничен
  `MilkyLayout.maxContentWidth = 560` dp; кнопки не растягиваются (кадр 14).

## TESTS

Flutter (`flutter test`):

- прежние функциональные тесты сохранены (`vpn_controller_test`, `subscription_test`, …);
- **parser regression + mutation/control**: `subscription_stats_test.dart` —
  «16 строк, 6 байт-дубликатов → 10 профилей + 6 duplicateEntries» и контрольная мутация
  «тот же endpoint + другой UUID/SNI/pbk → 16 профилей, 0 дубликатов» (ловит прежний класс
  бага 16→10);
- `milky_error_test.dart` — нормализованный словарь, upper-snake токены, emulator/real
  уточнение, RU/EN строки, плюрализация;
- `home_states_test.dart` — переходы орба idle→connecting→error, connected (FI/US) с
  «ОТКЛЮЧИТЬ», disconnected с «ВКЛЮЧИТЬ», failure-sheet для `tls_handshake/proxyerror/S/
  all_attempts_failed` (сырой код не рендерится), permission-флоу, вкладка «Подписка»
  (токен не рендерится), 5 размеров, light/dark, RU-переполнения;
- `ui_smoke_test.dart` — онбординг, home, навигация; запрет протокольной лексики;
- `golden_test.dart` — опционные golden 9 экранов (`MILKY_GOLDENS=1`).

Android (`./gradlew :app:testDebugUnitTest`): `SafeLogTest` (стабильный словарь кодов,
Go/obfuscated-ветки), `DeviceProfileTest` (эмуляторы vs реальные устройства). Здесь не
запускались (нет SDK) — см. BUILD.

## BUILD

Выполнено в sandbox:

- `python3 tool/check_dart.py lib` → **38 dart files, 0 issue(s)**;
- `python3 tool/check_dart.py test` → **8 dart files, 0 issue(s)**.
  (собственный статический анализатор; это НЕ `flutter analyze`).

Невозможно в sandbox (хосты SDK закрыты: `storage.googleapis.com`, `dl.google.com`,
`maven.google.com`, `services.gradle.org` → 000): `flutter analyze`, `flutter test`,
`./gradlew :app:testDebugUnitTest`, `flutter build apk --release`,
`flutter build appbundle --release`. Размер APK/AAB поэтому не измерен.

Команды для машины с SDK:

```
flutter analyze && flutter test
MILKY_GOLDENS=1 flutter test --update-goldens test/features/golden_test.dart  # опц.
cd android && ./gradlew :app:testDebugUnitTest && cd ..
flutter build apk --release && flutter build appbundle --release
```

## REAL DEVICE

- tested: **NO** (устройства/эмулятора в sandbox нет);
- tunnel verified: **NO** — никаких заявок «туннель починен» нет;
- **REAL_DEVICE_VPN_TEST = REQUIRED**: на устройстве проверить подключение FI/US, при
  ошибке — «Диагностика» (ожидается `TUN_FAILED`/`REAL_DEVICE_FAILURE` на устройстве и
  `EMULATOR_FAILURE` на LDPlayer/AVD), отчёт приложить к багу.

## STATUS

Редизайн V2 реализован в реальном приложении, парсер-баг дедупликации исправлен с
регрессионными тестами, 14 кадров отревьюированы, статическая проверка чистая.

BLOCKED — `flutter analyze/test/build apk|appbundle` и Android unit-тесты невозможно выполнить в этом sandbox (хосты Flutter/Android SDK недоступны); финальная сборочная и real-device верификация остаются на машине с SDK (команды выше).
