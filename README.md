# MilkyVPN

> Простой VPN без ручной настройки серверов.

Android VPN-клиент для подписки Milky (`https://sub.milky.homes/s/{token}`): Flutter UI + нативный Kotlin `VpnService` + движок **Xray-core** (через [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite)).

| | |
|---|---|
| Application ID | `homes.milky.vpn` |
| Version | `0.1.0+1` |
| minSdk / target / compile | 26 / 36 / 36 |
| Flutter / Dart | 3.35.4 / 3.9.2 |
| Kotlin / AGP / Gradle | 2.1.0 / 8.9.1 / 8.12 |
| VPN core | Xray-core v1.260327.1 (MPL-2.0) via libv2ray.aar v26.8.20 (LGPL-3.0) |
| Analytics / Ads / Billing | none |

## Поддерживаемые протоколы

| Профиль из подписки | Статус | Как исполняется |
|---|---|---|
| VLESS + Reality + TCP (`flow=xtls-rprx-vision`) | **Приоритет, исполняется** | Xray `vless` outbound, `security=reality` |
| VLESS + WS + TLS | Исполняется | Xray `vless` + `wsSettings` + `tlsSettings` |
| VLESS + XHTTP (+TLS/Reality) | Исполняется | Xray `vless` + `xhttpSettings` |
| Hysteria2 (`hysteria2://`, `hy2://`) | Исполняется | Xray `hysteria` outbound v2 (+ salamander obfs) |
| Всё остальное (vmess, trojan, ss, grpc, kcp…) | Парсится, **игнорируется** | В диагностике показывается «N несовместимых» |

Авто-режим ранжирует: Reality → XHTTP → WS → Hysteria2, максимум 4 попытки по 40 с, при неуспехе — понятная ошибка, а не вечное «Подключение…».

## Дизайн — «Milky Glass»

Полный редизайн UI (см. `UI_REDESIGN_RESULT.md`):

- дизайн-система в `lib/design/` (стеклянные карточки, орб подключения, навигация, error-sheet);
- шрифт Manrope (OFL 1.1) в `assets/fonts/`, полная кириллица;
- визуальное ревю: `design/preview.html` и `design/screens/*.png`;
- оригинальная иконка: `assets/brand/app_icon.svg` + адаптивные вектора в `android/app/src/main/res/`;
- честные счётчики подписки («N профилей найдено / M совместимых», без «10 servers»);
- человеко-читаемые ошибки; технические коды — только в «Диагностике».

## Архитектура

```
lib/
  main.dart                       UI: онбординг (3 экрана), главный, импорт, deep-link подтверждение,
                                  подписка, настройки, диагностика
  app/app_settings.dart           настройки (SharedPreferences) + строки RU/EN
  core/subscription/              парсер Base64/URI (vless, hysteria2, прочее), модель профиля,
                                  репозиторий (HTTPS, без редиректов, лимит 512 KB)
  core/security/                  allowlist URL подписки, редактор секретов, FNV-id профилей
  core/storage/secure_store.dart  Keystore-хранилище (flutter_secure_storage) + in-memory для тестов
  core/vpn/                       MethodChannel-мост и контроллер с ограниченным fallback

android/app/src/main/kotlin/homes/milky/vpn/
  MainActivity.kt                 каналы homes.milky.vpn/vpn, /vpn_state, /links; prepare(); deep link
  vpn/MilkyVpnService.kt          VpnService: FGS specialUse, TUN, маршруты, DNS, исключение себя,
                                  запуск Xray, HTTPS-проверка через туннель, onRevoke, смена сети
  vpn/KeystoreSealedStore.kt      AES-256-GCM (AndroidKeyStore) для активного профиля, noBackupFilesDir
  vpn/VpnStateStore.kt            состояние → EventChannel
  vpn/SafeLog.kt                  логи с редактированием секретов, классы ошибок
  core/XrayConfigBuilder.kt       JSON-конфиг Xray для всех поддерживаемых транспортов
android/app/libs/libv2ray.aar     движок (Go, gomobile)
```

### Честное состояние подключения
`CONNECTING → (prepare → resolve → establish TUN → Xray startLoop → measureDelay https://www.gstatic.com/generate_204 через туннель) → CONNECTED`. Любой сбой ⇒ teardown + `ERROR(code)`.

### Безопасность
- URL подписки: только `https://sub.milky.homes/s/<token>`; `http`, `file`, `javascript`, `localhost`, приватные IP, `@userinfo`, редиректы — отклоняются.
- Deep link `milkyvpn://import?url=…` → экран подтверждения, токен скрыт, автоподключения нет.
- Секреты: только Android Keystore (`flutter_secure_storage` + `KeystoreSealedStore`); `allowBackup=false`, `backup_rules.xml`, `data_extraction_rules.xml`.
- Логи и диагностика проходят через `Redactor` / `SafeLog`.

## Сборка

```bash
flutter pub get
flutter analyze
flutter test                                   # 27 тестов
(cd android && ./gradlew :app:testDebugUnitTest)   # 10 Kotlin-тестов
flutter build appbundle --release              # build/app/outputs/bundle/release/app-release.aab
```
Без `android/key.properties` AAB подписывается debug-ключом (для internal testing нужен upload-key — см. `docs/SIGNING.md`).

## Тестовые данные
`test/fixtures/subscription_16_fake.{txt,b64}` — 16 синтетических профилей (9 FI / 7 US) с **фальшивыми** ключами. Реальных токенов в репозитории нет.

## Документы для Google Play
`docs/PRIVACY_POLICY_RU.md`, `PRIVACY_POLICY_EN.md`, `PLAY_STORE_LISTING_RU.md`, `PLAY_STORE_LISTING_EN.md`, `VPN_SERVICE_DECLARATION.md`, `DATA_SAFETY_DRAFT.md` (**OWNER MUST VERIFY**), `PLAY_RELEASE_CHECKLIST.md`, `PLAY_REVIEW_VIDEO_SCRIPT.md`, `SIGNING.md`, `THIRD_PARTY_LICENSES.md`.

Статус сборки и блокеры — в `BUILD_RESULT.md`.

Поддержка: https://t.me/MilkyVPNbot
