# Milky VPN — приложение (Android / ПК)

Приложение на Flutter поверх Mirage core (протокол KAL/2). Туннель через
SOCKS5: приложение само поднимает ядро и заворачивает трафик телефона в
локальный SOCKS `127.0.0.1:11808`.

## Готовые файлы (dist/) — ставить и работать сразу

| файл | куда | размер |
|------|------|--------|
| `milky-arm64-v8a.apk` | любой современный телефон (95% устройств) | ~87 МБ |
| `milky-armeabi-v7a.apk` | старые 32-битные телефоны (в т.ч. Android 6) | ~83 МБ |
| `kal2-client-windows-x64.exe` | ПК на Windows (CLI-клиент, SOCKS5) | ~8 МБ |

Какой APK выбрать — почти наверняка `arm64-v8a`. Если не знаете —
попробуйте его; если установка скажет «приложение не совместимо»,
ставьте `armeabi-v7a`.

**Пошаговые инструкции:**
- Телефон → `INSTALL_ANDROID_RU.md`
- ПК (Windows) → `INSTALL_PC_RU.md`

## Что нужно для подключения

Профиль вида `kal2://` — ссылку выдаёт владелец сервера (содержит адрес,
домен, pub-ключ и ваш PSK). В приложении: «Импорт» → вставить ссылку →
«Подключить».

## Сборка из исходников

```bash
flutter pub get
flutter build apk --release --split-per-abi   # APK → build/app/outputs/flutter-apk/
flutter build windows                        # ПК-сборка (нужен Visual Studio)
```

Минимальный Android: **API 23 (Android 6)**. Нативные ядра
(`android/app/src/main/jniLibs/*/libcore.so`) собраны под API 23 —
если пересобираете через gomobile, используйте `-target android-23` или
новее — подробности в `milky-core/CONSUMING.md` у ядра.

Структура кода: `lib/` (UI+логика), `android/` (Kotlin-сервис VPN +
мост в ядро), `ios/`, `windows/`, `test/`.
