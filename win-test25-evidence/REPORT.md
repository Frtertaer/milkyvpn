# MilkyVPN Windows — проверка сборки `windows-test-25` (диагностика)

Машина: Windows Server 2022 (per-user install, без админа). Дата проверки: 2026-09-29 ~02:00 UTC.
Вердикт: **на чистой машине сборка работает end-to-end** — установка, запуск, импорт, подключение, туннель через SOCKS — всё OK. Найден один реальный функциональный дефект: **`ech` параметр из kal2-ссылки молча теряется при импорте** (см. «Корневая причина»).

## Хронология проверки (pre/post редеплой сервера 02:16 UTC)

| Шаг | Время (UTC) | Результат |
|---|---|---|
| Скачивание + установка | ~01:49 | OK |
| Запуск, онбординг | ~01:52 | OK |
| Импорт профиля | ~01:53 | OK (но `ech` отброшен — см. ниже) |
| Connect №1 → CONNECTED | ~01:55 | OK — `server flight: EOF` **не встречался** |
| SOCKS egress | ~01:57 | `23.133.88.167` |
| Disconnect + рестарт приложения | ~02:09–02:16 | OK (профиль сохранился; v25-процесс был убит отдельно — инсталлером v24, см. §2) |
| Connect №2 → CONNECTED | ~02:16 | OK |
| **Connect №3 → CONNECTED (post-redeploy)** | **~02:22** | **OK**, SOCKS egress `23.133.88.167` |

Примечание по контексту: по словам пользователя, до ~02:16 UTC на сервере крутился kal2-server с багом TLS-exporter binding (nil + no fallback → `server flight: EOF` у клиентов от merged core). В этой сессии ошибка не воспроизвелась ни до, ни после редеплоя — три подряд Connect прошли в CONNECTED, egress = `23.133.88.167`. Если у пользователя наблюдался `server flight: EOF` / handshake EOF / connect_timeout — это была серверная проблема, исправленная редеплоем 3fa81d3, не баг клиента/инсталлятора.

## 1. Скачивание

- URL `https://github.com/Frtertaer/milkyvpn/releases/download/windows-test-25/MilkyVPN-Setup.exe` — скачался напрямую (repo публичный), без gh fallback.
- Размер: **14 395 561 байт**; SHA256: `8E4AD4AE175AEEE69C9B8CF82210462B3C5E7962A66F478977BE2E5CF3C063E8`.
- Для сравнения скачан и windows-test-24: 14 391 257 байт, SHA256 `EC755686D6A0B607892169C56CB8F861E311F44BB651869FDE7E150422697234`.

## 2. Тихая установка

- `MilkyVPN-Setup.exe /VERYSILENT /NORESTART /SUPPRESSMSGBOXES` — **OK**. `$LASTEXITCODE` пуст (Inno возвращается сразу), установка завершилась за ~3 с. UAC-промптов не было (per-user, PrivilegesRequired=lowest).
- Замечание (не дефект этой сборки): в `installer/windows.iss` `PrepareToInstall` принудительно делает `taskkill /F /IM kal2-client.exe` и `/IM milkyvpn.exe` — тихая переустановка поверх запущенного приложения убьёт активный туннель без предупреждения. Проверено фактом: при установке build-24 в `TEMP\mv24` запущенный v25-процесс был убит.

## 3. Дерево установки

Установлено в `C:\Users\Administrator\AppData\Local\MilkyVPN` (не Programs\). Все ожидаемые файлы на месте:

- `milkyvpn.exe` (91 648), `flutter_windows.dll` (21 274 112), `flutter_secure_storage_windows_plugin.dll`, `url_launcher_windows_plugin.dll`
- `kal2\kal2-client.exe` (11 060 224), `kal2\wintun.dll` (427 552)
- VC++ runtime: `msvcp140.dll`, `vcruntime140.dll`, `vcruntime140_1.dll`
- `data\app.so` (6 407 048), `data\icudtl.dat`, `data\flutter_assets\` (шрифты Manrope, MaterialIcons, shaders, NOTICES.Z)
- Ярлык Desktop `Milky VPN.lnk` → `…\MilkyVPN\milkyvpn.exe` ✔; группа Start Menu `…\Programs\Milky VPN\Milky VPN.lnk` ✔.

## 4. Запуск

- `milkyvpn.exe` — окно открылось, онбординг отрендерился (3 шага: «VPN без сложных настроек» → «Защищённое VPN-соединение» → «Добавьте подписку»). Падений, missing-DLL диалогов нет. Event Log (Application, Error) — чисто, записей по milkyvpn/kal2/flutter нет.
- Приложение данных: `%APPDATA%\homes.milky\milkyvpn\` (`shared_preferences.json`, `flutter_secure_storage.dat`). `.log` файлов приложение не пишет нигде — stderr kal2-client читается родительским процессом и на диск не сохраняется (диагностировать проблемы на стороне пользователя нечем — тоже находка: логов нет).
- Ложная тревога: полоса «Engine starting / RAM 0.00 GB CPU 0.00% / Disk … / v4.80.0» внизу экрана — это окно **Docker Desktop** (Dashboard, PID 4604, rect покрывает экран), лежащее под окном MilkyVPN. Строки «Engine starting»/«4.80» нет ни в одном файле установки; после сворачивания Docker окна полоса исчезла. К приложению отношения не имеет.

## 5. Импорт kal2-профиля

- Ссылка вставлена из буфера одной строкой → «Подписка добавлена — 1 профиль найден, 1 совместим с приложением». Ошибок импорта нет.
- **НО**: экспортированный обратно профиль (`Подписка → Дополнительно → Экспортировать профили`, base64 → plain) даёт:
  `kal2://65e2…8bb1@23.133.88.167:443?sni=kal.mergescribe.dev&pub=9f0d…6c8f&carrier=veil#23.133.88.167%3A443`
  — т.е. параметр **`ech=AE3-DQBJ…AAA` из исходной ссылки молча удалён**. `carrier=veil` сохранился.

## 6. Настройки

- «Полный туннель» выключен (и выключен по умолчанию — `tun_mode ?? false`), скриншот `shot-03-settings.png`.
- В настройках видна Android-only строка «Always-on VPN / Системные настройки Android» — открывает `ms-settings:network-proxy`. Косметический недочёт порта.
- Пикера «Транспорт» (carrier override) в этой сборке нет — добавлен позже.

## 7. Подключение

- Нажатие на кнопку → «Подключаем… Ищем лучший сервер» → **«VPN подключён / Подключено / Защищено»**, таймер идёт. PERMISSION_DENIED/ERROR не возникали (SOCKS-режим, без админа).
- Спавн процесса (verbatim `Win32_Process.CommandLine`):
  `kal2-client.exe -addr 23.133.88.167:443 -sni kal.mergescribe.dev -pub 9f0d…6c8f -psk 65e2…8bb1 -carrier auto -drift "" -socks 127.0.0.1:11808`
  - `-carrier auto` вместо `veil` — **by design на этой ревизии**: `_argsFor()` мапит всё, кроме `relay`, в `auto` (hedged veil+drift dial). Соединение прошло.
  - `-drift ""` — пустой аргумент, безвредно.
  - **`-ech` отсутствует** — хотя флаг у клиента есть (`-ech string: base64 ECHConfigList — Encrypted Client Hello on veil (outer SNI shows only the cover name)`) и в ссылке параметр был.

## 8. Туннель

- `curl.exe --socks5-hostname 127.0.0.1:11808 https://api.ipify.org` → **`23.133.88.167`** — egress IP сервера, туннель работает (HTTPS через туннель — значит и DNS remote, и TLS ok).
- Системный прокси выставлен приложением: `ProxyEnable=1`, `ProxyServer=socks=127.0.0.1:11808`. После «ОТКЛЮЧИТЬ» → `ProxyEnable=0`, `kal2-client.exe` завершается, прямой egress `140.232.64.4`. Утечек/залипания прокси нет.
- Реконнект после перезапуска приложения — OK; профиль пережил рестарт (secure storage).
- **Post-redeploy ретрай (02:22 UTC): PASSED** — свежий Connect после редеплоя 3fa81d3 дошёл до «Подключено/Защищено», `curl --socks5-hostname 127.0.0.1:11808 https://api.ipify.org` → `23.133.88.167`. `server flight: EOF` не встречался ни до, ни после редеплоя.

## Корневая причина «не работает» — гипотеза с доказательствами

**Сборка windows-test-25 собрана из коммита `95d85cb`** (опубликована 2026-09-26T21:00Z, через ~4 мин после коммита 20:56Z; windows-test-24 — 04:51Z ≈ `d5c3849`).

**Дефект (присутствует и в 24, и в 25):** `ech` теряется при импорте профиля.
- Парсер читает `ech` из ссылки (`_nz(query['ech'])`), но `_identified()` — копия профиля с каноническим id — **не переносит поля `ech`, `cover`, `pin`**. Сохранённый профиль имеет `ech == null` → бридж не передаёт `-ech` клиенту.
- Доказательства: (1) экспортированная ссылка не содержит `ech`; (2) живой command line kal2-client без `-ech`; (3) исходник `subscription_parser.dart::_identified` на коммите сборки не копирует ech; (4) фикс — коммит `5df3cc9` «keep kal2 ech/cover/pin through profile identity» (2026-09-27, **после** этой сборки; также 33fbc67 `-pin`, 3c2a455 persist snapshot). В `data\app.so` v25 есть строка `-ech`, но нет `-pin` → окно сборки [95d85cb … 33fbc67), т.е. ровно 95d85cb.

**Почему это может выглядеть как «не работает» у пользователя:** без ECH внешний ClientHello veil открывает реальный SNI `kal.mergescribe.dev` вместо cover-имени (`us-ech.milky.homes`). На фильтруемом пути (SNI-блокировка ТСПУ) handshake режется → таймаут коннекта. На чистой сети (наш тест) сервер принимает veil и без ECH — туннель работает, дефект невидим. Т.е. сетевой путь пользователя решает, «работает» или нет.

**Разница 24→25:** единственный коммит `95d85cb` — добавляет в `_argsFor` `-ech`/`-cover=false` (мёртвый код: ech/cover всегда null после `_identified`) и Windows-текст для UAC-denied. Функциональной регрессии между 24 и 25 нет; бинарно различаются milkyvpn.exe/app.so/kal2-client.exe (пересборка), flutter_windows.dll идентичен.

## Прочие находки

- Логов приложение не пишет: `%LOCALAPPDATA%\MilkyVPN` (кроме unins000.dat), `%APPDATA%\homes.milky\milkyvpn\` — только prefs и secure storage. kal2-client stderr теряется в pipe родителя. При полевом «не работает» собирать нечего — стоит добавить запись stderr в файл.
- «Обновить» на странице подписки для link-only импорта показывает «Подписка не добавлена» (нечего перезапросить) — ожидаемо, но формулировка сбивает.
- Инсталлятор при тихой переустановке убивает запущенный VPN-процесс (taskkill /F) — при live-апдейте туннель оборвётся без подтверждения.
- Запланированный `[Run]` postinstall-launch пропускается в silent-режиме (`skipifsilent`) — ок.

## Проверенные пути/логи

- Event Log Application (300 последних, уровень Error/Warning, фильтр milky|kal2|flutter) — пусто.
- `%LOCALAPPDATA%\MilkyVPN` — дерево + хэши файлов (выше).
- `%APPDATA%\homes.milky\milkyvpn\shared_preferences.json` = `{"flutter.onboarding_done":true}`.
- `HKCU\…\Internet Settings` ProxyEnable/ProxyServer — выставляется/снимается корректно.
- `netstat` — слушатель `127.0.0.1:11808` живёт только при подключении.
- Репозиторий: ветка сборки `devin/1790199091-kal2-universal-subscriptions` (workflow `windows-package.yml`, tag = run_number; теги указывают на main HEAD — это артефакт action-gh-release, не реальный source ref).

## Файлы-свидетельства

- `shot-01-onboarding.png` — онбординг.
- `shot-02-imported.png` — «Подписка добавлена, 1 профиль найден».
- `shot-03-settings.png` — «Полный туннель» OFF.
- `shot-04-connected.png` / `shot-05-reconnected.png` — «Подключено/Защищено» + идущий таймер.
- Экспорт профиля (clipboard → decode) — verbatim выше в §5.
- Command line kal2-client — verbatim в §7.

Установленная копия оставлена на месте (`%LOCALAPPDATA%\MilkyVPN`, приложение запущено и подключено); вспомогательная копия v24 — `%TEMP%\mv24`.
