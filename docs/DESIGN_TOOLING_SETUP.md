# MilkyVPN — инструменты для дизайна

Дата настройки: 7–8 сентября 2026.

## Готовые подключения

| Инструмент | Установка и проверка |
|---|---|
| Figma | Уже подключена. Авторизованный `whoami` выполнен успешно; дубликат подключения не создавался. |
| Генерация изображений | Встроенный инструмент Codex доступен; отдельная установка и API-ключ не требуются для этого инструмента. |
| Dart / Flutter MCP | Добавлен сервер `dart`: Dart 3.9.2 из Flutter 3.35.4 проекта. MCP initialize и tools/list прошли; доступны 19 инструментов, корень MilkyVPN зарегистрирован через add_roots. |
| Mobile Next MCP | Локально установлен `@mobilenext/mobile-mcp@1.0.2`, mobilecli 1.0.0; Node 24.13.0. MCP initialize, tools/list и запрос устройств прошли; доступны 27 инструментов. Телеметрия выключена параметром сервера. |
| Blender + официальный Blender Lab MCP | Установлен Blender 5.2.1 LTS portable x64, SHA-256 архива сверена с официальной. Add-on / пакет 1.0.0, commit 4309a396, отдельный Python MCP SDK 1.30.0. Сервер `blender`: 26 инструментов; реальное создание, чтение и удаление тестового mesh прошли. Из сохранённой конфигурации отдельно проверено чтение версии и сцены. |

Dart использует существующий SDK проекта: `D:/vpnapp/.toolchains/flutter`. Обновление Flutter и зависимостей приложения не выполнялось. Для дерева виджетов и hot reload понадобится запущенная debug/profile-сборка с Dart Tooling Daemon; текущая release-сборка таким подключением не проверялась.

Mobile Next установлен в `D:/vpnapp/.toolchains/design-mcp/mobile-next`. Версия пакета закреплена в package.json и package-lock.json. Команда запуска использует абсолютный путь к node.exe и установленному index.js; при каждом запуске пакеты заново не скачиваются. Android SDK задан только окружением MCP: `D:/vpnapp/.toolchains/android-sdk`.

Во время настройки физический телефон не был доступен ADB; наблюдался только offline-эмулятор. Mobile Next корректно вернул пустой список доступных устройств. Чтение accessibility tree, снимки экрана и нажатия на реальном телефоне в этой установочной проверке не выполнялись. При будущей работе сначала использовать список элементов интерфейса, снимки — для визуальной проверки или недостаточного дерева доступности.

## Запуск Blender

Blender установлен в `D:/vpnapp/.toolchains/blender/blender-5.2.1-windows-x64`. Дополнение уже включено; соединение с ним разрешено только через localhost `127.0.0.1:9876`.

- Для обычного окна Blender: `D:/vpnapp/.toolchains/design-mcp/blender-labs/Start-Blender-MCP.cmd`.
- Для фоновой работы агента: `D:/vpnapp/.toolchains/design-mcp/blender-labs/Start-Blender-MCP-Headless.ps1`.
- Сначала запускается Blender одним из этих способов, затем используются его MCP-инструменты. Сам stdio MCP-сервер не открывает Blender автоматически.
- В фоновом режиме доступны работа со сценой и рендеринг; снимки окна/области Blender и навигация по вкладкам требуют обычного окна.
- Тестовые Blender-процессы завершены после проверок; постоянный фоновый процесс не оставлен.

У официального пакета обнаружена несовместимость с MCP SDK 2.x: его код использует API FastMCP из 1.x. Совместимая версия 1.30.0 закреплена в `D:/vpnapp/.toolchains/design-mcp/blender-labs/constraints-runtime.txt`; не обновлять это окружение без повторной проверки. Metadata tests официального сервера: 41/41 PASS. Протокольная проверка: 26 инструментов, корректное отклонение неверных аргументов и структурированная ошибка при исключении в Blender.

## Конфигурация и проверка

- Общая конфигурация: `C:/Users/user/.codex/config.toml`.
- Резервная копия до установки: `C:/Users/user/.codex/config.toml.before-design-mcp-20260907`.
- Проверка stdio-серверов: `D:/vpnapp/.toolchains/design-mcp/probe_mcp.py`.
- Результаты Dart: `D:/vpnapp/.toolchains/design-mcp/dart-verification.json`.
- Результаты Mobile Next: `D:/vpnapp/.toolchains/design-mcp/mobile-mcp-verification.json`.
- Результаты Blender из итоговой конфигурации: `D:/vpnapp/.toolchains/design-mcp/blender-verification.json`.
- Создание/чтение/удаление mesh: `D:/vpnapp/.toolchains/design-mcp/blender-labs/verify_install.py`.

В ходе добавления серверов CLI Codex 0.153.4 убрал два поля старых подключений и изменил тип числа тайм-аута. Эти изменения восстановлены из резервной копии; проверено сохранение остальных значений. Конфигурации Codex Router, работающего Hiddify и сетей не менялись.

Новые серверы проверены отдельным MCP-клиентом. Чтобы загрузить их инструменты в уже открытую сессию, обновите серверы через Settings → MCP servers → Restart. Это штатный способ применения конфигурации в [документации Codex](https://learn.chatgpt.com/docs/extend/mcp?surface=cli). Перезапуск Codex Router не нужен.

## Репозитории для будущего изучения интерфейса

- `D:/vpnapp/hiddify-app` — полноценный Flutter-проект. Главный экран: `lib/features/home/widget/home_page.dart`; кнопка подключения: `lib/features/home/widget/connection_button.dart`; тема: `lib/core/theme/app_theme.dart`; адаптивная навигация: `lib/core/router/adaptive_layout/my_adaptive_layout.dart`. Исходники и ресурсы не переносились в MilkyVPN.
- `D:/vpnapp/happ` — checkout содержит README.md и release-метаданные; исходников интерфейса в нём нет.

Исходники MilkyVPN, его UI и VPN-ядро в рамках установки инструментов не изменялись. Статус испытаний мобильной сети из ANDROID-DEVICE-001 этим документом не пересматривается.

## Источники

- [Dart MCP, официальный репозиторий](https://github.com/dart-lang/ai/blob/main/pkgs/dart_mcp_server/README.md).
- [Mobile Next MCP, репозиторий разработчика](https://github.com/mobile-next/mobile-mcp).
- [Blender Lab MCP, официальный репозиторий](https://projects.blender.org/lab/blender_mcp).
- [Figma MCP, официальная документация](https://developers.figma.com/docs/figma-mcp-server/).

## CQ

Проверены рекомендации по Windows/MCP. Сведения о тайм-аутах OAuth и ACL секретных файлов не требовали изменений для этой установки. Файлы JSON/TOML читаются с учётом UTF-8 BOM. Новое наблюдение о потере посторонних полей при `codex mcp add` сохранено в CQ: `ku_670236e63ae74a69a7f68ab19cf161db`.

Совместимость Blender Lab MCP с SDK 1.x: `ku_8d024107d3ed4dd6b15a5793c58bdf2d`. При завершении тестовых Blender-процессов использованы рекомендации о проверке точного PID и пути исполняемого файла.
