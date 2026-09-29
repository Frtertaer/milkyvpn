# BUGS — реестр известных багов

Правило проекта: **баг не считается закрытым, пока нет регрессионного теста.**
Каждая запись ссылается на GitHub Issue (создаётся по шаблону
`.github/ISSUE_TEMPLATE/bug_report.yml`); фикс → PR с тестом → запись
переводится в `FIXED` со ссылкой на PR и тест.

## Формат записи

```
### BUG-<YYYY-MM-DD>-<nn> — <короткое название>
- Severity: block | major | minor
- Platform: android | ios | windows | linux | macos | core | protocol
- Status: open | fixing | fixed-in-PR | verified
- Repro: <минимальные шаги>
- Found by: <сессия/трек/CI-джоба>
- Issue: #N   PR: #M   Regression test: <путь::тест>
```

## Закрытые (linux/macos TUN-трек, PR: —)

### BUG-2026-09-29-01 — tun read: `/dev/net/tun: not pollable` (сессия умирает мгновенно)
- Severity: block (TUN полностью не работает на ядрах/сэндбоксах, где
  EPOLL_CTL_ADD на chardev запрещён — VM с seccomp-фильтром, часть
  контейнерных рантаймов)
- Platform: linux (+ macos через общий fileDevice)
- Status: verified (live: kal2-client -tun, 53s+ сессия, трафик через туннель)
- Repro: запустить `kal2-client -tun` на VM с запрещённым EPOLL_CTL_ADD →
  `tun read: /dev/net/tun: not pollable`, ни один пакет не доходит
- Found by: linux/macos-track verification session
- Issue: —  PR: —  Regression test: internal/tun/tun_linux_test.go::TestReadPacketOnCharDevice,
  ::TestFdDevicePacketRoundTrip
- Fix: `fileDevice.ReadPacket`/`WritePacket` переведены на raw
  `unix.Read`/`unix.Write` (blocking fd, EINTR-retry) — без runtime poller

### BUG-2026-09-29-02 — первая сессия умирает через ~18s после поднятия /1-маршрутов
- Severity: major (каждый запуск теряет первую сессию; ~1-2s даунтайм
  и лишний хендшейк в логах DPI)
- Platform: linux, macos
- Status: verified (live: `grep -c "session lost"` = 0 за 53s после старта)
- Repro: `kal2-client -tun` → session up → через ~18s `session lost;
  redialing` → restored. Причина: Dial первой сессии идёт до того, как
  tun.Configure опубликует egress-dev в BindGuard — сокет без
  SO_BINDTODEVICE, и после установки 0.0.0.0/1 его пакеты уходят в туннель
- Found by: linux/macos-track verification session
- Issue: —  PR: —  Regression test: — (интеграционный порядок
  Dial/Configure; проверено live)
- Fix: `main.go` сидит `bindGuard.Set(tun.DefaultEgress())` до первого
  `kal2core.Dial`, когда включён -tun

### BUG-2026-09-29-03 — /32 bypass-маршруты к серверу остаются после kill -9
- Severity: major (остаточный host-route: после аварийной смерти клиента
  весь трафик к VPN-серверу идёт мимо любых будущих туннелей — тихая
  утечка + гарантированный ресёрч при диагностике)
- Platform: linux, macos
- Status: verified (live: kill -9 → `ip route` чисто, ни одного маршрута
  и устройства; ноль записей к 23.133.88.167)
- Repro: `kal2-client -tun` → `kill -9` → `ip route` показывает
  `<server>/32 via <gw>` — dev-scoped /1 чистятся ядром, а bypass-маршрут
  через default gw — нет
- Found by: linux/macos-track verification session
- Issue: —  PR: —  Regression test: internal/tun/tun_linux_test.go::TestBindGuardControlBindsSocket,
  ::TestBindGuardControlIgnoresNonIPNetworks, ::TestBindGuardEmptyDevIsNoop
- Fix: bypass-маршруты заменены на `BindGuard` (SO_BINDTODEVICE на Linux,
  IP_BOUND_IF/IPV6_BOUND_IF на Darwin) — сокет привязан к egress,
  FIB-записей нет, ревертить нечего. Бонус: работает и для hostname-сервера,
  и для смены /32 при ротации endpoint'ов

### BUG-2026-09-29-04 — defaultRoute парсит весь `ip route` одним Fields()
- Severity: minor (нужно ≥2 default-строк: multipath/стейл DHCP)
- Platform: linux
- Status: verified
- Repro: `default via A dev eth0` + `default via B dev wlan0` → старый код
  мог собрать gw=A, dev=wlan0 → BindGuard привязывал сокет не к тому
  интерфейсу
- Found by: linux/macos-track code review during live session
- Issue: —  PR: —  Regression test: internal/tun/tun_linux_test.go::TestParseDefaultRoutePairsWithinFirstLine,
  ::TestParseDefaultRouteNoDefault
- Fix: `parseDefaultRoute` читает только первую default-строку и собирает
  via/dev внутри неё

### BUG-2026-09-29-05 — Darwin: ifname utun содержит NUL-хвосты
- Severity: major на macOS (configure() падал бы на первом же exec
  `ifconfig`/`route` с NUL в аргументе — untested-path до этого трека)
- Platform: macos
- Status: fixed-in-PR (compile-verified; live на macOS не прогонялось)
- Repro: `ifname` из `unix.GetsockoptString(..., SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`
  возвращает NUL-padded буфер — `ifconfig utun5\0\0...` → exec reject
- Found by: linux/macos-track code review
- Issue: —  PR: —  Regression test: internal/tun/tun_linux_test.go::TestCstrTrimsNUL
- Fix: `cstr()` обрезает по первому NUL; применён к ifname и ifreq-именам

### BUG-2026-09-29-06 — SIGTERM/ctl-stop не вызывал tun.Restore
- Severity: major (graceful exit оставлял /1-маршруты и устройство —
  снаружи выглядит как SIGKILL-резидуум)
- Platform: linux, macos
- Status: verified (live: SIGTERM → routes/device чисто, egress работает)
- Repro: `kal2-client -tun` → SIGTERM → `ip route` всё ещё содержит
  0.0.0.0/1 + 128.0.0.0/1 и устройство milky0. Причина: `tun.Run` шёл в
  горутине с `context.Background()` — ни ctl.stopCh, ни сигнал его не
  останавливали
- Found by: linux/macos-track verification session
- Issue: —  PR: —  Regression test: — (lifecycle; проверено live)
- Fix: `signal.NotifyContext`(SIGINT/SIGTERM) проброшен в `tun.Run`;
  main ждёт `tunDone` до 4s после любого выхода

### BUG-2026-09-29-08 — Darwin: IP_BOUND_IF всё равно даёт ENETUNREACH без /32
- Severity: major (на macOS bound-сокет к серверу умирает при первой
  ревалидации маршрута — сессия живёт ~45s и теряется)
- Platform: macos
- Status: verified (live: сессия держится, `route -n get <srv>` → /32 via
  LAN-gw; без него bound connect() → `network is unreachable`)
- Repro: `kal2-client -tun` на macOS → после установки 0.0.0.0/1+128.0.0.0/1
  сокет с IP_BOUND_IF всё равно резолвит dst через FIB — /1 через utun
  побеждает default → connect ENETUNREACH. На Linux SO_BINDTODEVICE этому
  иммунен — тот же BindGuard на darwin недостаточен
- Found by: live macOS run (utun4, en0 172.16.5.2)
- Issue: —  PR: —  Regression test: internal/tun/bind_darwin_test.go::
  TestEnsureAndRestoreBypass, ::TestEnsureReplacesStaleRoute
- Fix: BindGuard на darwin поддерживает scoped `/32 <ip> -gateway <gw>`
  для каждого bypassable-адреса из Control() + `ServerIPs` через
  `EnsureIPs`; `route add` на дубликат молча exit 0 → безусловный
  delete+add + verify по полю `destination:` (`route get` отвечает и по
  крывающему /1)

### BUG-2026-09-29-09 — Darwin: /32 bypass'ы переживают kill -9
- Severity: major (после аварии host-route к серверу остаётся — тихий
  обход любых будущих туннелей)
- Platform: macos
- Status: verified (live: kill -9 → janitor-потомок удалил все /32 за
  <1s; SIGTERM-путь — Restore)
- Repro: `kal2-client -tun` → `kill -9` → `/32 23.133.88.167 via gw`
  остаётся в таблице (dev-scoped /1 умирают с utun, а host-route нет)
- Found by: live macOS run
- Issue: —  PR: —  Regression test: cmd/kal2-client/janitor_darwin_test.go::
  TestJanitorCleanupDeletesRoutes, ::TestJanitorCleanupNoLedger
- Fix: ledger `/tmp/kal2-bypass-<pid>.routes` пишется ДО `route add`;
  отцепленный ребёнок `-route-janitor` (Setpgid) каждые 300ms проверяет
  parent (ppid==1 / ESRCH) и реплеит ledger как `route delete -host`;
  Restore() чистит hosts+ledger на graceful exit

### BUG-2026-09-29-10 — Darwin: Control ставил /32 для loopback/private
- Severity: major (один /32 на 127.0.0.1 через LAN-gw ронял ВЕСЬ loopback:
  curl 127.0.0.1 → EADDRNOTAVAIL — убивал и socks-dial, и весь host)
- Platform: macos
- Status: verified (live: после фикса loopback живёт, туннель работает)
- Repro: tun → netstack → `cfg.OpenTCP(127.0.0.1:11808)` (local SOCKS) —
  Control видел bind-адрес/loopback-hairpin и ставил bypass-роут
  `127.0.0.1/32 via 172.16.5.1`
- Found by: live macOS run (loopback умер прямо под нагрузкой)
- Issue: —  PR: —  Regression test: internal/tun/bind_darwin_test.go::
  TestControlSkipsLoopbackAndPrivate
- Fix: `bypassable(ip)` — только public unicast (нет loopback/private/
  link-local/multicast/unspecified); Control рано выходит до bind'а для
  не-bypassable; EnsureIPs фильтрует тем же правилом

### BUG-2026-09-29-11 — Darwin: utun input AF-префикс big-endian
- Severity: critical (ВЕСЬ inbound через туннель молча умирал: SYN-ACK
  писался в fd, write(2) отвечал успехом, ядро выбрасывало пакет до
  bpf/host-stack — TCP вис в SYN_SENT, UDP-приёмник тоже голодал)
- Platform: macos
- Status: verified (live: после BE — `curl https://apple.com` → 200 через
  туннель, ifconfig.me → IP сервера, tcp flow'ы завершают handshake)
- Repro: `kal2-client -tun` → любой TCP через туннель → tcpdump на utun
  видит SYN + SYN-ACK на проводе, но хост их не принимает; tcp_input
  счётчики чистые — пакет дропается в utun_input на невалидном family
- Found by: live macOS run + инструментированные счётчики стека
  (in tcp=N, valid=N, out>0 — а на хосте ноль)
- Issue: —  PR: —  Regression test: internal/tun/device_unix_test.go::
  TestWritePacketAFPrefixBigEndian
- Fix: `WritePacket` пишет 4-байтный AF-префикс `binary.BigEndian`
  (ядро читает его ntohl'ом); раньше был LittleEndian → family 0x02000000
  → silent drop. UDP «работал» только по направлению host→netstack —
  ответы хосту тоже не доходили

### BUG-2026-09-29-12 — Darwin: ядро молча сносит /32 при down egress'а
- Severity: major (после `ifconfig en0 down/up` или смены сети /32
  исчезает из FIB, а hosts-map BindGuard'а верит, что он установлен —
  carrier-редиал уходит через туннель в самопетлю и сессия не
  восстанавливается)
- Platform: macos
- Status: verified (live: en0 down 8s → /32 удалён ядром → session lost
  → redial → ensureLocked переверил и пересоздал → сессия поднялась,
  трафик снова через сервер)
- Repro: `kal2-client -tun` → `sudo ifconfig en0 down; sleep 8;
  ifconfig en0 up` → `route -n get <srv>` показывает `destination:
  default` вместо /32; старый ensureLocked видел `hosts[s]` и
  early-return'ил
- Found by: live macOS run (en0 flap)
- Issue: —  PR: —  Regression test: покрыто поведением ensureLocked
  (verify-by-route-get перед skip) — юнит-эквивалент в
  bind_darwin_test.go::TestEnsureReplacesStaleRoute; live-цепочка
  flap→lost→recover задокументирована выше
- Fix: `ensureLocked` больше не доверяет hosts-map: `route -n get <ip>`
  должен ответить destination==ip И gateway==текущий, иначе
  безусловный delete+add. hosts-map остаётся только ledger для Restore

## Закрытые (iOS-трек, milky-app)

### BUG-2026-09-29-13 — iOS: prepare() сохраняет пустой proto → VPN-consent невозможен
- Severity: block (первый запуск на девайсе: `prepare()` →
  saveToPreferences → NEVPNErrorDomain Code=1 "Missing server address" →
  Dart видит vpn_permission_denied — connect() недостижим; в симуляторе
  дополнительно нет nehelper — IPC failed)
- Platform: ios
- Status: fixed-in-PR (в sim NE нет вообще — полноценная проверка только
  на железе; XCTest пинает инвариант «proto для save всегда валиден»)
- Repro: fresh install → Import kal2:// → Connect → prepare() падает до
  prompt'а "Add VPN Configuration"
- Found by: iOS sim integration run (iPhone 17, iOS 26.5)
- Issue: —  PR: #30  Regression test:
  ios/RunnerTests::testPlaceholderProtocolIsSaveable
- Fix: prepare() сохраняет placeholderProtocol() — полный
  NETunnelProviderProtocol (providerBundleIdentifier +
  placeholder serverAddress + includeAllNetworks); connect() переписывает
  его реальным configuredProtocol(configJSON:profile:)

### BUG-2026-09-29-14 — iOS: kal2ConfigJSON теряет ech/cover и половину carrier'ов
- Severity: major (ECH-параметр из kal2:// ссылки отбрасывался → внешний
  TLS без ECHConfigList; cover-флаг терялся → DPI-шум всегда дефолтный;
  carriers cdn/mosaic/quasar сворачивались в auto вместо явного выбора)
- Platform: ios
- Status: fixed-in-PR
- Repro: подключиться профилем с ech=…&cover=0&carrier=mosaic → в JSON,
  уходящий в Kal2mobileStart, нет ни ech, ни cover, carrier=auto
- Found by: iOS sim run (code review против android/Kal2Config.toJson)
- Issue: —  PR: #30  Regression test:
  ios/RunnerTests::testKal2ConfigJSONPassesEchCoverAndCarriers
- Fix: kal2ConfigJSON пишет ech + cover(=false только при "0"/"false") и
  принимает veil/drift/cdn/mosaic/quasar — паритет с Android

### BUG-2026-09-29-15 — Diagnostics показывает «Windows 26.5» на iOS
- Severity: minor
- Platform: ios
- Status: fixed-in-PR
- Repro: iOS → Diagnostics → platform label
- Found by: iOS sim run
- Issue: —  PR: #30  Regression test:
  test/milky_device_test.dart::platformLabel maps every supported platform
- Fix: platformLabel — switch по platform (ios/macos/android/windows)
  вместо бинарного android|Windows

### BUG-2026-09-29-16 — Текст permission-ошибки упоминает Android на iOS
- Severity: minor
- Platform: ios
- Status: fixed-in-PR
- Repro: отклонить/провалить VPN-consent на iOS → баннер «Android не
  разрешил создать VPN-туннель»
- Found by: iOS sim run
- Issue: —  PR: #30  Regression test: — (строка, не логика)
- Fix: permissionDenied-копия ветвится по Platform.isIOS/isMacOS —
  «Разрешите добавление конфигурации VPN»

## Открытые / известные ограничения

### iOS: NetworkExtension недоступен в симуляторах (платформенное)
- Не баг нашего кода: в iOS Simulator нет nehelper/nesessionmanager/
  neagent — `loadAllFromPreferences` → "Connection invalid"/IPC failed на
  26.5 и 27.0. NEPacketTunnelProvider проверяется только на физическом
  девайсе. Что реально прогнано вместо него: сборка Runner+PacketTunnel
  под sim (после установки iOS platform component), XCTest-набор,
  `kal2mobile.Start`→SOCKS→HTTPS на живом macOS (тот же путь, что
  вызывает MirageBridge), RSS ≈22MB под нагрузкой 20 параллельных
  10MB-потоков (heap ~1.6MB, плато — утечки нет).

### BUG-2026-09-29-07 — idle-сессия под «тихим» blackhole не детектируется
- Severity: minor
- Platform: core
- Status: open (by design до -cover)
- Repro: `iptables -A OUTPUT -d <server> -j DROP|REJECT` на работающей
  сессии без `-cover` → TCP ESTAB без трафика → watchdog ждёт ошибку
  carrier'а, которая придёт только на первой записи. За 3 минуты — ноль
  детектов. Реальная смена сети (link flap, RST) детектируется нормально.
- Found by: linux/macos-track verification session
- Issue: —  PR: —  Regression test: —
- Note: фикс = app-level keepalive; это уже функция `-cover` (jittered
  PINGs 6-18s). Задокументировано, не чинится в этом треке.
## Windows-трек (PRs и фиксы — из параллельного реестра; id +16)

### BUG-2026-09-29-17 — Windows: `ech=` теряется при импорте kal2:// профиля
- Severity: major (stealth-регрессия: veil hello светит реальный SNI)
- Platform: windows (+ любой клиент на общем `subscription_parser`)
- Status: fixed-in-tree (`5df3cc9`), needs release rebuild ≥ `5df3cc9`
- Repro: импортировать kal2-ссылку с `ech=` → экспорт/лог клиента показывает
  запуск `kal2-client` без `-ech` → внешний SNI = `kal.mergescribe.dev`
  вместо cover-имени
- Found by: windows-track verification session
- Issue: —  PR: —  Regression test: subscription_parser round-trip

### BUG-2026-09-29-18 — Windows: клиент нигде не пишет логи
- Severity: major (полевая диагностика невозможна)
- Platform: windows
- Status: fixed-in-PR
- Repro: любой сбой `kal2-client.exe` — stderr проглатывается родителем,
  в `%APPDATA%\homes.milky\milkyvpn` логов нет
- Fix: `kal2-client -log <path>` пишет собственный лог (ротация .1 > 1 МБ);
  мост передаёт `%APPDATA%\homes.milky\milkyvpn\logs\kal2-client.log`
  в обоих режимах (SOCKS и elevated -tun helper)
- Found by: windows-track verification session
- Issue: —  PR: —  Regression test: `milky-core/cmd/kal2-client/main_test.go`,
  `test/core/windows_vpn_bridge_test.dart`

### BUG-2026-09-29-19 — Windows: silent-переустановка убивает живой туннель
- Severity: minor
- Platform: windows
- Status: fixed-in-PR
- Repro: при активном соединении запустить `MilkyVPN-Setup.exe /VERYSILENT`
  → taskkill по kal2-client без drain'а сессий
- Fix: `PrepareToInstall` шлёт ctl `stop` и ждёт `Wait-Process` (kal2-client
  до 20 с, milkyvpn до 15 с после graceful WM_CLOSE); `/F` только как fallback
- Found by: windows-track verification session
- Issue: —  PR: —  Regression test: `tool/check_installer.py`,
  `milky-core/cmd/kal2-client/main_test.go::TestCtlMirrorAndStop`

### BUG-2026-09-29-20 — Windows: Android-only строка «Always-on VPN» в настройках
- Severity: minor (misleading UI; на Windows tap открывал ms-settings:network-proxy)
- Platform: windows (+ любые non-Android платформы)
- Status: fixed-in-PR
- Repro: Настройки → группа «Подключение» → строка «Always-on VPN /
  Системные настройки Android» показана и на Windows
- Fix: строка рендерится только на `Platform.isAndroid`
- Found by: windows-track verification session (build 25)
- Issue: —  PR: —  Regression test: `test/features/settings_refresh_test.dart`

### BUG-2026-09-29-21 — «Обновить» на link-only профиле показывает «Подписка не добавлена»
- Severity: minor (misleading UX: профили есть, обновлять просто нечего)
- Platform: all (android | ios | windows | macos | linux)
- Status: fixed-in-PR
- Repro: импортировать kal2:// ссылку текстом → Настройки/Подписка → «Обновить»
  → snackbar «Подписка не добавлена», хотя профили есть
- Fix: при `refresh()==null` различаем «вообще ничего не импортировано»
  (`noSubscription`) и «профили из ссылки, обновлять нечего» (`notRefreshable`)
- Found by: windows-track verification session (build 25)
- Issue: —  PR: —  Regression test: `test/features/settings_refresh_test.dart`

### BUG-2026-09-29-22 — Windows: disconnect затирает чужой системный прокси
- Severity: major (для пользователей за корпоративным прокси: их прокси
  теряется безвозвратно после первого disconnect)
- Platform: windows
- Status: fixed-in-PR
- Repro: иметь ProxyEnable=1 + ProxyServer=corp → connect → disconnect →
  ProxyEnable=0 и ProxyServer=оставлен наш `socks=127.0.0.1:11808`
- Fix: при connect снимок `ProxyEnable`/`ProxyServer` через `reg query`;
  на disconnect `restoreProxyPlan` возвращает прежние значения (или
  удаляет наш `ProxyServer`, если его не было); PAC/AutoConfigURL не трогаем.
  Снапшот равный нашему `socks=` значению = маркер утечки после краша —
  считается «не было прокси» (delete + enable=0), иначе утечка вечная
- Found by: static review windows_vpn_bridge (windows track)
- Issue: —  PR: —  Regression test:
  `test/core/windows_vpn_bridge_test.dart::proxy restore plan`

### BUG-2026-09-29-23 — Windows: silent-reinstall при живом elevated -tun helper'е → полу-замена файлов
- Severity: minor (edge: требуется зависший ctl elevated-процесс)
- Platform: windows
- Status: fixed-in-PR
- Repro: elevated -tun helper жив, но ctl не отвечает → `/VERYSILENT`
  reinstall: ctl-stop молчит, `taskkill /F` из non-elevated инсталлятора
  получает Access denied → файлы пишутся поверх работающего exe →
  смешанная старая/новая установка (или ошибка file-in-use)
- Fix: после fallback'а инсталлятор проверяет `Get-Process kal2-client`;
  если жив — PrepareToInstall возвращает сообщение и setup чистно
  абортается («disconnect and run setup again»)
- Found by: static review windows.iss (windows track)
- Issue: —  PR: —  Regression test: `tool/check_installer.py` (guard+
  abort ordering)

### BUG-2026-09-29-24 — Windows: ctl-сокет принимает только одно соединение → orphan -tun helper не остановить
- Severity: major (edge: после краша приложения -tun ломается до taskkill/reboot)
- Platform: windows
- Status: fixed-in-PR
- Repro: GUI -tun connect → elevated helper слушает :11909, app держит conn.
  Краш/убийство приложения → conn умирает БЕЗ 'stop'. Helper жив. Любая
  новая попытка -tun connect: `_stopCtl` пишет 'stop' в backlog (accept уже
  израсходован — одно-разовый), новый helper падает на `net.Listen(:11909)`
  address-in-use → `log.Fatalf`. Также мёртв log-mirror.
- Fix: ctl-accept в цикле — каждая новая conn замещает старую (закрывая её),
  'stop' срабатывает от любого пира; `sync.Once` против двойного close(stopCh)
- Found by: static review kal2-client ctl (windows track)
- Issue: —  PR: —  Regression test:
  `milky-core/cmd/kal2-client/main_test.go::TestCtlSecondPeerCanStop`
  (fails на старом коде — 2.1s timeout)

### BUG-2026-09-29-25 — Windows: `stop` по ctl оставляет /32 host-маршруты (graceful -tun stop)
- Severity: minor
- Platform: windows
- Status: fixed-in-PR
- Repro: -tun connect → ctl 'stop' → `route print`: /32 маршрут до сервера
  через физический шлюз остаётся (подтверждено в поле на build 27). /1
  умирают вместе с адаптером, host-маршрут — нет.
- Fix: `waitForTun` — ctl-'stop' теперь канселит tun-ctx и ждёт (≤15s) пока
  goroutine дойдёт до deferred `dev.Restore()`/`dev.Close()`; раньше `return`
  из main убивал goroutine до defer'ов
- Found by: windows verify session (build 27)
- Issue: —  PR: —  Regression test:
  `milky-core/cmd/kal2-client/main_test.go::TestWaitForTun*`

### BUG-2026-09-29-26 — Windows: лог elevated helper'а пуст после баннера (MultiWriter голод на invalid stderr)
- Severity: medium
- Platform: windows
- Status: fixed-in-PR
- Repro: elevated -tun helper (GUI-subsystem) → `-log` файл содержал только
  '=== started ===' (однажды на 71f9a58; на 97d2ed8 лог писался полностью —
  stderr там был валиден). Причина-механизм: `io.MultiWriter(os.Stderr,
  logFile)` — невалидный stderr handle у спавненного процесса → первый Write
  падает → все последующие sink'и голодают.
- Fix: `failsoft` — wrapper, глотающий Write-ошибку каждого sink'а
  независимо (stderr/file/ctl)
- Found by: windows verify session (fix-билд)
- Issue: —  PR: —  Regression test:
  `milky-core/cmd/kal2-client/main_test.go::TestFailsoftKeepsChainAlive`

### BUG-2026-09-29-27 — Windows: прокси остаётся на мёртвом listener'е при фейле коннекта
- Severity: major
- Platform: windows
- Status: fixed-in-PR
- Repro: клиент умирает ПОСЛЕ 'session up' но во время `_applyProxy`
  (напр. :11808 занят → ServeSocks fatal): exit-handler'овский `_restoreProxy`
  срабатывает no-op до `_proxySet=true` → `socks=` остаётся выставленным на
  мёртвый/чужой листенер → трафик юзера в refused/blackhole
- Fix: после `_applyProxy` — проверка `_proc == null` → синхронный
  `_restoreProxy` + `core_exit` (раньше `_set(connected)` шёл без проверки)
- Found by: windows verify session (build 27)
- Issue: —  PR: —  Regression test: `tool/check_windows_bridge.py`
  (ordering-gate: applyProxy → alive-check → connected)

### BUG-2026-09-29-28 — Windows: GUI -tun падает с tun_uac_denied у профилей без path
- Severity: critical (GUI -tun мёртв для любого профиля без drift-path)
- Platform: windows
- Status: fixed-in-PR
- Repro: профиль без `path` → `-drift ''` в arg list → tun path через
  `Start-Process -Verb RunAs -ArgumentList` → PowerShell
  ParameterBindingValidation («argument is null or empty») → exit 1 → мост
  маппит в `tun_uac_denied`. Не UAC, не EnableLUA — ломается на любом боксе.
- Fix: `_argsFor` опускает пары flag+value с пустым value (все флаги
  клиента дефолтятся в ""; Go flag pkg к тому же съел бы следующий токен
  как значение пустого флага)
- Found by: windows verify session (fix-билд, уточнение «EnableLUA» диагноза)
- Issue: —  PR: —  Regression test:
  `test/core/windows_vpn_bridge_test.dart` — path-less → нет ''/-drift;
  drift path → сохраняется

## Carrier/mux (carrier-stress трек, PR #29)


### BUG-2026-09-29-13 — mux: конкурентные Ping гонятся за pongReg → ложный pong-timeout
- Severity: major (сторож lanes читает таймаут как смерть lane →
  ложный kill живого лейна; под -race — data race на поле сессии)
- Platform: core (kal2 mux — все платформы, все lanes-клиенты)
- Status: fixed-in-PR
- Repro: `client.Ping(...)` из двух+ горутин одновременно:
  `registerPong` без синхронизации перезаписывает `s.pongReg` — второй
  caller перехватывает канал ответа, первый получает `pong timeout`
  на живой сессии. `go test -race` — гонка readLoop(dispatch/pongCh) ×
  Ping(registerPong/unregisterPong)
- Fix: `pongQ []chan []byte` — FIFO-очередь waiters под `pongMu`;
  каждый входящий PONG удовлетворяет самый старый ожидающий Ping
  (упорядоченный carrier возвращает эхо в порядке запросов)
- Found by: carrier-track stress session (recon + repro-тест)
- Issue: —  PR: —  Regression test:
  `milky-core/internal/kal2/stress_test.go::TestMuxConcurrentPings`

### BUG-2026-09-29-14 — lanes: задушенный lane собирает все новые стримы
  (kill-vs-quarantine инверсия)
- Severity: major (scorecard-контракт нарушен: живой-но-задушенный lane
  не подпадает под kill-путь — pong приходит — но монополизирует роутинг)
- Platform: core (kal2core Client lanes)
- Status: fixed-in-PR
- Repro: два lanes: здоровый и задушенный (pong приходит, но медленно).
  `Session()` выбирал least-`SentBytes` → у задушенного почти нет emitted
  байт → он выглядит «свежим» и получает ВСЕ новые стримы, ползая на
  черепашьей скорости, пока здоровый простаивает
- Fix: `laneRTT` scorecard — сторож записывает RTT последнего успешного
  pong на lane; `Session()` пропускает lanes с `laneRTT > laneQuarantineRTT`
  (3s), пока жив хотя бы один здоровый; все задушены → fallback на
  least-loaded. Убитый lane (2 реальных ping-фейла) kill'ается и
  редиалится как раньше — kill-vs-quarantine разведены
- Found by: carrier-track stress session (contract review + repro-тест)
- Issue: —  PR: —  Regression test:
  `milky-core/pkg/kal2core/lanes_test.go::TestLaneStrangledQuarantinedNotKilled`,
  `TestLaneDeadKilledAndRedialed`, `TestLaneAllQuarantinedFallback`

### BUG-2026-09-29-15 — mux: карта streams течёт на remote close
- Severity: major (unbounded leak: долгоживущая сессия накапливает zombie-
  entry на каждый закрытый пиром стрим → рост RSS на длинном soak'е;
  15-мин -race soak был убит OOM-киллером через ~6.5 мин)
- Platform: core (kal2 mux — все платформы)
- Status: fixed-in-PR
- Repro: пир закрывает стрим (`MsgClose`) или сбрасывает (`MsgRst`):
  `remoteClose()`/`reset()` помечали stream closed, но НИКОГДА не удаляли
  запись из `s.streams`. Локальный `Stream.Close()` удалял — удалённый
  конец нет. Server-side за churn-прогон скапливал по записи на стрим
- Fix: evict в терминальной точке жизненного цикла — pump удаляет запись
  после EOF-дрейна (graceful), `reset()` удаляет немедленно (abrupt);
  half-close ordering сохранён (данные до MsgClose доставляются)
- Found by: carrier-track mux -race soak (killed at ~395s) + map audit
- Issue: —  PR: —  Regression test:
  `milky-core/internal/kal2/stress_test.go::TestMuxRemoteCloseEvicts`

### BUG-2026-09-29-16 — mux: SetReadDeadline/SetWriteDeadline были no-op
- Severity: major (net.Conn-контракт сломан: любой код, полагающийся на
  deadline — SOCKS idle timeout, churn-читатели — блокируется навсегда;
  15-мин soak завис именно так: ReadFull в churn-воркере никогда не
  возвращался)
- Platform: core (kal2 mux — все платформы)
- Status: fixed-in-PR
- Repro: `st.SetReadDeadline(now+300ms); st.Read(buf)` без входящих данных
  → блок навсегда вместо timeout-ошибки; `SetWriteDeadline` + переполненная
  data-lane → блок навсегда на slot-токене
- Fix: `readDeadline`/`writeDeadline` (atomic ns) на stream; Read ждёт
  recvCh/closedCh/timer → `os.ErrDeadlineExceeded`; Write гонит чанки через
  `sendRecordDeadline` — timeout-селект на slot/ctrlCh enqueue
- Found by: carrier-track mux -race soak (hang at ~20m dump)
- Issue: —  PR: —  Regression test:
  `milky-core/internal/kal2/stress_test.go::TestMuxReadDeadlineReal`,
  `TestMuxWriteDeadlineReal`

### BUG-2026-09-29-17 — carrier tests: VeilListener logf вызывал t.Logf после конца теста
- Severity: minor (test-only data race: `-race` FAIL на пакете carrier;
  per-conn goroutine `v.Serve` переживает `tRunner`, лог ловит гонку на
  testing internals / может паниковать «Log after test completed»)
- Platform: core (test harness — internal/carrier e2e helpers)
- Status: fixed-in-PR
- Repro: `go test -race ./internal/carrier` — фоновый TLS-handshake
  handler логирует через `VeilConfig.Logf → t.Logf` после завершения
  теста (детектed на TestVeilSPKIPin teardown × late conn goroutine)
- Fix: `newTestServerWith` буферит строки лога под мьютексом и флашит
  через `t.Log` внутри `t.Cleanup` (пока t валиден); поздние строки дроп
- Found by: carrier-track `go test -race` suite rerun после merge universal
- Issue: —  PR: —  Regression test: `go test -race ./internal/carrier/`
  (ранее флаковал DATA RACE на testing.(*common).destination)

## Трек PROTOCOL — conformance SPEC v2.1

### BUG-2026-09-29-13 — vectors.json: ключевой материал выведен не по формуле §2

- **Severity:** High (test oracle)
- **Platform:** all
- **Status:** FIXED (spec-side)
- **Found by:** `TestVectorHandshakeKeys` / `TestVectorFlights`
- **Issue:** в testdata/vectors.json все HKDF-производные (signature,
  clientRecordKey, serverRecordKey, nonceBase, handshakeVerify, finished,
  resumeSecret, record ciphertext, resume.*, ticket) вычислены с
  `info = mxs-in-v2/transcript/<label>` — без суффикса `/<transcript>`,
  который прямо записан в §2 (`info = mxs-in-v2/transcript/<label>/<transcript>`).
  Реализация соответствует тексту спеки → вектор-файл был непригоден как
  conformance-оракул (любая корректная реализация «не проходила» его).
- **Fix:** `milky-core/cmd/genvec` — генератор векторов по формулам спеки
  (восстановлен удалённый «временный» генератор); vectors.json регенерирован.
  Дескриптор/openTargets/transcript/preauth/migrate совпали байт-в-байт.
- **PR:** spec-side PR в `devin/1790623610-kal2-spec-v2`
- **Regression test:** conformance_test.go — все `keys.*` сверяются с
  спек-формулой в тестовом коде (независимая реализация HKDF).

### BUG-2026-09-29-14 — vectors.json: ticketLen закодирован big-endian

- **Severity:** Medium (test oracle)
- **Status:** FIXED (spec-side)
- **Issue:** `resume.resumeFlight` содержит `ticketLen = 0x004e` (BE 78),
  спека §9.2 требует `[2,LE]` (`0x4e00`). Код PR #7 (`ParseResumeHead`)
  читает LE — вектор непарсабелен спек-имплементацией.
- **Fix:** регенерация vectors.json с LE.
- **Regression test:** `TestVectorResume` — парсинг полёта по LE.

### BUG-2026-09-29-15 — спека §3: порядок payload/padLen/pad в тексте неверен

- **Severity:** Medium (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** текст §3: `ct = AEAD(payload || padLen[2,LE] || pad[padLen])`.
  Имплементация и вектор кладут длину **в конец**: `payload || pad || padLen`.
  Реальное значение несовместимо с текстом.
- **Fix:** правка SPEC.md §3 (spec-side PR).
- **Regression test:** `TestVectorRecord` — impl дешифрует векторную запись.

### BUG-2026-09-29-16 — спека §9.2/9.4: nStreams помечен LE, вектор+код — BE

- **Severity:** Low (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** `nStreams[2,LE]` в тексте против BE в vectors.json
  (`migrate.payload`) и коде PR #7 (checkpoint). Весь wire-формат BE —
  правим текст, не байты.
- **Fix:** SPEC.md §9.2, §9.4 → `[2,BE]`/`[4,BE]`.
- **Regression test:** `TestVectorResume`/`TestVectorMigrate` — BE-парсинг.

### BUG-2026-09-29-17 — неизвестные типы записей <0x80 убивали сессию

- **Severity:** High (forward-compat)
- **Status:** FIXED (code)
- **Issue:** `readRecord` возвращал `ErrFraming` на любой неизвестный тип →
  v2.1-записи (TICKET 0x0A, будущие <0x80) рвали v2-сессию. §12 требует:
  <0x80 — пропускать (AEAD+seq-учёт сохраняется), ≥0x80 — разрыв.
- **Fix:** `session.go` — пропуск неизвестных <0x80 после AEAD-open;
  `protocol.go` — `MsgTicket = 0x0A`.
- **PR:** code PR → `devin/1790199091-kal2-universal-subscriptions`
- **Regression test:** `TestForwardCompatTypes` (0x40/0x0A skip, 0x81 kill).

### BUG-2026-09-29-18 — bound-клиент против unbound-сервера: разрыв вместо фолбэка

- **Severity:** High (interop, проверка (d))
- **Status:** FIXED (code)
- **Issue:** клиент всегда биндил к TLS-exporter; сервер с `binding=∅`
  (спека: «носитель без binding → binding=∅») выдавал signature/handshake
  mismatch → разрыв. Фолбэка на клиенте не было вовсе.
- **Fix:** `ClientConfig.AllowUnboundFallback` (opt-in, дефолт строгий —
  иначе stripping-MitM мог бы молча понизить binding) — один redial
  unbound при падении KAL/2-рукопожатия; `VeilConfig.IgnoreBinding` —
  серверный unbound-режим для смешанных флитов.
- **Regression test:** `TestDialVeilBoundClientUnboundServer`,
  `TestDialVeilUnboundClient` (tolerant / RequireBinding).

### BUG-2026-09-29-19 — §9/§10: resumption/migration и descriptor-публикация не реализованы на impl-ветке

- **Severity:** High (feature gap; проверки (b-resumption), (c), (e-server))
- **Status:** fixed-in-PR #7 (merged) для resumption/migration —
  resume.go, TICKET/MIGRATE, `ResumeAttach`, freeze/migGate/replay
  присутствуют на базе; проверки (b-resumption), (c) выполняются там.
  Остаётся OPEN: §10 server-publish/fetch descriptor'ов (rendezvous
  серверная часть) нигде не реализована.
- **Частично закрыто здесь:** `descriptor.go` — §10.1 парсер (подпись/pin/TTL)
  + `RendezvousPath` (§10.2 keyed path) + тесты против векторов; билет-
  формат и re-key проверены `TestVectorResume` по спек-формулам.

### BUG-2026-09-29-20 — спека: третий полёт (ClientAuthFlight) не описан; §10.2 epoch-энкодинг не определён

- **Severity:** Low (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** impl шлёт `pskMAC(32) || finished(32)` после server flight —
  в §2 не задокументировано; `epoch` в `kal2-rdvs/` || epoch без типа
  сериализации. Обе дыры делают cross-impl conformance недетерминированным.
- **Fix:** SPEC.md — описание третьего полёта + `epoch` как десятичное ASCII.
