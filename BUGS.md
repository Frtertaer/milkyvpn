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

## Открытые / известные ограничения

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
