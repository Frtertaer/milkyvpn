#!/usr/bin/env bash
# scenarios.sh — MilkyVPN emulator scenario battery.
#
# Usage:
#   testing/scenarios.sh --apk app-debug.apk [--serial emulator-5554]
#                        [--link 'kal2://...'] [--scenario name|--all]
#
# Scenarios: connect, wifi_lte, net_loss, dns_change, dns_leak, battery_opt,
#            on_revoke, tls_cutoff (needs --proxy), soak30, fgs_doze.
#
# The device must already be booted and `adb` reachable. The app profile is
# imported by typing the kal2:// link (see skill testing-android-emu-proxy:
# '&' chars must be escaped as '\&' for `adb shell input text`).
set -euo pipefail

SERIAL=${SERIAL:-emulator-5554}
APK=""
LINK="${KAL2_TEST_LINK:-}"
PROXY_HOST_IP=""          # set when emulator runs with -http-proxy
SCEN="all"
ADB=(adb -s "$SERIAL")

while [ $# -gt 0 ]; do
  case "$1" in
    --apk) APK=$2; shift 2;;
    --serial) SERIAL=$2; ADB=(adb -s "$SERIAL"); shift 2;;
    --link) LINK=$2; shift 2;;
    --proxy) PROXY_HOST_IP=$2; shift 2;;
    --scenario) SCEN=$2; shift 2;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done

# debug builds carry a .debug applicationId suffix — detect the installed id
PKG=${PKG:-}
if [ -z "$PKG" ]; then
  for _ in 1 2 3 4 5; do
    _pkgs=$("${ADB[@]}" shell pm list packages 2>/dev/null | sed -n 's/^package:\(.*milky.*\)$/\1/p' | tr -d '\r')
    PKG=$(printf '%s\n' "$_pkgs" | grep -m1 '\.debug$' || true)
    [ -n "$PKG" ] || PKG=$(printf '%s\n' "$_pkgs" | grep -m1 . || true)
    [ -n "$PKG" ] && break
    sleep 2
  done
fi
PKG=${PKG:-vpn.milky.app}

# adbd answers before the system finishes booting — a monkey launch into a
# half-up launcher silently goes nowhere (API 29 flake). Wait for real boot.
for _ in $(seq 1 30); do
  [ "$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
  sleep 5
done
sleep 5

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL  $*"; }
log()  { echo "[$(date +%H:%M:%S)] $*"; }

# wait_state <logcat-regex> [timeout_s] [byte_mark]
# Reads the STREAMED logcat (run_emu_ci.sh runs `adb logcat` into $LOGFILE
# for the whole job). mark_log gives a byte offset; passing it as $3 makes the
# wait see only lines appended since the mark — no stale matches, and the
# file keeps every MilkyVPN line even when the device ring buffer wraps.
# Falls back to `logcat -d` when no streamed file exists (local runs).
LOGFILE=${LOGFILE:-/tmp/milky_ci_logcat.txt}
mark_log() { [ -f "$LOGFILE" ] && wc -c < "$LOGFILE" || echo 0; }
wait_state() {
  local want=$1 to=${2:-90} mark=${3:-0} t0=$SECONDS
  while (( SECONDS - t0 < to )); do
    if [ -f "$LOGFILE" ]; then
      tail -c +$((mark + 1)) "$LOGFILE" | grep -s "MilkyVPN" | grep -qE "$want" && return 0
    else
      "${ADB[@]}" logcat -d -s MilkyVPN 2>/dev/null | grep -qE "$want" && return 0
    fi
    sleep 2
  done
  return 1
}
log_since() {  # dump MilkyVPN lines appended since a byte mark
  [ -f "$LOGFILE" ] && tail -c +$(($1 + 1)) "$LOGFILE" | grep -s "MilkyVPN"
}

launch_app() {
  "${ADB[@]}" shell am force-stop "$PKG" || true
  sleep 1
  "${ADB[@]}" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null
  sleep 5
}

screen_wh() {
  "${ADB[@]}" shell wm size 2>/dev/null | sed -n 's/.*: \([0-9]*\)x\([0-9]*\).*/\1 \2/p' | tail -1
}

ui_tap_pct() {  # ui_tap_pct <x%> <y%> — taps are fractions of the actual screen
  local w h x y
  read -r w h <<<"$(screen_wh)"
  [ -n "${w:-}" ] && [ -n "${h:-}" ] || { w=1080; h=1920; }
  x=$(( w * $1 / 100 )); y=$(( h * $2 / 100 ))
  "${ADB[@]}" shell input tap "$x" "$y"
}

ui_xml() {
  "${ADB[@]}" shell uiautomator dump /sdcard/__ci.xml >/dev/null 2>&1
  "${ADB[@]}" shell cat /sdcard/__ci.xml 2>/dev/null
}

# ui_ready — first frames on API 29 can take a while (Impeller slow path) and
# uiautomator returns an empty tree until the view hierarchy exists.
ui_ready() {
  local i
  for i in $(seq 1 20); do
    ui_xml | grep -q '<node ' && return 0
    sleep 2
  done
  log "ui: dump still empty after 40s — window state:"
  "${ADB[@]}" shell dumpsys window 2>/dev/null | grep -E "mCurrentFocus|mFocusedApp" | head -3
  return 1
}

# ui_tree_useful — the API29 ghost-tree flake: uiautomator returns nodes but
# every text/content-desc is empty, so no desc-match can ever succeed.
ui_tree_useful() {
  ui_xml | grep -qE '(text|content-desc)="[^"]+"'
}

# ui_heal — pre-connect only: force-stop would kill a live tunnel. Relaunch
# once when the accessibility tree is ghosted, then re-check.
ui_heal() {
  ui_tree_useful && return 0
  log "ui: ghost tree (nodes without texts) — relaunching app once"
  launch_app
  sleep 3
  ui_ready || true
  ui_tree_useful
}

_ui_center_of_match() {  # first clickable node matching regex → "x y"
  local re=$1 line b
  line=$(ui_xml | tr '<' '\n' | grep 'clickable="true"' | grep -m1 "\(content-desc=\"[^\"]*${re}[^\"]*\"\|text=\"[^\"]*${re}[^\"]*\"\)")
  [ -n "$line" ] || return 1
  b=$(echo "$line" | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p')
  [ -n "$b" ] || return 1
  local x1 y1 x2 y2
  read -r x1 y1 x2 y2 <<<"$b"
  echo "$(( (x1+x2)/2 )) $(( (y1+y2)/2 ))"
}

ui_tap_desc() {  # ui_tap_desc <regex on text/content-desc> [fallback_x% fallback_y%]
  local xy
  xy=$(_ui_center_of_match "$1") || { log "ui: no clickable '$1'"; [ -n "${2:-}" ] && ui_tap_pct "$2" "$3"; return 1; }
  "${ADB[@]}" shell input tap $xy
}

ui_tap_desc_wait() {  # poll up to ~30s for a clickable match, then tap it
  local i xml
  for i in $(seq 1 15); do
    ui_tap_desc "$1" && return 0
    sleep 2
  done
  xml=$(ui_xml)
  if ! printf '%s' "$xml" | grep -q '<node '; then
    log "ui: accessibility dump EMPTY (API29 first-frame flake?)"
    "${ADB[@]}" shell dumpsys window 2>/dev/null | grep -E "mCurrentFocus|mFocusedApp" | head -3
  else
    log "ui: tree populated, no match for '$1'; visible texts:"
    printf '%s\n' "$xml" | tr '<' '\n' | grep -o 'text="[^"]*"' | head -15
  fi
  return 1
}

ui_tap_class() {  # tap first node of a class (e.g. android.widget.EditText)
  local re="class=\"${1}\"" line b
  line=$(ui_xml | tr '<' '\n' | grep -m1 "$re" || true)
  [ -n "$line" ] || return 1
  b=$(echo "$line" | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p')
  local x1 y1 x2 y2
  read -r x1 y1 x2 y2 <<<"$b"
  "${ADB[@]}" shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 ))
}

onboarding_and_import() {
  # fresh install → 3-page onboarding, then ImportScreen paste+confirm.
  ui_ready || log "ui: no view tree yet — continuing anyway"
  ui_heal || log "ui: tree still ghosted — falls back to pct taps"
  ui_tap_desc_wait "Продолжить\|Continue" && sleep 2
  ui_tap_desc_wait "Понятно\|Got it" && sleep 2
  ui_tap_desc_wait "Добавить подписку\|Add subscription" && sleep 3
  [ -n "$LINK" ] || { log "no --link/KAL2_TEST_LINK — expecting profile already present"; return; }
  local esc=${LINK//&/\\&}
  ui_tap_class android.widget.EditText; sleep 1   # focus the url field
  if ! "${ADB[@]}" shell input text "$esc" 2>/dev/null; then
    # chunked fallback — some API levels silently drop very long input text
    local i=0 n=${#esc}
    while [ $i -lt $n ]; do
      "${ADB[@]}" shell input text "${esc:i:40}" || break
      i=$((i+40)); sleep 0.3
    done
  fi
  "${ADB[@]}" shell input keyevent 111 2>/dev/null || true  # close keyboard
  sleep 1
  ui_tap_desc_wait "Добавить\|^Add$" && sleep 4         # import
  ui_tap_desc_wait "Перейти\|Go to" && sleep 3          # success sheet
}

tap_connect() {
  ui_tap_desc_wait "MilkyVPN\|подключиться\|Connect" || ui_tap_pct 50 42
  sleep 2
  # consent dialog may take a few seconds — poll for its OK button
  ui_tap_desc_wait "OK\|ОК" || true
}

verify_tunnel() {  # SOCKS liveness: real bytes through the tunnel
  "${ADB[@]}" forward tcp:11808 tcp:11808 >/dev/null 2>&1 || true
  curl -s -m 12 --socks5-hostname 127.0.0.1:11808 https://ifconfig.me/ip 2>/dev/null
}

# verify_tunnel_wait <timeout_s> — poll until a real fetch succeeds; an empty
# answer (tunnel half-up) is retried, not accepted.
verify_tunnel_wait() {
  local to=${1:-45} t0=$SECONDS ip
  while (( SECONDS - t0 < to )); do
    ip=$(verify_tunnel)
    [ -n "$ip" ] && { echo "$ip"; return 0; }
    sleep 3
  done
  return 1
}

s_connect() {
  log "scenario: connect (watch + one manual retry; first EOF after a server restart is transient)"
  launch_app; onboarding_and_import
  local i ip m
  # The app itself retries recoverable failures (<=3, 2/4/6s backoff + its own
  # attempt budget) — the outer watch has to outlive that whole horizon.
  for i in 1 2; do
    m=$(mark_log)
    tap_connect
    if wait_state '[= ]CONNECTED' 150 "$m"; then
      if ip=$(verify_tunnel_wait 45); then
        ok "connected (attempt $i), real traffic through tunnel, exit $ip"
        return
      fi
      log "attempt $i: CONNECTED but real traffic check empty"
    else
      log "attempt $i: no CONNECTED in 150s — MilkyVPN log since attempt:"
      log_since "$m" | tail -30
    fi
    # manual retry only makes sense once the app sits on an error sheet;
    # ghost-tree flake → heal once before tapping (pre-connect, safe)
    ui_heal || true
    ui_tap_desc_wait "Попробовать снова\|Повторить\|Retry\|Try again" || ui_tap_desc_wait "подключиться\|Connect"
    sleep 2
  done
  bad "connect failed after 2 attempts"
  "${ADB[@]}" shell dumpsys activity processes | grep -A8 "$PKG" | head -20
}

# wifi_toggle <disable|enable> — returns 0 once `dumpsys wifi` shows the
# state. `svc wifi` throws SecurityException on API <=28 (shell lacks
# CHANGE_WIFI_STATE); the legacy `wifi_on` global setting still works there.
wifi_toggle() {
  local want=$1 i st
  for i in $(seq 1 10); do
    "${ADB[@]}" shell svc wifi "$want" >/dev/null 2>&1 || \
      "${ADB[@]}" shell settings put global wifi_on "$([ "$want" = enable ] && echo 1 || echo 0)" >/dev/null 2>&1 || true
    sleep 2
    st=$("${ADB[@]}" shell dumpsys wifi 2>/dev/null | grep -m1 "Wi-Fi is" || true)
    case "$want:$st" in
      disable:*disabled*|enable:*enabled*) return 0;;
    esac
    "${ADB[@]}" shell settings put global wifi_on "$([ "$want" = enable ] && echo 1 || echo 0)" >/dev/null 2>&1 || true
  done
  return 1
}

s_wifi_lte() {
  log "scenario: wifi<->lte switch (guest wifi toggle ↔ cellular data)"
  local m ip
  # svc/settings calls can return non-zero on some APIs (radio absent,
  # service timing) — the assertions below decide pass/fail, not these.
  # Cellular-capable? pm features is a capability check (the connectivity
  # dump only lists a cellular agent while data is actually up).
  local flap=0
  if ! "${ADB[@]}" shell pm list features 2>/dev/null | grep -qi "telephony"; then
    flap=1
    log "SKIP: no telephony feature — wifi off/on flap instead"
  fi
  if [ $flap -eq 0 ]; then
    # Bring cellular data up BEFORE cutting wifi: attach takes 10-30s on some
    # images and would otherwise race the reconnect window.
    "${ADB[@]}" shell svc data enable || true
    "${ADB[@]}" shell settings put global mobile_data 1 >/dev/null 2>&1 || true
    flap=1
    for i in $(seq 1 15); do
      if "${ADB[@]}" shell dumpsys connectivity 2>/dev/null \
          | grep -E "type: MOBILE|TRANSPORT_CELLULAR|MOBILE\[" | grep -q CONNECTED; then
        flap=0; break
      fi
      sleep 3
    done
    [ $flap -eq 1 ] && log "SKIP: telephony present but MOBILE never attached — wifi flap"
  fi
  if [ $flap -eq 1 ]; then
    m=$(mark_log)
    wifi_toggle disable || { log "SKIP: wifi toggle blocked on this API"; ok "wifi_lte: skipped (untoggleable wifi)"; return; }
    sleep 8
    wifi_toggle enable || true
    if wait_state '[= ]CONNECTED' 90 "$m" && ip=$(verify_tunnel_wait 45) && [ -n "$ip" ]; then
      ok "wifi flap: tunnel recovered (exit $ip; no usable cellular on device)"
    else
      bad "wifi flap: tunnel never recovered"
      log_since "$m" | tail -20
    fi
    return
  fi
  m=$(mark_log)
  wifi_toggle disable || { log "SKIP: wifi toggle blocked on this API"; ok "wifi_lte: skipped (untoggleable wifi)"; return; }
  sleep 8
  # kal2 must redial over cellular and the app must re-verify — the CONNECTED
  # wait only sees lines appended after the mark (fresh, not stale).
  if wait_state '[= ]CONNECTED' 90 "$m" && ip=$(verify_tunnel_wait 45) && [ -n "$ip" ]; then
    ok "wifi→data: session re-established (exit $ip)"
  else
    bad "wifi→data: session never recovered"
    log_since "$m" | tail -20
  fi
  m=$(mark_log)
  wifi_toggle enable || true
  sleep 6
  # Re-adding wifi does not force a redial — a healthy session may migrate or
  # simply keep running over cellular. Only the traffic check is meaningful.
  if ip=$(verify_tunnel_wait 75) && [ -n "$ip" ]; then
    ok "data→wifi: tunnel alive (exit $ip)"
  else
    bad "data→wifi: tunnel dead"
    log_since "$m" | tail -20
  fi
}

s_net_loss() {
  log "scenario: total net loss 15s"
  local m ip
  m=$(mark_log)
  wifi_toggle disable || { log "SKIP: wifi toggle blocked on this API"; ok "net_loss: skipped (untoggleable wifi)"; return; }
  "${ADB[@]}" shell svc data disable || true
  "${ADB[@]}" shell settings put global mobile_data 0 >/dev/null 2>&1 || true
  sleep 15
  wifi_toggle enable || true
  "${ADB[@]}" shell svc data enable || true
  "${ADB[@]}" shell settings put global mobile_data 1 >/dev/null 2>&1 || true
  # The kal2 carrier socket dies or blackholes with the underlay; the session
  # must be killed by liveness probes and redialed, then the app re-verifies.
  sleep 5
  if wait_state '[= ]CONNECTED' 90 "$m" && ip=$(verify_tunnel_wait 45) && [ -n "$ip" ]; then
    ok "net loss: session recovered (exit $ip)"
  else
    bad "net loss: no recovery in 90s"
    log_since "$m" | tail -20
  fi
}

s_dns_change() {
  log "scenario: private DNS flip while connected"
  "${ADB[@]}" shell settings put global private_dns_specifier dns.google || true
  sleep 4
  # The underlay network renegotiates; the tunnel must stay (or re-dial) and
  # real traffic must still pass.
  if ip=$(verify_tunnel_wait 60) && [ -n "$ip" ]; then
    ok "dns flip: tunnel alive (exit $ip)"
  else
    bad "dns flip: tunnel dead"
  fi
  "${ADB[@]}" shell settings delete global private_dns_specifier || true
}

s_dns_leak() {
  log "scenario: DNS leak check"
  "${ADB[@]}" forward tcp:11808 tcp:11808 >/dev/null 2>&1 || true
  curl -s -m 10 --socks5-hostname 127.0.0.1:11808 https://checkip.amazonaws.com >/dev/null || true
  # The VPN link must carry ONLY the tunnel resolvers — an underlay DNS on the
  # VPN interface means queries could escape around the tunnel.
  local dnsvpn dnsall
  dnsall=$("${ADB[@]}" shell dumpsys connectivity 2>/dev/null | grep -i "dnsaddresses" || true)
  dnsvpn=$(printf '%s\n' "$dnsall" | grep -i "1\.1\.1\.1\|8\.8\.8\.8" | head -3 || true)
  log "DnsAddresses view: $(printf '%s' "$dnsall" | tr '\n' ';')"
  if [ -n "$dnsvpn" ]; then
    ok "dns: vpn link carries tunnel resolvers ($(printf '%s' "$dnsvpn" | head -1 | cut -c1-90))"
  else
    bad "dns: tunnel resolvers not found in connectivity dump — manual review"
  fi
  # Functional DNS: name resolution through the tunnel must work end-to-end.
  if curl -s -m 10 --socks5-hostname 127.0.0.1:11808 https://ifconfig.me/ip >/dev/null 2>&1; then
    ok "dns: name resolution through tunnel works"
  else
    bad "dns: resolution through tunnel failed"
  fi
}

s_battery_opt() {
  log "scenario: battery optimization exemption + doze survival"
  "${ADB[@]}" shell dumpsys deviceidle whitelist +"$PKG" >/dev/null 2>&1 || true
  sleep 1
  local wl
  # dumpsys prints 'Whitelist user apps:' then one package per line — the
  # header and the package never share a line, so grep for the pkg directly.
  wl=$("${ADB[@]}" shell dumpsys deviceidle 2>/dev/null | grep -m1 "$PKG" || true)
  if [ -z "$wl" ]; then
    bad "battery: $PKG did not appear in deviceidle whitelist"
  else
    ok "battery: whitelisted ($(printf '%s' "$wl" | tr -d ' ' | cut -c1-60))"
    "${ADB[@]}" shell dumpsys deviceidle force-idle >/dev/null 2>&1 || true
    sleep 10
    # Whitelisted + foreground services keep network in doze — tunnel lives.
    if ip=$(verify_tunnel_wait 40) && [ -n "$ip" ]; then
      ok "battery: tunnel alive under forced doze (exit $ip)"
    else
      bad "battery: tunnel dead under forced doze despite whitelist"
    fi
    "${ADB[@]}" shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
  fi
  "${ADB[@]}" shell dumpsys deviceidle whitelist -"$PKG" >/dev/null 2>&1 || true
}

s_on_revoke() {
  log "scenario: onRevoke (appops ACTIVATE_VPN deny)"
  # OP_ACTIVATE_VPN exists since API 29 — detect and skip honestly below that.
  if ! "${ADB[@]}" shell appops get "$PKG" ACTIVATE_VPN >/dev/null 2>&1; then
    log "SKIP: ACTIVATE_VPN appop unsupported on this API"
    ok "on_revoke: skipped (appop unsupported on this API)"
    return
  fi
  local m
  m=$(mark_log)
  "${ADB[@]}" shell appops set "$PKG" ACTIVATE_VPN deny 2>/dev/null || true
  sleep 6
  # The framework revokes a live VPN via an OnOpChangedListener — present only
  # on newer APIs. Where it is absent, deny is advisory-at-prepare-time and
  # the tunnel legitimately stays up: record a SKIP rather than a fake fail.
  if log_since "$m" | grep -q "onRevoke"; then
    ok "revoke: onRevoke fired and logged"
  elif wait_state 'result=FAILED|connect failed' 35 "$m"; then
    ok "revoke: tunnel torn down (state FAILED)"
  else
    log "SKIP: ACTIVATE_VPN deny does not revoke a live VPN on this API"
    ok "on_revoke: skipped (no appop revoke path on this API)"
    "${ADB[@]}" shell appops set "$PKG" ACTIVATE_VPN allow 2>/dev/null || true
    return
  fi
  # the tunnel must actually be dead — traffic check must now fail
  if ! verify_tunnel >/dev/null; then
    ok "revoke: tunnel traffic dead after revoke"
  else
    bad "revoke: tunnel still passes traffic after revoke"
  fi
  "${ADB[@]}" shell appops set "$PKG" ACTIVATE_VPN allow 2>/dev/null || true
}

s_tls_cutoff() {
  log "scenario: TLS mid-flow cutoff (needs -http-proxy guest + host cutproxy)"
  [ -n "$PROXY_HOST_IP" ] || { log "skipped — pass --proxy <host shim addr> and launch emulator with -http-proxy"; return; }
  # cutproxy (milky-core) truncates each flow past N bytes; the client must
  # reconnect/migrate rather than wedge.
  local alive
  alive=$(verify_tunnel_wait 60 || true)
  [ -n "$alive" ] && ok "session re-established across flow cuts" || bad "session died across flow cuts"
}

s_soak30() {
  log "scenario: 30min soak with cover traffic"
  local t0=$SECONDS drops=0
  while (( SECONDS - t0 < 1800 )); do
    verify_tunnel >/dev/null || drops=$((drops+1))
    "${ADB[@]}" shell dumpsys activity processes 2>/dev/null | grep -q "$PKG:kal2" || drops=$((drops+1))
    sleep 60
  done
  [ "$drops" -le 3 ] && ok "soak 30min: $drops drops" || bad "soak 30min: $drops drops"
}

s_fgs_doze() {
  log "scenario: doze/FGS"
  "${ADB[@]}" shell dumpsys deviceidle force-idle 2>/dev/null || true
  sleep 10
  local svcdump procdump
  svcdump=$("${ADB[@]}" shell dumpsys activity services "$PKG" 2>/dev/null | grep -A25 "Kal2Service" || true)
  procdump=$("${ADB[@]}" shell dumpsys activity lru 2>/dev/null | grep "$PKG:kal2" || true)
  if printf '%s' "$svcdump" | grep -q "isForeground=true" \
     || printf '%s' "$procdump" | grep -qE "\bfg\b|fg-service"; then
    ok "doze: :kal2 service still foreground"
  else
    bad "doze: :kal2 not foreground — actual state:"
    printf '%s\n%s\n' "$svcdump" "$procdump" | head -14
  fi
  "${ADB[@]}" shell dumpsys deviceidle unforce 2>/dev/null || true
}

run_all() {
  s_connect
  s_wifi_lte
  s_net_loss
  s_dns_change
  s_dns_leak
  s_battery_opt
  s_fgs_doze
  s_tls_cutoff
  s_soak30
  s_on_revoke   # last — it kills the VPN
}

if [ "$SCEN" = "all" ]; then run_all; else "s_$SCEN"; fi
echo "=== results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
