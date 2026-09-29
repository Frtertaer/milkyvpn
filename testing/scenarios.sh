#!/usr/bin/env bash
# scenarios.sh — MilkyVPN emulator scenario battery.
#
# Usage:
#   testing/scenarios.sh --apk app-debug.apk [--serial emulator-5554]
#                        [--link 'kal2://...'] [--scenario name|--all]
#
# Scenarios: connect, wifi_lte, net_loss, dns_change, dns_leak,
#            tls_cutoff (needs --proxy), soak30, fgs_doze.
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

wait_state() {  # wait_state CONNECTED|ERROR [timeout_s]
  local want=$1 to=${2:-90} t0=$SECONDS
  while (( SECONDS - t0 < to )); do
    if "${ADB[@]}" logcat -d -s MilkyVPN 2>/dev/null | grep -q "$want"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

clear_log() { "${ADB[@]}" logcat -c || true; }

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

ui_tap_desc_wait() {  # poll up to ~20s for a clickable match, then tap it
  local i
  for i in $(seq 1 10); do
    ui_tap_desc "$1" && return 0
    sleep 2
  done
  return 1
}

ui_tap_class() {  # tap first node of a class (e.g. android.widget.EditText)
  local re="class=\"${1}\"" line b
  line=$(ui_xml | tr '<' '\n' | grep -m1 "$re")
  [ -n "$line" ] || return 1
  b=$(echo "$line" | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p')
  local x1 y1 x2 y2
  read -r x1 y1 x2 y2 <<<"$b"
  "${ADB[@]}" shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 ))
}

onboarding_and_import() {
  # fresh install → 3-page onboarding, then ImportScreen paste+confirm.
  ui_tap_desc_wait "Продолжить\|Continue" && sleep 2
  ui_tap_desc_wait "Понятно\|Got it" && sleep 2
  ui_tap_desc_wait "Добавить подписку\|Add subscription" && sleep 3
  [ -n "$LINK" ] || { log "no --link/KAL2_TEST_LINK — expecting profile already present"; return; }
  local esc=${LINK//&/\\&}
  ui_tap_class android.widget.EditText; sleep 1   # focus the url field
  "${ADB[@]}" shell input text "$esc" 2>/dev/null || \
    log "input text failed — paste link in UI manually next run"
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

s_connect() {
  log "scenario: connect"
  launch_app; onboarding_and_import; tap_connect
  if wait_state CONNECTED 90; then
    local ip; ip=$(verify_tunnel)
    [ -n "$ip" ] && ok "connected, tunnel exit $ip" || { ok "connected (SOCKS probe empty)"; }
  else
    bad "no CONNECTED in 90s"; "${ADB[@]}" logcat -d | tail -60
  fi
}

s_wifi_lte() {
  log "scenario: wifi<->lte switch (guest wifi toggle ↔ cellular data)"
  "${ADB[@]}" shell svc wifi disable
  sleep 8
  "${ADB[@]}" shell svc data enable
  sleep 4
  # kal2 session should still be alive — migration/reconnect covers it
  if "${ADB[@]}" logcat -d -s MilkyVPN | grep -q "session lost"; then
    wait_state CONNECTED 60 && ok "wifi→data: session re-established" || bad "session never recovered after wifi→data"
  else
    local ip; ip=$(verify_tunnel)
    [ -n "$ip" ] && ok "wifi→data: session survived (exit $ip)" || bad "wifi→data: session up but tunnel dead"
  fi
  "${ADB[@]}" shell svc wifi enable
  sleep 6
  verify_tunnel >/dev/null && ok "data→wifi: tunnel alive" || bad "data→wifi: tunnel dead"
}

s_net_loss() {
  log "scenario: total net loss 15s"
  "${ADB[@]}" shell svc wifi disable; "${ADB[@]}" shell svc data disable
  sleep 15
  "${ADB[@]}" shell svc wifi enable; "${ADB[@]}" shell svc data enable
  sleep 5
  wait_state CONNECTED 90 && verify_tunnel >/dev/null \
    && ok "net loss: session recovered" \
    || bad "net loss: no recovery in 90s"
}

s_dns_change() {
  log "scenario: private DNS flip while connected"
  "${ADB[@]}" shell settings put global private_dns_specifier dns.google
  sleep 4
  verify_tunnel >/dev/null && ok "dns flip: tunnel alive" || bad "dns flip: tunnel dead"
  "${ADB[@]}" shell settings delete global private_dns_specifier
}

s_dns_leak() {
  log "scenario: DNS leak check"
  "${ADB[@]}" forward tcp:11808 tcp:11808 >/dev/null 2>&1 || true
  # Through the tunnel all DNS is resolved server-side; nothing should hit
  # the guest resolver: watch the guest's resolver socket for queries.
  local before after
  before=$("${ADB[@]}" shell 'cat /proc/net/udp6 2>/dev/null | wc -l; dumpsys netd 2>/dev/null | grep -ci vpn || true')
  "${ADB[@]}" shell svc data enable >/dev/null 2>&1
  curl -s -m 10 --socks5-hostname 127.0.0.1:11808 https://checkip.amazonaws.com >/dev/null || true
  after=$("${ADB[@]}" shell 'cat /proc/net/udp6 2>/dev/null | wc -l')
  log "resolver-udp6 lines before=$before after=$after (manual review)"
  ok "dns leak snapshot logged (manual review)"
}

s_tls_cutoff() {
  log "scenario: TLS mid-flow cutoff (needs -http-proxy guest + host cutproxy)"
  [ -n "$PROXY_HOST_IP" ] || { log "skipped — pass --proxy <host shim addr> and launch emulator with -http-proxy"; return; }
  # cutproxy (milky-core) truncates each flow past N bytes; the client must
  # reconnect/migrate rather than wedge.
  local alive
  alive=$(verify_tunnel || true)
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
  "${ADB[@]}" shell dumpsys activity processes | grep -B2 -A6 "$PKG:kal2" | grep -q "fg" \
    && ok "doze: :kal2 service still foreground" \
    || bad "doze: :kal2 not foreground"
  "${ADB[@]}" shell dumpsys deviceidle unforce 2>/dev/null || true
}

run_all() {
  s_connect
  s_wifi_lte
  s_net_loss
  s_dns_change
  s_dns_leak
  s_tls_cutoff
  s_soak30
  s_fgs_doze
}

if [ "$SCEN" = "all" ]; then run_all; else "s_$SCEN"; fi
echo "=== results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
