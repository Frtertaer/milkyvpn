#!/usr/bin/env bash
# uptime-tg-alert.sh — Telegram alerts when the MilkyVPN server itself is down.
# Runs on the US box next to canary-tg-alert.sh (same creds: /etc/kal2/tg.*).
# Watches systemd units + listeners; posts on up→down / down→up transitions.
#
# Setup on the US host (cron every 2 min):
#   */2 * * * * /etc/kal2/uptime-tg-alert.sh >/dev/null 2>&1
#
# Env (optional):
#   UPTIME_TG_TOKEN / UPTIME_TG_CHAT   bot creds (or /etc/kal2/tg.token, tg.chat)
#   UPTIME_TG_STATE                  state dir (default /etc/kal2/uptime-tg-state)
#   UPTIME_UNITS                     space-separated systemd units (default below)
#   UPTIME_PORTS                     space-separated proto:port listeners (default below)
set -u

TOKEN=${UPTIME_TG_TOKEN:-$(cat /etc/kal2/tg.token 2>/dev/null)}
CHAT=${UPTIME_TG_CHAT:-$(cat /etc/kal2/tg.chat 2>/dev/null)}
STATE=${UPTIME_TG_STATE:-/etc/kal2/uptime-tg-state}
UNITS=${UPTIME_UNITS:-"kal2.service kal2-quasar.service kal2-panel.service"}
# udp443 sing-box and tcp443 haproxy are the public edge — watch them too.
PORTS=${UPTIME_PORTS:-"udp:443 tcp:443 udp:20443 udp:20444 udp:20445 tcp:9443"}
[ -n "$TOKEN" ] && [ -n "$CHAT" ] || exit 0
mkdir -p "$STATE"

emit() { # emit <key> <ok:true|false> <label>
  local key=$1 ok=$2 label=$3 prev
  prev=$(cat "$STATE/$key" 2>/dev/null)
  [ "$prev" = "$ok" ] && return
  printf '%s' "$ok" > "$STATE/$key"
  [ -z "$prev" ] && return # seed only
  local msg
  if [ "$ok" = "true" ]; then msg="✅ MilkyVPN сервер: $label восстановлен"
  else msg="🔴 MilkyVPN сервер: $label УПАЛ"; fi
  curl -s -m 10 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    -d "chat_id=${CHAT}" --data-urlencode "text=${msg}" >/dev/null 2>&1 || true
}

for unit in $UNITS; do
  if systemctl is-active --quiet "$unit" 2>/dev/null; then
    emit "unit:$unit" true "$unit"
  else
    emit "unit:$unit" false "$unit"
  fi
done

for spec in $PORTS; do
  proto=${spec%%:*}; port=${spec##*:}
  if [ "$proto" = "udp" ]; then
    ss -uln "sport = :$port" 2>/dev/null | grep -q ":$port" && ok=true || ok=false
  else
    ss -tln "sport = :$port" 2>/dev/null | grep -q ":$port" && ok=true || ok=false
  fi
  emit "port:$spec" "$ok" "listener $spec"
done
