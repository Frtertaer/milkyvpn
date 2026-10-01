#!/usr/bin/env bash
# canary-ru.sh — RU-side liveness probe for MilkyVPN entries.
# Runs on the RU vantage host (5.35.99.196), opens a real Pandora session per
# entry/carrier, records ok+ms, then scp's a JSONL summary to the US box where
# kal2-panel reads it (status.canary → the "Входы живы из РФ" card).
#
# Setup on the RU host (cron every 10 min):
#   */10 * * * * /opt/kal2/canary-ru.sh >/dev/null 2>&1
#
# Env (all optional, defaults match the current deployment):
#   CANARY_CLIENT   prebuilt kal2-client path        (default /opt/kal2/kal2-client)
#   CANARY_PSK      probe user's PSK                 (read from /etc/kal2/canary.psk)
#   CANARY_PUB      server ed25519 pub               (default below)
#   CANARY_PUSH     scp target for the summary file  (default root@23.133.88.167:/etc/kal2/canary-ru.jsonl)
set -u

CLIENT=${CANARY_CLIENT:-/opt/kal2/kal2-client}
PSK=${CANARY_PSK:-$(cat /opt/kal2/canary.psk 2>/dev/null)}
PUB=${CANARY_PUB:-9f0dfb763d6fbdb2fa0f0b1f2fb6fd2f3d8e9ca681c523241c63434d41c76c8f}
PUSH=${CANARY_PUSH:-root@23.133.88.167:/etc/kal2/canary-ru.jsonl}
SNI=${CANARY_SNI:-kal.mergescribe.dev}
OUT=/opt/kal2/canary-ru.jsonl
SOCKS=127.0.0.1:13918
mkdir -p /opt/kal2

# probe <entry-label> <addr> <carrier> [extra client args...]
probe() {
  local entry=$1 addr=$2 carrier=$3; shift 3
  local t0 ok=0 log=/tmp/canary-ru-client.log
  timeout 25 "$CLIENT" -addr "$addr" -sni "$SNI" -pub "$PUB" -psk "$PSK" \
    -carrier "$carrier" -socks "$SOCKS" "$@" >"$log" 2>&1 &
  local pid=$! t0=$(date +%s%3N)
  for i in $(seq 1 40); do
    grep -q "session up" "$log" && { ok=1; break; }
    kill -0 $pid 2>/dev/null || break
    sleep 0.5
  done
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  local okb=false; [ $ok -eq 1 ] && okb=true
  printf '{"ts":"%s","entry":"%s","carrier":"%s","ok":%s,"ms":%d}\n' \
    "$(date -u +%FT%TZ)" "$entry" "$carrier" "$okb" "$(( $(date +%s%3N) - t0 ))"
}

{
  probe "us:443"     "23.133.88.167:443"   veil
  probe "us:20444"   "23.133.88.167:20444" quic2
  probe "us:20445"   "23.133.88.167:20445" rtc
  probe "yandex-fn"  "23.133.88.167:443"   mosaic \
    -front "https://functions.yandexcloud.net/d4erhmmikarvfr4tsc7e"
  probe "cf-worker"  "23.133.88.167:443"   mosaic \
    -front "https://milky-front.milky-front.workers.dev"
} > "$OUT.new" 2>/dev/null
mv "$OUT.new" "$OUT"

scp -q -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$OUT" "$PUSH" 2>/dev/null
