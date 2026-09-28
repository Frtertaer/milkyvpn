#!/usr/bin/env bash
# canary.sh — passive KAL/2 liveness measurement against a real egress.
# Client-side only: dials OUR server and benign public targets, never
# probes third parties. Output: JSONL, one record per measurement.
#
#   research/canary.sh --server IP:PORT --pub HEX --psk HEX \
#                      [--sni HOST] [--out DIR] [--n 3]
set -u
cd "$(dirname "$0")/.."

ADDR=""; PUB=""; PSK=""; SNI="kal.mergescribe.dev"
OUT=research/runs; N=3
while [ $# -gt 0 ]; do
  case "$1" in
    --server) ADDR=$2; shift 2;; --pub) PUB=$2; shift 2;; --psk) PSK=$2; shift 2;;
    --sni) SNI=$2; shift 2;; --out) OUT=$2; shift 2;; --n) N=$2; shift 2;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
[ -n "$ADDR" ] && [ -n "$PUB" ] && [ -n "$PSK" ] || { echo "need --server/--pub/--psk" >&2; exit 2; }

mkdir -p "$OUT"
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="$OUT/canary-$TS.jsonl"
CLIENT=/tmp/kal2-canary
SOCKS=127.0.0.1:13908
FETCH_URL=${CANARY_FETCH:-https://proof.ovh.net/files/10Mb.dat}
BATCH_HOST=${CANARY_BATCH_HOST:-${ADDR%%:*}}
BATCH_PORT=${ADDR##*:}
BURST=${CANARY_BURST:-15}

emit() { printf '{"ts":"%s","probe":"%s",%s}\n' "$(date -u +%FT%TZ)" "$1" "$2" >>"$LOG"; }
ms_now() { date +%s%3N; }

(cd milky-core && go build -o "$CLIENT" ./cmd/kal2-client) \
  || { echo "kal2-client build failed" >&2; exit 1; }

# ---------- 1. carrier matrix ----------
for carrier in veil drift cdn; do
  "$CLIENT" -addr "$ADDR" -sni "$SNI" -pub "$PUB" -psk "$PSK" \
    -carrier "$carrier" -socks "$SOCKS" >/tmp/canary-client.log 2>&1 &
  pid=$!
  t0=$(ms_now); ok=0
  for i in $(seq 1 60); do
    grep -q "session up" /tmp/canary-client.log && { ok=1; break; }
    kill -0 $pid 2>/dev/null || break
    sleep 0.5
  done
  emit handshake "\"carrier\":\"$carrier\",\"ok\":$ok,\"ms\":$(( $(ms_now)-t0 ))"
  if [ $ok -eq 1 ]; then
    # 'session up' precedes the SOCKS bind — wait for the listener
    for i in $(seq 1 20); do
      timeout 2 bash -c "</dev/tcp/${SOCKS%:*}/${SOCKS##*:}" 2>/dev/null && break
      sleep 0.5
    done
    for i in $(seq 1 "$N"); do
      r=$(curl -s -o /dev/null -w '%{time_starttransfer} %{speed_download} %{size_download}' \
            -m 40 --socks5-hostname "$SOCKS" "$FETCH_URL")
      set -- $r
      emit probe "\"carrier\":\"$carrier\",\"ttfb_ms\":$(awk "BEGIN{printf \"%d\", ${1:-0}*1000}"),\"bps\":${2:-0},\"bytes\":${3:-0}"
    done
  fi
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  sleep 1
done

# ---------- 2. per-flow truncation probe (direct egress, not the tunnel) ----------
# If the primary fetch target is unreachable from this egress, fall back
# before declaring the flow truncated.
for url in "$FETCH_URL" https://proof.ovh.net/files/10Mb.dat https://speedtest.selectel.ru/10MB; do
  r=$(curl -s -o /dev/null -w '%{size_download} %{speed_download}' -m 60 "$url")
  set -- $r
  [ "${1:-0}" -gt 0 ] && break
done
emit truncation "\"url\":\"$url\",\"direct_bytes\":${1:-0},\"direct_bps\":${2:-0}"

# ---------- 3. SNI reachability probe ----------
# Passive TLS handshakes to OUR IP with varying SNI — detects SNI-based RST.
for sni in "$SNI" www.cloudflare.com www.ozon.ru; do
  ok=0
  timeout 8 openssl s_client -connect "$ADDR" -servername "$sni" </dev/null \
    2>/dev/null | grep -qE "Cipher is|Cipher.*TLS|Verify return code" && ok=1
  emit sni "\"sni\":\"$sni\",\"target\":\"$ADDR\",\"ok\":$ok"
done

# ---------- 4. IP-batch / rapid-connect probe ----------
# TSPU batching: a burst of fresh TCP connects; count accepts + slow ones.
ok=0; slow=0
for i in $(seq 1 "$BURST"); do
  t0=$(ms_now)
  if timeout 5 bash -c "</dev/tcp/$BATCH_HOST/$BATCH_PORT" 2>/dev/null; then
    ok=$((ok+1)); ms=$(( $(ms_now)-t0 ))
    [ "$ms" -gt 2000 ] && slow=$((slow+1))
  fi
done
emit batch "\"target\":\"$BATCH_HOST:$BATCH_PORT\",\"n\":$BURST,\"ok\":$ok,\"slow\":$slow"

# ---------- 5. DNS sanity ----------
if command -v dig >/dev/null; then
  a=$(dig +short +time=3 +tries=1 "$SNI" | tr '\n' ',')
  b=$(dig +short +time=3 +tries=1 @8.8.8.8 "$SNI" | tr '\n' ',')
  emit dns "\"domain\":\"$SNI\",\"local\":\"$a\",\"google\":\"$b\""
fi

echo "wrote $LOG"
