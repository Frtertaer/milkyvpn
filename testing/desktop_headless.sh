#!/usr/bin/env bash
# desktop_headless.sh — headless integration tests for the kal2 core on
# Linux/macOS/Windows(Git Bash): handshake budget, SOCKS liveness, TSPU
# per-flow truncation recovery, soak. No UI, no emulator.
#
#   testing/desktop_headless.sh [--link 'kal2://...' | --server IP:PORT --pub K --psk K] [--scenario name|--all]
set -euo pipefail
cd "$(dirname "$0")/.."
CORE=milky-core
ADDR=""; PUB=""; PSK=""; SNI="kal.mergescribe.dev"; LINK=""
SCEN="all"

while [ $# -gt 0 ]; do
  case "$1" in
    --server) ADDR=$2; shift 2;;
    --pub) PUB=$2; shift 2;;
    --psk) PSK=$2; shift 2;;
    --sni) SNI=$2; shift 2;;
    --link) LINK=$2; shift 2;;
    --scenario) SCEN=$2; shift 2;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done

# kal2://<psk>@<addr>?sni=&pub=&carrier=...
if [ -n "$LINK" ]; then
  PSK=${LINK#kal2://}; PSK=${PSK%%@*}
  rest=${LINK#*@}; ADDR=${rest%%\?*}
  qs=${rest#*\?}
  PUB=$(echo "$qs" | tr '&' '\n' | sed -n 's/^pub=//p')
  s=$(echo "$qs" | tr '&' '\n' | sed -n 's/^sni=//p'); [ -n "$s" ] && SNI=$s
fi
[ -n "$ADDR" ] && [ -n "$PUB" ] && [ -n "$PSK" ] || {
  echo "need --link or --server/--pub/--psk" >&2; exit 2; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS  $*"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL  $*"; }

CLIENT=/tmp/kal2-client-head
CUTPROXY=/tmp/cutproxy-sim
SOCKS=127.0.0.1:12908

build_tools() {
  (cd "$CORE" && go build -o "$CLIENT" ./cmd/kal2-client)
  cat > /tmp/cutproxy_main.go <<'EOF'
// TSPU per-flow truncation simulator: kills each TCP flow once a byte
// budget (TLS handshake included) has crossed in both directions.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
)

func main() {
	upstream := os.Args[1]
	limit, _ := strconv.ParseInt(os.Args[2], 10, 64)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { panic(err) }
	fmt.Println(ln.Addr())
	var flows, cuts atomic.Int64
	for {
		c, err := ln.Accept()
		if err != nil { return }
		flows.Add(1)
		go func(c net.Conn) {
			defer c.Close()
			up, err := net.Dial("tcp", upstream)
			if err != nil { return }
			defer up.Close()
			var n atomic.Int64
			done := make(chan struct{}, 2)
			pipe := func(dst, src net.Conn) {
				defer dst.Close()
				defer func() { done <- struct{}{} }()
				buf := make([]byte, 4096)
				for {
					k, err := src.Read(buf)
					if k > 0 {
						if total := n.Add(int64(k)); limit > 0 && total > limit {
							cuts.Add(1)
							return
						}
						if _, err := dst.Write(buf[:k]); err != nil { return }
					}
					if err != nil { return }
				}
			}
			go pipe(up, c)
			go pipe(c, up)
			<-done
		}(c)
	}
}
EOF
  go build -o "$CUTPROXY" /tmp/cutproxy_main.go
}

start_client() { # start_client <addr> <extra args...>
  "$CLIENT" -addr "$1" -sni "$SNI" -pub "$PUB" -psk "$PSK" \
    -carrier auto -socks "$SOCKS" ${INSECURE:+-insecure} ${ECH:+-ech "$ECH"} \
    > /tmp/head.log 2>&1 &
  echo $! > /tmp/head.pid
  for i in $(seq 1 40); do
    grep -q "session up" /tmp/head.log && return 0
    sleep 0.5
  done
  tail -20 /tmp/head.log >&2
  return 1
}

stop_client() { kill "$(cat /tmp/head.pid)" 2>/dev/null || true; }
tunnel_ip() { curl -s -m 12 --socks5-hostname "$SOCKS" https://ifconfig.me/ip 2>/dev/null; }

s_connect() {
  start_client "$ADDR" || { bad "client never said 'session up'"; return; }
  local ip; ip=$(tunnel_ip)
  [ -n "$ip" ] && ok "session up, tunnel exit $ip" || bad "session up but tunnel dead"
  stop_client
}

s_tls_cutoff() {
  # Route the client through the truncation sim: every flow dies past 256KiB.
  "$CUTPROXY" "$ADDR" $((256*1024)) >/tmp/cutaddr &
  sleep 0.5; CUT_ADDR=$(cat /tmp/cutaddr)
  start_client "$CUT_ADDR" || { bad "handshake exceeded the cut budget"; return; }
  # outgrow the budget: force a bulk pull
  curl -s -m 30 --socks5-hostname "$SOCKS" -o /dev/null http://speed.hetzner.de/10MB.bin || true
  # recovery: reconnect watchdog should stand a fresh session up
  local ok_=0
  for i in $(seq 1 30); do
    [ -n "$(tunnel_ip)" ] && { ok_=1; break; }
    sleep 2
  done
  [ $ok_ -eq 1 ] && ok "flow truncated → session recovered" || bad "no recovery after flow cut"
  stop_client
}

s_dns() {
  start_client "$ADDR" || { bad "dial"; return; }
  # hostname resolution must go through the tunnel (SOCKS5h semantics):
  # the exit IP seen over the tunnel must differ from the direct egress IP
  local ip; ip=$(curl -s -m 12 --socks5-hostname "$SOCKS" https://api.ipify.org)
  local dip; dip=$(curl -s -m 12 https://api.ipify.org)
  [ -n "$ip" ] && [ "$ip" != "$dip" ] && ok "egress via tunnel ($ip != direct $dip)" \
    || bad "dns/egress anomaly: tunnel=$ip direct=$dip"
  stop_client
}

s_soak() {
  local mins=${SOAK_MIN:-30}
  start_client "$ADDR" || { bad "dial"; return; }
  local t0=$SECONDS drops=0
  while (( SECONDS - t0 < mins*60 )); do
    tunnel_ip >/dev/null || drops=$((drops+1))
    grep -q "session lost" /tmp/head.log && log_fresh=$(grep -c "session restored" /tmp/head.log) && \
      [ "$log_fresh" -gt 0 ] || true
    sleep 60
  done
  [ "$drops" -le 2 ] && ok "soak ${mins}min: $drops probes dropped" || bad "soak: $drops drops"
  stop_client
}

build_tools
case "$SCEN" in
  all) s_connect; s_tls_cutoff; s_dns;;
  *) s_$SCEN;;
esac
echo "=== results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
