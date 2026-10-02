#!/usr/bin/env bash
# canary-bootstrap.sh — one-command canary probe install on a fresh RU box.
#
# Usage (run from the ops machine that has the milky_ops_plain key):
#   deploy/canary-bootstrap.sh <new-ru-host> [ssh-port]
#
# What it does:
#   1. copies a freshly built static kal2-client + canary-ru.sh + canary.psk
#   2. copies the ops key so the box can scp results to the US panel host
#   3. installs the */10 cron entry
#   4. runs one probe to verify (prints the JSONL it produced)
#
# Config comes from env, defaults match the current deployment:
#   OPS_KEY        ssh key for root@<new-host> and RU->US push (default ~/.ssh/milky_ops_plain)
#   US_HOST        panel/stats host               (default root@23.133.88.167)
#   CANARY_PSK     probe user psk                 (default: read from current RU box or repo env)
#   CANARY_PUB     server ed25519 pub             (default below)
#   SNI            veil SNI                       (default kal.mergescribe.dev)
set -euo pipefail

HOST=${1:?usage: canary-bootstrap.sh <ru-host> [ssh-port]}
PORT=${2:-22}
OPS_KEY=${OPS_KEY:-$HOME/.ssh/milky_ops_plain}
US_HOST=${US_HOST:-root@23.133.88.167}
PUB=${CANARY_PUB:-9f0dfb763d6fbdb2fa0f0b1f2fb6fd2f3d8e9ca681c523241c63434d41c76c8f}
SNI=${CANARY_SNI:-kal.mergescribe.dev}
REPO=$(cd "$(dirname "$0")/.." && pwd)

SSH="ssh -i $OPS_KEY -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -p $PORT"
SCP="scp -i $OPS_KEY -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -P $PORT"

echo "== building kal2-client (linux/amd64, static)"
(cd "$REPO/milky-core" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  /usr/local/go/bin/go build -o /tmp/kal2-client ./cmd/kal2-client)

PSK=${CANARY_PSK:-}
if [ -z "$PSK" ]; then
  # pull the canary user's psk off the US host (users.json "id":"canary" or
  # legacy /etc/kal2/canary.psk); falls back to CANARY_SRC_HOST (old RU box)
  PSK=$(ssh -i "$OPS_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$US_HOST" \
    'python3 -c "import json; print(next(u[\"psk\"] for u in json.load(open(\"/etc/kal2/users.json\")) if u.get(\"id\")==\"canary\"))" 2>/dev/null || cat /etc/kal2/canary.psk 2>/dev/null' || true)
  if [ -z "$PSK" ] && [ -n "${CANARY_SRC_HOST:-}" ]; then
    PSK=$(ssh -i "$OPS_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "root@$CANARY_SRC_HOST" \
      'cat /opt/kal2/canary.psk 2>/dev/null' || true)
  fi
fi
[ -z "$PSK" ] && { echo "CANARY_PSK not set and canary user not found on US host"; exit 1; }

echo "== installing on $HOST"
$SSH root@$HOST 'mkdir -p /opt/kal2 /root/.ssh && chmod 700 /root/.ssh'
$SCP /tmp/kal2-client "$REPO/deploy/canary-ru.sh" root@$HOST:/opt/kal2/
$SCP "$OPS_KEY" root@$HOST:/root/.ssh/milky_ops_plain
printf '%s\n' "$PSK" | $SSH root@$HOST 'cat > /opt/kal2/canary.psk && chmod 600 /opt/kal2/canary.psk'
$SSH root@$HOST 'chmod 700 /root/.ssh/milky_ops_plain /opt/kal2/kal2-client /opt/kal2/canary-ru.sh; touch /root/.ssh/known_hosts'

echo "== cron"
$SSH root@$HOST 'crontab -l 2>/dev/null | grep -v canary-ru.sh > /tmp/cron.new || true
printf "%s\n" "*/10 * * * * /opt/kal2/canary-ru.sh >/dev/null 2>&1" >> /tmp/cron.new
crontab /tmp/cron.new && rm /tmp/cron.new && crontab -l | tail -1'

echo "== authorizing box key on US host (idempotent)"
PUBKEY=$($SSH root@$HOST 'ssh-keygen -yf /root/.ssh/milky_ops_plain')
ssh -i "$OPS_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$US_HOST" \
  "grep -qF '$PUBKEY' /root/.ssh/authorized_keys || echo '$PUBKEY' >> /root/.ssh/authorized_keys"

echo "== smoke probe"
$SSH root@$HOST "CANARY_PUSH='$US_HOST:/etc/kal2/canary-ru.jsonl' CANARY_SNI='$SNI' CANARY_PUB='$PUB' /opt/kal2/canary-ru.sh && cat /opt/kal2/canary-ru.jsonl"

echo "== done. canary on $HOST reports to $US_HOST every 10 min"
