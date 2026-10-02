#!/usr/bin/env bash
# server-deploy.sh — push kal2-server + kal2-panel to the US box and restart.
# Runs on the ops machine or in CI (deploy-server.yml). Idempotent.
#
#   SSH_KEY=~/.ssh/milky_ops_plain deploy/server-deploy.sh [server-bin] [panel-bin]
#
# Binaries default to /tmp/kal2-server and /tmp/kal2-panel (built by caller).
# Migrates versioned ExecStart paths (kal2-server-vN) to stable paths once.
set -euo pipefail

HOST=${DEPLOY_HOST:-root@23.133.88.167}
KEY=${SSH_KEY:-$HOME/.ssh/milky_ops_plain}
SERVER_BIN=${1:-/tmp/kal2-server}
PANEL_BIN=${2:-/tmp/kal2-panel}
SSH="ssh -i $KEY -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new $HOST"
SCP="scp -i $KEY -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new"

[ -f "$SERVER_BIN" ] && [ -f "$PANEL_BIN" ] || { echo "missing binaries"; exit 1; }

echo "== upload"
$SCP "$SERVER_BIN" "$HOST:/opt/kal2/kal2-server.new"
$SCP "$PANEL_BIN" "$HOST:/opt/kal2/kal2-panel.new"

echo "== swap + migrate units to stable paths"
$SSH 'bash -s' <<'EOF'
set -euo pipefail
cd /opt/kal2
# keep last-known-good binaries for instant rollback
for b in kal2-server kal2-panel; do
  [ -f "$b" ] && cp -a "$b" "$b.prev"
  mv "$b.new" "$b"; chmod 755 "$b"
done
# rewrite any ExecStart that points at a versioned binary to the stable path
for u in kal2.service kal2-quasar.service kal2-panel.service; do
  for f in /etc/systemd/system/$u /etc/systemd/system/$u.d/*.conf; do
    [ -f "$f" ] || continue
    sed -i -E 's#/opt/kal2/kal2-server-v[0-9]+#/opt/kal2/kal2-server#g; s#/opt/kal2/kal2-panel(-v[0-9]+)?#/opt/kal2/kal2-panel#g' "$f"
  done
done
systemctl daemon-reload
systemctl restart kal2 kal2-quasar kal2-panel
sleep 2
for u in kal2 kal2-quasar kal2-panel; do
  systemctl is-active --quiet $u || { echo "FAIL: $u not active"; systemctl status $u --no-pager | tail -8; exit 1; }
  echo "OK: $u active"
done
curl -sk -o /dev/null -w 'panel https %{http_code}\n' https://127.0.0.1:9443/ || true
EOF
