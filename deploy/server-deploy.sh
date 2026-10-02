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

echo "== stage panel on :9444 + smoke before prod"
$SSH 'bash -s' <<'EOF'
set -euo pipefail
cd /opt/kal2
# staging panel: new binary on loopback :9444 against a copy of panel.json —
# catches a broken build before it replaces the live panel.
mv kal2-panel.new kal2-panel.stg; chmod 755 kal2-panel.stg
cp /etc/kal2/panel.json /etc/kal2/panel-staging.json
cat > /etc/systemd/system/kal2-panel-staging.service <<'UNIT'
[Unit]
Description=kal2 panel (staging)
After=network.target
[Service]
ExecStart=/opt/kal2/kal2-panel.stg -listen 127.0.0.1:9444 -data /etc/kal2/panel-staging.json -ops-listen 127.0.0.1:9459
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl restart kal2-panel-staging
sleep 2
systemctl is-active --quiet kal2-panel-staging || { echo "FAIL: staging panel dead"; journalctl -u kal2-panel-staging -n 10 --no-pager; exit 1; }
curl -sf -o /dev/null http://127.0.0.1:9444/ || { echo "FAIL: staging panel http"; exit 1; }
curl -sf http://127.0.0.1:9459/ops/status | grep -q '"users"' || { echo "FAIL: ops api smoke"; exit 1; }
echo "staging smoke OK"
EOF

echo "== swap + migrate units to stable paths"
$SSH 'bash -s' <<'EOF'
set -euo pipefail
cd /opt/kal2
# keep last-known-good binaries for instant rollback
for b in kal2-server kal2-panel; do
  [ -f "$b" ] && cp -a "$b" "$b.prev"
done
mv kal2-server.new kal2-server; chmod 755 kal2-server
mv kal2-panel.stg kal2-panel; chmod 755 kal2-panel
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
