#!/usr/bin/env bash
# backup-kal2.sh — daily backup of the kal2 config+stats on the US box.
# Keeps 30 local copies in /root/backups and, when tg creds exist, sends the
# archive to the owner's Telegram via sendDocument (free off-site copy).
#
# Setup on the US host (cron daily 04:10):
#   10 4 * * * /etc/kal2/backup-kal2.sh >/dev/null 2>&1
#
# Env (optional):
#   BACKUP_DIR    local dir      (default /root/backups)
#   BACKUP_KEEP   days to keep   (default 30)
#   BACKUP_TG     1 = send to telegram when creds present (default 1)
set -u

DIR=${BACKUP_DIR:-/root/backups}
KEEP=${BACKUP_KEEP:-30}
TG=${BACKUP_TG:-1}
TOKEN=$(cat /etc/kal2/tg.token 2>/dev/null)
CHAT=$(cat /etc/kal2/tg.chat 2>/dev/null)
mkdir -p "$DIR"

day=$(date -u +%F)
arc="$DIR/kal2-backup-$day.tar.gz"
tar -czf "$arc" -C /etc/kal2 \
  users.json panel.json ech-keys.json audit.jsonl stats.jsonl \
  canary-ru.jsonl canary-ru-history.jsonl 2>/dev/null || true

# rotate
find "$DIR" -name 'kal2-backup-*.tar.gz' -mtime +"$KEEP" -delete

# off-site copy via Telegram document
if [ "$TG" = "1" ] && [ -n "$TOKEN" ] && [ -n "$CHAT" ] && [ -s "$arc" ]; then
  curl -s -m 30 -X POST "https://api.telegram.org/bot${TOKEN}/sendDocument" \
    -F "chat_id=${CHAT}" \
    -F "document=@${arc}" \
    -F "caption=MilkyVPN backup ${day} (users+panel+ech+stats)" >/dev/null 2>&1 || true
fi
