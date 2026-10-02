#!/usr/bin/env bash
# Weekly backup sanity check: extract the newest /root/backups/kal2-backup-*.tar.gz
# to a temp dir, verify users.json parses and its user count matches the live file.
# TG alert on failure; silent on success (marker file records last-OK date).
set -u
BASE=/etc/kal2
TOKEN=$(cat $BASE/tg.token 2>/dev/null); CHAT=$(cat $BASE/tg.chat 2>/dev/null)
say(){ [ -n "$TOKEN" ] && curl -sm10 -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" --data-urlencode "chat_id=$CHAT" --data-urlencode "text=$1" >/dev/null; }
last=$(ls -1t /root/backups/kal2-backup-*.tar.gz 2>/dev/null | head -1)
if [ -z "$last" ]; then say "⚠️ Бэкапов нет — backup-kal2.sh не отрабатывает?"; exit 1; fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if ! tar -xzf "$last" -C "$tmp" 2>/dev/null; then say "⚠️ Бэкап $last не распаковывается"; exit 1; fi
buj=$(find "$tmp" -name users.json | head -1)
if [ -z "$buj" ]; then say "⚠️ В бэкапе нет users.json"; exit 1; fi
if ! python3 -c "import json,sys;u=json.load(open('$buj'));assert isinstance(u,list)" 2>/dev/null; then
  say "⚠️ users.json в бэкапе битый (не JSON)"; exit 1
fi
bn=$(python3 -c "import json;print(len(json.load(open('$buj'))))")
ln=$(python3 -c "import json;print(len(json.load(open('$BASE/users.json'))))")
if [ "$bn" -ne "$ln" ]; then
  say "⚠️ Бэкап устарел: юзеров в бэкапе $bn, в живом $ln"
else
  date +%F > $BASE/backup-verify-ok
fi
