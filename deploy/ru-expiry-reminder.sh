#!/usr/bin/env bash
# Reminds in Telegram when the RU canary box is about to expire.
# Put the expiry date in /etc/kal2/ru-box-expiry as YYYY-MM-DD.
# Alerts at T-3 and T-1 days (once per threshold, marker files in tg-bot-state).
set -u
BASE=/etc/kal2
EXPFILE=$BASE/ru-box-expiry
STATE=$BASE/tg-bot-state
[ -f "$EXPFILE" ] || exit 0
exp=$(cat "$EXPFILE" | tr -d ' \n')
now_s=$(date +%s)
exp_s=$(date -d "$exp 23:59:59" +%s 2>/dev/null) || exit 0
days=$(( (exp_s - now_s) / 86400 ))
mkdir -p "$STATE"
msg=""
for t in 3 1; do
  mark="$STATE/ru-expiry-t$t-$exp"
  if [ "$days" -le "$t" ] && [ "$days" -ge 0 ] && [ ! -f "$mark" ]; then
    msg="⏳ RU-бокс (канарейка) истекает через $days дн ($exp) — продлить или перенести пробник: deploy/canary-bootstrap.sh <новый-хост>"
    touch "$mark"
    break
  fi
done
if [ "$days" -lt 0 ] && [ ! -f "$STATE/ru-expired-$exp" ]; then
  msg="💀 RU-бокс просрочен ($exp) — канарейка скоро умрёт; см. deploy/canary-bootstrap.sh для нового хоста"
  touch "$STATE/ru-expired-$exp"
fi
[ -z "$msg" ] && exit 0
TOKEN=$(cat $BASE/tg.token); CHAT=$(cat $BASE/tg.chat)
curl -sm10 -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
  --data-urlencode "chat_id=$CHAT" --data-urlencode "text=$msg" >/dev/null
