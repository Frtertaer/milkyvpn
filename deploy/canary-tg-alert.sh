#!/usr/bin/env bash
# canary-tg-alert.sh — Telegram alerts for RU-vantage canary transitions.
# Runs on the US box (api.telegram.org is reachable from here; it is blocked
# from RU vantages). Reads the canary JSONL the RU probe pushes, tracks the
# last state per entry|carrier, and posts on alive→dead / dead→alive flips.
#
# Setup on the US host (cron every 5 min):
#   */5 * * * * /etc/kal2/canary-tg-alert.sh >/dev/null 2>&1
#
# Env (optional — defaults match the deployed paths):
#   CANARY_TG_FILE   canary jsonl produced by canary-ru.sh (default /etc/kal2/canary-ru.jsonl)
#   CANARY_TG_TOKEN  bot token   (or /etc/kal2/tg.token)
#   CANARY_TG_CHAT   chat id     (or /etc/kal2/tg.chat)
#   CANARY_TG_STATE  state dir   (default /etc/kal2/canary-tg-state)
set -u

FILE=${CANARY_TG_FILE:-/etc/kal2/canary-ru.jsonl}
TOKEN=${CANARY_TG_TOKEN:-$(cat /etc/kal2/tg.token 2>/dev/null)}
CHAT=${CANARY_TG_CHAT:-$(cat /etc/kal2/tg.chat 2>/dev/null)}
STATE=${CANARY_TG_STATE:-/etc/kal2/canary-tg-state}
[ -s "$FILE" ] || exit 0
[ -n "$TOKEN" ] && [ -n "$CHAT" ] || exit 0
mkdir -p "$STATE"

while IFS= read -r line; do
  key=$(printf '%s' "$line" | sed -n 's/.*"entry":"\([^"]*\)".*"carrier":"\([^"]*\)".*/\1|\2/p')
  ok=$(printf '%s' "$line" | sed -n 's/.*"ok":\([a-z]*\).*/\1/p')
  [ -z "$key" ] && continue
  prev=$(cat "$STATE/$key" 2>/dev/null)
  [ "$prev" = "$ok" ] && continue
  printf '%s' "$ok" > "$STATE/$key"
  # First observed state only seeds — never alert on it.
  [ -z "$prev" ] && continue
  if [ "$ok" = "true" ]; then
    msg="✅ MilkyVPN вход поднялся из РФ: $key"
  else
    msg="🔴 MilkyVPN вход УПАЛ из РФ: $key"
  fi
  curl -s -m 10 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    -d "chat_id=${CHAT}" --data-urlencode "text=${msg}" >/dev/null 2>&1 || true
done < "$FILE"
