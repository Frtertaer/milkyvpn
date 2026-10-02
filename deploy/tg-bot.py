#!/usr/bin/env python3
"""MilkyVPN Telegram management bot — runs on the US box as kal2-tgbot.service.

Long-polls api.telegram.org (reachable from US, unlike from RU) and answers
operator commands from the configured chat only; also pushes security events:
first-ever connect per user and daily-traffic spikes.

Files:
    /etc/kal2/tg.token          bot token
    /etc/kal2/tg.chat           allowed chat_id (one per line; extras ignored)
    /etc/kal2/panel.json        panel store (users) — read via ops API instead
    /etc/kal2/stats.jsonl       server session events (open/close + bytes)
    /etc/kal2/tg-bot-state/     update offset, seen users, daily totals, marks

Commands (in the allowed chat):
    /status    units + listeners + panel/tunnel probes
    /users     user table: state, month traffic, sessions, online
    /disable id /enable id   flip a user via the panel ops API
    /rotate_all              new PSK for every enabled user (sub URLs survive)
    /help
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

BASE = "/etc/kal2"
STATE = os.path.join(BASE, "tg-bot-state")
STATS = os.path.join(BASE, "stats.jsonl")
OPS = "http://127.0.0.1:9449"
PANEL_URL = "https://panel.mergescribe.dev/"

SPIKE_MIN_BYTES = 500 * 1024 * 1024   # never alert below 500MB/day
SPIKE_FACTOR = 3.0                    # and >3x the user's 7-day median


def read(name):
    with open(os.path.join(BASE, name)) as f:
        return f.read().strip()


TOKEN = read("tg.token")
CHAT = read("tg.chat")
API = "https://api.telegram.org/bot%s/" % TOKEN


def call(method, **kw):
    data = urllib.parse.urlencode(kw).encode()
    req = urllib.request.Request(API + method, data=data)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def send(text):
    try:
        call("sendMessage", chat_id=CHAT, text=text, disable_web_page_preview=True)
    except Exception as e:
        sys.stderr.write("send failed: %s\n" % e)


def state_get(name, default):
    try:
        with open(os.path.join(STATE, name)) as f:
            return json.load(f)
    except Exception:
        return default


def state_put(name, val):
    os.makedirs(STATE, exist_ok=True)
    tmp = os.path.join(STATE, name + ".tmp")
    with open(tmp, "w") as f:
        json.dump(val, f)
    os.replace(tmp, os.path.join(STATE, name))


def ops(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(OPS + path, data=data)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout


def fmt_b(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f%s" % (n, unit) if unit == "B" else "%.1f%s" % (n, unit)
        n /= 1024
    return "%.0fB" % n


def cmd_status():
    lines = []
    for u in ("kal2", "kal2-quasar", "kal2-panel", "cloudflared", "kal2-tgbot"):
        st = sh("systemctl is-active %s" % u).strip() or "?"
        mark = "ok" if st == "active" else "DOWN"
        lines.append("%s: %s" % (u, st if st == "active" else st + " " + mark))
    try:
        ops_s = ops("/ops/status")
        lines.append("panel: users=%d enabled=%d file_mode=%s" % (
            ops_s["users"], ops_s["users_enabled"], ops_s["file_mode"]))
    except Exception as e:
        lines.append("panel ops: %s" % e)
    try:
        import ssl
        ctx = ssl.create_default_context()
        req = urllib.request.Request(PANEL_URL)
        code = urllib.request.urlopen(req, timeout=8, context=ctx).status
        lines.append("туннель (panel.mergescribe.dev): %s" % ("живой" if code == 200 else "код %d" % code))
    except Exception:
        lines.append("туннель: недоступен")
    try:
        with open(os.path.join(BASE, "canary-ru.jsonl")) as f:
            last = [json.loads(x) for x in f.readlines()[-5:] if x.strip()]
        ok = sum(1 for x in last if x.get("ok"))
        lines.append("canary(РФ): %d/%d входов живы" % (ok, len(last)))
    except Exception:
        pass
    return "Статус:\n" + "\n".join(lines)


def user_stats():
    """Per-user aggregates from stats.jsonl: month bytes, sessions, open count.

    UDP-carrier sessions can die without a close event, so 'open' counts only
    sessions opened within the last STALE_SEC — an online estimate, not exact.
    """
    per = {}
    month = time.strftime("%Y-%m", time.gmtime())
    now = time.time()
    STALE_SEC = 1800
    try:
        with open(STATS) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                uid = e.get("uid")
                if not uid:
                    continue
                a = per.setdefault(uid, {"sess": 0, "month": 0, "open": 0, "last": 0})
                if e.get("ev") == "open":
                    a["sess"] += 1
                    if now - e.get("t", 0) <= STALE_SEC:
                        a["open"] += 1
                    a["last"] = max(a["last"], e.get("t", 0))
                elif e.get("ev") == "close":
                    if now - e.get("t", 0) <= STALE_SEC:
                        a["open"] -= 1
                    a["last"] = max(a["last"], e.get("t", 0))
                    if time.strftime("%Y-%m", time.gmtime(e.get("t", 0))) == month:
                        a["month"] += e.get("up", 0) + e.get("down", 0)
    except FileNotFoundError:
        pass
    return per


def cmd_users():
    try:
        us = ops("/ops/users")["users"]
    except Exception as e:
        return "panel ops недоступен: %s" % e
    if not us:
        return "Юзеров нет."
    agg = user_stats()
    lines = []
    for u in us:
        a = agg.get(u["id"], {})
        st = "выкл" if u.get("disabled") else "активен"
        extra = []
        if a.get("open", 0) > 0:
            extra.append("онлайн:%d" % a["open"])
        if u.get("quota_mb"):
            extra.append("квота %s/%dМБ" % (fmt_b(a.get("month", 0)), u["quota_mb"]))
        else:
            extra.append("месяц %s" % fmt_b(a.get("month", 0)))
        if u.get("expires_at"):
            d = time.strftime("%Y-%m-%d", time.gmtime(u["expires_at"]))
            extra.append("до %s%s" % (d, " (истёк)" if u["expires_at"] < time.time() else ""))
        lines.append("%-10s %s · %s" % (u["id"], st, ", ".join(extra)))
    return "Юзеры:\n" + "\n".join(lines)


def cmd_disable(uid, disabled):
    try:
        ops("/ops/users", {"id": uid, "disabled": disabled})
        return "%s %s" % (uid, "отключён" if disabled else "включён")
    except urllib.error.HTTPError as e:
        return "Ошибка: %s" % e.read().decode()[:80]
    except Exception as e:
        return "Ошибка: %s" % e


def cmd_rotate_all():
    try:
        n = ops("/ops/rotate-all", {})["rotated"]
        return ("Перевыпущено ключей: %d. URL подписок не менялись — клиенты "
                "получат новые PSK при обновлении подписки (авто-обновление "
                "должно быть включено) или раздай подписки заново." % n)
    except Exception as e:
        return "Ошибка: %s" % e


HELP = ("Команды:\n/status — юниты, слушатели, туннель, канарейка\n"
        "/users — юзеры: состояние, трафик месяца, онлайн\n"
        "/disable <id> /enable <id> — выкл/вкл юзера без перезапуска\n"
        "/rotate_all — перевыпустить PSK всем активным (ссылки подписок те же)\n"
        "/help — это сообщение")


def handle(text):
    parts = text.strip().split()
    cmd = parts[0].lstrip("/").split("@")[0].lower()
    arg = parts[1] if len(parts) > 1 else ""
    if cmd == "status":
        return cmd_status()
    if cmd == "users":
        return cmd_users()
    if cmd == "disable" and re.match(r"^[a-z0-9_-]{1,32}$", arg):
        return cmd_disable(arg, True)
    if cmd == "enable" and re.match(r"^[a-z0-9_-]{1,32}$", arg):
        return cmd_disable(arg, False)
    if cmd == "rotate_all":
        return cmd_rotate_all()
    return HELP


def check_alerts():
    """Tail stats.jsonl: first-ever connect per uid + daily traffic spikes."""
    off = state_get("stats_off", {"pos": 0})
    try:
        size = os.path.getsize(STATS)
    except FileNotFoundError:
        return
    if off["pos"] > size:  # rotated
        off["pos"] = 0
    seen = set(state_get("seen_users", []))
    daily = state_get("daily", {})       # uid -> {YYYY-MM-DD: bytes}
    alerted = set(state_get("spike_alerted", []))
    today = time.strftime("%Y-%m-%d", time.gmtime())
    with open(STATS) as f:
        f.seek(off["pos"])
        for line in f:
            try:
                e = json.loads(line)
            except Exception:
                continue
            uid = e.get("uid")
            if not uid:
                continue
            if uid not in seen:
                seen.add(uid)
                send("🔑 Первый коннект нового юзера: %s (carrier=%s)" % (
                    uid, e.get("carrier", "?")))
            if e.get("ev") == "close":
                day = time.strftime("%Y-%m-%d", time.gmtime(e.get("t", 0)))
                tot = daily.setdefault(uid, {})
                tot[day] = tot.get(day, 0) + e.get("up", 0) + e.get("down", 0)
                if day == today and uid + day not in alerted:
                    hist = [v for d, v in sorted(tot.items()) if d < today][-7:]
                    med = sorted(hist)[len(hist) // 2] if hist else 0
                    cur = tot[day]
                    if cur >= SPIKE_MIN_BYTES and cur > SPIKE_FACTOR * max(med, 1):
                        alerted.add(uid + day)
                        send("📈 Скачок трафика у %s: сегодня %s, медиана 7д %s" % (
                            uid, fmt_b(cur), fmt_b(med)))
        off["pos"] = f.tell()
    state_put("stats_off", off)
    state_put("seen_users", sorted(seen))
    state_put("daily", {u: {d: b for d, b in days.items() if d > "0000"} for u, days in daily.items()})
    state_put("spike_alerted", sorted(a for a in alerted if a.endswith(today)))


def main():
    os.makedirs(STATE, exist_ok=True)
    offset = state_get("offset", 0)
    send("kal2-tgbot поднялся — /help для команд")
    last_alerts = 0.0
    while True:
        try:
            res = call("getUpdates", offset=offset, timeout=25)
            for u in res.get("result", []):
                offset = u["update_id"] + 1
                m = u.get("message") or {}
                if str(m.get("chat", {}).get("id")) != CHAT:
                    continue
                text = m.get("text") or ""
                if text.startswith("/"):
                    try:
                        send(handle(text))
                    except Exception as e:
                        send("Ошибка: %s" % str(e)[:120])
            state_put("offset", offset)
        except Exception as e:
            sys.stderr.write("poll: %s\n" % e)
            time.sleep(5)
        if time.time() - last_alerts > 60:
            last_alerts = time.time()
            try:
                check_alerts()
            except Exception as e:
                sys.stderr.write("alerts: %s\n" % e)


if __name__ == "__main__":
    main()
