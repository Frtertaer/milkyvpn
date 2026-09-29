# research/ — autonomous canary stand

Пассивные измерения живучести KAL/2 carriers против реального egress.
Только свои клиентские соединения и безобидные публичные цели — никаких
активных проб чужой инфраструктуры.

## Что меряет (`canary.sh`)

| Проба | DESIGN.md-угроза | Метрика |
|---|---|---|
| carrier matrix (veil/drift/cdn) | любая | handshake ok + latency, TTFB, Mbps, bytes/flow через туннель |
| flow truncation | ТСПУ режет длинные потоки | direct-egress bytes до сталла |
| SNI reachability | SNI-блокировки | TLS-handshake ok по каждому SNI к нашему IP |
| connect burst | IP-батчинг / per-flow лимиты | accept rate + медленные коннекты в burst |
| DNS sanity | DNS-poison | ответ локального резолвера vs 8.8.8.8 |

Каждый прогон пишет `research/runs/canary-<ts>.jsonl` — одна JSON-строка
на замер. `report.py` сворачивает неделю в markdown-таблицу по carriers.

## Развёртывание на хосте наблюдения (напр. RU-релей)

```bash
git clone <repo> /opt/milkyvpn && cd /opt/milkyvpn
mkdir -p /etc/milky /var/lib/kal2-canary/runs
cat >/etc/milky/canary.env <<EOF
KAL2_SERVER=23.133.88.167:443
KAL2_SNI=kal.mergescribe.dev
KAL2_PUB=<pub hex>
KAL2_PSK=<psk hex>
EOF
chmod 600 /etc/milky/canary.env
cp research/kal2-canary.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now kal2-canary.timer
```

Weekly-отчёт: `/var/lib/kal2-canary/report.md` (перезаписывается после
каждого прогона `report.py`).

## Ручной прогон

```bash
./research/canary.sh --server 23.133.88.167:443 --pub <pub> --psk <psk>
python3 research/report.py research/runs --days 7
```
