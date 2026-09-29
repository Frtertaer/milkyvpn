---
name: kal2-bench-ru-us
description: Live RU→US bench/deploy contour for KAL/2 vs Hysteria2 — hosts, SSH, unit files, bench.sh, and the path's measured UDP/TCP profile.
---

# KAL/2 RU→US bench contour

Two prod hosts (only these may be used):
- **US** `root@23.133.88.167` — kal2-server (kal2.service, 127.0.0.1:8443 behind haproxy :443), sing-box hy2 (UDP :443), nginx :80 `/speedtest/{32,256}mb.bin`, kal2-quasar (kal2-quasar.service, UDP :20443; binary `/opt/kal2/kal2-server-v2`). Auth: `SSH_ASKPASS=/tmp/askpass.sh SSH_ASKPASS_REQUIRE=force ssh root@23.133.88.167`. Binary swap: `scp` to `*.new` then `mv -f` over the running binary (cp gives "Text file busy"); `systemctl restart kal2[-quasar]` is graceful.
- **RU** `root@5.35.99.196` — `ssh -i ~/.ssh/milky_ops_plain`. `soak.service` (`/root/soak/soak.sh`) spawns SOCKS clients `kal2-client-ws`: veil 13010, drift 13011, cdn 13012, veil+ech 13013; hy2 via sing-box :13023; experiment clients as systemd units (`kal2-quasar-client2` → SOCKS 13102, `kal2-cdn-client2` → 13112, `kal2-client-dev` binary). `/root/bench/bench.sh [rounds] [protos]` runs interleaved rounds → `/root/bench/bench.csv` (ttfb_med, lul p50/p95, dl_us, dl_cf).

Credentials live in `/root/soak/ms.creds` (PUB/PSK/ECH/MU/MP). hy2 test creds: password `3f45c159-7648-42a0-b4ec-4585201402df`, sni `us-ech` proxy `us-hy2.xn--80atldb.click`, obfs salamander `4008e6463aef20e3c837190077f631d8`, alpn h3.

## Measured path profile (2026-09, fix conditions when quoting)

- RTT ~144 ms; TCP RU→US ~98 Mbit/s; **TCP US→RU ~11 MB/s** (time-varying throttle).
- **UDP inbound to RU is policed**: ~25-85% loss for any flow — iperf3, raw paced floods, and KCP alike; port, rate, packet size, FEC and payload shape make no difference. The edge is stateful: UDP only passes on flows the RU host initiated (outbound punch needed for raw probes).
- ⇒ UDP carriers (quasar, hy2) cap ~2-6 MB/s and collapse entirely in bad windows; TCP carriers (cdn+lanes) sustain 10-11 MB/s. hy2 keeps ~5-6 MB/s only in good UDP windows.
- tcpdump on the US virtio box reports directions inverted ("In" = outbound).

## Winning config (PR #15)

`-carrier cdn -lanes 4` client-side. Lanes pools parallel carrier sessions; `Client.Session()` picks the lane with min `SentBytes()` so bulk transfers pin their own lane. Combined with session SFQ + `OpenOpt` optimistic open: dl ~2× hy2, TTFB ~0.31-0.37 vs 0.66-2.2, LUL p50 ~0-0.33 vs 0.58-1.76 in interleaved bench rounds.

## Gotchas

- RU box = 1 vCPU — not the bottleneck; `UdpRcvbufErrors` flat → middlebox drops, not host.
- `pkill -f <x>` matches your own `ssh … bash -c` cmdline and kills the connection — use `kill <pid>` or mv-replace.
- sed against systemd units fails silently when flags use `$ENVVAR` — match the `Environment=` line instead.
- Restart the quasar client after restarting kal2-quasar: KCP is stateless, a stale client "session" hangs on SOCKS connect.
