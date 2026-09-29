#!/usr/bin/env python3
"""report.py — fold canary JSONL runs into a weekly markdown report.

    python3 research/report.py [RUNS_DIR] [--days 7] [--out report.md]
"""
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def pct(vs):
    vs = sorted(vs)
    return vs[len(vs) // 2] if vs else 0


def main():
    runs_dir = Path(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "research/runs")
    days = int(sys.argv[sys.argv.index("--days") + 1]) if "--days" in sys.argv else 7
    out = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else None
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    recs = []
    for f in sorted(runs_dir.glob("canary-*.jsonl")):
        for line in f.read_text().splitlines():
            try:
                r = json.loads(line)
                ts = datetime.fromisoformat(r["ts"].replace("Z", "+00:00"))
                if ts >= cutoff:
                    recs.append((ts, r, f.parent.parent.name if f.parent.parent.name else ""))
            except Exception:
                continue
    if not recs:
        print(f"no records in {runs_dir} within {days}d", file=sys.stderr)
        sys.exit(1)

    carriers = defaultdict(lambda: {"hs": [], "hs_ms": [], "ttfb": [], "bps": [], "bytes": []})
    trunc = []
    sni_rows = defaultdict(lambda: [0, 0])
    batch = []
    dns = []

    for ts, r, site in recs:
        p = r["probe"]
        if p == "handshake":
            c = carriers[r["carrier"]]
            c["hs"].append(r["ok"])
            if r["ok"]:
                c["hs_ms"].append(r["ms"])
        elif p == "probe":
            c = carriers[r["carrier"]]
            c["ttfb"].append(r["ttfb_ms"])
            c["bps"].append(r["bps"])
            c["bytes"].append(r["bytes"])
        elif p == "truncation":
            trunc.append((ts, r["direct_bytes"], r["direct_bps"]))
        elif p == "sni":
            row = sni_rows[r["sni"]]
            row[0] += r["ok"]
            row[1] += 1
        elif p == "batch":
            batch.append(r)
        elif p == "dns":
            dns.append(r)

    md = []
    md.append(f"# KAL/2 carrier liveness — last {days}d")
    md.append(f"_runs: {len(set(f for _, _, f in recs))} → {len(recs)} records_\n")
    md.append("| carrier | handshake ok | p50 hs ms | p50 ttfb ms | p50 Mbps | avg MB/flow |")
    md.append("|---|---|---|---|---|---|")
    for name, c in sorted(carriers.items()):
        if not c["hs"]:
            continue
        ok_pct = 100.0 * sum(c["hs"]) / len(c["hs"])
        mbps = pct(c["bps"]) / 125000
        mb = (sum(c["bytes"]) / len(c["bytes"]) / 1e6) if c["bytes"] else 0
        md.append(
            f"| {name} | {ok_pct:.0f}% ({sum(c['hs'])}/{len(c['hs'])}) | "
            f"{pct(c['hs_ms'])} | {pct(c['ttfb'])} | {mbps:.1f} | {mb:.1f} |"
        )
    md.append("")
    if trunc:
        worst = min(b for _, b, _ in trunc)
        md.append(f"**Flow truncation** — direct-egress bytes before stall, min seen: {worst/1e6:.1f} MB "
                  f"({len(trunc)} probes)")
    if sni_rows:
        md.append("\n**SNI reachability to server IP:**")
        for s, (ok, n) in sorted(sni_rows.items()):
            md.append(f"- `{s}`: {ok}/{n}")
    if batch:
        oks = [b["ok"] / b["n"] for b in batch]
        md.append(f"\n**Connect burst** — median accept rate {100*sorted(oks)[len(oks)//2]:.0f}%")
    if dns:
        d = dns[-1]
        md.append(f"\n**DNS**: local=`{d['local']}` 8.8.8.8=`{d['google']}`")

    text = "\n".join(md) + "\n"
    if out:
        out.write_text(text)
        print(f"wrote {out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
