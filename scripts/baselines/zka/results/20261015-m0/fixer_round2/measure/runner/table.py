#!/usr/bin/env python3
"""table.py <runs_dir>: markdown tables from each run's phases.json (written by phases.py)."""
import json, os, re, statistics as st, sys
D = sys.argv[1]
runs = {}
for n in sorted(os.listdir(D)):
    p = os.path.join(D, n, "phases.json")
    if os.path.exists(p): runs[n] = json.load(open(p))
def g(o, ph, k):
    v = o["phases"].get(ph)
    return v[k] if v else None
def load_start(o):
    m = re.search(r'start=\S+ load="([\d.]+)', o["meta"]); return m.group(1)
def extra(o):
    m = re.findall(r"^(EXP_\S+=\S+(?: EXP_\S+=\S+)*)\s*$", o["meta"], re.M); return m[0] if m else ""
print("| run | switches | load1 at start | VK deriv. (QueryAudit::new) s / peak | update makespan s (leaves + merges) | worker-phase peak (coord + worker) | audit s / peak | query phase s / peak | wall s | **combined peak** (phase) | merge cache |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
for n, o in runs.items():
    c = o["csv"]; ph = o["phases"]
    whole = ph["whole"]
    # which phase holds the whole-run peak
    at = max((k for k in ph if k != "whole" and ph[k]), key=lambda k: ph[k]["peak_comb"])
    w = ph["worker"]
    cache = re.search(r"merge_cache=([^,]+)", o["worker_line"][0]).group(1) if o["worker_line"] else "?"
    sw = "A (all off)" if o["ab"] == "A" and "RETAIN" in o["meta"] else ("B (all on)" if not extra(o) else "B + " + extra(o))
    print(f"| {n} | {sw} | {load_start(o)} | {g(o,'vk','dur_s'):.1f} / {g(o,'vk','peak_comb'):,.0f} | {float(c['total_time_ms'])/1000:.1f} ({float(c['leafgen_seq_ms'])/1000:.1f} + {float(c['local_fold_ms'])/1000:.1f}) | {w['peak_comb']:,.0f} ({w['at_coord']:,.0f} + {w['at_worker']:,.0f}) | {g(o,'audit','dur_s'):.1f} / {g(o,'audit','peak_comb'):,.0f} ({g(o,'audit','at_coord'):,.0f} + {g(o,'audit','at_worker'):,.0f}) | {g(o,'query','dur_s'):.1f} / {g(o,'query','peak_comb'):,.0f} | {o['rsstree']['wall']:.1f} | **{whole['peak_comb']:,.0f}** ({at}) | {cache} |")
