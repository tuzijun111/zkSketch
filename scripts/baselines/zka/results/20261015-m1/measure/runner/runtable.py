#!/usr/bin/env python3
"""runtable.py <runs_dir> <load.csv>...: one markdown row per clean run: build, update makespan (leaves + merges),
per leaf / per merge, VK / audit / query phases, combined peaks (coordinator + worker, 0.1 s), others' load."""
import csv, datetime, json, os, re, sys
D = sys.argv[1]
load = [r for L in sys.argv[2:] for r in csv.DictReader(open(L))]
def win(meta):
    ts = lambda s: datetime.datetime.fromisoformat(s).timestamp()
    a = ts(re.search(r"start=(\S+)", meta).group(1)); b = ts(re.search(r"end=(\S+)", meta).group(1))
    o = [float(r["busy_cores_others"]) for r in load if a <= float(r["unix_s"]) <= b]
    return (sum(o) / len(o), max(o)) if o else (float("nan"), float("nan"))
print("| run | build | start | makespan s | leaves s (per leaf) | merges s (per merge; cache hits/misses) | VK phase s / peak MiB | worker peak MiB (coord + worker) | audit s / peak | queries s / peak | whole-run peak MiB | wall s | others' busy cores mean / max |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
def _st(x):
    try: return re.search(r"start=(\S+)", open(os.path.join(D, x, "meta.txt")).read()).group(1)
    except Exception: return ""
for n in sorted(os.listdir(D), key=_st):
    p = os.path.join(D, n, "phases.json")
    if not os.path.exists(p): continue
    o = json.load(open(p)); c = o["csv"]; ph = o["phases"]
    T = int(re.search(r"\bT=(\d+)", o["meta"]).group(1)); b = re.search(r"build=(\w+)", o["meta"]).group(1)
    st = re.search(r"start=\S+T(\d\d:\d\d:\d\d)", o["meta"]).group(1)
    hm = re.search(r"hits=(\d+);misses=(\d+)", o["worker_line"][0]); h, m = int(hm.group(1)), int(hm.group(2))
    lv, mg = float(c["leafgen_seq_ms"]) / 1e3, float(c["local_fold_ms"]) / 1e3
    om, ox = win(o["meta"])
    w = ph["worker"]
    print(f"| {n} | {b} | {st} | {float(c['total_time_ms'])/1e3:.1f} | {lv:.1f} ({lv/T:.2f}) | {mg:.1f} ({mg/(h+m):.2f}; {h}/{m}) | "
          f"{ph['vk']['dur_s']:.1f} / {ph['vk']['peak_comb']:,.0f} | {w['peak_comb']:,.0f} ({w['at_coord']:,.0f} + {w['at_worker']:,.0f}) | "
          f"{ph['audit']['dur_s']:.1f} / {ph['audit']['peak_comb']:,.0f} | {ph['query']['dur_s']:.1f} / {ph['query']['peak_comb']:,.0f} | "
          f"{ph['whole']['peak_comb']:,.0f} | {o['rsstree']['wall']:.1f} | {om:.2f} / {ox:.2f} |")
