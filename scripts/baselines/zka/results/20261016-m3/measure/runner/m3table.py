#!/usr/bin/env python3
"""m3table.py <runs_dir> <load.csv>: one markdown row per clean run (phases.json from phases.py):
rounds, cap, m, T, makespan, leaves (per leaf), merges (per merge; cache hits/misses), per-batch time
(T=4: the makespan of the single 2,048-record batch; T=8: makespan/2 and 4*leaf + 3*merge; T=16 at m 128:
the makespan), VK / worker / audit / query phases (duration / combined peak), whole-run combined peak,
root VK md5, others' busy cores."""
import csv, datetime, hashlib, json, os, re, sys
D = sys.argv[1]
load = [r for L in sys.argv[2:] for r in csv.DictReader(open(L))]
def win(meta):
    ts = lambda s: datetime.datetime.fromisoformat(s).timestamp()
    a = ts(re.search(r"start=(\S+)", meta).group(1)); b = ts(re.search(r"end=(\S+)", meta).group(1))
    o = [float(r["busy_cores_others"]) for r in load if a <= float(r["unix_s"]) <= b]
    l = [float(r["load1"]) for r in load if a <= float(r["unix_s"]) <= b]
    return (sum(o) / len(o), max(o), sum(l) / len(l)) if o else (float("nan"),) * 3
def st(n):
    try: return re.search(r"start=(\S+)", open(os.path.join(D, n, "meta.txt")).read()).group(1)
    except Exception: return ""
print("| run | rounds | cap / m / T | start | makespan s | leaves s (per leaf) | merges s (per merge; hits/misses) | per 2,048-record batch s | VK phase s / peak MiB | worker phase peak MiB (coord + worker) | audit s / peak | queries s / peak (decode) | whole-run peak MiB | wall s | root VK md5 | others' busy cores mean / max (load1 mean) |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
for n in sorted(os.listdir(D), key=st):
    p = os.path.join(D, n, "phases.json")
    if not os.path.exists(p): continue
    o = json.load(open(p)); c = o["csv"]; ph = o["phases"]; meta = o["meta"]
    T = int(re.search(r"\bT=(\d+)", meta).group(1)); m = int(re.search(r"\bm=(\d+)", meta).group(1))
    cap = int(re.search(r"\bcap=(\d+)", meta).group(1)); rounds = re.search(r"rounds=(\w+)", meta).group(1)
    t0 = re.search(r"start=\S+T(\d\d:\d\d:\d\d)", meta).group(1)
    hm = re.search(r"hits=(\d+);misses=(\d+)", o["worker_line"][0]); h, mi = int(hm.group(1)), int(hm.group(2))
    lv, mg = float(c["leafgen_seq_ms"]) / 1e3, float(c["local_fold_ms"]) / 1e3
    mk = float(c["total_time_ms"]) / 1e3
    pl, pm = lv / T, mg / (h + mi)
    k = 2048 // m  # leaves per 2,048-record batch
    if T == k: pb = f"**{mk:.1f}** (= makespan)"
    else: pb = f"**{mk * k / T:.1f}** (makespan x {k}/{T}); {k}*leaf + {k-1}*merge = {k*pl + (k-1)*pm:.1f}"
    vkp = os.path.join(D, n, "root_vk.bin")
    vk = hashlib.md5(open(vkp, "rb").read()).hexdigest()[:12] if os.path.exists(vkp) and os.path.getsize(vkp) else "-"
    om, ox, lm = win(meta)
    w = ph["worker"]
    print(f"| {n} | {rounds} | {cap} / {m} / {T} | {t0} | {mk:.1f} | {lv:.1f} ({pl:.2f}) | {mg:.1f} ({pm:.2f}; {h}/{mi}) | {pb} | "
          f"{ph['vk']['dur_s']:.1f} / {ph['vk']['peak_comb']:,.0f} | {w['peak_comb']:,.0f} ({w['at_coord']:,.0f} + {w['at_worker']:,.0f}) | "
          f"{ph['audit']['dur_s']:.1f} / {ph['audit']['peak_comb']:,.0f} | {ph['query']['dur_s']:.1f} / {ph['query']['peak_comb']:,.0f} | "
          f"**{ph['whole']['peak_comb']:,.0f}** | {o['rsstree']['wall']:.1f} | {vk} | {om:.2f} / {ox:.2f} ({lm:.1f}) |")
