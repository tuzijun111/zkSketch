#!/usr/bin/env python3
"""batchsplit.py <run_dir> <T> <L>: per-batch wall time of a T-leaf forest with L leaves per batch, from the
worker RSS humps (humps.py, FRAC=0.6) aligned to exp_compose's QLOG_PHASE marks (memsample T0).
Batch 1 = worker phase start (auditor_new: the coordinator spawns the worker) -> end of batch 1's last own
merge (hump 2L-1); batch b>1 = end of batch b-1's last own merge -> end of batch b's last own merge;
the remainder up to root_received is the cross-batch merge(s) and shipping the root.
Also the CSV formula: per batch = (total_time_ms - (T/L - 1) x fold_per_merge) / (T/L)."""
import csv, glob, os, re, subprocess, sys
d, T, L = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
here = os.path.dirname(os.path.abspath(__file__))
out = subprocess.run([sys.executable, "-I", os.path.join(here, "humps.py"), d, "0", str(T), str(L)], capture_output=True, text=True).stdout
ends = [float(m.group(2)) for m in re.finditer(r"hump\s+\d+ .*?([\d.]+)-\s*([\d.]+)s", out)]
log = [p for p in glob.glob(os.path.join(d, "out", "six_zksketch_*.log"))][0]
txt = open(log).read()
mk = {m.group(1): int(m.group(2)) / 1000 for m in re.finditer(r"QLOG_PHASE,after=(\w+),.*?unix_ms=(\d+)", txt)}
t0 = float(re.search(r"MEMSAMPLE_T0_UNIX=([\d.]+)", open(os.path.join(d, "memsum.txt")).read()).group(1))
ws, we = mk["auditor_new"] - t0, mk["root_received"] - t0
nb = T // L
sched = []
for i in range(1, T + 1):
    sched.append(("leaf", i))
    sched += [("merge", i)] * ((i & -i).bit_length() - 1)
lastown = []
for b in range(1, nb + 1):
    leaf = b * L
    k0 = sched.index(("leaf", leaf))
    lastown.append(k0 + (L.bit_length() - 1))  # index of the batch's own top merge
assert len(ends) == len(sched), (len(ends), len(sched))
prev = ws; res = []
for b, k in enumerate(lastown, 1):
    res.append(ends[k] - prev); prev = ends[k]
row = next(r for p in glob.glob(os.path.join(d, "out", "six_zksketch_*.csv")) if not p.endswith("_runs.csv") for r in csv.DictReader(open(p)))
tot, fold = float(row["total_time_ms"]) / 1000, float(row["local_fold_ms"]) / 1000
leafs = float(row["leafgen_seq_ms"]) / 1000
fpm = fold / (T - 1)
formula = (tot - (nb - 1) * fpm) / nb
print(f"{os.path.basename(d)}: worker phase {we - ws:.1f}s; " + "; ".join(f"batch {i} {v:.1f}s" for i, v in enumerate(res, 1)) +
      f"; cross-batch merge + root {we - prev:.1f}s | CSV total {tot:.1f}s = leaves {leafs:.1f}s ({leafs / T:.2f}/leaf) + merges {fold:.1f}s ({fpm:.2f}/merge) + other {tot - leafs - fold:.1f}s; formula per batch {formula:.1f}s")
