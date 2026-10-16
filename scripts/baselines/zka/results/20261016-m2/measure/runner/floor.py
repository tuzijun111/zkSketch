#!/usr/bin/env python3
"""floor.py <run_dir>...: the procs worker's RSS floor between proofs. A valley is a maximal run of samples below
FRAC x the worker's peak (FRAC=0.42 by default, so in-proof dips stay above it); its minimum is that gap's floor.
Valleys before the first proof (worker start-up) and after the worker phase are dropped.
Reports the first valley (post-first-leaf level) and the median / max of the later ones."""
import csv, os, statistics as st, sys
FRAC = float(os.environ.get("FRAC", "0.42"))
for d in sys.argv[1:]:
    w = []
    for row in csv.reader(open(os.path.join(d, "mem.csv"))):
        if row[0] == "t_s": continue
        mb = sum(float(p.split(":")[2]) for p in (row[3].split(";") if len(row) > 3 and row[3] else []) if p.split(":")[1].startswith("zks_dc_exe"))
        if mb > 0: w.append((float(row[0]), mb))
    pk = max(v for _, v in w); th = FRAC * pk
    first_hi = next(i for i, (_, v) in enumerate(w) if v >= th)
    last_hi = max(i for i, (_, v) in enumerate(w) if v >= th)
    vals, cur = [], None
    for t, v in w[first_hi:last_hi + 1]:
        if v < th: cur = v if cur is None else min(cur, v)
        elif cur is not None: vals.append(cur); cur = None
    later = vals[1:]
    print(f"{os.path.basename(d):10s} valleys={len(vals):2d} post_first_leaf={vals[0]:5.0f} later: median={st.median(later):5.0f} max={max(later):5.0f} "
          f"(max - post_first_leaf = {max(later) - vals[0]:+5.0f}; median - post_first_leaf = {st.median(later) - vals[0]:+5.0f}) worker_peak={pk:5.0f}")
