#!/usr/bin/env python3
"""humps.py <run_dir> <m> <T> [leaves_per_batch]: split the procs worker's RSS trace into proofs.

Every leaf and merge proof is one RSS hump of the worker (zks_dc_exe_*): its big trace/LDE buffers are
mmap'd and returned when the proof ends, so the worker RSS falls between proofs. A hump is a maximal run
of samples above FRAC x the worker peak (FRAC=0.6 by default). In a Bentley-Saxe forest leaf i is followed
by ctz(i) merges, so with L leaves per batch, batch b ends with hump b*(2L-1) (+ the cross-batch merges).
Prints each hump (start, end, peak) labelled leaf/merge by that schedule, and per batch: first hump start ->
last hump end (wall) and the sum of hump durations."""
import csv, os, sys
FRAC = float(os.environ.get("FRAC", "0.6"))
d, m, T = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
L = int(sys.argv[4]) if len(sys.argv) > 4 else T
w = []
for row in csv.reader(open(os.path.join(d, "mem.csv"))):
    if row[0] == "t_s": continue
    mb = sum(float(p.split(":")[2]) for p in (row[3].split(";") if len(row) > 3 and row[3] else []) if p.split(":")[1].startswith("zks_dc_exe"))
    w.append((float(row[0]), mb))
pk = max(v for _, v in w); th = FRAC * pk
humps, cur = [], None
for t, v in w:
    if v >= th:
        if cur is None: cur = [t, t, v]
        else: cur[1] = t; cur[2] = max(cur[2], v)
    elif cur is not None:
        humps.append(cur); cur = None
if cur: humps.append(cur)
# expected schedule
sched = []
for i in range(1, T + 1):
    sched.append(("leaf", i))
    c = (i & -i).bit_length() - 1
    for j in range(c): sched.append(("merge", i))
print(f"worker peak {pk:.0f} MiB, threshold {th:.0f}; humps found {len(humps)}, expected {len(sched)} ({T} leaves + {T-1} merges)")
ok = len(humps) == len(sched)
for k, h in enumerate(humps):
    lab = f"{sched[k][0]:5s} after leaf {sched[k][1]:2d}" if k < len(sched) else "?"
    print(f"  hump {k+1:2d} {lab}  {h[0]:7.1f}-{h[1]:7.1f}s  dur {h[1]-h[0]:5.1f}s  peak {h[2]:5.0f} MiB")
if ok:
    per = 2 * L - 1
    nb = T // L
    for b in range(nb):
        hs = humps[b * (per + 0) + (b and b * 0):][:0]
    # batch b covers sched indices of leaves (b*L+1..(b+1)*L) and their merges that stay inside the batch
    idx = 0; bounds = []
    for b in range(nb):
        first = None; last = None; s = 0.0; nl = nm = 0
        for k, (kind, leaf) in enumerate(sched):
            if b * L < leaf <= (b + 1) * L:
                # merges after leaf (b+1)*L beyond the batch's own log2(L) levels join batches
                if kind == "merge" and leaf == (b + 1) * L:
                    lvl = sum(1 for kk in range(k) if sched[kk] == ("merge", leaf))
                    if lvl >= (L.bit_length() - 1): continue
                h = humps[k]
                first = h[0] if first is None else first; last = h[1]
                s += h[1] - h[0]; nl += kind == "leaf"; nm += kind == "merge"
        print(f"BATCH {b+1}: {nl} leaves + {nm} merges, first hump start -> last hump end {last-first:6.1f}s, sum of humps {s:6.1f}s")
    rest = [humps[k] for k, (kind, leaf) in enumerate(sched) if kind == "merge" and leaf % L == 0 and
            sum(1 for kk in range(k) if sched[kk] == ("merge", leaf)) >= (L.bit_length() - 1)]
    for h in rest: print(f"CROSS-BATCH merge: {h[1]-h[0]:5.1f}s")
