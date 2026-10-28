#!/usr/bin/env python3
"""Count-Min operator (ZoKrates) vs zkSketch leaf: per-chunk tables and least-squares lines a + b * records on both sides.
Usage: python3 scripts/baselines/zkstream/fit.py   (after run_zkstream.py and run_ours.sh)
"""
import csv, math, statistics, sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
ZKA = HERE.parent / "zka" / "results"
N_STREAM = 1 << 20


def ols(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return my - b * mx, b


def load(path):
    if not path.exists():
        sys.exit(f"fit.py: missing {path} -- run the drivers first")
    with path.open() as f:
        return list(csv.DictReader(f))


def one(path, col):
    rows = load(path)
    return float(rows[0][col]) if rows else float("nan")


zok = load(RES / "zkstream_small.csv")
latest = max(r["run"] for r in zok)
zok = [r for r in zok if r["run"] == latest]
ours = load(RES / "zks_small.csv")

print(f"ZoKrates run {latest}   (d={zok[0]['d']}, w={zok[0]['w']})\n")

# ---- soundness gate -------------------------------------------------------
bad = [r for r in zok if r["step"].startswith(("tamper_", "witness_op", "verify")) and r["ok"] == "0"]
if bad:
    for r in bad:
        print(f"GATE FAILED: k={r['k']} chunk={r['chunk']} {r['step']} {r['note']}")
    sys.exit("fit.py: soundness or chain check failed -- no cost figure is valid")
tam = [r for r in zok if r["step"].startswith("tamper_")]
print(f"soundness: {len(tam)} forged inputs rejected; every chained witness and verify ok\n")

# ---- closed-form constraint count (packed8, d=3 w=1024 only) -------------
per_k = defaultdict(dict)
for r in zok:
    k = int(r["k"])
    if r["step"] == "compile_op":
        per_k[k].update(cons=int(r["constraints"]), compile_s=float(r["wall_s"]), compile_mb=float(r["peak_rss_mb"]))
    elif r["step"] == "setup":
        per_k[k].update(setup_s=float(r["wall_s"]), pk_bytes=int(r["bytes"]))
    elif r["step"] in ("witness_op", "prove", "verify"):
        per_k[k].setdefault(r["step"], []).append(float(r["wall_s"]))
        if r["step"] == "prove":
            per_k[k]["prove_mb"] = max(per_k[k].get("prove_mb", 0), float(r["peak_rss_mb"]))
            per_k[k]["proof_b"] = int(r["bytes"])

print("ZoKrates operator, per chunk                                            (MEASURED)")
print(f"{'k':>5} {'constraints':>12} {'model':>10} {'compile':>9} {'setup':>8} {'witness':>8} {'prove':>8} {'verify':>8} {'prove RSS':>10}")
for k in sorted(per_k):
    v = per_k[k]
    model = 1516 * k + 54512 + 354 * math.ceil(k / 5) + 412 if (zok[0]["d"], zok[0]["w"]) == ("3", "1024") else None
    mtxt = ("exact" if model == v["cons"] else f"{v['cons'] - model:+d}") if model else "n/a"
    print(f"{k:>5} {v['cons']:>12,} {mtxt:>10} {v['compile_s']:>8.1f}s {v['setup_s']:>7.2f}s "
          f"{statistics.median(v['witness_op']):>7.2f}s {statistics.median(v['prove']):>7.2f}s "
          f"{statistics.median(v['verify']):>7.2f}s {v['prove_mb']:>8.0f}MB")

ks = sorted(per_k)
zx = [float(k) for k in ks]
zy = [statistics.median(per_k[k]["witness_op"]) + statistics.median(per_k[k]["prove"]) for k in ks]
za, zb = ols(zx, zy)
rate = [per_k[k]["cons"] / statistics.median(per_k[k]["prove"]) for k in ks]
print(f"\nGroth16 (ark) prove rate: {', '.join(f'{x:,.0f}' for x in rate)} constraints/s at k={ks}   (MEASURED)")
print(f"fit, witness+prove per chunk = {za:.3f} s + {zb * 1000:.3f} ms/record                (FIT)")

# ---- zkSketch --------------------------------------------------------------
by_m = defaultdict(list)
for r in ours:
    by_m[int(r["m"])].append(r)
print("\nzkSketch leaf, t=1                                                     (MEASURED, median of reps)")
print(f"{'m':>5} {'reps':>5} {'prove':>9} {'verify':>9} {'proof':>11} {'RSS':>9}")
sx, sy = [], []
for m in sorted(by_m):
    rs = by_m[m]
    tot = statistics.median(float(r["total_time_ms"]) for r in rs) / 1000
    ver = statistics.median(float(r["verify_ms"]) for r in rs)
    pb = statistics.median(int(r["proof_bytes"]) for r in rs)
    rss = statistics.median(float(r["peak_rss_mb"]) for r in rs)
    sx.append(float(m)); sy.append(tot)
    print(f"{m:>5} {len(rs):>5} {tot:>8.2f}s {ver:>7.2f}ms {pb:>10,}B {rss:>7.0f}MB")
sa, sb = ols(sx, sy)
print(f"\nfit, leaf prove = {sa:.3f} s + {sb * 1000:.3f} ms/record                          (FIT)")

# ---- validate our fit against the measured 2^14 leaf ------------------------
m14 = 1 << 14
meas14 = one(ZKA / "zks_matched_t1.csv", "total_time_ms") / 1000
pred14 = sa + sb * m14
print(f"check: fit predicts {pred14:.2f} s at m=2^14; MEASURED {meas14:.2f} s "
      f"({(pred14 - meas14) / meas14:+.1%})")
if abs(pred14 - meas14) / meas14 > 0.25:
    print("  -> the small-m fit misses the measured 2^14 point by more than 25%; use the measured point")

# ---- head to head at the measured sizes ------------------------------------
m14_rate = meas14 / m14
zmed = {k: statistics.median(per_k[k]["witness_op"]) + statistics.median(per_k[k]["prove"]) for k in ks}
print("\nSame batch size, d, w, keys and cores                                   (MEASURED)")
print(f"{'batch':>6} {'ZoKrates w+p':>13} {'zkSketch':>10} {'prover':>8}   {'verify':>17}   {'proof bytes':>22}")
for b in sorted(set(ks) & set(by_m)):
    smed = statistics.median(float(r["total_time_ms"]) for r in by_m[b]) / 1000
    zv = statistics.median(per_k[b]["verify"]) * 1000
    sv = statistics.median(float(r["verify_ms"]) for r in by_m[b])
    sp = statistics.median(int(r["proof_bytes"]) for r in by_m[b])
    print(f"{b:>6} {zmed[b]:>12.2f}s {smed:>9.2f}s {zmed[b] / smed:>7.1f}x   "
          f"{zv:>5.1f} vs {sv:>5.1f} ms   {per_k[b]['proof_b']:>6,} vs {sp:>9,} B")
print("  verify on the ZoKrates side is the CLI, process start included; proof bytes are its JSON encoding")
print(f"\nper record: ZoKrates {zb * 1000:.2f} ms (slope k={ks[0]}..{ks[-1]})  vs  zkSketch "
      f"{sb * 1000:.2f} ms (slope m={sx[0]:.0f}..{sx[-1]:.0f}) / {m14_rate * 1000:.2f} ms (MEASURED at 2^14)"
      f"  ->  {zb / sb:.1f}x / {zb / m14_rate:.1f}x")

# ---- break-even, stated for every case ---------------------------------------
if za >= sa and zb >= sb:
    print("break-even: none -- zkSketch is cheaper per batch at every size (Groth16 has the larger intercept AND slope)")
elif za <= sa and zb <= sb:
    print("break-even: none -- Groth16 is cheaper per batch at every size")
else:
    bstar = (sa - za) / (zb - sb)
    lo, hi = ("Groth16", "zkSketch") if za < sa else ("zkSketch", "Groth16")
    print(f"break-even: ~{bstar:,.0f} records per batch; {lo} is cheaper below it, {hi} above      (FIT)")

# ---- the 2^20-record stream ---------------------------------------------------
print("\n2^20 records (ZoKrates side from its fit; zkSketch forest MEASURED)")
forest = one(ZKA / "zks_matched_t64_forest.csv", "total_time_ms") / 1000
forest_v = one(ZKA / "zks_matched_t64_forest.csv", "verify_ms")
forest_b = one(ZKA / "zks_matched_t64_forest.csv", "proof_bytes")
print(f"  zkSketch forest: prove {forest:,.0f} s, verify {forest_v:.1f} ms, one root of {forest_b / 1e3:,.0f} KB")
for k in ks:
    chunks = N_STREAM // k
    stream = chunks * (za + zb * k)
    zv = statistics.median(per_k[k]["verify"])
    print(f"  k={k:<4} {chunks:>6} Groth16 proofs: prove {stream / 3600:5.2f} h ({stream / forest:4.1f}x) | "
          f"verify all {chunks * zv:5.1f} s CLI | {chunks * per_k[k]['proof_b'] / 1e6:5.2f} MB JSON")
floor = N_STREAM * zb
print(f"  as k grows the prover ratio tends to the slope ratio: {floor / 3600:.2f} h, {floor / forest:.1f}x   (FIT)")
print("  Name the ZoKrates side 'a Count-Min operator following zkStream's design (our circuit)', never 'zkStream'.")
