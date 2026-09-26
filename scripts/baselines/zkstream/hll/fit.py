#!/usr/bin/env python3
"""Fit the HyperLogLog operator runs and model the deployed size. Every figure is
labelled MEASURED or MODELED.

  * soundness gate: every chained witness, helper==native check, proof and forgery row
    must be ok, or no cost figure is printed;
  * constraints: the exact closed form native.constraints(k, s, P, CK), checked against
    every compile;
  * witness+prove time: linear in constraints (fitted on all measured points), and the
    per-s intercept/slope in k that it implies;
  * compile wall/RSS: a0 + a1*S + k*(b0 + b1*S) least squares over all measured
    compiles (small k), and at the deployed s = 2^14 time = a + b*k + c*k^2 (ZoKrates'
    reducer is superlinear in k) and memory = a + b*k, checked against any measured
    refusal; the deployed verdict uses the s = 2^14 model;
  * deployed size s = 2^14 registers, m = 2^14 records per batch, 2^20-record stream:
    constraints (exact formula), compile (modeled, against the 45 min / 150 GB wall),
    setup/prove/pk (modeled), and the stream cost at the largest chunk that compiles.
"""
import csv, math, statistics, sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native import constraints as cons_model  # noqa: E402  (exact closed form)

HERE = Path(__file__).resolve().parent
RES = HERE.parent / "results"
CSV = RES / "zkstream_hll.csv"
N_STREAM = 1 << 20
DEPLOY_S, DEPLOY_M = 1 << 14, 1 << 14
WALL_S, WALL_MB = 45 * 60, 150 * 1024


def geometry(s, P=None):
    b = s.bit_length() - 1
    P = P or min(32, s)
    return b, P, s // P, 64 - b


def per_record(s, P=None, ck=8):
    """Amortized marginal constraints per record (digest share excluded)."""
    b, P, S, Q = geometry(s, P)
    return 764 + 2 * S + Q + 7 * (P - 1) + (P.bit_length() - 1) + S / ck


def ols(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    ss_res = sum((y - a - b * x) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys) or 1.0
    return a, b, 1 - ss_res / ss_tot


def powerlaw(xs, ys):
    a, g, r2 = ols([math.log(x) for x in xs], [math.log(y) for y in ys])
    return math.exp(a), g, r2


def load(path):
    if not path.exists():
        sys.exit(f"fit.py: missing {path} -- run run_hll.py first")
    with path.open() as f:
        return list(csv.DictReader(f))


CKSEL = int(sys.argv[1]) if len(sys.argv) > 1 else 8  # wire-refresh interval of the runs to fit
rows = [r for r in load(CSV) if r.get("CK") == str(CKSEL)]
if not rows:
    sys.exit(f"fit.py: no rows with CK={CKSEL} in {CSV}")
# keep, per (s, P, k), the latest run that reached its chain row (or its refusal)
latest = {}
for r in rows:
    key = (int(r["s"]), int(r["P"]), int(r["k"]))
    if r["step"] in ("chain",) or (r["step"].startswith("compile") and r["ok"] == "0"):
        latest[key] = max(latest.get(key, ""), r["run"])
rows = [r for r in rows if latest.get((int(r["s"]), int(r["P"]), int(r["k"]))) == r["run"]]
runs = sorted({r["run"] for r in rows})
print(f"zokrates_hll_op runs used: {', '.join(runs)}\n")

# ---- soundness gate -----------------------------------------------------------
gated = ("witness_helper", "native_statement", "witness_op", "prove", "verify", "chain")
bad = [r for r in rows if (r["step"] in gated or r["step"].startswith("tamper_")) and r["ok"] == "0"]
if bad:
    for r in bad:
        print(f"GATE FAILED: s={r['s']} k={r['k']} chunk={r['chunk']} {r['step']} {r['note']}")
    sys.exit("fit.py: soundness or chain check failed -- no cost figure is valid")
tam = [r for r in rows if r["step"].startswith("tamper_") and r["ok"] == "1"]
chains = [r for r in rows if r["step"] == "chain"]
kinds = sorted({r["step"][7:] for r in tam})
print(f"soundness: {len(tam)} forgeries rejected over {len(chains)} points ({len(kinds)} kinds: {', '.join(kinds)});")
nh = len({(r["s"], r["k"]) for r in rows if r["step"] == "witness_helper"})
nn = len({(r["s"], r["k"]) for r in rows if r["step"] == "native_statement"})
print(f"           {len(chains)} chains ok: com_in==prev com_out and every proof verifies; helper state == native "
      f"reference on {nh} points, statement from native.py alone on {nn} (--no-helper)\n")

# ---- per point ------------------------------------------------------------------
pt = defaultdict(lambda: defaultdict(list))
refused = []
for r in rows:
    key = (int(r["s"]), int(r["P"]), int(r["k"]))
    v = pt[key]
    st = r["step"]
    if st == "compile_op":
        if r["ok"] == "0":
            refused.append((key, r))
            continue
        v["cons"] = int(r["constraints"]); v["compile_s"] = float(r["wall_s"]); v["compile_mb"] = float(r["peak_rss_mb"])
    elif st == "setup":
        v["setup_s"] = float(r["wall_s"]); v["setup_mb"] = float(r["peak_rss_mb"]); v["pk_b"] = int(r["bytes"])
    elif st in ("witness_op", "prove", "verify"):
        v[st].append(float(r["wall_s"]))
        if st == "prove":
            v["prove_mb"] = max(v.get("prove_mb", 0), float(r["peak_rss_mb"]))
            v["proof_b"] = int(r["bytes"])
    if r["load1"]:
        v["load"].append(float(r["load1"]))
pts = {k: v for k, v in pt.items() if "cons" in v and v["prove"]}

print("Per point, one 4-chunk chain each                                                          (MEASURED)")
print(f"{'s':>6} {'P':>3} {'k':>5} {'constraints':>12} {'formula':>8} {'compile':>9} {'RSS':>7} {'setup':>7} "
      f"{'pk MB':>7} {'witness':>8} {'prove':>7} {'verify':>7} {'proof':>6} {'load1':>10}")
exact = 0
for key in sorted(pts):
    s, P, k = key
    v = pts[key]
    f = cons_model(k, s, P, CKSEL)
    exact += f == v["cons"]
    ftxt = "exact" if f == v["cons"] else f"{v['cons'] - f:+d}"
    print(f"{s:>6} {P:>3} {k:>5} {v['cons']:>12,} {ftxt:>8} {v['compile_s']:>8.1f}s {v['compile_mb'] / 1024:>6.2f}G "
          f"{v['setup_s']:>6.2f}s {v['pk_b'] / 1e6:>7.1f} {statistics.median(v['witness_op']):>7.3f}s "
          f"{statistics.median(v['prove']):>6.3f}s {statistics.median(v['verify']) * 1e3:>5.1f}ms {v['proof_b']:>6} "
          f"{min(v['load']):>4.1f}-{max(v['load']):<4.1f}")
for key, r in refused:
    print(f"{key[0]:>6} {key[1]:>3} {key[2]:>5} {cons_model(key[2], key[0], key[1], CKSEL):>12,} {'(model)':>8} "
          f"REFUSED after {float(r['wall_s']):.0f}s / {float(r['peak_rss_mb'] or 0) / 1024:.1f}G: {r['note'][:60]}")
print(f"constraint formula exact on {exact}/{len(pts)} measured points")

# probes (compile-only)
for name in ("zkstream_hll_constraint_probe.csv", "zkstream_hll_packing_probe.csv"):
    p = RES / name
    if p.exists():
        pr = [r for r in load(p) if r["constraints"] not in ("", "FAILED")]
        ok = sum(cons_model(int(r["k"]), int(r["s"]), int(r["P"]), int(r["CK"])) == int(r["constraints"]) for r in pr)
        print(f"  {name}: formula exact on {ok}/{len(pr)} probe compiles")

# ---- wire refresh justification ----------------------------------------------------
rp = RES / "zkstream_hll_refresh_probe.csv"
if rp.exists():
    with rp.open() as f:
        rr = list(csv.DictReader(line for line in f if not line.startswith("#")))
    print("\nWire refresh at s=2^14 (compile only; CK=none is the v1 encoding)                           (MEASURED)")
    print(f"  {'CK':>4} {'k':>5} {'constraints':>12} {'compile':>9} {'RSS':>7} {'program':>9}")
    for r in rr:
        print(f"  {r['CK']:>4} {r['k']:>5} {int(r['constraints']):>12,} {float(r['compile_s']):>8.1f}s "
              f"{float(r['peak_rss_mb']) / 1024:>6.1f}G {int(r['out_bytes']) / 1e6:>7.0f}MB")
    v1 = sorted((int(r["k"]), int(r["out_bytes"])) for r in rr if r["CK"] == "none")
    inc = [f"{(b2 - b1) / (k2 - k1) / 1e6:.1f}" for (k1, b1), (k2, b2) in zip(v1, v1[1:])]
    print(f"  v1 program growth per record between successive k: {', '.join(inc)} MB (grows with k: quadratic total)")

# ---- packing justification ------------------------------------------------------
print("\nPacking (registers per field element), per-chunk constraints from the exact formula      (MODELED, "
      "formula checked on the P sweep)")
for s, k in ((1024, 64), (DEPLOY_S, 64), (DEPLOY_S, DEPLOY_M)):
    line = ", ".join(f"P={P}: {cons_model(k, s, P, CKSEL):,}" for P in (1, 4, 8, 16, 32) if P <= s)
    print(f"  s={s:<6} k={k:<6} {line}")

# ---- time fits ------------------------------------------------------------------
keys = sorted(pts)
xs = [pts[k]["cons"] for k in keys]
wp = [statistics.median(pts[k]["witness_op"]) + statistics.median(pts[k]["prove"]) for k in keys]
pr_ = [statistics.median(pts[k]["prove"]) for k in keys]
wi_ = [statistics.median(pts[k]["witness_op"]) for k in keys]
ta, tb, tr2 = ols(xs, wp)
pa, pb, pr2 = ols(xs, pr_)
wa, wb, wr2 = ols(xs, wi_)
sa, sb, sr2 = ols(xs, [pts[k]["setup_s"] for k in keys])
ka, kb, kr2 = ols(xs, [pts[k]["pk_b"] for k in keys])
rssa, rssb, rssr2 = ols(xs, [pts[k]["prove_mb"] for k in keys])
print("\nTime and size vs constraints n, least squares over all measured points                    (MODELED)")
print(f"  witness+prove = {ta:.3f} s + {tb * 1e6:.3f} us * n   (R^2 {tr2:.4f}; {1 / tb:,.0f} constraints/s marginal)")
print(f"    prove       = {pa:.3f} s + {pb * 1e6:.3f} us * n   (R^2 {pr2:.4f})")
print(f"    witness     = {wa:.3f} s + {wb * 1e6:.3f} us * n   (R^2 {wr2:.4f})")
print(f"  setup         = {sa:.3f} s + {sb * 1e6:.3f} us * n   (R^2 {sr2:.4f})")
print(f"  proving key   = {ka / 1e6:.2f} MB + {kb:.1f} B * n   (R^2 {kr2:.4f})")
print(f"  prove RSS     = {rssa:.0f} MB + {rssb * 1e3:.3f} KB * n   (R^2 {rssr2:.4f})")
big_i = [i for i, x in enumerate(xs) if x >= 50000]
pl_c, pl_g, pl_r2 = powerlaw([xs[i] for i in big_i], [wp[i] for i in big_i])
print(f"  cross-check, power law on the {len(big_i)} points with n >= 50k: witness+prove = {pl_c:.3e} * n^{pl_g:.3f} (R^2 {pl_r2:.4f})")
print(f"  largest measured n = {max(xs):,}; beyond it these lines are extrapolations")

print("\nPer chunk, in k (from the fits above and the exact formula): witness+prove = a_s + b_s * k    (MODELED)")
for s in sorted({k[0] for k in keys} | {DEPLOY_S}):
    a_s = ta + tb * cons_model(0, s, None, CKSEL)
    b_s = tb * (per_record(s, None, CKSEL) + 339 / 5)
    meas = [k for k in keys if k[0] == s]
    chk = "; ".join(f"k={k[2]}: model {ta + tb * pts[k]['cons']:.2f}s vs {statistics.median(pts[k]['witness_op']) + statistics.median(pts[k]['prove']):.2f}s"
                    for k in meas)
    print(f"  s={s:<6} a={a_s:6.3f} s  b={b_s * 1e3:6.3f} ms/record   [{chk}]")

# ---- compile wall -----------------------------------------------------------------
# Compile is single-threaded. Its time and memory track the unrolled program: a fixed
# part per commitment word and a per-record part that grows with the S-word state
# arrays the record's mux/decoder loops rewrite. Model both as a0 + a1*S + k*(b0 + b1*S)
# (least squares over every measured compile), and cross-check the growth in k at
# s = 2^14 with a power law, which would expose superlinear compiler behaviour.
import numpy as np


def lsq(feats, ys):
    A = np.array(feats, dtype=float)
    y = np.array(ys, dtype=float)
    coef, *_ = np.linalg.lstsq(A, y, rcond=None)
    pred = A @ coef
    r2 = 1 - float(((y - pred) ** 2).sum()) / float(((y - y.mean()) ** 2).sum())
    worst = float(np.max(np.abs(pred - y) / y))
    return coef, r2, worst


def feat(k, s):
    S = geometry(s)[2]
    return [1.0, S, k, k * S]


small = [k for k in keys if k[2] <= 64]
F = [feat(k[2], k[0]) for k in small]
c_t, c_t_r2, c_t_w = lsq(F, [pts[k]["compile_s"] for k in small])
c_m, c_m_r2, c_m_w = lsq(F, [pts[k]["compile_mb"] for k in small])
print("\nCompile (single-threaded; wall 45 min / 150 GB)                                             (MODELED)")
print(f"  all s, k <= 64 ({len(small)} compiles; describes the small grid only, not large k):")
print(f"    compile_s  = {c_t[0]:.2f} + {c_t[1]:.4f}*S + k*({c_t[2]:.4f} + {c_t[3] * 1e3:.4f}e-3*S)   "
      f"(R^2 {c_t_r2:.4f}, worst point {c_t_w:.0%})")
print(f"    compile_MB = {c_m[0]:.1f} + {c_m[1]:.3f}*S + k*({c_m[2]:.3f} + {c_m[3]:.4f}*S)   "
      f"(R^2 {c_m_r2:.4f}, worst point {c_m_w:.0%})")
dk = sorted(k for k in keys if k[0] == DEPLOY_S)
if len(dk) < 3:
    sys.exit("fit.py: need >= 3 measured compiles at s=2^14 for the deployed model")
# At the deployed geometry the compiler's time is superlinear in k (ZoKrates' reducer,
# see README), so fit time = a + b*k + c*k^2 there; memory stays linear in k.
dq, dq_r2, dq_w = lsq([[1.0, k[2], k[2] ** 2] for k in dk], [pts[k]["compile_s"] for k in dk])
dm, dm_r2, dm_w = lsq([[1.0, k[2]] for k in dk], [pts[k]["compile_mb"] for k in dk])
print(f"  s=2^14, k={[k[2] for k in dk]}:")
print(f"    compile_s  = {dq[0]:.1f} + {dq[1]:.4f}*k + {dq[2]:.3e}*k^2   (R^2 {dq_r2:.4f}, worst point {dq_w:.0%})")
print(f"    compile_MB = {dm[0]:.0f} + {dm[1]:.2f}*k   (R^2 {dm_r2:.4f}, worst point {dm_w:.0%})")
big = max(keys, key=lambda k: pts[k]["cons"])
print(f"  largest measured compile: s={big[0]} k={big[2]}: {pts[big]['cons']:,} constraints, "
      f"{pts[big]['compile_s']:.0f} s, {pts[big]['compile_mb'] / 1024:.1f} GB")


def compile_model(k, s=DEPLOY_S):
    """Deployed-geometry compile model (s = 2^14 only)."""
    assert s == DEPLOY_S
    return dq[0] + dq[1] * k + dq[2] * k * k, dm[0] + dm[1] * k


hi2 = dk[-2:]
marg = (pts[hi2[1]]["compile_s"] - pts[hi2[0]]["compile_s"]) / (hi2[1][2] - hi2[0][2])
lin_lb = pts[hi2[1]]["compile_s"] + marg * (DEPLOY_M - hi2[1][2])
print(f"  lower bound at k=2^14 if compile time stopped growing faster than linearly: the marginal "
      f"{marg:.2f} s/record (k={hi2[0][2]}..{hi2[1][2]}) gives {lin_lb / 3600:.1f} h")
for key, r in refused:
    if key[0] == DEPLOY_S:
        t, mb = compile_model(key[2])
        print(f"  MEASURED refusal s=2^14 k={key[2]}: stopped after {float(r['wall_s']):.0f} s "
              f"({r['note'][:40]}); model predicts {t:.0f} s, {mb / 1024:.0f} GB -> "
              f"{'consistent' if t > float(r['wall_s']) or mb > WALL_MB else 'model too optimistic'}")
kmax = 0
for k in range(1, 1 << 16):
    t, mb = compile_model(k)
    if t <= WALL_S and mb <= WALL_MB:
        kmax = k
    elif k > 64:
        break
t_k, mb_k = compile_model(kmax)
print(f"  largest k whose modeled compile fits the wall at s=2^14: ~{kmax:,} records per chunk "
      f"({t_k / 60:.0f} min, {mb_k / 1024:.0f} GB modeled; bound by {'time' if t_k / WALL_S > mb_k / WALL_MB else 'memory'})")

# ---- deployed size ----------------------------------------------------------------
print(f"\nDEPLOYED SIZE: s=2^14 registers, one Groth16 proof per m=2^14-record batch      (MODELED unless marked)")
n = cons_model(DEPLOY_M, DEPLOY_S, None, CKSEL)
t_c, mb_c = compile_model(DEPLOY_M)
print(f"  constraints            {n:,}  (exact formula; {per_record(DEPLOY_S, None, CKSEL):,.0f}/record + {cons_model(0, DEPLOY_S, None, CKSEL):,} fixed + digest)")
print(f"  compile                {t_c / 3600:,.1f} h, {mb_c / 1024:,.0f} GB (quadratic-time model)  -> "
      f"{'EXCEEDS' if t_c > WALL_S or mb_c > WALL_MB else 'within'} the 45 min / 150 GB wall "
      f"({n / max(xs):.0f}x the largest measured circuit)")
print(f"  setup                  {sa + sb * n:,.0f} s, proving key {(ka + kb * n) / 1e9:,.1f} GB")
t_wp = ta + tb * n
print(f"  witness+prove / batch  {t_wp:,.0f} s linear fit ({pl_c * n ** pl_g:,.0f} s power law),  "
      f"prove RSS {(rssa + rssb * n) / 1024:,.0f} GB")
print(f"  2^20 stream = {N_STREAM // DEPLOY_M} batches: prove {N_STREAM // DEPLOY_M * t_wp / 3600:,.2f} h "
      f"({N_STREAM // DEPLOY_M * pl_c * n ** pl_g / 3600:,.2f} h power law), if it could be compiled; "
      f"verify {N_STREAM // DEPLOY_M} proofs x ~{statistics.median([statistics.median(pts[k]['verify']) for k in keys]) * 1e3:.0f} ms CLI")
if kmax:
    nk = cons_model(kmax, DEPLOY_S, None, CKSEL)
    chunks = math.ceil(N_STREAM / kmax)
    tk = ta + tb * nk
    print(f"  FEASIBLE CHUNKING: k={kmax:,} (largest modeled compile under the wall): {nk:,} constraints/chunk,")
    print(f"     {chunks:,} chained proofs for 2^20 records: prove {chunks * tk / 3600:,.2f} h, "
          f"{chunks * 997 / 1e6:.2f} MB of JSON proofs, {chunks} verifications")
for k in sorted({k[2] for k in keys if k[0] == DEPLOY_S}):
    v = pts[(DEPLOY_S, 32, k)]
    tw = statistics.median(v["witness_op"]) + statistics.median(v["prove"])
    print(f"  MEASURED chunking k={k:<5}: {v['cons']:,} constraints, witness+prove {tw:.2f} s/chunk -> "
          f"{N_STREAM // k:,} proofs, {N_STREAM // k * tw / 3600:,.2f} h for 2^20 records (linear in chunks)")
print(f"  as k grows the stream prover cost tends to 2^20 x {per_record(DEPLOY_S, None, CKSEL) + 339 / 5:,.0f} constraints x {tb * 1e6:.2f} us "
      f"= {N_STREAM * (per_record(DEPLOY_S, None, CKSEL) + 339 / 5) * tb / 3600:,.2f} h (floor, MODELED)")
print("\nName the ZoKrates side 'a HyperLogLog operator following zkStream's design (our circuit)', never 'zkStream'.")
