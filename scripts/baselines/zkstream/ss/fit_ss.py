#!/usr/bin/env python3
"""SpaceSaving replay operator: the measured runs (results/zkstream_ss.csv), the exact constraint formula and
least-squares fits evaluated at the deployed size (default s = 2^14 counters, 2^20-record stream).
Usage: fit_ss.py [--s-dep 16384 --stream 1048576 --k-dep 1 16 64 16384]
"""
import argparse, csv, math, statistics, sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSV_PATH = HERE.parent / "results" / "zkstream_ss.csv"
BN254_TWO_ADICITY = 28              # largest radix-2 FFT domain over BN254's scalar field: 2^28
COMPILE_WALL = (461_428, 185, 8.1)  # largest ZoKrates compile in this harness before (CM k=256): constraints, s, GB
CAP_S, CAP_GB = 45 * 60, 150        # per-compile budget used here (timeout 45m, MemoryMax=150G)


def lstsq(X, y):
    """Exact least squares over the rationals (normal equations, Gauss-Jordan)."""
    n = len(X[0])
    A = [[sum(Fraction(r[i]) * r[j] for r in X) for j in range(n)] for i in range(n)]
    b = [sum(Fraction(r[i]) * v for r, v in zip(X, y)) for i in range(n)]
    for c in range(n):
        p = next(r for r in range(c, n) if A[r][c] != 0)
        A[c], A[p], b[c], b[p] = A[p], A[c], b[p], b[c]
        for r in range(n):
            if r != c and A[r][c] != 0:
                f = A[r][c] / A[c][c]
                A[r] = [x - f * z for x, z in zip(A[r], A[c])]
                b[r] -= f * b[c]
    return [b[i] / A[i][i] for i in range(n)]


def ols(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return my - b * mx, b


def fmt_s(sec):
    if sec < 120:
        return f"{sec:.1f} s"
    if sec < 7200:
        return f"{sec / 60:.1f} min"
    if sec < 3 * 86400:
        return f"{sec / 3600:.1f} h"
    if sec < 2 * 365 * 86400:
        return f"{sec / 86400:.1f} days"
    return f"{sec / (365 * 86400):.1f} years"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", default=str(CSV_PATH))
    ap.add_argument("--s-dep", type=int, default=1 << 14, help="deployed SpaceSaving counters")
    ap.add_argument("--stream", type=int, default=1 << 20, help="deployed stream length")
    ap.add_argument("--k-dep", type=int, nargs="+", default=[1, 16, 64, 1 << 14], help="chunk sizes at which to evaluate the fits")
    ap.add_argument("--machine-gb", type=int, default=559, help="RAM of the proving machine")
    ap.add_argument("--cb", type=int, default=21, help="count bits of the layout to fit")
    ap.add_argument("--spe", type=int, default=3, help="slots per committed field element of the layout to fit (v1 = 1)")
    a = ap.parse_args()

    path = Path(a.csv)
    if not path.exists():
        sys.exit(f"fit_ss.py: missing {path} -- run run_ss.py first")
    rows = list(csv.DictReader(path.open()))
    rows = [r for r in rows if r["system"] == "zokrates_ss_op" and int(r["cb"]) == a.cb and int(r.get("spe") or 1) == a.spe]
    spe = a.spe

    def npk(s):  # packed field elements per state commitment
        return math.ceil(s / spe)

    def nblk(s):  # Poseidon calls per state commitment: ceil(ceil(s/spe)/5)
        return math.ceil(npk(s) / 5)

    # latest run per (s, k, cb) that compiled the operator; keep refused compiles separately
    runs = defaultdict(set)
    refused = []
    for r in rows:
        if r["step"] == "compile_op":
            if r["ok"] == "1":
                runs[(int(r["s"]), int(r["k"]), int(r["cb"]))].add(r["run"])
            else:
                refused.append(r)
    # a refusal stays binding only if no later attempt at the same point compiled
    superseded = [r for r in refused if any(run > r["run"] for run in runs.get((int(r["s"]), int(r["k"]), int(r["cb"])), ()))]
    refused = [r for r in refused if r not in superseded]
    pts = {}
    for key, rs in runs.items():
        run = max(rs)
        pts[key] = [r for r in rows if r["run"] == run and (int(r["s"]), int(r["k"]), int(r["cb"])) == key]

    # ---- soundness gate ---------------------------------------------------------
    bad, tam, na, chains = [], 0, 0, 0
    for key, rs in pts.items():
        for r in rs:
            st = r["step"]
            if st.startswith("tamper_"):
                if r["ok"] == "":
                    na += 1
                elif r["ok"] == "1":
                    tam += 1
                else:
                    bad.append((key, r))
            elif st in ("witness_op", "prove", "verify") and r["ok"] != "1":
                bad.append((key, r))
        if any(r["step"] == "verify" for r in rs):
            chains += 1
    if bad:
        for key, r in bad:
            print(f"GATE FAILED: s={key[0]} k={key[1]} chunk={r['chunk']} {r['step']} {r['note']}")
        sys.exit("fit_ss.py: soundness or chain check failed -- no cost figure is valid")
    print(f"soundness gate: {chains} chained runs, every witness/proof/verify ok and every chunk's com_in == "
          f"previous com_out; {tam} forgeries rejected ({na} not applicable to a chain)   (MEASURED)\n")

    # ---- per-point table --------------------------------------------------------
    cb_set = sorted({key[2] for key in pts})
    per = {}
    for key, rs in pts.items():
        v = {}
        for r in rs:
            st = r["step"]
            if st == "compile_op":
                v.update(cons=int(r["constraints"]), compile_s=float(r["wall_s"]), compile_gb=float(r["peak_rss_mb"]) / 1024,
                         out_mb=int(r["bytes"]) / 1e6)
            elif st == "setup":
                v.update(setup_s=float(r["wall_s"]), pk_mb=int(r["bytes"]) / 1e6, setup_gb=float(r["peak_rss_mb"]) / 1024)
            elif st in ("witness_op", "prove", "verify"):
                v.setdefault(st, []).append(float(r["wall_s"]))
                if st == "prove":
                    v["prove_gb"] = max(v.get("prove_gb", 0), float(r["peak_rss_mb"]) / 1024)
                    v["proof_b"] = int(r["bytes"])
            if r["load1"]:
                v.setdefault("load", []).append(float(r["load1"]))
        per[key] = v

    full = sorted(k for k in per if "prove" in per[k])
    print("ZoKrates SpaceSaving replay operator, per chunk                          (MEASURED)")
    print(f"{'s':>4} {'k':>3} {'cb':>3} {'constraints':>12} {'compile':>9} {'comp GB':>8} {'setup':>7} {'pk MB':>7} "
          f"{'witness':>8} {'prove':>7} {'w+p':>7} {'verify':>8} {'proof':>6} {'RSS GB':>7} {'load1':>10}")
    for key in sorted(per):
        v = per[key]
        s, k, cb = key
        if "prove" not in v:
            print(f"{s:>4} {k:>3} {cb:>3} {v['cons']:>12,} {v['compile_s']:>8.1f}s {v['compile_gb']:>7.2f}  (compile-only probe)")
            continue
        wm, pm, vm = (statistics.median(v[x]) for x in ("witness_op", "prove", "verify"))
        print(f"{s:>4} {k:>3} {cb:>3} {v['cons']:>12,} {v['compile_s']:>8.1f}s {v['compile_gb']:>7.2f} {v['setup_s']:>6.2f}s "
              f"{v['pk_mb']:>7.1f} {wm:>7.3f}s {pm:>6.3f}s {wm + pm:>6.3f}s {vm * 1000:>6.1f}ms {v['proof_b']:>5}B "
              f"{max(v['prove_gb'], v['setup_gb']):>7.2f} {min(v['load']):>4.1f}-{max(v['load']):<4.1f}")
    for r in refused:
        print(f"{r['s']:>4} {r['k']:>3} {r['cb']:>3}  compile REFUSED/OVER BUDGET after {float(r['wall_s']):.0f} s, "
              f"peak {float(r['peak_rss_mb']) / 1024:.1f} GB: {r['note']}   (MEASURED outcome)")
    for r in superseded:
        print(f"{r['s']:>4} {r['k']:>3} {r['cb']:>3}  an earlier attempt (run {r['run']}) was refused after {float(r['wall_s']):.0f} s, "
              f"peak {float(r['peak_rss_mb']) / 1024:.1f} GB; a later attempt compiled (row above)   (MEASURED)")

    # ---- constraint formula: exact rational least squares over every compile ---------
    print(f"\nconstraint model (cb={a.cb}, spe={spe}), cons(s,k) = A*s*k + B*k + C*s + G*ceil(s/spe) + D*ceil(ceil(s/spe)/5)"
          " + E*ceil(k/5) + H*k*floor(s/64) + J*s*floor(k/16) + F\n  (fit over all compiled points; G is folded into C when spe=1;"
          " H, J are the materialisation cuts of the final layout)")
    models = {}
    for cb in cb_set:
        ks = [key for key in per if key[2] == cb]
        X = [[s * k, k, s, npk(s), nblk(s), math.ceil(k / 5), k * (s // 64), s * (k // 16), 1] for s, k, _ in ks]
        y = [per[key]["cons"] for key in ks]
        if len(ks) < 9:
            print(f"  cb={cb}: only {len(ks)} points, need 9 -- skipped")
            continue
        coef = lstsq([[v for j, v in enumerate(r) if not (spe == 1 and j == 3)] for r in X], y)
        if spe == 1:
            coef = coef[:3] + [Fraction(0)] + coef[3:]
        res = [yy - sum(c * x for c, x in zip(coef, xx)) for xx, yy in zip(X, y)]
        exact = all(r == 0 for r in res)
        models[cb] = coef
        names = "A B C G D E H J F".split()
        print(f"  cb={cb}: " + ", ".join(f"{n}={float(c):g}" for n, c in zip(names, coef)) +
              f"   residuals: {'all exactly 0' if exact else max(abs(float(r)) for r in res)} over {len(ks)} points")
    cb0 = 21 if 21 in models else (cb_set[0] if models else None)
    if cb0 is None:
        sys.exit("fit_ss.py: no constraint model")
    A, B, Cc, G, D, E, H, J, F = (float(c) for c in models[cb0])

    def cons(s, k):
        return (A * s * k + B * k + Cc * s + G * npk(s) + D * nblk(s) + E * math.ceil(k / 5)
                + H * k * (s // 64) + J * s * (k // 16) + F)

    print(f"  -> per record: {A:g} per slot + {H:g} per 64 slots + {J:g} per slot every 16 records + {B:g} + {E:g}/5 (digest); "
          f"per chunk: {Cc:g} per opened slot + {G:g} per packed element + {D:g} per Poseidon block of {5 * spe} slots (two commitments)")

    # ---- time and memory fits -------------------------------------------------------
    xs = [float(per[k]["cons"]) for k in full]
    pw = [statistics.median(per[k]["prove"]) for k in full]
    ww = [statistics.median(per[k]["witness_op"]) for k in full]
    pa, pb = ols(xs, pw)
    wa, wb = ols(xs, ww)
    sa, sb = ols(xs, [per[k]["setup_s"] for k in full])
    ka, kb = ols(xs, [per[k]["pk_mb"] for k in full])
    ra, rb = ols(xs, [per[k]["prove_gb"] for k in full])
    rates = [x / t for x, t in zip(xs, pw)]
    print(f"\nprove (ark g16)  = {pa:.4f} s + {pb * 1e6:.3f} us/constraint;  rate {min(rates):,.0f}..{max(rates):,.0f} constraints/s   (fit, MEASURED range {min(xs):,.0f}..{max(xs):,.0f})")
    print(f"witness (interp) = {wa:.4f} s + {wb * 1e6:.3f} us/constraint")
    print(f"setup            = {sa:.4f} s + {sb * 1e6:.3f} us/constraint;  proving key {kb * 1e6:.1f} bytes/constraint")
    print(f"prove peak RSS   = {ra:.3f} GB + {rb * 1e6:.3f} KB/constraint")
    vall = [x for k in full for x in per[k]["verify"]]
    print(f"verify (CLI, incl. process start) median {statistics.median(vall) * 1000:.1f} ms, any size; proof {per[full[0]]['proof_b']} B JSON "
          f"(Groth16: 2 G1 + 1 G2, 3 public inputs)")

    comp = sorted(per)
    lx = [math.log(per[k]["cons"]) for k in comp]
    lt = [math.log(per[k]["compile_s"]) for k in comp]
    lm = [math.log(per[k]["compile_gb"]) for k in comp]
    ct_a, ct_b = ols(lx, lt)
    cm_a, cm_b = ols(lx, lm)
    ca, cbb = ols([float(per[k]["cons"]) for k in comp], [per[k]["compile_s"] for k in comp])
    ma, mb = ols([float(per[k]["cons"]) for k in comp], [per[k]["compile_gb"] for k in comp])
    print(f"compile time     = {math.exp(ct_a):.3g} * cons^{ct_b:.3f} s   (log-log; linear: {ca:.2f} s + {cbb * 1e6:.2f} us/constraint)")
    print(f"compile peak RSS = {math.exp(cm_a):.3g} * cons^{cm_b:.3f} GB  (log-log; linear: {ma:.3f} GB + {mb * 1e6:.3f} KB/constraint)")
    k1 = sorted(k for k in comp if k[1] == 1)
    if len(k1) >= 2:
        # compile cost at k=1 against the state size: ZoKrates' frontend is superlinear in
        # the size of the arrays it unrolls over, so fit the two largest k=1 points
        (s1, _, _), (s2, _, _) = k1[-2], k1[-1]
        t1, t2 = per[k1[-2]]["compile_s"], per[k1[-1]]["compile_s"]
        g1, g2 = per[k1[-2]]["compile_gb"], per[k1[-1]]["compile_gb"]
        et, eg = math.log(t2 / t1) / math.log(s2 / s1), math.log(g2 / g1) / math.log(s2 / s1)
        print("compile at k=1 vs state size (MEASURED): " + ", ".join(
            f"s={k[0]}: {per[k]['compile_s']:.0f} s / {per[k]['compile_gb']:.1f} GB" for k in k1))
        sd = a.s_dep
        print(f"  local exponent between s={s1} and s={s2}: time ~ s^{et:.2f}, memory ~ s^{eg:.2f} -> s={sd:,}, k=1: "
              f"{fmt_s(t2 * (sd / s2) ** et)}, {g2 * (sd / s2) ** eg:.0f} GB   (FIT; the exponent itself grows with s)")
    big = max(comp, key=lambda k: per[k]["cons"])
    print(f"largest compiled here: s={big[0]} k={big[1]}: {per[big]['cons']:,} constraints, {per[big]['compile_s']:.0f} s, "
          f"{per[big]['compile_gb']:.1f} GB   (MEASURED)")

    # ---- deployed size, from the fits above --------------------------------------------
    s = a.s_dep
    per_rec = A * s + B + E / 5 + H * (s // 64) + J * s / 16
    fixed = Cc * s + G * npk(s) + D * nblk(s) + F
    kmax = int((2 ** BN254_TWO_ADICITY - fixed) // per_rec)
    kmem = int(((a.machine_gb - ra) / rb - fixed) // per_rec) if rb > 0 else kmax
    print(f"\nDEPLOYED SIZE, s = {s:,} counters, {a.stream:,}-record stream, cb={cb0}   (every number below from the fits)")
    print(f"  per chunk: fixed {fixed:,.0f} constraints (opening {Cc:g}/slot + packing + two Poseidon chains) + {per_rec:,.0f} per record "
          f"({A:g} x s + {H:g} x s/64 + {J:g} x s/16 + {B + E / 5:g})   [exact model, k a multiple of 16]")
    print(f"  Groth16/BN254: FFT domain cap 2^{BN254_TWO_ADICITY} = {2 ** BN254_TWO_ADICITY:,} constraints -> k <= {kmax:,} records per chunk")
    print(f"  prove peak RSS ({rb * 1e6:.2f} KB/constraint) within this machine's {a.machine_gb} GB -> k <= {max(kmem, 0):,}")
    print(f"  compile budget here {CAP_S // 60} min / {CAP_GB} GB; previous harness wall {COMPILE_WALL[0]:,} constraints "
          f"({COMPILE_WALL[1]} s, {COMPILE_WALL[2]} GB); CM d=7 w=2^14 k=2 did not compile in 60 min (76 GB and growing)")
    print("  compile columns: power-law fit / linear fit (both fitted on <= "
          f"{max(per[k]['cons'] for k in comp):,} constraints)")
    big_full = max(full, key=lambda k: per[k]["cons"])
    rate_big = per[big_full]["cons"] / statistics.median(per[big_full]["prove"])
    print(f"  prove columns: linear fit / constant rate of the largest proven point (s={big_full[0]}, k={big_full[1]}: "
          f"{rate_big:,.0f} constraints/s)")
    print(f"  {'k':>6} {'cons/chunk':>14} {'chunks':>9} {'compile':>17} {'compile RSS':>15} {'pk':>8} {'prove RSS':>9} "
          f"{'prove/chunk':>17} {'prove, stream':>21} {'verify all':>10}  verdict")
    vmed = statistics.median(vall)
    ks_dep = sorted(set(a.k_dep) | {kmax} | ({kmem} if 0 < kmem < kmax else set()))
    for k in ks_dep:
        n = cons(s, k)
        chunks = math.ceil(a.stream / k)
        ct_p, ct_l = math.exp(ct_a) * n ** ct_b, ca + cbb * n
        cg_p, cg_l = math.exp(cm_a) * n ** cm_b, ma + mb * n
        pt = pa + pb * n
        pr = n / rate_big
        pk = (ka + kb * n) / 1e3
        prss = ra + rb * n
        why = []
        if n > 2 ** BN254_TWO_ADICITY:
            why.append("exceeds 2^28 FFT domain")
        if prss > a.machine_gb:
            why.append(f"prove RSS > {a.machine_gb} GB")
        if min(ct_p, ct_l) > CAP_S or min(cg_p, cg_l) > CAP_GB:
            why.append("over compile budget (both fits)")
        elif max(ct_p, ct_l) > CAP_S or max(cg_p, cg_l) > CAP_GB:
            why.append("over compile budget (one fit)")
        ref_k = [int(r["k"]) for r in refused if int(r["s"]) == s and int(r["k"]) <= k]
        if ref_k:
            why.insert(0, f"compile REFUSED (MEASURED at k={min(ref_k)}; a larger k only adds code)")
        why.append(f"{n / max(per[k2]['cons'] for k2 in comp):.0f}x the largest compile here")
        tag = "k_max(FFT)" if k == kmax else ("k_max(RAM)" if k == kmem else "")
        print(f"  {k:>6} {n:>14,.0f} {chunks:>9,} {fmt_s(ct_p):>8}/{fmt_s(ct_l):<8} {cg_p:>6.0f}/{cg_l:<6.0f}GB {pk:>6.1f}GB "
              f"{prss:>7.0f}GB {fmt_s(pt):>8}/{fmt_s(pr):<8} {fmt_s(pt * chunks):>10}/{fmt_s(pr * chunks):<10} "
              f"{fmt_s(vmed * chunks):>10}  {tag} {'; '.join(why)}")
    floor, floor_r = a.stream * pb * per_rec, a.stream * per_rec / rate_big
    print(f"  prove floor as k grows (fixed cost amortised away): {a.stream:,} records x {per_rec:,.0f} constraints = "
          f"{a.stream * per_rec:.3g} constraints -> {fmt_s(floor)} (linear fit) / {fmt_s(floor_r)} (constant rate) of 32-thread "
          f"Groth16 time. Both treat the per-constraint cost as constant beyond the largest proven circuit "
          f"({max(xs):,.0f} constraints); MSM/FFT grow as n log n and the feasible k needs 10^8-constraint circuits, "
          f"so the true figure at deployed k is at least this order.")
    for r in refused:
        if int(r["s"]) == s:
            print(f"  MEASURED at s={s:,}, k={r['k']} (run {r['run']}, load1 {r['load1']}, other compiles {r['foreign'].split('/')[0]}): "
                  f"operator compile REFUSED after {float(r['wall_s']):.0f} s at {float(r['peak_rss_mb']) / 1024:.1f} GB peak RSS "
                  f"({r['note'].split(';')[0]}); model constraints {cons(s, int(r['k'])):,.0f}")
    dep = (s, 1, cb0)
    if dep in per and "prove" in per[dep]:
        v = per[dep]
        print(f"  CHECK against the MEASURED s={s:,}, k=1 point: constraints {v['cons']:,} (model {cons(s, 1):,.0f}); "
              f"compile {v['compile_s']:.0f} s / {v['compile_gb']:.1f} GB; prove {statistics.median(v['prove']):.1f} s "
              f"(linear fit {pa + pb * v['cons']:.1f} s); setup {v['setup_s']:.1f} s; pk {v['pk_mb']:.0f} MB; "
              f"prove RSS {v['prove_gb']:.1f} GB")
    print("  Name this 'a SpaceSaving operator following zkStream's design (our circuit)', never 'zkStream'.")


if __name__ == "__main__":
    main()
