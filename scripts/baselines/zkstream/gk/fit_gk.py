#!/usr/bin/env python3
"""GK replay operator: the measured runs ($RESULTS/zkstream_gk.csv) and least-squares fits evaluated at s' = 2^11, m = 2^14.
Usage: python3 scripts/baselines/zkstream/gk/fit_gk.py
"""
import csv, math, os, statistics, sys
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
RES = Path(os.environ.get("RESULTS", HERE.parent / "results")).resolve()
CSV_PATH = RES / "zkstream_gk.csv"
N_STREAM = 1 << 20
# Compile wall (MEASURED elsewhere in this harness): largest ZoKrates compile that finished,
# and the Count-Min d=7/w=2^14 compile that did not (../results/probe_d7_w16384_20260924.md).
WALL_CONS, WALL_S, WALL_GB = 461_428, 185.0, 8.1


def load():
    if not CSV_PATH.exists():
        sys.exit(f"fit_gk.py: missing {CSV_PATH} -- run run_gk.py first")
    with CSV_PATH.open() as f:
        return list(csv.DictReader(f))


def geo(E, S, NB, k):
    """Structural parameters of gen.sh for one instance (E a power of two)."""
    EL = E.bit_length() - 1
    P = E // 2
    L = NB - EL + 1
    NC, cond = (k // P, 0) if k >= P else (1, 1)
    return dict(S=S, k=k, L=L, WB=22 + 2 * L, LOGS=S.bit_length() - 1, NC=NC, cond=cond,
                M=NB + EL + 2, Q=L.bit_length(), NB=NB)


def feats(g):
    """Structural terms: 2 commitments + digest + k inserts + NC compress passes + main."""
    S, k, L, LOGS, NC = g["S"], g["k"], g["L"], g["LOGS"], g["NC"]
    return [
        1.0,
        math.ceil((S + 1) / 5),            # Poseidon blocks per state commitment (x2)
        math.ceil(k / 5),                  # Poseidon blocks of the batch digest
        k * S,                             # insert: one-hot select + shift, per slot
        k * g["WB"],                       # insert: two packed-word range checks
        k,                                 # insert: key unpack, Delta, one-hot sum
        NC * S * L,                        # compress: unpack g/Delta, band automaton, g* pass
        NC * S * (g["M"] + 2 * g["Q"]),     # compress: the three comparisons of the scan
        NC * S * LOGS * (LOGS + 1) // 2,   # compaction: remaining-shift unpacks, LOGS-b bits at stage b
        NC * S * LOGS,                     # compaction: per-stage moves of (occ, word, shift)
        NC * S,                            # compress: per-slot constant work
        NC,                                # compress: per-pass constant (p bits, t_0 check)
        g["cond"] * S,                     # k < E/2: enable-select after the one COMPRESS
        g["NB"],                           # main: n unpacks
    ]


FEAT_NAMES = ["const", "commit_blocks", "digest_blocks", "k*S", "k*WB", "k", "NC*S*L",
              "NC*S*(M+2Q)", "NC*S*LOGS(LOGS+1)/2", "NC*S*LOGS", "NC*S", "NC", "cond*S", "NB"]


def ols(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx else 0.0
    return my - b * mx, b


def loglog(xs, ys):
    a, b = ols([math.log(x) for x in xs], [math.log(y) for y in ys])
    return math.exp(a), b


def main():
    rows = [r for r in load() if r["system"] == "zokrates_gk_replay_op"]

    # ---- 1. soundness gate ------------------------------------------------------------
    gate = ("witness_op", "verify", "tamper_", "overflow_rejected", "validate_witness")
    bad = [r for r in rows if r["step"].startswith(gate) and r["ok"] != "1"]
    if bad:
        for r in bad:
            print(f"GATE FAILED: run={r['run']} E={r['eps_den']} k={r['k']} s'={r['cap']} "
                  f"chunk={r['chunk']} {r['step']} {r['note']}")
        sys.exit("fit_gk.py: soundness or chain check failed -- no cost figure is valid")
    tam = [r for r in rows if r["step"].startswith("tamper_")]
    kinds = sorted({r["step"] for r in tam})
    val = [r for r in rows if r["step"] == "validate_witness"]
    ovf = [r for r in rows if r["step"] == "overflow_rejected"]
    print(f"soundness (MEASURED): {len(tam)} forgeries rejected ({len(kinds)} kinds x points), "
          f"{len(ovf)} capacity overflows rejected, {len(val)} witness-only validation chunks "
          f"== native GK; every chained witness and verify ok")
    print("  kinds: " + ", ".join(k.replace("tamper_", "") for k in kinds))

    # ---- 2. per measured point --------------------------------------------------------
    pts = defaultdict(lambda: defaultdict(list))
    for r in rows:
        key = (int(r["eps_den"]), int(r["k"]), int(r["cap"]), int(r["nb"]))
        pts[key]["rows"].append(r)
    measured = {}
    for key, d in pts.items():
        runs = sorted({r["run"] for r in d["rows"] if r["step"] == "prove"})
        if not runs:
            continue
        run = runs[-1]
        rs = [r for r in d["rows"] if r["run"] == run]
        get = lambda step: [r for r in rs if r["step"] == step]
        comp = get("compile_op")
        if not comp:
            continue
        c = comp[0]
        setup = get("setup")[0]
        wit = [float(r["wall_s"]) for r in get("witness_op")]
        prv = [float(r["wall_s"]) for r in get("prove")]
        ver = [float(r["wall_s"]) for r in get("verify")]
        measured[key] = dict(
            cons=int(c["constraints"]), compile_s=float(c["wall_s"]), compile_mb=float(c["peak_rss_mb"]),
            setup_s=float(setup["wall_s"]), pk=int(setup["bytes"]), wit=statistics.median(wit),
            prove=statistics.median(prv), verify_ms=1000 * statistics.median(ver),
            proof_b=int(get("prove")[0]["bytes"]), prove_mb=max(float(r["peak_rss_mb"]) for r in get("prove")),
            load=statistics.median(float(r["load1"]) for r in get("prove")), chunks=len(prv),
            tam=sum(1 for r in rs if r["step"].startswith("tamper_")))
    print("\nGK replay operator, per chunk of k records                                   (MEASURED)")
    print(f"{'1/eps':>5} {'k':>3} {'s_':>4} {'constraints':>11} {'compile':>8} {'GB':>5} {'setup':>6} "
          f"{'witness':>7} {'prove':>6} {'w+p/rec':>8} {'verify':>7} {'proof':>5} {'RSS':>6} {'load1':>5} {'chain':>5} {'tamper':>6}")
    for key in sorted(measured):
        E, k, S, nb = key
        v = measured[key]
        print(f"{E:>5} {k:>3} {S:>4} {v['cons']:>11,} {v['compile_s']:>7.1f}s {v['compile_mb'] / 1024:>5.2f} "
              f"{v['setup_s']:>5.2f}s {v['wit']:>6.2f}s {v['prove']:>5.2f}s {1000 * (v['wit'] + v['prove']) / k:>6.1f}ms "
              f"{v['verify_ms']:>5.1f}ms {v['proof_b']:>5} {v['prove_mb']:>4.0f}MB {v['load']:>5.2f} "
              f"{v['chunks']:>5} {v['tam']:>6}")
    dropped = [r for r in rows if r["step"] == "capacity"]
    for r in sorted({(r["eps_den"], r["k"], r["cap"], r["note"]) for r in dropped}):
        print(f"  dropped: 1/eps={r[0]} k={r[1]} s'={r[2]}: {r[3]}")
    print("  verify is the CLI (process start included); proof bytes are the JSON encoding; "
          "witness+prove is the prover's per-chunk cost")

    # ---- 3. constraints: least squares on the circuit's structural terms ----------------
    comp = {}
    for r in rows:
        if r["step"] == "compile_op" and r["constraints"]:
            E, k, S, nb = int(r["eps_den"]), int(r["k"]), int(r["cap"]), int(r["nb"])
            comp[(E, k, S, nb)] = dict(cons=int(r["constraints"]), s=float(r["wall_s"]),
                                       mb=float(r["peak_rss_mb"]), bytes=int(r["bytes"] or 0))
    refused = [r for r in rows if r["step"] == "compile_op" and r["ok"] == "0"]
    keys = sorted(comp)
    X = np.array([feats(geo(E, S, nb, k)) for (E, k, S, nb) in keys], dtype=float)
    y = np.array([comp[kk]["cons"] for kk in keys], dtype=float)
    coef, *_ = np.linalg.lstsq(X, y, rcond=None)
    pred = X @ coef
    rel = np.abs(pred - y) / y
    print(f"\nconstraint model: least squares over {len(keys)} compiles (grid + sweeps), "
          f"{len(FEAT_NAMES)} structural terms, rank {np.linalg.matrix_rank(X)}")
    print("  " + ", ".join(f"{n}={c:.2f}" for n, c in zip(FEAT_NAMES, coef)))
    print(f"  max |residual| = {np.max(np.abs(pred - y)):.0f} constraints ({np.max(rel):.2%}); "
          f"median {np.median(rel):.3%}")
    # out-of-sample check: refit without the largest compile and predict it
    ib = int(np.argmax(y))
    mask = np.arange(len(y)) != ib
    cho, *_ = np.linalg.lstsq(X[mask], y[mask], rcond=None)
    pb_ = float(X[ib] @ cho)
    print(f"  held-out check: fitted without 1/eps={keys[ib][0]} k={keys[ib][1]} s'={keys[ib][2]} nb={keys[ib][3]}, "
          f"the model predicts {pb_:,.0f} vs {int(y[ib]):,} measured ({(pb_ - y[ib]) / y[ib]:+.3%})")
    worst = np.argsort(-rel)[:3]
    for i in worst:
        E, k, S, nb = keys[i]
        print(f"    worst: 1/eps={E} k={k} s'={S} nb={nb}: measured {int(y[i]):,} model {pred[i]:,.0f}")

    def model(E_like, S, k, NB, L=None, P=None):
        g = geo(E_like, S, NB, k)
        if L is not None:
            g.update(L=L, WB=22 + 2 * L, Q=L.bit_length())
        if P is not None:
            g.update(NC=math.ceil(k / P), cond=0)
        return float(np.array(feats(g)) @ coef), g

    # ---- 4. time / memory fits ------------------------------------------------------------
    mk = sorted(measured)
    cs = [measured[k]["cons"] for k in mk]
    pa, pb = ols(cs, [measured[k]["prove"] for k in mk])
    wa, wb = ols(cs, [measured[k]["wit"] for k in mk])
    sa, sb = ols(cs, [measured[k]["setup_s"] for k in mk])
    ka, kb = ols(cs, [measured[k]["pk"] for k in mk])
    ccs = [comp[k]["cons"] for k in keys]
    ca, cb = loglog(ccs, [comp[k]["s"] for k in keys])
    ma, mb = loglog(ccs, [comp[k]["mb"] for k in keys])
    rate = [measured[k]["cons"] / measured[k]["prove"] for k in mk]
    # the Groth16 rate falls with size (MSM/FFT, memory), so larger circuits use a power law fitted to the points >= 100K
    lg = [k for k in mk if measured[k]["cons"] >= 100_000]
    if len(lg) >= 2:
        qa, qb = loglog([measured[k]["cons"] for k in lg], [measured[k]["prove"] for k in lg])
        ra, rb = loglog([measured[k]["cons"] for k in lg], [measured[k]["wit"] for k in lg])
        prove_t = lambda c: qa * c ** qb
        wit_t = lambda c: ra * c ** rb
    else:
        prove_t = lambda c: pa + pb * c
        wit_t = lambda c: wa + wb * c
    print("\nfits against constraints c                                                  (FIT)")
    print(f"  prove   = {pa:.3f} s + {pb * 1e6:.3f} us * c   (Groth16 ark; rate {min(rate):,.0f}..{max(rate):,.0f} c/s MEASURED)")
    print(f"  witness = {wa:.3f} s + {wb * 1e6:.3f} us * c")
    if len(lg) >= 2:
        print(f"  large points (c >= 100K, n={len(lg)}): prove = {qa:.3e} * c^{qb:.3f} s, witness = "
              f"{ra:.3e} * c^{rb:.3f} s  <- used below for sizes past the largest measured circuit")
        for k in sorted(lg, key=lambda kk: measured[kk]["cons"]):
            v = measured[k]
            print(f"    c={v['cons']:>9,}: prove {v['prove']:6.2f} s (linear fit {pa + pb * v['cons']:6.2f}, "
                  f"power {prove_t(v['cons']):6.2f}), witness {v['wit']:5.2f} s")
    print(f"  setup   = {sa:.3f} s + {sb * 1e6:.3f} us * c;   pk bytes = {ka:,.0f} + {kb:.1f} * c")
    print(f"  compile = {ca:.3e} * c^{cb:.3f} s;   compile RSS = {ma:.3e} * c^{mb:.3f} MB   "
          f"(over {min(ccs):,}..{max(ccs):,} c, all shapes)")
    # compile grows faster in s' than in c: fit the one-pass series (1/eps=64, k=32, nb=21) in s'
    ser = sorted((kk[2], comp[kk]) for kk in keys if kk[0] == 64 and kk[1] == 32 and kk[3] == 21)
    if len(ser) >= 3:
        xa, xb = loglog([x for x, _ in ser], [v["s"] for _, v in ser])
        ya, yb = loglog([x for x, _ in ser], [v["mb"] for _, v in ser])
        print(f"  one-pass series (1/eps=64, k=32, nb=21, s'={','.join(str(x) for x, _ in ser)}): "
              f"compile ~ s'^{xb:.2f}, RSS ~ s'^{yb:.2f}")
        for x, v in ser:
            print(f"    s'={x:<5} {v['cons']:>10,} c  compile {v['s']:>7.1f} s  {v['mb'] / 1024:>6.1f} GB  (MEASURED)")
    big = max(keys, key=lambda kk: comp[kk]["cons"])
    print(f"  largest compile measured here: {comp[big]['cons']:,} c in {comp[big]['s']:.0f} s, "
          f"{comp[big]['mb'] / 1024:.1f} GB (1/eps={big[0]} k={big[1]} s'={big[2]} nb={big[3]})")
    for r in refused:
        print(f"  refused compile (MEASURED outcome): 1/eps={r['eps_den']} k={r['k']} s'={r['cap']} "
              f"nb={r['nb']}: {r['note']}")

    # per-record marginal constraints at a given geometry: fitted formula at k = 2^12 minus k = 2^11, over 2^11
    def per_record(E_like, S, NB, L=None, P=None):
        c1, _ = model(E_like, S, 1 << 12, NB, L, P)
        c0, _ = model(E_like, S, 1 << 11, NB, L, P)
        return (c1 - c0) / (1 << 11)

    # ---- 5. deployed sizes, from the fits above -------------------------------------------
    S_dep, m_dep, E_dep = 1 << 11, 1 << 14, 51
    P_dep = E_dep // 2                                   # COMPRESS every floor(1/(2 eps)) = 25
    NB_dep = 21                                          # n < 2^21 covers the 2^20 stream
    L_dep = (2 * (1 << 21) // E_dep).bit_length()        # p = floor(2n/51) < 2^17
    print(f"\nDEPLOYED (FIT): eps = 1/{E_dep} (COMPRESS every {P_dep}), s' = {S_dep}, m = {m_dep} records "
          f"per chunk, n < 2^{NB_dep} (g, Delta, p: {L_dep} bits)")
    print("  1/51 is not a power of two: the circuit would add a floor-division hint for p (two range")
    print("  checks per pass, negligible); the model keeps every other term at these widths.")
    cons_dep, g_dep = model(64, S_dep, m_dep, NB_dep, L=L_dep, P=P_dep)
    pr = per_record(64, S_dep, NB_dep, L=L_dep, P=P_dep)
    one_pass, _ = model(64, S_dep, P_dep, NB_dep, L=L_dep, P=P_dep)
    fixed, _ = model(64, S_dep, 0, NB_dep, L=L_dep, P=P_dep)
    t_prove = prove_t(cons_dep) + wit_t(cons_dep)
    t_comp = ca * cons_dep ** cb
    gb_comp = ma * cons_dep ** mb / 1024
    chunks = N_STREAM // m_dep
    # the compile wall = the largest ZoKrates compile that finished, here or in the CM harness
    big = max(keys, key=lambda kk: comp[kk]["cons"])
    wall = max(WALL_CONS, comp[big]["cons"])
    wall_src = (f"this harness, 1/eps={big[0]} k={big[1]} s'={big[2]}: {comp[big]['s']:.0f} s, "
                f"{comp[big]['mb'] / 1024:.1f} GB" if comp[big]["cons"] > WALL_CONS
                else f"CM harness: {WALL_S:.0f} s, {WALL_GB} GB")
    print(f"  compile wall = largest compile that finished: {wall:,} constraints ({wall_src}); "
          f"refused compiles: {len(refused)}")
    print(f"  constraints per chunk (m=2^14): {cons_dep / 1e6:,.0f} M   "
          f"= fixed {fixed / 1e3:,.0f} K + {m_dep} x {pr / 1e3:,.1f} K per record "
          f"({g_dep['NC']} COMPRESS passes over {S_dep} slots)  -> {cons_dep / wall:,.0f}x the compile wall")
    ins_floor = float((np.array(feats(dict(g_dep, NC=0))) - np.array(feats(dict(g_dep, NC=0, k=0)))) @ coef)
    print(f"  of which INSERT alone (O(s') conditional moves per record): {ins_floor / 1e6:,.0f} M "
          f"({ins_floor / wall:,.0f}x the wall even if COMPRESS were free)")
    best = max(rate)
    lgst = max(mk, key=lambda kk: measured[kk]["cons"])
    r_lg = measured[lgst]["cons"] / measured[lgst]["prove"]
    print(f"  if it compiled: pk ~{(ka + kb * cons_dep) / 1e9:,.0f} GB; prove >= {cons_dep / best / 3600:,.1f} h per "
          f"chunk at the best measured rate ({best:,.0f} c/s), {cons_dep / r_lg / 3600:,.1f} h at the rate of the "
          f"largest point ({r_lg:,.0f} c/s); {chunks} chunks for 2^20 records -> >= "
          f"{chunks * cons_dep / best / 3600:,.0f} h (compile/RSS power laws give ~{t_comp / 3600:,.0f} h / "
          f"~{gb_comp:,.0f} GB -- 3 orders of magnitude beyond the measured range, indicative only)")
    # one COMPRESS pass alone, and the cheapest chunk shape (no pass) at the deployed capacity
    g1 = geo(64, S_dep, NB_dep, 1)
    g1.update(L=L_dep, WB=22 + 2 * L_dep, Q=L_dep.bit_length(), cond=0)
    g0 = dict(g1, NC=0)
    g1 = dict(g1, NC=1)
    c_pass = float((np.array(feats(g1)) - np.array(feats(g0))) @ coef)
    c_nopass = float(np.array(feats(g0)) @ coef)
    print(f"  one COMPRESS pass over {S_dep} slots: {c_pass / 1e3:,.0f} K constraints; "
          f"a 1-record chunk without a pass: {c_nopass / 1e3:,.0f} K")
    n_small = N_STREAM // P_dep
    t_small = prove_t(one_pass) + wit_t(one_pass)
    probe = [kk for kk in measured if kk[0] == 64 and kk[2] == S_dep]
    if probe:  # the measured one-pass chunk at s' = 2^11 (k = 32), scaled to the k = 25 shape
        v = measured[probe[0]]
        t_small = (v["wit"] + v["prove"]) * one_pass / v["cons"]
    print(f"  smallest chunk with a pass (k = {P_dep}): {one_pass / 1e3:,.0f} K constraints "
          f"({one_pass / wall:.2f}x the wall), witness+prove ~{t_small:.1f} s, pk ~{(ka + kb * one_pass) / 1e6:,.0f} MB; "
          f"2^20 records need {n_small:,} such proofs -> ~{n_small * t_small / 3600:,.0f} h of witness+prove, "
          f"{n_small * 997 / 1e6:,.0f} MB of JSON proofs")
    for kk in probe:
        v = measured[kk]
        mod, _ = model(64, S_dep, kk[1], kk[3])
        print(f"  MEASURED at s'={S_dep} (1/eps=64, k={kk[1]}, one pass, nb={kk[3]}): {v['cons']:,} constraints "
              f"(model {mod:,.0f}), compile {v['compile_s']:.0f} s / {v['compile_mb'] / 1024:.1f} GB, setup "
              f"{v['setup_s']:.1f} s, pk {v['pk'] / 1e6:,.0f} MB, witness {v['wit']:.1f} s, prove {v['prove']:.1f} s, "
              f"verify {v['verify_ms']:.0f} ms; {v['chunks']} chained chunks, {v['tam']} forgeries rejected")
    ref_s = [kk for kk in comp if kk[0] == 64 and kk[2] == S_dep]
    if not ref_s:
        print(f"  (no compile at s'={S_dep} in the CSV yet)")
    whole = N_STREAM * pr
    t_whole_lo = n_small * t_small
    print(f"  whole 2^20 stream: ~{whole / 1e9:,.1f} G constraints of proving work regardless of chunking; "
          f"at the smallest compilable chunk shape that is ~{t_whole_lo / 3600:,.0f} h of witness+prove")
    print(f"  VERDICT: at the deployed chunk size (m = 2^14) the GK replay operator is INFEASIBLE in "
          f"ZoKrates/Groth16: {cons_dep / 1e6:,.0f} M constraints per chunk, {cons_dep / wall:,.0f}x the "
          f"largest compile that finished. At s'=2^11 every record costs ~{pr / 1e3:,.0f} K constraints "
          f"(O(s') INSERT + O(s' log^2 s') COMPRESS every {P_dep} records), so shrinking the chunk only "
          f"trades the compile wall for ~{whole / 1e9:,.0f} G constraints (~{t_whole_lo / 3600:,.0f} h of "
          f"witness+prove) for 2^20 records.")
    # per-record constraints of the fitted formula at each measured geometry
    print("\nper-record constraints (marginal, from the fitted terms, at each point's own NB):")
    for (E, S, nb) in sorted({(k[0], k[2], k[3]) for k in measured}):
        print(f"  1/eps={E:<3} s'={S:<4} nb={nb:<2} {per_record(E, S, nb):>9,.0f}")
    print(f"  1/eps=51  s'=2048 nb={NB_dep} {pr:>9,.0f}   <- deployed")


if __name__ == "__main__":
    main()
