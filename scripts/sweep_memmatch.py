#!/usr/bin/env python3
"""Figure 5 data: measured zkSketch forest runs and zk-Analytics receipts at batch sizes 2^6..2^14, Table 2's setting.
GK zk-Analytics points without a receipt (zka_basis != measured): executor padded cycles x the seconds per 2^20
padded cycles of the capacity-768 GK receipts. Writes <out>/sweep_memmatch.{csv,md}; plot with plot_sweep.py.
Usage: python3 scripts/sweep_memmatch.py [--sweep DIR] [--memmatch DIR] [--batches DIR,...] [--gk768 DIR] [--out DIR]
"""
import argparse
import csv
import glob
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
ZKA_RES = os.path.join(ROOT, "scripts", "baselines", "zka", "results")
RUNS = os.path.join(ROOT, "results", "six")
FAMS = ["cm", "hll", "ss", "gk", "bloom", "kmv"]
LABEL = {"cm": "Count-Min", "hll": "HLL", "ss": "MG", "gk": "GK", "bloom": "Bloom", "kmv": "KMV"}
SIZES = [2 ** e for e in range(6, 15)]
SEG = 2 ** 20
GK_CAP, GK_STEP = 768, 512   # the memmatch run's GK capacity and zk-Analytics step (= zkSketch's GK leaf)
GK_DRIVER = os.path.join(os.environ.get("BASELINE_DIR", os.path.expanduser("~/ext-baselines")),
                         "build", "zka-gk-matched", "release", "gk_matched")


def rows(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return [r for r in csv.DictReader(f) if r and not (next(iter(r.values())) or "").startswith("#")]


def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def newest(rx):
    ds = []
    for base in (ZKA_RES, RUNS):
        if os.path.isdir(base):
            ds += [os.path.join(base, n) for n in os.listdir(base)
                   if re.fullmatch(rx, n) and os.path.isdir(os.path.join(base, n))]
    return max(ds, key=os.path.getmtime) if ds else None


def all_newest_first(rx):
    ds = []
    for base in (ZKA_RES, RUNS):
        if os.path.isdir(base):
            ds += [os.path.join(base, n) for n in os.listdir(base)
                   if re.fullmatch(rx, n) and os.path.isdir(os.path.join(base, n))]
    return sorted(ds, key=os.path.getmtime, reverse=True)


def started(d):
    try:
        for line in open(os.path.join(d, "manifest.txt")):
            for part in line.split():
                if part.startswith("started="):
                    return part.split("=", 1)[1]
    except OSError:
        pass
    return "?"


def rel(p):
    return os.path.relpath(p, ROOT)


def edir(d, m):
    return os.path.join(d, f"m{m.bit_length() - 1:02d}")


def zks_run(path):
    """The single ok row of a zkSketch forest CSV, or None."""
    ok = [r for r in rows(path) if r.get("status") == "ok"]
    return ok[-1] if ok else None


def desc_rss(path, fam):   # the procs worker's peak RSS (MB) from run_zks.sh's runs file next to the CSV
    for r in reversed(rows(os.path.join(os.path.dirname(path), "six_zksketch_runs.csv"))):
        if r.get("tag") == fam:
            return r.get("desc_peak_rss_mb", "")
    return ""


def load_memmatch(d):
    zks, zka = {}, {}
    for r in rows(os.path.join(d, "six_sketch_comparison.csv")):
        if r["run"] != "main" or r["operation"] != "update_per_epoch":
            continue
        if r["system"] == "zkSketch":
            zks[r["family"]] = r
        elif r.get("variant") == "noroot":   # the headline zk-Analytics variant (no per-bucket roots)
            zka[r["family"]] = r
    runs = {}
    for fam in FAMS:
        p = os.path.join(d, f"six_zksketch_{fam}.csv")
        r = zks_run(p)
        if r is None or fam not in zks or fam not in zka:
            sys.exit(f"{d}: no complete {fam} rows")
        if abs(float(r["total_time_ms"]) / 1000 - fnum(zks[fam]["prove_s"])) > 1e-3:
            sys.exit(f"{d}: {fam} total_time_ms differs from the table's update_per_epoch {zks[fam]['prove_s']} s")
        runs[fam] = (r, p)
    gk_proof = None
    for r in rows(os.path.join(d, "six_zka_gk_prove.csv")):
        if r.get("arm") == "proved" and r.get("mode") == "aggr":
            gk_proof = r
    if gk_proof is None:
        sys.exit(f"{d}: no proved GK aggregation receipt")
    return zks, zka, runs, gk_proof


def zka_rss(log):   # r0vm peak RSS (MB) from the RSSTREE line the harness writes into the proof log
    try:
        for line in reversed(open(log).read().splitlines()):
            if line.startswith("RSSTREE"):
                m = re.search(r"r0vm_peak_rss_mb=([0-9.]+)", line)
                return m.group(1) if m else ""
    except OSError:
        pass
    return ""


def gk_exec_rows(path, sizes):
    if not os.access(GK_DRIVER, os.X_OK):
        sys.exit(f"missing {GK_DRIVER} (scripts/baselines/zka/six/run_all.sh build) -- needed for the GK cycle counts at "
                 f"m = {sizes}")
    keys = os.path.join(ROOT, "data", "aol.keys")
    new = not os.path.exists(path)
    with open(path, "a") as f:
        if new:
            f.write(subprocess.run([GK_DRIVER, "--header"], check=True, capture_output=True, text=True).stdout)
        for m in sizes:
            cmd = [GK_DRIVER, "--mode", "aggr", "--epoch-index", "0", "--root", "noroot", "--epoch-size", str(m),
                   "--batch", "8", "--keys", keys, "--capacity", str(GK_CAP), "--m-sub", str(min(m, GK_STEP)),
                   "--s", "51", "--impl", "literal"]
            print(f"  executor: {' '.join(cmd[1:])}")
            f.write(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def load_gk768(d, extra=()):
    proofs = {}
    for p in [q for e in extra for q in sorted(glob.glob(os.path.join(e, "m*", "six_zka_gk_prove.csv")))] + \
             sorted(glob.glob(os.path.join(d, "m*", "six_zka_gk_prove.csv"))):
        for r in rows(p):
            if r.get("arm") == "proved" and r.get("mode") == "aggr" and r.get("capacity") == str(GK_CAP):
                proofs.setdefault(int(r["epoch_records"]), (r, zka_rss(os.path.splitext(p)[0] + ".log")))
    ex_path = os.path.join(d, "gk768_exec.csv")

    def ex_rows():
        return {int(r["epoch_records"]): r for r in rows(ex_path)
                if r.get("capacity") == str(GK_CAP) and int(r["m_sub"]) == min(int(r["epoch_records"]), GK_STEP)}
    ex = ex_rows()
    missing = [m for m in SIZES if m not in ex]
    if missing:
        print(f"== gk768: no executor rows for m = {missing}; running the matched GK executor (capacity {GK_CAP}, "
              f"steps of min(m, {GK_STEP}) records; no proof)")
        gk_exec_rows(ex_path, missing)
        ex = ex_rows()
    return proofs, ex


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sweep", default=newest(r"sweep-\d{8}-\d{6}"))
    ap.add_argument("--memmatch", default=newest(r"memmatch-\d{8}-\d{6}"))
    ap.add_argument("--batches", default=",".join(all_newest_first(r"batches-\d{8}-[0-9a-z]+")))
    ap.add_argument("--gk768", default=None)
    ap.add_argument("--out", default=os.path.join(ZKA_RES, "sweep-memmatch"))
    a = ap.parse_args()
    bdirs = [os.path.abspath(b) for b in a.batches.split(",") if b]
    for b in bdirs:
        if not os.path.isdir(b):
            sys.exit(f"--batches: no run directory {b}")
    if a.gk768 is None:
        a.gk768 = newest(r"sweep-gk768-\d{8}-\d{6}") or (bdirs[0] if bdirs else None)
    for k in ("sweep", "memmatch", "gk768"):
        if not getattr(a, k) or not os.path.isdir(getattr(a, k)):
            sys.exit(f"--{k}: no run directory ({getattr(a, k)})")
    a.batches = ",".join(rel(b) for b in bdirs)
    sw = {(r["family"], int(r["m"])): r for r in rows(os.path.join(a.sweep, "sweep.csv"))}
    mm_zks, mm_zka, mm_runs, mm_gk = load_memmatch(a.memmatch)
    gk_proofs, gk_ex = load_gk768(a.gk768, bdirs)
    for k in ("sweep", "memmatch", "gk768"):
        print(f"== {k:9s}{rel(getattr(a, k))} (started {started(getattr(a, k))})")
    for b in bdirs:
        print(f"== batches  {rel(b)} (started {started(b)})")

    # ---- zk-Analytics GK receipts at capacity 768: seconds per 2^20 padded cycles from the measured receipts
    pts = [(fnum(mm_gk["prove_s"]), fnum(mm_gk["padded_cycles"]), int(mm_gk["epoch_records"]), rel(a.memmatch))]
    for m, (r, _) in sorted(gk_proofs.items()):
        pts.append((fnum(r["prove_s"]), fnum(r["padded_cycles"]), m, rel(a.gk768)))
    k_gk = sum(p for p, _, _, _ in pts) / sum(c / SEG for _, c, _, _ in pts)
    print(f"\n== zk-Analytics GK receipts: {k_gk:.2f} s per 2^20 padded cycles, from "
          + "; ".join(f"m={m}: {p:.1f} s / {c/SEG:.2f} x 2^20 ({src})" for p, c, m, src in pts))
    errs = []
    for m in SIZES:
        for r in rows(os.path.join(edir(a.sweep, m), "six_zka_gk_prove.csv")):
            if r.get("arm") == "proved" and r.get("mode") == "aggr":
                errs.append((m, k_gk * fnum(r["padded_cycles"]) / SEG / fnum(r["prove_s"]) - 1))
    if errs:
        worst = max(errs, key=lambda e: abs(e[1]))
        print(f"   check against the sweep's {len(errs)} GK receipts at capacity 2048: "
              f"within {100*max(abs(e) for _, e in errs):.1f}% (worst at m={worst[0]}: {100*worst[1]:+.1f}%)")
    gk_model_note = (f"padded cycles x {k_gk:.2f} s per 2^20 (the capacity-{GK_CAP} receipts at m="
                     f"{', '.join(str(m) for _, _, m, _ in sorted(pts, key=lambda p: p[2]))})")

    # ---- the figure's points
    out_rows, md, summary, problems, checks = [], [], [], [], []
    md.append("# Batch-size figure in the memory-matched setting of Table 2 (sweep_memmatch.py)\n")
    md.append(f"_zkSketch: every point is the measured total_time_ms (leaves + compositions + setup; queries excluded) "
              f"of a forest run of the batch: from the batches runs `{a.batches}` where they hold the point, else the sweep's "
              f"single leaves `{rel(a.sweep)}` (GK: `{rel(a.gk768)}`); Table 2's epochs from `{rel(a.memmatch)}`. zk-Analytics: the measured "
              f"receipts of the sweep and of Table 2; GK receipts not measured at capacity {GK_CAP}: {gk_model_note}"
              + (f", which reproduces the sweep's capacity-2048 receipts within {100*max(abs(e) for _, e in errs):.1f}%" if errs else "")
              + "._\n")
    for fam in FAMS:
        mr, mp = mm_runs[fam]
        L, E = int(mr["m"]), int(mr["n"])
        shape, variant = mr["shape"], mr["variant"]
        md.append(f"\n## {LABEL[fam]} (zkSketch leaf L = {L} records, shape {shape}; Table 2 epoch {E})\n")
        md.append("| m | leaves | zkA prove (s) | zkS prove (s) | zkA ms/rec | zkS ms/rec | zkA / zkS | zkS worker GiB | zkA basis |")
        md.append("|---:|---:|---:|---:|---:|---:|---:|---:|---|")
        for m in SIZES:
            r = sw.get((fam, m), {})
            # zkSketch: a measured forest run of the batch (Table 2's run at its epoch; else the first
            # batches run holding the point; else, up to the leaf size, the sweep's single leaf)
            k = max(1, m // L)
            want = (m, min(m, L), k, shape)
            cands = [os.path.join(edir(b, m), f"six_zksketch_{fam}.csv") for b in bdirs]
            if m <= L:
                cands.append(os.path.join(edir(a.gk768 if fam == "gk" else a.sweep, m), f"six_zksketch_{fam}.csv"))
            found = [(z, q) for q in cands for z in [zks_run(q)]
                     if z is not None and (int(z["n"]), int(z["m"]), int(z["t"]), z["shape"]) == want and z["variant"] == variant]
            if m == E:
                zr, zp = mr, mp
                if found:
                    re_s = float(found[0][0]["total_time_ms"]) / 1000
                    checks.append(f"{LABEL[fam]}: Table 2 {float(mr['total_time_ms'])/1000:.1f} s, re-measured "
                                  f"{re_s:.1f} s ({100*(re_s/(float(mr['total_time_ms'])/1000)-1):+.1f}%, {rel(found[0][1])})")
            elif found:
                zr, zp = found[0]
            else:
                problems.append(f"{fam} m={m}: no ok zkSketch run of {k} leaf/leaves x {min(m, L)} ({shape}, {variant}) in "
                                + ", ".join(rel(q) for q in cands))
                continue
            got = (int(zr["n"]), int(zr["m"]), int(zr["t"]), zr["shape"])
            if got != want or zr["variant"] != variant:
                problems.append(f"{fam} m={m}: {rel(zp)} has (n, leaf, leaves, shape, variant) = {got + (zr['variant'],)}, "
                                f"expected {want + (variant,)}")
                continue
            zs_s = float(zr["total_time_ms"]) / 1000
            zs_rss = desc_rss(zp, fam)
            # zk-Analytics
            if fam == "gk":
                if m in gk_proofs:
                    g, rss = gk_proofs[m]
                    za = (fnum(g["prove_s"]), "measured", f"one receipt, capacity {GK_CAP} ({rel(a.gk768)})",
                          g.get("verify_ms", ""), g.get("receipt_bytes", ""), rss)
                elif m == E:
                    za = (fnum(mm_zka[fam]["prove_s"]), "measured", f"Table 2's receipt, {E // GK_STEP} steps of {GK_STEP} ({rel(a.memmatch)})",
                          mm_zka[fam]["verify_ms"], mm_zka[fam]["proof_bytes"], mm_zka[fam]["peak_rss_mb"])
                else:
                    e = gk_ex[m]
                    za = (k_gk * fnum(e["padded_cycles"]) / SEG, "cycles",
                          f"{e['steps']} step(s) of {e['m_sub']} records: {e['padded_cycles']} padded cycles ({e['segments']} segments) x {k_gk:.2f} s per 2^20",
                          "", "", "")
            elif m == E:
                za = (fnum(mm_zka[fam]["prove_s"]), "measured", f"Table 2's receipt ({rel(a.memmatch)})",
                      mm_zka[fam]["verify_ms"], mm_zka[fam]["proof_bytes"], mm_zka[fam]["peak_rss_mb"])
            else:
                if not fnum(r.get("zka_prove_s")):
                    problems.append(f"{fam} m={m}: no zk-Analytics receipt in the sweep")
                    continue
                za = (fnum(r["zka_prove_s"]), "measured", f"one receipt ({rel(a.sweep)})",
                      r["zka_verify_ms"], r["zka_proof_bytes"], r["zka_peak_rss_mb"])
            sp = za[0] / zs_s
            how = ("Table 2's measured epoch" if m == E else "one measured leaf" if k == 1 else
                   f"measured forest of {k} leaves + {k - 1} compositions")
            out_rows.append(dict(
                family=fam, m=m, zka_prove_s=f"{za[0]:.3f}", zks_prove_s=f"{zs_s:.3f}",
                zka_ms_per_record=f"{za[0]*1000/m:.3f}", zks_ms_per_record=f"{zs_s*1000/m:.3f}", speedup=f"{sp:.3f}",
                zka_verify_ms=za[3], zks_verify_ms=zr["verify_ms"], zka_proof_bytes=za[4], zks_proof_bytes=zr["proof_bytes"],
                zka_peak_rss_mb=za[5], zks_peak_rss_mb=zs_rss, zks_variant=zr["variant"], zks_shape=zr["shape"],
                zks_leaves=k, zks_leaf_records=min(m, L), zks_basis="measured", zka_basis=za[1],
                anchor=1 if m == E else 0, zks_source=rel(zp),
                provenance=f"zka {za[1]}; zks measured",
                note=f"zks: {how}, total_time_ms {zr['total_time_ms']} (leaves {zr['leafgen_seq_ms']}, compositions "
                     f"{zr['local_fold_ms']}) | zka: {za[2]}"))
            gib = f"{float(zs_rss)/1024:.1f}" if fnum(zs_rss) else "-"
            md.append(f"| {m} | {k} | {za[0]:.1f} | {zs_s:.2f} | {za[0]*1000/m:.1f} | {zs_s*1000/m:.2f} | {sp:.1f}x | {gib} | {za[1]} |")
            if m == E:
                summary.append((fam, za[0], zs_s, sp))
    if problems:
        sys.exit("missing or mismatched zkSketch runs (six/batches.sh measures the batches above the leaf size):\n  "
                 + "\n  ".join(problems))
    os.makedirs(a.out, exist_ok=True)
    cols = list(out_rows[0].keys())
    with open(os.path.join(a.out, "sweep_memmatch.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(out_rows)
    md.append("\n## At Table 2's epoch (m = 2^14; GK 2^11): zkA prove (s) / zkS prove (s) / ratio\n")
    md.append(" | ".join(f"{LABEL[f]} {za:.0f} / {zs:.1f} / {sp:.0f}x" for f, za, zs, sp in summary))
    if checks:
        md.append("\n## Table 2's epochs re-measured by a batches run (not plotted)\n")
        md += [f"- {c}" for c in checks]
    with open(os.path.join(a.out, "sweep_memmatch.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    with open(os.path.join(a.out, "manifest.txt"), "w") as f:
        for k in ("sweep", "memmatch", "gk768"):
            f.write(f"{k}={rel(getattr(a, k))} started={started(getattr(a, k))}\n")
        for b in bdirs:
            f.write(f"batches={rel(b)} started={started(b)}\n")
        f.write(f"zks=total_time_ms of a measured forest run per point\ngk_from_cycles={gk_model_note}\n")
    print("\n== points (ms per record; zkA | zkS | ratio; * = zk-Analytics prove time from padded cycles)")
    for fam in FAMS:
        line = f"  {LABEL[fam]:9s}"
        for r in out_rows:
            if r["family"] == fam:
                line += (f" {r['m']:>5}: {float(r['zka_ms_per_record']):7.1f}{'*' if r['zka_basis'] != 'measured' else ' '}"
                         f"|{float(r['zks_ms_per_record']):6.2f} {float(r['speedup']):5.1f}x")
        print(line)
    rss = [float(r["zks_peak_rss_mb"]) / 1024 for r in out_rows if fnum(r["zks_peak_rss_mb"]) and int(r["zks_leaves"]) > 1]
    if rss:
        print(f"\n== zkSketch worker peak RSS of the multi-leaf runs: {min(rss):.1f}-{max(rss):.1f} GiB")
    print("== at Table 2's epoch: " + " | ".join(f"{LABEL[f]} {za:.0f} / {zs:.1f} / {sp:.0f}x" for f, za, zs, sp in summary))
    for c in checks:
        print(f"   re-measured epoch: {c}")
    print(f"wrote {rel(os.path.join(a.out, 'sweep_memmatch.csv'))}, .md, manifest.txt")


if __name__ == "__main__":
    main()
