#!/usr/bin/env python3
"""Tables 4 (stream length, machines) and 5 (datasets) from the Table 2 epoch runs and the measured forest runs in results/.
Usage: python3 scripts/forest_tables.py [<memmatch run dir>]   (writes results/forest_tables.md)
"""
import csv
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
ZKA_RES = os.path.join(ROOT, "scripts", "baselines", "zka", "results")
FAMS = ["cm", "hll", "ss", "gk", "bloom", "kmv"]
LAB = {"cm": "CM", "hll": "HLL", "ss": "MG", "gk": "GK", "bloom": "Bloom", "kmv": "KMV"}
DATASETS = ("uniform", "gaussian", "netflix", "aol")
NS = [2 ** e for e in range(16, 21)]


def rows(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def rel(p):
    return os.path.relpath(p, ROOT)


def memmatch_dir():
    if len(sys.argv) > 1:
        return os.path.abspath(sys.argv[1])
    dirs = [d for d in glob.glob(os.path.join(ZKA_RES, "memmatch-*")) + glob.glob(os.path.join(ROOT, "results", "six", "memmatch-*"))
            if os.path.isdir(d) and "quick" not in os.path.basename(d)]
    if not dirs:
        sys.exit("no memmatch run (Table 2); pass one")
    return max(dirs, key=os.path.getmtime)


def epochs(d):
    """Per family: (leaf records L, time per leaf, remaining time per composition, epoch records, epoch total,
    setup of the epoch run) from the memmatch epoch run, and zk-Analytics' epoch receipt."""
    zka = {}
    for r in rows(os.path.join(d, "six_sketch_comparison.csv")):
        if r["run"] == "main" and r["operation"] == "update_per_epoch" and r["system"] != "zkSketch" and r.get("variant") == "noroot":
            zka[r["family"]] = float(r["prove_s"])
    out = {}
    for fam in FAMS:
        ok = [x for x in rows(os.path.join(d, f"six_zksketch_{fam}.csv")) if x.get("status", "ok") == "ok"]
        if not ok or fam not in zka:
            sys.exit(f"{d}: no complete {fam} rows")
        r = ok[-1]
        k, L, E = int(r["t"]), int(r["m"]), int(r["n"])
        tot, lg = float(r["total_time_ms"]) / 1000, float(r["leafgen_seq_ms"]) / 1000
        setup = tot - float(r["leaf_busy_max_ms"]) / 1000
        out[fam] = dict(L=L, leaf=lg / k, comp=(tot - lg) / (k - 1), E=E, epoch=tot, setup=setup, zka_epoch=zka[fam])
    return out


def zks_time(e, n):
    """n records: n / L leaves and n / L - 1 compositions, at the epoch run's time per leaf and per composition."""
    t = n // e["L"]
    return t * e["leaf"] + (t - 1) * e["comp"]


def earlier_runs():
    """Measured speedups (staged runs) and per-dataset ratios (earlier forest runs, default sizes)."""
    def forest(path):
        return [r for r in rows(path) if r.get("mode") == "forest"]
    m1 = {}
    for r in forest(os.path.join(ROOT, "results", "frame_out_1machine_plonky3.csv")):
        m1[r["family"].split("_")[0]] = float(r["total_time_ms"]) / 1000
    speed = {}
    for r in forest(os.path.join(ROOT, "results", "frame_out_staged_m234_plonky3.csv")):
        fam = r["family"].split("_")[0]
        speed.setdefault(fam, {})[int(float(r["machines"]))] = m1[fam] / (float(r["total_time_ms"]) / 1000)
    ratio = {}
    for r in forest(os.path.join(ROOT, "results", "frame_out_1machine_datasets_plonky3.csv")):
        fam = r["family"].split("_")[0]
        ratio.setdefault(fam, {})[r["dataset"]] = float(r["total_time_ms"]) / 1000 / m1[fam]
    for fam in ratio:
        ratio[fam]["aol"] = 1.0
    four = ["cm", "hll", "ss", "gk"]
    # Bloom and KMV are not in these runs: they take the mean of the four measured families
    for fam in ("bloom", "kmv"):
        speed[fam] = {M: sum(speed[f][M] for f in four) / 4 for M in (2, 3, 4)}
        ratio[fam] = {ds: sum(ratio[f][ds] for f in four) / 4 for ds in DATASETS}
    return speed, ratio


def tex(v):
    v = round(v)
    return f"{v // 1000}\\,{v % 1000:03d}" if v >= 1000 else f"{v}"


def main():
    d = memmatch_dir()
    ep = epochs(d)
    speed, ratio = earlier_runs()
    md = [f"# Forest tables in the setting of Table 2 (scripts/forest_tables.py; epochs from {rel(d)})", ""]
    md.append("inputs (per family): leaf records L | s per leaf | s per composition (incl. the run's setup) | "
              "epoch records | epoch total s | setup s | zk-Analytics epoch receipt s")
    for f in FAMS:
        e = ep[f]
        md.append(f"  {LAB[f]}: {e['L']} | {e['leaf']:.4f} | {e['comp']:.4f} | {e['E']} | {e['epoch']:.2f} | "
                  f"{e['setup']:.2f} | {e['zka_epoch']:.1f}")
    md.append("\n## Table 2 check: whole-stream hours (zkSketch / zk-Analytics)")
    for f in FAMS:
        e = ep[f]
        md.append(f"{LAB[f]}: {zks_time(e, 2 ** 20) / 3600:.2f} h / {e['zka_epoch'] * (2 ** 20 // e['E']) / 3600:.1f} h")
    md.append("\n## Table 4, rows N = 2^16 .. 2^20: proving time (s) on one machine")
    for f in FAMS:
        md.append(f"{LAB[f]} & " + " & ".join(f"${tex(zks_time(ep[f], n))}$" for n in NS) + " \\\\")
    # M = 2, 3, 4: the N = 2^20 time divided by the speedup measured in the staged runs (default sizes)
    md.append("\n## Table 4, rows M = 2, 3, 4: proving time (s) at N = 2^20 and speedup (M = 1 = the N = 2^20 row)")
    for f in FAMS:
        m1 = zks_time(ep[f], 2 ** 20)
        md.append(f"{LAB[f]} & ${tex(m1)}$ ($1.00\\times$) & " + " & ".join(
            f"${tex(m1 / speed[f][M])}$ (${speed[f][M]:.2f}\\times$)" for M in (2, 3, 4)) + " \\\\")
    # Uniform, Gaussian, Netflix: the AOL time at N = 2^20 times the ratio measured in the 1-machine dataset runs
    md.append("\n## Table 5: proving time (s) by dataset at N = 2^20, spread = (max-min)/min")
    for f in FAMS:
        m1 = zks_time(ep[f], 2 ** 20)
        v = {ds: m1 * ratio[f][ds] for ds in DATASETS}
        spread = (max(v.values()) - min(v.values())) / min(v.values())
        md.append(f"{LAB[f]} & " + " & ".join(f"${tex(v[ds])}$" for ds in DATASETS) + f" & ${100 * spread:.1f}\\%$ \\\\")
    md.append("\n## Quoted in the text")
    g = {f: zks_time(ep[f], 2 ** 20) / zks_time(ep[f], 2 ** 16) for f in FAMS}
    per = {f: (zks_time(ep[f], 2 ** 16) * 1000 / 2 ** 16, zks_time(ep[f], 2 ** 20) * 1000 / 2 ** 20) for f in FAMS}
    share = {f: ep[f]["setup"] / ep[f]["epoch"] for f in FAMS}
    md.append(f"growth 2^16 -> 2^20: " + ", ".join(f"{LAB[f]} {g[f]:.2f}x" for f in FAMS)
              + f" (range {min(g.values()):.2f}-{max(g.values()):.2f}x)")
    md.append("ms per record 2^16 / 2^20: " + ", ".join(f"{LAB[f]} {a:.2f} / {b:.2f}" for f, (a, b) in per.items()))
    md.append("per-record change: " + ", ".join(f"{LAB[f]} {100 * (b / a - 1):.1f}%" for f, (a, b) in per.items()))
    md.append("setup per epoch run: " + ", ".join(f"{LAB[f]} {ep[f]['setup']:.2f} s ({100 * share[f]:.1f}%)" for f in FAMS))
    out = os.path.join(ROOT, "results", "forest_tables.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as fh:
        fh.write("\n".join(md) + "\n")
    print("\n".join(md))
    print(f"wrote {rel(out)}")


if __name__ == "__main__":
    main()
