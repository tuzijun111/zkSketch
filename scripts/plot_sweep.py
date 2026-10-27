#!/usr/bin/env python3
"""Render the batch-size sweep (zkSketch vs zk-Analytics, six sketches) as
latex/pics/zkSketch_eval_sweep.pdf from a `run_all.sh sweep` results directory
(its sweep.csv; see scripts/baselines/zka/six/sweep_table.py for the columns).

Usage: python3 scripts/plot_sweep.py [<sweep results dir>]
  default dir: the newest results/six/sweep-*/ (quick smokes excluded).
Style follows scripts/plot_eval.py (same fonts, ink and palette); the legend sits
inside the first panel only. Needs matplotlib.
"""
import csv
import glob
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
_PICS = os.path.join(ROOT, "latex", "pics")
OUT = os.path.join(_PICS if os.path.isdir(_PICS) else os.path.join(ROOT, "results"),
                   "zkSketch_eval_sweep.pdf")

# palette as in plot_eval.py: blue = ours (certified), yellow = the replay baseline
C_ZKS = "#2a78d6"
C_ZKA = "#eda100"
GRID = "#d9d9d4"
INK = "#0b0b0b"
INK2 = "#52514e"

FAMS = ["cm", "hll", "ss", "gk", "bloom", "kmv"]
TITLES = {
    "cm": "Count-Min  ($3{\\times}1024$)",
    "hll": "HLL  ($b{=}14$)",
    "ss": "MG  ($s{=}1024$)",
    "gk": "GK  ($s'{=}2^{11}$)",
    "bloom": "Bloom  ($7{\\times}2^{14}$)",
    "kmv": "KMV  ($s{=}1024$)",
}


def newest_sweep_dir():
    dirs = [d for d in glob.glob(os.path.join(ROOT, "results", "six", "sweep-*"))
            if os.path.isdir(d) and "quick" not in os.path.basename(d)]
    if not dirs:
        sys.exit("no results/six/sweep-*/ directory; pass one explicitly")
    return max(dirs, key=os.path.getmtime)


def load(sweep_dir):
    rows = list(csv.DictReader(open(os.path.join(sweep_dir, "sweep.csv"))))
    data = {f: [] for f in FAMS}
    for r in rows:
        if r["family"] not in data or not r["zka_ms_per_record"] or not r["zks_ms_per_record"]:
            continue
        data[r["family"]].append((int(r["m"]), float(r["zka_ms_per_record"]),
                                  float(r["zks_ms_per_record"]), float(r["speedup"] or "nan"),
                                  r.get("zks_variant", "")))
    for f in data:
        data[f].sort()
    return data


def main():
    sweep_dir = sys.argv[1] if len(sys.argv) > 1 else newest_sweep_dir()
    data = load(sweep_dir)
    plt.rcParams.update({
        "font.size": 7.0, "axes.titlesize": 7.0, "axes.labelsize": 7.0,
        "xtick.labelsize": 6.5, "ytick.labelsize": 6.5, "legend.fontsize": 7.0,
        "text.color": INK, "axes.edgecolor": INK2, "axes.labelcolor": INK,
        "xtick.color": INK2, "ytick.color": INK2,
        "pdf.fonttype": 42,  # embed TrueType so ACM's pdf checks pass
    })
    fig, axes = plt.subplots(1, 6, figsize=(7.0, 1.45), sharey=True)
    fig.subplots_adjust(left=0.055, right=0.995, top=0.88, bottom=0.22, wspace=0.10)
    for ax, fam in zip(axes, FAMS):
        pts = data[fam]
        if not pts:
            ax.set_title(TITLES[fam], pad=3)
            continue
        xs = [p[0] for p in pts]
        ax.plot(xs, [p[1] for p in pts], color=C_ZKA, marker="^", markersize=3.2,
                linewidth=1.4, label="zk-Analytics", zorder=3,
                markerfacecolor=C_ZKA, markeredgewidth=0)
        ax.plot(xs, [p[2] for p in pts], color=C_ZKS, marker="o", markersize=3.2,
                linewidth=1.4, label="zkSketch", zorder=3,
                markerfacecolor=C_ZKS, markeredgewidth=0)
        # the ratio at the largest batch, next to the last points
        m_last, zka_last, zks_last, sp_last, _ = pts[-1]
        ax.annotate(f"{sp_last:.0f}×", xy=(m_last, (zka_last * zks_last) ** 0.5),
                    xytext=(-2, 0), textcoords="offset points", ha="right", va="center",
                    fontsize=6.5, color=INK2)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlim(40, 26000)
        ax.set_ylim(0.6, 40000)
        ax.set_xticks([2 ** k for k in (6, 8, 10, 12, 14)])
        ax.set_xticklabels(["$2^{%d}$" % k for k in (6, 8, 10, 12, 14)])
        ax.set_title(TITLES[fam], pad=3)
        ax.set_xlabel("batch size $m$", labelpad=1.5)
        ax.grid(axis="y", color=GRID, linewidth=0.6, zorder=0)
        ax.tick_params(length=2, pad=1.5)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_linewidth(0.6)
    axes[0].set_ylabel("proving time / record (ms)", labelpad=2)
    # one legend, inside the first panel (as in VPJoin's Figure 3)
    axes[0].legend(loc="upper right", fontsize=5.8, frameon=True, framealpha=0.9,
                   edgecolor=GRID, fancybox=False, handlelength=1.5, handletextpad=0.4,
                   borderpad=0.3, labelspacing=0.25, borderaxespad=0.3)
    fig.savefig(OUT, bbox_inches="tight", pad_inches=0.01)
    print(f"wrote {os.path.relpath(OUT)} from {os.path.relpath(sweep_dir)}")


if __name__ == "__main__":
    main()
