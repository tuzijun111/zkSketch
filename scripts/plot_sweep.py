#!/usr/bin/env python3
"""Figure 5 (zkSketch_eval_sweep.pdf): proving time per record vs batch size, zkSketch vs zk-Analytics, six sketches.
Usage: python3 scripts/plot_sweep.py [<csv> | <results dir>]   (default: the sweep_memmatch.csv of sweep_memmatch.py)
"""
import csv
import glob
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
_PICS = os.path.join(ROOT, "latex", "pics")
OUT = os.path.join(_PICS if os.path.isdir(_PICS) else os.path.join(ROOT, "results"),
                   "zkSketch_eval_sweep.pdf")
DEFAULT_CSV = os.path.join(ROOT, "scripts", "baselines", "zka", "results", "sweep-memmatch", "sweep_memmatch.csv")

# palette as in plot_eval.py: blue = ours (certified), yellow = the replay baseline
C_ZKS = "#2a78d6"
C_ZKA = "#eda100"
GRID = "#d9d9d4"
INK = "#0b0b0b"
INK2 = "#52514e"

FAMS = ["cm", "hll", "ss", "gk", "bloom", "kmv"]
TITLES = {"cm": "Count-Min", "hll": "HLL", "ss": "MG", "gk": "GK", "bloom": "Bloom", "kmv": "KMV"}


def default_input():
    if os.path.exists(DEFAULT_CSV):
        return DEFAULT_CSV
    dirs = [d for d in glob.glob(os.path.join(ROOT, "results", "six", "sweep-*"))
            if os.path.isdir(d) and "quick" not in os.path.basename(d) and os.path.exists(os.path.join(d, "sweep.csv"))]
    if not dirs:
        sys.exit("no sweep_memmatch.csv and no results/six/sweep-*/sweep.csv; pass a CSV explicitly")
    return max(dirs, key=os.path.getmtime)


def load(path):
    if os.path.isdir(path):
        csv_path = os.path.join(path, "sweep_memmatch.csv")
        if not os.path.exists(csv_path):
            csv_path = os.path.join(path, "sweep.csv")
    else:
        csv_path = path
    rows = list(csv.DictReader(open(csv_path)))
    data = {f: [] for f in FAMS}
    titles = dict(TITLES)
    for r in rows:
        if r["family"] not in data or not r["zka_ms_per_record"] or not r["zks_ms_per_record"]:
            continue
        f = r["family"]
        data[f].append(dict(m=int(r["m"]), zka=float(r["zka_ms_per_record"]), zks=float(r["zks_ms_per_record"]),
                            speedup=float(r["speedup"] or "nan"),
                            zka_meas=r.get("zka_basis", "measured") == "measured",
                            zks_meas=r.get("zks_basis", "measured") == "measured",
                            anchor=r.get("anchor", "") == "1"))
    for f in data:
        data[f].sort(key=lambda p: p["m"])
    return data, titles, csv_path


def series(ax, pts, key, color, marker):
    """One solid line with a marker at every point; points whose zka_basis / zks_basis is not 'measured'
    (computed in sweep_memmatch.py) are drawn the same way."""
    ax.plot([p["m"] for p in pts], [p[key] for p in pts], color=color, marker=marker, markersize=3.2,
            linewidth=1.4, markerfacecolor=color, markeredgewidth=0, zorder=3)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else default_input()
    data, titles, csv_path = load(src)
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
            ax.set_title(titles[fam], pad=3)
            continue
        series(ax, pts, "zka", C_ZKA, "^")
        series(ax, pts, "zks", C_ZKS, "o")
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlim(40, 26000)
        ax.set_ylim(0.6, 40000)
        ax.set_xticks([2 ** k for k in (6, 8, 10, 12, 14)])
        ax.set_xticklabels(["$2^{%d}$" % k for k in (6, 8, 10, 12, 14)])
        ax.set_title(titles[fam], pad=3)
        ax.set_xlabel("batch size $m$", labelpad=1.5)
        ax.grid(axis="y", color=GRID, linewidth=0.6, zorder=0)
        ax.tick_params(length=2, pad=1.5)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_linewidth(0.6)
    axes[0].set_ylabel("proving time / record (ms)", labelpad=2)
    # one legend, inside the first panel (as in VPJoin's Figure 3)
    handles = [Line2D([], [], color=C_ZKA, marker="^", markersize=3.2, linewidth=1.4, markeredgewidth=0, label="zk-Analytics"),
               Line2D([], [], color=C_ZKS, marker="o", markersize=3.2, linewidth=1.4, markeredgewidth=0, label="zkSketch")]
    axes[0].legend(handles=handles, loc="upper right", fontsize=5.8, frameon=True, framealpha=0.9,
                   edgecolor=GRID, fancybox=False, handlelength=1.5, handletextpad=0.4,
                   borderpad=0.3, labelspacing=0.25, borderaxespad=0.3)
    fig.savefig(OUT, bbox_inches="tight", pad_inches=0.01)
    print(f"wrote {os.path.relpath(OUT)} from {os.path.relpath(csv_path)}")


if __name__ == "__main__":
    main()
