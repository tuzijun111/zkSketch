#!/usr/bin/env python3
"""Generate the evaluation figures for zk1.tex from results/*.csv.

Reads the e1 per-family batch sweeps (results/{cm,hll,ss,gk}_batch_*.csv,
produced by scripts/run_experiments.sh e1) and renders zkSketch_eval_batch.pdf:

a 4-panel log-log figure: PER-UPDATE prover time (prove_total_ms / m) vs batch
size m, one panel per sketch family, one line per circuit variant, named as in
the paper: Pattern A (cm, hll) one-hot / Merkle / memory-checked; Pattern B
(ss, gk) replay / certified. A dotted whisker ending in an 'x' marks the first
infeasible batch size (a too_large row: the padded trace exceeds the backend's
2^27 FRI-domain cap or, for the Count-Min one-hot leaf, its m*d*(d*w) selector
cells exceed the prototype's memory guard, COUNTMIN_MAX_SEL_CELLS = 1.6e7).

Output goes to latex/pics/ when that directory exists (the paper tree, which is
not part of the public repo), else to results/.

Run from anywhere:  python3 scripts/plot_eval.py
Needs matplotlib (pip install --user matplotlib).
"""

import csv
import math
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
RESULTS = os.path.join(ROOT, "results")
_PICS = os.path.join(ROOT, "latex", "pics")
OUT = os.path.join(_PICS if os.path.isdir(_PICS) else RESULTS, "zkSketch_eval_batch.pdf")

# ── palette (validated categorical slots 1-3; color follows the VARIANT
#    entity across every panel, never the panel) ──────────────────────────
C_CERT = "#2a78d6"  # slot 1 blue  — certified / OMC (the deployed circuit)
C_MERK = "#1baf7a"  # slot 2 aqua  — Merkle sparse-opening
C_REPL = "#eda100"  # slot 3 yellow — per-record replay / one-hot
GRID = "#d9d9d4"
INK = "#0b0b0b"
INK2 = "#52514e"

# (csv file, variant-name-in-csv, legend label, color, marker). Colors follow
# the variant CLASS across panels (baseline / middle ground / deployed); labels
# use each pattern's own paper names, combined in the shared legend.
LBL_BASE = "one-hot / replay"
LBL_CERT = "certified (ours)"
VARIANTS = {
    "cm": [
        ("cm_batch_one_hot.csv", "one_hot", LBL_BASE, C_REPL, "^"),
        ("cm_batch_merkle.csv", "merkle", "Merkle", C_MERK, "s"),
        ("cm_batch_omc.csv", "omc", LBL_CERT, C_CERT, "o"),
    ],
    "hll": [
        ("hll_batch_one_hot.csv", "one_hot", LBL_BASE, C_REPL, "^"),
        ("hll_batch_merkle.csv", "merkle", "Merkle", C_MERK, "s"),
        ("hll_batch_omc.csv", "omc", LBL_CERT, C_CERT, "o"),
    ],
    "ss": [
        ("ss_batch_naive.csv", "naive", LBL_BASE, C_REPL, "^"),
        ("ss_batch_certified.csv", "certified", LBL_CERT, C_CERT, "o"),
    ],
    "gk": [
        ("gk_batch_naive.csv", "bandmerge2_naive", LBL_BASE, C_REPL, "^"),
        ("gk_batch_certified.csv", "bandmerge2", LBL_CERT, C_CERT, "o"),
    ],
}
TITLES = {
    "cm": "Count-Min  ($d{=}7$, $w{=}2^{14}$)",
    "hll": "HyperLogLog  ($b{=}14$)",
    "ss": "SpaceSaving  ($s{=}2^{14}$)",
    "gk": "Greenwald–Khanna  ($s'{=}2^{11}$)",
}


def load(fname, variant):
    """-> (ok: [(m, prove_ms_per_update)], first_infeasible_m or None).
    Dedupe by m, last wins."""
    path = os.path.join(RESULTS, fname)
    ok, dead = {}, set()
    if not os.path.exists(path):
        return [], None
    with open(path) as f:
        for r in csv.DictReader(f):
            if r.get("variant") != variant:
                continue
            m = int(r["m"])
            if r.get("status") == "ok":
                ok[m] = float(r["prove_total_ms"]) / m
                dead.discard(m)
            else:
                dead.add(m)
    pts = sorted(ok.items())
    dead_after_last = sorted(d for d in dead if not pts or d > pts[-1][0])
    return pts, (dead_after_last[0] if dead_after_last else None)


def main():
    plt.rcParams.update(
        {
            "font.size": 7.0,
            "axes.titlesize": 7.0,
            "axes.labelsize": 7.0,
            "xtick.labelsize": 6.5,
            "ytick.labelsize": 6.5,
            "legend.fontsize": 7.0,
            "text.color": INK,
            "axes.edgecolor": INK2,
            "axes.labelcolor": INK,
            "xtick.color": INK2,
            "ytick.color": INK2,
            "pdf.fonttype": 42,  # embed TrueType so ACM's pdf checks pass
        }
    )
    fig, axes = plt.subplots(1, 4, figsize=(7.0, 1.62), sharey=True)
    fig.subplots_adjust(left=0.055, right=0.995, top=0.80, bottom=0.21, wspace=0.10)

    for ax, fam in zip(axes, ["cm", "hll", "ss", "gk"]):
        for fname, var, label, color, marker in VARIANTS[fam]:
            pts, dead_m = load(fname, var)
            if not pts:
                continue
            xs, ys = zip(*pts)
            ax.plot(
                xs, ys, color=color, marker=marker, markersize=3.2,
                linewidth=1.4, label=label, zorder=3,
                markerfacecolor=color, markeredgewidth=0,
            )
            if dead_m is not None:
                # dotted whisker to the first infeasible m, ending in an x
                ax.plot([xs[-1], dead_m], [ys[-1], ys[-1]], color=color,
                        linewidth=1.0, linestyle=(0, (1, 2)), zorder=2)
                ax.plot([dead_m], [ys[-1]], color=color, marker="x",
                        markersize=4.5, markeredgewidth=1.3, zorder=3)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlim(11, 24000)
        ax.set_ylim(0.6, 30000)
        ax.set_xticks([2**k for k in (4, 6, 8, 10, 12, 14)])
        ax.set_xticklabels(["$2^{%d}$" % k for k in (4, 6, 8, 10, 12, 14)])
        ax.set_title(TITLES[fam], pad=3)
        ax.set_xlabel("batch size $m$", labelpad=1.5)
        ax.grid(axis="y", color=GRID, linewidth=0.6, zorder=0)
        ax.tick_params(length=2, pad=1.5)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_linewidth(0.6)
    axes[0].set_ylabel("prover time / update (ms)", labelpad=2)

    # one figure-level legend: the three variant entities (+ the infeasibility mark)
    handles, labels = axes[1].get_legend_handles_labels()  # hll panel has all 3
    xmark = plt.Line2D([], [], color=INK2, marker="x", markersize=4.5,
                       markeredgewidth=1.3, linestyle=(0, (1, 2)), linewidth=1.0,
                       label="infeasible ($>2^{27}$ FRI domain; CM one-hot: selector guard)")
    fig.legend(
        handles + [xmark], labels + [xmark.get_label()],
        loc="upper center", ncol=4, frameon=False,
        bbox_to_anchor=(0.5, 1.01), columnspacing=1.6, handletextpad=0.5,
        handlelength=1.8, borderaxespad=0.0,
    )
    fig.savefig(OUT, bbox_inches="tight", pad_inches=0.01)
    print(f"wrote {os.path.relpath(OUT)}")


if __name__ == "__main__":
    main()
