#!/usr/bin/env python3
"""Operator figure: per-phase proving time of the Count-Min and Misra-Gries leaves, from exp_operator's CSVs.
Usage: [OP_FAMS=cm,mg] [OP_LAYOUT=column|wide] python3 scripts/plot_operator.py [<input dir, default results/operator>]
"""
import csv
import os
import statistics
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "results", "operator")
OUT_DIR = os.path.join(ROOT, "latex", "pics") if os.path.isdir(os.path.join(ROOT, "latex", "pics")) else os.path.join(ROOT, "results")
OUT = os.path.join(OUT_DIR, "zkSketch_eval_operator.pdf")

BLUE = "#2a78d6"
YELLOW = "#eda100"
GREY = "#9a9a95"
GRID = "#d9d9d4"
INK = "#0b0b0b"
INK2 = "#52514e"

PHASES = {
    "cm": ["Bind", "Derive", "Group", "Patch", "Install"],
    "mg": ["Bind", "Merge", "Cutoff", "Reduce", "Output"],
    "gk": ["Bind", "Sorted union", "Initialize", "Fusion tests", "Compaction", "Output & count"],
}
TITLES = {"cm": "Count-Min ($3{\\times}2^{14}$, $m{=}2^{14}$)", "mg": "Misra–Gries ($s{=}2^{14}$, $m{=}2^{14}$)",
          "gk": "GK ($s'{=}768$, $m{=}512$)"}
FAMS = [f for f in os.environ.get("OP_FAMS", "cm,mg").split(",") if f]

FIXED_RANGE_ROWS = 256  # the byte table every range-check table carries


def short(table):
    t = table.lower()
    for k, n in [("poseidon2", "poseidon2"), ("recompose", "recompose"), ("permute", "permute"),
                 ("range", "range"), ("expose", "expose"), ("const", "const"), ("public", "public"), ("alu", "alu")]:
        if k in t:
            return n
    return t


def read(name):
    with open(os.path.join(IN, name)) as f:
        return list(csv.DictReader(f))


def span_table(name):
    """The table a `*::build_trace` / `AluAir::*` span belongs to."""
    n = name.lower()
    for k, t in [("constair", "const"), ("publicair", "public"), ("aluair", "alu"), ("poseidon2", "poseidon2"),
                 ("recomposeair", "recompose"), ("permuteair", "permute"), ("rangeair", "range"), ("exposeair", "expose")]:
        if k in n:
            return t
    return None


def analyse(fam, phases_rows, tables_rows, spans_rows, summary_rows):
    # --- rows per phase per table (prefix differences) and padded shapes ---
    rows_phase = defaultdict(lambda: defaultdict(int))  # table -> phase -> rows
    for r in phases_rows:
        if r["fam"] != fam:
            continue
        rows_phase[short(r["table"])][int(r["phase"])] += int(r["rows"])
    # the fixed 256-row byte table is not a phase's work
    if "range" in rows_phase and rows_phase["range"][1] >= FIXED_RANGE_ROWS:
        rows_phase["range"][1] -= FIXED_RANGE_ROWS
    shape = {}  # table -> (log_h, rows, width)
    for r in tables_rows:
        if r["fam"] != fam or not r["log_h"]:
            continue
        shape[short(r["table"])] = (int(r["log_h"]), int(r["rows"]), int(r["width"]))
    order = [short(r["table"]) for r in tables_rows if r["fam"] == fam and r["log_h"]]  # AIR order
    # `padded` = the power-of-two height a table pads to; the hiding PCS then
    # commits twice that many rows (zero-knowledge blinding), a cost every
    # phase shares in proportion, so it is apportioned like the table itself.
    padded = {t: 2 ** shape[t][0] for t in shape}
    cells = {t: 2 * padded[t] * shape[t][2] for t in shape}
    tot_cells = sum(cells.values())

    # --- spans: direct per-table work and the joint remainder, per repeat ---
    reps = sorted({int(r["repeat"]) for r in spans_rows if r["fam"] == fam and r["run"] == "leaf"})
    direct_by_rep, joint_by_rep, prove_by_rep, detail_by_rep = [], [], [], []
    for rep in reps:
        rs = [r for r in spans_rows if r["fam"] == fam and r["run"] == "leaf" and int(r["repeat"]) == rep]
        direct = defaultdict(float)
        detail = defaultdict(float)
        prove_all = 0.0
        in_verify = False
        air_seq = {"infer log of constraint degree": 0, "generate lookup permutation": 0, "compute quotient": 0}
        for r in rs:
            name, ms, depth = r["name"], float(r["ms"]), int(r["depth"])
            if "verifier" in r["target"] or name == "verify_all_tables":
                in_verify = True
            if in_verify:
                continue
            if name == "prove_all_tables":
                prove_all = ms
            t = span_table(name)
            if t and depth == 1:
                direct[t] += ms
                detail["trace:" + t] += ms
            elif name == "compute quotient":
                idx = int(r["fields"].split("air_idx=")[1].split(";")[0]) if "air_idx=" in r["fields"] else air_seq[name]
                air_seq[name] += 1
                if idx < len(order):
                    direct[order[idx]] += ms
                    detail["quotient:" + order[idx]] += ms
            elif name in ("infer log of constraint degree", "generate lookup permutation"):
                idx = int(r["fields"].split("air_idx=")[1].split(";")[0]) if "air_idx=" in r["fields"] else air_seq[name]
                air_seq[name] += 1
                if idx < len(order):
                    direct[order[idx]] += ms
                    detail[name + ":" + order[idx]] += ms
            elif depth <= 2 and name in ("build merkle tree", "FRI prover", "randomize polys",
                                         "grind for proof-of-work witness", "compute_inverse_denominators"):
                detail["joint:" + name] += ms
        joint = prove_all - sum(direct.values())
        direct_by_rep.append(direct)
        joint_by_rep.append(joint)
        prove_by_rep.append(prove_all)
        detail_by_rep.append(detail)

    def med(vals):
        return statistics.median(vals) if vals else 0.0

    tables = list(shape)
    direct = {t: med([d.get(t, 0.0) for d in direct_by_rep]) for t in tables}
    joint = med(joint_by_rep)
    prove_all = med(prove_by_rep)
    # a table's time: its own spans plus the joint work (LDEs, commitments, FRI) in proportion to its committed cells
    time_t = {t: direct[t] + joint * cells[t] / tot_cells for t in tables}

    # --- phases ---
    nphase = len(PHASES[fam])
    phase_ms = [0.0] * nphase
    padding_ms = 0.0
    for t in tables:
        used = sum(rows_phase[t].values()) + (FIXED_RANGE_ROWS if t == "range" else 0)
        for k in range(1, nphase + 1):
            phase_ms[k - 1] += time_t[t] * rows_phase[t].get(k, 0) / padded[t]
        padding_ms += time_t[t] * max(padded[t] - used, 0) / padded[t]
        if t == "range":
            padding_ms += time_t[t] * FIXED_RANGE_ROWS / padded[t]

    # --- witness, verify, query from the summary ---
    def summ(run, col):
        return med([float(r[col]) for r in summary_rows if r["fam"] == fam and r["run"] == run])

    witness = summ("leaf", "witness_ms")
    prove_summary = summ("leaf", "prove_ms")
    verify = summ("leaf", "verify_ms")
    query = summ("query", "witness_ms") + summ("query", "prove_ms")

    # Medians are taken per component, so rescale the phases and padding to
    # sum exactly to the median measured prove time.
    total_t = sum(time_t.values())
    scale = prove_summary / total_t if total_t > 0 else 1.0
    phase_ms = [p * scale for p in phase_ms]
    padding_ms *= scale

    bars = [("Witness", witness)] + list(zip(PHASES[fam], phase_ms)) + [("Padding", padding_ms), ("Query", query)]
    detail = {k: med([d.get(k, 0.0) for d in detail_by_rep]) for d0 in detail_by_rep for k in d0}
    return {
        "bars": bars, "witness": witness, "prove": prove_summary, "verify": verify, "query": query,
        "tables": {t: dict(log_h=shape[t][0], rows=shape[t][1], padded=padded[t], width=shape[t][2],
                           direct_ms=direct[t], time_ms=time_t[t], phases={k: rows_phase[t].get(k, 0) for k in range(1, nphase + 1)})
                   for t in tables},
        "joint_ms": joint, "prove_span_ms": prove_all, "detail": detail, "reps": len(reps),
    }


def main():
    tag = "_".join(FAMS)
    phases_rows = read(f"{tag}_phases.csv")
    tables_rows = read(f"{tag}_tables.csv")
    spans_rows = read(f"{tag}_spans.csv")
    summary_rows = read("operator_summary.csv")
    res = {fam: analyse(fam, phases_rows, tables_rows, spans_rows, summary_rows) for fam in FAMS}

    # --- breakdown CSV (for the text) ---
    with open(os.path.join(IN, "operator_breakdown.csv"), "w") as f:
        f.write("fam,step,ms\n")
        for fam, r in res.items():
            for name, ms in r["bars"]:
                f.write(f"{fam},{name},{ms:.1f}\n")
            f.write(f"{fam},total prove,{r['prove']:.1f}\n{fam},verify,{r['verify']:.1f}\n{fam},joint,{r['joint_ms']:.1f}\n")
    with open(os.path.join(IN, "operator_tables.csv"), "w") as f:
        f.write("fam,table,log_h,rows,padded,width,direct_ms,time_ms," + ",".join(f"phase{k}" for k in range(1, 7)) + "\n")
        for fam, r in res.items():
            for t, d in r["tables"].items():
                ph = ",".join(str(d["phases"].get(k, "")) for k in range(1, 7))
                f.write(f"{fam},{t},{d['log_h']},{d['rows']},{d['padded']},{d['width']},{d['direct_ms']:.1f},{d['time_ms']:.1f},{ph}\n")
    for fam, r in res.items():
        print(f"== {fam}: witness {r['witness']:.0f} ms, prove {r['prove']:.0f} ms (spans {r['prove_span_ms']:.0f}, joint {r['joint_ms']:.0f}), verify {r['verify']:.0f} ms, query {r['query']:.0f} ms, reps {r['reps']}")
        for name, ms in r["bars"]:
            print(f"   {name:16s} {ms:8.1f} ms")
        for t, d in r["tables"].items():
            print(f"   table {t:10s} 2^{d['log_h']}(+1) rows={d['rows']:7d} w={d['width']:3d} direct={d['direct_ms']:7.1f} time={d['time_ms']:7.1f} phases={d['phases']}")
        for k, v in sorted(r["detail"].items()):
            print(f"      {k:40s} {v:8.1f}")

    # --- figure ---
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not available: numbers only, no figure")
        return
    # Single-column layout (the paper's figure, \columnwidth = 3.33 in) by
    # default; OP_LAYOUT=wide gives the earlier full-width version.
    wide = os.environ.get("OP_LAYOUT", "column") == "wide"
    fs = 7.0 if wide else 6.5
    plt.rcParams.update({
        "font.size": fs, "axes.titlesize": fs, "axes.labelsize": fs, "xtick.labelsize": fs - 0.5,
        "ytick.labelsize": fs, "legend.fontsize": fs, "pdf.fonttype": 42, "ps.fonttype": 42,
        "font.family": "sans-serif",
    })
    if wide:
        fig, axes = plt.subplots(1, len(FAMS), figsize=(7.0, 1.75))
        plt.subplots_adjust(left=0.09, right=0.985, top=0.86, bottom=0.2, wspace=0.36)
    else:
        fig, axes = plt.subplots(1, len(FAMS), figsize=(3.33, 1.5))
        plt.subplots_adjust(left=0.155, right=0.995, top=0.88, bottom=0.22, wspace=0.62)
    short_titles = {"cm": "Count-Min", "mg": "Misra–Gries", "gk": "Greenwald–Khanna"}
    for ax, fam in zip(axes, FAMS):
        bars = res[fam]["bars"]
        names = [n for n, _ in bars]
        secs = [ms / 1000.0 for _, ms in bars]
        colors = []
        for n in names:
            colors.append(GREY if n in ("Witness", "Padding") else YELLOW if n == "Query" else BLUE)
        y = list(range(len(bars)))[::-1]
        ax.barh(y, secs, color=colors, height=0.7, edgecolor="none")
        ax.set_yticks(y)
        ax.set_yticklabels([f"{i+1} {n}" if n in PHASES[fam] else n for i, n in [(PHASES[fam].index(n) if n in PHASES[fam] else -1, n) for n in names]])
        ax.set_ylim(-0.6, len(bars) - 0.4)
        xmax = max(secs) * (1.3 if wide else 1.42)
        ax.set_xlim(0, xmax)
        fmt = "{:.1f}" if max(secs) >= 10 else "{:.2f}"
        for yi, s in zip(y, secs):
            ax.text(s + xmax * 0.015, yi, fmt.format(s), va="center", ha="left", fontsize=fs - 1.0, color=INK2)
        ax.xaxis.set_major_locator(plt.MaxNLocator(nbins=4, steps=[1, 2, 5, 10]))
        ax.set_xlabel("time (s)", labelpad=1.5)
        ax.set_title(TITLES[fam] if wide else short_titles[fam], color=INK, pad=3)
        ax.grid(axis="x", color=GRID, linewidth=0.5)
        ax.set_axisbelow(True)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_linewidth(0.6)
        ax.tick_params(axis="both", length=2, width=0.5, pad=1.5)
    fig.savefig(OUT, bbox_inches="tight", pad_inches=0.01)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
