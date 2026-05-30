#!/usr/bin/env python3
"""Render the zkSketch evaluation figures from the experiment CSVs.

Reads `results/*.csv` (produced by `cargo run --release --example exp_*`) and
writes one figure per panel to `results/figures/*.pdf` (+ `.png`). Each figure
maps to a paper panel (RQ1-a … RQ4, case study); see `docs/EVALUATION.md`.

Usage:
    cargo run --release --example exp_rq1   # (and exp_rq2 … exp_casestudy)
    python3 scripts/plot_experiments.py     # render every available figure
    python3 scripts/plot_experiments.py rq2a rq4ab   # just some

Dependencies: matplotlib only (CSV parsing is stdlib). If matplotlib is
missing the script explains how to install it and exits cleanly.
"""
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")
FIGS = os.path.join(RESULTS, "figures")

try:
    import matplotlib

    matplotlib.use("Agg")  # headless
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit(
        "matplotlib not found. Install it with:\n"
        "    python3 -m pip install matplotlib\n"
        "The CSVs in results/ are still usable directly (e.g. in a notebook)."
    )


def load(name):
    """Load results/<name>.csv → (header, list-of-dict-rows), or None if absent."""
    path = os.path.join(RESULTS, name + ".csv")
    if not os.path.exists(path):
        print(f"  skip {name}: {os.path.relpath(path, ROOT)} not found")
        return None
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    return reader.fieldnames, rows


def save(fig, name):
    os.makedirs(FIGS, exist_ok=True)
    for ext in ("pdf", "png"):
        out = os.path.join(FIGS, f"{name}.{ext}")
        fig.savefig(out, bbox_inches="tight", dpi=150)
    plt.close(fig)
    print(f"  wrote {os.path.relpath(os.path.join(FIGS, name + '.pdf'), ROOT)}")


def by_family(rows, fam_key="family"):
    fams = {}
    for r in rows:
        fams.setdefault(r[fam_key], []).append(r)
    return fams


# ─── RQ1-a: history independence ─────────────────────────────────────────────
def fig_rq1a():
    data = load("rq1a_history_independence")
    if not data:
        return
    _, rows = data
    x = [int(r["epoch"]) for r in rows]
    y = [float(r["prove_ms"]) for r in rows]
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.plot(x, y, "o-", label="per-epoch prove time")
    ax.axhline(sum(y) / len(y), ls="--", c="gray", label=f"mean {sum(y)/len(y):.0f} ms")
    ax.set_xlabel("epoch index $t$")
    ax.set_ylabel("prove time (ms)")
    ax.set_ylim(0, max(y) * 1.3)
    ax.set_title("RQ1-a: CM per-epoch cost is constant in $t$")
    ax.legend()
    save(fig, "fig_rq1a_history_independence")


# ─── RQ2-a: batch-size scaling ───────────────────────────────────────────────
def fig_rq2a():
    data = load("rq2a_batch_size")
    if not data:
        return
    _, rows = data
    fig, ax = plt.subplots(figsize=(5, 3))
    for fam, rs in by_family(rows).items():
        rs.sort(key=lambda r: int(r["m"]))
        ax.plot([int(r["m"]) for r in rs], [float(r["prove_ms"]) for r in rs], "o-", label=fam)
    ax.set_xlabel("batch size $m$")
    ax.set_ylabel("prove time (ms)")
    ax.set_xscale("log", base=2)
    ax.set_title("RQ2-a: prove time vs batch size")
    ax.legend()
    save(fig, "fig_rq2a_batch_size")


# ─── RQ2-b: distinct-bound linearity ─────────────────────────────────────────
def fig_rq2b():
    data = load("rq2b_distinct_bound")
    if not data:
        return
    _, rows = data
    rows.sort(key=lambda r: int(r["distinct_bound"]))
    x = [int(r["distinct_bound"]) for r in rows]
    y = [float(r["prove_ms"]) for r in rows]
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.plot(x, y, "s-", color="C2")
    ax.set_xlabel("distinct_bound (hash gadget runs $\\mathrm{db}\\cdot d$ times)")
    ax.set_ylabel("prove time (ms)")
    ax.set_title("RQ2-b: CM prove time linear in distinct_bound")
    save(fig, "fig_rq2b_distinct_bound")


# ─── RQ2-c: state-size scaling ───────────────────────────────────────────────
def fig_rq2c():
    data = load("rq2c_state_size")
    if not data:
        return
    _, rows = data
    fig, ax = plt.subplots(figsize=(5, 3))
    for fam, rs in by_family(rows).items():
        rs.sort(key=lambda r: int(r["state_size"]))
        ax.plot([int(r["state_size"]) for r in rs], [float(r["prove_ms"]) for r in rs], "o-", label=fam)
    ax.set_xlabel("state size $s$")
    ax.set_ylabel("prove time (ms)")
    ax.set_xscale("log", base=2)
    ax.set_title("RQ2-c: state-size scaling (flat commit ⇒ grows with $s$)")
    ax.legend()
    save(fig, "fig_rq2c_state_size")


# ─── RQ2-d: audit-window (merge counts; root constant) ───────────────────────
def fig_rq2d():
    data = load("rq2d_audit_window")
    if not data:
        return
    _, rows = data
    rows.sort(key=lambda r: int(r["E"]))
    E = [int(r["E"]) for r in rows]
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.plot(E, [int(r["chain_merges"]) for r in rows], "o-", label="chain merges Θ(E)")
    ax.plot(E, [int(r["forest_worst_insert_merges"]) for r in rows], "s-", label="forest worst insert log E")
    ax.plot(E, [int(r["root_digest_bytes"]) for r in rows], "^--", label="root digest bytes O(1)")
    ax.set_xlabel("audit window $E$")
    ax.set_ylabel("count")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=2)
    ax.set_title("RQ2-d/1-b: history grows Θ(E); root + verifier O(1)")
    ax.legend()
    save(fig, "fig_rq2d_audit_window")


# ─── RQ3-a: naive vs optimised ───────────────────────────────────────────────
def fig_rq3a():
    data = load("rq3a_naive_vs_optimised")
    if not data:
        return
    _, rows = data
    labels, naive, opt = [], [], []
    for r in rows:
        tag = f"({r['d']},{r['w']},{r['batch']})"
        if r["variant"] == "naive_strawman":
            labels.append(tag)
            naive.append(float(r["prove_ms"]))
        else:
            opt.append(float(r["prove_ms"]))
    import numpy as np

    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.bar(x - 0.2, naive, 0.4, label="naive strawman (§5.1)")
    ax.bar(x + 0.2, opt, 0.4, label="optimised (§5.2)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_xlabel("(d, w, batch)")
    ax.set_ylabel("prove time (ms)")
    ax.set_title("RQ3-a: structural gap (asymptotic; small-scale shown)")
    ax.legend()
    save(fig, "fig_rq3a_naive_vs_optimised")


# ─── RQ3-d: dedup under skew ─────────────────────────────────────────────────
def fig_rq3d():
    data = load("rq3d_dedup_skew")
    if not data:
        return
    _, rows = data
    rows.sort(key=lambda r: float(r["alpha"]))
    a = [float(r["alpha"]) for r in rows]
    fig, ax1 = plt.subplots(figsize=(5, 3))
    ax1.plot(a, [float(r["prove_ms_full"]) for r in rows], "o-", color="C3", label="full (db=batch)")
    ax1.plot(a, [float(r["prove_ms_dedup"]) for r in rows], "s-", color="C0", label="dedup (db=u)")
    ax1.set_xlabel("Zipf skew $\\alpha$")
    ax1.set_ylabel("prove time (ms)")
    ax2 = ax1.twinx()
    ax2.plot(a, [int(r["realised_distinct"]) for r in rows], "^--", color="gray", label="realised distinct $u$")
    ax2.set_ylabel("realised distinct $u$")
    ax1.set_title("RQ3-d: skew shrinks $u$ ⇒ dedup saving")
    ax1.legend(loc="center left")
    save(fig, "fig_rq3d_dedup_skew")


# ─── RQ3-e: retention vs fusion ──────────────────────────────────────────────
def fig_rq3e():
    data = load("rq3e_retention_vs_fusion")
    if not data:
        return
    _, rows = data
    labels = [f"{r['shape']}\n({r['rounds']}r)" for r in rows]
    y = [float(r["prove_ms"]) for r in rows]
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.bar(labels, y, color=["C0", "C3", "C1"][: len(y)])
    ax.set_ylabel("prove time (ms)")
    ax.set_title("RQ3-e: SS single-pass retention vs GK fusion rounds")
    save(fig, "fig_rq3e_retention_vs_fusion")


# ─── RQ4-a/b: topology online cost ───────────────────────────────────────────
def fig_rq4ab():
    data = load("rq4ab_topology_online")
    if not data:
        return
    _, rows = data
    rows.sort(key=lambda r: int(r["E"]))
    E = [int(r["E"]) for r in rows]
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.plot(E, [float(r["chain_per_insert"]) for r in rows], "o-", label="chain (serial)")
    ax.plot(E, [float(r["tree_spine_depth"]) for r in rows], "^-", label="tree spine log E")
    ax.plot(E, [float(r["forest_amortized"]) for r in rows], "s-", label="forest amortised")
    ax.plot(E, [float(r["forest_worst_insert"]) for r in rows], "d--", label="forest worst log E")
    ax.set_xlabel("audit window $E$")
    ax.set_ylabel("merges per insert")
    ax.set_xscale("log", base=2)
    ax.set_title("RQ4-a/b: per-update merge cost by topology")
    ax.legend()
    save(fig, "fig_rq4ab_topology")


# ─── RQ4-c/d: policy fold ────────────────────────────────────────────────────
def fig_rq4cd():
    data = load("rq4cd_policy")
    if not data:
        return
    _, rows = data
    rows.sort(key=lambda r: int(r["t"]))
    peaks = [int(r["surviving_peaks"]) for r in rows]
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.plot(peaks, [int(r["lazy_merges"]) for r in rows], "o-", label="lazy (ℓ-1 sequential)")
    ax.plot(peaks, [int(r["queryburst_merges"]) for r in rows], "s-", label="query-burst (⌈log₂ℓ⌉)")
    ax.set_xlabel("surviving peaks $\\ell = \\mathrm{popcount}(t)$")
    ax.set_ylabel("finalisation merges")
    ax.set_title("RQ4-c/d: query-burst folds peaks in log depth")
    ax.legend()
    save(fig, "fig_rq4cd_policy")


# ─── Case study: ingest ──────────────────────────────────────────────────────
def fig_casestudy():
    data = load("casestudy_ingest")
    if not data:
        return
    _, rows = data
    import numpy as np

    datasets = sorted({r["dataset"] for r in rows})
    families = ["CM", "GK", "HLL", "SS"]
    fig, ax = plt.subplots(figsize=(6, 3))
    x = np.arange(len(datasets))
    width = 0.2
    for i, fam in enumerate(families):
        vals = []
        for ds in datasets:
            match = [r for r in rows if r["dataset"] == ds and r["family"] == fam]
            vals.append(float(match[0]["total_prove_ms"]) if match else 0.0)
        ax.bar(x + (i - 1.5) * width, vals, width, label=fam)
    ax.set_xticks(x)
    ax.set_xticklabels(datasets)
    ax.set_ylabel("total prove time (ms)")
    ax.set_title("Case study: 4-epoch ingest per family per stream")
    ax.legend(ncol=4, fontsize=8)
    save(fig, "fig_casestudy_ingest")


FIGURES = {
    "rq1a": fig_rq1a,
    "rq2a": fig_rq2a,
    "rq2b": fig_rq2b,
    "rq2c": fig_rq2c,
    "rq2d": fig_rq2d,
    "rq3a": fig_rq3a,
    "rq3d": fig_rq3d,
    "rq3e": fig_rq3e,
    "rq4ab": fig_rq4ab,
    "rq4cd": fig_rq4cd,
    "casestudy": fig_casestudy,
}


def main():
    want = [a for a in sys.argv[1:] if not a.startswith("-")]
    keys = want if want else list(FIGURES)
    print(f"Rendering figures → {os.path.relpath(FIGS, ROOT)}/")
    for k in keys:
        fn = FIGURES.get(k)
        if fn is None:
            print(f"  unknown figure '{k}'; known: {', '.join(FIGURES)}")
            continue
        fn()
    print("done.")


if __name__ == "__main__":
    main()
