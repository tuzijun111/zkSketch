#!/usr/bin/env python3
"""E10 — cost-model validation (EVAL_SPEC E10).

Reads the measured E1/E3/E4 CSVs, computes the paper's closed-form per-family
constraint prediction for each config, and checks that the measured cost tracks
the prediction (target deviation <= 1.5x).

Honest unit caveat
------------------
The paper's cost model (App. constraint-budget) is stated in *arithmetic-circuit
constraints*. The prototype's reported ``constraint_count`` is NOT in that unit:
- plonky3 reports the summed FRI log-degrees (Sigma log2 of each padded table
  height) -- it grows ~logarithmically, so it does NOT track the arithmetic
  model linearly.
- plonky2 reports degree * num_wires (closer to a raw constraint count).

So a raw predicted-arithmetic vs measured-log-degree ratio is meaningless on
plonky3. The cost model is therefore validated against ``prove_total_ms`` -- the
backend-independent cost proxy the paper itself recommends -- calibrated per
(experiment, backend, family) group with a single scale constant (the gadget
constants c_* are absorbed into that constant). ``predicted_constraints`` and
``measured_constraints`` are still reported for reference, with the unit flagged.

Output: results/e10_costmodel.csv
  experiment, backend, family, config, predicted_constraints,
  measured_constraint_count, measured_prove_total_ms, ratio_prove, within_1.5x, note
"""
import csv
import math
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")


def log2(x):
    return math.log2(max(2.0, float(x)))


def load(name):
    path = os.path.join(RESULTS, name + ".csv")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return list(csv.DictReader(f))


def geti(row, key, default=0):
    v = row.get(key, default)
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def predicted(experiment, family, row):
    """Dominant-term constraint prediction (gadget constants = 1)."""
    m = geti(row, "m")
    d = geti(row, "d")
    w = geti(row, "w")
    s = geti(row, "s")
    tmax = geti(row, "T_max")
    if experiment == "e3":
        # decode re-hashes the whole committed state: Theta(s).
        return float(s)
    if family == "cm":
        # sort (m*d log m*d) + counter-aggregate/patch over touched cells + cells.
        touched = tmax if tmax else m * max(1, d)
        return m * max(1, d) * log2(m * max(1, d)) + touched + max(1, d) * max(1, w)
    if family == "hll":
        # m per-record routes + 2^b registers (s).
        return float(m + s)
    if family in ("ss", "gk"):
        # union + sort over s+m, then per-row work.
        return (s + m) * log2(s + m)
    return float("nan")


def collect():
    """Return list of (experiment, backend, family, config, predicted, meas_cc, meas_ms)."""
    rows = []
    # E1: certified rows only (skip replay baseline).
    for r in load("e1_circuit") or []:
        if r.get("variant") and r["variant"] != "certified":
            continue
        rows.append((
            "E1", r["backend"], r["family"], f"m{r.get('m')}",
            predicted("e1", r["family"], r),
            geti(r, "constraint_count"), float(r.get("prove_total_ms_median", 0) or 0),
        ))
    # E3: identity release only (avoid double-counting the threshold variant).
    for r in load("e3_decode") or []:
        if r.get("release_policy") not in (None, "identity"):
            continue
        rows.append((
            "E3", r["backend"], r["family"], f"s{r.get('s')}",
            predicted("e3", r["family"], r),
            geti(r, "constraint_count"), float(r.get("prove_total_ms_median", 0) or 0),
        ))
    # E4: scaling sweeps a (batch m) and b (touched-cell capacity).
    for r in load("e4_scaling") or []:
        sweep = r.get("sweep")
        if sweep not in ("a", "b"):
            continue
        rows.append((
            f"E4{sweep}", r["backend"], r["family"],
            f"m{r.get('m')};Tmax{r.get('T_max')}",
            predicted("e4", r["family"], r),
            geti(r, "constraint_count"), float(r.get("prove_total_ms_median", 0) or 0),
        ))
    return rows


def main():
    rows = collect()
    if not rows:
        print("E10: no input CSVs found in results/ (run e1/e3/e4 first).")
        return
    # Group by (experiment, backend, family); fit the paper's model shape
    # `prove_ms ≈ c_lin + k · predicted` (affine least-squares — c_lin is the
    # cost model's own constant term, k absorbs the gadget constants), then check
    # each config's residual ratio. A group needs >= 3 points to be a real test
    # (an affine fit is exact at 2 points), so only those count toward the
    # validated total.
    groups = {}
    for r in rows:
        groups.setdefault((r[0], r[1], r[2]), []).append(r)

    out = [[
        "experiment", "backend", "family", "config", "predicted_constraints",
        "measured_constraint_count", "measured_prove_total_ms", "ratio_prove",
        "within_1.5x", "note",
    ]]
    n_within = 0
    n_total = 0
    for key, grp in sorted(groups.items()):
        grp = sorted(grp, key=lambda x: x[4])  # by predicted
        xs = [g[4] for g in grp]
        ys = [g[6] for g in grp]
        n = len(grp)
        # affine least-squares: ys ≈ a + k·xs.
        if n == 1:
            a, k = ys[0], 0.0
        else:
            sx, sy = sum(xs), sum(ys)
            sxx = sum(x * x for x in xs)
            sxy = sum(x * y for x, y in zip(xs, ys))
            denom = n * sxx - sx * sx
            if abs(denom) < 1e-9:
                a, k = sy / n, 0.0
            else:
                k = (n * sxy - sx * sy) / denom
                a = (sy - k * sx) / n
        testable = n >= 3
        for (exp, backend, fam, cfg, pred, cc, ms) in grp:
            pred_ms = a + k * pred
            ratio = (ms / pred_ms) if pred_ms > 0 else float("nan")
            within = (not math.isnan(ratio)) and (1.0 / 1.5 <= ratio <= 1.5)
            note = []
            if not testable:
                note.append(f"n={n}<3(underdetermined)")
            if backend == "plonky3":
                note.append("cc=log_degree")
            out.append([
                exp, backend, fam, cfg, f"{pred:.1f}", str(cc), f"{ms:.3f}",
                f"{ratio:.3f}" if not math.isnan(ratio) else "nan",
                "true" if within else "false", ";".join(note) if note else "ok",
            ])
            if testable:
                n_total += 1
                if within:
                    n_within += 1

    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, "e10_costmodel.csv")
    with open(path, "w", newline="") as f:
        csv.writer(f).writerows(out)
    frac = (100.0 * n_within / n_total) if n_total else 0.0
    print(f"E10 cost-model validation → {path}")
    print(f"  configs within 1.5x of the fitted cost model (>=3-point groups): "
          f"{n_within}/{n_total} ({frac:.0f}%)")
    print("  (model: prove_ms ≈ c_lin + k·predicted, affine fit per group; "
          "validated against prove_total_ms — plonky3's constraint_count is summed "
          "FRI log-degrees, see header.)")


if __name__ == "__main__":
    main()
