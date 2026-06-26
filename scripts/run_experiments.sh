#!/usr/bin/env bash
# Reproduce the zkSketch evaluation experiments on both backends.
#
# Wired so far: E1 (per-family circuit cost, §1), E2 (integrity: tamper +
# fidelity), and E3 (decode/query cost vs. state size s). Runs the plonky3
# (STARK) and plonky2 (SNARK) runners and merges their rows into one combined
# CSV under results/ (with a `backend` column), plus per-backend env.json.
# E3 is plonky2-only for now (the plonky3 decode AIR is future work), so it
# skips the plonky3 leg automatically.
#
# Usage:
#   scripts/run_experiments.sh            # E1, both backends, small slice
#   scripts/run_experiments.sh e2         # E2 integrity
#   scripts/run_experiments.sh e3         # E3 decode (plonky2 only)
#   scripts/run_experiments.sh casestudy  # AOL/Netflix end-to-end (plonky3)
#   EXP_DATASET=aol scripts/run_experiments.sh e1
#   BACKENDS=plonky2 scripts/run_experiments.sh e2
#
# Config (env, forwarded to both runners):
#   EXP_DATASET  uniform|gaussian|zipf|aol|netflix     (default uniform)
#   EXP_FAMILY   E1: which families — all | comma-list of cm,gk,hll,ss
#                (e.g. EXP_FAMILY=cm runs only Count-Min)   (default all)
#   EXP_D        E1/cm: Count-Min depth d (1..=8)           (default 4)
#   EXP_W        E1/cm: comma-list of widths w (powers of 2, sweeps width)
#                                                            (default 8)
#   EXP_CM_VARIANT  E1/cm: one_hot|merkle|merkle_fast|merkle_gb|memcheck|omc|
#                comma-list (default one_hot). All hash per record and group
#                by counter (no key-grouping); they differ only in the Step-5
#                rebind. one_hot = flat one-hot sparse patch over all d·w cells
#                (Θ(n_ctr·d·w)); merkle = sparse Merkle rebind opening only touched
#                cells (Θ(t_max·d·log w), flat in w); merkle_fast = merkle with a
#                1-perm 2:1 compression climb (the AIR swaps by the bit for free —
#                1.86× at large w); merkle_gb = merkle_fast + the group-by routing
#                replacing the m·t_max·d selector with the O(m·d) group-by (1.86×
#                at large batch m); memcheck = sparse-patch-commit rebind, NO dense
#                d·w / NO Merkle (Θ(batch·d·log(d·w)), flat in w), empty-init only;
#                omc = sound offline-memory-checking M_old⊎W=M_new⊎R against a real
#                prior state (Θ(d·w), dense commit, batch factor below one_hot) — in
#                a hash-STARK (multiset equality only, no LogUp inclusion) this OMC
#                circuit IS the faithful §5 "lookup table" realization (the former
#                separate `lookup` label was a duplicate of `omc` and is removed).
#                (Retired replay/merkle leaves remain in-tree, unwired.)
#   COUNTMIN_MAX_SEL_CELLS  cap on the one_hot circuit's selector budget
#                (batch·d·d·w); raise for big widths (default 16M)
#   --- per-family size knobs (the analog of cm's EXP_D/EXP_W) ---
#   EXP_HLL_B    E1/hll: comma-list of precision b; registers = 2^b (default 4)
#   EXP_HLL_VARIANT  E1/hll: one_hot|merkle|comma-list  (default one_hot)
#   EXP_SS_CAP   E1/ss: comma-list of SpaceSaving capacities s (default 8;
#                rounded up to even ≥2)
#   EXP_GK_CAP   E1/gk: comma-list of Greenwald-Khanna capacities (default 8;
#                rounded up to even ≥2)
#   EXP_M        E1: comma-separated batch sizes (default 4,8,16,32)
#                E2: single batch size (default 16)
#   EXP_CORES    E1 (plonky3): pin the STARK prover to this many cores — the
#                "cores-per-proof" knob for the distributed-setting study (one
#                proof per machine of N cores). Adds a `cores` CSV column. Unset =
#                all cores, no column. plonky3-only (do not combine with the
#                plonky2 leg). e.g. EXP_CORES=8 ... e1   (default: all cores)
#   EXP_TRIALS   E1 measured trials (median/p95)        (default 5)
#   EXP_WARMUP   E1 warm-up runs                         (default 1)
#   EXP_TAMPER_TRIALS  E2 tamper trials                  (default 50)
#   BACKENDS     plonky3|plonky2|both|comma-list         (default both)
#                (e.g. BACKENDS=plonky3,plonky2 == both)
#   EXP_OUT      rename the combined output CSV to results/<EXP_OUT> so runs
#                under different settings don't overwrite each other; the .csv
#                suffix is optional. Also accepted as the positional 2nd arg
#                (`run_experiments.sh e1 cm_circuit_1.csv`). Default: the
#                experiment's standard name (e.g. e1_circuit.csv).
#
# Partial vs whole dataset: each runner consumes a small key slice (testing
# default). Fetch more (`python3 scripts/fetch_datasets.py`, raise *_MAX_KEYS)
# and raise EXP_M for larger runs. See docs/REPRODUCE.md.
set -euo pipefail
cd "$(dirname "$0")/.."

EXPERIMENT="${1:-e1}"
# Caller-chosen output filename (env EXP_OUT preferred; positional $2 accepted).
OUT_CSV="${EXP_OUT:-${2:-}}"

# E10 is pure post-processing (reads the E1/E3/E4 CSVs, applies the cost model);
# it has no prover runner — dispatch straight to the Python script.
if [[ "$EXPERIMENT" == "e10" ]]; then
  echo "== zkSketch e10 == cost-model validation (reads results/e{1,3,4}*.csv)"
  python3 scripts/cost_model_e10.py
  exit $?
fi

# Case study: AOL/Netflix end-to-end ingest + audit + tamper across all four
# families (plonky3). It emits TWO CSVs (ingest + audit), so it bypasses the
# single-CSV merge below and dispatches straight to its runner.
if [[ "$EXPERIMENT" == "casestudy" ]]; then
  echo "== zkSketch casestudy == AOL/Netflix end-to-end ingest + audit (plonky3)"
  echo "   (fetch real datasets first for the AOL/Netflix legs: python3 scripts/fetch_datasets.py)"
  cargo run --release --example exp_casestudy
  echo "results -> results/casestudy_ingest.csv, results/casestudy_audit.csv"
  exit $?
fi

EXP_DATASET="${EXP_DATASET:-uniform}"
EXP_TRIALS="${EXP_TRIALS:-5}"
EXP_WARMUP="${EXP_WARMUP:-1}"
EXP_TAMPER_TRIALS="${EXP_TAMPER_TRIALS:-50}"
BACKENDS="${BACKENDS:-both}"
export EXP_DATASET EXP_TRIALS EXP_WARMUP EXP_TAMPER_TRIALS

case "$EXPERIMENT" in
  e1) CSV="e1_circuit.csv";   P3_EX="exp_e1";  P2_EX="e1_metrics_demo"; export EXP_M="${EXP_M:-4,8,16,32}" ;;
  e2) CSV="e2_integrity.csv"; P3_EX="exp_e2";  P2_EX="e2_integrity";    export EXP_M="${EXP_M:-16}" ;;
  # E3 decode/query cost — now on BOTH backends (plonky3 decode added; CM leg
  # live, SS/HLL/GK landing). plonky2 leg covers all four families.
  e3) CSV="e3_decode.csv";    P3_EX="exp_e3";  P2_EX="e3_decode";       export EXP_M="${EXP_M:-16}" ;;
  # E4 scaling sweeps (certified CM) → plonky3 only.
  e4) CSV="e4_scaling.csv";   P3_EX="exp_e4";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # E5/E6 are the composition story (§4 framework) → plonky3 only.
  e5) CSV="e5_ladder.csv";    P3_EX="exp_e5";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # E5-real: composition ladder with REAL recursive STARK proofs (not digests).
  e5real) CSV="e5_real.csv";  P3_EX="exp_e5_real"; P2_EX=""; BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  e6) CSV="e6_forest.csv";    P3_EX="exp_e6";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # E7 policy simulation → plonky3 only (leaf-shape-agnostic).
  e7) CSV="e7_policy.csv";    P3_EX="exp_e7";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # E8 cross-stack head-to-head → BOTH backends (the whole point).
  e8) CSV="e8_crossstack.csv"; P3_EX="exp_e8"; P2_EX="e8_crossstack"; export EXP_M="${EXP_M:-n/a}" ;;
  # E9 optimisation ablations → plonky3 only.
  e9) CSV="e9_optim.csv";     P3_EX="exp_e9";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # Input-commitment + history-fold over real batches → plonky3 only.
  inputfold) CSV="input_fold.csv"; P3_EX="exp_inputfold"; P2_EX=""; BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  *) echo "unknown experiment '$EXPERIMENT' (supported: e1, e2, e3, e4, e5, e5real, e6, e7, e8, e9, e10, inputfold, casestudy)"; exit 1 ;;
esac
# Normalise BACKENDS into two flags so "both", "plonky3", "plonky2", and
# comma/space lists like "plonky3,plonky2" all work — an unknown value warns
# instead of silently running nothing.
want_p3=0; want_p2=0
for b in ${BACKENDS//,/ }; do
  case "$b" in
    both)             want_p3=1; want_p2=1 ;;
    plonky3|p3|stark) want_p3=1 ;;
    plonky2|p2|snark) want_p2=1 ;;
    *) echo "warning: unknown backend '$b' (use plonky3|plonky2|both)" >&2 ;;
  esac
done
if [[ "$want_p3" == 0 && "$want_p2" == 0 ]]; then
  echo "error: BACKENDS='$BACKENDS' selected no runnable backend (use plonky3|plonky2|both)" >&2
  exit 2
fi
if [[ -z "$P3_EX" && "$want_p3" == 1 ]]; then
  echo "note: $EXPERIMENT has no plonky3 runner; running plonky2 only"
  want_p3=0; want_p2=1
fi
if [[ -z "$P2_EX" && "$want_p2" == 1 ]]; then
  echo "note: $EXPERIMENT has no plonky2 runner; running plonky3 only"
  want_p2=0
fi
# EXP_CORES (E1 cores-per-proof) adds a `cores` column to the plonky3 CSV that the
# plonky2 leg doesn't emit, which would misalign the merge. Enforce plonky3-only.
if [[ -n "${EXP_CORES:-}" && "$want_p2" == 1 && "$EXPERIMENT" == "e1" ]]; then
  echo "note: EXP_CORES is plonky3-only (its 'cores' column would misalign the plonky2 merge); running plonky3 only" >&2
  want_p2=0
fi

sel=""
if [[ "$want_p3" == 1 ]]; then sel+="plonky3 "; fi
if [[ "$want_p2" == 1 ]]; then sel+="plonky2 "; fi
echo "== zkSketch $EXPERIMENT == dataset=$EXP_DATASET m=$EXP_M backends=${sel% }"
mkdir -p results
rm -f "results/$CSV" "plonky2/results/$CSV"

if [[ "$want_p3" == 1 ]]; then
  echo "-- plonky3 (STARK) --"
  cargo run --release --example "$P3_EX"
fi
if [[ "$want_p2" == 1 ]]; then
  echo "-- plonky2 (SNARK) --"  # plonky2/ pins nightly via rust-toolchain.toml
  ( cd plonky2 && cargo run --release --example "$P2_EX" )
fi

# Merge into one combined results/$CSV.
if [[ "$want_p3" == 1 && "$want_p2" == 1 && -f "plonky2/results/$CSV" ]]; then
  if [[ -f "results/$CSV" ]]; then
    tail -n +2 "plonky2/results/$CSV" >> "results/$CSV"
  else
    cp "plonky2/results/$CSV" "results/$CSV"
  fi
elif [[ "$want_p2" == 1 && "$want_p3" == 0 ]]; then
  cp -f "plonky2/results/$CSV" "results/$CSV"
fi

# Rename the combined output to the caller-chosen name (EXP_OUT or positional
# $2), so successive runs under different settings accumulate distinct files.
FINAL_CSV="$CSV"
if [[ -n "$OUT_CSV" && -f "results/$CSV" ]]; then
  FINAL_CSV="${OUT_CSV%.csv}.csv"
  if [[ "$FINAL_CSV" != "$CSV" ]]; then
    mkdir -p "$(dirname "results/$FINAL_CSV")"
    mv -f "results/$CSV" "results/$FINAL_CSV"
  fi
fi

echo "combined -> results/$FINAL_CSV"
[[ -f "results/$FINAL_CSV" ]] && column -t -s, "results/$FINAL_CSV" | sed -n '1,40p'
echo "env.json: results/env.json (plonky3), plonky2/results/env.json (plonky2)"
