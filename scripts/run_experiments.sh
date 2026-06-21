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
#   EXP_DATASET=aol scripts/run_experiments.sh e1
#   BACKENDS=plonky2 scripts/run_experiments.sh e2
#
# Config (env, forwarded to both runners):
#   EXP_DATASET  uniform|gaussian|zipf|aol|netflix     (default uniform)
#   EXP_M        E1: comma-separated batch sizes (default 4,8,16,32)
#                E2: single batch size (default 16)
#   EXP_TRIALS   E1 measured trials (median/p95)        (default 5)
#   EXP_WARMUP   E1 warm-up runs                         (default 1)
#   EXP_TAMPER_TRIALS  E2 tamper trials                  (default 50)
#   BACKENDS     plonky3|plonky2|both                    (default both)
#
# Partial vs whole dataset: each runner consumes a small key slice (testing
# default). Fetch more (`python3 scripts/fetch_datasets.py`, raise *_MAX_KEYS)
# and raise EXP_M for larger runs. See docs/REPRODUCE.md.
set -euo pipefail
cd "$(dirname "$0")/.."

EXPERIMENT="${1:-e1}"

# E10 is pure post-processing (reads the E1/E3/E4 CSVs, applies the cost model);
# it has no prover runner — dispatch straight to the Python script.
if [[ "$EXPERIMENT" == "e10" ]]; then
  echo "== zkSketch e10 == cost-model validation (reads results/e{1,3,4}*.csv)"
  python3 scripts/cost_model_e10.py
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
  # E3 has no plonky3 runner yet (decode AIR is future work) → plonky2 only.
  e3) CSV="e3_decode.csv";    P3_EX="";        P2_EX="e3_decode";       BACKENDS="plonky2"; export EXP_M="${EXP_M:-16}" ;;
  # E4 scaling sweeps (certified CM) → plonky3 only.
  e4) CSV="e4_scaling.csv";   P3_EX="exp_e4";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # E5/E6 are the composition story (§4 framework) → plonky3 only.
  e5) CSV="e5_ladder.csv";    P3_EX="exp_e5";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  e6) CSV="e6_forest.csv";    P3_EX="exp_e6";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # E7 policy simulation → plonky3 only (leaf-shape-agnostic).
  e7) CSV="e7_policy.csv";    P3_EX="exp_e7";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # E8 cross-stack head-to-head → BOTH backends (the whole point).
  e8) CSV="e8_crossstack.csv"; P3_EX="exp_e8"; P2_EX="e8_crossstack"; export EXP_M="${EXP_M:-n/a}" ;;
  # E9 optimisation ablations → plonky3 only.
  e9) CSV="e9_optim.csv";     P3_EX="exp_e9";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # Input-commitment + history-fold over real batches → plonky3 only.
  inputfold) CSV="input_fold.csv"; P3_EX="exp_inputfold"; P2_EX=""; BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  *) echo "unknown experiment '$EXPERIMENT' (supported: e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, inputfold)"; exit 1 ;;
esac
if [[ -z "$P3_EX" && ( "$BACKENDS" == "plonky3" || "$BACKENDS" == "both" ) ]]; then
  echo "note: $EXPERIMENT has no plonky3 runner; forcing BACKENDS=plonky2"
  BACKENDS="plonky2"
fi

echo "== zkSketch $EXPERIMENT == dataset=$EXP_DATASET m=$EXP_M backends=$BACKENDS"
mkdir -p results
rm -f "results/$CSV" "plonky2/results/$CSV"

if [[ "$BACKENDS" == "plonky3" || "$BACKENDS" == "both" ]]; then
  echo "-- plonky3 (STARK) --"
  cargo run --release --example "$P3_EX"
fi
if [[ "$BACKENDS" == "plonky2" || "$BACKENDS" == "both" ]]; then
  echo "-- plonky2 (SNARK) --"  # plonky2/ pins nightly via rust-toolchain.toml
  ( cd plonky2 && cargo run --release --example "$P2_EX" )
fi

# Merge into one combined results/$CSV.
if [[ "$BACKENDS" == "both" && -f "plonky2/results/$CSV" ]]; then
  if [[ -f "results/$CSV" ]]; then
    tail -n +2 "plonky2/results/$CSV" >> "results/$CSV"
  else
    cp "plonky2/results/$CSV" "results/$CSV"
  fi
elif [[ "$BACKENDS" == "plonky2" ]]; then
  cp -f "plonky2/results/$CSV" "results/$CSV"
fi

echo "combined -> results/$CSV"
[[ -f "results/$CSV" ]] && column -t -s, "results/$CSV" | sed -n '1,40p'
echo "env.json: results/env.json (plonky3), plonky2/results/env.json (plonky2)"
