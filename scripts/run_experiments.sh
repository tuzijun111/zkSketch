#!/usr/bin/env bash
# Run e1, e2, e5 or e8 on plonky3 and/or plonky2 and merge the rows into one CSV in results/ (EXP_* in docs/experiments.md).
# Usage: [BACKENDS=both|plonky3|plonky2] scripts/run_experiments.sh [e1|e2|e5|e8] [out.csv]
set -euo pipefail
cd "$(dirname "$0")/.."

EXPERIMENT="${1:-e1}"
# Caller-chosen output filename (env EXP_OUT preferred; positional $2 accepted).
OUT_CSV="${EXP_OUT:-${2:-}}"

# Retired modes: print what superseded them + the direct command, then exit.
# The runner sources stay in examples/ (and plonky2/examples/) so the old
# measurements remain reproducible; see docs/experiments.md (Running the experiments).
retired() { # $1 mode, $2 superseded-by, $3 direct command
  echo "'$1' was retired from this driver — superseded by $2."
  echo "Still runnable directly:  $3"
  echo "Details: docs/experiments.md (Running the experiments)"
  exit 2
}
case "$EXPERIMENT" in
  e3)        retired e3 "scripts/run_decode.sh (decode circuits of the DEPLOYED variants; the old runner benches non-deployed ones)" \
                     "cargo run --release --example exp_e3   # plonky2 leg: (cd plonky2 && cargo run --release --example e3_decode)" ;;
  e4)        retired e4 "the e1 sweeps (EXP_M/EXP_W axes) + run_stream.sh (stream-length axis); the distinct-bound axis (e4b) is obsolete since the per-record CM refactor" \
                     "cargo run --release --example exp_e4" ;;
  e5real)    retired e5real "run_compose.sh (real recursive chain/forest composition for all four families)" \
                     "cargo run --release --example exp_e5_real" ;;
  e6)        retired e6 "run_stream.sh (whole-stream total time over batch × cores)" \
                     "cargo run --release --example exp_e6" ;;
  e7)        retired e7 "run_compose.sh with EXP_COMPOSE_QUERY_EVERY (real mixed updates+queries instead of the structural policy sim)" \
                     "cargo run --release --example exp_e7" ;;
  e9)        retired e9 "nothing directly — the ss_single_round ablation's premise is gone (GK is single-pass now) and the rest are analytical rows" \
                     "cargo run --release --example exp_e9" ;;
  e10)       retired e10 "nothing — it post-processed the retired e3/e4 CSVs and its variant filter predates the current e1 schema" \
                     "python3 scripts/cost_model_e10.py" ;;
  inputfold) retired inputfold "run_compose.sh (every compose leaf binds Com(B_t) in-circuit; the fold is a real recursive proof) + the lib test inputfold::real_batch_commitments_bind_and_fold_into_root" \
                     "cargo run --release --example exp_inputfold" ;;
  casestudy) retired casestudy "run_compose.sh on the real datasets (EXP_DATASET=aol|netflix): real recursive composition + mixed queries across all four families" \
                     "cargo run --release --example exp_casestudy" ;;
esac

EXP_DATASET="${EXP_DATASET:-uniform}"
EXP_TRIALS="${EXP_TRIALS:-5}"
EXP_WARMUP="${EXP_WARMUP:-1}"
EXP_TAMPER_TRIALS="${EXP_TAMPER_TRIALS:-50}"
BACKENDS="${BACKENDS:-both}"
export EXP_DATASET EXP_TRIALS EXP_WARMUP EXP_TAMPER_TRIALS

case "$EXPERIMENT" in
  e1) CSV="e1_circuit.csv";   P3_EX="exp_e1";  P2_EX="e1_metrics_demo"; export EXP_M="${EXP_M:-4,8,16,32}" ;;
  e2) CSV="e2_integrity.csv"; P3_EX="exp_e2";  P2_EX="e2_integrity";    export EXP_M="${EXP_M:-16}" ;;
  # e5 composition-topology ladder (§4 framework, digest lift) → plonky3 only.
  e5) CSV="e5_ladder.csv";    P3_EX="exp_e5";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # e8 cross-stack head-to-head → BOTH backends (the whole point).
  e8) CSV="e8_crossstack.csv"; P3_EX="exp_e8"; P2_EX="e8_crossstack"; export EXP_M="${EXP_M:-n/a}" ;;
  *) echo "unknown experiment '$EXPERIMENT' (supported: e1, e2, e5, e8; retired: e3, e4, e5real, e6, e7, e9, e10, inputfold, casestudy)"; exit 1 ;;
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
  echo "   note: plonky2 proofs are zero-knowledge under the default zk feature, like the plonky3 rows (recorded as zero_knowledge in plonky2/results/env.json)"
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
if [[ -f "results/$FINAL_CSV" ]]; then
  if command -v column >/dev/null; then column -t -s, "results/$FINAL_CSV"; else cat "results/$FINAL_CSV"; fi | sed -n '1,40p'
fi
echo "env.json: results/env.json (plonky3), plonky2/results/env.json (plonky2)"
