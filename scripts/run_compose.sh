#!/usr/bin/env bash
# Prove a stream with per-batch, chain or forest composition (exp_compose); EXP_* settings in docs/experiments.md.
# Usage: [EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest ...] scripts/run_compose.sh [out.csv]
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_CSV="${EXP_OUT:-${1:-}}"
BACKEND="${EXP_COMPOSE_BACKEND:-plonky3}"
mkdir -p results

echo "== zkSketch stream-compose == backend=$BACKEND N=${EXP_COMPOSE_N:-32} dataset=${EXP_DATASET:-uniform} families=${EXP_COMPOSE_FAMILY:-cm,hll,ss,gk} modes=${EXP_COMPOSE_MODE:-per_batch,chain,forest} m=${EXP_COMPOSE_BATCHES:-8} cores=${EXP_COMPOSE_CORES:-all} machines=${EXP_COMPOSE_MACHINES:-1} commit=${ZKSKETCH_COMMIT:-default}"

case "$BACKEND" in
  plonky3|p3|stark)
    echo "-- plonky3 (STARK) --"
    # EXP_OUT is consumed by the example itself for the rename; pass it through.
    NAME="${OUT_CSV:-stream_compose}"; NAME="${NAME%.csv}"
    EXP_OUT="$NAME" cargo run --release --example exp_compose
    FINAL_CSV="results/${NAME}.csv"
    ENV_JSON="results/env.json"
    ;;
  plonky2|p2|snark)
    echo "-- plonky2 (SNARK) --  (dataset=${EXP_DATASET:-uniform}; single-value CORES/MACHINES; nightly via plonky2/rust-toolchain.toml)"
    echo "   note: plonky2 proofs are zero-knowledge under the default zk feature, like the plonky3 rows (recorded as zero_knowledge in plonky2/results/env.json)"
    NAME="${OUT_CSV:-stream_compose_p2}"; NAME="${NAME%.csv}"
    # plonky2/ is a self-contained crate; run its example there and surface the
    # CSV in the shared results/ dir so both backends land side by side.
    ( cd plonky2 && EXP_OUT="$NAME" cargo run --release --example exp_compose )
    [[ -f "plonky2/results/${NAME}.csv" ]] && cp -f "plonky2/results/${NAME}.csv" "results/${NAME}.csv"
    FINAL_CSV="results/${NAME}.csv"
    ENV_JSON="plonky2/results/env.json"
    ;;
  *)
    echo "error: unknown EXP_COMPOSE_BACKEND='$BACKEND' (use plonky3|plonky2)" >&2
    exit 2
    ;;
esac

if [[ -f "$FINAL_CSV" ]]; then
  echo "results -> $FINAL_CSV"
  if command -v column >/dev/null; then column -t -s, "$FINAL_CSV"; else cat "$FINAL_CSV"; fi | sed -n '1,200p'
fi
echo "env.json: $ENV_JSON"
