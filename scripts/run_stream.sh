#!/usr/bin/env bash
# Whole-stream prove time of Count-Min leaves plus their fold (exp_stream), over batch size and concurrent leaf proofs.
# The default fold (EXP_STREAM_MERGE=digest) combines commitment digests and makes no recursive proof; EXP_* in docs/experiments.md.
# Usage: [EXP_STREAM_N=2^16 EXP_STREAM_BATCHES=64,256,1024 EXP_STREAM_CORES=16,32,64 EXP_STREAM_MERGE=digest] scripts/run_stream.sh [out.csv]
set -euo pipefail
cd "$(dirname "$0")/.."

# Caller-chosen output filename (env EXP_OUT preferred; positional $1 accepted).
OUT_CSV="${EXP_OUT:-${1:-}}"
CSV="stream_forest.csv"

echo "== zkSketch stream-forest == N=${EXP_STREAM_N:-65536} dataset=${EXP_DATASET:-uniform} d=${EXP_D:-4} w=${EXP_W:-8} batches=${EXP_STREAM_BATCHES:-64,256,1024} cores=${EXP_STREAM_CORES:-1,2,4,8,16,32,64} variants=${EXP_CM_VARIANT:-${EXP_STREAM_CM_VARIANT:-omc,merkle}} merge=${EXP_STREAM_MERGE:-digest} commit=plain (single run)"
mkdir -p results
rm -f "results/$CSV"

echo "-- plonky3 (STARK) --"
cargo run --release --example exp_stream

# Rename the output to the caller-chosen name, so successive runs under
# different settings accumulate distinct files.
FINAL_CSV="$CSV"
if [[ -n "$OUT_CSV" && -f "results/$CSV" ]]; then
  FINAL_CSV="${OUT_CSV%.csv}.csv"
  if [[ "$FINAL_CSV" != "$CSV" ]]; then
    mkdir -p "$(dirname "results/$FINAL_CSV")"
    mv -f "results/$CSV" "results/$FINAL_CSV"
  fi
fi

echo "results -> results/$FINAL_CSV"
# Cap the pretty-print so a full sweep doesn't flood the terminal (rows beyond
# the first 200 are still in the CSV).
if [[ -f "results/$FINAL_CSV" ]]; then
  if command -v column >/dev/null; then column -t -s, "results/$FINAL_CSV"; else cat "results/$FINAL_CSV"; fi | sed -n '1,200p'
  rows=$(($(wc -l < "results/$FINAL_CSV") - 1))
  [[ "$rows" -gt 200 ]] && echo "… ($rows data rows total; see results/$FINAL_CSV)"
fi
echo "env.json: results/env.json"
