#!/usr/bin/env bash
set -u
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m2/sbenv.sh
OUT=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m2/sb
cd "$HOME/zkSketch"
mkdir -p "$OUT/proofs_T2"
echo "compose start $(date -Is) load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/index.txt"
env EXP_COMPOSE_FAMILY=bloom EXP_BLOOM_VARIANT=packed EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_DATASET=aol \
  EXP_COMPOSE_N=2048 EXP_COMPOSE_BATCHES=1024 EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=procs \
  EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_QUERY_EVERY=1 EXP_QUERY_LOG=1 \
  EXP_OUT=m2gate_packed_T2 EXP_COMPOSE_PROOF_DIR="$OUT/proofs_T2" \
  timeout 590 target/release/examples/exp_compose > "$OUT/compose_T2.log" 2>&1 &
PID=$!
python3 -I /home/binbin/zkSketch/latex/redesign_20261014/profile/memsample.py $PID "$OUT/compose_T2_mem.csv" 0.1 > "$OUT/compose_T2_mem.txt" 2>&1
wait $PID; rc=$?
echo "compose rc=$rc end=$(date -Is) load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/index.txt"
cp results/m2gate_packed_T2.csv "$OUT/" 2>/dev/null
rm -rf "$OUT/proofs_T2"
