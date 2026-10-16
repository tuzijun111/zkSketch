#!/usr/bin/env bash
# M2 gate measurements in the sandbox clone (fresh toolchains). Sequential, cores 0-31.
set -u
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m2/sbenv.sh
OUT=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m2/sb
mkdir -p "$OUT"
cd "$HOME/zkSketch"
BIN=target/release/examples/exp_bloom_packed
E0=target/release/examples/exp_e0
{
  echo "commit=$(git rev-parse --short HEAD) dirty=$(git status --porcelain | wc -l) rustc=$(rustc --version)"
  echo "exp_bloom_packed md5=$(md5sum < $BIN | cut -c1-12) exp_e0 md5=$(md5sum < $E0 | cut -c1-12)"
  echo "host=$(hostname) start=$(date -Is)"
} > "$OUT/env.txt"
run() {  # run <name> <env...>
  local name=$1; shift
  echo "== $name $(date -Is) load=$(cut -d' ' -f1-3 /proc/loadavg)" | tee -a "$OUT/index.txt"
  env "$@" timeout 590 taskset -c 0-31 "$BIN" > "$OUT/$name.log" 2>&1
  echo "   rc=$? end=$(date -Is) load=$(cut -d' ' -f1-3 /proc/loadavg)" | tee -a "$OUT/index.txt"
}
run shapes_hiding     B1_KIND=shapes B1_M=256,960,1024,2048
run shapes_plain      B1_KIND=shapes B1_M=256,960,1024,2048 B1_MODE=plain
run small_all_hiding  B1_KIND=all B1_K=3 B1_LOGW=7 B1_M=8 B1_PRIOR=20 B1_REPS=2
run small_all_plain   B1_KIND=all B1_K=3 B1_LOGW=7 B1_M=8 B1_PRIOR=20 B1_REPS=2 B1_MODE=plain
run leaf_query_hiding B1_KIND=all B1_M=1024 B1_REPS=2
run leaf_query_plain  B1_KIND=all B1_M=1024 B1_REPS=2 B1_MODE=plain
run merge_hiding      B1_KIND=merge B1_M=1024
run merge_plain       B1_KIND=merge B1_M=1024 B1_MODE=plain
# E-0 static probe rows (results/e0_*.csv), packed and, for reference, omc at m = 1,024.
echo "== e0 $(date -Is)" | tee -a "$OUT/index.txt"
# Append-only: keep the sandbox's earlier rows; copy out only this run's rows (with the header).
n_t=$( [[ -f results/e0_tables.csv ]] && wc -l < results/e0_tables.csv || echo 0 )
n_s=$( [[ -f results/e0_summary.csv ]] && wc -l < results/e0_summary.csv || echo 0 )
E0_FAMILY=bloom_packed E0_M=256,960,1024,2048 timeout 590 taskset -c 0-31 "$E0" > "$OUT/e0_packed.log" 2>&1; echo "   rc=$?" | tee -a "$OUT/index.txt"
E0_FAMILY=bloom E0_M=256,1024 timeout 590 taskset -c 0-31 "$E0" > "$OUT/e0_omc.log" 2>&1; echo "   rc=$?" | tee -a "$OUT/index.txt"
{ head -1 results/e0_tables.csv; tail -n +$((n_t + 1)) results/e0_tables.csv | grep -v '^commit,'; } > "$OUT/e0_tables.csv"
{ head -1 results/e0_summary.csv; tail -n +$((n_s + 1)) results/e0_summary.csv | grep -v '^commit,'; } > "$OUT/e0_summary.csv"
echo "done $(date -Is)" | tee -a "$OUT/index.txt"
