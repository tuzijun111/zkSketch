#!/usr/bin/env bash
# iso.sh: the packed leaf in isolation (sandbox clone, sequential, cores 0-31, 30 s apart):
# table_probe of the leaf (exp_e0, exp_bloom_packed shapes) and of the decoder (printed by B1_KIND=all),
# leaf + query prove/verify (B1_KIND=all, 3 reps), and two merges (B1_KIND=merge, one merge per call).
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"; O=$S/iso
. "$R/env.sh"
mkdir -p "$O"
BIN=target/release/examples/exp_bloom_packed; E0=target/release/examples/exp_e0
{
  echo "head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) rustc=$(rustc --version)"
  echo "exp_bloom_packed md5=$(md5sum < $BIN | cut -c1-12) exp_e0 md5=$(md5sum < $E0 | cut -c1-12)"
  echo "host=$(hostname) start=$(date -Is)"
} > "$O/env.txt"
run() {  # run <name> <bin> <env...>
  local name=$1 bin=$2; shift 2
  sleep 30
  echo "== $name $(date -Is) load=$(cut -d' ' -f1-3 /proc/loadavg)" | tee -a "$O/index.txt"
  env "$@" timeout 590 /usr/bin/time -v taskset -c 0-31 "$bin" > "$O/$name.log" 2> "$O/$name.time"
  echo "   rc=$? end=$(date -Is) load=$(cut -d' ' -f1-3 /proc/loadavg) maxrss_kb=$(sed -n 's/.*Maximum resident set size (kbytes): //p' "$O/$name.time") wall=$(sed -n 's/.*Elapsed (wall clock) time (h:mm:ss or m:ss): //p' "$O/$name.time")" | tee -a "$O/index.txt"
}
n_t=$( [[ -f results/e0_tables.csv ]] && wc -l < results/e0_tables.csv || echo 0 )
n_s=$( [[ -f results/e0_summary.csv ]] && wc -l < results/e0_summary.csv || echo 0 )
run e0_packed       $E0  E0_FAMILY=bloom_packed E0_M=768,960,1024
{ head -1 results/e0_tables.csv; tail -n +$((n_t + 1)) results/e0_tables.csv | grep -v '^commit,'; } > "$O/e0_tables.csv"
{ head -1 results/e0_summary.csv; tail -n +$((n_s + 1)) results/e0_summary.csv | grep -v '^commit,'; } > "$O/e0_summary.csv"
run shapes_hiding   $BIN B1_KIND=shapes B1_M=768,960,1024
run leaf_query_1024 $BIN B1_KIND=all B1_M=1024 B1_REPS=3
run merge_1024_a    $BIN B1_KIND=merge B1_M=1024
run merge_1024_b    $BIN B1_KIND=merge B1_M=1024
echo "done $(date -Is)" | tee -a "$O/index.txt"
