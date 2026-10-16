#!/usr/bin/env bash
# run1.sh <label> <tag bloom|bloom_absent> <variant omc|packed> <m> <T>
# One run_zks.sh call (forest, procs, 1 machine x 32 cores, AOL, a query after every leaf, ZK default build,
# M0 defaults = every M0 switch unset) under memsample.py (VmRSS of the whole process tree every 0.1 s),
# rooted at run_zks.sh.
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
LBL=$1; TAG=$2; VAR=$3; M=$4; T=$5
. "$R/env.sh"
unset EXP_FOREST_RETAIN_PREP EXP_MALLOC_TRIM EXP_EXIT_BEFORE_AUDIT EXP_MERGE_CACHE EXP_MERGE_CACHE_ENTRIES
D=$S/runs/$LBL
[[ -e $D ]] && { echo "exists: $D"; exit 2; }
mkdir -p "$D"
{
  echo "label=$LBL tag=$TAG variant=$VAR m=$M T=$T"
  echo "start=$(date -Is) load=\"$(cut -d' ' -f1-3 /proc/loadavg)\" memavail_gib=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo)"
  echo "head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) bin_md5=$(md5sum < target/release/examples/exp_compose | cut -c1-12)"
} > "$D/meta.txt"
RESULTS=$D/out SIX_M=$M SIX_T=$T SIX_BLOOM_VARIANT=$VAR GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 \
  scripts/baselines/zka/six/run_zks.sh "$TAG" > "$D/run_zks.stderr" 2>&1 &
PID=$!
python3 -I -c "import runpy,sys,time; sys.argv=['memsample.py','$PID','$D/mem.csv','0.1']; print(f'MEMSAMPLE_T0_UNIX={time.time():.3f}', flush=True); runpy.run_path('$R/memsample.py', run_name='__main__')" > "$D/memsum.txt" 2>&1 &
SP=$!
wait $PID; RC=$?
wait $SP
echo "end=$(date -Is) rc=$RC load=\"$(cut -d' ' -f1-3 /proc/loadavg)\"" >> "$D/meta.txt"
echo "rc=$RC"; cut -c1-200 "$D/memsum.txt"
