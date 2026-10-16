#!/usr/bin/env bash
# runab.sh <label> <tag gk|bloom> <m> <T> <gk_cap> <A|B> [VAR=val ...]  (extra switch overrides, diagnostics only)
# One run_zks.sh call (forest, procs, 1 machine x 32 cores, AOL, query every batch, ZK default build)
# under memsample.py (VmRSS of the whole process tree, every 0.1 s), rooted at run_zks.sh.
# A = pre-M0 behaviour (all four switches OFF); B = M0 defaults (switches unset = ON).
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
LBL=$1; TAG=$2; M=$3; T=$4; CAP=$5; AB=$6
. "$R/env.sh"
unset EXP_FOREST_RETAIN_PREP EXP_MALLOC_TRIM EXP_EXIT_BEFORE_AUDIT EXP_MERGE_CACHE EXP_MERGE_CACHE_ENTRIES
case $AB in
  A) export EXP_FOREST_RETAIN_PREP=1 EXP_MALLOC_TRIM=0 EXP_EXIT_BEFORE_AUDIT=0 EXP_MERGE_CACHE=0 ;;
  B) ;;
  *) echo "AB must be A or B"; exit 2 ;;
esac
shift 6
for kv in "$@"; do export "$kv"; done
D=$S/runs/$LBL
[[ -e $D ]] && { echo "exists: $D"; exit 2; }
mkdir -p "$D"
{
  echo "label=$LBL tag=$TAG m=$M T=$T cap=$CAP ab=$AB"
  echo "start=$(date -Is) load=\"$(cut -d' ' -f1-3 /proc/loadavg)\" memavail_gib=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo)"
  echo "head=$(git rev-parse --short=9 HEAD) bin_md5=$(md5sum < target/release/examples/exp_compose | cut -c1-12)"
  env | grep -E '^EXP_(FOREST_RETAIN_PREP|MALLOC_TRIM|EXIT_BEFORE_AUDIT|MERGE_CACHE)' | sort | tr '\n' ' '; echo
} > "$D/meta.txt"
RESULTS=$D/out SIX_M=$M SIX_T=$T SIX_GK_CAP=$CAP GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 \
  scripts/baselines/zka/six/run_zks.sh "$TAG" > "$D/run_zks.stderr" 2>&1 &
PID=$!
python3 -I -c "import runpy,sys,time; sys.argv=['memsample.py','$PID','$D/mem.csv','0.1']; print(f'MEMSAMPLE_T0_UNIX={time.time():.3f}', flush=True); runpy.run_path('$R/memsample.py', run_name='__main__')" > "$D/memsum.txt" 2>&1 &
SP=$!
wait $PID; RC=$?
wait $SP
{
  echo "end=$(date -Is) rc=$RC load=\"$(cut -d' ' -f1-3 /proc/loadavg)\""
} >> "$D/meta.txt"
echo "rc=$RC"; cat "$D/memsum.txt"
