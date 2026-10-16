#!/usr/bin/env bash
# runzks.sh <label> <tag gk|bloom> <m> <T> <gk_cap> <scalar|avx2>
# One six/run_zks.sh call (forest, procs, 1 machine x 32 cores, AOL, query every batch, ZK default build,
# M0 defaults: no M0 switch set) under memsample.py (VmRSS of the whole tree, every 0.1 s), rooted at run_zks.sh.
# scalar = $HOME/zkSketch/target/release/examples/exp_compose (no RUSTFLAGS: p3-monty-31 no_packing)
# avx2   = $HOME/target-avx2/release/examples/exp_compose (RUSTFLAGS="-C target-cpu=x86-64-v3")
# ZKS_BIN is a two-line wrapper that adds EXP_ROOT_VK_SAVE (run_zks.sh drops every other EXP_*) and
# exec's the real binary (same PID; the procs worker snapshots /proc/self/exe = the real binary), so every
# measured run also saves the root VK its auditor derived from public parameters.
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
LBL=$1; TAG=$2; M=$3; T=$4; CAP=$5; BUILD=$6
. "$R/env.sh"
unset EXP_FOREST_RETAIN_PREP EXP_MALLOC_TRIM EXP_EXIT_BEFORE_AUDIT EXP_MERGE_CACHE EXP_MERGE_CACHE_ENTRIES
case $BUILD in
  scalar) REAL=$HOME/zkSketch/target/release/examples/exp_compose; FEAT=default ;;
  avx2)   REAL=$HOME/target-avx2/release/examples/exp_compose; FEAT=default+RUSTFLAGS=-Ctarget-cpu=x86-64-v3 ;;
  *) echo "build must be scalar or avx2"; exit 2 ;;
esac
D=$S/runs/$LBL
[[ -e $D ]] && { echo "exists: $D"; exit 2; }
mkdir -p "$D"
printf '#!/bin/sh\nexport EXP_ROOT_VK_SAVE=%s/root_vk.bin\nexec %s "$@"\n' "$D" "$REAL" > "$D/zks_bin.sh"; chmod +x "$D/zks_bin.sh"
{
  echo "label=$LBL tag=$TAG m=$M T=$T cap=$CAP build=$BUILD"
  echo "start=$(date -Is) load=\"$(cut -d' ' -f1-3 /proc/loadavg)\" memavail_gib=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo)"
  echo "head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) real_bin=$REAL real_bin_md5=$(md5sum < $REAL | cut -c1-12) wrapper_md5=$(md5sum < $D/zks_bin.sh | cut -c1-12)"
  env | grep -E '^EXP_(FOREST_RETAIN_PREP|MALLOC_TRIM|EXIT_BEFORE_AUDIT|MERGE_CACHE)' | sort | tr '\n' ' '; echo
} > "$D/meta.txt"
RESULTS=$D/out SIX_M=$M SIX_T=$T SIX_GK_CAP=$CAP GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 ZKS_BIN=$D/zks_bin.sh ZKS_FEATURES=$FEAT \
  scripts/baselines/zka/six/run_zks.sh "$TAG" > "$D/run_zks.stderr" 2>&1 &
PID=$!
( sleep ${RUN_LIMIT_S:-590}; kill -0 $PID 2>/dev/null && { echo "watchdog: run over ${RUN_LIMIT_S:-590} s, stopping it $(date -Is)" >> "$D/meta.txt"; kill -TERM $PID; } ) &
WD=$!
python3 -I -c "import runpy,sys,time; sys.argv=['memsample.py','$PID','$D/mem.csv','0.1']; print(f'MEMSAMPLE_T0_UNIX={time.time():.3f}', flush=True); runpy.run_path('$R/memsample.py', run_name='__main__')" > "$D/memsum.txt" 2>&1 &
SP=$!
wait $PID; RC=$?
wait $SP
kill $WD 2>/dev/null; wait $WD 2>/dev/null
echo "end=$(date -Is) rc=$RC load=\"$(cut -d' ' -f1-3 /proc/loadavg)\"" >> "$D/meta.txt"
echo "rc=$RC vk_md5=$( [[ -s $D/root_vk.bin ]] && md5sum < $D/root_vk.bin | cut -c1-16) vk_bytes=$(stat -c %s $D/root_vk.bin 2>/dev/null)"; head -c 300 "$D/memsum.txt"; echo
