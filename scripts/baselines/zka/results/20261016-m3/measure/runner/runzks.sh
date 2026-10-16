#!/usr/bin/env bash
# runzks.sh <label> <m> <T> <gk_cap> <rounds stable|sorted>
# M3 measurer: one six/run_zks.sh gk call (forest, procs, 1 machine x 32 cores, AOL, a query after every leaf,
# ZK default build = scalar, M0 defaults: no M0 switch set) under memsample.py (VmRSS of the whole tree every
# 0.1 s), rooted at run_zks.sh. Adapted from 20261015-m1/measure/runner/runzks.sh (adds SIX_GK_ROUNDS).
# ZKS_BIN is a wrapper adding EXP_ROOT_VK_SAVE (run_zks.sh drops other EXP_*) and exec'ing the real binary.
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
LBL=$1; M=$2; T=$3; CAP=$4; ROUNDS=$5
. "$R/env.sh"
unset EXP_FOREST_RETAIN_PREP EXP_MALLOC_TRIM EXP_EXIT_BEFORE_AUDIT EXP_MERGE_CACHE EXP_MERGE_CACHE_ENTRIES
REAL=$HOME/zkSketch/target/release/examples/exp_compose
D=$S/runs/$LBL
[[ -e $D ]] && { echo "exists: $D"; exit 2; }
mkdir -p "$D"
printf '#!/bin/sh\nexport EXP_ROOT_VK_SAVE=%s/root_vk.bin\nexec %s "$@"\n' "$D" "$REAL" > "$D/zks_bin.sh"; chmod +x "$D/zks_bin.sh"
{
  echo "label=$LBL tag=gk m=$M T=$T cap=$CAP rounds=$ROUNDS build=scalar"
  echo "start=$(date -Is) load=\"$(cut -d' ' -f1-3 /proc/loadavg)\" memavail_gib=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo)"
  echo "head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) real_bin=$REAL real_bin_md5=$(md5sum < $REAL | cut -c1-12) wrapper_md5=$(md5sum < $D/zks_bin.sh | cut -c1-12)"
  env | grep -E '^EXP_(FOREST_RETAIN_PREP|MALLOC_TRIM|EXIT_BEFORE_AUDIT|MERGE_CACHE)' | sort | tr '\n' ' '; echo
} > "$D/meta.txt"
RESULTS=$D/out SIX_M=$M SIX_T=$T SIX_GK_CAP=$CAP SIX_GK_ROUNDS=$ROUNDS GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 ZKS_BIN=$D/zks_bin.sh ZKS_FEATURES=default \
  scripts/baselines/zka/six/run_zks.sh gk > "$D/run_zks.stderr" 2>&1 &
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
