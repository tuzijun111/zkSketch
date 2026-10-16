#!/usr/bin/env bash
# usage: zka_prove.sh <M> <jobs...>: run_zka.sh prove for this shape (noroot), after letting the 1-min load
# fall to <= 8 (up to 300 s; our own previous zkSketch run's load average) so the gate reads the box itself
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/env.sh
M=$1; shift
export RESULTS=/home/binbin/zkSketch/results/six/batchscale-20261013/m$M
export SIX_M=$M SIX_T=2 SIX_GK_CAP=2048 GATE_WAIT_S=0 SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=0 EXP_VERIFY_REPEATS=5
t0=$SECONDS
while (( SECONDS - t0 < 300 )) && ! awk -v l="$(cut -d' ' -f1 /proc/loadavg)" 'BEGIN{exit !(l <= 8)}'; do sleep 10; done
echo "### $(date -Is) pre-wait $((SECONDS - t0)) s, load $(cut -d' ' -f1-3 /proc/loadavg), MemAvailable $(awk '/MemAvailable/{printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
echo "### cmd: RESULTS=$RESULTS SIX_M=$SIX_M SIX_T=$SIX_T GATE_WAIT_S=0 SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=0 scripts/baselines/zka/six/run_zka.sh prove $*"
T1=$SECONDS
scripts/baselines/zka/six/run_zka.sh prove "$@"; rc=$?
echo "step rc=$rc seconds=$((SECONDS - T1)) scripts/baselines/zka/six/run_zka.sh prove $*" >> "$RESULTS/manifest.txt"
echo "### $(date -Is) rc=$rc"
exit $rc
