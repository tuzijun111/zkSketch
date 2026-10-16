#!/usr/bin/env bash
# usage: zks.sh <M> <tags...>   -> runs run_zks.sh for that shape into the batchscale dir
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/env.sh
M=$1; shift
export RESULTS=/home/binbin/zkSketch/results/six/batchscale-20261013/m$M
export SIX_M=$M SIX_T=2 SIX_GK_CAP=2048 GATE_WAIT_S=0 SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=0 EXP_VERIFY_REPEATS=5
echo "### $(date -Is) cmd: RESULTS=$RESULTS SIX_M=$SIX_M SIX_T=$SIX_T SIX_GK_CAP=$SIX_GK_CAP GATE_WAIT_S=$GATE_WAIT_S SIX_ZKA_ROOTS=$SIX_ZKA_ROOTS SIX_ZKA_CM_REF=$SIX_ZKA_CM_REF EXP_VERIFY_REPEATS=$EXP_VERIFY_REPEATS scripts/baselines/zka/six/run_zks.sh $*"
echo "### MemAvailable $(awk '/MemAvailable/{printf "%.1f GiB", $2/1048576}' /proc/meminfo) load $(cut -d' ' -f1-3 /proc/loadavg)"
scripts/baselines/zka/six/run_zks.sh "$@"
rc=$?
echo "### $(date -Is) rc=$rc"
exit $rc
