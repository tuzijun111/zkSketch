#!/usr/bin/env bash
# usage: zks.sh <tag> <m_leaf> <T> [gk_cap] [suffix]
# one run_zks.sh call (T batches of m_leaf AOL records, forest, procs, 32 cores, ZK default build)
# into /home/binbin/zkSketch/results/six/memmatch-20261014/<tag>-m<m>[-cap<c>][-t<T> if T!=2][suffix]
. "$(cd "$(dirname "$0")" && pwd)/env.sh"   # the runner directory (a session scratch dir when run)
TAG=$1; M=$2; T=$3; CAP=${4:-2048}; SUF=${5:-}
D=/home/binbin/zkSketch/results/six/memmatch-20261014/$TAG-m$M
[[ $TAG == gk ]] && D+=-cap$CAP
[[ $T != 2 ]] && D+=-t$T
D+=$SUF
mkdir -p "$D"
echo "start $(date -Is) tag=$TAG m=$M T=$T cap=$CAP dir=$D load=\"$(cut -d' ' -f1-3 /proc/loadavg)\" memavail_gib=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo)"
RESULTS=$D SIX_M=$M SIX_T=$T SIX_GK_CAP=$CAP GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 \
  scripts/baselines/zka/six/run_zks.sh "$TAG"
rc=$?
echo "end $(date -Is) rc=$rc"
grep '^RSSTREE' "$D"/six_zksketch_$TAG.log
exit $rc
