#!/usr/bin/env bash
# usage: zka_exec.sh <M>: zk-Analytics executor only (no proof), 1 epoch of M AOL records, all six
# families, noroot (+ designed, SIX_ZKA_CM_REF=1 default) -> memmatch-20261014/zka-m<M>
. "$(cd "$(dirname "$0")" && pwd)/env.sh"   # the runner directory (a session scratch dir when run)
M=$1; D=/home/binbin/zkSketch/results/six/memmatch-20261014/zka-m$M
mkdir -p "$D"
echo "start $(date -Is) M=$M dir=$D load=\"$(cut -d' ' -f1-3 /proc/loadavg)\" memavail_gib=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo)"
RESULTS=$D SIX_M=$M SIX_T=1 GATE_WAIT_S=0 SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=1 scripts/baselines/zka/six/run_zka.sh exec
rc=$?
echo "end $(date -Is) rc=$rc"
exit $rc
