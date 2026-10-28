#!/bin/bash
# A1: executor cycle counts of zk-Analytics' CM guest at CM_TOPK_SLOTS = 100, 8 and 1.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"   # PATH RESULTS build_cyc cyc_target
OUT=$RESULTS/a1_cycles.csv
mkdir -p $(dirname $OUT)
echo "topk_slots,n,keys,chunk_batch,total_cycles,cycles_per_record,exec_s" > $OUT
for slots in 100 8 1; do
  echo "### building CM_TOPK_SLOTS=$slots" >&2
  build_cyc $slots >&2 2>&1 || { echo "BUILD FAILED slots=$slots" >&2; continue; }
  for k in 256 1024 4096 16384; do
    L=$($(cyc_target $slots)/release/cyc 16384 $k 8 2>/dev/null)
    echo "$L" >&2
    TC=$(echo "$L" | grep -o 'total_cycles=[0-9]*' | cut -d= -f2)
    CPR=$(echo "$L" | grep -o 'cycles_per_record=[0-9.]*' | cut -d= -f2)
    ES=$(echo "$L" | grep -o 'exec_s=[0-9.]*' | cut -d= -f2)
    echo "$slots,16384,$k,8,$TC,$CPR,$ES" >> $OUT
  done
done
echo "A1 DONE" >&2
cat $OUT >&2
