#!/usr/bin/env bash
# probe.sh <outdir>: exp_e0 table_probe (static trace heights, nothing proved) of the GK leaf, both round
# variants, at cap 768 (m 512 = config B, m 1024) and cap 384 (m 128), plus one honest ZK no-op prove
# (E0_PROVE=1: degree_bits == log_h + is_zk check) of the stable leaf at config B and at cap 384 m 128,
# on cores 0-31 under /usr/bin/time -v. results/e0_*.csv are copied out after each call.
R="$(cd "$(dirname "$0")" && pwd)"
. "$R/env.sh"
O=$1; mkdir -p "$O"
B=target/release/examples/exp_e0
echo "# probe $(date -Is) head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) exp_e0 md5=$(md5sum < $B | cut -c1-12) load=[$(cut -d' ' -f1-3 /proc/loadavg)]" > "$O/status.txt"
for v in stable sorted; do
  for cfg in "768 512" "768 1024" "384 128"; do
    set -- $cfg
    EXP_GK_ROUNDS=$v E0_FAMILY=gk EXP_GK_CAP=$1 EXP_GK_S=51 E0_M=$2 timeout 600 $B > "$O/probe_${v}_c$1_m$2.log" 2>&1
    echo "probe $v cap $1 m $2 exit $?" >> "$O/status.txt"
    cp results/e0_tables.csv "$O/e0_tables_${v}_c$1_m$2.csv"; cp results/e0_summary.csv "$O/e0_summary_${v}_c$1_m$2.csv"
  done
done
for run in "stable 768 512" "stable 384 128"; do
  set -- $run
  echo "prove $1 cap $2 m $3 start $(date -Is) load=[$(cut -d' ' -f1-3 /proc/loadavg)]" >> "$O/status.txt"
  EXP_GK_ROUNDS=$1 E0_PROVE=1 E0_FAMILY=gk EXP_GK_CAP=$2 EXP_GK_S=51 E0_M=$3 /usr/bin/time -v taskset -c 0-31 timeout 600 $B > "$O/prove_$1_c$2_m$3.log" 2>&1
  echo "prove $1 cap $2 m $3 exit $? end $(date -Is) load=[$(cut -d' ' -f1-3 /proc/loadavg)]" >> "$O/status.txt"
done
echo DONE >> "$O/status.txt"
