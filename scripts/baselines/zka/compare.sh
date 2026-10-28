#!/bin/bash
# Count-Min 3 x 1024 on 16,384-record epochs, zkSketch vs zk-Analytics: prove and verify time, proof size, peak RSS.
# Usage: ./compare.sh   (ZKSKETCH_COMMIT=plain|hiding)
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"   # PATH RESULTS ZKS ZKA BASELINE_DIR build_cyc cyc_target
set -u
R=$RESULTS; mkdir -p $R
ZK=$ZKS
log(){ echo "[$(date +%H:%M:%S)] $*"; }
cleanup_r0vm(){ pkill -9 -u "$(id -u)" -x r0vm 2>/dev/null; sleep 2; }   # OUR r0vm only: shared box
# Refuse, rather than kill, if one of OUR r0vm is already in flight (as q_sweep.sh
# and rss_watch.sh do); the EXIT trap only reaps once that check has passed.
MAY_KILL=0; trap '[[ $MAY_KILL == 1 ]] && cleanup_r0vm' EXIT
if pgrep -x -u "$(id -u)" r0vm >/dev/null 2>&1; then
  echo "REFUSING TO START: an r0vm owned by $(id -un) is already running (none touched)" >&2; exit 3
fi
MAY_KILL=1

log "=== environment ==="
uptime
nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv,noheader
echo

######################## 1. OUR SIDE ########################
# Commitment mode (revision B2), pinned EXPLICITLY rather than inherited from
# exp_compose's library default (hiding): the stored matched rows (and
# zkstream/fit.py, which reads zks_matched_*.csv by name) are PLAIN. Set
# ZKSKETCH_COMMIT=hiding to measure the hiding circuits; those rows go to
# zks_matched_*_hiding.csv, so a file name never hides a mode switch (each row
# also carries exp_compose's `commit` column).
ZKSKETCH_COMMIT=$(printf %s "${ZKSKETCH_COMMIT:-plain}" | tr "[:upper:]" "[:lower:]")
export ZKSKETCH_COMMIT
case "$ZKSKETCH_COMMIT" in
  plain) SUF="" ;;
  hiding) SUF="_hiding" ;;
  *) echo "ZKSKETCH_COMMIT must be plain or hiding (got '$ZKSKETCH_COMMIT')" >&2; exit 2 ;;
esac
log "commit=$ZKSKETCH_COMMIT"
# One batch (t=1): the unit that matches one of their epochs.
log "=== S1 zkSketch, d=3 w=1024, single batch m=2^14 (t=1) ==="
cd $ZK && EXP_COMPOSE_FAMILY=cm EXP_D=3 EXP_W=1024 \
  EXP_COMPOSE_N=16384 EXP_COMPOSE_BATCHES=16384 \
  EXP_COMPOSE_MODE=forest EXP_DATASET=aol EXP_COMPOSE_CORES=32 \
  EXP_OUT=zks_matched_t1$SUF.csv \
  cargo run --release --example exp_compose 2>&1 | tail -20
cp -f $ZK/results/zks_matched_t1$SUF.csv $R/ 2>/dev/null
log "S1 DONE"

# Whole stream (t=64): forest and chain, for the composed-root numbers.
for MODE in forest chain; do
  log "=== S2-$MODE zkSketch, d=3 w=1024, N=2^20, t=64 ==="
  cd $ZK && EXP_COMPOSE_FAMILY=cm EXP_D=3 EXP_W=1024 \
    EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
    EXP_COMPOSE_MODE=$MODE EXP_DATASET=aol EXP_COMPOSE_CORES=32 \
    EXP_OUT=zks_matched_t64_$MODE$SUF.csv \
    cargo run --release --example exp_compose 2>&1 | tail -20
  cp -f $ZK/results/zks_matched_t64_$MODE$SUF.csv $R/ 2>/dev/null
  log "S2-$MODE DONE"
done

######################## 2. THEIR SIDE ########################
# risc0 proves inside a separate `r0vm` process, so the driver's own VmHWM is
# meaningless (~9 MB). Sample r0vm's VmHWM instead and take the max.
sample_r0vm_rss(){
  local out=$1 max=0 v
  : > $out
  while :; do
    for p in $(pgrep -u "$(id -u)" -x r0vm 2>/dev/null); do   # OUR r0vm only
      v=$(awk '/VmHWM/{print $2}' /proc/$p/status 2>/dev/null)
      [ -n "${v:-}" ] && [ "$v" -gt "$max" ] && max=$v
    done
    echo "$max" > $out
    sleep 3
  done
}

# S1/S2 took hours: re-check that no OTHER r0vm of ours appeared before reaping any.
if pgrep -x -u "$(id -u)" r0vm >/dev/null 2>&1; then log "REFUSING Z runs: an r0vm of ours is running (none touched)"; MAY_KILL=0; exit 3; fi
echo "topk_slots,n,keys,cycles,cycles_per_record,prove_s,khz,rec_per_s,verify_ms,receipt_bytes,r0vm_peak_rss_mb" > $R/zka_matched.csv
# TOPK=1 first: the semantics-matched configuration, and the cheaper of the two.
for SLOTS in 1 100; do
  cleanup_r0vm
  log "=== Z-$SLOTS zk-Analytics CM guest, n=16384, CM_TOPK_SLOTS=$SLOTS ==="
  cd "$BASELINE_DIR" && build_cyc $SLOTS --bin cmp 2>&1 | tail -1
  [[ ${PIPESTATUS[0]} == 0 ]] || { log "BUILD FAILED T=$SLOTS -- refusing to prove with a stale binary"; exit 1; }
  RSSF=$(mktemp); sample_r0vm_rss "$RSSF" & SAMPLER=$!
  L=$(CM_TOPK_SLOTS=$SLOTS $(cyc_target $SLOTS)/release/cmp 16384 1024 8 2>/dev/null)
  kill $SAMPLER 2>/dev/null; wait $SAMPLER 2>/dev/null
  RSSKB=$(cat "$RSSF" 2>/dev/null || echo 0); rm -f "$RSSF"
  RSSMB=$(awk -v k="$RSSKB" 'BEGIN{printf "%.1f", k/1024}')
  echo "$L  r0vm_peak_rss_mb=$RSSMB"
  g(){ echo "$L" | grep -o "$1=[0-9.]*" | cut -d= -f2; }
  echo "$SLOTS,16384,1024,$(g cycles),$(g cycles_per_record),$(g prove_s),$(g khz),$(g rec_per_s),$(g verify_ms),$(g receipt_bytes),$RSSMB" >> $R/zka_matched.csv
  log "Z-$SLOTS DONE"
done
cleanup_r0vm
log "=== THEIR SIDE DONE ==="
cat $R/zka_matched.csv

######################## 3. QUERY SWEEP ########################
B=$ZKA/target/release/bench_queries
COMMON="--num-sources 1 --sources-per-epoch 1 --keys-per-source 16384 --events-per-key 1 --num-aggregators 1 --dp-disabled --skip-samples --skip-histogram --skip-raw"
for n in 1 64 32 16 8 4 2; do
  cleanup_r0vm
  log "=== Q epochs=$n ==="
  RAYON_NUM_THREADS=32 timeout 21600 $B --epochs $n $COMMON > $R/q_n$n.log 2>&1 \
    || log "Q n=$n FAILED/TIMEOUT"
  tail -12 $R/q_n$n.log
done
cleanup_r0vm
log "=== ALL DONE ==="
