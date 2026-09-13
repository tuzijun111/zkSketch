#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"   # PATH RESULTS ZKA build_cyc cyc_target
R=$RESULTS; mkdir -p $R
log(){ echo "[$(date +%H:%M:%S)] $*"; }

log "=== env ==="; uptime; nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv,noheader

# --- A2: anchor proofs (cycles -> seconds), succinct receipts (their shipped tier)
log "=== A2 anchor proofs (CM_TOPK_SLOTS=100, as shipped) ==="
build_cyc 100 2>&1 | tail -1
[[ ${PIPESTATUS[0]} == 0 ]] || { log "BUILD FAILED T=100 -- refusing to prove with a stale binary"; exit 1; }
echo "n,keys,total_cycles,cycles_per_record,prove_s,khz,rec_per_s,receipt_bytes" > $R/a2_anchor.csv
for n in 512 1024; do
  log "A2 proving n=$n ..."
  L=$(PROVE=1 SUCCINCT=1 $(cyc_target 100)/release/cyc $n 1024 8 2>/dev/null)
  echo "$L"
  TC=$(echo "$L"|grep -o 'total_cycles=[0-9]*'|cut -d= -f2); CPR=$(echo "$L"|grep -o 'cycles_per_record=[0-9.]*'|cut -d= -f2)
  PS=$(echo "$L"|grep -o 'prove_s=[0-9.]*'|cut -d= -f2); KH=$(echo "$L"|grep -o 'khz=[0-9.]*'|cut -d= -f2)
  RS=$(echo "$L"|grep -o 'rec_per_s=[0-9.]*'|cut -d= -f2); RB=$(echo "$L"|grep -o 'receipt_bytes=[0-9]*'|cut -d= -f2)
  echo "$n,1024,$TC,$CPR,$PS,$KH,$RS,$RB" >> $R/a2_anchor.csv
done
log "A2 DONE"; cat $R/a2_anchor.csv

# --- A4: their own native (non-ZK) baseline
log "=== A4 native_baseline ==="
cd $ZKA && timeout 1800 cargo run --release -p native_baseline 2>&1 | tail -40 | tee $R/a4_native.log
log "A4 DONE"

# --- A3: query slope sweep. smoke n=1 first, then 64 downward.
log "=== A3 query sweep ==="
B=$ZKA/target/release/bench_queries
COMMON="--num-sources 1 --sources-per-epoch 1 --keys-per-source 16384 --events-per-key 1 --num-aggregators 1 --dp-disabled --skip-samples --skip-histogram --skip-raw"
log "A3 smoke test n=1"
RAYON_NUM_THREADS=32 timeout 3600 $B --epochs 1 $COMMON > $R/a3_n1.log 2>&1
if [ $? -ne 0 ]; then log "A3 SMOKE FAILED - see $R/a3_n1.log"; tail -20 $R/a3_n1.log; exit 1; fi
log "A3 smoke OK"; tail -5 $R/a3_n1.log
for n in 64 32 16 8 4 2; do
  log "A3 epochs=$n ..."
  RAYON_NUM_THREADS=32 timeout 21600 $B --epochs $n $COMMON > $R/a3_n$n.log 2>&1 || log "A3 n=$n FAILED/TIMEOUT"
  grep -iE "prove|proof|elapsed|ms|total" $R/a3_n$n.log | tail -8
done
log "A3 DONE"
