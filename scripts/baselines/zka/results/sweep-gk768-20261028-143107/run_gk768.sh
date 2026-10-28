#!/usr/bin/env bash
# GK at Table 2's capacity (768, s = 51) for the batch-size figure: zkSketch single leaves at
# m = 2^6..2^9 (run_zks.sh, the harness's own runner), the zk-Analytics matched-GK executor at
# every size (cycle counts, no proof; --m-sub = min(m, 512) as in the memmatch run) and ONE
# zk-Analytics proof at m = 2^6. Everything under taskset -c 0-31 as in the paper's runs.
set -uo pipefail
ZKS=/home/binbin/zkSketch
SIX=$ZKS/scripts/baselines/zka/six
OUT=${OUT:-$ZKS/results/six/sweep-gk768-$(date +%Y%m%d-%H%M%S)}
BIN=$HOME/ext-baselines/build/zka-gk-matched/release/gk_matched
KEYS=$ZKS/data/aol.keys
mkdir -p "$OUT"
echo "started=$(date -Is) out=$OUT cpus=$(taskset -p $$ | awk '{print $NF}')" | tee "$OUT/manifest.txt"
echo "gk_cap=768 gk_s=51 gk_rounds=stable zks_bin_md5=$(md5sum < $ZKS/target/release/examples/exp_compose | cut -c1-12) zka_bin=$BIN" | tee -a "$OUT/manifest.txt"
t0=$SECONDS
for E in 6 7 8 9; do
  m=$((1 << E)); d=$OUT/m0$E; mkdir -p "$d"
  echo "== zkSketch gk m=$m cap=768 -> $d ($(date +%T))"
  env RESULTS="$d" SIX_M=$m SIX_T=1 SIX_GK_CAP=768 SIX_GK_ROUNDS=stable SIX_BLOOM_VARIANT=packed \
      SIX_ZKA_CM_REF=0 SIX_ZKA_ROOTS=noroot SIX_CORES=32 GATE_WAIT_S=0 SIX_ZKS_PREFIX=six_zksketch \
      "$SIX/run_zks.sh" gk; rc=$?
  echo "step rc=$rc seconds=$((SECONDS - t0)) zkSketch gk m=$m" | tee -a "$OUT/manifest.txt"; t0=$SECONDS
done
echo "== zk-Analytics gk executor, cap 768, m = 2^6..2^14 ($(date +%T))"
"$BIN" --header > "$OUT/gk768_exec.csv"
for E in 6 7 8 9 10 11 12 13 14; do
  m=$((1 << E)); msub=$(( m < 512 ? m : 512 ))
  echo "# exec m=$m m_sub=$msub $(date -Is)" >> "$OUT/gk768_exec.log"
  "$BIN" --mode aggr --epoch-index 0 --root noroot --epoch-size "$m" --batch 8 --keys "$KEYS" \
         --capacity 768 --m-sub "$msub" --s 51 --impl literal >> "$OUT/gk768_exec.csv" 2>> "$OUT/gk768_exec.log"
  echo "# rc=$? m=$m" >> "$OUT/gk768_exec.log"
done
echo "step rc=0 seconds=$((SECONDS - t0)) zk-Analytics gk executor 9 sizes" | tee -a "$OUT/manifest.txt"; t0=$SECONDS
echo "== zk-Analytics gk proof m=64 cap=768 ($(date +%T))"
d=$OUT/m06
"$BIN" --header > "$d/six_zka_gk_prove.csv"
{ echo "# cmd: $BIN --mode aggr --epoch-index 0 --root noroot --epoch-size 64 --batch 8 --keys $KEYS --capacity 768 --m-sub 64 --s 51 --impl literal --prove"
  echo "# start=$(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)"; } >> "$d/six_zka_gk_prove.log"
"$SIX/rss_tree.sh" gk:aggr:0:noroot "$BIN" --mode aggr --epoch-index 0 --root noroot --epoch-size 64 --batch 8 \
    --keys "$KEYS" --capacity 768 --m-sub 64 --s 51 --impl literal --prove >> "$d/six_zka_gk_prove.csv" 2>> "$d/six_zka_gk_prove.log"; rc=$?
echo "step rc=$rc seconds=$((SECONDS - t0)) zk-Analytics gk proof m=64" | tee -a "$OUT/manifest.txt"
echo "finished=$(date -Is)" | tee -a "$OUT/manifest.txt"
