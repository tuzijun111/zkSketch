#!/usr/bin/env bash
# Step 3, arm A: zk-Analytics' OWN shipped epoch summaries (samples, histogram, cm)
# on REAL AOL records, for the query classes zkSketch covers. EXECUTOR ONLY.
#
#   aggregation guests on ONE epoch (the first 16,384 AOL records = our matched CM epoch):
#       samples, histogram (CM_TOPK_SLOTS=100 and =1, as a T-independence check),
#       cm at CM_TOPK_SLOTS=1 and =100
#   query guests over n populated epochs of 16,384 consecutive AOL records (n=64 is all 2^20):
#       samples SumTopk{limit}   heavy hitters (exact)          T=100
#       histogram P90            quantile (log2 bins)           T=100
#       histogram P90, --key-id const (steelman: one per-key histogram per epoch)
#       cm Estimate{heaviest key}, cm Topk{limit}                T=100
#       cm Estimate                                              T=1 (the TOPK=1 update arm's query)
#
# Every row carries MODELED prove-time columns = segments x s/segment. They are a
# MODEL, not a measurement: the four CPU prove anchors behind it are all CM guests
# (see README "Shipped-structure arm"); samples/histogram guests need their own
# proved anchor before their modeled seconds can be printed as anything but a model.
#
# Usage: ./shipped_exec.sh [n1 n2 ...]         (default epochs: 1 4 16 64)
# Env:   SKIP_BUILD=1    use the existing shipped binaries
#        LIMIT=10        SumTopk / Topk limit (their bench_queries default)
#        OUT=...         default $RESULTS/zka_shipped_exec.csv (overwritten; previous copy kept as .prev)
#        S_PER_SEG=30.1  central s/segment; LO/HI envelope 29.73 / 30.79 (per-anchor min/max)
#
# Runs no prover and touches no process it did not start: the executor spawns its
# own short-lived single-threaded r0vm per run, which exits with the run.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"   # RESULTS ZKA build_cyc cyc_target

EPOCHS=("$@"); [[ ${#EPOCHS[@]} -eq 0 ]] && EPOCHS=(1 4 16 64)
LIMIT=${LIMIT:-10}
OUT=${OUT:-$RESULTS/zka_shipped_exec.csv}
LOG=${OUT%.csv}.log
S_PER_SEG=${S_PER_SEG:-30.1}; S_LO=${S_LO:-29.73}; S_HI=${S_HI:-30.79}
KEYS=${KEYS:-$ZKS/data/aol.keys}
[[ -s $KEYS ]] || { echo "missing $KEYS (gitignored dataset; run scripts/fetch_datasets.py)" >&2; exit 2; }

if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  for T in 100 1; do
    build_cyc "$T" --bin shipped >&2 || { echo "build failed (CM_TOPK_SLOTS=$T)" >&2; exit 2; }
  done
fi
B100=$(cyc_target 100)/release/shipped
B1=$(cyc_target 1)/release/shipped
[[ -x $B100 && -x $B1 ]] || { echo "missing shipped binaries -- run without SKIP_BUILD" >&2; exit 2; }

if pgrep -x -u "$(id -u)" r0vm >/dev/null 2>&1; then
  echo "NOTE: another r0vm of $(id -un) is running; cycle/segment counts are unaffected (deterministic), exec_s may be." >&2
fi

mkdir -p "$(dirname "$OUT")"
[[ -s $OUT ]] && cp -f "$OUT" "$OUT.prev"
{ "$B100" --header | tr -d '\n'; echo ",MODELED_prove_s,MODELED_prove_s_lo,MODELED_prove_s_hi,model"; } > "$OUT"
{
  echo "# shipped_exec.sh $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
  echo "# zka=$(git -C "$ZKA" rev-parse --short=9 HEAD) r0vm=$(r0vm --version 2>/dev/null) keys=$KEYS md5=$(md5sum < "$KEYS" | cut -c1-12)"
  for T in 100 1; do
    for g in aggregator-methods/aggr_samples aggregator-methods/aggr_histogram aggregator-methods/aggr_cm \
             querier-methods/querier-guest-samples querier-methods/querier-guest-histogram querier-methods/querier-guest-cm; do
      n=${g#*/}; f=$(cyc_target $T)/riscv-guest/$g/riscv32im-risc0-zkvm-elf/release/$n
      echo "# elf T=$T $n md5=$(md5sum < "$f" | cut -d' ' -f1)"
    done
  done
} > "$LOG"
cat "$LOG" >&2

run() {  # run <binary> <args...>
  local bin=$1; shift
  echo "[run ] $(basename "$(dirname "$(dirname "$bin")")") shipped $*" | tee -a "$LOG" >&2
  local line rc
  line=$("$bin" "$@" 2>>"$LOG"); rc=$?
  if [[ $rc -ne 0 || -z $line ]]; then echo "[FAIL] rc=$rc: $*" | tee -a "$LOG" >&2; return 1; fi
  echo "$line" >> "$LOG"
  # segments is column 21 of the header (see shipped.rs HEADER)
  awk -F, -v s="$S_PER_SEG" -v lo="$S_LO" -v hi="$S_HI" 'BEGIN{OFS=","}
    {seg=$21; printf "%s,%.1f,%.1f,%.1f,MODELED=segments*%s s/seg (CM-guest CPU anchors; not measured)\n", $0, seg*s, seg*lo, seg*hi, s}' \
    <<< "$line" >> "$OUT"
  echo "       -> $(cut -d, -f4-6,9,19-21,23,27-28 <<< "$line")" >&2
}

# 1. aggregation guests, one epoch (epoch 0 = the first 16,384 AOL records)
run "$B100" --mode aggr --family samples   --keys "$KEYS"
run "$B100" --mode aggr --family histogram --keys "$KEYS"
run "$B100" --mode aggr --family cm        --keys "$KEYS"
run "$B1"   --mode aggr --family cm        --keys "$KEYS"
run "$B1"   --mode aggr --family samples   --keys "$KEYS"
run "$B1"   --mode aggr --family histogram --keys "$KEYS"
# steelman for their P90: one key_id for every record (one KeyHistogram per epoch)
run "$B100" --mode aggr --family histogram --key-id const --keys "$KEYS"

# 2. query guests over n populated epochs
for n in "${EPOCHS[@]}"; do
  run "$B100" --mode query --family samples   --epochs "$n" --limit "$LIMIT" --keys "$KEYS"
  run "$B100" --mode query --family histogram --epochs "$n" --keys "$KEYS"
  run "$B100" --mode query --family histogram --epochs "$n" --key-id const --keys "$KEYS"
  run "$B100" --mode query --family cm        --epochs "$n" --query estimate --keys "$KEYS"
  run "$B100" --mode query --family cm        --epochs "$n" --query topk --limit "$LIMIT" --keys "$KEYS"
  run "$B1"   --mode query --family cm        --epochs "$n" --query estimate --keys "$KEYS"
done

echo "done: $(( $(wc -l < "$OUT") - 1 )) rows in $OUT (raw log $LOG)" >&2
