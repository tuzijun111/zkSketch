#!/usr/bin/env bash
# Executor runs of the SpaceSaving port (aggregation and query guests) -> ../results/zka_ss_exec.csv.
# Usage: ./ss_exec.sh [epochs ...]   (default 1 4 16 64)   Env: SKIP_BUILD=1 CAPS="16384 1024" LATE_EPOCH=63 OUT=...
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common_ss.sh"

EPOCHS=("$@"); [[ ${#EPOCHS[@]} -eq 0 ]] && EPOCHS=(1 4 16 64)
read -r -a CAPS <<< "${CAPS:-16384 1024}"
LATE_EPOCH=${LATE_EPOCH-63}
OUT=${OUT:-$SS_OUT_DEFAULT}
LOG=${OUT%.csv}.log
KEYS=${KEYS:-$ZKS/data/aol.keys}
[[ -s $KEYS ]] || { echo "missing $KEYS (gitignored dataset; run scripts/fetch_datasets.py)" >&2; exit 2; }

if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  build_ss >&2 || { echo "build failed" >&2; exit 2; }
fi
[[ -x $SS_BIN ]] || { echo "missing $SS_BIN -- run without SKIP_BUILD" >&2; exit 2; }
ss_csv_init "$OUT" || exit 2
ss_log_header ss_exec.sh | tee -a "$LOG" >&2

fails=0
for s in "${CAPS[@]}"; do
  ss_run "$OUT" "$LOG" --mode aggr --capacity "$s"           || fails=$((fails+1))
  ss_run "$OUT" "$LOG" --mode aggr --capacity "$s" --profile || fails=$((fails+1))
  for r in buckets64 buckets1024 perkey none; do
    ss_run "$OUT" "$LOG" --mode aggr --capacity "$s" --root "$r" || fails=$((fails+1))
  done
  if [[ -n $LATE_EPOCH ]]; then
    ss_run "$OUT" "$LOG" --mode aggr --capacity "$s" --epoch-index "$LATE_EPOCH" || fails=$((fails+1))
  fi
done
for n in "${EPOCHS[@]}"; do
  for s in "${CAPS[@]}"; do
    q=(--mode query --capacity "$s" --epochs "$n")
    ss_run "$OUT" "$LOG" "${q[@]}" --query topk --limit 10                      || fails=$((fails+1))
    ss_run "$OUT" "$LOG" "${q[@]}" --query estimate --point-rank 1              || fails=$((fails+1))
    ss_run "$OUT" "$LOG" "${q[@]}" --query estimate --point-rank 100            || fails=$((fails+1))
    ss_run "$OUT" "$LOG" "${q[@]}" --query topk --limit 10 --profile            || fails=$((fails+1))
    ss_run "$OUT" "$LOG" "${q[@]}" --query estimate --point-rank 1 --profile    || fails=$((fails+1))
    ss_run "$OUT" "$LOG" "${q[@]}" --query estimate_merged --point-rank 1       || fails=$((fails+1))
    ss_run "$OUT" "$LOG" "${q[@]}" --query estimate_merged --point-rank 100     || fails=$((fails+1))
  done
done
echo "done: $fails failed runs; rows appended to $OUT (raw log $LOG)" >&2
exit $(( fails > 0 ))
