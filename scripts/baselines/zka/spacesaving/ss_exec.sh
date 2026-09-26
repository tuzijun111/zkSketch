#!/usr/bin/env bash
# SpaceSaving on zk-Analytics' pipeline (our port; see README.md). EXECUTOR ONLY.
#
#   aggregation guest on ONE epoch (the first 16,384 AOL records), s in {2^14, 1024}:
#       aggr_ss (headline root: their samples-style 64-bucket root) + its _prof twin;
#       aggr_ss_rootvar sensitivity rows: buckets1024, perkey (v1), none, and
#       buckets64 again (must match aggr_ss to within the extra 4-byte read);
#       aggr_ss on epoch 63 (a late-epoch guest-vs-native spot check: the query
#       rows' epoch states 1..63 come from native aggregation)
#   query guest over n populated epochs, s in {2^14, 1024}:
#       topk (limit 10, keys in the journal) and its _prof twin;
#       estimate (their SumExactKey per-epoch scan; the heaviest key of the prefix,
#       and rank 100 as a mid-frequency key) and a _prof twin of the rank-1 run;
#       estimate_merged (v1 point query: full merge, then lookup; sensitivity only)
#
# Every row carries MODELED prove time = segments x 30.1 s (envelope 29.73..30.79),
# the CM-guest CPU anchors of ../README.md. NOT measured. Proved rows never go
# here; they go to ../results/zka_ss_anchor.csv (ss_anchor.sh).
#
# Usage: ./ss_exec.sh [n1 n2 ...]          (default epochs: 1 4 16 64)
# Env:   SKIP_BUILD=1   use the existing binaries
#        CAPS="16384 1024"  capacities
#        LATE_EPOCH=63  epoch index of the late-epoch spot check ("" skips it)
#        OUT=...        default ../results/zka_ss_exec.csv (appended; header checked)
#
# Runs no prover. Kills nothing: each executor run spawns its own r0vm child,
# which exits with the run.
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
