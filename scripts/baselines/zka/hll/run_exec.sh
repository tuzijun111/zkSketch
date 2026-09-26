#!/usr/bin/env bash
# HyperLogLog in zk-Analytics' architecture (our port, see README.md): EXECUTOR ONLY.
#
#   aggregation guest hll_aggr on epoch(s) AGGR_EPOCHS (default 0 = the first 16,384
#   AOL records = our matched CM epoch)
#   query guest hll_query over n populated epochs, n in QUERY_EPOCHS (default 1 4 16 64)
#   query guest hll_query_words, same n (sensitivity: registers in serde's default
#   Vec<u8> encoding, one zkVM word each; same computation and journal)
#
# Every row: journal == native, independent reference check, exact distinct count,
# user/padded cycles, segments, guest phase split, and MODELED prove time
# (segments x 30.1 s, envelope 29.73-30.79 s: the CM-guest CPU anchors, not measured).
#
# Usage: ./run_exec.sh
# Env:   SKIP_BUILD=1               use the existing binary
#        AGGR_EPOCHS="0"            epoch indices for the aggregation guest ("" = none)
#        QUERY_EPOCHS="1 4 16 64"   n for the query guests ("" = none)
#        WORDS=1                    also run hll_query_words (0 = skip)
#        EPOCH_SIZE=16384 BATCH=8
#        OUT=$RESULTS/zka_hll_exec.csv   appended (header written once); raw log next to it
#
# Runs no prover. Touches no process it did not start (the executor spawns and reaps
# its own r0vm per run).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/hll_common.sh"
refuse_dev_mode

AGGR_EPOCHS=${AGGR_EPOCHS-0}
QUERY_EPOCHS=${QUERY_EPOCHS-1 4 16 64}
WORDS=${WORDS:-1}
EPOCH_SIZE=${EPOCH_SIZE:-16384}
BATCH=${BATCH:-8}
OUT=${OUT:-$RESULTS/zka_hll_exec.csv}
LOG=${OUT%.csv}.log
[[ -s $KEYS ]] || { echo "missing $KEYS (gitignored dataset; run scripts/fetch_datasets.py)" >&2; exit 2; }

if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  build_hll >&2 || { echo "build failed" >&2; exit 2; }
fi
[[ -x $HLL_BIN ]] || { echo "missing $HLL_BIN -- run without SKIP_BUILD" >&2; exit 2; }
csv_prepare "$OUT" || exit 2
hll_log_header run_exec.sh | tee -a "$LOG" >&2

FAILS=0
run() {
  echo "[run ] hll $*" | tee -a "$LOG" >&2
  local line rc
  line=$("$HLL_BIN" "$@" --keys "$KEYS" --epoch-size "$EPOCH_SIZE" --batch "$BATCH" 2>>"$LOG"); rc=$?
  if [[ $rc -ne 0 || -z $line ]]; then echo "[FAIL] rc=$rc: $*" | tee -a "$LOG" >&2; FAILS=$((FAILS+1)); return 1; fi
  echo "$line" | tee -a "$LOG" >> "$OUT"
  # guest, epochs, user_cycles, segments, journal_eq_native, ref_check, result, exact, rel_err
  echo "       -> $(cut -d, -f5,9,18,20,27,28,29,30,31 <<< "$line")" >&2
  if [[ $(cut -d, -f27 <<< "$line") != true || $(cut -d, -f28 <<< "$line") != ok ]]; then
    echo "[FAIL] journal/reference check failed: $*" | tee -a "$LOG" >&2; FAILS=$((FAILS+1))
  fi
}

for e in $AGGR_EPOCHS; do run --mode aggr --epoch-index "$e"; done
for n in $QUERY_EPOCHS; do
  run --mode query --epochs "$n"
  [[ $WORDS == 1 ]] && run --mode query --epochs "$n" --words
done

echo "done: $FAILS failure(s); $(( $(wc -l < "$OUT") - 1 )) rows now in $OUT (raw log $LOG)" >&2
exit $(( FAILS > 0 ))
