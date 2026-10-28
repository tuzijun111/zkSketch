#!/usr/bin/env bash
# HLL port of zk-Analytics, executor only: hll_aggr and hll_query(_words) rows appended to OUT.
# Usage: [AGGR_EPOCHS="0"] [QUERY_EPOCHS="1 4 16 64"] [WORDS=1] [EPOCH_SIZE=16384] ./run_exec.sh
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
