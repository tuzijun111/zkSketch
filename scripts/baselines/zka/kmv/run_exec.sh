#!/usr/bin/env bash
# KMV / bottom-k in zk-Analytics' architecture (our port †, see README.md).
#
# Runs the kmv driver once and appends its rows to OUT. The default is the
# executor-only pipeline at the planned comparison configuration:
#   --mode exec: kmv_aggr on epochs 0..EPOCHS-1 (EPOCHS=8 epochs of EPOCH_SIZE=2048 AOL
#   records, batches of 8), each epoch's chain carried from the previous guest journal;
#   kmv_query (distinct-count estimate) after epoch n for every n in QUERY_AT ("1 2 4 8").
# MODE=aggr (EPOCH_INDEX) and MODE=query (EPOCHS) run one guest instead.
#
# PROVE=1 also PROVES every guest run of the invocation (ProverOpts::succinct(), CPU
# r0vm). The driver records prove_s, verify_ms (best of 5), receipt bytes, the r0vm
# peak RSS and foreign-r0vm contention. It refuses when the 1-minute load average
# exceeds MAX_LOAD and prints the command instead. Default OUT is then
# zka_kmv_prove.csv.
#
# Every row: journal == native, independent reference bottom-k and f64 estimator,
# estimate vs the exact distinct count; the driver exits 1 when any check fails (its
# rows are still appended).
#
# Env: SKIP_BUILD=1  MODE=exec  EPOCHS=8  EPOCH_SIZE=2048  QUERY_AT="1 2 4 8"
#      EPOCH_INDEX=0  BATCH=8  PROVE=0  MAX_LOAD=24
#      OUT=$RESULTS/zka_kmv_exec.csv (PROVE=1: zka_kmv_prove.csv); raw log next to it
#
# Touches no process it did not start (the executor and prover spawn and reap their
# own r0vm); never uses ../rss_watch.sh, which pkills every r0vm of this account.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kmv_common.sh"
refuse_dev_mode

MODE=${MODE:-exec}
EPOCHS=${EPOCHS:-8}
EPOCH_SIZE=${EPOCH_SIZE:-2048}
QUERY_AT=${QUERY_AT:-1 2 4 8}
EPOCH_INDEX=${EPOCH_INDEX:-0}
BATCH=${BATCH:-8}
PROVE=${PROVE:-0}
MAX_LOAD=${MAX_LOAD:-24}
if [[ $PROVE == 1 ]]; then OUT=${OUT:-$RESULTS/zka_kmv_prove.csv}; else OUT=${OUT:-$RESULTS/zka_kmv_exec.csv}; fi
LOG=${OUT%.csv}.log
[[ -s $KEYS ]] || { echo "missing $KEYS (gitignored dataset; run scripts/fetch_datasets.py)" >&2; exit 2; }

ARGS=(--mode "$MODE" --epoch-size "$EPOCH_SIZE" --batch "$BATCH" --keys "$KEYS")
case $MODE in
  exec)  ARGS+=(--epochs "$EPOCHS" --query-at "$(tr ' ' ',' <<< "$QUERY_AT")");;
  aggr)  ARGS+=(--epoch-index "$EPOCH_INDEX");;
  query) ARGS+=(--epochs "$EPOCHS");;
  *) echo "MODE=$MODE: expected exec|aggr|query" >&2; exit 2;;
esac
[[ $PROVE == 1 ]] && ARGS+=(--prove)

if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  build_fam >&2 || { echo "build failed" >&2; exit 2; }
fi
[[ -x $FAM_BIN ]] || { echo "missing $FAM_BIN -- run without SKIP_BUILD" >&2; exit 2; }

L0=$(cut -d' ' -f1 /proc/loadavg)
if [[ $PROVE == 1 ]] && awk -v l="$L0" -v m="$MAX_LOAD" 'BEGIN{exit !(l > m)}'; then
  echo "SKIPPED: 1-minute load average $L0 > $MAX_LOAD. Run this later in a quiet window:" >&2
  echo "  $(printf '%q ' "$FAM_BIN" "${ARGS[@]}")" >&2
  exit 3
fi

csv_prepare "$OUT" || exit 2
{ fam_log_header run_exec.sh; echo "# cmd: $(rel_zks "$(printf '%q ' "$FAM_BIN" "${ARGS[@]}")")"; } | tee -a "$LOG" >&2
ROWS=$(mktemp)
"$FAM_BIN" "${ARGS[@]}" > "$ROWS" 2> >(tee -a "$LOG" >&2); RC=$?
sleep 1   # let the stderr tee drain
tee -a "$LOG" < "$ROWS" >> "$OUT"
# one summary line per row, by column name
awk -F, -v hdr="$(head -1 "$OUT")" 'BEGIN{n=split(hdr,h,","); for(i=1;i<=n;i++) c[h[i]]=i}
  {printf "  -> %s %s n=%s idx=%s cycles=%s segs=%s eq=%s ref=%s answer=%s exact=%s rel_err=%s acc=%s prove_s=%s\n",
     $c["arm"], $c["guest"], $c["epochs"], $c["epoch_index"], $c["user_cycles"], $c["segments"],
     $c["journal_eq_native"], $c["ref_check"], $c["answer"], $c["exact"], $c["rel_err"], $c["accuracy_ok"], $c["prove_s"]}' "$ROWS" >&2
NR=$(wc -l < "$ROWS"); rm -f "$ROWS"
echo "# rc=$RC rows=$NR load_before=$L0 load_after=$(cut -d' ' -f1 /proc/loadavg)" | tee -a "$LOG" >&2
echo "done: rc=$RC, $NR row(s) appended; $(( $(wc -l < "$OUT") - 1 )) rows now in $OUT (raw log $LOG)" >&2
exit $RC
