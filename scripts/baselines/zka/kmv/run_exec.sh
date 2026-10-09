#!/usr/bin/env bash
# KMV / bottom-k in zk-Analytics' architecture (our port †, see README.md).
#
# Runs the kmv driver once and appends its rows to OUT. The default is the
# executor-only pipeline at the planned comparison configuration:
#   --mode exec: kmv_aggr on epochs 0..EPOCHS-1 (EPOCHS=8 epochs of EPOCH_SIZE=2048 AOL
#   records, batches of 8), each epoch's chain carried from the previous guest journal;
#   kmv_query (distinct-count estimate) after epoch n for every n in QUERY_AT ("1 2 4 8");
#   with WORDS=1 (the executor default) each query is also run as kmv_query_words
#   (sensitivity: values in serde's default Vec<u64> encoding; same journal).
# MODE=aggr (EPOCH_INDEX) and MODE=query (EPOCHS) run one guest instead.
#
# PROVE=1 also PROVES every guest run of the invocation (ProverOpts::succinct(), CPU
# r0vm). The planned measurement is `PROVE=1 ./run_exec.sh` as is: under PROVE=1 the
# default is WORDS=0 (8 aggregation + 4 query proofs). The driver records prove_s,
# verify_ms (best of 5), receipt bytes, the r0vm peak RSS and contention. Before
# proving, the runner
#   - takes $BASELINE_DIR/build/zka-prove.lock (shared with ../bloom/run_exec.sh;
#     refuses when another bloom/kmv PROVE=1 run holds it), and
#   - waits up to WAIT_S until the 1-minute load is <= MAX_LOAD and no r0vm of any user
#     runs (../sketch_exec.sh's rule); it refuses (exit 3) if the box stays busy.
# The gate is recorded in each proved row's contention column (gate=load1_start=..;
# max_load=..;waited_s=..). MAX_LOAD above its default 24 tags proved rows
# arm=proved_override (ARM_TAG=<tag> sets any tag, e.g. validation); a row whose
# prove saw foreign load is arm=proved_contended. Only arm == proved is timing-grade;
# the runner prints a re-run command for every contended row. Default OUT is then
# zka_kmv_prove.csv.
#
# Rows are appended to OUT and the raw log as each guest run finishes, so an
# interrupted PROVE=1 run keeps its finished rows.
#
# Every row: journal == native, independent reference bottom-k and f64 estimator,
# estimate vs the exact distinct count; the driver exits 1 when any check fails (its
# rows are still appended).
#
# Env: SKIP_BUILD=1  MODE=exec  EPOCHS=8  EPOCH_SIZE=2048  QUERY_AT="1 2 4 8"
#      WORDS=1 (PROVE=1: 0)  EPOCH_INDEX=0  BATCH=8  PROVE=0  MAX_LOAD=24  WAIT_S=1800
#      ARM_TAG=  OUT=$RESULTS/zka_kmv_exec.csv (PROVE=1: zka_kmv_prove.csv); raw log next to it
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
PROVE=${PROVE:-0}
if [[ $PROVE == 1 ]]; then WORDS=${WORDS:-0}; else WORDS=${WORDS:-1}; fi
EPOCH_INDEX=${EPOCH_INDEX:-0}
BATCH=${BATCH:-8}
MAX_LOAD=${MAX_LOAD:-$DEFAULT_MAX_LOAD}
WAIT_S=${WAIT_S:-1800}
ARM_TAG=${ARM_TAG:-}
if [[ $PROVE == 1 && -z $ARM_TAG ]] && awk -v m="$MAX_LOAD" -v d="$DEFAULT_MAX_LOAD" 'BEGIN{exit !(m > d)}'; then
  ARM_TAG=override
fi
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
[[ $WORDS == 1 && $MODE != aggr ]] && ARGS+=(--words)

if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  build_fam >&2 || { echo "build failed" >&2; exit 2; }
fi
[[ -x $FAM_BIN ]] || { echo "missing $FAM_BIN -- run without SKIP_BUILD" >&2; exit 2; }

if [[ $PROVE == 1 ]]; then
  take_prove_lock || exit 2
  if ! wait_quiet; then
    echo "SKIPPED: run this later in a quiet window:" >&2
    echo "  PROVE=1 MODE=$MODE EPOCHS=$EPOCHS EPOCH_SIZE=$EPOCH_SIZE QUERY_AT=\"$QUERY_AT\" WORDS=$WORDS EPOCH_INDEX=$EPOCH_INDEX BATCH=$BATCH $(rel_zks "$FAM_DIR")/run_exec.sh" >&2
    exit 3
  fi
  ARGS+=(--prove --gate "load1_start=$L0;max_load=$MAX_LOAD;waited_s=$WAITED_S")
  [[ -n $ARM_TAG ]] && ARGS+=(--arm-tag "$ARM_TAG")
else
  L0=$(cut -d' ' -f1 /proc/loadavg)
fi

csv_prepare "$OUT" || exit 2
{ fam_log_header run_exec.sh; echo "# cmd: $(rel_zks "$(printf '%q ' "$FAM_BIN" "${ARGS[@]}")")"; } | tee -a "$LOG" >&2
ROWS=$(mktemp)
trap 'rm -f "$ROWS"' EXIT
# each row reaches OUT and LOG as soon as the driver prints it (its stdout is line-buffered)
"$FAM_BIN" "${ARGS[@]}" 2> >(tee -a "$LOG" >&2) | tee -a "$LOG" "$ROWS" >> "$OUT"
RC=${PIPESTATUS[0]}
sleep 1   # let the stderr tee drain
# one summary line per row, by column name; a re-run command for every contended prove
awk -F, -v hdr="$(head -1 "$OUT")" -v run="$(rel_zks "$FAM_DIR")/run_exec.sh" \
  'BEGIN{n=split(hdr,h,","); for(i=1;i<=n;i++) c[h[i]]=i}
  {printf "  -> %s %s n=%s idx=%s cycles=%s segs=%s eq=%s ref=%s answer=%s exact=%s rel_err=%s acc=%s prove_s=%s\n",
     $c["arm"], $c["guest"], $c["epochs"], $c["epoch_index"], $c["user_cycles"], $c["segments"],
     $c["journal_eq_native"], $c["ref_check"], $c["answer"], $c["exact"], $c["rel_err"], $c["accuracy_ok"], $c["prove_s"]}
  $c["arm"] ~ /contended/ {
     if ($c["step"] == "aggr") r = "MODE=aggr EPOCH_INDEX=" $c["epoch_index"];
     else r = "MODE=query EPOCHS=" $c["epochs"] " WORDS=" ($c["guest"] ~ /_words$/ ? 1 : 0);
     printf "     contended prove; re-run it in a quiet window: PROVE=1 EPOCH_SIZE=%s BATCH=%s %s %s\n",
       $c["epoch_records"], $c["batch"], r, run}' "$ROWS" >&2
NR=$(wc -l < "$ROWS")
echo "# rc=$RC rows=$NR load_before=$L0 load_after=$(cut -d' ' -f1 /proc/loadavg)" | tee -a "$LOG" >&2
echo "done: rc=$RC, $NR row(s) appended; $(( $(wc -l < "$OUT") - 1 )) rows now in $OUT (raw log $LOG)" >&2
exit $RC
