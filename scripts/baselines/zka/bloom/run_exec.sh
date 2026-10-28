#!/usr/bin/env bash
# Bloom port of zk-Analytics: run the bloom driver (executor; PROVE=1 also proves) and append its rows to OUT.
# Usage: [PROVE=1] [MODE=exec|aggr|query] [EPOCHS=8] [EPOCH_SIZE=2048] [QUERY_AT="1 2 4 8"] ./run_exec.sh
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/bloom_common.sh"
refuse_dev_mode

MODE=${MODE:-exec}
EPOCHS=${EPOCHS:-8}
EPOCH_SIZE=${EPOCH_SIZE:-2048}
QUERY_AT=${QUERY_AT:-1 2 4 8}
PROVE=${PROVE:-0}
if [[ $PROVE == 1 ]]; then PROBES=${PROBES:-first}; WORDS=${WORDS:-0}; else PROBES=${PROBES:-first,absent}; WORDS=${WORDS:-1}; fi
EPOCH_INDEX=${EPOCH_INDEX:-0}
BATCH=${BATCH:-8}
ABSENT=${ABSENT:-10000}
MAX_LOAD=${MAX_LOAD:-$DEFAULT_MAX_LOAD}
WAIT_S=${WAIT_S:-1800}
ARM_TAG=${ARM_TAG:-}
if [[ $PROVE == 1 && -z $ARM_TAG ]] && awk -v m="$MAX_LOAD" -v d="$DEFAULT_MAX_LOAD" 'BEGIN{exit !(m > d)}'; then
  ARM_TAG=override
fi
if [[ $PROVE == 1 ]]; then OUT=${OUT:-$RESULTS/zka_bloom_prove.csv}; else OUT=${OUT:-$RESULTS/zka_bloom_exec.csv}; fi
LOG=${OUT%.csv}.log
[[ -s $KEYS ]] || { echo "missing $KEYS (gitignored dataset; run scripts/fetch_datasets.py)" >&2; exit 2; }

ARGS=(--mode "$MODE" --epoch-size "$EPOCH_SIZE" --batch "$BATCH" --keys "$KEYS" --absent "$ABSENT")
case $MODE in
  exec)  ARGS+=(--epochs "$EPOCHS" --query-at "$(tr ' ' ',' <<< "$QUERY_AT")" --probe "$PROBES");;
  aggr)  ARGS+=(--epoch-index "$EPOCH_INDEX");;
  query) ARGS+=(--epochs "$EPOCHS" --probe "$PROBES");;
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
    echo "  PROVE=1 MODE=$MODE EPOCHS=$EPOCHS EPOCH_SIZE=$EPOCH_SIZE QUERY_AT=\"$QUERY_AT\" PROBES=$PROBES WORDS=$WORDS EPOCH_INDEX=$EPOCH_INDEX BATCH=$BATCH $(rel_zks "$FAM_DIR")/run_exec.sh" >&2
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
  {printf "  -> %s %s n=%s idx=%s cycles=%s segs=%s eq=%s ref=%s answer=%s exact=%s acc=%s prove_s=%s\n",
     $c["arm"], $c["guest"], $c["epochs"], $c["epoch_index"], $c["user_cycles"], $c["segments"],
     $c["journal_eq_native"], $c["ref_check"], $c["answer"], $c["exact"], $c["accuracy_ok"], $c["prove_s"]}
  $c["arm"] ~ /contended/ {
     if ($c["step"] == "aggr") r = "MODE=aggr EPOCH_INDEX=" $c["epoch_index"];
     else r = "MODE=query EPOCHS=" $c["epochs"] " PROBES=" ($c["probe_mode"] == "key" ? "key:" $c["probe_key"] : $c["probe_mode"]) \
              " WORDS=" ($c["guest"] ~ /_words$/ ? 1 : 0);
     printf "     contended prove; re-run it in a quiet window: PROVE=1 EPOCH_SIZE=%s BATCH=%s %s %s\n",
       $c["epoch_records"], $c["batch"], r, run}' "$ROWS" >&2
NR=$(wc -l < "$ROWS")
echo "# rc=$RC rows=$NR load_before=$L0 load_after=$(cut -d' ' -f1 /proc/loadavg)" | tee -a "$LOG" >&2
echo "done: rc=$RC, $NR row(s) appended; $(( $(wc -l < "$OUT") - 1 )) rows now in $OUT (raw log $LOG)" >&2
exit $RC
