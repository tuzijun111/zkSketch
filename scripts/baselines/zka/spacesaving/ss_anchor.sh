#!/usr/bin/env bash
# One proved run of aggr_ss (first EPOCH_SIZE AOL records, succinct, CPU) -> ../results/zka_ss_anchor.csv.
# Usage: ./ss_anchor.sh        Env: EPOCH_SIZE=2048 CAP=16384 MAX_LOAD=24 SKIP_BUILD=1 OUT=...
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common_ss.sh"

EPOCH_SIZE=${EPOCH_SIZE:-2048}
CAP=${CAP:-16384}
MAX_LOAD=${MAX_LOAD:-24}
OUT=${OUT:-$SS_ANCHOR_DEFAULT}
LOG=${OUT%.csv}.log
KEYS=${KEYS:-$ZKS/data/aol.keys}
[[ -s $KEYS ]] || { echo "missing $KEYS" >&2; exit 2; }
if [[ "$(realpath -m -- "$OUT")" == "$(realpath -m -- "$SS_OUT_DEFAULT")" ]]; then
  echo "REFUSING: proved rows do not go into the executor CSV $SS_OUT_DEFAULT; use the default OUT" >&2
  exit 2
fi
CMD=("$SS_BIN" --mode aggr --capacity "$CAP" --epoch-size "$EPOCH_SIZE" --prove)

load1=$(cut -d' ' -f1 /proc/loadavg)
busy=$(pgrep -x r0vm | wc -l)
if awk -v l="$load1" -v m="$MAX_LOAD" 'BEGIN{exit !(l > m)}' || (( busy > 0 )); then
  echo "SKIPPED: 1-minute load average $load1 (max $MAX_LOAD), r0vm processes running: $busy. Run later with:" >&2
  echo "  cd $SSDIR && SKIP_BUILD=1 ./ss_anchor.sh      # i.e. ${CMD[*]} --keys $KEYS" >&2
  exit 3
fi
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  build_ss >&2 || { echo "build failed" >&2; exit 2; }
fi
ss_csv_init "$OUT" || exit 2
{
  ss_log_header ss_anchor.sh
  echo "# proving: EPOCH_SIZE=$EPOCH_SIZE CAP=$CAP ProverOpts::succinct() CPU;" \
       "r0vm processes on the box at start (all users): $(pgrep -x r0vm | wc -l)"
} | tee -a "$LOG" >&2
ss_run "$OUT" "$LOG" --mode aggr --capacity "$CAP" --epoch-size "$EPOCH_SIZE" --prove; rc=$?
cond=$(tail -1 "$OUT" | cut -d, -f39)
echo "# anchor done rc=$rc prove_condition=$cond load=[$(cut -d' ' -f1-3 /proc/loadavg)] r0vm processes on the box at end (all users): $(pgrep -x r0vm | wc -l)" | tee -a "$LOG" >&2
[[ $cond == contended ]] && echo "WARNING: another r0vm ran during this proof; the row is marked contended -- do not use its timing" >&2
exit $rc
