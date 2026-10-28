#!/usr/bin/env bash
# gk_bm2 guest, executor only: equivalence check against zkSketch's apply_batch2, then the measurement rows.
# Usage: [CHECK=0] [SKIP_BUILD=1] [KEYS=...] [OUT=...] [CHECK_OUT=...] gk_bm2_exec.sh
#        (defaults: KEYS=data/aol.keys, OUT=$RESULTS/zka_gk_bm2_exec.csv, CHECK_OUT=$RESULTS/zka_gk_bm2_check.csv)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common_gk_bm2.sh"

DO_CHECK=${CHECK:-1}
LOG=${OUT%.csv}.log
CHECK_LOG=${CHECK_OUT%.csv}.log
LOGS=("$LOG"); [[ $DO_CHECK == 1 ]] && LOGS+=("$CHECK_LOG")
gkb_preflight "${LOGS[@]}"
HDR=$("$GKB_BIN" --header)

# promote <tmp> <csv>: move a fully successful staged CSV into place.
promote() {
  [[ -f $2 ]] && cp -p "$2" "$2.prev"
  mv -f "$1" "$2"
  echo "wrote $(( $(wc -l < "$2") - 1 )) rows to $2" >&2
}

if [[ $DO_CHECK == 1 ]]; then
  T="$CHECK_OUT.tmp"; echo "$HDR" > "$T"; fail=0
  D=(--capacity 2048 --s 51 --epoch-size 16384)
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset aol     --epochs 4 "${D[@]}" || fail=1
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset uniform --epochs 4 "${D[@]}" || fail=1
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset aol     --epochs 4 --query-every 10000 "${D[@]}" || fail=1
  S=(--capacity 64 --s 51 --epoch-size 16384)
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset aol     --epochs 8 "${S[@]}" || fail=1
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset uniform --epochs 8 "${S[@]}" || fail=1
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset aol     --epochs 4 --capacity 48 --s 51 --epoch-size 16384 || fail=1
  H=(--capacity 256 --s 6 --epoch-size 4096)
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset aol     --epochs 8 "${H[@]}" || fail=1
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset uniform --epochs 8 "${H[@]}" || fail=1
  O=(--capacity 8 --s 51 --epoch-size 4095)
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset aol     --epochs 4 "${O[@]}" || fail=1
  gkb_run "$T" "$CHECK_LOG" --mode check --dataset uniform --epochs 4 "${O[@]}" || fail=1
  if [[ $fail != 0 ]]; then
    echo "equivalence check FAILED (staged rows left in $T, raw record in $CHECK_LOG); measurement not run" >&2
    exit 1
  fi
  promote "$T" "$CHECK_OUT"
fi

T="$OUT.tmp"; echo "$HDR" > "$T"; fail=0
D=(--capacity 2048 --s 51 --epoch-size 16384)
gkb_run "$T" "$LOG" --mode exec --dataset aol     --epoch-index 0  "${D[@]}" || fail=1
gkb_run "$T" "$LOG" --mode exec --dataset aol     --epoch-index 63 "${D[@]}" || fail=1
gkb_run "$T" "$LOG" --mode exec --dataset uniform --epoch-index 0  "${D[@]}" || fail=1
if [[ $fail != 0 ]]; then
  echo "measurement FAILED (staged rows left in $T, raw record in $LOG)" >&2
  exit 1
fi
promote "$T" "$OUT"
