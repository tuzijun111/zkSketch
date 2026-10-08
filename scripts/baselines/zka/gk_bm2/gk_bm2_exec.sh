#!/usr/bin/env bash
# zkSketch's GK band-merge BATCH TRANSITION in a RISC Zero guest (gk_bm2). EXECUTOR ONLY.
#
#   1. equivalence check (skipped with CHECK=0): the guest runs at EVERY epoch of each
#      chain below, emits its new state, and the driver compares it tuple by tuple (and
#      n, params, the journal's three commitments, the merge census) with zkSketch's own
#      native apply_batch2 on the same input; the three ports are also re-run natively.
#        deployed  capacity 2048, s 51, m 16384: aol 4 epochs; uniform 4 epochs;
#                  aol under the mixed-workload batcher (query every 10,000 positions
#                  over 4 x 16,384 positions: 7 early-sealed batches padded with PAD_KEY)
#        small     capacity 64, s 51: aol 8, uniform 8 (capacity just above the ~50
#                  tuples the band-merge keeps at s = 51). theta = floor(N_t/s) does not
#                  depend on capacity, and L_f = ceil(log2(capacity + m)) is 15 for both
#                  64 and 2048 at m = 16384, so this chain repeats the deployed fusions
#                  exactly and differs only in the final slice (fewer trailing dummies)
#        overflow  capacity 48, s 51: aol 4 (capacity below the sketch; zkSketch's
#                  release build truncates silently, the port must truncate identically)
#        other s   capacity 256, s 6, m 4096: aol 8, uniform 8 (a different theta
#                  regime and L_f = 13; the unit tests' heavy-compression shape)
#        odd full  capacity 8, s 51, m 4095: aol 4, uniform 4 (capacity + m = 4103 is
#                  odd and, from epoch 1, full: the never-paired last row is dropped)
#      every variant (literal, literal_reuse, fixed_linear, fast) -> zka_gk_bm2_check.csv
#   2. measurement at the deployed config, every variant, no state emitted:
#        aol epoch 0, aol epoch 63 (state carried natively over epochs 0..62),
#        uniform epoch 0                                         -> zka_gk_bm2_exec.csv
#
# Every row: journal == native commitments, merge census == native, every native port
# == zkSketch; check rows also guest state == zkSketch tuple by tuple. A failed check
# exits 1 and keeps the rows out of the CSV. MODELED prove time = segments x 30.1 s
# (envelope 29.73 .. 30.79 s from the four CM CPU anchors in ../README.md); it is a
# model, not a measurement. Nothing is proved.
#
# Staged: each CSV is built in <name>.csv.tmp and replaces <name>.csv only when every
# run of its phase succeeded (the previous CSV is kept as <name>.csv.prev, gitignored).
# Raw logs are appended to <name>.log. The executor starts its own short-lived r0vm per
# run; this script signals no process.
#
# Env: SKIP_BUILD=1  CHECK=0  KEYS=<zkSketch>/data/aol.keys  OUT=...  CHECK_OUT=...  RESULTS  BASELINE_DIR
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
