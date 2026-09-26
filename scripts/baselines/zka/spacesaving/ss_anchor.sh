#!/usr/bin/env bash
# ONE small PROVED anchor for the SpaceSaving aggregation guest (aggr_ss, the
# headline samples-style 64-bucket root): epoch 0 cut to --epoch-size records
# (default 2048), s = 2^14, ProverOpts::succinct() (their shipped tier), CPU r0vm.
# Appends one row to ../results/zka_ss_anchor.csv (proved rows only; never the
# executor CSV) with prove_s, verify_ms, receipt_bytes, s_per_segment, the
# prover's peak RSS, and prove_condition = clean | contended: the driver counts,
# once a second and read-only, r0vm processes of ANY user that are not its own
# child; one sighting makes the row "contended". prove_other_r0vm_samples and
# prove_load1_mean/max carry the evidence.
#
# Refuses to start when the 1-minute load average exceeds MAX_LOAD (24) or any
# r0vm is already running on the box, and prints the command instead. Peak RSS is
# sampled by the driver itself from its OWN r0vm child (read-only).
# ../rss_watch.sh is not used: it refuses to start while any r0vm of this account
# runs and pkill -9's every r0vm of this account on exit, which would kill other
# jobs sharing the account.
#
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
