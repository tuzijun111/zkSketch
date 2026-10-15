#!/usr/bin/env bash
# Equivalence evidence for the matched GK port (executor only unless CERTIFY=1; nothing of
# zk-Analytics is proved here):
#   1. native unit tests (cargo test -p gk-matched-host): the core against zkSketch's own
#      apply_batch2 chain, carried-state binding, overflow = hard error, the rank estimator
#   2. --mode check for each configuration: every epoch < EPOCHS and implementation, the
#      guest's emitted state == zkSketch's chain tuple by tuple, journal == native, the query
#      guest's rank bounds == zkSketch's rank_interval on the hot value
#   3. --mode aggr (noroot, tuned: the driver's default implementation) at every epoch < EPOCHS:
#      the measurement-shaped row
#   4. CERTIFY=1: --mode certify, zkSketch's own GK leaf circuit (as exp_compose builds it) proves
#      every m_sub-record leaf, and each epoch's last leaf must expose Com(S) of the guest's
#      state; zkSketch's GK decoder proof must give the query guest's answer. Heavy: real STARK
#      proofs (~6 s per cap-384 / 128-record leaf, ~1.5 min per 2,048-record epoch).
# Env: CONFIGS (default "A:384:128 B:768:512" = name:capacity:m_sub), EPOCHS (2), EPOCH_SIZE
#   (2048), KEYS, OUT_DIR (default $RESULTS), SKIP_BUILD=1, CERTIFY=1.
# Writes $OUT_DIR/zka_gk_matched_{check,aggr,certify}.csv (header once; rewritten per run) and
# appends the raw record to $OUT_DIR/zka_gk_matched_check.log. Exit 1 on any failure.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common_gk_matched.sh"
case "${RISC0_DEV_MODE:-}" in ""|0|false|no|off) ;; *) echo "RISC0_DEV_MODE is set; refusing" >&2; exit 2 ;; esac
CONFIGS=${CONFIGS:-"A:384:128 B:768:512"}
EPOCHS=${EPOCHS:-2}
EPOCH_SIZE=${EPOCH_SIZE:-2048}
KEYS=${KEYS:-$ZKS/data/aol.keys}
OUT_DIR=${OUT_DIR:-$RESULTS}
mkdir -p "$OUT_DIR"
LOG=$OUT_DIR/zka_gk_matched_check.log
[[ -s $KEYS ]] || { echo "missing $KEYS" >&2; exit 2; }
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  build_gk_matched >&2 || { echo "build failed" >&2; exit 2; }
fi
[[ -x $GKM_BIN ]] || { echo "missing $GKM_BIN -- run without SKIP_BUILD" >&2; exit 2; }
{
  echo "# $(basename "$0") $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] configs=[$CONFIGS] epochs=$EPOCHS epoch_size=$EPOCH_SIZE certify=${CERTIFY:-0}"
  echo "# r0vm=$(r0vm --version 2>/dev/null) zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD) keys md5=$(md5sum < "$KEYS" | cut -c1-12)"
  echo "# zkSketch reference: src/sketch/gk_bandmerge.rs md5=$(md5sum < "$ZKS/src/sketch/gk_bandmerge.rs" | cut -c1-12) src/decode/gk_bandmerge.rs md5=$(md5sum < "$ZKS/src/decode/gk_bandmerge.rs" | cut -c1-12) src/experiments/stream_compose.rs md5=$(md5sum < "$ZKS/src/experiments/stream_compose.rs" | cut -c1-12)"
  echo "# gk_matched sources: $(cd "$GKM_DIR" && find core host methods guests ../gk_bm2/core -name '*.rs' -o -name Cargo.toml -o -name Cargo.lock | sort | xargs md5sum | md5sum | cut -c1-12) (md5 of per-file md5s, incl. ../gk_bm2/core)"
  for g in aggr_gkm querier_gkm; do echo "# elf $g md5=$(md5sum < "$(gkm_elf $g)" | cut -d' ' -f1)"; done
} >> "$LOG"
FAIL=0
echo "== native unit tests" >&2
( cd "$GKM_DIR" && CARGO_TARGET_DIR="$GKM_TARGET" RISC0_BUILD_LOCKED=1 cargo test --release --locked -p gk-matched-host 2>&1 ) \
  | tee -a "$LOG" | grep -E '^test |test result' >&2
(( PIPESTATUS[0] == 0 )) || { echo "[FAIL] unit tests" | tee -a "$LOG" >&2; FAIL=1; }
for mode in check aggr certify; do
  [[ $mode == certify && ${CERTIFY:-0} != 1 ]] && continue
  out=$OUT_DIR/zka_gk_matched_$mode.csv
  "$GKM_BIN" --header > "$out"
  for c in $CONFIGS; do
    IFS=: read -r name cap ms <<< "$c"
    common=(--capacity "$cap" --m-sub "$ms" --epoch-size "$EPOCH_SIZE" --keys "$KEYS")
    if [[ $mode == aggr ]]; then
      runs=(); for ((e = 0; e < EPOCHS; e++)); do runs+=("--mode aggr --epoch-index $e --root noroot"); done
    else
      runs=("--mode $mode --epochs $EPOCHS")
    fi
    for r in "${runs[@]}"; do
      echo "[run ] config $name: gk_matched $r ${common[*]}" | tee -a "$LOG" >&2
      # shellcheck disable=SC2086  # $r is a list of words
      rows=$("$GKM_BIN" $r "${common[@]}" 2>>"$LOG"); rc=$?
      [[ -n $rows ]] && echo "$rows" >> "$LOG"
      if (( rc != 0 )) || [[ -z $rows ]]; then
        echo "[FAIL] rc=$rc: config $name $r" | tee -a "$LOG" >&2; FAIL=1
      else
        echo "$rows" >> "$out"
      fi
    done
  done
  echo "-> $out" >&2
done
if (( FAIL )); then echo "gk_matched_check.sh: FAILED (see $LOG)" >&2; exit 1; fi
echo "gk_matched_check.sh: ok" >&2
