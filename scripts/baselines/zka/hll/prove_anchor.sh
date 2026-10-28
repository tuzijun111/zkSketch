#!/usr/bin/env bash
# Prove hll_aggr on epoch 0 once (CPU r0vm) and append prove time, segments and r0vm peak RSS to OUT.
# Usage: [EPOCH_SIZE=2048] [MAX_LOAD=24] [OUT=...] ./prove_anchor.sh
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/hll_common.sh"
refuse_dev_mode

EPOCH_SIZE=${EPOCH_SIZE:-2048}
MAX_LOAD=${MAX_LOAD:-24}
OUT=${OUT:-$RESULTS/zka_hll_anchor.csv}
LOG=${OUT%.csv}.log
[[ -s $KEYS ]] || { echo "missing $KEYS" >&2; exit 2; }
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  build_hll >&2 || { echo "build failed" >&2; exit 2; }
fi
[[ -x $HLL_BIN ]] || { echo "missing $HLL_BIN" >&2; exit 2; }
CMD=("$HLL_DIR/rss_child.sh" "anchor_hll_aggr_m$EPOCH_SIZE" "$HLL_BIN" --mode aggr --epoch-index 0
     --epoch-size "$EPOCH_SIZE" --keys "$KEYS" --prove)

L0=$(cut -d' ' -f1 /proc/loadavg)
if awk -v l="$L0" -v m="$MAX_LOAD" 'BEGIN{exit !(l > m)}'; then
  echo "SKIPPED: 1-minute load average $L0 > $MAX_LOAD. Run this later in a quiet window:" >&2
  echo "  $(printf '%q ' "${CMD[@]}")" >&2
  exit 3
fi

csv_prepare "$OUT" ",r0vm_peak_rss_mb,wall_s,load1_before,load1_after" || exit 2
{ hll_log_header prove_anchor.sh; echo "# cmd: $(printf '%q ' "${CMD[@]}")"; } | tee -a "$LOG" >&2
ERR=$(mktemp)
line=$("${CMD[@]}" 2> >(tee "$ERR" >&2)); RC=$?
sleep 1   # let the stderr tee drain
L1=$(cut -d' ' -f1 /proc/loadavg)
cat "$ERR" >> "$LOG"
rss=$(grep '^RSSCHILD,' "$ERR" | tail -1)
rm -f "$ERR"
if [[ $RC -ne 0 || -z $line ]]; then echo "[FAIL] rc=$RC" | tee -a "$LOG" >&2; exit 1; fi
mb=$(sed -n 's/.*r0vm_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rss")
ws=$(sed -n 's/.*wall_s=\([0-9.]*\).*/\1/p' <<< "$rss")
echo "$line,${mb:-NaN},${ws:-NaN},$L0,$L1" | tee -a "$LOG" >> "$OUT"
echo "anchor: $(cut -d, -f18,20,27,33-41 <<< "$line") rss_mb=${mb:-NaN} load=$L0->$L1" >&2
