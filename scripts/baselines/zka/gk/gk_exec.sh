#!/usr/bin/env bash
# zk-Analytics-architecture Greenwald-Khanna arm on REAL AOL records. EXECUTOR ONLY.
#
#   1. aggregation guest aggr_gk on ONE epoch (the first 16,384 AOL records)
#   2. the profiling guest on the same epoch (phase split; never a reported cost)
#   3. aggr_gk on a few other epochs ($DD_EPOCHS): the cycle count is data-dependent
#   4. query guest querier_gk over n populated epochs, n in "$@" (default 1 4 16 64),
#      queries: rank(2^20), p50, p90, p99 -- one guest run (one proof) per query
#
# Every row: journal == native, accuracy vs the exact answer over the covered values,
# the native checks min_kept / q_named / q_sweep_1001 / q_ok (see README.md here,
# "Accuracy columns"; a failed check exits 1 and keeps the row out of the CSV),
# and MODELED prove time = segments x 30.1 s (envelope 29.73 .. 30.79 s from the
# four CM CPU anchors in ../README.md). MODELED is not measured.
#
# Appends to $RESULTS/zka_gk_exec.csv (header written once; refuses a foreign header)
# and $RESULTS/zka_gk_exec.log. Runs no prover. The executor starts its own
# short-lived r0vm per run; this script signals no process.
#
# Env: SKIP_BUILD=1, KEYS=..., OUT=..., DD_EPOCHS="1 16 63"
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common_gk.sh"

EPOCHS=("$@"); [[ ${#EPOCHS[@]} -eq 0 ]] && EPOCHS=(1 4 16 64)
DD_EPOCHS=${DD_EPOCHS:-"1 16 63"}
gk_preflight "exec ${EPOCHS[*]}"
fail=0

gk_run --mode aggr || fail=1
gk_run --mode aggr --profile || fail=1
for e in $DD_EPOCHS; do gk_run --mode aggr --epoch-index "$e" || fail=1; done
for n in "${EPOCHS[@]}"; do
  for q in rank p50 p90 p99; do gk_run --mode query --epochs "$n" --query "$q" || fail=1; done
done

echo "done: $(( $(wc -l < "$OUT") - 1 )) rows in $OUT (raw log $LOG); failures=$fail" >&2
exit $fail
