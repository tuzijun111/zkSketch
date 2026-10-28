#!/usr/bin/env bash
# Executor runs of the GK guests on AOL epochs (aggregation, profiling, queries) -> $RESULTS/zka_gk_exec.csv.
# Usage: gk_exec.sh [n_epochs ...]   (default 1 4 16 64; env: SKIP_BUILD=1 KEYS OUT DD_EPOCHS)
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
