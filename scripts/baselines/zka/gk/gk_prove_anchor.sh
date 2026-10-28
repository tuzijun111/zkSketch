#!/usr/bin/env bash
# Proves aggr_gk once (succinct, CPU r0vm) on the first EPOCH_SIZE AOL records; appends to zka_gk_exec.csv.
# Usage: [EPOCH_SIZE=2048] [MAX_LOAD=24] gk_prove_anchor.sh   (refuses when the 1-minute load > MAX_LOAD)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common_gk.sh"

EPOCH_SIZE=${EPOCH_SIZE:-2048}
MAX_LOAD=${MAX_LOAD:-24}
load1=$(cut -d' ' -f1 /proc/loadavg)
if awk -v l="$load1" -v m="$MAX_LOAD" 'BEGIN{exit !(l > m)}'; then
  echo "1-minute load $load1 > $MAX_LOAD: not proving. Run later:" >&2
  echo "  $0" >&2
  exit 3
fi
gk_preflight "prove epoch_size=$EPOCH_SIZE load1=$load1"
gk_run --mode aggr --epoch-size "$EPOCH_SIZE" --prove
