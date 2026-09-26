#!/usr/bin/env bash
# ONE small proved anchor for the GK aggregation guest: aggr_gk on the first
# $EPOCH_SIZE (default 2048) AOL records, ProverOpts::succinct() (their tier), CPU
# r0vm. Records prove_s, segments, s/segment, receipt bytes, verify ms (best of 5)
# and r0vm peak RSS (VmHWM of the driver's own child processes, sampled by the
# driver; nothing is signalled). Asserts the proved journal equals the native output.
# The driver also samples /proc for r0vm processes that are NOT its own descendants
# (other users' or agents' provers and executors) and writes them to the `contention`
# column; arm=proved_contended when they burned >= 10 CPU seconds during the prove.
# Nothing is signalled.
#
# Refuses to start when the 1-minute load average exceeds $MAX_LOAD (default 24):
# prove time on a shared box is only meaningful when it is quiet.
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
