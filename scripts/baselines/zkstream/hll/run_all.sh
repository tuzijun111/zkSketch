#!/usr/bin/env bash
# run_all.sh [stage...] -- the measurement sequence behind results/zkstream_hll*.csv, one
# step after the other (never two provers at once). Stages (default: all, in this order):
#   probes    compile-only: exact constraint counts at k=1,2 for every s, and the P
#             (packing) sweep at s=1024 -> zkstream_hll_{constraint,packing}_probe.csv
#   grid      the requested grid: s in {16..4096} x k in {4, 16, 64}, 4-chunk chains, forgeries
#   deployed  the deployed register count s = 2^14 at the same k (measured, not fitted)
#   wall      s = 2^14 at k = 256, 1024: how compile time/memory grow toward the wall
#   edge      s = 2^14 at k = 512 (operator only, statement from native.py): a chunk just
#             under the modeled 45 min compile wall (k = 1024 is refused by the wall)
# Each driver run appends to results/zkstream_hll.csv and writes its own
# results/zkstream_hll_<run>.log. --allow-busy: the box is shared; the driver still waits
# for other zokrates provers before every setup/prove and records load1 per row.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BUILD="${BUILD:-$HOME/ext-baselines/build/zkstream_hll}" CK="${CK:-8}"
RES="$HERE/../results"
stages=("$@"); [[ ${#stages[@]} -gt 0 ]] || stages=(probes grid deployed wall edge)
for st in "${stages[@]}"; do
  case $st in
    probes)
      for s in 16 64 256 1024 4096; do "$HERE/probes/constraint_probe.sh" "$RES/zkstream_hll_constraint_probe.csv" default "$s" 1 2; done
      for p in 1 2 4 8 16 32; do "$HERE/probes/constraint_probe.sh" "$RES/zkstream_hll_packing_probe.csv" "$p" 1024 1 2; done ;;
    grid)     "$HERE/run_hll.py" --ck "$CK" --s 16 64 256 1024 4096 --k 4 16 64 --chunks 4 --tamper --prune --allow-busy ;;
    deployed) "$HERE/run_hll.py" --ck "$CK" --s 16384 --k 4 16 64 --chunks 4 --tamper --prune --allow-busy ;;
    wall)     "$HERE/run_hll.py" --ck "$CK" --s 16384 --k 256 1024 --chunks 4 --tamper --prune --allow-busy ;;
    edge)     "$HERE/run_hll.py" --ck "$CK" --s 16384 --k 512 --chunks 4 --tamper --prune --allow-busy --no-helper ;;
    *) echo "run_all.sh: unknown stage $st (probes|grid|deployed|wall|edge)" >&2; exit 2 ;;
  esac
done
