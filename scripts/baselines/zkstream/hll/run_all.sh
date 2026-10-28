#!/usr/bin/env bash
# The HLL operator measurements behind results/zkstream_hll*.csv, one stage after the other.
# Usage: run_all.sh [probes|grid|deployed|wall|edge ...]   (default: all five, in this order)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BUILD="${BUILD:-${BASELINE_DIR:-$HOME/ext-baselines}/build/zkstream_hll}" CK="${CK:-8}"
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
