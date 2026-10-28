#!/usr/bin/env bash
# Compile-only probe of hll_op.zok: constraint count, compile time and peak RSS per k (artifacts under $BUILD).
# Usage: constraint_probe.sh <csv> <P|default> <s> <k>...   (CK from the environment, default 8)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_DIR="${BASELINE_DIR:-$HOME/ext-baselines}"
ZOK="${ZOK:-$BASELINE_DIR/zok/zokrates}"; STDLIB="${ZOK_STDLIB:-$BASELINE_DIR/zok/stdlib}"
BUILD="${BUILD:-$BASELINE_DIR/build/zkstream_hll}"
CSV=$1 P=$2 S=$3; shift 3
CK=${CK:-8}; export CK
systemd-run --user --scope -q true 2>/dev/null \
  || { echo "systemd-run --user --scope unavailable: needs a systemd user session" >&2; exit 2; }
[[ -f $CSV ]] || echo "s,P,CK,k,constraints,compile_s,peak_rss_mb,load1" > "$CSV"
for k in "$@"; do
  d="$BUILD/probe_s${S}_p${P}_ck${CK}_k${k}"
  if [[ $P == default ]]; then "$HERE/gen.sh" "$k" "$S" "$d" >/dev/null; else "$HERE/gen.sh" "$k" "$S" "$d" "$P" >/dev/null; fi
  load=$(cut -d' ' -f1 /proc/loadavg)
  out=$(cd "$d" && /usr/bin/time -f "TIME %e %M" timeout 45m systemd-run --user --scope -q -p MemoryMax=150G \
        "$ZOK" compile --stdlib-path "$STDLIB" -i hll_op.zok -o hll_op.out 2>&1) || { echo "$S,$P,$CK,$k,FAILED,,,$load" >> "$CSV"; continue; }
  c=$(grep -oP 'Number of constraints: \K\d+' <<<"$out"); t=$(grep -oP 'TIME \K\S+' <<<"$out"); m=$(grep -oP 'TIME \S+ \K\d+' <<<"$out")
  pp=$P; [[ $P == default ]] && pp=$(( S < 32 ? S : 32 ))
  echo "$S,$pp,$CK,$k,$c,$t,$(awk -v m="$m" 'BEGIN{printf "%.1f", m/1024}'),$load" | tee -a "$CSV"
  rm -f "$d/hll_op.out"
done
