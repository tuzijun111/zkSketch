#!/bin/bash
# Cycle counts of zk-Analytics' CM guest with and without risc0's SHA-256 accelerator patch (executor only).
# Usage: ./sha_accel_control.sh   (env: N, KEYS, CBS, CM_TOPK_SLOTS, OUT; the accel build needs network: the patched sha2 is a git dependency)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"   # HERE BASELINE_DIR ZKA RESULTS build_cyc cyc_target
SRC=$ZKA
DST=$BASELINE_DIR/zka-shaccel
N=${N:-16384}
KEYS=${KEYS:-1024}
CBS=${CBS:-8}
TOPK=${CM_TOPK_SLOTS:-1}
OUT=${OUT:-$RESULTS/sha_accel_control.csv}
ELF_REL=riscv-guest/aggregator-methods/aggr_cm/riscv32im-risc0-zkvm-elf/release/aggr_cm
trap 'rm -f "$OUT.tmp"' EXIT   # no partial CSV left in results/ on a failed build

if [[ ! -d $DST ]]; then
  echo "[*] copying tree (excluding target/) -> $DST"
  rsync -a --exclude 'target' --exclude '.git' "$SRC/" "$DST/"
  # [patch.crates-io] sha2 -> tag sha2/v0.10.6-risc0 (verified with
  #   git ls-remote --tags https://github.com/risc0/RustCrypto-hashes | grep sha2/v0.10.6-risc0)
  # PLUS the =0.10.6 pins in aggregator/core + querier/core and the Cargo.lock hunk.
  patch -p1 -s -d "$DST" < "$HERE/sha2-risc0-accel.patch"
fi
grep -q 'RustCrypto-hashes?tag=sha2%2Fv0.10.6-risc0' "$DST/Cargo.lock" \
  || { echo "[!] $DST/Cargo.lock does not resolve sha2 to the risc0 fork: the accel arm would BE the baseline" >&2; exit 2; }

# The driver lives in cyc/ and path-deps ../.zka; stage a copy pointed at $DST.
# Re-synced every run so edits to cyc/ reach this arm.  The staged Cargo.lock is
# kept across runs: the =0.10.6 pin moves the host sha2 off cyc/Cargo.lock's 0.10.9.
CYCDST=$BASELINE_DIR/build/cyc-shaccel-src
mkdir -p "$CYCDST"
rsync -a --exclude target --exclude Cargo.lock "$HERE/cyc/" "$CYCDST/"
sed -i "s#\"\\.\\./\\.zka/#\"$DST/#g" "$CYCDST/Cargo.toml"
[[ -f $CYCDST/Cargo.lock ]] || cp "$HERE/cyc/Cargo.lock" "$CYCDST/Cargo.lock"

echo "topk,arm,n,keys,cycles,cycles_per_record,aggr_cm_elf_md5" > "$OUT.tmp"
declare -A ELF
for ARM in baseline accel; do
  if [[ $ARM == baseline ]]; then
    TD=$(cyc_target "$TOPK")
    build_cyc "$TOPK" --bin cyc >/dev/null 2>&1 || { echo "[!] build failed for arm=$ARM" >&2; exit 1; }
  else
    TD=$BASELINE_DIR/build/shaccel
    ( cd "$CYCDST" && CM_TOPK_SLOTS=$TOPK CARGO_TARGET_DIR=$TD RISC0_BUILD_LOCKED=1 cargo build --release --bin cyc >/dev/null 2>&1 ) \
      || { echo "[!] build failed for arm=$ARM (network up? the patch is a git dependency)" >&2; exit 1; }
  fi
  L=$(PROVE=0 CM_TOPK_SLOTS=$TOPK "$TD/release/cyc" "$N" "$KEYS" "$CBS" 2>/dev/null)   # EXECUTOR ONLY - cyc must not be run with PROVE=1
  C=$(echo "$L" | grep -o 'total_cycles=[0-9]*' | head -1 | cut -d= -f2)
  ELF[$ARM]=$(md5sum < "$TD/$ELF_REL" | cut -d' ' -f1)
  echo "$TOPK,$ARM,$N,$KEYS,$C,$(awk -v c="$C" -v n="$N" 'BEGIN{printf "%.1f", c/n}'),${ELF[$ARM]}" >> "$OUT.tmp"
done
if [[ ${ELF[baseline]} == "${ELF[accel]}" ]]; then
  echo "[!] both arms ran the SAME aggr_cm ELF (${ELF[baseline]}): the patch did not take. $OUT not written." >&2
  rm -f "$OUT.tmp"; exit 3
fi
mv "$OUT.tmp" "$OUT"
column -t -s, "$OUT"
echo
echo "Report the accel row next to the baseline row. If their cycle counts differ,"
echo "give every number computed from cycle counts for both builds, or for the"
echo "accelerated one."
