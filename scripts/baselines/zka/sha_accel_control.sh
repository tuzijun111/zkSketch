#!/bin/bash
# FAIRNESS CONTROL: how much of zk-Analytics' per-epoch cycle count is software
# SHA-256 that risc0's own accelerator would have removed?
#
# WHY (hypothesis under test; refuted, see RESULT): aggregator/core/Cargo.toml:7 pulls plain `sha2 0.10` and there is no
# [patch.crates-io] anywhere in their tree, so their guest runs SOFTWARE
# SHA-256 -- the fitted cost is ~1,695 cycles per 64-byte compression.  risc0
# 3.0.6 ships a SHA-256 ECALL accelerator in the rv32im circuit
# (HOST_ECALL_SHA2 dispatch at risc0-circuit-rv32im-4.0.5/src/execute/r0vm.rs:411
# and :616-626; guest-side selection documented at risc0-zkvm-3.0.6/src/sha.rs:17-19),
# reached the standard way by patching sha2 to risc0's fork.  Their guest is
# SHA-heavy (per-batch chain hash + per-batch events_commit, 3 x 1024-leaf CM
# row Merkle roots, the heap root, the epoch state commit), so an unpatched
# build inflates every cycles-derived comparison against us.
#
# Publishing "134.8x faster" against a build that leaves the vendor's standard
# accelerator switched off is the single easiest way for a reviewer to
# invalidate the headline.  This control costs ZERO prover time: cycle counts
# are deterministic executor output.
#
# ============================ RESULT (measured 2026-09-13) ======================
#   topk,arm,n,keys,cycles,cycles_per_record,aggr_cm_elf_md5
#   1,baseline,16384,1024,100696165,6146.0,90fce45d...
#   1,accel,   16384,1024,100696165,6146.0,bab5ef8f...
# Identical cycles from two DIFFERENT guest ELFs.  REASON: their guest ALREADY
# uses the risc0 SHA-256 accelerator.
#   aggregator/core/src/lib.rs:16-17  #[cfg(target_os = "zkvm")]
#                                     use risc0_zkvm::sha::rust_crypto::{Digest, Sha256};
#   aggregator/core/src/lib.rs:18-19  #[cfg(not(target_os = "zkvm"))] use rust_crypto::...
#   querier/core/src/lib.rs:36-39     same pattern.
#   aggregator/core/src/merkle.rs:22-28, querier/core/src/merkle.rs: risc0_zkvm::sha, unconditionally.
# The plain `sha2` in aggregator/core/Cargo.toml:7 (aliased `rust_crypto`) is the
# HOST path only.  So "no [patch.crates-io] => software SHA-256 in the guest" is
# FALSE, and any cost model that fits a cycles-per-SHA-compression constant on
# that premise is fitting a constant that is not a SHA cost.
#
# HISTORY: a first run (2026-09-12) printed the same two rows but tested nothing.
# It appended only [patch.crates-io]; zka's Cargo.lock keeps sha2 0.10.9, the
# 0.10.6 fork never matches, and its "accel" ELF was byte-identical to baseline
# (90fce45d).  The =0.10.6 pins that activate the patch were added by hand later
# and never measured.  Hence the full patch file, the ELF-md5 column, and the
# refusal below to write a CSV when both arms ran the same ELF.
# NOTE: $BASELINE_DIR/build/shaccel is ~3.3 GB; delete it when no longer needed.
# ===============================================================================
# SAFETY: works on an isolated COPY of their tree with its own CARGO_TARGET_DIR,
# so $BASELINE_DIR/zka and its target/ are untouched.  Runs the EXECUTOR only --
# never a prover.  A fresh copy needs network (the patch is a git dependency).
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
echo "Report the accel row next to the baseline row.  If the gap is large, every"
echo "cycles-derived claim (including the 174.3 h extrapolation) must be stated"
echo "against BOTH builds, or against the accelerated one as the steelman."
