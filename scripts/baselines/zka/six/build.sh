#!/usr/bin/env bash
# Six-sketch comparison: build everything both sides need (not timed).
#   zk-Analytics side: their CM driver at CM_TOPK_SLOTS=1 (cyc/ shipped, which also embeds
#   the CM noroot guest of ../cm_noroot, after `cm_noroot/gen_upstream.sh --check` confirms
#   its verbatim copy still matches the clone) and our HLL, SS, GK, Bloom and KMV ports (†),
#   each --locked into $BASELINE_DIR/build/... GK is built twice: the matched port
#   (../gk_matched, zkSketch's GK rule in their pipeline, the default of the comparison) and
#   the textbook port (../gk, the labelled reference). Every aggregation guest of the root
#   variants (designed / noroot, see ../README.md "Six-sketch comparison") must exist afterwards.
#   zkSketch side: exp_compose (release, --locked) in this checkout's target/.
# Usage: build.sh [all|zka|zks]   (default all). Needs the zk-Analytics clone first:
#   scripts/baselines/fetch_baselines.sh zka
# Exits non-zero if any build fails or a binary is missing afterwards.
# The measured run (2026-10-09) used BASELINE_DIR=<private scratch dir> whose zka/ is a
# symlink to ~/ext-baselines/zka (d4a5a9a), so it shared no build dir with other jobs.
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Z="$HERE6/.."
source "$Z/common.sh"   # BASELINE_DIR, ZKA, ZKS, PATH
ZKA_REV=d4a5a9a90f7470b4af29045ef248f724708813ad
WHAT=${1:-all}
case $WHAT in all|zka|zks) ;; *) echo "usage: $0 [all|zka|zks]" >&2; exit 2 ;; esac
command -v cargo >/dev/null || { echo "cargo not found: install Rust with rustup (scripts/baselines/zka/six/run_all.sh check)" >&2; exit 2; }

FAIL=()
# step <name> <binary> <function>: run the build in a subshell, record failures. After a
# successful build the binary's mtime is set to now: cargo relinks only when a file it
# depends on changed, and run_all.sh's stale-build check compares the binary's mtime with
# the whole source directory, so `build` must clear that check even when cargo had
# nothing to do (e.g. after a pull that touched only another bin of the same crate).
step() {
  local name=$1 bin=$2 rc; shift 2
  echo "== build $name ($(date +%T))"
  ( "$@" ); rc=$?
  echo "rc_$name=$rc"
  if (( rc == 0 )); then
    [[ -x $bin ]] && touch -c -- "$bin"
  else
    FAIL+=("$name(rc=$rc)")
  fi
}
b_cyc()   { source "$Z/common.sh"; BASELINE_DIR="$BASELINE_DIR" "$Z/cm_noroot/gen_upstream.sh" --check && build_cyc 1 --bin shipped; }
b_hll()   { source "$Z/hll/hll_common.sh"; build_hll; }
b_ss()    { source "$Z/spacesaving/common_ss.sh"; build_ss --bin ss; }
b_gk()    { source "$Z/gk/common_gk.sh"; build_gk; }
b_gkm()   { source "$Z/gk_matched/common_gk_matched.sh"; build_gk_matched; }
b_bloom() { source "$Z/bloom/bloom_common.sh"; build_fam; }
b_kmv()   { source "$Z/kmv/kmv_common.sh"; build_fam; }
b_zks()   { cd "$ZKS" && CARGO_TARGET_DIR="$ZKS/target" cargo build --release --locked --example exp_compose; }

if [[ $WHAT != zks ]]; then
  if [[ ! -d $ZKA/.git ]]; then
    echo "missing zk-Analytics clone $ZKA -- run: BASELINE_DIR=$BASELINE_DIR scripts/baselines/fetch_baselines.sh zka" >&2
    exit 2
  fi
  have=$(git -C "$ZKA" rev-parse HEAD 2>/dev/null)
  [[ $have == "$ZKA_REV" ]] || { echo "$ZKA is at ${have:-?}, expected $ZKA_REV -- re-run fetch_baselines.sh zka" >&2; exit 2; }
  EB=$BASELINE_DIR/build
  step cyc "$EB/cyc-t1/release/shipped" b_cyc
  step hll "$EB/hll/release/hll" b_hll
  step ss "$EB/zka-ss/release/ss" b_ss
  step gk "$EB/zka-gk/release/gk" b_gk
  step gk_matched "$EB/zka-gk-matched/release/gk_matched" b_gkm
  step bloom "$EB/zka-bloom/release/bloom" b_bloom
  step kmv "$EB/zka-kmv/release/kmv" b_kmv
  for b in "$EB/cyc-t1/release/shipped" "$EB/hll/release/hll" "$EB/zka-ss/release/ss" "$EB/zka-gk/release/gk" \
           "$EB/zka-gk-matched/release/gk_matched" "$EB/zka-bloom/release/bloom" "$EB/zka-kmv/release/kmv"; do
    [[ -x $b ]] || FAIL+=("missing:$b")
  done
  # The guests of the root variants (the drivers embed them; a missing file means the
  # build did not produce them). <target>/riscv-guest/<methods crate>/<guest>/...
  elf() { echo "$EB/$1/riscv-guest/$2/$3/riscv32im-risc0-zkvm-elf/release/$3"; }
  for g in "cyc-t1 aggregator-methods aggr_cm" "cyc-t1 zka-cm-noroot-methods aggr_cm_noroot" \
           "hll zka-hll-methods hll_aggr_root" "zka-ss ss-methods aggr_ss_rootvar" "zka-gk gk-methods aggr_gk_root" \
           "zka-gk-matched gk-matched-methods aggr_gkm" "zka-gk-matched gk-matched-methods querier_gkm" \
           "zka-bloom zka-bloom-methods bloom_aggr_root" "zka-kmv zka-kmv-methods kmv_aggr_root"; do
    read -r t mc gn <<< "$g"
    [[ -s $(elf "$t" "$mc" "$gn") ]] || FAIL+=("missing-guest:$(elf "$t" "$mc" "$gn")")
  done
fi
if [[ $WHAT != zka ]]; then
  step zks "$ZKS/target/release/examples/exp_compose" b_zks
  [[ -x $ZKS/target/release/examples/exp_compose ]] || FAIL+=("missing:$ZKS/target/release/examples/exp_compose")
fi
if (( ${#FAIL[@]} )); then
  echo "BUILD FAILED: ${FAIL[*]}" >&2
  exit 1
fi
echo "build.sh $WHAT: all builds ok (zk-Analytics side under $BASELINE_DIR/build, zkSketch under $ZKS/target)"
