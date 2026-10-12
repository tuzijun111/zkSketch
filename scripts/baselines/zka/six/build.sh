#!/usr/bin/env bash
# Six-sketch comparison: build everything both sides need (not timed).
#   zk-Analytics side: their CM driver at CM_TOPK_SLOTS=1 (cyc/ shipped) and our
#   HLL, SS, GK, Bloom and KMV ports (†), each --locked into $BASELINE_DIR/build/...
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
step() {  # step <name> <function>: run the build in a subshell, record failures
  local name=$1 rc; shift
  echo "== build $name ($(date +%T))"
  ( "$@" ); rc=$?
  echo "rc_$name=$rc"
  (( rc == 0 )) || FAIL+=("$name(rc=$rc)")
}
b_cyc()   { source "$Z/common.sh"; build_cyc 1 --bin shipped; }
b_hll()   { source "$Z/hll/hll_common.sh"; build_hll; }
b_ss()    { source "$Z/spacesaving/common_ss.sh"; build_ss --bin ss; }
b_gk()    { source "$Z/gk/common_gk.sh"; build_gk; }
b_bloom() { source "$Z/bloom/bloom_common.sh"; build_fam; }
b_kmv()   { source "$Z/kmv/kmv_common.sh"; build_fam; }
b_zks()   { cd "$ZKS" && cargo build --release --locked --example exp_compose; }

if [[ $WHAT != zks ]]; then
  if [[ ! -d $ZKA/.git ]]; then
    echo "missing zk-Analytics clone $ZKA -- run: BASELINE_DIR=$BASELINE_DIR scripts/baselines/fetch_baselines.sh zka" >&2
    exit 2
  fi
  have=$(git -C "$ZKA" rev-parse HEAD 2>/dev/null)
  [[ $have == "$ZKA_REV" ]] || { echo "$ZKA is at ${have:-?}, expected $ZKA_REV -- re-run fetch_baselines.sh zka" >&2; exit 2; }
  step cyc b_cyc
  step hll b_hll
  step ss b_ss
  step gk b_gk
  step bloom b_bloom
  step kmv b_kmv
  EB=$BASELINE_DIR/build
  for b in "$EB/cyc-t1/release/shipped" "$EB/hll/release/hll" "$EB/zka-ss/release/ss" "$EB/zka-gk/release/gk" \
           "$EB/zka-bloom/release/bloom" "$EB/zka-kmv/release/kmv"; do
    [[ -x $b ]] || FAIL+=("missing:$b")
  done
fi
if [[ $WHAT != zka ]]; then
  step zks b_zks
  [[ -x $ZKS/target/release/examples/exp_compose ]] || FAIL+=("missing:$ZKS/target/release/examples/exp_compose")
fi
if (( ${#FAIL[@]} )); then
  echo "BUILD FAILED: ${FAIL[*]}" >&2
  exit 1
fi
echo "build.sh $WHAT: all builds ok (zk-Analytics side under $BASELINE_DIR/build, zkSketch under $ZKS/target)"
