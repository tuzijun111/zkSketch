#!/usr/bin/env bash
# Six-sketch comparison: build everything both sides need (not timed).
#   zk-Analytics side: their CM driver at CM_TOPK_SLOTS=1 (cyc/ shipped) and our
#   HLL, SS, GK, Bloom and KMV ports (†), each --locked into $BASELINE_DIR/build/...
#   zkSketch side: exp_compose (release) in this checkout's target/.
# The measured run (2026-10-09) used BASELINE_DIR=<private scratch dir> whose zka/ is a
# symlink to ~/ext-baselines/zka (d4a5a9a), so it shared no build dir with other jobs.
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Z="$HERE6/.."
( source "$Z/common.sh"; echo "== cyc T=1"; build_cyc 1 --bin shipped ); echo "rc_cyc=$?"
( source "$Z/hll/hll_common.sh"; echo "== hll"; build_hll ); echo "rc_hll=$?"
( source "$Z/spacesaving/common_ss.sh"; echo "== ss"; build_ss --bin ss ); echo "rc_ss=$?"
( source "$Z/gk/common_gk.sh"; echo "== gk"; build_gk ); echo "rc_gk=$?"
( source "$Z/bloom/bloom_common.sh"; echo "== bloom"; build_fam ); echo "rc_bloom=$?"
( source "$Z/kmv/kmv_common.sh"; echo "== kmv"; build_fam ); echo "rc_kmv=$?"
( source "$Z/common.sh"; echo "== zkSketch exp_compose"; cd "$ZKS" && cargo build --release --example exp_compose ); echo "rc_zks=$?"
