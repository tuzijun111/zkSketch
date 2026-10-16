#!/usr/bin/env bash
# Tiny procs-engine A/B (switches OFF vs ON): saved root VK bytes and query answers must match.
# usage: ab_tiny.sh <outdir>
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0/env.sh
O=$1; mkdir -p $O
BIN=$SB/target/release/examples/exp_compose
export TMPDIR=/tmp
run() {  # tag fam m T mode extra...
  local tag=$1 fam=$2 m=$3 T=$4 mode=$5; shift 5
  for ab in A B; do
    if [[ $ab == A ]]; then sw="EXP_FOREST_RETAIN_PREP=1 EXP_MALLOC_TRIM=0 EXP_EXIT_BEFORE_AUDIT=0 EXP_MERGE_CACHE=0"; else sw=""; fi
    ( cd $SB && env $sw EXP_COMPOSE_FAMILY=$fam EXP_COMPOSE_MODE=$mode EXP_COMPOSE_EXEC=procs EXP_COMPOSE_MACHINES=${MACH:-1} \
      EXP_COMPOSE_CORES=8 EXP_COMPOSE_N=$((m*T)) EXP_COMPOSE_BATCHES=$m EXP_COMPOSE_QUERY_EVERY=1 EXP_DATASET=aol \
      EXP_QUERY_KEY_MODE=first EXP_QUERY_LOG=1 EXP_ROOT_VK_SAVE=$O/${tag}_$ab.rootvk EXP_OUT=m0ab_${tag}_$ab \
      EXP_COMPOSE_PROOF_DIR=$O/proofs_${tag}_$ab "$@" timeout 600 $BIN ) > $O/${tag}_$ab.log 2>&1
    echo "$tag $ab rc=$?"
    rm -rf $O/proofs_${tag}_$ab
  done
  if cmp -s $O/${tag}_A.rootvk $O/${tag}_B.rootvk; then echo "$tag rootvk IDENTICAL ($(stat -c%s $O/${tag}_A.rootvk) B)"; else echo "$tag rootvk DIFFER"; fi
  for ab in A B; do grep -o 'QLOG_QUERY,at_leaf=[0-9]*,.*answer=[0-9]*' $O/${tag}_$ab.log | sed 's/prove_ms=[^,]*,witness_ms=[^,]*,verify_ms=[^,]*,proof_bytes=[^,]*,//' > $O/${tag}_$ab.answers; done
  if cmp -s $O/${tag}_A.answers $O/${tag}_B.answers && [[ -s $O/${tag}_A.answers ]]; then echo "$tag answers IDENTICAL ($(wc -l < $O/${tag}_A.answers) queries)"; else echo "$tag answers DIFFER"; fi
}
run gk gk 16 4 forest EXP_GK_CAP=32
run bloom bloom 16 4 forest EXP_BLOOM_K=3 EXP_BLOOM_LOGW=7
run cmchain cm 8 3 chain EXP_D=4 EXP_W=8
MACH=2 run cmforest2 cm 8 4 forest EXP_D=4 EXP_W=8
echo ALLDONE
