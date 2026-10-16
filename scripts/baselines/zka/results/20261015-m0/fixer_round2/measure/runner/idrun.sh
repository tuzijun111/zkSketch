#!/usr/bin/env bash
# idrun.sh <label> <family gk|bloom> <m> <T> <A|B>: root-VK identity run at the measured shape.
# The exact exp_compose environment run_zks.sh uses, plus EXP_ROOT_VK_SAVE (run_zks.sh drops it).
# Per-batch proof files stay under <scratch>/idruns/<label>/proofs (scratch, session-scoped).
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
LBL=$1; FAM=$2; M=$3; T=$4; AB=$5
. "$R/env.sh"
for v in $(compgen -e); do case $v in EXP_*|ZKSKETCH_*|RAYON_NUM_THREADS) unset "$v";; esac; done
[[ $AB == A ]] && export EXP_FOREST_RETAIN_PREP=1 EXP_MALLOC_TRIM=0 EXP_EXIT_BEFORE_AUDIT=0 EXP_MERGE_CACHE=0
case $FAM in
  gk) FENV="EXP_GK_CAP=384 EXP_GK_S=51"; KM=hot;;
  bloom) FENV="EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14"; KM=first;;
esac
D=$S/idruns/$LBL; [[ -e $D ]] && { echo "exists $D"; exit 2; }; mkdir -p "$D"
echo "# $(date -Is) load=$(cut -d' ' -f1-3 /proc/loadavg) head=$(git rev-parse --short=9 HEAD) ab=$AB $(env | grep -E '^EXP_(FOREST|MALLOC|EXIT|MERGE)' | sort | tr '\n' ' ')" > "$D/log"
env EXP_COMPOSE_FAMILY=$FAM EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=procs EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
  EXP_COMPOSE_N=$((M*T)) EXP_COMPOSE_BATCHES=$M EXP_COMPOSE_QUERY_EVERY=1 EXP_DATASET=aol EXP_QUERY_KEY_MODE=$KM $FENV \
  EXP_QUERY_LOG=1 EXP_VERIFY_REPEATS=5 EXP_OUT=id_$LBL EXP_COMPOSE_PROOF_DIR=$D/proofs EXP_ROOT_VK_SAVE=$D/root_vk.bin \
  target/release/examples/exp_compose >> "$D/log" 2>&1
RC=$?
mv -f results/id_$LBL.csv "$D/" 2>/dev/null
echo "# end $(date -Is) rc=$RC" >> "$D/log"
echo "$LBL rc=$RC vk_md5=$(md5sum < $D/root_vk.bin | cut -c1-16) vk_bytes=$(stat -c %s $D/root_vk.bin)"
