#!/usr/bin/env bash
# usage: chain.sh <tag> <m> <T>: the run_zks.sh command for <tag>, with EXP_COMPOSE_MODE=chain instead of forest
# (run_zks.sh hard-codes forest; nothing else differs), behind rss_tree.sh; output in memmatch-20261014/<tag>-m<m>-t<T>-chain
. "$(cd "$(dirname "$0")" && pwd)/env.sh"   # the runner directory (a session scratch dir when run)
TAG=$1; M=$2; T=$3
declare -A FAM=([cm]=cm [hll]=hll [ss]=ss [kmv]=kmv [bloom]=bloom)
declare -A KM=([cm]=hot [hll]=first [ss]=first [kmv]=first [bloom]=first)
declare -A ENVS=([cm]="EXP_D=3 EXP_W=1024" [hll]="EXP_HLL_B=14" [ss]="EXP_SS_CAP=1024" [kmv]="EXP_KMV_K=1024" [bloom]="EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14")
D=/home/binbin/zkSketch/results/six/memmatch-20261014/$TAG-m$M-t$T-chain; mkdir -p "$D"; LOG=$D/six_zksketch_$TAG.log
for v in $(compgen -e); do case $v in EXP_VERIFY_REPEATS) ;; EXP_*|ZKSKETCH_*|RAYON_NUM_THREADS) unset "$v" ;; esac; done
envs="EXP_COMPOSE_FAMILY=${FAM[$TAG]} EXP_COMPOSE_MODE=chain EXP_COMPOSE_EXEC=procs EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_N=$((M*T)) EXP_COMPOSE_BATCHES=$M EXP_COMPOSE_QUERY_EVERY=1 EXP_DATASET=aol EXP_QUERY_KEY_MODE=${KM[$TAG]} ${ENVS[$TAG]} EXP_QUERY_LOG=1 EXP_VERIFY_REPEATS=5"
BIN=$PWD/target/release/examples/exp_compose
{ echo "# chain variant of run_zks.sh $TAG $(date -Is) host=$(hostname) load=$(cut -d' ' -f1-3 /proc/loadavg)"
  echo "# zkSketch HEAD=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) bin_md5=$(md5sum < $BIN | cut -c1-12)"
  echo "# env: $envs"; } > "$LOG"
SPW=$D/work; mkdir -p "$SPW"
echo "start $(date -Is) $TAG m=$M T=$T chain dir=$D"
# shellcheck disable=SC2086
env $envs EXP_OUT=memmatch_chain_$TAG EXP_COMPOSE_PROOF_DIR="$SPW/proofs" scripts/baselines/zka/six/rss_tree.sh "zks_$TAG" "$BIN" >> "$LOG" 2>&1
rc=$?
rm -rf "$SPW"
src=$(sed -n 's/^results -> //p' "$LOG" | tail -1); [[ -n $src && -s $src ]] && mv -f "$src" "$D/six_zksketch_$TAG.csv"
echo "# end $(date -Is) rc=$rc" >> "$LOG"
echo "end $(date -Is) rc=$rc"; grep '^RSSTREE' "$LOG"
