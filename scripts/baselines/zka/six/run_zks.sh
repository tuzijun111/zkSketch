#!/usr/bin/env bash
# zkSketch side of the six-sketch comparison: one exp_compose run per family (+ a second
# Bloom run for the absent-key probe), sequential, each behind the quiet-box gate.
#   forest, procs engine, 1 machine x 32 cores, N = 16,384 AOL records, m = 2,048 (t = 8),
#   a query after every batch (n = 1..8), default (hiding) commitments.
# Usage: run_zks.sh [tag ...]   (default: all)
# Optional env:
#   ZKS_BIN          exp_compose binary (default: this checkout's target/release/examples/exp_compose)
#   ZKS_FEATURES     label recorded in the log/notes for the binary's Cargo features (default "default")
#   SIX_ZKS_PREFIX   output file prefix (default six_zksketch): <prefix>_<tag>.csv/.log, <prefix>_runs.csv
#   EXP_VERIFY_REPEATS  passed through (default 5): extra warm verifies, logged only (QLOG_VERIFY/QLOG_BINDV)
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE6/../common.sh"   # BASELINE_DIR, ZKS, RESULTS, PATH
SP=${SIX_WORK:-$BASELINE_DIR/build/six}   # gate/proof scratch
mkdir -p "$SP"
WT=$ZKS
BIN=${ZKS_BIN:-$WT/target/release/examples/exp_compose}
FEAT=${ZKS_FEATURES:-default}
PFX=${SIX_ZKS_PREFIX:-six_zksketch}
VREP=${EXP_VERIFY_REPEATS:-5}
OUTD=$RESULTS
NOTES=$OUTD/${PFX}_runs.csv
source "$HERE6/gate.sh"

[[ -x $BIN ]] || { echo "missing $BIN" >&2; exit 2; }
[[ -s $NOTES ]] || echo "tag,family,key_mode,family_env,start_iso,gate,gate_waited_s,load1_start,busy_cores_start,load1_end,wall_s,rc,main_peak_rss_mb,desc_peak_rss_mb,commit,zks_head,features,bin_md5" > "$NOTES"
BIN_MD5=$(md5sum < "$BIN" | cut -c1-12)
# dirty files outside the results directory (results land there during the run)
dirty() { git -C "$WT" status --porcelain -- . ":(exclude)scripts/baselines/zka/results" | wc -l; }

declare -A FAM KM ENVS
FAM[cm]=cm;            KM[cm]=hot;      ENVS[cm]="EXP_D=3 EXP_W=1024"
FAM[hll]=hll;          KM[hll]=first;   ENVS[hll]="EXP_HLL_B=14"
FAM[ss]=ss;            KM[ss]=first;    ENVS[ss]="EXP_SS_CAP=1024"
FAM[gk]=gk;            KM[gk]=hot;      ENVS[gk]="EXP_GK_CAP=${SIX_GK_CAP:-2048} EXP_GK_S=51"
FAM[bloom]=bloom;      KM[bloom]=first; ENVS[bloom]="EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14"
FAM[bloom_absent]=bloom; KM[bloom_absent]=absent; ENVS[bloom_absent]="EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14"
FAM[kmv]=kmv;          KM[kmv]=first;   ENVS[kmv]="EXP_KMV_K=1024"
TAGS=("$@")
(( ${#TAGS[@]} )) || TAGS=(cm hll ss gk bloom bloom_absent kmv)

cleanup() {  # pinned procs-engine workers that outlived the coordinator (our uid only, by name)
  for p in $(pgrep -u "$(id -u)" '^zks_dc_exe_' 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
}
trap cleanup EXIT INT TERM

for tag in "${TAGS[@]}"; do
  fam=${FAM[$tag]:?unknown tag $tag}
  log=$OUTD/${PFX}_$tag.log
  csvname=${PFX}_$tag.csv
  rm -f "$WT/results/$csvname"
  if gate; then g=quiet; else g="$GATE_WHY"; echo "gate failed for $tag: $GATE_WHY -- running anyway, row marked" >&2; fi
  start=$(date -Is)
  {
    echo "# six-sketch zkSketch run tag=$tag $(date -Is) host=$(hostname) nproc=$(nproc) gate=$g waited_s=$GATE_WAITED_S load1_start=$GATE_L0 busy_cores_start=${GATE_BUSY:-NA}"
    echo "# zkSketch HEAD=$(git -C "$WT" rev-parse --short=9 HEAD) dirty_files_outside_results=$(dirty) features=$FEAT bin_md5=$BIN_MD5"
    echo "# env: EXP_COMPOSE_FAMILY=$fam EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=procs EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_N=${SIX_N:-16384} EXP_COMPOSE_BATCHES=${SIX_M:-2048} EXP_COMPOSE_QUERY_EVERY=1 EXP_DATASET=aol EXP_QUERY_KEY_MODE=${KM[$tag]} ${ENVS[$tag]} EXP_QUERY_LOG=1 EXP_VERIFY_REPEATS=$VREP (ZKSKETCH_COMMIT unset = hiding default)"
  } > "$log"
  T0=$SECONDS
  ( cd "$WT" && env EXP_COMPOSE_FAMILY="$fam" EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=procs \
      EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_N=${SIX_N:-16384} EXP_COMPOSE_BATCHES=${SIX_M:-2048} \
      EXP_COMPOSE_QUERY_EVERY=1 EXP_DATASET=aol EXP_QUERY_KEY_MODE="${KM[$tag]}" EXP_QUERY_LOG=1 \
      EXP_VERIFY_REPEATS="$VREP" \
      ${ENVS[$tag]} EXP_OUT="$csvname" EXP_COMPOSE_PROOF_DIR="$SP/proofs_$tag" \
      "$HERE6/rss_tree.sh" "zks_$tag" "$BIN" ) >> "$log" 2>&1
  rc=$?
  wall=$((SECONDS - T0))
  L1=$(cut -d' ' -f1 /proc/loadavg)
  cleanup
  rl=$(grep '^RSSTREE' "$log" | tail -1)
  mrss=$(sed -n 's/.*main_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
  drss=$(sed -n 's/.*desc_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
  commit=$(awk -F, 'NR==1{for(i=1;i<=NF;i++) if($i=="commit") c=i} NR==2{print $c}' "$WT/results/$csvname" 2>/dev/null)
  echo "# end $(date -Is) rc=$rc wall_s=$wall load1_end=$L1" >> "$log"
  echo "$tag,$fam,${KM[$tag]},${ENVS[$tag]},$start,$g,$GATE_WAITED_S,$GATE_L0,${GATE_BUSY:-NA},$L1,$wall,$rc,$mrss,$drss,$commit,$(git -C "$WT" rev-parse --short=9 HEAD),$FEAT,$BIN_MD5" >> "$NOTES"
  cp -f "$WT/results/$csvname" "$OUTD/$csvname" 2>/dev/null
  rm -rf "$SP/proofs_$tag"
  echo "done $tag rc=$rc wall=${wall}s" >&2
done
