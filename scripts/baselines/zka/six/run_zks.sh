#!/usr/bin/env bash
# zkSketch side of the six-sketch comparison: one exp_compose run per family (+ a second
# Bloom run for the absent-key probe), sequential, each behind the quiet-box gate.
#   forest, procs engine, 1 machine x SIX_CORES cores, N = SIX_T x SIX_M AOL records in SIX_T
#   batches of SIX_M, a query after every batch (n = 1..T), default (hiding) commitments.
#   Paper configuration (the defaults): 32 cores, N = 16,384, m = 2,048 (t = 8).
# Usage: run_zks.sh [tag ...]   (default: cm hll ss gk bloom bloom_absent kmv)
# Env (see six_common.sh for RESULTS, SIX_M, SIX_T, SIX_N, SIX_GK_CAP, SIX_CORES; gate.sh for GATE_*):
#   ZKS_BIN          exp_compose binary (default: this checkout's target/release/examples/exp_compose;
#                    build it in THIS checkout: exp_compose finds data/ and results/ through the
#                    checkout it was compiled in)
#   ZKS_FEATURES     label for the binary's Cargo features (default "default"); the pcs and
#                    logup_mask the binary reports are appended to it in <prefix>_runs.csv
#   SIX_ZKS_PREFIX   output file prefix (default six_zksketch): <prefix>_<tag>.csv/.log, <prefix>_runs.csv
#   SIX_WORK         scratch for per-batch proofs, deleted after each run (default $RESULTS/work)
#   EXP_VERIFY_REPEATS  passed through (default 5): extra warm verifies, logged only (QLOG_VERIFY/QLOG_BINDV)
#   SIX_FAIL_FAST=1  stop at the first failed run
#   EXP_FOREST_RETAIN_PREP, EXP_MALLOC_TRIM, EXP_EXIT_BEFORE_AUDIT, EXP_MERGE_CACHE,
#   EXP_MERGE_CACHE_ENTRIES  M0 harness switches, passed through (all other EXP_* are dropped);
#                    unset = the new default. Pre-M0 behaviour: EXP_FOREST_RETAIN_PREP=1
#                    EXP_MALLOC_TRIM=0 EXP_EXIT_BEFORE_AUDIT=0 EXP_MERGE_CACHE=0
# Exit status 0 only if every run exited 0 and wrote a CSV row with status=ok.
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALL_TAGS=(cm hll ss gk bloom bloom_absent kmv)
TAGS=("$@")
(( ${#TAGS[@]} )) || TAGS=("${ALL_TAGS[@]}")
for tag in "${TAGS[@]}"; do  # before anything is created
  known=0; for t in "${ALL_TAGS[@]}"; do [[ $tag == "$t" ]] && known=1; done
  (( known )) || { echo "error: unknown tag '$tag' (${ALL_TAGS[*]})" >&2; exit 2; }
done
source "$HERE6/six_common.sh"   # BASELINE_DIR, ZKS, RESULTS, SIX_*, PATH
six_prepare_results
six_clean_env
six_check_tmpdir
SP=${SIX_WORK:-$RESULTS/work}
mkdir -p "$SP" "$ZKS/results" || six_die "cannot create $SP or $ZKS/results"
SP=$(cd "$SP" && pwd)
WT=$ZKS
BIN=${ZKS_BIN:-$WT/target/release/examples/exp_compose}
FEAT=${ZKS_FEATURES:-default}
PFX=${SIX_ZKS_PREFIX:-six_zksketch}
VREP=${EXP_VERIFY_REPEATS:-5}
CORES=$SIX_CORES
OUTD=$RESULTS
NOTES=$OUTD/${PFX}_runs.csv
source "$HERE6/gate.sh"

[[ -x $BIN ]] || six_die "missing $BIN -- build it: (cd $WT && cargo build --release --locked --example exp_compose)"
(( CORES <= $(nproc) )) || six_die "SIX_CORES=$CORES > $(nproc) usable CPUs (exp_compose refuses to oversubscribe)"
NOTES_HDR="tag,family,key_mode,family_env,start_iso,gate,gate_waited_s,load1_start,busy_cores_start,load1_end,wall_s,rc,main_peak_rss_mb,desc_peak_rss_mb,commit,zks_head,features,bin_md5"
if [[ ! -s $NOTES ]]; then echo "$NOTES_HDR" > "$NOTES"
elif [[ "$(head -1 "$NOTES")" != "$NOTES_HDR" ]]; then six_die "$NOTES has a different header; use a fresh RESULTS directory"; fi
BIN_MD5=$(md5sum < "$BIN" | cut -c1-12)
# dirty files outside the results directory (results land there during the run)
dirty() { git -C "$WT" status --porcelain -- . ":(exclude)scripts/baselines/zka/results" | wc -l; }

declare -A FAM KM ENVS
FAM[cm]=cm;            KM[cm]=hot;      ENVS[cm]="EXP_D=3 EXP_W=1024"
FAM[hll]=hll;          KM[hll]=first;   ENVS[hll]="EXP_HLL_B=14"
FAM[ss]=ss;            KM[ss]=first;    ENVS[ss]="EXP_SS_CAP=1024"
FAM[gk]=gk;            KM[gk]=hot;      ENVS[gk]="EXP_GK_CAP=$SIX_GK_CAP EXP_GK_S=51"
FAM[bloom]=bloom;      KM[bloom]=first; ENVS[bloom]="EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14"
FAM[bloom_absent]=bloom; KM[bloom_absent]=absent; ENVS[bloom_absent]="EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14"
FAM[kmv]=kmv;          KM[kmv]=first;   ENVS[kmv]="EXP_KMV_K=1024"

# Ctrl-C / TERM: stop the running exp_compose (rss_tree.sh stops its process group) and exit.
CHILD=
on_signal() {
  if [[ -n $CHILD ]]; then kill -TERM "$CHILD" 2>/dev/null; wait "$CHILD" 2>/dev/null; fi
  echo "run_zks.sh: interrupted" >&2
  exit 130
}
trap on_signal INT TERM HUP
# only this call's proof dirs: another run_zks.sh may share an explicit SIX_WORK
trap 'for t in "${TAGS[@]}"; do rm -rf "$SP/proofs_$t"; done; rmdir "$SP" 2>/dev/null' EXIT

echo "run_zks.sh: ${#TAGS[@]} run(s) -> $OUTD (N=$SIX_N m=$SIX_M t=$SIX_T cores=$CORES; $(gate_settings))" >&2
FAILED=()
for tag in "${TAGS[@]}"; do
  fam=${FAM[$tag]}
  log=$OUTD/${PFX}_$tag.log
  csvname=${PFX}_$tag
  rm -f "$WT/results/$csvname.csv"
  if gate; then g=quiet; else g="$GATE_WHY"; echo "gate failed for $tag: $GATE_WHY -- running anyway, row marked" >&2; fi
  start=$(date -Is)
  envs="EXP_COMPOSE_FAMILY=$fam EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=procs EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=$CORES EXP_COMPOSE_N=$SIX_N EXP_COMPOSE_BATCHES=$SIX_M EXP_COMPOSE_QUERY_EVERY=1 EXP_DATASET=aol EXP_QUERY_KEY_MODE=${KM[$tag]} ${ENVS[$tag]} EXP_QUERY_LOG=1 EXP_VERIFY_REPEATS=$VREP"
  {
    echo "# six-sketch zkSketch run tag=$tag $(date -Is) host=$(hostname) nproc=$(nproc) gate=$g waited_s=$GATE_WAITED_S load1_start=$GATE_L0 busy_cores_start=$GATE_BUSY"
    echo "# zkSketch HEAD=$(git -C "$WT" rev-parse --short=9 HEAD) dirty_files_outside_results=$(dirty) features=$FEAT bin_md5=$BIN_MD5"
    echo "# env: $envs (ZKSKETCH_COMMIT unset = hiding default)"
    echo "# m0 switches: EXP_FOREST_RETAIN_PREP=${EXP_FOREST_RETAIN_PREP-unset} EXP_MALLOC_TRIM=${EXP_MALLOC_TRIM-unset} EXP_EXIT_BEFORE_AUDIT=${EXP_EXIT_BEFORE_AUDIT-unset} EXP_MERGE_CACHE=${EXP_MERGE_CACHE-unset} EXP_MERGE_CACHE_ENTRIES=${EXP_MERGE_CACHE_ENTRIES-unset} (unset = M0 default on)"
  } > "$log"
  echo "== zkSketch $tag ($(date +%T)); log $log" >&2
  T0=$SECONDS
  # shellcheck disable=SC2086  # $envs is a list of NAME=value words
  ( cd "$WT" && exec env $envs EXP_OUT="$csvname" EXP_COMPOSE_PROOF_DIR="$SP/proofs_$tag" \
      "$HERE6/rss_tree.sh" "zks_$tag" "$BIN" ) >> "$log" 2>&1 &
  CHILD=$!
  wait "$CHILD"; rc=$?
  CHILD=
  wall=$((SECONDS - T0))
  L1=$(cut -d' ' -f1 /proc/loadavg)
  rl=$(grep '^RSSTREE' "$log" | tail -1)
  mrss=$(sed -n 's/.*main_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
  drss=$(sed -n 's/.*desc_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
  # exp_compose prints where it wrote its CSV (the results/ dir of the checkout it was built in);
  # move it into $OUTD (exp_compose's results/env.json, a machine snapshot, stays there)
  src=$(sed -n 's/^results -> //p' "$log" | tail -1)
  commit=; status=; feat=$FEAT
  if [[ -n $src && -s $src ]]; then
    [[ $src -ef $OUTD/$csvname.csv ]] || mv -f "$src" "$OUTD/$csvname.csv" && src=$OUTD/$csvname.csv
    commit=$(six_csv_col "$OUTD/$csvname.csv" commit)
    status=$(six_csv_col "$OUTD/$csvname.csv" status)
    pcs=$(six_csv_col "$OUTD/$csvname.csv" pcs)
    lm=$(six_csv_col "$OUTD/$csvname.csv" logup_mask)
    [[ -n $pcs ]] && feat="$FEAT:pcs=$pcs;logup_mask=$lm"
  fi
  echo "# end $(date -Is) rc=$rc wall_s=$wall load1_end=$L1" >> "$log"
  echo "$tag,$fam,${KM[$tag]},${ENVS[$tag]},$start,$g,$GATE_WAITED_S,$GATE_L0,$GATE_BUSY,$L1,$wall,$rc,$mrss,$drss,$commit,$(git -C "$WT" rev-parse --short=9 HEAD),$feat,$BIN_MD5" >> "$NOTES"
  rm -rf "$SP/proofs_$tag"
  why=
  (( rc == 0 )) || why+="exit code $rc; "
  [[ -n $src && -s $src ]] || why+="no CSV written (no 'results ->' line); "
  [[ -z $src || $status == ok ]] || why+="CSV status=${status:-missing}; "
  if [[ -n $why ]]; then
    FAILED+=("$tag")
    echo "FAILED zkSketch $tag: ${why%; } -- see $log" >&2
    [[ ${SIX_FAIL_FAST:-0} == 1 ]] && break
  else
    echo "done $tag rc=$rc wall=${wall}s" >&2
  fi
done
if (( ${#FAILED[@]} )); then
  echo "run_zks.sh: ${#FAILED[@]} run(s) failed: ${FAILED[*]}" >&2
  exit 1
fi
echo "run_zks.sh: all ${#TAGS[@]} run(s) ok -> $OUTD/${PFX}_*" >&2
