#!/usr/bin/env bash
# Per-phase cycle profile of zk-Analytics' heavy-hitter (MG or SpaceSaving) aggregation and query guests, and of the textbook GK
# aggregation guest; executor only.
# Usage: prof_exec.sh   (writes <prefix>_prof_ss.csv, _prof_gk.csv and _prof.log; prefix SIX_ZKA_PREFIX=six_zka)
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE6/six_common.sh"   # BASELINE_DIR, ZKS, RESULTS, SIX_*, PATH
six_prepare_results
six_clean_env
EB=$BASELINE_DIR/build
KEYS=$ZKS/data/aol.keys
OUTD=$RESULTS
PFX=${SIX_ZKA_PREFIX:-six_zka}
SSB=$EB/$SIX_ZKA_HH_BIN   # family ss: SIX_ZKA_HH (../sizes.sh) picks the Misra-Gries or the SpaceSaving port
GKB=$EB/zka-gk/release/gk
PROF_GK=0; [[ $SIX_ZKA_GK == textbook ]] && PROF_GK=1
for b in "$SSB" $( (( PROF_GK )) && echo "$GKB"); do [[ -x $b ]] || six_die "missing $b (run six/build.sh zka)"; done
LOG=$OUTD/${PFX}_prof.log
cargs() { C=(--epoch-size "$(six_fam_m "$1")" --batch 8 --keys "$KEYS"); }  # the family's epoch (SIX_M_<FAM>)
EL=$((SIX_T - 1))
EPOCHS=(0); (( EL > 0 )) && EPOCHS+=("$EL")
NS=(1); (( SIX_T > 1 )) && NS+=("$SIX_T")
NFAIL=0
run() {  # run <csv> <bin> <args...>
  local out=$1 bin=$2 rc; shift 2
  echo "# $(basename "$bin") $*" >> "$LOG"
  "$bin" "$@" "${C[@]}" >> "$out" 2>> "$LOG"; rc=$?
  echo "# rc=$rc" >> "$LOG"
  (( rc == 0 )) || { NFAIL=$((NFAIL + 1)); echo "FAILED prof: $(basename "$bin") $* (rc=$rc)" >&2; }
}
echo "# ${PFX}_prof $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] executor only, not timed; M=$SIX_M T=$SIX_T ($SIX_ZKA_HH_NAME epoch $(six_fam_m ss), GK epoch $(six_fam_m gk))" > "$LOG"
echo "# zka=$(git -C "$ZKA" rev-parse --short=12 HEAD) zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD)" >> "$LOG"
SSO=$OUTD/${PFX}_prof_ss.csv
"$SSB" --header > "$SSO"
cargs ss
for e in "${EPOCHS[@]}"; do run "$SSO" "$SSB" --mode aggr --epoch-index "$e" --profile --capacity 1024; done
for n in "${NS[@]}"; do run "$SSO" "$SSB" --mode query --epochs "$n" --query topk --limit 1 --profile --capacity 1024; done
for n in "${NS[@]}"; do run "$SSO" "$SSB" --mode query --epochs "$n" --query estimate --point-rank 1 --capacity 1024; done
for n in "${NS[@]}"; do run "$SSO" "$SSB" --mode query --epochs "$n" --query estimate --point-rank 1 --profile --capacity 1024; done
GKO=$OUTD/${PFX}_prof_gk.csv
if (( PROF_GK )); then
  "$GKB" --header > "$GKO"
  cargs gk
  for e in "${EPOCHS[@]}"; do run "$GKO" "$GKB" --mode aggr --epoch-index "$e" --profile; done
else
  rm -f "$GKO"
  echo "# GK: $(six_gk_desc); its phase profile is the prof column of ${PFX}_gk_exec.csv (no profiling twin)" >> "$LOG"
fi
echo "# end $(date -Is)" >> "$LOG"
if (( NFAIL )); then echo "prof_exec.sh: $NFAIL failure(s); see $LOG" >&2; exit 1; fi
if (( PROF_GK )); then echo "prof_exec.sh: ok -> $OUTD/${PFX}_prof_{ss,gk}.csv" >&2
else echo "prof_exec.sh: ok -> $OUTD/${PFX}_prof_ss.csv (matched GK: profile in ${PFX}_gk_exec.csv)" >&2; fi
