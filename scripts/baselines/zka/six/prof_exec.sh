#!/usr/bin/env bash
# Six-sketch comparison, zk-Analytics side, EXECUTOR ONLY (not timed; cycle counts are
# deterministic): the per-phase profile of the SS and GK aggregation guests at SIX_M-record
# epochs (how much of an epoch is their Event read + batch chain), and the SS port's point
# query (`estimate`) next to the `topk --limit 1` query the comparison proves. Epochs 0 and
# T-1, queries at n = 1 and T (paper configuration: 2,048 records, epochs 0/7, n = 1/8).
#   -> <prefix>_prof_ss.csv, <prefix>_prof_gk.csv, <prefix>_prof.log   (prefix: SIX_ZKA_PREFIX, default six_zka)
# HLL, Bloom and KMV carry the same phase profile in their <prefix>_*_exec.csv rows already, and
# so does the matched GK (SIX_ZKA_GK=matched, the default: its guest's `prof` column), so the GK
# profile here runs only for SIX_ZKA_GK=textbook (no <prefix>_prof_gk.csv otherwise).
# The SS / textbook-GK profiling twins are the LEGACY aggregation guests (the drivers take
# --profile only without --root); table.py applies their read / chain cycles to the other root
# variants' executor user cycles (the read and chain code is the same in every variant).
# Exit status 0 only if every driver call succeeded.
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE6/six_common.sh"   # BASELINE_DIR, ZKS, RESULTS, SIX_*, PATH
six_prepare_results
six_clean_env
EB=$BASELINE_DIR/build
KEYS=$ZKS/data/aol.keys
OUTD=$RESULTS
PFX=${SIX_ZKA_PREFIX:-six_zka}
SSB=$EB/zka-ss/release/ss
GKB=$EB/zka-gk/release/gk
PROF_GK=0; [[ $SIX_ZKA_GK == textbook ]] && PROF_GK=1
for b in "$SSB" $( (( PROF_GK )) && echo "$GKB"); do [[ -x $b ]] || six_die "missing $b (run six/build.sh zka)"; done
LOG=$OUTD/${PFX}_prof.log
C=(--epoch-size "$SIX_M" --batch 8 --keys "$KEYS")
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
echo "# ${PFX}_prof $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] executor only, not timed; M=$SIX_M T=$SIX_T" > "$LOG"
echo "# zka=$(git -C "$ZKA" rev-parse --short=12 HEAD) zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD)" >> "$LOG"
SSO=$OUTD/${PFX}_prof_ss.csv
"$SSB" --header > "$SSO"
for e in "${EPOCHS[@]}"; do run "$SSO" "$SSB" --mode aggr --epoch-index "$e" --profile --capacity 1024; done
for n in "${NS[@]}"; do run "$SSO" "$SSB" --mode query --epochs "$n" --query topk --limit 1 --profile --capacity 1024; done
for n in "${NS[@]}"; do run "$SSO" "$SSB" --mode query --epochs "$n" --query estimate --point-rank 1 --capacity 1024; done
for n in "${NS[@]}"; do run "$SSO" "$SSB" --mode query --epochs "$n" --query estimate --point-rank 1 --profile --capacity 1024; done
GKO=$OUTD/${PFX}_prof_gk.csv
if (( PROF_GK )); then
  "$GKB" --header > "$GKO"
  for e in "${EPOCHS[@]}"; do run "$GKO" "$GKB" --mode aggr --epoch-index "$e" --profile; done
else
  rm -f "$GKO"
  echo "# GK: $(six_gk_desc); its phase profile is the prof column of ${PFX}_gk_exec.csv (no profiling twin)" >> "$LOG"
fi
echo "# end $(date -Is)" >> "$LOG"
if (( NFAIL )); then echo "prof_exec.sh: $NFAIL failure(s); see $LOG" >&2; exit 1; fi
if (( PROF_GK )); then echo "prof_exec.sh: ok -> $OUTD/${PFX}_prof_{ss,gk}.csv" >&2
else echo "prof_exec.sh: ok -> $OUTD/${PFX}_prof_ss.csv (matched GK: profile in ${PFX}_gk_exec.csv)" >&2; fi
