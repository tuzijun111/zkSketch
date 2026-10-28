#!/usr/bin/env bash
# zkSketch side of Figure 5: one batch of m = 2^6..2^14 AOL records per sketch, in Table 2's memory-matched leaves.
# Usage: batches.sh [--families cm,hll,ss,gk,bloom,kmv] [--sizes 6,...,14] [--zka-gk] [--dry-run] [--resume]
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZKS="$(cd "$HERE6/../../../.." && pwd)"
die() { echo "error: $*" >&2; exit 2; }

FAMS=(cm hll ss gk bloom kmv)
declare -A LEAF=([cm]=1024 [hll]=1024 [ss]=4096 [gk]=512 [bloom]=1024 [kmv]=4096)
SEL=$(IFS=,; echo "${FAMS[*]}"); SIZES=6,7,8,9,10,11,12,13,14; DRY=0; RESUME=0; ZKA_GK=0
while (( $# )); do
  case $1 in
    --families) SEL=${2:?--families cm,hll,...}; shift ;;
    --sizes) SIZES=${2:?--sizes 6,7,...}; shift ;;
    --zka-gk) ZKA_GK=1 ;;
    --dry-run) DRY=1 ;;
    --resume) RESUME=1 ;;
    *) die "unknown option $1 (batches.sh [--families LIST] [--sizes LIST] [--zka-gk] [--dry-run] [--resume])" ;;
  esac
  shift
done
for f in ${SEL//,/ }; do [[ -n ${LEAF[$f]:-} ]] || die "unknown family $f (${FAMS[*]})"; done
[[ $SIZES =~ ^[0-9]+(,[0-9]+)*$ ]] || die "--sizes $SIZES must be a comma list of exponents"
for e in ${SIZES//,/ }; do (( e >= 6 && e <= 14 )) || die "--sizes: E=$e outside 6..14"; done
[[ ,$SEL, == *,gk,* ]] || ZKA_GK=0
CORES=${SIX_CORES:-32}
GATE=${GATE_WAIT_S:-900}
if [[ -z ${RESULTS:-} ]]; then
  (( RESUME )) && die "--resume needs RESULTS=<an existing batches directory>"
  RESULTS=$ZKS/results/six/batches-$(date +%Y%m%d-%H%M%S)
fi
RESULTS=$(realpath -m -- "$RESULTS")

PLAN=()   # fam:m:leaf
for f in "${FAMS[@]}"; do
  [[ ,$SEL, == *,$f,* ]] || continue
  for e in $(tr ',' '\n' <<< "$SIZES" | sort -n | uniq); do
    m=$((1 << e)); l=${LEAF[$f]}; (( m < l )) && l=$m
    PLAN+=("$f:$m:$l")
  done
done
echo "batches.sh: ${#PLAN[@]} zkSketch run(s) -> $RESULTS (cores $CORES, gate wait <= ${GATE}s; zk-Analytics' sizes, GK capacity 768)"
for p in "${PLAN[@]}"; do IFS=: read -r f m l <<< "$p"; printf '  %-5s m = %5d = %2d leaf/leaves of %d\n' "$f" "$m" "$((m / l))" "$l"; done
(( ZKA_GK )) && echo "  + zk-Analytics GK receipt at capacity 768, m = 64 (one proof, about 3 min)"
(( DRY )) && exit 0
if (( RESUME )); then [[ -d $RESULTS ]] || die "--resume: $RESULTS does not exist"
elif [[ -e $RESULTS && -n $(ls -A "$RESULTS" 2>/dev/null) ]]; then die "RESULTS=$RESULTS is not empty (use --resume)"; fi
BIN=$ZKS/target/release/examples/exp_compose
[[ -x $BIN ]] || die "missing $BIN -- build it: (cd $ZKS && cargo build --release --locked --example exp_compose)"
mkdir -p "$RESULTS" || die "cannot create $RESULTS"

# another prover still running (e.g. an earlier batches.sh)? wait for it, so timings never overlap
# this script, its ancestors (e.g. a tmux pane's shell whose command line names this script) and its
# own subshells must not count as "another" run
MINE=" $(p=$$; while (( p > 1 )); do printf '%s ' "$p"; p=$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null || echo 1); done)"
busy() {   # a prover, or another harness script between its runs
  local p pp
  for p in $(pgrep -f 'target/release/examples/exp_compose'; pgrep -x r0vm
             pgrep -f 'zka/six/(batches|run_zks|run_zka|sweep|run_all|queryrate)\.sh'); do
    [[ $MINE == *" $p "* ]] && continue
    pp=$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null) || continue
    [[ -z $pp || $pp == "$$" ]] && continue
    return 0
  done
  return 1
}
if busy; then
  echo "waiting for another prover run to finish: $(pgrep -af 'examples/exp_compose|r0vm|zka/six/[a-z_]+\.sh' | grep -v "^$$ " | cut -c1-90 | head -3 | tr '\n' ';')"
  w0=$SECONDS
  while busy; do
    sleep 30
    (( (SECONDS - w0) % 600 < 30 )) && echo "  still waiting ($(( (SECONDS - w0) / 60 )) min) $(date +%T)"
  done
  echo "the other prover finished after $(( (SECONDS - w0) / 60 )) min; starting"
fi
{
  echo "# batches.sh: zkSketch, every batch size in Table 2's memory-matched setting (Figure 5)"
  echo "started=$(date -Is) host=$(hostname) cpus_allowed=$(awk '/^Cpus_allowed_list:/{print $2}' /proc/self/status) cores=$CORES gate_wait_s=$GATE"
  echo "zksketch=$(git -C "$ZKS" rev-parse HEAD) exp_compose_md5=$(md5sum < "$BIN" | cut -c1-12) sizes=zka (cm 3x1024, ss/kmv 1024, gk cap 768 s 51, hll b14, bloom 7x2^14 packed)"
  echo "plan=${PLAN[*]}"
} >> "$RESULTS/manifest.txt"

NFAIL=0; T_ALL=$SECONDS; i=0
for p in "${PLAN[@]}"; do
  i=$((i + 1))
  IFS=: read -r f m l <<< "$p"
  e=0; while (( (1 << e) < m )); do e=$((e + 1)); done
  d=$RESULTS/m$(printf %02d "$e")
  csv=$d/six_zksketch_$f.csv
  if (( RESUME )) && [[ -s $csv ]] && [[ $(awk -F, 'NR==1{for(i=1;i<=NF;i++)if($i=="status")k=i} NR==2&&k{print $k}' "$csv") == ok ]]; then
    echo "skip $f m=$m (done: $csv)"; continue
  fi
  echo "== [$i/${#PLAN[@]}] $(date +%T) zkSketch $f: m = $m as $((m / l)) leaf/leaves of $l -> $d"
  T0=$SECONDS
  env RESULTS="$d" SIX_M="$m" SIX_T=1 SIX_LEAF="$l" SIX_GK_CAP=768 SIX_GK_ROUNDS=stable SIX_BLOOM_VARIANT=packed \
      SIX_SIZES=zka SIX_CM_W=1024 SIX_SS_CAP=1024 SIX_KMV_K=1024 SIX_CORES="$CORES" GATE_WAIT_S="$GATE" \
      SIX_ZKS_PREFIX=six_zksketch SIX_ZKA_CM_REF=0 SIX_ZKA_ROOTS=noroot "$HERE6/run_zks.sh" "$f"
  rc=$?
  if (( rc == 0 )); then   # the run must have the planned shape
    got=$(awk -F, 'NR==1{for(i=1;i<=NF;i++)h[$i]=i} NR==2{print $h["n"]":"$h["m"]":"$h["t"]":"$h["status"]}' "$csv")
    [[ $got == "$m:$l:$((m / l)):ok" ]] || { echo "error: $csv has n:m:t:status = $got, expected $m:$l:$((m / l)):ok" >&2; rc=3; }
  fi
  (( rc == 0 )) || NFAIL=$((NFAIL + 1))
  echo "step rc=$rc seconds=$((SECONDS - T0)) $f m=$m leaves=$((m / l)) leaf=$l" >> "$RESULTS/manifest.txt"
done
if (( ZKA_GK )); then
  d=$RESULTS/m06
  if (( RESUME )) && [[ -s $d/six_zka_gk_prove.csv ]] && (( $(wc -l < "$d/six_zka_gk_prove.csv") > 1 )); then
    echo "skip zk-Analytics GK m=64 (done: $d/six_zka_gk_prove.csv)"
  else
    echo "== $(date +%T) zk-Analytics GK receipt, capacity 768, m = 64 -> $d"
    T0=$SECONDS
    env RESULTS="$d" SIX_M=64 SIX_T=1 SIX_LEAF=64 SIX_GK_CAP=768 SIX_GK_ROUNDS=stable SIX_SIZES=zka \
        SIX_ZKA_GK=matched SIX_ZKA_GK_IMPL=literal SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=0 GATE_WAIT_S="$GATE" \
        SIX_ZKA_PREFIX=six_zka "$HERE6/run_zka.sh" prove gk:aggr:0:noroot
    rc=$?
    (( rc == 0 )) || NFAIL=$((NFAIL + 1))
    echo "step rc=$rc seconds=$((SECONDS - T0)) zk-Analytics gk m=64 capacity=768 receipt" >> "$RESULTS/manifest.txt"
  fi
fi
echo "finished=$(date -Is) failures=$NFAIL seconds=$((SECONDS - T_ALL))" >> "$RESULTS/manifest.txt"
echo "batches.sh: $NFAIL failure(s), $(( (SECONDS - T_ALL) / 60 )) min -> $RESULTS"
(( NFAIL == 0 ))
