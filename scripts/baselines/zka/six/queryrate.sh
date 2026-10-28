#!/usr/bin/env bash
# Query-rate experiment of the six-sketch comparison: one query every Q stream positions. zkSketch proves the
# whole stream; zk-Analytics is not run over it: queryrate_model.py computes its totals from its epoch and
# query proofs and executor cycle counts.
#
# Usage: queryrate.sh [--q LIST] [--n N] [--quick] [--dry-run]
#   --n N       stream positions, an integer or 2^k (default 131072 = 2^17)
#   --q LIST    query periods Q (default 1000,10000,100000); the query-free Q = 0 always runs too
#   --quick     smoke run: N = 1024, Q = 100,1000, small zk-Analytics parts (about 40 min)
#   --dry-run   print the plan and run nothing
# Env: RESULTS (new or empty), BASELINE_DIR, SIX_CORES, GATE_WAIT_S, SIX_QR_DATASET (aol), SIX_QR_QEPOCH (4096),
#   SIX_QR_QEPOCHS (64), SIX_QR_PROVE_MAX_E (10000), SIX_QR_PROVE_QNS (1,8), SIX_QR_GK_CAP (768), SIX_FAIL_FAST=1,
#   SIX_ZKA_HH (../sizes.sh; spacesaving for Table 3)
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZKS="$(cd "$HERE6/../../../.." && pwd)"
die() { echo "error: $*" >&2; exit 2; }
hms() { printf '%dh%02dm%02ds' $(($1 / 3600)) $(($1 % 3600 / 60)) $(($1 % 60)); }
hmin() { local m=$(( ($1 + 30) / 60 )); printf '%dh%02dm' $((m / 60)) $((m % 60)); }   # whole minutes
usage() { sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

# ------------------------------------------------------------------ arguments
QR_N=; QR_Q=; QUICK=0; DRY=0
while (( $# )); do
  case $1 in
    --q) QR_Q=${2:?--q LIST}; shift ;;
    --n) QR_N=${2:?--n N}; shift ;;
    --quick) QUICK=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option $1 (queryrate.sh [--q LIST] [--n N] [--quick] [--dry-run])" ;;
  esac
  shift
done
size() {  # size <int | 2^k>
  if [[ $1 =~ ^2\^([0-9]+)$ ]]; then echo $((1 << BASH_REMATCH[1]))
  elif [[ $1 =~ ^[0-9]+$ ]]; then echo $((10#$1))
  else return 1; fi
}
if (( QUICK )); then
  N=$(size "${QR_N:-1024}") || die "--n $QR_N: an integer or 2^k"
  QLIST=${QR_Q:-100,1000}
  EQ=${SIX_QR_QEPOCH:-100}; TQ=${SIX_QR_QEPOCHS:-8}
  PROVE_MAX_E=${SIX_QR_PROVE_MAX_E:-100}; PROVE_QNS=${SIX_QR_PROVE_QNS:-1}
  export GATE_WAIT_S=${GATE_WAIT_S:-0} SIX_FAIL_FAST=1
  MODE=queryrate-quick
else
  N=$(size "${QR_N:-131072}") || die "--n $QR_N: an integer or 2^k"
  QLIST=${QR_Q:-1000,10000,100000}
  EQ=${SIX_QR_QEPOCH:-4096}; TQ=${SIX_QR_QEPOCHS:-64}
  PROVE_MAX_E=${SIX_QR_PROVE_MAX_E:-10000}; PROVE_QNS=${SIX_QR_PROVE_QNS:-1,8}
  export GATE_WAIT_S=${GATE_WAIT_S:-1800}
  MODE=queryrate
fi
(( N >= 2 )) || die "--n $N: need at least 2 stream positions"
[[ $QLIST =~ ^[0-9]+(,[0-9]+)*$ ]] || die "--q $QLIST: a comma list of integers"
QS=()   # the query periods, each once, ascending, without 0 / 1
for q in $(tr ',' '\n' <<< "$QLIST" | sort -nu); do
  q=$((10#$q))
  (( q == 0 )) && continue   # the baseline is always run
  (( q >= 2 )) || die "--q $QLIST: Q = 1 makes every position a query (exp_compose refuses it)"
  (( q <= N )) || die "--q $QLIST: Q = $q exceeds N = $N (no query would occur)"
  QS+=("$q")
done
(( ${#QS[@]} )) || die "--q $QLIST: no query period left"
for v in EQ TQ PROVE_MAX_E; do [[ ${!v} =~ ^[0-9]+$ ]] && (( ${!v} > 0 )) || die "$v=${!v}: a positive integer"; done
[[ $PROVE_QNS =~ ^[0-9]+(,[0-9]+)*$ ]] || die "SIX_QR_PROVE_QNS=$PROVE_QNS: a comma list of n"
QNS=1; for ((n = 2; n <= TQ; n *= 2)); do QNS+=",$n"; done   # query points 1,2,4,...,Tq
for n in ${PROVE_QNS//,/ }; do
  [[ ,$QNS, == *,$n,* ]] || die "SIX_QR_PROVE_QNS=$PROVE_QNS: n = $n is not one of the query points $QNS (Tq = $TQ)"
done
PQNS=(); for n in ${PROVE_QNS//,/ }; do PQNS+=("$n"); done
(( EQ * TQ <= 1048576 )) || die "Eq x Tq = $((EQ * TQ)) exceeds the 2^20 AOL keys"
for q in "${QS[@]}"; do (( q <= 1048576 )) || die "Q = $q exceeds the 2^20 AOL keys (the zk-Analytics epoch)"; done
(( N <= 1048576 )) || die "--n $N exceeds the 2^20 AOL keys (the GK capacity preflight chains all N records)"

# ------------------------------------------------------------------ shape and environment
# the fixed run shape: the shape knobs of the individual six/*.sh scripts are ignored here
given=()
for v in SIX_M SIX_T SIX_N SIX_QNS SIX_GK_CAP SIX_GK_MSUB SIX_LEAF SIX_ZKA_ROOTS SIX_ZKA_CM_REF \
         SIX_BLOOM_VARIANT SIX_GK_ROUNDS SIX_ZKA_GK; do
  [[ -n ${!v:-} ]] && given+=("$v=${!v}"); unset "$v"
done
for f in CM HLL SS GK BLOOM KMV; do
  for v in "SIX_M_$f" "SIX_LEAF_$f"; do [[ -n ${!v:-} ]] && given+=("$v=${!v}"); unset "$v"; done
done
(( ${#given[@]} )) && echo "note: queryrate.sh uses its fixed run shape; ignoring ${given[*]}" >&2
RESULTS=${RESULTS:-$ZKS/results/six/$MODE-$(date +%Y%m%d-%H%M%S)}
RESULTS=$(realpath -m -- "$RESULTS")
source "$HERE6/six_common.sh"   # ZKS, BASELINE_DIR, ZKA, SIX_CORES, six_die, six_* helpers, PATH
source "$HERE6/gate.sh"
export SIX_ZKA_GK=matched SIX_ZKA_GK_IMPL=${SIX_ZKA_GK_IMPL:-literal}
KEYS=$ZKS/data/aol.keys
EB=$BASELINE_DIR/build
ZKA_BINS=("$EB/cyc-t1/release/shipped" "$EB/hll/release/hll" "$EB/$SIX_ZKA_HH_BIN"
          "$EB/zka-gk-matched/release/gk_matched" "$EB/zka-bloom/release/bloom" "$EB/zka-kmv$SIX_KMV_SUFFIX/release/kmv")
BIN=${ZKS_BIN:-$ZKS/target/release/examples/exp_compose}
FEAT=${ZKS_FEATURES:-default}
VREP=${EXP_VERIFY_REPEATS:-5}
CORES=$SIX_CORES
DATASET=${SIX_QR_DATASET:-aol}
[[ $DATASET =~ ^(uniform|gaussian|zipf|aol|netflix)$ ]] || die "SIX_QR_DATASET=$DATASET: uniform|gaussian|zipf|aol|netflix (exp_compose's EXP_DATASET)"
[[ $DATASET != netflix || -s $ZKS/data/netflix.keys ]] || die "SIX_QR_DATASET=netflix needs $ZKS/data/netflix.keys"
GK_CAP=${SIX_QR_GK_CAP:-768}; GK_LEAF=512
[[ $GK_CAP =~ ^[0-9]+$ ]] && (( GK_CAP > 0 && (GK_CAP + GK_LEAF) % 2 == 0 )) ||
  die "SIX_QR_GK_CAP=$GK_CAP: a positive even integer (capacity + the $GK_LEAF-record leaf must be even)"
ROOT_COLS=root_variant,root_construction,variants_agree,state_commit   # drivers built with --root (run_all.sh)
FAMS6=(cm hll ss gk bloom kmv)
GROUPS_=(a b c)
declare -A GFAMS GLEAF GENV
GFAMS[a]=cm,hll,bloom; GLEAF[a]=1024; GENV[a]="EXP_D=3 EXP_W=1024 EXP_HLL_B=14 EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=packed"
GFAMS[b]=ss,kmv;       GLEAF[b]=4096; GENV[b]="EXP_SS_CAP=1024 EXP_KMV_K=1024"
GFAMS[c]=gk;           GLEAF[c]=512;  GENV[c]="EXP_GK_CAP=$GK_CAP EXP_GK_S=51 EXP_GK_ROUNDS=stable"

# gk_msub <epoch>: the matched zk-Analytics GK's --m-sub (SIX_QR_GK_MSUB, or the largest even
# divisor of the epoch not above the zkSketch GK leaf; cap + m_sub must be even, the epoch a multiple)
gk_msub() {
  local e=$1 d
  if [[ ${SIX_QR_GK_MSUB:-auto} != auto ]]; then
    d=$SIX_QR_GK_MSUB
    [[ $d =~ ^[0-9]+$ ]] && (( d > 0 && e % d == 0 && (GK_CAP + d) % 2 == 0 )) ||
      die "SIX_QR_GK_MSUB=$d must divide the epoch $e and leave capacity $GK_CAP + m_sub even"
    echo "$d"; return
  fi
  for ((d = (e < GK_LEAF ? e : GK_LEAF); d >= 1; d--)); do
    if (( e % d == 0 && (GK_CAP + d) % 2 == 0 )); then echo "$d"; return; fi
  done
  die "no --m-sub for a GK epoch of $e records (capacity $GK_CAP + m_sub must be even: use an even Q)"
}
EPOCHS=()   # every zk-Analytics epoch size of the run, each once
for q in "${QS[@]}" "$EQ"; do [[ " ${EPOCHS[*]} " == *" $q "* ]] || EPOCHS+=("$q"); done
for q in "${EPOCHS[@]}"; do gk_msub "$q" > /dev/null || exit 2; done

# ------------------------------------------------------------------ plan arithmetic
# leaves of a zkSketch run: N positions, leaf m, period Q (0 = no queries) -> "t split pad"
# (build_query_schedule_batches: each query seals the leaf in progress; the tail is pad-sealed)
leaves() {
  local n=$1 m=$2 q=$3 t s p T per rem tail
  if (( q == 0 )); then
    t=$(( (n + m - 1) / m )); rem=$(( n % m ))
    s=$(( rem ? 1 : 0 )); p=$(( rem ? m - rem : 0 ))
  else
    T=$(( n / q )); per=$(( (q - 1 + m - 1) / m )); rem=$(( (q - 1) % m ))
    tail=$(( n - T * q ))
    t=$(( T * per + (tail + m - 1) / m ))
    s=$(( T * (rem ? 1 : 0) + (tail % m ? 1 : 0) ))
    p=$(( T * (rem ? m - rem : 0) + (tail % m ? m - tail % m : 0) ))
  fi
  echo "$t $s $p"
}
# per-family rates of this machine for the dry-run time plan (memmatch-20261022-205419, 32 cores, ZK on), +/-20%:
# seconds per leaf incl. its merge, seconds per query, and the fixed cost per family and run
# (setup, the audit, verification: that run's wall time minus makespan and queries, HLL 78 s)
declare -A LEAF_S=([cm]=9.7 [hll]=10.0 [bloom]=9.9 [ss]=13.2 [kmv]=10.4 [gk]=10.9)
declare -A QRY_S=([cm]=0.28 [hll]=8.2 [bloom]=0.53 [ss]=0.52 [kmv]=0.45 [gk]=0.92)
declare -A RUN_OVH_S=([cm]=35 [hll]=80 [bloom]=35 [ss]=30 [kmv]=25 [gk]=25)
# zk-Analytics: ~33 s per 2^20-cycle segment (32 cores); aggregation ~5,400 cycles per record
# plus ~0.4M fixed, one segment at least; query proofs at n = 1 and the growth per n (s): CM
# and ss from the measured n = 1..8 series (ss: the SpaceSaving port, whose summaries saturate;
# an upper bound for the Misra-Gries port), the others placeholders (they only change the plan)
SEG_S=33
declare -A Q1_S=([cm]=41 [hll]=23 [ss]=235 [gk]=14 [bloom]=13 [kmv]=14)
declare -A QN_S=([cm]=26 [hll]=20 [ss]=200 [gk]=10 [bloom]=10 [kmv]=10)
epoch_est() { local seg=$(( (5400 * $1 + 400000 + 1048575) / 1048576 )); echo $(( seg * SEG_S )); }
query_est() { echo $(( Q1_S[$1] + QN_S[$1] * ($2 - 1) )); }
zks_est() {  # zks_est <group> <Q>: expected seconds of one exp_compose run
  local g=$1 q=$2 f t s p nq tot=0
  read -r t s p <<< "$(leaves "$N" "${GLEAF[$g]}" "$q")"
  nq=$(( q ? N / q : 0 ))
  for f in ${GFAMS[$g]//,/ }; do
    tot=$(awk -v t="$t" -v l="${LEAF_S[$f]}" -v nq="$nq" -v qs="${QRY_S[$f]}" -v o="${RUN_OVH_S[$f]}" -v a="$tot" \
          'BEGIN{printf "%d", a + t * l + nq * qs + o}')
  done
  echo "$tot"
}
# the zk-Analytics executor (no proof): ~15M cycles/s on this machine, ~5,400 cycles per record
exec_est() { echo $(( 5400 * $1 / 15000000 + 2 )); }   # exec_est <records>: seconds of one guest execution
# the query jobs of the query-cost run (jobs.py; the inserted Bloom key only)
query_jobs() {
  python3 -I "$HERE6/jobs.py" --keys "$KEYS" --m "$EQ" --t "$TQ" --qns "$QNS" --aggr 0 --roots noroot --cm-ref 0 --lines \
    | grep ':query:' | grep -v '^bloom:query:[0-9]*:key:'
}
jobs_at_n() {  # jobs_at_n <jobs> <n...>: the query jobs at those n
  local jobs=$1 j n; shift
  while read -r j; do
    for n in "$@"; do [[ $j =~ ^[a-z]+:query:$n(:|$) ]] && { echo "$j"; break; }; done
  done <<< "$jobs"
}
AGGR_JOBS=(); for f in "${FAMS6[@]}"; do AGGR_JOBS+=("$f:aggr:0:noroot"); done
PROVE_QS=(); for q in "${QS[@]}"; do (( q <= PROVE_MAX_E )) && PROVE_QS+=("$q"); done

# ------------------------------------------------------------------ dry run
if (( DRY )); then
  QJOBS=$(query_jobs) || die "jobs.py failed"
  PJOBS=$(jobs_at_n "$QJOBS" "${PQNS[@]}")
  est_zks=0; est_zka=0; est_exec=0
  echo "query-rate run plan (dry run; nothing is executed)$( (( QUICK )) && echo ": --quick, the tiny smoke shape")"
  echo "  RESULTS=$RESULTS  BASELINE_DIR=$BASELINE_DIR"
  echo "  N=$N stream positions, Q = ${QS[*]} (+ the baseline Q = 0), dataset $DATASET (zkSketch; zk-Analytics reads data/aol.keys),"
  echo "  zkSketch cores $CORES, gate wait <= ${GATE_WAIT_S}s per timed run, SIX_FAIL_FAST=${SIX_FAIL_FAST:-0}"
  echo "  times below are expected run times (+/-20%; the rates of memmatch-20261022-205419, ~${SEG_S} s per 2^20-cycle r0vm segment,"
  echo "  the query-proof slopes of CM and SpaceSaving measured, the others placeholders), without gate waits"
  e=$(exec_est "$N"); est_exec=$((est_exec + e))
  echo "  0. GK capacity preflight: gk_matched --mode aggr --epoch-index 0 --root noroot --epoch-size $N --m-sub $(gk_msub "$N") --capacity $GK_CAP --s 51"
  echo "     (executor only: all $N AOL records through zkSketch's GK rule in $(( N / $(gk_msub "$N") )) apply_batch2 steps; exit 3 = overflow stops the run; ~$(hmin "$e"))"
  e=0; for q in "${QS[@]}"; do e=$(( e + 6 * $(exec_est "$q") )); done
  e=$(( e + 6 * TQ * $(exec_est "$EQ") ))
  while read -r j; do [[ -n $j ]] || continue; f=${j%%:*}; n=$(cut -d: -f3 <<< "$j"); e=$(( e + $(query_est "$f" "$n") * 1048576 / SEG_S / 15000000 + 1 )); done <<< "$QJOBS"
  est_exec=$((est_exec + e))
  echo "  1. zk-Analytics executor (no proof): per Q, zka_epoch_E<Q>/: SIX_M=Q SIX_T=1 run_zka.sh exec; then zka_query_E${EQ}_T${TQ}/:"
  echo "     SIX_M=$EQ SIX_T=$TQ SIX_QNS=$QNS run_zka.sh exec (every family executes all $TQ epochs of $EQ records) + run_zka.sh qexec of the"
  echo "     $(wc -l <<< "$QJOBS") query jobs below (~$(hmin "$e") in all; SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=0 SIX_GK_CAP=$GK_CAP; matched GK --m-sub: $(for q in "${EPOCHS[@]}"; do printf 'E=%s %s; ' "$q" "$(gk_msub "$q")"; done))"
  if [[ $SIX_ZKA_HH == mg ]]; then
    echo "     Eq = $EQ: the KMV / GK summaries hold min(distinct keys, capacity) entries (MG at most that many, fewer after its decrement steps),"
  else
    echo "     Eq = $EQ: the SpaceSaving / KMV / GK summaries hold min(distinct keys, capacity) entries,"
  fi
  echo "     so q(n) depends on the epoch size; the first 4,096 AOL keys hold 2,372 distinct (> the capacity 1,024: saturated), the first 1,000 only 607"
  echo "  2. zkSketch, $(( (${#QS[@]} + 1) * 3 )) timed exp_compose runs (forest, procs, 1 x $CORES cores, EXP_QUERY_KEY_MODE=uniform_stream, EXP_DATASET=$DATASET):"
  printf '     %-10s %-14s %5s %8s %6s %7s %9s %7s   %s\n' run families leaf Q queries leaves '(padded)' pads 'expected'
  for q in 0 "${QS[@]}"; do
    for g in "${GROUPS_[@]}"; do
      read -r t s p <<< "$(leaves "$N" "${GLEAF[$g]}" "$q")"
      e=$(zks_est "$g" "$q"); est_zks=$((est_zks + e))
      printf '     %-10s %-14s %5s %8s %6s %7s %9s %7s   %s\n' "${g}_q$q" "${GFAMS[$g]}" "${GLEAF[$g]}" "$q" "$(( q ? N / q : 0 ))" "$t" "($s)" "$p" "$(hmin "$e")"
    done
  done
  echo "     env per run: EXP_COMPOSE_FAMILY=<families> EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=procs EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=$CORES"
  echo "       EXP_COMPOSE_N=$N EXP_COMPOSE_BATCHES=<leaf> [EXP_COMPOSE_QUERY_EVERY_OPS=<Q>] EXP_QUERY_KEY_MODE=uniform_stream EXP_DATASET=$DATASET <group knobs>"
  for g in "${GROUPS_[@]}"; do echo "       group $g: ${GENV[$g]}"; done
  echo "     about $(hmin "$est_zks") of zkSketch running (per leaf incl. its merge, per query and a fixed cost per family and run)"
  echo "  3. zk-Analytics proofs, run_zka.sh prove:"
  for q in "${QS[@]}"; do
    if (( q <= PROVE_MAX_E )); then
      e=$(( $(epoch_est "$q") * 6 )); est_zka=$((est_zka + e))
      echo "     zka_epoch_E$q/: ${AGGR_JOBS[*]} (about $(hmin "$e"): 6 x $(( (5400 * q + 400000 + 1048575) / 1048576 )) segment(s) x ~${SEG_S} s)"
    else
      echo "     zka_epoch_E$q/: no proof (E = $q > SIX_QR_PROVE_MAX_E=$PROVE_MAX_E): A(E) = the executor's padded cycles / 2^20 x k, k = s per 2^20 padded cycles of this run's proofs"
    fi
  done
  e=0; while read -r j; do [[ -n $j ]] || continue; f=${j%%:*}; n=$(cut -d: -f3 <<< "$j"); e=$((e + $(query_est "$f" "$n"))); done <<< "$PJOBS"
  est_zka=$((est_zka + e))
  echo "     zka_query_E${EQ}_T${TQ}/: $(wc -l <<< "$PJOBS") query proofs at n = $PROVE_QNS (about $(hmin "$e")): $(tr '\n' ' ' <<< "$PJOBS")"
  echo "     about $(hmin "$est_zka") of zk-Analytics proving"
  echo "  4. python3 -I $HERE6/queryrate_model.py \$RESULTS --out-csv \$RESULTS/queryrate.csv --out-md \$RESULTS/queryrate_table.md"
  echo "  expected total about $(hmin $((est_zks + est_zka + est_exec))) of running (zkSketch $(hmin "$est_zks"), zk-Analytics proofs $(hmin "$est_zka"), executors $(hmin "$est_exec"))"
  echo "query jobs (zk-Analytics query executor; those at n = $PROVE_QNS are also proved):"
  echo "$QJOBS"
  exit 0
fi

# ------------------------------------------------------------------ real run
stale_bins() {  # binaries older than their sources (run_all.sh stale_builds; src/proofs is test output)
  local z=$ZKS/scripts/baselines/zka i src bin stale=" "
  local -a pairs=("$z/cyc" "${ZKA_BINS[0]}" "$z/cm_noroot" "${ZKA_BINS[0]}" "$z/hll" "${ZKA_BINS[1]}"
                  "$z/$SIX_ZKA_HH_SRC" "${ZKA_BINS[2]}" "$z/gk_matched" "${ZKA_BINS[3]}" "$z/gk_bm2/core" "${ZKA_BINS[3]}"
                  "$z/bloom" "${ZKA_BINS[4]}" "$z/kmv" "${ZKA_BINS[5]}")
  for ((i = 0; i < ${#pairs[@]}; i += 2)); do
    src=${pairs[i]}; bin=${pairs[i + 1]}
    [[ -x $bin && $stale != *" $bin "* ]] || continue
    if [[ -n $(find "$src" -type f \( -name '*.rs' -o -name Cargo.toml -o -name Cargo.lock \) -newer "$bin" 2>/dev/null | head -1) ]]; then
      echo "$bin"; stale+="$bin "
    fi
  done
  # the matched GK driver links zkSketch as a path dependency; exp_compose is zkSketch itself
  for bin in "${ZKA_BINS[3]}" "$BIN"; do
    [[ -x $bin && $stale != *" $bin "* ]] || continue
    if [[ -n $(find "$ZKS/src" -path "$ZKS/src/proofs" -prune -o -type f -name '*.rs' -newer "$bin" -print 2>/dev/null | head -1;
              find "$ZKS/examples/exp_compose.rs" "$ZKS/Cargo.toml" "$ZKS/Cargo.lock" -newer "$bin" 2>/dev/null | head -1) ]]; then
      echo "$bin"; stale+="$bin "
    fi
  done
}
for b in "${ZKA_BINS[@]}"; do
  [[ -x $b ]] || die "missing $b -- run: $HERE6/run_all.sh build"
  [[ $("$b" --header 2>/dev/null) == *,"$ROOT_COLS" ]] || die "$b was built before the root variants (no --root) -- run: $HERE6/run_all.sh build"
done
[[ -x $BIN ]] || die "missing $BIN -- run: $HERE6/run_all.sh build"
STALE=$(stale_bins)
if [[ -n $STALE && ${SIX_ALLOW_STALE:-0} != 1 ]]; then
  die "built from older sources (run: $HERE6/run_all.sh build; or SIX_ALLOW_STALE=1 to use them anyway): ${STALE//$'\n'/ }"
fi
[[ -z $STALE ]] || echo "note: SIX_ALLOW_STALE=1: using binaries older than their sources: ${STALE//$'\n'/ }" >&2
[[ -s $KEYS ]] || die "missing $KEYS"
(( CORES <= $(nproc) )) || die "SIX_CORES=$CORES > $(nproc) usable CPUs (exp_compose refuses to oversubscribe)"
if [[ -d $RESULTS ]] && [[ -n $(ls -A "$RESULTS" 2>/dev/null) ]]; then die "RESULTS=$RESULTS is not empty; every run needs a fresh directory"; fi
six_prepare_results
six_clean_env
six_check_tmpdir
export RESULTS
SP=${SIX_WORK:-$RESULTS/work}
mkdir -p "$SP" "$ZKS/results" || die "cannot create $SP or $ZKS/results"
SP=$(cd "$SP" && pwd)
BIN_MD5=$(md5sum < "$BIN" | cut -c1-12)
RUNS=$RESULTS/qr_zks_runs.csv
echo "run,group,q,families,family_env,start_iso,gate,gate_waited_s,load1_start,busy_cores_start,load1_end,wall_s,rc,main_peak_rss_mb,desc_peak_rss_mb,tree_peak_rss_mb,status,zks_head,features,bin_md5" > "$RUNS"
dirty() { git -C "$ZKS" status --porcelain -- . ":(exclude)scripts/baselines/zka/results" | wc -l; }

CHILD=
on_signal() {
  if [[ -n $CHILD ]]; then kill -TERM "$CHILD" 2>/dev/null; wait "$CHILD" 2>/dev/null; fi
  echo "queryrate.sh: interrupted" >&2
  [[ -f $RESULTS/manifest.txt ]] && echo "finished=$(date -Is) interrupted" >> "$RESULTS/manifest.txt"
  exit 130
}
trap on_signal INT TERM HUP
trap 'rm -rf "$SP"/proofs_qr_*; rmdir "$SP" 2>/dev/null' EXIT

exec > >(trap '' TERM; exec tee -i -a "$RESULTS/queryrate.log") 2>&1   # tee outlives Ctrl-C / TERM; exits at EOF
{
  echo "# six-sketch comparison run manifest"
  echo "mode=$MODE"
  echo "started=$(date -Is)"
  echo "N=$N Q=$(IFS=,; echo "${QS[*]}") baseline_q0=1 dataset=$DATASET key_mode=uniform_stream cores=$CORES"
  echo "leaf_a=${GLEAF[a]} leaf_b=${GLEAF[b]} leaf_c=${GLEAF[c]} gk_cap=$GK_CAP gk_s=51 gk_rounds=stable bloom_variant=packed (group a = ${GFAMS[a]}, b = ${GFAMS[b]}, c = ${GFAMS[c]})"
  echo "group_a_env=\"${GENV[a]}\" group_b_env=\"${GENV[b]}\" group_c_env=\"${GENV[c]}\""
  echo "Eq=$EQ Tq=$TQ query_points=$QNS prove_max_e=$PROVE_MAX_E prove_qns=$PROVE_QNS zka_roots=noroot zka_cm_ref=0"
  echo "zka_gk=matched (zkSketch's GK rule in their pipeline: capacity $GK_CAP, s 51, implementation $SIX_ZKA_GK_IMPL; m_sub per epoch: $(for q in "${EPOCHS[@]}"; do printf 'E%s=%s ' "$q" "$(gk_msub "$q")"; done))"
  echo "gk_cap_source=$([[ -n ${SIX_QR_GK_CAP:-} ]] && echo "SIX_QR_GK_CAP (NOT the memory-matched 768)" || echo "memmatch default") eq_note=\"q(n) measured at Eq=$EQ-record epochs (KMV/GK summaries hold min(distinct, capacity) entries, MG at most that many)\""
  echo "allow_stale=${SIX_ALLOW_STALE:-0} stale_bins=\"${STALE//$'\n'/ }\""
  ncpu=$(grep -c '^cpu[0-9]' /proc/stat)
  echo "verify_repeats=$VREP gate: GATE_WAIT_S=$GATE_WAIT_S GATE_MAX_LOAD=${GATE_MAX_LOAD:-$(( ncpu >= 16 ? ncpu / 8 : 2 ))} GATE_MAX_BUSY=${GATE_MAX_BUSY:-4} fail_fast=${SIX_FAIL_FAST:-0}"
  echo "zksketch=$(git -C "$ZKS" rev-parse HEAD 2>/dev/null) changed_files=$(git -C "$ZKS" status --porcelain 2>/dev/null | wc -l) checkout=$ZKS"
  echo "exp_compose_md5=$BIN_MD5 features=$FEAT"
  echo "zka=$(git -C "$ZKA" rev-parse HEAD 2>/dev/null) baseline_dir=$BASELINE_DIR"
  echo "host=$(hostname) kernel=$(uname -r) cpu=\"$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)\" nproc=$(nproc) phys_cores=$(six_phys_cores) mem_gib=$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo) / 1024 / 1024 ))"
  echo "cpus_allowed=$(awk '/^Cpus_allowed_list:/{print $2}' /proc/self/status) (the affinity of this process, inherited by both sides)"
  echo "rustc=\"$(rustc --version 2>/dev/null)\" r0vm=\"$(r0vm --version 2>/dev/null)\" rzup=\"$(rzup --version 2>/dev/null)\" python=\"$(python3 --version 2>&1)\""
  echo "risc0_toolchains=\"$(find "${RISC0_HOME:-$HOME/.risc0}/toolchains" -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null)\""
} > "$RESULTS/manifest.txt"
echo "query-rate run$( (( QUICK )) && echo " (--quick: tiny smoke shape)") -> $RESULTS"
echo "  N=$N, Q = ${QS[*]} (+ baseline Q = 0), $(( (${#QS[@]} + 1) * 3 )) zkSketch runs on $CORES cores; zk-Analytics epochs E = ${QS[*]}"
echo "  (proved at E <= $PROVE_MAX_E), query cost at E=$EQ over n = $QNS (proved at n = $PROVE_QNS); GATE_WAIT_S=$GATE_WAIT_S"
[[ $DATASET == aol ]] || echo "  note: SIX_QR_DATASET=$DATASET on the zkSketch side; the zk-Analytics side reads data/aol.keys (different keys)"

RC=0
step() {  # step <title> <cmd...>: run and time one step; its exit status is returned
  local t0=$SECONDS rc title=$1
  shift
  echo
  echo "=== [$(date +%T)] $title"
  "$@"; rc=$?
  echo "=== $(hms $((SECONDS - t0))) rc=$rc: $title"
  echo "step rc=$rc seconds=$((SECONDS - t0)) $title" >> "$RESULTS/manifest.txt"
  return $rc
}
fail_fast() { [[ ${SIX_FAIL_FAST:-0} == 1 ]]; }
zka() {  # zka <subdir> <M> <T> <QNS> <run_zka.sh args...>: one run_zka.sh call in a results subdirectory
  local sub=$1 m=$2 t=$3 qns=$4; shift 4
  env RESULTS="$RESULTS/$sub" SIX_M="$m" SIX_T="$t" SIX_QNS="$qns" SIX_GK_CAP="$GK_CAP" SIX_GK_MSUB="$(gk_msub "$m")" \
      SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=0 SIX_ZKA_GK=matched SIX_ZKA_GK_IMPL="$SIX_ZKA_GK_IMPL" SIX_ZKA_PREFIX=six_zka \
      "$HERE6/run_zka.sh" "$@"
}
gk_preflight() {  # all N AOL records through zkSketch's GK rule at capacity GK_CAP: the matched
  # driver's native chain + one executor run (no proof); exit 3 = overflow (a hard error on both sides)
  local ms out rc
  ms=$(gk_msub "$N") || return 1
  out=$RESULTS/gk_preflight_E$N
  echo "-- gk_matched --mode aggr --epoch-index 0 --root noroot --epoch-size $N --m-sub $ms --capacity $GK_CAP --s 51 --impl $SIX_ZKA_GK_IMPL --batch 8 (executor only: $((N / ms)) apply_batch2 steps) -> $out.csv/.log"
  echo "# gk capacity preflight $(date -Is): ${ZKA_BINS[3]} --mode aggr --epoch-index 0 --root noroot --epoch-size $N --m-sub $ms --capacity $GK_CAP --s 51 --impl $SIX_ZKA_GK_IMPL --batch 8 --keys $KEYS" > "$out.log"
  "${ZKA_BINS[3]}" --header > "$out.csv" 2>> "$out.log"
  "${ZKA_BINS[3]}" --mode aggr --epoch-index 0 --root noroot --epoch-size "$N" --m-sub "$ms" --capacity "$GK_CAP" --s 51 \
      --impl "$SIX_ZKA_GK_IMPL" --batch 8 --keys "$KEYS" >> "$out.csv" 2>> "$out.log"; rc=$?
  echo "# rc=$rc" >> "$out.log"
  if (( rc == 3 )); then
    echo "GK CAPACITY $GK_CAP OVERFLOWS at N=$N (m_sub $ms): every group-c run and the E >= N epoch would fail; raise SIX_QR_GK_CAP (leaves the memory-matched shape) -- see $out.log" >&2
  elif (( rc != 0 )); then
    echo "gk_matched preflight failed (rc=$rc) -- see $out.log" >&2
  else
    [[ $DATASET == aol ]] || echo "note: the preflight chained data/aol.keys; the zkSketch GK runs read SIX_QR_DATASET=$DATASET (not covered)" >&2
    echo "GK capacity $GK_CAP holds over $N AOL records ($((N / ms)) steps of $ms); the split + padded leaves of the Q > 0 runs shift the batch boundaries (checked by those runs)"
  fi
  echo "gk_preflight=$( (( rc == 0 )) && echo ok || echo "rc$rc") N=$N m_sub=$ms capacity=$GK_CAP steps=$((N / ms)) keys=data/aol.keys" >> "$RESULTS/manifest.txt"
  return $rc
}
zks_run() {  # zks_run <group> <Q>: one exp_compose run as run_zks.sh makes it
  local g=$1 q=$2   # (a `local` expands every word before any assignment: two statements)
  local run=${g}_q$q fams=${GFAMS[$g]} lm=${GLEAF[$g]} log csvname envs start gate_s rc wall L1 rl mrss drss trss src status why t s p
  log=$RESULTS/qr_zks_$run.log
  csvname=qr_$run
  rm -f "$ZKS/results/$csvname.csv"
  if gate; then gate_s=quiet; else gate_s="$GATE_WHY"; echo "gate failed for $run: $GATE_WHY -- running anyway, row marked" >&2; fi
  start=$(date -Is)
  envs="EXP_COMPOSE_FAMILY=$fams EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=procs EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=$CORES EXP_COMPOSE_N=$N EXP_COMPOSE_BATCHES=$lm"
  (( q > 0 )) && envs+=" EXP_COMPOSE_QUERY_EVERY_OPS=$q"
  envs+=" EXP_DATASET=$DATASET EXP_QUERY_KEY_MODE=uniform_stream ${GENV[$g]} EXP_QUERY_LOG=1 EXP_VERIFY_REPEATS=$VREP"
  read -r t s p <<< "$(leaves "$N" "$lm" "$q")"
  {
    echo "# six-sketch query-rate zkSketch run $run $(date -Is) host=$(hostname) nproc=$(nproc) gate=$gate_s waited_s=$GATE_WAITED_S load1_start=$GATE_L0 busy_cores_start=$GATE_BUSY"
    echo "# zkSketch HEAD=$(git -C "$ZKS" rev-parse --short=9 HEAD) dirty_files_outside_results=$(dirty) features=$FEAT bin_md5=$BIN_MD5"
    echo "# env: $envs (ZKSKETCH_COMMIT unset = hiding default)"
    echo "# shape: stream_positions=$N query_every=$q queries=$(( q ? N / q : 0 )) leaf_records=$lm expected_leaves=$t expected_padded_leaves=$s expected_pad_records=$p"
    echo "# m0 switches: EXP_FOREST_RETAIN_PREP=${EXP_FOREST_RETAIN_PREP-unset} EXP_MALLOC_TRIM=${EXP_MALLOC_TRIM-unset} EXP_EXIT_BEFORE_AUDIT=${EXP_EXIT_BEFORE_AUDIT-unset} EXP_MERGE_CACHE=${EXP_MERGE_CACHE-unset} EXP_MERGE_CACHE_ENTRIES=${EXP_MERGE_CACHE_ENTRIES-unset} (unset = M0 default on)"
  } > "$log"
  echo "== zkSketch $run ($(date +%T); $fams, leaf $lm, Q=$q: ~$t leaves, ~$(hms "$(zks_est "$g" "$q")")); log $log" >&2
  local T0=$SECONDS
  # shellcheck disable=SC2086  # $envs is a list of NAME=value words
  ( cd "$ZKS" && exec env $envs EXP_OUT="$csvname" EXP_COMPOSE_PROOF_DIR="$SP/proofs_$csvname" \
      "$HERE6/rss_tree.sh" "zks_$run" "$BIN" ) >> "$log" 2>&1 &
  CHILD=$!
  wait "$CHILD"; rc=$?
  CHILD=
  wall=$((SECONDS - T0))
  L1=$(cut -d' ' -f1 /proc/loadavg)
  rl=$(grep '^RSSTREE' "$log" | tail -1)
  mrss=$(sed -n 's/.*main_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
  drss=$(sed -n 's/.*desc_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
  trss=$(sed -n 's/.*tree_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
  # exp_compose prints where it wrote its CSV (the results/ dir of the checkout it was built in);
  # move it next to the log
  src=$(sed -n 's/^results -> //p' "$log" | tail -1)
  status=
  if [[ -n $src && -s $src ]]; then
    [[ $src -ef $RESULTS/qr_zks_$run.csv ]] || mv -f "$src" "$RESULTS/qr_zks_$run.csv" && src=$RESULTS/qr_zks_$run.csv
    # one row per family, every row status=ok
    status=$(awk -F, -v want="$(tr ',' '\n' <<< "$fams" | wc -l)" '
      NR == 1 { for (i = 1; i <= NF; i++) if ($i == "status") k = i; next }
      NF && k { n++; if ($k != "ok") bad++ }
      END { if (!k) print "no status column"; else if (n != want) print "rows=" n " (expected " want ")"; else if (bad) print bad " row(s) not ok"; else print "ok" }' "$RESULTS/qr_zks_$run.csv")
  fi
  echo "# end $(date -Is) rc=$rc wall_s=$wall load1_end=$L1 status=${status:-no_csv}" >> "$log"
  echo "$run,$g,$q,\"$fams\",${GENV[$g]},$start,$gate_s,$GATE_WAITED_S,$GATE_L0,$GATE_BUSY,$L1,$wall,$rc,$mrss,$drss,$trss,${status:-no_csv},$(git -C "$ZKS" rev-parse --short=9 HEAD),$FEAT,$BIN_MD5" >> "$RUNS"
  rm -rf "$SP/proofs_$csvname"
  why=
  (( rc == 0 )) || why+="exit code $rc; "
  [[ -n $src && -s $src ]] || why+="no CSV written (no 'results ->' line); "
  [[ -z $src || $status == ok ]] || why+="CSV $status; "
  if [[ -n $why ]]; then
    echo "FAILED zkSketch $run: ${why%; } -- see $log" >&2
    return 1
  fi
  echo "done $run rc=$rc wall=${wall}s leaves=$(six_csv_col "$RESULTS/qr_zks_$run.csv" t) queries=$(six_csv_col "$RESULTS/qr_zks_$run.csv" n_queries)" >&2
}
zks_all() {  # every (Q, group) run; 1 if any failed
  local q g bad=0
  for q in 0 "${QS[@]}"; do
    for g in "${GROUPS_[@]}"; do
      zks_run "$g" "$q" || { bad=1; fail_fast && return 1; }
    done
  done
  return $bad
}
zka_exec_all() {  # the executor of every epoch size Q (epoch 0 only); 1 if any failed
  local q bad=0
  for q in "${QS[@]}"; do
    echo "-- zka_epoch_E$q: run_zka.sh exec (SIX_M=$q SIX_T=1, matched GK --m-sub $(gk_msub "$q"))"
    zka "zka_epoch_E$q" "$q" 1 1 exec || { bad=1; fail_fast && return 1; }
  done
  return $bad
}
zka_prove_epochs() {  # the aggregation proofs at every Q <= SIX_QR_PROVE_MAX_E; 1 if any failed
  local q bad=0
  for q in "${PROVE_QS[@]}"; do
    echo "-- zka_epoch_E$q: run_zka.sh prove ${AGGR_JOBS[*]}"
    zka "zka_epoch_E$q" "$q" 1 1 prove "${AGGR_JOBS[@]}" || { bad=1; fail_fast && return 1; }
  done
  return $bad
}
summary() {
  local rc=$1
  echo "finished=$(date -Is) rc=$rc" >> "$RESULTS/manifest.txt"
  echo
  if [[ -s $RESULTS/queryrate_table.md ]]; then
    echo "=== tables ($RESULTS/queryrate_table.md)"
    cat "$RESULTS/queryrate_table.md"
  fi
  echo "results:  $RESULTS"
  echo "  manifest.txt                 run configuration, versions and step lines"
  echo "  queryrate_table.md           per Q: zk-Analytics (computed from its proofs and cycle counts) vs zkSketch (measured), families as rows"
  echo "  queryrate.csv                one row per family x Q with every quantity and a provenance string"
  echo "  gk_preflight_E$N.csv/.log     the GK capacity preflight (gk_matched executor row over all N records)"
  echo "  qr_zks_<group>_q<Q>.csv/.log zkSketch runs (group a cm,hll,bloom; b ss,kmv; c gk); qr_zks_runs.csv"
  echo "  zka_epoch_E<Q>/              zk-Analytics executor (+ proofs at E <= $PROVE_MAX_E) of one epoch of Q records"
  echo "  zka_query_E${EQ}_T${TQ}/        zk-Analytics query executor at n = $QNS (+ proofs at n = $PROVE_QNS)"
  if (( rc == 0 )); then echo "$MODE: OK in $(hms $SECONDS)"; else echo "$MODE: FAILED (rc=$rc) after $(hms $SECONDS); see the logs above"; fi
}

# 0. the GK capacity preflight (an overflow is a hard error on both sides: stop at once)
step "GK capacity preflight: zkSketch's GK rule at capacity $GK_CAP over all N=$N AOL records (gk_matched executor; exit 3 = overflow)" gk_preflight; prc=$?
if (( prc == 3 )); then
  RC=1
  echo "stopping: the GK capacity overflow would fail every group-c run" >&2
  summary $RC
  exit $RC
fi
(( prc == 0 )) || RC=1
# 1. the cheap executor runs (a broken driver shows here, before the long zkSketch runs)
if (( RC == 0 )) || ! fail_fast; then
  step "zk-Analytics executor: one epoch of E = Q records for Q = ${QS[*]} (run_zka.sh exec x ${#QS[@]})" zka_exec_all || RC=1
fi
if (( RC == 0 )) || ! fail_fast; then
  step "zk-Analytics executor, query cost: zka_query_E${EQ}_T${TQ} (run_zka.sh exec at SIX_M=$EQ SIX_T=$TQ)" \
    zka "zka_query_E${EQ}_T${TQ}" "$EQ" "$TQ" "$QNS" exec || RC=1
fi
QJOBS=
if (( RC == 0 )) || ! fail_fast; then
  QJOBS=$(query_jobs) || { echo "cannot plan the query jobs (jobs.py failed)"; RC=1; }
  if [[ -n $QJOBS ]]; then
    echo "$QJOBS" > "$RESULTS/zka_query_jobs.txt"
    mapfile -t plan <<< "$QJOBS"
    step "zk-Analytics query executor: run_zka.sh qexec (${#plan[@]} jobs at n = $QNS, for the model)" \
      zka "zka_query_E${EQ}_T${TQ}" "$EQ" "$TQ" "$QNS" qexec "${plan[@]}" || RC=1
  fi
fi
# 2. zkSketch
if (( RC == 0 )) || ! fail_fast; then
  step "zkSketch: $(( (${#QS[@]} + 1) * 3 )) exp_compose runs (Q = 0 ${QS[*]}; groups a b c)" zks_all || RC=1
fi
# 3. zk-Analytics proofs
if (( RC == 0 )) || ! fail_fast; then
  if (( ${#PROVE_QS[@]} )); then
    step "zk-Analytics epoch proofs: run_zka.sh prove ${AGGR_JOBS[*]} at E = ${PROVE_QS[*]}" zka_prove_epochs || RC=1
  else
    echo "no zk-Analytics epoch proof: every Q (${QS[*]}) exceeds SIX_QR_PROVE_MAX_E=$PROVE_MAX_E (A(E) from padded cycles)"
  fi
fi
if (( RC == 0 )) || ! fail_fast; then
  if [[ -n $QJOBS ]]; then
    mapfile -t plan < <(jobs_at_n "$QJOBS" "${PQNS[@]}")
    if (( ${#plan[@]} )); then
      step "zk-Analytics query proofs: run_zka.sh prove ${plan[*]} (calibration at n = $PROVE_QNS)" \
        zka "zka_query_E${EQ}_T${TQ}" "$EQ" "$TQ" "$QNS" prove "${plan[@]}" || RC=1
    fi
  fi
fi
# 4. queryrate_model.py: zk-Analytics totals from its proofs and cycle counts, and the tables (on whatever the run produced)
step "model + tables: queryrate_model.py" python3 -I "$HERE6/queryrate_model.py" "$RESULTS" \
  --out-csv "$RESULTS/queryrate.csv" --out-md "$RESULTS/queryrate_table.md" || RC=1
summary $RC
exit $RC
