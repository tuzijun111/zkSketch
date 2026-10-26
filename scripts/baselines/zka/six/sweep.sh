#!/usr/bin/env bash
# Batch-size sweep of the six-sketch comparison: zkSketch vs zk-Analytics on ONE batch of m = 2^E
# records per size, six families (cm hll ss gk bloom kmv), E from --min to --max (default 6..14),
# one cross-size table at the end.
#   zkSketch:     one leaf per batch (SIX_T=1, k = 1: EXP_COMPOSE_N = EXP_COMPOSE_BATCHES = m), forest,
#                 procs engine, 1 machine x SIX_CORES cores, a query after the leaf (run_zks.sh)
#   zk-Analytics: one aggregation receipt per batch (epoch 0, root variant noroot; no shipped-CM
#                 reference: SIX_ZKA_CM_REF=0), its matched GK with --m-sub m (run_zka.sh)
#
#   sweep.sh [--min E] [--max E] [--sizes 6,8,10] [--quick] [--dry-run] [--resume]
#     --min E, --max E   exponents E of m = 2^E (defaults 6 and 14; 1 <= E <= 20, the keys file)
#     --sizes E,E,...    an explicit list of exponents instead of --min..--max
#     --quick            sizes 6 and 7 only (unless --sizes), GATE_WAIT_S=0, SIX_FAIL_FAST=1, GK capacity 512 unless
#                        SIX_GK_CAP is set (as run_all.sh quick; at 2048 the two GK proofs alone take ~12 min): a
#                        ~15-20 min smoke
#     --dry-run          print the plan (sizes, per-size shape, jobs, time estimates) and run nothing
#     --resume           RESULTS must be an existing sweep directory: sizes whose m<EE>/six_sketch_comparison.csv
#                        exists are skipped; an unfinished size directory is moved to m<EE>.incomplete-<stamp>
#                        and that size runs again from scratch (re-assemble a finished raw directory with
#                        run_all.sh assemble <dir> instead)
# Per size E, in $RESULTS/m<EE> (two-digit E), with RESULTS=<that dir> SIX_M=m SIX_T=1 SIX_GK_CAP SIX_BLOOM_VARIANT
# SIX_ZKA_CM_REF=0 exported to the child scripts:
#   1. run_zks.sh cm hll ss gk bloom kmv     six zkSketch runs (no bloom_absent)
#   2. run_zka.sh exec                       executor, all six, epoch 0 (root variants SIX_ZKA_ROOTS)
#   3. run_zka.sh prove <fam>:aggr:0:<variant> x 6 (x the variants of SIX_ZKA_ROOTS)
#   4. assemble.py <dir> data/aol.keys --zka six_zka --zks six_zksketch --m m --t 1 --out <dir>/six_sketch_comparison.csv
#      + table.py -> <dir>/six_sketch_table.md (--m/--t: the shape even when every zkSketch CSV of the size failed)
# then python3 -I sweep_table.py $RESULTS -> $RESULTS/sweep.csv + sweep_table.md (printed at the end).
# Env:
#   RESULTS          sweep directory (default <repo>/results/six/sweep-<YYYYmmdd-HHMMSS>, sweep-quick-<stamp> with
#                    --quick; git-ignored); must be new or empty unless --resume
#   BASELINE_DIR     zk-Analytics clone + builds (default ~/ext-baselines)
#   SIX_CORES        zkSketch cores (default: physical cores, at most 32)
#   GATE_WAIT_S      seconds each timed job waits for a quiet box (default 600; --quick 0); GATE_MAX_LOAD, GATE_MAX_BUSY
#   SIX_GK_CAP       GK capacity, both sides (default 2048, --quick 512; cap + m must be even); SIX_GK_ROUNDS (stable)
#   SIX_BLOOM_VARIANT  zkSketch Bloom leaf: default per size, packed while 7 x m < 2^16, else omc (the packed leaf's
#                    16-bit timestamps); set it to force one variant for every size (packed is refused at 7 x m >= 2^16)
#   SIX_ZKA_ROOTS    zk-Analytics aggregation variants (default noroot); SIX_ZKA_GK (matched), SIX_ZKA_GK_IMPL (literal)
#   SIX_FAIL_FAST=1  stop at the first failed step (--quick sets it); otherwise a failed run or proof leaves '-'
#                    in the tables, the sweep goes on and its exit status is 1
#   SIX_ALLOW_STALE=1  use binaries older than their sources (refused by default; run_all.sh build refreshes them)
#   EXP_VERIFY_REPEATS and the M0 switches (EXP_FOREST_RETAIN_PREP, EXP_MALLOC_TRIM, EXP_EXIT_BEFORE_AUDIT,
#                    EXP_MERGE_CACHE, EXP_MERGE_CACHE_ENTRIES) pass through to run_zks.sh
#   SIX_M, SIX_T, SIX_N, SIX_QNS, SIX_M_<FAM>, SIX_LEAF, SIX_LEAF_<FAM>, SIX_GK_MSUB, SIX_ZKA_CM_REF, SIX_WORK are set
#                    per size here and ignored from the environment (a note says so)
# Memory: a size's zkSketch leaf is one monolithic proof of m records (the memory-matched budget does not apply):
# the GK and HLL leaves at 2^13-2^14 records take tens of GiB. Times: see --dry-run (an estimate from the memmatch
# leaf rates, the executor's cycle counts and r0vm's 33-44 s per 2^20-cycle segment: about 12-16 h for E = 6..14,
# the 2^14 size alone 5-7 h; the large zkSketch leaves run slower than linear).
# Exit status 0 only if every step of every size succeeded (and the sweep table was written).
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZKS="$(cd "$HERE6/../../../.." && pwd)"
BASELINE_DIR="$(realpath -m -- "${BASELINE_DIR:-$HOME/ext-baselines}")"
export BASELINE_DIR
RZ_HOME=${RISC0_HOME:-$HOME/.risc0}
export PATH="$HOME/.cargo/bin:$RZ_HOME/bin:$PATH"
KEYS=$ZKS/data/aol.keys
KEYS_MD5=01dd7d5c8a73
EB=$BASELINE_DIR/build
ZKA_BINS=("$EB/cyc-t1/release/shipped" "$EB/hll/release/hll" "$EB/zka-mg/release/mg" "$EB/zka-gk/release/gk"
          "$EB/zka-bloom/release/bloom" "$EB/zka-kmv/release/kmv" "$EB/zka-gk-matched/release/gk_matched")
ZKS_BIN=$ZKS/target/release/examples/exp_compose
ROOT_COLS=root_variant,root_construction,variants_agree,state_commit
FAMS=(cm hll ss gk bloom kmv)
GK_S=51            # run_zks.sh: EXP_GK_S=51; run_zka.sh: --s 51
MAX_E=20           # data/aol.keys holds 2^20 keys

six_die() { echo "error: $*" >&2; exit 2; }
usage() { sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
hms() { printf '%dh%02dm%02ds' $(($1 / 3600)) $(($1 % 3600 / 60)) $(($1 % 60)); }
is_uint() { [[ $1 =~ ^[0-9]+$ ]]; }
phys_cores() {
  local n
  n=$(lscpu -p=SOCKET,CORE 2>/dev/null | grep -v '^#' | sort -u | wc -l)
  (( n >= 1 )) || n=$(awk -F: '/^physical id/{p=$2} /^core id/{print p ":" $2}' /proc/cpuinfo 2>/dev/null | sort -u | wc -l)
  (( n >= 1 )) || n=$(nproc)
  echo "$n"
}
default_cores() { local c; c=$(phys_cores); (( c > 32 )) && c=32; (( c > $(nproc) )) && c=$(nproc); echo "$c"; }
roots_ok() {  # roots_ok <list>: a comma list of distinct designed|noroot|legacy
  local v seen=,
  [[ $1 =~ ^(designed|noroot|legacy)(,(designed|noroot|legacy))*$ ]] || return 1
  for v in ${1//,/ }; do [[ $seen == *,$v,* ]] && return 1; seen+="$v,"; done
}

# ------------------------------------------------------------------ options
MIN=6; MAX=14; SIZES=; QUICK=0; DRY=0; RESUME=0
while (( $# )); do
  case $1 in
    --min) MIN=${2:?--min E}; shift ;;
    --max) MAX=${2:?--max E}; shift ;;
    --sizes) SIZES=${2:?--sizes E,E,...}; shift ;;
    --quick) QUICK=1 ;;
    --dry-run) DRY=1 ;;
    --resume) RESUME=1 ;;
    -h|--help) usage; exit 0 ;;
    *) six_die "unknown option $1 (sweep.sh [--min E] [--max E] [--sizes 6,8,10] [--quick] [--dry-run] [--resume])" ;;
  esac
  shift
done
if [[ -z $SIZES ]]; then
  if (( QUICK )); then SIZES=6,7
  else
    is_uint "$MIN" && is_uint "$MAX" && (( MIN <= MAX )) || six_die "--min $MIN / --max $MAX must be integers with min <= max"
    SIZES=$(seq -s, "$MIN" "$MAX")
  fi
fi
[[ $SIZES =~ ^[0-9]+(,[0-9]+)*$ ]] || six_die "--sizes $SIZES must be a comma list of exponents E (m = 2^E)"
ES=()
for e in ${SIZES//,/ }; do
  e=$((10#$e))   # decimal: --sizes 08 (the m08 directory's name) is 8, not an octal error
  (( e >= 1 && e <= MAX_E )) || six_die "size E=$e outside 1..$MAX_E (m = 2^E records of the 2^$MAX_E in data/aol.keys)"
  dup=0; for x in ${ES[@]+"${ES[@]}"}; do (( x == e )) && dup=1; done
  (( dup )) || ES+=("$e")
done
mapfile -t ES < <(printf '%s\n' "${ES[@]}" | sort -n)
SIZES=$(IFS=,; echo "${ES[*]}")
MODE=sweep; (( QUICK )) && MODE=sweep-quick

# ------------------------------------------------------------------ knobs (validated here; six_common.sh re-validates per size)
ignored=()
for v in SIX_M SIX_T SIX_N SIX_QNS SIX_GK_MSUB SIX_LEAF SIX_ZKA_CM_REF SIX_WORK; do [[ -n ${!v:-} ]] && ignored+=("$v=${!v}"); unset "$v"; done
for f in "${FAMS[@]}"; do
  for v in "SIX_M_${f^^}" "SIX_LEAF_${f^^}"; do [[ -n ${!v:-} ]] && ignored+=("$v=${!v}"); unset "$v"; done
done
(( ${#ignored[@]} )) && echo "note: sweep.sh sets the run shape per size; ignoring ${ignored[*]}" >&2
if [[ -n ${SIX_GK_CAP:-} ]]; then GK_CAP=$SIX_GK_CAP; GK_CAP_FROM=env
elif (( QUICK )); then GK_CAP=512; GK_CAP_FROM="--quick default, run_all.sh quick's"   # the matched GK guest's cost grows with capacity + m
else GK_CAP=2048; GK_CAP_FROM=default; fi
is_uint "$GK_CAP" && (( GK_CAP > 0 )) || six_die "SIX_GK_CAP=$GK_CAP must be a positive integer"
SIX_GK_ROUNDS=${SIX_GK_ROUNDS:-stable}
[[ $SIX_GK_ROUNDS == stable || $SIX_GK_ROUNDS == sorted ]] || six_die "SIX_GK_ROUNDS=$SIX_GK_ROUNDS must be stable or sorted"
BLOOM_ENV=${SIX_BLOOM_VARIANT:-}
[[ -z $BLOOM_ENV || $BLOOM_ENV == omc || $BLOOM_ENV == packed ]] || six_die "SIX_BLOOM_VARIANT=$BLOOM_ENV must be omc or packed (unset = per size)"
SIX_ZKA_ROOTS=${SIX_ZKA_ROOTS:-noroot}
roots_ok "$SIX_ZKA_ROOTS" || six_die "SIX_ZKA_ROOTS=$SIX_ZKA_ROOTS must be a comma list of distinct designed, noroot, legacy"
SIX_ZKA_GK=${SIX_ZKA_GK:-matched}; SIX_ZKA_GK_IMPL=${SIX_ZKA_GK_IMPL:-literal}
[[ $SIX_ZKA_GK == matched || $SIX_ZKA_GK == textbook ]] || six_die "SIX_ZKA_GK=$SIX_ZKA_GK: matched or textbook"
[[ $SIX_ZKA_GK_IMPL =~ ^(tuned|fast|fixed_linear|literal)$ ]] || six_die "SIX_ZKA_GK_IMPL=$SIX_ZKA_GK_IMPL: tuned, fast, fixed_linear or literal"
[[ $SIX_ZKA_GK == textbook || ,$SIX_ZKA_ROOTS, != *,legacy,* ]] ||
  six_die "SIX_ZKA_ROOTS=$SIX_ZKA_ROOTS has legacy (the committed 2026-10-09 guests, whose GK is the textbook port): set SIX_ZKA_GK=textbook with it"
SIX_CORES=${SIX_CORES:-$(default_cores)}
is_uint "$SIX_CORES" && (( SIX_CORES > 0 && SIX_CORES <= $(nproc) )) || six_die "SIX_CORES=$SIX_CORES must be in 1..$(nproc) (exp_compose refuses to oversubscribe)"
if (( QUICK )); then GATE_WAIT_S=${GATE_WAIT_S:-0}; SIX_FAIL_FAST=1; else GATE_WAIT_S=${GATE_WAIT_S:-600}; SIX_FAIL_FAST=${SIX_FAIL_FAST:-0}; fi
is_uint "$GATE_WAIT_S" || six_die "GATE_WAIT_S=$GATE_WAIT_S must be an integer"
[[ $SIX_FAIL_FAST == [01] ]] || six_die "SIX_FAIL_FAST=$SIX_FAIL_FAST must be 0 or 1"
export GATE_WAIT_S SIX_FAIL_FAST

bloom_variant() {  # bloom_variant <m>: SIX_BLOOM_VARIANT from the environment, else packed while 7 x m < 2^16
  if [[ -n $BLOOM_ENV ]]; then echo "$BLOOM_ENV"; elif (( 7 * $1 < 65536 )); then echo packed; else echo omc; fi
}
bloom_why() {  # bloom_why <m>: how the variant was chosen (manifest, plan)
  if [[ -n $BLOOM_ENV ]]; then echo "env"; elif (( 7 * $1 < 65536 )); then echo "auto: 7 x m < 2^16"; else echo "auto: 7 x m >= 2^16, the packed leaf's 16-bit timestamps"; fi
}
for e in "${ES[@]}"; do
  m=$((1 << e))
  (( (GK_CAP + m) % 2 == 0 )) || six_die "SIX_GK_CAP + m = $GK_CAP + $m is odd at E=$e: zkSketch's GK leaf needs an even table"
  [[ $(bloom_variant "$m") == packed ]] && (( 7 * m >= 65536 )) &&
    six_die "SIX_BLOOM_VARIANT=packed but 7 x m = $((7 * m)) >= 2^16 at E=$e (m=$m): the packed Bloom leaf needs 7 x m < 2^16; unset it (per-size default) or set omc"
done
jobs_of() {  # jobs_of: the zk-Analytics prove jobs of one size (every family's epoch 0, per root variant)
  local f v
  for v in ${SIX_ZKA_ROOTS//,/ }; do for f in "${FAMS[@]}"; do echo "$f:aggr:0:$v"; done; done
}
mapfile -t JOBS < <(jobs_of)
NROOTS=$(tr ',' '\n' <<< "$SIX_ZKA_ROOTS" | wc -l)

# ------------------------------------------------------------------ time estimates (the --dry-run plan; rough)
# zk-Analytics: user cycles of one aggregation = cycles per record x m + ~0.3M fixed, from the memmatch executor rows
# (cm 5,400, hll 5,000, ss 5,900, bloom 5,400, kmv 5,200); the matched GK guest is dominated by its apply_batch2 step
# over the T = capacity + m table, not by m: ~290 x T x log2(T) + ~3,700 per record read + ~0.8M fixed (measured
# user cycles per epoch 7.6M at cap 384 / 4 steps of 128, 3.4M at 512 / 256, 25.3M at 768 / 4 x 512). Segments of
# 2^20 cycles (one at least), 33-44 s each on 32 cores (r0vm: 44 s on every aggregation proof of memmatch-20261022,
# 29-42 s in the quick runs). zkSketch: the memmatch leaf rates taken linear in m (cm/hll/bloom ~5 s per 1,024
# records, ss/kmv ~7 s per 4,096; gk ~7 s per 1,280 table entries = capacity + m) + a fixed part per run (worker
# spawn, VK derivation, audit, the query: ~25 s; hll ~60 s, its decode query alone ~8 s: 97 s wall for 4 leaves of
# 128 in memmatch-quick, cm 39 s); no composition at k = 1. The large zkSketch leaves (HLL, GK at 2^13-2^14) run
# slower than linear: a lower bound there.
SEG_LO=33; SEG_HI=44   # seconds per 2^20-cycle segment, the measured range
est_zka_seg() {  # est_zka_seg <fam> <m> -> segments of one aggregation proof
  awk -v f="$1" -v m="$2" -v cap="$GK_CAP" 'BEGIN {
    if (f == "gk") { T = cap + m; c = 290 * T * log(T) / log(2) + 3700 * m + 800000 }
    else { r = (f == "ss") ? 5900 : (f == "hll") ? 5000 : (f == "kmv") ? 5200 : 5400; c = r * m + 300000 }
    s = int((c + 1048575) / 1048576); if (s < 1) s = 1; print s }'
}
est_zks() {  # est_zks <fam> <m> -> seconds of one zkSketch run
  awk -v f="$1" -v m="$2" -v cap="$GK_CAP" 'BEGIN { t = (f == "gk") ? 7 / 1280 * (cap + m) : (f == "ss" || f == "kmv") ? 7 / 4096 * m : 5 / 1024 * m
    o = (f == "hll") ? 60 : 25; printf "%d", o + t }'
}
gk_need() {  # gk_need <m>: exp_compose's capacity hint, s x log2(max(N/s, 2)) at N = m
  awk -v m="$1" -v s="$GK_S" 'BEGIN { x = m / s; if (x < 2) x = 2; n = s * log(x) / log(2); printf "%d", (n == int(n)) ? n : int(n) + 1 }'
}
size_estimate() {  # size_estimate <m> -> "<zks_s> <zka_s at SEG_LO> <zka_s at SEG_HI> <segments> <min>-<max segments>"
  local m=$1 f zs=0 segs=0 seg lo= hi=
  for f in "${FAMS[@]}"; do
    zs=$((zs + $(est_zks "$f" "$m")))
    seg=$(est_zka_seg "$f" "$m")
    segs=$((segs + seg)); [[ -z $lo ]] || (( seg < lo )) && lo=$seg; [[ -z $hi ]] || (( seg > hi )) && hi=$seg
  done
  segs=$((segs * NROOTS))
  echo "$zs $((segs * SEG_LO + 30)) $((segs * SEG_HI + 30)) $segs $lo-$hi"
}

# ------------------------------------------------------------------ dry run
if (( DRY )); then
  echo "batch-size sweep plan (dry run; nothing is executed)$( (( QUICK )) && echo ": --quick, the smoke sizes")"
  echo "  RESULTS=${RESULTS:-$ZKS/results/six/$MODE-<YYYYmmdd-HHMMSS>}  BASELINE_DIR=$BASELINE_DIR"
  echo "  sizes: E = $SIZES (m = 2^E AOL records, ONE batch per size: zkSketch one leaf = the batch (SIX_T=1, k = 1,"
  echo "         EXP_COMPOSE_N = EXP_COMPOSE_BATCHES = m, a query after it); zk-Analytics one epoch-0 receipt)"
  echo "  fixed: zkSketch cores $SIX_CORES, gate wait <= ${GATE_WAIT_S}s per timed job, SIX_FAIL_FAST=$SIX_FAIL_FAST; GK capacity $GK_CAP ($GK_CAP_FROM; rounds $SIX_GK_ROUNDS, s = $GK_S)"
  echo "         both sides; zk-Analytics root variants $SIX_ZKA_ROOTS, no shipped-CM reference (SIX_ZKA_CM_REF=0);"
  if [[ $SIX_ZKA_GK == matched ]]; then
    echo "         zk-Analytics GK: SIX_ZKA_GK=matched (zkSketch's GK rule in their pipeline: --capacity $GK_CAP --m-sub m --s $GK_S --impl $SIX_ZKA_GK_IMPL, 1 apply_batch2 step per batch)"
  else
    echo "         zk-Analytics GK: SIX_ZKA_GK=textbook (textbook Greenwald-Khanna: a reference, not zkSketch's algorithm)"
  fi
  echo "         Bloom leaf: $( [[ -n $BLOOM_ENV ]] && echo "SIX_BLOOM_VARIANT=$BLOOM_ENV for every size (env)" || echo "packed while 7 x m < 2^16 (m <= 8192), else omc (SIX_BLOOM_VARIANT unset)")"
  echo "  per size (estimates: zk-Analytics 5,000-5,900 cycles/record + 0.3M (gk: 290 x T log2 T + 3,700/record + 0.8M, T = capacity $GK_CAP + m),"
  echo "            2^20-cycle segments x ${SEG_LO}-${SEG_HI} s, 6 proofs x $NROOTS variant(s); zkSketch the memmatch leaf rates linear in m (gk in capacity + m)"
  echo "            + 25 s per run (hll 60 s), a lower bound for the large HLL / GK leaves; gate waits excluded):"
  printf '    %-3s %-9s %-4s %-7s %-20s %-16s %-44s %s\n' E m dir bloom 'gk cap (s=51 needs ~)' 'zkSketch ~6 runs' "zk-Analytics ~6 proofs (${SEG_LO}-${SEG_HI} s/segment)" '~size'
  TOT_LO=0; TOT_HI=0
  for e in "${ES[@]}"; do
    m=$((1 << e)); read -r zs za_lo za_hi segs seg <<< "$(size_estimate "$m")"
    TOT_LO=$((TOT_LO + zs + za_lo)); TOT_HI=$((TOT_HI + zs + za_hi))
    printf '    %-3s %-9s %-4s %-7s %-20s %-16s %-44s %s\n' "$e" "$m" "m$(printf '%02d' "$e")" "$(bloom_variant "$m")" \
      "$GK_CAP ($(gk_need "$m"))" "$(hms "$zs")" "$(hms "$za_lo")-$(hms "$za_hi") ($segs segments, $seg each)" "$(hms $((zs + za_lo)))-$(hms $((zs + za_hi)))"
  done
  echo "  total: ~$(hms "$TOT_LO")-$(hms "$TOT_HI") of running (estimate), plus gate waits (<= ${GATE_WAIT_S}s before each of the $(( (6 + ${#JOBS[@]}) * ${#ES[@]} )) timed jobs)"
  echo "  steps per size E (RESULTS=\$RESULTS/m<EE>; env RESULTS=<that dir> SIX_M=m SIX_T=1 SIX_GK_CAP=$GK_CAP SIX_GK_ROUNDS=$SIX_GK_ROUNDS SIX_BLOOM_VARIANT=<per size>"
  echo "                    SIX_ZKA_CM_REF=0 SIX_ZKA_ROOTS=$SIX_ZKA_ROOTS SIX_ZKA_GK=$SIX_ZKA_GK SIX_ZKA_GK_IMPL=$SIX_ZKA_GK_IMPL SIX_CORES=$SIX_CORES GATE_WAIT_S=$GATE_WAIT_S SIX_FAIL_FAST=$SIX_FAIL_FAST):"
  echo "    1. zkSketch, 6 timed runs:   $HERE6/run_zks.sh ${FAMS[*]}"
  echo "    2. zk-Analytics executor:    $HERE6/run_zka.sh exec        (epoch 0 of all six under root variants $SIX_ZKA_ROOTS)"
  echo "    3. zk-Analytics, ${#JOBS[@]} timed proofs: $HERE6/run_zka.sh prove ${JOBS[*]}"
  echo "    4. python3 -I $HERE6/assemble.py \$RESULTS/m<EE> $KEYS --zka six_zka --zks six_zksketch --m <m> --t 1 --out \$RESULTS/m<EE>/six_sketch_comparison.csv"
  echo "       python3 -I $HERE6/table.py \$RESULTS/m<EE>/six_sketch_comparison.csv --zka six_zka > \$RESULTS/m<EE>/six_sketch_table.md"
  echo "  then: python3 -I $HERE6/sweep_table.py \$RESULTS --out-csv \$RESULTS/sweep.csv --out-md \$RESULTS/sweep_table.md"
  echo "  a failed run or proof leaves '-' in the tables and makes the exit status 1$( [[ $SIX_FAIL_FAST == 1 ]] && echo " (SIX_FAIL_FAST=1: the sweep stops at the first failed step)")"
  echo "jobs (per size):"
  printf '%s\n' "${JOBS[@]}"
  exit 0
fi

# ------------------------------------------------------------------ preflight (as run_all.sh: built, current, --root-capable)
stale_builds() {
  local z=$ZKS/scripts/baselines/zka i src bin
  local -a pairs=("$z/cyc" "${ZKA_BINS[0]}" "$z/cm_noroot" "${ZKA_BINS[0]}" "$z/hll" "${ZKA_BINS[1]}"
                  "$z/mg" "${ZKA_BINS[2]}" "$z/gk" "${ZKA_BINS[3]}" "$z/bloom" "${ZKA_BINS[4]}"
                  "$z/kmv" "${ZKA_BINS[5]}" "$z/gk_matched" "${ZKA_BINS[6]}" "$z/gk_bm2/core" "${ZKA_BINS[6]}")
  local stale=" "
  for ((i = 0; i < ${#pairs[@]}; i += 2)); do
    src=${pairs[i]}; bin=${pairs[i + 1]}
    [[ -x $bin && $stale != *" $bin "* ]] || continue
    if [[ -n $(find "$src" -type f \( -name '*.rs' -o -name Cargo.toml -o -name Cargo.lock \) -newer "$bin" 2>/dev/null | head -1) ]]; then
      echo "$bin"; stale+="$bin "
    fi
  done
  bin=${ZKA_BINS[6]}   # the matched GK driver links zkSketch (path dependency)
  if [[ -x $bin && $stale != *" $bin "* ]] && [[ -n $(find "$ZKS/src" -path "$ZKS/src/proofs" -prune -o -type f -name '*.rs' -newer "$bin" -print 2>/dev/null | head -1;
        find "$ZKS/Cargo.toml" "$ZKS/Cargo.lock" -newer "$bin" 2>/dev/null | head -1) ]]; then
    echo "$bin"
  fi
  if [[ -x $ZKS_BIN ]] && [[ -n $(find "$ZKS/src" -path "$ZKS/src/proofs" -prune -o -type f -name '*.rs' -newer "$ZKS_BIN" -print 2>/dev/null | head -1;
        find "$ZKS/examples/exp_compose.rs" "$ZKS/Cargo.toml" "$ZKS/Cargo.lock" -newer "$ZKS_BIN" 2>/dev/null | head -1) ]]; then
    echo "$ZKS_BIN"
  fi
}
preflight() {
  local b stale
  for b in "${ZKA_BINS[@]}" "$ZKS_BIN"; do [[ -x $b ]] || six_die "missing $b -- run: $HERE6/run_all.sh build"; done
  [[ -s $KEYS ]] || six_die "missing $KEYS (it is tracked in git; re-checkout data/aol.keys)"
  [[ $(md5sum < "$KEYS" | cut -c1-12) == "$KEYS_MD5" ]] || six_die "$KEYS: md5 differs from $KEYS_MD5 (git checkout -- data/aol.keys)"
  command -v python3 >/dev/null || six_die "python3 missing"
  stale=$(stale_builds)
  if [[ -n $stale && ${SIX_ALLOW_STALE:-0} != 1 ]]; then
    six_die "built from older sources (run: $HERE6/run_all.sh build; or SIX_ALLOW_STALE=1 to use them anyway): $(echo $stale)"
  fi
  for b in "${ZKA_BINS[@]}"; do
    [[ $("$b" --header 2>/dev/null) == *,"$ROOT_COLS" ]] || six_die "$b was built before the root variants (no --root; run: $HERE6/run_all.sh build)"
  done
}
preflight

# ------------------------------------------------------------------ results directory, log, manifest
SWEEP=${RESULTS:-$ZKS/results/six/$MODE-$(date +%Y%m%d-%H%M%S)}
SWEEP=$(realpath -m -- "$SWEEP")
if (( RESUME )); then
  [[ -n ${RESULTS:-} && -f $SWEEP/manifest.txt ]] || six_die "--resume needs RESULTS=<an existing sweep directory with manifest.txt> (have ${RESULTS:-unset})"
  grep -q '^mode=sweep' "$SWEEP/manifest.txt" || six_die "$SWEEP/manifest.txt is not a sweep's (mode=sweep...)"
elif [[ -d $SWEEP ]] && [[ -n $(ls -A "$SWEEP" 2>/dev/null) ]]; then
  six_die "RESULTS=$SWEEP is not empty; every sweep needs a fresh directory (or --resume)"
fi
mkdir -p "$SWEEP" || six_die "cannot create $SWEEP"
if [[ -n $(git -C "$SWEEP" ls-files -- . 2>/dev/null | head -1) ]]; then six_die "RESULTS=$SWEEP is git-tracked"; fi
unset RESULTS   # the child scripts get RESULTS=<size dir>
exec > >(trap '' TERM; exec tee -i -a "$SWEEP/sweep.log") 2>&1   # tee outlives Ctrl-C / TERM; exits at EOF

write_manifest() {
  local ncpu; ncpu=$(grep -c '^cpu[0-9]' /proc/stat)   # gate.sh's default GATE_MAX_LOAD
  {
    echo "# six-sketch comparison run manifest"
    echo "mode=$MODE"
    echo "started=$(date -Is)"
    echo "sizes=$SIZES (E; m = 2^E records, one batch per size: SIX_T=1, one zkSketch leaf = the batch, k = 1)"
    echo "gk_cap=$GK_CAP gk_cap_from=$GK_CAP_FROM gk_rounds=$SIX_GK_ROUNDS gk_s=$GK_S bloom_variant=$( [[ -n $BLOOM_ENV ]] && echo "$BLOOM_ENV (env)" || echo "auto (packed while 7 x m < 2^16, else omc; per size below)") query_points=1 aggr_epochs=0 cores=$SIX_CORES"
    echo "zka_roots=$SIX_ZKA_ROOTS (aggregation root variants executed and proved) zka_cm_ref=0 (no separate CM reference)"
    if [[ $SIX_ZKA_GK == matched ]]; then
      echo "zka_gk=matched (zkSketch's GK rule in their pipeline: capacity $GK_CAP, s $GK_S, m_sub = the batch m = 1 apply_batch2 step per batch, implementation $SIX_ZKA_GK_IMPL)"
    else
      echo "zka_gk=textbook (textbook Greenwald-Khanna, NOT zkSketch's algorithm: a reference)"
    fi
    echo "verify_repeats=${EXP_VERIFY_REPEATS:-5} gate: GATE_WAIT_S=$GATE_WAIT_S GATE_MAX_LOAD=${GATE_MAX_LOAD:-$(( ncpu >= 16 ? ncpu / 8 : 2 ))} GATE_MAX_BUSY=${GATE_MAX_BUSY:-4} fail_fast=$SIX_FAIL_FAST"
    echo "zksketch=$(git -C "$ZKS" rev-parse HEAD 2>/dev/null) changed_files=$(git -C "$ZKS" status --porcelain 2>/dev/null | wc -l) checkout=$ZKS"
    echo "exp_compose_md5=$(md5sum < "$ZKS_BIN" | cut -c1-12)"
    echo "zka=$(git -C "$BASELINE_DIR/zka" rev-parse HEAD 2>/dev/null) baseline_dir=$BASELINE_DIR"
    echo "host=$(hostname) kernel=$(uname -r) cpu=\"$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)\" nproc=$(nproc) phys_cores=$(phys_cores) mem_gib=$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo) / 1024 / 1024 ))"
    echo "rustc=\"$(rustc --version 2>/dev/null)\" r0vm=\"$(r0vm --version 2>/dev/null)\" rzup=\"$(rzup --version 2>/dev/null)\" python=\"$(python3 --version 2>&1)\""
    echo "risc0_toolchains=\"$(find "$RZ_HOME/toolchains" -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null)\""
    echo "cpus_allowed=$(awk '/^Cpus_allowed_list:/{print $2}' /proc/self/status) (this process's affinity, e.g. taskset -c 0-31: zkSketch's worker and r0vm inherit it)"
  } > "$SWEEP/manifest.txt"
}
if (( RESUME )); then
  echo "resumed=$(date -Is) sizes=$SIZES zksketch=$(git -C "$ZKS" rev-parse HEAD 2>/dev/null) exp_compose_md5=$(md5sum < "$ZKS_BIN" | cut -c1-12) cpus_allowed=$(awk '/^Cpus_allowed_list:/{print $2}' /proc/self/status)" >> "$SWEEP/manifest.txt"
else
  write_manifest
fi

on_int() {
  echo "sweep.sh: interrupted" >&2
  [[ -f $SWEEP/manifest.txt ]] && echo "finished=$(date -Is) interrupted" >> "$SWEEP/manifest.txt"
  exit 130
}
trap on_int INT TERM HUP

# ------------------------------------------------------------------ steps
step() {  # step <size tag> <title> <cmd...>: run and time one step; its exit status is returned
  local tag=$1 title=$2 t0=$SECONDS rc
  shift 2
  echo
  echo "=== [$(date +%T)] $tag $title"
  "$@"; rc=$?
  echo "=== $(hms $((SECONDS - t0))) rc=$rc: $tag $title"
  echo "step rc=$rc seconds=$((SECONDS - t0)) $tag $title" >> "$SWEEP/manifest.txt"
  return $rc
}
run_child() {  # run_child <size dir> <m> <bloom variant> <script> [args...]: a six/ script with this size's shape
  local sub=$1 m=$2 bv=$3
  shift 3
  env RESULTS="$sub" SIX_M="$m" SIX_T=1 SIX_GK_CAP="$GK_CAP" SIX_GK_ROUNDS="$SIX_GK_ROUNDS" SIX_BLOOM_VARIANT="$bv" \
      SIX_ZKA_CM_REF=0 SIX_ZKA_ROOTS="$SIX_ZKA_ROOTS" SIX_ZKA_GK="$SIX_ZKA_GK" SIX_ZKA_GK_IMPL="$SIX_ZKA_GK_IMPL" \
      SIX_CORES="$SIX_CORES" SIX_ZKS_PREFIX=six_zksketch SIX_ZKA_PREFIX=six_zka "$@"
}
csv_col() {  # csv_col <csv> <column>: that column of the first data row (six_common.sh's six_csv_col)
  awk -F, -v c="$2" 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == c) k = i } NR == 2 && k { print $k }' "$1" 2>/dev/null
}
quarantine_failed_zks() {  # quarantine_failed_zks <size dir>: a zkSketch CSV whose status is not ok (e.g. too_large)
  local f csv st                    # would stop assemble.py for the whole size: set it aside (the log stays)
  for f in "${FAMS[@]}"; do
    csv=$1/six_zksketch_$f.csv
    [[ -s $csv ]] || continue
    st=$(csv_col "$csv" status)
    if [[ $st != ok ]]; then
      mv -f "$csv" "$csv.failed"
      echo "note: zkSketch $f: status=${st:-missing}; $csv set aside as .failed (its rows show '-')"
    fi
  done
}
assemble_and_table() {  # assemble_and_table <size dir> <m>: --m/--t = the sweep's shape, so the zk-Analytics proofs of a
  # size whose zkSketch CSVs all failed (or were never written) are still tabled (assemble.py would assume m=2048, T=8)
  python3 -I "$HERE6/assemble.py" "$1" "$KEYS" --zka six_zka --zks six_zksketch --m "$2" --t 1 --out "$1/six_sketch_comparison.csv" || return 1
  python3 -I "$HERE6/table.py" "$1/six_sketch_comparison.csv" --zka six_zka > "$1/six_sketch_table.md" || return 1
}

echo "batch-size sweep$( (( QUICK )) && echo " (--quick: the smoke sizes)")$( (( RESUME )) && echo " (--resume)") -> $SWEEP"
echo "  sizes E = $SIZES (m = 2^E records, one batch per size); zkSketch $SIX_CORES cores, one leaf per batch (SIX_T=1);"
echo "  zk-Analytics epoch-0 receipts under root variants $SIX_ZKA_ROOTS, no CM reference; GK capacity $GK_CAP (rounds $SIX_GK_ROUNDS, s = $GK_S);"
echo "  Bloom leaf $( [[ -n $BLOOM_ENV ]] && echo "$BLOOM_ENV (env)" || echo "packed while 7 x m < 2^16, else omc"); GATE_WAIT_S=$GATE_WAIT_S per timed job; SIX_FAIL_FAST=$SIX_FAIL_FAST"
RC=0; NDONE=0; NSKIP=0; NFAIL=0
for e in "${ES[@]}"; do
  m=$((1 << e)); EE=$(printf '%02d' "$e"); tag=m$EE; sub=$SWEEP/$tag; bv=$(bloom_variant "$m")
  if (( RESUME )) && [[ -s $sub/six_sketch_comparison.csv ]]; then
    echo; echo "##### $tag (m=$m): finished already, skipped (--resume)"
    echo "size $tag E=$e m=$m skipped=resume dir=$sub" >> "$SWEEP/manifest.txt"
    NSKIP=$((NSKIP + 1))
    continue
  fi
  if [[ -d $sub ]] && [[ -n $(ls -A "$sub" 2>/dev/null) ]]; then
    old=$sub.incomplete-$(date +%Y%m%d-%H%M%S)
    mv "$sub" "$old" || six_die "cannot move the unfinished $sub aside"
    echo "note: $sub was unfinished (no six_sketch_comparison.csv); moved to $old, running the size again"
  fi
  mkdir -p "$sub" || six_die "cannot create $sub"
  printf '%s\n' "${JOBS[@]}" > "$sub/zka_plan.txt"
  t0=$SECONDS; src=0
  echo; echo "##### [$(date +%T)] size $tag: m = 2^$e = $m records, bloom $bv ($(bloom_why "$m")), gk cap $GK_CAP -> $sub"
  echo "size $tag E=$e m=$m bloom_variant=$bv ($(bloom_why "$m")) gk_cap=$GK_CAP dir=$sub started=$(date -Is)" >> "$SWEEP/manifest.txt"
  step "$tag" "zkSketch: run_zks.sh (6 runs, m=$m)" run_child "$sub" "$m" "$bv" "$HERE6/run_zks.sh" "${FAMS[@]}" || src=1
  quarantine_failed_zks "$sub"
  if (( src == 0 || SIX_FAIL_FAST == 0 )); then
    step "$tag" "zk-Analytics executor: run_zka.sh exec (root variants $SIX_ZKA_ROOTS, m=$m)" run_child "$sub" "$m" "$bv" "$HERE6/run_zka.sh" exec || src=1
  fi
  if (( src == 0 || SIX_FAIL_FAST == 0 )); then
    step "$tag" "zk-Analytics proofs: run_zka.sh prove (${#JOBS[@]} jobs, m=$m)" run_child "$sub" "$m" "$bv" "$HERE6/run_zka.sh" prove "${JOBS[@]}" || src=1
  fi
  if (( src == 0 || SIX_FAIL_FAST == 0 )); then
    step "$tag" "assemble + table" assemble_and_table "$sub" "$m" || src=1
  fi
  echo "size $tag rc=$src seconds=$((SECONDS - t0)) finished=$(date -Is)" >> "$SWEEP/manifest.txt"
  if (( src )); then
    RC=1; NFAIL=$((NFAIL + 1))
    echo "size $tag (m=$m): FAILED step(s); see $SWEEP/sweep.log and the logs in $sub"
    if [[ $SIX_FAIL_FAST == 1 ]]; then echo "sweep.sh: stopping at the first failed size (SIX_FAIL_FAST=1)"; break; fi
  else
    NDONE=$((NDONE + 1))
    echo "size $tag (m=$m): ok in $(hms $((SECONDS - t0)))"
  fi
done
step sweep "sweep table: sweep_table.py ($SWEEP)" python3 -I "$HERE6/sweep_table.py" "$SWEEP" --out-csv "$SWEEP/sweep.csv" --out-md "$SWEEP/sweep_table.md" || RC=1
echo "finished=$(date -Is) rc=$RC sizes_ok=$NDONE sizes_failed=$NFAIL sizes_skipped=$NSKIP" >> "$SWEEP/manifest.txt"
echo
if [[ -s $SWEEP/sweep_table.md ]]; then
  echo "=== sweep table ($SWEEP/sweep_table.md)"
  cat "$SWEEP/sweep_table.md"
fi
echo "results:  $SWEEP"
echo "  manifest.txt                 configuration, versions, per-size and per-step times"
echo "  sweep.csv / sweep_table.md   one row per family x m: prove, ms per record, zkA / zkS, verify, proof bytes, peak RSS, zkS variant"
echo "  m<EE>/                       one size: six_sketch_comparison.csv + six_sketch_table.md (assemble.py / table.py), zkSketch"
echo "                               six_zksketch_*.csv/.log, zk-Analytics six_zka_*.csv/.log, zka_plan.txt"
if (( RC == 0 )); then echo "$MODE: OK in $(hms $SECONDS) ($NDONE size(s)$( (( NSKIP )) && echo ", $NSKIP skipped"))"
else echo "$MODE: FAILED (rc=$RC) after $(hms $SECONDS): $NFAIL size(s) with failed steps, $NDONE ok$( (( NSKIP )) && echo ", $NSKIP skipped"); see the logs above"; fi
exit $RC
