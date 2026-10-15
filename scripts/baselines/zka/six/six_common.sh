# Sourced by the six-sketch scripts (run_all.sh, run_zks.sh, run_zka.sh, prof_exec.sh).
# Adds to ../common.sh (HERE, ZKS, BASELINE_DIR, ZKA, RESULTS, PATH):
#   RESULTS     default <repo>/results/six/manual (git-ignored). The six-sketch scripts refuse
#               a directory that holds git-tracked files, such as the committed reference
#               results in scripts/baselines/zka/results (override: SIX_ALLOW_TRACKED=1).
#   SIX_M       records per epoch / batch       (default 2048)
#   SIX_T       epochs / batches                (default 8, or SIX_N / SIX_M when only SIX_N is set)
#   SIX_N       records in all = SIX_M x SIX_T  (default 16384)
#   SIX_QNS     query points n of the zk-Analytics side (default: powers of two <= T)
#   SIX_GK_CAP  zkSketch GK capacity            (default 2048)
#   SIX_ZKA_GK  matched (default) | textbook: the zk-Analytics side's GK. matched = our port
#               of zkSketch's GK rule (two-sided band-merge, apply_batch2) in their pipeline
#               (../gk_matched): the SAME algorithm as the zkSketch side, with zkSketch's
#               capacity SIX_GK_CAP, s = 51 and leaf size SIX_GK_MSUB, the state carried from
#               epoch to epoch. textbook = Greenwald-Khanna 2001 rebuilt per epoch with a
#               query-time merge (../gk): a DIFFERENT algorithm, kept as a labelled reference
#               (the committed 2026-10-09 rows are textbook).
#   SIX_GK_MSUB records per zkSketch GK leaf (default SIX_M, the zkSketch side's batch). The
#               matched zk-Analytics GK applies each SIX_M-record epoch as SIX_M / SIX_GK_MSUB
#               successive apply_batch2 steps: exactly zkSketch's leaves. Set it only to match
#               a zkSketch GK run with smaller leaves than SIX_M (a memory-matched forest, e.g.
#               zkSketch SIX_M=128 SIX_T=16 SIX_GK_CAP=384 against zk-Analytics SIX_M=2048
#               SIX_T=1 SIX_GK_MSUB=128 SIX_GK_CAP=384); run_zks.sh always uses SIX_M.
#   SIX_ZKA_GK_IMPL  fast (default) | fixed_linear | literal: the matched GK guest's
#               implementation of the one transition (same state; fast = the efficient
#               data-dependent one a zkVM programmer would write, the steelman).
#   SIX_CORES   zkSketch EXP_COMPOSE_CORES      (default: physical cores, at most 32)
#   SIX_ZKA_ROOTS  root variants of the zk-Analytics aggregation proofs, a comma list of
#               designed | noroot | legacy (default noroot, the headline): the variants
#               `run_zka.sh exec` executes (and `jobs.py --roots` plans). ../README.md,
#               "Root variants of the zk-Analytics aggregation proofs", says what they are.
#   SIX_ZKA_CM_REF  1 (default) or 0. 1: their shipped CM aggregation (variant designed, their
#               aggr_cm unchanged, incl. its per-row Merkle roots) is also run, as a REFERENCE,
#               unless SIX_ZKA_ROOTS already has designed or legacy (both are that same guest):
#               `run_zka.sh exec` then also executes designed, for all six families (executor
#               only, cheap: it gives the reference's cycle counts and the root-work table), and
#               `jobs.py --cm-ref 1` plans cm:aggr:<e>:designed at the proved epochs.
# The defaults are the paper configuration.
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${RESULTS:=$(cd "$HERE6/../../../.." && pwd)/results/six/manual}"
source "$HERE6/../common.sh"

six_die() { echo "error: $*" >&2; exit 2; }
six_is_uint() { [[ $1 =~ ^[0-9]+$ ]]; }

SIX_M=${SIX_M:-2048}
if [[ -z ${SIX_T:-} && -n ${SIX_N:-} ]]; then  # older calls set SIX_N (and SIX_M) only
  six_is_uint "$SIX_N" && six_is_uint "$SIX_M" && (( SIX_M > 0 && SIX_N % SIX_M == 0 )) ||
    six_die "SIX_N=$SIX_N must be a positive multiple of SIX_M=$SIX_M"
  SIX_T=$((SIX_N / SIX_M))
fi
SIX_T=${SIX_T:-8}
if ! six_is_uint "$SIX_M" || ! six_is_uint "$SIX_T" || (( SIX_M == 0 || SIX_T == 0 )); then
  six_die "SIX_M=$SIX_M / SIX_T=$SIX_T must be positive integers"
fi
SIX_N=${SIX_N:-$((SIX_M * SIX_T))}
(( SIX_N == SIX_M * SIX_T )) || six_die "SIX_N=$SIX_N must equal SIX_M x SIX_T = $((SIX_M * SIX_T))"
SIX_GK_CAP=${SIX_GK_CAP:-2048}
if [[ -z ${SIX_QNS:-} ]]; then
  SIX_QNS=1
  for ((q = 2; q <= SIX_T; q *= 2)); do SIX_QNS+=",$q"; done
fi
[[ $SIX_QNS =~ ^[0-9]+(,[0-9]+)*$ ]] || six_die "SIX_QNS=$SIX_QNS must be a comma list of n in 1..$SIX_T"
for q in ${SIX_QNS//,/ }; do (( q >= 1 && q <= SIX_T )) || six_die "SIX_QNS=$SIX_QNS: n=$q outside 1..$SIX_T"; done
SIX_ZKA_ROOTS=${SIX_ZKA_ROOTS:-noroot}
six_roots_ok() {  # six_roots_ok <list>: a comma list of distinct designed|noroot|legacy
  local v seen=,
  [[ $1 =~ ^(designed|noroot|legacy)(,(designed|noroot|legacy))*$ ]] || return 1
  for v in ${1//,/ }; do [[ $seen == *,$v,* ]] && return 1; seen+="$v,"; done
}
six_roots_ok "$SIX_ZKA_ROOTS" || six_die "SIX_ZKA_ROOTS=$SIX_ZKA_ROOTS must be a comma list of distinct designed, noroot, legacy"
SIX_ZKA_CM_REF=${SIX_ZKA_CM_REF:-1}
[[ $SIX_ZKA_CM_REF == [01] ]] || six_die "SIX_ZKA_CM_REF=$SIX_ZKA_CM_REF must be 0 or 1"
# six_cm_ref_on: their shipped CM runs as a reference next to SIX_ZKA_ROOTS (see above)
six_cm_ref_on() { [[ $SIX_ZKA_CM_REF == 1 && ,$SIX_ZKA_ROOTS, != *,designed,* && ,$SIX_ZKA_ROOTS, != *,legacy,* ]]; }
SIX_ZKA_EXEC_ROOTS=$SIX_ZKA_ROOTS   # the variants `run_zka.sh exec` executes
if six_cm_ref_on; then SIX_ZKA_EXEC_ROOTS+=,designed; fi
SIX_ZKA_GK=${SIX_ZKA_GK:-matched}
[[ $SIX_ZKA_GK == matched || $SIX_ZKA_GK == textbook ]] || six_die "SIX_ZKA_GK=$SIX_ZKA_GK must be matched or textbook"
SIX_GK_MSUB=${SIX_GK_MSUB:-$SIX_M}
SIX_ZKA_GK_IMPL=${SIX_ZKA_GK_IMPL:-fast}
if [[ $SIX_ZKA_GK == matched ]]; then
  six_is_uint "$SIX_GK_MSUB" && six_is_uint "$SIX_GK_CAP" && (( SIX_GK_MSUB > 0 && SIX_GK_CAP > 0 )) ||
    six_die "SIX_GK_MSUB=$SIX_GK_MSUB / SIX_GK_CAP=$SIX_GK_CAP must be positive integers"
  (( SIX_M % SIX_GK_MSUB == 0 )) ||
    six_die "SIX_GK_MSUB=$SIX_GK_MSUB must divide SIX_M=$SIX_M (each epoch is SIX_M / SIX_GK_MSUB zkSketch leaves)"
  (( (SIX_GK_CAP + SIX_GK_MSUB) % 2 == 0 )) ||
    six_die "SIX_GK_CAP + SIX_GK_MSUB = $((SIX_GK_CAP + SIX_GK_MSUB)) is odd: zkSketch's GK leaf needs an even table"
  [[ $SIX_ZKA_GK_IMPL =~ ^(fast|fixed_linear|literal)$ ]] ||
    six_die "SIX_ZKA_GK_IMPL=$SIX_ZKA_GK_IMPL must be fast, fixed_linear or literal"
  [[ ,$SIX_ZKA_EXEC_ROOTS, != *,legacy,* ]] ||
    six_die "SIX_ZKA_ROOTS has legacy, the committed 2026-10-09 guests, whose GK is the TEXTBOOK port: set SIX_ZKA_GK=textbook with it (the matched GK has designed and noroot)"
fi
# six_gk_desc: one line naming the zk-Analytics GK of this configuration (logs, manifest)
six_gk_desc() {
  if [[ $SIX_ZKA_GK == matched ]]; then
    echo "zka_gk=matched (zkSketch's GK rule bm2 in their pipeline: capacity $SIX_GK_CAP, s 51, m_sub $SIX_GK_MSUB = $((SIX_M / SIX_GK_MSUB)) apply_batch2 step(s) per $SIX_M-record epoch, implementation $SIX_ZKA_GK_IMPL)"
  else
    echo "zka_gk=textbook (Greenwald-Khanna 2001 per epoch + query-time merge: NOT zkSketch's algorithm; reference)"
  fi
}

six_phys_cores() {  # distinct (socket, core) pairs
  local n
  n=$(lscpu -p=SOCKET,CORE 2>/dev/null | grep -v '^#' | sort -u | wc -l)
  if (( n < 1 )); then
    n=$(awk -F: '/^physical id/{p=$2} /^core id/{print p ":" $2}' /proc/cpuinfo 2>/dev/null | sort -u | wc -l)
  fi
  (( n >= 1 )) || n=$(nproc)
  echo "$n"
}
if [[ -z ${SIX_CORES:-} ]]; then
  SIX_CORES=$(six_phys_cores)
  (( SIX_CORES > 32 )) && SIX_CORES=32
  (( SIX_CORES > $(nproc) )) && SIX_CORES=$(nproc)
fi
if ! six_is_uint "$SIX_CORES" || (( SIX_CORES == 0 )); then six_die "SIX_CORES=$SIX_CORES must be a positive integer"; fi

# Refuse a results directory that holds git-tracked files (the committed reference
# results): new rows would be appended to committed CSVs and mixed with them.
six_prepare_results() {
  if [[ ${SIX_ALLOW_TRACKED:-0} != 1 && -d $RESULTS ]] \
     && [[ -n $(git -C "$RESULTS" ls-files -- . 2>/dev/null | head -1) ]]; then
    six_die "RESULTS=$RESULTS holds git-tracked files (committed reference results). Write new runs elsewhere, e.g. RESULTS=$ZKS/results/six/<name>"
  fi
  mkdir -p "$RESULTS" || six_die "cannot create RESULTS=$RESULTS"
}

# Drop inherited settings that would silently change a run: exp_compose / zkSketch knobs
# (EXP_*, ZKSKETCH_*, RAYON_NUM_THREADS) and RISC Zero prover selection (Bonsai, dev mode).
# EXP_VERIFY_REPEATS is kept: run_zks.sh documents it.
six_clean_env() {
  local v dropped=()
  for v in $(compgen -e); do
    case $v in
      EXP_VERIFY_REPEATS) ;;
      # M0 harness memory/time switches (default on; set to the "off" value for the
      # pre-M0 behaviour in A/B runs): passed through and recorded in run_zks.sh logs.
      EXP_FOREST_RETAIN_PREP|EXP_MALLOC_TRIM|EXP_EXIT_BEFORE_AUDIT|EXP_MERGE_CACHE|EXP_MERGE_CACHE_ENTRIES) ;;
      EXP_*|ZKSKETCH_*|RAYON_NUM_THREADS|BONSAI_API_URL|BONSAI_API_KEY|RISC0_PROVER|RISC0_DEV_MODE)
        dropped+=("$v"); unset "$v" ;;
    esac
  done
  if (( ${#dropped[@]} )); then echo "note: ignoring inherited ${dropped[*]}" >&2; fi
  return 0
}

# The procs engine copies its executable into $TMPDIR and execs it, and binds a unix
# socket there (path limit 108 bytes). Fall back to /tmp when TMPDIR is too long or
# mounted noexec.
six_tmpdir_ok() {  # six_tmpdir_ok <dir>
  local d=$1 opts
  [[ -d $d && -w $d ]] || return 1
  (( ${#d} <= 60 )) || return 1
  opts=$(findmnt -no OPTIONS -T "$d" 2>/dev/null) || opts=
  [[ ,$opts, != *,noexec,* ]]
}
six_check_tmpdir() {
  local t=${TMPDIR:-/tmp}
  six_tmpdir_ok "$t" && return 0
  if [[ $t != /tmp ]] && six_tmpdir_ok /tmp; then
    echo "note: TMPDIR=$t is too long, missing or noexec for the procs engine; using /tmp" >&2
    export TMPDIR=/tmp
    return 0
  fi
  six_die "TMPDIR=$t must be a writable, exec-capable directory with a path of at most 60 characters (set TMPDIR=<such a dir>)"
}

six_csv_col() {  # six_csv_col <csv> <column>: that column of the first data row
  awk -F, -v c="$2" 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == c) k = i } NR == 2 && k { print $k }' "$1" 2>/dev/null
}
