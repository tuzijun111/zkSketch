#!/usr/bin/env bash
# zk-Analytics side of the six-sketch comparison (their CM + our ports of HLL, SS, GK,
# Bloom, KMV in their per-epoch architecture), AOL, SIX_T epochs x SIX_M records, batches of 8
# (paper configuration, the defaults: 8 epochs x 2,048 records).
#
#   run_zka.sh exec             executor only: aggregation epochs 0..T-1 of every family, once per
#                               root variant of SIX_ZKA_ROOTS (default designed,noroot)
#                               (Bloom/KMV: their --mode exec pipeline per variant, incl. the query
#                               executes at SIX_QNS; the query rows, which no root reaches, are kept
#                               once and checked identical across the variants)
#   run_zka.sh qexec <jobs...>  executor only, no proof, for the given query jobs: the cycle counts
#                               `assemble.py --plan` uses to ESTIMATE jobs that were not proved
#   run_zka.sh prove <jobs...>  proved jobs, sequential, each behind the quiet-box gate.
#                               job = <fam>:aggr:<epoch>[:<variant>] | <fam>:query:<n>[:<arg>]
#                               variant = designed | noroot | legacy (also ss: buckets1024, perkey;
#                               gk: pertuple), passed to the driver as --root; omitted = legacy (the
#                               guests of the committed 2026-10-09 run, the drivers' default).
#                               Query proofs take no variant (query guests read no root).
#                               (gk query arg = rank value; bloom query arg = first|key:<u32>)
#                               `jobs.py` prints the job list (52 jobs at the defaults).
# ProverOpts::succinct(), CPU r0vm. Every proof is wrapped by rss_tree.sh (r0vm peak RSS).
# Env: RESULTS, SIX_M, SIX_T, SIX_QNS, SIX_ZKA_ROOTS (six_common.sh); GATE_* (gate.sh);
#   SIX_ZKA_PREFIX  output prefix (default six_zka): <prefix>_<fam>_{exec,qexec,prove}.csv/.log,
#                   <prefix>_jobs.csv, <prefix>_qexec_jobs.csv. Rows of every variant share a
#                   family's CSV; its root_variant / root_construction columns tell them apart.
#   SIX_FAIL_FAST=1 stop at the first failed job
# exec and qexec rewrite their CSVs; prove appends (a job list can be split over several calls,
# e.g. to retry the jobs of a plan that have no rc=0 line in <prefix>_jobs.csv yet). A proof's
# row is appended only when its driver exits 0 having printed exactly one row; any other
# outcome is recorded in <prefix>_jobs.csv with a non-zero rc and adds no row. The jobs file's
# `arg` column holds an aggregation job's variant ('-' = none given = legacy).
# exec also checks, per family, that every variant gives the same state_commit for each epoch
# (the drivers check journal_eq_native and variants_agree themselves and exit 1 otherwise).
# Exit status 0 only if every driver call succeeded (and every proof appended its row).
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case ${1:-} in
  exec|qexec|prove) ;;
  *) echo "usage: $0 exec | qexec <jobs...> | prove <jobs...>" >&2; exit 2 ;;
esac
source "$HERE6/six_common.sh"   # BASELINE_DIR, ZKA, ZKS, RESULTS, SIX_*, PATH
six_prepare_results
six_clean_env                   # also drops RISC0_DEV_MODE, RISC0_PROVER and the Bonsai settings
WT=$ZKS
OUTD=$RESULTS
PFX=${SIX_ZKA_PREFIX:-six_zka}
EB=$BASELINE_DIR/build
KEYS=$WT/data/aol.keys
M=$SIX_M   # records per epoch
T=$SIX_T   # epochs
QNS=$SIX_QNS
source "$HERE6/gate.sh"

declare -A BIN=(
  [cm]=$EB/cyc-t1/release/shipped
  [hll]=$EB/hll/release/hll
  [ss]=$EB/zka-ss/release/ss
  [gk]=$EB/zka-gk/release/gk
  [bloom]=$EB/zka-bloom/release/bloom
  [kmv]=$EB/zka-kmv/release/kmv
)
for f in "${!BIN[@]}"; do [[ -x ${BIN[$f]} ]] || six_die "missing ${BIN[$f]} -- run scripts/baselines/zka/six/build.sh zka (BASELINE_DIR=$BASELINE_DIR)"; done
[[ -s $KEYS ]] || six_die "missing $KEYS (it is tracked in git; re-checkout data/aol.keys)"

csv_fresh() {  # csv_fresh <file> <fam>: start the file with the driver's header
  "${BIN[$2]}" --header > "$1" || six_die "${BIN[$2]} --header failed"
}
csv_init() {  # csv_init <file> <fam>: header if new; refuse a different header
  local h; h=$("${BIN[$2]}" --header)
  if [[ ! -s $1 ]]; then echo "$h" > "$1"
  elif [[ "$(head -1 "$1")" != "$h" ]]; then six_die "$1 has a different header; use a fresh RESULTS directory"; fi
}
elf_md5s() {  # provenance: md5 of every guest ELF under the build dirs
  find "$EB" -mindepth 7 -maxdepth 7 -path '*riscv32im-risc0-zkvm-elf/release/*' -type f ! -name '*.*' 2>/dev/null | sort | while read -r f; do
    echo "# elf ${f#"$EB"/} md5=$(md5sum < "$f" | cut -c1-12) bytes=$(stat -c %s "$f")"
  done
}
provenance() {
  echo "# $1 $(date -Is) host=$(hostname) nproc=$(nproc) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
  echo "# zka=$(git -C "$ZKA" rev-parse --short=12 HEAD) r0vm=$(r0vm --version 2>/dev/null) keys md5=$(md5sum < "$KEYS" | cut -c1-12) M=$M T=$T"
  echo "# zkSketch=$(git -C "$WT" rev-parse --short=9 HEAD) dirty_files=$(git -C "$WT" status --porcelain | wc -l) build_dir=$EB"
  elf_md5s
}

# common args per family (epoch slicing m = M, batches of 8, AOL) -> COMMON
common() {
  case $1 in
    cm)    COMMON=(--family cm --epoch-size "$M" --batch 8 --keys "$KEYS") ;;
    ss)    COMMON=(--capacity 1024 --epoch-size "$M" --batch 8 --keys "$KEYS") ;;
    bloom) COMMON=(--epoch-size "$M" --batch 8 --keys "$KEYS" --absent 10000) ;;
    *)     COMMON=(--epoch-size "$M" --batch 8 --keys "$KEYS") ;;
  esac
}

# root_ok <fam> <variant>: a --root value the family's aggregation driver can prove
root_ok() {
  case $2 in
    designed|noroot|legacy) return 0 ;;
    buckets1024|perkey) [[ $1 == ss ]] ;;
    pertuple) [[ $1 == gk ]] ;;
    *) return 1 ;;
  esac
}

# job_args <job> -> JFAM JOP JX JARG ARGS (driver args without --prove); 1 on a bad job
# (an aggregation job's JARG is its root variant, empty = legacy)
job_args() {
  IFS=: read -r JFAM JOP JX JARG <<< "$1"
  [[ -n ${BIN[$JFAM]:-} ]] && six_is_uint "$JX" || return 1
  common "$JFAM"
  case $JOP in
    aggr)  (( JX < T )) && root_ok "$JFAM" "${JARG:-legacy}" || return 1
           ARGS=(--mode aggr --epoch-index "$JX" --root "${JARG:-legacy}" "${COMMON[@]}") ;;
    query) (( JX >= 1 && JX <= T )) || return 1
           ARGS=(--mode query --epochs "$JX" "${COMMON[@]}")
           case $JFAM in
             cm) ARGS+=(--query estimate) ;;
             ss) ARGS+=(--query topk --limit 1) ;;
             gk) [[ -n $JARG ]] || return 1; ARGS+=(--query rank --rank-value "$JARG") ;;
             bloom) ARGS+=(--probe "${JARG:-first}") ;;
           esac ;;
    *) return 1 ;;
  esac
}
check_jobs() { local j; for j in "$@"; do job_args "$j" || six_die "bad job '$j' (fam:aggr:<epoch 0..$((T-1))>[:designed|noroot|legacy] | fam:query:<n 1..$T>[:arg]; gk needs a rank value)"; done; }

NFAIL=0
failed() {  # failed <what>
  NFAIL=$((NFAIL + 1))
  echo "FAILED $1" >&2
  if [[ ${SIX_FAIL_FAST:-0} == 1 ]]; then echo "run_zka.sh: stopping (SIX_FAIL_FAST=1)" >&2; exit 1; fi
}
finish() {
  if (( NFAIL )); then echo "run_zka.sh $1: $NFAIL failure(s); see the logs in $OUTD" >&2; exit 1; fi
  echo "run_zka.sh $1: ok -> $OUTD/${PFX}_*" >&2
}
CHILD=
ROWTMP=
on_signal() {
  if [[ -n $CHILD ]]; then kill -TERM "$CHILD" 2>/dev/null; wait "$CHILD" 2>/dev/null; fi
  [[ -n $ROWTMP ]] && rm -f "$ROWTMP"
  echo "run_zka.sh: interrupted" >&2
  exit 130
}
trap on_signal INT TERM HUP

# exec_py merge <out> <tmp> <variant> | check <T> <roots> <csv...>: the cross-variant steps of
# phase_exec. merge: append the aggregation rows of a Bloom / KMV pipeline (<tmp>, no header) to
# <out>, after checking that its query rows equal those already in <out> (all columns but exec_s).
# check: per CSV and epoch 0..T-1, exactly one aggregation row per variant, one state_commit for
# all of them, journal_eq_native and variants_agree true.
exec_py() {
  python3 -I - "$@" <<'PY'
import collections, csv, sys
mode = sys.argv[1]
if mode == 'merge':
    out, tmp, var = sys.argv[2:5]
    h = next(csv.reader(open(out)))
    st, ex = h.index('step'), h.index('exec_s')
    def queries(lines):
        rows = [r for r in csv.reader(lines) if r]
        return [[c for i, c in enumerate(r) if i != ex] for r in rows if r[st] == 'query']
    head, *old = open(out).read().splitlines()
    new = [line for line in open(tmp).read().splitlines() if line != head]
    if queries(old) != queries(new):
        sys.exit(f'{out}: the query rows of --root {var} differ from the first variant\'s '
                 f'(no query guest reads a root, so they must be identical)')
    with open(out, 'a') as fo:
        for line in new:
            r = next(csv.reader([line]), [])
            if r and r[st] != 'query':
                fo.write(line + '\n')
    sys.exit(0)
t, roots, files = int(sys.argv[2]), sys.argv[3].split(','), sys.argv[4:]
bad = []
for p in files:
    rows = [r for r in csv.DictReader(open(p)) if (r.get('step') or r.get('mode')) == 'aggr']
    by = collections.defaultdict(lambda: collections.defaultdict(list))
    for r in rows:
        by[r['epoch_index']][r['root_variant']].append(r)
    for e in range(t):
        got = by.pop(str(e), {})
        for v in roots:
            if len(got.get(v, [])) != 1:
                bad.append(f'{p}: epoch {e} --root {v}: {len(got.get(v, []))} rows (expected 1)')
        commits = {r['state_commit'] for rs in got.values() for r in rs}
        if len(commits) > 1:
            bad.append(f'{p}: epoch {e}: {len(commits)} different state_commit values across {sorted(got)}')
        for v, rs in got.items():
            for r in rs:
                if (r['journal_eq_native'], r['variants_agree']) != ('true', 'true'):
                    bad.append(f'{p}: epoch {e} --root {v}: journal_eq_native={r["journal_eq_native"]} '
                               f'variants_agree={r["variants_agree"]}')
    if by:
        bad.append(f'{p}: unexpected epochs {sorted(by)}')
    if not any(b.startswith(p + ':') for b in bad):
        print(f'exec variants ok: {p.rsplit("/", 1)[-1]}: epochs 0..{t - 1} x {",".join(roots)}, '
              f'one state_commit per epoch', file=sys.stderr)
for b in bad:
    print('VARIANT CHECK FAILED ' + b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
}

phase_exec() {
  local log=$OUTD/${PFX}_exec.log
  provenance "run_zka.sh exec (root variants $SIX_ZKA_ROOTS)" >> "$log"
  local fam e v out rc first files=() roots=(${SIX_ZKA_ROOTS//,/ })
  for fam in cm hll ss gk; do
    out=$OUTD/${PFX}_${fam}_exec.csv
    csv_fresh "$out" "$fam"
    files+=("$out")
    common "$fam"
    for v in "${roots[@]}"; do
      for ((e = 0; e < T; e++)); do
        echo "# exec $fam aggr epoch $e --root $v $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$log"
        "${BIN[$fam]}" --mode aggr --epoch-index "$e" --root "$v" "${COMMON[@]}" >> "$out" 2>> "$log"; rc=$?
        echo "# rc=$rc" >> "$log"
        (( rc == 0 )) || failed "exec $fam aggr epoch $e --root $v (rc=$rc)"
      done
    done
  done
  for fam in bloom kmv; do
    out=$OUTD/${PFX}_${fam}_exec.csv
    csv_fresh "$out" "$fam"
    files+=("$out")
    common "$fam"
    local extra=(); [[ $fam == bloom ]] && extra=(--probe "first,absent")
    first=1
    for v in "${roots[@]}"; do
      ROWTMP=$(mktemp "$OUTD/.${PFX}_${fam}_exec.XXXXXX") || six_die "cannot create a temporary file in $OUTD"
      echo "# exec $fam pipeline --root $v $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$log"
      "${BIN[$fam]}" --mode exec --epochs "$T" --query-at "$QNS" "${extra[@]}" --root "$v" "${COMMON[@]}" > "$ROWTMP" 2>> "$log"; rc=$?
      echo "# rc=$rc" >> "$log"
      if (( rc != 0 )); then
        failed "exec $fam pipeline --root $v (rc=$rc)"
      elif (( first )); then
        cat "$ROWTMP" >> "$out"; first=0
      else
        exec_py merge "$out" "$ROWTMP" "$v" 2>> "$log" || failed "exec $fam pipeline --root $v: its query rows differ from the first variant's (see $log)"
      fi
      rm -f "$ROWTMP"; ROWTMP=
    done
  done
  exec_py check "$T" "$SIX_ZKA_ROOTS" "${files[@]}" 2>&1 | tee -a "$log" >&2
  (( PIPESTATUS[0] == 0 )) || failed "exec: the root variants disagree (VARIANT CHECK FAILED lines above)"
  finish exec
}

phase_qexec() {
  check_jobs "$@"
  local log=$OUTD/${PFX}_qexec.log jobs=$OUTD/${PFX}_qexec_jobs.csv job out line rc f
  provenance "run_zka.sh qexec" >> "$log"
  echo "job,family,op,n_or_epoch,arg,rc" > "$jobs"
  for f in "${!BIN[@]}"; do rm -f "$OUTD/${PFX}_${f}_qexec.csv"; done
  for job in "$@"; do
    job_args "$job"
    [[ $JOP == query ]] || continue
    out=$OUTD/${PFX}_${JFAM}_qexec.csv
    [[ -s $out ]] || csv_fresh "$out" "$JFAM"
    echo "# qexec $job $(date -Is): ${BIN[$JFAM]} ${ARGS[*]}" >> "$log"
    line=$("${BIN[$JFAM]}" "${ARGS[@]}" 2>> "$log"); rc=$?
    echo "# rc=$rc" >> "$log"
    if (( rc == 0 )) && [[ -n $line ]]; then
      echo "$line" >> "$out"
    else
      failed "qexec $job (rc=$rc)"
      (( rc == 0 )) && rc=1
    fi
    echo "$job,$JFAM,$JOP,$JX,${JARG:--},$rc" >> "$jobs"
  done
  finish qexec
}

JOBS=$OUTD/${PFX}_jobs.csv
phase_prove() {
  check_jobs "$@"
  local hdr="job,family,op,n_or_epoch,arg,start_iso,gate,gate_waited_s,load1_start,busy_cores_start,load1_end,wall_s,rc,r0vm_peak_rss_mb,main_peak_rss_mb"
  if [[ ! -s $JOBS ]]; then echo "$hdr" > "$JOBS"
  elif [[ "$(head -1 "$JOBS")" != "$hdr" ]]; then six_die "$JOBS has a different header; use a fresh RESULTS directory"; fi
  echo "run_zka.sh prove: $# job(s) -> $OUTD ($(gate_settings))" >&2
  local job out log g L1 T0 rc wall rl r0 mn start nrow k=0
  for job in "$@"; do
    k=$((k + 1))
    job_args "$job"
    out=$OUTD/${PFX}_${JFAM}_prove.csv
    log=$OUTD/${PFX}_${JFAM}_prove.log
    csv_init "$out" "$JFAM"
    ARGS+=(--prove)
    if gate; then g=quiet; else g="$GATE_WHY"; echo "gate failed for $job: $GATE_WHY -- running anyway, marked" >&2; fi
    case $JFAM in bloom|kmv) ARGS+=(--gate "load1_start=$GATE_L0;max_load=$GATE_MAX_LOAD;busy_cores=$GATE_BUSY;waited_s=$GATE_WAITED_S") ;; esac
    start=$(date -Is)
    { provenance "run_zka.sh prove job=$job gate=$g waited_s=$GATE_WAITED_S load1_start=$GATE_L0 busy_cores_start=$GATE_BUSY"
      echo "# cmd: ${BIN[$JFAM]} ${ARGS[*]}"; } >> "$log"
    echo "== zk-Analytics prove $job [$k/$#] ($(date +%T))" >&2
    # The driver's CSV row goes to a temporary file first and joins $out only for a
    # successful job: a driver that prints its row and then exits non-zero (a failed
    # journal / accuracy check) must not leave a row for a job recorded as failed.
    ROWTMP=$(mktemp "$OUTD/.${PFX}_${JFAM}_row.XXXXXX") || six_die "cannot create a temporary file in $OUTD"
    T0=$SECONDS
    "$HERE6/rss_tree.sh" "$job" "${BIN[$JFAM]}" "${ARGS[@]}" > "$ROWTMP" 2>> "$log" &
    CHILD=$!
    wait "$CHILD"; rc=$?
    CHILD=
    wall=$((SECONDS - T0))
    nrow=$(wc -l < "$ROWTMP")
    if (( rc == 0 && nrow == 1 )); then
      cat "$ROWTMP" >> "$out"
    else
      { echo "# stdout of the failed job (not added to $(basename "$out")):"; cat "$ROWTMP"; } >> "$log"
      (( rc == 0 )) && rc=1   # no single row: record the job as failed
    fi
    rm -f "$ROWTMP"; ROWTMP=
    L1=$(cut -d' ' -f1 /proc/loadavg)
    rl=$(grep '^RSSTREE' "$log" | tail -1)
    r0=$(sed -n 's/.*r0vm_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
    mn=$(sed -n 's/.*main_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
    echo "# end job=$job $(date -Is) rc=$rc wall_s=$wall load1_end=$L1" >> "$log"
    echo "$job,$JFAM,$JOP,$JX,${JARG:--},$start,$g,$GATE_WAITED_S,$GATE_L0,$GATE_BUSY,$L1,$wall,$rc,$r0,$mn" >> "$JOBS"
    if (( rc != 0 )); then
      failed "prove $job (rc=$rc, $nrow row(s) printed, none kept) -- see $log"
    else
      echo "done $job rc=$rc wall=${wall}s r0vm_rss=${r0}MB" >&2
    fi
  done
  finish prove
}

case ${1:-} in
  exec) phase_exec ;;
  qexec) shift; phase_qexec "$@" ;;
  prove) shift; phase_prove "$@" ;;
esac
