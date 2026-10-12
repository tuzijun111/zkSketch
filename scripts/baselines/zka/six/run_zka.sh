#!/usr/bin/env bash
# zk-Analytics side of the six-sketch comparison (their CM + our ports of HLL, SS, GK,
# Bloom, KMV in their per-epoch architecture), AOL, SIX_T epochs x SIX_M records, batches of 8
# (paper configuration, the defaults: 8 epochs x 2,048 records).
#
#   run_zka.sh exec             executor only: aggregation epochs 0..T-1 of every family
#                               (Bloom/KMV: their --mode exec pipeline incl. query executes at SIX_QNS)
#   run_zka.sh qexec <jobs...>  executor only, no proof, for the given query jobs: the cycle counts
#                               `assemble.py --plan` uses to ESTIMATE jobs that were not proved
#   run_zka.sh prove <jobs...>  proved jobs, sequential, each behind the quiet-box gate.
#                               job = <fam>:aggr:<epoch> | <fam>:query:<n>[:<arg>]
#                               (gk query arg = rank value; bloom query arg = first|key:<u32>)
#                               `jobs.py` prints the job list (40 jobs at the defaults).
# ProverOpts::succinct(), CPU r0vm. Every proof is wrapped by rss_tree.sh (r0vm peak RSS).
# Env: RESULTS, SIX_M, SIX_T, SIX_QNS (six_common.sh); GATE_* (gate.sh);
#   SIX_ZKA_PREFIX  output prefix (default six_zka): <prefix>_<fam>_{exec,qexec,prove}.csv/.log,
#                   <prefix>_jobs.csv, <prefix>_qexec_jobs.csv
#   SIX_FAIL_FAST=1 stop at the first failed job
# exec and qexec rewrite their CSVs; prove appends (a job list can be split over several calls).
# Exit status 0 only if every driver call succeeded (and every proof appended its row).
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# job_args <job> -> JFAM JOP JX JARG ARGS (driver args without --prove); 1 on a bad job
job_args() {
  IFS=: read -r JFAM JOP JX JARG <<< "$1"
  [[ -n ${BIN[$JFAM]:-} ]] && six_is_uint "$JX" || return 1
  common "$JFAM"
  case $JOP in
    aggr)  (( JX < T )) || return 1
           ARGS=(--mode aggr --epoch-index "$JX" "${COMMON[@]}") ;;
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
check_jobs() { local j; for j in "$@"; do job_args "$j" || six_die "bad job '$j' (fam:aggr:<epoch 0..$((T-1))> | fam:query:<n 1..$T>[:arg]; gk needs a rank value)"; done; }

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
on_signal() {
  if [[ -n $CHILD ]]; then kill -TERM "$CHILD" 2>/dev/null; wait "$CHILD" 2>/dev/null; fi
  echo "run_zka.sh: interrupted" >&2
  exit 130
}
trap on_signal INT TERM HUP

phase_exec() {
  local log=$OUTD/${PFX}_exec.log
  provenance "run_zka.sh exec" >> "$log"
  local fam e out rc
  for fam in cm hll ss gk; do
    out=$OUTD/${PFX}_${fam}_exec.csv
    csv_fresh "$out" "$fam"
    common "$fam"
    for ((e = 0; e < T; e++)); do
      echo "# exec $fam aggr epoch $e $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$log"
      "${BIN[$fam]}" --mode aggr --epoch-index "$e" "${COMMON[@]}" >> "$out" 2>> "$log"; rc=$?
      echo "# rc=$rc" >> "$log"
      (( rc == 0 )) || failed "exec $fam aggr epoch $e (rc=$rc)"
    done
  done
  for fam in bloom kmv; do
    out=$OUTD/${PFX}_${fam}_exec.csv
    csv_fresh "$out" "$fam"
    common "$fam"
    local extra=(); [[ $fam == bloom ]] && extra=(--probe "first,absent")
    echo "# exec $fam pipeline $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$log"
    "${BIN[$fam]}" --mode exec --epochs "$T" --query-at "$QNS" "${extra[@]}" "${COMMON[@]}" >> "$out" 2>> "$log"; rc=$?
    echo "# rc=$rc" >> "$log"
    (( rc == 0 )) || failed "exec $fam pipeline (rc=$rc)"
  done
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
  local job out log g L1 T0 rc wall rl r0 mn start n0 n1 k=0
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
    n0=$(wc -l < "$out")
    T0=$SECONDS
    "$HERE6/rss_tree.sh" "$job" "${BIN[$JFAM]}" "${ARGS[@]}" >> "$out" 2>> "$log" &
    CHILD=$!
    wait "$CHILD"; rc=$?
    CHILD=
    wall=$((SECONDS - T0))
    n1=$(wc -l < "$out")
    L1=$(cut -d' ' -f1 /proc/loadavg)
    rl=$(grep '^RSSTREE' "$log" | tail -1)
    r0=$(sed -n 's/.*r0vm_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
    mn=$(sed -n 's/.*main_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
    echo "# end job=$job $(date -Is) rc=$rc wall_s=$wall load1_end=$L1" >> "$log"
    echo "$job,$JFAM,$JOP,$JX,${JARG:--},$start,$g,$GATE_WAITED_S,$GATE_L0,$GATE_BUSY,$L1,$wall,$rc,$r0,$mn" >> "$JOBS"
    if (( rc != 0 || n1 != n0 + 1 )); then
      failed "prove $job (rc=$rc, $((n1 - n0)) row(s) written) -- see $log"
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
  *) echo "usage: $0 exec | qexec <jobs...> | prove <jobs...>" >&2; exit 2 ;;
esac
