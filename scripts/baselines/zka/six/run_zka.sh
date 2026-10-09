#!/usr/bin/env bash
# zk-Analytics side of the six-sketch comparison (their CM + our ports of HLL, SS, GK,
# Bloom, KMV in their per-epoch architecture), AOL, 8 epochs x 2,048 records, batches of 8.
#
#   run_zka.sh exec             executor only: all 8 aggregation epochs of every family
#                               (Bloom/KMV: their --mode exec pipeline incl. query executes)
#   run_zka.sh prove <jobs...>  proved jobs, sequential, each behind the quiet-box gate.
#                               job = <fam>:aggr:<epoch> | <fam>:query:<n>[:<arg>]
#                               (gk query arg = rank value; bloom query arg = first|key:<u32>)
# ProverOpts::succinct(), CPU r0vm. Every job is wrapped by rss_tree.sh (r0vm peak RSS).
# SIX_ZKA_PREFIX (default six_zka) names the output files: <prefix>_<fam>_{exec,prove}.csv/.log,
# <prefix>_jobs.csv (e.g. six_zka_vt for the verify-protocol re-proofs).
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE6/../common.sh"   # BASELINE_DIR, ZKA, ZKS, RESULTS, PATH
WT=$ZKS
Z=$HERE6/..
OUTD=$RESULTS
PFX=${SIX_ZKA_PREFIX:-six_zka}
EB=$BASELINE_DIR/build
KEYS=$WT/data/aol.keys
M=${SIX_M:-2048}   # records per epoch
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
unset RISC0_DEV_MODE
source "$HERE6/gate.sh"

declare -A BIN=(
  [cm]=$EB/cyc-t1/release/shipped
  [hll]=$EB/hll/release/hll
  [ss]=$EB/zka-ss/release/ss
  [gk]=$EB/zka-gk/release/gk
  [bloom]=$EB/zka-bloom/release/bloom
  [kmv]=$EB/zka-kmv/release/kmv
)
for f in "${!BIN[@]}"; do [[ -x ${BIN[$f]} ]] || { echo "missing ${BIN[$f]}" >&2; exit 2; }; done

hdr() {  # hdr <fam>: the driver's CSV header
  case $1 in
    cm) "${BIN[cm]}" --header ;;
    *)  "${BIN[$1]}" --header ;;
  esac
}
csv_init() {  # csv_init <file> <fam>
  local h; h=$(hdr "$2")
  if [[ ! -s $1 ]]; then echo "$h" > "$1"
  elif [[ "$(head -1 "$1")" != "$h" ]]; then echo "REFUSING: $1 has a different header" >&2; exit 2; fi
}
elf_md5s() {  # provenance: md5 of every guest ELF under the build dirs
  find "$EB" -mindepth 7 -maxdepth 7 -path '*riscv32im-risc0-zkvm-elf/release/*' -type f ! -name '*.*' 2>/dev/null | sort | while read -r f; do
    echo "# elf ${f#"$EB"/} md5=$(md5sum < "$f" | cut -c1-12) bytes=$(stat -c %s "$f")"
  done
}
provenance() {
  echo "# $1 $(date -Is) host=$(hostname) nproc=$(nproc) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
  echo "# zka=$(git -C "$ZKA" rev-parse --short=12 HEAD) r0vm=$(r0vm --version 2>/dev/null) keys md5=$(md5sum < "$KEYS" | cut -c1-12)"
  echo "# zkSketch=$(git -C "$WT" rev-parse --short=9 HEAD) dirty_files=$(git -C "$WT" status --porcelain | wc -l) build_dir=\$SCRATCH/eb/build"
  elf_md5s
}

# common args per family (epoch slicing m = 2,048, batches of 8, AOL)
common() {
  case $1 in
    cm)    echo "--family cm --epoch-size $M --batch 8 --keys $KEYS" ;;
    ss)    echo "--capacity 1024 --epoch-size $M --batch 8 --keys $KEYS" ;;
    bloom) echo "--epoch-size $M --batch 8 --keys $KEYS --absent 10000" ;;
    *)     echo "--epoch-size $M --batch 8 --keys $KEYS" ;;
  esac
}

phase_exec() {
  local log=$OUTD/${PFX}_exec.log
  provenance "run_zka.sh exec" >> "$log"
  local fam e out
  for fam in cm hll ss gk; do
    out=$OUTD/${PFX}_${fam}_exec.csv
    csv_init "$out" "$fam"
    for e in 0 1 2 3 4 5 6 7; do
      echo "# exec $fam aggr epoch $e $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$log"
      # shellcheck disable=SC2046
      "${BIN[$fam]}" --mode aggr --epoch-index "$e" $(common "$fam") >> "$out" 2>> "$log"
      echo "# rc=$?" >> "$log"
    done
  done
  for fam in bloom kmv; do
    out=$OUTD/${PFX}_${fam}_exec.csv
    csv_init "$out" "$fam"
    local extra=""; [[ $fam == bloom ]] && extra="--probe first,absent"
    echo "# exec $fam pipeline $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$log"
    # shellcheck disable=SC2046,SC2086
    "${BIN[$fam]}" --mode exec --epochs 8 --query-at 1,2,4,8 $extra $(common "$fam") >> "$out" 2>> "$log"
    echo "# rc=$?" >> "$log"
  done
}

JOBS=$OUTD/${PFX}_jobs.csv
phase_prove() {
  [[ -s $JOBS ]] || echo "job,family,op,n_or_epoch,arg,start_iso,gate,gate_waited_s,load1_start,busy_cores_start,load1_end,wall_s,rc,r0vm_peak_rss_mb,main_peak_rss_mb" > "$JOBS"
  local job fam op x arg out log args g L1 T0 rc wall rl r0 mn start
  for job in "$@"; do
    IFS=: read -r fam op x arg <<< "$job"
    out=$OUTD/${PFX}_${fam}_prove.csv
    log=$OUTD/${PFX}_${fam}_prove.log
    csv_init "$out" "$fam"
    # shellcheck disable=SC2207
    args=($(common "$fam"))
    case $op in
      aggr)  args=(--mode aggr --epoch-index "$x" "${args[@]}") ;;
      query) args=(--mode query --epochs "$x" "${args[@]}")
             case $fam in
               cm) args+=(--query estimate) ;;
               ss) args+=(--query topk --limit 1) ;;
               gk) args+=(--query rank --rank-value "${arg:?gk query needs a rank value}") ;;
               bloom) args+=(--probe "${arg:-first}") ;;
             esac ;;
      *) echo "bad job $job" >&2; exit 2 ;;
    esac
    args+=(--prove)
    if gate; then g=quiet; else g="$GATE_WHY"; echo "gate failed for $job: $GATE_WHY -- running anyway, marked" >&2; fi
    case $fam in bloom|kmv) args+=(--gate "load1_start=$GATE_L0;max_load=$GATE_MAX_LOAD;busy_cores=${GATE_BUSY:-NA};waited_s=$GATE_WAITED_S") ;; esac
    start=$(date -Is)
    { provenance "run_zka.sh prove job=$job gate=$g waited_s=$GATE_WAITED_S load1_start=$GATE_L0 busy_cores_start=${GATE_BUSY:-NA}"
      echo "# cmd: ${BIN[$fam]} ${args[*]}"; } >> "$log"
    T0=$SECONDS
    "$HERE6/rss_tree.sh" "$job" "${BIN[$fam]}" "${args[@]}" >> "$out" 2>> "$log"
    rc=$?
    wall=$((SECONDS - T0))
    L1=$(cut -d' ' -f1 /proc/loadavg)
    rl=$(grep '^RSSTREE' "$log" | tail -1)
    r0=$(sed -n 's/.*r0vm_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
    mn=$(sed -n 's/.*main_peak_rss_mb=\([0-9.]*\).*/\1/p' <<< "$rl")
    echo "# end job=$job $(date -Is) rc=$rc wall_s=$wall load1_end=$L1" >> "$log"
    echo "$job,$fam,$op,$x,${arg:--},$start,$g,$GATE_WAITED_S,$GATE_L0,${GATE_BUSY:-NA},$L1,$wall,$rc,$r0,$mn" >> "$JOBS"
    echo "done $job rc=$rc wall=${wall}s r0vm_rss=${r0}MB" >&2
  done
}

case ${1:-} in
  exec) phase_exec ;;
  prove) shift; phase_prove "$@" ;;
  *) echo "usage: $0 exec | prove <jobs...>" >&2; exit 2 ;;
esac
