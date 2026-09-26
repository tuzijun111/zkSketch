#!/usr/bin/env bash
# sketch_run.sh -- one entry point for the sketch-family replay operators (HyperLogLog,
# SpaceSaving, Greenwald-Khanna) that follow zkStream's design. They are OUR ZoKrates
# circuits, never "zkStream" (see README.md, "Sketch-family replay operators"). The
# script re-runs the exact measurement sequences behind the family CSVs, the matched
# zkSketch leaves, and the fits.
#
#   hll   hll/run_hll.py + hll/probes/constraint_probe.sh -> zkstream_hll.csv,
#         zkstream_hll_{constraint,packing}_probe.csv, zkstream_hll_<run>.log
#         sub-stages: probes grid deployed wall edge   (refresh: opt-in, see below)
#   ss    ss/run_ss.py -> zkstream_ss.csv, zkstream_ss_<sub>_<ts>.log
#         sub-stages: grid scaling large deployed
#   gk    gk/run_gk.py -> zkstream_gk.csv, zkstream_gk_<ts>.log
#         sub-stages: grid sweep validate probes
#   ours  zkSketch's own leaves (hll_omc, ss_final_full, gk_bandmerge2; default binding)
#         at the ZoKrates points' state size and records per batch -> zks_sketch_small.csv
#   fit   hll/fit.py, ss/fit_ss.py (-> zkstream_ss_fit.log), gk/fit_gk.py
#   compare  prints the matched ZoKrates-vs-zkSketch tables from the CSVs (no proving)
#
# Usage: sketch_run.sh [options] [stage|family:sub ...]
#   default stages: hll ss gk ours fit compare  (several hours; the two 45-min refusals
#   alone take 1.5 h). Examples:
#     sketch_run.sh --dry-run                 # print the plan and every command
#     sketch_run.sh ours compare              # matched zkSketch leaves only (minutes)
#     sketch_run.sh --skip-refusals hll ss gk fit
#     sketch_run.sh ss:grid                   # partial run: stays in the staging dir
# Options:
#   --dry-run        print the plan and the commands; run and write nothing
#   --skip-refusals  skip the two compiles that are known to hit the 45 min budget
#                    (hll s=2^14 k=1024; ss s=2^14 k=1) and carry their previous rows
#                    over verbatim into the regenerated CSV
#   --allow-busy     skip the load guard (the drivers still wait for other provers)
#   --deployed       'ours' also proves zkSketch's deployed shapes (s=2^14 / s'=2^11,
#                    m=2^14), one rep each, under the same 45 min / 150 GB cap
# Env:
#   MAX_LOAD=8 WAIT_S=1800   load guard: before a family's first command and before the
#                            first 'ours' point, wait until the 1-minute load average is
#                            <= MAX_LOAD and no zokrates/exp_compose/r0vm of this user runs;
#                            before every later command or point, wait only for those
#                            processes (our own finished runs still lift load1). Refuse the
#                            stage (exit 3) after WAIT_S seconds
#   RESULTS  BASELINE_DIR  PIN_CPUS   as in common.sh
#   OURS_REV=HEAD                 git revision of zkSketch measured by 'ours' (git archive)
#   OURS_DIR=$BASELINE_DIR/build/zks_sketch_ours   exported source + its CARGO_TARGET_DIR
#   OURS_REPS=3                   repetitions per point (the CSV keeps every rep)
#
# Regeneration is staged. Every run writes into $RESULTS/sketch_run.<ts>.<pid>.tmp/
# (gitignored). A family's canonical files are replaced only when ALL its sub-stages
# ran, every driver exited 0 and the family gate passed: no row with ok=0 other than a
# compile refused by the budget, and the expected number of proven points. The
# previous canonical files are kept under <staging>/<family>/prev/. A partial run
# (e.g. ss:grid) or a failed gate leaves the canonical files untouched.
#
# Budgets: every ZoKrates compile runs under `timeout 45m systemd-run --user --scope
# -p MemoryMax=150G` inside the drivers; every zkSketch run here under the same cap.
# This script refuses to raise either cap. Stages run one after the other, never two
# provers at once. It signals no process.
#
# hll:refresh (opt-in, not in the default plan) recompiles the wire-refresh probe
# (CK=1 and CK=8, s=2^14, k=4 16 64) into zkstream_hll_refresh_probe_regen.csv. The
# committed zkstream_hll_refresh_probe.csv was assembled by hand (its header says how);
# its CK=none rows come from the superseded v1 template and cannot be regenerated.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/common.sh"   # ZKS BASELINE_DIR ZOK ZOK_STDLIB RESULTS PIN_CPUS require_tools

usage() { sed -n '2,/^set -uo pipefail/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

DRY=0; SKIP_REF=0; ALLOW_BUSY=0; DEPLOYED=0; REQ=()
while (($#)); do
  case $1 in
    --dry-run) DRY=1 ;;
    --skip-refusals) SKIP_REF=1 ;;
    --allow-busy) ALLOW_BUSY=1 ;;
    --deployed) DEPLOYED=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "sketch_run.sh: unknown option $1" >&2; exit 2 ;;
    *) REQ+=("$1") ;;
  esac
  shift
done
((${#REQ[@]})) || REQ=(hll ss gk ours fit compare)

MAX_LOAD="${MAX_LOAD:-8}"; WAIT_S="${WAIT_S:-1800}"
OURS_REV="${OURS_REV:-HEAD}"
OURS_DIR="$(realpath -m -- "${OURS_DIR:-$BASELINE_DIR/build/zks_sketch_ours}")"
OURS_REPS="${OURS_REPS:-3}"
CAP_T=45m; CAP_M=150G
declare -A SUBS=([hll]="probes grid deployed wall edge" [ss]="grid scaling large deployed"
                 [gk]="grid sweep validate probes")
declare -A EXTRA=([hll]="refresh")

# Budgets are fixed: refuse an environment that would raise them.
if [[ ${COMPILE_TIMEOUT:-45m} != 45m || ${COMPILE_MEM:-150G} != 150G ]]; then
  echo "sketch_run.sh: refusing: COMPILE_TIMEOUT/COMPILE_MEM differ from the 45m/150G budget" >&2; exit 2
fi

# ---- plan -----------------------------------------------------------------------
declare -A PLAN   # family -> requested sub-stages (space separated, in canonical order)
STAGES=()         # ordered list of top-level stages that run
add_stage() { local s; for s in "${STAGES[@]}"; do [[ $s == "$1" ]] && return; done; STAGES+=("$1"); }
for r in "${REQ[@]}"; do
  fam=${r%%:*}; sub=""; [[ $r == *:* ]] && sub=${r#*:}
  case $fam in
    hll|ss|gk)
      if [[ -z $sub ]]; then PLAN[$fam]="${SUBS[$fam]}"
      elif [[ " ${SUBS[$fam]} ${EXTRA[$fam]:-} " == *" $sub "* ]]; then PLAN[$fam]="${PLAN[$fam]:-} $sub"
      else echo "sketch_run.sh: unknown sub-stage $r (${SUBS[$fam]} ${EXTRA[$fam]:-})" >&2; exit 2; fi
      add_stage "$fam" ;;
    ours|fit|compare) [[ -z $sub ]] || { echo "sketch_run.sh: $fam has no sub-stages" >&2; exit 2; }; add_stage "$fam" ;;
    *) echo "sketch_run.sh: unknown stage $r (hll ss gk ours fit compare)" >&2; exit 2 ;;
  esac
done
# keep canonical order inside each family and note whether the plan is full
declare -A FULL
for fam in hll ss gk; do
  [[ -n ${PLAN[$fam]:-} ]] || continue
  ordered=""; for s in ${SUBS[$fam]} ${EXTRA[$fam]:-}; do [[ " ${PLAN[$fam]} " == *" $s "* ]] && ordered+=" $s"; done
  PLAN[$fam]="${ordered# }"
  FULL[$fam]=1; for s in ${SUBS[$fam]}; do [[ " ${PLAN[$fam]} " == *" $s "* ]] || FULL[$fam]=0; done
done

TS="$(date +%Y%m%dT%H%M%S)"
STAGE_ROOT="$RESULTS/sketch_run.$TS.$$.tmp"
say() { echo "[$(date +%H:%M:%S)] $*"; [[ $DRY -eq 1 || ! -d $STAGE_ROOT ]] || echo "[$(date +%H:%M:%S)] $*" >> "$STAGE_ROOT/sketch_run.log"; }
show() { printf '    $'; printf ' %q' "$@"; printf '\n'; [[ $DRY -eq 1 || ! -d $STAGE_ROOT ]] || { printf '    $'; printf ' %q' "$@"; printf '\n'; } >> "$STAGE_ROOT/sketch_run.log"; }

showline() { echo "    \$ $1"; [[ $DRY -eq 1 || ! -d $STAGE_ROOT ]] || echo "    \$ $1" >> "$STAGE_ROOT/sketch_run.log"; }

# ---- guards ---------------------------------------------------------------------
foreign_provers() {   # this user's zokrates/exp_compose/r0vm (ours have all exited when this runs)
  local p out=""
  for p in zokrates exp_compose r0vm; do out+=$(pgrep -u "$(id -u)" -x "$p" | tr '\n' ' '); done
  echo "${out% }"
}
guard() {             # guard <label> [procs]: wait for a quiet box, or refuse
  ((ALLOW_BUSY)) && return 0
  local t0=$SECONDS l busy maxl=$MAX_LOAD
  [[ ${2:-} == procs ]] && maxl=100000   # later steps: other provers only (our runs lift load1)
  while :; do
    l=$(cut -d' ' -f1 /proc/loadavg); busy=$(foreign_provers)
    if awk -v l="$l" -v m="$maxl" 'BEGIN{exit !(l <= m)}' && [[ -z $busy ]]; then
      say "guard $1: load1=$l ok"; return 0
    fi
    if ((SECONDS - t0 >= WAIT_S)); then
      say "guard $1: REFUSED after ${WAIT_S}s: load1=$l (max $maxl), other provers: [${busy:-none}]"; return 3
    fi
    sleep 30
  done
}

# ---- ZoKrates family commands (the sequences behind the CSVs) ---------------------
# Every command is run with RESULTS=<staging dir of the family>.
fam_cmds() {   # fam_cmds <fam> <sub> -> one command per line (eval'd)
  local d="$HERE"
  case $1:$2 in
    hll:probes)
      for s in 16 64 256 1024 4096; do echo "CK=8 $d/hll/probes/constraint_probe.sh \"\$RESULTS/zkstream_hll_constraint_probe.csv\" default $s 1 2"; done
      for p in 1 2 4 8 16 32; do echo "CK=8 $d/hll/probes/constraint_probe.sh \"\$RESULTS/zkstream_hll_packing_probe.csv\" $p 1024 1 2"; done ;;
    hll:grid)     echo "$d/hll/run_hll.py --ck 8 --s 16 64 256 1024 4096 --k 4 16 64 --chunks 4 --tamper --prune --allow-busy" ;;
    hll:deployed) echo "$d/hll/run_hll.py --ck 8 --s 16384 --k 4 16 64 --chunks 4 --tamper --prune --allow-busy" ;;
    hll:wall)     if ((SKIP_REF)); then echo "$d/hll/run_hll.py --ck 8 --s 16384 --k 256 --chunks 4 --tamper --prune --allow-busy"
                  else echo "$d/hll/run_hll.py --ck 8 --s 16384 --k 256 1024 --chunks 4 --tamper --prune --allow-busy"; fi ;;
    hll:edge)     echo "$d/hll/run_hll.py --ck 8 --s 16384 --k 512 --chunks 4 --tamper --prune --allow-busy --no-helper" ;;
    hll:refresh)
      for ck in 1 8; do echo "CK=$ck $d/hll/probes/constraint_probe.sh \"\$RESULTS/zkstream_hll_refresh_probe_regen.csv\" default 16384 4 16 64"; done ;;
    ss:grid)      echo "$d/ss/run_ss.py --s 8 16 32 64 128 --k 4 16 64 --chunks 4 --prune" ;;
    ss:scaling)   echo "$d/ss/run_ss.py --s 256 1024 4096 --k 1 --compile-only" ;;
    ss:large)     echo "$d/ss/run_ss.py --s 4096 --k 1 --chunks 5 --prune" ;;
    ss:deployed)  ((SKIP_REF)) || echo "$d/ss/run_ss.py --s 16384 --k 1 --chunks 5 --prune" ;;
    gk:grid)      echo "$d/gk/run_gk.py --E 8 16 --k 4 16 64 --cap 16 32 64 --chunks 4 --tamper --prune --overflow-demo --log zkstream_gk_$TS.log" ;;
    gk:sweep)
      local t="--tag 'constraint_sweep (compile only)' --log zkstream_gk_$TS.log"
      echo "$d/gk/run_gk.py --compile-only --E 8 --k 4 --cap 8 128 256 --nb 10 $t"
      for nb in 14 18 22; do echo "$d/gk/run_gk.py --compile-only --E 8 --k 4 --cap 32 --nb $nb $t"; done
      echo "$d/gk/run_gk.py --compile-only --E 32 --k 1 4 16 --cap 16 32 64 --nb 14 $t"
      echo "$d/gk/run_gk.py --compile-only --E 4 --k 16 --cap 32 --nb 10 $t"
      echo "$d/gk/run_gk.py --compile-only --E 64 --k 32 --cap 64 128 256 --nb 21 $t" ;;
    gk:validate)
      for st in aol fewdistinct; do
        for c in "8 16 32" "16 4 64" "16 64 64"; do set -- $c
          echo "$d/gk/run_gk.py --E $1 --k $2 --cap $3 --chunks 0 --validate-chunks 250 --stream $st --tag 'validation (witness only)' --log zkstream_gk_$TS.log"
        done
      done ;;
    gk:probes)
      for cap in 512 1024 2048; do
        echo "$d/gk/run_gk.py --E 64 --k 32 --cap $cap --nb 21 --chunks 4 --tamper --prune --log zkstream_gk_$TS.log --tag 'large-capacity probe (deployed-width g/Delta: NB=21)'"
      done ;;
  esac
}
fam_build() { echo "$BASELINE_DIR/build/zkstream_$1"; }
fam_csvs() {   # canonical files a full run of <fam> regenerates
  case $1 in
    hll) echo "zkstream_hll.csv zkstream_hll_constraint_probe.csv zkstream_hll_packing_probe.csv" ;;
    ss)  echo "zkstream_ss.csv" ;;
    gk)  echo "zkstream_gk.csv" ;;
  esac
}

# gate <fam> <staged csv> <full 0|1>: no ok=0 row except budget refusals (and GK capacity
# drops); the expected number of proven points
gate() {
  python3 - "$@" <<'PY'
import csv, sys
fam, path, full = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
need = {"hll": 20, "ss": 16, "gk": 18}[fam]
rows = list(csv.DictReader(open(path)))
# allowed ok=0 rows: a compile the budget refused; a GK point the native reference dropped
# because s' cannot hold its chain (its overflow_rejected row must then be ok=1)
bad = [r for r in rows if r.get("ok") == "0" and not (
       (r["step"].startswith("compile")
        and any(w in r.get("note", "").lower() for w in ("refused", "over budget", "timeout")))
       or (fam == "gk" and r["step"] == "capacity"))]
key = {"hll": ("s", "k"), "ss": ("s", "k"), "gk": ("eps_den", "k", "cap")}[fam]
proven = {tuple(r[c] for c in key) for r in rows if r["step"] == "verify" and r.get("ok") == "1"}
print(f"gate {fam}: {len(rows)} rows, {len(bad)} failing, {len(proven)} proven points" + (f" (need {need})" if full else ""))
for r in bad[:10]:
    print("  FAIL", {c: r[c] for c in r if r[c]})
sys.exit(1 if bad or (full and len(proven) < need) else 0)
PY
}

# carry_refusals <fam> <prev csv> <staged csv>: append the previous rows of the skipped refusals
carry_refusals() {
  python3 - "$@" <<'PY'
import csv, sys
fam, prev, staged = sys.argv[1:4]
sel = {"hll": lambda r: r["s"] == "16384" and r["k"] == "1024",
       "ss": lambda r: r["s"] == "16384" and r["k"] == "1"}[fam]
with open(prev) as f:
    rd = csv.DictReader(f); keep = [r for r in rd if sel(r)]; cols = rd.fieldnames
with open(staged, "a", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    for r in keep: w.writerow(r)
print(f"carried over {len(keep)} previous {fam} refusal row(s) from {prev}")
PY
}

run_family() {
  local fam=$1 sub cmd rc=0 st gmode=""
  st="$STAGE_ROOT/$fam"
  say "== $fam: ${PLAN[$fam]} (full=${FULL[$fam]}) -> staging $st"
  ((DRY)) || mkdir -p "$st"
  for sub in ${PLAN[$fam]}; do
    while IFS= read -r cmd; do
      [[ -n $cmd ]] || continue
      showline "RESULTS=$st BUILD=$(fam_build "$fam") $cmd"
      ((DRY)) && continue
      guard "$fam:$sub" $gmode || return 3; gmode=procs
      local logf=/dev/null
      [[ $fam == ss ]] && logf="$st/zkstream_ss_${sub}_$TS.log"
      ( export RESULTS="$st" BUILD="$(fam_build "$fam")"; eval "$cmd" ) < /dev/null 2>&1 | tee -a "$logf" "$STAGE_ROOT/sketch_run.log"
      rc=${PIPESTATUS[0]}
      ((rc == 0)) || { say "$fam:$sub FAILED (exit $rc): $cmd"; return 1; }
    done < <(fam_cmds "$fam" "$sub")
  done
  ((DRY)) && return 0
  local main; main="$st/$(fam_csvs "$fam" | cut -d' ' -f1)"
  if [[ ! -f $main ]]; then
    [[ ${FULL[$fam]} == 1 ]] && { say "$fam: no staged CSV $main"; return 1; }
    say "$fam: partial run; canonical files untouched, staged files in $st"; return 0
  fi
  if ((SKIP_REF)) && [[ ${FULL[$fam]} == 1 && ( $fam == hll || $fam == ss ) && -f $RESULTS/zkstream_$fam.csv ]]; then
    carry_refusals "$fam" "$RESULTS/zkstream_$fam.csv" "$main" | tee -a "$STAGE_ROOT/sketch_run.log"
  fi
  gate "$fam" "$main" "${FULL[$fam]}" | tee -a "$STAGE_ROOT/sketch_run.log"
  ((PIPESTATUS[0] == 0)) || { say "$fam: gate FAILED; canonical files untouched, staged files in $st"; return 1; }
  if [[ ${FULL[$fam]} != 1 ]]; then
    say "$fam: partial run; canonical files untouched, staged files in $st"; return 0
  fi
  mkdir -p "$st/prev"
  local f
  for f in $(fam_csvs "$fam"); do
    [[ -f $st/$f ]] || { say "$fam: missing staged $f"; return 1; }
    [[ -f $RESULTS/$f ]] && cp -p "$RESULTS/$f" "$st/prev/$f"
    cp -p "$st/$f" "$RESULTS/$f"
  done
  for f in "$st"/zkstream_"$fam"_*.log "$st"/zkstream_hll_refresh_probe_regen.csv; do
    [[ -f $f ]] && cp -p "$f" "$RESULTS/"
  done
  say "$fam: regenerated $(fam_csvs "$fam") (previous copies in $st/prev)"
}

# ---- zkSketch's matched leaves ('ours') -------------------------------------------
# One line per point: family  s  k  1/eps  zok_point
#   s = registers (hll), counters (ss), capacity s' (gk); k = records per chunk/batch.
#   zok_point: grid | large (a ZoKrates point outside the grid) | zok_refused (compile
#   over budget) | zok_dropped (GK capacity too small for the chain) | deployed
ours_points() {
  local s k c
  for s in 16 64 256 1024 4096; do for k in 4 16 64; do echo "hll $s $k - grid"; done; done
  for k in 4 16 64; do echo "hll 16384 $k - grid"; done
  echo "hll 16384 256 - large"; echo "hll 16384 512 - large"; echo "hll 16384 1024 - zok_refused"
  for s in 8 16 32 64 128; do for k in 4 16 64; do echo "ss $s $k - grid"; done; done
  echo "ss 4096 1 - large"; echo "ss 16384 1 - zok_refused"
  for c in "8 4 16" "8 4 32" "8 4 64" "8 16 16" "8 16 32" "8 16 64" "8 64 32" "8 64 64" \
           "16 4 16" "16 4 32" "16 4 64" "16 16 32" "16 16 64" "16 64 32" "16 64 64"; do
    set -- $c; echo "gk $3 $2 $1 grid"
  done
  for c in "8 64 16" "16 16 16" "16 64 16"; do set -- $c; echo "gk $3 $2 $1 zok_dropped"; done
  for s in 512 1024 2048; do echo "gk $s 32 64 large"; done
  if ((DEPLOYED)); then
    echo "hll 16384 16384 - deployed"; echo "ss 16384 16384 - deployed"; echo "gk 2048 16384 51 deployed"
  fi
}
OURS_COLS="run,commit,family,variant,zok_point,s,k,eps_den,shape,m,rep,prove_ms,verify_ms,proof_bytes,peak_rss_mb,proc_max_rss_mb,proc_wall_s,load1,status,note"

ours_build() {
  local rev; rev=$(git -C "$ZKS" rev-parse --verify "$OURS_REV^{commit}") || { say "ours: unknown revision $OURS_REV"; return 2; }
  OURS_COMMIT=$rev
  show git -C "$ZKS" archive "$rev" "|" tar -x -C "$OURS_DIR/src_rs"
  show cargo build --release --example exp_compose "(CARGO_TARGET_DIR=$OURS_DIR/target)"
  ((DRY)) && return 0
  if [[ ! -f $OURS_DIR/src_rs/.rev || $(cat "$OURS_DIR/src_rs/.rev") != "$rev" ]]; then
    rm -rf "$OURS_DIR/src_rs"; mkdir -p "$OURS_DIR/src_rs"
    git -C "$ZKS" archive "$rev" | tar -x -C "$OURS_DIR/src_rs" || return 1
    echo "$rev" > "$OURS_DIR/src_rs/.rev"
  fi
  ( cd "$OURS_DIR/src_rs" && CARGO_TARGET_DIR="$OURS_DIR/target" cargo build --release --example exp_compose 2>&1 | tail -2
    exit "${PIPESTATUS[0]}" ) || { say "ours: build failed (rev $rev)"; return 1; }
  OURS_BIN="$OURS_DIR/target/release/examples/exp_compose"
  [[ -x $OURS_BIN ]] || { say "ours: build failed"; return 1; }
}

run_ours() {
  local st out ncores
  st="$STAGE_ROOT/ours"
  say "== ours: zkSketch leaves at the ZoKrates points, rev $OURS_REV, reps $OURS_REPS -> staging $st"
  ours_build || return 1
  ncores=$(taskset -c "$PIN_CPUS" nproc)
  out="$st/zks_sketch_small.csv"
  ((DRY)) || { mkdir -p "$st"; echo "$OURS_COLS" > "$out"; }
  local fam s k E pt m b note envs rep name src tfile rc load reps variant gmode=""
  while read -r fam s k E pt; do
    note=""; m=$k; envs=()
    case $fam in
      hll) b=0; while ((1 << b < s)); do b=$((b + 1)); done; envs=(EXP_COMPOSE_FAMILY=hll "EXP_HLL_B=$b"); variant=hll_omc ;;
      ss)  ((m < 2)) && { m=2; note="m=2: ss_final_full needs an even batch >= 2 (ZoKrates k=1)"; }
           ((m % 2)) && m=$((m + 1)); envs=(EXP_COMPOSE_FAMILY=ss "EXP_SS_CAP=$s"); variant=ss_final_full ;;
      gk)  envs=(EXP_COMPOSE_FAMILY=gk "EXP_GK_CAP=$s" "EXP_GK_S=$E"); variant=gk_bandmerge2 ;;
    esac
    reps=$OURS_REPS; [[ $pt == deployed ]] && reps=1
    for rep in $(seq 1 "$reps"); do
      name="zks_sketch_${fam}_${s}_${k}_r${rep}_$$.csv"
      local cmd=(env -u ZKSKETCH_BINDING -u ZKSKETCH_STATEMENT -u EXP_ROOT_VK "${envs[@]}"
                 "EXP_COMPOSE_N=$m" "EXP_COMPOSE_BATCHES=$m" EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=sim
                 EXP_DATASET=aol "EXP_COMPOSE_CORES=$ncores" "EXP_OUT=$name"
                 taskset -c "$PIN_CPUS" /usr/bin/time -f "TIME %e %M" -o "$st/$name.time"
                 timeout "$CAP_T" systemd-run --user --scope -q -p "MemoryMax=$CAP_M" "${OURS_BIN:-exp_compose}")
      if ((DRY)); then [[ $rep == 1 ]] && show "${cmd[@]}"; continue; fi
      [[ $rep == 1 ]] && { guard "ours:$fam:$s:$k" $gmode || return 3; gmode=procs; }
      load=$(cut -d' ' -f1 /proc/loadavg)
      ( cd "$OURS_DIR/src_rs" && "${cmd[@]}" ) < /dev/null >> "$st/ours_console.log" 2>&1
      rc=$?
      src="$OURS_DIR/src_rs/results/$name"
      python3 - "$src" "$st/$name.time" "$rc" "$out" "$TS" "$OURS_COMMIT" "$fam" "$variant" "$pt" "$s" "$k" "$E" "$m" "$rep" "$load" "$note" <<'PY'
import csv, os, sys
src, tfile, rc, out, run, commit, fam, variant, pt, s, k, E, m, rep, load, note = sys.argv[1:17]
wall = rss = ""
if os.path.exists(tfile):
    for ln in open(tfile):
        if ln.startswith("TIME "):
            _, w, kb = ln.split()
            wall, rss = w, f"{int(kb) / 1024:.1f}"
row = dict(run=run, commit=commit[:12], family=fam, variant=variant, zok_point=pt, s=s, k=k,
           eps_den="" if E == "-" else E, shape="", m=m, rep=rep, prove_ms="", verify_ms="",
           proof_bytes="", peak_rss_mb="", proc_max_rss_mb=rss, proc_wall_s=wall, load1=load,
           status="", note=note)
if os.path.exists(src):
    r = next(csv.DictReader(open(src)))
    row.update(shape=r["shape"], prove_ms=r["total_time_ms"], verify_ms=r["verify_ms"],
               proof_bytes=r["proof_bytes"], peak_rss_mb=r["peak_rss_mb"], status=r["status"])
    assert r["t"] == "1" and r["m"] == m and r["exec"] == "sim", r
    os.remove(src)
else:
    row["status"] = "refused_budget" if rc in ("124", "137") else f"error_rc{rc}"
with open(out, "a", newline="") as f:
    csv.DictWriter(f, fieldnames=list(row)).writerow(row)
print(f"  {fam:<3} s={s:<6} k={k:<5} m={m:<5} rep={rep} prove_ms={row['prove_ms']} verify_ms={row['verify_ms']} "
      f"proof_B={row['proof_bytes']} rss_MB={row['peak_rss_mb']} proc_rss_MB={rss} status={row['status']}")
PY
      rm -f "$st/$name.time"
    done
  done < <(ours_points)
  ((DRY)) && return 0
  local nbad; nbad=$(awk -F, 'NR>1 && $19!="ok"' "$out" | wc -l)
  say "ours: $(($(wc -l < "$out") - 1)) rows, $nbad not ok (a GK point the capacity cannot hold reports too_large)"
  local prevmsg=""
  if [[ -f $RESULTS/zks_sketch_small.csv ]]; then
    mkdir -p "$st/prev"; cp -p "$RESULTS/zks_sketch_small.csv" "$st/prev/"; prevmsg=" (previous copy in $st/prev)"
  fi
  cp -p "$out" "$RESULTS/zks_sketch_small.csv"
  say "ours: regenerated zks_sketch_small.csv$prevmsg"
}

run_fit() {
  say "== fit"
  show "$HERE/hll/fit.py"
  show "$HERE/ss/fit_ss.py" ">" "$RESULTS/zkstream_ss_fit.log"
  show "$HERE/gk/fit_gk.py"
  ((DRY)) && return 0
  local rc=0
  "$HERE/hll/fit.py" 2>&1 | tee -a "$STAGE_ROOT/sketch_run.log"; ((PIPESTATUS[0] == 0)) || rc=1
  "$HERE/ss/fit_ss.py" > "$STAGE_ROOT/zkstream_ss_fit.log" 2>&1 && cp "$STAGE_ROOT/zkstream_ss_fit.log" "$RESULTS/" || rc=1
  cat "$STAGE_ROOT/zkstream_ss_fit.log" >> "$STAGE_ROOT/sketch_run.log"
  RESULTS="$RESULTS" "$HERE/gk/fit_gk.py" 2>&1 | tee -a "$STAGE_ROOT/sketch_run.log"; ((PIPESTATUS[0] == 0)) || rc=1
  return $rc
}

# compare: matched tables. ZoKrates: per-chunk witness+prove (median over the chained
# chunks), verify (median, CLI), proof bytes (JSON), prove peak RSS (median).
# zkSketch: leaf witness+prove, verify, proof bytes, sampled peak RSS (medians over reps).
run_compare() {
  say "== compare"
  ((DRY)) && { show python3 "<embedded comparison>" "$RESULTS"; return 0; }
  python3 - "$RESULTS" <<'PY'
import csv, statistics as st, sys
from collections import defaultdict
R = sys.argv[1]
med = st.median
def load(n):
    try:
        return list(csv.DictReader(open(f"{R}/{n}")))
    except FileNotFoundError:
        return []
def zok(fam, keycols):
    pts = defaultdict(lambda: defaultdict(list))
    for r in load(f"zkstream_{fam}.csv"):
        key = tuple(int(r[c]) for c in keycols)
        if r["step"] == "compile_op" and r["constraints"]:
            pts[key][("cons", r["run"])] = int(r["constraints"])   # per run: GK sweeps vary nb
        if r["chunk"] == "" or not r.get("wall_s"):
            continue
        if r["step"] in ("witness_op", "prove") and r.get("ok", "1") != "0":
            pts[key][(r["run"], r["chunk"])].append(float(r["wall_s"]))
            if r["step"] == "prove":
                pts[key]["rss"].append(float(r["peak_rss_mb"])); pts[key]["bytes"].append(int(r["bytes"]))
        if r["step"] == "verify" and r.get("ok") == "1":
            pts[key]["ver"].append(float(r["wall_s"]) * 1e3)
    out = {}
    for key, d in pts.items():
        chunks = {kk: v for kk, v in d.items() if isinstance(kk, tuple) and kk[0] != "cons" and len(v) == 2}
        if chunks:
            run = next(iter(chunks))[0]   # the constraints of the proven run
            out[key] = dict(cons=d.get(("cons", run)), wp=med(sum(v) for v in chunks.values()),
                            ver=med(d["ver"]), bytes=med(d["bytes"]), rss=med(d["rss"]))
    return out
ours = defaultdict(list)
for r in load("zks_sketch_small.csv"):
    ours[(r["family"], int(r["s"]), int(r["k"]), r["eps_den"])].append(r)
def zks(fam, s, k, E=""):
    rs = [r for r in ours.get((fam, s, k, E), []) if r["status"] == "ok"]
    if not rs:
        st_ = {r["status"] for r in ours.get((fam, s, k, E), [])}
        return None, ",".join(sorted(st_)) or "-"
    return dict(p=med(float(r["prove_ms"]) for r in rs) / 1e3, v=med(float(r["verify_ms"]) for r in rs),
                b=med(int(r["proof_bytes"]) for r in rs), rss=med(float(r["peak_rss_mb"]) for r in rs),
                m=rs[0]["m"], n=len(rs)), "ok"
def fmt_s(x):
    return f"{x:.3f} s" if x < 1 else f"{x:.2f} s"
def table(title, head, rows):
    print(f"\n### {title}\n")
    print("| " + " | ".join(head) + " |"); print("|" + "---|" * len(head))
    for r in rows:
        print("| " + " | ".join(r) + " |")
H = ["constraints", "ZoKrates w+p", "zkSketch w+p", "ratio", "ZoKrates verify", "zkSketch verify",
     "zkSketch proof", "ZoKrates RSS", "zkSketch RSS"]
def cells(z, o, st_):
    if o is None:
        return [f"{z['cons']:,}", fmt_s(z["wp"]), st_, "-", f"{z['ver']:.1f} ms", "-", "-", f"{z['rss']:.0f} MB", "-"]
    return [f"{z['cons']:,}", fmt_s(z["wp"]), fmt_s(o["p"]), f"{z['wp'] / o['p']:.1f}x", f"{z['ver']:.1f} ms",
            f"{o['v']:.1f} ms", f"{o['b'] / 1024:.0f} KiB", f"{z['rss']:.0f} MB", f"{o['rss']:.0f} MB"]
Z = zok("hll", ("s", "k"))
table("HyperLogLog: s registers, k records per chunk/batch", ["s", "k"] + H,
      [[str(s), str(k)] + cells(Z[(s, k)], *zks("hll", s, k)) for s, k in sorted(Z)])
Z = zok("ss", ("s", "k"))
rows = []
for s, k in sorted(Z):
    o, st_ = zks("ss", s, k)
    rows.append([str(s), f"{k}" + (f" (zkSketch m={o['m']})" if o and o["m"] != str(k) else "")] + cells(Z[(s, k)], o, st_))
table("SpaceSaving: s counters, k records per chunk/batch", ["s", "k"] + H, rows)
Z = zok("gk", ("eps_den", "k", "cap"))
table("Greenwald-Khanna: 1/eps, k records per chunk/batch, capacity s'", ["1/eps", "k", "s'"] + H,
      [[str(E), str(k), str(c)] + cells(Z[(E, k, c)], *zks("gk", c, k, str(E))) for E, k, c in sorted(Z, key=lambda t: (t[2] > 64, t))])
extra = [(f, s, k, E, r[0]["zok_point"]) for (f, s, k, E), r in sorted(ours.items()) if r[0]["zok_point"] not in ("grid", "large")]
if extra:
    print("\n### zkSketch points with no proven ZoKrates counterpart\n")
    print("| family | s | k | 1/eps | ZoKrates | zkSketch m | w+p | verify | proof | RSS | status |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for f, s, k, E, pt in extra:
        o, st_ = zks(f, s, k, E)
        if o:
            print(f"| {f} | {s} | {k} | {E or '-'} | {pt} | {o['m']} | {fmt_s(o['p'])} | {o['v']:.1f} ms | {o['b'] / 1024:.0f} KiB | {o['rss']:.0f} MB | ok |")
        else:
            print(f"| {f} | {s} | {k} | {E or '-'} | {pt} | - | - | - | - | - | {st_} |")
PY
}

# ---- main -------------------------------------------------------------------------
say "sketch_run $TS: stages [${STAGES[*]}]$(for f in hll ss gk; do [[ -n ${PLAN[$f]:-} ]] && printf ' %s=[%s]' "$f" "${PLAN[$f]}"; done)" \
    "skip_refusals=$SKIP_REF deployed=$DEPLOYED max_load=$MAX_LOAD wait=${WAIT_S}s pin=$PIN_CPUS dry=$DRY"
NEED_STAGE=0; for stg in "${STAGES[@]}"; do [[ $stg == compare ]] || NEED_STAGE=1; done
((DRY || !NEED_STAGE)) || { require_tools || exit 2; mkdir -p "$STAGE_ROOT"; say "staging: $STAGE_ROOT"; }
status=0
for stg in "${STAGES[@]}"; do
  case $stg in
    hll|ss|gk) run_family "$stg" || { status=1; say "$stg: not regenerated"; } ;;
    ours)      run_ours || { status=1; say "ours: not regenerated"; } ;;
    fit)       run_fit || status=1 ;;
    compare)   run_compare || status=1 ;;
  esac
done
((DRY || !NEED_STAGE)) || say "done (exit $status); log: $STAGE_ROOT/sketch_run.log"
exit $status
