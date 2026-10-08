#!/usr/bin/env bash
# zkSketch's SpaceSaving batch rule (mergeable Misra-Gries) as a RISC Zero guest
# (ss_mg; see README.md and ../README.md). EXECUTOR ONLY: proves nothing.
#
#   0. unit tests (native only): ss-mg-core vs zkSketch apply_batch_ss_full on
#      small random shapes (ties at the cut, pads, mask aliases), both sorts
#   1. equivalence: guest-chained epochs 0..N-1 (each run reads the previous
#      GUEST output) on AOL and Uniform at every s in CAPS; N = CHAIN_EPOCHS
#      (default 64 = the whole 2^20-record stream) with the headline radix sort
#      and STD_CHAIN_EPOCHS (default 8) with the std sort. Every run is checked
#      row by row and field by field against zkSketch's native
#      apply_batch_ss_full, its commitments against SHA-256 of zkSketch's
#      native objects, Com_old(e) against Com_new(e-1), and its cycle marks
#      against the executor's user cycles (probes_ok)        -> zka_ss_mg_equiv.csv
#   2. cost: AOL epoch 0, AOL epoch LATE_EPOCH (S_LATE computed natively from
#      epochs 0..LATE-1, ss-mg-core checked on every one of them), Uniform
#      epoch 0, at every s in CAPS, for three configurations (each run checked
#      as in 1)                                              -> zka_ss_mg_exec.csv
#        ss_mg       radix   headline (input via env::read_slice)
#        ss_mg       std     sort sensitivity (pdqsort + select_nth)
#        ss_mg_serde radix   read-path sensitivity (risc0 serde env::read, as the zka guests)
#
# Every row carries MODELED prove time = segments x 30.1 s (envelope
# 29.73..30.79), the CM-guest CPU anchors of ../README.md. NOT measured.
#
# Columns: the driver's (ss_mg --header), plus two this script appends from
# r0vm's own session summary (RISC0_INFO=1, one per guest run, in run order):
# r0vm_paging_cycles and r0vm_reserved_cycles. Every row is checked against it:
# r0vm's user cycles == user_cycles, its total == padded_cycles, and
# user + paging + reserved == total; a mismatch fails the step.
#
# Both CSVs are REGENERATED: rows go to <csv>.tmp, which replaces the CSV only
# if every step passed (the previous CSV is kept as <csv>.prev, gitignored).
# The raw log ../results/zka_ss_mg_exec.log is only ever appended to (one
# header per run, failed runs included): the unit-test results, every cost
# row, one summary line per chain (the chain rows themselves are in
# zka_ss_mg_equiv.csv) and the driver's messages, r0vm's summaries excepted.
#
# Usage: ./ss_mg_exec.sh
# Env:   SKIP_BUILD=1          use the existing binaries
#        SKIP_TESTS=1          skip step 0
#        CAPS="16384 1024"     capacities
#        CHAIN_EPOCHS=64       guest-chained epochs, radix sort (>= 4)
#        STD_CHAIN_EPOCHS=8    guest-chained epochs, std sort (>= 4)
#        LATE_EPOCH=63         late AOL epoch of the cost rows ("" skips it)
#        KEYS=...              AOL keys (default <checkout>/data/aol.keys)
#        RESULTS=...           output directory (default ../results)
#
# Kills nothing: each executor run spawns its own r0vm child, which exits with
# the run. RISC0_DEV_MODE is refused (here and by the driver).
set -uo pipefail
SSMG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SSMG_DIR/../common.sh"
unset RISC0_DEV_MODE
SSMG_TARGET="$BASELINE_DIR/build/zka-ss-mg"
SSMG_BIN="$SSMG_TARGET/release/ss_mg"
ssmg_elf() { echo "$SSMG_TARGET/riscv-guest/ss-mg-methods/$1/riscv32im-risc0-zkvm-elf/release/$1"; }

read -r -a CAPS <<< "${CAPS:-16384 1024}"
CHAIN_EPOCHS=${CHAIN_EPOCHS:-64}
STD_CHAIN_EPOCHS=${STD_CHAIN_EPOCHS:-8}
LATE_EPOCH=${LATE_EPOCH-63}
KEYS=${KEYS:-$ZKS/data/aol.keys}
EXEC_CSV=$RESULTS/zka_ss_mg_exec.csv
EQUIV_CSV=$RESULTS/zka_ss_mg_equiv.csv
LOG=$RESULTS/zka_ss_mg_exec.log
[[ -s $KEYS ]] || { echo "missing $KEYS (tracked in git as data/aol.keys; restore it in the checkout, or point KEYS= at a copy)" >&2; exit 2; }
(( CHAIN_EPOCHS >= 4 && STD_CHAIN_EPOCHS >= 4 )) || { echo "CHAIN_EPOCHS and STD_CHAIN_EPOCHS must be >= 4" >&2; exit 2; }
mkdir -p "$RESULTS"
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/ss_mg_exec.XXXXXX") || exit 2
trap 'rm -rf "$TMPD"' EXIT
# Paths in the log are relative to the checkout when they lie inside it, so the
# record does not depend on where the checkout sits.
rel() { case $1 in "$ZKS"/*) echo "${1#"$ZKS"/}" ;; *) echo "$1" ;; esac; }

# Host build pinned by Cargo.lock (--locked); the guest ELFs by
# methods/guests/Cargo.lock, which risc0-build's nested cargo honours only with
# RISC0_BUILD_LOCKED=1 (same arrangement as ../common.sh build_cyc).
cargo_ssmg() {  # cargo_ssmg <subcommand> [args...]
  local sub=$1; shift
  ( cd "$SSMG_DIR" && CARGO_TARGET_DIR="$SSMG_TARGET" RISC0_BUILD_LOCKED=1 cargo "$sub" --release --locked "$@" )
}
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  cargo_ssmg build >&2 || { echo "build failed" >&2; exit 2; }
fi
[[ -x $SSMG_BIN && -s $(ssmg_elf ss_mg) && -s $(ssmg_elf ss_mg_serde) ]] \
  || { echo "missing $SSMG_BIN or a guest ELF -- run without SKIP_BUILD" >&2; exit 2; }

{
  echo "# ss_mg_exec.sh $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] nproc=$(nproc)"
  echo "# r0vm=$(r0vm --version 2>/dev/null) keys=$(rel "$KEYS") md5=$(md5sum < "$KEYS" | cut -c1-12) caps=${CAPS[*]}" \
       "chain_epochs=$CHAIN_EPOCHS std_chain_epochs=$STD_CHAIN_EPOCHS late_epoch=${LATE_EPOCH:-none}"
  echo "# zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD)" \
       "ss_mg_untracked_or_dirty_files=$(git -C "$ZKS" status --porcelain -- "$SSMG_DIR" | wc -l)" \
       "native_reference_dirty_files=$(git -C "$ZKS" status --porcelain -- src/sketch/ss_final_full.rs src/experiments/stream_compose.rs src/dataset.rs | wc -l)"
  echo "# columns: ss_mg --header + r0vm_paging_cycles,r0vm_reserved_cycles (from r0vm's RISC0_INFO session summary)"
  echo "# guest risc0-zkvm=$(awk '/name = "risc0-zkvm"/{getline; print $3}' "$SSMG_DIR/methods/guests/Cargo.lock" | tr -d '"')" \
       "host risc0-zkvm=$(awk '/name = "risc0-zkvm"/{getline; print $3}' "$SSMG_DIR/Cargo.lock" | tr -d '"')"
  for g in ss_mg ss_mg_serde; do
    echo "# elf $g md5=$(md5sum < "$(ssmg_elf $g)" | cut -d' ' -f1) image_id=$("$SSMG_BIN" --image-id --guest $g)"
  done
} | tee -a "$LOG" >&2

fails=0
if [[ ${SKIP_TESTS:-0} != 1 ]]; then
  echo "[test] cargo test --release --locked --bin ss_mg" | tee -a "$LOG" >&2
  t_out=$(cargo_ssmg test --bin ss_mg -- --nocapture 2>&1); rc=$?
  grep -E '^(test |test result|radix: |std: )' <<< "$t_out" | sed 's/^/       /' | tee -a "$LOG" >&2
  if [[ $rc -ne 0 ]]; then
    echo "[FAIL] unit tests (rc=$rc)" | tee -a "$LOG" >&2; tail -40 <<< "$t_out" >> "$LOG"; fails=$((fails+1))
  fi
fi

hdr="$("$SSMG_BIN" --header),r0vm_paging_cycles,r0vm_reserved_cycles"
for f in "$EXEC_CSV" "$EQUIV_CSV"; do echo "$hdr" > "$f.tmp"; done

# dataset, guest, sort, capacity, epoch, union_distinct, tau, new_active, user_cycles, segments, transition_cycles, MODELED
SUMMARY_COLS=3-6,8,13-15,18,20,28,42

# Driver runs pass RISC0_INFO=1 to their r0vm children, which then log their
# session summary (user / paging / reserved / total cycles; target
# risc0_zkvm::host::server::session). r0vm logs to the stdout it shares with the
# driver, so the CSV rows are the lines starting "zka-port,".
R0VM_INFO=(env RISC0_INFO=1 RUST_LOG=risc0_zkvm::host::server::session=info)
R0VM_SUMMARY='risc0_zkvm::host::server::session: '
ssmg_run() {  # ssmg_run <tmp prefix> <driver args...>: the driver's CSV rows on stdout, r0vm's summaries
              # to <prefix>.r0vm; everything else either process printed goes to the log
  local t=$1 rc; shift
  "${R0VM_INFO[@]}" "$SSMG_BIN" "$@" --keys "$KEYS" >"$t.out" 2>"$t.err"; rc=$?
  sed -E 's/\x1b\[[0-9;]*m//g' "$t.out" "$t.err" > "$t.all"
  grep -F "$R0VM_SUMMARY" "$t.all" > "$t.r0vm"
  grep -vE "^zka-port,|$R0VM_SUMMARY" "$t.all" >> "$LOG"
  grep -E '^zka-port,' "$t.out"
  return $rc
}
r0vm_cols() {  # r0vm_cols <r0vm summaries> <rows>: append r0vm's paging and reserved cycles to each row, checked
  sed -nE "s/.*$R0VM_SUMMARY([0-9]+) (total|user|paging|reserved) cycles.*/\\2 \\1/p" "$1" > "$1.sum"
  awk -F, -v OFS=, -v sumf="$1.sum" '
    BEGIN { while ((getline line < sumf) > 0) { split(line, f, " "); if (f[1] == "total") r++; v[r, f[1]] = f[2] } }
    { if (NR > r) { bad = "no r0vm summary for row " NR; exit }
      u = v[NR, "user"]; t = v[NR, "total"]; p = v[NR, "paging"]; q = v[NR, "reserved"]
      if (u == "" || t == "" || p == "" || q == "" || u != $18 || t != $19 || u + p + q != t) {
        bad = sprintf("row %d: r0vm user %s paging %s reserved %s total %s vs user_cycles %s padded_cycles %s", NR, u, p, q, t, $18, $19); exit }
      print $0, p, q }
    END { if (bad == "" && NR != r) bad = sprintf("%d rows, %d r0vm summaries", NR, r)
          if (bad != "") { print "r0vm summary check FAILED: " bad > "/dev/stderr"; exit 1 } }' <<< "$2"
}

run_exec() {  # run_exec <driver args...>: one cost row, also teed to the log
  echo "[run ] ss_mg $*" | tee -a "$LOG" >&2
  local row rc t=$TMPD/exec
  row=$(ssmg_run "$t" "$@"); rc=$?
  if [[ $rc -ne 0 || $(grep -c . <<< "$row") -ne 1 ]]; then echo "[FAIL] rc=$rc: $*" | tee -a "$LOG" >&2; return 1; fi
  row=$(r0vm_cols "$t.r0vm" "$row" 2>"$t.chk"); rc=$?
  tee -a "$LOG" < "$t.chk" >&2
  if [[ $rc -ne 0 ]]; then echo "[FAIL] r0vm summary: $*" | tee -a "$LOG" >&2; return 1; fi
  echo "$row" | tee -a "$LOG" >> "$EXEC_CSV.tmp"
  cut -d, -f$SUMMARY_COLS <<< "$row" | sed 's/^/       -> /' >&2
}

run_chain() {  # run_chain <epochs> <driver args...>: one row per epoch to the equiv CSV, a summary to the log
  local n=$1; shift
  echo "[run ] ss_mg --mode chain --epochs $n $*" | tee -a "$LOG" >&2
  local rows rc t=$TMPD/chain
  rows=$(ssmg_run "$t" --mode chain --epochs "$n" "$@"); rc=$?
  if [[ $rc -ne 0 || $(grep -c . <<< "$rows") -ne $n ]]; then
    echo "[FAIL] rc=$rc rows=$(grep -c . <<< "$rows"): chain $*" | tee -a "$LOG" >&2; return 1
  fi
  rows=$(r0vm_cols "$t.r0vm" "$rows" 2>"$t.chk"); rc=$?
  tee -a "$LOG" < "$t.chk" >&2
  if [[ $rc -ne 0 ]]; then echo "[FAIL] r0vm summary: chain $*" | tee -a "$LOG" >&2; return 1; fi
  echo "$rows" >> "$EQUIV_CSV.tmp"
  # every row's state_eq/journal_eq/com_eq/probes_ok are true (the driver exits 1 otherwise); link_ok on epochs >= 1
  awk -F, -v n="$n" '
       NR == 1 { umin = umax = $18; smin = smax = $20 }
       { if ($18 < umin) umin = $18; if ($18 > umax) umax = $18; if ($20 < smin) smin = $20; if ($20 > smax) smax = $20
         ev += ($14 > 0); if (NR > 1 && $40 != "true") bad++ }
       END { printf "       -> %d epochs ok (field-by-field, commitments, links%s, probes, r0vm summaries); epochs with tau>0: %d; user cycles %d..%d; segments %d..%d\n",
             n, (bad ? " BAD" : ""), ev, umin, umax, smin, smax }' <<< "$rows" | tee -a "$LOG" >&2
}

for ds in aol uniform; do
  for s in "${CAPS[@]}"; do
    run_chain "$CHAIN_EPOCHS"     --sort radix --dataset "$ds" --capacity "$s" || fails=$((fails+1))
    run_chain "$STD_CHAIN_EPOCHS" --sort std   --dataset "$ds" --capacity "$s" || fails=$((fails+1))
  done
done
for cfg in "ss_mg radix" "ss_mg std" "ss_mg_serde radix"; do
  read -r g sort <<< "$cfg"
  for s in "${CAPS[@]}"; do
    c=(--guest "$g" --sort "$sort" --mode exec --capacity "$s")
    run_exec "${c[@]}" --dataset aol --epoch-index 0 || fails=$((fails+1))
    if [[ -n $LATE_EPOCH ]]; then
      run_exec "${c[@]}" --dataset aol --epoch-index "$LATE_EPOCH" || fails=$((fails+1))
    fi
    run_exec "${c[@]}" --dataset uniform --epoch-index 0 || fails=$((fails+1))
  done
done

if (( fails > 0 )); then
  echo "done: $fails FAILED steps; canonical CSVs untouched, staged rows left in *.tmp (raw log $(rel "$LOG"))" | tee -a "$LOG" >&2
  exit 1
fi
for f in "$EXEC_CSV" "$EQUIV_CSV"; do
  [[ -s $f ]] && cp -p "$f" "$f.prev"
  mv "$f.tmp" "$f"
done
echo "done $(date -Is): all checks passed; wrote $(rel "$EXEC_CSV") ($(($(wc -l < "$EXEC_CSV") - 1)) rows) and $(rel "$EQUIV_CSV") ($(($(wc -l < "$EQUIV_CSV") - 1)) rows)" | tee -a "$LOG" >&2
