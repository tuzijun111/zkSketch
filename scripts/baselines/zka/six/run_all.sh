#!/usr/bin/env bash
# zkSketch vs zk-Analytics on six sketches (Count-Min, HyperLogLog, SpaceSaving/MG,
# Greenwald-Khanna, Bloom, KMV), on ONE machine. One entry point; run it from anywhere.
#
#   run_all.sh check            check the prerequisites; exit 1 if something blocking is missing
#   run_all.sh build            fetch zk-Analytics @ d4a5a9a into $BASELINE_DIR, build both sides
#   run_all.sh quick            smoke test of the whole pipeline at tiny scale (about 9-11 min on 32
#                               cores): zkSketch 7 runs at N = 512 (2 batches of 256), zk-Analytics
#                               executor for all six (noroot, and designed for the CM reference and
#                               the root-work table), 4 real zk-Analytics proofs (SIX_QUICK_PROVE),
#                               the rest ESTIMATED ("est")
#   run_all.sh full [--dry-run] [--from-logs DIR [--zks-prefix P]]
#                               the paper configuration: N = 16,384 = 8 x 2,048, zkSketch 7 runs,
#                               zk-Analytics executor + 42 proofs (aggregation epochs 0 and 7 of every
#                               family, noroot: 12; 28 queries; their shipped CM at epochs 0 and 7 as a
#                               reference: 2; about 3 h 30 min plus gate waits, an estimate). --dry-run
#                               prints the plan and runs nothing; the GK rank values and Bloom absent
#                               keys are then derived natively, or read from DIR's zkSketch logs with
#                               --from-logs (the real run reads this run's logs)
#   run_all.sh assemble DIR     re-run assemble.py + table.py on a finished results directory
#
# zk-Analytics root variants. Their code builds, inside each epoch's aggregation proof, a Merkle
# root over the summary's buckets; it is not part of their paper's protocol (an epoch publishes
# its hash-chain values and ONE commitment to the whole state, which the query proof opens:
# paper sections 5.2 and 5.3), and nothing in their code reads it. `noroot` = their guests
# without that root: the DEFAULT and the headline, for all six. Their shipped CM (`designed`:
# aggr_cm unchanged; its roots cost ~11.1-11.2M cycles per epoch) is proved as a REFERENCE only
# (SIX_ZKA_CM_REF), to relate to their published numbers. `designed` for the five ports (their
# samples pattern, 64 buckets) is an option (SIX_ZKA_ROOTS). Query proofs read no root and are
# proved once.
#
# Env:
#   BASELINE_DIR   zk-Analytics clone + its builds (default ~/ext-baselines; about 13 GB)
#   RESULTS        output directory (default <repo>/results/six/<mode>-<YYYYmmdd-HHMMSS>, git-ignored);
#                  must be new or empty
#   SIX_CORES      zkSketch cores (default: physical cores, at most 32 = the paper configuration)
#   GATE_WAIT_S    seconds to wait for a quiet box before each timed job (quick 0, full 1800)
#   GATE_MAX_LOAD, GATE_MAX_BUSY  the quiet thresholds (gate.sh; defaults CPUs/8 (2 below 16 CPUs) and 4)
#   SIX_ZKA_ROOTS  zk-Analytics aggregation variants executed and proved, a comma list of
#                  designed | noroot | legacy (default noroot; legacy = the guests of the committed
#                  2026-10-09 run). full proves 12 aggregation jobs per variant + 28 queries (+ 2 for
#                  the CM reference): 42 at the defaults, 52 with designed,noroot (the earlier default)
#   SIX_ZKA_CM_REF 1 (default): also prove their shipped CM aggregation (cm:aggr:<0|7>:designed) as a
#                  reference, and execute designed for all six (executor only); skipped when
#                  SIX_ZKA_ROOTS already has designed or legacy (the same CM guest). 0: off (full: 40 jobs)
#   SIX_ZKA_GK     matched (default) | textbook: the zk-Analytics side's GK. matched = zkSketch's own
#                  GK rule (the two-sided band-merge apply_batch2, capacity SIX_GK_CAP, s = 51, one step
#                  per zkSketch leaf, the state carried across epochs) inside their pipeline
#                  (../gk_matched): the same algorithm on both sides. textbook = textbook
#                  Greenwald-Khanna rebuilt per epoch (../gk), a different algorithm, kept as a
#                  labelled reference; SIX_ZKA_ROOTS=legacy needs it (the committed rows are textbook)
#   SIX_ZKA_GK_IMPL  literal (default) | tuned | fast | fixed_linear: the matched GK guest's implementation
#                  of the one transition (same state; literal = zkSketch's apply_batch2 code as written, the
#                  baseline; the others are our rewrites, sensitivity only)
#   SIX_QUICK_PROVE  quick: the jobs proved for real, as jobs.py --select selectors
#                  (default cm:aggr:0:noroot,kmv:aggr:0:noroot,gk:query:1,bloom:query:1:key: CM and
#                  KMV noroot at epoch 0, the GK query and the Bloom absent-key query at n = 1)
#   SIX_ALLOW_STALE=1  let quick/full use binaries older than their sources (refused by default;
#                  `run_all.sh build` refreshes them)
#   SIX_GK_ROUNDS  stable (default) | sorted: zkSketch's GK leaf circuit (six_common.sh); honoured by quick/full
#   SIX_BLOOM_VARIANT  packed (default) | omc: zkSketch's Bloom leaf (six_common.sh); honoured by quick/full
#   EXP_VERIFY_REPEATS, EXP_FOREST_RETAIN_PREP, EXP_MALLOC_TRIM, EXP_EXIT_BEFORE_AUDIT, EXP_MERGE_CACHE,
#                  EXP_MERGE_CACHE_ENTRIES  passed through to the zkSketch runs (run_zks.sh)
# quick and full use fixed run shapes: SIX_M, SIX_T, SIX_N, SIX_GK_CAP, SIX_GK_MSUB and SIX_QNS are
# ignored here (they apply to the individual six/*.sh scripts).
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZKS="$(cd "$HERE6/../../../.." && pwd)"
BASELINE_DIR="$(realpath -m -- "${BASELINE_DIR:-$HOME/ext-baselines}")"
export BASELINE_DIR
RZ_HOME=${RISC0_HOME:-$HOME/.risc0}
export PATH="$HOME/.cargo/bin:$RZ_HOME/bin:$PATH"
ZKA_REV=d4a5a9a90f7470b4af29045ef248f724708813ad
KEYS=$ZKS/data/aol.keys
KEYS_MD5=01dd7d5c8a73
EB=$BASELINE_DIR/build
ZKA_BINS=("$EB/cyc-t1/release/shipped" "$EB/hll/release/hll" "$EB/zka-ss/release/ss" "$EB/zka-gk/release/gk"
          "$EB/zka-bloom/release/bloom" "$EB/zka-kmv/release/kmv" "$EB/zka-gk-matched/release/gk_matched")
ZKS_BIN=$ZKS/target/release/examples/exp_compose
TAGS=(cm hll ss gk bloom bloom_absent kmv)
QUICK_PROVE_DEFAULT=cm:aggr:0:noroot,kmv:aggr:0:noroot,gk:query:1,bloom:query:1:key
# the CSV columns of drivers built with the root variants (`--root`; 4e98711 and later)
ROOT_COLS=root_variant,root_construction,variants_agree,state_commit
roots_ok() {  # roots_ok <list>: a comma list of distinct designed|noroot|legacy
  local v seen=,
  [[ $1 =~ ^(designed|noroot|legacy)(,(designed|noroot|legacy))*$ ]] || return 1
  for v in ${1//,/ }; do [[ $seen == *,$v,* ]] && return 1; seen+="$v,"; done
}
cm_ref_on() {  # cm_ref_on <roots> <cm_ref>: their shipped CM is planned as a reference
  [[ $2 == 1 && ,$1, != *,designed,* && ,$1, != *,legacy,* ]]
}
gk_knobs_ok() {  # gk_knobs_ok <zka_gk> <impl> <roots>: "" if fine, else why not
  case $1 in matched|textbook) ;; *) echo "SIX_ZKA_GK=$1: matched or textbook"; return ;; esac
  [[ $2 =~ ^(tuned|fast|fixed_linear|literal)$ ]] || { echo "SIX_ZKA_GK_IMPL=$2: tuned, fast, fixed_linear or literal"; return; }
  [[ $1 == textbook || ,$3, != *,legacy,* ]] ||
    echo "SIX_ZKA_ROOTS=$3 has legacy (the committed 2026-10-09 guests, whose GK is the textbook port): set SIX_ZKA_GK=textbook with it"
}
plan_counts() {  # plan_counts <roots> <cm_ref>: "<total> <aggregation> <reference>" jobs of full
  local nr na nref=0
  nr=$(tr ',' '\n' <<< "$1" | wc -l); na=$((12 * nr))
  if cm_ref_on "$1" "$2"; then nref=2; fi
  echo "$((na + nref + 28)) $na $nref"
}

die() { echo "error: $*" >&2; exit 2; }
hms() { printf '%dh%02dm%02ds' $(($1 / 3600)) $(($1 % 3600 / 60)) $(($1 % 60)); }
phys_cores() {
  local n
  n=$(lscpu -p=SOCKET,CORE 2>/dev/null | grep -v '^#' | sort -u | wc -l)
  (( n >= 1 )) || n=$(awk -F: '/^physical id/{p=$2} /^core id/{print p ":" $2}' /proc/cpuinfo 2>/dev/null | sort -u | wc -l)
  (( n >= 1 )) || n=$(nproc)
  echo "$n"
}
default_cores() { local c; c=$(phys_cores); (( c > 32 )) && c=32; (( c > $(nproc) )) && c=$(nproc); echo "$c"; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }  # ver_ge A B: A >= B

# ------------------------------------------------------------------ check
NMISS=0; NWARN=0
ok()   { printf 'OK      %s\n' "$*"; }
warn() { printf 'WARN    %s\n' "$*"; NWARN=$((NWARN + 1)); }
info() { printf 'INFO    %s\n' "$*"; }
miss() { printf 'MISSING %s\n' "$1"; [[ -n ${2:-} ]] && printf '        fix: %s\n' "$2"; NMISS=$((NMISS + 1)); }
APT="sudo apt-get install -y build-essential git curl ca-certificates python3 procps util-linux diffutils numactl"
RUSTUP="curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.1 && . \"\$HOME/.cargo/env\""
RZUP_INSTALL="curl -L https://risczero.com/install | bash && export PATH=\"\$HOME/.risc0/bin:\$PATH\""

check_tools() {  # what building and running need (also used by `build`)
  local os arch g t
  os=$(uname -s); arch=$(uname -m)
  if [[ $os == Linux && $arch == x86_64 ]]; then ok "platform: Linux x86_64"
  else miss "platform: $os $arch (RISC Zero's rzup ships Linux x86_64 toolchains; this harness reads /proc)"; fi
  g=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+$')
  if [[ -n $g ]] && ver_ge "$g" 2.34; then ok "glibc $g (>= 2.34 for the RISC Zero guest toolchain)"
  else miss "glibc ${g:-?}: the RISC Zero rust 1.97.0 toolchain needs glibc >= 2.34 and libstdc++ of GCC >= 12 (Ubuntu 22.04+, Debian 12+, Fedora 37+)"; fi
  if (( BASH_VERSINFO[0] >= 4 )); then ok "bash $BASH_VERSION"; else miss "bash >= 4 (have $BASH_VERSION)"; fi
  for t in git curl awk sed grep cut sort md5sum stat realpath nproc hostname date find mktemp diff; do
    command -v "$t" >/dev/null || miss "command '$t'" "$APT"
  done
  for t in pgrep ps; do command -v "$t" >/dev/null || miss "command '$t' (procps)" "$APT"; done
  for t in setsid findmnt; do command -v "$t" >/dev/null || miss "command '$t' (util-linux)" "$APT"; done
  if command -v cc >/dev/null; then ok "C compiler: $(cc --version 2>/dev/null | head -1)"
  else miss "C compiler 'cc' (the Rust linker; also compiles the ring crate)" "$APT"; fi
  if command -v python3 >/dev/null && python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 8))'; then
    if python3 -I -c 'import argparse, collections, csv, os, re, statistics, struct, subprocess, sys' 2>/dev/null; then
      ok "python3 $(python3 -I -c 'import platform; print(platform.python_version())') (standard library only)"
    else miss "python3 standard-library modules (argparse csv statistics struct subprocess)" "$APT"; fi
  else miss "python3 >= 3.8" "$APT"; fi
  if command -v numactl >/dev/null; then ok "numactl (zkSketch pins its worker with numactl --physcpubind)"
  elif command -v taskset >/dev/null; then warn "numactl missing; zkSketch pins with taskset instead (fine)"
  else warn "neither numactl nor taskset: zkSketch's worker runs unpinned (timings noisier). fix: $APT"; fi
  local rv cv
  rv=$(rustc --version 2>/dev/null | awk '{print $2}'); cv=$(cargo --version 2>/dev/null | awk '{print $2}')
  if [[ -z $rv || -z $cv ]]; then miss "Rust (rustc + cargo) via rustup" "$RUSTUP"
  elif ver_ge "${rv%%-*}" 1.90; then ok "rustc $rv, cargo $cv (>= 1.90: zkSketch needs 1.88, the zk-Analytics hosts 1.90; reference 1.97.1)"
  else miss "rustc $rv: need >= 1.90 (zk-Analytics host lockfiles pin ruint 1.20.0)" "rustup toolchain install 1.97.1 --profile minimal && rustup default 1.97.1"; fi
  local rzup=
  if command -v rzup >/dev/null; then rzup=$(command -v rzup); fi
  if [[ -z $rzup ]]; then miss "rzup (RISC Zero toolchain manager)" "$RZUP_INSTALL"
  else ok "rzup $("$rzup" --version 2>/dev/null | awk '{print $NF}') ($rzup)"; fi
  # risc0-build compiles the guests with rzup's DEFAULT rust version (settings.toml), not
  # merely an installed one (rzup 0.5.0's `install` also sets the default; other versions may not).
  local rzdef
  rzdef=$(awk -F'"' '/^\[/{s=($0 ~ /^\[default_versions\]/)} s && /^[[:space:]]*rust[[:space:]]*=/{print $2}' "$RZ_HOME/settings.toml" 2>/dev/null)
  if ! compgen -G "$RZ_HOME/toolchains/v1.97.0-rust-*" >/dev/null; then
    miss "RISC Zero rust toolchain 1.97.0 under $RZ_HOME/toolchains" "rzup install rust 1.97.0 && rzup default rust 1.97.0"
  elif [[ $rzdef == 1.97.0 ]]; then ok "RISC Zero rust toolchain 1.97.0, the rzup default (guest builds)"
  elif [[ -z $rzdef ]]; then warn "RISC Zero rust toolchain 1.97.0 installed, but no rzup default rust version in $RZ_HOME/settings.toml; fix: rzup default rust 1.97.0"
  else miss "rzup's default rust toolchain is $rzdef, not 1.97.0 (risc0-build compiles the guests with the default)" "rzup default rust 1.97.0"; fi
  # glibc alone is not enough: the RISC Zero rustc also links libstdc++ of GCC >= 12
  # (GLIBCXX_3.4.30) and libz.so.1, which e.g. RHEL/Rocky/Alma 9 and Amazon Linux 2023 lack.
  # Running it is the only reliable test.
  local rzrustc
  rzrustc=$(compgen -G "$RZ_HOME/toolchains/v1.97.0-rust-*/bin/rustc" | head -1)
  if [[ -n $rzrustc ]]; then
    if "$rzrustc" --version >/dev/null 2>&1; then ok "RISC Zero rustc runs: $("$rzrustc" --version 2>/dev/null)"
    else miss "RISC Zero rustc 1.97.0 does not run here: $("$rzrustc" --version 2>&1 | head -1) (it needs libstdc++ of GCC >= 12 (GLIBCXX_3.4.30) and libz.so.1: Ubuntu 22.04+, Debian 12+, Fedora 37+; not RHEL/Rocky/Alma 9 or Amazon Linux 2023)"; fi
  fi
  local r0 r0v
  r0=$(command -v r0vm 2>/dev/null || true)
  [[ -n $r0 ]] || r0=$(compgen -G "$RZ_HOME/extensions/v3.0.6-cargo-risczero-*/r0vm" | head -1)
  r0v=$([[ -n $r0 ]] && "$r0" --version 2>/dev/null | awk '{print $NF}')
  if [[ $r0v == 3.0.6 ]]; then ok "r0vm 3.0.6 ($r0)"
  else miss "r0vm 3.0.6 (have: ${r0v:-none}; the hosts link risc0-zkvm 3.0.6 and accept r0vm 3.0.x only)" "rzup install r0vm 3.0.6 && rzup default r0vm 3.0.6"; fi
}

check_run() {  # machine resources and run-time settings
  local mem_kb mem_g pc cores allowed c bad free_b free_r d
  # MemTotal is a little below the installed RAM (a 16 / 96 GiB machine reports ~15.5 / ~94):
  # accept 15 / 90 GiB of MemTotal for the README's 16 / 96 GiB
  mem_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo); mem_g=$((mem_kb / 1024 / 1024))
  if (( mem_g >= 90 )); then ok "RAM ${mem_g} GiB MemTotal (quick needs 16 GiB installed; full 96, its zkSketch GK run peaks at ~59 GiB)"
  elif (( mem_g >= 15 )); then warn "RAM ${mem_g} GiB MemTotal: enough for quick, not for full (its zkSketch GK run peaks at ~59 GiB under the default zero-knowledge build; 96 GiB installed, 128 recommended)"
  else miss "RAM ${mem_g} GiB MemTotal: need 16 GiB installed (one zk-Analytics proof alone peaks at ~9.2 GiB)"; fi
  pc=$(phys_cores); cores=${SIX_CORES:-$(default_cores)}
  if (( pc >= 32 )); then ok "CPU: $pc physical cores, $(nproc) usable CPUs; zkSketch runs on SIX_CORES=$cores"
  else warn "CPU: $pc physical cores (< 32): zkSketch runs on SIX_CORES=$cores, the paper used 32; set SIX_CORES to change"; fi
  (( cores <= $(nproc) )) || miss "SIX_CORES=$cores > $(nproc) usable CPUs (exp_compose refuses to oversubscribe)"
  allowed=$(awk '/^Cpus_allowed_list:/{print $2}' /proc/self/status)
  bad=$(python3 -I -c '
import sys
spec, n = sys.argv[1], int(sys.argv[2])
cpus = set()
for part in spec.split(","):
    a, _, b = part.partition("-")
    cpus.update(range(int(a), int(b or a) + 1))
print(" ".join(str(c) for c in range(n) if c not in cpus))' "$allowed" "$cores" 2>/dev/null)
  if [[ -n $bad ]]; then miss "CPUs 0..$((cores - 1)) are pinned by the procs engine but $bad are outside this process's affinity ($allowed)" "run outside the cpuset/taskset, or lower SIX_CORES"
  fi
  if command -v lscpu >/dev/null; then
    c=$(lscpu -p=CPU,CORE,SOCKET 2>/dev/null | grep -v '^#' | awk -F, -v n="$cores" '$1 < n {print $2 "," $3}' | sort -u | wc -l)
    if (( c == cores )); then ok "CPUs 0..$((cores - 1)) are $cores distinct physical cores (pinning target)"
    else warn "CPUs 0..$((cores - 1)) cover only $c physical cores (SMT siblings numbered next to each other); zkSketch's pinned worker then shares cores"; fi
  fi
  d=$BASELINE_DIR; while [[ ! -d $d ]]; do d=$(dirname "$d"); done
  free_b=$(( $(df -Pk "$d" | awk 'NR==2{print $4}') / 1024 / 1024 ))
  free_r=$(( $(df -Pk "$ZKS" | awk 'NR==2{print $4}') / 1024 / 1024 ))
  if built_all; then ok "builds present; free disk: ${free_b} GiB under $d, ${free_r} GiB under the repo"
  elif (( free_b >= 20 )); then ok "free disk under $d: ${free_b} GiB (the zk-Analytics builds take ~13 GB)"
  else miss "free disk under $d: ${free_b} GiB; the zk-Analytics builds need ~13 GB (>= 20 GiB free recommended)" "set BASELINE_DIR to a larger disk"; fi
  (( free_r >= 3 )) || warn "free disk under $ZKS: ${free_r} GiB (zkSketch's target/ takes ~0.3 GB, a run's results and proof scratch < 1 GB; >= 3 GiB free recommended)"
  local t=${TMPDIR:-/tmp} o
  o=$(findmnt -no OPTIONS -T "$t" 2>/dev/null)
  if [[ -d $t && -w $t ]] && (( ${#t} <= 60 )) && [[ ,$o, != *,noexec,* ]]; then ok "TMPDIR $t (procs engine: exec copy + unix socket)"
  elif [[ -d /tmp && -w /tmp ]] && [[ ,$(findmnt -no OPTIONS -T /tmp 2>/dev/null), != *,noexec,* ]]; then warn "TMPDIR=$t is too long or noexec; the scripts fall back to /tmp"
  else miss "TMPDIR=$t: need a writable, exec-capable directory with a path of <= 60 characters" "export TMPDIR=<such a directory>"; fi
}

check_repo() {
  local sz m
  if git -C "$ZKS" rev-parse HEAD >/dev/null 2>&1; then ok "zkSketch checkout $ZKS @ $(git -C "$ZKS" rev-parse --short=9 HEAD) ($(git -C "$ZKS" status --porcelain | wc -l) changed files)"
  else warn "$ZKS is not a git checkout (provenance lines will lack the commit); use git clone, not a ZIP"; fi
  if [[ -s $KEYS ]]; then
    sz=$(stat -c %s "$KEYS"); m=$(md5sum < "$KEYS" | cut -c1-12)
    if [[ $sz == 4194304 && $m == "$KEYS_MD5" ]]; then ok "data/aol.keys (2^20 AOL keys, md5 $m; tracked in git)"
    else miss "data/aol.keys: size $sz md5 $m, expected 4194304 / $KEYS_MD5" "git checkout -- data/aol.keys"; fi
  else miss "data/aol.keys" "git checkout -- data/aol.keys (it is tracked; use a git clone)"; fi
  if [[ -d $BASELINE_DIR/zka/.git ]]; then
    if [[ $(git -C "$BASELINE_DIR/zka" rev-parse HEAD 2>/dev/null) == "$ZKA_REV" ]]; then ok "zk-Analytics clone $BASELINE_DIR/zka @ ${ZKA_REV:0:7}"
    else warn "zk-Analytics clone $BASELINE_DIR/zka is not at ${ZKA_REV:0:7}; run_all.sh build re-checks it out"; fi
  else info "zk-Analytics not fetched yet ($BASELINE_DIR/zka): run_all.sh build fetches it"; fi
  local b nb=0
  for b in "${ZKA_BINS[@]}"; do [[ -x $b ]] && nb=$((nb + 1)); done
  if (( nb == ${#ZKA_BINS[@]} )); then ok "zk-Analytics side built (${#ZKA_BINS[@]} drivers under $EB: their CM, our 5 ports, and GK twice: matched + textbook)"
  else info "zk-Analytics side: $nb of ${#ZKA_BINS[@]} drivers built under $EB -- run_all.sh build"; fi
  for b in $(no_root_bins); do warn "$b was built before the root variants (no --root) -- run_all.sh build (quick/full refuse it)"; done
  local roots=${SIX_ZKA_ROOTS:-noroot} cmref=${SIX_ZKA_CM_REF:-1} pc
  if ! roots_ok "$roots"; then
    miss "SIX_ZKA_ROOTS=$roots: a comma list of distinct designed, noroot, legacy" "unset SIX_ZKA_ROOTS (default noroot)"
  elif [[ $cmref != [01] ]]; then
    miss "SIX_ZKA_CM_REF=$cmref: 0 or 1" "unset SIX_ZKA_CM_REF (default 1)"
  else
    read -r -a pc <<< "$(plan_counts "$roots" "$cmref")"
    info "zk-Analytics aggregation root variants: SIX_ZKA_ROOTS=$roots, SIX_ZKA_CM_REF=$cmref (full proves ${pc[1]} aggregation + 28 query$( (( pc[2] )) && echo " + ${pc[2]} CM reference (their shipped CM)") = ${pc[0]} jobs)"
  fi
  local zgk=${SIX_ZKA_GK:-matched} zgi=${SIX_ZKA_GK_IMPL:-literal} why
  why=$(gk_knobs_ok "$zgk" "$zgi" "$roots")
  if [[ -n $why ]]; then miss "$why" "unset SIX_ZKA_GK / SIX_ZKA_GK_IMPL (defaults matched / literal)"
  elif [[ $zgk == matched ]]; then info "zk-Analytics GK: SIX_ZKA_GK=matched, zkSketch's GK rule in their pipeline (the same algorithm on both sides), implementation $zgi"
  else info "zk-Analytics GK: SIX_ZKA_GK=textbook, textbook Greenwald-Khanna (NOT zkSketch's algorithm: a reference)"; fi
  if [[ -x $ZKS_BIN ]]; then ok "zkSketch exp_compose built ($ZKS_BIN)"; else info "zkSketch exp_compose not built yet -- run_all.sh build"; fi
  for b in $(stale_builds); do warn "$b is older than its sources -- run_all.sh build refreshes it (quick/full refuse stale builds)"; done
  local v dropped=()
  for v in BONSAI_API_URL BONSAI_API_KEY RISC0_PROVER RISC0_DEV_MODE RAYON_NUM_THREADS; do [[ -n ${!v:-} ]] && dropped+=("$v"); done
  for v in $(compgen -e | grep -E '^(ZKSKETCH_|EXP_)' | grep -vx EXP_VERIFY_REPEATS); do dropped+=("$v"); done
  (( ${#dropped[@]} )) && info "set in your environment and ignored by the run scripts: ${dropped[*]}"
  info "load now: $(cut -d' ' -f1-3 /proc/loadavg); the quiet-box gate waits up to GATE_WAIT_S per timed job (quick 0 s, full 1800 s)"
}
built_all() { local b; for b in "${ZKA_BINS[@]}" "$ZKS_BIN"; do [[ -x $b ]] || return 1; done; }
no_root_bins() {  # built drivers whose CSV header lacks the root-variant columns (built before --root)
  local b
  for b in "${ZKA_BINS[@]}"; do
    [[ -x $b ]] || continue
    [[ $("$b" --header 2>/dev/null) == *,"$ROOT_COLS" ]] || echo "$b"
  done
}
# Built binaries older than their sources (e.g. a BASELINE_DIR built from an older checkout:
# the GK driver gained query proving on 2026-10-09), i.e. sources changed since the last
# `run_all.sh build`, which refreshes them (build.sh sets each binary's mtime to the build
# time even when cargo had nothing to recompile).
stale_builds() {
  local z=$ZKS/scripts/baselines/zka i src bin
  local -a pairs=("$z/cyc" "${ZKA_BINS[0]}" "$z/cm_noroot" "${ZKA_BINS[0]}" "$z/hll" "${ZKA_BINS[1]}"
                  "$z/spacesaving" "${ZKA_BINS[2]}" "$z/gk" "${ZKA_BINS[3]}" "$z/bloom" "${ZKA_BINS[4]}"
                  "$z/kmv" "${ZKA_BINS[5]}" "$z/gk_matched" "${ZKA_BINS[6]}" "$z/gk_bm2/core" "${ZKA_BINS[6]}")
  for ((i = 0; i < ${#pairs[@]}; i += 2)); do
    src=${pairs[i]}; bin=${pairs[i + 1]}
    [[ -x $bin ]] || continue
    if [[ -n $(find "$src" -type f \( -name '*.rs' -o -name Cargo.toml -o -name Cargo.lock \) -newer "$bin" 2>/dev/null | head -1) ]]; then
      echo "$bin"
    fi
  done
  # src/proofs/ is git-ignored output of the #[ignore]d *_generate_and_store_proof tests
  if [[ -x $ZKS_BIN ]] && [[ -n $(find "$ZKS/src" -path "$ZKS/src/proofs" -prune -o -type f -name '*.rs' -newer "$ZKS_BIN" -print 2>/dev/null | head -1;
        find "$ZKS/examples/exp_compose.rs" "$ZKS/Cargo.toml" "$ZKS/Cargo.lock" -newer "$ZKS_BIN" 2>/dev/null | head -1) ]]; then
    echo "$ZKS_BIN"
  fi
}

cmd_check() {
  echo "== prerequisites (zkSketch $ZKS, BASELINE_DIR $BASELINE_DIR)"
  check_tools
  check_run
  check_repo
  echo
  if (( NMISS )); then echo "check: $NMISS blocking problem(s), $NWARN warning(s)"; return 1; fi
  echo "check: ok ($NWARN warning(s))"
}

# ------------------------------------------------------------------ build
cmd_build() {
  echo "== prerequisites for building"
  check_tools
  (( NMISS == 0 )) || die "fix the MISSING items above first (run_all.sh check lists everything)"
  echo "== fetch zk-Analytics @ ${ZKA_REV:0:7} into $BASELINE_DIR/zka"
  BASELINE_DIR=$BASELINE_DIR FETCH_NO_NEXT=1 "$ZKS/scripts/baselines/fetch_baselines.sh" zka || die "fetch failed"
  local t0=$SECONDS
  BASELINE_DIR=$BASELINE_DIR "$HERE6/build.sh" all || die "build failed (see the output above)"
  echo "build: done in $(hms $((SECONDS - t0)))"
}

# ------------------------------------------------------------------ runs
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

write_manifest() {  # write_manifest <mode>
  {
    echo "# six-sketch comparison run manifest"
    echo "mode=$1"
    echo "started=$(date -Is)"
    echo "N=$SIX_N M=$SIX_M T=$SIX_T gk_cap=$SIX_GK_CAP gk_rounds=${SIX_GK_ROUNDS:-stable} bloom_variant=${SIX_BLOOM_VARIANT:-packed} query_points=$SIX_QNS aggr_epochs=0,$((SIX_T - 1)) cores=$SIX_CORES"
    echo "zka_roots=$SIX_ZKA_ROOTS (aggregation root variants executed and planned) zka_cm_ref=$SIX_ZKA_CM_REF ($(if cm_ref_on "$SIX_ZKA_ROOTS" "$SIX_ZKA_CM_REF"; then echo "their shipped CM planned as a reference; designed also executed"; else echo "no separate CM reference"; fi))"
    if [[ $SIX_ZKA_GK == matched ]]; then
      echo "zka_gk=matched (zkSketch's GK rule in their pipeline: capacity $SIX_GK_CAP, s 51, m_sub $SIX_M = 1 apply_batch2 step per epoch, implementation $SIX_ZKA_GK_IMPL)"
    else
      echo "zka_gk=textbook (textbook Greenwald-Khanna, NOT zkSketch's algorithm: a reference)"
    fi
    local ncpu; ncpu=$(grep -c '^cpu[0-9]' /proc/stat)   # gate.sh's default GATE_MAX_LOAD
    echo "verify_repeats=${EXP_VERIFY_REPEATS:-5} gate: GATE_WAIT_S=${GATE_WAIT_S:-1800} GATE_MAX_LOAD=${GATE_MAX_LOAD:-$(( ncpu >= 16 ? ncpu / 8 : 2 ))} GATE_MAX_BUSY=${GATE_MAX_BUSY:-4}"
    echo "zksketch=$(git -C "$ZKS" rev-parse HEAD 2>/dev/null) changed_files=$(git -C "$ZKS" status --porcelain 2>/dev/null | wc -l) checkout=$ZKS"
    echo "exp_compose_md5=$(md5sum < "$ZKS_BIN" | cut -c1-12)"
    echo "zka=$(git -C "$BASELINE_DIR/zka" rev-parse HEAD 2>/dev/null) baseline_dir=$BASELINE_DIR"
    echo "host=$(hostname) kernel=$(uname -r) cpu=\"$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)\" nproc=$(nproc) phys_cores=$(phys_cores) mem_gib=$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo) / 1024 / 1024 ))"
    echo "rustc=\"$(rustc --version 2>/dev/null)\" r0vm=\"$(r0vm --version 2>/dev/null)\" rzup=\"$(rzup --version 2>/dev/null)\" python=\"$(python3 --version 2>&1)\""
    echo "risc0_toolchains=\"$(find "$RZ_HOME/toolchains" -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null)\""
  } > "$RESULTS/manifest.txt"
}

new_results() {  # new_results <mode>
  RESULTS=${RESULTS:-$ZKS/results/six/$1-$(date +%Y%m%d-%H%M%S)}
  RESULTS=$(realpath -m -- "$RESULTS")
  if [[ -d $RESULTS ]] && [[ -n $(ls -A "$RESULTS" 2>/dev/null) ]]; then
    die "RESULTS=$RESULTS is not empty; every run needs a fresh directory"
  fi
  mkdir -p "$RESULTS" || die "cannot create $RESULTS"
  if [[ -n $(git -C "$RESULTS" ls-files -- . 2>/dev/null | head -1) ]]; then die "RESULTS=$RESULTS is git-tracked"; fi
  export RESULTS
}

preflight_built() {
  local b stale
  for b in "${ZKA_BINS[@]}" "$ZKS_BIN"; do [[ -x $b ]] || die "missing $b -- run: $0 build"; done
  [[ -s $KEYS ]] || die "missing $KEYS"
  stale=$(stale_builds)
  if [[ -n $stale && ${SIX_ALLOW_STALE:-0} != 1 ]]; then
    die "built from older sources (run: $0 build; or SIX_ALLOW_STALE=1 to use them anyway): $(echo $stale)"
  fi
  stale=$(no_root_bins)
  [[ -z $stale ]] || die "built before the root variants (no --root; run: $0 build): $(echo $stale)"
}

jobs_py() {  # jobs_py [jobs.py options...]: the job plan of this run shape
  python3 -I "$HERE6/jobs.py" --keys "$KEYS" --m "$SIX_M" --t "$SIX_T" --qns "$SIX_QNS" --aggr "0,$((SIX_T - 1))" \
    --roots "$SIX_ZKA_ROOTS" --cm-ref "$SIX_ZKA_CM_REF" "$@"
}

assemble_and_table() {  # assemble_and_table <dir> [--plan FILE]
  local d=$1; shift
  python3 -I "$HERE6/assemble.py" "$d" "$KEYS" --zka six_zka --zks six_zksketch "$@" \
    --out "$d/six_sketch_comparison.csv" || return 1
  python3 -I "$HERE6/table.py" "$d/six_sketch_comparison.csv" --zka six_zka > "$d/six_sketch_table.md" || return 1
}

summary() {  # summary <mode> <rc>
  local mode=$1 rc=$2
  echo "finished=$(date -Is) rc=$rc" >> "$RESULTS/manifest.txt"
  echo
  if [[ -s $RESULTS/six_sketch_table.md ]]; then
    echo "=== summary (full tables: $RESULTS/six_sketch_table.md)"
    awk '/^\*\*Update proofs side by side/{p=1} /^\*\*Update side/{p=0} p' "$RESULTS/six_sketch_table.md"
    awk '/^\*\*Query proving time/{p=1} /^\*\*zkSketch query proving at the other n|^\*\*Verifier work/{p=0} p' "$RESULTS/six_sketch_table.md"
  fi
  echo "results:  $RESULTS"
  echo "  manifest.txt                 run configuration and versions"
  echo "  six_sketch_table.md          all tables (markdown)"
  echo "  six_sketch_comparison.csv    one row per (family, system, root variant, operation); provenance says measured / sampled / derived / ESTIMATED"
  echo "  six_zksketch_*.csv/.log      zkSketch runs;  six_zka_*.csv/.log  zk-Analytics executor, profile and proofs"
  if (( rc == 0 )); then echo "$mode: OK in $(hms $SECONDS)"; else echo "$mode: FAILED (rc=$rc) after $(hms $SECONDS); see the logs above"; fi
}

load_shape() {  # load_shape <mode>: export the run shape for the child scripts
  local v given=()
  for v in SIX_M SIX_T SIX_N SIX_GK_CAP SIX_GK_MSUB SIX_QNS; do [[ -n ${!v:-} ]] && given+=("$v=${!v}"); done
  unset SIX_GK_MSUB   # = SIX_M (six_common.sh): one zkSketch leaf per epoch in both fixed shapes
  if (( ${#given[@]} )); then
    echo "note: run_all.sh $1 uses its fixed run shape; ignoring ${given[*]} (those apply to the individual six/*.sh scripts)" >&2
  fi
  if [[ $1 == quick ]]; then
    export SIX_M=256 SIX_T=2 SIX_N=512 SIX_GK_CAP=512 SIX_QNS=1,2
    export GATE_WAIT_S=${GATE_WAIT_S:-0}
  else
    export SIX_M=2048 SIX_T=8 SIX_N=16384 SIX_GK_CAP=2048 SIX_QNS=1,2,4,8
    export GATE_WAIT_S=${GATE_WAIT_S:-1800}
  fi
  export SIX_CORES=${SIX_CORES:-$(default_cores)}
  export SIX_ZKA_ROOTS=${SIX_ZKA_ROOTS:-noroot} SIX_ZKA_CM_REF=${SIX_ZKA_CM_REF:-1}
  roots_ok "$SIX_ZKA_ROOTS" || die "SIX_ZKA_ROOTS=$SIX_ZKA_ROOTS must be a comma list of distinct designed, noroot, legacy"
  [[ $SIX_ZKA_CM_REF == [01] ]] || die "SIX_ZKA_CM_REF=$SIX_ZKA_CM_REF must be 0 or 1"
  export SIX_ZKA_GK=${SIX_ZKA_GK:-matched} SIX_ZKA_GK_IMPL=${SIX_ZKA_GK_IMPL:-literal}
  local why; why=$(gk_knobs_ok "$SIX_ZKA_GK" "$SIX_ZKA_GK_IMPL" "$SIX_ZKA_ROOTS")
  [[ -z $why ]] || die "$why"
  EXEC_ROOTS=$SIX_ZKA_ROOTS
  if cm_ref_on "$SIX_ZKA_ROOTS" "$SIX_ZKA_CM_REF"; then EXEC_ROOTS+=,designed; fi
  export SIX_ZKS_PREFIX=six_zksketch SIX_ZKA_PREFIX=six_zka
  unset SIX_WORK
}

cmd_quick() {
  load_shape quick
  export SIX_FAIL_FAST=1
  local sel=${SIX_QUICK_PROVE:-$QUICK_PROVE_DEFAULT}
  preflight_built
  new_results quick
  exec > >(trap '' TERM; exec tee -i -a "$RESULTS/run_all.log") 2>&1   # tee outlives Ctrl-C / TERM; exits at EOF
  write_manifest quick
  echo "quick smoke test -> $RESULTS"
  echo "  zkSketch: 7 runs, N=$SIX_N (t=$SIX_T batches of m=$SIX_M), $SIX_CORES cores; zk-Analytics: executor for all six"
  echo "  under root variants $EXEC_ROOTS, proofs: ${sel//,/ } (the other planned jobs are ESTIMATED from padded"
  echo "  cycles); GATE_WAIT_S=$GATE_WAIT_S"
  local rc=0 plan
  step "zkSketch: run_zks.sh (7 runs)" "$HERE6/run_zks.sh" || rc=1
  if (( rc == 0 )); then
    step "zk-Analytics executor: run_zka.sh exec (root variants $EXEC_ROOTS)" "$HERE6/run_zka.sh" exec || rc=1
  fi
  if (( rc == 0 )); then
    jobs_py --logs "$RESULTS" --prefix six_zksketch --lines > "$RESULTS/zka_plan.txt" || rc=1
    echo "zk-Analytics plan: $(wc -l < "$RESULTS/zka_plan.txt") jobs ($RESULTS/zka_plan.txt), GK rank values and Bloom absent keys from this run's zkSketch logs"
  fi
  if (( rc == 0 )); then
    mapfile -t plan < <(grep ':query:' "$RESULTS/zka_plan.txt")
    step "zk-Analytics query executor: run_zka.sh qexec (${#plan[@]} jobs, for the estimates)" "$HERE6/run_zka.sh" qexec "${plan[@]}" || rc=1
  fi
  if (( rc == 0 )); then
    step "zk-Analytics SS/GK profile: prof_exec.sh" "$HERE6/prof_exec.sh" || rc=1
  fi
  if (( rc == 0 )); then
    mapfile -t plan < <(jobs_py --logs "$RESULTS" --prefix six_zksketch --select "$sel" --lines)
    (( ${#plan[@]} )) || rc=1
  fi
  if (( rc == 0 )); then
    step "zk-Analytics proofs: run_zka.sh prove ${plan[*]}" "$HERE6/run_zka.sh" prove "${plan[@]}" || rc=1
  fi
  if (( rc == 0 )); then
    step "assemble + table" assemble_and_table "$RESULTS" --plan "$RESULTS/zka_plan.txt" || rc=1
  fi
  summary quick $rc
  return $rc
}

cmd_full() {
  local dry=0 from='' zpfx=six_zksketch
  while (( $# )); do
    case $1 in
      --dry-run) dry=1 ;;
      --from-logs) from=${2:?--from-logs DIR}; shift ;;
      --zks-prefix) zpfx=${2:?--zks-prefix P}; shift ;;
      *) die "unknown option $1 (full [--dry-run] [--from-logs DIR [--zks-prefix P]])" ;;
    esac
    shift
  done
  load_shape full
  if (( ! dry )) && [[ -n $from ]]; then die "--from-logs / --zks-prefix apply to --dry-run only (the real run reads its own zkSketch logs)"; fi
  if (( dry )); then
    local src jobs
    if [[ -n $from ]]; then
      src="read from $from/${zpfx}_{gk,bloom_absent}.log and cross-checked against the native derivation"
      jobs=$(jobs_py --logs "$from" --prefix "$zpfx" --lines) || exit 1
    else
      src="derived natively from data/aol.keys; the real run reads them from its own zkSketch logs and cross-checks"
      jobs=$(jobs_py --lines) || exit 1
    fi
    local nagg nref=0
    nagg=$(grep -c ':aggr:' <<< "$jobs")
    if cm_ref_on "$SIX_ZKA_ROOTS" "$SIX_ZKA_CM_REF"; then nref=$(grep -c '^cm:aggr:[0-9]*:designed$' <<< "$jobs"); fi
    cat <<EOF
full run plan (dry run; nothing is executed)
  RESULTS=${RESULTS:-$ZKS/results/six/full-<YYYYmmdd-HHMMSS>}  BASELINE_DIR=$BASELINE_DIR
  shape: N=$SIX_N = T=$SIX_T x M=$SIX_M, GK cap $SIX_GK_CAP (rounds ${SIX_GK_ROUNDS:-stable}), zkSketch cores $SIX_CORES, gate wait <= ${GATE_WAIT_S}s per timed job
  zk-Analytics GK: SIX_ZKA_GK=$SIX_ZKA_GK$( [[ $SIX_ZKA_GK == matched ]] && echo " (zkSketch's GK rule in their pipeline, capacity $SIX_GK_CAP, one apply_batch2 step per $SIX_M-record epoch, implementation $SIX_ZKA_GK_IMPL)" || echo " (textbook Greenwald-Khanna: a reference, not zkSketch's algorithm)")
  1. zkSketch, 7 timed runs:   SIX_M=$SIX_M SIX_T=$SIX_T SIX_GK_CAP=$SIX_GK_CAP SIX_GK_ROUNDS=${SIX_GK_ROUNDS:-stable} SIX_BLOOM_VARIANT=${SIX_BLOOM_VARIANT:-packed} SIX_CORES=$SIX_CORES $HERE6/run_zks.sh ${TAGS[*]}
  2. zk-Analytics executor:    SIX_ZKA_ROOTS=$SIX_ZKA_ROOTS SIX_ZKA_CM_REF=$SIX_ZKA_CM_REF $HERE6/run_zka.sh exec
                               (aggregation epochs 0..$((SIX_T - 1)) of all six under root variants $EXEC_ROOTS;
                               Bloom/KMV pipelines with queries at n = $SIX_QNS, the query rows once)
  3. SS/GK guest profile:      $HERE6/prof_exec.sh          (executor only)
  4. zk-Analytics, $(wc -l <<< "$jobs") timed proofs: $HERE6/run_zka.sh prove <jobs>
     $((nagg - nref)) aggregation proofs (epochs 0 and $((SIX_T - 1)) x 6 families x root variants $SIX_ZKA_ROOTS)
     + $(grep -c ':query:' <<< "$jobs") query proofs (variant-independent: query guests read no root)$(
       (( nref )) && printf '\n     + %d CM reference proofs (their shipped CM, cm:aggr:<e>:designed; last in the plan)' "$nref")
     GK rank values / Bloom absent keys: $src
  5. python3 -I $HERE6/assemble.py \$RESULTS $KEYS --zka six_zka --zks six_zksketch --out \$RESULTS/six_sketch_comparison.csv
     python3 -I $HERE6/table.py \$RESULTS/six_sketch_comparison.csv > \$RESULTS/six_sketch_table.md
jobs:
$jobs
EOF
    return 0
  fi
  preflight_built
  new_results full
  exec > >(trap '' TERM; exec tee -i -a "$RESULTS/run_all.log") 2>&1   # tee outlives Ctrl-C / TERM; exits at EOF
  write_manifest full
  echo "full run (paper configuration) -> $RESULTS"
  echo "  zkSketch 7 runs + zk-Analytics executor (root variants $EXEC_ROOTS) + the planned proofs (42 at the"
  echo "  defaults: expect ~3 h 30 min of running, an estimate, plus gate waits; GATE_WAIT_S=$GATE_WAIT_S per timed job)"
  local rc=0 plan
  # zkSketch or executor failures stop the run (fix and start again); a failed proof does not:
  # the remaining proofs still run, the table shows '-' for it, and the exit status is 1.
  step "zkSketch: run_zks.sh (7 runs)" "$HERE6/run_zks.sh" || { summary full 1; return 1; }
  step "zk-Analytics executor: run_zka.sh exec (root variants $EXEC_ROOTS)" "$HERE6/run_zka.sh" exec || { summary full 1; return 1; }
  jobs_py --logs "$RESULTS" --prefix six_zksketch --lines > "$RESULTS/zka_plan.txt" \
    || { echo "cannot plan the zk-Analytics jobs (see above)"; summary full 1; return 1; }
  echo "zk-Analytics plan: $(wc -l < "$RESULTS/zka_plan.txt") jobs ($RESULTS/zka_plan.txt), GK rank values and Bloom absent keys from this run's zkSketch logs"
  step "zk-Analytics SS/GK profile: prof_exec.sh" "$HERE6/prof_exec.sh" || rc=1
  mapfile -t plan < "$RESULTS/zka_plan.txt"
  step "zk-Analytics proofs: run_zka.sh prove (${#plan[@]} jobs)" "$HERE6/run_zka.sh" prove "${plan[@]}" || rc=1
  step "assemble + table" assemble_and_table "$RESULTS" || rc=1
  summary full $rc
  return $rc
}

cmd_assemble() {
  local d=${1:?usage: run_all.sh assemble <results dir>}
  d=$(realpath -m -- "$d")
  [[ -d $d ]] || die "$d: no such directory"
  if [[ -n $(git -C "$d" ls-files -- . 2>/dev/null | head -1) ]]; then die "$d is git-tracked"; fi
  [[ -f $d/manifest.txt ]] ||
    echo "note: $d has no manifest.txt (made by the individual six/ scripts); assembling the files it holds" >&2
  if [[ -f $d/manifest.txt ]] && grep -qx 'mode=quick' "$d/manifest.txt"; then
    assemble_and_table "$d" --plan "$d/zka_plan.txt" || exit 1
  else
    assemble_and_table "$d" || exit 1
  fi
  echo "tables: $d/six_sketch_table.md"
}

on_int() {
  echo "run_all.sh: interrupted" >&2
  [[ -n ${RESULTS:-} && -f $RESULTS/manifest.txt ]] && echo "finished=$(date -Is) interrupted" >> "$RESULTS/manifest.txt"
  exit 130
}
trap on_int INT TERM HUP

case ${1:-} in
  check) cmd_check ;;
  build) cmd_build ;;
  quick) cmd_quick ;;
  full) shift; cmd_full "$@" ;;
  assemble) shift; cmd_assemble "$@" ;;
  *) sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
