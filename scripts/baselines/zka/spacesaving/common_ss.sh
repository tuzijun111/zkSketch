# Shared settings for ss_exec.sh and ss_anchor.sh (paths come from ../common.sh).
SSDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SSDIR/../common.sh"
SS_TARGET="$BASELINE_DIR/build/zka-ss"
SS_BIN="$SS_TARGET/release/ss"
SS_OUT_DEFAULT="$RESULTS/zka_ss_exec.csv"       # executor rows only (ss_exec.sh)
SS_ANCHOR_DEFAULT="$RESULTS/zka_ss_anchor.csv"  # proved rows only (ss_anchor.sh)
unset RISC0_DEV_MODE   # never report dev-mode numbers (the driver also refuses)

# Host binary pinned by Cargo.lock (--locked); the guest ELFs by
# methods/guests/Cargo.lock, which risc0-build's nested cargo honours only with
# RISC0_BUILD_LOCKED=1 (same arrangement as ../common.sh build_cyc).
build_ss() {
  link_zka || return
  ( cd "$SSDIR" && CARGO_TARGET_DIR="$SS_TARGET" RISC0_BUILD_LOCKED=1 cargo build --release --locked "$@" )
}

ss_elf() { echo "$SS_TARGET/riscv-guest/ss-methods/$1/riscv32im-risc0-zkvm-elf/release/$1"; }

# Provenance header for the raw log.
ss_log_header() {  # ss_log_header <script-name>
  echo "# $1 $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] nproc=$(nproc)"
  echo "# zka=$(git -C "$ZKA" rev-parse --short=9 HEAD) r0vm=$(r0vm --version 2>/dev/null) keys=$KEYS md5=$(md5sum < "$KEYS" | cut -c1-12)"
  echo "# zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD) spacesaving_untracked_or_dirty_files=$(git -C "$ZKS" status --porcelain -- "$SSDIR" | wc -l)"
  echo "# guest risc0-zkvm=$(awk '/name = "risc0-zkvm"/{getline; print $3}' "$SSDIR/methods/guests/Cargo.lock" | tr -d '"')" \
       "host risc0-zkvm=$(awk '/name = "risc0-zkvm"/{getline; print $3}' "$SSDIR/Cargo.lock" | tr -d '"')"
  for g in aggr_ss query_ss aggr_ss_prof query_ss_prof aggr_ss_rootvar; do
    echo "# elf $g md5=$(md5sum < "$(ss_elf $g)" | cut -d' ' -f1)"
  done
}

# Append-safe CSV: write the header to a new/empty file; refuse to append rows
# under a different header.
ss_csv_init() {  # ss_csv_init <out>
  local out=$1 hdr; hdr=$("$SS_BIN" --header)
  mkdir -p "$(dirname "$out")"
  if [[ ! -s $out ]]; then
    echo "$hdr" > "$out"
  elif [[ "$(head -1 "$out")" != "$hdr" ]]; then
    echo "REFUSING: $out has a different header; move it aside or set OUT=..." >&2
    return 2
  fi
}

ss_run() {  # ss_run <out> <log> <driver args...>
  local out=$1 log=$2; shift 2
  echo "[run ] ss $*" | tee -a "$log" >&2
  local line rc
  line=$("$SS_BIN" "$@" --keys "$KEYS" 2>>"$log"); rc=$?
  if [[ $rc -ne 0 || -z $line ]]; then echo "[FAIL] rc=$rc: $*" | tee -a "$log" >&2; return 1; fi
  echo "$line" | tee -a "$log" >> "$out"
  # guest, query, root, capacity, epochs, user_cycles, segments, journal_eq_native, ref_eq,
  # invariants_ok, prove_s, s_per_segment, prove_condition
  echo "       -> $(cut -d, -f4,6-9,19,21,27-29,34,37,39 <<< "$line")" >&2
}
