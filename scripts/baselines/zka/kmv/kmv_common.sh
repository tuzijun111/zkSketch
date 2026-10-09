# Sourced by the kmv/ scripts (the pattern of ../hll/hll_common.sh). Reuses
# ../common.sh (PATH, BASELINE_DIR, ZKA, ZKS, RESULTS, link_zka) and adds the KMV
# build, which goes to $BASELINE_DIR/build/zka-kmv.
#   host binary: --locked against kmv/Cargo.lock (derived from ../hll/Cargo.lock)
#   guest ELFs:  RISC0_BUILD_LOCKED=1 makes risc0-build's nested cargo honour
#                kmv/guests/Cargo.lock (derived from zk-Analytics' own Cargo.lock)
source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"
FAM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAM=kmv
FAM_TARGET="$BASELINE_DIR/build/zka-kmv"
FAM_BIN="$FAM_TARGET/release/kmv"
FAM_ELF_DIR="$FAM_TARGET/riscv-guest/zka-kmv-methods"
# <guest package>/<ELF>: the query package also builds the words variant (src/bin)
FAM_GUESTS=(kmv_aggr/kmv_aggr kmv_query/kmv_query kmv_query/kmv_query_words)
KEYS=${KEYS:-$ZKS/data/aol.keys}

build_fam() {
  link_zka || return
  ( cd "$FAM_DIR" && CARGO_TARGET_DIR="$FAM_TARGET" RISC0_BUILD_LOCKED=1 \
      cargo build --release --locked --bin "$FAM" )
}

refuse_dev_mode() {
  if [[ -n ${RISC0_DEV_MODE:-} ]]; then
    echo "RISC0_DEV_MODE is set ($RISC0_DEV_MODE); unset it -- nothing here may run in dev mode" >&2
    exit 2
  fi
}

# Paths inside this checkout are logged as $ZKS/..., so a log does not depend on (or
# leak) where the checkout lives.
rel_zks() {  # rel_zks <string>
  local s=$1
  echo "${s//"$ZKS"/\$ZKS}"
}

# Provenance header lines for a raw log.
fam_log_header() {  # fam_log_header <script name>
  echo "# $1 $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] nproc=$(nproc)"
  echo "# zka=$(git -C "$ZKA" rev-parse --short=9 HEAD) r0vm=$(r0vm --version 2>/dev/null) keys=$(rel_zks "$KEYS") md5=$(md5sum < "$KEYS" | cut -c1-12)"
  echo "# zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD) ${FAM}_dirty=$(git -C "$ZKS" status --porcelain -- "$FAM_DIR" | wc -l)"
  local g f
  for g in "${FAM_GUESTS[@]}"; do
    f="$FAM_ELF_DIR/${g%/*}/riscv32im-risc0-zkvm-elf/release/${g#*/}"
    echo "# elf ${g#*/} md5=$(md5sum < "$f" | cut -d' ' -f1) bytes=$(stat -c %s "$f")"
  done
}

# Append-safe CSV: write the header if the file is new or empty; refuse if an existing
# file has a different header (never silently mixes schemas).
csv_prepare() {  # csv_prepare <file>
  local out=$1 hdr
  hdr="$("$FAM_BIN" --header)"
  mkdir -p "$(dirname "$out")"
  if [[ ! -s $out ]]; then
    echo "$hdr" > "$out"
  elif [[ "$(head -1 "$out")" != "$hdr" ]]; then
    echo "REFUSING: $out has a different header; move it aside" >&2
    return 2
  fi
}

# ---------------------------------------------------------------- PROVE=1 gate
# One prover at a time across the Bloom and KMV ports: both runners take the same lock,
# and start only on a quiet box (the rule of ../sketch_exec.sh's wait_quiet).
DEFAULT_MAX_LOAD=24
PROVE_LOCK="$BASELINE_DIR/build/zka-prove.lock"

# take_prove_lock: flock on fd 9, held by this shell and inherited by the driver and
# its r0vm children (so it outlives an interrupted runner until its prover exits).
# Returns 2 when another bloom/kmv PROVE=1 run holds it.
take_prove_lock() {
  mkdir -p "$(dirname "$PROVE_LOCK")"
  exec 9> "$PROVE_LOCK"
  flock -n 9 || { echo "another bloom/kmv PROVE=1 run holds $PROVE_LOCK; refusing" >&2; return 2; }
}

# wait_quiet: 0 once the 1-minute load is <= MAX_LOAD and no r0vm of ANY user runs;
# 1 after WAIT_S seconds. Polls every 20 s. Sets L0 (load1 at return) and WAITED_S.
wait_quiet() {
  local t0=$SECONDS last=-1000 n
  while :; do
    L0=$(cut -d' ' -f1 /proc/loadavg); n=$(pgrep -x r0vm 2>/dev/null | wc -l)
    WAITED_S=$((SECONDS - t0))
    if awk -v l="$L0" -v m="$MAX_LOAD" 'BEGIN{exit !(l <= m)}' && (( n == 0 )); then return 0; fi
    if (( WAITED_S >= WAIT_S )); then
      echo "box not quiet after ${WAITED_S}s: 1-minute load $L0 (max $MAX_LOAD), $n r0vm process(es) of any user" >&2
      return 1
    fi
    if (( SECONDS - last >= 300 )); then
      echo "waiting for a quiet box: load1=$L0 (max $MAX_LOAD), r0vm processes (all users)=$n; up to ${WAIT_S}s" >&2
      last=$SECONDS
    fi
    sleep 20
  done
}
