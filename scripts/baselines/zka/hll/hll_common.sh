# Sourced by the hll/ scripts. Reuses ../common.sh (PATH, BASELINE_DIR, ZKA, RESULTS,
# link_zka) and adds the HLL build, which goes to $BASELINE_DIR/build/hll.
#   host binaries: --locked against hll/Cargo.lock (derived from ../cyc/Cargo.lock)
#   guest ELFs:    RISC0_BUILD_LOCKED=1 makes risc0-build's nested cargo honour
#                  hll/guests/Cargo.lock (derived from zk-Analytics' own Cargo.lock)
source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"
HLL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HLL_TARGET="$BASELINE_DIR/build/hll"
HLL_BIN="$HLL_TARGET/release/hll"
HLL_ELF_DIR="$HLL_TARGET/riscv-guest/zka-hll-methods"
KEYS=${KEYS:-$ZKS/data/aol.keys}

build_hll() {
  link_zka || return
  ( cd "$HLL_DIR" && CARGO_TARGET_DIR="$HLL_TARGET" RISC0_BUILD_LOCKED=1 \
      cargo build --release --locked --bin hll )
}

refuse_dev_mode() {
  if [[ -n ${RISC0_DEV_MODE:-} ]]; then
    echo "RISC0_DEV_MODE is set ($RISC0_DEV_MODE); unset it -- nothing here may run in dev mode" >&2
    exit 2
  fi
}

# Provenance header lines for a raw log.
hll_log_header() {  # hll_log_header <script name>
  echo "# $1 $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] nproc=$(nproc)"
  echo "# zka=$(git -C "$ZKA" rev-parse --short=9 HEAD) r0vm=$(r0vm --version 2>/dev/null) keys=$KEYS md5=$(md5sum < "$KEYS" | cut -c1-12)"
  echo "# zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD) hll_dirty=$(git -C "$ZKS" status --porcelain -- "$HLL_DIR" | wc -l)"
  local g
  for g in hll_aggr/hll_aggr hll_query/hll_query hll_query/hll_query_words; do
    local f="$HLL_ELF_DIR/${g%/*}/riscv32im-risc0-zkvm-elf/release/${g#*/}"
    echo "# elf ${g#*/} md5=$(md5sum < "$f" | cut -d' ' -f1) bytes=$(stat -c %s "$f")"
  done
}

# Append-safe CSV: write the header if the file is new or empty; refuse if an existing
# file has a different header (never silently mixes schemas).
csv_prepare() {  # csv_prepare <file> [extra header columns, starting with a comma]
  local out=$1 hdr
  hdr="$("$HLL_BIN" --header)${2:-}"
  mkdir -p "$(dirname "$out")"
  if [[ ! -s $out ]]; then
    echo "$hdr" > "$out"
  elif [[ "$(head -1 "$out")" != "$hdr" ]]; then
    echo "REFUSING: $out has a different header; move it aside" >&2
    return 2
  fi
}
