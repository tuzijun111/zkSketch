# Sourced by the scripts here: HERE, ZKS (this checkout), BASELINE_DIR (default ~/ext-baselines),
# ZKA (the zk-Analytics clone), RESULTS (default results/ next to this file) and the cyc/ build helpers.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZKS="$(cd "$HERE/../../.." && pwd)"
BASELINE_DIR="$(realpath -m -- "${BASELINE_DIR:-$HOME/ext-baselines}")"
ZKA="$BASELINE_DIR/zka"
RESULTS="$(realpath -m -- "${RESULTS:-$HERE/results}")"
export PATH="$HOME/.cargo/bin:${RISC0_HOME:-$HOME/.risc0}/bin:$PATH"

# cyc/Cargo.toml path-deps "../.zka/...". A Cargo path cannot read $BASELINE_DIR,
# so an untracked symlink points at the clone.
link_zka() {
  [[ -d $ZKA ]] || { echo "missing $ZKA -- run scripts/baselines/fetch_baselines.sh" >&2; return 2; }
  if [[ "$(readlink "$HERE/.zka" 2>/dev/null || true)" != "$ZKA" ]]; then
    ln -sfn "$ZKA" "$HERE/.zka"
  fi
}

# CM_TOPK_SLOTS is a BUILD-TIME knob (zka aggregator/core/build.rs:13) baked into
# the host binaries AND the guest ELFs. One target dir per value, so a T=1 build
# can never relink a binary that another script runs expecting T=100.
cyc_target() { echo "$BASELINE_DIR/build/cyc-t$1"; }
# --locked pins the HOST build to cyc/Cargo.lock. The guest ELFs, which produce every
# cycle count, come from a nested cargo run by risc0-build that drops the outer flags
# and CARGO* env; RISC0_BUILD_LOCKED=1 makes it honour $ZKA/Cargo.lock as well.
build_cyc() {  # build_cyc <topk> [cargo args...]
  local t=$1; shift
  link_zka || return
  ( cd "$HERE/cyc" && CM_TOPK_SLOTS=$t CARGO_TARGET_DIR="$(cyc_target "$t")" RISC0_BUILD_LOCKED=1 \
      cargo build --release --locked "$@" )
}

source "$HERE/sizes.sh"   # SIX_SIZES: the sketch sizes of the comparison (SIX_CM_W, SIX_SS_CAP, SIX_KMV_K, SIX_KMV_SUFFIX)
