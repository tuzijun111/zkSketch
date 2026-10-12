# Sourced by every script here. Resolves locations so the scripts run from any
# cwd and from any checkout (a worktree measures its own zkSketch sources).
#
#   HERE          this directory (harness sources, tracked)
#   ZKS           the zkSketch checkout containing HERE (ourcm/ and zksq/ path-dep it)
#   BASELINE_DIR  external clones; default ~/ext-baselines, the same default as
#                 ../fetch_baselines.sh. zk-Analytics-side builds go under it:
#                 build/ (cyc-t<T>, ourcm, zksq, shaccel), nb-target-<T> (accuracy.sh
#                 native) and zka/target (a234.sh, compare.sh). zkSketch-side runs
#                 (compare.sh S1/S2, our_query.sh Q1) build exp_compose in $ZKS/target.
#   ZKA           zk-Analytics clone @ d4a5a9a (../fetch_baselines.sh)
#   RESULTS       CSV/log destination; default results/ next to this file
# BASELINE_DIR and RESULTS are made absolute: several scripts cd before they build or write.
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
