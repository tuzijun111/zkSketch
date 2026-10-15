# Sourced by gk_matched_check.sh and six/build.sh. Reuses ../common.sh for locations (ZKS,
# ZKA, BASELINE_DIR, RESULTS, PATH, link_zka) and adds the matched-GK build.
GKM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$GKM_DIR/../common.sh"
GKM_TARGET="$BASELINE_DIR/build/zka-gk-matched"
GKM_BIN="$GKM_TARGET/release/gk_matched"

# Host resolves from gk_matched/Cargo.lock (seeded from ../gk/Cargo.lock, the zkSketch
# Cargo.lock and ../gk_bm2/Cargo.lock: risc0-zkvm 3.0.6, their host crates, zkSketch's
# dependencies); RISC0_BUILD_LOCKED=1 makes risc0-build's nested guest build honour
# gk_matched/guests/Cargo.lock (third-party entries identical to ../gk/guests/Cargo.lock,
# itself seeded from the zk-Analytics clone's Cargo.lock: risc0-zkvm 3.0.5).
build_gk_matched() {
  link_zka || return
  ( cd "$GKM_DIR" && CARGO_TARGET_DIR="$GKM_TARGET" RISC0_BUILD_LOCKED=1 cargo build --release --locked --bin gk_matched )
}

gkm_elf() { echo "$GKM_TARGET/riscv-guest/gk-matched-methods/$1/riscv32im-risc0-zkvm-elf/release/$1"; }
