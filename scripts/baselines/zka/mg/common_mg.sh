# Sourced by ../six/build.sh. Reuses ../common.sh for locations (ZKS, ZKA,
# BASELINE_DIR, RESULTS, PATH) and for the ../.zka symlink that the path
# dependencies go through.
MGDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MGDIR/../common.sh"
MG_TARGET="$BASELINE_DIR/build/zka-mg"
MG_BIN="$MG_TARGET/release/mg"
unset RISC0_DEV_MODE   # never report dev-mode numbers (the driver also refuses)

# Host binary pinned by Cargo.lock (--locked); the guest ELFs by
# methods/guests/Cargo.lock, which risc0-build's nested cargo honours only with
# RISC0_BUILD_LOCKED=1 (same arrangement as ../spacesaving/common_ss.sh).
build_mg() {
  link_zka || return
  ( cd "$MGDIR" && CARGO_TARGET_DIR="$MG_TARGET" RISC0_BUILD_LOCKED=1 cargo build --release --locked "$@" )
}

mg_elf() { echo "$MG_TARGET/riscv-guest/mg-methods/$1/riscv32im-risc0-zkvm-elf/release/$1"; }
