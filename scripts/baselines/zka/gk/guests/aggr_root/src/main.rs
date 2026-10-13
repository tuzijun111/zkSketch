#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;
use gk_zka_core::{process_gk_aggr_root, GkAggrInput, GkRoot};

risc0_zkvm::guest::entry!(main);

// The six-sketch ROOT VARIANTS of aggr_gk (../../core/src/lib.rs "Root variants"):
// designed = 64-bucket samples-pattern root, noroot = none, pertuple = the legacy
// per-tuple root. Same shape as aggr_gk, with the variant read before the input and
// committed with the journal: (GkRoot, GkAggrOutput). aggr_gk stays the guest of the
// committed 2026-10-09 reference rows (`legacy`).
fn main() {
    let root: GkRoot = env::read();
    let input: GkAggrInput = env::read();
    let (_, out) = process_gk_aggr_root(&input, root);
    env::commit(&(root, out));
}
