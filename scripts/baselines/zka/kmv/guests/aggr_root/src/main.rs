#![no_main]
#![no_std]

// KMV aggregation guest of the six-sketch ROOT VARIANTS (designed = 64-bucket samples-pattern
// root, noroot = none; ../../core/src/lib.rs "root variants"). It is kmv_aggr with the
// variant read before the input and committed with the journal, and one more phase mark
// (the root step): marks start, read, chain, flatten, update, commit, root, journal go to
// STDOUT (not the journal), 8 cycle_count calls and one 64-byte write. kmv_aggr (no root)
// stays the guest of the committed 2026-10-09 reference rows (`legacy`).

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;
use zka_kmv_core::{process_kmv_aggr_root_probed, KmvAggrInput, KmvRoot};

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut marks = [0u64; 8];
    marks[0] = env::cycle_count();
    let root: KmvRoot = env::read();
    let input: KmvAggrInput = env::read();
    marks[1] = env::cycle_count();
    let mut k = 2;
    let (_, out) = process_kmv_aggr_root_probed(&input, root, &mut || {
        marks[k] = env::cycle_count();
        k += 1;
    });
    env::commit(&(root, out));
    marks[7] = env::cycle_count();
    env::stdout().write_slice(&marks);
}
