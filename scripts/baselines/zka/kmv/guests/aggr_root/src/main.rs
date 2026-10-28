#![no_main]
#![no_std]

// kmv_aggr with the six-sketch root variant (designed = 64-bucket root, noroot = none) in the journal.

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
