#![no_main]
#![no_std]

// aggr_mg with the Merkle-root construction (MgRoot) read at run time; journal = (root, aggr_mg journal).

extern crate alloc;

use risc0_zkvm::guest::env;
use mg_core::{process_mg_aggr_root, MgAggrInput, MgRoot};

risc0_zkvm::guest::entry!(main);

fn main() {
    let root: MgRoot = env::read();
    let input: MgAggrInput = env::read();
    let out = process_mg_aggr_root(&input, root);
    env::commit(&(root, out));
}
