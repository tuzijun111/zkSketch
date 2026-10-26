#![no_main]
#![no_std]

// ROOT-VARIANT twin of aggr_mg: the same mg-core aggregation, with the Merkle-root
// construction chosen at run time (an MgRoot read before the input). Journal =
// (root, the aggr_mg journal). The six-sketch designed (Buckets64) and noroot (None)
// rows and the buckets1024/perkey sensitivity rows (../../../README.md); aggr_mg
// (MgRoot::HEADLINE compiled in) is the guest of the `legacy` rows.

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
