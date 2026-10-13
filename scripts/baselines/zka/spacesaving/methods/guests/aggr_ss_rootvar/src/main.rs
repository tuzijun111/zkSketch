#![no_main]
#![no_std]

// ROOT-VARIANT twin of aggr_ss: the same ss-core aggregation, with the Merkle-root
// construction chosen at run time (an SsRoot read before the input). Journal =
// (root, the aggr_ss journal). The six-sketch designed (Buckets64) and noroot (None)
// rows and the buckets1024/perkey sensitivity rows (../../../README.md); aggr_ss
// (SsRoot::HEADLINE compiled in) is the guest of the committed `legacy` rows.

extern crate alloc;

use risc0_zkvm::guest::env;
use ss_core::{process_ss_aggr_root, SsAggrInput, SsRoot};

risc0_zkvm::guest::entry!(main);

fn main() {
    let root: SsRoot = env::read();
    let input: SsAggrInput = env::read();
    let out = process_ss_aggr_root(&input, root);
    env::commit(&(root, out));
}
