#![no_main]
#![no_std]

// aggr_ss with the Merkle-root construction read at run time (an SsRoot before the input).
// Journal: (root, the aggr_ss journal).

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
