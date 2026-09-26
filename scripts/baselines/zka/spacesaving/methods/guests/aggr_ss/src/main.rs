#![no_main]
#![no_std]

// SpaceSaving aggregation guest; same shape as zk-Analytics' aggr_cm
// (aggregator/methods/guest_cm/src/main.rs @ d4a5a9a).

extern crate alloc;

use risc0_zkvm::guest::env;
use ss_core::{process_ss_aggr, SsAggrInput};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: SsAggrInput = env::read();
    let out = process_ss_aggr(&input);
    env::commit(&out);
}
