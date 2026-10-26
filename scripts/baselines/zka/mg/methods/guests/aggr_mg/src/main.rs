#![no_main]
#![no_std]

// Misra-Gries aggregation guest; same shape as zk-Analytics' aggr_cm
// (aggregator/methods/guest_cm/src/main.rs @ d4a5a9a).

extern crate alloc;

use risc0_zkvm::guest::env;
use mg_core::{process_mg_aggr, MgAggrInput};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: MgAggrInput = env::read();
    let out = process_mg_aggr(&input);
    env::commit(&out);
}
