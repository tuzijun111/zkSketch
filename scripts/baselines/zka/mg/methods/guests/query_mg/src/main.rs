#![no_main]
#![no_std]

// Misra-Gries query guest; same shape as zk-Analytics' querier-guest-samples
// (querier/methods/guest_samples/src/main.rs @ d4a5a9a), including their
// low-support suppression.

extern crate alloc;

use risc0_zkvm::guest::env;
use mg_core::{run_mg_query, MgQueryInput, MgQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: MgQueryInput = env::read();
    let out: MgQueryOutput = run_mg_query(&input).suppress_if_low_support();
    env::commit(&out);
}
