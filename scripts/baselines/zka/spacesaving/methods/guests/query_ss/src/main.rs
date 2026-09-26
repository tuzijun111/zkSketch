#![no_main]
#![no_std]

// SpaceSaving query guest; same shape as zk-Analytics' querier-guest-samples
// (querier/methods/guest_samples/src/main.rs @ d4a5a9a), including their
// low-support suppression.

extern crate alloc;

use risc0_zkvm::guest::env;
use ss_core::{run_ss_query, SsQueryInput, SsQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: SsQueryInput = env::read();
    let out: SsQueryOutput = run_ss_query(&input).suppress_if_low_support();
    env::commit(&out);
}
