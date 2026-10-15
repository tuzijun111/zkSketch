#![no_main]
#![no_std]

extern crate alloc;

use gk_matched_core::{run_gkm_query, GkmQueryInput, GkmQueryOutput};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

// Same shape as querier/methods/guest_histogram/src/main.rs (and ../../../gk/guests/query),
// including the low-support suppressed-sentinel rule: verify the epoch chain links,
// open the latest carried state against the last link, answer rank(v) with zkSketch's
// GK decoder estimator.
fn main() {
    let input: GkmQueryInput = env::read();
    let out: GkmQueryOutput = run_gkm_query(&input).suppress_if_low_support();
    env::commit(&out);
}
