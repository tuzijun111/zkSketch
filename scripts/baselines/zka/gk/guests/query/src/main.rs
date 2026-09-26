#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;
use gk_zka_core::{run_gk_query, GkQueryInput, GkQueryOutput};

risc0_zkvm::guest::entry!(main);

// Same shape as querier/methods/guest_histogram/src/main.rs, including the
// low-support suppressed-sentinel rule.
fn main() {
    let input: GkQueryInput = env::read();
    let out: GkQueryOutput = run_gk_query(&input).suppress_if_low_support();
    env::commit(&out);
}
