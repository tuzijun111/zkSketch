#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;
use gk_zka_core::{process_gk_aggr, GkAggrInput};

risc0_zkvm::guest::entry!(main);

// Same shape as aggregator/methods/guest_histogram/src/main.rs.
fn main() {
    let input: GkAggrInput = env::read();
    let out = process_gk_aggr(&input);
    env::commit(&out);
}
