#![no_main]
#![no_std]

// Their aggr_cm guest (aggregator/methods/guest_cm/src/main.rs @ d4a5a9a), line for line,
// with process_cm_aggr taken from ../../core's `noroot` module: their CM aggregation
// without the row/cm/heap Merkle roots (journal fields zero). Same input and journal types.

extern crate alloc;

use risc0_zkvm::guest::env;
use zka_cm_noroot_core::noroot::process_cm_aggr;
use zka_cm_noroot_core::CmAggrInput;

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: CmAggrInput = env::read();
    let out = process_cm_aggr(&input);
    env::commit(&out);
}
