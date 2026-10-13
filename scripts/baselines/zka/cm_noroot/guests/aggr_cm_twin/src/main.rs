#![no_main]
#![no_std]

// VALIDATION ONLY. Their aggr_cm guest (aggregator/methods/guest_cm/src/main.rs @ d4a5a9a)
// with process_cm_aggr taken from ../../core's `twin` module, an unedited copy of their
// code compiled in this crate. Same journal as aggr_cm; outside the Merkle work it costs
// what aggr_cm costs (../../core/src/lib.rs, "twin"). Never a reported number.

extern crate alloc;

use risc0_zkvm::guest::env;
use zka_cm_noroot_core::twin::process_cm_aggr;
use zka_cm_noroot_core::CmAggrInput;

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: CmAggrInput = env::read();
    let out = process_cm_aggr(&input);
    env::commit(&out);
}
