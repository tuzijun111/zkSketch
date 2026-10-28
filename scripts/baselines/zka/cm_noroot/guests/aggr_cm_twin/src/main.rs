#![no_main]
#![no_std]

// Their aggr_cm guest with process_cm_aggr from ../../core's `twin` module, an unedited
// copy of their code. Only used to check the noroot copy; not a reported number.

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
