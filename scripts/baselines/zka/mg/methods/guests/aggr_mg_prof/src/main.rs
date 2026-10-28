#![no_main]
#![no_std]

// Profiling copy of aggr_mg: commits its journal, then the (phase, env::cycle_count()) marks.

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use mg_core::{process_mg_aggr_hooked, MgAggrInput, MgRoot};

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut marks: Vec<(&'static str, u64)> = Vec::with_capacity(16);
    marks.push(("start", env::cycle_count()));
    let input: MgAggrInput = env::read();
    marks.push(("read", env::cycle_count()));
    let (_, out) = process_mg_aggr_hooked(&input, MgRoot::HEADLINE, |p| marks.push((p, env::cycle_count())));
    env::commit(&out);
    marks.push(("journal", env::cycle_count()));
    env::commit(&marks);
}
