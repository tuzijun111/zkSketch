#![no_main]
#![no_std]

// PROFILING twin of aggr_mg: the same mg-core code, with env::cycle_count()
// (host-reported, unconstrained) recorded after each phase. Journal = the
// aggr_mg journal followed by the (phase, cycle_count) marks. Used only for the
// phase breakdown; aggr_mg is the measured guest.

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
