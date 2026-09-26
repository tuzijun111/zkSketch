#![no_main]
#![no_std]

// PROFILING twin of aggr_ss: the same ss-core code, with env::cycle_count()
// (host-reported, unconstrained) recorded after each phase. Journal = the
// aggr_ss journal followed by the (phase, cycle_count) marks. Used only for the
// phase breakdown; aggr_ss is the measured guest.

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use ss_core::{process_ss_aggr_hooked, SsAggrInput, SsRoot};

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut marks: Vec<(&'static str, u64)> = Vec::with_capacity(16);
    marks.push(("start", env::cycle_count()));
    let input: SsAggrInput = env::read();
    marks.push(("read", env::cycle_count()));
    let (_, out) = process_ss_aggr_hooked(&input, SsRoot::HEADLINE, |p| marks.push((p, env::cycle_count())));
    env::commit(&out);
    marks.push(("journal", env::cycle_count()));
    env::commit(&marks);
}
