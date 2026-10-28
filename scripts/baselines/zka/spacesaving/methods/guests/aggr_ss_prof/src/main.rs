#![no_main]
#![no_std]

// aggr_ss plus env::cycle_count() marks (host-reported, unconstrained) after each phase, for
// the phase breakdown only. Journal: the aggr_ss journal, then the (phase, cycles) marks.

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
