#![no_main]
#![no_std]

// PROFILING twin of query_ss: the same ss-core code, with env::cycle_count()
// (host-reported, unconstrained) recorded after each phase. Journal = the
// query_ss journal followed by the (phase, cycle_count) marks. Used only for the
// phase breakdown; query_ss is the measured guest.

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use ss_core::{run_ss_query_hooked, SsQueryInput, SsQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut marks: Vec<(&'static str, u64)> = Vec::with_capacity(16);
    marks.push(("start", env::cycle_count()));
    let input: SsQueryInput = env::read();
    marks.push(("read", env::cycle_count()));
    let out: SsQueryOutput =
        run_ss_query_hooked(&input, |p| marks.push((p, env::cycle_count()))).suppress_if_low_support();
    env::commit(&out);
    marks.push(("journal", env::cycle_count()));
    env::commit(&marks);
}
