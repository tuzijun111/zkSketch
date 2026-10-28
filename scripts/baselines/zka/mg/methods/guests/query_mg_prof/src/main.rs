#![no_main]
#![no_std]

// Profiling copy of query_mg: commits its journal, then the (phase, env::cycle_count()) marks.

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use mg_core::{run_mg_query_hooked, MgQueryInput, MgQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut marks: Vec<(&'static str, u64)> = Vec::with_capacity(16);
    marks.push(("start", env::cycle_count()));
    let input: MgQueryInput = env::read();
    marks.push(("read", env::cycle_count()));
    let out: MgQueryOutput =
        run_mg_query_hooked(&input, |p| marks.push((p, env::cycle_count()))).suppress_if_low_support();
    env::commit(&out);
    marks.push(("journal", env::cycle_count()));
    env::commit(&marks);
}
