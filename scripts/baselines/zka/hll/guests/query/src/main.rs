#![no_main]
#![no_std]

// HLL query guest: their querier-guest-cm (querier/methods/guest_cm/src/main.rs) with
// run_cm_query replaced by run_hll_query, keeping their low-support suppression. The
// only addition is a cycle counter read at each phase boundary, written to STDOUT (not
// the journal); it is 8 cycle_count calls and one 64-byte write.

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;
use zka_hll_core::{run_hll_query_probed, HllQueryInput, HllQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    // marks: start, read, chain links, state commits, merge, estimator pass, estimator f64, journal
    let mut marks = [0u64; 8];
    marks[0] = env::cycle_count();
    let input: HllQueryInput = env::read();
    marks[1] = env::cycle_count();
    let mut k = 2;
    let out: HllQueryOutput = run_hll_query_probed(&input, &mut || {
        marks[k] = env::cycle_count();
        k += 1;
    })
    .suppress_if_low_support();
    env::commit(&out);
    marks[7] = env::cycle_count();
    env::stdout().write_slice(&marks);
}
