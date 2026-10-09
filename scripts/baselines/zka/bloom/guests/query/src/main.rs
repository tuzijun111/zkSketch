#![no_main]
#![no_std]

// Bloom query guest: their querier-guest-cm (querier/methods/guest_cm/src/main.rs) with
// run_cm_query replaced by run_bloom_query, keeping their low-support suppression (as
// ../../../hll's hll_query does for HLL). The only addition is a cycle counter read at
// each phase boundary, written to STDOUT (not the journal); it is 7 cycle_count calls
// and one 56-byte write.

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;
use zka_bloom_core::{run_bloom_query_probed, BloomQueryInput, BloomQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    // marks: start, read, chain links, state commits, merge, answer, journal
    let mut marks = [0u64; 7];
    marks[0] = env::cycle_count();
    let input: BloomQueryInput = env::read();
    marks[1] = env::cycle_count();
    let mut k = 2;
    let out: BloomQueryOutput = run_bloom_query_probed(&input, &mut || {
        marks[k] = env::cycle_count();
        k += 1;
    })
    .suppress_if_low_support();
    env::commit(&out);
    marks[6] = env::cycle_count();
    env::stdout().write_slice(&marks);
}
