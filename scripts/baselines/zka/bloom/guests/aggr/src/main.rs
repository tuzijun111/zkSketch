#![no_main]
#![no_std]

// Bloom aggregation guest: their aggr_cm guest (aggregator/methods/guest_cm/src/main.rs)
// with process_cm_aggr replaced by process_bloom_aggr (as ../../../hll's hll_aggr does
// for HLL). The only addition is a cycle counter read at each phase boundary, written
// to STDOUT (not the journal) so the host can split the cost; it is 7 cycle_count
// calls and one 56-byte write.

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;
use zka_bloom_core::{process_bloom_aggr_probed, BloomAggrInput};

risc0_zkvm::guest::entry!(main);

fn main() {
    // marks: start, read, chain, flatten, update, commit, journal
    let mut marks = [0u64; 7];
    marks[0] = env::cycle_count();
    let input: BloomAggrInput = env::read();
    marks[1] = env::cycle_count();
    let mut k = 2;
    let (_, out) = process_bloom_aggr_probed(&input, &mut || {
        marks[k] = env::cycle_count();
        k += 1;
    });
    env::commit(&out);
    marks[6] = env::cycle_count();
    env::stdout().write_slice(&marks);
}
