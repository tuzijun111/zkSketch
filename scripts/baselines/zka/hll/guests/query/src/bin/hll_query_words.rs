#![no_main]
#![no_std]

// Sensitivity variant of hll_query: identical computation and journal, but the epoch
// states arrive with serde's default Vec<u8> encoding (one zkVM word per register)
// instead of the packed byte string. The conversion is a move (no copy) and is counted
// in the "read" phase.

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;
use zka_hll_core::{run_hll_query_probed, HllQueryInput, HllQueryInputWords, HllQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut marks = [0u64; 8];
    marks[0] = env::cycle_count();
    let words: HllQueryInputWords = env::read();
    let input: HllQueryInput = words.into();
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
