#![no_main]
#![no_std]

// Sensitivity variant of bloom_query (the pattern of ../../../hll's hll_query_words):
// identical query and journal, but the epoch filters arrive as Vec<u32> bitsets in
// serde's default encoding (one zkVM word per 32 bits, read element by element), the
// form of their CmEpochState::counts, instead of the packed byte string. The words are
// then copied into the packed bytes; that copy is timed as its own phase ("convert"),
// so "read" is serde alone.

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;
use zka_bloom_core::{run_bloom_query_probed, BloomQueryInput, BloomQueryInputWords, BloomQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    // marks: start, read, convert, chain links, state commits, merge, answer, journal
    let mut marks = [0u64; 8];
    marks[0] = env::cycle_count();
    let words: BloomQueryInputWords = env::read();
    marks[1] = env::cycle_count();
    let input: BloomQueryInput = words.into();
    marks[2] = env::cycle_count();
    let mut k = 3;
    let out: BloomQueryOutput = run_bloom_query_probed(&input, &mut || {
        marks[k] = env::cycle_count();
        k += 1;
    })
    .suppress_if_low_support();
    env::commit(&out);
    marks[7] = env::cycle_count();
    env::stdout().write_slice(&marks);
}
