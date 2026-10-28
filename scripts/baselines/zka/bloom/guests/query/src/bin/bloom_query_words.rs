#![no_main]
#![no_std]

// bloom_query with the filters sent as Vec<u32> (serde's default encoding) instead of packed bytes.

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
