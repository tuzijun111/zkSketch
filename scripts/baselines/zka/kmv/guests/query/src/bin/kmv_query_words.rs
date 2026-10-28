#![no_main]
#![no_std]

// kmv_query with the values sent as Vec<u64> (serde's default encoding) instead of packed bytes.

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;
use zka_kmv_core::{run_kmv_query_probed, KmvQueryInput, KmvQueryInputWords, KmvQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    // marks: start, read, convert, chain links, state commits, merge, estimate, journal
    let mut marks = [0u64; 8];
    marks[0] = env::cycle_count();
    let words: KmvQueryInputWords = env::read();
    marks[1] = env::cycle_count();
    let input: KmvQueryInput = words.into();
    marks[2] = env::cycle_count();
    let mut k = 3;
    let out: KmvQueryOutput = run_kmv_query_probed(&input, &mut || {
        marks[k] = env::cycle_count();
        k += 1;
    })
    .suppress_if_low_support();
    env::commit(&out);
    marks[7] = env::cycle_count();
    env::stdout().write_slice(&marks);
}
