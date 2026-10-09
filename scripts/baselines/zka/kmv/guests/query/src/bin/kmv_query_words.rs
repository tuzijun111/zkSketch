#![no_main]
#![no_std]

// Sensitivity variant of kmv_query (the pattern of ../../../hll's hll_query_words):
// identical query and journal, but the epoch values arrive as a Vec<u64> in serde's
// default encoding (two zkVM words per value, read element by element), the form of
// their CmEpochState::heap_vals, instead of the packed big-endian byte image. The
// conversion to the query input is a move (no copy); it is timed as its own phase
// ("convert"), so "read" is serde alone.

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
