#![no_main]
#![no_std]

// KMV query guest: their querier-guest-cm with run_kmv_query; phase cycle counts go to stdout.

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;
use zka_kmv_core::{run_kmv_query_probed, KmvQueryInput, KmvQueryOutput};

risc0_zkvm::guest::entry!(main);

fn main() {
    // marks: start, read, chain links, state commits, merge, estimate, journal
    let mut marks = [0u64; 7];
    marks[0] = env::cycle_count();
    let input: KmvQueryInput = env::read();
    marks[1] = env::cycle_count();
    let mut k = 2;
    let out: KmvQueryOutput = run_kmv_query_probed(&input, &mut || {
        marks[k] = env::cycle_count();
        k += 1;
    })
    .suppress_if_low_support();
    env::commit(&out);
    marks[6] = env::cycle_count();
    env::stdout().write_slice(&marks);
}
