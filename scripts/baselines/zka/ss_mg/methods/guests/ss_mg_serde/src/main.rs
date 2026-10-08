#![no_main]
#![no_std]

// SENSITIVITY twin of ss_mg: identical except that it reads its input as an
// SsMgInput through risc0 serde (env::read), the way the zka guests read
// theirs, instead of env::read_slice. Same journal, same S_new. Used only for
// the read-path sensitivity rows; ss_mg is the headline guest.

extern crate alloc;

use risc0_zkvm::guest::env;
use ss_mg_core::{run_hooked, SortAlgo, SsMgInput, PHASES};

risc0_zkvm::guest::entry!(main);

/// start, read, the ss-mg-core phases, journal.
const N_MARKS: usize = PHASES.len() + 3;

fn main() {
    let mut marks = [0u64; N_MARKS];
    marks[0] = env::cycle_count();
    let input: SsMgInput = env::read();
    marks[1] = env::cycle_count();
    let mut i = 2;
    let algo = SortAlgo::from_word(input.sort);
    let (journal, new_rows, _) = run_hooked(input.capacity, input.batch, algo, &input.old_rows, &input.keys, |_| {
        marks[i] = env::cycle_count();
        i += 1;
    });
    env::commit_slice(&journal.to_bytes());
    marks[N_MARKS - 1] = env::cycle_count();
    // Host-only side channel, as in ss_mg.
    env::write_slice(&marks);
    env::write_slice(&new_rows);
}
