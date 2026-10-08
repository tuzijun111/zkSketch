#![no_main]
#![no_std]

// zkSketch's SpaceSaving batch transition (mergeable Misra-Gries) as a RISC
// Zero guest; see ../../../../core/src/lib.rs. One run = one zkSketch SS leaf:
// journal = Com_old || Com_batch || Com_new (96 bytes).
//
// HEADLINE guest: reads its input as raw words with env::read_slice (RISC
// Zero's documented fast path for bulk data). ss_mg_serde is the same guest
// reading the same data through risc0 serde (env::read), as the zka guests do.
//
// Cycle probes: env::cycle_count() (host-reported, unconstrained) after the
// input read and after each ss-mg-core phase. They are part of the measured
// guest (there is no probe-free twin); each costs a handful of cycles.

extern crate alloc;

use alloc::vec;
use risc0_zkvm::guest::env;
use ss_mg_core::{run_hooked, SortAlgo, HEADER_WORDS, PHASES, ROW_WORDS};

risc0_zkvm::guest::entry!(main);

/// start, read, the ss-mg-core phases, journal.
const N_MARKS: usize = PHASES.len() + 3;

fn main() {
    let mut marks = [0u64; N_MARKS];
    marks[0] = env::cycle_count();
    // ss_mg_core::input_words layout: [capacity, batch, sort], state, keys.
    let mut hdr = [0u32; HEADER_WORDS];
    env::read_slice(&mut hdr);
    let (capacity, batch, algo) = (hdr[0], hdr[1], SortAlgo::from_word(hdr[2]));
    let mut old_rows = vec![0u32; (capacity as usize).checked_mul(ROW_WORDS).expect("capacity too large")];
    env::read_slice(&mut old_rows);
    let mut keys = vec![0u32; batch as usize];
    env::read_slice(&mut keys);
    marks[1] = env::cycle_count();
    let mut i = 2;
    let (journal, new_rows, _) = run_hooked(capacity, batch, algo, &old_rows, &keys, |_| {
        marks[i] = env::cycle_count();
        i += 1;
    });
    env::commit_slice(&journal.to_bytes());
    marks[N_MARKS - 1] = env::cycle_count();
    // Host-only side channel (stdout: not the journal, not part of the
    // statement): the marks and S_new, for the host's field-by-field check of
    // S_new against zkSketch's native apply_batch_ss_full.
    env::write_slice(&marks);
    env::write_slice(&new_rows);
}
