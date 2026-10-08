#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec;
use gk_bm2_core::{
    apply_batch2_fast_marked, apply_batch2_fixed_marked, apply_batch2_marked, apply_batch2_reuse_marked, batch_commit,
    state_commit_words, state_from_words, state_to_words, vals_of, Mark, IN_HDR_WORDS, IN_MAGIC, JOURNAL_BYTES,
    N_PROBES, OUT_MAGIC, VARIANT_FAST, VARIANT_FIXED_LINEAR, VARIANT_LITERAL, VARIANT_LITERAL_REUSE,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

// One zkSketch GK band-merge batch transition S_{t-1}, batch_t -> S_t:
//   1. read the old state and the epoch's raw u32 keys (env::read_slice, no serde)
//   2. Com_old = SHA-256(old state), Com_batch = SHA-256(raw keys)
//   3. decode the state, map the keys (gk_vals_of)
//   4. apply_batch2 (literal port), apply_batch2_reuse (the same with per-round
//      tables reused), apply_batch2_fixed (zkSketch's fixed schedule with
//      linear-time union and re-sort) or apply_batch2_fast (data-dependent
//      schedule); same output
//   5. Com_new = SHA-256(new state)
//   6. journal: Com_old || Com_batch || Com_new
// The cycle-counter reads (host-provided, unchecked) and, on request, the new
// state go to the host's stdout, never to the journal or the receipt.
fn main() {
    let mut probes = [0u64; N_PROBES];
    probes[0] = env::cycle_count();

    let mut hdr = [0u32; IN_HDR_WORDS];
    env::read_slice(&mut hdr);
    assert_eq!(hdr[0], IN_MAGIC, "bad input magic");
    let (variant, emit_state) = (hdr[1], hdr[2] != 0);
    let mut state_words = vec![0u32; hdr[3] as usize];
    env::read_slice(&mut state_words);
    let mut keys = vec![0u32; hdr[4] as usize];
    env::read_slice(&mut keys);
    probes[1] = env::cycle_count();

    let com_old = state_commit_words(&state_words);
    let com_batch = batch_commit(&keys);
    probes[2] = env::cycle_count();

    let s_old = state_from_words(&state_words);
    // The wire batch is exactly m slots (PAD_KEY in unused ones), as zkSketch's harness builds it.
    assert_eq!(keys.len(), s_old.params.batch, "batch length != params.batch");
    let vals = vals_of(&keys);
    probes[3] = env::cycle_count();

    let mut rounds = 0u64;
    let mut merges = [0u64; 2];
    let mut on_mark = |m: Mark| {
        let now = env::cycle_count();
        match m {
            Mark::UnionBuilt => probes[4] = now,
            Mark::NeighborInit => probes[5] = now,
            Mark::RoundDone { fold_right, fold_left } => {
                probes[6] = now;
                rounds += 1;
                merges[0] += fold_right as u64;
                merges[1] += fold_left as u64;
            }
        }
    };
    let s_new = match variant {
        VARIANT_LITERAL => apply_batch2_marked(&s_old, &vals, &mut on_mark),
        VARIANT_LITERAL_REUSE => apply_batch2_reuse_marked(&s_old, &vals, &mut on_mark),
        VARIANT_FIXED_LINEAR => apply_batch2_fixed_marked(&s_old, &vals, &mut on_mark),
        VARIANT_FAST => apply_batch2_fast_marked(&s_old, &vals, &mut on_mark),
        _ => panic!("unknown variant"),
    };
    probes[7] = env::cycle_count();

    let new_words = state_to_words(&s_new);
    let com_new = state_commit_words(&new_words);
    probes[8] = env::cycle_count();

    let mut journal = [0u8; JOURNAL_BYTES];
    journal[..32].copy_from_slice(&com_old);
    journal[32..64].copy_from_slice(&com_batch);
    journal[64..].copy_from_slice(&com_new);
    env::commit_slice(&journal);
    probes[9] = env::cycle_count();
    probes[10] = rounds;
    probes[11] = merges[0];
    probes[12] = merges[1];

    let mut out = [0u32; 2 + 2 * N_PROBES];
    out[0] = OUT_MAGIC;
    out[1] = N_PROBES as u32;
    for (i, p) in probes.iter().enumerate() {
        out[2 + 2 * i] = *p as u32;
        out[3 + 2 * i] = (*p >> 32) as u32;
    }
    env::write_slice(&out);
    if emit_state {
        env::write_slice(&new_words);
    }
}
