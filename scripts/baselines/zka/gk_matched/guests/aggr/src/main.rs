#![no_main]
#![no_std]

extern crate alloc;

use gk_matched_core::{bm2, process_gkm_aggr_marked, GkmAggrInput, GkmRoot, MARK_NAMES};
use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write as _;

risc0_zkvm::guest::entry!(main);

// zk-Analytics' aggregation pipeline around zkSketch's GK batch rule (../../core):
// their batch-chain check, the carried state checked against the previous epoch's
// commitment, ceil(B / m_sub) apply_batch2 steps, the root of the selected variant
// (designed = 64-bucket samples pattern, noroot = none, pertuple = one leaf per tuple),
// the unsalted SHA-256 state commitment and their epoch link. Journal =
// (GkmRoot, GkmAggrOutput), as ../../../gk/guests/aggr_root.
// Private stdout (never the journal or the receipt): the cycle_count marks start, read,
// one per phase (MARK_NAMES), journal; then, when the host asked for it (`emit`), the
// new state's gk_bm2 words for the tuple-by-tuple equivalence check.
fn main() {
    let mut marks = [0u64; MARK_NAMES.len() + 3];
    marks[0] = env::cycle_count();
    let root: GkmRoot = env::read();
    let input: GkmAggrInput = env::read();
    let emit: bool = env::read();
    marks[1] = env::cycle_count();
    let mut k = 2;
    let (state, out) = process_gkm_aggr_marked(&input, root, &mut |_| {
        marks[k] = env::cycle_count();
        k += 1;
    });
    env::commit(&(root, out));
    marks[MARK_NAMES.len() + 2] = env::cycle_count();
    env::stdout().write_slice(&marks);
    if emit {
        env::stdout().write_slice(&bm2::state_to_words(&state));
    }
}
