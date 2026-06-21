//! Thread-local capture of the last leaf prove's phase timings.
//!
//! The plonky3 leaf provers (`countmin_final`, `gk_final_full`,
//! `hll_final_full`, `ss_final_full`) build the circuit, generate the trace
//! (`runner.run()`), prove (`prove_all_tables`), and self-verify
//! (`verify_all_tables`) inside one monolithic call. Rather than change their
//! signatures (which the merge/chain paths depend on), each records its
//! per-phase durations here; an experiment runner reads them with [`take`]
//! immediately after calling the prover. This gives the EVAL_SPEC §1
//! witness/prove/verify split for the STARK backend.
//!
//! Convention: `witness` = trace generation (`runner.run()`); `prove` =
//! `prove_all_tables`; `verify` = `verify_all_tables`; `trace_rows` = the sum of
//! padded heights across the batch-STARK tables (Poseidon2 + Recompose +
//! Permute + main). plonky3's multi-table batch-STARK has no single
//! `num_columns`, so `trace_rows` is the summed-rows measure; cross-backend
//! comparisons should use prove time / proof size / peak memory.

use std::cell::Cell;
use std::time::Duration;

/// Per-phase timing of one leaf prove.
#[derive(Clone, Copy, Default, Debug)]
pub struct LeafTiming {
    pub witness: Duration,
    pub prove: Duration,
    pub verify: Duration,
    pub trace_rows: u64,
}

thread_local! {
    static LAST: Cell<LeafTiming> = const { Cell::new(LeafTiming {
        witness: Duration::ZERO,
        prove: Duration::ZERO,
        verify: Duration::ZERO,
        trace_rows: 0,
    }) };
}

/// Record the most recent leaf prove's phase timings (called by the provers).
pub fn record(t: LeafTiming) {
    LAST.with(|c| c.set(t));
}

/// Read the most recent recorded timing (the experiment runner calls this right
/// after a prove).
pub fn take() -> LeafTiming {
    LAST.with(|c| c.get())
}
