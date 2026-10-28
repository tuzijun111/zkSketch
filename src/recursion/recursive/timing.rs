//! Phase timings of the last leaf prove, recorded by the leaf provers and read by the
//! experiment runners with `take`.

use std::cell::Cell;
use std::time::Duration;

/// Per-phase timing of one leaf prove.
#[derive(Clone, Copy, Default, Debug)]
pub struct LeafTiming {
    /// Trace generation (`runner.run()`).
    pub witness: Duration,
    /// `prove_all_tables`.
    pub prove: Duration,
    /// `verify_all_tables`.
    pub verify: Duration,
    /// Sum of the padded heights of all batch-STARK tables.
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
