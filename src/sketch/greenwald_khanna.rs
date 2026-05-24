//! Plaintext Greenwald-Khanna (GK) quantile sketch (paper §5.3 Pattern B
//! with merge-tree semantics).
//!
//! Phase 6a: plaintext only; in-circuit leaf and recursive merge are
//! deferred (proper Pattern B in-circuit shape is the §G four-gate
//! pipeline + per-tuple merge-tree certificate, multi-day follow-up).
//!
//! ### Scope (read carefully)
//!
//! This is a *simplified* GK summary: a bounded-capacity sorted list of
//! `(value, count, max_error)` tuples. The full GK guarantees ε-approximate
//! rank queries via careful merging of adjacent entries with bounded error
//! propagation. The prototype implements:
//!   - Insertion at the correct sorted position with `(value, 1, 0)`.
//!   - When the summary exceeds `capacity`, merge the two adjacent entries
//!     with the smallest combined `count + max_error` (a cheap stand-in
//!     for GK's band-based merge rule).
//!
//! What this gets right: a Pattern B mergeable summary with eviction-style
//! compression, sorted by value, bounded-capacity. What's deferred: the
//! ε-bound on rank-query accuracy (the full GK guarantee). For the
//! framework's purpose — exercising the recursion / chain / merge layers
//! with a Pattern B sketch — this is enough.

use crate::sketch::{DeltaCert, Sketch};

/// Public GK parameters: maximum summary capacity. Must be a multiple of 4
/// (4 tuples = 12 Vals — but our commit hashes 4 tuples per "block" anyway,
/// so capacity multiple of 4 keeps `3 * capacity % CELL_ALIGNMENT == 0`
/// when CELL_ALIGNMENT = 4 and we pad).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKParams {
    pub capacity: usize,
}

/// One tuple in the GK summary.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKTuple {
    pub value: u32,
    pub count: u32,
    pub max_error: u32,
}

/// Plaintext GK state: a sorted-by-`value` list of `GKTuple`s, padded with
/// zero tuples up to `capacity`. Active tuples have `count > 0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GKState {
    pub tuples: Vec<GKTuple>,
    pub params: GKParams,
}

/// One value to fold into the sketch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKUpdate {
    pub value: u32,
}

/// Per-batch certificate. For Pattern B, just carries the post-batch state
/// (no per-cell delta shortcut). A full GK in-circuit version would replace
/// this with the merge-tree certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GKDelta {
    pub batch: Vec<GKUpdate>,
    pub final_tuples: Vec<GKTuple>,
}

pub struct GK;

impl Sketch for GK {
    type Params = GKParams;
    type State = GKState;
    type Update = GKUpdate;

    fn new(params: &Self::Params) -> Self::State {
        assert!(params.capacity >= 2, "GK capacity must be ≥ 2");
        // For our commit alignment, require capacity multiple of 4.
        assert!(
            params.capacity % 4 == 0,
            "GK capacity must be a multiple of 4 (got {}); the commit \
             absorbs 3*capacity Vals and CELL_ALIGNMENT = 4",
            params.capacity
        );
        Self::State {
            tuples: vec![GKTuple { value: 0, count: 0, max_error: 0 }; params.capacity],
            params: *params,
        }
    }

    fn update(state: &mut Self::State, u: &Self::Update) {
        // Step 1: find the correct insertion position by value (sorted).
        // Active tuples have count > 0; inactive (zero-count) tuples are
        // padding at the end.
        let active_len = state.tuples.iter().take_while(|t| t.count > 0).count();

        // Step 2: locate insertion point.
        let pos = state.tuples[..active_len]
            .iter()
            .position(|t| t.value >= u.value)
            .unwrap_or(active_len);

        // Step 3: if room, shift right and insert.
        if active_len < state.params.capacity {
            // Shift [pos..active_len] right by 1.
            for i in (pos..active_len).rev() {
                state.tuples[i + 1] = state.tuples[i];
            }
            state.tuples[pos] = GKTuple { value: u.value, count: 1, max_error: 0 };
            return;
        }

        // Step 4: full — must compress before insert. Merge the two
        // adjacent tuples with smallest (count + max_error) sum.
        let mut min_sum = u64::MAX;
        let mut min_idx = 0usize;
        for i in 0..state.params.capacity - 1 {
            let s = state.tuples[i].count as u64
                + state.tuples[i].max_error as u64
                + state.tuples[i + 1].count as u64
                + state.tuples[i + 1].max_error as u64;
            if s < min_sum {
                min_sum = s;
                min_idx = i;
            }
        }
        // Merge tuples[min_idx] and tuples[min_idx + 1] into tuples[min_idx + 1].
        // (Keep the larger-value endpoint; combined count; propagated max_error.)
        let merged = GKTuple {
            value: state.tuples[min_idx + 1].value,
            count: state
                .tuples[min_idx]
                .count
                .saturating_add(state.tuples[min_idx + 1].count),
            max_error: state
                .tuples[min_idx]
                .max_error
                .saturating_add(state.tuples[min_idx].count)
                .max(state.tuples[min_idx + 1].max_error),
        };
        state.tuples[min_idx + 1] = merged;
        // Shift [min_idx + 2..] left to fill the gap, then we have a free
        // slot at the end which becomes the insertion point.
        for i in min_idx..state.params.capacity - 1 {
            state.tuples[i] = state.tuples[i + 1];
        }
        // Now insert (value, 1, 0) at the proper sorted position.
        let active_len_after = state.params.capacity - 1;
        let pos = state.tuples[..active_len_after]
            .iter()
            .position(|t| t.value >= u.value)
            .unwrap_or(active_len_after);
        for i in (pos..active_len_after).rev() {
            state.tuples[i + 1] = state.tuples[i];
        }
        state.tuples[pos] = GKTuple { value: u.value, count: 1, max_error: 0 };
    }
}

impl GK {
    /// Approximate rank query: returns the sum of counts for tuples with
    /// value ≤ `value`. Not bias-corrected; the full GK guarantees rank
    /// within ε of the true rank.
    pub fn rank(state: &GKState, value: u32) -> u64 {
        state
            .tuples
            .iter()
            .filter(|t| t.count > 0 && t.value <= value)
            .map(|t| t.count as u64)
            .sum()
    }

    /// Apply a delta (Pattern B: just overwrite the state).
    pub fn apply_delta(state: &mut GKState, delta: &GKDelta) {
        assert_eq!(delta.final_tuples.len(), state.params.capacity);
        state.tuples = delta.final_tuples.clone();
    }
}

impl DeltaCert for GK {
    type Delta = GKDelta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta {
        let mut s = prev.clone();
        for u in batch {
            GK::update(&mut s, u);
        }
        GKDelta { batch: batch.to_vec(), final_tuples: s.tuples }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(cap: usize) -> GKParams {
        GKParams { capacity: cap }
    }

    #[test]
    fn insert_into_empty_appends_active_tuple() {
        let mut s = GK::new(&params(4));
        GK::update(&mut s, &GKUpdate { value: 5 });
        assert_eq!(s.tuples[0], GKTuple { value: 5, count: 1, max_error: 0 });
        assert_eq!(s.tuples[1].count, 0);
    }

    #[test]
    fn insertions_stay_sorted() {
        let mut s = GK::new(&params(4));
        for v in [3u32, 7, 1, 5] {
            GK::update(&mut s, &GKUpdate { value: v });
        }
        let actives: Vec<u32> = s.tuples.iter().filter(|t| t.count > 0).map(|t| t.value).collect();
        let mut sorted = actives.clone();
        sorted.sort();
        assert_eq!(actives, sorted);
    }

    /// Inserting more than `capacity` distinct values triggers compression.
    /// Active-tuple count never exceeds `capacity` after compression.
    #[test]
    fn overflow_triggers_compression() {
        let cap = 4;
        let mut s = GK::new(&params(cap));
        // 8 distinct values into a capacity-4 summary
        for v in 0u32..8 {
            GK::update(&mut s, &GKUpdate { value: v });
        }
        let active = s.tuples.iter().filter(|t| t.count > 0).count();
        assert!(active <= cap, "active {active} > capacity {cap}");
        // Total counts add up to 8 (number of insertions).
        let total: u64 = s.tuples.iter().map(|t| t.count as u64).sum();
        assert_eq!(total, 8);
    }

    #[test]
    fn delta_replay_matches() {
        let p = params(4);
        let initial = GK::new(&p);
        let batch: Vec<GKUpdate> = (0..6).map(|i| GKUpdate { value: i }).collect();

        let mut by_replay = initial.clone();
        for u in &batch {
            GK::update(&mut by_replay, u);
        }

        let delta = GK::build_delta(&initial, &batch);
        let mut by_delta = initial.clone();
        GK::apply_delta(&mut by_delta, &delta);

        assert_eq!(by_replay, by_delta);
    }

    #[test]
    #[should_panic(expected = "GK capacity must be a multiple of 4")]
    fn misaligned_capacity_rejected() {
        let _ = GK::new(&GKParams { capacity: 6 });
    }
}
