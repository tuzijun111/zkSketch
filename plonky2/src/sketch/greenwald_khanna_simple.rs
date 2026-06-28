//! Plaintext **simple per-record** Greenwald–Khanna (GK) quantile sketch
//! (paper §5.3 Pattern B), ported from `../src/sketch/greenwald_khanna.rs`.
//!
//! This is the *simplified* GK summary — a bounded-capacity sorted list of
//! `(value, count, max_error)` tuples — kept as a baseline alongside the
//! **batched** §5.4 fusion pipeline in [`crate::sketch::greenwald_khanna`]
//! (which is the in-circuit shape). Insertion places `(value, 1, 0)` at the
//! sorted position; on overflow the two adjacent tuples with the smallest
//! combined `count + max_error` are merged (a cheap stand-in for GK's band rule).
//!
//! Unlike the plonky3 original, there is **no `capacity % 4` constraint**: that
//! was a BabyBear 4-cells-per-extension-element packing artifact, and over
//! Goldilocks each cell is a single field element (see `plonky2/README.md`).

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

use crate::commitment::commit;
use crate::config::F;
use crate::sketch::{DeltaCert, Sketch};

/// Public GK parameters: maximum summary capacity.
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

/// Plaintext GK state: a sorted-by-`value` list of tuples padded with zero
/// tuples up to `capacity`. Active tuples have `count > 0`.
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

/// Per-batch certificate. For Pattern B, just carries the post-batch state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GKDelta {
    pub batch: Vec<GKUpdate>,
    pub final_tuples: Vec<GKTuple>,
}

impl GKState {
    pub fn new(params: &GKParams) -> Self {
        assert!(params.capacity >= 2, "GK capacity must be >= 2");
        Self {
            tuples: vec![GKTuple { value: 0, count: 0, max_error: 0 }; params.capacity],
            params: *params,
        }
    }

    /// Fold one value in (sorted insert + compress-on-overflow).
    pub fn update(&mut self, u: &GKUpdate) {
        let active_len = self.tuples.iter().take_while(|t| t.count > 0).count();
        let pos = self.tuples[..active_len]
            .iter()
            .position(|t| t.value >= u.value)
            .unwrap_or(active_len);

        if active_len < self.params.capacity {
            for i in (pos..active_len).rev() {
                self.tuples[i + 1] = self.tuples[i];
            }
            self.tuples[pos] = GKTuple { value: u.value, count: 1, max_error: 0 };
            return;
        }

        // Full — compress before insert: merge the adjacent pair with the
        // smallest (count + max_error) sum.
        let mut min_sum = u64::MAX;
        let mut min_idx = 0usize;
        for i in 0..self.params.capacity - 1 {
            let s = self.tuples[i].count as u64
                + self.tuples[i].max_error as u64
                + self.tuples[i + 1].count as u64
                + self.tuples[i + 1].max_error as u64;
            if s < min_sum {
                min_sum = s;
                min_idx = i;
            }
        }
        let merged = GKTuple {
            value: self.tuples[min_idx + 1].value,
            count: self.tuples[min_idx].count.saturating_add(self.tuples[min_idx + 1].count),
            max_error: self.tuples[min_idx]
                .max_error
                .saturating_add(self.tuples[min_idx].count)
                .max(self.tuples[min_idx + 1].max_error),
        };
        self.tuples[min_idx + 1] = merged;
        for i in min_idx..self.params.capacity - 1 {
            self.tuples[i] = self.tuples[i + 1];
        }
        let active_len_after = self.params.capacity - 1;
        let pos = self.tuples[..active_len_after]
            .iter()
            .position(|t| t.value >= u.value)
            .unwrap_or(active_len_after);
        for i in (pos..active_len_after).rev() {
            self.tuples[i + 1] = self.tuples[i];
        }
        self.tuples[pos] = GKTuple { value: u.value, count: 1, max_error: 0 };
    }

    /// Approximate rank: sum of counts for tuples with `value <= value`.
    pub fn rank(&self, value: u32) -> u64 {
        self.tuples
            .iter()
            .filter(|t| t.count > 0 && t.value <= value)
            .map(|t| t.count as u64)
            .sum()
    }

    /// Apply a delta (Pattern B: overwrite the state).
    pub fn apply_delta(&mut self, delta: &GKDelta) {
        assert_eq!(delta.final_tuples.len(), self.params.capacity);
        self.tuples = delta.final_tuples.clone();
    }

    /// Build the Pattern-B delta for `batch` against this state.
    pub fn build_delta(&self, batch: &[GKUpdate]) -> GKDelta {
        let mut s = self.clone();
        for u in batch {
            s.update(u);
        }
        GKDelta { batch: batch.to_vec(), final_tuples: s.tuples }
    }

    /// Row-major flattened `(value, count, max_error)` cells (commit pre-image).
    pub fn cells(&self) -> Vec<F> {
        self.tuples
            .iter()
            .flat_map(|t| {
                [
                    F::from_canonical_u32(t.value),
                    F::from_canonical_u32(t.count),
                    F::from_canonical_u32(t.max_error),
                ]
            })
            .collect()
    }

    /// Poseidon commitment of the state.
    pub fn commit(&self) -> HashOut<F> {
        commit(&self.cells())
    }
}

/// Zero-sized marker wiring the simple GK into the [`Sketch`]/[`DeltaCert`]
/// abstraction, mirroring `../src/sketch/greenwald_khanna.rs::GK`.
pub struct GK;

impl Sketch for GK {
    type Params = GKParams;
    type State = GKState;
    type Update = GKUpdate;

    fn new(params: &Self::Params) -> Self::State {
        GKState::new(params)
    }
    fn update(state: &mut Self::State, u: &Self::Update) {
        state.update(u)
    }
}

impl DeltaCert for GK {
    type Delta = GKDelta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta {
        prev.build_delta(batch)
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
        let mut s = GKState::new(&params(4));
        s.update(&GKUpdate { value: 5 });
        assert_eq!(s.tuples[0], GKTuple { value: 5, count: 1, max_error: 0 });
        assert_eq!(s.tuples[1].count, 0);
    }

    #[test]
    fn insertions_stay_sorted() {
        let mut s = GKState::new(&params(4));
        for v in [3u32, 7, 1, 5] {
            s.update(&GKUpdate { value: v });
        }
        let actives: Vec<u32> = s.tuples.iter().filter(|t| t.count > 0).map(|t| t.value).collect();
        let mut sorted = actives.clone();
        sorted.sort();
        assert_eq!(actives, sorted);
    }

    #[test]
    fn overflow_triggers_compression() {
        let cap = 4;
        let mut s = GKState::new(&params(cap));
        for v in 0u32..8 {
            s.update(&GKUpdate { value: v });
        }
        let active = s.tuples.iter().filter(|t| t.count > 0).count();
        assert!(active <= cap, "active {active} > capacity {cap}");
        let total: u64 = s.tuples.iter().map(|t| t.count as u64).sum();
        assert_eq!(total, 8);
    }

    #[test]
    fn rank_counts_values_at_most() {
        let mut s = GKState::new(&params(8));
        for v in [1u32, 3, 3, 5, 9] {
            s.update(&GKUpdate { value: v });
        }
        assert_eq!(s.rank(0), 0);
        assert_eq!(s.rank(3), 3); // 1, 3, 3
        assert_eq!(s.rank(100), 5);
    }

    #[test]
    fn delta_replay_matches() {
        let initial = GKState::new(&params(4));
        let batch: Vec<GKUpdate> = (0..6).map(|i| GKUpdate { value: i }).collect();

        let mut by_replay = initial.clone();
        for u in &batch {
            by_replay.update(u);
        }
        let delta = initial.build_delta(&batch);
        let mut by_delta = initial.clone();
        by_delta.apply_delta(&delta);
        assert_eq!(by_replay, by_delta);
    }

    #[test]
    fn commit_changes_with_state() {
        let s0 = GKState::new(&params(4));
        let mut s1 = s0.clone();
        s1.update(&GKUpdate { value: 7 });
        assert_ne!(s0.commit(), s1.commit());
    }
}
