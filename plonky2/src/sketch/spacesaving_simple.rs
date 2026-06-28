//! Plaintext **simple per-record** SpaceSaving sketch (paper §5.3 Pattern B,
//! Appendix G), ported from `../src/sketch/spacesaving.rs`.
//!
//! The canonical Misra-Gries top-`s` summary — a fixed-capacity list of
//! `(key, count)` rows — kept as a baseline alongside the **batched** §G
//! group-sort-split pipeline in [`crate::sketch::spacesaving`] (the in-circuit
//! shape). On insert `(key, value)`: bump a matching row, else fill a free slot,
//! else evict the min-count row and write `(key, min_count + value)`.
//!
//! Unlike the plonky3 original there is **no `capacity_s % 2` constraint** —
//! that was a BabyBear cell-alignment artifact; over Goldilocks each cell is a
//! single field element.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

use crate::commitment::commit;
use crate::config::F;
use crate::sketch::{DeltaCert, Sketch};

/// Public SpaceSaving parameters: number of counter slots.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpaceSavingParams {
    pub capacity_s: usize,
}

/// Plaintext SpaceSaving state: a fixed `capacity_s`-row summary of `(key,
/// count)` pairs. Empty slots have count = 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceSavingState {
    pub rows: Vec<(u64, u32)>,
    pub params: SpaceSavingParams,
}

/// One record to fold in: `(key, value)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpaceSavingUpdate {
    pub key: u64,
    pub value: u32,
}

/// Per-batch certificate carrying the whole final state (Pattern B: eviction is
/// non-monotone, so there is no per-cell additive shortcut).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceSavingDelta {
    pub batch: Vec<SpaceSavingUpdate>,
    pub final_rows: Vec<(u64, u32)>,
}

impl SpaceSavingState {
    pub fn new(params: &SpaceSavingParams) -> Self {
        assert!(params.capacity_s >= 1, "SpaceSaving capacity_s must be >= 1");
        Self { rows: vec![(0u64, 0u32); params.capacity_s], params: *params }
    }

    /// Fold one record in (match / fill / evict-min).
    pub fn update(&mut self, u: &SpaceSavingUpdate) {
        if let Some(row) = self.rows.iter_mut().find(|(k, c)| *k == u.key && *c > 0) {
            row.1 = row.1.saturating_add(u.value);
            return;
        }
        if let Some(row) = self.rows.iter_mut().find(|(_, c)| *c == 0) {
            *row = (u.key, u.value);
            return;
        }
        let (min_idx, &(_, min_count)) = self
            .rows
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, c))| *c)
            .expect("non-empty rows");
        self.rows[min_idx] = (u.key, min_count.saturating_add(u.value));
    }

    /// Best-effort point query: the count stored for `key`, else 0.
    pub fn query(&self, key: u64) -> u32 {
        self.rows.iter().find(|(k, _)| *k == key).map(|(_, c)| *c).unwrap_or(0)
    }

    /// Apply a delta (Pattern B: copy the final state).
    pub fn apply_delta(&mut self, delta: &SpaceSavingDelta) {
        assert_eq!(delta.final_rows.len(), self.params.capacity_s);
        self.rows = delta.final_rows.clone();
    }

    /// Build the Pattern-B delta for `batch` against this state.
    pub fn build_delta(&self, batch: &[SpaceSavingUpdate]) -> SpaceSavingDelta {
        let mut s = self.clone();
        for u in batch {
            s.update(u);
        }
        SpaceSavingDelta { batch: batch.to_vec(), final_rows: s.rows }
    }

    /// Row-major flattened `(key, count)` cells (commit pre-image).
    pub fn cells(&self) -> Vec<F> {
        self.rows
            .iter()
            .flat_map(|&(k, c)| [F::from_canonical_u64(k), F::from_canonical_u32(c)])
            .collect()
    }

    /// Poseidon commitment of the state.
    pub fn commit(&self) -> HashOut<F> {
        commit(&self.cells())
    }
}

/// Zero-sized marker wiring the simple SpaceSaving into the [`Sketch`]/
/// [`DeltaCert`] abstraction, mirroring `../src/sketch/spacesaving.rs::SpaceSaving`.
pub struct SpaceSaving;

impl Sketch for SpaceSaving {
    type Params = SpaceSavingParams;
    type State = SpaceSavingState;
    type Update = SpaceSavingUpdate;

    fn new(params: &Self::Params) -> Self::State {
        SpaceSavingState::new(params)
    }
    fn update(state: &mut Self::State, u: &Self::Update) {
        state.update(u)
    }
}

impl DeltaCert for SpaceSaving {
    type Delta = SpaceSavingDelta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta {
        prev.build_delta(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(cap: usize) -> SpaceSavingParams {
        SpaceSavingParams { capacity_s: cap }
    }

    #[test]
    fn insert_fills_first_free_slot() {
        let mut s = SpaceSavingState::new(&params(4));
        s.update(&SpaceSavingUpdate { key: 42, value: 7 });
        assert_eq!(s.rows[0], (42, 7));
        for r in 1..4 {
            assert_eq!(s.rows[r], (0, 0));
        }
    }

    #[test]
    fn repeat_insert_increments_existing_row() {
        let mut s = SpaceSavingState::new(&params(4));
        s.update(&SpaceSavingUpdate { key: 42, value: 7 });
        s.update(&SpaceSavingUpdate { key: 42, value: 3 });
        assert_eq!(s.rows[0], (42, 10));
        assert_eq!(s.rows[1], (0, 0));
    }

    #[test]
    fn eviction_replaces_min_count_row() {
        let mut s = SpaceSavingState::new(&params(2));
        s.update(&SpaceSavingUpdate { key: 1, value: 10 });
        s.update(&SpaceSavingUpdate { key: 2, value: 3 });
        s.update(&SpaceSavingUpdate { key: 3, value: 5 });
        assert_eq!(s.rows[0], (1, 10));
        assert_eq!(s.rows[1], (3, 8));
    }

    #[test]
    fn delta_replay_matches() {
        let initial = SpaceSavingState::new(&params(4));
        let batch: Vec<SpaceSavingUpdate> = (0..6)
            .map(|i| SpaceSavingUpdate { key: (i % 3) as u64 + 1, value: 1 + (i as u32 % 5) })
            .collect();

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
        let s0 = SpaceSavingState::new(&params(4));
        let mut s1 = s0.clone();
        s1.update(&SpaceSavingUpdate { key: 7, value: 1 });
        assert_ne!(s0.commit(), s1.commit());
    }
}
