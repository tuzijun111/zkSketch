//! Plaintext SpaceSaving sketch: when full, a new key replaces the minimum-count row.

use crate::sketch::{DeltaCert, Sketch};

/// Public SpaceSaving parameters: number of counter slots.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpaceSavingParams {
    pub capacity_s: usize,
}

/// Plaintext SpaceSaving state: a fixed `capacity_s`-row summary of
/// `(key, count)` pairs. Empty slots have count = 0 (key = 0 is a valid
/// placeholder when count is also 0).
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

/// Per-batch certificate. For Pattern B, the delta type carries the whole
/// final state alongside the batch — there's no per-cell additive shortcut
/// (eviction is non-monotone in the cell-level view). The §G "TopS +
/// threshold-residual" certificate is what the in-circuit version would
/// use; this prototype just records the post-batch state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceSavingDelta {
    pub batch: Vec<SpaceSavingUpdate>,
    pub final_rows: Vec<(u64, u32)>,
}

pub struct SpaceSaving;

impl Sketch for SpaceSaving {
    type Params = SpaceSavingParams;
    type State = SpaceSavingState;
    type Update = SpaceSavingUpdate;

    fn new(params: &Self::Params) -> Self::State {
        assert!(params.capacity_s >= 1, "SpaceSaving capacity_s must be ≥ 1");
        assert!(
            params.capacity_s % 2 == 0,
            "SpaceSaving capacity_s must be even so 2*capacity_s aligns with CELL_ALIGNMENT = 4"
        );
        Self::State {
            rows: vec![(0u64, 0u32); params.capacity_s],
            params: *params,
        }
    }

    fn update(state: &mut Self::State, u: &Self::Update) {
        // 1. If `u.key` matches an existing row (with count > 0), increment.
        if let Some(row) = state.rows.iter_mut().find(|(k, c)| *k == u.key && *c > 0) {
            row.1 = row.1.saturating_add(u.value);
            return;
        }
        // 2. Else if a free slot exists, populate it.
        if let Some(row) = state.rows.iter_mut().find(|(_, c)| *c == 0) {
            *row = (u.key, u.value);
            return;
        }
        // 3. Else evict the min-count row: set it to (u.key, min_count + u.value).
        let (min_idx, &(_, min_count)) = state
            .rows
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, c))| *c)
            .expect("non-empty rows");
        state.rows[min_idx] = (u.key, min_count.saturating_add(u.value));
    }
}

impl SpaceSaving {
    /// Best-effort point query: returns the count stored for `key` if any
    /// row holds it, else 0. Note: SpaceSaving's count is an upper bound on
    /// the true frequency when paired with the (omitted) `err` field; the
    /// raw count alone over-estimates by the evicted predecessor's count.
    pub fn query(state: &SpaceSavingState, key: u64) -> u32 {
        state
            .rows
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, c)| *c)
            .unwrap_or(0)
    }

    /// Apply a previously-computed delta. For Pattern B the apply is just
    /// "copy the final state from the delta" — no incremental commute.
    pub fn apply_delta(state: &mut SpaceSavingState, delta: &SpaceSavingDelta) {
        assert_eq!(
            delta.final_rows.len(),
            state.params.capacity_s,
            "delta.final_rows length must equal capacity_s"
        );
        state.rows = delta.final_rows.clone();
    }
}

impl DeltaCert for SpaceSaving {
    type Delta = SpaceSavingDelta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta {
        let mut s = prev.clone();
        for u in batch {
            SpaceSaving::update(&mut s, u);
        }
        SpaceSavingDelta {
            batch: batch.to_vec(),
            final_rows: s.rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(cap: usize) -> SpaceSavingParams {
        SpaceSavingParams { capacity_s: cap }
    }

    /// One insert into a fresh empty state goes to the first free slot.
    #[test]
    fn insert_fills_first_free_slot() {
        let mut s = SpaceSaving::new(&params(4));
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 42, value: 7 });
        assert_eq!(s.rows[0], (42, 7));
        for r in 1..4 {
            assert_eq!(s.rows[r], (0, 0));
        }
    }

    /// Re-inserting the same key increments the existing row, doesn't take a new slot.
    #[test]
    fn repeat_insert_increments_existing_row() {
        let mut s = SpaceSaving::new(&params(4));
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 42, value: 7 });
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 42, value: 3 });
        assert_eq!(s.rows[0], (42, 10));
        assert_eq!(s.rows[1], (0, 0));
    }

    /// Once full, a new key evicts the min-count row (Misra-Gries semantics).
    #[test]
    fn eviction_replaces_min_count_row() {
        let mut s = SpaceSaving::new(&params(2));
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 1, value: 10 });
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 2, value: 3 });
        // Now full. Insert key=3 should evict the min-count row (key=2, count=3)
        // and set the new row to (3, 3 + 5) = (3, 8).
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 3, value: 5 });
        // Row 0 unchanged.
        assert_eq!(s.rows[0], (1, 10));
        // Row 1 was evicted; new content is (3, 8).
        assert_eq!(s.rows[1], (3, 8));
    }

    /// build_delta + apply_delta == replay (Pattern B trivially: apply just sets the final state).
    #[test]
    fn delta_replay_matches() {
        let p = params(4);
        let initial = SpaceSaving::new(&p);
        let batch: Vec<SpaceSavingUpdate> = (0..6)
            .map(|i| SpaceSavingUpdate { key: (i % 3) as u64 + 1, value: 1 + (i as u32 % 5) })
            .collect();

        let mut by_replay = initial.clone();
        for u in &batch {
            SpaceSaving::update(&mut by_replay, u);
        }

        let delta = SpaceSaving::build_delta(&initial, &batch);
        let mut by_delta = initial.clone();
        SpaceSaving::apply_delta(&mut by_delta, &delta);

        assert_eq!(by_replay, by_delta);
    }
}
