//! Plaintext batched Greenwald–Khanna with equal-value fusion; native side of leaf::greenwald_khanna.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

use crate::commitment::commit;
use crate::config::F;

/// One GK tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GkTuple {
    pub value: u64,
    pub count: u64,
    pub max_error: u64,
    pub active: u64,
}

impl GkTuple {
    pub const fn real(value: u64, count: u64, max_error: u64) -> Self {
        Self { value, count, max_error, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { value: 0, count: 0, max_error: 0, active: 0 }
    }
}

/// One streamed record: insert `value` (count 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GkUpdate {
    pub value: u64,
    pub active: u64,
}

impl GkUpdate {
    pub const fn real(value: u64) -> Self {
        Self { value, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { value: 0, active: 0 }
    }
}

/// GK shape: keep `capacity` tuples; ingest `batch` records per epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GkParams {
    pub capacity: usize,
    pub batch: usize,
}

impl GkParams {
    pub fn union_size(&self) -> usize {
        self.capacity + self.batch
    }
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity >= 1");
        assert!(self.batch >= 1, "batch >= 1");
    }
}

/// A GK summary: exactly `capacity` value-sorted tuples (dummies pad).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GkState {
    pub tuples: Vec<GkTuple>,
    pub params: GkParams,
}

impl GkState {
    pub fn empty(params: GkParams) -> Self {
        Self { tuples: vec![GkTuple::dummy(); params.capacity], params }
    }

    pub fn active_count(&self) -> usize {
        self.tuples.iter().filter(|t| t.active == 1).count()
    }

    pub fn total_mass(&self) -> u64 {
        self.tuples.iter().filter(|t| t.active == 1).map(|t| t.count).sum()
    }

    /// Rank of `q`: total count of active tuples with `value <= q`.
    pub fn rank(&self, q: u64) -> u64 {
        self.tuples.iter().filter(|t| t.active == 1 && t.value <= q).map(|t| t.count).sum()
    }

    /// Flattened `[value, count, max_error, active]` per tuple — the commit
    /// pre-image (must match the in-circuit `final_cells` layout).
    pub fn cells(&self) -> Vec<F> {
        self.tuples
            .iter()
            .flat_map(|t| {
                [
                    F::from_canonical_u64(t.value),
                    F::from_canonical_u64(t.count),
                    F::from_canonical_u64(t.max_error),
                    F::from_canonical_u64(t.active),
                ]
            })
            .collect()
    }

    pub fn commit(&self) -> HashOut<F> {
        commit(&self.cells())
    }
}

/// Flattened `[value, count, max_error, active]` per batch record (count =
/// active, max_error = 0) — the batch commit pre-image.
pub fn batch_cells(batch: &[GkUpdate]) -> Vec<F> {
    batch
        .iter()
        .flat_map(|u| {
            [
                F::from_canonical_u64(u.value),
                F::from_canonical_u64(u.active),
                F::ZERO,
                F::from_canonical_u64(u.active),
            ]
        })
        .collect()
}

/// One parity-0 fusion round: merge each adjacent pair `(2i, 2i+1)` when both
/// are active with equal value, into slot `2i+1` (summed count/max_error),
/// dummying slot `2i`. Returns `(fused, decisions)`.
pub fn fuse_round_parity0(input: &[GkTuple]) -> (Vec<GkTuple>, Vec<bool>) {
    let num_pairs = input.len() / 2;
    let mut output = input.to_vec();
    let mut decisions = Vec::with_capacity(num_pairs);
    for i in 0..num_pairs {
        let a = input[2 * i];
        let b = input[2 * i + 1];
        let eligible = a.active == 1 && b.active == 1 && a.value == b.value;
        decisions.push(eligible);
        if eligible {
            output[2 * i] = GkTuple::dummy();
            output[2 * i + 1] = GkTuple {
                value: b.value,
                count: a.count + b.count,
                max_error: a.max_error + b.max_error,
                active: 1,
            };
        }
    }
    (output, decisions)
}

/// Re-sort a tuple table by `(active asc, value asc)` and return
/// `(sorted, sigma)` with `sorted[i] = input[sigma[i]]`.
pub fn resort_by_active_value(input: &[GkTuple]) -> (Vec<GkTuple>, Vec<usize>) {
    let mut indexed: Vec<(usize, GkTuple)> = input.iter().copied().enumerate().collect();
    indexed.sort_by_key(|(_, t)| (t.active, t.value));
    let sigma = indexed.iter().map(|(i, _)| *i).collect();
    let sorted = indexed.iter().map(|(_, t)| *t).collect();
    (sorted, sigma)
}

/// Smallest `L` with `2^L >= total` (the §5.4 `⌈log₂ M⌉` schedule).
pub fn num_fusion_rounds(total: usize) -> usize {
    let mut l = 0usize;
    let mut span = 1usize;
    while span < total {
        span <<= 1;
        l += 1;
    }
    l.max(1)
}

/// Per-round witness (decisions + resorted table + permutation).
pub struct FusionRound {
    pub decisions: Vec<bool>,
    pub resorted: Vec<GkTuple>,
    pub sigma: Vec<usize>,
}

/// Run `rounds` fuse+resort rounds; returns `(final_table, per_round_data)`.
pub fn fuse_all_rounds(sorted_union: &[GkTuple], rounds: usize) -> (Vec<GkTuple>, Vec<FusionRound>) {
    let mut current = sorted_union.to_vec();
    let mut data = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let (fused, decisions) = fuse_round_parity0(&current);
        let (resorted, sigma) = resort_by_active_value(&fused);
        data.push(FusionRound { decisions, resorted: resorted.clone(), sigma });
        current = resorted;
    }
    (current, data)
}

/// Build the sorted union of `S_old.tuples ‖ batch-as-tuples`.
pub fn build_union(s_old: &GkState, batch: &[GkUpdate]) -> Vec<GkTuple> {
    let mut union: Vec<GkTuple> = s_old.tuples.clone();
    for u in batch {
        union.push(GkTuple { value: u.value, count: u.active, max_error: 0, active: u.active });
    }
    union.sort_by_key(|t| (t.active, t.value));
    union
}

/// Apply the batched GK update with the worst-case `⌈log₂(total)⌉` rounds.
pub fn apply_batch(s_old: &GkState, batch: &[GkUpdate]) -> (GkState, Vec<GkTuple>) {
    let total = s_old.params.union_size();
    apply_batch_with_rounds(s_old, batch, num_fusion_rounds(total))
}

/// Apply the batched GK update with exactly `fusion_rounds` rounds (the
/// paper-sanctioned public round-count knob).
pub fn apply_batch_with_rounds(
    s_old: &GkState,
    batch: &[GkUpdate],
    fusion_rounds: usize,
) -> (GkState, Vec<GkTuple>) {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    assert_eq!(batch.len(), m);
    assert!(fusion_rounds >= 1);
    let union = build_union(s_old, batch);
    let (fused_sorted, _data) = fuse_all_rounds(&union, fusion_rounds);
    let excess = fused_sorted[..m].to_vec();
    let s_new = fused_sorted[m..m + cap].to_vec();
    (GkState { tuples: s_new, params: s_old.params }, excess)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> GkParams {
        GkParams { capacity: 4, batch: 4 }
    }

    #[test]
    fn fusion_merges_equal_values() {
        let s0 = GkState::empty(params());
        // values 5,5,9,5 → after fusion the three 5s collapse to count 3.
        let batch =
            vec![GkUpdate::real(5), GkUpdate::real(5), GkUpdate::real(9), GkUpdate::real(5)];
        let (s1, _excess) = apply_batch(&s0, &batch);
        // rank(5) counts all three 5s; rank(9) counts everything.
        assert_eq!(s1.rank(5), 3);
        assert_eq!(s1.rank(9), 4);
        assert_eq!(s1.total_mass(), 4); // mass conserved (4 active inserts)
    }

    #[test]
    fn commit_changes_with_state() {
        let s0 = GkState::empty(params());
        let (s1, _) = apply_batch(
            &s0,
            &[GkUpdate::real(3), GkUpdate::dummy(), GkUpdate::dummy(), GkUpdate::dummy()],
        );
        assert_ne!(s0.commit(), s1.commit());
    }
}
