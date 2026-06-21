//! Plaintext SpaceSaving sketch (paper Appendix D/G, Pattern B top-`s`).
//!
//! Port of `../src/sketch/ss_final_full.rs` to Goldilocks. Each row is a
//! `(key, count, active)` triple; over Goldilocks the 64-bit key is a single
//! field element (no BabyBear key-lo/hi split), so a row commits as **3** field
//! elements (vs. 4 in the plonky3 original).
//!
//! The update is the §G single-pass top-`s` retention: union old∪batch, group
//! by key (summing counts), count-sort, keep the top `capacity` by count. The
//! in-circuit counterpart is [`crate::leaf::spacesaving`].

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

use crate::commitment::commit;
use crate::config::F;

/// One SpaceSaving row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SsRow {
    pub key: u64,
    pub count: u64,
    pub active: u64,
}

impl SsRow {
    pub const fn real(key: u64, count: u64) -> Self {
        Self { key, count, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { key: 0, count: 0, active: 0 }
    }
}

/// One streamed record `key += value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SsUpdate {
    pub key: u64,
    pub value: u64,
    pub active: u64,
}

impl SsUpdate {
    pub const fn real(key: u64, value: u64) -> Self {
        Self { key, value, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { key: 0, value: 0, active: 0 }
    }
}

/// SpaceSaving shape: keep the top `capacity` heavy hitters; ingest `batch`
/// records per epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsParams {
    pub capacity: usize,
    pub batch: usize,
}

impl SsParams {
    pub fn union_size(&self) -> usize {
        self.capacity + self.batch
    }
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity >= 1");
        assert!(self.batch >= 1, "batch >= 1");
    }
}

/// A SpaceSaving summary: exactly `capacity` rows (dummies pad the unused slots).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsState {
    pub rows: Vec<SsRow>,
    pub params: SsParams,
}

impl SsState {
    pub fn empty(params: SsParams) -> Self {
        Self { rows: vec![SsRow::dummy(); params.capacity], params }
    }

    pub fn active_count(&self) -> usize {
        self.rows.iter().filter(|r| r.active == 1).count()
    }

    pub fn total_mass(&self) -> u64 {
        self.rows.iter().filter(|r| r.active == 1).map(|r| r.count).sum()
    }

    /// Estimated frequency of `key` (0 if not retained).
    pub fn frequency(&self, key: u64) -> u64 {
        self.rows.iter().find(|r| r.active == 1 && r.key == key).map(|r| r.count).unwrap_or(0)
    }

    /// Flattened `[key, count, active]` per row — the commit pre-image (must
    /// match the in-circuit `final_cells` layout in [`crate::leaf::spacesaving`]).
    pub fn cells(&self) -> Vec<F> {
        self.rows
            .iter()
            .flat_map(|r| {
                [
                    F::from_canonical_u64(r.key),
                    F::from_canonical_u64(r.count),
                    F::from_canonical_u64(r.active),
                ]
            })
            .collect()
    }

    pub fn commit(&self) -> HashOut<F> {
        commit(&self.cells())
    }
}

/// Flattened `[key, value, active]` per batch record — the batch commit
/// pre-image.
pub fn batch_cells(batch: &[SsUpdate]) -> Vec<F> {
    batch
        .iter()
        .flat_map(|u| {
            [
                F::from_canonical_u64(u.key),
                F::from_canonical_u64(u.value),
                F::from_canonical_u64(u.active),
            ]
        })
        .collect()
}

/// All witnesses the in-circuit leaf needs, derived from one native update.
/// (The circuit reconstructs everything from these; only the permutations and
/// the grouped/sorted tables are surfaced.)
pub struct SsBuild {
    /// `combined` = old rows ‖ batch rows (length `cap + m`).
    pub combined: Vec<SsRow>,
    /// `key_sorted` = combined sorted ascending by key.
    pub key_sorted: Vec<SsRow>,
    /// adjacency-equal tag on the key-sorted view (`tag[r]=1` iff
    /// `key_sorted[r].key == key_sorted[r-1].key`); `tag[0]=0`.
    pub key_eq_tag: Vec<u64>,
    /// running count sum + active sum over equal-key runs.
    pub acc_count: Vec<u64>,
    pub acc_active: Vec<u64>,
    /// segment-end indicator.
    pub seg_end: Vec<u64>,
    /// grouped table `G`: segment-end rows carry the summed count.
    pub grouped: Vec<SsRow>,
    /// `g_sorted` = grouped re-sorted by (active asc, count asc, key asc).
    pub g_sorted: Vec<SsRow>,
}

/// Build the §G top-`s` update witnesses.
pub fn build_ss(s_old: &SsState, batch: &[SsUpdate]) -> SsBuild {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;

    let mut combined: Vec<SsRow> = Vec::with_capacity(total);
    for r in &s_old.rows {
        combined.push(*r);
    }
    for u in batch {
        combined.push(SsRow { key: u.key, count: u.value, active: u.active });
    }

    // key-sort ascending (stable).
    let mut idx: Vec<usize> = (0..total).collect();
    idx.sort_by_key(|&i| combined[i].key);
    let key_sorted: Vec<SsRow> = idx.iter().map(|&i| combined[i]).collect();

    // adjacency tags + running sums over equal-key runs.
    let mut key_eq_tag = vec![0u64; total];
    let mut acc_count = vec![0u64; total];
    let mut acc_active = vec![0u64; total];
    for r in 0..total {
        if r > 0 && key_sorted[r].key == key_sorted[r - 1].key {
            key_eq_tag[r] = 1;
            acc_count[r] = acc_count[r - 1] + key_sorted[r].count;
            acc_active[r] = acc_active[r - 1] + key_sorted[r].active;
        } else {
            acc_count[r] = key_sorted[r].count;
            acc_active[r] = key_sorted[r].active;
        }
    }
    let mut seg_end = vec![0u64; total];
    for r in 0..total {
        seg_end[r] =
            if r + 1 == total || key_sorted[r + 1].key != key_sorted[r].key { 1 } else { 0 };
    }

    // grouped table G: at each segment end emit (key, summed count, active).
    let mut grouped = vec![SsRow::dummy(); total];
    for r in 0..total {
        if seg_end[r] == 1 {
            let act = if acc_active[r] > 0 { 1 } else { 0 };
            grouped[r] = SsRow {
                key: if act == 1 { key_sorted[r].key } else { 0 },
                count: if act == 1 { acc_count[r] } else { 0 },
                active: act,
            };
        }
    }

    // count-sort G by (active asc, count asc, key asc).
    let mut idx2: Vec<usize> = (0..total).collect();
    idx2.sort_by_key(|&i| (grouped[i].active, grouped[i].count, grouped[i].key));
    let g_sorted: Vec<SsRow> = idx2.iter().map(|&i| grouped[i]).collect();

    SsBuild { combined, key_sorted, key_eq_tag, acc_count, acc_active, seg_end, grouped, g_sorted }
}

/// Apply the batched SpaceSaving top-`s` update natively, returning
/// `(s_new, residual)`. `s_new` = the top `capacity` by count; `residual` =
/// the lower `batch` candidates (count-ascending).
pub fn apply_batch(s_old: &SsState, batch: &[SsUpdate]) -> (SsState, Vec<SsRow>) {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    assert_eq!(batch.len(), m);
    let b = build_ss(s_old, batch);
    let residual: Vec<SsRow> = b.g_sorted[..m].to_vec();
    let s_new: Vec<SsRow> = b.g_sorted[m..m + cap].to_vec();
    (SsState { rows: s_new, params: s_old.params }, residual)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SsParams {
        SsParams { capacity: 4, batch: 4 }
    }

    #[test]
    fn group_then_topk_keeps_heaviest() {
        let s0 = SsState::empty(params());
        // key 7 appears 3× (counts 5+2+1=8), key 11 once (3), key 9 once (1).
        let batch = vec![
            SsUpdate::real(7, 5),
            SsUpdate::real(11, 3),
            SsUpdate::real(7, 2),
            SsUpdate::real(7, 1),
        ];
        let (s1, _residual) = apply_batch(&s0, &batch);
        assert_eq!(s1.frequency(7), 8, "key 7 grouped to 8");
        assert_eq!(s1.frequency(11), 3);
        assert_eq!(s1.active_count(), 2);
        // Mass conserved: 8 + 3 = 5+3+2+1.
        assert_eq!(s1.total_mass(), 11);
    }

    #[test]
    fn commit_changes_with_state() {
        let s0 = SsState::empty(params());
        let (s1, _) = apply_batch(&s0, &[SsUpdate::real(1, 1), SsUpdate::dummy(), SsUpdate::dummy(), SsUpdate::dummy()]);
        assert_ne!(s0.commit(), s1.commit());
    }
}
