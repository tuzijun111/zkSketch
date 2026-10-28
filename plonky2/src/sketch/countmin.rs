//! Plaintext Count-Min sketch; the commitment is Poseidon over the row-major counters.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

use crate::commitment::commit;
use crate::config::F;
use crate::sketch::{DeltaCert, Sketch};

/// Fixed per-row hash multipliers (odd 64-bit constants).
const HASH_PRIMES: [u64; 16] = [
    0x9E37_79B9_7F4A_7C15,
    0xC2B2_AE3D_27D4_EB4F,
    0x1656_67B1_9E37_79F9,
    0xD6E8_FEB8_6659_FD93,
    0xA0761D6478BD642F,
    0xE7037ED1A0B428DB,
    0x8EBC6AF09C88C6E3,
    0x5899_65CB_7174_8B01,
    0xBF58476D1CE4E5B9,
    0x94D0_49BB_1331_11EB,
    0x2545F4914F6CDD1D,
    0xFF51_AFD7_ED55_8CCD,
    0xC4CE_B9FE_1A85_EC53,
    0x1234_5678_9ABC_DEF1,
    0xDEAD_BEEF_CAFE_BABE,
    0xF00D_FACE_1357_9BDF,
];

/// Fixed per-row XOR offsets.
const HASH_OFFSETS: [u64; 16] = [
    0xDEAD_BEEF_DEAD_BEEF,
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0xA5A5_A5A5_A5A5_A5A5,
    0x5A5A_5A5A_5A5A_5A5A,
    0xCAFE_BABE_CAFE_BABE,
    0x1357_9BDF_2468_ACE0,
    0x0F0F_0F0F_0F0F_0F0F,
    0xF0F0_F0F0_F0F0_F0F0,
    0xAAAA_5555_AAAA_5555,
    0x3333_CCCC_3333_CCCC,
    0x7777_8888_7777_8888,
    0x9999_6666_9999_6666,
    0xBBBB_4444_BBBB_4444,
    0xDDDD_2222_DDDD_2222,
    0xEEEE_1111_EEEE_1111,
];

/// Map a key to its column in row `row` (mirrors the original `hash_cell`).
pub fn hash_cell(row: usize, key: u64, w: usize) -> usize {
    let mixed = key.wrapping_mul(HASH_PRIMES[row]) ^ HASH_OFFSETS[row];
    (mixed % w as u64) as usize
}

/// Native Count-Min **batch commitment** `C_B` (paper §5.2): binds the raw
/// `(key, value)` records, interleaved, under Poseidon — the off-circuit twin of
/// the in-circuit `batch_commit` in [`crate::leaf::countmin_final`]
/// (`Poseidon(key0, val0, key1, val1, …)`). A prover cannot insert, drop, or
/// reorder records without breaking this binding. Port of
/// `../src/commitment/countmin_batch.rs::commit_batch` (Goldilocks-native: each
/// `key` is a single field element, so no `key_lo`/`key_hi` split).
pub fn commit_batch(records: &[CountMinUpdate]) -> HashOut<F> {
    let mut pre = Vec::with_capacity(2 * records.len());
    for r in records {
        pre.push(F::from_canonical_u64(r.key));
        pre.push(F::from_canonical_u64(r.value));
    }
    commit(&pre)
}

/// Count-Min shape: `d` rows × `w` columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountMinParams {
    pub d: usize,
    pub w: usize,
}

/// One streamed record: increment `key`'s cells by `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountMinUpdate {
    pub key: u64,
    pub value: u64,
}

/// A `d × w` counter matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountMinState {
    pub counters: Vec<Vec<u64>>,
    pub d: usize,
    pub w: usize,
}

/// Per-batch delta certificate — Pattern A linear (paper §5.3): for each touched
/// cell `(row, col)`, the additive contribution this batch applies. Stored as a
/// sorted `((row, col), delta)` list so equality is order-independent. Port of
/// `../src/sketch/countmin.rs::CountMinDelta` (u32 → u64 over Goldilocks).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountMinDelta {
    pub touched: Vec<((usize, usize), u64)>,
}

impl CountMinState {
    pub fn new(p: &CountMinParams) -> Self {
        Self { counters: vec![vec![0u64; p.w]; p.d], d: p.d, w: p.w }
    }

    /// Apply one record: bump exactly `d` cells (one per row).
    pub fn update(&mut self, u: &CountMinUpdate) {
        for row in 0..self.d {
            let col = hash_cell(row, u.key, self.w);
            self.counters[row][col] = self.counters[row][col].saturating_add(u.value);
        }
    }

    /// Row-major flattened counters as field elements (the commit pre-image).
    pub fn cells(&self) -> Vec<F> {
        self.counters.iter().flatten().map(|&c| F::from_canonical_u64(c)).collect()
    }

    /// Poseidon commitment of the state.
    pub fn commit(&self) -> HashOut<F> {
        commit(&self.cells())
    }

    /// Point query — the Count-Min estimate for `key` (min over rows), an upper
    /// bound on the true frequency (classical Count-Min). Mirrors
    /// `../src/sketch/countmin.rs::CountMin::query`.
    pub fn query(&self, key: u64) -> u64 {
        (0..self.d)
            .map(|row| self.counters[row][hash_cell(row, key, self.w)])
            .min()
            .unwrap_or(0)
    }

    /// Build the Pattern-A delta certificate for `batch` against this state's
    /// shape: the sorted per-cell additive contributions. Depends only on the
    /// `(d, w)` hash profile, not on the current counter values.
    pub fn build_delta(&self, batch: &[CountMinUpdate]) -> CountMinDelta {
        let mut touched: Vec<((usize, usize), u64)> = Vec::new();
        for u in batch {
            for row in 0..self.d {
                let col = hash_cell(row, u.key, self.w);
                match touched.iter_mut().find(|(k, _)| *k == (row, col)) {
                    Some(entry) => entry.1 = entry.1.saturating_add(u.value),
                    None => touched.push(((row, col), u.value)),
                }
            }
        }
        touched.sort_by_key(|&((row, col), _)| (row, col));
        CountMinDelta { touched }
    }

    /// Apply a previously-computed delta. `apply_delta(build_delta(batch))`
    /// equals replaying the batch via [`update`](Self::update) — the §5.3
    /// Pattern-A linear invariant.
    pub fn apply_delta(&mut self, delta: &CountMinDelta) {
        for &((row, col), v) in &delta.touched {
            self.counters[row][col] = self.counters[row][col].saturating_add(v);
        }
    }
}

/// Zero-sized marker implementing the [`Sketch`]/[`DeltaCert`] traits over
/// [`CountMinState`], mirroring `../src/sketch/countmin.rs::CountMin`. The
/// inherent methods above remain the primary API; this just wires Count-Min into
/// the generic sketch-family abstraction.
pub struct CountMin;

impl Sketch for CountMin {
    type Params = CountMinParams;
    type State = CountMinState;
    type Update = CountMinUpdate;

    fn new(params: &Self::Params) -> Self::State {
        CountMinState::new(params)
    }
    fn update(state: &mut Self::State, u: &Self::Update) {
        state.update(u)
    }
}

impl DeltaCert for CountMin {
    type Delta = CountMinDelta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta {
        prev.build_delta(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_increments_d_cells() {
        let mut s = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        s.update(&CountMinUpdate { key: 7, value: 3 });
        let total: u64 = s.counters.iter().flatten().sum();
        assert_eq!(total, 2 * 3); // d=2 cells each +3
    }

    #[test]
    fn commit_changes_with_state() {
        let s0 = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        let mut s1 = s0.clone();
        s1.update(&CountMinUpdate { key: 1, value: 1 });
        assert_ne!(s0.commit(), s1.commit());
        assert_eq!(s0.commit(), CountMinState::new(&CountMinParams { d: 2, w: 4 }).commit());
    }

    /// Classical Count-Min upper bound: the query never under-counts, and with a
    /// wide sketch and few distinct keys the bound is tight (no collisions).
    #[test]
    fn point_query_upper_bounds_true_count() {
        let mut s = CountMinState::new(&CountMinParams { d: 3, w: 256 });
        let stream = [(10u64, 1u64), (10, 1), (10, 1), (10, 1), (20, 5), (20, 5), (999, 2)];
        let mut truth = std::collections::HashMap::<u64, u64>::new();
        for &(k, v) in &stream {
            *truth.entry(k).or_insert(0) += v;
            s.update(&CountMinUpdate { key: k, value: v });
        }
        for (&k, &t) in &truth {
            let est = s.query(k);
            assert!(est >= t, "query({k}) = {est} but true count = {t}");
            assert_eq!(est, t, "query({k}) over-counted by {}", est - t);
        }
    }

    /// §5.3 Pattern-A linear invariant: replaying a batch one-by-one equals
    /// applying the aggregated delta to the same starting state.
    #[test]
    fn delta_aggregates_batch() {
        let p = CountMinParams { d: 4, w: 16 };
        let initial = CountMinState::new(&p);
        let batch: Vec<CountMinUpdate> = (0..32)
            .map(|i| CountMinUpdate { key: (i % 6) as u64, value: 1 + (i as u64 % 3) })
            .collect();

        let mut by_replay = initial.clone();
        for u in &batch {
            by_replay.update(u);
        }

        let delta = initial.build_delta(&batch);
        let mut by_delta = initial.clone();
        by_delta.apply_delta(&delta);

        assert_eq!(by_replay, by_delta);
        assert!(delta.touched.len() <= p.d * batch.len());
    }

    /// The batch commitment is deterministic and binds key, value, and order.
    #[test]
    fn batch_commit_binds_records() {
        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 42, value: 1 },
        ];
        assert_eq!(commit_batch(&b1), commit_batch(&b1));

        let mut by_key = b1.clone();
        by_key[1].key += 1;
        assert_ne!(commit_batch(&b1), commit_batch(&by_key));

        let mut by_val = b1.clone();
        by_val[0].value += 1;
        assert_ne!(commit_batch(&b1), commit_batch(&by_val));

        let mut by_order = b1.clone();
        by_order.swap(0, 2);
        assert_ne!(commit_batch(&b1), commit_batch(&by_order));
    }
}
