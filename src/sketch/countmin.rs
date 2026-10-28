//! Plaintext Count-Min sketch with a fixed public hash profile.

use crate::sketch::{DeltaCert, Sketch};

/// Public Count-Min parameters: depth `d` and width `w`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CountMinParams {
    pub d: usize,
    pub w: usize,
}

/// Plaintext Count-Min state: a `d`-by-`w` matrix of counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountMinState {
    pub counters: Vec<Vec<u32>>,
    pub params: CountMinParams,
}

/// One record to fold into the sketch: `(key, value)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CountMinUpdate {
    pub key: u64,
    pub value: u32,
}

/// Per-batch delta certificate — Pattern A linear (paper §5.3): for each
/// touched cell `(row, col)`, the additive contribution this batch applies.
///
/// Stored as a sorted list of `((row, col), delta)` pairs so equality is
/// well-defined regardless of the order in which records were folded in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountMinDelta {
    pub touched: Vec<((usize, usize), u32)>,
}

pub struct CountMin;

/// Hash-family seeds, one per row. The primes are odd and pairwise distinct.
/// Sixteen entries — `CountMin` panics during `new` if `params.d > 16`, which
/// matches every regime the paper exercises in its evaluation (paper §6: `d`
/// up to 16). Add more entries here when wider profiles are needed.
const HASH_PRIMES: [u64; 16] = [
    0x9E37_79B9_7F4A_7C15, // 1
    0xBF58_476D_1CE4_E5B9, // 2
    0x94D0_49BB_1331_11EB, // 3
    0x2545_F491_4F6C_DD1D, // 4
    0xD801_2304_5687_AB13, // 5
    0xC2B2_AE3D_27D4_EB4F, // 6
    0xCBF2_9CE4_8422_2325, // 7
    0xC6BC_2796_8F2A_3D63, // 8
    0xA243_F605_BAA8_77D3, // 9
    0xB492_6F95_E4A5_C3C7, // 10
    0x82C1_2F3C_A05F_E791, // 11
    0xF1BB_CDCB_FA5E_E97D, // 12
    0xD632_2D0C_5B53_5AE1, // 13
    0x8E4F_47AB_3041_2C25, // 14
    0xA537_82B0_C923_DBDB, // 15
    0xE369_15A1_4B62_7CC9, // 16
];

const HASH_OFFSETS: [u64; 16] = [
    0xDEAD_BEEF_DEAD_BEEF,
    0xCAFE_BABE_CAFE_BABE,
    0xFEED_FACE_FEED_FACE,
    0xBAAA_AAAD_BAAA_AAAD,
    0xABAD_CAFE_ABAD_CAFE,
    0xDEFE_C8ED_DEFE_C8ED,
    0xD15E_A5E_D_15EA_5E_D,
    0xBADD_F00D_BADD_F00D,
    0xFACE_FEED_FACE_FEED,
    0xCAFE_D00D_CAFE_D00D,
    0x1234_5678_9ABC_DEF0,
    0x0FED_CBA9_8765_4321,
    0xAAAA_AAAA_5555_5555,
    0x5555_5555_AAAA_AAAA,
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
];

/// Compute the cell column for `(row, key)` under the public hash profile.
///
/// The profile is intentionally simple: one wrapping multiply, one xor, one
/// modulo. Cheap to recompute inside the eventual Count-Min update circuit.
pub fn hash_cell(row: usize, key: u64, w: usize) -> usize {
    assert!(row < HASH_PRIMES.len(), "row {row} exceeds the built-in hash profile width");
    assert!(w > 0, "width w must be positive");
    let mixed = key.wrapping_mul(HASH_PRIMES[row]) ^ HASH_OFFSETS[row];
    (mixed as usize) % w
}

impl Sketch for CountMin {
    type Params = CountMinParams;
    type State = CountMinState;
    type Update = CountMinUpdate;

    fn new(params: &Self::Params) -> Self::State {
        assert!(
            params.d <= HASH_PRIMES.len(),
            "Count-Min depth {} exceeds built-in hash profile ({})",
            params.d,
            HASH_PRIMES.len()
        );
        assert!(params.w > 0, "Count-Min width w must be positive");
        Self::State {
            counters: vec![vec![0u32; params.w]; params.d],
            params: *params,
        }
    }

    fn update(state: &mut Self::State, u: &Self::Update) {
        for row in 0..state.params.d {
            let col = hash_cell(row, u.key, state.params.w);
            state.counters[row][col] = state.counters[row][col].saturating_add(u.value);
        }
    }
}

impl CountMin {
    /// Point query — returns the Count-Min estimate for `key`, which is an
    /// upper bound on the true frequency (paper §3.2, classical Count-Min).
    pub fn query(state: &CountMinState, key: u64) -> u32 {
        (0..state.params.d)
            .map(|row| {
                let col = hash_cell(row, key, state.params.w);
                state.counters[row][col]
            })
            .min()
            .unwrap_or(0)
    }

    /// Apply a previously-computed delta to a state. `apply_delta(prev, d)`
    /// must equal `update`-replaying the batch `d` came from — that is the
    /// §5.3 Pattern A linear invariant we exercise in tests.
    pub fn apply_delta(state: &mut CountMinState, delta: &CountMinDelta) {
        for &((row, col), v) in &delta.touched {
            state.counters[row][col] = state.counters[row][col].saturating_add(v);
        }
    }
}

impl DeltaCert for CountMin {
    type Delta = CountMinDelta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta {
        let mut touched: Vec<((usize, usize), u32)> = Vec::new();
        for u in batch {
            for row in 0..prev.params.d {
                let col = hash_cell(row, u.key, prev.params.w);
                match touched.iter_mut().find(|(k, _)| *k == (row, col)) {
                    Some(entry) => entry.1 = entry.1.saturating_add(u.value),
                    None => touched.push(((row, col), u.value)),
                }
            }
        }
        touched.sort_by_key(|&((row, col), _)| (row, col));
        CountMinDelta { touched }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(d: usize, w: usize) -> CountMinParams {
        CountMinParams { d, w }
    }

    /// One update bumps exactly `d` counters (one per row). With these primes
    /// and `w = 8`, the chosen key's row hashes are pairwise distinct, so we
    /// can also assert each touched cell increased by exactly the update
    /// value and every other cell stayed zero.
    #[test]
    fn update_increments_d_cells() {
        let mut s = CountMin::new(&params(4, 8));
        CountMin::update(&mut s, &CountMinUpdate { key: 0x1234_5678_DEAD_BEEF, value: 7 });

        let mut nonzero_cells = 0;
        for row in 0..s.params.d {
            for col in 0..s.params.w {
                if s.counters[row][col] != 0 {
                    nonzero_cells += 1;
                    assert_eq!(s.counters[row][col], 7);
                }
            }
        }
        assert_eq!(nonzero_cells, s.params.d);
    }

    /// Classical Count-Min upper bound: the query never under-counts. With a
    /// large width and a small number of distinct keys, we don't expect
    /// collisions, so the bound should be tight for the inserted key.
    #[test]
    fn point_query_upper_bounds_true_count() {
        let mut s = CountMin::new(&params(3, 256));
        let stream = [
            (10u64, 1u32), (10, 1), (10, 1), (10, 1),  // key 10 → true count 4
            (20, 5), (20, 5),                            // key 20 → true count 10
            (999, 2),                                    // key 999 → true count 2
        ];
        let mut truth = std::collections::HashMap::<u64, u32>::new();
        for &(k, v) in &stream {
            *truth.entry(k).or_insert(0) += v;
            CountMin::update(&mut s, &CountMinUpdate { key: k, value: v });
        }

        for (&k, &t) in &truth {
            let est = CountMin::query(&s, k);
            assert!(est >= t, "query({k}) = {est} but true count = {t}");
            // Width is large enough that we don't expect collisions among
            // these three keys; bound should be tight.
            assert_eq!(est, t, "query({k}) over-counted by {}", est - t);
        }
    }

    /// §5.3 Pattern A linear invariant: per-cell additive deltas commute.
    /// Replaying the batch one-by-one and applying the aggregated delta to
    /// the same starting state should yield the same final state.
    #[test]
    fn delta_aggregates_batch() {
        let p = params(4, 16);
        let initial = CountMin::new(&p);

        // Build a batch with deliberate key reuse so the delta has to merge
        // contributions to the same cells.
        let batch: Vec<CountMinUpdate> = (0..32)
            .map(|i| CountMinUpdate { key: (i % 6) as u64, value: 1 + (i as u32 % 3) })
            .collect();

        let mut by_replay = initial.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }

        let delta = CountMin::build_delta(&initial, &batch);
        let mut by_delta = initial.clone();
        CountMin::apply_delta(&mut by_delta, &delta);

        assert_eq!(by_replay, by_delta);

        // Delta size bound: at most d × |batch| (per-record per-row entries),
        // typically much less after dedup.
        assert!(delta.touched.len() <= p.d * batch.len());
    }
}
