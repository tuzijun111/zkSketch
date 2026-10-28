//! Plaintext HyperLogLog sketch; register routing uses Poseidon(key) so the leaf circuits can recompute it.

use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::commitment::commit;
use crate::config::F;
use crate::sketch::{DeltaCert, Sketch};

/// Trailing-zero window for the `ρ` (leading-run) derivation. The in-circuit
/// routing in [`crate::leaf::hyperloglog`] re-derives `ρ` over exactly this many
/// low bits of the digest, so this constant MUST match there (native ↔ circuit).
/// `ρ = 1 + tz ∈ [1, RHO_WINDOW+1]`, kept `< 2^REGISTER_WIDTH`.
pub const RHO_WINDOW: usize = 48;

/// Map a key to `(register_index, leading_run)` via a **field-native Poseidon**
/// hash, so the routing is re-derivable in-circuit (matching the plonky3 HLL):
/// `idx = digest[0] mod m` (low `b` bits) and `ρ = 1 + trailing_zeros(digest[1])`
/// over the low [`RHO_WINDOW`] bits. `ρ` is 1-indexed and, for `b >= 2`, fits in
/// [`REGISTER_WIDTH`](crate::leaf::hyperloglog::REGISTER_WIDTH) bits.
pub fn hash_register(b: usize, key: u64) -> (usize, u64) {
    let digest = PoseidonHash::hash_no_pad(&[F::from_canonical_u64(key)]);
    let d0 = digest.elements[0].to_canonical_u64();
    let d1 = digest.elements[1].to_canonical_u64();
    let m = 1u64 << b;
    let idx = (d0 % m) as usize;
    let low = d1 & ((1u64 << RHO_WINDOW) - 1);
    let tz = if low == 0 { RHO_WINDOW as u64 } else { low.trailing_zeros() as u64 };
    (idx, tz + 1)
}

/// HLL shape: `m = 2^b` registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HllParams {
    pub b: usize,
}

impl HllParams {
    pub fn m(&self) -> usize {
        1usize << self.b
    }
}

/// One streamed record (distinct-count insertion).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HllUpdate {
    pub key: u64,
}

/// `m` registers holding max leading-runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HllState {
    pub registers: Vec<u64>,
    pub b: usize,
}

/// Per-batch delta certificate — Pattern A max (paper §5.3): for each touched
/// register, the maximum leading-run contributed by the batch. Sorted by
/// register index so equality is order-independent. Port of
/// `../src/sketch/hyperloglog.rs::HyperLogLogDelta` (u8 → u64 over Goldilocks).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HllDelta {
    pub touched: Vec<(usize, u64)>,
}

impl HllState {
    pub fn new(p: &HllParams) -> Self {
        assert!(p.b >= 2, "b must be >= 2 (m >= 4)");
        Self { registers: vec![0u64; p.m()], b: p.b }
    }

    pub fn m(&self) -> usize {
        1usize << self.b
    }

    /// Apply one record: `registers[idx] = max(registers[idx], leading_run)`.
    pub fn update(&mut self, u: &HllUpdate) {
        let (idx, lr) = hash_register(self.b, u.key);
        if lr > self.registers[idx] {
            self.registers[idx] = lr;
        }
    }

    pub fn cells(&self) -> Vec<F> {
        self.registers.iter().map(|&r| F::from_canonical_u64(r)).collect()
    }

    pub fn commit(&self) -> HashOut<F> {
        commit(&self.cells())
    }

    /// HyperLogLog distinct-count estimate via the classical harmonic-mean
    /// formula (no small/large-range bias correction). Mirrors
    /// `../src/sketch/hyperloglog.rs::HyperLogLog::estimate`.
    pub fn estimate(&self) -> f64 {
        let m = self.m() as f64;
        let alpha = match self.m() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let z: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        alpha * m * m / z
    }

    /// Build the Pattern-A (max) delta certificate for `batch` against this
    /// state's shape: per-register max leading-runs, sorted by register index.
    pub fn build_delta(&self, batch: &[HllUpdate]) -> HllDelta {
        let mut by_idx: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();
        for u in batch {
            let (idx, lr) = hash_register(self.b, u.key);
            let entry = by_idx.entry(idx).or_insert(0);
            if lr > *entry {
                *entry = lr;
            }
        }
        HllDelta { touched: by_idx.into_iter().collect() }
    }

    /// Apply a previously-computed delta. `apply_delta(build_delta(batch))`
    /// equals replaying the batch via [`update`](Self::update) — the §5.3
    /// Pattern-A max invariant (max is associative-commutative).
    pub fn apply_delta(&mut self, delta: &HllDelta) {
        for &(idx, v) in &delta.touched {
            if v > self.registers[idx] {
                self.registers[idx] = v;
            }
        }
    }
}

/// Zero-sized marker implementing the [`Sketch`]/[`DeltaCert`] traits over
/// [`HllState`], mirroring `../src/sketch/hyperloglog.rs::HyperLogLog`.
pub struct HyperLogLog;

impl Sketch for HyperLogLog {
    type Params = HllParams;
    type State = HllState;
    type Update = HllUpdate;

    fn new(params: &Self::Params) -> Self::State {
        HllState::new(params)
    }
    fn update(state: &mut Self::State, u: &Self::Update) {
        state.update(u)
    }
}

impl DeltaCert for HyperLogLog {
    type Delta = HllDelta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta {
        prev.build_delta(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_is_monotone_and_idempotent() {
        let mut s = HllState::new(&HllParams { b: 3 });
        s.update(&HllUpdate { key: 42 });
        let after_one = s.clone();
        s.update(&HllUpdate { key: 42 }); // same key -> no change (max)
        assert_eq!(s, after_one);
        let nonzero = s.registers.iter().filter(|&&r| r > 0).count();
        assert_eq!(nonzero, 1, "one insert touches exactly one register");
    }

    #[test]
    fn commit_changes_with_state() {
        let s0 = HllState::new(&HllParams { b: 3 });
        let mut s1 = s0.clone();
        s1.update(&HllUpdate { key: 7 });
        assert_ne!(s0.commit(), s1.commit());
    }

    /// §5.3 Pattern-A max invariant: per-register max over a batch equals
    /// replaying the batch one-by-one.
    #[test]
    fn delta_aggregates_batch_via_max() {
        let p = HllParams { b: 4 }; // m = 16
        let initial = HllState::new(&p);
        let batch: Vec<HllUpdate> =
            (0..64u64).map(|i| HllUpdate { key: i.wrapping_mul(0x9E37_79B9) }).collect();

        let mut by_replay = initial.clone();
        for u in &batch {
            by_replay.update(u);
        }

        let delta = initial.build_delta(&batch);
        let mut by_delta = initial.clone();
        by_delta.apply_delta(&delta);

        assert_eq!(by_replay, by_delta);
        assert!(delta.touched.len() <= batch.len());
        assert!(delta.touched.len() <= p.m());
    }

    /// The estimate is finite, positive, and grows with more distinct keys.
    #[test]
    fn estimate_is_monotone_in_distinct_keys() {
        let mut few = HllState::new(&HllParams { b: 6 });
        for k in 0..8u64 {
            few.update(&HllUpdate { key: k.wrapping_mul(0x9E37_79B9_7F4A_7C15) });
        }
        let mut many = HllState::new(&HllParams { b: 6 });
        for k in 0..2000u64 {
            many.update(&HllUpdate { key: k.wrapping_mul(0x9E37_79B9_7F4A_7C15) });
        }
        let (e_few, e_many) = (few.estimate(), many.estimate());
        assert!(e_few.is_finite() && e_few > 0.0);
        assert!(e_many > e_few, "estimate should grow: {e_few} !< {e_many}");
    }
}
