//! Plaintext HyperLogLog sketch with a fixed public hash (register index, leading-zero rank).

use crate::sketch::{DeltaCert, Sketch};

/// Public HyperLogLog parameters: `b` is the number of register-index bits;
/// the register count is `m = 2^b`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HyperLogLogParams {
    pub b: usize,
}

impl HyperLogLogParams {
    /// Register count `m = 2^b`.
    pub fn m(&self) -> usize {
        1usize << self.b
    }
}

/// Plaintext HyperLogLog state: an `m`-register array of `u8` leading-run-of-zeros statistics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperLogLogState {
    pub registers: Vec<u8>,
    pub params: HyperLogLogParams,
}

/// One record to fold into the sketch. HyperLogLog is distinct-counting, so
/// only the key matters; we don't carry a `value` field (unlike Count-Min,
/// where the value is the increment).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HyperLogLogUpdate {
    pub key: u64,
}

/// Per-batch delta certificate — Pattern A max (paper §5.3): for each touched
/// register, the maximum leading-run-of-zeros value contributed by this batch.
///
/// Stored as a `(register_idx, max_value)` list sorted by register index so
/// equality is well-defined regardless of input record order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperLogLogDelta {
    pub touched: Vec<(usize, u8)>,
}

pub struct HyperLogLog;

/// Single 64-bit multiplier used to derive both the register index and the
/// leading-run statistic. Choosing one well-mixed prime (odd, large) gives
/// both halves of the output adequate independence for our small `b`.
const HASH_PRIME: u64 = 0x9E37_79B9_7F4A_7C15;

/// XOR mixin paired with `HASH_PRIME`. Same role as `HASH_OFFSETS[0]` in the
/// Count-Min hash family.
const HASH_OFFSET: u64 = 0xDEAD_BEEF_C0DE_F00D;

/// Compute the `(register_idx, leading_run)` pair for the given key under the
/// public hash profile. The leading-run value is HLL-1-indexed (range `[1,
/// 64-b+1]`). Zero-tail (extremely rare) is treated as max leading-run.
pub fn hash_register(b: usize, key: u64) -> (usize, u8) {
    assert!(b >= 2 && b < 32, "HyperLogLog b must be in [2, 32); got {b}");
    let mixed = key.wrapping_mul(HASH_PRIME) ^ HASH_OFFSET;
    let m = 1u64 << b;
    let idx = (mixed & (m - 1)) as usize;
    let tail = mixed >> b;
    let leading = if tail == 0 {
        (64 - b) as u32
    } else {
        // u64::leading_zeros gives 63 - (position of highest set bit).
        // After shifting right by b, the leading zeros include the b bits
        // we shifted out — subtract them to get leading zeros *within* the
        // (64-b)-bit tail window.
        tail.leading_zeros() - (b as u32)
    };
    let lr = (leading + 1) as u8; // 1-indexed per HLL convention
    (idx, lr)
}

impl Sketch for HyperLogLog {
    type Params = HyperLogLogParams;
    type State = HyperLogLogState;
    type Update = HyperLogLogUpdate;

    fn new(params: &Self::Params) -> Self::State {
        assert!(
            params.b >= 2,
            "HyperLogLog b must be ≥ 2 (m ≥ 4) so the state aligns with the \
             Challenge extension degree in the in-circuit hash"
        );
        assert!(
            params.b < 32,
            "HyperLogLog b ≥ 32 not supported (would need m ≥ 2^32 registers)"
        );
        Self::State {
            registers: vec![0u8; params.m()],
            params: *params,
        }
    }

    fn update(state: &mut Self::State, u: &Self::Update) {
        let (idx, lr) = hash_register(state.params.b, u.key);
        if lr > state.registers[idx] {
            state.registers[idx] = lr;
        }
    }
}

impl HyperLogLog {
    /// HyperLogLog distinct-count estimate via the classical harmonic-mean
    /// formula. Bias correction for very small / very large cardinalities is
    /// out of scope here — we only need an estimate for tests / demos.
    pub fn estimate(state: &HyperLogLogState) -> f64 {
        let m = state.params.m() as f64;
        let alpha = match state.params.m() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let z: f64 = state
            .registers
            .iter()
            .map(|&r| 2f64.powi(-(r as i32)))
            .sum();
        alpha * m * m / z
    }

    /// Apply a previously-computed delta to a state. `apply_delta(prev,
    /// build_delta(prev, batch))` must equal `update`-replaying `batch` — the
    /// §5.3 Pattern A max invariant (max is associative-commutative).
    pub fn apply_delta(state: &mut HyperLogLogState, delta: &HyperLogLogDelta) {
        for &(idx, v) in &delta.touched {
            if v > state.registers[idx] {
                state.registers[idx] = v;
            }
        }
    }
}

impl DeltaCert for HyperLogLog {
    type Delta = HyperLogLogDelta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta {
        let mut by_idx: std::collections::BTreeMap<usize, u8> = std::collections::BTreeMap::new();
        let b = prev.params.b;
        for u in batch {
            let (idx, lr) = hash_register(b, u.key);
            let entry = by_idx.entry(idx).or_insert(0);
            if lr > *entry {
                *entry = lr;
            }
        }
        let touched: Vec<(usize, u8)> = by_idx.into_iter().collect();
        HyperLogLogDelta { touched }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(b: usize) -> HyperLogLogParams {
        HyperLogLogParams { b }
    }

    /// One update touches at most one register (and exactly one if the
    /// chosen leading-run statistic strictly exceeds the prior value, which
    /// is true here since the initial state is all zeros and lr ≥ 1).
    #[test]
    fn update_writes_one_register() {
        let mut s = HyperLogLog::new(&params(4)); // m = 16
        let before = s.registers.clone();
        HyperLogLog::update(&mut s, &HyperLogLogUpdate { key: 0xDEAD_BEEF });
        let diff_count = (0..s.params.m())
            .filter(|&i| s.registers[i] != before[i])
            .count();
        assert_eq!(diff_count, 1);
    }

    /// Re-inserting the same key leaves the state unchanged: HLL's register
    /// update is idempotent (max is monotone).
    #[test]
    fn register_max_is_monotone() {
        let mut s = HyperLogLog::new(&params(4));
        let u = HyperLogLogUpdate { key: 0x1234_5678_DEAD_BEEF };
        HyperLogLog::update(&mut s, &u);
        let snapshot = s.clone();
        HyperLogLog::update(&mut s, &u);
        HyperLogLog::update(&mut s, &u);
        assert_eq!(s, snapshot);
    }

    /// §5.3 Pattern A max invariant: per-register max over a batch equals
    /// `update`-replaying the batch. With a deliberate spread of distinct
    /// keys, several registers get touched and the delta has to merge.
    #[test]
    fn delta_aggregates_batch_via_max() {
        let p = params(4); // m = 16
        let initial = HyperLogLog::new(&p);
        let batch: Vec<HyperLogLogUpdate> = (0..64u64)
            .map(|i| HyperLogLogUpdate { key: i.wrapping_mul(0x9E37_79B9) })
            .collect();

        let mut by_replay = initial.clone();
        for u in &batch {
            HyperLogLog::update(&mut by_replay, u);
        }

        let delta = HyperLogLog::build_delta(&initial, &batch);
        let mut by_delta = initial.clone();
        HyperLogLog::apply_delta(&mut by_delta, &delta);

        assert_eq!(by_replay, by_delta);

        // Delta size bound: at most |batch| (one entry per touched register),
        // and at most m (one entry per register).
        assert!(delta.touched.len() <= batch.len());
        assert!(delta.touched.len() <= p.m());
    }

    /// `new` rejects `b < 2`. The leaf-circuit alignment check needs m ≥ 4.
    #[test]
    #[should_panic(expected = "HyperLogLog b must be ≥ 2")]
    fn rejects_b_below_two() {
        let _ = HyperLogLog::new(&HyperLogLogParams { b: 1 });
    }
}
