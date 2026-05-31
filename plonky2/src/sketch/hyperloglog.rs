//! Plaintext HyperLogLog sketch (paper §5.3, Pattern A max).
//!
//! Port of `../src/sketch/hyperloglog.rs`. Each register stores the
//! maximum observed leading-run; updates are idempotent and the per-register
//! merge is `max`, so epochs aggregate recursively just like Count-Min.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

use crate::commitment::commit;
use crate::config::F;

const HASH_PRIME: u64 = 0x9E37_79B9_7F4A_7C15;
const HASH_OFFSET: u64 = 0xDEAD_BEEF_C0DE_F00D;

/// Map a key to `(register_index, leading_run)`. `leading_run` is 1-indexed and,
/// for `b >= 2`, fits in [`REGISTER_WIDTH`](crate::leaf::hyperloglog::REGISTER_WIDTH) bits.
pub fn hash_register(b: usize, key: u64) -> (usize, u64) {
    let mixed = key.wrapping_mul(HASH_PRIME) ^ HASH_OFFSET;
    let m = 1u64 << b;
    let idx = (mixed & (m - 1)) as usize;
    let tail = mixed >> b;
    let leading = if tail == 0 {
        (64 - b) as u32
    } else {
        tail.leading_zeros() - b as u32
    };
    (idx, (leading + 1) as u64)
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
}
