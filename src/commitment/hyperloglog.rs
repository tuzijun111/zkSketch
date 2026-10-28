//! Poseidon2 `StateCommit` for the plaintext HyperLogLog sketch (the `m = 2^b` registers).

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::commitment::StateCommit;
use crate::config::{MyHash, Val, make_perm};
use crate::sketch::hyperloglog::{HyperLogLog, HyperLogLogState};

/// Width of the commitment, in BabyBear field elements. Matches the leaf
/// STARK's `MyHash` digest size and the in-circuit `add_hash_slice` output.
pub const DIGEST_W: usize = 8;

/// Required alignment of the flattened register count: BabyBear elements per
/// Challenge extension field element. `HyperLogLogParams::new` enforces
/// `b ≥ 2` so `m = 2^b` is always a multiple of 4.
pub const CELL_ALIGNMENT: usize = 4;

/// Fixed-width HyperLogLog commitment. Wraps `[Val; DIGEST_W]` so it
/// satisfies `StateCommit::Commit`'s `Copy + Clone + Eq + AsRef<[Val]>` bounds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HyperLogLogCommit(pub [Val; DIGEST_W]);

impl AsRef<[Val]> for HyperLogLogCommit {
    fn as_ref(&self) -> &[Val] {
        &self.0
    }
}

/// Compute the HyperLogLog commitment by hashing the register array via the
/// canonical `MyHash` (rate 8 / width 16 / digest 8 over `make_perm`).
/// Pure function — no hidden state, no RNG.
pub fn commit_hll(state: &HyperLogLogState) -> HyperLogLogCommit {
    let m = state.params.m();
    assert!(
        m % CELL_ALIGNMENT == 0,
        "HyperLogLog state has {} registers, not a multiple of {}; the \
         in-circuit hash uses Challenge extension-degree packing, which \
         requires this alignment. `HyperLogLogParams::new` enforces b ≥ 2 \
         so this should never trigger in practice.",
        m,
        CELL_ALIGNMENT
    );
    let hasher = MyHash::new(make_perm());
    let flat = state.registers.iter().map(|&r| Val::from_u32(r as u32));
    let digest: [Val; DIGEST_W] = hasher.hash_iter(flat);
    HyperLogLogCommit(digest)
}

impl StateCommit for HyperLogLog {
    type State = HyperLogLogState;
    type Commit = HyperLogLogCommit;

    fn commit(state: &Self::State) -> Self::Commit {
        commit_hll(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::Sketch;
    use crate::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogUpdate};

    fn sample_state() -> HyperLogLogState {
        let mut s = HyperLogLog::new(&HyperLogLogParams { b: 3 }); // m = 8
        for i in 0..7u64 {
            HyperLogLog::update(&mut s, &HyperLogLogUpdate { key: i.wrapping_mul(0xDEAD_BEEF) });
        }
        s
    }

    #[test]
    fn commit_is_deterministic() {
        let s = sample_state();
        let c1 = <HyperLogLog as StateCommit>::commit(&s);
        let c2 = <HyperLogLog as StateCommit>::commit(&s);
        assert_eq!(c1, c2);
    }

    /// Flipping any single register must change the commitment.
    #[test]
    fn commit_distinguishes_states() {
        let s1 = sample_state();
        let c1 = <HyperLogLog as StateCommit>::commit(&s1);

        let mut s2 = s1.clone();
        s2.registers[2] = s2.registers[2].wrapping_add(1);
        let c2 = <HyperLogLog as StateCommit>::commit(&s2);

        assert_ne!(c1, c2);
    }

    /// Defensive drift guard: the commit must be computable by
    /// `MyHash::new(make_perm()).hash_iter(...)` directly — i.e., the
    /// leaf STARK's hash. If `commit_hll` ever diverges (e.g., adds framing,
    /// changes the field embedding), this fires immediately.
    #[test]
    fn commit_matches_make_perm() {
        let s = sample_state();
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = s.registers.iter().map(|&r| Val::from_u32(r as u32)).collect();
        let expected: [Val; DIGEST_W] = hasher.hash_iter(flat);
        let actual = <HyperLogLog as StateCommit>::commit(&s);
        assert_eq!(actual.0, expected);
    }
}
