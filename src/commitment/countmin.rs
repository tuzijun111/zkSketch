//! Poseidon2-backed `StateCommit` for the plaintext Count-Min sketch.
//!
//! The Count-Min state is a `d × w` matrix of `u32` counters. We hash the
//! flattened row-major counters via the canonical `MyHash` (the leaf STARK's
//! `PaddingFreeSponge<Perm, 16, 8, 8>`). That hasher and the in-circuit
//! `CircuitBuilder::add_hash_slice` over the Challenge extension field agree
//! on aligned inputs — inputs whose count is a multiple of the challenge
//! extension degree `D = 4`. The Count-Min update AIR
//! (`crate::recursion::recursive::countmin_leaf`) absorbs the same cells
//! in-circuit and reproduces the same digest, so the commit chains across
//! the §4.2 recursive merge boundary.
//!
//! Phase 2 demos use `(d, w) = (2, 4)` so `d * w = 8` is aligned.
//! Wider profiles need explicit zero padding to the next multiple of 4 —
//! the assertion in `commit_countmin` catches misuses early.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::commitment::StateCommit;
use crate::config::{MyHash, Val, make_perm};
use crate::sketch::countmin::{CountMin, CountMinState};

/// Width of the commitment, in BabyBear field elements. Matches the leaf
/// STARK's `MyHash` digest size and the in-circuit `add_hash_slice` output.
pub const DIGEST_W: usize = 8;

/// Required alignment of the flattened cell count: BabyBear elements per
/// Challenge extension field element. Inputs whose length isn't a multiple
/// of this would diverge between the native `PaddingFreeSponge` and the
/// circuit's `add_hash_slice` (see the `test_hash_non_aligned` discussion
/// in `Plonky3-recursion/circuit/src/ops/hash.rs`).
pub const CELL_ALIGNMENT: usize = 4;

/// Fixed-width Count-Min commitment. Wraps `[Val; DIGEST_W]` so it satisfies
/// `StateCommit::Commit`'s `Copy + Clone + Eq + AsRef<[Val]>` bounds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CountMinCommit(pub [Val; DIGEST_W]);

impl AsRef<[Val]> for CountMinCommit {
    fn as_ref(&self) -> &[Val] {
        &self.0
    }
}

/// Compute the Count-Min commitment by hashing the row-major flattened
/// counters with the canonical `MyHash` (rate 8 / width 16 / digest 8 over
/// `make_perm`). Pure function — no hidden state, no RNG.
pub fn commit_countmin(state: &CountMinState) -> CountMinCommit {
    let total = state.params.d * state.params.w;
    assert!(
        total % CELL_ALIGNMENT == 0,
        "Count-Min state has {} cells, not a multiple of {}; the in-circuit \
         hash uses Challenge extension-degree packing, which requires this \
         alignment. Phase 2 fixes (d, w) = (2, 4) to satisfy it; wider \
         profiles need explicit zero padding.",
        total,
        CELL_ALIGNMENT
    );
    let hasher = MyHash::new(make_perm());
    let flat = state
        .counters
        .iter()
        .flatten()
        .map(|&c| Val::from_u32(c));
    let digest: [Val; DIGEST_W] = hasher.hash_iter(flat);
    CountMinCommit(digest)
}

impl StateCommit for CountMin {
    type State = CountMinState;
    type Commit = CountMinCommit;

    fn commit(state: &Self::State) -> Self::Commit {
        commit_countmin(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};

    fn sample_state() -> CountMinState {
        let mut s = CountMin::new(&CountMinParams { d: 2, w: 4 });
        for i in 0..3u64 {
            CountMin::update(&mut s, &CountMinUpdate { key: i.wrapping_mul(0xDEAD), value: 1 + (i as u32) });
        }
        s
    }

    #[test]
    fn commit_is_deterministic() {
        let s = sample_state();
        let c1 = <CountMin as StateCommit>::commit(&s);
        let c2 = <CountMin as StateCommit>::commit(&s);
        assert_eq!(c1, c2);
    }

    /// Flipping any single counter must change the commitment.
    #[test]
    fn commit_distinguishes_states() {
        let s1 = sample_state();
        let c1 = <CountMin as StateCommit>::commit(&s1);

        let mut s2 = s1.clone();
        s2.counters[1][2] = s2.counters[1][2].wrapping_add(1);
        let c2 = <CountMin as StateCommit>::commit(&s2);

        assert_ne!(c1, c2);
    }

    /// Defensive: the commit must be computable by `MyHash::new(make_perm()).
    /// hash_iter(...)` directly — i.e., the leaf STARK's hash. If
    /// `commit_countmin` ever diverges (e.g., adds framing back), this
    /// fires immediately.
    #[test]
    fn commit_matches_make_perm() {
        let s = sample_state();
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = s.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
        let expected: [Val; DIGEST_W] = hasher.hash_iter(flat);
        let actual = <CountMin as StateCommit>::commit(&s);
        assert_eq!(actual.0, expected);
    }
}
