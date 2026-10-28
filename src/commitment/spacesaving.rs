//! Poseidon2 `StateCommit` for the plaintext SpaceSaving sketch.
//! Keys are hashed as one field element (mod p), so test keys stay below 2^30.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::commitment::StateCommit;
use crate::config::{MyHash, Val, make_perm};
use crate::sketch::spacesaving::{SpaceSaving, SpaceSavingState};

pub const DIGEST_W: usize = 8;

pub const CELL_ALIGNMENT: usize = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpaceSavingCommit(pub [Val; DIGEST_W]);

impl AsRef<[Val]> for SpaceSavingCommit {
    fn as_ref(&self) -> &[Val] {
        &self.0
    }
}

/// Compute the SpaceSaving commitment by hashing the flattened `(key,
/// count)` pairs in row order. `SpaceSavingParams::new` enforces
/// `capacity_s % 2 == 0` so `2 * capacity_s` is aligned to 4.
pub fn commit_spacesaving(state: &SpaceSavingState) -> SpaceSavingCommit {
    let total = 2 * state.params.capacity_s;
    assert!(
        total % CELL_ALIGNMENT == 0,
        "SpaceSaving state has {} flat elements (2 * capacity_s), not a multiple of {}",
        total,
        CELL_ALIGNMENT
    );
    let hasher = MyHash::new(make_perm());
    let flat = state.rows.iter().flat_map(|&(k, c)| {
        [Val::from_u64(k), Val::from_u32(c)]
    });
    let digest: [Val; DIGEST_W] = hasher.hash_iter(flat);
    SpaceSavingCommit(digest)
}

impl StateCommit for SpaceSaving {
    type State = SpaceSavingState;
    type Commit = SpaceSavingCommit;

    fn commit(state: &Self::State) -> Self::Commit {
        commit_spacesaving(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::Sketch;
    use crate::sketch::spacesaving::{SpaceSaving, SpaceSavingParams, SpaceSavingUpdate};

    fn sample_state() -> SpaceSavingState {
        let mut s = SpaceSaving::new(&SpaceSavingParams { capacity_s: 4 });
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 1, value: 5 });
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 2, value: 7 });
        SpaceSaving::update(&mut s, &SpaceSavingUpdate { key: 1, value: 3 });
        s
    }

    #[test]
    fn commit_is_deterministic() {
        let s = sample_state();
        assert_eq!(
            <SpaceSaving as StateCommit>::commit(&s),
            <SpaceSaving as StateCommit>::commit(&s)
        );
    }

    #[test]
    fn commit_distinguishes_states() {
        let s1 = sample_state();
        let mut s2 = s1.clone();
        s2.rows[0].1 = s2.rows[0].1.wrapping_add(1);
        assert_ne!(
            <SpaceSaving as StateCommit>::commit(&s1),
            <SpaceSaving as StateCommit>::commit(&s2)
        );
    }

    #[test]
    fn commit_matches_make_perm() {
        let s = sample_state();
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = s
            .rows
            .iter()
            .flat_map(|&(k, c)| [Val::from_u64(k), Val::from_u32(c)])
            .collect();
        let expected: [Val; DIGEST_W] = hasher.hash_iter(flat);
        let actual = <SpaceSaving as StateCommit>::commit(&s);
        assert_eq!(actual.0, expected);
    }
}
