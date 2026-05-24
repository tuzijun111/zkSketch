//! Poseidon2-backed `StateCommit` for the plaintext Greenwald-Khanna sketch.
//!
//! Hashes the flattened `(value, count, max_error)` tuples row-by-row.
//! `3 * capacity` Vals total. With `capacity % 4 == 0` (enforced by
//! `GKParams::new`), `3 * capacity` is a multiple of 4 = `CELL_ALIGNMENT`.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::commitment::StateCommit;
use crate::config::{MyHash, Val, make_perm};
use crate::sketch::greenwald_khanna::{GK, GKState};

pub const DIGEST_W: usize = 8;
pub const CELL_ALIGNMENT: usize = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKCommit(pub [Val; DIGEST_W]);

impl AsRef<[Val]> for GKCommit {
    fn as_ref(&self) -> &[Val] {
        &self.0
    }
}

pub fn commit_gk(state: &GKState) -> GKCommit {
    let total = 3 * state.params.capacity;
    assert!(
        total % CELL_ALIGNMENT == 0,
        "GK state has {} flat elements (3 * capacity), not a multiple of {}",
        total,
        CELL_ALIGNMENT
    );
    let hasher = MyHash::new(make_perm());
    let flat = state.tuples.iter().flat_map(|t| {
        [
            Val::from_u32(t.value),
            Val::from_u32(t.count),
            Val::from_u32(t.max_error),
        ]
    });
    let digest: [Val; DIGEST_W] = hasher.hash_iter(flat);
    GKCommit(digest)
}

impl StateCommit for GK {
    type State = GKState;
    type Commit = GKCommit;

    fn commit(state: &Self::State) -> Self::Commit {
        commit_gk(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::Sketch;
    use crate::sketch::greenwald_khanna::{GK, GKParams, GKUpdate};

    fn sample_state() -> GKState {
        let mut s = GK::new(&GKParams { capacity: 4 });
        for v in [3u32, 7, 1, 5] {
            GK::update(&mut s, &GKUpdate { value: v });
        }
        s
    }

    #[test]
    fn commit_is_deterministic() {
        let s = sample_state();
        assert_eq!(
            <GK as StateCommit>::commit(&s),
            <GK as StateCommit>::commit(&s)
        );
    }

    #[test]
    fn commit_distinguishes_states() {
        let s1 = sample_state();
        let mut s2 = s1.clone();
        s2.tuples[0].count = s2.tuples[0].count.wrapping_add(1);
        assert_ne!(
            <GK as StateCommit>::commit(&s1),
            <GK as StateCommit>::commit(&s2)
        );
    }

    #[test]
    fn commit_matches_make_perm() {
        let s = sample_state();
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = s
            .tuples
            .iter()
            .flat_map(|t| [
                Val::from_u32(t.value),
                Val::from_u32(t.count),
                Val::from_u32(t.max_error),
            ])
            .collect();
        let expected: [Val; DIGEST_W] = hasher.hash_iter(flat);
        let actual = <GK as StateCommit>::commit(&s);
        assert_eq!(actual.0, expected);
    }
}
