//! Ordered-update digest helpers.
//!
//! The paper's `H_{[i,j]} = H(i, m, j, H_{[i,m]}, H_{[m+1,j]})` digest binds
//! the membership AND ordering of leaf proofs. Phase 1 implements this with a
//! single Poseidon2 permutation per call (width 16, BabyBear); we use a
//! `DIGEST_WIDTH` of 4 so the inputs (tag + interval ids + left + right) fit
//! in one application of the permutation. Phase 1.5 will move the same
//! schedule inside the recursive merge circuit so the digest is bound to the
//! in-circuit verification.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

use crate::config::{Perm, Val, make_perm};

/// Width of the digest, in BabyBear field elements.
///
/// Chosen so that `combine_digest` fits in one Poseidon2 permutation:
/// `1 (tag) + 3 (i, m, j) + 4 (left) + 4 (right) = 12 ≤ 16`.
pub const DIGEST_WIDTH: usize = 4;

pub type ChainDigest = [Val; DIGEST_WIDTH];

fn perm() -> Perm {
    make_perm()
}

/// Apply the Poseidon2 permutation to a 16-element state and read the first
/// `DIGEST_WIDTH` elements as the output.
fn perm_squeeze(state: [Val; 16]) -> ChainDigest {
    let p = perm();
    let mut s = state;
    p.permute_mut(&mut s);
    let mut out = [Val::ZERO; DIGEST_WIDTH];
    out.copy_from_slice(&s[..DIGEST_WIDTH]);
    out
}

/// Leaf digest: stands in for the paper's `H(C_{B_k})`. We commit the leaf's
/// `(initial, final)` boundary plus a domain-separation tag and the leaf
/// index, so leaves can't alias internal-merge digests and a permutation of
/// leaves would change the result.
pub fn leaf_digest(initial: &[Val; 2], final_: &[Val; 2], index: u64) -> ChainDigest {
    let mut state = [Val::ZERO; 16];
    state[0] = Val::from_u64(0x4C45_4146); // ASCII 'LEAF'
    state[1] = Val::from_u64(index);
    state[2] = initial[0];
    state[3] = initial[1];
    state[4] = final_[0];
    state[5] = final_[1];
    perm_squeeze(state)
}

/// Combine two child digests into a parent digest, binding the interval
/// `[i, j]` and the split point `m`. Mirrors `H_{[i,j]} = H(i, m, j, H_left, H_right)`.
pub fn combine_digest(
    i: u64,
    m: u64,
    j: u64,
    left: &ChainDigest,
    right: &ChainDigest,
) -> ChainDigest {
    let mut state = [Val::ZERO; 16];
    state[0] = Val::from_u64(0x4D52_4745); // ASCII 'MRGE'
    state[1] = Val::from_u64(i);
    state[2] = Val::from_u64(m);
    state[3] = Val::from_u64(j);
    // 4..4+DIGEST_WIDTH = 4..8 — fits.
    state[4..4 + DIGEST_WIDTH].copy_from_slice(left);
    // 8..8+DIGEST_WIDTH = 8..12 — fits.
    state[4 + DIGEST_WIDTH..4 + 2 * DIGEST_WIDTH].copy_from_slice(right);
    perm_squeeze(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_digest_is_deterministic() {
        let d1 = leaf_digest(&[Val::ZERO, Val::ONE], &[Val::from_u64(610), Val::from_u64(987)], 1);
        let d2 = leaf_digest(&[Val::ZERO, Val::ONE], &[Val::from_u64(610), Val::from_u64(987)], 1);
        assert_eq!(d1, d2, "same inputs must yield same digest");
    }

    #[test]
    fn leaf_digest_separates_distinct_inputs() {
        let d1 = leaf_digest(&[Val::ZERO, Val::ONE], &[Val::from_u64(610), Val::from_u64(987)], 1);
        let d2 = leaf_digest(&[Val::ZERO, Val::ONE], &[Val::from_u64(610), Val::from_u64(987)], 2);
        assert_ne!(d1, d2, "different indices must yield different digests");
    }

    #[test]
    fn combine_digest_orders_children() {
        let dl = leaf_digest(&[Val::ZERO, Val::ONE], &[Val::from_u64(610), Val::from_u64(987)], 1);
        let dr = leaf_digest(
            &[Val::from_u64(610), Val::from_u64(987)],
            &[Val::from_u64(1), Val::from_u64(2)],
            2,
        );
        let parent_lr = combine_digest(1, 1, 2, &dl, &dr);
        let parent_rl = combine_digest(1, 1, 2, &dr, &dl);
        assert_ne!(parent_lr, parent_rl, "child order must be bound by the digest");
    }
}
