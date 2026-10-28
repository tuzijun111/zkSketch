//! Chain digests: leaf `H[j,j] = H('LEAF', j, D_j, Com(B_j), Com(S_{j-1}), Com(S_j))`,
//! merge `H[i,j] = H('MRGE', i, m, j, H[i,m], H[m+1,j])`.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::{CryptographicHasher, Permutation};

use crate::config::{MyHash, Perm, Val, make_perm};

/// Width of the digest, in BabyBear field elements.
///
/// Chosen so that `combine_digest` fits in one Poseidon2 permutation:
/// `1 (tag) + 3 (i, m, j) + 4 (left) + 4 (right) = 12 ≤ 16`.
pub const DIGEST_WIDTH: usize = 4;

pub type ChainDigest = [Val; DIGEST_WIDTH];

/// Width of a state / batch commitment, in BabyBear field elements.
pub const COMMIT_WIDTH: usize = 8;

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

/// Canonical leaf digest `H[j,j]`: binds the epoch index, the range
/// descriptor, the batch commitment, and both boundary state commitments at
/// full width. The input exceeds one permutation, so it runs through the
/// variable-length sponge (the same construction
/// `framework::epoch_leaf_digest` has always used; that function now
/// delegates here).
pub fn leaf_digest(
    index: u64,
    descriptor: u64,
    batch_commit: &[Val; COMMIT_WIDTH],
    com_before: &[Val; COMMIT_WIDTH],
    com_after: &[Val; COMMIT_WIDTH],
) -> ChainDigest {
    let hasher = MyHash::new(make_perm());
    let mut input: Vec<Val> = Vec::with_capacity(3 + 3 * COMMIT_WIDTH);
    input.push(Val::from_u64(0x4C45_4146)); // ASCII 'LEAF'
    input.push(Val::from_u64(index));
    input.push(Val::from_u64(descriptor));
    input.extend_from_slice(batch_commit);
    input.extend_from_slice(com_before);
    input.extend_from_slice(com_after);
    let full: [Val; 8] = hasher.hash_iter(input);
    let mut out = [Val::ZERO; DIGEST_WIDTH];
    out.copy_from_slice(&full[..DIGEST_WIDTH]);
    out
}

/// Boundary-only leaf digest for ablation and demo composition paths whose
/// leaf statement carries no batch commitment (per-record replay baselines,
/// toy chains, the fib scaffold). Same layout as [`leaf_digest`] with a
/// zeroed batch slot and `descriptor = index`; a zero slot cannot alias a
/// real Poseidon2 batch commitment, so these digests stay domain-separated
/// from batch-carrying leaves. NOT the framework digest — the deployed
/// engine binds the real batch commitment.
pub fn boundary_leaf_digest(
    com_before: &[Val; COMMIT_WIDTH],
    com_after: &[Val; COMMIT_WIDTH],
    index: u64,
) -> ChainDigest {
    leaf_digest(index, index, &[Val::ZERO; COMMIT_WIDTH], com_before, com_after)
}

/// Zero-pad a 2-element demo boundary (the fib scaffold's `{a, b}`) to the
/// full commitment width the digest functions take.
pub fn pad_boundary2(a: Val, b: Val) -> [Val; COMMIT_WIDTH] {
    let mut out = [Val::ZERO; COMMIT_WIDTH];
    out[0] = a;
    out[1] = b;
    out
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

    fn com(seed: u64) -> [Val; COMMIT_WIDTH] {
        std::array::from_fn(|i| Val::from_u64(seed.wrapping_add(i as u64)))
    }

    #[test]
    fn leaf_digest_is_deterministic() {
        let d1 = leaf_digest(1, 1, &com(7), &com(0), &com(610));
        let d2 = leaf_digest(1, 1, &com(7), &com(0), &com(610));
        assert_eq!(d1, d2, "same inputs must yield same digest");
    }

    #[test]
    fn leaf_digest_separates_distinct_inputs() {
        let d1 = leaf_digest(1, 1, &com(7), &com(0), &com(610));
        let d2 = leaf_digest(2, 2, &com(7), &com(0), &com(610));
        assert_ne!(d1, d2, "different indices must yield different digests");
    }

    #[test]
    fn leaf_digest_binds_batch_commitment() {
        let d1 = leaf_digest(1, 1, &com(7), &com(0), &com(610));
        let d2 = leaf_digest(1, 1, &com(8), &com(0), &com(610));
        assert_ne!(d1, d2, "a substituted batch commitment must change the digest");
    }

    #[test]
    fn boundary_leaf_digest_cannot_alias_batch_leaf() {
        let d1 = boundary_leaf_digest(&com(0), &com(610), 1);
        let d2 = leaf_digest(1, 1, &com(7), &com(0), &com(610));
        assert_ne!(d1, d2, "zero batch slot must not collide with a real batch commit");
    }

    #[test]
    fn combine_digest_orders_children() {
        let dl = leaf_digest(1, 1, &com(7), &com(0), &com(610));
        let dr = leaf_digest(2, 2, &com(9), &com(610), &com(987));
        let parent_lr = combine_digest(1, 1, 2, &dl, &dr);
        let parent_rl = combine_digest(1, 1, 2, &dr, &dl);
        assert_ne!(parent_lr, parent_rl, "child order must be bound by the digest");
    }
}
