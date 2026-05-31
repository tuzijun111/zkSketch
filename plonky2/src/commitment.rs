//! Native (off-circuit) state commitments and the §4.2 boundary digests.
//!
//! The in-circuit equivalents (in [`crate::leaf`]) must reproduce [`commit`]
//! exactly: it is plain Poseidon over the flattened state cells, matching
//! `CircuitBuilder::hash_n_to_hash_no_pad::<PoseidonHash>`.
//!
//! Mirrors `../src/commitment/` (Poseidon2 commit) and
//! `../src/recursion/digest.rs` (leaf / combine digests, paper §4.2).

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::config::F;

/// Poseidon commitment of a flattened sketch state (row-major, no padding).
pub fn commit(cells: &[F]) -> HashOut<F> {
    PoseidonHash::hash_no_pad(cells)
}

// Domain-separation tags (ASCII), matching the spirit of the plonky3 digests.
const TAG_LEAF: u64 = 0x4C45_4146; // "LEAF"
const TAG_MRGE: u64 = 0x4D52_4745; // "MRGE"

/// Leaf digest binding `(initial, final, index)` — paper §4.2.
///
/// Swapping `initial`/`final` or changing `index` changes the digest, so a
/// leaf's position and boundary states are bound into the chain digest.
pub fn leaf_digest(initial: HashOut<F>, final_: HashOut<F>, index: u64) -> HashOut<F> {
    let mut v = Vec::with_capacity(2 + 8);
    v.push(F::from_canonical_u64(TAG_LEAF));
    v.push(F::from_canonical_u64(index));
    v.extend_from_slice(&initial.elements);
    v.extend_from_slice(&final_.elements);
    PoseidonHash::hash_no_pad(&v)
}

/// Combine two interval digests into the parent `H_{[i,j]}` — paper §4.2.
///
/// `i`/`m`/`j` are the interval bounds (`[i, m]` ∪ `[m+1, j]`); child order is
/// bound, so swapping `left`/`right` changes the result.
pub fn combine_digest(i: u64, m: u64, j: u64, left: HashOut<F>, right: HashOut<F>) -> HashOut<F> {
    let mut v = Vec::with_capacity(4 + 8);
    v.push(F::from_canonical_u64(TAG_MRGE));
    v.push(F::from_canonical_u64(i));
    v.push(F::from_canonical_u64(m));
    v.push(F::from_canonical_u64(j));
    v.extend_from_slice(&left.elements);
    v.extend_from_slice(&right.elements);
    PoseidonHash::hash_no_pad(&v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(x: u64) -> HashOut<F> {
        commit(&[F::from_canonical_u64(x)])
    }

    #[test]
    fn commit_is_deterministic() {
        assert_eq!(commit(&[F::ONE, F::TWO]), commit(&[F::ONE, F::TWO]));
    }

    #[test]
    fn commit_distinguishes_states() {
        assert_ne!(commit(&[F::ONE, F::TWO]), commit(&[F::TWO, F::ONE]));
    }

    #[test]
    fn leaf_digest_separates_index_and_order() {
        let a = h(1);
        let b = h(2);
        assert_ne!(leaf_digest(a, b, 1), leaf_digest(a, b, 2));
        assert_ne!(leaf_digest(a, b, 1), leaf_digest(b, a, 1));
    }

    #[test]
    fn combine_digest_orders_children() {
        let l = h(1);
        let r = h(2);
        assert_ne!(combine_digest(1, 1, 2, l, r), combine_digest(1, 1, 2, r, l));
    }
}
