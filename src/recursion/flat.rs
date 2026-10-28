//! Flat two-leaf merge for the Fibonacci toy leaf: `ChainProof` keeps both leaf
//! proofs and `verify_chain` re-verifies them and checks the shared boundary.

use core::fmt;

use crate::prover::leaf::LeafVerifyError;
use crate::prover::{Boundary, LeafProof, verify_fib_leaf};
use crate::recursion::digest::{ChainDigest, boundary_leaf_digest, combine_digest, pad_boundary2};

/// Aggregated proof over an interval `[i, j]` of leaf proofs.
///
/// In Phase 1 this is the §4.1 flat chain: the verifier sees the leaves
/// themselves. In Phase 1.5 the `leaves` field will be replaced by a single
/// recursive batch-STARK proof and `verify_chain` will become O(1).
pub struct ChainProof {
    /// Leaf proofs in left-to-right order. Length is `j - i + 1`.
    pub leaves: Vec<LeafProof>,
    /// Outer interval `[i, j]` (1-indexed, inclusive) — the public interval.
    pub interval: (u64, u64),
    /// Initial boundary `Com(S_{i-1})` — the input state of the leftmost leaf.
    pub initial: Boundary,
    /// Final boundary `Com(S_j)` — the output state of the rightmost leaf.
    pub final_: Boundary,
    /// `H_{[i,j]}` — ordered-update digest of the interval.
    pub digest: ChainDigest,
}

#[derive(Debug)]
pub enum MergeError {
    /// `left.final_` and `right.initial` disagree — the chain would not be
    /// well-formed. This is the §4.2 boundary-equality check, but performed
    /// natively in Phase 1.
    BoundaryMismatch {
        left_final: Boundary,
        right_initial: Boundary,
    },
    /// A leaf proof failed its own STARK verification.
    LeafFailed { index: usize, source: LeafVerifyError },
    /// Adjacent leaves inside an existing `ChainProof` no longer agree at
    /// their shared boundary (defensive — should be impossible after a
    /// successful `merge_two`).
    InternalBoundary { at_index: usize },
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryMismatch { left_final, right_initial } => write!(
                f,
                "boundary mismatch: left.final_ = {:?} but right.initial = {:?}",
                left_final, right_initial
            ),
            Self::LeafFailed { index, source } => {
                write!(f, "leaf #{index} failed verification: {source:?}")
            }
            Self::InternalBoundary { at_index } => write!(
                f,
                "internal boundary at index {at_index} no longer agrees"
            ),
        }
    }
}

impl core::error::Error for MergeError {}

/// Merge two adjacent leaf proofs into a `ChainProof` over the interval
/// `[i, j]` where `i = j - 1` (i.e. exactly two leaves). The function does
/// **not** invoke the leaf verifiers — the trust assumption is that the caller
/// produced honest leaves; `verify_chain` is what re-checks them. We do
/// enforce the boundary-equality check up-front so a malformed pair is
/// rejected immediately.
pub fn merge_two(left: LeafProof, right: LeafProof) -> Result<ChainProof, MergeError> {
    if left.final_ != right.initial {
        return Err(MergeError::BoundaryMismatch {
            left_final: left.final_,
            right_initial: right.initial,
        });
    }

    // Index leaves from 1, matching the paper's notation.
    let i = 1u64;
    let m = 1u64;
    let j = 2u64;

    let dl = boundary_leaf_digest(
        &pad_boundary2(left.initial.a, left.initial.b),
        &pad_boundary2(left.final_.a, left.final_.b),
        i,
    );
    let dr = boundary_leaf_digest(
        &pad_boundary2(right.initial.a, right.initial.b),
        &pad_boundary2(right.final_.a, right.final_.b),
        j,
    );
    let digest = combine_digest(i, m, j, &dl, &dr);

    let initial = left.initial;
    let final_ = right.final_;

    Ok(ChainProof {
        leaves: vec![left, right],
        interval: (i, j),
        initial,
        final_,
        digest,
    })
}

/// Verify a `ChainProof`:
///   1. every leaf proof verifies against its public values,
///   2. adjacent leaves share a boundary,
///   3. the recomputed digest matches the one in the proof,
///   4. the outer boundary matches `initial`/`final_`.
///
/// Phase 1.5 will replace the loop in (1)+(2) with a single recursive STARK
/// verification.
pub fn verify_chain(c: &ChainProof) -> Result<(), MergeError> {
    // (1) each leaf
    for (idx, leaf) in c.leaves.iter().enumerate() {
        verify_fib_leaf(leaf).map_err(|e| MergeError::LeafFailed {
            index: idx,
            source: e,
        })?;
    }

    // (2) chain consistency
    for k in 1..c.leaves.len() {
        if c.leaves[k].initial != c.leaves[k - 1].final_ {
            return Err(MergeError::InternalBoundary { at_index: k });
        }
    }

    // (4) outer boundary
    assert_eq!(c.leaves.first().unwrap().initial, c.initial);
    assert_eq!(c.leaves.last().unwrap().final_, c.final_);

    // (3) digest — recompute and compare.
    let (i, j) = c.interval;
    // For Phase 1 we only support 2-leaf chains. Generalising to E leaves
    // means folding through the binary tree (§4.2) or the streaming forest
    // (§4.3); both are out of scope here.
    assert_eq!(c.leaves.len(), 2, "Phase 1 supports two-leaf chains only");
    let dl = boundary_leaf_digest(
        &pad_boundary2(c.leaves[0].initial.a, c.leaves[0].initial.b),
        &pad_boundary2(c.leaves[0].final_.a, c.leaves[0].final_.b),
        i,
    );
    let dr = boundary_leaf_digest(
        &pad_boundary2(c.leaves[1].initial.a, c.leaves[1].initial.b),
        &pad_boundary2(c.leaves[1].final_.a, c.leaves[1].final_.b),
        j,
    );
    let m = i; // for E=2, m = i
    let expected = combine_digest(i, m, j, &dl, &dr);
    if expected != c.digest {
        return Err(MergeError::InternalBoundary { at_index: 0 });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{Boundary, prove_fib_leaf};

    #[test]
    fn honest_two_leaf_chain_accepts() {
        let l1 = prove_fib_leaf(Boundary::new(0, 1), 4).expect("prove l1");
        let l2 = prove_fib_leaf(l1.final_, 4).expect("prove l2");

        let chain = merge_two(l1, l2).expect("merge");
        verify_chain(&chain).expect("verify_chain");

        assert_eq!(chain.interval, (1, 2));
    }

    #[test]
    fn boundary_mismatch_rejected_at_merge() {
        let l1 = prove_fib_leaf(Boundary::new(0, 1), 4).expect("prove l1");
        // Deliberately start l2 from a wrong boundary.
        let l2 = prove_fib_leaf(Boundary::new(7, 8), 4).expect("prove l2");
        match merge_two(l1, l2) {
            Err(MergeError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("expected merge to reject mismatched boundary"),
        }
    }

    #[test]
    fn tampered_leaf_rejected_at_verify() {
        let l1 = prove_fib_leaf(Boundary::new(0, 1), 4).expect("prove l1");
        let l2 = prove_fib_leaf(l1.final_, 4).expect("prove l2");
        let mut chain = merge_two(l1, l2).expect("merge");
        // Corrupt the right leaf's stated final boundary.
        use p3_field::PrimeCharacteristicRing;
        chain.leaves[1].final_.a = chain.leaves[1].final_.a + crate::config::Val::ONE;
        // The corruption mismatches what the STARK proof actually certifies,
        // so verify_chain must reject (either at the leaf-verify step or
        // at the outer-boundary equality assertion).
        let result = std::panic::catch_unwind(|| verify_chain(&chain));
        assert!(result.is_err() || result.unwrap().is_err());
    }
}
