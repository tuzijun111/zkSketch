//! §4.1 flat proof chain for Count-Min update epochs.
//!
//! Companion to `recursion::flat` (which is the Fibonacci toy AIR) and the
//! §4.2 recursive merge in `recursion::recursive::countmin_merge`. The flat
//! `ChainProof` simply bundles two `CountMinLeafProof`s; `verify_chain`
//! re-verifies each leaf natively via `BatchStarkProver::verify_all_tables`
//! and checks the shared-boundary equality from the carried commits. The
//! ordered-update digest is computed once with the same `leaf_digest` /
//! `combine_digest` recipe the recursive merge uses, so both paths certify
//! the same `H_{[i,j]}` interval object.
//!
//! Verifier cost scales as `Θ(E)` in the number of leaves; contrast the
//! `O(1)` of the recursive merge. The `examples/countmin_chain_two.rs`
//! demo measures both on the same two leaves.

use core::fmt;

use p3_circuit_prover::{BatchStarkProver, TablePacking};
use p3_recursion::Poseidon2Config;

use crate::commitment::CountMinCommit;
use crate::config::LOG_BLOWUP;
use crate::recursion::digest::{ChainDigest, boundary_leaf_digest, combine_digest};
use crate::recursion::recursive::config::D as EXT_D;
use crate::recursion::recursive::countmin_leaf::{CountMinLeafProof, make_leaf_config};
use crate::sketch::countmin::CountMinUpdate;

/// Same `log_final_poly_len` as the recursive leaf / merge — keeps the
/// FRI shape consistent so both paths verify the same proofs.
const LOG_FINAL_POLY_LEN: usize = 6;

/// Flat §4.1 chain proof: bundles both leaves and carries their digest /
/// boundary metadata. `verify_chain_flat_countmin` re-runs each leaf's
/// `verify_all_tables` natively, then checks the shared-boundary equality.
pub struct CountMinFlatChainProof {
    pub leaves: Vec<CountMinLeafProof>,
    pub interval: (u64, u64),
    pub initial: CountMinCommit,
    pub final_: CountMinCommit,
    pub middle: CountMinCommit,
    pub left_batch: Vec<CountMinUpdate>,
    pub right_batch: Vec<CountMinUpdate>,
    pub digest: ChainDigest,
}

#[derive(Debug)]
pub enum CountMinFlatError {
    BoundaryMismatch {
        left_final: CountMinCommit,
        right_initial: CountMinCommit,
    },
    LeafFailed {
        index: usize,
        details: String,
    },
    DigestMismatch,
    InternalBoundary {
        at_index: usize,
    },
}

impl fmt::Display for CountMinFlatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryMismatch { left_final, right_initial } => write!(
                f,
                "boundary mismatch: left.final_ = {left_final:?} but right.initial = {right_initial:?}"
            ),
            Self::LeafFailed { index, details } => {
                write!(f, "leaf #{index} failed verification: {details}")
            }
            Self::DigestMismatch => write!(f, "recomputed digest does not match the carried one"),
            Self::InternalBoundary { at_index } => write!(
                f,
                "internal boundary at index {at_index} no longer agrees"
            ),
        }
    }
}

impl core::error::Error for CountMinFlatError {}

/// Build a Count-Min §4.1 flat chain from two adjacent leaf proofs.
///
/// Does not run any STARK prover — only checks the boundary natively and
/// combines the digest. The expensive work is shifted to `verify_chain_flat_countmin`,
/// which must re-run each leaf's STARK verification.
pub fn flat_merge_two_countmin(
    left: CountMinLeafProof,
    right: CountMinLeafProof,
) -> Result<CountMinFlatChainProof, CountMinFlatError> {
    if left.final_ != right.initial {
        return Err(CountMinFlatError::BoundaryMismatch {
            left_final: left.final_,
            right_initial: right.initial,
        });
    }

    let dl = boundary_leaf_digest(&left.initial.0, &left.final_.0, 1);
    let dr = boundary_leaf_digest(&right.initial.0, &right.final_.0, 2);
    let digest = combine_digest(1, 1, 2, &dl, &dr);

    let initial = left.initial;
    let final_ = right.final_;
    let middle = left.final_;
    let left_batch = left.batch.to_vec();
    let right_batch = right.batch.to_vec();

    Ok(CountMinFlatChainProof {
        leaves: vec![left, right],
        interval: (1, 2),
        initial,
        final_,
        middle,
        left_batch,
        right_batch,
        digest,
    })
}

/// Verify a Count-Min §4.1 flat chain.
///
/// Steps mirror the Fibonacci `recursion::flat::verify_chain`:
///   1. Re-verify each bundled leaf's batch-STARK proof.
///   2. Assert adjacent leaves share a boundary (`leaves[k].initial == leaves[k-1].final_`).
///   3. Recompute and compare the ordered-update digest.
///   4. Outer boundaries match the carried `initial`/`final_`.
pub fn verify_chain_flat_countmin(c: &CountMinFlatChainProof) -> Result<(), CountMinFlatError> {
    let config = make_leaf_config();
    // Leaf table packing — same `(1, 2)` shape the leaf prover used.
    let leaf_table_packing =
        TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);

    for (idx, leaf) in c.leaves.iter().enumerate() {
        let mut verifier = BatchStarkProver::new(config.clone())
            .with_table_packing(leaf_table_packing.clone());
        verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
        verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
        verifier
            .verify_all_tables(&leaf.output.0)
            .map_err(|e| CountMinFlatError::LeafFailed {
                index: idx,
                details: format!("{e:?}"),
            })?;
    }

    for k in 1..c.leaves.len() {
        if c.leaves[k].initial != c.leaves[k - 1].final_ {
            return Err(CountMinFlatError::InternalBoundary { at_index: k });
        }
    }

    assert_eq!(c.leaves.first().unwrap().initial, c.initial);
    assert_eq!(c.leaves.last().unwrap().final_, c.final_);

    let dl = boundary_leaf_digest(&c.leaves[0].initial.0, &c.leaves[0].final_.0, 1);
    let dr = boundary_leaf_digest(&c.leaves[1].initial.0, &c.leaves[1].final_.0, 2);
    let expected = combine_digest(1, 1, 2, &dl, &dr);
    if expected != c.digest {
        return Err(CountMinFlatError::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_leaf::{D, W, prove_countmin_leaf};
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};

    fn empty_state() -> crate::sketch::countmin::CountMinState {
        CountMin::new(&CountMinParams { d: D, w: W })
    }

    #[test]
    fn honest_two_leaf_countmin_flat_accepts() {
        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            CountMin::update(&mut s1, u);
        }
        let b2 = [
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_leaf(s1, b2);

        let chain = flat_merge_two_countmin(l1, l2).expect("flat_merge");
        verify_chain_flat_countmin(&chain).expect("verify_chain_flat");
    }

    #[test]
    fn boundary_mismatch_countmin_flat_rejected() {
        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf(s0, b1);

        // Wrong starting state — boundary won't match.
        let s1_wrong = empty_state();
        let b2 = [
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_leaf(s1_wrong, b2);

        match flat_merge_two_countmin(l1, l2) {
            Err(CountMinFlatError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("flat merge must reject mismatched boundary"),
        }
    }
}
