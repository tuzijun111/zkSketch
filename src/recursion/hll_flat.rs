//! §4.1 flat proof chain for HyperLogLog update epochs.
//!
//! Companion to `recursion::countmin_flat` (Count-Min's §4.1 path) and the
//! §4.2 recursive merge in `recursion::recursive::hll_merge`. The flat
//! `ChainProof` simply bundles two `HllLeafProof`s; `verify_chain_flat_hll`
//! re-verifies each leaf natively via `BatchStarkProver::verify_all_tables`
//! and checks the shared-boundary equality from the carried commits.
//!
//! Verifier cost scales as `Θ(E)` in the number of leaves; contrast the
//! `O(1)` of the recursive merge. `examples/hll_chain_two.rs` measures both
//! on the same two leaves.

use core::fmt;

use p3_circuit_prover::{BatchStarkProver, TablePacking};
use p3_recursion::Poseidon2Config;

use crate::commitment::HyperLogLogCommit;
use crate::config::LOG_BLOWUP;
use crate::recursion::digest::{ChainDigest, combine_digest, leaf_digest};
use crate::recursion::recursive::config::D as EXT_D;
use crate::recursion::recursive::hll_leaf::{HllLeafProof, make_leaf_config};
use crate::recursion::recursive::hll_merge::hll_leaf_digest;
use crate::sketch::hyperloglog::HyperLogLogUpdate;

/// Same `log_final_poly_len` as the recursive leaf / merge — keeps the
/// FRI shape consistent so both paths verify the same proofs.
const LOG_FINAL_POLY_LEN: usize = 6;

/// Flat §4.1 chain proof: bundles both leaves and carries their digest /
/// boundary metadata.
pub struct HllFlatChainProof {
    pub leaves: Vec<HllLeafProof>,
    pub interval: (u64, u64),
    pub initial: HyperLogLogCommit,
    pub final_: HyperLogLogCommit,
    pub middle: HyperLogLogCommit,
    pub left_batch: Vec<HyperLogLogUpdate>,
    pub right_batch: Vec<HyperLogLogUpdate>,
    pub digest: ChainDigest,
}

#[derive(Debug)]
pub enum HllFlatError {
    BoundaryMismatch {
        left_final: HyperLogLogCommit,
        right_initial: HyperLogLogCommit,
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

impl fmt::Display for HllFlatError {
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

impl core::error::Error for HllFlatError {}

/// Build an HLL §4.1 flat chain from two adjacent leaf proofs.
pub fn flat_merge_two_hll(
    left: HllLeafProof,
    right: HllLeafProof,
) -> Result<HllFlatChainProof, HllFlatError> {
    if left.final_ != right.initial {
        return Err(HllFlatError::BoundaryMismatch {
            left_final: left.final_,
            right_initial: right.initial,
        });
    }

    let dl = leaf_digest(
        &hll_leaf_digest(&left.initial),
        &hll_leaf_digest(&left.final_),
        1,
    );
    let dr = leaf_digest(
        &hll_leaf_digest(&right.initial),
        &hll_leaf_digest(&right.final_),
        2,
    );
    let digest = combine_digest(1, 1, 2, &dl, &dr);

    let initial = left.initial;
    let final_ = right.final_;
    let middle = left.final_;
    let left_batch = left.batch.to_vec();
    let right_batch = right.batch.to_vec();

    Ok(HllFlatChainProof {
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

/// Verify an HLL §4.1 flat chain.
pub fn verify_chain_flat_hll(c: &HllFlatChainProof) -> Result<(), HllFlatError> {
    let config = make_leaf_config();
    let leaf_table_packing =
        TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);

    for (idx, leaf) in c.leaves.iter().enumerate() {
        let mut verifier =
            BatchStarkProver::new(config.clone()).with_table_packing(leaf_table_packing.clone());
        verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
        verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
        verifier
            .verify_all_tables(&leaf.output.0)
            .map_err(|e| HllFlatError::LeafFailed {
                index: idx,
                details: format!("{e:?}"),
            })?;
    }

    for k in 1..c.leaves.len() {
        if c.leaves[k].initial != c.leaves[k - 1].final_ {
            return Err(HllFlatError::InternalBoundary { at_index: k });
        }
    }

    assert_eq!(c.leaves.first().unwrap().initial, c.initial);
    assert_eq!(c.leaves.last().unwrap().final_, c.final_);

    let dl = leaf_digest(
        &hll_leaf_digest(&c.leaves[0].initial),
        &hll_leaf_digest(&c.leaves[0].final_),
        1,
    );
    let dr = leaf_digest(
        &hll_leaf_digest(&c.leaves[1].initial),
        &hll_leaf_digest(&c.leaves[1].final_),
        2,
    );
    let expected = combine_digest(1, 1, 2, &dl, &dr);
    if expected != c.digest {
        return Err(HllFlatError::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::hll_leaf::{B, prove_hll_leaf};
    use crate::sketch::Sketch;
    use crate::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogUpdate};

    fn empty_state() -> crate::sketch::hyperloglog::HyperLogLogState {
        HyperLogLog::new(&HyperLogLogParams { b: B })
    }

    #[test]
    fn honest_two_leaf_hll_flat_accepts() {
        let s0 = empty_state();
        let b1 = [
            HyperLogLogUpdate { key: 0xDEAD_BEEF_0000_1111 },
            HyperLogLogUpdate { key: 0xC0FFEE_FACE_FACE },
        ];
        let l1 = prove_hll_leaf(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            HyperLogLog::update(&mut s1, u);
        }
        let b2 = [
            HyperLogLogUpdate { key: 0x1234_5678_9ABC_DEF0 },
            HyperLogLogUpdate { key: 0xCAFE_BABE_5555_AAAA },
        ];
        let l2 = prove_hll_leaf(s1, b2);

        let chain = flat_merge_two_hll(l1, l2).expect("flat_merge");
        verify_chain_flat_hll(&chain).expect("verify_chain_flat");
    }

    #[test]
    fn boundary_mismatch_hll_flat_rejected() {
        let s0 = empty_state();
        let b1 = [
            HyperLogLogUpdate { key: 0xDEAD_BEEF_0000_1111 },
            HyperLogLogUpdate { key: 0xC0FFEE_FACE_FACE },
        ];
        let l1 = prove_hll_leaf(s0, b1);

        let s1_wrong = empty_state();
        let b2 = [
            HyperLogLogUpdate { key: 0x1234_5678_9ABC_DEF0 },
            HyperLogLogUpdate { key: 0xCAFE_BABE_5555_AAAA },
        ];
        let l2 = prove_hll_leaf(s1_wrong, b2);

        match flat_merge_two_hll(l1, l2) {
            Err(HllFlatError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("flat merge must reject mismatched boundary"),
        }
    }
}
