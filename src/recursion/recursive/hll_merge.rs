//! Two-leaf recursive merge for HyperLogLog update epochs (paper §4.2 Lite).
//!
//! Aggregates two `HllLeafProof`s into one batch-STARK that certifies both
//! per-epoch updates. The §4.2 shared-boundary check is performed natively
//! against the exposed commits — full in-circuit hiding of the intermediate
//! commit is the same follow-up the Count-Min variant defers.
//!
//! Structurally identical to `countmin_merge` — the recursion / chain /
//! flat layers above the leaf are sketch-agnostic. Only the commit type
//! (`HyperLogLogCommit` instead of `CountMinCommit`) and the leaf-proof type
//! differ.

use core::fmt;

use p3_circuit_prover::{BatchStarkProver, ConstraintProfile, TablePacking};
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, RecursionOutput,
    build_and_prove_aggregation_layer,
};

use crate::commitment::HyperLogLogCommit;
use crate::config::LOG_BLOWUP;
use crate::recursion::digest::{ChainDigest, combine_digest, leaf_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::hll_leaf::{HllLeafProof, make_leaf_config};
use crate::sketch::hyperloglog::HyperLogLogUpdate;

const LOG_FINAL_POLY_LEN: usize = 6;

/// Aggregated proof over a chain of `E ≥ 2` HyperLogLog update epochs.
///
/// Produced by `merge_two_hll` (the §4.2 two-leaf merge atom) and by
/// `HllChainState::extend` (the §4.3 recursive chain extension). For
/// `E == 2` the structure degenerates to the original two-leaf merge:
/// `internal_boundaries == [middle]`, `batches == [left_batch, right_batch]`.
pub struct HllChainProof {
    pub recursive_proof: RecursionOutput<ConfigWithFriParams>,
    /// `(1, E)` — `E` is the total number of leaves folded into this proof.
    pub interval: (u64, u64),
    /// `Com(S_0)` — the outer left boundary (first leaf's initial).
    pub initial: HyperLogLogCommit,
    /// `Com(S_E)` — the outer right boundary (last leaf's final).
    pub final_: HyperLogLogCommit,
    /// Boundary between leaf 1 and leaf 2 — kept for backward compatibility
    /// with the two-leaf merge API. For chains of `E ≥ 3` it equals
    /// `internal_boundaries[0]`, *not* the structurally-central boundary.
    pub middle: HyperLogLogCommit,
    /// All `E - 1` internal boundaries in order. `internal_boundaries[i]`
    /// is the commit between leaf `i+1` and leaf `i+2`.
    pub internal_boundaries: Vec<HyperLogLogCommit>,
    /// Batches consumed, in chain order. `batches.len() == E`.
    pub batches: Vec<Vec<HyperLogLogUpdate>>,
    /// `H_{[1, E]}` — ordered-update digest of the whole interval.
    pub digest: ChainDigest,
}

impl HllChainProof {
    /// Number of leaves folded into this chain proof (`E`).
    pub fn num_leaves(&self) -> usize {
        self.batches.len()
    }

    /// The boundary commit at position `i ∈ 0..=E`.
    pub fn boundary(&self, i: usize) -> HyperLogLogCommit {
        let e = self.num_leaves();
        assert!(i <= e, "boundary index {i} > num_leaves {e}");
        if i == 0 {
            self.initial
        } else if i == e {
            self.final_
        } else {
            self.internal_boundaries[i - 1]
        }
    }
}

#[derive(Debug)]
pub enum HllMergeError {
    BoundaryMismatch {
        left_final: HyperLogLogCommit,
        right_initial: HyperLogLogCommit,
    },
    AggregationFailed(String),
    BatchVerifyFailed(String),
    DigestMismatch,
    MiddleBoundaryMismatch,
}

impl fmt::Display for HllMergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryMismatch { left_final, right_initial } => write!(
                f,
                "boundary mismatch: left.final_ = {left_final:?} but right.initial = {right_initial:?}"
            ),
            Self::AggregationFailed(s) => write!(f, "aggregation layer build/prove failed: {s}"),
            Self::BatchVerifyFailed(s) => write!(f, "batch-stark verification failed: {s}"),
            Self::DigestMismatch => write!(f, "recomputed digest does not match the carried one"),
            Self::MiddleBoundaryMismatch => write!(f, "middle boundary mismatch (left.final_ != right.initial)"),
        }
    }
}

impl core::error::Error for HllMergeError {}

pub(crate) fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// Fold an 8-element HyperLogLog commit into the 2-element boundary the
/// chain digest functions take. Same shortcut Count-Min uses: the first 2
/// of the 8 Poseidon2 digest elements retain enough entropy because the
/// digest is already collision-resistant.
pub(crate) fn hll_leaf_digest(c: &HyperLogLogCommit) -> [crate::config::Val; 2] {
    [c.0[0], c.0[1]]
}

/// Merge two HyperLogLog leaf proofs into one aggregated batch-STARK that
/// certifies both epochs.
pub fn merge_two_hll(
    left: &HllLeafProof,
    right: &HllLeafProof,
) -> Result<HllChainProof, HllMergeError> {
    if left.final_ != right.initial {
        return Err(HllMergeError::BoundaryMismatch {
            left_final: left.final_,
            right_initial: right.initial,
        });
    }

    let config = make_leaf_config();
    let backend = make_backend();
    let params = agg_params();

    let left_input = left.output.into_recursion_input::<BatchOnly>();
    let right_input = right.output.into_recursion_input::<BatchOnly>();

    let recursive_proof = build_and_prove_aggregation_layer::<
        ConfigWithFriParams,
        BatchOnly,
        BatchOnly,
        Backend,
        EXT_D,
    >(&left_input, &right_input, &config, &backend, &params, None)
    .map_err(|e| HllMergeError::AggregationFailed(format!("{e:?}")))?;

    let lp = hll_leaf_digest(&left.initial);
    let lf = hll_leaf_digest(&left.final_);
    let rp = hll_leaf_digest(&right.initial);
    let rf = hll_leaf_digest(&right.final_);
    let dl = leaf_digest(&lp, &lf, 1);
    let dr = leaf_digest(&rp, &rf, 2);
    let digest = combine_digest(1, 1, 2, &dl, &dr);

    Ok(HllChainProof {
        recursive_proof,
        interval: (1, 2),
        initial: left.initial,
        final_: right.final_,
        middle: left.final_,
        internal_boundaries: vec![left.final_],
        batches: vec![left.batch.to_vec(), right.batch.to_vec()],
        digest,
    })
}

/// Verify an `HllChainProof` of any length `E ≥ 2`. Same shape as
/// `verify_chain_countmin`: batch-STARK verify + structural-invariant
/// checks + left-deep digest re-derivation.
pub fn verify_chain_hll(c: &HllChainProof) -> Result<(), HllMergeError> {
    let config = make_leaf_config();
    let params = agg_params();

    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier
        .verify_all_tables(&c.recursive_proof.0)
        .map_err(|e| HllMergeError::BatchVerifyFailed(format!("{e:?}")))?;

    let e = c.num_leaves();
    if e < 2 || c.internal_boundaries.len() != e - 1 || c.interval != (1, e as u64) {
        return Err(HllMergeError::MiddleBoundaryMismatch);
    }

    let mut acc = leaf_digest(
        &hll_leaf_digest(&c.boundary(0)),
        &hll_leaf_digest(&c.boundary(1)),
        1,
    );
    for k in 2..=e {
        let dr = leaf_digest(
            &hll_leaf_digest(&c.boundary(k - 1)),
            &hll_leaf_digest(&c.boundary(k)),
            k as u64,
        );
        acc = combine_digest(1, (k - 1) as u64, k as u64, &acc, &dr);
    }
    if acc != c.digest {
        return Err(HllMergeError::DigestMismatch);
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
    fn honest_two_leaf_hll_chain_accepts() {
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

        let chain = merge_two_hll(&l1, &l2).expect("merge_two_hll");
        verify_chain_hll(&chain).expect("verify_chain_hll");

        assert_eq!(chain.middle, l1.final_);
        assert_eq!(chain.initial, l1.initial);
        assert_eq!(chain.final_, l2.final_);
    }

    #[test]
    fn boundary_mismatch_hll_rejected() {
        let s0 = empty_state();
        let b1 = [
            HyperLogLogUpdate { key: 0xDEAD_BEEF_0000_1111 },
            HyperLogLogUpdate { key: 0xC0FFEE_FACE_FACE },
        ];
        let l1 = prove_hll_leaf(s0, b1);

        // Wrong starting state — boundary won't match.
        let s1_wrong = empty_state();
        let b2 = [
            HyperLogLogUpdate { key: 0x1234_5678_9ABC_DEF0 },
            HyperLogLogUpdate { key: 0xCAFE_BABE_5555_AAAA },
        ];
        let l2 = prove_hll_leaf(s1_wrong, b2);

        match merge_two_hll(&l1, &l2) {
            Err(HllMergeError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("merge must reject mismatched boundary"),
        }
    }
}
