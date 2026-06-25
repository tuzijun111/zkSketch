//! Two-leaf recursive merge for privacy-preserving v9 Count-Min update
//! epochs (Phase 9d).
//!
//! Structurally mirrors `countmin_merge.rs` (the v1/v2/v3 merge), but:
//!
//! - Takes `CountMinLeafProofV9` (PI shape: `(initial, final, batch_commit)`)
//!   instead of `CountMinLeafProof` (PI shape: `(initial, final,
//!   [per-record])`).
//! - Tracks each epoch's `CountMinBatchCommit` rather than the raw
//!   `Vec<CountMinUpdate>` batch — preserving the privacy guarantee that
//!   per-record contents never escape the proof.
//! - Otherwise identical: same `build_and_prove_aggregation_layer` call,
//!   same digest scheme over state-commit boundaries (the batch_commits
//!   are *recorded* alongside the chain proof but not yet folded into
//!   the digest; a future iteration could absorb them via the §4.3
//!   history-composition layer if desired).
//!
//! v9 leaves are **not** cross-mergeable with v1/v2/v3 leaves — their PI
//! shapes diverge, so the aggregation layer can't bundle them. This is
//! the intentional trade-off for adopting the paper's §5.2 PI surface.

use core::fmt;

use p3_circuit_prover::{BatchStarkProver, ConstraintProfile, TablePacking};
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, RecursionOutput,
    build_and_prove_aggregation_layer,
};

use crate::commitment::countmin::CountMinCommit;
use crate::commitment::countmin_batch::CountMinBatchCommit;
use crate::config::LOG_BLOWUP;
use crate::recursion::digest::{ChainDigest, combine_digest, leaf_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::make_leaf_config;
use crate::recursion::recursive::countmin_leaf_v9::CountMinLeafProofV9;

const LOG_FINAL_POLY_LEN: usize = 6;

/// Aggregated proof over a chain of `E ≥ 2` v9 update epochs.
///
/// Structurally analogous to `CountMinChainProof` but with `batch_commits`
/// (privacy-preserving) instead of raw `batches`.
pub struct CountMinChainProofV9 {
    pub recursive_proof: RecursionOutput<ConfigWithFriParams>,
    /// `(1, E)` — number of leaves folded in.
    pub interval: (u64, u64),
    /// `Com(S_0)` — outer left boundary.
    pub initial: CountMinCommit,
    /// `Com(S_E)` — outer right boundary.
    pub final_: CountMinCommit,
    /// `Com(S_1)` — the first internal boundary, kept for `E=2` callers
    /// that want a "middle" pointer (matches the v3 merge API shape).
    pub middle: CountMinCommit,
    /// All `E - 1` internal boundaries in order.
    pub internal_boundaries: Vec<CountMinCommit>,
    /// Per-leaf batch commitments. **Privacy-preserving** — opaque
    /// 8-element Poseidon2 digests, never the raw batches.
    pub batch_commits: Vec<CountMinBatchCommit>,
    /// `H_{[1, E]}` — ordered digest over state-commit boundaries.
    pub digest: ChainDigest,
}

impl CountMinChainProofV9 {
    pub fn num_leaves(&self) -> usize {
        self.batch_commits.len()
    }

    pub fn boundary(&self, i: usize) -> CountMinCommit {
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
pub enum CountMinMergeErrorV9 {
    BoundaryMismatch {
        left_final: CountMinCommit,
        right_initial: CountMinCommit,
    },
    AggregationFailed(String),
    BatchVerifyFailed(String),
    DigestMismatch,
    MiddleBoundaryMismatch,
}

impl fmt::Display for CountMinMergeErrorV9 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryMismatch { left_final, right_initial } => write!(
                f,
                "boundary mismatch: left.final_ = {left_final:?} but right.initial = {right_initial:?}"
            ),
            Self::AggregationFailed(s) => write!(f, "v9 aggregation layer failed: {s}"),
            Self::BatchVerifyFailed(s) => write!(f, "v9 batch-stark verification failed: {s}"),
            Self::DigestMismatch => write!(f, "recomputed digest does not match the carried one"),
            Self::MiddleBoundaryMismatch => write!(f, "structural mismatch on boundaries"),
        }
    }
}

impl core::error::Error for CountMinMergeErrorV9 {}

/// `pub(crate)` so the linear-chain extension ([`countmin_chain_v9`]) folds
/// `agg + leaf` under the **same** FRI shape — any drift would make
/// [`verify_chain_countmin_v9`] reject the extended proof.
pub(crate) fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// Fold a `CountMinCommit` down to the 2-element boundary id the digest
/// hash takes. Same scheme as `countmin_merge.rs::cm_leaf_digest`: the
/// commit is itself a Poseidon2 digest, so the first two elements retain
/// ~62 bits of entropy — enough for binding. `pub(crate)` so the linear
/// chain extends the digest with the identical leaf-boundary encoding.
pub(crate) fn v9_leaf_digest_bound(c: &CountMinCommit) -> [crate::config::Val; 2] {
    [c.0[0], c.0[1]]
}

/// Merge two v9 leaves into one aggregated batch-STARK that certifies
/// both epochs.
pub fn merge_two_countmin_v9(
    left: &CountMinLeafProofV9,
    right: &CountMinLeafProofV9,
) -> Result<CountMinChainProofV9, CountMinMergeErrorV9> {
    if left.final_ != right.initial {
        return Err(CountMinMergeErrorV9::BoundaryMismatch {
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
    .map_err(|e| CountMinMergeErrorV9::AggregationFailed(format!("{e:?}")))?;

    let lp = v9_leaf_digest_bound(&left.initial);
    let lf = v9_leaf_digest_bound(&left.final_);
    let rp = v9_leaf_digest_bound(&right.initial);
    let rf = v9_leaf_digest_bound(&right.final_);
    let dl = leaf_digest(&lp, &lf, 1);
    let dr = leaf_digest(&rp, &rf, 2);
    let digest = combine_digest(1, 1, 2, &dl, &dr);

    Ok(CountMinChainProofV9 {
        recursive_proof,
        interval: (1, 2),
        initial: left.initial,
        final_: right.final_,
        middle: left.final_,
        internal_boundaries: vec![left.final_],
        batch_commits: vec![left.batch_commit, right.batch_commit],
        digest,
    })
}

/// Verify a `CountMinChainProofV9` of any length `E ≥ 2`. Same structure
/// as `verify_chain_countmin` (v3) but operating on the v9 chain proof.
pub fn verify_chain_countmin_v9(
    c: &CountMinChainProofV9,
) -> Result<(), CountMinMergeErrorV9> {
    let config = make_leaf_config();
    let params = agg_params();

    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier
        .verify_all_tables(&c.recursive_proof.0)
        .map_err(|e| CountMinMergeErrorV9::BatchVerifyFailed(format!("{e:?}")))?;

    let e = c.num_leaves();
    if e < 2
        || c.internal_boundaries.len() != e - 1
        || c.interval != (1, e as u64)
        || c.batch_commits.len() != e
    {
        return Err(CountMinMergeErrorV9::MiddleBoundaryMismatch);
    }

    let mut acc = leaf_digest(
        &v9_leaf_digest_bound(&c.boundary(0)),
        &v9_leaf_digest_bound(&c.boundary(1)),
        1,
    );
    for k in 2..=e {
        let dr = leaf_digest(
            &v9_leaf_digest_bound(&c.boundary(k - 1)),
            &v9_leaf_digest_bound(&c.boundary(k)),
            k as u64,
        );
        acc = combine_digest(1, (k - 1) as u64, k as u64, &acc, &dr);
    }
    if acc != c.digest {
        return Err(CountMinMergeErrorV9::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_leaf::{D, W};
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_v9::CountMinV9;

    fn empty_state() -> crate::sketch::countmin::CountMinState {
        CountMinV9::new(&CountMinParams { d: D, w: W })
    }

    /// Honest two-leaf v9 chain.
    #[test]
    fn honest_two_leaf_v9_chain_accepts() {
        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf_v9(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            CountMinV9::update(&mut s1, u);
        }

        let b2 = [
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_leaf_v9(s1, b2);

        let chain = merge_two_countmin_v9(&l1, &l2).expect("v9 merge");
        verify_chain_countmin_v9(&chain).expect("v9 verify");

        // Privacy check: the chain proof exposes batch_commits, not raw
        // batches. Inspect the field shape directly.
        assert_eq!(chain.batch_commits.len(), 2);
        assert_eq!(chain.middle, l1.final_);
        assert_eq!(chain.initial, l1.initial);
        assert_eq!(chain.final_, l2.final_);
    }

    /// Two v9 leaves with a state-boundary mismatch are rejected before
    /// the recursive prover is invoked.
    #[test]
    fn boundary_mismatch_v9_rejected() {
        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf_v9(s0, b1);

        let s1_wrong = empty_state();
        let b2 = [
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_leaf_v9(s1_wrong, b2);

        match merge_two_countmin_v9(&l1, &l2) {
            Err(CountMinMergeErrorV9::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("merge must reject mismatched boundary"),
        }
    }
}
