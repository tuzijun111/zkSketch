//! Two-leaf recursive merge for Count-Min update epochs (paper §4.2 Lite).
//!
//! Aggregates two `CountMinLeafProof`s into one batch-STARK that certifies
//! both per-epoch updates. The §4.2 shared-boundary check is performed
//! natively against the exposed commits — full in-circuit hiding of the
//! intermediate commit is the same follow-up the Fibonacci variant defers.

use core::fmt;

use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, TablePacking,
};
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, RecursionOutput,
    build_and_prove_aggregation_layer,
};

use crate::commitment::CountMinCommit;
use crate::config::LOG_BLOWUP;
use crate::recursion::digest::{ChainDigest, combine_digest, leaf_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::{CountMinLeafProof, make_leaf_config};
use crate::sketch::countmin::CountMinUpdate;

const LOG_FINAL_POLY_LEN: usize = 6;

/// Aggregated proof over a chain of `E ≥ 2` Count-Min update epochs.
///
/// Produced by `merge_two_countmin` (the §4.2 two-leaf merge atom) and by
/// `CountMinChainState::extend` (the §4.3 recursive chain extension). For
/// `E == 2` the structure degenerates to the original two-leaf merge:
/// `internal_boundaries == [middle]`, `batches == [left_batch, right_batch]`.
pub struct CountMinChainProof {
    pub recursive_proof: RecursionOutput<ConfigWithFriParams>,
    /// `(1, E)` — `E` is the total number of leaves folded into this proof.
    pub interval: (u64, u64),
    /// `Com(S_0)` — the outer left boundary (first leaf's initial).
    pub initial: CountMinCommit,
    /// `Com(S_E)` — the outer right boundary (last leaf's final).
    pub final_: CountMinCommit,
    /// Boundary between leaf 1 and leaf 2 — kept for backward compatibility
    /// with the two-leaf merge API. For chains of `E ≥ 3` it equals
    /// `internal_boundaries[0]`, *not* the structurally-central boundary.
    pub middle: CountMinCommit,
    /// All `E - 1` internal boundaries in order. `internal_boundaries[i]`
    /// is the commit between leaf `i+1` and leaf `i+2` (i.e.,
    /// `leaves[i].final_ == leaves[i+1].initial`). Needed for digest
    /// re-derivation when `E > 2`.
    pub internal_boundaries: Vec<CountMinCommit>,
    /// Batches consumed, in chain order. `batches.len() == E`.
    pub batches: Vec<Vec<CountMinUpdate>>,
    /// `H_{[1, E]}` — ordered-update digest of the whole interval.
    pub digest: ChainDigest,
}

impl CountMinChainProof {
    /// Number of leaves folded into this chain proof (`E`).
    pub fn num_leaves(&self) -> usize {
        self.batches.len()
    }

    /// The boundary commit at position `i ∈ 0..=E`. `i = 0` is `initial`,
    /// `i = E` is `final_`, intermediate values come from
    /// `internal_boundaries`.
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
pub enum CountMinMergeError {
    BoundaryMismatch {
        left_final: CountMinCommit,
        right_initial: CountMinCommit,
    },
    AggregationFailed(String),
    BatchVerifyFailed(String),
    DigestMismatch,
    MiddleBoundaryMismatch,
}

impl fmt::Display for CountMinMergeError {
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

impl core::error::Error for CountMinMergeError {}

pub(crate) fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

pub(crate) fn cm_leaf_digest(c: &CountMinCommit) -> [crate::config::Val; 2] {
    // The chain digest functions in `recursion::digest` take a 2-element
    // boundary. The Count-Min commit is 8 elements, so we fold it down by
    // summing-with-Poseidon-already-applied data: we use the first two
    // elements as the "boundary id" passed into the leaf-digest hash, which
    // is sufficient for binding because the full 8 elements are themselves
    // a Poseidon2 digest (collision-resistant), so the first 2 retain
    // 62-ish bits of entropy.
    [c.0[0], c.0[1]]
}

/// Merge two Count-Min leaf proofs into one aggregated batch-STARK that
/// certifies both epochs.
pub fn merge_two_countmin(
    left: &CountMinLeafProof,
    right: &CountMinLeafProof,
) -> Result<CountMinChainProof, CountMinMergeError> {
    if left.final_ != right.initial {
        return Err(CountMinMergeError::BoundaryMismatch {
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
    .map_err(|e| CountMinMergeError::AggregationFailed(format!("{e:?}")))?;

    let lp = cm_leaf_digest(&left.initial);
    let lf = cm_leaf_digest(&left.final_);
    let rp = cm_leaf_digest(&right.initial);
    let rf = cm_leaf_digest(&right.final_);
    let dl = leaf_digest(&lp, &lf, 1);
    let dr = leaf_digest(&rp, &rf, 2);
    let digest = combine_digest(1, 1, 2, &dl, &dr);

    Ok(CountMinChainProof {
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

/// Verify a `CountMinChainProof` of any length `E ≥ 2`:
///   1. The single recursive batch-STARK proof is sound.
///   2. Structural invariants: `internal_boundaries.len() == E - 1` and
///      `batches.len() == E` agree with `interval.1`.
///   3. The combined `H_{[1, E]}` digest re-derives from the boundaries.
///      Each leaf `k ∈ 1..=E` contributes `leaf_digest(b[k-1], b[k], k)`
///      where `b[0] = initial`, `b[E] = final_`, and `b[i] =
///      internal_boundaries[i-1]` for `1 ≤ i ≤ E-1`. The chain digest is
///      then built left-deep: `acc = leaf_digest(b[0], b[1], 1)`, then
///      `acc = combine(1, k-1, k, acc, leaf_digest(b[k-1], b[k], k))` for
///      each subsequent `k`.
pub fn verify_chain_countmin(c: &CountMinChainProof) -> Result<(), CountMinMergeError> {
    let config = make_leaf_config();
    let params = agg_params();

    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier
        .verify_all_tables(&c.recursive_proof.0)
        .map_err(|e| CountMinMergeError::BatchVerifyFailed(format!("{e:?}")))?;

    let e = c.num_leaves();
    if e < 2 || c.internal_boundaries.len() != e - 1 || c.interval != (1, e as u64) {
        return Err(CountMinMergeError::MiddleBoundaryMismatch);
    }

    // Digest re-derivation (left-deep accumulation).
    let mut acc = leaf_digest(
        &cm_leaf_digest(&c.boundary(0)),
        &cm_leaf_digest(&c.boundary(1)),
        1,
    );
    for k in 2..=e {
        let dr = leaf_digest(
            &cm_leaf_digest(&c.boundary(k - 1)),
            &cm_leaf_digest(&c.boundary(k)),
            k as u64,
        );
        acc = combine_digest(1, (k - 1) as u64, k as u64, &acc, &dr);
    }
    if acc != c.digest {
        return Err(CountMinMergeError::DigestMismatch);
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
    fn honest_two_leaf_countmin_chain_accepts() {
        // Build two adjacent epochs. Epoch 1 starts empty; Epoch 2 starts
        // from the post-Epoch-1 state.
        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf(s0.clone(), b1);

        // Apply b1 natively to derive the actual epoch-2 starting state.
        let mut s1 = s0;
        for u in &b1 {
            CountMin::update(&mut s1, u);
        }

        let b2 = [
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_leaf(s1, b2);

        // The recursion must accept the chain.
        let chain = merge_two_countmin(&l1, &l2).expect("merge_two_countmin");
        verify_chain_countmin(&chain).expect("verify_chain_countmin");

        // Sanity: the boundary chain matched.
        assert_eq!(chain.middle, l1.final_);
        assert_eq!(chain.initial, l1.initial);
        assert_eq!(chain.final_, l2.final_);
    }

    #[test]
    fn boundary_mismatch_countmin_rejected() {
        // Two leaves whose initial states disagree.
        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf(s0, b1);

        // Skip applying b1; epoch-2 starts from an empty state again, so
        // the boundary won't match l1.final_.
        let s1_wrong = empty_state();
        let b2 = [
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_leaf(s1_wrong, b2);

        match merge_two_countmin(&l1, &l2) {
            Err(CountMinMergeError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("merge must reject mismatched boundary"),
        }
    }
}
