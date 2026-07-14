//! Two-leaf recursive merge for **sparse-Merkle** Count-Min update epochs.
//!
//! Structurally mirrors [`super::countmin_merge_v9`], but the leaf is a
//! [`CountMinMerkleProof`] whose state commitment is the `d`-tuple of per-row
//! Merkle roots (see [`crate::sketch::countmin_merkle`]). The boundary between
//! two epochs is checked on the **full root tuple** (`left.final_roots ==
//! right.initial_roots`, exact); the chain digest folds each boundary's
//! *combined* commit ([`combined_commit`]) the same way the v9 merge folds its
//! `CountMinCommit` boundaries. The recursive aggregation itself is the
//! identical `build_and_prove_aggregation_layer` call — the merkle leaf's
//! `output` is the same `RecursionOutput<ConfigWithFriParams>` batch-STARK
//! proof, so it aggregates just like any other leaf (the merge circuit
//! recursively verifies both children regardless of their internal AIR set).

use core::fmt;

use p3_circuit_prover::{BatchStarkProver, ConstraintProfile, TablePacking};
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, RecursionOutput,
    build_and_prove_aggregation_layer,
};

use crate::commitment::countmin::CountMinCommit;
use crate::config::{LOG_BLOWUP, Val};
use crate::recursion::digest::{ChainDigest, combine_digest, leaf_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::make_leaf_config;
use crate::sketch::countmin_merkle::{combined_commit, CountMinMerkleProof};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Aggregated proof over a chain of `E ≥ 2` sparse-Merkle update epochs.
///
/// Boundaries are stored as the *combined* per-epoch state commitments (single
/// `CountMinCommit` each — `combined_commit` of that epoch's row roots), so the
/// digest scheme is identical to the v9 chain proof.
pub struct CountMinMerkleChainProof {
    pub recursive_proof: RecursionOutput<ConfigWithFriParams>,
    /// `(1, E)` — number of leaves folded in.
    pub interval: (u64, u64),
    /// Combined `Com(S_0)` — outer left boundary.
    pub initial: CountMinCommit,
    /// Combined `Com(S_E)` — outer right boundary.
    pub final_: CountMinCommit,
    /// Combined `Com(S_1)` — first internal boundary (E=2 "middle" pointer).
    pub middle: CountMinCommit,
    /// All `E - 1` internal boundaries in order (combined commits).
    pub internal_boundaries: Vec<CountMinCommit>,
    /// Per-leaf batch commitments (opaque Poseidon2 digests; privacy-preserving).
    pub batch_commits: Vec<CountMinCommit>,
    /// `H_{[1, E]}` — ordered digest over state-commit boundaries.
    pub digest: ChainDigest,
}

impl CountMinMerkleChainProof {
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
pub enum CountMinMerkleMergeError {
    BoundaryMismatch {
        left_final: Vec<CountMinCommit>,
        right_initial: Vec<CountMinCommit>,
    },
    AggregationFailed(String),
    BatchVerifyFailed(String),
    DigestMismatch,
    StructureMismatch,
}

impl fmt::Display for CountMinMerkleMergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryMismatch { .. } => {
                write!(f, "boundary mismatch: left.final_roots != right.initial_roots")
            }
            Self::AggregationFailed(s) => write!(f, "merkle aggregation layer failed: {s}"),
            Self::BatchVerifyFailed(s) => write!(f, "merkle batch-stark verification failed: {s}"),
            Self::DigestMismatch => write!(f, "recomputed digest does not match the carried one"),
            Self::StructureMismatch => write!(f, "structural mismatch on boundaries"),
        }
    }
}

impl core::error::Error for CountMinMerkleMergeError {}

fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// Merge two sparse-Merkle leaves into one aggregated batch-STARK certifying
/// both epochs. The boundary `left.final_roots == right.initial_roots` is
/// checked natively (exact, over the full root tuple) before the recursive
/// prover runs.
pub fn merge_two_countmin_merkle(
    left: &CountMinMerkleProof,
    right: &CountMinMerkleProof,
) -> Result<CountMinMerkleChainProof, CountMinMerkleMergeError> {
    if left.final_roots != right.initial_roots {
        return Err(CountMinMerkleMergeError::BoundaryMismatch {
            left_final: left.final_roots.clone(),
            right_initial: right.initial_roots.clone(),
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
    .map_err(|e| CountMinMerkleMergeError::AggregationFailed(format!("{e:?}")))?;

    let li = combined_commit(&left.initial_roots);
    let lf = combined_commit(&left.final_roots);
    let ri = combined_commit(&right.initial_roots);
    let rf = combined_commit(&right.final_roots);
    let dl = leaf_digest(1, 1, &left.batch_commit.0, &li.0, &lf.0);
    let dr = leaf_digest(2, 2, &right.batch_commit.0, &ri.0, &rf.0);
    let digest = combine_digest(1, 1, 2, &dl, &dr);

    Ok(CountMinMerkleChainProof {
        recursive_proof,
        interval: (1, 2),
        initial: li,
        final_: rf,
        middle: lf,
        internal_boundaries: vec![lf],
        batch_commits: vec![left.batch_commit, right.batch_commit],
        digest,
    })
}

/// Verify a `CountMinMerkleChainProof` of any length `E ≥ 2`: the recursive
/// batch-STARK plus the boundary-digest recomputation (mirrors
/// `verify_chain_countmin_v9`).
pub fn verify_chain_countmin_merkle(
    c: &CountMinMerkleChainProof,
) -> Result<(), CountMinMerkleMergeError> {
    let config = make_leaf_config();
    let params = agg_params();

    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier
        .verify_all_tables(&c.recursive_proof.0)
        .map_err(|e| CountMinMerkleMergeError::BatchVerifyFailed(format!("{e:?}")))?;

    let e = c.num_leaves();
    if e < 2
        || c.internal_boundaries.len() != e - 1
        || c.interval != (1, e as u64)
        || c.batch_commits.len() != e
    {
        return Err(CountMinMerkleMergeError::StructureMismatch);
    }

    let mut acc = leaf_digest(1, 1, &c.batch_commits[0].0, &c.boundary(0).0, &c.boundary(1).0);
    for k in 2..=e {
        let dr = leaf_digest(
            k as u64,
            k as u64,
            &c.batch_commits[k - 1].0,
            &c.boundary(k - 1).0,
            &c.boundary(k).0,
        );
        acc = combine_digest(1, (k - 1) as u64, k as u64, &acc, &dr);
    }
    if acc != c.digest {
        return Err(CountMinMerkleMergeError::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
    use crate::sketch::countmin_final::hash_cell_prf;
    use crate::sketch::countmin_merkle::{prove_countmin_merkle_leaf, CountMinMerkleParams};

    fn empty(d: usize, w: usize) -> CountMinState {
        CountMinState { counters: vec![vec![0u32; w]; d], params: CountMinParams { d, w } }
    }

    fn apply(state: &CountMinState, batch: &[CountMinUpdate]) -> CountMinState {
        let (d, w) = (state.params.d, state.params.w);
        let mut s = state.clone();
        for u in batch {
            for i in 0..d {
                s.counters[i][hash_cell_prf(i, u.key, w)] += u.value;
            }
        }
        s
    }

    /// Honest two-leaf sparse-Merkle chain (d rows) accepts.
    #[test]
    fn honest_two_leaf_merkle_chain_accepts() {
        let params = CountMinMerkleParams { d: 4, w: 16, batch: 2, t_max: 2 };
        let s0 = empty(4, 16);
        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_merkle_leaf(params, s0.clone(), b1.clone());
        let s1 = apply(&s0, &b1);
        let b2 = vec![
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_merkle_leaf(params, s1, b2);

        let chain = merge_two_countmin_merkle(&l1, &l2).expect("merkle merge");
        verify_chain_countmin_merkle(&chain).expect("merkle verify");
        assert_eq!(chain.num_leaves(), 2);
        assert_eq!(chain.initial, combined_commit(&l1.initial_roots));
        assert_eq!(chain.final_, combined_commit(&l2.final_roots));
        assert_eq!(chain.middle, combined_commit(&l1.final_roots));
    }

    /// A state-boundary mismatch is rejected before the recursive prover runs.
    #[test]
    fn boundary_mismatch_merkle_rejected() {
        let params = CountMinMerkleParams { d: 4, w: 16, batch: 2, t_max: 2 };
        let s0 = empty(4, 16);
        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_merkle_leaf(params, s0, b1);
        // Wrong starting state for the second leaf (not l1's final).
        let s1_wrong = empty(4, 16);
        let b2 = vec![
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_merkle_leaf(params, s1_wrong, b2);

        match merge_two_countmin_merkle(&l1, &l2) {
            Err(CountMinMerkleMergeError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("merge must reject mismatched boundary"),
        }
    }
}
