//! §4.3 **linear** recursive chain over privacy-preserving v9 Count-Min epochs.
//!
//! The paper's simplest recursive schedule, `Π^(t) = merge(Π^(t-1), π_t)`: each
//! [`CountMinChainStateV9::extend`] folds the accumulating chain root (an
//! aggregation proof) with one fresh leaf into a new aggregation that
//! recursively verifies **both** children — so the single carried proof
//! certifies the whole interval `[1, t]` at `O(1)` verifier cost. The chain
//! therefore only ever performs `agg + leaf` merges and never the `agg + agg`
//! that [`countmin_forest_v9`](super::countmin_forest_v9)'s Bentley–Saxe tree
//! hits.
//!
//! This mirrors [`countmin_chain::CountMinChainState`](super::countmin_chain),
//! which folds the original flat `CountMinLeafProof`, but operates on
//! [`CountMinLeafProofV9`] — the envelope the streaming runner's `lookup` (omc)
//! and `merkle` (c_merkle) leaves wrap into (see
//! `experiments::e6_forest::prove_leaf_full`). That makes the linear chain a
//! drop-in **comparison baseline** against
//! [`prove_countmin_forest_v9`](super::countmin_forest_v9::prove_countmin_forest_v9)'s
//! `O(log t)`-depth tree fold: identical leaves and merge atom, different
//! schedule (linear `O(t)` depth vs tree `O(log t)` depth).
//!
//! It reuses [`countmin_merge_v9`](super::countmin_merge_v9)'s two-leaf base
//! case ([`merge_two_countmin_v9`]) and its verifier
//! ([`verify_chain_countmin_v9`]) unchanged — that verifier already replays the
//! linear digest schedule (`H_{[1,E]} = combine(1, E-1, E, H_{[1,E-1]}, d_E)`),
//! so a chain built here verifies without a new verifier.

use p3_recursion::{build_and_prove_aggregation_layer, BatchOnly};

use crate::recursion::digest::{combine_digest, leaf_digest};
use crate::recursion::recursive::backend::{make_backend, Backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::make_leaf_config;
use crate::recursion::recursive::countmin_leaf_v9::CountMinLeafProofV9;
use crate::recursion::recursive::countmin_merge_v9::{
    agg_params, merge_two_countmin_v9, v9_leaf_digest_bound, CountMinChainProofV9,
    CountMinMergeErrorV9,
};

/// Accumulating linear-chain state. After every [`extend`](Self::extend) the
/// carried `root` certifies leaves `1..=E` where `E = root.num_leaves()`.
/// Cloning the inner proof is cheap (its `RecursionOutput` holds an `Rc`).
pub struct CountMinChainStateV9 {
    pub root: CountMinChainProofV9,
}

impl CountMinChainStateV9 {
    /// Initialise from two leaves — the two-leaf base case, identical to
    /// [`merge_two_countmin_v9`].
    pub fn init(
        l1: &CountMinLeafProofV9,
        l2: &CountMinLeafProofV9,
    ) -> Result<Self, CountMinMergeErrorV9> {
        Ok(Self { root: merge_two_countmin_v9(l1, l2)? })
    }

    /// Extend the chain by one leaf: `new_root = merge(chain_root, new_leaf)`.
    ///
    /// Returns [`BoundaryMismatch`](CountMinMergeErrorV9::BoundaryMismatch) — before
    /// any proving — if the new leaf's `initial` commit does not match the
    /// chain's current `final_`. Otherwise runs one `agg + leaf` aggregation
    /// (the chain root is an aggregation output, the new leaf a batch-STARK)
    /// and extends the linear digest.
    pub fn extend(&mut self, new_leaf: &CountMinLeafProofV9) -> Result<(), CountMinMergeErrorV9> {
        if self.root.final_ != new_leaf.initial {
            return Err(CountMinMergeErrorV9::BoundaryMismatch {
                left_final: self.root.final_,
                right_initial: new_leaf.initial,
            });
        }

        let config = make_leaf_config();
        let backend: Backend = make_backend();
        let params = agg_params();

        // Left = current chain root (an aggregation); right = fresh leaf.
        let left_input = self.root.recursive_proof.into_recursion_input::<BatchOnly>();
        let right_input = new_leaf.output.into_recursion_input::<BatchOnly>();

        let new_recursive_proof = build_and_prove_aggregation_layer::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            EXT_D,
        >(&left_input, &right_input, &config, &backend, &params, None)
        .map_err(|e| CountMinMergeErrorV9::AggregationFailed(format!("{e:?}")))?;

        // Linear digest extend: H_{[1,E+1]} = combine(1, E, E+1, H_{[1,E]}, d_leaf).
        // Matches the replay loop in `verify_chain_countmin_v9`.
        let prev_e = self.root.num_leaves() as u64;
        let new_e = prev_e + 1;
        let new_leaf_dig = leaf_digest(
            &v9_leaf_digest_bound(&new_leaf.initial),
            &v9_leaf_digest_bound(&new_leaf.final_),
            new_e,
        );
        let new_digest = combine_digest(1, prev_e, new_e, &self.root.digest, &new_leaf_dig);

        // Splice the new boundary / batch into the proof.
        let prev_final = self.root.final_;
        self.root.recursive_proof = new_recursive_proof;
        self.root.interval = (1, new_e);
        self.root.final_ = new_leaf.final_;
        self.root.internal_boundaries.push(prev_final);
        self.root.batch_commits.push(new_leaf.batch_commit);
        self.root.digest = new_digest;
        Ok(())
    }
}

/// Prove a linear §4.3 chain over `E ≥ 2` contiguous v9 leaves: `init(l0, l1)`
/// then `extend` left-to-right. The headline analog of
/// [`prove_countmin_forest_v9`](super::countmin_forest_v9::prove_countmin_forest_v9)
/// for the linear schedule; the returned proof verifies with
/// [`verify_chain_countmin_v9`].
///
/// Panics if fewer than two leaves are supplied (a programmer error — the
/// chain has no two-leaf base case below that). A non-contiguous history is
/// surfaced as [`BoundaryMismatch`](CountMinMergeErrorV9::BoundaryMismatch).
pub fn prove_countmin_chain_v9(
    leaves: &[CountMinLeafProofV9],
) -> Result<CountMinChainProofV9, CountMinMergeErrorV9> {
    assert!(leaves.len() >= 2, "linear chain needs ≥ 2 leaves, got {}", leaves.len());
    let mut state = CountMinChainStateV9::init(&leaves[0], &leaves[1])?;
    for leaf in &leaves[2..] {
        state.extend(leaf)?;
    }
    Ok(state.root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_leaf::{D, W};
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9;
    use crate::recursion::recursive::countmin_merge_v9::{
        merge_two_countmin_v9, verify_chain_countmin_v9,
    };
    use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
    use crate::sketch::countmin_v9::CountMinV9;
    use crate::sketch::Sketch;

    fn empty_state() -> CountMinState {
        CountMinV9::new(&CountMinParams { d: D, w: W })
    }

    /// Build a contiguous run of `n` honest native-v9 leaves over distinct
    /// batches (cheap leaf; mirrors `countmin_forest_v9`'s `honest_leaves`).
    fn honest_leaves(n: u64) -> Vec<CountMinLeafProofV9> {
        let mut state = empty_state();
        let mut leaves = Vec::with_capacity(n as usize);
        for i in 0..n {
            let batch = [
                CountMinUpdate { key: 1 + 2 * i, value: (1 + i) as u32 },
                CountMinUpdate { key: 2 + 2 * i, value: (2 + i) as u32 },
            ];
            let leaf = prove_countmin_leaf_v9(state.clone(), batch);
            for u in &batch {
                CountMinV9::update(&mut state, u);
            }
            leaves.push(leaf);
        }
        leaves
    }

    /// At `E = 2` the linear chain IS the two-leaf merge: same boundaries and
    /// the same digest (linear == tree at the base case).
    #[test]
    fn chain_two_matches_merge() {
        let leaves = honest_leaves(2);
        let chain = prove_countmin_chain_v9(&leaves).expect("chain of 2");
        verify_chain_countmin_v9(&chain).expect("verify chain of 2");

        let merge = merge_two_countmin_v9(&leaves[0], &leaves[1]).expect("merge");
        assert_eq!(chain.interval, (1, 2));
        assert_eq!(chain.initial, leaves[0].initial);
        assert_eq!(chain.final_, leaves[1].final_);
        assert_eq!(chain.digest, merge.digest, "E=2: chain digest == merge digest");
    }

    /// Three leaves chained: `init(l0, l1)` then `extend(l2)`. The root
    /// certifies `[1, 3]`, verifies, and carries the right boundary structure
    /// `[l0.final == l1.initial, l1.final == l2.initial]`.
    #[test]
    fn chain_three_accepts() {
        let leaves = honest_leaves(3);
        let chain = prove_countmin_chain_v9(&leaves).expect("chain of 3");
        verify_chain_countmin_v9(&chain).expect("verify chain of 3");

        assert_eq!(chain.num_leaves(), 3);
        assert_eq!(chain.interval, (1, 3));
        assert_eq!(chain.initial, leaves[0].initial);
        assert_eq!(chain.final_, leaves[2].final_);
        assert_eq!(chain.internal_boundaries.len(), 2);
        assert_eq!(chain.internal_boundaries[0], leaves[0].final_);
        assert_eq!(chain.internal_boundaries[1], leaves[1].final_);
    }

    /// Extending with a leaf whose `initial` doesn't match the chain's `final_`
    /// is rejected at the boundary check, before any aggregation runs.
    #[test]
    fn chain_rejects_bad_boundary() {
        let leaves = honest_leaves(2);
        let mut state = CountMinChainStateV9::init(&leaves[0], &leaves[1]).expect("init");

        // A leaf starting from a fresh (wrong) state — won't chain.
        let bad = prove_countmin_leaf_v9(
            empty_state(),
            [
                CountMinUpdate { key: 100, value: 1 },
                CountMinUpdate { key: 101, value: 1 },
            ],
        );
        match state.extend(&bad) {
            Err(CountMinMergeErrorV9::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("extend must reject mismatched boundary"),
        }
    }

    /// Baseline contrast with the tree fold. At `E = 4` the forest performs an
    /// `agg + agg` top merge while the linear chain stays left-leaning, so the
    /// two schedules diverge: the chain and forest roots agree on **every**
    /// boundary (`initial`, `final_`, all internals) but carry **different**
    /// digests (each root verifies only under its own schedule's verifier).
    /// Slow (chain-of-4 + forest-of-4 = 6 recursive proofs); run with
    /// `--ignored`.
    #[test]
    #[ignore = "slow: builds a 4-leaf chain and a 4-leaf forest (6 recursive proofs)"]
    fn chain_four_diverges_from_forest_schedule() {
        use crate::recursion::recursive::countmin_forest_v9::{
            prove_countmin_forest_v9, verify_forest_countmin_v9,
        };

        let leaves = honest_leaves(4);
        let chain = prove_countmin_chain_v9(&leaves).expect("chain of 4");
        let forest = prove_countmin_forest_v9(&leaves).expect("forest of 4");

        verify_chain_countmin_v9(&chain).expect("chain verifies under its schedule");
        verify_forest_countmin_v9(&forest).expect("forest verifies under its schedule");

        // Same certified history: identical outer + internal boundaries.
        assert_eq!(chain.initial, forest.initial);
        assert_eq!(chain.final_, forest.final_);
        assert_eq!(chain.internal_boundaries, forest.internal_boundaries);

        // Different schedule ⇒ different digest (the chain never does agg+agg,
        // so its left-leaning combine diverges from the tree's at E ≥ 4).
        assert_ne!(
            chain.digest, forest.digest,
            "E=4: linear and tree schedules must produce distinct digests"
        );
    }
}
