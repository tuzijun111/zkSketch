//! Recursive chain over Count-Min leaves: each `extend` folds the current root and
//! a new leaf into one aggregation proof covering `[1, t]`.

use core::fmt;

use p3_recursion::{BatchOnly, build_and_prove_aggregation_layer};

use crate::recursion::digest::{boundary_leaf_digest, combine_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::{CountMinLeafProof, make_leaf_config};
use crate::recursion::recursive::countmin_merge::{
    CountMinChainProof, CountMinMergeError, agg_params, merge_two_countmin,
};

/// Accumulating chain state. The current `root` certifies leaves `1..=E`
/// where `E = root.num_leaves()`. Cloning is cheap (the inner
/// `RecursionOutput` holds an `Rc<CircuitProverData>`).
pub struct CountMinChainState {
    pub root: CountMinChainProof,
}

impl fmt::Debug for CountMinChainState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CountMinChainState")
            .field("E", &self.root.num_leaves())
            .field("interval", &self.root.interval)
            .field("initial", &self.root.initial)
            .field("final_", &self.root.final_)
            .finish()
    }
}

impl CountMinChainState {
    /// Initialise the chain from two leaves — same as `merge_two_countmin`.
    pub fn init(
        l1: &CountMinLeafProof,
        l2: &CountMinLeafProof,
    ) -> Result<Self, CountMinMergeError> {
        let root = merge_two_countmin(l1, l2)?;
        Ok(Self { root })
    }

    /// Extend the chain by one leaf. Returns `BoundaryMismatch` if the
    /// new leaf's `initial` commit doesn't match the current chain's
    /// `final_`. Otherwise runs one aggregation prover call:
    /// `new_root = merge(chain_root, new_leaf)`.
    pub fn extend(&mut self, new_leaf: &CountMinLeafProof) -> Result<(), CountMinMergeError> {
        if self.root.final_ != new_leaf.initial {
            return Err(CountMinMergeError::BoundaryMismatch {
                left_final: self.root.final_,
                right_initial: new_leaf.initial,
            });
        }

        let config = make_leaf_config();
        let backend: Backend = make_backend();
        let params = agg_params();

        // Left = current chain root (already a batch-STARK).
        // Right = fresh leaf (also a batch-STARK in the §4.2 path).
        let left_input = self.root.recursive_proof.into_recursion_input::<BatchOnly>();
        let right_input = new_leaf.output.into_recursion_input::<BatchOnly>();

        let new_recursive_proof = build_and_prove_aggregation_layer::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            EXT_D,
        >(&left_input, &right_input, &config, &backend, &params, None)
        .map_err(|e| CountMinMergeError::AggregationFailed(format!("{e:?}")))?;

        // Extend the digest: H_{[1, E+1]} = combine(1, E, E+1, H_{[1, E]}, leaf_digest_new).
        let prev_e = self.root.num_leaves() as u64;
        let new_e = prev_e + 1;
        let new_leaf_dig =
            boundary_leaf_digest(&new_leaf.initial.0, &new_leaf.final_.0, new_e);
        let new_digest = combine_digest(1, prev_e, new_e, &self.root.digest, &new_leaf_dig);

        // Splice the new boundary / batch into the proof.
        let prev_final = self.root.final_;
        self.root.recursive_proof = new_recursive_proof;
        self.root.interval = (1, new_e);
        self.root.final_ = new_leaf.final_;
        self.root.internal_boundaries.push(prev_final);
        self.root.batches.push(new_leaf.batch.to_vec());
        self.root.digest = new_digest;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_leaf::{D, W, prove_countmin_leaf};
    use crate::recursion::recursive::countmin_merge::verify_chain_countmin;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMin, CountMinParams, CountMinState, CountMinUpdate};

    fn empty_state() -> CountMinState {
        CountMin::new(&CountMinParams { d: D, w: W })
    }

    /// Three epochs chained: init(l1, l2) then extend(l3). Final chain
    /// proof should verify, and the boundary structure should be
    /// `[initial, l1.final_, l2.final_, final_]`.
    #[test]
    fn chain_of_three_accepts() {
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
        let l2 = prove_countmin_leaf(s1.clone(), b2);

        let mut s2 = s1;
        for u in &b2 {
            CountMin::update(&mut s2, u);
        }
        let b3 = [
            CountMinUpdate { key: 99, value: 6 },
            CountMinUpdate { key: 13, value: 8 },
        ];
        let l3 = prove_countmin_leaf(s2, b3);

        let mut state = CountMinChainState::init(&l1, &l2).expect("init");
        state.extend(&l3).expect("extend");

        verify_chain_countmin(&state.root).expect("verify chain of 3");

        assert_eq!(state.root.num_leaves(), 3);
        assert_eq!(state.root.interval, (1, 3));
        assert_eq!(state.root.initial, l1.initial);
        assert_eq!(state.root.final_, l3.final_);
        assert_eq!(state.root.internal_boundaries.len(), 2);
        assert_eq!(state.root.internal_boundaries[0], l1.final_);
        assert_eq!(state.root.internal_boundaries[1], l2.final_);
    }

    /// Extending with a leaf whose initial doesn't match the chain's final
    /// must error at the boundary check, before any aggregation runs.
    #[test]
    fn extend_with_bad_boundary_rejected() {
        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 1, value: 1 },
            CountMinUpdate { key: 2, value: 1 },
        ];
        let l1 = prove_countmin_leaf(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            CountMin::update(&mut s1, u);
        }
        let b2 = [
            CountMinUpdate { key: 3, value: 1 },
            CountMinUpdate { key: 4, value: 1 },
        ];
        let l2 = prove_countmin_leaf(s1, b2);

        // Wrong starting state for l3 — won't match the chain's final.
        let s_wrong = empty_state();
        let b3 = [
            CountMinUpdate { key: 5, value: 1 },
            CountMinUpdate { key: 6, value: 1 },
        ];
        let l3 = prove_countmin_leaf(s_wrong, b3);

        let mut state = CountMinChainState::init(&l1, &l2).expect("init");
        match state.extend(&l3) {
            Err(CountMinMergeError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("extend must reject mismatched boundary"),
        }
    }
}
