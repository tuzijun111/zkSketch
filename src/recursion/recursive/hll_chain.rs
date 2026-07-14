//! §4.3 recursive chain over HyperLogLog update epochs.
//!
//! `HllChainState` is the accumulating root of the paper's recursive
//! chain schedule for HLL leaves: `Π^(t) = merge(Π^(t-1), π_t)`. Structurally
//! identical to `CountMinChainState` — only the leaf-proof type differs.
//! After every `extend(leaf)` call, the carried `HllChainProof` certifies the
//! whole interval `[1, t]`; verifier work stays `O(1)` regardless of `t`.

use core::fmt;

use p3_recursion::{BatchOnly, build_and_prove_aggregation_layer};

use crate::recursion::digest::{boundary_leaf_digest, combine_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::hll_leaf::{HllLeafProof, make_leaf_config};
use crate::recursion::recursive::hll_merge::{
    HllChainProof, HllMergeError, agg_params, merge_two_hll,
};

/// Accumulating chain state. The current `root` certifies leaves `1..=E`
/// where `E = root.num_leaves()`.
pub struct HllChainState {
    pub root: HllChainProof,
}

impl fmt::Debug for HllChainState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HllChainState")
            .field("E", &self.root.num_leaves())
            .field("interval", &self.root.interval)
            .field("initial", &self.root.initial)
            .field("final_", &self.root.final_)
            .finish()
    }
}

impl HllChainState {
    /// Initialise the chain from two leaves — same as `merge_two_hll`.
    pub fn init(l1: &HllLeafProof, l2: &HllLeafProof) -> Result<Self, HllMergeError> {
        let root = merge_two_hll(l1, l2)?;
        Ok(Self { root })
    }

    /// Extend the chain by one leaf. Returns `BoundaryMismatch` if the new
    /// leaf's `initial` commit doesn't match the current chain's `final_`.
    pub fn extend(&mut self, new_leaf: &HllLeafProof) -> Result<(), HllMergeError> {
        if self.root.final_ != new_leaf.initial {
            return Err(HllMergeError::BoundaryMismatch {
                left_final: self.root.final_,
                right_initial: new_leaf.initial,
            });
        }

        let config = make_leaf_config();
        let backend: Backend = make_backend();
        let params = agg_params();

        let left_input = self.root.recursive_proof.into_recursion_input::<BatchOnly>();
        let right_input = new_leaf.output.into_recursion_input::<BatchOnly>();

        let new_recursive_proof = build_and_prove_aggregation_layer::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            EXT_D,
        >(&left_input, &right_input, &config, &backend, &params, None)
        .map_err(|e| HllMergeError::AggregationFailed(format!("{e:?}")))?;

        let prev_e = self.root.num_leaves() as u64;
        let new_e = prev_e + 1;
        let new_leaf_dig =
            boundary_leaf_digest(&new_leaf.initial.0, &new_leaf.final_.0, new_e);
        let new_digest = combine_digest(1, prev_e, new_e, &self.root.digest, &new_leaf_dig);

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
    use crate::recursion::recursive::hll_leaf::{B, prove_hll_leaf};
    use crate::recursion::recursive::hll_merge::verify_chain_hll;
    use crate::sketch::Sketch;
    use crate::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogState, HyperLogLogUpdate};

    fn empty_state() -> HyperLogLogState {
        HyperLogLog::new(&HyperLogLogParams { b: B })
    }

    /// Three epochs chained: init(l1, l2) then extend(l3). Final chain
    /// proof should verify, and the boundary structure should be
    /// `[initial, l1.final_, l2.final_, final_]`.
    #[test]
    fn hll_chain_of_three_accepts() {
        let s0 = empty_state();
        let b1 = [
            HyperLogLogUpdate { key: 0x1111_2222_3333_4444 },
            HyperLogLogUpdate { key: 0x5555_6666_7777_8888 },
        ];
        let l1 = prove_hll_leaf(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            HyperLogLog::update(&mut s1, u);
        }
        let b2 = [
            HyperLogLogUpdate { key: 0x9999_AAAA_BBBB_CCCC },
            HyperLogLogUpdate { key: 0xDDDD_EEEE_FFFF_0000 },
        ];
        let l2 = prove_hll_leaf(s1.clone(), b2);

        let mut s2 = s1;
        for u in &b2 {
            HyperLogLog::update(&mut s2, u);
        }
        let b3 = [
            HyperLogLogUpdate { key: 0xFACE_FEED_C0FF_EE00 },
            HyperLogLogUpdate { key: 0xBAAD_F00D_DEAD_BEEF },
        ];
        let l3 = prove_hll_leaf(s2, b3);

        let mut state = HllChainState::init(&l1, &l2).expect("init");
        state.extend(&l3).expect("extend");

        verify_chain_hll(&state.root).expect("verify chain of 3");

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
    fn hll_extend_with_bad_boundary_rejected() {
        let s0 = empty_state();
        let b1 = [
            HyperLogLogUpdate { key: 0x1 },
            HyperLogLogUpdate { key: 0x2 },
        ];
        let l1 = prove_hll_leaf(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            HyperLogLog::update(&mut s1, u);
        }
        let b2 = [
            HyperLogLogUpdate { key: 0x3 },
            HyperLogLogUpdate { key: 0x4 },
        ];
        let l2 = prove_hll_leaf(s1, b2);

        // Wrong starting state for l3 — won't match the chain's final.
        let s_wrong = empty_state();
        let b3 = [
            HyperLogLogUpdate { key: 0x5 },
            HyperLogLogUpdate { key: 0x6 },
        ];
        let l3 = prove_hll_leaf(s_wrong, b3);

        let mut state = HllChainState::init(&l1, &l2).expect("init");
        match state.extend(&l3) {
            Err(HllMergeError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("extend must reject mismatched boundary"),
        }
    }
}
