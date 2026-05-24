//! Accumulating chain root (paper §4.3 — the simplest recursive schedule).
//!
//! Phase 1 only supports the two-leaf case (`init`). Extending the root by one
//! more leaf (`extend`) corresponds to one merge atom per arrival; the §4.3
//! description applies but we leave the implementation for Phase 1.5 once the
//! in-circuit merge is available.

use crate::prover::LeafProof;
use crate::recursion::flat::{ChainProof, MergeError, merge_two};

pub struct ChainState {
    pub root: ChainProof,
}

impl ChainState {
    /// Initialise the root from two leaf proofs. This is the two-leaf base
    /// case of the recursive chain.
    pub fn init(l1: LeafProof, l2: LeafProof) -> Result<Self, MergeError> {
        Ok(Self {
            root: merge_two(l1, l2)?,
        })
    }

    /// Append one more leaf to the right of the current root.
    ///
    /// Phase 1.5: replace the current §4.1 `ChainProof` with a single
    /// recursive merge that consumes `self.root` + the new leaf and emits a
    /// fresh `ChainProof` over the extended interval. Today this would still
    /// be flat (we'd just push another leaf into `root.leaves`), which is
    /// not the §4.3 semantics, so we refuse rather than mislead.
    pub fn extend(&mut self, _next: LeafProof) -> Result<(), MergeError> {
        todo!("Phase 1.5: recursive chain extension via plonky3-recursion merge atom (§4.2/§4.3)")
    }
}
