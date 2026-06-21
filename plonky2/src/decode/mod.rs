//! E3 decode/query circuits — prove `answer = decode(committed state)`.
//!
//! Unlike the update leaves (which prove a transition), a decode circuit proves
//! a **query answer against a committed state**: it re-hashes the whole state
//! in-circuit (binding it to the published `Com(S_t)`), then proves the query
//! relation over the witnessed cells. Cost is therefore `Θ(s)` in the state
//! size (the whole-state re-hash) plus the small per-query relation — exactly
//! the EVAL_SPEC E3 dependence on `s`, not on stream length.
//!
//! Decode proofs are **self-contained** (not chained), so they return a
//! [`DecodeProof`] rather than a recursion `Node`.
//!
//! Families: [`countmin`] (point-frequency = min of `d` cells), [`spacesaving`]
//! (heavy-hitter frequency), [`greenwald_khanna`] (rank/quantile). An optional
//! [`ReleasePolicy`] post-processes the answer in-circuit (identity / threshold
//! suppression) and the proof certifies the *released* value.

pub mod countmin;
pub mod greenwald_khanna;
pub mod hyperloglog;
pub mod spacesaving;

use std::sync::Arc;

use anyhow::Result;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::config::{C, D, F};

/// A deterministic, in-circuit release policy applied to the raw decoded answer
/// (the verifiable counterpart of an output-privacy layer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleasePolicy {
    /// Release the raw answer.
    Identity,
    /// Suppress below `θ`: release `answer` if `answer >= θ`, else `0`.
    Threshold(u64),
}

impl ReleasePolicy {
    pub fn name(&self) -> &'static str {
        match self {
            ReleasePolicy::Identity => "identity",
            ReleasePolicy::Threshold(_) => "threshold",
        }
    }
    /// Native application (matches the in-circuit logic).
    pub fn apply(&self, raw: u64) -> u64 {
        match self {
            ReleasePolicy::Identity => raw,
            ReleasePolicy::Threshold(t) => {
                if raw >= *t {
                    raw
                } else {
                    0
                }
            }
        }
    }
}

/// A self-contained decode proof: the circuit data, the proof, and the released
/// answer it certifies (public input).
pub struct DecodeProof {
    pub data: Arc<CircuitData<F, C, D>>,
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub answer: u64,
}

impl DecodeProof {
    pub fn verify(&self) -> Result<()> {
        self.data.verify(self.proof.clone())
    }
    pub fn proof_bytes(&self) -> usize {
        self.proof.to_bytes().len()
    }
}
