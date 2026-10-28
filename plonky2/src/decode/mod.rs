//! Decode (query) circuits: prove a query answer against a committed sketch state.

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
