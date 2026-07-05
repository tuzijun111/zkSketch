//! plonky3 (STARK) **decode / query circuits** — prove `answer =
//! release(decode(committed state))`, the STARK-backend counterpart of the
//! plonky2 `decode` family (EVAL_SPEC E3).
//!
//! Unlike the update leaves (which prove a *transition* `Com(S_{t-1}) →
//! Com(S_t)`), a decode circuit proves a **query answer against one committed
//! state**: it re-hashes the whole state in-circuit (binding it to the
//! published `Com(S)`), then proves the family's query relation over the
//! witnessed cells. Cost is therefore `Θ(s)` in the state size `s` (the
//! whole-state re-hash) plus the small per-query relation — exactly the E3
//! dependence on `s`, not on stream length.
//!
//! Decode proofs are **self-contained** (not chained): each prover self-verifies
//! (`verify_all_tables`) internally and returns a [`DecodeProof`] wrapping the
//! batch-STARK output plus the released answer. The per-phase timing split is
//! recorded via [`crate::recursion::recursive::timing`] (read it right after the
//! prove, as the E1/E3 runners do).
//!
//! Families: [`countmin`] (point-frequency = min of `d` cells). SS/HLL/GK decode
//! mirror the same harness over their respective relations.

pub mod countmin;
pub mod gk_bandmerge;
pub mod greenwald_khanna;
pub mod hyperloglog;
pub mod spacesaving;

use p3_recursion::RecursionOutput;

use crate::recursion::recursive::config::ConfigWithFriParams;

/// A deterministic, in-circuit **release policy** applied to the raw decoded
/// answer (the verifiable counterpart of an output-privacy layer). Matches the
/// plonky2 `decode::ReleasePolicy` semantics exactly.
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
    /// Native application (matches the in-circuit logic bit-for-bit).
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

/// A self-contained plonky3 decode proof: the batch-STARK output and the
/// released answer it certifies (a public input). The prover self-verifies, so
/// `output` is already a checked proof.
pub struct DecodeProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub answer: u64,
}

impl DecodeProof {
    /// Serialized proof size in bytes (postcard, matching the E1/E3 size metric).
    pub fn proof_size(&self) -> usize {
        postcard::to_allocvec(&self.output.0).map(|v| v.len()).unwrap_or(0)
    }
}
