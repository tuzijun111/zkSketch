//! Plaintext sketches + their native Poseidon commitments.
//!
//! Each sketch defines an update rule and a Pattern-A delta aggregation (the
//! per-cell merge is associative/commutative, so epochs can be proven
//! independently and recursively merged). Mirrors `../src/sketch/`.
//!
//! The [`greenwald_khanna`]/[`spacesaving`] modules carry the **batched** §5.4/§G
//! pipelines (the in-circuit shape). The [`greenwald_khanna_simple`]/
//! [`spacesaving_simple`] modules carry the **simple per-record** Pattern-B
//! sketches (sorted-list GK / Misra-Gries SS) ported from
//! `../src/sketch/{greenwald_khanna,spacesaving}.rs`, kept alongside the batched
//! versions as baselines.

pub mod countmin;
pub mod greenwald_khanna;
pub mod greenwald_khanna_simple;
pub mod hyperloglog;
pub mod spacesaving;
pub mod spacesaving_simple;

/// One streaming sketch family. Matches the paper's `A_τ.Update(S, u)` style.
/// Port of `../src/sketch/mod.rs::Sketch`.
pub trait Sketch {
    type Params;
    type State;
    type Update;

    fn new(params: &Self::Params) -> Self::State;
    fn update(state: &mut Self::State, u: &Self::Update);
}

/// A sketch family that admits per-batch delta certificates (paper §5.1). The
/// `Delta` summarises how a batch changes the touched cells of the state without
/// replaying the per-record decode inside the proving circuit. Port of
/// `../src/sketch/mod.rs::DeltaCert`.
pub trait DeltaCert: Sketch {
    type Delta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta;
}
