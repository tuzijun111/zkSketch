//! Plaintext sketches and their Poseidon commitments.

pub mod countmin;
pub mod gk_bandmerge2;
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
