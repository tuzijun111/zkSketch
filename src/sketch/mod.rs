//! Sketch-family traits and Phase-2 stubs.
//!
//! Phase 1 carries the trait shapes so the wiring into the rest of the project
//! (boundary commitments, leaf AIRs, recursive merge) is already there. The
//! concrete `CountMin` implementation lives in `countmin.rs` and is empty for
//! now — Phase 2 fills it in following §5.4 of the paper.

pub mod countmin;
pub mod countmin_c_merkle;
pub mod countmin_final;
pub mod countmin_memcheck;
pub mod countmin_merkle;
pub mod countmin_omc;
pub mod countmin_omc_gl;
pub mod countmin_replay;
pub mod countmin_v3;
pub mod countmin_v9;
pub mod gk_bandmerge;
pub mod gk_bandmerge_gl;
pub mod gk_final;
pub mod gk_final_full;
pub mod greenwald_khanna;
pub mod greenwald_khanna_naive;
pub mod hll_final;
pub mod hll_final_full;
pub mod hll_merkle;
pub mod hll_omc;
pub mod hll_omc_gl;
pub mod hyperloglog;
pub mod spacesaving;
pub mod spacesaving_naive;
pub mod ss_final;
pub mod ss_final_full;
pub mod ss_final_full_gl;

/// One streaming sketch family. Matches the paper's `A_τ.Update(S, u)` style.
pub trait Sketch {
    type Params;
    type State;
    type Update;

    fn new(params: &Self::Params) -> Self::State;
    fn update(state: &mut Self::State, u: &Self::Update);
}

/// A sketch family that admits per-batch delta certificates (paper §5.1).
/// The `Delta` summarises how a batch of updates changes the touched cells of
/// the state without replaying the per-record decode procedure inside the
/// proving circuit.
pub trait DeltaCert: Sketch {
    type Delta;

    fn build_delta(prev: &Self::State, batch: &[Self::Update]) -> Self::Delta;
}
