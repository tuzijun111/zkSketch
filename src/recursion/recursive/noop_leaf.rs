//! Public **no-op leaves** for root-VK derivation (BabyBear families).
//!
//! Each function proves the family's boundary-exposing leaf circuit for the
//! given public parameters over data-free input: the empty state and a batch
//! of the family's provable no-op records (the same no-ops the streaming
//! harness pads split batches with — `stream_compose::PAD_KEY`). The result
//! exposes `initial == final`, so it can stand in for every leaf when a
//! [`crate::recursion::recursive::root_vk::ShapeVkDeriver`] rebuilds a
//! forest's merge circuits (see
//! [`crate::recursion::recursive::expose_forest::root_vk_deriver`]).
//!
//! Its VK ([`derive_leaf_vk`]) equals the VK of every real leaf of the same
//! parameters: the leaf circuits take the sketch data only as witnesses
//! (asserted per family by `expose_forest::tests::real_*_vks_are_data_independent`
//! and the derivation tests below).
//!
//! The `*_expose` / `*_interval` variants prove the family's
//! Interval-statement leaf (B6(b)) at batch index 1; the index is a witness,
//! so every real Interval leaf of the same parameters has the same VK
//! (asserted by `interval_tests`).

use p3_circuit_prover::BatchStarkProof;

use crate::config::Challenge;
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;
use crate::recursion::recursive::expose_forest::vk_pin_values;
use crate::recursion::recursive::statement::Expose;

type Proof = BatchStarkProof<ConfigWithFriParams>;

/// A leaf's VK — the value a root-VK derivation starts from.
pub fn derive_leaf_vk(noop_leaf: &Proof) -> Vec<Challenge> {
    vk_pin_values(noop_leaf)
}

/// Count-Min v9 exposed leaf: `value = 0` updates (`new = old + 0`).
pub fn cm_v9_noop_leaf(params: CountMinLeafParams) -> Proof {
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_exposed_with_params;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_v9::CountMinV9;

    let state = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });
    let batch = vec![CountMinUpdate { key: 0, value: 0 }; params.batch];
    prove_countmin_leaf_v9_exposed_with_params(params, state, batch).output.0
}

/// Count-Min `omc` exposed leaf: `value = 0` updates.
pub fn cm_omc_noop_leaf(params: crate::sketch::countmin_omc::CmOmcParams) -> Proof {
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_omc::build_countmin_omc_leaf;
    use crate::sketch::countmin_v9::CountMinV9;

    let state = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });
    let batch = vec![CountMinUpdate { key: 0, value: 0 }; params.batch];
    build_countmin_omc_leaf(params, true).prove_epoch(state, batch).output.0
}

/// [`cm_omc_noop_leaf`] with an explicit statement ([`Expose`]) and binding;
/// an Interval no-op leaf is proved at batch index 1 (the index is a witness,
/// so the VK does not depend on it).
pub fn cm_omc_noop_leaf_expose(
    params: crate::sketch::countmin_omc::CmOmcParams,
    expose: Expose,
    binding: crate::sketch::bind::Binding,
) -> Proof {
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_omc::build_countmin_omc_leaf_expose;
    use crate::sketch::countmin_v9::CountMinV9;

    let state = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });
    let batch = vec![CountMinUpdate { key: 0, value: 0 }; params.batch];
    build_countmin_omc_leaf_expose(params, expose, binding).prove_epoch_at(1, state, batch).output.0
}

/// HyperLogLog (`hll_final_full`) exposed leaf: inactive (`dummy`) updates.
pub fn hll_full_noop_leaf(params: crate::sketch::hll_final_full::HllFullParams) -> Proof {
    use crate::sketch::hll_final_full::{HllFullState, HllFullUpdate, prove_hll_full_exposed};
    let batch = vec![HllFullUpdate::dummy(); params.batch];
    prove_hll_full_exposed(params, HllFullState::empty(params), batch).output.0
}

/// SpaceSaving (`ss_final_full`) exposed leaf: inactive (`dummy`) updates.
pub fn ss_full_noop_leaf(params: crate::sketch::ss_final_full::SsFullParams) -> Proof {
    use crate::sketch::ss_final_full::{SsFullState, SsFullUpdate, prove_ss_full_exposed};
    let batch = vec![SsFullUpdate::dummy(); params.batch];
    prove_ss_full_exposed(params, SsFullState::empty(params), batch).output.0
}

/// [`ss_full_noop_leaf`] with an explicit statement ([`Expose`]); an
/// Interval no-op leaf is proved at batch index 1.
pub fn ss_full_noop_leaf_expose(
    params: crate::sketch::ss_final_full::SsFullParams,
    expose: Expose,
) -> Proof {
    use crate::sketch::ss_final_full::{SsFullState, SsFullUpdate, build_ss_full_leaf_expose};
    let batch = vec![SsFullUpdate::dummy(); params.batch];
    build_ss_full_leaf_expose(params, expose)
        .prove_epoch_at(1, SsFullState::empty(params), batch)
        .output
        .0
}

/// Greenwald–Khanna (`gk_final_full`) exposed leaf: inactive (`dummy`) updates.
pub fn gk_full_noop_leaf(params: crate::sketch::gk_final_full::GKFullParams) -> Proof {
    use crate::sketch::gk_final_full::{GKFullState, GKFullUpdate, prove_gk_full_exposed};
    let batch = vec![GKFullUpdate::dummy(); params.batch];
    prove_gk_full_exposed(params, GKFullState::empty(params), batch).output.0
}

/// GK band-merge (`gk_bandmerge`, gk2) exposed leaf: an empty batch (the
/// prover pads the fresh-tuple rows with `E_MAX` dummies; `n` does not move).
pub fn gk2_noop_leaf(params: crate::sketch::gk_bandmerge::GkbParams) -> Proof {
    use crate::sketch::gk_bandmerge::{Gk2State, prove_gkb2_exposed};
    prove_gkb2_exposed(params, Gk2State::empty(params), Vec::new()).output.0
}

// ─── Interval-statement no-op leaves (B6(b)) ────────────────────────────────
//
// Each proves the family's Interval-statement leaf circuit at batch index 1
// over the same data-free no-op input as its Boundary counterpart above. The
// batch index is a witness, so the VK does not depend on it, and the
// derivation merges a no-op subtree with ITSELF through the twin merge
// (`expose_forest::root_vk_deriver`), so one no-op leaf serves every shape.

/// [`gk2_noop_leaf`] with an explicit statement ([`Expose`]).
pub fn gk2_noop_leaf_expose(params: crate::sketch::gk_bandmerge::GkbParams, expose: Expose) -> Proof {
    use crate::sketch::gk_bandmerge::{Gk2State, build_gkb2_leaf_expose};
    build_gkb2_leaf_expose(params, expose)
        .prove_epoch_at(1, Gk2State::empty(params), Vec::new())
        .output
        .0
}

/// [`hll_full_noop_leaf`] with the Interval statement.
pub fn hll_full_noop_leaf_interval(params: crate::sketch::hll_final_full::HllFullParams) -> Proof {
    use crate::sketch::hll_final_full::{HllFullState, HllFullUpdate, prove_hll_full_interval};
    let batch = vec![HllFullUpdate::dummy(); params.batch];
    prove_hll_full_interval(params, 1, HllFullState::empty(params), batch).output.0
}

/// [`gk_full_noop_leaf`] with the Interval statement.
pub fn gk_full_noop_leaf_interval(params: crate::sketch::gk_final_full::GKFullParams) -> Proof {
    use crate::sketch::gk_final_full::{GKFullState, GKFullUpdate, prove_gk_full_interval};
    let batch = vec![GKFullUpdate::dummy(); params.batch];
    prove_gk_full_interval(params, 1, GKFullState::empty(params), batch).output.0
}

/// [`cm_v9_noop_leaf`] with the Interval statement.
pub fn cm_v9_noop_leaf_interval(params: CountMinLeafParams) -> Proof {
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_interval_with_params;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_v9::CountMinV9;

    let state = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });
    let batch = vec![CountMinUpdate { key: 0, value: 0 }; params.batch];
    prove_countmin_leaf_v9_interval_with_params(params, 1, state, batch).output.0
}

/// HyperLogLog `omc` leaf with an explicit statement ([`Expose`]) and
/// binding: every record re-inserts key 1 into a state that already holds it
/// (`max` is idempotent), exactly the stream harness's HLL no-op.
pub fn hll_omc_noop_leaf_expose(
    params: crate::sketch::hll_omc::HllOmcParams,
    expose: Expose,
    binding: crate::sketch::bind::Binding,
) -> Proof {
    use crate::sketch::hll_omc::{build_hll_omc_leaf_expose, hll_omc_advance_with, hll_omc_empty};
    let mut regs = hll_omc_empty(params.b);
    hll_omc_advance_with(&mut regs, &[1], params.m(), binding);
    build_hll_omc_leaf_expose(params, expose, binding)
        .prove_epoch_at(1, regs, vec![1; params.batch])
        .output
        .0
}

/// Bloom-filter `omc` leaf with an explicit statement ([`Expose`]): the
/// empty filter and a batch of canonical dummy records only (`act = 0`
/// records OR in nothing, so `initial == final`; the stream harness strips
/// its `PAD_KEY` slots into exactly these dummies). An Interval no-op leaf is
/// proved at batch index 1, so `lo == hi`; the index is a witness, so every
/// real Interval leaf of the same `(k, log_w, batch)` has this VK.
pub fn bloom_omc_noop_leaf_expose(
    params: crate::sketch::bloom_omc::BloomOmcParams,
    expose: Expose,
) -> Proof {
    use crate::sketch::bloom_omc::{bloom_empty, build_bloom_omc_leaf_expose};
    build_bloom_omc_leaf_expose(params, expose)
        .prove_epoch_at(1, &bloom_empty(&params), &[])
        .output
        .0
}

/// KMV / bottom-`k` leaf with an explicit statement ([`Expose`]) and
/// binding: the empty state and an all-dummy batch (dummies never change the
/// state, so the leaf exposes `initial == final`). An Interval no-op leaf is
/// proved at batch index 1.
pub fn kmv_noop_leaf_expose(
    params: crate::sketch::kmv::KmvParams,
    expose: Expose,
    binding: crate::sketch::bind::Binding,
) -> Proof {
    use crate::sketch::kmv::{KmvState, build_kmv_leaf_expose};
    build_kmv_leaf_expose(params, expose, binding)
        .prove_records_at(1, KmvState::empty(params.k), vec![None; params.batch])
        .output
        .0
}
