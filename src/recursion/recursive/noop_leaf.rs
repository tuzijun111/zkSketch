//! No-op leaves (empty state, no-op batch) per BabyBear family; they have the same VK
//! as real leaves of the same parameters and stand in for them when deriving root VKs.

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

/// [`cm_omc_noop_leaf_expose`] with an explicit [`CommitMode`] (revision B2).
/// The no-op leaf opens all three commitments with the public zero salt
/// ([`Openings::public_zero`](crate::commitment::hiding::Openings::public_zero),
/// through the explicit `prove_epoch_public_zero` path), so `ρ_in = ρ_out`
/// and it still exposes `init == final`; the salts are witnesses, so its VK
/// is that of every real leaf of the same mode.
pub fn cm_omc_noop_leaf_commit(
    params: crate::sketch::countmin_omc::CmOmcParams,
    expose: Expose,
    binding: crate::sketch::bind::Binding,
    mode: crate::commitment::hiding::CommitMode,
) -> Proof {
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_omc::build_countmin_omc_leaf_commit;
    use crate::sketch::countmin_v9::CountMinV9;

    let state = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });
    let batch = vec![CountMinUpdate { key: 0, value: 0 }; params.batch];
    build_countmin_omc_leaf_commit(params, expose, binding, mode)
        .prove_epoch_public_zero(1, state, batch)
        .output
        .0
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

/// [`ss_full_noop_leaf_expose`] with an explicit
/// [`CommitMode`](crate::commitment::hiding::CommitMode) (revision B2). The
/// no-op leaf opens all three commitments with the public zero salt
/// ([`Openings::public_zero`](crate::commitment::hiding::Openings::public_zero),
/// through the explicit `prove_epoch_public_zero` path), so `ρ_in = ρ_out`
/// and it still exposes `init == final`; the salts are witnesses, so its VK
/// is that of every real leaf of the same mode.
pub fn ss_full_noop_leaf_commit(
    params: crate::sketch::ss_final_full::SsFullParams,
    expose: Expose,
    mode: crate::commitment::hiding::CommitMode,
) -> Proof {
    use crate::sketch::ss_final_full::{SsFullState, SsFullUpdate, build_ss_full_leaf_commit};
    let batch = vec![SsFullUpdate::dummy(); params.batch];
    build_ss_full_leaf_commit(params, expose, mode)
        .prove_epoch_public_zero(1, SsFullState::empty(params), batch)
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

/// [`gk2_noop_leaf_expose`] with an explicit binding and [`CommitMode`]
/// (revision B2). The no-op leaf (empty state, empty batch) opens all three
/// commitments with the public zero salt
/// ([`Openings::public_zero`](crate::commitment::hiding::Openings::public_zero),
/// through the explicit `prove_epoch_public_zero` path), so `ρ_in = ρ_out`
/// and it still exposes `init == final`; the salts are witnesses, so its VK
/// is that of every real leaf of the same mode.
pub fn gk2_noop_leaf_commit(
    params: crate::sketch::gk_bandmerge::GkbParams,
    expose: Expose,
    binding: crate::sketch::bind::Binding,
    mode: crate::commitment::hiding::CommitMode,
) -> Proof {
    use crate::sketch::gk_bandmerge::GkRounds;
    gk2_noop_leaf_rounds(params, expose, binding, mode, GkRounds::SortedCopy)
}

/// [`gk2_noop_leaf_commit`] with an explicit round certification
/// ([`GkRounds`](crate::sketch::gk_bandmerge::GkRounds), M3): the no-op leaf
/// of the `rounds` leaf circuit, whose VK is that of every real leaf of the
/// variant. `GkRounds::SortedCopy` is [`gk2_noop_leaf_commit`] byte for byte.
pub fn gk2_noop_leaf_rounds(
    params: crate::sketch::gk_bandmerge::GkbParams,
    expose: Expose,
    binding: crate::sketch::bind::Binding,
    mode: crate::commitment::hiding::CommitMode,
    rounds: crate::sketch::gk_bandmerge::GkRounds,
) -> Proof {
    use crate::sketch::gk_bandmerge::{Gk2State, build_gkb2_leaf_rounds};
    build_gkb2_leaf_rounds(params, expose, binding, mode, rounds)
        .prove_epoch_public_zero(1, Gk2State::empty(params), Vec::new())
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

/// [`hll_omc_noop_leaf_expose`] with an explicit [`CommitMode`] (revision
/// B2), over the same no-op input (key 1 re-inserted into a state that
/// already holds it). The no-op leaf opens all three commitments with the
/// public zero salt
/// ([`Openings::public_zero`](crate::commitment::hiding::Openings::public_zero),
/// through the explicit `prove_epoch_public_zero` path, which accepts only
/// this public no-op input, since for HLL a real batch of repeated keys can
/// also leave every register unchanged), so the init and final salts are
/// equal and it still exposes `init == final`; the salts are witnesses, so
/// its VK is that of every real leaf of the same mode.
pub fn hll_omc_noop_leaf_commit(
    params: crate::sketch::hll_omc::HllOmcParams,
    expose: Expose,
    binding: crate::sketch::bind::Binding,
    mode: crate::commitment::hiding::CommitMode,
) -> Proof {
    use crate::sketch::hll_omc::{build_hll_omc_leaf_commit, hll_omc_advance_with, hll_omc_empty};
    let mut regs = hll_omc_empty(params.b);
    hll_omc_advance_with(&mut regs, &[1], params.m(), binding);
    build_hll_omc_leaf_commit(params, expose, binding, mode)
        .prove_epoch_public_zero(1, regs, vec![1; params.batch])
        .output
        .0
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

/// [`bloom_omc_noop_leaf_expose`] with an explicit
/// [`CommitMode`](crate::commitment::hiding::CommitMode) (revision B2). The
/// no-op leaf (empty filter, all-dummy batch) opens all three commitments
/// with the public zero salt
/// ([`Openings::public_zero`](crate::commitment::hiding::Openings::public_zero),
/// through the explicit `prove_epoch_public_zero` path), so `ρ_in = ρ_out`
/// and it still exposes `init == final`; the salts are witnesses, so its VK
/// is that of every real leaf of the same mode.
pub fn bloom_omc_noop_leaf_commit(
    params: crate::sketch::bloom_omc::BloomOmcParams,
    expose: Expose,
    mode: crate::commitment::hiding::CommitMode,
) -> Proof {
    use crate::sketch::bloom_omc::{bloom_empty, build_bloom_omc_leaf_commit};
    build_bloom_omc_leaf_commit(params, expose, mode)
        .prove_epoch_public_zero(1, &bloom_empty(&params), &[])
        .output
        .0
}

/// The packed-byte Bloom leaf's no-op (M2, `crate::sketch::bloom_packed`):
/// the empty filter `0^{M_w}` and an all-dummy batch at batch index 1, all
/// three commitments opened with the public zero salt (so it exposes
/// `init == final = Com(0^{M_w}; 0)`, family 7 under `Hiding`). The state,
/// records, splits, salts and index are witnesses, so its VK is that of every
/// real packed leaf of the same `(k, log_w, batch)`, layout and mode.
pub fn bloom_packed_noop_leaf_commit(
    params: crate::sketch::bloom_packed::BloomPackedParams,
    expose: Expose,
    mode: crate::commitment::hiding::CommitMode,
) -> Proof {
    use crate::sketch::bloom_packed::{build_bloom_packed_leaf_commit, packed_empty};
    build_bloom_packed_leaf_commit(params, expose, mode)
        .prove_epoch_public_zero(1, &packed_empty(&params), &[])
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

/// [`kmv_noop_leaf_expose`] with an explicit
/// [`CommitMode`](crate::commitment::hiding::CommitMode) (revision B2). The
/// no-op leaf (empty state, all-dummy batch) opens all three commitments
/// with the public zero salt
/// ([`Openings::public_zero`](crate::commitment::hiding::Openings::public_zero),
/// through the explicit `prove_records_public_zero` path), so `ρ_in = ρ_out`
/// and it still exposes `init == final`; the salts are witnesses, so its VK
/// is that of every real leaf of the same mode. Under `Plain` it is
/// [`kmv_noop_leaf_expose`], op for op.
pub fn kmv_noop_leaf_commit(
    params: crate::sketch::kmv::KmvParams,
    expose: Expose,
    binding: crate::sketch::bind::Binding,
    mode: crate::commitment::hiding::CommitMode,
) -> Proof {
    use crate::sketch::kmv::{KmvState, build_kmv_leaf_commit};
    build_kmv_leaf_commit(params, expose, binding, mode)
        .prove_records_public_zero(1, KmvState::empty(params.k), vec![None; params.batch])
        .output
        .0
}
