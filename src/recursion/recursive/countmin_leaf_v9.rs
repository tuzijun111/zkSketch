//! Privacy-preserving §5.2 Count-Min update leaf (Phase 9c).
//!
//! Unlike v1/v2/v3 — which expose per-record `(key, value, pos)` tuples as
//! public inputs and leak the batch contents — this leaf implements the
//! paper's actual §5.2 PI shape: **`(initial_commit, final_commit,
//! batch_commit)`**, with everything per-record moved to private
//! witnesses. Keys are never disclosed.
//!
//! ### Phase 9c scope (this file)
//!
//! - Private `(key, value)` witnesses, bound to a public `batch_commit`
//!   via an in-circuit Poseidon2 hash of the encoded batch.
//! - In-circuit derivation of counter positions `pos_{k,i} = h_i(key_k)`
//!   under the v9 field-friendly hash family (see
//!   `src/sketch/countmin_v9.rs`). The native side computes `(k · a_i +
//!   b_i)` in BabyBear and reduces mod `w`; the in-circuit gadget
//!   reproduces this with a multiply-add gate, a bit-decomposition of
//!   the result, and a weighted sum of the bottom `log₂(w)` bits.
//! - All of v3's counter-grouping machinery (PermuteAir, adjacent-equality
//!   tags, running-sum aggregation, sparse-patch → cell delta) reused
//!   verbatim — operating on the in-circuit-derived positions now.
//!
//! ### Phase 9 scope (not yet in this file)
//!
//! - **9e (key-grouping)**: Without it, every record pays the in-circuit
//!   hash cost. With it, only `|distinct_keys|` records pay. That's where
//!   the duplicate-density curve will actually slope down. This is a
//!   follow-up.
//! - **9d (merge function)**: a v9-specific `merge_two_countmin_v9_private`
//!   that handles the new PI shape. Without it, v9 leaves cannot be
//!   chained.
//!
//! ### Constraints on `(d, w)`
//!
//! - `d ≤ 16` (v9 hash-family table size).
//! - **`w` must be a power of 2** in `{2, 4, 8, 16}` — Phase 9c's range
//!   check is a bottom-`log₂(w)`-bits extraction. Non-power-of-2 `w`
//!   would need an additional "r < w" check that we defer.
//! - `d * w` must be a multiple of 4 (Challenge extension degree — same
//!   constraint as v1/v2/v3 state-commitment).
//! - `m` (batch size) is free; private records pack as 4 Vals each into
//!   the batch hash input, so `4 * m` is automatically aligned.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_permute_trace, generate_poseidon2_trace,
    generate_range_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d4, poseidon2_preprocessor, range_air_builders, range_preprocessor,
        recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::countmin::commit_countmin;
use crate::commitment::countmin_batch::commit_batch;
use crate::commitment::{CountMinBatchCommit, CountMinCommit};
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::recursion::recursive::countmin_leaf::{
    CountMinLeafParams, DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMinState, CountMinUpdate};
use crate::sketch::countmin_v9::CountMinV9;

/// FRI parameters — match the v1/v2/v3 leaf config so the resulting proof
/// has the same shape (relevant if a v9-aware merge function is built
/// later in Phase 9d).
const LOG_FINAL_POLY_LEN: usize = 6;

/// Bit shift used to encode `(combined, value)` into a single Challenge
/// element for the PermuteAir input column. `SHIFT_VAL = 2^20` allows
/// per-record `value < 1 048 576` without overlapping the `combined`
/// bits — the same bound used by the v3 leaf.
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

#[cfg(test)]
thread_local! {
    /// Test-only malicious prover (`tests::forged_final_decomposition_*`):
    /// `Some(delta)` commits to a final state whose cell 0 is bumped by `delta`
    /// while the decomposition of that packed cell group, which every update
    /// constraint reads, still returns the honest counters.
    static FORGE_FINAL_CELL0: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Per-row hash family multipliers `a_i`. **Must match** the constants in
/// `src/sketch/countmin_v9.rs::HASH_A`. We re-declare here as a `Val`-
/// shaped array so we can index per-row at circuit-build time without a
/// `pub` export from the sketch module.
const HASH_A: [u32; 16] = [
    0x9E37_79B9, 0xBF58_476D, 0x94D0_49BB, 0x2545_F491, 0xD801_2304, 0xC2B2_AE3D,
    0xCBF2_9CE4, 0xC6BC_2796, 0xA243_F605, 0xB492_6F95, 0x82C1_2F3C, 0xF1BB_CDCB,
    0xD632_2D0C, 0x8E4F_47AB, 0xA537_82B0, 0xE369_15A1,
];
const HASH_B: [u32; 16] = [
    0xDEAD_BEEF, 0xCAFE_BABE, 0xFEED_FACE, 0xBAAA_AAAD, 0xABAD_CAFE, 0xDEFE_C8ED,
    0x0D15_EA5E, 0xBADD_F00D, 0xFACE_FEED, 0xCAFE_D00D, 0x1234_5678, 0x0FED_CBA9,
    0xAAAA_5555, 0x5555_AAAA, 0x0123_4567, 0xFEDC_BA98,
];

/// A successfully-proven privacy-preserving v9 Count-Min update epoch.
pub struct CountMinLeafProofV9 {
    pub output: RecursionOutput<ConfigWithFriParams>,
    /// `Com(S_{t-1})` — the input state commitment.
    pub initial: CountMinCommit,
    /// `Com(S_t)` — the output state commitment.
    pub final_: CountMinCommit,
    /// `C_B` — the batch commitment binding the *private* per-record data.
    pub batch_commit: CountMinBatchCommit,
    pub params: CountMinLeafParams,
}

/// Pack the flattened counters of a state into Challenge elements (same
/// layout as v1/v2/v3's state-commit absorption).
fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Pack the batch into Challenge elements — exactly the same encoding as
/// `commit_batch` uses natively, so the in-circuit hash gate reproduces
/// the same digest.
fn pack_batch_to_challenge(batch: &[CountMinUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = batch
        .iter()
        .flat_map(|r| {
            let key_lo = (r.key & 0xFFFF_FFFF) as u32;
            let key_hi = (r.key >> 32) as u32;
            [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(r.value),
                Val::ZERO,
            ]
        })
        .collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Prove one privacy-preserving Count-Min update epoch.
///
/// Convenience entry point at the default `(D, W, BATCH) = (2, 4, 2)`.
pub fn prove_countmin_leaf_v9(
    initial_state: CountMinState,
    batch: [CountMinUpdate;
        crate::recursion::recursive::countmin_leaf::BATCH],
) -> CountMinLeafProofV9 {
    let params = CountMinLeafParams::default();
    prove_countmin_leaf_v9_with_params(params, initial_state, batch.to_vec())
}

/// Runtime-parameterised privacy-preserving v9 leaf prover.
///
/// `params.w` must be a power of 2 in `{2, 4, 8, 16}` (see the module
/// docstring); the panic message is explicit if it isn't.
pub fn prove_countmin_leaf_v9_with_params(
    params: CountMinLeafParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinLeafProofV9 {
    prove_countmin_leaf_v9_inner(params, initial_state, batch, false)
}

/// Like [`prove_countmin_leaf_v9_with_params`] but also **surfaces the
/// boundary** `(Com(S_{i-1}), Com(S_i))` via the Expose NPO, so the proof's
/// public values carry the boundary into recursion. Used by the in-circuit
/// boundary-bound forest (`expose_forest`) to compose real Count-Min leaves;
/// the unexposed variant is left untouched so existing baselines are stable.
pub fn prove_countmin_leaf_v9_exposed_with_params(
    params: CountMinLeafParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinLeafProofV9 {
    prove_countmin_leaf_v9_inner(params, initial_state, batch, true)
}

/// Shared body for the v9 leaf prover. `expose_boundary` adds an Expose NPO
/// surfacing `(initial_commit, final_commit)` as the proof's public values.
fn prove_countmin_leaf_v9_inner(
    params: CountMinLeafParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    expose_boundary: bool,
) -> CountMinLeafProofV9 {
    prove_countmin_leaf_v9_stmt(params, initial_state, batch, Expose::from_bool(expose_boundary), 1)
}

/// Like [`prove_countmin_leaf_v9_exposed_with_params`] but with the
/// **Interval** statement for batch `t` (1-based): exposes
/// `(init, final, (t, t, 0, 0), Poseidon2(TAG_LEAF, t, Com(B_t)))` with the
/// in-circuit batch digest (see [`crate::recursion::recursive::statement`]).
pub fn prove_countmin_leaf_v9_interval_with_params(
    params: CountMinLeafParams,
    t: u64,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinLeafProofV9 {
    prove_countmin_leaf_v9_stmt(params, initial_state, batch, Expose::Interval, t)
}

fn prove_countmin_leaf_v9_stmt(
    params: CountMinLeafParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    expose: Expose,
    t: u64,
) -> CountMinLeafProofV9 {
    params.validate();
    assert_eq!(initial_state.params.d, params.d);
    assert_eq!(initial_state.params.w, params.w);
    assert_eq!(batch.len(), params.batch);
    assert!(
        params.w.is_power_of_two() && (1..=16).contains(&params.w),
        "v9 leaf requires w to be a power of 2 in {{2,4,8,16}}, got {}",
        params.w
    );

    // Native side: the honest key-sorted + counter-sorted views of the batch
    // (the §5.2 key-grouping hints the in-circuit verifier re-derives).
    let views = v9_honest_views(params, &batch);
    if cfg!(debug_assertions) {
        let mut replay = initial_state.clone();
        for u in &batch {
            CountMinV9::update(&mut replay, u);
        }
        debug_assert_eq!(
            replay.counters,
            v9_final_from_views(params, &initial_state, &views).counters,
            "view-derived final must equal the v9 replay"
        );
    }
    prove_v9_views_stmt(params, initial_state, batch, &views, expose, t)
}

/// The two sorted views every v9 private table is derived from: the key-sort
/// permute's output and the counter-sort permute's output. Honestly both are
/// sorts of their inputs; a soundness test may hand-craft them.
#[derive(Clone)]
struct V9Views {
    /// `key_sorted[i] = batch[sigma_key[i]]` (the key-sort permute's hint).
    sigma_key: Vec<usize>,
    /// Key-sorted records `(key_field, value)`, `key_field` = canonical `Val` key.
    key_sorted: Vec<(u64, u32)>,
    /// `ctr_sorted[i] = U_ctr[sigma[i]]` (the counter-sort permute's hint).
    sigma: Vec<usize>,
    /// Counter-sorted `(combined, value)` rows.
    ctr_sorted: Vec<(u64, u32)>,
}

/// Segment-end flags + per-row running sums of a sorted `(group, value)` list
/// (the in-circuit adjacency-tag gadget): `(eq_tag, acc, seg_end)`.
fn v9_group(rows: &[(u64, u32)]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let n = rows.len();
    let mut tag = vec![0u32; n];
    let mut acc = vec![0u32; n];
    for r in 0..n {
        if r > 0 && rows[r].0 == rows[r - 1].0 {
            tag[r] = 1;
            acc[r] = acc[r - 1].saturating_add(rows[r].1);
        } else {
            acc[r] = rows[r].1;
        }
    }
    let seg_end: Vec<u32> = (0..n)
        .map(|r| u32::from(r + 1 == n || tag[r + 1] == 0))
        .collect();
    (tag, acc, seg_end)
}

/// `U_ctr` (the counter-sort permute's input) of a key-sorted view: each row
/// hashed once per sketch row, carrying its segment total at segment ends and
/// 0 elsewhere.
fn v9_u_ctr(params: CountMinLeafParams, key_sorted: &[(u64, u32)]) -> Vec<(u64, u32)> {
    let (d, w) = (params.d, params.w);
    let (_, key_acc, g_active) = v9_group(key_sorted);
    let mut u = Vec::with_capacity(key_sorted.len() * d);
    for (r, &(kf, _)) in key_sorted.iter().enumerate() {
        let eff = if g_active[r] == 1 { key_acc[r] } else { 0 };
        for i in 0..d {
            let bucket = crate::sketch::countmin_v9::hash_cell_v9(i, kf, w);
            u.push(((i * w + bucket) as u64, eff));
        }
    }
    u
}

/// The honest views: sort the batch by key, then sort `U_ctr` by address.
fn v9_honest_views(params: CountMinLeafParams, batch: &[CountMinUpdate]) -> V9Views {
    let mut indexed_keys: Vec<(usize, &CountMinUpdate)> = batch.iter().enumerate().collect();
    indexed_keys.sort_by_key(|(_, u)| u.key);
    let sigma_key: Vec<usize> = indexed_keys.iter().map(|(i, _)| *i).collect();
    let key_sorted: Vec<(u64, u32)> = indexed_keys
        .iter()
        .map(|(_, u)| {
            let kf = <Val as p3_field::PrimeField64>::as_canonical_u64(&Val::from_u64(u.key));
            (kf, u.value)
        })
        .collect();
    let u_ctr = v9_u_ctr(params, &key_sorted);
    let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr.iter().enumerate().collect();
    indexed.sort_by_key(|(_, (combined, _))| *combined);
    let sigma: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let ctr_sorted: Vec<(u64, u32)> = indexed.iter().map(|(_, r)| **r).collect();
    V9Views {
        sigma_key,
        key_sorted,
        sigma,
        ctr_sorted,
    }
}

/// The final state the circuit certifies for given views: `S_0` plus each
/// counter segment's total at its address.
fn v9_final_from_views(
    params: CountMinLeafParams,
    initial: &CountMinState,
    views: &V9Views,
) -> CountMinState {
    let w = params.w;
    let (_, acc, seg_end) = v9_group(&views.ctr_sorted);
    let mut fin = initial.clone();
    for (r, &(c, _)) in views.ctr_sorted.iter().enumerate() {
        if seg_end[r] == 1 {
            let (row, col) = (c as usize / w, c as usize % w);
            fin.counters[row][col] = fin.counters[row][col].wrapping_add(acc[r]);
        }
    }
    fin
}

// ── Hardened permute encoding (revision Step 1) ──────────────────────────
//
// The legacy leaf packs both permute domains into ONE base element `x·2^20 + v`
// (coordinate 0), which is unsound twice over:
//
// 1. **Shared PermuteBus.** The fork concatenates every `add_permute` into ONE
//    PermuteAir whose PermuteBus message is the 4 value coordinates only (no op
//    id), so the key-sort and counter-sort permutes only prove that the union
//    of their inputs equals the union of their outputs. A record with a small
//    key `k < d·w` (`k·2^20 + v`) is also a valid counter payload "cell k += v":
//    a prover moves it into the counter-sort output — a direct, un-hashed
//    increment — and pays with another key's counter payload decoded as a fake
//    record (`tests::v9_shared_bus_forgery_rejected`).
// 2. **Packed split.** The sorted views are split from ONE in-field equation
//    `payload = x·2^20 + v` in two free witnesses: `(c − 1, v + 2^20)` re-splits
//    `(c, v)` (moving an increment to the neighbouring cell), and a key-sort row
//    re-splits into a garbage key (`tests::v9_packed_split_forgery_rejected`).
//    On BabyBear `1920·2^20 = p − 1`, so range checks alone cannot fix it.
//
// The hardened encoding keeps the two fields in separate coordinates and tags
// each domain in its own coordinate:
//     key sort:     (key_field, value, 1, 0) = key_field + value·X + X²
//     counter sort: (combined,  value, 0, 1) = combined  + value·X + X³
// Injective once every coordinate is BASE: `key_field_sorted` is (the hash's
// bit decomposition), `combined_sorted` is (active rows: the one-hot cell
// selector; inactive rows: equal to the next row via the eq-tag chain), and
// `val_sorted_by_key` / `val_sorted` are pinned by [`assert_base`]. The X²/X³
// tags make the two domains disjoint on the shared bus, so per-op multiset
// equality holds. (Like every constraint here, this presumes bound
// decompositions and constants.)

/// Whether [`prove_countmin_leaf_v9`] uses the hardened tuple encoding.
/// Always on outside tests; the soundness PoCs build the legacy circuit.
fn use_hardened() -> bool {
    #[cfg(test)]
    if let Some(v) = HARDENED.with(|c| c.get()) {
        return v;
    }
    true
}

#[cfg(test)]
thread_local! {
    /// Test-only override of [`use_hardened`] (`Some(false)` = legacy circuit).
    static HARDENED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    /// Test-only malicious prover: `(k, outputs)` makes permute op `k` (0 = key
    /// sort, 1 = counter sort) emit `outputs`.
    static FORGE: std::cell::RefCell<Vec<(usize, Vec<Challenge>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Force `x` into the BASE field (31-bit RangeAir decomposition of coefficient
/// 0; the byte window covers `[0, p)`, so no base value is excluded).
fn assert_base(b: &mut CircuitBuilder<Challenge>, x: ExprId) {
    b.add_range_bits::<Val>(x, Val::bits()).expect("assert_base");
}

/// A permute element: legacy `x·2^20 + v`, or the hardened tuple
/// `x + v·X + X^(2+domain)` (`domain` 0 = key sort, 1 = counter sort).
#[cfg(test)]
fn v9_elem(x: u64, v: u32, hardened: bool, domain: usize) -> Challenge {
    use p3_field::BasedVectorSpace;
    let c = if hardened {
        let mut c = [Val::from_u64(x), Val::from_u32(v), Val::ZERO, Val::ZERO];
        c[2 + domain] = Val::ONE;
        c
    } else {
        [
            Val::from_u64(x) * Val::from_u64(SHIFT_VAL) + Val::from_u32(v),
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
        ]
    };
    Challenge::from_basis_coefficients_slice(&c).expect("4 coeffs")
}

/// Build, run, prove and self-verify the v9 leaf for given (honest or
/// hand-crafted) views; the certified final is [`v9_final_from_views`].
fn prove_v9_views(
    params: CountMinLeafParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    views: &V9Views,
    expose_boundary: bool,
) -> CountMinLeafProofV9 {
    prove_v9_views_stmt(params, initial_state, batch, views, Expose::from_bool(expose_boundary), 1)
}

/// [`prove_v9_views`] with an explicit statement ([`Expose`]) and batch index.
fn prove_v9_views_stmt(
    params: CountMinLeafParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    views: &V9Views,
    expose: Expose,
    t: u64,
) -> CountMinLeafProofV9 {
    let expose_boundary = expose == Expose::Boundary;
    let CountMinLeafParams { d, w, batch: m } = params;
    let num_cells = params.num_cells();
    let cell_packing = params.cell_packing();
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let hardened = use_hardened();

    let final_state = v9_final_from_views(params, &initial_state, views);
    // The state the proof commits to as `Com(S_t)`: the view-derived update,
    // except under the test-only forged-decomposition prover below.
    #[allow(unused_mut)]
    let mut committed_final = final_state.clone();
    #[cfg(test)]
    let forge_delta = FORGE_FINAL_CELL0.with(|c| c.get());
    #[cfg(test)]
    if let Some(delta) = forge_delta {
        committed_final.counters[0][0] += delta;
    }
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&committed_final);
    let batch_commit = commit_batch(&batch);

    let sigma_key = views.sigma_key.clone();
    let key_field_sorted_native: Vec<u64> = views.key_sorted.iter().map(|r| r.0).collect();
    let val_sorted_by_key_native: Vec<u32> = views.key_sorted.iter().map(|r| r.1).collect();
    let (key_eq_tag_native, _, _) = v9_group(&views.key_sorted);
    let sigma = views.sigma.clone();
    let combined_sorted_native: Vec<u64> = views.ctr_sorted.iter().map(|r| r.0).collect();
    let val_sorted_native: Vec<u32> = views.ctr_sorted.iter().map(|r| r.1).collect();
    let (tag_native, _, a_active_native) = v9_group(&views.ctr_sorted);

    // ─── Build the circuit ───────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    crate::recompose_binding::configure(&mut b);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    if hardened {
        b.enable_range(generate_range_trace::<Val, Challenge>);
    }
    if expose.exposes() {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    // ---- Public inputs: (initial, final, batch) commits = 6 Challenge slots ----
    let initial_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Surface the boundary (initial, final) commitments via the Expose NPO so
    // they propagate into recursion as `air_public_targets` (consumed by the
    // in-circuit boundary-bound forest). These PI wires get connected to the
    // hashed commitments below, so the exposed values equal the real commits.
    if expose_boundary {
        b.add_expose(&[
            initial_commit_pis[0],
            initial_commit_pis[1],
            final_commit_pis[0],
            final_commit_pis[1],
        ])
        .expect("add_expose boundary");
    }

    // ---- Constants ----
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    // Basis constants of the hardened tuple encoding (x + v·X + X² / X³).
    let basis = |i: usize| -> Challenge {
        use p3_field::BasedVectorSpace;
        let mut c = [Val::ZERO; 4];
        c[i] = Val::ONE;
        Challenge::from_basis_coefficients_slice(&c).expect("basis")
    };
    // (Allocated only when hardened, so the legacy graph stays identical.)
    let (x_const, x2_const, x3_const) = if hardened {
        (
            b.alloc_const(basis(1), "X"),
            b.alloc_const(basis(2), "X^2"),
            b.alloc_const(basis(3), "X^3"),
        )
    } else {
        (zero, zero, zero)
    };
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
    // 2^32 mod BabyBear, used to reconstruct a Val key from (key_lo, key_hi).
    // `Challenge::from_u64(1u64 << 32)` embeds the u64 as a base-coefficient
    // Challenge with field reduction; same value as the native side computes
    // when reconstructing `key_lo + key_hi · 2^32` in `Val::from_u64`.
    let two_pow_32_const = b.alloc_const(Challenge::from_u64(1u64 << 32), "2^32");
    let row_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "row_i"))
        .collect();
    let cell_idx_consts: Vec<ExprId> = (0..num_cells)
        .map(|idx| b.alloc_const(Challenge::from_u64(idx as u64), "cell_idx"))
        .collect();
    let hash_a_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(HASH_A[i] as u64), "hash_a"))
        .collect();
    let hash_b_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(HASH_B[i] as u64), "hash_b"))
        .collect();
    // Power-of-two constants for the bit-decomposition weighted sum.
    let pow2_consts: Vec<ExprId> = (0..w_log2)
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();

    // ---- Private inputs ----
    // Packed cells for state commitments.
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    // Packed batch for the batch commitment hash. m records × 4 Vals
    // per record, packed 4 at a time into a Challenge — so one Challenge
    // per record.
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();

    // Per-record private (key_lo, key_hi, value) witnesses — consistent
    // with `batch_packed` via the decomposition below.
    let mut key_lo: Vec<ExprId> = Vec::with_capacity(m);
    let mut key_hi: Vec<ExprId> = Vec::with_capacity(m);
    let mut value_w: Vec<ExprId> = Vec::with_capacity(m);
    for _ in 0..m {
        key_lo.push(b.alloc_private_input("key_lo"));
        key_hi.push(b.alloc_private_input("key_hi"));
        value_w.push(b.alloc_private_input("value"));
    }

    // ── Phase 9g additions: sorted-by-key private witnesses ──
    //
    // The prover supplies the key-sorted view of the raw batch as a hint.
    // The circuit verifies (a) it's a valid permutation of the raw
    // (via PermuteAir on key payloads), (b) equal-key rows are adjacent
    // (via adjacent-equality tags), and (c) the running-sum aggregation
    // is consistent with the supplied key_acc.
    let key_field_sorted: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("key_field_sorted"))
        .collect();
    let val_sorted_by_key: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("val_sorted_by_key"))
        .collect();
    let key_eq_tag_w: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("key_eq_tag"))
        .collect();
    let key_inv_diff: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("key_inv_diff"))
        .collect();

    // Sorted-side decoded values for counter-sort (unchanged).
    let combined_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("combined_sorted"))
        .collect();
    let val_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("val_sorted"))
        .collect();

    let eq_tag: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("eq_tag"))
        .collect();
    let inv_diff: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("inv_diff"))
        .collect();

    let mut sel_a_cell: Vec<Vec<ExprId>> = Vec::with_capacity(n_ctr);
    for _ in 0..n_ctr {
        let row: Vec<ExprId> = (0..num_cells)
            .map(|_| b.alloc_private_input("sel_a_cell"))
            .collect();
        sel_a_cell.push(row);
    }

    // ---- Constraints ----

    // 1. Hash gates: bind packed cells / batch to public commitments.
    let digest_init = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &initial_packed, true)
        .expect("hash initial");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], initial_commit_pis[i]);
    }
    let digest_final = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
    }
    let digest_batch = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_batch[i], batch_commit_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (7th public input) and
    // H = Poseidon2(TAG_LEAF, t, digest_batch). Range only when hardened.
    if expose.is_interval() {
        let pin = if hardened { IndexPin::Range } else { IndexPin::Bits };
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &Poseidon2Config::BABY_BEAR_D4_W16,
            &initial_commit_pis,
            &final_commit_pis,
            &digest_batch,
            zero,
            crate::sketch::bind::Binding::Semantic,
            pin,
        );
    }

    // 2. Decompose packed cells into individual base-embedded ExprIds.
    let initial_cells: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    let final_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    assert_eq!(initial_cells.len(), num_cells);
    assert_eq!(final_cells.len(), num_cells);

    // 3. Decompose batch_packed into per-record base elements + connect
    //    to the (key_lo, key_hi, value) private witnesses. This is what
    //    binds the private per-record witnesses to the batch_commit PI.
    for k in 0..m {
        let coeffs = b
            .decompose_ext_to_base_coeffs::<Val>(batch_packed[k])
            .expect("decompose batch_packed");
        // coeffs = [key_lo, key_hi, value, padding(=0)]
        b.connect(coeffs[0], key_lo[k]);
        b.connect(coeffs[1], key_hi[k]);
        b.connect(coeffs[2], value_w[k]);
        b.connect(coeffs[3], zero);
    }

    // 4. Reconstruct key_field per raw record (key_lo + 2^32 · key_hi).
    let mut key_field: Vec<ExprId> = Vec::with_capacity(m);
    for k in 0..m {
        let hi_shifted = b.mul(key_hi[k], two_pow_32_const);
        let kf = b.add(key_lo[k], hi_shifted);
        key_field.push(kf);
    }

    // ─── Phase 9g — in-circuit key-grouping verification ─────────────────
    //
    // 5a. Build the per-record key payload: payload_key[k] = key_field[k] ·
    //     SHIFT_VAL + value_w[k]. Each (key, value) row encodes into one
    //     Challenge element. PermuteAir then enforces multiset equality
    //     against the sorted view.
    let mut key_payload: Vec<ExprId> = Vec::with_capacity(m);
    for k in 0..m {
        let kp = if hardened {
            // key-sort tuple (key_field, value, 1, 0).
            let t = b.mul_add(value_w[k], x_const, x2_const);
            b.add(key_field[k], t)
        } else {
            let kf_shifted = b.mul(key_field[k], shift_val_const);
            b.add(kf_shifted, value_w[k])
        };
        key_payload.push(kp);
    }

    // 5b. PermuteAir on key payloads with the σ_key witness. The output
    //     bound `multiset(sorted) == multiset(raw)` makes it impossible
    //     for the prover to introduce records the raw batch doesn't have.
    let key_payload_sorted: Vec<ExprId> = b
        .add_permute(&key_payload, sigma_key.clone())
        .expect("add_permute (key sort)");

    // 5c. Decode each sorted payload into (key_field_sorted[r],
    //     val_sorted_by_key[r]). Same SHIFT_VAL encoding; the prover-
    //     supplied private witnesses are forced to satisfy the encoding
    //     constraint, which (given the bit budget) uniquely determines
    //     them.
    for r in 0..m {
        let recovered = if hardened {
            // key-sort tuple (key_field_sorted, val_sorted_by_key, 1, 0); the
            // value coordinate is pinned to the base field (the key is, by the
            // hash's bit decomposition below).
            assert_base(&mut b, val_sorted_by_key[r]);
            let t = b.mul_add(val_sorted_by_key[r], x_const, x2_const);
            b.add(key_field_sorted[r], t)
        } else {
            // LEGACY (unsound): one in-field equation in two free witnesses.
            let kfs = b.mul(key_field_sorted[r], shift_val_const);
            b.add(kfs, val_sorted_by_key[r])
        };
        b.connect(recovered, key_payload_sorted[r]);
    }

    // 5d. Adjacent-equality tags on the sorted keys (PoneglyphDB §4.3
    //     Eq 7-8). Slot 0 forced to 0 (no preceding row).
    b.connect(key_eq_tag_w[0], zero);
    b.connect(key_inv_diff[0], zero);
    for r in 1..m {
        let diff = b.sub(key_field_sorted[r - 1], key_field_sorted[r]);
        let lhs1 = b.mul(key_eq_tag_w[r], diff);
        b.connect(lhs1, zero);
        let one_minus_tag = b.sub(one, key_eq_tag_w[r]);
        let diff_inv = b.mul(diff, key_inv_diff[r]);
        let one_minus_diff_inv = b.sub(one, diff_inv);
        let lhs2 = b.mul(one_minus_tag, one_minus_diff_inv);
        b.connect(lhs2, zero);
    }

    // 5e. Running-sum aggregation per key segment.
    //     key_acc[0] = val_sorted_by_key[0].
    //     key_acc[r] = val_sorted_by_key[r] + key_eq_tag_w[r] · key_acc[r-1].
    let mut key_acc: Vec<ExprId> = Vec::with_capacity(m);
    key_acc.push(val_sorted_by_key[0]);
    for r in 1..m {
        let carried = b.mul(key_eq_tag_w[r], key_acc[r - 1]);
        let new_acc = b.add(val_sorted_by_key[r], carried);
        key_acc.push(new_acc);
    }

    // 5f. Segment-end flag g_active[r] = 1 iff this row closes its
    //     key segment. Last row always closes (no successor).
    let mut g_active: Vec<ExprId> = Vec::with_capacity(m);
    for r in 0..m {
        let active = if r == m - 1 {
            one
        } else {
            b.sub(one, key_eq_tag_w[r + 1])
        };
        g_active.push(active);
    }

    // ─── Phase 9g — position hashing over the sorted-by-key view ─────────
    //
    // 6. Compute pos_sorted[r][i] = h_i(key_field_sorted[r]) via the field-
    //    friendly hash gadget. Every sorted row is hashed once per sketch
    //    row — m · d invocations total, independent of |distinct|.
    //
    // 7. Build U_ctr payload with g_active-gated values:
    //    payload[r·d + i] = (i·w + pos_sorted[r][i]) · SHIFT_VAL
    //                     + g_active[r] · key_acc[r]
    //    Inactive rows (g_active[r] = 0) contribute zero to the
    //    state delta — their segment's total has already been collapsed
    //    into the segment-end row that comes after them in sorted order.
    let mut payload: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..m {
        let effective_val = b.mul(g_active[r], key_acc[r]);
        for i in 0..d {
            // hash gadget — same as before but keyed off key_field_sorted[r].
            let prod = b.mul(key_field_sorted[r], hash_a_consts[i]);
            let mixed = b.add(prod, hash_b_consts[i]);
            let bits = b
                .decompose_to_bits::<Val>(mixed, Val::bits())
                .expect("decompose mixed");
            let mut pos_sum = b.mul(bits[0], pow2_consts[0]);
            for j in 1..w_log2 {
                let term = b.mul(bits[j], pow2_consts[j]);
                pos_sum = b.add(pos_sum, term);
            }
            // Build the payload entry inline.
            let row_times_w = b.mul(row_consts[i], w_const);
            let combined_expr = b.add(row_times_w, pos_sum);
            let payload_expr = if hardened {
                // counter-sort tuple (combined, value, 0, 1).
                let t = b.mul_add(effective_val, x_const, x3_const);
                b.add(combined_expr, t)
            } else {
                let combined_shifted = b.mul(combined_expr, shift_val_const);
                b.add(combined_shifted, effective_val)
            };
            payload.push(payload_expr);
        }
    }

    // 6. Counter-sort via PermuteAir.
    let payload_sorted: Vec<ExprId> = b
        .add_permute(&payload, sigma.clone())
        .expect("add_permute");

    // 7. Decode payload_sorted into (combined_sorted, val_sorted).
    for r in 0..n_ctr {
        let recovered = if hardened {
            // counter-sort tuple (combined_sorted, val_sorted, 0, 1); the value
            // coordinate is pinned to the base field (combined_sorted is, by the
            // cell selector / eq-tag chain below).
            assert_base(&mut b, val_sorted[r]);
            let t = b.mul_add(val_sorted[r], x_const, x3_const);
            b.add(combined_sorted[r], t)
        } else {
            // LEGACY (unsound): one in-field equation in two free witnesses.
            let combined_shifted = b.mul(combined_sorted[r], shift_val_const);
            b.add(combined_shifted, val_sorted[r])
        };
        b.connect(recovered, payload_sorted[r]);
    }

    // 8. Adjacent-equality tags (PoneglyphDB §4.3 Eq 7-8).
    b.connect(eq_tag[0], zero);
    b.connect(inv_diff[0], zero);
    for r in 1..n_ctr {
        let diff = b.sub(combined_sorted[r - 1], combined_sorted[r]);
        let lhs1 = b.mul(eq_tag[r], diff);
        b.connect(lhs1, zero);
        let one_minus_tag = b.sub(one, eq_tag[r]);
        let diff_inv = b.mul(diff, inv_diff[r]);
        let one_minus_diff_inv = b.sub(one, diff_inv);
        let lhs2 = b.mul(one_minus_tag, one_minus_diff_inv);
        b.connect(lhs2, zero);
    }

    // 9. Running sum.
    let mut acc: Vec<ExprId> = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        let new_acc = b.add(val_sorted[r], carried);
        acc.push(new_acc);
    }

    // 10. Per-row segment-end flag.
    let mut a_active: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let active = if r == n_ctr - 1 {
            one
        } else {
            b.sub(one, eq_tag[r + 1])
        };
        a_active.push(active);
    }

    // 11. Per-A-row cell selector validity.
    for r in 0..n_ctr {
        let sel = &sel_a_cell[r];
        for idx in 0..num_cells {
            let sm1 = b.sub(sel[idx], one);
            let prod = b.mul(sel[idx], sm1);
            b.connect(prod, zero);
        }
        let mut sum = sel[0];
        for idx in 1..num_cells {
            sum = b.add(sum, sel[idx]);
        }
        b.connect(sum, a_active[r]);

        let mut idx_acc = b.mul(cell_idx_consts[0], sel[0]);
        for idx in 1..num_cells {
            let term = b.mul(cell_idx_consts[idx], sel[idx]);
            idx_acc = b.add(idx_acc, term);
        }
        let active_combined = b.mul(a_active[r], combined_sorted[r]);
        b.connect(idx_acc, active_combined);
    }

    // 12. Per-cell delta from A + state transition.
    for idx in 0..num_cells {
        let mut delta_acc = b.mul(sel_a_cell[0][idx], acc[0]);
        for r in 1..n_ctr {
            let term = b.mul(sel_a_cell[r][idx], acc[r]);
            delta_acc = b.add(delta_acc, term);
        }
        let updated = b.add(initial_cells[idx], delta_acc);
        b.connect(updated, final_cells[idx]);
    }

    #[allow(unused_mut)]
    let mut circuit = b.build().expect("build v9 leaf circuit");
    #[cfg(test)]
    if forge_delta.is_some() {
        // Feed the constraints the honest counters of the forged cell group.
        use p3_field::BasedVectorSpace;
        let honest = pack_cells_to_challenge(&final_state)[0];
        let wid = circuit.private_input_rows[cell_packing];
        let coeffs: [Val; 4] = honest
            .as_basis_coefficients_slice()
            .try_into()
            .expect("4 coefficients");
        crate::sketch::forge_permute::forge_decomposition(&mut circuit, wid, coeffs);
    }
    // [test-only] malicious prover: swap in forged Permute outputs.
    #[cfg(test)]
    for (k, outs) in FORGE.with(|f| f.take()) {
        crate::sketch::forge_permute::forge_permute_outputs(&mut circuit, k, outs);
    }

    // ─── Pack public + private values ─────────────────────────────────────
    let initial_commit_packed = pack_commit_to_challenge(&initial_commit);
    let final_commit_packed = pack_commit_to_challenge(&final_commit);
    let batch_commit_packed = pack_commit_to_challenge(&CountMinCommit(batch_commit.0));

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&initial_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    public_inputs.extend_from_slice(&batch_commit_packed);
    if expose.is_interval() {
        public_inputs.push(Challenge::from_u64(t));
    }

    let initial_cells_packed = pack_cells_to_challenge(&initial_state);
    let final_cells_packed = pack_cells_to_challenge(&committed_final);
    let batch_packed_native = pack_batch_to_challenge(&batch);
    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&initial_cells_packed);
    private_inputs.extend_from_slice(&final_cells_packed);
    private_inputs.extend_from_slice(&batch_packed_native);

    // Per-record (key_lo, key_hi, value).
    for u in &batch {
        let kl = (u.key & 0xFFFF_FFFF) as u32;
        let kh = (u.key >> 32) as u32;
        private_inputs.push(Challenge::from_u32(kl));
        private_inputs.push(Challenge::from_u32(kh));
        private_inputs.push(Challenge::from_u32(u.value));
    }

    // ── Phase 9g — sorted-by-key witnesses ──
    // key_field_sorted: Val-reduced (key_lo + key_hi · 2^32) per sorted row.
    for r in 0..m {
        private_inputs.push(Challenge::from_u64(key_field_sorted_native[r]));
    }
    // val_sorted_by_key.
    for r in 0..m {
        private_inputs.push(Challenge::from_u32(val_sorted_by_key_native[r]));
    }
    // key_eq_tag.
    for r in 0..m {
        private_inputs.push(Challenge::from_u64(key_eq_tag_native[r] as u64));
    }
    // key_inv_diff: 1 / (key_field_sorted[r-1] - key_field_sorted[r]) when
    // they differ; 0 otherwise (and slot 0 is also 0 — no preceding row).
    for r in 0..m {
        let inv = if r == 0 {
            Challenge::ZERO
        } else if key_field_sorted_native[r - 1] == key_field_sorted_native[r] {
            Challenge::ZERO
        } else {
            let diff = Challenge::from_u64(key_field_sorted_native[r - 1])
                - Challenge::from_u64(key_field_sorted_native[r]);
            diff.try_inverse().expect("nonzero key diff inverts")
        };
        private_inputs.push(inv);
    }

    // combined_sorted, val_sorted.
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(combined_sorted_native[r]));
    }
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u32(val_sorted_native[r]));
    }
    // eq_tag.
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(tag_native[r] as u64));
    }
    // inv_diff.
    for r in 0..n_ctr {
        let inv = if r == 0 {
            Challenge::ZERO
        } else if combined_sorted_native[r - 1] == combined_sorted_native[r] {
            Challenge::ZERO
        } else {
            let diff = Challenge::from_u64(combined_sorted_native[r - 1])
                - Challenge::from_u64(combined_sorted_native[r]);
            diff.try_inverse().expect("nonzero diff inverts")
        };
        private_inputs.push(inv);
    }
    // sel_a_cell[r][idx].
    for r in 0..n_ctr {
        let target_idx = combined_sorted_native[r] as usize;
        for idx in 0..num_cells {
            let one_hot = a_active_native[r] == 1 && idx == target_idx;
            private_inputs.push(if one_hot { Challenge::ONE } else { Challenge::ZERO });
        }
    }

    // ─── Run + prove ──────────────────────────────────────────────────────
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run v9 circuit")
    };

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    if hardened {
        preprocessors.push(range_preprocessor::<Val>());
    }
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
    if hardened {
        air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    }
    if expose.exposes() {
        preprocessors.push(expose_preprocessor::<Val>());
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
    }

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (v9)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover =
        BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_permute_table::<4>();
    if hardened {
        prover.register_range_table::<4>();
    }
    if expose.exposes() {
        prover.register_expose_table::<4>();
    }
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (v9)");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify v9 leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
        ..Default::default()
    });

    CountMinLeafProofV9 {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_leaf::W;
    use crate::sketch::countmin::CountMinParams;

    fn empty_state(d: usize, w: usize) -> CountMinState {
        CountMinV9::new(&CountMinParams { d, w })
    }

    /// Default-shape `(D=2, W=4, BATCH=2)` round-trip — confirms the
    /// private-key design proves and self-verifies end-to-end.
    #[test]
    fn v9_leaf_round_trip() {
        let initial = empty_state(2, W);
        let batch = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let leaf = prove_countmin_leaf_v9(initial.clone(), batch);

        let mut expected = initial;
        for u in &batch {
            CountMinV9::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);

        let expected_batch_commit = commit_batch(&batch);
        assert_eq!(leaf.batch_commit.0, expected_batch_commit.0);
    }

    /// Larger shape `(d=4, w=8, batch=4)` — exercises non-trivial
    /// counter-collisions + larger key-hash payload.
    #[test]
    fn v9_leaf_round_trip_at_4_8_4() {
        let params = CountMinLeafParams { d: 4, w: 8, batch: 4 };
        params.validate();
        assert!(params.w.is_power_of_two());
        let initial = empty_state(params.d, params.w);
        let batch: Vec<CountMinUpdate> = (0..params.batch)
            .map(|i| CountMinUpdate {
                key: (i as u64).wrapping_mul(0x9E37_79B9) + 1,
                value: 1 + (i as u32 % 3),
            })
            .collect();
        let leaf = prove_countmin_leaf_v9_with_params(params, initial.clone(), batch.clone());

        let mut expected = initial;
        for u in &batch {
            CountMinV9::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);

        let expected_batch_commit = commit_batch(&batch);
        assert_eq!(leaf.batch_commit.0, expected_batch_commit.0);
    }

    // ─── Malicious-prover probe: shared PermuteBus (revision Step 1) ────────

    fn panic_msg(e: &Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "<non-string panic>".to_string()
        }
    }

    /// Count-Min point estimate `min_i C[i][h_i(key)]`.
    fn estimate(state: &CountMinState, key: u64) -> u32 {
        (0..state.params.d)
            .map(|i| {
                state.counters[i][crate::sketch::countmin_v9::hash_cell_v9(i, key, state.params.w)]
            })
            .min()
            .expect("d ≥ 1")
    }

    /// **Shared-PermuteBus forgery (key-sort ↔ counter-sort trade).** Batch
    /// `[(3, 5), (1000, 7)]` at `(d, w) = (2, 4)`. The small key 3's record
    /// payload `3·2^20 + 5` is also a valid counter payload "cell 3 += 5", and
    /// key 1000's row-1 counter payload `c0·2^20 + 7` is also a valid record
    /// "(key c0, value 7)". The malicious prover emits the record in the
    /// counter-sort output and the counter payload in the key-sort output; the
    /// rest (grouping, hashing of the fake record, running sums, sparse patch)
    /// is honest. The certified state misses key 1000's row-1 increment and
    /// key 3's hashed increments: Count-Min UNDER-estimates both.
    ///
    /// Legacy encoding: ACCEPTED. Hardened tuple encoding: REJECTED (the fake
    /// record's key-sort tuple `(c0, 7, 1, 0)` has no matching input — key
    /// 1000's counter tuple is `(c0, 7, 0, 1)`).
    #[test]
    fn v9_shared_bus_forgery_rejected() {
        let params = CountMinLeafParams { d: 2, w: 4, batch: 2 };
        let initial = empty_state(params.d, params.w);
        let (k_small, v_small, big, v_big) = (3u64, 5u32, 1000u64, 7u32);
        let batch = vec![
            CountMinUpdate { key: k_small, value: v_small },
            CountMinUpdate { key: big, value: v_big },
        ];
        let honest = v9_honest_views(params, &batch);
        let honest_final = v9_final_from_views(params, &initial, &honest);
        assert!(estimate(&honest_final, big) >= v_big && estimate(&honest_final, k_small) >= v_small);
        let _honest = prove_countmin_leaf_v9_with_params(params, initial.clone(), batch.clone());

        // key 1000's row-1 counter address (row 1 ⇒ c0 ∈ [w, 2w), never 3).
        let c0 = (params.w + crate::sketch::countmin_v9::hash_cell_v9(1, big, params.w)) as u64;
        let mut key_sorted: Vec<(u64, u32)> = honest.key_sorted.clone();
        let xpos = key_sorted.iter().position(|r| *r == (k_small, v_small)).expect("x");
        key_sorted[xpos] = (c0, v_big);
        key_sorted.sort_by_key(|r| r.0);
        let mut ctr = v9_u_ctr(params, &key_sorted);
        let ypos = ctr.iter().position(|r| *r == (c0, v_big)).expect("y ∈ U_ctr'");
        ctr[ypos] = (k_small, v_small);
        ctr.sort_by_key(|r| r.0);
        let forged = V9Views {
            sigma_key: (0..params.batch).collect(),
            key_sorted: key_sorted.clone(),
            sigma: (0..ctr.len()).collect(),
            ctr_sorted: ctr.clone(),
        };
        let forged_final = v9_final_from_views(params, &initial, &forged);
        println!(
            "[v9 shared bus] forged final {:?} (honest {:?}); estimate(1000) = {} (true 7), \
             estimate(3) = {} (true 5)",
            forged_final.counters,
            honest_final.counters,
            estimate(&forged_final, big),
            estimate(&forged_final, k_small)
        );
        assert!(
            estimate(&forged_final, big) < v_big || estimate(&forged_final, k_small) < v_small,
            "the forged state must under-estimate a key"
        );

        let run = |hardened: bool| {
            HARDENED.with(|c| c.set(Some(hardened)));
            let ks: Vec<Challenge> =
                key_sorted.iter().map(|&(k, v)| v9_elem(k, v, hardened, 0)).collect();
            let cs: Vec<Challenge> = ctr.iter().map(|&(c, v)| v9_elem(c, v, hardened, 1)).collect();
            FORGE.with(|f| *f.borrow_mut() = vec![(0, ks), (1, cs)]);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_v9_views(params, initial.clone(), batch.clone(), &forged, false)
            }));
            HARDENED.with(|c| c.set(None));
            FORGE.with(|f| f.borrow_mut().clear());
            r
        };
        let pre = run(false);
        match &pre {
            Ok(_) => println!("[v9 shared bus] legacy: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[v9 shared bus] legacy: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the legacy circuit accepts the trade");
        let post = run(true);
        match &post {
            Ok(_) => println!("[v9 shared bus] hardened: forged final ACCEPTED"),
            Err(e) => println!("[v9 shared bus] hardened: REJECTED: {}", panic_msg(e)),
        }
        assert!(post.is_err(), "the tagged tuples must stop the key-sort/counter-sort trade");
    }

    /// **Packed-split forgery.** Honest permutations, dishonest DECODING: the
    /// legacy counter-sort output `c·2^20 + v` is split as `(c − 1, v + 2^20)`
    /// (the same field element), so the increment lands in the neighbouring
    /// cell, inflated by 2^20, and the key hashed to cell `c` is
    /// under-estimated. Legacy: ACCEPTED. Hardened: REJECTED — the tuple
    /// `(c − 1, v + 2^20, 0, 1)` is not the permuted `(c, v, 0, 1)`.
    #[test]
    fn v9_packed_split_forgery_rejected() {
        let params = CountMinLeafParams { d: 2, w: 4, batch: 2 };
        let initial = empty_state(params.d, params.w);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let honest = v9_honest_views(params, &batch);
        // A counter row whose address c ≥ 1 is a singleton segment.
        let rows = &honest.ctr_sorted;
        let r = (0..rows.len())
            .find(|&r| {
                rows[r].0 >= 1
                    && rows[r].1 > 0
                    && (r == 0 || rows[r - 1].0 != rows[r].0)
                    && (r + 1 == rows.len() || rows[r + 1].0 != rows[r].0)
                    && (r == 0 || rows[r - 1].0 != rows[r].0 - 1)
            })
            .expect("a singleton counter segment");
        let (c, v) = rows[r];
        let mut forged = honest.clone();
        forged.ctr_sorted[r] = (c - 1, v + (1 << SHIFT_VAL_BITS));
        let honest_final = v9_final_from_views(params, &initial, &honest);
        let forged_final = v9_final_from_views(params, &initial, &forged);
        let (row, col) = (c as usize / params.w, c as usize % params.w);
        println!(
            "[v9 packed split] counter row ({c}, {v}) re-split as ({}, {}): cell ({row},{col}) \
             {} → {}",
            c - 1,
            v + (1 << SHIFT_VAL_BITS),
            honest_final.counters[row][col],
            forged_final.counters[row][col]
        );
        assert!(forged_final.counters[row][col] < honest_final.counters[row][col]);

        let run = |hardened: bool| {
            HARDENED.with(|cc| cc.set(Some(hardened)));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_v9_views(params, initial.clone(), batch.clone(), &forged, false)
            }));
            HARDENED.with(|cc| cc.set(None));
            r
        };
        let pre = run(false);
        match &pre {
            Ok(_) => println!("[v9 packed split] legacy: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[v9 packed split] legacy: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the legacy packed split accepts the re-split");
        let post = run(true);
        match &post {
            Ok(_) => println!("[v9 packed split] hardened: forged final ACCEPTED"),
            Err(e) => println!("[v9 packed split] hardened: REJECTED: {}", panic_msg(e)),
        }
        assert!(post.is_err(), "the tuple encoding must reject the re-split");
    }

    /// Cost of the hardened encoding (tagged tuples + base pins): padded trace
    /// rows, legacy vs hardened. Run:
    /// `cargo test --release --lib countmin_leaf_v9::tests::fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fix_overhead() {
        for &(d, w, m) in &[(4usize, 16usize, 16usize), (4, 16, 64)] {
            let params = CountMinLeafParams { d, w, batch: m };
            let batch: Vec<CountMinUpdate> = (0..m)
                .map(|i| CountMinUpdate {
                    key: (i as u64).wrapping_mul(0x9E37_79B9) + 1,
                    value: 1,
                })
                .collect();
            for (label, hardened) in [("legacy", false), ("hardened", true)] {
                HARDENED.with(|c| c.set(Some(hardened)));
                let t = std::time::Instant::now();
                let _ = prove_countmin_leaf_v9_with_params(params, empty_state(d, w), batch.clone());
                HARDENED.with(|c| c.set(None));
                println!(
                    "[v9 fix_overhead] d={d} w={w} m={m} {label:<8} trace_rows={} prove+verify={:?}",
                    crate::recursion::recursive::timing::take().trace_rows,
                    t.elapsed()
                );
            }
        }
    }

    /// Forged-decomposition regression test (Count-Min family). The prover
    /// commits to `Com(S')` with `S'` = the honest update plus 5 in cell 0,
    /// while the decomposition of that packed cell group, which every update
    /// constraint reads, returns the honest counters. Under the pre-fix
    /// recompose lowering nothing ties the two, and the proof verifies for a
    /// state the batch never produced. The fork's `recompose/coeff` lowering
    /// rejects it.
    #[test]
    fn forged_final_decomposition_rejected() {
        let params = CountMinLeafParams { d: 2, w: 4, batch: 2 };
        let initial = empty_state(params.d, params.w);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let mut honest = initial.clone();
        for u in &batch {
            CountMinV9::update(&mut honest, u);
        }
        let mut forged = honest.clone();
        forged.counters[0][0] += 5;
        let run = || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                FORGE_FINAL_CELL0.with(|c| c.set(Some(5)));
                let leaf =
                    prove_countmin_leaf_v9_with_params(params, initial.clone(), batch.clone());
                FORGE_FINAL_CELL0.with(|c| c.set(None));
                leaf.final_
            }))
            .inspect_err(|_| FORGE_FINAL_CELL0.with(|c| c.set(None)))
        };

        let legacy = crate::recompose_binding::with_unbound_recompose(run)
            .expect("PoC premise: the unbound lowering accepts the forged final state");
        assert_eq!(legacy.0, commit_countmin(&forged).0, "exposes Com(S')");
        assert_ne!(legacy.0, commit_countmin(&honest).0, "not the certified update");

        assert!(run().is_err(), "recompose/coeff lowering must reject the forged final state");
    }
}
