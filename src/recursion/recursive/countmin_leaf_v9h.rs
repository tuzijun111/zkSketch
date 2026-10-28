//! Count-Min leaf v9h: v9 with the key-grouped batch compacted to `distinct_bound`
//! rows, so hashing and counter grouping run over `distinct_bound * d` rows, not `m * d`.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_permute_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        permute_air_builders, permute_preprocessor, poseidon2_air_builders_d4,
        poseidon2_preprocessor, range_air_builders, range_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::countmin::commit_countmin;
use crate::commitment::countmin_batch::commit_batch;
use crate::commitment::CountMinCommit;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    CountMinLeafParams, DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::recursion::recursive::countmin_leaf_v9::CountMinLeafProofV9;
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMinState, CountMinUpdate};
use crate::sketch::countmin_v9::CountMinV9;

/// FRI parameters — match the v1/v2/v3/v9 leaf config so the resulting
/// proof has the same shape (chain-mergeable via `merge_two_countmin_v9`).
const LOG_FINAL_POLY_LEN: usize = 6;

/// Bit shift used to encode `(combined, value)` and `(key, value)` into a
/// single Challenge element. `SHIFT_VAL = 2^20` allows per-record `value
/// < 1 048 576`, the same bound used by v3 and v9.
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

/// Per-row hash family multipliers `a_i`. **Must match** the constants in
/// `src/sketch/countmin_v9.rs::HASH_A` (and `countmin_leaf_v9::HASH_A`).
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

/// Runtime parameters for the Phase 9h leaf. Extends [`CountMinLeafParams`]
/// with `distinct_bound`, a compile-time upper bound on the number of
/// distinct keys per batch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CountMinLeafParamsV9h {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
    /// Compile-time upper bound on `|distinct(batch.keys())|`. The hash
    /// gadget runs `distinct_bound · d` times instead of `batch · d`.
    /// Must satisfy `0 < distinct_bound ≤ batch`.
    pub distinct_bound: usize,
}

impl CountMinLeafParamsV9h {
    pub fn base(&self) -> CountMinLeafParams {
        CountMinLeafParams { d: self.d, w: self.w, batch: self.batch }
    }
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    pub fn cell_packing(&self) -> usize {
        self.base().cell_packing()
    }
    pub fn validate(&self) {
        self.base().validate();
        assert!(
            self.distinct_bound >= 1 && self.distinct_bound <= self.batch,
            "distinct_bound ({}) must be in 1..=batch ({})",
            self.distinct_bound, self.batch
        );
        assert!(
            self.w.is_power_of_two() && (1..=16).contains(&self.w),
            "v9h leaf requires w to be a power of 2 in {{2,4,8,16}}, got {}",
            self.w
        );
    }
}

/// Pack the flattened counters into Challenge elements (same layout as
/// Phase 9g and v1/v2/v3).
fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Pack the batch into Challenge elements — same encoding as
/// `commit_batch` so the in-circuit hash reproduces the same digest.
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

/// Runtime-parameterised Phase 9h leaf prover.
///
/// Returns a [`CountMinLeafProofV9`] — same proof type as Phase 9g, so two
/// v9h leaves at the same `(d, w, batch, distinct_bound)` chain-merge via
/// the existing `merge_two_countmin_v9`.
///
/// # Panics
///
/// - If `params.validate()` fails (alignment, range, `distinct_bound` shape).
/// - If `batch.len() != params.batch`.
/// - If the batch's actual number of distinct keys exceeds `distinct_bound`
///   (the in-circuit compaction PermuteAir cannot balance, and we surface
///   this as a native assertion before invoking the prover).
pub fn prove_countmin_leaf_v9h_with_params(
    params: CountMinLeafParamsV9h,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinLeafProofV9 {
    params.validate();
    assert_eq!(initial_state.params.d, params.d);
    assert_eq!(initial_state.params.w, params.w);
    assert_eq!(batch.len(), params.batch);

    let views = v9h_honest_views(params, &batch);
    if cfg!(debug_assertions) {
        let mut replay = initial_state.clone();
        for u in &batch {
            CountMinV9::update(&mut replay, u);
        }
        debug_assert_eq!(
            replay.counters,
            v9h_final_from_views(params, &initial_state, &views).counters,
            "view-derived final must equal the v9 replay"
        );
    }
    prove_v9h_views(params, initial_state, batch, &views)
}

/// The sorted views every v9h private table is derived from: the key-sort,
/// compaction and counter-sort permutes' outputs (honestly sorts of their
/// inputs; a soundness test may hand-craft them).
#[derive(Clone)]
struct V9hViews {
    sigma_key: Vec<usize>,
    /// Key-sorted records `(key_field, value)`.
    key_sorted: Vec<(u64, u32)>,
    /// Compaction hint: segment ends first, then the inactive rows.
    sigma_compact: Vec<usize>,
    /// The compact G table `(key, total)` (length `distinct_bound`, zero-padded).
    g_table: Vec<(u64, u32)>,
    sigma: Vec<usize>,
    /// Counter-sorted `(combined, value)` rows.
    ctr_sorted: Vec<(u64, u32)>,
}

/// `(eq_tag, acc, seg_end)` of a sorted `(group, value)` list.
fn v9h_group(rows: &[(u64, u32)]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
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

/// The compaction of a key-sorted view: `(sigma_compact, g_table)`.
fn v9h_compact(params: CountMinLeafParamsV9h, key_sorted: &[(u64, u32)]) -> (Vec<usize>, Vec<(u64, u32)>) {
    let m = key_sorted.len();
    let (_, key_acc, g_active) = v9h_group(key_sorted);
    let active: Vec<usize> = (0..m).filter(|&r| g_active[r] == 1).collect();
    let inactive: Vec<usize> = (0..m).filter(|&r| g_active[r] == 0).collect();
    assert!(
        active.len() <= params.distinct_bound,
        "batch has {} distinct keys but distinct_bound = {}; the compaction PermuteAir \
         cannot balance. Increase distinct_bound.",
        active.len(),
        params.distinct_bound
    );
    let mut g_table = vec![(0u64, 0u32); params.distinct_bound];
    for (j, &r) in active.iter().enumerate() {
        g_table[j] = (key_sorted[r].0, key_acc[r]);
    }
    let mut sigma_compact = active;
    sigma_compact.extend(inactive);
    (sigma_compact, g_table)
}

/// `U_ctr` (the counter-sort permute's input) of a G table.
fn v9h_u_ctr(params: CountMinLeafParamsV9h, g_table: &[(u64, u32)]) -> Vec<(u64, u32)> {
    let (d, w) = (params.d, params.w);
    let mut u = Vec::with_capacity(g_table.len() * d);
    for &(k, v) in g_table {
        for i in 0..d {
            let bucket = crate::sketch::countmin_v9::hash_cell_v9(i, k, w);
            u.push(((i * w + bucket) as u64, v));
        }
    }
    u
}

fn v9h_honest_views(params: CountMinLeafParamsV9h, batch: &[CountMinUpdate]) -> V9hViews {
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
    let (sigma_compact, g_table) = v9h_compact(params, &key_sorted);
    let u_ctr = v9h_u_ctr(params, &g_table);
    let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr.iter().enumerate().collect();
    indexed.sort_by_key(|(_, (combined, _))| *combined);
    let sigma: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let ctr_sorted: Vec<(u64, u32)> = indexed.iter().map(|(_, r)| **r).collect();
    V9hViews {
        sigma_key,
        key_sorted,
        sigma_compact,
        g_table,
        sigma,
        ctr_sorted,
    }
}

/// The final state the circuit certifies for given views.
fn v9h_final_from_views(
    params: CountMinLeafParamsV9h,
    initial: &CountMinState,
    views: &V9hViews,
) -> CountMinState {
    let w = params.w;
    let (_, acc, seg_end) = v9h_group(&views.ctr_sorted);
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
// All three legacy v9h permutes (key sort, compaction, counter sort) pack
// `x·2^20 + v` into ONE base element, inheriting both `countmin_leaf_v9`
// holes: (1) the fork's PermuteBus is shared by every permute with no op id, so
// a small-key record doubles as a counter payload "cell k += v" and can be
// traded across ops (`tests::v9h_shared_bus_forgery_rejected`); (2) the sorted
// views are split from one in-field equation in two free witnesses, so
// `(c − 1, v + 2^20)` re-splits `(c, v)` (`tests::v9h_packed_split_forgery_rejected`;
// `1920·2^20 = p − 1` on BabyBear, so range checks alone cannot fix it).
//
// The hardened encoding keeps the fields in separate coordinates and tags each
// domain in its own (X², X³) pattern:
//     key sort:     (key_field, value, 1, 0)
//     compaction:   (key,       total, 1, 1)   (inactive rows / padding: (0,0,1,1))
//     counter sort: (combined,  value, 0, 1)
// Injective once every coordinate is BASE: `key_table` is (the hash's bit
// decomposition), `combined_sorted` is (cell selector / eq-tag chain), and
// `key_field_sorted`, `val_sorted_by_key`, `val_table`, `val_sorted` are
// pinned by [`assert_base`]. (Presumes bound decompositions and constants.)

/// Whether [`prove_countmin_leaf_v9h_with_params`] uses the hardened tuple
/// encoding. Always on outside tests; the soundness PoCs build the legacy one.
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
    /// sort, 1 = compaction, 2 = counter sort) emit `outputs`.
    static FORGE: std::cell::RefCell<Vec<(usize, Vec<Challenge>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Force `x` into the BASE field (31-bit RangeAir decomposition of coefficient
/// 0; the byte window covers `[0, p)`, so no base value is excluded).
fn assert_base(b: &mut CircuitBuilder<Challenge>, x: ExprId) {
    b.add_range_bits::<Val>(x, Val::bits()).expect("assert_base");
}

/// A permute element: legacy `x·2^20 + v`, or the hardened tuple with the
/// domain's `(X², X³)` tag (`domain` 0 = key sort, 1 = compaction, 2 = counter).
#[cfg(test)]
fn v9h_elem(x: u64, v: u32, hardened: bool, domain: usize) -> Challenge {
    use p3_field::BasedVectorSpace;
    let c = if hardened {
        let (t2, t3) = [(1u32, 0u32), (1, 1), (0, 1)][domain];
        [Val::from_u64(x), Val::from_u32(v), Val::from_u32(t2), Val::from_u32(t3)]
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

/// Build, run, prove and self-verify the v9h leaf for given (honest or
/// hand-crafted) views; the certified final is [`v9h_final_from_views`].
fn prove_v9h_views(
    params: CountMinLeafParamsV9h,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    views: &V9hViews,
) -> CountMinLeafProofV9 {
    let CountMinLeafParamsV9h { d, w, batch: m, distinct_bound } = params;
    let num_cells = params.num_cells();
    let cell_packing = params.cell_packing();
    // n_ctr is now distinct_bound · d (down from m · d in Phase 9g).
    let n_ctr = distinct_bound * d;
    let w_log2 = w.trailing_zeros() as usize;
    let hardened = use_hardened();

    let final_state = v9h_final_from_views(params, &initial_state, views);
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&final_state);
    let batch_commit = commit_batch(&batch);

    let sigma_key = views.sigma_key.clone();
    let key_field_sorted_native: Vec<u64> = views.key_sorted.iter().map(|r| r.0).collect();
    let val_sorted_by_key_native: Vec<u32> = views.key_sorted.iter().map(|r| r.1).collect();
    let (key_eq_tag_native, _, _) = v9h_group(&views.key_sorted);
    let sigma_compact = views.sigma_compact.clone();
    let key_table_native: Vec<u64> = views.g_table.iter().map(|r| r.0).collect();
    let val_table_native: Vec<u32> = views.g_table.iter().map(|r| r.1).collect();
    let sigma = views.sigma.clone();
    let combined_sorted_native: Vec<u64> = views.ctr_sorted.iter().map(|r| r.0).collect();
    let val_sorted_native: Vec<u32> = views.ctr_sorted.iter().map(|r| r.1).collect();
    let (tag_native, _, a_active_native) = v9h_group(&views.ctr_sorted);

    // ─── Build the circuit ───────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    if hardened {
        b.enable_range(generate_range_trace::<Val, Challenge>);
    }

    // ---- Public inputs ----
    let initial_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // ---- Constants ----
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    // Basis constants of the hardened tuple encoding (allocated only when
    // hardened, so the legacy graph stays identical).
    let basis = |i: usize| -> Challenge {
        use p3_field::BasedVectorSpace;
        let mut c = [Val::ZERO; 4];
        c[i] = Val::ONE;
        Challenge::from_basis_coefficients_slice(&c).expect("basis")
    };
    let (x_const, x2_const, x3_const, x23_const) = if hardened {
        use p3_field::BasedVectorSpace;
        let x23 = Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ZERO, Val::ONE, Val::ONE])
            .expect("X^2 + X^3");
        (
            b.alloc_const(basis(1), "X"),
            b.alloc_const(basis(2), "X^2"),
            b.alloc_const(basis(3), "X^3"),
            b.alloc_const(x23, "X^2+X^3"),
        )
    } else {
        (zero, zero, zero, zero)
    };
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
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
    let pow2_consts: Vec<ExprId> = (0..w_log2)
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();

    // ---- Private inputs ----
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();

    // Per-raw-record (key_lo, key_hi, value).
    let mut key_lo: Vec<ExprId> = Vec::with_capacity(m);
    let mut key_hi: Vec<ExprId> = Vec::with_capacity(m);
    let mut value_w: Vec<ExprId> = Vec::with_capacity(m);
    for _ in 0..m {
        key_lo.push(b.alloc_private_input("key_lo"));
        key_hi.push(b.alloc_private_input("key_hi"));
        value_w.push(b.alloc_private_input("value"));
    }

    // Sorted-by-key witnesses (Phase 9g style, kept).
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

    // Phase 9h additions: compact G_table.
    let key_table: Vec<ExprId> = (0..distinct_bound)
        .map(|_| b.alloc_private_input("key_table"))
        .collect();
    let val_table: Vec<ExprId> = (0..distinct_bound)
        .map(|_| b.alloc_private_input("val_table"))
        .collect();

    // Counter-sort witnesses (n_ctr = distinct_bound · d now).
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

    // 3. Decompose batch_packed and bind to (key_lo, key_hi, value) witnesses.
    for k in 0..m {
        let coeffs = b
            .decompose_ext_to_base_coeffs::<Val>(batch_packed[k])
            .expect("decompose batch_packed");
        b.connect(coeffs[0], key_lo[k]);
        b.connect(coeffs[1], key_hi[k]);
        b.connect(coeffs[2], value_w[k]);
        b.connect(coeffs[3], zero);
    }

    // 4. Reconstruct key_field per raw record.
    let mut key_field: Vec<ExprId> = Vec::with_capacity(m);
    for k in 0..m {
        let hi_shifted = b.mul(key_hi[k], two_pow_32_const);
        let kf = b.add(key_lo[k], hi_shifted);
        key_field.push(kf);
    }

    // ─── Stage 5 — key-grouping verification (same as Phase 9g) ──────────

    // 5a. Build per-record key payload, sort via PermuteAir.
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
    let key_payload_sorted: Vec<ExprId> = b
        .add_permute(&key_payload, sigma_key.clone())
        .expect("add_permute (key sort)");

    // 5b. Decode sorted payloads.
    for r in 0..m {
        let recovered = if hardened {
            // key-sort tuple (key_field_sorted, val_sorted_by_key, 1, 0), both
            // coordinates pinned to the base field.
            assert_base(&mut b, key_field_sorted[r]);
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

    // 5c. Adjacent-equality tags on sorted keys.
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

    // 5d. Running-sum aggregation.
    let mut key_acc: Vec<ExprId> = Vec::with_capacity(m);
    key_acc.push(val_sorted_by_key[0]);
    for r in 1..m {
        let carried = b.mul(key_eq_tag_w[r], key_acc[r - 1]);
        let new_acc = b.add(val_sorted_by_key[r], carried);
        key_acc.push(new_acc);
    }

    // 5e. g_active[r].
    let mut g_active: Vec<ExprId> = Vec::with_capacity(m);
    for r in 0..m {
        let active = if r == m - 1 {
            one
        } else {
            b.sub(one, key_eq_tag_w[r + 1])
        };
        g_active.push(active);
    }

    // ─── Stage 6 (NEW in Phase 9h) — compact G via a second PermuteAir ───
    //
    // se_payload[r] = g_active[r] · (key_field_sorted[r] · SHIFT + key_acc[r])
    //   = 0 on inactive rows
    //   = real (key · SHIFT + key_acc) on segment-end rows
    //
    // The PermuteAir input is se_payload (length m); output se_permuted
    // is constrained to equal g_padded[j] for all j:
    //   g_padded[j] for j < distinct_bound = key_table[j] · SHIFT + val_table[j]
    //   g_padded[j] for j ≥ distinct_bound = 0  (length-m padding past distinct_bound)
    //
    // Multiset equality forces the prover's G_table to be the true
    // segment-end set. Capacity overflow (actual_distinct > distinct_bound)
    // makes multiset balance unsatisfiable.
    let mut se_payload: Vec<ExprId> = Vec::with_capacity(m);
    for r in 0..m {
        let se = if hardened {
            // compaction tuple g_active·(key, total) + (0, 0, 1, 1).
            let t = b.mul(key_acc[r], x_const);
            let real_payload = b.add(key_field_sorted[r], t);
            let se = b.mul(g_active[r], real_payload);
            b.add(se, x23_const)
        } else {
            let kfs = b.mul(key_field_sorted[r], shift_val_const);
            let real_payload = b.add(kfs, key_acc[r]);
            b.mul(g_active[r], real_payload)
        };
        se_payload.push(se);
    }
    let se_permuted: Vec<ExprId> = b
        .add_permute(&se_payload, sigma_compact.clone())
        .expect("add_permute (compaction)");
    for j in 0..m {
        let g_padded_j = if hardened {
            // compaction tuple (key_table, val_table, 1, 1) / padding (0, 0, 1, 1);
            // `val_table` pinned to the base field (`key_table` is, by the hash's
            // bit decomposition).
            if j < distinct_bound {
                assert_base(&mut b, val_table[j]);
                let t = b.mul_add(val_table[j], x_const, x23_const);
                b.add(key_table[j], t)
            } else {
                x23_const
            }
        } else if j < distinct_bound {
            let kts = b.mul(key_table[j], shift_val_const);
            b.add(kts, val_table[j])
        } else {
            zero
        };
        b.connect(se_permuted[j], g_padded_j);
    }

    // ─── Stage 7 (NEW in Phase 9h) — hash gadget over compact G ──────────
    //
    // Loop bound is distinct_bound (down from m). Padding rows
    // (j ≥ actual_distinct) have key_table[j] = val_table[j] = 0; they
    // still pay the hash gadget cost but contribute zero deltas.
    let mut payload: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for j in 0..distinct_bound {
        for i in 0..d {
            let prod = b.mul(key_table[j], hash_a_consts[i]);
            let mixed = b.add(prod, hash_b_consts[i]);
            let bits = b
                .decompose_to_bits::<Val>(mixed, Val::bits())
                .expect("decompose mixed");
            let mut pos_sum = b.mul(bits[0], pow2_consts[0]);
            for jb in 1..w_log2 {
                let term = b.mul(bits[jb], pow2_consts[jb]);
                pos_sum = b.add(pos_sum, term);
            }
            let row_times_w = b.mul(row_consts[i], w_const);
            let combined_expr = b.add(row_times_w, pos_sum);
            let payload_expr = if hardened {
                // counter-sort tuple (combined, value, 0, 1).
                let t = b.mul_add(val_table[j], x_const, x3_const);
                b.add(combined_expr, t)
            } else {
                let combined_shifted = b.mul(combined_expr, shift_val_const);
                b.add(combined_shifted, val_table[j])
            };
            payload.push(payload_expr);
        }
    }

    // ─── Stage 8 — counter-grouping + sparse patch (n_ctr = distinct_bound · d) ─

    // 8a. Counter-sort via PermuteAir.
    let payload_sorted: Vec<ExprId> = b
        .add_permute(&payload, sigma.clone())
        .expect("add_permute (counter sort)");

    // 8b. Decode payload_sorted into (combined_sorted, val_sorted).
    for r in 0..n_ctr {
        let recovered = if hardened {
            // counter-sort tuple (combined_sorted, val_sorted, 0, 1).
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

    // 8c. Adjacent-equality tags.
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

    // 8d. Running sum.
    let mut acc: Vec<ExprId> = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        let new_acc = b.add(val_sorted[r], carried);
        acc.push(new_acc);
    }

    // 8e. Per-row segment-end flag.
    let mut a_active: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let active = if r == n_ctr - 1 {
            one
        } else {
            b.sub(one, eq_tag[r + 1])
        };
        a_active.push(active);
    }

    // 8f. Per-A-row cell selector validity.
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

    // 8g. Per-cell delta from A + state transition.
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
    let mut circuit = b.build().expect("build v9h leaf circuit");
    // [test-only] malicious prover: swap in forged Permute outputs.
    #[cfg(test)]
    for (k, outs) in FORGE.with(|f| f.take()) {
        crate::sketch::forge_permute::forge_permute_outputs(&mut circuit, k, outs);
    }

    // ─── Pack public + private values ────────────────────────────────────
    let initial_commit_packed = pack_commit_to_challenge(&initial_commit);
    let final_commit_packed = pack_commit_to_challenge(&final_commit);
    let batch_commit_packed = pack_commit_to_challenge(&CountMinCommit(batch_commit.0));

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&initial_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    public_inputs.extend_from_slice(&batch_commit_packed);

    let initial_cells_packed = pack_cells_to_challenge(&initial_state);
    let final_cells_packed = pack_cells_to_challenge(&final_state);
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

    // Sorted-by-key witnesses.
    for r in 0..m {
        private_inputs.push(Challenge::from_u64(key_field_sorted_native[r]));
    }
    for r in 0..m {
        private_inputs.push(Challenge::from_u32(val_sorted_by_key_native[r]));
    }
    for r in 0..m {
        private_inputs.push(Challenge::from_u64(key_eq_tag_native[r] as u64));
    }
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

    // Phase 9h: G_table.
    for j in 0..distinct_bound {
        private_inputs.push(Challenge::from_u64(key_table_native[j]));
    }
    for j in 0..distinct_bound {
        private_inputs.push(Challenge::from_u32(val_table_native[j]));
    }

    // Counter-sort witnesses.
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(combined_sorted_native[r]));
    }
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u32(val_sorted_native[r]));
    }
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(tag_native[r] as u64));
    }
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
    for r in 0..n_ctr {
        let target_idx = combined_sorted_native[r] as usize;
        for idx in 0..num_cells {
            let one_hot = a_active_native[r] == 1 && idx == target_idx;
            private_inputs.push(if one_hot { Challenge::ONE } else { Challenge::ZERO });
        }
    }

    // ─── Run + prove ─────────────────────────────────────────────────────
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run v9h circuit")
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

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (v9h)");
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
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (v9h)");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify v9h leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
        ..Default::default()
    });

    CountMinLeafProofV9 {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        // CountMinLeafParams base; distinct_bound is implicit in the circuit shape.
        params: params.base(),
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

    /// Baseline parity at the default shape — distinct_bound = batch
    /// (no compaction, all rows real).
    #[test]
    fn v9h_leaf_round_trip() {
        let params = CountMinLeafParamsV9h {
            d: 2, w: W, batch: 2, distinct_bound: 2,
        };
        let initial = empty_state(params.d, params.w);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let leaf = prove_countmin_leaf_v9h_with_params(params, initial.clone(), batch.clone());

        let mut expected = initial;
        for u in &batch {
            CountMinV9::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
        let expected_batch_commit = commit_batch(&batch);
        assert_eq!(leaf.batch_commit.0, expected_batch_commit.0);
    }

    /// Larger shape, still no compaction.
    #[test]
    fn v9h_leaf_round_trip_at_4_8_4() {
        let params = CountMinLeafParamsV9h {
            d: 4, w: 8, batch: 4, distinct_bound: 4,
        };
        let initial = empty_state(params.d, params.w);
        let batch: Vec<CountMinUpdate> = (0..params.batch)
            .map(|i| CountMinUpdate {
                key: (i as u64).wrapping_mul(0x9E37_79B9) + 1,
                value: 1 + (i as u32 % 3),
            })
            .collect();
        let leaf = prove_countmin_leaf_v9h_with_params(params, initial.clone(), batch.clone());

        let mut expected = initial;
        for u in &batch {
            CountMinV9::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
    }

    /// Heavily duplicated batch — exercises the compaction path.
    /// 10 records, 3 distinct keys (cycling).
    #[test]
    fn v9h_leaf_with_duplicates() {
        let params = CountMinLeafParamsV9h {
            d: 4, w: 8, batch: 10, distinct_bound: 3,
        };
        let initial = empty_state(params.d, params.w);
        // 10 records, 3 distinct keys: cycling through (k=A,B,C).
        let batch: Vec<CountMinUpdate> = (0..params.batch)
            .map(|i| CountMinUpdate {
                key: ((i % 3) as u64).wrapping_mul(0x9E37_79B9) + 1,
                value: 1 + (i as u32 % 5),
            })
            .collect();
        let leaf = prove_countmin_leaf_v9h_with_params(params, initial.clone(), batch.clone());

        let mut expected = initial;
        for u in &batch {
            CountMinV9::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
    }

    /// Capacity overflow — 5 distinct keys but distinct_bound = 2. Native
    /// pre-check should panic before the prover is invoked.
    #[test]
    #[should_panic(expected = "distinct keys but distinct_bound")]
    fn v9h_leaf_rejects_under_distinct_bound() {
        let params = CountMinLeafParamsV9h {
            d: 4, w: 8, batch: 10, distinct_bound: 2,
        };
        let initial = empty_state(params.d, params.w);
        // 10 records, 5 distinct keys.
        let batch: Vec<CountMinUpdate> = (0..params.batch)
            .map(|i| CountMinUpdate {
                key: ((i % 5) as u64).wrapping_mul(0x9E37_79B9) + 1,
                value: 1,
            })
            .collect();
        let _ = prove_countmin_leaf_v9h_with_params(params, initial, batch);
    }

    /// Two v9h leaves at the same distinct_bound chain-merge via the
    /// existing v9 merge path.
    #[test]
    fn v9h_chain_merge_smoke() {
        use crate::recursion::recursive::countmin_merge_v9::{
            merge_two_countmin_v9, verify_chain_countmin_v9,
        };

        let params = CountMinLeafParamsV9h {
            d: 2, w: W, batch: 2, distinct_bound: 2,
        };
        let s0 = empty_state(params.d, params.w);
        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf_v9h_with_params(params, s0.clone(), b1.clone());

        let mut s1 = s0;
        for u in &b1 {
            CountMinV9::update(&mut s1, u);
        }
        let b2 = vec![
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_leaf_v9h_with_params(params, s1, b2);

        let chain = merge_two_countmin_v9(&l1, &l2).expect("v9h chain-merge");
        verify_chain_countmin_v9(&chain).expect("v9h chain verify");
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

    fn estimate(state: &CountMinState, key: u64) -> u32 {
        (0..state.params.d)
            .map(|i| {
                state.counters[i][crate::sketch::countmin_v9::hash_cell_v9(i, key, state.params.w)]
            })
            .min()
            .expect("d ≥ 1")
    }

    /// **Shared-PermuteBus forgery (key-sort ↔ counter-sort trade), v9h.** The
    /// `countmin_leaf_v9` attack through the compact G table: the small key 3's
    /// record payload is emitted by the counter sort as "cell 3 += 5", and key
    /// 1000's row-1 counter payload is emitted by the key sort as a fake record
    /// `(c0, 7)`, which the compaction and hashing then process honestly.
    /// Count-Min under-estimates keys 1000 and 3. Legacy: ACCEPTED; hardened
    /// tagged tuples: REJECTED.
    #[test]
    fn v9h_shared_bus_forgery_rejected() {
        let params = CountMinLeafParamsV9h { d: 2, w: 4, batch: 2, distinct_bound: 2 };
        let initial = empty_state(params.d, params.w);
        let (k_small, v_small, big, v_big) = (3u64, 5u32, 1000u64, 7u32);
        let batch = vec![
            CountMinUpdate { key: k_small, value: v_small },
            CountMinUpdate { key: big, value: v_big },
        ];
        let honest = v9h_honest_views(params, &batch);
        let honest_final = v9h_final_from_views(params, &initial, &honest);
        let _honest = prove_countmin_leaf_v9h_with_params(params, initial.clone(), batch.clone());

        let c0 = (params.w + crate::sketch::countmin_v9::hash_cell_v9(1, big, params.w)) as u64;
        let mut key_sorted = honest.key_sorted.clone();
        let xpos = key_sorted.iter().position(|r| *r == (k_small, v_small)).expect("x");
        key_sorted[xpos] = (c0, v_big);
        key_sorted.sort_by_key(|r| r.0);
        let (sigma_compact, g_table) = v9h_compact(params, &key_sorted);
        let mut ctr = v9h_u_ctr(params, &g_table);
        let ypos = ctr.iter().position(|r| *r == (c0, v_big)).expect("y ∈ U_ctr'");
        ctr[ypos] = (k_small, v_small);
        ctr.sort_by_key(|r| r.0);
        let forged = V9hViews {
            sigma_key: (0..params.batch).collect(),
            key_sorted: key_sorted.clone(),
            sigma_compact,
            g_table,
            sigma: (0..ctr.len()).collect(),
            ctr_sorted: ctr.clone(),
        };
        let forged_final = v9h_final_from_views(params, &initial, &forged);
        println!(
            "[v9h shared bus] forged final {:?} (honest {:?}); estimate(1000) = {}, estimate(3) = {}",
            forged_final.counters,
            honest_final.counters,
            estimate(&forged_final, big),
            estimate(&forged_final, k_small)
        );
        assert!(estimate(&forged_final, big) < v_big || estimate(&forged_final, k_small) < v_small);

        let run = |hardened: bool| {
            HARDENED.with(|c| c.set(Some(hardened)));
            let ks: Vec<Challenge> =
                key_sorted.iter().map(|&(k, v)| v9h_elem(k, v, hardened, 0)).collect();
            let cs: Vec<Challenge> = ctr.iter().map(|&(c, v)| v9h_elem(c, v, hardened, 2)).collect();
            FORGE.with(|f| *f.borrow_mut() = vec![(0, ks), (2, cs)]);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_v9h_views(params, initial.clone(), batch.clone(), &forged)
            }));
            HARDENED.with(|c| c.set(None));
            FORGE.with(|f| f.borrow_mut().clear());
            r
        };
        let pre = run(false);
        match &pre {
            Ok(_) => println!("[v9h shared bus] legacy: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[v9h shared bus] legacy: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the legacy circuit accepts the trade");
        let post = run(true);
        match &post {
            Ok(_) => println!("[v9h shared bus] hardened: forged final ACCEPTED"),
            Err(e) => println!("[v9h shared bus] hardened: REJECTED: {}", panic_msg(e)),
        }
        assert!(post.is_err(), "the tagged tuples must stop the cross-op trade");
    }

    /// **Packed-split forgery, v9h** (see `countmin_leaf_v9`): honest
    /// permutations, the counter-sort output `c·2^20 + v` decoded as
    /// `(c − 1, v + 2^20)`. Legacy: ACCEPTED (cell `c` loses its increment);
    /// hardened: REJECTED.
    #[test]
    fn v9h_packed_split_forgery_rejected() {
        let params = CountMinLeafParamsV9h { d: 2, w: 4, batch: 2, distinct_bound: 2 };
        let initial = empty_state(params.d, params.w);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let honest = v9h_honest_views(params, &batch);
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
        let honest_final = v9h_final_from_views(params, &initial, &honest);
        let forged_final = v9h_final_from_views(params, &initial, &forged);
        let (row, col) = (c as usize / params.w, c as usize % params.w);
        assert!(forged_final.counters[row][col] < honest_final.counters[row][col]);
        let run = |hardened: bool| {
            HARDENED.with(|cc| cc.set(Some(hardened)));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_v9h_views(params, initial.clone(), batch.clone(), &forged)
            }));
            HARDENED.with(|cc| cc.set(None));
            r
        };
        let pre = run(false);
        match &pre {
            Ok(_) => println!("[v9h packed split] legacy: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[v9h packed split] legacy: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the legacy packed split accepts the re-split");
        let post = run(true);
        match &post {
            Ok(_) => println!("[v9h packed split] hardened: forged final ACCEPTED"),
            Err(e) => println!("[v9h packed split] hardened: REJECTED: {}", panic_msg(e)),
        }
        assert!(post.is_err(), "the tuple encoding must reject the re-split");
    }

    /// Cost of the hardened encoding (tagged tuples + base pins), legacy vs
    /// hardened. Run:
    /// `cargo test --release --lib countmin_leaf_v9h::tests::fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fix_overhead() {
        for &(d, w, m, db) in &[(4usize, 16usize, 16usize, 8usize), (4, 16, 64, 32)] {
            let params = CountMinLeafParamsV9h { d, w, batch: m, distinct_bound: db };
            let batch: Vec<CountMinUpdate> = (0..m)
                .map(|i| CountMinUpdate {
                    key: ((i % db) as u64).wrapping_mul(0x9E37_79B9) + 1,
                    value: 1,
                })
                .collect();
            for (label, hardened) in [("legacy", false), ("hardened", true)] {
                HARDENED.with(|c| c.set(Some(hardened)));
                let t = std::time::Instant::now();
                let _ = prove_countmin_leaf_v9h_with_params(params, empty_state(d, w), batch.clone());
                HARDENED.with(|c| c.set(None));
                println!(
                    "[v9h fix_overhead] d={d} w={w} m={m} db={db} {label:<8} trace_rows={} prove+verify={:?}",
                    crate::recursion::recursive::timing::take().trace_rows,
                    t.elapsed()
                );
            }
        }
    }
}
