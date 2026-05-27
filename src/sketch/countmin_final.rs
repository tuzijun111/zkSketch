//! **Canonical** count-min update circuit — the final §5.2 design.
//!
//! This file is the single self-contained reference for what the count-
//! min update circuit does today. It bundles:
//!
//! - **Full circuit** with every §5.2 stage from raw batch to state
//!   transition, in one place (no jumping across modules).
//! - **Privacy preservation** — keys/values are private witnesses; the
//!   only public binding for the batch is a Poseidon2 commitment.
//! - **Compile-time `distinct_bound`** that compacts the per-key
//!   aggregation into a fixed-size G table, so the hash gadget runs
//!   `distinct_bound · d` times instead of `batch · d` — realizing
//!   §5.2's "only distinct keys pay the hash cost" promise.
//! - **Chain-merge compatibility** with the §4.2 recursive aggregation
//!   (`merge_two_countmin_v9`) so two leaves at the same params combine
//!   into one O(1)-verify proof.
//!
//! Background on design choices (e.g. why the v9 field-friendly hash
//! family, why a separate compaction PermuteAir, why power-of-2 `w`)
//! lives in [`docs/countmin.md`](../../../docs/countmin.md). This file
//! is the implementation; the doc is the narrative.
//!
//! ### Pipeline (one paragraph)
//!
//! The prover supplies the raw batch as private witnesses, the sorted-by-
//! key view as a permutation hint, the segment-end values as a separate
//! compact G table, and the per-record hash positions follow from a
//! field-friendly hash `h_i(k) = (k·a_i + b_i) mod w`. Three PermuteAir
//! instances (key-sort, G-table compaction, counter-sort) plus
//! PoneglyphDB §4.3-style adjacent-equality + running-sum gates enforce
//! the §5.2 group-by relations. The final state is reached via a sparse-
//! patch state-transition equation `final[idx] = initial[idx] + Σ
//! sel_a[r][idx] · acc[r]`. Cells are Poseidon2-committed at both ends,
//! exposing only `(initial_commit, final_commit, batch_commit)` as PIs.
//!
//! ### Tests in this file
//!
//! Two `#[test] #[ignore]` proving-time tests:
//!
//! - [`tests::proving_time_with_different_distinct_keys`] — sweeps
//!   `distinct_bound ∈ {1000, 500, 100, 50, 10, 5, 1}` at fixed
//!   `(d, w, batch) = (4, 8, 1000)`, printing prove time per setting.
//!   This is the §5.2 win demonstration.
//! - [`tests::proving_time_merge_two_leaves`] — proves two leaves and
//!   times the §4.2 sequential merge step separately from the leaf
//!   prove times.
//!
//! Run on demand: `V3_SWEEP_THREADS=8 cargo test --release --lib
//! countmin_final -- --ignored --nocapture`.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_permute_trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        permute_air_builders, permute_preprocessor, poseidon2_air_builders_d4,
        poseidon2_preprocessor, recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::commitment::countmin::commit_countmin;
use crate::commitment::countmin_batch::commit_batch;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::recursion::recursive::countmin_leaf_v9::CountMinLeafProofV9;
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::countmin_v9::{CountMinV9, hash_cell_v9};

// ─── Constants ───────────────────────────────────────────────────────────

/// FRI final-poly log size — matches the recursion config used for chain
/// merging. Locked here for self-containment.
const LOG_FINAL_POLY_LEN: usize = 6;

/// Bit-shift for the `(combined, value)` and `(key, value)` payload
/// encodings. `SHIFT_VAL = 2^20` allows per-record `value < 1 048 576`.
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

/// Per-row hash family multipliers `a_i` (Phase 9b field-friendly family).
/// Must match `sketch::countmin_v9::HASH_A` so the in-circuit gadget
/// reproduces the native sketch.
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

// ─── Public API ──────────────────────────────────────────────────────────

/// Runtime parameters for the canonical count-min leaf.
///
/// `(d, w, batch, distinct_bound)` together determine the circuit shape;
/// two leaves chain-merge only when all four match.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CountMinFinalParams {
    /// Number of sketch rows (depth). Must be `1 ≤ d ≤ 16`.
    pub d: usize,
    /// Number of buckets per row. Must be a power of 2 in `{2, 4, 8, 16}`.
    pub w: usize,
    /// Number of raw records per epoch. `d · w` must be a multiple of 4.
    pub batch: usize,
    /// Compile-time upper bound on `|distinct(keys)|`. The hash gadget
    /// runs `distinct_bound · d` times. Must satisfy `1 ≤ distinct_bound
    /// ≤ batch`.
    pub distinct_bound: usize,
}

impl CountMinFinalParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }

    pub fn cell_packing(&self) -> usize {
        self.num_cells() / 4
    }

    pub fn validate(&self) {
        assert!(self.d >= 1 && self.d <= 16, "d must be in 1..=16, got {}", self.d);
        assert!(
            self.w.is_power_of_two() && (1..=16).contains(&self.w),
            "w must be a power of 2 in {{2,4,8,16}}, got {}",
            self.w
        );
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(
            self.num_cells() % 4 == 0,
            "d·w = {} is not a multiple of 4 (Challenge alignment)",
            self.num_cells()
        );
        assert!(
            self.distinct_bound >= 1 && self.distinct_bound <= self.batch,
            "distinct_bound ({}) must be in 1..=batch ({})",
            self.distinct_bound, self.batch
        );
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

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

// ─── Prover ──────────────────────────────────────────────────────────────

/// Prove one count-min update epoch under the canonical §5.2 design.
///
/// Returns a [`CountMinLeafProofV9`] — chain-mergeable with the existing
/// `merge_two_countmin_v9` whenever two leaves share `(d, w, batch,
/// distinct_bound)`.
///
/// # Panics
///
/// - `params.validate()` failures.
/// - `batch.len() != params.batch`.
/// - `initial_state.params != (params.d, params.w)`.
/// - Actual distinct-key count exceeds `params.distinct_bound`.
pub fn prove_countmin_final(
    params: CountMinFinalParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinLeafProofV9 {
    params.validate();
    assert_eq!(initial_state.params.d, params.d);
    assert_eq!(initial_state.params.w, params.w);
    assert_eq!(batch.len(), params.batch);

    let CountMinFinalParams { d, w, batch: m, distinct_bound } = params;
    let num_cells = params.num_cells();
    let cell_packing = params.cell_packing();
    let n_ctr = distinct_bound * d;
    let w_log2 = w.trailing_zeros() as usize;

    // ─── Native side: state evolution + witnesses ────────────────────────
    let mut final_state = initial_state.clone();
    for u in &batch {
        CountMinV9::update(&mut final_state, u);
    }
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&final_state);
    let batch_commit = commit_batch(&batch);

    // Stage 1: σ_key (sort raw batch by key).
    let mut indexed_keys: Vec<(usize, &CountMinUpdate)> = batch.iter().enumerate().collect();
    indexed_keys.sort_by_key(|(_, u)| u.key);
    let sigma_key: Vec<usize> = indexed_keys.iter().map(|(i, _)| *i).collect();
    let key_sorted_native: Vec<&CountMinUpdate> =
        indexed_keys.iter().map(|(_, u)| *u).collect();

    // Stage 2: sorted-by-key field views (Val-reduced).
    let key_field_sorted_native: Vec<u64> = key_sorted_native
        .iter()
        .map(|u| Val::from_u64(u.key))
        .map(|v| <Val as p3_field::PrimeField64>::as_canonical_u64(&v))
        .collect();
    let val_sorted_by_key_native: Vec<u32> = key_sorted_native.iter().map(|u| u.value).collect();

    // Stage 3: adjacent-equality tags + running-sum (per key segment).
    let mut key_eq_tag_native: Vec<u32> = vec![0; m];
    for r in 1..m {
        if key_field_sorted_native[r] == key_field_sorted_native[r - 1] {
            key_eq_tag_native[r] = 1;
        }
    }
    let mut key_acc_native: Vec<u32> = vec![0; m];
    if m > 0 {
        key_acc_native[0] = val_sorted_by_key_native[0];
        for r in 1..m {
            key_acc_native[r] = if key_eq_tag_native[r] == 1 {
                key_acc_native[r - 1].saturating_add(val_sorted_by_key_native[r])
            } else {
                val_sorted_by_key_native[r]
            };
        }
    }
    let mut g_active_native: Vec<u32> = vec![0; m];
    for r in 0..m {
        let ends_segment = if r == m - 1 { true } else { key_eq_tag_native[r + 1] == 0 };
        g_active_native[r] = u32::from(ends_segment);
    }

    // Stage 4: σ_compact (place segment-end indices first, then inactives).
    let active_indices: Vec<usize> = (0..m).filter(|&r| g_active_native[r] == 1).collect();
    let inactive_indices: Vec<usize> = (0..m).filter(|&r| g_active_native[r] == 0).collect();
    let actual_distinct = active_indices.len();
    assert!(
        actual_distinct <= distinct_bound,
        "batch has {actual_distinct} distinct keys but distinct_bound = {distinct_bound}"
    );
    let mut sigma_compact: Vec<usize> = active_indices.clone();
    sigma_compact.extend(inactive_indices);
    assert_eq!(sigma_compact.len(), m);

    // Compact G table (length distinct_bound). Padding with (0, 0) for
    // slots beyond actual_distinct.
    let mut key_table_native: Vec<u64> = vec![0; distinct_bound];
    let mut val_table_native: Vec<u32> = vec![0; distinct_bound];
    for j in 0..actual_distinct {
        let row = sigma_compact[j];
        key_table_native[j] = key_field_sorted_native[row];
        val_table_native[j] = key_acc_native[row];
    }

    // Stage 5: U_ctr from G_table (length distinct_bound · d). Padding
    // rows contribute (any-hash, 0) — value 0 means zero state delta.
    let mut u_ctr_data: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
    for j in 0..distinct_bound {
        let key_for_hash = key_table_native[j];
        for i in 0..d {
            let bucket = hash_cell_v9(i, key_for_hash, w);
            let combined = (i * w + bucket) as u64;
            u_ctr_data.push((combined, val_table_native[j]));
        }
    }
    let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr_data.iter().enumerate().collect();
    indexed.sort_by_key(|(_, (combined, _))| *combined);
    let sigma_ctr: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let combined_sorted_native: Vec<u64> = indexed.iter().map(|(_, (c, _))| *c).collect();
    let val_sorted_native: Vec<u32> = indexed.iter().map(|(_, (_, v))| *v).collect();

    // Stage 6: counter-level adjacent-equality + running sum.
    let mut tag_native: Vec<u32> = vec![0; n_ctr];
    for r in 1..n_ctr {
        if combined_sorted_native[r] == combined_sorted_native[r - 1] {
            tag_native[r] = 1;
        }
    }
    let mut acc_native: Vec<u32> = vec![0; n_ctr];
    if n_ctr > 0 {
        acc_native[0] = val_sorted_native[0];
        for r in 1..n_ctr {
            acc_native[r] = if tag_native[r] == 1 {
                acc_native[r - 1].saturating_add(val_sorted_native[r])
            } else {
                val_sorted_native[r]
            };
        }
    }
    let mut a_active_native: Vec<u32> = vec![0; n_ctr];
    for r in 0..n_ctr {
        let ends_segment = if r == n_ctr - 1 { true } else { tag_native[r + 1] == 0 };
        a_active_native[r] = u32::from(ends_segment);
    }

    // ─── Build the circuit ───────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);

    // Public inputs: (initial_commit, final_commit, batch_commit). The
    // privacy property — no per-record data is exposed.
    let initial_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
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

    // Private inputs.
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();

    let mut key_lo: Vec<ExprId> = Vec::with_capacity(m);
    let mut key_hi: Vec<ExprId> = Vec::with_capacity(m);
    let mut value_w: Vec<ExprId> = Vec::with_capacity(m);
    for _ in 0..m {
        key_lo.push(b.alloc_private_input("key_lo"));
        key_hi.push(b.alloc_private_input("key_hi"));
        value_w.push(b.alloc_private_input("value"));
    }

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

    let key_table: Vec<ExprId> = (0..distinct_bound)
        .map(|_| b.alloc_private_input("key_table"))
        .collect();
    let val_table: Vec<ExprId> = (0..distinct_bound)
        .map(|_| b.alloc_private_input("val_table"))
        .collect();

    let combined_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("combined_sorted"))
        .collect();
    let val_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("val_sorted"))
        .collect();
    let eq_tag: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("eq_tag")).collect();
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

    // ─── Stage A — Bind cells and batch to commitments via Poseidon2 ─────
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

    // Decompose packed cells.
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

    // Decompose batch_packed → (key_lo, key_hi, value, 0) per record,
    // binding the private witnesses to the public batch_commit.
    for k in 0..m {
        let coeffs = b
            .decompose_ext_to_base_coeffs::<Val>(batch_packed[k])
            .expect("decompose batch_packed");
        b.connect(coeffs[0], key_lo[k]);
        b.connect(coeffs[1], key_hi[k]);
        b.connect(coeffs[2], value_w[k]);
        b.connect(coeffs[3], zero);
    }

    // Reconstruct key_field per raw record.
    let mut key_field: Vec<ExprId> = Vec::with_capacity(m);
    for k in 0..m {
        let hi_shifted = b.mul(key_hi[k], two_pow_32_const);
        let kf = b.add(key_lo[k], hi_shifted);
        key_field.push(kf);
    }

    // ─── Stage B — Sort raw batch by key (PermuteAir #1) ─────────────────
    let mut key_payload: Vec<ExprId> = Vec::with_capacity(m);
    for k in 0..m {
        let kf_shifted = b.mul(key_field[k], shift_val_const);
        let kp = b.add(kf_shifted, value_w[k]);
        key_payload.push(kp);
    }
    let key_payload_sorted: Vec<ExprId> = b
        .add_permute(&key_payload, sigma_key.clone())
        .expect("add_permute (key sort)");

    // Decode each sorted payload into (key_field_sorted, val_sorted_by_key).
    for r in 0..m {
        let kfs = b.mul(key_field_sorted[r], shift_val_const);
        let recovered = b.add(kfs, val_sorted_by_key[r]);
        b.connect(recovered, key_payload_sorted[r]);
    }

    // ─── Stage C — Adjacent-equality tags on sorted keys ─────────────────
    // PoneglyphDB §4.3 Eq 7-8:  tag·(a-b) = 0  AND  (1-tag)(1-(a-b)·inv) = 0
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

    // ─── Stage D — Running-sum aggregation per key segment ───────────────
    // key_acc[r] = val_sorted_by_key[r] + key_eq_tag[r] · key_acc[r-1]
    let mut key_acc: Vec<ExprId> = Vec::with_capacity(m);
    key_acc.push(val_sorted_by_key[0]);
    for r in 1..m {
        let carried = b.mul(key_eq_tag_w[r], key_acc[r - 1]);
        let new_acc = b.add(val_sorted_by_key[r], carried);
        key_acc.push(new_acc);
    }

    // Segment-end flag g_active[r] = 1 iff this row closes its key segment.
    let mut g_active: Vec<ExprId> = Vec::with_capacity(m);
    for r in 0..m {
        let active = if r == m - 1 {
            one
        } else {
            b.sub(one, key_eq_tag_w[r + 1])
        };
        g_active.push(active);
    }

    // ─── Stage E — Compact G table (PermuteAir #2) ───────────────────────
    // SE[r] = g_active[r] · (key_field_sorted[r] · SHIFT + key_acc[r])
    //       = 0 on inactive rows; segment-end payload otherwise.
    // After permutation, active payloads land at [0, actual_distinct).
    // G_padded[j] = key_table[j] · SHIFT + val_table[j]  for j < distinct_bound
    //             = 0                                    for j ≥ distinct_bound
    // Multiset equality SE ≡ G_padded forces the G_table to be the true
    // segment-end set.
    let mut se_payload: Vec<ExprId> = Vec::with_capacity(m);
    for r in 0..m {
        let kfs = b.mul(key_field_sorted[r], shift_val_const);
        let real_payload = b.add(kfs, key_acc[r]);
        let se = b.mul(g_active[r], real_payload);
        se_payload.push(se);
    }
    let se_permuted: Vec<ExprId> = b
        .add_permute(&se_payload, sigma_compact.clone())
        .expect("add_permute (compaction)");
    for j in 0..m {
        let g_padded_j = if j < distinct_bound {
            let kts = b.mul(key_table[j], shift_val_const);
            b.add(kts, val_table[j])
        } else {
            zero
        };
        b.connect(se_permuted[j], g_padded_j);
    }

    // ─── Stage F — Hash gadget over compact G ────────────────────────────
    // h_i(k) = (k · a_i + b_i) mod w, implemented via multiply-add +
    // bit-decomposition + weighted sum of bottom log₂(w) bits.
    // Loop bound is `distinct_bound` (not `m`) — the §5.2 win.
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
            let combined_shifted = b.mul(combined_expr, shift_val_const);
            let payload_expr = b.add(combined_shifted, val_table[j]);
            payload.push(payload_expr);
        }
    }

    // ─── Stage G — Sort U_ctr by counter (PermuteAir #3) ─────────────────
    let payload_sorted: Vec<ExprId> = b
        .add_permute(&payload, sigma_ctr.clone())
        .expect("add_permute (counter sort)");
    for r in 0..n_ctr {
        let combined_shifted = b.mul(combined_sorted[r], shift_val_const);
        let recovered = b.add(combined_shifted, val_sorted[r]);
        b.connect(recovered, payload_sorted[r]);
    }

    // ─── Stage H — Counter-level adjacent-equality + running sum ─────────
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
    let mut acc: Vec<ExprId> = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        let new_acc = b.add(val_sorted[r], carried);
        acc.push(new_acc);
    }
    let mut a_active: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let active = if r == n_ctr - 1 {
            one
        } else {
            b.sub(one, eq_tag[r + 1])
        };
        a_active.push(active);
    }

    // ─── Stage I — Sparse-patch selector validity ────────────────────────
    // sel_a_cell[r][idx] ∈ {0,1}, Σ_idx sel_a_cell[r][idx] = a_active[r],
    // Σ_idx idx · sel_a_cell[r][idx] = a_active[r] · combined_sorted[r].
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

    // ─── Stage J — Per-cell delta + state-transition equation ────────────
    // final[idx] = initial[idx] + Σ_r sel_a_cell[r][idx] · acc[r]
    for idx in 0..num_cells {
        let mut delta_acc = b.mul(sel_a_cell[0][idx], acc[0]);
        for r in 1..n_ctr {
            let term = b.mul(sel_a_cell[r][idx], acc[r]);
            delta_acc = b.add(delta_acc, term);
        }
        let updated = b.add(initial_cells[idx], delta_acc);
        b.connect(updated, final_cells[idx]);
    }

    let circuit = b.build().expect("build countmin_final circuit");

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
    for u in &batch {
        let kl = (u.key & 0xFFFF_FFFF) as u32;
        let kh = (u.key >> 32) as u32;
        private_inputs.push(Challenge::from_u32(kl));
        private_inputs.push(Challenge::from_u32(kh));
        private_inputs.push(Challenge::from_u32(u.value));
    }
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
    for j in 0..distinct_bound {
        private_inputs.push(Challenge::from_u64(key_table_native[j]));
    }
    for j in 0..distinct_bound {
        private_inputs.push(Challenge::from_u32(val_table_native[j]));
    }
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
        runner.run().expect("run countmin_final circuit")
    };

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (final)");
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
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (final)");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify countmin_final leaf");

    CountMinLeafProofV9 {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams {
            d: params.d,
            w: params.w,
            batch: params.batch,
        },
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

// ─── User-facing convenience API ─────────────────────────────────────────

/// A real, self-verified count-min update proof.
///
/// Returned by [`generate_proof`]. Carries both the STARK proof itself
/// (in `proof.output`) and the resulting sketch state's cells (in
/// `final_state`) so callers can immediately answer queries against the
/// sketch the proof certifies — no prover re-run needed.
///
/// ### Proof anatomy
///
/// - `proof.initial`: Poseidon2 commitment to the initial sketch state
///   (here, always the empty sketch).
/// - `proof.final_`: Poseidon2 commitment to the final sketch state.
///   `commit_countmin(&self.final_state) == proof.final_` by construction.
/// - `proof.batch_commit`: Poseidon2 commitment to the raw batch — the
///   only public binding of the per-record data (keys and values stay
///   private).
/// - `proof.output`: the actual STARK proof bytes (a `RecursionOutput`).
///
/// ### Verification
///
/// The proof is *self-verified* inside [`prove_countmin_final`] before
/// being returned, so a `CountMinFinalProof` you hold is guaranteed
/// valid. Independent re-verification (e.g. after deserializing) is
/// available via the batch-STARK verifier — see how
/// `merge_two_countmin_v9` and `verify_chain_countmin_v9` consume the
/// `output` field for the pattern.
pub struct CountMinFinalProof {
    /// The STARK leaf proof. `proof.output` is the actual proof data;
    /// the other fields are the public commitments it binds.
    pub proof: CountMinLeafProofV9,
    /// Materialized cells of the resulting sketch — for querying counts
    /// against the same state the proof commits to.
    pub final_state: CountMinState,
}

impl CountMinFinalProof {
    /// Count-min point estimate for `key` against the certified final
    /// state. Returns the minimum of the `d` cells `key` hashes into —
    /// the standard count-min estimator.
    pub fn query(&self, key: u64) -> u32 {
        let d = self.final_state.params.d;
        let w = self.final_state.params.w;
        let mut min_est = u32::MAX;
        for i in 0..d {
            let j = crate::sketch::countmin_v9::hash_cell_v9(i, key, w);
            min_est = min_est.min(self.final_state.counters[i][j]);
        }
        min_est
    }
}

/// **Generate a real STARK proof for a batch of count-min updates.**
///
/// Convenience entry point on top of [`prove_countmin_final`] that:
/// 1. Constructs an empty initial sketch of shape `(params.d, params.w)`.
/// 2. Computes the resulting state natively (for query access).
/// 3. Runs the §5.2 leaf prover (which self-verifies before returning).
/// 4. Bundles everything into a [`CountMinFinalProof`].
///
/// Returns a proof object that is **already self-verified** and ready
/// to use — pass it to a chain-merge function, serialize it to disk,
/// or query the resulting sketch immediately via `result.query(key)`.
///
/// # Parameters
///
/// - `params`: circuit shape `(d, w, batch, distinct_bound)`. Must
///   satisfy `params.validate()`'s constraints (in particular, `w` must
///   be a power of 2 in `{2, 4, 8, 16}`, `d·w` divisible by 4,
///   `1 ≤ distinct_bound ≤ batch`).
/// - `updates`: exactly `params.batch` count-min updates. The actual
///   number of distinct keys must be `≤ params.distinct_bound`.
///
/// # Panics
///
/// - On `params.validate()` failure (alignment / range checks).
/// - If `updates.len() != params.batch`.
/// - If `updates` contains more than `params.distinct_bound` distinct keys.
///
/// # Example
///
/// ```ignore
/// use zksketch::sketch::countmin::CountMinUpdate;
/// use zksketch::sketch::countmin_final::{CountMinFinalParams, generate_proof};
///
/// // 10 updates, at most 3 distinct keys per epoch.
/// let params = CountMinFinalParams {
///     d: 4, w: 8, batch: 10, distinct_bound: 3,
/// };
/// let updates: Vec<CountMinUpdate> = (0..10)
///     .map(|i| CountMinUpdate { key: (i % 3) as u64 + 1, value: 1 })
///     .collect();
///
/// let result = generate_proof(params, updates);
///
/// // result.proof  — the STARK proof (already self-verified, chain-mergeable).
/// // result.final_state — the resulting sketch (queryable directly).
/// // result.proof.batch_commit — public commitment to the raw batch.
/// // result.proof.final_     — public commitment to the resulting state.
/// assert!(result.query(1) >= 1);
/// ```
pub fn generate_proof(
    params: CountMinFinalParams,
    updates: Vec<CountMinUpdate>,
) -> CountMinFinalProof {
    params.validate();
    assert_eq!(
        updates.len(),
        params.batch,
        "updates length ({}) must equal params.batch ({})",
        updates.len(),
        params.batch
    );

    // Build an empty initial state at the requested shape.
    let initial_state = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });

    // Materialize the resulting state natively (used both as a private
    // witness inside the prover and as the query target afterwards).
    let mut final_state = initial_state.clone();
    for u in &updates {
        CountMinV9::update(&mut final_state, u);
    }

    // Run the prover (self-verifies before returning).
    let proof = prove_countmin_final(params, initial_state, updates);

    CountMinFinalProof { proof, final_state }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_merge_v9::{
        merge_two_countmin_v9, verify_chain_countmin_v9,
    };

    /// Deterministic batch generator: `batch` records distributed across
    /// exactly `distinct` distinct keys, cycling through key indices.
    fn gen_batch(params: CountMinFinalParams, distinct: usize) -> Vec<CountMinUpdate> {
        assert!(distinct > 0 && distinct <= params.batch);
        let salt = (params.d * params.w * params.batch) as u64;
        (0..params.batch)
            .map(|i| {
                let key_idx = (i % distinct) as u64;
                CountMinUpdate {
                    key: key_idx.wrapping_mul(0x9E37_79B9) ^ salt,
                    value: 1 + (i as u32 % 7),
                }
            })
            .collect()
    }

    /// Resolve a thread count: `V3_SWEEP_THREADS=N` overrides Rayon's
    /// default pool. Returns `(num_threads_opt, label_for_printing)`.
    fn resolve_threads() -> (Option<usize>, String) {
        let n: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse().ok());
        let label = match n {
            Some(k) => format!("V3_SWEEP_THREADS={k}"),
            None => {
                let cur = rayon::current_num_threads();
                format!("Rayon default pool ({cur} threads)")
            }
        };
        (n, label)
    }

    /// Run a closure in a sized Rayon pool (or the global pool if `n` is
    /// `None`). Mirrors the helper pattern in `countmin_v3.rs`.
    fn with_pool<F: FnOnce() -> T + Send, T: Send>(n: Option<usize>, f: F) -> T {
        match n {
            None => f(),
            Some(k) => {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(k)
                    .thread_name(|i| format!("countmin-final-bench-{i}"))
                    .build()
                    .expect("build rayon thread pool");
                pool.install(f)
            }
        }
    }

    /// **Test 1 — proving time vs. distinct-key count.**
    ///
    /// Sweep over `distinct_bound ∈ {1000, 500, 100, 50, 10, 5, 1}` at
    /// fixed `(d, w, batch) = (4, 8, 1000)`. For each grid point, generate
    /// a 1000-record batch with exactly `distinct` distinct keys and
    /// prove one leaf. Print prove time per setting.
    ///
    /// Expected: a strongly downward-sloping curve as `distinct_bound`
    /// shrinks — the §5.2 promise that "only distinct keys pay the hash
    /// cost".
    ///
    /// Run:
    ///
    /// ```bash
    /// V3_SWEEP_THREADS=8 cargo test --release --lib countmin_final::tests::proving_time_with_different_distinct_keys -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn proving_time_with_different_distinct_keys() {
        use std::time::Instant;

        let (threads, threads_label) = resolve_threads();
        let (d, w, batch) = (4usize, 8usize, 1000usize);

        println!();
        println!("countmin_final — proving time vs. distinct-key count");
        println!("======================================================");
        println!("  threads: {threads_label}");
        println!("  d={d}, w={w}, batch={batch}");
        println!();

        let grid = [1000usize, 500, 100, 50, 10, 5, 1];
        for &distinct in &grid {
            let params = CountMinFinalParams { d, w, batch, distinct_bound: distinct };
            let initial = CountMinV9::new(&CountMinParams { d, w });
            let batch_records = gen_batch(params, distinct);

            let elapsed = with_pool(threads, move || {
                let t = Instant::now();
                let _leaf = prove_countmin_final(params, initial, batch_records);
                t.elapsed()
            });

            println!(
                "  distinct_bound={:>5}  actual={:>5}  prove {:>10.2?}",
                distinct, distinct, elapsed
            );
        }
    }

    /// Sanity check: `generate_proof` produces a valid proof whose
    /// final-state commitment matches `commit_countmin(&final_state)`,
    /// and the `query` helper returns the expected count-min estimate.
    /// Small shape `(d=2, w=4, batch=2)` keeps this test fast (~1s).
    #[test]
    fn generate_proof_round_trip() {
        use crate::commitment::countmin::commit_countmin;

        let params = CountMinFinalParams { d: 2, w: 4, batch: 2, distinct_bound: 2 };
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];

        let result = generate_proof(params, updates.clone());

        // The proof's final commit matches the materialized final state.
        assert_eq!(commit_countmin(&result.final_state).0, result.proof.final_.0);

        // Each unique-key update contributes its value to every row it
        // hashes into, so the min-of-d estimate is at least the update
        // value for that key.
        assert!(result.query(7) >= 3);
        assert!(result.query(11) >= 5);

        // A never-seen key sees at most the max-seen value (since count-
        // min over-estimates due to collisions, but here only two updates
        // landed in the sketch).
        let unseen = result.query(999_999);
        assert!(unseen <= 5);
    }

    /// **Test 2 — proving time to merge two leaves.**
    ///
    /// Prove two leaves (each over a deterministic 1000-record batch
    /// with all-distinct keys, sharing the boundary `l_1.final ==
    /// l_2.initial`) and time the §4.2 sequential merge step separately.
    /// Reports per-leaf prove time and merge time.
    ///
    /// Run:
    ///
    /// ```bash
    /// V3_SWEEP_THREADS=8 cargo test --release --lib countmin_final::tests::proving_time_merge_two_leaves -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn proving_time_merge_two_leaves() {
        use std::time::Instant;

        let (threads, threads_label) = resolve_threads();
        let (d, w, batch) = (4usize, 8usize, 1000usize);

        println!();
        println!("countmin_final — merge proving-time check");
        println!("===========================================");
        println!("  threads: {threads_label}");
        println!("  d={d}, w={w}, batch={batch}");
        println!("  workflow: prove l_1, apply b_1, prove l_2, merge_two_countmin_v9");
        println!();

        let (l1_time, l2_time, m_time) = with_pool(threads, move || {
            let params = CountMinFinalParams { d, w, batch, distinct_bound: batch };

            // Both leaves' batches use all-distinct keys (no compaction).
            let s0 = CountMinV9::new(&CountMinParams { d, w });
            let b1 = gen_batch(params, batch);
            let t1 = Instant::now();
            let l1 = prove_countmin_final(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();

            // Apply b1 natively → s1, the input state for l2.
            let mut s1 = s0;
            for u in &b1 {
                CountMinV9::update(&mut s1, u);
            }

            // Second batch — same generator, shifted indices.
            let salt = (d * w * batch) as u64;
            let b2: Vec<CountMinUpdate> = (0..batch)
                .map(|i| {
                    let key_idx = (i as u64 + batch as u64).wrapping_mul(0x9E37_79B9);
                    CountMinUpdate { key: key_idx ^ salt, value: 1 + (i as u32 % 7) }
                })
                .collect();
            let t2 = Instant::now();
            let l2 = prove_countmin_final(params, s1, b2);
            let l2_time = t2.elapsed();

            // §4.2 merge step.
            let tm = Instant::now();
            let chain = merge_two_countmin_v9(&l1, &l2).expect("merge_two_countmin_v9");
            let m_time = tm.elapsed();
            verify_chain_countmin_v9(&chain).expect("verify_chain_countmin_v9");

            (l1_time, l2_time, m_time)
        });

        println!("  leaf 1 prove:       {l1_time:>10.2?}");
        println!("  leaf 2 prove:       {l2_time:>10.2?}");
        println!("  §4.2 merge step:    {m_time:>10.2?}");
        println!("  ────────────────────────────────");
        println!(
            "  total wall-clock:   {:>10.2?}",
            l1_time + l2_time + m_time
        );
    }

    /// **Generate a real proof and persist it to `src/proofs/`.**
    ///
    /// Calls [`generate_proof`] at a small `(d=2, w=4, batch=2)` shape
    /// (fast — runs in ~1s) and serializes the resulting STARK proof
    /// via `postcard` into `src/proofs/countmin_final_example.bin`.
    /// Also writes a sidecar `.meta.txt` with the public commitments and
    /// params in human-readable form, so a future verifier knows what
    /// to feed back into the verifier alongside the proof bytes.
    ///
    /// File layout after the test runs:
    ///
    /// ```text
    /// src/proofs/
    ///   countmin_final_example.bin       — postcard-serialized STARK proof
    ///   countmin_final_example.meta.txt  — params + public-input commitments
    /// ```
    ///
    /// Run:
    ///
    /// ```bash
    /// cargo test --release --lib generate_and_store_proof -- --nocapture
    /// ```
    #[test]
    fn generate_and_store_proof() {
        use crate::commitment::countmin::commit_countmin;
        use std::fs;
        use std::path::PathBuf;

        // Small shape — keeps the test under ~1s.
        let params = CountMinFinalParams { d: 2, w: 4, batch: 2, distinct_bound: 2 };
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];

        let result = generate_proof(params, updates.clone());

        // Sanity: the stored proof certifies a state whose commit matches
        // what `commit_countmin` derives natively from `final_state`.
        assert_eq!(commit_countmin(&result.final_state).0, result.proof.final_.0);

        // Resolve src/proofs/ relative to the crate root (not the test
        // process's cwd, which can vary).
        let crate_root = env!("CARGO_MANIFEST_DIR");
        let out_dir = PathBuf::from(crate_root).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("create src/proofs directory");

        // Serialize the STARK proof. `output.0` is the inner `Proof<SC>`,
        // which is what's actually postcard-serializable
        // (`output.1: Arc<CircuitProverData<...>>` is prover-side scaffolding,
        // reconstructed from params on the verifier side).
        let proof_bytes = postcard::to_allocvec(&result.proof.output.0)
            .expect("postcard serialize proof");
        let proof_path = out_dir.join("countmin_final_example.bin");
        fs::write(&proof_path, &proof_bytes).expect("write proof file");

        // Sidecar metadata — what a verifier needs in addition to the proof
        // bytes: the public-input commitments and the circuit-shape params.
        let mut meta = String::new();
        meta.push_str("# Count-Min final-design proof — sidecar metadata\n");
        meta.push_str("# This file is paired with `countmin_final_example.bin`.\n");
        meta.push_str("# To verify the proof, reconstruct the circuit from `params`\n");
        meta.push_str("# below, set the public-input vector to the three commitments\n");
        meta.push_str("# below, and run the batch-STARK verifier on the deserialized\n");
        meta.push_str("# proof.\n");
        meta.push('\n');
        meta.push_str(&format!("params.d              = {}\n", params.d));
        meta.push_str(&format!("params.w              = {}\n", params.w));
        meta.push_str(&format!("params.batch          = {}\n", params.batch));
        meta.push_str(&format!("params.distinct_bound = {}\n", params.distinct_bound));
        meta.push('\n');
        meta.push_str(&format!("initial_commit  = {:?}\n", result.proof.initial.0));
        meta.push_str(&format!("final_commit    = {:?}\n", result.proof.final_.0));
        meta.push_str(&format!("batch_commit    = {:?}\n", result.proof.batch_commit.0));
        meta.push('\n');
        meta.push_str(&format!("proof_size_bytes = {}\n", proof_bytes.len()));
        let meta_path = out_dir.join("countmin_final_example.meta.txt");
        fs::write(&meta_path, &meta).expect("write meta file");

        eprintln!(
            "wrote {} bytes of proof to {}",
            proof_bytes.len(),
            proof_path.display()
        );
        eprintln!("wrote sidecar metadata to {}", meta_path.display());

        // Postconditions.
        assert!(proof_path.exists(), "proof file should exist after write");
        assert!(meta_path.exists(), "meta file should exist after write");
        assert!(!proof_bytes.is_empty(), "proof should serialize to non-empty bytes");
    }
}
