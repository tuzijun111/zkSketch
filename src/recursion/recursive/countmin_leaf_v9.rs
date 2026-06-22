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
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
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
use crate::commitment::{CountMinBatchCommit, CountMinCommit};
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
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
    params.validate();
    assert_eq!(initial_state.params.d, params.d);
    assert_eq!(initial_state.params.w, params.w);
    assert_eq!(batch.len(), params.batch);
    assert!(
        params.w.is_power_of_two() && (1..=16).contains(&params.w),
        "v9 leaf requires w to be a power of 2 in {{2,4,8,16}}, got {}",
        params.w
    );

    let CountMinLeafParams { d, w, batch: m } = params;
    let num_cells = params.num_cells();
    let cell_packing = params.cell_packing();
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;

    // Native side: replay the v9 sketch update, compute commitments.
    let mut final_state = initial_state.clone();
    for u in &batch {
        CountMinV9::update(&mut final_state, u);
    }
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&final_state);
    let batch_commit = commit_batch(&batch);

    // ─── Native side, Phase 9g pipeline ───────────────────────────────────
    //
    // The raw batch is the ground truth. We compute the §5.2 key-grouping
    // off-circuit as a hint (the in-circuit verifier re-derives it and
    // checks each step). All native quantities below feed the private-
    // witness arrays the circuit consumes.

    // 1. Sort raw_batch by key → σ_key permutation.
    let mut indexed_keys: Vec<(usize, &CountMinUpdate)> = batch.iter().enumerate().collect();
    indexed_keys.sort_by_key(|(_, u)| u.key);
    let sigma_key: Vec<usize> = indexed_keys.iter().map(|(i, _)| *i).collect();
    let key_sorted_native: Vec<&CountMinUpdate> =
        indexed_keys.iter().map(|(_, u)| *u).collect();

    // 2. Sorted-by-key per-record fields, in Val (matches in-circuit
    //    `key_field = key_lo + key_hi · 2^32`).
    let key_field_sorted_native: Vec<u64> = key_sorted_native
        .iter()
        .map(|u| Val::from_u64(u.key))
        .map(|v| <Val as p3_field::PrimeField64>::as_canonical_u64(&v))
        .collect();
    let val_sorted_by_key_native: Vec<u32> = key_sorted_native.iter().map(|u| u.value).collect();

    // 3. Adjacent-equality tags + inverse-diff witnesses on key_field_sorted.
    let mut key_eq_tag_native: Vec<u32> = vec![0; m];
    for r in 1..m {
        if key_field_sorted_native[r] == key_field_sorted_native[r - 1] {
            key_eq_tag_native[r] = 1;
        }
    }

    // 4. Running-sum aggregation per key segment.
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

    // 5. g_active flag — 1 iff this row is the last in its key segment
    //    (so its key_acc holds the segment total).
    let mut g_active_native: Vec<u32> = vec![0; m];
    for r in 0..m {
        let ends_segment = if r == m - 1 { true } else { key_eq_tag_native[r + 1] == 0 };
        g_active_native[r] = u32::from(ends_segment);
    }

    // 6. Build U_ctr from sorted-by-key data, with g_active-gated values:
    //    inactive rows contribute (combined, 0) to the counter-sort, so
    //    the running-sum at the counter level adds nothing for them.
    let mut u_ctr_data: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
    for r in 0..m {
        let key_orig = key_sorted_native[r].key;
        let effective_val =
            if g_active_native[r] == 1 { key_acc_native[r] } else { 0 };
        for i in 0..d {
            let bucket = crate::sketch::countmin_v9::hash_cell_v9(i, key_orig, w);
            let combined = (i * w + bucket) as u64;
            u_ctr_data.push((combined, effective_val));
        }
    }
    let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr_data.iter().enumerate().collect();
    indexed.sort_by_key(|(_, (combined, _))| *combined);
    let sigma: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let combined_sorted_native: Vec<u64> = indexed.iter().map(|(_, (c, _))| *c).collect();
    let val_sorted_native: Vec<u32> = indexed.iter().map(|(_, (_, v))| *v).collect();

    // 7. Counter-level adjacent-equality tags + running sum (unchanged
    //    from the previous design, just now operating on the g_active-
    //    gated U_ctr).
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
    if expose_boundary {
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
        let kf_shifted = b.mul(key_field[k], shift_val_const);
        let kp = b.add(kf_shifted, value_w[k]);
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
        let kfs = b.mul(key_field_sorted[r], shift_val_const);
        let recovered = b.add(kfs, val_sorted_by_key[r]);
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
            let combined_shifted = b.mul(combined_expr, shift_val_const);
            let payload_expr = b.add(combined_shifted, effective_val);
            payload.push(payload_expr);
        }
    }

    // 6. Counter-sort via PermuteAir.
    let payload_sorted: Vec<ExprId> = b
        .add_permute(&payload, sigma.clone())
        .expect("add_permute");

    // 7. Decode payload_sorted into (combined_sorted, val_sorted).
    for r in 0..n_ctr {
        let combined_shifted = b.mul(combined_sorted[r], shift_val_const);
        let recovered = b.add(combined_shifted, val_sorted[r]);
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

    let circuit = b.build().expect("build v9 leaf circuit");

    // ─── Pack public + private values ─────────────────────────────────────
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
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
    if expose_boundary {
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
    if expose_boundary {
        prover.register_expose_table::<4>();
    }
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (v9)");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify v9 leaf");

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
}
