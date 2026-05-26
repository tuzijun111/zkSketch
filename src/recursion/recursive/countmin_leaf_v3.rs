//! §5.2 Count-Min update leaf (the v3 design, Phase 8d — PermuteAir + fork patch).
//!
//! This module implements the new §5.2 "Count-Min Circuit Design" from the
//! paper as a CircuitBuilder leaf. The §5.2 maintenance plan is:
//!
//! ```text
//! B ──group by key──▶ G ──compute counter ids──▶ U_ctr ──group by counter──▶ A ──sparse patch──▶ S_t
//! ```
//!
//! ### How v3 evolved (Phase 8 → Phase 8b → Phase 8d)
//!
//! - **Phase 8** bound per-record contributions to A rows via a quadratic
//!   `sel_a[u][r]` one-hot matrix of size `n_ctr × n_ctr`, where `n_ctr =
//!   m · d`. Sound but `O(n_ctr²)` — a `batch=100, d=4` workload (`n_ctr =
//!   400`) cost ~800 K constraints / ~87 s on a 64-core machine.
//! - **Phase 8b** attempted to drop `sel_a` in favour of the fork's
//!   `PermuteAir` plus PoneglyphDB §4.3-style adjacent-equality tags. It
//!   crashed because the fork's `PermuteAir` was only tested at D=1 (base
//!   field circuits); combining it with Poseidon2 + Recompose in a D=4
//!   extension-field circuit hit an EF→BF type mismatch and the multi-NPO
//!   prover dropped one of the three NPOs.
//! - **Phase 8d** (this file, paired with `Plonky3-recursion-fork` edits to
//!   `generate_permute_trace`, `PermuteCircuitPlugin`, `enable_permute`, and
//!   `PermuteAir::trace_to_matrix`) fixes the fork so PermuteAir produces a
//!   base-field-coefficient trace from any extension-field circuit. The
//!   leaf below now uses the Phase 8b design end-to-end: cost drops from
//!   `O(n_ctr²)` to `O(n_ctr + n_ctr · num_cells)`.
//!
//! ### How each §5.2 step is implemented
//!
//! - **Step 1 (batch binding)** — records' `(key, value, pos[0..d])` are
//!   public inputs, identical to v1/v2 (so the leaf is merge-compatible).
//! - **Steps 2–3 (key-group + key-aggregate)** — *skipped as a prototype
//!   simplification*. The plaintext pipeline in `src/sketch/countmin_v3.rs`
//!   carries the full key-grouping for the soundness oracle; in-circuit we
//!   go directly from per-record positions to the per-(record,row)
//!   counter-update vector. The counter-group step below merges any
//!   per-record collisions at the same counter, so key-grouping is purely
//!   an optimisation — and one our per-record-PI design already eliminates
//!   (hashes are computed natively and exposed, not recomputed in-circuit).
//! - **Step 4 (counter-derive)** — `U_ctr[k·d + i] = (row=i, bucket=pos_k[i],
//!   value=value_k)` is built in-circuit as a linear combination of PIs
//!   and the loop index — no new witnesses.
//! - **Steps 5–6 (counter-sort + counter-group + counter-aggregate)** —
//!   each U_ctr row encodes into one Challenge payload `(row·w + bucket) ·
//!   SHIFT_VAL + value`. The fork's `PermuteAir` enforces `multiset
//!   (payload_sorted) == multiset(payload)` via its LogUp bus. The sorted
//!   payloads are then decoded into `combined_sorted[r]` and `val_sorted[r]`
//!   private witnesses, and adjacent-equality tags `eq_tag[r]` (PoneglyphDB
//!   §4.3 Eq 7-8) identify equal-counter runs. A running sum
//!   `acc[r] = val_sorted[r] + eq_tag[r] · acc[r-1]` accumulates each
//!   segment's total.
//! - **Step 7 (sparse-patch apply)** — per-row segment-end flag
//!   `a_active[r] = 1 - eq_tag[r+1]` (with `a_active[n_ctr - 1] = 1`).
//!   For each segment-end row, a per-A-row "cell selector" `sel_a_cell[r]`
//!   maps to cell `combined_sorted[r]` via a length-`num_cells` one-hot.
//!   `delta_per_cell[idx] = Σ_r sel_a_cell[r][idx] · acc[r]`, then
//!   `final[idx] = initial[idx] + delta_per_cell[idx]`.
//! - **Step 8 (metadata)** — fixed at compile time via the FRI config and
//!   `CountMinLeafParams`, identical to v1/v2.
//!
//! ### Soundness sketch
//!
//! 1. **U_ctr is read directly from PIs**: every record's per-row counter
//!    contribution `(row=i, bucket=pos_k[i], value=value_k)` appears as a
//!    linear combination of public inputs. The prover cannot omit or
//!    fabricate records.
//! 2. **Counter-sort multiset equality**: each U_ctr row is encoded into
//!    one Challenge `payload = (row·w + bucket) · SHIFT_VAL + value`
//!    where `SHIFT_VAL = 2^20`. Under our prototype's per-record value
//!    bound (`value < 2^16`), the encoding is unique — `(combined, value)`
//!    pairs map to distinct payloads. PermuteAir's `PermuteBus` enforces
//!    multiset equality between original and sorted payload columns.
//! 3. **Adjacent equality tags** (PoneglyphDB §4.3 Eq 7-8) force
//!    `eq_tag[r] = 1 iff combined_sorted[r-1] == combined_sorted[r]`. No
//!    range-checked sortedness is enforced — that's not needed for
//!    soundness because…
//! 4. **Running-sum aggregation**: `acc[r] = val_sorted[r] + eq_tag[r] ·
//!    acc[r-1]` correctly totals each *adjacent* equal-counter segment.
//!    Even if the prover supplies a permuted-but-not-sorted layout where
//!    a counter's records aren't contiguous, the segments split — but the
//!    **per-cell delta application** below re-merges them at the cell
//!    level because every split contributes to the same `combined_sorted`
//!    value, hence the same `delta_per_cell[idx]`. Net effect on the
//!    state transition is identical regardless of how the prover orders
//!    equal-counter rows.
//! 5. **Sparse patch → cell**: `sel_a_cell[r]` is a length-`num_cells`
//!    one-hot. The sum-to-active constraint forces inactive segments to
//!    contribute zero; the weighted-sum constraint pins active segments
//!    to cell `combined_sorted[r] = row · w + bucket`.
//! 6. **State transition**: `final[idx] = initial[idx] + delta_per_cell
//!    [idx]` for every cell. The Poseidon2 hash gates bind `initial_packed`
//!    and `final_packed` to the public state commitments, so the prover
//!    cannot inflate or deflate any cell's delta without breaking the
//!    hash.
//!
//! ### Public inputs (same shape as v1/v2 — merge-compatible)
//!
//! 1. `initial_commit[0..2]` packed into 2 Challenge PIs.
//! 2. `final_commit[0..2]`.
//! 3. For each record `k`: `(key_k, value_k, pos_k[0..d])` as Challenge PIs.

use std::rc::Rc;

use p3_batch_stark::ProverData;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit::ops::{
    Poseidon2Config, generate_permute_trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        permute_air_builders, permute_preprocessor, poseidon2_air_builders_d4,
        poseidon2_preprocessor, recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_baby_bear::default_babybear_poseidon2_16;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::countmin::commit_countmin;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    CountMinLeafParams, CountMinLeafProof, DIGEST_PACKING, make_leaf_config,
    pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMin, CountMinState, CountMinUpdate, hash_cell};

/// FRI parameters — must equal the leaf-config's `LOG_FINAL_POLY_LEN = 6`
/// so a v3 leaf can be chained with v1/v2 leaves in the same recursive
/// merge (same boundary PIs, same proof shape).
const LOG_FINAL_POLY_LEN: usize = 6;

/// Bit shift used to encode `(combined, value)` into a single Challenge
/// element for the PermuteAir input column. `SHIFT_VAL = 2^20` allows
/// per-record `value < 1 048 576` without overlapping the `combined`
/// bits — comfortably above the per-record values our prototype sweeps
/// exercise (`value` is `u32` and the largest grid point uses `value <
/// 2^3`).
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

/// Pack the flattened counters of a state into Challenge elements (same
/// layout as v1's hash absorption).
fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Prove one Count-Min update epoch using the §5.2 v3 leaf.
///
/// Convenience entry point at the default `(D, W, BATCH) = (2, 4, 2)`.
pub fn prove_countmin_leaf_v3(
    initial_state: CountMinState,
    batch: [CountMinUpdate;
        crate::recursion::recursive::countmin_leaf::BATCH],
) -> CountMinLeafProof {
    let params = CountMinLeafParams::default();
    prove_countmin_leaf_v3_with_params(params, initial_state, batch.to_vec())
}

/// Runtime-parameterised v3 leaf prover. Same input contract as
/// `prove_countmin_leaf_with_params` in v1; the resulting
/// `CountMinLeafProof` plugs into `merge_two_countmin`,
/// `CountMinChainState::extend`, and `flat_merge_two_countmin` exactly like
/// a v1 or v2 leaf.
pub fn prove_countmin_leaf_v3_with_params(
    params: CountMinLeafParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinLeafProof {
    params.validate();
    assert_eq!(initial_state.params.d, params.d);
    assert_eq!(initial_state.params.w, params.w);
    assert_eq!(batch.len(), params.batch);

    let CountMinLeafParams { d, w, batch: m } = params;
    let num_cells = params.num_cells();
    let cell_packing = params.cell_packing();
    let n_ctr = m * d; // size of U_ctr and the sorted/A tables

    // Native pipeline + final state.
    let mut final_state = initial_state.clone();
    for u in &batch {
        CountMin::update(&mut final_state, u);
    }
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&final_state);

    // ─── Natively compute the U_ctr table + the σ permutation that sorts it
    //
    // U_ctr[k·d + i] = (combined = i·w + pos_k[i], value = value_k). σ is
    // the permutation such that `U_ctr_sorted[r] = U_ctr[σ[r]]`, sorting
    // by `combined`. We supply σ as the `PermuteAir` witness, and the
    // sorted-side decoded fields (combined_sorted, val_sorted) as decoded
    // private witnesses checked against the permuted payload column.
    let mut u_ctr_data: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
    for u in &batch {
        for i in 0..d {
            let bucket = hash_cell(i, u.key, w);
            let combined = (i * w + bucket) as u64;
            u_ctr_data.push((combined, u.value));
        }
    }
    let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr_data.iter().enumerate().collect();
    indexed.sort_by_key(|(_, (combined, _))| *combined);
    let sigma: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let combined_sorted_native: Vec<u64> = indexed.iter().map(|(_, (c, _))| *c).collect();
    let val_sorted_native: Vec<u32> = indexed.iter().map(|(_, (_, v))| *v).collect();

    // Adjacent-equality tags. `tag[r] = 1` iff `combined_sorted[r-1] ==
    // combined_sorted[r]`. Slot 0 is forced to 0 (no preceding row).
    let mut tag_native: Vec<u32> = vec![0; n_ctr];
    for r in 1..n_ctr {
        if combined_sorted_native[r] == combined_sorted_native[r - 1] {
            tag_native[r] = 1;
        }
    }

    // Running sum per segment.
    let mut acc_native: Vec<u32> = vec![0; n_ctr];
    acc_native[0] = val_sorted_native[0];
    for r in 1..n_ctr {
        acc_native[r] = if tag_native[r] == 1 {
            acc_native[r - 1].saturating_add(val_sorted_native[r])
        } else {
            val_sorted_native[r]
        };
    }

    // Segment-end flag (the active flag for A row r).
    let mut a_active_native: Vec<u32> = vec![0; n_ctr];
    for r in 0..n_ctr {
        let ends_segment = if r == n_ctr - 1 { true } else { tag_native[r + 1] == 0 };
        a_active_native[r] = if ends_segment { 1 } else { 0 };
    }

    // ─── Build the circuit ───────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);

    // ---- Public inputs (identical to v1/v2 — merge-compatible) ----
    let initial_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let mut record_pis: Vec<(ExprId, ExprId, Vec<ExprId>)> = Vec::with_capacity(m);
    for _ in 0..m {
        let key = b.alloc_public_input("key");
        let value = b.alloc_public_input("value");
        let pos: Vec<ExprId> = (0..d).map(|_| b.alloc_public_input("pos")).collect();
        record_pis.push((key, value, pos));
    }

    // ---- Constants ----
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
    let row_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "row_i"))
        .collect();
    let cell_idx_consts: Vec<ExprId> = (0..num_cells)
        .map(|idx| b.alloc_const(Challenge::from_u64(idx as u64), "cell_idx"))
        .collect();

    // ---- Private inputs ----
    // Packed cells for hash binding.
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();

    // Sorted-side decoded values.
    let combined_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("combined_sorted"))
        .collect();
    let val_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("val_sorted"))
        .collect();

    // Adjacent-equality tags + inverse witnesses (slot 0 unused but
    // allocated for indexing symmetry).
    let eq_tag: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("eq_tag"))
        .collect();
    let inv_diff: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("inv_diff"))
        .collect();

    // Per-A-row cell selector — one-hot pointing at the cell
    // `combined_sorted[r]` when the row is segment-end-active.
    let mut sel_a_cell: Vec<Vec<ExprId>> = Vec::with_capacity(n_ctr);
    for _ in 0..n_ctr {
        let row: Vec<ExprId> = (0..num_cells)
            .map(|_| b.alloc_private_input("sel_a_cell"))
            .collect();
        sel_a_cell.push(row);
    }

    // ---- Constraints ----

    // 1. Hash gates: bind packed cells to the public commitments.
    let digest_init = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &initial_packed, true)
        .expect("add_hash_slice(initial)");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], initial_commit_pis[i]);
    }
    let digest_final = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("add_hash_slice(final)");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
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

    // 3. Build the U_ctr payload column from PIs.
    //    payload[u = k·d + i] = (i·w + pos_k[i]) · SHIFT_VAL + value_k
    let mut payload: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for k in 0..m {
        for i in 0..d {
            let row_times_w = b.mul(row_consts[i], w_const);
            let combined_expr = b.add(row_times_w, record_pis[k].2[i]);
            let combined_shifted = b.mul(combined_expr, shift_val_const);
            let payload_expr = b.add(combined_shifted, record_pis[k].1);
            payload.push(payload_expr);
        }
    }

    // 4. Counter-sort via PermuteAir. The prover supplies σ; PermuteAir's
    //    LogUp bus enforces multiset(payload_sorted) == multiset(payload).
    //    Multi-column row-binding is preserved because the payload uniquely
    //    encodes (combined, value) under the bit-budget assumption.
    let payload_sorted: Vec<ExprId> = b
        .add_permute(&payload, sigma.clone())
        .expect("add_permute should accept σ of length n_ctr");

    // 5. Decode payload_sorted: combined_sorted · SHIFT_VAL + val_sorted == payload_sorted.
    for r in 0..n_ctr {
        let combined_shifted = b.mul(combined_sorted[r], shift_val_const);
        let recovered = b.add(combined_shifted, val_sorted[r]);
        b.connect(recovered, payload_sorted[r]);
    }

    // 6. Adjacent-equality tags (PoneglyphDB §4.3 Eq 7-8).
    //    Slot 0 has no preceding row, so both `eq_tag[0]` and `inv_diff[0]`
    //    are forced to zero. The `inv_diff[0]` constraint also serves to
    //    register that witness as an ALU operand (otherwise the
    //    WitnessChecks bus debug-assert would fire — every private input
    //    must participate in at least one ALU op).
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

    // 7. Running sum per segment.
    //    acc[0] = val_sorted[0]
    //    acc[r] = val_sorted[r] + eq_tag[r] · acc[r-1]
    let mut acc: Vec<ExprId> = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        let new_acc = b.add(val_sorted[r], carried);
        acc.push(new_acc);
    }

    // 8. Per-row segment-end flag — the "A row r is active" indicator.
    //    a_active[r] = 1 - eq_tag[r+1]    for r < n_ctr - 1
    //    a_active[n_ctr - 1] = 1          (last row always closes its segment)
    let mut a_active: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let active = if r == n_ctr - 1 {
            one
        } else {
            b.sub(one, eq_tag[r + 1])
        };
        a_active.push(active);
    }

    // 9. Per-A-row cell selector validity.
    //    For each r:
    //      - Each entry boolean: sel * (sel - 1) = 0.
    //      - Σ_idx sel[idx] = a_active[r]   (inactive rows contribute zero
    //        everywhere; active rows hit exactly one cell).
    //      - Σ_idx idx · sel[idx] = a_active[r] · combined_sorted[r].
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

    // 10. Per-cell delta from A: delta[idx] = Σ_r sel_a_cell[r][idx] · acc[r].
    //     State transition: final[idx] = initial[idx] + delta[idx].
    for idx in 0..num_cells {
        let mut delta_acc = b.mul(sel_a_cell[0][idx], acc[0]);
        for r in 1..n_ctr {
            let term = b.mul(sel_a_cell[r][idx], acc[r]);
            delta_acc = b.add(delta_acc, term);
        }
        let updated = b.add(initial_cells[idx], delta_acc);
        b.connect(updated, final_cells[idx]);
    }

    let circuit = b.build().expect("build v3 leaf circuit");

    // ─── Pack public + private values ─────────────────────────────────────
    let initial_commit_packed = pack_commit_to_challenge(&initial_commit);
    let final_commit_packed = pack_commit_to_challenge(&final_commit);

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&initial_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    for u in &batch {
        public_inputs.push(Challenge::from_u64(u.key));
        public_inputs.push(Challenge::from_u32(u.value));
        for r in 0..d {
            public_inputs.push(Challenge::from_u64(hash_cell(r, u.key, w) as u64));
        }
    }

    let initial_cells_packed = pack_cells_to_challenge(&initial_state);
    let final_cells_packed = pack_cells_to_challenge(&final_state);
    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&initial_cells_packed);
    private_inputs.extend_from_slice(&final_cells_packed);

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
    // inv_diff: 1/(combined_sorted[r-1] - combined_sorted[r]) when distinct, else 0.
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
    // sel_a_cell[r][idx] — one-hot to combined_sorted[r] when a_active[r] == 1.
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
        runner.run().expect("run v3 circuit")
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
        .expect("get_airs_and_degrees_with_prep (v3)");
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
        .expect("prove_all_tables (v3)");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify v3 leaf");

    CountMinLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch,
        params,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_leaf::{D, W};
    use crate::sketch::countmin::CountMinParams;

    fn empty_state() -> CountMinState {
        CountMin::new(&CountMinParams { d: D, w: W })
    }

    /// Default-shape `(D, W, BATCH) = (2, 4, 2)` round-trip — mirrors
    /// `countmin_leaf::tests::countmin_leaf_round_trip`.
    #[test]
    fn v3_leaf_round_trip() {
        let initial = empty_state();
        let batch = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let leaf = prove_countmin_leaf_v3(initial.clone(), batch);

        let mut expected = initial;
        for u in &batch {
            CountMin::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
    }

    /// Runtime-param at `(4, 4, 4)` — mirrors
    /// `countmin_leaf::tests::countmin_leaf_round_trip_at_4_4_4`.
    #[test]
    fn v3_leaf_round_trip_at_4_4_4() {
        let params = CountMinLeafParams { d: 4, w: 4, batch: 4 };
        params.validate();
        let initial = CountMin::new(&CountMinParams { d: params.d, w: params.w });
        let batch: Vec<CountMinUpdate> = (0..params.batch)
            .map(|i| CountMinUpdate { key: (i as u64) * 11 + 1, value: (i as u32) + 1 })
            .collect();
        let leaf = prove_countmin_leaf_v3_with_params(params, initial.clone(), batch.clone());

        let mut expected = initial;
        for u in &batch {
            CountMin::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
    }

    /// A v3 leaf must be a drop-in replacement for a v1 leaf in the §4.2
    /// recursive merge — same `CountMinLeafProof` shape, same
    /// `merge_two_countmin`.
    #[test]
    fn v3_leaf_merges_with_v1() {
        use crate::recursion::recursive::countmin_leaf::prove_countmin_leaf;
        use crate::recursion::recursive::countmin_merge::{
            merge_two_countmin, verify_chain_countmin,
        };

        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 42, value: 7 },
            CountMinUpdate { key: 99, value: 1 },
        ];
        let l1 = prove_countmin_leaf_v3(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            CountMin::update(&mut s1, u);
        }
        let b2 = [
            CountMinUpdate { key: 42, value: 3 },
            CountMinUpdate { key: 7, value: 9 },
        ];
        let l2 = prove_countmin_leaf(s1, b2);

        let chain = merge_two_countmin(&l1, &l2).expect("merge");
        verify_chain_countmin(&chain).expect("verify");
    }

    /// A v3 leaf must also chain with a v2 leaf (§5.4-shaped structural
    /// scaffold). Same merge function, different internal data flow on
    /// each side.
    #[test]
    fn v3_leaf_merges_with_v2() {
        use crate::recursion::recursive::countmin_leaf_v2::prove_countmin_leaf_v2;
        use crate::recursion::recursive::countmin_merge::{
            merge_two_countmin, verify_chain_countmin,
        };

        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 3, value: 4 },
            CountMinUpdate { key: 5, value: 6 },
        ];
        let l1 = prove_countmin_leaf_v3(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            CountMin::update(&mut s1, u);
        }
        let b2 = [
            CountMinUpdate { key: 5, value: 1 },
            CountMinUpdate { key: 13, value: 2 },
        ];
        let l2 = prove_countmin_leaf_v2(s1, b2);

        let chain = merge_two_countmin(&l1, &l2).expect("merge");
        verify_chain_countmin(&chain).expect("verify");
    }
}
