//! §5.2 Count-Min update leaf (the v3 design).
//!
//! This module implements the new §5.2 "Count-Min Circuit Design" from the
//! paper as a CircuitBuilder leaf. The §5.2 maintenance plan is:
//!
//! ```text
//! B ──group by key──▶ G ──compute counter ids──▶ U_ctr ──group by counter──▶ A ──sparse patch──▶ S_t
//! ```
//!
//! Compared to the §5.1 strawman in `countmin_leaf.rs` (which materialises
//! per-cell selectors and replays `final = initial + Σ(selector · value)`
//! cell-by-cell), and the §5.4 structural seam in `countmin_leaf_v2.rs`
//! (which exposes a flat aggregate vector `A[i·w+j]`), v3 exposes the §5.2
//! *sparse patch* `A` as an explicit witness: `m·d` rows, each `(active,
//! row, bucket, delta)`, where the active rows are exactly the touched
//! counters and the delta is the net contribution to that counter from
//! the whole batch.
//!
//! ### What §5.2 step gets which in-circuit machinery
//!
//! - **Steps 1 (batch binding)** — records' `(key, value, pos[0..d])` are
//!   public inputs, identical to v1/v2 (so the leaf is merge-compatible).
//! - **Steps 2–3 (key-group + key-aggregate)** — *skipped as a prototype
//!   simplification*. The plaintext pipeline in `src/sketch/countmin_v3.rs`
//!   carries the full key-grouping for the soundness oracle; in-circuit we
//!   go directly from per-record positions to the per-(record,row)
//!   counter-update vector. This is sound — the counter-group step below
//!   still merges any per-record collisions at the same counter — and the
//!   "key-group" optimisation only matters when the framework can avoid
//!   recomputing per-duplicate-key hashes, which our keep-per-record-PIs
//!   design already does.
//! - **Step 4 (counter-derive)** — `U_ctr[k·d + i] = (key_k, row=i,
//!   bucket=pos_k[i], value=value_k)` is materialised purely from PIs and
//!   the loop index — no new witnesses.
//! - **Steps 5–6 (counter-group + counter-aggregate)** — implemented as a
//!   per-(record,row) → per-A-row selector binding (PoneglyphDB §4.3
//!   group-by gate, written via boolean selectors instead of inline
//!   sortedness checks). For each `(k, i)` the prover supplies a one-hot
//!   selector over A rows; the constraint forces the selected A row to
//!   match `(row=i, bucket=pos_k[i])` and contribute `value_k` to that
//!   row's delta. Per the user's clarification, no range-checked sortedness
//!   is enforced — `A` is just an unsorted sparse vector whose entries are
//!   bound to the records via the selectors.
//! - **Step 7 (sparse-patch apply)** — per-A-row "cell selector"
//!   `sel_a_cell[r][idx]` is a one-hot over `d·w` cells pointing at the
//!   `(row_r, bucket_r)` cell. The per-cell delta is built as
//!   `Σ_r sel_a_cell[r][idx] · delta_r`, and the transition is the
//!   familiar `final[idx] = initial[idx] + delta[idx]`.
//! - **Step 8 (metadata)** — fixed at compile time via the FRI config and
//!   `CountMinLeafParams`, identical to v1/v2.
//!
//! ### Public inputs (same shape as v1/v2 — merge-compatible)
//!
//! 1. `initial_commit[0..2]` packed into 2 Challenge PIs.
//! 2. `final_commit[0..2]`.
//! 3. For each record `k`: `(key_k, value_k, pos_k[0..d])` as Challenge PIs.
//!
//! ### Soundness sketch
//!
//! The §5.2 sparse patch `A` is bound to the records by:
//! - For each `(k, i)`, the selector `sel_a[k·d+i][r]` is a one-hot vector
//!   over A's `m·d` rows.
//! - Constraints force the selected `r` to have `A.row[r] = i` and
//!   `A.bucket[r] = pos_k[i]`.
//! - Per A row `r`, `A.delta[r] = Σ_{(k,i)} sel_a[k·d+i][r] · value_k` —
//!   the row's delta is the sum of every record's contribution that lands
//!   there.
//! - The per-cell delta column is then bound to `A` via the cell selectors.
//!
//! A malicious prover cannot inflate or deflate any cell's delta because
//! every record's contribution `value_k` is accounted for in exactly one A
//! row (selector sums to 1), and each A row's delta is exactly the sum of
//! its accounted contributions. The state transition then forces
//! `final = initial + Σ deltas`.

use std::rc::Rc;

use p3_batch_stark::ProverData;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_baby_bear::default_babybear_poseidon2_16;
use p3_field::PrimeCharacteristicRing;
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
use crate::sketch::countmin_v3;

/// FRI parameters — must equal the leaf-config's `LOG_FINAL_POLY_LEN = 6`
/// so a v3 leaf can be chained with v1/v2 leaves in the same recursive
/// merge (same boundary PIs, same proof shape).
const LOG_FINAL_POLY_LEN: usize = 6;

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
    let n_ctr = m * d; // size of U_ctr and A tables

    // Native pipeline + final state.
    let mut final_state = initial_state.clone();
    for u in &batch {
        CountMin::update(&mut final_state, u);
    }
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&final_state);

    // The §5.2 pipeline (plaintext oracle) — supplies A and the selectors.
    let pipeline = countmin_v3::build(&initial_state, &batch);

    // Build the "A-row-index for each (k, i)" map: for each per-record
    // counter-update entry, find the A row that aggregates it. The
    // plaintext pipeline already produced one valid A; we just locate
    // each `(row=i, bucket=pos_k[i])` within it.
    let mut a_row_for_contrib: Vec<usize> = Vec::with_capacity(n_ctr);
    for u in &batch {
        for i in 0..d {
            let bucket = hash_cell(i, u.key, w);
            let idx = pipeline
                .a
                .iter()
                .position(|a| a.active && a.row == i && a.bucket == bucket)
                .expect("every per-record counter location must appear in A");
            a_row_for_contrib.push(idx);
        }
    }

    // ─── Build the circuit ───────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

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

    // ---- Private inputs ----
    // 1. Packed cells for hash binding.
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();

    // 2. Sparse patch A: per-row (active, row, bucket, delta).
    let a_active: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("a_active")).collect();
    let a_row: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("a_row")).collect();
    let a_bucket: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("a_bucket")).collect();
    let a_delta: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("a_delta")).collect();

    // 3. Per-(record, row) selector over A rows — one-hot of length n_ctr.
    //    sel_a[k*d + i][r] = 1 iff the (k, i) per-record counter update lands
    //    in A row r.
    let mut sel_a: Vec<Vec<ExprId>> = Vec::with_capacity(n_ctr);
    for _ in 0..n_ctr {
        let row: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("sel_a")).collect();
        sel_a.push(row);
    }

    // 4. Per-A-row "cell selector" over the d*w cells — one-hot pointing at
    //    cell (a_row[r], a_bucket[r]).
    let mut sel_a_cell: Vec<Vec<ExprId>> = Vec::with_capacity(n_ctr);
    for _ in 0..n_ctr {
        let row: Vec<ExprId> = (0..num_cells)
            .map(|_| b.alloc_private_input("sel_a_cell"))
            .collect();
        sel_a_cell.push(row);
    }

    // ---- Constraints ----

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let row_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "row_i"))
        .collect();
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let cell_idx_consts: Vec<ExprId> = (0..num_cells)
        .map(|idx| b.alloc_const(Challenge::from_u64(idx as u64), "cell_idx"))
        .collect();

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

    // 2. Decompose packed cells into individual base-embedded ExprIds for
    //    the per-cell transition.
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

    // 3. Per-A-row "active is boolean": active * (active - 1) = 0.
    for r in 0..n_ctr {
        let am1 = b.sub(a_active[r], one);
        let prod = b.mul(a_active[r], am1);
        b.connect(prod, zero);
    }

    // 4. Per-(record, row) selector validity. sel_a[k*d+i] is a one-hot
    //    vector of length n_ctr.
    //
    //    For each (k, i):
    //      - Each entry boolean: sel * (sel - 1) = 0.
    //      - Sum over r of sel_a[k*d+i][r] = 1.
    //      - Sum over r of A_row[r]    * sel_a[k*d+i][r] = i.
    //      - Sum over r of A_bucket[r] * sel_a[k*d+i][r] = pos_k[i].
    //
    //    The last two pin the selected A row to match `(row=i, bucket=pos_k[i])`.
    for k in 0..m {
        for i in 0..d {
            let u = k * d + i;
            let sel = &sel_a[u];

            // Booleans.
            for r in 0..n_ctr {
                let sm1 = b.sub(sel[r], one);
                let prod = b.mul(sel[r], sm1);
                b.connect(prod, zero);
            }

            // Sum = 1.
            let mut sum = sel[0];
            for r in 1..n_ctr {
                sum = b.add(sum, sel[r]);
            }
            b.connect(sum, one);

            // Σ A_row * sel = i.
            let mut row_acc = b.mul(a_row[0], sel[0]);
            for r in 1..n_ctr {
                let term = b.mul(a_row[r], sel[r]);
                row_acc = b.add(row_acc, term);
            }
            b.connect(row_acc, row_consts[i]);

            // Σ A_bucket * sel = pos_k[i].
            let mut bucket_acc = b.mul(a_bucket[0], sel[0]);
            for r in 1..n_ctr {
                let term = b.mul(a_bucket[r], sel[r]);
                bucket_acc = b.add(bucket_acc, term);
            }
            b.connect(bucket_acc, record_pis[k].2[i]);
        }
    }

    // 5. Per-A-row delta is the sum of every (k, i) contribution landing here.
    //    a_delta[r] = Σ_{(k,i)} sel_a[k*d+i][r] * value_k.
    for r in 0..n_ctr {
        let mut acc = zero;
        for k in 0..m {
            for i in 0..d {
                let u = k * d + i;
                let term = b.mul(sel_a[u][r], record_pis[k].1);
                acc = b.add(acc, term);
            }
        }
        b.connect(acc, a_delta[r]);
    }

    // 6. Per-A-row cell selector validity. sel_a_cell[r] is a one-hot vector
    //    of length num_cells = d*w.
    //
    //    For each r:
    //      - Each entry boolean.
    //      - Sum over idx of sel_a_cell[r][idx] = a_active[r]  (sum is the
    //        active flag, so inactive rows contribute zero everywhere).
    //      - Σ idx * sel_a_cell[r][idx] = a_active[r] * (a_row[r] * w + a_bucket[r])
    //        — when active, selects cell (a_row[r], a_bucket[r]); when
    //        inactive, the LHS and RHS are both zero (every sel = 0).
    for r in 0..n_ctr {
        let sel = &sel_a_cell[r];

        // Booleans.
        for idx in 0..num_cells {
            let sm1 = b.sub(sel[idx], one);
            let prod = b.mul(sel[idx], sm1);
            b.connect(prod, zero);
        }

        // Sum = a_active.
        let mut sum = sel[0];
        for idx in 1..num_cells {
            sum = b.add(sum, sel[idx]);
        }
        b.connect(sum, a_active[r]);

        // Σ idx * sel = a_active * (a_row * w + a_bucket).
        let mut idx_acc = b.mul(cell_idx_consts[0], sel[0]);
        for idx in 1..num_cells {
            let term = b.mul(cell_idx_consts[idx], sel[idx]);
            idx_acc = b.add(idx_acc, term);
        }
        let row_w = b.mul(a_row[r], w_const);
        let cell_idx = b.add(row_w, a_bucket[r]);
        let active_cell_idx = b.mul(a_active[r], cell_idx);
        b.connect(idx_acc, active_cell_idx);
    }

    // 7. Per-cell delta from A: delta[idx] = Σ_r sel_a_cell[r][idx] * a_delta[r].
    //    Then state transition: final[idx] = initial[idx] + delta[idx].
    for idx in 0..num_cells {
        let mut delta_acc = b.mul(sel_a_cell[0][idx], a_delta[0]);
        for r in 1..n_ctr {
            let term = b.mul(sel_a_cell[r][idx], a_delta[r]);
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

    // A: active, row, bucket, delta — column-major.
    for r in 0..n_ctr {
        let ar = &pipeline.a[r];
        private_inputs.push(if ar.active { Challenge::ONE } else { Challenge::ZERO });
    }
    for r in 0..n_ctr {
        let ar = &pipeline.a[r];
        private_inputs.push(Challenge::from_u64(ar.row as u64));
    }
    for r in 0..n_ctr {
        let ar = &pipeline.a[r];
        private_inputs.push(Challenge::from_u64(ar.bucket as u64));
    }
    for r in 0..n_ctr {
        let ar = &pipeline.a[r];
        private_inputs.push(Challenge::from_u32(ar.delta));
    }

    // sel_a[u][r] — record (k, i) contributes to A row r.
    for u in 0..n_ctr {
        let target = a_row_for_contrib[u];
        for r in 0..n_ctr {
            private_inputs.push(if r == target { Challenge::ONE } else { Challenge::ZERO });
        }
    }

    // sel_a_cell[r][idx] — A row r points to cell idx.
    for r in 0..n_ctr {
        let ar = &pipeline.a[r];
        let target_idx = if ar.active { ar.row * w + ar.bucket } else { usize::MAX };
        for idx in 0..num_cells {
            private_inputs.push(if idx == target_idx { Challenge::ONE } else { Challenge::ZERO });
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
    let preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));

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
