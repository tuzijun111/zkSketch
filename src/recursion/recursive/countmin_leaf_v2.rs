//! Count-Min leaf v2: same public inputs as `countmin_leaf`, but the transition is
//! `final = initial + A` with an explicit per-cell aggregate `A`.

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

/// FRI parameters — must equal the leaf-config's `LOG_FINAL_POLY_LEN = 6`
/// so a v2 leaf can be chained with v1 leaves in the same recursive merge.
const LOG_FINAL_POLY_LEN: usize = 6;

/// Pack the flattened counters of a state into Challenge elements (same
/// layout as v1's hash absorption).
fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(4)
        .map(|chunk| {
            use p3_field::BasedVectorSpace;
            Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs")
        })
        .collect()
}

/// Compute the v2 per-cell aggregate table `A` natively.
///
/// `A[i * w + j] = sum over (k, r) where r == i and hash_cell(r, key_k, w) == j of value_k`.
fn build_aggregate(state_params: (usize, usize), batch: &[CountMinUpdate]) -> Vec<Val> {
    let (d, w) = state_params;
    let mut a = vec![Val::ZERO; d * w];
    for u in batch {
        for r in 0..d {
            let col = hash_cell(r, u.key, w);
            a[r * w + col] += Val::from_u32(u.value);
        }
    }
    a
}

/// Prove one Count-Min update epoch using the §5.4-shaped v2 leaf.
///
/// Convenience entry point at the default `(D, W, BATCH) = (2, 4, 2)`.
pub fn prove_countmin_leaf_v2(
    initial_state: CountMinState,
    batch: [CountMinUpdate;
        crate::recursion::recursive::countmin_leaf::BATCH],
) -> CountMinLeafProof {
    let params = CountMinLeafParams::default();
    prove_countmin_leaf_v2_with_params(params, initial_state, batch.to_vec())
}

/// Runtime-parameterised version. Same input contract as
/// `prove_countmin_leaf_with_params` in v1; the resulting
/// `CountMinLeafProof` is verified by exactly the same downstream
/// chains, merges and flat paths.
pub fn prove_countmin_leaf_v2_with_params(
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

    let mut final_state = initial_state.clone();
    for u in &batch {
        CountMin::update(&mut final_state, u);
    }
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&final_state);
    let aggregate = build_aggregate((d, w), &batch);

    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // ---- Public inputs (identical to v1) ----
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
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();

    // v2-specific: per-cell aggregate A as explicit private witnesses.
    // `A[i * w + j]` is the §5.4 segment-aggregated delta for cell (i, j).
    let agg: Vec<ExprId> = (0..num_cells)
        .map(|_| b.alloc_private_input("aggregate"))
        .collect();

    // Selectors `s[k][r][j]` retained — they're the in-circuit handle on
    // per-record-per-row position. A future Merkle / LogUp variant would
    // drop these entirely; v2 keeps them so the constraints land on
    // ground both v1 and §5.4 agree on.
    let mut selectors: Vec<Vec<Vec<ExprId>>> = Vec::with_capacity(m);
    for _ in 0..m {
        let mut per_row = Vec::with_capacity(d);
        for _ in 0..d {
            let s: Vec<ExprId> = (0..w).map(|_| b.alloc_private_input("sel")).collect();
            per_row.push(s);
        }
        selectors.push(per_row);
    }

    // ---- Constraints ----

    // 1. Hash initial cells.
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

    // Decompose packed cells for per-cell constraints.
    let initial_cells: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    let final_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();

    let one = b.alloc_const(Challenge::ONE, "one");
    let j_consts: Vec<ExprId> = (0..w)
        .map(|j| b.alloc_const(Challenge::from_u64(j as u64), "j"))
        .collect();

    // 2. Selector validity (one-hot pinned to `pos[k][r]`).
    for k in 0..m {
        for r in 0..d {
            let s = &selectors[k][r];
            let mut sum = s[0];
            for j in 1..w {
                sum = b.add(sum, s[j]);
            }
            b.connect(sum, one);

            let zero = b.alloc_const(Challenge::ZERO, "zero");
            let mut weighted = zero;
            for j in 0..w {
                let term = b.mul(s[j], j_consts[j]);
                weighted = b.add(weighted, term);
            }
            b.connect(weighted, record_pis[k].2[r]);
        }
    }

    // 3. §5.4 segment-aggregation. For each cell (i, j),
    //    A[i * w + j] = sum over k of selector[k][i][j] * value[k].
    //
    // This is the data-flow refactor from v1: the per-cell aggregate is
    // exposed as an explicit witness vector (the "A" table in §5.4) and
    // the application step below reads from it.
    for i in 0..d {
        for j in 0..w {
            let idx = i * w + j;
            let zero = b.alloc_const(Challenge::ZERO, "zero");
            let mut acc = zero;
            for k in 0..m {
                let contrib = b.mul(selectors[k][i][j], record_pis[k].1);
                acc = b.add(acc, contrib);
            }
            b.connect(acc, agg[idx]);
        }
    }

    // 4. §5.4 sparse-patch application:
    //    final[i * w + j] == initial[i * w + j] + A[i * w + j].
    //
    // (In a future homomorphic-commitment variant, this collapses to a
    // single EC equation `Com(S_t) = Com(S_{t-1}) + Com(Δ)` and the
    // per-cell iteration disappears.)
    for idx in 0..num_cells {
        let sum = b.add(initial_cells[idx], agg[idx]);
        b.connect(sum, final_cells[idx]);
    }

    let circuit = b.build().expect("build v2 leaf circuit");

    // ---- Pack public + private values ----
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
    // The aggregate A, in row-major order.
    for &a in &aggregate {
        private_inputs.push(Challenge::from(a));
    }
    // Then the selectors.
    for k in 0..m {
        for r in 0..d {
            let pos = hash_cell(r, batch[k].key, w);
            for j in 0..w {
                private_inputs.push(if j == pos { Challenge::ONE } else { Challenge::ZERO });
            }
        }
    }

    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run v2 circuit")
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
        .expect("get_airs_and_degrees_with_prep (v2)");
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
        .expect("prove_all_tables (v2)");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify v2 leaf");

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

    #[test]
    fn v2_leaf_round_trip() {
        let initial = empty_state();
        let batch = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let leaf = prove_countmin_leaf_v2(initial.clone(), batch);

        let mut expected = initial;
        for u in &batch {
            CountMin::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
    }

    /// A v2 leaf must be a drop-in replacement for a v1 leaf in the §4.2
    /// recursive merge — same `CountMinLeafProof` shape, same `merge_two_countmin`.
    #[test]
    fn v2_leaf_merges_with_v1() {
        use crate::recursion::recursive::countmin_leaf::prove_countmin_leaf;
        use crate::recursion::recursive::countmin_merge::{merge_two_countmin, verify_chain_countmin};

        let s0 = empty_state();
        let b1 = [
            CountMinUpdate { key: 42, value: 7 },
            CountMinUpdate { key: 99, value: 1 },
        ];
        let l1 = prove_countmin_leaf_v2(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            CountMin::update(&mut s1, u);
        }
        let b2 = [
            CountMinUpdate { key: 42, value: 3 },
            CountMinUpdate { key: 7, value: 9 },
        ];
        // Second leaf via v1 to confirm interoperability.
        let l2 = prove_countmin_leaf(s1, b2);

        let chain = merge_two_countmin(&l1, &l2).expect("merge");
        verify_chain_countmin(&chain).expect("verify");
    }
}
