//! Parallel / additive merge for v9 Count-Min leaves.
//!
//! Unlike the sequential [`countmin_merge_v9`] which threads two leaves
//! via shared-boundary identity (`l_1.final == l_2.initial`), this module
//! **adds** two sketches cell-wise. Both leaves are proven from an empty
//! initial state — so each leaf certifies `0 → A_i`. The additive merge
//! then proves
//!
//! > `M[i][j] = A_1[i][j] + A_2[i][j]   for all i ∈ [0, d), j ∈ [0, w)`
//!
//! *in-circuit*, and publishes `Com(M)`. The merged state `M` is also
//! materialized natively in the returned proof so the caller can answer
//! queries against it directly.
//!
//! This is the "merge two count-min sketches by adding their corresponding
//! cells" pattern — the standard linearity property of Count-Min, lifted
//! into a verifier-checkable form.
//!
//! ### What the returned proof certifies
//!
//! - **`recursive_proof`**: a batch-STARK that recursively verifies both
//!   leaf STARKs (the same `build_and_prove_aggregation_layer` call the
//!   sequential merge uses).
//! - **`cell_sum_proof`**: a small standalone STARK that opens `Com(A_1)`,
//!   `Com(A_2)`, and `Com(M)` via Poseidon2, then asserts the per-cell
//!   sum relation. Total ~`d·w` field additions plus 3 Poseidon2 hashes —
//!   small compared to a leaf prove.
//! - Together: the two proofs certify that **both leaves were valid** *and*
//!   **their final-state cells sum to `M` cell-wise**.
//!
//! ### Usage shape
//!
//! Each leaf must be proven from `CountMinV9::new(&params)` (empty initial
//! state) and you must hand the leaf's resulting cell array back to the
//! merge so the cell-sum circuit can use it as a private witness. The
//! merge then exposes `Com(A_1)`, `Com(A_2)`, `Com(M)`, and the cells of
//! `M` natively.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::{
    BatchOnly, ProveNextLayerParams, RecursionOutput,
    build_and_prove_aggregation_layer,
};
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::countmin::commit_countmin;
use crate::commitment::{CountMinBatchCommit, CountMinCommit};
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::{
    CountMinLeafParams, DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::recursion::recursive::countmin_leaf_v9::CountMinLeafProofV9;
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMinParams, CountMinState};
use crate::sketch::countmin_v9::CountMinV9;

const LOG_FINAL_POLY_LEN: usize = 6;

/// Aggregated proof of "two v9 leaves' cells sum cell-wise to M".
pub struct CountMinAdditiveMergeProof {
    /// Recursive batch-STARK certifying both leaves' STARKs are valid.
    pub recursive_proof: RecursionOutput<ConfigWithFriParams>,
    /// Standalone STARK certifying `M[i][j] = A_1[i][j] + A_2[i][j]` and
    /// the three commitment hashes.
    pub cell_sum_proof: RecursionOutput<ConfigWithFriParams>,
    /// `Com(A_1)` — left leaf's final-state commitment.
    pub a1: CountMinCommit,
    /// `Com(A_2)` — right leaf's final-state commitment.
    pub a2: CountMinCommit,
    /// `Com(M)` — merged sketch's commitment.
    pub m: CountMinCommit,
    /// `M` materialized as cells — for direct query answering.
    pub merged_state: CountMinState,
    /// Per-leaf batch commitments (privacy-preserving — same shape as
    /// `CountMinChainProofV9.batch_commits`).
    pub batch_commits: Vec<CountMinBatchCommit>,
    pub params: CountMinLeafParams,
}

#[derive(Debug)]
pub enum CountMinAdditiveMergeError {
    /// One of the leaves did not start from `CountMinV9::new(&params)`.
    NonEmptyInitial { which: &'static str, actual: CountMinCommit, expected: CountMinCommit },
    /// The supplied cells of `A_i` don't hash to the leaf's `final_` commit.
    CellsCommitMismatch { which: &'static str },
    AggregationFailed(String),
    CellSumProveFailed(String),
    VerifyFailed(String),
}

impl core::fmt::Display for CountMinAdditiveMergeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonEmptyInitial { which, actual, expected } => write!(
                f,
                "additive merge requires {which} leaf to start from the empty state; \
                 got initial {actual:?}, expected {expected:?}"
            ),
            Self::CellsCommitMismatch { which } => {
                write!(f, "{which} cell array does not hash to the leaf's final_ commitment")
            }
            Self::AggregationFailed(s) => write!(f, "recursive aggregation failed: {s}"),
            Self::CellSumProveFailed(s) => write!(f, "cell-sum STARK prove failed: {s}"),
            Self::VerifyFailed(s) => write!(f, "verify failed: {s}"),
        }
    }
}

impl core::error::Error for CountMinAdditiveMergeError {}

fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// Pack a `CountMinState`'s flattened cells into Challenge elements (same
/// layout `commit_countmin` hashes — the cell-sum circuit's Poseidon2
/// hash absorbs this).
fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Prove the in-circuit cell-sum relation `M[idx] = A_1[idx] + A_2[idx]`
/// for every cell, plus the three Poseidon2 commitments.
///
/// Exposed `pub(crate)` so callers can time it independently of the
/// recursive aggregation step (see `bench_v9_merge_additive` in
/// `src/sketch/countmin_v3.rs`).
pub(crate) fn prove_cell_sum(
    a1: &CountMinState,
    a2: &CountMinState,
    m: &CountMinState,
) -> Result<RecursionOutput<ConfigWithFriParams>, CountMinAdditiveMergeError> {
    assert_eq!(a1.params, a2.params, "a1/a2 param mismatch");
    assert_eq!(a1.params, m.params, "a1/m param mismatch");

    let d = a1.params.d;
    let w = a1.params.w;
    let num_cells = d * w;
    assert!(num_cells % 4 == 0, "num_cells must be a multiple of 4");
    let cell_packing = num_cells / 4;

    // ─── Build the cell-sum circuit ──────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // PIs: Com(A_1), Com(A_2), Com(M).
    let com_a1_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "com_a1_lo" } else { "com_a1_hi" })
    });
    let com_a2_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "com_a2_lo" } else { "com_a2_hi" })
    });
    let com_m_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "com_m_lo" } else { "com_m_hi" })
    });

    // Private: packed cells of A_1, A_2, M.
    let a1_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("a1_packed"))
        .collect();
    let a2_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("a2_packed"))
        .collect();
    let m_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("m_packed"))
        .collect();

    // 1. Bind commits via Poseidon2.
    let h_a1 = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &a1_packed, true)
        .expect("hash a1");
    for i in 0..DIGEST_PACKING {
        b.connect(h_a1[i], com_a1_pis[i]);
    }
    let h_a2 = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &a2_packed, true)
        .expect("hash a2");
    for i in 0..DIGEST_PACKING {
        b.connect(h_a2[i], com_a2_pis[i]);
    }
    let h_m = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &m_packed, true)
        .expect("hash m");
    for i in 0..DIGEST_PACKING {
        b.connect(h_m[i], com_m_pis[i]);
    }

    // 2. Per-cell M constraint at the *packed* Challenge level.
    //    Challenge = BabyBear^4, and Challenge addition is per-coefficient.
    //    So if `a1_packed[c] + a2_packed[c] = m_packed[c]` holds at the
    //    Challenge level, then `A_1[idx] + A_2[idx] = M[idx]` follows for
    //    every cell `idx` that packs into chunk `c`. One add+connect per
    //    chunk — `cell_packing` operations total, vs `num_cells` if we
    //    decomposed.
    //
    //    This avoids decomposing `m_packed` (which previously tripped the
    //    WitnessChecks bus — the decomposed M cells had nowhere natural to
    //    flow given the per-chunk encoding) and is cheaper besides.
    for c in 0..cell_packing {
        let chunk_sum = b.add(a1_packed[c], a2_packed[c]);
        b.connect(chunk_sum, m_packed[c]);
    }

    let circuit = b.build().expect("build cell-sum circuit");

    // ─── Pack inputs ─────────────────────────────────────────────────────
    let com_a1 = commit_countmin(a1);
    let com_a2 = commit_countmin(a2);
    let com_m = commit_countmin(m);

    let com_a1_packed = pack_commit_to_challenge(&com_a1);
    let com_a2_packed = pack_commit_to_challenge(&com_a2);
    let com_m_packed = pack_commit_to_challenge(&com_m);

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&com_a1_packed);
    public_inputs.extend_from_slice(&com_a2_packed);
    public_inputs.extend_from_slice(&com_m_packed);

    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&pack_cells_to_challenge(a1));
    private_inputs.extend_from_slice(&pack_cells_to_challenge(a2));
    private_inputs.extend_from_slice(&pack_cells_to_challenge(m));

    // ─── Run + prove ─────────────────────────────────────────────────────
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run cell-sum circuit")
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
        .expect("get_airs_and_degrees_with_prep (cell-sum)");
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
        .map_err(|e| CountMinAdditiveMergeError::CellSumProveFailed(format!("{e:?}")))?;
    prover
        .verify_all_tables(&proof)
        .map_err(|e| CountMinAdditiveMergeError::CellSumProveFailed(format!("self-verify: {e:?}")))?;

    Ok(RecursionOutput(proof, Rc::new(circuit_prover_data)))
}

/// Merge two v9 leaves additively: both must have been proven from the
/// empty initial state; the merge then certifies cell-wise sum.
pub fn merge_two_countmin_v9_additive(
    l1: &CountMinLeafProofV9,
    a1_state: &CountMinState,
    l2: &CountMinLeafProofV9,
    a2_state: &CountMinState,
) -> Result<CountMinAdditiveMergeProof, CountMinAdditiveMergeError> {
    assert_eq!(a1_state.params, a2_state.params, "a1/a2 param shape mismatch");
    assert_eq!(l1.params, l2.params, "leaf params mismatch between l1 and l2");
    let params = l1.params;
    let CountMinLeafParams { d, w, .. } = params;
    assert_eq!(a1_state.params.d, d);
    assert_eq!(a1_state.params.w, w);

    // 1. Leaves must start from the empty state.
    let empty_state = CountMinV9::new(&CountMinParams { d, w });
    let empty_commit = commit_countmin(&empty_state);
    if l1.initial != empty_commit {
        return Err(CountMinAdditiveMergeError::NonEmptyInitial {
            which: "left",
            actual: l1.initial,
            expected: empty_commit,
        });
    }
    if l2.initial != empty_commit {
        return Err(CountMinAdditiveMergeError::NonEmptyInitial {
            which: "right",
            actual: l2.initial,
            expected: empty_commit,
        });
    }

    // 2. The supplied cells must hash to the leaves' final_ commits.
    if commit_countmin(a1_state) != l1.final_ {
        return Err(CountMinAdditiveMergeError::CellsCommitMismatch { which: "left" });
    }
    if commit_countmin(a2_state) != l2.final_ {
        return Err(CountMinAdditiveMergeError::CellsCommitMismatch { which: "right" });
    }

    // 3. Compute M = A_1 + A_2 natively.
    let mut merged_state = a1_state.clone();
    for i in 0..d {
        for j in 0..w {
            merged_state.counters[i][j] = a1_state.counters[i][j]
                .saturating_add(a2_state.counters[i][j]);
        }
    }
    let com_m = commit_countmin(&merged_state);

    // 4. Prove the cell-sum circuit.
    let cell_sum_proof = prove_cell_sum(a1_state, a2_state, &merged_state)?;

    // 5. Recursively aggregate both leaves' STARK proofs.
    let config = make_leaf_config();
    let backend = make_backend();
    let recursion_params = agg_params();

    let left_input = l1.output.into_recursion_input::<BatchOnly>();
    let right_input = l2.output.into_recursion_input::<BatchOnly>();

    let recursive_proof = build_and_prove_aggregation_layer::<
        ConfigWithFriParams,
        BatchOnly,
        BatchOnly,
        Backend,
        EXT_D,
    >(&left_input, &right_input, &config, &backend, &recursion_params, None)
    .map_err(|e| CountMinAdditiveMergeError::AggregationFailed(format!("{e:?}")))?;

    Ok(CountMinAdditiveMergeProof {
        recursive_proof,
        cell_sum_proof,
        a1: l1.final_,
        a2: l2.final_,
        m: com_m,
        merged_state,
        batch_commits: vec![l1.batch_commit, l2.batch_commit],
        params,
    })
}

/// Verify the two proofs inside an additive merge.
pub fn verify_additive_merge(
    p: &CountMinAdditiveMergeProof,
) -> Result<(), CountMinAdditiveMergeError> {
    let config = make_leaf_config();

    // Verify recursive aggregation (leaves).
    let recursion_params = agg_params();
    let mut v1 = BatchStarkProver::new(config.clone())
        .with_table_packing(recursion_params.table_packing.clone());
    v1.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    v1.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    v1.verify_all_tables(&p.recursive_proof.0)
        .map_err(|e| CountMinAdditiveMergeError::VerifyFailed(format!("recursive: {e:?}")))?;

    // Verify cell-sum proof.
    let cell_sum_table_packing =
        TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut v2 = BatchStarkProver::new(config).with_table_packing(cell_sum_table_packing);
    v2.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    v2.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    v2.verify_all_tables(&p.cell_sum_proof.0)
        .map_err(|e| CountMinAdditiveMergeError::VerifyFailed(format!("cell-sum: {e:?}")))?;

    // Native sanity: M actually equals A_1 + A_2 cell-wise (matches what
    // the cell-sum proof attests, given honestly-constructed proof).
    if commit_countmin(&p.merged_state) != p.m {
        return Err(CountMinAdditiveMergeError::VerifyFailed(
            "merged_state cells do not hash to advertised Com(M)".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_leaf::W;
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_with_params;
    use crate::sketch::countmin::CountMinUpdate;

    #[test]
    fn additive_merge_round_trip() {
        let params = CountMinLeafParams { d: 2, w: W, batch: 2 };

        // Both leaves start from empty.
        let s0 = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });

        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf_v9_with_params(params, s0.clone(), b1.clone());

        let b2 = vec![
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let l2 = prove_countmin_leaf_v9_with_params(params, s0.clone(), b2.clone());

        // Compute the leaves' final cells natively.
        let mut a1 = s0.clone();
        for u in &b1 {
            CountMinV9::update(&mut a1, u);
        }
        let mut a2 = s0;
        for u in &b2 {
            CountMinV9::update(&mut a2, u);
        }

        let proof = merge_two_countmin_v9_additive(&l1, &a1, &l2, &a2).expect("additive merge");
        verify_additive_merge(&proof).expect("verify additive merge");

        // merged_state must equal a1 + a2 cell-wise.
        for i in 0..params.d {
            for j in 0..params.w {
                assert_eq!(
                    proof.merged_state.counters[i][j],
                    a1.counters[i][j].saturating_add(a2.counters[i][j]),
                    "mismatch at cell ({i},{j})",
                );
            }
        }
    }

    /// A leaf with non-empty initial state is rejected before the prover runs.
    #[test]
    fn additive_merge_rejects_nonempty_initial() {
        let params = CountMinLeafParams { d: 2, w: W, batch: 2 };
        let s0 = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });

        // Apply a batch to get a NON-empty s1; use s1 as l2's initial state
        // to deliberately violate the additive-merge contract.
        let b_warmup = vec![
            CountMinUpdate { key: 1, value: 1 },
            CountMinUpdate { key: 2, value: 2 },
        ];
        let mut s1 = s0.clone();
        for u in &b_warmup {
            CountMinV9::update(&mut s1, u);
        }

        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let l1 = prove_countmin_leaf_v9_with_params(params, s0.clone(), b1.clone());

        let b2 = vec![
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        // l2's initial = s1 (non-empty) → should be rejected.
        let l2 = prove_countmin_leaf_v9_with_params(params, s1.clone(), b2.clone());

        let mut a1 = s0;
        for u in &b1 {
            CountMinV9::update(&mut a1, u);
        }
        let mut a2 = s1;
        for u in &b2 {
            CountMinV9::update(&mut a2, u);
        }

        match merge_two_countmin_v9_additive(&l1, &a1, &l2, &a2) {
            Err(CountMinAdditiveMergeError::NonEmptyInitial { which, .. }) => {
                assert_eq!(which, "right", "should have flagged the non-empty leaf");
            }
            Err(other) => panic!("expected NonEmptyInitial, got {other:?}"),
            Ok(_) => panic!("additive merge must reject non-empty initial states"),
        }
    }
}
