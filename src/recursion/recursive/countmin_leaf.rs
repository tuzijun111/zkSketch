//! CircuitBuilder-based Count-Min update leaf for the §4.2 recursive merge.
//!
//! The circuit verifies one epoch of the Count-Min sketch (paper §5.4
//! Pattern A linear), staged here as the §5.1 *strawman*: per-cell additive
//! deltas, with the in-circuit Poseidon2 hash binding the per-epoch state
//! commitments. Parameters `(d, w, batch)` are runtime-supplied so the
//! sweep demo can scan a workload grid without recompilation.
//!
//! The flattened cell count `d * w` must be a multiple of the Challenge
//! extension degree (4), so the off-circuit `commit_countmin` and the
//! in-circuit `add_hash_slice` produce identical 8-element base-field
//! digests. See the alignment comment in `src/commitment/countmin.rs`.
//!
//! ### Public inputs (Challenge field elements)
//!
//! In allocation order:
//! 1. `initial_commit[0..2]` — `[Val; 8]` digest packed into 2 Challenge PIs.
//! 2. `final_commit[0..2]`   — same shape for the post-update state.
//! 3. For each record `k`: `(key_k, value_k, pos_k[0..d])`, each as one PI
//!    embedded into Challenge. `pos_k[r]` is the public hash position
//!    `hash_cell(r, key_k, w)`; the off-circuit caller computes it and the
//!    leaf verifier (or downstream merge verifier) checks the pos PIs
//!    against a native recomputation.
//!
//! ### Private inputs
//!
//! - Packed initial cells (`d*w/4` Challenge entries) decomposed in-circuit
//!   into individual base-embedded cell values for the per-cell transitions.
//! - Packed final cells (same shape).
//! - Per record `(k, r)`: `selectors[k][r][0..w]` — `w` base-embedded
//!   indicators forming a one-hot vector pointing at column `pos_k[r]`.
//!
//! ### Constraints
//!
//! 1. `hash(initial_packed) == initial_commit` (in-circuit Poseidon2).
//! 2. `hash(final_packed)   == final_commit`.
//! 3. For each `(k, r)`: `sum(selectors[k][r]) == 1` and
//!    `sum_j(selectors[k][r][j] * j) == pos_k[r]`.
//! 4. State transition for every cell `(i, j)`:
//!        `final[i*w + j] = initial[i*w + j] + sum_k(selectors[k][i][j] * value_k)`.

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
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::commitment::countmin::commit_countmin;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::{ConfigWithFriParams, make_recursion_config};
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMin, CountMinState, CountMinUpdate, hash_cell};

// ─── Demo defaults ───────────────────────────────────────────────────────

/// Default Count-Min depth used by the Phase 2 / 3a / 3b demos and tests.
pub const D: usize = 2;
/// Default Count-Min width.
pub const W: usize = 4;
/// Default records per epoch.
pub const BATCH: usize = 2;

/// Required alignment of the flattened cell count to the Challenge
/// extension degree, so `add_hash_slice` and `MyHash::hash_iter` agree.
pub const CELL_ALIGNMENT: usize = 4;
/// Number of Challenge digest outputs from `add_hash_slice` for any Count-Min
/// state (digest is always 8 base elements = 2 Challenge elements).
pub const DIGEST_PACKING: usize = 2;

/// FRI parameters used for the leaf — kept equal to the recursive merge
/// layer's parameters so the two share a verifier-circuit shape.
const LOG_FINAL_POLY_LEN: usize = 6;

// ─── Runtime parameters ──────────────────────────────────────────────────

/// Per-leaf runtime parameters. `d * w` must be a multiple of `CELL_ALIGNMENT`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CountMinLeafParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CountMinLeafParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    pub fn cell_packing(&self) -> usize {
        self.num_cells() / CELL_ALIGNMENT
    }
    /// Panics if the parameters are out of range or misaligned for the
    /// in-circuit hash.
    pub fn validate(&self) {
        assert!(self.d >= 1 && self.w >= 1 && self.batch >= 1, "params must be positive");
        let n = self.num_cells();
        assert!(
            n % CELL_ALIGNMENT == 0,
            "d*w = {n} is not a multiple of {CELL_ALIGNMENT}; in-circuit hash absorption requires alignment"
        );
    }
}

impl Default for CountMinLeafParams {
    fn default() -> Self {
        Self { d: D, w: W, batch: BATCH }
    }
}

// ─── Leaf proof type ─────────────────────────────────────────────────────

/// A successfully-proven Count-Min update epoch.
pub struct CountMinLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: CountMinCommit,
    pub final_: CountMinCommit,
    /// Batch consumed by this epoch. Length equals `params.batch`.
    pub batch: Vec<CountMinUpdate>,
    pub params: CountMinLeafParams,
}

impl CountMinLeafProof {
    /// Reconstruct the public-values vector this proof was bound to, in
    /// allocation order. Useful for sanity-checking the leaf in isolation.
    pub fn public_values(&self) -> Vec<Challenge> {
        let mut pis = Vec::new();
        pis.extend(pack_commit_to_challenge(&self.initial));
        pis.extend(pack_commit_to_challenge(&self.final_));
        for u in &self.batch {
            pis.push(Challenge::from_u64(u.key));
            pis.push(Challenge::from_u32(u.value));
            for r in 0..self.params.d {
                pis.push(Challenge::from_u64(hash_cell(r, u.key, self.params.w) as u64));
            }
        }
        pis
    }
}

// ─── Packing helpers ─────────────────────────────────────────────────────

/// Pack a `CountMinCommit` (`[Val; 8]`) into 2 Challenge elements, the
/// shape the in-circuit hash returns and the format the leaf PIs use.
pub fn pack_commit_to_challenge(c: &CountMinCommit) -> [Challenge; DIGEST_PACKING] {
    [
        Challenge::from_basis_coefficients_slice(&c.0[0..4]).expect("4 base coeffs"),
        Challenge::from_basis_coefficients_slice(&c.0[4..8]).expect("4 base coeffs"),
    ]
}

/// Pack the flattened counters of a Count-Min state into `d*w/4` Challenge
/// elements, matching the layout the in-circuit `add_hash_slice` absorbs.
fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    assert_eq!(flat.len(), state.params.d * state.params.w);
    flat.chunks(CELL_ALIGNMENT)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

// ─── Recursion config (shared with merge / chain / flat) ─────────────────

/// Reconstruct the recursion-friendly config used by both the leaf prove
/// and the §4.2 aggregation step.
pub fn make_leaf_config() -> ConfigWithFriParams {
    let leaf_cfg = crate::config::make_config(LOG_FINAL_POLY_LEN);
    make_recursion_config(
        leaf_cfg,
        LOG_BLOWUP,
        LOG_FINAL_POLY_LEN,
        crate::config::COMMIT_POW_BITS,
        crate::config::QUERY_POW_BITS,
    )
}

// ─── Leaf prover ─────────────────────────────────────────────────────────

/// Compile-time-defaults wrapper. Convenient for the original
/// `(D, W, BATCH) = (2, 4, 2)` demo path; for the workload sweep use
/// `prove_countmin_leaf_with_params`.
pub fn prove_countmin_leaf(
    initial_state: CountMinState,
    batch: [CountMinUpdate; BATCH],
) -> CountMinLeafProof {
    prove_countmin_leaf_with_params(
        CountMinLeafParams { d: D, w: W, batch: BATCH },
        initial_state,
        batch.to_vec(),
    )
}

/// Runtime-parameterised version. `params.d * params.w` must be a multiple
/// of 4; `batch.len() == params.batch`; and `initial_state.params.{d, w}`
/// must match `params.{d, w}`.
pub fn prove_countmin_leaf_with_params(
    params: CountMinLeafParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinLeafProof {
    params.validate();
    assert_eq!(initial_state.params.d, params.d, "state.d / params.d mismatch");
    assert_eq!(initial_state.params.w, params.w, "state.w / params.w mismatch");
    assert_eq!(batch.len(), params.batch, "batch length / params.batch mismatch");

    let CountMinLeafParams { d, w, batch: m } = params;
    let num_cells = params.num_cells();
    let cell_packing = params.cell_packing();

    // Compute the final state and per-record positions natively. Both end
    // up in the proof as public commitments / positions.
    let mut final_state = initial_state.clone();
    for u in &batch {
        CountMin::update(&mut final_state, u);
    }
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&final_state);

    // Build the circuit.
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // ---- Public inputs ----
    let initial_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    // Per-record PIs: (key, value, pos[0..d]).
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

    // Selectors: m × d × w one-hot indicators (base-embedded in Challenge).
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

    // 1. Hash the packed initial cells, connect to initial_commit PIs.
    let digest_init = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &initial_packed, true)
        .expect("add_hash_slice(initial)");
    assert_eq!(digest_init.len(), DIGEST_PACKING);
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], initial_commit_pis[i]);
    }

    // 2. Hash the packed final cells, connect to final_commit PIs.
    let digest_final = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("add_hash_slice(final)");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
    }

    // Decompose packed cell inputs into individual base-embedded ExprIds
    // for the per-cell transition constraints.
    let initial_cells: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| {
            b.decompose_ext_to_base_coeffs::<Val>(p)
                .expect("decompose initial_packed")
        })
        .collect();
    let final_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| {
            b.decompose_ext_to_base_coeffs::<Val>(p)
                .expect("decompose final_packed")
        })
        .collect();
    assert_eq!(initial_cells.len(), num_cells);
    assert_eq!(final_cells.len(), num_cells);

    let one = b.alloc_const(Challenge::ONE, "one");
    let j_consts: Vec<ExprId> = (0..w)
        .map(|j| b.alloc_const(Challenge::from_u64(j as u64), "j"))
        .collect();

    // 3. Selector validity.
    for k in 0..m {
        for r in 0..d {
            let s = &selectors[k][r];

            // sum(s) == 1
            let mut sum = s[0];
            for j in 1..w {
                sum = b.add(sum, s[j]);
            }
            b.connect(sum, one);

            // sum_j(s[j] * j) == pos[k][r]
            let zero = b.alloc_const(Challenge::ZERO, "zero");
            let mut weighted = zero;
            for j in 0..w {
                let term = b.mul(s[j], j_consts[j]);
                weighted = b.add(weighted, term);
            }
            b.connect(weighted, record_pis[k].2[r]);
        }
    }

    // 4. State transition: for each cell (i, j),
    //    final[i*w + j] = initial[i*w + j] + sum_k(s[k][i][j] * value_k).
    for i in 0..d {
        for j in 0..w {
            let idx = i * w + j;
            let mut accum = initial_cells[idx];
            for k in 0..m {
                let term = b.mul(selectors[k][i][j], record_pis[k].1);
                accum = b.add(accum, term);
            }
            b.connect(accum, final_cells[idx]);
        }
    }

    let circuit = b.build().expect("build leaf circuit");

    // ---- Pack public + private values and run the circuit ----
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
    for k in 0..m {
        for r in 0..d {
            let pos = hash_cell(r, batch[k].key, w);
            for j in 0..w {
                let v = if j == pos { Challenge::ONE } else { Challenge::ZERO };
                private_inputs.push(v);
            }
        }
    }

    let traces = {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .expect("set_public_inputs");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set_private_inputs");
        runner.run().expect("run circuit")
    };

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);

    // The leaf circuit uses Poseidon2 (`add_hash_slice`) and recompose
    // (`decompose_ext_to_base_coeffs`), so the prover needs their
    // preprocessors and AIR builders to enumerate every table.
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
        .expect("get_airs_and_degrees_with_prep");
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
        .expect("prove_all_tables");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify count-min leaf");

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
    use crate::sketch::countmin::CountMinParams;

    fn empty_state() -> CountMinState {
        CountMin::new(&CountMinParams { d: D, w: W })
    }

    #[test]
    fn countmin_leaf_round_trip() {
        let initial = empty_state();
        let batch = [
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let leaf = prove_countmin_leaf(initial.clone(), batch);

        let mut expected = initial;
        for u in &batch {
            CountMin::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
        assert_eq!(leaf.params, CountMinLeafParams::default());
        assert_eq!(leaf.batch.len(), BATCH);
    }

    /// Same shape but at a larger workload — exercises the runtime-param
    /// path on `(d, w, batch) = (4, 4, 4)` (16 cells = 4 × 4 = aligned).
    #[test]
    fn countmin_leaf_round_trip_at_4_4_4() {
        let params = CountMinLeafParams { d: 4, w: 4, batch: 4 };
        params.validate();
        let initial = CountMin::new(&CountMinParams { d: params.d, w: params.w });
        let batch: Vec<CountMinUpdate> = (0..params.batch)
            .map(|i| CountMinUpdate { key: (i as u64) * 11 + 1, value: (i as u32) + 1 })
            .collect();
        let leaf = prove_countmin_leaf_with_params(params, initial.clone(), batch.clone());

        let mut expected = initial;
        for u in &batch {
            CountMin::update(&mut expected, u);
        }
        let expected_commit = commit_countmin(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
        assert_eq!(leaf.params, params);
        assert_eq!(leaf.batch.len(), params.batch);
    }

    /// Alignment assertion fires when `d * w % 4 != 0`.
    #[test]
    #[should_panic(expected = "not a multiple of 4")]
    fn misaligned_params_rejected() {
        // d=3, w=2 ⇒ 6 cells, not a multiple of 4.
        CountMinLeafParams { d: 3, w: 2, batch: 2 }.validate();
    }
}
