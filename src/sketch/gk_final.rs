//! Structural GK leaf (baseline): binds the commitments and checks active flags, padding
//! order and mass conservation, but not the insert or fusion steps.

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
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};

// ─── Constants ───────────────────────────────────────────────────────────

const LOG_FINAL_POLY_LEN: usize = 6;

/// Each tuple is `(value, count, max_error, active)` — 4 BabyBear Vals,
/// exactly one Challenge element after extension-field packing.
const TUPLE_FIELDS: usize = 4;

// ─── Types ───────────────────────────────────────────────────────────────

/// One entry in a GK summary. Padded entries have `active = 0` and are
/// zero in every other field; the in-circuit verifier ignores them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct GKFinalTuple {
    pub value: u32,
    pub count: u32,
    pub max_error: u32,
    /// 1 if this tuple holds real data; 0 if it's a padding dummy.
    pub active: u32,
}

impl GKFinalTuple {
    pub const fn dummy() -> Self {
        Self { value: 0, count: 0, max_error: 0, active: 0 }
    }

    pub const fn real(value: u32, count: u32, max_error: u32) -> Self {
        Self { value, count, max_error, active: 1 }
    }
}

/// One batch update. `active = 0` rows are padding (no effect on the
/// sketch); the verifier sees them indistinguishably from real updates.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct GKFinalUpdate {
    pub value: u32,
    pub active: u32,
}

impl GKFinalUpdate {
    pub const fn real(value: u32) -> Self {
        Self { value, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { value: 0, active: 0 }
    }
}

/// Public parameters fixing the leaf-circuit shape. Two leaves chain-merge
/// only when these match exactly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKFinalParams {
    /// Public state capacity. The committed state always holds exactly
    /// `capacity` tuples (active + dummy), regardless of how full the
    /// sketch actually is.
    pub capacity: usize,
    /// Public batch capacity. Each epoch consumes exactly `batch` records
    /// (active + dummy).
    pub batch: usize,
}

impl GKFinalParams {
    /// Total `Val` count for a packed state — must be a multiple of the
    /// rate of [`MyHash`] for clean sponge alignment. With `TUPLE_FIELDS = 4`
    /// and rate 8 Vals (= 2 Challenges) per absorb, `capacity` must be
    /// **even** so `4·capacity` is a multiple of 8.
    pub fn state_vals(&self) -> usize {
        self.capacity * TUPLE_FIELDS
    }

    /// Packed Challenge count for the state — one Challenge per tuple.
    pub fn state_packing(&self) -> usize {
        self.capacity
    }

    /// Packed Challenge count for the batch — same shape as state.
    pub fn batch_packing(&self) -> usize {
        self.batch
    }

    pub fn validate(&self) {
        assert!(self.capacity >= 2, "capacity must be ≥ 2, got {}", self.capacity);
        assert!(
            self.capacity % 2 == 0,
            "capacity must be even so 4·capacity is multiple of Poseidon2 rate (8); got {}",
            self.capacity
        );
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(
            self.batch % 2 == 0,
            "batch must be even for the same Poseidon2 alignment reason; got {}",
            self.batch
        );
    }
}

/// GK summary state. Length is always `params.capacity`; active prefix
/// holds real tuples sorted by value, the rest is `dummy()` padding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GKFinalState {
    pub tuples: Vec<GKFinalTuple>,
    pub params: GKFinalParams,
}

impl GKFinalState {
    /// Build a fresh empty state — all tuples are dummies.
    pub fn empty(params: GKFinalParams) -> Self {
        Self {
            tuples: vec![GKFinalTuple::dummy(); params.capacity],
            params,
        }
    }

    /// Number of real (active) tuples currently in the summary. **Private.**
    pub fn active_count(&self) -> usize {
        self.tuples.iter().filter(|t| t.active == 1).count()
    }

    /// Total mass — sum of `count` over active tuples. **Private.**
    pub fn total_mass(&self) -> u64 {
        self.tuples
            .iter()
            .filter(|t| t.active == 1)
            .map(|t| t.count as u64)
            .sum()
    }

    /// Approximate rank: number of items with `value ≤ q`. Same shape as
    /// the plaintext GK rank query — useful for sanity-checking proofs.
    pub fn rank(&self, q: u32) -> u64 {
        self.tuples
            .iter()
            .filter(|t| t.active == 1 && t.value <= q)
            .map(|t| t.count as u64)
            .sum()
    }
}

/// Poseidon2 commitment to a `GKFinalState`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKFinalStateCommit(pub [Val; 8]);

/// Poseidon2 commitment to a batch slice.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKFinalBatchCommit(pub [Val; 8]);

/// A successful leaf proof — same shape as `CountMinLeafProofV9`.
pub struct GKFinalLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: GKFinalStateCommit,
    pub final_: GKFinalStateCommit,
    pub batch_commit: GKFinalBatchCommit,
    pub params: GKFinalParams,
}

/// User-facing proof bundle. Mirrors `CountMinFinalProof`.
pub struct GKFinalProof {
    pub proof: GKFinalLeafProof,
    pub final_state: GKFinalState,
}

impl GKFinalProof {
    /// Approximate rank query against the certified final state.
    pub fn rank(&self, q: u32) -> u64 {
        self.final_state.rank(q)
    }
}

// ─── Native helpers ──────────────────────────────────────────────────────

/// Pack a state's tuples into 4 Val coefficients per Challenge (so the
/// in-circuit `decompose_ext_to_base_coeffs` reproduces the same layout).
fn pack_state_to_challenge(state: &GKFinalState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    state
        .tuples
        .iter()
        .map(|t| {
            let coeffs = [
                Val::from_u32(t.value),
                Val::from_u32(t.count),
                Val::from_u32(t.max_error),
                Val::from_u32(t.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

/// Pack a batch slice — same shape (4 Vals per record).
fn pack_batch_to_challenge(batch: &[GKFinalUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    batch
        .iter()
        .map(|u| {
            let coeffs = [
                Val::from_u32(u.value),
                Val::ZERO,
                Val::ZERO,
                Val::from_u32(u.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

/// Native flattened-Val view of a state, used to compute the Poseidon2
/// commitment.
fn flat_state_vals(state: &GKFinalState) -> Vec<Val> {
    state
        .tuples
        .iter()
        .flat_map(|t| {
            [
                Val::from_u32(t.value),
                Val::from_u32(t.count),
                Val::from_u32(t.max_error),
                Val::from_u32(t.active),
            ]
        })
        .collect()
}

fn flat_batch_vals(batch: &[GKFinalUpdate]) -> Vec<Val> {
    batch
        .iter()
        .flat_map(|u| {
            [
                Val::from_u32(u.value),
                Val::ZERO,
                Val::ZERO,
                Val::from_u32(u.active),
            ]
        })
        .collect()
}

/// Poseidon2 commitment to a GK state.
pub fn commit_gk_state(state: &GKFinalState) -> GKFinalStateCommit {
    let hasher = MyHash::new(make_perm());
    let flat = flat_state_vals(state);
    let digest: [Val; 8] = hasher.hash_iter(flat);
    GKFinalStateCommit(digest)
}

/// Poseidon2 commitment to a batch slice.
pub fn commit_gk_batch(batch: &[GKFinalUpdate]) -> GKFinalBatchCommit {
    let hasher = MyHash::new(make_perm());
    let flat = flat_batch_vals(batch);
    let digest: [Val; 8] = hasher.hash_iter(flat);
    GKFinalBatchCommit(digest)
}

/// Apply one record to a GK state — the bounded-GK update rule.
///
/// 1. If `u.active == 0`: no-op (the record is padding).
/// 2. Find sorted insertion point by value.
/// 3. If room (active count < capacity): shift right and insert
///    `(value, 1, 0, 1)`.
/// 4. Else (state is full): merge the adjacent pair with smallest
///    `count + max_error` sum, then insert into the freed slot.
pub fn apply_update(state: &mut GKFinalState, u: &GKFinalUpdate) {
    if u.active == 0 {
        return;
    }
    let cap = state.params.capacity;
    let active_len = state.tuples.iter().take_while(|t| t.active == 1).count();
    let pos = state.tuples[..active_len]
        .iter()
        .position(|t| t.value >= u.value)
        .unwrap_or(active_len);

    if active_len < cap {
        // Shift [pos..active_len] right by 1, insert at pos.
        for i in (pos..active_len).rev() {
            state.tuples[i + 1] = state.tuples[i];
        }
        state.tuples[pos] = GKFinalTuple::real(u.value, 1, 0);
        return;
    }

    // Full — find the adjacent pair with smallest combined cost.
    let mut min_sum = u64::MAX;
    let mut min_idx = 0usize;
    for i in 0..cap - 1 {
        let s = state.tuples[i].count as u64
            + state.tuples[i].max_error as u64
            + state.tuples[i + 1].count as u64
            + state.tuples[i + 1].max_error as u64;
        if s < min_sum {
            min_sum = s;
            min_idx = i;
        }
    }
    // Merge tuples[min_idx] and tuples[min_idx + 1] into tuples[min_idx + 1].
    let merged = GKFinalTuple::real(
        state.tuples[min_idx + 1].value,
        state.tuples[min_idx]
            .count
            .saturating_add(state.tuples[min_idx + 1].count),
        state.tuples[min_idx]
            .max_error
            .saturating_add(state.tuples[min_idx].count)
            .max(state.tuples[min_idx + 1].max_error),
    );
    state.tuples[min_idx + 1] = merged;
    // Shift [min_idx + 1..] left to fill the gap.
    for i in min_idx..cap - 1 {
        state.tuples[i] = state.tuples[i + 1];
    }
    state.tuples[cap - 1] = GKFinalTuple::dummy();

    // Now insert (value, 1, 0) at the proper sorted position.
    let active_len_after = cap - 1;
    let pos = state.tuples[..active_len_after]
        .iter()
        .position(|t| t.value >= u.value)
        .unwrap_or(active_len_after);
    for i in (pos..active_len_after).rev() {
        state.tuples[i + 1] = state.tuples[i];
    }
    state.tuples[pos] = GKFinalTuple::real(u.value, 1, 0);
}

// ─── Prover ──────────────────────────────────────────────────────────────

/// Prove one GK update epoch under the simplified §5.4 design.
///
/// **What's certified** (the insert and fusion steps are not):
///
/// - `initial_state` opens to `proof.initial` (Poseidon2 binding).
/// - `final_state` opens to `proof.final_` (Poseidon2 binding).
/// - `batch` opens to `proof.batch_commit` (Poseidon2 binding).
/// - Every `active` flag is in `{0, 1}`.
/// - Active flags in `final_state` are weakly monotone decreasing
///   (actives first, padding last).
/// - Total active count is preserved:
///   `sum(final.count·final.active) = sum(initial.count·initial.active) +
///   sum(batch.active)`.
///
/// **Not yet certified** (TODO, paper §5.4 Steps 2–5): per-value sortedness
/// of the active prefix and the L-round adjacent-fusion relation.
///
/// # Panics
///
/// - `params.validate()` failures.
/// - `initial_state.params != params`.
/// - `batch.len() != params.batch`.
pub fn prove_gk_final(
    params: GKFinalParams,
    initial_state: GKFinalState,
    batch: Vec<GKFinalUpdate>,
) -> GKFinalLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);

    let cap = params.capacity;
    let m = params.batch;
    let state_packing = params.state_packing();
    let batch_packing = params.batch_packing();

    // ─── Native side: state evolution + commits ─────────────────────────
    let mut final_state = initial_state.clone();
    for u in &batch {
        apply_update(&mut final_state, u);
    }
    let initial_commit = commit_gk_state(&initial_state);
    let final_commit = commit_gk_state(&final_state);
    let batch_commit = commit_gk_batch(&batch);

    // Sanity (native): mass preservation must hold.
    let init_mass = initial_state.total_mass();
    let batch_mass: u64 = batch.iter().map(|u| u.active as u64).sum();
    let final_mass = final_state.total_mass();
    assert_eq!(
        final_mass,
        init_mass + batch_mass,
        "native: GK mass preservation violated — bug in apply_update?"
    );

    // ─── Build the circuit ──────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // Public inputs: (initial_commit, final_commit, batch_commit) — same
    // shape as count-min.
    let init_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");

    // Private inputs: packed state tuples + batch records.
    let init_packed: Vec<ExprId> = (0..state_packing)
        .map(|_| b.alloc_private_input("init_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..state_packing)
        .map(|_| b.alloc_private_input("final_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..batch_packing)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();

    // ─── Stage 1: Poseidon2 bind each packed sequence to its commit ─────
    let h_init = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &init_packed, true)
        .expect("hash init state");
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("hash final state");
    for i in 0..DIGEST_PACKING {
        b.connect(h_final[i], final_pis[i]);
    }
    let h_batch = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(h_batch[i], batch_pis[i]);
    }

    // ─── Stage 2: Decompose packed sequences into per-field ExprIds ─────
    // Each Challenge packs (value, count, max_error, active) into 4
    // base coefficients.
    let init_fields: Vec<Vec<ExprId>> = init_packed
        .iter()
        .map(|&p| {
            b.decompose_ext_to_base_coeffs::<Val>(p)
                .expect("decompose init")
        })
        .collect();
    let final_fields: Vec<Vec<ExprId>> = final_packed
        .iter()
        .map(|&p| {
            b.decompose_ext_to_base_coeffs::<Val>(p)
                .expect("decompose final")
        })
        .collect();
    let batch_fields: Vec<Vec<ExprId>> = batch_packed
        .iter()
        .map(|&p| {
            b.decompose_ext_to_base_coeffs::<Val>(p)
                .expect("decompose batch")
        })
        .collect();

    // ─── Stage 3: Boolean constraint on every active flag ───────────────
    // active ∈ {0, 1}: active · (active − 1) = 0.
    for r in 0..cap {
        let a = init_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);

        let a = final_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    }
    for r in 0..m {
        // Batch row: only `active` (field 3) and `value` (field 0) are
        // meaningful — fields 1, 2 are zero (enforced by the structure of
        // pack_batch_to_challenge, but the circuit doesn't need to check
        // since they don't affect the verification target).
        let a = batch_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    }

    // ─── Stage 4: Active flag monotonicity in `final_state` ─────────────
    // active[r+1] ≤ active[r] — once we hit padding, no more actives.
    // Equivalent: active[r] · (1 − active[r+1]) ≥ 0 (automatic since
    // both are in {0,1}). Stronger form via "delta is 0 or 1":
    //   active[r] − active[r+1] ∈ {0, 1}, i.e., (active[r] − active[r+1]) ·
    //   (1 − (active[r] − active[r+1])) = 0.
    for r in 0..cap - 1 {
        let curr = final_fields[r][3];
        let next = final_fields[r + 1][3];
        let diff = b.sub(curr, next);
        let one_minus_diff = b.sub(one, diff);
        let prod = b.mul(diff, one_minus_diff);
        b.connect(prod, zero);
    }

    // ─── Stage 5: Mass preservation ─────────────────────────────────────
    // sum_r (final.count[r] · final.active[r]) =
    //   sum_r (init.count[r] · init.active[r]) + sum_r batch.active[r]
    //
    // (Active flag gates the count contribution to zero on padding rows.)
    let mut init_mass_expr = b.mul(init_fields[0][1], init_fields[0][3]);
    for r in 1..cap {
        let term = b.mul(init_fields[r][1], init_fields[r][3]);
        init_mass_expr = b.add(init_mass_expr, term);
    }
    let mut final_mass_expr = b.mul(final_fields[0][1], final_fields[0][3]);
    for r in 1..cap {
        let term = b.mul(final_fields[r][1], final_fields[r][3]);
        final_mass_expr = b.add(final_mass_expr, term);
    }
    let mut batch_active_sum = batch_fields[0][3];
    for r in 1..m {
        batch_active_sum = b.add(batch_active_sum, batch_fields[r][3]);
    }
    let init_plus_batch = b.add(init_mass_expr, batch_active_sum);
    b.connect(final_mass_expr, init_plus_batch);

    let circuit = b.build().expect("build gk_final circuit");

    // ─── Pack public + private values ───────────────────────────────────
    let initial_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(initial_commit.0),
    );
    let final_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(final_commit.0),
    );
    let batch_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(batch_commit.0),
    );

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&initial_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    public_inputs.extend_from_slice(&batch_commit_packed);

    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&pack_state_to_challenge(&initial_state));
    private_inputs.extend_from_slice(&pack_state_to_challenge(&final_state));
    private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));

    // ─── Run + prove ────────────────────────────────────────────────────
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run gk_final circuit")
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
        .expect("get_airs_and_degrees_with_prep (gk_final)");
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
        .expect("prove_all_tables (gk_final)");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify gk_final leaf");

    GKFinalLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
}

/// Convenience entry point: generate a real STARK proof for a batch of
/// GK updates starting from an empty sketch. Mirrors
/// `countmin_final::generate_proof`.
///
/// The proof is **already self-verified** before being returned.
pub fn generate_proof(
    params: GKFinalParams,
    updates: Vec<GKFinalUpdate>,
) -> GKFinalProof {
    params.validate();
    assert_eq!(
        updates.len(),
        params.batch,
        "updates length ({}) must equal params.batch ({})",
        updates.len(),
        params.batch
    );

    let initial_state = GKFinalState::empty(params);
    let mut final_state = initial_state.clone();
    for u in &updates {
        apply_update(&mut final_state, u);
    }

    let proof = prove_gk_final(params, initial_state, updates);

    GKFinalProof { proof, final_state }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a batch with `active_count` real records followed by
    /// padding dummies, deterministic in `(params, active_count)`.
    fn gen_padded_batch(params: GKFinalParams, active_count: usize) -> Vec<GKFinalUpdate> {
        assert!(active_count <= params.batch);
        let salt = (params.capacity * params.batch) as u32;
        (0..params.batch)
            .map(|i| {
                if i < active_count {
                    GKFinalUpdate::real(
                        ((i as u32).wrapping_mul(0x9E37_79B9) ^ salt) & 0x000F_FFFF,
                    )
                } else {
                    GKFinalUpdate::dummy()
                }
            })
            .collect()
    }

    /// Resolve thread count via `V3_SWEEP_THREADS` (consistent with the
    /// count-min sweep tests).
    fn resolve_threads() -> (Option<usize>, String) {
        let n: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse().ok());
        let label = match n {
            Some(k) => format!("V3_SWEEP_THREADS={k}"),
            None => format!(
                "Rayon default pool ({} threads)",
                rayon::current_num_threads()
            ),
        };
        (n, label)
    }

    fn with_pool<F: FnOnce() -> T + Send, T: Send>(n: Option<usize>, f: F) -> T {
        match n {
            None => f(),
            Some(k) => {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(k)
                    .thread_name(|i| format!("gk-final-bench-{i}"))
                    .build()
                    .expect("build rayon thread pool");
                pool.install(f)
            }
        }
    }

    /// Quick correctness check: at small params, generate a proof, verify
    /// the final state's commit matches, run a rank query. ~ms-scale test.
    #[test]
    fn gk_generate_proof_round_trip() {
        let params = GKFinalParams { capacity: 4, batch: 2 };
        let updates = vec![GKFinalUpdate::real(7), GKFinalUpdate::real(11)];

        let result = generate_proof(params, updates);

        assert_eq!(commit_gk_state(&result.final_state).0, result.proof.final_.0);
        // Two active inserts, no eviction → total mass = 2.
        assert_eq!(result.final_state.total_mass(), 2);
        // Both values present in the rank query.
        assert!(result.rank(11) >= 2);
        assert!(result.rank(6) <= 1);
    }

    /// **Test 1 — proving time vs. active-count density.**
    ///
    /// Holds `(capacity, batch) = (32, 100)` fixed and sweeps the number
    /// of *active* records in the batch — the rest are dummies. The
    /// circuit shape is constant across grid points, so prove time
    /// should be nearly flat; this measures whether padding adds
    /// observable cost beyond proof correctness.
    ///
    /// Run:
    ///
    /// ```bash
    /// V3_SWEEP_THREADS=8 cargo test --release --lib gk_proving_time_with_different_active_counts -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn gk_proving_time_with_different_active_counts() {
        use std::time::Instant;

        let (threads, threads_label) = resolve_threads();
        let params = GKFinalParams { capacity: 32, batch: 100 };

        println!();
        println!("gk_final — proving time vs. active-count density");
        println!("==================================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={} (public)", params.capacity, params.batch);
        println!();

        for &active in &[100usize, 50, 30, 10, 5, 1] {
            let updates = gen_padded_batch(params, active);
            let elapsed = with_pool(threads, move || {
                let t = Instant::now();
                let _ = generate_proof(params, updates);
                t.elapsed()
            });
            println!(
                "  active={:>3} (of {:>3})   prove {:>10.2?}",
                active, params.batch, elapsed
            );
        }
    }

    /// **Test 2 — proving time to merge two leaves.**
    ///
    /// Two consecutive GK leaves at `(capacity=32, batch=100)`. Times
    /// per-leaf prove plus the §4.2 recursive merge step.
    ///
    /// Note: the merge step uses `merge_two_countmin_v9` from the
    /// count-min path. Both leaves carry `CountMinLeafProofV9`-compatible
    /// proof outputs (same `RecursionOutput<ConfigWithFriParams>`), but
    /// they target different verifier circuits (gk_final vs count-min),
    /// so the chain proof here is structural — not yet a soundly
    /// composable GK chain. A dedicated `merge_two_gk_final` is a
    /// follow-up.
    #[test]
    #[ignore]
    fn gk_proving_time_merge_two_leaves() {
        use std::time::Instant;

        let (threads, threads_label) = resolve_threads();
        let params = GKFinalParams { capacity: 32, batch: 100 };

        println!();
        println!("gk_final — merge proving-time check");
        println!("=====================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}", params.capacity, params.batch);
        println!();

        let (l1_time, l2_time) = with_pool(threads, move || {
            let s0 = GKFinalState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_gk_final(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();

            // Apply b1 natively → s1.
            let mut s1 = s0;
            for u in &b1 {
                apply_update(&mut s1, u);
            }
            assert_eq!(commit_gk_state(&s1).0, l1.final_.0, "s1 commit mismatch");

            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let _l2 = prove_gk_final(params, s1, b2);
            let l2_time = t2.elapsed();
            (l1_time, l2_time)
        });

        println!("  leaf 1 prove:       {l1_time:>10.2?}");
        println!("  leaf 2 prove:       {l2_time:>10.2?}");
        println!("  ────────────────────────────────");
        println!("  total wall-clock:   {:>10.2?}", l1_time + l2_time);
        println!();
        println!("  (Sequential merge via recursive aggregation is");
        println!("   not yet wired for gk_final — see test docstring.)");
    }

    /// **Test 3 — generate two proofs and persist them to `src/proofs/`.**
    ///
    /// Mirrors `countmin_final::generate_and_store_proof`. Two GK leaves
    /// at `(capacity=32, batch=100)` with 60 / 40 active records; each
    /// proof's STARK bytes written to disk via `postcard`, with a
    /// sidecar `.meta.txt` carrying params + public commitments.
    #[test]
    #[ignore]
    fn gk_generate_and_store_proof() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::Instant;

        let (threads, threads_label) = resolve_threads();
        let params = GKFinalParams { capacity: 32, batch: 100 };

        let crate_root = env!("CARGO_MANIFEST_DIR");
        let out_dir = PathBuf::from(crate_root).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("create src/proofs directory");

        println!();
        println!("gk_final — generate two proofs + store to disk");
        println!("================================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}", params.capacity, params.batch);
        println!();

        with_pool(threads, move || {
            let s0 = GKFinalState::empty(params);

            // Leaf 1: 60 active records.
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_gk_final(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();
            let proof1_bytes = postcard::to_allocvec(&l1.output.0)
                .expect("postcard serialize proof1");
            let proof1_path = out_dir.join("gk_proof1.bin");
            fs::write(&proof1_path, &proof1_bytes).expect("write proof1");
            write_gk_meta(
                &out_dir.join("gk_proof1.meta.txt"),
                "gk_proof1.bin",
                &params,
                &l1,
                proof1_bytes.len(),
            );

            // Apply b1 to get s1, then leaf 2 with 40 active records.
            let mut s1 = s0;
            for u in &b1 {
                apply_update(&mut s1, u);
            }
            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let l2 = prove_gk_final(params, s1, b2);
            let l2_time = t2.elapsed();
            let proof2_bytes = postcard::to_allocvec(&l2.output.0)
                .expect("postcard serialize proof2");
            let proof2_path = out_dir.join("gk_proof2.bin");
            fs::write(&proof2_path, &proof2_bytes).expect("write proof2");
            write_gk_meta(
                &out_dir.join("gk_proof2.meta.txt"),
                "gk_proof2.bin",
                &params,
                &l2,
                proof2_bytes.len(),
            );

            println!("  leaf 1 prove time:  {l1_time:>10.2?}");
            println!("  proof 1 size:       {:>10} bytes", proof1_bytes.len());
            println!("  leaf 2 prove time:  {l2_time:>10.2?}");
            println!("  proof 2 size:       {:>10} bytes", proof2_bytes.len());
            println!();
            println!("  proofs persisted to: {}", out_dir.display());
        });
    }

    fn write_gk_meta(
        path: &std::path::Path,
        bin_filename: &str,
        params: &GKFinalParams,
        leaf: &GKFinalLeafProof,
        proof_bytes: usize,
    ) {
        use std::fs;
        let mut meta = String::new();
        meta.push_str("# GK final-design proof — sidecar metadata\n");
        meta.push_str(&format!("# Paired with `{bin_filename}`.\n"));
        meta.push('\n');
        meta.push_str(&format!("params.capacity = {}\n", params.capacity));
        meta.push_str(&format!("params.batch    = {}\n", params.batch));
        meta.push('\n');
        meta.push_str(&format!("initial_commit  = {:?}\n", leaf.initial.0));
        meta.push_str(&format!("final_commit    = {:?}\n", leaf.final_.0));
        meta.push_str(&format!("batch_commit    = {:?}\n", leaf.batch_commit.0));
        meta.push('\n');
        meta.push_str(&format!("proof_size_bytes = {proof_bytes}\n"));
        fs::write(path, &meta).expect("write meta file");
    }
}
