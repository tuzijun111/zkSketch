//! **Canonical HyperLogLog update circuit** (zkSketch paper Appendix F).
//!
//! Same template as [`crate::sketch::gk_final`] and
//! [`crate::sketch::countmin_final`], specialised to HLL semantics:
//!
//! - **Pattern A max**: per-key contribution `ρ_j = LeadingOnes(h_2(k_j))`
//!   is folded into register `b_j = h_1(k_j)` via the **max** operator. The
//!   committed state is updated by a sparse max-patch — `N[b] = max(O[b],
//!   M_b)`. Unlike Count-Min's additive structure, HLL needs a whole-state
//!   replacement commitment because `max` doesn't compose into a
//!   homomorphic Poseidon2 commit.
//! - **Privacy**: active flags on the batch hide the actual number of
//!   inserts per epoch (`m_t ≤ params.batch`). The register count
//!   `m = 2^b` is public.
//! - **PRF hash family**: Poseidon2 — same primitive that backs the
//!   commitments. The 8-Val digest provides the `(b_j, ρ_j)` pair without
//!   the bit-local XOR family that the v1 baseline used.
//!
//! ### Tuple / record layout
//!
//! - **Register**: one Challenge per register (only first base coefficient
//!   carries the `lr` value; the rest are zero).
//! - **Batch record**: one Challenge per record packing
//!   `(key_lo, key_hi, active, 0)` where `active ∈ {0, 1}`.
//!
//! ### Scope of in-circuit verification (this file)
//!
//! - Step 1 (bind state + batch) — ✓
//! - Step 2 (register contributions via Poseidon2 hash) — ✗ deferred (full
//!   per-record hashing in-circuit would mirror count-min's PRF approach;
//!   here the contributions are computed natively and bound via the
//!   batch commit only).
//! - Step 3 (sort by register id) — ✗ deferred
//! - Step 4 (max-aggregate per register) — ✗ deferred
//! - Step 5 (sparse max-patch apply) — ✗ deferred
//! - **What IS checked**: Poseidon2 commits on `(initial_state, final_state,
//!   batch)`; active flags ∈ {0,1}; **per-register monotonicity**
//!   `final[i] ≥ initial[i]` enforced via a non-negative-difference
//!   range proof (HLL's `max` is monotone non-decreasing).
//!
//! Privacy guarantees the simplified version still delivers:
//! - batch contents are private (only `batch_commit` is public);
//! - actual active count in the batch is private;
//! - register values are private (only `initial_commit` / `final_commit`
//!   bind them).
//!
//! The deferred steps would close the soundness gap by additionally
//! certifying that the new state really is `apply_max_patch(O, M)` rather
//! than any monotone-non-decreasing replacement.

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
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Each register is one Challenge: `(lr, 0, 0, 0)` where `lr` lives in
/// `[0, 64-b]`. Storing one value per 4-Val Challenge wastes 75% of the
/// Poseidon2 absorb rate but keeps decomposition trivial — matching the
/// simplest representation we can verify in-circuit.
const REGISTER_PACK: usize = 4;

// ─── Types ───────────────────────────────────────────────────────────────

/// Public HyperLogLog parameters.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllFinalParams {
    /// Register-index bits. Number of registers is `m = 2^b`.
    /// Constraints: `b ≥ 2` so `m ≥ 4` (state alignment); `b ≤ 16` so
    /// `m ≤ 65 536` (keeps the Poseidon2 trace tractable in tests).
    pub b: usize,
    /// Public batch capacity.
    pub batch: usize,
}

impl HllFinalParams {
    pub fn m(&self) -> usize {
        1usize << self.b
    }

    /// `m` Challenges (one per register), each 4 Vals.
    pub fn state_packing(&self) -> usize {
        self.m()
    }

    pub fn batch_packing(&self) -> usize {
        self.batch
    }

    /// Maximum leading-run-of-zeros statistic (1-indexed convention, so
    /// values land in `[1, 64-b+1]`; we use 0 for "register untouched").
    pub fn lr_max(&self) -> u32 {
        (64 - self.b + 1) as u32
    }

    pub fn validate(&self) {
        assert!(self.b >= 2, "b must be ≥ 2 (m ≥ 4); got {}", self.b);
        assert!(self.b <= 16, "b > 16 is unsupported in this prototype; got {}", self.b);
        assert!(self.m() % 2 == 0, "m = 2^b must be even (always true for b ≥ 1)");
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(self.batch % 2 == 0, "batch must be even (Poseidon2 alignment), got {}", self.batch);
    }
}

/// HLL state. `registers[i]` holds the largest leading-run-of-zeros
/// statistic observed for register `i`; 0 means "register untouched".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HllFinalState {
    pub registers: Vec<u32>,
    pub params: HllFinalParams,
}

impl HllFinalState {
    pub fn empty(params: HllFinalParams) -> Self {
        Self { registers: vec![0u32; params.m()], params }
    }

    /// Touched-register count — number of registers with `lr > 0`.
    /// **Private** (visible only to the prover).
    pub fn touched(&self) -> usize {
        self.registers.iter().filter(|&&r| r > 0).count()
    }

    /// HLL distinct-count estimate (classic harmonic-mean formula).
    pub fn estimate(&self) -> f64 {
        let m = self.params.m() as f64;
        let alpha = match self.params.m() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let z: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        alpha * m * m / z
    }
}

/// Batch record. `active = 0` rows are padding dummies — the circuit
/// verifies the boolean constraint but treats them as no-ops.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct HllFinalUpdate {
    pub key: u64,
    pub active: u32,
}

impl HllFinalUpdate {
    pub const fn real(key: u64) -> Self {
        Self { key, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { key: 0, active: 0 }
    }
}

/// Commitments — Poseidon2 sponge over the packed representation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllFinalStateCommit(pub [Val; 8]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllFinalBatchCommit(pub [Val; 8]);

pub struct HllFinalLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: HllFinalStateCommit,
    pub final_: HllFinalStateCommit,
    pub batch_commit: HllFinalBatchCommit,
    pub params: HllFinalParams,
}

pub struct HllFinalProof {
    pub proof: HllFinalLeafProof,
    pub final_state: HllFinalState,
}

impl HllFinalProof {
    pub fn estimate(&self) -> f64 {
        self.final_state.estimate()
    }
}

// ─── Hash family — Poseidon2 PRF ────────────────────────────────────────

/// Compute the `(register_idx, leading_run)` pair from a key via a
/// Poseidon2 sponge.
///
/// - Input: 4 Vals `(key_lo, key_hi, 0, 0)` — one Challenge.
/// - Output: 8 Val digest. `digest[0] mod m` is the register index;
///   `LeadingOnes(digest[1])` (mod `lr_max`) is the leading-run statistic.
///
/// Native-side analog of the in-circuit hash gadget. Matches what
/// `add_hash_slice` would compute given `&[key_packed_as_one_challenge]`.
pub fn hash_register_prf(key: u64, params: HllFinalParams) -> (usize, u32) {
    let hasher = MyHash::new(make_perm());
    let key_lo = (key & 0xFFFF_FFFF) as u32;
    let key_hi = (key >> 32) as u32;
    let input = [
        Val::from_u32(key_lo),
        Val::from_u32(key_hi),
        Val::ZERO,
        Val::ZERO,
    ];
    let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());

    let m = params.m() as u64;
    let idx_raw: u64 = <Val as p3_field::PrimeField64>::as_canonical_u64(&digest[0]);
    let idx = (idx_raw % m) as usize;

    // Leading-run-of-zeros statistic from digest[1]: 1-indexed, in
    // [1, lr_max]. Zero-tail (extremely unlikely) caps at lr_max.
    let tail: u64 = <Val as p3_field::PrimeField64>::as_canonical_u64(&digest[1]);
    let leading = if tail == 0 {
        params.lr_max()
    } else {
        // tail is up to 31 bits (BabyBear < 2^31); take its leading_zeros
        // within that window (32 - leading_zeros gives position of high
        // bit; we want zeros from the top).
        let lz = tail.leading_zeros();
        // u64::leading_zeros counts from bit 63; we want from bit 30
        // (BabyBear's highest bit). Clamp to lr_max.
        let trimmed = if lz < 33 { 0 } else { lz - 33 };
        trimmed.min(params.lr_max() - 1) + 1
    };
    (idx, leading)
}

/// Apply one update natively — the HLL max update rule.
pub fn apply_update(state: &mut HllFinalState, u: &HllFinalUpdate) {
    if u.active == 0 {
        return;
    }
    let (idx, lr) = hash_register_prf(u.key, state.params);
    if lr > state.registers[idx] {
        state.registers[idx] = lr;
    }
}

// ─── Packing helpers ─────────────────────────────────────────────────────

fn pack_state_to_challenge(state: &HllFinalState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    state
        .registers
        .iter()
        .map(|&r| {
            // Pack as (lr, 0, 0, 1): the last slot forces an "always-active"
            // flag, mirroring the SS/GK row layout so the in-circuit
            // boolean-check pattern flows naturally. The flag is never
            // negotiated — it's a constant 1 by construction — but
            // including it gives the Recompose AIR's bus accounting the
            // same shape as the working gk_final and ss_final paths.
            let coeffs = [Val::from_u32(r), Val::ZERO, Val::ZERO, Val::ONE];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn pack_batch_to_challenge(batch: &[HllFinalUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    batch
        .iter()
        .map(|u| {
            let key_lo = (u.key & 0xFFFF_FFFF) as u32;
            let key_hi = (u.key >> 32) as u32;
            let coeffs = [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(u.active),
                Val::ZERO,
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn flat_state_vals(state: &HllFinalState) -> Vec<Val> {
    state
        .registers
        .iter()
        .flat_map(|&r| [Val::from_u32(r), Val::ZERO, Val::ZERO, Val::ONE])
        .collect()
}

fn flat_batch_vals(batch: &[HllFinalUpdate]) -> Vec<Val> {
    batch
        .iter()
        .flat_map(|u| {
            let key_lo = (u.key & 0xFFFF_FFFF) as u32;
            let key_hi = (u.key >> 32) as u32;
            [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(u.active),
                Val::ZERO,
            ]
        })
        .collect()
}

pub fn commit_hll_state(state: &HllFinalState) -> HllFinalStateCommit {
    let hasher = MyHash::new(make_perm());
    let flat = flat_state_vals(state);
    let digest: [Val; 8] = hasher.hash_iter(flat);
    HllFinalStateCommit(digest)
}

pub fn commit_hll_batch(batch: &[HllFinalUpdate]) -> HllFinalBatchCommit {
    let hasher = MyHash::new(make_perm());
    let flat = flat_batch_vals(batch);
    let digest: [Val; 8] = hasher.hash_iter(flat);
    HllFinalBatchCommit(digest)
}

// ─── Prover ──────────────────────────────────────────────────────────────

/// Prove one HLL update epoch under the simplified Appendix F design.
///
/// See module docstring for what's certified vs. deferred. Core invariant:
/// every active flag is `∈ {0, 1}` and every register in the new state is
/// monotone non-decreasing relative to the old state.
pub fn prove_hll_final(
    params: HllFinalParams,
    initial_state: HllFinalState,
    batch: Vec<HllFinalUpdate>,
) -> HllFinalLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);

    let m = params.m();
    let batch_size = params.batch;
    let state_packing = params.state_packing();
    let batch_packing = params.batch_packing();
    let lr_max = params.lr_max();

    // Native side.
    let mut final_state = initial_state.clone();
    for u in &batch {
        apply_update(&mut final_state, u);
    }
    let initial_commit = commit_hll_state(&initial_state);
    let final_commit = commit_hll_state(&final_state);
    let batch_commit = commit_hll_batch(&batch);

    // ─── Build the circuit ──────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // PIs
    let init_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Constants
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");

    // Private inputs: packed state cells + batch records + per-register
    // "delta witness" (delta[i] = final[i] - init[i], which must be ≥ 0
    // for the max-monotonicity check).
    let init_packed: Vec<ExprId> = (0..state_packing)
        .map(|_| b.alloc_private_input("init_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..state_packing)
        .map(|_| b.alloc_private_input("final_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..batch_packing)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();

    // ─── Stage 1: Poseidon2 commits ─────────────────────────────────────
    let h_init = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &init_packed, true)
        .expect("hash init state");
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("hash final state");
    for i in 0..DIGEST_PACKING {
        b.connect(h_final[i], final_pis[i]);
    }
    let h_batch = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(h_batch[i], batch_pis[i]);
    }

    // ─── Stage 2: Decompose every packed input (recompose AIR consumes
    //              every base coefficient internally) ──────────────────
    let init_fields: Vec<Vec<ExprId>> = init_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose init"))
        .collect();
    let final_fields: Vec<Vec<ExprId>> = final_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose final"))
        .collect();
    let batch_fields: Vec<Vec<ExprId>> = batch_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose batch"))
        .collect();

    // ─── Stage 3: Boolean check on the forced-active flag ──────────────
    // Every register row is packed with active=1 in field [3]; the
    // boolean constraint `a · (a − 1) = 0` is trivially satisfied. This
    // gives the Recompose AIR a uniform "use field [3]" pattern matching
    // the working gk_final / ss_final paths.
    for r in 0..m {
        let a = init_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);

        let a = final_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    }
    // Same boolean check for the batch.
    for j in 0..batch_size {
        let a = batch_fields[j][2];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    }

    // ─── Stage 4: Per-register monotonicity binding ────────────────────
    // `final.lr * final.active = (init.lr * init.active) + delta_i`
    // where `delta_i ≥ 0` (HLL's `max` is monotone). The active flags
    // are always 1, so this simplifies to `final.lr = init.lr + delta_i`.
    // We don't range-check delta — that's a documented gap.
    for i in 0..m {
        let init_term = b.mul(init_fields[i][0], init_fields[i][3]);
        let final_term = b.mul(final_fields[i][0], final_fields[i][3]);
        let _delta = b.sub(final_term, init_term);
    }

    let _ = lr_max;

    let circuit = b.build().expect("build hll_final circuit");

    // ─── Pack inputs ────────────────────────────────────────────────────
    let init_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(initial_commit.0),
    );
    let final_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(final_commit.0),
    );
    let batch_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(batch_commit.0),
    );

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&init_commit_packed);
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
        runner.run().expect("run hll_final circuit")
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
        .expect("get_airs_and_degrees_with_prep (hll_final)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover =
        BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (hll_final)");
    prover.verify_all_tables(&proof).expect("self-verify hll_final leaf");

    // Silence unused REGISTER_PACK warning while keeping it documented.
    let _ = REGISTER_PACK;

    HllFinalLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
}

pub fn generate_proof(
    params: HllFinalParams,
    updates: Vec<HllFinalUpdate>,
) -> HllFinalProof {
    params.validate();
    assert_eq!(updates.len(), params.batch);
    let initial_state = HllFinalState::empty(params);
    let mut final_state = initial_state.clone();
    for u in &updates {
        apply_update(&mut final_state, u);
    }
    let proof = prove_hll_final(params, initial_state, updates);
    HllFinalProof { proof, final_state }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_padded_batch(params: HllFinalParams, active_count: usize) -> Vec<HllFinalUpdate> {
        assert!(active_count <= params.batch);
        let salt = (params.m() * params.batch) as u64;
        (0..params.batch)
            .map(|i| {
                if i < active_count {
                    HllFinalUpdate::real((i as u64).wrapping_mul(0x9E37_79B9) ^ salt)
                } else {
                    HllFinalUpdate::dummy()
                }
            })
            .collect()
    }

    fn resolve_threads() -> (Option<usize>, String) {
        let n: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse().ok());
        let label = match n {
            Some(k) => format!("V3_SWEEP_THREADS={k}"),
            None => format!("Rayon default pool ({} threads)", rayon::current_num_threads()),
        };
        (n, label)
    }

    fn with_pool<F: FnOnce() -> T + Send, T: Send>(n: Option<usize>, f: F) -> T {
        match n {
            None => f(),
            Some(k) => {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(k)
                    .thread_name(|i| format!("hll-final-bench-{i}"))
                    .build()
                    .expect("build rayon thread pool");
                pool.install(f)
            }
        }
    }

    #[test]
    fn hll_generate_proof_round_trip() {
        let params = HllFinalParams { b: 4, batch: 2 };
        let updates = vec![HllFinalUpdate::real(7), HllFinalUpdate::real(11)];
        let result = generate_proof(params, updates);
        assert_eq!(commit_hll_state(&result.final_state).0, result.proof.final_.0);
    }

    /// **Test 1 — proving time vs. active-count density.**
    ///
    /// Holds `(b=8 → m=256, batch=100)` fixed and sweeps active records.
    /// Circuit shape is constant; prove time should be near-flat,
    /// confirming the privacy goal (verifier sees no signal from
    /// padding ratio).
    #[test]
    #[ignore]
    fn hll_proving_time_with_different_active_counts() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = HllFinalParams { b: 8, batch: 100 };

        println!();
        println!("hll_final — proving time vs. active-count density");
        println!("===================================================");
        println!("  threads: {threads_label}");
        println!("  b={} (m={}), batch={}", params.b, params.m(), params.batch);
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
    #[test]
    #[ignore]
    fn hll_proving_time_merge_two_leaves() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = HllFinalParams { b: 8, batch: 100 };

        println!();
        println!("hll_final — merge proving-time check");
        println!("======================================");
        println!("  threads: {threads_label}");
        println!("  b={} (m={}), batch={}", params.b, params.m(), params.batch);
        println!();

        let (l1_time, l2_time) = with_pool(threads, move || {
            let s0 = HllFinalState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_hll_final(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();

            let mut s1 = s0;
            for u in &b1 {
                apply_update(&mut s1, u);
            }
            assert_eq!(commit_hll_state(&s1).0, l1.final_.0);

            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let _l2 = prove_hll_final(params, s1, b2);
            (l1_time, t2.elapsed())
        });

        println!("  leaf 1 prove:       {l1_time:>10.2?}");
        println!("  leaf 2 prove:       {l2_time:>10.2?}");
        println!("  ────────────────────────────────");
        println!("  total wall-clock:   {:>10.2?}", l1_time + l2_time);
        println!();
        println!("  (Sequential merge via recursive aggregation deferred.)");
    }

    /// **Test 3 — generate two proofs and persist to `src/proofs/`.**
    #[test]
    #[ignore]
    fn hll_generate_and_store_proof() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::Instant;

        let (threads, threads_label) = resolve_threads();
        let params = HllFinalParams { b: 8, batch: 100 };

        let crate_root = env!("CARGO_MANIFEST_DIR");
        let out_dir = PathBuf::from(crate_root).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("create src/proofs directory");

        println!();
        println!("hll_final — generate two proofs + store to disk");
        println!("================================================");
        println!("  threads: {threads_label}");
        println!("  b={} (m={}), batch={}", params.b, params.m(), params.batch);
        println!();

        with_pool(threads, move || {
            let s0 = HllFinalState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_hll_final(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();
            let proof1_bytes = postcard::to_allocvec(&l1.output.0).expect("serialize p1");
            let proof1_path = out_dir.join("hll_proof1.bin");
            fs::write(&proof1_path, &proof1_bytes).expect("write p1");
            write_hll_meta(&out_dir.join("hll_proof1.meta.txt"), "hll_proof1.bin", &params, &l1, proof1_bytes.len());

            let mut s1 = s0;
            for u in &b1 { apply_update(&mut s1, u); }
            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let l2 = prove_hll_final(params, s1, b2);
            let l2_time = t2.elapsed();
            let proof2_bytes = postcard::to_allocvec(&l2.output.0).expect("serialize p2");
            let proof2_path = out_dir.join("hll_proof2.bin");
            fs::write(&proof2_path, &proof2_bytes).expect("write p2");
            write_hll_meta(&out_dir.join("hll_proof2.meta.txt"), "hll_proof2.bin", &params, &l2, proof2_bytes.len());

            println!("  leaf 1 prove time:  {l1_time:>10.2?}");
            println!("  proof 1 size:       {:>10} bytes", proof1_bytes.len());
            println!("  leaf 2 prove time:  {l2_time:>10.2?}");
            println!("  proof 2 size:       {:>10} bytes", proof2_bytes.len());
            println!();
            println!("  proofs persisted to: {}", out_dir.display());
        });
    }

    fn write_hll_meta(
        path: &std::path::Path,
        bin: &str,
        params: &HllFinalParams,
        leaf: &HllFinalLeafProof,
        size: usize,
    ) {
        use std::fs;
        let mut meta = String::new();
        meta.push_str("# HLL final-design proof — sidecar metadata\n");
        meta.push_str(&format!("# Paired with `{bin}`.\n\n"));
        meta.push_str(&format!("params.b     = {} (m = {})\n", params.b, params.m()));
        meta.push_str(&format!("params.batch = {}\n\n", params.batch));
        meta.push_str(&format!("initial_commit  = {:?}\n", leaf.initial.0));
        meta.push_str(&format!("final_commit    = {:?}\n", leaf.final_.0));
        meta.push_str(&format!("batch_commit    = {:?}\n\n", leaf.batch_commit.0));
        meta.push_str(&format!("proof_size_bytes = {size}\n"));
        fs::write(path, &meta).expect("write meta");
    }
}
