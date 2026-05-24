//! CircuitBuilder-based HyperLogLog update leaf for the §4.2 recursive merge.
//!
//! Verifies one epoch of the HyperLogLog sketch (paper §5.3 Pattern A *max*,
//! Appendix F), staged as the §5.1-style strawman: per-register max-update
//! enforced via bit-decomposition + product-of-differences constraints, with
//! the in-circuit Poseidon2 hash binding the per-epoch state commitments.
//! Parameters `(b, batch)` are runtime-supplied so the workload sweep can
//! scan a grid without recompilation.
//!
//! `m = 2^b` must be a multiple of the Challenge extension degree (4) so the
//! off-circuit `commit_hll` and the in-circuit `add_hash_slice` produce
//! identical 8-element base-field digests. `HllLeafParams::validate` enforces
//! this and `b ≥ 2` guarantees it.
//!
//! ### Public inputs (Challenge field elements)
//!
//! 1. `initial_commit[0..2]` — `[Val; 8]` digest packed into 2 Challenge PIs.
//! 2. `final_commit[0..2]`   — same shape for the post-update state.
//! 3. For each record `k`: `(key_k, register_idx_k, lead_run_k)`, each as one
//!    PI. The caller computes the register index / leading-run pair via
//!    `sketch::hyperloglog::hash_register` and exposes them as PIs; the leaf
//!    verifier (or downstream merge verifier) is responsible for cross-checking
//!    them against a native recomputation if it doesn't trust the leaf prover.
//!
//! ### Private inputs
//!
//! - Packed initial registers (`m/4` Challenge entries) decomposed in-circuit
//!   into `m` base-embedded register values.
//! - Packed final registers (same shape).
//! - Per record `k`: `selectors[k][0..m]` — `m` base-embedded indicators
//!   forming a one-hot vector pointing at `register_idx_k`.
//! - Per register `r`: `REGISTER_WIDTH` bits for `initial[r]` and `REGISTER_WIDTH`
//!   bits for `final[r]` (range proofs).
//! - Per `(r, candidate)` pair: `REGISTER_WIDTH` bits for the non-negative
//!   difference `final[r] - candidate` (range proof for `final[r] ≥ candidate`).
//!
//! ### Constraints
//!
//! 1. `hash(initial_packed) == initial_commit` (in-circuit Poseidon2).
//! 2. `hash(final_packed)   == final_commit`.
//! 3. For each record `k`: every selector entry is boolean (`(1 - s) * s = 0`),
//!    `sum(s[0..m]) == 1`, and `sum_r(s[r] * r) == register_idx_k`.
//!    **Gotcha**: the equivalent form `s * s = s` looks identical mathematically
//!    but trips the `WitnessChecks` lookup-bus check inside `BatchStarkProver`.
//!    The ALU AIR treats `mul(x, x)` as a single reader on the bus, so the
//!    multiplicity disagrees with the public AIR's count and verify fails with
//!    `LookupError("GlobalCumulativeMismatch(None): WitnessChecks")`. Use the
//!    `(1 - x) * x = 0` formulation everywhere a boolean check is needed.
//! 4. Bit decomposition: every bit is boolean and the weighted sum equals
//!    the corresponding register value (initial and final).
//! 5. For each register `r`, build the candidate set
//!    `{initial[r], initial[r] + s[k][r] * (lead[k] - initial[r]) : k ∈ batch}`.
//!    Records not touching `r` collapse to `initial[r]` so the set is exactly
//!    `{initial[r]} ∪ {lead[k] : s[k][r] = 1}`.
//!    - **Product**: `Π(final[r] - candidate) = 0` — `final[r]` equals one
//!      of the candidates.
//!    - **Range**: for each candidate `c`, `final[r] - c` is a non-negative
//!      `REGISTER_WIDTH`-bit integer.
//!    Together these enforce `final[r] = max(candidate_set)`, the §5.3
//!    Pattern A max invariant.

use std::rc::Rc;

use p3_batch_stark::ProverData;
use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::HyperLogLogCommit;
use crate::commitment::hyperloglog::commit_hll;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::{ConfigWithFriParams, make_recursion_config};
use crate::sketch::Sketch;
use crate::sketch::hyperloglog::{
    HyperLogLog, HyperLogLogState, HyperLogLogUpdate, hash_register,
};

// ─── Demo defaults ───────────────────────────────────────────────────────

/// Default index-bit count for the Phase 4 demos and tests (`m = 8`).
pub const B: usize = 3;
/// Default records per epoch.
pub const BATCH: usize = 2;

/// Required alignment of the register count to the Challenge extension degree
/// so `add_hash_slice` and `MyHash::hash_iter` produce identical digests.
pub const CELL_ALIGNMENT: usize = 4;
/// Number of Challenge digest outputs (always 8 base = 2 Challenge).
pub const DIGEST_PACKING: usize = 2;
/// Bit width of a single HyperLogLog register. `64 - b + 1 ≤ 63` for `b ≥ 2`
/// fits in 6 bits with room to spare.
pub const REGISTER_WIDTH: usize = 6;

/// FRI parameters used for the leaf — kept equal to the recursive merge
/// layer's parameters so the two share a verifier-circuit shape.
const LOG_FINAL_POLY_LEN: usize = 6;

// ─── Runtime parameters ──────────────────────────────────────────────────

/// Per-leaf runtime parameters. `m = 2^b` must be a multiple of `CELL_ALIGNMENT`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllLeafParams {
    pub b: usize,
    pub batch: usize,
}

impl HllLeafParams {
    pub fn m(&self) -> usize {
        1usize << self.b
    }
    pub fn cell_packing(&self) -> usize {
        self.m() / CELL_ALIGNMENT
    }
    /// Panics if the parameters are out of range or misaligned for the
    /// in-circuit hash.
    pub fn validate(&self) {
        assert!(self.b >= 2 && self.b < 32, "b must be in [2, 32); got {}", self.b);
        assert!(self.batch >= 1, "batch must be positive");
        let m = self.m();
        assert!(
            m % CELL_ALIGNMENT == 0,
            "m = 2^b = {m} is not a multiple of {CELL_ALIGNMENT}; in-circuit hash absorption requires alignment"
        );
    }
}

impl Default for HllLeafParams {
    fn default() -> Self {
        Self { b: B, batch: BATCH }
    }
}

// ─── Leaf proof type ─────────────────────────────────────────────────────

/// A successfully-proven HyperLogLog update epoch.
pub struct HllLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: HyperLogLogCommit,
    pub final_: HyperLogLogCommit,
    /// Batch consumed by this epoch. Length equals `params.batch`.
    pub batch: Vec<HyperLogLogUpdate>,
    pub params: HllLeafParams,
}

impl HllLeafProof {
    /// Reconstruct the public-values vector this proof was bound to, in
    /// allocation order. Useful for sanity-checking the leaf in isolation.
    pub fn public_values(&self) -> Vec<Challenge> {
        let mut pis = Vec::new();
        pis.extend(pack_commit_to_challenge(&self.initial));
        pis.extend(pack_commit_to_challenge(&self.final_));
        for u in &self.batch {
            let (idx, lr) = hash_register(self.params.b, u.key);
            pis.push(Challenge::from_u64(u.key));
            pis.push(Challenge::from_u64(idx as u64));
            pis.push(Challenge::from_u32(lr as u32));
        }
        pis
    }
}

// ─── Packing helpers ─────────────────────────────────────────────────────

/// Pack a `HyperLogLogCommit` (`[Val; 8]`) into 2 Challenge elements.
pub fn pack_commit_to_challenge(c: &HyperLogLogCommit) -> [Challenge; DIGEST_PACKING] {
    [
        Challenge::from_basis_coefficients_slice(&c.0[0..4]).expect("4 base coeffs"),
        Challenge::from_basis_coefficients_slice(&c.0[4..8]).expect("4 base coeffs"),
    ]
}

/// Pack the m registers of an HLL state into `m/4` Challenge elements,
/// matching the layout the in-circuit `add_hash_slice` absorbs.
fn pack_registers_to_challenge(state: &HyperLogLogState) -> Vec<Challenge> {
    let flat: Vec<Val> = state.registers.iter().map(|&r| Val::from_u32(r as u32)).collect();
    assert_eq!(flat.len(), state.params.m());
    flat.chunks(CELL_ALIGNMENT)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Decompose a u8 register value into `REGISTER_WIDTH` little-endian bits.
fn bits_of(v: u8) -> [Challenge; REGISTER_WIDTH] {
    let mut out = [Challenge::ZERO; REGISTER_WIDTH];
    for i in 0..REGISTER_WIDTH {
        out[i] = if (v >> i) & 1 == 1 { Challenge::ONE } else { Challenge::ZERO };
    }
    out
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

/// Compile-time-defaults wrapper. Convenient for the original `(B, BATCH) =
/// (3, 2)` demo path; for the workload sweep use `prove_hll_leaf_with_params`.
pub fn prove_hll_leaf(
    initial_state: HyperLogLogState,
    batch: [HyperLogLogUpdate; BATCH],
) -> HllLeafProof {
    prove_hll_leaf_with_params(
        HllLeafParams { b: B, batch: BATCH },
        initial_state,
        batch.to_vec(),
    )
}

/// Runtime-parameterised version. `m = 2^params.b` must be a multiple of 4;
/// `batch.len() == params.batch`; `initial_state.params.b == params.b`.
pub fn prove_hll_leaf_with_params(
    params: HllLeafParams,
    initial_state: HyperLogLogState,
    batch: Vec<HyperLogLogUpdate>,
) -> HllLeafProof {
    params.validate();
    assert_eq!(initial_state.params.b, params.b, "state.b / params.b mismatch");
    assert_eq!(batch.len(), params.batch, "batch length / params.batch mismatch");

    let m = params.m();
    let batch_size = params.batch;
    let cell_packing = params.cell_packing();

    // Compute the final state natively. Used both as a private-witness source
    // and to derive the public final-commit PI.
    let mut final_state = initial_state.clone();
    for u in &batch {
        HyperLogLog::update(&mut final_state, u);
    }
    let initial_commit = commit_hll(&initial_state);
    let final_commit = commit_hll(&final_state);

    // Build the circuit.
    let mut b_c = CircuitBuilder::<Challenge>::new();
    b_c.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b_c.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // ---- Public inputs ----
    let initial_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b_c.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b_c.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    // Per-record PIs: (key, register_idx, lead_run).
    let mut record_pis: Vec<(ExprId, ExprId, ExprId)> = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let key = b_c.alloc_public_input("key");
        let reg = b_c.alloc_public_input("reg_idx");
        let lead = b_c.alloc_public_input("lead");
        record_pis.push((key, reg, lead));
    }

    // ---- Private inputs ----
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b_c.alloc_private_input("init_reg_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b_c.alloc_private_input("final_reg_packed"))
        .collect();

    // Per-record one-hot register selectors.
    let mut selectors: Vec<Vec<ExprId>> = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let s: Vec<ExprId> = (0..m).map(|_| b_c.alloc_private_input("sel")).collect();
        selectors.push(s);
    }

    // Bit decomp witnesses for initial and final registers.
    let mut initial_bits: Vec<Vec<ExprId>> = Vec::with_capacity(m);
    let mut final_bits: Vec<Vec<ExprId>> = Vec::with_capacity(m);
    for _ in 0..m {
        let ib: Vec<ExprId> = (0..REGISTER_WIDTH)
            .map(|_| b_c.alloc_private_input("init_bit"))
            .collect();
        let fb: Vec<ExprId> = (0..REGISTER_WIDTH)
            .map(|_| b_c.alloc_private_input("final_bit"))
            .collect();
        initial_bits.push(ib);
        final_bits.push(fb);
    }

    // Bit decomp witnesses for (final[r] - candidate_i) non-negative range
    // proofs. Candidates per register: 1 (initial) + batch_size (per-record).
    let candidates_per_r = batch_size + 1;
    let mut diff_bits: Vec<Vec<Vec<ExprId>>> = vec![vec![vec![]; candidates_per_r]; m];
    for r in 0..m {
        for c in 0..candidates_per_r {
            diff_bits[r][c] = (0..REGISTER_WIDTH)
                .map(|_| b_c.alloc_private_input("diff_bit"))
                .collect();
        }
    }

    // ---- Constraints ----

    let one = b_c.alloc_const(Challenge::ONE, "one");
    let zero = b_c.alloc_const(Challenge::ZERO, "zero");

    // 1. Hash packed initial → initial_commit PIs.
    let digest_init = b_c
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &initial_packed, true)
        .expect("add_hash_slice(initial)");
    assert_eq!(digest_init.len(), DIGEST_PACKING);
    for i in 0..DIGEST_PACKING {
        b_c.connect(digest_init[i], initial_commit_pis[i]);
    }

    // 2. Hash packed final → final_commit PIs.
    let digest_final = b_c
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("add_hash_slice(final)");
    for i in 0..DIGEST_PACKING {
        b_c.connect(digest_final[i], final_commit_pis[i]);
    }

    // Decompose packed register inputs into base-embedded individual values.
    let initial_regs: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| {
            b_c.decompose_ext_to_base_coeffs::<Val>(p)
                .expect("decompose initial_packed")
        })
        .collect();
    let final_regs: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| {
            b_c.decompose_ext_to_base_coeffs::<Val>(p)
                .expect("decompose final_packed")
        })
        .collect();
    assert_eq!(initial_regs.len(), m);
    assert_eq!(final_regs.len(), m);

    let r_consts: Vec<ExprId> = (0..m)
        .map(|r| b_c.alloc_const(Challenge::from_u64(r as u64), "r"))
        .collect();
    let pow2: Vec<ExprId> = (0..REGISTER_WIDTH)
        .map(|i| b_c.alloc_const(Challenge::from_u64(1u64 << i), "pow2"))
        .collect();

    // 3. Selector validity.
    for k in 0..batch_size {
        let s = &selectors[k];

        // Each selector entry is boolean: (1 - s[r]) * s[r] = 0.
        for &sr in s {
            let one_minus = b_c.sub(one, sr);
            let prod = b_c.mul(one_minus, sr);
            b_c.connect(prod, zero);
        }

        // sum_r(s[r]) == 1.
        let mut sum = s[0];
        for r in 1..m {
            sum = b_c.add(sum, s[r]);
        }
        b_c.connect(sum, one);

        // sum_r(s[r] * r) == register_idx[k].
        let mut weighted = zero;
        for r in 0..m {
            let term = b_c.mul(s[r], r_consts[r]);
            weighted = b_c.add(weighted, term);
        }
        b_c.connect(weighted, record_pis[k].1);
    }

    // 4. Bit decomp of initial[r] and final[r] (range check + decomposition).
    for r in 0..m {
        // initial[r] boolean checks: (1 - bit) * bit = 0
        for &bit in &initial_bits[r] {
            let one_minus = b_c.sub(one, bit);
            let prod = b_c.mul(one_minus, bit);
            b_c.connect(prod, zero);
        }
        let mut sum = b_c.mul(initial_bits[r][0], pow2[0]);
        for i in 1..REGISTER_WIDTH {
            let term = b_c.mul(initial_bits[r][i], pow2[i]);
            sum = b_c.add(sum, term);
        }
        b_c.connect(sum, initial_regs[r]);

        // final[r] boolean checks
        for &bit in &final_bits[r] {
            let one_minus = b_c.sub(one, bit);
            let prod = b_c.mul(one_minus, bit);
            b_c.connect(prod, zero);
        }
        let mut sum = b_c.mul(final_bits[r][0], pow2[0]);
        for i in 1..REGISTER_WIDTH {
            let term = b_c.mul(final_bits[r][i], pow2[i]);
            sum = b_c.add(sum, term);
        }
        b_c.connect(sum, final_regs[r]);
    }

    // 5. Max-update constraint per register.
    //    candidate[0] = initial[r]
    //    candidate[k+1] = initial[r] + selector[k][r] * (lead[k] - initial[r])
    //    Π(final[r] - candidate_i) = 0     (final[r] ∈ candidate set)
    //    final[r] - candidate_i ∈ [0, 2^6) (final[r] ≥ candidate_i, range-checked)
    for r in 0..m {
        let mut candidates: Vec<ExprId> = Vec::with_capacity(candidates_per_r);
        candidates.push(initial_regs[r]);
        for k in 0..batch_size {
            let s_kr = selectors[k][r];
            let lead = record_pis[k].2;
            let lead_minus_init = b_c.sub(lead, initial_regs[r]);
            let scaled = b_c.mul(s_kr, lead_minus_init);
            let cand = b_c.add(initial_regs[r], scaled);
            candidates.push(cand);
        }

        // Π(final - candidate_i) = 0
        let mut factors: Vec<ExprId> = Vec::with_capacity(candidates_per_r);
        for c in &candidates {
            factors.push(b_c.sub(final_regs[r], *c));
        }
        let prod = b_c.mul_many(&factors);
        b_c.connect(prod, zero);

        // For each candidate: bit-decomp of (final - candidate) in [0, 64).
        for c_idx in 0..candidates_per_r {
            let diff = b_c.sub(final_regs[r], candidates[c_idx]);
            for &bit in &diff_bits[r][c_idx] {
                let one_minus = b_c.sub(one, bit);
                let prod = b_c.mul(one_minus, bit);
                b_c.connect(prod, zero);
            }
            let mut sum = b_c.mul(diff_bits[r][c_idx][0], pow2[0]);
            for i in 1..REGISTER_WIDTH {
                let term = b_c.mul(diff_bits[r][c_idx][i], pow2[i]);
                sum = b_c.add(sum, term);
            }
            b_c.connect(sum, diff);
        }
    }

    let circuit = b_c.build().expect("build leaf circuit");

    // ---- Pack public + private values and run the circuit ----
    let initial_commit_packed = pack_commit_to_challenge(&initial_commit);
    let final_commit_packed = pack_commit_to_challenge(&final_commit);

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&initial_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    let mut record_meta: Vec<(usize, u8)> = Vec::with_capacity(batch_size);
    for u in &batch {
        let (idx, lr) = hash_register(params.b, u.key);
        public_inputs.push(Challenge::from_u64(u.key));
        public_inputs.push(Challenge::from_u64(idx as u64));
        public_inputs.push(Challenge::from_u32(lr as u32));
        record_meta.push((idx, lr));
    }

    let initial_regs_packed = pack_registers_to_challenge(&initial_state);
    let final_regs_packed = pack_registers_to_challenge(&final_state);
    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&initial_regs_packed);
    private_inputs.extend_from_slice(&final_regs_packed);

    // selectors
    for k in 0..batch_size {
        let (idx, _lr) = record_meta[k];
        for r in 0..m {
            private_inputs.push(if r == idx { Challenge::ONE } else { Challenge::ZERO });
        }
    }

    // initial_bits[r], final_bits[r]
    for r in 0..m {
        for &bit in &bits_of(initial_state.registers[r]) {
            private_inputs.push(bit);
        }
        for &bit in &bits_of(final_state.registers[r]) {
            private_inputs.push(bit);
        }
    }

    // diff_bits[r][c]: final[r] - candidate[c]. Candidate[0] = initial[r],
    // Candidate[k+1] = initial[r] if !touched else lead[k].
    for r in 0..m {
        // Reconstruct the candidates for this register in the SAME ORDER the
        // circuit defines them. The "no-record" candidate (initial) is first.
        let init_v = initial_state.registers[r];
        let mut candidates_v: Vec<u8> = Vec::with_capacity(candidates_per_r);
        candidates_v.push(init_v);
        for k in 0..batch_size {
            let (idx, lr) = record_meta[k];
            let cand = if idx == r { lr } else { init_v };
            candidates_v.push(cand);
        }
        let final_v = final_state.registers[r];
        for &cv in &candidates_v {
            // final_v >= cv must hold by construction (final_state is the
            // honest max-update). The bit decomp witnesses (final_v - cv).
            let diff = final_v.checked_sub(cv).expect("final < candidate; not a valid HLL transition");
            for &bit in &bits_of(diff) {
                private_inputs.push(bit);
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

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify hll leaf");

    HllLeafProof {
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
    use crate::sketch::hyperloglog::HyperLogLogParams;

    fn empty_state() -> HyperLogLogState {
        HyperLogLog::new(&HyperLogLogParams { b: B })
    }

    #[test]
    fn hll_leaf_round_trip() {
        let initial = empty_state();
        let batch = [
            HyperLogLogUpdate { key: 0xDEAD_BEEF_0000_1111 },
            HyperLogLogUpdate { key: 0xC0FFEE_C0FFEE },
        ];
        let leaf = prove_hll_leaf(initial.clone(), batch);

        let mut expected = initial;
        for u in &batch {
            HyperLogLog::update(&mut expected, u);
        }
        let expected_commit = commit_hll(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
        assert_eq!(leaf.params, HllLeafParams::default());
        assert_eq!(leaf.batch.len(), BATCH);
    }

    /// Same shape but at a larger workload (b=4 ⇒ m=16, batch=4).
    #[test]
    fn hll_leaf_round_trip_at_b4_batch4() {
        let params = HllLeafParams { b: 4, batch: 4 };
        params.validate();
        let initial = HyperLogLog::new(&HyperLogLogParams { b: params.b });
        let batch: Vec<HyperLogLogUpdate> = (0..params.batch)
            .map(|i| HyperLogLogUpdate { key: (i as u64).wrapping_mul(0x9E37_79B9) ^ 0xBEEF })
            .collect();
        let leaf = prove_hll_leaf_with_params(params, initial.clone(), batch.clone());

        let mut expected = initial;
        for u in &batch {
            HyperLogLog::update(&mut expected, u);
        }
        let expected_commit = commit_hll(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
        assert_eq!(leaf.params, params);
        assert_eq!(leaf.batch.len(), params.batch);
    }

    /// `validate` panics on `b < 2`.
    #[test]
    #[should_panic(expected = "b must be in [2, 32)")]
    fn hll_misaligned_params_rejected() {
        HllLeafParams { b: 1, batch: 2 }.validate();
    }
}
