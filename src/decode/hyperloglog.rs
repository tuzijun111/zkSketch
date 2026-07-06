// see worktree file /home/binbin/zkSketch/.claude/worktrees/wf_0b93e877-7d4-3/src/decode/hyperloglog.rs (full contents below)
//! HyperLogLog **cardinality** decode circuit (E3, plonky3/STARK), estimator mode.
//!
//! Implements the paper's HLL query relation (zk1.tex app:hll, "HLL estimator
//! mode") in **fixed-point** arithmetic on the STARK backend, mirroring the
//! plonky2 `decode::hyperloglog` relation. Unlike the previous integer
//! harmonic surrogate `Σ 2^(B−reg)`, this certifies the fixed-point cardinality
//!
//! ```text
//!   Z   = Σ_b Pow2Neg[S_t[b]]            (fixed-point harmonic sum, scale 2^β)
//!   res = α_s · s² · Inv_β(Z)            (fixed-point cardinality, scale 2^β)
//!   ans = release(res)
//! ```
//!
//! where `Pow2Neg[x] = round(2^β / 2^x)` is a **public** fixed-point lookup table
//! selected per register by a one-hot over the register value `0..=MU_MAX`, and
//! `Inv_β(Z)` is a **witnessed** reciprocal `invZ` certified by the range-checked
//! rounding residual `Z·invZ − T ∈ [0, Z)` with reciprocal target
//! `T = 2^(2β)` (so `invZ ≈ 2^β / Z` retains β fractional bits — see the BETA
//! note below). `res` is then the exact in-circuit product `K_num · invZ`, with
//! `K_num = round(α_s · s²)` a public integer constant; `ans = release(res)`.
//!
//! Reusing the `hll_final_full` commit layout and the `countmin` decode harness
//! (Poseidon2 + Recompose, no Permute — decode does not sort).
//!
//! Stages:
//! 1. Re-hash the `m` registers → bind to the committed digest (the `Θ(s)` cost).
//! 2. Per register: a one-hot selector over `[0, MU_MAX]` picks `Pow2Neg[reg]`
//!    and binds `idx_acc == reg` (selected index == register value).
//! 3. Sum the picked fixed-point weights → `Z`.
//! 4. Reciprocal: witness `invZ`, certify `Z·invZ − T ∈ [0, Z)` (range check),
//!    then `res = K_num · invZ`.
//! 5. Apply the release policy and bind the released value to the public answer.
//!
//! There is no query-key public input for cardinality: the answer depends only
//! on the committed state, so PIs are `(committed-state, answer)`.
//!
//! ### Field-size / soundness budget (BabyBear, p ≈ 2^30.9)
//! Every range-checked value and every product fed to a range check must stay
//! `< p`. With `BETA = 8` and `m = 2^b ≤ 256`:
//! * `Z ≤ m·2^β ≤ 2^(8+8) = 2^16`;
//! * reciprocal target `T = 2^(2β) = 2^16`, `invZ = ceil(T/Z) ≤ T/Pow2Neg[0] = 2^β = 2^8`;
//! * `Z·invZ < T + Z ≤ 2^16 + 2^16 = 2^17`  (residual range check sound);
//! * `res = K_num·invZ ≤ round(0.78·256²)·2^8 ≈ 2^15.6·2^8 ≈ 2^23.6 < p`.
//!
//! So this is a **fully sound** in-circuit reciprocal at the prototype register
//! scale — no witnessed-`res` fallback is needed on BabyBear at `BETA = 8`.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_range_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        range_air_builders, range_preprocessor, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::hll_final_full::{HllFullState, commit_hll_state};
use crate::sketch::hll_omc::commit_hll_omc;

const LOG_FINAL_POLY_LEN: usize = 6;

/// Fixed-point precision (mantissa bits) for the estimator. Public metadata.
/// Kept at 8 so every product fits the BabyBear field (see the module budget).
pub const BETA: usize = 8;

/// Max register value the `Pow2Neg` one-hot table covers (`0..=MU_MAX`). At the
/// prototype stream scale registers stay tiny; entries past `BETA` round to 0
/// (`Pow2Neg[x] = round(2^β / 2^x) = 0` for large `x`).
pub const MU_MAX: usize = 24;

/// Range-check window for the reciprocal rounding residual `Z·invZ − T`. The
/// residual lies in `[0, Z)` with `Z ≤ 2^(b+β)`; this window must contain it and
/// stay strictly below the field bit-width so a "negative" residual wraps and
/// overflows the check (sound `≥ 0`).
const DIFF_BITS: usize = 20;

#[derive(Copy, Clone, Debug)]
pub struct HllDecodeParams {
    /// Register-index bits; `m = 2^b` registers.
    pub b: usize,
    pub release: ReleasePolicy,
}

impl HllDecodeParams {
    pub fn validate(&self) {
        assert!(self.b >= 2 && self.b <= 8, "b in [2,8] (m = 2^b registers), got {}", self.b);
    }
}

/// Public fixed-point lookup table `Pow2Neg[x] = round(2^β / 2^x)` for
/// `x ∈ {0,…,MU_MAX}` (round-half-up). Entry 0 is `2^β`; entries past `β`
/// underflow to 0.
pub fn pow2neg(x: usize) -> u64 {
    if x == 0 {
        1u64 << BETA
    } else if x > BETA + 1 {
        0
    } else {
        // round(2^β / 2^x) = round(2^(β−x)); round-half-up via (2^β + 2^(x−1)) >> x.
        let num: u128 = (1u128 << BETA) + (1u128 << (x - 1));
        (num >> x) as u64
    }
}

/// HLL bias-correction `α_s` for `m` registers (matches `HllFullState::estimate`).
fn alpha(m: usize) -> f64 {
    match m {
        16 => 0.673,
        32 => 0.697,
        64 => 0.709,
        _ => 0.7213 / (1.0 + 1.079 / m as f64),
    }
}

/// Public integer constant `K_num = round(α_s · s²)` (`s = m`). `res = K_num·invZ`.
pub fn k_num(m: usize) -> u64 {
    (alpha(m) * (m as f64) * (m as f64)).round() as u64
}

/// Reciprocal target `T = 2^(2β)`.
const fn recip_target() -> u64 {
    1u64 << (2 * BETA)
}

/// Native fixed-point harmonic sum `Z = Σ_b Pow2Neg[reg_b]`.
pub fn fixed_z(regs: &[u32]) -> u64 {
    regs.iter().map(|&r| pow2neg(r as usize)).sum()
}

/// Native witnessed reciprocal `invZ = ceil(T / Z)` (so `Z·invZ − T ∈ [0, Z)`).
pub fn inv_z(z: u64) -> u64 {
    let t = recip_target();
    (t + z - 1) / z
}

/// Native fixed-point cardinality `res = K_num · invZ` (scale `2^β`).
pub fn fixed_res(m: usize, regs: &[u32]) -> u64 {
    let z = fixed_z(regs);
    k_num(m) * inv_z(z)
}

/// Pack an HLL state's registers into Challenge elements, reproducing
/// `commit_hll_state`'s register flattening: each register `r` flattens to the
/// 4-tuple `[r, 0, 0, 1]`, i.e. exactly one Challenge per register.
fn pack_cells(state: &HllFullState) -> Vec<Challenge> {
    state
        .registers
        .iter()
        .map(|&r| {
            let coeffs = [Val::from_u32(r), Val::ZERO, Val::ZERO, Val::ONE];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

/// Prove a HyperLogLog cardinality (fixed-point estimator) decode. Returns a
/// [`DecodeProof`]; the prover self-verifies and records the
/// witness/prove/verify split via [`crate::recursion::recursive::timing`].
///
/// `_query` is unused for cardinality (the answer depends only on the committed
/// state) but kept in the signature to mirror the other decode families.
pub fn prove_hll_decode(params: HllDecodeParams, state: HllFullState, _query: u64) -> DecodeProof {
    params.validate();
    let HllDecodeParams { b: blog2, release } = params;
    let m = 1usize << blog2;
    assert_eq!(state.registers.len(), m, "state shape must match params (m = 2^b)");
    assert!(
        state.registers.iter().all(|&r| (r as usize) <= MU_MAX),
        "register exceeds MU_MAX; raise MU_MAX"
    );

    // ─── Native decode ───────────────────────────────────────────────────
    let commit = commit_hll_state(&state);
    let z = fixed_z(&state.registers);
    let invz = inv_z(z);
    let knum = k_num(m);
    let res = knum * invz;
    let answer = release.apply(res);

    // ─── Build circuit ───────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);

    // PIs: committed state, released answer. (No query key for cardinality.)
    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let answer_pi = b.alloc_public_input("answer");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    // Fixed-point Pow2Neg weights and index constants j, for j in 0..=MU_MAX.
    let pow: Vec<ExprId> = (0..=MU_MAX)
        .map(|j| b.alloc_const(Challenge::from_u64(pow2neg(j)), "pow2neg"))
        .collect();
    let idx: Vec<ExprId> =
        (0..=MU_MAX).map(|j| b.alloc_const(Challenge::from_u64(j as u64), "idx")).collect();
    let target = b.alloc_const(Challenge::from_u64(recip_target()), "recip_target");
    let knum_c = b.alloc_const(Challenge::from_u64(knum), "k_num");

    // Private witnesses.
    let cells_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("cell_packed")).collect();
    let sel: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..=MU_MAX).map(|_| b.alloc_private_input("sel")).collect())
        .collect();
    let invz_w = b.alloc_private_input("invz");
    let flag = if matches!(release, ReleasePolicy::Threshold(_)) {
        Some(b.alloc_private_input("flag"))
    } else {
        None
    };

    // ── Stage 1: open the committed state ──
    let digest = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, true)
        .expect("hash cells");
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }
    // Each register Challenge decomposes to [r, 0, 0, 1]; coeff[0] is the
    // register value. Every decompose output must flow through an ALU op as the
    // LHS (first operand) so it gets a WitnessChecks bus creator — a coeff read
    // only as an rhs (or only via `connect`) panics at prove time with
    // "GlobalCumulativeMismatch: WitnessChecks".
    let regs: Vec<ExprId> = cells_packed
        .iter()
        .map(|&p| {
            let c = b.decompose_ext_to_base_coeffs::<Val>(p).unwrap();
            // coeff[1], coeff[2] must be 0; coeff[3] must be 1 (canonical pack).
            // Put each coeff FIRST (lhs) via `mul(coeff, ·)` to seed its bus
            // creator, then `connect` the product to the expected constant.
            let c1 = b.mul(c[1], one);
            b.connect(c1, zero);
            let c2 = b.mul(c[2], one);
            b.connect(c2, zero);
            let c3 = b.mul(c[3], one);
            b.connect(c3, one);
            c[0]
        })
        .collect();

    // ── Stage 2 + 3: per-register one-hot Pow2Neg selector → Z ──
    let mut z_expr = zero;
    for r in 0..m {
        let row = &sel[r];
        let mut sum = zero;
        let mut idx_acc = zero;
        let mut term = zero;
        for j in 0..=MU_MAX {
            let sm1 = b.sub(row[j], one);
            let bchk = b.mul(row[j], sm1);
            b.connect(bchk, zero);
            sum = b.add(sum, row[j]);
            // idx[j]·sel[j] and sel[j]·pow[j].
            let it = b.mul(idx[j], row[j]);
            idx_acc = b.add(idx_acc, it);
            let pt = b.mul(row[j], pow[j]);
            term = b.add(term, pt);
        }
        b.connect(sum, one);
        // Selected exponent index == register value. The register coeff goes
        // FIRST (lhs) so it gets a bus creator covering this `connect` consume.
        let reg_lhs = b.mul(regs[r], one);
        b.connect(idx_acc, reg_lhs);
        z_expr = b.add(z_expr, term);
    }

    // ── Stage 4: witnessed reciprocal invZ, residual range check, res = K·invZ ──
    // Certify Z·invZ − T ∈ [0, Z): the rounding residual of invZ = ceil(T/Z).
    //   residual := Z·invZ − T            (≥ 0  ⇔  invZ ≥ T/Z, i.e. invZ ≥ ceil)
    //   Z − 1 − residual                  (≥ 0  ⇔  residual ≤ Z−1, i.e. residual < Z)
    // Both range-checked ≥ 0 pin invZ = ceil(T/Z) uniquely. `invz_w` goes FIRST
    // (lhs) in `z·invZ` so it gets a bus creator.
    let z_invz = b.mul(invz_w, z_expr);
    let residual = b.sub(z_invz, target);
    let _ = b.add_range_bits::<Val>(residual, DIFF_BITS).expect("Z·invZ − T >= 0");
    let zm1 = b.sub(z_expr, one);
    let upper = b.sub(zm1, residual);
    let _ = b.add_range_bits::<Val>(upper, DIFF_BITS).expect("residual < Z");
    // res = K_num · invZ (fixed-point cardinality, scale 2^β). invZ already has a
    // bus creator from `z_invz` above; using it as rhs here is fine.
    let res_expr = b.mul(knum_c, invz_w);

    // ── Stage 5: release policy → answer ──
    match release {
        ReleasePolicy::Identity => {
            b.connect(res_expr, answer_pi);
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.alloc_const(Challenge::from_u64(t), "theta");
            let fl = flag.unwrap();
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            // chosen = fl·(res−θ) + (1−fl)·(θ−res−1) ≥ 0  ⇔  fl = [res ≥ θ].
            let res_minus_t = b.sub(res_expr, theta);
            let tm = b.sub(theta, res_expr);
            let t_minus_res_m1 = b.sub(tm, one);
            let nf = b.sub(one, fl);
            let a = b.mul(fl, res_minus_t);
            let nft = b.mul(nf, t_minus_res_m1);
            let chosen = b.add(a, nft);
            let _ = b.add_range_bits::<Val>(chosen, DIFF_BITS).expect("chosen >= 0");
            let released = b.mul(fl, res_expr);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build hll decode circuit");

    // ─── Pack public + private values ────────────────────────────────────
    let commit_packed =
        pack_commit_to_challenge(&crate::commitment::CountMinCommit(commit.0));
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_u64(answer));

    let mut private_inputs: Vec<Challenge> = pack_cells(&state);
    // sel[r][j]: one-hot at j == reg_r.
    for r in 0..m {
        let rv = state.registers[r] as usize;
        for j in 0..=MU_MAX {
            private_inputs.push(if j == rv { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    // invZ
    private_inputs.push(Challenge::from_u64(invz));
    // flag (threshold only).
    if flag.is_some() {
        let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
        private_inputs.push(if res >= t { Challenge::ONE } else { Challenge::ZERO });
    }

    // ─── Run + prove ─────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run hll decode circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false), range_preprocessor::<Val>()];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (hll decode)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_range_table::<4>();
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove hll decode");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify hll decode");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    DecodeProof { output: RecursionOutput(proof, Rc::new(circuit_prover_data)), answer }
}

/// Register-value range for the omc-form decode (`reg ≤ MU_MAX`, one-hot-indexed).
const REG_BITS: usize = 6;

/// HyperLogLog cardinality decode against the **omc** committed state: the `m`
/// registers as a `d=1, w=m` array committed via [`commit_hll_omc`] (=
/// `commit_countmin`, one Val per register, 4 registers per Challenge) — the
/// state the deployed `prove_hll_omc` update recommits. Same fixed-point
/// estimator as [`prove_hll_decode`]; only the state binding differs (so this
/// one chains to the omc update, which `prove_hll_decode`'s `[r,0,0,1]` /
/// `commit_hll_state` binding does not).
pub fn prove_hll_decode_omc(params: HllDecodeParams, regs: Vec<u64>, _query: u64) -> DecodeProof {
    params.validate();
    let HllDecodeParams { b: blog2, release } = params;
    let m = 1usize << blog2;
    assert_eq!(regs.len(), m, "state shape must match params (m = 2^b)");
    assert_eq!(m % 4, 0, "m = 2^b must be a multiple of 4 (b >= 2)");
    assert!(regs.iter().all(|&r| (r as usize) <= MU_MAX), "register exceeds MU_MAX; raise MU_MAX");

    // ─── Native decode ───────────────────────────────────────────────────
    let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
    let commit = commit_hll_omc(&regs, blog2);
    let z = fixed_z(&regs32);
    let invz = inv_z(z);
    let knum = k_num(m);
    let res = knum * invz;
    let answer = release.apply(res);

    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);

    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let answer_pi = b.alloc_public_input("answer");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let pow: Vec<ExprId> = (0..=MU_MAX)
        .map(|j| b.alloc_const(Challenge::from_u64(pow2neg(j)), "pow2neg"))
        .collect();
    let idx: Vec<ExprId> =
        (0..=MU_MAX).map(|j| b.alloc_const(Challenge::from_u64(j as u64), "idx")).collect();
    let knum_c = b.alloc_const(Challenge::from_u64(knum), "k_num");
    let target = b.alloc_const(Challenge::from_u64(recip_target()), "recip_target");

    // Private witnesses: m/4 packed challenges (4 registers each).
    let n_cells = m / 4;
    let cells_packed: Vec<ExprId> =
        (0..n_cells).map(|_| b.alloc_private_input("cell_packed")).collect();
    let sel: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..=MU_MAX).map(|_| b.alloc_private_input("sel")).collect())
        .collect();
    let invz_w = b.alloc_private_input("invz");
    let flag = if matches!(release, ReleasePolicy::Threshold(_)) {
        Some(b.alloc_private_input("flag"))
    } else {
        None
    };

    // ── Stage 1: open the committed omc register state ──
    let digest = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, true)
        .expect("hash cells");
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }
    // Extract the m registers (4 per challenge); range-check each (bus-safe
    // consumption, the pattern that balances multi-coeff challenges).
    let mut regs_expr: Vec<ExprId> = Vec::with_capacity(m);
    for &p in &cells_packed {
        let c = b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose cell");
        for k in 0..4 {
            let _ = b.add_range_bits::<Val>(c[k], REG_BITS).expect("reg range");
            regs_expr.push(c[k]);
        }
    }

    // ── Stage 2 + 3: per-register one-hot Pow2Neg selector → Z ──
    let mut z_expr = zero;
    for r in 0..m {
        let row = &sel[r];
        let mut sum = zero;
        let mut idx_acc = zero;
        let mut term = zero;
        for j in 0..=MU_MAX {
            let sm1 = b.sub(row[j], one);
            let bchk = b.mul(row[j], sm1);
            b.connect(bchk, zero);
            sum = b.add(sum, row[j]);
            let it = b.mul(idx[j], row[j]);
            idx_acc = b.add(idx_acc, it);
            let pt = b.mul(row[j], pow[j]);
            term = b.add(term, pt);
        }
        b.connect(sum, one);
        let reg_lhs = b.mul(regs_expr[r], one);
        b.connect(idx_acc, reg_lhs);
        z_expr = b.add(z_expr, term);
    }

    // ── Stage 4: witnessed reciprocal invZ, residual range-check, res = K·invZ ──
    let z_invz = b.mul(invz_w, z_expr);
    let residual = b.sub(z_invz, target);
    let _ = b.add_range_bits::<Val>(residual, DIFF_BITS).expect("Z·invZ − T >= 0");
    let zm1 = b.sub(z_expr, one);
    let upper = b.sub(zm1, residual);
    let _ = b.add_range_bits::<Val>(upper, DIFF_BITS).expect("residual < Z");
    let res_expr = b.mul(knum_c, invz_w);

    // ── Stage 5: release policy → answer ──
    match release {
        ReleasePolicy::Identity => {
            b.connect(res_expr, answer_pi);
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.alloc_const(Challenge::from_u64(t), "theta");
            let fl = flag.unwrap();
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            let res_minus_t = b.sub(res_expr, theta);
            let tm = b.sub(theta, res_expr);
            let t_minus_res_m1 = b.sub(tm, one);
            let nf = b.sub(one, fl);
            let a = b.mul(fl, res_minus_t);
            let nft = b.mul(nf, t_minus_res_m1);
            let chosen = b.add(a, nft);
            let _ = b.add_range_bits::<Val>(chosen, DIFF_BITS).expect("chosen >= 0");
            let released = b.mul(fl, res_expr);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build hll omc decode circuit");

    let commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(commit));
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_u64(answer));

    // pack the m registers 4-per-challenge (commit_countmin / commit_hll_omc form).
    let mut private_inputs: Vec<Challenge> = regs
        .chunks(4)
        .map(|ch| {
            let coeffs: Vec<Val> = ch.iter().map(|&r| Val::from_u32(r as u32)).collect();
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect();
    for r in 0..m {
        let rv = regs[r] as usize;
        for j in 0..=MU_MAX {
            private_inputs.push(if j == rv { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    private_inputs.push(Challenge::from_u64(invz));
    if flag.is_some() {
        let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
        private_inputs.push(if res >= t { Challenge::ONE } else { Challenge::ZERO });
    }

    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run hll omc decode circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false), range_preprocessor::<Val>()];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (hll omc decode)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_range_table::<4>();
    let __t_p = std::time::Instant::now();
    let proof =
        prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove hll omc decode");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify hll omc decode");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    DecodeProof { output: RecursionOutput(proof, Rc::new(circuit_prover_data)), answer }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::hll_final_full::{HllFullParams, HllFullState, HllFullUpdate, apply_update};

    fn state() -> HllFullState {
        let params = HllFullParams { b: 4, batch: 2 };
        let mut s = HllFullState::empty(params);
        for k in 0..40u64 {
            apply_update(&mut s, &HllFullUpdate::real(k.wrapping_mul(0x9E37_79B9)));
        }
        s
    }

    /// The omc-form decode binds `commit_hll_omc` (so it chains to the deployed
    /// `prove_hll_omc` update), matches the native cardinality, and self-verifies.
    #[test]
    fn hll_omc_decode_chains_and_selfverifies() {
        let blog2 = 2usize; // m = 4
        let regs: Vec<u64> = vec![3, 1, 4, 2];
        let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
        let expected = k_num(1 << blog2) * inv_z(fixed_z(&regs32));
        // Identity release.
        let p = HllDecodeParams { b: blog2, release: ReleasePolicy::Identity };
        let proof = prove_hll_decode_omc(p, regs.clone(), 0);
        assert_eq!(proof.answer, expected, "omc decode must match native cardinality");
        // Threshold release: suppress above expected, pass at/below.
        let p_hi = HllDecodeParams { b: blog2, release: ReleasePolicy::Threshold(expected + 1) };
        assert_eq!(prove_hll_decode_omc(p_hi, regs.clone(), 0).answer, 0);
        let p_lo = HllDecodeParams { b: blog2, release: ReleasePolicy::Threshold(expected) };
        assert_eq!(prove_hll_decode_omc(p_lo, regs, 0).answer, expected);
    }

    #[test]
    fn pow2neg_table() {
        assert_eq!(pow2neg(0), 1 << BETA);
        assert_eq!(pow2neg(1), 1 << (BETA - 1));
        assert_eq!(pow2neg(BETA), 1);
        // far past β underflows to 0.
        assert_eq!(pow2neg(MU_MAX), 0);
    }

    #[test]
    fn reciprocal_residual_in_range() {
        let s = state();
        let z = fixed_z(&s.registers);
        let invz = inv_z(z);
        let t = recip_target();
        let resid = z * invz - t;
        assert!(resid < z, "Z·invZ − T must lie in [0, Z); got resid={resid}, Z={z}");
    }

    #[test]
    fn hll_decode_round_trip() {
        let s = state();
        let p = HllDecodeParams { b: 4, release: ReleasePolicy::Identity };
        let proof = prove_hll_decode(p, s.clone(), 0);
        assert_eq!(proof.answer, fixed_res(16, &s.registers), "answer == native fixed-point res");
    }

    #[test]
    fn fixed_res_tracks_float_estimate() {
        // The fixed-point res / 2^β should be close to the float estimate.
        let s = state();
        let res = fixed_res(16, &s.registers) as f64 / (1u64 << BETA) as f64;
        let est = s.estimate();
        let rel = (res - est).abs() / est.max(1.0);
        assert!(rel < 0.10, "fixed-point res {res} vs float estimate {est} (rel err {rel})");
    }

    #[test]
    fn hll_decode_threshold_passes() {
        let s = state();
        let res = fixed_res(16, &s.registers);
        // θ below res ⇒ released unchanged.
        let p = HllDecodeParams { b: 4, release: ReleasePolicy::Threshold(1) };
        let proof = prove_hll_decode(p, s, 0);
        assert_eq!(proof.answer, res, "res >= θ ⇒ released res");
    }

    #[test]
    fn hll_decode_threshold_suppresses() {
        let s = state();
        let res = fixed_res(16, &s.registers);
        // θ above res but within the DIFF_BITS range-check window (so the gated
        // `θ − res − 1` diff stays sound) ⇒ suppressed to 0.
        let theta = 100_000u64;
        assert!(res < theta && theta < (1u64 << DIFF_BITS), "test precondition");
        let p = HllDecodeParams { b: 4, release: ReleasePolicy::Threshold(theta) };
        let proof = prove_hll_decode(p, s, 0);
        assert_eq!(proof.answer, 0, "res < θ ⇒ released 0");
    }
}
