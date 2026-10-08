//! HyperLogLog **cardinality** decode circuit (E3, plonky3/STARK), estimator mode.
//!
//! Implements the paper's HLL query relation (zk1.tex app:hll, "HLL estimator
//! mode") in **fixed-point** arithmetic on the STARK backend, mirroring the
//! plonky2 `decode::hyperloglog` relation. Unlike the previous integer
//! harmonic surrogate `Σ 2^(B−reg)`, this certifies the fixed-point cardinality
//!
//! ```text
//!   Z   = Σ_b Pow2Neg[S_t[b]]            (fixed-point harmonic sum, scale 2^β)
//!   res = floor(K_num · 2^(2β) / Z)      (fixed-point cardinality, scale 2^β)
//!   ans = release(res)
//! ```
//!
//! where `Pow2Neg[x] = round(2^β / 2^x)` is a **public** fixed-point lookup
//! table (identically 0 past `x = β + 1`) and `K_num = round(α_s · s²)` is a
//! public integer constant. The division is certified by a **witnessed
//! quotient**: `res` and the remainder `rem` are supplied in range-checked
//! base-2^11 limbs and the integer identity `res·Z + rem = N`
//! (`N = K_num·2^(2β)`, up to 44 bits at `b = 14`) is enforced digit-by-digit
//! with range-checked carries, so every in-field term stays far below the
//! BabyBear modulus (see the budget below).
//!
//! Reusing the `hll_final_full` commit layout and the `countmin` decode harness
//! (Poseidon2 + Recompose, no Permute — decode does not sort).
//!
//! Stages:
//! 1. Re-hash the `m` registers → bind to the committed digest (the `Θ(s)` cost).
//! 2. Per register: a one-hot selector over `[0, SEL_MAX]` picks `Pow2Neg[reg]`,
//!    with a boolean **catch-all** for `reg > SEL_MAX` (weight 0 — the exact
//!    table value there); the selected index (or the catch-all's gated range
//!    check) binds the selector to the register value.
//! 3. Sum the picked fixed-point weights → `Z`.
//! 4. Division certificate: witness `res`/`rem` in limbs, enforce
//!    `res·Z + rem = N` over ℤ (base-2^11 digits + carries) and `rem ∈ [0, Z)`.
//! 5. Apply the release policy and bind the released value to the public answer.
//!
//! There is no query-key public input for cardinality: the answer depends only
//! on the committed state, so PIs are `(committed-state, answer)`.
//!
//! ### Field-size / soundness budget (BabyBear, p ≈ 2^30.9), b ≤ 14
//! Every range-checked value and every product fed to a range check must stay
//! `< p`. With `BETA = 8` and `m = 2^b ≤ 2^14`:
//! * `Z ≤ m·2^β ≤ 2^22` — by construction (one-hot/catch-all selected public
//!   weights, each `≤ 2^β`), no range check needed;
//! * `N = K_num·2^(2β) < 2^44` with `K_num = round(α_s·s²) < 2^28`;
//! * `res < 2^RES_BITS = 2^29`, pinned by its three range-checked limbs
//!   `(r0, r1) ∈ [0, 2^11)`, `r2 ∈ [0, 2^7)`;
//! * `Z` is re-decomposed as `z1·2^11 + z0` (`z0 ∈ [0, 2^11)`,
//!   `z1 ∈ [0, 2^12)` — covers `Z = 2^22` exactly), `rem = m1·2^11 + m0`
//!   with `Z − 1 − rem` range-checked to `Z_BITS = 22` bits (⇒ `rem < Z`);
//! * convolution digits `c_k = Σ_{i+j=k} r_i·z_j < 2^24` and digit equations
//!   `c_k + rem_k + γ_{k-1} = n_k + γ_k·2^11` with carries `γ_k ∈ [0, 2^14)`:
//!   every term `< 2^26 ≪ p`, so each field equation is an integer equation
//!   and telescoping gives `res·Z + rem = N` over ℤ — with `rem ∈ [0, Z)`
//!   this pins `res = floor(N/Z)` **uniquely** (all witnesses range-checked;
//!   nothing relies on an implicitly-small witness);
//! * release: `res < 2^29` (limb-pinned), threshold window
//!   `DIFF_BITS = 29` is sound since `p − 2^29 > 2^29` (a wrapped "negative"
//!   difference always lands above the window).
//!
//! The bounds above leave slack on purpose: `add_range_bits` with a
//! non-byte-aligned width checks its shifted top byte, which admits values a
//! factor `≤ (1 + 2^−r)` past `2^n_bits` (`r` = top-byte bits). Every budget
//! line survives that looseness with room to spare (terms stay `< 2^26·1.13`,
//! the digit equations remain integer equations, and `res·Z + rem = N` pins
//! the same unique `res`).
//!
//! Completeness cap: `res < 2^29` ⇔ estimate `< 2^(29−β) = 2^21` — ample for
//! the `n ≤ 2^20` experiment scale (asserted natively with a clear message).
//! Registers may take any value `≤ MU_MAX = 63` (the update leaves produce
//! `ρ = 1 + trailing_zeros ≤ 32`); values past `SEL_MAX = β + 1` carry weight
//! 0 via the catch-all, so no register value reachable from the updates can
//! make the decode unprovable.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4, poseidon2_preprocessor,
        range_air_builders, range_preprocessor, recompose_air_builders, recompose_preprocessor,
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
use crate::sketch::bind::{self, Binding};
use crate::sketch::hll_omc::commit_hll_omc;

const LOG_FINAL_POLY_LEN: usize = 6;

/// Fixed-point precision (mantissa bits) for the estimator. Public metadata.
/// The answer is the estimate at scale `2^β` (`ans ≈ E·2^β`).
pub const BETA: usize = 8;

/// Register-value bits. The omc form range-checks each opened register to
/// `REG_BITS`; the full-state form bounds registers through the selector
/// alone (one-hot pins `reg ≤ SEL_MAX`; the catch-all's gated check pins
/// `reg ∈ [SEL_MAX+1, SEL_MAX+2^REG_BITS]`, where the weight is exactly 0
/// either way). It also windows the gated catch-all check.
const REG_BITS: usize = 6;

/// Max supported register value (`2^REG_BITS − 1`, native assert). The update
/// leaves produce `ρ = 1 + trailing_zeros(digest) ≤ 32`, comfortably inside.
pub const MU_MAX: usize = (1 << REG_BITS) - 1;

/// Largest register value with its own one-hot lane. `Pow2Neg[x] = 0` for all
/// `x > SEL_MAX` (`round(2^β/2^x)` underflows), so registers past `SEL_MAX`
/// share a single catch-all selector with weight 0.
pub const SEL_MAX: usize = BETA + 1;

/// Max register bits: `Z ≤ m·2^β = 2^(b+β)` must fit `Z_BITS` (see budget).
pub const MAX_B: usize = 14;

/// Bits covering the harmonic sum: `Z ≤ 2^(MAX_B+BETA) = 2^22`.
const Z_BITS: usize = MAX_B + BETA;

/// Limb width for the division certificate (base-2^11 digits).
const LIMB_BITS: usize = 11;

/// Cap on the witnessed quotient: `res = floor(N/Z) < 2^RES_BITS`. Bounded by
/// the threshold-compare window (`DIFF_BITS ≤ 29` on BabyBear); caps the
/// provable estimate at `2^(RES_BITS−β) = 2^21`.
const RES_BITS: usize = 29;

/// Bits in the top `res` limb (`res = r2·2^22 + r1·2^11 + r0`).
const RES_TOP_BITS: usize = RES_BITS - 2 * LIMB_BITS;

/// Bits in the top `Z` limb (`Z = z1·2^11 + z0`); one extra bit so
/// `Z = 2^22` (the all-zeros state) is representable.
const Z_TOP_BITS: usize = Z_BITS - LIMB_BITS + 1;

/// Range window for the division-certificate carries `γ_k` (honest carries
/// stay `< 2^13 + 4`; see the module budget).
const CARRY_BITS: usize = 14;

/// Range-check window for the release-policy threshold compare. Must cover
/// `res` and `θ` (both `< 2^29`) and stay sound against field wraparound:
/// `p − 2^DIFF_BITS > 2^DIFF_BITS` holds for `DIFF_BITS = 29` on BabyBear.
const DIFF_BITS: usize = 29;

#[derive(Copy, Clone, Debug)]
pub struct HllDecodeParams {
    /// Register-index bits; `m = 2^b` registers.
    pub b: usize,
    pub release: ReleasePolicy,
}

impl HllDecodeParams {
    pub fn validate(&self) {
        assert!(
            self.b >= 2 && self.b <= MAX_B,
            "b in [2,{MAX_B}] (m = 2^b registers), got {}",
            self.b
        );
        if let ReleasePolicy::Threshold(t) = self.release {
            assert!(t < 1u64 << DIFF_BITS, "threshold θ = {t} must be < 2^{DIFF_BITS}");
        }
    }
}

/// Public fixed-point lookup table `Pow2Neg[x] = round(2^β / 2^x)`
/// (round-half-up). Entry 0 is `2^β`; entries past `SEL_MAX = β + 1`
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

/// Public integer constant `K_num = round(α_s · s²)` (`s = m`).
pub fn k_num(m: usize) -> u64 {
    (alpha(m) * (m as f64) * (m as f64)).round() as u64
}

/// Division numerator `N = K_num · 2^(2β)` (`res = floor(N/Z)`). Up to 44 bits
/// at `b = 14` — a native constant only; in-circuit it appears via its
/// base-2^11 digits in the limb certificate.
fn big_n(m: usize) -> u64 {
    let n = k_num(m) << (2 * BETA);
    assert!(n < 1u64 << (4 * LIMB_BITS), "N must fit 4 base-2^11 digits");
    n
}

/// Base-2^11 digits of `N` (little-endian, 4 digits).
fn n_digits(m: usize) -> [u64; 4] {
    let n = big_n(m);
    let mask = (1u64 << LIMB_BITS) - 1;
    std::array::from_fn(|k| (n >> (k * LIMB_BITS)) & mask)
}

/// Native fixed-point harmonic sum `Z = Σ_b Pow2Neg[reg_b]`.
pub fn fixed_z(regs: &[u32]) -> u64 {
    regs.iter().map(|&r| pow2neg(r as usize)).sum()
}

/// Native fixed-point cardinality `res = floor(K_num·2^(2β) / Z)` (scale `2^β`).
pub fn fixed_res(m: usize, regs: &[u32]) -> u64 {
    let z = fixed_z(regs);
    assert!(z > 0, "Z = 0: every register exceeds the Pow2Neg support");
    big_n(m) / z
}

/// Witness limbs for the division certificate, in private-input order:
/// `[r0, r1, r2, z0, z1, m0, m1, g0, g1, g2]` (quotient, Z, remainder limbs,
/// then digit-equation carries). Panics (with a clear message) when the state
/// falls outside the fixed-point budget — `Z = 0` or `res ≥ 2^RES_BITS`.
fn div_limbs(m: usize, z: u64) -> [u64; 10] {
    assert!(z > 0, "Z = 0: every register exceeds the Pow2Neg support");
    let n = big_n(m);
    let res = n / z;
    let rem = n % z;
    assert!(
        res < 1u64 << RES_BITS,
        "fixed-point cardinality {res} = floor(N/Z) exceeds 2^{RES_BITS} \
         (estimate ≥ 2^{}): state too large for the BabyBear budget",
        RES_BITS - BETA
    );
    let mask = (1u64 << LIMB_BITS) - 1;
    let (r0, r1, r2) = (res & mask, (res >> LIMB_BITS) & mask, res >> (2 * LIMB_BITS));
    let (z0, z1) = (z & mask, z >> LIMB_BITS);
    let (m0, m1) = (rem & mask, rem >> LIMB_BITS);
    let nd = n_digits(m);
    // Base-2^11 long-multiplication digits and their canonical carries; each
    // subtraction is exact and non-negative because res·Z + rem = N digit-by-digit.
    let c0 = r0 * z0;
    let g0 = (c0 + m0 - nd[0]) >> LIMB_BITS;
    let c1 = r0 * z1 + r1 * z0;
    let g1 = (c1 + m1 + g0 - nd[1]) >> LIMB_BITS;
    let c2 = r1 * z1 + r2 * z0;
    let g2 = (c2 + g1 - nd[2]) >> LIMB_BITS;
    debug_assert_eq!(c0 + m0 - nd[0], g0 << LIMB_BITS, "digit 0 must close");
    debug_assert_eq!(c1 + m1 + g0 - nd[1], g1 << LIMB_BITS, "digit 1 must close");
    debug_assert_eq!(c2 + g1 - nd[2], g2 << LIMB_BITS, "digit 2 must close");
    debug_assert_eq!(r2 * z1 + g2, nd[3], "digit 3 must close");
    [r0, r1, r2, z0, z1, m0, m1, g0, g1, g2]
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

// ───────────────────────── shared estimator subcircuit ─────────────────────

/// Private-witness wires of the estimator, allocated in the same order
/// [`estimator_witness_values`] pushes values: per register the
/// `SEL_MAX + 1` one-hot lanes then the catch-all flag, then the 10 division
/// limbs.
struct EstimatorWires {
    /// `[m][SEL_MAX + 2]`: one-hot over `0..=SEL_MAX`, catch-all last.
    sel: Vec<Vec<ExprId>>,
    /// `[r0, r1, r2, z0, z1, m0, m1, g0, g1, g2]` (see [`div_limbs`]).
    limbs: [ExprId; 10],
}

fn alloc_estimator_wires(b: &mut CircuitBuilder<Challenge>, m: usize) -> EstimatorWires {
    let sel = (0..m)
        .map(|_| (0..SEL_MAX + 2).map(|_| b.alloc_private_input("sel")).collect())
        .collect();
    let limbs = std::array::from_fn(|_| b.alloc_private_input("div_limb"));
    EstimatorWires { sel, limbs }
}

/// Mirror of [`alloc_estimator_wires`]: the private-input values, in
/// allocation order.
fn estimator_witness_values(m: usize, regs: &[u32]) -> Vec<Challenge> {
    assert_eq!(regs.len(), m);
    let mut vals = Vec::with_capacity(m * (SEL_MAX + 2) + 10);
    for &rv in regs {
        let rv = rv as usize;
        for j in 0..=SEL_MAX {
            vals.push(if j == rv { Challenge::ONE } else { Challenge::ZERO });
        }
        vals.push(if rv > SEL_MAX { Challenge::ONE } else { Challenge::ZERO });
    }
    for l in div_limbs(m, fixed_z(regs)) {
        vals.push(Challenge::from_u64(l));
    }
    vals
}

/// Constrain the fixed-point estimator over the opened register coeffs and
/// return `res` (the certified `floor(N/Z)`); see the module budget for why
/// every product/range-checked value stays below the field modulus.
///
/// Bus discipline: every private witness and every register coeff flows
/// through an ALU op as the LHS (first operand) before being consumed by a
/// `connect`/range check, so it gets a WitnessChecks bus creator (the harness
/// panics at prove time otherwise).
fn constrain_estimator(
    b: &mut CircuitBuilder<Challenge>,
    m: usize,
    regs: &[ExprId],
    wires: &EstimatorWires,
    one: ExprId,
    zero: ExprId,
) -> ExprId {
    assert_eq!(regs.len(), m);
    // Public constants: Pow2Neg table, selector indices, catch-all cut,
    // limb weights and the base-2^11 digits of N.
    let pow: Vec<ExprId> = (0..=SEL_MAX)
        .map(|j| b.alloc_const(Challenge::from_u64(pow2neg(j)), "pow2neg"))
        .collect();
    let idx: Vec<ExprId> =
        (0..=SEL_MAX).map(|j| b.alloc_const(Challenge::from_u64(j as u64), "idx")).collect();
    let sel_cut = b.alloc_const(Challenge::from_u64((SEL_MAX + 1) as u64), "sel_cut");
    let p_limb = b.alloc_const(Challenge::from_u64(1u64 << LIMB_BITS), "2^11");
    let p_limb2 = b.alloc_const(Challenge::from_u64(1u64 << (2 * LIMB_BITS)), "2^22");
    let nd: Vec<ExprId> = n_digits(m)
        .iter()
        .map(|&d| b.alloc_const(Challenge::from_u64(d), "n_digit"))
        .collect();

    // ── per-register one-hot / catch-all Pow2Neg selector → Z ──
    let mut z_expr = zero;
    for r in 0..m {
        let row = &wires.sel[r];
        // The register coeff goes FIRST (lhs) so it gets a bus creator
        // covering the `connect`/product consumes below.
        let reg_lhs = b.mul(regs[r], one);
        // Lane j = 0 seeds the accumulators (its idx term is idx[0]·sel = 0).
        let mut sum = row[0];
        let mut idx_acc = zero;
        for j in 0..=SEL_MAX {
            let sm1 = b.sub(row[j], one);
            let bchk = b.mul(row[j], sm1);
            b.connect(bchk, zero);
            if j > 0 {
                sum = b.add(sum, row[j]);
                idx_acc = b.mul_add(row[j], idx[j], idx_acc);
            }
            // Selected weight accumulates straight into Z.
            z_expr = b.mul_add(row[j], pow[j], z_expr);
        }
        let big = row[SEL_MAX + 1];
        let bm1 = b.sub(big, one);
        let bchk = b.mul(big, bm1);
        b.connect(bchk, zero);
        sum = b.add(sum, big);
        b.connect(sum, one);
        // Selector↔register binding: Σ j·sel_j + big·reg == reg, i.e.
        // (1−big)·reg = Σ j·sel_j — with big = 0 the one-hot lane pins
        // reg = j exactly; with big = 1 it is vacuous and the gated range
        // check below pins reg ∈ [SEL_MAX+1, SEL_MAX+2^REG_BITS] instead
        // (weight 0 = Pow2Neg[reg] on that whole range).
        idx_acc = b.mul_add(big, reg_lhs, idx_acc);
        b.connect(idx_acc, reg_lhs);
        // Gated catch-all range check: big·(reg − (SEL_MAX+1)) ∈ [0, 2^REG_BITS).
        let over = b.sub(reg_lhs, sel_cut);
        let gated = b.mul(big, over);
        let _ = b.add_range_bits::<Val>(gated, REG_BITS).expect("catch-all register range");
    }

    // ── division certificate: res·Z + rem = N over ℤ, rem ∈ [0, Z) ──
    // Materialize each limb witness as an ALU output (bus creator) and
    // range-check it.
    let [r0, r1, r2, z0, z1, m0, m1, g0, g1, g2] = wires.limbs;
    let mut mk = |b: &mut CircuitBuilder<Challenge>, w: ExprId, bits: usize| {
        let v = b.mul(w, one);
        let _ = b.add_range_bits::<Val>(v, bits).expect("limb range");
        v
    };
    let r0v = mk(b, r0, LIMB_BITS);
    let r1v = mk(b, r1, LIMB_BITS);
    let r2v = mk(b, r2, RES_TOP_BITS);
    let z0v = mk(b, z0, LIMB_BITS);
    let z1v = mk(b, z1, Z_TOP_BITS);
    let m0v = mk(b, m0, LIMB_BITS);
    let m1v = mk(b, m1, LIMB_BITS);
    let g0v = mk(b, g0, CARRY_BITS);
    let g1v = mk(b, g1, CARRY_BITS);
    let g2v = mk(b, g2, CARRY_BITS);

    // Bind the Z limbs: z1·2^11 + z0 == Z (unique canonical digits).
    let z1s = b.mul(z1v, p_limb);
    let z_rec = b.add(z1s, z0v);
    b.connect(z_rec, z_expr);

    // rem = m1·2^11 + m0 with rem < Z: range-check Z − 1 − rem ≥ 0.
    let m1s = b.mul(m1v, p_limb);
    let rem = b.add(m1s, m0v);
    let zm1 = b.sub(z_expr, one);
    let upper = b.sub(zm1, rem);
    let _ = b.add_range_bits::<Val>(upper, Z_BITS).expect("rem < Z");

    // Convolution digits of res·Z in base 2^11 (all < 2^24, field-exact).
    let c0 = b.mul(r0v, z0v);
    let t01 = b.mul(r0v, z1v);
    let t10 = b.mul(r1v, z0v);
    let c1 = b.add(t01, t10);
    let t11 = b.mul(r1v, z1v);
    let t20 = b.mul(r2v, z0v);
    let c2 = b.add(t11, t20);
    let c3 = b.mul(r2v, z1v);

    // Digit equations with carries: telescoping yields res·Z + rem = N over ℤ.
    //   c0 + m0      = n0 + γ0·2^11
    //   c1 + m1 + γ0 = n1 + γ1·2^11
    //   c2      + γ1 = n2 + γ2·2^11
    //   c3      + γ2 = n3
    let l0 = b.add(c0, m0v);
    let g0s = b.mul(g0v, p_limb);
    let r0d = b.add(nd[0], g0s);
    b.connect(l0, r0d);
    let l1a = b.add(c1, m1v);
    let l1 = b.add(l1a, g0v);
    let g1s = b.mul(g1v, p_limb);
    let r1d = b.add(nd[1], g1s);
    b.connect(l1, r1d);
    let l2 = b.add(c2, g1v);
    let g2s = b.mul(g2v, p_limb);
    let r2d = b.add(nd[2], g2s);
    b.connect(l2, r2d);
    let l3 = b.add(c3, g2v);
    b.connect(l3, nd[3]);

    // res = r2·2^22 + r1·2^11 + r0 (< 2^29, limb-pinned).
    let r1s = b.mul(r1v, p_limb);
    let r2s = b.mul(r2v, p_limb2);
    let res_lo = b.add(r0v, r1s);
    b.add(res_lo, r2s)
}

/// Allocate the release policy's private witness (the threshold comparison
/// flag; nothing for Identity). Mirrored by [`release_flag_value`].
fn alloc_release_flag(
    b: &mut CircuitBuilder<Challenge>,
    release: ReleasePolicy,
) -> Option<ExprId> {
    matches!(release, ReleasePolicy::Threshold(_)).then(|| b.alloc_private_input("flag"))
}

/// Mirror of [`alloc_release_flag`]: the flag value `[res ≥ θ]` for the
/// threshold policy, nothing for Identity.
fn release_flag_value(release: ReleasePolicy, res: u64) -> Option<Challenge> {
    match release {
        ReleasePolicy::Identity => None,
        ReleasePolicy::Threshold(t) => {
            Some(if res >= t { Challenge::ONE } else { Challenge::ZERO })
        }
    }
}

/// Constrain `answer_pi == release(res)` (shared release-policy tail).
fn constrain_release(
    b: &mut CircuitBuilder<Challenge>,
    release: ReleasePolicy,
    res_expr: ExprId,
    answer_pi: ExprId,
    flag: Option<ExprId>,
    one: ExprId,
    zero: ExprId,
) {
    match release {
        ReleasePolicy::Identity => {
            b.connect(res_expr, answer_pi);
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.alloc_const(Challenge::from_u64(t), "theta");
            let fl = flag.expect("threshold flag");
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
}

/// Prove a HyperLogLog cardinality (fixed-point estimator) decode. Returns a
/// [`DecodeProof`]; the prover self-verifies and records the
/// witness/prove/verify split via [`crate::recursion::recursive::timing`].
///
/// `_query` is unused for cardinality (the answer depends only on the committed
/// state) but kept in the signature to mirror the other decode families.
pub fn prove_hll_decode(params: HllDecodeParams, state: HllFullState, _query: u64) -> DecodeProof {
    prove_hll_decode_with(params, state, _query, bind::default_binding())
}

/// [`prove_hll_decode`] with an explicit [`Binding`] (see
/// [`prove_hll_decode_omc_with`] for what each mode changes).
pub fn prove_hll_decode_with(
    params: HllDecodeParams,
    state: HllFullState,
    _query: u64,
    binding: Binding,
) -> DecodeProof {
    build_hll_decode(params, &state, binding).prove()
}

/// A built HLL decode circuit together with its witness and registered prover.
struct HllDecodeCircuit {
    circuit: p3_circuit::Circuit<Challenge>,
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    answer: u64,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: CircuitProverData<ConfigWithFriParams>,
    trace_rows: u64,
}

impl HllDecodeCircuit {
    fn run(&self) -> p3_circuit::tables::Traces<Challenge> {
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&self.public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&self.private_inputs).expect("set_private_inputs");
        runner.run().expect("run hll decode circuit")
    }

    fn prove(self) -> DecodeProof {
        let __t_w = std::time::Instant::now();
        let traces = self.run();
        let __witness = __t_w.elapsed();
        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove hll decode");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover.verify_all_tables(&proof).expect("self-verify hll decode");
        crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
            witness: __witness,
            prove: __prove,
            verify: __t_v.elapsed(),
            trace_rows: self.trace_rows,
        });
        DecodeProof { output: RecursionOutput(proof, Rc::new(self.circuit_prover_data)), answer: self.answer }
    }

    #[cfg(test)]
    fn prove_traces(
        &self,
        traces: &p3_circuit::tables::Traces<Challenge>,
    ) -> Result<p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>, String> {
        let proof = self
            .prover
            .prove_all_tables(traces, &self.circuit_prover_data)
            .map_err(|e| format!("prove: {e:?}"))?;
        self.prover.verify_all_tables(&proof).map_err(|e| format!("verify: {e:?}"))?;
        Ok(proof)
    }

    /// This circuit's VK (preprocessed commitment + proof metadata), read off
    /// a proof of its own honest witness.
    fn derive_vk(&self) -> crate::decode::DecodeVk {
        let proof = self
            .prover
            .prove_all_tables(&self.run(), &self.circuit_prover_data)
            .expect("prove hll decode (VK derivation)");
        self.prover.verify_all_tables(&proof).expect("self-verify hll decode (VK derivation)");
        crate::decode::DecodeVk {
            commitment: crate::recursion::recursive::expose_forest::vk_pin_values(&proof),
            shape: Some(crate::recursion::recursive::root_vk::bound_proof_shape(&proof)),
        }
    }
}

/// The trusted VK of the HyperLogLog cardinality decode circuit over the
/// `omc` register state ([`prove_hll_decode_omc`]) at `params` and `binding`,
/// derived from public parameters only: built over the all-zero registers
/// (witnesses, not circuit structure), proved once, and its preprocessed
/// commitment and metadata read off. A verifier pins every HyperLogLog query
/// proof to it with [`crate::decode::verify_decode_proof`].
pub fn hll_omc_decode_vk(params: HllDecodeParams, binding: Binding) -> crate::decode::DecodeVk {
    build_hll_decode_omc(params, &vec![0u64; 1usize << params.b], binding).derive_vk()
}

/// Prover data + registered prover for a built HLL decode circuit (Poseidon2,
/// Recompose, Range, and Expose when `expose`).
fn finish_hll_decode(
    circuit: p3_circuit::Circuit<Challenge>,
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    answer: u64,
    expose: bool,
) -> HllDecodeCircuit {
    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false), range_preprocessor::<Val>()];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    if expose {
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
    if expose {
        prover.register_expose_table::<4>();
    }
    HllDecodeCircuit {
        circuit,
        public_inputs,
        private_inputs,
        answer,
        prover,
        circuit_prover_data,
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    }
}

fn build_hll_decode(params: HllDecodeParams, state: &HllFullState, binding: Binding) -> HllDecodeCircuit {
    params.validate();
    let bound = binding.is_bound();
    let HllDecodeParams { b: blog2, release } = params;
    let m = 1usize << blog2;
    assert_eq!(state.registers.len(), m, "state shape must match params (m = 2^b)");
    assert!(
        state.registers.iter().all(|&r| (r as usize) <= MU_MAX),
        "register exceeds MU_MAX = {MU_MAX}"
    );

    // ─── Native decode ───────────────────────────────────────────────────
    let commit = commit_hll_state(state);
    let res = fixed_res(m, &state.registers);
    let answer = release.apply(res);

    // ─── Build circuit ───────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    if bound {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    // PIs: committed state, released answer. (No query key for cardinality.)
    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let answer_pi = b.alloc_public_input("answer");
    if bound {
        b.add_expose(&[commit_pis[0], commit_pis[1], answer_pi]).expect("expose (commit, answer)");
    }

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");

    // Private witnesses.
    let cells_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("cell_packed")).collect();
    for (q, &p) in cells_packed.iter().enumerate() {
        b.tag(p, format!("hll_dec_cell_{q}")).expect("tag");
    }
    let wires = alloc_estimator_wires(&mut b, m);
    let flag = alloc_release_flag(&mut b, release);

    // ── Stage 1: open the committed state ──
    let digest = bind::hash_slice(&mut b, &Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, zero, binding);
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }
    // Each register Challenge decomposes to [r, 0, 0, 1]; coeff[0] is the
    // register value. Every decompose output must flow through an ALU op as the
    // LHS (first operand) so it gets a WitnessChecks bus creator — a coeff read
    // only as an rhs (or only via `connect`) panics at prove time with
    // "GlobalCumulativeMismatch: WitnessChecks".
    // Base pins: coeff 1..3 are connected to constants below and the register
    // is pinned by the estimator (one-hot or gated range), so `Bound` only adds
    // the ALU binding of the four coefficients to the hashed Challenge.
    let regs: Vec<ExprId> = cells_packed
        .iter()
        .map(|&p| {
            let c = bind::decompose::<Val, Challenge>(&mut b, p, binding, bind::no_pin, bind::no_pin);
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

    // ── Stages 2–4: estimator (one-hot/catch-all → Z → division certificate) ──
    let res_expr = constrain_estimator(&mut b, m, &regs, &wires, one, zero);

    // ── Stage 5: release policy → answer ──
    constrain_release(&mut b, release, res_expr, answer_pi, flag, one, zero);

    let circuit = b.build().expect("build hll decode circuit");

    // ─── Pack public + private values ────────────────────────────────────
    let commit_packed =
        pack_commit_to_challenge(&crate::commitment::CountMinCommit(commit.0));
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_u64(answer));

    let mut private_inputs: Vec<Challenge> = pack_cells(state);
    private_inputs.extend(estimator_witness_values(m, &state.registers));
    private_inputs.extend(release_flag_value(release, res));

    finish_hll_decode(circuit, public_inputs, private_inputs, answer, bound)
}

/// HyperLogLog cardinality decode against the **omc** committed state: the `m`
/// registers as a `d=1, w=m` array committed via [`commit_hll_omc`] (=
/// `commit_countmin`, one Val per register, 4 registers per Challenge) — the
/// state the deployed `prove_hll_omc` update recommits. Same fixed-point
/// estimator as [`prove_hll_decode`]; only the state binding differs (so this
/// one chains to the omc update, which `prove_hll_decode`'s `[r,0,0,1]` /
/// `commit_hll_state` binding does not).
pub fn prove_hll_decode_omc(params: HllDecodeParams, regs: Vec<u64>, _query: u64) -> DecodeProof {
    prove_hll_decode_omc_with(params, regs, _query, bind::default_binding())
}

/// [`prove_hll_decode_omc`] with an explicit [`Binding`].
///
/// [`Binding::Legacy`] is the pre-fix circuit, unchanged. It is unsound: the
/// registers are unbound from the commitment, so the answer is free, and it
/// exposes nothing. [`Binding::Semantic`] / [`Binding::Bound`] surface
/// `(commit, answer)` through the Expose NPO (8 + 4 base values). `Bound`
/// also ALU-binds the four register coefficients of every hashed Challenge
/// (already base-pinned by their range checks and the estimator) and hashes
/// with a zero IV (see [`crate::sketch::bind`]).
pub fn prove_hll_decode_omc_with(
    params: HllDecodeParams,
    regs: Vec<u64>,
    _query: u64,
    binding: Binding,
) -> DecodeProof {
    build_hll_decode_omc(params, &regs, binding).prove()
}

fn build_hll_decode_omc(params: HllDecodeParams, regs: &[u64], binding: Binding) -> HllDecodeCircuit {
    params.validate();
    let bound = binding.is_bound();
    let HllDecodeParams { b: blog2, release } = params;
    let m = 1usize << blog2;
    assert_eq!(regs.len(), m, "state shape must match params (m = 2^b)");
    assert_eq!(m % 4, 0, "m = 2^b must be a multiple of 4 (b >= 2)");
    assert!(regs.iter().all(|&r| (r as usize) <= MU_MAX), "register exceeds MU_MAX = {MU_MAX}");

    // ─── Native decode ───────────────────────────────────────────────────
    let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
    let commit = commit_hll_omc(regs, blog2);
    let res = fixed_res(m, &regs32);
    let answer = release.apply(res);

    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    if bound {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let answer_pi = b.alloc_public_input("answer");
    if bound {
        b.add_expose(&[commit_pis[0], commit_pis[1], answer_pi]).expect("expose (commit, answer)");
    }

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");

    // Private witnesses: m/4 packed challenges (4 registers each).
    let n_cells = m / 4;
    let cells_packed: Vec<ExprId> =
        (0..n_cells).map(|_| b.alloc_private_input("cell_packed")).collect();
    for (q, &p) in cells_packed.iter().enumerate() {
        b.tag(p, format!("hll_dec_cell_{q}")).expect("tag");
    }
    let wires = alloc_estimator_wires(&mut b, m);
    let flag = alloc_release_flag(&mut b, release);

    // ── Stage 1: open the committed omc register state ──
    let digest = bind::hash_slice(&mut b, &Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, zero, binding);
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }
    // Extract the m registers (4 per challenge); range-check each (bus-safe
    // consumption, the pattern that balances multi-coeff challenges). The
    // range check also pins each register to the base field, so `Bound` only
    // adds the ALU binding to the hashed Challenge.
    let mut regs_expr: Vec<ExprId> = Vec::with_capacity(m);
    for &p in &cells_packed {
        let c = bind::decompose::<Val, Challenge>(&mut b, p, binding, bind::no_pin, bind::no_pin);
        for k in 0..4 {
            let _ = b.add_range_bits::<Val>(c[k], REG_BITS).expect("reg range");
            regs_expr.push(c[k]);
        }
    }

    // ── Stages 2–4: estimator (one-hot/catch-all → Z → division certificate) ──
    let res_expr = constrain_estimator(&mut b, m, &regs_expr, &wires, one, zero);

    // ── Stage 5: release policy → answer ──
    constrain_release(&mut b, release, res_expr, answer_pi, flag, one, zero);

    let circuit = b.build().expect("build hll omc decode circuit");

    let commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(commit));
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_u64(answer));

    // pack the m registers 4-per-challenge (commit_countmin / commit_hll_omc form).
    let mut private_inputs: Vec<Challenge> = pack_omc_regs(regs);
    private_inputs.extend(estimator_witness_values(m, &regs32));
    private_inputs.extend(release_flag_value(release, res));

    finish_hll_decode(circuit, public_inputs, private_inputs, answer, bound)
}

/// Pack omc registers 4-per-Challenge (the `commit_hll_omc` absorption order).
fn pack_omc_regs(regs: &[u64]) -> Vec<Challenge> {
    regs.chunks(4)
        .map(|ch| {
            let coeffs: Vec<Val> = ch.iter().map(|&r| Val::from_u32(r as u32)).collect();
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
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
        let expected = fixed_res(1 << blog2, &regs32);
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

    /// Registers past `SEL_MAX` (the update produces ρ up to 32) take the
    /// catch-all selector with weight 0 and still prove/verify.
    #[test]
    fn hll_omc_decode_catchall_registers() {
        let blog2 = 2usize; // m = 4
        let regs: Vec<u64> = vec![12, 0, 4, 32]; // 12 and 32 are past SEL_MAX = 9
        let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
        assert_eq!(pow2neg(12), 0);
        assert_eq!(pow2neg(32), 0);
        let expected = fixed_res(1 << blog2, &regs32);
        let p = HllDecodeParams { b: blog2, release: ReleasePolicy::Identity };
        let proof = prove_hll_decode_omc(p, regs, 0);
        assert_eq!(proof.answer, expected, "catch-all decode must match native cardinality");
    }

    #[test]
    fn pow2neg_table() {
        assert_eq!(pow2neg(0), 1 << BETA);
        assert_eq!(pow2neg(1), 1 << (BETA - 1));
        assert_eq!(pow2neg(BETA), 1);
        // x = β+1 rounds half-up to 1; everything past SEL_MAX underflows to 0.
        assert_eq!(pow2neg(SEL_MAX), 1);
        assert_eq!(pow2neg(SEL_MAX + 1), 0);
        assert_eq!(pow2neg(MU_MAX), 0);
    }

    /// The native division witness closes the limb certificate exactly:
    /// `res·Z + rem = N` with `rem ∈ [0, Z)` (the in-circuit relation).
    #[test]
    fn division_certificate_closes() {
        for (m, regs) in [
            (16usize, state().registers.clone()),
            (4, vec![3u32, 1, 4, 2]),
            (4, vec![12, 0, 4, 32]),
            // b = 14 shapes: all-empty (Z = 2^22, the z1-top-limb edge) and a
            // realistic mixed fill.
            (1 << 14, vec![0u32; 1 << 14]),
            (1 << 14, (0..1u32 << 14).map(|i| [7, 6, 8, 7, 5, 9, 7, 25][i as usize % 8]).collect()),
        ] {
            let z = fixed_z(&regs);
            let n = big_n(m);
            let res = fixed_res(m, &regs);
            let limbs = div_limbs(m, z); // debug-asserts the digit equations
            let rem = n - res * z;
            assert!(rem < z, "rem in [0, Z)");
            assert_eq!(limbs[0] + (limbs[1] << LIMB_BITS) + (limbs[2] << (2 * LIMB_BITS)), res);
            assert_eq!(limbs[3] + (limbs[4] << LIMB_BITS), z);
            assert_eq!(limbs[5] + (limbs[6] << LIMB_BITS), rem);
        }
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

    /// Full b = 14 prove+verify against the omc commit — the deployed
    /// update-leaf scale (m = 2^14 registers). Large circuit; run explicitly:
    /// `cargo test --release hll_decode_b14 -- --ignored`.
    #[test]
    #[ignore = "large: m = 2^14 registers"]
    fn hll_decode_b14_prove_verify() {
        let blog2 = 14usize;
        let m = 1usize << blog2;
        // Realistic n ≈ 2^20 uniform fill (avg register ≈ 6-7) with empty and
        // past-SEL_MAX registers mixed in (the update produces ρ ≤ 32).
        let regs: Vec<u64> = (0..m)
            .map(|i| match i % 331 {
                0 => 0,             // empty register
                1 => 25,            // catch-all territory
                2 => 32,            // update's max ρ
                k => 5 + ((k * 2654435761) >> 7) as u64 % 5, // 5..=9
            })
            .collect();
        let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
        let expected = fixed_res(m, &regs32);
        // The estimate must be in the b = 14 budget (res < 2^29) and at a
        // realistic ~n = 2^20 magnitude.
        assert!(expected < 1u64 << RES_BITS);
        assert!(expected >> BETA > 1 << 19, "estimate should be ~2^20 scale");
        let p = HllDecodeParams { b: blog2, release: ReleasePolicy::Identity };
        let proof = prove_hll_decode_omc(p, regs, 0);
        assert_eq!(proof.answer, expected, "b=14 decode must match native cardinality");
    }

    // ── Binding (see `crate::sketch::bind`): legacy-vs-bound forgery tests ──

    use crate::config::make_perm;
    use crate::sketch::forge;
    use p3_field::PrimeField64;

    /// The pinned verifier with the VK derived from public parameters
    /// accepts honest proofs over non-empty register states and returns the
    /// exposed `(Com(S), answer)` (query coordinates zero); it rejects the
    /// Legacy circuit and a decoder at another register count.
    #[test]
    fn hll_omc_decode_vk_pins_proofs() {
        use crate::decode::{QueryStatement, verify_decode_proof};
        let binding = bind::default_binding();
        if binding == Binding::Legacy {
            return;
        }
        let p = HllDecodeParams { b: 4, release: ReleasePolicy::Identity };
        let vk = hll_omc_decode_vk(p, binding);
        for n in [0u64, 40, 400] {
            let mut regs = vec![0u64; 16];
            crate::sketch::hll_omc::hll_omc_advance(&mut regs, &(0..n).collect::<Vec<_>>(), 16);
            let proof = prove_hll_decode_omc(p, regs.clone(), 0);
            let want = QueryStatement::new(commit_hll_omc(&regs, 4), 0, proof.answer);
            assert_eq!(verify_decode_proof(&proof.output.0, &vk), Ok(want), "n = {n}");
        }
        let legacy = prove_hll_decode_omc_with(p, omc_regs(4), 0, Binding::Legacy);
        assert!(verify_decode_proof(&legacy.output.0, &vk).is_err(), "Legacy circuit");
        let other = prove_hll_decode_omc(HllDecodeParams { b: 5, release: ReleasePolicy::Identity }, omc_regs(5), 0);
        assert!(verify_decode_proof(&other.output.0, &vk).is_err(), "another register count");
    }

    fn omc_regs(b: usize) -> Vec<u64> {
        let m = 1usize << b;
        let mut regs = vec![0u64; m];
        crate::sketch::hll_omc::hll_omc_advance(&mut regs, &(0..40u64).collect::<Vec<_>>(), m);
        regs
    }

    fn exposed(proof: &DecodeProof) -> Vec<Val> {
        proof
            .output
            .0
            .non_primitives
            .iter()
            .map(|e| e.public_values.clone())
            .find(|v| v.len() == 12)
            .expect("exposed (commit, answer)")
    }

    /// Every binding agrees with native; Semantic/Bound expose (commit, answer).
    #[test]
    fn decoders_round_trip_all_bindings() {
        let p = HllDecodeParams { b: 4, release: ReleasePolicy::Identity };
        let regs = omc_regs(4);
        let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
        for binding in [Binding::Bound, Binding::Semantic, Binding::Legacy] {
            let pr = prove_hll_decode_omc_with(p, regs.clone(), 0, binding);
            assert_eq!(pr.answer, fixed_res(16, &regs32), "{binding:?}");
            if binding.is_bound() {
                let pv = exposed(&pr);
                assert_eq!(&pv[0..8], &commit_hll_omc(&regs, 4)[..]);
                assert_eq!(pv[8].as_canonical_u64(), pr.answer);
            }
            let pf = prove_hll_decode_with(p, state(), 0, binding);
            assert_eq!(pf.answer, fixed_res(16, &state().registers), "{binding:?}");
        }
    }

    /// FORGED STATE (transplant), omc decoder: estimate on registers with
    /// register 0 raised to 20, then recommit the cells to the real
    /// registers and rehash. Returns the in-circuit answer if the forged proof
    /// verifies. Every call first runs the positive control
    /// ([`forge::forged_with_control`]): estimate on the real registers and
    /// write the same cells back through the same plumbing; it must verify.
    fn forged_omc_answer(binding: Binding) -> Option<u64> {
        let honest = build_hll_decode_omc(
            HllDecodeParams { b: 4, release: ReleasePolicy::Identity },
            &omc_regs(4),
            binding,
        )
        .answer;
        forge::forged_with_control(
            &format!("hll omc decode forged state ({binding:?})"),
            |f| forged_omc_answer_run(binding, f),
            |a| assert_eq!(*a, honest, "control certifies the honest answer"),
        )
    }

    fn forged_omc_answer_run(binding: Binding, forge_it: bool) -> Option<u64> {
        let p = HllDecodeParams { b: 4, release: ReleasePolicy::Identity };
        let regs = omc_regs(4);
        let mut forged = regs.clone();
        forged[0] = 20;
        let dc = build_hll_decode_omc(p, if forge_it { &forged } else { &regs }, binding);
        let mut traces = dc.run();
        for (q, (h, f)) in pack_omc_regs(&regs).iter().zip(&pack_omc_regs(&forged)).enumerate() {
            if h != f {
                let wid = traces.tag_to_witness[&format!("hll_dec_cell_{q}")];
                forge::set_wid::<Val, Challenge>(&mut traces, wid, *h);
            }
        }
        forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, Poseidon2Config::BABY_BEAR_D4_W16, &make_perm());
        forge::accepted(|| dc.prove_traces(&traces).map(|_| ())).then(|| dc.answer)
    }

    /// Legacy ACCEPTS an omc decode for `Com(regs)` whose answer is the estimate
    /// of different registers; Bound rejects it.
    #[test]
    fn forged_omc_state_legacy_accepts_bound_rejects() {
        if !crate::sketch::bind::probe::fork_binds_decompose() {
            let regs32: Vec<u32> = omc_regs(4).iter().map(|&r| r as u32).collect();
            let a = forged_omc_answer(Binding::Legacy).expect("Legacy accepts the forged decode (PoC)");
            assert_ne!(a, fixed_res(16, &regs32), "answer is not the committed state's estimate");
        }
        assert!(forged_omc_answer(Binding::Bound).is_none(), "Bound must reject the forged decode");
        // Merged soundness fork: the fork itself binds decompose coefficients, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if crate::sketch::bind::probe::fork_binds_decompose() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(forged_omc_answer(b).is_none(), "fork binds decompose coefficients: {b:?} must reject too");
            }
        }
    }

    /// Same forgery against the `[r, 0, 0, 1]` full-state decoder.
    #[test]
    fn forged_full_state_legacy_accepts_bound_rejects() {
        let run_forger = |binding: Binding, forge_it: bool| -> Option<u64> {
            let p = HllDecodeParams { b: 4, release: ReleasePolicy::Identity };
            let real = state();
            let mut forged = real.clone();
            forged.registers[0] = 20;
            let dc = build_hll_decode(p, if forge_it { &forged } else { &real }, binding);
            let mut traces = dc.run();
            for (q, (h, f)) in pack_cells(&real).iter().zip(&pack_cells(&forged)).enumerate() {
                if h != f {
                    let wid = traces.tag_to_witness[&format!("hll_dec_cell_{q}")];
                    forge::set_wid::<Val, Challenge>(&mut traces, wid, *h);
                }
            }
            forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, Poseidon2Config::BABY_BEAR_D4_W16, &make_perm());
            forge::accepted(|| dc.prove_traces(&traces).map(|_| ())).then(|| dc.answer)
        };
        // Positive control first: decode the real state and write the same
        // cells back through the same plumbing; it must verify, honest answer.
        let run = |binding: Binding| -> Option<u64> {
            forge::forged_with_control(
                &format!("hll full decode forged state ({binding:?})"),
                |f| run_forger(binding, f),
                |a| assert_eq!(*a, fixed_res(16, &state().registers), "control: honest answer"),
            )
        };
        if !crate::sketch::bind::probe::fork_binds_decompose() {
            let a = run(Binding::Legacy).expect("Legacy accepts the forged decode (PoC)");
            assert_ne!(a, fixed_res(16, &state().registers));
        }
        assert!(run(Binding::Bound).is_none(), "Bound must reject the forged decode");
        // Merged soundness fork: the fork itself binds decompose coefficients, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if crate::sketch::bind::probe::fork_binds_decompose() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(run(b).is_none(), "fork binds decompose coefficients: {b:?} must reject too");
            }
        }
    }
}
