//! HyperLogLog cardinality decode circuit, in fixed point with BETA fractional bits.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;

use crate::config::{C, D, F};
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::leaf::gadgets::{bind_commit, vhash};
use crate::sketch::hyperloglog::HllState;

/// Fixed-point precision (mantissa bits) for the estimator. Public metadata.
pub const BETA: usize = 20;

/// Max register value the `Pow2Neg` one-hot table covers (`0..=MU_MAX`). Entries
/// past `BETA` round to 0. Replaces the old integer-surrogate `HLL_B` base.
pub const MU_MAX: usize = 24;

/// Range-check window for the reciprocal residual `Z·invZ − T` and the gated
/// threshold diff. Wide enough to contain `Z ≤ 2^(b+β)` (and small thresholds)
/// yet far below the 64-bit field so a "negative" value wraps and overflows the
/// check (sound `≥ 0`).
const DIFF_BITS: usize = 40;

#[derive(Copy, Clone, Debug)]
pub struct HllDecodeParams {
    pub b: usize, // log2(register count)
    pub release: ReleasePolicy,
}

struct Tgt {
    commit: HashOutTarget,
    answer: Target,
    cells: Vec<Target>,    // m registers
    sel: Vec<Vec<Target>>, // [m][MU_MAX+1] one-hot exponent selectors
    invz: Target,          // witnessed reciprocal
    flag: Option<Target>,  // threshold release flag
}

pub struct HllDecodeLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: HllDecodeParams,
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
        let num: u128 = (1u128 << BETA) + (1u128 << (x - 1));
        (num >> x) as u64
    }
}

/// HLL bias-correction `α_s` for `m` registers (matches the sketch estimator).
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
pub fn fixed_z(regs: &[u64]) -> u64 {
    regs.iter().map(|&r| pow2neg(r as usize)).sum()
}

/// Native witnessed reciprocal `invZ = ceil(T / Z)` (so `Z·invZ − T ∈ [0, Z)`).
pub fn inv_z(z: u64) -> u64 {
    let t = recip_target();
    (t + z - 1) / z
}

/// Native fixed-point cardinality `res = K_num · invZ` (scale `2^β`).
pub fn fixed_res(m: usize, regs: &[u64]) -> u64 {
    let z = fixed_z(regs);
    k_num(m) * inv_z(z)
}

pub fn build_hll_decode(params: HllDecodeParams) -> HllDecodeLeaf {
    let m = 1usize << params.b;
    let knum = k_num(m);
    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());
    let one = b.one();
    let zero = b.zero();

    let commit = vhash(&mut b);
    b.register_public_inputs(&commit.elements);
    let answer = b.add_virtual_target();
    b.register_public_input(answer);

    let cells = b.add_virtual_targets(m);
    let sel: Vec<Vec<Target>> = (0..m).map(|_| b.add_virtual_targets(MU_MAX + 1)).collect();
    let invz = b.add_virtual_target();

    bind_commit(&mut b, cells.clone(), &commit);

    // Fixed-point Pow2Neg weights and index constants j, for j in 0..=MU_MAX.
    let pow: Vec<Target> =
        (0..=MU_MAX).map(|j| b.constant(F::from_canonical_u64(pow2neg(j)))).collect();
    let idx: Vec<Target> =
        (0..=MU_MAX).map(|j| b.constant(F::from_canonical_u64(j as u64))).collect();
    let target = b.constant(F::from_canonical_u64(recip_target()));
    let knum_c = b.constant(F::from_canonical_u64(knum));

    // ── Stages 2 + 3: per-register one-hot Pow2Neg selector → Z ──
    let mut z = zero;
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
            idx_acc = b.mul_add(idx[j], row[j], idx_acc);
            term = b.mul_add(row[j], pow[j], term);
        }
        b.connect(sum, one);
        b.connect(idx_acc, cells[r]); // selected exponent index == register value
        z = b.add(z, term);
    }

    // ── Stage 4: witnessed reciprocal invZ, residual range check, res = K·invZ ──
    // Certify Z·invZ − T ∈ [0, Z): the rounding residual of invZ = ceil(T/Z).
    //   residual = Z·invZ − T        (≥ 0 ⇔ invZ ≥ ceil(T/Z))
    //   Z − 1 − residual             (≥ 0 ⇔ residual < Z)
    // Both range-checked ≥ 0 pin invZ = ceil(T/Z) uniquely.
    let z_invz = b.mul(z, invz);
    let residual = b.sub(z_invz, target);
    let _ = b.split_le(residual, DIFF_BITS); // residual >= 0
    let zm1 = b.sub(z, one);
    let upper = b.sub(zm1, residual);
    let _ = b.split_le(upper, DIFF_BITS); // residual < Z
    let res = b.mul(knum_c, invz); // fixed-point cardinality, scale 2^β

    // ── Stage 5: release policy → answer ──
    let flag = match params.release {
        ReleasePolicy::Identity => {
            b.connect(res, answer);
            None
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.constant(F::from_canonical_u64(t));
            let fl = b.add_virtual_target();
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            // chosen = fl*(res-θ) + (1-fl)*(θ-res-1) >= 0 ⇒ fl = [res>=θ].
            let res_minus_t = b.sub(res, theta);
            let t_minus_res_m1 = {
                let tm = b.sub(theta, res);
                b.sub(tm, one)
            };
            let nf = b.sub(one, fl);
            let a = b.mul(fl, res_minus_t);
            let chosen = b.mul_add(nf, t_minus_res_m1, a);
            let _ = b.split_le(chosen, DIFF_BITS);
            let released = b.mul(fl, res);
            b.connect(released, answer);
            Some(fl)
        }
    };

    let data = Arc::new(crate::config::build_circuit(b));
    HllDecodeLeaf { data, t: Tgt { commit, answer, cells, sel, invz, flag }, params }
}

impl HllDecodeLeaf {
    pub fn prove_timed(&self, state: &HllState) -> Result<(DecodeProof, Duration, Duration)> {
        let m = 1usize << self.params.b;
        let regs: Vec<u64> = state.cells().iter().map(|c| c.to_canonical_u64()).collect();
        assert_eq!(regs.len(), m);
        assert!(regs.iter().all(|&r| (r as usize) <= MU_MAX), "register exceeds MU_MAX; raise MU_MAX");
        let t_w = Instant::now();
        let z = fixed_z(&regs);
        let invz = inv_z(z);
        let res = k_num(m) * invz;
        let answer = self.params.release.apply(res);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.commit, state.commit())?;
        pw.set_target(self.t.answer, F::from_canonical_u64(answer))?;
        for (tt, v) in self.t.cells.iter().zip(state.cells()) {
            pw.set_target(*tt, v)?;
        }
        for r in 0..m {
            let rv = regs[r] as usize;
            for j in 0..=MU_MAX {
                pw.set_target(self.t.sel[r][j], if j == rv { F::ONE } else { F::ZERO })?;
            }
        }
        pw.set_target(self.t.invz, F::from_canonical_u64(invz))?;
        if let Some(fl) = self.t.flag {
            let t = if let ReleasePolicy::Threshold(t) = self.params.release { t } else { 0 };
            pw.set_target(fl, if res >= t { F::ONE } else { F::ZERO })?;
        }
        let witness = t_w.elapsed();
        let t_p = Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((DecodeProof { data: self.data.clone(), proof, answer }, witness, prove))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::hyperloglog::{HllParams, HllState, HllUpdate};

    fn state() -> HllState {
        let mut s = HllState::new(&HllParams { b: 4 });
        for k in 0..40u64 {
            s.update(&HllUpdate { key: k.wrapping_mul(0x9E37_79B9) });
        }
        s
    }

    #[test]
    fn pow2neg_table() {
        assert_eq!(pow2neg(0), 1 << BETA);
        assert_eq!(pow2neg(1), 1 << (BETA - 1));
        assert_eq!(pow2neg(BETA), 1);
        assert_eq!(pow2neg(MU_MAX), 0);
    }

    #[test]
    fn reciprocal_residual_in_range() {
        let s = state();
        let regs: Vec<u64> = s.cells().iter().map(|c| c.to_canonical_u64()).collect();
        let z = fixed_z(&regs);
        let invz = inv_z(z);
        let resid = z * invz - recip_target();
        assert!(resid < z, "Z·invZ − T must lie in [0, Z); got resid={resid}, Z={z}");
    }

    #[test]
    fn hll_decode_round_trip() -> Result<()> {
        let leaf =
            build_hll_decode(HllDecodeParams { b: 4, release: ReleasePolicy::Identity });
        let s = state();
        let (proof, _, _) = leaf.prove_timed(&s)?;
        let regs: Vec<u64> = s.cells().iter().map(|c| c.to_canonical_u64()).collect();
        assert_eq!(proof.answer, fixed_res(16, &regs), "answer == native fixed-point res");
        proof.verify()
    }

    #[test]
    fn fixed_res_tracks_native_estimate() {
        // The fixed-point res / 2^β should be close to the native float estimate
        // α·m²/Σ2^{-reg}.
        let s = state();
        let regs: Vec<u64> = s.cells().iter().map(|c| c.to_canonical_u64()).collect();
        let res = fixed_res(16, &regs) as f64 / (1u64 << BETA) as f64;
        let z_real: f64 = regs.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        let est = 0.673 * 16.0 * 16.0 / z_real;
        let rel = (res - est).abs() / est.max(1.0);
        assert!(rel < 0.05, "fixed-point res {res} vs float estimate {est} (rel err {rel})");
    }

    #[test]
    fn hll_decode_threshold_passes() -> Result<()> {
        let leaf =
            build_hll_decode(HllDecodeParams { b: 4, release: ReleasePolicy::Threshold(1) });
        let s = state();
        let regs: Vec<u64> = s.cells().iter().map(|c| c.to_canonical_u64()).collect();
        let (proof, _, _) = leaf.prove_timed(&s)?;
        assert_eq!(proof.answer, fixed_res(16, &regs), "res >= θ ⇒ released res");
        proof.verify()
    }

    #[test]
    fn hll_decode_threshold_suppresses() -> Result<()> {
        let s = state();
        let regs: Vec<u64> = s.cells().iter().map(|c| c.to_canonical_u64()).collect();
        let res = fixed_res(16, &regs);
        let theta = res + (1u64 << 24); // above res, within DIFF_BITS window
        assert!(theta < (1u64 << DIFF_BITS));
        let leaf =
            build_hll_decode(HllDecodeParams { b: 4, release: ReleasePolicy::Threshold(theta) });
        let (proof, _, _) = leaf.prove_timed(&s)?;
        assert_eq!(proof.answer, 0, "res < θ ⇒ released 0");
        proof.verify()
    }

    #[test]
    fn hll_decode_rejects_wrong_res() {
        let leaf =
            build_hll_decode(HllDecodeParams { b: 4, release: ReleasePolicy::Identity });
        let s = state();
        let regs: Vec<u64> = s.cells().iter().map(|c| c.to_canonical_u64()).collect();
        let m = 16;
        let z = fixed_z(&regs);
        let invz = inv_z(z);
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.commit, s.commit()).unwrap();
        // wrong answer: claim res+1 with consistent invZ ⇒ res = K·invZ binding fails.
        pw.set_target(leaf.t.answer, F::from_canonical_u64(k_num(m) * invz + 1)).unwrap();
        for (tt, v) in leaf.t.cells.iter().zip(s.cells()) {
            pw.set_target(*tt, v).unwrap();
        }
        for r in 0..m {
            let rv = regs[r] as usize;
            for j in 0..=MU_MAX {
                pw.set_target(leaf.t.sel[r][j], if j == rv { F::ONE } else { F::ZERO }).unwrap();
            }
        }
        pw.set_target(leaf.t.invz, F::from_canonical_u64(invz)).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "wrong res must be rejected");
    }
}
