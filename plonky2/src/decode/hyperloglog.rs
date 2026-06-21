//! HyperLogLog **cardinality** decode circuit (E3).
//!
//! HLL's cardinality estimate `α·m²/Σ 2^{-rᵢ}` is floating-point, so the decode
//! *circuit* certifies the integer harmonic surrogate
//! `Z = Σ_r 2^{B − reg_r}` (with a fixed base `B`, registers forced into
//! `[0, B]` by a one-hot exponent selector); the float estimate `α·m²·2^B / Z`
//! is then a deterministic **native** post-processing of the certified `Z`.
//! Re-hashes the registers (binds them to the committed state) first.
//!
//! `B = HLL_B` caps the largest register value the surrogate represents; small
//! streams keep registers far below it (a huge-cardinality stream would need a
//! larger `B`). Proven answer = `Z`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};

use crate::config::{C, D, F};
use crate::decode::DecodeProof;
use crate::leaf::gadgets::{bind_commit, vhash};
use crate::sketch::hyperloglog::HllState;

/// Exponent base for the harmonic surrogate (registers must be `≤ B`).
pub const HLL_B: usize = 24;

#[derive(Copy, Clone, Debug)]
pub struct HllDecodeParams {
    pub b: usize, // log2(register count)
}

struct Tgt {
    commit: HashOutTarget,
    answer: Target,
    cells: Vec<Target>,    // m registers
    sel: Vec<Vec<Target>>, // [m][B+1] one-hot exponent selectors
}

pub struct HllDecodeLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: HllDecodeParams,
}

/// Native harmonic surrogate `Z = Σ_r 2^{B - reg_r}` from the registers.
pub fn surrogate(regs: &[u64]) -> u64 {
    regs.iter().map(|&r| 1u64 << (HLL_B as u64 - r)).sum()
}

pub fn build_hll_decode(params: HllDecodeParams) -> HllDecodeLeaf {
    let m = 1usize << params.b;
    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let one = b.one();
    let zero = b.zero();

    let commit = vhash(&mut b);
    b.register_public_inputs(&commit.elements);
    let answer = b.add_virtual_target();
    b.register_public_input(answer);

    let cells = b.add_virtual_targets(m);
    let sel: Vec<Vec<Target>> = (0..m).map(|_| b.add_virtual_targets(HLL_B + 1)).collect();

    bind_commit(&mut b, cells.clone(), &commit);

    // exponent constants: 2^(B-j) for j in 0..=B; index constants j.
    let pow: Vec<Target> = (0..=HLL_B).map(|j| b.constant(F::from_canonical_u64(1u64 << (HLL_B - j) as u64))).collect();
    let idx: Vec<Target> = (0..=HLL_B).map(|j| b.constant(F::from_canonical_u64(j as u64))).collect();

    let mut z = zero;
    for r in 0..m {
        let row = &sel[r];
        let mut sum = zero;
        let mut idx_acc = zero;
        let mut term = zero;
        for j in 0..=HLL_B {
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
    b.connect(z, answer);

    let data = Arc::new(b.build::<C>());
    HllDecodeLeaf { data, t: Tgt { commit, answer, cells, sel }, params }
}

impl HllDecodeLeaf {
    pub fn prove_timed(&self, state: &HllState) -> Result<(DecodeProof, Duration, Duration)> {
        let m = 1usize << self.params.b;
        let regs: Vec<u64> = state.cells().iter().map(|c| c.to_canonical_u64()).collect();
        assert_eq!(regs.len(), m);
        assert!(regs.iter().all(|&r| (r as usize) <= HLL_B), "register exceeds HLL_B; raise HLL_B");
        let t_w = Instant::now();
        let z = surrogate(&regs);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.commit, state.commit())?;
        pw.set_target(self.t.answer, F::from_canonical_u64(z))?;
        for (tt, v) in self.t.cells.iter().zip(state.cells()) {
            pw.set_target(*tt, v)?;
        }
        for r in 0..m {
            let rv = regs[r] as usize;
            for j in 0..=HLL_B {
                pw.set_target(self.t.sel[r][j], if j == rv { F::ONE } else { F::ZERO })?;
            }
        }
        let witness = t_w.elapsed();
        let t_p = Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((DecodeProof { data: self.data.clone(), proof, answer: z }, witness, prove))
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
    fn hll_decode_round_trip() -> Result<()> {
        let leaf = build_hll_decode(HllDecodeParams { b: 4 });
        let s = state();
        let (proof, _, _) = leaf.prove_timed(&s)?;
        let regs: Vec<u64> = s.cells().iter().map(|c| c.to_canonical_u64()).collect();
        assert_eq!(proof.answer, surrogate(&regs));
        proof.verify()
    }

    #[test]
    fn hll_decode_rejects_wrong_z() {
        let leaf = build_hll_decode(HllDecodeParams { b: 4 });
        let s = state();
        let regs: Vec<u64> = s.cells().iter().map(|c| c.to_canonical_u64()).collect();
        let m = 16;
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.commit, s.commit()).unwrap();
        pw.set_target(leaf.t.answer, F::from_canonical_u64(surrogate(&regs) + 1)).unwrap(); // wrong
        for (tt, v) in leaf.t.cells.iter().zip(s.cells()) {
            pw.set_target(*tt, v).unwrap();
        }
        for r in 0..m {
            let rv = regs[r] as usize;
            for j in 0..=HLL_B {
                pw.set_target(leaf.t.sel[r][j], if j == rv { F::ONE } else { F::ZERO }).unwrap();
            }
        }
        assert!(leaf.data.prove(pw).is_err(), "wrong Z must be rejected");
    }
}
