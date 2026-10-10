//! Count-Min **point-frequency** decode circuit (E3).
//!
//! Proves `answer = release( min_i  S[i][ h_i(key) ] )` against a committed
//! Count-Min state `S`, where `h_i(key) = Poseidon(key)[i] mod w` (derived
//! in-circuit, so the prover can't pick favourable cells). Stages:
//! 1. Re-hash the `d·w` cells → bind to the committed digest (the `Θ(s)` cost).
//! 2. Derive the `d` query positions from `Poseidon(key)`; select each cell via
//!    a one-hot row selector.
//! 3. Prove the min via the standard gadget (`mn ≤ every cell` by range check,
//!    and `∏(cell − mn) = 0` so `mn` is one of them).
//! 4. Apply the release policy and bind the released value to the public answer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;

use crate::config::{C, D, F};
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::leaf::countmin_final::hash_cell_prf;
use crate::leaf::gadgets::{bind_commit, vhash};
use crate::sketch::countmin::CountMinState;

const CELL_BITS: usize = 32;

#[derive(Copy, Clone, Debug)]
pub struct CmDecodeParams {
    pub d: usize,
    pub w: usize,
    pub release: ReleasePolicy,
}

struct Tgt {
    commit: HashOutTarget,
    key: Target,
    answer: Target,
    cells: Vec<Target>,
    sel: Vec<Vec<Target>>, // [d][w] one-hot
    mn: Target,
    flag: Option<Target>, // threshold release flag
}

pub struct CmDecodeLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: CmDecodeParams,
}

pub fn build_cm_decode(params: CmDecodeParams) -> CmDecodeLeaf {
    let CmDecodeParams { d, w, release } = params;
    assert!(d >= 1 && w.is_power_of_two());
    let w_log2 = w.trailing_zeros() as usize;
    let num_cells = d * w;

    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());
    let one = b.one();
    let zero = b.zero();

    // PIs: committed state, query key, released answer.
    let commit = vhash(&mut b);
    b.register_public_inputs(&commit.elements);
    let key = b.add_virtual_target();
    b.register_public_input(key);
    let answer = b.add_virtual_target();
    b.register_public_input(answer);

    let cells = b.add_virtual_targets(num_cells);
    let sel: Vec<Vec<Target>> = (0..d).map(|_| b.add_virtual_targets(w)).collect();
    let mn = b.add_virtual_target();

    // Stage 1: bind the whole committed state.
    bind_commit(&mut b, cells.clone(), &commit);

    // Stage 2: positions h_i(key) = low w_log2 bits of the PRF digest; select.
    // One digest per block of 4 rows (block 0 hashes `[key]`, later blocks
    // `[key, block]`), matching `hash_cell_prf` exactly.
    let digests: Vec<_> = (0..d.div_ceil(4))
        .map(|blk| {
            if blk == 0 {
                b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![key])
            } else {
                let blk_c = b.constant(F::from_canonical_u64(blk as u64));
                b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![key, blk_c])
            }
        })
        .collect();
    let pow2: Vec<Target> = (0..w_log2).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let idx_const: Vec<Target> = (0..w).map(|j| b.constant(F::from_canonical_u64(j as u64))).collect();
    let mut vals: Vec<Target> = Vec::with_capacity(d);
    for i in 0..d {
        let bits = b.split_le(digests[i / 4].elements[i % 4], 64);
        let mut pos = b.mul(bits[0].target, pow2[0]);
        for jb in 1..w_log2 {
            pos = b.mul_add(bits[jb].target, pow2[jb], pos);
        }
        // one-hot selector over the w cells of row i.
        let row = &sel[i];
        let mut sum = zero;
        let mut idx_acc = zero;
        let mut val = zero;
        for j in 0..w {
            let sm1 = b.sub(row[j], one);
            let bchk = b.mul(row[j], sm1);
            b.connect(bchk, zero);
            sum = b.add(sum, row[j]);
            idx_acc = b.mul_add(idx_const[j], row[j], idx_acc);
            val = b.mul_add(row[j], cells[i * w + j], val);
        }
        b.connect(sum, one);
        b.connect(idx_acc, pos);
        vals.push(val);
    }

    // Stage 3: min gadget — mn ≤ every val, and mn equals some val.
    let mut prod = one;
    for &v in &vals {
        let diff = b.sub(v, mn);
        let _ = b.split_le(diff, CELL_BITS); // v - mn >= 0
        prod = b.mul(prod, diff);
    }
    b.connect(prod, zero);

    // Stage 4: release policy → answer.
    let flag = match release {
        ReleasePolicy::Identity => {
            b.connect(mn, answer);
            None
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.constant(F::from_canonical_u64(t));
            let fl = b.add_virtual_target();
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            // chosen = fl*(mn-θ) + (1-fl)*(θ-mn-1) must be >= 0 ⇒ fl = [mn>=θ].
            let mn_minus_t = b.sub(mn, theta);
            let t_minus_mn_m1 = {
                let tm = b.sub(theta, mn);
                b.sub(tm, one)
            };
            let nf = b.sub(one, fl);
            let a = b.mul(fl, mn_minus_t);
            let chosen = b.mul_add(nf, t_minus_mn_m1, a);
            let _ = b.split_le(chosen, CELL_BITS);
            let released = b.mul(fl, mn);
            b.connect(released, answer);
            Some(fl)
        }
    };

    let data = Arc::new(crate::config::build_circuit(b));
    CmDecodeLeaf { data, t: Tgt { commit, key, answer, cells, sel, mn, flag }, params }
}

impl CmDecodeLeaf {
    pub fn prove_timed(&self, state: &CountMinState, key: u64) -> Result<(DecodeProof, Duration, Duration)> {
        let CmDecodeParams { d, w, release } = self.params;
        assert_eq!((state.d, state.w), (d, w));
        let t_w = Instant::now();

        // Native decode.
        let mut vals = Vec::with_capacity(d);
        for i in 0..d {
            let pos = hash_cell_prf(i, key, w);
            vals.push(state.counters[i][pos]);
        }
        let mn = *vals.iter().min().unwrap();
        let answer = release.apply(mn);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.commit, state.commit())?;
        pw.set_target(self.t.key, F::from_canonical_u64(key))?;
        pw.set_target(self.t.answer, F::from_canonical_u64(answer))?;
        for (tt, v) in self.t.cells.iter().zip(state.cells()) {
            pw.set_target(*tt, v)?;
        }
        for i in 0..d {
            let pos = hash_cell_prf(i, key, w);
            for j in 0..w {
                pw.set_target(self.t.sel[i][j], if j == pos { F::ONE } else { F::ZERO })?;
            }
        }
        pw.set_target(self.t.mn, F::from_canonical_u64(mn))?;
        if let Some(fl) = self.t.flag {
            let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
            pw.set_target(fl, if mn >= t { F::ONE } else { F::ZERO })?;
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
    use crate::leaf::countmin_final::apply_update_prf;
    use crate::sketch::countmin::{CountMinParams, CountMinUpdate};

    fn state() -> CountMinState {
        let mut s = CountMinState::new(&CountMinParams { d: 4, w: 8 });
        for k in [7u64, 7, 11, 7, 11, 3] {
            apply_update_prf(&mut s, &CountMinUpdate { key: k, value: 1 });
        }
        s
    }

    #[test]
    fn cm_decode_round_trip() -> Result<()> {
        let leaf = build_cm_decode(CmDecodeParams { d: 4, w: 8, release: ReleasePolicy::Identity });
        let s = state();
        let (proof, _, _) = leaf.prove_timed(&s, 7)?;
        // answer = count-min estimate of key 7 (>= true count 3).
        assert!(proof.answer >= 3);
        proof.verify()
    }

    #[test]
    fn cm_decode_threshold_suppresses() -> Result<()> {
        // θ above the estimate ⇒ released 0.
        let leaf = build_cm_decode(CmDecodeParams { d: 4, w: 8, release: ReleasePolicy::Threshold(1000) });
        let (proof, _, _) = leaf.prove_timed(&state(), 7)?;
        assert_eq!(proof.answer, 0);
        proof.verify()
    }

    #[test]
    fn cm_decode_rejects_wrong_answer() {
        let leaf = build_cm_decode(CmDecodeParams { d: 4, w: 8, release: ReleasePolicy::Identity });
        let s = state();
        // Hand-build a witness claiming a wrong (too-small) answer.
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.commit, s.commit()).unwrap();
        pw.set_target(leaf.t.key, F::from_canonical_u64(7)).unwrap();
        pw.set_target(leaf.t.answer, F::ZERO).unwrap(); // wrong
        for (tt, v) in leaf.t.cells.iter().zip(s.cells()) {
            pw.set_target(*tt, v).unwrap();
        }
        for i in 0..4 {
            let pos = hash_cell_prf(i, 7, 8);
            for j in 0..8 {
                pw.set_target(leaf.t.sel[i][j], if j == pos { F::ONE } else { F::ZERO }).unwrap();
            }
        }
        let mn = (0..4).map(|i| s.counters[i][hash_cell_prf(i, 7, 8)]).min().unwrap();
        pw.set_target(leaf.t.mn, F::from_canonical_u64(mn)).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "wrong answer must be rejected");
    }
}
