//! Greenwald–Khanna **rank / quantile** decode circuit (E3).
//!
//! Proves `answer = release( Σ_r active_r · [value_r ≤ q] · count_r )` against a
//! committed GK state (tuples `(value, count, max_error, active)`) — i.e. the
//! rank of `q`. Re-hashes the state (binds it), then for each tuple a forced
//! `≤` flag (`le_r`) is range-checked correct, and the active counts with
//! `value ≤ q` are summed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};

use crate::config::{C, D, F};
use crate::decode::spacesaving::bind_release;
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::leaf::gadgets::{bind_commit, vhash};
use crate::sketch::greenwald_khanna::GkState;

const VALUE_BITS: usize = 32;

#[derive(Copy, Clone, Debug)]
pub struct GkDecodeParams {
    pub capacity: usize,
    pub release: ReleasePolicy,
}

struct Tgt {
    commit: HashOutTarget,
    query: Target,
    answer: Target,
    cells: Vec<Target>, // [value,count,max_error,active] * capacity
    le: Vec<Target>,    // ≤ flags
    flag: Option<Target>,
    raw: Target,
}

pub struct GkDecodeLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: GkDecodeParams,
}

pub fn build_gk_decode(params: GkDecodeParams) -> GkDecodeLeaf {
    let GkDecodeParams { capacity: cap, release } = params;
    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let one = b.one();
    let zero = b.zero();

    let commit = vhash(&mut b);
    b.register_public_inputs(&commit.elements);
    let query = b.add_virtual_target();
    b.register_public_input(query);
    let answer = b.add_virtual_target();
    b.register_public_input(answer);

    let cells = b.add_virtual_targets(4 * cap);
    let le = b.add_virtual_targets(cap);
    let raw = b.add_virtual_target();

    bind_commit(&mut b, cells.clone(), &commit);

    let mut acc = zero;
    for r in 0..cap {
        let value_r = cells[4 * r];
        let count_r = cells[4 * r + 1];
        let active_r = cells[4 * r + 3];
        let le_r = le[r];
        // le_r boolean.
        let lm1 = b.sub(le_r, one);
        let bchk = b.mul(le_r, lm1);
        b.connect(bchk, zero);
        // chosen = le_r*(q - value_r) + (1-le_r)*(value_r - q - 1) >= 0 ⇒ le_r = [value_r ≤ q].
        let q_minus_v = b.sub(query, value_r);
        let v_minus_q_m1 = {
            let vm = b.sub(value_r, query);
            b.sub(vm, one)
        };
        let nle = b.sub(one, le_r);
        let a = b.mul(le_r, q_minus_v);
        let chosen = b.mul_add(nle, v_minus_q_m1, a);
        let _ = b.split_le(chosen, VALUE_BITS);
        // contrib = active_r * le_r * count_r.
        let al = b.mul(active_r, le_r);
        let contrib = b.mul(al, count_r);
        acc = b.add(acc, contrib);
    }
    b.connect(acc, raw);

    let flag = bind_release(&mut b, raw, release, answer, VALUE_BITS, one, zero);

    let data = Arc::new(b.build::<C>());
    GkDecodeLeaf { data, t: Tgt { commit, query, answer, cells, le, flag, raw }, params }
}

impl GkDecodeLeaf {
    pub fn prove_timed(&self, state: &GkState, query: u64) -> Result<(DecodeProof, Duration, Duration)> {
        let cap = self.params.capacity;
        assert_eq!(state.tuples.len(), cap);
        let t_w = Instant::now();

        let raw: u64 = state.tuples.iter().filter(|t| t.active == 1 && t.value <= query).map(|t| t.count).sum();
        let answer = self.params.release.apply(raw);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.commit, state.commit())?;
        pw.set_target(self.t.query, F::from_canonical_u64(query))?;
        pw.set_target(self.t.answer, F::from_canonical_u64(answer))?;
        for (tt, v) in self.t.cells.iter().zip(state.cells()) {
            pw.set_target(*tt, v)?;
        }
        for r in 0..cap {
            pw.set_target(self.t.le[r], if state.tuples[r].value <= query { F::ONE } else { F::ZERO })?;
        }
        pw.set_target(self.t.raw, F::from_canonical_u64(raw))?;
        if let Some(fl) = self.t.flag {
            let t = if let ReleasePolicy::Threshold(t) = self.params.release { t } else { 0 };
            pw.set_target(fl, if raw >= t { F::ONE } else { F::ZERO })?;
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
    use crate::sketch::greenwald_khanna::{apply_batch, GkParams, GkState, GkUpdate};

    fn state() -> GkState {
        let s0 = GkState::empty(GkParams { capacity: 8, batch: 8 });
        let batch = vec![
            GkUpdate::real(5), GkUpdate::real(5), GkUpdate::real(9), GkUpdate::real(12),
            GkUpdate::dummy(), GkUpdate::dummy(), GkUpdate::dummy(), GkUpdate::dummy(),
        ];
        apply_batch(&s0, &batch).0
    }

    #[test]
    fn gk_decode_rank() -> Result<()> {
        let leaf = build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let s = state();
        let (p5, _, _) = leaf.prove_timed(&s, 5)?;
        assert_eq!(p5.answer, s.rank(5)); // both 5s
        p5.verify()?;
        let (p12, _, _) = leaf.prove_timed(&s, 12)?;
        assert_eq!(p12.answer, s.rank(12)); // everything
        p12.verify()
    }

    #[test]
    fn gk_decode_rejects_wrong_answer() {
        let leaf = build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let s = state();
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.commit, s.commit()).unwrap();
        pw.set_target(leaf.t.query, F::from_canonical_u64(5)).unwrap();
        pw.set_target(leaf.t.answer, F::from_canonical_u64(0)).unwrap(); // wrong
        for (tt, v) in leaf.t.cells.iter().zip(s.cells()) {
            pw.set_target(*tt, v).unwrap();
        }
        for r in 0..8 {
            pw.set_target(leaf.t.le[r], if s.tuples[r].value <= 5 { F::ONE } else { F::ZERO }).unwrap();
        }
        pw.set_target(leaf.t.raw, F::from_canonical_u64(s.rank(5))).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "wrong rank must be rejected");
    }
}
