//! SpaceSaving **heavy-hitter frequency** decode circuit (E3).
//!
//! Proves `answer = release( Σ_r [key_r == q ∧ active_r] · count_r )` against a
//! committed SpaceSaving state (rows `(key, count, active)`). Re-hashes the
//! state (binds it), then matches the query key with a forced `is_zero` flag
//! per row. For a valid (distinct-key) state at most one row matches, so the
//! sum is the retained frequency (or 0 if not retained).

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
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::leaf::gadgets::{bind_commit, is_zero, vhash};
use crate::sketch::spacesaving::SsState;

const COUNT_BITS: usize = 32;

#[derive(Copy, Clone, Debug)]
pub struct SsDecodeParams {
    pub capacity: usize,
    pub release: ReleasePolicy,
}

struct Tgt {
    commit: HashOutTarget,
    query: Target,
    answer: Target,
    cells: Vec<Target>,    // [key,count,active] * capacity
    key_inv: Vec<Target>,  // is_zero inverse per row
    flag: Option<Target>,
    raw: Target,
}

pub struct SsDecodeLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: SsDecodeParams,
}

pub fn build_ss_decode(params: SsDecodeParams) -> SsDecodeLeaf {
    let SsDecodeParams { capacity: cap, release } = params;
    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let one = b.one();
    let zero = b.zero();

    let commit = vhash(&mut b);
    b.register_public_inputs(&commit.elements);
    let query = b.add_virtual_target();
    b.register_public_input(query);
    let answer = b.add_virtual_target();
    b.register_public_input(answer);

    let cells = b.add_virtual_targets(3 * cap);
    let key_inv = b.add_virtual_targets(cap);
    let raw = b.add_virtual_target();

    bind_commit(&mut b, cells.clone(), &commit);

    // raw = Σ_r [key_r == query] * active_r * count_r.
    let mut acc = zero;
    for r in 0..cap {
        let key_r = cells[3 * r];
        let count_r = cells[3 * r + 1];
        let active_r = cells[3 * r + 2];
        let diff = b.sub(key_r, query);
        let eq = is_zero(&mut b, diff, key_inv[r]);
        let m1 = b.mul(eq, active_r);
        let contrib = b.mul(m1, count_r);
        acc = b.add(acc, contrib);
    }
    b.connect(acc, raw);

    let flag = bind_release(&mut b, raw, release, answer, COUNT_BITS, one, zero);

    let data = Arc::new(b.build::<C>());
    SsDecodeLeaf { data, t: Tgt { commit, query, answer, cells, key_inv, flag, raw }, params }
}

/// Shared in-circuit release binding (also used by the GK decode). Returns the
/// threshold flag witness (if any) for the prover to fill.
pub(crate) fn bind_release(
    b: &mut CircuitBuilder<F, D>,
    raw: Target,
    release: ReleasePolicy,
    answer: Target,
    bits: usize,
    one: Target,
    zero: Target,
) -> Option<Target> {
    match release {
        ReleasePolicy::Identity => {
            b.connect(raw, answer);
            None
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.constant(F::from_canonical_u64(t));
            let fl = b.add_virtual_target();
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            let raw_minus_t = b.sub(raw, theta);
            let t_minus_raw_m1 = {
                let tm = b.sub(theta, raw);
                b.sub(tm, one)
            };
            let nf = b.sub(one, fl);
            let a = b.mul(fl, raw_minus_t);
            let chosen = b.mul_add(nf, t_minus_raw_m1, a);
            let _ = b.split_le(chosen, bits);
            let released = b.mul(fl, raw);
            b.connect(released, answer);
            Some(fl)
        }
    }
}

impl SsDecodeLeaf {
    pub fn prove_timed(&self, state: &SsState, query: u64) -> Result<(DecodeProof, Duration, Duration)> {
        let cap = self.params.capacity;
        assert_eq!(state.rows.len(), cap);
        let t_w = Instant::now();

        let raw: u64 = state.rows.iter().filter(|r| r.active == 1 && r.key == query).map(|r| r.count).sum();
        let answer = self.params.release.apply(raw);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.commit, state.commit())?;
        pw.set_target(self.t.query, F::from_canonical_u64(query))?;
        pw.set_target(self.t.answer, F::from_canonical_u64(answer))?;
        for (tt, v) in self.t.cells.iter().zip(state.cells()) {
            pw.set_target(*tt, v)?;
        }
        for r in 0..cap {
            let diff = F::from_canonical_u64(state.rows[r].key) - F::from_canonical_u64(query);
            pw.set_target(self.t.key_inv[r], if diff == F::ZERO { F::ZERO } else { diff.inverse() })?;
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
    use crate::sketch::spacesaving::{apply_batch, SsParams, SsState, SsUpdate};

    fn state() -> SsState {
        let s0 = SsState::empty(SsParams { capacity: 8, batch: 8 });
        let batch = vec![
            SsUpdate::real(7, 5), SsUpdate::real(11, 3), SsUpdate::real(7, 2),
            SsUpdate::real(7, 1), SsUpdate::dummy(), SsUpdate::dummy(), SsUpdate::dummy(), SsUpdate::dummy(),
        ];
        apply_batch(&s0, &batch).0
    }

    #[test]
    fn ss_decode_round_trip() -> Result<()> {
        let leaf = build_ss_decode(SsDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let (proof, _, _) = leaf.prove_timed(&state(), 7)?;
        assert_eq!(proof.answer, 8); // 5+2+1
        proof.verify()
    }

    #[test]
    fn ss_decode_absent_key_is_zero() -> Result<()> {
        let leaf = build_ss_decode(SsDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let (proof, _, _) = leaf.prove_timed(&state(), 999)?;
        assert_eq!(proof.answer, 0);
        proof.verify()
    }

    #[test]
    fn ss_decode_rejects_wrong_answer() {
        let leaf = build_ss_decode(SsDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let s = state();
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.commit, s.commit()).unwrap();
        pw.set_target(leaf.t.query, F::from_canonical_u64(7)).unwrap();
        pw.set_target(leaf.t.answer, F::from_canonical_u64(99)).unwrap(); // wrong
        for (tt, v) in leaf.t.cells.iter().zip(s.cells()) {
            pw.set_target(*tt, v).unwrap();
        }
        for r in 0..8 {
            let diff = F::from_canonical_u64(s.rows[r].key) - F::from_canonical_u64(7);
            pw.set_target(leaf.t.key_inv[r], if diff == F::ZERO { F::ZERO } else { diff.inverse() }).unwrap();
        }
        pw.set_target(leaf.t.raw, F::from_canonical_u64(8)).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "wrong answer must be rejected");
    }
}
