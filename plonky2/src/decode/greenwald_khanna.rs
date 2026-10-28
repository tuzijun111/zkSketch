//! Greenwald–Khanna rank-query decode circuit over a committed GK state.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;

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
    sel: Vec<Target>,   // one-hot bracketing selector over k ∈ {0,…,cap}
    res: Target,        // ⌊(r_min+r_max)/2⌋
    rem: Target,        // (r_min+r_max) mod 2 ∈ {0,1}
    flag: Option<Target>,
}

pub struct GkDecodeLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: GkDecodeParams,
}

pub fn build_gk_decode(params: GkDecodeParams) -> GkDecodeLeaf {
    let GkDecodeParams { capacity: cap, release } = params;
    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());
    let one = b.one();
    let zero = b.zero();
    let two = b.constant(F::from_canonical_u64(2));

    let commit = vhash(&mut b);
    b.register_public_inputs(&commit.elements);
    let query = b.add_virtual_target();
    b.register_public_input(query);
    let answer = b.add_virtual_target();
    b.register_public_input(answer);

    let cells = b.add_virtual_targets(4 * cap);
    let le = b.add_virtual_targets(cap);
    let sel = b.add_virtual_targets(cap + 1);
    let res = b.add_virtual_target();
    let rem = b.add_virtual_target();

    bind_commit(&mut b, cells.clone(), &commit);

    // ── Stage 3: per-tuple ≤-flag soundness + prefix mass P_i ──
    // For each tuple force `le_r ∈ {0,1}` to equal `[value_r ≤ q]` (a single
    // range-checked non-negative diff), and accumulate the prefix mass
    // `P_i = Σ active_r · le_r · count_r`. Dummies have count 0, and the active
    // table is value-sorted, so this is exactly the prefix mass at the bracket.
    let mut p_i = zero;
    for r in 0..cap {
        let value_r = cells[4 * r];
        let count_r = cells[4 * r + 1];
        let active_r = cells[4 * r + 3];
        let le_r = le[r];
        // le_r boolean.
        let lm1 = b.sub(le_r, one);
        let bchk = b.mul(le_r, lm1);
        b.connect(bchk, zero);
        // chosen = le_r*(q - value_r) + (1-le_r)*(value_r - q - 1) >= 0
        //   ⇒ le_r = [value_r ≤ q].
        let q_minus_v = b.sub(query, value_r);
        let v_minus_q_m1 = {
            let vm = b.sub(value_r, query);
            b.sub(vm, one)
        };
        let nle = b.sub(one, le_r);
        let a = b.mul(le_r, q_minus_v);
        let chosen = b.mul_add(nle, v_minus_q_m1, a);
        let _ = b.split_le(chosen, VALUE_BITS);
        // P_i contribution: active_r * le_r * count_r.
        let al = b.mul(active_r, le_r);
        let contrib = b.mul(al, count_r);
        p_i = b.add(p_i, contrib);
    }

    // ── Stage 4: one-hot bracketing selector + bracket estimator ──
    //
    // sel[k] = 1 for exactly one k ∈ {0,…,cap}, the bracket boundary (number of
    // tuples with value ≤ q). Constraints:
    //   - each sel[k] ∈ {0,1}, Σ sel[k] = 1 (one-hot);
    //   - Σ_k k·sel[k] = Σ_r le_r (ties k to the bracket; the table is
    //     value-ascending so the le flags are 1…1 0…0 and k is the index of the
    //     first tuple with value > q);
    //   - max_error_i   = Σ_{k≥1}   sel[k]·max_error_{k-1}  (left bracket, 0 at k=0);
    //   - max_error_{i+1} = Σ_{k<cap} sel[k]·max_error_k     (right bracket, 0 at k=cap).
    let mut sel_sum = zero;
    let mut k_acc = zero; // Σ k·sel[k]
    let mut me_left = zero; // max_error_i
    let mut me_right = zero; // max_error_{i+1}
    for k in 0..=cap {
        let s = sel[k];
        let sm1 = b.sub(s, one);
        let bchk = b.mul(s, sm1);
        b.connect(bchk, zero);
        sel_sum = b.add(sel_sum, s);

        let kconst = b.constant(F::from_canonical_u64(k as u64));
        k_acc = b.mul_add(kconst, s, k_acc);

        if k >= 1 {
            let me = cells[4 * (k - 1) + 2];
            me_left = b.mul_add(s, me, me_left);
        }
        if k < cap {
            let me = cells[4 * k + 2];
            me_right = b.mul_add(s, me, me_right);
        }
    }
    b.connect(sel_sum, one);

    // Boundary correctness: Σ_k k·sel[k] = Σ_r le_r (count of tuples, incl.
    // value-0 dummies, with value ≤ q).
    let mut le_sum = zero;
    for r in 0..cap {
        le_sum = b.add(le_sum, le[r]);
    }
    b.connect(k_acc, le_sum);

    // r_min = P_i − max_error_i, r_max = P_i + max_error_{i+1}.
    // num = r_min + r_max = 2·P_i + max_error_{i+1} − max_error_i.
    // res = ⌊num/2⌋ with witnessed remainder rem ∈ {0,1}: 2·res + rem = num.
    let r_min = b.sub(p_i, me_left);
    let r_max = b.add(p_i, me_right);
    let num = b.add(r_min, r_max);

    // rem boolean.
    let rm1 = b.sub(rem, one);
    let bchk = b.mul(rem, rm1);
    b.connect(bchk, zero);
    // 2·res + rem = num.
    let recon = b.mul_add(two, res, rem);
    b.connect(recon, num);
    // res ≥ 0 (floor of a non-negative midpoint) — range-checked.
    let _ = b.split_le(res, VALUE_BITS);

    // ── Stage 5: release policy → answer (binds res, not the raw prefix) ──
    let flag = bind_release(&mut b, res, release, answer, VALUE_BITS, one, zero);

    let data = Arc::new(crate::config::build_circuit(b));
    GkDecodeLeaf { data, t: Tgt { commit, query, answer, cells, le, sel, res, rem, flag }, params }
}

/// Native approximate-rank estimate over the committed GK state, mirroring the
/// in-circuit relation. Returns `(res, k, rem)` where `k` is the bracket
/// boundary (number of tuples with `value ≤ q`, dummies included).
fn native_estimate(state: &GkState, q: u64) -> (u64, usize, u64) {
    let tuples = &state.tuples;
    let cap = tuples.len();
    let le: Vec<bool> = tuples.iter().map(|t| t.value <= q).collect();
    let k = le.iter().filter(|&&x| x).count();
    let p_i: u64 = tuples
        .iter()
        .zip(&le)
        .filter(|&(_, &x)| x)
        .filter(|(t, _)| t.active == 1)
        .map(|(t, _)| t.count)
        .sum();
    let max_error_i: u64 = if k == 0 { 0 } else { tuples[k - 1].max_error };
    let max_error_ip1: u64 = if k == cap { 0 } else { tuples[k].max_error };
    let r_min = p_i.saturating_sub(max_error_i);
    let r_max = p_i + max_error_ip1;
    let num = r_min + r_max;
    (num / 2, k, num % 2)
}

impl GkDecodeLeaf {
    pub fn prove_timed(
        &self,
        state: &GkState,
        query: u64,
    ) -> Result<(DecodeProof, Duration, Duration)> {
        let cap = self.params.capacity;
        assert_eq!(state.tuples.len(), cap);
        let t_w = Instant::now();

        let (res, k, rem) = native_estimate(state, query);
        let answer = self.params.release.apply(res);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.commit, state.commit())?;
        pw.set_target(self.t.query, F::from_canonical_u64(query))?;
        pw.set_target(self.t.answer, F::from_canonical_u64(answer))?;
        for (tt, v) in self.t.cells.iter().zip(state.cells()) {
            pw.set_target(*tt, v)?;
        }
        for r in 0..cap {
            pw.set_target(
                self.t.le[r],
                if state.tuples[r].value <= query { F::ONE } else { F::ZERO },
            )?;
        }
        for kk in 0..=cap {
            pw.set_target(self.t.sel[kk], if kk == k { F::ONE } else { F::ZERO })?;
        }
        pw.set_target(self.t.res, F::from_canonical_u64(res))?;
        pw.set_target(self.t.rem, F::from_canonical_u64(rem))?;
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
    use crate::sketch::greenwald_khanna::{apply_batch, GkParams, GkState, GkTuple, GkUpdate};

    fn state() -> GkState {
        let s0 = GkState::empty(GkParams { capacity: 8, batch: 8 });
        let batch = vec![
            GkUpdate::real(5),
            GkUpdate::real(5),
            GkUpdate::real(9),
            GkUpdate::real(12),
            GkUpdate::dummy(),
            GkUpdate::dummy(),
            GkUpdate::dummy(),
            GkUpdate::dummy(),
        ];
        apply_batch(&s0, &batch).0
    }

    /// Native approximate-rank estimate (matches the in-circuit relation).
    fn native_res(s: &GkState, q: u64) -> u64 {
        native_estimate(s, q).0
    }

    #[test]
    fn gk_decode_rank() -> Result<()> {
        let leaf = build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let s = state();
        let (p5, _, _) = leaf.prove_timed(&s, 5)?;
        assert_eq!(p5.answer, native_res(&s, 5));
        p5.verify()?;
        let (p12, _, _) = leaf.prove_timed(&s, 12)?;
        assert_eq!(p12.answer, native_res(&s, 12));
        p12.verify()
    }

    /// With all max_error = 0 the midpoint estimator collapses to the exact
    /// prefix mass: res = exact rank. Pins the estimator to a known value.
    #[test]
    fn gk_decode_matches_exact_rank_when_no_error() -> Result<()> {
        let leaf = build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let s = state();
        assert!(s.tuples.iter().all(|t| t.max_error == 0), "test premise: no error");
        let (p, _, _) = leaf.prove_timed(&s, 8)?;
        assert_eq!(p.answer, s.rank(8), "res = exact rank when max_error = 0");
        assert_eq!(p.answer, 2, "only the two fused 5s counted");
        p.verify()
    }

    /// Exercise the deviation arithmetic with a hand-built state whose
    /// bracketing tuples carry non-zero max_error: the estimator must yield the
    /// midpoint, not the exact prefix mass.
    #[test]
    fn gk_decode_uses_deviation() -> Result<()> {
        let leaf = build_gk_decode(GkDecodeParams { capacity: 6, release: ReleasePolicy::Identity });
        // Value-ascending, dummies first. q = 10: P_i = count(5) + count(10) =
        // 4 + 6 = 10. Left bracket tuple value 10, max_error 2; right bracket
        // tuple value 20, max_error 3. r_min = 8, r_max = 13, num = 21, res = 10.
        let tuples = vec![
            GkTuple::dummy(),
            GkTuple::dummy(),
            GkTuple { value: 5, count: 4, max_error: 1, active: 1 },
            GkTuple { value: 10, count: 6, max_error: 2, active: 1 },
            GkTuple { value: 20, count: 7, max_error: 3, active: 1 },
            GkTuple { value: 30, count: 8, max_error: 4, active: 1 },
        ];
        let s = GkState { tuples, params: GkParams { capacity: 6, batch: 2 } };
        assert_eq!(native_estimate(&s, 10).0, 10, "native midpoint estimate");
        let (p, _, _) = leaf.prove_timed(&s, 10)?;
        assert_eq!(p.answer, 10, "circuit certifies the midpoint estimate");
        p.verify()
    }

    #[test]
    fn gk_decode_below_table() -> Result<()> {
        let leaf = build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let s = state();
        // q = 0: brackets below the smallest active value. res = 0.
        let (p, _, _) = leaf.prove_timed(&s, 0)?;
        assert_eq!(p.answer, native_res(&s, 0));
        assert_eq!(p.answer, 0);
        p.verify()
    }

    #[test]
    fn gk_decode_threshold() -> Result<()> {
        let s = state();
        let res = native_res(&s, 12);
        // Suppresses below θ.
        let leaf =
            build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Threshold(1000) });
        let (p, _, _) = leaf.prove_timed(&s, 12)?;
        assert_eq!(p.answer, 0, "res below θ ⇒ released 0");
        p.verify()?;
        // Passes at or above θ.
        let leaf =
            build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Threshold(1) });
        let (p, _, _) = leaf.prove_timed(&s, 12)?;
        assert_eq!(p.answer, res, "res ≥ θ ⇒ released res");
        p.verify()
    }

    #[test]
    fn gk_decode_rejects_wrong_answer() {
        let leaf = build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let s = state();
        let (res, k, rem) = native_estimate(&s, 5);
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.commit, s.commit()).unwrap();
        pw.set_target(leaf.t.query, F::from_canonical_u64(5)).unwrap();
        pw.set_target(leaf.t.answer, F::from_canonical_u64(res + 1)).unwrap(); // wrong
        for (tt, v) in leaf.t.cells.iter().zip(s.cells()) {
            pw.set_target(*tt, v).unwrap();
        }
        for r in 0..8 {
            pw.set_target(leaf.t.le[r], if s.tuples[r].value <= 5 { F::ONE } else { F::ZERO })
                .unwrap();
        }
        for kk in 0..=8 {
            pw.set_target(leaf.t.sel[kk], if kk == k { F::ONE } else { F::ZERO }).unwrap();
        }
        pw.set_target(leaf.t.res, F::from_canonical_u64(res)).unwrap();
        pw.set_target(leaf.t.rem, F::from_canonical_u64(rem)).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "wrong answer must be rejected");
    }

    /// A forged selector that does not match the bracket boundary must be
    /// rejected by the `Σ k·sel[k] = Σ le_r` check.
    #[test]
    fn gk_decode_rejects_bad_selector() {
        let leaf = build_gk_decode(GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity });
        let s = state();
        let (res, k, rem) = native_estimate(&s, 5);
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.commit, s.commit()).unwrap();
        pw.set_target(leaf.t.query, F::from_canonical_u64(5)).unwrap();
        pw.set_target(leaf.t.answer, F::from_canonical_u64(res)).unwrap();
        for (tt, v) in leaf.t.cells.iter().zip(s.cells()) {
            pw.set_target(*tt, v).unwrap();
        }
        for r in 0..8 {
            pw.set_target(leaf.t.le[r], if s.tuples[r].value <= 5 { F::ONE } else { F::ZERO })
                .unwrap();
        }
        // Bad selector: pick k' = k+1 instead of the true boundary.
        let bad_k = k + 1;
        for kk in 0..=8 {
            pw.set_target(leaf.t.sel[kk], if kk == bad_k { F::ONE } else { F::ZERO }).unwrap();
        }
        pw.set_target(leaf.t.res, F::from_canonical_u64(res)).unwrap();
        pw.set_target(leaf.t.rem, F::from_canonical_u64(rem)).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "wrong selector must be rejected");
    }
}
