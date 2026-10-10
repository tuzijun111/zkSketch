//! SpaceSaving **top-`c` query** decode circuit (E3).
//!
//! Implements the paper's *SpaceSaving Top-`c` Query Circuit* (zk1.tex
//! §SpaceSaving Query Circuit). A top-`c` query returns the first `c` active
//! rows of the committed summary under the declared count/key order; \sys
//! answers queries against the closed (committed) state `S_t`.
//!
//! The committed state is an [`SsState`] whose rows are kept in
//! `(active asc, count asc)` order (dummies first, then actives by **ascending**
//! count), so the top heavy hitters (highest counts) are the *last* active
//! rows. The circuit re-hashes the state (binds it to the published commitment),
//! then enforces the paper's checks and releases the top-`c` mass.
//!
//! ## Verification target (paper)
//!
//! Public input is the query size `c`. With `#active = #{active rows}` and
//! `k = min(c, #active)`, the released result table `res` is the first `k`
//! rows of `S_t` under the declared (top-count-first) order, with canonical
//! dummy rows beyond position `k`. For the identity release policy the circuit
//! binds the published answer to `res` (here: the released top-`c` mass
//! `Σ res[z].count`, a deterministic function of the fully-pinned `res`).
//!
//! ## Checks
//!
//! 1. **State opening** — re-hash the `capacity` rows, bind to `Com(S_t)`.
//! 2. **Active-prefix structure** — active flags are monotone (here a
//!    contiguous *suffix*: dummies first, actives last).
//! 3. **Distinct-key** — adjacent active rows carry distinct keys (the grouped
//!    summary has no duplicate retained keys); witnessed inverse.
//! 4. **Sortedness** — counts non-decreasing along the stored order
//!    (range-checked adjacent diff); equivalently the top heavy hitters are
//!    the trailing rows.
//! 5. **Top-`c` selection** — a monotone 0/1 selector `sel` marks exactly
//!    `k = min(c, #active)` rows as released: a *suffix* of the row array
//!    (the highest-count actives), each selected row active, and
//!    `Σ sel = min(c, #active)`.
//! 6. **Release binding** — identity / threshold over the released mass
//!    `Σ sel·count` (shared [`bind_release`], same semantics as the other
//!    decode leaves).

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
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::leaf::gadgets::{bind_commit, is_zero, vhash};
use crate::sketch::spacesaving::SsState;

const COUNT_BITS: usize = 32;
/// Range-check window for the count-sortedness diff and the `c − Σsel ≥ 0`
/// selection bound. Counts/`c` fit in `< 2^32` at prototype scale; a "negative"
/// diff wraps past `p` and overflows the `split_le`, soundly rejecting.
const DIFF_BITS: usize = 40;

#[derive(Copy, Clone, Debug)]
pub struct SsDecodeParams {
    pub capacity: usize,
    /// Query size `c` — release the top-`c` heavy hitters by count.
    pub c: usize,
    pub release: ReleasePolicy,
}

struct Tgt {
    commit: HashOutTarget,
    c: Target,
    answer: Target,
    cells: Vec<Target>,   // [key,count,active] * capacity
    sel: Vec<Target>,     // top-c selector per row
    key_inv: Vec<Target>, // distinct-key inverse per adjacent active pair
    flag: Option<Target>,
    mass: Target,
}

pub struct SsDecodeLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: SsDecodeParams,
}

pub fn build_ss_decode(params: SsDecodeParams) -> SsDecodeLeaf {
    let SsDecodeParams { capacity: cap, c: _c, release } = params;
    assert!(cap >= 1, "capacity must be positive");
    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());
    let one = b.one();
    let zero = b.zero();

    let commit = vhash(&mut b);
    b.register_public_inputs(&commit.elements);
    // Public query size `c`.
    let c = b.add_virtual_target();
    b.register_public_input(c);
    let answer = b.add_virtual_target();
    b.register_public_input(answer);

    let cells = b.add_virtual_targets(3 * cap);
    let sel = b.add_virtual_targets(cap);
    let key_inv = b.add_virtual_targets(cap.saturating_sub(1));
    let mass = b.add_virtual_target();

    // ── Check 1: open the committed state ──
    bind_commit(&mut b, cells.clone(), &commit);

    let key_of = |r: usize| cells[3 * r];
    let count_of = |r: usize| cells[3 * r + 1];
    let active_of = |r: usize| cells[3 * r + 2];

    // ── Check 2: active-prefix structure (active monotone non-decreasing) ──
    // Stored order puts dummies first, actives last → actives form a suffix.
    for r in 0..cap {
        // active ∈ {0,1}.
        let a = active_of(r);
        let am1 = b.sub(a, one);
        let bchk = b.mul(a, am1);
        b.connect(bchk, zero);
    }
    for r in 0..cap - 1 {
        // active[r+1] − active[r] ∈ {0,1}.
        let d = b.sub(active_of(r + 1), active_of(r));
        let dm1 = b.sub(d, one);
        let prod = b.mul(d, dm1);
        b.connect(prod, zero);
    }

    // ── Check 4: sortedness — counts non-decreasing along the stored order ──
    // count[r+1] − count[r] ≥ 0; range-check via bit-decomposition (a negative
    // diff wraps past p and overflows COUNT_BITS bits). Dummies have count 0 so
    // the dummy→active boundary is also non-negative.
    for r in 0..cap - 1 {
        let diff = b.sub(count_of(r + 1), count_of(r));
        let _ = b.split_le(diff, COUNT_BITS);
    }

    // ── Check 3: distinct-key on adjacent ACTIVE rows ──
    // If active[r]·active[r+1] = 1 then key[r+1] ≠ key[r]. eq = [key[r+1]==key[r]]
    // via the is_zero gadget; force active[r]·active[r+1]·eq = 0.
    for r in 0..cap - 1 {
        let kdiff = b.sub(key_of(r + 1), key_of(r));
        let eq = is_zero(&mut b, kdiff, key_inv[r]);
        let both = b.mul(active_of(r), active_of(r + 1));
        let viol = b.mul(both, eq);
        b.connect(viol, zero);
    }

    // ── Check 5: top-c selection ──
    // sel[r] ∈ {0,1}; sel monotone non-decreasing (a suffix); sel ≤ active;
    // Σ sel = min(c, #active).
    for r in 0..cap {
        // sel ∈ {0,1}.
        let s = sel[r];
        let sm1 = b.sub(s, one);
        let bchk = b.mul(s, sm1);
        b.connect(bchk, zero);
        // sel ≤ active: sel·(1 − active) = 0.
        let one_minus_a = b.sub(one, active_of(r));
        let outside = b.mul(s, one_minus_a);
        b.connect(outside, zero);
    }
    // sel monotone non-decreasing: sel[r+1] − sel[r] ∈ {0,1}.
    for r in 0..cap - 1 {
        let d = b.sub(sel[r + 1], sel[r]);
        let dm1 = b.sub(d, one);
        let prod = b.mul(d, dm1);
        b.connect(prod, zero);
    }
    // n_active = Σ active; sum_sel = Σ sel.
    let mut n_active = zero;
    for r in 0..cap {
        n_active = b.add(n_active, active_of(r));
    }
    let mut sum_sel = zero;
    for r in 0..cap {
        sum_sel = b.add(sum_sel, sel[r]);
    }
    // Σ sel = min(c, #active):
    //   c − Σsel ≥ 0   (range-checked)
    //   (c − Σsel)·(#active − Σsel) = 0   (one bound is tight)
    // With sel ≤ active (⇒ Σsel ≤ #active), this pins Σsel = min(c,#active).
    let c_minus_sel = b.sub(c, sum_sel);
    let _ = b.split_le(c_minus_sel, DIFF_BITS);
    let act_minus_sel = b.sub(n_active, sum_sel);
    let prod = b.mul(c_minus_sel, act_minus_sel);
    b.connect(prod, zero);

    // ── released mass = Σ sel·count ──
    let mut acc = zero;
    for r in 0..cap {
        let contrib = b.mul(sel[r], count_of(r));
        acc = b.add(acc, contrib);
    }
    b.connect(acc, mass);

    // ── Check 6: release policy → answer (shared with the GK decode) ──
    let flag = bind_release(&mut b, mass, release, answer, COUNT_BITS, one, zero);

    let data = Arc::new(crate::config::build_circuit(b));
    SsDecodeLeaf { data, t: Tgt { commit, c, answer, cells, sel, key_inv, flag, mass }, params }
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

/// Native top-`c` selection over a stored SpaceSaving state.
///
/// The rows are in `(active asc, count asc)` order, so the top heavy hitters
/// by count are the trailing rows. Returns the per-row 0/1 selector for the
/// released top-`min(c, #active)` rows (a suffix), and the released mass.
fn native_select(state: &SsState, c: usize) -> (Vec<u64>, u64) {
    let cap = state.rows.len();
    let n_active = state.rows.iter().filter(|r| r.active == 1).count();
    let k = c.min(n_active);
    let mut sel = vec![0u64; cap];
    for r in (0..cap).rev().take(k) {
        sel[r] = 1;
    }
    let mass: u64 = (0..cap).filter(|&r| sel[r] == 1).map(|r| state.rows[r].count).sum();
    (sel, mass)
}

impl SsDecodeLeaf {
    pub fn prove_timed(&self, state: &SsState, c: usize) -> Result<(DecodeProof, Duration, Duration)> {
        let cap = self.params.capacity;
        assert_eq!(state.rows.len(), cap);
        assert_eq!(c, self.params.c, "c argument must match params.c");
        let t_w = Instant::now();

        let (sel_native, mass) = native_select(state, c);
        let answer = self.params.release.apply(mass);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.commit, state.commit())?;
        pw.set_target(self.t.c, F::from_canonical_u64(c as u64))?;
        pw.set_target(self.t.answer, F::from_canonical_u64(answer))?;
        for (tt, v) in self.t.cells.iter().zip(state.cells()) {
            pw.set_target(*tt, v)?;
        }
        for r in 0..cap {
            pw.set_target(self.t.sel[r], F::from_canonical_u64(sel_native[r]))?;
        }
        for r in 0..cap.saturating_sub(1) {
            let kdiff = F::from_canonical_u64(state.rows[r + 1].key)
                - F::from_canonical_u64(state.rows[r].key);
            pw.set_target(self.t.key_inv[r], if kdiff == F::ZERO { F::ZERO } else { kdiff.inverse() })?;
        }
        pw.set_target(self.t.mass, F::from_canonical_u64(mass))?;
        if let Some(fl) = self.t.flag {
            let t = if let ReleasePolicy::Threshold(t) = self.params.release { t } else { 0 };
            pw.set_target(fl, if mass >= t { F::ONE } else { F::ZERO })?;
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

    /// Build a state with distinct keys 101..104 of weights 1..4 (capacity 4,
    /// batch 4), so the stored rows are ascending count.
    fn state() -> SsState {
        let s0 = SsState::empty(SsParams { capacity: 4, batch: 4 });
        let batch = vec![
            SsUpdate::real(101, 1),
            SsUpdate::real(102, 2),
            SsUpdate::real(103, 3),
            SsUpdate::real(104, 4),
        ];
        apply_batch(&s0, &batch).0
    }

    /// Native top-`c` mass: sum of the `min(c, #active)` highest counts.
    fn native_topc_mass(st: &SsState, c: usize) -> u64 {
        let mut counts: Vec<u64> = st.rows.iter().filter(|r| r.active == 1).map(|r| r.count).collect();
        counts.sort_unstable_by(|a, b| b.cmp(a));
        counts.into_iter().take(c).sum()
    }

    #[test]
    fn ss_decode_topc_all() -> Result<()> {
        let st = state();
        assert_eq!(st.active_count(), 4);
        let native = native_topc_mass(&st, 4);
        assert_eq!(native, 10); // 1+2+3+4
        let leaf = build_ss_decode(SsDecodeParams { capacity: 4, c: 4, release: ReleasePolicy::Identity });
        let (proof, _, _) = leaf.prove_timed(&st, 4)?;
        assert_eq!(proof.answer, native, "top-c mass matches native");
        proof.verify()
    }

    #[test]
    fn ss_decode_topc_larger_than_active() -> Result<()> {
        let st = state();
        let native = native_topc_mass(&st, 10);
        assert_eq!(native, 10);
        let leaf = build_ss_decode(SsDecodeParams { capacity: 4, c: 10, release: ReleasePolicy::Identity });
        let (proof, _, _) = leaf.prove_timed(&st, 10)?;
        assert_eq!(proof.answer, native);
        proof.verify()
    }

    #[test]
    fn ss_decode_top2() -> Result<()> {
        let st = state();
        let native = native_topc_mass(&st, 2);
        assert_eq!(native, 7); // 4 + 3
        let leaf = build_ss_decode(SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Identity });
        let (proof, _, _) = leaf.prove_timed(&st, 2)?;
        assert_eq!(proof.answer, native, "top-2 mass = 4 + 3");
        proof.verify()
    }

    #[test]
    fn ss_decode_top1() -> Result<()> {
        let st = state();
        let native = native_topc_mass(&st, 1);
        assert_eq!(native, 4);
        let leaf = build_ss_decode(SsDecodeParams { capacity: 4, c: 1, release: ReleasePolicy::Identity });
        let (proof, _, _) = leaf.prove_timed(&st, 1)?;
        assert_eq!(proof.answer, native, "top-1 mass = 4");
        proof.verify()
    }

    #[test]
    fn ss_decode_threshold_suppresses() -> Result<()> {
        // Top-1 mass = 4 < θ = 1000 ⇒ suppressed to 0.
        let leaf = build_ss_decode(SsDecodeParams { capacity: 4, c: 1, release: ReleasePolicy::Threshold(1000) });
        let (proof, _, _) = leaf.prove_timed(&state(), 1)?;
        assert_eq!(proof.answer, 0, "mass below θ ⇒ released 0");
        proof.verify()
    }

    #[test]
    fn ss_decode_threshold_passes() -> Result<()> {
        // Top-2 mass = 7 ≥ θ = 5 ⇒ released raw.
        let leaf = build_ss_decode(SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Threshold(5) });
        let (proof, _, _) = leaf.prove_timed(&state(), 2)?;
        assert_eq!(proof.answer, 7, "mass 7 ≥ θ=5 ⇒ released raw");
        proof.verify()
    }

    /// Boundary: mass == θ must be released (the `≥` semantics).
    #[test]
    fn ss_decode_threshold_boundary() -> Result<()> {
        let leaf = build_ss_decode(SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Threshold(7) });
        let (proof, _, _) = leaf.prove_timed(&state(), 2)?;
        assert_eq!(proof.answer, 7, "mass 7 == θ=7 ⇒ released raw");
        proof.verify()
    }

    /// Soundness: a tampered answer public input must be rejected.
    #[test]
    fn ss_decode_rejects_wrong_answer() {
        let leaf = build_ss_decode(SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Identity });
        let st = state();
        let (sel_native, _mass) = native_select(&st, 2);
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.commit, st.commit()).unwrap();
        pw.set_target(leaf.t.c, F::from_canonical_u64(2)).unwrap();
        pw.set_target(leaf.t.answer, F::from_canonical_u64(99)).unwrap(); // wrong (true is 7)
        for (tt, v) in leaf.t.cells.iter().zip(st.cells()) {
            pw.set_target(*tt, v).unwrap();
        }
        for r in 0..4 {
            pw.set_target(leaf.t.sel[r], F::from_canonical_u64(sel_native[r])).unwrap();
        }
        for r in 0..3 {
            let kdiff =
                F::from_canonical_u64(st.rows[r + 1].key) - F::from_canonical_u64(st.rows[r].key);
            pw.set_target(leaf.t.key_inv[r], if kdiff == F::ZERO { F::ZERO } else { kdiff.inverse() })
                .unwrap();
        }
        pw.set_target(leaf.t.mass, F::from_canonical_u64(7)).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "wrong answer must be rejected");
    }
}
