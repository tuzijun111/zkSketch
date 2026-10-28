//! Greenwald–Khanna update leaf that fuses equal-value tuples only (port of ../src/sketch/gk_final_full.rs).

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::leaf::gadgets::{assert_perm_cols, bind_commit, vhash};
use crate::recursion::Node;
use crate::sketch::greenwald_khanna::{
    apply_batch, apply_batch_with_rounds, batch_cells, build_union, fuse_all_rounds,
    num_fusion_rounds, GkParams, GkState, GkUpdate,
};

const VALUE_BITS: usize = 32;

/// Circuit shape; two leaves chain-merge only when both fields match (the
/// fusion-round count is derived from `capacity+batch`, so it matches too).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GkLeafParams {
    pub capacity: usize,
    pub batch: usize,
}

impl GkLeafParams {
    pub fn total(&self) -> usize {
        self.capacity + self.batch
    }
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity >= 1");
        assert!(self.batch >= 1, "batch >= 1");
        assert!(self.total() % 2 == 0, "capacity+batch must be even (pairwise fusion)");
    }
    fn as_sketch(&self) -> GkParams {
        GkParams { capacity: self.capacity, batch: self.batch }
    }
}

/// Per-round witness targets: the fusion decisions and the resorted output.
struct RoundTgt {
    dec: Vec<Target>, // length total/2
    rv: Vec<Target>,
    rc: Vec<Target>,
    rme: Vec<Target>,
    ra: Vec<Target>,
}

struct Tgt {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    // old tuples
    ov: Vec<Target>,
    oc: Vec<Target>,
    ome: Vec<Target>,
    oa: Vec<Target>,
    // batch (value, active); tuple count = active, max_error = 0
    bv: Vec<Target>,
    ba: Vec<Target>,
    // sorted union (round-0 input)
    uv: Vec<Target>,
    uc: Vec<Target>,
    ume: Vec<Target>,
    ua: Vec<Target>,
    rounds: Vec<RoundTgt>,
}

/// A built, reusable GK leaf circuit.
pub struct GreenwaldKhannaLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: GkLeafParams,
    pub fusion_rounds: usize,
}

/// Compute one parity-0 fusion round's output columns as circuit expressions,
/// enforcing the eligibility implication for each `decision` bit.
#[allow(clippy::too_many_arguments)]
fn fuse_pairs(
    b: &mut CircuitBuilder<F, D>,
    iv: &[Target],
    ic: &[Target],
    ime: &[Target],
    ia: &[Target],
    dec: &[Target],
    theta_t: Target,
) -> (Vec<Target>, Vec<Target>, Vec<Target>, Vec<Target>) {
    let total = iv.len();
    let one = b.one();
    let zero = b.zero();
    let mut fv = vec![zero; total];
    let mut fc = vec![zero; total];
    let mut fme = vec![zero; total];
    let mut fa = vec![zero; total];
    for i in 0..total / 2 {
        let (l, r) = (2 * i, 2 * i + 1);
        let de = dec[i];
        // decision is boolean.
        let dm1 = b.sub(de, one);
        let boolchk = b.mul(de, dm1);
        b.connect(boolchk, zero);
        // eligibility: decision=1 ⇒ both active and equal value.
        let not_al = b.sub(one, ia[l]);
        let c1 = b.mul(de, not_al);
        b.connect(c1, zero);
        let not_ar = b.sub(one, ia[r]);
        let c2 = b.mul(de, not_ar);
        b.connect(c2, zero);
        let vdiff = b.sub(iv[l], iv[r]);
        let c3 = b.mul(de, vdiff);
        b.connect(c3, zero);

        // Step 4 (§5.4 GK band-threshold gate): fusion is decided by the
        // threshold, not freely by the prover — a fused pair's merged band
        // (count_l + count_r + maxerr_l + maxerr_r) must fit under θ_t. We take
        // θ_t = N_t (total active mass), the GK band at ε = 1/2 — a generous
        // calibration that never blocks a legitimate exact-value merge yet
        // installs the real gate (mirrors the plonky3 gk_final_full Step 4).
        // Encoding: range-check `decision · (θ_t − band) ≥ 0`; when decision = 0
        // the product is 0 (no constraint), when decision = 1 it forces band ≤ θ_t.
        let band_ab = b.add(ic[l], ic[r]);
        let band_err = b.add(ime[l], ime[r]);
        let band = b.add(band_ab, band_err);
        let slack = b.sub(theta_t, band);
        let gated_slack = b.mul(de, slack);
        let _ = b.split_le(gated_slack, VALUE_BITS + 1); // de=1 ⇒ band ≤ θ_t

        let keep = b.sub(one, de); // 1 - decision
        // slot 2i: dummied when fused.
        fv[l] = b.mul(iv[l], keep);
        fc[l] = b.mul(ic[l], keep);
        fme[l] = b.mul(ime[l], keep);
        fa[l] = b.mul(ia[l], keep);
        // slot 2i+1: absorbs the pair when fused.
        fv[r] = iv[r];
        fc[r] = b.mul_add(de, ic[l], ic[r]); // ic[r] + decision*ic[l]
        fme[r] = b.mul_add(de, ime[l], ime[r]);
        // active = ia[r] + decision*(1 - ia[r]); = 1 when fused (eligible ⇒ ia[r]=1).
        let gain = b.sub(one, ia[r]);
        fa[r] = b.mul_add(de, gain, ia[r]);
    }
    (fv, fc, fme, fa)
}

/// Enforce `(active asc, value asc)` sortedness on a tuple table.
fn assert_value_sorted(b: &mut CircuitBuilder<F, D>, value: &[Target], active: &[Target]) {
    let total = value.len();
    let one = b.one();
    let zero = b.zero();
    let big = b.constant(F::from_canonical_u64(1u64 << VALUE_BITS));
    let mut sortkey = Vec::with_capacity(total);
    for r in 0..total {
        // active boolean + value range, then composite key.
        let am1 = b.sub(active[r], one);
        let bc = b.mul(active[r], am1);
        b.connect(bc, zero);
        let _ = b.split_le(value[r], VALUE_BITS);
        sortkey.push(b.mul_add(active[r], big, value[r]));
    }
    for r in 1..total {
        let diff = b.sub(sortkey[r], sortkey[r - 1]);
        let _ = b.split_le(diff, VALUE_BITS + 1); // >= 0
    }
}

/// Build the GK fusion circuit for the given shape.
pub fn build_gk_leaf(params: GkLeafParams) -> GreenwaldKhannaLeaf {
    let total = params.capacity + params.batch;
    build_gk_leaf_with_rounds(params, num_fusion_rounds(total))
}

/// Like [`build_gk_leaf`] but builds the circuit with exactly `fusion_rounds`
/// parity-0 fusion rounds — the paper-sanctioned public round-count knob
/// (mirrors plonky3's `prove_gk_full_with_rounds`). Capping below the worst
/// case `num_fusion_rounds(capacity+batch)` cuts prover cost ~linearly in the
/// round count; it is exact when no value repeats more than `2^fusion_rounds`
/// times within the union, else it under-fuses gracefully (still sorted +
/// mass-conserved). The verification key depends on `fusion_rounds`, so two
/// leaves chain-merge only when they share it.
pub fn build_gk_leaf_with_rounds(params: GkLeafParams, fusion_rounds: usize) -> GreenwaldKhannaLeaf {
    params.validate();
    assert!(fusion_rounds >= 1, "need at least one fusion round");
    let GkLeafParams { capacity: cap, batch: m } = params;
    let total = cap + m;

    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());
    let zero = b.zero();

    // ---- Public inputs ----
    let init_commit = vhash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = vhash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = vhash(&mut b);
    b.register_public_inputs(&batch_commit.elements);

    // ---- Witnesses ----
    let ov = b.add_virtual_targets(cap);
    let oc = b.add_virtual_targets(cap);
    let ome = b.add_virtual_targets(cap);
    let oa = b.add_virtual_targets(cap);
    let bv = b.add_virtual_targets(m);
    let ba = b.add_virtual_targets(m);
    let uv = b.add_virtual_targets(total);
    let uc = b.add_virtual_targets(total);
    let ume = b.add_virtual_targets(total);
    let ua = b.add_virtual_targets(total);
    let rounds: Vec<RoundTgt> = (0..fusion_rounds)
        .map(|_| RoundTgt {
            dec: b.add_virtual_targets(total / 2),
            rv: b.add_virtual_targets(total),
            rc: b.add_virtual_targets(total),
            rme: b.add_virtual_targets(total),
            ra: b.add_virtual_targets(total),
        })
        .collect();

    // ---- Stage A: commitment binding ----
    let mut init_pre = Vec::with_capacity(4 * cap);
    for i in 0..cap {
        init_pre.extend_from_slice(&[ov[i], oc[i], ome[i], oa[i]]);
    }
    bind_commit(&mut b, init_pre, &init_commit);
    let mut batch_pre = Vec::with_capacity(4 * m);
    for i in 0..m {
        // batch tuple = (value, active, 0, active).
        batch_pre.extend_from_slice(&[bv[i], ba[i], zero, ba[i]]);
    }
    bind_commit(&mut b, batch_pre, &batch_commit);
    // final = last round's resorted[m..m+cap].
    let last = &rounds[fusion_rounds - 1];
    let mut final_pre = Vec::with_capacity(4 * cap);
    for i in 0..cap {
        final_pre.extend_from_slice(&[last.rv[m + i], last.rc[m + i], last.rme[m + i], last.ra[m + i]]);
    }
    bind_commit(&mut b, final_pre, &final_commit);

    // ---- Stage B: union + value-sort ----
    let comb_v: Vec<Target> = ov.iter().chain(bv.iter()).copied().collect();
    let comb_c: Vec<Target> = oc.iter().chain(ba.iter()).copied().collect(); // batch count = active
    let comb_me: Vec<Target> = ome.iter().chain(std::iter::repeat(&zero).take(m)).copied().collect();
    let comb_a: Vec<Target> = oa.iter().chain(ba.iter()).copied().collect();
    assert_perm_cols(&mut b, &[&comb_v, &comb_c, &comb_me, &comb_a], &[&uv, &uc, &ume, &ua]);
    assert_value_sorted(&mut b, &uv, &ua);

    // θ_t = N_t = total active mass of the union (Σ active·count); the Step-4
    // band gate (in `fuse_pairs`) bounds every fused pair under it.
    let mut theta_t = zero;
    for r in 0..total {
        theta_t = b.mul_add(ua[r], uc[r], theta_t); // ua[r]·uc[r] + acc
    }

    // ---- Stage C: L fusion rounds ----
    let (mut iv, mut ic, mut ime_cur, mut ia) = (uv.clone(), uc.clone(), ume.clone(), ua.clone());
    for rd in &rounds {
        let (fv, fc, fme, fa) = fuse_pairs(&mut b, &iv, &ic, &ime_cur, &ia, &rd.dec, theta_t);
        // resorted = perm(fused), sorted by (active asc, value asc).
        assert_perm_cols(&mut b, &[&fv, &fc, &fme, &fa], &[&rd.rv, &rd.rc, &rd.rme, &rd.ra]);
        assert_value_sorted(&mut b, &rd.rv, &rd.ra);
        iv = rd.rv.clone();
        ic = rd.rc.clone();
        ime_cur = rd.rme.clone();
        ia = rd.ra.clone();
    }

    // ---- Stage D: mass conservation ----
    // Σ final-table count == Σ old.count + Σ batch.active.
    let mut lhs = ic[0];
    for r in 1..total {
        lhs = b.add(lhs, ic[r]);
    }
    let mut rhs = zero;
    for i in 0..cap {
        rhs = b.add(rhs, oc[i]);
    }
    for i in 0..m {
        rhs = b.add(rhs, ba[i]);
    }
    b.connect(lhs, rhs);

    let data = Arc::new(crate::config::build_circuit(b));
    GreenwaldKhannaLeaf {
        data,
        t: Tgt {
            init_commit, final_commit, batch_commit,
            ov, oc, ome, oa, bv, ba, uv, uc, ume, ua, rounds,
        },
        params,
        fusion_rounds,
    }
}

impl GreenwaldKhannaLeaf {
    /// Prove one GK epoch. `index` is the 1-based leaf position.
    pub fn prove(&self, initial: &GkState, batch: &[GkUpdate], index: u64) -> Result<Node> {
        self.prove_timed(initial, batch, index).map(|(n, _, _)| n)
    }

    /// Like [`prove`](Self::prove) but also returns `(witness_gen, prove)`
    /// durations — the EVAL_SPEC §1 phase split.
    pub fn prove_timed(
        &self,
        initial: &GkState,
        batch: &[GkUpdate],
        index: u64,
    ) -> Result<(Node, std::time::Duration, std::time::Duration)> {
        let t_w = std::time::Instant::now();
        let GkLeafParams { capacity: cap, batch: m } = self.params;
        let total = cap + m;
        assert_eq!(batch.len(), m);
        assert_eq!(initial.params, self.params.as_sketch());

        let union = build_union(initial, batch);
        let (_fused_final, round_data) = fuse_all_rounds(&union, self.fusion_rounds);
        // Final state from EXACTLY `self.fusion_rounds` rounds, so it matches the
        // round witness above (the leaf may be built with a capped round count).
        let (final_state, _excess) = apply_batch_with_rounds(initial, batch, self.fusion_rounds);

        let init_commit = PoseidonHash::hash_no_pad(&initial.cells());
        let final_commit = PoseidonHash::hash_no_pad(&final_state.cells());
        let batch_commit = PoseidonHash::hash_no_pad(&batch_cells(batch));

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;
        pw.set_hash_target(self.t.batch_commit, batch_commit)?;

        for i in 0..cap {
            pw.set_target(self.t.ov[i], F::from_canonical_u64(initial.tuples[i].value))?;
            pw.set_target(self.t.oc[i], F::from_canonical_u64(initial.tuples[i].count))?;
            pw.set_target(self.t.ome[i], F::from_canonical_u64(initial.tuples[i].max_error))?;
            pw.set_target(self.t.oa[i], F::from_canonical_u64(initial.tuples[i].active))?;
        }
        for i in 0..m {
            pw.set_target(self.t.bv[i], F::from_canonical_u64(batch[i].value))?;
            pw.set_target(self.t.ba[i], F::from_canonical_u64(batch[i].active))?;
        }
        for r in 0..total {
            pw.set_target(self.t.uv[r], F::from_canonical_u64(union[r].value))?;
            pw.set_target(self.t.uc[r], F::from_canonical_u64(union[r].count))?;
            pw.set_target(self.t.ume[r], F::from_canonical_u64(union[r].max_error))?;
            pw.set_target(self.t.ua[r], F::from_canonical_u64(union[r].active))?;
        }
        for (rd_t, rd_n) in self.t.rounds.iter().zip(round_data.iter()) {
            for i in 0..total / 2 {
                pw.set_target(rd_t.dec[i], F::from_canonical_u64(rd_n.decisions[i] as u64))?;
            }
            for r in 0..total {
                pw.set_target(rd_t.rv[r], F::from_canonical_u64(rd_n.resorted[r].value))?;
                pw.set_target(rd_t.rc[r], F::from_canonical_u64(rd_n.resorted[r].count))?;
                pw.set_target(rd_t.rme[r], F::from_canonical_u64(rd_n.resorted[r].max_error))?;
                pw.set_target(rd_t.ra[r], F::from_canonical_u64(rd_n.resorted[r].active))?;
            }
        }

        let witness = t_w.elapsed();
        let t_p = std::time::Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((Node::leaf(self.data.clone(), proof, init_commit, final_commit, index), witness, prove))
    }
}

/// Convenience: an empty GK state of the given shape.
pub fn empty_state(capacity: usize, batch: usize) -> GkState {
    GkState::empty(GkParams { capacity, batch })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};

    fn p() -> GkLeafParams {
        GkLeafParams { capacity: 4, batch: 4 }
    }

    #[test]
    fn gk_round_trip() -> Result<()> {
        let leaf = build_gk_leaf(p());
        let batch =
            vec![GkUpdate::real(5), GkUpdate::real(5), GkUpdate::real(9), GkUpdate::real(5)];
        let node = leaf.prove(&empty_state(4, 4), &batch, 1)?;
        let (expected, _) = apply_batch(&empty_state(4, 4), &batch);
        assert_eq!(node.final_, expected.commit());
        verify_node(&node)
    }

    /// The fusion-round knob: a leaf built with fewer than the worst-case
    /// rounds proves + verifies, and binds the matching capped-round final
    /// state. (cap=4, batch=4 ⇒ worst case num_fusion_rounds(8)=3; here 1.)
    #[test]
    fn gk_capped_rounds_round_trip() -> Result<()> {
        let leaf = build_gk_leaf_with_rounds(p(), 1);
        assert_eq!(leaf.fusion_rounds, 1);
        let batch =
            vec![GkUpdate::real(5), GkUpdate::real(5), GkUpdate::real(9), GkUpdate::real(5)];
        let node = leaf.prove(&empty_state(4, 4), &batch, 1)?;
        let (expected, _) = apply_batch_with_rounds(&empty_state(4, 4), &batch, 1);
        assert_eq!(node.final_, expected.commit());
        verify_node(&node)
    }

    #[test]
    fn gk_two_epoch_merge() -> Result<()> {
        let leaf = build_gk_leaf(p());
        let s0 = empty_state(4, 4);
        let b1 = vec![GkUpdate::real(5), GkUpdate::real(5), GkUpdate::real(9), GkUpdate::dummy()];
        let n1 = leaf.prove(&s0, &b1, 1)?;
        let (s1, _) = apply_batch(&s0, &b1);
        let b2 = vec![GkUpdate::real(9), GkUpdate::real(12), GkUpdate::real(5), GkUpdate::dummy()];
        let n2 = leaf.prove(&s1, &b2, 2)?;
        let root = merge(&n1, &n2)?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }

    /// Soundness: a wrong claimed final (the initial commit) must be rejected.
    #[test]
    fn gk_rejects_wrong_final() {
        let leaf = build_gk_leaf(p());
        let s0 = empty_state(4, 4);
        let batch = vec![GkUpdate::real(5), GkUpdate::real(5), GkUpdate::real(9), GkUpdate::dummy()];
        let union = build_union(&s0, &batch);
        let (_f, round_data) = fuse_all_rounds(&union, leaf.fusion_rounds);
        let (cap, m, total) = (4usize, 4usize, 8usize);

        let mut pw = PartialWitness::<F>::new();
        let init_commit = PoseidonHash::hash_no_pad(&s0.cells());
        pw.set_hash_target(leaf.t.init_commit, init_commit).unwrap();
        pw.set_hash_target(leaf.t.final_commit, init_commit).unwrap(); // WRONG
        pw.set_hash_target(leaf.t.batch_commit, PoseidonHash::hash_no_pad(&batch_cells(&batch))).unwrap();
        for i in 0..cap {
            pw.set_target(leaf.t.ov[i], F::from_canonical_u64(s0.tuples[i].value)).unwrap();
            pw.set_target(leaf.t.oc[i], F::from_canonical_u64(s0.tuples[i].count)).unwrap();
            pw.set_target(leaf.t.ome[i], F::from_canonical_u64(s0.tuples[i].max_error)).unwrap();
            pw.set_target(leaf.t.oa[i], F::from_canonical_u64(s0.tuples[i].active)).unwrap();
        }
        for i in 0..m {
            pw.set_target(leaf.t.bv[i], F::from_canonical_u64(batch[i].value)).unwrap();
            pw.set_target(leaf.t.ba[i], F::from_canonical_u64(batch[i].active)).unwrap();
        }
        for r in 0..total {
            pw.set_target(leaf.t.uv[r], F::from_canonical_u64(union[r].value)).unwrap();
            pw.set_target(leaf.t.uc[r], F::from_canonical_u64(union[r].count)).unwrap();
            pw.set_target(leaf.t.ume[r], F::from_canonical_u64(union[r].max_error)).unwrap();
            pw.set_target(leaf.t.ua[r], F::from_canonical_u64(union[r].active)).unwrap();
        }
        for (rd_t, rd_n) in leaf.t.rounds.iter().zip(round_data.iter()) {
            for i in 0..total / 2 {
                pw.set_target(rd_t.dec[i], F::from_canonical_u64(rd_n.decisions[i] as u64)).unwrap();
            }
            for r in 0..total {
                pw.set_target(rd_t.rv[r], F::from_canonical_u64(rd_n.resorted[r].value)).unwrap();
                pw.set_target(rd_t.rc[r], F::from_canonical_u64(rd_n.resorted[r].count)).unwrap();
                pw.set_target(rd_t.rme[r], F::from_canonical_u64(rd_n.resorted[r].max_error)).unwrap();
                pw.set_target(rd_t.ra[r], F::from_canonical_u64(rd_n.resorted[r].active)).unwrap();
            }
        }
        assert!(leaf.data.prove(pw).is_err(), "wrong final must be rejected");
    }
}
