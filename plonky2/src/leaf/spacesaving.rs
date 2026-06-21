//! In-circuit SpaceSaving update leaf for plonky2 (Pattern B top-`s`).
//!
//! Port of `../src/sketch/ss_final_full.rs` (the §G single-pass retention) to
//! plonky2's gate model. Pipeline:
//!
//! 1. Bind old state, batch, and new state to Poseidon commitments (PIs).
//! 2. **Union + key-sort**: `combined = old ‖ batch` is permuted (grand-product)
//!    to a key-ascending view; sortedness is range-checked.
//! 3. **Group by key**: adjacency-equality tags (forced by [`is_zero`]) drive a
//!    running count/active sum; segment ends emit the grouped table `G`.
//! 4. **Count-sort + top-`s` split**: `G` is permuted to `(active asc, count
//!    asc)` order; the **last `capacity`** rows (heaviest) become the new state,
//!    the first `batch` are the discarded residual.
//! 5. **Mass conservation**: `Σ new.count + Σ residual.count == Σ old.count +
//!    Σ batch.value`.
//!
//! Because top-`s` retention (unlike linear Count-Min) depends on the grouped
//! counts being *exact*, the grouping tags are forced correct with [`is_zero`]
//! (not the honest-prover shortcut Count-Min can afford).

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::leaf::gadgets::{assert_perm_cols, bind_commit, is_zero, vhash};
use crate::recursion::Node;
use crate::sketch::spacesaving::{batch_cells, build_ss, SsParams, SsState, SsUpdate};

/// Range bits for key sortedness (Goldilocks keeps full keys; benchmarks keep
/// keys below 2^48).
const KEY_BITS: usize = 48;
/// Range bits for grouped counts (and the count-sort key composition).
const COUNT_BITS: usize = 32;

/// Circuit shape; two leaves chain-merge only when both fields match.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SsLeafParams {
    pub capacity: usize,
    pub batch: usize,
}

impl SsLeafParams {
    pub fn total(&self) -> usize {
        self.capacity + self.batch
    }
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity >= 1");
        assert!(self.batch >= 1, "batch >= 1");
    }
    fn as_sketch(&self) -> SsParams {
        SsParams { capacity: self.capacity, batch: self.batch }
    }
}

struct Tgt {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    // old state rows
    ok: Vec<Target>,
    oc: Vec<Target>,
    oa: Vec<Target>,
    // batch rows
    bk: Vec<Target>,
    bv: Vec<Target>,
    ba: Vec<Target>,
    // key-sorted view
    ks: Vec<Target>,
    cs: Vec<Target>,
    az: Vec<Target>,
    key_inv: Vec<Target>,       // inverse for key-diff is_zero (r>=1)
    acc_active_inv: Vec<Target>, // inverse for acc_active is_nonzero
    // count-sorted grouped table
    gskey: Vec<Target>,
    gscount: Vec<Target>,
    gsactive: Vec<Target>,
}

/// A built, reusable SpaceSaving leaf circuit.
pub struct SpaceSavingLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: SsLeafParams,
}

/// Build the SpaceSaving top-`s` circuit for the given shape.
pub fn build_spacesaving_leaf(params: SsLeafParams) -> SpaceSavingLeaf {
    params.validate();
    let SsLeafParams { capacity: cap, batch: m } = params;
    let total = cap + m;

    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let one = b.one();
    let zero = b.zero();

    // ---- Public inputs: (initial, final, batch) commitments ----
    let init_commit = vhash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = vhash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = vhash(&mut b);
    b.register_public_inputs(&batch_commit.elements);

    // ---- Witnesses ----
    let ok = b.add_virtual_targets(cap);
    let oc = b.add_virtual_targets(cap);
    let oa = b.add_virtual_targets(cap);
    let bk = b.add_virtual_targets(m);
    let bv = b.add_virtual_targets(m);
    let ba = b.add_virtual_targets(m);
    let ks = b.add_virtual_targets(total);
    let cs = b.add_virtual_targets(total);
    let az = b.add_virtual_targets(total);
    let key_inv = b.add_virtual_targets(total);
    let acc_active_inv = b.add_virtual_targets(total);
    let gskey = b.add_virtual_targets(total);
    let gscount = b.add_virtual_targets(total);
    let gsactive = b.add_virtual_targets(total);

    // ---- Stage A: commitment binding ----
    let mut init_pre = Vec::with_capacity(3 * cap);
    for i in 0..cap {
        init_pre.push(ok[i]);
        init_pre.push(oc[i]);
        init_pre.push(oa[i]);
    }
    bind_commit(&mut b, init_pre, &init_commit);
    let mut batch_pre = Vec::with_capacity(3 * m);
    for i in 0..m {
        batch_pre.push(bk[i]);
        batch_pre.push(bv[i]);
        batch_pre.push(ba[i]);
    }
    bind_commit(&mut b, batch_pre, &batch_commit);
    // final cells = g_sorted[m..m+cap].
    let mut final_pre = Vec::with_capacity(3 * cap);
    for i in 0..cap {
        final_pre.push(gskey[m + i]);
        final_pre.push(gscount[m + i]);
        final_pre.push(gsactive[m + i]);
    }
    bind_commit(&mut b, final_pre, &final_commit);

    // ---- Stage B: union + key-sort permutation ----
    let comb_key: Vec<Target> = ok.iter().chain(bk.iter()).copied().collect();
    let comb_count: Vec<Target> = oc.iter().chain(bv.iter()).copied().collect();
    let comb_active: Vec<Target> = oa.iter().chain(ba.iter()).copied().collect();
    assert_perm_cols(&mut b, &[&comb_key, &comb_count, &comb_active], &[&ks, &cs, &az]);
    for r in 1..total {
        let diff = b.sub(ks[r], ks[r - 1]);
        let _ = b.split_le(diff, KEY_BITS); // diff >= 0
    }

    // ---- Stage C: adjacency tags (forced via is_zero) ----
    // tag[r] = [ks[r] == ks[r-1]]; tag[0] = 0.
    let mut tag: Vec<Target> = Vec::with_capacity(total);
    tag.push(zero);
    for r in 1..total {
        let diff = b.sub(ks[r], ks[r - 1]);
        tag.push(is_zero(&mut b, diff, key_inv[r]));
    }

    // ---- Stage D: running count/active sums per key segment ----
    let mut acc_count: Vec<Target> = Vec::with_capacity(total);
    let mut acc_active: Vec<Target> = Vec::with_capacity(total);
    acc_count.push(cs[0]);
    acc_active.push(az[0]);
    for r in 1..total {
        let carried_c = b.mul(tag[r], acc_count[r - 1]);
        acc_count.push(b.add(cs[r], carried_c));
        let carried_a = b.mul(tag[r], acc_active[r - 1]);
        acc_active.push(b.add(az[r], carried_a));
    }

    // ---- Stage E: segment-end indicator ----
    // seg_end[r] = (r == total-1) ? 1 : (1 - tag[r+1]).
    let mut seg_end: Vec<Target> = Vec::with_capacity(total);
    for r in 0..total {
        let s = if r + 1 == total { one } else { b.sub(one, tag[r + 1]) };
        seg_end.push(s);
    }

    // ---- Stage F: grouped table G (circuit expressions) ----
    // act_nz[r] = [acc_active[r] != 0]; gactive = seg_end*act_nz;
    // gcount = seg_end*acc_count; gkey = gactive*ks.
    let mut gkey: Vec<Target> = Vec::with_capacity(total);
    let mut gcount: Vec<Target> = Vec::with_capacity(total);
    let mut gactive: Vec<Target> = Vec::with_capacity(total);
    for r in 0..total {
        let zf = is_zero(&mut b, acc_active[r], acc_active_inv[r]);
        let act_nz = b.sub(one, zf);
        let ga = b.mul(seg_end[r], act_nz);
        let gc = b.mul(seg_end[r], acc_count[r]);
        let gk = b.mul(ga, ks[r]);
        gactive.push(ga);
        gcount.push(gc);
        gkey.push(gk);
    }

    // ---- Stage G: count-sort permutation + (active asc, count asc) sortedness ----
    assert_perm_cols(&mut b, &[&gkey, &gcount, &gactive], &[&gskey, &gscount, &gsactive]);
    let big = b.constant(F::from_canonical_u64(1u64 << COUNT_BITS));
    // gsactive bool + gscount range; build sort key active*BIG + count.
    let mut sortkey: Vec<Target> = Vec::with_capacity(total);
    for r in 0..total {
        let am1 = b.sub(gsactive[r], one);
        let boolchk = b.mul(gsactive[r], am1);
        b.connect(boolchk, zero);
        let _ = b.split_le(gscount[r], COUNT_BITS);
        let sk = b.mul_add(gsactive[r], big, gscount[r]);
        sortkey.push(sk);
    }
    for r in 1..total {
        let diff = b.sub(sortkey[r], sortkey[r - 1]);
        let _ = b.split_le(diff, COUNT_BITS + 1); // >= 0
    }

    // ---- Stage H: mass conservation ----
    // Σ gscount == Σ old.count + Σ batch.value.
    let mut lhs = gscount[0];
    for r in 1..total {
        lhs = b.add(lhs, gscount[r]);
    }
    let mut rhs = zero;
    for i in 0..cap {
        rhs = b.add(rhs, oc[i]);
    }
    for i in 0..m {
        rhs = b.add(rhs, bv[i]);
    }
    b.connect(lhs, rhs);

    let data = Arc::new(b.build::<C>());
    SpaceSavingLeaf {
        data,
        t: Tgt {
            init_commit, final_commit, batch_commit,
            ok, oc, oa, bk, bv, ba, ks, cs, az, key_inv, acc_active_inv, gskey, gscount, gsactive,
        },
        params,
    }
}

impl SpaceSavingLeaf {
    /// Prove one SpaceSaving epoch. `index` is the 1-based leaf position.
    pub fn prove(&self, initial: &SsState, batch: &[SsUpdate], index: u64) -> Result<Node> {
        self.prove_timed(initial, batch, index).map(|(n, _, _)| n)
    }

    /// Like [`prove`](Self::prove) but also returns `(witness_gen, prove)`
    /// durations — the EVAL_SPEC §1 phase split (witness build vs. `data.prove`).
    pub fn prove_timed(
        &self,
        initial: &SsState,
        batch: &[SsUpdate],
        index: u64,
    ) -> Result<(Node, std::time::Duration, std::time::Duration)> {
        let t_w = std::time::Instant::now();
        let SsLeafParams { capacity: cap, batch: m } = self.params;
        let total = cap + m;
        assert_eq!(batch.len(), m);
        assert_eq!(initial.params, self.params.as_sketch());

        let build = build_ss(initial, batch);
        let (final_state, _residual) = crate::sketch::spacesaving::apply_batch(initial, batch);

        let init_commit = PoseidonHash::hash_no_pad(&initial.cells());
        let final_commit = PoseidonHash::hash_no_pad(&final_state.cells());
        let batch_commit = PoseidonHash::hash_no_pad(&batch_cells(batch));

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;
        pw.set_hash_target(self.t.batch_commit, batch_commit)?;

        // Old / batch rows.
        for i in 0..cap {
            pw.set_target(self.t.ok[i], F::from_canonical_u64(initial.rows[i].key))?;
            pw.set_target(self.t.oc[i], F::from_canonical_u64(initial.rows[i].count))?;
            pw.set_target(self.t.oa[i], F::from_canonical_u64(initial.rows[i].active))?;
        }
        for i in 0..m {
            pw.set_target(self.t.bk[i], F::from_canonical_u64(batch[i].key))?;
            pw.set_target(self.t.bv[i], F::from_canonical_u64(batch[i].value))?;
            pw.set_target(self.t.ba[i], F::from_canonical_u64(batch[i].active))?;
        }

        // Key-sorted view + inverses.
        let mut acc_active = vec![0u64; total];
        for r in 0..total {
            pw.set_target(self.t.ks[r], F::from_canonical_u64(build.key_sorted[r].key))?;
            pw.set_target(self.t.cs[r], F::from_canonical_u64(build.key_sorted[r].count))?;
            pw.set_target(self.t.az[r], F::from_canonical_u64(build.key_sorted[r].active))?;
            acc_active[r] = build.acc_active[r];
            // key-diff inverse (r>=1).
            let ki = if r == 0 {
                F::ZERO
            } else {
                let diff = F::from_canonical_u64(build.key_sorted[r].key)
                    - F::from_canonical_u64(build.key_sorted[r - 1].key);
                if diff == F::ZERO { F::ZERO } else { diff.inverse() }
            };
            pw.set_target(self.t.key_inv[r], ki)?;
            // acc_active inverse.
            let aa = F::from_canonical_u64(build.acc_active[r]);
            let ai = if aa == F::ZERO { F::ZERO } else { aa.inverse() };
            pw.set_target(self.t.acc_active_inv[r], ai)?;
        }
        let _ = acc_active;

        // Count-sorted grouped table.
        for r in 0..total {
            pw.set_target(self.t.gskey[r], F::from_canonical_u64(build.g_sorted[r].key))?;
            pw.set_target(self.t.gscount[r], F::from_canonical_u64(build.g_sorted[r].count))?;
            pw.set_target(self.t.gsactive[r], F::from_canonical_u64(build.g_sorted[r].active))?;
        }

        let witness = t_w.elapsed();
        let t_p = std::time::Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((Node::leaf(self.data.clone(), proof, init_commit, final_commit, index), witness, prove))
    }
}

/// Convenience: an empty SpaceSaving state of the given shape.
pub fn empty_state(capacity: usize, batch: usize) -> SsState {
    SsState::empty(SsParams { capacity, batch })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};
    use crate::sketch::spacesaving::apply_batch;

    fn p() -> SsLeafParams {
        SsLeafParams { capacity: 4, batch: 4 }
    }

    #[test]
    fn spacesaving_round_trip() -> Result<()> {
        let leaf = build_spacesaving_leaf(p());
        let batch = vec![
            SsUpdate::real(7, 5),
            SsUpdate::real(11, 3),
            SsUpdate::real(7, 2),
            SsUpdate::real(7, 1),
        ];
        let node = leaf.prove(&empty_state(4, 4), &batch, 1)?;
        let (expected, _) = apply_batch(&empty_state(4, 4), &batch);
        assert_eq!(node.final_, expected.commit());
        verify_node(&node)
    }

    #[test]
    fn spacesaving_two_epoch_merge() -> Result<()> {
        let leaf = build_spacesaving_leaf(p());
        let s0 = empty_state(4, 4);
        let b1 = vec![SsUpdate::real(7, 5), SsUpdate::real(11, 3), SsUpdate::real(7, 2), SsUpdate::dummy()];
        let n1 = leaf.prove(&s0, &b1, 1)?;
        let (s1, _) = apply_batch(&s0, &b1);
        let b2 = vec![SsUpdate::real(11, 4), SsUpdate::real(7, 1), SsUpdate::real(20, 9), SsUpdate::dummy()];
        let n2 = leaf.prove(&s1, &b2, 2)?;
        let root = merge(&n1, &n2)?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }

    /// Soundness: a tampered final state (wrong committed result) must be
    /// rejected. We feed an honest batch but claim the empty state as `final`,
    /// which breaks the in-circuit transition.
    #[test]
    fn spacesaving_rejects_wrong_final() {
        let leaf = build_spacesaving_leaf(p());
        // Build a witness by hand where final_commit is the *initial* commit.
        let s0 = empty_state(4, 4);
        let batch = vec![SsUpdate::real(7, 5), SsUpdate::real(11, 3), SsUpdate::dummy(), SsUpdate::dummy()];
        let build = build_ss(&s0, &batch);
        let (cap, m, total) = (4usize, 4usize, 8usize);

        let mut pw = PartialWitness::<F>::new();
        let init_commit = PoseidonHash::hash_no_pad(&s0.cells());
        // WRONG: claim final == initial.
        pw.set_hash_target(leaf.t.init_commit, init_commit).unwrap();
        pw.set_hash_target(leaf.t.final_commit, init_commit).unwrap();
        pw.set_hash_target(leaf.t.batch_commit, PoseidonHash::hash_no_pad(&batch_cells(&batch))).unwrap();
        for i in 0..cap {
            pw.set_target(leaf.t.ok[i], F::from_canonical_u64(s0.rows[i].key)).unwrap();
            pw.set_target(leaf.t.oc[i], F::from_canonical_u64(s0.rows[i].count)).unwrap();
            pw.set_target(leaf.t.oa[i], F::from_canonical_u64(s0.rows[i].active)).unwrap();
        }
        for i in 0..m {
            pw.set_target(leaf.t.bk[i], F::from_canonical_u64(batch[i].key)).unwrap();
            pw.set_target(leaf.t.bv[i], F::from_canonical_u64(batch[i].value)).unwrap();
            pw.set_target(leaf.t.ba[i], F::from_canonical_u64(batch[i].active)).unwrap();
        }
        for r in 0..total {
            pw.set_target(leaf.t.ks[r], F::from_canonical_u64(build.key_sorted[r].key)).unwrap();
            pw.set_target(leaf.t.cs[r], F::from_canonical_u64(build.key_sorted[r].count)).unwrap();
            pw.set_target(leaf.t.az[r], F::from_canonical_u64(build.key_sorted[r].active)).unwrap();
            let ki = if r == 0 { F::ZERO } else {
                let diff = F::from_canonical_u64(build.key_sorted[r].key) - F::from_canonical_u64(build.key_sorted[r - 1].key);
                if diff == F::ZERO { F::ZERO } else { diff.inverse() }
            };
            pw.set_target(leaf.t.key_inv[r], ki).unwrap();
            let aa = F::from_canonical_u64(build.acc_active[r]);
            pw.set_target(leaf.t.acc_active_inv[r], if aa == F::ZERO { F::ZERO } else { aa.inverse() }).unwrap();
            pw.set_target(leaf.t.gskey[r], F::from_canonical_u64(build.g_sorted[r].key)).unwrap();
            pw.set_target(leaf.t.gscount[r], F::from_canonical_u64(build.g_sorted[r].count)).unwrap();
            pw.set_target(leaf.t.gsactive[r], F::from_canonical_u64(build.g_sorted[r].active)).unwrap();
        }
        // The final-commit binding (hash of g_sorted[m..]) cannot equal the
        // initial commit, so proving must fail.
        assert!(leaf.data.prove(pw).is_err(), "wrong final must be rejected");
    }
}
