//! In-circuit **offline-memory-checking Count-Min leaf (`omc`)** (plonky2 / SNARK).
//! Port of `../src/sketch/countmin_omc.rs`.
//!
//! The sound, **cross-state** Count-Min rebind: it proves the transition against
//! a *non-trivial committed prior state* (no empty-init assumption, no Merkle
//! path) via a single read/write **multiset equality**
//!
//! ```text
//!     M_old ⊎ W  ==  M_new ⊎ R       (as multisets)
//! ```
//!
//! where `M_old = {(a, S_{t-1}[a])}`, `M_new = {(a, S_t[a])}` are the full dense
//! memories (bound to `init_commit`/`final_commit`), `W = {(a_z, N_z)}` the touched
//! writes and `R = {(a_z, O_z)}` the touched reads. Because the encoding binds the
//! address, the multiset forces the prover's claimed old value `O_z` to be the
//! genuinely committed old value, and `N[a_z] = O_z + Δ_z`; untouched addresses are
//! forced `O[u] = N[u]`. This is the only variant that reconciles touched old
//! values against a real committed prior state with no Merkle path.
//!
//! ## plonky2 vs plonky3
//! plonky3 routes the rebind through a `PermuteAir` with an explicit `sigma`.
//! plonky2's grand-product ([`assert_perm_cols`]) is **sigma-free** — it proves
//! multiset equality directly — so both the counter-sort and the `M_old⊎W=M_new⊎R`
//! check are a single `assert_perm_cols`. Each multiset element is the 3-column row
//! `(addr, val, tag)`; the `tag` (1 for real, 0 for inactive dummies) keeps a real
//! `(0,0)` element disjoint from the zero dummies that inactive W/R rows produce.
//!
//! ## Cost
//! `Θ(d·w + n_ctr)` — the dense commit/decompose of both ends plus one grand-product
//! over `d·w + n_ctr` rows. It replaces `one_hot`'s `Θ(batch·d·(d·w))` selector
//! matrix while remaining sound against a committed prior state.

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};

use crate::config::{C, D, F};
use crate::leaf::countmin_final::{apply_update_prf, hash_cell_prf};
use crate::leaf::gadgets::{assert_perm_cols, is_zero, vhash};
use crate::recursion::Node;
use crate::sketch::countmin::{commit_batch, CountMinState, CountMinUpdate};

/// Circuit shape: `d` rows of `w` counters, `batch` records per epoch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmOmcParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CmOmcParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    fn addr_bits(&self) -> usize {
        (self.num_cells().next_power_of_two().trailing_zeros() as usize).max(1)
    }
    pub fn validate(&self) {
        assert!((1..=8).contains(&self.d), "d must be in 1..=8 (two Poseidon digests, 4 rows each)");
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of two >= 2");
        assert!(self.batch >= 1, "batch >= 1");
    }
}

struct Tgt {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    key: Vec<Target>,
    val: Vec<Target>,
    init_cells: Vec<Target>,
    final_cells: Vec<Target>,
    combined_sorted: Vec<Target>,
    val_sorted: Vec<Target>,
    inv_diff: Vec<Target>,
    op_old: Vec<Target>,
}

/// A built, reusable `omc` Count-Min leaf circuit.
pub struct CountMinOmcLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: CmOmcParams,
}

/// Build the `omc` (offline-memory-checking) Count-Min circuit for the shape.
pub fn build_countmin_omc_leaf(params: CmOmcParams) -> CountMinOmcLeaf {
    params.validate();
    let CmOmcParams { d, w, batch: m } = params;
    let num_cells = d * w;
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let addr_bits = params.addr_bits();

    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    // ---- Public inputs: commits only (keys/values stay private) ----
    let init_commit = vhash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = vhash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = vhash(&mut b);
    b.register_public_inputs(&batch_commit.elements);

    // ---- Private witness ----
    let key = b.add_virtual_targets(m);
    let val = b.add_virtual_targets(m);
    let init_cells = b.add_virtual_targets(num_cells); // O[a]
    let final_cells = b.add_virtual_targets(num_cells); // N[a]
    let combined_sorted = b.add_virtual_targets(n_ctr);
    let val_sorted = b.add_virtual_targets(n_ctr);
    let inv_diff = b.add_virtual_targets(n_ctr);
    let op_old = b.add_virtual_targets(n_ctr);

    let one = b.one();
    let zero = b.zero();
    let pow2: Vec<Target> = (0..w_log2).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let row_w: Vec<Target> = (0..d).map(|i| b.constant(F::from_canonical_u64((i * w) as u64))).collect();
    let cell_idx: Vec<Target> =
        (0..num_cells).map(|a| b.constant(F::from_canonical_u64(a as u64))).collect();

    // ---- Stage A: bind both dense states + the batch to their commits ----
    let hi = b.hash_n_to_hash_no_pad::<PoseidonHash>(init_cells.clone());
    for i in 0..4 {
        b.connect(hi.elements[i], init_commit.elements[i]);
    }
    let hf = b.hash_n_to_hash_no_pad::<PoseidonHash>(final_cells.clone());
    for i in 0..4 {
        b.connect(hf.elements[i], final_commit.elements[i]);
    }
    let mut batch_pre: Vec<Target> = Vec::with_capacity(2 * m);
    for k in 0..m {
        batch_pre.push(key[k]);
        batch_pre.push(val[k]);
    }
    let hb = b.hash_n_to_hash_no_pad::<PoseidonHash>(batch_pre);
    for i in 0..4 {
        b.connect(hb.elements[i], batch_commit.elements[i]);
    }

    // ---- Stage F: per-record PRF — payload (combined = i·w + pos, value) ----
    // Row digests: `Poseidon([key])` covers rows 0..4; a second, domain-separated
    // `Poseidon([key, 1])` covers rows 4..8 (so d up to 8). This MUST match the
    // native `hash_cell_prf` family (same inputs, same row→element assignment).
    let dom = b.constant(F::from_canonical_u64(1));
    let mut payload_combined: Vec<Target> = Vec::with_capacity(n_ctr);
    let mut payload_value: Vec<Target> = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let digest0 = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![key[k]]);
        let digest1 = (d > 4).then(|| b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![key[k], dom]));
        for i in 0..d {
            let elem = if i < 4 {
                digest0.elements[i]
            } else {
                digest1.as_ref().expect("digest1 built for d>4").elements[i - 4]
            };
            let bits = b.split_le(elem, 64);
            let mut pos = b.mul(bits[0].target, pow2[0]);
            for jb in 1..w_log2 {
                let term = b.mul(bits[jb].target, pow2[jb]);
                pos = b.add(pos, term);
            }
            let comb = b.add(row_w[i], pos);
            payload_combined.push(comb);
            payload_value.push(val[k]);
        }
    }

    // ---- Stage G: counter sort (multiset of (combined, value) pairs) ----
    assert_perm_cols(
        &mut b,
        &[&payload_combined, &payload_value],
        &[&combined_sorted, &val_sorted],
    );

    // ---- Stage H: adjacency / sortedness / running sum / active flags ----
    // eq_tag[r] = [combined_sorted[r] == combined_sorted[r-1]] (forced via is_zero).
    let mut eq_tag: Vec<Target> = Vec::with_capacity(n_ctr);
    eq_tag.push(zero); // r = 0
    for r in 1..n_ctr {
        let diff = b.sub(combined_sorted[r], combined_sorted[r - 1]);
        let tag = is_zero(&mut b, diff, inv_diff[r]);
        eq_tag.push(tag);
        // sortedness: gap = combined_sorted[r] - combined_sorted[r-1] ∈ [0, 2^addr_bits).
        let _ = b.split_le(diff, addr_bits);
    }
    // running sum: acc[0] = val_sorted[0]; acc[r] = val_sorted[r] + eq_tag[r]·acc[r-1].
    let mut acc: Vec<Target> = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        acc.push(b.add(val_sorted[r], carried));
    }
    // a_active[r] = (r == last) ? 1 : (1 - eq_tag[r+1]).
    let mut a_active: Vec<Target> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        a_active.push(if r == n_ctr - 1 { one } else { b.sub(one, eq_tag[r + 1]) });
    }

    // ---- Multiset rebind: M_old ⊎ W == M_new ⊎ R (3 columns: addr, val, tag) ----
    let l = num_cells + n_ctr;
    let mut addr_in: Vec<Target> = Vec::with_capacity(l);
    let mut val_in: Vec<Target> = Vec::with_capacity(l);
    let mut tag_in: Vec<Target> = Vec::with_capacity(l);
    let mut addr_out: Vec<Target> = Vec::with_capacity(l);
    let mut val_out: Vec<Target> = Vec::with_capacity(l);
    let mut tag_out: Vec<Target> = Vec::with_capacity(l);
    // Dense cells: M_old = (a, O[a], 1), M_new = (a, N[a], 1).
    for a in 0..num_cells {
        addr_in.push(cell_idx[a]);
        val_in.push(init_cells[a]);
        tag_in.push(one);
        addr_out.push(cell_idx[a]);
        val_out.push(final_cells[a]);
        tag_out.push(one);
    }
    // Touched rows: W = active·(addr, O_z+Δ, 1), R = active·(addr, O_z, 1).
    for r in 0..n_ctr {
        let n_z = b.add(op_old[r], acc[r]);
        addr_in.push(b.mul(a_active[r], combined_sorted[r]));
        val_in.push(b.mul(a_active[r], n_z));
        tag_in.push(a_active[r]);
        addr_out.push(b.mul(a_active[r], combined_sorted[r]));
        val_out.push(b.mul(a_active[r], op_old[r]));
        tag_out.push(a_active[r]);
    }
    assert_perm_cols(
        &mut b,
        &[&addr_in, &val_in, &tag_in],
        &[&addr_out, &val_out, &tag_out],
    );

    let data = Arc::new(b.build::<C>());
    CountMinOmcLeaf {
        data,
        t: Tgt {
            init_commit, final_commit, batch_commit, key, val, init_cells, final_cells,
            combined_sorted, val_sorted, inv_diff, op_old,
        },
        params,
    }
}

impl CountMinOmcLeaf {
    /// Prove one epoch from an arbitrary committed `initial` via the multiset
    /// rebind. `index` is the 1-based leaf position.
    pub fn prove(
        &self,
        initial: &CountMinState,
        batch: &[CountMinUpdate],
        index: u64,
    ) -> Result<Node> {
        let CmOmcParams { d, w, batch: m } = self.params;
        assert_eq!(batch.len(), m, "batch length mismatch");
        assert_eq!(initial.d, d, "state.d mismatch");
        assert_eq!(initial.w, w, "state.w mismatch");
        let n_ctr = m * d;

        // Native: final via PRF replay.
        let mut final_state = initial.clone();
        for u in batch {
            apply_update_prf(&mut final_state, u);
        }
        let init_commit = initial.commit();
        let final_commit = final_state.commit();
        let batch_commit = commit_batch(batch);

        // Per-(record,row) payloads, then stable-sort by combined address.
        let mut u_ctr: Vec<(u64, u64)> = Vec::with_capacity(n_ctr);
        for u in batch {
            for i in 0..d {
                let bucket = hash_cell_prf(i, u.key, w);
                u_ctr.push(((i * w + bucket) as u64, u.value));
            }
        }
        let mut sorted = u_ctr.clone();
        sorted.sort_by_key(|&(c, _)| c);
        let combined_sorted: Vec<u64> = sorted.iter().map(|&(c, _)| c).collect();
        let val_sorted: Vec<u64> = sorted.iter().map(|&(_, v)| v).collect();
        // op_old[r] = O[combined_sorted[r]] (genuine committed old value).
        let op_old: Vec<u64> = combined_sorted
            .iter()
            .map(|&a| initial.counters[a as usize / w][a as usize % w])
            .collect();

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;
        pw.set_hash_target(self.t.batch_commit, batch_commit)?;
        for (k, u) in batch.iter().enumerate() {
            pw.set_target(self.t.key[k], F::from_canonical_u64(u.key))?;
            pw.set_target(self.t.val[k], F::from_canonical_u64(u.value))?;
        }
        for (t, v) in self.t.init_cells.iter().zip(initial.cells()) {
            pw.set_target(*t, v)?;
        }
        for (t, v) in self.t.final_cells.iter().zip(final_state.cells()) {
            pw.set_target(*t, v)?;
        }
        for r in 0..n_ctr {
            pw.set_target(self.t.combined_sorted[r], F::from_canonical_u64(combined_sorted[r]))?;
            pw.set_target(self.t.val_sorted[r], F::from_canonical_u64(val_sorted[r]))?;
            pw.set_target(self.t.op_old[r], F::from_canonical_u64(op_old[r]))?;
            // inv_diff[r] = (combined_sorted[r] - combined_sorted[r-1])^{-1} or 0.
            let inv = if r == 0 || combined_sorted[r] == combined_sorted[r - 1] {
                F::ZERO
            } else {
                let diff = F::from_canonical_u64(combined_sorted[r])
                    - F::from_canonical_u64(combined_sorted[r - 1]);
                diff.inverse()
            };
            pw.set_target(self.t.inv_diff[r], inv)?;
        }

        let proof = self.data.prove(pw)?;
        Ok(Node::leaf(self.data.clone(), proof, init_commit, final_commit, index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};
    use crate::sketch::countmin::CountMinParams;

    fn prior_with(d: usize, w: usize, seed: &[(u64, u64)]) -> CountMinState {
        let mut s = CountMinState::new(&CountMinParams { d, w });
        for &(k, v) in seed {
            apply_update_prf(&mut s, &CountMinUpdate { key: k, value: v });
        }
        s
    }

    fn check(node: &Node, initial: &CountMinState, batch: &[CountMinUpdate]) {
        let mut s = initial.clone();
        for u in batch {
            apply_update_prf(&mut s, u);
        }
        assert_eq!(node.initial, initial.commit(), "initial commit");
        assert_eq!(node.final_, s.commit(), "final commit");
    }

    /// The whole point: a **non-empty** committed prior state, reconciled by the
    /// multiset rebind.
    #[test]
    fn omc_round_trip_nonempty_prior() -> Result<()> {
        let params = CmOmcParams { d: 2, w: 4, batch: 2 };
        let leaf = build_countmin_omc_leaf(params);
        let prior = prior_with(2, 4, &[(3, 4), (9, 2)]);
        let batch = vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 9, value: 5 }];
        let node = leaf.prove(&prior, &batch, 1)?;
        check(&node, &prior, &batch);
        assert_ne!(node.initial, node.final_);
        verify_node(&node)
    }

    /// Repeated keys across a non-empty prior: the running sum folds duplicates
    /// into one read/write pair, reconciled against the prior.
    #[test]
    fn omc_repeated_keys_nonempty() -> Result<()> {
        let params = CmOmcParams { d: 4, w: 8, batch: 4 };
        let leaf = build_countmin_omc_leaf(params);
        let prior = prior_with(4, 8, &[(7, 10)]);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let node = leaf.prove(&prior, &batch, 1)?;
        check(&node, &prior, &batch);
        verify_node(&node)
    }

    /// Two adjacent omc epochs thread by boundary and recursively merge.
    #[test]
    fn omc_two_leaf_merge() -> Result<()> {
        let params = CmOmcParams { d: 2, w: 4, batch: 2 };
        let leaf = build_countmin_omc_leaf(params);
        let s0 = prior_with(2, 4, &[(1, 2)]);
        let batch1 = vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }];
        let n1 = leaf.prove(&s0, &batch1, 1)?;
        let mut s1 = s0.clone();
        for u in &batch1 {
            apply_update_prf(&mut s1, u);
        }
        let batch2 = vec![CountMinUpdate { key: 7, value: 1 }, CountMinUpdate { key: 13, value: 9 }];
        let n2 = leaf.prove(&s1, &batch2, 2)?;
        let root = merge(&n1, &n2)?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }

    /// Tamper: committing a corrupted final state (one cell bumped) while the
    /// batch is honest breaks the multiset equality, so proving fails.
    #[test]
    fn tamper_rejected() {
        let params = CmOmcParams { d: 2, w: 4, batch: 2 };
        let leaf = build_countmin_omc_leaf(params);
        let prior = prior_with(2, 4, &[]);
        let batch = vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }];

        // Build a corrupted final state and drive the witness with it directly.
        let mut final_state = prior.clone();
        for u in &batch {
            apply_update_prf(&mut final_state, u);
        }
        let mut corrupted = final_state.clone();
        corrupted.counters[0][0] = corrupted.counters[0][0].wrapping_add(1);

        // Re-run prove but with the corrupted final cells / commit: easiest is to
        // call the leaf with a state whose replay does NOT match the commit. We
        // emulate that by proving a batch that yields `final_state` but asserting
        // against a bumped commit — done by a hand-built witness below.
        let n_ctr = params.batch * params.d;
        let mut u_ctr: Vec<(u64, u64)> = Vec::new();
        for u in &batch {
            for i in 0..params.d {
                let bucket = hash_cell_prf(i, u.key, params.w);
                u_ctr.push(((i * params.w + bucket) as u64, u.value));
            }
        }
        u_ctr.sort_by_key(|&(c, _)| c);
        let combined_sorted: Vec<u64> = u_ctr.iter().map(|&(c, _)| c).collect();
        let val_sorted: Vec<u64> = u_ctr.iter().map(|&(_, v)| v).collect();
        let op_old: Vec<u64> = combined_sorted
            .iter()
            .map(|&a| prior.counters[a as usize / params.w][a as usize % params.w])
            .collect();

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.init_commit, prior.commit()).unwrap();
        // Corrupted final commit (does not match the honest transition).
        pw.set_hash_target(leaf.t.final_commit, corrupted.commit()).unwrap();
        pw.set_hash_target(leaf.t.batch_commit, commit_batch(&batch)).unwrap();
        for (k, u) in batch.iter().enumerate() {
            pw.set_target(leaf.t.key[k], F::from_canonical_u64(u.key)).unwrap();
            pw.set_target(leaf.t.val[k], F::from_canonical_u64(u.value)).unwrap();
        }
        for (t, v) in leaf.t.init_cells.iter().zip(prior.cells()) {
            pw.set_target(*t, v).unwrap();
        }
        // Commit binds the corrupted cells, so the dense witness must be corrupted too.
        for (t, v) in leaf.t.final_cells.iter().zip(corrupted.cells()) {
            pw.set_target(*t, v).unwrap();
        }
        for r in 0..n_ctr {
            pw.set_target(leaf.t.combined_sorted[r], F::from_canonical_u64(combined_sorted[r])).unwrap();
            pw.set_target(leaf.t.val_sorted[r], F::from_canonical_u64(val_sorted[r])).unwrap();
            pw.set_target(leaf.t.op_old[r], F::from_canonical_u64(op_old[r])).unwrap();
            let inv = if r == 0 || combined_sorted[r] == combined_sorted[r - 1] {
                F::ZERO
            } else {
                (F::from_canonical_u64(combined_sorted[r]) - F::from_canonical_u64(combined_sorted[r - 1])).inverse()
            };
            pw.set_target(leaf.t.inv_diff[r], inv).unwrap();
        }
        // The corrupted untouched cell makes M_old⊎W ≠ M_new⊎R → prove must fail.
        assert!(leaf.data.prove(pw).is_err(), "corrupted final state must break the multiset equality");
    }
}
