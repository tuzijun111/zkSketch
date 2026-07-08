//! **§4.3 composition topologies over real recursive proofs.**
//!
//! The sketch-agnostic [`merge`](super::merge) atom composes any two
//! [`Node`]s (a leaf epoch or a merged subtree) into one O(1)-verifiable proof.
//! This module packages the three §4.3 *schedules* over that atom as first-class
//! drivers — the real-proof counterparts of the plaintext
//! [`crate::recursion::framework`] schedules and of the plonky3
//! `countmin_chain` / `hll_chain` / `countmin_forest_v9` aggregators:
//!
//! - [`compose_chain`] — §4.3(a) linear accumulating chain (left-deep fold).
//! - [`compose_tree`]  — §4.3(b) balanced binary tree (power-of-two history).
//! - [`StreamingForest`] — §4.3(c) Bentley–Saxe / MMR binary-counter cascade.
//!
//! It also adds [`merge_cross_family`] — the §4.2 merge atom across *heterogeneous*
//! sketch families (e.g. a Count-Min leaf and a HyperLogLog leaf), with **no
//! shared boundary**, binding both `(initial, final)` pairs under one combined
//! digest. plonky3 needed a dedicated `cross_family_merge` spike for this; on
//! plonky2 it is the same `verify_proof` machinery with the boundary `connect`
//! dropped (each child carries its own `common_data`, so the two circuits may
//! differ).

use std::sync::Arc;

use anyhow::{ensure, Result};
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;

use super::{merge, Node};
use crate::commitment::{combine_digest, leaf_digest};
use crate::config::{C, D, F};

// ─── §4.3(a) Linear accumulating chain ───────────────────────────────────

/// §4.3(a): fold the [`merge`](super::merge) atom left-to-right over a contiguous
/// run of nodes, producing one root whose verification is O(1). Consumes the
/// nodes (each merge reproves). The resulting digest equals
/// [`flat_verify`](super::flat_verify)'s left-deep re-derivation.
pub fn compose_chain(nodes: Vec<Node>) -> Result<Node> {
    ensure!(!nodes.is_empty(), "empty chain");
    let mut it = nodes.into_iter();
    let mut acc = it.next().unwrap();
    for n in it {
        acc = merge(&acc, &n)?;
    }
    Ok(acc)
}

// ─── §4.3(b) Balanced binary tree ────────────────────────────────────────

/// §4.3(b): compose a **power-of-two** number of nodes as a balanced binary
/// tree — disjoint subtrees merge level by level.
pub fn compose_tree(nodes: Vec<Node>) -> Result<Node> {
    ensure!(!nodes.is_empty(), "empty tree");
    ensure!(nodes.len().is_power_of_two(), "compose_tree requires a power-of-two leaf count");
    let mut level = nodes;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut it = level.into_iter();
        while let Some(a) = it.next() {
            let b = it.next().expect("power-of-two ⇒ even level");
            next.push(merge(&a, &b)?);
        }
        level = next;
    }
    Ok(level.pop().unwrap())
}

// ─── §4.3(c) Streaming forest (Bentley–Saxe / MMR cascade) ───────────────

/// §4.3(c): a streaming forest of perfect interval-proof subtrees whose sizes
/// are the powers of two in the binary representation of the current length `t`.
/// Each [`insert`](Self::insert) appends a leaf on the right and runs the
/// binary-counter cascade, merging equal-sized neighbours (the merge composes
/// real recursive proofs, including subtree-with-subtree). [`finalize`](Self::finalize)
/// chains the surviving roots into one `Π[1,t]`.
#[derive(Default)]
pub struct StreamingForest {
    roots: Vec<Node>,
    next_index: u64,
}

impl StreamingForest {
    pub fn new() -> Self {
        Self { roots: Vec::new(), next_index: 1 }
    }

    /// Epochs ingested so far (`t`).
    pub fn len(&self) -> u64 {
        self.next_index - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of surviving subtree roots (`= popcount(t)`).
    pub fn num_trees(&self) -> usize {
        self.roots.len()
    }

    /// Sizes of the surviving roots, earliest→latest (strictly decreasing).
    pub fn root_sizes(&self) -> Vec<u64> {
        self.roots.iter().map(Node::num_leaves).collect()
    }

    /// Insert the next epoch leaf and run the cascade. `node.interval` must be
    /// the single-epoch interval `(next_index, next_index)` (contiguous append).
    pub fn insert(&mut self, node: Node) -> Result<()> {
        ensure!(
            node.interval == (self.next_index, self.next_index),
            "out-of-order insert: expected leaf {}, got interval {:?}",
            self.next_index,
            node.interval
        );
        let mut node = node;
        while let Some(last) = self.roots.last() {
            if last.num_leaves() == node.num_leaves() {
                let left = self.roots.pop().unwrap();
                node = merge(&left, &node)?;
            } else {
                break;
            }
        }
        self.roots.push(node);
        self.next_index += 1;
        Ok(())
    }

    /// Finalize the forest into a single root by chaining the surviving roots
    /// left-to-right (`popcount(t) − 1` on-demand merges). Consumes the forest.
    pub fn finalize(self) -> Result<Node> {
        ensure!(!self.roots.is_empty(), "empty forest");
        compose_chain(self.roots)
    }
}

// ─── §4.2 Cross-family merge (heterogeneous, no shared boundary) ──────────

/// A recursive proof that two *independent* sketch epochs — typically from
/// different families (e.g. Count-Min + HyperLogLog) — are both valid, bound
/// under one combined digest. There is **no shared boundary** (the two states
/// are unrelated), so both `(initial, final)` pairs are exposed.
pub struct CrossFamilyNode {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub data: Arc<CircuitData<F, C, D>>,
    pub a_initial: HashOut<F>,
    pub a_final: HashOut<F>,
    pub b_initial: HashOut<F>,
    pub b_final: HashOut<F>,
    /// Combined ordered digest over the two families' boundaries.
    pub digest: HashOut<F>,
}

/// Combined digest binding both epochs' boundaries (left = a as epoch 1, right =
/// b as epoch 2), mirroring plonky3's `cross_family_merge::combined_digest`.
fn cross_family_digest(
    a_initial: HashOut<F>,
    a_final: HashOut<F>,
    b_initial: HashOut<F>,
    b_final: HashOut<F>,
) -> HashOut<F> {
    let dl = leaf_digest(a_initial, a_final, 1);
    let dr = leaf_digest(b_initial, b_final, 2);
    combine_digest(1, 1, 2, dl, dr)
}

/// §4.2 cross-family merge: verify BOTH child proofs in one circuit (each under
/// its own `common_data`, so the two leaves may be different circuits), expose
/// both boundaries, and bind them under one combined digest. Unlike
/// [`merge`](super::merge) there is **no** `left.final == right.initial` connect.
pub fn merge_cross_family(a: &Node, b: &Node) -> Result<CrossFamilyNode> {
    let mut bld = CircuitBuilder::<F, D>::new(crate::config::circuit_config());

    let apt = bld.add_virtual_proof_with_pis(&a.data.common);
    let bpt = bld.add_virtual_proof_with_pis(&b.data.common);
    let avd = bld.add_virtual_verifier_data(a.data.common.config.fri_config.cap_height);
    let bvd = bld.add_virtual_verifier_data(b.data.common.config.fri_config.cap_height);
    bld.verify_proof::<C>(&apt, &avd, &a.data.common);
    bld.verify_proof::<C>(&bpt, &bvd, &b.data.common);

    // Re-expose both children's boundaries (initial[0..4], final[0..4]); no
    // boundary connect, since the two states are independent.
    for i in 0..8 {
        let t = apt.public_inputs[i];
        bld.register_public_input(t);
    }
    for i in 0..8 {
        let t = bpt.public_inputs[i];
        bld.register_public_input(t);
    }

    let data = bld.build::<C>();

    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&apt, &a.proof)?;
    pw.set_proof_with_pis_target(&bpt, &b.proof)?;
    pw.set_verifier_data_target(&avd, &a.data.verifier_only)?;
    pw.set_verifier_data_target(&bvd, &b.data.verifier_only)?;
    let proof = data.prove(pw)?;

    let digest = cross_family_digest(a.initial, a.final_, b.initial, b.final_);

    Ok(CrossFamilyNode {
        proof,
        data: Arc::new(data),
        a_initial: a.initial,
        a_final: a.final_,
        b_initial: b.initial,
        b_final: b.final_,
        digest,
    })
}

/// Verify a cross-family merge: the single recursive proof is sound, its 16
/// exposed boundary public inputs match the carried commits, and the combined
/// digest re-derives.
pub fn verify_cross_family(n: &CrossFamilyNode) -> Result<()> {
    n.data.verify(n.proof.clone())?;
    let pis = &n.proof.public_inputs;
    ensure!(pis.len() >= 16, "cross-family proof missing boundary public inputs");
    for i in 0..4 {
        ensure!(pis[i] == n.a_initial.elements[i], "exposed a_initial mismatch");
        ensure!(pis[4 + i] == n.a_final.elements[i], "exposed a_final mismatch");
        ensure!(pis[8 + i] == n.b_initial.elements[i], "exposed b_initial mismatch");
        ensure!(pis[12 + i] == n.b_final.elements[i], "exposed b_final mismatch");
    }
    ensure!(
        n.digest == cross_family_digest(n.a_initial, n.a_final, n.b_initial, n.b_final),
        "combined digest mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::countmin::{build_countmin_leaf, CmLeafParams};
    use crate::leaf::hyperloglog::{build_hll_leaf, HllLeafParams};
    use crate::recursion::{flat_verify, verify_node};
    use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
    use crate::sketch::hyperloglog::{HllParams, HllState, HllUpdate};

    fn cm_epochs(batches: &[Vec<CountMinUpdate>]) -> Vec<Node> {
        let params = CmLeafParams { d: 2, w: 4, batch: 2 };
        let leaf = build_countmin_leaf(params);
        let mut state = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        let mut nodes = Vec::new();
        for (i, batch) in batches.iter().enumerate() {
            nodes.push(leaf.prove(&state, batch, (i + 1) as u64).unwrap());
            for u in batch {
                state.update(u);
            }
        }
        nodes
    }

    fn b(k0: u64, v0: u64, k1: u64, v1: u64) -> Vec<CountMinUpdate> {
        vec![CountMinUpdate { key: k0, value: v0 }, CountMinUpdate { key: k1, value: v1 }]
    }

    #[test]
    fn chain_driver_matches_flat_digest() {
        let nodes = cm_epochs(&[b(7, 3, 11, 5), b(7, 1, 13, 9), b(2, 4, 9, 6)]);
        let flat = flat_verify(&nodes).unwrap();
        let root = compose_chain(nodes).unwrap();
        verify_node(&root).unwrap();
        assert_eq!(root.num_leaves(), 3);
        assert_eq!(root.digest, flat);
    }

    #[test]
    fn tree_driver_certifies_outer_boundary() {
        let nodes = cm_epochs(&[b(1, 1, 2, 2), b(3, 3, 4, 4), b(5, 5, 6, 6), b(7, 7, 8, 8)]);
        let (first_initial, last_final) = (nodes[0].initial, nodes[3].final_);
        let root = compose_tree(nodes).unwrap();
        verify_node(&root).unwrap();
        assert_eq!(root.num_leaves(), 4);
        assert_eq!(root.initial, first_initial);
        assert_eq!(root.final_, last_final);
    }

    #[test]
    fn forest_cascade_and_finalize() {
        let nodes = cm_epochs(&[b(1, 1, 2, 2), b(3, 3, 4, 4), b(5, 5, 6, 6)]);
        let (first_initial, last_final) = (nodes[0].initial, nodes[2].final_);
        let mut f = StreamingForest::new();
        for n in nodes {
            f.insert(n).unwrap();
        }
        assert_eq!(f.len(), 3);
        // 3 = 2 + 1 → two surviving roots of sizes 2, 1.
        assert_eq!(f.root_sizes(), vec![2, 1]);
        let root = f.finalize().unwrap();
        verify_node(&root).unwrap();
        assert_eq!(root.num_leaves(), 3);
        assert_eq!(root.initial, first_initial);
        assert_eq!(root.final_, last_final);
    }

    #[test]
    fn forest_power_of_two_matches_tree() {
        let batches = [b(1, 1, 2, 2), b(3, 3, 4, 4)];
        let mut f = StreamingForest::new();
        for n in cm_epochs(&batches) {
            f.insert(n).unwrap();
        }
        assert_eq!(f.num_trees(), 1);
        let froot = f.finalize().unwrap();
        let troot = compose_tree(cm_epochs(&batches)).unwrap();
        // Same balanced shape at a power of two ⇒ identical digest.
        assert_eq!(froot.digest, troot.digest);
    }

    #[test]
    fn cross_family_cm_hll_merge_accepts() {
        // One Count-Min epoch.
        let cm_leaf = build_countmin_leaf(CmLeafParams { d: 2, w: 4, batch: 2 });
        let cm_state = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        let cm = cm_leaf.prove(&cm_state, &b(7, 3, 11, 5), 1).unwrap();

        // One HyperLogLog epoch.
        let hll_leaf = build_hll_leaf(HllLeafParams { b: 3, batch: 2 });
        let hll_state = HllState::new(&HllParams { b: 3 });
        let hll_batch = vec![HllUpdate { key: 0xDEAD_BEEF }, HllUpdate { key: 0xC0FFEE }];
        let hll = hll_leaf.prove(&hll_state, &hll_batch, 1).unwrap();

        let merged = merge_cross_family(&cm, &hll).unwrap();
        verify_cross_family(&merged).unwrap();
        assert_eq!(merged.a_initial, cm.initial);
        assert_eq!(merged.b_final, hll.final_);
    }

    #[test]
    fn cross_family_tamper_rejected() {
        let cm_leaf = build_countmin_leaf(CmLeafParams { d: 2, w: 4, batch: 2 });
        let cm_state = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        let cm = cm_leaf.prove(&cm_state, &b(1, 1, 2, 1), 1).unwrap();
        let hll_leaf = build_hll_leaf(HllLeafParams { b: 3, batch: 2 });
        let hll_state = HllState::new(&HllParams { b: 3 });
        let hll_batch = vec![HllUpdate { key: 42 }, HllUpdate { key: 99 }];
        let hll = hll_leaf.prove(&hll_state, &hll_batch, 1).unwrap();

        let mut merged = merge_cross_family(&cm, &hll).unwrap();
        // Corrupt a carried boundary ⇒ digest re-derivation must fail.
        merged.b_final = hll.initial;
        assert!(verify_cross_family(&merged).is_err());
    }
}
