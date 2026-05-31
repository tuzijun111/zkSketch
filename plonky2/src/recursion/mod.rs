//! Recursive proof aggregation — the heart of the framework (paper §4).
//!
//! Sketch-agnostic: everything operates on [`Node`]s, which carry a plonky2
//! proof plus its circuit data and the boundary commits/digest. A leaf and a
//! merged subtree are both `Node`s and expose the **same** first 8 public inputs
//! (`initial_commit[0..4]`, `final_commit[0..4]`), so [`merge`] composes them
//! uniformly into a left-deep or balanced tree.
//!
//! - [`merge`]   — §4.2 two-input recursive merge (verify both children in-circuit).
//! - [`flat_verify`] — §4.1 baseline (verify each node natively); Θ(E) verifier.
//! - §4.3 chain   — just repeated [`merge`] of the running root with a new leaf.

use std::sync::Arc;

use anyhow::{ensure, Result};
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::commitment::{combine_digest, leaf_digest};
use crate::config::{C, D, F};

/// A node in the aggregation tree (a leaf epoch or a merged subtree).
pub struct Node {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub data: Arc<CircuitData<F, C, D>>,
    /// State commit at the start of this node's interval.
    pub initial: HashOut<F>,
    /// State commit at the end of this node's interval.
    pub final_: HashOut<F>,
    /// Paper §4.2 interval digest binding all leaves under this node.
    pub digest: HashOut<F>,
    /// Inclusive leaf-index interval `[lo, hi]` this node covers.
    pub interval: (u64, u64),
}

impl Node {
    /// Wrap a freshly proven leaf (index `index`) as a chain node.
    pub fn leaf(
        data: Arc<CircuitData<F, C, D>>,
        proof: ProofWithPublicInputs<F, C, D>,
        initial: HashOut<F>,
        final_: HashOut<F>,
        index: u64,
    ) -> Self {
        Self {
            proof,
            data,
            initial,
            final_,
            digest: leaf_digest(initial, final_, index),
            interval: (index, index),
        }
    }

    pub fn num_leaves(&self) -> u64 {
        self.interval.1 - self.interval.0 + 1
    }
}

/// §4.2 recursive merge: build a circuit that verifies both child proofs, glues
/// the shared boundary (`left.final == right.initial`), and re-exposes
/// `[left.initial, right.final]`. The result is one proof whose verification is
/// O(1) regardless of how many leaves are underneath.
pub fn merge(left: &Node, right: &Node) -> Result<Node> {
    ensure!(
        left.final_ == right.initial,
        "boundary mismatch: left.final != right.initial"
    );

    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    let lpt = b.add_virtual_proof_with_pis(&left.data.common);
    let rpt = b.add_virtual_proof_with_pis(&right.data.common);
    let lvd = b.add_virtual_verifier_data(left.data.common.config.fri_config.cap_height);
    let rvd = b.add_virtual_verifier_data(right.data.common.config.fri_config.cap_height);
    b.verify_proof::<C>(&lpt, &lvd, &left.data.common);
    b.verify_proof::<C>(&rpt, &rvd, &right.data.common);

    // In-circuit boundary: left.final (PI[4..8]) == right.initial (PI[0..4]).
    for i in 0..4 {
        b.connect(lpt.public_inputs[4 + i], rpt.public_inputs[i]);
    }
    // Expose this node's boundary: initial = left.initial, final = right.final.
    for i in 0..4 {
        let t = lpt.public_inputs[i];
        b.register_public_input(t);
    }
    for i in 0..4 {
        let t = rpt.public_inputs[4 + i];
        b.register_public_input(t);
    }

    let data = b.build::<C>();

    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&lpt, &left.proof)?;
    pw.set_proof_with_pis_target(&rpt, &right.proof)?;
    pw.set_verifier_data_target(&lvd, &left.data.verifier_only)?;
    pw.set_verifier_data_target(&rvd, &right.data.verifier_only)?;
    let proof = data.prove(pw)?;

    let digest = combine_digest(
        left.interval.0,
        left.interval.1,
        right.interval.1,
        left.digest,
        right.digest,
    );

    Ok(Node {
        proof,
        data: Arc::new(data),
        initial: left.initial,
        final_: right.final_,
        digest,
        interval: (left.interval.0, right.interval.1),
    })
}

/// Verify a node proof and confirm its exposed boundary matches the carried commits.
pub fn verify_node(node: &Node) -> Result<()> {
    node.data.verify(node.proof.clone())?;
    let pis = &node.proof.public_inputs;
    ensure!(pis.len() >= 8, "node proof missing boundary public inputs");
    for i in 0..4 {
        ensure!(pis[i] == node.initial.elements[i], "exposed initial commit mismatch");
        ensure!(pis[4 + i] == node.final_.elements[i], "exposed final commit mismatch");
    }
    Ok(())
}

/// §4.1 flat baseline: verify every node natively, check adjacent boundaries, and
/// re-derive the left-deep chain digest. Verifier work is Θ(E). Returns the root
/// digest, which equals the digest a left-deep [`merge`] tree would produce.
pub fn flat_verify(nodes: &[Node]) -> Result<HashOut<F>> {
    ensure!(!nodes.is_empty(), "empty chain");
    for n in nodes {
        verify_node(n)?;
    }
    for k in 1..nodes.len() {
        ensure!(
            nodes[k - 1].final_ == nodes[k].initial,
            "flat boundary mismatch before leaf {k}"
        );
    }
    let lo = nodes[0].interval.0;
    let mut acc = nodes[0].digest;
    let mut hi = nodes[0].interval.1;
    for n in &nodes[1..] {
        acc = combine_digest(lo, hi, n.interval.1, acc, n.digest);
        hi = n.interval.1;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::countmin::{build_countmin_leaf, CmLeafParams};
    use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};

    /// Prove `batches.len()` adjacent Count-Min epochs threaded by boundary.
    fn prove_epochs(batches: &[Vec<CountMinUpdate>]) -> Result<Vec<Node>> {
        let params = CmLeafParams { d: 2, w: 4, batch: 2 };
        let leaf = build_countmin_leaf(params);
        let mut state = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        let mut nodes = Vec::new();
        for (i, batch) in batches.iter().enumerate() {
            let node = leaf.prove(&state, batch, (i + 1) as u64)?;
            for u in batch {
                state.update(u);
            }
            nodes.push(node);
        }
        Ok(nodes)
    }

    fn b(k0: u64, v0: u64, k1: u64, v1: u64) -> Vec<CountMinUpdate> {
        vec![
            CountMinUpdate { key: k0, value: v0 },
            CountMinUpdate { key: k1, value: v1 },
        ]
    }

    #[test]
    fn two_leaf_recursive_merge_accepts() -> Result<()> {
        let nodes = prove_epochs(&[b(7, 3, 11, 5), b(7, 1, 13, 9)])?;
        let root = merge(&nodes[0], &nodes[1])?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        // Flat baseline yields the identical root digest.
        let flat_digest = flat_verify(&nodes)?;
        assert_eq!(root.digest, flat_digest);
        Ok(())
    }

    #[test]
    fn recursive_chain_of_three_accepts() -> Result<()> {
        let nodes = prove_epochs(&[b(7, 3, 11, 5), b(7, 1, 13, 9), b(2, 4, 9, 6)])?;
        let node12 = merge(&nodes[0], &nodes[1])?;
        let root = merge(&node12, &nodes[2])?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 3);
        assert_eq!(root.digest, flat_verify(&nodes)?);
        Ok(())
    }

    #[test]
    fn boundary_mismatch_rejected_at_merge() -> Result<()> {
        // Two leaves that do NOT thread: both start from the empty state.
        let params = CmLeafParams { d: 2, w: 4, batch: 2 };
        let leaf = build_countmin_leaf(params);
        let s0 = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        let n1 = leaf.prove(&s0, &b(7, 3, 11, 5), 1)?;
        let n2_wrong = leaf.prove(&s0, &b(7, 1, 13, 9), 2)?; // should start from s1, not s0
        assert!(merge(&n1, &n2_wrong).is_err());
        Ok(())
    }
}
