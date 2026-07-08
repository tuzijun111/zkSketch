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

pub mod framework;
pub mod mmr;
pub mod topology;

use std::sync::Arc;

use anyhow::{anyhow, ensure, Result};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;
use serde::{Deserialize, Serialize};

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

/// The pieces of a merge child the [`merge`] circuit actually reads: its proof,
/// the `common`/`verifier_only` circuit data needed to verify it in-circuit, and
/// the boundary/digest/interval metadata. A local [`Node`] and a wire-decoded
/// [`MergeInput`] both project to this, so both compose through one code path —
/// which is what lets a peer machine's subtree root (reconstructed from bytes,
/// with no local `CircuitData`) be merged exactly like an in-memory node.
struct ChildParts<'a> {
    proof: &'a ProofWithPublicInputs<F, C, D>,
    common: &'a CommonCircuitData<F, D>,
    verifier_only: &'a VerifierOnlyCircuitData<C, D>,
    initial: HashOut<F>,
    final_: HashOut<F>,
    digest: HashOut<F>,
    interval: (u64, u64),
}

impl Node {
    fn as_child(&self) -> ChildParts<'_> {
        ChildParts {
            proof: &self.proof,
            common: &self.data.common,
            verifier_only: &self.data.verifier_only,
            initial: self.initial,
            final_: self.final_,
            digest: self.digest,
            interval: self.interval,
        }
    }
}

/// The merge circuit itself, over the projected child pieces (see [`ChildParts`]).
fn merge_parts(left: ChildParts, right: ChildParts) -> Result<Node> {
    ensure!(
        left.final_ == right.initial,
        "boundary mismatch: left.final != right.initial"
    );

    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());

    let lpt = b.add_virtual_proof_with_pis(left.common);
    let rpt = b.add_virtual_proof_with_pis(right.common);
    let lvd = b.add_virtual_verifier_data(left.common.config.fri_config.cap_height);
    let rvd = b.add_virtual_verifier_data(right.common.config.fri_config.cap_height);
    b.verify_proof::<C>(&lpt, &lvd, left.common);
    b.verify_proof::<C>(&rpt, &rvd, right.common);

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
    pw.set_proof_with_pis_target(&lpt, left.proof)?;
    pw.set_proof_with_pis_target(&rpt, right.proof)?;
    pw.set_verifier_data_target(&lvd, left.verifier_only)?;
    pw.set_verifier_data_target(&rvd, right.verifier_only)?;
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

/// §4.2 recursive merge: build a circuit that verifies both child proofs, glues
/// the shared boundary (`left.final == right.initial`), and re-exposes
/// `[left.initial, right.final]`. The result is one proof whose verification is
/// O(1) regardless of how many leaves are underneath.
pub fn merge(left: &Node, right: &Node) -> Result<Node> {
    merge_parts(left.as_child(), right.as_child())
}

/// [`merge`] with the RIGHT child arriving over the wire from another machine
/// (the streaming forest's cross-machine reduction step: the receiver folds its
/// own local root `left` with a peer's serialized subtree root `right`).
pub fn merge_wire(left: &Node, right: &MergeInput) -> Result<Node> {
    merge_parts(left.as_child(), right.as_child())
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

/// A merge child reconstructed from wire bytes — the cross-machine analog of a
/// [`Node`], holding just the pieces [`merge`] reads (proof + `common` +
/// `verifier_only`) plus boundary/digest/interval metadata, but **no prover
/// `CircuitData`** (the receiver never needs to re-prove the child, only to
/// verify it in-circuit). Produced by [`MergeInput::from_wire_bytes`] and folded
/// via [`merge_wire`].
///
/// Wire payload per subtree root (Plonky2's merge circuit is not uniform across
/// levels, so the child's `common` must travel with the proof — unlike the
/// Plonky3 backend, whose uniform verifier lets a bare proof suffice):
///   proof bytes (~10² KB) + `CommonCircuitData` (~50 KB, `DefaultGateSerializer`)
///   + `VerifierOnlyCircuitData` (~0.5 KB) + digest/interval (a few words).
pub struct MergeInput {
    proof: ProofWithPublicInputs<F, C, D>,
    common: CommonCircuitData<F, D>,
    verifier_only: VerifierOnlyCircuitData<C, D>,
    initial: HashOut<F>,
    final_: HashOut<F>,
    digest: HashOut<F>,
    interval: (u64, u64),
}

/// postcard-able envelope: the plonky2 proof/circuit types aren't `Serialize`,
/// so we carry their native `to_bytes()`/`from_bytes()` encodings as opaque
/// `Vec<u8>` (the same pattern the plonky3 IPC layer uses for proof bytes).
#[derive(Serialize, Deserialize)]
struct WireNode {
    proof: Vec<u8>,
    common: Vec<u8>,
    verifier_only: Vec<u8>,
    digest: [u64; 4],
    interval: (u64, u64),
}

fn hashout_to_u64(h: HashOut<F>) -> [u64; 4] {
    [
        h.elements[0].to_canonical_u64(),
        h.elements[1].to_canonical_u64(),
        h.elements[2].to_canonical_u64(),
        h.elements[3].to_canonical_u64(),
    ]
}

fn u64s_to_hashout(a: [u64; 4]) -> HashOut<F> {
    HashOut {
        elements: [
            F::from_canonical_u64(a[0]),
            F::from_canonical_u64(a[1]),
            F::from_canonical_u64(a[2]),
            F::from_canonical_u64(a[3]),
        ],
    }
}

impl MergeInput {
    /// Project a local node into a wire-mergeable child (clones the proof +
    /// circuit data; used right before serialization on the sending machine).
    pub fn from_node(node: &Node) -> Self {
        Self {
            proof: node.proof.clone(),
            common: node.data.common.clone(),
            verifier_only: node.data.verifier_only.clone(),
            initial: node.initial,
            final_: node.final_,
            digest: node.digest,
            interval: node.interval,
        }
    }

    fn as_child(&self) -> ChildParts<'_> {
        ChildParts {
            proof: &self.proof,
            common: &self.common,
            verifier_only: &self.verifier_only,
            initial: self.initial,
            final_: self.final_,
            digest: self.digest,
            interval: self.interval,
        }
    }

    /// Serialize for shipping to another machine (proof + circuit data + meta).
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        let gs = DefaultGateSerializer;
        let w = WireNode {
            proof: self.proof.to_bytes(),
            common: self
                .common
                .to_bytes(&gs)
                .map_err(|_| anyhow!("CommonCircuitData::to_bytes failed"))?,
            verifier_only: self
                .verifier_only
                .to_bytes()
                .map_err(|_| anyhow!("VerifierOnlyCircuitData::to_bytes failed"))?,
            digest: hashout_to_u64(self.digest),
            interval: self.interval,
        };
        Ok(postcard::to_allocvec(&w)?)
    }

    /// Reconstruct on the receiving machine. The `initial`/`final_` boundary is
    /// read back from the proof's public inputs (`PI[0..4]`/`PI[4..8]`), so it
    /// is bound to the proof, not trusted from the wire.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let w: WireNode = postcard::from_bytes(bytes)?;
        let gs = DefaultGateSerializer;
        let common = CommonCircuitData::<F, D>::from_bytes(w.common, &gs)
            .map_err(|_| anyhow!("CommonCircuitData::from_bytes failed"))?;
        let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(w.verifier_only)
            .map_err(|_| anyhow!("VerifierOnlyCircuitData::from_bytes failed"))?;
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(w.proof, &common)
            .map_err(|_| anyhow!("ProofWithPublicInputs::from_bytes failed"))?;
        let pis = &proof.public_inputs;
        ensure!(pis.len() >= 8, "wire proof missing boundary public inputs");
        let initial = HashOut { elements: [pis[0], pis[1], pis[2], pis[3]] };
        let final_ = HashOut { elements: [pis[4], pis[5], pis[6], pis[7]] };
        Ok(Self {
            proof,
            common,
            verifier_only,
            initial,
            final_,
            digest: u64s_to_hashout(w.digest),
            interval: w.interval,
        })
    }

    /// Verify a wire-received root with no local prover data: rebuild a
    /// [`VerifierCircuitData`] from the shipped `common`+`verifier_only` and
    /// check the proof, then confirm its exposed boundary matches the carried
    /// commits (the auditor path for a subtree root that arrived as bytes).
    pub fn verify(&self) -> Result<()> {
        let vcd = VerifierCircuitData {
            verifier_only: self.verifier_only.clone(),
            common: self.common.clone(),
        };
        vcd.verify(self.proof.clone())?;
        let pis = &self.proof.public_inputs;
        ensure!(pis.len() >= 8, "wire proof missing boundary public inputs");
        for i in 0..4 {
            ensure!(pis[i] == self.initial.elements[i], "wire initial commit mismatch");
            ensure!(pis[4 + i] == self.final_.elements[i], "wire final commit mismatch");
        }
        Ok(())
    }

    pub fn initial(&self) -> HashOut<F> {
        self.initial
    }
    pub fn final_(&self) -> HashOut<F> {
        self.final_
    }
    pub fn num_leaves(&self) -> u64 {
        self.interval.1 - self.interval.0 + 1
    }
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

    /// CROSS-PROCESS GATE (Phase 0): a subtree root survives the wire codec and
    /// merges exactly like an in-memory node. This is the mechanic the streaming
    /// forest's cross-machine reduction relies on — a peer ships its root as
    /// bytes, the receiver rebuilds a `MergeInput` (no local `CircuitData`) and
    /// folds it. Exercises both a leaf and a MERGED root crossing the wire, and
    /// checks the reassembled root verifies and matches the all-local digest.
    #[test]
    fn merge_from_wire_round_trips() -> Result<()> {
        // Four threaded Count-Min epochs.
        let nodes = prove_epochs(&[b(7, 3, 11, 5), b(7, 1, 13, 9), b(2, 4, 9, 6), b(5, 2, 3, 8)])?;

        // (1) A single leaf crosses the wire as the right child.
        let wire_leaf = MergeInput::from_node(&nodes[1]).to_wire_bytes()?;
        assert!(wire_leaf.len() > 1000, "wire payload carries proof + common data");
        let remote_leaf = MergeInput::from_wire_bytes(&wire_leaf)?;
        let root01_wire = merge_wire(&nodes[0], &remote_leaf)?;
        verify_node(&root01_wire)?;
        // Identical to the fully-local merge.
        let root01_local = merge(&nodes[0], &nodes[1])?;
        assert_eq!(root01_wire.digest, root01_local.digest, "wire merge == local merge");
        assert_eq!(root01_wire.num_leaves(), 2);

        // (2) A MERGED subtree root crosses the wire as the right child — the
        // real forest reduction: left slice-root ⊕ peer slice-root(bytes).
        let right23 = merge(&nodes[2], &nodes[3])?;
        let wire_root = MergeInput::from_node(&right23).to_wire_bytes()?;
        let remote_root = MergeInput::from_wire_bytes(&wire_root)?;
        let root = merge_wire(&root01_local, &remote_root)?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 4, "fold-of-folds over the wire covers all 4 leaves");
        // Boundary threads end-to-end: Com(S_0) .. Com(S_4).
        assert_eq!(root.initial, nodes[0].initial);
        assert_eq!(root.final_, nodes[3].final_);
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
