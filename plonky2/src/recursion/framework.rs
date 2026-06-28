//! **zkSketch Framework §4: Verifiable Streaming Sketch Maintenance.**
//!
//! Port of `../src/recursion/framework.rs` to plonky2/Goldilocks. The proof-
//! orchestration layer that sits *above* the per-family update circuits of §5
//! (`crate::leaf::*`). It is **sketch-agnostic**: it composes per-epoch
//! transition proofs into a single auditable root, independent of whether the
//! leaves are Count-Min, GK, HLL, or SpaceSaving.
//!
//! - **§4.1 Per-epoch transition proof chain.** Each closed epoch yields a leaf
//!   with public boundary `(D_i, Com(S_{i-1}), C_{B_i}, Com(S_i), M)`. Adjacent
//!   leaves chain through `Com(S_i)`. [`verify_epoch_chain`] is the Θ(E) verifier.
//! - **§4.2 Interval proofs + the merge atom.** An [`IntervalProof`] carries the
//!   public boundary; [`merge_atom`] composes two adjacent intervals, checking the
//!   shared boundary and combining the ordered-epoch digests via the existing
//!   [`combine_digest`].
//! - **§4.3 Composition topologies.** [`compose_chain`] (linear), [`compose_tree`]
//!   (balanced binary), and [`StreamingForest`] (Bentley–Saxe / MMR cascade).
//! - **Root `R(t)`.** [`root_commitment`] packages a root's boundary into the
//!   `O(1)`-size digest the verifier checks.
//!
//! Unlike the plonky3 original, the per-family leaves here are real plonky2
//! proofs that self-verify natively; this module adds the **composition
//! soundness** §4 is about (contiguity, boundary agreement, order-binding).

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::commitment::combine_digest;
use crate::config::F;

/// A state / batch commitment — a Poseidon digest (`HashOut<F>`), matching every
/// `crate::sketch::*` `commit()` and `crate::leaf::*` boundary public input.
pub type Commit = HashOut<F>;

/// One per-epoch transition leaf (§4.1) — the public boundary of `π_i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochLeaf {
    /// Epoch index `i` (1-based, contiguous).
    pub index: u64,
    /// `Com(S_{i-1})` — the input state commitment.
    pub com_before: Commit,
    /// `Com(S_i)` — the output state commitment.
    pub com_after: Commit,
    /// `C_{B_i}` — the binding commitment to the (private) epoch batch.
    pub batch_commit: Commit,
    /// `D_i` — public epoch descriptor, bound into the leaf digest.
    pub descriptor: u64,
}

impl EpochLeaf {
    pub fn new(
        index: u64,
        com_before: Commit,
        com_after: Commit,
        batch_commit: Commit,
        descriptor: u64,
    ) -> Self {
        Self { index, com_before, com_after, batch_commit, descriptor }
    }
}

/// An interval proof `Π[lo,hi]` boundary (§4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntervalProof {
    pub lo: u64,
    pub hi: u64,
    pub com_before: Commit,
    pub com_after: Commit,
    pub digest: HashOut<F>,
}

impl IntervalProof {
    /// Number of epochs the interval covers (`hi − lo + 1`).
    pub fn size(&self) -> u64 {
        self.hi - self.lo + 1
    }
}

/// Errors the framework's composition checks raise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameworkError {
    /// Two intervals being merged aren't adjacent (`left.hi + 1 != right.lo`).
    NonAdjacent { left_hi: u64, right_lo: u64 },
    /// The shared join boundary disagrees (`left.com_after != right.com_before`).
    BoundaryMismatch { at: u64 },
    /// Composing an empty list of leaves.
    Empty,
    /// `compose_tree` requires a power-of-two leaf count.
    NotPowerOfTwo(usize),
    /// Leaves aren't a contiguous, in-order epoch run starting at the expected index.
    OutOfOrder { expected: u64, got: u64 },
}

// Domain-separation tags (ASCII).
const TAG_EPOCH_LEAF: u64 = 0x4550_4C46; // "EPLF"
const TAG_ROOT: u64 = 0x524F_4F54; // "ROOT"

// ─── Leaf digest ───────────────────────────────────────────────────────────

/// The leaf interval digest — binds the epoch index, descriptor, batch
/// commitment, and both boundary commitments, so no two distinct epochs (or a
/// reordered one) share a digest.
pub fn epoch_leaf_digest(leaf: &EpochLeaf) -> HashOut<F> {
    let mut input: Vec<F> = Vec::with_capacity(3 + 4 * 3);
    input.push(F::from_canonical_u64(TAG_EPOCH_LEAF));
    input.push(F::from_canonical_u64(leaf.index));
    input.push(F::from_canonical_u64(leaf.descriptor));
    input.extend_from_slice(&leaf.batch_commit.elements);
    input.extend_from_slice(&leaf.com_before.elements);
    input.extend_from_slice(&leaf.com_after.elements);
    PoseidonHash::hash_no_pad(&input)
}

/// Lift a per-epoch leaf to a single-epoch interval proof `Π[j,j]` (§4.2).
pub fn lift_leaf(leaf: &EpochLeaf) -> IntervalProof {
    IntervalProof {
        lo: leaf.index,
        hi: leaf.index,
        com_before: leaf.com_before,
        com_after: leaf.com_after,
        digest: epoch_leaf_digest(leaf),
    }
}

// ─── §4.2 The merge atom ─────────────────────────────────────────────────

/// The merge atom: compose two **adjacent** interval proofs into one.
///
/// Enforces (1) contiguity `left.hi + 1 == right.lo`, (2) the shared boundary
/// `left.com_after == right.com_before`, and (3) order-binding by combining the
/// digests via `H[i,j] = H(i, m, j, H[i,m], H[m+1,j])`.
pub fn merge_atom(
    left: &IntervalProof,
    right: &IntervalProof,
) -> Result<IntervalProof, FrameworkError> {
    if left.hi + 1 != right.lo {
        return Err(FrameworkError::NonAdjacent { left_hi: left.hi, right_lo: right.lo });
    }
    if left.com_after != right.com_before {
        return Err(FrameworkError::BoundaryMismatch { at: left.hi });
    }
    let digest = combine_digest(left.lo, left.hi, right.hi, left.digest, right.digest);
    Ok(IntervalProof {
        lo: left.lo,
        hi: right.hi,
        com_before: left.com_before,
        com_after: right.com_after,
        digest,
    })
}

// ─── §4.1 The per-epoch proof chain (direct Θ(E) verifier) ───────────────

/// Verify a per-epoch proof chain (§4.1): a contiguous, in-order epoch run
/// starting at `start_index`, with adjacent leaves agreeing on their boundary
/// commitment.
pub fn verify_epoch_chain(leaves: &[EpochLeaf], start_index: u64) -> Result<(), FrameworkError> {
    if leaves.is_empty() {
        return Err(FrameworkError::Empty);
    }
    let mut expected = start_index;
    for w in leaves.windows(2) {
        if w[0].index != expected {
            return Err(FrameworkError::OutOfOrder { expected, got: w[0].index });
        }
        if w[1].index != w[0].index + 1 {
            return Err(FrameworkError::OutOfOrder { expected: w[0].index + 1, got: w[1].index });
        }
        if w[0].com_after != w[1].com_before {
            return Err(FrameworkError::BoundaryMismatch { at: w[0].index });
        }
        expected = w[1].index;
    }
    let last = leaves.last().unwrap();
    if last.index != leaves[0].index + (leaves.len() as u64 - 1) {
        return Err(FrameworkError::OutOfOrder {
            expected: leaves[0].index + (leaves.len() as u64 - 1),
            got: last.index,
        });
    }
    if leaves[0].index != start_index {
        return Err(FrameworkError::OutOfOrder { expected: start_index, got: leaves[0].index });
    }
    Ok(())
}

// ─── §4.3(a) Linear chain ────────────────────────────────────────────────

/// §4.3(a): fold the merge atom left-to-right into one root interval proof.
pub fn compose_chain(leaves: &[EpochLeaf]) -> Result<IntervalProof, FrameworkError> {
    if leaves.is_empty() {
        return Err(FrameworkError::Empty);
    }
    let mut acc = lift_leaf(&leaves[0]);
    for leaf in &leaves[1..] {
        acc = merge_atom(&acc, &lift_leaf(leaf))?;
    }
    Ok(acc)
}

// ─── §4.3(b) Balanced binary tree ────────────────────────────────────────

/// §4.3(b): compose a **power-of-two** number of leaves as a balanced binary tree.
pub fn compose_tree(leaves: &[EpochLeaf]) -> Result<IntervalProof, FrameworkError> {
    let n = leaves.len();
    if n == 0 {
        return Err(FrameworkError::Empty);
    }
    if !n.is_power_of_two() {
        return Err(FrameworkError::NotPowerOfTwo(n));
    }
    let mut level: Vec<IntervalProof> = leaves.iter().map(lift_leaf).collect();
    while level.len() > 1 {
        let mut next: Vec<IntervalProof> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(merge_atom(&pair[0], &pair[1])?);
        }
        level = next;
    }
    Ok(level.pop().unwrap())
}

// ─── §4.3(c) Streaming forest (Bentley–Saxe / MMR cascade) ───────────────

/// §4.3(c): a streaming forest of perfect interval-proof subtrees whose sizes
/// are the powers of two in the binary representation of the current length `t`.
/// New leaves append on the right; a binary-counter **cascade** merges equal-
/// sized neighbours. Finalizable to a single root via [`StreamingForest::finalize`].
#[derive(Clone, Debug, Default)]
pub struct StreamingForest {
    roots: Vec<IntervalProof>,
    next_index: u64,
}

impl StreamingForest {
    pub fn new() -> Self {
        Self { roots: Vec::new(), next_index: 1 }
    }

    /// Number of epochs ingested so far (`t`).
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
        self.roots.iter().map(IntervalProof::size).collect()
    }

    /// Insert the next epoch leaf and run the cascade. `leaf.index` must equal
    /// the forest's `next_index` (contiguous append).
    pub fn insert(&mut self, leaf: &EpochLeaf) -> Result<(), FrameworkError> {
        if leaf.index != self.next_index {
            return Err(FrameworkError::OutOfOrder { expected: self.next_index, got: leaf.index });
        }
        let mut node = lift_leaf(leaf);
        while let Some(last) = self.roots.last() {
            if last.size() == node.size() {
                let left = self.roots.pop().unwrap();
                node = merge_atom(&left, &node)?;
            } else {
                break;
            }
        }
        self.roots.push(node);
        self.next_index += 1;
        Ok(())
    }

    /// Finalize the current forest into a single root interval proof `Π[1,t]` by
    /// chaining the surviving roots left-to-right. `O(log t)` work; read-only.
    pub fn finalize(&self) -> Result<IntervalProof, FrameworkError> {
        if self.roots.is_empty() {
            return Err(FrameworkError::Empty);
        }
        let mut acc = self.roots[0];
        for r in &self.roots[1..] {
            acc = merge_atom(&acc, r)?;
        }
        Ok(acc)
    }
}

// ─── Root R(t) ───────────────────────────────────────────────────────────

/// `R(t)` — the `O(1)`-size root digest published alongside `Π(t)`. The verifier
/// recomputes it from the interval proof's exposed boundary and checks equality.
pub fn root_commitment(root: &IntervalProof) -> HashOut<F> {
    let mut input: Vec<F> = Vec::with_capacity(3 + 4 * 2 + 4);
    input.push(F::from_canonical_u64(TAG_ROOT));
    input.push(F::from_canonical_u64(root.lo));
    input.push(F::from_canonical_u64(root.hi));
    input.extend_from_slice(&root.com_before.elements);
    input.extend_from_slice(&root.com_after.elements);
    input.extend_from_slice(&root.digest.elements);
    PoseidonHash::hash_no_pad(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic synthetic commitment for epoch boundary `k`.
    fn commit(k: u64) -> Commit {
        HashOut {
            elements: std::array::from_fn(|i| {
                F::from_canonical_u64(k.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64) + 1)
            }),
        }
    }

    /// A contiguous run of `n` leaves, chained so `leaf[k].com_after ==
    /// leaf[k+1].com_before`.
    fn history(n: u64) -> Vec<EpochLeaf> {
        (1..=n)
            .map(|i| EpochLeaf::new(i, commit(i - 1), commit(i), commit(1000 + i), i))
            .collect()
    }

    #[test]
    fn epoch_chain_accepts_valid_history() {
        assert!(verify_epoch_chain(&history(5), 1).is_ok());
    }

    #[test]
    fn epoch_chain_rejects_boundary_break() {
        let mut leaves = history(5);
        leaves[2].com_after = commit(999);
        match verify_epoch_chain(&leaves, 1) {
            Err(FrameworkError::BoundaryMismatch { at: 3 }) => {}
            other => panic!("expected boundary mismatch at epoch 3, got {other:?}"),
        }
    }

    #[test]
    fn epoch_chain_rejects_reorder() {
        let mut leaves = history(5);
        leaves.swap(1, 3);
        assert!(verify_epoch_chain(&leaves, 1).is_err());
    }

    #[test]
    fn merge_atom_composes_adjacent() {
        let leaves = history(2);
        let p = merge_atom(&lift_leaf(&leaves[0]), &lift_leaf(&leaves[1])).expect("adjacent merge");
        assert_eq!((p.lo, p.hi), (1, 2));
        assert_eq!(p.com_before, commit(0));
        assert_eq!(p.com_after, commit(2));
    }

    #[test]
    fn merge_atom_rejects_non_adjacent() {
        let leaves = history(3);
        match merge_atom(&lift_leaf(&leaves[0]), &lift_leaf(&leaves[2])) {
            Err(FrameworkError::NonAdjacent { left_hi: 1, right_lo: 3 }) => {}
            other => panic!("expected non-adjacent, got {other:?}"),
        }
    }

    #[test]
    fn merge_atom_rejects_boundary_mismatch() {
        let mut leaves = history(2);
        leaves[1].com_before = commit(999);
        match merge_atom(&lift_leaf(&leaves[0]), &lift_leaf(&leaves[1])) {
            Err(FrameworkError::BoundaryMismatch { at: 1 }) => {}
            other => panic!("expected boundary mismatch, got {other:?}"),
        }
    }

    #[test]
    fn chain_composes_to_root() {
        let root = compose_chain(&history(6)).expect("chain");
        assert_eq!((root.lo, root.hi), (1, 6));
        assert_eq!(root.com_before, commit(0));
        assert_eq!(root.com_after, commit(6));
    }

    #[test]
    fn chain_rejects_reordered_history() {
        let mut leaves = history(4);
        leaves.swap(0, 1);
        assert!(compose_chain(&leaves).is_err());
    }

    #[test]
    fn tree_composes_power_of_two() {
        let root = compose_tree(&history(8)).expect("tree");
        assert_eq!((root.lo, root.hi), (1, 8));
        assert_eq!(root.com_before, commit(0));
        assert_eq!(root.com_after, commit(8));
    }

    #[test]
    fn tree_rejects_non_power_of_two() {
        match compose_tree(&history(6)) {
            Err(FrameworkError::NotPowerOfTwo(6)) => {}
            other => panic!("expected NotPowerOfTwo(6), got {other:?}"),
        }
    }

    #[test]
    fn chain_and_tree_agree_on_boundary() {
        let leaves = history(8);
        let c = compose_chain(&leaves).expect("chain");
        let t = compose_tree(&leaves).expect("tree");
        assert_eq!((c.lo, c.hi), (t.lo, t.hi));
        assert_eq!(c.com_before, t.com_before);
        assert_eq!(c.com_after, t.com_after);
        assert_ne!(c.digest, t.digest, "digest binds the schedule shape");
    }

    #[test]
    fn forest_cascade_tracks_binary_counter() {
        let mut f = StreamingForest::new();
        for leaf in &history(11) {
            f.insert(leaf).expect("insert");
        }
        assert_eq!(f.len(), 11);
        assert_eq!(f.num_trees(), (11u64).count_ones() as usize);
        assert_eq!(f.root_sizes(), vec![8, 2, 1]);
    }

    #[test]
    fn forest_finalizes_to_single_root() {
        let mut f = StreamingForest::new();
        for leaf in &history(11) {
            f.insert(leaf).expect("insert");
        }
        let root = f.finalize().expect("finalize");
        assert_eq!((root.lo, root.hi), (1, 11));
        assert_eq!(root.com_before, commit(0));
        assert_eq!(root.com_after, commit(11));
    }

    #[test]
    fn forest_power_of_two_matches_tree() {
        let leaves = history(8);
        let mut f = StreamingForest::new();
        for leaf in &leaves {
            f.insert(leaf).expect("insert");
        }
        assert_eq!(f.num_trees(), 1);
        assert_eq!(f.finalize().expect("finalize"), compose_tree(&leaves).expect("tree"));
    }

    #[test]
    fn forest_rejects_out_of_order_insert() {
        let leaves = history(3);
        let mut f = StreamingForest::new();
        f.insert(&leaves[0]).expect("insert 1");
        match f.insert(&leaves[2]) {
            Err(FrameworkError::OutOfOrder { expected: 2, got: 3 }) => {}
            other => panic!("expected out-of-order, got {other:?}"),
        }
    }

    #[test]
    fn root_commitment_binds_history() {
        let r6 = root_commitment(&compose_chain(&history(6)).expect("chain 6"));
        assert_eq!(r6, root_commitment(&compose_chain(&history(6)).expect("chain 6")));
        assert_ne!(r6, root_commitment(&compose_chain(&history(5)).expect("chain 5")));
    }

    #[test]
    fn root_verifier_recompute_detects_tamper() {
        let leaves = history(6);
        let published = root_commitment(&compose_chain(&leaves).expect("chain"));
        assert_eq!(published, root_commitment(&compose_chain(&leaves).expect("chain")));
        let mut bad = leaves.clone();
        bad[2].batch_commit = commit(424242);
        assert_ne!(published, root_commitment(&compose_chain(&bad).expect("chain")));
    }
}
