//! Sketch-agnostic composition of epoch proofs: the epoch chain, the merge atom, the
//! chain / tree / streaming-forest schedules, and the root commitment `R(t)`.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::config::{MyHash, Val, make_perm};
use crate::recursion::digest::{ChainDigest, DIGEST_WIDTH, combine_digest};

/// State / batch commitments are 8 BabyBear field elements (a Poseidon2
/// digest), matching every `*_final[_full]` leaf's `[Val; 8]` commit.
pub type Commit = [Val; 8];

/// One per-epoch transition leaf (§4.1) — the public boundary of `π_i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochLeaf {
    /// Epoch index `i` (1-based, contiguous).
    pub index: u64,
    /// `Com(S_{i-1})` — the input state commitment.
    pub com_before: Commit,
    /// `Com(S_i)` — the output state commitment.
    pub com_after: Commit,
    /// `C_{B_i}` — the binding commitment to the (private) epoch batch.
    pub batch_commit: Commit,
    /// `D_i` — public epoch descriptor (stand-in for the upload-log slice
    /// `[ℓ_{i-1}+1, ℓ_i]` + its digest). Bound into the leaf digest so a
    /// descriptor substitution changes the public input.
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

/// An interval proof `Π[lo,hi]` boundary (§4.2). The underlying STARK
/// proofs of the constituent leaves are verified at leaf-creation time;
/// this carries the public boundary the framework composes and binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalProof {
    pub lo: u64,
    pub hi: u64,
    pub com_before: Commit,
    pub com_after: Commit,
    pub digest: ChainDigest,
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
    /// Leaves aren't a contiguous, in-order epoch run starting at the
    /// expected index.
    OutOfOrder { expected: u64, got: u64 },
}

// ─── Leaf digest ───────────────────────────────────────────────────────────

/// `H[j,j] = H(j, D_j, C_{b_j}, Com(S_{j-1}), Com(S_j))` — the leaf
/// interval digest. Binds the epoch index, descriptor, batch commitment,
/// and both boundary commitments, so no two distinct epochs (or a
/// reordered one) share a digest. Delegates to the canonical
/// `digest::leaf_digest` (identical input layout, so digest values are
/// unchanged).
pub fn epoch_leaf_digest(leaf: &EpochLeaf) -> ChainDigest {
    crate::recursion::digest::leaf_digest(
        leaf.index,
        leaf.descriptor,
        &leaf.batch_commit,
        &leaf.com_before,
        &leaf.com_after,
    )
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

/// The merge atom: compose two **adjacent** interval proofs `Π[i,m]` and
/// `Π[m+1,j]` into `Π[i,j]`.
///
/// Enforces (1) contiguity `left.hi + 1 == right.lo`, (2) the shared
/// boundary `left.com_after == right.com_before` (the absorbed
/// `Com(S_m)`), and (3) order-binding by combining the digests via
/// `H[i,j] = H(i, m, j, H[i,m], H[m+1,j])`.
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
    let digest = combine_digest(left.lo, left.hi, right.hi, &left.digest, &right.digest);
    Ok(IntervalProof {
        lo: left.lo,
        hi: right.hi,
        com_before: left.com_before,
        com_after: right.com_after,
        digest,
    })
}

// ─── §4.1 The per-epoch proof chain (direct Θ(E) verifier) ───────────────

/// Verify a per-epoch proof chain (§4.1): the leaves are a contiguous,
/// in-order epoch run starting at `start_index`, and adjacent leaves agree
/// on their boundary commitment (`leaf[k].com_after == leaf[k+1].com_before`).
/// This is the linear-cost verifier the composition layer (§4.2/§4.3)
/// replaces with a single root proof.
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
    // single-leaf or last-leaf index check
    if leaves.last().unwrap().index != leaves[0].index + (leaves.len() as u64 - 1) {
        return Err(FrameworkError::OutOfOrder {
            expected: leaves[0].index + (leaves.len() as u64 - 1),
            got: leaves.last().unwrap().index,
        });
    }
    if leaves[0].index != start_index {
        return Err(FrameworkError::OutOfOrder { expected: start_index, got: leaves[0].index });
    }
    Ok(())
}

// ─── §4.3(a) Linear chain ────────────────────────────────────────────────

/// §4.3(a): compose leaves into one root interval proof by folding the
/// merge atom left-to-right (the accumulating-chain schedule, `O(1)` ready
/// root). This is the same digest shape the existing `countmin_chain`
/// produces.
pub fn compose_chain(leaves: &[EpochLeaf]) -> Result<IntervalProof, FrameworkError> {
    if leaves.is_empty() {
        return Err(FrameworkError::Empty);
    }
    let mut acc = lift_leaf(&leaves[0]);
    for leaf in &leaves[1..] {
        let next = lift_leaf(leaf);
        acc = merge_atom(&acc, &next)?;
    }
    Ok(acc)
}

// ─── §4.3(b) Balanced binary tree ────────────────────────────────────────

/// §4.3(b): compose a **power-of-two** number of leaves as a balanced
/// binary tree — disjoint subtrees merge level by level. Requires `E`
/// known in advance and a power of two; the verifier still checks one root.
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

/// §4.3(c): a streaming forest of perfect interval-proof subtrees whose
/// sizes are the powers of two in the binary representation of the current
/// length `t`. New leaves are appended on the right; a binary-counter
/// **cascade** merges equal-sized neighbours. At any moment the surviving
/// roots are chained into a single root proof via [`StreamingForest::finalize`].
///
/// Invariant: `roots` are ordered earliest→latest with **strictly
/// decreasing** sizes (each a distinct power of two), and
/// `roots.len() == popcount(t)`.
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

    /// Insert the next epoch leaf and run the cascade. The leaf's `index`
    /// must equal the forest's `next_index` (contiguous append).
    pub fn insert(&mut self, leaf: &EpochLeaf) -> Result<(), FrameworkError> {
        if leaf.index != self.next_index {
            return Err(FrameworkError::OutOfOrder { expected: self.next_index, got: leaf.index });
        }
        let mut node = lift_leaf(leaf); // a fresh size-1 subtree on the right
        // Cascade: while the rightmost surviving root has the same size as
        // `node`, merge them (the existing root is the *earlier* / left
        // interval). Mirrors a binary-counter carry.
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

    /// Finalize the current forest into a single root interval proof
    /// `Π[1,t]` by chaining the surviving roots left-to-right (`ℓ−1`
    /// on-demand merges). `O(log t)` work; idempotent / read-only.
    pub fn finalize(&self) -> Result<IntervalProof, FrameworkError> {
        if self.roots.is_empty() {
            return Err(FrameworkError::Empty);
        }
        let mut acc = self.roots[0].clone();
        for r in &self.roots[1..] {
            acc = merge_atom(&acc, r)?;
        }
        Ok(acc)
    }
}

// ─── Root R(t) ───────────────────────────────────────────────────────────

/// `R(t) = H(1, t, Com(S_0), Com(S_t), H[1,t], M)` — the `O(1)`-size root
/// digest published alongside `Π(t)`. The verifier recomputes it from the
/// interval proof's exposed boundary and checks equality.
pub fn root_commitment(root: &IntervalProof) -> ChainDigest {
    let hasher = MyHash::new(make_perm());
    let mut input: Vec<Val> = Vec::with_capacity(2 + 8 * 2 + DIGEST_WIDTH);
    input.push(Val::from_u64(0x524F_4F54)); // 'ROOT' tag
    input.push(Val::from_u64(root.lo));
    input.push(Val::from_u64(root.hi));
    input.extend_from_slice(&root.com_before);
    input.extend_from_slice(&root.com_after);
    input.extend_from_slice(&root.digest);
    let full: [Val; 8] = hasher.hash_iter(input);
    let mut out = [Val::ZERO; DIGEST_WIDTH];
    out.copy_from_slice(&full[..DIGEST_WIDTH]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic synthetic commitment for epoch boundary `k`.
    fn commit(k: u64) -> Commit {
        std::array::from_fn(|i| Val::from_u64(k.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64) + 1))
    }

    /// Build a contiguous run of `n` epoch leaves, chained so
    /// `leaf[k].com_after == leaf[k+1].com_before` (a valid history
    /// `Com(S_0) → … → Com(S_n)`).
    fn history(n: u64) -> Vec<EpochLeaf> {
        (1..=n)
            .map(|i| EpochLeaf::new(i, commit(i - 1), commit(i), commit(1000 + i), i))
            .collect()
    }

    // ─── §4.1 per-epoch chain ────────────────────────────────────────────

    #[test]
    fn epoch_chain_accepts_valid_history() {
        let leaves = history(5);
        assert!(verify_epoch_chain(&leaves, 1).is_ok());
    }

    #[test]
    fn epoch_chain_rejects_boundary_break() {
        let mut leaves = history(5);
        // Tamper leaf 3's output so it no longer matches leaf 4's input.
        leaves[2].com_after = commit(999);
        match verify_epoch_chain(&leaves, 1) {
            Err(FrameworkError::BoundaryMismatch { at: 3 }) => {}
            other => panic!("expected boundary mismatch at epoch 3, got {other:?}"),
        }
    }

    #[test]
    fn epoch_chain_rejects_reorder() {
        let mut leaves = history(5);
        leaves.swap(1, 3); // out-of-order epochs
        assert!(verify_epoch_chain(&leaves, 1).is_err());
    }

    // ─── §4.2 merge atom ─────────────────────────────────────────────────

    #[test]
    fn merge_atom_composes_adjacent() {
        let leaves = history(2);
        let l = lift_leaf(&leaves[0]);
        let r = lift_leaf(&leaves[1]);
        let p = merge_atom(&l, &r).expect("adjacent merge");
        assert_eq!((p.lo, p.hi), (1, 2));
        assert_eq!(p.com_before, commit(0));
        assert_eq!(p.com_after, commit(2));
    }

    #[test]
    fn merge_atom_rejects_non_adjacent() {
        let leaves = history(3);
        let l = lift_leaf(&leaves[0]); // [1,1]
        let r = lift_leaf(&leaves[2]); // [3,3]
        match merge_atom(&l, &r) {
            Err(FrameworkError::NonAdjacent { left_hi: 1, right_lo: 3 }) => {}
            other => panic!("expected non-adjacent, got {other:?}"),
        }
    }

    #[test]
    fn merge_atom_rejects_boundary_mismatch() {
        let mut leaves = history(2);
        leaves[1].com_before = commit(999); // join point disagrees
        let l = lift_leaf(&leaves[0]);
        let r = lift_leaf(&leaves[1]);
        match merge_atom(&l, &r) {
            Err(FrameworkError::BoundaryMismatch { at: 1 }) => {}
            other => panic!("expected boundary mismatch, got {other:?}"),
        }
    }

    // ─── §4.3(a) linear chain ────────────────────────────────────────────

    #[test]
    fn chain_composes_to_root() {
        let leaves = history(6);
        let root = compose_chain(&leaves).expect("chain");
        assert_eq!((root.lo, root.hi), (1, 6));
        assert_eq!(root.com_before, commit(0));
        assert_eq!(root.com_after, commit(6));
    }

    #[test]
    fn chain_rejects_reordered_history() {
        let mut leaves = history(4);
        leaves.swap(0, 1); // breaks contiguity at the merge
        assert!(compose_chain(&leaves).is_err());
    }

    // ─── §4.3(b) balanced binary tree ────────────────────────────────────

    #[test]
    fn tree_composes_power_of_two() {
        let leaves = history(8);
        let root = compose_tree(&leaves).expect("tree");
        assert_eq!((root.lo, root.hi), (1, 8));
        assert_eq!(root.com_before, commit(0));
        assert_eq!(root.com_after, commit(8));
    }

    #[test]
    fn tree_rejects_non_power_of_two() {
        let leaves = history(6);
        match compose_tree(&leaves) {
            Err(FrameworkError::NotPowerOfTwo(6)) => {}
            other => panic!("expected NotPowerOfTwo(6), got {other:?}"),
        }
    }

    /// The chain and the balanced tree certify the **same outer boundary**
    /// for the same history (the digest differs because it binds the merge
    /// schedule, which is the point of §4.3's topology choice).
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

    // ─── §4.3(c) streaming forest ────────────────────────────────────────

    #[test]
    fn forest_cascade_tracks_binary_counter() {
        let leaves = history(11);
        let mut f = StreamingForest::new();
        for leaf in &leaves {
            f.insert(leaf).expect("insert");
        }
        assert_eq!(f.len(), 11);
        // 11 = 8 + 2 + 1 → three surviving roots of sizes 8, 2, 1.
        assert_eq!(f.num_trees(), (11u64).count_ones() as usize);
        assert_eq!(f.root_sizes(), vec![8, 2, 1]);
    }

    #[test]
    fn forest_finalizes_to_single_root() {
        let leaves = history(11);
        let mut f = StreamingForest::new();
        for leaf in &leaves {
            f.insert(leaf).expect("insert");
        }
        let root = f.finalize().expect("finalize");
        assert_eq!((root.lo, root.hi), (1, 11));
        assert_eq!(root.com_before, commit(0));
        assert_eq!(root.com_after, commit(11));
    }

    #[test]
    fn forest_power_of_two_matches_tree_boundary() {
        // At t = 8 the forest holds exactly one size-8 root.
        let leaves = history(8);
        let mut f = StreamingForest::new();
        for leaf in &leaves {
            f.insert(leaf).expect("insert");
        }
        assert_eq!(f.num_trees(), 1);
        let froot = f.finalize().expect("finalize");
        let troot = compose_tree(&leaves).expect("tree");
        // Same balanced shape at a power of two → identical digest, too.
        assert_eq!(froot, troot);
    }

    #[test]
    fn forest_rejects_out_of_order_insert() {
        let leaves = history(3);
        let mut f = StreamingForest::new();
        f.insert(&leaves[0]).expect("insert 1");
        // Skip epoch 2, try to insert epoch 3.
        match f.insert(&leaves[2]) {
            Err(FrameworkError::OutOfOrder { expected: 2, got: 3 }) => {}
            other => panic!("expected out-of-order, got {other:?}"),
        }
    }

    // ─── Root R(t) ───────────────────────────────────────────────────────

    #[test]
    fn root_commitment_binds_history() {
        let root6 = compose_chain(&history(6)).expect("chain 6");
        let root5 = compose_chain(&history(5)).expect("chain 5");
        let r6 = root_commitment(&root6);
        assert_eq!(r6, root_commitment(&root6), "deterministic");
        assert_ne!(r6, root_commitment(&root5), "different histories → different roots");
    }

    /// A verifier recomputes `R(t)` from a re-composed root over the public
    /// epoch records and checks equality — and a single tampered batch
    /// commitment makes the recomputed root differ.
    #[test]
    fn root_verifier_recompute_detects_tamper() {
        let leaves = history(6);
        let published = root_commitment(&compose_chain(&leaves).expect("chain"));

        // Honest re-composition matches.
        let recomputed = root_commitment(&compose_chain(&leaves).expect("chain"));
        assert_eq!(published, recomputed);

        // Tamper one epoch's batch commitment → digest changes → root differs.
        let mut bad = leaves.clone();
        bad[2].batch_commit = commit(424242);
        let bad_root = root_commitment(&compose_chain(&bad).expect("chain"));
        assert_ne!(published, bad_root, "tampered batch commitment must change R(t)");
    }

    // ─── End-to-end: compose REAL sketch leaves (§5 GK) via the framework ──

    /// Build a real 4-epoch GK history with the complete §5.4 update
    /// circuit (`gk_final_full`), lift each transition proof into an
    /// [`EpochLeaf`], and compose it through all three §4.3 topologies.
    /// Every topology certifies the same outer boundary `Com(S_0) →
    /// Com(S_4)`, equal to the natively-recomputed state commitments — the
    /// framework wired end-to-end over the per-family circuits.
    #[test]
    fn framework_composes_real_gk_history() {
        use crate::sketch::gk_final_full::{
            GKFullParams, GKFullState, GKFullUpdate, apply_batch_full, commit_gk_state,
            prove_gk_full,
        };

        let params = GKFullParams { capacity: 4, batch: 2 };
        let mut state = GKFullState::empty(params);
        let com_s0 = commit_gk_state(&state).0;
        let mut leaves: Vec<EpochLeaf> = Vec::new();

        for i in 1..=4u64 {
            // Distinct per-epoch batch (values fit the GK 20-bit bound).
            let v = (i as u32) * 10;
            let batch = vec![GKFullUpdate::real(v), GKFullUpdate::real(v + 1)];
            // Real transition proof for this epoch (self-verifies inside).
            let leaf = prove_gk_full(params, state.clone(), batch.clone());
            let (s_new, _excess) = apply_batch_full(&state, &batch);
            // The leaf's committed boundary must match the native state.
            assert_eq!(leaf.initial.0, commit_gk_state(&state).0);
            assert_eq!(leaf.final_.0, commit_gk_state(&s_new).0);
            leaves.push(EpochLeaf::new(i, leaf.initial.0, leaf.final_.0, leaf.batch_commit.0, i));
            state = s_new;
        }
        let com_s4 = commit_gk_state(&state).0;

        // §4.1: the raw per-epoch chain is contiguous + boundary-consistent.
        verify_epoch_chain(&leaves, 1).expect("real epoch chain valid");

        // §4.3(a/b/c): all three topologies certify Com(S_0) → Com(S_4).
        let chain = compose_chain(&leaves).expect("chain");
        let tree = compose_tree(&leaves).expect("tree (4 = 2^2)");
        let mut forest = StreamingForest::new();
        for l in &leaves {
            forest.insert(l).expect("forest insert");
        }
        let forest_root = forest.finalize().expect("forest finalize");

        for root in [&chain, &tree, &forest_root] {
            assert_eq!((root.lo, root.hi), (1, 4));
            assert_eq!(root.com_before, com_s0, "outer-left boundary = Com(S_0)");
            assert_eq!(root.com_after, com_s4, "outer-right boundary = Com(S_4)");
        }
        // Balanced shape: forest at t=4 (a single size-4 subtree) equals the
        // balanced tree exactly (digest included).
        assert_eq!(forest_root, tree);
    }
}
