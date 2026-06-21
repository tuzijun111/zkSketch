//! **Standalone Merkle Mountain Range (MMR) over the per-batch input
//! commitments** `{Com(B_1), …, Com(B_t)}` — the append-only *upload log* (ULog).
//!
//! This is the input-commitment log as a **separate artifact**, decoupled from
//! the proof/state composition: the streaming forest folds `Com(B_t)` into the
//! unified history root `R(t)` (carrying boundary/order/transition semantics);
//! this MMR instead binds *just the ordered batch input commitments* into one
//! published root, so a light client can prove "batch `i`'s committed input is in
//! the log" in `O(log t)` without verifying any transition proof — the standard
//! transparency-log pattern (CT / Grin / FlyClient).
//!
//! - **Append-only, `O(1)` amortized append** (binary-counter peak cascade).
//! - **One root** = bag the `popcount(t)` peaks, with the leaf count bound in.
//! - **`O(log t)` inclusion proofs**, verifiable by anyone holding the root.
//!
//! Nodes hash in the project's `MyHash` family (`PaddingFreeSponge<Perm,16,8,8>`),
//! the same one the commitments use, and leaves are the `Com(B_t)` digests
//! themselves.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::config::{make_perm, MyHash, Val};
use crate::recursion::framework::Commit; // [Val; 8]

/// 2-to-1 node hash over two child digests, in the canonical `MyHash` family.
fn node_hash(l: &Commit, r: &Commit) -> Commit {
    let mut buf = [Val::ZERO; 16];
    buf[..8].copy_from_slice(l);
    buf[8..].copy_from_slice(r);
    MyHash::new(make_perm()).hash_iter(buf)
}

/// `Com` encoding the leaf count (binds the log size into the root).
fn size_leaf(t: usize) -> Commit {
    let mut s = [Val::ZERO; 8];
    s[0] = Val::from_u64(t as u64);
    s
}

/// Binary decomposition of `t` into perfect-tree peak ranges `(start, size)`,
/// largest peak first. e.g. `t = 11 = 8+2+1 → [(0,8),(8,2),(10,1)]`.
fn peak_ranges(t: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0usize;
    let mut bit = 1usize;
    while bit <= t {
        bit <<= 1;
    }
    while bit > 1 {
        bit >>= 1;
        if t & bit != 0 {
            ranges.push((start, bit));
            start += bit;
        }
    }
    ranges
}

/// An inclusion proof that `Com(B_index)` is the `index`-th leaf of a log of
/// `leaf_count` entries committing to `root`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: usize,
    pub leaf_count: usize,
    /// Sibling digests on the path from the leaf to its peak, bottom-up.
    pub path: Vec<Commit>,
    /// All peak roots, largest-first (so the verifier can re-bag the root).
    pub peaks: Vec<Commit>,
    /// Which peak (index into `peaks`) contains the leaf.
    pub peak_index: usize,
}

/// Append-only MMR over batch input commitments. Stores the leaves; peaks, root,
/// and proofs are derived (a production log would cache node digests, but
/// recompute-from-leaves is correct and keeps the artifact simple).
#[derive(Clone, Debug, Default)]
pub struct Mmr {
    leaves: Vec<Commit>,
}

impl Mmr {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
    /// Append one batch input commitment (`O(1)`).
    pub fn append(&mut self, com: Commit) {
        self.leaves.push(com);
    }
    /// Number of surviving peaks = `popcount(t)`.
    pub fn num_peaks(&self) -> usize {
        self.leaves.len().count_ones() as usize
    }

    /// Merkle root of the perfect tree over `leaves[start..start+size]` (`size`
    /// a power of two).
    fn perfect_root(&self, start: usize, size: usize) -> Commit {
        let mut level: Vec<Commit> = self.leaves[start..start + size].to_vec();
        while level.len() > 1 {
            level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
        }
        level[0]
    }

    fn peaks(&self) -> Vec<Commit> {
        peak_ranges(self.leaves.len())
            .iter()
            .map(|&(s, sz)| self.perfect_root(s, sz))
            .collect()
    }

    /// The single published log root: bag the peaks (right-to-left) then bind the
    /// leaf count.
    pub fn root(&self) -> Commit {
        bag(&self.peaks(), self.leaves.len())
    }

    /// Inclusion proof for the `index`-th batch commitment against the current root.
    pub fn prove(&self, index: usize) -> InclusionProof {
        assert!(index < self.leaves.len(), "index out of range");
        let ranges = peak_ranges(self.leaves.len());
        let peak_index = ranges.iter().position(|&(s, sz)| index >= s && index < s + sz).unwrap();
        let (start, size) = ranges[peak_index];
        // Merkle path within the peak's perfect tree.
        let mut path = Vec::new();
        let mut level: Vec<Commit> = self.leaves[start..start + size].to_vec();
        let mut off = index - start;
        while level.len() > 1 {
            let sib = if off % 2 == 0 { off + 1 } else { off - 1 };
            path.push(level[sib]);
            level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
            off /= 2;
        }
        InclusionProof {
            index,
            leaf_count: self.leaves.len(),
            path,
            peaks: self.peaks(),
            peak_index,
        }
    }
}

/// Bag the peaks right-to-left, then bind the leaf count.
fn bag(peaks: &[Commit], leaf_count: usize) -> Commit {
    let acc = if peaks.is_empty() {
        [Val::ZERO; 8]
    } else {
        let mut acc = peaks[peaks.len() - 1];
        for p in peaks[..peaks.len() - 1].iter().rev() {
            acc = node_hash(p, &acc);
        }
        acc
    };
    node_hash(&size_leaf(leaf_count), &acc)
}

/// Verify an inclusion proof for `leaf` against the published `root` — the
/// auditor's check, no log state needed.
pub fn verify_inclusion(root: &Commit, leaf: &Commit, proof: &InclusionProof) -> bool {
    // Recompute the peak root from the leaf and its path (offset bits give L/R).
    let ranges = peak_ranges(proof.leaf_count);
    if proof.peak_index >= ranges.len() || proof.peaks.len() != ranges.len() {
        return false;
    }
    let (start, _size) = ranges[proof.peak_index];
    let mut node = *leaf;
    let mut off = proof.index - start;
    for sib in &proof.path {
        node = if off % 2 == 0 { node_hash(&node, sib) } else { node_hash(sib, &node) };
        off /= 2;
    }
    if node != proof.peaks[proof.peak_index] {
        return false;
    }
    bag(&proof.peaks, proof.leaf_count) == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn com(x: u64) -> Commit {
        let mut c = [Val::ZERO; 8];
        for (lane, slot) in c.iter_mut().enumerate() {
            *slot = Val::from_u64(x.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(lane as u64));
        }
        c
    }

    fn build(t: usize) -> Mmr {
        let mut m = Mmr::new();
        for i in 0..t {
            m.append(com(i as u64));
        }
        m
    }

    #[test]
    fn every_leaf_proves_against_root() {
        for &t in &[1usize, 2, 3, 4, 7, 8, 11, 16, 23] {
            let m = build(t);
            let root = m.root();
            assert_eq!(m.num_peaks(), t.count_ones() as usize);
            for i in 0..t {
                let proof = m.prove(i);
                assert!(verify_inclusion(&root, &com(i as u64), &proof), "leaf {i} of {t} must prove");
            }
        }
    }

    #[test]
    fn rejects_wrong_leaf_and_tampered_proof() {
        let m = build(11);
        let root = m.root();
        let proof = m.prove(5);
        assert!(verify_inclusion(&root, &com(5), &proof));
        // Wrong leaf value at the right index.
        assert!(!verify_inclusion(&root, &com(999), &proof));
        // Tampered sibling.
        let mut bad = proof.clone();
        if !bad.path.is_empty() {
            bad.path[0] = com(424242);
        }
        assert!(!verify_inclusion(&root, &com(5), &bad));
        // Tampered peak.
        let mut bad2 = proof.clone();
        bad2.peaks[0] = com(7777);
        assert!(!verify_inclusion(&root, &com(5), &bad2));
    }

    #[test]
    fn append_changes_root_and_old_proof_does_not_carry() {
        let m1 = build(8);
        let r1 = m1.root();
        let m2 = build(9); // appended one more
        let r2 = m2.root();
        assert_ne!(r1, r2, "appending a batch commitment changes the log root");
        // An inclusion proof generated against the size-8 log must not verify
        // against the size-9 root (size is bound in).
        let p = m1.prove(3);
        assert!(!verify_inclusion(&r2, &com(3), &p));
        assert!(verify_inclusion(&r1, &com(3), &p));
    }
}
