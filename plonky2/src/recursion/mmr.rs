//! Merkle Mountain Range over the per-batch input commitments Com(B_1..B_t), with O(log t) inclusion proofs.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::config::F;
use crate::recursion::framework::Commit; // HashOut<F>

/// 2-to-1 node hash over two child digests, in the canonical Poseidon family.
fn node_hash(l: &Commit, r: &Commit) -> Commit {
    let mut buf = [F::ZERO; 8];
    buf[..4].copy_from_slice(&l.elements);
    buf[4..].copy_from_slice(&r.elements);
    PoseidonHash::hash_no_pad(&buf)
}

/// `Com` encoding the leaf count (binds the log size into the root).
fn size_leaf(t: usize) -> Commit {
    let mut s = [F::ZERO; 4];
    s[0] = F::from_canonical_u64(t as u64);
    HashOut { elements: s }
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

/// Append-only MMR over batch input commitments.
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

    /// Merkle root of the perfect tree over `leaves[start..start+size]`.
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

    /// The single published log root: bag the peaks then bind the leaf count.
    pub fn root(&self) -> Commit {
        bag(&self.peaks(), self.leaves.len())
    }

    /// Inclusion proof for the `index`-th batch commitment against the current root.
    pub fn prove(&self, index: usize) -> InclusionProof {
        assert!(index < self.leaves.len(), "index out of range");
        let ranges = peak_ranges(self.leaves.len());
        let peak_index = ranges.iter().position(|&(s, sz)| index >= s && index < s + sz).unwrap();
        let (start, size) = ranges[peak_index];
        let mut path = Vec::new();
        let mut level: Vec<Commit> = self.leaves[start..start + size].to_vec();
        let mut off = index - start;
        while level.len() > 1 {
            let sib = if off % 2 == 0 { off + 1 } else { off - 1 };
            path.push(level[sib]);
            level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
            off /= 2;
        }
        InclusionProof { index, leaf_count: self.leaves.len(), path, peaks: self.peaks(), peak_index }
    }
}

/// Bag the peaks right-to-left, then bind the leaf count.
fn bag(peaks: &[Commit], leaf_count: usize) -> Commit {
    let acc = if peaks.is_empty() {
        HashOut { elements: [F::ZERO; 4] }
    } else {
        let mut acc = peaks[peaks.len() - 1];
        for p in peaks[..peaks.len() - 1].iter().rev() {
            acc = node_hash(p, &acc);
        }
        acc
    };
    node_hash(&size_leaf(leaf_count), &acc)
}

/// Verify an inclusion proof for `leaf` against the published `root`.
pub fn verify_inclusion(root: &Commit, leaf: &Commit, proof: &InclusionProof) -> bool {
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
        HashOut {
            elements: std::array::from_fn(|lane| {
                F::from_canonical_u64(x.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(lane as u64))
            }),
        }
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
        assert!(!verify_inclusion(&root, &com(999), &proof));
        let mut bad = proof.clone();
        if !bad.path.is_empty() {
            bad.path[0] = com(424242);
        }
        assert!(!verify_inclusion(&root, &com(5), &bad));
        let mut bad2 = proof.clone();
        bad2.peaks[0] = com(7777);
        assert!(!verify_inclusion(&root, &com(5), &bad2));
    }

    #[test]
    fn append_changes_root_and_old_proof_does_not_carry() {
        let m1 = build(8);
        let r1 = m1.root();
        let m2 = build(9);
        let r2 = m2.root();
        assert_ne!(r1, r2, "appending a batch commitment changes the log root");
        let p = m1.prove(3);
        assert!(!verify_inclusion(&r2, &com(3), &p));
        assert!(verify_inclusion(&r1, &com(3), &p));
    }
}
