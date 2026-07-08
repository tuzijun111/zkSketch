//! **HyperLogLog sparse-rebind via a Merkle vector commitment** (plonky2) —
//! the Pattern-A rebind for HLL, the §5.2 sparse-opening commit applied to the
//! register array.
//!
//! HLL's register array `m = 2^b` grows with the accuracy target (≈2¹⁴ for ~1%
//! error), just like Count-Min's width `w`. The flat HLL leaf
//! ([`super::hyperloglog`]) re-hashes all `m` registers per epoch (`Θ(m)`) and
//! scatters every record over every register (`O(m·batch)`). Here `Com(S)` is a
//! **Merkle root** over the `m` registers, and a batch touches only the
//! `T ≤ min(batch, m)` distinct registers its keys route to — so the rebind is
//! `Θ(T·log m)`, **independent of `m`**.
//!
//! It is structurally the single-tree (`d = 1`) Count-Min Merkle leaf
//! ([`super::countmin_merkle`]), with two differences dictated by HLL:
//! - the cell "value" is the **derived rank** `ρ = 1 + trailing_zeros(digest[1])`
//!   (re-derived in-circuit — the prover can neither pick the register nor
//!   inflate ρ), not a supplied count; and
//! - the per-register aggregation is a **max** (`new = max(old, routed ρ)`),
//!   enforced by the flat HLL leaf's product-of-differences + range gadget,
//!   instead of a sum.
//!
//! Register routing (`idx = digest[0] mod m`) and ρ derivation mirror
//! [`crate::sketch::hyperloglog::hash_register`] exactly, so the leaf is a
//! faithful HLL update. The flat HLL leaf remains the baseline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::leaf::hyperloglog::REGISTER_WIDTH;
use crate::recursion::Node;
use crate::sketch::hyperloglog::{hash_register, RHO_WINDOW};

/// Shape of a sparse-rebind HLL leaf: `m = 2^b` registers, `batch` records per
/// epoch, capacity `t_max` for distinct touched registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HllMerkleParams {
    /// Register-index bits; `m = 2^b` registers.
    pub b: usize,
    /// Records per epoch.
    pub batch: usize,
    /// Compile-time bound on distinct touched registers (`1 ≤ t_max ≤ m`).
    pub t_max: usize,
}

impl HllMerkleParams {
    pub fn m(&self) -> usize {
        1usize << self.b
    }
    pub fn validate(&self) {
        assert!(self.b >= 2 && self.b <= 16, "b in [2,16]; got {}", self.b);
        assert!(self.batch >= 1, "batch must be positive");
        assert!(self.t_max >= 1 && self.t_max <= self.m(), "t_max in [1, m]");
    }
    /// Merkle tree height = `b` (a perfect tree over `m = 2^b` leaves).
    pub fn height(&self) -> usize {
        self.b
    }
}

/// Merkle root over the `m` register cells (each a single-element leaf).
pub fn merkle_root(cells: &[F]) -> HashOut<F> {
    let leaves: Vec<Vec<F>> = cells.iter().map(|&c| vec![c]).collect();
    MerkleTree::<F, PoseidonHash>::new(leaves, 0).cap.0[0]
}

fn cells_f(cells: &[u64]) -> Vec<F> {
    cells.iter().map(|&c| F::from_canonical_u64(c)).collect()
}

/// Canonical little-endian 64-bit decomposition (pins unique bits despite the
/// `x`/`x+p` wraparound ambiguity) — copy of the flat HLL leaf's helper.
fn canonical_bits_64(b: &mut CircuitBuilder<F, D>, x: Target) -> Vec<BoolTarget> {
    let bits = b.split_le(x, 64);
    let one = b.one();
    let zero = b.zero();
    let mut all_hi = one;
    for bit in bits.iter().skip(32) {
        all_hi = b.mul(all_hi, bit.target);
    }
    let mut none_lo = one;
    for bit in bits.iter().take(32) {
        let omb = b.sub(one, bit.target);
        none_lo = b.mul(none_lo, omb);
    }
    let any_lo = b.sub(one, none_lo);
    let bad = b.mul(all_hi, any_lo);
    b.connect(bad, zero);
    bits
}

struct Tgt {
    init_root: HashOutTarget,
    final_root: HashOutTarget,
    batch_commit: HashOutTarget,
    keys: Vec<Target>,
    sel: Vec<Vec<Target>>,             // [batch][t_max] one-hot record→op
    op_pos_bits: Vec<Vec<BoolTarget>>, // [t_max][b] register-index bits per op
    op_old: Vec<Target>,
    op_new: Vec<Target>,
    op_active: Vec<Target>,
    op_proof: Vec<MerkleProofTarget>, // [t_max] sibling paths
    mid_roots: Vec<HashOutTarget>,    // r_1 .. r_{t_max-1}
}

pub struct HllMerkleLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: HllMerkleParams,
}

pub fn build_hll_merkle_leaf(params: HllMerkleParams) -> HllMerkleLeaf {
    params.validate();
    let HllMerkleParams { b: bb, batch, t_max } = params;
    let h = params.height();
    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());
    let one = b.one();
    let zero = b.zero();

    // ── Public inputs: Com(S_{t-1}), Com(S_t), Com(B_t) ──────────────────────
    let init_root = b.add_virtual_hash();
    b.register_public_inputs(&init_root.elements);
    let final_root = b.add_virtual_hash();
    b.register_public_inputs(&final_root.elements);
    let batch_commit = b.add_virtual_hash();
    b.register_public_inputs(&batch_commit.elements);

    // ── Private witness ──────────────────────────────────────────────────────
    let keys = b.add_virtual_targets(batch);
    let sel: Vec<Vec<Target>> = (0..batch).map(|_| b.add_virtual_targets(t_max)).collect();
    let op_pos_bits: Vec<Vec<BoolTarget>> =
        (0..t_max).map(|_| (0..h).map(|_| b.add_virtual_bool_target_safe()).collect()).collect();
    let op_old = b.add_virtual_targets(t_max);
    let op_new = b.add_virtual_targets(t_max);
    let op_active = b.add_virtual_targets(t_max);
    let op_proof: Vec<MerkleProofTarget> = (0..t_max)
        .map(|_| MerkleProofTarget { siblings: (0..h).map(|_| b.add_virtual_hash()).collect() })
        .collect();
    let mid_roots: Vec<HashOutTarget> =
        (0..t_max.saturating_sub(1)).map(|_| b.add_virtual_hash()).collect();

    // ── S1: open the batch commitment over the keys ──────────────────────────
    let hb = b.hash_n_to_hash_no_pad::<PoseidonHash>(keys.clone());
    for i in 0..4 {
        b.connect(hb.elements[i], batch_commit.elements[i]);
    }

    let pow2: Vec<Target> = (0..h).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let op_pos: Vec<Target> = (0..t_max)
        .map(|c| {
            let mut p = zero;
            for j in 0..h {
                p = b.mul_add(op_pos_bits[c][j].target, pow2[j], p);
            }
            p
        })
        .collect();
    for c in 0..t_max {
        let am1 = b.sub(op_active[c], one);
        let chk = b.mul(op_active[c], am1);
        b.connect(chk, zero);
    }

    // ── S2: derive (idx, ρ) per record; route via a one-hot selector ─────────
    let mut lrs = Vec::with_capacity(batch);
    for k in 0..batch {
        let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![keys[k]]);
        // idx = digest[0] mod m (low b bits).
        let d0_bits = canonical_bits_64(&mut b, digest.elements[0]);
        let mut idx_t = zero;
        for j in 0..bb {
            idx_t = b.mul_add(d0_bits[j].target, pow2[j], idx_t);
        }
        // ρ = 1 + trailing_zeros(digest[1]) over the low RHO_WINDOW bits.
        let d1_bits = canonical_bits_64(&mut b, digest.elements[1]);
        let mut prod = one;
        let mut tz = zero;
        for bit in d1_bits.iter().take(RHO_WINDOW) {
            let omb = b.sub(one, bit.target);
            prod = b.mul(prod, omb);
            tz = b.add(tz, prod);
        }
        lrs.push(b.add(one, tz));
        // sel[k] one-hot over ops; route pos + active.
        let mut sum = zero;
        let mut routed_pos = zero;
        let mut routed_active = zero;
        for c in 0..t_max {
            let s = sel[k][c];
            let sm1 = b.sub(s, one);
            let chk = b.mul(s, sm1);
            b.connect(chk, zero); // boolean
            sum = b.add(sum, s);
            routed_pos = b.mul_add(s, op_pos[c], routed_pos);
            routed_active = b.mul_add(s, op_active[c], routed_active);
        }
        b.connect(sum, one); // exactly one op
        b.connect(routed_pos, idx_t); // selected op sits at the derived register
        b.connect(routed_active, one); // selected op is active
    }

    // ── S3: per-op max — new = max(old, {ρ_k routed to this op}) ─────────────
    // (product-of-differences + range checks, the flat HLL leaf's gadget, but
    // over the t_max distinct touched registers instead of all m.)
    for c in 0..t_max {
        let d0 = b.sub(op_new[c], op_old[c]);
        let _ = b.split_le(d0, REGISTER_WIDTH); // new >= old
        let mut prod = d0; // factor for the "keep old" candidate
        for k in 0..batch {
            // candidate_k = old + sel[k][c]·(ρ_k − old)  (= ρ_k if routed, else old)
            let lr_minus_old = b.sub(lrs[k], op_old[c]);
            let scaled = b.mul(sel[k][c], lr_minus_old);
            let cand = b.add(op_old[c], scaled);
            let diff = b.sub(op_new[c], cand);
            let _ = b.split_le(diff, REGISTER_WIDTH); // new >= candidate_k
            prod = b.mul(prod, diff);
        }
        b.connect(prod, zero); // new is one of {old} ∪ {ρ_k routed}
    }

    // ── S5: Merkle update chain r_0=init → r_T=final ─────────────────────────
    for c in 0..t_max {
        let r_in = if c == 0 { init_root } else { mid_roots[c - 1] };
        let r_out = if c == t_max - 1 { final_root } else { mid_roots[c] };
        b.verify_merkle_proof::<PoseidonHash>(vec![op_old[c]], &op_pos_bits[c], r_in, &op_proof[c]);
        b.verify_merkle_proof::<PoseidonHash>(vec![op_new[c]], &op_pos_bits[c], r_out, &op_proof[c]);
    }

    let data = Arc::new(b.build::<C>());
    HllMerkleLeaf {
        data,
        t: Tgt {
            init_root, final_root, batch_commit, keys, sel, op_pos_bits, op_old, op_new,
            op_active, op_proof, mid_roots,
        },
        params,
    }
}

impl HllMerkleLeaf {
    pub fn prove(&self, initial: &[u64], keys: &[u64], index: u64) -> Result<Node> {
        self.prove_timed(initial, keys, index).map(|(n, _, _)| n)
    }

    /// Prove one sparse-rebind epoch. `initial` is the `m` register values;
    /// `keys` is the `batch` record keys.
    pub fn prove_timed(
        &self,
        initial: &[u64],
        keys: &[u64],
        index: u64,
    ) -> Result<(Node, Duration, Duration)> {
        let HllMerkleParams { b: bb, batch: m_batch, t_max } = self.params;
        let m = self.params.m();
        assert_eq!(initial.len(), m, "initial registers != m");
        assert_eq!(keys.len(), m_batch, "keys length != batch");
        let h = self.params.height();
        let t_w = Instant::now();

        // Native: route each record to its register, build the distinct-touched
        // op list, fold by max.
        let mut cells: Vec<u64> = initial.to_vec();
        let mut op_pos: Vec<usize> = Vec::new();
        let mut record_op = vec![0usize; m_batch];
        let mut rhos = vec![0u64; m_batch];
        for (k, &key) in keys.iter().enumerate() {
            let (idx, rho) = hash_register(bb, key);
            rhos[k] = rho;
            let c = op_pos.iter().position(|&q| q == idx).unwrap_or_else(|| {
                op_pos.push(idx);
                op_pos.len() - 1
            });
            record_op[k] = c;
        }
        assert!(op_pos.len() <= t_max, "touched registers {} exceed t_max {}", op_pos.len(), t_max);

        let init_root = merkle_root(&cells_f(&cells));
        let mut op_old = vec![0u64; t_max];
        let mut op_new = vec![0u64; t_max];
        let mut op_active = vec![0u64; t_max];
        let mut op_used_pos = vec![0usize; t_max];
        let mut roots: Vec<HashOut<F>> = Vec::with_capacity(t_max + 1);
        roots.push(init_root);
        let mut snap: Vec<u64> = initial.to_vec();

        let mut pw = PartialWitness::<F>::new();
        for c in 0..t_max {
            let (pos, active) = if c < op_pos.len() { (op_pos[c], 1u64) } else { (0usize, 0u64) };
            // new = max(old, max routed ρ).
            let routed_max = keys
                .iter()
                .enumerate()
                .filter(|(k, _)| active == 1 && record_op[*k] == c)
                .map(|(k, _)| rhos[k])
                .max()
                .unwrap_or(0);
            op_used_pos[c] = pos;
            let old = cells[pos];
            let new = old.max(routed_max);
            op_old[c] = old;
            op_new[c] = new;
            op_active[c] = active;
            for j in 0..h {
                pw.set_bool_target(self.t.op_pos_bits[c][j], ((pos >> j) & 1) == 1)?;
            }
            pw.set_target(self.t.op_old[c], F::from_canonical_u64(old))?;
            pw.set_target(self.t.op_new[c], F::from_canonical_u64(new))?;
            pw.set_target(self.t.op_active[c], F::from_canonical_u64(active))?;
            // sibling path for `pos` in the tree BEFORE this op.
            let tree = MerkleTree::<F, PoseidonHash>::new(
                snap.iter().map(|&v| vec![F::from_canonical_u64(v)]).collect(),
                0,
            );
            let proof = tree.prove(pos);
            for (j, sib) in proof.siblings.iter().enumerate() {
                pw.set_hash_target(self.t.op_proof[c].siblings[j], *sib)?;
            }
            snap[pos] = new;
            cells[pos] = new;
            roots.push(merkle_root(&cells_f(&cells)));
            if c < self.t.mid_roots.len() {
                pw.set_hash_target(self.t.mid_roots[c], roots[c + 1])?;
            }
            for k in 0..m_batch {
                let v = if record_op[k] == c { F::ONE } else { F::ZERO };
                pw.set_target(self.t.sel[k][c], v)?;
            }
        }
        let final_root = *roots.last().unwrap();

        pw.set_hash_target(self.t.init_root, init_root)?;
        pw.set_hash_target(self.t.final_root, final_root)?;
        let key_f: Vec<F> = keys.iter().map(|&k| F::from_canonical_u64(k)).collect();
        pw.set_hash_target(self.t.batch_commit, PoseidonHash::hash_no_pad(&key_f))?;
        for (k, &key) in keys.iter().enumerate() {
            pw.set_target(self.t.keys[k], F::from_canonical_u64(key))?;
        }

        let witness = t_w.elapsed();
        let t_p = Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((Node::leaf(self.data.clone(), proof, init_root, final_root, index), witness, prove))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};

    /// Native register array after a max-fold of the batch.
    fn native_apply(initial: &[u64], keys: &[u64], b: usize) -> Vec<u64> {
        let mut c = initial.to_vec();
        for &key in keys {
            let (idx, rho) = hash_register(b, key);
            if rho > c[idx] {
                c[idx] = rho;
            }
        }
        c
    }

    #[test]
    fn hll_merkle_round_trip() -> Result<()> {
        let params = HllMerkleParams { b: 6, batch: 4, t_max: 4 };
        let leaf = build_hll_merkle_leaf(params);
        let initial = vec![0u64; 1 << 6];
        let keys = vec![7u64, 11, 7, 3];
        let node = leaf.prove(&initial, &keys, 1)?;
        assert_eq!(node.final_, merkle_root(&cells_f(&native_apply(&initial, &keys, 6))));
        verify_node(&node)
    }

    /// Large register array, tiny batch: touches ≤ t_max registers, so the
    /// rebind pays O(t_max·log m), NOT O(m). The flat HLL leaf hashes all m.
    #[test]
    fn hll_merkle_large_state_small_patch() -> Result<()> {
        let params = HllMerkleParams { b: 12, batch: 4, t_max: 4 };
        let leaf = build_hll_merkle_leaf(params);
        let initial = vec![0u64; 1 << 12];
        let keys = vec![123u64, 777, 123, 9];
        let node = leaf.prove(&initial, &keys, 1)?;
        assert_eq!(node.final_, merkle_root(&cells_f(&native_apply(&initial, &keys, 12))));
        verify_node(&node)
    }

    /// Two HLL-merkle leaves chain like any other leaf (recursive merge).
    #[test]
    fn hll_merkle_two_leaf_merge() -> Result<()> {
        let params = HllMerkleParams { b: 6, batch: 4, t_max: 4 };
        let leaf = build_hll_merkle_leaf(params);
        let s0 = vec![0u64; 1 << 6];
        let k1 = vec![7u64, 11, 7, 3];
        let n1 = leaf.prove(&s0, &k1, 1)?;
        let s1 = native_apply(&s0, &k1, 6);
        let k2 = vec![9u64, 7, 2, 5];
        let n2 = leaf.prove(&s1, &k2, 2)?;
        let root = merge(&n1, &n2)?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }

    /// A claimed final root that isn't the honest max-rebind must be rejected.
    #[test]
    fn hll_merkle_rejects_tampered_final_root() {
        let params = HllMerkleParams { b: 6, batch: 2, t_max: 2 };
        let leaf = build_hll_merkle_leaf(params);
        let initial = vec![0u64; 1 << 6];
        let keys = vec![7u64, 3];
        let bb = 6;
        let mut cells = initial.clone();
        let mut op_pos: Vec<usize> = Vec::new();
        let mut record_op = vec![0usize; 2];
        let mut rhos = vec![0u64; 2];
        for (k, &key) in keys.iter().enumerate() {
            let (idx, rho) = hash_register(bb, key);
            rhos[k] = rho;
            let c = op_pos.iter().position(|&q| q == idx).unwrap_or_else(|| { op_pos.push(idx); op_pos.len() - 1 });
            record_op[k] = c;
        }
        let init_root = merkle_root(&cells_f(&cells));
        let h = params.height();
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.init_root, init_root).unwrap();
        // WRONG final root (the init root — not the rebind result).
        pw.set_hash_target(leaf.t.final_root, init_root).unwrap();
        let key_f: Vec<F> = keys.iter().map(|&k| F::from_canonical_u64(k)).collect();
        pw.set_hash_target(leaf.t.batch_commit, PoseidonHash::hash_no_pad(&key_f)).unwrap();
        for (k, &key) in keys.iter().enumerate() {
            pw.set_target(leaf.t.keys[k], F::from_canonical_u64(key)).unwrap();
            for c in 0..2 {
                pw.set_target(leaf.t.sel[k][c], if record_op[k] == c { F::ONE } else { F::ZERO }).unwrap();
            }
        }
        let mut snap = initial.clone();
        for c in 0..2 {
            let (pos, active) = if c < op_pos.len() { (op_pos[c], 1u64) } else { (0usize, 0u64) };
            let routed_max = keys.iter().enumerate()
                .filter(|(k, _)| active == 1 && record_op[*k] == c)
                .map(|(k, _)| rhos[k]).max().unwrap_or(0);
            let old = cells[pos];
            let new = old.max(routed_max);
            for j in 0..h { pw.set_bool_target(leaf.t.op_pos_bits[c][j], ((pos >> j) & 1) == 1).unwrap(); }
            pw.set_target(leaf.t.op_old[c], F::from_canonical_u64(old)).unwrap();
            pw.set_target(leaf.t.op_new[c], F::from_canonical_u64(new)).unwrap();
            pw.set_target(leaf.t.op_active[c], F::from_canonical_u64(active)).unwrap();
            let tree = MerkleTree::<F, PoseidonHash>::new(snap.iter().map(|&v| vec![F::from_canonical_u64(v)]).collect(), 0);
            let proof = tree.prove(pos);
            for (j, sib) in proof.siblings.iter().enumerate() { pw.set_hash_target(leaf.t.op_proof[c].siblings[j], *sib).unwrap(); }
            snap[pos] = new;
            cells[pos] = new;
        }
        assert!(leaf.data.prove(pw).is_err(), "tampered final root must be rejected");
    }
}
