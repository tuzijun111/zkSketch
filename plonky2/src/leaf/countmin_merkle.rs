//! **Count-Min sparse-patch rebind via a Merkle vector commitment** (plonky2),
//! realizing zk1.tex §5.2 Step 7 — the Pattern-A rebind whose cost scales with
//! the number of *touched* cells `T`, not the whole array `w`.
//!
//! The other CM leaves commit the state with a **flat** Poseidon sponge over all
//! `w` cells, so a rebind costs `Θ(w)`. Here `Com(S)` is a **Merkle root** over
//! the `w` cells, and the rebind opens only the `T` touched cells via a
//! **Merkle update chain**: thread the root `r_0 = Com(S_{t-1}) → … → r_T =
//! Com(S_t)` through `T` single-leaf updates, each verifying the old value
//! against `r_{c-1}` and the new value against `r_c` with the **same** sibling
//! path. Untouched cells never appear (they carry through the shared siblings),
//! so the rebind is `Θ(T·log w)`, independent of `w`. Threading is what makes
//! repeated/overlapping touches sound: a second touch of a cell sees the first
//! update already folded into the current root.
//!
//! This is a single-row (`d = 1`) demonstration of the sparse rebind; a full
//! `d`-row Count-Min uses `d` such trees (or one flat tree of `d·w` cells), the
//! rebind machinery is identical. The flat-commit leaves
//! ([`super::countmin_final`]) remain the baseline.
//!
//! ## Soundness sketch
//! - **Batch opened:** `Com(B_t)` binds the witnessed `(key, value)` records.
//! - **Routing (S2):** each record's cell `pos = digest[0] mod w` is derived
//!   in-circuit from `Poseidon(key)` (canonical low bits — see
//!   [`canonical_bits_64`]); a one-hot selector maps each record to an *active*
//!   patch op whose position equals that derived `pos`, so every contribution
//!   lands at the right cell.
//! - **Aggregate (S3):** `new_c = old_c + Σ_{records→c} value`.
//! - **Rebind (S5):** the Merkle update chain ties `old_c`/`new_c` to
//!   `Com(S_{t-1})`/`Com(S_t)`; untouched cells are unchanged because only the
//!   touched leaf moves along each path.

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
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::recursion::Node;
use crate::sketch::countmin::CountMinUpdate;

/// Shape of a sparse-rebind CM-row leaf: a width-`w` counter row, `batch`
/// records per epoch, capacity `t_max` for distinct touched cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmMerkleParams {
    pub w: usize,
    pub batch: usize,
    pub t_max: usize,
}

impl CmMerkleParams {
    pub fn validate(&self) {
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of 2 >= 2");
        assert!(self.batch >= 1, "batch must be positive");
        assert!(self.t_max >= 1 && self.t_max <= self.w, "t_max in [1, w]");
    }
    pub fn height(&self) -> usize {
        self.w.trailing_zeros() as usize
    }
}

/// `pos = digest[0] mod w` — the cell a key routes to (native mirror of the
/// in-circuit derivation).
pub fn pos_of(key: u64, w: usize) -> usize {
    let digest = PoseidonHash::hash_no_pad(&[F::from_canonical_u64(key)]);
    (digest.elements[0].to_canonical_u64() % w as u64) as usize
}

/// Merkle root over `w` counter cells (each a single-element leaf), `cap_height = 0`.
pub fn merkle_root(cells: &[F]) -> HashOut<F> {
    let leaves: Vec<Vec<F>> = cells.iter().map(|&c| vec![c]).collect();
    MerkleTree::<F, PoseidonHash>::new(leaves, 0).cap.0[0]
}

// ── In-circuit gadgets ───────────────────────────────────────────────────────

/// Canonical little-endian 64-bit decomposition of a Goldilocks element (pins the
/// unique bits despite the `x`/`x+p` wraparound ambiguity of a plain 64-bit
/// split). `p − 1 = 0xFFFFFFFF_00000000`, so forbid all high-32 ones with any
/// low-32 bit set.
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
    values: Vec<Target>,
    sel: Vec<Vec<Target>>,          // [batch][t_max] one-hot record→op
    op_pos_bits: Vec<Vec<BoolTarget>>, // [t_max][height] position bits per op
    op_old: Vec<Target>,
    op_new: Vec<Target>,
    op_active: Vec<Target>,
    op_proof: Vec<MerkleProofTarget>, // [t_max] sibling paths
    mid_roots: Vec<HashOutTarget>,    // r_1 .. r_{t_max-1}
}

pub struct CmMerkleLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: CmMerkleParams,
}

pub fn build_cm_merkle_leaf(params: CmMerkleParams) -> CmMerkleLeaf {
    params.validate();
    let CmMerkleParams { w: _w, batch, t_max } = params;
    let h = params.height();
    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
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
    let values = b.add_virtual_targets(batch);
    let sel: Vec<Vec<Target>> = (0..batch).map(|_| b.add_virtual_targets(t_max)).collect();
    let op_pos_bits: Vec<Vec<BoolTarget>> =
        (0..t_max).map(|_| (0..h).map(|_| b.add_virtual_bool_target_safe()).collect()).collect();
    let op_old = b.add_virtual_targets(t_max);
    let op_new = b.add_virtual_targets(t_max);
    let op_active = b.add_virtual_targets(t_max);
    let op_proof: Vec<MerkleProofTarget> = (0..t_max)
        .map(|_| MerkleProofTarget { siblings: (0..h).map(|_| b.add_virtual_hash()).collect() })
        .collect();
    let mid_roots: Vec<HashOutTarget> = (0..t_max.saturating_sub(1)).map(|_| b.add_virtual_hash()).collect();

    // ── S1: open the batch commitment over (key, value) ──────────────────────
    let mut batch_pre = Vec::with_capacity(2 * batch);
    for k in 0..batch {
        batch_pre.push(keys[k]);
        batch_pre.push(values[k]);
    }
    let hb = b.hash_n_to_hash_no_pad::<PoseidonHash>(batch_pre);
    for i in 0..4 {
        b.connect(hb.elements[i], batch_commit.elements[i]);
    }

    // Per-op position value from its bits: pos_c = Σ bit·2^i.
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
    // op_active boolean.
    for c in 0..t_max {
        let am1 = b.sub(op_active[c], one);
        let chk = b.mul(op_active[c], am1);
        b.connect(chk, zero);
    }

    // ── S2: derive each record's cell pos = digest[0] mod w; route via one-hot ─
    for k in 0..batch {
        let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![keys[k]]);
        let bits = canonical_bits_64(&mut b, digest.elements[0]);
        let mut pos_k = zero;
        for j in 0..h {
            pos_k = b.mul_add(bits[j].target, pow2[j], pos_k);
        }
        // sel[k] one-hot.
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
        b.connect(routed_pos, pos_k); // selected op sits at the derived cell
        b.connect(routed_active, one); // selected op is active
    }

    // ── S3: per-op increment = Σ routed values; new = old + increment ─────────
    for c in 0..t_max {
        let mut inc = zero;
        for k in 0..batch {
            inc = b.mul_add(sel[k][c], values[k], inc);
        }
        let expect_new = b.add(op_old[c], inc);
        b.connect(op_new[c], expect_new);
    }

    // ── S5: Merkle update chain r_0=init → r_T=final ─────────────────────────
    for c in 0..t_max {
        let r_in = if c == 0 { init_root } else { mid_roots[c - 1] };
        let r_out = if c == t_max - 1 { final_root } else { mid_roots[c] };
        // old value opens at pos_c in r_in; new value opens at pos_c in r_out
        // (same siblings ⇒ only the touched leaf moves).
        b.verify_merkle_proof::<PoseidonHash>(vec![op_old[c]], &op_pos_bits[c], r_in, &op_proof[c]);
        b.verify_merkle_proof::<PoseidonHash>(vec![op_new[c]], &op_pos_bits[c], r_out, &op_proof[c]);
    }

    let data = Arc::new(b.build::<C>());
    CmMerkleLeaf {
        data,
        t: Tgt {
            init_root, final_root, batch_commit, keys, values, sel, op_pos_bits,
            op_old, op_new, op_active, op_proof, mid_roots,
        },
        params,
    }
}

impl CmMerkleLeaf {
    pub fn prove(&self, initial: &[u64], batch: &[CountMinUpdate], index: u64) -> Result<Node> {
        self.prove_timed(initial, batch, index).map(|(n, _, _)| n)
    }

    /// Prove one sparse-rebind epoch. `initial` is the `w` counter cells.
    pub fn prove_timed(
        &self,
        initial: &[u64],
        batch: &[CountMinUpdate],
        index: u64,
    ) -> Result<(Node, Duration, Duration)> {
        let CmMerkleParams { w, batch: m, t_max } = self.params;
        assert_eq!(initial.len(), w, "initial cells != w");
        assert_eq!(batch.len(), m, "batch length != m");
        let h = self.params.height();
        let t_w = Instant::now();

        // Native apply: route each record, build the distinct-touched op list.
        let mut cells: Vec<u64> = initial.to_vec();
        let mut op_pos: Vec<usize> = Vec::new(); // distinct touched positions, first-touch order
        let mut record_op = vec![0usize; m]; // which op each record routes to
        for (k, u) in batch.iter().enumerate() {
            let p = pos_of(u.key, w);
            let c = op_pos.iter().position(|&q| q == p).unwrap_or_else(|| {
                op_pos.push(p);
                op_pos.len() - 1
            });
            record_op[k] = c;
        }
        assert!(op_pos.len() <= t_max, "touched cells {} exceed t_max {}", op_pos.len(), t_max);

        let init_root = merkle_root(&cells_f(&cells));
        // Apply ops in order, recording (old, new) and intermediate roots.
        let mut op_old = vec![0u64; t_max];
        let mut op_new = vec![0u64; t_max];
        let mut op_active = vec![0u64; t_max];
        let mut roots: Vec<HashOut<F>> = Vec::with_capacity(t_max + 1);
        roots.push(init_root);
        let mut op_used_pos = vec![0usize; t_max];
        for c in 0..t_max {
            let (pos, inc, active) = if c < op_pos.len() {
                let pos = op_pos[c];
                let inc: u64 = batch
                    .iter()
                    .enumerate()
                    .filter(|(k, _)| record_op[*k] == c)
                    .map(|(_, u)| u.value as u64)
                    .sum();
                (pos, inc, 1u64)
            } else {
                (0usize, 0u64, 0u64) // padding no-op at cell 0
            };
            op_used_pos[c] = pos;
            op_old[c] = cells[pos];
            op_new[c] = cells[pos] + inc;
            op_active[c] = active;
            cells[pos] = op_new[c];
            roots.push(merkle_root(&cells_f(&cells)));
        }
        let final_root = *roots.last().unwrap();

        // Witness.
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_root, init_root)?;
        pw.set_hash_target(self.t.final_root, final_root)?;
        let mut batch_pre = Vec::with_capacity(2 * m);
        for u in batch {
            batch_pre.push(F::from_canonical_u64(u.key));
            batch_pre.push(F::from_canonical_u64(u.value as u64));
        }
        pw.set_hash_target(self.t.batch_commit, PoseidonHash::hash_no_pad(&batch_pre))?;
        for (k, u) in batch.iter().enumerate() {
            pw.set_target(self.t.keys[k], F::from_canonical_u64(u.key))?;
            pw.set_target(self.t.values[k], F::from_canonical_u64(u.value as u64))?;
            for c in 0..t_max {
                let v = if record_op[k] == c { F::ONE } else { F::ZERO };
                pw.set_target(self.t.sel[k][c], v)?;
            }
        }
        // Re-derive intermediate cell snapshots to produce each op's sibling path
        // against the correct (threaded) tree state.
        let mut snap: Vec<u64> = initial.to_vec();
        for c in 0..t_max {
            let pos = op_used_pos[c];
            for j in 0..h {
                let bit = (pos >> j) & 1;
                pw.set_bool_target(self.t.op_pos_bits[c][j], bit == 1)?;
            }
            pw.set_target(self.t.op_old[c], F::from_canonical_u64(op_old[c]))?;
            pw.set_target(self.t.op_new[c], F::from_canonical_u64(op_new[c]))?;
            pw.set_target(self.t.op_active[c], F::from_canonical_u64(op_active[c]))?;
            // sibling path for `pos` in the tree BEFORE this op (== roots[c]).
            let tree = MerkleTree::<F, PoseidonHash>::new(
                snap.iter().map(|&v| vec![F::from_canonical_u64(v)]).collect(),
                0,
            );
            let proof = tree.prove(pos);
            for (j, sib) in proof.siblings.iter().enumerate() {
                pw.set_hash_target(self.t.op_proof[c].siblings[j], *sib)?;
            }
            snap[pos] = op_new[c]; // apply this op for the next path
            if c < self.t.mid_roots.len() {
                pw.set_hash_target(self.t.mid_roots[c], roots[c + 1])?;
            }
        }

        let witness = t_w.elapsed();
        let t_p = Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((Node::leaf(self.data.clone(), proof, init_root, final_root, index), witness, prove))
    }
}

fn cells_f(cells: &[u64]) -> Vec<F> {
    cells.iter().map(|&c| F::from_canonical_u64(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};

    fn native_apply(initial: &[u64], batch: &[CountMinUpdate], w: usize) -> Vec<u64> {
        let mut c = initial.to_vec();
        for u in batch {
            c[pos_of(u.key, w)] += u.value as u64;
        }
        c
    }

    #[test]
    fn cm_merkle_round_trip() -> Result<()> {
        let params = CmMerkleParams { w: 16, batch: 4, t_max: 4 };
        let leaf = build_cm_merkle_leaf(params);
        let initial = vec![0u64; 16];
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let node = leaf.prove(&initial, &batch, 1)?;
        // final_ PI must equal the native Merkle root of the updated cells.
        let expect = merkle_root(&cells_f(&native_apply(&initial, &batch, 16)));
        assert_eq!(node.final_, expect);
        verify_node(&node)
    }

    #[test]
    fn cm_merkle_two_leaf_merge() -> Result<()> {
        let params = CmMerkleParams { w: 16, batch: 4, t_max: 4 };
        let leaf = build_cm_merkle_leaf(params);
        let s0 = vec![0u64; 16];
        let b1: Vec<CountMinUpdate> = [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let n1 = leaf.prove(&s0, &b1, 1)?;
        let s1 = native_apply(&s0, &b1, 16);
        let b2: Vec<CountMinUpdate> = [9u64, 7, 2, 5].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let n2 = leaf.prove(&s1, &b2, 2)?;
        let root = merge(&n1, &n2)?; // sparse-rebind leaves chain like any other
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }

    #[test]
    fn cm_merkle_large_state_small_patch() -> Result<()> {
        // The headline: a 1024-cell state rebound by a 4-record batch touches only
        // ≤4 cells, so the rebind pays O(T·log w), NOT O(w). A flat whole-state
        // commit would hash all 1024 cells every epoch.
        let params = CmMerkleParams { w: 1024, batch: 4, t_max: 4 };
        let leaf = build_cm_merkle_leaf(params);
        let initial = vec![0u64; 1024];
        let batch: Vec<CountMinUpdate> =
            [123u64, 777, 123, 9].iter().map(|&k| CountMinUpdate { key: k, value: 2 }).collect();
        let node = leaf.prove(&initial, &batch, 1)?;
        assert_eq!(node.final_, merkle_root(&cells_f(&native_apply(&initial, &batch, 1024))));
        verify_node(&node)
    }

    #[test]
    fn cm_merkle_rejects_tampered_final_root() {
        // A prover claiming a final root that isn't the honest rebind must fail.
        let params = CmMerkleParams { w: 16, batch: 2, t_max: 2 };
        let leaf = build_cm_merkle_leaf(params);
        let initial = vec![0u64; 16];
        let batch: Vec<CountMinUpdate> = [7u64, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        // Build the honest witness, then corrupt the final-root PI.
        let mut cells = initial.clone();
        let mut op_pos: Vec<usize> = Vec::new();
        let mut record_op = vec![0usize; 2];
        for (k, u) in batch.iter().enumerate() {
            let p = pos_of(u.key, 16);
            let c = op_pos.iter().position(|&q| q == p).unwrap_or_else(|| { op_pos.push(p); op_pos.len() - 1 });
            record_op[k] = c;
        }
        let init_root = merkle_root(&cells_f(&cells));
        let h = params.height();
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.init_root, init_root).unwrap();
        // WRONG final root (just the init root — not the rebind result).
        pw.set_hash_target(leaf.t.final_root, init_root).unwrap();
        let mut batch_pre = Vec::new();
        for u in &batch { batch_pre.push(F::from_canonical_u64(u.key)); batch_pre.push(F::from_canonical_u64(u.value as u64)); }
        pw.set_hash_target(leaf.t.batch_commit, PoseidonHash::hash_no_pad(&batch_pre)).unwrap();
        for (k, u) in batch.iter().enumerate() {
            pw.set_target(leaf.t.keys[k], F::from_canonical_u64(u.key)).unwrap();
            pw.set_target(leaf.t.values[k], F::from_canonical_u64(u.value as u64)).unwrap();
            for c in 0..2 { pw.set_target(leaf.t.sel[k][c], if record_op[k] == c { F::ONE } else { F::ZERO }).unwrap(); }
        }
        let mut snap = initial.clone();
        for c in 0..2 {
            let (pos, inc, active) = if c < op_pos.len() {
                let pos = op_pos[c];
                let inc: u64 = batch.iter().enumerate().filter(|(k, _)| record_op[*k] == c).map(|(_, u)| u.value as u64).sum();
                (pos, inc, 1u64)
            } else { (0usize, 0u64, 0u64) };
            for j in 0..h { pw.set_bool_target(leaf.t.op_pos_bits[c][j], ((pos >> j) & 1) == 1).unwrap(); }
            pw.set_target(leaf.t.op_old[c], F::from_canonical_u64(cells[pos])).unwrap();
            pw.set_target(leaf.t.op_new[c], F::from_canonical_u64(cells[pos] + inc)).unwrap();
            pw.set_target(leaf.t.op_active[c], F::from_canonical_u64(active)).unwrap();
            let tree = MerkleTree::<F, PoseidonHash>::new(snap.iter().map(|&v| vec![F::from_canonical_u64(v)]).collect(), 0);
            let proof = tree.prove(pos);
            for (j, sib) in proof.siblings.iter().enumerate() { pw.set_hash_target(leaf.t.op_proof[c].siblings[j], *sib).unwrap(); }
            cells[pos] += inc;
            snap[pos] = cells[pos];
        }
        assert!(leaf.data.prove(pw).is_err(), "tampered final root must be rejected");
    }
}
