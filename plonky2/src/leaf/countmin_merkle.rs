//! **Count-Min sparse-patch rebind via Merkle vector commitments** (plonky2),
//! realizing zk1.tex §5.2 Step 7 — the Pattern-A rebind whose cost scales with
//! the number of *touched* cells, not the whole array `w`.
//!
//! The other CM leaves commit the state with a **flat** Poseidon sponge over all
//! `d·w` cells, so a rebind costs `Θ(d·w)`. Here each of the `d` rows is a
//! **Merkle tree** over its `w` cells, and the rebind opens only the touched
//! cells via a per-row **Merkle update chain**: thread the row's root
//! `r_0 = Com(row_{t-1}) → … → r_T = Com(row_t)` through `T` single-leaf
//! updates, each verifying the old value against `r_{c-1}` and the new value
//! against `r_c` with the **same** sibling path. Untouched cells never appear
//! (they carry through the shared siblings), so a rebind is `Θ(T·log w)` per row
//! — `Θ(distinct·d·log w)` overall, **independent of `w`**. Threading is what
//! makes repeated/overlapping touches sound: a second touch of a cell sees the
//! first update already folded into the current root.
//!
//! ## d rows, d independent trees
//! A Count-Min sketch has `d` rows of `w` counters with independent row hashes
//! `h_i(key) = Poseidon(key)[i] mod w` (the same family the flat
//! [`super::countmin_final`] leaf uses, so `d ≤ 4` — a `PoseidonHash` digest is
//! four elements). Each row is its own perfect binary Merkle tree of `w` leaves;
//! the per-row roots are combined into a single state commitment
//! `Com(S) = Poseidon(r_0 ‖ … ‖ r_{d-1})` (and `Com(S) = r_0` when `d = 1`, so
//! the single-row case is unchanged). The flat-commit leaves remain the baseline.
//!
//! ## Soundness sketch
//! - **Batch opened:** `Com(B_t)` binds the witnessed `(key, value)` records.
//! - **Routing (S2):** each record's per-row cell `pos_i = digest[i] mod w` is
//!   derived in-circuit from `Poseidon(key)` (canonical low bits — see
//!   [`canonical_bits_64`]); a one-hot selector maps each `(record, row)` to an
//!   *active* patch op at that cell.
//! - **Aggregate (S3):** `new_c = old_c + Σ_{records→c} value`.
//! - **Rebind (S5):** the per-row Merkle update chain ties `old_c`/`new_c` to
//!   the row's boundary roots; untouched cells are unchanged because only the
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
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::leaf::countmin_final::hash_cell_prf;
use crate::recursion::Node;
use crate::sketch::countmin::CountMinUpdate;

/// Shape of a sparse-rebind Count-Min leaf: `d` rows of `w` counters, `batch`
/// records per epoch, capacity `t_max` for distinct touched cells **per row**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmMerkleParams {
    /// Number of rows (independent Merkle trees). `d ≥ 1` — the PRF hash family
    /// draws `ceil(d/4)` digests per key, so depth is unbounded.
    pub d: usize,
    /// Counters per row. A power of two `≥ 2` (each row tree is perfect).
    pub w: usize,
    /// Records per epoch.
    pub batch: usize,
    /// Compile-time bound on distinct touched cells **per row** (`1 ≤ t_max ≤ w`).
    pub t_max: usize,
}

impl CmMerkleParams {
    pub fn validate(&self) {
        // `d` unbounded: the shared `hash_cell_prf` draws `ceil(d/4)` Poseidon
        // digests per key (4 row positions each), so any depth is supported.
        assert!(self.d >= 1, "d must be >= 1");
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of 2 >= 2");
        assert!(self.batch >= 1, "batch must be positive");
        assert!(self.t_max >= 1 && self.t_max <= self.w, "t_max in [1, w]");
    }
    pub fn height(&self) -> usize {
        self.w.trailing_zeros() as usize
    }
}

/// Merkle root over a row of `w` counter cells (each a single-element leaf).
pub fn merkle_root(cells: &[F]) -> HashOut<F> {
    let leaves: Vec<Vec<F>> = cells.iter().map(|&c| vec![c]).collect();
    MerkleTree::<F, PoseidonHash>::new(leaves, 0).cap.0[0]
}

/// Combine `d` per-row roots into one state commitment: the single root when
/// `d = 1` (unchanged single-row behaviour), else `Poseidon(r_0 ‖ … ‖ r_{d-1})`.
pub fn combined_commit(roots: &[HashOut<F>]) -> HashOut<F> {
    if roots.len() == 1 {
        return roots[0];
    }
    let elems: Vec<F> = roots.iter().flat_map(|r| r.elements).collect();
    PoseidonHash::hash_no_pad(&elems)
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

/// Combine `d` root targets into one commitment target (mirrors [`combined_commit`]).
fn combine_commit_target(b: &mut CircuitBuilder<F, D>, roots: &[HashOutTarget]) -> HashOutTarget {
    if roots.len() == 1 {
        return roots[0];
    }
    let mut elems = Vec::with_capacity(roots.len() * 4);
    for r in roots {
        elems.extend_from_slice(&r.elements);
    }
    b.hash_n_to_hash_no_pad::<PoseidonHash>(elems)
}

struct Tgt {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    keys: Vec<Target>,
    values: Vec<Target>,
    // Per-row boundary roots (combined into the commitments).
    init_root: Vec<HashOutTarget>,  // [d]
    final_root: Vec<HashOutTarget>, // [d]
    // Per-row op data.
    sel: Vec<Vec<Vec<Target>>>,          // [d][batch][t_max] one-hot record→op
    op_pos_bits: Vec<Vec<Vec<BoolTarget>>>, // [d][t_max][height]
    op_old: Vec<Vec<Target>>,            // [d][t_max]
    op_new: Vec<Vec<Target>>,
    op_active: Vec<Vec<Target>>,
    op_proof: Vec<Vec<MerkleProofTarget>>, // [d][t_max] sibling paths
    mid_roots: Vec<Vec<HashOutTarget>>,    // [d][t_max-1]
}

pub struct CmMerkleLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: CmMerkleParams,
}

pub fn build_cm_merkle_leaf(params: CmMerkleParams) -> CmMerkleLeaf {
    params.validate();
    let CmMerkleParams { d, w: _w, batch, t_max } = params;
    let h = params.height();
    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());
    let one = b.one();
    let zero = b.zero();

    // ── Public inputs: Com(S_{t-1}), Com(S_t), Com(B_t) ──────────────────────
    let init_commit = b.add_virtual_hash();
    b.register_public_inputs(&init_commit.elements);
    let final_commit = b.add_virtual_hash();
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = b.add_virtual_hash();
    b.register_public_inputs(&batch_commit.elements);

    // ── Private witness ──────────────────────────────────────────────────────
    let keys = b.add_virtual_targets(batch);
    let values = b.add_virtual_targets(batch);
    let init_root: Vec<HashOutTarget> = (0..d).map(|_| b.add_virtual_hash()).collect();
    let final_root: Vec<HashOutTarget> = (0..d).map(|_| b.add_virtual_hash()).collect();
    let sel: Vec<Vec<Vec<Target>>> = (0..d)
        .map(|_| (0..batch).map(|_| b.add_virtual_targets(t_max)).collect())
        .collect();
    let op_pos_bits: Vec<Vec<Vec<BoolTarget>>> = (0..d)
        .map(|_| {
            (0..t_max)
                .map(|_| (0..h).map(|_| b.add_virtual_bool_target_safe()).collect())
                .collect()
        })
        .collect();
    let op_old: Vec<Vec<Target>> = (0..d).map(|_| b.add_virtual_targets(t_max)).collect();
    let op_new: Vec<Vec<Target>> = (0..d).map(|_| b.add_virtual_targets(t_max)).collect();
    let op_active: Vec<Vec<Target>> = (0..d).map(|_| b.add_virtual_targets(t_max)).collect();
    let op_proof: Vec<Vec<MerkleProofTarget>> = (0..d)
        .map(|_| {
            (0..t_max)
                .map(|_| MerkleProofTarget {
                    siblings: (0..h).map(|_| b.add_virtual_hash()).collect(),
                })
                .collect()
        })
        .collect();
    let mid_roots: Vec<Vec<HashOutTarget>> = (0..d)
        .map(|_| (0..t_max.saturating_sub(1)).map(|_| b.add_virtual_hash()).collect())
        .collect();

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

    // Per-(row, op) position value from its bits; op_active boolean.
    let pow2: Vec<Target> = (0..h).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let op_pos: Vec<Vec<Target>> = (0..d)
        .map(|i| {
            (0..t_max)
                .map(|c| {
                    let mut p = zero;
                    for j in 0..h {
                        p = b.mul_add(op_pos_bits[i][c][j].target, pow2[j], p);
                    }
                    p
                })
                .collect()
        })
        .collect();
    for i in 0..d {
        for c in 0..t_max {
            let am1 = b.sub(op_active[i][c], one);
            let chk = b.mul(op_active[i][c], am1);
            b.connect(chk, zero);
        }
    }

    // ── S2: per record, derive per-row pos_i = digest[i] mod w; route one-hot ─
    for k in 0..batch {
        // One digest per block of 4 rows (block 0 hashes `[key]`, later blocks
        // `[key, block]`), matching `hash_cell_prf` exactly.
        let digests: Vec<_> = (0..d.div_ceil(4))
            .map(|blk| {
                if blk == 0 {
                    b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![keys[k]])
                } else {
                    let blk_c = b.constant(F::from_canonical_u64(blk as u64));
                    b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![keys[k], blk_c])
                }
            })
            .collect();
        for i in 0..d {
            let bits = canonical_bits_64(&mut b, digests[i / 4].elements[i % 4]);
            let mut pos_ki = zero;
            for j in 0..h {
                pos_ki = b.mul_add(bits[j].target, pow2[j], pos_ki);
            }
            let mut sum = zero;
            let mut routed_pos = zero;
            let mut routed_active = zero;
            for c in 0..t_max {
                let s = sel[i][k][c];
                let sm1 = b.sub(s, one);
                let chk = b.mul(s, sm1);
                b.connect(chk, zero); // boolean
                sum = b.add(sum, s);
                routed_pos = b.mul_add(s, op_pos[i][c], routed_pos);
                routed_active = b.mul_add(s, op_active[i][c], routed_active);
            }
            b.connect(sum, one); // exactly one op
            b.connect(routed_pos, pos_ki); // selected op sits at the derived cell
            b.connect(routed_active, one); // selected op is active
        }
    }

    // ── S3: per-op increment = Σ routed values; new = old + increment ─────────
    for i in 0..d {
        for c in 0..t_max {
            let mut inc = zero;
            for k in 0..batch {
                inc = b.mul_add(sel[i][k][c], values[k], inc);
            }
            let expect_new = b.add(op_old[i][c], inc);
            b.connect(op_new[i][c], expect_new);
        }
    }

    // ── S5: per-row Merkle update chain r_0=init → r_T=final ──────────────────
    for i in 0..d {
        for c in 0..t_max {
            let r_in = if c == 0 { init_root[i] } else { mid_roots[i][c - 1] };
            let r_out = if c == t_max - 1 { final_root[i] } else { mid_roots[i][c] };
            // old value opens at pos_c in r_in; new value opens at pos_c in r_out
            // (same siblings ⇒ only the touched leaf moves).
            b.verify_merkle_proof::<PoseidonHash>(vec![op_old[i][c]], &op_pos_bits[i][c], r_in, &op_proof[i][c]);
            b.verify_merkle_proof::<PoseidonHash>(vec![op_new[i][c]], &op_pos_bits[i][c], r_out, &op_proof[i][c]);
        }
    }

    // ── Bind the combined commitments (Com(S) = Poseidon over the d row roots,
    //    or the single root when d = 1) ──────────────────────────────────────
    let ic = combine_commit_target(&mut b, &init_root);
    let fc = combine_commit_target(&mut b, &final_root);
    for i in 0..4 {
        b.connect(ic.elements[i], init_commit.elements[i]);
        b.connect(fc.elements[i], final_commit.elements[i]);
    }

    let data = Arc::new(crate::config::build_circuit(b));
    CmMerkleLeaf {
        data,
        t: Tgt {
            init_commit, final_commit, batch_commit, keys, values, init_root, final_root,
            sel, op_pos_bits, op_old, op_new, op_active, op_proof, mid_roots,
        },
        params,
    }
}

impl CmMerkleLeaf {
    pub fn prove(&self, initial: &[Vec<u64>], batch: &[CountMinUpdate], index: u64) -> Result<Node> {
        self.prove_timed(initial, batch, index).map(|(n, _, _)| n)
    }

    /// Prove one sparse-rebind epoch. `initial` is `d` rows of `w` counter cells.
    pub fn prove_timed(
        &self,
        initial: &[Vec<u64>],
        batch: &[CountMinUpdate],
        index: u64,
    ) -> Result<(Node, Duration, Duration)> {
        let CmMerkleParams { d, w, batch: m, t_max } = self.params;
        assert_eq!(initial.len(), d, "initial rows != d");
        assert!(initial.iter().all(|r| r.len() == w), "each row must have w cells");
        assert_eq!(batch.len(), m, "batch length != m");
        let h = self.params.height();
        let t_w = Instant::now();

        let mut pw = PartialWitness::<F>::new();

        // Batch commitment.
        let mut batch_pre = Vec::with_capacity(2 * m);
        for u in batch {
            batch_pre.push(F::from_canonical_u64(u.key));
            batch_pre.push(F::from_canonical_u64(u.value as u64));
        }
        pw.set_hash_target(self.t.batch_commit, PoseidonHash::hash_no_pad(&batch_pre))?;
        for (k, u) in batch.iter().enumerate() {
            pw.set_target(self.t.keys[k], F::from_canonical_u64(u.key))?;
            pw.set_target(self.t.values[k], F::from_canonical_u64(u.value as u64))?;
        }

        let mut init_roots = Vec::with_capacity(d);
        let mut final_roots = Vec::with_capacity(d);
        for i in 0..d {
            let mut cells: Vec<u64> = initial[i].clone();
            // Route each record to a distinct touched cell in this row.
            let mut op_pos: Vec<usize> = Vec::new();
            let mut record_op = vec![0usize; m];
            for (k, u) in batch.iter().enumerate() {
                let p = hash_cell_prf(i, u.key, w);
                let c = op_pos.iter().position(|&q| q == p).unwrap_or_else(|| {
                    op_pos.push(p);
                    op_pos.len() - 1
                });
                record_op[k] = c;
            }
            assert!(
                op_pos.len() <= t_max,
                "row {i}: touched cells {} exceed t_max {}",
                op_pos.len(),
                t_max
            );

            let init_root = merkle_root(&cells_f(&cells));
            init_roots.push(init_root);
            let mut roots: Vec<HashOut<F>> = Vec::with_capacity(t_max + 1);
            roots.push(init_root);
            let mut op_used_pos = vec![0usize; t_max];
            let mut snap: Vec<u64> = initial[i].clone();

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
                    (0usize, 0u64, 0u64)
                };
                op_used_pos[c] = pos;
                let old = cells[pos];
                let new = cells[pos] + inc;
                // Witness per-op fields.
                for j in 0..h {
                    pw.set_bool_target(self.t.op_pos_bits[i][c][j], ((pos >> j) & 1) == 1)?;
                }
                pw.set_target(self.t.op_old[i][c], F::from_canonical_u64(old))?;
                pw.set_target(self.t.op_new[i][c], F::from_canonical_u64(new))?;
                pw.set_target(self.t.op_active[i][c], F::from_canonical_u64(active))?;
                // sibling path for `pos` in the tree BEFORE this op (== roots[c]).
                let tree = MerkleTree::<F, PoseidonHash>::new(
                    snap.iter().map(|&v| vec![F::from_canonical_u64(v)]).collect(),
                    0,
                );
                let proof = tree.prove(pos);
                for (j, sib) in proof.siblings.iter().enumerate() {
                    pw.set_hash_target(self.t.op_proof[i][c].siblings[j], *sib)?;
                }
                snap[pos] = new;
                cells[pos] = new;
                roots.push(merkle_root(&cells_f(&cells)));
                if c < self.t.mid_roots[i].len() {
                    pw.set_hash_target(self.t.mid_roots[i][c], roots[c + 1])?;
                }
                // sel for records routed to this op.
                for (k, _) in batch.iter().enumerate() {
                    let v = if record_op[k] == c { F::ONE } else { F::ZERO };
                    pw.set_target(self.t.sel[i][k][c], v)?;
                }
            }
            let final_root = *roots.last().unwrap();
            final_roots.push(final_root);
            pw.set_hash_target(self.t.init_root[i], init_root)?;
            pw.set_hash_target(self.t.final_root[i], final_root)?;
        }

        let init_commit = combined_commit(&init_roots);
        let final_commit = combined_commit(&final_roots);
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;

        let witness = t_w.elapsed();
        let t_p = Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((Node::leaf(self.data.clone(), proof, init_commit, final_commit, index), witness, prove))
    }
}

fn cells_f(cells: &[u64]) -> Vec<F> {
    cells.iter().map(|&c| F::from_canonical_u64(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};

    /// Native d×w update + the per-row final roots (for checking the commitment).
    fn native_rows(initial: &[Vec<u64>], batch: &[CountMinUpdate], w: usize) -> Vec<Vec<u64>> {
        let d = initial.len();
        let mut rows = initial.to_vec();
        for u in batch {
            for i in 0..d {
                rows[i][hash_cell_prf(i, u.key, w)] += u.value as u64;
            }
        }
        rows
    }

    fn expect_final(initial: &[Vec<u64>], batch: &[CountMinUpdate], w: usize) -> HashOut<F> {
        let rows = native_rows(initial, batch, w);
        let roots: Vec<HashOut<F>> = rows.iter().map(|r| merkle_root(&cells_f(r))).collect();
        combined_commit(&roots)
    }

    /// Single-row baseline: `Com(S)` is the row root, machinery unchanged.
    #[test]
    fn cm_merkle_round_trip() -> Result<()> {
        let params = CmMerkleParams { d: 1, w: 16, batch: 4, t_max: 4 };
        let leaf = build_cm_merkle_leaf(params);
        let initial = vec![vec![0u64; 16]];
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let node = leaf.prove(&initial, &batch, 1)?;
        assert_eq!(node.final_, expect_final(&initial, &batch, 16));
        verify_node(&node)
    }

    /// d rows, multi-op: the real Count-Min shape (each key touches one cell per
    /// row; per-row trees update independently, combined into one commitment).
    #[test]
    fn cm_merkle_d_rows_round_trip() -> Result<()> {
        let params = CmMerkleParams { d: 4, w: 16, batch: 4, t_max: 4 };
        let leaf = build_cm_merkle_leaf(params);
        let initial = vec![vec![0u64; 16]; 4];
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let node = leaf.prove(&initial, &batch, 1)?;
        assert_eq!(node.final_, expect_final(&initial, &batch, 16));
        verify_node(&node)
    }

    #[test]
    fn cm_merkle_two_leaf_merge() -> Result<()> {
        let params = CmMerkleParams { d: 4, w: 16, batch: 4, t_max: 4 };
        let leaf = build_cm_merkle_leaf(params);
        let s0 = vec![vec![0u64; 16]; 4];
        let b1: Vec<CountMinUpdate> = [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let n1 = leaf.prove(&s0, &b1, 1)?;
        let s1 = native_rows(&s0, &b1, 16);
        let b2: Vec<CountMinUpdate> = [9u64, 7, 2, 5].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let n2 = leaf.prove(&s1, &b2, 2)?;
        let root = merge(&n1, &n2)?; // sparse-rebind leaves chain like any other
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }

    /// The headline: a large state rebound by a tiny batch touches ≤ t_max cells
    /// per row, so the rebind pays O(t_max·d·log w), NOT O(d·w). A flat
    /// whole-state commit hashes all `d·w` cells every epoch.
    #[test]
    fn cm_merkle_large_state_small_patch() -> Result<()> {
        let params = CmMerkleParams { d: 4, w: 1024, batch: 4, t_max: 4 };
        let leaf = build_cm_merkle_leaf(params);
        let initial = vec![vec![0u64; 1024]; 4];
        let batch: Vec<CountMinUpdate> =
            [123u64, 777, 123, 9].iter().map(|&k| CountMinUpdate { key: k, value: 2 }).collect();
        let node = leaf.prove(&initial, &batch, 1)?;
        assert_eq!(node.final_, expect_final(&initial, &batch, 1024));
        verify_node(&node)
    }

    #[test]
    fn cm_merkle_rejects_tampered_final_root() {
        // A prover claiming a final commitment that isn't the honest rebind must
        // fail. Build the honest witness, then corrupt the final-root PI.
        let params = CmMerkleParams { d: 1, w: 16, batch: 2, t_max: 2 };
        let leaf = build_cm_merkle_leaf(params);
        let initial = vec![vec![0u64; 16]];
        let batch: Vec<CountMinUpdate> = [7u64, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let w = 16;
        let mut cells = initial[0].clone();
        let mut op_pos: Vec<usize> = Vec::new();
        let mut record_op = vec![0usize; 2];
        for (k, u) in batch.iter().enumerate() {
            let p = hash_cell_prf(0, u.key, w);
            let c = op_pos.iter().position(|&q| q == p).unwrap_or_else(|| { op_pos.push(p); op_pos.len() - 1 });
            record_op[k] = c;
        }
        let init_root = merkle_root(&cells_f(&cells));
        let h = params.height();
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.init_root[0], init_root).unwrap();
        pw.set_hash_target(leaf.t.init_commit, init_root).unwrap();
        // WRONG final commitment (just the init root — not the rebind result).
        pw.set_hash_target(leaf.t.final_root[0], init_root).unwrap();
        pw.set_hash_target(leaf.t.final_commit, init_root).unwrap();
        let mut batch_pre = Vec::new();
        for u in &batch { batch_pre.push(F::from_canonical_u64(u.key)); batch_pre.push(F::from_canonical_u64(u.value as u64)); }
        pw.set_hash_target(leaf.t.batch_commit, PoseidonHash::hash_no_pad(&batch_pre)).unwrap();
        for (k, u) in batch.iter().enumerate() {
            pw.set_target(leaf.t.keys[k], F::from_canonical_u64(u.key)).unwrap();
            pw.set_target(leaf.t.values[k], F::from_canonical_u64(u.value as u64)).unwrap();
            for c in 0..2 { pw.set_target(leaf.t.sel[0][k][c], if record_op[k] == c { F::ONE } else { F::ZERO }).unwrap(); }
        }
        let mut snap = initial[0].clone();
        for c in 0..2 {
            let (pos, inc, active) = if c < op_pos.len() {
                let pos = op_pos[c];
                let inc: u64 = batch.iter().enumerate().filter(|(k, _)| record_op[*k] == c).map(|(_, u)| u.value as u64).sum();
                (pos, inc, 1u64)
            } else { (0usize, 0u64, 0u64) };
            for j in 0..h { pw.set_bool_target(leaf.t.op_pos_bits[0][c][j], ((pos >> j) & 1) == 1).unwrap(); }
            pw.set_target(leaf.t.op_old[0][c], F::from_canonical_u64(cells[pos])).unwrap();
            pw.set_target(leaf.t.op_new[0][c], F::from_canonical_u64(cells[pos] + inc)).unwrap();
            pw.set_target(leaf.t.op_active[0][c], F::from_canonical_u64(active)).unwrap();
            let tree = MerkleTree::<F, PoseidonHash>::new(snap.iter().map(|&v| vec![F::from_canonical_u64(v)]).collect(), 0);
            let proof = tree.prove(pos);
            for (j, sib) in proof.siblings.iter().enumerate() { pw.set_hash_target(leaf.t.op_proof[0][c].siblings[j], *sib).unwrap(); }
            cells[pos] += inc;
            snap[pos] = cells[pos];
        }
        assert!(leaf.data.prove(pw).is_err(), "tampered final root must be rejected");
    }
}
