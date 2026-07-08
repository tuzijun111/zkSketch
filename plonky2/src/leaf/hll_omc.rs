//! In-circuit **offline-memory-checking HyperLogLog leaf (`omc`)** (plonky2 / SNARK).
//! Port of `../src/sketch/hll_omc.rs` — the max-update analogue of
//! [`super::countmin_omc`].
//!
//! HLL keeps `m = 2^b` registers; a record routes to `idx = digest[0] mod m` and
//! contributes a rank `ρ = 1 + trailing_zeros(digest[1])`. The per-register update
//! is a **max** (`S_t[idx] = max(S_{t-1}[idx], ρ)`), not the additive patch of
//! Count-Min — the one semantic difference from `countmin_omc`, and the reason the
//! rebind needs a **time coordinate**.
//!
//! ## The check (offline memory checking with a `ts` coordinate)
//!
//! Each multiset element is `(addr, val, ts, tag)`. The rebind is one grand-product
//! multiset equality between a write set and a read set:
//!
//! ```text
//!   WS = {(a, S_{t-1}[a], 0, 1)}  ⊎  active·{(idx, N_z, 1, 1)}   (init writes ⊎ update writes)
//!   RS = {(a, S_t[a], ft_a, 1)}   ⊎  active·{(idx, O_z, 0, 1)}   (final reads ⊎ update reads)
//!   WS == RS   (as multisets)
//! ```
//!
//! The `ts` breaks the max-degenerate pairing (`N_z = O_z`): at a touched register
//! the `ts=0` init write can only cancel the `ts=0` update read, forcing
//! `O_z == S_{t-1}[a]` (the genuinely committed old value); the `ts=1` update write
//! then forces `S_t[a] == N_z`. Untouched registers (`ft_a=0`) pin `S_{t-1}[u] =
//! S_t[u]`. The `tag` column (1 on real rows) keeps a real `(0,0,0,·)` element
//! disjoint from the `(0,0,0,0)` dummies inactive update rows produce. A companion
//! **max gate** (`prove_max`) explains each touched value.
//!
//! ## plonky2 vs plonky3
//! plonky3 routes the rebind through a `PermuteAir` with an explicit `sigma`;
//! plonky2's [`assert_perm_cols`] grand-product is **sigma-free** (proves multiset
//! equality of the column-sets directly), so both the register sort and the
//! `WS==RS` check are a single `assert_perm_cols`.
//!
//! ## Cost `Θ(m + batch)` — dense commit/decompose of both ends + one grand-product
//! over `m + batch` tagged rows + `Θ(batch)` sort/hash. Flat in the batch's
//! register sparsity (unlike the `Θ(t_max·log m)` sparse-Merkle leaf).

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::leaf::gadgets::{assert_perm_cols, bind_commit, is_zero, vhash};
use crate::recursion::Node;
use crate::sketch::hyperloglog::{hash_register, RHO_WINDOW};

/// Register width in bits. `ρ ≤ RHO_WINDOW + 1 = 49 < 2^6`, and registers hold a
/// rank, so 6 bits bound every register/rank/max-difference operand.
pub const REGISTER_WIDTH: usize = 6;

/// Circuit shape: `m = 2^b` registers, `batch` records per epoch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllOmcParams {
    pub b: usize,
    pub batch: usize,
}

impl HllOmcParams {
    pub fn m(&self) -> usize {
        1usize << self.b
    }
    fn addr_bits(&self) -> usize {
        self.b
    }
    pub fn validate(&self) {
        assert!(self.b >= 2, "b must be >= 2");
        assert!(self.batch >= 1, "batch must be >= 1");
    }
}

struct Tgt {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    keys: Vec<Target>,
    init_regs: Vec<Target>,
    final_regs: Vec<Target>,
    idx_sorted: Vec<Target>,
    rho_sorted: Vec<Target>,
    inv_diff: Vec<Target>,
    op_old: Vec<Target>,
    acc: Vec<Target>,
    op_new: Vec<Target>,
    ft: Vec<Target>,
}

/// A built, reusable `omc` HLL leaf circuit.
pub struct HllOmcLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: HllOmcParams,
}

/// Canonical little-endian 64-bit decomposition of a Goldilocks element — forbids
/// the near-wraparound residue so a grinding prover cannot pick a different
/// routing (mirrors `hyperloglog::canonical_bits_64`).
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

/// Range-checked `mx == max(a, bb)`: proves `mx ≥ a`, `mx ≥ bb` (both differences
/// range-checked to `REGISTER_WIDTH`), and `(mx−a)(mx−bb) == 0` (so `mx ∈ {a, bb}`).
fn prove_max(b: &mut CircuitBuilder<F, D>, mx: Target, a: Target, bb: Target) {
    let da = b.sub(mx, a);
    let _ = b.split_le(da, REGISTER_WIDTH);
    let dbb = b.sub(mx, bb);
    let _ = b.split_le(dbb, REGISTER_WIDTH);
    let prod = b.mul(da, dbb);
    let zero = b.zero();
    b.connect(prod, zero);
}

/// Build the `omc` HLL circuit for the shape.
pub fn build_hll_omc_leaf(params: HllOmcParams) -> HllOmcLeaf {
    params.validate();
    let m = params.m();
    let batch = params.batch;
    let addr_bits = params.addr_bits();

    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());

    // ---- Public inputs: (Com(S_{t-1}), Com(S_t), Com(B_t)) ----
    let init_commit = vhash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = vhash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = vhash(&mut b);
    b.register_public_inputs(&batch_commit.elements);

    // ---- Private witness ----
    let keys = b.add_virtual_targets(batch);
    let init_regs = b.add_virtual_targets(m);
    let final_regs = b.add_virtual_targets(m);
    let idx_sorted = b.add_virtual_targets(batch);
    let rho_sorted = b.add_virtual_targets(batch);
    let inv_diff = b.add_virtual_targets(batch);
    let op_old = b.add_virtual_targets(batch);
    let acc = b.add_virtual_targets(batch);
    let op_new = b.add_virtual_targets(batch);
    let ft = b.add_virtual_targets(m);

    let one = b.one();
    let zero = b.zero();
    let pow2b: Vec<Target> =
        (0..params.b).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let cell_idx: Vec<Target> =
        (0..m).map(|a| b.constant(F::from_canonical_u64(a as u64))).collect();

    // ---- Stage A: bind both register arrays + the batch to their commits ----
    bind_commit(&mut b, init_regs.clone(), &init_commit);
    bind_commit(&mut b, final_regs.clone(), &final_commit);
    bind_commit(&mut b, keys.clone(), &batch_commit);

    // ---- Stage F: per record derive (idx, ρ) from the committed key in-circuit ----
    let mut payload_idx: Vec<Target> = Vec::with_capacity(batch);
    let mut payload_rho: Vec<Target> = Vec::with_capacity(batch);
    for k in 0..batch {
        let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![keys[k]]);
        // idx = digest[0] mod 2^b (low b canonical bits).
        let d0_bits = canonical_bits_64(&mut b, digest.elements[0]);
        let mut idx = zero;
        for j in 0..params.b {
            idx = b.mul_add(d0_bits[j].target, pow2b[j], idx);
        }
        // ρ = 1 + trailing_zeros(digest[1]) over RHO_WINDOW bits (running product).
        let d1_bits = canonical_bits_64(&mut b, digest.elements[1]);
        let mut prod = one;
        let mut tz = zero;
        for bit in d1_bits.iter().take(RHO_WINDOW) {
            let omb = b.sub(one, bit.target);
            prod = b.mul(prod, omb);
            tz = b.add(tz, prod);
        }
        payload_idx.push(idx);
        payload_rho.push(b.add(one, tz));
    }

    // ---- Stage G: permute payload into register-sorted order (sigma-free) ----
    assert_perm_cols(&mut b, &[&payload_idx, &payload_rho], &[&idx_sorted, &rho_sorted]);

    // ---- Stage H: sortedness / segment tags / running max / touched new value ----
    // eq_tag[r] = [idx_sorted[r] == idx_sorted[r-1]] (forced via is_zero on the gap).
    let mut eq_tag: Vec<Target> = Vec::with_capacity(batch);
    eq_tag.push(zero); // r = 0 starts a segment
    if batch > 0 {
        // First segment's running max starts at ρ_sorted[0].
        b.connect(acc[0], rho_sorted[0]);
    }
    for r in 1..batch {
        let diff = b.sub(idx_sorted[r], idx_sorted[r - 1]);
        let tag = is_zero(&mut b, diff, inv_diff[r]);
        eq_tag.push(tag);
        // sortedness: gap ∈ [0, 2^addr_bits) (ascending register order).
        let _ = b.split_le(diff, addr_bits);
        // running max: acc[r] = max(eq_tag[r]·acc[r-1], ρ_sorted[r]).
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        prove_max(&mut b, acc[r], carried, rho_sorted[r]);
    }
    // Segment-end flags: last row of each register run.
    let mut a_active: Vec<Target> = Vec::with_capacity(batch);
    for r in 0..batch {
        a_active.push(if r == batch - 1 { one } else { b.sub(one, eq_tag[r + 1]) });
    }
    // Range-check the max-gate operands to REGISTER_WIDTH so the difference-based
    // `≥` checks in prove_max cannot wrap.
    for r in 0..batch {
        let _ = b.split_le(rho_sorted[r], REGISTER_WIDTH);
        let _ = b.split_le(op_old[r], REGISTER_WIDTH);
        let _ = b.split_le(op_new[r], REGISTER_WIDTH);
        // acc[r] is already the output of prove_max for r>=1; bound r=0 too.
        let _ = b.split_le(acc[r], REGISTER_WIDTH);
    }
    // Touched new value: op_new[r] = max(op_old[r], acc[r]).
    for r in 0..batch {
        prove_max(&mut b, op_new[r], op_old[r], acc[r]);
    }
    // Final-read timestamps are boolean (0 = untouched, 1 = written this batch).
    for a in 0..m {
        let fm1 = b.sub(ft[a], one);
        let chk = b.mul(ft[a], fm1);
        b.connect(chk, zero);
    }

    // ---- OMC rebind: WS == RS over 4 columns (addr, val, ts, tag) ----
    let l = m + batch;
    let mut addr_in: Vec<Target> = Vec::with_capacity(l);
    let mut val_in: Vec<Target> = Vec::with_capacity(l);
    let mut ts_in: Vec<Target> = Vec::with_capacity(l);
    let mut tag_in: Vec<Target> = Vec::with_capacity(l);
    let mut addr_out: Vec<Target> = Vec::with_capacity(l);
    let mut val_out: Vec<Target> = Vec::with_capacity(l);
    let mut ts_out: Vec<Target> = Vec::with_capacity(l);
    let mut tag_out: Vec<Target> = Vec::with_capacity(l);
    // Dense registers: init write (a, o[a], 0, 1), final read (a, n[a], ft[a], 1).
    for a in 0..m {
        addr_in.push(cell_idx[a]);
        val_in.push(init_regs[a]);
        ts_in.push(zero);
        tag_in.push(one);
        addr_out.push(cell_idx[a]);
        val_out.push(final_regs[a]);
        ts_out.push(ft[a]);
        tag_out.push(one);
    }
    // Touched rows: update write active·(idx, op_new, 1, 1), update read active·(idx, op_old, 0, 1).
    for r in 0..batch {
        addr_in.push(b.mul(a_active[r], idx_sorted[r]));
        val_in.push(b.mul(a_active[r], op_new[r]));
        ts_in.push(a_active[r]); // = a_active·1
        tag_in.push(a_active[r]);
        addr_out.push(b.mul(a_active[r], idx_sorted[r]));
        val_out.push(b.mul(a_active[r], op_old[r]));
        ts_out.push(zero); // update read ts = 0 always
        tag_out.push(a_active[r]);
    }
    assert_perm_cols(
        &mut b,
        &[&addr_in, &val_in, &ts_in, &tag_in],
        &[&addr_out, &val_out, &ts_out, &tag_out],
    );

    let data = Arc::new(b.build::<C>());
    HllOmcLeaf {
        data,
        t: Tgt {
            init_commit, final_commit, batch_commit, keys, init_regs, final_regs,
            idx_sorted, rho_sorted, inv_diff, op_old, acc, op_new, ft,
        },
        params,
    }
}

/// Native max-fold: `regs[route(k).idx] = max(regs[..], route(k).ρ)`. Feeds the
/// next leaf's `initial` so the boundary chains.
pub fn hll_omc_advance(regs: &mut [u64], keys: &[u64], b: usize) {
    for &k in keys {
        let (idx, rho) = hash_register(b, k);
        regs[idx] = regs[idx].max(rho);
    }
}

/// `Com(S)` for an `m`-register array — Poseidon over the registers (matches the
/// leaf's in-circuit `bind_commit`).
pub fn commit_hll_omc(regs: &[u64]) -> plonky2::hash::hash_types::HashOut<F> {
    let cells: Vec<F> = regs.iter().map(|&r| F::from_canonical_u64(r)).collect();
    PoseidonHash::hash_no_pad(&cells)
}

impl HllOmcLeaf {
    /// Prove one HLL epoch from an arbitrary committed `initial` register array via
    /// the max `omc` rebind. `index` is the 1-based leaf position.
    pub fn prove(&self, initial: &[u64], keys: &[u64], index: u64) -> Result<Node> {
        let HllOmcParams { b, batch } = self.params;
        let m = self.params.m();
        assert_eq!(initial.len(), m, "initial registers != m");
        assert_eq!(keys.len(), batch, "keys length != batch");

        // ─── Native side: route + sort by register + running-max fold ───
        let mut idx_of = vec![0usize; batch];
        let mut rho_of = vec![0u64; batch];
        for (k, &key) in keys.iter().enumerate() {
            let (i, r) = hash_register(b, key);
            idx_of[k] = i;
            rho_of[k] = r;
        }
        let mut order: Vec<usize> = (0..batch).collect();
        order.sort_by_key(|&k| idx_of[k]);
        let idx_sorted: Vec<u64> = order.iter().map(|&k| idx_of[k] as u64).collect();
        let rho_sorted: Vec<u64> = order.iter().map(|&k| rho_of[k]).collect();

        let mut tag = vec![false; batch];
        for r in 1..batch {
            tag[r] = idx_sorted[r] == idx_sorted[r - 1];
        }
        let mut acc = vec![0u64; batch];
        if batch > 0 {
            acc[0] = rho_sorted[0];
            for r in 1..batch {
                acc[r] = if tag[r] { acc[r - 1].max(rho_sorted[r]) } else { rho_sorted[r] };
            }
        }
        let mut a_active = vec![false; batch];
        for r in 0..batch {
            a_active[r] = if r == batch - 1 { true } else { !tag[r + 1] };
        }
        let op_old: Vec<u64> = (0..batch).map(|r| initial[idx_sorted[r] as usize]).collect();
        let op_new: Vec<u64> = (0..batch).map(|r| op_old[r].max(acc[r])).collect();

        let mut final_regs = initial.to_vec();
        for r in 0..batch {
            if a_active[r] {
                let a = idx_sorted[r] as usize;
                final_regs[a] = final_regs[a].max(op_new[r]);
            }
        }
        let mut ft = vec![0u64; m];
        for r in 0..batch {
            if a_active[r] {
                ft[idx_sorted[r] as usize] = 1;
            }
        }

        let init_commit = commit_hll_omc(initial);
        let final_commit = commit_hll_omc(&final_regs);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;
        let keys_f: Vec<F> = keys.iter().map(|&k| F::from_canonical_u64(k)).collect();
        pw.set_hash_target(self.t.batch_commit, PoseidonHash::hash_no_pad(&keys_f))?;
        for (t, v) in self.t.keys.iter().zip(&keys_f) {
            pw.set_target(*t, *v)?;
        }
        for (t, &v) in self.t.init_regs.iter().zip(initial) {
            pw.set_target(*t, F::from_canonical_u64(v))?;
        }
        for (t, &v) in self.t.final_regs.iter().zip(&final_regs) {
            pw.set_target(*t, F::from_canonical_u64(v))?;
        }
        for r in 0..batch {
            pw.set_target(self.t.idx_sorted[r], F::from_canonical_u64(idx_sorted[r]))?;
            pw.set_target(self.t.rho_sorted[r], F::from_canonical_u64(rho_sorted[r]))?;
            pw.set_target(self.t.op_old[r], F::from_canonical_u64(op_old[r]))?;
            pw.set_target(self.t.acc[r], F::from_canonical_u64(acc[r]))?;
            pw.set_target(self.t.op_new[r], F::from_canonical_u64(op_new[r]))?;
            let inv = if r == 0 || idx_sorted[r] == idx_sorted[r - 1] {
                F::ZERO
            } else {
                (F::from_canonical_u64(idx_sorted[r]) - F::from_canonical_u64(idx_sorted[r - 1]))
                    .inverse()
            };
            pw.set_target(self.t.inv_diff[r], inv)?;
        }
        for (t, &v) in self.t.ft.iter().zip(&ft) {
            pw.set_target(*t, F::from_canonical_u64(v))?;
        }

        let proof = self.data.prove(pw)?;
        Ok(Node::leaf(self.data.clone(), proof, init_commit, final_commit, index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};

    fn native_final(b: usize, initial: &[u64], keys: &[u64]) -> Vec<u64> {
        let mut regs = initial.to_vec();
        hll_omc_advance(&mut regs, keys, b);
        regs
    }

    /// Round-trip against a **non-empty** prior register array: the touched old
    /// values reconcile against a real committed `M_old` and the final commit
    /// equals the natively max-folded HLL.
    #[test]
    fn omc_round_trip_nonempty_prior() -> Result<()> {
        let params = HllOmcParams { b: 4, batch: 8 };
        let m = params.m();
        let prior_keys: Vec<u64> = (0..20u64).map(|k| k.wrapping_mul(0x9E37_79B9) ^ 0x55).collect();
        let mut prior = vec![0u64; m];
        hll_omc_advance(&mut prior, &prior_keys, params.b);
        let keys: Vec<u64> = (0..params.batch as u64).map(|i| i.wrapping_mul(0xABCD_1234) ^ 0x7).collect();
        let expect = native_final(params.b, &prior, &keys);

        let leaf = build_hll_omc_leaf(params);
        let node = leaf.prove(&prior, &keys, 1)?;
        assert_eq!(node.initial, commit_hll_omc(&prior));
        assert_eq!(node.final_, commit_hll_omc(&expect), "final commit == natively max-folded HLL");
        assert_ne!(node.initial, node.final_);
        verify_node(&node)
    }

    /// Repeated keys collapsing to the same register: the running max folds
    /// duplicates into one read/write pair.
    #[test]
    fn omc_repeated_registers() -> Result<()> {
        let params = HllOmcParams { b: 3, batch: 6 };
        let m = params.m();
        let initial = vec![0u64; m];
        let keys: Vec<u64> = (0..params.batch as u64).map(|i| i % 3).collect();
        let expect = native_final(params.b, &initial, &keys);
        let leaf = build_hll_omc_leaf(params);
        let node = leaf.prove(&initial, &keys, 1)?;
        assert_eq!(node.final_, commit_hll_omc(&expect));
        verify_node(&node)
    }

    /// Two adjacent omc epochs thread by boundary and recursively merge.
    #[test]
    fn omc_two_leaf_merge() -> Result<()> {
        let params = HllOmcParams { b: 3, batch: 4 };
        let m = params.m();
        let leaf = build_hll_omc_leaf(params);
        let s0 = vec![0u64; m];
        let batch1: Vec<u64> = vec![7, 11, 13, 17];
        let n1 = leaf.prove(&s0, &batch1, 1)?;
        let mut s1 = s0.clone();
        hll_omc_advance(&mut s1, &batch1, params.b);
        let batch2: Vec<u64> = vec![3, 5, 19, 23];
        let n2 = leaf.prove(&s1, &batch2, 2)?;
        let root = merge(&n1, &n2)?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }

    /// Tamper: committing a corrupted final register (one bumped) while the
    /// multiset is built from the honest evolution breaks `WS==RS` — proving fails.
    #[test]
    fn tamper_rejected() {
        let params = HllOmcParams { b: 3, batch: 4 };
        let m = params.m();
        let leaf = build_hll_omc_leaf(params);
        let initial = vec![0u64; m];
        let keys: Vec<u64> = vec![7, 11, 13, 17];

        // Honest witness, then corrupt one committed final register.
        let b = params.b;
        let batch = params.batch;
        let mut idx_of = vec![0usize; batch];
        let mut rho_of = vec![0u64; batch];
        for (k, &key) in keys.iter().enumerate() {
            let (i, r) = hash_register(b, key);
            idx_of[k] = i;
            rho_of[k] = r;
        }
        let mut order: Vec<usize> = (0..batch).collect();
        order.sort_by_key(|&k| idx_of[k]);
        let idx_sorted: Vec<u64> = order.iter().map(|&k| idx_of[k] as u64).collect();
        let rho_sorted: Vec<u64> = order.iter().map(|&k| rho_of[k]).collect();
        let mut tag = vec![false; batch];
        for r in 1..batch {
            tag[r] = idx_sorted[r] == idx_sorted[r - 1];
        }
        let mut acc = vec![0u64; batch];
        acc[0] = rho_sorted[0];
        for r in 1..batch {
            acc[r] = if tag[r] { acc[r - 1].max(rho_sorted[r]) } else { rho_sorted[r] };
        }
        let mut a_active = vec![false; batch];
        for r in 0..batch {
            a_active[r] = if r == batch - 1 { true } else { !tag[r + 1] };
        }
        let op_old: Vec<u64> = (0..batch).map(|r| initial[idx_sorted[r] as usize]).collect();
        let op_new: Vec<u64> = (0..batch).map(|r| op_old[r].max(acc[r])).collect();
        let mut final_regs = initial.clone();
        for r in 0..batch {
            if a_active[r] {
                let a = idx_sorted[r] as usize;
                final_regs[a] = final_regs[a].max(op_new[r]);
            }
        }
        let mut ft = vec![0u64; m];
        for r in 0..batch {
            if a_active[r] {
                ft[idx_sorted[r] as usize] = 1;
            }
        }
        // Corrupt the committed final (untouched cell 0 bumped).
        let mut corrupted = final_regs.clone();
        corrupted[0] = corrupted[0].wrapping_add(1);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.init_commit, commit_hll_omc(&initial)).unwrap();
        pw.set_hash_target(leaf.t.final_commit, commit_hll_omc(&corrupted)).unwrap();
        let keys_f: Vec<F> = keys.iter().map(|&k| F::from_canonical_u64(k)).collect();
        pw.set_hash_target(leaf.t.batch_commit, PoseidonHash::hash_no_pad(&keys_f)).unwrap();
        for (t, v) in leaf.t.keys.iter().zip(&keys_f) {
            pw.set_target(*t, *v).unwrap();
        }
        for (t, &v) in leaf.t.init_regs.iter().zip(&initial) {
            pw.set_target(*t, F::from_canonical_u64(v)).unwrap();
        }
        // Commit binds the corrupted cells → the dense final witness must be corrupted too.
        for (t, &v) in leaf.t.final_regs.iter().zip(&corrupted) {
            pw.set_target(*t, F::from_canonical_u64(v)).unwrap();
        }
        for r in 0..batch {
            pw.set_target(leaf.t.idx_sorted[r], F::from_canonical_u64(idx_sorted[r])).unwrap();
            pw.set_target(leaf.t.rho_sorted[r], F::from_canonical_u64(rho_sorted[r])).unwrap();
            pw.set_target(leaf.t.op_old[r], F::from_canonical_u64(op_old[r])).unwrap();
            pw.set_target(leaf.t.acc[r], F::from_canonical_u64(acc[r])).unwrap();
            pw.set_target(leaf.t.op_new[r], F::from_canonical_u64(op_new[r])).unwrap();
            let inv = if r == 0 || idx_sorted[r] == idx_sorted[r - 1] {
                F::ZERO
            } else {
                (F::from_canonical_u64(idx_sorted[r]) - F::from_canonical_u64(idx_sorted[r - 1])).inverse()
            };
            pw.set_target(leaf.t.inv_diff[r], inv).unwrap();
        }
        for (t, &v) in leaf.t.ft.iter().zip(&ft) {
            pw.set_target(*t, F::from_canonical_u64(v)).unwrap();
        }
        assert!(leaf.data.prove(pw).is_err(), "corrupted final register must break WS==RS");
    }

    /// **Max-suppression** (regression for the ts read-binding). A batch that must
    /// RAISE registers is proven with `op_old = op_new = acc` and an unchanged
    /// committed final; the `ts=0` init write can only cancel the `ts=0` update
    /// read, so no matching exists and proving fails.
    #[test]
    fn suppression_rejected() {
        let params = HllOmcParams { b: 3, batch: 8 };
        let m = params.m();
        let leaf = build_hll_omc_leaf(params);
        let initial = vec![0u64; m]; // empty prior ⇒ every routed record must raise
        let keys: Vec<u64> = vec![7, 11, 13, 17, 3, 5, 19, 23];
        let b = params.b;
        let batch = params.batch;

        let mut idx_of = vec![0usize; batch];
        let mut rho_of = vec![0u64; batch];
        for (k, &key) in keys.iter().enumerate() {
            let (i, r) = hash_register(b, key);
            idx_of[k] = i;
            rho_of[k] = r;
        }
        let mut order: Vec<usize> = (0..batch).collect();
        order.sort_by_key(|&k| idx_of[k]);
        let idx_sorted: Vec<u64> = order.iter().map(|&k| idx_of[k] as u64).collect();
        let rho_sorted: Vec<u64> = order.iter().map(|&k| rho_of[k]).collect();
        let mut tag = vec![false; batch];
        for r in 1..batch {
            tag[r] = idx_sorted[r] == idx_sorted[r - 1];
        }
        let mut acc = vec![0u64; batch];
        acc[0] = rho_sorted[0];
        for r in 1..batch {
            acc[r] = if tag[r] { acc[r - 1].max(rho_sorted[r]) } else { rho_sorted[r] };
        }
        let mut a_active = vec![false; batch];
        for r in 0..batch {
            a_active[r] = if r == batch - 1 { true } else { !tag[r + 1] };
        }
        // SUPPRESS: claim old == new == acc (so prove_max passes) and commit no change.
        let op_old: Vec<u64> = (0..batch).map(|r| acc[r]).collect();
        let op_new: Vec<u64> = op_old.clone();
        let final_regs = initial.clone(); // unchanged
        let ft = vec![0u64; m]; // claim nothing written

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.init_commit, commit_hll_omc(&initial)).unwrap();
        pw.set_hash_target(leaf.t.final_commit, commit_hll_omc(&final_regs)).unwrap();
        let keys_f: Vec<F> = keys.iter().map(|&k| F::from_canonical_u64(k)).collect();
        pw.set_hash_target(leaf.t.batch_commit, PoseidonHash::hash_no_pad(&keys_f)).unwrap();
        for (t, v) in leaf.t.keys.iter().zip(&keys_f) {
            pw.set_target(*t, *v).unwrap();
        }
        for (t, &v) in leaf.t.init_regs.iter().zip(&initial) {
            pw.set_target(*t, F::from_canonical_u64(v)).unwrap();
        }
        for (t, &v) in leaf.t.final_regs.iter().zip(&final_regs) {
            pw.set_target(*t, F::from_canonical_u64(v)).unwrap();
        }
        for r in 0..batch {
            pw.set_target(leaf.t.idx_sorted[r], F::from_canonical_u64(idx_sorted[r])).unwrap();
            pw.set_target(leaf.t.rho_sorted[r], F::from_canonical_u64(rho_sorted[r])).unwrap();
            pw.set_target(leaf.t.op_old[r], F::from_canonical_u64(op_old[r])).unwrap();
            pw.set_target(leaf.t.acc[r], F::from_canonical_u64(acc[r])).unwrap();
            pw.set_target(leaf.t.op_new[r], F::from_canonical_u64(op_new[r])).unwrap();
            let inv = if r == 0 || idx_sorted[r] == idx_sorted[r - 1] {
                F::ZERO
            } else {
                (F::from_canonical_u64(idx_sorted[r]) - F::from_canonical_u64(idx_sorted[r - 1])).inverse()
            };
            pw.set_target(leaf.t.inv_diff[r], inv).unwrap();
        }
        for (t, &v) in leaf.t.ft.iter().zip(&ft) {
            pw.set_target(*t, F::from_canonical_u64(v)).unwrap();
        }
        assert!(leaf.data.prove(pw).is_err(), "max-suppression (unchanged commit) must be rejected");
    }
}
