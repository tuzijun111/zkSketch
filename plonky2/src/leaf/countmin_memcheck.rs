//! In-circuit **offline-memory-checking Count-Min leaf (`memcheck`)** (plonky2 /
//! SNARK). Port of `../src/sketch/countmin_memcheck.rs`.
//!
//! Rebinds the sparse patch **without a Merkle path per touched cell and without
//! the dense `d·w` array**. It shares the front half with [`super::countmin_final`]
//! / [`super::countmin_omc`] — per-record PRF hash → counter-sort → group-by
//! running sum — and differs only in Step 5: it commits the state as the **sparse
//! multiset of touched `(address, total)` cells** (a Poseidon hash over the
//! `n_ctr`-padded segment-end entries). Untouched cells "cancel" by *not being
//! named*. Cost is `Θ(batch·d · log(d·w))` — independent of `w` in the dominant
//! term — so it proves a wide `7×16384` update where `one_hot` blows the selector
//! budget.
//!
//! ## Empty-init caveat (faithful to the original)
//! Cancelling untouched cells without opening them is sound only because the
//! initial state is **empty**: every touched cell's old value is `0`, so the new
//! value *is* the running-sum total. Chaining onto a non-trivial prior is what
//! [`super::countmin_omc`] (dense multiset) or `merkle` handle instead — so this
//! leaf returns a standalone proof, not a chain `Node`.
//!
//! ## plonky2 vs plonky3
//! plonky3 routes the counter-sort through a `PermuteAir` with an explicit
//! `sigma`; plonky2's grand-product ([`assert_perm_cols`]) is sigma-free. The
//! sparse-patch entry is `[active, active·addr, active·total]` per row (the
//! BabyBear 4-cell `recompose` packing collapses to 3 plain field elements over
//! Goldilocks); native and in-circuit hash the identical flat stream.

use std::sync::Arc;

use anyhow::{ensure, Result};
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::config::{C, D, F};
use crate::leaf::countmin_final::hash_cell_prf;
use crate::leaf::gadgets::{assert_perm_cols, is_zero, vhash};
use crate::sketch::countmin::{commit_batch, CountMinUpdate};

/// Circuit shape: `d` rows of `w` counters, `batch` records. There is **no
/// selector budget** — cost is independent of `w` in the dominant term.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmMemcheckParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CmMemcheckParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    fn addr_bits(&self) -> usize {
        (self.num_cells().next_power_of_two().trailing_zeros() as usize).max(1)
    }
    pub fn validate(&self) {
        assert!((1..=4).contains(&self.d), "d must be in 1..=4 (PRF digest width)");
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of two >= 2");
        assert!(self.batch >= 1, "batch >= 1");
    }
}

/// Native sparse-patch commitment: Poseidon over the `n_ctr`-long entry stream,
/// each row contributing `[active, active·addr, active·total]` (segment-ends →
/// `[1, addr, total]`, all other rows → `[0,0,0]`). Mirrors the in-circuit hash.
pub fn commit_sparse_patch(entries: &[(bool, u64, u64)]) -> HashOut<F> {
    let flat: Vec<F> = entries
        .iter()
        .flat_map(|&(active, addr, total)| {
            if active {
                [F::ONE, F::from_canonical_u64(addr), F::from_canonical_u64(total)]
            } else {
                [F::ZERO; 3]
            }
        })
        .collect();
    PoseidonHash::hash_no_pad(&flat)
}

struct Tgt {
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    key: Vec<Target>,
    val: Vec<Target>,
    combined_sorted: Vec<Target>,
    val_sorted: Vec<Target>,
    inv_diff: Vec<Target>,
}

/// A built, reusable `memcheck` leaf circuit.
pub struct CountMinMemcheckLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: CmMemcheckParams,
}

/// A self-verified `memcheck` proof carrying the sparse-patch commitment and the
/// touched-cell list (for querying). Not a chain `Node` (empty-init only).
pub struct CountMinMemcheckProof {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub data: Arc<CircuitData<F, C, D>>,
    pub final_commit: HashOut<F>,
    pub batch_commit: HashOut<F>,
    pub params: CmMemcheckParams,
    /// Certified touched cells `(address, total)` in sorted order.
    pub patch: Vec<(usize, u64)>,
}

impl CountMinMemcheckProof {
    /// Count-Min point estimate for `key` against the certified sparse patch
    /// (untouched cells read as 0).
    pub fn query(&self, key: u64) -> u64 {
        let (d, w) = (self.params.d, self.params.w);
        (0..d)
            .map(|i| {
                let addr = i * w + hash_cell_prf(i, key, w);
                self.patch.iter().filter(|(a, _)| *a == addr).map(|(_, t)| *t).sum::<u64>()
            })
            .min()
            .unwrap_or(0)
    }

    /// Verify the proof and confirm its exposed `(final_commit, batch_commit)`.
    pub fn verify(&self) -> Result<()> {
        self.data.verify(self.proof.clone())?;
        let pis = &self.proof.public_inputs;
        ensure!(pis.len() >= 8, "memcheck proof missing public inputs");
        for i in 0..4 {
            ensure!(pis[i] == self.final_commit.elements[i], "final_commit mismatch");
            ensure!(pis[4 + i] == self.batch_commit.elements[i], "batch_commit mismatch");
        }
        Ok(())
    }
}

/// Build the `memcheck` Count-Min circuit for the given shape.
pub fn build_countmin_memcheck_leaf(params: CmMemcheckParams) -> CountMinMemcheckLeaf {
    params.validate();
    let CmMemcheckParams { d, w, batch: m } = params;
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let addr_bits = params.addr_bits();

    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());

    // ---- Public inputs: (final sparse-patch commit, batch commit). Empty init. ----
    let final_commit = vhash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = vhash(&mut b);
    b.register_public_inputs(&batch_commit.elements);

    // ---- Private witness ----
    let key = b.add_virtual_targets(m);
    let val = b.add_virtual_targets(m);
    let combined_sorted = b.add_virtual_targets(n_ctr);
    let val_sorted = b.add_virtual_targets(n_ctr);
    let inv_diff = b.add_virtual_targets(n_ctr);

    let one = b.one();
    let zero = b.zero();
    let pow2: Vec<Target> = (0..w_log2).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let row_w: Vec<Target> = (0..d).map(|i| b.constant(F::from_canonical_u64((i * w) as u64))).collect();

    // ---- Batch commitment over interleaved (key, value) ----
    let mut batch_pre: Vec<Target> = Vec::with_capacity(2 * m);
    for k in 0..m {
        batch_pre.push(key[k]);
        batch_pre.push(val[k]);
    }
    let hb = b.hash_n_to_hash_no_pad::<PoseidonHash>(batch_pre);
    for i in 0..4 {
        b.connect(hb.elements[i], batch_commit.elements[i]);
    }

    // ---- Per-record PRF — payload (combined = i·w + pos, value) ----
    let mut payload_combined: Vec<Target> = Vec::with_capacity(n_ctr);
    let mut payload_value: Vec<Target> = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![key[k]]);
        for i in 0..d {
            let bits = b.split_le(digest.elements[i], 64);
            let mut pos = b.mul(bits[0].target, pow2[0]);
            for jb in 1..w_log2 {
                let term = b.mul(bits[jb].target, pow2[jb]);
                pos = b.add(pos, term);
            }
            payload_combined.push(b.add(row_w[i], pos));
            payload_value.push(val[k]);
        }
    }

    // ---- Counter sort (sigma-free grand-product) ----
    assert_perm_cols(
        &mut b,
        &[&payload_combined, &payload_value],
        &[&combined_sorted, &val_sorted],
    );

    // ---- Adjacency / sortedness / running sum / segment-end flags ----
    let mut eq_tag: Vec<Target> = Vec::with_capacity(n_ctr);
    eq_tag.push(zero);
    for r in 1..n_ctr {
        let diff = b.sub(combined_sorted[r], combined_sorted[r - 1]);
        eq_tag.push(is_zero(&mut b, diff, inv_diff[r]));
        let _ = b.split_le(diff, addr_bits); // sortedness ⇒ canonical (one entry/address)
    }
    let mut acc: Vec<Target> = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        acc.push(b.add(val_sorted[r], carried));
    }
    let mut a_active: Vec<Target> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        a_active.push(if r == n_ctr - 1 { one } else { b.sub(one, eq_tag[r + 1]) });
    }

    // ---- Sparse-patch commitment (the rebind — no dense d·w, no Merkle) ----
    let mut flat: Vec<Target> = Vec::with_capacity(3 * n_ctr);
    for r in 0..n_ctr {
        let active_addr = b.mul(a_active[r], combined_sorted[r]);
        let active_total = b.mul(a_active[r], acc[r]);
        flat.push(a_active[r]);
        flat.push(active_addr);
        flat.push(active_total);
    }
    let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(flat);
    for i in 0..4 {
        b.connect(digest.elements[i], final_commit.elements[i]);
    }

    let data = Arc::new(b.build::<C>());
    CountMinMemcheckLeaf {
        data,
        t: Tgt { final_commit, batch_commit, key, val, combined_sorted, val_sorted, inv_diff },
        params,
    }
}

impl CountMinMemcheckLeaf {
    /// Prove one epoch from the **empty** state via the sparse-patch rebind.
    pub fn prove(&self, batch: &[CountMinUpdate]) -> Result<CountMinMemcheckProof> {
        let ((pw,), final_commit, batch_commit, patch) = self.build_witness(batch, None)?;
        let proof = self.data.prove(pw)?;
        Ok(CountMinMemcheckProof {
            proof,
            data: self.data.clone(),
            final_commit,
            batch_commit,
            params: self.params,
            patch,
        })
    }

    /// Build the partial witness + the native (final, batch) commits + patch.
    /// `override_final` (test-only) publishes a different final commitment to
    /// drive the tamper check.
    fn build_witness(
        &self,
        batch: &[CountMinUpdate],
        override_final: Option<HashOut<F>>,
    ) -> Result<((PartialWitness<F>,), HashOut<F>, HashOut<F>, Vec<(usize, u64)>)> {
        let CmMemcheckParams { d, w, batch: m } = self.params;
        assert_eq!(batch.len(), m, "batch length mismatch");
        let n_ctr = m * d;

        // Per-(record,row) payloads, then sort by combined address.
        let mut u_ctr: Vec<(u64, u64)> = Vec::with_capacity(n_ctr);
        for u in batch {
            for i in 0..d {
                let bucket = hash_cell_prf(i, u.key, w);
                u_ctr.push(((i * w + bucket) as u64, u.value));
            }
        }
        u_ctr.sort_by_key(|&(c, _)| c);
        let combined_sorted: Vec<u64> = u_ctr.iter().map(|&(c, _)| c).collect();
        let val_sorted: Vec<u64> = u_ctr.iter().map(|&(_, v)| v).collect();

        // Group-by running sum + segment-end flags.
        let mut eq_tag = vec![false; n_ctr];
        for r in 1..n_ctr {
            eq_tag[r] = combined_sorted[r] == combined_sorted[r - 1];
        }
        let mut acc = vec![0u64; n_ctr];
        if n_ctr > 0 {
            acc[0] = val_sorted[0];
            for r in 1..n_ctr {
                acc[r] = if eq_tag[r] { acc[r - 1] + val_sorted[r] } else { val_sorted[r] };
            }
        }
        let a_active: Vec<bool> =
            (0..n_ctr).map(|r| if r == n_ctr - 1 { true } else { !eq_tag[r + 1] }).collect();

        let entries: Vec<(bool, u64, u64)> =
            (0..n_ctr).map(|r| (a_active[r], combined_sorted[r], acc[r])).collect();
        let final_commit = commit_sparse_patch(&entries);
        let batch_commit = commit_batch(batch);
        let patch: Vec<(usize, u64)> = entries
            .iter()
            .filter(|(active, _, _)| *active)
            .map(|&(_, addr, total)| (addr as usize, total))
            .collect();

        let published_final = override_final.unwrap_or(final_commit);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.final_commit, published_final)?;
        pw.set_hash_target(self.t.batch_commit, batch_commit)?;
        for (k, u) in batch.iter().enumerate() {
            pw.set_target(self.t.key[k], F::from_canonical_u64(u.key))?;
            pw.set_target(self.t.val[k], F::from_canonical_u64(u.value))?;
        }
        for r in 0..n_ctr {
            pw.set_target(self.t.combined_sorted[r], F::from_canonical_u64(combined_sorted[r]))?;
            pw.set_target(self.t.val_sorted[r], F::from_canonical_u64(val_sorted[r]))?;
            let inv = if r == 0 || combined_sorted[r] == combined_sorted[r - 1] {
                F::ZERO
            } else {
                (F::from_canonical_u64(combined_sorted[r]) - F::from_canonical_u64(combined_sorted[r - 1]))
                    .inverse()
            };
            pw.set_target(self.t.inv_diff[r], inv)?;
        }
        Ok(((pw,), final_commit, batch_commit, patch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memcheck_round_trip() -> Result<()> {
        let params = CmMemcheckParams { d: 2, w: 4, batch: 2 };
        let leaf = build_countmin_memcheck_leaf(params);
        let updates = vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }];
        let r = leaf.prove(&updates)?;
        r.verify()?;
        assert!(r.query(7) >= 3);
        assert!(r.query(11) >= 5);
        assert!(r.query(999_999) <= 5);
        let empty = commit_sparse_patch(&vec![(false, 0, 0); params.d * params.batch]);
        assert_ne!(r.final_commit, empty, "final commit must differ from empty");
        assert!(!r.patch.is_empty());
        Ok(())
    }

    #[test]
    fn memcheck_repeated_keys() -> Result<()> {
        let params = CmMemcheckParams { d: 4, w: 8, batch: 4 };
        let leaf = build_countmin_memcheck_leaf(params);
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let r = leaf.prove(&updates)?;
        r.verify()?;
        assert!(r.query(7) >= 6); // 3 + 2 + 1
        assert!(r.query(11) >= 5);
        // Canonical: at most one patch entry per touched address.
        let mut addrs: Vec<usize> = r.patch.iter().map(|(a, _)| *a).collect();
        addrs.sort_unstable();
        let n = addrs.len();
        addrs.dedup();
        assert_eq!(addrs.len(), n, "each touched address appears exactly once");
        Ok(())
    }

    /// Tamper: publishing a wrong (empty-state) final commitment while the
    /// circuit hashes the real sparse patch must make proving fail.
    #[test]
    fn tamper_rejected() {
        let params = CmMemcheckParams { d: 2, w: 4, batch: 2 };
        let leaf = build_countmin_memcheck_leaf(params);
        let updates = vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }];
        let empty = commit_sparse_patch(&vec![(false, 0, 0); params.d * params.batch]);
        let (witness, _real_final, _batch, _patch) =
            leaf.build_witness(&updates, Some(empty)).unwrap();
        assert!(leaf.data.prove(witness.0).is_err(), "wrong final commit must be rejected");
    }
}
