//! Certified (§"Pattern A") Count-Min update leaf for plonky2 — the
//! **hash-every-record** design matching the updated paper (zk1.tex Steps 1–5).
//!
//! The data-dependent key-grouping step was removed from the paper design: the
//! circuit no longer pre-aggregates same-key records before hashing. Instead it
//! hashes **every** record to its `d` counters (`n_ctr = batch·d`), groups BY
//! COUNTER, and accumulates each counter segment by a checked running sum, so
//! duplicate keys and independent collisions alike are reconciled in one pass.
//! The circuit's shape is fixed by the public batch capacity `m`, never by the
//! realised number of distinct keys. The additive relation is unchanged
//! (Count-Min is additive), so the final committed state is identical whether
//! same-key records are pre-grouped or hashed one-by-one.
//!
//! ## Pipeline (paper Steps 1–5; circuit stages A, F–J)
//! 1. (Stage A) Bind initial/final cells and the raw batch to Poseidon
//!    commitments (PIs).
//! 2. (Stage F) Derive the `d` counters each record updates:
//!    `h_i(k) = Poseidon(k)[i] mod w`, run once PER RECORD, value = record value.
//!    This builds the `n_ctr = batch·d` counter-update table directly.
//! 3. (Stage G) Sort the `batch·d` counter updates (permutation + sortedness).
//! 4. (Stage H) Counter-level adjacent-equality + running sum.
//! 5. (Stages I/J) Sparse-patch one-hot cell selector + state transition
//!    `final[idx] = initial[idx] + Σ sel·acc`.
//!
//! ## The one structural difference from plonky3
//! plonky3 proves each sort with a dedicated `PermuteAir` table. plonky2 has no
//! such table, so each permutation here is an **in-circuit grand-product
//! argument**: fold each tuple with a Fiat-Shamir challenge `α`, then assert
//! `Π(x_i + β) == Π(y_i + β)` for two independent challenges `β₁, β₂` derived
//! (with `α`) from a Poseidon hash of both lists. Two independent base-field
//! challenges give soundness error ≈ `(n/|F|)² ≈ 2⁻¹⁰⁰` for our list sizes over
//! Goldilocks. Sortedness is enforced by range-checking adjacent differences
//! (`split_le`).

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::recursion::Node;
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};

/// PRF row hash family: `h_i(k) = digest_i mod w`.
///
/// plonky2's `PoseidonHash` digest is 4 field elements, so a single call covers
/// `d <= 4` rows. Rows 4..8 come from a second, domain-separated call
/// `Poseidon([k, 1])`, extending the family to `d <= 8` — matching the plonky3
/// original's width-16 Poseidon (8 digest elements). The two inputs differ in
/// length and in the appended domain tag, so the eight row hashes are
/// independent. Both the in-circuit derivation (`countmin_omc` Stage F) and this
/// native routing MUST agree, so any change here must mirror there.
pub fn hash_cell_prf(row: usize, key: u64, w: usize) -> usize {
    assert!(row < 8, "plonky2 PRF hash family supports row < 8; got {row}");
    let kf = F::from_canonical_u64(key);
    let e = if row < 4 {
        PoseidonHash::hash_no_pad(&[kf]).elements[row]
    } else {
        PoseidonHash::hash_no_pad(&[kf, F::from_canonical_u64(1)]).elements[row - 4]
    };
    (e.to_canonical_u64() as usize) % w
}

/// Apply one update with the PRF hash family (the certified Count-Min update).
pub fn apply_update_prf(state: &mut CountMinState, u: &CountMinUpdate) {
    for i in 0..state.d {
        let j = hash_cell_prf(i, u.key, state.w);
        state.counters[i][j] = state.counters[i][j].saturating_add(u.value);
    }
}

/// Circuit shape. Two leaves chain-merge only when all three fields match.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmFinalParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CmFinalParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    pub fn validate(&self) {
        assert!((1..=4).contains(&self.d), "d must be in 1..=4 (PRF digest width)");
        // `w` must be a power of two (the position is the low log2(w) digest bits,
        // = `% w` only for powers of two). No fixed upper bound — the real limit
        // is the selector-budget guard below. The flat circuit's dominant cost is
        // `batch·d·(d·w)`: the hash-per-record table has `n_ctr = batch·d` rows,
        // each carrying a `d·w`-wide one-hot selector. It OOMs at large w, which is
        // exactly why the sparse Merkle leaf exists. Raise via COUNTMIN_MAX_SEL_CELLS.
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of two >= 2");
        assert!(self.batch >= 1, "batch >= 1");
        let sel_cells = self
            .batch
            .saturating_mul(self.d)
            .saturating_mul(self.num_cells());
        let max_sel = std::env::var("COUNTMIN_MAX_SEL_CELLS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(16_000_000);
        assert!(
            sel_cells <= max_sel,
            "selector budget exceeded: batch·d·(d·w) = {sel_cells} > {max_sel} \
             (d={}, w={}, batch={}). Reduce w / batch, or raise \
             COUNTMIN_MAX_SEL_CELLS (expect heavy RAM/time).",
            self.d,
            self.w,
            self.batch
        );
    }
}

struct Tgt {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    // raw batch
    key: Vec<Target>,
    val: Vec<Target>,
    // counter-level sorted view
    csort: Vec<Target>,
    cval: Vec<Target>,
    ctag: Vec<Target>,
    sel: Vec<Vec<Target>>,
    // cells
    init_cells: Vec<Target>,
    final_cells: Vec<Target>,
}

/// A built, reusable certified Count-Min leaf circuit.
pub struct CountMinFinalLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: CmFinalParams,
}

fn vhash(b: &mut CircuitBuilder<F, D>) -> HashOutTarget {
    HashOutTarget { elements: core::array::from_fn(|_| b.add_virtual_target()) }
}

/// Grand-product permutation argument: assert the multiset of folded pairs
/// `{a_key[i] + α·a_val[i]}` equals `{b_key[i] + α·b_val[i]}`, using two
/// independent Fiat-Shamir challenges derived from both lists.
fn assert_perm(b: &mut CircuitBuilder<F, D>, ak: &[Target], av: &[Target], bk: &[Target], bv: &[Target]) {
    assert_eq!(ak.len(), bk.len());
    let mut seed: Vec<Target> = Vec::with_capacity(ak.len() * 4);
    seed.extend_from_slice(ak);
    seed.extend_from_slice(av);
    seed.extend_from_slice(bk);
    seed.extend_from_slice(bv);
    let h = b.hash_n_to_hash_no_pad::<PoseidonHash>(seed);
    let alpha = h.elements[0];
    for &beta in &[h.elements[1], h.elements[2]] {
        let mut pa = b.one();
        for i in 0..ak.len() {
            let folded = b.mul_add(alpha, av[i], ak[i]); // ak + alpha*av
            let term = b.add(folded, beta);
            pa = b.mul(pa, term);
        }
        let mut pb = b.one();
        for i in 0..bk.len() {
            let folded = b.mul_add(alpha, bv[i], bk[i]);
            let term = b.add(folded, beta);
            pb = b.mul(pb, term);
        }
        b.connect(pa, pb);
    }
}

/// Build the certified Count-Min circuit for the given shape.
pub fn build_countmin_final_leaf(params: CmFinalParams) -> CountMinFinalLeaf {
    params.validate();
    let CmFinalParams { d, w, batch: m } = params;
    let num_cells = d * w;
    // Hash EVERY record to its `d` counters: one update row per (record, row).
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let comb_bits = (num_cells as u64).next_power_of_two().trailing_zeros().max(1) as usize;

    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());
    let one = b.one();
    let zero = b.zero();

    // ---- Public inputs: (initial, final, batch) commitments ----
    let init_commit = vhash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = vhash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = vhash(&mut b);
    b.register_public_inputs(&batch_commit.elements);

    // ---- Witnesses ----
    let key = b.add_virtual_targets(m);
    let val = b.add_virtual_targets(m);
    let csort = b.add_virtual_targets(n_ctr);
    let cval = b.add_virtual_targets(n_ctr);
    let ctag = b.add_virtual_targets(n_ctr);
    let sel: Vec<Vec<Target>> = (0..n_ctr).map(|_| b.add_virtual_targets(num_cells)).collect();
    let init_cells = b.add_virtual_targets(num_cells);
    let final_cells = b.add_virtual_targets(num_cells);

    // ---- Stage A: commitments ----
    let hi = b.hash_n_to_hash_no_pad::<PoseidonHash>(init_cells.clone());
    for i in 0..4 {
        b.connect(hi.elements[i], init_commit.elements[i]);
    }
    let hf = b.hash_n_to_hash_no_pad::<PoseidonHash>(final_cells.clone());
    for i in 0..4 {
        b.connect(hf.elements[i], final_commit.elements[i]);
    }
    // Batch commitment binds the raw (key,val) records, interleaved.
    let mut batch_pre: Vec<Target> = Vec::with_capacity(2 * m);
    for k in 0..m {
        batch_pre.push(key[k]);
        batch_pre.push(val[k]);
    }
    let hb = b.hash_n_to_hash_no_pad::<PoseidonHash>(batch_pre);
    for i in 0..4 {
        b.connect(hb.elements[i], batch_commit.elements[i]);
    }

    // ---- Stage F: PRF hash gadget, run once PER RECORD (Steps 2) ----
    // For each record k: digest = Poseidon(key[k]); position_i = digest[i] mod w.
    // Emit the n_ctr = m·d counter-update payloads (combined, value) where
    // combined = i*w + position_i and value = val[k]. Duplicate keys are NOT
    // pre-aggregated — they target the same counters and are summed in the
    // counter grouping below (Step 4), alongside every other collision.
    let w_const = b.constant(F::from_canonical_u64(w as u64));
    let pow2: Vec<Target> = (0..w_log2).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let row_const: Vec<Target> = (0..d).map(|i| b.constant(F::from_canonical_u64(i as u64))).collect();
    let mut u_combined: Vec<Target> = Vec::with_capacity(n_ctr);
    let mut u_value: Vec<Target> = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![key[k]]);
        for i in 0..d {
            // position_i = low w_log2 bits of digest[i].
            let bits = b.split_le(digest.elements[i], 64);
            let mut pos = b.mul(bits[0].target, pow2[0]);
            for jb in 1..w_log2 {
                let term = b.mul(bits[jb].target, pow2[jb]);
                pos = b.add(pos, term);
            }
            let row_w = b.mul(row_const[i], w_const);
            let combined = b.add(row_w, pos);
            u_combined.push(combined);
            u_value.push(val[k]);
        }
    }

    // ---- Stage G: sort the counter updates by `combined` (permutation + sortedness) ----
    assert_perm(&mut b, &u_combined, &u_value, &csort, &cval);
    for r in 1..n_ctr {
        let diff = b.sub(csort[r], csort[r - 1]);
        let _ = b.split_le(diff, comb_bits + 1);
    }

    // ---- Stage H: counter-level adjacent-equality + running sum ----
    b.connect(ctag[0], zero);
    for r in 1..n_ctr {
        let e = ctag[r];
        let em1 = b.sub(e, one);
        let boolchk = b.mul(e, em1);
        b.connect(boolchk, zero);
        let diff = b.sub(csort[r], csort[r - 1]);
        let prod = b.mul(e, diff);
        b.connect(prod, zero);
    }
    let mut acc: Vec<Target> = Vec::with_capacity(n_ctr);
    acc.push(cval[0]);
    for r in 1..n_ctr {
        let carried = b.mul(ctag[r], acc[r - 1]);
        let new_acc = b.add(cval[r], carried);
        acc.push(new_acc);
    }
    let mut a_active: Vec<Target> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let a = if r == n_ctr - 1 { one } else { b.sub(one, ctag[r + 1]) };
        a_active.push(a);
    }

    // ---- Stage I: sparse-patch selector validity ----
    let cell_idx: Vec<Target> = (0..num_cells).map(|i| b.constant(F::from_canonical_u64(i as u64))).collect();
    for r in 0..n_ctr {
        for idx in 0..num_cells {
            let s = sel[r][idx];
            let sm1 = b.sub(s, one);
            let chk = b.mul(s, sm1);
            b.connect(chk, zero);
        }
        let mut sum = sel[r][0];
        for idx in 1..num_cells {
            sum = b.add(sum, sel[r][idx]);
        }
        b.connect(sum, a_active[r]);
        let mut idx_acc = b.mul(cell_idx[0], sel[r][0]);
        for idx in 1..num_cells {
            let term = b.mul(cell_idx[idx], sel[r][idx]);
            idx_acc = b.add(idx_acc, term);
        }
        let active_combined = b.mul(a_active[r], csort[r]);
        b.connect(idx_acc, active_combined);
    }

    // ---- Stage J: per-cell delta + state transition ----
    for idx in 0..num_cells {
        let mut delta = b.mul(sel[0][idx], acc[0]);
        for r in 1..n_ctr {
            let term = b.mul(sel[r][idx], acc[r]);
            delta = b.add(delta, term);
        }
        let updated = b.add(init_cells[idx], delta);
        b.connect(updated, final_cells[idx]);
    }

    let data = Arc::new(crate::config::build_circuit(b));
    CountMinFinalLeaf {
        data,
        t: Tgt {
            init_commit, final_commit, batch_commit,
            key, val, csort, cval, ctag, sel, init_cells, final_cells,
        },
        params,
    }
}

impl CountMinFinalLeaf {
    /// Prove one epoch. `index` is the 1-based leaf position.
    pub fn prove(&self, initial: &CountMinState, batch: &[CountMinUpdate], index: u64) -> Result<Node> {
        self.prove_timed(initial, batch, index).map(|(n, _, _)| n)
    }

    /// Like [`prove`](Self::prove) but also returns `(witness_gen, prove)`
    /// durations — the EVAL_SPEC §1 phase split.
    pub fn prove_timed(
        &self,
        initial: &CountMinState,
        batch: &[CountMinUpdate],
        index: u64,
    ) -> Result<(Node, std::time::Duration, std::time::Duration)> {
        let t_w = std::time::Instant::now();
        let CmFinalParams { d, w, batch: m } = self.params;
        assert_eq!(batch.len(), m);
        assert_eq!(initial.d, d);
        assert_eq!(initial.w, w);
        let num_cells = d * w;
        let n_ctr = m * d;

        // Native state evolution + commitments.
        let mut final_state = initial.clone();
        for u in batch {
            apply_update_prf(&mut final_state, u);
        }
        let init_commit = PoseidonHash::hash_no_pad(&initial.cells());
        let final_commit = PoseidonHash::hash_no_pad(&final_state.cells());
        let mut batch_pre: Vec<F> = Vec::with_capacity(2 * m);
        for u in batch {
            batch_pre.push(F::from_canonical_u64(u.key));
            batch_pre.push(F::from_canonical_u64(u.value as u64));
        }
        let batch_commit = PoseidonHash::hash_no_pad(&batch_pre);

        // Stage F native: PRF positions -> counter updates, one row per (record, row).
        let mut uc: Vec<u64> = Vec::with_capacity(n_ctr);
        let mut uv: Vec<u64> = Vec::with_capacity(n_ctr);
        for u in batch {
            for i in 0..d {
                let bucket = hash_cell_prf(i, u.key, w) as u64;
                uc.push((i as u64) * (w as u64) + bucket);
                uv.push(u.value as u64);
            }
        }
        // Stage G native: sort counter updates by combined.
        let mut idxc: Vec<usize> = (0..n_ctr).collect();
        idxc.sort_by_key(|&i| uc[i]);
        let csort_n: Vec<u64> = idxc.iter().map(|&i| uc[i]).collect();
        let cval_n: Vec<u64> = idxc.iter().map(|&i| uv[i]).collect();
        let mut ctag_n = vec![0u64; n_ctr];
        for r in 1..n_ctr {
            if csort_n[r] == csort_n[r - 1] {
                ctag_n[r] = 1;
            }
        }
        let mut acc_n = vec![0u64; n_ctr];
        acc_n[0] = cval_n[0];
        for r in 1..n_ctr {
            acc_n[r] = if ctag_n[r] == 1 { acc_n[r - 1] + cval_n[r] } else { cval_n[r] };
        }
        let mut a_active_n = vec![0u64; n_ctr];
        for r in 0..n_ctr {
            let ends = if r == n_ctr - 1 { true } else { ctag_n[r + 1] == 0 };
            a_active_n[r] = ends as u64;
        }

        // ---- Fill witness ----
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;
        pw.set_hash_target(self.t.batch_commit, batch_commit)?;
        for k in 0..m {
            pw.set_target(self.t.key[k], F::from_canonical_u64(batch[k].key))?;
            pw.set_target(self.t.val[k], F::from_canonical_u64(batch[k].value as u64))?;
        }
        for r in 0..n_ctr {
            pw.set_target(self.t.csort[r], F::from_canonical_u64(csort_n[r]))?;
            pw.set_target(self.t.cval[r], F::from_canonical_u64(cval_n[r]))?;
            pw.set_target(self.t.ctag[r], F::from_canonical_u64(ctag_n[r]))?;
            let target_idx = csort_n[r] as usize;
            for idx in 0..num_cells {
                let one_hot = a_active_n[r] == 1 && idx == target_idx;
                pw.set_target(self.t.sel[r][idx], if one_hot { F::ONE } else { F::ZERO })?;
            }
        }
        for (t, v) in self.t.init_cells.iter().zip(initial.cells()) {
            pw.set_target(*t, v)?;
        }
        for (t, v) in self.t.final_cells.iter().zip(final_state.cells()) {
            pw.set_target(*t, v)?;
        }

        let witness = t_w.elapsed();
        let t_p = std::time::Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((Node::leaf(self.data.clone(), proof, init_commit, final_commit, index), witness, prove))
    }
}

/// Build an empty state of the given shape (convenience for benchmarks/tests).
pub fn empty_state(d: usize, w: usize) -> CountMinState {
    CountMinState::new(&CountMinParams { d, w })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::verify_node;

    #[test]
    fn countmin_final_round_trip() -> Result<()> {
        let params = CmFinalParams { d: 2, w: 4, batch: 4 };
        let leaf = build_countmin_final_leaf(params);
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 11, value: 1 },
        ];
        let node = leaf.prove(&empty_state(2, 4), &updates, 1)?;
        let mut expected = empty_state(2, 4);
        for u in &updates {
            apply_update_prf(&mut expected, u);
        }
        assert_eq!(node.final_, PoseidonHash::hash_no_pad(&expected.cells()));
        verify_node(&node)
    }

    /// Tamper: a prover claiming a `final` commitment that is NOT the honest
    /// hash-per-record rebind must be rejected. Build the honest witness, then
    /// corrupt the final-state cells/commitment so the Stage J transition fails.
    #[test]
    fn countmin_final_rejects_tampered_final() {
        let params = CmFinalParams { d: 2, w: 4, batch: 4 };
        let leaf = build_countmin_final_leaf(params);
        let (d, w, m) = (2usize, 4usize, 4usize);
        let num_cells = d * w;
        let n_ctr = m * d;
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 11, value: 1 },
        ];
        let initial = empty_state(d, w);

        // Honest counter-update table.
        let mut uc: Vec<u64> = Vec::with_capacity(n_ctr);
        let mut uv: Vec<u64> = Vec::with_capacity(n_ctr);
        for u in &updates {
            for i in 0..d {
                uc.push((i as u64) * (w as u64) + hash_cell_prf(i, u.key, w) as u64);
                uv.push(u.value as u64);
            }
        }
        let mut idxc: Vec<usize> = (0..n_ctr).collect();
        idxc.sort_by_key(|&i| uc[i]);
        let csort_n: Vec<u64> = idxc.iter().map(|&i| uc[i]).collect();
        let cval_n: Vec<u64> = idxc.iter().map(|&i| uv[i]).collect();
        let mut ctag_n = vec![0u64; n_ctr];
        for r in 1..n_ctr {
            if csort_n[r] == csort_n[r - 1] {
                ctag_n[r] = 1;
            }
        }
        let mut acc_n = vec![0u64; n_ctr];
        acc_n[0] = cval_n[0];
        for r in 1..n_ctr {
            acc_n[r] = if ctag_n[r] == 1 { acc_n[r - 1] + cval_n[r] } else { cval_n[r] };
        }
        let mut a_active_n = vec![0u64; n_ctr];
        for r in 0..n_ctr {
            a_active_n[r] = (if r == n_ctr - 1 { true } else { ctag_n[r + 1] == 0 }) as u64;
        }

        // TAMPERED final state: claim the initial cells unchanged (no patch
        // applied), but keep the honest selectors/running sums — the Stage J
        // `final = init + Σ sel·acc` constraint must reject this.
        let init_commit = PoseidonHash::hash_no_pad(&initial.cells());
        let tampered_final_cells = initial.cells();
        let tampered_final_commit = PoseidonHash::hash_no_pad(&tampered_final_cells);
        let mut batch_pre: Vec<F> = Vec::with_capacity(2 * m);
        for u in &updates {
            batch_pre.push(F::from_canonical_u64(u.key));
            batch_pre.push(F::from_canonical_u64(u.value as u64));
        }
        let batch_commit = PoseidonHash::hash_no_pad(&batch_pre);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.init_commit, init_commit).unwrap();
        pw.set_hash_target(leaf.t.final_commit, tampered_final_commit).unwrap();
        pw.set_hash_target(leaf.t.batch_commit, batch_commit).unwrap();
        for k in 0..m {
            pw.set_target(leaf.t.key[k], F::from_canonical_u64(updates[k].key)).unwrap();
            pw.set_target(leaf.t.val[k], F::from_canonical_u64(updates[k].value as u64)).unwrap();
        }
        for r in 0..n_ctr {
            pw.set_target(leaf.t.csort[r], F::from_canonical_u64(csort_n[r])).unwrap();
            pw.set_target(leaf.t.cval[r], F::from_canonical_u64(cval_n[r])).unwrap();
            pw.set_target(leaf.t.ctag[r], F::from_canonical_u64(ctag_n[r])).unwrap();
            let target_idx = csort_n[r] as usize;
            for idx in 0..num_cells {
                let one_hot = a_active_n[r] == 1 && idx == target_idx;
                pw.set_target(leaf.t.sel[r][idx], if one_hot { F::ONE } else { F::ZERO }).unwrap();
            }
        }
        for (t, v) in leaf.t.init_cells.iter().zip(initial.cells()) {
            pw.set_target(*t, v).unwrap();
        }
        for (t, v) in leaf.t.final_cells.iter().zip(tampered_final_cells) {
            pw.set_target(*t, v).unwrap();
        }
        assert!(leaf.data.prove(pw).is_err(), "tampered (un-patched) final state must be rejected");
    }

    // ─── Benchmarks mirroring ../zkSketch/src/sketch/countmin_final.rs ──────
    //
    // These three `#[ignore]` tests are the plonky2 counterparts of the three
    // plonky3 perf benchmarks, at the SAME shape (d, w, batch) = (4, 8, 1000),
    // so prove times are directly comparable. Run:
    //
    //   cargo test --release leaf::countmin_final::tests -- --ignored --nocapture --test-threads=1

    /// Deterministic batch with exactly `distinct` distinct keys (cycling),
    /// keys bounded below 2^48. Mirrors plonky3's `gen_batch`.
    fn gen_batch(batch: usize, distinct: usize) -> Vec<CountMinUpdate> {
        assert!(distinct > 0 && distinct <= batch);
        (0..batch)
            .map(|i| {
                let key_idx = (i % distinct) as u64 + 1;
                CountMinUpdate { key: key_idx.wrapping_mul(0x9E37_79B9), value: 1 + (i as u64 % 7) }
            })
            .collect()
    }

    /// Second, disjoint batch for the merge benchmarks (keys shifted past b1).
    fn gen_batch2(batch: usize, distinct: usize) -> Vec<CountMinUpdate> {
        (0..batch)
            .map(|i| {
                let key_idx = (i % distinct) as u64 + 1 + batch as u64;
                CountMinUpdate { key: key_idx.wrapping_mul(0x9E37_79B9), value: 1 + (i as u64 % 7) }
            })
            .collect()
    }

    /// **Test 1 — proving time vs. distinct-key count.** Sweep the realised
    /// distinct-key count `∈ {1000, 500, 100, 50, 10, 5, 1}` at fixed
    /// (4, 8, 1000). The certified circuit's shape is now fixed by `batch` (it
    /// hashes every record), so prove time is flat in distinct keys — this sweep
    /// documents exactly that (vs. the old key-grouped design where it dropped).
    #[test]
    #[ignore]
    fn proving_time_with_different_distinct_keys() {
        use std::time::Instant;
        let (d, w, batch) = (4usize, 8usize, 1000usize);
        println!("\ncountmin_final (plonky2) — proving time vs. distinct-key count");
        println!("==============================================================");
        println!("  threads: rayon default ({} threads)", rayon::current_num_threads());
        println!("  d={d}, w={w}, batch={batch}\n");

        for &distinct in &[1000usize, 500, 100, 50, 10, 5, 1] {
            let params = CmFinalParams { d, w, batch };
            let updates = gen_batch(batch, distinct);
            let t = Instant::now();
            let leaf = build_countmin_final_leaf(params);
            let _node = leaf.prove(&empty_state(d, w), &updates, 1).expect("prove");
            let elapsed = t.elapsed();
            println!("  distinct_keys={:>5}  build+prove {:>10.2?}", distinct, elapsed);
        }
    }

    /// **Test 2 — proving time to merge two leaves.** Prove two leaves at
    /// (4, 8, 1000) sharing a boundary, then time the §4.2 recursive merge.
    #[test]
    #[ignore]
    fn proving_time_merge_two_leaves() {
        use std::time::Instant;
        use crate::recursion::{merge, verify_node};
        let (d, w, batch) = (4usize, 8usize, 1000usize);
        let params = CmFinalParams { d, w, batch };
        println!("\ncountmin_final (plonky2) — merge proving-time check");
        println!("===================================================");
        println!("  threads: rayon default ({} threads)", rayon::current_num_threads());
        println!("  d={d}, w={w}, batch={batch}\n");

        let leaf = build_countmin_final_leaf(params);
        let s0 = empty_state(d, w);
        let b1 = gen_batch(batch, batch);

        let t1 = Instant::now();
        let l1 = leaf.prove(&s0, &b1, 1).expect("prove l1");
        let l1_time = t1.elapsed();

        let mut s1 = s0.clone();
        for u in &b1 {
            apply_update_prf(&mut s1, u);
        }
        let b2 = gen_batch2(batch, batch);
        let t2 = Instant::now();
        let l2 = leaf.prove(&s1, &b2, 2).expect("prove l2");
        let l2_time = t2.elapsed();

        let tm = Instant::now();
        let root = merge(&l1, &l2).expect("merge");
        let m_time = tm.elapsed();
        verify_node(&root).expect("verify merged root");

        println!("  leaf 1 prove:    {l1_time:>10.2?}");
        println!("  leaf 2 prove:    {l2_time:>10.2?}");
        println!("  §4.2 merge step: {m_time:>10.2?}");
        println!("  ───────────────────────────────");
        println!("  total:           {:>10.2?}", l1_time + l2_time + m_time);
    }

    /// **Test 3 — generate two proofs, persist to disk, merge.** Mirrors
    /// plonky3's `generate_and_store_proof` at (4, 8, 1000): prove l1, serialize
    /// bytes to `src/proofs/`, prove l2, serialize, then merge (using in-memory
    /// nodes; the byte round-trip through disk is verified, same caveat as
    /// plonky3 re: reconstructing circuit data).
    #[test]
    #[ignore]
    fn generate_and_store_proof() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::Instant;
        use crate::recursion::{merge, verify_node};

        let (d, w, batch) = (4usize, 8usize, 1000usize);
        let params = CmFinalParams { d, w, batch };
        let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("create src/proofs");

        println!("\ncountmin_final (plonky2) — generate two proofs + merge (stored)");
        println!("===============================================================");
        println!("  params: d={d}, w={w}, batch={batch}\n");

        let leaf = build_countmin_final_leaf(params);
        let s0 = empty_state(d, w);
        let b1 = gen_batch(batch, 100);

        let t1 = Instant::now();
        let l1 = leaf.prove(&s0, &b1, 1).expect("prove l1");
        let l1_time = t1.elapsed();
        let bytes1 = l1.proof.to_bytes();
        fs::write(out_dir.join("countmin_proof1.bin"), &bytes1).expect("write proof1");
        println!("  leaf 1 prove time:   {l1_time:>10.2?}");
        println!("  proof 1 size:        {:>10} bytes", bytes1.len());

        let mut s1 = s0.clone();
        for u in &b1 {
            apply_update_prf(&mut s1, u);
        }
        let b2 = gen_batch2(batch, 100);
        let t2 = Instant::now();
        let l2 = leaf.prove(&s1, &b2, 2).expect("prove l2");
        let l2_time = t2.elapsed();
        let bytes2 = l2.proof.to_bytes();
        fs::write(out_dir.join("countmin_proof2.bin"), &bytes2).expect("write proof2");
        println!("  leaf 2 prove time:   {l2_time:>10.2?}");
        println!("  proof 2 size:        {:>10} bytes", bytes2.len());

        // Byte round-trip through disk.
        assert_eq!(fs::read(out_dir.join("countmin_proof1.bin")).unwrap(), bytes1);
        assert_eq!(fs::read(out_dir.join("countmin_proof2.bin")).unwrap(), bytes2);

        let tm = Instant::now();
        let root = merge(&l1, &l2).expect("merge");
        let m_time = tm.elapsed();
        verify_node(&root).expect("verify root");

        println!("\n  §4.2 merge time:     {m_time:>10.2?}");
        println!("  ───────────────────────────────────");
        println!("  total wall-clock:    {:>10.2?}", l1_time + l2_time + m_time);
        println!("  proofs persisted to: {}", out_dir.display());
    }
}
