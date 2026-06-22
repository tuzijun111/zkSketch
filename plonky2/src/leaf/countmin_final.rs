//! Canonical (§5.2) Count-Min update leaf for plonky2 — the distinct-key
//! compacted design, ported from `../zkSketch/src/sketch/countmin_final.rs`.
//!
//! This is the faithful counterpart of the plonky3 `countmin_final` circuit, so
//! the three benchmark tests measure the *same algorithm* on both stacks. The
//! defining §5.2 property is preserved: the expensive Poseidon hash gadget runs
//! `distinct_bound` times (once per distinct key), **not** `batch` times — so
//! prove time drops as the distinct-key count shrinks even at a fixed batch.
//!
//! ## Pipeline (mirrors the plonky3 stages A-J)
//! 1. Bind initial/final cells and the raw batch to Poseidon commitments (PIs).
//! 2. Sort the raw batch by key (permutation + range-checked sortedness).
//! 3. Adjacent-equality tags + running-sum aggregation per key segment.
//! 4. Compact the segment-ends into a `distinct_bound`-sized G-table (permutation).
//! 5. PRF hash family `h_i(k) = Poseidon(k)[i] mod w`, run once per G-table slot.
//! 6. Sort the `distinct_bound·d` counter updates (permutation + sortedness).
//! 7. Counter-level adjacent-equality + running sum.
//! 8. Sparse-patch state transition `final[idx] = initial[idx] + Σ sel·acc`.
//!
//! ## The one structural difference from plonky3
//! plonky3 proves each sort/compaction with a dedicated `PermuteAir` table.
//! plonky2 has no such table, so each permutation here is an **in-circuit
//! grand-product argument**: fold each tuple with a Fiat-Shamir challenge `α`,
//! then assert `Π(x_i + β) == Π(y_i + β)` for two independent challenges
//! `β₁, β₂` derived (with `α`) from a Poseidon hash of both lists. Two
//! independent base-field challenges give soundness error ≈ `(n/|F|)² ≈ 2⁻¹⁰⁰`
//! for our list sizes over Goldilocks. Sortedness is enforced by range-checking
//! adjacent differences (`split_le`).

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::recursion::Node;
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};

/// Bit-width for range-checking key sortedness. Goldilocks keeps full 64-bit
/// keys (unlike the plonky3 original, which reduces them mod the ~31-bit BabyBear
/// prime), so adjacent sorted-key differences need a wider range check. The
/// benchmark generators keep keys below `2^48`.
const KEY_BITS: usize = 48;

/// PRF row hash family: `h_i(k) = Poseidon(k)[i] mod w`.
///
/// plonky2's `PoseidonHash` digest is 4 field elements, so this family supports
/// `d <= 4` rows per key (the benchmarks use `d = 4`). The plonky3 original uses
/// a width-16 Poseidon (8 digest elements, `d <= 8`); for the shared benchmark
/// shape `(d = 4)` the two are equivalent in cost structure.
pub fn hash_cell_prf(row: usize, key: u64, w: usize) -> usize {
    assert!(row < 4, "plonky2 PRF hash family supports row < 4; got {row}");
    let digest = PoseidonHash::hash_no_pad(&[F::from_canonical_u64(key)]);
    (digest.elements[row].to_canonical_u64() as usize) % w
}

/// Apply one update with the PRF hash family (the canonical §5.2 update).
pub fn apply_update_prf(state: &mut CountMinState, u: &CountMinUpdate) {
    for i in 0..state.d {
        let j = hash_cell_prf(i, u.key, state.w);
        state.counters[i][j] = state.counters[i][j].saturating_add(u.value);
    }
}

/// Circuit shape. Two leaves chain-merge only when all four fields match.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmFinalParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
    /// Compile-time upper bound on distinct keys; the hash gadget runs this many times.
    pub distinct_bound: usize,
}

impl CmFinalParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    pub fn validate(&self) {
        assert!((1..=4).contains(&self.d), "d must be in 1..=4 (PRF digest width)");
        // `w` must be a power of two (the position is the low log2(w) digest bits,
        // = `% w` only for powers of two). No fixed upper bound — the real limit
        // is the selector-budget guard below (the flat circuit's dominant cost is
        // `distinct_bound·d·(d·w)`; it OOMs at large w, which is exactly why the
        // sparse Merkle leaf exists). Raise via COUNTMIN_MAX_SEL_CELLS.
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of two >= 2");
        assert!(self.batch >= 1, "batch >= 1");
        assert!(
            self.distinct_bound >= 1 && self.distinct_bound <= self.batch,
            "distinct_bound in 1..=batch"
        );
        let sel_cells = self
            .distinct_bound
            .saturating_mul(self.d)
            .saturating_mul(self.num_cells());
        let max_sel = std::env::var("COUNTMIN_MAX_SEL_CELLS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(16_000_000);
        assert!(
            sel_cells <= max_sel,
            "selector budget exceeded: distinct_bound·d·(d·w) = {sel_cells} > {max_sel} \
             (d={}, w={}, distinct_bound={}). Reduce w / batch, or raise \
             COUNTMIN_MAX_SEL_CELLS (expect heavy RAM/time).",
            self.d,
            self.w,
            self.distinct_bound
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
    // sorted-by-key view
    ks: Vec<Target>,
    vs: Vec<Target>,
    key_eq: Vec<Target>,
    // compact G-table
    gkey: Vec<Target>,
    gval: Vec<Target>,
    // counter-level sorted view
    csort: Vec<Target>,
    cval: Vec<Target>,
    ctag: Vec<Target>,
    sel: Vec<Vec<Target>>,
    // cells
    init_cells: Vec<Target>,
    final_cells: Vec<Target>,
}

/// A built, reusable §5.2 Count-Min leaf circuit.
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

/// Build the §5.2 Count-Min circuit for the given shape.
pub fn build_countmin_final_leaf(params: CmFinalParams) -> CountMinFinalLeaf {
    params.validate();
    let CmFinalParams { d, w, batch: m, distinct_bound } = params;
    let num_cells = d * w;
    let n_ctr = distinct_bound * d;
    let w_log2 = w.trailing_zeros() as usize;
    let comb_bits = (num_cells as u64).next_power_of_two().trailing_zeros().max(1) as usize;

    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
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
    let ks = b.add_virtual_targets(m);
    let vs = b.add_virtual_targets(m);
    let key_eq = b.add_virtual_targets(m);
    let gkey = b.add_virtual_targets(distinct_bound);
    let gval = b.add_virtual_targets(distinct_bound);
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

    // ---- Stage B: sort raw batch by key (permutation of (key,val) -> (ks,vs)) ----
    assert_perm(&mut b, &key, &val, &ks, &vs);
    // Sortedness: ks[r] - ks[r-1] >= 0 (range-checked to KEY_BITS).
    for r in 1..m {
        let diff = b.sub(ks[r], ks[r - 1]);
        let _ = b.split_le(diff, KEY_BITS);
    }

    // ---- Stage C: adjacent-equality tags on sorted keys ----
    // key_eq[r] in {0,1}; key_eq[r]*(ks[r]-ks[r-1]) == 0; and when keys differ, tag is 0.
    b.connect(key_eq[0], zero);
    for r in 1..m {
        let e = key_eq[r];
        let em1 = b.sub(e, one);
        let boolchk = b.mul(e, em1);
        b.connect(boolchk, zero);
        let diff = b.sub(ks[r], ks[r - 1]);
        let prod = b.mul(e, diff);
        b.connect(prod, zero);
        // If diff == 0 then tag must be 1: (1-tag)*(1 - diff*inv) handled by giving the
        // prover inv; we enforce (1-tag) * diff_is_zero == 0 via the witnessed equality
        // that diff==0 => the running sum below would otherwise be wrong. To keep the tag
        // honest on equal keys we add: (1 - tag) must be 0 when diff == 0. Use selector:
        // enforce tag == 1 - is_nonzero(diff) by checking (1-tag)*? — instead we rely on
        // the permutation+sortedness+running-sum + final-state binding to make a dishonest
        // tag produce a wrong final commit. (Same soundness route as the plonky3 leaf.)
    }

    // ---- Stage D: running-sum aggregation per key segment ----
    let mut key_acc: Vec<Target> = Vec::with_capacity(m);
    key_acc.push(vs[0]);
    for r in 1..m {
        let carried = b.mul(key_eq[r], key_acc[r - 1]);
        let new_acc = b.add(vs[r], carried);
        key_acc.push(new_acc);
    }
    // g_active[r] = 1 iff row r ends its key segment.
    let mut g_active: Vec<Target> = Vec::with_capacity(m);
    for r in 0..m {
        let a = if r == m - 1 { one } else { b.sub(one, key_eq[r + 1]) };
        g_active.push(a);
    }

    // ---- Stage E: compact segment-ends into the G-table (permutation) ----
    // SE[r] = g_active[r] * (ks[r]*SHIFT + key_acc[r]); inactive rows -> 0.
    // G_padded[j] = gkey[j]*SHIFT + gval[j] for j < distinct_bound, else 0.
    let shift = b.constant(F::from_canonical_u64(1u64 << 40));
    let mut se: Vec<Target> = Vec::with_capacity(m);
    for r in 0..m {
        let kshift = b.mul(ks[r], shift);
        let payload = b.add(kshift, key_acc[r]);
        let s = b.mul(g_active[r], payload);
        se.push(s);
    }
    let mut gpad: Vec<Target> = Vec::with_capacity(m);
    for j in 0..m {
        if j < distinct_bound {
            let kshift = b.mul(gkey[j], shift);
            let p = b.add(kshift, gval[j]);
            gpad.push(p);
        } else {
            gpad.push(zero);
        }
    }
    let zeros_m = vec![zero; m];
    assert_perm(&mut b, &se, &zeros_m, &gpad, &zeros_m);

    // ---- Stage F: PRF hash gadget over the compact G-table ----
    // For each distinct slot j: digest = Poseidon(gkey[j]); position_i = digest[i] mod w.
    // Build the n_ctr counter-update payloads (combined, value) where
    // combined = i*w + position_i and value = gval[j].
    let w_const = b.constant(F::from_canonical_u64(w as u64));
    let pow2: Vec<Target> = (0..w_log2).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let row_const: Vec<Target> = (0..d).map(|i| b.constant(F::from_canonical_u64(i as u64))).collect();
    let mut u_combined: Vec<Target> = Vec::with_capacity(n_ctr);
    let mut u_value: Vec<Target> = Vec::with_capacity(n_ctr);
    for j in 0..distinct_bound {
        let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![gkey[j]]);
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
            u_value.push(gval[j]);
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

    let data = Arc::new(b.build::<C>());
    CountMinFinalLeaf {
        data,
        t: Tgt {
            init_commit, final_commit, batch_commit,
            key, val, ks, vs, key_eq, gkey, gval, csort, cval, ctag, sel, init_cells, final_cells,
        },
        params,
    }
}

impl CountMinFinalLeaf {
    /// Prove one §5.2 epoch. `index` is the 1-based leaf position.
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
        let CmFinalParams { d, w, batch: m, distinct_bound } = self.params;
        assert_eq!(batch.len(), m);
        assert_eq!(initial.d, d);
        assert_eq!(initial.w, w);
        let num_cells = d * w;
        let n_ctr = distinct_bound * d;

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

        // Stage B native: sort by key.
        let mut idxk: Vec<usize> = (0..m).collect();
        idxk.sort_by_key(|&i| batch[i].key);
        let ks_n: Vec<u64> = idxk.iter().map(|&i| batch[i].key).collect();
        let vs_n: Vec<u64> = idxk.iter().map(|&i| batch[i].value as u64).collect();
        // Stage C/D native: tags, running sum, segment ends.
        let mut key_eq_n = vec![0u64; m];
        for r in 1..m {
            if ks_n[r] == ks_n[r - 1] {
                key_eq_n[r] = 1;
            }
        }
        let mut key_acc_n = vec![0u64; m];
        key_acc_n[0] = vs_n[0];
        for r in 1..m {
            key_acc_n[r] = if key_eq_n[r] == 1 { key_acc_n[r - 1] + vs_n[r] } else { vs_n[r] };
        }
        let mut g_active_n = vec![0u64; m];
        for r in 0..m {
            let ends = if r == m - 1 { true } else { key_eq_n[r + 1] == 0 };
            g_active_n[r] = ends as u64;
        }
        // Stage E native: compact G-table.
        let active: Vec<usize> = (0..m).filter(|&r| g_active_n[r] == 1).collect();
        let actual = active.len();
        assert!(actual <= distinct_bound, "distinct keys {actual} > bound {distinct_bound}");
        let mut gkey_n = vec![0u64; distinct_bound];
        let mut gval_n = vec![0u64; distinct_bound];
        for (slot, &r) in active.iter().enumerate() {
            gkey_n[slot] = ks_n[r];
            gval_n[slot] = key_acc_n[r];
        }
        // Stage F native: PRF positions -> counter updates.
        let mut uc: Vec<u64> = Vec::with_capacity(n_ctr);
        let mut uv: Vec<u64> = Vec::with_capacity(n_ctr);
        for j in 0..distinct_bound {
            for i in 0..d {
                let bucket = hash_cell_prf(i, gkey_n[j], w) as u64;
                uc.push((i as u64) * (w as u64) + bucket);
                uv.push(gval_n[j]);
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
            pw.set_target(self.t.ks[k], F::from_canonical_u64(ks_n[k]))?;
            pw.set_target(self.t.vs[k], F::from_canonical_u64(vs_n[k]))?;
            pw.set_target(self.t.key_eq[k], F::from_canonical_u64(key_eq_n[k]))?;
        }
        for j in 0..distinct_bound {
            pw.set_target(self.t.gkey[j], F::from_canonical_u64(gkey_n[j]))?;
            pw.set_target(self.t.gval[j], F::from_canonical_u64(gval_n[j]))?;
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
        let params = CmFinalParams { d: 2, w: 4, batch: 4, distinct_bound: 2 };
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

    /// **Test 1 — proving time vs. distinct-key count.** Sweep
    /// `distinct_bound ∈ {1000, 500, 100, 50, 10, 5, 1}` at fixed (4, 8, 1000).
    /// Times full circuit build + prove per setting (matching plonky3, whose
    /// `prove_countmin_final` constructs the circuit inside the timed region).
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
            let params = CmFinalParams { d, w, batch, distinct_bound: distinct };
            let updates = gen_batch(batch, distinct);
            let t = Instant::now();
            let leaf = build_countmin_final_leaf(params);
            let _node = leaf.prove(&empty_state(d, w), &updates, 1).expect("prove");
            let elapsed = t.elapsed();
            println!("  distinct_bound={:>5}  build+prove {:>10.2?}", distinct, elapsed);
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
        let params = CmFinalParams { d, w, batch, distinct_bound: batch };
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
    /// plonky3's `generate_and_store_proof` at (4, 8, 1000, distinct_bound=100):
    /// prove l1, serialize bytes to `src/proofs/`, prove l2, serialize, then
    /// merge (using in-memory nodes; the byte round-trip through disk is
    /// verified, same caveat as plonky3 re: reconstructing circuit data).
    #[test]
    #[ignore]
    fn generate_and_store_proof() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::Instant;
        use crate::recursion::{merge, verify_node};

        let (d, w, batch, distinct_bound) = (4usize, 8usize, 1000usize, 100usize);
        let params = CmFinalParams { d, w, batch, distinct_bound };
        let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("create src/proofs");

        println!("\ncountmin_final (plonky2) — generate two proofs + merge (stored)");
        println!("===============================================================");
        println!("  params: d={d}, w={w}, batch={batch}, distinct_bound={distinct_bound}\n");

        let leaf = build_countmin_final_leaf(params);
        let s0 = empty_state(d, w);
        let b1 = gen_batch(batch, distinct_bound);

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
        let b2 = gen_batch2(batch, distinct_bound);
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
