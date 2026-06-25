//! **Offline-memory-checking count-min leaf** — the §"Pattern A" Step-5
//! alternative that rebinds the sparse patch *without a Merkle path per
//! touched cell* (zk1.tex, "offline memory checking").
//!
//! ## What this is
//!
//! `one_hot` ([`super::countmin_final`]) and `merkle`
//! ([`super::countmin_c_merkle`]) both share the front half of the
//! pipeline — per-record PRF hash → counter-sort permutation →
//! group-by-counter running sum — and differ only in how they *rebind*
//! the state in Step 5:
//!
//! - `one_hot` materialises the **dense** `d·w` array, scatters each
//!   counter total through a one-hot selector matrix
//!   (`n_ctr × d·w` private witnesses), and re-hashes all `d·w` cells.
//!   Cost grows with `w`; large widths blow the selector budget / the
//!   BabyBear `2^27` FRI-domain ceiling.
//! - `merkle` opens each touched cell with a two-sided Merkle path
//!   (`Θ(t_max·d·log w)`), flat in `w` but paying a `log w` Poseidon
//!   path per cell.
//!
//! `memcheck` does neither. It treats the sketch as memory and commits
//! the state as the **sparse multiset of touched `(address, total)`
//! cells**: the group-by running sum already produces exactly one
//! `(address, total)` pair per touched counter at each segment end, so
//! the rebind is just a Poseidon hash over those `n_ctr`-padded entries.
//! Untouched cells never appear — they "cancel" by *not being named*,
//! which is the offline-memory-checking idea in its cheapest form. There
//! is **no dense `d·w` work and no Merkle path**: the cost is
//! `Θ(batch·d · log(d·w))` — the `log(d·w)` from a sortedness
//! range-check that keeps the sparse commitment canonical (one entry per
//! address) — and is **independent of `w`** in the dominant term. This is
//! the variant that proves a `7 × 16384` sketch update where `one_hot`
//! panics.
//!
//! ## Why it starts from the empty state (the honest caveat)
//!
//! Cancelling untouched cells without opening them is sound here because
//! the initial state is **empty**: every touched cell's old value is `0`,
//! so the new value *is* the running-sum total and no membership proof
//! against a prior commitment is needed. Chaining `memcheck` onto a
//! *non-trivial* `Com(S_{t-1})` would require proving the old value of
//! each touched cell was the last-written one — i.e. either materialising
//! the prior state (back to `Θ(d·w)`) or a per-cell membership proof
//! (back to Merkle). The genuinely sub-linear cross-batch version is the
//! Spice-style running write-set product (init once at genesis, carry the
//! accumulator); this prototype demonstrates the single-epoch core that
//! the cross-batch construction is built from. See the module
//! `prove_countmin_memcheck` docs.
//!
//! ## Obliviousness
//!
//! The committed entry list is a fixed length `n_ctr = batch·d` (the
//! public batch capacity), padded with all-zero entries; the number of
//! *real* touched cells is hidden inside the Poseidon digest. The circuit
//! shape depends only on `(d, w, batch)`, never on the realised number of
//! distinct counters — Property-4 obliviousness, same as the other
//! variants.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_permute_trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        permute_air_builders, permute_preprocessor, poseidon2_air_builders_d4,
        poseidon2_preprocessor, recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use p3_symmetric::CryptographicHasher;

use crate::commitment::CountMinCommit;
use crate::commitment::countmin_batch::commit_batch;
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::countmin_final::{apply_update_prf, hash_cell_prf};
use crate::sketch::countmin_v9::CountMinV9;

// ─── Constants ───────────────────────────────────────────────────────────

/// FRI final-poly log size — matches the leaf config used elsewhere.
const LOG_FINAL_POLY_LEN: usize = 6;

/// Bit-shift for the `(combined, value)` payload encoding (per-record
/// value `< 2^20`). Same as `countmin_final`.
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

// ─── Test-only fault injection ─────────────────────────────────────────────

thread_local! {
    /// When set, the prover publishes a *wrong* final-state commitment
    /// (the empty-state digest) while the circuit still hashes the real
    /// sparse patch — the `connect(digest_entries, final_commit_pis)`
    /// gate then fails, so the self-verify rejects. Drives
    /// [`tests::tamper_rejected`]. Always `false` outside tests.
    static TAMPER_FINAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// ─── Public API ──────────────────────────────────────────────────────────

/// Runtime parameters for the `memcheck` leaf. `(d, w, batch)` fix the
/// circuit shape. Unlike `one_hot` there is **no selector budget** — the
/// cost is independent of `w` in the dominant term — so `w` may grow
/// freely.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmMemcheckParams {
    /// Sketch depth. `1 ≤ d ≤ 8` (PRF digest has 8 `Val` elements).
    pub d: usize,
    /// Buckets per row. Power of two `≥ 2`. No upper bound.
    pub w: usize,
    /// Records per epoch. The PRF gadget runs `batch · d` times.
    pub batch: usize,
}

impl CmMemcheckParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    /// Bits needed to hold an address in `[0, d·w)` — the sortedness
    /// range-check width (the `log(d·w)` cost term).
    fn addr_bits(&self) -> usize {
        let n = self.num_cells();
        // ceil(log2(n)), with a floor of 1.
        (usize::BITS - n.saturating_sub(1).leading_zeros()).max(1) as usize
    }
    pub fn validate(&self) {
        assert!(self.d >= 1 && self.d <= 8, "d must be in 1..=8, got {}", self.d);
        assert!(
            self.w.is_power_of_two() && self.w >= 2,
            "w must be a power of two ≥ 2, got {}",
            self.w
        );
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
    }
}

/// A self-verified `memcheck` leaf proof. The commitment is the sparse
/// patch digest (see module docs), **not** the dense `commit_countmin`
/// digest — so it is not directly comparable to `one_hot`/`merkle`
/// commitments. Querying goes through the materialised `patch`.
pub struct CountMinMemcheckProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    /// Sparse-patch commitment to the final state.
    pub final_commit: CountMinCommit,
    /// Commitment to the raw batch (the only public binding of the keys).
    pub batch_commit: CountMinCommit,
    pub params: CmMemcheckParams,
    /// Touched cells `(address = i·w + bucket, total)` in sorted order —
    /// the certified sparse state, for answering queries.
    pub patch: Vec<(usize, u32)>,
}

impl CountMinMemcheckProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }

    /// Count-min point estimate for `key` against the certified sparse
    /// patch: the min over the `d` cells `key` hashes into (untouched
    /// cells read as 0).
    pub fn query(&self, key: u64) -> u32 {
        let d = self.params.d;
        let w = self.params.w;
        let mut min_est = u32::MAX;
        for i in 0..d {
            let addr = i * w + hash_cell_prf(i, key, w);
            // Canonical patch: at most one entry per address. Sum defensively
            // in case a caller built a non-canonical patch by hand.
            let v: u32 = self
                .patch
                .iter()
                .filter(|(a, _)| *a == addr)
                .map(|(_, t)| *t)
                .sum();
            min_est = min_est.min(v);
        }
        min_est
    }
}

/// Native sparse-patch commitment. Hashes the `n_ctr`-long entry list
/// where each segment-end row `r` contributes the 4 `Val`s
/// `[1, address, total, 0]` and every other row contributes `[0,0,0,0]`.
/// This mirrors the in-circuit `add_hash_slice` over the `recompose`d
/// entries exactly (the same flat `Val` stream feeds the same
/// `PaddingFreeSponge`), the way [`commit_countmin`] mirrors the dense
/// `one_hot` hash.
///
/// [`commit_countmin`]: crate::commitment::countmin::commit_countmin
fn commit_sparse_patch(entries: &[(bool, u64, u32)]) -> CountMinCommit {
    let hasher = MyHash::new(make_perm());
    let flat = entries.iter().flat_map(|&(active, addr, total)| {
        if active {
            [Val::ONE, Val::from_u64(addr), Val::from_u32(total), Val::ZERO]
        } else {
            [Val::ZERO; 4]
        }
    });
    CountMinCommit(hasher.hash_iter(flat))
}

fn pack_batch_to_challenge(batch: &[CountMinUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = batch
        .iter()
        .flat_map(|r| {
            let key_lo = (r.key & 0xFFFF_FFFF) as u32;
            let key_hi = (r.key >> 32) as u32;
            [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(r.value),
                Val::ZERO,
            ]
        })
        .collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

// ─── Prover ──────────────────────────────────────────────────────────────

/// Prove one count-min epoch from the **empty** state via offline memory
/// checking (sparse-patch rebind, no Merkle).
///
/// Returns a [`CountMinMemcheckProof`] carrying the sparse-patch
/// commitment and the touched-cell list for querying. The proof
/// self-verifies before return.
///
/// # Why empty-init
///
/// Soundness of "untouched cells cancel by omission" relies on the old
/// value of every touched cell being a public constant (`0`). See the
/// module docs for the cross-batch extension.
///
/// # Panics
/// - `params.validate()` failures.
/// - `batch.len() != params.batch`.
pub fn prove_countmin_memcheck(
    params: CmMemcheckParams,
    batch: Vec<CountMinUpdate>,
) -> CountMinMemcheckProof {
    params.validate();
    assert_eq!(batch.len(), params.batch, "batch.len() != params.batch");

    let CmMemcheckParams { d, w, batch: m } = params;
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let addr_bits = params.addr_bits();

    // ─── Native side: state evolution + witnesses ────────────────────────
    let initial_state: CountMinState = CountMinV9::new(&CountMinParams { d, w });
    let mut final_state = initial_state.clone();
    for u in &batch {
        apply_update_prf(&mut final_state, u);
    }
    let batch_commit = commit_batch(&batch);

    // U_ctr: one (combined, value) row per (record, row) — no key-grouping.
    let mut u_ctr_data: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
    for u in &batch {
        let key_for_hash =
            <Val as p3_field::PrimeField64>::as_canonical_u64(&Val::from_u64(u.key));
        for i in 0..d {
            let bucket = hash_cell_prf(i, key_for_hash, w);
            let combined = (i * w + bucket) as u64;
            u_ctr_data.push((combined, u.value));
        }
    }
    let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr_data.iter().enumerate().collect();
    indexed.sort_by_key(|(_, (combined, _))| *combined);
    let sigma_ctr: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let combined_sorted_native: Vec<u64> = indexed.iter().map(|(_, (c, _))| *c).collect();
    let val_sorted_native: Vec<u32> = indexed.iter().map(|(_, (_, v))| *v).collect();

    // Group-by-counter adjacent-equality + running sum.
    let mut tag_native: Vec<u32> = vec![0; n_ctr];
    for r in 1..n_ctr {
        if combined_sorted_native[r] == combined_sorted_native[r - 1] {
            tag_native[r] = 1;
        }
    }
    let mut acc_native: Vec<u32> = vec![0; n_ctr];
    if n_ctr > 0 {
        acc_native[0] = val_sorted_native[0];
        for r in 1..n_ctr {
            acc_native[r] = if tag_native[r] == 1 {
                acc_native[r - 1].saturating_add(val_sorted_native[r])
            } else {
                val_sorted_native[r]
            };
        }
    }
    let mut a_active_native: Vec<u32> = vec![0; n_ctr];
    for r in 0..n_ctr {
        let ends_segment = if r == n_ctr - 1 { true } else { tag_native[r + 1] == 0 };
        a_active_native[r] = u32::from(ends_segment);
    }

    // Sparse patch (segment ends) → committed entries + queryable list.
    let entries_native: Vec<(bool, u64, u32)> = (0..n_ctr)
        .map(|r| (a_active_native[r] == 1, combined_sorted_native[r], acc_native[r]))
        .collect();
    let final_commit = commit_sparse_patch(&entries_native);
    let patch: Vec<(usize, u32)> = entries_native
        .iter()
        .filter(|(active, _, _)| *active)
        .map(|(_, addr, total)| (*addr as usize, *total))
        .collect();

    // ─── Build the circuit ───────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);

    // Public inputs: (final_commit, batch_commit). The initial state is the
    // public empty state, so it needs no commitment input.
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
    let two_pow_32_const = b.alloc_const(Challenge::from_u64(1u64 << 32), "2^32");
    let row_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "row_i"))
        .collect();
    let pow2_consts: Vec<ExprId> = (0..w_log2.max(addr_bits))
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();

    // Private inputs.
    let batch_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("batch_packed")).collect();
    let mut key_lo: Vec<ExprId> = Vec::with_capacity(m);
    let mut key_hi: Vec<ExprId> = Vec::with_capacity(m);
    let mut value_w: Vec<ExprId> = Vec::with_capacity(m);
    for _ in 0..m {
        key_lo.push(b.alloc_private_input("key_lo"));
        key_hi.push(b.alloc_private_input("key_hi"));
        value_w.push(b.alloc_private_input("value"));
    }
    let combined_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("combined_sorted"))
        .collect();
    let val_sorted: Vec<ExprId> =
        (0..n_ctr).map(|_| b.alloc_private_input("val_sorted")).collect();
    let eq_tag: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("eq_tag")).collect();
    let inv_diff: Vec<ExprId> =
        (0..n_ctr).map(|_| b.alloc_private_input("inv_diff")).collect();

    // ─── Bind the batch to its commitment ────────────────────────────────
    let digest_batch = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_batch[i], batch_commit_pis[i]);
    }
    for k in 0..m {
        let coeffs = b
            .decompose_ext_to_base_coeffs::<Val>(batch_packed[k])
            .expect("decompose batch_packed");
        b.connect(coeffs[0], key_lo[k]);
        b.connect(coeffs[1], key_hi[k]);
        b.connect(coeffs[2], value_w[k]);
        b.connect(coeffs[3], zero);
    }
    let mut key_field: Vec<ExprId> = Vec::with_capacity(m);
    for k in 0..m {
        let hi_shifted = b.mul(key_hi[k], two_pow_32_const);
        key_field.push(b.add(key_lo[k], hi_shifted));
    }

    // ─── PRF hash gadget over every record → payload rows ────────────────
    // (Identical to countmin_final Stage F.)
    let mut h_digest_witnesses: Vec<(ExprId, ExprId)> = Vec::with_capacity(m);
    for _ in 0..m {
        let h0 = b.alloc_private_input("h_digest_0");
        let h1 = b.alloc_private_input("h_digest_1");
        h_digest_witnesses.push((h0, h1));
    }
    let mut payload: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let hashed = b
            .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &[key_field[k]], true)
            .expect("hash key_field[k]");
        let (h0, h1) = h_digest_witnesses[k];
        b.connect(hashed[0], h0);
        b.connect(hashed[1], h1);
        let coeffs_0 = b.decompose_ext_to_base_coeffs::<Val>(h0).expect("decompose h0");
        let coeffs_1 = b.decompose_ext_to_base_coeffs::<Val>(h1).expect("decompose h1");
        let h_vals: [ExprId; 8] = [
            coeffs_0[0], coeffs_0[1], coeffs_0[2], coeffs_0[3],
            coeffs_1[0], coeffs_1[1], coeffs_1[2], coeffs_1[3],
        ];
        for i in 0..d {
            let bits = b
                .decompose_to_bits::<Val>(h_vals[i], Val::bits())
                .expect("decompose h_val");
            let mut pos_sum = b.mul(bits[0], pow2_consts[0]);
            for jb in 1..w_log2 {
                let term = b.mul(bits[jb], pow2_consts[jb]);
                pos_sum = b.add(pos_sum, term);
            }
            let row_times_w = b.mul(row_consts[i], w_const);
            let combined_expr = b.add(row_times_w, pos_sum);
            let combined_shifted = b.mul(combined_expr, shift_val_const);
            let payload_expr = b.add(combined_shifted, value_w[k]);
            payload.push(payload_expr);
        }
        for kk in d..8 {
            let _ = b
                .decompose_to_bits::<Val>(h_vals[kk], Val::bits())
                .expect("decompose unused h_val");
        }
    }

    // ─── Counter-sort permutation (the only PermuteAir) ──────────────────
    let payload_sorted: Vec<ExprId> = b
        .add_permute(&payload, sigma_ctr.clone())
        .expect("add_permute (counter sort)");
    for r in 0..n_ctr {
        let combined_shifted = b.mul(combined_sorted[r], shift_val_const);
        let recovered = b.add(combined_shifted, val_sorted[r]);
        b.connect(recovered, payload_sorted[r]);
    }

    // ─── Adjacent-equality + running sum + segment-end flags ─────────────
    b.connect(eq_tag[0], zero);
    b.connect(inv_diff[0], zero);
    for r in 1..n_ctr {
        let diff = b.sub(combined_sorted[r - 1], combined_sorted[r]);
        let lhs1 = b.mul(eq_tag[r], diff);
        b.connect(lhs1, zero);
        let one_minus_tag = b.sub(one, eq_tag[r]);
        let diff_inv = b.mul(diff, inv_diff[r]);
        let one_minus_diff_inv = b.sub(one, diff_inv);
        let lhs2 = b.mul(one_minus_tag, one_minus_diff_inv);
        b.connect(lhs2, zero);
    }

    // ─── Sortedness range-check (canonical sparse commit; the log(d·w) cost)
    // For each adjacent pair the gap `combined_sorted[r] − combined_sorted[r-1]`
    // must be a non-negative `addr_bits`-bit value. Decompose to full Val
    // width and force every bit at/above `addr_bits` to zero: a *decrease*
    // wraps to ≈ p (high bits set) and is rejected, so the prover cannot
    // split one counter's run into multiple segments. With sortedness,
    // equal addresses are adjacent ⇒ exactly one segment-end (entry) per
    // touched cell ⇒ the commitment is a function of the state alone.
    for r in 1..n_ctr {
        let gap = b.sub(combined_sorted[r], combined_sorted[r - 1]);
        let gap_bits = b
            .decompose_to_bits::<Val>(gap, Val::bits())
            .expect("decompose sort gap");
        // Top bits must vanish ⇒ 0 ≤ gap < 2^addr_bits (a decrease wraps to
        // ≈ p and sets a high bit, so it is rejected).
        for &bit in gap_bits.iter().skip(addr_bits) {
            b.connect(bit, zero);
        }
    }

    let mut acc: Vec<ExprId> = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        let new_acc = b.add(val_sorted[r], carried);
        acc.push(new_acc);
    }
    let mut a_active: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let active = if r == n_ctr - 1 { one } else { b.sub(one, eq_tag[r + 1]) };
        a_active.push(active);
    }

    // ─── Sparse-patch commitment (the rebind — no dense d·w, no Merkle) ──
    // entry[r] = recompose([a_active, a_active·addr, a_active·total, 0]).
    // Segment ends → [1, addr, total, 0]; all other rows → [0,0,0,0].
    let mut entries: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let active_addr = b.mul(a_active[r], combined_sorted[r]);
        let active_total = b.mul(a_active[r], acc[r]);
        let entry = b
            .recompose_base_coeffs_to_ext_via_alu::<Val>(&[
                a_active[r],
                active_addr,
                active_total,
                zero,
            ])
            .expect("recompose sparse entry");
        entries.push(entry);
    }
    let digest_entries = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &entries, true)
        .expect("hash sparse patch");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_entries[i], final_commit_pis[i]);
    }

    let circuit = b.build().expect("build countmin_memcheck circuit");

    // ─── Pack public + private values ────────────────────────────────────
    // The tamper hook publishes the EMPTY-state sparse commitment instead of
    // the real one, so the digest gate above must reject it.
    let published_final = if TAMPER_FINAL.with(|f| f.get()) {
        let empty: Vec<(bool, u64, u32)> = (0..n_ctr).map(|_| (false, 0, 0)).collect();
        commit_sparse_patch(&empty)
    } else {
        final_commit
    };
    let final_commit_packed = pack_commit_to_challenge(&published_final);
    let batch_commit_packed = pack_commit_to_challenge(&CountMinCommit(batch_commit.0));
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&final_commit_packed);
    public_inputs.extend_from_slice(&batch_commit_packed);

    let batch_packed_native = pack_batch_to_challenge(&batch);
    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&batch_packed_native);
    for u in &batch {
        let kl = (u.key & 0xFFFF_FFFF) as u32;
        let kh = (u.key >> 32) as u32;
        private_inputs.push(Challenge::from_u32(kl));
        private_inputs.push(Challenge::from_u32(kh));
        private_inputs.push(Challenge::from_u32(u.value));
    }
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(combined_sorted_native[r]));
    }
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u32(val_sorted_native[r]));
    }
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(tag_native[r] as u64));
    }
    for r in 0..n_ctr {
        let inv = if r == 0 || combined_sorted_native[r - 1] == combined_sorted_native[r] {
            Challenge::ZERO
        } else {
            let diff = Challenge::from_u64(combined_sorted_native[r - 1])
                - Challenge::from_u64(combined_sorted_native[r]);
            diff.try_inverse().expect("nonzero diff inverts")
        };
        private_inputs.push(inv);
    }
    {
        use p3_field::BasedVectorSpace;
        let hasher = MyHash::new(make_perm());
        for u in &batch {
            let input = [Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO];
            let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
            let d0 = Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 coeffs");
            let d1 = Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 coeffs");
            private_inputs.push(d0);
            private_inputs.push(d1);
        }
    }

    // ─── Run + prove ─────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run countmin_memcheck circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (memcheck)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_permute_table::<4>();
    let __t_p = std::time::Instant::now();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (memcheck)");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover
        .verify_all_tables(&proof)
        .expect("self-verify countmin_memcheck leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    CountMinMemcheckProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        final_commit,
        batch_commit: CountMinCommit(batch_commit.0),
        params,
        patch,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip. The prover self-verifies before returning, and that
    /// self-verify includes the `connect(digest_entries, final_commit_pis)`
    /// gate — so a returned proof *is* a witness that the native
    /// `commit_sparse_patch` (fed as the public input) equals the
    /// in-circuit Poseidon digest of the recompose'd entries. This test
    /// therefore validates the native↔circuit hash agreement just by not
    /// panicking, then checks the query estimates and that the certified
    /// state is non-empty.
    #[test]
    fn memcheck_round_trip() {
        let params = CmMemcheckParams { d: 2, w: 4, batch: 2 };
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let r = prove_countmin_memcheck(params, updates);

        // Each unique-key update contributes its value to every row it hits.
        assert!(r.query(7) >= 3);
        assert!(r.query(11) >= 5);
        assert!(r.query(999_999) <= 5);

        // Non-empty state ⇒ the sparse commitment differs from the empty one.
        let empty = commit_sparse_patch(&vec![(false, 0, 0); params.d * params.batch]);
        assert_ne!(r.final_commit.0, empty.0, "final commit must differ from empty");
        assert!(!r.patch.is_empty(), "two distinct keys must touch some cells");
    }

    /// Repeated keys: both records for the repeated key hash to the same
    /// `d` counters and are summed by the running sum into a single
    /// sparse entry (canonical commit).
    #[test]
    fn memcheck_repeated_keys() {
        let params = CmMemcheckParams { d: 4, w: 8, batch: 4 };
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let r = prove_countmin_memcheck(params, updates);
        assert!(r.query(7) >= 6); // 3 + 2 + 1
        assert!(r.query(11) >= 5);
        // Canonical: at most one patch entry per touched address.
        let mut addrs: Vec<usize> = r.patch.iter().map(|(a, _)| *a).collect();
        addrs.sort_unstable();
        let n = addrs.len();
        addrs.dedup();
        assert_eq!(addrs.len(), n, "each touched address appears exactly once");
    }

    /// **Tamper.** Publishing a wrong (empty-state) final commitment while
    /// the circuit hashes the real sparse patch must make the self-verify
    /// reject: the `connect(digest_entries, final_commit_pis)` gate fails.
    #[test]
    fn tamper_rejected() {
        let params = CmMemcheckParams { d: 2, w: 4, batch: 2 };
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        // Honest proof verifies.
        let _ok = prove_countmin_memcheck(params, updates.clone());

        // Tampered: force the wrong published commitment; expect a panic
        // from the prover's self-verify.
        TAMPER_FINAL.with(|f| f.set(true));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prove_countmin_memcheck(params, updates.clone());
        }));
        std::panic::set_hook(prev);
        TAMPER_FINAL.with(|f| f.set(false));
        assert!(res.is_err(), "tampered final commitment must be rejected");
    }

    /// **Proves a wide sketch that `one_hot` rejects outright.** At
    /// `d = 7, w = 16384, batch = 32`, `one_hot`'s selector budget
    /// `batch·d·(d·w) = 32·7·114688 ≈ 25.7M` exceeds its default `16M`
    /// `COUNTMIN_MAX_SEL_CELLS` cap, so `prove_countmin_final` panics in
    /// `validate()`. `memcheck`'s cost is independent of `w` (it only ever
    /// handles `batch·d = 224` counter rows plus the sparse patch), so it
    /// proves in well under a second. `#[ignore]`d because it is still a
    /// real STARK prove, not a unit check.
    ///
    /// Run: `cargo test --release --lib countmin_memcheck::tests::proves_wide_sketch -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn proves_wide_sketch() {
        let (d, w, batch) = (7usize, 16384usize, 32usize);

        // one_hot would refuse this shape: assert its guard actually trips so
        // the head-to-head claim stays honest if the cap ever changes.
        let sel = batch * d * (d * w);
        assert!(sel > 16_000_000, "one_hot selector budget {sel} should exceed the 16M cap");

        let params = CmMemcheckParams { d, w, batch };
        let updates: Vec<CountMinUpdate> = (0..batch)
            .map(|i| CountMinUpdate {
                key: (i as u64).wrapping_mul(0x9E37_79B9) ^ 0xABCD,
                value: 1,
            })
            .collect();
        let t = std::time::Instant::now();
        let r = prove_countmin_memcheck(params, updates.clone());
        println!(
            "memcheck d={d} w={w} batch={batch}: proved in {:?}, {} touched cells, proof {} bytes \
             (one_hot selector budget would be {sel} > 16M → rejected)",
            t.elapsed(),
            r.patch.len(),
            r.proof_size()
        );
        assert!(r.patch.len() <= d * batch);
        assert!(r.query(updates[0].key) >= 1);
    }
}
