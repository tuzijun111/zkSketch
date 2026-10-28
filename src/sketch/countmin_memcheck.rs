//! Count-Min `memcheck` leaf: commits only the touched (address, total) cells, no Merkle path.
//! Sound only from the empty initial state, since untouched cells are never opened.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_permute_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        permute_air_builders, permute_preprocessor, poseidon2_air_builders_d4,
        poseidon2_preprocessor, range_air_builders, range_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
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
use crate::sketch::bind::{self, Binding};
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

#[cfg(test)]
thread_local! {
    /// Test-only malicious prover: `(touch index k·d + i, claimed address,
    /// claimed value)` overrides the honest touch of record `k` on row `i`
    /// in the claimed sorted view (and hence the committed sparse patch).
    /// Drives `tests::stage_g_collision_*`.
    static FORGE_TOUCHES: std::cell::RefCell<Vec<(usize, u64, u32)>> =
        const { std::cell::RefCell::new(Vec::new()) };
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
/// patch digest (a Poseidon2 hash of the padded touched-cell list), **not**
/// the dense `commit_countmin` digest — so it is not directly comparable to
/// `one_hot`/`merkle` commitments. Querying goes through the materialised `patch`.
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
/// value of every touched cell being a public constant (`0`). For a
/// non-empty prior state use the `omc` leaf ([`super::countmin_omc`]).
///
/// # Panics
/// - `params.validate()` failures.
/// - `batch.len() != params.batch`.
pub fn prove_countmin_memcheck(
    params: CmMemcheckParams,
    batch: Vec<CountMinUpdate>,
) -> CountMinMemcheckProof {
    prove_countmin_memcheck_with(params, batch, bind::default_binding())
}

/// [`prove_countmin_memcheck`] with an explicit [`Binding`].
///
/// [`Binding::Legacy`] is the pre-fix circuit, unchanged (unsound: batch
/// fields and digest limbs are unbound, sponge IVs are free, and the
/// counter sort packs `address·2^20 + value`, which collides on BabyBear once
/// `d·w > 1920`). [`Binding::Semantic`] / [`Binding::Bound`] use canonical
/// position splits, the coordinate-wise sort key `address + value·e₁`, an
/// exact range on `combined_sorted[0]` and base pins on `val_sorted`;
/// `Bound` also ALU-binds the batch fields and digest limbs and hashes with a
/// zero IV (see [`crate::sketch::bind`]).
pub fn prove_countmin_memcheck_with(
    params: CmMemcheckParams,
    batch: Vec<CountMinUpdate>,
    binding: Binding,
) -> CountMinMemcheckProof {
    build_countmin_memcheck(params, batch, binding).prove()
}

/// A built memcheck leaf: circuit, witness, registered prover.
struct MemcheckCircuit {
    circuit: p3_circuit::Circuit<Challenge>,
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: CircuitProverData<ConfigWithFriParams>,
    trace_rows: u64,
    final_commit: CountMinCommit,
    batch_commit: CountMinCommit,
    params: CmMemcheckParams,
    patch: Vec<(usize, u32)>,
}

impl MemcheckCircuit {
    fn run(&self) -> p3_circuit::tables::Traces<Challenge> {
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&self.public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&self.private_inputs).expect("set_private_inputs");
        runner.run().expect("run countmin_memcheck circuit")
    }

    fn prove(self) -> CountMinMemcheckProof {
        let __t_w = std::time::Instant::now();
        let traces = self.run();
        let __witness = __t_w.elapsed();
        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (memcheck)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify countmin_memcheck leaf");
        crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
            witness: __witness,
            prove: __prove,
            verify: __t_v.elapsed(),
            trace_rows: self.trace_rows,
        });
        CountMinMemcheckProof {
            output: RecursionOutput(proof, Rc::new(self.circuit_prover_data)),
            final_commit: self.final_commit,
            batch_commit: self.batch_commit,
            params: self.params,
            patch: self.patch,
        }
    }

    #[cfg(test)]
    fn prove_traces(
        &self,
        traces: &p3_circuit::tables::Traces<Challenge>,
    ) -> Result<p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>, String> {
        let proof = self
            .prover
            .prove_all_tables(traces, &self.circuit_prover_data)
            .map_err(|e| format!("prove: {e:?}"))?;
        self.prover.verify_all_tables(&proof).map_err(|e| format!("verify: {e:?}"))?;
        Ok(proof)
    }
}

fn build_countmin_memcheck(
    params: CmMemcheckParams,
    batch: Vec<CountMinUpdate>,
    binding: Binding,
) -> MemcheckCircuit {
    params.validate();
    let bound = binding.is_bound();
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
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
    #[cfg(test)]
    FORGE_TOUCHES.with(|f| {
        for &(idx, addr, val) in f.borrow().iter() {
            u_ctr_data[idx] = (addr, val);
        }
    });
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
    if bound {
        assert!(addr_bits <= 24, "bound memcheck: d·w must be ≤ 2^24");
        b.enable_range(generate_range_trace::<Val, Challenge>);
    }

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
    // Semantic/Bound: e₁ (coordinate-wise sort key), i·w, split constants.
    // (Allocated only when used, so the Legacy circuit stays byte-identical.)
    let e1 = if bound {
        b.alloc_const(
            Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE, Val::ZERO, Val::ZERO])
                .expect("e1"),
            "e1",
        )
    } else {
        zero
    };
    let row_w_consts: Vec<ExprId> = if bound {
        (0..d)
            .map(|i| b.alloc_const(Challenge::from_u64((i * w) as u64), "row_i*w"))
            .collect()
    } else {
        Vec::new()
    };
    let split_c = bound.then(|| bind::SplitConsts::new::<Val, Challenge>(&mut b, w_log2, one, zero));

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

    if let Some(&b0) = batch_packed.first() {
        b.tag(b0, "mc_batch_packed_0").expect("tag");
    }

    // ─── Bind the batch to its commitment ────────────────────────────────
    let digest_batch = bind::hash_slice(&mut b, &cfg, &batch_packed, zero, binding);
    for i in 0..DIGEST_PACKING {
        b.connect(digest_batch[i], batch_commit_pis[i]);
    }
    for k in 0..m {
        let coeffs = bind::decompose::<Val, Challenge>(&mut b, batch_packed[k], binding, bind::no_pin, |b, i, c| {
            if i < 3 {
                bind::pin_base::<Val, Challenge>(b, c);
            }
        });
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
    if let Some(&kf0) = key_field.first() {
        b.tag(kf0, "mc_key_field_0").expect("tag");
    }

    // ─── PRF hash gadget over every record → payload rows ────────────────
    // (Identical to countmin_final Stage F.)
    let mut h_digest_witnesses: Vec<(ExprId, ExprId)> = Vec::with_capacity(m);
    for _ in 0..m {
        let h0 = b.alloc_private_input("h_digest_0");
        let h1 = b.alloc_private_input("h_digest_1");
        h_digest_witnesses.push((h0, h1));
    }
    // Semantic/Bound: per record, per row, the canonical split `(pos, hi, dinv)`
    // of the row's digest limb (allocated after the digests; pushed after them).
    let split_w: Vec<Vec<[ExprId; 3]>> = if bound {
        (0..m)
            .map(|_| (0..d).map(|_| std::array::from_fn(|_| b.alloc_private_input("split"))).collect())
            .collect()
    } else {
        Vec::new()
    };
    let mut payload: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let hashed = bind::hash_slice(&mut b, &cfg, &[key_field[k]], zero, binding);
        let (h0, h1) = h_digest_witnesses[k];
        b.connect(hashed[0], h0);
        b.connect(hashed[1], h1);
        if let Some(sc) = &split_c {
            let sw = &split_w[k];
            let split_limb = |b: &mut CircuitBuilder<Challenge>, t: usize, c: ExprId| {
                if t < d {
                    let [pos, hi, dinv] = sw[t];
                    let x = bind::canonical_split_gadget::<Val, Challenge>(b, pos, hi, dinv, sc);
                    b.connect(x, c);
                }
            };
            let pin_unused = |b: &mut CircuitBuilder<Challenge>, t: usize, c: ExprId| {
                if t >= d {
                    bind::pin_base::<Val, Challenge>(b, c);
                }
            };
            let _ = bind::decompose::<Val, Challenge>(&mut b, h0, binding, split_limb, pin_unused);
            if d > 4 {
                let _ = bind::decompose::<Val, Challenge>(
                    &mut b,
                    h1,
                    binding,
                    |b, i, c| split_limb(b, 4 + i, c),
                    |b, i, c| pin_unused(b, 4 + i, c),
                );
            }
            for (i, sw_i) in sw.iter().enumerate() {
                let comb = b.add(row_w_consts[i], sw_i[0]);
                payload.push(b.mul_add(value_w[k], e1, comb));
            }
            continue;
        }
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
        let recovered = if bound {
            b.mul_add(val_sorted[r], e1, combined_sorted[r])
        } else {
            let combined_shifted = b.mul(combined_sorted[r], shift_val_const);
            b.add(combined_shifted, val_sorted[r])
        };
        b.connect(recovered, payload_sorted[r]);
    }
    if bound {
        // First sorted address exact (later ones: + range-checked gaps);
        // sorted values base (they reach the entries through `acc`).
        bind::range_exact::<Val, Challenge>(&mut b, combined_sorted[0], addr_bits);
        for r in 0..n_ctr {
            bind::pin_base::<Val, Challenge>(&mut b, val_sorted[r]);
        }
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
    let digest_entries = bind::hash_slice(&mut b, &cfg, &entries, zero, binding);
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
        if bound {
            for u in &batch {
                let input = [Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO];
                let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
                for limb in digest.iter().take(d) {
                    private_inputs
                        .extend(bind::canonical_split_vals::<Val>(*limb, w_log2).map(Challenge::from));
                }
            }
        }
    }

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
    if bound {
        preprocessors.push(range_preprocessor::<Val>());
        air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    }

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
    if bound {
        prover.register_range_table::<4>();
    }

    MemcheckCircuit {
        circuit,
        public_inputs,
        private_inputs,
        prover,
        circuit_prover_data,
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
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

    // ── Binding (see `crate::sketch::bind`): legacy-vs-bound forgery tests ──

    use crate::sketch::forge;
    use p3_circuit::ops::{NpoTypeId, Poseidon2Trace};

    const FP: CmMemcheckParams = CmMemcheckParams { d: 2, w: 8, batch: 2 };

    fn fp_updates() -> Vec<CountMinUpdate> {
        vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 9, value: 5 }]
    }

    #[test]
    fn memcheck_round_trip_all_bindings() {
        let legacy = prove_countmin_memcheck_with(FP, fp_updates(), Binding::Legacy);
        for binding in [Binding::Bound, Binding::Semantic] {
            let r = prove_countmin_memcheck_with(FP, fp_updates(), binding);
            assert_eq!(r.final_commit.0, legacy.final_commit.0, "{binding:?}");
            assert_eq!(r.query(7), legacy.query(7));
        }
        // d > 4 (second digest Challenge).
        let p = CmMemcheckParams { d: 7, w: 8, batch: 2 };
        let r = prove_countmin_memcheck_with(p, fp_updates(), Binding::Bound);
        assert!(r.query(9) >= 5);
    }

    /// FORGED BATCH RECORD (transplant): record 0 routes key 7, then the
    /// committed batch is rewritten to key 1234 and rehashed.
    fn forged_batch(binding: Binding) -> bool {
        forge::accepted_with_control(&format!("cm memcheck forged batch ({binding:?})"), |f| {
            forged_batch_run(binding, f)
        })
    }

    fn forged_batch_run(binding: Binding, forge_it: bool) -> bool {
        let c = build_countmin_memcheck(FP, fp_updates(), binding);
        let mut traces = c.run();
        let mut recs = fp_updates();
        if forge_it {
            recs[0].key = 1234;
        }
        let w = traces.tag_to_witness["mc_batch_packed_0"];
        forge::set_wid::<Val, Challenge>(&mut traces, w, pack_batch_to_challenge(&recs)[0]);
        forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, Poseidon2Config::BABY_BEAR_D4_W16, &make_perm());
        forge::accepted(|| c.prove_traces(&traces).map(|_| ()))
    }

    /// FREE SPONGE IV on record 0's routing hash.
    fn forged_iv(binding: Binding) -> bool {
        forge::accepted_with_control(&format!("cm memcheck forged IV ({binding:?})"), |f| {
            forged_iv_run(binding, f)
        })
    }

    fn forged_iv_run(binding: Binding, forge_it: bool) -> bool {
        let c = build_countmin_memcheck(FP, fp_updates(), binding);
        let mut traces = c.run();
        let kf0 = traces.tag_to_witness["mc_key_field_0"].0;
        let key = NpoTypeId::poseidon2_perm(Poseidon2Config::BABY_BEAR_D4_W16);
        let mut pt = traces.non_primitive_trace::<Poseidon2Trace<Val>>(&key).expect("p2").clone();
        let row = pt
            .operations
            .iter_mut()
            .find(|r| r.new_start && r.in_ctl[0] && r.input_indices[0] == kf0)
            .expect("record 0 routing hash row");
        if forge_it {
            row.input_values[8] += Val::ONE;
        }
        traces.non_primitive_traces.insert(key, Box::new(pt));
        forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, Poseidon2Config::BABY_BEAR_D4_W16, &make_perm());
        forge::accepted(|| c.prove_traces(&traces).map(|_| ()))
    }

    #[test]
    fn forged_batch_record_legacy_accepts_bound_rejects() {
        if !bind::probe::fork_binds_decompose() {
            assert!(forged_batch(Binding::Legacy), "Legacy accepts the forged batch record (PoC)");
        }
        assert!(!forged_batch(Binding::Bound), "Bound must reject the forged batch record");
        // Merged soundness fork: the fork itself binds decompose coefficients, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if bind::probe::fork_binds_decompose() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(!forged_batch(b), "fork binds decompose coefficients: {b:?} must reject too");
            }
        }
    }

    #[test]
    fn forged_routing_iv_legacy_accepts_bound_rejects() {
        if !bind::probe::fork_binds_iv() && !bind::probe::fork_binds_decompose() {
            assert!(forged_iv(Binding::Legacy), "Legacy accepts the free-IV digest (PoC)");
        }
        assert!(!forged_iv(Binding::Bound), "Bound must reject the IV forgery");
        // Merged soundness fork: the fork itself binds the sponge IV, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if bind::probe::fork_binds_iv() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(!forged_iv(b), "fork binds the sponge IV: {b:?} must reject too");
            }
        }
    }

    // ── Circuit-level attack: Stage-G packing collision ─────────────────────
    //
    // The memcheck port of `countmin_omc::tests::stage_g_collision_*` (same
    // Stage-G code). Fork-independent: in-field arithmetic on the `Legacy`
    // packing `address·2^20 + value`, closed only by the `Semantic`
    // coordinate-wise sort key.

    use crate::sketch::forge_permute;

    /// Where a (possibly forged) memcheck proof ended: `Ok((certified final
    /// commitment, certified sparse patch))` if it proved and verified, else
    /// `Err((runner_rejected, message))`.
    type McOutcome = Result<(CountMinCommit, Vec<(usize, u32)>), (bool, String)>;

    /// On BabyBear `1920·2^20 = p − 1`, so `(a + 1920)·2^20 + (v + 1) ≡
    /// a·2^20 + v`. With `d·w = 2048 > 1920`, record 0's row-0 touch at
    /// bucket `a < 128` is re-split in the claimed sorted view as address
    /// `a + 1920` (row 1) with value `v + 1`, and the certified sparse patch
    /// follows it. `proof_level` also forges the Stage-G PermuteAir outputs
    /// to the claimed sorted tuples, so only the PermuteBus can reject. With
    /// `forged = false` the same plumbing carries the honest touch (control).
    /// Returns the outcome and `a`.
    fn stage_g_collision(binding: Binding, forged: bool, proof_level: bool) -> (McOutcome, usize) {
        let (d, w, m) = (2usize, 1024usize, 2usize);
        let params = CmMemcheckParams { d, w, batch: m };
        let key = (1u64..)
            .find(|&k| hash_cell_prf(0, k, w) < 128)
            .expect("key with row-0 bucket < 128");
        let a = hash_cell_prf(0, key, w) as u64;
        let updates = vec![
            CountMinUpdate { key, value: 5 },
            CountMinUpdate { key: key + 7_777, value: 1 },
        ];
        let touch = if forged { (0, a + 1920, 6) } else { (0, a, 5) };
        FORGE_TOUCHES.with(|f| *f.borrow_mut() = vec![touch]);
        let built = forge::catch_msg(|| build_countmin_memcheck(params, updates.clone(), binding));
        FORGE_TOUCHES.with(|f| f.borrow_mut().clear());
        let mut c = built.expect("build (the runner has not run yet)");
        if proof_level {
            let mut sorted: Vec<(u64, u32)> = updates
                .iter()
                .flat_map(|u| {
                    (0..d).map(move |i| ((i * w + hash_cell_prf(i, u.key, w)) as u64, u.value))
                })
                .collect();
            sorted[0] = (touch.1, touch.2);
            sorted.sort_by_key(|&(c, _)| c); // the same stable sort as the builder
            let tuples: Vec<Challenge> = sorted
                .iter()
                .map(|&(c, v)| {
                    if binding.is_bound() {
                        Challenge::from_basis_coefficients_slice(&[
                            Val::from_u64(c),
                            Val::from_u32(v),
                            Val::ZERO,
                            Val::ZERO,
                        ])
                        .expect("4 coeffs")
                    } else {
                        Challenge::from_u64(c * SHIFT_VAL + u64::from(v))
                    }
                })
                .collect();
            forge_permute::forge_permute_outputs(&mut c.circuit, 0, tuples);
        }
        let out = match forge::catch_msg(|| c.run()) {
            Err(msg) => Err((true, msg)),
            Ok(traces) => match forge::catch_msg(|| c.prove_traces(&traces)) {
                Ok(Ok(_)) => Ok((c.final_commit, c.patch.clone())),
                Ok(Err(e)) => Err((false, e)),
                Err(msg) => Err((false, format!("prove panicked: {msg}"))),
            },
        };
        (out, a as usize)
    }

    fn check_stage_g_collision(proof_level: bool) {
        let total = |patch: &[(usize, u32)], addr: usize| -> u32 {
            patch.iter().filter(|e| e.0 == addr).map(|e| e.1).sum()
        };
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let what = format!("memcheck {binding:?} Stage-G collision (proof_level={proof_level})");
            let (ctl, a) = stage_g_collision(binding, false, proof_level);
            eprintln!("{what} control: {ctl:?}");
            let (honest_commit, honest_patch) =
                ctl.unwrap_or_else(|e| panic!("{what}: the control must verify: {e:?}"));
            let (out, _) = stage_g_collision(binding, true, proof_level);
            eprintln!("{what} forged: {out:?}");
            if binding.is_bound() {
                let ok = match &out {
                    Err((true, msg)) => {
                        !proof_level
                            && msg.contains("run countmin_memcheck")
                            && msg.contains("WitnessConflict")
                    }
                    Err((false, msg)) => proof_level && msg.starts_with("verify:"),
                    Ok(_) => false,
                };
                assert!(ok, "{what}: expected rejection, got {out:?}");
            } else {
                let (commit, patch) = out.expect("Legacy accepts the (a + 1920, v + 1) re-split (PoC)");
                assert_ne!(commit, honest_commit, "{what}: certifies a different patch");
                assert_eq!(total(&patch, a) + 5, total(&honest_patch, a), "{what}: the +5 left `a`");
                assert_eq!(
                    total(&patch, a + 1920),
                    total(&honest_patch, a + 1920) + 6,
                    "{what}: …and landed at a + 1920 as +6"
                );
            }
        }
    }

    /// Witness level: `Semantic`/`Bound` conflict at the Stage-G `connect`;
    /// `Legacy` ACCEPTS.
    #[test]
    fn stage_g_collision_legacy_accepts_semantic_bound_reject() {
        check_stage_g_collision(false);
    }

    /// Proof level: the verifier rejects `Semantic`/`Bound` on the
    /// PermuteBus; `Legacy` ACCEPTS.
    #[test]
    fn stage_g_collision_proof_level_legacy_accepts_semantic_bound_reject() {
        check_stage_g_collision(true);
    }
}
