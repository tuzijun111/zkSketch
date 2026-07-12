//! **Goldilocks (D=2) offline-memory-checking HyperLogLog leaf** — the
//! selectable Goldilocks counterpart of [`super::hll_omc`], mirroring how
//! [`super::ss_final_full_gl`] / [`super::gk_bandmerge_gl`] shadow their
//! BabyBear originals. The BabyBear module stays byte-for-byte untouched;
//! this file only adds the `hll_gl` option.
//!
//! Same check as the BabyBear leaf (see [`super::hll_omc`]'s header for the
//! WS ⊎ = RS offline-memory-checking argument and the max-update `ts`
//! soundness note). The port-relevant differences:
//!
//! - **Config**: `crate::config_gl` (Goldilocks, D=2 extension, width-8
//!   Poseidon2, digest 4) via `GOLDILOCKS_D2_W8`; registration/builders use
//!   the `::<2>` / `_d2` forms.
//! - **Register packing**: 2 registers per `Challenge` (D=2) instead of 4.
//! - **Routing**: the key digest is 4 Goldilocks coefficients (2 Challenges)
//!   instead of 8 BabyBear ones; `idx`/`ρ` come from 64-bit decompositions of
//!   `digest[0]`/`digest[1]` and the remaining 2 coefficients are consumed
//!   (BabyBear: 8 × 31-bit — same ~256 decomposed bits per record).
//! - **Multiset encoding**: BabyBear packs `(addr, val, ts, 1)` into one
//!   D=4 challenge. D=2 has only two coords, and splitting an element across
//!   two cells would be UNSOUND: the permutation argument is a multiset
//!   equality over *cells*, so a malicious σ could re-pair value-cells with
//!   ts-cells across elements and resurrect the max-suppression attack the
//!   `ts` coordinate exists to kill. Instead each element stays ONE cell:
//!   `[addr, 4·val + 2·ts + 1]` — injective because `val < 2^RANK_BITS` is
//!   range-checked for every multiset participant (`ts` is boolean, the `+1`
//!   tag keeps real cells disjoint from the zero dummies of inactive rows).
//!   The two extra 8-bit range checks per register this needs (`o_cells`,
//!   `n_cells`) are honest-complete — registers hold ranks `ρ ≤ 65 < 2^8`.

use std::collections::HashMap;
use std::rc::Rc;

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    GoldilocksD2Width8, Poseidon2Config, generate_expose_trace, generate_permute_trace,
    generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d2, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::config_gl::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl as ConfigWithFriParams;
use crate::recursion::recursive::leaf_gl::{
    DIGEST_PACKING, GlCommit, make_leaf_config, pack_commit_to_challenge,
};

const LOG_FINAL_POLY_LEN: usize = 6;
/// Pack `(idx, ρ)` as `idx·2^SHIFT + ρ`. `ρ ≤ Val::bits()+1 = 65 < 2^RANK_BITS`,
/// so `SHIFT = RANK_BITS` keeps the packing injective; range-checking
/// `ρ_sorted < 2^RANK_BITS` makes it uniquely invertible.
const SHIFT_VAL_BITS: u64 = 8;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;
/// Range-check window for rank/register comparisons. `ρ ≤ Val::bits()+1`
/// (= 65) and registers hold a rank, so both stay well under `2^RANK_BITS`.
const RANK_BITS: usize = 8;

fn val_bits() -> usize {
    Val::bits()
}

thread_local! {
    /// When set, the prover commits to a CORRUPTED final state (one register
    /// bumped) while the multiset/patch are built from the honest one, so
    /// `M_old ⊎ W = M_new ⊎ R` fails and the self-verify rejects. Drives
    /// [`tests::tamper_rejected`].
    static TAMPER_FINAL_CELL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When set, mount the max-suppression attack (see the injection site): the
    /// honest witness is rewritten to claim no register was raised while the
    /// committed final is left unchanged. Drives [`tests::suppression_rejected`].
    static TAMPER_SUPPRESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Native register routing: `idx = digest[0] mod m`, `ρ = 1 +
/// trailing_zeros(digest[1])` over the `val_bits()` window (digest =
/// `MyHash([key, 0])`, one Challenge's worth of coefficients) — mirrors the
/// in-circuit derivation. NOTE: the Goldilocks digest differs from the
/// BabyBear [`super::hll_omc::route`], so `hll_gl` register arrays are a
/// distinct (statistically equivalent) HLL instance — chains/forests must not
/// mix fields.
pub fn route(key: u64, m: usize) -> (usize, u32) {
    let hasher = MyHash::new(make_perm());
    let input = [Val::from_u64(key), Val::ZERO];
    let digest: [Val; 4] = hasher.hash_iter(input.iter().copied());
    let idx = (<Val as PrimeField64>::as_canonical_u64(&digest[0]) % m as u64) as usize;
    let tail = <Val as PrimeField64>::as_canonical_u64(&digest[1]);
    let nbits = val_bits() as u32;
    let mut tz = 0u32;
    while tz < nbits && (tail >> tz) & 1 == 0 {
        tz += 1;
    }
    (idx, tz + 1)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllOmcParams {
    /// Register-index bits; `m = 2^b` registers.
    pub b: usize,
    /// Records per epoch.
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
        assert!(
            self.b >= 2 && self.b <= 22,
            "b must be in 2..=22, got {}",
            self.b
        );
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(
            self.m() % 2 == 0,
            "m = 2^b must be a multiple of 2 (Challenge packing, D=2)"
        );
    }
}

/// A self-verified Goldilocks `omc` HLL leaf proof. Commitments are the dense
/// Poseidon2 digests over the `m` registers, so this chains against a real
/// committed prior register array.
pub struct HllOmcProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: GlCommit,
    pub final_commit: GlCommit,
    pub batch_commit: GlCommit,
    pub params: HllOmcParams,
}

impl HllOmcProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

/// Empty HLL/omc register array (`m = 2^b` zeros) — the stream boundary chain's
/// `S_0`, fed as the first leaf's `initial`.
pub fn hll_omc_empty(b: usize) -> Vec<u64> {
    vec![0u64; 1usize << b]
}

/// Native single-batch advance: max-fold each key's rank `ρ = route(key, m).1`
/// into its register — exactly the update the leaf proves — so the resulting
/// register array feeds the next leaf's `initial` and the boundaries chain.
pub fn hll_omc_advance(regs: &mut [u64], keys: &[u64], m: usize) {
    for &key in keys {
        let (idx, rho) = route(key, m);
        regs[idx] = regs[idx].max(rho as u64);
    }
}

/// `Com(S)` for an HLL/omc register array — the flat Poseidon2 hash over the
/// `m` register values the leaf recomputes in-circuit, so it equals the leaf's
/// `initial_commit`/`final_commit` and anchors the per-batch chain.
pub fn commit_hll_omc(regs: &[u64], _b: usize) -> [Val; 4] {
    let hasher = MyHash::new(make_perm());
    hasher.hash_iter(regs.iter().map(|&r| Val::from_u32(r as u32)))
}

fn commit_regs(regs32: &[u32]) -> GlCommit {
    let hasher = MyHash::new(make_perm());
    GlCommit(hasher.hash_iter(regs32.iter().map(|&c| Val::from_u32(c))))
}

/// Pack the register array 2-per-Challenge (D=2) — the coefficient stream the
/// in-circuit `add_hash_slice` absorbs equals the flat stream [`commit_regs`]
/// hashes natively.
fn pack_cells_to_challenge(regs32: &[u32]) -> Vec<Challenge> {
    let flat: Vec<Val> = regs32.iter().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(2)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("2 base coeffs"))
        .collect()
}

/// Range-checked `mx == max(a, bb)`: proves `mx ≥ a`, `mx ≥ bb`, and
/// `(mx−a)(mx−bb) == 0` (so `mx ∈ {a, bb}`). Both differences are range-checked
/// to `RANK_BITS` bits, so the values must be `< 2^RANK_BITS`.
fn prove_max(b: &mut CircuitBuilder<Challenge>, mx: ExprId, a: ExprId, bb: ExprId, zero: ExprId) {
    let da = b.sub(mx, a);
    let _ = b
        .decompose_to_bits::<Val>(da, RANK_BITS)
        .expect("max: mx>=a");
    let dbb = b.sub(mx, bb);
    let _ = b
        .decompose_to_bits::<Val>(dbb, RANK_BITS)
        .expect("max: mx>=bb");
    let prod = b.mul(da, dbb);
    b.connect(prod, zero);
}

/// Assert the LSB-first boolean `bits` (length `Val::bits()`) encode a
/// CANONICAL field value (`< p`), rejecting the alternate `x + p`
/// decomposition that `decompose_to_bits` otherwise admits — without which a
/// malicious prover could pick a non-canonical routing and misroute a record.
/// Both supported fields have the form `p = 2^n − 2^m + 1`, so `V ≥ p` iff the
/// top `n−m` bits are all 1 AND the low `m` bits are nonzero; assert the
/// negation as `(∏_{i≥m} bit_i) · (Σ_{i<m} bit_i·2^i) == 0`.
/// `pow2_lo[i] = 2^i` for `i < m` (`m == pow2_lo.len()`).
fn assert_canonical_bits(
    b: &mut CircuitBuilder<Challenge>,
    bits: &[ExprId],
    pow2_lo: &[ExprId],
    one: ExprId,
    zero: ExprId,
) {
    let m = pow2_lo.len();
    let n = bits.len();
    // Π of the high-run bits (bits[m..n]); == 1 iff every high bit is set.
    let mut hi_and = one;
    for &bit in &bits[m..n] {
        hi_and = b.mul(hi_and, bit);
    }
    // Σ of the low bits as an integer (< 2^m); == 0 iff the low run is all zero.
    let mut lo = zero;
    for i in 0..m {
        lo = b.mul_add(bits[i], pow2_lo[i], lo);
    }
    // Non-canonical (V ≥ p) ⟺ hi_and == 1 AND lo != 0; forbid it.
    let prod = b.mul(hi_and, lo);
    b.connect(prod, zero);
}

/// Low-bit count `m` of the canonical gadget: `p = 2^n − 2^m + 1`.
fn canon_low_bits() -> usize {
    let pm1 = <Val as PrimeField64>::as_canonical_u64(&(Val::ZERO - Val::ONE));
    let m = pm1.trailing_zeros() as usize;
    let n = val_bits();
    let expected = ((1u64 << (n - m)) - 1) << m; // bits [m..n) all set
    assert_eq!(
        pm1, expected,
        "canonical gadget requires the field modulus to have the form p = 2^n − 2^m + 1"
    );
    m
}

/// Prove one HLL epoch from an arbitrary committed `initial` register array
/// via the `M_old ⊎ W = M_new ⊎ R` multiset rebind with a max update.
/// `initial` is the `m` register values; `keys` is `params.batch` record keys.
pub fn prove_hll_omc(params: HllOmcParams, initial: Vec<u64>, keys: Vec<u64>) -> HllOmcProof {
    prove_hll_omc_impl(params, initial, keys, false)
}

/// Like [`prove_hll_omc`] but surfaces the `(initial, final)` boundary
/// commitments via the **Expose NPO** so the leaf can be folded by the
/// in-circuit boundary-bound Goldilocks forest.
pub fn prove_hll_omc_exposed(
    params: HllOmcParams,
    initial: Vec<u64>,
    keys: Vec<u64>,
) -> HllOmcProof {
    prove_hll_omc_impl(params, initial, keys, true)
}

/// A built, reusable Goldilocks `omc` HLL leaf: the circuit graph, its prover
/// data, and a registered prover. Build once per `(params, expose_boundary)`
/// and call [`Self::prove_epoch`] per batch — the graph is a pure function of
/// the shape except for the two Permute ops’ trace-generation hints, which each
/// prove swaps in via `Circuit::update_permute_witnesses`.
pub struct HllOmcLeafCircuit {
    params: HllOmcParams,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
}

/// Build the reusable Goldilocks `omc` HLL leaf circuit for a shape.
pub fn build_hll_omc_leaf(params: HllOmcParams, expose_boundary: bool) -> HllOmcLeafCircuit {
    params.validate();
    let HllOmcParams { batch: m_batch, .. } = params;
    let m = params.m();
    let addr_bits = params.addr_bits();
    let num_cells = m;
    let cell_packing = num_cells / 2;
    let l = num_cells + m_batch; // multiset side length

    // ─── Circuit ─────────────────────────────────────────────────────────
    let cfg = Poseidon2Config::GOLDILOCKS_D2_W8;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        make_perm(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    if expose_boundary {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    let init_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    if expose_boundary {
        b.add_expose(&[
            init_commit_pis[0],
            init_commit_pis[1],
            final_commit_pis[0],
            final_commit_pis[1],
        ])
        .expect("add_expose boundary");
    }
    let batch_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let two = b.alloc_const(Challenge::from_u64(2), "two");
    let four = b.alloc_const(Challenge::from_u64(4), "four");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
    let pow2_consts: Vec<ExprId> = (0..addr_bits)
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();
    // Canonicity gadget: `2^i` consts for the low `m` bits of `p = 2^n − 2^m + 1`.
    let canon_m = canon_low_bits();
    let canon_pow2: Vec<ExprId> = (0..canon_m)
        .map(|i| b.alloc_const(Challenge::from_u64(1u64 << i), "canon2^i"))
        .collect();
    let cell_idx_consts: Vec<ExprId> = (0..num_cells)
        .map(|idx| b.alloc_const(Challenge::from_u64(idx as u64), "cell_idx"))
        .collect();

    // Private witnesses (allocation order MUST match the value push order).
    let init_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    let key_coeff: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("key_coeff"))
        .collect();
    let key_h0: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("key_h0"))
        .collect();
    let key_h1: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("key_h1"))
        .collect();
    let idx_sorted_w: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("idx_sorted"))
        .collect();
    let rho_sorted_w: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("rho_sorted"))
        .collect();
    let eq_tag: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("eq_tag"))
        .collect();
    let inv_diff: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("inv_diff"))
        .collect();
    let op_old: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("op_old"))
        .collect();
    let acc: Vec<ExprId> = (0..m_batch).map(|_| b.alloc_private_input("acc")).collect();
    let op_new: Vec<ExprId> = (0..m_batch)
        .map(|_| b.alloc_private_input("op_new"))
        .collect();
    // Per-cell final-read timestamp (1 iff the cell was written this batch).
    let ft_w: Vec<ExprId> = (0..num_cells)
        .map(|_| b.alloc_private_input("ft"))
        .collect();

    // ── Stage A: bind both register arrays + batch to their commitments ──
    let digest_init = b
        .add_hash_slice(&cfg, &init_packed, true)
        .expect("hash init");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], init_commit_pis[i]);
    }
    let digest_final = b
        .add_hash_slice(&cfg, &final_packed, true)
        .expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
    }
    let o_cells: Vec<ExprId> = init_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    let n_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    // Keys → field elements; batch commitment over them.
    let keys_t: Vec<ExprId> = (0..m_batch)
        .map(|k| {
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_coeff[k], zero])
                .expect("recompose key")
        })
        .collect();
    let hb = b.add_hash_slice(&cfg, &keys_t, true).expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_commit_pis[i]);
    }

    // ── Stage F: per record, derive (idx, ρ) from the key hash → payload ──
    let mut payload = Vec::with_capacity(m_batch);
    for k in 0..m_batch {
        let hashed = b
            .add_hash_slice(&cfg, &[keys_t[k]], true)
            .expect("hash key");
        b.connect(hashed[0], key_h0[k]);
        b.connect(hashed[1], key_h1[k]);
        let c0 = b
            .decompose_ext_to_base_coeffs::<Val>(key_h0[k])
            .expect("decompose h0");
        let c1 = b
            .decompose_ext_to_base_coeffs::<Val>(key_h1[k])
            .expect("decompose h1");
        // idx = digest[0] mod m = bottom `addr_bits` bits of c0[0].
        let idx_bits = b
            .decompose_to_bits::<Val>(c0[0], val_bits())
            .expect("bits digest0");
        // Canonicity: without this a prover could witness the bits of `c0[0]+p`
        // (when `c0[0] < 2^n − p`) and shift `idx` to misroute the record.
        assert_canonical_bits(&mut b, &idx_bits, &canon_pow2, one, zero);
        let mut idx = zero;
        for j in 0..addr_bits {
            idx = b.mul_add(idx_bits[j], pow2_consts[j], idx);
        }
        // ρ = 1 + trailing_zeros(digest[1]) = 1 + Σ_k ∏_{i≤k}(1 − bit_i) over c0[1].
        let dbits = b
            .decompose_to_bits::<Val>(c0[1], val_bits())
            .expect("bits digest1");
        // Canonicity: a non-canonical `c0[1]+p` decomposition flips the parity
        // (p is odd) and changes trailing_zeros, hence ρ — pin it to canonical.
        assert_canonical_bits(&mut b, &dbits, &canon_pow2, one, zero);
        let mut acc_zero = b.sub(one, dbits[0]);
        let mut tz = acc_zero;
        for k2 in 1..val_bits() {
            let omb = b.sub(one, dbits[k2]);
            acc_zero = b.mul(acc_zero, omb);
            tz = b.add(tz, acc_zero);
        }
        let rho = b.add(tz, one);
        // Consume the remaining decompose coeffs (every coeff must flow through
        // an ALU lhs — decompose_to_bits does). Goldilocks digest = 4 coeffs:
        // c0[0]/c0[1] already flow above; consume c1[0], c1[1].
        for idx2 in 0..2 {
            let _ = b
                .decompose_to_bits::<Val>(c1[idx2], val_bits())
                .expect("consume c1");
        }
        let packed = b.mul(idx, shift_val_const);
        payload.push(b.add(packed, rho));
    }

    // ── Stage G: permute payload into register-sorted order ──────────────
    // Placeholder identity permutation — `prove_epoch` swaps in the real
    // per-batch sigma via `update_permute_witnesses` before each run.
    let payload_sorted = b
        .add_permute(&payload, (0..m_batch).collect::<Vec<_>>())
        .expect("permute reg");
    for r in 0..m_batch {
        // Range-check ρ_sorted < 2^RANK_BITS so idx·2^SHIFT + ρ inverts uniquely.
        let _ = b
            .decompose_to_bits::<Val>(rho_sorted_w[r], RANK_BITS)
            .expect("rho range");
        let packed = b.mul(idx_sorted_w[r], shift_val_const);
        let rec = b.add(packed, rho_sorted_w[r]);
        b.connect(rec, payload_sorted[r]);
    }

    // ── Stage H: sortedness, segment tags, running max, touched new value ─
    if m_batch > 0 {
        b.connect(eq_tag[0], zero);
        b.connect(inv_diff[0], zero);
        // First segment starts at ρ_sorted[0].
        b.connect(acc[0], rho_sorted_w[0]);
    }
    for r in 1..m_batch {
        // eq_tag[r] == (idx_sorted[r] == idx_sorted[r-1]).
        let diff = b.sub(idx_sorted_w[r - 1], idx_sorted_w[r]);
        let l1 = b.mul(eq_tag[r], diff);
        b.connect(l1, zero);
        let omt = b.sub(one, eq_tag[r]);
        let di = b.mul(diff, inv_diff[r]);
        let omdi = b.sub(one, di);
        let l2 = b.mul(omt, omdi);
        b.connect(l2, zero);
        // sortedness: gap = idx_sorted[r] − idx_sorted[r-1] ∈ [0, 2^addr_bits).
        // The full-width window + zero-forced high bits keeps the decomposition
        // canonical (gap+p would need a forced-zero high bit).
        let gap = b.sub(idx_sorted_w[r], idx_sorted_w[r - 1]);
        let gb = b
            .decompose_to_bits::<Val>(gap, val_bits())
            .expect("gap bits");
        for &bit in gb.iter().skip(addr_bits) {
            b.connect(bit, zero);
        }
        // Running max: acc[r] = max(eq_tag[r]·acc[r-1], ρ_sorted[r]).
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        prove_max(&mut b, acc[r], carried, rho_sorted_w[r], zero);
    }
    // Segment-end flags (derived from eq_tag).
    let mut a_active = Vec::with_capacity(m_batch);
    for r in 0..m_batch {
        a_active.push(if r == m_batch - 1 {
            one
        } else {
            b.sub(one, eq_tag[r + 1])
        });
    }
    // Range-check every max-gadget operand to RANK_BITS so the difference-based
    // `≥` checks in prove_max are sound — an unbounded operand (e.g. a garbage
    // committed cell ≈ p−k) could otherwise wrap a difference into [0,2^RANK_BITS)
    // and certify a decrease.
    for r in 0..m_batch {
        let _ = b
            .decompose_to_bits::<Val>(op_old[r], RANK_BITS)
            .expect("op_old range");
        let _ = b
            .decompose_to_bits::<Val>(acc[r], RANK_BITS)
            .expect("acc range");
        let _ = b
            .decompose_to_bits::<Val>(op_new[r], RANK_BITS)
            .expect("op_new range");
    }
    // Touched new value: op_new[r] = max(op_old[r], acc[r]).
    for r in 0..m_batch {
        prove_max(&mut b, op_new[r], op_old[r], acc[r], zero);
    }
    // Final-read timestamps are boolean (0 = untouched/reads init, 1 = written).
    for a in 0..num_cells {
        let fm1 = b.sub(ft_w[a], one);
        let chk = b.mul(ft_w[a], fm1);
        b.connect(chk, zero);
    }
    // Range-check every committed register value entering the multiset: the
    // D=2 element encoding below packs `val` arithmetically with `ts`, which is
    // injective only for `val < 2^RANK_BITS`. Honest registers hold ranks
    // `ρ ≤ 65`, so this is complete; it also pins the committed state format.
    for a in 0..num_cells {
        let _ = b
            .decompose_to_bits::<Val>(o_cells[a], RANK_BITS)
            .expect("o_cell range");
        let _ = b
            .decompose_to_bits::<Val>(n_cells[a], RANK_BITS)
            .expect("n_cell range");
    }

    // ── Recommit (offline memory checking): WS ⊎ = RS with a time coordinate ─
    // enc(a, v, ts) = recompose([a, 4v + 2ts + 1]) — ONE D=2 cell per element
    // so the permutation argument cannot re-pair coordinates across elements
    // (see the module header). The +1 tag keeps real elements disjoint from the
    // zero dummies inactive update rows produce; the `ts` bit forces the read
    // at a touched cell to see the ts=0 init value, binding op_old to the
    // committed old register (the max fix). Injective because every `v` is
    // range-checked `< 2^RANK_BITS` and `ts` is boolean.
    let enc = |b: &mut CircuitBuilder<Challenge>, a: ExprId, v: ExprId, ts: ExprId| -> ExprId {
        let tag = b.mul_add(ts, two, one); // 2·ts + 1
        let packed_v = b.mul_add(v, four, tag); // 4·v + 2·ts + 1
        b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[a, packed_v])
            .expect("enc")
    };
    let mut input: Vec<ExprId> = Vec::with_capacity(l);
    let mut target: Vec<ExprId> = Vec::with_capacity(l);
    for a in 0..num_cells {
        // init write (ts=0) and final read (ts=ft_a).
        input.push(enc(&mut b, cell_idx_consts[a], o_cells[a], zero));
        target.push(enc(&mut b, cell_idx_consts[a], n_cells[a], ft_w[a]));
    }
    for r in 0..m_batch {
        // update write (ts=1) and update read (ts=0); inactive → zero dummy.
        let enc_w = enc(&mut b, idx_sorted_w[r], op_new[r], one);
        let w_elem = b.mul(a_active[r], enc_w);
        input.push(w_elem);
        let enc_r = enc(&mut b, idx_sorted_w[r], op_old[r], zero);
        let r_elem = b.mul(a_active[r], enc_r);
        target.push(r_elem);
    }
    let permuted = b
        .add_permute(&input, (0..l).collect::<Vec<_>>())
        .expect("permute mset");
    for r in 0..l {
        b.connect(permuted[r], target[r]);
    }

    let circuit = b.build().expect("build hll_omc_gl circuit");

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d2::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 2>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 2>(1));
    if expose_boundary {
        preprocessors.push(expose_preprocessor::<Val>());
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 2>());
    }

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 2>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (hll_omc_gl)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    if std::env::var("ZKS_DUMP_SHAPES").is_ok() {
        for (i, (air, deg)) in airs.iter().zip(degrees.iter()).enumerate() {
            eprintln!(
                "[hll_gl] table {i}: log2_h={deg} main_width={}",
                <_ as p3_air::BaseAir<Val>>::width(air)
            );
        }
    }
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8);
    prover.register_recompose_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8.d() != 2);
    prover.register_permute_table::<2>();
    if expose_boundary {
        prover.register_expose_table::<2>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();

    HllOmcLeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
    }
}

impl HllOmcLeafCircuit {
    /// Prove one epoch on the prebuilt circuit. `initial` is the `m` register
    /// values; `keys` is the `params.batch` record keys.
    pub fn prove_epoch(&mut self, initial: Vec<u64>, keys: Vec<u64>) -> HllOmcProof {
        let params = self.params;
        let HllOmcParams { batch: m_batch, .. } = params;
        let m = params.m();
        assert_eq!(initial.len(), m, "initial registers != m");
        assert_eq!(keys.len(), m_batch, "keys length != batch");
        let num_cells = m;
        let l = num_cells + m_batch; // multiset side length

        // ─── Native side: route + sort by register + max-fold ────────────────
        let init_regs: Vec<u32> = initial.iter().map(|&x| x as u32).collect();
        let mut idx_of = vec![0usize; m_batch];
        let mut rho_of = vec![0u32; m_batch];
        for (k, &key) in keys.iter().enumerate() {
            let (i, r) = route(key, m);
            idx_of[k] = i;
            rho_of[k] = r;
        }
        // Stable sort of the record indices by register, so per-register keys are
        // adjacent.
        let mut order: Vec<usize> = (0..m_batch).collect();
        order.sort_by_key(|&k| idx_of[k]);
        let sigma_reg: Vec<usize> = order.clone();
        let idx_sorted: Vec<u64> = order.iter().map(|&k| idx_of[k] as u64).collect();
        let rho_sorted: Vec<u32> = order.iter().map(|&k| rho_of[k]).collect();

        let mut tag_native = vec![0u32; m_batch];
        for r in 1..m_batch {
            if idx_sorted[r] == idx_sorted[r - 1] {
                tag_native[r] = 1;
            }
        }
        // Running max ρ over each register's contiguous segment.
        let mut acc_native = vec![0u32; m_batch];
        if m_batch > 0 {
            acc_native[0] = rho_sorted[0];
            for r in 1..m_batch {
                acc_native[r] = if tag_native[r] == 1 {
                    acc_native[r - 1].max(rho_sorted[r])
                } else {
                    rho_sorted[r]
                };
            }
        }
        // Segment-end flag: last row of each register's run.
        let mut a_active_native = vec![0u32; m_batch];
        for r in 0..m_batch {
            let ends = if r == m_batch - 1 {
                true
            } else {
                tag_native[r + 1] == 0
            };
            a_active_native[r] = u32::from(ends);
        }
        // Old register value at each row's register (from the honest initial state).
        let mut op_old_native: Vec<u32> = (0..m_batch)
            .map(|r| init_regs[idx_sorted[r] as usize])
            .collect();
        // New register value = max(old, running max ρ). Only meaningful at
        // segment-ends; harmless elsewhere (inactive rows never enter the multiset).
        let mut op_new_native: Vec<u32> = (0..m_batch)
            .map(|r| op_old_native[r].max(acc_native[r]))
            .collect();

        // Honest final register array: max update per touched register.
        let mut final_regs = init_regs.clone();
        for r in 0..m_batch {
            if a_active_native[r] == 1 {
                let a = idx_sorted[r] as usize;
                final_regs[a] = final_regs[a].max(op_new_native[r]);
            }
        }

        // Test-only max-suppression attack: claim every raised register was already
        // at the batch max (op_old = op_new = acc, so prove_max passes) and commit
        // the state UNCHANGED. The ts-based read binding must make the multiset
        // unmatchable.
        if TAMPER_SUPPRESS.with(|f| f.get()) {
            for r in 0..m_batch {
                if a_active_native[r] == 1 {
                    op_old_native[r] = acc_native[r];
                    op_new_native[r] = acc_native[r];
                }
            }
            final_regs = init_regs.clone(); // commit no change
        }

        let mut committed_final_regs = final_regs.clone();
        if TAMPER_FINAL_CELL.with(|f| f.get()) {
            committed_final_regs[0] = committed_final_regs[0].wrapping_add(1);
        }
        let initial_commit = commit_regs(&init_regs);
        let final_commit = commit_regs(&committed_final_regs);

        // Batch commitment over the keys (one Val each, MyHash([key,0]) blocks).
        let batch_commit: GlCommit = {
            let hasher = MyHash::new(make_perm());
            let flat: Vec<Val> = keys
                .iter()
                .flat_map(|&k| [Val::from_u64(k), Val::ZERO])
                .collect();
            GlCommit(hasher.hash_iter(flat.iter().copied()))
        };

        // Dense old/new register multisets + touched read/write rows, in the
        // offline-memory-checking read/write-set form with a time coordinate `ts`
        // (see the BabyBear module's soundness note).
        let o_cells_native: Vec<u32> = init_regs.clone();
        let n_cells_native: Vec<u32> = committed_final_regs.clone();
        // ft_a = 1 iff register a is touched (its final value was written at ts=1).
        let mut ft_native = vec![0u64; num_cells];
        for r in 0..m_batch {
            if a_active_native[r] == 1 {
                ft_native[idx_sorted[r] as usize] = 1;
            }
        }
        let mut input_native: Vec<Option<(u64, u64, u64)>> = Vec::with_capacity(l);
        let mut target_native: Vec<Option<(u64, u64, u64)>> = Vec::with_capacity(l);
        for a in 0..num_cells {
            input_native.push(Some((a as u64, o_cells_native[a] as u64, 0))); // init write
            target_native.push(Some((a as u64, n_cells_native[a] as u64, ft_native[a]))); // final read
        }
        for r in 0..m_batch {
            if a_active_native[r] == 1 {
                let addr = idx_sorted[r];
                input_native.push(Some((addr, op_new_native[r] as u64, 1))); // update write, ts=1
                target_native.push(Some((addr, op_old_native[r] as u64, 0))); // update read, ts=0
            } else {
                input_native.push(None);
                target_native.push(None);
            }
        }
        // sigma_mset s.t. input[sigma[r]] == target[r] (multiset matching).
        let mut buckets: HashMap<Option<(u64, u64, u64)>, Vec<usize>> = HashMap::new();
        for (i, v) in input_native.iter().enumerate() {
            buckets.entry(*v).or_default().push(i);
        }
        let sigma_mset: Vec<usize> = target_native
            .iter()
            .map(|t| {
                buckets
                    .get_mut(t)
                    .and_then(|v| v.pop())
                    .expect("honest multiset matching exists")
            })
            .collect();

        // Swap the real per-batch permutation hints into the prebuilt graph
        // (op order: register-sort permute, then multiset permute). Both are
        // single-cell-per-element, so no sigma expansion is needed.
        self.circuit
            .update_permute_witnesses(&[sigma_reg, sigma_mset])
            .expect("update permute witnesses (hll_omc_gl)");

        // ─── Public + private values (order matches allocation) ──────────────
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&initial_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&final_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&batch_commit));

        let mut private_inputs: Vec<Challenge> = Vec::new();
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&init_regs));
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&committed_final_regs));
        for &k in &keys {
            private_inputs.push(Challenge::from_u64(k));
        }
        {
            let hasher = MyHash::new(make_perm());
            for &k in &keys {
                let input = [Val::from_u64(k), Val::ZERO];
                let digest: [Val; 4] = hasher.hash_iter(input.iter().copied());
                private_inputs.push(
                    Challenge::from_basis_coefficients_slice(&digest[0..2]).expect("2 coeffs"),
                );
            }
            for &k in &keys {
                let input = [Val::from_u64(k), Val::ZERO];
                let digest: [Val; 4] = hasher.hash_iter(input.iter().copied());
                private_inputs.push(
                    Challenge::from_basis_coefficients_slice(&digest[2..4]).expect("2 coeffs"),
                );
            }
        }
        for r in 0..m_batch {
            private_inputs.push(Challenge::from_u64(idx_sorted[r]));
        }
        for r in 0..m_batch {
            private_inputs.push(Challenge::from_u32(rho_sorted[r]));
        }
        for r in 0..m_batch {
            private_inputs.push(Challenge::from_u64(tag_native[r] as u64));
        }
        for r in 0..m_batch {
            let inv = if r == 0 || idx_sorted[r - 1] == idx_sorted[r] {
                Challenge::ZERO
            } else {
                (Challenge::from_u64(idx_sorted[r - 1]) - Challenge::from_u64(idx_sorted[r]))
                    .try_inverse()
                    .expect("nonzero diff inverts")
            };
            private_inputs.push(inv);
        }
        for r in 0..m_batch {
            private_inputs.push(Challenge::from_u32(op_old_native[r]));
        }
        for r in 0..m_batch {
            private_inputs.push(Challenge::from_u32(acc_native[r]));
        }
        for r in 0..m_batch {
            private_inputs.push(Challenge::from_u32(op_new_native[r]));
        }
        for a in 0..num_cells {
            private_inputs.push(Challenge::from_u64(ft_native[a]));
        }

        // ─── Run + prove ─────────────────────────────────────────────────────
        let __t_w = std::time::Instant::now();
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&public_inputs).expect("set pubs");
            runner
                .set_private_inputs(&private_inputs)
                .expect("set privs");
            runner.run().expect("run hll_omc_gl")
        };
        let __witness = __t_w.elapsed();

        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (hll_omc_gl)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify hll_omc_gl leaf");
        crate::recursion::recursive::timing::record(
            crate::recursion::recursive::timing::LeafTiming {
                witness: __witness,
                prove: __prove,
                verify: __t_v.elapsed(),
                trace_rows: self.trace_rows,
            },
        );

        HllOmcProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial_commit,
            final_commit,
            batch_commit,
            params,
        }
    }
}

fn prove_hll_omc_impl(
    params: HllOmcParams,
    initial: Vec<u64>,
    keys: Vec<u64>,
    expose_boundary: bool,
) -> HllOmcProof {
    build_hll_omc_leaf(params, expose_boundary).prove_epoch(initial, keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Canonical gadget logic** — mirrors `assert_canonical_bits`' arithmetic
    /// in plain integers and confirms it flags EXACTLY the non-canonical
    /// (`x + p`) decompositions and accepts every canonical value. This is the
    /// soundness check for the routing-canonicity fix (the in-circuit gadget is
    /// a direct transcription of the same `(∏ hi)·lo == 0` predicate).
    #[test]
    fn canonical_gadget_logic() {
        let n = val_bits();
        let pm1 = <Val as PrimeField64>::as_canonical_u64(&(Val::ZERO - Val::ONE));
        let m = canon_low_bits(); // also asserts p = 2^n − 2^m + 1
        let p = pm1 as u128 + 1;
        // The predicate the circuit enforces == 0: hi_all AND lo_nonzero.
        let rejected = |v: u128| -> bool {
            let hi_mask = (1u128 << (n - m)) - 1;
            let hi_all = ((v >> m) & hi_mask) == hi_mask;
            let lo_nonzero = (v & ((1u128 << m) - 1)) != 0;
            hi_all && lo_nonzero
        };
        // Canonical values (< p) must be ACCEPTED.
        for &x in &[0u64, 1, 7, 255, pm1 - 1, pm1] {
            assert!(!rejected(x as u128), "canonical {x} wrongly rejected");
        }
        assert!(!rejected((p / 2) as u128), "canonical p/2 wrongly rejected");
        // Non-canonical x+p (fits n bits iff x < 2^n − p = 2^m − 1) must be REJECTED.
        let cprime = (1u128 << n) - p; // == 2^m − 1
        for x in 0u64..6 {
            if (x as u128) < cprime {
                let v = x as u128 + p;
                assert!(v < (1u128 << n), "x+p must fit n bits for this to be an alias");
                assert!(rejected(v), "non-canonical value {v} (= {x}+p) not rejected");
            }
        }
        // p itself (the x=0 alias) must be rejected.
        assert!(rejected(p), "the value p must be rejected as non-canonical");
    }

    /// Native max-fold reference for the final register array.
    fn native_final(b: usize, initial: &[u64], keys: &[u64]) -> Vec<u32> {
        let m = 1usize << b;
        let mut regs: Vec<u32> = initial.iter().map(|&x| x as u32).collect();
        for &k in keys {
            let (idx, rho) = route(k, m);
            regs[idx] = regs[idx].max(rho);
        }
        regs
    }

    /// Round-trip against a **non-empty** prior register array: the touched old
    /// values are reconciled against a real committed `M_old`, and the certified
    /// final commitment must equal the natively max-folded state.
    #[test]
    fn omc_round_trip_nonempty_prior() {
        let params = HllOmcParams { b: 4, batch: 8 };
        let m = params.m();
        // Seed a non-trivial prior register array.
        let prior_keys: Vec<u64> = (0..20u64)
            .map(|k| k.wrapping_mul(0x9E37_79B9) ^ 0x55)
            .collect();
        let mut prior = vec![0u64; m];
        for &k in &prior_keys {
            let (idx, rho) = route(k, m);
            prior[idx] = prior[idx].max(rho as u64);
        }
        let keys: Vec<u64> = (0..params.batch as u64)
            .map(|i| i.wrapping_mul(0xABCD_1234) ^ 0x7)
            .collect();
        let expect = native_final(params.b, &prior, &keys);
        let r = prove_hll_omc(params, prior.clone(), keys);
        assert_eq!(
            r.initial_commit,
            commit_regs(&prior.iter().map(|&x| x as u32).collect::<Vec<_>>())
        );
        assert_eq!(
            r.final_commit,
            commit_regs(&expect),
            "omc final commit must equal natively max-folded HLL"
        );
        assert_ne!(r.initial_commit, r.final_commit);
    }

    /// Repeated keys collapsing to the same register: the running max folds the
    /// duplicates into one read/write pair, reconciled against the prior.
    #[test]
    fn omc_repeated_registers() {
        let params = HllOmcParams { b: 3, batch: 6 };
        let m = params.m();
        let initial = vec![0u64; m];
        // Craft keys that collide on registers (route mod m).
        let keys: Vec<u64> = (0..params.batch as u64).map(|i| i % 3).collect();
        let expect = native_final(params.b, &initial, &keys);
        let r = prove_hll_omc(params, initial, keys);
        assert_eq!(r.final_commit, commit_regs(&expect));
    }

    /// Exposed-boundary smoke: the forest folds this leaf shape, so the Expose
    /// NPO registration must prove and self-verify.
    #[test]
    fn omc_exposed_smoke() {
        let params = HllOmcParams { b: 3, batch: 4 };
        let m = params.m();
        let initial = vec![0u64; m];
        let keys: Vec<u64> = vec![7, 11, 13, 17];
        let expect = native_final(params.b, &initial, &keys);
        let r = prove_hll_omc_exposed(params, initial, keys);
        assert_eq!(r.final_commit, commit_regs(&expect));
    }

    /// **Tamper.** Commit a corrupted final register (one bumped) while the
    /// multiset is built from the honest evolution: an untouched register then
    /// disagrees across `M_old`/`M_new`, so the equality fails and self-verify
    /// rejects.
    #[test]
    fn tamper_rejected() {
        let params = HllOmcParams { b: 3, batch: 4 };
        let m = params.m();
        let initial = vec![0u64; m];
        let keys: Vec<u64> = vec![7, 11, 13, 17];
        let _ok = prove_hll_omc(params, initial.clone(), keys.clone());

        TAMPER_FINAL_CELL.with(|f| f.set(true));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prove_hll_omc(params, initial.clone(), keys.clone());
        }));
        std::panic::set_hook(prev);
        TAMPER_FINAL_CELL.with(|f| f.set(false));
        assert!(
            res.is_err(),
            "corrupted final register must break the multiset equality"
        );
    }

    /// **Max-suppression attack (regression for the OMC soundness fix).** A batch
    /// that must RAISE registers is proven with op_old = op_new = acc and an
    /// unchanged committed final. The single-cell `(addr, 4v+2ts+1)` encoding
    /// must keep the ts read-binding intact, so no multiset matching exists and
    /// proving fails.
    #[test]
    fn suppression_rejected() {
        let params = HllOmcParams { b: 3, batch: 8 };
        let m = params.m();
        let initial = vec![0u64; m]; // empty prior ⇒ every routed record MUST raise
        let keys: Vec<u64> = vec![7, 11, 13, 17, 3, 5, 19, 23];
        // Honest proof accepts and actually changes the state.
        let honest = prove_hll_omc(params, initial.clone(), keys.clone());
        assert_ne!(
            honest.initial_commit, honest.final_commit,
            "honest batch changes state"
        );

        TAMPER_SUPPRESS.with(|f| f.set(true));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prove_hll_omc(params, initial.clone(), keys.clone());
        }));
        std::panic::set_hook(prev);
        TAMPER_SUPPRESS.with(|f| f.set(false));
        assert!(
            res.is_err(),
            "max-suppression (unchanged commit) must be rejected"
        );
    }
}
