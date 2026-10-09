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
    generate_poseidon2_trace, generate_range_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d2, poseidon2_preprocessor, range_air_builders, range_preprocessor,
        recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::hiding::{
    self, CommitFamily, CommitKind, CommitMode, OpeningsGl, SaltGl, commit_flat_gl,
};
use crate::config_gl::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::sketch::bind::{self, Binding};
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
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

/// Native register routing under the process default [`Binding`] (the one
/// [`build_hll_omc_leaf`] uses); see [`route_with`].
pub fn route(key: u64, m: usize) -> (usize, u32) {
    route_with(key, m, bind::default_binding())
}

/// Native register routing: `idx = digest[0] mod m`, `ρ = 1 +
/// trailing_zeros(digest[1])` over the `val_bits()` window, digest =
/// `MyHash(bind::key_hash_input(key, binding))` (one Challenge's worth of
/// coefficients): the exact 32-bit limbs `[lo, hi]` under `Semantic`/`Bound`,
/// `[key mod p, 0]` under `Legacy` (so `k` and `k + p` collide there) —
/// mirrors the in-circuit derivation. NOTE: the Goldilocks digest differs from
/// the BabyBear [`super::hll_omc::route_with`], so `hll_gl` register arrays
/// are a distinct (statistically equivalent) HLL instance — chains/forests
/// must not mix fields.
pub fn route_with(key: u64, m: usize, binding: Binding) -> (usize, u32) {
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 4] = hasher.hash_iter(bind::key_hash_input::<Val>(key, binding));
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
/// into its register — exactly the update the leaf proves (process default
/// [`Binding`]) — so the resulting register array feeds the next leaf's
/// `initial` and the boundaries chain.
pub fn hll_omc_advance(regs: &mut [u64], keys: &[u64], m: usize) {
    hll_omc_advance_with(regs, keys, m, bind::default_binding());
}

/// [`hll_omc_advance`] for an explicit [`Binding`] (routing by
/// [`route_with`]).
pub fn hll_omc_advance_with(regs: &mut [u64], keys: &[u64], m: usize, binding: Binding) {
    for &key in keys {
        let (idx, rho) = route_with(key, m, binding);
        regs[idx] = regs[idx].max(rho as u64);
    }
}

/// The batch commitment `Com(B_t)` the Goldilocks omc HLL leaf binds
/// in-circuit (what the public log publishes for the batch). Process default
/// [`Binding`].
pub fn hll_omc_batch_commit(keys: &[u64]) -> [Val; 4] {
    hll_omc_batch_commit_with(keys, bind::default_binding())
}

/// [`hll_omc_batch_commit`] for an explicit [`Binding`]: one Challenge per
/// key, `[lo, hi]` (exact 32-bit limbs) under `Semantic`/`Bound`, `[key mod
/// p, 0]` under `Legacy`.
pub fn hll_omc_batch_commit_with(keys: &[u64], binding: Binding) -> [Val; 4] {
    let hasher = MyHash::new(make_perm());
    let flat: Vec<Val> = keys
        .iter()
        .flat_map(|&k| bind::key_hash_input::<Val>(k, binding))
        .collect();
    hasher.hash_iter(flat.iter().copied())
}

/// [`hll_omc_batch_commit_with`] under a [`CommitMode`] (revision B2,
/// [`crate::commitment::hiding`]): `Plain` is exactly
/// [`hll_omc_batch_commit_with`] (the salt is ignored); `Hiding` is
/// `Com(B_t; salt)` over the same flat key stream (one Challenge per key),
/// the value a `Hiding` leaf opened with `batch = salt` binds.
pub fn hll_omc_batch_commit_salted(keys: &[u64], binding: Binding, mode: CommitMode, salt: &SaltGl) -> [Val; 4] {
    match mode {
        CommitMode::Plain => hll_omc_batch_commit_with(keys, binding),
        CommitMode::Hiding => {
            let flat: Vec<Val> = keys
                .iter()
                .flat_map(|&k| bind::key_hash_input::<Val>(k, binding))
                .collect();
            commit_flat_gl(mode, CommitKind::Batch, CommitFamily::HyperLogLog, salt, &flat)
        }
    }
}

/// `Com(S)` for an HLL/omc register array — the flat Poseidon2 hash over the
/// `m` register values the leaf recomputes in-circuit, so it equals the leaf's
/// `initial_commit`/`final_commit` and anchors the per-batch chain.
pub fn commit_hll_omc(regs: &[u64], _b: usize) -> [Val; 4] {
    let hasher = MyHash::new(make_perm());
    hasher.hash_iter(regs.iter().map(|&r| Val::from_u32(r as u32)))
}

/// [`commit_hll_omc`] under a [`CommitMode`] (revision B2): `Plain` is
/// exactly [`commit_hll_omc`] (the salt is ignored); `Hiding` is
/// `MyHash([TAG_STATE, HyperLogLog, salt_0..salt_5] ‖ registers)` over the
/// same `m` register values ([`commit_flat_gl`]), the value a `Hiding` leaf
/// exposes for `Com(S_t; salt)`. (The family tag separates it from a `d = 1`
/// Count-Min state of the same width.)
pub fn commit_hll_omc_with(regs: &[u64], b: usize, mode: CommitMode, salt: &SaltGl) -> [Val; 4] {
    match mode {
        CommitMode::Plain => commit_hll_omc(regs, b),
        CommitMode::Hiding => {
            let flat: Vec<Val> = regs.iter().map(|&r| Val::from_u32(r as u32)).collect();
            commit_flat_gl(mode, CommitKind::State, CommitFamily::HyperLogLog, salt, &flat)
        }
    }
}

fn commit_regs(regs32: &[u32]) -> GlCommit {
    let hasher = MyHash::new(make_perm());
    GlCommit(hasher.hash_iter(regs32.iter().map(|&c| Val::from_u32(c))))
}

/// [`commit_regs`] under a [`CommitMode`] (the leaf's copy of
/// [`commit_hll_omc_with`] over the `u32` registers it already holds).
fn commit_regs_with(regs32: &[u32], mode: CommitMode, salt: &SaltGl) -> GlCommit {
    match mode {
        CommitMode::Plain => commit_regs(regs32),
        CommitMode::Hiding => {
            let flat: Vec<Val> = regs32.iter().map(|&c| Val::from_u32(c)).collect();
            GlCommit(commit_flat_gl(mode, CommitKind::State, CommitFamily::HyperLogLog, salt, &flat))
        }
    }
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
    b.add_range_bits::<Val>(da, RANK_BITS).expect("max: mx>=a");
    let dbb = b.sub(mx, bb);
    b.add_range_bits::<Val>(dbb, RANK_BITS).expect("max: mx>=bb");
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
    binding: Binding,
    expose: Expose,
    mode: CommitMode,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
}

/// Build the reusable Goldilocks `omc` HLL leaf circuit for a shape.
pub fn build_hll_omc_leaf(params: HllOmcParams, expose_boundary: bool) -> HllOmcLeafCircuit {
    build_hll_omc_leaf_with(params, expose_boundary, bind::default_binding())
}

/// Build the Goldilocks `omc` HLL leaf for a shape and binding.
///
/// [`Binding::Legacy`] is the pre-fix circuit, unchanged. It is unsound:
/// the register and digest decompositions are unbound and the sponge IVs are
/// free. [`Binding::Semantic`] / [`Binding::Bound`] take each key as two
/// exact 32-bit limbs, range-checked and ALU-recomposed into the one Challenge
/// the batch commitment and the routing hash both absorb
/// ([`bind::key_from_limbs`]), so the hashed key is a real 64-bit key, not a
/// grindable extension element and not reduced mod `p` (`Legacy`'s `[key mod
/// p, 0]` routes `k` and `k + p` identically; `tests::congruent_keys_*`), and
/// range-check `idx_sorted[0]` exactly. `Bound` also
/// ALU-binds the register cells (`RANK_BITS` range pins) and both routing
/// digest coefficients (already pinned by their canonical bit
/// decompositions), skips the unused second digest Challenge, and hashes
/// with a zero IV (see [`crate::sketch::bind`]).
pub fn build_hll_omc_leaf_with(
    params: HllOmcParams,
    expose_boundary: bool,
    binding: Binding,
) -> HllOmcLeafCircuit {
    build_hll_omc_leaf_expose(params, Expose::from_bool(expose_boundary), binding)
}

/// Goldilocks `omc` HLL leaf with an explicit composition statement
/// ([`Expose`]); `None` / `Boundary` are byte-for-byte
/// [`build_hll_omc_leaf_with`], `Interval` adds the batch index `t` (last
/// public input) and exposes `(init, final, (t, t), H)`. Plain commitments
/// ([`build_hll_omc_leaf_commit`] with [`CommitMode::Plain`]); prove with
/// [`HllOmcLeafCircuit::prove_epoch_at`].
pub fn build_hll_omc_leaf_expose(
    params: HllOmcParams,
    expose: Expose,
    binding: Binding,
) -> HllOmcLeafCircuit {
    build_hll_omc_leaf_commit(params, expose, binding, CommitMode::Plain)
}

/// [`build_hll_omc_leaf_expose`] with an explicit [`CommitMode`] (revision
/// B2, [`crate::commitment::hiding`]). `Plain` is the pre-B2 circuit byte for
/// byte (same VK). `Hiding` adds 9 private inputs, the salts of
/// `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)` (init, final, batch; three D = 2
/// Challenges each), allocated as the FIRST private inputs, and hashes each
/// commitment as `[tag, salt…, inputs…]`, i.e. [`commit_hll_omc_with`] /
/// [`hll_omc_batch_commit_salted`]. The per-key routing hashes are not
/// commitments and stay unsalted. The salts are witnesses, so the VK does not
/// depend on them; prove with [`HllOmcLeafCircuit::prove_epoch_commit`].
pub fn build_hll_omc_leaf_commit(
    params: HllOmcParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
) -> HllOmcLeafCircuit {
    let expose_boundary = expose == Expose::Boundary;
    params.validate();
    let bound = binding.is_bound();
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
    b.enable_range(generate_range_trace::<Val, Challenge>);
    if expose.exposes() {
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
    // B2: the salts of (init, final, batch) are the FIRST 9 private inputs
    // under `Hiding` ([`OpeningsGl::private_inputs`] order); `Plain`
    // allocates nothing, so its circuit is byte-identical.
    // `alloc_leaf_salts_first` panics if any private input precedes them.
    let salts = crate::recursion::recursive::leaf_gl::alloc_leaf_salts_first(&mut b, mode);
    let init_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    // Legacy: one field element per key (the key mod p). Semantic/Bound: the
    // two exact 32-bit limbs.
    let key_coeff: Vec<ExprId> = if bound {
        Vec::new()
    } else {
        (0..m_batch)
            .map(|_| b.alloc_private_input("key_coeff"))
            .collect()
    };
    let key_limbs: Vec<[ExprId; 2]> = if bound {
        (0..m_batch)
            .map(|_| std::array::from_fn(|_| b.alloc_private_input("key_limb")))
            .collect()
    } else {
        Vec::new()
    };
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
    if let Some(&f0) = final_packed.first() {
        b.tag(f0, "hllgl_final_packed_0").expect("tag");
    }
    // Salted under `Hiding` (`[tag, salt…, inputs…]`); exactly
    // `bind::hash_slice(inputs)` under `Plain`.
    let fam = CommitFamily::HyperLogLog;
    let digest_init = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::State,
        fam,
        salts.as_ref().map(|s| &s.init),
        &init_packed,
        zero,
        binding,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], init_commit_pis[i]);
    }
    let digest_final = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::State,
        fam,
        salts.as_ref().map(|s| &s.final_),
        &final_packed,
        zero,
        binding,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
    }
    let pin_reg = |b: &mut CircuitBuilder<Challenge>, _i: usize, c: ExprId| {
        bind::range_exact::<Val, Challenge>(b, c, RANK_BITS);
    };
    let o_cells: Vec<ExprId> = init_packed
        .iter()
        .flat_map(|&p| bind::decompose::<Val, Challenge>(&mut b, p, binding, bind::no_pin, pin_reg))
        .collect();
    let n_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| bind::decompose::<Val, Challenge>(&mut b, p, binding, bind::no_pin, pin_reg))
        .collect();
    // Keys → one Challenge each (exact limbs under Semantic/Bound); batch
    // commitment over them.
    let keys_t: Vec<ExprId> = if bound {
        key_limbs
            .iter()
            .map(|l| bind::key_from_limbs::<Val, Challenge>(&mut b, l))
            .collect()
    } else {
        (0..m_batch)
            .map(|k| {
                b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_coeff[k], zero])
                    .expect("recompose key")
            })
            .collect()
    };
    if let Some(&k0) = keys_t.first() {
        b.tag(k0, "hllgl_keys_t_0").expect("tag");
    }
    let hb = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::Batch,
        fam,
        salts.as_ref().map(|s| &s.batch),
        &keys_t,
        zero,
        binding,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_commit_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (7th public input) and
    // H = Poseidon2(TAG_LEAF, t, hb), exposed with the boundary.
    if expose.is_interval() {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &cfg,
            &init_commit_pis,
            &final_commit_pis,
            &hb,
            zero,
            binding,
            IndexPin::Range,
        );
    }

    // ── Stage F: per record, derive (idx, ρ) from the key hash → payload ──
    let mut payload = Vec::with_capacity(m_batch);
    for k in 0..m_batch {
        let hashed = bind::hash_slice(&mut b, &cfg, &[keys_t[k]], zero, binding);
        b.connect(hashed[0], key_h0[k]);
        b.connect(hashed[1], key_h1[k]);
        if bound {
            // Coefficient 0 → idx (canonical bits), coefficient 1 → ρ (canonical
            // bits); both pin themselves. The second digest Challenge is unused.
            let mut idx_bits: Vec<ExprId> = Vec::new();
            let mut dbits: Vec<ExprId> = Vec::new();
            let _ = bind::decompose::<Val, Challenge>(
                &mut b,
                key_h0[k],
                binding,
                |b, i, c| {
                    let bits = b.decompose_to_bits::<Val>(c, val_bits()).expect("bits digest");
                    assert_canonical_bits(b, &bits, &canon_pow2, one, zero);
                    if i == 0 {
                        idx_bits = bits;
                    } else {
                        dbits = bits;
                    }
                },
                bind::no_pin,
            );
            let mut idx = zero;
            for j in 0..addr_bits {
                idx = b.mul_add(idx_bits[j], pow2_consts[j], idx);
            }
            let mut acc_zero = b.sub(one, dbits[0]);
            let mut tz = acc_zero;
            for k2 in 1..val_bits() {
                let omb = b.sub(one, dbits[k2]);
                acc_zero = b.mul(acc_zero, omb);
                tz = b.add(tz, acc_zero);
            }
            let rho = b.add(tz, one);
            let packed = b.mul(idx, shift_val_const);
            payload.push(b.add(packed, rho));
            continue;
        }
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
        // Consume the remaining (unused) decompose coeffs: c0[0]=idx, c0[1]=ρ
        // already flow above; c1[0], c1[1] are pinned by the recompose table and
        // just need one ALU lhs each. A self-mul is the cheapest such read
        // (`add(x, 0)` const-folds away and leaves the coeff unconstrained); the
        // old full-width `decompose_to_bits` here was pure waste (RangeAir refactor).
        for idx2 in 0..2 {
            let _ = b.mul(c1[idx2], c1[idx2]);
        }
        let packed = b.mul(idx, shift_val_const);
        payload.push(b.add(packed, rho));
    }

    let payload_sorted = b
        .add_permute(&payload, (0..m_batch).collect::<Vec<_>>())
        .expect("permute reg");
    for r in 0..m_batch {
        // Range-check ρ_sorted < 2^RANK_BITS so idx·2^SHIFT + ρ inverts uniquely.
        b.add_range_bits::<Val>(rho_sorted_w[r], RANK_BITS)
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
        if bound {
            bind::range_exact::<Val, Challenge>(&mut b, idx_sorted_w[0], addr_bits);
        }
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
        // sortedness: gap = idx_sorted[r] − idx_sorted[r-1] ∈ [0, 2^addr_bits),
        // via the byte-table range check. Canonical because addr_bits ≪ field
        // width (a wrapped gap ≈ p would not reconstruct from addr_bits bits).
        let gap = b.sub(idx_sorted_w[r], idx_sorted_w[r - 1]);
        b.add_range_bits::<Val>(gap, addr_bits).expect("gap range");
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
        b.add_range_bits::<Val>(op_old[r], RANK_BITS)
            .expect("op_old range");
        b.add_range_bits::<Val>(acc[r], RANK_BITS).expect("acc range");
        b.add_range_bits::<Val>(op_new[r], RANK_BITS)
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
        b.add_range_bits::<Val>(o_cells[a], RANK_BITS)
            .expect("o_cell range");
        b.add_range_bits::<Val>(n_cells[a], RANK_BITS)
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
    preprocessors.push(range_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d2::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 2>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 2>(1));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 2>(1));
    if expose.exposes() {
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
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8);
    prover.register_recompose_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8.d() != 2);
    prover.register_permute_table::<2>();
    prover.register_range_table::<2>();
    if expose.exposes() {
        prover.register_expose_table::<2>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();

    HllOmcLeafCircuit {
        params,
        binding,
        expose,
        mode,
        batch_index: 1,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
    }
}

type GlEpoch = (Vec<Challenge>, Vec<Challenge>, GlCommit, GlCommit, GlCommit);

impl HllOmcLeafCircuit {
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// The commitment mode the circuit was built with (revision B2).
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }

    /// The VK (preprocessed commitment, `expose_forest_gl::vk_pin_values`
    /// order) of every proof this prebuilt leaf produces, read from its
    /// prover data (public parameters alone, no proving).
    pub fn vk_pin_values(&self) -> Vec<Challenge> {
        crate::recursion::recursive::expose_forest_gl::common_vk_pin_values(
            self.circuit_prover_data.common_data(),
        )
    }

    /// Prove one epoch on the prebuilt circuit. `initial` is the `m` register
    /// values; `keys` is the `params.batch` record keys.
    pub fn prove_epoch(&mut self, initial: Vec<u64>, keys: Vec<u64>) -> HllOmcProof {
        self.prove_epoch_at(1, initial, keys)
    }

    /// The statement this leaf exposes ([`Expose`]).
    pub fn expose(&self) -> Expose {
        self.expose
    }

    /// Prove the epoch of batch `t` (1-based); `t` is part of the Interval
    /// statement (ignored by the other layouts). `Plain` circuits only: on a
    /// `Hiding` circuit this would open every commitment with the public
    /// zero salt, so it panics; use [`Self::prove_epoch_commit`] (or, for
    /// the no-op leaf, [`Self::prove_epoch_public_zero`]).
    pub fn prove_epoch_at(&mut self, t: u64, initial: Vec<u64>, keys: Vec<u64>) -> HllOmcProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             OpeningsGl::for_leaf(..)"
        );
        self.prove_epoch_opened(t, initial, keys, &OpeningsGl::plain())
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`OpeningsGl::for_leaf(seed, CommitFamily::HyperLogLog, t)` for an
    /// honest prover; ignored by a `Plain` circuit). The proof's
    /// `initial_commit`, `final_commit` and `batch_commit` are then the salted
    /// `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)`. A `Hiding` circuit panics
    /// when `openings.final_` or `openings.batch` is the public zero salt
    /// (never an honest PRF output). The init salt may be zero only at `t = 1`
    /// on the empty genesis registers (or the public no-op state `S_noop`)
    /// (leaf 1 of the genesis history opens the public `Com(S_0; 0)`); a zero
    /// init on any other input panics
    /// ([`assert_zero_init_opens_public_state`](crate::commitment::hiding::assert_zero_init_opens_public_state)).
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial: Vec<u64>,
        keys: Vec<u64>,
        openings: &OpeningsGl,
    ) -> HllOmcProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (OpeningsGl::for_leaf), not the public zero salt"
            );
            crate::commitment::hiding::assert_zero_init_opens_public_state(t, openings.init.is_zero(), || {
                let empty = hll_omc_empty(self.params.b);
                let mut noop = empty.clone();
                hll_omc_advance_with(&mut noop, &[1], self.params.m(), self.binding);
                initial == empty || initial == noop
            });
        }
        self.prove_epoch_opened(t, initial, keys, openings)
    }

    /// The no-op VK-derivation leaf's epoch: all three commitments opened
    /// with [`OpeningsGl::public_zero`], so a batch that changes nothing
    /// exposes `init == final` in either mode. The only path that proves a
    /// `Hiding` leaf with zero final/batch salts, so (like the BabyBear
    /// leaf's) it accepts exactly the public no-op input
    /// ([`hll_omc_gl_noop_leaf_commit`]): batch index `t = 1`, `initial` is
    /// key 1 inserted into empty registers (under this leaf's binding) and
    /// every key is 1 (the `t` check comes last). "The
    /// batch leaves the registers unchanged" alone would not do for HLL: a
    /// real batch of repeated keys often raises nothing, and would then
    /// publish the deterministic (guess-checkable) commitments of a secret
    /// state and of real keys. Input checks only (circuit and VK unchanged),
    /// in both modes.
    pub fn prove_epoch_public_zero(&mut self, t: u64, initial: Vec<u64>, keys: Vec<u64>) -> HllOmcProof {
        let mut after = initial.clone();
        hll_omc_advance_with(&mut after, &keys, self.params.m(), self.binding);
        assert!(
            after == initial,
            "prove_epoch_public_zero is for the no-op leaf: the batch must not change the registers"
        );
        let mut noop = hll_omc_empty(self.params.b);
        hll_omc_advance_with(&mut noop, &[1], self.params.m(), self.binding);
        assert!(
            initial == noop && keys.iter().all(|&k| k == 1),
            "prove_epoch_public_zero is for the no-op leaf: the public no-op input only (initial = key 1 \
             in empty registers, every key 1)"
        );
        assert_eq!(t, 1, "prove_epoch_public_zero is for the no-op leaf: it is proved at batch index 1");
        self.prove_epoch_opened(t, initial, keys, &OpeningsGl::public_zero())
    }

    /// Shared body of the three `prove_epoch_*` entry points (no opening
    /// checks).
    fn prove_epoch_opened(
        &mut self,
        t: u64,
        initial: Vec<u64>,
        keys: Vec<u64>,
        openings: &OpeningsGl,
    ) -> HllOmcProof {
        self.batch_index = t;
        let params = self.params;
        let __t_w = std::time::Instant::now();
        let (traces, (_, _, initial_commit, final_commit, batch_commit)) =
            self.run_epoch_commit(initial, keys, openings);
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

    /// Run the circuit on one epoch's witness; returns the traces and inputs.
    #[allow(dead_code)] // test-only since B2: the prove paths run `run_epoch_commit`
    fn run_epoch(&mut self, initial: Vec<u64>, keys: Vec<u64>) -> (p3_circuit::tables::Traces<Challenge>, GlEpoch) {
        self.run_epoch_commit(initial, keys, &OpeningsGl::plain())
    }

    /// [`Self::run_epoch`] with explicit commitment openings (ignored under
    /// `Plain`).
    fn run_epoch_commit(
        &mut self,
        initial: Vec<u64>,
        keys: Vec<u64>,
        openings: &OpeningsGl,
    ) -> (p3_circuit::tables::Traces<Challenge>, GlEpoch) {
        let ep = self.epoch(initial, keys, openings);
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&ep.0).expect("set pubs");
            runner.set_private_inputs(&ep.1).expect("set privs");
            runner.run().expect("run hll_omc_gl")
        };
        (traces, ep)
    }

    /// Prove + self-verify arbitrary traces of this circuit.
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

    /// Native side of one epoch + runner inputs (swaps the permutation hints).
    /// `openings` are the commitment salts (ignored under `Plain`).
    fn epoch(&mut self, initial: Vec<u64>, keys: Vec<u64>, openings: &OpeningsGl) -> GlEpoch {
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
        let binding = self.binding;
        for (k, &key) in keys.iter().enumerate() {
            let (i, r) = route_with(key, m, binding);
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
        let mode = self.mode;
        let initial_commit = commit_regs_with(&init_regs, mode, &openings.init);
        let final_commit = commit_regs_with(&committed_final_regs, mode, &openings.final_);

        // Batch commitment over the keys (one Challenge each).
        let batch_commit: GlCommit = GlCommit(hll_omc_batch_commit_salted(&keys, binding, mode, &openings.batch));

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
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            // The salts come first (see `build_hll_omc_leaf_commit`).
            private_inputs.extend(openings.private_inputs());
        }
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&init_regs));
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&committed_final_regs));
        if binding.is_bound() {
            for &k in &keys {
                private_inputs.extend(bind::key_limbs::<Val>(k).into_iter().map(Challenge::from));
            }
        } else {
            for &k in &keys {
                private_inputs.push(Challenge::from_u64(k));
            }
        }
        let digests: Vec<[Val; 4]> = {
            let hasher = MyHash::new(make_perm());
            keys.iter()
                .map(|&k| hasher.hash_iter(bind::key_hash_input::<Val>(k, binding)))
                .collect()
        };
        for digest in &digests {
            private_inputs.push(
                Challenge::from_basis_coefficients_slice(&digest[0..2]).expect("2 coeffs"),
            );
        }
        for digest in &digests {
            private_inputs.push(
                Challenge::from_basis_coefficients_slice(&digest[2..4]).expect("2 coeffs"),
            );
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

        (public_inputs, private_inputs, initial_commit, final_commit, batch_commit)
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

/// [`prove_hll_omc`] / [`prove_hll_omc_exposed`] with an explicit [`Binding`].
pub fn prove_hll_omc_with(
    params: HllOmcParams,
    initial: Vec<u64>,
    keys: Vec<u64>,
    expose_boundary: bool,
    binding: Binding,
) -> HllOmcProof {
    build_hll_omc_leaf_with(params, expose_boundary, binding).prove_epoch(initial, keys)
}

/// Public **no-op leaf** of the Goldilocks `omc` HLL leaf for root-VK
/// derivation (the Goldilocks counterpart of
/// `noop_leaf::hll_omc_noop_leaf_expose`): every record re-inserts key 1
/// into a state that already holds it (`max` is idempotent; the stream
/// harness's HLL no-op), proved at batch index 1 through the explicit
/// zero-salt path ([`HllOmcLeafCircuit::prove_epoch_public_zero`], all three
/// salts [`OpeningsGl::public_zero`]), so it exposes `init == final` in
/// either mode. The salts and the index are witnesses, so its VK is that of
/// every real leaf of the same parameters and mode.
pub fn hll_omc_gl_noop_leaf_commit(
    params: HllOmcParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
) -> p3_circuit_prover::BatchStarkProof<ConfigWithFriParams> {
    let mut regs = hll_omc_empty(params.b);
    hll_omc_advance_with(&mut regs, &[1], params.m(), binding);
    build_hll_omc_leaf_commit(params, expose, binding, mode)
        .prove_epoch_public_zero(1, regs, vec![1; params.batch])
        .output
        .0
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

    /// Native max-fold reference for the final register array (process
    /// default binding, as `prove_hll_omc` uses).
    fn native_final(b: usize, initial: &[u64], keys: &[u64]) -> Vec<u32> {
        native_final_with(b, initial, keys, bind::default_binding())
    }

    /// [`native_final`] with `binding`'s routing.
    fn native_final_with(b: usize, initial: &[u64], keys: &[u64], binding: Binding) -> Vec<u32> {
        let m = 1usize << b;
        let mut regs: Vec<u32> = initial.iter().map(|&x| x as u32).collect();
        for &k in keys {
            let (idx, rho) = route_with(k, m, binding);
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

    // ── Binding (see `crate::sketch::bind`): legacy-vs-bound forgery tests ──

    use crate::sketch::forge;
    use p3_circuit::ops::{NpoTypeId, Poseidon2Trace};

    const FP: HllOmcParams = HllOmcParams { b: 3, batch: 4 };
    const FP_KEYS: [u64; 4] = [7, 11, 13, 17];

    fn fp_prior() -> Vec<u64> {
        let mut prior = vec![0u64; FP.m()];
        hll_omc_advance(&mut prior, &[101, 202, 303], FP.m());
        prior
    }

    fn cfg() -> Poseidon2Config {
        Poseidon2Config::GOLDILOCKS_D2_W8
    }

    /// Honest epochs verify under every binding and certify that binding's
    /// native model (register fold and batch commitment); 64-bit keys use
    /// both exact limbs.
    #[test]
    fn omc_gl_round_trip_all_bindings() {
        let mut keys = FP_KEYS.to_vec();
        keys[3] = 0xFEDC_BA98_7654_3210;
        for binding in [Binding::Bound, Binding::Semantic, Binding::Legacy] {
            let expect = native_final_with(FP.b, &fp_prior(), &keys, binding);
            let r = prove_hll_omc_with(FP, fp_prior(), keys.clone(), true, binding);
            assert_eq!(r.final_commit.0, commit_regs(&expect).0, "{binding:?}");
            assert_eq!(r.batch_commit.0, hll_omc_batch_commit_with(&keys, binding));
        }
    }

    /// First `k ≥ 12_345` whose congruent twin `k + p` (Goldilocks `p = 2^64 −
    /// 2^32 + 1`, both u64) lands in a DIFFERENT register under the exact-limb
    /// encoding.
    fn congruent_pair(m: usize) -> (u64, u64) {
        let p = <Val as PrimeField64>::ORDER_U64;
        (12_345u64..)
            .map(|k| (k, k + p))
            .find(|&(k, t)| route_with(k, m, Binding::Semantic).0 != route_with(t, m, Binding::Semantic).0)
            .expect("a separated pair")
    }

    /// Native routing: `Legacy` hashes `[key mod p, 0]`, so `k` and `k + p`
    /// share register, rank and batch commitment (the documented control);
    /// `Semantic`/`Bound` hash the exact 32-bit limbs and separate them.
    #[test]
    fn congruent_keys_native_routing() {
        let m = 1usize << 10;
        let (k, t) = congruent_pair(m);
        assert_eq!(route_with(k, m, Binding::Legacy), route_with(t, m, Binding::Legacy));
        assert_eq!(
            hll_omc_batch_commit_with(&[k], Binding::Legacy),
            hll_omc_batch_commit_with(&[t], Binding::Legacy)
        );
        for binding in [Binding::Semantic, Binding::Bound] {
            assert_ne!(route_with(k, m, binding), route_with(t, m, binding));
            assert_ne!(hll_omc_batch_commit_with(&[k], binding), hll_omc_batch_commit_with(&[t], binding));
        }
    }

    /// Proof level: one batch `[k, k + p]` into empty registers. `Legacy`
    /// certifies one raised register (the documented control),
    /// `Semantic`/`Bound` two.
    #[test]
    fn congruent_keys_legacy_collide_semantic_bound_separate() {
        let params = HllOmcParams { b: 10, batch: 2 };
        let (k, t) = congruent_pair(params.m());
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let expect = native_final_with(params.b, &vec![0; params.m()], &[k, t], binding);
            let r = prove_hll_omc_with(params, vec![0; params.m()], vec![k, t], true, binding);
            assert_eq!(r.final_commit.0, commit_regs(&expect).0, "{binding:?}");
            let raised = expect.iter().filter(|&&x| x > 0).count();
            assert_eq!(raised, if binding.is_bound() { 2 } else { 1 }, "{binding:?}");
        }
    }

    /// FORGED FINAL STATE (transplant): recommit the first packed register
    /// Challenge with register 0 raised by one, rehash.
    fn forged_final(binding: Binding) -> bool {
        forge::accepted_with_control(&format!("hll_gl forged final ({binding:?})"), |f| {
            forged_final_run(binding, f)
        })
    }

    fn forged_final_run(binding: Binding, forge_it: bool) -> bool {
        let mut leaf = build_hll_omc_leaf_with(FP, true, binding);
        let (mut traces, _) = leaf.run_epoch(fp_prior(), FP_KEYS.to_vec());
        let mut forged = native_final_with(FP.b, &fp_prior(), &FP_KEYS, binding);
        if forge_it {
            forged[0] += 1;
        }
        let w = traces.tag_to_witness["hllgl_final_packed_0"];
        forge::set_wid::<Val, Challenge>(&mut traces, w, pack_cells_to_challenge(&forged)[0]);
        forge::rehash_all::<Val, Challenge, _, 8>(&mut traces, cfg(), &make_perm());
        forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
    }

    /// FREE SPONGE IV on record 0's routing hash (the last `new_start` row
    /// reading `keys_t[0]`; capacity limb 2 = base 4).
    fn forged_iv(binding: Binding) -> bool {
        forge::accepted_with_control(&format!("hll_gl forged IV ({binding:?})"), |f| {
            forged_iv_run(binding, f)
        })
    }

    fn forged_iv_run(binding: Binding, forge_it: bool) -> bool {
        let mut leaf = build_hll_omc_leaf_with(FP, true, binding);
        let (mut traces, _) = leaf.run_epoch(fp_prior(), FP_KEYS.to_vec());
        let k0 = traces.tag_to_witness["hllgl_keys_t_0"].0;
        let key = NpoTypeId::poseidon2_perm(cfg());
        let mut pt = traces.non_primitive_trace::<Poseidon2Trace<Val>>(&key).expect("p2").clone();
        let row = pt
            .operations
            .iter_mut()
            .filter(|r| r.new_start && r.in_ctl[0] && r.input_indices[0] == k0)
            .last()
            .expect("record 0 routing hash row");
        if forge_it {
            row.input_values[4] += Val::ONE;
        }
        traces.non_primitive_traces.insert(key, Box::new(pt));
        forge::rehash_all::<Val, Challenge, _, 8>(&mut traces, cfg(), &make_perm());
        forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
    }

    #[test]
    fn forged_final_state_legacy_accepts_bound_rejects() {
        if !bind::probe::fork_binds_decompose() {
            assert!(forged_final(Binding::Legacy), "Legacy accepts the forged final (PoC)");
        }
        assert!(!forged_final(Binding::Bound), "Bound must reject the forged final");
        // Merged soundness fork: the fork itself binds decompose coefficients, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if bind::probe::fork_binds_decompose() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(!forged_final(b), "fork binds decompose coefficients: {b:?} must reject too");
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

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────
    //
    // The hiding module's randomizer PRF is imported under salt names here
    // (`rho` is the HLL rank in this file).

    use crate::commitment::hiding::{
        SaltSeed, rho_batch_gl as batch_salt, rho_batch_gl_in as batch_salt_in,
        rho_state_gl as state_salt, rho_state_gl_in as state_salt_in,
    };
    use crate::recursion::recursive::expose_forest_gl::{
        batch_log, check_leaves_against_log, check_root_against_log, prove_hiding_merge,
        read_exposed_boundary_proof, read_exposed_statement, root_vk_deriver,
        verify_bound_stark_proof_against_log, vk_pin_values,
    };
    use crate::recursion::recursive::leaf_gl::hiding_probe::{
        leaked_salts, proof_alu_rows, trace_rows, vk_flat, vk_literal,
    };
    use crate::recursion::recursive::root_vk::ForestShape;
    use crate::recursion::recursive::statement::{hash_gl, leaf_digest};

    const HP: HllOmcParams = HllOmcParams { b: 3, batch: 4 };
    const HLL: CommitFamily = CommitFamily::HyperLogLog;

    fn hiding_leaf(binding: Binding) -> HllOmcLeafCircuit {
        build_hll_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding)
    }

    /// `regs` advanced by `keys` under `binding`'s routing.
    fn advanced(regs: &[u64], keys: &[u64], binding: Binding) -> Vec<u64> {
        let mut r = regs.to_vec();
        hll_omc_advance_with(&mut r, keys, HP.m(), binding);
        r
    }

    fn hp_prior(binding: Binding) -> Vec<u64> {
        advanced(&hll_omc_empty(HP.b), &[5, 9], binding)
    }

    fn hp_batches() -> Vec<Vec<u64>> {
        vec![vec![7, 11, 13, 7], vec![19, 7, 23, 29]]
    }

    /// Native drift guard: `Plain` is the pre-B2 commitment whatever the
    /// salt (both the public `commit_hll_omc` and the leaf's private
    /// `commit_regs`); `Hiding` is `MyHash([TAG_STATE | TAG_BATCH,
    /// HyperLogLog, salt…] ‖ flat)` over exactly the pre-B2 flat stream, and
    /// the family tag separates an HLL state from a `d = 1` Count-Min state
    /// with the same cells.
    #[test]
    fn commit_with_modes() {
        use crate::commitment::hiding::{TAG_BATCH, TAG_STATE};
        use crate::sketch::countmin_omc_gl::commit_countmin_with;
        let seed = SaltSeed::for_tests(9);
        let (s1, s2) = (state_salt(&seed, HLL, 1), state_salt(&seed, HLL, 2));
        let regs = hp_prior(Binding::Semantic);
        let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
        assert_eq!(commit_hll_omc_with(&regs, HP.b, CommitMode::Plain, &s1), commit_hll_omc(&regs, HP.b));
        assert_eq!(commit_regs_with(&regs32, CommitMode::Plain, &s1), commit_regs(&regs32));
        let mut input = vec![Val::from_u64(TAG_STATE), Val::from_u64(HLL.id())];
        input.extend_from_slice(&s1.0);
        input.extend(regs.iter().map(|&r| Val::from_u64(r)));
        let want: [Val; 4] = MyHash::new(make_perm()).hash_iter(input);
        let h1 = commit_hll_omc_with(&regs, HP.b, CommitMode::Hiding, &s1);
        assert_eq!(h1, want, "state layout drift");
        assert_eq!(commit_regs_with(&regs32, CommitMode::Hiding, &s1).0, h1);
        assert_ne!(h1, commit_hll_omc_with(&regs, HP.b, CommitMode::Hiding, &s2));
        assert_ne!(h1, commit_hll_omc(&regs, HP.b));
        // The same cells as a d = 1 Count-Min state: equal Plain digests (the
        // pre-B2 collision), separated by the family tag under Hiding.
        let cm = crate::sketch::countmin::CountMinState {
            counters: vec![regs32.clone()],
            params: crate::sketch::countmin::CountMinParams { d: 1, w: HP.m() },
        };
        assert_eq!(crate::sketch::countmin_omc_gl::commit_countmin(&cm).0, commit_hll_omc(&regs, HP.b));
        assert_ne!(commit_countmin_with(&cm, CommitMode::Hiding, &s1).0, h1, "family tags separate");
        let sb = batch_salt(&seed, HLL, 1);
        let keys = hp_batches()[0].clone();
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            assert_eq!(
                hll_omc_batch_commit_salted(&keys, binding, CommitMode::Plain, &sb),
                hll_omc_batch_commit_with(&keys, binding)
            );
            let mut input = vec![Val::from_u64(TAG_BATCH), Val::from_u64(HLL.id())];
            input.extend_from_slice(&sb.0);
            input.extend(keys.iter().flat_map(|&k| bind::key_hash_input::<Val>(k, binding)));
            let want: [Val; 4] = MyHash::new(make_perm()).hash_iter(input);
            let hb = hll_omc_batch_commit_salted(&keys, binding, CommitMode::Hiding, &sb);
            assert_eq!(hb, want, "{binding:?}: batch layout drift");
            assert_ne!(hb, hll_omc_batch_commit_with(&keys, binding), "{binding:?}");
        }
    }

    /// (1) A hiding leaf's commitments (the proof's `initial/final/batch`
    /// fields and the exposed Interval statement) equal the NATIVE hiding
    /// commitments under the leaf-`t` openings, under every binding; the
    /// Boundary layout exposes the hiding pair too.
    #[test]
    fn hiding_leaf_exposes_native_hiding_commitments() {
        let seed = SaltSeed::for_tests(21);
        let t = 3u64;
        let keys = hp_batches()[0].clone();
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut leaf = hiding_leaf(binding);
            assert_eq!(leaf.commit_mode(), CommitMode::Hiding);
            let prior = hp_prior(binding);
            let r = leaf.prove_epoch_commit(t, prior.clone(), keys.clone(), &OpeningsGl::for_leaf(&seed, HLL, t));
            let expect = advanced(&prior, &keys, binding);
            let init = commit_hll_omc_with(&prior, HP.b, CommitMode::Hiding, &state_salt(&seed, HLL, t - 1));
            let fin = commit_hll_omc_with(&expect, HP.b, CommitMode::Hiding, &state_salt(&seed, HLL, t));
            let bc = hll_omc_batch_commit_salted(&keys, binding, CommitMode::Hiding, &batch_salt(&seed, HLL, t));
            assert_eq!(r.initial_commit.0, init, "{binding:?}");
            assert_eq!(r.final_commit.0, fin, "{binding:?}");
            assert_eq!(r.batch_commit.0, bc, "{binding:?}");
            assert_ne!(init, commit_hll_omc(&prior, HP.b), "{binding:?}: hiding != plain");
            assert_ne!(fin, commit_hll_omc(&expect, HP.b), "{binding:?}: hiding != plain");
            assert_ne!(bc, hll_omc_batch_commit_with(&keys, binding), "{binding:?}: hiding != plain");
            let st = read_exposed_statement(&r.output.0);
            assert_eq!(st.init, init.to_vec(), "{binding:?}");
            assert_eq!(st.final_, fin.to_vec(), "{binding:?}");
            let iv = st.interval.expect("interval layout");
            assert_eq!((iv.lo, iv.hi), (Val::from_u64(t), Val::from_u64(t)));
            assert_eq!(iv.digest, leaf_digest(&hash_gl, 2, t, &bc), "{binding:?}: H(TAG_LEAF, t, Com(B_t; salt))");
        }
        // Boundary layout, leaf 1 of the genesis history from the empty S_0
        // (its zero init salt opens only that public state).
        for binding in [Binding::Semantic, Binding::Legacy] {
            let mut bleaf = build_hll_omc_leaf_commit(HP, Expose::Boundary, binding, CommitMode::Hiding);
            let prior = hll_omc_empty(HP.b);
            let r = bleaf.prove_epoch_commit(1, prior.clone(), keys.clone(), &OpeningsGl::for_leaf(&seed, HLL, 1));
            let (i, f) = read_exposed_boundary_proof(&r.output.0);
            assert_eq!(i.0, commit_hll_omc_with(&prior, HP.b, CommitMode::Hiding, &SaltGl::ZERO), "{binding:?}");
            assert_eq!(f, r.final_commit, "{binding:?}");
            let fin = advanced(&prior, &keys, binding);
            assert_eq!(f.0, commit_hll_omc_with(&fin, HP.b, CommitMode::Hiding, &state_salt(&seed, HLL, 1)));
        }
    }

    /// (2) The hiding leaf's VK does not depend on the salts (two different
    /// openings, and the zero-salt no-op leaf, give one VK), differs from the
    /// Plain VK, and the Plain circuit is the pre-B2 circuit: its VK equals
    /// the value recorded on the unmodified Goldilocks leaf (b2-hiding
    /// @94e9f58), through both the old builder and
    /// `build_hll_omc_leaf_commit(.., Plain)`, for every layout and binding.
    #[test]
    fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
        #[cfg(not(feature = "zk"))]
        let recorded = [
            (Expose::None, Binding::Legacy, [14168919388163267691, 14460048179212378628, 8910995631445728004, 15256646160871894868]),
            (Expose::None, Binding::Semantic, [11499029830929027002, 952261770204596331, 14617706948556334579, 5938851537768499731]),
            (Expose::None, Binding::Bound, [813484156469277899, 8183806348160860546, 17654867415947999660, 12531779750251986898]),
            (Expose::Boundary, Binding::Legacy, [15543137933915619559, 18139362217733167749, 12155153133407480564, 8127256034025869025]),
            (Expose::Boundary, Binding::Semantic, [5138130978998227796, 7067718375919704150, 13912666147390980263, 6321985076559359309]),
            (Expose::Boundary, Binding::Bound, [13782179169350075207, 12056932387851708703, 2236995706214631902, 4354521716714807773]),
            (Expose::Interval, Binding::Legacy, [14669599425293956236, 16341529921799257724, 3702582242897993872, 14699538780081726645]),
            (Expose::Interval, Binding::Semantic, [10507600970848577520, 12831808682093879075, 14828731557621822660, 9751981943810625564]),
            (Expose::Interval, Binding::Bound, [705249840634679929, 2970675906437864458, 18350968471023740034, 18034393421210718204]),
        ];
        // The same circuits under the `zk` feature (hiding PCS, ZK LogUp masks):
        // recorded on the zk-logup-mask forks (Plonky3 280b1a07, Plonky3_RangeAir
        // 3acdc06); equal across separate processes.
        #[cfg(feature = "zk")]
        let recorded = [
            (Expose::None, Binding::Legacy, [12843633197085160025, 1973246844554064726, 10115236069762327301, 1839186298692920541]),
            (Expose::None, Binding::Semantic, [17149106072649584078, 3213173757015386923, 5514794797752986343, 734955693792738847]),
            (Expose::None, Binding::Bound, [13655316104553688434, 4277497990887388895, 3513359456177223169, 1227831705505133851]),
            (Expose::Boundary, Binding::Legacy, [10400147223916106891, 9985631918361231737, 18278563724178953343, 16076730326068749976]),
            (Expose::Boundary, Binding::Semantic, [10628986860418130623, 248974971472835638, 8063241438019367872, 9712733251898176963]),
            (Expose::Boundary, Binding::Bound, [10637519388640979750, 10158719310969828686, 14304558720825130073, 10020669626151510138]),
            (Expose::Interval, Binding::Legacy, [2725765967471395645, 8772019563160574572, 2112950665198605864, 8390733671217434290]),
            (Expose::Interval, Binding::Semantic, [14976669043194114096, 10672772107355373239, 18020997587345258397, 5284501358491283267]),
            (Expose::Interval, Binding::Bound, [1077786934167096079, 16706272757113618578, 12763520485174343776, 1786286342386896936]),
        ];
        for (expose, binding, vk) in recorded {
            let old = build_hll_omc_leaf_expose(HP, expose, binding).vk_pin_values();
            let plain = build_hll_omc_leaf_commit(HP, expose, binding, CommitMode::Plain).vk_pin_values();
            assert_eq!(vk_flat(&old), vk_literal(vk), "{expose:?}/{binding:?}: Plain VK drifted from the pre-B2 leaf");
            assert_eq!(plain, old, "{expose:?}/{binding:?}");
            let hid = build_hll_omc_leaf_commit(HP, expose, binding, CommitMode::Hiding).vk_pin_values();
            assert_ne!(hid, old, "{expose:?}/{binding:?}: the hiding circuit differs");
        }
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = hiding_leaf(binding);
            let vk = leaf.vk_pin_values();
            let keys = hp_batches()[0].clone();
            let o1 = OpeningsGl::for_leaf(&SaltSeed::for_tests(1), HLL, 1);
            let o5 = OpeningsGl::for_leaf(&SaltSeed::for_tests(2), HLL, 5);
            // Leaf 1 starts from the empty S_0 (its zero init salt opens only
            // that public state); leaf 5 from a real prior.
            let a = leaf.prove_epoch_commit(1, hll_omc_empty(HP.b), keys.clone(), &o1);
            let b = leaf.prove_epoch_commit(5, hp_prior(binding), keys, &o5);
            assert_ne!(a.final_commit, b.final_commit);
            assert_eq!(vk_pin_values(&a.output.0), vk, "{binding:?}");
            assert_eq!(vk_pin_values(&b.output.0), vk, "{binding:?}");
            let noop = hll_omc_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
            assert_eq!(vk_pin_values(&noop), vk, "{binding:?}: the zero-salt no-op leaf has the real leaves' VK");
        }
    }

    /// (2b) The Hiding leaf's VK is pinned, one literal per statement layout and binding.
    /// It does not depend on the salts (test (2)), so it is a fixed value per
    /// shape; recorded on b2-gl @77a02a3. The pin guards what the other
    /// tests only compare against the native functions, which would carry the
    /// same change: which sponge each salted commitment uses, the
    /// `(kind, HyperLogLog)` tag constants, and the salt allocation order.
    /// Under `Bound` the three salted sponges are the zero-IV bound sponge
    /// (`hash_slice_bound`); a Hiding leaf that fell back to the plain sponge
    /// there keeps its row counts and still matches the native `_with`
    /// functions, so only this pin sees it.
    #[test]
    fn hiding_leaf_vk_is_pinned() {
        #[cfg(not(feature = "zk"))]
        let recorded = [
            (Expose::None, Binding::Legacy, [9020287199632471132, 4922640300835232299, 6545664025718793889, 16708064044724174711]),
            (Expose::None, Binding::Semantic, [16676829244106536675, 7186883655321923827, 7030534363062251864, 3279728442841506886]),
            (Expose::None, Binding::Bound, [3612063495855129343, 11975865296845562783, 4356664480343767723, 1742447526026485940]),
            (Expose::Boundary, Binding::Legacy, [478692673385797063, 9835345290699689723, 17957644977397044213, 2418480954263820918]),
            (Expose::Boundary, Binding::Semantic, [13832337578725166954, 10137499088671747806, 1255461744675994764, 15138686581792200521]),
            (Expose::Boundary, Binding::Bound, [7159761428616114914, 9102334846850709283, 2608971208970966697, 5004193696937718827]),
            (Expose::Interval, Binding::Legacy, [12682436709770012897, 17765918685796911134, 9764386592423390210, 17028952910073436610]),
            (Expose::Interval, Binding::Semantic, [7723533189676974475, 2704071495339774341, 2715990335894637200, 11753830400438177939]),
            (Expose::Interval, Binding::Bound, [11527054926566344460, 3907425700823126067, 8490328091609986456, 16436418461637429624]),
        ];
        // The same circuits under the `zk` feature (hiding PCS, ZK LogUp masks):
        // recorded on the zk-logup-mask forks (Plonky3 280b1a07, Plonky3_RangeAir
        // 3acdc06); equal across separate processes.
        #[cfg(feature = "zk")]
        let recorded = [
            (Expose::None, Binding::Legacy, [1060066494264781902, 2864682081814860394, 442020378394646386, 12505018517506870987]),
            (Expose::None, Binding::Semantic, [1227849124213491052, 13973643989405887027, 9114888084066537111, 10167589689063649288]),
            (Expose::None, Binding::Bound, [7949040825910014685, 13836263201141873930, 8196240963165780358, 11068931954918414438]),
            (Expose::Boundary, Binding::Legacy, [16516203131505752699, 10847811354169506729, 6980063389444128213, 2376492755754048800]),
            (Expose::Boundary, Binding::Semantic, [9032029471902953080, 12731224046628185720, 15531265860298768780, 7238891196635346050]),
            (Expose::Boundary, Binding::Bound, [7669746267685604878, 15939240087022082401, 11301853757721397422, 14210135854534823754]),
            (Expose::Interval, Binding::Legacy, [15251023697127359713, 15187859359075680481, 16228464834449041078, 5741590290874913996]),
            (Expose::Interval, Binding::Semantic, [7001983067262644209, 696150212661417443, 138483124316188683, 9058426969602764981]),
            (Expose::Interval, Binding::Bound, [7029719668439341613, 14735731503025159210, 15548973866860472885, 715458863828805765]),
        ];
        for (expose, binding, vk) in recorded {
            let hid = build_hll_omc_leaf_commit(HP, expose, binding, CommitMode::Hiding).vk_pin_values();
            assert_eq!(vk_flat(&hid), vk_literal(vk), "{expose:?}/{binding:?}: Hiding VK drifted");
        }
    }

    /// (3) Equal states at two versions get different hiding commitments,
    /// both different from the plain one; at the proof level, two no-op
    /// leaves (every key already at its register's rank) at `t = 1, 2` from
    /// the public no-op state `S_noop` (leaf 1's zero init salt opens only a
    /// public state) expose `Com(S; 0) → Com(S; salt_1) → Com(S; salt_2)`:
    /// three distinct values for one state, chained.
    #[test]
    fn equal_states_get_unlinkable_hiding_commitments() {
        let binding = Binding::Semantic;
        let seed = SaltSeed::for_tests(33);
        let s = hp_prior(binding);
        let (s1, s2) = (state_salt(&seed, HLL, 1), state_salt(&seed, HLL, 2));
        let (c1, c2) = (
            commit_hll_omc_with(&s, HP.b, CommitMode::Hiding, &s1),
            commit_hll_omc_with(&s, HP.b, CommitMode::Hiding, &s2),
        );
        assert_ne!(c1, c2);
        assert_ne!(c1, commit_hll_omc(&s, HP.b));
        assert_ne!(c2, commit_hll_omc(&s, HP.b));
        assert_eq!(commit_hll_omc_with(&s, HP.b, CommitMode::Plain, &s1), commit_hll_omc(&s, HP.b));

        let s = advanced(&hll_omc_empty(HP.b), &[1], binding);
        let (c1, c2) = (
            commit_hll_omc_with(&s, HP.b, CommitMode::Hiding, &s1),
            commit_hll_omc_with(&s, HP.b, CommitMode::Hiding, &s2),
        );
        let same = vec![1u64; HP.batch];
        assert_eq!(advanced(&s, &same, binding), s, "re-inserting present keys moves nothing");
        let mut leaf = hiding_leaf(binding);
        let l1 = leaf.prove_epoch_commit(1, s.clone(), same.clone(), &OpeningsGl::for_leaf(&seed, HLL, 1));
        let l2 = leaf.prove_epoch_commit(2, s.clone(), same, &OpeningsGl::for_leaf(&seed, HLL, 2));
        let (t1, t2) = (read_exposed_statement(&l1.output.0), read_exposed_statement(&l2.output.0));
        assert_eq!(t1.init, commit_hll_omc_with(&s, HP.b, CommitMode::Hiding, &SaltGl::ZERO).to_vec());
        assert_eq!(t1.final_, c1.to_vec());
        assert_eq!(t2.init, t1.final_, "leaf 2 opens Com(S_1) with the same salt");
        assert_eq!(t2.final_, c2.to_vec());
        assert_ne!(t1.init, t1.final_, "the state did not move, the commitment did");
        assert_ne!(t2.init, t2.final_);
    }

    /// (4) Binding in Hiding mode, through the auditor paths: an honest
    /// 2-leaf forest passes the per-batch log check and its root verifies
    /// against the log under the root VK derived from the zero-salt no-op
    /// leaf; another seed's log, a wrong batch salt and a wrong final salt
    /// are rejected; an inconsistent salt across the leaf boundary cannot be
    /// merged.
    #[test]
    fn wrong_salt_rejected_by_log_and_inconsistent_salt_breaks_merge() {
        let binding = Binding::Semantic;
        let (a, b) = (SaltSeed::for_tests(41), SaltSeed::for_tests(42));
        let bs = hp_batches();
        let s0 = hll_omc_empty(HP.b);
        let s1 = advanced(&s0, &bs[0], binding);
        let s2 = advanced(&s1, &bs[1], binding);
        let log_for = |seed: &SaltSeed| {
            let bc: Vec<[Val; 4]> = (0..2)
                .map(|k| hll_omc_batch_commit_salted(&bs[k], binding, CommitMode::Hiding, &batch_salt(seed, HLL, k as u64 + 1)))
                .collect();
            batch_log(
                &commit_hll_omc_with(&s0, HP.b, CommitMode::Hiding, &SaltGl::ZERO),
                &commit_hll_omc_with(&s2, HP.b, CommitMode::Hiding, &state_salt(seed, HLL, 2)),
                &bc,
            )
        };
        let (log_a, log_b) = (log_for(&a), log_for(&b));
        let mut leaf = hiding_leaf(binding);
        let l1 = leaf.prove_epoch_commit(1, s0.clone(), bs[0].clone(), &OpeningsGl::for_leaf(&a, HLL, 1)).output;
        let l2 = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &OpeningsGl::for_leaf(&a, HLL, 2)).output;
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log_a, Expose::Interval), Ok(()));
        assert!(check_leaves_against_log(&[&l1.0, &l2.0], &log_b, Expose::Interval).is_err(), "another seed's log");

        let bad_batch = OpeningsGl { batch: batch_salt(&b, HLL, 2), ..OpeningsGl::for_leaf(&a, HLL, 2) };
        let l2b = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_batch).output;
        let e = check_leaves_against_log(&[&l1.0, &l2b.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("digest")), "{e:?}");
        let bad_final = OpeningsGl { final_: state_salt(&b, HLL, 2), ..OpeningsGl::for_leaf(&a, HLL, 2) };
        let l2f = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_final).output;
        let e = check_leaves_against_log(&[&l1.0, &l2f.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("Com(S_T)")), "{e:?}");

        let shape = ForestShape::forest(2);
        let root = prove_hiding_merge(&l1, &l2);
        let noop = hll_omc_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
        let vk = root_vk_deriver(noop).root_vk(&shape);
        verify_bound_stark_proof_against_log(&root.0, &vk, &log_a, &shape);
        assert!(check_root_against_log(&root.0, &log_b, &shape).is_err());

        let bad_init = OpeningsGl { init: state_salt(&b, HLL, 1), ..OpeningsGl::for_leaf(&a, HLL, 2) };
        let l2i = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_init).output;
        assert_ne!(read_exposed_statement(&l2i.0).init, read_exposed_statement(&l1.0).final_);
        let e = forge::catch_msg(|| prove_hiding_merge(&l1, &l2i)).map(|_| ());
        println!("B2 GL hll inconsistent salt merge: {e:?}");
        assert!(
            e.as_ref().is_err_and(|m| m.contains("WitnessConflict")),
            "leaf 2's init must use leaf 1's final salt: {e:?}"
        );
    }

    /// (5) The zero-salt no-op leaf of a Hiding circuit still exposes
    /// `init == final` (the public zero-salt commitment of its public
    /// state), so the twin-merge root-VK derivation works unchanged; the
    /// Plain no-op leaf exposes the pre-B2 commitment.
    #[test]
    fn hiding_noop_leaf_has_init_eq_final() {
        let mut regs = hll_omc_empty(HP.b);
        for binding in [Binding::Semantic, Binding::Bound] {
            regs = hll_omc_empty(HP.b);
            hll_omc_advance_with(&mut regs, &[1], HP.m(), binding);
            let noop = hll_omc_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
            let st = read_exposed_statement(&noop);
            let anchor = commit_hll_omc_with(&regs, HP.b, CommitMode::Hiding, &SaltGl::ZERO);
            assert_eq!(st.init, st.final_, "{binding:?}");
            assert_eq!(st.init, anchor.to_vec(), "{binding:?}");
            assert_ne!(anchor, commit_hll_omc(&regs, HP.b), "{binding:?}");
        }
        let plain = hll_omc_gl_noop_leaf_commit(HP, Expose::Boundary, Binding::Bound, CommitMode::Plain);
        let (i, f) = read_exposed_boundary_proof(&plain);
        assert_eq!((i.0, f.0), (commit_hll_omc(&regs, HP.b), commit_hll_omc(&regs, HP.b)));
    }

    /// (F3, F5) The Hiding leaf costs exactly +2 Poseidon2 rows and +3 ALU
    /// rows per commitment over the Plain leaf (+6 and +9 per leaf) under
    /// every binding, and none of its 18 salt values is a public value of
    /// the proof (positive control: a "salt" equal to an exposed commitment
    /// value is found).
    #[test]
    fn hiding_leaf_row_overhead_and_no_salt_in_public_values() {
        let seed = SaltSeed::for_tests(91);
        let t = 3u64;
        let keys = hp_batches()[0].clone();
        let o = OpeningsGl::for_leaf(&seed, HLL, t);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut plain = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
            let mut leaf = hiding_leaf(binding);
            let (p0, a0) = trace_rows(&plain.run_epoch(hp_prior(binding), keys.clone()).0);
            let (p1, a1) = trace_rows(&leaf.run_epoch_commit(hp_prior(binding), keys.clone(), &o).0);
            println!("B2 GL hll leaf rows {binding:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 6, "{binding:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 9, "{binding:?}: ALU rows");
            let hid = leaf.prove_epoch_commit(t, hp_prior(binding), keys.clone(), &o);
            assert_eq!(proof_alu_rows(&hid.output.0), a1, "{binding:?}: the proof's ALU height");
            assert_eq!(leaked_salts(&hid.output.0, &[o.init, o.final_, o.batch]), vec![], "{binding:?}");
            let mut control = SaltGl::ZERO;
            control.0[0] = hid.initial_commit.0[0];
            assert!(!leaked_salts(&hid.output.0, &[control]).is_empty(), "{binding:?}: the scan sees the statement");
        }
    }

    /// (F1) A Hiding leaf never falls back to zero salts silently: the old
    /// `prove_epoch_at` / `prove_epoch` entry points panic on it, and so does
    /// `prove_epoch_commit` handed a zero final or batch salt. The explicit
    /// no-op path refuses a batch that moves the registers. Controls: a zero
    /// INIT salt is leaf 1's honest opening (from the empty genesis
    /// registers; a zero init on a real state is refused, test
    /// `hiding_leaf_refuses_zero_init_on_a_real_state`), and a Plain leaf
    /// still ignores its openings.
    #[test]
    fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
        let seed = SaltSeed::for_tests(81);
        let binding = Binding::Semantic;
        let keys = hp_batches()[0].clone();
        let mut leaf = hiding_leaf(binding);
        let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, hp_prior(binding), keys.clone()).final_commit).unwrap_err();
        assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
        assert!(forge::catch(|| leaf.prove_epoch(hp_prior(binding), keys.clone()).final_commit).is_none());
        let honest = OpeningsGl::for_leaf(&seed, HLL, 2);
        for (what, o) in [
            ("plain", OpeningsGl::plain()),
            ("public_zero", OpeningsGl::public_zero()),
            ("zero final", OpeningsGl { final_: SaltGl::ZERO, ..honest }),
            ("zero batch", OpeningsGl { batch: SaltGl::ZERO, ..honest }),
        ] {
            let msg = forge::catch_msg(|| leaf.prove_epoch_commit(2, hp_prior(binding), keys.clone(), &o).final_commit)
                .unwrap_err();
            assert!(msg.contains("public zero salt"), "{what}: {msg}");
        }
        let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, hp_prior(binding), keys.clone()).final_commit)
            .unwrap_err();
        assert!(msg.contains("must not change the registers"), "{msg}");

        let o1 = OpeningsGl::for_leaf(&seed, HLL, 1);
        assert!(o1.init.is_zero());
        let s0 = hll_omc_empty(HP.b);
        let r = leaf.prove_epoch_commit(1, s0.clone(), keys.clone(), &o1);
        assert_eq!(r.initial_commit.0, commit_hll_omc_with(&s0, HP.b, CommitMode::Hiding, &SaltGl::ZERO));
        let mut plain = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
        let p = plain.prove_epoch_commit(2, hp_prior(binding), keys.clone(), &OpeningsGl::plain());
        assert_eq!(p.initial_commit.0, commit_hll_omc(&hp_prior(binding), HP.b));
        assert_eq!(p.final_commit.0, commit_hll_omc(&advanced(&hp_prior(binding), &keys, binding), HP.b));
        assert_eq!(p.batch_commit.0, hll_omc_batch_commit_with(&keys, binding));
    }

    /// (F1, init salt) The twin of the BabyBear leaf's test: under `Hiding` a
    /// zero INIT salt opens only a public state at batch index 1 (the empty
    /// genesis registers or the public `S_noop`). Refused, under every
    /// binding: a forgotten init opening on a real prior (`t = 2`), local
    /// numbering (`for_leaf(.., 1)` at global `t = 5` on a real state), leaf
    /// 1's openings on a real prior at `t = 1`, and a zero init at `t = 2` on
    /// the empty registers. Controls: the empty-registers and `S_noop`
    /// leaves at `t = 1` prove and expose the zero-salt commitment of their
    /// public state; a Plain leaf ignores its openings on the same inputs.
    #[test]
    fn hiding_leaf_refuses_zero_init_on_a_real_state() {
        let seed = SaltSeed::for_tests(83);
        let keys = hp_batches()[0].clone();
        let s0 = hll_omc_empty(HP.b);
        let forgot = OpeningsGl { init: SaltGl::ZERO, ..OpeningsGl::for_leaf(&seed, HLL, 2) };
        let local = OpeningsGl::for_leaf(&seed, HLL, 1);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let prior = hp_prior(binding);
            let noop = advanced(&s0, &[1], binding);
            assert!(prior != s0 && prior != noop, "precondition: a real (secret) prior");
            let cases = [
                ("forgotten init, real prior", 2u64, prior.clone(), forgot),
                ("local numbering at global t = 5", 5, prior.clone(), local),
                ("leaf-1 openings on a real prior", 1, prior.clone(), local),
                ("zero init at t = 2 on the empty registers", 2, s0.clone(), forgot),
            ];
            let mut leaf = hiding_leaf(binding);
            for (what, t, init, o) in &cases {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(*t, init.clone(), keys.clone(), o).final_commit)
                    .unwrap_err();
                assert!(msg.contains("zero init salt"), "{binding:?}/{what}: {msg}");
            }
            for public in [s0.clone(), noop.clone()] {
                let r = leaf.prove_epoch_commit(1, public.clone(), keys.clone(), &local);
                let want = commit_hll_omc_with(&public, HP.b, CommitMode::Hiding, &SaltGl::ZERO);
                assert_eq!(r.initial_commit.0, want, "{binding:?}");
            }
            if binding == Binding::Semantic {
                let mut plain = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
                for (what, t, init, o) in &cases {
                    let p = plain.prove_epoch_commit(*t, init.clone(), keys.clone(), o);
                    assert_eq!(p.initial_commit.0, commit_hll_omc(init, HP.b), "Plain/{what}");
                }
            }
        }
    }

    /// The zero-salt no-op path is proved at batch index 1 only (the
    /// VK-derivation leaf's), like every other family's: the canonical
    /// public input at `t = 2` is refused under every binding and in either
    /// mode, after the input checks.
    #[test]
    fn public_zero_path_refuses_another_batch_index() {
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let noop = advanced(&hll_omc_empty(HP.b), &[1], binding);
            for mode in [CommitMode::Hiding, CommitMode::Plain] {
                let mut leaf = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, mode);
                let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(2, noop.clone(), vec![1; HP.batch]).final_commit)
                    .unwrap_err();
                assert!(msg.contains("batch index 1"), "{binding:?}/{mode:?}: {msg}");
            }
        }
    }

    /// The zero-salt no-op path accepts only the public no-op input (key 1
    /// in empty registers, every key 1), the twin of the BabyBear leaf's
    /// test: for HLL a real batch of repeated keys often raises nothing, so
    /// "the registers do not move" alone would let it publish the
    /// deterministic commitments of a secret state and of real keys.
    /// Rejected, under every binding and in either mode: a real state with a
    /// repeated real key (the stream harness's split-leaf pad shape), a
    /// non-canonical state with keys 1, and the canonical state with a real
    /// key that does not raise its register. Control: the canonical input
    /// proves, and exposes `Com(S_noop; 0)`.
    #[test]
    fn noop_path_accepts_only_the_public_noop_input() {
        let noop_msg = "the public no-op input only";
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let empty = hll_omc_empty(HP.b);
            let noop = advanced(&empty, &[1], binding);
            let real = advanced(&empty, &[4242, 777], binding);
            let repeat = vec![4242u64; HP.batch];
            assert_eq!(advanced(&real, &repeat, binding), real, "{binding:?}: the repeat raises nothing");
            let other = advanced(&empty, &[1, 4242], binding);
            assert_ne!(other, noop, "{binding:?}");
            let quiet = (2u64..100_000)
                .find(|&k| advanced(&noop, &[k], binding) == noop)
                .expect("a key dominated by key 1's register");
            let cases = [
                ("real state, repeated real key", real, repeat),
                ("non-canonical state, keys 1", other, vec![1; HP.batch]),
                ("canonical state, dominated real key", noop.clone(), vec![quiet; HP.batch]),
            ];
            for mode in [CommitMode::Hiding, CommitMode::Plain] {
                let mut leaf = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, mode);
                for (what, init, keys) in &cases {
                    let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(9, init.clone(), keys.clone()).final_commit)
                        .unwrap_err();
                    assert!(msg.contains(noop_msg), "{binding:?}/{mode:?}/{what}: {msg}");
                }
            }
            let r = hiding_leaf(binding).prove_epoch_public_zero(1, noop.clone(), vec![1; HP.batch]);
            let c = commit_hll_omc_with(&noop, HP.b, CommitMode::Hiding, &SaltGl::ZERO);
            assert_eq!(r.initial_commit.0, c, "{binding:?}");
            assert_eq!(r.final_commit.0, c, "{binding:?}");
            assert_eq!(
                r.batch_commit.0,
                hll_omc_batch_commit_salted(&vec![1; HP.batch], binding, CommitMode::Hiding, &SaltGl::ZERO),
                "{binding:?}"
            );
        }
    }

    /// (F2) A continued history is anchored on the previous history's
    /// certified final commitment ([`OpeningsGl::for_leaf_after`]): history
    /// 1's leaf 1 exposes exactly history 0's final `Com(S_2; salt)`, both
    /// leaves pass history 1's log; the zero init salt (the guess-checkable
    /// `Com(S_2; 0)`) is refused by the leaf, and a nonzero wrong anchor salt
    /// is rejected by the log.
    #[test]
    fn continued_history_leaf_opens_the_previous_final_commitment() {
        let binding = Binding::Semantic;
        let seed = SaltSeed::for_tests(71);
        let bs = hp_batches();
        let s1 = advanced(&hll_omc_empty(HP.b), &bs[0], binding);
        let s2 = advanced(&s1, &bs[1], binding);
        let mut leaf = hiding_leaf(binding);
        let h0_last = leaf.prove_epoch_commit(2, s1, bs[1].clone(), &OpeningsGl::for_leaf(&seed, HLL, 2));
        let anchor_salt = state_salt(&seed, HLL, 2);
        let anchor = h0_last.final_commit.0;
        assert_eq!(anchor, commit_hll_omc_with(&s2, HP.b, CommitMode::Hiding, &anchor_salt));

        let h = 1u64;
        let s3 = advanced(&s2, &bs[0], binding);
        let s4 = advanced(&s3, &bs[1], binding);
        let o1 = OpeningsGl::for_leaf_after(&anchor_salt, &seed, HLL, h);
        let l1 = leaf.prove_epoch_commit(1, s2.clone(), bs[0].clone(), &o1).output;
        let l2 = leaf.prove_epoch_commit(2, s3, bs[1].clone(), &OpeningsGl::for_leaf_in(&seed, HLL, h, 2)).output;
        assert_eq!(read_exposed_statement(&l1.0).init, anchor.to_vec(), "history 1 starts at history 0's final");
        assert_eq!(read_exposed_statement(&l2.0).init, read_exposed_statement(&l1.0).final_);
        let bc: Vec<[Val; 4]> = (0..2)
            .map(|k| hll_omc_batch_commit_salted(&bs[k], binding, CommitMode::Hiding, &batch_salt_in(&seed, HLL, h, k as u64 + 1)))
            .collect();
        let fin = commit_hll_omc_with(&s4, HP.b, CommitMode::Hiding, &state_salt_in(&seed, HLL, h, 2));
        let log1 = batch_log(&anchor, &fin, &bc);
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log1, Expose::Interval), Ok(()));
        let zero_init = OpeningsGl { init: SaltGl::ZERO, ..o1 };
        let msg = forge::catch_msg(|| leaf.prove_epoch_commit(1, s2.clone(), bs[0].clone(), &zero_init).final_commit)
            .unwrap_err();
        assert!(msg.contains("zero init salt"), "{msg}");
        let wrong_init = OpeningsGl { init: state_salt(&seed, HLL, 1), ..o1 };
        let l1w = leaf.prove_epoch_commit(1, s2, bs[0].clone(), &wrong_init).output;
        let e = check_leaves_against_log(&[&l1w.0, &l2.0], &log1, Expose::Interval);
        assert!(e.as_ref().is_err_and(|m| m.contains("Com(S_0)")), "{e:?}");
    }

    /// (8) Build and prove the Hiding leaf at a tiny shape. Under the DEBUG
    /// profile (`cargo test --lib hll_omc_gl::tests::hiding_leaf_tiny_debug`)
    /// the fork debug-asserts, during the build, that each of the 9 salt
    /// private inputs has an ALU creator.
    #[test]
    fn hiding_leaf_tiny_debug() {
        let p = HllOmcParams { b: 2, batch: 1 };
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = build_hll_omc_leaf_commit(p, Expose::Interval, binding, CommitMode::Hiding);
            let seed = SaltSeed::for_tests(8);
            let r = leaf.prove_epoch_commit(1, hll_omc_empty(2), vec![9], &OpeningsGl::for_leaf(&seed, HLL, 1));
            let mut fin = hll_omc_empty(2);
            hll_omc_advance_with(&mut fin, &[9], p.m(), binding);
            assert_eq!(r.final_commit.0, commit_hll_omc_with(&fin, 2, CommitMode::Hiding, &state_salt(&seed, HLL, 1)));
        }
    }
}
