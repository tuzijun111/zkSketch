//! **Goldilocks (D=2) offline-memory-checking Count-Min leaf** — the
//! selectable Goldilocks counterpart of [`super::countmin_omc`], mirroring how
//! [`super::hll_omc_gl`] / [`super::ss_final_full_gl`] / [`super::gk_bandmerge_gl`]
//! shadow their BabyBear originals. The BabyBear module stays byte-for-byte
//! untouched; this file only adds the `cm_gl` option.
//!
//! Same `M_old ⊎ W == M_new ⊎ R` check as the BabyBear leaf (see
//! [`super::countmin_omc`]'s header). The port-relevant differences:
//!
//! - **Config**: `crate::config_gl` (Goldilocks, D=2, width-8 Poseidon2,
//!   digest 4) via `GOLDILOCKS_D2_W8`; `::<2>` / `_d2` registration forms.
//! - **Cell packing**: 2 counters per `Challenge` (D=2) instead of 4.
//! - **Key encoding**: under `Binding::Legacy` Goldilocks holds the u64 key
//!   in ONE base element, so a batch record packs as `[key, value]` in one
//!   Challenge (the BabyBear Legacy batch row is `[key_lo, key_hi, value,
//!   0]`). That element is the key mod `p` (`p = 2^64 − 2^32 + 1 < 2^64`), so
//!   `k` and `k + p` collide for every `k < 2^32 − 1`. Under
//!   `Semantic`/`Bound` the key is two exact 32-bit limbs `[lo, hi]` (one
//!   Challenge, range-checked, [`bind::key_from_limbs`]) that the routing
//!   hash and the batch commitment both absorb; a record commits as `[lo,
//!   hi, value, 0]` (two Challenges). Commitments are field-specific.
//! - **PRF routing**: the key digest is 4 Goldilocks coefficients instead of
//!   8 BabyBear ones, but the PRF family still needs up to 8 row streams
//!   (`d ≤ 8`). Row `i` draws its bucket from the 32-bit HALF-coefficient
//!   `i`: `bucket_i = ((digest[i/2] >> 32·(i mod 2)) mod 2^32) mod w`
//!   ([`hash_cell_prf`]) — in-circuit, bits `[32·(i mod 2), 32·(i mod 2) +
//!   log2 w)` of coefficient `i/2`'s 64-bit decomposition. Distinct rows use
//!   disjoint bit ranges, preserving the 8-stream PRF shape. NOTE: this is a
//!   DIFFERENT hash family from BabyBear's, so `cm_gl` sketch states are a
//!   distinct (statistically equivalent) Count-Min instance — chains/forests
//!   must not mix fields.
//! - **Multiset encoding**: BabyBear packs `(addr, val, tag, 0)` into one
//!   D=4 challenge. D=2 has two coords and CM counter values are unbounded
//!   by design (no range checks on committed cells — exactly BabyBear's
//!   contract), so the dummy-separating tag moves to the ADDRESS coordinate:
//!   `enc(a, v) = recompose([2a+1, v])`; the value coordinate stays RAW.
//!   `recompose` is injective in `(2a+1, v)`, so distinct real elements never
//!   collide. Caveat vs BabyBear's dedicated constant tag coordinate: `2a+1`
//!   is nonzero only for `a ≠ (p−1)/2`, so real/dummy disjointness is
//!   conditional on the address witness — adversarial review found no
//!   standalone exploit (a `(p−1)/2` address cannot satisfy gap-sortedness
//!   next to canonical neighbors without collapsing into the shared split
//!   gap below), but it is defense-in-depth BabyBear has and this encoding
//!   lacks. On Goldilocks the payload packing `addr·2^SHIFT + val` cannot
//!   wrap for any admissible shape (`< 2^55 ≪ p`), unlike BabyBear where it
//!   exceeds `p` at the deployed `d·w`.
//!
//! ### KNOWN SHARED SOUNDNESS GAP (inherited from [`super::countmin_omc`])
//!
//! The sorted-view split `combined_sorted[r]·2^SHIFT + val_sorted[r] ==
//! payload_sorted[r]` is ONE in-field equation in TWO free witnesses:
//! `val_sorted` is never range-checked and `combined_sorted[0]` has no
//! absolute bound (only gaps are checked). A malicious prover can therefore
//! trade value bits against address bits in the split — redirecting an
//! increment to a different (gap-consistent) cell with an attacker-chosen
//! magnitude — and certify a final commitment that is not the honest
//! Count-Min fold. The BabyBear original has the IDENTICAL structure
//! (`countmin_omc.rs` Stage G), so this port is soundness-envelope-matched
//! to it (deliberately: the leaf is a same-arithmetization field-comparison
//! artifact). The fix — range-check `val_sorted[r] < 2^SHIFT_VAL_BITS` and
//! `combined_sorted[r] < 2^addr_bits` at every row — costs ~(SHIFT_VAL_BITS
//! + addr_bits) bit witnesses per counter-touch row in BOTH files and is
//! tracked as a separate work item.

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

use crate::config_gl::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl as ConfigWithFriParams;
use crate::recursion::recursive::leaf_gl::{
    DIGEST_PACKING, GlCommit, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::bind::{self, Binding};
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::countmin_v9::CountMinV9;

const LOG_FINAL_POLY_LEN: usize = 6;
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

fn val_bits() -> usize {
    Val::bits()
}

thread_local! {
    /// When set, the prover commits to a CORRUPTED final state (one cell
    /// bumped) while the patch/multiset are built from the honest one, so
    /// `M_old ⊎ W = M_new ⊎ R` fails and the self-verify rejects. Drives
    /// [`tests::tamper_rejected`].
    static TAMPER_FINAL_CELL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Test-only malicious prover: `(from, to)` takes the ACTIVE sorted row
    /// at address `from` and claims the extension-valued old value
    /// [`redirect_op_old`], so both multiset elements of that row encode
    /// address `to` and the increment is committed at `to` (untouched by the
    /// batch). Drives `tests::op_old_redirect_*`.
    static OP_OLD_REDIRECT: std::cell::Cell<Option<(u64, u64)>> = const { std::cell::Cell::new(None) };
}

/// The extension-valued `op_old = O[to] + t·X`, `t = 2(to − from)/W`
/// (`X² = W`), for which `enc(from, op_old) = enc(to, O[to])` and
/// `enc(from, op_old + Δ) = enc(to, O[to] + Δ)`, with
/// `enc(a, v) = (2a + 1) + v·X`.
#[cfg(test)]
fn redirect_op_old(from: u64, to: u64, o_to: u32) -> Challenge {
    let x: Challenge =
        Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE]).expect("X");
    let x2: Challenge = x * x;
    let w_ext: Val = <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&x2)[0];
    let t = (Val::from_u64(to) - Val::from_u64(from)).double() * w_ext.inverse();
    Challenge::from_u32(o_to) + x * Challenge::from(t)
}

/// Goldilocks PRF row hash under the process default [`Binding`] (the one
/// [`build_countmin_omc_leaf`] uses); see [`hash_cell_prf_with`].
pub fn hash_cell_prf(row: usize, key: u64, w: usize) -> usize {
    hash_cell_prf_with(row, key, w, bind::default_binding())
}

/// The PRF digest of `key` under `binding`: `MyHash([lo, hi])` (exact 32-bit
/// limbs) under `Semantic`/`Bound`, `MyHash([key mod p, 0])` under `Legacy`
/// ([`bind::key_hash_input`]).
pub fn key_digest(key: u64, binding: Binding) -> [Val; 4] {
    MyHash::new(make_perm()).hash_iter(bind::key_hash_input::<Val>(key, binding))
}

/// Goldilocks PRF row hash: row `i` reads the 32-bit half-coefficient `i` of
/// the key digest ([`key_digest`]; 4 Goldilocks elements = 8 halves), reduced
/// mod `w`. Mirrors the in-circuit derivation bit-for-bit (`w` is a power of
/// two, so `mod w` = the bottom `log2 w` bits of the half).
pub fn hash_cell_prf_with(row: usize, key: u64, w: usize, binding: Binding) -> usize {
    assert!(row < 8, "PRF hash family supports row < 8; got {row}");
    assert!(w > 0, "width w must be positive");
    bucket_of(&key_digest(key, binding), row, w)
}

/// Row `row`'s bucket from a key digest (see [`hash_cell_prf_with`]).
fn bucket_of(digest: &[Val; 4], row: usize, w: usize) -> usize {
    let h: u64 = <Val as PrimeField64>::as_canonical_u64(&digest[row / 2]);
    let half = (h >> (32 * (row % 2))) & 0xFFFF_FFFF;
    (half as usize) % w
}

/// Apply one [`CountMinUpdate`] with the GOLDILOCKS PRF row hash under the
/// process default [`Binding`] — the canonical native update for the `cm_gl`
/// leaf (distinct instance from the BabyBear `apply_update_prf`).
pub fn apply_update_prf(state: &mut CountMinState, u: &CountMinUpdate) {
    apply_update_prf_with(state, u, bind::default_binding());
}

/// [`apply_update_prf`] for an explicit [`Binding`].
pub fn apply_update_prf_with(state: &mut CountMinState, u: &CountMinUpdate, binding: Binding) {
    let digest = key_digest(u.key, binding);
    for i in 0..state.params.d {
        let j = bucket_of(&digest, i, state.params.w);
        state.counters[i][j] = state.counters[i][j].saturating_add(u.value);
    }
}

/// Empty Count-Min state (shared field-independent `CountMinState`).
pub fn cm_gl_empty(d: usize, w: usize) -> CountMinState {
    CountMinV9::new(&CountMinParams { d, w })
}

/// `Com(S)` for a Count-Min state under the Goldilocks hash — the flat
/// Poseidon2 digest over the `d·w` counters the leaf recomputes in-circuit.
pub fn commit_countmin(state: &CountMinState) -> GlCommit {
    let hasher = MyHash::new(make_perm());
    let flat = state.counters.iter().flatten().map(|&c| Val::from_u32(c));
    GlCommit(hasher.hash_iter(flat))
}

/// Batch commitment under the process default [`Binding`]; see
/// [`commit_batch_with`].
pub fn commit_batch(records: &[CountMinUpdate]) -> GlCommit {
    commit_batch_with(records, bind::default_binding())
}

/// Batch commitment, matching the in-circuit batch sponge: flat `[key mod p,
/// value]` per record under `Legacy` (one D=2 Challenge), and the exact
/// limbs `[lo, hi, value, 0]` (two Challenges) under `Semantic`/`Bound`.
pub fn commit_batch_with(records: &[CountMinUpdate], binding: Binding) -> GlCommit {
    let hasher = MyHash::new(make_perm());
    let flat: Vec<Val> = records
        .iter()
        .flat_map(|r| {
            if binding.is_bound() {
                let l = bind::key_limbs::<Val>(r.key);
                vec![l[0], l[1], Val::from_u32(r.value), Val::ZERO]
            } else {
                vec![Val::from_u64(r.key), Val::from_u32(r.value)]
            }
        })
        .collect();
    GlCommit(hasher.hash_iter(flat))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmOmcParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CmOmcParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    fn addr_bits(&self) -> usize {
        let n = self.num_cells();
        (usize::BITS - n.saturating_sub(1).leading_zeros()).max(1) as usize
    }
    pub fn validate(&self) {
        assert!(
            self.d >= 1 && self.d <= 8,
            "d must be in 1..=8, got {}",
            self.d
        );
        assert!(
            self.w.is_power_of_two() && self.w >= 2,
            "w must be a power of two ≥ 2, got {}",
            self.w
        );
        assert!(
            self.w.trailing_zeros() <= 32,
            "w must fit a 32-bit half-coefficient PRF stream, got {}",
            self.w
        );
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(
            self.num_cells() % 2 == 0,
            "d·w must be a multiple of 2 (Challenge packing, D=2)"
        );
    }
}

/// A self-verified Goldilocks `omc` Count-Min leaf proof. Commitments are the
/// dense Goldilocks digests on both ends, so this chains against a real
/// committed prior state.
pub struct CountMinOmcProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: GlCommit,
    pub final_commit: GlCommit,
    pub batch_commit: GlCommit,
    pub params: CmOmcParams,
}

impl CountMinOmcProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

/// Pack the counters 2-per-Challenge (D=2) — the coefficient stream the
/// in-circuit `add_hash_slice` absorbs equals the flat stream
/// [`commit_countmin`] hashes natively.
fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    let flat: Vec<Val> = state
        .counters
        .iter()
        .flatten()
        .map(|&c| Val::from_u32(c))
        .collect();
    flat.chunks(2)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("2 base coeffs"))
        .collect()
}

/// The batch sponge's input Challenges under `binding`: `Legacy` one
/// `[key, value]` per record ([`pack_batch_to_challenge`]); `Semantic`/`Bound`
/// two, the exact key limbs `[lo, hi]` and then `[value, 0]`.
#[cfg(test)]
fn batch_sponge_input(batch: &[CountMinUpdate], binding: Binding) -> Vec<Challenge> {
    if !binding.is_bound() {
        return pack_batch_to_challenge(batch);
    }
    batch
        .iter()
        .flat_map(|r| {
            let key = Challenge::from_basis_coefficients_slice(&bind::key_limbs::<Val>(r.key))
                .expect("2 key limbs");
            [key, Challenge::from_u32(r.value)]
        })
        .collect()
}

/// Pack the batch records 1-per-Challenge: `[key, value]`.
fn pack_batch_to_challenge(batch: &[CountMinUpdate]) -> Vec<Challenge> {
    batch
        .iter()
        .map(|r| {
            Challenge::from_basis_coefficients_slice(&[
                Val::from_u64(r.key),
                Val::from_u32(r.value),
            ])
            .expect("2 base coeffs")
        })
        .collect()
}

/// Prove one count-min epoch from an arbitrary committed `initial_state`
/// via the `M_old ⊎ W = M_new ⊎ R` multiset rebind.
pub fn prove_countmin_omc(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    prove_countmin_omc_impl(params, initial_state, batch, false)
}

/// Like [`prove_countmin_omc`] but surfaces the `(initial, final)` boundary
/// commitments via the **Expose NPO** so the leaf can be folded by the
/// in-circuit boundary-bound Goldilocks forest.
pub fn prove_countmin_omc_exposed(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    prove_countmin_omc_impl(params, initial_state, batch, true)
}

/// A built, reusable Goldilocks `omc` Count-Min leaf: the circuit graph, its
/// prover data, and a registered prover. Build once per
/// `(params, expose_boundary)` and call [`Self::prove_epoch`] per batch.
pub struct CmOmcLeafCircuit {
    params: CmOmcParams,
    binding: Binding,
    expose: Expose,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    /// Test-only handles: the per-row `op_old` private inputs (sorted order).
    #[cfg(test)]
    probe_op_old: Vec<ExprId>,
}

/// Build the reusable Goldilocks `omc` Count-Min leaf circuit for a shape,
/// with the process default [`Binding`] (`Semantic` unless `ZKSKETCH_BINDING`).
pub fn build_countmin_omc_leaf(params: CmOmcParams, expose_boundary: bool) -> CmOmcLeafCircuit {
    build_countmin_omc_leaf_with(params, expose_boundary, bind::default_binding())
}

/// Build the Goldilocks `omc` Count-Min leaf for a shape and binding.
///
/// [`Binding::Legacy`] is the pre-fix circuit, unchanged. It is unsound: the
/// cells, batch fields and digest coefficients are unbound, sponge IVs are
/// free, digest bits may be non-canonical, and the "known shared soundness
/// gap" of the module header applies: the `address·2^SHIFT + value` split is
/// one equation in two free witnesses.
///
/// [`Binding::Semantic`] / [`Binding::Bound`] fix the circuit-semantic parts:
/// - canonical bits on every digest coefficient that carries a row position;
/// - the coordinate-wise sort key `address + value·e₁`;
/// - an exact range on `combined_sorted[0]`;
/// - base pins on `val_sorted` and `op_old`, which closes that header gap
///   (an extension-valued `op_old` redirects an update to any cell under
///   `Legacy`; `tests::op_old_redirect_*`).
///
/// - the key as two exact 32-bit limbs `[lo, hi]`, range-checked and
///   ALU-recomposed into the one Challenge the routing hash and the batch
///   commitment both absorb ([`bind::key_from_limbs`]); `Legacy` hashes
///   `[key mod p, 0]`, so `k` and `k + p` collide (`tests::congruent_keys_*`).
///
/// `Bound` also ALU-binds cells, batch fields and digest coefficients and
/// hashes with a zero IV (see [`crate::sketch::bind`]). Counters and values
/// are natively `u32`, so they are pinned by an exact 4-byte `< 2^32` range
/// (`bind::pin_u32`) instead of the 8-byte full-width base pin; only the
/// unused digest coefficients (and `Legacy`'s one-element key) take the
/// latter.
pub fn build_countmin_omc_leaf_with(
    params: CmOmcParams,
    expose_boundary: bool,
    binding: Binding,
) -> CmOmcLeafCircuit {
    build_countmin_omc_leaf_expose(params, Expose::from_bool(expose_boundary), binding)
}

/// Goldilocks `omc` Count-Min leaf with an explicit composition statement
/// ([`Expose`]); `None` / `Boundary` are byte-for-byte
/// [`build_countmin_omc_leaf_with`], `Interval` adds the batch index `t`
/// (last public input) and exposes `(init, final, (t, t), H)` with
/// `H = Poseidon2(TAG_LEAF, t, Com(B_t))` over the in-circuit batch digest.
pub fn build_countmin_omc_leaf_expose(
    params: CmOmcParams,
    expose: Expose,
    binding: Binding,
) -> CmOmcLeafCircuit {
    let expose_boundary = expose == Expose::Boundary;
    params.validate();
    let bound = binding.is_bound();
    let CmOmcParams { d, w, batch: m } = params;
    let num_cells = params.num_cells();
    let cell_packing = num_cells / 2;
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let addr_bits = params.addr_bits();
    let l = num_cells + n_ctr; // multiset side length

    // ─── Circuit ─────────────────────────────────────────────────────────
    let cfg = Poseidon2Config::GOLDILOCKS_D2_W8;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        make_perm(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    if bound {
        assert!(addr_bits <= 24, "bound omc_gl: d·w must be ≤ 2^24");
        b.enable_range(generate_range_trace::<Val, Challenge>);
    }
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
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
    let row_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "row_i"))
        .collect();
    let cell_idx_consts: Vec<ExprId> = (0..num_cells)
        .map(|idx| b.alloc_const(Challenge::from_u64(idx as u64), "cell_idx"))
        .collect();
    let pow2_consts: Vec<ExprId> = (0..w_log2)
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();
    // Semantic/Bound: e₁ (coordinate-wise sort key), i·w, canonicity 2^i.
    // (Allocated only when used, so the Legacy circuit stays byte-identical.)
    let e1 = if bound {
        b.alloc_const(
            Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE]).expect("e1"),
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
    let canon_pow2: Vec<ExprId> = if bound {
        (0..bind::canon_low_bits::<Val>())
            .map(|i| b.alloc_const(Challenge::from_u64(1u64 << i), "canon2^i"))
            .collect()
    } else {
        Vec::new()
    };

    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    // Per record: `[key, value]` (Legacy) or `[value, 0]` (Semantic/Bound,
    // whose key Challenge is recomposed from exact limbs).
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();
    let mut key_w = Vec::with_capacity(m);
    let mut key_limbs: Vec<[ExprId; 2]> = Vec::new();
    let mut value_w = Vec::with_capacity(m);
    for _ in 0..m {
        if bound {
            key_limbs.push(std::array::from_fn(|_| b.alloc_private_input("key_limb")));
        } else {
            key_w.push(b.alloc_private_input("key"));
        }
        value_w.push(b.alloc_private_input("value"));
    }
    let combined_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("combined_sorted"))
        .collect();
    let val_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("val_sorted"))
        .collect();
    let eq_tag: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("eq_tag"))
        .collect();
    let inv_diff: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("inv_diff"))
        .collect();
    let op_old: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("op_old"))
        .collect();
    if let Some(&f0) = final_packed.first() {
        b.tag(f0, "cmgl_final_packed_0").expect("tag");
    }

    // Stage A — bind both states + batch to commitments.
    let digest_init = bind::hash_slice(&mut b, &cfg, &initial_packed, zero, binding);
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], init_commit_pis[i]);
    }
    let digest_final = bind::hash_slice(&mut b, &cfg, &final_packed, zero, binding);
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
    }
    // Semantic/Bound: exact key limbs → one key Challenge per record; the
    // batch sponge absorbs `[key, value]` and the routing hash the same key.
    let key_chal: Vec<ExprId> = key_limbs
        .iter()
        .map(|l| bind::key_from_limbs::<Val, Challenge>(&mut b, l))
        .collect();
    let batch_input: Vec<ExprId> = if bound {
        key_chal
            .iter()
            .zip(&batch_packed)
            .flat_map(|(&k, &v)| [k, v])
            .collect()
    } else {
        batch_packed.clone()
    };
    if let Some(&b0) = batch_input.first() {
        b.tag(b0, "cmgl_batch_packed_0").expect("tag");
    }
    let digest_batch = bind::hash_slice(&mut b, &cfg, &batch_input, zero, binding);
    for i in 0..DIGEST_PACKING {
        b.connect(digest_batch[i], batch_commit_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (7th public input) and
    // H = Poseidon2(TAG_LEAF, t, digest_batch), exposed with the boundary.
    if expose.is_interval() {
        let pin = if bound { IndexPin::Range } else { IndexPin::Bits };
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &cfg,
            &init_commit_pis,
            &final_commit_pis,
            &digest_batch,
            zero,
            binding,
            pin,
        );
    }
    let o_cells: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| {
            bind::decompose::<Val, Challenge>(&mut b, p, binding, bind::no_pin, bind::pin_all_u32::<Val, Challenge>)
        })
        .collect();
    let n_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| {
            bind::decompose::<Val, Challenge>(&mut b, p, binding, bind::no_pin, bind::pin_all_u32::<Val, Challenge>)
        })
        .collect();
    for k in 0..m {
        if bound {
            // [value (u32), 0].
            let coeffs = bind::decompose::<Val, Challenge>(
                &mut b,
                batch_packed[k],
                binding,
                bind::no_pin,
                |b, i, c| {
                    if i == 0 {
                        bind::pin_u32::<Val, Challenge>(b, c);
                    }
                },
            );
            b.connect(coeffs[0], value_w[k]);
            b.connect(coeffs[1], zero);
            continue;
        }
        // [key (full 64-bit base value), value (u32)].
        let coeffs = bind::decompose::<Val, Challenge>(
            &mut b,
            batch_packed[k],
            binding,
            bind::no_pin,
            |b, i, c| {
                if i == 0 {
                    bind::pin_base::<Val, Challenge>(b, c);
                } else {
                    bind::pin_u32::<Val, Challenge>(b, c);
                }
            },
        );
        b.connect(coeffs[0], key_w[k]);
        b.connect(coeffs[1], value_w[k]);
    }
    // Legacy: single-limb key → hash-input Challenge [key, 0].
    let key_field: Vec<ExprId> = if bound {
        key_chal
    } else {
        (0..m)
            .map(|k| {
                b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_w[k], zero])
                    .expect("recompose key")
            })
            .collect()
    };
    if let Some(&kf0) = key_field.first() {
        b.tag(kf0, "cmgl_key_field_0").expect("tag");
    }

    // Stage F — per-record PRF hash → payload. Row `i` draws its bucket from
    // the 32-bit half `i` of the 64-bit digest coefficients (see the module
    // header): bits [32·(i mod 2), 32·(i mod 2) + w_log2) of coeff i/2.
    let mut h_w = Vec::with_capacity(m);
    for _ in 0..m {
        h_w.push((b.alloc_private_input("h0"), b.alloc_private_input("h1")));
    }
    let mut payload = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let hashed = bind::hash_slice(&mut b, &cfg, &[key_field[k]], zero, binding);
        let (h0, h1) = h_w[k];
        b.connect(hashed[0], h0);
        b.connect(hashed[1], h1);
        if bound {
            // Coefficient t (= digest[t]) carries rows 2t, 2t+1: canonical
            // 64-bit bits for the ⌈d/2⌉ routing coefficients, base pins for the
            // rest of an ALU-bound Challenge; for d ≤ 4 the second digest
            // Challenge is not decomposed.
            let n_route = d.div_ceil(2);
            let mut hv_bits: Vec<Vec<ExprId>> = vec![Vec::new(); 4];
            for (half, h) in [(0usize, h0), (1usize, h1)] {
                if half == 1 && d <= 4 {
                    break;
                }
                let _ = bind::decompose::<Val, Challenge>(
                    &mut b,
                    h,
                    binding,
                    |b, i, c| {
                        let t = 2 * half + i;
                        if t < n_route {
                            let bits = b.decompose_to_bits::<Val>(c, val_bits()).expect("bits digest coeff");
                            bind::assert_canonical_bits(b, &bits, &canon_pow2, one, zero);
                            hv_bits[t] = bits;
                        }
                    },
                    |b, i, c| {
                        if 2 * half + i >= n_route {
                            bind::pin_base::<Val, Challenge>(b, c);
                        }
                    },
                );
            }
            for i in 0..d {
                let bits = &hv_bits[i / 2];
                let off = 32 * (i % 2);
                let mut pos = zero;
                for jb in 0..w_log2 {
                    pos = b.mul_add(bits[off + jb], pow2_consts[jb], pos);
                }
                let comb = b.add(row_w_consts[i], pos);
                payload.push(b.mul_add(value_w[k], e1, comb));
            }
            continue;
        }
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(h0).expect("d h0");
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(h1).expect("d h1");
        let hv = [c0[0], c0[1], c1[0], c1[1]];
        // Decompose all 4 coefficients once (also satisfies the consume rule
        // for the unused halves/coeffs at d < 8).
        let hv_bits: Vec<Vec<ExprId>> = hv
            .iter()
            .map(|&coeff| {
                b.decompose_to_bits::<Val>(coeff, val_bits())
                    .expect("bits digest coeff")
            })
            .collect();
        for i in 0..d {
            let bits = &hv_bits[i / 2];
            let off = 32 * (i % 2);
            let mut pos = b.mul(bits[off], pow2_consts[0]);
            for jb in 1..w_log2 {
                let t = b.mul(bits[off + jb], pow2_consts[jb]);
                pos = b.add(pos, t);
            }
            let rw = b.mul(row_consts[i], w_const);
            let comb = b.add(rw, pos);
            let cs = b.mul(comb, shift_val_const);
            payload.push(b.add(cs, value_w[k]));
        }
    }

    // Stage G — counter sort.
    // Placeholder identity permutation — `prove_epoch` swaps in the real
    // per-batch sigma via `update_permute_witnesses` before each run.
    let payload_sorted = b
        .add_permute(&payload, (0..n_ctr).collect::<Vec<_>>())
        .expect("permute ctr");
    for r in 0..n_ctr {
        let rec = if bound {
            b.mul_add(val_sorted[r], e1, combined_sorted[r])
        } else {
            let cs = b.mul(combined_sorted[r], shift_val_const);
            b.add(cs, val_sorted[r])
        };
        b.connect(rec, payload_sorted[r]);
    }

    // Stage H — adjacency / running sum / sortedness / segment flags.
    b.connect(eq_tag[0], zero);
    b.connect(inv_diff[0], zero);
    if bound {
        bind::range_exact::<Val, Challenge>(&mut b, combined_sorted[0], addr_bits);
        // Sorted values and old counters are natively u32.
        for r in 0..n_ctr {
            bind::pin_u32::<Val, Challenge>(&mut b, val_sorted[r]);
            bind::pin_u32::<Val, Challenge>(&mut b, op_old[r]);
        }
    }
    for r in 1..n_ctr {
        let diff = b.sub(combined_sorted[r - 1], combined_sorted[r]);
        let l1 = b.mul(eq_tag[r], diff);
        b.connect(l1, zero);
        let omt = b.sub(one, eq_tag[r]);
        let di = b.mul(diff, inv_diff[r]);
        let omdi = b.sub(one, di);
        let l2 = b.mul(omt, omdi);
        b.connect(l2, zero);
        // sortedness: gap ∈ [0, 2^addr_bits) (canonical 1-entry-per-address).
        // Full-width window + zero-forced high bits keeps it canonical.
        let gap = b.sub(combined_sorted[r], combined_sorted[r - 1]);
        let gb = b
            .decompose_to_bits::<Val>(gap, val_bits())
            .expect("gap bits");
        for &bit in gb.iter().skip(addr_bits) {
            b.connect(bit, zero);
        }
    }
    let mut acc = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        acc.push(b.add(val_sorted[r], carried));
    }
    let mut a_active = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        a_active.push(if r == n_ctr - 1 {
            one
        } else {
            b.sub(one, eq_tag[r + 1])
        });
    }

    // ─── Build the multiset sides and check M_old ⊎ W == M_new ⊎ R ───────
    // enc(a, v) = recompose([2a+1, v]) — the odd-address tag keeps real
    // elements disjoint from the zero dummies of inactive W/R rows (addresses
    // are canonical small integers; the value coordinate stays RAW, matching
    // the BabyBear contract of no range assumptions on committed cells).
    let enc = |b: &mut CircuitBuilder<Challenge>, a: ExprId, v: ExprId| -> ExprId {
        let ta = b.mul_add(a, two, one); // 2·a + 1
        b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[ta, v])
            .expect("enc")
    };
    let mut input: Vec<ExprId> = Vec::with_capacity(l);
    let mut target: Vec<ExprId> = Vec::with_capacity(l);
    for a in 0..num_cells {
        input.push(enc(&mut b, cell_idx_consts[a], o_cells[a]));
        target.push(enc(&mut b, cell_idx_consts[a], n_cells[a]));
    }
    for r in 0..n_ctr {
        let n_z = b.add(op_old[r], acc[r]); // N_z = O_z + Δ
        let enc_w = enc(&mut b, combined_sorted[r], n_z);
        let w_elem = b.mul(a_active[r], enc_w); // active → enc, inactive → 0
        input.push(w_elem);
        let enc_r = enc(&mut b, combined_sorted[r], op_old[r]);
        let r_elem = b.mul(a_active[r], enc_r);
        target.push(r_elem);
    }
    let permuted = b
        .add_permute(&input, (0..l).collect::<Vec<_>>())
        .expect("permute mset");
    for r in 0..l {
        b.connect(permuted[r], target[r]);
    }

    let circuit = b.build().expect("build countmin_omc_gl circuit");

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
    if bound {
        preprocessors.push(range_preprocessor::<Val>());
        air_builders.extend(range_air_builders::<ConfigWithFriParams, 2>(1));
    }
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
        .expect("get_airs_and_degrees_with_prep (omc_gl)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8);
    prover.register_recompose_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8.d() != 2);
    prover.register_permute_table::<2>();
    if bound {
        prover.register_range_table::<2>();
    }
    if expose.exposes() {
        prover.register_expose_table::<2>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();

    CmOmcLeafCircuit {
        params,
        binding,
        expose,
        batch_index: 1,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        #[cfg(test)]
        probe_op_old: op_old.clone(),
    }
}

type GlEpoch = (Vec<Challenge>, Vec<Challenge>, GlCommit, GlCommit, GlCommit);

impl CmOmcLeafCircuit {
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// Prove one epoch on the prebuilt circuit (batch index 1 under the
    /// Interval statement; see [`Self::prove_epoch_at`]).
    pub fn prove_epoch(
        &mut self,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> CountMinOmcProof {
        self.prove_epoch_at(1, initial_state, batch)
    }

    /// The statement this leaf exposes ([`Expose`]).
    pub fn expose(&self) -> Expose {
        self.expose
    }

    /// Prove the epoch of batch `t` (1-based); `t` is part of the Interval
    /// statement (ignored by the other layouts).
    pub fn prove_epoch_at(
        &mut self,
        t: u64,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> CountMinOmcProof {
        self.batch_index = t;
        let params = self.params;
        let __t_w = std::time::Instant::now();
        let (traces, (_, _, initial_commit, final_commit, batch_commit)) =
            self.run_epoch(initial_state, batch);
        let __witness = __t_w.elapsed();

        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (omc_gl)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify countmin_omc_gl leaf");
        crate::recursion::recursive::timing::record(
            crate::recursion::recursive::timing::LeafTiming {
                witness: __witness,
                prove: __prove,
                verify: __t_v.elapsed(),
                trace_rows: self.trace_rows,
            },
        );

        CountMinOmcProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial_commit,
            final_commit,
            batch_commit,
            params,
        }
    }

    /// Run the circuit on one epoch's witness; returns the traces and inputs.
    fn run_epoch(
        &mut self,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> (p3_circuit::tables::Traces<Challenge>, GlEpoch) {
        let ep = self.epoch(initial_state, batch);
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&ep.0).expect("set pubs");
            runner.set_private_inputs(&ep.1).expect("set privs");
            runner.run().expect("run countmin_omc_gl")
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
    fn epoch(&mut self, initial_state: CountMinState, batch: Vec<CountMinUpdate>) -> GlEpoch {
        let params = self.params;
        assert_eq!(initial_state.params.d, params.d);
        assert_eq!(initial_state.params.w, params.w);
        assert_eq!(batch.len(), params.batch, "batch.len() != params.batch");

        let CmOmcParams { d, w, batch: m } = params;
        let num_cells = params.num_cells();
        let n_ctr = m * d;
        let l = num_cells + n_ctr; // multiset side length

        // ─── Native side ─────────────────────────────────────────────────────
        let binding = self.binding;
        #[allow(unused_mut)]
        let mut final_state = initial_state.clone();
        for u in &batch {
            apply_update_prf_with(&mut final_state, u, binding);
        }
        let digests: Vec<[Val; 4]> = batch.iter().map(|u| key_digest(u.key, binding)).collect();

        // U_ctr (per record, no key-grouping) + counter sort.
        let mut u_ctr_data: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
        for (u, digest) in batch.iter().zip(&digests) {
            for i in 0..d {
                let bucket = bucket_of(digest, i, w);
                u_ctr_data.push(((i * w + bucket) as u64, u.value));
            }
        }
        let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr_data.iter().enumerate().collect();
        indexed.sort_by_key(|(_, (combined, _))| *combined);
        let sigma_ctr: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
        let combined_sorted_native: Vec<u64> = indexed.iter().map(|(_, (c, _))| *c).collect();
        let val_sorted_native: Vec<u32> = indexed.iter().map(|(_, (_, v))| *v).collect();

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
            let ends = if r == n_ctr - 1 {
                true
            } else {
                tag_native[r + 1] == 0
            };
            a_active_native[r] = u32::from(ends);
        }
        // Old value at each row's address (from the HONEST initial state).
        let op_old_native: Vec<u32> = (0..n_ctr)
            .map(|r| {
                let a = combined_sorted_native[r] as usize;
                initial_state.counters[a / w][a % w]
            })
            .collect();
        // The private `op_old` witness per row, and the (address, old value)
        // each active row's W/R elements encode: the sorted address and its
        // committed old value for an honest prover.
        #[allow(unused_mut)]
        let mut op_old_witness: Vec<Challenge> =
            op_old_native.iter().map(|&o| Challenge::from_u32(o)).collect();
        #[allow(unused_mut)]
        let mut mset_addr: Vec<u64> = combined_sorted_native.clone();
        #[allow(unused_mut)]
        let mut mset_old: Vec<u32> = op_old_native.clone();
        #[cfg(test)]
        if let Some((from, to)) = OP_OLD_REDIRECT.with(|c| c.get()) {
            let r = (0..n_ctr)
                .find(|&r| a_active_native[r] == 1 && combined_sorted_native[r] == from)
                .expect("redirect: no active row at `from`");
            let o_to = initial_state.counters[to as usize / w][to as usize % w];
            op_old_witness[r] = redirect_op_old(from, to, o_to);
            mset_addr[r] = to;
            mset_old[r] = o_to;
            let (fr, fc) = (from as usize / w, from as usize % w);
            let (tr, tc) = (to as usize / w, to as usize % w);
            final_state.counters[fr][fc] = initial_state.counters[fr][fc];
            final_state.counters[tr][tc] = o_to.saturating_add(acc_native[r]);
        }

        // Optionally corrupt the COMMITTED final state for the tamper test (the
        // patch is still built from the honest evolution).
        let mut committed_final = final_state.clone();
        if TAMPER_FINAL_CELL.with(|f| f.get()) {
            committed_final.counters[0][0] = committed_final.counters[0][0].wrapping_add(1);
        }
        let initial_commit = commit_countmin(&initial_state);
        let final_commit = commit_countmin(&committed_final);
        let batch_commit = commit_batch_with(&batch, binding);

        // Native multiset elements. None = zero dummy (inactive W/R row); a real
        // element is keyed by (addr, value), carried in-circuit as [2a+1, v].
        let o_cells_native: Vec<u32> = initial_state.counters.iter().flatten().copied().collect();
        let n_cells_native: Vec<u32> = committed_final.counters.iter().flatten().copied().collect();
        let mut input_native: Vec<Option<(u64, u64)>> = Vec::with_capacity(l);
        let mut target_native: Vec<Option<(u64, u64)>> = Vec::with_capacity(l);
        for a in 0..num_cells {
            input_native.push(Some((a as u64, o_cells_native[a] as u64)));
            target_native.push(Some((a as u64, n_cells_native[a] as u64)));
        }
        for r in 0..n_ctr {
            if a_active_native[r] == 1 {
                let addr = mset_addr[r];
                let o = mset_old[r] as u64;
                let n = o + acc_native[r] as u64;
                input_native.push(Some((addr, n))); // W
                target_native.push(Some((addr, o))); // R
            } else {
                input_native.push(None);
                target_native.push(None);
            }
        }
        // Build sigma s.t. input[sigma[r]] == target[r] (multiset matching).
        let mut buckets: HashMap<Option<(u64, u64)>, Vec<usize>> = HashMap::new();
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
        // (op order: counter-sort permute, then multiset permute).
        self.circuit
            .update_permute_witnesses(&[sigma_ctr, sigma_mset])
            .expect("update permute witnesses (countmin_omc_gl)");

        // ─── Public + private values ─────────────────────────────────────────
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&initial_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&final_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&batch_commit));
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        let mut private_inputs: Vec<Challenge> = Vec::new();
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&initial_state));
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&committed_final));
        if binding.is_bound() {
            private_inputs.extend(batch.iter().map(|u| Challenge::from_u32(u.value)));
            for u in &batch {
                private_inputs.extend(bind::key_limbs::<Val>(u.key).into_iter().map(Challenge::from));
                private_inputs.push(Challenge::from_u32(u.value));
            }
        } else {
            private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
            for u in &batch {
                private_inputs.push(Challenge::from_u64(u.key));
                private_inputs.push(Challenge::from_u32(u.value));
            }
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
                (Challenge::from_u64(combined_sorted_native[r - 1])
                    - Challenge::from_u64(combined_sorted_native[r]))
                .try_inverse()
                .expect("nonzero diff inverts")
            };
            private_inputs.push(inv);
        }
        private_inputs.extend_from_slice(&op_old_witness);
        for digest in &digests {
            private_inputs.push(
                Challenge::from_basis_coefficients_slice(&digest[0..2]).expect("2 coeffs"),
            );
            private_inputs.push(
                Challenge::from_basis_coefficients_slice(&digest[2..4]).expect("2 coeffs"),
            );
        }

        (public_inputs, private_inputs, initial_commit, final_commit, batch_commit)
    }
}

fn prove_countmin_omc_impl(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    expose_boundary: bool,
) -> CountMinOmcProof {
    build_countmin_omc_leaf(params, expose_boundary).prove_epoch(initial_state, batch)
}

/// [`prove_countmin_omc`] / [`prove_countmin_omc_exposed`] with an explicit
/// [`Binding`].
pub fn prove_countmin_omc_with(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    expose_boundary: bool,
    binding: Binding,
) -> CountMinOmcProof {
    build_countmin_omc_leaf_with(params, expose_boundary, binding).prove_epoch(initial_state, batch)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip against a **non-empty** prior state: the touched old values
    /// are reconciled against a real committed `M_old`, and the certified
    /// final commitment must equal the natively-applied (GL-PRF) Count-Min.
    #[test]
    fn omc_round_trip_nonempty_prior() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        // Seed a non-trivial prior state with a real prior batch.
        let mut prior = cm_gl_empty(2, 4);
        for u in &[
            CountMinUpdate { key: 3, value: 4 },
            CountMinUpdate { key: 9, value: 2 },
        ] {
            apply_update_prf(&mut prior, u);
        }
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 9, value: 5 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior.clone(), updates);
        assert_eq!(r.initial_commit, commit_countmin(&prior));
        assert_eq!(r.final_commit, commit_countmin(&expect_final));
        assert_ne!(r.initial_commit, r.final_commit);
    }

    /// Exposed-boundary smoke: the forest folds this leaf shape, so the Expose
    /// NPO registration must prove and self-verify.
    #[test]
    fn omc_exposed_smoke() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        let prior = cm_gl_empty(2, 4);
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc_exposed(params, prior, updates);
        assert_eq!(r.final_commit, commit_countmin(&expect_final));
    }

    /// **Tamper.** Commit a corrupted final state (one cell bumped) while the
    /// patch is built from the honest evolution: an untouched cell disagrees
    /// across `M_old`/`M_new`, so the multiset equality fails and self-verify
    /// rejects.
    #[test]
    fn tamper_rejected() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        let prior = cm_gl_empty(2, 4);
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let _ok = prove_countmin_omc(params, prior.clone(), updates.clone());

        TAMPER_FINAL_CELL.with(|f| f.set(true));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prove_countmin_omc(params, prior.clone(), updates.clone());
        }));
        std::panic::set_hook(prev);
        TAMPER_FINAL_CELL.with(|f| f.set(false));
        assert!(
            res.is_err(),
            "corrupted final state must break the multiset equality"
        );
    }

    /// Repeated keys across a non-empty prior: the running sum folds the
    /// duplicates into one read/write pair, reconciled against the prior.
    /// `d=7` also exercises the half-coefficient PRF streams past coeff 3.
    #[test]
    fn omc_repeated_keys_nonempty() {
        let params = CmOmcParams {
            d: 7,
            w: 8,
            batch: 4,
        };
        let mut prior = cm_gl_empty(7, 8);
        apply_update_prf(&mut prior, &CountMinUpdate { key: 7, value: 10 });
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior, updates);
        assert_eq!(r.final_commit, commit_countmin(&expect_final));
    }

    // ── Binding (see `crate::sketch::bind`): legacy-vs-bound forgery tests ──

    use crate::sketch::forge;
    use p3_circuit::ops::{NpoTypeId, Poseidon2Trace};

    const FP: CmOmcParams = CmOmcParams { d: 2, w: 8, batch: 2 };

    fn fp_prior() -> CountMinState {
        let mut s = cm_gl_empty(FP.d, FP.w);
        apply_update_prf(&mut s, &CountMinUpdate { key: 3, value: 4 });
        s
    }

    fn fp_updates() -> Vec<CountMinUpdate> {
        vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 9, value: 5 }]
    }

    fn cfg() -> Poseidon2Config {
        Poseidon2Config::GOLDILOCKS_D2_W8
    }

    /// `prior` advanced by `updates` under `binding`'s native model.
    fn advanced(prior: &CountMinState, updates: &[CountMinUpdate], binding: Binding) -> CountMinState {
        let mut s = prior.clone();
        for u in updates {
            apply_update_prf_with(&mut s, u, binding);
        }
        s
    }

    /// Honest epochs verify under every binding and certify that binding's
    /// native model (final state and batch commitment).
    #[test]
    fn omc_gl_round_trip_all_bindings() {
        for binding in [Binding::Bound, Binding::Semantic, Binding::Legacy] {
            let expect = advanced(&fp_prior(), &fp_updates(), binding);
            let r = prove_countmin_omc_with(FP, fp_prior(), fp_updates(), true, binding);
            assert_eq!(r.final_commit.0, commit_countmin(&expect).0, "{binding:?}");
            assert_eq!(r.batch_commit.0, commit_batch_with(&fp_updates(), binding).0);
        }
        // d > 4 (second digest Challenge) and a 64-bit key (both limbs used).
        let p = CmOmcParams { d: 7, w: 8, batch: 3 };
        let mut ups = fp_updates();
        ups.push(CountMinUpdate { key: 0xFEDC_BA98_7654_3210, value: 2 });
        for binding in [Binding::Bound, Binding::Semantic] {
            let expect = advanced(&cm_gl_empty(7, 8), &ups, binding);
            let r = prove_countmin_omc_with(p, cm_gl_empty(7, 8), ups.clone(), false, binding);
            assert_eq!(r.final_commit.0, commit_countmin(&expect).0);
            assert_eq!(r.batch_commit.0, commit_batch_with(&ups, binding).0);
        }
    }

    /// Two distinct keys congruent mod the Goldilocks `p = 2^64 − 2^32 + 1`
    /// (`k` and `k + p`, both u64 for `k < 2^32 − 1`).
    fn congruent_pair() -> (u64, u64) {
        let p = <Val as PrimeField64>::ORDER_U64;
        (12_345, 12_345 + p)
    }

    /// Native routing: `Legacy` hashes `[key mod p, 0]`, so `k` and `k + p`
    /// share the digest, every bucket and the batch commitment (the
    /// documented control); `Semantic`/`Bound` hash the exact 32-bit limbs.
    #[test]
    fn congruent_keys_native_routing() {
        let (k, t) = congruent_pair();
        let (d, w) = (7usize, 1usize << 14);
        let routes = |key: u64, b: Binding| -> Vec<usize> {
            (0..d).map(|i| hash_cell_prf_with(i, key, w, b)).collect()
        };
        let one = |key: u64| vec![CountMinUpdate { key, value: 1 }];
        assert_eq!(key_digest(k, Binding::Legacy), key_digest(t, Binding::Legacy));
        assert_eq!(routes(k, Binding::Legacy), routes(t, Binding::Legacy));
        assert_eq!(commit_batch_with(&one(k), Binding::Legacy), commit_batch_with(&one(t), Binding::Legacy));
        for binding in [Binding::Semantic, Binding::Bound] {
            let (rk, rt) = (routes(k, binding), routes(t, binding));
            assert!(rk.iter().zip(&rt).all(|(a, b)| a != b), "{binding:?}: {rk:?} vs {rt:?}");
            assert_ne!(commit_batch_with(&one(k), binding), commit_batch_with(&one(t), binding));
        }
    }

    /// Proof level: one batch `[k, k + p]` into an empty sketch. `Legacy`
    /// certifies both records on the same `d` counters (the estimate of `k`
    /// is 2, the documented control); `Semantic`/`Bound` keep them apart.
    #[test]
    fn congruent_keys_legacy_collide_semantic_bound_separate() {
        let (k, t) = congruent_pair();
        let (d, w) = (4usize, 64usize);
        let params = CmOmcParams { d, w, batch: 2 };
        let ups = vec![CountMinUpdate { key: k, value: 1 }, CountMinUpdate { key: t, value: 1 }];
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let expect = advanced(&cm_gl_empty(d, w), &ups, binding);
            let r = prove_countmin_omc_with(params, cm_gl_empty(d, w), ups.clone(), true, binding);
            assert_eq!(r.final_commit.0, commit_countmin(&expect).0, "{binding:?}");
            let est = (0..d).map(|i| expect.counters[i][hash_cell_prf_with(i, k, w, binding)]).min().unwrap();
            assert_eq!(est, if binding.is_bound() { 1 } else { 2 }, "{binding:?}");
        }
    }

    /// FORGED FINAL STATE (transplant): recommit the first packed final
    /// Challenge with cell 0 bumped by 5, rehash. Every forger here runs its
    /// positive control first ([`forge::accepted_with_control`]: the same
    /// pipeline with the honest value must verify).
    fn forged_final(binding: Binding) -> bool {
        forge::accepted_with_control(&format!("cm_gl forged final ({binding:?})"), |f| {
            forged_final_run(binding, f)
        })
    }

    fn forged_final_run(binding: Binding, forge_it: bool) -> bool {
        let mut leaf = build_countmin_omc_leaf_with(FP, true, binding);
        let (mut traces, _) = leaf.run_epoch(fp_prior(), fp_updates());
        let mut forged = advanced(&fp_prior(), &fp_updates(), binding);
        if forge_it {
            forged.counters[0][0] += 5;
        }
        let w = traces.tag_to_witness["cmgl_final_packed_0"];
        forge::set_wid::<Val, Challenge>(&mut traces, w, pack_cells_to_challenge(&forged)[0]);
        forge::rehash_all::<Val, Challenge, _, 8>(&mut traces, cfg(), &make_perm());
        forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
    }

    /// FORGED BATCH RECORD (transplant): route key 7, recommit record 0 as key 1234.
    fn forged_batch(binding: Binding) -> bool {
        forge::accepted_with_control(&format!("cm_gl forged batch ({binding:?})"), |f| {
            forged_batch_run(binding, f)
        })
    }

    fn forged_batch_run(binding: Binding, forge_it: bool) -> bool {
        let mut leaf = build_countmin_omc_leaf_with(FP, true, binding);
        let (mut traces, _) = leaf.run_epoch(fp_prior(), fp_updates());
        let mut recs = fp_updates();
        if forge_it {
            recs[0].key = 1234;
        }
        // Record 0's first batch-sponge Challenge: `[key, value]` (Legacy) or
        // its exact key limbs (Semantic/Bound).
        let w = traces.tag_to_witness["cmgl_batch_packed_0"];
        forge::set_wid::<Val, Challenge>(&mut traces, w, batch_sponge_input(&recs, binding)[0]);
        forge::rehash_all::<Val, Challenge, _, 8>(&mut traces, cfg(), &make_perm());
        forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
    }

    /// FREE SPONGE IV on record 0's routing hash (capacity limb 2 = base 4).
    fn forged_iv(binding: Binding) -> bool {
        forge::accepted_with_control(&format!("cm_gl forged IV ({binding:?})"), |f| {
            forged_iv_run(binding, f)
        })
    }

    fn forged_iv_run(binding: Binding, forge_it: bool) -> bool {
        let mut leaf = build_countmin_omc_leaf_with(FP, true, binding);
        let (mut traces, _) = leaf.run_epoch(fp_prior(), fp_updates());
        let kf0 = traces.tag_to_witness["cmgl_key_field_0"].0;
        let key = NpoTypeId::poseidon2_perm(cfg());
        let mut pt = traces.non_primitive_trace::<Poseidon2Trace<Val>>(&key).expect("p2").clone();
        // Semantic/Bound: the batch sponge starts with the same key Challenge,
        // so take the single-Challenge routing sponge (no second input CTL, or
        // under Bound the last such row: routing is built after the batch).
        let is_k0 = |r: &p3_circuit::ops::Poseidon2CircuitRow<Val>| {
            r.new_start && r.in_ctl[0] && r.input_indices[0] == kf0
        };
        let idx = pt
            .operations
            .iter()
            .position(|r| is_k0(r) && !r.in_ctl[1])
            .or_else(|| pt.operations.iter().rposition(|r| is_k0(r)))
            .expect("record 0 routing hash row");
        let row = &mut pt.operations[idx];
        if forge_it {
            row.input_values[4] += Val::ONE;
        }
        traces.non_primitive_traces.insert(key, Box::new(pt));
        forge::rehash_all::<Val, Challenge, _, 8>(&mut traces, cfg(), &make_perm());
        forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
    }

    // The fork probes run on BabyBear; the GL decompose/IV code paths are the
    // same fork code, so the probes gate the GL Legacy assertions too.
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

    // ── Circuit-level attack: extension-valued `op_old` ─────────────────────
    //
    // The Goldilocks port of `countmin_omc::tests::op_old_redirect_*`. It does
    // not depend on the fork binding decompose coefficients or the sponge IV:
    // `op_old` is a free extension-valued private input, and only the
    // `Semantic` base pin (`pin_u32`) closes the redirect.

    use crate::sketch::forge_permute;

    /// Where a (possibly forged) epoch ended: `Ok(exposed final commitment)`
    /// if it proved and verified, else `Err((runner_rejected, message))`.
    type GlOutcome = Result<[Val; 4], (bool, String)>;

    /// ATTACK — extension-valued `op_old`. `enc(a, v) = (2a + 1) + v·X` is
    /// injective only for BASE `v`: with `op_old = O[to] + t·X`,
    /// `t = 2(to − from)/W` (`X² = W`), both the read and the write element of
    /// the active row at `from` encode address `to`, so the update is
    /// committed at an untouched cell `to` whose committed old value is
    /// non-zero. `proof_level` (`Semantic`/`Bound` only) also forges the
    /// byte hint of `op_old`'s `pin_u32` to `[op_old, 0, 0, 0]`, so the byte
    /// reconstruction equals the extension-valued `op_old` and no runner
    /// conflict remains; only the RangeAir lookup can reject. With
    /// `forged = false` the same plumbing carries the honest values
    /// (control). Returns the outcome, the honest and the claimed state.
    fn op_old_redirect(
        binding: Binding,
        forged: bool,
        proof_level: bool,
    ) -> (GlOutcome, CountMinState, CountMinState) {
        let (d, w, m) = (2usize, 16usize, 2usize);
        let params = CmOmcParams { d, w, batch: m };
        let mut prior = cm_gl_empty(d, w);
        apply_update_prf_with(&mut prior, &CountMinUpdate { key: 3, value: 4 }, binding);
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let addr = |i: usize, key: u64| (i * w + hash_cell_prf_with(i, key, w, binding)) as u64;
        let mut touched: Vec<u64> = updates
            .iter()
            .flat_map(|u| (0..d).map(move |i| addr(i, u.key)))
            .collect();
        let from = touched[0];
        let to = (0..d)
            .map(|i| addr(i, 3))
            .find(|a| !touched.contains(a))
            .expect("a prior-touched cell the batch does not touch");
        let cell = |s: &CountMinState, a: u64| s.counters[a as usize / w][a as usize % w];
        assert!(cell(&prior, to) > 0, "`to` carries a non-zero committed old value");
        touched.sort();
        let r = touched.iter().rposition(|&a| a == from).expect("active row at `from`");
        let honest = advanced(&prior, &updates, binding);
        let mut claimed = honest.clone();
        if forged {
            let delta = cell(&honest, from) - cell(&prior, from);
            claimed.counters[from as usize / w][from as usize % w] = cell(&prior, from);
            claimed.counters[to as usize / w][to as usize % w] = cell(&prior, to) + delta;
        }
        let mut leaf = build_countmin_omc_leaf_with(params, true, binding);
        if proof_level {
            assert!(binding.is_bound(), "Legacy has no base pin on op_old");
            let bytes: Vec<Challenge> = if forged {
                let v = redirect_op_old(from, to, cell(&prior, to));
                vec![v, Challenge::ZERO, Challenge::ZERO, Challenge::ZERO]
            } else {
                let o = cell(&prior, from);
                (0..4).map(|j| Challenge::from_u32((o >> (8 * j)) & 0xFF)).collect()
            };
            let wid = forge_permute::wid_of(&leaf.circuit, leaf.probe_op_old[r]);
            forge_permute::forge_hint(&mut leaf.circuit, wid, bytes);
        }
        OP_OLD_REDIRECT.with(|c| c.set(forged.then_some((from, to))));
        let ran = forge::catch_msg(|| leaf.run_epoch(prior.clone(), updates.clone()));
        OP_OLD_REDIRECT.with(|c| c.set(None));
        let out = match ran {
            Err(m) => Err((true, m)),
            Ok((traces, ep)) => match forge::catch_msg(|| leaf.prove_traces(&traces)) {
                Ok(Ok(proof)) => {
                    let pv = proof
                        .non_primitives
                        .iter()
                        .map(|e| &e.public_values)
                        .find(|v| v.len() == 8)
                        .expect("exposed (init, final)");
                    let fin: [Val; 4] = std::array::from_fn(|i| pv[4 + i]);
                    assert_eq!(fin, ep.3.0, "exposes the committed final state");
                    Ok(fin)
                }
                Ok(Err(e)) => Err((false, e)),
                Err(m) => Err((false, format!("prove panicked: {m}"))),
            },
        };
        (out, honest, claimed)
    }

    /// Witness level. `Legacy` ACCEPTS a proof that commits the increment at
    /// the wrong cell. `Semantic`/`Bound` pin `op_old` to `[0, 2^32)` (base),
    /// so the runner's byte reconstruction conflicts.
    #[test]
    fn op_old_redirect_legacy_accepts_semantic_bound_reject() {
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let what = format!("GL {binding:?} op_old redirect");
            let (ctl, honest, _) = op_old_redirect(binding, false, false);
            eprintln!("{what} control: {ctl:?}");
            assert_eq!(ctl, Ok(commit_countmin(&honest).0), "{what}: control");
            let (out, honest, claimed) = op_old_redirect(binding, true, false);
            eprintln!("{what} forged: {out:?}");
            assert_ne!(claimed, honest);
            if binding.is_bound() {
                assert!(
                    matches!(&out, Err((true, m)) if m.contains("run countmin_omc_gl")
                        && m.contains("WitnessConflict")),
                    "{what}: expected a runner WitnessConflict, got {out:?}"
                );
            } else {
                assert_eq!(
                    out,
                    Ok(commit_countmin(&claimed).0),
                    "{what}: Legacy accepts the redirect (PoC)"
                );
            }
        }
    }

    /// Proof level (`Semantic`/`Bound`): with the base pin's byte hint forged
    /// as well, the verifier rejects on the Range lookup.
    #[test]
    fn op_old_redirect_proof_level_rejected() {
        for binding in [Binding::Semantic, Binding::Bound] {
            let what = format!("GL {binding:?} op_old redirect (proof level)");
            let (ctl, honest, _) = op_old_redirect(binding, false, true);
            eprintln!("{what} control: {ctl:?}");
            assert_eq!(ctl, Ok(commit_countmin(&honest).0), "{what}: control");
            let (out, _, _) = op_old_redirect(binding, true, true);
            eprintln!("{what} forged: {out:?}");
            assert!(
                matches!(&out, Err((false, m)) if m.starts_with("verify:")),
                "{what}: expected a verifier rejection, got {out:?}"
            );
        }
    }
}
