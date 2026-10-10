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

use crate::commitment::hiding::{
    self, CommitFamily, CommitKind, CommitMode, OpeningsGl, SaltGl, commit_flat_gl,
};
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
    GlCommit(hasher.hash_iter(batch_flat(records, binding)))
}

/// The flat base stream [`commit_batch_with`] hashes (and the in-circuit
/// batch sponge absorbs): `[key mod p, value]` per record under `Legacy`,
/// `[lo, hi, value, 0]` under `Semantic`/`Bound`.
fn batch_flat(records: &[CountMinUpdate], binding: Binding) -> Vec<Val> {
    records
        .iter()
        .flat_map(|r| {
            if binding.is_bound() {
                let l = bind::key_limbs::<Val>(r.key);
                vec![l[0], l[1], Val::from_u32(r.value), Val::ZERO]
            } else {
                vec![Val::from_u64(r.key), Val::from_u32(r.value)]
            }
        })
        .collect()
}

/// [`commit_countmin`] under a [`CommitMode`] (revision B2,
/// [`crate::commitment::hiding`]): `Plain` is exactly [`commit_countmin`]
/// (the salt is ignored); `Hiding` is `MyHash([TAG_STATE, CountMin, ρ_0..ρ_5]
/// ‖ cells)` over the same `d·w` counters ([`commit_flat_gl`]), the value a
/// `Hiding` leaf exposes for `Com(S_t; ρ)`.
pub fn commit_countmin_with(state: &CountMinState, mode: CommitMode, salt: &SaltGl) -> GlCommit {
    match mode {
        CommitMode::Plain => commit_countmin(state),
        CommitMode::Hiding => {
            let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
            GlCommit(commit_flat_gl(mode, CommitKind::State, CommitFamily::CountMin, salt, &flat))
        }
    }
}

/// [`commit_batch_with`] under a [`CommitMode`]: `Plain` is exactly
/// [`commit_batch_with`] (the salt is ignored); `Hiding` is `Com(B_t; ρ)` over
/// the same binding-dependent flat encoding (`[key mod p, value]` under
/// `Legacy`, `[lo, hi, value, 0]` under `Semantic`/`Bound`), the value a
/// `Hiding` leaf opened with `batch = ρ` binds.
pub fn commit_batch_salted(
    records: &[CountMinUpdate],
    binding: Binding,
    mode: CommitMode,
    salt: &SaltGl,
) -> GlCommit {
    match mode {
        CommitMode::Plain => commit_batch_with(records, binding),
        CommitMode::Hiding => {
            let flat = batch_flat(records, binding);
            GlCommit(commit_flat_gl(mode, CommitKind::Batch, CommitFamily::CountMin, salt, &flat))
        }
    }
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
    mode: CommitMode,
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
/// Plain commitments ([`build_countmin_omc_leaf_commit`] with
/// [`CommitMode::Plain`]); prove with [`CmOmcLeafCircuit::prove_epoch_at`].
pub fn build_countmin_omc_leaf_expose(
    params: CmOmcParams,
    expose: Expose,
    binding: Binding,
) -> CmOmcLeafCircuit {
    build_countmin_omc_leaf_commit(params, expose, binding, CommitMode::Plain)
}

/// [`build_countmin_omc_leaf_expose`] with an explicit [`CommitMode`]
/// (revision B2, [`crate::commitment::hiding`]). `Plain` is the pre-B2
/// circuit byte for byte (same VK). `Hiding` adds 9 private inputs, the
/// salts of `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)` (init, final, batch;
/// three D = 2 Challenges each), allocated as the FIRST private inputs, and
/// hashes each commitment as `[tag, salt…, inputs…]`, i.e.
/// [`commit_countmin_with`] / [`commit_batch_salted`]. The salts are
/// witnesses, so the VK does not depend on them; prove with
/// [`CmOmcLeafCircuit::prove_epoch_commit`].
pub fn build_countmin_omc_leaf_commit(
    params: CmOmcParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
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

    // B2: the salts of (init, final, batch) are the FIRST 9 private inputs
    // under `Hiding` ([`OpeningsGl::private_inputs`] order); `Plain`
    // allocates nothing, so its circuit is byte-identical.
    // `alloc_leaf_salts_first` panics if any private input precedes them.
    let salts = crate::recursion::recursive::leaf_gl::alloc_leaf_salts_first(&mut b, mode);
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

    // Stage A — bind both states + batch to commitments (salted under
    // `Hiding`: `[tag, salt…, inputs…]`; exactly `bind::hash_slice(inputs)`
    // under `Plain`).
    let fam = CommitFamily::CountMin;
    let digest_init = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::State,
        fam,
        salts.as_ref().map(|s| &s.init),
        &initial_packed,
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
    let digest_batch = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::Batch,
        fam,
        salts.as_ref().map(|s| &s.batch),
        &batch_input,
        zero,
        binding,
    );
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
        mode,
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
    /// statement (ignored by the other layouts). `Plain` circuits only: on a
    /// `Hiding` circuit this would open every commitment with the public
    /// zero salt, so it panics; use [`Self::prove_epoch_commit`] (or, for
    /// the no-op leaf, [`Self::prove_epoch_public_zero`]).
    pub fn prove_epoch_at(
        &mut self,
        t: u64,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> CountMinOmcProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             OpeningsGl::for_leaf(..)"
        );
        self.prove_epoch_opened(t, initial_state, batch, &OpeningsGl::plain())
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`OpeningsGl::for_leaf(seed, CommitFamily::CountMin, t)` for an honest
    /// prover; ignored by a `Plain` circuit). The proof's `initial_commit`,
    /// `final_commit` and `batch_commit` are then `Com(S_{t-1}; ρ^S_{t-1})`,
    /// `Com(S_t; ρ^S_t)` and `Com(B_t; ρ^B_t)`. A `Hiding` circuit panics when
    /// `openings.final_` or `openings.batch` is the public zero salt (never an
    /// honest PRF output). The init salt may be zero only at `t = 1` on the
    /// empty genesis state (leaf 1 of the genesis history opens the public
    /// `Com(S_0; 0)`); a zero init on any other input panics
    /// ([`assert_zero_init_opens_public_state`](crate::commitment::hiding::assert_zero_init_opens_public_state)).
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
        openings: &OpeningsGl,
    ) -> CountMinOmcProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (OpeningsGl::for_leaf), not the public zero salt"
            );
            crate::commitment::hiding::assert_zero_init_opens_public_state(t, openings.init.is_zero(), || {
                initial_state == cm_gl_empty(self.params.d, self.params.w)
            });
        }
        self.prove_epoch_opened(t, initial_state, batch, openings)
    }

    /// The no-op VK-derivation leaf's epoch: all three commitments opened
    /// with [`OpeningsGl::public_zero`], so a batch that changes nothing
    /// exposes `init == final` in either mode. The only path that proves a
    /// `Hiding` leaf with zero final/batch salts, so (like the BabyBear
    /// leaf's) it accepts exactly the VK-derivation leaf's public input
    /// ([`cm_omc_gl_noop_leaf_commit`], and the harness's `PAD_KEY` no-op
    /// batch): batch index `t = 1`, the EMPTY initial state and a batch of
    /// `{ key: 0, value: 0 }` updates. "Every value is 0" alone would not
    /// do: a value-0 batch leaves ANY state unchanged, so a real state would
    /// publish the deterministic, guess-checkable `Com(S_t; 0)` as both init
    /// and final. Input checks only (circuit and VK unchanged), in both modes.
    pub fn prove_epoch_public_zero(
        &mut self,
        t: u64,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> CountMinOmcProof {
        assert!(
            batch.iter().all(|u| u.value == 0),
            "prove_epoch_public_zero is for the no-op leaf: every update must have value 0"
        );
        assert_eq!(t, 1, "prove_epoch_public_zero is for the no-op leaf: it is proved at batch index 1");
        assert!(
            batch.iter().all(|u| *u == CountMinUpdate { key: 0, value: 0 }),
            "prove_epoch_public_zero is for the no-op leaf: every update must be the public no-op \
             {{ key: 0, value: 0 }}"
        );
        let (d, w) = (self.params.d, self.params.w);
        let empty = CountMinState { counters: vec![vec![0u32; w]; d], params: CountMinParams { d, w } };
        assert!(
            initial_state == empty,
            "prove_epoch_public_zero is for the no-op leaf: the initial state must be the empty genesis \
             state (a real state would publish the guess-checkable Com(S; 0))"
        );
        self.prove_epoch_opened(t, initial_state, batch, &OpeningsGl::public_zero())
    }

    /// Shared body of the three `prove_epoch_*` entry points (no opening
    /// checks).
    fn prove_epoch_opened(
        &mut self,
        t: u64,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
        openings: &OpeningsGl,
    ) -> CountMinOmcProof {
        self.batch_index = t;
        let params = self.params;
        let __t_w = std::time::Instant::now();
        let (traces, (_, _, initial_commit, final_commit, batch_commit)) =
            self.run_epoch_commit(initial_state, batch, openings);
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
    #[allow(dead_code)] // test-only since B2: the prove paths run `run_epoch_commit`
    fn run_epoch(
        &mut self,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> (p3_circuit::tables::Traces<Challenge>, GlEpoch) {
        self.run_epoch_commit(initial_state, batch, &OpeningsGl::plain())
    }

    /// [`Self::run_epoch`] with explicit commitment openings (ignored under
    /// `Plain`).
    fn run_epoch_commit(
        &mut self,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
        openings: &OpeningsGl,
    ) -> (p3_circuit::tables::Traces<Challenge>, GlEpoch) {
        let ep = self.epoch(initial_state, batch, openings);
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
    /// `openings` are the commitment salts (ignored under `Plain`).
    fn epoch(
        &mut self,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
        openings: &OpeningsGl,
    ) -> GlEpoch {
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
        let mode = self.mode;
        let initial_commit = commit_countmin_with(&initial_state, mode, &openings.init);
        let final_commit = commit_countmin_with(&committed_final, mode, &openings.final_);
        let batch_commit = commit_batch_salted(&batch, binding, mode, &openings.batch);

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
        if mode.is_hiding() {
            // The salts come first (see `build_countmin_omc_leaf_commit`).
            private_inputs.extend(openings.private_inputs());
        }
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

/// Public **no-op leaf** of the Goldilocks `omc` Count-Min leaf for root-VK
/// derivation (the Goldilocks counterpart of
/// `noop_leaf::cm_omc_noop_leaf_commit`): the empty state and `value = 0`
/// updates (the stream harness's Count-Min no-op), proved at batch index 1
/// through the explicit zero-salt path
/// ([`CmOmcLeafCircuit::prove_epoch_public_zero`], all three salts
/// [`OpeningsGl::public_zero`]), so `ρ_in = ρ_out` and it exposes
/// `init == final` in either mode. The salts and the index are witnesses,
/// so its VK is that of every real leaf of the same parameters and mode.
pub fn cm_omc_gl_noop_leaf_commit(
    params: CmOmcParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
) -> p3_circuit_prover::BatchStarkProof<ConfigWithFriParams> {
    let batch = vec![CountMinUpdate { key: 0, value: 0 }; params.batch];
    build_countmin_omc_leaf_commit(params, expose, binding, mode)
        .prove_epoch_public_zero(1, cm_gl_empty(params.d, params.w), batch)
        .output
        .0
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

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────

    use crate::commitment::hiding::{SaltSeed, rho_batch_gl, rho_state_gl};
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

    const HP: CmOmcParams = CmOmcParams { d: 2, w: 4, batch: 2 };
    const CM: CommitFamily = CommitFamily::CountMin;

    fn hiding_leaf(binding: Binding) -> CmOmcLeafCircuit {
        build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding)
    }

    fn hp_prior(binding: Binding) -> CountMinState {
        advanced(&cm_gl_empty(HP.d, HP.w), &[CountMinUpdate { key: 3, value: 4 }], binding)
    }

    fn hp_batches() -> Vec<Vec<CountMinUpdate>> {
        vec![
            vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }],
            vec![CountMinUpdate { key: 13, value: 2 }, CountMinUpdate { key: 7, value: 4 }],
        ]
    }

    /// Native drift guard: `Plain` is the pre-B2 commitment whatever the
    /// salt; `Hiding` is `MyHash([TAG_STATE | TAG_BATCH, CountMin, ρ…] ‖
    /// flat)` over exactly the pre-B2 flat stream, so equal states at two
    /// versions (two salts) get different commitments.
    #[test]
    fn commit_with_modes() {
        use crate::commitment::hiding::{TAG_BATCH, TAG_STATE};
        let seed = SaltSeed::for_tests(9);
        let (r1, r2) = (rho_state_gl(&seed, CM, 1), rho_state_gl(&seed, CM, 2));
        let s = hp_prior(Binding::Semantic);
        assert_eq!(commit_countmin_with(&s, CommitMode::Plain, &r1), commit_countmin(&s));
        let mut input = vec![Val::from_u64(TAG_STATE), Val::from_u64(CM.id())];
        input.extend_from_slice(&r1.0);
        input.extend(s.counters.iter().flatten().map(|&c| Val::from_u32(c)));
        let want: [Val; 4] = MyHash::new(make_perm()).hash_iter(input);
        let h1 = commit_countmin_with(&s, CommitMode::Hiding, &r1);
        assert_eq!(h1.0, want, "state layout drift");
        assert_ne!(h1, commit_countmin_with(&s, CommitMode::Hiding, &r2));
        assert_ne!(h1, commit_countmin(&s));
        let rb = rho_batch_gl(&seed, CM, 1);
        let ups = hp_batches()[0].clone();
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            assert_eq!(commit_batch_salted(&ups, binding, CommitMode::Plain, &rb), commit_batch_with(&ups, binding));
            let mut input = vec![Val::from_u64(TAG_BATCH), Val::from_u64(CM.id())];
            input.extend_from_slice(&rb.0);
            input.extend(batch_flat(&ups, binding));
            let want: [Val; 4] = MyHash::new(make_perm()).hash_iter(input);
            let hb = commit_batch_salted(&ups, binding, CommitMode::Hiding, &rb);
            assert_eq!(hb.0, want, "{binding:?}: batch layout drift");
            assert_ne!(hb, commit_batch_with(&ups, binding), "{binding:?}");
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
        let ups = hp_batches()[0].clone();
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut leaf = hiding_leaf(binding);
            assert_eq!(leaf.commit_mode(), CommitMode::Hiding);
            let prior = hp_prior(binding);
            let r = leaf.prove_epoch_commit(t, prior.clone(), ups.clone(), &OpeningsGl::for_leaf(&seed, CM, t));
            let expect = advanced(&prior, &ups, binding);
            let init = commit_countmin_with(&prior, CommitMode::Hiding, &rho_state_gl(&seed, CM, t - 1));
            let fin = commit_countmin_with(&expect, CommitMode::Hiding, &rho_state_gl(&seed, CM, t));
            let bc = commit_batch_salted(&ups, binding, CommitMode::Hiding, &rho_batch_gl(&seed, CM, t));
            assert_eq!(r.initial_commit, init, "{binding:?}");
            assert_eq!(r.final_commit, fin, "{binding:?}");
            assert_eq!(r.batch_commit, bc, "{binding:?}");
            assert_ne!(init, commit_countmin(&prior), "{binding:?}: hiding != plain");
            assert_ne!(fin, commit_countmin(&expect), "{binding:?}: hiding != plain");
            assert_ne!(bc, commit_batch_with(&ups, binding), "{binding:?}: hiding != plain");
            let st = read_exposed_statement(&r.output.0);
            assert_eq!(st.init, init.0.to_vec(), "{binding:?}");
            assert_eq!(st.final_, fin.0.to_vec(), "{binding:?}");
            let iv = st.interval.expect("interval layout");
            assert_eq!((iv.lo, iv.hi), (Val::from_u64(t), Val::from_u64(t)));
            assert_eq!(iv.digest, leaf_digest(&hash_gl, 2, t, &bc.0), "{binding:?}: H(TAG_LEAF, t, Com(B_t; ρ))");
        }
        // Boundary layout: the exposed pair is the hiding pair too (leaf 1 of
        // the genesis history, from the empty S_0: its zero init salt opens
        // only that public state).
        for binding in [Binding::Semantic, Binding::Legacy] {
            let mut bleaf = build_countmin_omc_leaf_commit(HP, Expose::Boundary, binding, CommitMode::Hiding);
            let prior = cm_gl_empty(HP.d, HP.w);
            let r = bleaf.prove_epoch_commit(1, prior.clone(), ups.clone(), &OpeningsGl::for_leaf(&seed, CM, 1));
            let (i, f) = read_exposed_boundary_proof(&r.output.0);
            assert_eq!(i, commit_countmin_with(&prior, CommitMode::Hiding, &SaltGl::ZERO), "{binding:?}");
            assert_eq!(f, r.final_commit, "{binding:?}");
            let fin = commit_countmin_with(&advanced(&prior, &ups, binding), CommitMode::Hiding, &rho_state_gl(&seed, CM, 1));
            assert_eq!(f, fin, "{binding:?}");
        }
    }

    /// (2) The hiding leaf's VK does not depend on the salts (two different
    /// openings, and the zero-salt no-op leaf, give one VK), differs from the
    /// Plain VK, and the Plain circuit is the pre-B2 circuit: its VK equals
    /// the value recorded on the unmodified Goldilocks leaf (b2-hiding
    /// @94e9f58), through both the old builder and
    /// `build_countmin_omc_leaf_commit(.., Plain)`, for every statement
    /// layout and binding.
    #[test]
    fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
        #[cfg(not(feature = "zk"))]
        let recorded = [
            (Expose::None, Binding::Legacy, [11253098034312167780, 6111472104168597677, 9057969219549333354, 15624834195553422946]),
            (Expose::None, Binding::Semantic, [15393870867059974150, 5197277875777594513, 13916471621423022434, 3770530916699088781]),
            (Expose::None, Binding::Bound, [9140665954949353592, 6238431330558298535, 1498052926725916503, 13194858194538131478]),
            (Expose::Boundary, Binding::Legacy, [3042929165136131552, 9747001576966743655, 2891353066147790141, 9459168645585591966]),
            (Expose::Boundary, Binding::Semantic, [14519590689671211180, 16247600322728467116, 17571590736827068436, 16803712535656029841]),
            (Expose::Boundary, Binding::Bound, [15415433088234574101, 4542720187869579078, 15849813861365725350, 17091937498901072019]),
            (Expose::Interval, Binding::Legacy, [2005737465954836697, 9314241296366430560, 3601534311278020700, 2167768342133527382]),
            (Expose::Interval, Binding::Semantic, [6918344718897754454, 6129663935149601144, 3951319592497298276, 2838287130005875833]),
            (Expose::Interval, Binding::Bound, [18004278476191420884, 3916738887510153842, 5551060390168597683, 9493829487614614466]),
        ];
        // The same circuits under the `zk` feature: hiding-PCS VKs, recorded on the
        // zk-logup-mask forks (Plonky3 280b1a07, Plonky3_RangeAir 3acdc06), equal
        // across separate processes. The LogUp masks do not move them (main-trace
        // columns; see `config::tests::leaf_opens_logup_mask_columns`).
        #[cfg(feature = "zk")]
        let recorded = [
            (Expose::None, Binding::Legacy, [13990053241392263647, 15196497905194662320, 11760893114052960470, 12532609202950211120]),
            (Expose::None, Binding::Semantic, [4735498081410364905, 9887910684131172578, 9507956603496282953, 17089710893839786296]),
            (Expose::None, Binding::Bound, [5849867602530124715, 15747091349251717946, 16329322739755763526, 10903980084946694554]),
            (Expose::Boundary, Binding::Legacy, [3931495787248871136, 14151049193977100886, 10043256254889462269, 5254571912822669885]),
            (Expose::Boundary, Binding::Semantic, [1522655068916900024, 1487822851690814888, 1195573952753445497, 2860232266040203451]),
            (Expose::Boundary, Binding::Bound, [1443698010911810733, 7761126322843735439, 6511127113485611865, 7363499078777190416]),
            (Expose::Interval, Binding::Legacy, [9734999615456884666, 15688446402401735045, 11297349151012561138, 8446775489295396344]),
            (Expose::Interval, Binding::Semantic, [9522395358186270663, 604315592290528537, 10189453294407303153, 9684638641599018314]),
            (Expose::Interval, Binding::Bound, [8705140589810585446, 5461018876195344916, 2406902569149142381, 8709103986354304347]),
        ];
        for (expose, binding, vk) in recorded {
            let old = build_countmin_omc_leaf_expose(HP, expose, binding).vk_pin_values();
            let plain = build_countmin_omc_leaf_commit(HP, expose, binding, CommitMode::Plain).vk_pin_values();
            assert_eq!(vk_flat(&old), vk_literal(vk), "{expose:?}/{binding:?}: Plain VK drifted from the pre-B2 leaf");
            assert_eq!(plain, old, "{expose:?}/{binding:?}");
            let hid = build_countmin_omc_leaf_commit(HP, expose, binding, CommitMode::Hiding).vk_pin_values();
            assert_ne!(hid, old, "{expose:?}/{binding:?}: the hiding circuit differs");
        }
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = hiding_leaf(binding);
            let vk = leaf.vk_pin_values();
            let ups = hp_batches()[0].clone();
            let o1 = OpeningsGl::for_leaf(&SaltSeed::for_tests(1), CM, 1);
            let o5 = OpeningsGl::for_leaf(&SaltSeed::for_tests(2), CM, 5);
            // Leaf 1 starts from the empty S_0 (its zero init salt opens only
            // that public state); leaf 5 from a real prior.
            let a = leaf.prove_epoch_commit(1, cm_gl_empty(HP.d, HP.w), ups.clone(), &o1);
            let b = leaf.prove_epoch_commit(5, hp_prior(binding), ups, &o5);
            assert_ne!(a.final_commit, b.final_commit);
            assert_eq!(vk_pin_values(&a.output.0), vk, "{binding:?}");
            assert_eq!(vk_pin_values(&b.output.0), vk, "{binding:?}");
            let noop = cm_omc_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
            assert_eq!(vk_pin_values(&noop), vk, "{binding:?}: the zero-salt no-op leaf has the real leaves' VK");
        }
    }

    /// (2b) The Hiding leaf's VK is pinned, one literal per statement layout and binding.
    /// It does not depend on the salts (test (2)), so it is a fixed value per
    /// shape; recorded on b2-gl @77a02a3. The pin guards what the other
    /// tests only compare against the native functions, which would carry the
    /// same change: which sponge each salted commitment uses, the
    /// `(kind, CountMin)` tag constants, and the salt allocation order.
    /// Under `Bound` the three salted sponges are the zero-IV bound sponge
    /// (`hash_slice_bound`); a Hiding leaf that fell back to the plain sponge
    /// there keeps its row counts and still matches the native `_with`
    /// functions, so only this pin sees it.
    #[test]
    fn hiding_leaf_vk_is_pinned() {
        #[cfg(not(feature = "zk"))]
        let recorded = [
            (Expose::None, Binding::Legacy, [1209048783911369258, 3216447902964584638, 12947535799659380384, 5646591501530747128]),
            (Expose::None, Binding::Semantic, [7349006575898561557, 6256196679151424162, 3055476655359237123, 1401001913241464381]),
            (Expose::None, Binding::Bound, [12665347745712431082, 9498482916401844271, 17685773841516715020, 7651120999216484910]),
            (Expose::Boundary, Binding::Legacy, [1396435466495284504, 740194491434253706, 17697181761623709612, 10325467725295208062]),
            (Expose::Boundary, Binding::Semantic, [14733403394272993113, 14221585957395502450, 5133293819085424338, 12939071837758623063]),
            (Expose::Boundary, Binding::Bound, [16712771615301697041, 10215139177040792698, 478190077531758473, 4632644434176259701]),
            (Expose::Interval, Binding::Legacy, [6263751611740419246, 1064263913461478156, 12511219769127999746, 909137269195788339]),
            (Expose::Interval, Binding::Semantic, [17904528877781983934, 8662947022379381733, 4519687381455688719, 4952869705893663476]),
            (Expose::Interval, Binding::Bound, [10025573174721201256, 1147731897123444152, 17223478526520213318, 5401075298436491336]),
        ];
        // The same circuits under the `zk` feature: hiding-PCS VKs, recorded on the
        // zk-logup-mask forks (Plonky3 280b1a07, Plonky3_RangeAir 3acdc06), equal
        // across separate processes. The LogUp masks do not move them (main-trace
        // columns; see `config::tests::leaf_opens_logup_mask_columns`).
        #[cfg(feature = "zk")]
        let recorded = [
            (Expose::None, Binding::Legacy, [6892355000818038717, 9126832647823867408, 1560637912211152191, 6497207872375728217]),
            (Expose::None, Binding::Semantic, [6625960406400864413, 4026841871897624343, 10532234963669588216, 15556054490999977398]),
            (Expose::None, Binding::Bound, [11447754885926847120, 16223156848147146973, 13838045958487994559, 3776638595634508097]),
            (Expose::Boundary, Binding::Legacy, [4798566821910256894, 3068678862434420169, 7153065392270724617, 9689950443067277141]),
            (Expose::Boundary, Binding::Semantic, [12690897353814155929, 7121256085236330840, 10505062560593120007, 13240173348372971459]),
            (Expose::Boundary, Binding::Bound, [3146522810300326681, 11267462543046055733, 12763125157441334071, 3112899402016546181]),
            (Expose::Interval, Binding::Legacy, [11827826063287879682, 12448745107300064980, 2794041674979286320, 204142547800239941]),
            (Expose::Interval, Binding::Semantic, [17783888483177304971, 13823278589892337693, 12816598119146913361, 13475040520198414275]),
            (Expose::Interval, Binding::Bound, [6372342565390004394, 17204711973722110642, 12360014267183666943, 17494367253642146913]),
        ];
        for (expose, binding, vk) in recorded {
            let hid = build_countmin_omc_leaf_commit(HP, expose, binding, CommitMode::Hiding).vk_pin_values();
            assert_eq!(vk_flat(&hid), vk_literal(vk), "{expose:?}/{binding:?}: Hiding VK drifted");
        }
    }

    /// (3) Equal states at two versions get different hiding commitments,
    /// both different from the plain one; at the proof level, two no-op
    /// (value-0) leaves at `t = 1, 2` from the empty genesis state `S`
    /// (leaf 1's zero init salt opens only that public state) expose
    /// `Com(S; 0) → Com(S; ρ_1) → Com(S; ρ_2)`: three distinct values for one
    /// state, chained.
    #[test]
    fn equal_states_get_unlinkable_hiding_commitments() {
        let seed = SaltSeed::for_tests(33);
        let s = hp_prior(Binding::Semantic);
        let (r1, r2) = (rho_state_gl(&seed, CM, 1), rho_state_gl(&seed, CM, 2));
        let (c1, c2) = (
            commit_countmin_with(&s, CommitMode::Hiding, &r1),
            commit_countmin_with(&s, CommitMode::Hiding, &r2),
        );
        assert_ne!(c1, c2);
        assert_ne!(c1, commit_countmin(&s));
        assert_ne!(c2, commit_countmin(&s));
        assert_eq!(commit_countmin_with(&s, CommitMode::Plain, &r1), commit_countmin(&s), "Plain ignores the salt");

        let s = cm_gl_empty(HP.d, HP.w);
        let (c1, c2) = (
            commit_countmin_with(&s, CommitMode::Hiding, &r1),
            commit_countmin_with(&s, CommitMode::Hiding, &r2),
        );
        let zero_batch = vec![CountMinUpdate { key: 1, value: 0 }, CountMinUpdate { key: 2, value: 0 }];
        let mut leaf = hiding_leaf(Binding::Semantic);
        let l1 = leaf.prove_epoch_commit(1, s.clone(), zero_batch.clone(), &OpeningsGl::for_leaf(&seed, CM, 1));
        let l2 = leaf.prove_epoch_commit(2, s.clone(), zero_batch, &OpeningsGl::for_leaf(&seed, CM, 2));
        let (s1, s2) = (read_exposed_statement(&l1.output.0), read_exposed_statement(&l2.output.0));
        assert_eq!(s1.init, commit_countmin_with(&s, CommitMode::Hiding, &SaltGl::ZERO).0.to_vec());
        assert_eq!(s1.final_, c1.0.to_vec());
        assert_eq!(s2.init, s1.final_, "leaf 2 opens Com(S_1) with the same ρ_1");
        assert_eq!(s2.final_, c2.0.to_vec());
        assert_ne!(s1.init, s1.final_, "the state did not move, the commitment did");
        assert_ne!(s2.init, s2.final_);
    }

    /// (4) Binding in Hiding mode, through the auditor paths. Control: two
    /// honest leaves (seed A) pass the per-batch log check, merge, and the
    /// root verifies against the log with the root VK derived from the
    /// zero-salt no-op leaf. A log recomputed with another seed rejects both;
    /// a leaf opened with a wrong batch or final salt mismatches the log;
    /// and a leaf 2 whose init uses a different `ρ_1` than leaf 1's final
    /// cannot be merged (the in-circuit `left.final == right.init`).
    #[test]
    fn wrong_salt_rejected_by_log_and_inconsistent_salt_breaks_merge() {
        let binding = Binding::Semantic;
        let (a, b) = (SaltSeed::for_tests(41), SaltSeed::for_tests(42));
        let bs = hp_batches();
        let s0 = cm_gl_empty(HP.d, HP.w);
        let s1 = advanced(&s0, &bs[0], binding);
        let s2 = advanced(&s1, &bs[1], binding);
        let log_for = |seed: &SaltSeed| {
            let bc: Vec<[Val; 4]> = (0..2)
                .map(|k| commit_batch_salted(&bs[k], binding, CommitMode::Hiding, &rho_batch_gl(seed, CM, k as u64 + 1)).0)
                .collect();
            batch_log(
                &commit_countmin_with(&s0, CommitMode::Hiding, &SaltGl::ZERO).0,
                &commit_countmin_with(&s2, CommitMode::Hiding, &rho_state_gl(seed, CM, 2)).0,
                &bc,
            )
        };
        let (log_a, log_b) = (log_for(&a), log_for(&b));
        let mut leaf = hiding_leaf(binding);
        let l1 = leaf.prove_epoch_commit(1, s0.clone(), bs[0].clone(), &OpeningsGl::for_leaf(&a, CM, 1)).output;
        let l2 = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &OpeningsGl::for_leaf(&a, CM, 2)).output;
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log_a, Expose::Interval), Ok(()));
        assert!(check_leaves_against_log(&[&l1.0, &l2.0], &log_b, Expose::Interval).is_err(), "another seed's log");

        // Leaf 2 opened with a wrong batch salt: its digest H(TAG_LEAF, 2,
        // Com(B_2; ρ')) is not the log's.
        let bad_batch = OpeningsGl { batch: rho_batch_gl(&b, CM, 2), ..OpeningsGl::for_leaf(&a, CM, 2) };
        let l2b = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_batch).output;
        let e = check_leaves_against_log(&[&l1.0, &l2b.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("digest")), "{e:?}");
        // … with a wrong final salt: Com(S_2; ρ') is not the log's Com(S_T).
        let bad_final = OpeningsGl { final_: rho_state_gl(&b, CM, 2), ..OpeningsGl::for_leaf(&a, CM, 2) };
        let l2f = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_final).output;
        let e = check_leaves_against_log(&[&l1.0, &l2f.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("Com(S_T)")), "{e:?}");

        // Composition: the honest pair merges and verifies against log A.
        let shape = ForestShape::forest(2);
        let root = prove_hiding_merge(&l1, &l2);
        let noop = cm_omc_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
        let vk = root_vk_deriver(noop).root_vk(&shape);
        verify_bound_stark_proof_against_log(&root.0, &vk, &log_a, &shape);
        assert!(check_root_against_log(&root.0, &log_b, &shape).is_err());

        // Inconsistent ρ_1 across the boundary: the merge is unprovable.
        let bad_init = OpeningsGl { init: rho_state_gl(&b, CM, 1), ..OpeningsGl::for_leaf(&a, CM, 2) };
        let l2i = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_init).output;
        assert_ne!(read_exposed_statement(&l2i.0).init, read_exposed_statement(&l1.0).final_);
        let e = forge::catch_msg(|| prove_hiding_merge(&l1, &l2i)).map(|_| ());
        println!("B2 GL cm inconsistent salt merge: {e:?}");
        assert!(
            e.as_ref().is_err_and(|m| m.contains("WitnessConflict")),
            "leaf 2's init must use leaf 1's final salt: {e:?}"
        );
    }

    /// (5) The zero-salt no-op leaf of a Hiding circuit still exposes
    /// `init == final` (`= Com(S_0; 0)`, the public anchor), so the twin-merge
    /// root-VK derivation works unchanged; the Plain no-op leaf exposes the
    /// pre-B2 anchor.
    #[test]
    fn hiding_noop_leaf_has_init_eq_final() {
        let empty = cm_gl_empty(HP.d, HP.w);
        for binding in [Binding::Semantic, Binding::Bound] {
            let noop = cm_omc_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
            let st = read_exposed_statement(&noop);
            let anchor = commit_countmin_with(&empty, CommitMode::Hiding, &SaltGl::ZERO);
            assert_eq!(st.init, st.final_, "{binding:?}");
            assert_eq!(st.init, anchor.0.to_vec(), "{binding:?}");
            assert_ne!(anchor, commit_countmin(&empty), "{binding:?}");
        }
        let plain = cm_omc_gl_noop_leaf_commit(HP, Expose::Boundary, Binding::Semantic, CommitMode::Plain);
        let (i, f) = read_exposed_boundary_proof(&plain);
        assert_eq!((i, f), (commit_countmin(&empty), commit_countmin(&empty)));
    }

    /// (F3, F5) The Hiding leaf costs exactly +2 Poseidon2 rows and +3 ALU
    /// rows per commitment over the Plain leaf (3 commitments: +6 and +9)
    /// under every binding, and none of its 18 salt values is a public value
    /// of the proof (the scan's positive control: a "salt" equal to an
    /// exposed commitment value is found).
    #[test]
    fn hiding_leaf_row_overhead_and_no_salt_in_public_values() {
        let seed = SaltSeed::for_tests(91);
        let t = 3u64;
        let ups = hp_batches()[0].clone();
        let o = OpeningsGl::for_leaf(&seed, CM, t);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut plain = build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
            let mut leaf = hiding_leaf(binding);
            let (p0, a0) = trace_rows(&plain.run_epoch(hp_prior(binding), ups.clone()).0);
            let (p1, a1) = trace_rows(&leaf.run_epoch_commit(hp_prior(binding), ups.clone(), &o).0);
            println!("B2 GL cm leaf rows {binding:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 6, "{binding:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 9, "{binding:?}: ALU rows");
            let hid = leaf.prove_epoch_commit(t, hp_prior(binding), ups.clone(), &o);
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
    /// no-op path refuses a batch that moves the state. Controls: a zero INIT
    /// salt is leaf 1's honest opening (from the empty genesis state; a zero
    /// init on a real state is refused, test
    /// `hiding_leaf_refuses_zero_init_on_a_real_state`), and a Plain leaf
    /// still ignores its openings.
    #[test]
    fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
        let seed = SaltSeed::for_tests(81);
        let binding = Binding::Semantic;
        let ups = hp_batches()[0].clone();
        let mut leaf = hiding_leaf(binding);
        let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, hp_prior(binding), ups.clone()).final_commit).unwrap_err();
        assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
        assert!(forge::catch(|| leaf.prove_epoch(hp_prior(binding), ups.clone()).final_commit).is_none());
        let honest = OpeningsGl::for_leaf(&seed, CM, 2);
        for (what, o) in [
            ("plain", OpeningsGl::plain()),
            ("public_zero", OpeningsGl::public_zero()),
            ("zero final", OpeningsGl { final_: SaltGl::ZERO, ..honest }),
            ("zero batch", OpeningsGl { batch: SaltGl::ZERO, ..honest }),
        ] {
            let msg = forge::catch_msg(|| leaf.prove_epoch_commit(2, hp_prior(binding), ups.clone(), &o).final_commit)
                .unwrap_err();
            assert!(msg.contains("public zero salt"), "{what}: {msg}");
        }
        let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, hp_prior(binding), ups.clone()).final_commit)
            .unwrap_err();
        assert!(msg.contains("value 0"), "{msg}");

        let o1 = OpeningsGl::for_leaf(&seed, CM, 1);
        assert!(o1.init.is_zero());
        let s0 = cm_gl_empty(HP.d, HP.w);
        let r = leaf.prove_epoch_commit(1, s0.clone(), ups.clone(), &o1);
        assert_eq!(r.initial_commit, commit_countmin_with(&s0, CommitMode::Hiding, &SaltGl::ZERO));
        let mut plain = build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
        let p = plain.prove_epoch_commit(2, hp_prior(binding), ups.clone(), &OpeningsGl::plain());
        assert_eq!(p.initial_commit, commit_countmin(&hp_prior(binding)));
        assert_eq!(p.final_commit, commit_countmin(&advanced(&hp_prior(binding), &ups, binding)));
        assert_eq!(p.batch_commit, commit_batch_with(&ups, binding));
    }

    /// (F1, init salt) The twin of the BabyBear leaf's test: under `Hiding` a
    /// zero INIT salt opens only the public genesis `Com(S_0; 0)` (batch
    /// index 1, the empty state). Refused, under every binding: a forgotten
    /// init opening on a real prior (`t = 2`), local numbering
    /// (`for_leaf(.., 1)` at global `t = 5` on a real state), leaf 1's
    /// openings on a real prior at `t = 1`, and a zero init at `t = 2` on the
    /// empty state. Controls: the genesis leaf proves and exposes
    /// `Com(S_0; 0)`; a Plain leaf ignores its openings on the same inputs.
    #[test]
    fn hiding_leaf_refuses_zero_init_on_a_real_state() {
        let seed = SaltSeed::for_tests(83);
        let ups = hp_batches()[0].clone();
        let s0 = cm_gl_empty(HP.d, HP.w);
        let forgot = OpeningsGl { init: SaltGl::ZERO, ..OpeningsGl::for_leaf(&seed, CM, 2) };
        let local = OpeningsGl::for_leaf(&seed, CM, 1);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let prior = hp_prior(binding);
            assert_ne!(prior, s0, "precondition: a real (secret) prior");
            let cases = [
                ("forgotten init, real prior", 2u64, prior.clone(), forgot),
                ("local numbering at global t = 5", 5, prior.clone(), local),
                ("leaf-1 openings on a real prior", 1, prior.clone(), local),
                ("zero init at t = 2 on the empty state", 2, s0.clone(), forgot),
            ];
            let mut leaf = hiding_leaf(binding);
            for (what, t, init, o) in &cases {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(*t, init.clone(), ups.clone(), o).final_commit)
                    .unwrap_err();
                assert!(msg.contains("zero init salt"), "{binding:?}/{what}: {msg}");
            }
            let r = leaf.prove_epoch_commit(1, s0.clone(), ups.clone(), &local);
            assert_eq!(r.initial_commit, commit_countmin_with(&s0, CommitMode::Hiding, &SaltGl::ZERO), "{binding:?}");
            if binding == Binding::Semantic {
                let mut plain = build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
                for (what, t, init, o) in &cases {
                    let p = plain.prove_epoch_commit(*t, init.clone(), ups.clone(), o);
                    assert_eq!(p.initial_commit, commit_countmin(init), "Plain/{what}");
                }
            }
        }
    }

    /// The zero-salt no-op path accepts only the public no-op input (batch
    /// index 1, the empty state, every update `{ key: 0, value: 0 }`), the
    /// twin of the BabyBear leaf's test: a value-0 batch leaves ANY state
    /// unchanged, so "every value is 0" alone would let a real state publish
    /// the guess-checkable `Com(S_t; 0)`. Rejected, under every binding and
    /// in either mode: a real state with the canonical no-op batch, the
    /// empty state with value-0 updates on real keys, and the canonical input
    /// at another batch index. Control: the canonical input proves and
    /// exposes `Com(S_0; 0)` as init and final and the zero-salt commitment
    /// of the public batch.
    #[test]
    fn noop_path_accepts_only_the_public_noop_input() {
        let noop = vec![CountMinUpdate { key: 0, value: 0 }; HP.batch];
        let real_keys: Vec<CountMinUpdate> =
            hp_batches()[0].iter().map(|u| CountMinUpdate { key: u.key, value: 0 }).collect();
        let empty = cm_gl_empty(HP.d, HP.w);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let cases = [
                ("real state, canonical no-op batch", 1u64, hp_prior(binding), noop.clone(), "empty genesis state"),
                ("empty state, value-0 real keys", 1, empty.clone(), real_keys.clone(), "public no-op"),
                ("canonical input at t = 2", 2, empty.clone(), noop.clone(), "batch index 1"),
            ];
            for mode in [CommitMode::Hiding, CommitMode::Plain] {
                let mut leaf = build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, mode);
                for (what, t, init, ups, want) in &cases {
                    let msg = forge::catch_msg(|| {
                        leaf.prove_epoch_public_zero(*t, init.clone(), ups.clone()).final_commit
                    })
                    .unwrap_err();
                    assert!(msg.contains(want), "{binding:?}/{mode:?}/{what}: {msg}");
                }
            }
            let r = hiding_leaf(binding).prove_epoch_public_zero(1, empty.clone(), noop.clone());
            let anchor = commit_countmin_with(&empty, CommitMode::Hiding, &SaltGl::ZERO);
            assert_eq!(r.initial_commit, anchor, "{binding:?}");
            assert_eq!(r.final_commit, anchor, "{binding:?}");
            assert_eq!(r.batch_commit, commit_batch_salted(&noop, binding, CommitMode::Hiding, &SaltGl::ZERO), "{binding:?}");
        }
    }

    /// The harness's Goldilocks Count-Min VK-derivation input
    /// (`dist_compose`'s `noop_leaf_input` / `prove_noop_leaf_gl`: the empty
    /// state [`cm_gl_empty`] and `PAD_KEY` records mapped by
    /// `stream_compose::cm_updates_of`, at batch index 1) is exactly the
    /// canonical public no-op input: it passes the tightened
    /// `prove_epoch_public_zero` in either mode and under every binding.
    #[test]
    fn harness_noop_input_is_the_public_noop_input() {
        use crate::experiments::stream_compose::{PAD_KEY, cm_updates_of};
        let batch = cm_updates_of(&vec![PAD_KEY; HP.batch]);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            for mode in [CommitMode::Hiding, CommitMode::Plain] {
                let mut leaf = build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, mode);
                let r = leaf.prove_epoch_public_zero(1, cm_gl_empty(HP.d, HP.w), batch.clone());
                assert_eq!(r.initial_commit, r.final_commit, "{binding:?}/{mode:?}");
                assert_eq!(
                    r.initial_commit,
                    commit_countmin_with(&cm_gl_empty(HP.d, HP.w), mode, &SaltGl::ZERO),
                    "{binding:?}/{mode:?}"
                );
            }
        }
    }

    /// (F2) A continued history is anchored on the previous history's
    /// certified final commitment: history 0 ends at `Com(S_2; ρ_{0,2})`;
    /// history 1 restarts `t` at 1 from `S_2`, its leaf 1 opens the init with
    /// that anchor salt ([`OpeningsGl::for_leaf_after`]) and exposes exactly
    /// the certified value, and both leaves pass the per-batch check against
    /// history 1's log. The zero init salt (what `for_leaf(.., 1)` gives)
    /// would expose the guess-checkable `Com(S_2; 0)`: the leaf refuses it. A
    /// nonzero WRONG anchor salt (not detectable by the leaf) is rejected by
    /// that log.
    #[test]
    fn continued_history_leaf_opens_the_previous_final_commitment() {
        use crate::commitment::hiding::{rho_batch_gl_in, rho_state_gl_in};
        let binding = Binding::Semantic;
        let seed = SaltSeed::for_tests(71);
        let bs = hp_batches();
        let s1 = advanced(&cm_gl_empty(HP.d, HP.w), &bs[0], binding);
        let s2 = advanced(&s1, &bs[1], binding);
        let mut leaf = hiding_leaf(binding);
        let h0_last = leaf.prove_epoch_commit(2, s1, bs[1].clone(), &OpeningsGl::for_leaf(&seed, CM, 2));
        let anchor_salt = rho_state_gl(&seed, CM, 2);
        let anchor = h0_last.final_commit;
        assert_eq!(anchor, commit_countmin_with(&s2, CommitMode::Hiding, &anchor_salt));

        let h = 1u64;
        let s3 = advanced(&s2, &bs[0], binding);
        let s4 = advanced(&s3, &bs[1], binding);
        let o1 = OpeningsGl::for_leaf_after(&anchor_salt, &seed, CM, h);
        let l1 = leaf.prove_epoch_commit(1, s2.clone(), bs[0].clone(), &o1).output;
        let l2 = leaf.prove_epoch_commit(2, s3, bs[1].clone(), &OpeningsGl::for_leaf_in(&seed, CM, h, 2)).output;
        assert_eq!(read_exposed_statement(&l1.0).init, anchor.0.to_vec(), "history 1 starts at history 0's final");
        assert_eq!(read_exposed_statement(&l2.0).init, read_exposed_statement(&l1.0).final_);
        let bc: Vec<[Val; 4]> = (0..2)
            .map(|k| {
                let salt = rho_batch_gl_in(&seed, CM, h, k as u64 + 1);
                commit_batch_salted(&bs[k], binding, CommitMode::Hiding, &salt).0
            })
            .collect();
        let fin = commit_countmin_with(&s4, CommitMode::Hiding, &rho_state_gl_in(&seed, CM, h, 2));
        let log1 = batch_log(&anchor.0, &fin.0, &bc);
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log1, Expose::Interval), Ok(()));

        let zero_init = OpeningsGl { init: SaltGl::ZERO, ..o1 };
        let msg = forge::catch_msg(|| leaf.prove_epoch_commit(1, s2.clone(), bs[0].clone(), &zero_init).final_commit)
            .unwrap_err();
        assert!(msg.contains("zero init salt"), "{msg}");
        let wrong_init = OpeningsGl { init: rho_state_gl(&seed, CM, 1), ..o1 };
        let l1w = leaf.prove_epoch_commit(1, s2, bs[0].clone(), &wrong_init).output;
        let e = check_leaves_against_log(&[&l1w.0, &l2.0], &log1, Expose::Interval);
        assert!(e.as_ref().is_err_and(|m| m.contains("Com(S_0)")), "{e:?}");
    }

    /// (8, with `commitment::hiding::tests::salt_private_inputs_have_alu_creators`)
    /// Build and prove the Hiding leaf at a tiny shape. Under the DEBUG
    /// profile (`cargo test --lib countmin_omc_gl::tests::hiding_leaf_tiny_debug`)
    /// the fork debug-asserts, during the build, that each of the 9 salt
    /// private inputs has an ALU creator.
    #[test]
    fn hiding_leaf_tiny_debug() {
        let p = CmOmcParams { d: 2, w: 4, batch: 1 };
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = build_countmin_omc_leaf_commit(p, Expose::Interval, binding, CommitMode::Hiding);
            let ups = vec![CountMinUpdate { key: 9, value: 2 }];
            let seed = SaltSeed::for_tests(8);
            let r = leaf.prove_epoch_commit(1, cm_gl_empty(2, 4), ups.clone(), &OpeningsGl::for_leaf(&seed, CM, 1));
            let fin = advanced(&cm_gl_empty(2, 4), &ups, binding);
            assert_eq!(r.final_commit, commit_countmin_with(&fin, CommitMode::Hiding, &rho_state_gl(&seed, CM, 1)));
        }
    }
}
