//! **Offline-memory-checking HyperLogLog leaf (`omc`)** — the sound,
//! cross-state realization of the §"Pattern A" Step-5 rebind applied to
//! HyperLogLog, the max-update analogue of [`super::countmin_omc`].
//!
//! HLL keeps `m = 2^b` registers; a record routes to one register
//! `idx = digest[0] mod m` and contributes a rank `ρ = 1 +
//! trailing_zeros(digest[1])`. The per-register update is a **max**
//! (`S_t[idx] = max(S_{t-1}[idx], {ρ routed})`), not the additive patch of
//! Count-Min — that is the only semantic difference from `countmin_omc`.
//!
//! ## The check
//!
//! Treat the `m` registers as timestamped memory; each element is `(addr,
//! value, ts)`. The rebind is one **offline-memory-checking** multiset
//! equality between a write set and a read set:
//!
//! ```text
//!   WS = {(a, S_{t-1}[a], 0)}  ⊎  {(a_z, N_z, 1)}      (init writes ⊎ update writes)
//!   RS = {(a, S_t[a], ft_a)}   ⊎  {(a_z, O_z, 0)}      (final reads ⊎ update reads)
//!   WS  ==  RS        (as multisets over (addr, value, ts))
//! ```
//!
//! with `ft_a ∈ {0,1}`. The time coordinate is what makes it sound under a
//! **max** update: at a touched register the `ts=0` init write can only
//! cancel the `ts=0` update read, forcing `O_z == S_{t-1}[a]` (the genuinely
//! committed old value); the `ts=1` update write then forces `S_t[a] == N_z`.
//! Every untouched register is pinned `S_{t-1}[u] = S_t[u]` (its init write
//! cancels its `ts=0` final read). Without `ts` a max whose write equals its
//! read (`N_z = O_z`) admits a degenerate pairing that lets a prover suppress
//! updates — the additive Count-Min avoids this only because its delta ≥ 1
//! keeps write ≠ read.
//!
//! A companion **max gate** (`N_z ≥ O_z`, `N_z ≥ A_z`, `(N_z−O_z)(N_z−A_z)=0`,
//! all operands range-checked to `RANK_BITS`) explains the touched update,
//! where `A_z = max{ρ routed to a_z}` is a per-register running max over the
//! keys sorted by register. `O[a]/N[a]` are bound to the public
//! `(init_commit, final_commit)` by decomposing the same Poseidon-committed
//! register cells (the dense commitment [`super::countmin_omc`] uses).
//!
//! ## Cost
//!
//! The rebind is one [`CircuitBuilder::add_permute`] over `m + batch`
//! tagged `(addr, val, ts)` elements plus the dense commit/decompose of both
//! ends and the `Θ(batch)` sort + per-record hash: **`Θ(m + batch)`**,
//! flat in the batch's sparsity (unlike the sparse Merkle leaf, whose
//! `Θ(t_max·log m)` routing grows with the touched-register count).
//!
//! ## Hiding commitments (revision B2)
//!
//! [`build_hll_omc_leaf_commit`] with [`CommitMode::Hiding`] salts the three
//! commitments (`Com(S_{t-1})`, `Com(S_t)`, `Com(B_t)`) as described in
//! [`crate::commitment::hiding`], under the [`CommitFamily::HyperLogLog`]
//! tag; the natives are [`commit_hll_omc_with`] and
//! [`hll_omc_batch_commit_salted`], the prover entry point is
//! [`HllOmcLeafCircuit::prove_epoch_commit`] and the no-op leaf's is
//! [`HllOmcLeafCircuit::prove_epoch_public_zero`]. In this module the
//! commitment randomizers are called salts or openings: `ρ` is the HLL
//! rank. [`CommitMode::Plain`] (every pre-B2 API) is byte-identical to the
//! pre-B2 leaf.

use std::collections::HashMap;
use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_permute_trace, generate_poseidon2_trace,
    generate_range_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d4, poseidon2_preprocessor, range_air_builders, range_preprocessor,
        recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::commitment::countmin::commit_countmin;
use crate::commitment::hiding::{self, CommitFamily, CommitKind, CommitMode, Openings, SaltBb};
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::bind::{self, Binding};
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::sketch::countmin::{CountMinParams, CountMinState};
use crate::sketch::countmin_v9::CountMinV9;

const LOG_FINAL_POLY_LEN: usize = 6;
/// Pack `(idx, ρ)` as `idx·2^SHIFT + ρ`. `ρ ≤ Val::bits()+1 < 2^RANK_BITS`,
/// so `SHIFT = RANK_BITS` keeps the packing injective; range-checking
/// `ρ_sorted < 2^RANK_BITS` makes it uniquely invertible.
const SHIFT_VAL_BITS: u64 = 8;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;
/// Range-check window for rank/register comparisons. `ρ ≤ Val::bits()+1`
/// (≈ 32) and registers hold a rank, so both stay well under `2^RANK_BITS`.
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
/// trailing_zeros(digest[1])` over the `val_bits()` window, with digest =
/// `MyHash(bind::key_hash_input(key, binding))`: the four exact 16-bit key
/// limbs `[k0, k1, k2, k3]` under `Semantic`/`Bound`, and `[key mod p, 0, 0,
/// 0]` under `Legacy` (which matches [`super::hll_merkle::route`]
/// bit-for-bit, and routes keys congruent mod `p` to the same register with
/// the same rank). Mirrors the in-circuit derivation.
pub fn route_with(key: u64, m: usize, binding: Binding) -> (usize, u32) {
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 8] = hasher.hash_iter(bind::key_hash_input::<Val>(key, binding));
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
            self.m() % 4 == 0,
            "m = 2^b must be a multiple of 4 (Challenge packing)"
        );
    }
}

/// A self-verified `omc` HLL leaf proof. Commitments are the dense
/// `commit_countmin` digests over the `m` registers (a `d=1, w=m` state), so
/// this chains against a real committed prior register array.
pub struct HllOmcProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: CountMinCommit,
    pub final_commit: CountMinCommit,
    pub batch_commit: CountMinCommit,
    pub params: HllOmcParams,
}

impl HllOmcProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

/// View an `m`-register array as a `d=1, w=m` Count-Min state so the dense
/// `commit_countmin` / packing machinery applies unchanged.
fn regs_to_state(regs: &[u32], b: usize) -> CountMinState {
    let m = 1usize << b;
    let mut st = CountMinV9::new(&CountMinParams { d: 1, w: m });
    st.counters[0][..m].copy_from_slice(&regs[..m]);
    st
}

/// Empty HLL/omc register array (`m = 2^b` zeros) — the stream boundary chain's
/// `S_0`, fed as the first leaf's `initial`.
pub fn hll_omc_empty(b: usize) -> Vec<u64> {
    vec![0u64; 1usize << b]
}

/// Native single-batch advance: max-fold each key's rank `ρ = route(key, m).1`
/// into its register — exactly the update `prove_hll_omc` proves (process
/// default [`Binding`]) — so the resulting register array feeds the next
/// leaf's `initial` and the boundaries chain. `regs.len()` must be `m = 2^b`.
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

/// `Com(S)` for an HLL/omc register array — the same `commit_countmin` over the
/// `(d=1, w=m)` register state the leaf commits, so it equals the leaf's
/// `initial_commit`/`final_commit` and anchors the per-batch chain.
pub fn commit_hll_omc(regs: &[u64], b: usize) -> [Val; 8] {
    let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
    commit_countmin(&regs_to_state(&regs32, b)).0
}

/// [`commit_hll_omc`] under a [`CommitMode`] (revision B2,
/// [`crate::commitment::hiding`]). `Plain` is exactly [`commit_hll_omc`] (the
/// salt is ignored). `Hiding` is `Com(S; salt) = MyHash([TAG_STATE,
/// HyperLogLog, 0, 0, salt…] ‖ regs)` over the same `m` register values
/// [`commit_hll_omc`] hashes, the value a `Hiding` leaf and the omc decoder
/// expose. Its family tag is [`CommitFamily::HyperLogLog`], so an HLL register
/// state no longer collides with the `d = 1, w = m` Count-Min state that
/// [`commit_hll_omc`] (Plain) shares its digest with.
pub fn commit_hll_omc_with(regs: &[u64], b: usize, mode: CommitMode, salt: &SaltBb) -> [Val; 8] {
    let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
    commit_regs_state(&regs_to_state(&regs32, b), mode, salt).0
}

/// The state commitment of a register array viewed as a `d = 1` state:
/// `commit_countmin(state)` under `Plain` (byte-identical to the pre-B2
/// leaf), the HLL-tagged hiding commitment of the same flat under `Hiding`.
fn commit_regs_state(state: &CountMinState, mode: CommitMode, salt: &SaltBb) -> CountMinCommit {
    match mode {
        CommitMode::Plain => commit_countmin(state),
        CommitMode::Hiding => {
            let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
            CountMinCommit(hiding::commit_flat_bb(
                mode,
                CommitKind::State,
                CommitFamily::HyperLogLog,
                salt,
                &flat,
            ))
        }
    }
}

fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    let flat: Vec<Val> = state
        .counters
        .iter()
        .flatten()
        .map(|&c| Val::from_u32(c))
        .collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
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
    let mut hi_and = one;
    for &bit in &bits[m..n] {
        hi_and = b.mul(hi_and, bit);
    }
    let mut lo = zero;
    for i in 0..m {
        lo = b.mul_add(bits[i], pow2_lo[i], lo);
    }
    let prod = b.mul(hi_and, lo);
    b.connect(prod, zero);
}

/// Low-bit count `m` of the canonical gadget: `p = 2^n − 2^m + 1`.
fn canon_low_bits() -> usize {
    let pm1 = <Val as PrimeField64>::as_canonical_u64(&(Val::ZERO - Val::ONE));
    let m = pm1.trailing_zeros() as usize;
    let n = val_bits();
    let expected = ((1u64 << (n - m)) - 1) << m;
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
/// in-circuit boundary-bound forest (mirrors [`super::countmin_omc::prove_countmin_omc_exposed`]).
pub fn prove_hll_omc_exposed(
    params: HllOmcParams,
    initial: Vec<u64>,
    keys: Vec<u64>,
) -> HllOmcProof {
    prove_hll_omc_impl(params, initial, keys, true)
}

/// A built, reusable `omc` HLL leaf: the circuit graph, its prover data, and
/// a registered prover. Build once per `(params, expose_boundary)` and call
/// [`Self::prove_epoch`] per batch — the graph is a pure function of the shape
/// except for the two Permute ops’ trace-generation hints, which each prove
/// swaps in via `Circuit::update_permute_witnesses`. This hoists the dominant
/// per-leaf costs (graph build + AIR/`ProverData` prep) out of the epoch loop.
pub struct HllOmcLeafCircuit {
    params: HllOmcParams,
    binding: Binding,
    expose: Expose,
    mode: CommitMode,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
    table_rows: Vec<usize>,
}

/// Build the reusable `omc` HLL leaf circuit for a shape, with the process
/// default [`Binding`] (`Semantic` unless `ZKSKETCH_BINDING` overrides it).
pub fn build_hll_omc_leaf(params: HllOmcParams, expose_boundary: bool) -> HllOmcLeafCircuit {
    build_hll_omc_leaf_with(params, expose_boundary, bind::default_binding())
}

/// Build the reusable `omc` HLL leaf circuit for a shape and binding.
///
/// [`Binding::Legacy`] is the pre-fix circuit, unchanged (unsound; kept for
/// side-by-side cost runs and the forgery PoCs). [`Binding::Bound`] differs
/// in exactly these places (see [`crate::sketch::bind`]):
/// - every sponge hashes with a bound zero IV;
/// - both register arrays are decomposed with ALU-bound coefficients, each
///   pinned by an exact `RANK_BITS` range check (the same bound the max
///   gadget already assumes of every register operand);
/// - the key is four exact 16-bit limbs, range-checked and ALU-recomposed
///   into the one Challenge the batch commitment and the routing hash both
///   absorb ([`bind::key_from_limbs`]), so the hashed key is a real 64-bit
///   key, not a grindable extension element, and not reduced mod `p`
///   (Legacy's one-coefficient `[key mod p, 0, 0, 0]` routes keys congruent
///   mod `p` identically; `tests::congruent_keys_*`);
/// - the register index is the canonical split of the ALU-bound digest limb
///   0 (private `(pos, hi, dinv)` per record), and `ρ` comes from the
///   canonical bits of the ALU-bound limb 1. Limbs 2 and 3 are base-pinned,
///   and the second digest Challenge carries nothing and is not decomposed;
/// - `idx_sorted[0]` is range-checked exactly.
pub fn build_hll_omc_leaf_with(
    params: HllOmcParams,
    expose_boundary: bool,
    binding: Binding,
) -> HllOmcLeafCircuit {
    build_hll_omc_leaf_expose(params, Expose::from_bool(expose_boundary), binding)
}

/// Build the reusable `omc` HLL leaf circuit with an explicit composition
/// statement ([`Expose`]); `None` / `Boundary` are byte-for-byte
/// [`build_hll_omc_leaf_with`], `Interval` adds the batch index `t` (last
/// public input) and exposes `(init, final, (t, t, 0, 0), H)` with
/// `H = Poseidon2(TAG_LEAF, t, Com(B_t))` over the in-circuit batch digest.
/// Plain commitments ([`build_hll_omc_leaf_commit`] with
/// [`CommitMode::Plain`]).
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
/// `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)` (init, final, batch; three
/// Challenges each), allocated as the FIRST private inputs, and hashes each
/// commitment as `[tag, salt…, inputs…]` under the
/// [`CommitFamily::HyperLogLog`] tag, i.e. [`commit_hll_omc_with`] /
/// [`hll_omc_batch_commit_salted`]. The per-record routing hash is not a
/// commitment and stays unsalted. The salts are witnesses, so the VK does not
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
    let cell_packing = num_cells / 4;
    let l = num_cells + m_batch; // multiset side length

    // ─── Circuit ─────────────────────────────────────────────────────────
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
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
    // under `Hiding` ([`Openings::private_inputs`] order); `Plain` allocates
    // nothing, so its circuit is byte-identical.
    let salts = hiding::alloc_leaf_salts(&mut b, mode);
    let init_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    // Legacy: one field element per key (the key mod p). Semantic/Bound: the
    // four exact 16-bit limbs.
    let key_coeff: Vec<ExprId> = if bound {
        Vec::new()
    } else {
        (0..m_batch)
            .map(|_| b.alloc_private_input("key_coeff"))
            .collect()
    };
    let key_limbs: Vec<[ExprId; 4]> = if bound {
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

    // Bound: per record, the canonical split `(pos, hi, dinv)` of digest limb 0
    // (allocated last; pushed last).
    let split_w: Vec<[ExprId; 3]> = if bound {
        (0..m_batch)
            .map(|_| std::array::from_fn(|_| b.alloc_private_input("split")))
            .collect()
    } else {
        Vec::new()
    };
    let split_c = bound.then(|| bind::SplitConsts::new::<Val, Challenge>(&mut b, addr_bits, one, zero));
    if let Some(&f0) = final_packed.first() {
        b.tag(f0, "hll_final_packed_0").expect("tag");
    }

    // ── Stage A: bind both register arrays + batch to their commitments ──
    // (salted under `Hiding`: `[tag, salt…, inputs…]`; exactly
    // `bind::hash_slice(inputs)` under `Plain`).
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
    // Registers hold a rank < 2^RANK_BITS: an exact byte-aligned range pin.
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
    // Keys → one Challenge each (exact limbs under Semantic/Bound); the batch
    // commitment absorbs them and each routing hash absorbs its own.
    let keys_t: Vec<ExprId> = if bound {
        key_limbs
            .iter()
            .map(|l| bind::key_from_limbs::<Val, Challenge>(&mut b, l))
            .collect()
    } else {
        (0..m_batch)
            .map(|k| {
                b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_coeff[k], zero, zero, zero])
                    .expect("recompose key")
            })
            .collect()
    };
    if let Some(&k0) = keys_t.first() {
        b.tag(k0, "hll_keys_t_0").expect("tag");
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
        let (idx, rho) = if let Some(sc) = &split_c {
            // Limb 0 → canonical split (idx = pos); limb 1 → canonical bits (ρ);
            // limbs 2, 3 → base pins. The ALU binding ties all four to the digest.
            let [pos, hi, dinv] = split_w[k];
            let mut dbits: Vec<ExprId> = Vec::new();
            let _ = bind::decompose::<Val, Challenge>(
                &mut b,
                key_h0[k],
                binding,
                |b, i, c| match i {
                    0 => {
                        let x = bind::canonical_split_gadget::<Val, Challenge>(b, pos, hi, dinv, sc);
                        b.connect(x, c);
                    }
                    1 => {
                        dbits = b.decompose_to_bits::<Val>(c, val_bits()).expect("bits digest1");
                        assert_canonical_bits(b, &dbits, &canon_pow2, one, zero);
                    }
                    _ => {}
                },
                |b, i, c| {
                    if i >= 2 {
                        bind::pin_base::<Val, Challenge>(b, c);
                    }
                },
            );
            // ρ = 1 + trailing_zeros(digest[1]) = 1 + Σ_k ∏_{i≤k}(1 − bit_i).
            let mut acc_zero = b.sub(one, dbits[0]);
            let mut tz = acc_zero;
            for k2 in 1..val_bits() {
                let omb = b.sub(one, dbits[k2]);
                acc_zero = b.mul(acc_zero, omb);
                tz = b.add(tz, acc_zero);
            }
            (pos, b.add(tz, one))
        } else {
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
            // Consume the remaining (unused) decompose coeffs: only c0[0]=idx and
            // c0[1]=ρ carry routing; c0[2..4], c1[0..4] are already pinned by the
            // recompose table, so each just needs to flow through one ALU lhs.
            // A self-mul is the cheapest such read (`add(x, 0)` would const-fold
            // away and leave the coeff unconstrained); the old full-width
            // `decompose_to_bits` here was pure waste (RangeAir refactor).
            for idx2 in 2..4 {
                let _ = b.mul(c0[idx2], c0[idx2]);
            }
            for idx2 in 0..4 {
                let _ = b.mul(c1[idx2], c1[idx2]);
            }
            (idx, rho)
        };
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
            // First sorted register exact; later ones follow by range-checked gaps.
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

    // ── Recommit (offline memory checking): WS ⊎ = RS with a time coordinate ─
    // enc(a, v, ts) = recompose([a, v, ts, 1]) — coord-3 tag=1 keeps real
    // elements disjoint from the zero dummies inactive update rows produce; the
    // `ts` in coord-2 forces the read at a touched cell to see the ts=0 init
    // value, binding op_old to the committed old register (the max fix).
    let enc = |b: &mut CircuitBuilder<Challenge>, a: ExprId, v: ExprId, ts: ExprId| -> ExprId {
        b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[a, v, ts, one])
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

    let circuit = b.build().expect("build hll_omc circuit");

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    preprocessors.push(range_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    if expose.exposes() {
        preprocessors.push(expose_preprocessor::<Val>());
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
    }

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (hll_omc)");
    // E-0 table probe (read-only; a no-op unless armed).
    crate::experiments::table_probe::record_leaf(
        "hll_omc",
        &table_packing,
        &airs_degrees,
        &non_primitive_columns,
        &primitive_columns,
    );
    crate::experiments::table_probe::maybe_stop();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_permute_table::<4>();
    prover.register_range_table::<4>();
    if expose.exposes() {
        prover.register_expose_table::<4>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();
    let table_rows: Vec<usize> = ext_degrees.iter().map(|&d| 1usize << d).collect();

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
        table_rows,
    }
}

/// The witness of one epoch: runner inputs plus the natively computed
/// commitments.
struct HllOmcEpoch {
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    initial_commit: CountMinCommit,
    final_commit: CountMinCommit,
    batch_commit: [Val; 8],
}

impl HllOmcLeafCircuit {
    pub fn params(&self) -> HllOmcParams {
        self.params
    }
    pub fn binding(&self) -> Binding {
        self.binding
    }
    /// The commitment mode the circuit was built with.
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }
    /// The VK pin values ([`crate::recursion::recursive::expose_forest::vk_pin_values`])
    /// of every proof this prebuilt leaf produces, read from its prover data
    /// (derived from the public parameters alone, without proving).
    pub fn vk_pin_values(&self) -> Vec<Challenge> {
        crate::recursion::recursive::expose_forest::common_vk_pin_values(
            self.circuit_prover_data.common_data(),
        )
    }
    /// `Σ 2^degree` over all tables.
    pub fn trace_rows(&self) -> u64 {
        self.trace_rows
    }
    /// Padded height of each table (AIR order).
    pub fn table_rows(&self) -> &[usize] {
        &self.table_rows
    }

    /// Prove one epoch on the prebuilt circuit. `initial` is the `m` register
    /// values; `keys` is the `params.batch` record keys. (Batch index 1 under
    /// the Interval statement; see [`Self::prove_epoch_at`].) `Plain`
    /// circuits only, like [`Self::prove_epoch_at`].
    pub fn prove_epoch(&mut self, initial: Vec<u64>, keys: Vec<u64>) -> HllOmcProof {
        self.prove_epoch_at(1, initial, keys)
    }

    /// The statement this leaf exposes ([`Expose`]).
    pub fn expose(&self) -> Expose {
        self.expose
    }

    /// Prove the epoch of batch `t` (1-based); `t` is part of the Interval
    /// statement (ignored by the other layouts). `Plain` circuits only: on a
    /// `Hiding` circuit this would open every commitment with the public zero
    /// salt, so it panics; use [`Self::prove_epoch_commit`] (or, for the
    /// no-op leaf, [`Self::prove_epoch_public_zero`]).
    pub fn prove_epoch_at(&mut self, t: u64, initial: Vec<u64>, keys: Vec<u64>) -> HllOmcProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             Openings::for_leaf(..)"
        );
        self.prove_epoch_opened(t, initial, keys, &Openings::plain())
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`Openings::for_leaf(seed, CommitFamily::HyperLogLog, t)` for an honest
    /// prover; ignored by a `Plain` circuit). The proof's `initial_commit`,
    /// `final_commit` and `batch_commit` are then `Com(S_{t-1}; salt^S_{t-1})`,
    /// `Com(S_t; salt^S_t)` and `Com(B_t; salt^B_t)`. A `Hiding` circuit panics
    /// when `openings.final_` or `openings.batch` is the public zero salt
    /// (never an honest PRF output): a forgotten opening would otherwise give a
    /// consistent, deterministic chain that nothing downstream detects. The
    /// init salt may be zero only at `t = 1` on the empty genesis registers (or
    /// the public no-op state `S_noop`) (leaf 1 of the genesis history opens
    /// the public `Com(S_0; 0)`); a zero init on any other input panics
    /// ([`assert_zero_init_opens_public_state`](crate::commitment::hiding::assert_zero_init_opens_public_state)).
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial: Vec<u64>,
        keys: Vec<u64>,
        openings: &Openings,
    ) -> HllOmcProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (Openings::for_leaf), not the public zero salt"
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
    /// with [`Openings::public_zero`], so a batch that changes nothing
    /// exposes `init == final` in either mode. The only path that proves a
    /// `Hiding` leaf with zero final/batch salts, so it accepts exactly the
    /// public no-op input: batch index `t = 1`, `initial` is key 1 inserted
    /// into empty registers (under this leaf's binding) and every key is 1
    /// (the `t` check comes last, after the input checks). It publishes only
    /// `Com(S_noop; 0)` and `Com([1; batch]; 0)`, commitments to public
    /// data. "No key raises its register" alone would not do for HLL: a real
    /// batch of repeated keys often raises nothing, and would then publish
    /// the deterministic (guess-checkable) commitments of a secret state and
    /// of real keys.
    pub fn prove_epoch_public_zero(&mut self, t: u64, initial: Vec<u64>, keys: Vec<u64>) -> HllOmcProof {
        let mut after = initial.clone();
        hll_omc_advance_with(&mut after, &keys, self.params.m(), self.binding);
        assert!(
            after == initial,
            "prove_epoch_public_zero is for the no-op leaf: no key may raise its register"
        );
        let mut noop = hll_omc_empty(self.params.b);
        hll_omc_advance_with(&mut noop, &[1], self.params.m(), self.binding);
        assert!(
            initial == noop && keys.iter().all(|&k| k == 1),
            "prove_epoch_public_zero is for the no-op leaf: the public no-op input only (initial = key 1 \
             in empty registers, every key 1)"
        );
        assert_eq!(t, 1, "prove_epoch_public_zero is for the no-op leaf: it is proved at batch index 1");
        self.prove_epoch_opened(t, initial, keys, &Openings::public_zero())
    }

    /// Shared body of the three `prove_epoch_*` entry points (no opening
    /// checks).
    fn prove_epoch_opened(
        &mut self,
        t: u64,
        initial: Vec<u64>,
        keys: Vec<u64>,
        openings: &Openings,
    ) -> HllOmcProof {
        self.batch_index = t;
        let params = self.params;
        let __t_w = std::time::Instant::now();
        let (traces, ep) = self.run_epoch_commit(&initial, &keys, openings);
        let __witness = __t_w.elapsed();

        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (hll_omc)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify hll_omc leaf");
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
            initial_commit: ep.initial_commit,
            final_commit: ep.final_commit,
            batch_commit: CountMinCommit(ep.batch_commit),
            params,
        }
    }

    /// Run the circuit on one epoch's witness with the Plain (all-zero,
    /// ignored by a `Plain` circuit) openings; returns the traces (for the
    /// forgery tests) and the epoch.
    #[cfg(test)]
    fn run_epoch(
        &mut self,
        initial: &[u64],
        keys: &[u64],
    ) -> (p3_circuit::tables::Traces<Challenge>, HllOmcEpoch) {
        self.run_epoch_commit(initial, keys, &Openings::plain())
    }

    /// Run the circuit on one epoch's witness with explicit commitment
    /// openings (at the current batch index); returns the traces and the
    /// epoch.
    fn run_epoch_commit(
        &mut self,
        initial: &[u64],
        keys: &[u64],
        openings: &Openings,
    ) -> (p3_circuit::tables::Traces<Challenge>, HllOmcEpoch) {
        let ep = self.epoch(initial, keys, openings);
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&ep.public_inputs).expect("set pubs");
            runner
                .set_private_inputs(&ep.private_inputs)
                .expect("set privs");
            runner.run().expect("run hll_omc")
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
        self.prover
            .verify_all_tables(&proof)
            .map_err(|e| format!("verify: {e:?}"))?;
        Ok(proof)
    }

    /// Native side of one epoch: route + sort + max-fold + multiset matching,
    /// the two permutation hints swapped into the graph, and the runner inputs.
    /// `openings` are the commitment salts (ignored under `Plain`).
    fn epoch(&mut self, initial: &[u64], keys: &[u64], openings: &Openings) -> HllOmcEpoch {
        let params = self.params;
        let HllOmcParams { b, batch: m_batch } = params;
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
        // adjacent (mirrors countmin_omc's counter sort).
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
        // the state UNCHANGED. Pre-fix this produced an accepting proof for a wrong
        // final; the ts-based read binding must now make the multiset unmatchable.
        if TAMPER_SUPPRESS.with(|f| f.get()) {
            for r in 0..m_batch {
                if a_active_native[r] == 1 {
                    op_old_native[r] = acc_native[r];
                    op_new_native[r] = acc_native[r];
                }
            }
            final_regs = init_regs.clone(); // commit no change
        }

        let init_state = regs_to_state(&init_regs, b);
        let mut committed_final_regs = final_regs.clone();
        if TAMPER_FINAL_CELL.with(|f| f.get()) {
            committed_final_regs[0] = committed_final_regs[0].wrapping_add(1);
        }
        let committed_final = regs_to_state(&committed_final_regs, b);
        let mode = self.mode;
        let initial_commit = commit_regs_state(&init_state, mode, &openings.init);
        let final_commit = commit_regs_state(&committed_final, mode, &openings.final_);

        // Batch commitment over the keys (one Challenge each).
        let batch_commit: [Val; 8] = hll_omc_batch_commit_salted(keys, binding, mode, &openings.batch);

        // Dense old/new register multisets + touched read/write rows, in the
        // offline-memory-checking read/write-set form with a time coordinate `ts`:
        //   write set  = init-writes (a, o[a], ts=0) ⊎ update-writes (idx, N, ts=1)
        //   read set   = final-reads (a, n[a], ts=ft_a) ⊎ update-reads (idx, O, ts=0)
        // The `ts` breaks the max-degenerate pairing: a touched cell's ts=0 init
        // write can only cancel the ts=0 update read, forcing O == committed old
        // value (a plain additive Count-Min needs no `ts`, but max's write==read
        // case does — see the soundness note in the module header).
        let o_cells_native: Vec<u32> = init_state.counters[0].clone();
        let n_cells_native: Vec<u32> = committed_final.counters[0].clone();
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
        // (op order: register-sort permute, then multiset permute).
        self.circuit
            .update_permute_witnesses(&[sigma_reg, sigma_mset])
            .expect("update permute witnesses (hll_omc)");

        // ─── Public + private values (order matches allocation) ──────────────
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&initial_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&final_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&CountMinCommit(batch_commit)));
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            // The salts come first (see `build_hll_omc_leaf_commit`).
            private_inputs.extend(openings.private_inputs());
        }
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&init_state));
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&committed_final));
        if binding.is_bound() {
            for &k in keys {
                private_inputs.extend(bind::key_limbs::<Val>(k).into_iter().map(Challenge::from));
            }
        } else {
            for &k in keys {
                private_inputs.push(Challenge::from_u64(k));
            }
        }
        let digests: Vec<[Val; 8]> = {
            let hasher = MyHash::new(make_perm());
            keys.iter()
                .map(|&k| hasher.hash_iter(bind::key_hash_input::<Val>(k, binding)))
                .collect()
        };
        for digest in &digests {
            private_inputs.push(
                Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 coeffs"),
            );
        }
        for digest in &digests {
            private_inputs.push(
                Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 coeffs"),
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

        if binding.is_bound() {
            for digest in &digests {
                private_inputs.extend(
                    bind::canonical_split_vals::<Val>(digest[0], b).map(Challenge::from),
                );
            }
        }

        HllOmcEpoch {
            public_inputs,
            private_inputs,
            initial_commit,
            final_commit,
            batch_commit,
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

/// The batch commitment `Com(B_t)` the omc HLL leaf binds in-circuit (the
/// sponge over the keys, one extension element each): what the public log
/// publishes for the batch. Process default [`Binding`].
pub fn hll_omc_batch_commit(keys: &[u64]) -> [Val; 8] {
    hll_omc_batch_commit_with(keys, bind::default_binding())
}

/// [`hll_omc_batch_commit`] for an explicit [`Binding`]: each key's
/// Challenge is its exact 16-bit limbs `[k0, k1, k2, k3]` under
/// `Semantic`/`Bound` and `[key mod p, 0, 0, 0]` under `Legacy`
/// ([`bind::key_hash_input`]).
pub fn hll_omc_batch_commit_with(keys: &[u64], binding: Binding) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    let flat: Vec<Val> = keys
        .iter()
        .flat_map(|&k| bind::key_hash_input::<Val>(k, binding))
        .collect();
    hasher.hash_iter(flat.iter().copied())
}

/// [`hll_omc_batch_commit_with`] under a [`CommitMode`] (revision B2):
/// `Plain` is exactly [`hll_omc_batch_commit_with`] (the salt is ignored);
/// `Hiding` is `Com(B_t; salt) = MyHash([TAG_BATCH, HyperLogLog, 0, 0,
/// salt…] ‖ keys)` over the same binding-dependent key encoding (one
/// Challenge per key), the value a `Hiding` leaf opened with `batch = salt`
/// binds and the log publishes.
pub fn hll_omc_batch_commit_salted(keys: &[u64], binding: Binding, mode: CommitMode, salt: &SaltBb) -> [Val; 8] {
    match mode {
        CommitMode::Plain => hll_omc_batch_commit_with(keys, binding),
        CommitMode::Hiding => {
            let flat: Vec<Val> = keys
                .iter()
                .flat_map(|&k| bind::key_hash_input::<Val>(k, binding))
                .collect();
            hiding::commit_flat_bb(mode, CommitKind::Batch, CommitFamily::HyperLogLog, salt, &flat)
        }
    }
}

/// Prove batch `t` (1-based) as an **Interval-statement** HLL leaf (process
/// default [`Binding`]).
pub fn prove_hll_omc_interval(
    params: HllOmcParams,
    t: u64,
    initial: Vec<u64>,
    keys: Vec<u64>,
) -> HllOmcProof {
    build_hll_omc_leaf_expose(params, Expose::Interval, bind::default_binding())
        .prove_epoch_at(t, initial, keys)
}

/// [`prove_hll_omc_interval`] with an explicit [`CommitMode`] and the
/// openings of leaf `t` (process default [`Binding`]). Under `Hiding`, zero
/// final/batch salts panic ([`HllOmcLeafCircuit::prove_epoch_commit`]).
pub fn prove_hll_omc_interval_commit(
    params: HllOmcParams,
    t: u64,
    initial: Vec<u64>,
    keys: Vec<u64>,
    mode: CommitMode,
    openings: &Openings,
) -> HllOmcProof {
    build_hll_omc_leaf_commit(params, Expose::Interval, bind::default_binding(), mode)
        .prove_epoch_commit(t, initial, keys, openings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Canonical gadget logic** — mirrors `assert_canonical_bits`' arithmetic
    /// in plain integers for the BabyBear modulus and confirms it flags EXACTLY
    /// the non-canonical (`x + p`) decompositions. Soundness check for the
    /// routing-canonicity fix.
    #[test]
    fn canonical_gadget_logic() {
        let n = val_bits();
        let pm1 = <Val as PrimeField64>::as_canonical_u64(&(Val::ZERO - Val::ONE));
        let m = canon_low_bits(); // also asserts p = 2^n − 2^m + 1 (BabyBear)
        let p = pm1 as u128 + 1;
        let rejected = |v: u128| -> bool {
            let hi_mask = (1u128 << (n - m)) - 1;
            let hi_all = ((v >> m) & hi_mask) == hi_mask;
            let lo_nonzero = (v & ((1u128 << m) - 1)) != 0;
            hi_all && lo_nonzero
        };
        for &x in &[0u64, 1, 7, 255, pm1 - 1, pm1] {
            assert!(!rejected(x as u128), "canonical {x} wrongly rejected");
        }
        let cprime = (1u128 << n) - p; // == 2^m − 1
        for x in 0u64..6 {
            if (x as u128) < cprime {
                let v = x as u128 + p;
                assert!(v < (1u128 << n), "x+p must fit n bits");
                assert!(rejected(v), "non-canonical {v} (= {x}+p) not rejected");
            }
        }
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
            r.initial_commit.0,
            commit_countmin(&regs_to_state(
                &prior.iter().map(|&x| x as u32).collect::<Vec<_>>(),
                params.b
            ))
            .0
        );
        assert_eq!(
            r.final_commit.0,
            commit_countmin(&regs_to_state(&expect, params.b)).0,
            "omc final commit must equal natively max-folded HLL"
        );
        assert_ne!(r.initial_commit.0, r.final_commit.0);
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
        assert_eq!(
            r.final_commit.0,
            commit_countmin(&regs_to_state(&expect, params.b)).0
        );
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
    /// unchanged committed final. Before the `ts` read-binding this produced an
    /// accepting proof for a wrong (unchanged) state; now the ts=0 init write can
    /// only cancel the ts=0 read, so no multiset matching exists and proving fails.
    #[test]
    fn suppression_rejected() {
        let params = HllOmcParams { b: 3, batch: 8 };
        let m = params.m();
        let initial = vec![0u64; m]; // empty prior ⇒ every routed record MUST raise
        let keys: Vec<u64> = vec![7, 11, 13, 17, 3, 5, 19, 23];
        // Honest proof accepts and actually changes the state.
        let honest = prove_hll_omc(params, initial.clone(), keys.clone());
        assert_ne!(
            honest.initial_commit.0, honest.final_commit.0,
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
        Poseidon2Config::BABY_BEAR_D4_W16
    }

    /// Honest epochs verify under every binding and certify that binding's
    /// native model (register fold and batch commitment).
    #[test]
    fn omc_round_trip_both_bindings() {
        for binding in [Binding::Bound, Binding::Semantic, Binding::Legacy] {
            let expect = native_final_with(FP.b, &fp_prior(), &FP_KEYS, binding);
            let r = prove_hll_omc_with(FP, fp_prior(), FP_KEYS.to_vec(), true, binding);
            assert_eq!(
                r.final_commit.0,
                commit_countmin(&regs_to_state(&expect, FP.b)).0,
                "{binding:?}"
            );
            assert_eq!(r.batch_commit.0, hll_omc_batch_commit_with(&FP_KEYS, binding));
        }
        // A larger register file (b = 10) for the split at a realistic width,
        // with 64-bit keys (every key limb non-zero).
        let p = HllOmcParams { b: 10, batch: 8 };
        let keys: Vec<u64> = (0..8u64).map(|i| (i * 7919 + 3) ^ 0xA5A5_0000_5A5A_0000).collect();
        for binding in [Binding::Bound, Binding::Semantic] {
            let expect = native_final_with(p.b, &vec![0; p.m()], &keys, binding);
            let r = prove_hll_omc_with(p, vec![0; p.m()], keys.clone(), false, binding);
            assert_eq!(r.final_commit.0, commit_countmin(&regs_to_state(&expect, p.b)).0);
            assert_eq!(r.batch_commit.0, hll_omc_batch_commit_with(&keys, binding));
        }
    }

    /// First `k ≥ 12_345` whose congruent twin `k + p` (both 32-bit) lands in
    /// a DIFFERENT register under the exact-limb encoding (`2^b` registers).
    fn congruent_pair(m: usize) -> (u64, u64) {
        let p = <Val as PrimeField64>::ORDER_U64;
        (12_345u64..)
            .map(|k| (k, k + p))
            .find(|&(k, t)| route_with(k, m, Binding::Semantic).0 != route_with(t, m, Binding::Semantic).0)
            .expect("a separated pair")
    }

    /// Native routing of keys congruent mod `p`. `Legacy` hashes `[key mod p,
    /// 0, 0, 0]`, so `k` and `k + p` (both 32-bit) get the same register, the
    /// same rank and the same batch commitment (the documented control);
    /// `Semantic`/`Bound` hash the exact 16-bit limbs and separate them.
    #[test]
    fn congruent_keys_native_routing() {
        let m = 1usize << 10;
        let p = <Val as PrimeField64>::ORDER_U64;
        for k in [0u64, 1, 12_345, (1u64 << 32) - p - 1] {
            let t = k + p;
            assert!(t < 1 << 32);
            assert_eq!(route_with(k, m, Binding::Legacy), route_with(t, m, Binding::Legacy));
            assert_eq!(
                hll_omc_batch_commit_with(&[k], Binding::Legacy),
                hll_omc_batch_commit_with(&[t], Binding::Legacy)
            );
            for binding in [Binding::Semantic, Binding::Bound] {
                assert_ne!(
                    hll_omc_batch_commit_with(&[k], binding),
                    hll_omc_batch_commit_with(&[t], binding),
                    "{binding:?}"
                );
            }
        }
        let (k, t) = congruent_pair(m);
        assert_ne!(route_with(k, m, Binding::Bound), route_with(t, m, Binding::Bound));
        assert_eq!(route_with(k, m, Binding::Semantic), route_with(k, m, Binding::Bound));
    }

    /// Proof level: one batch `[k, k + p]` into empty registers. `Legacy`
    /// certifies ONE raised register (the two keys are indistinguishable, so
    /// the cardinality sketch counts one key: the documented control);
    /// `Semantic`/`Bound` certify two.
    #[test]
    fn congruent_keys_legacy_collide_semantic_bound_separate() {
        let params = HllOmcParams { b: 10, batch: 2 };
        let (k, t) = congruent_pair(params.m());
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let expect = native_final_with(params.b, &vec![0; params.m()], &[k, t], binding);
            let r = prove_hll_omc_with(params, vec![0; params.m()], vec![k, t], true, binding);
            assert_eq!(r.final_commit.0, commit_countmin(&regs_to_state(&expect, params.b)).0);
            let raised = expect.iter().filter(|&&x| x > 0).count();
            assert_eq!(raised, if binding.is_bound() { 2 } else { 1 }, "{binding:?}");
        }
    }

    /// FORGED FINAL STATE (transplant): recommit the first packed register
    /// Challenge with register 0 raised by one, then rehash. The multiset keeps
    /// reconciling the honest registers. Returns the exposed final commitment
    /// if the forged proof verifies. Every call first runs the positive
    /// control ([`forge::forged_with_control`]): the same pipeline
    /// recommitting the HONEST registers must verify and expose `Com(S)`.
    fn forged_final_state(binding: Binding) -> Option<([Val; 8], Vec<u32>)> {
        let honest = native_final_with(FP.b, &fp_prior(), &FP_KEYS, binding);
        let want = commit_countmin(&regs_to_state(&honest, FP.b)).0;
        forge::forged_with_control(
            &format!("hll omc forged final ({binding:?})"),
            |f| forged_final_state_run(binding, f),
            |(fin, _)| assert_eq!(*fin, want, "control exposes Com(S)"),
        )
    }

    fn forged_final_state_run(binding: Binding, forge_it: bool) -> Option<([Val; 8], Vec<u32>)> {
        let mut leaf = build_hll_omc_leaf_with(FP, true, binding);
        let (mut traces, _) = leaf.run_epoch(&fp_prior(), &FP_KEYS);
        let mut forged = native_final_with(FP.b, &fp_prior(), &FP_KEYS, binding);
        if forge_it {
            forged[0] += 1;
        }
        let st = regs_to_state(&forged, FP.b);
        let fp0 = traces.tag_to_witness["hll_final_packed_0"];
        forge::set_wid::<Val, Challenge>(&mut traces, fp0, pack_cells_to_challenge(&st)[0]);
        forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, cfg(), &make_perm());
        forge::catch(|| leaf.prove_traces(&traces).ok())
            .flatten()
            .map(|proof| {
                let pv = proof
                    .non_primitives
                    .iter()
                    .map(|e| e.public_values.clone())
                    .find(|v| v.len() == 16)
                    .expect("exposed (init, final)");
                (std::array::from_fn(|i| pv[8 + i]), forged)
            })
    }

    /// Legacy ACCEPTS a proof exposing `Com(S')` with a register the batch
    /// never raised (an inflated cardinality estimate); Bound rejects it.
    #[test]
    fn forged_final_state_legacy_accepts_bound_rejects() {
        if !bind::probe::fork_binds_decompose() {
            let (fin, forged) =
                forged_final_state(Binding::Legacy).expect("Legacy accepts the forged final (PoC)");
            let honest = native_final_with(FP.b, &fp_prior(), &FP_KEYS, Binding::Legacy);
            assert_eq!(fin, commit_countmin(&regs_to_state(&forged, FP.b)).0);
            assert_ne!(fin, commit_countmin(&regs_to_state(&honest, FP.b)).0);
        }
        assert!(
            forged_final_state(Binding::Bound).is_none(),
            "Bound must reject the forged final state"
        );
        // Merged soundness fork: the fork itself binds decompose coefficients, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if bind::probe::fork_binds_decompose() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(forged_final_state(b).is_none(), "fork binds decompose coefficients: {b:?} must reject too");
            }
        }
    }

    /// FREE SPONGE IV on record 0's routing hash (bump a capacity input, rehash).
    /// Legacy accepts a digest that is not `MyHash(key)`. Bound feeds the zero
    /// constant into the capacity, so the CTL read fails.
    #[test]
    fn forged_routing_iv_legacy_accepts_bound_rejects() {
        let run_iv = |binding: Binding, forge_it: bool| -> bool {
            let mut leaf = build_hll_omc_leaf_with(FP, true, binding);
            let (mut traces, _) = leaf.run_epoch(&fp_prior(), &FP_KEYS);
            let k0 = traces.tag_to_witness["hll_keys_t_0"].0;
            let key = NpoTypeId::poseidon2_perm(cfg());
            let mut pt = traces
                .non_primitive_trace::<Poseidon2Trace<Val>>(&key)
                .expect("poseidon2 trace")
                .clone();
            // The routing hash of record 0 is its own single-Challenge sponge (the
            // batch sponge starts with the same input but absorbs two Challenges).
            let row = pt
                .operations
                .iter_mut()
                .find(|r| r.new_start && r.in_ctl[0] && r.input_indices[0] == k0 && !r.in_ctl[1])
                .or(None);
            let row = match row {
                Some(r) => r,
                None => pt
                    .operations
                    .iter_mut()
                    .filter(|r| r.new_start && r.in_ctl[0] && r.input_indices[0] == k0)
                    .last()
                    .expect("record 0 routing hash row"),
            };
            if forge_it {
                row.input_values[8] += Val::ONE; // capacity limb 2, coefficient 0
            }
            traces.non_primitive_traces.insert(key, Box::new(pt));
            forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, cfg(), &make_perm());
            forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
        };
        // Positive control first: the same row edit with a zero bump.
        let run = |binding: Binding| -> bool {
            forge::accepted_with_control(&format!("hll omc forged IV ({binding:?})"), |forge_it| {
                run_iv(binding, forge_it)
            })
        };
        if !bind::probe::fork_binds_iv() && !bind::probe::fork_binds_decompose() {
            assert!(run(Binding::Legacy), "Legacy accepts the free-IV digest (PoC)");
        }
        assert!(!run(Binding::Bound), "Bound must reject the IV forgery");
        // Merged soundness fork: the fork itself binds the sponge IV, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if bind::probe::fork_binds_iv() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(!run(b), "fork binds the sponge IV: {b:?} must reject too");
            }
        }
    }

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────
    //
    // The commitment randomizers are called salts here (`ρ` is the HLL rank),
    // so the hiding module's PRF helpers are imported under salt names.

    use crate::commitment::countmin::commit_countmin_with;
    use crate::commitment::hiding::{
        SaltSeed, TAG_BATCH, TAG_STATE, rho_batch_bb as batch_salt, rho_batch_bb_in as batch_salt_in,
        rho_state_bb as state_salt, rho_state_bb_in as state_salt_in,
    };
    use crate::recursion::recursive::expose_forest::{
        batch_log, check_leaves_against_log, check_root_against_log, prove_hiding_merge,
        read_exposed_statement, root_vk_deriver, verify_bound_stark_proof_against_log, vk_pin_values,
    };
    use crate::recursion::recursive::noop_leaf::{hll_omc_noop_leaf_commit, hll_omc_noop_leaf_expose};
    use crate::recursion::recursive::root_vk::ForestShape;
    use crate::recursion::recursive::statement::{hash_bb, leaf_digest};

    const HP: HllOmcParams = HllOmcParams { b: 3, batch: 2 };
    const HLL: CommitFamily = CommitFamily::HyperLogLog;
    const HIDING: CommitMode = CommitMode::Hiding;

    fn hiding_leaf(binding: Binding) -> HllOmcLeafCircuit {
        build_hll_omc_leaf_commit(HP, Expose::Interval, binding, HIDING)
    }

    /// `m = 8` registers after keys 3 and 5.
    fn hp_prior(binding: Binding) -> Vec<u64> {
        hp_advanced(&hll_omc_empty(HP.b), &[3, 5], binding)
    }

    fn hp_batches() -> Vec<Vec<u64>> {
        vec![vec![7, 11], vec![13, 7]]
    }

    fn hp_advanced(regs: &[u64], keys: &[u64], binding: Binding) -> Vec<u64> {
        let mut r = regs.to_vec();
        hll_omc_advance_with(&mut r, keys, HP.m(), binding);
        r
    }

    /// The no-op leaf's state: key 1 inserted into empty registers.
    fn hp_noop_regs(binding: Binding) -> Vec<u64> {
        hp_advanced(&hll_omc_empty(HP.b), &[1], binding)
    }

    /// Flat basis coefficients of VK pin values.
    fn vk_flat(vk: &[Challenge]) -> Vec<u64> {
        vk.iter()
            .flat_map(|c| {
                <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                    .iter()
                    .map(|x| <Val as PrimeField64>::as_canonical_u64(x))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// A VK recorded on the unmodified code (b2-hiding@94e9f58, pre-HLL-B2):
    /// 8 base values, each the first coefficient of one pin Challenge.
    fn vk_literal(v: [u64; 8]) -> Vec<u64> {
        v.iter().flat_map(|&x| [x, 0, 0, 0]).collect()
    }

    fn vals(v: &[Val]) -> Vec<u64> {
        v.iter().map(|x| x.as_canonical_u64()).collect()
    }

    /// Natives: `Plain` is the pre-B2 commitment whatever the salt (values
    /// recorded on the unmodified code); `Hiding` is `MyHash([TAG_STATE |
    /// TAG_BATCH, HyperLogLog = 2, 0, 0, salt…] ‖ flat)` over exactly the old
    /// flat. The Plain HLL state commitment collides with the `d = 1, w = m`
    /// Count-Min one (the documented pre-B2 gap); under `Hiding` the family
    /// tag separates them even for the same salt. Two versions (two salts)
    /// give two commitments.
    #[test]
    fn hiding_natives_match_layout_and_separate_hll_from_count_min() {
        let seed = SaltSeed::for_tests(3);
        let (s1, s2) = (state_salt(&seed, HLL, 1), state_salt(&seed, HLL, 2));
        let regs: Vec<u64> = vec![1, 3, 3, 5, 3, 2, 4, 3, 3, 10, 0, 1, 3, 2, 2, 1];
        let recorded_state = [1755727638u64, 1309124030, 1726472135, 578956338, 698405071, 19484024, 746830669, 1524002173];
        assert_eq!(vals(&commit_hll_omc(&regs, 4)), recorded_state, "Plain Com(S) drifted");
        assert_eq!(commit_hll_omc_with(&regs, 4, CommitMode::Plain, &s1), commit_hll_omc(&regs, 4));
        let h = MyHash::new(make_perm());
        let mut input = vec![Val::from_u64(TAG_STATE), Val::from_u64(2), Val::ZERO, Val::ZERO];
        input.extend_from_slice(&s1.0);
        input.extend(regs.iter().map(|&r| Val::from_u32(r as u32)));
        let want: [Val; 8] = h.hash_iter(input);
        let h1 = commit_hll_omc_with(&regs, 4, HIDING, &s1);
        assert_eq!(h1, want, "state layout drift");
        assert_ne!(h1, commit_hll_omc_with(&regs, 4, HIDING, &s2), "two versions, two commitments");
        assert_ne!(h1, commit_hll_omc(&regs, 4));
        // The CM/HLL collision: Plain collides, Hiding does not.
        let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
        let cm_state = regs_to_state(&regs32, 4);
        assert_eq!(commit_countmin(&cm_state).0, commit_hll_omc(&regs, 4), "the Plain collision (pre-B2)");
        assert_ne!(commit_countmin_with(&cm_state, HIDING, &s1).0, h1, "Hiding separates the families");
        assert_ne!(
            commit_countmin_with(&cm_state, HIDING, &SaltBb::ZERO).0,
            commit_hll_omc_with(&regs, 4, HIDING, &SaltBb::ZERO),
            "even under the public zero salt"
        );

        let recorded_batch = [1985436089u64, 1220977314, 1527386085, 842854202, 1968443998, 1764238478, 1253482826, 1181162660];
        let keys = [7u64, 11, 13];
        let big = [0xA5A5_0000_5A5A_0001u64, 1 << 40, 12_345];
        let b1 = batch_salt(&seed, HLL, 1);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            assert_eq!(vals(&hll_omc_batch_commit_with(&keys, binding)), recorded_batch, "{binding:?}: Plain Com(B) drifted");
            for ks in [&keys[..], &big[..]] {
                assert_eq!(
                    hll_omc_batch_commit_salted(ks, binding, CommitMode::Plain, &b1),
                    hll_omc_batch_commit_with(ks, binding),
                    "{binding:?}"
                );
                let mut input = vec![Val::from_u64(TAG_BATCH), Val::from_u64(2), Val::ZERO, Val::ZERO];
                input.extend_from_slice(&b1.0);
                input.extend(ks.iter().flat_map(|&k| bind::key_hash_input::<Val>(k, binding)));
                let want: [Val; 8] = h.hash_iter(input);
                let hb = hll_omc_batch_commit_salted(ks, binding, HIDING, &b1);
                assert_eq!(hb, want, "{binding:?}: batch layout drift");
                assert_ne!(hb, hll_omc_batch_commit_with(ks, binding), "{binding:?}");
                assert_ne!(hb, hll_omc_batch_commit_salted(ks, binding, HIDING, &batch_salt(&seed, HLL, 2)));
            }
        }
        // The key encoding stays binding-dependent under Hiding (exact limbs
        // vs `key mod p`).
        assert_ne!(
            hll_omc_batch_commit_salted(&big, Binding::Semantic, HIDING, &b1),
            hll_omc_batch_commit_salted(&big, Binding::Legacy, HIDING, &b1)
        );
    }

    /// (1) A hiding leaf's commitments (the proof's `initial/final/batch`
    /// fields and the exposed statement) equal the NATIVE hiding commitments
    /// under the leaf-`t` openings, under every binding and both statement
    /// layouts (Interval: `H(TAG_LEAF, t, Com(B_t; salt))`; Boundary: the
    /// pair), and differ from the Plain ones.
    #[test]
    fn hiding_leaf_exposes_native_hiding_commitments() {
        let seed = SaltSeed::for_tests(21);
        let t = 3u64;
        let ups = hp_batches()[0].clone();
        for expose in [Expose::Interval, Expose::Boundary] {
            for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
                let mut leaf = build_hll_omc_leaf_commit(HP, expose, binding, HIDING);
                assert_eq!(leaf.commit_mode(), HIDING);
                let prior = hp_prior(binding);
                let r = leaf.prove_epoch_commit(t, prior.clone(), ups.clone(), &Openings::for_leaf(&seed, HLL, t));
                let expect = hp_advanced(&prior, &ups, binding);
                let init = commit_hll_omc_with(&prior, HP.b, HIDING, &state_salt(&seed, HLL, t - 1));
                let fin = commit_hll_omc_with(&expect, HP.b, HIDING, &state_salt(&seed, HLL, t));
                let bc = hll_omc_batch_commit_salted(&ups, binding, HIDING, &batch_salt(&seed, HLL, t));
                assert_eq!(r.initial_commit.0, init, "{expose:?}/{binding:?}");
                assert_eq!(r.final_commit.0, fin, "{expose:?}/{binding:?}");
                assert_eq!(r.batch_commit.0, bc, "{expose:?}/{binding:?}");
                assert_ne!(init, commit_hll_omc(&prior, HP.b), "{binding:?}: hiding != plain");
                assert_ne!(fin, commit_hll_omc(&expect, HP.b), "{binding:?}: hiding != plain");
                assert_ne!(bc, hll_omc_batch_commit_with(&ups, binding), "{binding:?}: hiding != plain");
                let st = read_exposed_statement(&r.output.0);
                assert_eq!(st.init, init.to_vec(), "{expose:?}/{binding:?}");
                assert_eq!(st.final_, fin.to_vec(), "{expose:?}/{binding:?}");
                match expose {
                    Expose::Interval => {
                        let iv = st.interval.expect("interval layout");
                        assert_eq!((iv.lo, iv.hi), (Val::from_u64(t), Val::from_u64(t)));
                        assert_eq!(iv.digest, leaf_digest(&hash_bb, 4, t, &bc), "{binding:?}: H(TAG_LEAF, t, Com(B_t; salt))");
                    }
                    _ => assert!(st.interval.is_none(), "{binding:?}: boundary layout"),
                }
            }
        }
        // The one-call API (process default binding).
        let dflt = bind::default_binding();
        let o = Openings::for_leaf(&seed, HLL, t);
        let r = prove_hll_omc_interval_commit(HP, t, hp_prior(dflt), ups.clone(), HIDING, &o);
        let fin = commit_hll_omc_with(&hp_advanced(&hp_prior(dflt), &ups, dflt), HP.b, HIDING, &o.final_);
        assert_eq!(r.final_commit.0, fin);
        assert_eq!(read_exposed_statement(&r.output.0).final_, fin.to_vec());
    }

    /// (2) The Plain leaf is the pre-B2 circuit: its VK equals the value
    /// recorded on the unmodified code for all 9 statement/binding
    /// combinations, through the old builder and through
    /// `build_hll_omc_leaf_commit(.., Plain)`, and so does the Plain no-op
    /// leaf's. The hiding leaf's VK differs from it, does not depend on the
    /// salts (two different openings, and the zero-salt no-op leaf, give one
    /// VK) and is the one the proofs carry.
    #[test]
    fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
        let recorded = [
            (Expose::None, Binding::Legacy, [636999072, 1898491012, 1128112536, 830154893, 609369003, 713306263, 357902989, 1000782104]),
            (Expose::None, Binding::Semantic, [42744576, 216833339, 1107521933, 201435337, 935860620, 220747263, 431030994, 1358685319]),
            (Expose::None, Binding::Bound, [1709165717, 664825638, 1250578729, 1763936516, 33983242, 349787729, 1830277133, 316054631]),
            (Expose::Boundary, Binding::Legacy, [23627548, 720985757, 1619716651, 1365574028, 1346264072, 599693484, 858553584, 1737678621]),
            (Expose::Boundary, Binding::Semantic, [1679086738, 262377458, 1652284322, 478543385, 1678862835, 269325595, 1807344777, 805944137]),
            (Expose::Boundary, Binding::Bound, [73921216, 444870412, 1674324123, 1070314468, 137506833, 757753555, 1859052487, 1692122645]),
            (Expose::Interval, Binding::Legacy, [1896707957, 1604584613, 974349343, 620291790, 408969713, 1887377153, 818756554, 559561033]),
            (Expose::Interval, Binding::Semantic, [1661779960, 604174863, 632468435, 1618790266, 837830444, 514216797, 1113288870, 1087655075]),
            (Expose::Interval, Binding::Bound, [1496412106, 666070042, 1877954448, 1595189162, 134027221, 405324434, 836048836, 185054744]),
        ];
        for (expose, binding, vk) in recorded {
            let old = build_hll_omc_leaf_expose(HP, expose, binding).vk_pin_values();
            let plain = build_hll_omc_leaf_commit(HP, expose, binding, CommitMode::Plain).vk_pin_values();
            assert_eq!(vk_flat(&old), vk_literal(vk), "{expose:?}/{binding:?}: Plain VK drifted from the unmodified code");
            assert_eq!(plain, old, "{expose:?}/{binding:?}");
            let hid = build_hll_omc_leaf_commit(HP, expose, binding, HIDING).vk_pin_values();
            assert_ne!(hid, old, "{expose:?}/{binding:?}: the hiding circuit differs");
            if expose == Expose::Interval {
                let noop = hll_omc_noop_leaf_expose(HP, expose, binding);
                assert_eq!(vk_flat(&vk_pin_values(&noop)), vk_literal(vk), "{binding:?}: Plain no-op leaf");
                let noop_plain = hll_omc_noop_leaf_commit(HP, expose, binding, CommitMode::Plain);
                assert_eq!(vk_flat(&vk_pin_values(&noop_plain)), vk_literal(vk), "{binding:?}: Plain no-op (commit API)");
                let noop_hid = hll_omc_noop_leaf_commit(HP, expose, binding, HIDING);
                assert_eq!(vk_pin_values(&noop_hid), hid, "{binding:?}: the zero-salt no-op leaf has the real leaves' VK");
            }
        }
        let mut leaf = hiding_leaf(Binding::Semantic);
        let vk = leaf.vk_pin_values();
        let ups = hp_batches()[0].clone();
        let prior = hp_prior(Binding::Semantic);
        // Leaf 1 starts from the empty S_0 (its zero init salt opens only that
        // public state); leaf 5 from a real prior.
        let a = leaf.prove_epoch_commit(1, hll_omc_empty(HP.b), ups.clone(), &Openings::for_leaf(&SaltSeed::for_tests(1), HLL, 1));
        let b = leaf.prove_epoch_commit(5, prior, ups, &Openings::for_leaf(&SaltSeed::for_tests(2), HLL, 5));
        assert_ne!(a.final_commit, b.final_commit);
        assert_eq!(vk_pin_values(&a.output.0), vk);
        assert_eq!(vk_pin_values(&b.output.0), vk);
    }

    /// (3) Equal states at two versions get different hiding commitments,
    /// both different from the plain one; at the proof level, two leaves
    /// whose batch raises no register (the state does not move) at `t = 1, 2`
    /// expose `Com(S; 0) → Com(S; salt_1) → Com(S; salt_2)`: three distinct
    /// values for one state, chained.
    #[test]
    fn equal_states_get_unlinkable_hiding_commitments() {
        let binding = Binding::Semantic;
        let seed = SaltSeed::for_tests(33);
        let s = hp_noop_regs(binding);
        let (c1, c2) = (
            commit_hll_omc_with(&s, HP.b, HIDING, &state_salt(&seed, HLL, 1)),
            commit_hll_omc_with(&s, HP.b, HIDING, &state_salt(&seed, HLL, 2)),
        );
        assert_ne!(c1, c2);
        assert_ne!(c1, commit_hll_omc(&s, HP.b));
        assert_ne!(c2, commit_hll_omc(&s, HP.b));

        let still = vec![1u64; HP.batch];
        assert_eq!(hp_advanced(&s, &still, binding), s, "the batch raises no register");
        let mut leaf = hiding_leaf(binding);
        let l1 = leaf.prove_epoch_commit(1, s.clone(), still.clone(), &Openings::for_leaf(&seed, HLL, 1));
        let l2 = leaf.prove_epoch_commit(2, s.clone(), still, &Openings::for_leaf(&seed, HLL, 2));
        let (s1, s2) = (read_exposed_statement(&l1.output.0), read_exposed_statement(&l2.output.0));
        assert_eq!(s1.init, commit_hll_omc_with(&s, HP.b, HIDING, &SaltBb::ZERO).to_vec());
        assert_eq!(s1.final_, c1.to_vec());
        assert_eq!(s2.init, s1.final_, "leaf 2 opens Com(S_1) with the same salt_1");
        assert_eq!(s2.final_, c2.to_vec());
        assert_ne!(s1.init, s1.final_, "the state did not move, the commitment did");
        assert_ne!(s2.init, s2.final_);
    }

    /// (4) Binding in Hiding mode, through the auditor paths. Control: two
    /// honest leaves (seed A) pass the per-batch log check, merge, and the
    /// root verifies against the log with the root VK derived from the
    /// zero-salt no-op leaf. A log recomputed with another seed rejects both;
    /// a leaf opened with a wrong batch or final salt mismatches the log; and
    /// a leaf 2 whose init uses a different `salt_1` than leaf 1's final
    /// cannot be merged (the in-circuit `left.final == right.init`).
    #[test]
    fn wrong_salt_rejected_by_log_and_inconsistent_salt_breaks_merge() {
        let binding = Binding::Semantic;
        let (a, b) = (SaltSeed::for_tests(41), SaltSeed::for_tests(42));
        let bs = hp_batches();
        let s0 = hll_omc_empty(HP.b);
        let s1 = hp_advanced(&s0, &bs[0], binding);
        let s2 = hp_advanced(&s1, &bs[1], binding);
        let log_for = |seed: &SaltSeed| {
            let bc: Vec<[Val; 8]> = (0..2)
                .map(|k| hll_omc_batch_commit_salted(&bs[k], binding, HIDING, &batch_salt(seed, HLL, k as u64 + 1)))
                .collect();
            batch_log(
                &commit_hll_omc_with(&s0, HP.b, HIDING, &SaltBb::ZERO),
                &commit_hll_omc_with(&s2, HP.b, HIDING, &state_salt(seed, HLL, 2)),
                &bc,
            )
        };
        let (log_a, log_b) = (log_for(&a), log_for(&b));
        let mut leaf = hiding_leaf(binding);
        let l1 = leaf.prove_epoch_commit(1, s0.clone(), bs[0].clone(), &Openings::for_leaf(&a, HLL, 1)).output;
        let l2 = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &Openings::for_leaf(&a, HLL, 2)).output;
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log_a, Expose::Interval), Ok(()));
        assert!(check_leaves_against_log(&[&l1.0, &l2.0], &log_b, Expose::Interval).is_err(), "another seed's log");

        // Leaf 2 opened with a wrong batch salt: its digest H(TAG_LEAF, 2,
        // Com(B_2; salt')) is not the log's.
        let bad_batch = Openings { batch: batch_salt(&b, HLL, 2), ..Openings::for_leaf(&a, HLL, 2) };
        let l2b = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_batch).output;
        let e = check_leaves_against_log(&[&l1.0, &l2b.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("digest")), "{e:?}");
        // … with a wrong final salt: Com(S_2; salt') is not the log's Com(S_T).
        let bad_final = Openings { final_: state_salt(&b, HLL, 2), ..Openings::for_leaf(&a, HLL, 2) };
        let l2f = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_final).output;
        let e = check_leaves_against_log(&[&l1.0, &l2f.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("Com(S_T)")), "{e:?}");

        // Composition: the honest pair merges and verifies against log A.
        let shape = ForestShape::forest(2);
        let root = prove_hiding_merge(&l1, &l2);
        let noop = hll_omc_noop_leaf_commit(HP, Expose::Interval, binding, HIDING);
        let vk = root_vk_deriver(noop).root_vk(&shape);
        verify_bound_stark_proof_against_log(&root.0, &vk, &log_a, &shape);
        assert!(check_root_against_log(&root.0, &log_b, &shape).is_err());

        // Inconsistent salt_1 across the boundary: the merge is unprovable.
        let bad_init = Openings { init: state_salt(&b, HLL, 1), ..Openings::for_leaf(&a, HLL, 2) };
        let l2i = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_init).output;
        assert_ne!(read_exposed_statement(&l2i.0).init, read_exposed_statement(&l1.0).final_);
        let e = forge::catch_msg(|| prove_hiding_merge(&l1, &l2i)).map(|_| ());
        println!("B2 HLL inconsistent salt_1 merge: {e:?}");
        assert!(
            e.as_ref().is_err_and(|m| m.contains("WitnessConflict")),
            "leaf 2's init must use leaf 1's final salt: {e:?}"
        );
    }

    /// (5) The zero-salt no-op leaf of a Hiding circuit still exposes
    /// `init == final` (`= Com(S_noop; 0)` under the HLL tag), so the
    /// twin-merge root-VK derivation works unchanged.
    #[test]
    fn hiding_noop_leaf_has_init_eq_final() {
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let noop = hll_omc_noop_leaf_commit(HP, Expose::Interval, binding, HIDING);
            let st = read_exposed_statement(&noop);
            let regs = hp_noop_regs(binding);
            let c = commit_hll_omc_with(&regs, HP.b, HIDING, &SaltBb::ZERO);
            assert_eq!(st.init, st.final_, "{binding:?}");
            assert_eq!(st.init, c.to_vec(), "{binding:?}");
            assert_ne!(c, commit_hll_omc(&regs, HP.b), "{binding:?}");
        }
    }

    /// (8, with `commitment::hiding::tests::salt_private_inputs_have_alu_creators`)
    /// Build and prove the Hiding leaf at a tiny shape. Under the DEBUG
    /// profile (`cargo test --lib hll_omc::tests::hiding_leaf_tiny_debug`)
    /// the fork debug-asserts, during the build, that each of the 9 salt
    /// private inputs has an ALU creator.
    #[test]
    fn hiding_leaf_tiny_debug() {
        let p = HllOmcParams { b: 2, batch: 1 };
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = build_hll_omc_leaf_commit(p, Expose::Interval, binding, HIDING);
            let seed = SaltSeed::for_tests(8);
            let r = leaf.prove_epoch_commit(1, hll_omc_empty(p.b), vec![9], &Openings::for_leaf(&seed, HLL, 1));
            let mut fin = hll_omc_empty(p.b);
            hll_omc_advance_with(&mut fin, &[9], p.m(), binding);
            assert_eq!(r.final_commit.0, commit_hll_omc_with(&fin, p.b, HIDING, &state_salt(&seed, HLL, 1)));
        }
    }

    /// (F3, F5) The Hiding leaf costs exactly +2 Poseidon2 rows and +3 ALU
    /// rows per commitment over the Plain leaf (3 commitments: +6 and +9)
    /// under every binding, and none of its 36 salt values is a public value
    /// of the proof (the scan's positive control: a "salt" equal to an
    /// exposed commitment value is found).
    #[test]
    fn hiding_leaf_row_overhead_and_no_salt_in_public_values() {
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows, trace_rows};
        let seed = SaltSeed::for_tests(91);
        let t = 3u64;
        let ups = hp_batches()[0].clone();
        let o = Openings::for_leaf(&seed, HLL, t);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let prior = hp_prior(binding);
            let mut plain = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
            let mut leaf = hiding_leaf(binding);
            let (p0, a0) = trace_rows(&plain.run_epoch(&prior, &ups).0);
            let (p1, a1) = trace_rows(&leaf.run_epoch_commit(&prior, &ups, &o).0);
            println!("B2 HLL leaf rows {binding:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 6, "{binding:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 9, "{binding:?}: ALU rows");
            let hid = leaf.prove_epoch_commit(t, prior.clone(), ups.clone(), &o);
            assert_eq!(proof_alu_rows(&hid.output.0), a1, "{binding:?}: the proof's ALU height");
            assert_eq!(leaked_salts(&hid.output.0, &[o.init, o.final_, o.batch]), vec![], "{binding:?}");
            let mut control = SaltBb::ZERO;
            control.0[0] = hid.initial_commit.0[0];
            assert!(!leaked_salts(&hid.output.0, &[control]).is_empty(), "{binding:?}: the scan sees the statement");
        }
    }

    /// (F1) A Hiding leaf never falls back to zero salts silently: the old
    /// `prove_epoch_at` / `prove_epoch` entry points panic on it, and so does
    /// `prove_epoch_commit` (and the one-call API) handed a zero final or
    /// batch salt. The explicit no-op path refuses a batch that raises a
    /// register. Controls: a zero INIT salt is leaf 1's honest opening (from
    /// the empty genesis registers; a zero init on a real state is refused,
    /// test `hiding_leaf_refuses_zero_init_on_a_real_state`), and a Plain
    /// leaf still ignores its openings.
    #[test]
    fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
        let binding = Binding::Semantic;
        let seed = SaltSeed::for_tests(81);
        let ups = hp_batches()[0].clone();
        let prior = hp_prior(binding);
        assert_ne!(hp_advanced(&prior, &ups, binding), prior, "the batch raises a register");
        let mut leaf = hiding_leaf(binding);
        let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, prior.clone(), ups.clone()).final_commit).unwrap_err();
        assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
        assert!(forge::catch(|| leaf.prove_epoch(prior.clone(), ups.clone()).final_commit).is_none());
        let honest = Openings::for_leaf(&seed, HLL, 2);
        for (what, o) in [
            ("plain", Openings::plain()),
            ("public_zero", Openings::public_zero()),
            ("zero final", Openings { final_: SaltBb::ZERO, ..honest }),
            ("zero batch", Openings { batch: SaltBb::ZERO, ..honest }),
        ] {
            let msg = forge::catch_msg(|| leaf.prove_epoch_commit(2, prior.clone(), ups.clone(), &o).final_commit)
                .unwrap_err();
            assert!(msg.contains("public zero salt"), "{what}: {msg}");
        }
        let msg = forge::catch_msg(|| {
            prove_hll_omc_interval_commit(HP, 2, prior.clone(), ups.clone(), HIDING, &Openings::plain()).final_commit
        })
        .unwrap_err();
        assert!(msg.contains("public zero salt"), "{msg}");
        let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, prior.clone(), ups.clone()).final_commit).unwrap_err();
        assert!(msg.contains("no key may raise its register"), "{msg}");

        let o1 = Openings::for_leaf(&seed, HLL, 1);
        assert!(o1.init.is_zero());
        let s0 = hll_omc_empty(HP.b);
        let r = leaf.prove_epoch_commit(1, s0.clone(), ups.clone(), &o1);
        assert_eq!(r.initial_commit.0, commit_hll_omc_with(&s0, HP.b, HIDING, &SaltBb::ZERO));
        let mut plain = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
        let p = plain.prove_epoch_commit(2, prior.clone(), ups.clone(), &Openings::plain());
        assert_eq!(p.initial_commit.0, commit_hll_omc(&prior, HP.b));
        assert_eq!(p.final_commit.0, commit_hll_omc(&hp_advanced(&prior, &ups, binding), HP.b));
        assert_eq!(p.batch_commit.0, hll_omc_batch_commit_with(&ups, binding));
    }

    /// (F1, init salt) Under `Hiding` a zero INIT salt opens only a public
    /// state at batch index 1: the empty genesis registers (`Com(S_0; 0)`)
    /// or the no-op leaf's public `S_noop`. Refused, under every binding: a
    /// forgotten init opening on a real prior (`t = 2`), local numbering
    /// (`for_leaf(.., 1)` at global `t = 5` on a real state), leaf 1's
    /// openings on a real prior at `t = 1`, and a zero init at `t = 2` on
    /// the empty registers. Controls: the genesis leaf (empty registers) and
    /// the `S_noop` leaf at `t = 1` (`exp_e0`'s chained Hiding leaf 1) prove
    /// and expose the zero-salt commitment of their public state; a Plain
    /// leaf ignores its openings on the same inputs.
    #[test]
    fn hiding_leaf_refuses_zero_init_on_a_real_state() {
        let seed = SaltSeed::for_tests(83);
        let ups = hp_batches()[0].clone();
        let s0 = hll_omc_empty(HP.b);
        let forgot = Openings { init: SaltBb::ZERO, ..Openings::for_leaf(&seed, HLL, 2) };
        let local = Openings::for_leaf(&seed, HLL, 1);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let prior = hp_prior(binding);
            let noop = hp_noop_regs(binding);
            assert!(prior != s0 && prior != noop, "precondition: a real (secret) prior");
            let cases = [
                ("forgotten init, real prior", 2u64, prior.clone(), forgot),
                ("local numbering at global t = 5", 5, prior.clone(), local),
                ("leaf-1 openings on a real prior", 1, prior.clone(), local),
                ("zero init at t = 2 on the empty registers", 2, s0.clone(), forgot),
            ];
            let mut leaf = hiding_leaf(binding);
            for (what, t, init, o) in &cases {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(*t, init.clone(), ups.clone(), o).final_commit)
                    .unwrap_err();
                assert!(msg.contains("zero init salt"), "{binding:?}/{what}: {msg}");
            }
            for public in [s0.clone(), noop.clone()] {
                let r = leaf.prove_epoch_commit(1, public.clone(), ups.clone(), &local);
                assert_eq!(r.initial_commit.0, commit_hll_omc_with(&public, HP.b, HIDING, &SaltBb::ZERO), "{binding:?}");
            }
            if binding == Binding::Semantic {
                let mut plain = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
                for (what, t, init, o) in &cases {
                    let p = plain.prove_epoch_commit(*t, init.clone(), ups.clone(), o);
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
            let noop = hp_noop_regs(binding);
            for mode in [HIDING, CommitMode::Plain] {
                let mut leaf = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, mode);
                let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(2, noop.clone(), vec![1; HP.batch]).final_commit)
                    .unwrap_err();
                assert!(msg.contains("batch index 1"), "{binding:?}/{mode:?}: {msg}");
            }
        }
    }

    /// The zero-salt no-op path accepts only the public no-op input (key 1
    /// in empty registers, every key 1), not merely "a batch that raises no
    /// register": for HLL a real batch of repeated keys often raises
    /// nothing, and would otherwise publish the deterministic commitments of
    /// a secret state and of real keys. Rejected, under every binding and in
    /// either mode: a real state with a repeated real key (the stream
    /// harness's split-leaf pad shape), a non-canonical state with keys 1,
    /// and the canonical state with a real key that does not raise its
    /// register. Control: the canonical input proves, and exposes
    /// `Com(S_noop; 0)`.
    #[test]
    fn noop_path_accepts_only_the_public_noop_input() {
        let noop_msg = "the public no-op input only";
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let empty = hll_omc_empty(HP.b);
            let noop = hp_noop_regs(binding);
            let real = hp_advanced(&empty, &[4242, 777], binding);
            let repeat = vec![4242u64, 4242];
            assert_eq!(hp_advanced(&real, &repeat, binding), real, "{binding:?}: the repeat raises nothing");
            let other = hp_advanced(&empty, &[1, 4242], binding);
            assert_ne!(other, noop, "{binding:?}");
            assert_eq!(hp_advanced(&other, &[1, 1], binding), other, "{binding:?}");
            let quiet = (2u64..10_000)
                .find(|&k| hp_advanced(&noop, &[k], binding) == noop)
                .expect("a key dominated by key 1's register");
            let cases = [
                ("real state, repeated real key", real, repeat),
                ("non-canonical state, keys 1", other, vec![1, 1]),
                ("canonical state, dominated real key", noop.clone(), vec![quiet, quiet]),
            ];
            for mode in [HIDING, CommitMode::Plain] {
                let mut leaf = build_hll_omc_leaf_commit(HP, Expose::Interval, binding, mode);
                for (what, init, keys) in &cases {
                    let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(9, init.clone(), keys.clone()).final_commit)
                        .unwrap_err();
                    assert!(msg.contains(noop_msg), "{binding:?}/{mode:?}/{what}: {msg}");
                }
            }
            let mut leaf = hiding_leaf(binding);
            let r = leaf.prove_epoch_public_zero(1, noop.clone(), vec![1; HP.batch]);
            let c = commit_hll_omc_with(&noop, HP.b, HIDING, &SaltBb::ZERO);
            assert_eq!(r.initial_commit.0, c, "{binding:?}");
            assert_eq!(r.final_commit.0, c, "{binding:?}");
            assert_eq!(
                r.batch_commit.0,
                hll_omc_batch_commit_salted(&vec![1; HP.batch], binding, HIDING, &SaltBb::ZERO),
                "{binding:?}"
            );
        }
    }

    /// A Plain leaf ignores REAL openings too (the harness under
    /// `ZKSKETCH_COMMIT=plain` routes every leaf through `prove_epoch_commit`
    /// with `Openings::for_leaf`): under every binding and both statement
    /// layouts, the leaf-2 openings give the Plain natives, the same exposed
    /// statement, the same public values and the same VK as the pre-B2
    /// `prove_epoch_at`.
    #[test]
    fn plain_leaf_ignores_real_openings() {
        use crate::commitment::hiding::probe::public_values;
        let seed = SaltSeed::for_tests(61);
        let t = 2u64;
        let o = Openings::for_leaf(&seed, HLL, t);
        assert!(!o.init.is_zero() && !o.final_.is_zero() && !o.batch.is_zero());
        let ups = hp_batches()[1].clone();
        for expose in [Expose::Interval, Expose::Boundary] {
            for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
                let prior = hp_prior(binding);
                let mut plain = build_hll_omc_leaf_commit(HP, expose, binding, CommitMode::Plain);
                let old = plain.prove_epoch_at(t, prior.clone(), ups.clone());
                let p = plain.prove_epoch_commit(t, prior.clone(), ups.clone(), &o);
                assert_eq!(p.initial_commit.0, commit_hll_omc(&prior, HP.b), "{expose:?}/{binding:?}");
                assert_eq!(
                    p.final_commit.0,
                    commit_hll_omc(&hp_advanced(&prior, &ups, binding), HP.b),
                    "{expose:?}/{binding:?}"
                );
                assert_eq!(p.batch_commit.0, hll_omc_batch_commit_with(&ups, binding), "{expose:?}/{binding:?}");
                assert_eq!(p.initial_commit.0, old.initial_commit.0, "{expose:?}/{binding:?}");
                assert_eq!(p.final_commit.0, old.final_commit.0, "{expose:?}/{binding:?}");
                assert_eq!(p.batch_commit.0, old.batch_commit.0, "{expose:?}/{binding:?}");
                assert_eq!(
                    read_exposed_statement(&p.output.0),
                    read_exposed_statement(&old.output.0),
                    "{expose:?}/{binding:?}"
                );
                assert_eq!(public_values(&p.output.0), public_values(&old.output.0), "{expose:?}/{binding:?}");
                assert_eq!(vk_pin_values(&p.output.0), vk_pin_values(&old.output.0), "{expose:?}/{binding:?}");
                assert_eq!(vk_pin_values(&p.output.0), plain.vk_pin_values(), "{expose:?}/{binding:?}");
            }
        }
    }

    /// (F2) A continued history is anchored on the previous history's
    /// certified final commitment: history 0 ends at `Com(S_2; salt_{0,2})`;
    /// history 1 restarts `t` at 1 from `S_2`, its leaf 1 opens the init with
    /// that anchor salt ([`Openings::for_leaf_after`]) and exposes exactly
    /// the certified value, and both leaves pass the per-batch check against
    /// history 1's log, whose `Com(S_0)` is that anchor (taken from history
    /// 0, not recomputed). The same batch at the same `t` gets another
    /// commitment in each history. A zero init salt (what `for_leaf(.., 1)`
    /// gives) would expose the guess-checkable `Com(S_2; 0)`: the leaf
    /// refuses it. A nonzero WRONG anchor salt (not detectable by the leaf)
    /// exposes another commitment, and the log rejects it.
    #[test]
    fn continued_history_leaf_opens_the_previous_final_commitment() {
        let binding = Binding::Semantic;
        let seed = SaltSeed::for_tests(71);
        let bs = hp_batches();
        let s1 = hp_advanced(&hll_omc_empty(HP.b), &bs[0], binding);
        let s2 = hp_advanced(&s1, &bs[1], binding);
        let mut leaf = hiding_leaf(binding);
        let h0_last = leaf.prove_epoch_commit(2, s1, bs[1].clone(), &Openings::for_leaf(&seed, HLL, 2));
        let anchor_salt = state_salt(&seed, HLL, 2);
        let anchor = h0_last.final_commit.0;
        assert_eq!(anchor, commit_hll_omc_with(&s2, HP.b, HIDING, &anchor_salt));

        let h = 1u64;
        let more = [vec![21u64, 23], vec![25, 27]];
        let s3 = hp_advanced(&s2, &more[0], binding);
        let s4 = hp_advanced(&s3, &more[1], binding);
        let o1 = Openings::for_leaf_after(&anchor_salt, &seed, HLL, h);
        let l1 = leaf.prove_epoch_commit(1, s2.clone(), more[0].clone(), &o1).output;
        let l2 = leaf.prove_epoch_commit(2, s3, more[1].clone(), &Openings::for_leaf_in(&seed, HLL, h, 2)).output;
        assert_eq!(read_exposed_statement(&l1.0).init, anchor.to_vec(), "history 1 starts at history 0's final");
        assert_eq!(read_exposed_statement(&l2.0).init, read_exposed_statement(&l1.0).final_);
        let bc: Vec<[Val; 8]> = (0..2)
            .map(|k| hll_omc_batch_commit_salted(&more[k], binding, HIDING, &batch_salt_in(&seed, HLL, h, k as u64 + 1)))
            .collect();
        let fin = commit_hll_omc_with(&s4, HP.b, HIDING, &state_salt_in(&seed, HLL, h, 2));
        let log1 = batch_log(&anchor, &fin, &bc);
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log1, Expose::Interval), Ok(()));
        let h0 = hll_omc_batch_commit_salted(&more[0], binding, HIDING, &batch_salt(&seed, HLL, 1));
        assert_ne!(bc[0], h0, "t restarted, the salt did not");

        let zero_init = Openings { init: SaltBb::ZERO, ..o1 };
        let msg = forge::catch_msg(|| leaf.prove_epoch_commit(1, s2.clone(), more[0].clone(), &zero_init).final_commit)
            .unwrap_err();
        assert!(msg.contains("zero init salt"), "{msg}");
        let wrong_init = Openings { init: state_salt(&seed, HLL, 1), ..o1 };
        let l1w = leaf.prove_epoch_commit(1, s2, more[0].clone(), &wrong_init).output;
        let e = check_leaves_against_log(&[&l1w.0, &l2.0], &log1, Expose::Interval);
        assert!(e.as_ref().is_err_and(|m| m.contains("Com(S_0)")), "{e:?}");
    }

    /// Measurement (explicit): legacy vs bound.
    /// `HLL_OMC_MEASURE=b,batch[;b,batch...] cargo test --release --lib
    /// hll_omc::tests::hll_binding_measure -- --ignored --nocapture`
    /// (default `14,4096`).
    #[test]
    #[ignore = "measurement: large circuits"]
    fn hll_binding_measure() {
        let spec = std::env::var("HLL_OMC_MEASURE").unwrap_or_else(|_| "14,4096".into());
        for shape in spec.split(';') {
            let v: Vec<usize> = shape.split(',').map(|x| x.trim().parse().unwrap()).collect();
            let params = HllOmcParams { b: v[0], batch: v[1] };
            let mut prior = vec![0u64; params.m()];
            let pk: Vec<u64> = (0..5000u64).map(|k| k.wrapping_mul(0x9E37_79B9_7F4A_7C15)).collect();
            hll_omc_advance(&mut prior, &pk, params.m());
            let keys: Vec<u64> = (0..params.batch as u64)
                .map(|i| i.wrapping_mul(0xD1B5_4A32_D192_ED03) ^ 0x5555)
                .collect();
            for binding in [Binding::Legacy, Binding::Bound] {
                let t_b = std::time::Instant::now();
                let mut leaf = build_hll_omc_leaf_with(params, true, binding);
                let build = t_b.elapsed();
                let t = std::time::Instant::now();
                let proof = leaf.prove_epoch(prior.clone(), keys.clone());
                let total = t.elapsed();
                let tm = crate::recursion::recursive::timing::take();
                eprintln!(
                    "HLL_OMC_MEASURE binding={:?} b={} batch={} trace_rows={} tables={:?} build_ms={:.0} witness_ms={:.0} prove_ms={:.0} verify_ms={:.0} total_ms={:.0} proof_bytes={}",
                    binding, params.b, params.batch, leaf.trace_rows(), leaf.table_rows(),
                    build.as_secs_f64() * 1e3, tm.witness.as_secs_f64() * 1e3,
                    tm.prove.as_secs_f64() * 1e3, tm.verify.as_secs_f64() * 1e3,
                    total.as_secs_f64() * 1e3, proof.proof_size()
                );
            }
        }
    }
}
