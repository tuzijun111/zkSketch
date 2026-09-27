//! **Offline-memory-checking count-min leaf (`omc`)** — the sound,
//! cross-state realization of zk1.tex §"Pattern A" Step 5 that proves
//! `N[a] = O[a] + Δ_a` at the touched cells AND that every *untouched*
//! cell is unchanged, by a single read/write **multiset equality**
//! against the real committed prior state — no Merkle path, no
//! timestamps, and (unlike [`super::countmin_memcheck`]) **no empty-init
//! assumption**.
//!
//! ## The check
//!
//! Treat the `d×w` array as memory; address `a = i·w + b`, value
//! `S[a]`. With the full old/new memories
//! `M_old = {(a, S_{t-1}[a])}` and `M_new = {(a, S_t[a])}`, the touched
//! reads `R = {(a_z, O_z)}` and writes `W = {(a_z, N_z)}`, the leaf
//! proves
//!
//! ```text
//!     M_old ⊎ W  ==  M_new ⊎ R       (as multisets)
//! ```
//!
//! For a touched address the pair `(M_old[a_z], W) = (enc(a_z,O[a_z]),
//! enc(a_z,N_z))` must equal `(M_new[a_z], R) = (enc(a_z,N[a_z]),
//! enc(a_z,O_z))`. Because `enc` binds the address, the only matching is
//! `O_z = O[a_z]` and `N[a_z] = O_z + Δ_z` — i.e. the multiset **forces
//! the prover's claimed old value `O_z` to be the genuinely committed old
//! value** (membership) and the new committed cell to be `old + Δ`. For
//! an untouched address nothing is added, so `O[u] = N[u]` is forced.
//! `O[a]` / `N[a]` are bound to the public `(init_commit, final_commit)`
//! by decomposing the same Poseidon-committed cells the dense `one_hot`
//! leaf uses.
//!
//! ## Why this is the honest "maintained accumulator"
//!
//! The "accumulator carried across versions" here is simply the
//! **committed dense state itself**: `init_commit = Com(S_{t-1})` is the
//! certified digest of the whole old memory, established by the previous
//! transition's `final_commit`. This leaf reconciles the touched
//! reads/writes against it. A *scalar grand-product* accumulator carried
//! across separately-proven batches is NOT sound in a hash-based STARK
//! (its binding challenge is per-proof Fiat–Shamir; a fixed challenge is
//! not binding), and an `O(1)`-membership algebraic accumulator needs
//! hidden-order groups we do not have — so the committed-state-plus-
//! multiset realization below is the strongest sound option here.
//!
//! ## Cost
//!
//! The rebind is one [`CircuitBuilder::add_permute`] over `dw + n_ctr`
//! tagged `(addr,val)` elements plus the dense commit/decompose of both
//! ends: **`Θ(dw + n_ctr)`**. This is `Θ(dw)` — it does *not* beat the
//! sparse [`merkle`](super::countmin_c_merkle) /
//! [`memcheck`](super::countmin_memcheck) rebinds when `T ≪ dw` — but it
//! replaces `one_hot`'s `Θ(batch·d·dw)` one-hot selector matrix with a
//! single `dw`-length permutation, so it sits far below `one_hot` while
//! remaining the only variant that reconciles touched **old values
//! against a non-trivial committed prior state** with no Merkle path.
//!
//! Each touched address appears once (canonical group-by + sortedness
//! range-check), and inactive rows are zero on both the `W` and `R` side
//! so they cancel; real elements carry a `1` tag in coordinate 2 so they
//! can never collide with the zero dummies. Shape depends only on
//! `(d, w, batch)` — Property-4 oblivious.

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
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::commitment::countmin::commit_countmin_with;
use crate::commitment::countmin_batch::{
    commit_batch, commit_batch_limbs, commit_batch_limbs_with, commit_batch_with,
};
use crate::commitment::hiding::{self, CommitFamily, CommitKind, CommitMode, Openings, SaltBb};
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::bind::{self, Binding};
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::countmin_final::{apply_update_prf_with, key_digest};
use crate::sketch::countmin_v9::CountMinV9;

const LOG_FINAL_POLY_LEN: usize = 6;
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

thread_local! {
    /// When set, the prover commits to a CORRUPTED final state (one cell
    /// bumped) while the patch/multiset are built from the honest one, so
    /// `M_old ⊎ W = M_new ⊎ R` fails and the self-verify rejects. Drives
    /// [`tests::tamper_rejected`].
    static TAMPER_FINAL_CELL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only malicious-prover plan for [`CmOmcLeafCircuit::epoch`]. It
/// rewrites the prover's NATIVE witness (the claimed per-record touches, the
/// canonical position splits, the claimed old values) and commits the final
/// state that witness implies. The circuit is untouched, so whatever it
/// accepts under such a plan is a soundness counterexample. Hint and
/// permutation forgeries (bits, bytes, sorted tuples) are applied separately
/// by the tests through [`CmOmcProbes`] and [`crate::sketch::forge_permute`].
#[cfg(test)]
#[derive(Default, Clone, Debug)]
pub(crate) struct CmOmcForge {
    /// `(touch index k·d + i, claimed address, claimed value)`: overrides the
    /// honest touch of record `k` on row `i`, and the committed final state
    /// follows the claimed touches.
    pub touches: Vec<(usize, u64, u32)>,
    /// `(touch index k·d + i, [pos, hi, dinv])`: overrides the canonical split
    /// private inputs of record `k`'s row-`i` digest limb (`Semantic` and
    /// `Bound` only; `Legacy` has no split witnesses).
    pub splits: Vec<(usize, [Val; 3])>,
    /// `(from, to)`: take the ACTIVE sorted row at address `from` and claim
    /// the extension-valued old value `op_old = O[to] + t·X³` with
    /// `t = (to − from)/W` (`X⁴ = W`). Both multiset elements of that row then
    /// encode address `to` instead of `from`, and the increment is committed
    /// at `to`. `to` must be untouched by the batch.
    pub op_old_redirect: Option<(u64, u64)>,
}

#[cfg(test)]
thread_local! {
    static FORGE: std::cell::RefCell<Option<CmOmcForge>> = const { std::cell::RefCell::new(None) };
}

/// The extension-valued `op_old = O[to] + t·X³`, `t = (to − from)/W`
/// (`X⁴ = W`), for which `enc(from, op_old) = enc(to, O[to])` and
/// `enc(from, op_old + Δ) = enc(to, O[to] + Δ)`, with
/// `enc(a, v) = a + v·X + X²`.
#[cfg(test)]
fn redirect_op_old(from: u64, to: u64, o_to: u32) -> Challenge {
    let x: Challenge =
        Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE, Val::ZERO, Val::ZERO])
            .expect("X");
    let x3 = x * x * x;
    let x4: Challenge = x3 * x;
    let w_ext: Val = <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&x4)[0];
    let t = (Val::from_u64(to) - Val::from_u64(from)) * w_ext.inverse();
    Challenge::from_u32(o_to) + x3 * Challenge::from(t)
}

/// Test-only handles to the circuit expressions a forgery targets.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct CmOmcProbes {
    /// `Legacy` only: per record, the 8 digest limbs `hv` whose
    /// `decompose_to_bits` give the positions (empty under `Semantic`/`Bound`,
    /// which split the limbs canonically from private witnesses instead).
    pub hv: Vec<[ExprId; 8]>,
    /// The per-row `op_old` private inputs (sorted order).
    pub op_old: Vec<ExprId>,
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
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(
            self.num_cells() % 4 == 0,
            "d·w must be a multiple of 4 (Challenge packing)"
        );
    }
}

/// A self-verified `omc` leaf proof. Commitments are the dense
/// `commit_countmin` digests on both ends (so this DOES chain against a
/// real prior state, unlike `memcheck`).
pub struct CountMinOmcProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: CountMinCommit,
    pub final_commit: CountMinCommit,
    pub batch_commit: CountMinCommit,
    pub params: CmOmcParams,
}

impl CountMinOmcProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
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

/// The batch sponge's input Challenges (what `Com(B_t)` absorbs) under
/// `binding`: `Legacy` packs one `[key_lo, key_hi, value, 0]` per record
/// ([`pack_batch_to_challenge`], [`commit_batch`]); `Semantic`/`Bound` pack
/// two, the exact key limbs `[k0, k1, k2, k3]` and then `[value, 0, 0, 0]`
/// ([`commit_batch_limbs`]).
#[cfg(test)]
fn batch_sponge_input(batch: &[CountMinUpdate], binding: Binding) -> Vec<Challenge> {
    if !binding.is_bound() {
        return pack_batch_to_challenge(batch);
    }
    batch
        .iter()
        .flat_map(|r| {
            let key = Challenge::from_basis_coefficients_slice(&bind::key_limbs::<Val>(r.key))
                .expect("4 key limbs");
            [key, Challenge::from_u32(r.value)]
        })
        .collect()
}

fn pack_batch_to_challenge(batch: &[CountMinUpdate]) -> Vec<Challenge> {
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

/// Prove one count-min epoch from an arbitrary committed `initial_state`
/// via the `M_old ⊎ W = M_new ⊎ R` multiset rebind.
///
/// # Panics
/// - `params.validate()` failures, `initial_state.params != (d, w)`,
///   `batch.len() != params.batch`.
pub fn prove_countmin_omc(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    prove_countmin_omc_impl(params, initial_state, batch, false)
}

/// Like [`prove_countmin_omc`] but additionally surfaces the `(initial, final)`
/// boundary commitments via the **Expose NPO**, so the leaf proof can be folded
/// by the in-circuit boundary-bound forest
/// ([`crate::recursion::recursive::expose_forest::prove_forest_over`]) — which
/// binds `left.final == right.initial` in-circuit rather than natively. The
/// commitments and proof are otherwise identical to [`prove_countmin_omc`].
pub fn prove_countmin_omc_exposed(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    prove_countmin_omc_impl(params, initial_state, batch, true)
}

/// A built, reusable `omc` Count-Min leaf: the circuit graph, its prover
/// data, and a registered prover. Build once per `(params, expose_boundary,
/// binding)` and call [`Self::prove_epoch`] per batch. The graph is a pure
/// function of the shape except for the two Permute ops' trace-generation
/// hints, which each prove swaps in via `Circuit::update_permute_witnesses`.
/// This hoists the dominant per-leaf costs (graph build + AIR/`ProverData`
/// prep) out of the epoch loop.
pub struct CmOmcLeafCircuit {
    params: CmOmcParams,
    binding: Binding,
    expose: Expose,
    mode: CommitMode,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    table_rows: Vec<usize>,
    #[cfg(test)]
    probes: CmOmcProbes,
}

/// Build the reusable `omc` Count-Min leaf circuit for a shape, with the
/// process default [`Binding`] (`Semantic` unless `ZKSKETCH_BINDING` overrides it).
pub fn build_countmin_omc_leaf(params: CmOmcParams, expose_boundary: bool) -> CmOmcLeafCircuit {
    build_countmin_omc_leaf_with(params, expose_boundary, bind::default_binding())
}

/// Build the reusable `omc` Count-Min leaf circuit for a shape and binding.
///
/// [`Binding::Legacy`] is the pre-fix circuit, unchanged (unsound; kept for
/// side-by-side cost runs and the forgery PoCs). [`Binding::Bound`] differs
/// in exactly these places (see [`crate::sketch::bind`]):
/// - every sponge hashes with a bound zero IV ([`bind::hash_slice_bound`]);
/// - both dense states and every batch record are decomposed with ALU-bound,
///   base-pinned coefficients ([`bind::decompose_bound`]), so the multiset
///   runs on the committed cells and records;
/// - positions come from a canonical split of each ALU-bound digest limb
///   ([`bind::canonical_split_gadget`], private `(pos, hi, dinv)` per record
///   and row), not from a free-coefficient, possibly non-canonical
///   `decompose_to_bits`;
/// - the counter sort carries `(address, value)` coordinate-wise
///   (`address + value·e₁`) instead of `address·2^20 + value`, which
///   collides on BabyBear once `d·w > 1920`. `combined_sorted[0]` is range
///   checked, and `val_sorted` / `op_old` are pinned to the base field
///   (their extension coordinates would otherwise shift addresses inside
///   `enc`);
/// - the key is four exact 16-bit limbs, range-checked and ALU-recomposed
///   into one Challenge ([`bind::key_from_limbs`]) that the routing hash
///   and the batch commitment ([`commit_batch_limbs`]) both absorb. Legacy
///   hashes `key_lo + 2^32·key_hi` as one field element, i.e. the key mod
///   `p`, so keys congruent mod `p` (already among 32-bit keys) share every
///   counter; `tests::congruent_keys_*`.
///
/// The last three bullets (canonical split; coordinate-wise sort key, range
/// and base pins; exact key limbs) are the circuit-semantic fixes `Semantic`
/// shares with `Bound`. Each has a leaf-level test run under all three
/// bindings: `tests::noncanonical_position_semantic_bound_reject`,
/// `tests::stage_g_collision_*`, `tests::op_old_redirect_*` and
/// `tests::congruent_keys_*`. The native model of each binding is
/// [`countmin_omc_advance_with`] / [`countmin_omc_batch_commit_with`].
pub fn build_countmin_omc_leaf_with(
    params: CmOmcParams,
    expose_boundary: bool,
    binding: Binding,
) -> CmOmcLeafCircuit {
    build_countmin_omc_leaf_expose(params, Expose::from_bool(expose_boundary), binding)
}

/// Build the reusable `omc` Count-Min leaf circuit with an explicit
/// composition statement ([`Expose`]). `Expose::None` / `Expose::Boundary`
/// are exactly [`build_countmin_omc_leaf_with`] with `expose_boundary =
/// false / true` (byte-for-byte). `Expose::Interval` additionally takes the
/// batch index `t` as the last public input and exposes
/// `(init, final, (t, t, 0, 0), Poseidon2(TAG_LEAF, t, Com(B_t)))`, where
/// `Com(B_t)` is the in-circuit batch digest (see
/// [`crate::recursion::recursive::statement`]); prove with
/// [`CmOmcLeafCircuit::prove_epoch_at`]. Plain commitments
/// ([`build_countmin_omc_leaf_commit`] with [`CommitMode::Plain`]).
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
/// three Challenges each), allocated as the FIRST private inputs, and
/// hashes each commitment as `[tag, salt…, inputs…]`, i.e.
/// [`commit_countmin_with`] / [`countmin_omc_batch_commit_salted`]. The salts
/// are witnesses, so the VK does not depend on them; prove with
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
    let cell_packing = num_cells / 4;
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let addr_bits = params.addr_bits();
    let l = num_cells + n_ctr; // multiset side length
    if bound {
        assert!(addr_bits <= 24, "bound omc: d·w must be ≤ 2^24");
    }
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;

    // ─── Circuit ─────────────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    if bound {
        b.enable_range(generate_range_trace::<Val, Challenge>);
    }
    if expose.exposes() {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    let init_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    // Surface (initial, final) via the Expose NPO so the boundary propagates into
    // recursion (consumed by the in-circuit boundary-bound forest). These PI
    // wires are connected to the hashed dense-state commitments below, so the
    // exposed values equal the real commitments.
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
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
    // Legacy only: the hashed key field element `key_lo + 2^32·key_hi`.
    let two_pow_32_const =
        (!bound).then(|| b.alloc_const(Challenge::from_u64(1u64 << 32), "2^32"));
    let row_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "row_i"))
        .collect();
    let cell_idx_consts: Vec<ExprId> = (0..num_cells)
        .map(|idx| b.alloc_const(Challenge::from_u64(idx as u64), "cell_idx"))
        .collect();
    let pow2_consts: Vec<ExprId> = (0..w_log2)
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();
    // Bound-only constants: the e₁ basis element (coordinate-wise sort key),
    // the row offsets i·w, and the canonical-split constants.
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

    // B2: the salts of (init, final, batch) are the FIRST 9 private inputs
    // under `Hiding` ([`Openings::private_inputs`] order); `Plain` allocates
    // nothing, so its circuit is byte-identical.
    let salts = hiding::alloc_leaf_salts(&mut b, mode);
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    // Per record: `[key_lo, key_hi, value, 0]` (Legacy) or `[value, 0, 0, 0]`
    // (Semantic/Bound, whose key Challenge is recomposed from exact limbs).
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();
    let mut key_lo = Vec::with_capacity(m);
    let mut key_hi = Vec::with_capacity(m);
    let mut key_limbs: Vec<[ExprId; 4]> = Vec::new();
    let mut value_w = Vec::with_capacity(m);
    for _ in 0..m {
        if bound {
            key_limbs.push(std::array::from_fn(|_| b.alloc_private_input("key_limb")));
        } else {
            key_lo.push(b.alloc_private_input("key_lo"));
            key_hi.push(b.alloc_private_input("key_hi"));
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
        b.tag(f0, "cm_final_packed_0").expect("tag");
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
    // Semantic/Bound: a record's key is four exact 16-bit limbs, range-checked
    // and ALU-recomposed into one Challenge (`bind::key_from_limbs`). The batch
    // sponge absorbs `[key, value]` per record, and the routing hash below
    // absorbs the same key Challenge. Legacy absorbs `[key_lo, key_hi, value,
    // 0]` and routes on `key_lo + 2^32·key_hi`, i.e. on the key mod p, so keys
    // congruent mod p share every counter.
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
        b.tag(b0, "cm_batch_packed_0").expect("tag");
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
    // Cells: any base value (u32 counters reduced mod p) — `pin_base`.
    let o_cells: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| {
            bind::decompose::<Val, Challenge>(
                &mut b,
                p,
                binding,
                bind::no_pin,
                bind::pin_all_base::<Val, Challenge>,
            )
        })
        .collect();
    let n_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| {
            bind::decompose::<Val, Challenge>(
                &mut b,
                p,
                binding,
                bind::no_pin,
                bind::pin_all_base::<Val, Challenge>,
            )
        })
        .collect();
    for k in 0..m {
        if bound {
            // [value, 0, 0, 0]: value pinned, coefficients 1..4 connected to zero.
            let coeffs = bind::decompose::<Val, Challenge>(
                &mut b,
                batch_packed[k],
                binding,
                bind::no_pin,
                |b, i, c| {
                    if i == 0 {
                        bind::pin_base::<Val, Challenge>(b, c);
                    }
                },
            );
            b.connect(coeffs[0], value_w[k]);
            for &c in &coeffs[1..] {
                b.connect(c, zero);
            }
            continue;
        }
        // (key_lo, key_hi, value) pinned; coefficient 3 is connected to zero below.
        let coeffs = bind::decompose::<Val, Challenge>(
            &mut b,
            batch_packed[k],
            binding,
            bind::no_pin,
            |b, i, c| {
                if i < 3 {
                    bind::pin_base::<Val, Challenge>(b, c);
                }
            },
        );
        b.connect(coeffs[0], key_lo[k]);
        b.connect(coeffs[1], key_hi[k]);
        b.connect(coeffs[2], value_w[k]);
        b.connect(coeffs[3], zero);
    }
    let mut key_field = Vec::with_capacity(m);
    if bound {
        key_field = key_chal;
    } else {
        let two_pow_32_const = two_pow_32_const.expect("Legacy 2^32");
        for k in 0..m {
            let hi = b.mul(key_hi[k], two_pow_32_const);
            key_field.push(b.add(key_lo[k], hi));
        }
    }
    if let Some(&kf0) = key_field.first() {
        b.tag(kf0, "cm_key_field_0").expect("tag");
    }

    // Stage F — per-record PRF hash → payload.
    let mut h_w = Vec::with_capacity(m);
    for _ in 0..m {
        h_w.push((b.alloc_private_input("h0"), b.alloc_private_input("h1")));
    }
    // Bound: per record, per row, the canonical split `(pos, hi, dinv)` of the
    // row's digest limb (allocated after `h_w`; pushed after the digests).
    let split_w: Vec<Vec<[ExprId; 3]>> = if bound {
        (0..m)
            .map(|_| {
                (0..d)
                    .map(|_| std::array::from_fn(|_| b.alloc_private_input("split")))
                    .collect()
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut payload = Vec::with_capacity(n_ctr);
    #[cfg(test)]
    let mut probe_hv: Vec<[ExprId; 8]> = Vec::new();
    for k in 0..m {
        let hashed = bind::hash_slice(&mut b, &cfg, &[key_field[k]], zero, binding);
        let (h0, h1) = h_w[k];
        b.connect(hashed[0], h0);
        b.connect(hashed[1], h1);
        if let Some(sc) = &split_c {
            // Digest limb t < d = canonical split (pins it and yields pos_t);
            // limbs d..8 of an ALU-bound Challenge only need a base pin. For
            // d ≤ 4 the second digest Challenge carries no routing and is not
            // decomposed at all.
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
        } else {
            let c0 = b.decompose_ext_to_base_coeffs::<Val>(h0).expect("d h0");
            let c1 = b.decompose_ext_to_base_coeffs::<Val>(h1).expect("d h1");
            let hv = [c0[0], c0[1], c0[2], c0[3], c1[0], c1[1], c1[2], c1[3]];
            #[cfg(test)]
            probe_hv.push(hv);
            for i in 0..d {
                let bits = b
                    .decompose_to_bits::<Val>(hv[i], Val::bits())
                    .expect("bits");
                let mut pos = b.mul(bits[0], pow2_consts[0]);
                for jb in 1..w_log2 {
                    let t = b.mul(bits[jb], pow2_consts[jb]);
                    pos = b.add(pos, t);
                }
                let rw = b.mul(row_consts[i], w_const);
                let comb = b.add(rw, pos);
                let cs = b.mul(comb, shift_val_const);
                payload.push(b.add(cs, value_w[k]));
            }
            for kk in d..8 {
                let _ = b
                    .decompose_to_bits::<Val>(hv[kk], Val::bits())
                    .expect("bits unused");
            }
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
        // First sorted address exact; every later one is it plus a range-checked gap.
        bind::range_exact::<Val, Challenge>(&mut b, combined_sorted[0], addr_bits);
        for r in 0..n_ctr {
            bind::pin_base::<Val, Challenge>(&mut b, val_sorted[r]);
            bind::pin_base::<Val, Challenge>(&mut b, op_old[r]);
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
        let gap = b.sub(combined_sorted[r], combined_sorted[r - 1]);
        let gb = b
            .decompose_to_bits::<Val>(gap, Val::bits())
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
    // enc(a,v) = recompose([a, v, 1, 0]) — the `1` tag in coord 2 keeps real
    // elements disjoint from the zero dummies that inactive W/R rows produce.
    let enc = |b: &mut CircuitBuilder<Challenge>, a: ExprId, v: ExprId| -> ExprId {
        b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[a, v, one, zero])
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

    let circuit = b.build().expect("build countmin_omc circuit");

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
        .expect("get_airs_and_degrees_with_prep (omc)");
    // E-0 table probe (read-only; a no-op unless armed).
    crate::experiments::table_probe::record_leaf(
        "countmin_omc",
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
    if bound {
        prover.register_range_table::<4>();
    }
    if expose.exposes() {
        prover.register_expose_table::<4>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();
    let table_rows: Vec<usize> = ext_degrees.iter().map(|&d| 1usize << d).collect();

    CmOmcLeafCircuit {
        params,
        binding,
        expose,
        mode,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        table_rows,
        #[cfg(test)]
        probes: CmOmcProbes {
            hv: probe_hv,
            op_old: op_old.clone(),
        },
    }
}

/// The witness of one epoch: runner inputs plus the natively computed
/// commitments.
struct CmOmcEpoch {
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    initial_commit: CountMinCommit,
    final_commit: CountMinCommit,
    batch_commit: CountMinCommit,
}

impl CmOmcLeafCircuit {
    /// The VK (preprocessed commitment, `expose_forest::vk_pin_values` order)
    /// of every proof this prebuilt leaf produces — read from its prover data,
    /// so it is derived from the public parameters alone, without proving.
    pub fn vk_pin_values(&self) -> Vec<Challenge> {
        crate::recursion::recursive::expose_forest::common_vk_pin_values(
            self.circuit_prover_data.common_data(),
        )
    }

    pub fn params(&self) -> CmOmcParams {
        self.params
    }
    pub fn binding(&self) -> Binding {
        self.binding
    }
    /// The commitment mode the circuit was built with.
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }
    /// `Σ 2^degree` over all tables.
    pub fn trace_rows(&self) -> u64 {
        self.trace_rows
    }
    /// Padded height of each table (AIR order).
    pub fn table_rows(&self) -> &[usize] {
        &self.table_rows
    }

    /// Native side of one epoch: route + sort + multiset matching, the two
    /// permutation hints swapped into the graph, and the runner inputs.
    /// `openings` are the commitment salts (ignored under `Plain`).
    fn epoch(
        &mut self,
        t: u64,
        initial_state: &CountMinState,
        batch: &[CountMinUpdate],
        openings: &Openings,
    ) -> CmOmcEpoch {
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
        for u in batch {
            apply_update_prf_with(&mut final_state, u, binding);
        }
        // Per record: the PRF digest of its key encoding (see `key_hash_input`).
        let digests: Vec<[Val; 8]> = batch.iter().map(|u| key_digest(u.key, binding)).collect();

        // U_ctr (per record, no key-grouping) + counter sort.
        #[allow(unused_mut)]
        let mut u_ctr_data: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
        for (u, digest) in batch.iter().zip(&digests) {
            for i in 0..d {
                let bucket = (<Val as p3_field::PrimeField64>::as_canonical_u64(&digest[i]) as usize) % w;
                u_ctr_data.push(((i * w + bucket) as u64, u.value));
            }
        }
        // Test-only malicious plan: rewrite the claimed touches and commit the
        // state they imply (see [`CmOmcForge`]).
        #[cfg(test)]
        let forge = FORGE.with(|f| f.borrow().clone());
        #[cfg(test)]
        if let Some(fg) = &forge
            && !fg.touches.is_empty()
        {
            for &(idx, addr, val) in &fg.touches {
                u_ctr_data[idx] = (addr, val);
            }
            let mut s = initial_state.clone();
            for &(a, v) in &u_ctr_data {
                let (row, col) = (a as usize / w, a as usize % w);
                s.counters[row][col] = s.counters[row][col].saturating_add(v);
            }
            final_state = s;
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
        if let Some((from, to)) = forge.as_ref().and_then(|f| f.op_old_redirect) {
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
        let initial_commit = commit_countmin_with(initial_state, mode, &openings.init);
        let final_commit = commit_countmin_with(&committed_final, mode, &openings.final_);
        let batch_commit = countmin_omc_batch_commit_salted(batch, binding, mode, &openings.batch);

        // Native multiset elements. None = zero dummy (inactive W/R row); a real
        // element is keyed by (addr, value) and carries the coord-2 tag in-circuit.
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
            .expect("update permute witnesses (countmin_omc)");

        // ─── Public + private values ─────────────────────────────────────────
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&initial_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&final_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&CountMinCommit(batch_commit)));
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(t));
        }

        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            // The salts come first (see `build_countmin_omc_leaf_commit`).
            private_inputs.extend(openings.private_inputs());
        }
        private_inputs.extend_from_slice(&pack_cells_to_challenge(initial_state));
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&committed_final));
        if binding.is_bound() {
            private_inputs.extend(batch.iter().map(|u| Challenge::from_u32(u.value)));
            for u in batch {
                private_inputs.extend(bind::key_limbs::<Val>(u.key).into_iter().map(Challenge::from));
                private_inputs.push(Challenge::from_u32(u.value));
            }
        } else {
            private_inputs.extend_from_slice(&pack_batch_to_challenge(batch));
            for u in batch {
                private_inputs.push(Challenge::from_u32((u.key & 0xFFFF_FFFF) as u32));
                private_inputs.push(Challenge::from_u32((u.key >> 32) as u32));
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
                Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 coeffs"),
            );
            private_inputs.push(
                Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 coeffs"),
            );
        }
        if self.binding.is_bound() {
            let w_log2 = w.trailing_zeros() as usize;
            // One canonical split per touch, in touch order k·d + i.
            #[allow(unused_mut)]
            let mut splits: Vec<[Val; 3]> = digests
                .iter()
                .flat_map(|digest| {
                    digest
                        .iter()
                        .take(d)
                        .map(|&limb| bind::canonical_split_vals::<Val>(limb, w_log2))
                })
                .collect();
            #[cfg(test)]
            if let Some(fg) = &forge {
                for &(idx, s) in &fg.splits {
                    splits[idx] = s;
                }
            }
            for s in splits {
                private_inputs.extend(s.map(Challenge::from));
            }
        }

        CmOmcEpoch {
            public_inputs,
            private_inputs,
            initial_commit,
            final_commit,
            batch_commit: CountMinCommit(batch_commit),
        }
    }

    /// Run the circuit on one epoch's witness; returns the traces (for the
    /// forgery tests) and the epoch.
    fn run_epoch(
        &mut self,
        initial_state: &CountMinState,
        batch: &[CountMinUpdate],
    ) -> (p3_circuit::tables::Traces<Challenge>, CmOmcEpoch) {
        self.run_epoch_at(1, initial_state, batch)
    }

    /// [`Self::run_epoch`] for batch index `t` (Interval statement only).
    #[allow(dead_code)] // test-only since B2: `prove_epoch_commit` runs `run_epoch_commit`
    fn run_epoch_at(
        &mut self,
        t: u64,
        initial_state: &CountMinState,
        batch: &[CountMinUpdate],
    ) -> (p3_circuit::tables::Traces<Challenge>, CmOmcEpoch) {
        self.run_epoch_commit(t, initial_state, batch, &Openings::plain())
    }

    /// [`Self::run_epoch_at`] with explicit commitment openings.
    fn run_epoch_commit(
        &mut self,
        t: u64,
        initial_state: &CountMinState,
        batch: &[CountMinUpdate],
        openings: &Openings,
    ) -> (p3_circuit::tables::Traces<Challenge>, CmOmcEpoch) {
        let ep = self.epoch(t, initial_state, batch, openings);
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&ep.public_inputs).expect("set pubs");
            runner
                .set_private_inputs(&ep.private_inputs)
                .expect("set privs");
            runner.run().expect("run countmin_omc")
        };
        (traces, ep)
    }

    /// Prove + self-verify arbitrary traces of this circuit.
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

    /// Prove the epoch of batch `t` (1-based) on the prebuilt circuit. `t` is
    /// part of the Interval statement (ignored by the other layouts). `Plain`
    /// circuits only: on a `Hiding` circuit this would open every commitment
    /// with the public zero salt, so it panics; use
    /// [`Self::prove_epoch_commit`] (or, for the no-op leaf,
    /// [`Self::prove_epoch_public_zero`]).
    pub fn prove_epoch_at(
        &mut self,
        t: u64,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> CountMinOmcProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             Openings::for_leaf(..)"
        );
        self.prove_epoch_opened(t, initial_state, batch, &Openings::plain())
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`Openings::for_leaf(seed, CommitFamily::CountMin, t)` for an honest
    /// prover; ignored by a `Plain` circuit). The proof's `initial_commit`,
    /// `final_commit` and `batch_commit` are then `Com(S_{t-1}; ρ^S_{t-1})`,
    /// `Com(S_t; ρ^S_t)` and `Com(B_t; ρ^B_t)`. A `Hiding` circuit panics when
    /// `openings.final_` or `openings.batch` is the public zero salt (never an
    /// honest PRF output): a forgotten opening would otherwise give a
    /// consistent, deterministic chain that nothing downstream detects. The
    /// init salt may be zero only at `t = 1` on the empty genesis state (leaf 1
    /// of the genesis history opens the public `Com(S_0; 0)`); a zero init on
    /// any other input panics
    /// ([`assert_zero_init_opens_public_state`](crate::commitment::hiding::assert_zero_init_opens_public_state)).
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
        openings: &Openings,
    ) -> CountMinOmcProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (Openings::for_leaf), not the public zero salt"
            );
            crate::commitment::hiding::assert_zero_init_opens_public_state(t, openings.init.is_zero(), || {
                initial_state
                    == CountMinState {
                        counters: vec![vec![0u32; self.params.w]; self.params.d],
                        params: CountMinParams { d: self.params.d, w: self.params.w },
                    }
            });
        }
        self.prove_epoch_opened(t, initial_state, batch, openings)
    }

    /// The no-op VK-derivation leaf's epoch: all three commitments opened
    /// with [`Openings::public_zero`], so a batch that changes nothing
    /// exposes `init == final` in either mode. The only path that proves a
    /// `Hiding` leaf with zero final/batch salts, so it accepts exactly the
    /// VK-derivation leaf's public input
    /// ([`cm_omc_noop_leaf_commit`](crate::recursion::recursive::noop_leaf::cm_omc_noop_leaf_commit),
    /// and the harness's `PAD_KEY` no-op batch): batch index `t = 1`, the
    /// EMPTY initial state (whose `Com(S_0; 0)` the verifier recomputes
    /// itself) and a batch of `{ key: 0, value: 0 }` updates. It publishes
    /// only `Com(S_0; 0)` and the zero-salt commitment of that public batch.
    /// "Every value is 0" alone would not do: a value-0 batch leaves ANY
    /// state unchanged, so a real state would publish the deterministic,
    /// guess-checkable `Com(S_t; 0)` as both init and final. The checks are
    /// on the inputs only (the circuit and its VK are unchanged) and apply
    /// in both modes.
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
        self.prove_epoch_opened(t, initial_state, batch, &Openings::public_zero())
    }

    /// Shared body of the three `prove_epoch_*` entry points (no opening
    /// checks).
    fn prove_epoch_opened(
        &mut self,
        t: u64,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
        openings: &Openings,
    ) -> CountMinOmcProof {
        let params = self.params;
        let __t_w = std::time::Instant::now();
        let (traces, ep) = self.run_epoch_commit(t, &initial_state, &batch, openings);
        let __witness = __t_w.elapsed();

        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (omc)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify countmin_omc leaf");
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
            initial_commit: ep.initial_commit,
            final_commit: ep.final_commit,
            batch_commit: ep.batch_commit,
            params,
        }
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

/// Prove batch `t` (1-based) as an **Interval-statement** leaf (process
/// default [`Binding`]); the leaf exposes
/// `(Com(S_{t-1}), Com(S_t), (t, t), Poseidon2(TAG_LEAF, t, Com(B_t)))`.
pub fn prove_countmin_omc_interval(
    params: CmOmcParams,
    t: u64,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    build_countmin_omc_leaf_expose(params, Expose::Interval, bind::default_binding())
        .prove_epoch_at(t, initial_state, batch)
}

/// The batch commitment `Com(B_t)` the omc leaf binds in-circuit (what the
/// public log publishes for the batch), under the process default
/// [`Binding`] (the one [`build_countmin_omc_leaf`] uses).
pub fn countmin_omc_batch_commit(batch: &[CountMinUpdate]) -> [Val; 8] {
    countmin_omc_batch_commit_with(batch, bind::default_binding())
}

/// [`countmin_omc_batch_commit`] for an explicit [`Binding`]: the exact-limb
/// [`commit_batch_limbs`] under `Semantic`/`Bound`, [`commit_batch`] under
/// `Legacy`.
pub fn countmin_omc_batch_commit_with(batch: &[CountMinUpdate], binding: Binding) -> [Val; 8] {
    if binding.is_bound() {
        commit_batch_limbs(batch).0
    } else {
        commit_batch(batch).0
    }
}

/// [`countmin_omc_batch_commit_with`] under a [`CommitMode`]: `Plain` is
/// exactly [`countmin_omc_batch_commit_with`] (the salt is ignored); `Hiding`
/// is `Com(B_t; ρ)` over the same binding-dependent encoding
/// ([`commit_batch_limbs_with`] / [`commit_batch_with`]), the value a
/// `Hiding` leaf opened with `batch = ρ` binds.
pub fn countmin_omc_batch_commit_salted(
    batch: &[CountMinUpdate],
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> [Val; 8] {
    if binding.is_bound() {
        commit_batch_limbs_with(batch, mode, salt).0
    } else {
        commit_batch_with(batch, mode, salt).0
    }
}

/// [`prove_countmin_omc_interval`] with an explicit [`CommitMode`] and the
/// openings of leaf `t` (process default [`Binding`]). Under `Hiding`,
/// zero final/batch salts panic ([`CmOmcLeafCircuit::prove_epoch_commit`]).
pub fn prove_countmin_omc_interval_commit(
    params: CmOmcParams,
    t: u64,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    mode: CommitMode,
    openings: &Openings,
) -> CountMinOmcProof {
    build_countmin_omc_leaf_commit(params, Expose::Interval, bind::default_binding(), mode)
        .prove_epoch_commit(t, initial_state, batch, openings)
}

/// Native single-batch advance: exactly the update the omc leaf proves
/// under the process default [`Binding`], so the resulting state feeds the
/// next leaf's `initial_state` and the boundaries chain.
pub fn countmin_omc_advance(state: &mut CountMinState, batch: &[CountMinUpdate]) {
    countmin_omc_advance_with(state, batch, bind::default_binding());
}

/// [`countmin_omc_advance`] for an explicit [`Binding`]: `Semantic`/`Bound`
/// route each key by its exact 16-bit limbs, `Legacy` by the key mod `p`
/// ([`crate::sketch::countmin_final::key_hash_input`]).
pub fn countmin_omc_advance_with(state: &mut CountMinState, batch: &[CountMinUpdate], binding: Binding) {
    for u in batch {
        apply_update_prf_with(state, u, binding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::countmin::commit_countmin;
    use crate::config::make_perm;
    use crate::sketch::countmin_final::{apply_update_prf, hash_cell_prf, hash_cell_prf_with};

    fn empty(d: usize, w: usize) -> CountMinState {
        CountMinV9::new(&CountMinParams { d, w })
    }

    /// The native update the default-binding leaf proves.
    fn apply_default(state: &mut CountMinState, u: &CountMinUpdate) {
        apply_update_prf_with(state, u, bind::default_binding());
    }

    /// Round-trip against a **non-empty** prior state — the whole point:
    /// the touched old values `O_z` are reconciled against a real
    /// committed `M_old`, not assumed 0. Self-verify (incl. the multiset
    /// equality) passing IS the soundness witness.
    #[test]
    fn omc_round_trip_nonempty_prior() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        // Seed a non-trivial prior state with a real prior batch.
        let mut prior = empty(2, 4);
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
            apply_default(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior.clone(), updates);
        assert_eq!(r.initial_commit.0, commit_countmin(&prior).0);
        assert_eq!(r.final_commit.0, commit_countmin(&expect_final).0);
        assert_ne!(r.initial_commit.0, r.final_commit.0);
    }

    /// **Correctness at the reported shape** (`d=7, w=128`, large batch) where
    /// `omc` beats `merkle` — the regime where touched cells approach
    /// the whole small row. Asserts the certified final commitment equals the
    /// natively-applied Count-Min, i.e. the speed is NOT a degenerate shortcut:
    /// the cheaper proof still commits to the correct state. `#[ignore]`d (a real
    /// STARK prove at a larger shape).
    ///
    /// Run: `cargo test --release --lib countmin_omc::tests::omc_correct_d7_w128_large_batch -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn omc_correct_d7_w128_large_batch() {
        let (d, w, m) = (7usize, 128usize, 128usize);
        let params = CmOmcParams { d, w, batch: m };
        let mut prior = empty(d, w);
        for k in 0..60u64 {
            apply_update_prf(
                &mut prior,
                &CountMinUpdate {
                    key: k.wrapping_mul(0x9E37_79B9) ^ 0x55,
                    value: 1 + (k as u32 % 4),
                },
            );
        }
        let updates: Vec<CountMinUpdate> = (0..m)
            .map(|i| CountMinUpdate {
                key: (i as u64).wrapping_mul(0xABCD_1234) ^ 0x7,
                value: 1 + (i as u32 % 5),
            })
            .collect();
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_default(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior.clone(), updates);
        assert_eq!(r.initial_commit.0, commit_countmin(&prior).0);
        assert_eq!(
            r.final_commit.0,
            commit_countmin(&expect_final).0,
            "omc final commit must equal natively-applied Count-Min at d=7,w=128,m=128"
        );
        println!(
            "omc d=7 w=128 m=128: certified final commitment == native Count-Min (sound, not a shortcut)."
        );
    }

    /// **Tamper.** Commit a corrupted final state (one cell bumped) while
    /// the patch is built from the honest evolution: `M_new` then has an
    /// untouched cell that disagrees with `M_old`, so the multiset
    /// equality cannot hold and the self-verify rejects.
    #[test]
    fn tamper_rejected() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        let prior = empty(2, 4);
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
    #[test]
    fn omc_repeated_keys_nonempty() {
        let params = CmOmcParams {
            d: 4,
            w: 8,
            batch: 4,
        };
        let mut prior = empty(4, 8);
        apply_update_prf(&mut prior, &CountMinUpdate { key: 7, value: 10 });
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_default(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior, updates);
        assert_eq!(r.final_commit.0, commit_countmin(&expect_final).0);
    }

    // ── Binding (see `crate::sketch::bind`): legacy-vs-bound forgery tests ──

    use crate::sketch::forge;
    use p3_circuit::ops::Poseidon2Trace;
    use p3_circuit::ops::NpoTypeId;

    const FP: CmOmcParams = CmOmcParams {
        d: 2,
        w: 8,
        batch: 2,
    };

    fn fp_prior() -> CountMinState {
        let mut prior = empty(FP.d, FP.w);
        apply_update_prf(&mut prior, &CountMinUpdate { key: 3, value: 4 });
        prior
    }

    fn fp_updates() -> Vec<CountMinUpdate> {
        vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 9, value: 5 },
        ]
    }

    fn cfg() -> Poseidon2Config {
        Poseidon2Config::BABY_BEAR_D4_W16
    }

    /// `prior` advanced by `updates` under `binding`'s native model.
    fn advanced(prior: &CountMinState, updates: &[CountMinUpdate], binding: Binding) -> CountMinState {
        let mut s = prior.clone();
        countmin_omc_advance_with(&mut s, updates, binding);
        s
    }

    /// Honest epochs verify under every binding and certify that binding's
    /// native model: the final state ([`countmin_omc_advance_with`]) and the
    /// batch commitment ([`countmin_omc_batch_commit_with`]).
    #[test]
    fn omc_round_trip_both_bindings() {
        for binding in [Binding::Bound, Binding::Semantic, Binding::Legacy] {
            let expect = advanced(&fp_prior(), &fp_updates(), binding);
            let r = prove_countmin_omc_with(FP, fp_prior(), fp_updates(), true, binding);
            assert_eq!(r.initial_commit.0, commit_countmin(&fp_prior()).0);
            assert_eq!(r.final_commit.0, commit_countmin(&expect).0, "{binding:?}");
            assert_eq!(r.batch_commit.0, countmin_omc_batch_commit_with(&fp_updates(), binding));
        }
        // d > 4 exercises the second digest Challenge (bound: split rows 4..d),
        // and 64-bit keys every key limb.
        let p = CmOmcParams { d: 7, w: 8, batch: 3 };
        let prior = empty(7, 8);
        let mut ups = fp_updates();
        ups.push(CountMinUpdate { key: 0xFEDC_BA98_7654_3210, value: 2 });
        for binding in [Binding::Bound, Binding::Semantic] {
            let r = prove_countmin_omc_with(p, prior.clone(), ups.clone(), false, binding);
            assert_eq!(r.final_commit.0, commit_countmin(&advanced(&prior, &ups, binding)).0);
            assert_eq!(r.batch_commit.0, countmin_omc_batch_commit_with(&ups, binding));
        }
    }

    /// `BabyBear p`.
    fn p_bb() -> u64 {
        <Val as p3_field::PrimeField64>::ORDER_U64
    }

    /// Two DISTINCT 32-bit keys congruent mod `p` (`k` and `k + p`).
    const CONGRUENT_LO: u64 = 12_345;

    /// Native routing of keys congruent mod `p`. `Legacy` hashes the key mod
    /// `p`, so `k` and `k + p` (both 32-bit, as the AOL keys are) get the same
    /// digest, the same bucket in every row and the same batch commitment:
    /// the documented control. `Semantic`/`Bound` hash the exact 16-bit limbs
    /// and separate them (here in every row).
    #[test]
    fn congruent_keys_native_routing() {
        let (k1, k2) = (CONGRUENT_LO, CONGRUENT_LO + p_bb());
        assert!(k2 < 1 << 32 && k1 != k2);
        let (d, w) = (7usize, 1usize << 14);
        let routes = |key: u64, binding: Binding| -> Vec<usize> {
            (0..d).map(|i| hash_cell_prf_with(i, key, w, binding)).collect()
        };
        assert_eq!(key_digest(k1, Binding::Legacy), key_digest(k2, Binding::Legacy));
        assert_eq!(routes(k1, Binding::Legacy), routes(k2, Binding::Legacy));
        assert_eq!(routes(k1, Binding::Legacy), (0..d).map(|i| hash_cell_prf(i, k1, w)).collect::<Vec<_>>());
        let one = |k: u64| vec![CountMinUpdate { key: k, value: 1 }];
        assert_eq!(
            countmin_omc_batch_commit_with(&one(k1), Binding::Legacy),
            countmin_omc_batch_commit_with(&one(k2), Binding::Legacy),
            "Legacy batch commitment reduces the key mod p"
        );
        for binding in [Binding::Semantic, Binding::Bound] {
            assert_ne!(key_digest(k1, binding), key_digest(k2, binding));
            let (r1, r2) = (routes(k1, binding), routes(k2, binding));
            assert!(r1.iter().zip(&r2).all(|(a, b)| a != b), "{binding:?}: {r1:?} vs {r2:?}");
            assert_ne!(
                countmin_omc_batch_commit_with(&one(k1), binding),
                countmin_omc_batch_commit_with(&one(k2), binding)
            );
        }
        // Semantic and Bound share the key encoding.
        assert_eq!(routes(k1, Binding::Semantic), routes(k1, Binding::Bound));
    }

    /// Proof level: one batch `[k, k + p]` into an empty sketch. Under
    /// `Legacy` the verified proof certifies a state in which both records hit
    /// the same `d` counters, so the Count-Min estimate of `k` is 2 although
    /// `k` occurs once (the documented control). Under `Semantic`/`Bound` the
    /// certified state keeps them apart and the estimate is exact (1).
    #[test]
    fn congruent_keys_legacy_collide_semantic_bound_separate() {
        let (k1, k2) = (CONGRUENT_LO, CONGRUENT_LO + p_bb());
        let (d, w) = (4usize, 64usize);
        let params = CmOmcParams { d, w, batch: 2 };
        let ups = vec![CountMinUpdate { key: k1, value: 1 }, CountMinUpdate { key: k2, value: 1 }];
        let estimate = |s: &CountMinState, key: u64, binding: Binding| -> u32 {
            (0..d).map(|i| s.counters[i][hash_cell_prf_with(i, key, w, binding)]).min().unwrap()
        };
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let expect = advanced(&empty(d, w), &ups, binding);
            let r = prove_countmin_omc_with(params, empty(d, w), ups.clone(), true, binding);
            assert_eq!(r.final_commit.0, commit_countmin(&expect).0, "{binding:?}");
            let want = if binding.is_bound() { 1 } else { 2 };
            assert_eq!(estimate(&expect, k1, binding), want, "{binding:?}");
            assert_eq!(estimate(&expect, k2, binding), want, "{binding:?}");
            let touched = expect.counters.iter().flatten().filter(|&&c| c > 0).count();
            assert_eq!(touched, if binding.is_bound() { 2 * d } else { d }, "{binding:?}");
        }
    }

    /// Exposed `(init, final)` commitments of a verified proof.
    fn exposed(proof: &p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>) -> ([Val; 8], [Val; 8]) {
        let pv = proof
            .non_primitives
            .iter()
            .map(|e| &e.public_values)
            .find(|v| v.len() == 16)
            .expect("exposed (init, final)");
        (std::array::from_fn(|i| pv[i]), std::array::from_fn(|i| pv[8 + i]))
    }

    /// FORGED FINAL STATE (transplant). Run the honest epoch, then recommit
    /// the first packed final Challenge to a different state `S'` (cell 0
    /// bumped by 5) and rehash. The multiset still runs on the honest
    /// decomposed cells. Returns the exposed final commitment if the forged
    /// proof verifies. Every call first runs the positive control
    /// ([`forge::forged_with_control`]): the same pipeline recommitting the
    /// HONEST final must verify and expose `Com(S)`.
    fn forged_final_state(binding: Binding) -> Option<([Val; 8], CountMinState)> {
        let honest = advanced(&fp_prior(), &fp_updates(), binding);
        let want = commit_countmin(&honest).0;
        forge::forged_with_control(
            &format!("cm omc forged final ({binding:?})"),
            |f| forged_final_state_run(binding, f),
            |(exp, _)| assert_eq!(*exp, want, "control exposes Com(S)"),
        )
    }

    fn forged_final_state_run(binding: Binding, forge_it: bool) -> Option<([Val; 8], CountMinState)> {
        let mut leaf = build_countmin_omc_leaf_with(FP, true, binding);
        let prior = fp_prior();
        let (mut traces, _) = leaf.run_epoch(&prior, &fp_updates());
        let mut forged = advanced(&prior, &fp_updates(), binding);
        if forge_it {
            forged.counters[0][0] += 5;
        }
        let fp0 = traces.tag_to_witness["cm_final_packed_0"];
        let packed0 = pack_cells_to_challenge(&forged)[0];
        forge::set_wid::<Val, Challenge>(&mut traces, fp0, packed0);
        forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, cfg(), &make_perm());
        forge::catch(|| leaf.prove_traces(&traces).ok())
            .flatten()
            .map(|proof| (exposed(&proof).1, forged))
    }

    /// The positive control is live, not decorative: a forger with a
    /// realistic bug (a stale tag, so the packed final is written into the
    /// batch witness instead) rejects honest traces too. Without the control
    /// its forgery would count as "rejected"; with it,
    /// [`forge::accepted_with_control`] panics and names the broken forger.
    #[test]
    fn forger_control_catches_broken_forger() {
        let broken = |forge_it: bool| -> bool {
            let mut leaf = build_countmin_omc_leaf_with(FP, true, Binding::Semantic);
            let (mut traces, _) = leaf.run_epoch(&fp_prior(), &fp_updates());
            let mut st = advanced(&fp_prior(), &fp_updates(), Binding::Semantic);
            if forge_it {
                st.counters[0][0] += 5;
            }
            let wrong = traces.tag_to_witness["cm_batch_packed_0"]; // BUG: should be cm_final_packed_0
            forge::set_wid::<Val, Challenge>(&mut traces, wrong, pack_cells_to_challenge(&st)[0]);
            forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, cfg(), &make_perm());
            forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
        };
        assert!(!broken(true), "the broken forgery is 'rejected' (vacuously)");
        let msg = forge::catch_msg(|| forge::accepted_with_control("broken forger", broken))
            .expect_err("the positive control must flag the broken forger");
        assert!(msg.contains("POSITIVE CONTROL rejected"), "{msg}");
    }

    /// Legacy ACCEPTS a proof whose exposed final commitment is `Com(S')`, a
    /// state the batch never produced: the committed cells are unbound from
    /// the cells the multiset reconciles. Bound rejects it.
    #[test]
    fn forged_final_state_legacy_accepts_bound_rejects() {
        if !bind::probe::fork_binds_decompose() {
            let (final_exposed, forged) = forged_final_state(Binding::Legacy)
                .expect("Legacy accepts the forged final state (PoC)");
            let honest = advanced(&fp_prior(), &fp_updates(), Binding::Legacy);
            assert_eq!(final_exposed, commit_countmin(&forged).0, "exposes Com(S')");
            assert_ne!(final_exposed, commit_countmin(&honest).0, "…not the certified update");
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

    /// FORGED BATCH RECORD (transplant). Run the honest epoch (record 0 = key
    /// 7), then recommit batch record 0 to key 1234 and rehash. The routing
    /// (key_lo/key_hi → key hash → positions) still follows key 7. Legacy
    /// accepts: the in-circuit batch digest names a record whose cells were
    /// never touched. Bound rejects. (The batch commitment is not exposed
    /// today, so this binding matters once it is; see
    /// backend_binding_gaps.)
    #[test]
    fn forged_batch_record_legacy_accepts_bound_rejects() {
        // Positive control first: the same pipeline writing the honest record.
        let run = |binding: Binding| -> bool {
            forge::accepted_with_control(&format!("cm omc forged batch ({binding:?})"), |forge_it| {
                let mut leaf = build_countmin_omc_leaf_with(FP, true, binding);
                let (mut traces, _) = leaf.run_epoch(&fp_prior(), &fp_updates());
                let mut recs = fp_updates();
                if forge_it {
                    recs[0].key = 1234;
                }
                // Record 0's first batch-sponge Challenge: `[key_lo, key_hi, value,
                // 0]` (Legacy) or its exact key limbs (Semantic/Bound).
                let bp0 = traces.tag_to_witness["cm_batch_packed_0"];
                forge::set_wid::<Val, Challenge>(&mut traces, bp0, batch_sponge_input(&recs, binding)[0]);
                forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, cfg(), &make_perm());
                forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
            })
        };
        if !bind::probe::fork_binds_decompose() {
            assert!(run(Binding::Legacy), "Legacy accepts the forged batch record (PoC)");
        }
        assert!(!run(Binding::Bound), "Bound must reject the forged batch record");
        // Merged soundness fork: the fork itself binds decompose coefficients, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if bind::probe::fork_binds_decompose() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(!run(b), "fork binds decompose coefficients: {b:?} must reject too");
            }
        }
    }

    /// FREE SPONGE IV on record 0's routing hash: bump a capacity input of its
    /// Poseidon2 row and rehash. Legacy accepts a digest that is not
    /// `MyHash(key)`: the D = 4 layout leaves the non-CTL capacity free, and
    /// the positions are not tied to the digest anyway. Bound feeds the zero
    /// constant into the capacity, so the CTL read fails.
    #[test]
    fn forged_routing_iv_legacy_accepts_bound_rejects() {
        // Positive control first: the same row edit with a zero bump.
        let run = |binding: Binding| -> bool {
            forge::accepted_with_control(&format!("cm omc forged IV ({binding:?})"), |forge_it| {
                let mut leaf = build_countmin_omc_leaf_with(FP, true, binding);
                let (mut traces, _) = leaf.run_epoch(&fp_prior(), &fp_updates());
                let kf0 = traces.tag_to_witness["cm_key_field_0"].0;
                let key = NpoTypeId::poseidon2_perm(cfg());
                let mut pt = traces
                    .non_primitive_trace::<Poseidon2Trace<Val>>(&key)
                    .expect("poseidon2 trace")
                    .clone();
                // Under Semantic/Bound the batch sponge starts with the same key
                // Challenge (`[key_0, value_0]`), so take the single-Challenge
                // routing sponge: no second input CTL, or (Bound: zero-fed limbs
                // are CTL'd too) the last such row, since routing is built after
                // the batch sponge.
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
                    row.input_values[8] += Val::ONE; // capacity limb 2, coefficient 0
                }
                traces.non_primitive_traces.insert(key, Box::new(pt));
                forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, cfg(), &make_perm());
                forge::accepted(|| leaf.prove_traces(&traces).map(|_| ()))
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

    // ── Circuit-level attacks on the Stage-F/G/H witnesses ──────────────────
    //
    // Ported from the pre-merge hardening track's `attack_*` tests onto the
    // `Binding`-parameterised leaf. Unlike the transplant forgeries above,
    // these do not depend on the fork binding decompose coefficients or the
    // sponge IV: they attack the circuit's own relation (position canonicity,
    // the Stage-G packing, extension-valued private inputs), which only the
    // `Semantic` fixes close. Each attack runs under all three bindings, and
    // each forged run has a control that goes through the SAME plumbing (plan,
    // forged hint or permute executor) with the honest values and must verify,
    // so a rejection is attributable to the forged value.

    use crate::sketch::forge_permute;

    /// Where a (possibly forged) epoch ended.
    #[derive(Debug)]
    enum Outcome {
        /// Proved and verified; the exposed final commitment.
        Accepted([Val; 8]),
        /// The runner refused the witness (a constraint it evaluates while
        /// filling the witness, e.g. a `connect` conflict).
        RunnerRejected(String),
        /// Traces were produced, but proving or verification failed.
        ProofRejected(String),
    }

    impl Outcome {
        fn accepted(&self) -> Option<[Val; 8]> {
            match self {
                Outcome::Accepted(f) => Some(*f),
                _ => None,
            }
        }
        /// Rejected by the runner on a witness conflict (not a plan bug).
        fn assert_runner_conflict(&self, what: &str) {
            match self {
                Outcome::RunnerRejected(m)
                    if m.contains("run countmin_omc") && m.contains("WitnessConflict") => {}
                o => panic!("{what}: expected a runner WitnessConflict, got {o:?}"),
            }
        }
        /// Rejected by the verifier: the forged traces were proved, and only
        /// the AIRs/buses could reject them.
        fn assert_verifier_rejects(&self, what: &str) {
            match self {
                Outcome::ProofRejected(m) if m.starts_with("verify:") => {}
                o => panic!("{what}: expected a verifier rejection, got {o:?}"),
            }
        }
    }

    /// Run, prove and verify one epoch on `leaf` under the malicious `plan`.
    fn run_plan(
        leaf: &mut CmOmcLeafCircuit,
        prior: &CountMinState,
        updates: &[CountMinUpdate],
        plan: CmOmcForge,
    ) -> Outcome {
        FORGE.with(|f| *f.borrow_mut() = Some(plan));
        let ran = forge::catch_msg(|| leaf.run_epoch(prior, updates));
        FORGE.with(|f| *f.borrow_mut() = None);
        let (traces, ep) = match ran {
            Ok(x) => x,
            Err(m) => return Outcome::RunnerRejected(m),
        };
        match forge::catch_msg(|| leaf.prove_traces(&traces)) {
            Ok(Ok(proof)) => {
                let (init, fin) = exposed(&proof);
                assert_eq!(init, ep.initial_commit.0, "exposes the committed prior");
                assert_eq!(fin, ep.final_commit.0, "exposes the committed final state");
                Outcome::Accepted(fin)
            }
            Ok(Err(e)) => Outcome::ProofRejected(e),
            Err(m) => Outcome::ProofRejected(format!("prove panicked: {m}")),
        }
    }

    /// `prior` plus every record's touch, with `(touch index k·d + i) →
    /// (address, value)` overrides.
    fn fold_touches(
        prior: &CountMinState,
        updates: &[CountMinUpdate],
        overrides: &[(usize, u64, u32)],
        binding: Binding,
    ) -> CountMinState {
        let (d, w) = (prior.params.d, prior.params.w);
        let mut s = prior.clone();
        for (k, u) in updates.iter().enumerate() {
            for i in 0..d {
                let (a, v) = overrides
                    .iter()
                    .find(|o| o.0 == k * d + i)
                    .map(|o| (o.1 as usize, o.2))
                    .unwrap_or((i * w + hash_cell_prf_with(i, u.key, w, binding), u.value));
                s.counters[a / w][a % w] = s.counters[a / w][a % w].saturating_add(v);
            }
        }
        s
    }

    /// Digest limbs of the routing hash of `key` under `binding` (the
    /// in-circuit `hv`): `MyHash([key, 0, 0, 0])` for Legacy,
    /// `MyHash([k0, k1, k2, k3])` for Semantic/Bound.
    fn digest_limbs(key: u64, binding: Binding) -> [u64; 8] {
        key_digest(key, binding).map(|v| <Val as p3_field::PrimeField64>::as_canonical_u64(&v))
    }

    /// First key from `start` whose row-`i < d` digest limb `x` has a
    /// non-canonical twin `x + p < 2^31`.
    fn key_with_small_limb(d: usize, start: u64, binding: Binding) -> (u64, usize, u64) {
        let p = <Val as p3_field::PrimeField64>::ORDER_U64;
        let lim = (1u64 << Val::bits()) - p;
        for key in start.. {
            let h = digest_limbs(key, binding);
            if let Some(i) = (0..d).find(|&i| h[i] < lim) {
                return (key, i, h[i]);
            }
        }
        unreachable!()
    }

    /// ATTACK 1 — non-canonical bucket position. For a record whose row-`row`
    /// digest limb `x` has a twin `x + p < 2^31`, the prover claims the
    /// position of the integer `x + p`. Since `p ≡ 1 (mod w)` that is bucket
    /// `(x + 1) mod w`: the increment is credited to the neighbouring column.
    /// `Legacy` gets the 31 bits of `x + p` from its bit-decomposition hint;
    /// `Semantic`/`Bound` get the split `(pos, hi)` of `x + p` as the private
    /// split witnesses. With `forged = false` the same plumbing carries the
    /// honest values (control). Returns the outcome and the claimed state.
    fn noncanonical_position(binding: Binding, forged: bool) -> (Outcome, CountMinState) {
        let (d, w, m) = (2usize, 16usize, 2usize);
        let params = CmOmcParams { d, w, batch: m };
        let log_w = w.trailing_zeros() as usize;
        let (key, row, x) = key_with_small_limb(d, 1, binding);
        let updates = vec![
            CountMinUpdate { key, value: 3 },
            CountMinUpdate { key: key + 1_000_003, value: 2 },
        ];
        let prior = empty(d, w);
        let v = if forged { x + <Val as p3_field::PrimeField64>::ORDER_U64 } else { x };
        assert!(v < 1u64 << Val::bits());
        let bucket = (v % w as u64) as usize;
        assert_eq!(bucket, (x as usize + usize::from(forged)) % w);
        let touch = (row, (row * w + bucket) as u64, 3u32);
        let mut leaf = build_countmin_omc_leaf_with(params, true, binding);
        let mut plan = CmOmcForge {
            touches: vec![touch],
            ..Default::default()
        };
        if binding.is_bound() {
            let (pos, hi) = (v & (w as u64 - 1), v >> log_w);
            let dd = Val::from_u64(bind::hi_max::<Val>(log_w)) - Val::from_u64(hi);
            let split = [
                Val::from_u64(pos),
                Val::from_u64(hi),
                dd.try_inverse().unwrap_or(Val::ZERO),
            ];
            if !forged {
                assert_eq!(split, bind::canonical_split_vals::<Val>(Val::from_u64(x), log_w));
            }
            plan.splits = vec![(row, split)];
        } else {
            let hv = forge_permute::wid_of(&leaf.circuit, leaf.probes.hv[0][row]);
            let bits = (0..Val::bits())
                .map(|j| Challenge::from_u64((v >> j) & 1))
                .collect();
            forge_permute::forge_hint(&mut leaf.circuit, hv, bits);
        }
        let claimed = fold_touches(&prior, &updates, &[touch], binding);
        (run_plan(&mut leaf, &prior, &updates, plan), claimed)
    }

    /// Attack 1 under every binding. `Semantic` and `Bound` reject the
    /// non-canonical split at the runner (`HI_MAX − hi` fails its exact range
    /// check, and `d = 0 ⇒ pos = 0` covers `hi = HI_MAX`). `Legacy` accepts
    /// it where the fork's full-width `decompose_to_bits` admits non-canonical
    /// bits (the pinned rev 19dcb37), and rejects it where the fork
    /// canonicalises them (the merged soundness fork;
    /// `bind::probe::fork_canonical_bits`).
    #[test]
    fn noncanonical_position_semantic_bound_reject() {
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let (ctl, honest) = noncanonical_position(binding, false);
            eprintln!("noncanonical position {binding:?} control: {ctl:?}");
            assert_eq!(
                ctl.accepted(),
                Some(commit_countmin(&honest).0),
                "{binding:?}: the control (honest values, same plumbing) must verify"
            );
            let (out, claimed) = noncanonical_position(binding, true);
            eprintln!("noncanonical position {binding:?} forged: {out:?}");
            assert_ne!(claimed, honest, "the claimed state is not the Count-Min fold");
            if binding == Binding::Legacy && !bind::probe::fork_canonical_bits() {
                assert_eq!(
                    out.accepted(),
                    Some(commit_countmin(&claimed).0),
                    "Legacy accepts the x + p position (PoC, unfixed fork)"
                );
            } else {
                out.assert_runner_conflict(&format!("{binding:?} non-canonical position"));
            }
        }
    }

    /// ATTACK 2 — Stage-G packing collision. `Legacy` packs a counter touch
    /// as `comb·2^20 + value` in ONE field element, and on BabyBear
    /// `1920·2^20 = p − 1`, so `(a + 1920)·2^20 + (v + 1) ≡ a·2^20 + v`. With
    /// `d·w = 2048 > 1920`, a record routed to row-0 bucket `a < 128` is
    /// re-split in the sorted view as address `a + 1920` (row 1) with value
    /// `v + 1`: the increment moves to an unrelated cell and grows by one.
    /// `proof_level` also forges the Stage-G PermuteAir outputs to the claimed
    /// sorted tuples (in the binding's encoding), so no runner conflict
    /// remains and only the PermuteBus multiset equality can reject.
    fn stage_g_collision(
        binding: Binding,
        forged: bool,
        proof_level: bool,
    ) -> (Outcome, CountMinState) {
        let (d, w, m) = (2usize, 1024usize, 2usize);
        let params = CmOmcParams { d, w, batch: m };
        let key = (1u64..)
            .find(|&k| hash_cell_prf_with(0, k, w, binding) < 128)
            .expect("key with row-0 bucket < 128");
        let a = hash_cell_prf_with(0, key, w, binding) as u64;
        let updates = vec![
            CountMinUpdate { key, value: 5 },
            CountMinUpdate { key: key + 7_777, value: 1 },
        ];
        let prior = empty(d, w);
        let touch = if forged { (0, a + 1920, 6) } else { (0, a, 5) };
        let mut leaf = build_countmin_omc_leaf_with(params, true, binding);
        if proof_level {
            let mut sorted: Vec<(u64, u32)> = updates
                .iter()
                .flat_map(|u| {
                    (0..d).map(move |i| ((i * w + hash_cell_prf_with(i, u.key, w, binding)) as u64, u.value))
                })
                .collect();
            sorted[0] = (touch.1, touch.2);
            sorted.sort_by_key(|&(c, _)| c); // the same stable sort as `epoch`
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
            // Permute op 0 is the Stage-G counter sort (op 1 is the multiset).
            forge_permute::forge_permute_outputs(&mut leaf.circuit, 0, tuples);
        }
        let plan = CmOmcForge {
            touches: vec![touch],
            ..Default::default()
        };
        let claimed = fold_touches(&prior, &updates, &[touch], binding);
        (run_plan(&mut leaf, &prior, &updates, plan), claimed)
    }

    fn check_stage_g_collision(proof_level: bool) {
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let what = format!("{binding:?} Stage-G collision (proof_level={proof_level})");
            let (ctl, honest) = stage_g_collision(binding, false, proof_level);
            eprintln!("{what} control: {ctl:?}");
            assert_eq!(
                ctl.accepted(),
                Some(commit_countmin(&honest).0),
                "{what}: the control must verify"
            );
            let (out, claimed) = stage_g_collision(binding, true, proof_level);
            eprintln!("{what} forged: {out:?}");
            assert_ne!(claimed, honest);
            if binding.is_bound() {
                if proof_level {
                    out.assert_verifier_rejects(&what);
                } else {
                    out.assert_runner_conflict(&what);
                }
            } else {
                // In-field arithmetic, independent of the fork.
                assert_eq!(
                    out.accepted(),
                    Some(commit_countmin(&claimed).0),
                    "{what}: Legacy accepts the (a + 1920, v + 1) re-split (PoC)"
                );
            }
        }
    }

    /// Attack 2, witness level: `Semantic`/`Bound` sort `(address, value)`
    /// coordinate-wise, so the re-split tuple differs from the Stage-F tuple
    /// and the runner's Stage-G `connect` conflicts. `Legacy` ACCEPTS.
    #[test]
    fn stage_g_collision_legacy_accepts_semantic_bound_reject() {
        check_stage_g_collision(false);
    }

    /// Attack 2, proof level: with the PermuteAir outputs forged too, the
    /// verifier rejects `Semantic`/`Bound` on the PermuteBus. `Legacy`
    /// ACCEPTS (the forged outputs equal the honest packed values).
    #[test]
    fn stage_g_collision_proof_level_legacy_accepts_semantic_bound_reject() {
        check_stage_g_collision(true);
    }

    /// ATTACK 3 — extension-valued `op_old`. `op_old` is a private input in
    /// the degree-4 extension, and `enc(a, v) = a + v·X + X²` is injective only
    /// for BASE `v`: with `op_old = O[to] + t·X³`, `t = (to − from)/W`, both the
    /// read and the write element of the active row at `from` encode address
    /// `to`, so the update is committed at an untouched cell `to` (chosen
    /// with a non-zero committed old value, so the redirect also reconciles a
    /// real prior). `proof_level` (`Semantic`/`Bound` only) also forges the
    /// byte hint of `op_old`'s base pin to `[op_old, 0, 0, 0]`, so the byte
    /// reconstruction equals the extension-valued `op_old` and no runner
    /// conflict remains; only the RangeAir lookup (bytes in `[0, 256)`) can
    /// reject.
    fn op_old_redirect(
        binding: Binding,
        forged: bool,
        proof_level: bool,
    ) -> (Outcome, CountMinState, CountMinState) {
        let (d, w, m) = (2usize, 16usize, 2usize);
        let params = CmOmcParams { d, w, batch: m };
        let mut prior = empty(d, w);
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
        let honest = fold_touches(&prior, &updates, &[], binding);
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
            let wid = forge_permute::wid_of(&leaf.circuit, leaf.probes.op_old[r]);
            forge_permute::forge_hint(&mut leaf.circuit, wid, bytes);
        }
        let plan = CmOmcForge {
            op_old_redirect: forged.then_some((from, to)),
            ..Default::default()
        };
        (run_plan(&mut leaf, &prior, &updates, plan), honest, claimed)
    }

    /// Attack 3, witness level. `Legacy` ACCEPTS a proof that commits the
    /// increment at the wrong cell (fork-independent: `op_old` is a free
    /// extension-valued private input). `Semantic`/`Bound` pin `op_old` to
    /// the base field, so the runner's byte reconstruction conflicts.
    #[test]
    fn op_old_redirect_legacy_accepts_semantic_bound_reject() {
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let what = format!("{binding:?} op_old redirect");
            let (ctl, honest, _) = op_old_redirect(binding, false, false);
            eprintln!("{what} control: {ctl:?}");
            assert_eq!(ctl.accepted(), Some(commit_countmin(&honest).0), "{what}: control");
            let (out, honest, claimed) = op_old_redirect(binding, true, false);
            eprintln!("{what} forged: {out:?}");
            assert_ne!(claimed, honest);
            if binding.is_bound() {
                out.assert_runner_conflict(&what);
            } else {
                assert_eq!(
                    out.accepted(),
                    Some(commit_countmin(&claimed).0),
                    "{what}: Legacy accepts the redirect (PoC)"
                );
            }
        }
    }

    /// Attack 3, proof level (`Semantic`/`Bound`): with the base pin's byte
    /// hint forged as well, the verifier rejects on the Range lookup.
    #[test]
    fn op_old_redirect_proof_level_rejected() {
        for binding in [Binding::Semantic, Binding::Bound] {
            let what = format!("{binding:?} op_old redirect (proof level)");
            let (ctl, honest, _) = op_old_redirect(binding, false, true);
            eprintln!("{what} control: {ctl:?}");
            assert_eq!(ctl.accepted(), Some(commit_countmin(&honest).0), "{what}: control");
            let (out, _, _) = op_old_redirect(binding, true, true);
            eprintln!("{what} forged: {out:?}");
            out.assert_verifier_rejects(&what);
        }
    }

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────

    use crate::commitment::hiding::{SaltSeed, rho_batch_bb, rho_state_bb};
    use crate::recursion::recursive::expose_forest::{
        batch_log, check_leaves_against_log, check_root_against_log, prove_hiding_merge,
        read_exposed_statement, root_vk_deriver, verify_bound_stark_proof_against_log,
        vk_pin_values,
    };
    use crate::recursion::recursive::noop_leaf::cm_omc_noop_leaf_commit;
    use crate::recursion::recursive::root_vk::ForestShape;
    use crate::recursion::recursive::statement::{hash_bb, leaf_digest};

    const HP: CmOmcParams = CmOmcParams { d: 2, w: 4, batch: 2 };
    const CM: CommitFamily = CommitFamily::CountMin;

    fn hiding_leaf(binding: Binding) -> CmOmcLeafCircuit {
        build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding)
    }

    fn hp_prior() -> CountMinState {
        let mut prior = empty(HP.d, HP.w);
        apply_update_prf(&mut prior, &CountMinUpdate { key: 3, value: 4 });
        prior
    }

    fn hp_batches() -> Vec<Vec<CountMinUpdate>> {
        vec![
            vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }],
            vec![CountMinUpdate { key: 13, value: 2 }, CountMinUpdate { key: 7, value: 4 }],
        ]
    }

    /// Flat basis coefficients of VK pin values.
    fn vk_flat(vk: &[Challenge]) -> Vec<u64> {
        vk.iter()
            .flat_map(|c| {
                <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                    .iter()
                    .map(|x| <Val as p3_field::PrimeField64>::as_canonical_u64(x))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// A VK recorded at main@7089f70 (pre-B2): 8 base values, each the first
    /// coefficient of one pin Challenge.
    fn vk_literal(v: [u64; 8]) -> Vec<u64> {
        v.iter().flat_map(|&x| [x, 0, 0, 0]).collect()
    }

    /// (1) A hiding leaf's commitments (the proof's `initial/final/batch`
    /// fields and the exposed Interval statement) equal the NATIVE hiding
    /// commitments under the leaf-`t` openings, under every binding.
    #[test]
    fn hiding_leaf_exposes_native_hiding_commitments() {
        let seed = SaltSeed::for_tests(21);
        let t = 3u64;
        let ups = hp_batches()[0].clone();
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut leaf = hiding_leaf(binding);
            assert_eq!(leaf.commit_mode(), CommitMode::Hiding);
            let r = leaf.prove_epoch_commit(t, hp_prior(), ups.clone(), &Openings::for_leaf(&seed, CM, t));
            let expect = advanced(&hp_prior(), &ups, binding);
            let init = commit_countmin_with(&hp_prior(), CommitMode::Hiding, &rho_state_bb(&seed, CM, t - 1));
            let fin = commit_countmin_with(&expect, CommitMode::Hiding, &rho_state_bb(&seed, CM, t));
            let bc = countmin_omc_batch_commit_salted(&ups, binding, CommitMode::Hiding, &rho_batch_bb(&seed, CM, t));
            assert_eq!(r.initial_commit, init, "{binding:?}");
            assert_eq!(r.final_commit, fin, "{binding:?}");
            assert_eq!(r.batch_commit.0, bc, "{binding:?}");
            assert_ne!(init, commit_countmin(&hp_prior()), "{binding:?}: hiding != plain");
            assert_ne!(fin, commit_countmin(&expect), "{binding:?}: hiding != plain");
            assert_ne!(bc, countmin_omc_batch_commit_with(&ups, binding), "{binding:?}: hiding != plain");
            let st = read_exposed_statement(&r.output.0);
            assert_eq!(st.init, init.0.to_vec(), "{binding:?}");
            assert_eq!(st.final_, fin.0.to_vec(), "{binding:?}");
            let iv = st.interval.expect("interval layout");
            assert_eq!((iv.lo, iv.hi), (Val::from_u64(t), Val::from_u64(t)));
            assert_eq!(iv.digest, leaf_digest(&hash_bb, 4, t, &bc), "{binding:?}: H(TAG_LEAF, t, Com(B_t; ρ))");
        }
        // The one-call API (process default binding).
        let dflt = bind::default_binding();
        let o = Openings::for_leaf(&seed, CM, t);
        let r = prove_countmin_omc_interval_commit(HP, t, hp_prior(), ups.clone(), CommitMode::Hiding, &o);
        let fin = commit_countmin_with(&advanced(&hp_prior(), &ups, dflt), CommitMode::Hiding, &o.final_);
        assert_eq!(r.final_commit, fin);
        // Boundary layout: the exposed pair is the hiding pair too (leaf 1 of
        // the genesis history, from the empty S_0: its zero init salt opens
        // only that public state).
        let s0 = empty(HP.d, HP.w);
        let mut bleaf = build_countmin_omc_leaf_commit(HP, Expose::Boundary, Binding::Semantic, CommitMode::Hiding);
        let r = bleaf.prove_epoch_commit(1, s0.clone(), ups.clone(), &Openings::for_leaf(&seed, CM, 1));
        let (i, f) = exposed(&r.output.0);
        assert_eq!(i, commit_countmin_with(&s0, CommitMode::Hiding, &SaltBb::ZERO).0);
        assert_eq!(f, r.final_commit.0);
    }

    /// (2) The hiding leaf's VK does not depend on the salts (two different
    /// openings, and the zero-salt no-op leaf, give one VK), differs from the
    /// Plain VK, and the Plain circuit is the pre-B2 circuit: its VK equals
    /// the value recorded at main@7089f70, through both the old builder and
    /// `build_countmin_omc_leaf_commit(.., Plain)`.
    #[test]
    fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
        let recorded = [
            (Expose::Interval, Binding::Semantic, [311146798, 1251184148, 67745973, 1950185229, 813267801, 1800539963, 440903848, 825798510]),
            (Expose::Interval, Binding::Bound, [609245164, 1860305887, 1884344271, 1329743628, 615658389, 735468151, 734990312, 1891164946]),
            (Expose::Boundary, Binding::Legacy, [1736090810, 1831588262, 662316068, 1368614943, 306038768, 912717005, 886156929, 1189438024]),
            (Expose::None, Binding::Semantic, [1834649507, 1407219679, 827127958, 416953406, 1951498694, 439518398, 1447935561, 760283013]),
        ];
        for (expose, binding, vk) in recorded {
            let old = build_countmin_omc_leaf_expose(HP, expose, binding).vk_pin_values();
            let plain = build_countmin_omc_leaf_commit(HP, expose, binding, CommitMode::Plain).vk_pin_values();
            assert_eq!(vk_flat(&old), vk_literal(vk), "{expose:?}/{binding:?}: Plain VK drifted from main@7089f70");
            assert_eq!(plain, old, "{expose:?}/{binding:?}");
            let hid = build_countmin_omc_leaf_commit(HP, expose, binding, CommitMode::Hiding).vk_pin_values();
            assert_ne!(hid, old, "{expose:?}/{binding:?}: the hiding circuit differs");
        }
        let mut leaf = hiding_leaf(Binding::Semantic);
        let vk = leaf.vk_pin_values();
        let ups = hp_batches()[0].clone();
        // Leaf 1 starts from the empty S_0 (its zero init salt opens only that
        // public state); leaf 5 from a real prior.
        let a = leaf.prove_epoch_commit(1, empty(HP.d, HP.w), ups.clone(), &Openings::for_leaf(&SaltSeed::for_tests(1), CM, 1));
        let b = leaf.prove_epoch_commit(5, hp_prior(), ups, &Openings::for_leaf(&SaltSeed::for_tests(2), CM, 5));
        assert_ne!(a.final_commit, b.final_commit);
        assert_eq!(vk_pin_values(&a.output.0), vk);
        assert_eq!(vk_pin_values(&b.output.0), vk);
        let noop = cm_omc_noop_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Hiding);
        assert_eq!(vk_pin_values(&noop), vk, "the zero-salt no-op leaf has the real leaves' VK");
    }

    /// (3) Equal states at two versions get different hiding commitments,
    /// both different from the plain one; at the proof level, two no-op
    /// (value-0) leaves at `t = 1, 2` from the empty genesis state `S_0`
    /// (leaf 1's zero init salt opens only that public state) expose
    /// `Com(S_0; 0) → Com(S_0; ρ_1) → Com(S_0; ρ_2)`: three distinct values
    /// for one state, chained.
    #[test]
    fn equal_states_get_unlinkable_hiding_commitments() {
        let seed = SaltSeed::for_tests(33);
        let s = hp_prior();
        let (r1, r2) = (rho_state_bb(&seed, CM, 1), rho_state_bb(&seed, CM, 2));
        let (c1, c2) = (
            commit_countmin_with(&s, CommitMode::Hiding, &r1),
            commit_countmin_with(&s, CommitMode::Hiding, &r2),
        );
        assert_ne!(c1, c2);
        assert_ne!(c1, commit_countmin(&s));
        assert_ne!(c2, commit_countmin(&s));
        assert_eq!(commit_countmin_with(&s, CommitMode::Plain, &r1), commit_countmin(&s), "Plain ignores the salt");

        let s = empty(HP.d, HP.w);
        let (c1, c2) = (
            commit_countmin_with(&s, CommitMode::Hiding, &r1),
            commit_countmin_with(&s, CommitMode::Hiding, &r2),
        );
        let zero_batch = vec![CountMinUpdate { key: 1, value: 0 }, CountMinUpdate { key: 2, value: 0 }];
        let mut leaf = hiding_leaf(Binding::Semantic);
        let l1 = leaf.prove_epoch_commit(1, s.clone(), zero_batch.clone(), &Openings::for_leaf(&seed, CM, 1));
        let l2 = leaf.prove_epoch_commit(2, s.clone(), zero_batch, &Openings::for_leaf(&seed, CM, 2));
        let (s1, s2) = (read_exposed_statement(&l1.output.0), read_exposed_statement(&l2.output.0));
        assert_eq!(s1.init, commit_countmin_with(&s, CommitMode::Hiding, &SaltBb::ZERO).0.to_vec());
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
    /// a leaf opened with a wrong batch or final randomizer mismatches the
    /// log; and a leaf 2 whose init uses a different `ρ_1` than leaf 1's
    /// final cannot be merged (the in-circuit `left.final == right.init`).
    #[test]
    fn wrong_rho_rejected_by_log_and_inconsistent_rho_breaks_merge() {
        let binding = Binding::Semantic;
        let (a, b) = (SaltSeed::for_tests(41), SaltSeed::for_tests(42));
        let bs = hp_batches();
        let s0 = empty(HP.d, HP.w);
        let s1 = advanced(&s0, &bs[0], binding);
        let s2 = advanced(&s1, &bs[1], binding);
        let log_for = |seed: &SaltSeed| {
            let bc: Vec<[Val; 8]> = (0..2)
                .map(|k| {
                    countmin_omc_batch_commit_salted(&bs[k], binding, CommitMode::Hiding, &rho_batch_bb(seed, CM, k as u64 + 1))
                })
                .collect();
            batch_log(
                &commit_countmin_with(&s0, CommitMode::Hiding, &SaltBb::ZERO).0,
                &commit_countmin_with(&s2, CommitMode::Hiding, &rho_state_bb(seed, CM, 2)).0,
                &bc,
            )
        };
        let (log_a, log_b) = (log_for(&a), log_for(&b));
        let mut leaf = hiding_leaf(binding);
        let l1 = leaf.prove_epoch_commit(1, s0.clone(), bs[0].clone(), &Openings::for_leaf(&a, CM, 1)).output;
        let l2 = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &Openings::for_leaf(&a, CM, 2)).output;
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log_a, Expose::Interval), Ok(()));
        assert!(check_leaves_against_log(&[&l1.0, &l2.0], &log_b, Expose::Interval).is_err(), "another seed's log");

        // Leaf 2 opened with a wrong batch randomizer: its digest H(TAG_LEAF, 2,
        // Com(B_2; ρ')) is not the log's.
        let bad_batch = Openings { batch: rho_batch_bb(&b, CM, 2), ..Openings::for_leaf(&a, CM, 2) };
        let l2b = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_batch).output;
        let e = check_leaves_against_log(&[&l1.0, &l2b.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("digest")), "{e:?}");
        // … with a wrong final randomizer: Com(S_2; ρ') is not the log's Com(S_T).
        let bad_final = Openings { final_: rho_state_bb(&b, CM, 2), ..Openings::for_leaf(&a, CM, 2) };
        let l2f = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_final).output;
        let e = check_leaves_against_log(&[&l1.0, &l2f.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("Com(S_T)")), "{e:?}");

        // Composition: the honest pair merges and verifies against log A.
        let shape = ForestShape::forest(2);
        let root = prove_hiding_merge(&l1, &l2);
        let noop = cm_omc_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
        let vk = root_vk_deriver(noop).root_vk(&shape);
        verify_bound_stark_proof_against_log(&root.0, &vk, &log_a, &shape);
        assert!(check_root_against_log(&root.0, &log_b, &shape).is_err());

        // Inconsistent ρ_1 across the boundary: the merge is unprovable.
        let bad_init = Openings { init: rho_state_bb(&b, CM, 1), ..Openings::for_leaf(&a, CM, 2) };
        let l2i = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_init).output;
        assert_ne!(read_exposed_statement(&l2i.0).init, read_exposed_statement(&l1.0).final_);
        let e = forge::catch_msg(|| prove_hiding_merge(&l1, &l2i)).map(|_| ());
        println!("B2 inconsistent ρ_1 merge: {e:?}");
        assert!(
            e.as_ref().is_err_and(|m| m.contains("WitnessConflict")),
            "leaf 2's init must use leaf 1's final randomizer: {e:?}"
        );
    }

    /// (5) The zero-salt no-op leaf of a Hiding circuit still exposes
    /// `init == final` (`= Com(S_0; 0)`, the public anchor), so the twin-merge
    /// root-VK derivation works unchanged.
    #[test]
    fn hiding_noop_leaf_has_init_eq_final() {
        for binding in [Binding::Semantic, Binding::Bound] {
            let noop = cm_omc_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
            let st = read_exposed_statement(&noop);
            let anchor = commit_countmin_with(&empty(HP.d, HP.w), CommitMode::Hiding, &SaltBb::ZERO);
            assert_eq!(st.init, st.final_, "{binding:?}");
            assert_eq!(st.init, anchor.0.to_vec(), "{binding:?}");
            assert_ne!(anchor, commit_countmin(&empty(HP.d, HP.w)), "{binding:?}");
        }
    }

    /// (8, with `commitment::hiding::tests::salt_private_inputs_have_alu_creators`)
    /// Build and prove the Hiding leaf at a tiny shape. Under the DEBUG
    /// profile (`cargo test --lib countmin_omc::tests::hiding_leaf_tiny_debug`)
    /// the fork debug-asserts, during the build, that each of the 9 salt
    /// private inputs has an ALU creator.
    #[test]
    fn hiding_leaf_tiny_debug() {
        let p = CmOmcParams { d: 2, w: 4, batch: 1 };
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = build_countmin_omc_leaf_commit(p, Expose::Interval, binding, CommitMode::Hiding);
            let ups = vec![CountMinUpdate { key: 9, value: 2 }];
            let seed = SaltSeed::for_tests(8);
            let r = leaf.prove_epoch_commit(1, empty(2, 4), ups.clone(), &Openings::for_leaf(&seed, CM, 1));
            let fin = advanced(&empty(2, 4), &ups, binding);
            assert_eq!(r.final_commit, commit_countmin_with(&fin, CommitMode::Hiding, &rho_state_bb(&seed, CM, 1)));
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
        let o = Openings::for_leaf(&seed, CM, t);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut plain = build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
            let mut leaf = hiding_leaf(binding);
            let (p0, a0) = trace_rows(&plain.run_epoch_at(t, &hp_prior(), &ups).0);
            let (p1, a1) = trace_rows(&leaf.run_epoch_commit(t, &hp_prior(), &ups, &o).0);
            println!("B2 leaf rows {binding:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 6, "{binding:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 9, "{binding:?}: ALU rows");
            let hid = leaf.prove_epoch_commit(t, hp_prior(), ups.clone(), &o);
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
    /// batch salt. The explicit no-op path refuses a batch that moves the
    /// state. Controls: a zero INIT salt is leaf 1's honest opening (from the
    /// empty genesis state; a zero init on a real state is refused, test
    /// `hiding_leaf_refuses_zero_init_on_a_real_state`), and a Plain leaf
    /// still ignores its openings.
    #[test]
    fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
        let seed = SaltSeed::for_tests(81);
        let ups = hp_batches()[0].clone();
        let mut leaf = hiding_leaf(Binding::Semantic);
        let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, hp_prior(), ups.clone()).final_commit).unwrap_err();
        assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
        assert!(forge::catch(|| leaf.prove_epoch(hp_prior(), ups.clone()).final_commit).is_none());
        let honest = Openings::for_leaf(&seed, CM, 2);
        for (what, o) in [
            ("plain", Openings::plain()),
            ("public_zero", Openings::public_zero()),
            ("zero final", Openings { final_: SaltBb::ZERO, ..honest }),
            ("zero batch", Openings { batch: SaltBb::ZERO, ..honest }),
        ] {
            let msg = forge::catch_msg(|| leaf.prove_epoch_commit(2, hp_prior(), ups.clone(), &o).final_commit)
                .unwrap_err();
            assert!(msg.contains("public zero salt"), "{what}: {msg}");
        }
        let msg = forge::catch_msg(|| {
            prove_countmin_omc_interval_commit(HP, 2, hp_prior(), ups.clone(), CommitMode::Hiding, &Openings::plain())
                .final_commit
        })
        .unwrap_err();
        assert!(msg.contains("public zero salt"), "{msg}");
        let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, hp_prior(), ups.clone()).final_commit).unwrap_err();
        assert!(msg.contains("value 0"), "{msg}");

        let o1 = Openings::for_leaf(&seed, CM, 1);
        assert!(o1.init.is_zero());
        let r = leaf.prove_epoch_commit(1, empty(HP.d, HP.w), ups.clone(), &o1);
        assert_eq!(r.initial_commit, commit_countmin_with(&empty(HP.d, HP.w), CommitMode::Hiding, &SaltBb::ZERO));
        let mut plain = build_countmin_omc_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Plain);
        let p = plain.prove_epoch_commit(2, hp_prior(), ups, &Openings::plain());
        assert_eq!(p.initial_commit, commit_countmin(&hp_prior()));
        assert_eq!(p.final_commit, commit_countmin(&advanced(&hp_prior(), &hp_batches()[0], Binding::Semantic)));
    }

    /// (F1, init salt) Under `Hiding` a zero INIT salt opens only the public
    /// genesis `Com(S_0; 0)`: batch index 1 and the empty state. Refused,
    /// under both non-legacy bindings and Legacy: a forgotten init opening
    /// on a real prior (`t = 2`), a worker that numbers its leaves locally
    /// (`for_leaf(.., 1)` at global `t = 5` on a real state), leaf 1's
    /// openings on a real prior at `t = 1`, and a zero init at `t = 2` even
    /// on the empty state (its `Com(·; 0)` would reveal `S_1 = S_0`). Each
    /// would otherwise prove a leaf exposing the guess-checkable
    /// `Com(S; 0)` of a secret state (the review probe's cases (a), (b)).
    /// Controls: leaf 1 of the genesis history (empty state, zero init)
    /// proves and exposes `Com(S_0; 0)`, and a Plain leaf ignores its
    /// openings on the same inputs.
    #[test]
    fn hiding_leaf_refuses_zero_init_on_a_real_state() {
        let seed = SaltSeed::for_tests(83);
        let ups = hp_batches()[0].clone();
        let s0 = empty(HP.d, HP.w);
        assert_ne!(hp_prior(), s0, "precondition: a real (secret) prior");
        let forgot = Openings { init: SaltBb::ZERO, ..Openings::for_leaf(&seed, CM, 2) };
        let local = Openings::for_leaf(&seed, CM, 1);
        let cases = [
            ("forgotten init, real prior", 2u64, hp_prior(), forgot),
            ("local numbering at global t = 5", 5, hp_prior(), local),
            ("leaf-1 openings on a real prior", 1, hp_prior(), local),
            ("zero init at t = 2 on the empty state", 2, s0.clone(), forgot),
        ];
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut leaf = hiding_leaf(binding);
            for (what, t, prior, o) in &cases {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(*t, prior.clone(), ups.clone(), o).final_commit)
                    .unwrap_err();
                assert!(msg.contains("zero init salt"), "{binding:?}/{what}: {msg}");
            }
            let r = leaf.prove_epoch_commit(1, s0.clone(), ups.clone(), &local);
            assert_eq!(r.initial_commit, commit_countmin_with(&s0, CommitMode::Hiding, &SaltBb::ZERO), "{binding:?}");
        }
        let mut plain = build_countmin_omc_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Plain);
        for (what, t, prior, o) in &cases {
            let p = plain.prove_epoch_commit(*t, prior.clone(), ups.clone(), o);
            assert_eq!(p.initial_commit, commit_countmin(prior), "Plain/{what}");
        }
    }

    /// The zero-salt no-op path accepts only the public no-op input (batch
    /// index 1, the empty state, every update `{ key: 0, value: 0 }`), not
    /// merely "every value is 0": a value-0 batch leaves ANY state unchanged,
    /// so a real state would otherwise publish the deterministic,
    /// guess-checkable `Com(S_t; 0)` as both init and final. Rejected, under
    /// every binding and in either mode: a real state with the canonical
    /// no-op batch (an all-pad leaf of a live stream, whose state needs its
    /// `ρ_t`), the empty state with value-0 updates on real keys, and the
    /// canonical input at another batch index. Control: the canonical input
    /// proves and exposes `Com(S_0; 0)` as init and final and the zero-salt
    /// commitment of the public batch.
    #[test]
    fn noop_path_accepts_only_the_public_noop_input() {
        let noop = vec![CountMinUpdate { key: 0, value: 0 }; HP.batch];
        let real_keys: Vec<CountMinUpdate> =
            hp_batches()[0].iter().map(|u| CountMinUpdate { key: u.key, value: 0 }).collect();
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let cases = [
                ("real state, canonical no-op batch", 1u64, hp_prior(), noop.clone(), "empty genesis state"),
                ("empty state, value-0 real keys", 1, empty(HP.d, HP.w), real_keys.clone(), "public no-op"),
                ("canonical input at t = 2", 2, empty(HP.d, HP.w), noop.clone(), "batch index 1"),
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
            let mut leaf = hiding_leaf(binding);
            let r = leaf.prove_epoch_public_zero(1, empty(HP.d, HP.w), noop.clone());
            let anchor = commit_countmin_with(&empty(HP.d, HP.w), CommitMode::Hiding, &SaltBb::ZERO);
            assert_eq!(r.initial_commit, anchor, "{binding:?}");
            assert_eq!(r.final_commit, anchor, "{binding:?}");
            assert_eq!(
                r.batch_commit.0,
                countmin_omc_batch_commit_salted(&noop, binding, CommitMode::Hiding, &SaltBb::ZERO),
                "{binding:?}"
            );
        }
    }

    /// The harness's Count-Min VK-derivation input (`dist_compose`'s
    /// `noop_leaf_input` / `prove_noop_leaf`: the empty state
    /// `families::cm_empty` and a batch of `PAD_KEY` records mapped by
    /// `stream_compose::cm_updates_of`, proved at batch index 1) is exactly
    /// the canonical public no-op input, so it passes the tightened
    /// `prove_epoch_public_zero` in either mode and under every binding, and
    /// exposes `init == final`; the harness code itself is not changed here.
    #[test]
    fn harness_noop_input_is_the_public_noop_input() {
        use crate::experiments::families::cm_empty;
        use crate::experiments::stream_compose::{PAD_KEY, cm_updates_of};
        let batch = cm_updates_of(&vec![PAD_KEY; HP.batch]);
        assert!(batch.iter().all(|u| *u == CountMinUpdate { key: 0, value: 0 }));
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            for mode in [CommitMode::Hiding, CommitMode::Plain] {
                let mut leaf = build_countmin_omc_leaf_commit(HP, Expose::Interval, binding, mode);
                let r = leaf.prove_epoch_public_zero(1, cm_empty(HP.d, HP.w), batch.clone());
                assert_eq!(r.initial_commit, r.final_commit, "{binding:?}/{mode:?}");
                assert_eq!(
                    r.initial_commit,
                    commit_countmin_with(&empty(HP.d, HP.w), mode, &SaltBb::ZERO),
                    "{binding:?}/{mode:?}"
                );
            }
        }
    }

    /// (F2) A continued history (e.g. after a GK rotation) is anchored on the
    /// previous history's certified final commitment: history 0 ends at
    /// `Com(S_2; ρ_{0,2})`; history 1 restarts `t` at 1 from `S_2`, its leaf 1
    /// opens the init with that anchor salt ([`Openings::for_leaf_after`]) and
    /// exposes exactly the certified value, and both leaves pass the per-batch
    /// check against history 1's log, whose `Com(S_0)` is that anchor (taken
    /// from history 0, not recomputed). The same batch at the same `t` gets
    /// another commitment in each history. The pre-fix opening (init salt 0,
    /// what `for_leaf(.., 1)` gives) would expose the guess-checkable
    /// `Com(S_2; 0)`: the leaf refuses it. A nonzero WRONG anchor salt (not
    /// detectable by the leaf) exposes another commitment, and the log
    /// rejects it.
    #[test]
    fn continued_history_leaf_opens_the_previous_final_commitment() {
        use crate::commitment::hiding::{rho_batch_bb_in, rho_state_bb_in};
        let binding = Binding::Semantic;
        let seed = SaltSeed::for_tests(71);
        let bs = hp_batches();
        let s1 = advanced(&empty(HP.d, HP.w), &bs[0], binding);
        let s2 = advanced(&s1, &bs[1], binding);
        let mut leaf = hiding_leaf(binding);
        let h0_last = leaf.prove_epoch_commit(2, s1, bs[1].clone(), &Openings::for_leaf(&seed, CM, 2));
        let anchor_salt = rho_state_bb(&seed, CM, 2);
        let anchor = h0_last.final_commit;
        assert_eq!(anchor, commit_countmin_with(&s2, CommitMode::Hiding, &anchor_salt));

        let h = 1u64;
        let s3 = advanced(&s2, &bs[0], binding);
        let s4 = advanced(&s3, &bs[1], binding);
        let o1 = Openings::for_leaf_after(&anchor_salt, &seed, CM, h);
        let l1 = leaf.prove_epoch_commit(1, s2.clone(), bs[0].clone(), &o1).output;
        let l2 = leaf.prove_epoch_commit(2, s3, bs[1].clone(), &Openings::for_leaf_in(&seed, CM, h, 2)).output;
        assert_eq!(read_exposed_statement(&l1.0).init, anchor.0.to_vec(), "history 1 starts at history 0's final");
        assert_eq!(read_exposed_statement(&l2.0).init, read_exposed_statement(&l1.0).final_);
        let bc: Vec<[Val; 8]> = (0..2)
            .map(|k| {
                let salt = rho_batch_bb_in(&seed, CM, h, k as u64 + 1);
                countmin_omc_batch_commit_salted(&bs[k], binding, CommitMode::Hiding, &salt)
            })
            .collect();
        let fin = commit_countmin_with(&s4, CommitMode::Hiding, &rho_state_bb_in(&seed, CM, h, 2));
        let log1 = batch_log(&anchor.0, &fin.0, &bc);
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log1, Expose::Interval), Ok(()));
        let h0_bc1 = countmin_omc_batch_commit_salted(&bs[0], binding, CommitMode::Hiding, &rho_batch_bb(&seed, CM, 1));
        assert_ne!(bc[0], h0_bc1, "t restarted, the randomizer did not");

        let zero_init = Openings { init: SaltBb::ZERO, ..o1 };
        let msg = forge::catch_msg(|| leaf.prove_epoch_commit(1, s2.clone(), bs[0].clone(), &zero_init).final_commit)
            .unwrap_err();
        assert!(msg.contains("zero init salt"), "{msg}");
        let wrong_init = Openings { init: rho_state_bb(&seed, CM, 1), ..o1 };
        let l1w = leaf.prove_epoch_commit(1, s2, bs[0].clone(), &wrong_init).output;
        let e = check_leaves_against_log(&[&l1w.0, &l2.0], &log1, Expose::Interval);
        assert!(e.as_ref().is_err_and(|m| m.contains("Com(S_0)")), "{e:?}");
    }

    /// Measurement (explicit): legacy vs semantic vs bound at one shape.
    /// `CM_OMC_MEASURE=d,w,batch[;d,w,batch...] cargo test --release --lib
    /// countmin_omc::tests::omc_binding_measure -- --ignored --nocapture`
    /// (default `7,16384,4096`). `CM_OMC_MEASURE_BINDING=legacy|semantic|bound`
    /// measures one binding only (default: all three; `Semantic` vs `Legacy`
    /// is the cost of the circuit-semantic fixes alone, the replacement for
    /// the pre-merge `omc_hardening_cost`).
    #[test]
    #[ignore = "measurement: large circuits"]
    fn omc_binding_measure() {
        let spec = std::env::var("CM_OMC_MEASURE").unwrap_or_else(|_| "7,16384,4096".into());
        let bindings: Vec<Binding> = match std::env::var("CM_OMC_MEASURE_BINDING").as_deref() {
            Ok("legacy") => vec![Binding::Legacy],
            Ok("semantic") => vec![Binding::Semantic],
            Ok("bound") => vec![Binding::Bound],
            _ => vec![Binding::Legacy, Binding::Semantic, Binding::Bound],
        };
        for shape in spec.split(';') {
            let v: Vec<usize> = shape.split(',').map(|x| x.trim().parse().unwrap()).collect();
            let (d, w, batch) = (v[0], v[1], v[2]);
            let params = CmOmcParams { d, w, batch };
            let mut prior = empty(d, w);
            for k in 0..2000u64 {
                apply_update_prf(&mut prior, &CountMinUpdate { key: k.wrapping_mul(0x9E37_79B9_7F4A_7C15), value: 1 + (k % 3) as u32 });
            }
            let upd: Vec<CountMinUpdate> = (0..batch as u64)
                .map(|i| CountMinUpdate { key: i.wrapping_mul(0xD1B5_4A32_D192_ED03) ^ 0x5555, value: 1 + (i % 4) as u32 })
                .collect();
            for &binding in &bindings {
                let t_b = std::time::Instant::now();
                let mut leaf = build_countmin_omc_leaf_with(params, true, binding);
                let build = t_b.elapsed();
                let t = std::time::Instant::now();
                let proof = leaf.prove_epoch(prior.clone(), upd.clone());
                let total = t.elapsed();
                let tm = crate::recursion::recursive::timing::take();
                eprintln!(
                    "CM_OMC_MEASURE binding={:?} d={} w={} batch={} trace_rows={} tables={:?} build_ms={:.0} witness_ms={:.0} prove_ms={:.0} verify_ms={:.0} total_ms={:.0} proof_bytes={}",
                    binding, d, w, batch, leaf.trace_rows(), leaf.table_rows(),
                    build.as_secs_f64() * 1e3, tm.witness.as_secs_f64() * 1e3,
                    tm.prove.as_secs_f64() * 1e3, tm.verify.as_secs_f64() * 1e3,
                    total.as_secs_f64() * 1e3, proof.proof_size()
                );
            }
        }
    }
}
