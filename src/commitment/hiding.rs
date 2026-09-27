//! **Hiding state and batch commitments** (revision B2): every deployed
//! `Com(S_t)` / `Com(B_t)` absorbs a secret per-version randomizer `ρ`, so a
//! published commitment leaks nothing about a low-entropy state or batch (no
//! guess-and-check against the log), while [`CommitMode::Plain`] keeps
//! today's commitments and circuits byte for byte.
//!
//! ## The commitment
//!
//! ```text
//! Plain  : Com(x)     = MyHash(enc(x))                          (unchanged)
//! Hiding : Com(x; ρ)  = MyHash(prefix ‖ enc(x))
//!          prefix     = [kind, family, 0, 0, ρ_0 .. ρ_11]       (BabyBear, 16 values)
//!                     = [kind, family, ρ_0 .. ρ_5]              (Goldilocks, 8 values)
//! ```
//!
//! `enc(x)` is exactly the flat input the Plain commitment hashes today.
//! The prefix is two rate blocks of the native sponge (BabyBear rate 8,
//! Goldilocks rate 4), so `enc(x)` stays block-aligned and a hiding
//! commitment costs exactly two more Poseidon2 permutations, natively and
//! in-circuit (4 prefix Challenges, 2 per permutation), plus 3 ALU rows
//! for the salt's creators ([`SaltTargets`]): +6 Poseidon2 and +9 ALU rows
//! per update leaf (3 commitments), +2 and +3 per decoder (logical rows,
//! before padding; pinned by `tests::hiding_row_overhead_per_commitment`,
//! `countmin_omc::tests::hiding_leaf_row_overhead_and_no_salt_in_public_values`
//! and its decoder twin). `kind` is [`TAG_STATE`] or [`TAG_BATCH`] (a batch
//! commitment can never be passed off as a state commitment) and `family`
//! the [`CommitFamily`] id (an HLL register state no longer collides with a
//! `d = 1` Count-Min state). `ρ` is a [`SaltBb`] (12 BabyBear elements,
//! about 371 bits) or a [`SaltGl`] (6 Goldilocks elements, 384 bits).
//!
//! In-circuit, the prefix is four extension elements: the tag constant with
//! basis coefficients `(kind, family, 0, 0)` (Goldilocks `(kind, family)`)
//! and the three salt Challenges, whose basis coefficients are `ρ` in order.
//! A Challenge's basis coefficients are exactly the native base stream (the
//! `CELL_ALIGNMENT` convention of [`crate::commitment::countmin`]), so the
//! in-circuit sponge over `[tag, salt_0, salt_1, salt_2, inputs…]` equals
//! the native `MyHash(prefix ‖ enc(x))`. The sponge is [`bind::hash_slice`],
//! so `Binding::Bound` keeps its zero-IV, fully bound first row.
//!
//! ## Who holds what
//!
//! * **Seed.** A 256-bit [`SaltSeed`] held by the PROVER only, on all of its
//!   machines (the distributed prover's workers must derive the same `ρ_t`,
//!   because leaf `t` and leaf `t + 1` may run on different machines). It is
//!   read from `ZKSKETCH_SALT_SEED` or drawn from the OS RNG. It is never
//!   logged or printed (its `Debug` is redacted) and never reaches the
//!   verifier.
//! * **Randomizers.** `ρ^S_t = PRF(seed, STATE, family, h, t)` for the
//!   state after batch `t` and `ρ^B_t = PRF(seed, BATCH, family, h, t)` for
//!   batch `t`, where `h` is the public HISTORY id and `t` the 1-based batch
//!   index within history `h` (the index the leaf already uses);
//!   [`rho_state_bb_in`] / [`rho_batch_bb_in`] and the Goldilocks twins, with
//!   [`rho_state_bb`] / [`rho_batch_bb`] the genesis history
//!   [`GENESIS_HISTORY`]. The PRF is the field's native Poseidon2 sponge
//!   keyed by the seed (see [`rho_state_bb_in`]).
//! * **One `(seed, h)` per history.** `(h, t)` must never repeat under one
//!   seed: every history, stream or window that restarts `t` at 1 needs its
//!   own `h` (or its own seed). Two histories sharing a seed AND an id would
//!   reuse `ρ` at equal `t`, so equal states or batches there would get
//!   equal, linkable commitments. `ZKSKETCH_SALT_SEED` is reusable across
//!   runs for reproducibility only under distinct history ids.
//! * **Genesis `ρ_0` is public: zero.** In the genesis history `S_0` is the
//!   public empty sketch, so `ρ^S_0 = SaltBb::ZERO` and the verifier
//!   recomputes `Com(S_0; 0)` itself. Hiding it would buy nothing.
//! * **A continued history is anchored, not recomputed.** History `h ≥ 1`
//!   (e.g. a GK rotation after 2^24 records) starts from the previous
//!   history's final state `S_T`, which is SECRET. Its anchor is the previous
//!   history's certified `Com(S_T; ρ_T)`, which the verifier takes from that
//!   history's certified log (it cannot recompute it), and the prover opens
//!   leaf 1's init with that same `ρ_T`
//!   ([`Openings::for_leaf_after`]); a query at version 0 of history `h`
//!   uses `ρ_T` too. There is no PRF value for `(h ≥ 1, t = 0)`:
//!   [`rho_state_bb_in`] panics rather than silently break the link.
//! * **The circuit does not check the derivation.** Each salt is a free
//!   private witness. A prover that picks `ρ = 0` (or any other value) only
//!   gives up its own privacy; binding holds for every `ρ`. This is also what
//!   lets the no-op VK-derivation leaf use `ρ_in = ρ_out = 0` and expose
//!   `init == final` ([`Openings::public_zero`]). The LIBRARY does check the
//!   honest-prover side: a `Hiding` leaf refuses the public zero salt on its
//!   final or batch commitment except on the explicit no-op path (see
//!   `CmOmcLeafCircuit::prove_epoch_commit`), so a harness that forgets the
//!   openings fails loudly instead of publishing `Com(S_t; 0)`.
//!
//! ## Cross-leaf consistency (binding exactly as before)
//!
//! **Lemma.** Let the honest prover open leaf `t` with
//! `(init, final, batch) = (ρ^S_{t-1}, ρ^S_t, ρ^B_t)` ([`Openings::for_leaf`],
//! [`Openings::for_leaf_in`]; [`Openings::for_leaf_after`] for leaf 1 of a
//! continued history) and every query at version `t` with `ρ^S_t`. Then
//! leaf `t`'s final, leaf `t + 1`'s init and every query at version `t`
//! expose the same value `Com(S_t; ρ^S_t)`. Conversely, whenever a merge accepts two adjacent
//! children, its in-circuit check `left.final == right.init` plus collision
//! resistance of the sponge over the fixed-length input `prefix ‖ enc(x)`
//! gives `(ρ_left, S_left) = (ρ_right, S_right)`: the right child starts from
//! exactly the state the left child ended in. For a fixed family and shape
//! the input length is fixed and `(kind, family, ρ, x) ↦ prefix ‖ enc(x)` is
//! injective, so this is the same argument as for the Plain commitments with
//! `x` replaced by `(ρ, x)`; the merge circuits, the interval digest and the
//! auditor are unchanged (they compare and absorb commitment VALUES). The
//! log's `Com(B_t)` binds the batch the same way, and the auditor never
//! opens a commitment. Only the prover (and harness code that recomputes a
//! commitment from plaintext) needs `ρ`.
//!
//! ## What is hidden (and what is not)
//!
//! Hidden, in the random-oracle model and given `ρ` unknown to the verifier:
//! every `Com(S_t)` for `t ≥ 1` and every `Com(B_t)`, provided `(seed, h,
//! t)` never repeats (above). Equal states at two versions get unrelated
//! commitments (Plain would repeat the value).
//! NOT hidden: the genesis `Com(S_0)` (public by design), the public
//! parameters and shapes (`d, w, m`, `T`, capacities), the history id `h`
//! and batch index `t`, a query's key and answer (the query statement
//! exposes them), and anything the PROOF reveals. No salt value is a public
//! or exposed value of a leaf or decoder proof (tested). This module hides
//! only the published commitment values: with the current non-ZK FRI
//! configuration a proof's openings reveal trace evaluations, including `ρ`
//! and the state columns, so the end-to-end property also needs a
//! zero-knowledge PCS (revision B1).
//!
//! The tag and the basis constants are circuit constants, and at the pinned
//! fork (fbcc78f) constant VALUES are bound by the VK: ConstAir keeps each
//! constant's value in its preprocessed (committed) columns and constrains
//! the main-trace value to it (`circuit-prover/src/air/const_air.rs`: module
//! doc, `ConstAir` doc, and `builder.assert_eq(main_val, prep_val)` in
//! `eval`), so a prover cannot swap the tag
//! (`tests::tag_constant_is_bound_by_the_vk`). The older "constants are not
//! bound" caveat in [`crate::sketch::bind`] predates that fork revision.
//!
//! ## Modes
//!
//! [`CommitMode::Plain`] allocates nothing new: the circuits, VKs and
//! commitments are byte-identical to the pre-B2 ones, and every library API
//! that existed before B2 stays Plain. [`commit_mode_from_env`] is what the
//! harnesses read: `ZKSKETCH_COMMIT=plain|hiding`, unset = `Hiding` except
//! under `ZKSKETCH_BINDING=legacy` (then `Plain`, so a Legacy side-by-side
//! run stays byte-for-byte legacy, like
//! [`crate::recursion::recursive::statement::composition_expose`]).
//!
//! ## Pattern guide (HLL, SpaceSaving, GK and the Goldilocks twins)
//!
//! The reference wiring is the Count-Min `omc` leaf
//! ([`crate::sketch::countmin_omc`]) and its decoder
//! ([`crate::decode::countmin`]). Per family:
//!
//! 1. **Native commitments.** Keep every old `commit_*`; add a mode-aware
//!    twin whose `Plain` arm calls the old function verbatim and whose
//!    `Hiding` arm is `commit_flat_bb(Hiding, kind, family, salt, &flat)`
//!    over EXACTLY the flat the old function hashes (Goldilocks:
//!    [`commit_flat_gl`]). Name it `<old>_with(.., mode, &salt)` when that
//!    name is free, `<old>_salted(.., binding, mode, &salt)` when
//!    `<old>_with` already takes a `Binding`. Count-Min:
//!    `commit_countmin_with(state, mode, &SaltBb) -> CountMinCommit`,
//!    `commit_batch_with` / `commit_batch_limbs_with(records, mode, &SaltBb)`,
//!    `countmin_omc_batch_commit_salted(batch, binding, mode, &SaltBb) -> [Val; 8]`.
//! 2. **Builder.** `build_<leaf>_commit(params, expose, binding, mode)`; the
//!    old `build_<leaf>_expose(params, expose, binding)` becomes
//!    `build_<leaf>_commit(.., CommitMode::Plain)`. Inside it:
//!    * `let salts = hiding::alloc_leaf_salts(&mut b, mode);` immediately
//!      BEFORE the leaf's first private-input allocation, so the 9 salt
//!      inputs (init, final, batch; 3 Challenges each) are the first private
//!      inputs. `Plain` returns `None` and allocates nothing.
//!    * replace each of the three commitment sponges by
//!      `hiding::commit_hash::<Val, Challenge>(&mut b, &cfg, CommitKind::State
//!      | CommitKind::Batch, CommitFamily::X, salts.as_ref().map(|s| &s.init
//!      | &s.final_ | &s.batch), inputs, zero, binding)`. With `None` it is
//!      exactly `bind::hash_slice(inputs)`; a leaf that calls raw
//!      `b.add_hash_slice(cfg, inputs, true)` (SS, GK) passes
//!      `Binding::Semantic`, which is that same call.
//!    * keep `mode` in the leaf struct (`commit_mode()` accessor).
//! 3. **Prover.** `prove_epoch_commit(t, state, batch, &Openings)`. On a
//!    `Hiding` leaf it asserts that `openings.final_` and `openings.batch`
//!    are not [`SaltBb::ZERO`] (an honest `ρ` is zero with probability
//!    about 2^-371); the old `prove_epoch_at(t, ..)` asserts the leaf is
//!    `Plain` and then runs the same epoch with [`Openings::plain`]. So a
//!    call site left on the old API, or handed zero openings, panics instead
//!    of silently publishing deterministic `Com(S_t; 0)` values.
//!    The epoch computes the three public commitments with the step-1 natives
//!    and `openings.init / final_ / batch`, and, when `mode.is_hiding()`,
//!    pushes `openings.private_inputs()` BEFORE every other private input.
//!    Convenience: `prove_countmin_omc_interval_commit(params, t, state,
//!    batch, mode, &openings)`.
//! 4. **No-op leaf.** `cm_omc_noop_leaf_commit(params, expose, binding, mode)`
//!    in [`crate::recursion::recursive::noop_leaf`] proves through the one
//!    explicit zero-salt path, `prove_epoch_public_zero` (all three salts
//!    [`Openings::public_zero`], so `ρ_in = ρ_out` and `init == final`; the
//!    batch must change nothing, which it asserts).
//! 5. **Decoder.** `prove_<dec>_commit(params, state, query.., binding, mode,
//!    &SaltBb)`; the old entry point passes `(Plain, &SaltBb::ZERO)`. Call
//!    [`alloc_salt_targets`] immediately before the first private input, hash
//!    the state with `commit_hash(.., CommitKind::State, .., salt.as_ref(),
//!    cells, ..)`, and put `salt.packed()` first in the private inputs. The
//!    honest salt of a query at version `t` of history `h` is
//!    `rho_state_bb_in(seed, family, h, t)` (the history's anchor salt at
//!    `t = 0` of a continued history).
//! 6. **Goldilocks.** Same shape with [`SaltGl`], [`OpeningsGl`],
//!    [`commit_flat_gl`] and `rho_*_gl`. [`alloc_salt_targets`],
//!    [`alloc_leaf_salts`], [`salted_hash_inputs`] and [`commit_hash`] are
//!    field-generic (`commit_hash::<GlVal, GlChallenge>`: tag `(kind,
//!    family)`, 2 salt values per Challenge); so far tested at runner level
//!    only (`tests::in_circuit_salted_commit_matches_native_gl`).
//! 7. **Harness (later stage).** `commit_mode_from_env()`; the seed
//!    `SaltSeed::from_env().unwrap_or_else(SaltSeed::os_random)`; a public
//!    history id per history/stream (unique under the seed); leaf `t` opens
//!    with `Openings::for_leaf_in(&seed, family, h, t)` (genesis:
//!    `Openings::for_leaf(&seed, family, t)`); in the genesis history the log
//!    anchor is `Com(S_0; SaltBb::ZERO)`, in a continued history it is the
//!    previous history's certified `Com(S_T; ρ_T)` and leaf 1 opens with
//!    `Openings::for_leaf_after(&ρ_T, &seed, family, h)`; `Com(B_t)` uses
//!    `rho_batch_bb_in(seed, family, h, t)` and the posted final
//!    `rho_state_bb_in(seed, family, h, T)`. Every leaf goes through
//!    `prove_epoch_commit`, never `prove_epoch_at`. Wired (genesis history
//!    per stream) in [`crate::experiments::prover_commit`] (the prover's
//!    context: mode + seed, shipped to the distributed workers as
//!    [`SaltSeedWire`]), `experiments::dist_compose` / `stream_compose` (the
//!    prover-side log), and [`crate::experiments::audit`] (the auditor: the
//!    published log, the proofs and public parameters only).
//! 8. **Tests to replicate** (in `countmin_omc::tests` /
//!    `decode::countmin::tests`): `hiding_leaf_exposes_native_hiding_commitments`,
//!    `hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged` (record the
//!    Plain VKs on main BEFORE editing and pin them as literals),
//!    `equal_states_get_unlinkable_hiding_commitments`,
//!    `wrong_rho_rejected_by_log_and_inconsistent_rho_breaks_merge`,
//!    `hiding_noop_leaf_has_init_eq_final`, `hiding_decode_exposes_hiding_commit`,
//!    `hiding_leaf_row_overhead_and_no_salt_in_public_values` (and its
//!    decoder twin), `hiding_leaf_rejects_zero_openings_outside_the_noop_path`,
//!    `continued_history_leaf_opens_the_previous_final_commitment`, and
//!    `hiding_leaf_tiny_debug` (run once without `--release`, where the fork
//!    debug-asserts the salts' ALU creators).

use p3_circuit::ops::Poseidon2Config;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::CryptographicHasher;

use crate::config::{Challenge, MyHash, Val, make_perm};
use crate::config_gl::{
    Challenge as GlChallenge, MyHash as GlHash, Val as GlVal, make_perm as make_perm_gl,
};
use crate::sketch::bind::{self, Binding};

// ─── Mode ────────────────────────────────────────────────────────────────────

/// Whether state and batch commitments absorb a randomizer.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CommitMode {
    /// `MyHash(enc(x))`: the pre-B2 commitments, circuits and VKs, byte for
    /// byte. Deterministic, so NOT hiding for low-entropy states/batches.
    Plain,
    /// `MyHash(prefix ‖ enc(x))` with a per-version secret `ρ` (module doc).
    Hiding,
}

impl CommitMode {
    pub const fn is_hiding(self) -> bool {
        matches!(self, CommitMode::Hiding)
    }
}

/// The commitment mode the harnesses use: `ZKSKETCH_COMMIT` (`plain` /
/// `hiding`, any case). Unset or empty gives `Hiding`, except under
/// `ZKSKETCH_BINDING=legacy`, which gives `Plain`. Any other value, including
/// one that is not valid UTF-8, panics ([`parse_commit_env`]).
pub fn commit_mode_from_env() -> CommitMode {
    parse_commit_env(std::env::var("ZKSKETCH_COMMIT"), bind::default_binding())
}

/// Parse a `ZKSKETCH_COMMIT` lookup (`std::env::var` result) given the
/// process binding. An explicit value wins; unset or empty falls back to
/// `Plain` under [`Binding::Legacy`] and `Hiding` otherwise.
pub fn parse_commit_env(var: Result<String, std::env::VarError>, binding: Binding) -> CommitMode {
    let fallback = if binding == Binding::Legacy { CommitMode::Plain } else { CommitMode::Hiding };
    match var {
        Ok(v) if v.eq_ignore_ascii_case("plain") => CommitMode::Plain,
        Ok(v) if v.eq_ignore_ascii_case("hiding") => CommitMode::Hiding,
        Ok(v) if v.is_empty() => fallback,
        Ok(v) => panic!("ZKSKETCH_COMMIT={v:?}: expected plain or hiding"),
        Err(std::env::VarError::NotPresent) => fallback,
        Err(std::env::VarError::NotUnicode(v)) => {
            panic!("ZKSKETCH_COMMIT={v:?}: not valid UTF-8; expected plain or hiding")
        }
    }
}

// ─── Domain tags ─────────────────────────────────────────────────────────────

/// Kind tag of a state commitment (`"STAT"` in ASCII, < BabyBear p).
pub const TAG_STATE: u64 = 0x5354_4154;
/// Kind tag of a batch commitment (`"BATC"` in ASCII, < BabyBear p).
pub const TAG_BATCH: u64 = 0x4241_5443;
/// Domain tag of the randomizer PRF (`"RHO_"` in ASCII, < BabyBear p).
pub const DS_RHO: u64 = 0x5248_4F5F;

/// What a commitment commits to.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CommitKind {
    State,
    Batch,
}

impl CommitKind {
    pub const fn tag(self) -> u64 {
        match self {
            CommitKind::State => TAG_STATE,
            CommitKind::Batch => TAG_BATCH,
        }
    }
}

/// Sketch family of a commitment (its id is absorbed with the kind tag).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CommitFamily {
    CountMin = 1,
    HyperLogLog = 2,
    SpaceSaving = 3,
    GreenwaldKhanna = 4,
    Bloom = 5,
}

impl CommitFamily {
    pub const fn id(self) -> u64 {
        self as u64
    }
}

// ─── Salts ───────────────────────────────────────────────────────────────────

/// Salt Challenges per commitment (both fields).
pub const SALT_CHALLENGES: usize = 3;
/// BabyBear salt length in base elements (3 D=4 Challenges, about 371 bits).
pub const SALT_BB_LEN: usize = 12;
/// Goldilocks salt length in base elements (3 D=2 Challenges, 384 bits).
pub const SALT_GL_LEN: usize = 6;
/// Native prefix length, BabyBear: `[kind, family, 0, 0, ρ_0..ρ_11]`.
pub const PREFIX_BB_LEN: usize = 16;
/// Native prefix length, Goldilocks: `[kind, family, ρ_0..ρ_5]`.
pub const PREFIX_GL_LEN: usize = 8;

const BB_D: usize = 4;
const GL_D: usize = 2;

/// BabyBear randomizer `ρ` of one commitment. `Debug` is redacted.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SaltBb(pub [Val; SALT_BB_LEN]);

/// Goldilocks randomizer `ρ` of one commitment. `Debug` is redacted.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SaltGl(pub [GlVal; SALT_GL_LEN]);

impl SaltBb {
    /// The public randomizer of `S_0` and of the no-op leaf.
    pub const ZERO: Self = SaltBb([Val::ZERO; SALT_BB_LEN]);

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// The three salt Challenges (4 basis coefficients each, in order): the
    /// private-input values of a [`SaltTargets`].
    pub fn packed(&self) -> [Challenge; SALT_CHALLENGES] {
        std::array::from_fn(|i| {
            Challenge::from_basis_coefficients_slice(&self.0[BB_D * i..BB_D * (i + 1)])
                .expect("4 base coeffs")
        })
    }
}

impl SaltGl {
    /// The public randomizer of `S_0` and of the no-op leaf.
    pub const ZERO: Self = SaltGl([GlVal::ZERO; SALT_GL_LEN]);

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// The three salt Challenges (2 basis coefficients each, in order).
    pub fn packed(&self) -> [GlChallenge; SALT_CHALLENGES] {
        std::array::from_fn(|i| {
            GlChallenge::from_basis_coefficients_slice(&self.0[GL_D * i..GL_D * (i + 1)])
                .expect("2 base coeffs")
        })
    }
}

impl std::fmt::Debug for SaltBb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.is_zero() { "SaltBb(zero)" } else { "SaltBb(<secret>)" })
    }
}

impl std::fmt::Debug for SaltGl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.is_zero() { "SaltGl(zero)" } else { "SaltGl(<secret>)" })
    }
}

// ─── Native commitments ──────────────────────────────────────────────────────

/// `[kind, family, 0, 0, ρ_0..ρ_11]`: two BabyBear rate blocks.
pub fn hiding_prefix_bb(kind: CommitKind, family: CommitFamily, salt: &SaltBb) -> [Val; PREFIX_BB_LEN] {
    let mut p = [Val::ZERO; PREFIX_BB_LEN];
    p[0] = Val::from_u64(kind.tag());
    p[1] = Val::from_u64(family.id());
    p[BB_D..].copy_from_slice(&salt.0);
    p
}

/// `[kind, family, ρ_0..ρ_5]`: two Goldilocks rate blocks.
pub fn hiding_prefix_gl(kind: CommitKind, family: CommitFamily, salt: &SaltGl) -> [GlVal; PREFIX_GL_LEN] {
    let mut p = [GlVal::ZERO; PREFIX_GL_LEN];
    p[0] = GlVal::from_u64(kind.tag());
    p[1] = GlVal::from_u64(family.id());
    p[GL_D..].copy_from_slice(&salt.0);
    p
}

/// BabyBear commitment of the flat encoding `flat`: `MyHash(flat)` under
/// `Plain` (the salt is ignored), `MyHash(prefix ‖ flat)` under `Hiding`.
/// In `Hiding` mode `flat.len()` must be a multiple of 4, or the native
/// digest would diverge from the in-circuit one.
pub fn commit_flat_bb(
    mode: CommitMode,
    kind: CommitKind,
    family: CommitFamily,
    salt: &SaltBb,
    flat: &[Val],
) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    match mode {
        CommitMode::Plain => hasher.hash_iter(flat.iter().copied()),
        CommitMode::Hiding => {
            assert!(
                flat.len() % BB_D == 0,
                "hiding commitment: {} base values, not a multiple of {BB_D}",
                flat.len()
            );
            let prefix = hiding_prefix_bb(kind, family, salt);
            hasher.hash_iter(prefix.into_iter().chain(flat.iter().copied()))
        }
    }
}

/// Goldilocks twin of [`commit_flat_bb`] (`flat.len()` even under `Hiding`).
pub fn commit_flat_gl(
    mode: CommitMode,
    kind: CommitKind,
    family: CommitFamily,
    salt: &SaltGl,
    flat: &[GlVal],
) -> [GlVal; 4] {
    let hasher = GlHash::new(make_perm_gl());
    match mode {
        CommitMode::Plain => hasher.hash_iter(flat.iter().copied()),
        CommitMode::Hiding => {
            assert!(
                flat.len() % GL_D == 0,
                "hiding commitment: {} base values, not a multiple of {GL_D}",
                flat.len()
            );
            let prefix = hiding_prefix_gl(kind, family, salt);
            hasher.hash_iter(prefix.into_iter().chain(flat.iter().copied()))
        }
    }
}

// ─── Seed and randomizer PRF (prover side only) ──────────────────────────────

/// The prover's 256-bit salt seed. Never logged: `Debug` is redacted and no
/// accessor returns the bytes.
#[derive(Clone)]
pub struct SaltSeed([u8; 32]);

impl std::fmt::Debug for SaltSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaltSeed(<redacted>)")
    }
}

impl SaltSeed {
    /// `ZKSKETCH_SALT_SEED` (64 hex characters), `None` when unset or empty.
    /// A malformed value panics without echoing it ([`Self::parse_env`]).
    pub fn from_env() -> Option<Self> {
        Self::parse_env(std::env::var("ZKSKETCH_SALT_SEED"))
    }

    /// Parse a `ZKSKETCH_SALT_SEED` lookup. The panic messages never contain
    /// the value.
    pub fn parse_env(var: Result<String, std::env::VarError>) -> Option<Self> {
        let v = match var {
            Err(std::env::VarError::NotPresent) => return None,
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("ZKSKETCH_SALT_SEED is not valid UTF-8; expected 64 hex characters")
            }
            Ok(v) => v,
        };
        let v = v.trim();
        if v.is_empty() {
            return None;
        }
        assert!(
            v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit()),
            "ZKSKETCH_SALT_SEED must be exactly 64 hex characters (got {} characters)",
            v.len()
        );
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&v[2 * i..2 * i + 2], 16).expect("hex digit pair");
        }
        Some(SaltSeed(bytes))
    }

    /// A fresh seed from the operating system's RNG.
    pub fn os_random() -> Self {
        use rand::TryRng;
        let mut bytes = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .expect("OS RNG failed to produce a salt seed");
        SaltSeed(bytes)
    }

    /// A deterministic, PUBLIC seed for tests and reproducible runs (not
    /// secret, so it hides nothing).
    pub fn for_tests(n: u64) -> Self {
        let mut bytes = [0xA5u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        SaltSeed(bytes)
    }

    /// The seed as 11 limbs of 24 bits, little-endian (10 full limbs and one
    /// of 16 bits): an injective encoding, every limb `< 2^24 < p`.
    fn limbs24(&self) -> [u64; SEED_LIMBS] {
        std::array::from_fn(|i| {
            (0..3).fold(0u64, |acc, j| {
                let byte = self.0.get(3 * i + j).copied().unwrap_or(0) as u64;
                acc | (byte << (8 * j))
            })
        })
    }
}

/// The wire form of a [`SaltSeed`], for the distributed PROVER's own machines
/// only: the harness coordinator ships it to the worker processes it spawns
/// (`experiments::dist_compose`), each of which derives its slice's openings
/// from `(seed, family, t)`. It is never part of a published artifact, never
/// logged (`Debug` is redacted) and crate-private, so no public API returns
/// the seed bytes.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SaltSeedWire([u8; 32]);

impl std::fmt::Debug for SaltSeedWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaltSeedWire(<redacted>)")
    }
}

impl SaltSeed {
    /// See [`SaltSeedWire`] (prover-internal transport only).
    pub(crate) fn to_prover_wire(&self) -> SaltSeedWire {
        SaltSeedWire(self.0)
    }
}

impl SaltSeedWire {
    /// The seed a worker received from its coordinator.
    pub(crate) fn into_seed(self) -> SaltSeed {
        SaltSeed(self.0)
    }
}

const SEED_LIMBS: usize = 11;
const INDEX_LIMBS: usize = 3;
/// `[DS_RHO, kind, family, h (3 limbs), t (3 limbs), seed (11 limbs), counter]`.
const PRF_INPUT_LEN: usize = 3 + 2 * INDEX_LIMBS + SEED_LIMBS + 1;

/// The genesis history: its `S_0` is the public empty sketch, so its
/// `ρ^S_0` is [`SaltBb::ZERO`]. Every randomizer API without an explicit
/// history id ([`rho_state_bb`], [`Openings::for_leaf`], …) uses it.
pub const GENESIS_HISTORY: u64 = 0;

/// A `u64` (a history id or a batch index) as three 24-bit limbs,
/// little-endian (the last one 16 bits).
fn index_limbs24(t: u64) -> [u64; INDEX_LIMBS] {
    const M: u64 = (1 << 24) - 1;
    [t & M, (t >> 24) & M, t >> 48]
}

/// The fixed-length PRF input `[DS_RHO, kind, family, h_0..h_2, t_0..t_2,
/// seed_0..seed_10, counter]`. Every entry is `< 2^32` and below both
/// primes, and the length is fixed, so the encoding is injective in `(kind,
/// family, history, t, seed, counter)`.
fn prf_input<BF: PrimeField64>(
    seed: &SaltSeed,
    kind: CommitKind,
    family: CommitFamily,
    history: u64,
    t: u64,
    counter: u64,
) -> Vec<BF> {
    let mut v = Vec::with_capacity(PRF_INPUT_LEN);
    v.push(BF::from_u64(DS_RHO));
    v.push(BF::from_u64(kind.tag()));
    v.push(BF::from_u64(family.id()));
    v.extend(index_limbs24(history).map(BF::from_u64));
    v.extend(index_limbs24(t).map(BF::from_u64));
    v.extend(seed.limbs24().map(BF::from_u64));
    v.push(BF::from_u64(counter));
    debug_assert_eq!(v.len(), PRF_INPUT_LEN);
    v
}

fn rho_bb(seed: &SaltSeed, kind: CommitKind, family: CommitFamily, history: u64, t: u64) -> SaltBb {
    let h = MyHash::new(make_perm());
    let a: [Val; 8] = h.hash_iter(prf_input::<Val>(seed, kind, family, history, t, 0));
    let b: [Val; 8] = h.hash_iter(prf_input::<Val>(seed, kind, family, history, t, 1));
    SaltBb(std::array::from_fn(|i| if i < 8 { a[i] } else { b[i - 8] }))
}

fn rho_gl(seed: &SaltSeed, kind: CommitKind, family: CommitFamily, history: u64, t: u64) -> SaltGl {
    let h = GlHash::new(make_perm_gl());
    let a: [GlVal; 4] = h.hash_iter(prf_input::<GlVal>(seed, kind, family, history, t, 0));
    let b: [GlVal; 4] = h.hash_iter(prf_input::<GlVal>(seed, kind, family, history, t, 1));
    SaltGl(std::array::from_fn(|i| if i < 4 { a[i] } else { b[i - 4] }))
}

/// `ρ^S_0` of a history: the public zero in the genesis history; a
/// continued history has no PRF value there (its init is opened with the
/// previous history's final randomizer, [`Openings::for_leaf_after`]).
fn assert_state_index(history: u64, t: u64) {
    assert!(
        t >= 1 || history == GENESIS_HISTORY,
        "history {history}: ρ^S_0 of a continued history is the previous history's final \
         randomizer (open leaf 1 with Openings::for_leaf_after), not a PRF value"
    );
}

/// `ρ^S_t` of history `history` (BabyBear), the randomizer of `Com(S_t)`.
/// Genesis `t = 0` gives the public [`SaltBb::ZERO`]; a continued history's
/// `t = 0` panics (module doc: it is anchored, not derived). For `t ≥ 1` it
/// is a keyed-sponge PRF: the native Poseidon2 sponge (`MyHash`) over the
/// fixed-length input `[DS_RHO, TAG_STATE, family, history (three 24-bit
/// limbs), t (three 24-bit limbs), seed (eleven 24-bit limbs), counter]`,
/// squeezed once per counter (counter 0 gives `ρ_0..ρ_7`, counter 1 gives
/// `ρ_8..ρ_11`).
pub fn rho_state_bb_in(seed: &SaltSeed, family: CommitFamily, history: u64, t: u64) -> SaltBb {
    assert_state_index(history, t);
    if t == 0 { SaltBb::ZERO } else { rho_bb(seed, CommitKind::State, family, history, t) }
}

/// `ρ^B_t` of history `history` (BabyBear), the randomizer of `Com(B_t)`:
/// the [`rho_state_bb_in`] PRF under `TAG_BATCH`. Batch indices are 1-based
/// (`t = 0` panics).
pub fn rho_batch_bb_in(seed: &SaltSeed, family: CommitFamily, history: u64, t: u64) -> SaltBb {
    assert!(t >= 1, "batch indices are 1-based (got t = 0)");
    rho_bb(seed, CommitKind::Batch, family, history, t)
}

/// [`rho_state_bb_in`] in the [`GENESIS_HISTORY`] (`t = 0` gives the public
/// [`SaltBb::ZERO`]).
pub fn rho_state_bb(seed: &SaltSeed, family: CommitFamily, t: u64) -> SaltBb {
    rho_state_bb_in(seed, family, GENESIS_HISTORY, t)
}

/// [`rho_batch_bb_in`] in the [`GENESIS_HISTORY`].
pub fn rho_batch_bb(seed: &SaltSeed, family: CommitFamily, t: u64) -> SaltBb {
    rho_batch_bb_in(seed, family, GENESIS_HISTORY, t)
}

/// Goldilocks twin of [`rho_state_bb_in`] (the Goldilocks `MyHash`, rate 4:
/// counter 0 gives `ρ_0..ρ_3`, counter 1 gives `ρ_4, ρ_5`).
pub fn rho_state_gl_in(seed: &SaltSeed, family: CommitFamily, history: u64, t: u64) -> SaltGl {
    assert_state_index(history, t);
    if t == 0 { SaltGl::ZERO } else { rho_gl(seed, CommitKind::State, family, history, t) }
}

/// Goldilocks twin of [`rho_batch_bb_in`].
pub fn rho_batch_gl_in(seed: &SaltSeed, family: CommitFamily, history: u64, t: u64) -> SaltGl {
    assert!(t >= 1, "batch indices are 1-based (got t = 0)");
    rho_gl(seed, CommitKind::Batch, family, history, t)
}

/// Goldilocks twin of [`rho_state_bb`].
pub fn rho_state_gl(seed: &SaltSeed, family: CommitFamily, t: u64) -> SaltGl {
    rho_state_gl_in(seed, family, GENESIS_HISTORY, t)
}

/// Goldilocks twin of [`rho_batch_bb`].
pub fn rho_batch_gl(seed: &SaltSeed, family: CommitFamily, t: u64) -> SaltGl {
    rho_batch_gl_in(seed, family, GENESIS_HISTORY, t)
}

// ─── Openings of one leaf ────────────────────────────────────────────────────

/// The three randomizers a BabyBear update leaf opens its commitments with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Openings {
    /// `ρ` of `Com(S_{t-1})`.
    pub init: SaltBb,
    /// `ρ` of `Com(S_t)`.
    pub final_: SaltBb,
    /// `ρ` of `Com(B_t)`.
    pub batch: SaltBb,
}

impl Openings {
    /// All-zero randomizers, the (ignored) openings of a `Plain` leaf. A
    /// `Hiding` leaf refuses them on its final and batch commitments; the
    /// no-op leaf's all-zero opening is [`Self::public_zero`].
    pub const fn plain() -> Self {
        Openings { init: SaltBb::ZERO, final_: SaltBb::ZERO, batch: SaltBb::ZERO }
    }

    /// The public opening of the no-op VK-derivation leaf: all three salts
    /// zero (`ρ_in = ρ_out`, so it exposes `init == final`). It hides
    /// nothing; only the explicit no-op path proves with it
    /// (`CmOmcLeafCircuit::prove_epoch_public_zero`).
    pub const fn public_zero() -> Self {
        Self::plain()
    }

    /// The honest openings of leaf `t` (1-based) of the genesis history:
    /// `(ρ^S_{t-1}, ρ^S_t, ρ^B_t)`, with `ρ^S_0 = 0` at `t = 1`.
    pub fn for_leaf(seed: &SaltSeed, family: CommitFamily, t: u64) -> Self {
        Self::for_leaf_in(seed, family, GENESIS_HISTORY, t)
    }

    /// The honest openings of leaf `t` (1-based) of history `history`:
    /// `(ρ^S_{t-1}, ρ^S_t, ρ^B_t)`. Leaf 1 of a continued history
    /// (`history ≠ GENESIS_HISTORY`) has no derived init and panics: use
    /// [`Self::for_leaf_after`].
    pub fn for_leaf_in(seed: &SaltSeed, family: CommitFamily, history: u64, t: u64) -> Self {
        assert!(t >= 1, "batch indices are 1-based (got t = 0)");
        Openings {
            init: rho_state_bb_in(seed, family, history, t - 1),
            final_: rho_state_bb_in(seed, family, history, t),
            batch: rho_batch_bb_in(seed, family, history, t),
        }
    }

    /// The honest openings of leaf 1 of a CONTINUED history `history`, whose
    /// `S_0` is the previous history's final state: the init opens the
    /// previous history's certified `Com(S_T; ρ_T)` with `anchor = ρ_T`,
    /// so leaf 1 exposes exactly that commitment as its init; final and
    /// batch are history `history`'s `(ρ^S_1, ρ^B_1)`. Leaf `t ≥ 2` is
    /// [`Self::for_leaf_in`]. The genesis history's anchor is the public
    /// zero ([`Self::for_leaf`]), so `history = GENESIS_HISTORY` panics.
    pub fn for_leaf_after(anchor: &SaltBb, seed: &SaltSeed, family: CommitFamily, history: u64) -> Self {
        assert!(
            history != GENESIS_HISTORY,
            "the genesis history starts from the public S_0 (ρ^S_0 = 0): use Openings::for_leaf"
        );
        Openings {
            init: *anchor,
            final_: rho_state_bb_in(seed, family, history, 1),
            batch: rho_batch_bb_in(seed, family, history, 1),
        }
    }

    /// The 9 salt private inputs of a hiding leaf, in allocation order
    /// (init, final, batch; 3 Challenges each).
    pub fn private_inputs(&self) -> Vec<Challenge> {
        [self.init, self.final_, self.batch].iter().flat_map(|s| s.packed()).collect()
    }
}

/// Goldilocks twin of [`Openings`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OpeningsGl {
    pub init: SaltGl,
    pub final_: SaltGl,
    pub batch: SaltGl,
}

impl OpeningsGl {
    /// See [`Openings::plain`].
    pub const fn plain() -> Self {
        OpeningsGl { init: SaltGl::ZERO, final_: SaltGl::ZERO, batch: SaltGl::ZERO }
    }

    /// See [`Openings::public_zero`].
    pub const fn public_zero() -> Self {
        Self::plain()
    }

    /// See [`Openings::for_leaf`].
    pub fn for_leaf(seed: &SaltSeed, family: CommitFamily, t: u64) -> Self {
        Self::for_leaf_in(seed, family, GENESIS_HISTORY, t)
    }

    /// See [`Openings::for_leaf_in`].
    pub fn for_leaf_in(seed: &SaltSeed, family: CommitFamily, history: u64, t: u64) -> Self {
        assert!(t >= 1, "batch indices are 1-based (got t = 0)");
        OpeningsGl {
            init: rho_state_gl_in(seed, family, history, t - 1),
            final_: rho_state_gl_in(seed, family, history, t),
            batch: rho_batch_gl_in(seed, family, history, t),
        }
    }

    /// See [`Openings::for_leaf_after`].
    pub fn for_leaf_after(anchor: &SaltGl, seed: &SaltSeed, family: CommitFamily, history: u64) -> Self {
        assert!(
            history != GENESIS_HISTORY,
            "the genesis history starts from the public S_0 (ρ^S_0 = 0): use OpeningsGl::for_leaf"
        );
        OpeningsGl {
            init: *anchor,
            final_: rho_state_gl_in(seed, family, history, 1),
            batch: rho_batch_gl_in(seed, family, history, 1),
        }
    }

    /// See [`Openings::private_inputs`].
    pub fn private_inputs(&self) -> Vec<GlChallenge> {
        [self.init, self.final_, self.batch].iter().flat_map(|s| s.packed()).collect()
    }
}

// ─── In-circuit ──────────────────────────────────────────────────────────────

/// The salt of one in-circuit commitment: three PRIVATE inputs (never a
/// constant, never exposed).
///
/// The fork gives a private input its WitnessChecks creator only from its
/// first ALU use, and debug-asserts that every private input has one
/// (`circuit.rs` "was never used as an ALU operand"); a salt fed straight to
/// the Poseidon2 table would leave the bus unbalanced. So each salt input
/// `s` gets one ALU row `u = s·1 + 0` (a `mul_add`, which the expression
/// builder does not fold, unlike `s + 0` or `s·1`): the row creates `s`, and
/// the sponge absorbs `u`, which the ALU defines. Cost: 3 ALU rows per salt.
#[derive(Copy, Clone, Debug)]
pub struct SaltTargets {
    /// The private-input wires, in allocation (= packing) order.
    pub inputs: [ExprId; SALT_CHALLENGES],
    /// The ALU copies the sponge absorbs.
    pub absorbed: [ExprId; SALT_CHALLENGES],
}

/// Allocate one salt: 3 consecutive private inputs plus their ALU creators.
/// Field-generic (BabyBear D = 4, Goldilocks D = 2).
pub fn alloc_salt_targets<F: Field>(b: &mut CircuitBuilder<F>) -> SaltTargets {
    let inputs: [ExprId; SALT_CHALLENGES] =
        std::array::from_fn(|_| b.alloc_private_input("commit_salt"));
    let one = b.alloc_const(F::ONE, "one");
    let zero = b.alloc_const(F::ZERO, "zero");
    let mut absorbed = [zero; SALT_CHALLENGES];
    for (a, &s) in absorbed.iter_mut().zip(&inputs) {
        *a = b.mul_add(s, one, zero);
    }
    SaltTargets { inputs, absorbed }
}

/// The salts of an update leaf's three commitments.
#[derive(Copy, Clone, Debug)]
pub struct LeafSaltTargets {
    pub init: SaltTargets,
    pub final_: SaltTargets,
    pub batch: SaltTargets,
}

/// Allocate a leaf's salts (init, final, batch: 9 consecutive private inputs,
/// the order of [`Openings::private_inputs`]) under `Hiding`; allocate
/// NOTHING under `Plain`, so the Plain circuit is byte-identical.
pub fn alloc_leaf_salts<F: Field>(b: &mut CircuitBuilder<F>, mode: CommitMode) -> Option<LeafSaltTargets> {
    mode.is_hiding().then(|| LeafSaltTargets {
        init: alloc_salt_targets(b),
        final_: alloc_salt_targets(b),
        batch: alloc_salt_targets(b),
    })
}

/// The tag Challenge: basis coefficients `(kind, family, 0, …)`.
pub fn tag_challenge<BF, F>(kind: CommitKind, family: CommitFamily) -> F
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    let mut c = vec![BF::ZERO; <F as BasedVectorSpace<BF>>::DIMENSION];
    c[0] = BF::from_u64(kind.tag());
    c[1] = BF::from_u64(family.id());
    F::from_basis_coefficients_slice(&c).expect("tag coefficients")
}

/// `[tag, salt_0, salt_1, salt_2, inputs…]`: the in-circuit image of the
/// native `prefix ‖ enc(x)`. Hash it with [`bind::hash_slice`] (as
/// [`commit_hash`] does).
pub fn salted_hash_inputs<BF, F>(
    b: &mut CircuitBuilder<F>,
    kind: CommitKind,
    family: CommitFamily,
    salt: &SaltTargets,
    inputs: &[ExprId],
) -> Vec<ExprId>
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    let tag = b.alloc_const(tag_challenge::<BF, F>(kind, family), "commit_tag");
    let mut v = Vec::with_capacity(1 + SALT_CHALLENGES + inputs.len());
    v.push(tag);
    v.extend_from_slice(&salt.absorbed);
    v.extend_from_slice(inputs);
    v
}

/// An in-circuit commitment: `bind::hash_slice(inputs)` without a salt (the
/// Plain gadget, unchanged), `bind::hash_slice(salted_hash_inputs(..))`
/// with one.
#[allow(clippy::too_many_arguments)]
pub fn commit_hash<BF, F>(
    b: &mut CircuitBuilder<F>,
    cfg: &Poseidon2Config,
    kind: CommitKind,
    family: CommitFamily,
    salt: Option<&SaltTargets>,
    inputs: &[ExprId],
    zero: ExprId,
    binding: Binding,
) -> Vec<ExprId>
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    match salt {
        None => bind::hash_slice(b, cfg, inputs, zero, binding),
        Some(s) => {
            let salted = salted_hash_inputs::<BF, F>(b, kind, family, s, inputs);
            bind::hash_slice(b, cfg, &salted, zero, binding)
        }
    }
}

/// Test-only proof inspectors shared by the leaf and decoder tests.
#[cfg(test)]
pub(crate) mod probe {
    use super::*;
    use crate::recursion::recursive::config::ConfigWithFriParams;
    use p3_circuit::ops::NpoTypeId;
    use p3_circuit_prover::{BatchStarkProof, PrimitiveTable};

    /// Logical `(Poseidon2, ALU)` rows of a BabyBear run (before any
    /// padding: a proof's Poseidon2 entry reports the padded height).
    pub(crate) fn trace_rows(traces: &p3_circuit::tables::Traces<Challenge>) -> (usize, usize) {
        let key = NpoTypeId::poseidon2_perm(Poseidon2Config::BABY_BEAR_D4_W16);
        let p2 = traces.non_primitive_traces.get(&key).map_or(0, |t| t.rows());
        (p2, traces.alu_trace.values.len())
    }

    /// The ALU rows a proof reports (logical, equal to [`trace_rows`]'s).
    pub(crate) fn proof_alu_rows(proof: &BatchStarkProof<ConfigWithFriParams>) -> usize {
        proof.rows[PrimitiveTable::Alu]
    }

    /// Every public value the verifier is handed: the primitive tables carry
    /// none, so these are the non-primitive tables' (including the Expose
    /// table's exposed statement).
    pub(crate) fn public_values(proof: &BatchStarkProof<ConfigWithFriParams>) -> Vec<Val> {
        proof.non_primitives.iter().flat_map(|e| e.public_values.iter().copied()).collect()
    }

    /// The nonzero coefficients of `salts` that occur among
    /// [`public_values`] (zero is the public salt, so it is skipped).
    pub(crate) fn leaked_salts(proof: &BatchStarkProof<ConfigWithFriParams>, salts: &[SaltBb]) -> Vec<Val> {
        let pv = public_values(proof);
        salts.iter().flat_map(|s| s.0).filter(|c| *c != Val::ZERO && pv.contains(c)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::forge;
    use p3_baby_bear::default_babybear_poseidon2_16;
    use p3_circuit::ops::{
        GoldilocksD2Width8, generate_expose_trace, generate_poseidon2_trace, generate_recompose_trace,
    };
    use p3_poseidon2_circuit_air::BabyBearD4Width16;

    const FAMILIES: [CommitFamily; 5] = [
        CommitFamily::CountMin,
        CommitFamily::HyperLogLog,
        CommitFamily::SpaceSaving,
        CommitFamily::GreenwaldKhanna,
        CommitFamily::Bloom,
    ];

    #[test]
    fn tags_fit_babybear() {
        let p = <Val as PrimeField64>::ORDER_U64;
        for tag in [TAG_STATE, TAG_BATCH, DS_RHO] {
            assert!(tag < p);
        }
        assert_eq!(&TAG_STATE.to_be_bytes()[4..], b"STAT");
        assert_eq!(&TAG_BATCH.to_be_bytes()[4..], b"BATC");
        let ids: Vec<u64> = FAMILIES.iter().map(|f| f.id()).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    }

    /// (7) The PRF: deterministic, `ρ^S_0` is the public zero, and distinct
    /// across `t`, kind, family and seed, in both fields.
    #[test]
    fn prf_deterministic_zero_at_origin_and_separated() {
        let seed = SaltSeed::for_tests(7);
        assert!(rho_state_bb(&seed, CommitFamily::CountMin, 0).is_zero());
        assert!(rho_state_gl(&seed, CommitFamily::CountMin, 0).is_zero());
        let mut seen_bb: Vec<SaltBb> = vec![SaltBb::ZERO];
        let mut seen_gl: Vec<SaltGl> = vec![SaltGl::ZERO];
        for fam in FAMILIES {
            for t in [1u64, 2, 3, 1 << 24, (1 << 24) + 1, u64::MAX] {
                for (s_bb, s_gl) in [
                    (rho_state_bb(&seed, fam, t), rho_state_gl(&seed, fam, t)),
                    (rho_batch_bb(&seed, fam, t), rho_batch_gl(&seed, fam, t)),
                ] {
                    assert!(!seen_bb.contains(&s_bb), "{fam:?} t={t}: BabyBear randomizer repeats");
                    assert!(!seen_gl.contains(&s_gl), "{fam:?} t={t}: Goldilocks randomizer repeats");
                    seen_bb.push(s_bb);
                    seen_gl.push(s_gl);
                }
            }
        }
        // Deterministic.
        assert_eq!(
            rho_state_bb(&seed, CommitFamily::CountMin, 5),
            rho_state_bb(&SaltSeed::for_tests(7), CommitFamily::CountMin, 5)
        );
        assert_eq!(
            rho_batch_gl(&seed, CommitFamily::SpaceSaving, 5),
            rho_batch_gl(&SaltSeed::for_tests(7), CommitFamily::SpaceSaving, 5)
        );
        // Another seed, and every single seed byte, changes the randomizer.
        let base = rho_state_bb(&seed, CommitFamily::CountMin, 1);
        assert_ne!(base, rho_state_bb(&SaltSeed::for_tests(8), CommitFamily::CountMin, 1));
        for i in 0..32 {
            let mut bytes = seed.0;
            bytes[i] ^= 1;
            assert_ne!(base, rho_state_bb(&SaltSeed(bytes), CommitFamily::CountMin, 1), "byte {i}");
        }
        // The two squeezes are independent outputs, not a repeat.
        assert_ne!(&base.0[..4], &base.0[8..12]);
        // Openings of leaf t chain: final(t) == init(t + 1).
        let o3 = Openings::for_leaf(&seed, CommitFamily::CountMin, 3);
        let o4 = Openings::for_leaf(&seed, CommitFamily::CountMin, 4);
        assert_eq!(o3.final_, o4.init);
        assert_ne!(o3.final_, o4.final_);
        assert!(Openings::for_leaf(&seed, CommitFamily::CountMin, 1).init.is_zero());
        let g3 = OpeningsGl::for_leaf(&seed, CommitFamily::CountMin, 3);
        assert_eq!(g3.final_, OpeningsGl::for_leaf(&seed, CommitFamily::CountMin, 4).init);
        assert_eq!(Openings::plain().private_inputs(), vec![Challenge::ZERO; 9]);
        assert!(forge::catch(|| rho_batch_bb(&seed, CommitFamily::CountMin, 0)).is_none());
    }

    #[test]
    fn os_random_seeds_differ_and_debug_is_redacted() {
        let (a, b) = (SaltSeed::os_random(), SaltSeed::os_random());
        assert_ne!(a.0, b.0);
        let seed = SaltSeed::parse_env(Ok("ab".repeat(32))).unwrap();
        let shown = format!("{seed:?} {:?}", rho_state_bb(&seed, CommitFamily::CountMin, 1));
        assert!(!shown.contains("ab") && !shown.contains("171"), "{shown}");
        assert_eq!(format!("{:?}", SaltBb::ZERO), "SaltBb(zero)");
    }

    /// (7) Env parsing: `ZKSKETCH_COMMIT` and `ZKSKETCH_SALT_SEED`.
    #[test]
    fn env_parsing() {
        use std::env::VarError;
        let unset = || Err(VarError::NotPresent);
        assert_eq!(parse_commit_env(unset(), Binding::Semantic), CommitMode::Hiding);
        assert_eq!(parse_commit_env(unset(), Binding::Bound), CommitMode::Hiding);
        assert_eq!(parse_commit_env(unset(), Binding::Legacy), CommitMode::Plain);
        assert_eq!(parse_commit_env(Ok(String::new()), Binding::Semantic), CommitMode::Hiding);
        assert_eq!(parse_commit_env(Ok(String::new()), Binding::Legacy), CommitMode::Plain);
        assert_eq!(parse_commit_env(Ok("PLAIN".into()), Binding::Semantic), CommitMode::Plain);
        assert_eq!(parse_commit_env(Ok("hiding".into()), Binding::Legacy), CommitMode::Hiding);
        let msg = forge::catch_msg(|| parse_commit_env(Ok("hidden".into()), Binding::Semantic)).unwrap_err();
        assert!(msg.contains("expected plain or hiding"), "{msg}");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = std::ffi::OsString::from_vec(vec![0x68, 0xFF]);
            let msg = forge::catch_msg(|| parse_commit_env(Err(VarError::NotUnicode(bad)), Binding::Semantic))
                .unwrap_err();
            assert!(msg.contains("not valid UTF-8"), "{msg}");
        }

        assert!(SaltSeed::parse_env(unset()).is_none());
        assert!(SaltSeed::parse_env(Ok("  ".into())).is_none());
        let hex: String = (0u8..32).map(|i| format!("{:02x}", i.wrapping_mul(37))).collect();
        let seed = SaltSeed::parse_env(Ok(hex.to_uppercase())).expect("valid seed");
        assert_eq!(seed.0, std::array::from_fn(|i| (i as u8).wrapping_mul(37)));
        for bad in [&hex[..62], &format!("{}zz", &hex[..62])] {
            let msg = forge::catch_msg(|| SaltSeed::parse_env(Ok(bad.to_string()))).unwrap_err();
            assert!(msg.contains("64 hex characters"), "{msg}");
            assert!(!msg.contains(&bad[..16]), "the panic message must not echo the seed");
        }
    }

    /// Drift guard of the native layout: `Plain` is `MyHash(flat)`, `Hiding`
    /// is `MyHash([kind, family, 0, 0, ρ…] ‖ flat)` (BabyBear) and
    /// `MyHash([kind, family, ρ…] ‖ flat)` (Goldilocks).
    #[test]
    fn native_layout_matches_spec() {
        let seed = SaltSeed::for_tests(1);
        let rho = rho_state_bb(&seed, CommitFamily::CountMin, 2);
        let flat: Vec<Val> = (1..=8u32).map(Val::from_u32).collect();
        let h = MyHash::new(make_perm());
        let plain: [Val; 8] = h.hash_iter(flat.clone());
        let fam = CommitFamily::CountMin;
        assert_eq!(commit_flat_bb(CommitMode::Plain, CommitKind::State, fam, &rho, &flat), plain);
        let mut input = vec![Val::from_u64(TAG_STATE), Val::ONE, Val::ZERO, Val::ZERO];
        input.extend_from_slice(&rho.0);
        input.extend_from_slice(&flat);
        let want: [Val; 8] = h.hash_iter(input);
        let hiding = commit_flat_bb(CommitMode::Hiding, CommitKind::State, fam, &rho, &flat);
        assert_eq!(hiding, want);
        assert_ne!(hiding, plain);
        assert_ne!(hiding, commit_flat_bb(CommitMode::Hiding, CommitKind::Batch, fam, &rho, &flat));
        assert_ne!(
            hiding,
            commit_flat_bb(CommitMode::Hiding, CommitKind::State, CommitFamily::HyperLogLog, &rho, &flat)
        );
        // Even the public zero salt separates kinds and families from Plain.
        assert_ne!(commit_flat_bb(CommitMode::Hiding, CommitKind::State, fam, &SaltBb::ZERO, &flat), plain);

        let rho_g = rho_state_gl(&seed, fam, 2);
        let flat_g: Vec<GlVal> = (1..=4u32).map(GlVal::from_u32).collect();
        let hg = GlHash::new(make_perm_gl());
        let mut input_g = vec![GlVal::from_u64(TAG_STATE), GlVal::ONE];
        input_g.extend_from_slice(&rho_g.0);
        input_g.extend_from_slice(&flat_g);
        let want_g: [GlVal; 4] = hg.hash_iter(input_g);
        assert_eq!(commit_flat_gl(CommitMode::Hiding, CommitKind::State, fam, &rho_g, &flat_g), want_g);
        let plain_g: [GlVal; 4] = hg.hash_iter(flat_g.clone());
        assert_eq!(commit_flat_gl(CommitMode::Plain, CommitKind::State, fam, &rho_g, &flat_g), plain_g);
        assert!(forge::catch(|| commit_flat_bb(CommitMode::Hiding, CommitKind::State, fam, &rho, &flat[..3])).is_none());
    }

    /// A tiny BabyBear circuit: `Com(x; ρ)` of two private Challenges `x`,
    /// through [`commit_hash`], connected to 2 public inputs (the native
    /// digest) and exposed. `raw_salt` is the negative control: the salt
    /// private inputs are allocated WITHOUT their ALU creators and fed
    /// straight to the sponge. Returns the circuit and its runner inputs.
    fn salted_commit_circuit(
        salt: Option<SaltBb>,
        binding: Binding,
        raw_salt: bool,
    ) -> (p3_circuit::Circuit<Challenge>, Vec<Challenge>, Vec<Challenge>, [Val; 8]) {
        salted_commit_circuit_fam(salt, binding, raw_salt, CommitFamily::CountMin)
    }

    /// [`salted_commit_circuit`] under the tag of `family`.
    fn salted_commit_circuit_fam(
        salt: Option<SaltBb>,
        binding: Binding,
        raw_salt: bool,
        family: CommitFamily,
    ) -> (p3_circuit::Circuit<Challenge>, Vec<Challenge>, Vec<Challenge>, [Val; 8]) {
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let pis: [ExprId; 2] = std::array::from_fn(|_| b.alloc_public_input("digest"));
        b.add_expose(&pis).unwrap();
        let one = b.alloc_const(Challenge::ONE, "one");
        let zero = b.alloc_const(Challenge::ZERO, "zero");
        let st = salt.map(|_| {
            if raw_salt {
                let inputs: [ExprId; SALT_CHALLENGES] =
                    std::array::from_fn(|_| b.alloc_private_input("raw_salt"));
                SaltTargets { inputs, absorbed: inputs }
            } else {
                alloc_salt_targets(&mut b)
            }
        });
        let x: [ExprId; 2] = std::array::from_fn(|_| b.alloc_private_input("x"));
        // The data inputs need an ALU creator too (the leaves' cells get one
        // from their decomposition); the sponge reads the inputs themselves.
        for &xi in &x {
            let _ = b.mul_add(xi, one, zero);
        }
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
        let digest = commit_hash::<Val, Challenge>(
            &mut b,
            &cfg,
            CommitKind::State,
            family,
            st.as_ref(),
            &x,
            zero,
            binding,
        );
        for i in 0..2 {
            b.connect(digest[i], pis[i]);
        }
        let circuit = b.build().unwrap();

        let flat: Vec<Val> = (0..8u32).map(|i| Val::from_u32(1000 + i)).collect();
        let mode = if salt.is_some() { CommitMode::Hiding } else { CommitMode::Plain };
        let native = commit_flat_bb(mode, CommitKind::State, family, &salt.unwrap_or(SaltBb::ZERO), &flat);
        let pub_vals: Vec<Challenge> = native
            .chunks(4)
            .map(|c| Challenge::from_basis_coefficients_slice(c).unwrap())
            .collect();
        let mut priv_vals: Vec<Challenge> = salt.map(|s| s.packed().to_vec()).unwrap_or_default();
        priv_vals.extend(flat.chunks(4).map(|c| Challenge::from_basis_coefficients_slice(c).unwrap()));
        (circuit, pub_vals, priv_vals, native)
    }

    /// Run + prove + verify [`salted_commit_circuit`]; the exposed digest if
    /// the proof verifies (checked equal to the native commitment).
    fn prove_salted_commit(salt: Option<SaltBb>, binding: Binding, raw_salt: bool) -> Option<Vec<Val>> {
        let (circuit, pub_vals, priv_vals, native) = salted_commit_circuit(salt, binding, raw_salt);
        let traces = forge::catch(|| {
            let mut runner = circuit.runner();
            runner.set_public_inputs(&pub_vals).unwrap();
            runner.set_private_inputs(&priv_vals).unwrap();
            runner.run().unwrap()
        })?;
        let exposed = bind::probe::prove_small(&circuit, &traces, false)?;
        assert_eq!(exposed, native.to_vec(), "exposed digest == native commitment");
        Some(exposed)
    }

    /// Native == in-circuit (the runner connects the in-circuit digest to the
    /// native one, and the proof exposes it), Plain and Hiding, under the
    /// plain and the bound sponge.
    #[test]
    fn in_circuit_salted_commit_matches_native() {
        let rho = rho_state_bb(&SaltSeed::for_tests(3), CommitFamily::CountMin, 4);
        for binding in [Binding::Semantic, Binding::Bound] {
            assert!(prove_salted_commit(None, binding, false).is_some(), "{binding:?} plain");
            assert!(prove_salted_commit(Some(rho), binding, false).is_some(), "{binding:?} hiding");
            assert!(prove_salted_commit(Some(SaltBb::ZERO), binding, false).is_some(), "{binding:?} zero");
        }
    }

    /// (8) Every salt private input has a WitnessChecks creator. Run this in
    /// the DEBUG profile too (`cargo test --lib
    /// commitment::hiding::tests::salt_private_inputs_have_alu_creators`,
    /// no `--release`): there the fork debug-asserts, while building the
    /// preprocessed columns, that every private input was claimed by an ALU
    /// op (`circuit.rs` "was never used as an ALU operand"). Negative
    /// control: the same circuit with the salts fed raw to the sponge (no ALU
    /// use) trips that assertion in debug, and its proof fails in release
    /// (a WitnessChecks read with no creator).
    #[test]
    fn salt_private_inputs_have_alu_creators() {
        let rho = rho_state_bb(&SaltSeed::for_tests(5), CommitFamily::CountMin, 1);
        let (good, ..) = salted_commit_circuit(Some(rho), Binding::Semantic, false);
        good.generate_preprocessed_columns::<4>().expect("preprocessed columns (ALU-created salts)");
        assert!(prove_salted_commit(Some(rho), Binding::Semantic, false).is_some());
        assert!(
            prove_salted_commit(Some(rho), Binding::Semantic, true).is_none(),
            "raw salts (no ALU creator) must be rejected"
        );
        let (raw, ..) = salted_commit_circuit(Some(rho), Binding::Semantic, true);
        let pre = forge::catch_msg(|| raw.generate_preprocessed_columns::<4>().map(|_| ()));
        if cfg!(debug_assertions) {
            let msg = pre.expect_err("a salt with no ALU use trips the fork's debug assertion");
            assert!(msg.contains("never used as an ALU operand"), "{msg}");
        } else {
            assert!(pre.is_ok(), "release builds skip the debug assertion: {pre:?}");
        }
    }

    /// Goldilocks: the field-generic salt gadget over `GOLDILOCKS_D2_W8`
    /// equals [`commit_flat_gl`] (runner level: the in-circuit digest is
    /// connected to the native one).
    #[test]
    fn in_circuit_salted_commit_matches_native_gl() {
        let rho = rho_state_gl(&SaltSeed::for_tests(3), CommitFamily::SpaceSaving, 2);
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut b = CircuitBuilder::<GlChallenge>::new();
            b.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
                generate_poseidon2_trace::<GlChallenge, GoldilocksD2Width8>,
                make_perm_gl(),
            );
            let pis: [ExprId; 2] = std::array::from_fn(|_| b.alloc_public_input("digest"));
            let zero = b.alloc_const(GlChallenge::ZERO, "zero");
            let st = alloc_salt_targets(&mut b);
            let x: [ExprId; 3] = std::array::from_fn(|_| b.alloc_private_input("x"));
            let digest = commit_hash::<GlVal, GlChallenge>(
                &mut b,
                &Poseidon2Config::GOLDILOCKS_D2_W8,
                CommitKind::State,
                CommitFamily::SpaceSaving,
                Some(&st),
                &x,
                zero,
                binding,
            );
            for i in 0..2 {
                b.connect(digest[i], pis[i]);
            }
            let circuit = b.build().unwrap();
            let flat: Vec<GlVal> = (0..6u64).map(|i| GlVal::from_u64((1 << 40) + i)).collect();
            let native =
                commit_flat_gl(CommitMode::Hiding, CommitKind::State, CommitFamily::SpaceSaving, &rho, &flat);
            let pub_vals: Vec<GlChallenge> = native
                .chunks(2)
                .map(|c| GlChallenge::from_basis_coefficients_slice(c).unwrap())
                .collect();
            let mut priv_vals = rho.packed().to_vec();
            priv_vals.extend(flat.chunks(2).map(|c| GlChallenge::from_basis_coefficients_slice(c).unwrap()));
            let mut runner = circuit.runner();
            runner.set_public_inputs(&pub_vals).unwrap();
            runner.set_private_inputs(&priv_vals).unwrap();
            runner.run().unwrap_or_else(|e| panic!("{binding:?}: in-circuit != native: {e:?}"));
            // A different salt conflicts with the native digest.
            let mut runner = circuit.runner();
            runner.set_public_inputs(&pub_vals).unwrap();
            let mut wrong = priv_vals.clone();
            wrong[0] += GlChallenge::ONE;
            runner.set_private_inputs(&wrong).unwrap();
            assert!(runner.run().is_err(), "{binding:?}: a wrong salt must conflict");
        }
    }

    /// (F2) History separation: the PRF absorbs a public history id, so one
    /// seed reused by two histories that both restart `t` at 1 gives
    /// unrelated randomizers (no repeat across `(history, t)`, including the
    /// swapped pair), the genesis wrappers are history 0, a continued
    /// history has no derived `ρ^S_0` (it panics), and its leaf 1 opens its
    /// init with the anchor (the previous history's final randomizer) and
    /// chains into its leaf 2.
    #[test]
    fn prf_separates_histories_and_anchors_continued_histories() {
        let seed = SaltSeed::for_tests(17);
        let fam = CommitFamily::GreenwaldKhanna;
        assert_eq!(PRF_INPUT_LEN, 21);
        for t in [0u64, 1, 9] {
            assert_eq!(rho_state_bb(&seed, fam, t), rho_state_bb_in(&seed, fam, GENESIS_HISTORY, t));
            assert_eq!(rho_state_gl(&seed, fam, t), rho_state_gl_in(&seed, fam, GENESIS_HISTORY, t));
        }
        assert_eq!(rho_batch_bb(&seed, fam, 9), rho_batch_bb_in(&seed, fam, GENESIS_HISTORY, 9));
        assert_eq!(rho_batch_gl(&seed, fam, 9), rho_batch_gl_in(&seed, fam, GENESIS_HISTORY, 9));
        let (mut seen_bb, mut seen_gl) = (vec![SaltBb::ZERO], vec![SaltGl::ZERO]);
        for h in [GENESIS_HISTORY, 1, 2, 1 << 24, u64::MAX] {
            for t in [1u64, 2, 1 << 24, u64::MAX] {
                for (s_bb, s_gl) in [
                    (rho_state_bb_in(&seed, fam, h, t), rho_state_gl_in(&seed, fam, h, t)),
                    (rho_batch_bb_in(&seed, fam, h, t), rho_batch_gl_in(&seed, fam, h, t)),
                ] {
                    assert!(!seen_bb.contains(&s_bb), "h={h} t={t}: BabyBear randomizer repeats");
                    assert!(!seen_gl.contains(&s_gl), "h={h} t={t}: Goldilocks randomizer repeats");
                    seen_bb.push(s_bb);
                    seen_gl.push(s_gl);
                }
            }
        }
        // A continued history's ρ^S_0 is anchored, not derived.
        for h in [1u64, 7] {
            let msg = forge::catch_msg(|| rho_state_bb_in(&seed, fam, h, 0)).unwrap_err();
            assert!(msg.contains("for_leaf_after"), "{msg}");
            assert!(forge::catch(|| rho_state_gl_in(&seed, fam, h, 0)).is_none());
            assert!(forge::catch(|| Openings::for_leaf_in(&seed, fam, h, 1)).is_none());
            assert!(forge::catch(|| OpeningsGl::for_leaf_in(&seed, fam, h, 1)).is_none());
        }
        // Leaf 1 of history 1 opens the previous history's final Com(S_T; ρ_T).
        let t_prev = 5;
        let anchor = rho_state_bb(&seed, fam, t_prev);
        let o1 = Openings::for_leaf_after(&anchor, &seed, fam, 1);
        assert_eq!(o1.init, anchor);
        assert_eq!(o1.init, Openings::for_leaf(&seed, fam, t_prev).final_);
        assert_eq!(o1.final_, rho_state_bb_in(&seed, fam, 1, 1));
        assert_eq!(o1.batch, rho_batch_bb_in(&seed, fam, 1, 1));
        assert_eq!(o1.final_, Openings::for_leaf_in(&seed, fam, 1, 2).init, "leaf 1 chains into leaf 2");
        assert_ne!(o1.final_, Openings::for_leaf(&seed, fam, 1).final_, "t restarts, ρ does not");
        assert_ne!(o1.batch, Openings::for_leaf(&seed, fam, 1).batch);
        let anchor_g = rho_state_gl(&seed, fam, t_prev);
        let g1 = OpeningsGl::for_leaf_after(&anchor_g, &seed, fam, 1);
        assert_eq!(g1.init, anchor_g);
        assert_eq!(g1.final_, OpeningsGl::for_leaf_in(&seed, fam, 1, 2).init);
        // The genesis history's anchor is the public zero.
        assert!(forge::catch(|| Openings::for_leaf_after(&anchor, &seed, fam, GENESIS_HISTORY)).is_none());
        assert!(forge::catch(|| OpeningsGl::for_leaf_after(&anchor_g, &seed, fam, GENESIS_HISTORY)).is_none());
        assert_eq!(Openings::public_zero(), Openings::plain());
    }

    /// (F3) Per-commitment overhead of the salt: +2 Poseidon2 rows (the
    /// 4-Challenge prefix is two rate blocks) and +3 ALU rows (one creator
    /// per salt Challenge), under the plain and the bound sponge.
    #[test]
    fn hiding_row_overhead_per_commitment() {
        let rho = rho_state_bb(&SaltSeed::for_tests(4), CommitFamily::CountMin, 1);
        for binding in [Binding::Semantic, Binding::Bound] {
            let rows = |salt: Option<SaltBb>| {
                let (circuit, pub_vals, priv_vals, _) = salted_commit_circuit(salt, binding, false);
                let mut runner = circuit.runner();
                runner.set_public_inputs(&pub_vals).unwrap();
                runner.set_private_inputs(&priv_vals).unwrap();
                probe::trace_rows(&runner.run().unwrap())
            };
            let ((p0, a0), (p1, a1)) = (rows(None), rows(Some(rho)));
            assert_eq!(p1, p0 + 2, "{binding:?}: Poseidon2 rows {p0} -> {p1}");
            assert_eq!(a1, a0 + SALT_CHALLENGES, "{binding:?}: ALU rows {a0} -> {a1}");
        }
    }

    /// Preprocessed commitment (VK, `vk_pin_values` order) of a circuit on
    /// the [`bind::probe::prove_small`] tables. Structural: no trace.
    fn small_circuit_vk(circuit: &p3_circuit::Circuit<Challenge>) -> Vec<Challenge> {
        use crate::config::LOG_BLOWUP;
        use crate::recursion::recursive::config::ConfigWithFriParams;
        use crate::recursion::recursive::countmin_leaf::make_leaf_config;
        use p3_batch_stark::ProverData;
        use p3_circuit_prover::batch_stark_prover::{
            expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4, poseidon2_preprocessor,
            recompose_air_builders, recompose_preprocessor,
        };
        use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
        use p3_circuit_prover::{ConstraintProfile, TablePacking};
        use p3_uni_stark::StarkGenericConfig;

        let config = make_leaf_config();
        let table_packing = TablePacking::new(1, 2).with_fri_params(6, LOG_BLOWUP);
        let preprocessors =
            vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false), expose_preprocessor::<Val>()];
        let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
        air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
        let (airs_degrees, _, _) = get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("salted commit AIRs");
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext);
        crate::recursion::recursive::expose_forest::common_vk_pin_values(&pd.common)
    }

    /// (F4) The tag is a circuit constant, and at the pinned fork a constant's
    /// VALUE is part of the VK (ConstAir preprocesses it): two circuits that
    /// differ only in the family tag have different VKs, while two salts
    /// (witnesses) share one VK. Cross-checked with the structural probe.
    #[test]
    fn tag_constant_is_bound_by_the_vk() {
        let seed = SaltSeed::for_tests(12);
        let (r1, r2) = (rho_state_bb(&seed, CommitFamily::CountMin, 1), rho_state_bb(&seed, CommitFamily::CountMin, 2));
        let vk = |salt: SaltBb, family: CommitFamily| {
            small_circuit_vk(&salted_commit_circuit_fam(Some(salt), Binding::Semantic, false, family).0)
        };
        let cm = vk(r1, CommitFamily::CountMin);
        assert_eq!(cm, vk(r2, CommitFamily::CountMin), "the salt is a witness, not part of the VK");
        assert_ne!(cm, vk(r1, CommitFamily::HyperLogLog), "the family tag is bound by the VK");
        assert!(bind::probe::fork_binds_const(), "the pinned fork binds constant values");
    }

    /// Goldilocks at PROOF level (the runner-level test above only checks the
    /// witness): the field-generic salt gadget over `GOLDILOCKS_D2_W8`,
    /// connected to the native [`commit_flat_gl`] digest and exposed, proves
    /// and verifies; the exposed digest is the native one and no salt value
    /// is a public value. Negative control: the salts fed raw to the sponge
    /// (no ALU creator) do not prove.
    #[test]
    fn in_circuit_salted_commit_proves_gl() {
        let rho = rho_state_gl(&SaltSeed::for_tests(3), CommitFamily::SpaceSaving, 2);
        for binding in [Binding::Semantic, Binding::Bound] {
            let pv = prove_salted_commit_gl(rho, binding, false)
                .unwrap_or_else(|| panic!("{binding:?}: the Goldilocks hiding commitment must prove"));
            let flat: Vec<GlVal> = (0..6u64).map(|i| GlVal::from_u64((1 << 40) + i)).collect();
            let native = commit_flat_gl(CommitMode::Hiding, CommitKind::State, CommitFamily::SpaceSaving, &rho, &flat);
            assert_eq!(pv, native.to_vec(), "{binding:?}: exposed digest == native commitment");
            assert!(rho.0.iter().all(|s| !pv.contains(s)), "{binding:?}: a salt value is public");
            assert!(prove_salted_commit_gl(rho, binding, true).is_none(), "{binding:?}: raw salts must not prove");
        }
    }

    /// Build, run, prove and verify the Goldilocks salted commitment of 3
    /// private Challenges; the exposed values if the proof verifies.
    fn prove_salted_commit_gl(rho: SaltGl, binding: Binding, raw_salt: bool) -> Option<Vec<GlVal>> {
        use crate::config_gl::LOG_BLOWUP;
        use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl;
        use crate::recursion::recursive::leaf_gl::make_leaf_config;
        use p3_batch_stark::ProverData;
        use p3_circuit_prover::batch_stark_prover::{
            expose_air_builders, expose_preprocessor, poseidon2_air_builders_d2, poseidon2_preprocessor,
            recompose_air_builders, recompose_preprocessor,
        };
        use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
        use p3_circuit_prover::{BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking};
        use p3_uni_stark::StarkGenericConfig;

        let cfg = Poseidon2Config::GOLDILOCKS_D2_W8;
        let mut b = CircuitBuilder::<GlChallenge>::new();
        b.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<GlChallenge, GoldilocksD2Width8>,
            make_perm_gl(),
        );
        b.enable_recompose::<GlVal>(generate_recompose_trace::<GlVal, GlChallenge>);
        b.enable_expose(generate_expose_trace::<GlVal, GlChallenge>);
        let pis: [ExprId; 2] = std::array::from_fn(|_| b.alloc_public_input("digest"));
        b.add_expose(&pis).unwrap();
        let one = b.alloc_const(GlChallenge::ONE, "one");
        let zero = b.alloc_const(GlChallenge::ZERO, "zero");
        let st = if raw_salt {
            let inputs: [ExprId; SALT_CHALLENGES] = std::array::from_fn(|_| b.alloc_private_input("raw_salt"));
            SaltTargets { inputs, absorbed: inputs }
        } else {
            alloc_salt_targets(&mut b)
        };
        let x: [ExprId; 3] = std::array::from_fn(|_| b.alloc_private_input("x"));
        for &xi in &x {
            let _ = b.mul_add(xi, one, zero);
        }
        let digest = commit_hash::<GlVal, GlChallenge>(
            &mut b,
            &cfg,
            CommitKind::State,
            CommitFamily::SpaceSaving,
            Some(&st),
            &x,
            zero,
            binding,
        );
        for i in 0..2 {
            b.connect(digest[i], pis[i]);
        }
        let circuit = b.build().unwrap();
        let flat: Vec<GlVal> = (0..6u64).map(|i| GlVal::from_u64((1 << 40) + i)).collect();
        let native = commit_flat_gl(CommitMode::Hiding, CommitKind::State, CommitFamily::SpaceSaving, &rho, &flat);
        let pub_vals: Vec<GlChallenge> =
            native.chunks(2).map(|c| GlChallenge::from_basis_coefficients_slice(c).unwrap()).collect();
        let mut priv_vals = rho.packed().to_vec();
        priv_vals.extend(flat.chunks(2).map(|c| GlChallenge::from_basis_coefficients_slice(c).unwrap()));

        forge::catch(|| {
            let mut runner = circuit.runner();
            runner.set_public_inputs(&pub_vals).unwrap();
            runner.set_private_inputs(&priv_vals).unwrap();
            let traces = runner.run().ok()?;
            let config = make_leaf_config();
            let table_packing = TablePacking::new(1, 2).with_fri_params(6, LOG_BLOWUP);
            let preprocessors = vec![
                poseidon2_preprocessor::<GlVal>(),
                recompose_preprocessor::<GlVal>(false),
                expose_preprocessor::<GlVal>(),
            ];
            let mut air_builders = poseidon2_air_builders_d2::<ConfigWithFriParamsGl>();
            air_builders.extend(recompose_air_builders::<ConfigWithFriParamsGl, 2>(1, false));
            air_builders.extend(expose_air_builders::<ConfigWithFriParamsGl, 2>());
            let (airs_degrees, pc, npc) = get_airs_and_degrees_with_prep::<ConfigWithFriParamsGl, GlChallenge, 2>(
                &circuit,
                &table_packing,
                &preprocessors,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .ok()?;
            let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
            let ext: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
            let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext);
            let cpd = CircuitProverData::new(pd, pc, npc);
            let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
            prover.register_poseidon2_table::<2>(cfg);
            prover.register_recompose_table::<2>(false);
            prover.register_expose_table::<2>();
            let proof = prover.prove_all_tables(&traces, &cpd).ok()?;
            prover.verify_all_tables(&proof).ok()?;
            let pv: Vec<GlVal> = proof.non_primitives.iter().flat_map(|e| e.public_values.clone()).collect();
            Some(pv)
        })
        .flatten()
    }
}
