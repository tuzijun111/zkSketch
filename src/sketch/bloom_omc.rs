//! **Offline-memory-checking Bloom-filter leaf (`bloom_omc`)** — a measured
//! generality instance of the Pattern-A Step-5 rebind for an *OR* update,
//! forked from [`super::hll_omc`] (the max-update leaf), not from the additive
//! [`super::countmin_omc`].
//!
//! ## Sketch
//!
//! A **partitioned** Bloom filter: `k` slices of `W = 2^log_w` bits each
//! (`M = k·W` cells). A record `key` is hashed ONCE with Poseidon2 and digest
//! limb `j` gives slice `j`'s position `pos_j = digest[j] mod W` (the Count-Min
//! row construction: `k ≤ 8` positions from one 8-limb digest). Insert sets
//! the `k` bits `S[j·W + pos_j] := 1`; a membership query ANDs them. Each
//! state cell is one bit stored as its own field element.
//!
//! ## Why the timestamp coordinate is REQUIRED
//!
//! The per-cell update is `N = O ∨ A` (old bit OR the batch's OR at that cell).
//! OR has a fixed point (`1 ∨ x = 1`), so — exactly like HLL's max — a write can
//! equal its read. A certificate that lists only newly set bits, or a plain
//! `M_old ⊎ W = M_new ⊎ R` rebind without time, is unsound: the prover claims a
//! touched `0` bit "was already 1" (`O = N = 1`), leaves it `0` in the committed
//! final state, and the balance still closes — the insert is suppressed and the
//! filter reports a **false negative**. The rebind below is the timestamped
//! offline-memory-checking form (Blum et al. / Spice) specialised to one
//! read/write pair per touched cell:
//!
//! ```text
//!   WS = {(a, S_{t-1}[a], 0) : a < M}  ⊎  {(a_z, N_z, 1) : touched a_z}
//!   RS = {(a, S_t[a],  ft_a) : a < M}  ⊎  {(a_z, O_z, 0) : touched a_z}
//!   WS == RS   (multisets of (addr, bit, ts), one Permute op)
//! ```
//!
//! The only `ts = 0` writes are the init writes, one per address, so a touched
//! cell's `ts = 0` update read can only consume its own init write, forcing
//! `O_z = S_{t-1}[a_z]`; the `ts = 1` update write then forces `S_t[a_z] = N_z`,
//! and every untouched cell is pinned `S_t[u] = S_{t-1}[u]`. `N_z = O_z ∨ A_z` is
//! computed in-circuit, where `A_z` is the OR of the batch bits routed to
//! `a_z`, a running OR over the `(address, bit)` pairs sorted by address
//! (group-by: every touched address has exactly one segment, hence exactly one
//! read/write pair).
//!
//! ## Binding discipline (differs from `hll_omc` ON PURPOSE)
//!
//! * **No `decompose_ext_to_base_coeffs` anywhere.** In the pinned fork, with
//!   the recompose NPO enabled and `coeff_lookups = false` (the configuration
//!   every leaf in this crate uses), the decompose coefficients are hint
//!   outputs that the Recompose table does *not* read on the WitnessChecks bus
//!   (only the packed output is bus-bound, see `RecomposeAir::eval`). They are
//!   therefore not bound to the value they decompose. [`tests::poc_npo_decompose_coefficients_are_unbound`]
//!   forges one such coefficient in the trace and the proof still verifies.
//!   This leaf instead witnesses every base coefficient as a private input,
//!   pins it to the base field with a range/boolean check, and recomposes it
//!   through the ALU (`recompose_base_coeffs_to_ext_via_alu`) before
//!   `connect`ing to the hash input/output — [`tests::control_alu_recompose_binding_rejects_forgery`]
//!   shows the same forgery is rejected there.
//! * **Only byte-aligned `add_range_bits`.** For `n % 8 != 0` the fork's
//!   `add_range_bits` looks up only `byte·2^(8−r)` for the top byte, which in a
//!   prime field admits `byte = v·2^-(8−r)` for every byte `v`: for `n ≥ 9` the
//!   proven bound is `x < 2^n + 2^(8⌈n/8⌉−8)` (not `2^n`), for `n < 8` it is no
//!   range bound at all ([`tests::poc_add_range_bits_unaligned_is_not_a_range_check`]
//!   gets `add_range_bits(x, 4)` to accept `x = 16^{-1} mod p`).
//!   [`range_exact`] uses two aligned checks instead
//!   ([`tests::control_range_exact_rejects_unaligned_forgery`]).
//! * **Bound Poseidon2 IV.** In the fork's D = 4 Poseidon2 layout a
//!   `new_start` row does not constrain input limbs that carry no CTL (the
//!   zero-capacity assertion exists only in the compact D = 1 layout), so
//!   `add_hash_slice` hashes under a prover-chosen capacity (and, for a
//!   one-Challenge input, a prover-chosen second rate limb):
//!   [`tests::poc_poseidon_d4_free_capacity`] exposes a "digest" of `x` that is
//!   not `MyHash(x)`. For routing this is fatal — with any nonzero capacity a
//!   record's positions are unrelated to its key, so the insert is silently
//!   dropped (false negative), and positions can be ground at will. Every hash
//!   here goes through [`hash_slice_bound`], which feeds the zero constant into
//!   every first-row limb ([`tests::control_bound_sponge_rejects_capacity_forgery`]).
//! * **Canonical positions.** `digest[j] = pos + 2^log_w·hi` with `pos` exact in
//!   `[0, 2^log_w)`, `hi ≤ HI_MAX = (p−1)/2^log_w`, and `hi = HI_MAX ⇒ pos = 0`,
//!   i.e. the split integer is `≤ p−1`. Without this, a limb `x < 2^27 − 1`
//!   also splits as `x + p`, which shifts the position to `(x+1) mod W`
//!   (`p ≡ 1 mod 2^27`) — a misrouting [`tests::noncanonical_position_rejected`]
//!   mounts end-to-end.
//! * **Injective key encoding.** The 64-bit key is NOT reduced mod `p` (the
//!   `Legacy` CM/HLL omc leaves, and the one-hot/memcheck/Merkle CM leaves,
//!   hash `Val::from_u64(key)`, so keys congruent mod `p` collide and are
//!   deterministic false positives of each other; the `Semantic`/`Bound`
//!   CM/HLL omc leaves and the CM decoder now use the same 16-bit limbs,
//!   [`crate::sketch::bind::key_from_limbs`]). On BabyBear a
//!   32-bit limb is not injective either (`p < 2^31`), so the key is hashed as
//!   four range-checked 16-bit limbs, one Challenge `[k0, k1, k2, k3 + 2^16·act]`
//!   (still ONE Poseidon2 absorb). `act ∈ {0,1}` marks real records; dummy
//!   (padding) records are forced canonical: `act = 0 ⇒ k0 = k1 = k2 = k3 = 0`,
//!   and they OR in bit `act = 0`, i.e. never change the state.
//! * **Exposed boundary.** In this fork `alloc_public_input` values are *not*
//!   visible to an outside verifier (the Public table is a committed trace).
//!   The standalone leaf ([`build_bloom_omc_leaf`]) therefore always surfaces
//!   `(init, final, batch)` commitments via the Expose NPO (24 base values);
//!   [`read_exposed_commitments`] reads them from a proof. (`hll_omc` exposes
//!   only `(init, final)`, so its batch is not bound to the proof.)
//! * **Composable statement.** The 24-value layout is not one the proof forest
//!   folds. [`build_bloom_omc_leaf_expose`] with [`Expose::Interval`] instead
//!   exposes the composition layer's interval statement
//!   `(Com(S_{t-1}), Com(S_t), (t, t, 0, 0), H(TAG_LEAF, t, Com(B_t)))`
//!   (28 values, [`crate::recursion::recursive::statement`]): `t` is a public
//!   input pinned to the base field, and `Com(B_t)` is the in-circuit batch
//!   digest above, so the batch is still bound to the proof, now through `H`.
//!   `H` is hashed with the bound sponge like every other hash here.
//!   [`Expose::Boundary`] exposes `(init, final)` only (the pre-B6(b)
//!   statement, for side-by-side runs); [`Expose::None`] is the standalone
//!   24-value leaf, op for op.
//!
//! ## Open caveat: constants are not bound by the pinned fork
//!
//! `ConstAir` stores constant VALUES in the main trace (only `(multiplicity,
//! index)` are preprocessed, no constraint), so a prover can replace any
//! constant consistently across its uses — [`tests::poc_const_values_are_prover_chosen`]
//! verifies a proof of `y = x + 5` that exposes `x = 1, y = 8`. This breaks
//! every circuit built on the fork, this one included (e.g. the zero IV of
//! [`hash_slice_bound`], the `assert_zero` target, the cell-address constants).
//! Everything argued above is therefore **conditional on the fork binding
//! constant values** (moving the value columns into the preprocessed trace).
//! A fork-free mitigation also exists because constants are pooled by value:
//! expose every distinct constant once and derive the per-cell constants by
//! an ALU chain; it is not implemented here. Separately, the native
//! `verify_all_tables` reads the preprocessed commitments from the proof
//! itself, so a real verifier must also pin them (the forgery tests keep the
//! circuit, hence those commitments, unchanged).
//!
//! ## Hiding commitments (revision B2)
//!
//! [`build_bloom_omc_leaf_commit`] takes a [`CommitMode`]. `Plain` is the
//! leaf above byte for byte (no new op, same VK). Under `Hiding` the three
//! commitments absorb the prefix `[kind, family, 0, 0, ρ_0..ρ_11]` of
//! [`crate::commitment::hiding`] (tag `TAG_STATE` / `TAG_BATCH`, family
//! [`CommitFamily::Bloom`] = 5) before the same cells / records, with the
//! three salts (init, final, batch) the FIRST private inputs; natively
//! [`commit_bloom_with`] and [`bloom_batch_commit_with`]. The salts are
//! witnesses (each gets an ALU creator, [`hiding::alloc_salt_targets`]),
//! hashed with the same bound zero-IV sponge as every other hash here, so
//! binding holds for every `ρ`. A hiding leaf is proved with
//! [`BloomOmcLeafCircuit::prove_epoch_commit`] and the prover's openings of
//! leaf `t`; `prove_epoch_at` refuses to run on it, and the one zero-salt
//! path, [`BloomOmcLeafCircuit::prove_epoch_public_zero`], accepts only the
//! public no-op input of the VK-derivation leaf (the empty filter and an
//! all-dummy batch at `t = 1`).
//!
//! ## Two Permute ops share one bus
//!
//! The fork's PermuteAir sends bare values on one `PermuteBus` for ALL Permute
//! ops of a circuit, so what is proven is `sort_in ⊎ omc_in == sort_out ⊎
//! omc_out`, not two separate equalities. Here that union still splits: sort
//! elements are base-field values `2a + bit` (coordinate 3 = 0); OMC elements
//! are `(a, bit, ts, 1)` (coordinate 3 = 1) or the zero dummy of an inactive
//! update row, and the zero dummies occur at the same `a_active = 0` rows on
//! both OMC sides. So every value class balances within its own op.
//!
//! ## Cost
//!
//! One Permute over `M + k·batch` tagged elements, dense commit/unpack of both
//! states (`Θ(M)`), and per record one Poseidon2 digest, `k` canonical splits
//! and `k` sorted `(address, bit)` rows: **`Θ(M + k·batch)`**.
//!
//! Measured (2026-09-24, shared 64-thread box under load, official release
//! profile, `tests::bloom_omc_measure`, k = 7, W = 2^14, M = 114,688, half-full
//! prior): batch 256 → 852,992 trace rows, prove ≈ 1.8 s, proof ≈ 581 KB;
//! batch 4096 → 3,081,216 rows, ≈ 6.4 s, ≈ 717 KB; batch 16384 → 7,013,376
//! rows, ≈ 12.9 s, ≈ 734 KB (verify ≈ 15–20 ms throughout).

use std::collections::HashMap;
use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, Poseidon2PermCall, generate_expose_trace, generate_permute_trace,
    generate_poseidon2_trace, generate_range_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
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
use crate::commitment::hiding::{
    self, CommitFamily, CommitKind, CommitMode, Openings, SaltBb, SaltTargets,
};
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::sketch::bind::Binding;

const LOG_FINAL_POLY_LEN: usize = 6;
/// Key limb width: the 64-bit key is four exact 16-bit limbs (injective, and
/// each limb is `< p`).
pub const KEY_LIMB_BITS: usize = 16;
/// `act` sits at bit 16 of the fourth record coefficient.
const ACT_SHIFT: u64 = 1u64 << KEY_LIMB_BITS;
/// Aligned width for the sorted-address and gap range checks. `M ≤ 2^23`.
const ADDR_RANGE_BITS: usize = 24;
/// Poseidon2 digest limbs available for positions.
pub const MAX_K: usize = 8;
/// Number of base values surfaced by the Expose op: `(init, final, batch)`.
pub const EXPOSED_LEN: usize = 3 * 8;

/// Tamper modes (test-only fault injection; see the injection sites).
const TAMPER_NONE: u8 = 0;
/// (a) Suppression: at a touched cell whose old bit is 0 and whose batch OR is
/// 1, claim `O = 1` (so `N = 1`) but commit the final bit as 0 (`ft = 0`).
const TAMPER_SUPPRESS: u8 = 1;
/// (b) Wrong final bit at an UNTOUCHED cell (flip it, `ft = 0`).
const TAMPER_WRONG_FINAL_UNTOUCHED: u8 = 2;
/// (b') Clear a touched cell's final bit while keeping `ft = 1`.
const TAMPER_WRONG_FINAL_TOUCHED: u8 = 3;
/// (c) Non-canonical split `x + p` of one position limb (see
/// [`tests::noncanonical_position_rejected`]); the target is set with
/// [`TAMPER_NONCANON_TARGET`].
const TAMPER_NONCANON: u8 = 4;

thread_local! {
    static TAMPER: std::cell::Cell<u8> = const { std::cell::Cell::new(TAMPER_NONE) };
    /// `(record, slice)` whose digest limb gets the non-canonical split.
    static TAMPER_NONCANON_TARGET: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
    /// Build-time switch (tests only): omit the canonicity constraints
    /// (`hi ≤ HI_MAX` and the `hi = HI_MAX ⇒ pos = 0` edge) to show they are
    /// what stops the non-canonical misrouting.
    static DISABLE_CANON_CHECK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn p_u64() -> u64 {
    <Val as PrimeField64>::ORDER_U64
}

// ─── Parameters ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BloomOmcParams {
    /// Number of slices = hash positions per key (`1..=8`).
    pub k: usize,
    /// Bits per slice `W = 2^log_w` (`7..=20`).
    pub log_w: usize,
    /// Record slots per epoch; shorter batches are padded with canonical dummies.
    pub batch: usize,
}

impl BloomOmcParams {
    pub fn w(&self) -> usize {
        1usize << self.log_w
    }
    /// Total cells `M = k·W`.
    pub fn m_cells(&self) -> usize {
        self.k * self.w()
    }
    /// `(address, bit)` pairs per epoch, `L = k·batch`.
    pub fn pairs(&self) -> usize {
        self.k * self.batch
    }
    pub fn validate(&self) {
        if let Err(e) = self.check() {
            panic!("{e}");
        }
    }
    /// [`Self::validate`] without the panic: the reason a shape is rejected,
    /// for callers that report bad configuration instead of aborting.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=MAX_K).contains(&self.k) {
            return Err(format!("k must be in 1..={MAX_K}, got {}", self.k));
        }
        // log_w ≥ 7 keeps HI_MAX < 2^24 (aligned 24-bit check); log_w ≤ 20
        // keeps M ≤ 2^23 < 2^ADDR_RANGE_BITS.
        if !(7..=20).contains(&self.log_w) {
            return Err(format!("log_w must be in 7..=20, got {}", self.log_w));
        }
        if self.batch < 1 {
            return Err("batch must be ≥ 1".into());
        }
        if !self.m_cells().is_multiple_of(4) {
            return Err(format!("M = k·2^log_w = {} must be a multiple of 4", self.m_cells()));
        }
        if self.m_cells() >= (1usize << ADDR_RANGE_BITS) {
            return Err(format!(
                "M = k·2^log_w = {} must be below 2^{ADDR_RANGE_BITS}",
                self.m_cells()
            ));
        }
        Ok(())
    }
}

/// `HI_MAX = (p−1) / 2^log_w` — the largest high part of a canonical limb.
fn hi_max(log_w: usize) -> u64 {
    let pm1 = p_u64() - 1;
    assert_eq!(pm1 % (1u64 << log_w), 0, "p−1 must be divisible by 2^log_w");
    pm1 >> log_w
}

/// Byte-aligned width that holds `HI_MAX`.
fn hi_bits_aligned(log_w: usize) -> usize {
    let bl = 64 - hi_max(log_w).leading_zeros() as usize;
    bl.div_ceil(8) * 8
}

// ─── Native model ────────────────────────────────────────────────────────

/// The record's hash input: `[k0, k1, k2, k3 + 2^16·act]` (16-bit limbs of the
/// key, little-endian). `None` is the canonical dummy `[0, 0, 0, 0]`.
pub fn record_vals(key: Option<u64>) -> [Val; 4] {
    match key {
        None => [Val::ZERO; 4],
        Some(k) => {
            let l = |i: usize| (k >> (KEY_LIMB_BITS * i)) & 0xFFFF;
            [
                Val::from_u64(l(0)),
                Val::from_u64(l(1)),
                Val::from_u64(l(2)),
                Val::from_u64(l(3) + ACT_SHIFT),
            ]
        }
    }
}

/// Poseidon2 digest of a record (`MyHash` over the 4 record values).
pub fn record_digest(key: Option<u64>) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    hasher.hash_iter(record_vals(key))
}

/// Per-slice positions `pos_j = digest[j] mod W`, `j < k`.
pub fn bloom_positions(k: usize, log_w: usize, key: u64) -> Vec<usize> {
    let d = record_digest(Some(key));
    (0..k)
        .map(|j| (d[j].as_canonical_u64() % (1u64 << log_w)) as usize)
        .collect()
}

/// Global cell addresses `j·W + pos_j`.
pub fn bloom_addresses(k: usize, log_w: usize, key: u64) -> Vec<usize> {
    bloom_positions(k, log_w, key)
        .into_iter()
        .enumerate()
        .map(|(j, p)| (j << log_w) + p)
        .collect()
}

/// Empty filter (`M` zero bits).
pub fn bloom_empty(params: &BloomOmcParams) -> Vec<u8> {
    vec![0u8; params.m_cells()]
}

/// Native insert of a batch — exactly the update the leaf proves.
pub fn bloom_insert(bits: &mut [u8], params: &BloomOmcParams, keys: &[u64]) {
    assert_eq!(bits.len(), params.m_cells());
    for &key in keys {
        for a in bloom_addresses(params.k, params.log_w, key) {
            bits[a] = 1;
        }
    }
}

/// Native membership query (AND of the `k` bits).
pub fn bloom_contains(bits: &[u8], params: &BloomOmcParams, key: u64) -> bool {
    bloom_addresses(params.k, params.log_w, key)
        .into_iter()
        .all(|a| bits[a] == 1)
}

/// `Com(S)`: `MyHash` over the `M` bits as field elements (the leaf absorbs the
/// same values 4-per-Challenge in-circuit; `M` is a multiple of 4).
pub fn commit_bloom(bits: &[u8]) -> [Val; 8] {
    assert!(bits.len().is_multiple_of(4));
    let hasher = MyHash::new(make_perm());
    hasher.hash_iter(bits.iter().map(|&b| Val::from_u8(b)))
}

/// [`commit_bloom`] under `mode` (revision B2): `Plain` is exactly
/// [`commit_bloom`] (`salt` ignored); `Hiding` is
/// `MyHash([TAG_STATE, Bloom, 0, 0, ρ] ‖ bits)`, the value a hiding leaf
/// exposes for `Com(S; ρ)` and a hiding membership query opens.
pub fn commit_bloom_with(bits: &[u8], mode: CommitMode, salt: &SaltBb) -> [Val; 8] {
    match mode {
        CommitMode::Plain => commit_bloom(bits),
        CommitMode::Hiding => {
            assert!(bits.len().is_multiple_of(4));
            let flat: Vec<Val> = bits.iter().map(|&b| Val::from_u8(b)).collect();
            hiding::commit_flat_bb(mode, CommitKind::State, CommitFamily::Bloom, salt, &flat)
        }
    }
}

/// [`bloom_batch_commit`] under `mode` (revision B2): `Plain` is exactly
/// [`bloom_batch_commit`]; `Hiding` is
/// `MyHash([TAG_BATCH, Bloom, 0, 0, ρ] ‖ records)` over the same `batch`
/// padded record slots, the `Com(B_t; ρ^B_t)` a hiding leaf binds and the
/// prover publishes in the batch log.
pub fn bloom_batch_commit_with(
    batch: usize,
    keys: &[u64],
    mode: CommitMode,
    salt: &SaltBb,
) -> [Val; 8] {
    match mode {
        CommitMode::Plain => bloom_batch_commit(batch, keys),
        CommitMode::Hiding => {
            let flat: Vec<Val> = padded_slots(batch, keys).into_iter().flat_map(record_vals).collect();
            hiding::commit_flat_bb(mode, CommitKind::Batch, CommitFamily::Bloom, salt, &flat)
        }
    }
}

/// Batch commitment over the padded record sequence (`4·batch` values).
pub fn commit_bloom_batch(params: &BloomOmcParams, keys: &[u64]) -> [Val; 8] {
    bloom_batch_commit(params.batch, keys)
}

/// [`commit_bloom_batch`] from the slot count alone: `Com(B)` depends on the
/// `batch` record slots (`keys` then canonical dummies), not on the filter
/// shape `(k, log_w)`. What a public batch log lists for the leaf.
pub fn bloom_batch_commit(batch: usize, keys: &[u64]) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    let flat: Vec<Val> = padded_slots(batch, keys)
        .into_iter()
        .flat_map(record_vals)
        .collect();
    hasher.hash_iter(flat)
}

fn padded_records(params: &BloomOmcParams, keys: &[u64]) -> Vec<Option<u64>> {
    padded_slots(params.batch, keys)
}

fn padded_slots(batch: usize, keys: &[u64]) -> Vec<Option<u64>> {
    assert!(
        keys.len() <= batch,
        "{} keys exceed batch {}",
        keys.len(),
        batch
    );
    let mut recs: Vec<Option<u64>> = keys.iter().map(|&k| Some(k)).collect();
    recs.resize(batch, None);
    recs
}

/// Standard FPR estimate `(1 − e^{−n/W})^k` for a partitioned filter.
pub fn fpr_estimate(params: &BloomOmcParams, n: usize) -> f64 {
    let w = params.w() as f64;
    (1.0 - (-(n as f64) / w).exp()).powi(params.k as i32)
}

/// Canonical split of a canonical limb `x < p`: `(pos, hi, dinv)` with
/// `x = pos + 2^log_w·hi` and `dinv = (HI_MAX − hi)^{-1}` (0 if `hi = HI_MAX`).
fn canonical_split(x: u64, log_w: usize) -> (u64, u64, Val) {
    debug_assert!(x < p_u64());
    let pos = x & ((1u64 << log_w) - 1);
    let hi = x >> log_w;
    let d = hi_max(log_w) - hi;
    let dinv = Val::from_u64(d).try_inverse().unwrap_or(Val::ZERO);
    (pos, hi, dinv)
}

// ─── Exposed commitments ─────────────────────────────────────────────────

/// Read `(init, final, batch)` from the proof's Expose table — what an
/// outside verifier checks against the claimed commitments. Standalone
/// ([`Expose::None`]) leaves only; a composable leaf's statement is read with
/// [`crate::recursion::recursive::expose_forest::read_exposed_statement`].
pub fn read_exposed_commitments(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> ([Val; 8], [Val; 8], [Val; 8]) {
    let pv = proof
        .non_primitives
        .iter()
        .map(|e| &e.public_values)
        .find(|v| v.len() == EXPOSED_LEN)
        .expect("bloom leaf proof must expose (init, final, batch)");
    let take = |o: usize| -> [Val; 8] { std::array::from_fn(|i| pv[o + i]) };
    (take(0), take(8), take(16))
}

// ─── Proof / circuit types ───────────────────────────────────────────────

/// A self-verified Bloom `omc` leaf proof. The commitments are the natively
/// computed ones; tests check them against [`read_exposed_commitments`].
pub struct BloomOmcProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: CountMinCommit,
    pub final_commit: CountMinCommit,
    pub batch_commit: CountMinCommit,
    pub final_bits: Vec<u8>,
    pub params: BloomOmcParams,
}

impl BloomOmcProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

/// Where a (tampered) epoch was rejected.
#[derive(Debug)]
pub enum BloomProveError {
    /// Circuit execution (witness generation) found an unsatisfied constraint.
    Run(String),
    /// Trace → proof failed.
    Prove(String),
    /// The self-verifier rejected the proof.
    Verify(String),
}

/// Private-input wires of the leaf (allocation order = value push order).
struct Wires {
    o: Vec<ExprId>,
    n: Vec<ExprId>,
    ft: Vec<ExprId>,
    /// Per record `[k0, k1, k2, k3, act]`.
    rec: Vec<[ExprId; 5]>,
    /// Per record: `[pos, hi, dinv]` per position limb, then one pin per
    /// unused limb (see [`record_route_gadget`]).
    split: Vec<Vec<ExprId>>,
    as_: Vec<ExprId>,
    vs: Vec<ExprId>,
    eq_tag: Vec<ExprId>,
    inv_diff: Vec<ExprId>,
    op_old: Vec<ExprId>,
}

/// A built, reusable Bloom `omc` leaf. Build once per shape; each
/// [`Self::prove_epoch`] swaps in the two per-batch permutations.
pub struct BloomOmcLeafCircuit {
    params: BloomOmcParams,
    expose: Expose,
    /// Commitment mode the circuit was built with (revision B2).
    mode: CommitMode,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    table_rows: Vec<usize>,
}

// ─── In-circuit gadgets ──────────────────────────────────────────────────

/// Exact `x ∈ [0, 2^n)` (`1 ≤ n ≤ 24`) from byte-aligned `add_range_bits`
/// only: `x ∈ [0, 2^{n8})` and `x + (2^{n8} − 2^n) ∈ [0, 2^{n8})`, `n8 =
/// 8⌈n/8⌉`. Both are exact byte-table checks, the sum cannot wrap (`< 2^25 ≪
/// p`), so `x < 2^n`. Also pins `x` to the base field.
pub(crate) fn range_exact(b: &mut CircuitBuilder<Challenge>, x: ExprId, n: usize) {
    assert!((1..=24).contains(&n));
    let n8 = n.div_ceil(8) * 8;
    b.add_range_bits::<Val>(x, n8).expect("range_exact aligned");
    if n8 != n {
        let off = b.alloc_const(
            Challenge::from_u64((1u64 << n8) - (1u64 << n)),
            "range_exact_off",
        );
        let y = b.add(x, off);
        b.add_range_bits::<Val>(y, n8).expect("range_exact shifted");
    }
}

/// Sponge hash equal to `add_hash_slice(cfg, inputs, true)` and to the native
/// `MyHash` (`PaddingFreeSponge`, zero IV, overwrite mode), except that EVERY
/// input limb of the first (`new_start`) permutation row is CTL-bound: rate
/// limbs the first chunk does not fill and both capacity limbs are fed the zero
/// constant. In the pinned fork's D = 4 (non-compact) Poseidon2 layout a
/// `new_start` row places no constraint on input limbs without a CTL (the
/// zero-capacity assertion exists only for the compact D = 1 layout), so with
/// plain `add_hash_slice` the IV is prover-chosen: a single-block digest can be
/// ground for favourable positions (see
/// [`tests::poc_poseidon_d4_free_capacity`]). Later chunks are unchanged
/// (missing rate limbs and the capacity chain from the previous row).
pub(crate) fn hash_slice_bound(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    inputs: &[ExprId],
    zero: ExprId,
) -> Vec<ExprId> {
    assert!(!inputs.is_empty());
    let width_ext = cfg.width_ext();
    let rate_ext = cfg.rate_ext();
    let chunks: Vec<&[ExprId]> = inputs.chunks(rate_ext).collect();
    let last = chunks.len() - 1;
    let mut outputs: Vec<Option<ExprId>> = Vec::new();
    for (i, ch) in chunks.iter().enumerate() {
        let first = i == 0;
        let call_inputs: Vec<Option<ExprId>> = (0..width_ext)
            .map(|j| {
                if j < ch.len() {
                    Some(ch[j])
                } else if first {
                    Some(zero)
                } else {
                    None
                }
            })
            .collect();
        let (_, outs) = b
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: *cfg,
                new_start: first,
                merkle_path: false,
                mmcs_bit: None,
                inputs: call_inputs,
                out_ctl: vec![i == last; rate_ext],
                return_all_outputs: false,
                mmcs_index_sum: None,
            })
            .expect("poseidon2 perm");
        outputs = outs;
    }
    outputs
        .into_iter()
        .take(rate_ext)
        .map(|o| o.expect("rate output"))
        .collect()
}

/// An in-circuit commitment with this leaf's bound sponge: exactly
/// [`hash_slice_bound`]`(inputs)` without a salt (the `Plain` gadget, op for
/// op), and `hash_slice_bound([tag, salt_0, salt_1, salt_2, inputs…])` with
/// one ([`hiding::salted_hash_inputs`], family [`CommitFamily::Bloom`]), the
/// in-circuit image of [`hiding::commit_flat_bb`].
pub(crate) fn commit_hash_bound(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    kind: CommitKind,
    salt: Option<&SaltTargets>,
    inputs: &[ExprId],
    zero: ExprId,
) -> Vec<ExprId> {
    match salt {
        None => hash_slice_bound(b, cfg, inputs, zero),
        Some(st) => {
            let salted =
                hiding::salted_hash_inputs::<Val, Challenge>(b, kind, CommitFamily::Bloom, st, inputs);
            hash_slice_bound(b, cfg, &salted, zero)
        }
    }
}

/// Constants shared by the gadgets.
pub(crate) struct Consts {
    pub(crate) one: ExprId,
    pub(crate) zero: ExprId,
    pub(crate) two: ExprId,
    act_shift: ExprId,
    pow_log_w: ExprId,
    hi_max: ExprId,
    /// Slice offsets `j·W`, `j < k` (index 0 unused).
    pub(crate) slice_off: Vec<ExprId>,
    e1: ExprId,
    e2: ExprId,
    e3: ExprId,
}

impl Consts {
    pub(crate) fn new(b: &mut CircuitBuilder<Challenge>, k: usize, log_w: usize) -> Self {
        let basis = |i: usize| -> Challenge {
            let mut c = [Val::ZERO; 4];
            c[i] = Val::ONE;
            Challenge::from_basis_coefficients_slice(&c).unwrap()
        };
        Self {
            one: b.alloc_const(Challenge::ONE, "one"),
            zero: b.alloc_const(Challenge::ZERO, "zero"),
            two: b.alloc_const(Challenge::from_u64(2), "two"),
            act_shift: b.alloc_const(Challenge::from_u64(ACT_SHIFT), "2^16"),
            pow_log_w: b.alloc_const(Challenge::from_u64(1u64 << log_w), "2^log_w"),
            hi_max: b.alloc_const(Challenge::from_u64(hi_max(log_w)), "hi_max"),
            slice_off: (0..k)
                .map(|j| b.alloc_const(Challenge::from_u64((j << log_w) as u64), "j*W"))
                .collect(),
            e1: b.alloc_const(basis(1), "e1"),
            e2: b.alloc_const(basis(2), "e2"),
            e3: b.alloc_const(basis(3), "e3"),
        }
    }
}

/// Number of private split witnesses per record (`3` per position limb, `1`
/// per unused limb) — the layout [`record_route_gadget`] consumes.
pub(crate) fn split_witness_count(k: usize) -> usize {
    3 * k + (MAX_K - k)
}

/// Native values of the split witnesses of one record, in the order
/// [`record_route_gadget`] consumes them.
pub(crate) fn split_witness_values(k: usize, log_w: usize, key: Option<u64>) -> Vec<Val> {
    let d = record_digest(key);
    let mut out = Vec::with_capacity(split_witness_count(k));
    for (t, &limb) in d.iter().enumerate() {
        if t < k {
            let (pos, hi, dinv) = canonical_split(limb.as_canonical_u64(), log_w);
            out.extend([Val::from_u64(pos), Val::from_u64(hi), dinv]);
        } else {
            out.push(limb);
        }
    }
    out
}

/// In-circuit record routing shared by the update leaf and the membership
/// query: range-check the four 16-bit key limbs, build the record Challenge
/// `[k0, k1, k2, k3 + 2^16·act]` (ALU), hash it with the bound sponge, and bind
/// the 8 digest limbs to base-pinned split witnesses through ALU
/// recomposition. `split` is `split_witness_count(k)` private inputs:
/// `[pos, hi, dinv]` for each limb `t < k`, then one pin witness per unused
/// limb. Returns `(record, [pos_j]_{j<k})`; `act` must already be boolean.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_route_gadget(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    c: &Consts,
    k: usize,
    log_w: usize,
    limbs: [ExprId; 4],
    act: ExprId,
    split: &[ExprId],
    canon: bool,
) -> (ExprId, Vec<ExprId>) {
    assert_eq!(split.len(), split_witness_count(k));
    let [k0, k1, k2, k3] = limbs;
    for &kk in &limbs {
        range_exact(b, kk, KEY_LIMB_BITS);
    }
    let l3 = b.mul_add(act, c.act_shift, k3);
    let rec = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&[k0, k1, k2, l3])
        .expect("record");
    let h = hash_slice_bound(b, cfg, &[rec], c.zero);
    let mut digest_limbs: Vec<ExprId> = Vec::with_capacity(MAX_K);
    let mut pos_of: Vec<ExprId> = Vec::with_capacity(k);
    let mut it = split.iter().copied();
    for t in 0..MAX_K {
        if t < k {
            let (pos, hi, dinv) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
            digest_limbs.push(canonical_split_gadget(b, pos, hi, dinv, log_w, c, canon));
            pos_of.push(pos);
        } else {
            // Unused limb: only needs to be base-field so the recomposition
            // below is unique (a free extension element here would absorb
            // any change to the other three coefficients).
            let u = it.next().unwrap();
            b.add_range_bits::<Val>(u, Val::bits())
                .expect("pin unused limb");
            digest_limbs.push(u);
        }
    }
    let h0 = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&digest_limbs[0..4])
        .expect("recompose digest lo");
    let h1 = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&digest_limbs[4..8])
        .expect("recompose digest hi");
    b.connect(h0, h[0]);
    b.connect(h1, h[1]);
    (rec, pos_of)
}

/// Pack bit cells 4-per-Challenge through the ALU (cells must be base-pinned,
/// e.g. by `assert_bool`), matching [`commit_bloom`]'s absorption order.
pub(crate) fn pack_cells(b: &mut CircuitBuilder<Challenge>, cells: &[ExprId]) -> Vec<ExprId> {
    cells
        .chunks(4)
        .map(|ch| {
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(ch)
                .expect("pack 4 cells")
        })
        .collect()
}

/// Canonical split: returns `x = pos + 2^log_w·hi` (an ALU output) after
/// constraining `pos ∈ [0, 2^log_w)`, `hi ∈ [0, 2^hi_w)` and — unless the test
/// switch disables it — `hi ≤ HI_MAX` and `hi = HI_MAX ⇒ pos = 0`, i.e. the
/// split integer is `≤ p − 1` (canonical).
fn canonical_split_gadget(
    b: &mut CircuitBuilder<Challenge>,
    pos: ExprId,
    hi: ExprId,
    dinv: ExprId,
    log_w: usize,
    c: &Consts,
    canon: bool,
) -> ExprId {
    range_exact(b, pos, log_w);
    let hi_w = hi_bits_aligned(log_w);
    b.add_range_bits::<Val>(hi, hi_w).expect("hi range");
    if canon {
        // d = HI_MAX − hi ∈ [0, 2^hi_w) ⇒ hi ≤ HI_MAX (no wrap: both < 2^24).
        let d = b.sub(c.hi_max, hi);
        b.add_range_bits::<Val>(d, hi_w).expect("hi <= HI_MAX");
        // Edge: d = 0 ⇒ z = 1 ⇒ pos = 0. (For d ≠ 0 the honest dinv makes z = 0.)
        let e = b.mul(d, dinv);
        let z = b.sub(c.one, e);
        let chk = b.mul(pos, z);
        b.connect(chk, c.zero);
    } else {
        // Keep `dinv` an ALU operand so the private input is still consumed.
        let _ = b.mul(dinv, dinv);
    }
    b.mul_add(hi, c.pow_log_w, pos)
}

// ─── Build ───────────────────────────────────────────────────────────────

/// Build the reusable Bloom `omc` leaf circuit for a shape (the standalone
/// leaf exposing `(init, final, batch)`).
pub fn build_bloom_omc_leaf(params: BloomOmcParams) -> BloomOmcLeafCircuit {
    build_bloom_omc_leaf_expose(params, Expose::None)
}

/// Build the reusable Bloom `omc` leaf with an explicit statement layout:
///
/// * [`Expose::None`]: the standalone leaf, op for op [`build_bloom_omc_leaf`]
///   — `(init, final, batch)`, 24 values, not composable;
/// * [`Expose::Boundary`]: `(init, final)`, 16 values (the pre-B6(b)
///   composition statement);
/// * [`Expose::Interval`]: adds the batch index `t` (the 7th, last public
///   input, pinned to the base field as the other leaves pin it,
///   [`IndexPin::Range`]) and exposes `(init, final, (t, t, 0, 0), H)` with
///   `H = Poseidon2(TAG_LEAF, t, Com(B_t))` over the in-circuit batch digest,
///   28 values ([`statement::expose_leaf_interval`], bound sponge).
///
/// The update relation is identical in all three; only the exposed statement
/// (and, for `Interval`, the index pin and one more digest) differ. Prove
/// batch `t` with [`BloomOmcLeafCircuit::prove_epoch_at`]. The `Plain`
/// commitments: [`build_bloom_omc_leaf_commit`] with [`CommitMode::Plain`].
pub fn build_bloom_omc_leaf_expose(params: BloomOmcParams, expose: Expose) -> BloomOmcLeafCircuit {
    build_bloom_omc_leaf_commit(params, expose, CommitMode::Plain)
}

/// [`build_bloom_omc_leaf_expose`] under the commitment mode `mode`
/// (revision B2, module doc "Hiding commitments"). `Plain` is the pre-B2
/// circuit op for op (same VK). `Hiding` allocates the three salts (init,
/// final, batch) as the first private inputs and absorbs them, behind the
/// kind/family tag, into `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)`; prove it
/// with [`BloomOmcLeafCircuit::prove_epoch_commit`].
pub fn build_bloom_omc_leaf_commit(
    params: BloomOmcParams,
    expose: Expose,
    mode: CommitMode,
) -> BloomOmcLeafCircuit {
    params.validate();
    let BloomOmcParams { k, log_w, batch } = params;
    let m = params.m_cells();
    let l = params.pairs();
    let canon = !DISABLE_CANON_CHECK.with(|f| f.get());

    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    b.enable_expose(generate_expose_trace::<Val, Challenge>);

    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));
    match expose {
        Expose::None => {
            b.add_expose(&[
                init_pis[0],
                init_pis[1],
                final_pis[0],
                final_pis[1],
                batch_pis[0],
                batch_pis[1],
            ])
            .expect("expose (init, final, batch)");
        }
        Expose::Boundary => {
            b.add_expose(&[init_pis[0], init_pis[1], final_pis[0], final_pis[1]])
                .expect("expose (init, final)");
        }
        // After the in-circuit batch digest (Stage B).
        Expose::Interval => {}
    }

    let consts = Consts::new(&mut b, k, log_w);
    let c = &consts;
    // (a, 0, 0, 1) per cell — the address + tag coordinates of every
    // init-write / final-read element.
    let cell_base: Vec<ExprId> = (0..m)
        .map(|a| {
            let v = Challenge::from_basis_coefficients_slice(&[
                Val::from_u64(a as u64),
                Val::ZERO,
                Val::ZERO,
                Val::ONE,
            ])
            .unwrap();
            b.alloc_const(v, "cell_base")
        })
        .collect();

    // ── Private inputs (allocation order == push order in prove_epoch) ──
    // B2: under `Hiding` the 9 salt inputs (init, final, batch) come first;
    // `Plain` allocates nothing.
    let salts = hiding::alloc_leaf_salts(&mut b, mode);
    let wires = Wires {
        o: (0..m).map(|_| b.alloc_private_input("o")).collect(),
        n: (0..m).map(|_| b.alloc_private_input("n")).collect(),
        ft: (0..m).map(|_| b.alloc_private_input("ft")).collect(),
        rec: (0..batch)
            .map(|_| std::array::from_fn(|_| b.alloc_private_input("rec")))
            .collect(),
        split: (0..batch)
            .map(|_| {
                (0..split_witness_count(k))
                    .map(|_| b.alloc_private_input("split"))
                    .collect()
            })
            .collect(),
        as_: (0..l).map(|_| b.alloc_private_input("as")).collect(),
        vs: (0..l).map(|_| b.alloc_private_input("vs")).collect(),
        eq_tag: (0..l.saturating_sub(1))
            .map(|_| b.alloc_private_input("eq_tag"))
            .collect(),
        inv_diff: (0..l.saturating_sub(1))
            .map(|_| b.alloc_private_input("inv_diff"))
            .collect(),
        op_old: (0..l).map(|_| b.alloc_private_input("op_old")).collect(),
    };

    // ── Stage A: both states are bits (pins base field) and hash to the commits ──
    for a in 0..m {
        b.assert_bool(wires.o[a]);
        b.assert_bool(wires.n[a]);
        b.assert_bool(wires.ft[a]);
    }
    let init_packed = pack_cells(&mut b, &wires.o);
    let final_packed = pack_cells(&mut b, &wires.n);
    let dig_init = commit_hash_bound(
        &mut b,
        &cfg,
        CommitKind::State,
        salts.as_ref().map(|s| &s.init),
        &init_packed,
        c.zero,
    );
    let dig_final = commit_hash_bound(
        &mut b,
        &cfg,
        CommitKind::State,
        salts.as_ref().map(|s| &s.final_),
        &final_packed,
        c.zero,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(dig_init[i], init_pis[i]);
        b.connect(dig_final[i], final_pis[i]);
    }

    // ── Stage B: records → batch commitment; digest → canonical positions ──
    let mut recs: Vec<ExprId> = Vec::with_capacity(batch);
    let mut payload: Vec<ExprId> = Vec::with_capacity(l);
    for r in 0..batch {
        let [k0, k1, k2, k3, act] = wires.rec[r];
        b.assert_bool(act);
        let (rec, pos_of) = record_route_gadget(
            &mut b,
            &cfg,
            c,
            k,
            log_w,
            [k0, k1, k2, k3],
            act,
            &wires.split[r],
            canon,
        );
        // Dummy canonical: act = 0 ⇒ k0+k1+k2+k3 = 0 ⇒ all limbs 0 (each < 2^16).
        let s01 = b.add(k0, k1);
        let s012 = b.add(s01, k2);
        let s = b.add(s012, k3);
        let oma = b.sub(c.one, act);
        let dchk = b.mul(oma, s);
        b.connect(dchk, c.zero);
        recs.push(rec);

        // (address, bit) pairs: a = j·W + pos_j, bit = act; payload = 2a + act.
        for (j, &pos) in pos_of.iter().enumerate() {
            let a = if j == 0 {
                pos
            } else {
                b.add(pos, c.slice_off[j])
            };
            payload.push(b.mul_add(a, c.two, act));
        }
    }
    let hb = commit_hash_bound(
        &mut b,
        &cfg,
        CommitKind::Batch,
        salts.as_ref().map(|s| &s.batch),
        &recs,
        c.zero,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (7th public input) and
    // H = Poseidon2(TAG_LEAF, t, hb), exposed with the boundary. `Bound` keeps
    // this leaf's zero-IV sponge discipline for H too.
    if expose.is_interval() {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &cfg,
            &init_pis,
            &final_pis,
            &hb,
            c.zero,
            Binding::Bound,
            IndexPin::Range,
        );
    }

    // ── Stage C: sort pairs by address (placeholder σ, swapped per epoch) ──
    let payload_sorted = b
        .add_permute(&payload, (0..l).collect::<Vec<_>>())
        .expect("permute sort");
    for r in 0..l {
        b.assert_bool(wires.vs[r]);
        let rec = b.mul_add(wires.as_[r], c.two, wires.vs[r]);
        b.connect(rec, payload_sorted[r]);
    }
    // as[0] ∈ [0, 2^24) and every gap ∈ [0, 2^24): all rows decode without a
    // half-offset and addresses are non-decreasing (equal addresses contiguous).
    b.add_range_bits::<Val>(wires.as_[0], ADDR_RANGE_BITS)
        .expect("first address range");
    let mut acc: Vec<ExprId> = Vec::with_capacity(l);
    acc.push(wires.vs[0]);
    for r in 1..l {
        let gap = b.sub(wires.as_[r], wires.as_[r - 1]);
        b.add_range_bits::<Val>(gap, ADDR_RANGE_BITS)
            .expect("gap range");
        // eq_tag[r] == [as[r] == as[r-1]] (exact: two constraints with inverse).
        let tag = wires.eq_tag[r - 1];
        let diff = b.sub(wires.as_[r - 1], wires.as_[r]);
        let l1 = b.mul(tag, diff);
        b.connect(l1, c.zero);
        let omt = b.sub(c.one, tag);
        let di = b.mul(diff, wires.inv_diff[r - 1]);
        let omdi = b.sub(c.one, di);
        let l2 = b.mul(omt, omdi);
        b.connect(l2, c.zero);
        // Running OR: acc[r] = carried ∨ vs[r], carried = tag·acc[r-1].
        let carried = b.mul(tag, acc[r - 1]);
        let omc = b.sub(c.one, carried);
        let t = b.mul(wires.vs[r], omc);
        acc.push(b.add(carried, t));
    }

    // ── Stage D: timestamped offline-memory-checking rebind ──
    let mut input: Vec<ExprId> = Vec::with_capacity(m + l);
    let mut target: Vec<ExprId> = Vec::with_capacity(m + l);
    for a in 0..m {
        // init write (a, o, 0) ; final read (a, n, ft)
        input.push(b.mul_add(wires.o[a], c.e1, cell_base[a]));
        let fr = b.mul_add(wires.n[a], c.e1, cell_base[a]);
        target.push(b.mul_add(wires.ft[a], c.e2, fr));
    }
    for r in 0..l {
        let active = if r == l - 1 {
            c.one
        } else {
            b.sub(c.one, wires.eq_tag[r])
        };
        b.assert_bool(wires.op_old[r]);
        // N = O ∨ A.
        let om = b.sub(c.one, wires.op_old[r]);
        let t = b.mul(acc[r], om);
        let op_new = b.add(wires.op_old[r], t);
        // (as, ·, ·, 1) — as is base (range-checked first row + gaps).
        let base = b.add(wires.as_[r], c.e3);
        let wr = b.mul_add(op_new, c.e1, base);
        let wr1 = b.add(wr, c.e2);
        input.push(b.mul(active, wr1)); // update write (as, N, 1)
        let rd = b.mul_add(wires.op_old[r], c.e1, base);
        target.push(b.mul(active, rd)); // update read (as, O, 0)
    }
    let permuted = b
        .add_permute(&input, (0..m + l).collect::<Vec<_>>())
        .expect("permute mset");
    for i in 0..m + l {
        b.connect(permuted[i], target[i]);
    }

    let circuit = b.build().expect("build bloom_omc circuit");

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
        permute_preprocessor::<Val>(),
        range_preprocessor::<Val>(),
        expose_preprocessor::<Val>(),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (bloom_omc)");
    // E-0 table probe (read-only; a no-op unless armed).
    crate::experiments::table_probe::record_leaf(
        "bloom_omc",
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
    prover.register_expose_table::<4>();
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();
    let table_rows: Vec<usize> = ext_degrees.iter().map(|&d| 1usize << d).collect();

    BloomOmcLeafCircuit {
        params,
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

// ─── Native epoch witness ────────────────────────────────────────────────

struct EpochWitness {
    recs: Vec<Option<u64>>,
    /// Per record, per limb: the split values pushed as private inputs.
    split_vals: Vec<Vec<Vec<Val>>>,
    as_sorted: Vec<u64>,
    vs_sorted: Vec<u8>,
    eq_tag: Vec<u8>,
    inv_diff: Vec<Val>,
    op_old: Vec<u8>,
    final_bits: Vec<u8>,
    ft: Vec<u8>,
    sigma_sort: Vec<usize>,
    sigma_mset: Vec<usize>,
}

fn epoch_witness(params: &BloomOmcParams, initial: &[u8], keys: &[u64]) -> EpochWitness {
    let BloomOmcParams { k, log_w, .. } = *params;
    let m = params.m_cells();
    let l = params.pairs();
    let w = params.w() as u64;
    let tamper = TAMPER.with(|t| t.get());
    let recs = padded_records(params, keys);

    // Route every record; build the split witnesses.
    let mut split_vals: Vec<Vec<Vec<Val>>> = Vec::with_capacity(recs.len());
    let mut pairs: Vec<(u64, u8)> = Vec::with_capacity(l); // (address, bit), record-major
    for (r, rec) in recs.iter().enumerate() {
        let d = record_digest(*rec);
        let act = u8::from(rec.is_some());
        let mut sv: Vec<Vec<Val>> = Vec::with_capacity(MAX_K);
        for t in 0..MAX_K {
            let x = d[t].as_canonical_u64();
            if t < k {
                let (mut pos, mut hi, mut dinv) = canonical_split(x, log_w);
                if tamper == TAMPER_NONCANON && TAMPER_NONCANON_TARGET.with(|c| c.get()) == (r, t) {
                    // The alternate integer x + p (fits 31 bits iff x < 2^31 − p).
                    let xp = x + p_u64();
                    assert!(xp < (1u64 << 31), "tamper target limb must be < 2^31 − p");
                    pos = xp & ((1u64 << log_w) - 1);
                    hi = xp >> log_w;
                    // hi > HI_MAX here; any dinv (the honest-mode d range check fails first).
                    dinv = Val::ZERO;
                }
                sv.push(vec![Val::from_u64(pos), Val::from_u64(hi), dinv]);
                pairs.push((t as u64 * w + pos, act));
            } else {
                sv.push(vec![d[t]]);
            }
        }
        split_vals.push(sv);
    }

    // Sort by address (stable) — σ with payload_sorted[i] = payload[σ[i]].
    let mut order: Vec<usize> = (0..l).collect();
    order.sort_by_key(|&i| pairs[i].0);
    let sigma_sort = order.clone();
    let as_sorted: Vec<u64> = order.iter().map(|&i| pairs[i].0).collect();
    let vs_sorted: Vec<u8> = order.iter().map(|&i| pairs[i].1).collect();

    let mut eq_tag = vec![0u8; l]; // eq_tag[r] for r ≥ 1 (index 0 unused)
    let mut inv_diff = vec![Val::ZERO; l];
    for r in 1..l {
        if as_sorted[r] == as_sorted[r - 1] {
            eq_tag[r] = 1;
        } else {
            inv_diff[r] = (Val::from_u64(as_sorted[r - 1]) - Val::from_u64(as_sorted[r]))
                .try_inverse()
                .expect("nonzero diff");
        }
    }
    let mut acc = vec![0u8; l];
    acc[0] = vs_sorted[0];
    for r in 1..l {
        let carried = eq_tag[r] & acc[r - 1];
        acc[r] = carried | vs_sorted[r];
    }
    let active: Vec<bool> = (0..l).map(|r| r == l - 1 || eq_tag[r + 1] == 0).collect();
    let mut op_old: Vec<u8> = (0..l).map(|r| initial[as_sorted[r] as usize]).collect();
    let op_new = |op_old: &[u8], r: usize| op_old[r] | acc[r];

    let mut final_bits = initial.to_vec();
    let mut ft = vec![0u8; m];
    for r in 0..l {
        if active[r] {
            let a = as_sorted[r] as usize;
            final_bits[a] = op_new(&op_old, r);
            ft[a] = 1;
        }
    }

    // ── Test-only fault injection ──
    match tamper {
        TAMPER_SUPPRESS => {
            // A touched cell that the batch must SET (old 0, OR 1): claim it was
            // already 1 and leave the committed bit 0 as an "untouched" cell.
            let r = (0..l)
                .find(|&r| active[r] && op_old[r] == 0 && acc[r] == 1)
                .expect("suppression needs a cell the batch sets");
            let a = as_sorted[r] as usize;
            op_old[r] = 1; // ⇒ N = 1 ∨ 1 = 1, the max/OR degenerate pairing
            final_bits[a] = 0;
            ft[a] = 0;
        }
        TAMPER_WRONG_FINAL_UNTOUCHED => {
            let a = (0..m).find(|&a| ft[a] == 0).expect("an untouched cell");
            final_bits[a] ^= 1;
        }
        TAMPER_WRONG_FINAL_TOUCHED => {
            let r = (0..l)
                .find(|&r| active[r] && op_new(&op_old, r) == 1)
                .expect("a touched cell set to 1");
            final_bits[as_sorted[r] as usize] = 0; // ft stays 1
        }
        _ => {}
    }

    // Multiset elements (None = the zero dummy of an inactive row).
    type Elem = Option<(u64, u8, u8)>;
    let mut input: Vec<Elem> = Vec::with_capacity(m + l);
    let mut target: Vec<Elem> = Vec::with_capacity(m + l);
    for a in 0..m {
        input.push(Some((a as u64, initial[a], 0)));
        target.push(Some((a as u64, final_bits[a], ft[a])));
    }
    for r in 0..l {
        if active[r] {
            input.push(Some((as_sorted[r], op_new(&op_old, r), 1)));
            target.push(Some((as_sorted[r], op_old[r], 0)));
        } else {
            input.push(None);
            target.push(None);
        }
    }
    // σ with input[σ[i]] == target[i]; best effort so a tampered (unmatchable)
    // witness reaches the circuit and is rejected THERE, not by this helper.
    let mut buckets: HashMap<Elem, Vec<usize>> = HashMap::new();
    for (i, v) in input.iter().enumerate() {
        buckets.entry(*v).or_default().push(i);
    }
    let mut sigma_mset: Vec<Option<usize>> = target
        .iter()
        .map(|t| buckets.get_mut(t).and_then(|v| v.pop()))
        .collect();
    let mut leftovers: Vec<usize> = buckets.into_values().flatten().collect();
    let unmatched = sigma_mset.iter().filter(|s| s.is_none()).count();
    if tamper == TAMPER_NONE {
        assert_eq!(unmatched, 0, "honest multiset matching must exist");
    }
    for s in sigma_mset.iter_mut() {
        if s.is_none() {
            *s = leftovers.pop();
        }
    }
    let sigma_mset: Vec<usize> = sigma_mset.into_iter().map(|s| s.unwrap()).collect();

    EpochWitness {
        recs,
        split_vals,
        as_sorted,
        vs_sorted,
        eq_tag,
        inv_diff,
        op_old,
        final_bits,
        ft,
        sigma_sort,
        sigma_mset,
    }
}

impl BloomOmcLeafCircuit {
    pub fn params(&self) -> BloomOmcParams {
        self.params
    }
    /// `Σ 2^degree` over all tables (the per-leaf trace-row metric used by the
    /// other leaves' timing records).
    pub fn trace_rows(&self) -> u64 {
        self.trace_rows
    }
    /// Padded height of each table (same order as the AIR list).
    pub fn table_rows(&self) -> &[usize] {
        &self.table_rows
    }

    /// The statement this leaf exposes ([`Expose`]).
    pub fn expose(&self) -> Expose {
        self.expose
    }

    /// The commitment mode the circuit was built with.
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }

    /// Prove one epoch; panics if any stage rejects. (Batch index 1 under the
    /// Interval statement; see [`Self::prove_epoch_at`].) `Plain` circuits
    /// only, like [`Self::prove_epoch_at`].
    pub fn prove_epoch(&mut self, initial: &[u8], keys: &[u64]) -> BloomOmcProof {
        self.prove_epoch_at(1, initial, keys)
    }

    /// Prove the epoch of batch `t` (1-based); `t` is part of the Interval
    /// statement (ignored by the other layouts). Panics if any stage rejects.
    /// `Plain` circuits only: on a `Hiding` circuit this would open every
    /// commitment with the public zero salt, so it panics; use
    /// [`Self::prove_epoch_commit`] (or, for the no-op leaf,
    /// [`Self::prove_epoch_public_zero`]).
    pub fn prove_epoch_at(&mut self, t: u64, initial: &[u8], keys: &[u64]) -> BloomOmcProof {
        self.try_prove_epoch_at(t, initial, keys)
            .unwrap_or_else(|e| panic!("bloom_omc epoch rejected: {e:?}"))
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`Openings::for_leaf(seed, CommitFamily::Bloom, t)` for an honest
    /// prover; ignored by a `Plain` circuit). The proof's commitments are then
    /// `Com(S_{t-1}; ρ^S_{t-1})`, `Com(S_t; ρ^S_t)` and `Com(B_t; ρ^B_t)`. A
    /// `Hiding` circuit panics when `openings.final_` or `openings.batch` is
    /// the public zero salt (never an honest PRF output), and accepts a zero
    /// init salt only at `t = 1` on the empty genesis filter
    /// ([`hiding::assert_zero_init_opens_public_state`]).
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial: &[u8],
        keys: &[u64],
        openings: &Openings,
    ) -> BloomOmcProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (Openings::for_leaf), not the public zero salt"
            );
            hiding::assert_zero_init_opens_public_state(t, openings.init.is_zero(), || {
                initial.iter().all(|&x| x == 0)
            });
        }
        self.try_prove_epoch_opened(t, initial, keys, openings)
            .unwrap_or_else(|e| panic!("bloom_omc epoch rejected: {e:?}"))
    }

    /// The no-op VK-derivation leaf's epoch: all three commitments opened
    /// with [`Openings::public_zero`], so it exposes `init == final` in
    /// either mode. The only path that proves a `Hiding` leaf with zero
    /// final/batch salts, so it accepts exactly the public no-op input: batch
    /// index `t = 1`, the empty filter and no key (every record slot the
    /// canonical dummy). It publishes only `Com(0^M; 0)` and
    /// `Com(dummies; 0)`, commitments to public data.
    pub fn prove_epoch_public_zero(&mut self, t: u64, initial: &[u8], keys: &[u64]) -> BloomOmcProof {
        assert!(
            initial.iter().all(|&x| x == 0) && keys.is_empty(),
            "prove_epoch_public_zero is for the no-op leaf: the public no-op input only (the empty \
             filter and an all-dummy batch)"
        );
        assert_eq!(t, 1, "prove_epoch_public_zero is for the no-op leaf: it is proved at batch index 1");
        self.try_prove_epoch_opened(t, initial, keys, &Openings::public_zero())
            .unwrap_or_else(|e| panic!("bloom_omc epoch rejected: {e:?}"))
    }

    /// Prove one epoch from a committed `initial` bit array (`M` bits) and up
    /// to `batch` keys (padded with canonical dummies). Reports which stage
    /// rejected a (tampered) witness. `Plain` circuits only.
    pub fn try_prove_epoch(
        &mut self,
        initial: &[u8],
        keys: &[u64],
    ) -> Result<BloomOmcProof, BloomProveError> {
        self.try_prove_epoch_at(1, initial, keys)
    }

    /// [`Self::try_prove_epoch`] for batch `t` (1-based; Interval statement).
    /// `Plain` circuits only (see [`Self::prove_epoch_at`]).
    pub fn try_prove_epoch_at(
        &mut self,
        t: u64,
        initial: &[u8],
        keys: &[u64],
    ) -> Result<BloomOmcProof, BloomProveError> {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             Openings::for_leaf(..)"
        );
        self.try_prove_epoch_opened(t, initial, keys, &Openings::plain())
    }

    /// Shared body of the `prove_epoch_*` entry points (no opening checks):
    /// the commitments are opened with `openings` (ignored under `Plain`).
    fn try_prove_epoch_opened(
        &mut self,
        t: u64,
        initial: &[u8],
        keys: &[u64],
        openings: &Openings,
    ) -> Result<BloomOmcProof, BloomProveError> {
        self.batch_index = t;
        let params = self.params;
        let m = params.m_cells();
        let l = params.pairs();
        assert_eq!(initial.len(), m, "initial state must have M bits");
        assert!(
            initial.iter().all(|&x| x <= 1),
            "initial state must be bits"
        );

        let wit = epoch_witness(&params, initial, keys);
        let mode = self.mode;
        let initial_commit = commit_bloom_with(initial, mode, &openings.init);
        let final_commit = commit_bloom_with(&wit.final_bits, mode, &openings.final_);
        let batch_commit = bloom_batch_commit_with(params.batch, keys, mode, &openings.batch);

        self.circuit
            .update_permute_witnesses(&[wit.sigma_sort.clone(), wit.sigma_mset.clone()])
            .map_err(|e| BloomProveError::Run(format!("update_permute_witnesses: {e:?}")))?;

        let mut public_inputs: Vec<Challenge> = Vec::with_capacity(6);
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&CountMinCommit(initial_commit)));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&CountMinCommit(final_commit)));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&CountMinCommit(batch_commit)));
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        let bit = |x: u8| Challenge::from_u8(x);
        let base = |x: Val| Challenge::from(x);
        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            // B2: the salts first, in allocation order (init, final, batch).
            private_inputs.extend(openings.private_inputs());
        }
        private_inputs.extend(initial.iter().map(|&x| bit(x)));
        private_inputs.extend(wit.final_bits.iter().map(|&x| bit(x)));
        private_inputs.extend(wit.ft.iter().map(|&x| bit(x)));
        for rec in &wit.recs {
            let v = record_vals(*rec);
            let k3 = match rec {
                Some(key) => Val::from_u64(key >> 48),
                None => Val::ZERO,
            };
            private_inputs.extend([base(v[0]), base(v[1]), base(v[2]), base(k3)]);
            private_inputs.push(bit(u8::from(rec.is_some())));
        }
        for sv in &wit.split_vals {
            for limb in sv {
                private_inputs.extend(limb.iter().map(|&x| base(x)));
            }
        }
        private_inputs.extend(wit.as_sorted.iter().map(|&a| Challenge::from_u64(a)));
        private_inputs.extend(wit.vs_sorted.iter().map(|&x| bit(x)));
        private_inputs.extend((1..l).map(|r| bit(wit.eq_tag[r])));
        private_inputs.extend((1..l).map(|r| base(wit.inv_diff[r])));
        private_inputs.extend(wit.op_old.iter().map(|&x| bit(x)));

        let t_w = std::time::Instant::now();
        let traces = {
            let mut runner = self.circuit.runner();
            runner
                .set_public_inputs(&public_inputs)
                .map_err(|e| BloomProveError::Run(format!("set_public_inputs: {e:?}")))?;
            runner
                .set_private_inputs(&private_inputs)
                .map_err(|e| BloomProveError::Run(format!("set_private_inputs: {e:?}")))?;
            runner
                .run()
                .map_err(|e| BloomProveError::Run(format!("{e:?}")))?
        };
        let witness = t_w.elapsed();

        let t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .map_err(|e| BloomProveError::Prove(format!("{e:?}")))?;
        let prove = t_p.elapsed();
        let t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .map_err(|e| BloomProveError::Verify(format!("{e:?}")))?;
        crate::recursion::recursive::timing::record(
            crate::recursion::recursive::timing::LeafTiming {
                witness,
                prove,
                verify: t_v.elapsed(),
                trace_rows: self.trace_rows,
            },
        );

        Ok(BloomOmcProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial_commit: CountMinCommit(initial_commit),
            final_commit: CountMinCommit(final_commit),
            batch_commit: CountMinCommit(batch_commit),
            final_bits: wit.final_bits,
            params,
        })
    }
}

/// One-shot: build + prove one epoch.
pub fn prove_bloom_omc(params: BloomOmcParams, initial: &[u8], keys: &[u64]) -> BloomOmcProof {
    build_bloom_omc_leaf(params).prove_epoch(initial, keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_circuit::ops::{ExposeTrace, NpoTypeId};

    const SMALL: BloomOmcParams = BloomOmcParams {
        k: 3,
        log_w: 7,
        batch: 8,
    };

    fn keys(n: usize, seed: u64) -> Vec<u64> {
        (0..n as u64)
            .map(|i| {
                (i ^ seed)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .rotate_left(17)
            })
            .collect()
    }

    // ── native model ──

    #[test]
    fn native_no_false_negatives_and_fpr_sane() {
        let p = BloomOmcParams {
            k: 7,
            log_w: 14,
            batch: 1,
        };
        let inserted = keys(12_000, 1);
        let mut bits = bloom_empty(&p);
        bloom_insert(&mut bits, &p, &inserted);
        assert!(inserted.iter().all(|&k| bloom_contains(&bits, &p, k)));
        let probes = keys(20_000, 0xDEAD_BEEF);
        let fp = probes
            .iter()
            .filter(|&&k| !inserted.contains(&k) && bloom_contains(&bits, &p, k))
            .count();
        let rate = fp as f64 / probes.len() as f64;
        let est = fpr_estimate(&p, inserted.len());
        eprintln!("k=7 W=2^14 n=12000: measured FPR {rate:.4}, estimate {est:.4}");
        assert!(est < 0.012, "design point is ~1% FPR");
        assert!(
            rate < 2.0 * est + 0.002,
            "FPR {rate} far above estimate {est}"
        );
    }

    /// Keys congruent mod p are distinct records here (the key is hashed as
    /// 16-bit limbs), unlike `Val::from_u64(key)`, which maps them to the same
    /// field element and hence the same positions.
    #[test]
    fn keys_congruent_mod_p_are_not_collapsed() {
        let p = p_u64();
        for key in [5u64, 1 << 40, 0xABCD_EF01_2345] {
            let other = key + p;
            assert_eq!(Val::from_u64(key), Val::from_u64(other), "mod-p collapse");
            assert_ne!(record_vals(Some(key)), record_vals(Some(other)));
            assert_ne!(
                bloom_addresses(7, 14, key),
                bloom_addresses(7, 14, other),
                "distinct keys must not be forced onto the same positions"
            );
        }
        // Real key 0 is distinct from the dummy record.
        assert_ne!(record_vals(Some(0)), record_vals(None));
    }

    /// The canonical-split rule in plain integers: for every x in a boundary
    /// set and every integer split `pos + 2^log_w·hi ≡ x (mod p)` with
    /// `pos < 2^log_w`, `hi < 2^hi_w`, the gadget's constraints accept iff the
    /// split integer equals the canonical x.
    #[test]
    fn canonical_split_rule_accepts_exactly_canonical() {
        let p = p_u64();
        for log_w in [7usize, 14, 20] {
            let hm = hi_max(log_w);
            let hw = hi_bits_aligned(log_w);
            let accept = |pos: u64, hi: u64| -> bool {
                let d = hm as i128 - hi as i128;
                let range_ok =
                    pos < (1 << log_w) && hi < (1 << hw) && (0..(1i128 << hw)).contains(&d);
                range_ok && !(d == 0 && pos != 0)
            };
            let w = 1u64 << log_w;
            for x in [
                0u64,
                1,
                2,
                w - 2,
                w - 1,
                w,
                12345,
                (1 << 27) - 2,
                (1 << 27) - 1,
                p - w,
                p - 2,
                p - 1,
            ] {
                for mult in 0..3u64 {
                    let v = x as u128 + mult as u128 * p as u128;
                    let pos = (v % w as u128) as u64;
                    let hi = (v / w as u128) as u64;
                    let fits = hi < (1u64 << hw);
                    let ok = fits && accept(pos, hi);
                    assert_eq!(ok, mult == 0, "log_w={log_w} x={x} mult={mult}");
                }
            }
        }
    }

    // ── circuit: honest ──

    fn check_exposed(proof: &BloomOmcProof) {
        let (i, f, bc) = read_exposed_commitments(&proof.output.0);
        assert_eq!(i, proof.initial_commit.0, "exposed init");
        assert_eq!(f, proof.final_commit.0, "exposed final");
        assert_eq!(bc, proof.batch_commit.0, "exposed batch");
    }

    #[test]
    fn omc_round_trip_nonempty_prior_with_dummies() {
        let p = SMALL;
        let mut prior = bloom_empty(&p);
        bloom_insert(&mut prior, &p, &keys(20, 7));
        // 6 real keys + 2 dummy slots; include a key already inserted (a pure
        // re-set) so some touched cells have O = N = 1.
        let mut ks = keys(5, 99);
        ks.push(keys(20, 7)[3]);
        let mut expect = prior.clone();
        bloom_insert(&mut expect, &p, &ks);
        let mut leaf = build_bloom_omc_leaf(p);
        let proof = leaf.prove_epoch(&prior, &ks);
        assert_eq!(proof.final_bits, expect);
        assert_eq!(proof.final_commit.0, commit_bloom(&expect));
        assert_eq!(proof.initial_commit.0, commit_bloom(&prior));
        assert_ne!(proof.initial_commit.0, proof.final_commit.0);
        check_exposed(&proof);
        // Chain a second epoch on the same built leaf (fresh permutations).
        let ks2 = keys(8, 1234);
        let mut expect2 = expect.clone();
        bloom_insert(&mut expect2, &p, &ks2);
        let proof2 = leaf.prove_epoch(&expect, &ks2);
        assert_eq!(proof2.initial_commit.0, proof.final_commit.0, "chains");
        assert_eq!(proof2.final_commit.0, commit_bloom(&expect2));
        check_exposed(&proof2);
    }

    /// All-dummy batch: the state must not change; also exercises collisions
    /// (every dummy routes to the same k cells).
    #[test]
    fn omc_all_dummy_batch_is_noop() {
        let p = SMALL;
        let mut prior = bloom_empty(&p);
        bloom_insert(&mut prior, &p, &keys(10, 3));
        let proof = prove_bloom_omc(p, &prior, &[]);
        assert_eq!(proof.final_commit.0, proof.initial_commit.0);
        check_exposed(&proof);
    }

    /// Repeated keys: several records hit the same cells (one read/write pair
    /// per touched address after the group-by).
    #[test]
    fn omc_repeated_keys() {
        let p = SMALL;
        let ks: Vec<u64> = vec![42, 42, 7, 42, 7, 9, 9, 42];
        let mut expect = bloom_empty(&p);
        bloom_insert(&mut expect, &p, &ks);
        let proof = prove_bloom_omc(p, &bloom_empty(&p), &ks);
        assert_eq!(proof.final_commit.0, commit_bloom(&expect));
        check_exposed(&proof);
    }

    // ── composable statement ──

    /// The three statement layouts over the same update. Interval: the leaf
    /// of batch `t` exposes `(Com(S_{t-1}), Com(S_t), (t, t, 0, 0),
    /// H(TAG_LEAF, t, Com(B_t)))` with the natively recomputed digest, and its
    /// VK (commitment + metadata) does not depend on `t` or the data: it is
    /// the VK of the no-op proof (empty filter, all-dummy batch) at `t = 1`.
    /// Boundary: `(init, final)` only. None: the standalone 24-value leaf of
    /// [`build_bloom_omc_leaf`] (which delegates to it, so their VKs agree by
    /// construction; `standalone_leaf_vk_is_pinned` checks that VK against the
    /// builder before the change). The three are distinct circuits.
    #[test]
    fn statement_layouts_interval_boundary_none() {
        use crate::recursion::recursive::expose_forest::{read_exposed_statement, vk_pin_values};
        use crate::recursion::recursive::root_vk::bound_proof_shape;
        use crate::recursion::recursive::statement::{hash_bb, leaf_digest};
        let p = SMALL;
        let mut prior = bloom_empty(&p);
        bloom_insert(&mut prior, &p, &keys(20, 7));
        let ks = keys(6, 99);
        let mut expect = prior.clone();
        bloom_insert(&mut expect, &p, &ks);
        let vk = |o: &BloomOmcProof| (vk_pin_values(&o.output.0), bound_proof_shape(&o.output.0));
        let exposed_len = |o: &BloomOmcProof| -> Vec<usize> {
            let lens = o.output.0.non_primitives.iter().map(|e| e.public_values.len());
            lens.filter(|&n| n > 0).collect()
        };

        let mut iv = build_bloom_omc_leaf_expose(p, Expose::Interval);
        assert_eq!(iv.expose(), Expose::Interval);
        let proof = iv.prove_epoch_at(5, &prior, &ks);
        assert_eq!(proof.final_bits, expect);
        assert_eq!(exposed_len(&proof), vec![28], "Interval layout");
        let st = read_exposed_statement(&proof.output.0);
        assert_eq!(st.init, commit_bloom(&prior).to_vec(), "exposed Com(S_{{t-1}})");
        assert_eq!(st.final_, commit_bloom(&expect).to_vec(), "exposed Com(S_t)");
        let ip = st.interval.expect("interval part");
        assert_eq!((ip.lo, ip.hi), (Val::from_u64(5), Val::from_u64(5)), "idx = (t, t)");
        assert!(ip.idx_pad.iter().all(|&x| x == Val::ZERO), "idx padding");
        let com_b = bloom_batch_commit(p.batch, &ks);
        assert_eq!(com_b, commit_bloom_batch(&p, &ks));
        assert_eq!(ip.digest, leaf_digest(&hash_bb, 4, 5, &com_b), "H(TAG_LEAF, t, Com(B_t))");
        // The no-op proof the VK derivation starts from (same built leaf).
        let noop = iv.prove_epoch_at(1, &bloom_empty(&p), &[]);
        let sn = read_exposed_statement(&noop.output.0);
        assert_eq!(sn.init, sn.final_, "all-dummy batch is a no-op");
        assert_eq!(vk(&noop), vk(&proof), "VK independent of t and data");

        let bd = build_bloom_omc_leaf_expose(p, Expose::Boundary).prove_epoch(&prior, &ks);
        assert_eq!(exposed_len(&bd), vec![16], "Boundary layout");
        let sb = read_exposed_statement(&bd.output.0);
        assert_eq!((sb.init, sb.final_, sb.interval), (st.init.clone(), st.final_.clone(), None));

        let std = build_bloom_omc_leaf(p).prove_epoch(&prior, &ks);
        let none = build_bloom_omc_leaf_expose(p, Expose::None).prove_epoch(&prior, &ks);
        assert_eq!(exposed_len(&std), vec![EXPOSED_LEN], "standalone layout");
        check_exposed(&std);
        check_exposed(&none);
        assert_eq!(vk(&std), vk(&none), "Expose::None is the standalone leaf");
        assert_ne!(vk(&std).0, vk(&proof).0);
        assert_ne!(vk(&bd).0, vk(&proof).0);
        assert_ne!(vk(&bd).0, vk(&std).0);
    }

    /// `check` reports exactly what `validate` panics on (runners use it to
    /// reject a bad configured shape with its reason).
    #[test]
    fn params_check_matches_validate() {
        let p = |k, log_w, batch| BloomOmcParams { k, log_w, batch };
        for ok in [SMALL, p(1, 7, 1), p(7, 14, 16384), p(MAX_K, 20, 1)] {
            assert_eq!(ok.check(), Ok(()), "{ok:?}");
            ok.validate();
        }
        for (bad, why) in [
            (p(0, 7, 8), "k must be in 1..=8, got 0"),
            (p(9, 14, 8), "k must be in 1..=8, got 9"),
            (p(3, 6, 8), "log_w must be in 7..=20, got 6"),
            (p(3, 21, 8), "log_w must be in 7..=20, got 21"),
            (p(3, 7, 0), "batch must be ≥ 1"),
        ] {
            assert_eq!(bad.check(), Err(why.to_string()), "{bad:?}");
            let panic = std::panic::catch_unwind(|| bad.validate()).expect_err("validate panics");
            let msg = panic.downcast_ref::<String>().cloned().unwrap_or_default();
            assert_eq!(msg, why, "validate panics with the check reason");
        }
    }

    /// FNV-1a-64 (a stable, dependency-free fingerprint for the VK pin below).
    fn fnv1a64(bytes: impl IntoIterator<Item = u8>) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// `(commitment, metadata)` fingerprint of a leaf proof's VK: FNV-1a-64 of
    /// the preprocessed commitment (`vk_pin_values` order, canonical `u32`
    /// coefficients, little-endian) and of the postcard-encoded
    /// `bound_proof_shape`.
    fn vk_fingerprint(o: &BloomOmcProof) -> (u64, u64) {
        use crate::recursion::recursive::expose_forest::vk_pin_values;
        use crate::recursion::recursive::root_vk::bound_proof_shape;
        use p3_field::PrimeField32;
        let commit = fnv1a64(vk_pin_values(&o.output.0).iter().flat_map(|c| {
            <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                .iter()
                .flat_map(|x| x.as_canonical_u32().to_le_bytes())
                .collect::<Vec<u8>>()
        }));
        let shape = postcard::to_allocvec(&bound_proof_shape(&o.output.0)).expect("serialize shape");
        (commit, fnv1a64(shape))
    }

    /// Regression pin: the standalone 24-value leaf ([`build_bloom_omc_leaf`],
    /// i.e. [`Expose::None`]) keeps the VK of the builder before the
    /// composable [`Expose`] layouts were added. The constants were produced
    /// by this fingerprint over that unmodified builder (the tree at commit
    /// 7089f70, built side by side), at two small shapes; the VK does not
    /// depend on the data, which the no-op proof re-checks. An edit to the
    /// shared builder that moves the `None` path fails here. A deliberate
    /// circuit change, a Plonky3-fork bump or a new `BoundProofShape` field
    /// moves the pin too; re-pin only once that is confirmed as the cause.
    #[test]
    fn standalone_leaf_vk_is_pinned() {
        // (k, log_w, batch, live keys) → (commitment, metadata) fingerprints.
        #[cfg(not(feature = "zk"))]
        const PINNED: [((usize, usize, usize, usize), (u64, u64)); 2] = [
            ((3, 7, 8, 6), (0x5799_0f46_158c_a38e, 0xb2c4_1ac7_ed6a_d550)),
            ((7, 8, 4, 3), (0x6e87_0de0_0d50_0e7b, 0xc986_76c8_919c_a78b)),
        ];
        // The same circuits under the `zk` feature (hiding PCS, ZK LogUp masks):
        // recorded on the zk-logup-mask forks (Plonky3 280b1a07, Plonky3_RangeAir
        // 3acdc06); equal across separate processes.
        #[cfg(feature = "zk")]
        const PINNED: [((usize, usize, usize, usize), (u64, u64)); 2] = [
            ((3, 7, 8, 6), (0xd9f0_8d56_6a6c_eac6, 0x395b_b466_75fb_5f14)),
            ((7, 8, 4, 3), (0x1b0d_1bac_eb90_68c7, 0xe4d4_2c1b_9768_cb0b)),
        ];
        for ((k, log_w, batch, live), pin) in PINNED {
            let p = BloomOmcParams { k, log_w, batch };
            let mut prior = bloom_empty(&p);
            bloom_insert(&mut prior, &p, &keys(20, 7));
            let proof = build_bloom_omc_leaf(p).prove_epoch(&prior, &keys(live, 99));
            check_exposed(&proof);
            let noop = build_bloom_omc_leaf(p).prove_epoch(&bloom_empty(&p), &[]);
            let (got, got_noop) = (vk_fingerprint(&proof), vk_fingerprint(&noop));
            assert_eq!(got, got_noop, "k={k} log_w={log_w} batch={batch}: VK independent of data");
            assert_eq!(
                got.0, pin.0,
                "k={k} log_w={log_w} batch={batch}: standalone leaf VK commitment moved \
                 (got 0x{:016x})",
                got.0
            );
            assert_eq!(
                got.1, pin.1,
                "k={k} log_w={log_w} batch={batch}: standalone leaf proof metadata moved \
                 (got 0x{:016x})",
                got.1
            );
        }
    }

    // ── circuit: tamper ──

    fn with_tamper<T>(mode: u8, f: impl FnOnce() -> T) -> T {
        TAMPER.with(|t| t.set(mode));
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        TAMPER.with(|t| t.set(TAMPER_NONE));
        match out {
            Ok(v) => v,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    fn expect_rejected(mode: u8, what: &str) -> BloomProveError {
        let p = SMALL;
        let prior = bloom_empty(&p); // empty ⇒ every real record must set bits
        let ks = keys(6, 5);
        let mut leaf = build_bloom_omc_leaf(p);
        leaf.prove_epoch(&prior, &ks); // honest accepts on the same leaf
        let err = with_tamper(mode, || leaf.try_prove_epoch(&prior, &ks))
            .err()
            .unwrap_or_else(|| panic!("{what}: tampered epoch was ACCEPTED"));
        eprintln!("{what}: rejected at {err:?}");
        err
    }

    /// (a) Suppression: a touched 0-bit claimed already 1 (O = N = 1) and left 0
    /// in the committed final. The ts = 0 update read (a, 1, 0) has no ts = 0
    /// write to consume (the only one is the init write (a, 0, 0)).
    #[test]
    fn suppression_rejected() {
        let e = expect_rejected(TAMPER_SUPPRESS, "suppression");
        assert!(matches!(e, BloomProveError::Run(_)));
    }

    /// (b) Wrong final bit at an untouched cell.
    #[test]
    fn wrong_final_untouched_rejected() {
        let e = expect_rejected(TAMPER_WRONG_FINAL_UNTOUCHED, "wrong final (untouched)");
        assert!(matches!(e, BloomProveError::Run(_)));
    }

    /// (b') A touched cell's final bit cleared while its final read keeps ts = 1.
    #[test]
    fn wrong_final_touched_rejected() {
        let e = expect_rejected(TAMPER_WRONG_FINAL_TOUCHED, "wrong final (touched)");
        assert!(matches!(e, BloomProveError::Run(_)));
    }

    /// (c) Non-canonical position bits. Pick a (record, slice) whose digest limb
    /// x < 2^31 − p, witness the split of x + p (position (x+1) mod W). With the
    /// canonicity constraints the epoch is rejected; with them disabled
    /// (test-only build switch) the SAME witness yields an accepting proof whose
    /// exposed final commitment differs from the honest one — the misrouting
    /// is real and the gadget is what closes it.
    #[test]
    fn noncanonical_position_rejected() {
        let p = SMALL;
        let prior = bloom_empty(&p);
        let lim = (1u64 << 31) - p_u64();
        // Find a batch whose record 0 has a small limb in a position slice and
        // whose misrouted bit changes the final state.
        let mut found = None;
        'outer: for seed in 0..10_000u64 {
            let ks = keys(p.batch, seed);
            let d = record_digest(Some(ks[0]));
            for j in 0..p.k {
                let x = d[j].as_canonical_u64();
                if x < lim {
                    let mut honest = prior.clone();
                    bloom_insert(&mut honest, &p, &ks);
                    let bad_pos = (x + p_u64()) % (1u64 << p.log_w);
                    let bad_addr = (j << p.log_w) + bad_pos as usize;
                    if honest[bad_addr] == 0 {
                        found = Some((ks, j));
                        break 'outer;
                    }
                }
            }
        }
        let (ks, j) = found.expect("a batch with a small digest limb");
        let mut honest = prior.clone();
        bloom_insert(&mut honest, &p, &ks);
        TAMPER_NONCANON_TARGET.with(|c| c.set((0, j)));

        // With the canonicity constraints: rejected.
        let mut leaf = build_bloom_omc_leaf(p);
        let err = with_tamper(TAMPER_NONCANON, || leaf.try_prove_epoch(&prior, &ks))
            .err()
            .expect("non-canonical split must be rejected");
        eprintln!("non-canonical split (canonical check ON): rejected at {err:?}");
        assert!(matches!(err, BloomProveError::Run(_)));

        // Without them (test-only): the forged routing verifies and certifies a
        // WRONG final state.
        DISABLE_CANON_CHECK.with(|f| f.set(true));
        let mut weak = build_bloom_omc_leaf(p);
        DISABLE_CANON_CHECK.with(|f| f.set(false));
        let forged = with_tamper(TAMPER_NONCANON, || weak.try_prove_epoch(&prior, &ks))
            .expect("without canonicity the misrouted witness is accepted");
        let (_, exposed_final, _) = read_exposed_commitments(&forged.output.0);
        assert_ne!(
            exposed_final,
            commit_bloom(&honest),
            "accepted proof certifies a misrouted (wrong) final state"
        );
        eprintln!("non-canonical split (canonical check OFF): ACCEPTED with a wrong final commit");
    }

    /// In-circuit edge branch of the canonical split (hi = HI_MAX, pos ≠ 0),
    /// which random digests essentially never reach: run the gadget alone on a
    /// chosen limb x = 5 with the non-canonical split of x + p.
    #[test]
    fn canonical_split_edge_branch_in_circuit() {
        let run = |x: u64, pos: u64, hi: u64, dinv: Val| -> bool {
            let log_w = 7usize;
            let mut b = CircuitBuilder::<Challenge>::new();
            b.enable_range(generate_range_trace::<Val, Challenge>);
            let xpub = b.alloc_public_input("x");
            let consts = Consts {
                one: b.alloc_const(Challenge::ONE, "one"),
                zero: b.alloc_const(Challenge::ZERO, "zero"),
                two: b.alloc_const(Challenge::from_u64(2), "two"),
                act_shift: b.alloc_const(Challenge::from_u64(ACT_SHIFT), "s"),
                pow_log_w: b.alloc_const(Challenge::from_u64(1 << log_w), "w"),
                hi_max: b.alloc_const(Challenge::from_u64(hi_max(log_w)), "hm"),
                slice_off: vec![],
                e1: b.alloc_const(Challenge::ONE, "e1"),
                e2: b.alloc_const(Challenge::ONE, "e2"),
                e3: b.alloc_const(Challenge::ONE, "e3"),
            };
            let pw = b.alloc_private_input("pos");
            let hw = b.alloc_private_input("hi");
            let dw = b.alloc_private_input("dinv");
            let xe = canonical_split_gadget(&mut b, pw, hw, dw, log_w, &consts, true);
            b.connect(xe, xpub);
            let circuit = b.build().unwrap();
            let mut runner = circuit.runner();
            runner.set_public_inputs(&[Challenge::from_u64(x)]).unwrap();
            runner
                .set_private_inputs(&[
                    Challenge::from_u64(pos),
                    Challenge::from_u64(hi),
                    Challenge::from(dinv),
                ])
                .unwrap();
            runner.run().is_ok()
        };
        let log_w = 7usize;
        let x = 5u64;
        let (pos, hi, dinv) = canonical_split(x, log_w);
        assert!(run(x, pos, hi, dinv), "honest split accepted");
        let xp = x + p_u64();
        let (pos2, hi2) = (xp % (1 << log_w), xp >> log_w);
        assert_eq!(
            hi2,
            hi_max(log_w),
            "x < 2^log_w − 2 lands exactly on HI_MAX"
        );
        assert_eq!(pos2, x + 1);
        for dinv in [Val::ZERO, Val::ONE, Val::from_u64(12345)] {
            assert!(
                !run(x, pos2, hi2, dinv),
                "edge non-canonical split must be rejected"
            );
        }
        // The canonical top value p − 1 (hi = HI_MAX, pos = 0) is accepted.
        let (pp, ph, pd) = canonical_split(p_u64() - 1, log_w);
        assert_eq!((pp, ph), (0, hi_max(log_w)));
        assert!(run(p_u64() - 1, pp, ph, pd));
    }

    // ── fork binding PoC (why this leaf never uses decompose_ext_to_base_coeffs) ──

    /// Build `x` (public, exposed) and `y` (public, exposed) with the in-circuit
    /// claim `y = 2·coeff0(x)`, the coefficient taken either via the NPO
    /// `decompose_ext_to_base_coeffs` (as `hll_omc`/`countmin_omc` do) or via
    /// this leaf's ALU recomposition of range-pinned private coefficients. Run
    /// honestly, then FORGE the trace so the coefficient is `x0 + 1` (and `y`
    /// accordingly) and return whether the forged proof verifies, plus the
    /// exposed `(x0, y)`.
    fn decompose_forgery(alu_binding: bool, forge: bool) -> (bool, Val, Val) {
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_range(generate_range_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let xpub = b.alloc_public_input("x");
        let ypub = b.alloc_public_input("y");
        b.add_expose(&[xpub, ypub]).unwrap();
        let two = b.alloc_const(Challenge::from_u64(2), "two");
        let c0 = if alu_binding {
            let cs: Vec<ExprId> = (0..4).map(|_| b.alloc_private_input("c")).collect();
            for &ci in &cs {
                b.add_range_bits::<Val>(ci, Val::bits()).unwrap();
            }
            let r = b.recompose_base_coeffs_to_ext_via_alu::<Val>(&cs).unwrap();
            b.connect(r, xpub);
            cs[0]
        } else {
            let cs = b.decompose_ext_to_base_coeffs::<Val>(xpub).unwrap();
            for &ci in &cs[1..] {
                let _ = b.mul(ci, ci); // consume (the hll_omc idiom)
            }
            cs[0]
        };
        let t = b.mul(c0, two);
        b.connect(t, ypub);
        b.tag(c0, "c0").unwrap();
        b.tag(ypub, "y").unwrap();
        let circuit = b.build().unwrap();

        let xs = [
            Val::from_u64(1000),
            Val::from_u64(7),
            Val::from_u64(8),
            Val::from_u64(9),
        ];
        let x = Challenge::from_basis_coefficients_slice(&xs).unwrap();
        let y = Challenge::from(xs[0] * Val::from_u64(2));
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[x, y]).unwrap();
        if alu_binding {
            runner
                .set_private_inputs(&xs.iter().map(|&v| Challenge::from(v)).collect::<Vec<_>>())
                .unwrap();
        }
        let mut traces = runner.run().expect("honest run");

        // ── forge: coefficient c0 := x0 + 1, y := 2·(x0 + 1) ──
        if forge {
            let c0_wid = traces.tag_to_witness["c0"];
            let y_wid = traces.tag_to_witness["y"];
            let new_c0 = Challenge::from(xs[0] + Val::ONE);
            let new_y = new_c0 * Challenge::from_u64(2);
            for (row, idx) in traces.alu_trace.indices.iter().enumerate() {
                for slot in 0..4 {
                    if idx[slot] == c0_wid {
                        traces.alu_trace.values[row][slot] = new_c0;
                    }
                    if idx[slot] == y_wid {
                        traces.alu_trace.values[row][slot] = new_y;
                    }
                }
            }
            for (i, wid) in traces.public_trace.index.iter().enumerate() {
                if *wid == y_wid {
                    traces.public_trace.values[i] = new_y;
                }
            }
            let expose_id = NpoTypeId::expose();
            let mut ex: ExposeTrace<Val> = traces
                .non_primitive_trace::<ExposeTrace<Val>>(&expose_id)
                .expect("expose trace")
                .clone();
            for row in ex.operations.iter_mut() {
                for (pos, wid) in row.input_wids.iter().enumerate() {
                    if *wid == y_wid {
                        let ny = <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(
                            &new_y,
                        );
                        row.input_values[4 * pos..4 * pos + 4].copy_from_slice(ny);
                    }
                }
            }
            traces.non_primitive_traces.insert(expose_id, Box::new(ex));
        }

        let config = make_leaf_config();
        let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        let preprocessors = vec![
            recompose_preprocessor::<Val>(false),
            range_preprocessor::<Val>(),
            expose_preprocessor::<Val>(),
        ];
        let mut air_builders = recompose_air_builders::<ConfigWithFriParams, 4>(1, false);
        air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
        let (airs_degrees, pc, npc) =
            get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
                &circuit,
                &table_packing,
                &preprocessors,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let cpd = CircuitProverData::new(pd, pc, npc);
        let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        prover.register_recompose_table::<4>(false);
        prover.register_range_table::<4>();
        prover.register_expose_table::<4>();
        let ok = match prover.prove_all_tables(&traces, &cpd) {
            Ok(proof) => {
                let verified = prover.verify_all_tables(&proof).is_ok();
                if verified {
                    let pv = proof
                        .non_primitives
                        .iter()
                        .map(|e| &e.public_values)
                        .find(|v| v.len() == 8)
                        .expect("exposed (x, y)");
                    return (true, pv[0], pv[4]);
                }
                false
            }
            Err(_) => false,
        };
        (ok, xs[0], Val::ZERO)
    }

    /// PoC: through the NPO decompose path the proof VERIFIES while exposing
    /// `(x, y)` with `y ≠ 2·coeff0(x)` — the decomposed coefficient is not
    /// bound to the value it decomposes. Gated on
    /// [`crate::sketch::bind::probe::fork_binds_decompose`]: on a fork that
    /// binds decompose coefficients itself (the merged soundness fork) the
    /// same forgery must be REJECTED instead.
    #[test]
    fn poc_npo_decompose_coefficients_are_unbound() {
        let (honest_ok, hx0, hy) = decompose_forgery(false, false);
        assert!(
            honest_ok && hy == hx0 * Val::from_u64(2),
            "honest run must verify"
        );
        let (verified, x0, y) = decompose_forgery(false, true);
        if crate::sketch::bind::probe::fork_binds_decompose() {
            assert!(
                !verified,
                "fork binds decompose coefficients (probe), yet the forged NPO-decompose trace verified"
            );
            eprintln!("NPO decompose forgery REJECTED (fork binds decompose coefficients)");
            return;
        }
        assert!(
            verified,
            "forged NPO-decompose trace was rejected (coefficients ARE bound)"
        );
        assert_ne!(
            y,
            x0 * Val::from_u64(2),
            "exposed y contradicts y = 2·coeff0(x)"
        );
        eprintln!("NPO decompose forgery ACCEPTED: exposed x0 = {x0}, y = {y} (≠ 2·x0)");
    }

    /// Control: the same forgery against the ALU recomposition of range-pinned
    /// coefficients (this leaf's binding) is rejected.
    #[test]
    fn control_alu_recompose_binding_rejects_forgery() {
        let (honest_ok, hx0, hy) = decompose_forgery(true, false);
        assert!(
            honest_ok && hy == hx0 * Val::from_u64(2),
            "honest run must verify"
        );
        let (verified, _, _) = decompose_forgery(true, true);
        assert!(!verified, "forged coefficient must break the ALU binding");
    }

    /// Hash one exposed Challenge `x` (4 values → one Poseidon2 row) and expose
    /// the digest, via plain `add_hash_slice` or via [`hash_slice_bound`]. Then
    /// FORGE: change one capacity input value of that row, recompute the
    /// permutation, and patch the exposed digest. Returns whether the forged
    /// (or honest, `forge = false`) proof verifies and the exposed digest.
    fn poseidon_capacity_forgery(bound: bool, forge: bool) -> (bool, [Val; 8]) {
        use p3_circuit::ops::Poseidon2Trace;
        use p3_symmetric::Permutation;
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let xpub = b.alloc_public_input("x");
        let zero = b.alloc_const(Challenge::ZERO, "zero");
        let h = if bound {
            hash_slice_bound(&mut b, &cfg, &[xpub], zero)
        } else {
            b.add_hash_slice(&cfg, &[xpub], true).unwrap()
        };
        b.add_expose(&[xpub, h[0], h[1]]).unwrap();
        b.tag(h[0], "h0").unwrap();
        b.tag(h[1], "h1").unwrap();
        let circuit = b.build().unwrap();

        let xs = [1u64, 2, 3, 4].map(Val::from_u64);
        let x = Challenge::from_basis_coefficients_slice(&xs).unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[x]).unwrap();
        let mut traces = runner.run().expect("honest run");

        if forge {
            let pid = NpoTypeId::poseidon2_perm(cfg);
            let mut pt: Poseidon2Trace<Val> = traces
                .non_primitive_trace::<Poseidon2Trace<Val>>(&pid)
                .expect("poseidon2 trace")
                .clone();
            assert_eq!(pt.operations.len(), 1, "one permutation row");
            let row = &mut pt.operations[0];
            row.input_values[8] += Val::ONE; // capacity limb 2, coefficient 0
            let mut state: [Val; 16] = row.input_values.clone().try_into().unwrap();
            make_perm().permute_mut(&mut state);
            traces.non_primitive_traces.insert(pid, Box::new(pt));
            let h0 = traces.tag_to_witness["h0"];
            let h1 = traces.tag_to_witness["h1"];
            let expose_id = NpoTypeId::expose();
            let mut ex: ExposeTrace<Val> = traces
                .non_primitive_trace::<ExposeTrace<Val>>(&expose_id)
                .expect("expose trace")
                .clone();
            for r in ex.operations.iter_mut() {
                for (pos, wid) in r.input_wids.iter().enumerate() {
                    if *wid == h0 {
                        r.input_values[4 * pos..4 * pos + 4].copy_from_slice(&state[0..4]);
                    }
                    if *wid == h1 {
                        r.input_values[4 * pos..4 * pos + 4].copy_from_slice(&state[4..8]);
                    }
                }
            }
            traces.non_primitive_traces.insert(expose_id, Box::new(ex));
        }

        let config = make_leaf_config();
        let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        let preprocessors = vec![
            poseidon2_preprocessor::<Val>(),
            recompose_preprocessor::<Val>(false),
            expose_preprocessor::<Val>(),
        ];
        let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
        air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
        let (airs_degrees, pc, npc) =
            get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
                &circuit,
                &table_packing,
                &preprocessors,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let cpd = CircuitProverData::new(pd, pc, npc);
        let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        prover.register_poseidon2_table::<4>(cfg);
        prover.register_recompose_table::<4>(false);
        prover.register_expose_table::<4>();
        match prover.prove_all_tables(&traces, &cpd) {
            Ok(proof) if prover.verify_all_tables(&proof).is_ok() => {
                let pv = proof
                    .non_primitives
                    .iter()
                    .map(|e| &e.public_values)
                    .find(|v| v.len() == 12)
                    .expect("exposed (x, h0, h1)");
                (true, std::array::from_fn(|i| pv[4 + i]))
            }
            _ => (false, [Val::ZERO; 8]),
        }
    }

    /// PoC: with plain `add_hash_slice` (D = 4) the first row's capacity is
    /// free — a proof verifies while exposing a "digest" of `x` that is NOT
    /// `MyHash(x)`. Any single-block digest (e.g. a record's positions) can be
    /// ground by the prover.
    ///
    /// Gated on [`crate::sketch::bind::probe::fork_binds_iv`]: on a fork that
    /// enforces the zero IV on `new_start` rows the forgery must be REJECTED.
    #[test]
    fn poc_poseidon_d4_free_capacity() {
        let native: [Val; 8] =
            MyHash::new(make_perm()).hash_iter([1u64, 2, 3, 4].map(Val::from_u64));
        let (ok, honest) = poseidon_capacity_forgery(false, false);
        assert!(ok && honest == native, "honest digest must equal MyHash");
        let (ok, forged) = poseidon_capacity_forgery(false, true);
        if crate::sketch::bind::probe::fork_binds_iv() {
            assert!(!ok, "fork binds the sponge IV (probe), yet the free-capacity forgery verified");
            eprintln!("free-capacity forgery REJECTED (fork binds the zero IV)");
            return;
        }
        assert!(ok, "forged capacity was rejected (IV is bound)");
        assert_ne!(forged, native);
        eprintln!(
            "free-capacity forgery ACCEPTED: exposed digest[0] = {} vs MyHash = {}",
            forged[0], native[0]
        );
    }

    /// Control: [`hash_slice_bound`] feeds the zero constant into every
    /// first-row limb, so the same forgery is rejected.
    #[test]
    fn control_bound_sponge_rejects_capacity_forgery() {
        let native: [Val; 8] =
            MyHash::new(make_perm()).hash_iter([1u64, 2, 3, 4].map(Val::from_u64));
        let (ok, honest) = poseidon_capacity_forgery(true, false);
        assert!(ok && honest == native, "bound sponge must equal MyHash");
        let (ok, _) = poseidon_capacity_forgery(true, true);
        assert!(!ok, "capacity forgery must be rejected by the bound sponge");
    }

    // ── measurement (explicit) ──

    /// Range-check `x` (public, exposed) to 4 bits with the fork's
    /// `add_range_bits(x, 4)` or with [`range_exact`]; run honestly with `x = 3`,
    /// then FORGE `x := 16^{-1} mod p` by rewriting every trace value that
    /// depended on `x` (`add_range_bits`: byte = x, shifted byte·16 = 1;
    /// `range_exact`: bytes x and x + 248). Returns whether the forged proof
    /// verifies and the exposed `x`.
    fn range_bits_forgery(exact: bool, forge: bool) -> (bool, Val) {
        use p3_circuit::ops::RangeTrace;
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_range(generate_range_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let xpub = b.alloc_public_input("x");
        b.add_expose(&[xpub]).unwrap();
        if exact {
            range_exact(&mut b, xpub, 4);
        } else {
            b.add_range_bits::<Val>(xpub, 4).unwrap();
        }
        b.tag(xpub, "x").unwrap();
        let circuit = b.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[Challenge::from_u64(3)]).unwrap();
        let mut traces = runner.run().expect("honest run");

        let x_forged = Val::from_u64(16).inverse();
        if forge {
            // honest value → forged value, for every wire derived from x.
            let remap: Vec<(Val, Val)> = if exact {
                let off = Val::from_u64(248);
                vec![
                    (Val::from_u64(3), x_forged),
                    (Val::from_u64(251), x_forged + off),
                ]
            } else {
                vec![(Val::from_u64(3), x_forged), (Val::from_u64(48), Val::ONE)]
            };
            let map = |v: Challenge| -> Challenge {
                for &(h, f) in &remap {
                    if v == Challenge::from(h) {
                        return Challenge::from(f);
                    }
                }
                v
            };
            for row in traces.alu_trace.values.iter_mut() {
                for slot in row.iter_mut() {
                    *slot = map(*slot);
                }
            }
            for v in traces.public_trace.values.iter_mut() {
                *v = map(*v);
            }
            let rid = NpoTypeId::range();
            let mut rt: RangeTrace<Val> = traces
                .non_primitive_trace::<RangeTrace<Val>>(&rid)
                .expect("range trace")
                .clone();
            for op in rt.operations.iter_mut() {
                for v in op.input_values.chunks_mut(4) {
                    for &(h, f) in &remap {
                        if v[0] == h && v[1..].iter().all(|c| *c == Val::ZERO) {
                            v[0] = f;
                            break;
                        }
                    }
                }
            }
            traces.non_primitive_traces.insert(rid, Box::new(rt));
            let eid = NpoTypeId::expose();
            let mut ex: ExposeTrace<Val> = traces
                .non_primitive_trace::<ExposeTrace<Val>>(&eid)
                .expect("expose trace")
                .clone();
            for op in ex.operations.iter_mut() {
                op.input_values[0] = x_forged;
            }
            traces.non_primitive_traces.insert(eid, Box::new(ex));
        }

        let config = make_leaf_config();
        let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        let preprocessors = vec![range_preprocessor::<Val>(), expose_preprocessor::<Val>()];
        let mut air_builders = range_air_builders::<ConfigWithFriParams, 4>(1);
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
        let (airs_degrees, pc, npc) =
            get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
                &circuit,
                &table_packing,
                &preprocessors,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let cpd = CircuitProverData::new(pd, pc, npc);
        let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        prover.register_range_table::<4>();
        prover.register_expose_table::<4>();
        match prover.prove_all_tables(&traces, &cpd) {
            Ok(proof) if prover.verify_all_tables(&proof).is_ok() => {
                let pv = proof
                    .non_primitives
                    .iter()
                    .map(|e| &e.public_values)
                    .find(|v| v.len() == 4)
                    .expect("exposed x");
                (true, pv[0])
            }
            _ => (false, Val::ZERO),
        }
    }

    /// PoC: `add_range_bits(x, 4)` accepts `x = 16^{-1} mod p` (≈ 0.94·p), i.e.
    /// for `n < 8` it is not a range check at all (for `n ≥ 9` the proven bound
    /// is `2^n + 2^{8⌈n/8⌉−8}`, argued in the module docs, not PoC'd here).
    ///
    /// Gated on [`crate::sketch::bind::probe::fork_binds_range_top_byte`]: on a
    /// fork whose `add_range_bits` also looks the top byte up unshifted, the
    /// forgery must be REJECTED.
    #[test]
    fn poc_add_range_bits_unaligned_is_not_a_range_check() {
        let (ok, x) = range_bits_forgery(false, false);
        assert!(ok && x == Val::from_u64(3), "honest run must verify");
        let (ok, x) = range_bits_forgery(false, true);
        if crate::sketch::bind::probe::fork_binds_range_top_byte() {
            assert!(!ok, "fork range-checks the unshifted top byte (probe), yet x = 16^-1 verified");
            eprintln!("add_range_bits(x, 4) forgery REJECTED (fork checks the unshifted top byte)");
            return;
        }
        assert!(ok, "forged 4-bit range check was rejected");
        assert!(x.as_canonical_u64() >= 16);
        eprintln!("add_range_bits(x, 4) forgery ACCEPTED with exposed x = {x}");
    }

    /// Control: [`range_exact`] (two byte-aligned checks) rejects the same x.
    #[test]
    fn control_range_exact_rejects_unaligned_forgery() {
        let (ok, x) = range_bits_forgery(true, false);
        assert!(ok && x == Val::from_u64(3), "honest run must verify");
        let (ok, _) = range_bits_forgery(true, true);
        assert!(!ok, "range_exact must reject x = 16^-1");
    }

    /// `y = x + K` with the constant `K = 5`, `(x, y)` exposed. Run honestly
    /// (`x = 1`, `y = 6`), then optionally FORGE the Const table's VALUE of `K`
    /// to 7 (patching the one ALU row and the exposed `y`). Returns whether the
    /// proof verifies and the exposed `(x, y)`.
    fn const_value_forgery(forge: bool) -> (bool, Val, Val) {
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let xpub = b.alloc_public_input("x");
        let kc = b.alloc_const(Challenge::from_u64(5), "K");
        let y = b.add(xpub, kc);
        b.add_expose(&[xpub, y]).unwrap();
        b.tag(kc, "K").unwrap();
        b.tag(y, "y").unwrap();
        let circuit = b.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[Challenge::from_u64(1)]).unwrap();
        let mut traces = runner.run().expect("honest run");
        if forge {
            let k_wid = traces.tag_to_witness["K"];
            let y_wid = traces.tag_to_witness["y"];
            let (k_new, y_new) = (Challenge::from_u64(7), Challenge::from_u64(8));
            for (i, wid) in traces.const_trace.index.iter().enumerate() {
                if *wid == k_wid {
                    traces.const_trace.values[i] = k_new;
                }
            }
            for (row, idx) in traces.alu_trace.indices.iter().enumerate() {
                for slot in 0..4 {
                    if idx[slot] == k_wid {
                        traces.alu_trace.values[row][slot] = k_new;
                    }
                    if idx[slot] == y_wid {
                        traces.alu_trace.values[row][slot] = y_new;
                    }
                }
            }
            let eid = NpoTypeId::expose();
            let mut ex: ExposeTrace<Val> = traces
                .non_primitive_trace::<ExposeTrace<Val>>(&eid)
                .expect("expose trace")
                .clone();
            for op in ex.operations.iter_mut() {
                for (pos, wid) in op.input_wids.iter().enumerate() {
                    if *wid == y_wid {
                        op.input_values[4 * pos] = Val::from_u64(8);
                    }
                }
            }
            traces.non_primitive_traces.insert(eid, Box::new(ex));
        }
        let config = make_leaf_config();
        let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        let preprocessors = vec![expose_preprocessor::<Val>()];
        let air_builders = expose_air_builders::<ConfigWithFriParams, 4>();
        let (airs_degrees, pc, npc) =
            get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
                &circuit,
                &table_packing,
                &preprocessors,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let cpd = CircuitProverData::new(pd, pc, npc);
        let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        prover.register_expose_table::<4>();
        match prover.prove_all_tables(&traces, &cpd) {
            Ok(proof) if prover.verify_all_tables(&proof).is_ok() => {
                let pv = proof
                    .non_primitives
                    .iter()
                    .map(|e| &e.public_values)
                    .find(|v| v.len() == 8)
                    .expect("exposed (x, y)");
                (true, pv[0], pv[4])
            }
            _ => (false, Val::ZERO, Val::ZERO),
        }
    }

    /// PoC (fork-level, affects EVERY circuit including this leaf): `ConstAir`
    /// keeps constant VALUES in the main trace, with only `(multiplicity,
    /// index)` preprocessed and no constraint, so a prover may replace any
    /// constant (consistently across its uses). A proof of `y = x + 5` verifies
    /// while exposing `x = 1, y = 8`. This leaf's soundness argument is
    /// therefore CONDITIONAL on the fork binding constants (e.g. moving the
    /// value columns into the preprocessed trace). Like the other `poc_*`
    /// tests this asserts the behaviour of the fork in use: gated on
    /// [`crate::sketch::bind::probe::fork_binds_const`] (a structural VK probe),
    /// it asserts ACCEPTED at the pinned rev and REJECTED on a fork that binds
    /// constant values.
    #[test]
    fn poc_const_values_are_prover_chosen() {
        let (ok, x, y) = const_value_forgery(false);
        assert!(
            ok && x == Val::ONE && y == Val::from_u64(6),
            "honest run must verify"
        );
        let (forged_ok, x, y) = const_value_forgery(true);
        if crate::sketch::bind::probe::fork_binds_const() {
            assert!(!forged_ok, "fork binds constant values (probe), yet the forged constant verified");
            eprintln!("CONST forgery REJECTED (fork binds constant values)");
            return;
        }
        assert!(
            forged_ok,
            "forged constant was rejected (constants ARE bound)"
        );
        assert_eq!((x, y), (Val::ONE, Val::from_u64(8)));
        eprintln!("CONST forgery ACCEPTED: circuit y = x + 5 exposes x = {x}, y = {y}");
    }

    /// Context only: the deployed Count-Min `omc` leaf at the matching shape
    /// (d = 7, w = 2^14, same batch sizes), timed through its public API. NOTE:
    /// that leaf uses the NPO decompose + plain `add_hash_slice` bindings this
    /// module avoids, so it is a cost reference, not a like-for-like sound
    /// baseline. `BLOOM_MEASURE_BATCHES=... cargo test --release
    /// cm_omc_same_shape_measure -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement: large circuits"]
    fn cm_omc_same_shape_measure() {
        use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
        use crate::sketch::countmin_omc::{CmOmcParams, build_countmin_omc_leaf};
        let batches: Vec<usize> = std::env::var("BLOOM_MEASURE_BATCHES")
            .unwrap_or_else(|_| "256".into())
            .split(',')
            .map(|s| s.trim().parse().unwrap())
            .collect();
        for batch in batches {
            let (d, w) = (7usize, 1usize << 14);
            let params = CmOmcParams { d, w, batch };
            let t_b = std::time::Instant::now();
            let mut leaf = build_countmin_omc_leaf(params, false);
            let build = t_b.elapsed();
            let state = CountMinState {
                counters: vec![vec![0u32; w]; d],
                params: CountMinParams { d, w },
            };
            let upd: Vec<CountMinUpdate> = keys(batch, 1000)
                .into_iter()
                .map(|key| CountMinUpdate { key, value: 1 })
                .collect();
            let t = std::time::Instant::now();
            let proof = leaf.prove_epoch(state, upd);
            let total = t.elapsed();
            let tm = crate::recursion::recursive::timing::take();
            eprintln!(
                "CM_OMC d=7 w=2^14 batch={} trace_rows={} build_ms={:.0} witness_ms={:.0} prove_ms={:.0} verify_ms={:.0} total_ms={:.0} proof_bytes={}",
                batch,
                tm.trace_rows,
                build.as_secs_f64() * 1e3,
                tm.witness.as_secs_f64() * 1e3,
                tm.prove.as_secs_f64() * 1e3,
                tm.verify.as_secs_f64() * 1e3,
                total.as_secs_f64() * 1e3,
                proof.proof_size()
            );
        }
    }

    /// `BLOOM_MEASURE_BATCHES=256,4096,16384 cargo test --release
    /// bloom_omc_measure -- --ignored --nocapture` — k = 7, W = 2^14.
    #[test]
    #[ignore = "measurement: large circuits"]
    fn bloom_omc_measure() {
        let batches: Vec<usize> = std::env::var("BLOOM_MEASURE_BATCHES")
            .unwrap_or_else(|_| "256".into())
            .split(',')
            .map(|s| s.trim().parse().unwrap())
            .collect();
        let reps: usize = std::env::var("BLOOM_MEASURE_REPS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        for batch in batches {
            let p = BloomOmcParams {
                k: 7,
                log_w: 14,
                batch,
            };
            let t_b = std::time::Instant::now();
            let mut leaf = build_bloom_omc_leaf(p);
            let build = t_b.elapsed();
            let mut state = bloom_empty(&p);
            bloom_insert(&mut state, &p, &keys(6000, 77)); // half-full prior (~n/2 of the 12k design)
            for rep in 0..reps {
                let ks = keys(batch, 1000 + rep as u64);
                let t = std::time::Instant::now();
                let proof = leaf.prove_epoch(&state, &ks);
                let total = t.elapsed();
                let tm = crate::recursion::recursive::timing::take();
                check_exposed(&proof);
                eprintln!(
                    "BLOOM k=7 log_w=14 M={} batch={} rep={} trace_rows={} tables={:?} build_ms={:.0} witness_ms={:.0} prove_ms={:.0} verify_ms={:.0} total_ms={:.0} proof_bytes={}",
                    p.m_cells(),
                    batch,
                    rep,
                    leaf.trace_rows(),
                    leaf.table_rows(),
                    build.as_secs_f64() * 1e3,
                    tm.witness.as_secs_f64() * 1e3,
                    tm.prove.as_secs_f64() * 1e3,
                    tm.verify.as_secs_f64() * 1e3,
                    total.as_secs_f64() * 1e3,
                    proof.proof_size()
                );
                state = proof.final_bits;
            }
        }
    }

    // ── hiding commitments (revision B2) ──

    mod hiding_b2 {
        use super::*;
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows};
        use crate::commitment::hiding::{
            SaltSeed, TAG_BATCH, TAG_STATE, rho_batch_bb as batch_salt, rho_state_bb as state_salt,
        };
        use crate::recursion::recursive::expose_forest::{read_exposed_statement, vk_pin_values};
        use crate::recursion::recursive::noop_leaf::{bloom_omc_noop_leaf_commit, bloom_omc_noop_leaf_expose};
        use crate::recursion::recursive::statement::{hash_bb, leaf_digest};
        use crate::sketch::forge;

        const BLOOM: CommitFamily = CommitFamily::Bloom;
        const HIDING: CommitMode = CommitMode::Hiding;

        fn prior() -> Vec<u8> {
            let mut b = bloom_empty(&SMALL);
            bloom_insert(&mut b, &SMALL, &keys(20, 7));
            b
        }

        fn after(bits: &[u8], ks: &[u64]) -> Vec<u8> {
            let mut b = bits.to_vec();
            bloom_insert(&mut b, &SMALL, ks);
            b
        }

        /// Natives: `Plain` ignores the salt; `Hiding` is
        /// `MyHash([TAG_STATE | TAG_BATCH, Bloom = 5, 0, 0, salt…] ‖ flat)` over
        /// exactly the Plain flat (the `M` bits; the `4·batch` record values).
        #[test]
        fn hiding_natives_match_layout() {
            let seed = SaltSeed::for_tests(41);
            let (s1, s2) = (state_salt(&seed, BLOOM, 1), state_salt(&seed, BLOOM, 2));
            let bits = prior();
            assert_eq!(commit_bloom_with(&bits, CommitMode::Plain, &s1), commit_bloom(&bits));
            let h = MyHash::new(make_perm());
            let mut input = vec![Val::from_u64(TAG_STATE), Val::from_u64(5), Val::ZERO, Val::ZERO];
            input.extend_from_slice(&s1.0);
            input.extend(bits.iter().map(|&b| Val::from_u8(b)));
            let want: [Val; 8] = h.hash_iter(input);
            let c1 = commit_bloom_with(&bits, HIDING, &s1);
            assert_eq!(c1, want, "state layout drift");
            assert_ne!(c1, commit_bloom_with(&bits, HIDING, &s2), "two versions, two commitments");
            assert_ne!(c1, commit_bloom(&bits));
            let ks = keys(5, 3);
            let b1 = batch_salt(&seed, BLOOM, 1);
            assert_eq!(bloom_batch_commit_with(SMALL.batch, &ks, CommitMode::Plain, &b1), bloom_batch_commit(SMALL.batch, &ks));
            let mut input = vec![Val::from_u64(TAG_BATCH), Val::from_u64(5), Val::ZERO, Val::ZERO];
            input.extend_from_slice(&b1.0);
            input.extend(padded_slots(SMALL.batch, &ks).into_iter().flat_map(record_vals));
            let want: [Val; 8] = h.hash_iter(input);
            assert_eq!(bloom_batch_commit_with(SMALL.batch, &ks, HIDING, &b1), want, "batch layout drift");
            // The kind tag separates a state from a batch even under one salt.
            assert_ne!(commit_bloom_with(&bits, HIDING, &SaltBb::ZERO), commit_bloom(&bits));
        }

        /// A hiding leaf's commitments (proof fields and the exposed statement,
        /// Interval and standalone layouts) are the NATIVE hiding commitments
        /// under the leaf-`t` openings, and differ from the Plain ones.
        #[test]
        fn hiding_leaf_exposes_native_hiding_commitments() {
            let seed = SaltSeed::for_tests(42);
            let t = 3u64;
            let (pr, ks) = (prior(), keys(6, 99));
            let fin_bits = after(&pr, &ks);
            let o = Openings::for_leaf(&seed, BLOOM, t);
            let init = commit_bloom_with(&pr, HIDING, &state_salt(&seed, BLOOM, t - 1));
            let fin = commit_bloom_with(&fin_bits, HIDING, &state_salt(&seed, BLOOM, t));
            let bc = bloom_batch_commit_with(SMALL.batch, &ks, HIDING, &batch_salt(&seed, BLOOM, t));
            assert_ne!(fin, commit_bloom(&fin_bits));
            assert_ne!(bc, bloom_batch_commit(SMALL.batch, &ks));
            let mut iv = build_bloom_omc_leaf_commit(SMALL, Expose::Interval, HIDING);
            assert_eq!(iv.commit_mode(), HIDING);
            let r = iv.prove_epoch_commit(t, &pr, &ks, &o);
            assert_eq!(r.final_bits, fin_bits);
            assert_eq!((r.initial_commit.0, r.final_commit.0, r.batch_commit.0), (init, fin, bc));
            let st = read_exposed_statement(&r.output.0);
            assert_eq!((st.init, st.final_), (init.to_vec(), fin.to_vec()));
            let ip = st.interval.expect("interval part");
            assert_eq!((ip.lo, ip.hi), (Val::from_u64(t), Val::from_u64(t)));
            assert_eq!(ip.digest, leaf_digest(&hash_bb, 4, t, &bc), "H(TAG_LEAF, t, Com(B_t; salt))");
            let r = build_bloom_omc_leaf_commit(SMALL, Expose::None, HIDING).prove_epoch_commit(t, &pr, &ks, &o);
            check_exposed(&r);
            assert_eq!(read_exposed_commitments(&r.output.0), (init, fin, bc));
        }

        /// The Plain leaf through the commit API is the pre-B2 leaf (the
        /// standalone VK pin of [`standalone_leaf_vk_is_pinned`] holds for
        /// it, and every layout's VK equals the `*_expose` builder's); the
        /// hiding VK differs, does not depend on the salts, and is the
        /// zero-salt no-op leaf's. A hiding leaf costs exactly +9 ALU rows (3
        /// salts) and exposes no salt value.
        #[test]
        fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
            let (pr, ks) = (prior(), keys(6, 99));
            let vk = |o: &BloomOmcProof| vk_pin_values(&o.output.0);
            for expose in [Expose::None, Expose::Boundary, Expose::Interval] {
                let old = build_bloom_omc_leaf_expose(SMALL, expose).prove_epoch_at(2, &pr, &ks);
                let plain = build_bloom_omc_leaf_commit(SMALL, expose, CommitMode::Plain).prove_epoch_at(2, &pr, &ks);
                assert_eq!(vk(&plain), vk(&old), "{expose:?}: Plain VK");
                assert_eq!(
                    (plain.initial_commit, plain.final_commit, plain.batch_commit),
                    (old.initial_commit, old.final_commit, old.batch_commit),
                    "{expose:?}"
                );
                let mut leaf = build_bloom_omc_leaf_commit(SMALL, expose, HIDING);
                let o5 = Openings::for_leaf(&SaltSeed::for_tests(1), BLOOM, 5);
                let a = leaf.prove_epoch_commit(5, &pr, &ks, &o5);
                let b = leaf.prove_epoch_commit(
                    1,
                    &bloom_empty(&SMALL),
                    &ks,
                    &Openings::for_leaf(&SaltSeed::for_tests(2), BLOOM, 1),
                );
                assert_ne!(vk(&a), vk(&old), "{expose:?}: the hiding circuit differs");
                assert_eq!(vk(&a), vk(&b), "{expose:?}: salt-independent VK");
                assert_eq!(proof_alu_rows(&a.output.0), proof_alu_rows(&old.output.0) + 9, "{expose:?}: ALU rows");
                assert_eq!(leaked_salts(&a.output.0, &[o5.init, o5.final_, o5.batch]), vec![], "{expose:?}");
                let mut control = SaltBb::ZERO;
                control.0[0] = a.final_commit.0[0];
                assert!(!leaked_salts(&a.output.0, &[control]).is_empty(), "{expose:?}: the scan sees the statement");
                if expose == Expose::Interval {
                    assert_eq!(vk_pin_values(&bloom_omc_noop_leaf_expose(SMALL, expose)), vk(&old));
                    assert_eq!(vk_pin_values(&bloom_omc_noop_leaf_commit(SMALL, expose, CommitMode::Plain)), vk(&old));
                    assert_eq!(vk_pin_values(&bloom_omc_noop_leaf_commit(SMALL, expose, HIDING)), vk(&a));
                }
            }
        }

        /// A hiding leaf never falls back to zero salts silently: the old
        /// entry points panic, and so do zero final / batch salts and a zero
        /// init on a real prior (or at `t ≥ 2`); the explicit no-op path
        /// accepts only the empty filter with no key at `t = 1`, and then
        /// exposes `init == final == Com(0^M; 0)`. Controls: leaf 1 from the
        /// empty filter opens `Com(S_0; 0)`, and a Plain leaf ignores its
        /// openings.
        #[test]
        fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
            let seed = SaltSeed::for_tests(43);
            let (pr, ks) = (prior(), keys(6, 99));
            let empty = bloom_empty(&SMALL);
            let mut leaf = build_bloom_omc_leaf_commit(SMALL, Expose::Interval, HIDING);
            let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, &pr, &ks).final_commit).unwrap_err();
            assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
            assert!(forge::catch(|| leaf.prove_epoch(&pr, &ks).final_commit).is_none());
            let honest = Openings::for_leaf(&seed, BLOOM, 2);
            for (what, o) in [
                ("plain", Openings::plain()),
                ("zero final", Openings { final_: SaltBb::ZERO, ..honest }),
                ("zero batch", Openings { batch: SaltBb::ZERO, ..honest }),
            ] {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(2, &pr, &ks, &o).final_commit).unwrap_err();
                assert!(msg.contains("public zero salt"), "{what}: {msg}");
            }
            let forgot = Openings { init: SaltBb::ZERO, ..honest };
            for (what, t, init) in [("real prior", 2u64, &pr), ("t = 2 on the empty filter", 2, &empty)] {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(t, init, &ks, &forgot).final_commit).unwrap_err();
                assert!(msg.contains("zero init salt"), "{what}: {msg}");
            }
            let local = Openings::for_leaf(&seed, BLOOM, 1);
            let msg = forge::catch_msg(|| leaf.prove_epoch_commit(1, &pr, &ks, &local).final_commit).unwrap_err();
            assert!(msg.contains("zero init salt"), "leaf-1 openings on a real prior: {msg}");
            for (what, t, init, k) in [
                ("a real prior", 1u64, &pr, vec![]),
                ("a real key", 1, &empty, keys(1, 5)),
                ("another batch index", 2, &empty, vec![]),
            ] {
                let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(t, init, &k).final_commit).unwrap_err();
                assert!(msg.contains("no-op leaf"), "{what}: {msg}");
            }
            let noop = leaf.prove_epoch_public_zero(1, &empty, &[]);
            let z = commit_bloom_with(&empty, HIDING, &SaltBb::ZERO);
            assert_eq!((noop.initial_commit.0, noop.final_commit.0), (z, z));
            let st = read_exposed_statement(&noop.output.0);
            assert_eq!(st.init, st.final_, "the zero-salt no-op leaf exposes init == final");
            let r = leaf.prove_epoch_commit(1, &empty, &ks, &local);
            assert_eq!(r.initial_commit.0, z, "leaf 1 opens the public genesis Com(S_0; 0)");
            let mut plain = build_bloom_omc_leaf_commit(SMALL, Expose::Interval, CommitMode::Plain);
            let p = plain.prove_epoch_commit(2, &pr, &ks, &honest);
            assert_eq!(p.initial_commit.0, commit_bloom(&pr), "Plain ignores the openings");
            assert_eq!(p.batch_commit.0, bloom_batch_commit(SMALL.batch, &ks));
        }

        /// Hiding leaves chain: leaf `t`'s final and leaf `t + 1`'s init are
        /// the same `Com(S_t; ρ^S_t)`, and the forest merge of two hiding
        /// leaves verifies (an inconsistent init salt breaks the merge's
        /// in-circuit boundary bind).
        #[test]
        fn hiding_leaves_chain_and_merge() {
            use crate::recursion::recursive::expose_forest::prove_hiding_merge;
            let seed = SaltSeed::for_tests(44);
            let (k1, k2) = (keys(6, 1), keys(5, 2));
            let s1 = after(&bloom_empty(&SMALL), &k1);
            let mut leaf = build_bloom_omc_leaf_commit(SMALL, Expose::Interval, HIDING);
            let l1 = leaf.prove_epoch_commit(1, &bloom_empty(&SMALL), &k1, &Openings::for_leaf(&seed, BLOOM, 1));
            let l2 = leaf.prove_epoch_commit(2, &s1, &k2, &Openings::for_leaf(&seed, BLOOM, 2));
            assert_eq!(l1.final_commit, l2.initial_commit, "leaf 1's final is leaf 2's init");
            let root = prove_hiding_merge(&l1.output, &l2.output);
            let st = read_exposed_statement(&root.0);
            assert_eq!(st.init, l1.initial_commit.0.to_vec());
            assert_eq!(st.final_, l2.final_commit.0.to_vec());
            let bad = Openings { init: state_salt(&SaltSeed::for_tests(45), BLOOM, 1), ..Openings::for_leaf(&seed, BLOOM, 2) };
            let l2b = leaf.prove_epoch_commit(2, &s1, &k2, &bad);
            assert_ne!(l1.final_commit, l2b.initial_commit);
            let r = forge::catch_msg(|| {
                let _ = prove_hiding_merge(&l1.output, &l2b.output);
            });
            assert!(r.is_err(), "a merge across inconsistent salts must fail");
        }
    }
}
