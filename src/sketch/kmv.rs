//! **KMV / bottom-`k` distinct-counting leaf (`kmv`)** — a Pattern-B
//! (verified sorted reduction) instance: the k-minimum-values sketch of
//! Bar-Yossef et al. (KMV) / Cohen–Kaplan (bottom-`k`).
//!
//! ## Sketch semantics
//!
//! * **Hash.** `h(x) = Poseidon2(k0, k1, k2, k3)[0] mod 2^HASH_BITS` over
//!   the key's four exact 16-bit limbs ([`crate::sketch::bind::key_limbs`],
//!   the `Semantic` CM/HLL `omc` key encoding), `HASH_BITS = 27`.
//! * **State.** The `k` smallest DISTINCT hash values over every key seen,
//!   stored in ascending order in `k` rows `(h, act)`. Fewer than `k`
//!   distinct values ⇒ the tail rows are inactive sentinels `(0, 0)` (an
//!   inactive row is always canonical: `act = 0 ⇒ h = 0`).
//! * **Batch rule.** `S_t = bottom_k(S_{t-1} ∪ {h(x) : x a real record of
//!   B_t})`, where `bottom_k(X)` is the set of the `k` smallest elements of
//!   the set `X` (all of `X` when `|X| < k`). Dummy records (`act = 0`)
//!   contribute nothing.
//! * **Estimate.** With `D` active values: `D` (exact) when `D < k`, else
//!   `floor((k − 1)·2^HASH_BITS / v_k)`, `v_k` = the `k`-th smallest value.
//!
//! **Batch rule = per-record insertion.** Per-record insertion is
//! `S ← bottom_k(S ∪ {h(x)})`. For sets `X, Y`: every element of
//! `bottom_k(X ∪ Y)` that lies in `X` has at most as many smaller elements in
//! `X` as in `X ∪ Y`, so it lies in `bottom_k(X)`; hence `bottom_k(X ∪ Y) ⊆
//! bottom_k(X) ∪ Y ⊆ X ∪ Y`, and `bottom_k` of any set squeezed between
//! `bottom_k(Z)` and `Z` is `bottom_k(Z)`. So `bottom_k(bottom_k(X) ∪ Y) =
//! bottom_k(X ∪ Y)`, and by induction over the records of a batch, inserting
//! them one at a time (in any order, with any repetitions) gives the batch
//! rule ([`kmv_insert_each`] vs [`kmv_advance`], `tests::batch_rule_equals_per_record`).
//!
//! ## Hash width (`HASH_BITS = 27`)
//!
//! * **Sound comparisons.** Every hash value is `< 2^27` and every order check
//!   range-checks a difference into `[0, 2^27)`. A "negative" difference
//!   `−δ` (`0 < δ < 2^27`) is the field element `p − δ ≥ p − 2^27 = 14·2^27 + 1
//!   ≫ 2^27`, so it cannot pass (BabyBear `p = 15·2^27 + 1`). This works for
//!   any width with `2^(b+1) < p`, i.e. `b ≤ 29`.
//! * **Canonical, near-uniform extraction.** `2^27 | p − 1`, so the digest
//!   limb splits uniquely as `limb = h + 2^27·hi` with `h < 2^27`, `hi ≤ 15`,
//!   and `hi = 15 ⇒ h = 0` (`p − 1 = 15·2^27`): one canonical split, no
//!   `x + p` alias (`tests::attack_noncanonical_split_rejected`). `27` is the
//!   widest such width (`2^28 ∤ p − 1`). Each value
//!   `< 2^27` has 15 preimages in `[0, p)` (value 0 has 16), so `h` is
//!   uniform up to an excess mass `1/p` on the single value 0.
//! * **Collisions among the `k` smallest at `n = 2^20` distinct keys.**
//!   KMV estimates the number of distinct HASH values; two keys whose hashes
//!   collide count once. The expected number of colliding pairs among the
//!   keys whose hashes fall in the bottom-`k` region (`≈ k·2^b/n` values,
//!   holding `≈ k` keys) is `≈ k²/(2·k·2^b/n) = k·n/2^(b+1)`, a relative
//!   undercount of `n/2^(b+1)`. At `b = 27`, `n = 2^20`: `2^-8 ≈ 0.39%`
//!   (4 pairs at `k = 1024`, 16 at `k = 4096`), 4–8× below KMV's own
//!   standard error `1/√(k−2)` (3.1% at `k = 1024`, 1.6% at `k = 4096`). The
//!   aligned alternative `b = 24` would give `3.1%` (32 / 128 pairs), as large
//!   as the sampling error. Ties are well defined either way: equal hash values
//!   are one distinct value (`tests::circuit_matches_native_*` uses a real
//!   27-bit collision between two distinct keys).
//! * **Range-check exactness.** Order checks only need SOME bound below
//!   `p − 2^27`, so they use one `add_range_bits(·, 27)` (exact on the pinned
//!   fork, which looks the top byte up unshifted and shifted —
//!   `bind::probe::fork_binds_range_top_byte`; `< 2^27 + 2^24` on the older
//!   rev, still sound). The hash split, which binds `h` to the key, uses the
//!   two-sided [`range_hash_exact`] (`x` and `2^27 − 1 − x` both in 27 bits),
//!   exact on either rev.
//!
//! ## The certificate (fixed shape, `n = k + m` rows)
//!
//! ```text
//!   U = S_{t-1} rows ⊎ {(act·h(x), act) : records}       (old state ⊎ batch)
//!   V = U sorted (actives ascending by h, then (0,0))    (prover-supplied)
//!   op 1: U → V  (Permute, tag SORT)
//!   V: act non-increasing; act_{r+1}·(h_{r+1} − h_r) ∈ [0, 2^27)
//!   f_r  = [h_r ≠ h_{r−1}] (f_0 = 1)  — exact is-equal gadget (tag + inverse)
//!   df_r = act_r·f_r,  rank_r = Σ_{j≤r} df_j,  D = rank_{n−1}
//!   w    = boolean, non-increasing,  keep_r = df_r·w_r,  K = Σ keep_r
//!   K = min(k, D):  k − K ≥ 0,  D − K ≥ 0,  (k − K)(D − K) = 0
//!   op 2: {keep_r·(h_r, rank_r)} ⊎ … → {act'_j·(S_t[j], j + 1)}_{j<k} ⊎ 0^m
//!         (Permute, tag COMPACT)
//! ```
//!
//! `V` is the unique sorted arrangement of `U` (equal elements are equal
//! values), `f` is forced by the is-equal gadget, the kept rows are the first
//! `K = min(k, D)` distinct active values (a monotone `w` cuts a prefix of the
//! `df` rows, the count pins where), and op 2 places the rank-`j` kept value in
//! slot `j − 1`: the active slots are exactly `0..K`, in ascending order, and
//! every other slot is the canonical sentinel. The union is never trusted to
//! be grouped by the prover: grouping is FORCED by sortedness, which is what
//! closes the fragmentation break the SpaceSaving circuit once had (a
//! scattered key re-enters as a "new" distinct value; `tests::attack_unsorted_union_rejected`).
//!
//! **Shared PermuteBus.** The fork's Permute ops of one circuit share one bus
//! with no op id, so what is proven is `op1_in ⊎ op2_in = op1_out ⊎ op2_out`.
//! Every op-1 element is `(h, act, SORT_OP_TAG, 1)`, every op-2 element is
//! `(h, rank, COMPACT_OP_TAG, 1)` or the zero dummy, all coordinates
//! base-pinned, so counting each tag class separately restores the two
//! per-op equalities. Without the tags a rank-1 compaction element
//! `(v, 1, ·, 1)` equals the sort element of an active `v`, and a prover can
//! trade the two to drop the smallest value
//! (`tests::attack_cross_permute_exchange_rejected` mounts it).
//!
//! The old state need not be well formed for this to hold: the union is
//! re-sorted, so the transition is `bottom_k` over the SET of its active
//! values, and every state the leaf commits is well formed (ascending,
//! distinct, sentinel tail) by construction.
//!
//! **Dummies.** A record with `act = 0` must have all key limbs 0 (canonical,
//! so `Com(B_t)` is a function of the real records), and it enters `U` as the
//! sentinel `(0, 0)`: it can never be kept.
//!
//! ## Commitments and statement
//!
//! * `Com(S) = MyHash([TAG_KMV_STATE, k, 0, 0] ‖ p_0 … p_{k−1})`, `p_j = h_j +
//!   2^27·act_j` (four per extension element). The family tag `"KMVS"`
//!   separates it from every other family's state digest.
//! * `Com(B) = MyHash([TAG_KMV_BATCH, m, 0, 0] ‖ rec_0 … rec_{m−1})`, `rec =
//!   [k0, k1, k2, k3 + 2^16·act]` (the `bloom_omc` record encoding): the
//!   batch commitment absorbs the key limbs and the activity flags in-circuit.
//! * The statement layouts are those of every other leaf ([`Expose`]); the
//!   Interval layout is [`statement::expose_leaf_interval`] over the
//!   in-circuit batch digest with [`IndexPin::Range`].
//!
//! ## Hiding commitments (revision B2)
//!
//! [`build_kmv_leaf_commit`] takes a [`CommitMode`]. `Plain` is the leaf
//! above op for op (no new op, same VK: [`build_kmv_leaf_expose`] delegates
//! to it). Under `Hiding` the three commitments absorb the prefix `[kind,
//! family, 0, 0, ρ_0..ρ_11]` of [`crate::commitment::hiding`] (tag
//! `TAG_STATE` / `TAG_BATCH`, family [`CommitFamily::Kmv`] = 6) before the
//! same header and rows / records, with the three salts (init, final, batch)
//! the FIRST private inputs; natively [`commit_kmv_state_with`],
//! [`commit_kmv_rows_with`] and [`kmv_batch_commit_with`]. The salts are
//! witnesses (each gets an ALU creator, [`hiding::alloc_salt_targets`]),
//! hashed with the leaf's own sponge under its binding
//! ([`hiding::commit_hash`]), so binding holds for every `ρ`. A hiding leaf
//! is proved with [`KmvLeafCircuit::prove_epoch_commit`] (or
//! [`KmvLeafCircuit::prove_records_commit`]) and the prover's openings of
//! leaf `t`; `prove_epoch_at` / `prove_records_at` refuse to run on it, and
//! the one zero-salt path, [`KmvLeafCircuit::prove_records_public_zero`],
//! accepts only the public no-op input of the VK-derivation leaf (the empty
//! state and an all-dummy batch at `t = 1`). The decoder twin is
//! [`crate::decode::kmv::prove_kmv_decode_commit`].
//!
//! ## Binding
//!
//! The state values, records and certificate tables are base-pinned private
//! inputs recomposed through the ALU, so nothing here depends on the fork
//! binding decomposition coefficients — except the routing digest's limb 0,
//! read through [`bind::decompose`] exactly as the `hll_omc` leaf reads it
//! (`Semantic`: the merged fork binds it; `Bound`: ALU re-binding plus base
//! pins). There is no pre-fix (`Legacy`) KMV circuit: the family was written
//! after the binding fixes, so [`kmv_binding`] builds `Binding::Legacy` (e.g.
//! a `ZKSKETCH_BINDING=legacy` side-by-side run) as the `Semantic` circuit,
//! with a one-time stderr note, instead of panicking. The leaf's
//! [`KmvLeafCircuit::binding`] reports the binding actually built, and a
//! "legacy" KMV number is the `Semantic` cost.
//!
//! ## Cost
//!
//! Two Permute ops over `n = k + m` elements, per row a constant number of
//! range checks (two 27-bit), ALU rows and two element encodings, the two
//! state sponges (`≈ k/8` permutations each), and per record one key-hash
//! permutation plus half a batch-sponge permutation: **`Θ(k + m)`** rows.
//!
//! Measured (2026-10-08, `tests::kmv_measure`, shared 64-core box under load
//! (load average ≈ 30), release profile, `Semantic`, Interval statement, one
//! epoch from a full prior state): `k = m = 1024` → 206,848 trace rows, prove
//! ≈ 0.8 s, proof ≈ 588 KB; `k = m = 4096` → 824,320 rows, ≈ 2.4–2.8 s,
//! ≈ 654 KB; `k = m = 16384` → 3,294,208 rows, ≈ 7.3 s, ≈ 725 KB (verify
//! ≈ 20 ms throughout). The ALU (`2^17 / 2^19 / 2^21` rows) and Range
//! (`2^16 / 2^18 / 2^20`) tables dominate; the Permute table is `2n` rows.

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

use crate::commitment::hiding::{
    self, CommitFamily, CommitKind, CommitMode, Openings, SaltBb, SaltTargets,
};
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{DIGEST_PACKING, make_leaf_config};
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::sketch::bind::{self, Binding};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Hash width `b`: values live in `[0, 2^27)` (see the module doc).
pub const HASH_BITS: usize = 27;
/// `2^HASH_BITS`.
const HASH_RANGE: u64 = 1 << HASH_BITS;
/// `(p − 1) / 2^HASH_BITS`: the largest high part of a canonical digest limb.
const HI_MAX: u64 = 15;
/// Exact width of the high part: `hi ∈ [0, 2^HI_BITS) = [0, HI_MAX]`.
const HI_BITS: usize = 4;
/// `act` sits at bit 16 of the fourth record coefficient (`bloom_omc`).
const KEY_ACT_SHIFT: u64 = 1 << 16;
/// Range window of the cut counts `k − K` and `D − K` (`k + m < 2^24`).
const COUNT_BITS: usize = 24;
/// Largest supported `k`: the decoder's numerator `(k − 1)·2^27` must stay
/// below `2^42` (three base-2^14 digits).
pub const MAX_K: usize = 1 << 15;
/// Family tag of the state commitment (`"KMVS"` in ASCII, `< p`).
pub const TAG_KMV_STATE: u64 = 0x4B4D_5653;
/// Family tag of the batch commitment (`"KMVB"` in ASCII, `< p`).
pub const TAG_KMV_BATCH: u64 = 0x4B4D_5642;
/// Coordinate-2 tag of every element the sort permute (op 1) moves.
const SORT_OP_TAG: u64 = 1;
/// Coordinate-2 tag of every non-dummy element the compaction permute
/// (op 2) moves.
const COMPACT_OP_TAG: u64 = 2;

// ─── Test-only ablations (each removes ONE check, to show it is the one that
// rejects an attack; see the `attack_*` tests) ────────────────────────────────

/// Untagged permute encodings (both ops on the same layout, pre-fix shared bus).
const ABL_OP_TAG: u32 = 1;
/// Drop the `e = 0 ⇒ h_r ≠ h_{r−1}` half of the is-equal gadget (`e` stays boolean).
const ABL_EQ_NE: u32 = 2;
/// Drop the gated sortedness range check on `V`.
const ABL_SORT: u32 = 4;
/// Drop the `K = min(k, D)` cut check.
const ABL_MIN_K: u32 = 8;
/// Drop the range check on the hash split's high part (`hi ≤ HI_MAX`).
const ABL_SPLIT: u32 = 16;
/// Drop the hash split's `hi = HI_MAX ⇒ h = 0` check (the `x + p` alias guard).
const ABL_CANON: u32 = 32;
/// Drop the canonical-sentinel check `act' = 0 ⇒ h' = 0` on the NEW state rows.
const ABL_SENTINEL: u32 = 64;

#[cfg(test)]
thread_local! {
    static ABLATE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// The ablation mask builders on this thread read (always 0 outside tests).
fn ablation() -> u32 {
    #[cfg(test)]
    {
        ABLATE.with(|c| c.get())
    }
    #[cfg(not(test))]
    {
        0
    }
}

fn p_u64() -> u64 {
    <Val as PrimeField64>::ORDER_U64
}

// ─── Parameters and native model ─────────────────────────────────────────────

/// Shape of a KMV leaf: capacity `k` and record slots per batch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KmvParams {
    /// Capacity: the number of smallest distinct hash values kept.
    pub k: usize,
    /// Record slots per batch; shorter batches are padded with dummies.
    pub batch: usize,
}

impl KmvParams {
    /// Rows of the sorted union `V`: `k + batch`.
    pub fn union_size(&self) -> usize {
        self.k + self.batch
    }
    pub fn validate(&self) {
        if let Err(e) = self.check() {
            panic!("{e}");
        }
    }
    /// [`Self::validate`] without the panic: the reason a shape is rejected,
    /// for callers that report bad configuration instead of aborting.
    pub fn check(&self) -> Result<(), String> {
        if !(self.k >= 4 && self.k.is_multiple_of(4) && self.k <= MAX_K) {
            return Err(format!("k must be a multiple of 4 in 4..={MAX_K}, got {}", self.k));
        }
        if self.batch < 1 {
            return Err("batch must be ≥ 1".into());
        }
        if self.union_size() >= (1usize << COUNT_BITS) {
            return Err(format!("k + batch must be < 2^{COUNT_BITS}"));
        }
        Ok(())
    }
}

/// Poseidon2 digest limb 0 of `key` (exact 16-bit limbs, the `Semantic`
/// key encoding), as a canonical integer `< p`.
fn digest_limb0(key: u64) -> u64 {
    let hasher = MyHash::new(make_perm());
    let d: [Val; 8] = hasher.hash_iter(bind::key_limbs::<Val>(key));
    d[0].as_canonical_u64()
}

/// The KMV hash `h(key) = digest[0] mod 2^HASH_BITS` (the in-circuit value).
pub fn kmv_hash(key: u64) -> u32 {
    (digest_limb0(key) & (HASH_RANGE - 1)) as u32
}

/// A KMV state: the active values, ascending and distinct (at most `k`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KmvState {
    pub k: usize,
    pub vals: Vec<u32>,
}

impl KmvState {
    /// The empty state (`k` sentinels).
    pub fn empty(k: usize) -> Self {
        Self { k, vals: Vec::new() }
    }

    /// `k` active values.
    pub fn is_full(&self) -> bool {
        self.vals.len() == self.k
    }

    /// The `k` committed rows `(h, act)`: the values, then `(0, 0)` sentinels.
    pub fn rows(&self) -> Vec<(u32, u32)> {
        assert!(self.vals.len() <= self.k);
        let mut r: Vec<(u32, u32)> = self.vals.iter().map(|&h| (h, 1)).collect();
        r.resize(self.k, (0, 0));
        r
    }

    /// Per-record insertion `S ← bottom_k(S ∪ {h})`.
    pub fn insert_hash(&mut self, h: u32) {
        if let Err(pos) = self.vals.binary_search(&h) {
            self.vals.insert(pos, h);
            self.vals.truncate(self.k);
        }
    }

    /// The distinct-count estimate (module doc).
    pub fn estimate(&self) -> u64 {
        kmv_estimate(self)
    }
}

/// The batch rule: `bottom_k(S ∪ {h(x) : x ∈ keys})`.
pub fn kmv_advance(state: &KmvState, keys: &[u64]) -> KmvState {
    let mut all: Vec<u32> = state.vals.clone();
    all.extend(keys.iter().map(|&x| kmv_hash(x)));
    all.sort_unstable();
    all.dedup();
    all.truncate(state.k);
    KmvState { k: state.k, vals: all }
}

/// Reference per-record insertion (equals [`kmv_advance`]; module doc).
pub fn kmv_insert_each(state: &KmvState, keys: &[u64]) -> KmvState {
    let mut s = state.clone();
    for &x in keys {
        s.insert_hash(kmv_hash(x));
    }
    s
}

/// Distinct-count estimate: the exact count below capacity, else
/// `floor((k − 1)·2^HASH_BITS / v_k)`.
pub fn kmv_estimate(state: &KmvState) -> u64 {
    let k = state.k;
    if state.vals.len() < k {
        state.vals.len() as u64
    } else {
        let vk = state.vals[k - 1] as u64;
        assert!(vk > 0, "v_k = 0 is impossible for k ≥ 2 distinct values");
        ((k as u64 - 1) << HASH_BITS) / vk
    }
}

/// `p_j = h_j + 2^HASH_BITS·act_j` of a row (the committed per-row value).
fn row_value((h, act): (u32, u32)) -> Val {
    Val::from_u64(h as u64 + ((act as u64) << HASH_BITS))
}

/// The flat input of `Com(S)` over explicit rows: `[TAG_KMV_STATE, k, 0, 0]
/// ‖ p_0 … p_{k−1}` (`4 + k` values, a multiple of 4).
fn state_flat(k: usize, rows: &[(u32, u32)]) -> Vec<Val> {
    assert_eq!(rows.len(), k);
    let mut flat = vec![Val::from_u64(TAG_KMV_STATE), Val::from_u64(k as u64), Val::ZERO, Val::ZERO];
    flat.extend(rows.iter().map(|&r| row_value(r)));
    flat
}

/// `Com(S)` of explicit rows (`k` of them; rows need not be well formed —
/// the forgery tests commit to malformed states).
pub fn commit_kmv_rows(k: usize, rows: &[(u32, u32)]) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    hasher.hash_iter(state_flat(k, rows))
}

/// `Com(S)`.
pub fn commit_kmv_state(state: &KmvState) -> [Val; 8] {
    commit_kmv_rows(state.k, &state.rows())
}

/// [`commit_kmv_rows`] under `mode` (revision B2): `Plain` is exactly
/// [`commit_kmv_rows`] (`salt` ignored); `Hiding` is
/// `MyHash([TAG_STATE, Kmv, 0, 0, ρ] ‖ [TAG_KMV_STATE, k, 0, 0] ‖ p_0 …)`
/// over the same flat, the value a hiding leaf exposes for `Com(S; ρ)`.
pub fn commit_kmv_rows_with(k: usize, rows: &[(u32, u32)], mode: CommitMode, salt: &SaltBb) -> [Val; 8] {
    match mode {
        CommitMode::Plain => commit_kmv_rows(k, rows),
        CommitMode::Hiding => {
            hiding::commit_flat_bb(mode, CommitKind::State, CommitFamily::Kmv, salt, &state_flat(k, rows))
        }
    }
}

/// [`commit_kmv_state`] under `mode` (revision B2): the `Com(S; ρ)` a hiding
/// leaf exposes and a hiding distinct-count query opens.
pub fn commit_kmv_state_with(state: &KmvState, mode: CommitMode, salt: &SaltBb) -> [Val; 8] {
    commit_kmv_rows_with(state.k, &state.rows(), mode, salt)
}

/// A record as the circuit sees it: `(key, act)`; a real key is `(x, 1)`,
/// the canonical dummy `(0, 0)`.
fn rec_raw(rec: Option<u64>) -> (u64, u32) {
    rec.map_or((0, 0), |x| (x, 1))
}

/// The record encoding `[k0, k1, k2, k3 + 2^16·act]` (the canonical dummy is
/// `[0, 0, 0, 0]`).
fn record_vals((key, act): (u64, u32)) -> [Val; 4] {
    let l = bind::key_limbs::<Val>(key);
    [l[0], l[1], l[2], l[3] + Val::from_u64(KEY_ACT_SHIFT * act as u64)]
}

/// Real keys padded with dummies to `params.batch` records.
pub fn kmv_records(params: &KmvParams, keys: &[u64]) -> Vec<Option<u64>> {
    assert!(keys.len() <= params.batch, "{} keys exceed batch {}", keys.len(), params.batch);
    let mut recs: Vec<Option<u64>> = keys.iter().map(|&x| Some(x)).collect();
    recs.resize(params.batch, None);
    recs
}

/// `Com(B)` of an explicit record sequence (`params.batch` records).
pub fn commit_kmv_records(params: &KmvParams, records: &[Option<u64>]) -> [Val; 8] {
    kmv_batch_commit(params.batch, records)
}

/// [`commit_kmv_records`] from the slot count alone: `Com(B)` depends on the
/// `batch` record slots, not on the capacity `k`. What a public batch log
/// lists for the leaf.
pub fn kmv_batch_commit(batch: usize, records: &[Option<u64>]) -> [Val; 8] {
    kmv_batch_commit_with(batch, records, CommitMode::Plain, &SaltBb::ZERO)
}

/// [`kmv_batch_commit`] under `mode` (revision B2): `Plain` is exactly
/// [`kmv_batch_commit`]; `Hiding` is `MyHash([TAG_BATCH, Kmv, 0, 0, ρ] ‖
/// [TAG_KMV_BATCH, batch, 0, 0] ‖ rec_0 …)` over the same flat, the
/// `Com(B_t; ρ^B_t)` a hiding leaf binds and the prover publishes in the
/// batch log.
pub fn kmv_batch_commit_with(
    batch: usize,
    records: &[Option<u64>],
    mode: CommitMode,
    salt: &SaltBb,
) -> [Val; 8] {
    let raw: Vec<(u64, u32)> = records.iter().map(|&r| rec_raw(r)).collect();
    commit_records_raw_with(batch, &raw, mode, salt)
}

/// The flat input of `Com(B)`: `[TAG_KMV_BATCH, batch, 0, 0] ‖ rec_0 …`
/// (`4 + 4·batch` values).
fn batch_flat(batch: usize, records: &[(u64, u32)]) -> Vec<Val> {
    assert_eq!(records.len(), batch);
    let mut flat = vec![Val::from_u64(TAG_KMV_BATCH), Val::from_u64(batch as u64), Val::ZERO, Val::ZERO];
    flat.extend(records.iter().flat_map(|&r| record_vals(r)));
    flat
}

/// `Com(B)` of raw `(key, act)` records (non-canonical dummies included)
/// under `mode` (the `Plain` arm is the pre-B2 commitment, byte for byte).
fn commit_records_raw_with(batch: usize, records: &[(u64, u32)], mode: CommitMode, salt: &SaltBb) -> [Val; 8] {
    let flat = batch_flat(batch, records);
    match mode {
        CommitMode::Plain => MyHash::new(make_perm()).hash_iter(flat),
        CommitMode::Hiding => hiding::commit_flat_bb(mode, CommitKind::Batch, CommitFamily::Kmv, salt, &flat),
    }
}

/// `Com(B)` of real keys padded with dummies — what the public log publishes.
pub fn commit_kmv_batch(params: &KmvParams, keys: &[u64]) -> [Val; 8] {
    commit_kmv_records(params, &kmv_records(params, keys))
}

/// The canonical split `limb = h + 2^27·hi` and `dinv = (HI_MAX − hi)^{-1}`
/// (0 when `hi = HI_MAX`).
fn split27(limb: u64) -> [Val; 3] {
    debug_assert!(limb < p_u64());
    let h = limb & (HASH_RANGE - 1);
    let hi = limb >> HASH_BITS;
    let dinv = Val::from_u64(HI_MAX - hi).try_inverse().unwrap_or(Val::ZERO);
    [Val::from_u64(h), Val::from_u64(hi), dinv]
}

// ─── Native certificate witness ──────────────────────────────────────────────

/// A row `(h, act)`.
type Row = (u32, u32);

/// Every private table of one epoch. [`honest_witness`] derives it from
/// `(S_{t-1}, B_t)`; the soundness tests hand-craft malicious ones.
#[derive(Clone, Debug)]
struct KmvWitness {
    initial: Vec<Row>,
    /// Raw `(key, act)` records.
    records: Vec<(u64, u32)>,
    /// Per record `(h, hi, dinv)` of its digest limb 0.
    split: Vec<[Val; 3]>,
    /// The sorted union `V`.
    v: Vec<Row>,
    /// `(e_r, inv_r)` for rows `1..n`.
    eq: Vec<(u32, Val)>,
    /// The cut prefix flags.
    w: Vec<u32>,
    /// The new state rows.
    fin: Vec<Row>,
    sigma_sort: Vec<usize>,
    sigma_compact: Vec<usize>,
}

/// The `h` the split witness of a record certifies.
fn split_h(s: &[Val; 3]) -> u32 {
    s[0].as_canonical_u64() as u32
}

/// `U` in circuit order: the old rows, then `(act·h, act)` per record.
fn union_rows(initial: &[Row], records: &[(u64, u32)], split: &[[Val; 3]]) -> Vec<Row> {
    let mut u = initial.to_vec();
    for (&(_, act), s) in records.iter().zip(split) {
        u.push(if act == 1 { (split_h(s), 1) } else { (0, 0) });
    }
    u
}

/// The order `V` must follow: actives ascending by `h`, then sentinels.
fn sort_key(r: &Row) -> (u32, u32) {
    (1 - r.1, r.0)
}

/// `(e_r, inv_r)` for `r ≥ 1`: `e = [h_r = h_{r−1}]`, `inv = (h_r − h_{r−1})^{-1}`.
fn eq_witness(v: &[Row]) -> Vec<(u32, Val)> {
    (1..v.len())
        .map(|r| {
            let diff = Val::from_u32(v[r].0) - Val::from_u32(v[r - 1].0);
            match diff.try_inverse() {
                Some(inv) => (0, inv),
                None => (1, Val::ZERO),
            }
        })
        .collect()
}

/// `df_r = act_r·f_r` and `rank_r = Σ_{j≤r} df_j` (as the circuit computes
/// them from `V` and `e`).
fn distinct_ranks(v: &[Row], eq: &[(u32, u32)]) -> (Vec<u32>, Vec<u32>) {
    let mut df = Vec::with_capacity(v.len());
    let mut rank = Vec::with_capacity(v.len());
    let mut acc = 0u32;
    for r in 0..v.len() {
        let f = if r == 0 { 1 } else { 1 - eq[r - 1].0 };
        let d = v[r].1 * f;
        acc += d;
        df.push(d);
        rank.push(acc);
    }
    (df, rank)
}

/// The kept rows' new state: kept values in `V` order, then sentinels.
fn compact(v: &[Row], df: &[u32], w: &[u32], k: usize) -> Vec<Row> {
    let mut fin: Vec<Row> = (0..v.len())
        .filter(|&r| df[r] * w[r] == 1)
        .map(|r| (v[r].0, 1))
        .collect();
    fin.resize(k.max(fin.len()), (0, 0));
    fin.truncate(k);
    fin
}

/// `σ` with `output[i] == input[σ[i]]`, if `output` is a permutation of `input`.
fn match_sigma<T: Eq + std::hash::Hash + Copy>(input: &[T], output: &[T]) -> Option<Vec<usize>> {
    let mut buckets: HashMap<T, Vec<usize>> = HashMap::new();
    for (i, x) in input.iter().enumerate().rev() {
        buckets.entry(*x).or_default().push(i);
    }
    output.iter().map(|x| buckets.get_mut(x).and_then(|b| b.pop())).collect()
}

/// Compaction-permute elements as `(h, label)` (`None` = the zero dummy):
/// the inputs `keep_r·(h_r, rank_r)` and the outputs `act'_j·(h'_j, j + 1)`
/// followed by `m` dummies.
fn compact_elems(
    v: &[Row],
    df: &[u32],
    rank: &[u32],
    w: &[u32],
    fin: &[Row],
    m: usize,
) -> (Vec<Option<(u32, u32)>>, Vec<Option<(u32, u32)>>) {
    let input = (0..v.len())
        .map(|r| (df[r] * w[r] == 1).then_some((v[r].0, rank[r])))
        .collect();
    let mut output: Vec<Option<(u32, u32)>> = fin
        .iter()
        .enumerate()
        .map(|(j, &(h, a))| (a == 1).then_some((h, j as u32 + 1)))
        .collect();
    output.resize(fin.len() + m, None);
    (input, output)
}

/// Complete a witness from its free tables: `e`/`inv` are recomputed from
/// `v`; `w` (default: `[rank ≤ k]`) and `fin` (default: the compaction of
/// the kept rows) may be overridden; both permutation hints are matched on a
/// best-effort basis (identity when the tables are not permutations — the
/// circuit, not this helper, must reject such a witness).
fn finish_witness(
    params: &KmvParams,
    initial: Vec<Row>,
    records: Vec<(u64, u32)>,
    split: Vec<[Val; 3]>,
    v: Vec<Row>,
    w: Option<Vec<u32>>,
    fin: Option<Vec<Row>>,
) -> KmvWitness {
    let n = params.union_size();
    let k = params.k;
    assert_eq!(initial.len(), k);
    assert_eq!(records.len(), params.batch);
    assert_eq!(v.len(), n);
    let eq = eq_witness(&v);
    let eq_bits: Vec<(u32, u32)> = eq.iter().map(|&(e, _)| (e, 0)).collect();
    let (df, rank) = distinct_ranks(&v, &eq_bits);
    let w = w.unwrap_or_else(|| rank.iter().map(|&r| u32::from(r as usize <= k)).collect());
    let fin = fin.unwrap_or_else(|| compact(&v, &df, &w, k));
    let u = union_rows(&initial, &records, &split);
    let sigma_sort = match_sigma(&u, &v).unwrap_or_else(|| (0..n).collect());
    let (cin, cout) = compact_elems(&v, &df, &rank, &w, &fin, params.batch);
    let sigma_compact = match_sigma(&cin, &cout).unwrap_or_else(|| (0..n).collect());
    KmvWitness { initial, records, split, v, eq, w, fin, sigma_sort, sigma_compact }
}

/// The honest witness of `(S_{t-1}, records)`.
fn honest_witness(params: &KmvParams, initial: &KmvState, records: &[Option<u64>]) -> KmvWitness {
    assert_eq!(initial.k, params.k, "state capacity != params.k");
    let raw: Vec<(u64, u32)> = records.iter().map(|&r| rec_raw(r)).collect();
    let split: Vec<[Val; 3]> = raw.iter().map(|&(x, _)| split27(digest_limb0(x))).collect();
    let mut v = union_rows(&initial.rows(), &raw, &split);
    v.sort_by_key(sort_key);
    finish_witness(params, initial.rows(), raw, split, v, None, None)
}

/// The active values of state rows (in row order).
fn rows_to_state(k: usize, rows: &[Row]) -> KmvState {
    KmvState { k, vals: rows.iter().filter(|r| r.1 == 1).map(|r| r.0).collect() }
}

// ─── In-circuit gadgets ──────────────────────────────────────────────────────

/// Constants shared by the leaf and the decoder.
pub(crate) struct KmvConsts {
    pub(crate) one: ExprId,
    pub(crate) zero: ExprId,
    /// `2^HASH_BITS`.
    pub(crate) two27: ExprId,
    /// `2^HASH_BITS − 1` (the complement in [`range_hash_exact`]).
    pub(crate) hash_max: ExprId,
    /// `[TAG_KMV_STATE, k, 0, 0]`, the state sponge header.
    pub(crate) state_hdr: ExprId,
}

impl KmvConsts {
    pub(crate) fn new(b: &mut CircuitBuilder<Challenge>, k: usize) -> Self {
        let hdr = Challenge::from_basis_coefficients_slice(&[
            Val::from_u64(TAG_KMV_STATE),
            Val::from_u64(k as u64),
            Val::ZERO,
            Val::ZERO,
        ])
        .expect("4 coeffs");
        Self {
            one: b.alloc_const(Challenge::ONE, "one"),
            zero: b.alloc_const(Challenge::ZERO, "zero"),
            two27: b.alloc_const(Challenge::from_u64(HASH_RANGE), "2^27"),
            hash_max: b.alloc_const(Challenge::from_u64(HASH_RANGE - 1), "2^27-1"),
            state_hdr: b.alloc_const(hdr, "kmv_state_hdr"),
        }
    }
}

/// Exact `x ∈ [0, 2^HASH_BITS)` on any fork rev: `x` and `2^27 − 1 − x` both
/// pass a 27-bit `add_range_bits` (each `< 2^27 + 2^24` even where the
/// unaligned top byte is only shift-checked; the second excludes everything
/// above `2^27 − 1`, the first every wrapped "negative" value).
pub(crate) fn range_hash_exact(b: &mut CircuitBuilder<Challenge>, x: ExprId, c: &KmvConsts) {
    b.add_range_bits::<Val>(x, HASH_BITS).expect("hash range");
    let y = b.sub(c.hash_max, x);
    b.add_range_bits::<Val>(y, HASH_BITS).expect("hash range (complement)");
}

/// One state row `(h, act)`: `act` boolean, `h` a 27-bit value (exact when
/// `exact`, else bounded as the order checks need), canonical sentinel
/// (`act = 0 ⇒ h = 0`). Returns `p = h + 2^27·act`.
///
/// The sentinel check is what makes `Com(S)` a function of the logical state:
/// without it a row `(x, 0)`, `x ≠ 0`, packs to `p = x` and the same state
/// has `2^27` commitments per inactive slot (`tests::attack_noncanonical_sentinel_rejected`).
/// `abl` is the test-only ablation mask (0 = every check; only
/// [`ABL_SENTINEL`] is read here, and the leaf passes it for the new state
/// only).
pub(crate) fn state_row_gadget(
    b: &mut CircuitBuilder<Challenge>,
    [h, act]: [ExprId; 2],
    c: &KmvConsts,
    exact: bool,
    abl: u32,
) -> ExprId {
    b.assert_bool(act);
    if exact {
        range_hash_exact(b, h, c);
    } else {
        b.add_range_bits::<Val>(h, HASH_BITS).expect("state value range");
    }
    let oma = b.sub(c.one, act);
    let z = b.mul(oma, h);
    if abl & ABL_SENTINEL == 0 {
        b.connect(z, c.zero);
    }
    b.mul_add(act, c.two27, h)
}

/// `Com(S)` of `k` state rows in-circuit: [`state_row_gadget`] per row, four
/// `p` values per extension element (ALU), then the sponge over the family
/// header and the packed values. Returns the packed elements and the digest.
/// `abl` as in [`state_row_gadget`] (the decoder passes 0). `salt` (revision
/// B2): `None` is the `Plain` sponge, op for op; `Some` prepends the hiding
/// prefix `[tag, salt_0, salt_1, salt_2]` ([`hiding::commit_hash`], family
/// [`CommitFamily::Kmv`]), the in-circuit image of [`commit_kmv_rows_with`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn state_commit_gadget(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    rows: &[[ExprId; 2]],
    c: &KmvConsts,
    binding: Binding,
    exact: bool,
    abl: u32,
    salt: Option<&SaltTargets>,
) -> (Vec<ExprId>, Vec<ExprId>) {
    assert!(rows.len().is_multiple_of(4));
    let ps: Vec<ExprId> = rows.iter().map(|&r| state_row_gadget(b, r, c, exact, abl)).collect();
    let packs: Vec<ExprId> = ps
        .chunks(4)
        .map(|ch| b.recompose_base_coeffs_to_ext_via_alu::<Val>(ch).expect("pack state"))
        .collect();
    let mut inputs = vec![c.state_hdr];
    inputs.extend_from_slice(&packs);
    let digest = hiding::commit_hash::<Val, Challenge>(
        b,
        cfg,
        CommitKind::State,
        CommitFamily::Kmv,
        salt,
        &inputs,
        c.zero,
        binding,
    );
    (packs, digest)
}

/// Canonical split of a digest limb: returns `x = h + 2^27·hi` (connect it to
/// the limb) after constraining `h` exactly to 27 bits, `hi ∈ [0, 16)`
/// (exact, so `hi ≤ HI_MAX = 15`), and `hi = HI_MAX ⇒ h = 0` (via `dinv`,
/// the inverse of `HI_MAX − hi`): the split integer is `≤ p − 1`, the
/// canonical one, so `h` is a function of the limb.
///
/// The last check is the only guard against the `x + p` alias: a limb `x <
/// 2^27 − 1` also splits as `(x + 1) + 15·2^27 = x + p` with both parts in
/// range, which would shift the record's hash to `h(x) + 1`
/// (`tests::attack_noncanonical_split_rejected`).
fn hash_split_gadget(
    b: &mut CircuitBuilder<Challenge>,
    [h, hi, dinv]: [ExprId; 3],
    c: &KmvConsts,
    hi_max: ExprId,
    abl: u32,
) -> ExprId {
    range_hash_exact(b, h, c);
    if abl & ABL_SPLIT == 0 {
        bind::range_exact::<Val, Challenge>(b, hi, HI_BITS);
    }
    let d = b.sub(hi_max, hi);
    let e = b.mul(d, dinv);
    let z = b.sub(c.one, e);
    let chk = b.mul(h, z);
    if abl & ABL_CANON == 0 {
        b.connect(chk, c.zero);
    }
    b.mul_add(hi, c.two27, h)
}

/// The two permute tags under ablation mask `abl` (both 0 when untagged).
fn op_tags(abl: u32) -> (u64, u64) {
    if abl & ABL_OP_TAG != 0 { (0, 0) } else { (SORT_OP_TAG, COMPACT_OP_TAG) }
}

/// A permute element `(x0, x1, tag, 1)` as a native extension element.
#[cfg(test)]
fn elem(x0: u32, x1: u32, tag: u64) -> Challenge {
    Challenge::from_basis_coefficients_slice(&[
        Val::from_u32(x0),
        Val::from_u32(x1),
        Val::from_u64(tag),
        Val::ONE,
    ])
    .expect("4 coeffs")
}

// ─── Proof / circuit types ───────────────────────────────────────────────────

/// A self-verified KMV leaf proof with its natively computed commitments.
pub struct KmvProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: [Val; 8],
    pub final_commit: [Val; 8],
    pub batch_commit: [Val; 8],
    pub final_state: KmvState,
    pub params: KmvParams,
}

impl KmvProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

/// A built, reusable KMV leaf: build once per shape; every proof swaps in its
/// two permutation hints via `Circuit::update_permute_witnesses`.
pub struct KmvLeafCircuit {
    params: KmvParams,
    binding: Binding,
    expose: Expose,
    /// Commitment mode the circuit was built with (revision B2).
    mode: CommitMode,
    /// Ablation mask the circuit was built with (0 outside tests).
    #[cfg_attr(not(test), allow(dead_code))]
    ablate: u32,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    table_rows: Vec<usize>,
}

/// Build the KMV leaf with the process-default [`Binding`] and the
/// `expose_boundary` switch of the other leaves.
pub fn build_kmv_leaf(params: KmvParams, expose_boundary: bool) -> KmvLeafCircuit {
    build_kmv_leaf_expose(params, Expose::from_bool(expose_boundary), bind::default_binding())
}

/// The binding a KMV circuit (leaf or decoder) is built with: `binding`
/// itself, except `Legacy`, which selects `Semantic` (there is no pre-fix KMV
/// circuit; module doc), printing a note to stderr once per process.
pub fn kmv_binding(binding: Binding) -> Binding {
    match binding {
        Binding::Legacy => {
            static NOTED: std::sync::Once = std::sync::Once::new();
            NOTED.call_once(|| {
                eprintln!(
                    "note: KMV has no pre-fix (Legacy) circuit; Binding::Legacy builds the \
                     Semantic KMV leaf and decoder (their cost is reported under legacy)"
                )
            });
            Binding::Semantic
        }
        other => other,
    }
}

/// Build the KMV leaf with an explicit statement layout and binding
/// (`Semantic` or `Bound`; `Legacy` builds `Semantic`, [`kmv_binding`]).
/// `Interval` appends the batch index `t` as the last public input and
/// exposes `(init, final, (t, t, 0, 0), Poseidon2(TAG_LEAF, t, Com(B_t)))`.
/// The `Plain` commitments: [`build_kmv_leaf_commit`] with
/// [`CommitMode::Plain`].
pub fn build_kmv_leaf_expose(params: KmvParams, expose: Expose, binding: Binding) -> KmvLeafCircuit {
    build_kmv_leaf_commit(params, expose, binding, CommitMode::Plain)
}

/// [`build_kmv_leaf_expose`] under the commitment mode `mode` (revision B2,
/// module doc "Hiding commitments"). `Plain` is the pre-B2 circuit op for op
/// (same VK). `Hiding` allocates the three salts (init, final, batch) as the
/// first private inputs and absorbs them, behind the kind/family tag, into
/// `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)`; prove it with
/// [`KmvLeafCircuit::prove_epoch_commit`].
pub fn build_kmv_leaf_commit(
    params: KmvParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
) -> KmvLeafCircuit {
    params.validate();
    let binding = kmv_binding(binding);
    let abl = ablation();
    let (sort_tag, compact_tag) = op_tags(abl);
    let KmvParams { k, batch: m } = params;
    let n = k + m;

    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    crate::recompose_binding::configure(&mut b);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    if expose.exposes() {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    if expose == Expose::Boundary {
        b.add_expose(&[init_pis[0], init_pis[1], final_pis[0], final_pis[1]])
            .expect("add_expose boundary");
    }
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));

    let c = KmvConsts::new(&mut b, k);
    let one = c.one;
    let zero = c.zero;
    let hi_max = b.alloc_const(Challenge::from_u64(HI_MAX), "hi_max");
    let act16 = b.alloc_const(Challenge::from_u64(KEY_ACT_SHIFT), "2^16");
    let k_const = b.alloc_const(Challenge::from_u64(k as u64), "k");
    let batch_hdr = b.alloc_const(
        Challenge::from_basis_coefficients_slice(&[
            Val::from_u64(TAG_KMV_BATCH),
            Val::from_u64(m as u64),
            Val::ZERO,
            Val::ZERO,
        ])
        .expect("4 coeffs"),
        "kmv_batch_hdr",
    );
    // e1 = X (coordinate 1); `(0, 0, tag, 1)` bases of the two element classes.
    let e1 = b.alloc_const(
        Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE, Val::ZERO, Val::ZERO])
            .expect("4 coeffs"),
        "e1",
    );
    let class_base = |b: &mut CircuitBuilder<Challenge>, tag: u64, label: &'static str| {
        b.alloc_const(
            Challenge::from_basis_coefficients_slice(&[
                Val::ZERO,
                Val::ZERO,
                Val::from_u64(tag),
                Val::ONE,
            ])
            .expect("4 coeffs"),
            label,
        )
    };
    let sort_base = class_base(&mut b, sort_tag, "sort_class");
    let compact_base = class_base(&mut b, compact_tag, "compact_class");
    // `(x0, x1, tag, 1)` from base-pinned `x0`, `x1` (two ALU rows).
    let enc = |b: &mut CircuitBuilder<Challenge>, x0: ExprId, x1: ExprId, base: ExprId| -> ExprId {
        let lo = b.add(x0, base);
        b.mul_add(x1, e1, lo)
    };
    let labels: Vec<ExprId> =
        (0..k).map(|j| b.alloc_const(Challenge::from_u64(j as u64 + 1), "slot_label")).collect();

    // ── Private inputs (allocation order == push order in `inputs`) ──
    // B2: under `Hiding` the 9 salt inputs (init, final, batch) come first;
    // `Plain` allocates nothing.
    let salts = hiding::alloc_leaf_salts(&mut b, mode);
    let s_old: Vec<[ExprId; 2]> =
        (0..k).map(|_| std::array::from_fn(|_| b.alloc_private_input("old_row"))).collect();
    let s_new: Vec<[ExprId; 2]> =
        (0..k).map(|_| std::array::from_fn(|_| b.alloc_private_input("new_row"))).collect();
    let rec: Vec<[ExprId; 5]> =
        (0..m).map(|_| std::array::from_fn(|_| b.alloc_private_input("record"))).collect();
    let split: Vec<[ExprId; 3]> =
        (0..m).map(|_| std::array::from_fn(|_| b.alloc_private_input("split"))).collect();
    let v: Vec<[ExprId; 2]> =
        (0..n).map(|_| std::array::from_fn(|_| b.alloc_private_input("v_row"))).collect();
    let eq: Vec<[ExprId; 2]> =
        (1..n).map(|_| std::array::from_fn(|_| b.alloc_private_input("eq"))).collect();
    let w: Vec<ExprId> = (0..n).map(|_| b.alloc_private_input("w")).collect();

    // ── Stage A: both states → their commitments ──
    let (_, d_old) = state_commit_gadget(
        &mut b,
        &cfg,
        &s_old,
        &c,
        binding,
        false,
        0,
        salts.as_ref().map(|s| &s.init),
    );
    let (_, d_new) = state_commit_gadget(
        &mut b,
        &cfg,
        &s_new,
        &c,
        binding,
        false,
        abl,
        salts.as_ref().map(|s| &s.final_),
    );
    for i in 0..DIGEST_PACKING {
        b.connect(d_old[i], init_pis[i]);
        b.connect(d_new[i], final_pis[i]);
    }

    // ── Stage B: records → batch commitment; key hash → h; U elements ──
    let mut u_elems: Vec<ExprId> = Vec::with_capacity(n);
    for row in &s_old {
        u_elems.push(enc(&mut b, row[0], row[1], sort_base));
    }
    let mut recs: Vec<ExprId> = Vec::with_capacity(m + 1);
    recs.push(batch_hdr);
    for i in 0..m {
        let [k0, k1, k2, k3, act] = rec[i];
        b.assert_bool(act);
        let key = bind::key_from_limbs::<Val, Challenge>(&mut b, &[k0, k1, k2, k3]);
        // Canonical dummy: act = 0 ⇒ k0 + k1 + k2 + k3 = 0 ⇒ every limb 0
        // (each `< 2^16`, so the sum cannot wrap).
        let s01 = b.add(k0, k1);
        let s012 = b.add(s01, k2);
        let s = b.add(s012, k3);
        let oma = b.sub(one, act);
        let dchk = b.mul(oma, s);
        b.connect(dchk, zero);
        let l3 = b.mul_add(act, act16, k3);
        recs.push(
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[k0, k1, k2, l3])
                .expect("record"),
        );
        // h = canonical low 27 bits of digest limb 0 (limbs 1..3 base-pinned
        // under Bound; the merged fork binds them under Semantic).
        let digest = bind::hash_slice(&mut b, &cfg, &[key], zero, binding);
        let sp = split[i];
        let _ = bind::decompose::<Val, Challenge>(
            &mut b,
            digest[0],
            binding,
            |b, idx, coeff| {
                if idx == 0 {
                    let x = hash_split_gadget(b, sp, &c, hi_max, abl);
                    b.connect(x, coeff);
                }
            },
            |b, idx, coeff| {
                if idx >= 1 {
                    bind::pin_base::<Val, Challenge>(b, coeff);
                }
            },
        );
        let hg = b.mul(act, sp[0]);
        u_elems.push(enc(&mut b, hg, act, sort_base));
    }
    let hb = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::Batch,
        CommitFamily::Kmv,
        salts.as_ref().map(|s| &s.batch),
        &recs,
        zero,
        binding,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_pis[i]);
    }
    if expose.is_interval() {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &cfg,
            &init_pis,
            &final_pis,
            &hb,
            zero,
            binding,
            IndexPin::Range,
        );
    }

    // ── Stage C: op 1, U → V (placeholder σ; swapped per epoch) ──
    let v_out = b.add_permute(&u_elems, (0..n).collect()).expect("permute sort");
    for r in 0..n {
        let [hv, av] = v[r];
        b.assert_bool(av);
        b.add_range_bits::<Val>(hv, HASH_BITS).expect("V value range");
        let oma = b.sub(one, av);
        let z = b.mul(oma, hv);
        b.connect(z, zero);
        let e = enc(&mut b, hv, av, sort_base);
        b.connect(v_out[r], e);
    }
    // Sortedness: actives form a prefix, ascending by h.
    for r in 0..n - 1 {
        let [h0, a0] = v[r];
        let [h1, a1] = v[r + 1];
        let oma0 = b.sub(one, a0);
        let pre = b.mul(oma0, a1);
        b.connect(pre, zero);
        if abl & ABL_SORT == 0 {
            let d = b.sub(h1, h0);
            let g = b.mul(a1, d);
            b.add_range_bits::<Val>(g, HASH_BITS).expect("V sortedness");
        }
    }

    // ── Stage D: first-of-run, ranks, cut ──
    let mut f: Vec<ExprId> = Vec::with_capacity(n);
    f.push(one);
    for r in 1..n {
        let [e, inv] = eq[r - 1];
        let diff = b.sub(v[r][0], v[r - 1][0]);
        // e = 1 ⇒ equal.
        let l1 = b.mul(e, diff);
        b.connect(l1, zero);
        if abl & ABL_EQ_NE == 0 {
            // e = 0 ⇒ diff invertible ⇒ distinct (and so e is boolean).
            let omt = b.sub(one, e);
            let di = b.mul(diff, inv);
            let omdi = b.sub(one, di);
            let l2 = b.mul(omt, omdi);
            b.connect(l2, zero);
        } else {
            b.assert_bool(e);
            let _ = b.mul(inv, inv);
        }
        f.push(b.sub(one, e));
    }
    let mut rank: Vec<ExprId> = Vec::with_capacity(n);
    let mut keep: Vec<ExprId> = Vec::with_capacity(n);
    let mut k_sum = zero;
    for r in 0..n {
        let df = if r == 0 { v[0][1] } else { b.mul(v[r][1], f[r]) };
        rank.push(if r == 0 { df } else { b.add(rank[r - 1], df) });
        b.assert_bool(w[r]);
        if r + 1 < n {
            let omw = b.sub(one, w[r]);
            let mono = b.mul(omw, w[r + 1]);
            b.connect(mono, zero);
        }
        let kp = b.mul(df, w[r]);
        keep.push(kp);
        k_sum = if r == 0 { kp } else { b.add(k_sum, kp) };
    }
    if abl & ABL_MIN_K == 0 {
        // K = min(k, D): K ≤ k, K ≤ D, and K ∈ {k, D}.
        let kk = b.sub(k_const, k_sum);
        b.add_range_bits::<Val>(kk, COUNT_BITS).expect("K <= k");
        let dk = b.sub(rank[n - 1], k_sum);
        b.add_range_bits::<Val>(dk, COUNT_BITS).expect("K <= D");
        let prod = b.mul(kk, dk);
        b.connect(prod, zero);
    }

    // ── Stage E: op 2, kept (h, rank) → slots (S_t[j], j + 1) ──
    let mut c_in: Vec<ExprId> = Vec::with_capacity(n);
    for r in 0..n {
        let e = enc(&mut b, v[r][0], rank[r], compact_base);
        c_in.push(b.mul(keep[r], e));
    }
    let c_out = b.add_permute(&c_in, (0..n).collect()).expect("permute compact");
    for j in 0..k {
        let [h, a] = s_new[j];
        let e = enc(&mut b, h, labels[j], compact_base);
        let t = b.mul(a, e);
        b.connect(c_out[j], t);
    }
    for i in 0..m {
        b.connect(c_out[k + i], zero);
    }

    let circuit = b.build().expect("build kmv circuit");

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
        permute_preprocessor::<Val>(),
        range_preprocessor::<Val>(),
    ];
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
        .expect("get_airs_and_degrees_with_prep (kmv)");
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

    KmvLeafCircuit {
        params,
        binding,
        expose,
        mode,
        ablate: abl,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        table_rows,
    }
}

/// Inputs and commitments of one epoch.
struct KmvEpoch {
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    initial_commit: [Val; 8],
    final_commit: [Val; 8],
    batch_commit: [Val; 8],
}

impl KmvLeafCircuit {
    pub fn params(&self) -> KmvParams {
        self.params
    }
    pub fn binding(&self) -> Binding {
        self.binding
    }
    /// The statement this leaf exposes ([`Expose`]).
    pub fn expose(&self) -> Expose {
        self.expose
    }
    /// `Σ 2^degree` over all tables.
    pub fn trace_rows(&self) -> u64 {
        self.trace_rows
    }
    /// Padded height of each table (AIR order).
    pub fn table_rows(&self) -> &[usize] {
        &self.table_rows
    }

    /// The commitment mode the circuit was built with.
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }

    /// Prove batch 1 (`keys` padded with dummies to `params.batch`).
    /// `Plain` circuits only, like [`Self::prove_epoch_at`].
    pub fn prove_epoch(&mut self, initial: KmvState, keys: Vec<u64>) -> KmvProof {
        self.prove_epoch_at(1, initial, keys)
    }

    /// Prove batch `t` (1-based; part of the Interval statement) from
    /// `initial` over `keys` padded with dummies to `params.batch`. `Plain`
    /// circuits only (see [`Self::prove_records_at`]).
    pub fn prove_epoch_at(&mut self, t: u64, initial: KmvState, keys: Vec<u64>) -> KmvProof {
        let records = kmv_records(&self.params, &keys);
        self.prove_records_at(t, initial, records)
    }

    /// Prove batch `t` over an explicit record sequence (`None` = a dummy at
    /// that position; `params.batch` records). `Plain` circuits only: on a
    /// `Hiding` circuit this would open every commitment with the public zero
    /// salt, so it panics; use [`Self::prove_records_commit`] (or, for the
    /// no-op leaf, [`Self::prove_records_public_zero`]).
    pub fn prove_records_at(
        &mut self,
        t: u64,
        initial: KmvState,
        records: Vec<Option<u64>>,
    ) -> KmvProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             Openings::for_leaf(..)"
        );
        self.prove_records_opened(t, initial, records, &Openings::plain())
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`Openings::for_leaf(seed, CommitFamily::Kmv, t)` for an honest
    /// prover; ignored by a `Plain` circuit). See [`Self::prove_records_commit`].
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial: KmvState,
        keys: Vec<u64>,
        openings: &Openings,
    ) -> KmvProof {
        let records = kmv_records(&self.params, &keys);
        self.prove_records_commit(t, initial, records, openings)
    }

    /// [`Self::prove_records_at`] with the commitment openings of leaf `t`.
    /// The proof's commitments are then `Com(S_{t-1}; ρ^S_{t-1})`,
    /// `Com(S_t; ρ^S_t)` and `Com(B_t; ρ^B_t)`. A `Hiding` circuit panics when
    /// `openings.final_` or `openings.batch` is the public zero salt (never an
    /// honest PRF output), and accepts a zero init salt only at `t = 1` on the
    /// empty genesis state ([`hiding::assert_zero_init_opens_public_state`]).
    pub fn prove_records_commit(
        &mut self,
        t: u64,
        initial: KmvState,
        records: Vec<Option<u64>>,
        openings: &Openings,
    ) -> KmvProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (Openings::for_leaf), not the public zero salt"
            );
            hiding::assert_zero_init_opens_public_state(t, openings.init.is_zero(), || {
                initial.vals.is_empty()
            });
        }
        self.prove_records_opened(t, initial, records, openings)
    }

    /// The no-op VK-derivation leaf's epoch over `keys` (padded with dummies):
    /// see [`Self::prove_records_public_zero`].
    pub fn prove_epoch_public_zero(&mut self, t: u64, initial: KmvState, keys: Vec<u64>) -> KmvProof {
        let records = kmv_records(&self.params, &keys);
        self.prove_records_public_zero(t, initial, records)
    }

    /// The no-op VK-derivation leaf's epoch: all three commitments opened
    /// with [`Openings::public_zero`], so it exposes `init == final` in
    /// either mode. The only path that proves a `Hiding` leaf with zero
    /// final/batch salts, so it accepts exactly the public no-op input: batch
    /// index `t = 1`, the empty state and every record slot the canonical
    /// dummy. It publishes only `Com(S_0; 0)` and `Com(dummies; 0)`,
    /// commitments to public data.
    pub fn prove_records_public_zero(
        &mut self,
        t: u64,
        initial: KmvState,
        records: Vec<Option<u64>>,
    ) -> KmvProof {
        assert!(
            initial.vals.is_empty() && records.iter().all(Option::is_none),
            "prove_epoch_public_zero is for the no-op leaf: the public no-op input only (the empty \
             state and an all-dummy batch)"
        );
        assert_eq!(t, 1, "prove_epoch_public_zero is for the no-op leaf: it is proved at batch index 1");
        self.prove_records_opened(t, initial, records, &Openings::public_zero())
    }

    /// Shared body of the `prove_*` entry points (no opening checks): the
    /// commitments are opened with `openings` (ignored under `Plain`).
    fn prove_records_opened(
        &mut self,
        t: u64,
        initial: KmvState,
        records: Vec<Option<u64>>,
        openings: &Openings,
    ) -> KmvProof {
        let params = self.params;
        assert_eq!(records.len(), params.batch, "records != batch");
        let t_w = std::time::Instant::now();
        let wit = honest_witness(&params, &initial, &records);
        let (traces, ep) =
            self.run_witness_opened(t, &wit, openings).unwrap_or_else(|e| panic!("run kmv: {e}"));
        let witness = t_w.elapsed();
        let t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (kmv)");
        let prove = t_p.elapsed();
        let t_v = std::time::Instant::now();
        self.prover.verify_all_tables(&proof).expect("self-verify kmv leaf");
        crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
            witness,
            prove,
            verify: t_v.elapsed(),
            trace_rows: self.trace_rows,
        });
        KmvProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial_commit: ep.initial_commit,
            final_commit: ep.final_commit,
            batch_commit: ep.batch_commit,
            final_state: rows_to_state(params.k, &wit.fin),
            params,
        }
    }

    /// Public and private inputs of a witness, in allocation order, with the
    /// commitments opened by `openings` (ignored under `Plain`).
    fn epoch(&self, t: u64, w: &KmvWitness, openings: &Openings) -> KmvEpoch {
        let params = self.params;
        let mode = self.mode;
        let initial_commit = commit_kmv_rows_with(params.k, &w.initial, mode, &openings.init);
        let final_commit = commit_kmv_rows_with(params.k, &w.fin, mode, &openings.final_);
        let batch_commit = commit_records_raw_with(params.batch, &w.records, mode, &openings.batch);
        let ch = |d: &[Val; 8]| -> [Challenge; 2] {
            [
                Challenge::from_basis_coefficients_slice(&d[0..4]).expect("4 coeffs"),
                Challenge::from_basis_coefficients_slice(&d[4..8]).expect("4 coeffs"),
            ]
        };
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend(ch(&initial_commit));
        public_inputs.extend(ch(&final_commit));
        public_inputs.extend(ch(&batch_commit));
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(t));
        }

        let row = |out: &mut Vec<Challenge>, &(h, a): &Row| {
            out.push(Challenge::from_u32(h));
            out.push(Challenge::from_u32(a));
        };
        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            // B2: the salts first, in allocation order (init, final, batch).
            private_inputs.extend(openings.private_inputs());
        }
        w.initial.iter().for_each(|r| row(&mut private_inputs, r));
        w.fin.iter().for_each(|r| row(&mut private_inputs, r));
        for &(key, act) in &w.records {
            private_inputs.extend(bind::key_limbs::<Val>(key).into_iter().map(Challenge::from));
            private_inputs.push(Challenge::from_u32(act));
        }
        for s in &w.split {
            private_inputs.extend(s.iter().map(|&x| Challenge::from(x)));
        }
        w.v.iter().for_each(|r| row(&mut private_inputs, r));
        for &(e, inv) in &w.eq {
            private_inputs.push(Challenge::from_u32(e));
            private_inputs.push(Challenge::from(inv));
        }
        private_inputs.extend(w.w.iter().map(|&x| Challenge::from_u32(x)));
        KmvEpoch { public_inputs, private_inputs, initial_commit, final_commit, batch_commit }
    }

    /// Install the witness's permutation hints and run the circuit, the
    /// commitments opened with `openings` (ignored under `Plain`).
    fn run_witness_opened(
        &mut self,
        t: u64,
        w: &KmvWitness,
        openings: &Openings,
    ) -> Result<(p3_circuit::tables::Traces<Challenge>, KmvEpoch), String> {
        self.circuit
            .update_permute_witnesses(&[w.sigma_sort.clone(), w.sigma_compact.clone()])
            .map_err(|e| format!("update permute witnesses: {e:?}"))?;
        let ep = self.epoch(t, w, openings);
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&ep.public_inputs).map_err(|e| format!("pubs: {e:?}"))?;
        runner.set_private_inputs(&ep.private_inputs).map_err(|e| format!("privs: {e:?}"))?;
        let traces = runner.run().map_err(|e| format!("run: {e:?}"))?;
        Ok((traces, ep))
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

    /// The malicious prover's entry point: run, prove and self-verify a
    /// (possibly forged) witness with panics caught. `Err` names the stage
    /// that rejected it (`run:` = an unsatisfiable wire/ALU constraint,
    /// `prove:`/`verify:` = the STARK tables).
    #[cfg(test)]
    fn try_prove_witness(
        &mut self,
        t: u64,
        w: &KmvWitness,
    ) -> Result<p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>, String> {
        let (traces, _) = crate::sketch::forge::catch_msg(|| self.run_witness_opened(t, w, &Openings::plain()))
            .map_err(|e| format!("run (panic): {e}"))??;
        crate::sketch::forge::catch_msg(|| self.prove_traces(&traces))
            .map_err(|e| format!("prove (panic): {e}"))?
    }

    /// The op-1 output elements (`V`) of a witness under this circuit's tags.
    #[cfg(test)]
    fn sort_outputs(&self, v: &[Row]) -> Vec<Challenge> {
        let (st, _) = op_tags(self.ablate);
        v.iter().map(|&(h, a)| elem(h, a, st)).collect()
    }

    /// The op-2 output elements of new-state rows (then `m` zero dummies).
    #[cfg(test)]
    fn compact_outputs(&self, fin: &[Row]) -> Vec<Challenge> {
        let (_, ct) = op_tags(self.ablate);
        let mut out: Vec<Challenge> = fin
            .iter()
            .enumerate()
            .map(|(j, &(h, a))| if a == 1 { elem(h, j as u32 + 1, ct) } else { Challenge::ZERO })
            .collect();
        out.resize(fin.len() + self.params.batch, Challenge::ZERO);
        out
    }
}

/// Prove batch `t` (1-based) as an **Interval-statement** KMV leaf (process
/// default [`Binding`]).
pub fn prove_kmv_interval(params: KmvParams, t: u64, initial: KmvState, keys: Vec<u64>) -> KmvProof {
    build_kmv_leaf_expose(params, Expose::Interval, bind::default_binding())
        .prove_epoch_at(t, initial, keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::expose_forest::read_exposed_statement;
    use crate::sketch::forge_permute::forge_permute_outputs;

    /// Build a leaf with ablation mask `flags` (0 = the real circuit).
    fn leaf_with(params: KmvParams, flags: u32) -> KmvLeafCircuit {
        ABLATE.with(|c| c.set(flags));
        let leaf = crate::sketch::forge::catch_msg(|| {
            build_kmv_leaf_expose(params, Expose::Boundary, Binding::Semantic)
        });
        ABLATE.with(|c| c.set(0));
        leaf.unwrap_or_else(|e| panic!("build kmv leaf: {e}"))
    }

    /// The exposed `Com(S_t)` of a Boundary/Interval leaf proof.
    fn exposed_final(p: &p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>) -> Vec<Val> {
        read_exposed_statement(p).final_
    }

    /// First pair of distinct keys `(a, b)` (`a < b`, from 1 up) whose 27-bit
    /// hashes collide (a birthday search, ~2^13.5 keys).
    fn collision_pair() -> (u64, u64) {
        static PAIR: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();
        *PAIR.get_or_init(|| {
            let mut seen: HashMap<u32, u64> = HashMap::new();
            for key in 1u64.. {
                let x = key.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5DEE_CE66;
                if let Some(&prev) = seen.get(&kmv_hash(x)) {
                    return (prev, x);
                }
                seen.insert(kmv_hash(x), x);
            }
            unreachable!()
        })
    }

    /// Keys sorted by hash: `keys_by_hash(n)[i]` has the `i`-th smallest hash
    /// among `n` pseudo-random keys (all hashes distinct).
    fn keys_by_hash(n: usize, salt: u64) -> Vec<u64> {
        let mut ks: Vec<u64> = (0..n as u64)
            .map(|i| (i + 1).wrapping_mul(0xD1B5_4A32_D192_ED03) ^ salt)
            .collect();
        ks.sort_by_key(|&x| kmv_hash(x));
        ks.dedup_by_key(|x| kmv_hash(*x));
        assert_eq!(ks.len(), n, "pick a salt without collisions");
        ks
    }

    // ─── Native model ────────────────────────────────────────────────────────

    /// The batch rule equals per-record insertion (any order, repetitions),
    /// on random streams for every small `k`, including real hash collisions.
    #[test]
    fn batch_rule_equals_per_record() {
        let (ca, cb) = collision_pair();
        assert_ne!(ca, cb);
        assert_eq!(kmv_hash(ca), kmv_hash(cb));
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for k in [1usize, 2, 3, 4, 5, 8] {
            for _ in 0..40 {
                let mut s = KmvState::empty(k);
                let mut s_rec = s.clone();
                for _ in 0..4 {
                    let len = (next() % 9) as usize;
                    let mut keys: Vec<u64> = (0..len).map(|_| next() % 12).collect();
                    if next() % 3 == 0 {
                        keys.push(ca);
                        keys.push(cb);
                    }
                    s = kmv_advance(&s, &keys);
                    s_rec = kmv_insert_each(&s_rec, &keys);
                    assert_eq!(s, s_rec, "k = {k}, keys = {keys:?}");
                    let mut rev = keys.clone();
                    rev.reverse();
                    assert_eq!(kmv_insert_each(&s, &rev), s, "re-inserting is idempotent");
                    assert!(s.vals.windows(2).all(|w| w[0] < w[1]) && s.vals.len() <= k);
                }
            }
        }
    }

    /// Estimator: exact below capacity, `floor((k−1)2^27/v_k)` at capacity.
    #[test]
    fn estimate_native() {
        let s = KmvState { k: 4, vals: vec![10, 20] };
        assert_eq!(s.estimate(), 2);
        let s = KmvState { k: 4, vals: vec![10, 20, 30, 1 << 20] };
        assert_eq!(s.estimate(), (3u64 << 27) / (1 << 20));
        // Roughly unbiased on a real stream: 5000 distinct keys, k = 256.
        let mut st = KmvState::empty(256);
        let keys: Vec<u64> = (0..5000u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15)).collect();
        st = kmv_advance(&st, &keys);
        let est = st.estimate() as f64;
        assert!((est - 5000.0).abs() / 5000.0 < 0.2, "estimate {est}");
    }

    // ─── Circuit vs native ───────────────────────────────────────────────────

    /// Chained multi-batch streams at k ∈ {4, 8}, m ∈ {4, 8}: duplicates
    /// within and across batches, short batches (dummy padding) and interior
    /// dummies, states below and at capacity, evictions, and a tie between two
    /// DISTINCT keys with equal 27-bit hashes. After every batch the
    /// circuit's EXPOSED `Com(S_t)` equals the native bottom-k.
    #[test]
    fn circuit_matches_native_chained() {
        let (ca, cb) = collision_pair();
        for (k, m) in [(4usize, 4usize), (4, 8), (8, 4), (8, 8)] {
            let params = KmvParams { k, batch: m };
            let mut leaf = build_kmv_leaf_expose(params, Expose::Boundary, Binding::Semantic);
            let ks = keys_by_hash(3 * k + 6, 0xABCD);
            // Batches as record lists (None = dummy), padded to m.
            let pad = |mut r: Vec<Option<u64>>| {
                r.truncate(m);
                r.resize(m, None);
                r
            };
            let batches: Vec<Vec<Option<u64>>> = vec![
                // Below capacity, a within-batch duplicate, interior dummy.
                pad(vec![Some(ks[5]), None, Some(ks[5]), Some(ks[9])]),
                // The tie: two distinct keys, one hash; plus a cross-batch dup.
                pad(vec![Some(ca), Some(ks[9]), Some(cb), None, Some(ks[2])]),
                // Reach / pass capacity.
                pad((0..m).map(|i| Some(ks[k + 2 + i])).collect()),
                // Smaller values evict larger ones; duplicates of kept values.
                pad(vec![Some(ks[0]), Some(ks[1]), Some(ks[0]), Some(ks[5]), Some(ks[1])]),
                // All dummies: a no-op.
                vec![None; m],
                // Larger values than every kept one: no change at capacity.
                pad((0..m).map(|i| Some(ks[3 * k + 5 - i])).collect()),
            ];
            let mut s = KmvState::empty(k);
            let mut saw_full = false;
            for (t, recs) in batches.iter().enumerate() {
                let keys: Vec<u64> = recs.iter().flatten().copied().collect();
                let expect = kmv_advance(&s, &keys);
                assert_eq!(expect, kmv_insert_each(&s, &keys));
                let p = leaf.prove_records_at(t as u64 + 1, s.clone(), recs.clone());
                assert_eq!(p.final_state, expect, "k={k} m={m} batch {t}");
                assert_eq!(p.initial_commit, commit_kmv_state(&s));
                assert_eq!(p.batch_commit, commit_kmv_records(&params, recs));
                assert_eq!(
                    exposed_final(&p.output.0),
                    commit_kmv_state(&expect).to_vec(),
                    "k={k} m={m} batch {t}: exposed Com(S_t) == native bottom-k"
                );
                saw_full |= expect.is_full();
                s = expect;
            }
            assert!(saw_full, "the stream must reach capacity");
            assert!(s.vals.contains(&kmv_hash(ks[0])), "the smallest value is kept");
        }
    }

    /// Short `keys` are padded with dummies: the padded and explicit record
    /// lists give the same batch commitment and final state; an all-dummy
    /// batch leaves the state (and its commitment) unchanged.
    #[test]
    fn dummy_padding_and_noop() {
        let params = KmvParams { k: 4, batch: 4 };
        let mut leaf = build_kmv_leaf_expose(params, Expose::Boundary, Binding::Semantic);
        let s1 = kmv_advance(&KmvState::empty(4), &[11, 22, 33]);
        let p = leaf.prove_epoch(s1.clone(), vec![44]);
        assert_eq!(p.batch_commit, commit_kmv_batch(&params, &[44]));
        assert_eq!(p.final_state, kmv_advance(&s1, &[44]));
        let q = leaf.prove_records_at(1, s1.clone(), vec![None; 4]);
        assert_eq!(q.final_state, s1);
        assert_eq!(q.initial_commit, q.final_commit);
    }

    /// The Bound binding (zero-IV sponges, ALU-rebound digest limb) proves
    /// the same transitions.
    #[test]
    fn bound_binding_round_trip() {
        let params = KmvParams { k: 4, batch: 4 };
        let mut leaf = build_kmv_leaf_expose(params, Expose::Boundary, Binding::Bound);
        let s0 = KmvState::empty(4);
        let s1 = kmv_advance(&s0, &[1, 2, 3, 4]);
        let p = leaf.prove_epoch(s0, vec![1, 2, 3, 4]);
        assert_eq!(exposed_final(&p.output.0), commit_kmv_state(&s1).to_vec());
        let s2 = kmv_advance(&s1, &[5, 1, 6]);
        let p = leaf.prove_epoch(s1, vec![5, 1, 6]);
        assert_eq!(exposed_final(&p.output.0), commit_kmv_state(&s2).to_vec());
    }

    /// `Binding::Legacy` (a `ZKSKETCH_BINDING=legacy` run) builds the
    /// Semantic KMV leaf instead of panicking: the leaf reports `Semantic`,
    /// proves the native transition, and its proof has the Semantic no-op
    /// leaf's VK (the same circuit); the Legacy no-op leaf has it too.
    #[test]
    fn legacy_binding_selects_semantic() {
        use crate::recursion::recursive::expose_forest::vk_pin_values;
        use crate::recursion::recursive::noop_leaf::kmv_noop_leaf_expose;
        assert_eq!(kmv_binding(Binding::Legacy), Binding::Semantic);
        assert_eq!(kmv_binding(Binding::Semantic), Binding::Semantic);
        assert_eq!(kmv_binding(Binding::Bound), Binding::Bound);
        let params = KmvParams { k: 4, batch: 4 };
        let mut leaf = build_kmv_leaf_expose(params, Expose::Interval, Binding::Legacy);
        assert_eq!(leaf.binding(), Binding::Semantic, "the leaf reports the binding it built");
        let s0 = KmvState::empty(4);
        let p = leaf.prove_epoch_at(1, s0.clone(), vec![3, 1, 4, 1]);
        assert_eq!(p.final_state, kmv_advance(&s0, &[3, 1, 4, 1]));
        let semantic = vk_pin_values(&kmv_noop_leaf_expose(params, Expose::Interval, Binding::Semantic));
        assert_eq!(vk_pin_values(&p.output.0), semantic, "Legacy builds the Semantic circuit");
        let legacy_noop = kmv_noop_leaf_expose(params, Expose::Interval, Binding::Legacy);
        assert_eq!(vk_pin_values(&legacy_noop), semantic);
    }

    // ─── Attacks ─────────────────────────────────────────────────────────────
    //
    // Each attack is a malicious witness (and, where the attack needs it,
    // forged Permute outputs) run through `try_prove_witness`. Every test
    // first pushes the HONEST witness through the identical pipeline (same
    // forgers, same plumbing) and requires it to verify, so a broken forger
    // cannot make a rejection vacuous. Where one check is responsible, the
    // test also builds the circuit WITHOUT that check (`ABL_*`) and shows the
    // attack is then accepted with a wrong exposed state: the rejection is due
    // to that check. `run:` rejections are wire/ALU constraints no trace can
    // satisfy: either over private inputs and constants only, or a range
    // check's byte reconstruction `x = Σ byte_i·256^i` that no in-range bytes
    // meet, whatever the byte hint; `prove:`/`verify:` rejections come from the
    // STARK tables (PermuteBus / RangeBus).

    const AP: KmvParams = KmvParams { k: 4, batch: 4 };

    /// A full prior state and a batch, chosen by hash rank (`ks[i]` has the
    /// `i`-th smallest hash): `S_{t-1} = {1, 2, 4, 7}`, batch `{0, 1, 5, 3}`,
    /// so `V = [0, 1, 1, 2, 3, 4, 5, 7]` (all active, one duplicate run at
    /// rank 2), `D = 7 > k = 4`, and the honest `S_t = {0, 1, 2, 3}`.
    /// Returns `(S_{t-1}, records, ks)`.
    fn attack_instance() -> (KmvState, Vec<Option<u64>>, Vec<u64>) {
        let ks = keys_by_hash(8, 0x77);
        let s = kmv_advance(&KmvState::empty(AP.k), &[ks[1], ks[2], ks[4], ks[7]]);
        assert!(s.is_full());
        let records = vec![Some(ks[0]), Some(ks[1]), Some(ks[5]), Some(ks[3])];
        (s, records, ks)
    }

    /// Run `w` through a fresh leaf (ablation `flags`), forging the op-1 and/or
    /// op-2 outputs to `forge_v` / `forge_fin` encodings when given.
    fn attempt(
        flags: u32,
        w: &KmvWitness,
        forge_v: Option<&[Row]>,
        forge_fin: Option<&[Row]>,
    ) -> Result<Vec<Val>, String> {
        let mut leaf = leaf_with(AP, flags);
        if let Some(v) = forge_v {
            let outs = leaf.sort_outputs(v);
            forge_permute_outputs(&mut leaf.circuit, 0, outs);
        }
        if let Some(fin) = forge_fin {
            let outs = leaf.compact_outputs(fin);
            forge_permute_outputs(&mut leaf.circuit, 1, outs);
        }
        leaf.try_prove_witness(1, w).map(|p| exposed_final(&p))
    }

    /// The honest witness through the same pipeline must verify and expose
    /// the honest `Com(S_t)` (the positive control of every attack).
    fn control(flags: u32, honest: &KmvWitness, forge_v: bool, forge_fin: bool) {
        let r = attempt(
            flags,
            honest,
            forge_v.then_some(honest.v.as_slice()),
            forge_fin.then_some(honest.fin.as_slice()),
        );
        let want = commit_kmv_rows(AP.k, &honest.fin).to_vec();
        assert_eq!(r, Ok(want), "POSITIVE CONTROL rejected: the forger is broken");
    }

    fn honest() -> KmvWitness {
        let (s, recs, _) = attack_instance();
        honest_witness(&AP, &s, &recs)
    }

    /// Assert the attack is rejected and report where.
    fn rejected(what: &str, r: Result<Vec<Val>, String>) {
        match r {
            Ok(_) => panic!("{what}: ACCEPTED"),
            Err(e) => println!("[kmv attack] {what}: REJECTED at {}", e.lines().next().unwrap_or("")),
        }
    }

    /// Assert the ablated circuit accepts the attack with the forged state.
    fn accepted_without(what: &str, r: Result<Vec<Val>, String>, forged_fin: &[Row]) {
        let got = r.unwrap_or_else(|e| panic!("{what}: PoC premise failed, ablated circuit rejected: {e}"));
        assert_eq!(got, commit_kmv_rows(AP.k, forged_fin).to_vec(), "{what}: exposes Com(S')");
        println!("[kmv attack] {what}: accepted by the ablated circuit (exposes the forged state)");
    }

    /// DROP THE SMALLEST HASH: commit `S' = S_t` minus its smallest value
    /// plus the next distinct value (the true rank-5 value) while `V`, the
    /// ranks and the cut stay honest. The compaction outputs must be forged
    /// (they are no permutation of the kept rows); the PermuteBus rejects.
    #[test]
    fn attack_drop_smallest_rejected() {
        let h = honest();
        control(0, &h, false, true);
        control(0, &h, false, false);
        let eq: Vec<(u32, u32)> = h.eq.iter().map(|&(e, _)| (e, 0)).collect();
        let (df, _) = distinct_ranks(&h.v, &eq);
        let next = (0..h.v.len()).filter(|&r| df[r] == 1).nth(AP.k).map(|r| h.v[r].0).unwrap();
        let mut fin: Vec<Row> = h.fin[1..].to_vec();
        fin.push((next, 1));
        assert_ne!(fin, h.fin);
        let mut w = h.clone();
        w.fin = fin.clone();
        rejected("drop smallest (forged compaction outputs)", attempt(0, &w, None, Some(&fin)));
        // Without forging, the honest permute output cannot meet the targets.
        rejected("drop smallest (honest permute)", attempt(0, &w, None, None));
    }

    /// KEEP A DUPLICATE TWICE: the state's rank-3 value also arrives in the
    /// batch; the prover tags the second copy "distinct" (e = 0) so it takes
    /// a second rank and pushes the true 4th-smallest value out. The
    /// is-equal gadget's `e = 0 ⇒ distinct` half rejects it; without that
    /// half the circuit accepts `S'` with the duplicate kept twice.
    #[test]
    fn attack_duplicate_kept_twice_rejected() {
        let h = honest();
        control(0, &h, false, false);
        let r = (1..h.v.len())
            .find(|&r| h.v[r].1 == 1 && h.v[r] == h.v[r - 1])
            .expect("a duplicate active pair in V");
        let mut w = h.clone();
        w.eq[r - 1] = (0, Val::ONE);
        let eq: Vec<(u32, u32)> = w.eq.iter().map(|&(e, _)| (e, 0)).collect();
        let (df, rank) = distinct_ranks(&w.v, &eq);
        w.w = rank.iter().map(|&x| u32::from(x as usize <= AP.k)).collect();
        w.fin = compact(&w.v, &df, &w.w, AP.k);
        let (cin, cout) = compact_elems(&w.v, &df, &rank, &w.w, &w.fin, AP.batch);
        w.sigma_compact = match_sigma(&cin, &cout).expect("consistent compaction");
        assert_eq!(w.fin.iter().filter(|x| **x == h.v[r]).count(), 2, "S' keeps the duplicate twice");
        assert_ne!(w.fin, h.fin);
        control(ABL_EQ_NE, &h, false, false);
        accepted_without("duplicate kept twice", attempt(ABL_EQ_NE, &w, None, None), &w.fin);
        rejected("duplicate kept twice", attempt(0, &w, None, None));
    }

    /// CUT AT k − 1 / k + 1. (k − 1): the prefix `w` stops one distinct value
    /// early, `S'` holds 3 values and a sentinel although `D ≥ k`; only the
    /// `K = min(k, D)` check rejects it (accepted without it). (k + 1): one
    /// distinct value too many is kept; the `k` slots cannot hold it, so the
    /// compaction multiset rejects it even without the cut check.
    #[test]
    fn attack_cut_off_by_one_rejected() {
        let h = honest();
        let eq: Vec<(u32, u32)> = h.eq.iter().map(|&(e, _)| (e, 0)).collect();
        let (df, rank) = distinct_ranks(&h.v, &eq);
        let cut = |limit: usize| -> KmvWitness {
            let mut w = h.clone();
            w.w = rank.iter().map(|&x| u32::from(x as usize <= limit)).collect();
            w.fin = compact(&w.v, &df, &w.w, AP.k);
            let (cin, cout) = compact_elems(&w.v, &df, &rank, &w.w, &w.fin, AP.batch);
            w.sigma_compact = match_sigma(&cin, &cout).unwrap_or_else(|| (0..w.v.len()).collect());
            w
        };
        // k − 1.
        control(0, &h, false, false);
        control(ABL_MIN_K, &h, false, false);
        let lo = cut(AP.k - 1);
        assert_eq!(lo.fin.iter().filter(|r| r.1 == 1).count(), AP.k - 1);
        accepted_without("cut at k-1", attempt(ABL_MIN_K, &lo, None, None), &lo.fin);
        rejected("cut at k-1", attempt(0, &lo, None, None));
        // k + 1 (forge the compaction outputs to the first k kept values).
        control(0, &h, false, true);
        control(ABL_MIN_K, &h, false, true);
        let hi = cut(AP.k + 1);
        assert_eq!(hi.fin, h.fin, "k slots hold the first k kept values");
        rejected("cut at k+1 (no cut check)", attempt(ABL_MIN_K, &hi, None, Some(&hi.fin)));
        rejected("cut at k+1", attempt(0, &hi, None, Some(&hi.fin)));
    }

    /// FREE HASH VALUE: record 0's split witness claims `h' = 0` (so the
    /// record plants the global minimum) with `hi'` solving `h' + 2^27·hi' =
    /// digest limb` in the field. Only the exact range check on `hi` binds
    /// `h` to the key: without it the circuit accepts `S'` containing `0`.
    /// (The rejection is at the byte reconstruction of `hi'`: one range-checked
    /// byte cannot equal the huge field element `hi'`, whatever the hint.)
    #[test]
    fn attack_free_hash_rejected() {
        let h = honest();
        control(0, &h, false, false);
        control(ABL_SPLIT, &h, false, false);
        let (s, recs, _) = attack_instance();
        let limb = digest_limb0(recs[0].unwrap());
        let mut split = h.split.clone();
        let forged_h = 0u64;
        assert_ne!(limb & (HASH_RANGE - 1), forged_h);
        let hi = (Val::from_u64(limb) - Val::from_u64(forged_h))
            * Val::from_u64(HASH_RANGE).try_inverse().unwrap();
        let dinv = (Val::from_u64(HI_MAX) - hi).try_inverse().unwrap_or(Val::ZERO);
        split[0] = [Val::from_u64(forged_h), hi, dinv];
        let mut v = union_rows(&s.rows(), &h.records, &split);
        v.sort_by_key(sort_key);
        let w = finish_witness(&AP, s.rows(), h.records.clone(), split, v, None, None);
        assert_eq!(w.fin[0], (0, 1), "S' holds the planted value 0");
        accepted_without("free hash value", attempt(ABL_SPLIT, &w, None, None), &w.fin);
        rejected("free hash value", attempt(0, &w, None, None));
    }

    /// NON-CANONICAL HASH SPLIT (the `x + p` alias, the bug class of the old
    /// CM/HLL `+1` column shift): for a key whose digest limb is `L < 2^27 −
    /// 1`, the integer `L + p = (L + 1) + 15·2^27` is a second split with
    /// BOTH parts in range (`L + 1 < 2^27`, `hi = 15 = HI_MAX`) and equals
    /// `L` in the field, so it passes every range check and the limb
    /// connection; it shifts the record's hash to `h(x) + 1`. Only the split's
    /// `hi = HI_MAX ⇒ h = 0` check (via `dinv`; `HI_MAX − hi = 0` has no
    /// inverse, so no `dinv` helps) rejects it: without that check the
    /// circuit accepts `S'` holding `h(x) + 1` instead of `h(x)`.
    #[test]
    fn attack_noncanonical_split_rejected() {
        let (_, _, ks) = attack_instance();
        // A key whose digest limb has high part 0 (about 1 key in 15).
        let x = (1u64..)
            .map(|i| i.wrapping_mul(0xA24B_AED4_963E_E407) ^ 0x0BAD_5EED)
            .find(|&x| digest_limb0(x) < HASH_RANGE - 1)
            .expect("a key with a small digest limb");
        let limb = digest_limb0(x);
        assert_eq!(kmv_hash(x) as u64, limb, "high part 0: h(x) is the whole limb");
        // Below capacity, so h(x) (and the shifted value) is kept.
        let s = kmv_advance(&KmvState::empty(AP.k), &[ks[1]]);
        let recs = vec![Some(x), None, Some(ks[6]), None];
        let h = honest_witness(&AP, &s, &recs);
        let (honest_row, shifted_row) = ((limb as u32, 1), (limb as u32 + 1, 1));
        assert!(h.fin.contains(&honest_row) && !h.fin.contains(&shifted_row));
        control(0, &h, false, false);
        control(ABL_CANON, &h, false, false);
        let mut split = h.split.clone();
        split[0] = [Val::from_u64(limb + 1), Val::from_u64(HI_MAX), Val::ZERO];
        assert_eq!(
            split[0][0] + split[0][1] * Val::from_u64(HASH_RANGE),
            Val::from_u64(limb),
            "the alias split equals the digest limb in the field"
        );
        assert_ne!(split[0], h.split[0]);
        let mut v = union_rows(&s.rows(), &h.records, &split);
        v.sort_by_key(sort_key);
        let w = finish_witness(&AP, s.rows(), h.records.clone(), split, v, None, None);
        assert!(
            w.fin.contains(&shifted_row) && !w.fin.contains(&honest_row),
            "S' holds h(x) + 1 instead of h(x)"
        );
        accepted_without("non-canonical split (x + p alias)", attempt(ABL_CANON, &w, None, None), &w.fin);
        rejected("non-canonical split (x + p alias)", attempt(0, &w, None, None));
    }

    /// A DUMMY RECORD CONTRIBUTING A VALUE. (a) The dummy slot's sentinel
    /// `(0, 0)` in `V` is replaced by the dummy key's hash `h(0)` as an
    /// active row, so `S'` holds a value no real record produced; `V` is then
    /// no permutation of `U` (op-1 outputs forged) and the PermuteBus rejects
    /// it. (b) A non-canonical dummy (`act = 0` with a real key's limbs, the
    /// rest of the witness honest) is rejected by the canonical-dummy check.
    #[test]
    fn attack_dummy_contributes_rejected() {
        let (_, _, ks) = attack_instance();
        let s = kmv_advance(&KmvState::empty(AP.k), &[ks[1]]);
        let recs = vec![Some(ks[5]), None, Some(ks[6]), None];
        let h = honest_witness(&AP, &s, &recs);
        assert_eq!(h.fin.iter().filter(|r| r.1 == 1).count(), 3, "honest S_t is below capacity");
        control(0, &h, true, false);
        // (a) h(0) planted as an active row of V; ranks/cut/compaction follow.
        let h0 = kmv_hash(0);
        let mut v: Vec<Row> = h.v.clone();
        let pos = v.iter().position(|r| r.1 == 0).expect("a sentinel row");
        v[pos] = (h0, 1);
        v.sort_by_key(sort_key);
        let w = finish_witness(&AP, s.rows(), h.records.clone(), h.split.clone(), v.clone(), None, None);
        assert!(w.fin.contains(&(h0, 1)), "S' holds the dummy's hash");
        rejected("dummy contributes (forged V)", attempt(0, &w, Some(&v), None));
        // (b) Non-canonical dummy.
        control(0, &h, false, false);
        let mut w = h.clone();
        w.records[1] = (ks[0], 0);
        w.split[1] = split27(digest_limb0(ks[0]));
        assert_eq!(union_rows(&w.initial, &w.records, &w.split), union_rows(&h.initial, &h.records, &h.split));
        rejected("non-canonical dummy (act = 0, nonzero key)", attempt(0, &w, None, None));
    }

    /// UNSORTED UNION (fragmentation route): `V` is a true permutation of `U`
    /// but the smallest value is moved behind the cut. The ranks, cut and
    /// compaction are recomputed honestly from it, so `S'` evicts the true
    /// minimum; the duplicate run split in two also counts one value twice.
    /// Only the sortedness check rejects it (accepted without it).
    #[test]
    fn attack_unsorted_union_rejected() {
        let h = honest();
        control(0, &h, false, false);
        control(ABL_SORT, &h, false, false);
        let (s, _, _) = attack_instance();
        let n_act = h.v.iter().filter(|r| r.1 == 1).count();
        // (1) The smallest value moved to the end of the active block.
        let mut v = h.v.clone();
        let first = v.remove(0);
        v.insert(n_act - 1, first);
        let w = finish_witness(&AP, s.rows(), h.records.clone(), h.split.clone(), v, None, None);
        assert!(!w.fin.contains(&h.fin[0]), "S' evicts the true minimum");
        accepted_without("unsorted V (minimum behind the cut)", attempt(ABL_SORT, &w, None, None), &w.fin);
        rejected("unsorted V (minimum behind the cut)", attempt(0, &w, None, None));
        // (2) Fragmentation: split the duplicate run [x, x] around another value.
        let r = (1..h.v.len()).find(|&r| h.v[r].1 == 1 && h.v[r] == h.v[r - 1]).unwrap();
        let mut v = h.v.clone();
        let dup = v.remove(r);
        v.insert(r + 1, dup);
        let w = finish_witness(&AP, s.rows(), h.records.clone(), h.split.clone(), v, None, None);
        assert_ne!(w.fin, h.fin);
        accepted_without("fragmented duplicate run", attempt(ABL_SORT, &w, None, None), &w.fin);
        rejected("fragmented duplicate run", attempt(0, &w, None, None));
    }

    /// REORDERED / FRAGMENTED OUTPUT STATE: the right SET in the wrong slots
    /// (two values swapped), and a sentinel in the middle of the actives
    /// (the last value dropped). Compaction outputs forged to the committed
    /// rows; the slot labels make each a different multiset.
    #[test]
    fn attack_reordered_output_rejected() {
        let h = honest();
        control(0, &h, false, true);
        let mut swapped = h.fin.clone();
        swapped.swap(0, 2);
        let mut w = h.clone();
        w.fin = swapped.clone();
        rejected("reordered output state", attempt(0, &w, None, Some(&swapped)));
        let mut frag = h.fin.clone();
        frag.insert(1, (0, 0));
        frag.truncate(AP.k);
        let mut w = h.clone();
        w.fin = frag.clone();
        rejected("fragmented output state", attempt(0, &w, None, Some(&frag)));
        let mut dup = h.fin.clone();
        dup[1] = dup[0];
        let mut w = h.clone();
        w.fin = dup.clone();
        rejected("duplicated output value", attempt(0, &w, None, Some(&dup)));
    }

    /// NON-CANONICAL SENTINEL IN THE NEW STATE: the honest `S_t` is below
    /// capacity and the prover commits its inactive last slot as `(x, 0)`,
    /// `x ≠ 0`: the same logical state under ANOTHER `Com(S_t)` (so the
    /// committed state is no longer a function of the transition, and the
    /// next leaf's old-state rows and the decoder, which check canonical
    /// sentinels too, could not open it). Op 2 routes an inactive slot to the
    /// zero element whatever its value, so the compaction outputs are
    /// unchanged (run with the honest outputs and with outputs forged to the
    /// committed rows). Only the new state's `act' = 0 ⇒ h' = 0` check rejects
    /// it: without it the circuit accepts and exposes the second commitment.
    #[test]
    fn attack_noncanonical_sentinel_rejected() {
        let (_, _, ks) = attack_instance();
        let s = kmv_advance(&KmvState::empty(AP.k), &[ks[1]]);
        let recs = vec![Some(ks[5]), None, Some(ks[6]), None];
        let h = honest_witness(&AP, &s, &recs);
        assert_eq!(h.fin[AP.k - 1], (0, 0), "honest S_t is below capacity");
        for forge_fin in [false, true] {
            control(0, &h, false, forge_fin);
            control(ABL_SENTINEL, &h, false, forge_fin);
        }
        let mut fin = h.fin.clone();
        fin[AP.k - 1] = (kmv_hash(ks[7]), 0);
        assert_ne!(fin[AP.k - 1].0, 0);
        assert_eq!(rows_to_state(AP.k, &fin), rows_to_state(AP.k, &h.fin), "same logical state");
        assert_ne!(commit_kmv_rows(AP.k, &fin), commit_kmv_rows(AP.k, &h.fin), "another Com(S_t)");
        let mut w = h.clone();
        w.fin = fin.clone();
        let l = leaf_with(AP, 0);
        assert_eq!(l.compact_outputs(&fin), l.compact_outputs(&h.fin), "op-2 outputs unchanged");
        accepted_without("non-canonical sentinel", attempt(ABL_SENTINEL, &w, None, None), &fin);
        accepted_without("non-canonical sentinel (forged op-2 outputs)", attempt(ABL_SENTINEL, &w, None, Some(&fin)), &fin);
        rejected("non-canonical sentinel", attempt(0, &w, None, None));
        rejected("non-canonical sentinel (forged op-2 outputs)", attempt(0, &w, None, Some(&fin)));
    }

    /// EXCHANGING ROWS BETWEEN THE TWO PERMUTE OPS (shared PermuteBus). The
    /// forged sort output holds the minimum `v1` twice and drops the evicted
    /// `v_{k+1}`; the forged compaction output puts `v_{k+1}` in slot 0 (label
    /// 1). Per op neither is a permutation, but over the UNION of both ops the
    /// multisets balance when the two element classes share one layout, so
    /// the untagged circuit accepts `S' = {v_{k+1}, v2, …, vk}` (the minimum
    /// dropped). With the class tags the union no longer balances.
    #[test]
    fn attack_cross_permute_exchange_rejected() {
        let h = honest();
        control(0, &h, true, true);
        control(ABL_OP_TAG, &h, true, true);
        let (s, _, _) = attack_instance();
        let eq: Vec<(u32, u32)> = h.eq.iter().map(|&(e, _)| (e, 0)).collect();
        let (df, _) = distinct_ranks(&h.v, &eq);
        let dist: Vec<usize> = (0..h.v.len()).filter(|&r| df[r] == 1).collect();
        let v1 = h.v[dist[0]];
        let vk1 = h.v[dist[AP.k]];
        let mut v = h.v.clone();
        let pos = v.iter().position(|r| *r == vk1).unwrap();
        v.remove(pos);
        v.insert(0, v1);
        let w0 = finish_witness(&AP, s.rows(), h.records.clone(), h.split.clone(), v.clone(), None, None);
        assert_eq!(w0.fin, h.fin, "the forged V keeps the same first k distinct values");
        let mut fin = h.fin.clone();
        fin[0] = (vk1.0, 1);
        let mut w = w0.clone();
        w.fin = fin.clone();
        accepted_without("cross-permute exchange", attempt(ABL_OP_TAG, &w, Some(&v), Some(&fin)), &fin);
        rejected("cross-permute exchange", attempt(0, &w, Some(&v), Some(&fin)));
    }

    // ─── Composition (pattern: `recursion::recursive::interval_tests`) ───────

    mod compose {
        use super::*;
        use crate::recursion::recursive::expose_forest::{
            batch_log, check_leaves_against_log, check_root_against_log, leaf_vk,
            prove_exposing_leaf, prove_forest_over, root_vk_deriver,
            verify_bound_stark_proof_against_log, verify_leaves_against_log, vk_pin_values,
        };
        use crate::recursion::recursive::noop_leaf::kmv_noop_leaf_expose;
        use crate::recursion::recursive::root_vk::{ForestShape, bound_proof_shape};
        use crate::recursion::recursive::statement::{BatchLog, hash_bb, leaf_digest};

        const CP: KmvParams = KmvParams { k: 4, batch: 4 };

        /// Four batches: a short (dummy-padded) one, cross-batch duplicates,
        /// evictions past capacity.
        fn batches() -> Vec<Vec<u64>> {
            vec![vec![1, 2, 3], vec![2, 4, 5, 6], vec![7, 1, 8, 9], vec![10, 11, 2, 12]]
        }

        fn noop() -> p3_circuit_prover::BatchStarkProof<ConfigWithFriParams> {
            kmv_noop_leaf_expose(CP, Expose::Interval, Binding::Semantic)
        }

        /// Interval leaves `t = 1..4` chained from the empty state; each
        /// leaf's exposed statement is checked against the native model.
        /// Returns the leaves and the batch log.
        fn stream() -> (Vec<RecursionOutput<ConfigWithFriParams>>, BatchLog<Val>) {
            let mut leaf = build_kmv_leaf_expose(CP, Expose::Interval, Binding::Semantic);
            let s0 = KmvState::empty(CP.k);
            let mut s = s0.clone();
            let mut leaves = Vec::new();
            let mut commits = Vec::new();
            for (i, keys) in batches().iter().enumerate() {
                let t = i as u64 + 1;
                let p = leaf.prove_epoch_at(t, s.clone(), keys.clone());
                let bc = commit_kmv_batch(&CP, keys);
                let st = read_exposed_statement(&p.output.0);
                let iv = st.interval.clone().expect("interval layout");
                assert_eq!((iv.lo, iv.hi), (Val::from_u64(t), Val::from_u64(t)));
                assert!(iv.idx_pad.iter().all(|&x| x == Val::ZERO));
                assert_eq!(iv.digest, leaf_digest(&hash_bb, 4, t, &bc), "leaf {t}: H == native");
                assert_eq!(st.init, commit_kmv_state(&s).to_vec());
                s = kmv_advance(&s, keys);
                assert_eq!(st.final_, commit_kmv_state(&s).to_vec(), "leaf {t}: Com(S_t) == native");
                commits.push(bc);
                leaves.push(p.output);
            }
            assert!(s.is_full());
            let log = batch_log(&commit_kmv_state(&s0), &commit_kmv_state(&s), &commits);
            (leaves, log)
        }

        /// A 4-leaf forest of real KMV Interval leaves verifies end to end
        /// against the batch log and the root VK derived from the public no-op
        /// leaf (derived == real, commitment and metadata); every real leaf has
        /// the no-op leaf's VK whatever its batch index; a log listing two
        /// batches in the other order, another final state, or another
        /// bracketing is rejected.
        #[test]
        fn kmv_forest_verifies_against_log() {
            let (leaves, log) = stream();
            let lvk = leaf_vk(&noop());
            for l in &leaves {
                assert_eq!(lvk.commitment, vk_pin_values(&l.0), "leaf VK is data independent");
            }
            let refs: Vec<_> = leaves.iter().map(|l| &l.0).collect();
            assert_eq!(verify_leaves_against_log(&refs, &lvk, &log, Expose::Interval), Ok(()));
            let shape = ForestShape::forest(4);
            let vk = root_vk_deriver(noop()).root_vk(&shape);
            let root = prove_forest_over(leaves);
            assert_eq!(vk.commitment, vk_pin_values(&root.0), "derived root VK == real");
            assert_eq!(vk.shape, Some(bound_proof_shape(&root.0)), "derived metadata == real");
            verify_bound_stark_proof_against_log(&root.0, &vk, &log, &shape);
            let mut swapped = log.clone();
            swapped.batch_commits.swap(1, 2);
            let r = check_root_against_log(&root.0, &swapped, &shape);
            assert!(r.is_err_and(|e| e.contains("digest")), "swapped log must be rejected");
            let mut other_final = log.clone();
            other_final.final_ = commit_kmv_state(&KmvState::empty(CP.k)).to_vec();
            assert!(check_root_against_log(&root.0, &other_final, &shape).is_err());
            assert!(
                check_root_against_log(&root.0, &log, &ForestShape::chain(4)).is_err(),
                "another bracketing is rejected"
            );
        }

        /// A toy circuit (no sketch logic) exposing the HONEST leaf statement
        /// passes the statement check alone, and is rejected by the leaf VK
        /// derived from public parameters; so is a toy exposing a forged
        /// `Com(S_1)`, and a real KMV leaf of another shape. Control: the real
        /// leaf passes the pinned check.
        #[test]
        fn kmv_leaf_pin_rejects_toy() {
            let s0 = KmvState::empty(CP.k);
            let keys = batches()[0].clone();
            let real = build_kmv_leaf_expose(CP, Expose::Interval, Binding::Semantic)
                .prove_epoch_at(1, s0.clone(), keys.clone())
                .output;
            let s1 = kmv_advance(&s0, &keys);
            let bc = commit_kmv_batch(&CP, &keys);
            let log = batch_log(&commit_kmv_state(&s0), &commit_kmv_state(&s1), &[bc]);
            let vk = leaf_vk(&noop());
            assert_eq!(verify_leaves_against_log(&[&real.0], &vk, &log, Expose::Interval), Ok(()));
            let toy = |vals: &[Val]| {
                let cs: Vec<Challenge> = vals
                    .chunks(4)
                    .map(|c| Challenge::from_basis_coefficients_slice(c).expect("4 coeffs"))
                    .collect();
                prove_exposing_leaf(&cs)
            };
            let honest_vals = read_exposed_statement(&real.0).values();
            let t = toy(&honest_vals);
            assert_eq!(
                check_leaves_against_log(&[&t.0], &log, Expose::Interval),
                Ok(()),
                "the statement check alone accepts the toy"
            );
            let r = verify_leaves_against_log(&[&t.0], &vk, &log, Expose::Interval);
            println!("[kmv leaf pin] toy exposing the honest statement: {r:?}");
            assert!(r.as_ref().is_err_and(|e| e.contains("leaf 1")), "{r:?}");
            // A toy exposing a forged final (a planted value 0).
            let forged = KmvState { k: CP.k, vals: vec![0, kmv_hash(1), kmv_hash(2)] };
            let mut vals = honest_vals.clone();
            vals[8..16].copy_from_slice(&commit_kmv_state(&forged));
            let t = toy(&vals);
            let flog = batch_log(&commit_kmv_state(&s0), &commit_kmv_state(&forged), &[bc]);
            assert_eq!(check_leaves_against_log(&[&t.0], &flog, Expose::Interval), Ok(()));
            assert!(verify_leaves_against_log(&[&t.0], &vk, &flog, Expose::Interval).is_err());
            // A real leaf of another shape is another circuit.
            let other = build_kmv_leaf_expose(KmvParams { k: 8, batch: 4 }, Expose::Interval, Binding::Semantic)
                .prove_epoch_at(1, KmvState::empty(8), keys.clone())
                .output;
            assert!(verify_leaves_against_log(&[&other.0], &vk, &log, Expose::Interval).is_err());
        }
    }

    // ─── Hiding commitments (revision B2) ────────────────────────────────────

    mod hiding_b2 {
        use super::*;
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows};
        use crate::commitment::hiding::{
            SaltSeed, TAG_BATCH, TAG_STATE, rho_batch_bb as batch_salt, rho_state_bb as state_salt,
        };
        use crate::recursion::recursive::expose_forest::vk_pin_values;
        use crate::recursion::recursive::noop_leaf::{kmv_noop_leaf_commit, kmv_noop_leaf_expose};
        use crate::recursion::recursive::statement::{hash_bb, leaf_digest};
        use crate::sketch::forge;

        const KMV: CommitFamily = CommitFamily::Kmv;
        const HIDING: CommitMode = CommitMode::Hiding;
        const HP: KmvParams = KmvParams { k: 4, batch: 4 };

        /// A full prior state (5 distinct keys, capacity 4).
        fn prior() -> KmvState {
            kmv_advance(&KmvState::empty(HP.k), &[11, 22, 33, 44, 55])
        }

        /// Natives: `Plain` ignores the salt; `Hiding` is
        /// `MyHash([TAG_STATE | TAG_BATCH, Kmv = 6, 0, 0, salt…] ‖ flat)` over
        /// exactly the Plain flat (the state header and `k` packed rows; the
        /// batch header and `4·batch` record values).
        #[test]
        fn hiding_natives_match_layout() {
            let seed = SaltSeed::for_tests(51);
            let (s1, s2) = (state_salt(&seed, KMV, 1), state_salt(&seed, KMV, 2));
            let st = prior();
            assert!(st.is_full());
            assert_eq!(commit_kmv_state_with(&st, CommitMode::Plain, &s1), commit_kmv_state(&st));
            let h = MyHash::new(make_perm());
            let mut input = vec![Val::from_u64(TAG_STATE), Val::from_u64(6), Val::ZERO, Val::ZERO];
            input.extend_from_slice(&s1.0);
            input.extend([Val::from_u64(TAG_KMV_STATE), Val::from_u64(HP.k as u64), Val::ZERO, Val::ZERO]);
            input.extend(st.rows().into_iter().map(row_value));
            let want: [Val; 8] = h.hash_iter(input);
            let c1 = commit_kmv_state_with(&st, HIDING, &s1);
            assert_eq!(c1, want, "state layout drift");
            assert_eq!(commit_kmv_rows_with(HP.k, &st.rows(), HIDING, &s1), c1);
            assert_ne!(c1, commit_kmv_state_with(&st, HIDING, &s2), "two versions, two commitments");
            assert_ne!(c1, commit_kmv_state(&st));
            let recs = kmv_records(&HP, &[7, 8]);
            let b1 = batch_salt(&seed, KMV, 1);
            assert_eq!(kmv_batch_commit_with(HP.batch, &recs, CommitMode::Plain, &b1), commit_kmv_records(&HP, &recs));
            assert_eq!(kmv_batch_commit(HP.batch, &recs), commit_kmv_batch(&HP, &[7, 8]));
            let mut input = vec![Val::from_u64(TAG_BATCH), Val::from_u64(6), Val::ZERO, Val::ZERO];
            input.extend_from_slice(&b1.0);
            input.extend([Val::from_u64(TAG_KMV_BATCH), Val::from_u64(HP.batch as u64), Val::ZERO, Val::ZERO]);
            input.extend(recs.iter().flat_map(|&r| record_vals(rec_raw(r))));
            let want: [Val; 8] = h.hash_iter(input);
            assert_eq!(kmv_batch_commit_with(HP.batch, &recs, HIDING, &b1), want, "batch layout drift");
            // The tag prefix separates hiding from plain even under the zero salt.
            assert_ne!(commit_kmv_state_with(&st, HIDING, &SaltBb::ZERO), commit_kmv_state(&st));
        }

        /// A hiding leaf's commitments (proof fields and the exposed Interval
        /// statement, under both bindings) are the NATIVE hiding commitments
        /// under the leaf-`t` openings, and differ from the Plain ones.
        #[test]
        fn hiding_leaf_exposes_native_hiding_commitments() {
            let seed = SaltSeed::for_tests(52);
            let t = 3u64;
            let (pr, keys) = (prior(), vec![5u64, 66, 5, 77]);
            let fin = kmv_advance(&pr, &keys);
            let o = Openings::for_leaf(&seed, KMV, t);
            let init = commit_kmv_state_with(&pr, HIDING, &state_salt(&seed, KMV, t - 1));
            let fc = commit_kmv_state_with(&fin, HIDING, &state_salt(&seed, KMV, t));
            let bc = kmv_batch_commit_with(HP.batch, &kmv_records(&HP, &keys), HIDING, &batch_salt(&seed, KMV, t));
            assert_ne!(fc, commit_kmv_state(&fin));
            assert_ne!(bc, commit_kmv_batch(&HP, &keys));
            for binding in [Binding::Semantic, Binding::Bound] {
                let mut iv = build_kmv_leaf_commit(HP, Expose::Interval, binding, HIDING);
                assert_eq!(iv.commit_mode(), HIDING);
                let r = iv.prove_epoch_commit(t, pr.clone(), keys.clone(), &o);
                assert_eq!(r.final_state, fin, "{binding:?}");
                assert_eq!((r.initial_commit, r.final_commit, r.batch_commit), (init, fc, bc), "{binding:?}");
                let st = read_exposed_statement(&r.output.0);
                assert_eq!((st.init, st.final_), (init.to_vec(), fc.to_vec()), "{binding:?}");
                let ip = st.interval.expect("interval part");
                assert_eq!((ip.lo, ip.hi), (Val::from_u64(t), Val::from_u64(t)));
                assert_eq!(ip.digest, leaf_digest(&hash_bb, 4, t, &bc), "H(TAG_LEAF, t, Com(B_t; salt))");
            }
        }

        /// The Plain leaf through the commit API is the pre-B2 leaf (same VK
        /// and commitments as the `*_expose` builder, every layout); the hiding
        /// VK differs, does not depend on the salts, and is the zero-salt no-op
        /// leaf's. A hiding leaf costs exactly +9 ALU rows (3 salts) and
        /// exposes no salt value.
        #[test]
        fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
            let (pr, keys) = (prior(), vec![5u64, 66]);
            let vk = |o: &KmvProof| vk_pin_values(&o.output.0);
            let sem = Binding::Semantic;
            for expose in [Expose::None, Expose::Boundary, Expose::Interval] {
                let old = build_kmv_leaf_expose(HP, expose, sem).prove_epoch_at(2, pr.clone(), keys.clone());
                let plain = build_kmv_leaf_commit(HP, expose, sem, CommitMode::Plain)
                    .prove_epoch_at(2, pr.clone(), keys.clone());
                assert_eq!(vk(&plain), vk(&old), "{expose:?}: Plain VK");
                assert_eq!(
                    (plain.initial_commit, plain.final_commit, plain.batch_commit),
                    (old.initial_commit, old.final_commit, old.batch_commit),
                    "{expose:?}"
                );
                let mut leaf = build_kmv_leaf_commit(HP, expose, sem, HIDING);
                let o5 = Openings::for_leaf(&SaltSeed::for_tests(1), KMV, 5);
                let a = leaf.prove_epoch_commit(5, pr.clone(), keys.clone(), &o5);
                let b = leaf.prove_epoch_commit(
                    1,
                    KmvState::empty(HP.k),
                    keys.clone(),
                    &Openings::for_leaf(&SaltSeed::for_tests(2), KMV, 1),
                );
                assert_ne!(vk(&a), vk(&old), "{expose:?}: the hiding circuit differs");
                assert_eq!(vk(&a), vk(&b), "{expose:?}: salt-independent VK");
                assert_eq!(proof_alu_rows(&a.output.0), proof_alu_rows(&old.output.0) + 9, "{expose:?}: ALU rows");
                assert_eq!(leaked_salts(&a.output.0, &[o5.init, o5.final_, o5.batch]), vec![], "{expose:?}");
                if expose != Expose::None {
                    let mut control = SaltBb::ZERO;
                    control.0[0] = a.final_commit[0];
                    assert!(!leaked_salts(&a.output.0, &[control]).is_empty(), "{expose:?}: the scan sees the statement");
                    assert_eq!(vk_pin_values(&kmv_noop_leaf_expose(HP, expose, sem)), vk(&old));
                    assert_eq!(vk_pin_values(&kmv_noop_leaf_commit(HP, expose, sem, CommitMode::Plain)), vk(&old));
                    assert_eq!(vk_pin_values(&kmv_noop_leaf_commit(HP, expose, sem, HIDING)), vk(&a));
                }
            }
        }

        /// A hiding leaf never falls back to zero salts silently: the old
        /// entry points panic, and so do zero final / batch salts and a zero
        /// init on a real prior (or at `t ≥ 2`); the explicit no-op path
        /// accepts only the empty state with an all-dummy batch at `t = 1`,
        /// and then exposes `init == final == Com(S_0; 0)`. Controls: leaf 1
        /// from the empty state opens `Com(S_0; 0)`, and a Plain leaf ignores
        /// its openings.
        #[test]
        fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
            let seed = SaltSeed::for_tests(53);
            let (pr, keys) = (prior(), vec![5u64, 66]);
            let empty = KmvState::empty(HP.k);
            let mut leaf = build_kmv_leaf_commit(HP, Expose::Interval, Binding::Semantic, HIDING);
            let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, pr.clone(), keys.clone()).final_commit).unwrap_err();
            assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
            assert!(forge::catch(|| leaf.prove_records_at(1, empty.clone(), vec![None; HP.batch]).final_commit).is_none());
            let honest = Openings::for_leaf(&seed, KMV, 2);
            for (what, o) in [
                ("plain", Openings::plain()),
                ("zero final", Openings { final_: SaltBb::ZERO, ..honest }),
                ("zero batch", Openings { batch: SaltBb::ZERO, ..honest }),
            ] {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(2, pr.clone(), keys.clone(), &o).final_commit)
                    .unwrap_err();
                assert!(msg.contains("public zero salt"), "{what}: {msg}");
            }
            let forgot = Openings { init: SaltBb::ZERO, ..honest };
            for (what, t, init) in [("real prior", 2u64, &pr), ("t = 2 on the empty state", 2, &empty)] {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(t, init.clone(), keys.clone(), &forgot).final_commit)
                    .unwrap_err();
                assert!(msg.contains("zero init salt"), "{what}: {msg}");
            }
            let local = Openings::for_leaf(&seed, KMV, 1);
            let msg = forge::catch_msg(|| leaf.prove_epoch_commit(1, pr.clone(), keys.clone(), &local).final_commit)
                .unwrap_err();
            assert!(msg.contains("zero init salt"), "leaf-1 openings on a real prior: {msg}");
            for (what, t, init, k) in [
                ("a real prior", 1u64, &pr, vec![]),
                ("a real key", 1, &empty, vec![5u64]),
                ("another batch index", 2, &empty, vec![]),
            ] {
                let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(t, init.clone(), k.clone()).final_commit)
                    .unwrap_err();
                assert!(msg.contains("no-op leaf"), "{what}: {msg}");
            }
            let noop = leaf.prove_epoch_public_zero(1, empty.clone(), vec![]);
            let z = commit_kmv_state_with(&empty, HIDING, &SaltBb::ZERO);
            assert_eq!((noop.initial_commit, noop.final_commit), (z, z));
            let st = read_exposed_statement(&noop.output.0);
            assert_eq!(st.init, st.final_, "the zero-salt no-op leaf exposes init == final");
            let r = leaf.prove_epoch_commit(1, empty.clone(), keys.clone(), &local);
            assert_eq!(r.initial_commit, z, "leaf 1 opens the public genesis Com(S_0; 0)");
            let mut plain = build_kmv_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Plain);
            let p = plain.prove_epoch_commit(2, pr.clone(), keys.clone(), &honest);
            assert_eq!(p.initial_commit, commit_kmv_state(&pr), "Plain ignores the openings");
            assert_eq!(p.batch_commit, commit_kmv_batch(&HP, &keys));
        }

        /// Hiding leaves chain: leaf `t`'s final and leaf `t + 1`'s init are
        /// the same `Com(S_t; ρ^S_t)`, and the merge of two hiding leaves
        /// verifies (an inconsistent init salt breaks the merge's in-circuit
        /// boundary bind).
        #[test]
        fn hiding_leaves_chain_and_merge() {
            use crate::recursion::recursive::expose_forest::prove_hiding_merge;
            let seed = SaltSeed::for_tests(54);
            let (k1, k2) = (vec![1u64, 2, 3], vec![4u64, 2, 5, 6]);
            let s0 = KmvState::empty(HP.k);
            let s1 = kmv_advance(&s0, &k1);
            let mut leaf = build_kmv_leaf_commit(HP, Expose::Interval, Binding::Semantic, HIDING);
            let l1 = leaf.prove_epoch_commit(1, s0.clone(), k1.clone(), &Openings::for_leaf(&seed, KMV, 1));
            let l2 = leaf.prove_epoch_commit(2, s1.clone(), k2.clone(), &Openings::for_leaf(&seed, KMV, 2));
            assert_eq!(l1.final_commit, l2.initial_commit, "leaf 1's final is leaf 2's init");
            let root = prove_hiding_merge(&l1.output, &l2.output);
            let st = read_exposed_statement(&root.0);
            assert_eq!(st.init, l1.initial_commit.to_vec());
            assert_eq!(st.final_, l2.final_commit.to_vec());
            let bad = Openings { init: state_salt(&SaltSeed::for_tests(55), KMV, 1), ..Openings::for_leaf(&seed, KMV, 2) };
            let l2b = leaf.prove_epoch_commit(2, s1.clone(), k2.clone(), &bad);
            assert_ne!(l1.final_commit, l2b.initial_commit);
            let r = forge::catch_msg(|| {
                let _ = prove_hiding_merge(&l1.output, &l2b.output);
            });
            assert!(r.is_err(), "a merge across inconsistent salts must fail");
        }
    }

    // ─── Measurement ─────────────────────────────────────────────────────────

    /// Trace rows and prove time of one epoch from a FULL prior state.
    /// `KMV_MEASURE="k,m[;k,m...]" cargo test --release --lib
    /// kmv::tests::kmv_measure -- --ignored --nocapture` (default
    /// `1024,1024;4096,4096`).
    #[test]
    #[ignore = "measurement: large circuits"]
    fn kmv_measure() {
        let spec = std::env::var("KMV_MEASURE").unwrap_or_else(|_| "1024,1024;4096,4096".into());
        for shape in spec.split(';') {
            let v: Vec<usize> = shape.split(',').map(|x| x.trim().parse().unwrap()).collect();
            let params = KmvParams { k: v[0], batch: v[1] };
            let prior_keys: Vec<u64> =
                (0..4 * params.k as u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x1111).collect();
            let prior = kmv_advance(&KmvState::empty(params.k), &prior_keys);
            let keys: Vec<u64> = (0..params.batch as u64)
                .map(|i| i.wrapping_mul(0xD1B5_4A32_D192_ED03) ^ 0x5555)
                .collect();
            for expose in [Expose::None, Expose::Interval] {
                let t_b = std::time::Instant::now();
                let mut leaf = build_kmv_leaf_expose(params, expose, Binding::Semantic);
                let build = t_b.elapsed();
                let t = std::time::Instant::now();
                let proof = leaf.prove_epoch(prior.clone(), keys.clone());
                let total = t.elapsed();
                let tm = crate::recursion::recursive::timing::take();
                assert_eq!(proof.final_state, kmv_advance(&prior, &keys));
                eprintln!(
                    "KMV_MEASURE k={} m={} expose={:?} trace_rows={} tables={:?} build_ms={:.0} witness_ms={:.0} prove_ms={:.0} verify_ms={:.0} total_ms={:.0} proof_bytes={}",
                    params.k, params.batch, expose, leaf.trace_rows(), leaf.table_rows(),
                    build.as_secs_f64() * 1e3, tm.witness.as_secs_f64() * 1e3,
                    tm.prove.as_secs_f64() * 1e3, tm.verify.as_secs_f64() * 1e3,
                    total.as_secs_f64() * 1e3, proof.proof_size()
                );
            }
        }
    }
}
