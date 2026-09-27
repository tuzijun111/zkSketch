//! **Complete SpaceSaving update circuit** (paper Appendix D/G, Pattern B
//! top-`s` retention) — the optimized counterpart to the
//! [`crate::sketch::ss_final`] baseline, mirroring how
//! [`crate::sketch::gk_final_full`] completes [`crate::sketch::gk_final`].
//!
//! Where `ss_final` only certified the Poseidon2 commits + active-flag
//! monotonicity + mass conservation (Steps 2–4 deferred), this module
//! enforces the full §G pipeline in-circuit:
//!
//! 1. **Bind** old state + batch to their commitments (Poseidon2).
//! 2. **Union** `(S_old.active ‖ B.active)` — realized as the input to
//!    the key-sort PermuteAir (the multiset check ties the sorted view to
//!    the combined old+batch rows; no separate union table needed).
//! 3. **Group by key, sum counts** — key-sort via PermuteAir, then
//!    PoneglyphDB §4.3 adjacency-equality tags + a running sum produce the
//!    grouped candidate table `G` (one summed row per distinct key; the
//!    rest become dummies). This is the Count-Min running-sum gadget.
//! 4. **Top-`s` retention** — a second PermuteAir re-sorts `G` by
//!    `(active asc, count asc)`; range-checked count-sortedness +
//!    active-monotonicity force the canonical order, and the compaction
//!    binds `S_new = G_sorted[batch..]` (the **top `capacity` by count**)
//!    and `residual = G_sorted[..batch]`. Because the table is sorted
//!    count-ascending, every residual row's count is `≤` the smallest
//!    kept count — exactly the paper's threshold-residual condition
//!    `R[q] ⪯ τ` (no omitted candidate beats the worst retained one).
//! 5. **Recommit** `S_new` to `C_new` (whole-state replacement).
//! 6. **Metadata** via `params.validate()`.
//!
//! Plus **mass conservation**: `Σ(S_new.count) + Σ(residual.count) =
//! Σ(S_old.count·active) + Σ(B.value·active)` — SpaceSaving's grouping
//! preserves total weight.
//!
//! ### Convention (mirrors `gk_final_full`)
//!
//! Rows are kept in `(active asc, count asc)` order: dummies (count 0)
//! first, then actives by ascending count. So the **top `capacity`** rows
//! (highest counts = heavy hitters) are the *last* `capacity`, and the
//! count diff `count[r+1] − count[r]` is non-negative across **every**
//! adjacent pair (the dummy→active boundary too, since dummies have
//! count 0), which lets the sortedness check be a plain
//! `decompose_to_bits(count[r+1] − count[r], COUNT_DIFF_BITS)` with no
//! gating — sidestepping the `mul(decompose, decompose)` bus issue.
//!
//! ### Why §G's single-pass retention (no GK-style log rounds)
//!
//! Top-`s` retention is a single threshold cut, not iterative fusion:
//! group once, sort once, split once. So unlike `gk_final_full` there is
//! no `L`-round schedule — SpaceSaving is the cheapest Pattern B family,
//! exactly as the paper notes ("SpaceSaving avoids the … round count").
//!
//! ### Permute domains (shared PermuteBus)
//!
//! The pinned fork concatenates every `add_permute` of a circuit into ONE
//! PermuteAir whose `PermuteBus` message is the four value coordinates only
//! (no op id), so it proves only that the union of all permute inputs equals
//! the union of all outputs. With both permutes on the same untagged
//! `[key_lo, key_hi, count, active]` encoding a prover could trade rows
//! between them and re-fragment a key (PoC:
//! `tests::shared_permute_bus_forgery_rejected`, accepted before the fix).
//! The count-sort domain (`grouped`, `g_sorted`, `residual`) therefore carries
//! `GROUPED_OP_TAG` in the `key_hi` slot (keys are single-limb, and
//! `key_sorted.key_hi = 0` is enforced), which restores per-op multiset
//! equality by a counting argument. NOTE: like every constraint on decomposed
//! fields, this relies on decompositions being bound to their packed values,
//! which the fork's `recompose/coeff` lowering does by default (see
//! `crate::recompose_binding` and `BIND_DECOMPOSITIONS`).
//!
//! ### Assumptions / scope
//!
//! - Per-record `count`/`value` fit in `COUNT_DIFF_BITS − 1` bits
//!   (`< 2^21`); `key` fits in one BabyBear limb (`key_hi = 0`, so
//!   `key < 2^31`) so the group-by adjacency test on `key_field` has no
//!   field-wrap collisions. The test workloads honor both.
//! - Real keys must be non-zero (key `0` is the dummy sentinel). The
//!   all-dummy rows form one key-0 segment whose summed count is 0; that
//!   count-0 "segment-end" row sorts to the bottom and never enters the
//!   top-`capacity`, so it's harmless.
//! - The `(count, key)` total order's **key tie-breaker** is not strictly
//!   verified (we verify the primary count order + the multiset +
//!   exact-kept-count); ties on count are resolved by the prover's stable
//!   sort. This is the same flavor of honest-prover latitude that
//!   `gk_final_full` documents for its fusion policy.
//! - Flat Poseidon2-over-all-rows commitment (same as `gk_final_full`);
//!   the §G "whole-state recommit" is `∝ capacity`, which is inherent for
//!   a bounded summary (sparse openings wouldn't help).
//!
//! ### Hiding commitments (revision B2)
//!
//! [`build_ss_full_leaf_commit`] with [`CommitMode::Hiding`] salts all three
//! commitments, `Com(x; ρ) = MyHash([kind, SpaceSaving, 0, 0, ρ…] ‖ rows)`
//! ([`commit_ss_state_with`] / [`commit_ss_batch_with`], see
//! [`crate::commitment::hiding`]): +2 Poseidon2 and +3 ALU rows per
//! commitment. Prove it with [`SsFullLeafCircuit::prove_epoch_commit`]; the
//! no-op VK-derivation leaf uses [`SsFullLeafCircuit::prove_epoch_public_zero`].
//! Every pre-B2 entry point builds the `Plain` circuit, byte for byte.

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
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::hiding::{self, CommitFamily, CommitKind, CommitMode, Openings, SaltBb};
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::sketch::bind::Binding;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Range for the count-sortedness diff. `count < 2^(COUNT_DIFF_BITS−1)`
/// so the unsigned diff `count[r+1] − count[r]` fits in `COUNT_DIFF_BITS`
/// bits; a "negative" diff wraps to ≈ p and overflows, soundly rejecting.
const COUNT_DIFF_BITS: usize = 22;

/// Bit-width for the union **key**-sortedness check (and single-limb key
/// range-check). Keys are bound to `[0, 2^KEY_DIFF_BITS)`, so the union sort
/// diff `key[r] − key[r-1]` is non-negative only when it fits in
/// `KEY_DIFF_BITS` bits: a real decrease wraps to `≈ p` (> 2^KEY_DIFF_BITS,
/// since `2·2^KEY_DIFF_BITS < p`) and fails, forcing equal keys to be
/// adjacent. Must satisfy `2^(KEY_DIFF_BITS+1) < p` (BabyBear `p ≈ 2^30.9`),
/// so 29 is the max safe width; callers mask keys to `KEY_DIFF_BITS` bits.
const KEY_DIFF_BITS: usize = 29;

/// Permute-domain tag carried in the `key_hi` coordinate of every row the
/// COUNT-SORT permute moves (`grouped` → `g_sorted`). The key-sort permute's
/// rows (`combined` → `key_sorted`) have `key_hi = 0`. See Stage 6.
const GROUPED_OP_TAG: u32 = 1;

// ─── Types ─────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SsFullRow {
    pub key: u64,
    pub count: u32,
    pub active: u32,
}

impl SsFullRow {
    pub const fn real(key: u64, count: u32) -> Self {
        Self {
            key,
            count,
            active: 1,
        }
    }
    pub const fn dummy() -> Self {
        Self {
            key: 0,
            count: 0,
            active: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SsFullUpdate {
    pub key: u64,
    pub value: u32,
    pub active: u32,
}

impl SsFullUpdate {
    pub const fn real(key: u64, value: u32) -> Self {
        Self {
            key,
            value,
            active: 1,
        }
    }
    pub const fn dummy() -> Self {
        Self {
            key: 0,
            value: 0,
            active: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SsFullParams {
    pub capacity: usize,
    pub batch: usize,
}

impl SsFullParams {
    pub fn union_size(&self) -> usize {
        self.capacity + self.batch
    }
    pub fn validate(&self) {
        assert!(self.capacity >= 2 && self.capacity % 2 == 0);
        assert!(self.batch >= 2 && self.batch % 2 == 0);
        assert!((self.capacity + self.batch) % 2 == 0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsFullState {
    pub rows: Vec<SsFullRow>,
    pub params: SsFullParams,
}

impl SsFullState {
    pub fn empty(params: SsFullParams) -> Self {
        Self {
            rows: vec![SsFullRow::dummy(); params.capacity],
            params,
        }
    }
    pub fn active_count(&self) -> usize {
        self.rows.iter().filter(|r| r.active == 1).count()
    }
    pub fn total_mass(&self) -> u64 {
        self.rows
            .iter()
            .filter(|r| r.active == 1)
            .map(|r| r.count as u64)
            .sum()
    }
    pub fn frequency(&self, key: u64) -> u32 {
        self.rows
            .iter()
            .find(|r| r.active == 1 && r.key == key)
            .map(|r| r.count)
            .unwrap_or(0)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SsFullStateCommit(pub [Val; 8]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SsFullBatchCommit(pub [Val; 8]);

pub struct SsFullLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: SsFullStateCommit,
    pub final_: SsFullStateCommit,
    pub batch_commit: SsFullBatchCommit,
    pub params: SsFullParams,
}

pub struct SsFullProof {
    pub proof: SsFullLeafProof,
    pub final_state: SsFullState,
}

impl SsFullProof {
    pub fn frequency(&self, key: u64) -> u32 {
        self.final_state.frequency(key)
    }
}

// ─── Native packing ──────────────────────────────────────────────────────

fn key_lo_hi(key: u64) -> (u32, u32) {
    ((key & 0xFFFF_FFFF) as u32, (key >> 32) as u32)
}

fn pack_state_to_challenge(state: &SsFullState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    state
        .rows
        .iter()
        .map(|r| {
            let (lo, hi) = key_lo_hi(r.key);
            let coeffs = [
                Val::from_u32(lo),
                Val::from_u32(hi),
                Val::from_u32(r.count),
                Val::from_u32(r.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn pack_batch_to_challenge(batch: &[SsFullUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    batch
        .iter()
        .map(|u| {
            let (lo, hi) = key_lo_hi(u.key);
            let coeffs = [
                Val::from_u32(lo),
                Val::from_u32(hi),
                Val::from_u32(u.value),
                Val::from_u32(u.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

/// Pack a generic (key, count, active) row table to Challenges.
fn pack_rows_to_challenge(rows: &[SsFullRow]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    rows.iter()
        .map(|r| {
            let (lo, hi) = key_lo_hi(r.key);
            let coeffs = [
                Val::from_u32(lo),
                Val::from_u32(hi),
                Val::from_u32(r.count),
                Val::from_u32(r.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn flat_state_vals(state: &SsFullState) -> Vec<Val> {
    state
        .rows
        .iter()
        .flat_map(|r| {
            let (lo, hi) = key_lo_hi(r.key);
            [
                Val::from_u32(lo),
                Val::from_u32(hi),
                Val::from_u32(r.count),
                Val::from_u32(r.active),
            ]
        })
        .collect()
}

fn flat_batch_vals(batch: &[SsFullUpdate]) -> Vec<Val> {
    batch
        .iter()
        .flat_map(|u| {
            let (lo, hi) = key_lo_hi(u.key);
            [
                Val::from_u32(lo),
                Val::from_u32(hi),
                Val::from_u32(u.value),
                Val::from_u32(u.active),
            ]
        })
        .collect()
}

pub fn commit_ss_state(state: &SsFullState) -> SsFullStateCommit {
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 8] = hasher.hash_iter(flat_state_vals(state));
    SsFullStateCommit(digest)
}

pub fn commit_ss_batch(batch: &[SsFullUpdate]) -> SsFullBatchCommit {
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 8] = hasher.hash_iter(flat_batch_vals(batch));
    SsFullBatchCommit(digest)
}

/// [`commit_ss_state`] under a [`CommitMode`] (revision B2,
/// [`crate::commitment::hiding`]): `Plain` is exactly [`commit_ss_state`]
/// (the salt is ignored); `Hiding` is `MyHash([TAG_STATE, SpaceSaving, 0, 0,
/// ρ…] ‖ rows)` over the same flat rows, the value the certified leaf and the
/// top-`c` decoder expose for `Com(S_t; ρ)`. Each row is 4 base values, so
/// the rows stay rate-aligned behind the 16-value prefix.
pub fn commit_ss_state_with(state: &SsFullState, mode: CommitMode, salt: &SaltBb) -> SsFullStateCommit {
    match mode {
        CommitMode::Plain => commit_ss_state(state),
        CommitMode::Hiding => SsFullStateCommit(hiding::commit_flat_bb(
            mode,
            CommitKind::State,
            CommitFamily::SpaceSaving,
            salt,
            &flat_state_vals(state),
        )),
    }
}

/// [`commit_ss_batch`] under a [`CommitMode`]: `Plain` is exactly
/// [`commit_ss_batch`]; `Hiding` is `Com(B_t; ρ) = MyHash([TAG_BATCH,
/// SpaceSaving, 0, 0, ρ…] ‖ records)`, the value a `Hiding` leaf opened with
/// `batch = ρ` binds.
pub fn commit_ss_batch_with(batch: &[SsFullUpdate], mode: CommitMode, salt: &SaltBb) -> SsFullBatchCommit {
    match mode {
        CommitMode::Plain => commit_ss_batch(batch),
        CommitMode::Hiding => SsFullBatchCommit(hiding::commit_flat_bb(
            mode,
            CommitKind::Batch,
            CommitFamily::SpaceSaving,
            salt,
            &flat_batch_vals(batch),
        )),
    }
}

// ─── Native: batched top-s update ────────────────────────────────────────

/// One row of the combined (key-sorted) union, used to drive the
/// in-circuit group-by. The circuit reconstructs all of this from the
/// permutation witness, so only the permutations are surfaced.
#[derive(Clone)]
struct SsBuild {
    /// `combined` = old rows ‖ batch rows (length cap+m), unsorted.
    #[allow(dead_code)] // reference copy; the circuit reads `key_sorted` directly.
    combined: Vec<SsFullRow>,
    /// permutation σ_key with `key_sorted[i] = combined[σ_key[i]]`.
    sigma_key: Vec<usize>,
    /// `key_sorted` = the key-sort permute's output table (honestly
    /// `combined[σ_key[i]]`; a soundness test may hand-craft it).
    key_sorted: Vec<SsFullRow>,
    /// grouped table `G` (length cap+m): segment-end rows carry the summed
    /// count, others are dummies.
    grouped: Vec<SsFullRow>,
    /// per-row adjacency-equal tag on the key-sorted view (`tag[r]=1` iff
    /// `key_sorted[r] == key_sorted[r-1]`); `tag[0]=0`.
    key_eq_tag: Vec<u32>,
    /// segment-end indicator on the key-sorted view.
    seg_end: Vec<u32>,
    /// permutation σ_count with `g_sorted[i] = grouped[σ_count[i]]`.
    sigma_count: Vec<usize>,
    /// `g_sorted` = grouped re-sorted by (active asc, count asc, key asc).
    g_sorted: Vec<SsFullRow>,
    /// The `(s+1)`-th largest grouped count, `τ = g_sorted[m-1].count` — the
    /// mergeable Misra-Gries / Frequent compression threshold subtracted from
    /// every retained counter (Agarwal et al., "Mergeable Summaries", 2012).
    /// `0` whenever the summary is under-full (row `m-1` is a dummy), so the
    /// subtraction is a no-op there.
    tau: u32,
}

fn key_field(key: u64) -> u128 {
    let (lo, hi) = key_lo_hi(key);
    (lo as u128) + ((hi as u128) << 32)
}

/// Group a key-sorted table by ADJACENT equal keys (the in-circuit
/// PoneglyphDB running-sum gadget): returns `(key_eq_tag, seg_end, grouped)`.
/// `grouped[r]` is the segment total at a segment end (active iff any
/// contributor was active) and a dummy elsewhere.
fn group_by_key(key_sorted: &[SsFullRow]) -> (Vec<u32>, Vec<u32>, Vec<SsFullRow>) {
    let total = key_sorted.len();
    let mut key_eq_tag = vec![0u32; total];
    let mut acc_count = vec![0u64; total];
    let mut acc_active = vec![0u64; total];
    for r in 0..total {
        if r > 0 && key_field(key_sorted[r].key) == key_field(key_sorted[r - 1].key) {
            key_eq_tag[r] = 1;
            acc_count[r] = acc_count[r - 1] + key_sorted[r].count as u64;
            acc_active[r] = acc_active[r - 1] + key_sorted[r].active as u64;
        } else {
            acc_count[r] = key_sorted[r].count as u64;
            acc_active[r] = key_sorted[r].active as u64;
        }
    }
    let mut seg_end = vec![0u32; total];
    for r in 0..total {
        seg_end[r] =
            if r + 1 == total || key_field(key_sorted[r + 1].key) != key_field(key_sorted[r].key) {
                1
            } else {
                0
            };
    }

    // grouped table G: segment-end rows carry the summed count; the row is
    // "active" iff the segment had any active contributor (acc_active > 0).
    let mut grouped = vec![SsFullRow::dummy(); total];
    for r in 0..total {
        if seg_end[r] == 1 {
            let act = if acc_active[r] > 0 { 1 } else { 0 };
            grouped[r] = SsFullRow {
                key: if act == 1 { key_sorted[r].key } else { 0 },
                count: if act == 1 { acc_count[r] as u32 } else { 0 },
                active: act,
            };
        }
    }
    (key_eq_tag, seg_end, grouped)
}

/// The mergeable Misra-Gries compression of a count-sorted grouped table:
/// `S_new = g_sorted[m..]` with `τ` subtracted (non-positive → dummy), and
/// `residual = g_sorted[..m]` (original counts).
fn compress_from_gsorted(
    params: SsFullParams,
    g_sorted: &[SsFullRow],
    tau: u32,
) -> (SsFullState, Vec<SsFullRow>) {
    let cap = params.capacity;
    let m = params.batch;
    let residual: Vec<SsFullRow> = g_sorted[..m].to_vec();
    let s_new: Vec<SsFullRow> = (0..cap)
        .map(|i| {
            let src = g_sorted[m + i];
            let c = src.count.saturating_sub(tau);
            if src.active == 1 && c > 0 {
                SsFullRow::real(src.key, c)
            } else {
                SsFullRow::dummy()
            }
        })
        .collect();
    (
        SsFullState {
            rows: s_new,
            params,
        },
        residual,
    )
}

/// Build the SpaceSaving top-`s` update certificate witnesses.
fn build_ss(s_old: &SsFullState, batch: &[SsFullUpdate]) -> SsBuild {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;

    // combined = old rows (key,count,active) ‖ batch rows (key,value,active)
    let mut combined: Vec<SsFullRow> = Vec::with_capacity(total);
    for r in &s_old.rows {
        combined.push(*r);
    }
    for u in batch {
        combined.push(SsFullRow {
            key: u.key,
            count: u.value,
            active: u.active,
        });
    }

    // key-sort (ascending by key_field; stable for determinism).
    let mut idx: Vec<usize> = (0..total).collect();
    idx.sort_by_key(|&i| key_field(combined[i].key));
    // Test-only: leave the union unsorted so same-key rows that aren't already
    // adjacent in `[old ‖ batch]` fragment under the adjacency-only group-by.
    // The circuit accepts it because union key-sortedness is never enforced.
    #[cfg(test)]
    if TAMPER_FRAGMENT.with(|f| f.get()) {
        idx = (0..total).collect();
    }
    let sigma_key = idx.clone();
    let key_sorted: Vec<SsFullRow> = idx.iter().map(|&i| combined[i]).collect();

    // adjacency tags + running sum (count + active) over equal-key runs.
    #[allow(unused_mut)]
    let (key_eq_tag, seg_end, mut grouped) = group_by_key(&key_sorted);

    // Test-only: demote the largest-key count-0 ACTIVE segment to a dummy
    // (active bit flipped off), freeing a retained slot for a different
    // zero-weight key. The active-binding constraint must reject it.
    #[cfg(test)]
    if TAMPER_ACTIVE.with(|f| f.get()) {
        for r in (0..total).rev() {
            if seg_end[r] == 1 && grouped[r].active == 1 && grouped[r].count == 0 {
                grouped[r] = SsFullRow::dummy();
                break;
            }
        }
    }

    // count-sort G by (active asc, count asc, key asc).
    let mut idx2: Vec<usize> = (0..total).collect();
    idx2.sort_by_key(|&i| {
        (
            grouped[i].active,
            grouped[i].count,
            key_field(grouped[i].key),
        )
    });
    // Test-only: break count ties by DESCENDING key, a non-canonical order that
    // keeps a different equal-count subset across the top-s cut. The key
    // tie-break constraint must reject it. (Prod callers never set this.)
    #[cfg(test)]
    if TAMPER_TIE.with(|f| f.get()) {
        idx2.sort_by_key(|&i| {
            (
                grouped[i].active,
                grouped[i].count,
                std::cmp::Reverse(key_field(grouped[i].key)),
            )
        });
    }
    let sigma_count = idx2.clone();
    let g_sorted: Vec<SsFullRow> = idx2.iter().map(|&i| grouped[i]).collect();

    // τ = the (s+1)-th largest grouped count = the largest residual count =
    // `g_sorted[m-1].count` (count-ascending, the row just below the retention
    // cut). NOT `g_sorted[m]` (smallest retained), which would over-delete.
    let tau = g_sorted[m - 1].count;

    SsBuild {
        combined,
        sigma_key,
        key_sorted,
        grouped,
        key_eq_tag,
        seg_end,
        sigma_count,
        g_sorted,
        tau,
    }
}

/// Apply the batched SpaceSaving top-`s` update natively, returning
/// `(s_new, residual)`. `s_new` = the top `capacity` candidates by count;
/// `residual` = the lower candidates + dummies (length `batch`).
pub fn apply_batch_ss_full(
    s_old: &SsFullState,
    batch: &[SsFullUpdate],
) -> (SsFullState, Vec<SsFullRow>) {
    let m = s_old.params.batch;
    assert_eq!(batch.len(), m);
    let b = build_ss(s_old, batch);
    // Mergeable Misra-Gries / Frequent compression (Agarwal et al. 2012):
    // subtract the (s+1)-th largest grouped count `τ` from every retained
    // counter and clamp non-positive counters to dummies. This gives the
    // cross-batch N/s heavy-hitter *surfacing* guarantee — retained counts are
    // exact-or-under-estimates with per-key deficit ≤ N/s, so every key with
    // true frequency > N/s stays active. Because `g_sorted[m..]` is
    // count-ascending, each retained count ≥ `g_sorted[m] ≥ τ`, so the
    // saturating subtraction never truncates a real survivor and the clamped
    // (count-0) rows form the low-count prefix — final stays (active asc, count asc).
    compress_from_gsorted(s_old.params, &b.g_sorted, b.tau)
}

/// Every table the SS leaf binds. [`SsFullLeafCircuit::prove_epoch`] derives
/// it honestly from `(S_old, B)`; soundness tests hand-craft one to play a
/// malicious prover (see `tests::shared_permute_bus_*`).
#[derive(Clone)]
struct SsWitness {
    initial: SsFullState,
    batch: Vec<SsFullUpdate>,
    final_state: SsFullState,
    residual: Vec<SsFullRow>,
    build: SsBuild,
}

fn honest_ss_witness(initial: &SsFullState, batch: &[SsFullUpdate]) -> SsWitness {
    let (final_state, residual) = apply_batch_ss_full(initial, batch);
    let build = build_ss(initial, batch);
    SsWitness {
        initial: initial.clone(),
        batch: batch.to_vec(),
        final_state,
        residual,
        build,
    }
}

// ─── Test-only soundness hook ─────────────────────────────────────────────
// When set, the prover corrupts the `g_sorted` table so it no longer
// matches the count-sort permute of `grouped`. Exercises whether the
// count-sort PermuteAir + sortedness + compaction reject a bogus
// post-retention table. Production callers never touch this.
#[cfg(test)]
thread_local! {
    static TAMPER_GSORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When set, the prover leaves the key-union UNSORTED (identity σ_key). Since
    /// the circuit binds `key_sorted` to `combined` only as a MULTISET permutation
    /// and never checks it is sorted by key, a key whose rows are non-adjacent in
    /// `[old ‖ batch]` fragments into several sub-count grouped rows under the
    /// adjacency-only group-by — so a genuine top-`s` key can be evicted. Drives
    /// [`tests::fragmentation_rejected`] (the union-sortedness fix's regression).
    static TAMPER_FRAGMENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When set, the prover breaks count ties in the count-sort by DESCENDING
    /// key, a non-canonical order that retains a different equal-count subset
    /// across the top-`s` cut. The key tie-break constraint must reject it.
    /// Drives [`tests::tie_break_rejected`].
    static TAMPER_TIE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When set, the prover demotes the largest-key count-0 ACTIVE segment to a
    /// dummy (flipping its active bit off) to free a leftover retained slot for
    /// a different zero-weight key. The `grouped.active = se·(acc_active≠0)`
    /// binding must reject it. Drives [`tests::count0_active_rejected`].
    static TAMPER_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Test-only override of [`bind_decompositions`].
    static BIND_DECOMP: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    /// Test-only override of [`use_op_tag`] (`Some(false)` = pre-fix circuit).
    static OP_TAG: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Whether the count-sort permute domain is op-tagged (shared-PermuteBus fix).
/// Always on outside tests.
fn use_op_tag() -> bool {
    #[cfg(test)]
    if let Some(v) = OP_TAG.with(|c| c.get()) {
        return v;
    }
    true
}

/// Circuit-level decomposition binding (OFF by default — see
/// [`BIND_DECOMPOSITIONS`]).
fn bind_decompositions() -> bool {
    #[cfg(test)]
    if let Some(v) = BIND_DECOMP.with(|c| c.get()) {
        return v;
    }
    BIND_DECOMPOSITIONS
}

/// **Circuit-level decomposition binding (opt-in alternative; OFF).**
///
/// Under the pre-fix recompose lowering (fork rev 19dcb37, or
/// `crate::recompose_binding::with_unbound_recompose`),
/// `decompose_ext_to_base_coeffs(x)` emits the coefficients as an
/// unconstrained hint and re-links them to `x` only via a RecomposeAir row
/// whose WitnessChecks message is `[x_idx, v0..v3]`. The coefficient witnesses
/// never appear on the bus there, and each gets its bus creator from its first
/// ALU use. So NOTHING ties the decomposed fields the constraints use to the
/// packed value that is hashed/permuted:
/// `tests::decomposition_forgery_accepted_without_coeff_binding` commits to a
/// final state claiming count 1000 for a key seen once, and the proof
/// self-verifies.
///
/// The fork's default lowering now closes this at no row cost: the
/// `recompose/coeff` row publishes each coefficient as `[idx, v_i, 0, 0, 0]`,
/// with first-occurrence creator arbitration
/// (`tests::decomposition_forgery_rejected_by_recompose_coeff_table`).
/// This flag is the per-circuit alternative, kept for comparison: for every
/// decomposed table it adds an explicit ALU recomposition
/// `sum_i c_i X^i - x = 0` and forces every coefficient into the base field
/// (range check / boolean / constant / ALU image of such), which makes the
/// decomposition unique on its own (+18% trace rows at cap=1024, m=16).
pub const BIND_DECOMPOSITIONS: bool = false;

/// Constrain `x == sum_i c_i X^i` with ALU rows. Sound only if every `c_i`
/// is separately forced into the base field.
fn bind_decomposition(
    b: &mut CircuitBuilder<Challenge>,
    x: ExprId,
    coeffs: &[ExprId],
    zero: ExprId,
) {
    let r = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(coeffs)
        .expect("recompose for decomposition binding");
    let d = b.sub(r, x);
    b.connect(d, zero);
}

// ─── Prover ──────────────────────────────────────────────────────────────

/// Prove one SpaceSaving epoch with the full §G top-`s` pipeline enforced
/// in-circuit (see the module docstring).
pub fn prove_ss_full(
    params: SsFullParams,
    initial_state: SsFullState,
    batch: Vec<SsFullUpdate>,
) -> SsFullLeafProof {
    prove_ss_full_inner(params, initial_state, batch, false)
}

/// Like [`prove_ss_full`] but also surfaces the `(initial, final)` boundary via
/// the Expose NPO, for the in-circuit boundary-bound forest. Baselines stable:
/// the unexposed entry point is unchanged.
pub fn prove_ss_full_exposed(
    params: SsFullParams,
    initial_state: SsFullState,
    batch: Vec<SsFullUpdate>,
) -> SsFullLeafProof {
    prove_ss_full_inner(params, initial_state, batch, true)
}

/// A built, reusable SpaceSaving leaf: circuit graph + prover data +
/// registered prover. Build once per `(params, expose_boundary)`; each
/// [`Self::prove_epoch`] swaps the two Permute ops’ trace-generation hints via
/// `Circuit::update_permute_witnesses`, hoisting graph build and
/// AIR/`ProverData` prep out of the epoch loop.
pub struct SsFullLeafCircuit {
    params: SsFullParams,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    /// Padded height of each table (AIR order), as `trace_rows` sums.
    table_rows: Vec<usize>,
    /// Whether the count-sort permute's rows carry [`GROUPED_OP_TAG`] in the
    /// `key_hi` coordinate (the shared-PermuteBus fix). Always `true` outside
    /// tests; the soundness PoC builds the pre-fix circuit to show the attack.
    op_tag: bool,
    /// The composition statement this leaf exposes.
    expose: Expose,
    /// Whether the three commitments absorb a salt (revision B2).
    mode: CommitMode,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
}

/// Build the reusable SpaceSaving leaf circuit for a shape.
pub fn build_ss_full_leaf(params: SsFullParams, expose_boundary: bool) -> SsFullLeafCircuit {
    build_ss_full_leaf_expose(params, Expose::from_bool(expose_boundary))
}

/// Build the reusable SpaceSaving leaf circuit with an explicit composition
/// statement. `Expose::None` / `Expose::Boundary` are exactly
/// [`build_ss_full_leaf`] with `expose_boundary = false / true`
/// (byte-for-byte); `Expose::Interval` additionally takes the batch index `t`
/// as the last public input and exposes
/// `(init, final, (t, t, 0, 0), Poseidon2(TAG_LEAF, t, Com(B_t)))` with the
/// in-circuit batch digest (see [`crate::recursion::recursive::statement`]).
/// Plain commitments ([`build_ss_full_leaf_commit`] with
/// [`CommitMode::Plain`]); prove with [`SsFullLeafCircuit::prove_epoch_at`].
pub fn build_ss_full_leaf_expose(params: SsFullParams, expose: Expose) -> SsFullLeafCircuit {
    build_ss_full_leaf_commit(params, expose, CommitMode::Plain)
}

/// [`build_ss_full_leaf_expose`] with an explicit [`CommitMode`] (revision
/// B2, [`crate::commitment::hiding`]). `Plain` is the pre-B2 circuit byte for
/// byte (same VK). `Hiding` adds 9 private inputs, the salts of
/// `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)` (init, final, batch; three
/// Challenges each), allocated as the FIRST private inputs, and hashes each
/// commitment as `[tag, salt…, rows…]`, i.e. [`commit_ss_state_with`] /
/// [`commit_ss_batch_with`]. The leaf has no `Binding` parameter: its sponge
/// is the plain `add_hash_slice`, which is [`hiding::commit_hash`] under
/// `Binding::Semantic`. The salts are witnesses, so the VK does not depend on
/// them; prove with [`SsFullLeafCircuit::prove_epoch_commit`].
pub fn build_ss_full_leaf_commit(params: SsFullParams, expose: Expose, mode: CommitMode) -> SsFullLeafCircuit {
    let expose_boundary = expose == Expose::Boundary;
    params.validate();
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    let op_tag = use_op_tag();

    // ─── Build circuit ──────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    crate::recompose_binding::configure(&mut b);
    let bind_decomp = bind_decompositions();
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    if expose.exposes() {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    if expose_boundary {
        b.add_expose(&[init_pis[0], init_pis[1], final_pis[0], final_pis[1]])
            .expect("add_expose boundary");
    }
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let two_pow_32 = b.alloc_const(Challenge::from_u64(1u64 << 32), "two_pow_32");
    let grouped_tag = b.alloc_const(Challenge::from_u32(GROUPED_OP_TAG), "grouped_op_tag");

    // Private inputs (alloc order MUST match the packing below):
    //   [salts (Hiding only)], init, final(=s_new), batch, key_sorted,
    //   grouped, g_sorted, residual, key_eq_tag, key_inv_diff,
    //   acc_active_inv, c_new_inv.
    // B2: the salts of (init, final, batch) are the FIRST 9 private inputs
    // under `Hiding` ([`Openings::private_inputs`] order); `Plain` allocates
    // nothing, so its circuit is byte-identical.
    let salts = hiding::alloc_leaf_salts(&mut b, mode);
    let init_packed: Vec<ExprId> = (0..cap)
        .map(|_| b.alloc_private_input("init_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cap)
        .map(|_| b.alloc_private_input("final_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();
    let key_sorted_packed: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("key_sorted_packed"))
        .collect();
    let grouped_packed: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("grouped_packed"))
        .collect();
    let g_sorted_packed: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("g_sorted_packed"))
        .collect();
    let residual_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("residual_packed"))
        .collect();
    let key_eq_tag: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("key_eq_tag"))
        .collect();
    let key_inv_diff: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("key_inv_diff"))
        .collect();
    // Inverse hint for the per-segment active running sum (is-nonzero gadget
    // that binds grouped.active = se·(acc_active≠0)).
    let acc_active_inv: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("acc_active_inv"))
        .collect();
    // Inverse hint for the post-subtraction retained count (is-nonzero gadget
    // that derives the compacted final active flag = [count−τ ≠ 0]).
    let c_new_inv: Vec<ExprId> = (0..cap)
        .map(|_| b.alloc_private_input("c_new_inv"))
        .collect();

    // ─── Stage 1: commit bindings ───────────────────────────────────────
    // Salted under `Hiding` (`[tag, salt…, rows…]`); under `Plain`,
    // `commit_hash(.., None, .., Binding::Semantic)` is exactly the former
    // `add_hash_slice(BABY_BEAR_D4_W16, rows, true)`.
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let fam = CommitFamily::SpaceSaving;
    let h_init = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::State,
        fam,
        salts.as_ref().map(|s| &s.init),
        &init_packed,
        zero,
        Binding::Semantic,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::State,
        fam,
        salts.as_ref().map(|s| &s.final_),
        &final_packed,
        zero,
        Binding::Semantic,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(h_final[i], final_pis[i]);
    }
    let h_batch = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::Batch,
        fam,
        salts.as_ref().map(|s| &s.batch),
        &batch_packed,
        zero,
        Binding::Semantic,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(h_batch[i], batch_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (7th public input) and
    // H = Poseidon2(TAG_LEAF, t, h_batch), exposed with the boundary.
    if expose.is_interval() {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &Poseidon2Config::BABY_BEAR_D4_W16,
            &init_pis,
            &final_pis,
            &h_batch,
            zero,
            Binding::Semantic,
            IndexPin::Range,
        );
    }

    // ─── Stage 2: decompose all packed sequences ────────────────────────
    let init_fields: Vec<Vec<ExprId>> = init_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d init"))
        .collect();
    let final_fields: Vec<Vec<ExprId>> = final_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d final"))
        .collect();
    let batch_fields: Vec<Vec<ExprId>> = batch_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d batch"))
        .collect();
    let key_sorted_fields: Vec<Vec<ExprId>> = key_sorted_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d ks"))
        .collect();
    let grouped_fields: Vec<Vec<ExprId>> = grouped_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d g"))
        .collect();
    let g_sorted_fields: Vec<Vec<ExprId>> = g_sorted_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d gs"))
        .collect();
    let residual_fields: Vec<Vec<ExprId>> = residual_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d res"))
        .collect();

    // ─── Stage 2b (opt-in): bind every decomposition to its packed value ─
    // See BIND_DECOMPOSITIONS: without this the decomposed fields are not
    // constrained to the packed (hashed / permuted) values at all.
    if bind_decomp {
        assert!(op_tag, "decomposition binding assumes the op-tagged layout");
        for (packed, fields) in [
            (&init_packed, &init_fields),
            (&final_packed, &final_fields),
            (&batch_packed, &batch_fields),
            (&key_sorted_packed, &key_sorted_fields),
            (&grouped_packed, &grouped_fields),
            (&g_sorted_packed, &g_sorted_fields),
            (&residual_packed, &residual_fields),
        ] {
            for (&p, f) in packed.iter().zip(fields.iter()) {
                bind_decomposition(&mut b, p, f, zero);
            }
        }
        // Base-force the coefficients no other constraint pins to the base
        // field: committed init/batch keys (single-limb, < 2^KEY_DIFF_BITS) and
        // counts/values (< 2^(COUNT_DIFF_BITS−1)), and the g_sorted key (the
        // final key is its ALU image). Every other coefficient is already
        // range-checked, boolean, a constant, or an ALU image of such.
        for r in 0..cap {
            b.connect(init_fields[r][1], zero);
            let _ = b
                .add_range_bits::<Val>(init_fields[r][0], KEY_DIFF_BITS)
                .expect("init key base-range");
            let _ = b
                .add_range_bits::<Val>(init_fields[r][2], COUNT_DIFF_BITS - 1)
                .expect("init count base-range");
        }
        for j in 0..m {
            b.connect(batch_fields[j][1], zero);
            let _ = b
                .add_range_bits::<Val>(batch_fields[j][0], KEY_DIFF_BITS)
                .expect("batch key base-range");
            let _ = b
                .add_range_bits::<Val>(batch_fields[j][2], COUNT_DIFF_BITS - 1)
                .expect("batch value base-range");
        }
        for r in 0..total {
            let _ = b
                .add_range_bits::<Val>(g_sorted_fields[r][0], KEY_DIFF_BITS)
                .expect("g_sorted key base-range");
        }
    }

    // ─── Stage 3: boolean active-flag checks ────────────────────────────
    let bool_check = |b: &mut CircuitBuilder<Challenge>, a: ExprId| {
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    };
    for r in 0..cap {
        bool_check(&mut b, init_fields[r][3]);
        bool_check(&mut b, final_fields[r][3]);
        // Well-formedness of the committed S_old: an INACTIVE init row must
        // carry count 0 (`active=0 ⇒ count=0`), severing the malformed-preimage
        // source that could otherwise seed a count-carrying dummy. Mirrors the
        // GK init check and the active-gated group-by below (redundant barrier).
        let c_gated = b.mul(init_fields[r][2], init_fields[r][3]);
        b.connect(init_fields[r][2], c_gated);
    }
    for j in 0..m {
        bool_check(&mut b, batch_fields[j][3]);
    }
    for r in 0..total {
        bool_check(&mut b, key_sorted_fields[r][3]);
        bool_check(&mut b, g_sorted_fields[r][3]);
    }
    for j in 0..m {
        bool_check(&mut b, residual_fields[j][3]);
    }

    // key_field per row = key_lo + key_hi·2^32, for several tables.
    let key_field_of = |b: &mut CircuitBuilder<Challenge>, f: &[ExprId]| -> ExprId {
        let hi = b.mul(f[1], two_pow_32);
        b.add(f[0], hi)
    };

    // ─── Stage 4: Union → key-sort via PermuteAir ───────────────────────
    // combined = init ‖ batch; the multiset check ties key_sorted to it.
    let mut combined: Vec<ExprId> = Vec::with_capacity(total);
    combined.extend(init_packed.iter().copied());
    combined.extend(batch_packed.iter().copied());
    // Placeholder identity permutations — `prove_epoch` swaps in the real
    // per-batch sigmas via `update_permute_witnesses` before each run.
    let ks_permuted = b
        .add_permute(&combined, (0..combined.len()).collect::<Vec<_>>())
        .expect("permute key-sort");
    for i in 0..total {
        b.connect(ks_permuted[i], key_sorted_packed[i]);
    }

    // ─── Stage 5: group-by-key (adjacency tags + running sum) ───────────
    // key_eq_tag[r] ∈ {0,1}, tag[0]=0. PoneglyphDB §4.3 constraints.
    let ks_keyfield: Vec<ExprId> = (0..total)
        .map(|r| key_field_of(&mut b, &key_sorted_fields[r]))
        .collect();

    // ── Union key-sortedness (closes the fragmentation soundness hole) ──
    // Bind every union key to a single limb in [0, 2^KEY_DIFF_BITS) and force
    // `key_sorted` non-decreasing. Then equal keys are necessarily contiguous,
    // so the adjacency-only group-by below cannot be gamed by scattering a
    // key's rows to fragment its aggregate (see tests::fragmentation_rejected).
    for r in 0..total {
        b.connect(key_sorted_fields[r][1], zero); // single-limb: key_hi = 0
        let _ = b
            .add_range_bits::<Val>(key_sorted_fields[r][0], KEY_DIFF_BITS)
            .expect("union key range-check");
        // Bound every union count at the SOURCE to `< 2^(COUNT_DIFF_BITS−1)` so
        // no single input can approach `p`; combined with the g_sorted count
        // range-check on the summed output, this forecloses the field-wrap where
        // a committed S_old count `≈ p` (plus one batch occurrence of the same
        // key) wraps a segment sum down to a small residue and is silently kept.
        let _ = b
            .add_range_bits::<Val>(key_sorted_fields[r][2], COUNT_DIFF_BITS - 1)
            .expect("union count range-check");
    }
    for r in 1..total {
        let kdiff = b.sub(ks_keyfield[r], ks_keyfield[r - 1]);
        let _ = b
            .add_range_bits::<Val>(kdiff, KEY_DIFF_BITS)
            .expect("union key-sortedness");
    }

    bool_check(&mut b, key_eq_tag[0]);
    b.connect(key_eq_tag[0], zero);
    // key_inv_diff[0] is unused by the r>=1 is-zero gadget; give it a real
    // ALU-operand use so the private input gets a WitnessChecks-bus creator.
    // Without this the debug builder asserts "Private input … never used as an
    // ALU operand" and every in-circuit test panics at build time under
    // `cargo test` (release masks it). Use `sub` (not `mul`-by-zero, which
    // const-folds away the operand).
    {
        let z = b.sub(key_inv_diff[0], zero);
        b.connect(z, zero);
    }
    for r in 1..total {
        bool_check(&mut b, key_eq_tag[r]);
        let diff = b.sub(ks_keyfield[r], ks_keyfield[r - 1]);
        // tag · diff = 0
        let lhs1 = b.mul(key_eq_tag[r], diff);
        b.connect(lhs1, zero);
        // (1 − tag)(1 − diff·inv) = 0
        let one_minus_tag = b.sub(one, key_eq_tag[r]);
        let diff_inv = b.mul(diff, key_inv_diff[r]);
        let one_minus = b.sub(one, diff_inv);
        let lhs2 = b.mul(one_minus_tag, one_minus);
        b.connect(lhs2, zero);
    }

    // running sums of count (field [2]) and active (field [3]).
    //
    // SOUNDNESS (count is ACTIVE-GATED): each row contributes `count·active`,
    // NOT the raw count, so an INACTIVE row adds nothing to a segment sum. This
    // makes every dummy grouped row a canonical `(0,·,0,0)` and forecloses a
    // malformed committed S_old dummy `(key, count=C, active=0)` seeding a
    // count-carrying dummy grouped row (the SS count-sort + count-monotone
    // already pin such a row to the evicted region, but the gate removes the
    // reliance on that incidental defense and keeps SS in lockstep with GK). For
    // honest input dummies carry count=0, so the gate is a no-op (completeness
    // unchanged) and it matches native `build_ss`, whose dummy rows also carry 0.
    let mut acc_count: Vec<ExprId> = Vec::with_capacity(total);
    let mut acc_active: Vec<ExprId> = Vec::with_capacity(total);
    let c0 = b.mul(key_sorted_fields[0][2], key_sorted_fields[0][3]);
    acc_count.push(c0);
    acc_active.push(key_sorted_fields[0][3]);
    for r in 1..total {
        let c_act = b.mul(key_sorted_fields[r][2], key_sorted_fields[r][3]);
        let carried_c = b.mul(key_eq_tag[r], acc_count[r - 1]);
        acc_count.push(b.add(c_act, carried_c));
        let carried_a = b.mul(key_eq_tag[r], acc_active[r - 1]);
        acc_active.push(b.add(key_sorted_fields[r][3], carried_a));
    }

    // seg_end[r] = 1 − key_eq_tag[r+1] (and 1 for the last row). Native
    // supplies the grouped table; we bind it to the segment-end rows and
    // force non-end rows to be dummies.
    //
    // For each r: let se = seg_end indicator.
    //   grouped[r].count  = se · acc_count[r]
    //   grouped[r].active = se · (acc_active[r] != 0 ? 1 : 0)
    //   grouped[r].key    = se · active · key_sorted[r].key
    // We use the native `seg_end`/`acc_active>0` to provide grouped, and
    // verify the count/active relations in-circuit. To keep the bus clean
    // we bind grouped's fields to ALU expressions of the (already-created)
    // running sums.
    for r in 0..total {
        let se = if r + 1 == total {
            one
        } else {
            // se = 1 − key_eq_tag[r+1]
            b.sub(one, key_eq_tag[r + 1])
        };
        // grouped[r].count = se · acc_count[r]  (acc_count lhs → bus creator)
        let want_count = b.mul(acc_count[r], se);
        b.connect(grouped_fields[r][2], want_count);
        // grouped[r].active is fully DERIVED (not a free prover bit): it must
        // equal se·(acc_active[r] ≠ 0). This closes the count-0 active-bit
        // latitude — a prover can no longer flag a count-0 segment active or
        // inactive at will (which, when the summary is under-full, would let it
        // pick which zero-weight key fills a leftover retained slot). is-nonzero
        // via the inverse hint:  nz = acc_active·acc_active_inv, with
        // acc_active·(1−nz)=0 forcing nz = [acc_active ≠ 0] (boolean).
        let nz = b.mul(acc_active[r], acc_active_inv[r]);
        let one_minus_nz = b.sub(one, nz);
        let must_zero = b.mul(acc_active[r], one_minus_nz);
        b.connect(must_zero, zero);
        let want_active = b.mul(se, nz);
        b.connect(grouped_fields[r][3], want_active);
        bool_check(&mut b, grouped_fields[r][3]);
        // key gating: grouped.key_lo/hi = active · key_sorted.key_lo/hi
        let want_key_lo = b.mul(key_sorted_fields[r][0], grouped_fields[r][3]);
        b.connect(grouped_fields[r][0], want_key_lo);
        if op_tag {
            // Op tag (shared-PermuteBus fix): every row of the count-sort
            // permute's INPUT carries GROUPED_OP_TAG in the key_hi slot. The
            // union keys are single-limb (key_hi = 0 is enforced on key_sorted
            // above), so key_hi is free to name the permute domain.
            b.connect(grouped_fields[r][1], grouped_tag);
        } else {
            let want_key_hi = b.mul(key_sorted_fields[r][1], grouped_fields[r][3]);
            b.connect(grouped_fields[r][1], want_key_hi);
        }
    }

    // ─── Stage 6: count-sort G → g_sorted via PermuteAir ────────────────
    let cs_permuted = b
        .add_permute(
            &grouped_packed,
            (0..grouped_packed.len()).collect::<Vec<_>>(),
        )
        .expect("permute count-sort");
    for i in 0..total {
        b.connect(cs_permuted[i], g_sorted_packed[i]);
    }
    // ── Op tag on the count-sort OUTPUT (shared-PermuteBus fix) ──
    // The fork concatenates every add_permute into ONE PermuteAir whose
    // PermuteBus message is the 4 value coordinates only (no op id), so it
    // proves only  M(combined) ⊎ M(grouped) = M(key_sorted) ⊎ M(g_sorted).
    // With key_hi = 0 on every key_sorted row (Stage 5) and key_hi =
    // GROUPED_OP_TAG on every grouped AND g_sorted row, counting the tagged
    // elements on each side forces  M(grouped) = M(g_sorted)  and then
    // M(combined) = M(key_sorted): the two permutes can no longer trade rows
    // (tests::shared_permute_bus_forgery_rejected).
    if op_tag {
        for r in 0..total {
            b.connect(g_sorted_fields[r][1], grouped_tag);
        }
    }

    // ─── Stage 7: sortedness on g_sorted ────────────────────────────────
    // Range-check every count to < 2^(COUNT_DIFF_BITS−1) so the count-diff
    // sortedness below is sound: an in-domain decrease wraps to ≈ p (≫ 2^BITS)
    // and fails, while a crafted out-of-domain count (≈ p) — which could
    // otherwise wrap a genuine descent into a small in-range diff and admit a
    // non-canonical retention cut (evicting a real heavy hitter) — is rejected
    // here. This is the count analog of the union key range-check in Stage 5.
    for r in 0..total {
        let _ = b
            .add_range_bits::<Val>(g_sorted_fields[r][2], COUNT_DIFF_BITS - 1)
            .expect("g_sorted count range-check");
    }
    // active monotone increasing (dummies first):
    for r in 0..total - 1 {
        let diff = b.sub(g_sorted_fields[r + 1][3], g_sorted_fields[r][3]);
        let one_minus = b.sub(one, diff);
        let prod = b.mul(diff, one_minus);
        b.connect(prod, zero);
    }
    // count monotone increasing across all adjacent pairs (count[r+1] ≥
    // count[r]); dummies have count 0 so the dummy→active boundary is also
    // non-negative — no gating needed. We capture the diff bits to derive
    // `count[r]==count[r+1]` for the key tie-break below.
    for r in 0..total - 1 {
        let diff = b.sub(g_sorted_fields[r + 1][2], g_sorted_fields[r][2]);
        let bits = b
            .decompose_to_bits::<Val>(diff, COUNT_DIFF_BITS)
            .expect("decompose count diff");

        // ── Key tie-break (canonical top-s retention) ──────────────────────
        // Within a count-EQUAL run the retained set must not depend on the
        // prover's ordering. Force keys non-decreasing whenever counts are
        // equal, matching the native (active, count, key)-ascending sort, so
        // tied keys have one canonical order and the top-s split is
        // deterministic (closes the count-tie straddle: a prover can no longer
        // pick which equal-count key is evicted across the cut).
        //   count_eq = ∏(1 − bit)  (== 1 iff the count diff is 0).
        let mut count_eq = one;
        for &bit in &bits {
            let nb = b.sub(one, bit);
            count_eq = b.mul(count_eq, nb);
        }
        // g_sorted keys are single-limb in [0, 2^KEY_DIFF_BITS): grouped keys
        // are `union_key × active` and the union keys are range-checked in
        // Stage 5; the count-sort permutation preserves the packed values. So
        // a real key decrease wraps to ≈ p and the gated 29-bit check rejects
        // it; a count-unequal pair gates to 0 and is unconstrained.
        let gk_r = key_field_of(&mut b, &g_sorted_fields[r]);
        let gk_r1 = key_field_of(&mut b, &g_sorted_fields[r + 1]);
        let kdiff = b.sub(gk_r1, gk_r);
        let gated = b.mul(count_eq, kdiff);
        let _ = b
            .add_range_bits::<Val>(gated, KEY_DIFF_BITS)
            .expect("key tie-break within count-equal run");
    }

    // ─── Stage 8: compaction + Misra-Gries (s+1)-th-value subtraction ────
    // residual ↔ g_sorted[..m] (ORIGINAL counts, needed for mass accounting).
    for i in 0..m {
        for k in 0..4 {
            b.connect(residual_fields[i][k], g_sorted_fields[i][k]);
        }
    }
    // S_new ↔ mergeable Misra-Gries / Frequent compression of g_sorted[m..]:
    // subtract τ = the (s+1)-th largest count = g_sorted[m-1].count from every
    // retained counter and clamp non-positive to a dummy. τ is the already-pinned
    // rank-(m-1) cell (range-checked in Stage 7, its rank fixed by the count-sort),
    // so it is not a free witness. `final_fields` are decompositions of the
    // committed final state, so binding count/active/key to the subtracted values
    // forces the prover's committed S_new to be the compressed table.
    let tau = g_sorted_fields[m - 1][2];
    for i in 0..cap {
        let src = m + i;
        // c_new = g_sorted[src].count − τ ≥ 0 (count-ascending ⇒ src.count ≥ τ).
        let c_new = b.sub(g_sorted_fields[src][2], tau);
        // no-underflow: an out-of-domain descent wraps to ≈ p (≫ 2^BITS) and fails.
        let _ = b
            .add_range_bits::<Val>(c_new, COUNT_DIFF_BITS - 1)
            .expect("c_new range-check");
        // active = [c_new ≠ 0] via inverse hint; since c_new ≥ 0 this is [c_new > 0].
        // nz = c_new·c_new_inv, with c_new·(1−nz)=0 forcing nz = [c_new ≠ 0] (boolean).
        let nz = b.mul(c_new, c_new_inv[i]);
        let one_minus_nz = b.sub(one, nz);
        let must_zero = b.mul(c_new, one_minus_nz);
        b.connect(must_zero, zero);
        bool_check(&mut b, nz);
        // Bind the committed final row: count = c_new, active = nz, key gated by nz
        // (mirror Stage 5's key-gating) so a clamped slot cannot smuggle a live key.
        b.connect(final_fields[i][2], c_new);
        b.connect(final_fields[i][3], nz);
        let want_key_lo = b.mul(g_sorted_fields[src][0], nz);
        b.connect(final_fields[i][0], want_key_lo);
        if op_tag {
            // g_sorted.key_hi is the op tag, not key material: the committed
            // final key_hi is 0 (single-limb keys), as before.
            b.connect(final_fields[i][1], zero);
        } else {
            let want_key_hi = b.mul(g_sorted_fields[src][1], nz);
            b.connect(final_fields[i][1], want_key_hi);
        }
    }

    // ─── Stage 9: mass conservation ─────────────────────────────────────
    // Σ(init.count·active) + Σ(batch.value·active)
    //   = Σ(final.count·active) + Σ(residual.count·active) + capacity·τ.
    // The `capacity·τ` term is the mass the Misra-Gries subtraction deliberately
    // discards (each of the `capacity` retained slots loses exactly τ; a clamped
    // slot loses its whole count τ, a survivor loses τ of its count), so the
    // identity stays an EXACT equality rather than a bound.
    let mut init_mass_e = b.mul(init_fields[0][2], init_fields[0][3]);
    for r in 1..cap {
        let t = b.mul(init_fields[r][2], init_fields[r][3]);
        init_mass_e = b.add(init_mass_e, t);
    }
    let mut batch_mass_e = b.mul(batch_fields[0][2], batch_fields[0][3]);
    for j in 1..m {
        let t = b.mul(batch_fields[j][2], batch_fields[j][3]);
        batch_mass_e = b.add(batch_mass_e, t);
    }
    let in_mass = b.add(init_mass_e, batch_mass_e);

    let mut final_mass_e = b.mul(final_fields[0][2], final_fields[0][3]);
    for r in 1..cap {
        let t = b.mul(final_fields[r][2], final_fields[r][3]);
        final_mass_e = b.add(final_mass_e, t);
    }
    let mut res_mass_e = b.mul(residual_fields[0][2], residual_fields[0][3]);
    for j in 1..m {
        let t = b.mul(residual_fields[j][2], residual_fields[j][3]);
        res_mass_e = b.add(res_mass_e, t);
    }
    let out_mass = b.add(final_mass_e, res_mass_e);
    // Add back the deliberately-discarded Misra-Gries deficit capacity·τ. `cap·τ`
    // and the mass sum stay < p (cap · 2^(COUNT_DIFF_BITS−1) < p).
    let cap_const = b.alloc_const(Challenge::from_u64(cap as u64), "capacity");
    let cap_tau = b.mul(tau, cap_const);
    let out_mass2 = b.add(out_mass, cap_tau);
    b.connect(in_mass, out_mass2);

    let circuit = b.build().expect("build ss_full circuit");

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
        .expect("get_airs_and_degrees_with_prep (ss_full)");
    // E-0 table probe (read-only; a no-op unless armed).
    crate::experiments::table_probe::record_leaf(
        "ss_final_full",
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

    SsFullLeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        table_rows,
        op_tag,
        expose,
        mode,
        batch_index: 1,
    }
}

/// The public, private and committed values of one epoch (see
/// [`SsFullLeafCircuit::epoch_inputs`]).
struct SsEpochInputs {
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    initial_commit: SsFullStateCommit,
    final_commit: SsFullStateCommit,
    batch_commit: SsFullBatchCommit,
}

impl SsFullLeafCircuit {
    /// Pack a table in the key-sort permute's encoding (`key_sorted`).
    fn pack_union_table(&self, rows: &[SsFullRow]) -> Vec<Challenge> {
        pack_rows_to_challenge(rows)
    }

    /// Pack a table in the count-sort permute's encoding (`grouped`,
    /// `g_sorted`, and `residual`, which is wired to `g_sorted[..m]`): the
    /// `key_hi` coordinate carries [`GROUPED_OP_TAG`] when the op tag is on.
    fn pack_grouped_table(&self, rows: &[SsFullRow]) -> Vec<Challenge> {
        if !self.op_tag {
            return pack_rows_to_challenge(rows);
        }
        use p3_field::BasedVectorSpace;
        rows.iter()
            .map(|r| {
                let (lo, hi) = key_lo_hi(r.key);
                assert_eq!(hi, 0, "SS keys are single-limb (key_hi = 0)");
                let coeffs = [
                    Val::from_u32(lo),
                    Val::from_u32(GROUPED_OP_TAG),
                    Val::from_u32(r.count),
                    Val::from_u32(r.active),
                ];
                Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
            })
            .collect()
    }

    /// Prove one epoch on the prebuilt circuit (batch index 1 under the
    /// Interval statement; see [`Self::prove_epoch_at`], so `Plain` circuits
    /// only).
    pub fn prove_epoch(
        &mut self,
        initial_state: SsFullState,
        batch: Vec<SsFullUpdate>,
    ) -> SsFullLeafProof {
        self.prove_epoch_at(1, initial_state, batch)
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

    /// The VK (preprocessed commitment, `expose_forest::vk_pin_values` order)
    /// of every proof this prebuilt leaf produces, read from its prover data:
    /// derived from the public parameters alone, without proving.
    pub fn vk_pin_values(&self) -> Vec<Challenge> {
        crate::recursion::recursive::expose_forest::common_vk_pin_values(
            self.circuit_prover_data.common_data(),
        )
    }

    /// The commitment mode the circuit was built with.
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }

    /// Prove the epoch of batch `t` (1-based); `t` is part of the Interval
    /// statement (ignored by the other layouts). `Plain` circuits only: on a
    /// `Hiding` circuit this would open every commitment with the public zero
    /// salt, so it panics; use [`Self::prove_epoch_commit`] (or, for the no-op
    /// leaf, [`Self::prove_epoch_public_zero`]).
    pub fn prove_epoch_at(
        &mut self,
        t: u64,
        initial_state: SsFullState,
        batch: Vec<SsFullUpdate>,
    ) -> SsFullLeafProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             Openings::for_leaf(..)"
        );
        self.prove_epoch_opened(t, initial_state, batch, &Openings::plain())
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`Openings::for_leaf(seed, CommitFamily::SpaceSaving, t)` for an honest
    /// prover; ignored by a `Plain` circuit). The proof's `initial`, `final_`
    /// and `batch_commit` are then `Com(S_{t-1}; ρ^S_{t-1})`,
    /// `Com(S_t; ρ^S_t)` and `Com(B_t; ρ^B_t)`. A `Hiding` circuit panics when
    /// `openings.final_` or `openings.batch` is the public zero salt (never an
    /// honest PRF output): a forgotten opening would otherwise give a
    /// consistent, deterministic chain that nothing downstream detects. The
    /// init salt may be zero (leaf 1 opens the public `Com(S_0; 0)`).
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial_state: SsFullState,
        batch: Vec<SsFullUpdate>,
        openings: &Openings,
    ) -> SsFullLeafProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (Openings::for_leaf), not the public zero salt"
            );
        }
        self.prove_epoch_opened(t, initial_state, batch, openings)
    }

    /// The no-op VK-derivation leaf's epoch: all three commitments opened
    /// with [`Openings::public_zero`], so a batch that changes nothing
    /// exposes `init == final` in either mode. The only path that proves a
    /// `Hiding` leaf with zero final/batch salts; it asserts that every
    /// update is the circuit-native no-op [`SsFullUpdate::dummy`] and that
    /// the state does not move, so it cannot publish a real batch (or a moved
    /// state) under deterministic commitments.
    pub fn prove_epoch_public_zero(
        &mut self,
        t: u64,
        initial_state: SsFullState,
        batch: Vec<SsFullUpdate>,
    ) -> SsFullLeafProof {
        assert!(
            batch.iter().all(|u| *u == SsFullUpdate::dummy()),
            "prove_epoch_public_zero is for the no-op leaf: every update must be SsFullUpdate::dummy()"
        );
        assert!(
            apply_batch_ss_full(&initial_state, &batch).0 == initial_state,
            "prove_epoch_public_zero is for the no-op leaf: the state must not move"
        );
        self.prove_epoch_opened(t, initial_state, batch, &Openings::public_zero())
    }

    /// Shared body of the three `prove_epoch_*` entry points (no opening
    /// checks).
    fn prove_epoch_opened(
        &mut self,
        t: u64,
        initial_state: SsFullState,
        batch: Vec<SsFullUpdate>,
        openings: &Openings,
    ) -> SsFullLeafProof {
        let w = self.prepare_epoch(t, &initial_state, &batch);
        self.prove_witness_opened(&w, openings)
    }

    /// Native side of the epoch of batch `t`: the honest witness (checked for
    /// mass conservation), with its two permutation hints swapped into the
    /// prebuilt graph.
    fn prepare_epoch(&mut self, t: u64, initial_state: &SsFullState, batch: &[SsFullUpdate]) -> SsWitness {
        self.batch_index = t;
        let params = self.params;
        assert_eq!(initial_state.params, params);
        assert_eq!(batch.len(), params.batch);

        let cap = params.capacity;

        // ─── Native side ────────────────────────────────────────────────────
        let w = honest_ss_witness(initial_state, batch);
        let (final_state, residual_rows, build) = (&w.final_state, &w.residual, &w.build);

        // Sanity: mass conservation.
        let init_mass = initial_state.total_mass();
        let batch_mass: u64 = batch
            .iter()
            .filter(|u| u.active == 1)
            .map(|u| u.value as u64)
            .sum();
        let final_mass = final_state.total_mass();
        let residual_mass: u64 = residual_rows
            .iter()
            .filter(|r| r.active == 1)
            .map(|r| r.count as u64)
            .sum();
        // Mass conservation after the Misra-Gries subtraction: the compression
        // discards exactly capacity·τ (see Stage 9), so add it back.
        assert_eq!(
            final_mass + residual_mass + (cap as u64) * (build.tau as u64),
            init_mass + batch_mass
        );

        // Swap the real per-batch permutation hints into the prebuilt graph
        // (op order: key-sort permute, then count-sort permute).
        self.circuit
            .update_permute_witnesses(&[build.sigma_key.clone(), build.sigma_count.clone()])
            .expect("update permute witnesses (ss_full)");

        w
    }

    /// [`Self::prove_witness_opened`] with the Plain openings: the soundness
    /// tests' entry point for a hand-crafted (possibly malicious) witness on
    /// a `Plain` leaf.
    #[cfg(test)]
    fn prove_witness(&mut self, w: &SsWitness) -> SsFullLeafProof {
        self.prove_witness_opened(w, &Openings::plain())
    }

    /// Pack a witness into public/private inputs, with the three commitments
    /// opened with `openings` (ignored by a `Plain` circuit; under `Hiding`
    /// the 9 salts are the first private inputs).
    fn epoch_inputs(&self, w: &SsWitness, openings: &Openings) -> SsEpochInputs {
        let params = self.params;
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        let (initial_state, batch) = (&w.initial, &w.batch);
        let (final_state, residual_rows, build) = (&w.final_state, &w.residual, &w.build);
        let mode = self.mode;
        let initial_commit = commit_ss_state_with(initial_state, mode, &openings.init);
        let final_commit = commit_ss_state_with(final_state, mode, &openings.final_);
        let batch_commit = commit_ss_batch_with(batch, mode, &openings.batch);

        // ─── Pack public + private ──────────────────────────────────────────
        let init_commit_packed =
            pack_commit_to_challenge(&crate::commitment::CountMinCommit(initial_commit.0));
        let final_commit_packed =
            pack_commit_to_challenge(&crate::commitment::CountMinCommit(final_commit.0));
        let batch_commit_packed =
            pack_commit_to_challenge(&crate::commitment::CountMinCommit(batch_commit.0));

        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&init_commit_packed);
        public_inputs.extend_from_slice(&final_commit_packed);
        public_inputs.extend_from_slice(&batch_commit_packed);
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        // MUST match alloc order.
        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            // The salts come first (see `build_ss_full_leaf_commit`).
            private_inputs.extend(openings.private_inputs());
        }
        private_inputs.extend_from_slice(&pack_state_to_challenge(&initial_state));
        private_inputs.extend_from_slice(&pack_state_to_challenge(&final_state));
        private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
        let key_sorted_rows: &[SsFullRow] = &build.key_sorted;
        private_inputs.extend_from_slice(&self.pack_union_table(key_sorted_rows));
        private_inputs.extend_from_slice(&self.pack_grouped_table(&build.grouped));
        #[allow(unused_mut)]
        let mut g_sorted_vals = self.pack_grouped_table(&build.g_sorted);
        // [test-only] corrupt the post-retention table to confirm the
        // count-sort PermuteAir + sortedness + compaction reject it.
        #[cfg(test)]
        if TAMPER_GSORTED.with(|c| c.get()) {
            g_sorted_vals[0] += Challenge::ONE;
        }
        private_inputs.extend_from_slice(&g_sorted_vals);
        private_inputs.extend_from_slice(&self.pack_grouped_table(residual_rows));
        // key_eq_tag
        for &t in &build.key_eq_tag {
            private_inputs.push(if t == 1 {
                Challenge::ONE
            } else {
                Challenge::ZERO
            });
        }
        // key_inv_diff: inverse of (key_sorted[r] − key_sorted[r-1]) when
        // distinct, else 0. r=0 unused (push 0).
        {
            use p3_field::Field;
            private_inputs.push(Challenge::ZERO);
            for r in 1..total {
                let d = key_field(key_sorted_rows[r].key) as i128
                    - key_field(key_sorted_rows[r - 1].key) as i128;
                let inv = if d == 0 {
                    Challenge::ZERO
                } else {
                    // diff as a field element = key_field[r] − key_field[r-1]
                    let cur = Challenge::from_u64(key_field(key_sorted_rows[r].key) as u64);
                    let prev = Challenge::from_u64(key_field(key_sorted_rows[r - 1].key) as u64);
                    (cur - prev).inverse()
                };
                private_inputs.push(inv);
            }
        }
        // acc_active_inv: inverse of the per-segment active running sum (0 when the
        // sum is 0), for the is-nonzero gadget that binds grouped.active.
        {
            use p3_field::Field;
            let mut acc_a = 0u64;
            for r in 0..total {
                acc_a = if r > 0 && build.key_eq_tag[r] == 1 {
                    acc_a + key_sorted_rows[r].active as u64
                } else {
                    key_sorted_rows[r].active as u64
                };
                let inv = if acc_a == 0 {
                    Challenge::ZERO
                } else {
                    Challenge::from_u64(acc_a).inverse()
                };
                private_inputs.push(inv);
            }
        }
        // c_new_inv: inverse of the post-subtraction retained count `count − τ`
        // (0 when the counter clamps to a dummy), for the is-nonzero gadget that
        // derives the compacted final active flag. Same order as the alloc.
        {
            use p3_field::Field;
            for i in 0..cap {
                let c = build.g_sorted[m + i].count.saturating_sub(build.tau);
                let inv = if c == 0 {
                    Challenge::ZERO
                } else {
                    Challenge::from_u64(c as u64).inverse()
                };
                private_inputs.push(inv);
            }
        }
        let _ = &build.seg_end; // segment ends are recomputed in-circuit from tags

        SsEpochInputs { public_inputs, private_inputs, initial_commit, final_commit, batch_commit }
    }

    /// Run the circuit on packed inputs (trace generation only).
    fn run_inputs(&self, ep: &SsEpochInputs) -> p3_circuit::tables::Traces<Challenge> {
        let mut runner = self.circuit.runner();
        runner
            .set_public_inputs(&ep.public_inputs)
            .expect("set_public_inputs");
        runner
            .set_private_inputs(&ep.private_inputs)
            .expect("set_private_inputs");
        runner.run().expect("run ss_full circuit")
    }

    /// The traces of the epoch of batch `t` under `openings`, without
    /// proving (row-count tests).
    #[cfg(test)]
    fn run_epoch_commit(
        &mut self,
        t: u64,
        initial_state: &SsFullState,
        batch: &[SsFullUpdate],
        openings: &Openings,
    ) -> p3_circuit::tables::Traces<Challenge> {
        let w = self.prepare_epoch(t, initial_state, batch);
        let ep = self.epoch_inputs(&w, openings);
        self.run_inputs(&ep)
    }

    /// Pack a witness (commitments opened with `openings`), run the circuit,
    /// prove and self-verify. The Permute ops' hints must already be
    /// installed.
    fn prove_witness_opened(&mut self, w: &SsWitness, openings: &Openings) -> SsFullLeafProof {
        let params = self.params;
        let ep = self.epoch_inputs(w, openings);

        // ─── Run + prove ────────────────────────────────────────────────────
        let __t_w = std::time::Instant::now();
        let traces = self.run_inputs(&ep);
        let __witness = __t_w.elapsed(); // witness_gen = trace generation only

        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (ss_full)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify ss_full leaf");
        crate::recursion::recursive::timing::record(
            crate::recursion::recursive::timing::LeafTiming {
                witness: __witness,
                prove: __prove,
                verify: __t_v.elapsed(),
                trace_rows: self.trace_rows,
            },
        );

        SsFullLeafProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial: ep.initial_commit,
            final_: ep.final_commit,
            batch_commit: ep.batch_commit,
            params,
        }
    }
}

fn prove_ss_full_inner(
    params: SsFullParams,
    initial_state: SsFullState,
    batch: Vec<SsFullUpdate>,
    expose_boundary: bool,
) -> SsFullLeafProof {
    build_ss_full_leaf(params, expose_boundary).prove_epoch(initial_state, batch)
}

/// Prove batch `t` (1-based) as an **Interval-statement** SpaceSaving leaf.
pub fn prove_ss_full_interval(
    params: SsFullParams,
    t: u64,
    initial_state: SsFullState,
    batch: Vec<SsFullUpdate>,
) -> SsFullLeafProof {
    build_ss_full_leaf_expose(params, Expose::Interval).prove_epoch_at(t, initial_state, batch)
}

/// [`prove_ss_full_interval`] with an explicit [`CommitMode`] and the
/// openings of leaf `t`. Under `Hiding`, zero final/batch salts panic
/// ([`SsFullLeafCircuit::prove_epoch_commit`]).
pub fn prove_ss_full_interval_commit(
    params: SsFullParams,
    t: u64,
    initial_state: SsFullState,
    batch: Vec<SsFullUpdate>,
    mode: CommitMode,
    openings: &Openings,
) -> SsFullLeafProof {
    build_ss_full_leaf_commit(params, Expose::Interval, mode).prove_epoch_commit(t, initial_state, batch, openings)
}

pub fn generate_proof(params: SsFullParams, updates: Vec<SsFullUpdate>) -> SsFullProof {
    params.validate();
    assert_eq!(updates.len(), params.batch);
    let initial_state = SsFullState::empty(params);
    let (final_state, _residual) = apply_batch_ss_full(&initial_state, &updates);
    let proof = prove_ss_full(params, initial_state, updates);
    SsFullProof { proof, final_state }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys masked to 20 bits (single limb, non-zero) so `key_field` has no
    /// field-wrap collision and `0` stays the dummy sentinel.
    fn gen_padded_batch(params: SsFullParams, active_count: usize) -> Vec<SsFullUpdate> {
        assert!(active_count <= params.batch);
        let salt = (params.capacity * params.batch) as u64;
        (0..params.batch)
            .map(|i| {
                if i < active_count {
                    let key = (((i as u64).wrapping_mul(0x9E37_79B9) ^ salt) & 0x000F_FFFF) + 1;
                    SsFullUpdate::real(key, 1)
                } else {
                    SsFullUpdate::dummy()
                }
            })
            .collect()
    }

    fn resolve_threads() -> (Option<usize>, String) {
        let n: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse().ok());
        let label = match n {
            Some(k) => format!("V3_SWEEP_THREADS={k}"),
            None => format!(
                "Rayon default pool ({} threads)",
                rayon::current_num_threads()
            ),
        };
        (n, label)
    }

    fn with_pool<F: FnOnce() -> T + Send, T: Send>(n: Option<usize>, f: F) -> T {
        match n {
            None => f(),
            Some(k) => rayon::ThreadPoolBuilder::new()
                .num_threads(k)
                .thread_name(|i| format!("ss-full-bench-{i}"))
                .build()
                .expect("pool")
                .install(f),
        }
    }

    #[test]
    fn ss_full_round_trip() {
        let params = SsFullParams {
            capacity: 4,
            batch: 2,
        };
        let updates = vec![SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)];
        let result = generate_proof(params, updates);
        assert_eq!(
            commit_ss_state(&result.final_state).0,
            result.proof.final_.0
        );
        assert_eq!(result.final_state.total_mass(), 2);
    }

    /// In-circuit group-by: two records with the same key must sum into one
    /// candidate (count 2), and the proof certifies it.
    #[test]
    fn ss_full_in_circuit_grouping_sums_counts() {
        let params = SsFullParams {
            capacity: 4,
            batch: 2,
        };
        let updates = vec![SsFullUpdate::real(42, 1), SsFullUpdate::real(42, 1)];
        let result = generate_proof(params, updates);
        assert_eq!(
            commit_ss_state(&result.final_state).0,
            result.proof.final_.0
        );
        let actives: Vec<_> = result
            .final_state
            .rows
            .iter()
            .filter(|r| r.active == 1)
            .collect();
        assert_eq!(actives.len(), 1, "same key groups into one candidate");
        assert_eq!(actives[0].key, 42);
        assert_eq!(actives[0].count, 2, "grouped count = 1 + 1");
        assert_eq!(result.final_state.total_mass(), 2);
    }

    /// Top-`s` retention: with capacity 2 and 4 distinct heavy keys of
    /// increasing weight, the two highest-count keys are kept and the two
    /// lowest spill to the residual — and the leaf verifies.
    #[test]
    fn ss_full_top_s_retention() {
        let params = SsFullParams {
            capacity: 2,
            batch: 4,
        };
        // weights 1,2,3,4 on distinct keys → top-2 are the weight-3 and
        // weight-4 keys.
        let updates = vec![
            SsFullUpdate::real(101, 1),
            SsFullUpdate::real(102, 2),
            SsFullUpdate::real(103, 3),
            SsFullUpdate::real(104, 4),
        ];
        let s0 = SsFullState::empty(params);
        let (s_new, residual) = apply_batch_ss_full(&s0, &updates);
        let kept: Vec<_> = s_new.rows.iter().filter(|r| r.active == 1).collect();
        assert_eq!(kept.len(), 2, "exactly capacity heavy hitters kept");
        // Surfacing: the retained SET is the true top-2 keys (103, 104).
        let kept_keys: Vec<u64> = {
            let mut k: Vec<u64> = kept.iter().map(|r| r.key).collect();
            k.sort_unstable();
            k
        };
        assert_eq!(kept_keys, vec![103, 104], "the two heaviest keys are retained");
        // Misra-Gries subtraction: τ = (s+1)-th largest count = 2, so the retained
        // counts are their true counts minus τ (3−2=1, 4−2=2) — under-estimates.
        let kept_counts: Vec<u32> = {
            let mut c: Vec<u32> = kept.iter().map(|r| r.count).collect();
            c.sort_unstable();
            c
        };
        assert_eq!(
            kept_counts,
            vec![1, 2],
            "retained counts are the true counts minus τ=2"
        );
        // Mass conservation now carries the discarded deficit capacity·τ.
        let res_mass: u64 = residual
            .iter()
            .filter(|r| r.active == 1)
            .map(|r| r.count as u64)
            .sum();
        let tau = 2u64; // (s+1)-th largest grouped count for this fixture
        assert_eq!(
            s_new.total_mass() + res_mass + (params.capacity as u64) * tau,
            1 + 2 + 3 + 4
        );

        let result = generate_proof(params, updates);
        assert_eq!(
            commit_ss_state(&result.final_state).0,
            result.proof.final_.0
        );
    }

    /// **Cross-batch N/s surfacing (the Misra-Gries deficit guarantee).** A
    /// genuinely heavy key that arrives thinly spread must still surface. Under
    /// the previous keep-top-`s`-exact rule the padding keys hold their exact
    /// high counts, so `H` never overtakes them and is dropped every epoch; the
    /// (s+1)-th-value subtraction decays the padding keys so `H` accumulates and
    /// surfaces, with a per-key deficit bounded by `N/s` (Agarwal et al.,
    /// "Mergeable Summaries", 2012).
    #[test]
    fn cross_batch_ns_surfacing() {
        let params = SsFullParams {
            capacity: 2,
            batch: 4,
        };
        let (w1, w2, h, f) = (10u64, 11u64, 12u64, 13u64);

        // B1: two padding keys just above H. Old keep-top-s-exact would fix
        // {W1:6, W2:6} EXACTLY and drop H every epoch; MG decays them to
        // {W1:1, W2:1} (τ = the (s+1)-th largest count = H's 5).
        let s0 = SsFullState::empty(params);
        let b1 = vec![
            SsFullUpdate::real(w1, 6),
            SsFullUpdate::real(w2, 6),
            SsFullUpdate::real(h, 5),
            SsFullUpdate::dummy(),
        ];
        let (s1, _) = apply_batch_ss_full(&s0, &b1);
        assert_eq!(s1.frequency(h), 0, "H below the padding keys is dropped at B1");
        assert_eq!(s1.frequency(w1), 1, "padding key W1 decayed by τ=5");

        // B2: H arrives again; now it overtakes the DECAYED padding keys and
        // surfaces (under keep-top-s-exact the padding keys would still be 6 and
        // H would be dropped a second time).
        let b2 = vec![
            SsFullUpdate::real(h, 5),
            SsFullUpdate::real(f, 1),
            SsFullUpdate::dummy(),
            SsFullUpdate::dummy(),
        ];
        let (s2, _) = apply_batch_ss_full(&s1, &b2);
        assert!(s2.frequency(h) > 0, "the heavy key H surfaces after MG decay");

        // Under-estimate + N/s deficit bound. True H mass = 10; N so far = 23.
        let true_h = 10u64;
        let n = 23u64;
        let s = params.capacity as u64;
        let fhat = s2.frequency(h) as u64;
        assert!(fhat <= true_h, "MG counters never over-estimate");
        assert!(true_h - fhat <= n / s, "per-key deficit is bounded by N/s");

        // The surfacing transition also self-verifies in-circuit.
        let _ = prove_ss_full(params, s1, b2);
    }

    /// Soundness: a corrupted post-retention table (not the count-sort
    /// image of the grouped candidates) must be rejected by the PermuteAir
    /// + sortedness + compaction constraints.
    #[test]
    fn ss_full_soundness_rejects_bad_table() {
        let params = SsFullParams {
            capacity: 4,
            batch: 2,
        };
        let updates = vec![SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)];

        TAMPER_GSORTED.with(|c| c.set(false));
        let _ok = generate_proof(params, updates.clone());

        TAMPER_GSORTED.with(|c| c.set(true));
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(params, updates)
        }));
        TAMPER_GSORTED.with(|c| c.set(false));
        assert!(
            bad.is_err(),
            "corrupted g_sorted accepted — top-s constraints unsound"
        );
    }

    #[test]
    #[ignore]
    fn ss_full_proving_time_with_different_active_counts() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = SsFullParams {
            capacity: 32,
            batch: 100,
        };
        println!();
        println!("ss_final_full — proving time vs. active-count density");
        println!("=====================================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}", params.capacity, params.batch);
        println!();
        for &active in &[100usize, 50, 30, 10, 5, 1] {
            let updates = gen_padded_batch(params, active);
            let elapsed = with_pool(threads, move || {
                let t = Instant::now();
                let _ = generate_proof(params, updates);
                t.elapsed()
            });
            println!(
                "  active={active:>3} (of {:>3})   prove {elapsed:>10.2?}",
                params.batch
            );
        }
    }

    #[test]
    #[ignore]
    fn ss_full_proving_time_merge_two_leaves() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = SsFullParams {
            capacity: 32,
            batch: 100,
        };
        println!();
        println!("ss_final_full — merge proving-time check");
        println!("==========================================");
        println!("  threads: {threads_label}");
        let (l1, l2) = with_pool(threads, move || {
            let s0 = SsFullState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let leaf1 = prove_ss_full(params, s0.clone(), b1.clone());
            let l1 = t1.elapsed();
            let (s1, _) = apply_batch_ss_full(&s0, &b1);
            assert_eq!(commit_ss_state(&s1).0, leaf1.final_.0);
            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let _ = prove_ss_full(params, s1, b2);
            (l1, t2.elapsed())
        });
        println!("  leaf 1 prove:       {l1:>10.2?}");
        println!("  leaf 2 prove:       {l2:>10.2?}");
        println!("  total wall-clock:   {:>10.2?}", l1 + l2);
    }

    #[test]
    #[ignore]
    fn ss_full_generate_and_store_proof() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = SsFullParams {
            capacity: 32,
            batch: 100,
        };
        let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("mkdir");
        println!();
        println!("ss_final_full — generate two proofs + store to disk");
        println!("  threads: {threads_label}");
        with_pool(threads, move || {
            let s0 = SsFullState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_ss_full(params, s0.clone(), b1.clone());
            let l1t = t1.elapsed();
            let p1 = postcard::to_allocvec(&l1.output.0).expect("ser p1");
            fs::write(out_dir.join("ss_full_proof1.bin"), &p1).expect("w p1");
            let (s1, _) = apply_batch_ss_full(&s0, &b1);
            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let l2 = prove_ss_full(params, s1, b2);
            let l2t = t2.elapsed();
            let p2 = postcard::to_allocvec(&l2.output.0).expect("ser p2");
            fs::write(out_dir.join("ss_full_proof2.bin"), &p2).expect("w p2");
            println!("  leaf 1 prove: {l1t:>10.2?}  size {} bytes", p1.len());
            println!("  leaf 2 prove: {l2t:>10.2?}  size {} bytes", p2.len());
            let mut meta = String::new();
            meta.push_str("# ss_final_full proofs — §G top-s retention, full pipeline\n");
            meta.push_str("# Certifies: commits; union→key-group-sum→count-sort→top-s split;\n");
            meta.push_str("# count-sortedness + active-monotonicity; threshold-residual via\n");
            meta.push_str("# count-ascending order; mass conservation.\n");
            fs::write(out_dir.join("ss_full_proofs.meta.txt"), &meta).expect("w meta");
        });
    }

    /// **Regression: union-fragmentation is rejected.** The circuit binds the
    /// key-union to `[old ‖ batch]` only as a MULTISET permutation and groups by
    /// ADJACENCY equality. Without a union key-sortedness constraint a prover
    /// could scatter a heavy key's rows non-adjacently, fragmenting its aggregate
    /// so the genuine heaviest key is evicted below the top-`s` cut — an
    /// accepting proof for a wrong monitored set. Stage 5's key-sortedness +
    /// single-limb range-check now forces equal keys to be contiguous, so the
    /// fragmenting witness fails and proving is rejected.
    ///
    /// Setup (capacity s=2): old {A:6, C:9}, batch {A:+4, B:8}. True grouped
    /// union {A:10, B:8, C:9} ⇒ top-2 = {A:10, C:9}. The tampered prover leaves
    /// the union unsorted so A fragments into 6+4 and would certify {B:8, C:9}
    /// (A evicted). The fix rejects it.
    #[test]
    fn fragmentation_rejected() {
        let params = SsFullParams {
            capacity: 2,
            batch: 2,
        };
        // key_field(1) < key_field(2) < key_field(3); all non-zero (0 = dummy).
        let (ka, kb, kc) = (1u64, 2u64, 3u64);
        let initial = SsFullState {
            rows: vec![SsFullRow::real(ka, 6), SsFullRow::real(kc, 9)],
            params,
        };
        let batch = vec![SsFullUpdate::real(ka, 4), SsFullUpdate::real(kb, 8)];

        // Honest transition keeps the true top-2 SET {A, C}, evicts B — and its
        // proof self-verifies (key-sorted union passes the new constraint). The
        // Misra-Gries subtraction (τ = largest-residual count = 8) leaves A and C
        // as under-estimates (10−8=2, 9−8=1), the surfacing guarantee: the true
        // heaviest keys stay active.
        let (honest_final, _) = apply_batch_ss_full(&initial, &batch);
        assert_eq!(
            honest_final.frequency(ka),
            2,
            "honest keeps A (true heaviest), under-estimated by τ=8"
        );
        assert_eq!(honest_final.frequency(kc), 1, "honest keeps C, under-estimated by τ=8");
        assert_eq!(
            honest_final.frequency(kb),
            0,
            "honest evicts B:8 (lightest)"
        );
        let _honest_proof = prove_ss_full(params, initial.clone(), batch.clone());

        // Attack: fragment A. Natively it WOULD certify a wrong state (A evicted)…
        TAMPER_FRAGMENT.with(|f| f.set(true));
        let (mal_final, _) = apply_batch_ss_full(&initial, &batch);
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_ss_full(params, initial.clone(), batch.clone())
        }));
        TAMPER_FRAGMENT.with(|f| f.set(false));
        assert_eq!(
            mal_final.frequency(ka),
            0,
            "the attack WOULD evict true top key A"
        );
        assert!(
            mal_final.frequency(kb) > 0,
            "the attack WOULD wrongly retain B (under-estimated post-subtraction)"
        );

        // …but the circuit now REJECTS the fragmenting union (non-sorted keys
        // fail the key-sortedness range-check → witness/self-verify fails).
        assert!(
            mal.is_err(),
            "FIX REGRESSED: fragmenting the union must be rejected by key-sortedness",
        );
    }

    /// **Regression: non-canonical count-equal ordering is rejected.** Within a
    /// count-equal run the prover must not be free to choose the order (which
    /// fixes the canonical top-`s` cut). Stage 7's key tie-break (keys
    /// non-decreasing within count-equal runs, matching the native ascending
    /// sort) makes the order deterministic and rejects any reorder.
    ///
    /// Setup (capacity s=2): a tied retained pair {A:9, B:9} above a low decoy
    /// {C:5}. The Misra-Gries subtraction uses τ = the (s+1)-th largest count =
    /// the decoy's 5, so the tied pair survives as under-estimates {A:4, B:4}
    /// (surfacing: both genuine heavy hitters stay active). A descending-key
    /// reorder of the count-9 run keeps the same SET but violates the canonical
    /// order; the tie-break range-check rejects it. (Note: under Misra-Gries a
    /// tie that *straddles* the cut is additionally zeroed — τ equals the tied
    /// count — so the classic "straddle picks a different monitored set" attack
    /// is neutralized outright; this test therefore guards the canonical-order
    /// constraint itself.)
    #[test]
    fn tie_break_rejected() {
        let params = SsFullParams {
            capacity: 2,
            batch: 2,
        };
        let (ka, kb, kc) = (1u64, 2u64, 3u64);
        let initial = SsFullState {
            rows: vec![SsFullRow::real(ka, 9), SsFullRow::real(kb, 9)],
            params,
        };
        let batch = vec![SsFullUpdate::real(kc, 5), SsFullUpdate::dummy()];

        // Honest canonical order retains the tied pair {A, B} (true top-2),
        // under-estimated by τ=5 (the decoy count), evicts the decoy C, and
        // self-verifies.
        let (honest_final, _) = apply_batch_ss_full(&initial, &batch);
        assert_eq!(honest_final.frequency(ka), 4, "A retained, under-estimated by τ=5");
        assert_eq!(honest_final.frequency(kb), 4, "B retained, under-estimated by τ=5");
        assert_eq!(
            honest_final.frequency(kc),
            0,
            "the low decoy C is evicted"
        );
        let _honest = prove_ss_full(params, initial.clone(), batch.clone());

        // Non-canonical (descending-key) reorder of the count-9 run keeps the
        // same surviving set but violates the canonical order…
        TAMPER_TIE.with(|f| f.set(true));
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_ss_full(params, initial.clone(), batch.clone())
        }));
        TAMPER_TIE.with(|f| f.set(false));

        // …and the key tie-break rejects it.
        assert!(
            mal.is_err(),
            "FIX REGRESSED: non-canonical count-equal order must be rejected by the key tie-break",
        );
    }

    /// **Regression: count-0 active-bit latitude is rejected (full canonical
    /// retention).** `grouped.active` must be derived (`se·(acc_active≠0)`), not
    /// a free prover bit — otherwise, with the summary under-full, a prover
    /// could flip the active flag on a count-0 real key (weight 0, reachable via
    /// value-0 records) to pick which zero-weight key fills a leftover retained
    /// slot, giving two accepting proofs with different retained SETS.
    ///
    /// Setup (capacity s=2): old {A:5}, batch {C:0, D:0} (C, D distinct real
    /// keys, value 0). Only A has weight; C and D are count-0 active candidates
    /// competing for the one leftover slot. Canonical order retains {A, D}
    /// (larger-key tie); demoting D's active bit would instead retain {A, C}.
    /// The active binding rejects the demotion.
    #[test]
    fn count0_active_rejected() {
        let params = SsFullParams {
            capacity: 2,
            batch: 2,
        };
        let (ka, kc, kd) = (1u64, 3u64, 4u64);
        let initial = SsFullState {
            rows: vec![SsFullRow::real(ka, 5), SsFullRow::dummy()],
            params,
        };
        let batch = vec![SsFullUpdate::real(kc, 0), SsFullUpdate::real(kd, 0)];

        // Honest: A retained; the larger-key count-0 candidate D fills the
        // leftover slot; C is evicted — and it self-verifies.
        let (honest_final, _) = apply_batch_ss_full(&initial, &batch);
        assert_eq!(
            honest_final.frequency(ka),
            5,
            "A (the only weighted key) retained"
        );
        let _honest = prove_ss_full(params, initial.clone(), batch.clone());

        // Demoting D's active bit WOULD retain {A, C} instead — a different set…
        TAMPER_ACTIVE.with(|f| f.set(true));
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_ss_full(params, initial.clone(), batch.clone())
        }));
        TAMPER_ACTIVE.with(|f| f.set(false));

        // …but the active binding (active = se·(acc_active≠0)) rejects it.
        assert!(
            mal.is_err(),
            "FIX REGRESSED: flipping a count-0 segment's active bit must be rejected",
        );
    }

    /// **Regression: out-of-domain counts are rejected (count-wrap defense).**
    /// The count-sortedness only decomposes the adjacent count DIFF, so a count
    /// crafted ≈ p could wrap a genuine descent into a small in-range diff and
    /// admit a non-canonical order (evicting a real heavy hitter). Stage 7 now
    /// range-checks every count to < 2^(COUNT_DIFF_BITS−1); a count reaching that
    /// bound is rejected. Honest small counts still verify.
    #[test]
    fn count_overflow_rejected() {
        let params = SsFullParams {
            capacity: 2,
            batch: 2,
        };
        // Honest small-count batch verifies.
        let _ok = prove_ss_full(
            params,
            SsFullState::empty(params),
            vec![SsFullUpdate::real(1, 5), SsFullUpdate::real(2, 3)],
        );

        // A count reaching 2^(COUNT_DIFF_BITS−1) is out of the sortedness domain.
        let over = 1u32 << (COUNT_DIFF_BITS - 1);
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_ss_full(
                params,
                SsFullState::empty(params),
                vec![SsFullUpdate::real(1, over), SsFullUpdate::real(2, 1)],
            )
        }));
        assert!(
            mal.is_err(),
            "a count ≥ 2^(COUNT_DIFF_BITS−1) must be rejected by the range-check"
        );
    }

    /// **Regression (canonicality parity with GK): a malformed S_old dummy
    /// carrying a nonzero count is rejected.** SS's count-sort + count-monotone
    /// already pin such a row to the evicted region, but the active-gated
    /// group-by sum and the init `active=0 ⇒ count=0` check now reject it
    /// outright, keeping SS in lockstep with the GK hardening.
    #[test]
    fn malformed_dummy_count_rejected() {
        let params = SsFullParams {
            capacity: 2,
            batch: 2,
        };
        let batch = vec![SsFullUpdate::real(7, 1), SsFullUpdate::dummy()];

        // Honest all-zero-dummy S_old proves fine.
        let _ok = prove_ss_full(params, SsFullState::empty(params), batch.clone());

        // Malformed dummy: key=3, count=9, active=0.
        let initial = SsFullState {
            rows: vec![
                SsFullRow::real(5, 1),
                SsFullRow {
                    key: 3,
                    count: 9,
                    active: 0,
                },
            ],
            params,
        };
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_ss_full(params, initial.clone(), batch.clone())
        }));
        assert!(
            mal.is_err(),
            "a committed S_old dummy with nonzero count must be rejected",
        );
    }

    // ─── Malicious-prover probes (revision Step 1, Track B) ─────────────────

    fn panic_msg(e: &Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "<non-string panic>".to_string()
        }
    }

    /// Malicious witness exploiting a PermuteBus SHARED by the two permutes:
    /// move one union row `x` out of the key-sort permute's output and into the
    /// count-sort permute's output, paying for it with one all-zero dummy
    /// grouped row moved the other way. Per op the multisets differ; only the
    /// union of all permute rows balances. Everything downstream (group-by
    /// tags, running sums, count-sort order, τ, compression) is recomputed
    /// honestly from the forged tables, so every non-permute constraint holds.
    fn forge_cross_permute_witness(
        initial: &SsFullState,
        batch: &[SsFullUpdate],
        x: SsFullRow,
    ) -> SsWitness {
        let params = initial.params;
        let m = params.batch;
        let total = params.capacity + m;
        let mut combined: Vec<SsFullRow> = initial.rows.clone();
        combined.extend(batch.iter().map(|u| SsFullRow {
            key: u.key,
            count: u.value,
            active: u.active,
        }));
        // key_sorted' = (combined − {x}) + {dummy}, key-sorted.
        let mut ks = combined.clone();
        let pos = ks.iter().position(|r| *r == x).expect("x must be a union row");
        ks[pos] = SsFullRow::dummy();
        ks.sort_by_key(|r| key_field(r.key));
        let (key_eq_tag, seg_end, grouped) = group_by_key(&ks);
        // g_sorted' = (grouped' − {dummy}) + {x}, count-sorted.
        let mut gs = grouped.clone();
        let dpos = gs
            .iter()
            .position(|r| *r == SsFullRow::dummy())
            .expect("an all-zero dummy grouped row");
        gs[dpos] = x;
        gs.sort_by_key(|r| (r.active, r.count, key_field(r.key)));
        let tau = gs[m - 1].count;
        let (final_state, residual) = compress_from_gsorted(params, &gs, tau);
        SsWitness {
            initial: initial.clone(),
            batch: batch.to_vec(),
            final_state,
            residual,
            build: SsBuild {
                combined,
                sigma_key: (0..total).collect(),
                key_sorted: ks,
                grouped,
                key_eq_tag,
                seg_end,
                sigma_count: (0..total).collect(),
                g_sorted: gs,
                tau,
            },
        }
    }

    /// Run the malicious prover: both Permute ops emit the forged tables.
    fn prove_forged_cross_permute(
        params: SsFullParams,
        w: &SsWitness,
    ) -> std::thread::Result<SsFullLeafProof> {
        let mut leaf = build_ss_full_leaf(params, false);
        let ks = leaf.pack_union_table(&w.build.key_sorted);
        let gs = leaf.pack_grouped_table(&w.build.g_sorted);
        crate::sketch::forge_permute::forge_permute_outputs(&mut leaf.circuit, 0, ks);
        crate::sketch::forge_permute::forge_permute_outputs(&mut leaf.circuit, 1, gs);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| leaf.prove_witness(w)))
    }

    /// **Shared-PermuteBus forgery (key fragmentation through the bus).**
    /// batch = [K, K] into an empty capacity-4 summary. Honest final: {K:2}.
    /// Forged: the key-sort output drops one (K,1) row for a dummy; the
    /// count-sort output takes that (K,1) row instead of a dummy grouped row.
    /// The group-by then sees K once (count 1), and the count-sorted table
    /// holds K twice — final {K:1, K:1}: the fragmentation break the union
    /// key-sortedness fix was meant to close, reopened through the bus. Sorted,
    /// tie-break, Misra-Gries subtraction and mass (2 = 1+1) all hold.
    ///
    /// Pre-fix circuit (no op tag): the forged final is ACCEPTED (the proof
    /// self-verifies). With the op tag the same malicious prover is REJECTED:
    /// the moved rows no longer have a matching element on the other side of
    /// the PermuteBus (`GlobalCumulativeMismatch` on PermuteBus).
    #[test]
    fn shared_permute_bus_forgery_rejected() {
        let params = SsFullParams {
            capacity: 4,
            batch: 2,
        };
        let k = 42u64;
        let initial = SsFullState::empty(params);
        let batch = vec![SsFullUpdate::real(k, 1), SsFullUpdate::real(k, 1)];
        let (honest_final, _) = apply_batch_ss_full(&initial, &batch);
        assert_eq!(honest_final.frequency(k), 2);
        let _honest = prove_ss_full(params, initial.clone(), batch.clone());

        let forged = forge_cross_permute_witness(&initial, &batch, SsFullRow::real(k, 1));
        let copies = forged
            .final_state
            .rows
            .iter()
            .filter(|r| r.active == 1 && r.key == k && r.count == 1)
            .count();
        assert_eq!(copies, 2, "forged final holds K twice at count 1");
        assert_ne!(
            commit_ss_state(&forged.final_state),
            commit_ss_state(&honest_final),
            "forged final is a different committed state"
        );

        // Pre-fix circuit: the attack goes through.
        OP_TAG.with(|c| c.set(Some(false)));
        let pre = prove_forged_cross_permute(params, &forged);
        OP_TAG.with(|c| c.set(None));
        match &pre {
            Ok(_) => println!("[shared_permute_bus] pre-fix: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[shared_permute_bus] pre-fix: REJECTED: {}", panic_msg(e)),
        }
        assert!(
            pre.is_ok(),
            "PoC premise: the untagged circuit accepts the cross-permute forgery"
        );

        // Fixed circuit (default): rejected.
        let post = prove_forged_cross_permute(params, &forged);
        match &post {
            Ok(_) => println!("[shared_permute_bus] fixed: forged final ACCEPTED"),
            Err(e) => println!("[shared_permute_bus] fixed: REJECTED: {}", panic_msg(e)),
        }
        assert!(
            post.is_err(),
            "op tag must stop the two permutes from trading rows on the shared bus"
        );
    }

    /// **Decomposition-binding probe.** `decompose_ext_to_base_coeffs(x)`
    /// with the recompose NPO and NO coefficient lookups emits the coefficients
    /// as a hint and re-links them to `x` only through a RecomposeAir row whose
    /// WitnessChecks message is `[x_idx, v0..v3]` — the coefficient witnesses
    /// themselves are never on the bus there. The probe commits to a final
    /// state whose key-7 row says count 1000 while the decomposition feeds the
    /// honest coefficients (count 1) to every constraint. Returns the outcome.
    fn run_decomposition_probe(bind: bool) -> std::thread::Result<SsFullLeafProof> {
        BIND_DECOMP.with(|c| c.set(Some(bind)));
        let params = SsFullParams {
            capacity: 4,
            batch: 2,
        };
        let initial = SsFullState::empty(params);
        let batch = vec![SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)];
        // The honest transition proves under this configuration.
        let _honest_proof = prove_ss_full(params, initial.clone(), batch.clone());
        let honest = honest_ss_witness(&initial, &batch);
        let i = honest
            .final_state
            .rows
            .iter()
            .position(|r| r.active == 1 && r.key == 7)
            .expect("key 7 retained");
        let row = honest.final_state.rows[i];
        let mut forged = honest.clone();
        forged.final_state.rows[i].count = 1000;

        let mut leaf = build_ss_full_leaf(params, false);
        leaf.circuit
            .update_permute_witnesses(&[
                honest.build.sigma_key.clone(),
                honest.build.sigma_count.clone(),
            ])
            .expect("sigmas");
        let wid = leaf.circuit.private_input_rows[params.capacity + i];
        let (lo, hi) = key_lo_hi(row.key);
        crate::sketch::forge_permute::forge_decomposition(
            &mut leaf.circuit,
            wid,
            [
                Val::from_u32(lo),
                Val::from_u32(hi),
                Val::from_u32(row.count),
                Val::from_u32(row.active),
            ],
        );
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            leaf.prove_witness(&forged)
        }));
        BIND_DECOMP.with(|c| c.set(None));
        match &res {
            Ok(_) => println!("[decomposition bind={bind}] forged final (count 1000) ACCEPTED"),
            Err(e) => println!("[decomposition bind={bind}] forged final REJECTED: {}", panic_msg(e)),
        }
        res
    }

    /// PoC (pre-fix recompose lowering, `BIND_DECOMPOSITIONS = false`): the
    /// committed final state is NOT bound to the decomposed fields the
    /// constraints use — a final claiming count 1000 for a key seen once
    /// self-verifies.
    #[test]
    fn decomposition_forgery_accepted_without_coeff_binding() {
        assert!(
            crate::recompose_binding::with_unbound_recompose(|| run_decomposition_probe(false))
                .is_ok(),
            "expected the unbound decomposition to accept the forged final state"
        );
    }

    /// Fix check (the deployed configuration): the fork's `recompose/coeff`
    /// lowering alone rejects the same malicious prover — the row's
    /// `[coeff_idx, v_i, 0, 0, 0]` lookups carry the forged packed row's
    /// coefficients, which the honest coefficients the constraints read cannot
    /// match.
    #[test]
    fn decomposition_forgery_rejected_by_recompose_coeff_table() {
        assert!(
            run_decomposition_probe(false).is_err(),
            "recompose/coeff lowering must reject the forged final state"
        );
    }

    /// Fix check for the per-circuit alternative: with the ALU binding
    /// (+ base-forcing) the same malicious prover is rejected even under the
    /// pre-fix recompose lowering (the recomposition `sum c_i X^i - x = 0`
    /// cannot hold for the honest coefficients of a forged packed row).
    #[test]
    fn decomposition_forgery_rejected_with_coeff_binding() {
        assert!(
            crate::recompose_binding::with_unbound_recompose(|| run_decomposition_probe(true))
                .is_err(),
            "bound decomposition must reject the forged final state"
        );
    }

    /// Completeness of the opt-in decomposition binding: honest transitions
    /// (grouping, top-s eviction + Misra-Gries subtraction, a chained epoch
    /// with a non-empty prior) still self-verify, and the shared-bus forgery is
    /// still rejected.
    #[test]
    fn decomposition_binding_honest_proofs_verify() {
        BIND_DECOMP.with(|c| c.set(Some(true)));
        let params = SsFullParams {
            capacity: 4,
            batch: 4,
        };
        let s0 = SsFullState::empty(params);
        let b1 = vec![
            SsFullUpdate::real(42, 1),
            SsFullUpdate::real(42, 1),
            SsFullUpdate::real(7, 3),
            SsFullUpdate::dummy(),
        ];
        let p1 = prove_ss_full(params, s0.clone(), b1.clone());
        let (s1, _) = apply_batch_ss_full(&s0, &b1);
        assert_eq!(p1.final_.0, commit_ss_state(&s1).0);
        let b2 = vec![
            SsFullUpdate::real(9, 5),
            SsFullUpdate::real(11, 6),
            SsFullUpdate::real(13, 2),
            SsFullUpdate::real(42, 4),
        ];
        let p2 = prove_ss_full(params, s1.clone(), b2.clone());
        let (s2, _) = apply_batch_ss_full(&s1, &b2);
        assert_eq!(p2.initial.0, p1.final_.0);
        assert_eq!(p2.final_.0, commit_ss_state(&s2).0);

        let p = SsFullParams {
            capacity: 4,
            batch: 2,
        };
        let batch = vec![SsFullUpdate::real(42, 1), SsFullUpdate::real(42, 1)];
        let forged =
            forge_cross_permute_witness(&SsFullState::empty(p), &batch, SsFullRow::real(42, 1));
        let res = prove_forged_cross_permute(p, &forged);
        BIND_DECOMP.with(|c| c.set(None));
        assert!(res.is_err(), "shared-bus forgery must stay rejected under binding");
    }

    /// Cost of the fixes (padded trace rows + one prove): pre-fix circuit
    /// (untagged, unbound recompose lowering) vs op tag vs op tag + the
    /// per-circuit ALU decomposition binding vs op tag + the fork's
    /// `recompose/coeff` lowering (the deployed configuration).
    /// Run: `cargo test --release --lib ss_final_full::tests::fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fix_overhead() {
        for &(cap, m) in &[(64usize, 16usize), (1024, 16)] {
            let params = SsFullParams { capacity: cap, batch: m };
            let batch = gen_padded_batch(params, m);
            for (label, tag, bind, coeff_table) in [
                ("pre-fix", false, false, false),
                ("op-tag", true, false, false),
                ("op-tag+alu-bind", true, true, false),
                ("op-tag+coeff", true, false, true),
            ] {
                OP_TAG.with(|c| c.set(Some(tag)));
                BIND_DECOMP.with(|c| c.set(Some(bind)));
                let mut leaf = if coeff_table {
                    build_ss_full_leaf(params, false)
                } else {
                    crate::recompose_binding::with_unbound_recompose(|| {
                        build_ss_full_leaf(params, false)
                    })
                };
                OP_TAG.with(|c| c.set(None));
                BIND_DECOMP.with(|c| c.set(None));
                let t = std::time::Instant::now();
                let _ = leaf.prove_epoch(SsFullState::empty(params), batch.clone());
                println!(
                    "[ss fix_overhead] cap={cap} m={m} {label:<16} trace_rows={} prove+verify={:?}",
                    leaf.trace_rows,
                    t.elapsed()
                );
            }
        }
    }

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────

    use crate::commitment::hiding::{SaltSeed, TAG_BATCH, TAG_STATE, rho_batch_bb, rho_state_bb};
    use crate::recursion::recursive::expose_forest::{
        batch_log, check_leaves_against_log, check_root_against_log, prove_hiding_merge,
        read_exposed_statement, root_vk_deriver, verify_bound_stark_proof_against_log,
        vk_pin_values,
    };
    use crate::recursion::recursive::noop_leaf::{ss_full_noop_leaf_commit, ss_full_noop_leaf_expose};
    use crate::recursion::recursive::root_vk::ForestShape;
    use crate::recursion::recursive::statement::{hash_bb, leaf_digest};
    use crate::sketch::forge;
    use p3_field::{BasedVectorSpace, PrimeField64};

    const HP: SsFullParams = SsFullParams { capacity: 4, batch: 2 };
    const SS: CommitFamily = CommitFamily::SpaceSaving;
    const HIDING: CommitMode = CommitMode::Hiding;

    fn hiding_leaf(expose: Expose) -> SsFullLeafCircuit {
        build_ss_full_leaf_commit(HP, expose, HIDING)
    }

    fn hp_empty() -> SsFullState {
        SsFullState::empty(HP)
    }

    /// A non-empty prior state (two retained keys).
    fn hp_prior() -> SsFullState {
        advanced(&hp_empty(), &[SsFullUpdate::real(3, 4), SsFullUpdate::real(5, 2)])
    }

    fn hp_batches() -> Vec<Vec<SsFullUpdate>> {
        vec![
            vec![SsFullUpdate::real(7, 3), SsFullUpdate::real(11, 5)],
            vec![SsFullUpdate::real(13, 2), SsFullUpdate::real(7, 4)],
        ]
    }

    fn advanced(s: &SsFullState, batch: &[SsFullUpdate]) -> SsFullState {
        apply_batch_ss_full(s, batch).0
    }

    /// Flat basis coefficients of VK pin values.
    fn vk_flat(vk: &[Challenge]) -> Vec<u64> {
        vk.iter()
            .flat_map(|c| {
                <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                    .iter()
                    .map(|x| x.as_canonical_u64())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// A VK recorded at b2-hiding@94e9f58 before the SS wiring: 8 base
    /// values, each the first coefficient of one pin Challenge.
    fn vk_literal(v: [u64; 8]) -> Vec<u64> {
        v.iter().flat_map(|&x| [x, 0, 0, 0]).collect()
    }

    /// Native twins: `Plain` is the old commitment whatever the salt (and the
    /// old commitments equal the digests recorded at b2-hiding@94e9f58);
    /// `Hiding` is `MyHash([kind, SpaceSaving, 0, 0, ρ…] ‖ flat)` over the
    /// same flat rows (layout drift guard). Equal states get different
    /// commitments under two salts, and a state and a batch with the SAME
    /// flat encoding (which collide under `Plain`) are separated by the kind
    /// tag; the family tag separates SS from Count-Min.
    #[test]
    fn commit_with_modes() {
        let lit = |v: [u64; 8]| v.map(Val::from_u64);
        let p4 = SsFullParams { capacity: 4, batch: 4 };
        let b4: Vec<SsFullUpdate> = (1..=4u32).map(|i| SsFullUpdate::real(100 + i as u64, i)).collect();
        let st = advanced(&SsFullState::empty(p4), &b4);
        let recorded_state =
            [1438579399, 1350688804, 1521214047, 649078179, 1528141926, 585250997, 1232065379, 1517326682];
        assert_eq!(commit_ss_state(&st).0, lit(recorded_state), "Plain Com(S) drifted");
        assert_eq!(
            commit_ss_state(&hp_empty()).0,
            lit([1639427943, 498343310, 136177619, 154834331, 561923912, 6334046, 777956955, 239184579]),
            "Plain Com(S_0) drifted"
        );
        assert_eq!(commit_ss_batch(&b4).0, lit(recorded_state), "Plain: same flat, same digest");
        assert_eq!(
            commit_ss_batch(&[SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)]).0,
            lit([1868926812, 122330611, 629661750, 1837177459, 1044260622, 1447332708, 1657134433, 1557521847]),
            "Plain Com(B) drifted"
        );

        let seed = SaltSeed::for_tests(9);
        let (r1, r2) = (rho_state_bb(&seed, SS, 1), rho_state_bb(&seed, SS, 2));
        let rb = rho_batch_bb(&seed, SS, 1);
        assert_eq!(commit_ss_state_with(&st, CommitMode::Plain, &r1), commit_ss_state(&st));
        assert_eq!(commit_ss_batch_with(&b4, CommitMode::Plain, &rb), commit_ss_batch(&b4));

        let h = MyHash::new(make_perm());
        let h1 = commit_ss_state_with(&st, HIDING, &r1);
        let mut input = vec![Val::from_u64(TAG_STATE), Val::from_u64(3), Val::ZERO, Val::ZERO];
        input.extend_from_slice(&r1.0);
        input.extend(flat_state_vals(&st));
        let want: [Val; 8] = h.hash_iter(input);
        assert_eq!(h1.0, want, "state layout drift");
        let hb = commit_ss_batch_with(&b4, HIDING, &rb);
        let mut input = vec![Val::from_u64(TAG_BATCH), Val::from_u64(3), Val::ZERO, Val::ZERO];
        input.extend_from_slice(&rb.0);
        input.extend(flat_batch_vals(&b4));
        let want: [Val; 8] = h.hash_iter(input);
        assert_eq!(hb.0, want, "batch layout drift");

        assert_ne!(h1, commit_ss_state_with(&st, HIDING, &r2), "two salts, two commitments");
        assert_ne!(h1, commit_ss_state(&st));
        assert_ne!(hb, commit_ss_batch(&b4));
        assert_eq!(flat_state_vals(&st), flat_batch_vals(&b4), "the fixture's state and batch share a flat");
        assert_ne!(
            commit_ss_state_with(&st, HIDING, &rb).0,
            commit_ss_batch_with(&b4, HIDING, &rb).0,
            "the kind tag separates Com(S) from Com(B)"
        );
        assert_ne!(
            h1.0,
            hiding::commit_flat_bb(HIDING, CommitKind::State, CommitFamily::CountMin, &r1, &flat_state_vals(&st)),
            "the family tag separates SS from Count-Min"
        );
    }

    /// (1) A hiding leaf's commitments (the proof's `initial/final_/
    /// batch_commit` fields and the exposed statement) equal the NATIVE
    /// hiding commitments under the leaf-`t` openings, for every statement
    /// layout (the leaf supports one binding: its sponge is the Semantic
    /// `add_hash_slice`). Also the one-call API, and leaf 1's init is the
    /// public anchor `Com(S_0; 0)`.
    #[test]
    fn hiding_leaf_exposes_native_hiding_commitments() {
        let seed = SaltSeed::for_tests(21);
        let t = 3u64;
        let ups = hp_batches()[0].clone();
        let expect = advanced(&hp_prior(), &ups);
        let o = Openings::for_leaf(&seed, SS, t);
        let init = commit_ss_state_with(&hp_prior(), HIDING, &rho_state_bb(&seed, SS, t - 1));
        let fin = commit_ss_state_with(&expect, HIDING, &rho_state_bb(&seed, SS, t));
        let bc = commit_ss_batch_with(&ups, HIDING, &rho_batch_bb(&seed, SS, t));
        assert_ne!(init, commit_ss_state(&hp_prior()), "hiding != plain");
        assert_ne!(fin, commit_ss_state(&expect), "hiding != plain");
        assert_ne!(bc, commit_ss_batch(&ups), "hiding != plain");
        for expose in [Expose::Interval, Expose::Boundary, Expose::None] {
            let mut leaf = hiding_leaf(expose);
            assert_eq!(leaf.commit_mode(), HIDING);
            let r = leaf.prove_epoch_commit(t, hp_prior(), ups.clone(), &o);
            assert_eq!(r.initial, init, "{expose:?}");
            assert_eq!(r.final_, fin, "{expose:?}");
            assert_eq!(r.batch_commit, bc, "{expose:?}");
            if !expose.exposes() {
                continue;
            }
            let st = read_exposed_statement(&r.output.0);
            assert_eq!(st.init, init.0.to_vec(), "{expose:?}");
            assert_eq!(st.final_, fin.0.to_vec(), "{expose:?}");
            match st.interval {
                Some(iv) => {
                    assert_eq!(expose, Expose::Interval);
                    assert_eq!((iv.lo, iv.hi), (Val::from_u64(t), Val::from_u64(t)));
                    assert_eq!(iv.digest, leaf_digest(&hash_bb, 4, t, &bc.0), "H(TAG_LEAF, t, Com(B_t; ρ))");
                }
                None => assert_eq!(expose, Expose::Boundary),
            }
        }
        // The one-call API.
        let r = prove_ss_full_interval_commit(HP, t, hp_prior(), ups.clone(), HIDING, &o);
        assert_eq!((r.initial, r.final_, r.batch_commit), (init, fin, bc));
        // Leaf 1 opens the public anchor Com(S_0; 0).
        let mut bleaf = hiding_leaf(Expose::Boundary);
        let r = bleaf.prove_epoch_commit(1, hp_empty(), ups.clone(), &Openings::for_leaf(&seed, SS, 1));
        let st = read_exposed_statement(&r.output.0);
        assert_eq!(st.init, commit_ss_state_with(&hp_empty(), HIDING, &SaltBb::ZERO).0.to_vec());
        assert_eq!(st.final_, r.final_.0.to_vec());
    }

    /// (2) The hiding leaf's VK does not depend on the salts (two different
    /// openings, and the zero-salt no-op leaf, give one VK), differs from the
    /// Plain VK, and the Plain circuit is the pre-B2 circuit: its VK equals
    /// the value recorded at b2-hiding@94e9f58 through the old builders and
    /// `build_ss_full_leaf_commit(.., Plain)`, and the Plain no-op leaf is the
    /// old one.
    #[test]
    fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
        let recorded = [
            (Expose::None, [244076800, 348624130, 86818571, 987364216, 794433870, 1128569993, 1199812825, 207596035]),
            (Expose::Boundary, [1660367479, 141433590, 1771118436, 411651249, 1631202690, 816723062, 1223335467, 1149506330]),
            (Expose::Interval, [407321886, 607299717, 1921107414, 734011497, 1873119001, 1590884499, 189246359, 7492791]),
        ];
        for (expose, vk) in recorded {
            let old = build_ss_full_leaf_expose(HP, expose).vk_pin_values();
            let plain = build_ss_full_leaf_commit(HP, expose, CommitMode::Plain).vk_pin_values();
            assert_eq!(vk_flat(&old), vk_literal(vk), "{expose:?}: Plain VK drifted from b2-hiding@94e9f58");
            assert_eq!(plain, old, "{expose:?}");
            if expose != Expose::Interval {
                assert_eq!(build_ss_full_leaf(HP, expose == Expose::Boundary).vk_pin_values(), old, "{expose:?}");
            }
            let hid = hiding_leaf(expose).vk_pin_values();
            assert_ne!(hid, old, "{expose:?}: the hiding circuit differs");
        }
        let ups = hp_batches()[0].clone();
        for expose in [Expose::Interval, Expose::Boundary] {
            let mut leaf = hiding_leaf(expose);
            let vk = leaf.vk_pin_values();
            let a = leaf.prove_epoch_commit(1, hp_prior(), ups.clone(), &Openings::for_leaf(&SaltSeed::for_tests(1), SS, 1));
            let b = leaf.prove_epoch_commit(5, hp_prior(), ups.clone(), &Openings::for_leaf(&SaltSeed::for_tests(2), SS, 5));
            assert_ne!(a.final_, b.final_, "{expose:?}");
            assert_eq!(vk_pin_values(&a.output.0), vk, "{expose:?}");
            assert_eq!(vk_pin_values(&b.output.0), vk, "{expose:?}");
            let noop = ss_full_noop_leaf_commit(HP, expose, HIDING);
            assert_eq!(vk_pin_values(&noop), vk, "{expose:?}: the zero-salt no-op leaf has the real leaves' VK");
        }
        // The Plain no-op leaf through the new path is the old one.
        let (new, old) = (
            ss_full_noop_leaf_commit(HP, Expose::Interval, CommitMode::Plain),
            ss_full_noop_leaf_expose(HP, Expose::Interval),
        );
        assert_eq!(vk_pin_values(&new), vk_pin_values(&old));
        assert_eq!(vk_flat(&vk_pin_values(&old)), vk_literal(recorded[2].1));
        assert_eq!(read_exposed_statement(&new), read_exposed_statement(&old));
    }

    /// (3) Equal states at two versions get different hiding commitments,
    /// both different from the plain one; at the proof level, two leaves at
    /// `t = 1, 2` whose (dummy) batches leave the state unchanged expose
    /// `Com(S; 0) → Com(S; ρ_1) → Com(S; ρ_2)`: three distinct values for
    /// one state, chained. Their two equal batches get different `Com(B_t)`.
    #[test]
    fn equal_states_get_unlinkable_hiding_commitments() {
        let seed = SaltSeed::for_tests(33);
        let s = hp_prior();
        let (r1, r2) = (rho_state_bb(&seed, SS, 1), rho_state_bb(&seed, SS, 2));
        let (c1, c2) = (commit_ss_state_with(&s, HIDING, &r1), commit_ss_state_with(&s, HIDING, &r2));
        assert_ne!(c1, c2);
        assert_ne!(c1, commit_ss_state(&s));
        assert_ne!(c2, commit_ss_state(&s));
        assert_eq!(commit_ss_state_with(&s, CommitMode::Plain, &r1), commit_ss_state(&s), "Plain ignores the salt");

        let noop = vec![SsFullUpdate::dummy(); HP.batch];
        assert_eq!(advanced(&s, &noop), s, "a dummy batch does not move the state");
        let mut leaf = hiding_leaf(Expose::Interval);
        let l1 = leaf.prove_epoch_commit(1, s.clone(), noop.clone(), &Openings::for_leaf(&seed, SS, 1));
        let l2 = leaf.prove_epoch_commit(2, s.clone(), noop, &Openings::for_leaf(&seed, SS, 2));
        let (s1, s2) = (read_exposed_statement(&l1.output.0), read_exposed_statement(&l2.output.0));
        assert_eq!(s1.init, commit_ss_state_with(&s, HIDING, &SaltBb::ZERO).0.to_vec());
        assert_eq!(s1.final_, c1.0.to_vec());
        assert_eq!(s2.init, s1.final_, "leaf 2 opens Com(S_1) with the same ρ_1");
        assert_eq!(s2.final_, c2.0.to_vec());
        assert_ne!(s1.init, s1.final_, "the state did not move, the commitment did");
        assert_ne!(s2.init, s2.final_);
        assert_ne!(l1.batch_commit, l2.batch_commit, "equal batches, unlinkable Com(B_t)");
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
        let (a, b) = (SaltSeed::for_tests(41), SaltSeed::for_tests(42));
        let bs = hp_batches();
        let s0 = hp_empty();
        let s1 = advanced(&s0, &bs[0]);
        let s2 = advanced(&s1, &bs[1]);
        let log_for = |seed: &SaltSeed| {
            let bc: Vec<[Val; 8]> =
                (0..2).map(|k| commit_ss_batch_with(&bs[k], HIDING, &rho_batch_bb(seed, SS, k as u64 + 1)).0).collect();
            batch_log(
                &commit_ss_state_with(&s0, HIDING, &SaltBb::ZERO).0,
                &commit_ss_state_with(&s2, HIDING, &rho_state_bb(seed, SS, 2)).0,
                &bc,
            )
        };
        let (log_a, log_b) = (log_for(&a), log_for(&b));
        let mut leaf = hiding_leaf(Expose::Interval);
        let l1 = leaf.prove_epoch_commit(1, s0.clone(), bs[0].clone(), &Openings::for_leaf(&a, SS, 1)).output;
        let l2 = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &Openings::for_leaf(&a, SS, 2)).output;
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log_a, Expose::Interval), Ok(()));
        assert!(check_leaves_against_log(&[&l1.0, &l2.0], &log_b, Expose::Interval).is_err(), "another seed's log");

        // Leaf 2 opened with a wrong batch randomizer: its digest H(TAG_LEAF, 2,
        // Com(B_2; ρ')) is not the log's.
        let bad_batch = Openings { batch: rho_batch_bb(&b, SS, 2), ..Openings::for_leaf(&a, SS, 2) };
        let l2b = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_batch).output;
        let e = check_leaves_against_log(&[&l1.0, &l2b.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("digest")), "{e:?}");
        // … with a wrong final randomizer: Com(S_2; ρ') is not the log's Com(S_T).
        let bad_final = Openings { final_: rho_state_bb(&b, SS, 2), ..Openings::for_leaf(&a, SS, 2) };
        let l2f = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_final).output;
        let e = check_leaves_against_log(&[&l1.0, &l2f.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("Com(S_T)")), "{e:?}");

        // Composition: the honest pair merges and verifies against log A.
        let shape = ForestShape::forest(2);
        let root = prove_hiding_merge(&l1, &l2);
        let noop = ss_full_noop_leaf_commit(HP, Expose::Interval, HIDING);
        let vk = root_vk_deriver(noop).root_vk(&shape);
        verify_bound_stark_proof_against_log(&root.0, &vk, &log_a, &shape);
        assert!(check_root_against_log(&root.0, &log_b, &shape).is_err());

        // Inconsistent ρ_1 across the boundary: the merge is unprovable.
        let bad_init = Openings { init: rho_state_bb(&b, SS, 1), ..Openings::for_leaf(&a, SS, 2) };
        let l2i = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_init).output;
        assert_ne!(read_exposed_statement(&l2i.0).init, read_exposed_statement(&l1.0).final_);
        let e = forge::catch_msg(|| prove_hiding_merge(&l1, &l2i)).map(|_| ());
        println!("B2 ss inconsistent ρ_1 merge: {e:?}");
        assert!(
            e.as_ref().is_err_and(|m| m.contains("WitnessConflict")),
            "leaf 2's init must use leaf 1's final randomizer: {e:?}"
        );
    }

    /// (5) The zero-salt no-op leaf of a Hiding circuit still exposes
    /// `init == final` (`= Com(S_0; 0)`, the public anchor), under both
    /// exposing layouts, so the twin-merge root-VK derivation works
    /// unchanged; the Plain no-op leaf exposes the plain `Com(S_0)`.
    #[test]
    fn hiding_noop_leaf_has_init_eq_final() {
        let anchor = commit_ss_state_with(&hp_empty(), HIDING, &SaltBb::ZERO);
        assert_ne!(anchor, commit_ss_state(&hp_empty()));
        for expose in [Expose::Interval, Expose::Boundary] {
            let noop = ss_full_noop_leaf_commit(HP, expose, HIDING);
            let st = read_exposed_statement(&noop);
            assert_eq!(st.init, st.final_, "{expose:?}");
            assert_eq!(st.init, anchor.0.to_vec(), "{expose:?}");
        }
        let plain = ss_full_noop_leaf_commit(HP, Expose::Boundary, CommitMode::Plain);
        let st = read_exposed_statement(&plain);
        assert_eq!(st.init, commit_ss_state(&hp_empty()).0.to_vec());
        assert_eq!(st.final_, st.init);
    }

    /// (F3, F5) The Hiding leaf costs exactly +2 Poseidon2 rows and +3 ALU
    /// rows per commitment over the Plain leaf (3 commitments: +6 and +9)
    /// under every statement layout, and none of its 36 salt values is a
    /// public value of the proof (the scan's positive control: a "salt"
    /// equal to an exposed commitment value is found).
    #[test]
    fn hiding_leaf_row_overhead_and_no_salt_in_public_values() {
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows, trace_rows};
        let seed = SaltSeed::for_tests(91);
        let t = 3u64;
        let ups = hp_batches()[0].clone();
        let o = Openings::for_leaf(&seed, SS, t);
        for expose in [Expose::Interval, Expose::Boundary, Expose::None] {
            let mut plain = build_ss_full_leaf_commit(HP, expose, CommitMode::Plain);
            let mut leaf = hiding_leaf(expose);
            let (p0, a0) = trace_rows(&plain.run_epoch_commit(t, &hp_prior(), &ups, &Openings::plain()));
            let (p1, a1) = trace_rows(&leaf.run_epoch_commit(t, &hp_prior(), &ups, &o));
            println!("B2 ss leaf rows {expose:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 6, "{expose:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 9, "{expose:?}: ALU rows");
            let hid = leaf.prove_epoch_commit(t, hp_prior(), ups.clone(), &o);
            assert_eq!(proof_alu_rows(&hid.output.0), a1, "{expose:?}: the proof's ALU height");
            assert_eq!(leaked_salts(&hid.output.0, &[o.init, o.final_, o.batch]), vec![], "{expose:?}");
            if expose.exposes() {
                let mut control = SaltBb::ZERO;
                control.0[0] = hid.initial.0[0];
                assert!(!leaked_salts(&hid.output.0, &[control]).is_empty(), "{expose:?}: the scan sees the statement");
            }
        }
    }

    /// (F1) A Hiding leaf never falls back to zero salts silently: the old
    /// `prove_epoch_at` / `prove_epoch` entry points panic on it, and so does
    /// `prove_epoch_commit` (and the one-call API) handed a zero final or
    /// batch salt. The explicit no-op path refuses a real batch and a batch
    /// that moves the state. Controls: a zero INIT salt is leaf 1's honest
    /// opening, and a Plain leaf still ignores its openings.
    #[test]
    fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
        let seed = SaltSeed::for_tests(81);
        let ups = hp_batches()[0].clone();
        let mut leaf = hiding_leaf(Expose::Interval);
        let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, hp_prior(), ups.clone()).final_).unwrap_err();
        assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
        assert!(forge::catch(|| leaf.prove_epoch(hp_prior(), ups.clone()).final_).is_none());
        let honest = Openings::for_leaf(&seed, SS, 2);
        for (what, o) in [
            ("plain", Openings::plain()),
            ("public_zero", Openings::public_zero()),
            ("zero final", Openings { final_: SaltBb::ZERO, ..honest }),
            ("zero batch", Openings { batch: SaltBb::ZERO, ..honest }),
        ] {
            let msg =
                forge::catch_msg(|| leaf.prove_epoch_commit(2, hp_prior(), ups.clone(), &o).final_).unwrap_err();
            assert!(msg.contains("public zero salt"), "{what}: {msg}");
        }
        let msg = forge::catch_msg(|| {
            prove_ss_full_interval_commit(HP, 2, hp_prior(), ups.clone(), HIDING, &Openings::plain()).final_
        })
        .unwrap_err();
        assert!(msg.contains("public zero salt"), "{msg}");
        let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, hp_prior(), ups.clone()).final_).unwrap_err();
        assert!(msg.contains("SsFullUpdate::dummy()"), "{msg}");
        // A non-canonical prior that the dummy batch would reorder.
        let unsorted = SsFullState {
            rows: vec![SsFullRow::real(9, 1), SsFullRow::dummy(), SsFullRow::dummy(), SsFullRow::dummy()],
            params: HP,
        };
        let noop = vec![SsFullUpdate::dummy(); HP.batch];
        let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, unsorted, noop.clone()).final_).unwrap_err();
        assert!(msg.contains("must not move"), "{msg}");

        let o1 = Openings::for_leaf(&seed, SS, 1);
        assert!(o1.init.is_zero());
        let r = leaf.prove_epoch_commit(1, hp_prior(), ups.clone(), &o1);
        assert_eq!(r.initial, commit_ss_state_with(&hp_prior(), HIDING, &SaltBb::ZERO));
        let mut plain = build_ss_full_leaf_commit(HP, Expose::Interval, CommitMode::Plain);
        for o in [Openings::plain(), honest] {
            let p = plain.prove_epoch_commit(2, hp_prior(), ups.clone(), &o);
            assert_eq!(p.initial, commit_ss_state(&hp_prior()));
            assert_eq!(p.final_, commit_ss_state(&advanced(&hp_prior(), &ups)));
            assert_eq!(p.batch_commit, commit_ss_batch(&ups));
        }
    }

    /// (F2) A continued history is anchored on the previous history's
    /// certified final commitment: history 0 ends at `Com(S_2; ρ_{0,2})`;
    /// history 1 restarts `t` at 1 from `S_2`, its leaf 1 opens the init with
    /// that anchor salt ([`Openings::for_leaf_after`]) and exposes exactly the
    /// certified value, and both leaves pass the per-batch check against
    /// history 1's log, whose `Com(S_0)` is that anchor. The same batch at the
    /// same `t` gets another commitment in each history. The zero init salt
    /// (what `for_leaf(.., 1)` gives) exposes `Com(S_2; 0)` and the log
    /// rejects it.
    #[test]
    fn continued_history_leaf_opens_the_previous_final_commitment() {
        use crate::commitment::hiding::{rho_batch_bb_in, rho_state_bb_in};
        let seed = SaltSeed::for_tests(71);
        let bs = hp_batches();
        let s1 = advanced(&hp_empty(), &bs[0]);
        let s2 = advanced(&s1, &bs[1]);
        let mut leaf = hiding_leaf(Expose::Interval);
        let h0_last = leaf.prove_epoch_commit(2, s1, bs[1].clone(), &Openings::for_leaf(&seed, SS, 2));
        let anchor_salt = rho_state_bb(&seed, SS, 2);
        let anchor = h0_last.final_;
        assert_eq!(anchor, commit_ss_state_with(&s2, HIDING, &anchor_salt));

        let h = 1u64;
        let s3 = advanced(&s2, &bs[0]);
        let s4 = advanced(&s3, &bs[1]);
        let o1 = Openings::for_leaf_after(&anchor_salt, &seed, SS, h);
        let l1 = leaf.prove_epoch_commit(1, s2.clone(), bs[0].clone(), &o1).output;
        let l2 = leaf.prove_epoch_commit(2, s3, bs[1].clone(), &Openings::for_leaf_in(&seed, SS, h, 2)).output;
        assert_eq!(read_exposed_statement(&l1.0).init, anchor.0.to_vec(), "history 1 starts at history 0's final");
        assert_eq!(read_exposed_statement(&l2.0).init, read_exposed_statement(&l1.0).final_);
        let bc: Vec<[Val; 8]> = (0..2)
            .map(|k| commit_ss_batch_with(&bs[k], HIDING, &rho_batch_bb_in(&seed, SS, h, k as u64 + 1)).0)
            .collect();
        let fin = commit_ss_state_with(&s4, HIDING, &rho_state_bb_in(&seed, SS, h, 2));
        let log1 = batch_log(&anchor.0, &fin.0, &bc);
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log1, Expose::Interval), Ok(()));
        let h0_bc1 = commit_ss_batch_with(&bs[0], HIDING, &rho_batch_bb(&seed, SS, 1)).0;
        assert_ne!(bc[0], h0_bc1, "t restarted, the randomizer did not");

        let zero_init = Openings { init: SaltBb::ZERO, ..o1 };
        let l1z = leaf.prove_epoch_commit(1, s2, bs[0].clone(), &zero_init).output;
        let e = check_leaves_against_log(&[&l1z.0, &l2.0], &log1, Expose::Interval);
        assert!(e.as_ref().is_err_and(|m| m.contains("Com(S_0)")), "{e:?}");
    }

    /// (8, with `commitment::hiding::tests::salt_private_inputs_have_alu_creators`)
    /// Build and prove the Hiding leaf at a tiny shape. Under the DEBUG
    /// profile (`cargo test --lib ss_final_full::tests::hiding_leaf_tiny_debug`)
    /// the fork debug-asserts, during the build, that each of the 9 salt
    /// private inputs has an ALU creator.
    #[test]
    fn hiding_leaf_tiny_debug() {
        let p = SsFullParams { capacity: 2, batch: 2 };
        let mut leaf = build_ss_full_leaf_commit(p, Expose::Interval, HIDING);
        let ups = vec![SsFullUpdate::real(9, 2), SsFullUpdate::dummy()];
        let seed = SaltSeed::for_tests(8);
        let s0 = SsFullState::empty(p);
        let r = leaf.prove_epoch_commit(1, s0.clone(), ups.clone(), &Openings::for_leaf(&seed, SS, 1));
        let fin = advanced(&s0, &ups);
        assert_eq!(r.final_, commit_ss_state_with(&fin, HIDING, &rho_state_bb(&seed, SS, 1)));
        assert_eq!(r.initial, commit_ss_state_with(&s0, HIDING, &SaltBb::ZERO));
    }
}
