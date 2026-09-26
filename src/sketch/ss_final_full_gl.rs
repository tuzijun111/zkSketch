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

use std::rc::Rc;

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
        poseidon2_air_builders_d2, poseidon2_preprocessor, range_air_builders, range_preprocessor,
        recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_circuit::ops::GoldilocksD2Width8;
use p3_field::PrimeCharacteristicRing;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::config_gl::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl as ConfigWithFriParams;
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::recursion::recursive::leaf_gl::{
    DIGEST_PACKING, GlCommit, make_leaf_config, pack_commit_to_challenge,
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
/// since `2·2^KEY_DIFF_BITS < p`) and fails, forcing equal keys to be adjacent.
///
/// Goldilocks holds the whole u64 key in ONE base element (no `key_lo`/`key_hi`
/// split), so this matches the plonky2 SS leaf's single-limb `KEY_BITS = 48`
/// (`split_le(diff, 48)`), removing the BabyBear double-limb comparison penalty.
/// The only bound is `2^(KEY_DIFF_BITS+1) < p` (Goldilocks `p ≈ 2^64`), so 48 is
/// well within range.
const KEY_DIFF_BITS: usize = 48;

/// Count-sort permute-domain tags (shared-PermuteBus fix; see Stage 6): every
/// `grouped`/`g_sorted` row is `[key + GROUPED_KEY_TAG, count]`,
/// `[active, GROUPED_PAD_TAG]`. Union keys are `< 2^KEY_DIFF_BITS` and counts
/// `< 2^(COUNT_DIFF_BITS−1)`, so neither tagged cell can equal a key-sort cell
/// (`[key, count]` / `[active, 0]`) — the pad tag is far above any count.
const GROUPED_KEY_TAG: u64 = 1 << KEY_DIFF_BITS;
const GROUPED_PAD_TAG: u64 = 1 << 40;

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
pub struct SsFullStateCommit(pub [Val; 4]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SsFullBatchCommit(pub [Val; 4]);

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

/// Encode a SpaceSaving row as TWO Goldilocks (D=2) challenges, ONE field per
/// coord: `cell0 = [key, count]`, `cell1 = [active, 0]`. Fields stay RAW (no
/// `count+active·2^32` packing), so the body range-checks each exactly once with
/// NO in-circuit `decompose_to_bits`/reconstruction — the per-bit rebuild of the
/// old 1-cell packing roughly doubled the trace (see the GK note).
fn enc_row(key: u64, count: u32, active: u32) -> [Challenge; 2] {
    use p3_field::BasedVectorSpace;
    let mk = |a: u64, b: u64| {
        Challenge::from_basis_coefficients_slice(&[Val::from_u64(a), Val::from_u64(b)])
            .expect("2 coeffs")
    };
    [mk(key, count as u64), mk(active as u64, 0)]
}

/// Unpack a 2-cell row `([key, count], [active, 0])` into the 3-slot field layout
/// the body indexes: `[key, count, active]` (`key_field_of = f[0]`, count `f[1]`,
/// active `f[2]`). Each field is a RAW base coord — no split. The trailing pad
/// coord of cell1 is forced to zero (consumed to keep the WitnessChecks bus
/// balanced).
fn unpack_cell(
    b: &mut CircuitBuilder<Challenge>,
    cell0: ExprId,
    cell1: ExprId,
    pad: ExprId,
) -> Vec<ExprId> {
    let c0 = b
        .decompose_ext_to_base_coeffs::<Val>(cell0)
        .expect("decompose cell0"); // [key, count]
    let c1 = b
        .decompose_ext_to_base_coeffs::<Val>(cell1)
        .expect("decompose cell1"); // [active, pad]
    b.connect(c1[1], pad); // pad coord = 0, or the op tag (consume it)
    vec![c0[0], c0[1], c1[0]] // [key, count, active]
}

/// Unpack a flat table of cells (2 per row) into the per-row 3-slot fields;
/// `pad` is the value the trailing coordinate must hold (0 or an op tag).
fn unpack_table(b: &mut CircuitBuilder<Challenge>, cells: &[ExprId], pad: ExprId) -> Vec<Vec<ExprId>> {
    (0..cells.len() / 2)
        .map(|r| unpack_cell(b, cells[2 * r], cells[2 * r + 1], pad))
        .collect()
}

/// Expand a row-permutation to the cell-permutation that keeps each row's two
/// challenges together (`row s → cells 2s, 2s+1`).
fn expand_sigma(sigma: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(sigma.len() * 2);
    for &s in sigma {
        out.push(2 * s);
        out.push(2 * s + 1);
    }
    out
}

fn pack_state_to_challenge(state: &SsFullState) -> Vec<Challenge> {
    state
        .rows
        .iter()
        .flat_map(|r| enc_row(r.key, r.count, r.active))
        .collect()
}

fn pack_batch_to_challenge(batch: &[SsFullUpdate]) -> Vec<Challenge> {
    batch
        .iter()
        .flat_map(|u| enc_row(u.key, u.value, u.active))
        .collect()
}

/// Pack a generic (key, count, active) row table to Challenges (2 cells/row).
fn pack_rows_to_challenge(rows: &[SsFullRow]) -> Vec<Challenge> {
    rows.iter()
        .flat_map(|r| enc_row(r.key, r.count, r.active))
        .collect()
}

/// Pack a count-sort-domain table (`grouped`, `g_sorted`) in its op-tagged
/// encoding `[key + GROUPED_KEY_TAG, count]`, `[active, GROUPED_PAD_TAG]`
/// (plain encoding when `op_tag` is off).
fn pack_grouped_rows(rows: &[SsFullRow], op_tag: bool) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    if !op_tag {
        return pack_rows_to_challenge(rows);
    }
    let mk = |a: u64, b: u64| {
        Challenge::from_basis_coefficients_slice(&[Val::from_u64(a), Val::from_u64(b)])
            .expect("2 coeffs")
    };
    rows.iter()
        .flat_map(|r| {
            [
                mk(r.key + GROUPED_KEY_TAG, r.count as u64),
                mk(r.active as u64, GROUPED_PAD_TAG),
            ]
        })
        .collect()
}

fn flat_state_vals(state: &SsFullState) -> Vec<Val> {
    state
        .rows
        .iter()
        .flat_map(|r| {
            [
                Val::from_u64(r.key),
                Val::from_u32(r.count),
                Val::from_u32(r.active),
                Val::ZERO,
            ]
        })
        .collect()
}

fn flat_batch_vals(batch: &[SsFullUpdate]) -> Vec<Val> {
    batch
        .iter()
        .flat_map(|u| {
            [
                Val::from_u64(u.key),
                Val::from_u32(u.value),
                Val::from_u32(u.active),
                Val::ZERO,
            ]
        })
        .collect()
}

pub fn commit_ss_state(state: &SsFullState) -> SsFullStateCommit {
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 4] = hasher.hash_iter(flat_state_vals(state));
    SsFullStateCommit(digest)
}

pub fn commit_ss_batch(batch: &[SsFullUpdate]) -> SsFullBatchCommit {
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 4] = hasher.hash_iter(flat_batch_vals(batch));
    SsFullBatchCommit(digest)
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
    build_ss_rest(combined, sigma_key, key_sorted, key_eq_tag, seg_end, grouped, m)
}

/// Group a key-sorted table by ADJACENT equal keys (the in-circuit
/// PoneglyphDB running-sum gadget): returns `(key_eq_tag, seg_end, grouped)`.
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

/// The rest of [`build_ss`] after the group-by: test-only tampering, the
/// count-sort and `τ`.
#[allow(unused_mut)]
fn build_ss_rest(
    combined: Vec<SsFullRow>,
    sigma_key: Vec<usize>,
    key_sorted: Vec<SsFullRow>,
    key_eq_tag: Vec<u32>,
    seg_end: Vec<u32>,
    mut grouped: Vec<SsFullRow>,
    m: usize,
) -> SsBuild {
    let total = grouped.len();

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
    compress_from_gsorted(s_old.params, &b.g_sorted, b.tau)
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
    // Mergeable Misra-Gries / Frequent compression (Agarwal et al. 2012):
    // subtract the (s+1)-th largest grouped count `τ` from every retained
    // counter and clamp non-positive counters to dummies. This gives the
    // cross-batch N/s heavy-hitter *surfacing* guarantee — retained counts are
    // exact-or-under-estimates with per-key deficit ≤ N/s, so every key with
    // true frequency > N/s stays active. Because `g_sorted[m..]` is
    // count-ascending, each retained count ≥ `g_sorted[m] ≥ τ`, so the
    // saturating subtraction never truncates a real survivor and the clamped
    // (count-0) rows form the low-count prefix — final stays (active asc, count asc).
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
    (SsFullState { rows: s_new, params }, residual)
}

/// Every table the SS leaf binds. [`SsFullLeafCircuit::prove_epoch`] derives
/// it honestly from `(S_old, B)`; soundness tests hand-craft one to play a
/// malicious prover (see `tests::shared_permute_bus_forgery_rejected`).
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

/// Whether the count-sort permute domain is op-tagged (shared-PermuteBus fix).
/// Always on outside tests.
fn use_op_tag() -> bool {
    #[cfg(test)]
    if let Some(v) = OP_TAG.with(|c| c.get()) {
        return v;
    }
    true
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
    /// Test-only override of [`use_op_tag`] (`Some(false)` = pre-fix circuit).
    static OP_TAG: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
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
    /// Whether the count-sort permute domain carries the op tags
    /// ([`GROUPED_KEY_TAG`], [`GROUPED_PAD_TAG`]; the shared-PermuteBus fix).
    /// Always `true` outside tests; the soundness PoC builds the pre-fix circuit.
    op_tag: bool,
    /// The composition statement this leaf exposes.
    expose: Expose,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
}

/// Build the reusable SpaceSaving leaf circuit for a shape.
pub fn build_ss_full_leaf(params: SsFullParams, expose_boundary: bool) -> SsFullLeafCircuit {
    build_ss_full_leaf_expose(params, Expose::from_bool(expose_boundary))
}

/// Goldilocks SpaceSaving leaf with an explicit composition statement
/// ([`Expose`]); `None` / `Boundary` are byte-for-byte [`build_ss_full_leaf`],
/// `Interval` adds the batch index `t` (last public input) and exposes
/// `(init, final, (t, t), Poseidon2(TAG_LEAF, t, Com(B_t)))`.
pub fn build_ss_full_leaf_expose(params: SsFullParams, expose: Expose) -> SsFullLeafCircuit {
    let expose_boundary = expose == Expose::Boundary;
    params.validate();
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    let op_tag = use_op_tag();

    // ─── Build circuit ──────────────────────────────────────────────────
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
    let key_tag = b.alloc_const(Challenge::from_u64(GROUPED_KEY_TAG), "grouped_key_tag");
    // Pad coordinate of the count-sort domain's `[active, pad]` cell.
    let grouped_pad = if op_tag {
        b.alloc_const(Challenge::from_u64(GROUPED_PAD_TAG), "grouped_pad_tag")
    } else {
        zero
    };

    // Private inputs (alloc order MUST match the packing below). Each row is TWO
    // challenges (`[key,count]`, `[active,0]`), so the packed tables are 2× the
    // row count; the scalar hint tables (key_eq_tag, …) stay one per row.
    //   init, final(=s_new), batch, key_sorted, grouped, g_sorted,
    //   residual, key_eq_tag, key_inv_diff, acc_active_inv, c_new_inv.
    let init_packed: Vec<ExprId> = (0..2 * cap)
        .map(|_| b.alloc_private_input("init_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..2 * cap)
        .map(|_| b.alloc_private_input("final_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..2 * m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();
    let key_sorted_packed: Vec<ExprId> = (0..2 * total)
        .map(|_| b.alloc_private_input("key_sorted_packed"))
        .collect();
    let grouped_packed: Vec<ExprId> = (0..2 * total)
        .map(|_| b.alloc_private_input("grouped_packed"))
        .collect();
    let g_sorted_packed: Vec<ExprId> = (0..2 * total)
        .map(|_| b.alloc_private_input("g_sorted_packed"))
        .collect();
    let residual_packed: Vec<ExprId> = (0..2 * m)
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
    let h_init = b
        .add_hash_slice(&Poseidon2Config::GOLDILOCKS_D2_W8, &init_packed, true)
        .expect("hash init");
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = b
        .add_hash_slice(&Poseidon2Config::GOLDILOCKS_D2_W8, &final_packed, true)
        .expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(h_final[i], final_pis[i]);
    }
    let h_batch = b
        .add_hash_slice(&Poseidon2Config::GOLDILOCKS_D2_W8, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(h_batch[i], batch_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (7th public input) and
    // H = Poseidon2(TAG_LEAF, t, h_batch), exposed with the boundary.
    if expose.is_interval() {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &Poseidon2Config::GOLDILOCKS_D2_W8,
            &init_pis,
            &final_pis,
            &h_batch,
            zero,
            crate::sketch::bind::Binding::Semantic,
            IndexPin::Range,
        );
    }

    // ─── Stage 2: unpack all packed sequences to [key, count, active] ──
    let init_fields: Vec<Vec<ExprId>> = unpack_table(&mut b, &init_packed, zero);
    let final_fields: Vec<Vec<ExprId>> = unpack_table(&mut b, &final_packed, zero);
    let batch_fields: Vec<Vec<ExprId>> = unpack_table(&mut b, &batch_packed, zero);
    let key_sorted_fields: Vec<Vec<ExprId>> = unpack_table(&mut b, &key_sorted_packed, zero);
    let grouped_fields: Vec<Vec<ExprId>> = unpack_table(&mut b, &grouped_packed, grouped_pad);
    let g_sorted_fields: Vec<Vec<ExprId>> = unpack_table(&mut b, &g_sorted_packed, grouped_pad);
    // g_sorted is the count-sort permute's OUTPUT: de-tag its key (every key
    // use below reads `gs_key`). No output-side key range check is needed:
    // all `total` grouped `[key, count]` cells lie in the tagged class
    // `[2^48, 2^49)` and no key-sort OUTPUT can (union keys are range-checked
    // `< 2^48`; `[active, pad]` cells never can), so counting that class on
    // the PermuteBus forces every g_sorted `[key, count]` cell into it.
    let gs_key: Vec<ExprId> = (0..total)
        .map(|r| {
            if op_tag {
                b.sub(g_sorted_fields[r][0], key_tag)
            } else {
                g_sorted_fields[r][0]
            }
        })
        .collect();
    let residual_fields: Vec<Vec<ExprId>> = unpack_table(&mut b, &residual_packed, zero);

    // ─── Stage 3: boolean active-flag checks ────────────────────────────
    let bool_check = |b: &mut CircuitBuilder<Challenge>, a: ExprId| {
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    };
    for r in 0..cap {
        bool_check(&mut b, init_fields[r][2]);
        bool_check(&mut b, final_fields[r][2]);
        // Well-formedness of the committed S_old: an INACTIVE init row must
        // carry count 0 (`active=0 ⇒ count=0`), severing the malformed-preimage
        // source that could otherwise seed a count-carrying dummy. Mirrors the
        // GK init check and the active-gated group-by below (redundant barrier).
        let c_gated = b.mul(init_fields[r][1], init_fields[r][2]);
        b.connect(init_fields[r][1], c_gated);
    }
    for j in 0..m {
        bool_check(&mut b, batch_fields[j][2]);
        // Well-formedness of the committed batch: an INACTIVE batch row must
        // carry value 0 (`active=0 ⇒ value=0`), mirroring the init check above.
        // Without it, the D=2 encoding (which splits `active` into its own
        // permutable `[active,0]` cell) admits a malformed inactive-but-valued
        // "mass reservoir": a re-paired active cell switches it ON while
        // switching a genuine heavy hitter OFF, keeping the mass-conservation
        // identity balanced and certifying a wrong top-s (see the ss_gl
        // cell-re-pairing audit / tests::inactive_valued_batch_rejected).
        let v_gated = b.mul(batch_fields[j][1], batch_fields[j][2]);
        b.connect(batch_fields[j][1], v_gated);
    }
    for r in 0..total {
        bool_check(&mut b, key_sorted_fields[r][2]);
        bool_check(&mut b, g_sorted_fields[r][2]);
    }
    for j in 0..m {
        bool_check(&mut b, residual_fields[j][2]);
    }

    // key_field per row = key_lo + key_hi·2^32, for several tables.
    let key_field_of = |_b: &mut CircuitBuilder<Challenge>, f: &[ExprId]| -> ExprId { f[0] };

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
    for i in 0..2 * total {
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
        let _ = b
            .add_range_bits::<Val>(key_sorted_fields[r][0], KEY_DIFF_BITS)
            .expect("union key range-check");
        // Bound every union count at the SOURCE to `< 2^(COUNT_DIFF_BITS−1)` so
        // no single input can approach `p`; combined with the g_sorted count
        // range-check on the summed output, this forecloses the field-wrap where
        // a committed S_old count `≈ p` (plus one batch occurrence of the same
        // key) wraps a segment sum down to a small residue and is silently kept.
        let _ = b
            .add_range_bits::<Val>(key_sorted_fields[r][1], COUNT_DIFF_BITS - 1)
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
    let c0 = b.mul(key_sorted_fields[0][1], key_sorted_fields[0][2]);
    acc_count.push(c0);
    acc_active.push(key_sorted_fields[0][2]);
    for r in 1..total {
        let c_act = b.mul(key_sorted_fields[r][1], key_sorted_fields[r][2]);
        let carried_c = b.mul(key_eq_tag[r], acc_count[r - 1]);
        acc_count.push(b.add(c_act, carried_c));
        let carried_a = b.mul(key_eq_tag[r], acc_active[r - 1]);
        acc_active.push(b.add(key_sorted_fields[r][2], carried_a));
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
        b.connect(grouped_fields[r][1], want_count);
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
        b.connect(grouped_fields[r][2], want_active);
        bool_check(&mut b, grouped_fields[r][2]);
        // key gating: grouped.key_lo/hi = active · key_sorted.key_lo/hi
        let want_key = b.mul(key_sorted_fields[r][0], grouped_fields[r][2]);
        // grouped is the count-sort permute's INPUT: its key carries the op tag.
        let want_key_op = if op_tag { b.add(want_key, key_tag) } else { want_key };
        b.connect(grouped_fields[r][0], want_key_op);
    }

    // ─── Stage 6: count-sort G → g_sorted via PermuteAir ────────────────
    // Op tags (shared-PermuteBus fix): the fork concatenates every add_permute
    // into ONE PermuteAir whose PermuteBus message is the 2 value coordinates
    // only (no op id), so it proves only
    //   M(combined) ⊎ M(grouped) = M(key_sorted) ⊎ M(g_sorted)
    // over CELLS. Untagged, a prover could trade a row's cells between the two
    // permutes and re-fragment a key (tests::shared_permute_bus_forgery_rejected).
    // The count-sort domain is `[key + 2^48, count]`, `[active, 2^40]` (inputs
    // built so above; outputs' pad pinned by `unpack_table`), the key-sort
    // domain's outputs are `[key < 2^48, count < 2^21]`, `[active, 0]`: the
    // classes are disjoint, so counting forces per-op multiset equality.
    let cs_permuted = b
        .add_permute(
            &grouped_packed,
            (0..grouped_packed.len()).collect::<Vec<_>>(),
        )
        .expect("permute count-sort");
    for i in 0..2 * total {
        b.connect(cs_permuted[i], g_sorted_packed[i]);
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
            .add_range_bits::<Val>(g_sorted_fields[r][1], COUNT_DIFF_BITS - 1)
            .expect("g_sorted count range-check");
    }
    // active monotone increasing (dummies first):
    for r in 0..total - 1 {
        let diff = b.sub(g_sorted_fields[r + 1][2], g_sorted_fields[r][2]);
        let one_minus = b.sub(one, diff);
        let prod = b.mul(diff, one_minus);
        b.connect(prod, zero);
    }
    // count monotone increasing across all adjacent pairs (count[r+1] ≥
    // count[r]); dummies have count 0 so the dummy→active boundary is also
    // non-negative — no gating needed. We capture the diff bits to derive
    // `count[r]==count[r+1]` for the key tie-break below.
    for r in 0..total - 1 {
        let diff = b.sub(g_sorted_fields[r + 1][1], g_sorted_fields[r][1]);
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
        let gk_r = gs_key[r];
        let gk_r1 = gs_key[r + 1];
        let kdiff = b.sub(gk_r1, gk_r);
        let gated = b.mul(count_eq, kdiff);
        let _ = b
            .add_range_bits::<Val>(gated, KEY_DIFF_BITS)
            .expect("key tie-break within count-equal run");
    }

    // ─── Stage 8: compaction + Misra-Gries (s+1)-th-value subtraction ────
    // residual ↔ g_sorted[..m] (ORIGINAL counts, needed for mass accounting).
    for i in 0..m {
        b.connect(residual_fields[i][0], gs_key[i]);
        for k in 1..3 {
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
    let tau = g_sorted_fields[m - 1][1];
    for i in 0..cap {
        let src = m + i;
        // c_new = g_sorted[src].count − τ ≥ 0 (count-ascending ⇒ src.count ≥ τ).
        let c_new = b.sub(g_sorted_fields[src][1], tau);
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
        b.connect(final_fields[i][1], c_new);
        b.connect(final_fields[i][2], nz);
        let want_key = b.mul(gs_key[src], nz);
        b.connect(final_fields[i][0], want_key);
    }

    // ─── Stage 9: mass conservation ─────────────────────────────────────
    // Σ(init.count·active) + Σ(batch.value·active)
    //   = Σ(final.count·active) + Σ(residual.count·active) + capacity·τ.
    // The `capacity·τ` term is the mass the Misra-Gries subtraction deliberately
    // discards (each of the `capacity` retained slots loses exactly τ; a clamped
    // slot loses its whole count τ, a survivor loses τ of its count), so the
    // identity stays an EXACT equality rather than a bound.
    let mut init_mass_e = b.mul(init_fields[0][1], init_fields[0][2]);
    for r in 1..cap {
        let t = b.mul(init_fields[r][1], init_fields[r][2]);
        init_mass_e = b.add(init_mass_e, t);
    }
    let mut batch_mass_e = b.mul(batch_fields[0][1], batch_fields[0][2]);
    for j in 1..m {
        let t = b.mul(batch_fields[j][1], batch_fields[j][2]);
        batch_mass_e = b.add(batch_mass_e, t);
    }
    let in_mass = b.add(init_mass_e, batch_mass_e);

    let mut final_mass_e = b.mul(final_fields[0][1], final_fields[0][2]);
    for r in 1..cap {
        let t = b.mul(final_fields[r][1], final_fields[r][2]);
        final_mass_e = b.add(final_mass_e, t);
    }
    let mut res_mass_e = b.mul(residual_fields[0][1], residual_fields[0][2]);
    for j in 1..m {
        let t = b.mul(residual_fields[j][1], residual_fields[j][2]);
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
        .expect("get_airs_and_degrees_with_prep (ss_full)");
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

    SsFullLeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        op_tag,
        expose,
        batch_index: 1,
    }
}

impl SsFullLeafCircuit {
    /// Prove one epoch on the prebuilt circuit (batch index 1 under the
    /// Interval statement; see [`Self::prove_epoch_at`]).
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

    /// Prove the epoch of batch `t` (1-based); `t` is part of the Interval
    /// statement (ignored by the other layouts).
    pub fn prove_epoch_at(
        &mut self,
        t: u64,
        initial_state: SsFullState,
        batch: Vec<SsFullUpdate>,
    ) -> SsFullLeafProof {
        self.batch_index = t;
        let params = self.params;
        assert_eq!(initial_state.params, params);
        assert_eq!(batch.len(), params.batch);

        let cap = params.capacity;

        // ─── Native side ────────────────────────────────────────────────────
        let w = honest_ss_witness(&initial_state, &batch);
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
            .update_permute_witnesses(&[
                expand_sigma(&build.sigma_key),
                expand_sigma(&build.sigma_count),
            ])
            .expect("update permute witnesses (ss_full)");

        self.prove_witness(&w)
    }

    /// Pack a witness into public/private inputs, run the circuit, prove and
    /// self-verify. The Permute ops' hints must already be installed.
    fn prove_witness(&mut self, w: &SsWitness) -> SsFullLeafProof {
        let params = self.params;
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        let (initial_state, batch) = (&w.initial, &w.batch);
        let (final_state, residual_rows, build) = (&w.final_state, &w.residual, &w.build);
        let initial_commit = commit_ss_state(initial_state);
        let final_commit = commit_ss_state(final_state);
        let batch_commit = commit_ss_batch(batch);

        // ─── Pack public + private ──────────────────────────────────────────
        let init_commit_packed =
            pack_commit_to_challenge(&GlCommit(initial_commit.0));
        let final_commit_packed =
            pack_commit_to_challenge(&GlCommit(final_commit.0));
        let batch_commit_packed =
            pack_commit_to_challenge(&GlCommit(batch_commit.0));

        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&init_commit_packed);
        public_inputs.extend_from_slice(&final_commit_packed);
        public_inputs.extend_from_slice(&batch_commit_packed);
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        // MUST match alloc order.
        let mut private_inputs: Vec<Challenge> = Vec::new();
        private_inputs.extend_from_slice(&pack_state_to_challenge(initial_state));
        private_inputs.extend_from_slice(&pack_state_to_challenge(final_state));
        private_inputs.extend_from_slice(&pack_batch_to_challenge(batch));
        let key_sorted_rows: &[SsFullRow] = &build.key_sorted;
        private_inputs.extend_from_slice(&pack_rows_to_challenge(key_sorted_rows));
        private_inputs.extend_from_slice(&pack_grouped_rows(&build.grouped, self.op_tag));
        #[allow(unused_mut)]
        let mut g_sorted_vals = pack_grouped_rows(&build.g_sorted, self.op_tag);
        // [test-only] corrupt the post-retention table to confirm the
        // count-sort PermuteAir + sortedness + compaction reject it.
        #[cfg(test)]
        if TAMPER_GSORTED.with(|c| c.get()) {
            g_sorted_vals[0] += Challenge::ONE;
        }
        private_inputs.extend_from_slice(&g_sorted_vals);
        private_inputs.extend_from_slice(&pack_rows_to_challenge(residual_rows));
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

        // ─── Run + prove ────────────────────────────────────────────────────
        let __t_w = std::time::Instant::now();
        let traces = {
            let mut runner = self.circuit.runner();
            runner
                .set_public_inputs(&public_inputs)
                .expect("set_public_inputs");
            runner
                .set_private_inputs(&private_inputs)
                .expect("set_private_inputs");
            runner.run().expect("run ss_full circuit")
        };
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
            initial: initial_commit,
            final_: final_commit,
            batch_commit,
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

    /// Regression test for the D=2 `WitnessChecks` bus balance: a bare
    /// `private inputs -> add_permute -> decompose` circuit under the Goldilocks
    /// D=2 config must balance the global `WitnessChecks` bus during trace
    /// generation. This path (D=2 permute + decompose) was unexercised in the
    /// fork (proven only at D=1/D=4) and surfaced two creator-assignment bugs
    /// since fixed in `Plonky3_RangeAir` `circuit/src/circuit.rs`.
    #[test]
    fn min_permute_gl_dup_creator() {
        use std::rc::Rc;

        use p3_batch_stark::ProverData;
        use p3_circuit::CircuitBuilder;
        use p3_circuit::ops::{
            Poseidon2Config, generate_permute_trace, generate_poseidon2_trace,
            generate_recompose_trace,
        };
        use p3_circuit_prover::{
            BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
            batch_stark_prover::{
                permute_air_builders, permute_preprocessor, poseidon2_air_builders_d2,
                poseidon2_preprocessor, recompose_air_builders, recompose_preprocessor,
            },
            common::get_airs_and_degrees_with_prep,
        };
        use p3_field::PrimeCharacteristicRing;
        use p3_uni_stark::StarkGenericConfig;

        let n = 4usize;
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
            make_perm(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_permute(generate_permute_trace::<Val, Challenge>);
        let a: Vec<ExprId> = (0..n).map(|_| b.alloc_private_input("a")).collect();
        // Hash the inputs so the poseidon2 table is non-empty (as in SS).
        let h = b
            .add_hash_slice(&Poseidon2Config::GOLDILOCKS_D2_W8, &a, true)
            .expect("hash");
        let hp: Vec<ExprId> = (0..h.len()).map(|_| b.alloc_public_input("h")).collect();
        for i in 0..h.len() {
            b.connect(h[i], hp[i]);
        }
        // Permute a -> out (identity), connect to a separate private-input table.
        let perm = b
            .add_permute(&a, (0..n).collect::<Vec<_>>())
            .expect("permute");
        // Decompose the permute output + input and consume coeffs in ALU ops.
        for &c in a.iter().chain(perm.iter()) {
            let f = b
                .decompose_ext_to_base_coeffs::<Val>(c)
                .expect("decompose cell");
            let s = b.add(f[0], f[1]);
            let _ = b.mul(s, s);
        }
        let mut circuit = b.build().expect("build");
        // Install the real permutation (identity here) + compute output values,
        // exactly as SS's prove_epoch does. Without this the permute outputs are 0.
        circuit
            .update_permute_witnesses(&[(0..n).collect::<Vec<usize>>()])
            .expect("update permute witnesses");

        let config = make_leaf_config();
        let tp = TablePacking::new(1, 2).with_fri_params(6, LOG_BLOWUP);
        let preps = vec![
            poseidon2_preprocessor::<Val>(),
            recompose_preprocessor::<Val>(false),
            permute_preprocessor::<Val>(),
        ];
        let mut air_builders = poseidon2_air_builders_d2::<ConfigWithFriParams>();
        air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 2>(1, false));
        air_builders.extend(permute_air_builders::<ConfigWithFriParams, 2>(1));
        let (airs_degrees, pc, npc) = get_airs_and_degrees_with_prep::<
            ConfigWithFriParams,
            Challenge,
            2,
        >(&circuit, &tp, &preps, &air_builders, ConstraintProfile::Standard)
        .expect("airs");
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let cpd = CircuitProverData::new(prover_data, pc, npc);
        let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(tp);
        prover.register_poseidon2_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8);
        prover.register_recompose_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8.d() != 2);
        prover.register_permute_table::<2>();

        // a = [0, 0, 5, 7] (two dummy/zero cells); identity permute -> out = a.
        let vals = [
            Challenge::ZERO,
            Challenge::ZERO,
            Challenge::from_u64(5),
            Challenge::from_u64(7),
        ];
        let mut hasher_in: Vec<Val> = Vec::new();
        for v in &vals {
            use p3_field::BasedVectorSpace;
            hasher_in.extend(<Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(v));
        }
        let digest: [Val; 4] = MyHash::new(make_perm()).hash_iter(hasher_in);
        let hp_vals = pack_commit_to_challenge(&GlCommit(digest));

        let mut runner = circuit.runner();
        runner.set_public_inputs(&hp_vals).expect("set pub");
        let mut priv_in: Vec<Challenge> = Vec::new();
        priv_in.extend_from_slice(&vals); // a
        runner.set_private_inputs(&priv_in).expect("set priv");
        let traces = runner.run().expect("run min permute circuit");
        let proof = prover.prove_all_tables(&traces, &cpd).expect("prove");
        prover.verify_all_tables(&proof).expect("verify");
    }

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

    /// **Regression (cell-re-pairing / mass-reservoir defense).** In the D=2
    /// encoding the `active` flag lives in its own permutable `[active,0]` cell,
    /// so a malicious `σ_key` can swap active flags between rows. The attack
    /// needs a malformed inactive-but-valued batch row `(key, value>0, active=0)`
    /// as a "mass reservoir" (switch it ON, a real hitter OFF, mass stays
    /// balanced). The batch `active=0 ⇒ value=0` well-formedness check rejects
    /// the reservoir at commit time, closing the attack.
    #[test]
    fn inactive_valued_batch_rejected() {
        let params = SsFullParams {
            capacity: 2,
            batch: 2,
        };
        let initial = SsFullState {
            rows: vec![SsFullRow::real(100, 50), SsFullRow::dummy()],
            params,
        };
        // Malformed: an inactive row carrying value 50 (the reservoir).
        let batch = vec![
            SsFullUpdate {
                key: 200,
                value: 50,
                active: 0,
            },
            SsFullUpdate {
                key: 0,
                value: 0,
                active: 0,
            },
        ];
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_ss_full(params, initial.clone(), batch.clone())
        }));
        std::panic::set_hook(prev);
        assert!(
            mal.is_err(),
            "malformed inactive-but-valued batch row must be rejected (active=0 ⇒ value=0)"
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

    // ─── Malicious-prover probe: shared PermuteBus (revision Step 1) ────────

    fn panic_msg(e: &Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "<non-string panic>".to_string()
        }
    }

    /// Malicious witness exploiting the SHARED PermuteBus (the BabyBear SS
    /// attack, on D=2 cells): move union row `x` (both its cells) out of the
    /// key-sort permute's output and into the count-sort permute's output,
    /// paying with an all-zero dummy row moved the other way. Everything
    /// downstream (group-by, count-sort order, τ, compression) is recomputed
    /// honestly from the forged tables.
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
        let mut ks = combined.clone();
        let pos = ks.iter().position(|r| *r == x).expect("x must be a union row");
        ks[pos] = SsFullRow::dummy();
        ks.sort_by_key(|r| key_field(r.key));
        let (key_eq_tag, seg_end, grouped) = group_by_key(&ks);
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
        let ks = pack_rows_to_challenge(&w.build.key_sorted);
        let gs = pack_grouped_rows(&w.build.g_sorted, leaf.op_tag);
        crate::sketch::forge_permute::forge_permute_outputs(&mut leaf.circuit, 0, ks);
        crate::sketch::forge_permute::forge_permute_outputs(&mut leaf.circuit, 1, gs);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| leaf.prove_witness(w)))
    }

    /// **Shared-PermuteBus forgery (key fragmentation through the bus), D=2.**
    /// batch = [K, K] into an empty capacity-4 summary. Honest final: {K:2}.
    /// Forged: the key-sort output drops one (K,1) row for a dummy; the
    /// count-sort output takes that row instead of a dummy grouped row — final
    /// {K:1, K:1}. Pre-fix circuit: ACCEPTED. With the count-sort domain's
    /// `[key+2^48, count]`/`[active, 2^40]` tags: REJECTED (the moved cells
    /// have no matching element on the PermuteBus).
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
            commit_ss_state(&honest_final)
        );

        OP_TAG.with(|c| c.set(Some(false)));
        let pre = prove_forged_cross_permute(params, &forged);
        OP_TAG.with(|c| c.set(None));
        match &pre {
            Ok(_) => println!("[ss_gl shared bus] pre-fix: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[ss_gl shared bus] pre-fix: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the untagged circuit accepts the forgery");

        let post = prove_forged_cross_permute(params, &forged);
        match &post {
            Ok(_) => println!("[ss_gl shared bus] fixed: forged final ACCEPTED"),
            Err(e) => println!("[ss_gl shared bus] fixed: REJECTED: {}", panic_msg(e)),
        }
        assert!(post.is_err(), "op tags must stop the two permutes trading cells");
    }

    /// Cost of the op tags (padded trace rows + one prove), pre-fix vs fixed.
    /// Run: `cargo test --release --lib ss_final_full_gl::tests::fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fix_overhead() {
        for &(cap, m) in &[(64usize, 16usize), (1024, 16)] {
            let params = SsFullParams { capacity: cap, batch: m };
            let batch = gen_padded_batch(params, m);
            for (label, tag) in [("pre-fix", false), ("op-tag", true)] {
                OP_TAG.with(|c| c.set(Some(tag)));
                let mut leaf = build_ss_full_leaf(params, false);
                OP_TAG.with(|c| c.set(None));
                let t = std::time::Instant::now();
                let _ = leaf.prove_epoch(SsFullState::empty(params), batch.clone());
                println!(
                    "[ss_gl fix_overhead] cap={cap} m={m} {label:<8} trace_rows={} prove+verify={:?}",
                    leaf.trace_rows,
                    t.elapsed()
                );
            }
        }
    }
}
