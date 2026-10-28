//! GK same-value-collapse leaf (baseline): sorted union, one group-by-value pass, compaction.
//! It aggregates equal values exactly; the band-merge GK is in `gk_bandmerge`.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_permute_trace, generate_poseidon2_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Per-record `value` field range for the strict-sortedness check.
/// `value < 2^(VALUE_DIFF_BITS - 1)` so the unsigned diff
/// `value[r+1] − value[r]` fits in `VALUE_DIFF_BITS` bits.
/// BabyBear is ~31 bits, so a "negative" diff wraps to ≈ `p` which
/// won't fit — soundly rejecting the proof.
const VALUE_DIFF_BITS: usize = 22;

/// Per-tuple `count` and `max_error` field range. Every surviving `count`/
/// `max_error` (and every union input feeding a segment sum) is range-checked
/// to `< 2^(COUNT_DIFF_BITS − 1)` so it cannot approach the field size: a
/// crafted value `≈ p` (or a run-sum engineered to wrap `p` down to a small
/// residue) is rejected before it can corrupt the certified integer count.
/// Mirrors `ss_final_full::COUNT_DIFF_BITS`; the documented count domain is
/// `< 2^21`.
const COUNT_DIFF_BITS: usize = 22;

// ─── Types — same shape as gk_final.rs ───────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct GKFullTuple {
    pub value: u32,
    pub count: u32,
    pub max_error: u32,
    pub active: u32,
}

impl GKFullTuple {
    pub const fn real(value: u32, count: u32, max_error: u32) -> Self {
        Self { value, count, max_error, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { value: 0, count: 0, max_error: 0, active: 0 }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct GKFullUpdate {
    pub value: u32,
    pub active: u32,
}

impl GKFullUpdate {
    pub const fn real(value: u32) -> Self {
        Self { value, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { value: 0, active: 0 }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKFullParams {
    pub capacity: usize,
    pub batch: usize,
}

impl GKFullParams {
    pub fn union_size(&self) -> usize {
        self.capacity + self.batch
    }
    pub fn validate(&self) {
        assert!(self.capacity >= 2 && self.capacity % 2 == 0);
        assert!(self.batch >= 2 && self.batch % 2 == 0);
        assert!(
            (self.capacity + self.batch) % 2 == 0,
            "union_size must be even for Poseidon2 alignment"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GKFullState {
    pub tuples: Vec<GKFullTuple>,
    pub params: GKFullParams,
}

impl GKFullState {
    pub fn empty(params: GKFullParams) -> Self {
        Self {
            tuples: vec![GKFullTuple::dummy(); params.capacity],
            params,
        }
    }
    pub fn active_count(&self) -> usize {
        self.tuples.iter().filter(|t| t.active == 1).count()
    }
    pub fn total_mass(&self) -> u64 {
        self.tuples.iter().filter(|t| t.active == 1).map(|t| t.count as u64).sum()
    }
    pub fn rank(&self, q: u32) -> u64 {
        self.tuples
            .iter()
            .filter(|t| t.active == 1 && t.value <= q)
            .map(|t| t.count as u64)
            .sum()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKFullStateCommit(pub [Val; 8]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GKFullBatchCommit(pub [Val; 8]);

pub struct GKFullLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: GKFullStateCommit,
    pub final_: GKFullStateCommit,
    pub batch_commit: GKFullBatchCommit,
    pub params: GKFullParams,
}

pub struct GKFullProof {
    pub proof: GKFullLeafProof,
    pub final_state: GKFullState,
}

impl GKFullProof {
    pub fn rank(&self, q: u32) -> u64 {
        self.final_state.rank(q)
    }
}

// ─── Native packing helpers ──────────────────────────────────────────────

fn pack_state_to_challenge(state: &GKFullState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    state
        .tuples
        .iter()
        .map(|t| {
            let coeffs = [
                Val::from_u32(t.value),
                Val::from_u32(t.count),
                Val::from_u32(t.max_error),
                Val::from_u32(t.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn pack_batch_to_challenge(batch: &[GKFullUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    batch
        .iter()
        .map(|u| {
            // Pack B[j] in tuple-canonical form (value, count=active, 0, active)
            // so it can be PermuteAir'd directly against state tuples.
            let coeffs = [
                Val::from_u32(u.value),
                Val::from_u32(u.active), // count = active (1 if real, 0 if dummy)
                Val::ZERO,
                Val::from_u32(u.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn flat_state_vals(state: &GKFullState) -> Vec<Val> {
    state
        .tuples
        .iter()
        .flat_map(|t| {
            [
                Val::from_u32(t.value),
                Val::from_u32(t.count),
                Val::from_u32(t.max_error),
                Val::from_u32(t.active),
            ]
        })
        .collect()
}

fn flat_batch_vals(batch: &[GKFullUpdate]) -> Vec<Val> {
    batch
        .iter()
        .flat_map(|u| {
            [
                Val::from_u32(u.value),
                Val::from_u32(u.active),
                Val::ZERO,
                Val::from_u32(u.active),
            ]
        })
        .collect()
}

pub fn commit_gk_state(state: &GKFullState) -> GKFullStateCommit {
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 8] = hasher.hash_iter(flat_state_vals(state));
    GKFullStateCommit(digest)
}

pub fn commit_gk_batch(batch: &[GKFullUpdate]) -> GKFullBatchCommit {
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 8] = hasher.hash_iter(flat_batch_vals(batch));
    GKFullBatchCommit(digest)
}

// ─── Native update — same as gk_final ────────────────────────────────────

pub fn apply_update(state: &mut GKFullState, u: &GKFullUpdate) {
    if u.active == 0 {
        return;
    }
    let cap = state.params.capacity;
    let active_len = state.tuples.iter().take_while(|t| t.active == 1).count();
    let pos = state.tuples[..active_len]
        .iter()
        .position(|t| t.value >= u.value)
        .unwrap_or(active_len);

    if active_len < cap {
        for i in (pos..active_len).rev() {
            state.tuples[i + 1] = state.tuples[i];
        }
        state.tuples[pos] = GKFullTuple::real(u.value, 1, 0);
        return;
    }

    let mut min_sum = u64::MAX;
    let mut min_idx = 0usize;
    for i in 0..cap - 1 {
        let s = state.tuples[i].count as u64
            + state.tuples[i].max_error as u64
            + state.tuples[i + 1].count as u64
            + state.tuples[i + 1].max_error as u64;
        if s < min_sum {
            min_sum = s;
            min_idx = i;
        }
    }
    let merged = GKFullTuple::real(
        state.tuples[min_idx + 1].value,
        state.tuples[min_idx].count.saturating_add(state.tuples[min_idx + 1].count),
        state.tuples[min_idx]
            .max_error
            .saturating_add(state.tuples[min_idx].count)
            .max(state.tuples[min_idx + 1].max_error),
    );
    state.tuples[min_idx + 1] = merged;
    for i in min_idx..cap - 1 {
        state.tuples[i] = state.tuples[i + 1];
    }
    state.tuples[cap - 1] = GKFullTuple::dummy();

    let active_len_after = cap - 1;
    let pos = state.tuples[..active_len_after]
        .iter()
        .position(|t| t.value >= u.value)
        .unwrap_or(active_len_after);
    for i in (pos..active_len_after).rev() {
        state.tuples[i + 1] = state.tuples[i];
    }
    state.tuples[pos] = GKFullTuple::real(u.value, 1, 0);
}

// ─── Native: single-pass group-by-value collapse ────────────────────────

/// Pack a generic tuple table to Challenges (4 base coeffs per tuple:
/// value, count, max_error, active).
fn pack_union_to_challenge(tuples: &[GKFullTuple]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    tuples
        .iter()
        .map(|t| {
            let coeffs = [
                Val::from_u32(t.value),
                Val::from_u32(t.count),
                Val::from_u32(t.max_error),
                Val::from_u32(t.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

/// Witnesses for the single-pass group-by-value update certificate. The
/// circuit reconstructs the value-sorted union, the grouped table, and the
/// grouped-resorted table from the two permutations, so only the
/// permutations (plus the derived tables it binds) are surfaced. This is the
/// GK analogue of `ss_final_full::SsBuild` (group by VALUE instead of key;
/// sum count AND max_error; positional split with NO count-sort/tie-break).
#[derive(Clone)]
struct GkBuild {
    /// permutation σ_union with `union_sorted[i] = combined[σ_union[i]]`
    /// (value-sorted view).
    sigma_union: Vec<usize>,
    /// value-sorted union `(active asc, value asc)`.
    union_sorted: Vec<GKFullTuple>,
    /// grouped table `G` (length cap+m): each segment-end row carries the
    /// summed count/max_error (active iff any active contributor); the rest
    /// are dummies.
    grouped: Vec<GKFullTuple>,
    /// per-row value-adjacency tag on the value-sorted view (`tag[r]=1` iff
    /// `value_sorted[r] == value_sorted[r-1]`); `tag[0]=0`.
    value_eq_tag: Vec<u32>,
    /// permutation σ_group with `g_sorted[i] = grouped[σ_group[i]]`.
    sigma_group: Vec<usize>,
    /// `g_sorted` = grouped re-sorted by `(active asc, value asc)`.
    g_sorted: Vec<GKFullTuple>,
}

/// Build the GK single-pass group-by-value update certificate witnesses.
///
/// Mirrors `ss_final_full::build_ss` exactly, grouping by **value** (the GK
/// analogue of SS's key) and summing both `count` and `max_error` over each
/// same-value run. The final compaction is a plain positional split (no
/// count-sort, no tie-break) — GK keeps the *largest `capacity` distinct
/// values* by value order, not the top-`s` by count.
fn build_gk(s_old: &GKFullState, batch: &[GKFullUpdate]) -> GkBuild {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;

    // combined = old tuples ‖ batch-as-tuples `(value, count=active, 0, active)`.
    let mut combined: Vec<GKFullTuple> = Vec::with_capacity(total);
    for t in &s_old.tuples {
        combined.push(*t);
    }
    for u in batch {
        combined.push(GKFullTuple {
            value: u.value,
            count: u.active,
            max_error: 0,
            active: u.active,
        });
    }

    // value-sort by (active asc, value asc) — dummies first, actives ascending.
    let mut idx: Vec<usize> = (0..total).collect();
    idx.sort_by_key(|&i| (combined[i].active, combined[i].value));
    // Test-only: leave the union in `[old ‖ batch]` order so same-value rows
    // that aren't already adjacent fragment under the adjacency-only group-by.
    // The union value-sortedness (Stage 7.5) must reject it.
    #[cfg(test)]
    if TAMPER_FRAGMENT.with(|f| f.get()) {
        idx = (0..total).collect();
    }
    let sigma_union = idx.clone();
    let union_sorted: Vec<GKFullTuple> = idx.iter().map(|&i| combined[i]).collect();
    finish_gk(sigma_union, union_sorted)
}

/// Everything after the union permute — group-by-value and the grouped
/// resort — replayed from a given value-sorted union (honestly
/// `sort(S_old ‖ B)`; a soundness test may hand in a forged one).
fn finish_gk(sigma_union: Vec<usize>, union_sorted: Vec<GKFullTuple>) -> GkBuild {
    let total = union_sorted.len();

    // value-adjacency tags + running sums (count + max_error + active).
    let mut value_eq_tag = vec![0u32; total];
    let mut acc_count = vec![0u64; total];
    let mut acc_maxerr = vec![0u64; total];
    let mut acc_active = vec![0u64; total];
    for r in 0..total {
        if r > 0 && union_sorted[r].value == union_sorted[r - 1].value {
            value_eq_tag[r] = 1;
            acc_count[r] = acc_count[r - 1] + union_sorted[r].count as u64;
            acc_maxerr[r] = acc_maxerr[r - 1] + union_sorted[r].max_error as u64;
            acc_active[r] = acc_active[r - 1] + union_sorted[r].active as u64;
        } else {
            acc_count[r] = union_sorted[r].count as u64;
            acc_maxerr[r] = union_sorted[r].max_error as u64;
            acc_active[r] = union_sorted[r].active as u64;
        }
    }
    let mut seg_end = vec![0u32; total];
    for r in 0..total {
        seg_end[r] = if r + 1 == total || union_sorted[r + 1].value != union_sorted[r].value {
            1
        } else {
            0
        };
    }

    // grouped table G: segment-end rows carry the summed count/max_error; the
    // row is active iff the segment had any active contributor (acc_active>0).
    let mut grouped = vec![GKFullTuple::dummy(); total];
    for r in 0..total {
        if seg_end[r] == 1 {
            let act = if acc_active[r] > 0 { 1 } else { 0 };
            // [review probe] The circuit binds grouped.count = se·acc_count and
            // grouped.max_error = se·acc_maxerr for EVERY segment-end row,
            // regardless of `act`. Native zeroes them for dummy rows, which does
            // NOT match the circuit — so emit the RAW sums a malicious prover
            // would supply to satisfy the constraint on a count/maxerr-carrying
            // dummy grouped row. Value stays gated (grouped.value=active·union).
            #[cfg(test)]
            let (dummy_count, dummy_maxerr) = if TAMPER_DUMMY_COUNT.with(|f| f.get()) {
                (acc_count[r] as u32, acc_maxerr[r] as u32)
            } else {
                (0, 0)
            };
            #[cfg(not(test))]
            let (dummy_count, dummy_maxerr) = (0u32, 0u32);
            grouped[r] = GKFullTuple {
                value: if act == 1 { union_sorted[r].value } else { 0 },
                count: if act == 1 { acc_count[r] as u32 } else { dummy_count },
                max_error: if act == 1 { acc_maxerr[r] as u32 } else { dummy_maxerr },
                active: act,
            };
        }
    }

    // Test-only: leave a value in TWO active tuples (skip the segment collapse
    // for one same-value run: keep BOTH the run's members as active grouped
    // rows carrying their own count, instead of collapsing to one summed row).
    // The strict active value-ascent must reject the surviving duplicate.
    #[cfg(test)]
    if TAMPER_SPLIT.with(|f| f.get()) {
        // Find the first same-value ACTIVE run of length ≥ 2 and, instead of
        // one summed segment-end row + interior dummies, emit each member as
        // its own active grouped row (count/max_error un-summed).
        let mut r = 0usize;
        while r < total {
            let mut e = r;
            while e + 1 < total
                && union_sorted[e + 1].value == union_sorted[r].value
                && union_sorted[r].active == 1
            {
                e += 1;
            }
            if e > r && union_sorted[r].active == 1 {
                for k in r..=e {
                    grouped[k] = GKFullTuple {
                        value: union_sorted[k].value,
                        count: union_sorted[k].count,
                        max_error: union_sorted[k].max_error,
                        active: 1,
                    };
                }
                break;
            }
            r = e + 1;
        }
    }

    // grouped-resort by (active asc, value asc).
    let mut idx2: Vec<usize> = (0..total).collect();
    idx2.sort_by_key(|&i| (grouped[i].active, grouped[i].value));
    let sigma_group = idx2.clone();
    let g_sorted: Vec<GKFullTuple> = idx2.iter().map(|&i| grouped[i]).collect();

    GkBuild {
        sigma_union,
        union_sorted,
        grouped,
        value_eq_tag,
        sigma_group,
        g_sorted,
    }
}

// ─── Native: batched group-by-and-compact update ────────────────────────

/// Batched §5.4-style update via a **single-pass group-by-value collapse**:
/// build the union of `S_old.tuples` and `B`-as-tuples, value-sort by
/// `(active asc, value asc)`, collapse every same-value run into one tuple
/// with summed count/max_error, re-sort the grouped table, and split
/// positionally into `(s_new, excess)` where
/// - `excess` is the first `batch` rows of the grouped-resorted table
///   (dummies + the smallest few distinct values if there's overflow);
/// - `s_new` is the next `capacity` rows — the **largest `capacity`
///   distinct values** (padded with dummies on the lower side if fewer than
///   `capacity` distinct active values existed).
///
/// The single-pass group-by is GUARANTEED to fully collapse every run (it
/// sums the whole run in one shot), so the in-circuit strict value-ascent
/// canonicalization always holds for honest input — unlike the old
/// `L = ⌈log₂ M⌉`-round parity-0 schedule, which could leave an odd-position
/// duplicate un-collapsed and reject an honest proof at large `cap`.
pub fn apply_batch_full(
    s_old: &GKFullState,
    batch: &[GKFullUpdate],
) -> (GKFullState, Vec<GKFullTuple>) {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    assert_eq!(batch.len(), m);
    let b = build_gk(s_old, batch);
    let excess_tuples: Vec<GKFullTuple> = b.g_sorted[..m].to_vec();
    let s_new_tuples: Vec<GKFullTuple> = b.g_sorted[m..m + cap].to_vec();
    (
        GKFullState { tuples: s_new_tuples, params: s_old.params },
        excess_tuples,
    )
}

/// Backward-compatibility shim (retained for [`crate::experiments`] callers
/// that still take a "round count" arg). The certified transition is now a
/// **single group-by pass** with no round schedule, so the round count is
/// vestigial — this always returns `1`.
pub fn num_fusion_rounds(_total: usize) -> usize {
    1
}

// ─── Test-only soundness hooks ────────────────────────────────────────────
#[cfg(test)]
thread_local! {
    /// When set, the prover corrupts the `g_sorted` private-input table so it
    /// no longer matches the grouped-resort image. Exercises whether the
    /// resort PermuteAir + sortedness + compaction reject a bogus
    /// post-collapse table. Drives [`tests::gk_full_fusion_soundness_rejects_bad_table`].
    static TAMPER_GSORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When set, the prover leaves the union in `[old ‖ batch]` order (identity
    /// σ_union), so a value whose rows are non-adjacent fragments under the
    /// adjacency-only group-by. The union value-sortedness (Stage 7.5) must
    /// reject it. Drives [`tests::fragmentation_rejected`].
    static TAMPER_FRAGMENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When set, the prover leaves a same-value run in TWO active tuples (skips
    /// the segment collapse for one value). The strict active value-ascent must
    /// reject the surviving duplicate active value. Drives
    /// [`tests::count_split_rejected`].
    static TAMPER_SPLIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// [review probe] When set, dummy (inactive) segment-end grouped rows carry
    /// the RAW acc_count/acc_maxerr (which is what the circuit constraint
    /// `grouped.count = se·acc_count` actually requires) instead of native's 0.
    static TAMPER_DUMMY_COUNT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// ─── Prover ──────────────────────────────────────────────────────────────

/// Prove one GK update epoch with the §5.4 same-value-collapse pipeline
/// enforced in-circuit: Step 2 (union multiset via PermuteAir + value
/// range-check + non-strict value-sortedness, which forces same-value runs
/// contiguous), the **single-pass group-by-value collapse** (Step 5:
/// adjacency-tag running sums of count/max_error/active bind the grouped
/// table, then a resort PermuteAir + strict active value-ascent
/// canonicalize it), the positional compaction into `(S_new, excess)`
/// (Step 6), and combined mass conservation. A malicious prover cannot
/// fabricate values, reshuffle any table, fragment a value's run
/// (value-sortedness forces contiguity), under-fuse or count-split a run
/// (the strict active value-ascent rejects surviving duplicate active
/// values), or misbind a segment's active bit (it is derived as
/// `se·(acc_active≠0)`). The sole remaining simplification versus textbook
/// GK is the exact value-equality collapse policy (vs. band-merge of
/// different values), which keeps rank queries exact and avoids the 7-field
/// Δ tuple.
pub fn prove_gk_full(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
) -> GKFullLeafProof {
    prove_gk_full_inner(params, initial_state, batch, false)
}

/// Backward-compatibility shim (retained for [`crate::experiments`] callers).
/// The certified transition is now a **single group-by pass** with no fusion
/// round schedule, so the `_fusion_rounds` argument is vestigial and ignored
/// — this is identical to [`prove_gk_full`].
pub fn prove_gk_full_with_rounds(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
    _fusion_rounds: usize,
) -> GKFullLeafProof {
    prove_gk_full_inner(params, initial_state, batch, false)
}

/// Like [`prove_gk_full`] but also surfaces the `(initial, final)` boundary via
/// the Expose NPO, so the proof can feed the in-circuit boundary-bound forest
/// (`recursion::recursive::expose_forest`). The unexposed entry points are
/// unchanged, keeping the GK baselines stable.
pub fn prove_gk_full_exposed(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
) -> GKFullLeafProof {
    prove_gk_full_inner(params, initial_state, batch, true)
}

fn prove_gk_full_inner(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
    expose_boundary: bool,
) -> GKFullLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);
    // Single-pass group-by-value: build the union, value-sort, collapse each
    // same-value run, re-sort, and positionally split into (excess, S_new).
    let build = build_gk(&initial_state, &batch);
    prove_gk_full_build(params, initial_state, batch, &build, expose_boundary)
}

// ─── Op tag (shared-PermuteBus fix, revision Step 1) ─────────────────────
//
// The fork concatenates every `add_permute` into ONE PermuteAir whose
// PermuteBus message is the 4 value coordinates only (no op id), so the union
// permute and the grouped-resort permute only prove
// `M(S_old ⊎ B) ⊎ M(G) = M(U) ⊎ M(G_sorted)`. With honest (canonical)
// committed inputs the union mass check + the strict active value-ascent leave
// a prover no room (`tests::shared_bus_trades`: moving a row between the two
// permutes breaks one or the other), but a NON-canonical committed dummy
// `(v≠0, 0, 0, 0)` can be routed around the group-by into `S_new` — a second
// accepted `Com(S_new)` for one `(S_old, B)`. The resort domain (`grouped`,
// `g_sorted`) therefore carries `GROUPED_OP_TAG` in the `active` coordinate
// (`active + 2`): its inputs are built as `want_active + 2`, its outputs are
// de-tagged and the de-tagged flag boolean-checked, so the two permutes' element
// classes (`active ∈ {0,1}` vs `{2,3}`) are disjoint and per-class counting
// restores per-op multiset equality — no reliance on the mass/ascent argument.

/// `active`-coordinate tag of the grouped-resort permute domain.
const GROUPED_OP_TAG: u32 = 2;

/// Whether the grouped-resort permute domain is op-tagged. Always on outside
/// tests.
fn use_op_tag() -> bool {
    #[cfg(test)]
    if let Some(v) = OP_TAG.with(|c| c.get()) {
        return v;
    }
    true
}

#[cfg(test)]
thread_local! {
    /// Test-only override of [`use_op_tag`] (`Some(false)` = pre-fix circuit).
    static OP_TAG: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    /// Test-only malicious prover: `(k, tuples)` makes permute op `k` (0 =
    /// union, 1 = grouped resort) emit `tuples` in its encoding.
    static FORGE: std::cell::RefCell<Vec<(usize, Vec<GKFullTuple>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Pack a grouped-resort-domain table (`grouped`, `g_sorted`): `active` carries
/// [`GROUPED_OP_TAG`] when the op tag is on.
fn pack_grouped(tuples: &[GKFullTuple], op_tag: bool) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let tag = if op_tag { GROUPED_OP_TAG } else { 0 };
    tuples
        .iter()
        .map(|t| {
            let coeffs = [
                Val::from_u32(t.value),
                Val::from_u32(t.count),
                Val::from_u32(t.max_error),
                Val::from_u32(t.active + tag),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

/// Build, run, prove and self-verify the GK leaf for a (honest or
/// hand-crafted) group-by witness; `S_new`/`excess` are its `g_sorted` split.
fn prove_gk_full_build(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
    build: &GkBuild,
    expose_boundary: bool,
) -> GKFullLeafProof {
    prove_gk_full_build_stmt(
        params,
        initial_state,
        batch,
        build,
        Expose::from_bool(expose_boundary),
        1,
    )
}

/// Like [`prove_gk_full_exposed`] but with the **Interval** statement for
/// batch `t` (1-based): exposes `(init, final, (t, t, 0, 0), H)` with
/// `H = Poseidon2(TAG_LEAF, t, Com(B_t))` over the in-circuit batch digest.
pub fn prove_gk_full_interval(
    params: GKFullParams,
    t: u64,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
) -> GKFullLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);
    let build = build_gk(&initial_state, &batch);
    prove_gk_full_build_stmt(params, initial_state, batch, &build, Expose::Interval, t)
}

fn prove_gk_full_build_stmt(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
    build: &GkBuild,
    expose: Expose,
    t: u64,
) -> GKFullLeafProof {
    let expose_boundary = expose == Expose::Boundary;
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    let op_tag = use_op_tag();

    // ─── Native side ────────────────────────────────────────────────────
    let excess_tuples: Vec<GKFullTuple> = build.g_sorted[..m].to_vec();
    let final_state = GKFullState {
        tuples: build.g_sorted[m..m + cap].to_vec(),
        params,
    };
    let initial_commit = commit_gk_state(&initial_state);
    let final_commit = commit_gk_state(&final_state);
    let batch_commit = commit_gk_batch(&batch);

    let union_tuples = build.union_sorted.clone();
    assert_eq!(union_tuples.len(), total);
    assert_eq!(build.sigma_union.len(), total);
    assert_eq!(excess_tuples.len(), m);
    // Spot-check: final_state == g_sorted[m..m+cap], excess == g_sorted[..m].
    debug_assert_eq!(final_state.tuples.as_slice(), &build.g_sorted[m..m + cap]);
    debug_assert_eq!(excess_tuples.as_slice(), &build.g_sorted[..m]);

    // Sanity: combined mass conservation.
    // final.actives + excess.actives = init.actives + batch.actives.
    let init_mass = initial_state.total_mass();
    let batch_mass: u64 = batch.iter().map(|u| u.active as u64).sum();
    let final_mass = final_state.total_mass();
    let excess_mass: u64 = excess_tuples
        .iter()
        .filter(|t| t.active == 1)
        .map(|t| t.count as u64)
        .sum();
    assert_eq!(final_mass + excess_mass, init_mass + batch_mass);

    // ─── Build the circuit ──────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    if expose.exposes() {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    // Public inputs.
    let init_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    if expose_boundary {
        b.add_expose(&[init_pis[0], init_pis[1], final_pis[0], final_pis[1]])
            .expect("add_expose boundary");
    }
    let batch_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let grouped_tag = b.alloc_const(Challenge::from_u32(GROUPED_OP_TAG), "grouped_op_tag");

    // Private inputs (alloc order, MUST match the witness packing below):
    //   init, final(=S_new), batch, union(=value_sorted), grouped, g_sorted,
    //   excess, value_eq_tag, val_inv_diff, acc_active_inv.
    // Mirrors `ss_final_full`'s private-input set (grouped + g_sorted are
    // prover-supplied tables bound in-circuit; the inverse hints drive the
    // is-zero/is-nonzero group-by gadgets).
    let init_packed: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("init_packed")).collect();
    let final_packed: Vec<ExprId> =
        (0..cap).map(|_| b.alloc_private_input("final_packed")).collect();
    let batch_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("batch_packed")).collect();
    let union_packed: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("union_packed")).collect();
    // Grouped table G (private input, bound in-circuit from the running sums):
    // each segment-end row carries the summed count/max_error; the rest dummies.
    let grouped_packed: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("grouped_packed")).collect();
    // Grouped-resorted table `g_sorted` = σ_group image of `grouped`
    // (`(active asc, value asc)`); canonicalized + split.
    let g_sorted_packed: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("g_sorted_packed")).collect();
    // Excess: the first `batch` rows of `g_sorted` (dummies + smallest
    // distinct values on overflow). Length = batch.
    let excess_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("excess_packed")).collect();
    // Group-by adjacency tag: value_eq_tag[r] ∈ {0,1}, 1 iff value[r]==value[r-1].
    let value_eq_tag: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("value_eq_tag")).collect();
    // Inverse hint for the value-adjacency is-zero gadget (inverse of the
    // value diff when distinct, else 0).
    let val_inv_diff: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("val_inv_diff")).collect();
    // Inverse hint for the per-segment active running sum (is-nonzero gadget
    // that binds grouped.active = se·(acc_active≠0)).
    let acc_active_inv: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("acc_active_inv")).collect();

    // ─── Stage 1: Poseidon2 commit bindings ─────────────────────────────
    let h_init = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &init_packed, true)
        .expect("hash init");
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(h_final[i], final_pis[i]);
    }
    let h_batch = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(h_batch[i], batch_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (7th public input, bit-pinned:
    // no Range table here) and H = Poseidon2(TAG_LEAF, t, h_batch).
    if expose.is_interval() {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &Poseidon2Config::BABY_BEAR_D4_W16,
            &init_pis,
            &final_pis,
            &h_batch,
            zero,
            crate::sketch::bind::Binding::Semantic,
            IndexPin::Bits,
        );
    }

    // ─── Stage 2: Decompose every packed sequence ───────────────────────
    let init_fields: Vec<Vec<ExprId>> = init_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose init"))
        .collect();
    let final_fields: Vec<Vec<ExprId>> = final_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose final"))
        .collect();
    let batch_fields: Vec<Vec<ExprId>> = batch_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose batch"))
        .collect();
    let union_fields: Vec<Vec<ExprId>> = union_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose union"))
        .collect();
    // Decompose grouped + g_sorted EARLY (matches ss_final_full's Stage-2
    // ordering: the recompose that creates each packed value must be processed
    // before the PermuteAir that reads/emits it).
    let grouped_fields: Vec<Vec<ExprId>> = grouped_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose grouped"))
        .collect();
    let g_sorted_fields: Vec<Vec<ExprId>> = g_sorted_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose g_sorted"))
        .collect();
    // g_sorted is the grouped-resort permute's OUTPUT: de-tag its active flag
    // (every use below reads `gs_act`; its boolean check pins the op class).
    let gs_act: Vec<ExprId> = (0..total)
        .map(|r| {
            if op_tag {
                b.sub(g_sorted_fields[r][3], grouped_tag)
            } else {
                g_sorted_fields[r][3]
            }
        })
        .collect();

    // ─── Stage 3: Active flag boolean checks ────────────────────────────
    for r in 0..cap {
        let a = init_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);

        // Well-formedness of the committed S_old: an INACTIVE init row must be a
        // canonical all-zero dummy — `active=0 ⇒ count=0 ∧ max_error=0`. This
        // severs the malformed-preimage source directly: a dummy carrying a
        // nonzero count/max_error can no longer be opened from `init_commit` to
        // seed a count-carrying grouped dummy. (The active-gated group-by sums
        // above already annihilate such a contribution; this is the redundant
        // second barrier, and it also makes every committed dummy bit-identical.)
        let c_gated = b.mul(init_fields[r][1], a);
        b.connect(init_fields[r][1], c_gated);
        let e_gated = b.mul(init_fields[r][2], a);
        b.connect(init_fields[r][2], e_gated);

        let a = final_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    }
    for j in 0..m {
        // Batch is packed in tuple-canonical form `(value, count=active, 0, active)`.
        // The active flag is in field [3].
        let a = batch_fields[j][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);

        // Also: batch.count (field [1]) must equal batch.active (field [3]) —
        // enforces the (value, active, 0, active) layout.
        b.connect(batch_fields[j][1], batch_fields[j][3]);
        b.connect(batch_fields[j][2], zero);
    }
    for r in 0..total {
        let a = union_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);

        // g_sorted active boolean check (mirrors ss_final_full Stage 3).
        let ga = gs_act[r];
        let gam1 = b.sub(ga, one);
        let gprod = b.mul(ga, gam1);
        b.connect(gprod, zero);
    }

    // ─── Stage 4: Active flag monotonicity on final state and union ────
    // Active flags must be weakly monotone **increasing** (dummies first,
    // actives at the tail). This pairs with Stage 7.5's value-asc
    // sortedness check on the union — both are walks in the same
    // direction (left to right = small to large) which avoids the
    // dummy/active boundary issue that gating would otherwise need.
    for r in 0..cap - 1 {
        let curr = final_fields[r][3];
        let next = final_fields[r + 1][3];
        // Enforce next - curr ∈ {0, 1}: monotone increasing.
        let diff = b.sub(next, curr);
        let one_minus = b.sub(one, diff);
        let prod = b.mul(diff, one_minus);
        b.connect(prod, zero);
    }
    for r in 0..total - 1 {
        let curr = union_fields[r][3];
        let next = union_fields[r + 1][3];
        let diff = b.sub(next, curr);
        let one_minus = b.sub(one, diff);
        let prod = b.mul(diff, one_minus);
        b.connect(prod, zero);
    }

    // ─── Stage 5: Mass conservation ─────────────────────────────────────
    let mut init_mass_expr = b.mul(init_fields[0][1], init_fields[0][3]);
    for r in 1..cap {
        let term = b.mul(init_fields[r][1], init_fields[r][3]);
        init_mass_expr = b.add(init_mass_expr, term);
    }
    let mut final_mass_expr = b.mul(final_fields[0][1], final_fields[0][3]);
    for r in 1..cap {
        let term = b.mul(final_fields[r][1], final_fields[r][3]);
        final_mass_expr = b.add(final_mass_expr, term);
    }
    let mut batch_active_sum = batch_fields[0][3];
    for j in 1..m {
        batch_active_sum = b.add(batch_active_sum, batch_fields[j][3]);
    }
    let init_plus_batch = b.add(init_mass_expr, batch_active_sum);
    // NOTE: We do NOT connect `final_mass_expr == init_plus_batch` here.
    // With the batched union+compact rule, some active mass can land in
    // the `excess` table (overflow from the union). The combined
    // mass check `final_mass + excess_mass == init_plus_batch` is
    // enforced in Stage 9 below.

    // ─── Stage 6 (NEW): Union table multiset verification (Step 2) ─────
    // PermuteAir from `(init_packed ‖ batch_packed)` to `union_packed`
    // enforces multiset(combined) == multiset(union_packed). With
    // batch_packed in tuple-canonical form, the union is a proper
    // multiset union of state tuples and batch-as-tuples.
    let mut combined_input: Vec<ExprId> = Vec::with_capacity(total);
    combined_input.extend(init_packed.iter().copied());
    combined_input.extend(batch_packed.iter().copied());
    let union_permuted = b
        .add_permute(&combined_input, build.sigma_union.clone())
        .expect("add_permute (union)");
    for i in 0..total {
        b.connect(union_permuted[i], union_packed[i]);
    }

    // ─── Stage 7: Union mass conservation ──────────────────────────────
    // Σ(union.count · union.active) must equal init_mass + batch_active_sum
    // (mass identity at the union level, before any fusion compaction).
    // Since the union is a multiset of state + batch tuples, the union's
    // total count must match the input total count exactly.
    let mut union_mass_expr = b.mul(union_fields[0][1], union_fields[0][3]);
    for r in 1..total {
        let term = b.mul(union_fields[r][1], union_fields[r][3]);
        union_mass_expr = b.add(union_mass_expr, term);
    }
    b.connect(union_mass_expr, init_plus_batch);

    // ─── Stage 7.5 (NEW): Strict per-value sortedness across all of U ──
    //
    // With Stage 4 enforcing active-asc monotonicity (dummies first,
    // actives last) and Stage 6's PermuteAir tying U's multiset to
    // `(S_old ‖ B_as_tuples)`, we now enforce **strict value-asc
    // sortedness across every adjacent pair of U** by range-checking the
    // raw diff:
    //
    //   for r in 0..total-1:
    //       diff = U[r+1].value − U[r].value
    //       decompose_to_bits(diff, VALUE_DIFF_BITS)  // ⇒ diff ∈ [0, 2^N)
    //
    // The previous gated-diff design (`active[r+1] · diff → decompose_to_bits`)
    // hit a Plonky3 WitnessChecks bus over-consumption that I couldn't
    // unblock. The unblocking trick here is the convention flip: with
    // dummies at value=0 and actives at value ≥ 1, the chain is monotone
    // across the dummy→active boundary too (`diff = first_active.value > 0`),
    // so no gating is needed.
    //
    // Why this is sound (= **why the prover can't reshuffle U's actives
    // out of value order**):
    //
    //   - Stage 6: `multiset(U) = multiset(S_old ‖ B_as_tuples)` (PermuteAir).
    //   - Stage 4: `U.active` weakly monotone increasing.
    //   - Stage 7.5: `U.value` weakly monotone increasing (this stage).
    //
    // Together: the prover has no freedom in choosing U's internal order
    // — it MUST be `(active asc, value asc)`. Any non-canonical ordering
    // either breaks active monotonicity or fails the range check.
    //
    // **Value range-check (ENFORCED)**: every union `value` field must fit in
    // `VALUE_DIFF_BITS = 22` bits (`< 2^22`, and `2^22 ≤ p − 2^22` for BabyBear
    // `p ≈ 2^30.9`), so the value-diff checks below cannot be bypassed by a
    // crafted out-of-range value: a real "negative" diff (`value[r+1] <
    // value[r]`) wraps to `≈ p ≫ 2^22` and fails. Values propagate unchanged
    // through fusion (survivor keeps its value) and the resort permutation, so
    // this one check bounds every value in every round and in the final table.
    for r in 0..total {
        let _ = b
            .decompose_to_bits::<Val>(union_fields[r][0], VALUE_DIFF_BITS)
            .expect("union value range-check");
        // Bound every union count/max_error at the SOURCE to `< 2^(COUNT_DIFF_BITS−1)`
        // so no single input can approach `p`; combined with the g_sorted
        // range-check on the summed output, this forecloses the field-wrap where
        // a committed S_old count `≈ p` (plus one batch occurrence) would wrap a
        // segment sum down to a small residue and be silently accepted.
        let _ = b
            .decompose_to_bits::<Val>(union_fields[r][1], COUNT_DIFF_BITS - 1)
            .expect("union count range-check");
        let _ = b
            .decompose_to_bits::<Val>(union_fields[r][2], COUNT_DIFF_BITS - 1)
            .expect("union max_error range-check");
    }
    for r in 0..total - 1 {
        let curr = union_fields[r][0]; // value field
        let next = union_fields[r + 1][0];
        let diff = b.sub(next, curr);
        let _bits = b
            .decompose_to_bits::<Val>(diff, VALUE_DIFF_BITS)
            .expect("decompose union value diff");
    }

    // ─── Stage 7: single-pass group-by-value (Step 5) ─────────────────────
    // Mirrors `ss_final_full` Stage 5 (group-by-key), grouping by VALUE and
    // summing count AND max_error over each contiguous same-value run. The
    // union value-sortedness above forces every run contiguous, so the
    // adjacency-only tag captures whole runs. The grouped table is built as
    // ALU expressions (recompose-via-alu) — never a raw private input — so
    // every packed grouped value gets a WitnessChecks-bus creator.

    // value_eq_tag[r] ∈ {0,1}, tag[0]=0. is-zero gadget pins it to
    // `value[r] == value[r-1]` (PoneglyphDB §4.3 constraints).
    {
        let am1 = b.sub(value_eq_tag[0], one);
        let prod = b.mul(value_eq_tag[0], am1);
        b.connect(prod, zero);
    }
    b.connect(value_eq_tag[0], zero);
    // val_inv_diff[0] is unused by the r>=1 is-zero gadget (it only reads
    // val_inv_diff[r] for r>=1). Give it a real ALU-operand use so the private
    // input gets a WitnessChecks-bus creator; without this the debug builder
    // asserts "Private input … never used as an ALU operand" and every
    // in-circuit test panics at build time under `cargo test` (release masks
    // it). Use `sub` (not `mul`-by-zero, which const-folds away the operand).
    {
        let z = b.sub(val_inv_diff[0], zero);
        b.connect(z, zero);
    }
    for r in 1..total {
        let am1 = b.sub(value_eq_tag[r], one);
        let prod = b.mul(value_eq_tag[r], am1);
        b.connect(prod, zero);
        let diff = b.sub(union_fields[r][0], union_fields[r - 1][0]);
        // tag · diff = 0
        let lhs1 = b.mul(value_eq_tag[r], diff);
        b.connect(lhs1, zero);
        // (1 − tag)(1 − diff·inv) = 0
        let one_minus_tag = b.sub(one, value_eq_tag[r]);
        let diff_inv = b.mul(diff, val_inv_diff[r]);
        let one_minus = b.sub(one, diff_inv);
        let lhs2 = b.mul(one_minus_tag, one_minus);
        b.connect(lhs2, zero);
    }

    // running sums of count (field [1]), max_error (field [2]), active
    // (field [3]) over each same-value segment.
    //
    // SOUNDNESS (count/max_error are ACTIVE-GATED): each row contributes
    // `count·active` and `max_error·active`, NOT the raw field. An INACTIVE row
    // therefore adds nothing to the segment sums. This closes two canonicality
    // holes that the un-gated version had:
    //   (1) a malformed committed S_old dummy `(value=v, count=C, active=0)` no
    //       longer seeds a count-carrying grouped dummy that σ_group could route
    //       into either the final or the excess region (two S_new for one
    //       (S_old,B)); its C is annihilated → the grouped dummy is truly (0,0,0,0);
    //   (2) an inactive row sharing a value-run with an active survivor can no
    //       longer launder a stale `max_error` onto that survivor.
    // For honest chained input (dummies carry count=max_error=0) the gate is a
    // no-op, so completeness is unchanged; it matches native `build_gk`, whose
    // dummy rows also carry 0.
    let mut acc_count: Vec<ExprId> = Vec::with_capacity(total);
    let mut acc_maxerr: Vec<ExprId> = Vec::with_capacity(total);
    let mut acc_active: Vec<ExprId> = Vec::with_capacity(total);
    let c0 = b.mul(union_fields[0][1], union_fields[0][3]);
    let e0 = b.mul(union_fields[0][2], union_fields[0][3]);
    acc_count.push(c0);
    acc_maxerr.push(e0);
    acc_active.push(union_fields[0][3]);
    for r in 1..total {
        let c_act = b.mul(union_fields[r][1], union_fields[r][3]);
        let carried_c = b.mul(value_eq_tag[r], acc_count[r - 1]);
        acc_count.push(b.add(c_act, carried_c));
        let e_act = b.mul(union_fields[r][2], union_fields[r][3]);
        let carried_e = b.mul(value_eq_tag[r], acc_maxerr[r - 1]);
        acc_maxerr.push(b.add(e_act, carried_e));
        let carried_a = b.mul(value_eq_tag[r], acc_active[r - 1]);
        acc_active.push(b.add(union_fields[r][3], carried_a));
    }

    // Bind the grouped table G (private input) from the running sums. For each
    // r let `se = seg_end` indicator (`se = 1 − value_eq_tag[r+1]`, 1 for the
    // last row):
    //   grouped[r].count      = se · acc_count[r]
    //   grouped[r].max_error  = se · acc_maxerr[r]
    //   grouped[r].active     = se · (acc_active[r] ≠ 0)   (is-nonzero gadget)
    //   grouped[r].value      = active · union_value
    // Non-segment-end rows get se=0 ⇒ all-zero ⇒ dummy. Dummies (value 0)
    // form one segment whose acc_active=0 ⇒ a single dummy grouped row.
    for r in 0..total {
        let se = if r + 1 == total {
            one
        } else {
            b.sub(one, value_eq_tag[r + 1])
        };
        // grouped.count = se · acc_count  (acc_count lhs → bus creator)
        let want_count = b.mul(acc_count[r], se);
        b.connect(grouped_fields[r][1], want_count);
        // grouped.max_error = se · acc_maxerr
        let want_maxerr = b.mul(acc_maxerr[r], se);
        b.connect(grouped_fields[r][2], want_maxerr);
        // grouped.active = se·(acc_active ≠ 0) — fully DERIVED, not a free bit.
        // is-nonzero via the inverse hint: nz = acc_active·acc_active_inv, with
        // acc_active·(1−nz)=0 forcing nz = [acc_active ≠ 0] (boolean).
        let nz = b.mul(acc_active[r], acc_active_inv[r]);
        let one_minus_nz = b.sub(one, nz);
        let must_zero = b.mul(acc_active[r], one_minus_nz);
        b.connect(must_zero, zero);
        let want_active = b.mul(se, nz);
        // grouped is the resort permute's INPUT: its active coordinate carries
        // the op tag.
        let want_active_op = if op_tag {
            b.add(want_active, grouped_tag)
        } else {
            want_active
        };
        b.connect(grouped_fields[r][3], want_active_op);
        // boolean check on grouped.active.
        let am1 = b.sub(want_active, one);
        let prod = b.mul(want_active, am1);
        b.connect(prod, zero);
        // value gating: grouped.value = active · union_value.
        let want_value = b.mul(union_fields[r][0], want_active);
        b.connect(grouped_fields[r][0], want_value);
    }

    // ─── Stage 7.7: resort G → g_sorted via PermuteAir ────────────────────
    // (grouped + g_sorted decomposed early in Stage 2, mirroring ss_final_full.)
    let gs_permuted = b
        .add_permute(&grouped_packed, build.sigma_group.clone())
        .expect("add_permute (grouped resort)");
    for i in 0..total {
        b.connect(gs_permuted[i], g_sorted_packed[i]);
    }

    // ─── Stage 7.8: canonicalization on g_sorted ──────────────────────────
    // Value range-check (defense-in-depth; grouped values = active·union_value
    // are ≤ union values, already range-checked, and the resort permutes
    // them — but re-check so the strict-ascent diff below is sound). Also
    // range-check count (field [1]) and max_error (field [2]) to
    // `< 2^(COUNT_DIFF_BITS−1)`: mirrors SS's count range-check (and closes the
    // field-wrap hole — an un-gated summed count/error `≈ p` would otherwise
    // survive), and — as in SS — gives every g_sorted field an ALU-lhs use so
    // the WitnessChecks bus has a creator for it (the compaction wire-merge
    // alone leaves count/max_error uncreated otherwise).
    for r in 0..total {
        let _ = b
            .decompose_to_bits::<Val>(g_sorted_fields[r][0], VALUE_DIFF_BITS)
            .expect("g_sorted value range-check");
        let _ = b
            .decompose_to_bits::<Val>(g_sorted_fields[r][1], COUNT_DIFF_BITS - 1)
            .expect("g_sorted count range-check");
        let _ = b
            .decompose_to_bits::<Val>(g_sorted_fields[r][2], COUNT_DIFF_BITS - 1)
            .expect("g_sorted max_error range-check");
    }
    // active monotone increasing (dummies first):
    for r in 0..total - 1 {
        let diff = b.sub(gs_act[r + 1], gs_act[r]);
        let one_minus = b.sub(one, diff);
        let prod = b.mul(diff, one_minus);
        b.connect(prod, zero);
    }
    // non-strict value-asc sortedness across all adjacent pairs (dummies have
    // value 0, so the dummy→active boundary is also non-negative — no gating).
    for r in 0..total - 1 {
        let diff = b.sub(g_sorted_fields[r + 1][0], g_sorted_fields[r][0]);
        let _ = b
            .decompose_to_bits::<Val>(diff, VALUE_DIFF_BITS)
            .expect("g_sorted value sortedness");
    }
    // STRICT active value-ascent (final canonicalization). An equal adjacent
    // active pair (an un-collapsed same-value run, i.e. under-fusion or
    // count-split) has diff = 0, so gated = both_active·(diff − 1) = −1 ≈ p
    // and fails the 22-bit range check. Because the single-pass group-by sums
    // each whole run in one shot, this ALWAYS holds for honest input (no
    // odd-position-duplicate completeness gap). It forces DISTINCT active
    // values ⇒ every same-value run fully collapsed and no count-split; with
    // the union multiset conservation + derived per-run sums + mass
    // conservation, the certified S_t is the UNIQUE canonical per-value
    // aggregation of S_{t-1} ⊎ B.
    for r in 0..total - 1 {
        let both_active = b.mul(gs_act[r], gs_act[r + 1]);
        let diff = b.sub(g_sorted_fields[r + 1][0], g_sorted_fields[r][0]);
        let diff_m1 = b.sub(diff, one);
        let gated = b.mul(both_active, diff_m1);
        let _ = b
            .decompose_to_bits::<Val>(gated, VALUE_DIFF_BITS)
            .expect("strict active value-ascent (final canonicalization)");
    }

    // ─── Stage 8: Compaction binding excess ↔ g_sorted[..batch],
    //                              S_new  ↔ g_sorted[batch..] ───
    //
    // g_sorted is in `(active asc, value asc)` order (dummies first, then the
    // distinct-valued survivors in value-asc order). The first `batch` rows
    // become `excess`; the next `capacity` rows become `S_new` — the
    // **largest `capacity` distinct values** (padded with the smallest few
    // dummies if fewer than `capacity` distinct active values existed).
    //
    // We bind the **decomposed base coefficients** field-by-field (Plonky3
    // disallows connecting two packed Challenges that have both already
    // been ext-to-base decomposed — both carry recompose-coeff metadata
    // that must agree at the ExprId level).
    //
    // End-to-end soundness chain now closed:
    //   Step 2 (Stage 6): multiset(U) = multiset(S_old ‖ B_as_tuples)
    //   Sortedness (Stage 7.5): U uniquely `(active asc, value asc)` ⇒ every
    //     same-value run contiguous (no fragmentation)
    //   Group-by (Stage 7): G = per-run count/max_error sum of U (derived)
    //   Resort (Stage 7.7): multiset(g_sorted) = multiset(G)
    //   Canonicalize (Stage 7.8): g_sorted distinct-valued (no under-fusion,
    //     no count-split)
    //   Compaction (here): S_new = g_sorted[batch..], excess = g_sorted[..batch]
    // ⇒ every active tuple in S_new is the canonical per-value aggregate of
    //   rows tracing back to S_old ∪ B. No fabricated values, no fragmentation,
    //   no cherry-picking a malicious prover could exploit to inflate ranks.
    let excess_fields: Vec<Vec<ExprId>> = excess_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose excess"))
        .collect();

    for i in 0..m {
        for k in 0..3 {
            b.connect(excess_fields[i][k], g_sorted_fields[i][k]);
        }
        b.connect(excess_fields[i][3], gs_act[i]);
    }
    for i in 0..cap {
        for k in 0..3 {
            b.connect(final_fields[i][k], g_sorted_fields[m + i][k]);
        }
        b.connect(final_fields[i][3], gs_act[m + i]);
    }

    // Excess active-flag boolean check.
    for j in 0..m {
        let a = excess_fields[j][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    }

    // ─── Stage 9 (NEW): Combined mass conservation across S_new + excess ─
    // Σ(final.count·active) + Σ(excess.count·active) = init_mass + batch_active.
    // This re-derives Stage 5's mass check but extended to include the
    // overflow tuples — necessary because S_new alone may not capture
    // all the active mass (when |S_old.actives ∪ B.actives| > capacity).
    let mut excess_mass_expr = b.mul(excess_fields[0][1], excess_fields[0][3]);
    for j in 1..m {
        let term = b.mul(excess_fields[j][1], excess_fields[j][3]);
        excess_mass_expr = b.add(excess_mass_expr, term);
    }
    let combined_mass = b.add(final_mass_expr, excess_mass_expr);
    b.connect(combined_mass, init_plus_batch);

    #[allow(unused_mut)]
    let mut circuit = b.build().expect("build gk_full circuit");
    // [test-only] malicious prover: swap in forged Permute outputs.
    #[cfg(test)]
    for (k, ts) in FORGE.with(|f| f.take()) {
        let outs = if k == 0 {
            pack_union_to_challenge(&ts)
        } else {
            pack_grouped(&ts, op_tag)
        };
        crate::sketch::forge_permute::forge_permute_outputs(&mut circuit, k, outs);
    }

    // ─── Pack public + private values ───────────────────────────────────
    let initial_commit_packed =
        pack_commit_to_challenge(&crate::commitment::CountMinCommit(initial_commit.0));
    let final_commit_packed =
        pack_commit_to_challenge(&crate::commitment::CountMinCommit(final_commit.0));
    let batch_commit_packed =
        pack_commit_to_challenge(&crate::commitment::CountMinCommit(batch_commit.0));

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&initial_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    public_inputs.extend_from_slice(&batch_commit_packed);
    if expose.is_interval() {
        public_inputs.push(Challenge::from_u64(t));
    }

    // NOTE: this order MUST match the `alloc_private_input` order above:
    //   init, final, batch, union, grouped, g_sorted, excess,
    //   value_eq_tag, val_inv_diff, acc_active_inv.
    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&pack_state_to_challenge(&initial_state));
    private_inputs.extend_from_slice(&pack_state_to_challenge(&final_state));
    private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
    private_inputs.extend_from_slice(&pack_union_to_challenge(&union_tuples));
    private_inputs.extend_from_slice(&pack_grouped(&build.grouped, op_tag));
    #[allow(unused_mut)]
    let mut g_sorted_vals = pack_grouped(&build.g_sorted, op_tag);
    // [test-only] corrupt the post-collapse table to confirm the resort
    // PermuteAir + sortedness + compaction reject it.
    #[cfg(test)]
    if TAMPER_GSORTED.with(|c| c.get()) {
        use p3_field::PrimeCharacteristicRing;
        g_sorted_vals[0] += Challenge::ONE;
    }
    private_inputs.extend_from_slice(&g_sorted_vals);
    private_inputs.extend_from_slice(&pack_union_to_challenge(&excess_tuples));
    // value_eq_tag
    for &t in &build.value_eq_tag {
        private_inputs.push(if t == 1 { Challenge::ONE } else { Challenge::ZERO });
    }
    // val_inv_diff: inverse of (union_value[r] − union_value[r-1]) when
    // distinct, else 0. r=0 unused (push 0).
    {
        use p3_field::Field;
        private_inputs.push(Challenge::ZERO);
        for r in 1..total {
            let d = union_tuples[r].value as i128 - union_tuples[r - 1].value as i128;
            let inv = if d == 0 {
                Challenge::ZERO
            } else {
                let cur = Challenge::from_u64(union_tuples[r].value as u64);
                let prev = Challenge::from_u64(union_tuples[r - 1].value as u64);
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
            acc_a = if r > 0 && build.value_eq_tag[r] == 1 {
                acc_a + union_tuples[r].active as u64
            } else {
                union_tuples[r].active as u64
            };
            let inv = if acc_a == 0 { Challenge::ZERO } else { Challenge::from_u64(acc_a).inverse() };
            private_inputs.push(inv);
        }
    }

    // ─── Run + prove ────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run gk_full circuit")
    };
    let __witness = __t_w.elapsed(); // witness_gen = trace generation only

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
        .expect("get_airs_and_degrees_with_prep (gk_full)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_permute_table::<4>();
    if expose.exposes() {
        prover.register_expose_table::<4>();
    }
    let __t_p = std::time::Instant::now();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (gk_full)");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover
        .verify_all_tables(&proof)
        .expect("self-verify gk_full leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    GKFullLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
}

pub fn generate_proof(
    params: GKFullParams,
    updates: Vec<GKFullUpdate>,
) -> GKFullProof {
    params.validate();
    assert_eq!(updates.len(), params.batch);
    let initial_state = GKFullState::empty(params);
    let (final_state, _excess) = apply_batch_full(&initial_state, &updates);
    let proof = prove_gk_full(params, initial_state, updates);
    GKFullProof { proof, final_state }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_padded_batch(params: GKFullParams, active_count: usize) -> Vec<GKFullUpdate> {
        assert!(active_count <= params.batch);
        let salt = (params.capacity * params.batch) as u32;
        (0..params.batch)
            .map(|i| {
                if i < active_count {
                    GKFullUpdate::real(
                        ((i as u32).wrapping_mul(0x9E37_79B9) ^ salt) & 0x000F_FFFF,
                    )
                } else {
                    GKFullUpdate::dummy()
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
            None => format!("Rayon default pool ({} threads)", rayon::current_num_threads()),
        };
        (n, label)
    }

    fn with_pool<F: FnOnce() -> T + Send, T: Send>(n: Option<usize>, f: F) -> T {
        match n {
            None => f(),
            Some(k) => {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(k)
                    .thread_name(|i| format!("gk-full-bench-{i}"))
                    .build()
                    .expect("build rayon thread pool");
                pool.install(f)
            }
        }
    }

    #[test]
    fn gk_full_round_trip() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let updates = vec![GKFullUpdate::real(7), GKFullUpdate::real(11)];
        let result = generate_proof(params, updates);
        assert_eq!(commit_gk_state(&result.final_state).0, result.proof.final_.0);
        assert_eq!(result.final_state.total_mass(), 2);
        assert!(result.rank(11) >= 2);
    }

    /// **Group-by collapse: a repeated value verifies + collapses to ONE
    /// tuple with the summed count.** The single-pass group-by-value sums the
    /// whole same-value run in one shot; the final state carries exactly one
    /// active value-42 tuple with count 2, and the proof self-verifies.
    #[test]
    fn duplicate_values_collapse() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let updates = vec![GKFullUpdate::real(42), GKFullUpdate::real(42)];

        let result = generate_proof(params, updates);
        assert_eq!(commit_gk_state(&result.final_state).0, result.proof.final_.0);
        let actives: Vec<_> =
            result.final_state.tuples.iter().filter(|t| t.active == 1).collect();
        assert_eq!(actives.len(), 1, "the same-value run collapses to one tuple");
        assert_eq!(actives[0].value, 42);
        assert_eq!(actives[0].count, 2, "grouped count = 1 + 1");
        assert_eq!(result.final_state.total_mass(), 2);
    }

    /// **Regression: count-split is rejected (canonical collapse).** The
    /// certified transition must fully collapse every same-value run so the
    /// output is the unique per-value aggregation — a prover cannot leave a
    /// value in TWO active tuples (which would split its count and make the
    /// retained state non-deterministic). `TAMPER_SPLIT` skips the segment
    /// collapse for one value, leaving two adjacent active value-42 tuples;
    /// the strict active value-ascent (zero value-gap ⇒ gated = −1 ≈ p) must
    /// reject it.
    #[test]
    fn count_split_rejected() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let updates = vec![GKFullUpdate::real(42), GKFullUpdate::real(42)];

        // Honest: the run collapses; the proof verifies and mass is preserved.
        let ok = generate_proof(params, updates.clone());
        assert_eq!(ok.final_state.total_mass(), 2, "honest run collapses to one value-42 tuple");

        // Count-split: leave the value in two active tuples.
        TAMPER_SPLIT.with(|f| f.set(true));
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(params, updates.clone())
        }));
        TAMPER_SPLIT.with(|f| f.set(false));
        assert!(
            mal.is_err(),
            "count-split (un-collapsed duplicate active values) must be rejected by strict ascent",
        );
    }

    /// **Regression: union fragmentation is rejected.** The circuit binds the
    /// value-union to `[old ‖ batch]` only as a MULTISET permutation and groups
    /// by ADJACENCY equality. The union value-sortedness (Stage 7.5) forces
    /// every same-value run contiguous, so a prover cannot scatter a value's
    /// rows to fragment its aggregate. Leaving the union unsorted (identity
    /// σ_union) so two value-7 rows are non-adjacent must fail the value
    /// range-check / sortedness. Here old {value 7} + batch {value 3, value 7}:
    /// unsorted `[7, 3, 7]` has a descent (7→3) that wraps and is rejected.
    #[test]
    fn fragmentation_rejected() {
        let params = GKFullParams { capacity: 2, batch: 2 };
        let initial = GKFullState {
            tuples: vec![GKFullTuple::real(7, 1, 0), GKFullTuple::dummy()],
            params,
        };
        let batch = vec![GKFullUpdate::real(3), GKFullUpdate::real(7)];

        // Honest transition verifies (value-sorted union passes the checks).
        let _honest = prove_gk_full(params, initial.clone(), batch.clone());

        // Attack: leave the union unsorted so the two value-7 rows fragment.
        TAMPER_FRAGMENT.with(|f| f.set(true));
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_gk_full(params, initial.clone(), batch.clone())
        }));
        TAMPER_FRAGMENT.with(|f| f.set(false));
        assert!(
            mal.is_err(),
            "FIX REGRESSED: fragmenting the union must be rejected by value-sortedness",
        );
    }

    /// **Regression (canonicality): a malformed S_old dummy carrying a nonzero
    /// count is rejected.** Historically the group-by summed the RAW union count
    /// (not `count·active`) and never constrained `active=0 ⇒ count=0`, so an
    /// `active=0` dummy with `count=9` opened from `init_commit` seeded a
    /// count-9 *dummy* grouped row that `σ_group` could route into either the
    /// final or the excess region — two distinct S_new for one (S_old,B). Two
    /// independent barriers now reject it: (1) the init well-formedness check
    /// `active=0 ⇒ count=0 ∧ max_error=0`, and (2) the active-gated group-by
    /// sums (an inactive row contributes 0), which forces every dummy grouped
    /// row to a canonical `(0,0,0,0)`. `TAMPER_DUMMY_COUNT` additionally makes
    /// the prover *emit* the raw count on the dummy grouped row (the witness a
    /// malicious prover would supply); barrier (2) rejects that too.
    #[test]
    fn malformed_dummy_count_rejected() {
        let params = GKFullParams { capacity: 2, batch: 2 };
        let batch = vec![GKFullUpdate::real(7), GKFullUpdate::dummy()];

        // Honest counterpart: an all-zero dummy S_old proves fine.
        let honest = GKFullState {
            tuples: vec![GKFullTuple::real(5, 1, 0), GKFullTuple::dummy()],
            params,
        };
        let _ok = prove_gk_full(params, honest, batch.clone());

        // Malformed dummy: value=3, count=9, active=0.
        let malformed_dummy = GKFullTuple { value: 3, count: 9, max_error: 0, active: 0 };
        let initial = GKFullState {
            tuples: vec![GKFullTuple::real(5, 1, 0), malformed_dummy],
            params,
        };

        // Barrier (1): the malformed init alone (native zeroes dummy grouped
        // rows, so the honest witness is well-formed) must be rejected by the
        // init `active=0 ⇒ count=0` check.
        let mal_init = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_gk_full(params, initial.clone(), batch.clone())
        }));
        assert!(
            mal_init.is_err(),
            "FIX REGRESSED: a committed S_old dummy with nonzero count must be rejected",
        );

        // Barrier (2): the full malicious witness (raw count emitted on the dummy
        // grouped row) must be rejected by the active-gated group-by binding.
        TAMPER_DUMMY_COUNT.with(|f| f.set(true));
        let mal_witness = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_gk_full(params, initial.clone(), batch.clone())
        }));
        TAMPER_DUMMY_COUNT.with(|f| f.set(false));
        assert!(
            mal_witness.is_err(),
            "FIX REGRESSED: a count-carrying dummy grouped row must be rejected",
        );
    }

    /// **Regression (canonicality): max_error laundering is rejected.** An
    /// inactive row `(v=5, max_error=99, active=0)` sharing a value-run with an
    /// active survivor `(v=5, count=1, active=1)` used to have its stale
    /// `max_error=99` summed into the survivor (the group-by summed raw
    /// max_error, and max_error is in no mass identity nor range-check) — a
    /// forged per-value ε/Δ certificate with an accepting proof. The init
    /// `active=0 ⇒ max_error=0` check and the active-gated `acc_maxerr` both
    /// reject it now.
    #[test]
    fn max_error_laundering_rejected() {
        let params = GKFullParams { capacity: 2, batch: 2 };
        let batch = vec![GKFullUpdate::dummy(), GKFullUpdate::dummy()];
        let initial = GKFullState {
            tuples: vec![
                GKFullTuple { value: 5, count: 0, max_error: 99, active: 0 },
                GKFullTuple { value: 5, count: 1, max_error: 0, active: 1 },
            ],
            params,
        };
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_gk_full(params, initial.clone(), batch.clone())
        }));
        assert!(
            mal.is_err(),
            "FIX REGRESSED: an inactive row's max_error must not launder onto an active survivor",
        );
    }

    /// **Regression (field-wrap): an out-of-domain count is rejected.** Counts
    /// (union inputs and grouped survivors) are range-checked to
    /// `< 2^(COUNT_DIFF_BITS−1)`; a committed S_old count at/above the bound —
    /// which a malicious prover could pick `≈ p` so a segment sum wraps the
    /// field down to a small residue — is rejected by the union count
    /// range-check before it can corrupt the certified integer count. Mirrors
    /// `ss_final_full::count_overflow_rejected`.
    #[test]
    fn gk_count_overflow_rejected() {
        let params = GKFullParams { capacity: 2, batch: 2 };
        let batch = vec![GKFullUpdate::real(5), GKFullUpdate::dummy()];
        let over = 1u32 << (COUNT_DIFF_BITS - 1); // 2^21, out of the count domain
        let initial = GKFullState {
            tuples: vec![GKFullTuple::real(5, over, 0), GKFullTuple::dummy()],
            params,
        };
        let mal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_gk_full(params, initial.clone(), batch.clone())
        }));
        assert!(
            mal.is_err(),
            "a count ≥ 2^(COUNT_DIFF_BITS−1) must be rejected by the range-check",
        );
    }

    /// Native-side exercise of the single-pass group-by-value collapse
    /// performed by [`apply_batch_full`]. Two duplicate values in the batch
    /// should land in a single grouped tuple with `count = 2` in the final
    /// state. The total mass equals the active batch count.
    #[test]
    fn gk_full_native_fusion_round_trip() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        // Two updates with the same value — should collapse natively.
        let updates = vec![GKFullUpdate::real(42), GKFullUpdate::real(42)];

        let s0 = GKFullState::empty(params);
        let (s1, excess) = apply_batch_full(&s0, &updates);

        // After fusion: one tuple with value=42, count=2.
        let actives: Vec<_> = s1.tuples.iter().filter(|t| t.active == 1).collect();
        assert_eq!(actives.len(), 1, "exactly one active after fusing duplicates");
        assert_eq!(actives[0].value, 42);
        assert_eq!(actives[0].count, 2, "fused count = a.count + b.count");
        assert_eq!(actives[0].max_error, 0);

        // Excess is all dummies (everything fit into S_new after fusion).
        assert!(excess.iter().all(|t| t.active == 0));

        // Mass conservation across the pipeline.
        let init_mass = s0.total_mass();
        let batch_mass = updates.iter().map(|u| u.active as u64).sum::<u64>();
        let final_mass = s1.total_mass();
        let excess_mass: u64 = excess
            .iter()
            .filter(|t| t.active == 1)
            .map(|t| t.count as u64)
            .sum();
        assert_eq!(final_mass + excess_mass, init_mass + batch_mass);
    }

    /// In-circuit acceptance of Step 5 fusion: a batch with two equal
    /// values must produce a proof whose final commit reflects the fused
    /// tuple (count = 2), and the leaf self-verifies. This is the honest
    /// counterpart to `gk_full_fusion_soundness_rejects_bad_table`.
    #[test]
    fn gk_full_in_circuit_fusion_accepts() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let updates = vec![GKFullUpdate::real(99), GKFullUpdate::real(99)];
        let result = generate_proof(params, updates);
        // Proof's final commit matches the natively-fused final state.
        assert_eq!(commit_gk_state(&result.final_state).0, result.proof.final_.0);
        // The fused tuple carries the merged count.
        let actives: Vec<_> =
            result.final_state.tuples.iter().filter(|t| t.active == 1).collect();
        assert_eq!(actives.len(), 1);
        assert_eq!(actives[0].value, 99);
        assert_eq!(actives[0].count, 2);
        assert_eq!(result.final_state.total_mass(), 2);
    }

    /// Long same-value run: four copies of one value collapse in the single
    /// group-by pass into one active tuple with count = 4 (the old L-round
    /// schedule needed `⌈log₂(total)⌉ ≥ 2` rounds; the group-by sums the whole
    /// run in one shot). The proof self-verifies.
    #[test]
    fn gk_full_in_circuit_multiround_fusion() {
        let params = GKFullParams { capacity: 4, batch: 4 };
        let updates = vec![
            GKFullUpdate::real(55),
            GKFullUpdate::real(55),
            GKFullUpdate::real(55),
            GKFullUpdate::real(55),
        ];
        let result = generate_proof(params, updates);
        assert_eq!(commit_gk_state(&result.final_state).0, result.proof.final_.0);
        let actives: Vec<_> =
            result.final_state.tuples.iter().filter(|t| t.active == 1).collect();
        assert_eq!(actives.len(), 1, "all four copies must collapse into one tuple");
        assert_eq!(actives[0].value, 55);
        assert_eq!(actives[0].count, 4, "grouped count = 4 in a single pass");
        assert_eq!(result.final_state.total_mass(), 4);
    }

    /// Soundness: if a malicious prover supplies a `g_sorted` table that isn't
    /// the σ_group image of the grouped candidates, the resort PermuteAir +
    /// sortedness + compaction constraints must reject it. We flip the
    /// test-only tamper flag and assert that proving panics (self-verify fails
    /// on the WitnessChecks / lookup bus).
    #[test]
    fn gk_full_fusion_soundness_rejects_bad_table() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let updates = vec![GKFullUpdate::real(7), GKFullUpdate::real(11)];

        // Sanity: honest prove succeeds (tamper off).
        TAMPER_GSORTED.with(|c| c.set(false));
        let _ok = generate_proof(params, updates.clone());

        // Now corrupt the post-collapse table: prove must fail.
        TAMPER_GSORTED.with(|c| c.set(true));
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(params, updates)
        }));
        TAMPER_GSORTED.with(|c| c.set(false)); // reset for other tests
        assert!(
            bad.is_err(),
            "corrupted g_sorted table was accepted — group-by resort/compaction \
             constraints are not sound"
        );
    }

    #[test]
    #[ignore]
    fn gk_full_proving_time_with_different_active_counts() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = GKFullParams { capacity: 32, batch: 100 };

        println!();
        println!("gk_final_full — proving time vs. active-count density");
        println!("(now includes Step 2 union multiset verification via PermuteAir)");
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
                "  active={:>3} (of {:>3})   prove {:>10.2?}",
                active, params.batch, elapsed
            );
        }
    }

    #[test]
    #[ignore]
    fn gk_full_proving_time_merge_two_leaves() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = GKFullParams { capacity: 32, batch: 100 };

        println!();
        println!("gk_final_full — merge proving-time check");
        println!("==========================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}", params.capacity, params.batch);
        println!();

        let (l1_time, l2_time) = with_pool(threads, move || {
            let s0 = GKFullState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_gk_full(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();

            // Native batched update produces the same s1 as l1 certifies.
            let (s1, _excess) = apply_batch_full(&s0, &b1);
            assert_eq!(commit_gk_state(&s1).0, l1.final_.0);

            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let _l2 = prove_gk_full(params, s1, b2);
            (l1_time, t2.elapsed())
        });

        println!("  leaf 1 prove:       {l1_time:>10.2?}");
        println!("  leaf 2 prove:       {l2_time:>10.2?}");
        println!("  ────────────────────────────────");
        println!("  total wall-clock:   {:>10.2?}", l1_time + l2_time);
    }

    #[test]
    #[ignore]
    fn gk_full_generate_and_store_proof() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::Instant;

        let (threads, threads_label) = resolve_threads();
        let params = GKFullParams { capacity: 32, batch: 100 };
        let crate_root = env!("CARGO_MANIFEST_DIR");
        let out_dir = PathBuf::from(crate_root).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("create src/proofs directory");

        println!();
        println!("gk_final_full — generate two proofs + store to disk");
        println!("====================================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}", params.capacity, params.batch);
        println!();

        with_pool(threads, move || {
            let s0 = GKFullState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_gk_full(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();
            let proof1_bytes = postcard::to_allocvec(&l1.output.0).expect("serialize p1");
            let proof1_path = out_dir.join("gk_full_proof1.bin");
            fs::write(&proof1_path, &proof1_bytes).expect("write p1");

            let (s1, _excess) = apply_batch_full(&s0, &b1);
            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let l2 = prove_gk_full(params, s1, b2);
            let l2_time = t2.elapsed();
            let proof2_bytes = postcard::to_allocvec(&l2.output.0).expect("serialize p2");
            let proof2_path = out_dir.join("gk_full_proof2.bin");
            fs::write(&proof2_path, &proof2_bytes).expect("write p2");

            println!("  leaf 1 prove time:  {l1_time:>10.2?}");
            println!("  proof 1 size:       {:>10} bytes", proof1_bytes.len());
            println!("  leaf 2 prove time:  {l2_time:>10.2?}");
            println!("  proof 2 size:       {:>10} bytes", proof2_bytes.len());
            println!();
            println!("  proofs persisted to: {}", out_dir.display());

            // Document the new layer of verification in a sidecar.
            let mut meta = String::new();
            meta.push_str("# gk_final_full proofs — §5.4 Steps 1,2,5,6,7 in-circuit\n");
            meta.push_str("# Compared to gk_final.rs, these proofs additionally certify:\n");
            meta.push_str("#   - Union table multiset equality (S_old ‖ B as tuples) ≡ U\n");
            meta.push_str("#   - Union mass conservation (Σ active counts)\n");
            meta.push_str("#   - Active-flag monotonicity on union (dummies first, actives at tail)\n");
            meta.push_str("#   - Strict value-asc sortedness on U (Stage 7.5, range-checked diffs)\n");
            meta.push_str("#   - Step 4 band-threshold gate: e·(θ_t − merged_band) range-checked\n");
            meta.push_str("#     each fusion (θ_t = N_t, the ε=1/2 GK band)\n");
            meta.push_str("#   - Step 5 FULL L=ceil(log2(total))-round parity-0 fusion: per-round,\n");
            meta.push_str("#     per-pair eligibility + merged counts, re-sorted via a per-round\n");
            meta.push_str("#     PermuteAir, sortedness re-checked each round (Stages 7.6-7.8 looped)\n");
            meta.push_str("#   - Compaction: excess = F_sorted[..batch], S_new = F_sorted[batch..]\n");
            meta.push_str("#\n");
            meta.push_str("# All 7 §5.4 steps have an in-circuit mechanism. Step 3 (Δ_1,Δ_2 init)\n");
            meta.push_str("# is done-by-design via the 4-field tuple; the GK band-merge of DIFFERENT\n");
            meta.push_str("# values (tighter space bound, approximate rank) is the 7-field-tuple extension.\n");
            fs::write(out_dir.join("gk_full_proofs.meta.txt"), &meta)
                .expect("write meta file");
        });
    }

    // ─── Shared-PermuteBus probes (revision Step 1, Track B) ────────────────

    fn panic_msg(e: &Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "<non-string panic>".to_string()
        }
    }

    /// Malicious witness trading rows between the two permutes on the SHARED
    /// PermuteBus: the union permute emits `U' = U − {x} + {y}` and the
    /// grouped-resort permute emits `G_sorted' = G(U') − {y} + {x}` (both
    /// re-sorted); the group-by is replayed honestly from `U'`. Balances the
    /// bus iff `y ∈ G(U')`. `None` if `x ∉ U` or `y ∉ G(U')`.
    fn forge_trade(
        initial: &GKFullState,
        batch: &[GKFullUpdate],
        x: GKFullTuple,
        y: GKFullTuple,
    ) -> Option<GkBuild> {
        let honest = build_gk(initial, batch);
        let mut u = honest.union_sorted.clone();
        let pos = u.iter().position(|t| *t == x)?;
        u[pos] = y;
        u.sort_by_key(|t| (t.active, t.value));
        let mut f = finish_gk(honest.sigma_union.clone(), u);
        let gpos = f.g_sorted.iter().position(|t| *t == y)?;
        f.g_sorted[gpos] = x;
        f.g_sorted.sort_by_key(|t| (t.active, t.value));
        Some(f)
    }

    fn run_forged(
        params: GKFullParams,
        initial: &GKFullState,
        batch: &[GKFullUpdate],
        f: &GkBuild,
        tag: bool,
    ) -> std::thread::Result<GKFullLeafProof> {
        OP_TAG.with(|c| c.set(Some(tag)));
        FORGE.with(|g| *g.borrow_mut() = vec![(0, f.union_sorted.clone()), (1, f.g_sorted.clone())]);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_gk_full_build(params, initial.clone(), batch.to_vec(), f, false)
        }));
        OP_TAG.with(|c| c.set(None));
        FORGE.with(|g| g.borrow_mut().clear());
        r
    }

    fn report(label: &str, r: &std::thread::Result<GKFullLeafProof>) {
        match r {
            Ok(_) => println!("[gk_full shared bus] {label}: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[gk_full shared bus] {label}: REJECTED: {}", panic_msg(e)),
        }
    }

    /// **Shared-PermuteBus probes on the group-by GK leaf.** The union and
    /// grouped-resort permutes share one untagged PermuteBus, as in SS. Unlike
    /// SS, the direct attacks are blocked even WITHOUT an op tag:
    ///
    /// (a) SS's key-fragmentation trade (move a batch row `(K,1,0,1)` from the
    ///     union output into `G_sorted`, paying with a `(0,0,0,0)` dummy) is
    ///     REJECTED by the union mass check (Stage 7): the union loses mass 1;
    /// (b) the mass-balanced version (pay with a fabricated fresh singleton
    ///     `(u,1,0,1)`, which `G(U')` contains) re-creates a duplicate active
    ///     value in `G_sorted` and is REJECTED by the strict active value-ascent.
    ///
    /// What gets through pre-fix is (c): a NON-canonical committed batch dummy
    /// `(5,0,0,0)` (the circuit pins a batch dummy's count/max_error, not its
    /// value) is routed around the group-by (which zeroes inactive rows) into
    /// `S_new` — a second accepted `Com(S_new)` for the same `(S_old, B)`. The
    /// op tag REJECTS it (no class-{2,3} element `(5,0,0,2)` on the bus).
    #[test]
    fn shared_bus_trades() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let initial = GKFullState::empty(params);
        let k = GKFullTuple::real(42, 1, 0);
        let batch = vec![GKFullUpdate::real(42), GKFullUpdate::real(42)];

        // (a) SS-style fragmentation trade, paid with a dummy.
        let fa = forge_trade(&initial, &batch, k, GKFullTuple::dummy()).expect("trade (a)");
        let ra = run_forged(params, &initial, &batch, &fa, false);
        report("pre-fix (a) dummy-paid fragmentation", &ra);
        assert!(ra.is_err(), "union mass check must reject (a)");

        // (b) mass-balanced: paid with a fabricated fresh singleton.
        let fb = forge_trade(&initial, &batch, k, GKFullTuple::real(99, 1, 0)).expect("trade (b)");
        let rb = run_forged(params, &initial, &batch, &fb, false);
        report("pre-fix (b) singleton-paid fragmentation", &rb);
        assert!(rb.is_err(), "strict active value-ascent must reject (b)");

        // (c) a non-canonical committed dummy routed around the group-by.
        let batch_c = vec![GKFullUpdate { value: 5, active: 0 }, GKFullUpdate::real(10)];
        let _honest = prove_gk_full(params, initial.clone(), batch_c.clone());
        let (honest_final, _) = apply_batch_full(&initial, &batch_c);
        let fc = forge_trade(
            &initial,
            &batch_c,
            GKFullTuple { value: 5, count: 0, max_error: 0, active: 0 },
            GKFullTuple::dummy(),
        )
        .expect("trade (c)");
        let forged_final = GKFullState {
            tuples: fc.g_sorted[params.batch..].to_vec(),
            params,
        };
        println!(
            "[gk_full shared bus] (c) forged final {:?} vs honest {:?}",
            forged_final.tuples, honest_final.tuples
        );
        assert_ne!(commit_gk_state(&forged_final).0, commit_gk_state(&honest_final).0);
        let pre = run_forged(params, &initial, &batch_c, &fc, false);
        report("pre-fix (c) non-canonical dummy", &pre);
        assert!(pre.is_ok(), "PoC premise: the untagged circuit accepts (c)");
        let post = run_forged(params, &initial, &batch_c, &fc, true);
        report("fixed (c) non-canonical dummy", &post);
        assert!(post.is_err(), "the op tag must reject (c)");
        // (a)/(b) stay rejected under the op tag.
        assert!(run_forged(params, &initial, &batch, &fa, true).is_err());
        assert!(run_forged(params, &initial, &batch, &fb, true).is_err());
    }

    /// Cost of the op tag (padded trace rows + one prove), pre-fix vs fixed.
    /// Run: `cargo test --release --lib gk_final_full::tests::fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fix_overhead() {
        for &(cap, m) in &[(64usize, 16usize), (1024, 16)] {
            let params = GKFullParams { capacity: cap, batch: m };
            let batch = gen_padded_batch(params, m);
            for (label, tag) in [("pre-fix", false), ("op-tag", true)] {
                OP_TAG.with(|c| c.set(Some(tag)));
                let t = std::time::Instant::now();
                let _ = prove_gk_full(params, GKFullState::empty(params), batch.clone());
                OP_TAG.with(|c| c.set(None));
                println!(
                    "[gk_full fix_overhead] cap={cap} m={m} {label:<8} trace_rows={} prove+verify={:?}",
                    crate::recursion::recursive::timing::take().trace_rows,
                    t.elapsed()
                );
            }
        }
    }
}
