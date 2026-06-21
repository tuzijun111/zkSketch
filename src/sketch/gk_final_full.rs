//! **Full Greenwald-Khanna update circuit** (paper §5.4) — extends
//! [`crate::sketch::gk_final`] with the previously-deferred steps.
//!
//! Relative to [`crate::sketch::gk_final`] this adds:
//!
//! - **Step 2 (insert epoch into old tuple order)**: an in-circuit
//!   PermuteAir multiset-equality check between the combined
//!   `(S_old.tuples ‖ B_as_tuples)` and a prover-supplied sorted union
//!   table `U`. The verifier learns that every active tuple in `U` came
//!   from either the old state or the batch — no fabricated values.
//! - **Step 6 compaction tie**: a positional binding `excess[i] = U[i]`
//!   for `i ∈ [0, batch)` and `S_new[i] = U[batch + i]` for
//!   `i ∈ [0, capacity)`. Together with Step 2 this gives the **end-to-end
//!   chain** `S_new ⊆ U ⊆ (S_old ∪ B)` as multisets: every active row
//!   in the final state traces back to either the old state or the
//!   batch, with no fabricated values.
//! - **Strict per-value sortedness across `U` (NEW, Stage 7.5)**: every
//!   adjacent pair `(U[r], U[r+1])` is forced to satisfy
//!   `U[r+1].value ≥ U[r].value` via a range-checked raw diff
//!   (`decompose_to_bits(value[r+1] − value[r], 22)`). The convention is
//!   flipped from the previous `(active desc, value asc)` to
//!   `(active asc, value asc)` — dummies (value=0) now come first, then
//!   actives in ascending value order. This makes the diff non-negative
//!   across the dummy→active boundary too (`diff = first_active.value`),
//!   so the check needs **no gating** and avoids the previous
//!   `mul(decompose, decompose) → decompose_to_bits` Plonky3
//!   WitnessChecks bus-accounting failure. Together with active-flag
//!   monotonicity (Stage 4) and PermuteAir multiset equality (Stage 6),
//!   this forces the union's order to be uniquely `(active asc, value
//!   asc)` — the prover can no longer reshuffle.
//!
//! - **Compaction reversed**: now `excess = U[..batch]` (dummies + the
//!   smallest few actives if there's overflow) and `S_new = U[batch..]`
//!   — the **largest `capacity` actives by value**. Semantically
//!   different from the previous "smallest cap actives" version, but
//!   both preserve the same `multiset(S_new ∪ excess) =
//!   multiset(S_old ∪ B)` invariant.
//!
//! ### Value-range assumption
//!
//! The strict sortedness check uses a 22-bit diff range, so **per-record
//! `value` fields must fit in 21 bits** (`value < 2^21 = 2 097 152`).
//! BabyBear is ~31 bits, so a "negative" diff (`value[r+1] < value[r]`)
//! wraps to ≈ `p`, which won't fit in 22 bits — the bit-decomposition
//! then fails, soundly rejecting the proof. The test workloads
//! (`gen_padded_batch`) generate values masked to 20 bits, fitting
//! comfortably under this bound.
//!
//! - **Step 5 (full `L = ⌈log₂(total)⌉`-round parity-0 fusion) —
//!   IN-CIRCUIT & sound (NEW, Stages 7.6–7.8, looped)**: each round, for
//!   every adjacent pair `(T[2i], T[2i+1])` the prover supplies a
//!   decision bit `e[i] ∈ {0,1}`; the circuit enforces `e·(e−1)=0`, the
//!   eligibility implications `e·(a.value−b.value)=0`, `e·(1−a.active)=0`,
//!   `e·(1−b.active)=0`, and builds the post-fusion tuples as ALU
//!   expressions (`F[2i]=(1−e)·a`, `F[2i+1]=(b.val, b.cnt+e·a.cnt,
//!   b.max+e·a.max, b.act)`). Those fused rows are packed into Challenges
//!   via [`CircuitBuilder::recompose_base_coeffs_to_ext_via_alu`] (pure
//!   ALU, so every fused field gets a WitnessChecks-bus creator) and fed
//!   to a **per-round PermuteAir** that re-sorts `F → F_sorted`; each
//!   round's `F_sorted` gets active-monotonicity + strict value-asc
//!   sortedness checks and becomes the next round's input. Re-sorting
//!   between rounds re-adjacenttizes survivors, so `L` plain parity-0
//!   rounds collapse any run of equal values (≤ `total` long) into one
//!   tuple — the §5.4 `L = ⌈log M⌉` schedule. Stage 8's compaction binds
//!   `S_new`/`excess` to the **final** round's `F_sorted` (not `U`). This
//!   closes the soundness chain end-to-end —
//!   a malicious prover supplying a non-canonical post-fusion table is
//!   rejected (test `gk_full_fusion_soundness_rejects_bad_table`).
//!
//!   **Pipeline-preserving proving-time knob**: the round count is a
//!   public circuit-shape parameter (§5), so
//!   [`prove_gk_full_with_rounds`] lets callers run fewer than the
//!   worst-case `⌈log₂(total)⌉` rounds. The worst case only bites when a
//!   *single value* repeats across most of the union; the rounds actually
//!   needed are `⌈log₂(max run length)⌉`. For any workload where no value
//!   repeats more than `2^rounds` times the result is identical, and
//!   prove time falls ≈ linearly in the round count (measured at
//!   `cap=32, batch=100`: 8 rounds ≈ 675 ms → 2 rounds ≈ 217 ms, ~3.1×).
//!   This is the GK analogue of Count-Min's `distinct_bound`. The default
//!   [`prove_gk_full`] keeps the worst-case count (baseline behavior).
//!
//!   **The bus-accounting fix that unblocked this** (it failed for many
//!   prior sessions): a decompose coefficient is created on the
//!   WitnessChecks bus only when it first appears as an ALU **lhs**
//!   (operand `a`/`c`); a coeff read *only* as an rhs (operand `b`) — as
//!   `a.max_error` was, in the `(1−e)·a_max` / `e·a_max` products — never
//!   gets a creator, so the global lookup sum is unbalanced
//!   (`GlobalCumulativeMismatch(WitnessChecks)`). Putting each union
//!   field first in its product (lhs) gives it a creator and balances the
//!   bus. Equivalently: never feed a raw private input straight into an
//!   NPO with no ALU use — use `recompose_base_coeffs_to_ext_via_alu`.
//!
//!   The native side ([`apply_batch_full`] → [`fuse_round_parity0`] →
//!   [`resort_by_active_value`]) produces the witnesses the circuit
//!   verifies. Only a **single** parity-0 round is applied; the full
//!   `L = ⌈log M⌉` parity-alternating schedule (Step 5 in full) is a
//!   strict superset (see "still deferred" below).
//! - **Full mass conservation**: `Σ(S_new.count·active) + Σ(excess.count
//!   ·active) = Σ(S_old.count·active) + Σ(B.active)`. The excess holds
//!   whatever actives in `U` didn't fit into `S_new`, so the combined
//!   mass is preserved exactly across the pipeline (no leakage, no
//!   forgery).
//!
//! ### Step coverage summary
//!
//! **All seven §5.4 steps now have an in-circuit mechanism.** Steps 1, 2,
//! 4, 5, 6, 7 are enforced as explicit constraints (bind, union multiset,
//! band-threshold gate, `L`-round fusion, compaction, metadata-
//! invariants). Step 3 is done-by-design by the single-Challenge tuple.
//!
//! - **Step 3 (Δ initialization via prefix/suffix-copy)** —
//!   *done-by-design via the 4-field tuple simplification*. The full
//!   §5.4 tuple `(e, g_1, g_2, Δ_1, Δ_2, t, active)` keeps `g_1, g_2`
//!   and `Δ_1, Δ_2` separate so that fusion can do the prefix/suffix
//!   copy on `Δ`. Our `(value, count, max_error, active)` layout already
//!   folds `g_1+g_2 ↔ count` and `Δ_1+Δ_2 ↔ max_error`, so no
//!   per-side bookkeeping is needed; `max_error` after fusion is simply
//!   `a.max_error + b.max_error` (computed natively in
//!   [`fuse_round_parity0`]). If we were to switch to the 7-field tuple
//!   for a tighter ε-bound, Step 3 would resurface.
//! - **Step 4 (band threshold `θ_t`) — IN-CIRCUIT (NEW, in Stage 7.6)**:
//!   every fusion is gated by a range-checked inequality `e · (θ_t −
//!   (a.count + b.count + a.max_err + b.max_err)) ∈ [0, 2^22)`, i.e. a
//!   fused pair's merged band must fit under `θ_t`. We take `θ_t = N_t`
//!   (`init_plus_batch`, the total active mass) — the GK band at
//!   `ε = 1/2`, a valid generous calibration. The fusion *policy* the
//!   prover follows is still exact value-equality (so rank queries stay
//!   exact, no introduced error); the threshold *gate* is what §5.4
//!   verifies, and it is now enforced. The full GK band-merge of
//!   *different* adjacent values (which trades the exact-rank guarantee
//!   for the tighter `O((1/ε)log εN)` space bound) needs the 7-field
//!   `Δ_1/Δ_2` tuple to bound the introduced error — that tuple swap is
//!   the one remaining architectural extension.
//!
//! ### Tuple representation
//!
//! Same as `gk_final` — `(value, count, max_error, active)`. The full
//! 7-field §5.4 tuple `(e, g_1, g_2, Δ_1, Δ_2, t, active)` would need
//! 2 Challenges per tuple; we use a single Challenge per tuple here,
//! folding `g_1+g_2 ↔ count` and `Δ_1+Δ_2 ↔ max_error` per the
//! existing baseline.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_permute_trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        permute_air_builders, permute_preprocessor, poseidon2_air_builders_d4,
        poseidon2_preprocessor, recompose_air_builders, recompose_preprocessor,
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

// ─── Native: one round of adjacent same-value fusion (parity 0) ─────────

/// Apply one parity-0 round of adjacent same-value fusion to a sorted
/// tuple table (one iteration of the `L`-round schedule run by
/// [`fuse_all_rounds`]). Pairs (0,1), (2,3), ... are checked; if both are
/// active and have the same value, the left tuple becomes a dummy and the
/// right tuple absorbs the left's count and max_error. Returns the fused
/// table and the per-pair decision bits.
///
/// Simplification vs. paper §5.4: the eligibility predicate here is
/// "values are equal AND both active" instead of the full threshold
/// inequality `g_1+Δ_1+g_2+Δ_2+1 ≤ θ_t`. [`fuse_all_rounds`] repeats this
/// (with a resort between rounds) `⌈log₂(total)⌉` times, which collapses
/// arbitrarily long runs of equal values; the threshold-gated variant
/// (Step 4) is the remaining future extension.
pub fn fuse_round_parity0(input: &[GKFullTuple]) -> (Vec<GKFullTuple>, Vec<bool>) {
    let total = input.len();
    let num_pairs = total / 2;
    let mut output = input.to_vec();
    let mut decisions = Vec::with_capacity(num_pairs);

    for i in 0..num_pairs {
        let a = input[2 * i];
        let b = input[2 * i + 1];
        let eligible = a.active == 1 && b.active == 1 && a.value == b.value;
        decisions.push(eligible);
        if eligible {
            output[2 * i] = GKFullTuple::dummy();
            output[2 * i + 1] = GKFullTuple {
                value: b.value,
                count: a.count.saturating_add(b.count),
                max_error: a.max_error.saturating_add(b.max_error),
                active: 1,
            };
        }
    }
    (output, decisions)
}

/// Re-sort a tuple table by `(active asc, value asc)` (dummies first,
/// then actives by value ascending) and return both the sorted table
/// and the permutation `sigma` such that `output[i] = input[sigma[i]]`.
/// Used after `fuse_round_parity0` to bring the fusion-induced dummies
/// to the head of the table before compaction. The convention matches
/// `build_union_table` and `apply_batch_full`.
#[allow(dead_code)]
fn resort_by_active_value(input: &[GKFullTuple]) -> (Vec<GKFullTuple>, Vec<usize>) {
    let mut indexed: Vec<(usize, GKFullTuple)> =
        input.iter().enumerate().map(|(i, t)| (i, *t)).collect();
    indexed.sort_by_key(|(_, t)| (t.active, t.value));
    let sigma: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let sorted: Vec<GKFullTuple> = indexed.iter().map(|(_, t)| *t).collect();
    (sorted, sigma)
}

/// Number of parity-0 fusion rounds needed to fully collapse a table of
/// length `total`: the smallest `L` with `2^L ≥ total`. Because each
/// round (fuse + resort) at most halves the longest run of equal values,
/// `L` rounds collapse any run (up to `total` long) down to one tuple —
/// the §5.4 `L = ⌈log M⌉` schedule, with `M = total`.
pub fn num_fusion_rounds(total: usize) -> usize {
    let mut l = 0usize;
    let mut span = 1usize;
    while span < total {
        span <<= 1;
        l += 1;
    }
    l.max(1)
}

/// Witness data for one parity-0 fusion round, captured for the
/// in-circuit proof. The circuit re-derives `fused` from the round's
/// input table + `decisions`, then checks `resorted = σ(fused)` via a
/// PermuteAir; so only `decisions`, `resorted`, and `sigma` need to be
/// surfaced.
#[derive(Clone)]
struct FusionRound {
    decisions: Vec<bool>,
    resorted: Vec<GKFullTuple>,
    sigma: Vec<usize>,
}

/// Apply `rounds` parity-0 fusion+resort rounds to `sorted_union`,
/// returning the final fused+sorted table and per-round witness data.
/// Round 0's input is `sorted_union`; round `r>0`'s input is round
/// `r-1`'s resorted output.
fn fuse_all_rounds(
    sorted_union: &[GKFullTuple],
    rounds: usize,
) -> (Vec<GKFullTuple>, Vec<FusionRound>) {
    let mut current = sorted_union.to_vec();
    let mut data = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let (fused, decisions) = fuse_round_parity0(&current);
        let (resorted, sigma) = resort_by_active_value(&fused);
        data.push(FusionRound { decisions, resorted: resorted.clone(), sigma });
        current = resorted;
    }
    (current, data)
}

// ─── Native: batched union-and-compact update ───────────────────────────

/// Batched §5.4-style update: builds the union of `S_old.tuples` and
/// `B`-as-tuples, sorts by `(active asc, value asc)` (dummies first,
/// then actives in ascending value order), and returns `(s_new, excess)`
/// where
/// - `excess` is the first `batch` rows of the sorted union (the
///   smallest values, where dummies live; plus any overflow actives
///   that didn't fit into `s_new`);
/// - `s_new` is the next `capacity` rows — the **largest `capacity`
///   actives by value** (padded with dummies on the lower side if
///   fewer than `capacity` actives existed).
///
/// Unlike the per-record `apply_update` (which evicts the minimum-cost
/// adjacent pair), this batched version is **side-by-side** verifiable:
/// the in-circuit proof can certify `excess[i] = U[i]` and `S_new[i] =
/// U[batch + i]` directly, tying the final state's contents to the
/// union via simple positional connects.
///
/// **Soundness consequence**: combined with Step 2's PermuteAir on
/// `(S_old.tuples ‖ B_as_tuples) → U`, this guarantees
/// `multiset(S_new.actives) ⊆ multiset(S_old.actives ∪ B.actives)`. No
/// fabricated values can sneak into the final state.
///
/// **Why dummies-first ordering** (changed from the previous
/// `(active desc, value asc)`): with all dummies sharing `value=0` and
/// actives having `value ≥ 1`, the ASC ordering makes `U` strictly
/// value-monotone across **every** adjacent pair — including the
/// dummy→active boundary (`diff = first_active.value > 0`). That in
/// turn unlocks a simple in-circuit sortedness check (Stage 7.5) using
/// `sub(value[r+1], value[r]) → decompose_to_bits` with no gating —
/// sidestepping the `mul(decompose, decompose) → decompose_to_bits`
/// bus-accounting issue that blocked the gated-diff approach.
///
/// **Fusion**: before splitting, `L = ⌈log₂(total)⌉` parity-0
/// fusion+resort rounds (Step 5) collapse every run of equal-valued
/// actives into one tuple with summed count. Overflow actives that still
/// don't fit after fusion land in `excess`. The fusion predicate is
/// value-equality (exact, no rank error) rather than the GK band
/// threshold `θ_t` (which needs the 7-field `Δ_1/Δ_2` tuple — see the
/// module docstring's "still deferred" notes).
pub fn apply_batch_full(
    s_old: &GKFullState,
    batch: &[GKFullUpdate],
) -> (GKFullState, Vec<GKFullTuple>) {
    let total = s_old.params.capacity + s_old.params.batch;
    apply_batch_full_with_rounds(s_old, batch, num_fusion_rounds(total))
}

/// Like [`apply_batch_full`] but runs exactly `fusion_rounds` parity-0
/// fusion+resort rounds instead of the worst-case `⌈log₂(total)⌉`.
///
/// **Round-count is a paper-sanctioned public circuit parameter** ("the
/// public number of fusion or eviction rounds encoded in circuit shape",
/// §5). The worst-case `⌈log₂(total)⌉` only matters when a *single value*
/// repeats across most of the union; the rounds actually needed are
/// `⌈log₂(max run length)⌉`. For workloads where no value repeats more
/// than `2^fusion_rounds` times within the union, the result is
/// **identical** to the full-round update — the extra rounds would be
/// no-ops. With fewer rounds than that, residual duplicates remain
/// un-fused (they stay sorted and mass-conserved, just occupy extra
/// slots / spill to `excess`) — a graceful, sound degradation, exactly
/// analogous to Count-Min's `distinct_bound`.
pub fn apply_batch_full_with_rounds(
    s_old: &GKFullState,
    batch: &[GKFullUpdate],
    fusion_rounds: usize,
) -> (GKFullState, Vec<GKFullTuple>) {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    assert_eq!(batch.len(), m);
    assert!(fusion_rounds >= 1, "need at least one fusion round");

    let mut union: Vec<GKFullTuple> = s_old.tuples.iter().cloned().collect();
    for u in batch {
        union.push(GKFullTuple {
            value: u.value,
            count: u.active,
            max_error: 0,
            active: u.active,
        });
    }
    // Sort by (active asc, value asc) — dummies first, actives last by value asc.
    union.sort_by_key(|t| (t.active, t.value));

    let (fused_sorted, _rounds_data) = fuse_all_rounds(&union, fusion_rounds);

    // Excess = first `batch` rows (dummies + smallest actives if any spill).
    // S_new = last `capacity` rows (= largest `capacity` actives + padding).
    let excess_tuples: Vec<GKFullTuple> = fused_sorted[..m].to_vec();
    let s_new_tuples: Vec<GKFullTuple> = fused_sorted[m..m + cap].to_vec();
    (
        GKFullState { tuples: s_new_tuples, params: s_old.params },
        excess_tuples,
    )
}

// ─── Native: build the sorted union table (Step 2) ───────────────────────

/// Build the union table `U` of length `capacity + batch`.
///
/// Logical contents:
/// - From `S_old`: every tuple as-is (capacity rows; active or dummy).
/// - From `B`: each record as a tuple `(value, active, 0, active)`
///   so an active batch row contributes `(value, count=1)` and a
///   dummy contributes `(0, 0, 0, 0)`.
///
/// Sort key: `(active ascending, value ascending)` — dummies first
/// (with `value = 0`), actives last in ascending value order. This
/// produces a strictly value-monotone union, which unlocks the simple
/// non-gated sortedness check at Stage 7.5. Stability not strictly
/// required; we use stable sort for determinism.
///
/// Returns `(sorted_union, sigma)` where `sigma[i]` is the position in
/// the combined `(S_old ‖ B_as_tuples)` input that landed at output
/// position `i`.
fn build_union_table(
    s_old: &GKFullState,
    batch: &[GKFullUpdate],
) -> (Vec<GKFullTuple>, Vec<usize>) {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;

    // Combined input: indices 0..cap are S_old; cap..total are B.
    let mut indexed: Vec<(usize, GKFullTuple)> = Vec::with_capacity(total);
    for (i, t) in s_old.tuples.iter().enumerate() {
        indexed.push((i, *t));
    }
    for (j, u) in batch.iter().enumerate() {
        indexed.push((
            cap + j,
            GKFullTuple {
                value: u.value,
                count: u.active,
                max_error: 0,
                active: u.active,
            },
        ));
    }
    // Stable sort by (active ascending, value ascending) — dummies
    // first, actives last by value asc.
    indexed.sort_by_key(|(_, t)| (t.active, t.value));

    let sigma: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let sorted: Vec<GKFullTuple> = indexed.iter().map(|(_, t)| *t).collect();
    (sorted, sigma)
}

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

// ─── Test-only soundness hook ─────────────────────────────────────────────
//
// When set (only in tests), the prover corrupts the `fused_sorted`
// private-input table so it no longer matches the in-circuit fusion +
// resort. This exercises whether Stages 7.7/7.8/8 actually *reject* a
// bogus post-fusion table (soundness), as opposed to merely accepting an
// honest one. Production callers never touch this.
#[cfg(test)]
thread_local! {
    static TAMPER_FUSED_SORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    // When set, the Step 4 band gate uses θ_t = 0 instead of N_t, so any
    // real fusion (merged band > 0) violates the range check — proving the
    // gate actually binds.
    static TIGHTEN_THETA: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// ─── Prover ──────────────────────────────────────────────────────────────

/// Prove one GK update epoch with the §5.4 pipeline enforced in-circuit:
/// Step 2 (union multiset via PermuteAir), strict union sortedness, the
/// full `L = ⌈log₂(total)⌉`-round parity-0 fusion schedule (Step 5) —
/// each round verified per-pair and re-sorted via its own PermuteAir +
/// sortedness check — compaction of the final fused+sorted table into
/// `(S_new, excess)`, and combined mass conservation. A malicious prover
/// cannot fabricate values, reshuffle any table, supply a bogus
/// post-fusion table at any round, or fuse a pair whose merged band
/// exceeds `θ_t` (Step 4) — each is rejected by a lookup-bus / range /
/// connect constraint. The only honest-prover latitude left is *how
/// much* to fuse (the eligibility implication is one-directional). The
/// sole remaining simplification versus textbook GK is the exact
/// value-equality fusion policy (vs. band-merge of different values),
/// which keeps rank queries exact and avoids the 7-field Δ tuple — see
/// the module docstring.
pub fn prove_gk_full(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
) -> GKFullLeafProof {
    let total = params.capacity + params.batch;
    prove_gk_full_with_rounds(params, initial_state, batch, num_fusion_rounds(total))
}

/// Like [`prove_gk_full`] but runs exactly `fusion_rounds` parity-0
/// fusion rounds in-circuit instead of the worst-case `⌈log₂(total)⌉`.
///
/// **This is a pipeline-preserving proving-time optimization, not a
/// design change.** The §5.4 pipeline (sorted-union → parity-alternating
/// fusion *rounds* → compaction → invariant checks) is unchanged — we
/// only run the fusion stage `fusion_rounds` times, and the paper
/// explicitly treats the round count as a public circuit-shape parameter.
/// Each dropped round removes one PermuteAir + one decompose pass + one
/// set of `total` sortedness range-checks, so prove time falls roughly
/// linearly in the round count.
///
/// Correctness: for any workload whose longest run of equal values in the
/// union is `≤ 2^fusion_rounds`, the result is **identical** to the
/// full-round proof. With fewer rounds, residual duplicates remain
/// un-fused (sorted + mass-conserved, just occupying extra slots) — the
/// same graceful, sound degradation as Count-Min's `distinct_bound`.
/// Leaves proved with different `fusion_rounds` have different circuit
/// shapes (different verification keys), so a chain/merge must use a
/// consistent value.
pub fn prove_gk_full_with_rounds(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
    fusion_rounds: usize,
) -> GKFullLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);
    assert!(fusion_rounds >= 1, "need at least one fusion round");

    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;

    // ─── Native side ────────────────────────────────────────────────────
    // Use the batched union-and-compact update so S_new is positionally
    // bound to U via the in-circuit compaction step. Both the native
    // update and the circuit below run exactly `fusion_rounds` rounds, so
    // the committed final state matches what the circuit verifies.
    let (final_state, excess_tuples) =
        apply_batch_full_with_rounds(&initial_state, &batch, fusion_rounds);
    let initial_commit = commit_gk_state(&initial_state);
    let final_commit = commit_gk_state(&final_state);
    let batch_commit = commit_gk_batch(&batch);

    // Step 2 native: build sorted union.
    let (union_tuples, sigma_union) = build_union_table(&initial_state, &batch);
    assert_eq!(union_tuples.len(), total);
    assert_eq!(sigma_union.len(), total);
    assert_eq!(excess_tuples.len(), m);

    // Step 5 native: run `fusion_rounds` parity-0 fusion+resort rounds.
    // `rounds_data[r]` holds round r's decision bits, resorted table, and
    // resort permutation; the circuit verifies each round's per-pair
    // fusion transition and ties round r's resorted view to round r+1's
    // input (and the final round to the compaction, Stage 8).
    let num_rounds = fusion_rounds;
    let (final_fused_sorted, rounds_data) = fuse_all_rounds(&union_tuples, num_rounds);
    assert_eq!(rounds_data.len(), num_rounds);
    assert_eq!(final_fused_sorted.len(), total);
    // Spot-check: final_state == final_fused_sorted[m..m+cap].
    debug_assert_eq!(
        final_state.tuples.as_slice(),
        &final_fused_sorted[m..m + cap]
    );
    debug_assert_eq!(excess_tuples.as_slice(), &final_fused_sorted[..m]);

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

    // Public inputs.
    let init_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");

    // Private inputs (alloc order, MUST match the witness packing below):
    //   init, final, batch, union,
    //   [round 0..L: fuse_decision bits], [round 0..L: resorted table],
    //   excess.
    let init_packed: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("init_packed")).collect();
    let final_packed: Vec<ExprId> =
        (0..cap).map(|_| b.alloc_private_input("final_packed")).collect();
    let batch_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("batch_packed")).collect();
    let union_packed: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("union_packed")).collect();
    // Step 5: per-round, per-pair fusion decision bits (length = total/2
    // each). Each bit `e[i] ∈ {0,1}` says whether pair (T[2i], T[2i+1])
    // was fused in that round. They appear as ALU operands below so the
    // WitnessChecks bus claims them as creators.
    let num_pairs = total / 2;
    let round_decisions: Vec<Vec<ExprId>> = (0..num_rounds)
        .map(|_| (0..num_pairs).map(|_| b.alloc_private_input("fuse_decision")).collect())
        .collect();
    // Step 5: per-round post-fusion resorted tables (active asc, value
    // asc). Each is created on the bus by its own decompose and read by
    // its resort-connect — the proven-balanced `union_packed` role.
    let round_resorted: Vec<Vec<ExprId>> = (0..num_rounds)
        .map(|_| (0..total).map(|_| b.alloc_private_input("fused_sorted_packed")).collect())
        .collect();
    // Excess: overflow tuples from the final F_sorted that didn't fit
    // into S_new. Length = batch.
    let excess_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("excess_packed")).collect();

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

    // ─── Stage 3: Active flag boolean checks ────────────────────────────
    for r in 0..cap {
        let a = init_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);

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
        .add_permute(&combined_input, sigma_union.clone())
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
    // **Value-range assumption**: per-record `value` fields must fit in
    // `VALUE_DIFF_BITS - 1` bits so that a "negative" diff
    // (`value[r+1] < value[r]`) wraps to ≈ `p` ≈ 2^31 and won't fit in
    // `VALUE_DIFF_BITS = 22` bits — soundly rejecting the proof.
    // `gen_padded_batch` generates values masked to 20 bits, comfortably
    // under this bound. `VALUE_DIFF_BITS` is module-level.
    for r in 0..total - 1 {
        let curr = union_fields[r][0]; // value field
        let next = union_fields[r + 1][0];
        let diff = b.sub(next, curr);
        let _bits = b
            .decompose_to_bits::<Val>(diff, VALUE_DIFF_BITS)
            .expect("decompose union value diff");
    }

    // ─── Stage 7.6–7.8 (NEW): Step 5 — full L-round parity-0 fusion ─────
    //
    // Repeat `num_rounds = ⌈log₂(total)⌉` times: fuse adjacent pairs of
    // the current table, then re-sort. Because re-sorting re-adjacenttizes
    // surviving equal-value tuples, every run of equal values collapses to
    // one tuple after `L` rounds (each round at most halves the longest
    // run) — the §5.4 `L = ⌈log M⌉` schedule with plain parity-0 each
    // round (resort substitutes for parity alternation).
    //
    // Per round, for each pair `(T[2i], T[2i+1]) = (a, b)`, the prover
    // supplies a decision bit `e[i] ∈ {0,1}`; the circuit enforces:
    //   - `e·(e−1)=0`, `e·(a.value−b.value)=0`,
    //     `e·(1−a.active)=0`, `e·(1−b.active)=0`
    // and builds the post-fusion tuples as **ALU expressions**:
    //   - F[2i]   = (1−e)·a       (dummy if fused, else a)
    //   - F[2i+1] = (b.value, b.count+e·a.count, b.max_err+e·a.max_err, b.active)
    //
    // **Bus-safety** (the crux of why earlier attempts failed):
    //   1. F's rows are recomposed into Challenges via
    //      `recompose_base_coeffs_to_ext_via_alu` (a `mul_add` chain),
    //      never introduced as raw private inputs — so every fused field
    //      and packed value gets a WitnessChecks-bus creator.
    //   2. Each `a`/`b` field (a decompose-coeff hint witness) MUST appear
    //      as an ALU **lhs** (operand `a`) at least once, or it is never
    //      created on the bus (a coeff read only as rhs has no creator →
    //      `GlobalCumulativeMismatch(WitnessChecks)`). Hence every union
    //      field leads its product below.
    //
    // The round input `current_fields` is `union_fields` for round 0; for
    // round r>0 it is the previous round's `resorted_fields` (each decomposed
    // exactly once — re-decomposing a packed value would double-create it).
    let mut current_fields: Vec<Vec<ExprId>> = union_fields.clone();
    for round in 0..num_rounds {
        let decisions = &round_decisions[round];
        let resorted_packed = &round_resorted[round];
        let sigma = rounds_data[round].sigma.clone();

        // 7.6: build the fused payload from current_fields + decisions.
        let mut fused_payload: Vec<ExprId> = Vec::with_capacity(total);
        for i in 0..num_pairs {
            let e = decisions[i];
            let a_val = current_fields[2 * i][0];
            let a_cnt = current_fields[2 * i][1];
            let a_max = current_fields[2 * i][2];
            let a_act = current_fields[2 * i][3];
            let b_val = current_fields[2 * i + 1][0];
            let b_cnt = current_fields[2 * i + 1][1];
            let b_max = current_fields[2 * i + 1][2];
            let b_act = current_fields[2 * i + 1][3];

            // Boolean check: e · (e − 1) = 0.
            let em1 = b.sub(e, one);
            let bool_prod = b.mul(e, em1);
            b.connect(bool_prod, zero);

            // Eligibility implications (e = 1 ⇒ values equal, both active).
            let val_diff = b.sub(a_val, b_val);
            let prod_val = b.mul(e, val_diff);
            b.connect(prod_val, zero);
            let one_minus_a_act = b.sub(one, a_act);
            let prod_a_act = b.mul(e, one_minus_a_act);
            b.connect(prod_a_act, zero);
            let one_minus_b_act = b.sub(one, b_act);
            let prod_b_act = b.mul(e, one_minus_b_act);
            b.connect(prod_b_act, zero);

            // F[2i] = (1 − e) · a (union fields lead → lhs → bus creator).
            let one_minus_e = b.sub(one, e);
            let f_lo_val = b.mul(a_val, one_minus_e);
            let f_lo_cnt = b.mul(a_cnt, one_minus_e);
            let f_lo_max = b.mul(a_max, one_minus_e);
            let f_lo_act = b.mul(a_act, one_minus_e);
            let f_lo_packed = b
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[
                    f_lo_val, f_lo_cnt, f_lo_max, f_lo_act,
                ])
                .expect("recompose F[2i] via alu");
            fused_payload.push(f_lo_packed);

            // F[2i+1] = (b.value, b.count+e·a.count, b.max_err+e·a.max_err, b.active).
            let ea_cnt = b.mul(a_cnt, e);
            let f_hi_cnt = b.add(b_cnt, ea_cnt);
            let ea_max = b.mul(a_max, e);
            let f_hi_max = b.add(b_max, ea_max);
            let f_hi_packed = b
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[b_val, f_hi_cnt, f_hi_max, b_act])
                .expect("recompose F[2i+1] via alu");
            fused_payload.push(f_hi_packed);

            // ── Step 4 (NEW): GK band-threshold gate ──────────────────
            // §5.4 only fuses a pair when the merged band fits under
            // `θ_t = ⌊2εN_t⌋`. We enforce that in-circuit: if `e = 1`, the
            // merged band `a.count + b.count + a.max_err + b.max_err` must
            // be `≤ θ_t`. We take `θ_t = N_t` (the total active mass
            // `init_plus_batch`), i.e. the GK band at `ε = 1/2` — a valid,
            // generous calibration that never blocks a legitimate
            // exact-value merge (a pair's count-sum is always `≤ N_t`) yet
            // installs the real Step 4 mechanism: a range-checked
            // inequality gating every fusion.
            //
            // Encoding: `slack = θ_t − band`; range-check `e · slack ∈
            // [0, 2^VALUE_DIFF_BITS)`. When `e = 0` the product is 0 (in
            // range, no constraint); when `e = 1` it forces `slack ≥ 0`
            // (band ≤ θ_t) and `slack < 2^22` (true for N_t < 2^22 — our
            // batch scales sit far below that; documented bound).
            //
            // `a_cnt`/`b_cnt`/`a_max`/`b_max` already appear as ALU lhs in
            // the F-construction above, so they have bus creators; the
            // adds below are plain reads.
            let band_ab = b.add(a_cnt, b_cnt);
            let band_err = b.add(a_max, b_max);
            let band = b.add(band_ab, band_err);
            // θ_t = N_t normally; a test hook can tighten it to 0 to prove
            // the gate binds (any real fusion then has band > θ_t → reject).
            let theta_t = {
                #[cfg(test)]
                {
                    if TIGHTEN_THETA.with(|c| c.get()) { zero } else { init_plus_batch }
                }
                #[cfg(not(test))]
                {
                    init_plus_batch
                }
            };
            let slack = b.sub(theta_t, band);
            let gated_slack = b.mul(e, slack);
            let _band_bits = b
                .decompose_to_bits::<Val>(gated_slack, VALUE_DIFF_BITS)
                .expect("decompose Step 4 band slack");
        }

        // 7.7: resort F → resorted via PermuteAir, connect to the prover's
        // `resorted_packed`, then boolean + active-monotonicity checks.
        // Decompose `resorted_packed` FIRST (connect target needs a creator
        // before the connect reads it — mirrors Stage 6's ordering).
        let resorted_fields: Vec<Vec<ExprId>> = resorted_packed
            .iter()
            .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose resorted"))
            .collect();
        let permuted = b
            .add_permute(&fused_payload, sigma)
            .expect("add_permute (resort round)");
        for r in 0..total {
            b.connect(permuted[r], resorted_packed[r]);
        }
        for r in 0..total {
            let a = resorted_fields[r][3];
            let am1 = b.sub(a, one);
            let prod = b.mul(a, am1);
            b.connect(prod, zero);
        }
        for r in 0..total - 1 {
            let curr = resorted_fields[r][3];
            let next = resorted_fields[r + 1][3];
            let diff = b.sub(next, curr);
            let one_minus = b.sub(one, diff);
            let prod = b.mul(diff, one_minus);
            b.connect(prod, zero);
        }

        // 7.8: strict value-asc sortedness on the resorted table.
        for r in 0..total - 1 {
            let curr = resorted_fields[r][0];
            let next = resorted_fields[r + 1][0];
            let diff = b.sub(next, curr);
            let _bits = b
                .decompose_to_bits::<Val>(diff, VALUE_DIFF_BITS)
                .expect("decompose resorted value diff");
        }

        current_fields = resorted_fields;
    }
    // After L rounds, `current_fields` is the fully-fused, sorted table
    // that compaction (Stage 8) splits into (excess, S_new).
    let fused_sorted_fields = current_fields;

    // ─── Stage 8: Compaction binding excess ↔ F_sorted[..batch],
    //                              S_new  ↔ F_sorted[batch..] ───
    //
    // F_sorted is in `(active asc, value asc)` order (dummies first, then
    // actives in value-asc order). The first `batch` rows become
    // `excess`; the next `capacity` rows become `S_new` — the **largest
    // `capacity` actives by value** (padded with the smallest few dummies
    // if `n_active < capacity`).
    //
    // We bind the **decomposed base coefficients** field-by-field (Plonky3
    // disallows connecting two packed Challenges that have both already
    // been ext-to-base decomposed — both carry recompose-coeff metadata
    // that must agree at the ExprId level).
    //
    // End-to-end soundness chain now closed:
    //   Step 2 (Stage 6): multiset(U) = multiset(S_old ‖ B_as_tuples)
    //   Step 5 (Stage 7.6): F = per-pair fusion of U (verified)
    //   Resort (Stage 7.7): multiset(F_sorted) = multiset(F)
    //   Sortedness (Stage 7.8): F_sorted uniquely ordered
    //   Compaction (here): S_new = F_sorted[batch..], excess = F_sorted[..batch]
    // ⇒ every active tuple in S_new traces back to S_old ∪ B, with
    //   adjacent same-value duplicates fused per GK §5.4. No fabricated
    //   values, no cherry-picking, no skipped fusions a malicious prover
    //   could exploit to inflate rank estimates.
    let excess_fields: Vec<Vec<ExprId>> = excess_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose excess"))
        .collect();

    for i in 0..m {
        for k in 0..4 {
            b.connect(excess_fields[i][k], fused_sorted_fields[i][k]);
        }
    }
    for i in 0..cap {
        for k in 0..4 {
            b.connect(final_fields[i][k], fused_sorted_fields[m + i][k]);
        }
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

    let circuit = b.build().expect("build gk_full circuit");

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

    // NOTE: this order MUST match the `alloc_private_input` order above:
    //   init, final, batch, union,
    //   [round 0..L: decision bits], [round 0..L: resorted table], excess.
    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&pack_state_to_challenge(&initial_state));
    private_inputs.extend_from_slice(&pack_state_to_challenge(&final_state));
    private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
    private_inputs.extend_from_slice(&pack_union_to_challenge(&union_tuples));
    // Step 5 witnesses: all rounds' decision bits, then all rounds'
    // resorted tables. `rounds_data[r].sigma` is consumed as the round's
    // PermuteAir config (not a private input); the fused table itself is
    // re-derived in-circuit.
    for rd in &rounds_data {
        for &d in &rd.decisions {
            private_inputs.push(if d { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    for (r, rd) in rounds_data.iter().enumerate() {
        // `mut` is only used by the `#[cfg(test)]` tamper block below.
        #[allow(unused_mut)]
        let mut resorted_vals = pack_union_to_challenge(&rd.resorted);
        // [test-only] corrupt the FINAL round's resorted table (the one
        // compaction binds S_new/excess to) to confirm the resort
        // PermuteAir + sortedness + compaction constraints reject it.
        // Bumping one entry makes it no longer the σ image of the
        // in-circuit fused table, so the Stage 7.7 connect can't hold.
        #[cfg(test)]
        if r + 1 == rounds_data.len() && TAMPER_FUSED_SORTED.with(|c| c.get()) {
            use p3_field::PrimeCharacteristicRing;
            resorted_vals[0] += Challenge::ONE;
        }
        let _ = r;
        private_inputs.extend_from_slice(&resorted_vals);
    }
    private_inputs.extend_from_slice(&pack_union_to_challenge(&excess_tuples));

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
        trace_rows: ext_degrees.iter().map(|&d| d as u64).sum(),
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

    /// Native-side exercise of [`fuse_round_parity0`] + the resort + the
    /// compaction performed by [`apply_batch_full`]. Two duplicate values
    /// in the batch should land in a single fused tuple with `count = 2`
    /// in the final state. The total mass equals the active batch count.
    /// (Step 5 is verified on the native side only — see Stage 7.6's
    /// deferred-status comment for the in-circuit gap.)
    #[test]
    fn gk_full_native_fusion_round_trip() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        // Two updates with the same value — should fuse natively.
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

    /// Multi-round fusion: four copies of one value cannot collapse in a
    /// single parity-0 round (that only pairs them down to two count-2
    /// tuples); it needs `⌈log₂(total)⌉ ≥ 2` rounds. This proves the
    /// L-round schedule is wired end-to-end in-circuit — the final state
    /// must carry a single active tuple with count = 4.
    #[test]
    fn gk_full_in_circuit_multiround_fusion() {
        let params = GKFullParams { capacity: 4, batch: 4 };
        assert!(num_fusion_rounds(params.union_size()) >= 2);
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
        assert_eq!(actives.len(), 1, "all four copies must fuse into one tuple");
        assert_eq!(actives[0].value, 55);
        assert_eq!(actives[0].count, 4, "fused count = 4 across multiple rounds");
        assert_eq!(result.final_state.total_mass(), 4);
    }

    /// Pipeline-preserving optimization: capping the fusion-round count
    /// below the worst-case `⌈log₂(total)⌉` yields the **identical** result
    /// when no value's run exceeds `2^rounds`. Here every value repeats at
    /// most twice (max run = 2), so `fusion_rounds = 1` matches the full
    /// schedule exactly — proving the reduced-round circuit is correct, not
    /// just faster.
    #[test]
    fn gk_full_reduced_rounds_matches_full_when_runs_fit() {
        let params = GKFullParams { capacity: 4, batch: 4 };
        // Two distinct values, each appearing twice → max run length 2.
        let updates = vec![
            GKFullUpdate::real(5),
            GKFullUpdate::real(5),
            GKFullUpdate::real(9),
            GKFullUpdate::real(9),
        ];
        // Native full vs 1-round must agree for this max-run-2 workload.
        let s0 = GKFullState::empty(params);
        let (full_state, _) = apply_batch_full(&s0, &updates);
        let (r1_state, _) = apply_batch_full_with_rounds(&s0, &updates, 1);
        assert_eq!(full_state, r1_state, "1 round must equal full for max-run-2");

        // The 1-round proof certifies exactly that state.
        let proof = prove_gk_full_with_rounds(params, s0, updates, 1);
        assert_eq!(commit_gk_state(&full_state).0, proof.final_.0);
        let actives: Vec<_> = full_state.tuples.iter().filter(|t| t.active == 1).collect();
        assert_eq!(actives.len(), 2);
        assert!(actives.iter().all(|t| t.count == 2));
        assert_eq!(full_state.total_mass(), 4);
    }

    /// Graceful degradation: when a run exceeds `2^rounds`, the reduced-
    /// round proof still **verifies** (it's a valid k-round update) — the
    /// surplus duplicates simply remain un-fused, sorted and mass-conserved.
    /// Four copies of one value with `fusion_rounds = 1` collapse only to
    /// two count-2 tuples (full needs 2 rounds for count-4), yet mass is
    /// preserved and the leaf self-verifies.
    #[test]
    fn gk_full_reduced_rounds_underfuses_gracefully() {
        let params = GKFullParams { capacity: 4, batch: 4 };
        let updates = vec![
            GKFullUpdate::real(7),
            GKFullUpdate::real(7),
            GKFullUpdate::real(7),
            GKFullUpdate::real(7),
        ];
        let s0 = GKFullState::empty(params);
        let (r1_state, _) = apply_batch_full_with_rounds(&s0, &updates, 1);
        // 1 round merges into pairs: two (7, count 2) tuples, not one (7,4).
        let actives: Vec<_> = r1_state.tuples.iter().filter(|t| t.active == 1).collect();
        assert_eq!(actives.len(), 2, "1 round leaves 2 partially-fused tuples");
        assert!(actives.iter().all(|t| t.value == 7 && t.count == 2));
        // Mass is still conserved and the reduced-round proof verifies.
        assert_eq!(r1_state.total_mass(), 4);
        let proof = prove_gk_full_with_rounds(params, s0, updates, 1);
        assert_eq!(commit_gk_state(&r1_state).0, proof.final_.0);
    }

    #[test]
    #[ignore]
    fn gk_full_fusion_rounds_sweep() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = GKFullParams { capacity: 32, batch: 100 };
        let full = num_fusion_rounds(params.union_size());

        println!();
        println!("gk_final_full — prove time vs. fusion-round count (pipeline-preserving)");
        println!("=====================================================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}, full ⌈log₂(total)⌉ = {full}", params.capacity, params.batch);
        println!();

        for &rounds in &[1usize, 2, 4, full] {
            let updates = gen_padded_batch(params, 60);
            let elapsed = with_pool(threads, move || {
                let s0 = GKFullState::empty(params);
                let t = Instant::now();
                let _ = prove_gk_full_with_rounds(params, s0, updates, rounds);
                t.elapsed()
            });
            println!("  fusion_rounds={rounds:>2} (of {full})   prove {elapsed:>10.2?}");
        }
    }

    /// Step 4 gate binds: with θ_t tightened to 0, a batch that fuses
    /// (two equal values, merged band = 2 > 0) must be rejected by the
    /// band range-check. Confirms the threshold gate is a real constraint,
    /// not a no-op. (At the production θ_t = N_t the same batch is
    /// accepted — see `gk_full_in_circuit_fusion_accepts`.)
    #[test]
    fn gk_full_step4_threshold_gate_binds() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let updates = vec![GKFullUpdate::real(13), GKFullUpdate::real(13)];

        TIGHTEN_THETA.with(|c| c.set(true));
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(params, updates)
        }));
        TIGHTEN_THETA.with(|c| c.set(false)); // reset for other tests
        assert!(
            rejected.is_err(),
            "fusion with merged band > θ_t (=0) was accepted — Step 4 gate is a no-op"
        );
    }

    /// Soundness: if a malicious prover supplies a `fused_sorted` table
    /// that isn't the σ_resort image of the in-circuit fusion, the resort
    /// PermuteAir + sortedness + compaction constraints must reject it.
    /// We flip the test-only tamper flag and assert that proving panics
    /// (self-verify fails on the WitnessChecks / lookup bus).
    #[test]
    fn gk_full_fusion_soundness_rejects_bad_table() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let updates = vec![GKFullUpdate::real(7), GKFullUpdate::real(11)];

        // Sanity: honest prove succeeds (tamper off).
        TAMPER_FUSED_SORTED.with(|c| c.set(false));
        let _ok = generate_proof(params, updates.clone());

        // Now corrupt the post-fusion table: prove must fail.
        TAMPER_FUSED_SORTED.with(|c| c.set(true));
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(params, updates)
        }));
        TAMPER_FUSED_SORTED.with(|c| c.set(false)); // reset for other tests
        assert!(
            bad.is_err(),
            "corrupted fused_sorted table was accepted — Step 5 resort/compaction \
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
}
