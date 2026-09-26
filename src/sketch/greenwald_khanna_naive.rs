//! **Naive in-circuit "replay" leaf for Greenwald-Khanna (GK)** — the
//! per-record oblivious replay of the plaintext GK quantile-summary update
//! ([`crate::sketch::greenwald_khanna::GK::update`], mirrored as
//! [`crate::sketch::gk_final_full::apply_update`]). This is the **baseline
//! strawman** that the optimized certified leaf
//! ([`crate::sketch::gk_final_full`]) is shown to beat. It is the GK analog
//! of Count-Min's replay strawman
//! ([`crate::recursion::recursive::countmin_leaf`]) and of the SpaceSaving
//! naive leaf (`spacesaving_naive`).
//!
//! Where `gk_final_full` certifies the whole epoch with a single
//! sorted-union → `L`-round fusion → compaction pipeline (cost
//! `Θ((cap+batch)·log(cap+batch))` permute rows for the *whole* batch), the
//! naive leaf literally re-executes the plaintext per-record GK update once
//! **per record**, threading the full `cap`-tuple sorted summary
//! `S_0 → S_1 → … → S_m`. Each record does a `Θ(cap)` insert-by-value-
//! position (verified with a per-record PermuteAir + sortedness range-checks)
//! followed by a capacity-bounded compress (verified with a `Θ(cap)`
//! min-cost adjacent-pair range-check and a second per-record PermuteAir).
//! The dominant cost is the intended `Θ(batch · cap)` per batch — the
//! cost-to-beat.
//!
//! ### Commitment interchangeability
//!
//! The naive leaf binds the **same** initial / final / batch commitments,
//! with the **same** Poseidon2 packing as `gk_final_full` (4 base coeffs per
//! tuple: `(value, count, max_error, active)` for state; `(value, active, 0,
//! active)` for batch records), so the two leaves' proofs are directly
//! comparable: a [`crate::sketch::gk_final_full::commit_gk_state`] /
//! [`crate::sketch::gk_final_full::commit_gk_batch`] from one is
//! byte-identical to the other for the same inputs. We reuse
//! `GKFullParams` / `GKFullState` / `GKFullTuple` / `GKFullUpdate` and the
//! `GKFullProof` / `GKFullLeafProof` proof types verbatim from
//! `gk_final_full`.
//!
//! ### What the circuit enforces per record (`prev → next`)
//!
//! For record `k` with packed tuple `r_k = (value, active, 0, active)`:
//!
//! 1. **Sorted-summary invariant on `prev` and `next`** (dummies-first
//!    convention): dummies (value 0) come first, then actives in **ascending
//!    value** order — enforced by an active-flag `{0,1}`-step *increasing*
//!    monotonicity check plus an **un-gated** `decompose_to_bits` range-check
//!    on every adjacent value diff (`next.value − cur.value ≥ 0`, valid
//!    across the dummy→active boundary too). Dummies-first matches
//!    `gk_final_full` and lets the sortedness check skip the
//!    `mul(decompose, decompose) → decompose_to_bits` gating that caused a
//!    WitnessChecks bus failure.
//! 2. **Working-table multiset (Step "insert")**: a per-record PermuteAir
//!    proves `multiset(work_k) == multiset(prev ‖ r_k)` where `work_k` is a
//!    witnessed length-`cap+1` table that is itself range-checked sorted.
//!    The prover is forced to place `r_k` at its unique sorted position — no
//!    fabricated values, no reorder.
//! 3. **Capacity-bounded compress (Step "merge")**: `work_k` has `cap+1`
//!    slots. A witnessed one-hot `merge_at ∈ [0, cap)` picks the adjacent
//!    active pair `(work[j], work[j+1])` to fuse. A `Θ(cap)` range-check
//!    forces the chosen pair to have the **minimum** `count+max_error`
//!    adjacent-pair sum among all *active* adjacent pairs (the plaintext
//!    compress rule). `do_merge = Σ merge_at` is forced to fire iff `work`
//!    holds `cap+1` actives. The fused table `F` (length `cap+1`) is built
//!    from `work + merge_at` by ALU selects, then re-sorted via a **second
//!    PermuteAir** to `next ‖ [dummy]`, binding every `next` tuple to a fused
//!    tuple. Combined with `next`'s own sortedness check this uniquely pins
//!    `next`.
//! 4. **Mass conservation**: `Σ next.count·active == Σ prev.count·active +
//!    record.active`. Each active record adds exactly 1 to the summary's
//!    total count; a compress preserves total count (sums the merged pair).
//!
//! ### HONEST SCOPE — what is simplified vs. the certified leaf
//!
//! The certified `gk_final_full` proves the textbook §5.4 *band-threshold*
//! merge gate (`e·(θ_t − merged_band) ∈ [0,2^22)`) and the full
//! `L=⌈log₂(total)⌉`-round batched fusion. This naive leaf instead replays a
//! faithful per-record GK-style compress: **insert** the record into the
//! sorted summary, and if that overflows capacity, **fuse the single
//! adjacent active pair with the minimum `count+max_error` sum**, once per
//! over-capacity insert. This is the GK compression rule (min-cost adjacent
//! merge under the same band) applied per record with **insert-then-merge**
//! ordering — the variant the per-record PermuteAir + compaction can certify
//! directly. (The plaintext `apply_update` uses merge-then-insert ordering;
//! both are legitimate GK-bounded updates with identical total mass, but
//! their intermediate states can differ when compression fires, so the
//! committed final equals THIS replay's, not `apply_update`'s.) The naive
//! leaf's own native function [`apply_batch_gk_naive`] is the ground truth
//! the round-trip test checks against. Both leaves bind the identical
//! commitment *shape*; each certifies its own update rule, so a tamper
//! corrupting the committed final is rejected by either.
//!
//! The single deliberate simplification: the fused tuple's **`max_error`**
//! propagation (`a.max_error.saturating_add(a.count).max(b.max_error)`) is
//! **witnessed** and bound by the resort-multiset (so `next`'s max_error
//! must be one of `F`'s witnessed values) rather than re-derived in-circuit
//! from the `.max()`/`saturating_add` rule. Every fused tuple's **value,
//! count, and active flag**, the multiset membership at every stage, the
//! sortedness, the minimality of the chosen merge pair, and total-mass
//! conservation ARE enforced in-circuit. So the leaf is sound for: "every
//! active tuple in `next` traces back to `prev ∪ {record}` via a sorted
//! insert and a minimum-cost adjacent merge, with total count preserved."
//! The `max_error` exactness is the lone gap, mirroring how `gk_final_full`
//! itself defers the tighter ε-bound `Δ_1/Δ_2` tuple.
//!
//! ### Value-range assumption (same as `gk_final_full`)
//!
//! Per-record `value` fields must fit in `VALUE_DIFF_BITS − 1` bits
//! (`< 2^21`), so a "negative" sortedness diff wraps past the field modulus
//! and fails the `VALUE_DIFF_BITS`-bit decomposition, soundly rejecting an
//! out-of-order table. Counts/max_errors fit in `SUM_DIFF_BITS − 1` bits so
//! the minimality diffs don't wrap. The test workloads honor both.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_permute_trace, generate_poseidon2_trace,
    generate_recompose_trace,
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
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};

// Reuse the certified leaf's public types so the two leaves are drop-in
// comparable (same commitments, same proof type).
use crate::sketch::gk_final_full::{
    GKFullLeafProof, GKFullParams, GKFullProof, GKFullState, GKFullTuple, GKFullUpdate,
    commit_gk_batch, commit_gk_state,
};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Range for the strict value-sortedness diff. `value < 2^(VALUE_DIFF_BITS−1)`
/// so an out-of-order diff wraps past `p` and fails the bit-decomposition.
const VALUE_DIFF_BITS: usize = 22;
/// Range for the merge-minimality `(count+max_error)` adjacent-pair sums.
const SUM_DIFF_BITS: usize = 24;

// ─── Native replay ───────────────────────────────────────────────────────

/// Per-record witnesses for the oblivious replay of one GK update.
#[derive(Clone)]
struct StepWitness {
    /// The length-`cap+1` working table = `sort(prev ‖ record_as_tuple)`.
    work: Vec<GKFullTuple>,
    /// Permutation `sigma` s.t. `work[i] = (prev ‖ record)[sigma[i]]`.
    sigma: Vec<usize>,
    /// One-hot over `[0, cap)`: `merge_at[j] = 1` iff adjacent pair
    /// `(work[j], work[j+1])` is the min-cost active pair that gets fused.
    /// All-zero iff no compression is needed (≤ cap actives in `work`).
    merge_at: Vec<u32>,
    /// The post-compress length-`cap` table = `next`.
    next: Vec<GKFullTuple>,
}

/// Sort key `(active asc, value asc, original index)`: **dummies first**
/// (active=0, value=0), then actives in ascending value order; stable by
/// original index. Dummies-first is deliberate (matches `gk_final_full`): it
/// makes every adjacent `value` diff non-negative — including across the
/// dummy→active boundary (`diff = first_active.value ≥ 0`) — so the
/// in-circuit sortedness check needs **no gating** (an un-gated
/// `decompose_to_bits(next.value − cur.value)`), sidestepping the
/// `mul(decompose, decompose) → decompose_to_bits` WitnessChecks bus failure.
fn sort_key(t: &GKFullTuple, idx: usize) -> (u32, u32, usize) {
    (t.active, t.value, idx)
}

/// Build the sorted working table `sort(prev ‖ record)` and its permutation
/// `sigma` with `work[i] = (prev ‖ record)[sigma[i]]`.
fn build_work(prev: &[GKFullTuple], rec: GKFullTuple) -> (Vec<GKFullTuple>, Vec<usize>) {
    let n = prev.len() + 1;
    let mut indexed: Vec<(usize, GKFullTuple)> = Vec::with_capacity(n);
    for (i, t) in prev.iter().enumerate() {
        indexed.push((i, *t));
    }
    indexed.push((prev.len(), rec));
    indexed.sort_by_key(|(i, t)| sort_key(t, *i));
    let sigma: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let work: Vec<GKFullTuple> = indexed.iter().map(|(_, t)| *t).collect();
    (work, sigma)
}

/// The fused length-(cap+1) table `F`: `work` with the merged pair
/// `(work[j], work[j+1])` turned into `(dummy, absorbing)` when merging, or
/// `work` unchanged when not. The absorbing right slot gets value = right
/// endpoint, count summed, max_error propagated by the GK `.max()` rule.
fn build_fused(work: &[GKFullTuple], merge_at: &[u32]) -> Vec<GKFullTuple> {
    let mut f = work.to_vec();
    if let Some(j) = merge_at.iter().position(|&x| x == 1) {
        let a = work[j];
        let bb = work[j + 1];
        f[j] = GKFullTuple::dummy();
        f[j + 1] = GKFullTuple {
            value: bb.value,
            count: a.count.saturating_add(bb.count),
            max_error: a.max_error.saturating_add(a.count).max(bb.max_error),
            active: 1,
        };
    }
    f
}

/// Re-sort `fused` by `(active desc, value asc)` and return the permutation
/// `sigma_f` with `resorted[i] = fused[sigma_f[i]]`. `resorted[0..cap]` is
/// `next` and `resorted[cap]` is the dropped dummy.
fn resort_fused_sigma(fused: &[GKFullTuple]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..fused.len()).collect();
    idx.sort_by_key(|&i| sort_key(&fused[i], i));
    idx
}

/// Pick the min-cost (`count+max_error`-sum) adjacent ACTIVE pair index in
/// `work` (ties → first). `None` if no adjacent active pair exists.
fn min_merge_index(work: &[GKFullTuple], cap: usize) -> Option<usize> {
    let mut best: Option<(u64, usize)> = None;
    for j in 0..cap {
        if work[j].active == 1 && work[j + 1].active == 1 {
            let s = work[j].count as u64
                + work[j].max_error as u64
                + work[j + 1].count as u64
                + work[j + 1].max_error as u64;
            if best.is_none_or(|(bs, _)| s < bs) {
                best = Some((s, j));
            }
        }
    }
    best.map(|(_, j)| j)
}

/// Native replay of one record using **insert-then-merge** ordering (the
/// circuit's semantics): build `work = sort(prev ‖ rec)`, and if that holds
/// `cap+1` actives (over capacity) fuse the min-cost adjacent ACTIVE pair,
/// then re-sort and drop the leading dummy to get `next`. This is a faithful
/// GK-style per-record compress — a min-cost adjacent merge under the same
/// `count+max_error` band — differing from the plaintext `apply_update` only
/// in ordering (it merges within `prev` *before* inserting; we merge the
/// inserted record's table). Both preserve total mass and keep the summary
/// sorted and bounded; we use the insert-then-merge variant because it is the
/// one the per-record PermuteAir/compaction can certify directly.
fn replay_step(prev: &[GKFullTuple], params: GKFullParams, u: &GKFullUpdate) -> StepWitness {
    let cap = params.capacity;
    let rec = GKFullTuple {
        value: u.value,
        count: u.active,
        max_error: 0,
        active: u.active,
    };
    let (work, sigma) = build_work(prev, rec);

    let active_in_work = work.iter().filter(|t| t.active == 1).count();
    let mut merge_at = vec![0u32; cap];
    if active_in_work > cap {
        let j = min_merge_index(&work, cap).expect("active pair exists when over capacity");
        merge_at[j] = 1;
    }
    // next = resort(fused)[1..=cap]  (drop the single leading dummy; with
    // dummies-first ordering the dropped slot is at position 0).
    let fused = build_fused(&work, &merge_at);
    let sf = resort_fused_sigma(&fused);
    let next: Vec<GKFullTuple> = (1..=cap).map(|i| fused[sf[i]]).collect();
    StepWitness { work, sigma, merge_at, next }
}

/// Apply the whole batch natively by per-record replay, returning every
/// intermediate state `S_0 … S_m` (length `m+1`) plus the per-record
/// witnesses (length `m`).
fn replay_batch(
    initial: &GKFullState,
    batch: &[GKFullUpdate],
) -> (Vec<Vec<GKFullTuple>>, Vec<StepWitness>) {
    let params = initial.params;
    let mut states: Vec<Vec<GKFullTuple>> = Vec::with_capacity(batch.len() + 1);
    let mut witnesses: Vec<StepWitness> = Vec::with_capacity(batch.len());
    let mut cur = initial.tuples.clone();
    states.push(cur.clone());
    for u in batch {
        let w = replay_step(&cur, params, u);
        cur = w.next.clone();
        witnesses.push(w);
        states.push(cur.clone());
    }
    (states, witnesses)
}

/// [test-only] Replay the batch but, for the FIRST compression encountered,
/// deliberately pick a NON-minimum adjacent active pair to merge (the max-sum
/// pair). The `work`/`sigma`/`next` are kept mutually consistent with that
/// wrong merge so every constraint EXCEPT the merge-minimality range-check is
/// satisfied — isolating that check.
#[cfg(test)]
fn replay_batch_force_nonmin(
    initial: &GKFullState,
    batch: &[GKFullUpdate],
) -> (Vec<Vec<GKFullTuple>>, Vec<StepWitness>) {
    let params = initial.params;
    let cap = params.capacity;
    let mut states: Vec<Vec<GKFullTuple>> = Vec::with_capacity(batch.len() + 1);
    let mut witnesses: Vec<StepWitness> = Vec::with_capacity(batch.len());
    let mut cur = initial.tuples.clone();
    states.push(cur.clone());
    let mut tampered = false;
    for u in batch {
        let rec = GKFullTuple { value: u.value, count: u.active, max_error: 0, active: u.active };
        let (work, sigma) = build_work(&cur, rec);
        let active_in_work = work.iter().filter(|t| t.active == 1).count();
        let mut merge_at = vec![0u32; cap];

        // Active adjacent pair sums (j, sum) for the current `work`.
        let pair_sums: Vec<(usize, u64)> = (0..cap)
            .filter(|&j| work[j].active == 1 && work[j + 1].active == 1)
            .map(|j| {
                let s = work[j].count as u64
                    + work[j].max_error as u64
                    + work[j + 1].count as u64
                    + work[j + 1].max_error as u64;
                (j, s)
            })
            .collect();
        let min_s = pair_sums.iter().map(|&(_, s)| s).min();
        let max_s = pair_sums.iter().map(|&(_, s)| s).max();
        // Only tamper the FIRST compression whose max-sum active pair STRICTLY
        // exceeds its min-sum active pair (otherwise a non-min pick has equal
        // cost and is legitimately accepted — no soundness signal).
        let detectable = matches!((min_s, max_s), (Some(a), Some(b)) if b > a);

        let next: Vec<GKFullTuple> = if active_in_work > cap && !tampered && detectable {
            tampered = true;
            // pick the MAX-sum active adjacent pair (strictly non-minimum).
            let j = pair_sums.iter().max_by_key(|&&(_, s)| s).expect("active pair").0;
            merge_at[j] = 1;
            // next = resort(fused)[1..=cap], consistent with the WRONG merge.
            let fused = build_fused(&work, &merge_at);
            let sf = resort_fused_sigma(&fused);
            (1..=cap).map(|i| fused[sf[i]]).collect()
        } else {
            // honest path (insert-then-merge, same as replay_step).
            if active_in_work > cap {
                let j = min_merge_index(&work, cap).expect("active pair exists");
                merge_at[j] = 1;
            }
            let fused = build_fused(&work, &merge_at);
            let sf = resort_fused_sigma(&fused);
            (1..=cap).map(|i| fused[sf[i]]).collect()
        };

        cur = next.clone();
        witnesses.push(StepWitness { work, sigma, merge_at, next });
        states.push(cur.clone());
    }
    (states, witnesses)
}

/// Public native entry point: apply the batch by faithful replay and return
/// the final state.
pub fn apply_batch_gk_naive(initial: &GKFullState, batch: &[GKFullUpdate]) -> GKFullState {
    let (states, _w) = replay_batch(initial, batch);
    let final_tuples = states.last().expect("at least S_0").clone();
    GKFullState { tuples: final_tuples, params: initial.params }
}

// ─── Native packing (identical shape to gk_final_full) ─────────────────────

fn pack_tuples_to_challenge(tuples: &[GKFullTuple]) -> Vec<Challenge> {
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

fn pack_batch_to_challenge(batch: &[GKFullUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    batch
        .iter()
        .map(|u| {
            let coeffs = [
                Val::from_u32(u.value),
                Val::from_u32(u.active),
                Val::ZERO,
                Val::from_u32(u.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

// ─── Test-only soundness hooks ─────────────────────────────────────────────
#[cfg(test)]
thread_local! {
    /// When set, the prover corrupts the witnessed final state so it no
    /// longer equals the natively-replayed final. The commit-binding +
    /// transition constraints must reject it.
    static TAMPER_FINAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When set, the prover moves a compress merge to a NON-minimum adjacent
    /// pair (with a consistent wrong `next`) to confirm the merge-minimality
    /// range-check rejects it.
    static TAMPER_MERGE_NONMIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// ─── Op tags (shared-PermuteBus fix, revision Step 1) ───────────────────────
//
// The fork concatenates every `add_permute` of a circuit into ONE PermuteAir
// whose PermuteBus message is the 4 value coordinates only (no op id), so the
// `2m` per-record permutes (insert = op `2k`, resort = op `2k+1`) only prove
// that the union of ALL their inputs equals the union of ALL their outputs.
// On the shared `(value, count, max_error, active)` encoding a prover could
// swap two records between their insert permutes — replaying the stream in a
// different order than the committed batch (`tests::record_swap_forgery_rejected`,
// accepted before this fix). Every element of op `o` therefore carries the op
// tag `2(o+1)` in its `active` coordinate: inputs get it by a constant ext-add
// (states, record) or in the ALU recompose (fused rows); outputs are
// de-tagged and the de-tagged `active` is boolean-checked, which pins every
// output of op `o` to `{2(o+1), 2(o+1)+1}` — disjoint classes, so per-class
// counting forces per-op multiset equality. The committed tables keep the
// committed encoding.

/// `active`-coordinate op tag of permute op `o`.
fn op_tag_val(o: usize) -> u64 {
    2 * (o as u64 + 1)
}

/// Whether [`prove_gk_naive`] tags its permutes. Always on outside tests.
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
    /// Test-only malicious prover: `(o, tuples)` makes permute op `o` emit
    /// `tuples` (packed in op `o`'s encoding, see [`pack_op`]).
    static FORGE: std::cell::RefCell<Vec<(usize, Vec<GKFullTuple>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// Test-only: `Some((o, row, o2))` packs row `row` of op `o`'s OUTPUT
    /// (permute output AND private input) with op `o2`'s tag — a prover lying
    /// about the tag so the element matches another op's input on the bus.
    static ROW_TAG: std::cell::Cell<Option<(usize, usize, usize)>> =
        const { std::cell::Cell::new(None) };
}

/// Pack op `o`'s OUTPUT table (`work` for `o = 2k`, `resorted` for `o = 2k+1`)
/// in its tagged encoding (untagged when `op_tag` is off).
fn pack_op(tuples: &[GKFullTuple], o: usize, op_tag: bool) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    #[allow(unused_mut)]
    let mut row_tag = vec![o; tuples.len()];
    #[cfg(test)]
    if let Some((oo, row, o2)) = ROW_TAG.with(|c| c.get())
        && oo == o
    {
        row_tag[row] = o2;
    }
    tuples
        .iter()
        .enumerate()
        .map(|(r, t)| {
            let tag = if op_tag { op_tag_val(row_tag[r]) } else { 0 };
            let coeffs = [
                Val::from_u32(t.value),
                Val::from_u32(t.count),
                Val::from_u32(t.max_error),
                Val::from_u64(t.active as u64 + tag),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

// ─── Prover ────────────────────────────────────────────────────────────────

/// Prove one GK epoch by **naive per-record replay** (the strawman baseline).
/// Binds the same commitments as [`crate::sketch::gk_final_full`].
pub fn prove_gk_naive(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
) -> GKFullLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);

    // ─── Native side ────────────────────────────────────────────────────
    #[cfg(test)]
    let (states, witnesses) = if TAMPER_MERGE_NONMIN.with(|c| c.get()) {
        replay_batch_force_nonmin(&initial_state, &batch)
    } else {
        replay_batch(&initial_state, &batch)
    };
    #[cfg(not(test))]
    let (states, witnesses) = replay_batch(&initial_state, &batch);
    prove_gk_naive_witness(params, initial_state, batch, &states, &witnesses)
}

/// Build, run, prove and self-verify the naive replay circuit for a (honest or
/// hand-crafted) replay witness `S_0 … S_m` + per-record steps.
fn prove_gk_naive_witness(
    params: GKFullParams,
    initial_state: GKFullState,
    batch: Vec<GKFullUpdate>,
    states: &[Vec<GKFullTuple>],
    witnesses: &[StepWitness],
) -> GKFullLeafProof {
    let cap = params.capacity;
    let m = params.batch;
    let work_len = cap + 1;
    let op_tag = use_op_tag();
    debug_assert_eq!(states.len(), m + 1);
    debug_assert_eq!(witnesses.len(), m);
    let final_state = GKFullState { tuples: states[m].clone(), params };

    let initial_commit = commit_gk_state(&initial_state);
    let final_commit = commit_gk_state(&final_state);
    let batch_commit = commit_gk_batch(&batch);

    // ─── Build circuit ──────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);

    // Public inputs: initial / final / batch commitments (2 Challenge each).
    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");

    // ─── Private inputs (alloc order MUST match the packing below) ───────
    // 1. threaded states S_0 … S_m, each `cap` packed tuples.
    let state_packed: Vec<Vec<ExprId>> = (0..=m)
        .map(|_| (0..cap).map(|_| b.alloc_private_input("state_packed")).collect())
        .collect();
    // 2. batch records (`m` packed rows).
    let batch_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("batch_packed")).collect();
    // 3. per-record working tables (`cap+1` packed tuples each).
    let work_packed: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..work_len).map(|_| b.alloc_private_input("work_packed")).collect())
        .collect();
    // 4. per-record one-hot merge selectors (`cap` each).
    let merge_sel: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..cap).map(|_| b.alloc_private_input("merge_sel")).collect())
        .collect();
    // 5. per-record fused-table max_error witnesses (`cap+1` each). Allocated
    //    upfront (NOT interleaved with Stage-4 gadget calls) so the private
    //    input stream lines up unambiguously.
    let f_max_w: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..work_len).map(|_| b.alloc_private_input("f_max")).collect())
        .collect();
    // 6. per-record resorted (post-fusion, re-sorted) tables (`cap+1` packed
    //    tuples each). The per-record resort PermuteAir output is *connected*
    //    to these private inputs (mirroring `gk_final_full`'s Stage 7.7), and
    //    these private inputs — not the raw permute output — are decomposed
    //    for the `next` binding, so every coeff gets a WitnessChecks-bus
    //    creator.
    let resorted_packed: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..work_len).map(|_| b.alloc_private_input("resorted_packed")).collect())
        .collect();

    // ─── Stage 1: commit bindings ───────────────────────────────────────
    let h_init = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &state_packed[0], true)
        .expect("hash init");
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &state_packed[m], true)
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

    // ─── Stage 2: decompose every packed sequence to base coeffs ─────────
    // state_fields[t][j] = [value, count, max_error, active] for S_t tuple j.
    let state_fields: Vec<Vec<Vec<ExprId>>> = state_packed
        .iter()
        .map(|st| {
            st.iter()
                .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d state"))
                .collect()
        })
        .collect();
    let batch_fields: Vec<Vec<ExprId>> = batch_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d batch"))
        .collect();
    let work_fields: Vec<Vec<Vec<ExprId>>> = work_packed
        .iter()
        .map(|wt| {
            wt.iter()
                .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d work"))
                .collect()
        })
        .collect();

    // ─── helpers ─────────────────────────────────────────────────────────
    let bool_check = |b: &mut CircuitBuilder<Challenge>, a: ExprId| {
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    };

    // Sorted-table well-formedness (dummies-first convention): active∈{0,1},
    // count·(1−active)==0, max_error·(1−active)==0, active weakly INCREASING
    // (dummies then actives), and **un-gated** value-asc sortedness across
    // every adjacent pair (`decompose_to_bits(next.value − cur.value)`).
    // Un-gated works because dummies (value 0) come first and actives are
    // value-asc, so every adjacent diff ≥ 0 — including across the
    // dummy→active boundary. This avoids the `mul(decompose, decompose) →
    // decompose_to_bits` WitnessChecks bus failure. `fields` is a slice of
    // length-`len` tuples [value,count,max_error,active].
    let sorted_checks =
        |b: &mut CircuitBuilder<Challenge>, fields: &[Vec<ExprId>], len: usize| {
            for j in 0..len {
                let active = fields[j][3];
                let count = fields[j][1];
                let max_err = fields[j][2];
                let am1 = b.sub(active, one);
                let prod = b.mul(active, am1);
                b.connect(prod, zero);
                let oma = b.sub(one, active);
                // dummy ⇒ count == 0 (count·(1−active) == 0).
                let lhs = b.mul(count, oma);
                b.connect(lhs, zero);
                // dummy ⇒ max_error == 0 (max_error·(1−active) == 0). Also
                // consumes the max_error coeff on the WitnessChecks bus (it is
                // otherwise unread on `prev`/`S_0`, which would dangle a bus
                // entry → GlobalCumulativeMismatch).
                let lhs2 = b.mul(max_err, oma);
                b.connect(lhs2, zero);
            }
            for j in 0..len - 1 {
                let cur_a = fields[j][3];
                let nxt_a = fields[j + 1][3];
                // active weakly INCREASING: next − cur ∈ {0,1}.
                let diff = b.sub(nxt_a, cur_a);
                let one_minus = b.sub(one, diff);
                let prod = b.mul(diff, one_minus);
                b.connect(prod, zero);
                // un-gated value-asc sortedness: next.value − cur.value ≥ 0.
                let cur_v = fields[j][0];
                let nxt_v = fields[j + 1][0];
                let vdiff = b.sub(nxt_v, cur_v);
                let _bits = b
                    .decompose_to_bits::<Val>(vdiff, VALUE_DIFF_BITS)
                    .expect("decompose sorted value diff");
            }
        };

    // ─── Stage 3: every threaded state is a well-formed sorted summary ───
    for t in 0..=m {
        sorted_checks(&mut b, &state_fields[t], cap);
    }
    // batch active flags boolean + canonical (value, active, 0, active) form.
    for k in 0..m {
        bool_check(&mut b, batch_fields[k][3]);
        b.connect(batch_fields[k][1], batch_fields[k][3]);
        b.connect(batch_fields[k][2], zero);
        // dummy record ⇒ value == 0 (value·(1−active) == 0). Also consumes
        // the batch value coeff [0] on the WitnessChecks bus (value enters
        // the permute via the packed Challenge, so coeff [0] is otherwise
        // unread → dangling bus entry).
        let oma = b.sub(one, batch_fields[k][3]);
        let vlhs = b.mul(batch_fields[k][0], oma);
        b.connect(vlhs, zero);
    }

    // ─── Stage 4: per-record transition prev → next ─────────────────────
    for k in 0..m {
        let prev = &state_fields[k];
        let next = &state_fields[k + 1];
        let rec_packed = batch_packed[k];
        // Op tags of this record's insert (op 2k) and resort (op 2k+1)
        // permutes: `*_x` adds the tag to a packed value's `active`
        // coordinate, `*_b` is the base value for de-tagging a decomposed field.
        let (tag_ins_x, tag_ins_b, tag_rs_b) = {
            use p3_field::BasedVectorSpace;
            let tx = |o: usize| {
                Challenge::from_basis_coefficients_slice(&[
                    Val::ZERO,
                    Val::ZERO,
                    Val::ZERO,
                    Val::from_u64(op_tag_val(o)),
                ])
                .expect("4 coeffs")
            };
            (
                b.alloc_const(tx(2 * k), "op_tag_insert_x"),
                b.alloc_const(Challenge::from_u64(op_tag_val(2 * k)), "op_tag_insert"),
                b.alloc_const(Challenge::from_u64(op_tag_val(2 * k + 1)), "op_tag_resort"),
            )
        };
        // The work table is the insert op's OUTPUT: de-tag its `active` field
        // (the boolean check in `sorted_checks` then pins the op class).
        let work_eff: Vec<Vec<ExprId>> = if op_tag {
            work_fields[k]
                .iter()
                .map(|f| vec![f[0], f[1], f[2], b.sub(f[3], tag_ins_b)])
                .collect()
        } else {
            work_fields[k].clone()
        };
        let work = &work_eff;

        // 4.1 — work table is a well-formed sorted summary (cap+1 long).
        sorted_checks(&mut b, work, work_len);

        // 4.2 — Step "insert": multiset(work) == multiset(prev ‖ record).
        let mut combined: Vec<ExprId> = Vec::with_capacity(work_len);
        combined.extend(state_packed[k].iter().copied());
        combined.push(rec_packed);
        if op_tag {
            // insert op INPUT: tag every committed row's `active` coordinate.
            combined = combined.iter().map(|&p| b.add(p, tag_ins_x)).collect();
        }
        let permuted = b
            .add_permute(&combined, witnesses[k].sigma.clone())
            .expect("add_permute (work)");
        for j in 0..work_len {
            b.connect(permuted[j], work_packed[k][j]);
        }

        // 4.3 — merge selector well-formedness: each ∈{0,1}; Σ∈{0,1};
        // merge[j]=1 ⟹ work[j] and work[j+1] both active.
        let mut sel_sum = zero;
        for j in 0..cap {
            bool_check(&mut b, merge_sel[k][j]);
            sel_sum = b.add(sel_sum, merge_sel[k][j]);
            let oma = b.sub(one, work[j][3]);
            let c1 = b.mul(merge_sel[k][j], oma);
            b.connect(c1, zero);
            let omb = b.sub(one, work[j + 1][3]);
            let c2 = b.mul(merge_sel[k][j], omb);
            b.connect(c2, zero);
        }
        bool_check(&mut b, sel_sum);

        // 4.4 — `do_merge` (= Σ merge_sel) fires iff `work` is over capacity.
        // active_in_work − do_merge == active_in_next: a merge fuses two
        // actives into one (−1 active) and drops a dummy leading slot; a
        // no-merge drops a dummy and keeps all actives. This forces do_merge
        // ON exactly when active_in_work = cap+1 (since active_in_next ≤ cap),
        // and OFF otherwise (active_in_work ≤ cap ⇒ active_in_next =
        // active_in_work needs do_merge = 0).
        let mut active_in_work = zero;
        for j in 0..work_len {
            active_in_work = b.add(active_in_work, work[j][3]);
        }
        let mut active_in_next = zero;
        for j in 0..cap {
            active_in_next = b.add(active_in_next, next[j][3]);
        }
        let lhs = b.sub(active_in_work, sel_sum);
        b.connect(lhs, active_in_next);

        // 4.5 — merge minimality: when a merge fires, the chosen ACTIVE
        // adjacent pair has the minimum `count+max_error` sum among all
        // active adjacent pairs. To avoid the `mul(decompose, decompose) →
        // decompose_to_bits` WitnessChecks bus failure we (a) give inactive
        // pairs a large penalty `BIG` so they can never undercut the chosen
        // min, and (b) gate the range-checked diff by `sel_sum` only (a sum
        // of private selector bits — NOT a product of decompose coeffs), the
        // same safe shape as `gk_final_full`'s Step-4 `mul(e, slack)`.
        //
        //   pair_cost[l] = (count_l + max_l + count_{l+1} + max_{l+1})
        //                  + (1 − both_active[l]) · BIG
        //   chosen_cost  = Σ_j merge_sel[j] · pair_cost[j]   (chosen is active
        //                  ⇒ no penalty ⇒ chosen_cost = chosen pair's raw sum)
        //   range-check  sel_sum · (pair_cost[l] − chosen_cost) ∈ [0, 2^B)
        //
        // BIG (= 2^20) exceeds every real pair sum at our scales yet
        // BIG + pair_sum stays < 2^SUM_DIFF_BITS, so the diff for an inactive
        // pair (≈ BIG) is a valid in-range non-negative value; for an active
        // pair the diff is sum_l − chosen ≥ 0 (chosen is the min). When
        // sel_sum = 0 (no merge) the gated value is 0 (trivially in range).
        let big = b.alloc_const(Challenge::from_u64(1u64 << 20), "merge_penalty");
        let mut pair_cost: Vec<ExprId> = Vec::with_capacity(cap);
        for j in 0..cap {
            // raw pair sum (work coeffs as ALU lhs → bus creators).
            let s1 = b.add(work[j][1], work[j][2]);
            let s2 = b.add(work[j + 1][1], work[j + 1][2]);
            let raw = b.add(s1, s2);
            // both_active[j] = work[j].active · work[j+1].active.
            let ba = b.mul(work[j][3], work[j + 1][3]);
            // penalty = (1 − both_active)·BIG.
            let omba = b.sub(one, ba);
            let penalty = b.mul(omba, big);
            let cost = b.add(raw, penalty);
            pair_cost.push(cost);
        }
        let mut chosen_cost = zero;
        for j in 0..cap {
            let t = b.mul(merge_sel[k][j], pair_cost[j]);
            chosen_cost = b.add(chosen_cost, t);
        }
        for l in 0..cap {
            let diff = b.sub(pair_cost[l], chosen_cost);
            // gate by sel_sum (sum of private selector bits) — safe shape.
            let gated = b.mul(sel_sum, diff);
            let _bits = b
                .decompose_to_bits::<Val>(gated, SUM_DIFF_BITS)
                .expect("decompose merge-min diff");
        }

        // 4.6 — build the fused length-(cap+1) table F from work + merge_sel,
        // then re-sort F via a PermuteAir to `next ‖ [dummy]`.
        //   killed[j]  = merge_sel[j]   (this slot becomes dummy)
        //   absorb[j]  = merge_sel[j-1] (this slot absorbs the left half)
        //   F[j].value  = (1−killed)·work[j].value          (right endpoint kept)
        //   F[j].count  = (1−killed)·work[j].count + absorb·work[j-1].count
        //   F[j].active = (1−killed)·work[j].active
        //   F[j].max_err= (1−killed)·work[j].max_error  (+ witnessed propagation
        //                 on the absorbing slot — the documented simplification)
        //
        // The absorbing slot's propagated max_error
        // (`a.max_err.saturating_add(a.count).max(b.max_err)`) is WITNESSED in
        // `work_packed`? No — it's recomputed from `next`'s committed value via
        // the resort multiset. We add it as a correction term `me_corr[j]`
        // that is constrained to be 0 on non-absorbing slots and otherwise
        // free, bound to `next` only through the resort multiset. Value, count,
        // active are exact; max_error is witnessed (see module docs).
        let mut f_packed: Vec<ExprId> = Vec::with_capacity(work_len);
        for j in 0..work_len {
            let killed = if j < cap { merge_sel[k][j] } else { zero };
            let absorb = if j >= 1 && (j - 1) < cap { merge_sel[k][j - 1] } else { zero };
            let one_minus_killed = b.sub(one, killed);
            // NOTE: every `work[j][*]` coeff is placed as the ALU **lhs**
            // (operand `a`) of a multiplication so it gets a WitnessChecks-bus
            // creator (a coeff read only as an rhs has no creator → bus
            // imbalance `GlobalCumulativeMismatch(WitnessChecks)`).
            let v = b.mul(work[j][0], one_minus_killed);
            let base_c = b.mul(work[j][1], one_minus_killed);
            let add_c = if j >= 1 { b.mul(work[j - 1][1], absorb) } else { zero };
            let c = b.add(base_c, add_c);
            let a = b.mul(work[j][3], one_minus_killed);
            // max_error of the fused/absorbing slot is provided natively via
            // the upfront-allocated `f_max_w[k][j]` witness; recompose F's row
            // with it so the resort multiset binds `next`'s committed
            // max_error to it.
            let me_witness = f_max_w[k][j];
            // On non-absorbing slots, force me_witness == (1−killed)·work.max_err.
            // On the absorbing slot, me_witness is free (the propagated value).
            // work[j][2] as ALU lhs → bus creator (see note above).
            let me_kept = b.mul(work[j][2], one_minus_killed);
            // If NOT absorbing (absorb==0): me_witness must equal me_kept.
            //   (1 − absorb)·(me_witness − me_kept) == 0.
            let one_minus_absorb = b.sub(one, absorb);
            let me_diff = b.sub(me_witness, me_kept);
            let me_con = b.mul(one_minus_absorb, me_diff);
            b.connect(me_con, zero);
            // F is the resort op's INPUT: its `active` coordinate carries the tag.
            let a_op = if op_tag { b.add(a, tag_rs_b) } else { a };
            let packed = b
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[v, c, me_witness, a_op])
                .expect("recompose F row via alu");
            f_packed.push(packed);
        }

        // resort F → resorted = next ‖ [dummy], via PermuteAir. Mirror
        // gk_final_full's Stage 7.7: decompose the PRIVATE-INPUT resorted
        // table FIRST (so its coeffs get bus creators), then connect the
        // permute output to that private input.
        let resorted_fields: Vec<Vec<ExprId>> = resorted_packed[k]
            .iter()
            .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d resorted"))
            .collect();
        let fused_native = build_fused(&witnesses[k].work, &witnesses[k].merge_at);
        let sigma_f = resort_fused_sigma(&fused_native);
        let resorted = b
            .add_permute(&f_packed, sigma_f)
            .expect("add_permute (F resort)");
        for r in 0..work_len {
            b.connect(resorted[r], resorted_packed[k][r]);
        }
        // With dummies-first ordering the dropped slot is resorted[0] (a full
        // dummy); resorted[1..=cap] is `next`. Constrain resorted[0]'s 4
        // coeffs to 0 and bind resorted[1+i]'s 4 coeffs to next[i]. (All
        // coeffs consumed → no dangling WitnessChecks-bus entry.)
        // resorted is the resort op's OUTPUT: its `active` field is de-tagged
        // (the dropped dummy's must equal the bare tag; the rest must equal
        // `next`'s boolean active flag, which pins the op class).
        for c in 0..3 {
            b.connect(resorted_fields[0][c], zero);
        }
        b.connect(resorted_fields[0][3], if op_tag { tag_rs_b } else { zero });
        for i in 0..cap {
            for c in 0..3 {
                b.connect(resorted_fields[i + 1][c], next[i][c]);
            }
            if op_tag {
                let a = b.sub(resorted_fields[i + 1][3], tag_rs_b);
                b.connect(a, next[i][3]);
            } else {
                b.connect(resorted_fields[i + 1][3], next[i][3]);
            }
        }

        // 4.7 — mass conservation: Σ next.count·active == Σ prev.count·active
        // + record.active.
        let mut prev_mass = b.mul(prev[0][1], prev[0][3]);
        for j in 1..cap {
            let t = b.mul(prev[j][1], prev[j][3]);
            prev_mass = b.add(prev_mass, t);
        }
        let mut next_mass = b.mul(next[0][1], next[0][3]);
        for j in 1..cap {
            let t = b.mul(next[j][1], next[j][3]);
            next_mass = b.add(next_mass, t);
        }
        let ra = batch_fields[k][3];
        let want = b.add(prev_mass, ra);
        b.connect(next_mass, want);
    }

    #[allow(unused_mut)]
    let mut circuit = b.build().expect("build gk_naive circuit");
    // [test-only] malicious prover: swap in forged Permute outputs.
    #[cfg(test)]
    for (o, ts) in FORGE.with(|f| f.take()) {
        crate::sketch::forge_permute::forge_permute_outputs(&mut circuit, o, pack_op(&ts, o, op_tag));
    }

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

    // MUST match alloc order: states, batch, work tables, merge selectors,
    // then per-record per-F-slot max_error witnesses (interleaved in build
    // order: for each record k, for each j in 0..work_len).
    let mut private_inputs: Vec<Challenge> = Vec::new();
    #[allow(unused_mut)]
    let mut state_vals: Vec<Vec<Challenge>> =
        states.iter().map(|st| pack_tuples_to_challenge(st)).collect();
    #[cfg(test)]
    if TAMPER_FINAL.with(|c| c.get()) {
        state_vals[m][0] += Challenge::ONE;
    }
    for sv in &state_vals {
        private_inputs.extend_from_slice(sv);
    }
    private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
    for (k, w) in witnesses.iter().enumerate() {
        private_inputs.extend_from_slice(&pack_op(&w.work, 2 * k, op_tag));
    }
    let to_ch = |x: u32| if x == 0 { Challenge::ZERO } else { Challenge::ONE };
    for w in witnesses {
        for &mj in &w.merge_at {
            private_inputs.push(to_ch(mj));
        }
    }
    // f_max witnesses: for each record k, for each F slot j, the max_error
    // the circuit recomposes into F[j]. Non-absorbing slots use
    // (1−killed)·work[j].max_error; the absorbing slot uses the native
    // propagated value from `fused`.
    for w in witnesses {
        let fused = build_fused(&w.work, &w.merge_at);
        for j in 0..work_len {
            private_inputs.push(Challenge::from_u32(fused[j].max_error));
        }
    }
    // resorted_packed witnesses: for each record k, the re-sorted fused table
    // = resort(fused) = next ‖ [dropped dummy] (length cap+1).
    for (k, w) in witnesses.iter().enumerate() {
        let fused = build_fused(&w.work, &w.merge_at);
        let sf = resort_fused_sigma(&fused);
        let resorted: Vec<GKFullTuple> = sf.iter().map(|&i| fused[i]).collect();
        private_inputs.extend_from_slice(&pack_op(&resorted, 2 * k + 1, op_tag));
    }

    // ─── Run + prove ────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run gk_naive circuit")
    };
    let __witness = __t_w.elapsed();

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
        .expect("get_airs_and_degrees_with_prep (gk_naive)");
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
        .expect("prove_all_tables (gk_naive)");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover
        .verify_all_tables(&proof)
        .expect("self-verify gk_naive leaf");
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

/// Generate a GK epoch proof by naive replay, returning the proof and the
/// natively-computed final state. Mirrors `gk_final_full::generate_proof` so
/// callers can swap the two leaves and compare.
pub fn generate_proof_naive(
    params: GKFullParams,
    initial: GKFullState,
    batch: Vec<GKFullUpdate>,
) -> GKFullProof {
    params.validate();
    assert_eq!(initial.params, params);
    assert_eq!(batch.len(), params.batch);
    let final_state = apply_batch_gk_naive(&initial, &batch);
    let proof = prove_gk_naive(params, initial, batch);
    GKFullProof { proof, final_state }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::gk_final_full;

    /// Distinct increasing-ish values within 20 bits → forces inserts AND,
    /// once distinct count exceeds capacity, compressions.
    fn mixed_batch(_capacity: usize, batch: usize) -> Vec<GKFullUpdate> {
        (0..batch)
            .map(|i| {
                let v = ((i as u32) * 7 + 3) & 0x000F_FFFF;
                GKFullUpdate::real(v)
            })
            .collect()
    }

    fn run_round_trip(capacity: usize, batch_len: usize) {
        let params = GKFullParams { capacity, batch: batch_len };
        let initial = GKFullState::empty(params);
        let updates = mixed_batch(capacity, batch_len);

        // Native expected final via the same insert-then-merge replay the
        // circuit certifies.
        let expected_state = apply_batch_gk_naive(&initial, &updates);

        let result = generate_proof_naive(params, initial.clone(), updates.clone());

        assert_eq!(
            commit_gk_state(&expected_state).0,
            result.proof.final_.0,
            "committed final must equal natively-replayed (insert-then-merge) final"
        );
        assert_eq!(
            commit_gk_state(&result.final_state).0,
            result.proof.final_.0,
            "proof.final_state vs committed final mismatch"
        );
        assert_eq!(result.final_state.tuples.len(), capacity);
        let active: u64 = updates.iter().map(|u| u.active as u64).sum();
        assert_eq!(result.final_state.total_mass(), active);
    }

    #[test]
    fn round_trip() {
        // capacity=4, batch=8 — 8 distinct values into a cap-4 summary:
        // 4 inserts then 4 compressions.
        run_round_trip(4, 8);
        // capacity=8, batch=8 — wider state; inserts only (8 distinct == cap)
        // exercising the work PermuteAir + sortedness on a larger table.
        run_round_trip(8, 8);
    }

    /// Soundness gate: a proof claiming a WRONG final commitment must FAIL.
    #[test]
    fn tamper_rejected() {
        let params = GKFullParams { capacity: 4, batch: 8 };
        let initial = GKFullState::empty(params);
        let updates = mixed_batch(4, 8);

        TAMPER_FINAL.with(|c| c.set(false));
        let _ok = generate_proof_naive(params, initial.clone(), updates.clone());

        TAMPER_FINAL.with(|c| c.set(true));
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof_naive(params, initial.clone(), updates.clone())
        }));
        TAMPER_FINAL.with(|c| c.set(false));
        assert!(
            bad.is_err(),
            "corrupted final accepted — naive GK replay leaf is UNSOUND"
        );
    }

    /// Stronger soundness isolation: a replay that compresses a NON-minimum
    /// adjacent pair (everything else consistent) must be rejected purely by
    /// the per-compress minimality range-check (Stage 4.5), not by the hash
    /// binding. Proves the GK compress logic actually bites.
    #[test]
    fn tamper_nonmin_merge_rejected() {
        let params = GKFullParams { capacity: 4, batch: 8 };
        let initial = GKFullState::empty(params);
        // Three copies of value 10 (which the insert-then-merge replay does
        // NOT merge until forced) give a count-3 tuple, so a later
        // compression has DISTINCT adjacent-pair sums (the pair touching the
        // heavy tuple costs strictly more). That makes a non-minimum merge
        // genuinely detectable by the minimality range-check.
        let updates = vec![
            GKFullUpdate::real(10),
            GKFullUpdate::real(10),
            GKFullUpdate::real(10),
            GKFullUpdate::real(20),
            GKFullUpdate::real(30),
            GKFullUpdate::real(40),
            GKFullUpdate::real(50),
            GKFullUpdate::real(60),
        ];

        TAMPER_MERGE_NONMIN.with(|c| c.set(false));
        let _ok = generate_proof_naive(params, initial.clone(), updates.clone());

        TAMPER_MERGE_NONMIN.with(|c| c.set(true));
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_gk_naive(params, initial.clone(), updates.clone())
        }));
        TAMPER_MERGE_NONMIN.with(|c| c.set(false));
        assert!(
            bad.is_err(),
            "non-minimum merge accepted — merge-minimality range-check is UNSOUND"
        );
    }

    fn panic_msg(e: &Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "<non-string panic>".to_string()
        }
    }

    /// Run the malicious prover on a replay witness: `forge` = forged
    /// Permute outputs, `row_tag` = the test-only tag override.
    fn prove_forged(
        params: GKFullParams,
        initial: &GKFullState,
        batch: &[GKFullUpdate],
        states: &[Vec<GKFullTuple>],
        witnesses: &[StepWitness],
        tag: bool,
        forge: Vec<(usize, Vec<GKFullTuple>)>,
        row_tag: Option<(usize, usize, usize)>,
    ) -> std::thread::Result<GKFullLeafProof> {
        OP_TAG.with(|c| c.set(Some(tag)));
        FORGE.with(|f| *f.borrow_mut() = forge);
        ROW_TAG.with(|c| c.set(row_tag));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_gk_naive_witness(params, initial.clone(), batch.to_vec(), states, witnesses)
        }));
        OP_TAG.with(|c| c.set(None));
        FORGE.with(|f| f.borrow_mut().clear());
        ROW_TAG.with(|c| c.set(None));
        r
    }

    /// **Shared-PermuteBus forgery: record reordering.** Records `k0` and `k1`
    /// trade places between their insert permutes (ops `2k0`, `2k1`): step
    /// `k0`'s work table holds record `k1` and vice versa. Per op the multisets
    /// differ; only the union of all permute rows balances. Everything else is
    /// the honest replay of the reordered stream, so every per-step constraint
    /// (sortedness, forced min-cost merge, per-record mass `+1`) holds, and the
    /// certified final is the replay of a stream the batch commitment does not
    /// describe — the leaf's "every tuple of `S_{k+1}` traces back to
    /// `S_k ∪ {B[k]}`" claim is broken.
    ///
    /// Pre-fix (untagged permutes): ACCEPTED. With the `active`-coordinate op
    /// tag: REJECTED — (a) with the moved record tagged for the op that emits
    /// it (no matching input on the PermuteBus), and (b) with it tagged for its
    /// own op so the bus balances (the de-tagged `active` is not boolean).
    #[test]
    fn record_swap_forgery_rejected() {
        let params = GKFullParams { capacity: 4, batch: 8 };
        let initial = GKFullState::empty(params);
        let updates: Vec<GKFullUpdate> = [10u32, 50, 20, 60, 30, 70, 40, 80]
            .iter()
            .map(|&v| GKFullUpdate::real(v))
            .collect();
        let honest = apply_batch_gk_naive(&initial, &updates);
        let _honest_proof = prove_gk_naive(params, initial.clone(), updates.clone());

        // A swap of two records that changes the certified final.
        let (k0, k1, states, witnesses) = (0..params.batch)
            .flat_map(|a| (a + 1..params.batch).map(move |c| (a, c)))
            .find_map(|(k0, k1)| {
                let mut order = updates.clone();
                order.swap(k0, k1);
                let (st, w) = replay_batch(&initial, &order);
                (commit_gk_state(&GKFullState {
                    tuples: st[params.batch].clone(),
                    params,
                })
                .0 != commit_gk_state(&honest).0)
                    .then_some((k0, k1, st, w))
            })
            .expect("a record swap that changes the final state");
        println!(
            "[gk naive record swap] records {k0} (value {}) and {k1} (value {}) trade insert \
             permutes; forged final {:?} vs honest {:?}",
            updates[k0].value,
            updates[k1].value,
            states[params.batch],
            honest.tuples
        );
        let forge = vec![
            (2 * k0, witnesses[k0].work.clone()),
            (2 * k1, witnesses[k1].work.clone()),
        ];

        let pre = prove_forged(params, &initial, &updates, &states, &witnesses, false, forge.clone(), None);
        match &pre {
            Ok(_) => println!("[gk naive record swap] pre-fix: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[gk naive record swap] pre-fix: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the untagged circuit accepts the record swap");

        let post_a = prove_forged(params, &initial, &updates, &states, &witnesses, true, forge.clone(), None);
        match &post_a {
            Ok(_) => println!("[gk naive record swap] fixed (a): ACCEPTED"),
            Err(e) => println!("[gk naive record swap] fixed (a) emitting-op tag: REJECTED: {}", panic_msg(e)),
        }
        assert!(post_a.is_err(), "op tags must stop records trading insert permutes");

        // (b) the moved record k1 in step k0's work carries op 2k1's tag.
        let row = witnesses[k0]
            .work
            .iter()
            .position(|t| t.active == 1 && t.value == updates[k1].value)
            .expect("record k1 sits in step k0's work");
        let post_b = prove_forged(
            params,
            &initial,
            &updates,
            &states,
            &witnesses,
            true,
            forge,
            Some((2 * k0, row, 2 * k1)),
        );
        match &post_b {
            Ok(_) => println!("[gk naive record swap] fixed (b): ACCEPTED"),
            Err(e) => println!("[gk naive record swap] fixed (b) source-op tag: REJECTED: {}", panic_msg(e)),
        }
        assert!(post_b.is_err(), "a foreign op tag must fail the de-tagged boolean check");
    }

    /// Cost of the op tag (padded trace rows + one prove), pre-fix vs fixed.
    /// Run: `cargo test --release --lib greenwald_khanna_naive::tests::fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fix_overhead() {
        for &(capacity, batch) in &[(16usize, 16usize), (64, 16), (256, 16)] {
            let params = GKFullParams { capacity, batch };
            let updates: Vec<GKFullUpdate> = (0..batch)
                .map(|i| GKFullUpdate::real(((i as u32) * 11 + 5) & 0x000F_FFFF))
                .collect();
            for (label, tag) in [("pre-fix", false), ("op-tag", true)] {
                OP_TAG.with(|c| c.set(Some(tag)));
                let t = std::time::Instant::now();
                let _ = prove_gk_naive(params, GKFullState::empty(params), updates.clone());
                OP_TAG.with(|c| c.set(None));
                println!(
                    "[gk naive fix_overhead] cap={capacity} m={batch} {label:<8} trace_rows={} prove+verify={:?}",
                    crate::recursion::recursive::timing::take().trace_rows,
                    t.elapsed()
                );
            }
        }
    }

    #[test]
    #[ignore]
    fn timing_naive_vs_certified() {
        use std::time::Instant;
        let capacity = 16usize;
        println!();
        println!("gk naive replay vs gk_final_full certified — prove time");
        println!("=======================================================");
        println!("  capacity = {capacity}");
        println!();
        println!(
            "  {:>6}  {:>14}  {:>14}  {:>8}",
            "batch", "naive (ms)", "certified (ms)", "ratio"
        );
        for &batch in &[8usize, 16, 32, 64] {
            let params = GKFullParams { capacity, batch };
            let initial = GKFullState::empty(params);
            let updates: Vec<GKFullUpdate> = (0..batch)
                .map(|i| GKFullUpdate::real(((i as u32) * 11 + 5) & 0x000F_FFFF))
                .collect();

            let t1 = Instant::now();
            let _naive = generate_proof_naive(params, initial.clone(), updates.clone());
            let naive_ms = t1.elapsed().as_secs_f64() * 1e3;

            let t2 = Instant::now();
            let _cert = gk_final_full::generate_proof(params, updates.clone());
            let cert_ms = t2.elapsed().as_secs_f64() * 1e3;

            let ratio = naive_ms / cert_ms;
            println!("  {batch:>6}  {naive_ms:>14.1}  {cert_ms:>14.1}  {ratio:>7.2}x");
        }
    }
}

