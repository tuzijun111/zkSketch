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

/// Range for the count-sortedness diff. `count < 2^(COUNT_DIFF_BITS−1)`
/// so the unsigned diff `count[r+1] − count[r]` fits in `COUNT_DIFF_BITS`
/// bits; a "negative" diff wraps to ≈ p and overflows, soundly rejecting.
const COUNT_DIFF_BITS: usize = 22;

// ─── Types ─────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SsFullRow {
    pub key: u64,
    pub count: u32,
    pub active: u32,
}

impl SsFullRow {
    pub const fn real(key: u64, count: u32) -> Self {
        Self { key, count, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { key: 0, count: 0, active: 0 }
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
        Self { key, value, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { key: 0, value: 0, active: 0 }
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
        Self { rows: vec![SsFullRow::dummy(); params.capacity], params }
    }
    pub fn active_count(&self) -> usize {
        self.rows.iter().filter(|r| r.active == 1).count()
    }
    pub fn total_mass(&self) -> u64 {
        self.rows.iter().filter(|r| r.active == 1).map(|r| r.count as u64).sum()
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
            [Val::from_u32(lo), Val::from_u32(hi), Val::from_u32(r.count), Val::from_u32(r.active)]
        })
        .collect()
}

fn flat_batch_vals(batch: &[SsFullUpdate]) -> Vec<Val> {
    batch
        .iter()
        .flat_map(|u| {
            let (lo, hi) = key_lo_hi(u.key);
            [Val::from_u32(lo), Val::from_u32(hi), Val::from_u32(u.value), Val::from_u32(u.active)]
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

// ─── Native: batched top-s update ────────────────────────────────────────

/// One row of the combined (key-sorted) union, used to drive the
/// in-circuit group-by. The circuit reconstructs all of this from the
/// permutation witness, so only the permutations are surfaced.
struct SsBuild {
    /// `combined` = old rows ‖ batch rows (length cap+m), unsorted.
    combined: Vec<SsFullRow>,
    /// permutation σ_key with `key_sorted[i] = combined[σ_key[i]]`.
    sigma_key: Vec<usize>,
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
        combined.push(SsFullRow { key: u.key, count: u.value, active: u.active });
    }

    // key-sort (ascending by key_field; stable for determinism).
    let mut idx: Vec<usize> = (0..total).collect();
    idx.sort_by_key(|&i| key_field(combined[i].key));
    let sigma_key = idx.clone();
    let key_sorted: Vec<SsFullRow> = idx.iter().map(|&i| combined[i]).collect();

    // adjacency tags + running sum (count + active) over equal-key runs.
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
        seg_end[r] = if r + 1 == total || key_field(key_sorted[r + 1].key) != key_field(key_sorted[r].key) {
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

    // count-sort G by (active asc, count asc, key asc).
    let mut idx2: Vec<usize> = (0..total).collect();
    idx2.sort_by_key(|&i| (grouped[i].active, grouped[i].count, key_field(grouped[i].key)));
    let sigma_count = idx2.clone();
    let g_sorted: Vec<SsFullRow> = idx2.iter().map(|&i| grouped[i]).collect();

    SsBuild { combined, sigma_key, grouped, key_eq_tag, seg_end, sigma_count, g_sorted }
}

/// Apply the batched SpaceSaving top-`s` update natively, returning
/// `(s_new, residual)`. `s_new` = the top `capacity` candidates by count;
/// `residual` = the lower candidates + dummies (length `batch`).
pub fn apply_batch_ss_full(
    s_old: &SsFullState,
    batch: &[SsFullUpdate],
) -> (SsFullState, Vec<SsFullRow>) {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    assert_eq!(batch.len(), m);
    let b = build_ss(s_old, batch);
    let residual: Vec<SsFullRow> = b.g_sorted[..m].to_vec();
    let s_new: Vec<SsFullRow> = b.g_sorted[m..m + cap].to_vec();
    (SsFullState { rows: s_new, params: s_old.params }, residual)
}

// ─── Test-only soundness hook ─────────────────────────────────────────────
// When set, the prover corrupts the `g_sorted` table so it no longer
// matches the count-sort permute of `grouped`. Exercises whether the
// count-sort PermuteAir + sortedness + compaction reject a bogus
// post-retention table. Production callers never touch this.
#[cfg(test)]
thread_local! {
    static TAMPER_GSORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// ─── Prover ──────────────────────────────────────────────────────────────

/// Prove one SpaceSaving epoch with the full §G top-`s` pipeline enforced
/// in-circuit (see the module docstring).
pub fn prove_ss_full(
    params: SsFullParams,
    initial_state: SsFullState,
    batch: Vec<SsFullUpdate>,
) -> SsFullLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);

    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;

    // ─── Native side ────────────────────────────────────────────────────
    let (final_state, residual_rows) = apply_batch_ss_full(&initial_state, &batch);
    let build = build_ss(&initial_state, &batch);
    let initial_commit = commit_ss_state(&initial_state);
    let final_commit = commit_ss_state(&final_state);
    let batch_commit = commit_ss_batch(&batch);

    // Sanity: mass conservation.
    let init_mass = initial_state.total_mass();
    let batch_mass: u64 = batch.iter().filter(|u| u.active == 1).map(|u| u.value as u64).sum();
    let final_mass = final_state.total_mass();
    let residual_mass: u64 =
        residual_rows.iter().filter(|r| r.active == 1).map(|r| r.count as u64).sum();
    assert_eq!(final_mass + residual_mass, init_mass + batch_mass);

    // ─── Build circuit ──────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);

    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let two_pow_32 = b.alloc_const(Challenge::from_u64(1u64 << 32), "two_pow_32");

    // Private inputs (alloc order MUST match the packing below):
    //   init, final(=s_new), batch, key_sorted, grouped, g_sorted,
    //   residual, key_eq_tag, key_inv_diff.
    let init_packed: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("init_packed")).collect();
    let final_packed: Vec<ExprId> =
        (0..cap).map(|_| b.alloc_private_input("final_packed")).collect();
    let batch_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("batch_packed")).collect();
    let key_sorted_packed: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("key_sorted_packed")).collect();
    let grouped_packed: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("grouped_packed")).collect();
    let g_sorted_packed: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("g_sorted_packed")).collect();
    let residual_packed: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("residual_packed")).collect();
    let key_eq_tag: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("key_eq_tag")).collect();
    let key_inv_diff: Vec<ExprId> =
        (0..total).map(|_| b.alloc_private_input("key_inv_diff")).collect();

    // ─── Stage 1: commit bindings ───────────────────────────────────────
    let h_init = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &init_packed, true).expect("hash init");
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true).expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(h_final[i], final_pis[i]);
    }
    let h_batch = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true).expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(h_batch[i], batch_pis[i]);
    }

    // ─── Stage 2: decompose all packed sequences ────────────────────────
    let init_fields: Vec<Vec<ExprId>> =
        init_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d init")).collect();
    let final_fields: Vec<Vec<ExprId>> =
        final_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d final")).collect();
    let batch_fields: Vec<Vec<ExprId>> =
        batch_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d batch")).collect();
    let key_sorted_fields: Vec<Vec<ExprId>> =
        key_sorted_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d ks")).collect();
    let grouped_fields: Vec<Vec<ExprId>> =
        grouped_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d g")).collect();
    let g_sorted_fields: Vec<Vec<ExprId>> =
        g_sorted_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d gs")).collect();
    let residual_fields: Vec<Vec<ExprId>> =
        residual_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d res")).collect();

    // ─── Stage 3: boolean active-flag checks ────────────────────────────
    let bool_check = |b: &mut CircuitBuilder<Challenge>, a: ExprId| {
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    };
    for r in 0..cap {
        bool_check(&mut b, init_fields[r][3]);
        bool_check(&mut b, final_fields[r][3]);
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
    let ks_permuted = b.add_permute(&combined, build.sigma_key.clone()).expect("permute key-sort");
    for i in 0..total {
        b.connect(ks_permuted[i], key_sorted_packed[i]);
    }

    // ─── Stage 5: group-by-key (adjacency tags + running sum) ───────────
    // key_eq_tag[r] ∈ {0,1}, tag[0]=0. PoneglyphDB §4.3 constraints.
    let ks_keyfield: Vec<ExprId> =
        (0..total).map(|r| key_field_of(&mut b, &key_sorted_fields[r])).collect();
    bool_check(&mut b, key_eq_tag[0]);
    b.connect(key_eq_tag[0], zero);
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
    let mut acc_count: Vec<ExprId> = Vec::with_capacity(total);
    let mut acc_active: Vec<ExprId> = Vec::with_capacity(total);
    acc_count.push(key_sorted_fields[0][2]);
    acc_active.push(key_sorted_fields[0][3]);
    for r in 1..total {
        let carried_c = b.mul(key_eq_tag[r], acc_count[r - 1]);
        acc_count.push(b.add(key_sorted_fields[r][2], carried_c));
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
        // grouped[r].active: prover supplies it; enforce it is `se`-gated
        // and that count>0 ⇔ active=1 within the segment via the
        // `seg_active` witness = se·(acc_active>0). We bind active to a
        // prover value `g_active_native` already inside grouped_fields[r][3];
        // soundness for the count/active coupling comes from:
        //   active ∈ {0,1} (checked above is on g_sorted not grouped;
        //   add here), active ≤ se (no active outside a segment end), and
        //   count = se·acc_count ties the mass. A segment with acc_count>0
        //   must report active=1 to keep mass in S_new; acc_count=0 rows
        //   are harmless either way.
        bool_check(&mut b, grouped_fields[r][3]);
        // active ≤ se : active·(1−se) = 0  (active is 0 on non-segment-ends)
        let one_minus_se = b.sub(one, se);
        let act_outside = b.mul(grouped_fields[r][3], one_minus_se);
        b.connect(act_outside, zero);
        // key gating: grouped.key_lo/hi = active · key_sorted.key_lo/hi
        let want_key_lo = b.mul(key_sorted_fields[r][0], grouped_fields[r][3]);
        b.connect(grouped_fields[r][0], want_key_lo);
        let want_key_hi = b.mul(key_sorted_fields[r][1], grouped_fields[r][3]);
        b.connect(grouped_fields[r][1], want_key_hi);
    }

    // ─── Stage 6: count-sort G → g_sorted via PermuteAir ────────────────
    let cs_permuted = b.add_permute(&grouped_packed, build.sigma_count.clone()).expect("permute count-sort");
    for i in 0..total {
        b.connect(cs_permuted[i], g_sorted_packed[i]);
    }

    // ─── Stage 7: sortedness on g_sorted ────────────────────────────────
    // active monotone increasing (dummies first):
    for r in 0..total - 1 {
        let diff = b.sub(g_sorted_fields[r + 1][3], g_sorted_fields[r][3]);
        let one_minus = b.sub(one, diff);
        let prod = b.mul(diff, one_minus);
        b.connect(prod, zero);
    }
    // count monotone increasing across all adjacent pairs (count[r+1] ≥
    // count[r]); dummies have count 0 so the dummy→active boundary is also
    // non-negative — no gating needed.
    for r in 0..total - 1 {
        let diff = b.sub(g_sorted_fields[r + 1][2], g_sorted_fields[r][2]);
        let _bits = b
            .decompose_to_bits::<Val>(diff, COUNT_DIFF_BITS)
            .expect("decompose count diff");
    }

    // ─── Stage 8: compaction — residual ↔ g_sorted[..m], S_new ↔ g_sorted[m..] ─
    for i in 0..m {
        for k in 0..4 {
            b.connect(residual_fields[i][k], g_sorted_fields[i][k]);
        }
    }
    for i in 0..cap {
        for k in 0..4 {
            b.connect(final_fields[i][k], g_sorted_fields[m + i][k]);
        }
    }

    // ─── Stage 9: mass conservation ─────────────────────────────────────
    // Σ(init.count·active) + Σ(batch.value·active)
    //   = Σ(final.count·active) + Σ(residual.count·active).
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
    b.connect(in_mass, out_mass);

    let circuit = b.build().expect("build ss_full circuit");

    // ─── Pack public + private ──────────────────────────────────────────
    let init_commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(initial_commit.0));
    let final_commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(final_commit.0));
    let batch_commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(batch_commit.0));

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&init_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    public_inputs.extend_from_slice(&batch_commit_packed);

    // MUST match alloc order.
    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&pack_state_to_challenge(&initial_state));
    private_inputs.extend_from_slice(&pack_state_to_challenge(&final_state));
    private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
    let key_sorted_rows: Vec<SsFullRow> =
        build.sigma_key.iter().map(|&i| build.combined[i]).collect();
    private_inputs.extend_from_slice(&pack_rows_to_challenge(&key_sorted_rows));
    private_inputs.extend_from_slice(&pack_rows_to_challenge(&build.grouped));
    #[allow(unused_mut)]
    let mut g_sorted_vals = pack_rows_to_challenge(&build.g_sorted);
    // [test-only] corrupt the post-retention table to confirm the
    // count-sort PermuteAir + sortedness + compaction reject it.
    #[cfg(test)]
    if TAMPER_GSORTED.with(|c| c.get()) {
        g_sorted_vals[0] += Challenge::ONE;
    }
    private_inputs.extend_from_slice(&g_sorted_vals);
    private_inputs.extend_from_slice(&pack_rows_to_challenge(&residual_rows));
    // key_eq_tag
    for &t in &build.key_eq_tag {
        private_inputs.push(if t == 1 { Challenge::ONE } else { Challenge::ZERO });
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
    let _ = &build.seg_end; // segment ends are recomputed in-circuit from tags

    // ─── Run + prove ────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run ss_full circuit")
    };
    let __witness = __t_w.elapsed(); // witness_gen = trace generation only

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false)];
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
        .expect("get_airs_and_degrees_with_prep (ss_full)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_permute_table::<4>();
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove_all_tables (ss_full)");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify ss_full leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| d as u64).sum(),
    });

    SsFullLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
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
        let n: Option<usize> = std::env::var("V3_SWEEP_THREADS").ok().and_then(|s| s.parse().ok());
        let label = match n {
            Some(k) => format!("V3_SWEEP_THREADS={k}"),
            None => format!("Rayon default pool ({} threads)", rayon::current_num_threads()),
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
        let params = SsFullParams { capacity: 4, batch: 2 };
        let updates = vec![SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)];
        let result = generate_proof(params, updates);
        assert_eq!(commit_ss_state(&result.final_state).0, result.proof.final_.0);
        assert_eq!(result.final_state.total_mass(), 2);
    }

    /// In-circuit group-by: two records with the same key must sum into one
    /// candidate (count 2), and the proof certifies it.
    #[test]
    fn ss_full_in_circuit_grouping_sums_counts() {
        let params = SsFullParams { capacity: 4, batch: 2 };
        let updates = vec![SsFullUpdate::real(42, 1), SsFullUpdate::real(42, 1)];
        let result = generate_proof(params, updates);
        assert_eq!(commit_ss_state(&result.final_state).0, result.proof.final_.0);
        let actives: Vec<_> = result.final_state.rows.iter().filter(|r| r.active == 1).collect();
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
        let params = SsFullParams { capacity: 2, batch: 4 };
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
        let kept_counts: Vec<u32> = {
            let mut c: Vec<u32> = kept.iter().map(|r| r.count).collect();
            c.sort_unstable();
            c
        };
        assert_eq!(kept_counts, vec![3, 4], "the two largest counts are retained");
        // residual holds the lower candidates; mass is conserved.
        let res_mass: u64 = residual.iter().filter(|r| r.active == 1).map(|r| r.count as u64).sum();
        assert_eq!(s_new.total_mass() + res_mass, 1 + 2 + 3 + 4);

        let result = generate_proof(params, updates);
        assert_eq!(commit_ss_state(&result.final_state).0, result.proof.final_.0);
    }

    /// Soundness: a corrupted post-retention table (not the count-sort
    /// image of the grouped candidates) must be rejected by the PermuteAir
    /// + sortedness + compaction constraints.
    #[test]
    fn ss_full_soundness_rejects_bad_table() {
        let params = SsFullParams { capacity: 4, batch: 2 };
        let updates = vec![SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)];

        TAMPER_GSORTED.with(|c| c.set(false));
        let _ok = generate_proof(params, updates.clone());

        TAMPER_GSORTED.with(|c| c.set(true));
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(params, updates)
        }));
        TAMPER_GSORTED.with(|c| c.set(false));
        assert!(bad.is_err(), "corrupted g_sorted accepted — top-s constraints unsound");
    }

    #[test]
    #[ignore]
    fn ss_full_proving_time_with_different_active_counts() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = SsFullParams { capacity: 32, batch: 100 };
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
            println!("  active={active:>3} (of {:>3})   prove {elapsed:>10.2?}", params.batch);
        }
    }

    #[test]
    #[ignore]
    fn ss_full_proving_time_merge_two_leaves() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = SsFullParams { capacity: 32, batch: 100 };
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
        let params = SsFullParams { capacity: 32, batch: 100 };
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
}
