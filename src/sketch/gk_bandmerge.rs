//! **Faithful bounded-size Greenwald–Khanna band-merge** (the *real* GK, the
//! distinct-value quantile compression), per Gribelyuk–Sawettamalya–Wu–Yu 2024,
//! "Simple & Optimal Quantile Sketch: Combining Greenwald–Khanna with
//! Khanna–Greenwald" (§3, the toy algorithm whose COMPRESS is the band-merge;
//! this is the same variant the S³ streaming-MPC paper builds on, and the one
//! `zk1.tex` cites for the size bound).
//!
//! This is the genuine article, in contrast to [`crate::sketch::gk_final_full`]
//! (kept as a baseline), which only collapses *equal* values — an exact
//! per-value frequency aggregation, not a quantile sketch. Here we merge
//! **distinct** adjacent representatives under a rank-mass threshold and track
//! rank uncertainty, so the summary answers `ε`-approximate rank/quantile
//! queries.
//!
//! ### Tuple `(e, g, Δ, t)` (§2/§3 of the source)
//!
//! Each active representative `e` carries:
//! - `g = |S_e|`: the number of stream elements the representative covers
//!   (`Σ_{e_j ≤ e} g_j = r_min(e)`, the minimum possible rank).
//! - `Δ`: an upper bound on how many covered elements are actually smaller than
//!   `e` (rank uncertainty); `rank(e) ∈ [r_min(e), r_min(e) + Δ]`.
//! - `t`: the insertion time, used to direct fusions deterministically.
//!
//! **Main invariant (A2):** `g + Δ ≤ ⌊εt⌋` for every active tuple. As long as
//! this holds, the summary answers any rank query within additive `εN`
//! (Claim 5 of the source). We take the accuracy parameter `s = 1/ε`, so the
//! threshold is `θ_t = ⌊N_t / s⌋ = ⌊εN_t⌋`, with `N_t` the cumulative record
//! count. The certified leaves force `N_t` in-circuit (`= N_{t-1} + #active`
//! and `=` the mass of `S_t`) and, under the default binding, `θ_t = ⌊N_t/s⌋`
//! from it (`bind_theta`, revision B6(d)); `Binding::Legacy` keeps the pre-fix
//! free-`θ` circuit.
//!
//! ### Batch update
//!
//! 1. **Insert** (Alg 1): each active batch value `v` becomes a fresh tuple
//!    `(v, g=1, Δ = g_right + Δ_right − 1, t = N_{t-1}+ord)`, where `right` is its
//!    immediate successor in the value-sorted union (the paper's "neighbor
//!    initialization"; computed right-to-left so successive fresh tuples chain).
//! 2. **Compress** (Def 7 / Alg 2): merge an adjacent pair `(e_i, e_{i+1})`
//!    (value-sorted, so `e_i < e_{i+1}`) iff BOTH
//!    - `g_i + g_{i+1} + Δ_{i+1} ≤ θ_t`  (merging preserves invariant A2), and
//!    - `t_i > t_{i+1}`  (the younger, smaller-valued `e_i` folds into the older,
//!      larger-valued `e_{i+1}`, which survives).
//!    On merge: `g_{i+1} ← g_i + g_{i+1}`; `e_{i+1}, Δ_{i+1}, t_{i+1}` unchanged;
//!    `e_i` is deleted. Applied over `L_f = ⌈log₂ M⌉` parity-0 rounds with
//!    recompaction (a chain of `k` mergeable tuples contracts in `⌈log₂ k⌉`
//!    rounds; a merge only *raises* `g`, so it never unlocks a new merge —
//!    the eligible set shrinks monotonically, and the schedule is deterministic,
//!    hence canonical).
//! 3. **Compact** to the public capacity `s'` (survivors padded; an honest
//!    proof requires the survivor count `≤ s'`).
//!
//! ### Scope vs. the source
//!
//! This implements §3's COMPRESS — the real band-merge, which maintains A2 and
//! the additive-`εN` guarantee. The source's §4 adds a second "mirrored" sketch
//! over the reversed order to also bound the *worst-case space* at the optimal
//! `O(ε⁻¹ log εn)` (the "hard case"). We deploy a fixed public capacity `s'`
//! instead; the mirror is a further extension for worst-case-optimal space and
//! is not needed for correctness of the rank guarantee.

/// Value field width (`e < 2^E_BITS`); the top value `E_MAX` is reserved for
/// dummies so they sort to the BACK (keeping actives at positions `0,1,…`, which
/// makes the parity-0 pairing align exactly with the compacted native compress,
/// and keeps the value-ascending sortedness check globally clean).
const E_BITS: usize = 22;
pub const E_MAX: u32 = (1 << E_BITS) - 1;

/// A GK representative tuple. `g`/`delta` are rank-mass / rank-uncertainty;
/// `t` is the insertion time (fusion direction). A dummy is `(E_MAX,0,0,0)`
/// (`active = [g≠0]` is derived, not stored, in the circuit packing).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct GkbTuple {
    pub e: u32,
    pub g: u64,
    pub delta: u64,
    pub t: u64,
    pub active: u32,
}

impl GkbTuple {
    pub fn dummy() -> Self {
        Self {
            e: E_MAX,
            g: 0,
            delta: 0,
            t: 0,
            active: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GkbParams {
    /// Public summary capacity `s'` (fixed constant, as the other families).
    pub capacity: usize,
    /// Public per-batch capacity `m`.
    pub batch: usize,
    /// Accuracy parameter `s = 1/ε`; threshold `θ_t = ⌊N_t / s⌋`.
    pub s: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GkbState {
    /// Active representatives, value-sorted, padded to `capacity` with dummies.
    pub tuples: Vec<GkbTuple>,
    pub params: GkbParams,
    /// Cumulative record count `N` covered by this summary (`= Σ g` over actives).
    pub n: u64,
}

impl GkbState {
    pub fn empty(params: GkbParams) -> Self {
        Self {
            tuples: vec![GkbTuple::dummy(); params.capacity],
            params,
            n: 0,
        }
    }

    /// Active tuples in value order.
    pub fn actives(&self) -> Vec<GkbTuple> {
        self.tuples
            .iter()
            .copied()
            .filter(|t| t.active == 1)
            .collect()
    }

    /// Estimated rank of `x` = `Σ_{e_j ≤ x} g_j` (the `r_min` estimator of the
    /// largest representative `≤ x`). True rank is within additive `εN`.
    pub fn rank(&self, x: u32) -> u64 {
        self.tuples
            .iter()
            .filter(|t| t.active == 1 && t.e <= x)
            .map(|t| t.g)
            .sum()
    }
}

/// `L_f = ⌈log₂ total⌉` (rounds enough to contract any mergeable chain).
pub fn num_rounds(total: usize) -> usize {
    if total <= 1 {
        0
    } else {
        (usize::BITS - (total - 1).leading_zeros()) as usize
    }
}

/// Mergeable predicate (Def 7): both the invariant-preserving rank-mass bound
/// and the timestamp direction.
fn mergeable(a: &GkbTuple, b: &GkbTuple, theta: u64) -> bool {
    a.active == 1 && b.active == 1 && a.g + b.g + b.delta <= theta && a.t > b.t
}

/// Merge `a` (left, smaller value, younger) into `b` (right, larger value,
/// older): keep `b`'s value/Δ/t, fold `a`'s mass. (Alg 2.)
fn merge(a: &GkbTuple, b: &GkbTuple) -> GkbTuple {
    GkbTuple {
        e: b.e,
        g: a.g + b.g,
        delta: b.delta,
        t: b.t,
        active: 1,
    }
}

/// Apply the batch update to `s_old` with active batch values `batch_vals`
/// (each an inserted record). This is the single canonical compress — the
/// fixed-size (`total = cap+m`) parity-0 schedule the circuit certifies (via
/// [`build_bm`]); dummies carry value `E_MAX` and sort to the back so the active
/// prefix pairs `(0,1),(2,3),…` deterministically. Panics on the "hard case"
/// (compressed summary exceeds capacity — declare a larger `s'`).
pub fn apply_batch(s_old: &GkbState, batch_vals: &[u32]) -> GkbState {
    let b = build_bm(s_old, batch_vals);
    // Hard case: any active mass beyond the capacity slice means s' is too small.
    assert!(
        b.excess.iter().all(|t| !is_active(t)),
        "bounded-GK hard case: active survivors exceed capacity {} (declare a larger s')",
        s_old.params.capacity
    );
    GkbState {
        tuples: b.final_tuples,
        params: s_old.params,
        n: b.n_t,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// In-circuit certificate for the band-merge transition.
// ─────────────────────────────────────────────────────────────────────────

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

use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::bind::{self, Binding};

const LOG_FINAL_POLY_LEN: usize = 6;
/// Rank-mass / uncertainty / timestamp range (`g, Δ, t < 2^24`), so the merge
/// sums `g_i+g_{i+1}+Δ_{i+1} < 3·2^24 < 2^26` never approach `p ≈ 2^30.9`.
const MASS_BITS: usize = 24;
/// Comparison-gadget width (a real "negative" slack wraps to ≈ p ≫ 2^27).
const CMP_BITS: usize = 27;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GkbStateCommit(pub [Val; 8]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GkbBatchCommit(pub [Val; 8]);

pub struct GkbLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: GkbStateCommit,
    pub final_: GkbStateCommit,
    pub batch_commit: GkbBatchCommit,
    pub params: GkbParams,
}

pub struct GkbProof {
    pub proof: GkbLeafProof,
    pub final_state: GkbState,
}

// ── Packing: one Challenge per tuple = (e, g, Δ, t); active = [g≠0] derived ──

fn enc(t: &GkbTuple) -> Challenge {
    use p3_field::BasedVectorSpace;
    let coeffs = [
        Val::from_u32(t.e),
        Val::from_u32(t.g as u32),
        Val::from_u32(t.delta as u32),
        Val::from_u32(t.t as u32),
    ];
    Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
}

fn pack_tuples(ts: &[GkbTuple]) -> Vec<Challenge> {
    ts.iter().map(enc).collect()
}

/// The fresh tuples a batch inserts: active value `v` at position `j` →
/// `(v, g=1, Δ=0, t=N_prev+1+j)`; padding → `(E_MAX,0,0,0)`. These ARE the rows
/// fed to the union permute (as the group-by feeds its batch-as-tuples), so
/// committing them directly gives their coefficients WitnessChecks-bus creators
/// via the commit hash + decompose — no in-circuit derivation of a permute input.
pub fn fresh_tuples(vals: &[u32], m: usize, n_prev: u64) -> Vec<GkbTuple> {
    (0..m)
        .map(|j| {
            if j < vals.len() {
                GkbTuple {
                    e: vals[j],
                    g: 1,
                    delta: 0,
                    t: n_prev + 1 + j as u64,
                    active: 1,
                }
            } else {
                GkbTuple::dummy()
            }
        })
        .collect()
}

fn flat_tuples(ts: &[GkbTuple]) -> Vec<Val> {
    ts.iter()
        .flat_map(|t| {
            [
                Val::from_u32(t.e),
                Val::from_u32(t.g as u32),
                Val::from_u32(t.delta as u32),
                Val::from_u32(t.t as u32),
            ]
        })
        .collect()
}

pub fn commit_gkb_state(state: &GkbState) -> GkbStateCommit {
    let hasher = MyHash::new(make_perm());
    GkbStateCommit(hasher.hash_iter(flat_tuples(&state.tuples)))
}

pub fn commit_gkb_batch(vals: &[u32], m: usize, n_prev: u64) -> GkbBatchCommit {
    let hasher = MyHash::new(make_perm());
    GkbBatchCommit(hasher.hash_iter(flat_tuples(&fresh_tuples(vals, m, n_prev))))
}

// ── Witness-capturing fixed-size replay (mirrors the native compress) ──

fn is_active(t: &GkbTuple) -> bool {
    t.g != 0
}

/// One fixed-size (`total`) parity-0 fuse round: pairs `(2i,2i+1)`, decision
/// `e = mergeable`, `fused[2i] = (1−e)·left`, `fused[2i+1] = right + e·left.g`.
fn fuse_round_fixed(cur: &[GkbTuple], theta: u64) -> (Vec<GkbTuple>, Vec<u32>) {
    let total = cur.len();
    let mut fused = vec![GkbTuple::dummy(); total];
    let mut dec = Vec::with_capacity(total / 2);
    for i in 0..total / 2 {
        let a = cur[2 * i];
        let bb = cur[2 * i + 1];
        let e = mergeable(&a, &bb, theta);
        dec.push(e as u32);
        if e {
            fused[2 * i] = GkbTuple::dummy();
            fused[2 * i + 1] = merge(&a, &bb);
        } else {
            fused[2 * i] = a;
            fused[2 * i + 1] = bb;
        }
    }
    (fused, dec)
}

/// Resort a fused table by `(e, t)` — actives first (dummy value `E_MAX` sorts
/// last) — recompacting the merge-induced dummies to the back so the next
/// round's parity-0 pairing again lines up with the active prefix.
fn resort_fixed(fused: &[GkbTuple]) -> (Vec<GkbTuple>, Vec<usize>) {
    let mut idx: Vec<usize> = (0..fused.len()).collect();
    idx.sort_by_key(|&i| (fused[i].e, fused[i].t));
    let sorted = idx.iter().map(|&i| fused[i]).collect();
    (sorted, idx)
}

#[derive(Clone)]
struct BmRound {
    #[allow(dead_code)] // captured for reference; the circuit re-derives the decision from hints.
    decisions: Vec<u32>,
    fused: Vec<GkbTuple>,
    resorted: Vec<GkbTuple>,
    sigma: Vec<usize>,
}

#[derive(Clone)]
struct BmBuild {
    sigma_union: Vec<usize>,
    union_raw: Vec<GkbTuple>,
    union_init: Vec<GkbTuple>,
    rounds: Vec<BmRound>,
    final_tuples: Vec<GkbTuple>,
    excess: Vec<GkbTuple>,
    theta: u64,
    n_prev: u64,
    n_t: u64,
}

/// Replay the band-merge in fixed-size (`total = cap+m`) form, capturing every
/// intermediate table the circuit binds.
fn build_bm(s_old: &GkbState, batch_vals: &[u32]) -> BmBuild {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;
    let n_prev = s_old.n;
    let m_active = batch_vals.len() as u64;
    let n_t = n_prev + m_active;
    let theta = n_t / s_old.params.s;

    // combined = init tuples ‖ fresh-raw tuples (Δ=0), padded to `total`.
    let mut combined: Vec<GkbTuple> = s_old.tuples.clone();
    for j in 0..m {
        if j < batch_vals.len() {
            combined.push(GkbTuple {
                e: batch_vals[j],
                g: 1,
                delta: 0,
                t: n_prev + 1 + j as u64,
                active: 1,
            });
        } else {
            combined.push(GkbTuple::dummy());
        }
    }
    debug_assert_eq!(combined.len(), total);

    // value-sort → union_raw by (e, t): actives first (e < E_MAX), dummies last.
    let mut idx: Vec<usize> = (0..total).collect();
    idx.sort_by_key(|&i| (combined[i].e, combined[i].t));
    let sigma_union = idx.clone();
    let union_raw: Vec<GkbTuple> = idx.iter().map(|&i| combined[i]).collect();
    finish_bm(s_old, sigma_union, union_raw, n_prev, n_t, theta)
}

/// Everything after the union permute: neighbor-init, the `L_f` fuse/resort
/// rounds and the compaction, replayed from a given `union_raw` (honestly the
/// `(e,t)`-sorted union; a soundness test may hand in a forged one).
fn finish_bm(
    s_old: &GkbState,
    sigma_union: Vec<usize>,
    union_raw: Vec<GkbTuple>,
    n_prev: u64,
    n_t: u64,
    theta: u64,
) -> BmBuild {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = union_raw.len();

    // neighbor-init Δ for active fresh rows (right-to-left).
    let mut union_init = union_raw.clone();
    for i in (0..total).rev() {
        let fresh = is_active(&union_init[i]) && union_init[i].t > n_prev;
        if fresh {
            union_init[i].delta = if i + 1 < total {
                (union_init[i + 1].g + union_init[i + 1].delta).saturating_sub(1)
            } else {
                0
            };
        }
    }

    // L_f parity-0 fuse+resort rounds.
    let lf = num_rounds(total);
    let mut cur = union_init.clone();
    let mut rounds = Vec::with_capacity(lf);
    for _ in 0..lf {
        let (fused, decisions) = fuse_round_fixed(&cur, theta);
        let (resorted, sigma) = resort_fixed(&fused);
        rounds.push(BmRound {
            decisions,
            fused,
            resorted: resorted.clone(),
            sigma,
        });
        cur = resorted;
    }

    // Compact: actives first ⇒ final = first cap rows, excess = trailing m dummies.
    let final_tuples = cur[..cap].to_vec();
    let excess = cur[cap..cap + m].to_vec();

    BmBuild {
        sigma_union,
        union_raw,
        union_init,
        rounds,
        final_tuples,
        excess,
        theta,
        n_prev,
        n_t,
    }
}

// ── Forced comparison / is-nonzero gadgets ──────────────────────────────

/// Force boolean `cond = [x ≤ y]`, given both `x, y < 2^bits` (so a wrong
/// `cond` makes the witness wrap to ≈ p and fail the bit-decomposition).
fn force_le(
    b: &mut CircuitBuilder<Challenge>,
    cond: ExprId,
    x: ExprId,
    y: ExprId,
    one: ExprId,
    zero: ExprId,
    bits: usize,
) {
    let cm1 = b.sub(cond, one);
    let cbool = b.mul(cond, cm1);
    b.connect(cbool, zero); // cond ∈ {0,1}
    let ymx = b.sub(y, x);
    let hi = b.mul(cond, ymx); // cond·(y−x)
    let xmy = b.sub(x, y);
    let xmym1 = b.sub(xmy, one);
    let omc = b.sub(one, cond);
    let lo = b.mul(omc, xmym1); // (1−cond)·(x−y−1)
    let w = b.add(hi, lo);
    let _ = b.add_range_bits::<Val>(w, bits).expect("force_le range");
}

/// Return boolean `nz = [x ≠ 0]`, using the inverse hint `x_inv` (= 1/x, or 0).
fn force_nz(
    b: &mut CircuitBuilder<Challenge>,
    x: ExprId,
    x_inv: ExprId,
    one: ExprId,
    zero: ExprId,
) -> ExprId {
    let nz = b.mul(x, x_inv);
    let omn = b.sub(one, nz);
    let must0 = b.mul(x, omn);
    b.connect(must0, zero); // x·(1−nz)=0 ⇒ nz=1 when x≠0; nz = x·x_inv = 0 when x=0
    nz
}

// ── Fusion threshold θ_t = ⌊N_t / s⌋ (revision B6(d)) ────────────────────

/// Largest threshold the in-circuit θ binding admits: `⌊(2^MASS_BITS − 1)/s⌋`,
/// i.e. `θ` of any record count `N_t < 2^MASS_BITS` (the leaves' timestamp and
/// mass range, so it is not a new completeness limit).
pub(crate) fn theta_max(s: u64) -> u64 {
    ((1u64 << MASS_BITS) - 1) / s
}

/// **Bind the fusion threshold to the record count**: constrain
/// `θ = ⌊N_t / s⌋` in-circuit, from the in-circuit `N_t` (which the leaves
/// already force to `N_{t-1} + #active(B_t)` and to the mass of the committed
/// `S_t`). Before this, `θ` was a free public input read only by the fusion
/// comparisons (`force_le(cond, sum, θ)`), so a prover could raise it and
/// over-merge, breaking the `εN` rank guarantee (`tests::
/// gk2_inflated_theta_legacy_accepts_semantic_rejects`).
///
/// With `r = N_t − θ·s` the gadget range-checks, all at `MASS_BITS`
/// (byte-aligned, exact):
/// * `r ∈ [0, 2^24)` and `s − 1 − r ∈ [0, 2^24)`, so `r + (s−1−r) = s − 1`
///   holds over the integers (both `< 2^24`, the sum `< 2^25 < p`): `r ≤ s−1`;
/// * `θ ∈ [0, 2^24)` and `θ_max − θ ∈ [0, 2^24)`: `θ ≤ θ_max = ⌊(2^24−1)/s⌋`.
///
/// Then `θ·s + r ≤ 2^24 − 1 + s − 1 < p`, so `N_t ≡ θ·s + r (mod p)` is an
/// integer identity and `θ = ⌊N_t/s⌋`, `r = N_t mod s` are unique (the range
/// checks also pin `θ` and `r` to the base field). Honest witnesses exist for
/// every `N_t < 2^MASS_BITS`. Cost (`gk2_theta_bind_overhead`): 4 three-byte
/// range checks, +3 constants and +16 ALU rows; padded trace rows unchanged at
/// cap 16…256.
///
/// Generic over the field so the Goldilocks leaf
/// ([`crate::sketch::gk_bandmerge_gl`]) shares it.
pub(crate) fn bind_theta<BF, F>(b: &mut CircuitBuilder<F>, theta: ExprId, n_t: ExprId, s: u64)
where
    BF: p3_field::PrimeField64,
    F: p3_field::ExtensionField<BF>,
{
    assert!(
        (1..1u64 << MASS_BITS).contains(&s),
        "GK accuracy s = {s} must lie in [1, 2^{MASS_BITS})"
    );
    let s_c = b.alloc_const(F::from_u64(s), "gk_s");
    let s_m1 = b.alloc_const(F::from_u64(s - 1), "gk_s_minus_1");
    let th_max = b.alloc_const(F::from_u64(theta_max(s)), "gk_theta_max");
    let ts = b.mul(theta, s_c);
    let r = b.sub(n_t, ts); // N_t − θ·s
    b.add_range_bits::<BF>(r, MASS_BITS).expect("θ remainder ≥ 0");
    let y = b.sub(s_m1, r); // s − 1 − r
    b.add_range_bits::<BF>(y, MASS_BITS).expect("θ remainder < s");
    b.add_range_bits::<BF>(theta, MASS_BITS).expect("θ ≥ 0");
    let z = b.sub(th_max, theta); // θ_max − θ
    b.add_range_bits::<BF>(z, MASS_BITS).expect("θ ≤ θ_max");
}

// ── Prover ───────────────────────────────────────────────────────────────

// ── Op tags (shared-PermuteBus fix, revision Step 1) ──
//
// The fork concatenates every `add_permute` into ONE PermuteAir whose
// PermuteBus message is the 4 value coordinates only (no op id), so it proves
// only that the union of ALL permute inputs equals the union of ALL outputs.
// With every op on the same `(e,g,Δ,t)` encoding a prover could move a tuple
// out of one op and into another: e.g. a FRESH batch tuple leaves the union
// output (a dummy takes its slot), skips neighbor-init and every fuse round,
// and re-enters in the last round's resort output with its committed `Δ = 0`
// (`tests::gkb_shared_bus_forgery_rejected`). The round-resort ops therefore
// carry an op tag in the high bits of `t`: op `k` (0 = union, `r+1` = round
// `r`'s resort) encodes `t' = t + k·2^MASS_BITS`. The fused (input) side is
// built with the tag; the resorted (output) side is de-tagged and the de-tagged
// `t` range-checked `< 2^MASS_BITS`, so every element of op `k` lies in
// `[k·2^24, (k+1)·2^24)` and — the union's outputs being range-checked into
// class 0 — per-class counting forces per-op multiset equality.

/// Tag added to the `t` coordinate of every element of permute op `k`.
fn gkb_op_tag(k: usize) -> u64 {
    (k as u64) << MASS_BITS
}

/// Encode a one-sided tuple for permute op `k` (`t' = t + k·2^MASS_BITS`).
fn enc_op(t: &GkbTuple, k: usize) -> Challenge {
    use p3_field::BasedVectorSpace;
    let coeffs = [
        Val::from_u32(t.e),
        Val::from_u32(t.g as u32),
        Val::from_u32(t.delta as u32),
        Val::from_u64(t.t + gkb_op_tag(k)),
    ];
    Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
}

/// Pack a permuted table of op `k` (untagged when `op_tag` is off).
fn pack_tuples_op(ts: &[GkbTuple], k: usize, op_tag: bool) -> Vec<Challenge> {
    ts.iter()
        .map(|t| if op_tag { enc_op(t, k) } else { enc(t) })
        .collect()
}

/// Whether [`prove_gkb`] tags its round-resort permutes. Always on outside
/// tests; the soundness PoC builds the pre-fix circuit.
fn use_gkb_op_tag() -> bool {
    #[cfg(test)]
    if let Some(v) = GKB_OP_TAG.with(|c| c.get()) {
        return v;
    }
    true
}

#[cfg(test)]
thread_local! {
    /// Test-only override of [`use_gkb_op_tag`] (`Some(false)` = pre-fix circuit).
    static GKB_OP_TAG: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    /// Test-only malicious prover: `(k, tuples)` makes permute op `k` emit
    /// `tuples` (packed in op `k`'s encoding) instead of a permutation of its
    /// inputs. Consumed by the next [`prove_gkb_build`].
    static GKB_FORGE: std::cell::RefCell<Vec<(usize, Vec<GkbTuple>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// Test-only: `Some((round, row))` packs that resorted row (permute output
    /// AND private input) WITHOUT its op tag — a prover lying about the tag.
    static GKB_UNTAG_ROW: std::cell::Cell<Option<(usize, usize)>> =
        const { std::cell::Cell::new(None) };
}

/// [`pack_tuples_op`] for a round's resorted table, honoring the test-only
/// [`GKB_UNTAG_ROW`] override.
fn pack_resorted_op(ts: &[GkbTuple], round: usize, op_tag: bool) -> Vec<Challenge> {
    #[allow(unused_mut)]
    let mut v = pack_tuples_op(ts, round + 1, op_tag);
    #[cfg(test)]
    if let Some((rd, row)) = GKB_UNTAG_ROW.with(|c| c.get())
        && rd == round
    {
        v[row] = enc(&ts[row]);
    }
    v
}

pub fn prove_gkb(params: GkbParams, initial_state: GkbState, batch_vals: Vec<u32>) -> GkbLeafProof {
    prove_gkb_with(params, initial_state, batch_vals, bind::default_binding())
}

/// [`prove_gkb`] with an explicit [`Binding`]. `Semantic` / `Bound` constrain
/// the fusion threshold `θ = ⌊N_t/s⌋` in-circuit ([`bind_theta`]); `Legacy`
/// is the pre-fix circuit, byte-for-byte, whose `θ` is a free public input
/// (unsound: a prover may over-merge). The GK leaves have no in-circuit
/// coefficient re-binding, so `Bound` builds the same circuit as `Semantic`.
pub fn prove_gkb_with(
    params: GkbParams,
    initial_state: GkbState,
    batch_vals: Vec<u32>,
    binding: Binding,
) -> GkbLeafProof {
    assert!(batch_vals.len() <= params.batch);
    // ── Native side: replay + commitments ──
    let build = build_bm(&initial_state, &batch_vals);
    prove_gkb_build(params, initial_state, batch_vals, &build, binding)
}

/// Build, run, prove and self-verify the one-sided circuit for a (honest or
/// hand-crafted) band-merge witness.
fn prove_gkb_build(
    params: GkbParams,
    initial_state: GkbState,
    batch_vals: Vec<u32>,
    build: &BmBuild,
    binding: Binding,
) -> GkbLeafProof {
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    assert_eq!(total % 2, 0, "total = cap+m must be even");
    assert!(batch_vals.len() <= m);
    let op_tag = use_gkb_op_tag();

    let final_state = GkbState {
        tuples: build.final_tuples.clone(),
        params,
        n: build.n_t,
    };
    let initial_commit = commit_gkb_state(&initial_state);
    let final_commit = commit_gkb_state(&final_state);
    let batch_commit = commit_gkb_batch(&batch_vals, m, build.n_prev);
    let lf = num_rounds(total);
    let num_pairs = total / 2;
    // Every tagged `t' < (lf+1)·2^MASS_BITS` stays below p (no class wrap).
    assert!(gkb_op_tag(lf + 1) < 2_013_265_921, "too many rounds for the t-coordinate op tag");

    // ── Circuit ──
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    crate::recompose_binding::configure(&mut b);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);

    // Public inputs: init, final, batch commits (2 each) + θ, N_prev, N_t.
    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));
    let theta_pi = b.alloc_public_input("theta");
    let n_prev_pi = b.alloc_public_input("n_prev");
    let n_t_pi = b.alloc_public_input("n_t");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let e_max = b.alloc_const(Challenge::from_u64(E_MAX as u64), "e_max");

    // Private inputs (alloc order == packing order below).
    let init_packed: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("init")).collect();
    let final_packed: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("final")).collect();
    let batch_packed: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("batch")).collect();
    let union_raw_packed: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("union_raw"))
        .collect();
    // per-round pre-resort fused table (private; bound field-by-field below).
    let fused_packed: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| (0..total).map(|_| b.alloc_private_input("fused")).collect())
        .collect();
    let resorted_packed: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..total)
                .map(|_| b.alloc_private_input("resorted"))
                .collect()
        })
        .collect();
    let excess_packed: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("excess")).collect();
    // Hint witnesses.
    let is_fresh: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("is_fresh"))
        .collect();
    let cond1: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("cond1"))
                .collect()
        })
        .collect();
    let cond2: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("cond2"))
                .collect()
        })
        .collect();
    let a_inv: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("a_inv"))
                .collect()
        })
        .collect();
    let b_inv: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("b_inv"))
                .collect()
        })
        .collect();
    let g_inv_union: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("g_inv_union"))
        .collect();

    // ── Stage 1: commit bindings ──
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

    // ── Stage 2: decompose ──
    let dec = |b: &mut CircuitBuilder<Challenge>, p: ExprId| -> Vec<ExprId> {
        b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose")
    };
    // Every packed private input needs a WitnessChecks-bus creator, supplied by
    // decomposing it; the resulting fields must then be consumed (range-checked
    // or used in an ALU op) so they are not orphaned in turn.
    let init_f: Vec<Vec<ExprId>> = init_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let final_f: Vec<Vec<ExprId>> = final_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let batch_f: Vec<Vec<ExprId>> = batch_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let uraw_f: Vec<Vec<ExprId>> = union_raw_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let resort_f: Vec<Vec<Vec<ExprId>>> = resorted_packed
        .iter()
        .map(|round| round.iter().map(|&p| dec(&mut b, p)).collect())
        .collect();

    // ── Stage 3: union multiset ──
    // The committed batch IS the fresh-tuple table `(value, g, Δ, t)` inserted
    // this epoch (a real value → g=1,Δ=0,t=N_prev+1+ord; padding → the E_MAX
    // dummy), exactly like the group-by's batch-as-tuples. So the union is a
    // permutation of `init ‖ batch`, both committed private inputs.
    let mut combined: Vec<ExprId> = init_packed.clone();
    combined.extend(batch_packed.iter().copied());
    // Well-formedness of the fresh rows: g ∈ {0,1} (a singleton insert or a
    // dummy) and Δ = 0.
    for j in 0..m {
        let g = batch_f[j][1];
        let gm1 = b.sub(g, one);
        let gb = b.mul(g, gm1);
        b.connect(gb, zero);
        b.connect(batch_f[j][2], zero);
    }
    let union_perm = b
        .add_permute(&combined, build.sigma_union.clone())
        .expect("permute union");
    for i in 0..total {
        b.connect(union_perm[i], union_raw_packed[i]);
    }

    // ── Stage 4: union_raw range-checks + value sortedness (dummies e=E_MAX last) ──
    for r in 0..total {
        let _ = b
            .add_range_bits::<Val>(uraw_f[r][0], E_BITS)
            .expect("e range");
        let _ = b
            .add_range_bits::<Val>(uraw_f[r][1], MASS_BITS)
            .expect("g range");
        let _ = b
            .add_range_bits::<Val>(uraw_f[r][2], MASS_BITS)
            .expect("Δ range");
        let _ = b
            .add_range_bits::<Val>(uraw_f[r][3], MASS_BITS)
            .expect("t range");
    }
    for r in 0..total - 1 {
        let diff = b.sub(uraw_f[r + 1][0], uraw_f[r][0]);
        let _ = b
            .add_range_bits::<Val>(diff, E_BITS)
            .expect("union e sortedness");
    }

    // ── Stage 5: neighbor-init Δ (right-to-left) → union_init ──
    // is_fresh[r] = [t_r > N_prev] = [N_prev+1 ≤ t_r]; Δ_init[r] = fresh ?
    // (g_{r+1}+Δ_init[r+1]−1) : Δ_raw[r]. e/g/t unchanged from union_raw.
    let n_prev_p1 = b.add(n_prev_pi, one);
    for r in 0..total {
        force_le(
            &mut b,
            is_fresh[r],
            n_prev_p1,
            uraw_f[r][3],
            one,
            zero,
            MASS_BITS,
        );
    }
    // g_nz[r] = [g_r ≠ 0] (active), for the right-neighbor gate below.
    let mut g_nz: Vec<ExprId> = Vec::with_capacity(total);
    for r in 0..total {
        let nz = force_nz(&mut b, uraw_f[r][1], g_inv_union[r], one, zero);
        g_nz.push(nz);
    }
    let mut delta_init: Vec<ExprId> = vec![zero; total];
    for r in (0..total).rev() {
        // base = right-active ? (g_{r+1} + Δ_init[r+1] − 1) : 0
        // (a dummy right neighbor has g=0 ⇒ the native `saturating_sub(1)` gives
        //  0, so the gate must zero the −1 that field arithmetic would produce).
        let base = if r + 1 < total {
            let s = b.add(uraw_f[r + 1][1], delta_init[r + 1]);
            let sm1 = b.sub(s, one);
            b.mul(g_nz[r + 1], sm1)
        } else {
            zero
        };
        // Δ_init[r] = is_fresh·base + (1−is_fresh)·Δ_raw[r]
        let f_part = b.mul(is_fresh[r], base);
        let omf = b.sub(one, is_fresh[r]);
        let o_part = b.mul(omf, uraw_f[r][2]);
        delta_init[r] = b.add(f_part, o_part);
    }
    // union_init fields = (e, g, Δ_init, t) — built directly (no separate packed
    // private input to bind); the round loop consumes these, and every field is
    // already a bus creator (uraw_f from the Stage-4 range-checks, Δ_init an ALU
    // expression). This avoids an orphan packed value on the WitnessChecks bus.
    let uinit_f: Vec<Vec<ExprId>> = (0..total)
        .map(|r| vec![uraw_f[r][0], uraw_f[r][1], delta_init[r], uraw_f[r][3]])
        .collect();

    // ── Stage 6: L_f parity-0 fuse+resort rounds ──
    // `cur_f` starts as union_init; each round builds the fused payload with
    // FORCED merge decisions, PermuteAir-resorts it, and range-/sort-checks the
    // resorted table, which becomes `cur_f` for the next round.
    let mut cur_f: Vec<Vec<ExprId>> = uinit_f.clone();
    for round in 0..lf {
        // Op tag of this round's resort permute (op `round + 1`).
        let round_tag = b.alloc_const(Challenge::from_u64(gkb_op_tag(round + 1)), "gkb_op_tag");
        // this round's pre-resort fused table (private input, bound below).
        let fused_f: Vec<Vec<ExprId>> = fused_packed[round]
            .iter()
            .map(|&p| dec(&mut b, p))
            .collect();
        for k in 0..num_pairs {
            let a = cur_f[2 * k].clone();
            let bb = cur_f[2 * k + 1].clone();
            // cond1 = [a.g + b.g + b.Δ ≤ θ]
            let sab = b.add(a[1], bb[1]);
            let sum = b.add(sab, bb[2]);
            force_le(&mut b, cond1[round][k], sum, theta_pi, one, zero, CMP_BITS);
            // cond2 = [b.t + 1 ≤ a.t]  (i.e. a.t > b.t)
            let bt1 = b.add(bb[3], one);
            force_le(&mut b, cond2[round][k], bt1, a[3], one, zero, MASS_BITS);
            // both active
            let nz_a = force_nz(&mut b, a[1], a_inv[round][k], one, zero);
            let nz_b = force_nz(&mut b, bb[1], b_inv[round][k], one, zero);
            // e = cond1·cond2·nz_a·nz_b
            let e1 = b.mul(cond1[round][k], cond2[round][k]);
            let e2 = b.mul(e1, nz_a);
            let e = b.mul(e2, nz_b);
            let ome = b.sub(one, e);
            // bind f_lo (row 2k) = merged ? (E_MAX,0,0,0) : a
            let lo_e_a = b.mul(ome, a[0]);
            let lo_e_d = b.mul(e, e_max);
            let lo_e = b.add(lo_e_a, lo_e_d);
            let lo_g = b.mul(ome, a[1]);
            let lo_d = b.mul(ome, a[2]);
            let lo_t = b.mul(ome, a[3]);
            b.connect(fused_f[2 * k][0], lo_e);
            b.connect(fused_f[2 * k][1], lo_g);
            b.connect(fused_f[2 * k][2], lo_d);
            // fused rows are this round-op's permute INPUT: t carries the op tag.
            let lo_t_op = if op_tag { b.add(lo_t, round_tag) } else { lo_t };
            b.connect(fused_f[2 * k][3], lo_t_op);
            // bind f_hi (row 2k+1) = (b.e, b.g + e·a.g, b.Δ, b.t)
            let eag = b.mul(e, a[1]);
            let hi_g = b.add(bb[1], eag);
            b.connect(fused_f[2 * k + 1][0], bb[0]);
            b.connect(fused_f[2 * k + 1][1], hi_g);
            b.connect(fused_f[2 * k + 1][2], bb[2]);
            let hi_t_op = if op_tag { b.add(bb[3], round_tag) } else { bb[3] };
            b.connect(fused_f[2 * k + 1][3], hi_t_op);
        }
        // resort: PermuteAir(fused) == resorted[round]
        let perm = b
            .add_permute(&fused_packed[round], build.rounds[round].sigma.clone())
            .expect("permute resort");
        for i in 0..total {
            b.connect(perm[i], resorted_packed[round][i]);
        }
        // resorted range-checks + value sortedness (dummies E_MAX last). The
        // resorted rows are the op's permute OUTPUT: de-tag t and range-check
        // the de-tagged value, which pins every output into this op's class.
        let rs_t: Vec<ExprId> = (0..total)
            .map(|r| {
                if op_tag {
                    b.sub(resort_f[round][r][3], round_tag)
                } else {
                    resort_f[round][r][3]
                }
            })
            .collect();
        for r in 0..total {
            let _ = b
                .add_range_bits::<Val>(resort_f[round][r][0], E_BITS)
                .expect("rs e");
            let _ = b
                .add_range_bits::<Val>(resort_f[round][r][1], MASS_BITS)
                .expect("rs g");
            let _ = b
                .add_range_bits::<Val>(resort_f[round][r][2], MASS_BITS)
                .expect("rs Δ");
            let _ = b
                .add_range_bits::<Val>(rs_t[r], MASS_BITS)
                .expect("rs t");
        }
        for r in 0..total - 1 {
            let diff = b.sub(resort_f[round][r + 1][0], resort_f[round][r][0]);
            let _ = b
                .add_range_bits::<Val>(diff, E_BITS)
                .expect("rs sortedness");
        }
        cur_f = (0..total)
            .map(|r| {
                vec![
                    resort_f[round][r][0],
                    resort_f[round][r][1],
                    resort_f[round][r][2],
                    rs_t[r],
                ]
            })
            .collect();
    }

    // ── Stage 7: compaction — final = cur[..cap], excess = cur[cap..] ──
    // Range-check every final/excess field first: besides bounding the certified
    // state, this gives each decompose-output field a WitnessChecks-bus creator
    // so the field-by-field compaction connects below balance.
    let excess_f: Vec<Vec<ExprId>> = excess_packed.iter().map(|&p| dec(&mut b, p)).collect();
    for i in 0..cap {
        let _ = b
            .add_range_bits::<Val>(final_f[i][0], E_BITS)
            .expect("final e");
        let _ = b
            .add_range_bits::<Val>(final_f[i][1], MASS_BITS)
            .expect("final g");
        let _ = b
            .add_range_bits::<Val>(final_f[i][2], MASS_BITS)
            .expect("final Δ");
        let _ = b
            .add_range_bits::<Val>(final_f[i][3], MASS_BITS)
            .expect("final t");
    }
    for j in 0..m {
        let _ = b
            .add_range_bits::<Val>(excess_f[j][0], E_BITS)
            .expect("excess e");
        let _ = b
            .add_range_bits::<Val>(excess_f[j][1], MASS_BITS)
            .expect("excess g");
        let _ = b
            .add_range_bits::<Val>(excess_f[j][2], MASS_BITS)
            .expect("excess Δ");
        let _ = b
            .add_range_bits::<Val>(excess_f[j][3], MASS_BITS)
            .expect("excess t");
    }
    for i in 0..cap {
        for k in 0..4 {
            b.connect(final_f[i][k], cur_f[i][k]);
        }
    }
    for j in 0..m {
        for k in 0..4 {
            b.connect(excess_f[j][k], cur_f[cap + j][k]);
        }
    }

    // ── Stage 8: mass — Σ g over final = N_t; Σ g over excess = 0 ──
    let mut fmass = final_f[0][1];
    for i in 1..cap {
        fmass = b.add(fmass, final_f[i][1]);
    }
    b.connect(fmass, n_t_pi);
    let mut emass = excess_f[0][1];
    for j in 1..m {
        emass = b.add(emass, excess_f[j][1]);
    }
    b.connect(emass, zero);
    // N_t = N_prev + Σ active batch (g = active).
    let mut bsum = batch_f[0][1];
    for j in 1..m {
        bsum = b.add(bsum, batch_f[j][1]);
    }
    let np_plus_b = b.add(n_prev_pi, bsum);
    b.connect(np_plus_b, n_t_pi);
    // θ = ⌊N_t/s⌋ from the in-circuit N_t (revision B6(d); appended last so
    // the Legacy circuit is byte-for-byte the pre-fix one).
    if binding.is_bound() {
        bind_theta::<Val, Challenge>(&mut b, theta_pi, n_t_pi, params.s);
    }

    #[allow(unused_mut)]
    let mut circuit = b.build().expect("build gkb circuit");
    // [test-only] malicious prover: swap in forged Permute outputs.
    #[cfg(test)]
    for (k, ts) in GKB_FORGE.with(|f| f.take()) {
        let outs = if k == 0 {
            pack_tuples_op(&ts, 0, op_tag)
        } else {
            pack_resorted_op(&ts, k - 1, op_tag)
        };
        crate::sketch::forge_permute::forge_permute_outputs(&mut circuit, k, outs);
    }

    // ── Pack public + private ──
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
    public_inputs.push(Challenge::from_u64(build.theta));
    public_inputs.push(Challenge::from_u64(build.n_prev));
    public_inputs.push(Challenge::from_u64(build.n_t));

    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&pack_tuples(&initial_state.tuples));
    private_inputs.extend_from_slice(&pack_tuples(&final_state.tuples));
    private_inputs.extend_from_slice(&pack_tuples(&fresh_tuples(&batch_vals, m, build.n_prev)));
    private_inputs.extend_from_slice(&pack_tuples(&build.union_raw));
    for (round, rd) in build.rounds.iter().enumerate() {
        private_inputs.extend_from_slice(&pack_tuples_op(&rd.fused, round + 1, op_tag));
    }
    for (round, rd) in build.rounds.iter().enumerate() {
        private_inputs.extend_from_slice(&pack_resorted_op(&rd.resorted, round, op_tag));
    }
    private_inputs.extend_from_slice(&pack_tuples(&build.excess));
    // is_fresh
    for r in 0..total {
        let fresh = is_active(&build.union_raw[r]) && build.union_raw[r].t > build.n_prev;
        private_inputs.push(if fresh {
            Challenge::ONE
        } else {
            Challenge::ZERO
        });
    }
    // per-round hint witnesses — emitted GROUPED BY TYPE to match the alloc
    // order (all cond1, then all cond2, all a_inv, all b_inv), then g_inv_union.
    {
        use p3_field::Field;
        // `curs[round]` = the current table entering round `round`.
        let mut curs: Vec<Vec<GkbTuple>> = vec![build.union_init.clone()];
        for round in 0..lf {
            curs.push(build.rounds[round].resorted.clone());
        }
        let inv = |x: u64| {
            if x == 0 {
                Challenge::ZERO
            } else {
                Challenge::from_u64(x).inverse()
            }
        };
        // cond1 = [g_a+g_b+Δ_b ≤ θ]
        for round in 0..lf {
            for k in 0..num_pairs {
                let (a, bb) = (curs[round][2 * k], curs[round][2 * k + 1]);
                private_inputs.push(Challenge::from_u64(
                    (a.g + bb.g + bb.delta <= build.theta) as u64,
                ));
            }
        }
        // cond2 = [t_a > t_b]
        for round in 0..lf {
            for k in 0..num_pairs {
                let (a, bb) = (curs[round][2 * k], curs[round][2 * k + 1]);
                private_inputs.push(Challenge::from_u64((a.t > bb.t) as u64));
            }
        }
        // a_inv, b_inv
        for round in 0..lf {
            for k in 0..num_pairs {
                private_inputs.push(inv(curs[round][2 * k].g));
            }
        }
        for round in 0..lf {
            for k in 0..num_pairs {
                private_inputs.push(inv(curs[round][2 * k + 1].g));
            }
        }
        // g_inv_union
        for r in 0..total {
            private_inputs.push(inv(build.union_raw[r].g));
        }
    }

    // ── Run + prove ──
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set pub");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set priv");
        runner.run().expect("run gkb circuit")
    };
    let __witness = __t_w.elapsed();
    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
        permute_preprocessor::<Val>(),
        range_preprocessor::<Val>(),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("airs_and_degrees");
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
    let __t_p = std::time::Instant::now();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (gkb)");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover
        .verify_all_tables(&proof)
        .expect("self-verify gkb leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    GkbLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
}

/// Prove one band-merge epoch from empty, returning proof + final state.
pub fn generate_proof(params: GkbParams, batch_vals: Vec<u32>) -> GkbProof {
    let initial_state = GkbState::empty(params);
    let final_state = apply_batch(&initial_state, &batch_vals);
    let proof = prove_gkb(params, initial_state, batch_vals);
    GkbProof { proof, final_state }
}

// ══════════════════════════════════════════════════════════════════════════
// Two-sided §4 band-merge — the *optimal* Gribelyuk variant (§4, "combining
// Greenwald–Khanna with the mirrored Khanna–Greenwald"; the concrete batch form
// is the S³ streaming-MPC paper's Alg 5/6). The one-sided version above is
// Gribelyuk's §3 *toy* algorithm: it has the εN rank guarantee but **no space
// bound** — in the "hard case" (adjacent reps with the smaller value *older*,
// `t_i<t_{i+1}`) it can keep an unbounded number of non-mergeable pairs. The
// mirror handles exactly that case, so the two-sided sketch has a **provable
// `O(ε⁻¹ log εn)` space bound** (Gribelyuk Thm 11) and never rejects a hard case.
//
// Each representative `e` carries TWO (g, Δ) pairs, one per side:
//   `g  = |S_e|`  covered elements  `≺ e`  (left),  uncertainty `Δ`;
//   `g° = |S°_e|` covered elements  `≻ e`  (right), uncertainty `Δ°`.
// `e` itself is in neither set, so reps + sets partition the stream:
//   `Σ_active (g + g° + 1) = N`.
// Invariant (B2): `g+Δ ≤ ⌊εt⌋` AND `g°+Δ° ≤ ⌊εt⌋` on every active tuple, which
// makes the S³ rank estimator err by at most additive `εN`.
//
// This is the NATIVE algorithm (+ its ε/space verification). The in-circuit
// certificate for the two-sided tuple is a follow-on to the one-sided
// [`prove_gkb`] above (more fields and both fusion branches); the one-sided
// circuit remains the working ZK baseline.
// ══════════════════════════════════════════════════════════════════════════

/// A two-sided GK representative tuple `(e, g, g°, Δ, Δ°, t)`. A dummy is
/// `(E_MAX, 0,0,0,0, 0)` with `active = 0`, so it sorts to the back by `(e, t)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Gk2Tuple {
    pub e: u32,
    /// `g₁ = |S_e|`: rank mass of covered elements `≺ e` (left).
    pub g: u64,
    /// `g₂ = |S°_e|`: rank mass of covered elements `≻ e` (right).
    pub g_o: u64,
    /// `Δ₁`: uncertainty toward the right (value-successor) neighbor.
    pub delta: u64,
    /// `Δ₂`: uncertainty toward the left (value-predecessor) neighbor.
    pub delta_o: u64,
    pub t: u64,
    pub active: u32,
}

impl Gk2Tuple {
    pub fn dummy() -> Self {
        Self {
            e: E_MAX,
            g: 0,
            g_o: 0,
            delta: 0,
            delta_o: 0,
            t: 0,
            active: 0,
        }
    }
    /// Total mass this representative accounts for: its two sets plus itself.
    fn mass(&self) -> u64 {
        self.g + self.g_o + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gk2State {
    /// Active representatives, value-sorted, padded to `capacity` with dummies.
    pub tuples: Vec<Gk2Tuple>,
    pub params: GkbParams,
    /// Cumulative record count `N` (`= Σ (g + g° + 1)` over actives).
    pub n: u64,
}

impl Gk2State {
    pub fn empty(params: GkbParams) -> Self {
        Self {
            tuples: vec![Gk2Tuple::dummy(); params.capacity],
            params,
            n: 0,
        }
    }

    /// Active tuples in value order.
    pub fn actives(&self) -> Vec<Gk2Tuple> {
        self.tuples
            .iter()
            .copied()
            .filter(|t| t.active == 1)
            .collect()
    }

    /// S³ rank query (Alg 5): for the bracket `e_i ≤ q` (largest such `i`),
    /// return the interval `[r_min, r_max]` the true rank of `q` (number of
    /// stream elements `≤ q`) provably lies in. `r_min = P_i − g°_i − Δ°_i`,
    /// `r_max = P_i + g_{i+1} + Δ_{i+1}`, with prefix mass `P_i = Σ_{z≤i}(g+g°+1)`.
    /// By (B2) the width is `≤ 2εN`, so the midpoint errs by `≤ εN`.
    pub fn rank_interval(&self, q: u32) -> (u64, u64) {
        let a = self.actives(); // value-sorted
        let mut prefix = 0u64;
        let mut pi = 0u64;
        let mut bracket: Option<usize> = None;
        for (i, tup) in a.iter().enumerate() {
            prefix += tup.mass();
            if tup.e <= q {
                bracket = Some(i);
                pi = prefix;
            }
        }
        match bracket {
            None => (0, if a.is_empty() { 0 } else { a[0].g + a[0].delta }),
            Some(i) => {
                let r_min = pi.saturating_sub(a[i].g_o + a[i].delta_o);
                let r_max = if i + 1 < a.len() {
                    pi + a[i + 1].g + a[i + 1].delta
                } else {
                    pi
                };
                (r_min, r_max)
            }
        }
    }

    /// Midpoint rank estimate; true rank is within additive `εN`.
    pub fn rank(&self, q: u32) -> u64 {
        let (lo, hi) = self.rank_interval(q);
        (lo + hi) / 2
    }
}

fn is_active2(t: &Gk2Tuple) -> bool {
    t.active == 1
}

/// Two-sided mergeable test (Gribelyuk Alg 4 — authoritative over the Def 12
/// typo) for an adjacent value-sorted pair `a` (left) `< b` (right). Returns
/// `1` if `a` folds right into `b` (case `t_a>t_b`), `2` if `b` folds left into
/// `a` (case `t_a<t_b`), `0` if not mergeable. The threshold `εt = N_t/s` is
/// tested exactly by cross-multiplication, and in each case the tested sum is
/// precisely the survivor's post-merge `g+Δ` (resp. `g°+Δ°`), so a merge cannot
/// break invariant (B2).
#[allow(dead_code)] // clean per-pair reference for Alg 4; the batch driver is fuse_round_fixed2.
fn mergeable2(a: &Gk2Tuple, b: &Gk2Tuple, n_t: u64, s: u64) -> u8 {
    if !is_active2(a) || !is_active2(b) {
        return 0;
    }
    if a.t > b.t {
        // fold a into b: new b.g = a.g + a.g° + b.g + 1; need (·) + Δ_b ≤ εt.
        let lhs = a.g + a.g_o + b.g + b.delta + 1;
        if lhs * s <= n_t { 1 } else { 0 }
    } else {
        // a.t < b.t: fold b into a: new a.g° = b.g° + b.g + a.g° + 1; need (·) + Δ°_a ≤ εt.
        let lhs = b.g_o + b.g + a.g_o + a.delta_o + 1;
        if lhs * s <= n_t { 2 } else { 0 }
    }
}

/// Apply a two-sided merge `dir` (`1` or `2`) to `(a, b)`, returning
/// `(new_a, new_b)` with the folded-away member turned into a dummy.
#[allow(dead_code)] // clean per-pair reference for Alg 4; the batch driver is fuse_round_fixed2.
fn merge2(a: &Gk2Tuple, b: &Gk2Tuple, dir: u8) -> (Gk2Tuple, Gk2Tuple) {
    match dir {
        1 => {
            // a folds into b; b survives with grown LEFT mass g.
            let mut nb = *b;
            nb.g = a.g + a.g_o + b.g + 1;
            (Gk2Tuple::dummy(), nb)
        }
        2 => {
            // b folds into a; a survives with grown RIGHT mass g°.
            let mut na = *a;
            na.g_o = b.g_o + b.g + a.g_o + 1;
            (na, Gk2Tuple::dummy())
        }
        _ => (*a, *b),
    }
}

/// Apply a batch of inserted values to the two-sided sketch: union old ‖ fresh,
/// value-sort, two-sided neighbor-init, `L_f = ⌈log₂(cap+m)⌉` parity-0 fuse
/// rounds (re-sorting between rounds to recompact), then compact to capacity.
pub fn apply_batch2(s_old: &Gk2State, batch_vals: &[u32]) -> Gk2State {
    let b = build_bm2(s_old, batch_vals);
    // The two-sided sketch has no hard case, so a capacity ≥ the Gribelyuk bound
    // 2s·ln(N/s+2)+2 never overflows.
    debug_assert!(
        b.excess.iter().all(|t| !is_active2(t)),
        "two-sided sketch exceeded capacity {} (declare s' ≥ 2s·ln(N/s+2)+2)",
        s_old.params.capacity
    );
    Gk2State {
        tuples: b.final_tuples,
        params: s_old.params,
        n: b.n_t,
    }
}

/// One fixed-size parity-0 two-sided fuse round: pairs `(2i, 2i+1)`; per pair it
/// captures the two threshold booleans and the direction (`0` none, `1` a→b,
/// `2` b→a), and applies the merge. `theta = ⌊N_t/s⌋`.
fn fuse_round_fixed2(cur: &[Gk2Tuple], theta: u64) -> (Vec<Gk2Tuple>, Vec<u8>, Vec<u32>, Vec<u32>) {
    let total = cur.len();
    let mut fused = vec![Gk2Tuple::dummy(); total];
    let mut dirs = Vec::with_capacity(total / 2);
    let mut c1s = Vec::with_capacity(total / 2);
    let mut c2s = Vec::with_capacity(total / 2);
    for i in 0..total / 2 {
        let a = cur[2 * i];
        let bb = cur[2 * i + 1];
        // sum1 = g₁ₐ+g₂ₐ+g₁_b+Δ₁_b+1 (case-1 / newer-left survivor's post-merge g₁+Δ₁);
        // sum2 = g₂_b+g₁_b+g₂ₐ+Δ₂ₐ+1 (case-2 / newer-right survivor's post-merge g₂+Δ₂).
        let sum1 = a.g + a.g_o + bb.g + bb.delta + 1;
        let sum2 = bb.g_o + bb.g + a.g_o + a.delta_o + 1;
        let cond1 = (sum1 <= theta) as u32;
        let cond2 = (sum2 <= theta) as u32;
        let both = a.active == 1 && bb.active == 1;
        let dir: u8 = if !both {
            0
        } else if a.t > bb.t {
            if cond1 == 1 { 1 } else { 0 }
        } else if cond2 == 1 {
            2
        } else {
            0
        };
        c1s.push(cond1);
        c2s.push(cond2);
        dirs.push(dir);
        match dir {
            1 => {
                fused[2 * i] = Gk2Tuple::dummy();
                fused[2 * i + 1] = Gk2Tuple {
                    e: bb.e,
                    g: a.g + a.g_o + bb.g + 1,
                    g_o: bb.g_o,
                    delta: bb.delta,
                    delta_o: bb.delta_o,
                    t: bb.t,
                    active: 1,
                };
            }
            2 => {
                fused[2 * i] = Gk2Tuple {
                    e: a.e,
                    g: a.g,
                    g_o: bb.g_o + bb.g + a.g_o + 1,
                    delta: a.delta,
                    delta_o: a.delta_o,
                    t: a.t,
                    active: 1,
                };
                fused[2 * i + 1] = Gk2Tuple::dummy();
            }
            _ => {
                fused[2 * i] = a;
                fused[2 * i + 1] = bb;
            }
        }
    }
    (fused, dirs, c1s, c2s)
}

#[derive(Clone)]
struct Bm2Round {
    #[allow(dead_code)] // captured for reference; the circuit re-derives the direction from hints.
    dir: Vec<u8>,
    cond1: Vec<u32>,
    cond2: Vec<u32>,
    fused: Vec<Gk2Tuple>,
    resorted: Vec<Gk2Tuple>,
    sigma: Vec<usize>,
}

#[derive(Clone)]
struct Bm2Build {
    /// Tuple-level union permutation: `union_raw[i] = combined[sigma_union[i]]`.
    #[allow(dead_code)] // kept for reference; the circuit consumes `sigma_union_chal`.
    sigma_union: Vec<usize>,
    /// Challenge-level union permutation actually installed in the Permute op
    /// (honestly `expand_sigma(sigma_union)`; a soundness test may re-pair).
    sigma_union_chal: Vec<usize>,
    union_raw: Vec<Gk2Tuple>,
    union_init: Vec<Gk2Tuple>,
    rounds: Vec<Bm2Round>,
    final_tuples: Vec<Gk2Tuple>,
    excess: Vec<Gk2Tuple>,
    theta: u64,
    n_prev: u64,
    n_t: u64,
}

/// Witness-capturing fixed-size replay of the two-sided band-merge: captures
/// every intermediate table the circuit ([`prove_gkb2`]) binds.
fn build_bm2(s_old: &Gk2State, batch_vals: &[u32]) -> Bm2Build {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;
    let n_prev = s_old.n;
    let n_t = n_prev + batch_vals.len() as u64;
    let theta = n_t / s_old.params.s;

    // combined = init ‖ fresh singletons (g₁=g₂=0, Δ=0), padded to `total`.
    let mut combined: Vec<Gk2Tuple> = s_old.tuples.clone();
    for j in 0..m {
        if j < batch_vals.len() {
            combined.push(Gk2Tuple {
                e: batch_vals[j],
                g: 0,
                g_o: 0,
                delta: 0,
                delta_o: 0,
                t: n_prev + 1 + j as u64,
                active: 1,
            });
        } else {
            combined.push(Gk2Tuple::dummy());
        }
    }

    // value-sort by (e, t): actives first (e < E_MAX), dummies last.
    let mut idx: Vec<usize> = (0..total).collect();
    idx.sort_by_key(|&i| (combined[i].e, combined[i].t));
    let sigma_union = idx.clone();
    let union_raw: Vec<Gk2Tuple> = idx.iter().map(|&i| combined[i]).collect();
    let sigma_union_chal = expand_sigma(&sigma_union);
    finish_bm2(s_old, sigma_union, sigma_union_chal, union_raw, n_prev, n_t, theta)
}

/// Everything after the union permute: neighbor-init, the `L_f` fuse/resort
/// rounds and the compaction, replayed from a given `union_raw` (honestly the
/// `(e,t)`-sorted union; a soundness test may hand in a forged one).
fn finish_bm2(
    s_old: &Gk2State,
    sigma_union: Vec<usize>,
    sigma_union_chal: Vec<usize>,
    union_raw: Vec<Gk2Tuple>,
    n_prev: u64,
    n_t: u64,
    theta: u64,
) -> Bm2Build {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = union_raw.len();

    // two-sided neighbor-init: Δ₁ from the right (right-to-left), Δ₂ from the
    // left (left-to-right). A dummy neighbor has g=Δ=0 so contributes 0 (no gate
    // needed, unlike the one-sided toy's saturating −1).
    let mut union_init = union_raw.clone();
    for i in (0..total).rev() {
        if union_init[i].active == 1 && union_init[i].t > n_prev {
            union_init[i].delta = if i + 1 < total {
                union_init[i + 1].g + union_init[i + 1].delta
            } else {
                0
            };
        }
    }
    for i in 0..total {
        if union_init[i].active == 1 && union_init[i].t > n_prev {
            union_init[i].delta_o = if i >= 1 {
                union_init[i - 1].g_o + union_init[i - 1].delta_o
            } else {
                0
            };
        }
    }

    // L_f parity-0 fuse + resort rounds.
    let lf = num_rounds(total);
    let mut cur = union_init.clone();
    let mut rounds = Vec::with_capacity(lf);
    for _ in 0..lf {
        let (fused, dir, cond1, cond2) = fuse_round_fixed2(&cur, theta);
        let mut ridx: Vec<usize> = (0..total).collect();
        ridx.sort_by_key(|&i| (fused[i].e, fused[i].t));
        let resorted: Vec<Gk2Tuple> = ridx.iter().map(|&i| fused[i]).collect();
        rounds.push(Bm2Round {
            dir,
            cond1,
            cond2,
            fused,
            resorted: resorted.clone(),
            sigma: ridx,
        });
        cur = resorted;
    }

    let final_tuples = cur[..cap].to_vec();
    let excess = cur[cap..cap + m].to_vec();
    Bm2Build {
        sigma_union,
        sigma_union_chal,
        union_raw,
        union_init,
        rounds,
        final_tuples,
        excess,
        theta,
        n_prev,
        n_t,
    }
}

/// The Gribelyuk §4 worst-case space bound `s'(N) = ⌈2s·ln(N/s + 2) + 2⌉`.
pub fn gribelyuk_space_bound(n: u64, s: u64) -> usize {
    (2.0 * s as f64 * ((n as f64 / s as f64) + 2.0).ln() + 2.0).ceil() as usize
}

// ══════════════════════════════════════════════════════════════════════════
// Naive per-record replay of the TWO-SIDED §4 band-merge — the strawman
// baseline for [`prove_gkb2`]. It certifies the SAME two-sided algorithm proven
// a DIFFERENT way: instead of one batch-effect certificate, it literally
// re-executes the plaintext per-record update `S_0 → S_1 → … → S_m`, each record
// paying a `Θ(cap)` sorted insert + a `Θ(cap)` two-sided compress. Dominant cost
// `Θ(m·cap)` per batch — the cost-to-beat, the exact GK analog of Count-Min's
// replay strawman. It binds the SAME `commit_gk2_state`/`commit_gk2_batch` as
// `prove_gkb2`, so their proofs are directly cost-comparable. (The two schedules
// — per-record vs batch — are both valid two-sided GK updates but may reach
// different final states; the comparison is proving cost, not identical output.)
// ══════════════════════════════════════════════════════════════════════════

/// Per-record step witness for the naive replay.
#[derive(Clone)]
struct Naive2Step {
    /// `prev ‖ fresh`, sorted by `(e,t)`, fresh `Δ=0` (the permute output) —
    /// length `cap+1`.
    work: Vec<Gk2Tuple>,
    /// `work` with the fresh row's two-sided neighbor-init `Δ₁,Δ₂` set (the
    /// table the compress actually operates on; the circuit re-derives it).
    work_init: Vec<Gk2Tuple>,
    /// `work[j] = (prev ‖ fresh)[sigma_insert[j]]`.
    #[allow(dead_code)] // kept for reference; the circuit consumes `sigma_insert_chal`.
    sigma_insert: Vec<usize>,
    /// Challenge-level insert permutation actually installed in the Permute op
    /// (honestly `expand_sigma(sigma_insert)`; a soundness test may re-pair).
    sigma_insert_chal: Vec<usize>,
    /// The merged pair index (leftmost mergeable) when over capacity; else `cap`.
    merge_at: usize,
    /// Merge direction at `merge_at` (`0` none, `1` a→b, `2` b→a).
    dir: u8,
    /// `work` after the merge — length `cap+1`.
    fused: Vec<Gk2Tuple>,
    /// `fused` resorted by `(e,t)` — length `cap+1`.
    resorted: Vec<Gk2Tuple>,
    sigma_resort: Vec<usize>,
    /// `⌊N_k / s⌋` at this record (`N_k` = record count after this insert).
    theta: u64,
}

#[derive(Clone)]
struct Naive2Build {
    /// Threaded states `S_0 … S_m`, each `cap` tuples.
    states: Vec<Vec<Gk2Tuple>>,
    steps: Vec<Naive2Step>,
    n_prev: u64,
    n_final: u64,
}

/// Sort a `(prev ‖ fresh)` table by `(e,t)` and return `(sorted, sigma)` with
/// `sorted[j] = combined[sigma[j]]`.
fn sort_by_et2(combined: &[Gk2Tuple]) -> (Vec<Gk2Tuple>, Vec<usize>) {
    let mut idx: Vec<usize> = (0..combined.len()).collect();
    idx.sort_by_key(|&i| (combined[i].e, combined[i].t));
    let sorted = idx.iter().map(|&i| combined[i]).collect();
    (sorted, idx)
}

/// One naive per-record replay step. `n_after` = record count after this insert
/// (`= n_before + 1` for an active record, else `n_before`). Returns the step
/// witness and the next `cap`-tuple state.
fn replay_step2(
    prev: &[Gk2Tuple],
    cap: usize,
    s: u64,
    n_before: u64,
    val: Option<u32>,
) -> (Naive2Step, Vec<Gk2Tuple>) {
    let n_after = if val.is_some() {
        n_before + 1
    } else {
        n_before
    };
    let mut combined = prev.to_vec();
    combined.push(fresh_tuple2(val, n_after));
    let (work, sigma_insert) = sort_by_et2(&combined);
    let sigma_insert_chal = expand_sigma(&sigma_insert);
    finish_step2(work, sigma_insert, sigma_insert_chal, cap, s, n_after, val.is_some())
}

/// The fresh singleton a record inserts (or a dummy for a padding record).
fn fresh_tuple2(val: Option<u32>, n_after: u64) -> Gk2Tuple {
    match val {
        Some(v) => Gk2Tuple {
            e: v,
            g: 0,
            g_o: 0,
            delta: 0,
            delta_o: 0,
            t: n_after,
            active: 1,
        },
        None => Gk2Tuple::dummy(),
    }
}

/// Everything after the insert permute of one naive step (neighbor-init,
/// two-sided compress, resort), replayed from a given `work` table (honestly
/// the `(e,t)`-sorted `prev ‖ fresh`; a soundness test may hand in a forged one).
fn finish_step2(
    work: Vec<Gk2Tuple>,
    sigma_insert: Vec<usize>,
    sigma_insert_chal: Vec<usize>,
    cap: usize,
    s: u64,
    n_after: u64,
    has_val: bool,
) -> (Naive2Step, Vec<Gk2Tuple>) {
    let theta = n_after / s;
    // neighbor-init the fresh tuple (the one with t == n_after, if active).
    let mut work_init = work.clone();
    if has_val {
        let p = work_init
            .iter()
            .position(|t| t.active == 1 && t.t == n_after)
            .unwrap();
        // Δ₁ from the right (value-successor), Δ₂ from the left (predecessor).
        work_init[p].delta = if p + 1 < work_init.len() && work_init[p + 1].active == 1 {
            work_init[p + 1].g + work_init[p + 1].delta
        } else {
            0
        };
        work_init[p].delta_o = if p >= 1 && work_init[p - 1].active == 1 {
            work_init[p - 1].g_o + work_init[p - 1].delta_o
        } else {
            0
        };
    }

    // compress: if over capacity, merge the leftmost mergeable adjacent pair.
    let n_active = work_init.iter().filter(|t| t.active == 1).count();
    let mut merge_at = cap; // sentinel: no merge
    let mut dir = 0u8;
    let mut fused = work_init.clone();
    if n_active > cap {
        // find leftmost mergeable pair at threshold θ = ⌊n_after/s⌋.
        let mut found = None;
        for j in 0..cap {
            let d = mergeable2(&work_init[j], &work_init[j + 1], n_after, s);
            if d != 0 {
                found = Some((j, d));
                break;
            }
        }
        let (j, d) = found.expect("two-sided: a mergeable pair exists when over capacity");
        merge_at = j;
        dir = d;
        let (na, nb) = merge2(&work_init[j], &work_init[j + 1], d);
        fused[j] = na;
        fused[j + 1] = nb;
    }

    let (resorted, sigma_resort) = sort_by_et2(&fused);
    let next: Vec<Gk2Tuple> = resorted[..cap].to_vec();
    (
        Naive2Step {
            work,
            work_init,
            sigma_insert,
            sigma_insert_chal,
            merge_at,
            dir,
            fused,
            resorted,
            sigma_resort,
            theta,
        },
        next,
    )
}

/// Replay a whole batch per-record, capturing every intermediate state and step.
fn replay_batch2(s_old: &Gk2State, batch_vals: &[u32]) -> Naive2Build {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let s = s_old.params.s;
    let n_prev = s_old.n;

    let mut states: Vec<Vec<Gk2Tuple>> = Vec::with_capacity(m + 1);
    let mut steps: Vec<Naive2Step> = Vec::with_capacity(m);
    let mut cur = s_old.tuples.clone();
    let mut n = n_prev;
    states.push(cur.clone());
    for j in 0..m {
        let val = batch_vals.get(j).copied();
        let (step, next) = replay_step2(&cur, cap, s, n, val);
        if val.is_some() {
            n += 1;
        }
        cur = next;
        steps.push(step);
        states.push(cur.clone());
    }
    Naive2Build {
        states,
        steps,
        n_prev,
        n_final: n,
    }
}

/// Naive per-record replay as a plaintext state transition (the reference the
/// circuit certifies). Produces a valid two-sided GK final (possibly a different
/// merge schedule than [`apply_batch2`], but the same algorithm).
pub fn apply_batch2_naive(s_old: &Gk2State, batch_vals: &[u32]) -> Gk2State {
    let b = replay_batch2(s_old, batch_vals);
    Gk2State {
        tuples: b.states[b.states.len() - 1].clone(),
        params: s_old.params,
        n: b.n_final,
    }
}

/// The naive per-record replay leaf: certifies the same two-sided transition as
/// [`prove_gkb2`] by threading `S_0 → … → S_m` and re-executing each record's
/// insert + two-sided compress in-circuit — the `Θ(m·cap)` strawman baseline.
/// Binds the same `commit_gk2_state`/`commit_gk2_batch`. Per-step public scalars
/// `theta_k = ⌊N_k/s⌋` and `n_before_k`.
///
/// **Open gap (revision B6(d), not fixed here).** Unlike the certified leaves
/// ([`build_gkb2_leaf_expose_with`], [`prove_gkb_with`]), this baseline
/// constrains neither `theta_k` nor `n_before_k`: there is no count/mass
/// binding to derive them from, so both are free public inputs (a prover can
/// over-merge or corrupt the `is_fresh` gate). It is a cost baseline only; as
/// a proof it is unsound, and it is marginally cheaper than a sound replay
/// would be (so the certified-vs-naive ratio is, if anything, understated).
/// It ignores `ZKSKETCH_BINDING`.
pub fn prove_gkb2_naive(
    params: GkbParams,
    initial_state: Gk2State,
    batch_vals: Vec<u32>,
) -> Gk2LeafProof {
    assert!(batch_vals.len() <= params.batch);
    let build = replay_batch2(&initial_state, &batch_vals);
    prove_gkb2_naive_build(params, initial_state, batch_vals, &build)
}

/// Source bits of the naive replay's source-bound layout: `⌈log₂(cap+1)⌉`
/// (its `2m` permute ops need the rest of the coordinate for op ids).
fn naive2_src_bits(work_len: usize) -> usize {
    ((usize::BITS - (work_len - 1).leading_zeros()) as usize).max(1)
}

#[cfg(test)]
thread_local! {
    /// Test-only malicious prover: `(k, outputs)` makes permute op `k` of the
    /// naive replay emit `outputs` (raw challenges). Consumed by the next
    /// [`prove_gkb2_naive_build`].
    static NAIVE2_FORGE: std::cell::RefCell<Vec<(usize, Vec<Challenge>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Build, run, prove and self-verify the naive replay circuit for a (honest or
/// hand-crafted) replay witness.
///
/// **Source-bound permutes (revision Step 1, 2026-09-24).** The `2m` per-record
/// permutes (insert = op `2k`, resort = op `2k+1`) share ONE PermuteBus with no
/// op id, and each tuple is two challenges, so the committed layout let a prover
/// re-pair tuple halves inside an op (give a fresh value an old timestamp so it
/// skips neighbor-init — `tests::gk2_naive_half_repairing_forgery_rejected`,
/// accepted before this fix) and trade halves between records. Every permuted
/// table therefore uses [`build_gkb2_leaf`]'s source-bound layout
/// (`bind_coord_w`, with `⌈log₂(cap+1)⌉` source bits): each output tuple is
/// exactly one input tuple of the same op.
fn prove_gkb2_naive_build(
    params: GkbParams,
    initial_state: Gk2State,
    batch_vals: Vec<u32>,
    build: &Naive2Build,
) -> Gk2LeafProof {
    let cap = params.capacity;
    let m = params.batch;
    let work_len = cap + 1;
    assert!(batch_vals.len() <= m);
    let pair_bind = use_pair_bind();
    let sb = naive2_src_bits(work_len);
    assert!(
        bind_coord_w(2 * m, 1, (1 << sb) - 1, sb) < 2_013_265_921,
        "naive source-bound layout: too many records for the op-id range"
    );

    let final_state = Gk2State {
        tuples: build.states[m].clone(),
        params,
        n: build.n_final,
    };
    let initial_commit = commit_gk2_state(&initial_state);
    let final_commit = commit_gk2_state(&final_state);
    let batch_commit = commit_gk2_batch(&batch_vals, m, build.n_prev);

    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    crate::recompose_binding::configure(&mut b);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);

    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));
    let theta_pis: Vec<ExprId> = (0..m).map(|_| b.alloc_public_input("theta_k")).collect();
    let nbefore_pis: Vec<ExprId> = (0..m).map(|_| b.alloc_public_input("nbefore_k")).collect();

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let e_max = b.alloc_const(Challenge::from_u64(E_MAX as u64), "e_max");

    // Private inputs (2 challenges/tuple). Alloc order == packing order below.
    let state_packed: Vec<Vec<ExprId>> = (0..=m)
        .map(|_| {
            (0..2 * cap)
                .map(|_| b.alloc_private_input("state"))
                .collect()
        })
        .collect();
    let batch_packed: Vec<ExprId> = (0..2 * m).map(|_| b.alloc_private_input("batch")).collect();
    let work_packed: Vec<Vec<ExprId>> = (0..m)
        .map(|_| {
            (0..2 * work_len)
                .map(|_| b.alloc_private_input("work"))
                .collect()
        })
        .collect();
    let fused_packed: Vec<Vec<ExprId>> = (0..m)
        .map(|_| {
            (0..2 * work_len)
                .map(|_| b.alloc_private_input("fused"))
                .collect()
        })
        .collect();
    let resorted_packed: Vec<Vec<ExprId>> = (0..m)
        .map(|_| {
            (0..2 * work_len)
                .map(|_| b.alloc_private_input("resorted"))
                .collect()
        })
        .collect();
    // hints
    let is_fresh: Vec<Vec<ExprId>> = (0..m)
        .map(|_| {
            (0..work_len)
                .map(|_| b.alloc_private_input("is_fresh"))
                .collect()
        })
        .collect();
    let merge_sel: Vec<Vec<ExprId>> = (0..m)
        .map(|_| {
            (0..cap)
                .map(|_| b.alloc_private_input("merge_sel"))
                .collect()
        })
        .collect();
    let lt: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..cap).map(|_| b.alloc_private_input("lt")).collect())
        .collect();
    let cond1: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..cap).map(|_| b.alloc_private_input("cond1")).collect())
        .collect();
    let cond2: Vec<Vec<ExprId>> = (0..m)
        .map(|_| (0..cap).map(|_| b.alloc_private_input("cond2")).collect())
        .collect();
    let de_inv_work: Vec<Vec<ExprId>> = (0..m)
        .map(|_| {
            (0..work_len - 1)
                .map(|_| b.alloc_private_input("de_w"))
                .collect()
        })
        .collect();
    let de_inv_rs: Vec<Vec<ExprId>> = (0..m)
        .map(|_| {
            (0..work_len - 1)
                .map(|_| b.alloc_private_input("de_r"))
                .collect()
        })
        .collect();
    let e_inv_work: Vec<Vec<ExprId>> = (0..m)
        .map(|_| {
            (0..work_len)
                .map(|_| b.alloc_private_input("e_inv_w"))
                .collect()
        })
        .collect();

    // ── Stage 1: commit bindings (state[0]=init, state[m]=final, batch) ──
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

    let dec = |b: &mut CircuitBuilder<Challenge>, p: ExprId| -> Vec<ExprId> {
        b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose")
    };
    // ── Stage 2: decompose ──
    let state_f: Vec<Vec<Vec<ExprId>>> = state_packed
        .iter()
        .map(|st| st.iter().map(|&p| dec(&mut b, p)).collect())
        .collect();
    let batch_f: Vec<Vec<ExprId>> = batch_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let work_f: Vec<Vec<Vec<ExprId>>> = work_packed
        .iter()
        .map(|w| w.iter().map(|&p| dec(&mut b, p)).collect())
        .collect();
    let resort_f: Vec<Vec<Vec<ExprId>>> = resorted_packed
        .iter()
        .map(|w| w.iter().map(|&p| dec(&mut b, p)).collect())
        .collect();

    // batch well-formedness: fresh singleton g₁=g₂=Δ₁=Δ₂=0 + padding.
    for j in 0..m {
        b.connect(batch_f[2 * j][1], zero);
        b.connect(batch_f[2 * j][2], zero);
        b.connect(batch_f[2 * j][3], zero);
        b.connect(batch_f[2 * j + 1][0], zero);
        b.connect(batch_f[2 * j + 1][2], zero);
        b.connect(batch_f[2 * j + 1][3], zero);
    }

    // ── Stage 3: every threaded state is a well-formed value-sorted summary ──
    // `bind_op = Some(k)`: `f` is the OUTPUT of permute op `k` in the
    // source-bound layout (read with `fld6b`, halves bound to one source);
    // `None`: a committed-layout table (pads pinned to 0).
    let range_and_sort = |b: &mut CircuitBuilder<Challenge>,
                          f: &[Vec<ExprId>],
                          n: usize,
                          de_inv: Option<&[ExprId]>,
                          bind_op: Option<usize>| {
        for r in 0..n {
            let fl = if bind_op.is_some() { fld6b(f, r) } else { fld6(f, r) };
            let _ = b.add_range_bits::<Val>(fl[0], E_BITS).expect("e");
            let _ = b.add_range_bits::<Val>(fl[1], MASS_BITS).expect("g1");
            let _ = b.add_range_bits::<Val>(fl[2], MASS_BITS).expect("g2");
            let _ = b.add_range_bits::<Val>(fl[3], MASS_BITS).expect("d1");
            let _ = b.add_range_bits::<Val>(fl[4], MASS_BITS).expect("d2");
            let _ = b.add_range_bits::<Val>(fl[5], MASS_BITS).expect("t");
            if let Some(k) = bind_op {
                bind_output_pair_w(b, f, r, k, sb);
            } else {
                b.connect(f[2 * r + 1][2], zero);
                b.connect(f[2 * r + 1][3], zero);
            }
        }
        for r in 0..n - 1 {
            let diff = b.sub(f[2 * (r + 1)][0], f[2 * r][0]);
            let _ = b.add_range_bits::<Val>(diff, E_BITS).expect("e sort");
            if let Some(di) = de_inv {
                let nz = force_nz(b, diff, di[r], one, zero);
                let is0 = b.sub(one, nz);
                let dt = b.sub(f[2 * (r + 1) + 1][1], f[2 * r + 1][1]);
                let w = b.mul(is0, dt);
                let _ = b.add_range_bits::<Val>(w, MASS_BITS).expect("t tiebreak");
            }
        }
    };
    for t in 0..=m {
        range_and_sort(&mut b, &state_f[t], cap, None, None);
    }

    // ── Stage 4: per-record transition state[k] → state[k+1] ──
    for k in 0..m {
        // 4.1 insert: work = permute(state[k] ‖ batch[k]) (op 2k).
        let combined: Vec<ExprId> = if pair_bind {
            // Source-bound INPUT: tuple i of state[k] ‖ batch[k] re-encoded as
            // lo=(e,g₁,g₂,B(2k,0,i)), hi=(Δ₂,t,Δ₁,B(2k,1,i)) from its committed
            // coefficients (committed pads are pinned to 0: states by Stage 3,
            // the batch by its well-formedness above).
            let mut c = Vec::with_capacity(2 * work_len);
            for i in 0..work_len {
                let f: &[Vec<ExprId>] = if i < cap {
                    &state_f[k][2 * i..2 * i + 2]
                } else {
                    &batch_f[2 * k..2 * k + 2]
                };
                let b_lo = b.alloc_const(
                    Challenge::from_u64(bind_coord_w(2 * k, 0, i, sb)),
                    "bind_lo",
                );
                let b_hi = b.alloc_const(
                    Challenge::from_u64(bind_coord_w(2 * k, 1, i, sb)),
                    "bind_hi",
                );
                let lo = b
                    .recompose_base_coeffs_to_ext_via_alu::<Val>(&[f[0][0], f[0][1], f[0][2], b_lo])
                    .expect("bound lo");
                let hi = b
                    .recompose_base_coeffs_to_ext_via_alu::<Val>(&[f[1][0], f[1][1], f[0][3], b_hi])
                    .expect("bound hi");
                c.push(lo);
                c.push(hi);
            }
            c
        } else {
            let mut c: Vec<ExprId> = state_packed[k].clone();
            c.push(batch_packed[2 * k]);
            c.push(batch_packed[2 * k + 1]);
            c
        };
        let perm = b
            .add_permute(&combined, build.steps[k].sigma_insert_chal.clone())
            .expect("permute insert");
        for i in 0..2 * work_len {
            b.connect(perm[i], work_packed[k][i]);
        }
        let bind_ins = pair_bind.then_some(2 * k);
        let bind_rs = pair_bind.then_some(2 * k + 1);
        range_and_sort(&mut b, &work_f[k], work_len, Some(&de_inv_work[k]), bind_ins);
        // Δ₁ of work row r (committed layout: lo[3]; source-bound: hi[2]).
        let work_d1 = |r: usize| -> ExprId {
            if pair_bind {
                work_f[k][2 * r + 1][2]
            } else {
                work_f[k][2 * r][3]
            }
        };

        // 4.2 neighbor-init the fresh row → work_init (fresh Δ set two-sided).
        // is_fresh[r] = [t_r > n_before_k] = [n_before_k + 1 ≤ t_r].
        let nbefore_p1 = b.add(nbefore_pis[k], one);
        for r in 0..work_len {
            force_le(
                &mut b,
                is_fresh[k][r],
                nbefore_p1,
                work_f[k][2 * r + 1][1],
                one,
                zero,
                MASS_BITS,
            );
        }
        let mut d1: Vec<ExprId> = vec![zero; work_len];
        for r in (0..work_len).rev() {
            let base = if r + 1 < work_len {
                b.add(work_f[k][2 * (r + 1)][1], d1[r + 1])
            } else {
                zero
            };
            let fp = b.mul(is_fresh[k][r], base);
            let omf = b.sub(one, is_fresh[k][r]);
            let op = b.mul(omf, work_d1(r));
            d1[r] = b.add(fp, op);
        }
        let mut d2: Vec<ExprId> = vec![zero; work_len];
        for r in 0..work_len {
            let base = if r >= 1 {
                b.add(work_f[k][2 * (r - 1)][2], d2[r - 1])
            } else {
                zero
            };
            let fp = b.mul(is_fresh[k][r], base);
            let omf = b.sub(one, is_fresh[k][r]);
            let op = b.mul(omf, work_f[k][2 * r + 1][0]);
            d2[r] = b.add(fp, op);
        }
        let wi: Vec<[ExprId; 6]> = (0..work_len)
            .map(|r| {
                [
                    work_f[k][2 * r][0],
                    work_f[k][2 * r][1],
                    work_f[k][2 * r][2],
                    d1[r],
                    d2[r],
                    work_f[k][2 * r + 1][1],
                ]
            })
            .collect();

        // 4.3 compress: per pair compute the two-sided decision + merged tuples,
        // pick one via the one-hot merge_sel, build fused (selected pair merged,
        // others copied), force do_merge = [work over capacity].
        // per-position active from e (needed for do_merge + pair activeness).
        let mut act: Vec<ExprId> = Vec::with_capacity(work_len);
        for r in 0..work_len {
            let di = b.sub(e_max, wi[r][0]);
            act.push(force_nz(&mut b, di, e_inv_work[k][r], one, zero));
        }
        // merged_lo[j], merged_hi[j], mergeable[j] for each pair j.
        let mut merged_lo: Vec<[ExprId; 6]> = Vec::with_capacity(cap);
        let mut merged_hi: Vec<[ExprId; 6]> = Vec::with_capacity(cap);
        let mut mergeable: Vec<ExprId> = Vec::with_capacity(cap);
        for j in 0..cap {
            let a = wi[j];
            let bb = wi[j + 1];
            let bt1 = b.add(bb[5], one);
            force_le(&mut b, lt[k][j], bt1, a[5], one, zero, MASS_BITS);
            let s1a = b.add(a[1], a[2]);
            let s1b = b.add(bb[1], bb[3]);
            let s1 = b.add(s1a, s1b);
            let sum1 = b.add(s1, one);
            force_le(&mut b, cond1[k][j], sum1, theta_pis[k], one, zero, CMP_BITS);
            let s2a = b.add(bb[2], bb[1]);
            let s2b = b.add(a[2], a[4]);
            let s2 = b.add(s2a, s2b);
            let sum2 = b.add(s2, one);
            force_le(&mut b, cond2[k][j], sum2, theta_pis[k], one, zero, CMP_BITS);
            let ab = b.mul(act[j], act[j + 1]);
            let l1 = b.mul(lt[k][j], cond1[k][j]);
            let dir1 = b.mul(l1, ab);
            let omlt = b.sub(one, lt[k][j]);
            let l2 = b.mul(omlt, cond2[k][j]);
            let dir2 = b.mul(l2, ab);
            let mrg = b.add(dir1, dir2);
            mergeable.push(mrg);
            let omdir1 = b.sub(one, dir1);
            let omdir2 = b.sub(one, dir2);
            let omd12 = b.sub(omdir1, dir2);
            let new_hi_g1 = {
                let t1 = b.add(a[1], a[2]);
                let t2 = b.add(t1, bb[1]);
                b.add(t2, one)
            };
            let new_lo_g2 = {
                let t1 = b.add(bb[2], bb[1]);
                let t2 = b.add(t1, a[2]);
                b.add(t2, one)
            };
            let lo_e = {
                let x = b.mul(dir1, e_max);
                let y = b.mul(omdir1, a[0]);
                b.add(x, y)
            };
            let lo_g1 = b.mul(omdir1, a[1]);
            let lo_g2 = {
                let x = b.mul(dir2, new_lo_g2);
                let y = b.mul(omd12, a[2]);
                b.add(x, y)
            };
            let lo_d1 = b.mul(omdir1, a[3]);
            let lo_d2 = b.mul(omdir1, a[4]);
            let lo_t = b.mul(omdir1, a[5]);
            merged_lo.push([lo_e, lo_g1, lo_g2, lo_d1, lo_d2, lo_t]);
            let hi_e = {
                let x = b.mul(dir2, e_max);
                let y = b.mul(omdir2, bb[0]);
                b.add(x, y)
            };
            let hi_g1 = {
                let x = b.mul(dir1, new_hi_g1);
                let y = b.mul(omd12, bb[1]);
                b.add(x, y)
            };
            let hi_g2 = b.mul(omdir2, bb[2]);
            let hi_d1 = b.mul(omdir2, bb[3]);
            let hi_d2 = b.mul(omdir2, bb[4]);
            let hi_t = b.mul(omdir2, bb[5]);
            merged_hi.push([hi_e, hi_g1, hi_g2, hi_d1, hi_d2, hi_t]);
        }
        // merge_sel one-hot; selected pair must be mergeable; Σ = do_merge.
        let mut sel_sum = zero;
        for j in 0..cap {
            let sm1 = b.sub(merge_sel[k][j], one);
            let sb = b.mul(merge_sel[k][j], sm1);
            b.connect(sb, zero); // ∈{0,1}
            sel_sum = b.add(sel_sum, merge_sel[k][j]);
            let omm = b.sub(one, mergeable[j]);
            let must0 = b.mul(merge_sel[k][j], omm);
            b.connect(must0, zero); // selected ⇒ mergeable
        }
        // do_merge = [work over capacity] = [last slot active].
        b.connect(sel_sum, act[work_len - 1]);
        // build fused: fused[pos] = sel[pos]·merged_lo[pos] + sel[pos-1]·merged_hi[pos-1]
        //              + (1 − sel[pos] − sel[pos-1])·work_init[pos].
        let fused_f: Vec<Vec<ExprId>> = fused_packed[k].iter().map(|&p| dec(&mut b, p)).collect();
        for pos in 0..work_len {
            let sl = if pos < cap { merge_sel[k][pos] } else { zero };
            let sr = if pos >= 1 {
                merge_sel[k][pos - 1]
            } else {
                zero
            };
            let both = b.add(sl, sr);
            let keep = b.sub(one, both);
            for c in 0..6 {
                let lo_term = if pos < cap {
                    b.mul(sl, merged_lo[pos][c])
                } else {
                    zero
                };
                let hi_term = if pos >= 1 {
                    b.mul(sr, merged_hi[pos - 1][c])
                } else {
                    zero
                };
                let keep_term = b.mul(keep, wi[pos][c]);
                let s = b.add(lo_term, hi_term);
                let val = b.add(s, keep_term);
                // map field c → (challenge, coeff): 0..3 → lo[c], 4 → hi[0],
                // 5 → hi[1]; the source-bound layout moves Δ₁ (c = 3) to hi[2].
                let (ci, co) = if pair_bind && c == 3 {
                    (2 * pos + 1, 2)
                } else if c < 4 {
                    (2 * pos, c)
                } else {
                    (2 * pos + 1, c - 4)
                };
                b.connect(fused_f[ci][co], val);
            }
            if pair_bind {
                // fused = resort op 2k+1's INPUT: bind to input position `pos`.
                let b_lo = b.alloc_const(
                    Challenge::from_u64(bind_coord_w(2 * k + 1, 0, pos, sb)),
                    "bind_lo",
                );
                let b_hi = b.alloc_const(
                    Challenge::from_u64(bind_coord_w(2 * k + 1, 1, pos, sb)),
                    "bind_hi",
                );
                b.connect(fused_f[2 * pos][3], b_lo);
                b.connect(fused_f[2 * pos + 1][3], b_hi);
            } else {
                b.connect(fused_f[2 * pos + 1][2], zero);
                b.connect(fused_f[2 * pos + 1][3], zero);
            }
        }
        // 4.4 resort: resorted = permute(fused); range+sort+tiebreak.
        let permr = b
            .add_permute(&fused_packed[k], expand_sigma(&build.steps[k].sigma_resort))
            .expect("permute resort");
        for i in 0..2 * work_len {
            b.connect(permr[i], resorted_packed[k][i]);
        }
        range_and_sort(&mut b, &resort_f[k], work_len, Some(&de_inv_rs[k]), bind_rs);
        // 4.5 next state = resorted[..cap].
        for r in 0..cap {
            let sf = fld6(&state_f[k + 1], r);
            let rf = if pair_bind {
                fld6b(&resort_f[k], r)
            } else {
                fld6(&resort_f[k], r)
            };
            for c in 0..6 {
                b.connect(sf[c], rf[c]);
            }
        }
    }

    #[allow(unused_mut)]
    let mut circuit = b.build().expect("build gkb2_naive circuit");
    // [test-only] malicious prover: swap in forged Permute outputs.
    #[cfg(test)]
    for (k, outs) in NAIVE2_FORGE.with(|f| f.take()) {
        crate::sketch::forge_permute::forge_permute_outputs(&mut circuit, k, outs);
    }

    // ── Pack public + private ──
    let ip = pack_commit_to_challenge(&crate::commitment::CountMinCommit(initial_commit.0));
    let fp = pack_commit_to_challenge(&crate::commitment::CountMinCommit(final_commit.0));
    let bp = pack_commit_to_challenge(&crate::commitment::CountMinCommit(batch_commit.0));
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&ip);
    public_inputs.extend_from_slice(&fp);
    public_inputs.extend_from_slice(&bp);
    for step in &build.steps {
        public_inputs.push(Challenge::from_u64(step.theta));
    }
    // n_before per step = N before that record (n_prev + active count so far).
    {
        let mut nb = build.n_prev;
        for j in 0..m {
            public_inputs.push(Challenge::from_u64(nb));
            if batch_vals.get(j).is_some() {
                nb += 1;
            }
        }
    }

    let mut private_inputs: Vec<Challenge> = Vec::new();
    for st in &build.states {
        private_inputs.extend_from_slice(&pack_tuples2(st));
    }
    private_inputs.extend_from_slice(&pack_tuples2(&fresh_tuples2(&batch_vals, m, build.n_prev)));
    for (k, step) in build.steps.iter().enumerate() {
        private_inputs.extend_from_slice(&naive2_pack_work(step, k, pair_bind, sb));
    }
    let identity: Vec<usize> = (0..work_len).collect();
    for (k, step) in build.steps.iter().enumerate() {
        private_inputs.extend_from_slice(&if pair_bind {
            pack_bound2_w(&step.fused, 2 * k + 1, &identity, &identity, sb)
        } else {
            pack_tuples2(&step.fused)
        });
    }
    for (k, step) in build.steps.iter().enumerate() {
        private_inputs.extend_from_slice(&naive2_pack_resorted(step, k, pair_bind, sb));
    }
    {
        use p3_field::Field;
        let inv = |x: u64| {
            if x == 0 {
                Challenge::ZERO
            } else {
                Challenge::from_u64(x).inverse()
            }
        };
        // is_fresh per step (over work): [t > n_before_k].
        let mut nb = build.n_prev;
        for j in 0..m {
            let step = &build.steps[j];
            for r in 0..work_len {
                let fresh = step.work[r].active == 1 && step.work[r].t > nb;
                private_inputs.push(if fresh {
                    Challenge::ONE
                } else {
                    Challenge::ZERO
                });
            }
            if batch_vals.get(j).is_some() {
                nb += 1;
            }
        }
        // merge_sel one-hot.
        for step in &build.steps {
            for j in 0..cap {
                private_inputs.push(Challenge::from_u64((step.merge_at == j) as u64));
            }
        }
        // lt, cond1, cond2 per pair — on the neighbor-init'd work.
        for j in 0..m {
            let w = &build.steps[j].work_init;
            for p in 0..cap {
                let (a, bb) = (w[p], w[p + 1]);
                private_inputs.push(Challenge::from_u64((a.t > bb.t) as u64));
            }
        }
        for j in 0..m {
            let w = &build.steps[j].work_init;
            let theta = build.steps[j].theta;
            for p in 0..cap {
                let (a, bb) = (w[p], w[p + 1]);
                private_inputs.push(Challenge::from_u64(
                    (a.g + a.g_o + bb.g + bb.delta + 1 <= theta) as u64,
                ));
            }
        }
        for j in 0..m {
            let w = &build.steps[j].work_init;
            let theta = build.steps[j].theta;
            for p in 0..cap {
                let (a, bb) = (w[p], w[p + 1]);
                private_inputs.push(Challenge::from_u64(
                    (bb.g_o + bb.g + a.g_o + a.delta_o + 1 <= theta) as u64,
                ));
            }
        }
        // de_inv_work, de_inv_rs.
        for step in &build.steps {
            for r in 0..work_len - 1 {
                let de = (step.work[r + 1].e - step.work[r].e) as u64;
                private_inputs.push(inv(de));
            }
        }
        for step in &build.steps {
            for r in 0..work_len - 1 {
                let de = (step.resorted[r + 1].e - step.resorted[r].e) as u64;
                private_inputs.push(inv(de));
            }
        }
        // e_inv_work (over work_len).
        for step in &build.steps {
            for r in 0..work_len {
                private_inputs.push(inv((E_MAX - step.work[r].e) as u64));
            }
        }
    }

    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set pub");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set priv");
        runner.run().expect("run gkb2_naive circuit")
    };
    let __witness = __t_w.elapsed();
    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
        permute_preprocessor::<Val>(),
        range_preprocessor::<Val>(),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("airs_and_degrees");
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
    let __t_p = std::time::Instant::now();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (gkb2_naive)");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover
        .verify_all_tables(&proof)
        .expect("self-verify gkb2_naive leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    Gk2LeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
}

/// Pack step `k`'s `work` table (insert op `2k`'s OUTPUT): output halves name
/// the input position the challenge-level σ took them from.
fn naive2_pack_work(step: &Naive2Step, k: usize, pair_bind: bool, sb: usize) -> Vec<Challenge> {
    if !pair_bind {
        return pack_tuples2(&step.work);
    }
    let n = step.work.len();
    let src_lo: Vec<usize> = (0..n).map(|r| step.sigma_insert_chal[2 * r] / 2).collect();
    let src_hi: Vec<usize> = (0..n).map(|r| step.sigma_insert_chal[2 * r + 1] / 2).collect();
    pack_bound2_w(&step.work, 2 * k, &src_lo, &src_hi, sb)
}

/// Pack step `k`'s `resorted` table (resort op `2k+1`'s OUTPUT).
fn naive2_pack_resorted(step: &Naive2Step, k: usize, pair_bind: bool, sb: usize) -> Vec<Challenge> {
    if !pair_bind {
        return pack_tuples2(&step.resorted);
    }
    pack_bound2_w(&step.resorted, 2 * k + 1, &step.sigma_resort, &step.sigma_resort, sb)
}

/// Prove one naive two-sided replay epoch from empty, returning proof + state.
pub fn generate_proof2_naive(params: GkbParams, batch_vals: Vec<u32>) -> Gk2Proof {
    let initial_state = Gk2State::empty(params);
    let final_state = apply_batch2_naive(&initial_state, &batch_vals);
    let proof = prove_gkb2_naive(params, initial_state, batch_vals);
    Gk2Proof { proof, final_state }
}

// ── Two-sided in-circuit certificate ──────────────────────────────────────
//
// A two-sided tuple has SIX fields, but one `Challenge` (a degree-4 extension
// element) holds only four base coefficients, so each tuple is packed into TWO
// challenges: lo = (e, g₁, g₂, Δ₁), hi = (Δ₂, t, 0, 0). Tuple `r` therefore
// occupies challenge slots `2r, 2r+1`. Active detection can no longer use
// `[g≠0]` (a fresh singleton has g₁=g₂=0) — we use the value marker `[e≠E_MAX]`.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Gk2StateCommit(pub [Val; 8]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Gk2BatchCommit(pub [Val; 8]);

pub struct Gk2LeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: Gk2StateCommit,
    pub final_: Gk2StateCommit,
    pub batch_commit: Gk2BatchCommit,
    pub params: GkbParams,
}

pub struct Gk2Proof {
    pub proof: Gk2LeafProof,
    pub final_state: Gk2State,
}

/// Pack a tuple into two challenges: lo=(e,g₁,g₂,Δ₁), hi=(Δ₂,t,0,0).
fn enc2(t: &Gk2Tuple) -> [Challenge; 2] {
    use p3_field::BasedVectorSpace;
    let lo = [
        Val::from_u32(t.e),
        Val::from_u32(t.g as u32),
        Val::from_u32(t.g_o as u32),
        Val::from_u32(t.delta as u32),
    ];
    let hi = [
        Val::from_u32(t.delta_o as u32),
        Val::from_u32(t.t as u32),
        Val::ZERO,
        Val::ZERO,
    ];
    [
        Challenge::from_basis_coefficients_slice(&lo).expect("4 lo coeffs"),
        Challenge::from_basis_coefficients_slice(&hi).expect("4 hi coeffs"),
    ]
}

pub fn pack_tuples2(ts: &[Gk2Tuple]) -> Vec<Challenge> {
    ts.iter().flat_map(|t| enc2(t)).collect()
}

/// Flatten to base vals in the SAME order as the packed challenges' coeffs
/// (e,g₁,g₂,Δ₁,Δ₂,t,0,0 per tuple), so `hash_iter` matches the circuit hash.
fn flat_tuples2(ts: &[Gk2Tuple]) -> Vec<Val> {
    ts.iter()
        .flat_map(|t| {
            [
                Val::from_u32(t.e),
                Val::from_u32(t.g as u32),
                Val::from_u32(t.g_o as u32),
                Val::from_u32(t.delta as u32),
                Val::from_u32(t.delta_o as u32),
                Val::from_u32(t.t as u32),
                Val::ZERO,
                Val::ZERO,
            ]
        })
        .collect()
}

/// The fresh singletons a batch inserts: active value `v` → `(v,0,0,0,0,t)`;
/// padding → the E_MAX dummy. These ARE the rows fed to the union permute.
pub fn fresh_tuples2(vals: &[u32], m: usize, n_prev: u64) -> Vec<Gk2Tuple> {
    (0..m)
        .map(|j| {
            if j < vals.len() {
                Gk2Tuple {
                    e: vals[j],
                    g: 0,
                    g_o: 0,
                    delta: 0,
                    delta_o: 0,
                    t: n_prev + 1 + j as u64,
                    active: 1,
                }
            } else {
                Gk2Tuple::dummy()
            }
        })
        .collect()
}

pub fn commit_gk2_state(state: &Gk2State) -> Gk2StateCommit {
    let hasher = MyHash::new(make_perm());
    Gk2StateCommit(hasher.hash_iter(flat_tuples2(&state.tuples)))
}

pub fn commit_gk2_batch(vals: &[u32], m: usize, n_prev: u64) -> Gk2BatchCommit {
    let hasher = MyHash::new(make_perm());
    Gk2BatchCommit(hasher.hash_iter(flat_tuples2(&fresh_tuples2(vals, m, n_prev))))
}

/// Expand a tuple-permutation to the challenge-permutation that moves each
/// tuple's two challenges together.
fn expand_sigma(sigma: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(sigma.len() * 2);
    for &s in sigma {
        out.push(2 * s);
        out.push(2 * s + 1);
    }
    out
}

/// Read tuple `r`'s six fields `[e, g₁, g₂, Δ₁, Δ₂, t]` from a decomposed table
/// (`f[2r]` = lo coeffs, `f[2r+1]` = hi coeffs).
fn fld6(f: &[Vec<ExprId>], r: usize) -> [ExprId; 6] {
    [
        f[2 * r][0],
        f[2 * r][1],
        f[2 * r][2],
        f[2 * r][3],
        f[2 * r + 1][0],
        f[2 * r + 1][1],
    ]
}

// ── Source-bound permute layout (tuple-half re-pairing + shared-bus fix) ──
//
// The fork's PermuteAir proves only that the multiset of ALL permute-input
// challenges equals the multiset of ALL permute-output challenges (one
// PermuteBus, no op id), and each tuple is two challenges. With the committed
// layout lo=(e,g₁,g₂,Δ₁), hi=(Δ₂,t,0,0) a prover can re-pair halves across
// tuples inside one permute (and trade halves between permutes), e.g. give a
// fresh value an old timestamp so it skips neighbor-init
// (`tests::gk2_half_repairing_forgery_rejected`). The permuted tables
// (union_raw, fused, resorted) therefore use a SOURCE-BOUND layout:
//     lo = (e, g₁, g₂, B(k,0,i))      hi = (Δ₂, t, Δ₁, B(k,1,i))
// where `i` is the tuple's position in the INPUT of permute op `k` (0 = union,
// r+1 = round r's resort) and B(k,h,i) = i + (2k+h+1)·2^SRC_BITS. Every input
// element is thus unique and names (op, half, source). On the output side the
// circuit forces lo[3] = src + B(k,0,0), hi[3] = src + B(k,1,0) with the SAME
// range-checked `src < 2^SRC_BITS`, so each output tuple is exactly one input
// tuple of the same op (a bijection) — no re-pairing, no cross-op trading.
// Committed tables (init/final/batch/excess) keep the committed layout.

/// Bits reserved for a tuple's source position in the source-bound layout.
const SRC_BITS: usize = 20;

/// Binding coordinate of half `h` (0 = lo, 1 = hi) of the tuple at input
/// position `i` of permute op `k`.
fn bind_coord(k: usize, h: usize, i: usize) -> u64 {
    bind_coord_w(k, h, i, SRC_BITS)
}

/// [`bind_coord`] with `src_bits` reserved for the source position (the naive
/// replay, whose op count grows with the batch, uses `⌈log₂(cap+1)⌉`).
fn bind_coord_w(k: usize, h: usize, i: usize, src_bits: usize) -> u64 {
    i as u64 + (((2 * k + h + 1) as u64) << src_bits)
}

fn check_bind_range(total: usize, lf: usize) {
    assert!(
        total <= 1 << SRC_BITS,
        "source-bound layout supports cap+m ≤ 2^{SRC_BITS}"
    );
    // Every binding coordinate stays below p (no wrap between op ranges).
    assert!(bind_coord(lf, 1, (1 << SRC_BITS) - 1) < 2_013_265_921);
}

/// Read tuple `r`'s six fields `[e, g₁, g₂, Δ₁, Δ₂, t]` from a SOURCE-BOUND
/// table (`f[2r]` = `[e,g₁,g₂,B_lo]`, `f[2r+1]` = `[Δ₂,t,Δ₁,B_hi]`).
fn fld6b(f: &[Vec<ExprId>], r: usize) -> [ExprId; 6] {
    [
        f[2 * r][0],
        f[2 * r][1],
        f[2 * r][2],
        f[2 * r + 1][2],
        f[2 * r + 1][0],
        f[2 * r + 1][1],
    ]
}

/// Output-side binding for tuple `r` of permute op `k`: both halves name the
/// same source, `lo[3] = src + B(k,0,0)`, `hi[3] − lo[3] = 2^SRC_BITS`,
/// `src < 2^SRC_BITS`.
fn bind_output_pair(b: &mut CircuitBuilder<Challenge>, f: &[Vec<ExprId>], r: usize, k: usize) {
    bind_output_pair_w(b, f, r, k, SRC_BITS);
}

/// [`bind_output_pair`] with `src_bits` source bits (see [`bind_coord_w`]).
fn bind_output_pair_w(
    b: &mut CircuitBuilder<Challenge>,
    f: &[Vec<ExprId>],
    r: usize,
    k: usize,
    src_bits: usize,
) {
    let base_lo = b.alloc_const(
        Challenge::from_u64(bind_coord_w(k, 0, 0, src_bits)),
        "bind_base_lo",
    );
    let gap = b.alloc_const(
        Challenge::from_u64(bind_coord_w(k, 1, 0, src_bits) - bind_coord_w(k, 0, 0, src_bits)),
        "bind_gap",
    );
    let src = b.sub(f[2 * r][3], base_lo);
    let _ = b
        .add_range_bits::<Val>(src, src_bits)
        .expect("bind src range");
    let d = b.sub(f[2 * r + 1][3], f[2 * r][3]);
    b.connect(d, gap);
}

/// Connect fused tuple `p` of round-op `k` (a permute INPUT) to its computed
/// fields `v = [e, g₁, g₂, Δ₁, Δ₂, t]` in the table's layout.
fn connect_fused(
    b: &mut CircuitBuilder<Challenge>,
    fused_f: &[Vec<ExprId>],
    p: usize,
    v: [ExprId; 6],
    pair_bind: bool,
    k: usize,
    zero: ExprId,
) {
    connect_fused_w(b, fused_f, p, v, pair_bind, k, zero, SRC_BITS);
}

/// [`connect_fused`] with `src_bits` source bits (see [`bind_coord_w`]).
#[allow(clippy::too_many_arguments)]
fn connect_fused_w(
    b: &mut CircuitBuilder<Challenge>,
    fused_f: &[Vec<ExprId>],
    p: usize,
    v: [ExprId; 6],
    pair_bind: bool,
    k: usize,
    zero: ExprId,
    src_bits: usize,
) {
    b.connect(fused_f[2 * p][0], v[0]);
    b.connect(fused_f[2 * p][1], v[1]);
    b.connect(fused_f[2 * p][2], v[2]);
    b.connect(fused_f[2 * p + 1][0], v[4]);
    b.connect(fused_f[2 * p + 1][1], v[5]);
    if pair_bind {
        let b_lo = b.alloc_const(Challenge::from_u64(bind_coord_w(k, 0, p, src_bits)), "bind_lo");
        let b_hi = b.alloc_const(Challenge::from_u64(bind_coord_w(k, 1, p, src_bits)), "bind_hi");
        b.connect(fused_f[2 * p][3], b_lo);
        b.connect(fused_f[2 * p + 1][2], v[3]);
        b.connect(fused_f[2 * p + 1][3], b_hi);
    } else {
        b.connect(fused_f[2 * p][3], v[3]);
        b.connect(fused_f[2 * p + 1][2], zero);
        b.connect(fused_f[2 * p + 1][3], zero);
    }
}

/// Pack a permuted table in the source-bound layout; `src_lo[r]`/`src_hi[r]`
/// are the input positions the output tuple's lo/hi halves came from (equal
/// for an honest prover; the input tables use `src = r`).
fn pack_bound2(ts: &[Gk2Tuple], k: usize, src_lo: &[usize], src_hi: &[usize]) -> Vec<Challenge> {
    pack_bound2_w(ts, k, src_lo, src_hi, SRC_BITS)
}

/// [`pack_bound2`] with `src_bits` source bits (see [`bind_coord_w`]).
fn pack_bound2_w(
    ts: &[Gk2Tuple],
    k: usize,
    src_lo: &[usize],
    src_hi: &[usize],
    src_bits: usize,
) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    ts.iter()
        .enumerate()
        .flat_map(|(r, t)| {
            let lo = [
                Val::from_u32(t.e),
                Val::from_u32(t.g as u32),
                Val::from_u32(t.g_o as u32),
                Val::from_u64(bind_coord_w(k, 0, src_lo[r], src_bits)),
            ];
            let hi = [
                Val::from_u32(t.delta_o as u32),
                Val::from_u32(t.t as u32),
                Val::from_u32(t.delta as u32),
                Val::from_u64(bind_coord_w(k, 1, src_hi[r], src_bits)),
            ];
            [
                Challenge::from_basis_coefficients_slice(&lo).expect("4 lo coeffs"),
                Challenge::from_basis_coefficients_slice(&hi).expect("4 hi coeffs"),
            ]
        })
        .collect()
}

/// Whether [`build_gkb2_leaf`] uses the source-bound layout. Always on
/// outside tests.
fn use_pair_bind() -> bool {
    #[cfg(test)]
    if let Some(v) = PAIR_BIND.with(|c| c.get()) {
        return v;
    }
    true
}

#[cfg(test)]
thread_local! {
    /// Test-only tamper: override the public `N_prev` fed to the circuit while
    /// keeping the honest witness, to PoC-verify audit fix #3. Thread-local, so
    /// it is isolated per test thread (parallel-safe).
    static TAMPER_NPREV: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    /// Test-only override of [`use_pair_bind`] (`Some(false)` = pre-fix layout).
    static PAIR_BIND: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// The two-sided band-merge transition circuit.
///
/// ### Soundness (adversarial audit, 2026-07-05)
/// A 5-lens audit closed three two-sided-specific holes, each with a regression
/// test: **#4A** a poisoned final-slice dummy (`e=E_MAX`, `g≠0`) is now forced to
/// `(1−active)·g=0` (`gk2_poisoned_dummy_rejected`); **#3/#4B** `N_t` is bound to
/// `N_prev + #active-batch` (`gk2_wrong_n_prev_rejected`), matching the one-sided
/// circuit and pinning the `is_fresh` gate; **#5** an `(e,t)` tiebreak on every
/// sortedness check pins equal-value ordering (no two accepting finals). The
/// forced-decision arithmetic (lt/cond/active → dir1/dir2, survivor updates) was
/// verified canonical.
///
/// **Tuple-half re-pairing (revision Step 1, 2026-09-24).** Each tuple is two
/// permuted challenges and the fork's PermuteBus is shared by all permutes with
/// no op id, so the committed layout let a prover re-pair lo/hi halves (and
/// trade halves between permutes): swapping the hi halves of an old and a fresh
/// tuple was ACCEPTED and broke the rank guarantee
/// (`gk2_half_repairing_forgery_rejected`). The permuted tables now use the
/// source-bound layout (see `bind_coord`), which forces every output tuple to be
/// exactly one input tuple of the same op.
///
/// **Threshold (revision B6(d), 2026-09-24).** The threshold `θ` used to be a
/// free public input "assumed to equal `⌊N_t/s⌋` (cross-checked by the
/// streaming-forest log)"; nothing checked it, and an inflated `θ` over-merged
/// and was ACCEPTED (`gk2_inflated_theta_legacy_accepts_semantic_rejects`).
/// Under the default binding the circuit now forces `θ = ⌊N_t/s⌋` from the
/// in-circuit `N_t` ([`bind_theta`]); `Binding::Legacy` keeps the pre-fix
/// circuit for side-by-side runs.
///
/// One residual assumption remains, **shared with the one-sided `prove_gkb`**
/// and standard for these leaves: the Stage-8 mass sum `Σ(g₁+g₂)` is a field
/// add that could wrap `p` only for a *crafted* init with `Θ(cap)` maximal `g`
/// values — unreachable in the chained forest, whose init is the prior
/// canonical state (mass conserved from an empty epoch 1).
pub fn prove_gkb2(
    params: GkbParams,
    initial_state: Gk2State,
    batch_vals: Vec<u32>,
) -> Gk2LeafProof {
    prove_gkb2_inner(params, initial_state, batch_vals, false)
}

/// Like [`prove_gkb2`] but also surfaces the `(initial, final)` boundary via the
/// Expose NPO, so the proof's public values carry the boundary into recursion —
/// consumed by the family-agnostic boundary-bound forest/chain
/// (`expose_forest::prove_forest_over` / `prove_chain_over`). Mirrors
/// [`crate::sketch::ss_final_full::prove_ss_full_exposed`]; the unexposed entry
/// point is unchanged so existing baselines are stable.
pub fn prove_gkb2_exposed(
    params: GkbParams,
    initial_state: Gk2State,
    batch_vals: Vec<u32>,
) -> Gk2LeafProof {
    prove_gkb2_inner(params, initial_state, batch_vals, true)
}

/// A built, reusable GK band-merge leaf: circuit graph + prover data +
/// registered prover. Build once per `(params, expose_boundary)`; each
/// [`Self::prove_epoch`] swaps the `1 + lf` Permute ops’ trace-generation
/// hints (union sort + per-round resorts) via
/// `Circuit::update_permute_witnesses`, hoisting graph build and
/// AIR/`ProverData` prep out of the epoch loop.
pub struct Gkb2LeafCircuit {
    params: GkbParams,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    /// Whether the permuted tables use the source-bound layout
    /// ([`pack_bound2`]; the tuple-half re-pairing + shared-PermuteBus fix).
    /// Always `true` outside tests; the soundness PoC builds the pre-fix circuit.
    pair_bind: bool,
    /// The composition statement this leaf exposes.
    expose: Expose,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
}

/// Build the reusable GK band-merge leaf circuit for a shape.
pub fn build_gkb2_leaf(params: GkbParams, expose_boundary: bool) -> Gkb2LeafCircuit {
    build_gkb2_leaf_expose(params, Expose::from_bool(expose_boundary))
}

/// Build the reusable GK band-merge leaf circuit with an explicit composition
/// statement ([`Expose`]); `None` / `Boundary` are byte-for-byte
/// [`build_gkb2_leaf`], `Interval` adds the batch index `t` (last public
/// input, after `n_t`) and exposes `(init, final, (t, t, 0, 0), H)` with
/// `H = Poseidon2(TAG_LEAF, t, Com(B_t))` over the in-circuit batch digest.
/// Uses the process-default [`Binding`] ([`bind::default_binding`]); see
/// [`build_gkb2_leaf_expose_with`].
pub fn build_gkb2_leaf_expose(params: GkbParams, expose: Expose) -> Gkb2LeafCircuit {
    build_gkb2_leaf_expose_with(params, expose, bind::default_binding())
}

/// [`build_gkb2_leaf_expose`] with an explicit [`Binding`].
///
/// `Semantic` / `Bound` constrain the fusion threshold `θ = ⌊N_t/s⌋`
/// in-circuit ([`bind_theta`], revision B6(d)). `Legacy` is the pre-fix
/// circuit, byte-for-byte: its `θ` is a free public input, so a prover can
/// over-merge (`tests::gk2_inflated_theta_legacy_accepts_semantic_rejects`).
/// The GK leaf has no in-circuit coefficient re-binding (it relies on the
/// merged fork's `recompose/coeff` binding), so `Bound` builds the same
/// circuit as `Semantic`.
///
/// **Statement.** `θ`, `N_{t-1}` and `N_t` stay unexposed public inputs (not
/// statement values): the circuit forces `N_t = mass(S_t)` (Stage 8) and
/// `N_t = N_{t-1} + #active(B_t)`, and conservation through the union, the
/// fusion rounds and the compaction then forces `N_{t-1} = mass(S_{t-1})`.
/// All three are therefore functions of the exposed `Com(S_{t-1})`,
/// `Com(S_t)` (and the batch `Com(B_t)` the interval digest binds), and the
/// merge's `left.final == right.init` check already chains `N` between
/// adjacent leaves. Exposing them would add no binding the verifier could
/// check against the log.
pub fn build_gkb2_leaf_expose_with(
    params: GkbParams,
    expose: Expose,
    binding: Binding,
) -> Gkb2LeafCircuit {
    let expose_boundary = expose == Expose::Boundary;
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    assert_eq!(total % 2, 0, "total = cap+m must be even");
    let lf = num_rounds(total);
    let num_pairs = total / 2;
    let pair_bind = use_pair_bind();
    check_bind_range(total, lf);

    // ── Circuit ──
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
    // Surface the boundary (init, final) commitments via the Expose NPO so they
    // propagate into recursion as air_public_targets (the in-circuit
    // boundary-bound fold reads + binds them).
    if expose_boundary {
        b.add_expose(&[init_pis[0], init_pis[1], final_pis[0], final_pis[1]])
            .expect("add_expose boundary");
    }
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));
    let theta_pi = b.alloc_public_input("theta");
    let n_prev_pi = b.alloc_public_input("n_prev");
    let n_t_pi = b.alloc_public_input("n_t");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let e_max = b.alloc_const(Challenge::from_u64(E_MAX as u64), "e_max");

    // Private inputs — 2 challenges per tuple. Alloc order == packing order.
    let init_packed: Vec<ExprId> = (0..2 * cap)
        .map(|_| b.alloc_private_input("init"))
        .collect();
    let final_packed: Vec<ExprId> = (0..2 * cap)
        .map(|_| b.alloc_private_input("final"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..2 * m).map(|_| b.alloc_private_input("batch")).collect();
    let union_raw_packed: Vec<ExprId> = (0..2 * total)
        .map(|_| b.alloc_private_input("union_raw"))
        .collect();
    let fused_packed: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..2 * total)
                .map(|_| b.alloc_private_input("fused"))
                .collect()
        })
        .collect();
    let resorted_packed: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..2 * total)
                .map(|_| b.alloc_private_input("resorted"))
                .collect()
        })
        .collect();
    let excess_packed: Vec<ExprId> = (0..2 * m)
        .map(|_| b.alloc_private_input("excess"))
        .collect();
    // Hints.
    let is_fresh: Vec<ExprId> = (0..total)
        .map(|_| b.alloc_private_input("is_fresh"))
        .collect();
    let lt: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("lt"))
                .collect()
        })
        .collect();
    let cond1: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("cond1"))
                .collect()
        })
        .collect();
    let cond2: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("cond2"))
                .collect()
        })
        .collect();
    let ea_inv: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("ea_inv"))
                .collect()
        })
        .collect();
    let eb_inv: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..num_pairs)
                .map(|_| b.alloc_private_input("eb_inv"))
                .collect()
        })
        .collect();
    let e_inv_final: Vec<ExprId> = (0..cap)
        .map(|_| b.alloc_private_input("e_inv_final"))
        .collect();
    let e_inv_batch: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("e_inv_batch"))
        .collect();
    // Audit fix #5: (e,t) tiebreak inverses — one per adjacent pair of the union
    // and of each round's resorted table, so equal-e rows are pinned to ascending
    // t (the native (e,t) sort) rather than left prover-orderable.
    let de_inv_union: Vec<ExprId> = (0..total - 1)
        .map(|_| b.alloc_private_input("de_inv_u"))
        .collect();
    let de_inv_round: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..total - 1)
                .map(|_| b.alloc_private_input("de_inv_r"))
                .collect()
        })
        .collect();

    // ── Stage 1: commit bindings ──
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
    // Interval statement (B6(b)): batch index t (10th public input, after
    // n_t) and H = Poseidon2(TAG_LEAF, t, h_batch), exposed with the boundary.
    if expose.is_interval() {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &Poseidon2Config::BABY_BEAR_D4_W16,
            &init_pis,
            &final_pis,
            &h_batch,
            zero,
            crate::sketch::bind::Binding::Semantic,
            IndexPin::Range,
        );
    }

    // ── Stage 2: decompose ──
    let dec = |b: &mut CircuitBuilder<Challenge>, p: ExprId| -> Vec<ExprId> {
        b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose")
    };
    let init_f: Vec<Vec<ExprId>> = init_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let final_f: Vec<Vec<ExprId>> = final_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let batch_f: Vec<Vec<ExprId>> = batch_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let uraw_f: Vec<Vec<ExprId>> = union_raw_packed.iter().map(|&p| dec(&mut b, p)).collect();
    let resort_f: Vec<Vec<Vec<ExprId>>> = resorted_packed
        .iter()
        .map(|round| round.iter().map(|&p| dec(&mut b, p)).collect())
        .collect();

    // ── Stage 3: union multiset ──
    // Fresh singletons committed as (v,0,0,0,0,t): well-formedness g₁=g₂=Δ₁=Δ₂=0,
    // and both padding coeffs 0. The union is a permutation of init ‖ batch.
    for j in 0..m {
        b.connect(batch_f[2 * j][1], zero); // g₁
        b.connect(batch_f[2 * j][2], zero); // g₂
        b.connect(batch_f[2 * j][3], zero); // Δ₁
        b.connect(batch_f[2 * j + 1][0], zero); // Δ₂
        b.connect(batch_f[2 * j + 1][2], zero); // pad
        b.connect(batch_f[2 * j + 1][3], zero); // pad
    }
    let mut combined: Vec<ExprId> = init_packed.clone();
    combined.extend(batch_packed.iter().copied());
    if pair_bind {
        // Source-bound union INPUT: tuple i of init ‖ batch is re-encoded as
        // lo=(e,g₁,g₂,B(0,0,i)), hi=(Δ₂,t,Δ₁,B(0,1,i)) from the committed
        // coefficients (committed layout lo=(e,g₁,g₂,Δ₁), hi=(Δ₂,t,0,0)).
        // Committed pads are pinned to 0 (init; batch pads are pinned above).
        combined = Vec::with_capacity(2 * total);
        for i in 0..total {
            let f: &[Vec<ExprId>] = if i < cap {
                &init_f[2 * i..2 * i + 2]
            } else {
                &batch_f[2 * (i - cap)..2 * (i - cap) + 2]
            };
            if i < cap {
                b.connect(f[1][2], zero);
                b.connect(f[1][3], zero);
            }
            let b_lo = b.alloc_const(Challenge::from_u64(bind_coord(0, 0, i)), "bind_lo");
            let b_hi = b.alloc_const(Challenge::from_u64(bind_coord(0, 1, i)), "bind_hi");
            let lo = b
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[f[0][0], f[0][1], f[0][2], b_lo])
                .expect("bound lo");
            let hi = b
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[f[1][0], f[1][1], f[0][3], b_hi])
                .expect("bound hi");
            combined.push(lo);
            combined.push(hi);
        }
    }
    // Placeholder identity permutations — `prove_epoch` swaps in the real
    // per-batch sigmas via `update_permute_witnesses` before each run.
    let union_perm = b
        .add_permute(&combined, (0..combined.len()).collect::<Vec<_>>())
        .expect("permute union");
    for i in 0..2 * total {
        b.connect(union_perm[i], union_raw_packed[i]);
    }

    // ── Stage 4: union_raw range-checks + value sortedness + padding ──
    // `fi` reads the six fields of a PERMUTED table in its layout (the
    // source-bound layout moves Δ₁ to hi[2]; see `pack_bound2`).
    let fi = |f: &[Vec<ExprId>], r: usize| -> [ExprId; 6] {
        if pair_bind { fld6b(f, r) } else { fld6(f, r) }
    };
    for r in 0..total {
        let f = fi(&uraw_f, r);
        let _ = b.add_range_bits::<Val>(f[0], E_BITS).expect("e range");
        let _ = b.add_range_bits::<Val>(f[1], MASS_BITS).expect("g₁ range");
        let _ = b.add_range_bits::<Val>(f[2], MASS_BITS).expect("g₂ range");
        let _ = b.add_range_bits::<Val>(f[3], MASS_BITS).expect("Δ₁ range");
        let _ = b.add_range_bits::<Val>(f[4], MASS_BITS).expect("Δ₂ range");
        let _ = b.add_range_bits::<Val>(f[5], MASS_BITS).expect("t range");
        if pair_bind {
            bind_output_pair(&mut b, &uraw_f, r, 0);
        } else {
            b.connect(uraw_f[2 * r + 1][2], zero);
            b.connect(uraw_f[2 * r + 1][3], zero);
        }
    }
    for r in 0..total - 1 {
        let diff = b.sub(uraw_f[2 * (r + 1)][0], uraw_f[2 * r][0]);
        let _ = b
            .add_range_bits::<Val>(diff, E_BITS)
            .expect("union e sortedness");
        // (e,t) tiebreak: if e_{r+1}=e_r then t_{r+1} ≥ t_r (pins equal-e order).
        let nz = force_nz(&mut b, diff, de_inv_union[r], one, zero);
        let is_de_zero = b.sub(one, nz);
        let dt = b.sub(uraw_f[2 * (r + 1) + 1][1], uraw_f[2 * r + 1][1]);
        let w = b.mul(is_de_zero, dt);
        let _ = b
            .add_range_bits::<Val>(w, MASS_BITS)
            .expect("union t tiebreak");
    }

    // ── Stage 5: two-sided neighbor-init (no gate: a dummy neighbor is 0) ──
    let n_prev_p1 = b.add(n_prev_pi, one);
    for r in 0..total {
        force_le(
            &mut b,
            is_fresh[r],
            n_prev_p1,
            uraw_f[2 * r + 1][1],
            one,
            zero,
            MASS_BITS,
        );
    }
    // Δ₁_init right-to-left: fresh ? (g₁_{r+1} + Δ₁_init[r+1]) : Δ₁_raw[r].
    let mut d1: Vec<ExprId> = vec![zero; total];
    for r in (0..total).rev() {
        let base = if r + 1 < total {
            b.add(uraw_f[2 * (r + 1)][1], d1[r + 1])
        } else {
            zero
        };
        let f_part = b.mul(is_fresh[r], base);
        let omf = b.sub(one, is_fresh[r]);
        let o_part = b.mul(omf, fi(&uraw_f, r)[3]);
        d1[r] = b.add(f_part, o_part);
    }
    // Δ₂_init left-to-right: fresh ? (g₂_{r-1} + Δ₂_init[r-1]) : Δ₂_raw[r].
    let mut d2: Vec<ExprId> = vec![zero; total];
    for r in 0..total {
        let base = if r >= 1 {
            b.add(uraw_f[2 * (r - 1)][2], d2[r - 1])
        } else {
            zero
        };
        let f_part = b.mul(is_fresh[r], base);
        let omf = b.sub(one, is_fresh[r]);
        let o_part = b.mul(omf, uraw_f[2 * r + 1][0]);
        d2[r] = b.add(f_part, o_part);
    }
    // uinit fields [e, g₁, g₂, Δ₁_init, Δ₂_init, t].
    let uinit_f: Vec<[ExprId; 6]> = (0..total)
        .map(|r| {
            [
                uraw_f[2 * r][0],
                uraw_f[2 * r][1],
                uraw_f[2 * r][2],
                d1[r],
                d2[r],
                uraw_f[2 * r + 1][1],
            ]
        })
        .collect();

    // ── Stage 6: L_f parity-0 two-sided fuse + resort rounds ──
    let mut cur_f: Vec<[ExprId; 6]> = uinit_f.clone();
    for round in 0..lf {
        let fused_f: Vec<Vec<ExprId>> = fused_packed[round]
            .iter()
            .map(|&p| dec(&mut b, p))
            .collect();
        for k in 0..num_pairs {
            let a = cur_f[2 * k];
            let bb = cur_f[2 * k + 1];
            // lt = [a.t > b.t] = [b.t+1 ≤ a.t]
            let bt1 = b.add(bb[5], one);
            force_le(&mut b, lt[round][k], bt1, a[5], one, zero, MASS_BITS);
            // cond1 = [g₁ₐ+g₂ₐ+g₁_b+Δ₁_b+1 ≤ θ]
            let s1a = b.add(a[1], a[2]);
            let s1b = b.add(bb[1], bb[3]);
            let s1 = b.add(s1a, s1b);
            let sum1 = b.add(s1, one);
            force_le(&mut b, cond1[round][k], sum1, theta_pi, one, zero, CMP_BITS);
            // cond2 = [g₂_b+g₁_b+g₂ₐ+Δ₂ₐ+1 ≤ θ]
            let s2a = b.add(bb[2], bb[1]);
            let s2b = b.add(a[2], a[4]);
            let s2 = b.add(s2a, s2b);
            let sum2 = b.add(s2, one);
            force_le(&mut b, cond2[round][k], sum2, theta_pi, one, zero, CMP_BITS);
            // active_a = [e_a ≠ E_MAX], active_b = [e_b ≠ E_MAX]
            let da = b.sub(e_max, a[0]);
            let active_a = force_nz(&mut b, da, ea_inv[round][k], one, zero);
            let db = b.sub(e_max, bb[0]);
            let active_b = force_nz(&mut b, db, eb_inv[round][k], one, zero);
            let ab = b.mul(active_a, active_b);
            // dir1 = lt·cond1·ab ; dir2 = (1−lt)·cond2·ab
            let l1 = b.mul(lt[round][k], cond1[round][k]);
            let dir1 = b.mul(l1, ab);
            let omlt = b.sub(one, lt[round][k]);
            let l2 = b.mul(omlt, cond2[round][k]);
            let dir2 = b.mul(l2, ab);
            let omdir1 = b.sub(one, dir1);
            let omdir2 = b.sub(one, dir2);
            let omd12 = b.sub(omdir1, dir2); // 1 − dir1 − dir2
            // survivor mass updates
            let new_hi_g1 = {
                // dir1 survivor b.g₁ ← g₁ₐ+g₂ₐ+g₁_b+1
                let t1 = b.add(a[1], a[2]);
                let t2 = b.add(t1, bb[1]);
                b.add(t2, one)
            };
            let new_lo_g2 = {
                // dir2 survivor a.g₂ ← g₂_b+g₁_b+g₂ₐ+1
                let t1 = b.add(bb[2], bb[1]);
                let t2 = b.add(t1, a[2]);
                b.add(t2, one)
            };
            // f_lo (position 2k):  e,g₁,g₂,Δ₁,Δ₂,t
            let lo_e = {
                let x = b.mul(dir1, e_max);
                let y = b.mul(omdir1, a[0]);
                b.add(x, y)
            };
            let lo_g1 = b.mul(omdir1, a[1]);
            let lo_g2 = {
                let x = b.mul(dir2, new_lo_g2);
                let y = b.mul(omd12, a[2]);
                b.add(x, y)
            };
            let lo_d1 = b.mul(omdir1, a[3]);
            let lo_d2 = b.mul(omdir1, a[4]);
            let lo_t = b.mul(omdir1, a[5]);
            let p_lo = 2 * k;
            connect_fused(
                &mut b,
                &fused_f,
                p_lo,
                [lo_e, lo_g1, lo_g2, lo_d1, lo_d2, lo_t],
                pair_bind,
                round + 1,
                zero,
            );
            // f_hi (position 2k+1)
            let hi_e = {
                let x = b.mul(dir2, e_max);
                let y = b.mul(omdir2, bb[0]);
                b.add(x, y)
            };
            let hi_g1 = {
                let x = b.mul(dir1, new_hi_g1);
                let y = b.mul(omd12, bb[1]);
                b.add(x, y)
            };
            let hi_g2 = b.mul(omdir2, bb[2]);
            let hi_d1 = b.mul(omdir2, bb[3]);
            let hi_d2 = b.mul(omdir2, bb[4]);
            let hi_t = b.mul(omdir2, bb[5]);
            let p_hi = 2 * k + 1;
            connect_fused(
                &mut b,
                &fused_f,
                p_hi,
                [hi_e, hi_g1, hi_g2, hi_d1, hi_d2, hi_t],
                pair_bind,
                round + 1,
                zero,
            );
        }
        // resort
        let perm = b
            .add_permute(
                &fused_packed[round],
                (0..fused_packed[round].len()).collect::<Vec<_>>(),
            )
            .expect("permute resort");
        for i in 0..2 * total {
            b.connect(perm[i], resorted_packed[round][i]);
        }
        for r in 0..total {
            let f = fi(&resort_f[round], r);
            let _ = b.add_range_bits::<Val>(f[0], E_BITS).expect("rs e");
            let _ = b.add_range_bits::<Val>(f[1], MASS_BITS).expect("rs g₁");
            let _ = b.add_range_bits::<Val>(f[2], MASS_BITS).expect("rs g₂");
            let _ = b.add_range_bits::<Val>(f[3], MASS_BITS).expect("rs Δ₁");
            let _ = b.add_range_bits::<Val>(f[4], MASS_BITS).expect("rs Δ₂");
            let _ = b.add_range_bits::<Val>(f[5], MASS_BITS).expect("rs t");
            if pair_bind {
                bind_output_pair(&mut b, &resort_f[round], r, round + 1);
            } else {
                b.connect(resort_f[round][2 * r + 1][2], zero);
                b.connect(resort_f[round][2 * r + 1][3], zero);
            }
        }
        for r in 0..total - 1 {
            let diff = b.sub(resort_f[round][2 * (r + 1)][0], resort_f[round][2 * r][0]);
            let _ = b
                .add_range_bits::<Val>(diff, E_BITS)
                .expect("rs sortedness");
            // (e,t) tiebreak (audit fix #5).
            let nz = force_nz(&mut b, diff, de_inv_round[round][r], one, zero);
            let is_de_zero = b.sub(one, nz);
            let dt = b.sub(
                resort_f[round][2 * (r + 1) + 1][1],
                resort_f[round][2 * r + 1][1],
            );
            let w = b.mul(is_de_zero, dt);
            let _ = b
                .add_range_bits::<Val>(w, MASS_BITS)
                .expect("rs t tiebreak");
        }
        cur_f = (0..total).map(|r| fi(&resort_f[round], r)).collect();
    }

    // ── Stage 7: compaction — final = cur[..cap], excess = cur[cap..] ──
    let excess_f: Vec<Vec<ExprId>> = excess_packed.iter().map(|&p| dec(&mut b, p)).collect();
    for i in 0..cap {
        let f = fld6(&final_f, i);
        let _ = b.add_range_bits::<Val>(f[0], E_BITS).expect("final e");
        let _ = b.add_range_bits::<Val>(f[1], MASS_BITS).expect("final g₁");
        let _ = b.add_range_bits::<Val>(f[2], MASS_BITS).expect("final g₂");
        let _ = b.add_range_bits::<Val>(f[3], MASS_BITS).expect("final Δ₁");
        let _ = b.add_range_bits::<Val>(f[4], MASS_BITS).expect("final Δ₂");
        let _ = b.add_range_bits::<Val>(f[5], MASS_BITS).expect("final t");
        b.connect(final_f[2 * i + 1][2], zero);
        b.connect(final_f[2 * i + 1][3], zero);
    }
    for i in 0..cap {
        let cf = cur_f[i];
        b.connect(final_f[2 * i][0], cf[0]);
        b.connect(final_f[2 * i][1], cf[1]);
        b.connect(final_f[2 * i][2], cf[2]);
        b.connect(final_f[2 * i][3], cf[3]);
        b.connect(final_f[2 * i + 1][0], cf[4]);
        b.connect(final_f[2 * i + 1][1], cf[5]);
    }
    // excess must be all-dummy: e=E_MAX, g₁=g₂=0, and it equals cur[cap+j].
    for j in 0..m {
        let cf = cur_f[cap + j];
        b.connect(excess_f[2 * j][0], cf[0]);
        b.connect(excess_f[2 * j][1], cf[1]);
        b.connect(excess_f[2 * j][2], cf[2]);
        b.connect(excess_f[2 * j][3], cf[3]);
        b.connect(excess_f[2 * j + 1][0], cf[4]);
        b.connect(excess_f[2 * j + 1][1], cf[5]);
        b.connect(excess_f[2 * j + 1][2], zero);
        b.connect(excess_f[2 * j + 1][3], zero);
        b.connect(excess_f[2 * j][0], e_max); // e = E_MAX
        b.connect(excess_f[2 * j][1], zero); // g₁ = 0
        b.connect(excess_f[2 * j][2], zero); // g₂ = 0
    }

    // ── Stage 8: mass — Σ_active(g₁+g₂+1) = N_t ──
    // count_active = Σ [e_i ≠ E_MAX]; mass = Σ(g₁+g₂) + count_active.
    let mut mass = zero;
    let mut count = zero;
    for i in 0..cap {
        let f = fld6(&final_f, i);
        let di = b.sub(e_max, f[0]);
        let act = force_nz(&mut b, di, e_inv_final[i], one, zero);
        // Audit fix #4A: a dummy final row (e=E_MAX ⇒ act=0) must carry no mass,
        // else a poisoned init dummy (e=E_MAX, g≠0) that lands in the final slice
        // would inflate mass while contributing 0 to count. Force (1−act)·g = 0.
        let omact = b.sub(one, act);
        let z1 = b.mul(omact, f[1]);
        b.connect(z1, zero);
        let z2 = b.mul(omact, f[2]);
        b.connect(z2, zero);
        count = b.add(count, act);
        let gg = b.add(f[1], f[2]);
        mass = b.add(mass, gg);
    }
    mass = b.add(mass, count);
    b.connect(mass, n_t_pi);
    // Audit fix #3/#4B: bind N_t = N_prev + (#active batch values), matching the
    // one-sided circuit's conservation check (omitted here originally). This pins
    // the public N_prev (so a malicious N_prev cannot corrupt the is_fresh gate)
    // and ties the certified count to the committed batch. #active batch =
    // Σ [batch.e ≠ E_MAX].
    let mut count_batch = zero;
    for j in 0..m {
        let dj = b.sub(e_max, batch_f[2 * j][0]);
        let actj = force_nz(&mut b, dj, e_inv_batch[j], one, zero);
        count_batch = b.add(count_batch, actj);
    }
    let np_plus_b = b.add(n_prev_pi, count_batch);
    b.connect(np_plus_b, n_t_pi);
    // ── Stage 9: θ = ⌊N_t/s⌋ from the in-circuit N_t (revision B6(d)) ──
    // Appended last so the Legacy circuit is byte-for-byte the pre-fix one.
    if binding.is_bound() {
        bind_theta::<Val, Challenge>(&mut b, theta_pi, n_t_pi, params.s);
    }

    let circuit = b.build().expect("build gkb2 circuit");

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
        .expect("airs_and_degrees");
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

    Gkb2LeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        pair_bind,
        expose,
        batch_index: 1,
    }
}

impl Gkb2LeafCircuit {
    /// Prove one epoch on the prebuilt circuit.
    pub fn prove_epoch(&mut self, initial_state: Gk2State, batch_vals: Vec<u32>) -> Gk2LeafProof {
        self.prove_epoch_at(1, initial_state, batch_vals)
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
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
    ) -> Gk2LeafProof {
        self.batch_index = t;
        let params = self.params;
        assert!(batch_vals.len() <= params.batch);
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        assert_eq!(total % 2, 0, "total = cap+m must be even");

        // ── Native replay + commitments ──
        let build = build_bm2(&initial_state, &batch_vals);
        self.prove_build(initial_state, batch_vals, &build)
    }

    /// Pack a (honest or hand-crafted) band-merge witness, install its permute
    /// hints, run, prove and self-verify.
    fn prove_build(
        &mut self,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        build: &Bm2Build,
    ) -> Gk2LeafProof {
        let params = self.params;
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        let final_state = Gk2State {
            tuples: build.final_tuples.clone(),
            params,
            n: build.n_t,
        };
        let initial_commit = commit_gk2_state(&initial_state);
        let final_commit = commit_gk2_state(&final_state);
        let batch_commit = commit_gk2_batch(&batch_vals, m, build.n_prev);
        let lf = num_rounds(total);
        let num_pairs = total / 2;

        // Swap the real per-batch permutation hints into the prebuilt graph
        // (op order: union-sort permute, then the lf per-round resort permutes).
        let mut sigmas: Vec<Vec<usize>> = Vec::with_capacity(1 + lf);
        sigmas.push(build.sigma_union_chal.clone());
        for round in 0..lf {
            sigmas.push(expand_sigma(&build.rounds[round].sigma));
        }
        self.circuit
            .update_permute_witnesses(&sigmas)
            .expect("update permute witnesses (gkb2)");

        // ── Pack public + private ──
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
        public_inputs.push(Challenge::from_u64(build.theta));
        let n_prev_pub = {
            let mut v = build.n_prev;
            #[cfg(test)]
            {
                if let Some(t) = TAMPER_NPREV.with(|c| c.get()) {
                    v = t;
                }
            }
            v
        };
        public_inputs.push(Challenge::from_u64(n_prev_pub));
        public_inputs.push(Challenge::from_u64(build.n_t));
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        let mut private_inputs: Vec<Challenge> = Vec::new();
        private_inputs.extend_from_slice(&pack_tuples2(&initial_state.tuples));
        private_inputs.extend_from_slice(&pack_tuples2(&final_state.tuples));
        private_inputs.extend_from_slice(&pack_tuples2(&fresh_tuples2(
            &batch_vals,
            m,
            build.n_prev,
        )));
        if self.pair_bind {
            // Permuted tables in the source-bound layout. Output halves name the
            // input position the permute took them from (σ is challenge-level).
            let identity: Vec<usize> = (0..total).collect();
            let src_lo: Vec<usize> = (0..total).map(|r| build.sigma_union_chal[2 * r] / 2).collect();
            let src_hi: Vec<usize> =
                (0..total).map(|r| build.sigma_union_chal[2 * r + 1] / 2).collect();
            private_inputs.extend_from_slice(&pack_bound2(&build.union_raw, 0, &src_lo, &src_hi));
            for (round, rd) in build.rounds.iter().enumerate() {
                private_inputs.extend_from_slice(&pack_bound2(
                    &rd.fused,
                    round + 1,
                    &identity,
                    &identity,
                ));
            }
            for (round, rd) in build.rounds.iter().enumerate() {
                private_inputs.extend_from_slice(&pack_bound2(
                    &rd.resorted,
                    round + 1,
                    &rd.sigma,
                    &rd.sigma,
                ));
            }
        } else {
            private_inputs.extend_from_slice(&pack_tuples2(&build.union_raw));
            for round in &build.rounds {
                private_inputs.extend_from_slice(&pack_tuples2(&round.fused));
            }
            for round in &build.rounds {
                private_inputs.extend_from_slice(&pack_tuples2(&round.resorted));
            }
        }
        private_inputs.extend_from_slice(&pack_tuples2(&build.excess));
        // is_fresh
        for r in 0..total {
            let fresh = build.union_raw[r].active == 1 && build.union_raw[r].t > build.n_prev;
            private_inputs.push(if fresh {
                Challenge::ONE
            } else {
                Challenge::ZERO
            });
        }
        // per-round hints, GROUPED BY TYPE to match alloc order.
        {
            use p3_field::Field;
            let mut curs: Vec<Vec<Gk2Tuple>> = vec![build.union_init.clone()];
            for round in 0..lf {
                curs.push(build.rounds[round].resorted.clone());
            }
            let inv = |x: u64| {
                if x == 0 {
                    Challenge::ZERO
                } else {
                    Challenge::from_u64(x).inverse()
                }
            };
            // lt
            for round in 0..lf {
                for k in 0..num_pairs {
                    let (a, bb) = (curs[round][2 * k], curs[round][2 * k + 1]);
                    private_inputs.push(Challenge::from_u64((a.t > bb.t) as u64));
                }
            }
            // cond1
            for round in 0..lf {
                for k in 0..num_pairs {
                    private_inputs.push(Challenge::from_u64(build.rounds[round].cond1[k] as u64));
                }
            }
            // cond2
            for round in 0..lf {
                for k in 0..num_pairs {
                    private_inputs.push(Challenge::from_u64(build.rounds[round].cond2[k] as u64));
                }
            }
            // ea_inv = 1/(E_MAX − a.e)
            for round in 0..lf {
                for k in 0..num_pairs {
                    let a = curs[round][2 * k];
                    private_inputs.push(inv((E_MAX - a.e) as u64));
                }
            }
            // eb_inv = 1/(E_MAX − b.e)
            for round in 0..lf {
                for k in 0..num_pairs {
                    let bb = curs[round][2 * k + 1];
                    private_inputs.push(inv((E_MAX - bb.e) as u64));
                }
            }
            // e_inv_final = 1/(E_MAX − final.e)
            for i in 0..cap {
                private_inputs.push(inv((E_MAX - build.final_tuples[i].e) as u64));
            }
            // e_inv_batch = 1/(E_MAX − batch.e)  (dummy batch slot → 0)
            let fresh = fresh_tuples2(&batch_vals, m, build.n_prev);
            for j in 0..m {
                private_inputs.push(inv((E_MAX - fresh[j].e) as u64));
            }
            // de_inv_union = 1/(e_{r+1} − e_r) over the sorted union (0 when equal).
            for r in 0..total - 1 {
                let de = (build.union_raw[r + 1].e - build.union_raw[r].e) as u64;
                private_inputs.push(inv(de));
            }
            // de_inv_round = same over each round's resorted table.
            for round in 0..lf {
                let rs = &build.rounds[round].resorted;
                for r in 0..total - 1 {
                    let de = (rs[r + 1].e - rs[r].e) as u64;
                    private_inputs.push(inv(de));
                }
            }
        }

        // ── Run + prove ──
        let __t_w = std::time::Instant::now();
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&public_inputs).expect("set pub");
            runner
                .set_private_inputs(&private_inputs)
                .expect("set priv");
            runner.run().expect("run gkb2 circuit")
        };
        let __witness = __t_w.elapsed();

        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (gkb2)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify gkb2 leaf");
        crate::recursion::recursive::timing::record(
            crate::recursion::recursive::timing::LeafTiming {
                witness: __witness,
                prove: __prove,
                verify: __t_v.elapsed(),
                trace_rows: self.trace_rows,
            },
        );

        Gk2LeafProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial: initial_commit,
            final_: final_commit,
            batch_commit,
            params,
        }
    }
}

fn prove_gkb2_inner(
    params: GkbParams,
    initial_state: Gk2State,
    batch_vals: Vec<u32>,
    expose_boundary: bool,
) -> Gk2LeafProof {
    build_gkb2_leaf(params, expose_boundary).prove_epoch(initial_state, batch_vals)
}

/// Prove batch `t` (1-based) as an **Interval-statement** GK band-merge leaf.
pub fn prove_gkb2_interval(
    params: GkbParams,
    t: u64,
    initial_state: Gk2State,
    batch_vals: Vec<u32>,
) -> Gk2LeafProof {
    build_gkb2_leaf_expose(params, Expose::Interval).prove_epoch_at(t, initial_state, batch_vals)
}

/// Prove one two-sided band-merge epoch from empty, returning proof + final state.
pub fn generate_proof2(params: GkbParams, batch_vals: Vec<u32>) -> Gk2Proof {
    let initial_state = Gk2State::empty(params);
    let final_state = apply_batch2(&initial_state, &batch_vals);
    let proof = prove_gkb2(params, initial_state, batch_vals);
    Gk2Proof { proof, final_state }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random stream (no external RNG; keeps tests
    /// reproducible and dependency-free).
    fn lcg_stream(seed: u64, n: usize, universe: u32) -> Vec<u32> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((x >> 33) as u32) % universe
            })
            .collect()
    }

    /// Check invariant (A2): `g + Δ ≤ ⌊εt⌋` for every active tuple.
    fn check_invariant(state: &GkbState) {
        let theta = state.n / state.params.s;
        for t in state.actives() {
            assert!(
                t.g + t.delta <= theta,
                "A2 violated: g={} Δ={} > θ={} (N={})",
                t.g,
                t.delta,
                theta,
                state.n
            );
        }
    }

    /// **The proof it's really GK: the additive-`εN` rank guarantee holds.**
    /// Run a stream in batches through the band-merge, then check that for every
    /// query the estimated rank is within `εN` of the true rank, and that the
    /// invariant (A2) and mass conservation (`Σg = N`) hold throughout.
    #[test]
    fn bandmerge_epsilon_guarantee() {
        let s = 64u64; // ε = 1/64
        let params = GkbParams {
            capacity: 4096,
            batch: 256,
            s,
        };
        let mut state = GkbState::empty(params);

        let universe = 100_000u32;
        let stream = lcg_stream(0xC0FFEE, 20_000, universe);
        let mut seen: Vec<u32> = Vec::new();

        for chunk in stream.chunks(params.batch) {
            state = apply_batch(&state, chunk);
            seen.extend_from_slice(chunk);

            // mass conservation: Σ g over actives == N == #records seen.
            let mass: u64 = state.actives().iter().map(|t| t.g).sum();
            assert_eq!(mass, state.n, "mass Σg must equal N");
            assert_eq!(state.n as usize, seen.len());
            check_invariant(&state);
        }

        // εN rank guarantee at a spread of query points.
        let n = seen.len() as u64;
        let eps_n = n / s; // εN
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        for q in (0..universe).step_by(1000) {
            let est = state.rank(q);
            let truth = sorted.partition_point(|&v| v <= q) as u64;
            let err = est.abs_diff(truth);
            assert!(
                err <= eps_n,
                "rank error {err} at q={q} exceeds εN={eps_n} (est={est}, true={truth}, N={n})"
            );
        }

        // It actually compressed: far fewer representatives than records.
        let active = state.actives().len();
        assert!(
            active < seen.len() / 4,
            "expected real compression, kept {active} reps for {} records",
            seen.len()
        );
        eprintln!(
            "bandmerge: N={}, kept {} representatives (εN={}), invariant + εN guarantee hold",
            n, active, eps_n
        );
    }

    /// The compress genuinely merges DISTINCT values (not just equal ones):
    /// a batch of all-distinct values collapses to fewer representatives.
    ///
    /// NOTE the arrival order matters — the timestamp rule `t_i > t_{i+1}` only
    /// merges a smaller-valued element into a larger-valued one when the smaller
    /// is *younger*. We feed the distinct values in decreasing-value order (so
    /// smaller values are younger), which is the merge-favorable case; on a real
    /// random-order stream roughly half the pairs qualify (see
    /// `bandmerge_epsilon_guarantee`).
    #[test]
    fn distinct_values_merge() {
        let s = 4u64; // coarse ε = 1/4 so merging is aggressive
        let params = GkbParams {
            capacity: 64,
            batch: 32,
            s,
        };
        let mut state = GkbState::empty(params);
        // 32 distinct values, arriving largest-first.
        let batch: Vec<u32> = (0..32u32).rev().map(|i| i * 10).collect();
        state = apply_batch(&state, &batch);

        let active = state.actives();
        // Distinct values, yet compressed below the input count — only possible
        // by merging DISTINCT adjacent representatives (the real band-merge).
        assert!(
            active.len() < batch.len(),
            "distinct-value band-merge did not compress: {} reps for {} distinct values",
            active.len(),
            batch.len()
        );
        // Values are distinct and sorted; mass conserved.
        for w in active.windows(2) {
            assert!(
                w[0].e < w[1].e,
                "representatives must be value-sorted & distinct"
            );
        }
        assert_eq!(active.iter().map(|t| t.g).sum::<u64>(), 32);
        // Every retained representative was an input value.
        for t in &active {
            assert!(
                batch.contains(&t.e),
                "representative {} not from the input",
                t.e
            );
        }
        eprintln!(
            "distinct-value merge: 32 distinct values → {} representatives",
            active.len()
        );
    }

    /// **The circuit: an honest band-merge transition self-verifies**, and its
    /// certified final commit matches the natively-computed final state.
    #[test]
    fn gkb_circuit_round_trip() {
        let params = GkbParams {
            capacity: 8,
            batch: 4,
            s: 2,
        };
        // largest-first arrival so the timestamp rule permits distinct-value merges.
        let batch = vec![300u32, 200, 100, 50];
        let result = generate_proof(params, batch);
        assert_eq!(
            commit_gkb_state(&result.final_state).0,
            result.proof.final_.0,
            "certified final commit must match the native final state"
        );
    }

    /// **Circuit over a CHAINED epoch**: prove epoch 1 (empty → s1), then feed
    /// the certified s1 as the old state for epoch 2 and prove that too. Epoch 2
    /// exercises the full path — old tuples with real timestamps/Δ, neighbor-init
    /// against old neighbors, and distinct old/fresh merges — and both proofs
    /// self-verify with commits chaining (init₂ = final₁).
    #[test]
    fn gkb_circuit_chained_epoch() {
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s: 3,
        };
        let b1: Vec<u32> = vec![900, 800, 700, 600, 500, 400, 300, 200];
        let e1 = generate_proof(params, b1);
        let s1 = e1.final_state.clone();

        let b2: Vec<u32> = vec![850, 250, 650, 450, 950, 150, 550, 350];
        let e2_commit_in = commit_gkb_state(&s1);
        let p2 = prove_gkb(params, s1.clone(), b2.clone());
        // chaining: epoch-2 init commit == epoch-1 final commit.
        assert_eq!(p2.initial.0, e2_commit_in.0);
        assert_eq!(p2.initial.0, e1.proof.final_.0);
        // certified final matches the native chained state.
        let s2 = apply_batch(&s1, &b2);
        assert_eq!(commit_gkb_state(&s2).0, p2.final_.0);
        assert!(s2.actives().len() <= params.capacity);
    }

    /// `Δ` neighbor-init + the timestamp direction give the exact §3 tuple.
    #[test]
    fn neighbor_init_and_invariant_small() {
        let s = 8u64;
        let params = GkbParams {
            capacity: 32,
            batch: 8,
            s,
        };
        let mut state = GkbState::empty(params);
        for chunk in [
            [5u32, 20, 8, 8, 30, 1, 25, 12],
            [7, 7, 7, 40, 2, 18, 22, 33],
        ] {
            state = apply_batch(&state, &chunk);
            check_invariant(&state);
            assert_eq!(state.actives().iter().map(|t| t.g).sum::<u64>(), state.n);
        }
    }

    // ── Two-sided §4 (optimal, mirrored) band-merge ───────────────────────

    /// Check the two-sided invariant (B2): `g+Δ ≤ ⌊εt⌋` AND `g°+Δ° ≤ ⌊εt⌋`.
    fn check_invariant2(state: &Gk2State) {
        let theta = state.n / state.params.s;
        for t in state.actives() {
            assert!(
                t.g + t.delta <= theta && t.g_o + t.delta_o <= theta,
                "B2 violated: g={} Δ={} g°={} Δ°={} > θ={} (N={})",
                t.g,
                t.delta,
                t.g_o,
                t.delta_o,
                theta,
                state.n
            );
        }
    }

    /// **The two-sided sketch is a real ε-approximate quantile summary AND has a
    /// bounded size.** Runs a stream in batches and checks, at every version:
    /// mass conservation `Σ(g+g°+1)=N`, invariant (B2), the Gribelyuk §4 space
    /// bound `|M| ≤ 2s·ln(N/s+2)+2`, and finally the additive-`εN` rank guarantee
    /// (true rank ∈ `[r_min, r_max]`, midpoint within `εN`).
    #[test]
    fn two_sided_epsilon_and_bounded_space() {
        let s = 64u64; // ε = 1/64
        let params = GkbParams {
            capacity: 4096,
            batch: 256,
            s,
        };
        let mut state = Gk2State::empty(params);

        let universe = 100_000u32;
        let stream = lcg_stream(0xBEEF, 20_000, universe);
        let mut seen: Vec<u32> = Vec::new();

        for chunk in stream.chunks(params.batch) {
            state = apply_batch2(&state, chunk);
            seen.extend_from_slice(chunk);

            let mass: u64 = state.actives().iter().map(|t| t.mass()).sum();
            assert_eq!(mass, state.n, "two-sided mass Σ(g+g°+1) must equal N");
            assert_eq!(state.n as usize, seen.len());
            check_invariant2(&state);

            // Bounded space — the whole point of the mirror (no hard case).
            let bound = gribelyuk_space_bound(state.n, s);
            assert!(
                state.actives().len() <= bound,
                "two-sided kept {} reps > Gribelyuk bound {} at N={}",
                state.actives().len(),
                bound,
                state.n
            );
        }

        // εN rank guarantee: true rank brackets inside [r_min, r_max], midpoint ≤ εN.
        let n = seen.len() as u64;
        let eps_n = n / s;
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        for q in (0..universe).step_by(500) {
            let (lo, hi) = state.rank_interval(q);
            let truth = sorted.partition_point(|&v| v <= q) as u64;
            assert!(
                lo <= truth && truth <= hi,
                "true rank {truth} outside [{lo},{hi}] at q={q} (N={n})"
            );
            let est = (lo + hi) / 2;
            assert!(
                est.abs_diff(truth) <= eps_n,
                "rank error {} at q={q} exceeds εN={eps_n} (est={est}, true={truth})",
                est.abs_diff(truth)
            );
        }
        let active = state.actives().len();
        eprintln!(
            "two-sided: N={}, kept {} reps (bound {}, εN={}), B2 + εN + space bound hold",
            n,
            active,
            gribelyuk_space_bound(n, s),
            eps_n
        );
    }

    /// **The mirror handles the "hard case" the one-sided toy cannot.** A
    /// strictly-increasing (sorted) arrival makes every adjacent pair have the
    /// smaller value *older* (`t_i<t_{i+1}`) — the hard case in which the
    /// one-sided §3 toy (`apply_batch`) can never merge and its summary grows
    /// unboundedly. The two-sided sketch merges them via the mirror (case 2) and
    /// stays within the Gribelyuk bound.
    #[test]
    fn two_sided_handles_hard_case() {
        let s = 16u64;
        let params = GkbParams {
            capacity: 8192,
            batch: 256,
            s,
        };
        let mut two = Gk2State::empty(params);

        let n: u32 = 8_000;
        let mut start = 0u32;
        while start < n {
            let end = (start + params.batch as u32).min(n);
            let chunk: Vec<u32> = (start..end).collect(); // strictly increasing
            two = apply_batch2(&two, &chunk);
            check_invariant2(&two);
            start = end;
        }

        let bound = gribelyuk_space_bound(two.n, s);
        assert!(
            two.actives().len() <= bound,
            "two-sided hard case kept {} reps > bound {}",
            two.actives().len(),
            bound
        );
        // Genuine compression on the hard case (the one-sided toy would keep ~all N).
        assert!(
            two.actives().len() < (n as usize) / 4,
            "expected the mirror to compress the hard case, kept {} for {} records",
            two.actives().len(),
            n
        );

        // Sanity: the one-sided toy really *cannot* compress this sorted arrival
        // (its merge needs t_i>t_{i+1}); it keeps a representative per value.
        let mut one = GkbState::empty(GkbParams {
            capacity: 8192,
            batch: 256,
            s,
        });
        one = apply_batch(&one, &(0..256u32).collect::<Vec<_>>());
        assert_eq!(
            one.actives().len(),
            256,
            "one-sided toy should keep every rep on a sorted batch (the hard case)"
        );

        eprintln!(
            "hard case: two-sided kept {} reps (bound {}) vs one-sided {} for a sorted batch of 256",
            two.actives().len(),
            bound,
            one.actives().len()
        );
    }

    /// **The two-sided circuit: an honest two-sided band-merge transition
    /// self-verifies**, and its certified final commit matches the native state.
    #[test]
    fn gk2_circuit_round_trip() {
        let params = GkbParams {
            capacity: 8,
            batch: 4,
            s: 2,
        };
        // increasing arrival so the mirror (case-2) branch fires.
        let batch = vec![50u32, 100, 200, 300];
        let result = generate_proof2(params, batch);
        assert_eq!(
            commit_gk2_state(&result.final_state).0,
            result.proof.final_.0,
            "certified two-sided final commit must match the native final state"
        );
        assert!(result.final_state.actives().len() <= params.capacity);
    }

    /// The naive per-record replay produces a valid two-sided GK summary:
    /// mass Σ(g₁+g₂+1)=N, invariant B2, and bounded size — the same guarantees
    /// as the batch `apply_batch2`, via a different (per-record) schedule.
    #[test]
    fn naive2_replay_is_valid_gk() {
        let s = 32u64;
        let params = GkbParams {
            capacity: 2048,
            batch: 128,
            s,
        };
        let mut state = Gk2State::empty(params);
        let stream = lcg_stream(0x5EED, 6_000, 100_000);
        let mut seen = 0usize;
        for chunk in stream.chunks(params.batch) {
            state = apply_batch2_naive(&state, chunk);
            seen += chunk.len();
            let mass: u64 = state.actives().iter().map(|t| t.mass()).sum();
            assert_eq!(mass, state.n, "naive mass Σ(g₁+g₂+1) must equal N");
            assert_eq!(state.n as usize, seen);
            let theta = state.n / s;
            for t in state.actives() {
                assert!(
                    t.g + t.delta <= theta && t.g_o + t.delta_o <= theta,
                    "B2 violated"
                );
            }
            assert!(state.actives().len() <= params.capacity);
        }
        eprintln!(
            "naive replay: N={}, kept {} reps",
            state.n,
            state.actives().len()
        );
    }

    /// **The naive per-record replay circuit self-verifies**, exercising the
    /// compress path (cap small enough that records overflow and merge), and its
    /// certified final commit matches the native per-record state.
    #[test]
    fn gk2_naive_circuit_round_trip() {
        let params = GkbParams {
            capacity: 3,
            batch: 6,
            s: 1,
        };
        let batch = vec![10u32, 20, 30, 40, 50, 60];
        let result = generate_proof2_naive(params, batch);
        assert_eq!(
            commit_gk2_state(&result.final_state).0,
            result.proof.final_.0,
            "certified naive final commit must match the native per-record state"
        );
    }

    /// **Audit regression (#4A): a poisoned init dummy is rejected.** A dummy
    /// tuple (e=E_MAX, so inactive) carrying nonzero mass g₁=5, placed in the
    /// final slice, would inflate the certified record count while contributing 0
    /// to the active count — fabricating records from nothing. Stage 8's
    /// `(1−active)·g = 0` gate (and the mass check) must reject it.
    #[test]
    #[should_panic]
    fn gk2_poisoned_dummy_rejected() {
        let params = GkbParams {
            capacity: 8,
            batch: 4,
            s: 2,
        };
        let mut tuples = vec![Gk2Tuple::dummy(); params.capacity];
        tuples[0] = Gk2Tuple {
            e: E_MAX,
            g: 5,
            g_o: 0,
            delta: 0,
            delta_o: 0,
            t: 0,
            active: 0,
        };
        let init = Gk2State {
            tuples,
            params,
            n: 0,
        };
        // Empty batch: N_prev=0, N_t=0, but the poisoned dummy carries mass 5.
        let _ = prove_gkb2(params, init, vec![]);
    }

    /// **Audit regression (#3/#4B): a wrong public N_prev is rejected.** The
    /// certified transition binds N_t = N_prev + (#active batch); feeding a
    /// N_prev inconsistent with the honest count must fail the Stage-8 check
    /// (which also pins the is_fresh gate against neighbor-init corruption).
    #[test]
    #[should_panic]
    fn gk2_wrong_n_prev_rejected() {
        let params = GkbParams {
            capacity: 8,
            batch: 4,
            s: 2,
        };
        let init = Gk2State::empty(params); // N_prev = 0 honestly
        let batch = vec![50u32, 100, 200, 300];
        // Tamper the public N_prev to 999 while the honest state has N_prev=0.
        // N_t=4 but 999 + 4 ≠ 4, so the Stage-8 binding must reject.
        TAMPER_NPREV.with(|c| c.set(Some(999)));
        let _ = prove_gkb2(params, init, batch);
    }

    // ─── θ binding (revision B6(d)) ────────────────────────────────────────

    /// Largest midpoint rank error `|rank(q) − truth|` of `state` against the
    /// true `stream`, over queries at, just below and just above every value.
    fn max_rank_err(state: &Gk2State, stream: &[u32]) -> u64 {
        let mut qs: Vec<u32> = stream.to_vec();
        qs.extend(stream.iter().map(|&x| x.saturating_sub(1)));
        qs.extend(stream.iter().map(|&x| x + 1));
        qs.sort_unstable();
        qs.dedup();
        qs.iter()
            .map(|&q| {
                let truth = stream.iter().filter(|&&x| x <= q).count() as u64;
                state.rank(q).abs_diff(truth)
            })
            .max()
            .unwrap_or(0)
    }

    /// An over-merging malicious witness: the honest union of `s_old ⊎ batch`,
    /// with the neighbor-init, the `L_f` fusion rounds and the compaction
    /// replayed under the inflated threshold `theta` (so every fusion decision
    /// is consistent with the claimed `θ`). `None` if it changes nothing or
    /// the survivors overflow the capacity.
    fn forge_theta(s_old: &Gk2State, batch: &[u32], theta: u64) -> Option<Bm2Build> {
        let honest = build_bm2(s_old, batch);
        let f = finish_bm2(
            s_old,
            honest.sigma_union.clone(),
            honest.sigma_union_chal.clone(),
            honest.union_raw.clone(),
            honest.n_prev,
            honest.n_t,
            theta,
        );
        (f.final_tuples != honest.final_tuples && f.excess.iter().all(|t| t.active == 0))
            .then_some(f)
    }

    /// Search two-batch streams and inflated thresholds `θ' ∈ (θ, N_t]` for an
    /// epoch-2 over-merge whose certified final breaks the `εN` rank
    /// guarantee by the widest margin. Returns `(s1, b2, forged, stream)`.
    fn inflated_theta_instance(params: GkbParams) -> (Gk2State, Vec<u32>, Bm2Build, Vec<u32>) {
        let m = params.batch;
        let mut best: Option<(u64, Gk2State, Vec<u32>, Bm2Build, Vec<u32>)> = None;
        for seed in 1..=24u64 {
            let b1 = lcg_stream(seed, m, 1000);
            let b2 = lcg_stream(seed + 1000, m, 1000);
            let s1 = apply_batch2(&Gk2State::empty(params), &b1);
            let honest = build_bm2(&s1, &b2);
            let stream: Vec<u32> = b1.iter().chain(b2.iter()).copied().collect();
            let eps_n = honest.n_t / params.s;
            for theta in honest.theta + 1..=honest.n_t {
                let Some(f) = forge_theta(&s1, &b2, theta) else {
                    continue;
                };
                let st = Gk2State {
                    tuples: f.final_tuples.clone(),
                    params,
                    n: f.n_t,
                };
                let err = max_rank_err(&st, &stream);
                let margin = err.saturating_sub(eps_n);
                if margin > 0 && best.as_ref().is_none_or(|b| margin > b.0) {
                    best = Some((margin, s1.clone(), b2.clone(), f, stream.clone()));
                }
            }
        }
        let (_, s1, b2, f, stream) =
            best.expect("an inflated θ whose over-merge breaks the εN guarantee");
        (s1, b2, f, stream)
    }

    /// Exposed `(init, final)` of a Boundary-layout leaf proof.
    fn exposed_boundary(proof: &p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>) -> [Val; 16] {
        let pv = proof
            .non_primitives
            .iter()
            .map(|e| &e.public_values)
            .find(|v| v.len() == 16)
            .expect("exposed (init, final)");
        std::array::from_fn(|i| pv[i])
    }

    /// **Inflated-threshold PoC (revision B6(d)).** `θ` used to be a free
    /// public input read only by the fusion comparisons, "assumed" to equal
    /// `⌊N_t/s⌋`. A malicious prover claims a larger `θ'` and replays every
    /// fusion round under it (each `cond`/`dir` hint consistent with `θ'`),
    /// so adjacent tuples over-merge. The certified final has the right mass
    /// (`N_t`) and passes every other check, but its rank uncertainty exceeds
    /// `εN`: the midpoint estimator errs by more than `εN` for some query.
    ///
    /// `Legacy` (the pre-fix circuit, byte-for-byte): ACCEPTED, exposing
    /// `Com(S')` for the over-merged `S'`. `Semantic` / `Bound`: the circuit
    /// forces `θ = ⌊N_t/s⌋` ([`bind_theta`]), so no witness exists for `θ'`
    /// (the runner fails the range reconstruction of `N_t − θ'·s`); each has a
    /// positive control (the honest build, same leaf) that must verify.
    #[test]
    fn gk2_inflated_theta_legacy_accepts_semantic_rejects() {
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s: 3,
        };
        let (s1, b2, forged, stream) = inflated_theta_instance(params);
        let honest = build_bm2(&s1, &b2);
        let eps_n = honest.n_t / params.s;
        let honest_final = Gk2State {
            tuples: honest.final_tuples.clone(),
            params,
            n: honest.n_t,
        };
        let forged_final = Gk2State {
            tuples: forged.final_tuples.clone(),
            params,
            n: forged.n_t,
        };
        let (err_h, err_f) = (max_rank_err(&honest_final, &stream), max_rank_err(&forged_final, &stream));
        println!(
            "[gk2 θ] N_t={} s={} true θ={} claimed θ'={}: honest max rank err {err_h} (εN={eps_n}, \
             {} reps), over-merged max rank err {err_f} ({} reps); B2 violations {:?}",
            honest.n_t,
            params.s,
            honest.theta,
            forged.theta,
            honest_final.actives().len(),
            forged_final.actives().len(),
            semantic_damage(&forged_final, &stream)
        );
        assert_eq!(honest.theta, honest.n_t / params.s);
        assert!(err_h <= eps_n, "the honest final keeps the εN guarantee");
        assert!(err_f > eps_n, "PoC premise: the over-merged final breaks it");
        assert_ne!(commit_gk2_state(&forged_final).0, commit_gk2_state(&honest_final).0);

        // Pre-fix circuit (free θ): ACCEPTED, and the proof exposes Com(S').
        let mut leaf = build_gkb2_leaf_expose_with(params, Expose::Boundary, Binding::Legacy);
        let pre = crate::sketch::forge::catch_msg(|| {
            leaf.prove_build(s1.clone(), b2.clone(), &forged)
        });
        let proof = match pre {
            Ok(p) => p,
            Err(m) => panic!("PoC premise: the pre-fix circuit accepts the over-merge, got {m}"),
        };
        let pv = exposed_boundary(&proof.output.0);
        assert_eq!(&pv[8..], &commit_gk2_state(&forged_final).0[..], "exposes Com(S')");
        println!("[gk2 θ] Legacy (free θ): over-merged final ACCEPTED (self-verified)");

        // Fixed circuit: honest control verifies, the over-merge is rejected.
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = build_gkb2_leaf_expose_with(params, Expose::Boundary, binding);
            let ok = crate::sketch::forge::catch_msg(|| {
                leaf.prove_build(s1.clone(), b2.clone(), &honest)
            });
            assert!(ok.is_ok(), "{binding:?}: positive control (honest θ) must verify: {:?}", ok.err());
            let bad = crate::sketch::forge::catch_msg(|| {
                leaf.prove_build(s1.clone(), b2.clone(), &forged)
            });
            match &bad {
                Ok(_) => panic!("{binding:?}: the inflated θ must be rejected"),
                Err(m) => println!("[gk2 θ] {binding:?}: REJECTED: {m}"),
            }
        }
    }

    /// Every `θ ≠ ⌊N_t/s⌋` is rejected, not only inflated ones: an UNDER-stated
    /// threshold (fewer fusions, a fatter summary) and `θ = ⌊N_t/s⌋ ± 1` at
    /// the remainder boundaries. Shapes chosen so `N_t mod s` hits both `0`
    /// and `s − 1`. Legacy accepts each (control of the tamper plumbing).
    #[test]
    fn gk2_theta_off_by_one_rejected() {
        // (s, N): N mod s = 2 = s−1, 0, 0 (cap + m must be even).
        for (s, n) in [(3u64, 8usize), (4, 8), (3, 6)] {
            let params = GkbParams {
                capacity: 16,
                batch: n,
                s,
            };
            let vals = lcg_stream(7 + s, n, 1000);
            let s0 = Gk2State::empty(params);
            let honest = build_bm2(&s0, &vals);
            assert_eq!(honest.n_t, n as u64);
            let mut claims = vec![honest.theta + 1];
            if honest.theta > 0 {
                claims.push(honest.theta - 1);
            }
            for theta in claims {
                let f = finish_bm2(
                    &s0,
                    honest.sigma_union.clone(),
                    honest.sigma_union_chal.clone(),
                    honest.union_raw.clone(),
                    honest.n_prev,
                    honest.n_t,
                    theta,
                );
                if f.excess.iter().any(|t| t.active == 1) {
                    continue; // an under-stated θ that overflows the capacity
                }
                let mut legacy = build_gkb2_leaf_expose_with(params, Expose::None, Binding::Legacy);
                assert!(
                    crate::sketch::forge::catch_msg(|| legacy.prove_build(s0.clone(), vals.clone(), &f))
                        .is_ok(),
                    "s={s} N={n} θ'={theta}: Legacy accepts (control)"
                );
                let mut leaf = build_gkb2_leaf_expose_with(params, Expose::None, Binding::Semantic);
                assert!(
                    crate::sketch::forge::catch_msg(|| leaf.prove_build(s0.clone(), vals.clone(), &f))
                        .is_err(),
                    "s={s} N={n} θ={} θ'={theta}: must be rejected",
                    honest.theta
                );
            }
            // And the honest θ proves under Semantic.
            let mut leaf = build_gkb2_leaf_expose_with(params, Expose::None, Binding::Semantic);
            let _ = leaf.prove_build(s0.clone(), vals.clone(), &honest);
        }
    }

    /// Cost of the θ binding (Legacy = pre-fix vs Semantic), padded trace
    /// rows, primitive row counts and proof size. Run:
    /// `cargo test --release --lib gk_bandmerge::tests::gk2_theta_bind_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn gk2_theta_bind_overhead() {
        for &(cap, m) in &[(16usize, 8usize), (64, 16), (256, 16)] {
            let params = GkbParams {
                capacity: cap,
                batch: m,
                s: 8,
            };
            let vals = lcg_stream(7, m, 1 << 20);
            for binding in [Binding::Legacy, Binding::Semantic] {
                let mut leaf = build_gkb2_leaf_expose_with(params, Expose::None, binding);
                let t = std::time::Instant::now();
                let p = leaf.prove_epoch(Gk2State::empty(params), vals.clone());
                let bytes = postcard::to_allocvec(&p.output.0).map(|v| v.len()).unwrap_or(0);
                println!(
                    "[gk2 θ overhead] cap={cap} m={m} {binding:?}: trace_rows={} rows={:?} \
                     proof_bytes={bytes} prove+verify={:?}",
                    leaf.trace_rows,
                    p.output.0.rows,
                    t.elapsed()
                );
            }
        }
    }

    /// **Two-sided circuit over a CHAINED epoch**: prove epoch 1 (empty → s1),
    /// then feed the certified s1 as the old state for epoch 2 — exercising the
    /// full path with real old tuples (nonzero g₁,g₂,Δ₁,Δ₂), neighbor-init against
    /// old neighbors, and BOTH fusion branches — with commits chaining
    /// (init₂ = final₁).
    #[test]
    fn gk2_circuit_chained_epoch() {
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s: 3,
        };
        // mixed arrival so both the newer-left and newer-right (mirror) branches fire.
        let b1: Vec<u32> = vec![100, 400, 200, 700, 300, 600, 500, 800];
        let e1 = generate_proof2(params, b1);
        let s1 = e1.final_state.clone();

        let b2: Vec<u32> = vec![150, 650, 250, 750, 350, 550, 450, 850];
        let e2_commit_in = commit_gk2_state(&s1);
        let p2 = prove_gkb2(params, s1.clone(), b2.clone());
        // chaining: epoch-2 init commit == epoch-1 final commit.
        assert_eq!(p2.initial.0, e2_commit_in.0);
        assert_eq!(p2.initial.0, e1.proof.final_.0);
        // certified final matches the native chained state.
        let s2 = apply_batch2(&s1, &b2);
        assert_eq!(commit_gk2_state(&s2).0, p2.final_.0);
        assert!(s2.actives().len() <= params.capacity);
    }

    /// The mirror branch (case 2) genuinely fires: a right, *younger* neighbor
    /// folds LEFT into an older, smaller-valued representative — impossible for
    /// the one-sided rule. We feed values so the larger value is younger.
    #[test]
    fn two_sided_mirror_branch_fires() {
        let s = 4u64; // coarse ε so merging is aggressive
        let params = GkbParams {
            capacity: 64,
            batch: 32,
            s,
        };
        let mut state = Gk2State::empty(params);
        // Increasing values => each larger value is younger => case-2 (mirror) merges.
        let batch: Vec<u32> = (0..32u32).map(|i| i * 10).collect();
        state = apply_batch2(&state, &batch);

        let active = state.actives();
        check_invariant2(&state);
        assert!(
            active.len() < batch.len(),
            "mirror did not compress the increasing arrival: {} reps for {} distinct values",
            active.len(),
            batch.len()
        );
        // Value-sorted, distinct, mass conserved.
        for w in active.windows(2) {
            assert!(
                w[0].e < w[1].e,
                "representatives must be value-sorted & distinct"
            );
        }
        assert_eq!(active.iter().map(|t| t.mass()).sum::<u64>(), 32);
        // Some representative absorbed mass on its RIGHT (g° > 0) — the mirror at work.
        assert!(
            active.iter().any(|t| t.g_o > 0),
            "expected a nonzero right-mass g° from the mirror branch"
        );
        eprintln!(
            "mirror branch: 32 increasing values → {} reps (g° absorbed)",
            active.len()
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

    /// Forge the union by RE-PAIRING tuple halves: union positions `i` and
    /// `j` exchange their hi halves — `(Δ₂, t)` in the committed layout, and
    /// `(Δ₂, t, Δ₁)` in the source-bound layout (`hi_has_d1`). The
    /// challenge-level σ moves the same input challenges (so the multiset of
    /// permuted challenges is unchanged); neighbor-init, fusion rounds and
    /// compaction are then replayed honestly from the forged union.
    fn repair_union(
        s_old: &Gk2State,
        batch_vals: &[u32],
        i: usize,
        j: usize,
        hi_has_d1: bool,
    ) -> Bm2Build {
        let honest = build_bm2(s_old, batch_vals);
        let mut ur = honest.union_raw.clone();
        let (di, ti, d1i) = (ur[i].delta_o, ur[i].t, ur[i].delta);
        ur[i].delta_o = ur[j].delta_o;
        ur[i].t = ur[j].t;
        ur[j].delta_o = di;
        ur[j].t = ti;
        if hi_has_d1 {
            ur[i].delta = ur[j].delta;
            ur[j].delta = d1i;
        }
        let mut sc = honest.sigma_union_chal.clone();
        sc.swap(2 * i + 1, 2 * j + 1);
        finish_bm2(
            s_old,
            honest.sigma_union.clone(),
            sc,
            ur,
            honest.n_prev,
            honest.n_t,
            honest.theta,
        )
    }

    /// The union order the circuit checks: e non-decreasing, t ascending on ties.
    fn union_order_ok(ur: &[Gk2Tuple]) -> bool {
        ur.windows(2)
            .all(|w| w[0].e < w[1].e || (w[0].e == w[1].e && w[0].t <= w[1].t))
    }

    /// Count (B2 violations, εN rank-interval violations) of a state against
    /// the true stream.
    fn semantic_damage(state: &Gk2State, stream: &[u32]) -> (usize, usize) {
        let theta = state.n / state.params.s;
        let b2 = state
            .actives()
            .iter()
            .filter(|t| t.g + t.delta > theta || t.g_o + t.delta_o > theta)
            .count();
        let mut qs: Vec<u32> = stream.to_vec();
        qs.extend(stream.iter().map(|&x| x.saturating_sub(1)));
        qs.extend(stream.iter().map(|&x| x + 1));
        qs.sort_unstable();
        qs.dedup();
        let rank_bad = qs
            .iter()
            .filter(|&&q| {
                let truth = stream.iter().filter(|&&x| x <= q).count() as u64;
                let (lo, hi) = state.rank_interval(q);
                truth < lo || truth > hi
            })
            .count();
        (b2, rank_bad)
    }

    /// **Tuple-half re-pairing probe.** Each two-sided tuple is permuted as two
    /// separate challenges lo=(e,g₁,g₂,Δ₁), hi=(Δ₂,t,0,0); `expand_sigma` only
    /// describes the honest pairing. Swapping the hi halves of an OLD tuple and
    /// a FRESH tuple flips both `is_fresh` gates: the fresh value inherits the
    /// old timestamp (so it keeps its committed Δ₁=0 instead of the neighbor
    /// init), and the old representative is re-initialized as if fresh. Mass,
    /// sortedness and the (e,t) tiebreak all still hold.
    #[test]
    fn gk2_half_repairing_forgery_rejected() {
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s: 3,
        };
        let b1: Vec<u32> = vec![100, 400, 200, 700, 300, 600, 500, 800];
        let b2: Vec<u32> = vec![150, 650, 250, 750, 350, 550, 450, 850];
        let s1 = apply_batch2(&Gk2State::empty(params), &b1);
        let honest = build_bm2(&s1, &b2);
        let honest_final = Gk2State {
            tuples: honest.final_tuples.clone(),
            params,
            n: honest.n_t,
        };
        let stream: Vec<u32> = b1.iter().chain(b2.iter()).copied().collect();

        // Search an (old i, fresh j) pair whose re-paired union is still
        // circuit-ordered, fits the capacity, and changes the final state;
        // prefer one that also breaks the rank guarantee.
        let n_prev = honest.n_prev;
        let ur = &honest.union_raw;
        let mut pick: Option<(usize, usize, Bm2Build, (usize, usize))> = None;
        for i in 0..ur.len() {
            if ur[i].active != 1 || ur[i].t > n_prev {
                continue;
            }
            for j in 0..ur.len() {
                if ur[j].active != 1 || ur[j].t <= n_prev {
                    continue;
                }
                let f = repair_union(&s1, &b2, i, j, false);
                if !union_order_ok(&f.union_raw) || f.excess.iter().any(|t| t.active == 1) {
                    continue;
                }
                if f.final_tuples == honest.final_tuples {
                    continue;
                }
                let st = Gk2State {
                    tuples: f.final_tuples.clone(),
                    params,
                    n: f.n_t,
                };
                let dmg = semantic_damage(&st, &stream);
                let better = match &pick {
                    None => true,
                    Some((_, _, _, d)) => (dmg.0 + dmg.1) > (d.0 + d.1),
                };
                if better {
                    pick = Some((i, j, f, dmg));
                }
            }
        }
        let (i, j, forged, dmg) = pick.expect("a re-pairing that changes the final state");
        let forged_final = Gk2State {
            tuples: forged.final_tuples.clone(),
            params,
            n: forged.n_t,
        };
        println!(
            "[gk2 re-pair] swap hi halves of union[{i}] (old e={}) and union[{j}] (fresh e={}); \
             forged final: {} B2 violations, {} rank-interval violations (honest: {:?})",
            ur[i].e,
            ur[j].e,
            dmg.0,
            dmg.1,
            semantic_damage(&honest_final, &stream)
        );
        assert_ne!(
            commit_gk2_state(&forged_final).0,
            commit_gk2_state(&honest_final).0
        );

        // Pre-fix circuit (committed layout on the permutes): ACCEPTED.
        PAIR_BIND.with(|c| c.set(Some(false)));
        let mut leaf = build_gkb2_leaf(params, false);
        PAIR_BIND.with(|c| c.set(None));
        let pre = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            leaf.prove_build(s1.clone(), b2.clone(), &forged)
        }));
        match &pre {
            Ok(_) => println!("[gk2 re-pair] pre-fix: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[gk2 re-pair] pre-fix: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the pre-fix circuit accepts the re-pairing");

        // Fixed circuit (source-bound layout), same swap of whole hi halves.
        let forged_b = repair_union(&s1, &b2, i, j, true);
        // (a) truthful source labels: the output binding hi[3]−lo[3]=2^SRC_BITS
        //     cannot hold (the halves name different sources).
        let mut leaf = build_gkb2_leaf(params, false);
        let post_a = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            leaf.prove_build(s1.clone(), b2.clone(), &forged_b)
        }));
        match &post_a {
            Ok(_) => println!("[gk2 re-pair] fixed (a): ACCEPTED"),
            Err(e) => println!("[gk2 re-pair] fixed (a) truthful labels: REJECTED: {}", panic_msg(e)),
        }
        assert!(post_a.is_err(), "re-paired halves with truthful source labels must be rejected");

        // (b) lying labels: both halves claim the lo's source, so the binding
        //     holds, but the emitted hi element is not any permute input —
        //     a malicious prover must forge the Permute op's outputs.
        let mut lying = forged_b.clone();
        lying.sigma_union_chal = expand_sigma(&lying.sigma_union);
        let src: Vec<usize> = lying.sigma_union.clone();
        let outs = pack_bound2(&lying.union_raw, 0, &src, &src);
        let mut leaf = build_gkb2_leaf(params, false);
        let mut sigmas = vec![lying.sigma_union_chal.clone()];
        for rd in &lying.rounds {
            sigmas.push(expand_sigma(&rd.sigma));
        }
        leaf.circuit.update_permute_witnesses(&sigmas).expect("sigmas");
        crate::sketch::forge_permute::forge_permute_outputs(&mut leaf.circuit, 0, outs);
        let post_b = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            leaf.prove_build(s1.clone(), b2.clone(), &lying)
        }));
        match &post_b {
            Ok(_) => println!("[gk2 re-pair] fixed (b): ACCEPTED"),
            Err(e) => println!("[gk2 re-pair] fixed (b) lying labels: REJECTED: {}", panic_msg(e)),
        }
        assert!(post_b.is_err(), "re-paired halves with forged labels must be rejected");
    }

    /// Cost of the source-bound layout (padded trace rows + one prove), pre-fix
    /// vs fixed. Run:
    /// `cargo test --release --lib gk_bandmerge::tests::gk2_fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn gk2_fix_overhead() {
        for &(cap, m) in &[(64usize, 16usize), (256, 16), (1024, 16)] {
            let params = GkbParams {
                capacity: cap,
                batch: m,
                s: 8,
            };
            let vals = lcg_stream(7, m, 1 << 20);
            for (label, bind) in [("pre-fix", false), ("source-bound", true)] {
                PAIR_BIND.with(|c| c.set(Some(bind)));
                let mut leaf = build_gkb2_leaf(params, false);
                PAIR_BIND.with(|c| c.set(None));
                let t = std::time::Instant::now();
                let _ = leaf.prove_epoch(Gk2State::empty(params), vals.clone());
                println!(
                    "[gk2 fix_overhead] cap={cap} m={m} {label:<13} trace_rows={} prove+verify={:?}",
                    leaf.trace_rows,
                    t.elapsed()
                );
            }
        }
    }

    /// Forged-decomposition regression test (Greenwald–Khanna family, the
    /// deployed band-merge leaf). The prover commits to `Com(S')` with the
    /// first active final tuple's `Δ` bumped by 1, while the decomposition of
    /// that packed tuple half, which every compaction constraint reads, returns
    /// the honest tuple. Under the pre-fix recompose lowering nothing ties the
    /// two, and the proof verifies for a state the batch never produced. The
    /// fork's `recompose/coeff` lowering rejects it.
    #[test]
    fn forged_final_decomposition_rejected() {
        use p3_field::BasedVectorSpace;
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s: 3,
        };
        let b1: Vec<u32> = vec![100, 400, 200, 700, 300, 600, 500, 800];
        let b2: Vec<u32> = vec![150, 650, 250, 750, 350, 550, 450, 850];
        let s1 = apply_batch2(&Gk2State::empty(params), &b1);
        let honest = build_bm2(&s1, &b2);
        let i = honest
            .final_tuples
            .iter()
            .position(|t| t.active == 1)
            .expect("an active final tuple");
        let mut forged = honest.clone();
        forged.final_tuples[i].delta += 1;
        let forged_final = Gk2State {
            tuples: forged.final_tuples.clone(),
            params,
            n: forged.n_t,
        };
        let honest_final = Gk2State {
            tuples: honest.final_tuples.clone(),
            params,
            n: honest.n_t,
        };
        // Tuple i's lo half (e, g, g_o, Δ) is private input 2·cap + 2i.
        let honest_lo: [Val; 4] = enc2(&honest.final_tuples[i])[0]
            .as_basis_coefficients_slice()
            .try_into()
            .expect("4 coefficients");
        let run = |mut leaf: Gkb2LeafCircuit| {
            let wid = leaf.circuit.private_input_rows[2 * params.capacity + 2 * i];
            crate::sketch::forge_permute::forge_decomposition(&mut leaf.circuit, wid, honest_lo);
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                leaf.prove_build(s1.clone(), b2.clone(), &forged).final_
            }))
        };

        let legacy = run(crate::recompose_binding::with_unbound_recompose(|| {
            build_gkb2_leaf(params, false)
        }))
        .expect("PoC premise: the unbound lowering accepts the forged final state");
        assert_eq!(legacy.0, commit_gk2_state(&forged_final).0, "exposes Com(S')");
        assert_ne!(legacy.0, commit_gk2_state(&honest_final).0, "not the certified update");

        assert!(
            run(build_gkb2_leaf(params, false)).is_err(),
            "recompose/coeff lowering must reject the forged final state"
        );
    }

    // ─── One-sided prove_gkb: shared-PermuteBus probe ───────────────────────

    /// Rank-interval violations of a one-sided state against the true stream
    /// (distinct values): for every active tuple `i` in value order the true
    /// rank of `e_i` must lie in `[r_min_i, r_min_i + Δ_i]`, `r_min_i = Σ_{j≤i} g_j`.
    fn gkb_rank_violations(state: &GkbState, stream: &[u32]) -> usize {
        let mut acts = state.actives();
        acts.sort_by_key(|t| (t.e, t.t));
        let mut rmin = 0u64;
        let mut bad = 0;
        for t in &acts {
            rmin += t.g;
            let truth = stream.iter().filter(|&&x| x <= t.e).count() as u64;
            if truth < rmin || truth > rmin + t.delta {
                bad += 1;
            }
        }
        bad
    }

    /// Malicious one-sided witness exploiting the SHARED PermuteBus: the fresh
    /// union tuple at `x_pos` leaves the union permute's output (an E_MAX dummy
    /// takes its slot), neighbor-init and all `L_f` fuse rounds are replayed
    /// honestly WITHOUT it, and it re-enters in the LAST round's resort output
    /// in place of a dummy — still carrying its committed `Δ = 0`. Per op the
    /// multisets differ; only the union of all permute rows balances. `None` if
    /// the forged final would overflow the capacity.
    fn forge_skip_rounds(s_old: &GkbState, batch: &[u32], x_pos: usize) -> Option<BmBuild> {
        let cap = s_old.params.capacity;
        let honest = build_bm(s_old, batch);
        let mut ur = honest.union_raw.clone();
        let x = ur.remove(x_pos);
        ur.push(GkbTuple::dummy()); // dummies (E_MAX) sort last
        let mut f = finish_bm(
            s_old,
            honest.sigma_union.clone(),
            ur,
            honest.n_prev,
            honest.n_t,
            honest.theta,
        );
        let last = f.rounds.last_mut().expect("L_f ≥ 1");
        let dpos = last.resorted.iter().position(|t| *t == GkbTuple::dummy())?;
        last.resorted.remove(dpos);
        let ins = last
            .resorted
            .iter()
            .position(|t| (t.e, t.t) > (x.e, x.t))
            .unwrap_or(last.resorted.len());
        last.resorted.insert(ins, x);
        f.final_tuples = last.resorted[..cap].to_vec();
        f.excess = last.resorted[cap..].to_vec();
        if f.excess.iter().any(is_active) {
            return None;
        }
        Some(f)
    }

    /// **Inflated-threshold PoC on the one-sided circuit (revision B6(d)).**
    /// Same attack as `gk2_inflated_theta_legacy_accepts_semantic_rejects`:
    /// the rounds are replayed under a claimed `θ' > ⌊N_t/s⌋`, so the certified
    /// final over-merges and violates invariant A2 (`g + Δ ≤ ⌊εN⌋`). Legacy
    /// (free `θ`) ACCEPTS it; Semantic rejects it and proves the honest build.
    #[test]
    fn gkb_inflated_theta_legacy_accepts_semantic_rejects() {
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s: 3,
        };
        let b1: Vec<u32> = vec![800, 700, 600, 500, 400, 300, 200, 100];
        let b2: Vec<u32> = vec![750, 650, 550, 450, 350, 250, 150, 50];
        let s1 = apply_batch(&GkbState::empty(params), &b1);
        let honest = build_bm(&s1, &b2);
        let a2_violations = |ts: &[GkbTuple]| {
            ts.iter()
                .filter(|t| t.active == 1 && t.g + t.delta > honest.theta)
                .count()
        };
        assert_eq!(a2_violations(&honest.final_tuples), 0);
        let forged = (honest.theta + 1..=honest.n_t)
            .map(|theta| {
                finish_bm(
                    &s1,
                    honest.sigma_union.clone(),
                    honest.union_raw.clone(),
                    honest.n_prev,
                    honest.n_t,
                    theta,
                )
            })
            .find(|f| {
                f.excess.iter().all(|t| t.active == 0) && a2_violations(&f.final_tuples) > 0
            })
            .expect("an inflated θ whose over-merge violates A2");
        println!(
            "[gkb θ] N_t={} true θ={} claimed θ'={}: {} A2 violations, {} → {} reps",
            honest.n_t,
            honest.theta,
            forged.theta,
            a2_violations(&forged.final_tuples),
            honest.final_tuples.iter().filter(|t| t.active == 1).count(),
            forged.final_tuples.iter().filter(|t| t.active == 1).count(),
        );
        let run = |build: &BmBuild, binding: Binding| {
            crate::sketch::forge::catch_msg(|| {
                prove_gkb_build(params, s1.clone(), b2.clone(), build, binding)
            })
        };
        let pre = run(&forged, Binding::Legacy);
        assert!(pre.is_ok(), "PoC premise: Legacy (free θ) accepts: {:?}", pre.err());
        let forged_state = GkbState {
            tuples: forged.final_tuples.clone(),
            params,
            n: forged.n_t,
        };
        assert_eq!(pre.unwrap().final_.0, commit_gkb_state(&forged_state).0);
        assert!(run(&honest, Binding::Semantic).is_ok(), "positive control: honest θ verifies");
        match run(&forged, Binding::Semantic) {
            Ok(_) => panic!("Semantic must reject the inflated θ"),
            Err(m) => println!("[gkb θ] Semantic: REJECTED: {m}"),
        }
    }

    /// **Shared-PermuteBus forgery on the one-sided circuit.** A fresh value is
    /// routed around the union output and every fuse round (its committed
    /// `Δ = 0` never gets the neighbor-init `g_right + Δ_right − 1`), so the
    /// certified final understates its rank uncertainty: the true rank of that
    /// value falls outside `[r_min, r_min + Δ]`. Mass (`Σg = N_t`), value
    /// sortedness and every fuse decision still hold.
    ///
    /// Pre-fix circuit (untagged permutes): ACCEPTED (self-verifies). With the
    /// `t`-coordinate op tag the same malicious prover is REJECTED: the tuple
    /// the last round emits carries op tag `L_f` and has no matching element
    /// on the PermuteBus (its only copy is the union op's class-0 input).
    #[test]
    fn gkb_shared_bus_forgery_rejected() {
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s: 3,
        };
        let b1: Vec<u32> = vec![900, 800, 700, 600, 500, 400, 300, 200];
        let b2: Vec<u32> = vec![850, 250, 650, 450, 950, 150, 550, 350];
        let s1 = apply_batch(&GkbState::empty(params), &b1);
        let honest = build_bm(&s1, &b2);
        let stream: Vec<u32> = b1.iter().chain(b2.iter()).copied().collect();
        let honest_final = GkbState {
            tuples: honest.final_tuples.clone(),
            params,
            n: honest.n_t,
        };
        assert_eq!(
            gkb_rank_violations(&honest_final, &stream),
            0,
            "honest final must satisfy the rank intervals"
        );
        let _honest_proof = prove_gkb(params, s1.clone(), b2.clone());

        // Pick the fresh tuple whose round-skipping does the most damage.
        let mut pick: Option<(usize, BmBuild, usize)> = None;
        for (pos, t) in honest.union_raw.iter().enumerate() {
            if !is_active(t) || t.t <= honest.n_prev {
                continue;
            }
            let Some(f) = forge_skip_rounds(&s1, &b2, pos) else {
                continue;
            };
            let st = GkbState {
                tuples: f.final_tuples.clone(),
                params,
                n: f.n_t,
            };
            let bad = gkb_rank_violations(&st, &stream);
            if pick.as_ref().is_none_or(|(_, _, b)| bad > *b) {
                pick = Some((pos, f, bad));
            }
        }
        let (pos, forged, bad) = pick.expect("a fresh tuple to route around the rounds");
        let x = honest.union_raw[pos];
        let forged_final = GkbState {
            tuples: forged.final_tuples.clone(),
            params,
            n: forged.n_t,
        };
        println!(
            "[gkb shared bus] fresh e={} (t={}) skips neighbor-init + {} rounds; \
             forged final: {} rank-interval violations (honest: 0)",
            x.e,
            x.t,
            num_rounds(params.capacity + params.batch),
            bad
        );
        assert!(bad > 0, "the forged final must break the rank guarantee");
        assert_eq!(
            forged_final.actives().iter().map(|t| t.g).sum::<u64>(),
            forged.n_t,
            "forged final conserves mass"
        );
        assert_ne!(
            commit_gkb_state(&forged_final).0,
            commit_gkb_state(&honest_final).0
        );

        let lf = num_rounds(params.capacity + params.batch);
        let x_row = forged.rounds[lf - 1]
            .resorted
            .iter()
            .position(|t| *t == x)
            .expect("x re-enters the last round");
        let run = |tag: bool, untag_x: bool| {
            GKB_OP_TAG.with(|c| c.set(Some(tag)));
            GKB_UNTAG_ROW.with(|c| c.set(untag_x.then_some((lf - 1, x_row))));
            GKB_FORGE.with(|f| {
                *f.borrow_mut() = vec![
                    (0, forged.union_raw.clone()),
                    (lf, forged.rounds[lf - 1].resorted.clone()),
                ]
            });
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_gkb_build(params, s1.clone(), b2.clone(), &forged, bind::default_binding())
            }));
            GKB_OP_TAG.with(|c| c.set(None));
            GKB_UNTAG_ROW.with(|c| c.set(None));
            GKB_FORGE.with(|f| f.borrow_mut().clear());
            r
        };
        let pre = run(false, false);
        match &pre {
            Ok(_) => println!("[gkb shared bus] pre-fix: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[gkb shared bus] pre-fix: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the untagged circuit accepts the forgery");
        // (a) the malicious prover tags x like the rest of the last round's
        //     output: no matching (class-0) element on the PermuteBus.
        let post_a = run(true, false);
        match &post_a {
            Ok(_) => println!("[gkb shared bus] fixed (a) tagged x: ACCEPTED"),
            Err(e) => println!("[gkb shared bus] fixed (a) tagged x: REJECTED: {}", panic_msg(e)),
        }
        assert!(post_a.is_err(), "op tags must stop the union and a round trading tuples");
        // (b) it leaves x untagged so the bus balances: the de-tagged
        //     t − L_f·2^24 wraps and fails the output-side range check.
        let post_b = run(true, true);
        match &post_b {
            Ok(_) => println!("[gkb shared bus] fixed (b) untagged x: ACCEPTED"),
            Err(e) => println!("[gkb shared bus] fixed (b) untagged x: REJECTED: {}", panic_msg(e)),
        }
        assert!(post_b.is_err(), "an untagged output must fail the de-tagged t range check");
    }

    /// Cost of the one-sided op tag (padded trace rows + one prove), pre-fix vs
    /// fixed. Run:
    /// `cargo test --release --lib gk_bandmerge::tests::gkb_fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn gkb_fix_overhead() {
        for &(cap, m) in &[(64usize, 16usize), (256, 16), (1024, 16)] {
            let params = GkbParams {
                capacity: cap,
                batch: m,
                s: 8,
            };
            let vals = lcg_stream(7, m, 1 << 20);
            for (label, tag) in [("pre-fix", false), ("op-tag", true)] {
                GKB_OP_TAG.with(|c| c.set(Some(tag)));
                let t = std::time::Instant::now();
                let _ = prove_gkb(params, GkbState::empty(params), vals.clone());
                GKB_OP_TAG.with(|c| c.set(None));
                println!(
                    "[gkb fix_overhead] cap={cap} m={m} {label:<8} trace_rows={} prove+verify={:?}",
                    crate::recursion::recursive::timing::take().trace_rows,
                    t.elapsed()
                );
            }
        }
    }

    // ─── Naive two-sided replay: half re-pairing / shared-bus probe ─────────

    /// Replay a naive epoch honestly, except that at record `k0` the insert
    /// permute RE-PAIRS the hi halves of work rows `i` and `jf` (`(Δ₂,t)` in
    /// the committed layout, `(Δ₂,t,Δ₁)` in the source-bound one): the
    /// challenge-level σ moves the same input challenges, so the multiset of
    /// permuted challenges is unchanged. `None` if the forged work is not
    /// `(e,t)`-ordered or a later step has no mergeable pair.
    fn forge_naive2_repair(
        s_old: &Gk2State,
        batch: &[u32],
        k0: usize,
        i: usize,
        jf: usize,
        hi_has_d1: bool,
    ) -> Option<Naive2Build> {
        let (cap, m, s) = (s_old.params.capacity, s_old.params.batch, s_old.params.s);
        let mut states = vec![s_old.tuples.clone()];
        let mut steps = Vec::with_capacity(m);
        let mut cur = s_old.tuples.clone();
        let mut n = s_old.n;
        for j in 0..m {
            let val = batch.get(j).copied();
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if j != k0 {
                    return Some(replay_step2(&cur, cap, s, n, val));
                }
                let n_after = n + val.is_some() as u64;
                let mut combined = cur.clone();
                combined.push(fresh_tuple2(val, n_after));
                let (mut work, sigma) = sort_by_et2(&combined);
                let mut sc = expand_sigma(&sigma);
                let (d2, t, d1) = (work[i].delta_o, work[i].t, work[i].delta);
                work[i].delta_o = work[jf].delta_o;
                work[i].t = work[jf].t;
                work[jf].delta_o = d2;
                work[jf].t = t;
                if hi_has_d1 {
                    work[i].delta = work[jf].delta;
                    work[jf].delta = d1;
                }
                sc.swap(2 * i + 1, 2 * jf + 1);
                if !work
                    .windows(2)
                    .all(|w| w[0].e < w[1].e || (w[0].e == w[1].e && w[0].t <= w[1].t))
                {
                    return None;
                }
                Some(finish_step2(work, sigma, sc, cap, s, n_after, val.is_some()))
            }));
            let (step, next) = res.ok().flatten()?;
            if val.is_some() {
                n += 1;
            }
            cur = next;
            steps.push(step);
            states.push(cur.clone());
        }
        Some(Naive2Build {
            states,
            steps,
            n_prev: s_old.n,
            n_final: n,
        })
    }

    /// Search record `k0`, old row `i`, fresh row `jf` for the most damaging
    /// re-pairing (committed layout). Returns `(k0, i, jf, forged, damage)`.
    fn search_naive2_repair(
        s_old: &Gk2State,
        batch: &[u32],
        stream: &[u32],
    ) -> Option<(usize, usize, usize, Naive2Build, (usize, usize))> {
        let params = s_old.params;
        let honest = replay_batch2(s_old, batch);
        let mut pick: Option<(usize, usize, usize, Naive2Build, (usize, usize))> = None;
        let mut nb = s_old.n;
        for k0 in 0..batch.len() {
            let w = &honest.steps[k0].work;
            for i in 0..w.len() {
                if w[i].active != 1 || w[i].t > nb {
                    continue;
                }
                for jf in 0..w.len() {
                    if w[jf].active != 1 || w[jf].t <= nb {
                        continue;
                    }
                    let Some(f) = forge_naive2_repair(s_old, batch, k0, i, jf, false) else {
                        continue;
                    };
                    let st = Gk2State {
                        tuples: f.states[params.batch].clone(),
                        params,
                        n: f.n_final,
                    };
                    let dmg = semantic_damage(&st, stream);
                    if dmg.0 + dmg.1 > 0
                        && pick.as_ref().is_none_or(|p| dmg.0 + dmg.1 > p.4.0 + p.4.1)
                    {
                        pick = Some((k0, i, jf, f, dmg));
                    }
                }
            }
            nb += 1;
        }
        pick
    }

    /// **Tuple-half re-pairing / shared-bus forgery on the naive replay.** At
    /// one record the insert permute swaps the hi halves of an OLD work row and
    /// the FRESH row: the fresh value inherits the old timestamp (skipping
    /// neighbor-init) and the old representative is re-initialized as if
    /// fresh. The rest of the epoch replays honestly; the certified final
    /// breaks the two-sided rank guarantee.
    ///
    /// Pre-fix (committed layout on the permutes): ACCEPTED. Source-bound
    /// layout: REJECTED with truthful source labels (the output pair's
    /// `hi[3] − lo[3] ≠ 2^sb`) and with lying labels (the emitted hi element is
    /// no input of that op → PermuteBus mismatch).
    #[test]
    fn gk2_naive_half_repairing_forgery_rejected() {
        let params = GkbParams {
            capacity: 4,
            batch: 8,
            s: 2,
        };
        let b1: Vec<u32> = lcg_stream(11, params.batch, 1000);
        let b2: Vec<u32> = lcg_stream(29, params.batch, 1000);
        let s1 = apply_batch2_naive(&Gk2State::empty(params), &b1);
        let stream: Vec<u32> = b1.iter().chain(b2.iter()).copied().collect();
        let honest = apply_batch2_naive(&s1, &b2);
        assert_eq!(semantic_damage(&honest, &stream), (0, 0));
        let _honest_proof = prove_gkb2_naive(params, s1.clone(), b2.clone());

        let (k0, i, jf, forged, dmg) =
            search_naive2_repair(&s1, &b2, &stream).expect("a damaging re-pairing");
        let forged_final = Gk2State {
            tuples: forged.states[params.batch].clone(),
            params,
            n: forged.n_final,
        };
        println!(
            "[gk2 naive re-pair] record {k0}: swap hi halves of work[{i}] (old) and work[{jf}] \
             (fresh); forged final: {} B2 violations, {} rank-interval violations (honest: 0, 0)",
            dmg.0, dmg.1
        );
        assert_ne!(
            commit_gk2_state(&forged_final).0,
            commit_gk2_state(&honest).0
        );
        let run = |bind: bool, build: &Naive2Build, forge: Vec<(usize, Vec<Challenge>)>| {
            PAIR_BIND.with(|c| c.set(Some(bind)));
            NAIVE2_FORGE.with(|f| *f.borrow_mut() = forge);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_gkb2_naive_build(params, s1.clone(), b2.clone(), build)
            }));
            PAIR_BIND.with(|c| c.set(None));
            NAIVE2_FORGE.with(|f| f.borrow_mut().clear());
            r
        };

        // Pre-fix circuit: ACCEPTED.
        let pre = run(false, &forged, vec![]);
        match &pre {
            Ok(_) => println!("[gk2 naive re-pair] pre-fix: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[gk2 naive re-pair] pre-fix: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the pre-fix naive circuit accepts the re-pairing");

        // Fixed circuit, same swap of whole (source-bound) hi halves.
        let forged_b = forge_naive2_repair(&s1, &b2, k0, i, jf, true).expect("source-bound swap");
        // (a) truthful source labels (the Permute op really moved those halves).
        let post_a = run(true, &forged_b, vec![]);
        match &post_a {
            Ok(_) => println!("[gk2 naive re-pair] fixed (a): ACCEPTED"),
            Err(e) => println!("[gk2 naive re-pair] fixed (a) truthful labels: REJECTED: {}", panic_msg(e)),
        }
        assert!(post_a.is_err(), "re-paired halves with truthful labels must be rejected");
        // (b) lying labels: both halves claim the lo's source; the Permute op's
        //     outputs must be forged (the emitted hi element is no input).
        let mut lying = forged_b.clone();
        lying.steps[k0].sigma_insert_chal = expand_sigma(&lying.steps[k0].sigma_insert);
        let sb = naive2_src_bits(params.capacity + 1);
        let outs = naive2_pack_work(&lying.steps[k0], k0, true, sb);
        let post_b = run(true, &lying, vec![(2 * k0, outs)]);
        match &post_b {
            Ok(_) => println!("[gk2 naive re-pair] fixed (b): ACCEPTED"),
            Err(e) => println!("[gk2 naive re-pair] fixed (b) lying labels: REJECTED: {}", panic_msg(e)),
        }
        assert!(post_b.is_err(), "re-paired halves with forged labels must be rejected");
    }

    /// Cost of the naive replay's source-bound layout (padded trace rows + one
    /// prove), pre-fix vs fixed. Run:
    /// `cargo test --release --lib gk_bandmerge::tests::gk2_naive_fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn gk2_naive_fix_overhead() {
        for &(cap, m) in &[(16usize, 16usize), (64, 16), (256, 16)] {
            let params = GkbParams {
                capacity: cap,
                batch: m,
                s: 8,
            };
            let vals = lcg_stream(7, m, 1 << 20);
            for (label, bind) in [("pre-fix", false), ("source-bound", true)] {
                PAIR_BIND.with(|c| c.set(Some(bind)));
                let t = std::time::Instant::now();
                let _ = prove_gkb2_naive(params, Gk2State::empty(params), vals.clone());
                PAIR_BIND.with(|c| c.set(None));
                println!(
                    "[gk2 naive fix_overhead] cap={cap} m={m} {label:<13} trace_rows={} prove+verify={:?}",
                    crate::recursion::recursive::timing::take().trace_rows,
                    t.elapsed()
                );
            }
        }
    }
}
