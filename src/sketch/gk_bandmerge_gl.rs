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
//! count (public in the streaming-forest log).
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

// The one-sided (`prove_gkb`) and `_naive` circuit provers are NOT ported to
// Goldilocks (they are BabyBear baseline-only, unused by the forest). Their
// pure-Rust native helpers are retained for reference and become dead code here.
#![allow(dead_code)]

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

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    GoldilocksD2Width8, Poseidon2Config, generate_expose_trace, generate_permute_trace,
    generate_poseidon2_trace, generate_range_trace, generate_recompose_trace,
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
use p3_field::PrimeCharacteristicRing;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::config_gl::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl as ConfigWithFriParams;
use crate::recursion::recursive::leaf_gl::{
    DIGEST_PACKING, GlCommit, make_leaf_config, pack_commit_to_challenge,
};

// ── Goldilocks D=2 encoding (parallels ss_final_full_gl) ─────────────────────
//
// Each `Gk2Tuple` has SIX numeric fields `(e, g₁, g₂, Δ₁, Δ₂, t)`. BabyBear's
// D=4 encoding held them in TWO Challenges (8 coords: `[e,g₁,g₂,Δ₁]`/`[Δ₂,t,0,0]`).
// Goldilocks D=2 gives only 2 coords per Challenge, so each tuple is THREE cells,
// ONE field per coord (no packing):
//   cell0 = [e,  g₁]    cell1 = [g₂,  Δ₁]    cell2 = [Δ₂,  t]
// This costs a 1.5× wider permute vs BabyBear but keeps every field a RAW coord —
// range-checked exactly once by the existing Stage 3–8 body, with NO in-circuit
// `decompose_to_bits`/reconstruction. (An earlier 2-cell packing that shifted two
// fields per coord and split them in-circuit blew the trace up ~13× in memory —
// the split's per-bit reconstruction dominated; the raw 3-cell layout is the fix.)
// `unpack_gk_table` still assembles the exact BabyBear-shaped `f`
// (`f[2r]=[e,g₁,g₂,Δ₁]`, `f[2r+1]=[Δ₂,t,0,0]`), so the whole body is reused
// byte-for-byte; only the CELL-level counts (alloc, permute, `expand_sigma`) go
// 2→3 per tuple. The two trailing `0`s of `f[2r+1]` are the shared `zero` const
// (the packing has no spare coord to abuse — cell2's two coords are both fields).

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

struct BmRound {
    decisions: Vec<u32>,
    fused: Vec<GkbTuple>,
    resorted: Vec<GkbTuple>,
    sigma: Vec<usize>,
}

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

struct Bm2Round {
    #[allow(dead_code)] // captured for reference; the circuit re-derives the direction from hints.
    dir: Vec<u8>,
    cond1: Vec<u32>,
    cond2: Vec<u32>,
    fused: Vec<Gk2Tuple>,
    resorted: Vec<Gk2Tuple>,
    sigma: Vec<usize>,
}

struct Bm2Build {
    sigma_union: Vec<usize>,
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
struct Naive2Step {
    /// `prev ‖ fresh`, sorted by `(e,t)`, fresh `Δ=0` (the permute output) —
    /// length `cap+1`.
    work: Vec<Gk2Tuple>,
    /// `work` with the fresh row's two-sided neighbor-init `Δ₁,Δ₂` set (the
    /// table the compress actually operates on; the circuit re-derives it).
    work_init: Vec<Gk2Tuple>,
    /// `work[j] = (prev ‖ fresh)[sigma_insert[j]]`.
    sigma_insert: Vec<usize>,
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
    let theta = n_after / s;
    // fresh singleton (or a dummy for a padding record).
    let fresh = match val {
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
    };
    let mut combined = prev.to_vec();
    combined.push(fresh);
    let (work, sigma_insert) = sort_by_et2(&combined);

    // neighbor-init the fresh tuple (the one with t == n_after, if active).
    let mut work_init = work.clone();
    if val.is_some() {
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



// ── Two-sided in-circuit certificate ──────────────────────────────────────
//
// A two-sided tuple has SIX fields, but one `Challenge` (a degree-4 extension
// element) holds only four base coefficients, so each tuple is packed into TWO
// challenges: lo = (e, g₁, g₂, Δ₁), hi = (Δ₂, t, 0, 0). Tuple `r` therefore
// occupies challenge slots `2r, 2r+1`. Active detection can no longer use
// `[g≠0]` (a fresh singleton has g₁=g₂=0) — we use the value marker `[e≠E_MAX]`.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Gk2StateCommit(pub [Val; 4]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Gk2BatchCommit(pub [Val; 4]);

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

/// Encode a tuple as THREE Goldilocks (D=2) challenges, one field per coord:
///   cell0 = [e, g₁]   cell1 = [g₂, Δ₁]   cell2 = [Δ₂, t]
/// Fields stay raw (no packing) so the body range-checks each exactly once.
fn enc2(t: &Gk2Tuple) -> [Challenge; 3] {
    use p3_field::BasedVectorSpace;
    let mk = |a: u64, b: u64| {
        Challenge::from_basis_coefficients_slice(&[Val::from_u64(a), Val::from_u64(b)])
            .expect("2 coeffs")
    };
    [
        mk(t.e as u64, t.g),
        mk(t.g_o, t.delta),
        mk(t.delta_o, t.t),
    ]
}

pub fn pack_tuples2(ts: &[Gk2Tuple]) -> Vec<Challenge> {
    ts.iter().flat_map(|t| enc2(t)).collect()
}

/// Flatten to base vals in the SAME order as the challenges' coeffs
/// (`[e, g₁, g₂, Δ₁, Δ₂, t]` per tuple = 6 Goldilocks Vals), so `hash_iter`
/// matches the circuit hash (3 D=2 cells → 6 base coords).
fn flat_tuples2(ts: &[Gk2Tuple]) -> Vec<Val> {
    ts.iter()
        .flat_map(|t| {
            [
                Val::from_u32(t.e),
                Val::from_u64(t.g),
                Val::from_u64(t.g_o),
                Val::from_u64(t.delta),
                Val::from_u64(t.delta_o),
                Val::from_u64(t.t),
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
    let mut out = Vec::with_capacity(sigma.len() * 3);
    for &s in sigma {
        out.push(3 * s);
        out.push(3 * s + 1);
        out.push(3 * s + 2);
    }
    out
}

/// Read tuple `r`'s six fields `[e, g₁, g₂, Δ₁, Δ₂, t]` from the reconstructed,
/// BabyBear-shaped table (`f[2r]` = lo coeffs `[e,g₁,g₂,Δ₁]`, `f[2r+1]` = hi
/// coeffs `[Δ₂,t,0,0]`). Unchanged from the BabyBear circuit — `unpack_gk_table`
/// rebuilds `f` in exactly that shape from the Goldilocks 2-cell packing.
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

/// Unpack a flat table of Goldilocks cells (3 per tuple) into the exact
/// BabyBear-shaped decomposed table the Stage 3–8 body indexes: for tuple `r`,
/// `f[2r] = [e, g₁, g₂, Δ₁]` and `f[2r+1] = [Δ₂, t, 0, 0]`. Each field is a RAW
/// base coord of one of the three cells (`cell0=[e,g₁]`, `cell1=[g₂,Δ₁]`,
/// `cell2=[Δ₂,t]`) — no `decompose_to_bits`, no reconstruction. The two trailing
/// `0`s of `f[2r+1]` are the shared `zero` const, so the body's `connect(f[..][2/3],
/// zero)` pad checks are trivial no-ops (the cells have no spare coord to abuse).
fn unpack_gk_table(b: &mut CircuitBuilder<Challenge>, cells: &[ExprId], zero: ExprId) -> Vec<Vec<ExprId>> {
    let n = cells.len() / 3;
    let mut f = Vec::with_capacity(2 * n);
    for r in 0..n {
        let c0 = b
            .decompose_ext_to_base_coeffs::<Val>(cells[3 * r])
            .expect("dec gk cell0"); // [e, g₁]
        let c1 = b
            .decompose_ext_to_base_coeffs::<Val>(cells[3 * r + 1])
            .expect("dec gk cell1"); // [g₂, Δ₁]
        let c2 = b
            .decompose_ext_to_base_coeffs::<Val>(cells[3 * r + 2])
            .expect("dec gk cell2"); // [Δ₂, t]
        f.push(vec![c0[0], c0[1], c1[0], c1[1]]); // [e, g₁, g₂, Δ₁]
        f.push(vec![c2[0], c2[1], zero, zero]); // [Δ₂, t, 0, 0]
    }
    f
}

#[cfg(test)]
thread_local! {
    /// Test-only tamper: override the public `N_prev` fed to the circuit while
    /// keeping the honest witness, to PoC-verify audit fix #3. Thread-local, so
    /// it is isolated per test thread (parallel-safe).
    static TAMPER_NPREV: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
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
/// Two residual assumptions remain, **shared with the one-sided `prove_gkb`** and
/// standard for these leaves: (i) the threshold `θ` is a public input assumed to
/// equal `⌊N_t/s⌋` (cross-checked by the streaming-forest log, not in-circuit);
/// (ii) the Stage-8 mass sum `Σ(g₁+g₂)` is a field add that could wrap `p` only
/// for a *crafted* init with `Θ(cap)` maximal `g` values — unreachable in the
/// chained forest, whose init is the prior canonical state (mass conserved from
/// an empty epoch 1).
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
}

/// Build the reusable GK band-merge leaf circuit for a shape.
pub fn build_gkb2_leaf(params: GkbParams, expose_boundary: bool) -> Gkb2LeafCircuit {
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    assert_eq!(total % 2, 0, "total = cap+m must be even");
    let lf = num_rounds(total);
    let num_pairs = total / 2;

    // ── Circuit ──
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        make_perm(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    if expose_boundary {
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

    // Private inputs — 3 challenges per tuple. Alloc order == packing order.
    let init_packed: Vec<ExprId> = (0..3 * cap)
        .map(|_| b.alloc_private_input("init"))
        .collect();
    let final_packed: Vec<ExprId> = (0..3 * cap)
        .map(|_| b.alloc_private_input("final"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..3 * m).map(|_| b.alloc_private_input("batch")).collect();
    let union_raw_packed: Vec<ExprId> = (0..3 * total)
        .map(|_| b.alloc_private_input("union_raw"))
        .collect();
    let fused_packed: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..3 * total)
                .map(|_| b.alloc_private_input("fused"))
                .collect()
        })
        .collect();
    let resorted_packed: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| {
            (0..3 * total)
                .map(|_| b.alloc_private_input("resorted"))
                .collect()
        })
        .collect();
    let excess_packed: Vec<ExprId> = (0..3 * m)
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

    // ── Stage 2: decompose (Goldilocks: unpack 2-cell packing → BabyBear shape) ──
    let _init_f: Vec<Vec<ExprId>> = unpack_gk_table(&mut b, &init_packed, zero);
    let final_f: Vec<Vec<ExprId>> = unpack_gk_table(&mut b, &final_packed, zero);
    let batch_f: Vec<Vec<ExprId>> = unpack_gk_table(&mut b, &batch_packed, zero);
    let uraw_f: Vec<Vec<ExprId>> = unpack_gk_table(&mut b, &union_raw_packed, zero);
    let resort_f: Vec<Vec<Vec<ExprId>>> = resorted_packed
        .iter()
        .map(|round| unpack_gk_table(&mut b, round, zero))
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
    // Placeholder identity permutations — `prove_epoch` swaps in the real
    // per-batch sigmas via `update_permute_witnesses` before each run.
    let union_perm = b
        .add_permute(&combined, (0..combined.len()).collect::<Vec<_>>())
        .expect("permute union");
    for i in 0..3 * total {
        b.connect(union_perm[i], union_raw_packed[i]);
    }

    // ── Stage 4: union_raw range-checks + value sortedness + padding ──
    for r in 0..total {
        let f = fld6(&uraw_f, r);
        let _ = b.add_range_bits::<Val>(f[0], E_BITS).expect("e range");
        let _ = b.add_range_bits::<Val>(f[1], MASS_BITS).expect("g₁ range");
        let _ = b.add_range_bits::<Val>(f[2], MASS_BITS).expect("g₂ range");
        let _ = b.add_range_bits::<Val>(f[3], MASS_BITS).expect("Δ₁ range");
        let _ = b.add_range_bits::<Val>(f[4], MASS_BITS).expect("Δ₂ range");
        let _ = b.add_range_bits::<Val>(f[5], MASS_BITS).expect("t range");
        b.connect(uraw_f[2 * r + 1][2], zero);
        b.connect(uraw_f[2 * r + 1][3], zero);
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
        let o_part = b.mul(omf, uraw_f[2 * r][3]);
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
        let fused_f: Vec<Vec<ExprId>> = unpack_gk_table(&mut b, &fused_packed[round], zero);
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
            b.connect(fused_f[2 * p_lo][0], lo_e);
            b.connect(fused_f[2 * p_lo][1], lo_g1);
            b.connect(fused_f[2 * p_lo][2], lo_g2);
            b.connect(fused_f[2 * p_lo][3], lo_d1);
            b.connect(fused_f[2 * p_lo + 1][0], lo_d2);
            b.connect(fused_f[2 * p_lo + 1][1], lo_t);
            b.connect(fused_f[2 * p_lo + 1][2], zero);
            b.connect(fused_f[2 * p_lo + 1][3], zero);
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
            b.connect(fused_f[2 * p_hi][0], hi_e);
            b.connect(fused_f[2 * p_hi][1], hi_g1);
            b.connect(fused_f[2 * p_hi][2], hi_g2);
            b.connect(fused_f[2 * p_hi][3], hi_d1);
            b.connect(fused_f[2 * p_hi + 1][0], hi_d2);
            b.connect(fused_f[2 * p_hi + 1][1], hi_t);
            b.connect(fused_f[2 * p_hi + 1][2], zero);
            b.connect(fused_f[2 * p_hi + 1][3], zero);
        }
        // resort
        let perm = b
            .add_permute(
                &fused_packed[round],
                (0..fused_packed[round].len()).collect::<Vec<_>>(),
            )
            .expect("permute resort");
        for i in 0..3 * total {
            b.connect(perm[i], resorted_packed[round][i]);
        }
        for r in 0..total {
            let f = fld6(&resort_f[round], r);
            let _ = b.add_range_bits::<Val>(f[0], E_BITS).expect("rs e");
            let _ = b.add_range_bits::<Val>(f[1], MASS_BITS).expect("rs g₁");
            let _ = b.add_range_bits::<Val>(f[2], MASS_BITS).expect("rs g₂");
            let _ = b.add_range_bits::<Val>(f[3], MASS_BITS).expect("rs Δ₁");
            let _ = b.add_range_bits::<Val>(f[4], MASS_BITS).expect("rs Δ₂");
            let _ = b.add_range_bits::<Val>(f[5], MASS_BITS).expect("rs t");
            b.connect(resort_f[round][2 * r + 1][2], zero);
            b.connect(resort_f[round][2 * r + 1][3], zero);
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
        cur_f = (0..total).map(|r| fld6(&resort_f[round], r)).collect();
    }

    // ── Stage 7: compaction — final = cur[..cap], excess = cur[cap..] ──
    let excess_f: Vec<Vec<ExprId>> = unpack_gk_table(&mut b, &excess_packed, zero);
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

    let circuit = b.build().expect("build gkb2 circuit");

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
        permute_preprocessor::<Val>(),
        range_preprocessor::<Val>(),
    ];
    let mut air_builders = poseidon2_air_builders_d2::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 2>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 2>(1));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 2>(1));
    if expose_boundary {
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
        .expect("airs_and_degrees");
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
    if expose_boundary {
        prover.register_expose_table::<2>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();

    Gkb2LeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
    }
}

impl Gkb2LeafCircuit {
    /// Prove one epoch on the prebuilt circuit.
    pub fn prove_epoch(&mut self, initial_state: Gk2State, batch_vals: Vec<u32>) -> Gk2LeafProof {
        let params = self.params;
        assert!(batch_vals.len() <= params.batch);
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        assert_eq!(total % 2, 0, "total = cap+m must be even");

        // ── Native replay + commitments ──
        let build = build_bm2(&initial_state, &batch_vals);
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
        sigmas.push(expand_sigma(&build.sigma_union));
        for round in 0..lf {
            sigmas.push(expand_sigma(&build.rounds[round].sigma));
        }
        self.circuit
            .update_permute_witnesses(&sigmas)
            .expect("update permute witnesses (gkb2)");

        // ── Pack public + private ──
        let initial_commit_packed = pack_commit_to_challenge(&GlCommit(initial_commit.0));
        let final_commit_packed = pack_commit_to_challenge(&GlCommit(final_commit.0));
        let batch_commit_packed = pack_commit_to_challenge(&GlCommit(batch_commit.0));
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

        let mut private_inputs: Vec<Challenge> = Vec::new();
        private_inputs.extend_from_slice(&pack_tuples2(&initial_state.tuples));
        private_inputs.extend_from_slice(&pack_tuples2(&final_state.tuples));
        private_inputs.extend_from_slice(&pack_tuples2(&fresh_tuples2(
            &batch_vals,
            m,
            build.n_prev,
        )));
        private_inputs.extend_from_slice(&pack_tuples2(&build.union_raw));
        for round in &build.rounds {
            private_inputs.extend_from_slice(&pack_tuples2(&round.fused));
        }
        for round in &build.rounds {
            private_inputs.extend_from_slice(&pack_tuples2(&round.resorted));
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

    /// Gating check for the Goldilocks (D=2) GK band-merge leaf: prove one epoch
    /// end-to-end. `prove_epoch` runs the circuit (`runner.run()` — the point the
    /// `WitnessChecks` LogUp bus is enforced, exactly where the D=2 fork bugs bit
    /// SS) and then self-verifies (`verify_all_tables`). Mirrors the BabyBear
    /// `gk2_circuit_round_trip`. Passing confirms the 2-cell packing + `unpack_gk_table`
    /// keep the bus balanced under Goldilocks.
    #[test]
    fn gk2_gl_circuit_round_trip() {
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

    /// Two chained epochs over a persistent state — exercises `prove_epoch`'s
    /// witness-swap path (`update_permute_witnesses`) a second time and a
    /// non-empty initial state (real `init_packed`), the forest's per-leaf shape.
    #[test]
    fn gk2_gl_circuit_chained_epoch() {
        let params = GkbParams {
            capacity: 8,
            batch: 4,
            s: 2,
        };
        let b1 = vec![10u32, 20, 30, 40];
        let e1 = generate_proof2(params, b1);
        let s1 = e1.final_state.clone();
        let b2 = vec![15u32, 25, 35, 45];
        let s2 = apply_batch2(&s1, &b2);
        let p2 = prove_gkb2(params, s1.clone(), b2.clone());
        assert_eq!(
            commit_gk2_state(&s1).0,
            p2.initial.0,
            "epoch-2 initial commit must equal epoch-1 final state commit"
        );
        assert_eq!(
            commit_gk2_state(&s2).0,
            p2.final_.0,
            "epoch-2 final commit must match the native chained state"
        );
    }
}

