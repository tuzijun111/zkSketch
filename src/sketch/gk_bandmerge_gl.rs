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

use crate::commitment::hiding::{
    self, CommitFamily, CommitKind, CommitMode, OpeningsGl, SaltGl, commit_flat_gl,
};
use crate::config_gl::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl as ConfigWithFriParams;
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::recursion::recursive::leaf_gl::{
    DIGEST_PACKING, GlCommit, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::bind::{self, Binding};
use crate::sketch::gk_bandmerge::bind_theta;

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
// 2→3 per tuple.
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ CELL RE-PAIRING — FIXED (was: confirmed exploitable; see `atoms_of`).      │
// │                                                                           │
// │ `add_permute` proves a multiset equality over INDIVIDUAL cells, and σ is  │
// │ a prover-supplied witness. The old 3-cell RAW split kept each tuple        │
// │ together only under the HONEST σ: a malicious σ could re-pair             │
// │ `cell1=[g₂,Δ₁]` across tuples (only `cell0=[e,g₁]` was pinned by           │
// │ e-sortedness), swapping two active reps' right-masses `g₂` while every     │
// │ check still passed → verifying proof for a wrong state.                    │
// │                                                                           │
// │ FIX: the permutes no longer move raw cells. `atoms_of` derives 2 ATOMIC    │
// │ cells/tuple — `atom_lo=[e+g₁·2^24, g₂+Δ₁·2^24]` binds (e,g₁,g₂,Δ₁) into    │
// │ ONE challenge (BabyBear parity), `atom_hi=[Δ₂,t]` — and BOTH the union     │
// │ (Stage 3) and round-resort (Stage 6) permutes operate on those atoms       │
// │ (`expand_sigma` now 2/tuple). Packed fields are range-checked on both      │
// │ sides so the atoms are injective. The raw cells / commitment / body are    │
// │ unchanged. `atom_hi=[e+Δ₂·2^24, t]` ALSO carries `e`, so the hi cell is    │
// │ bound to the same tuple as `atom_lo` via the multiset — closing the        │
// │ (Δ₂,t) re-pairing surface too (STRICTLY stronger than BabyBear, whose hi   │
// │ cell is separable). Only equal-`e` tuples share an atom_hi coord0, and     │
// │ those are pinned by the (e,t) tiebreak.                                    │
// └─────────────────────────────────────────────────────────────────────────┘

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
    finish_bm2(s_old, sigma_union, union_raw, n_prev, n_t, theta)
}

/// Everything after the union permute (neighbor-init, the `L_f` fuse/resort
/// rounds, compaction), replayed from a given `union_raw` (honestly the
/// `(e,t)`-sorted union; a soundness test may hand in a forged one).
fn finish_bm2(
    s_old: &Gk2State,
    sigma_union: Vec<usize>,
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

/// [`commit_gk2_state`] under a [`CommitMode`] (revision B2,
/// [`crate::commitment::hiding`]): `Plain` is exactly [`commit_gk2_state`]
/// (the salt is ignored); `Hiding` is `MyHash([TAG_STATE, GreenwaldKhanna,
/// ρ_0..ρ_5] ‖ tuples)` over the same per-tuple `[e, g₁, g₂, Δ₁, Δ₂, t]`
/// stream ([`commit_flat_gl`]), the value a `Hiding` leaf exposes for
/// `Com(S_t; ρ)`.
pub fn commit_gk2_state_with(state: &Gk2State, mode: CommitMode, salt: &SaltGl) -> Gk2StateCommit {
    match mode {
        CommitMode::Plain => commit_gk2_state(state),
        CommitMode::Hiding => Gk2StateCommit(commit_flat_gl(
            mode,
            CommitKind::State,
            CommitFamily::GreenwaldKhanna,
            salt,
            &flat_tuples2(&state.tuples),
        )),
    }
}

/// [`commit_gk2_batch`] under a [`CommitMode`]: `Plain` is exactly
/// [`commit_gk2_batch`]; `Hiding` is `Com(B_t; ρ)` over the same fresh
/// singletons `(v, 0, 0, 0, 0, n_prev + 1 + j)` (padded with `E_MAX`
/// dummies to `m`).
pub fn commit_gk2_batch_with(
    vals: &[u32],
    m: usize,
    n_prev: u64,
    mode: CommitMode,
    salt: &SaltGl,
) -> Gk2BatchCommit {
    match mode {
        CommitMode::Plain => commit_gk2_batch(vals, m, n_prev),
        CommitMode::Hiding => Gk2BatchCommit(commit_flat_gl(
            mode,
            CommitKind::Batch,
            CommitFamily::GreenwaldKhanna,
            salt,
            &flat_tuples2(&fresh_tuples2(vals, m, n_prev)),
        )),
    }
}

/// Expand a tuple-permutation to the atom-cell permutation that moves each
/// tuple's TWO atomic cells (`atom_lo`, `atom_hi`) together.
fn expand_sigma(sigma: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(sigma.len() * 2);
    for &s in sigma {
        out.push(2 * s);
        out.push(2 * s + 1);
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

/// The TWO atomic permute cells for tuple `r` of an unpacked `f`-table. To
/// close the cell re-pairing hole (a malicious `add_permute` σ separating
/// `[g₂,Δ₁]`/`[Δ₂,t]` from their `[e,g₁]`), the re-pairable fields are packed
/// into single challenges permuted as atomic units:
///   `atom_lo = [e + g₁·2^24, g₂ + Δ₁·2^24]`   `atom_hi = [Δ₂, t]`
/// This is BabyBear parity: BabyBear's D=4 lo cell holds `(e,g₁,g₂,Δ₁)` atomic;
/// its hi cell `(Δ₂,t)` is separable in both variants. Every packed field is
/// range-checked `< 2^MASS_BITS`, so each coord `< 2^48 ≪ p` and the packing is
/// injective (unique split) — the multiset argument then binds `(e,g₁,g₂,Δ₁)`
/// together per tuple. Callers MUST range-check the packed fields on BOTH the
/// input and output sides of the permute (else an out-of-range field aliases).
fn atoms_of(
    b: &mut CircuitBuilder<Challenge>,
    f: &[Vec<ExprId>],
    r: usize,
    shift24: ExprId,
) -> [ExprId; 2] {
    let ff = fld6(f, r); // [e, g₁, g₂, Δ₁, Δ₂, t]
    let lo0 = b.mul_add(ff[1], shift24, ff[0]); // e + g₁·2^24
    let lo1 = b.mul_add(ff[3], shift24, ff[2]); // g₂ + Δ₁·2^24
    let atom_lo = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&[lo0, lo1])
        .expect("atom_lo");
    // `atom_hi` ALSO carries `e` (`e + Δ₂·2^24`): this binds (Δ₂,t) to the same
    // `e` as atom_lo through the multiset, so a malicious σ cannot re-pair the
    // hi cell to a different tuple (a swap to a different-`e` tuple has no
    // matching combined atom_hi). This closes the residual (Δ₂,t) surface —
    // gk_gl is thus STRICTLY stronger than BabyBear here, whose hi cell is
    // separable. Injective: e<2^22 in bits[0,22), Δ₂<2^24 in bits[24,48).
    let hi0 = b.mul_add(ff[4], shift24, ff[0]); // e + Δ₂·2^24
    let atom_hi = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&[hi0, ff[5]])
        .expect("atom_hi");
    [atom_lo, atom_hi]
}

// ── Source-bound atoms (shared-PermuteBus + equal-e re-pairing fix) ──────
//
// The fork concatenates every `add_permute` into ONE PermuteAir whose
// PermuteBus message is the 2 value coordinates only (no op id), so it proves
// only that the multiset of ALL permute-input atoms equals that of ALL outputs.
// With the `atoms_of` layout (`[e+g₁·2^24, g₂+Δ₁·2^24]`, `[e+Δ₂·2^24, t]`) a
// prover could (i) trade atoms between the union and the round permutes — a
// FRESH tuple leaves the union output (a dummy takes its slot), skips
// neighbor-init and every fuse round, and re-enters in the last round's resort
// output with `Δ₁ = Δ₂ = 0` (`tests::gk2_gl_shared_bus_forgery_rejected`,
// accepted before this fix) — and (ii) re-pair `atom_hi` between two
// equal-`e` tuples (it carries only `e` as a link). The permutes therefore use
// the source-bound layout of the BabyBear leaf, fitted to 64-bit coordinates:
//     atom_lo = [e + g₁·2^24, g₂ + B(k,0,i)·2^24]
//     atom_hi = [Δ₁ + Δ₂·2^24, t + B(k,1,i)·2^24]
// with `B(k,h,i) = i + (2k+h+1)·2^SRC_BITS` (`i` = input position of permute op
// `k`: 0 = union, `r+1` = round `r`'s resort). Inputs use the constant `B`;
// every output tuple carries a range-checked source witness `src < 2^SRC_BITS`
// in BOTH atoms. Every field is range-checked `< 2^24` on both sides (`B < 2^39`),
// so each coordinate splits uniquely and each output tuple is exactly one input
// tuple of the same op — no cross-op trading, no re-pairing.

/// Bits reserved for a tuple's source position in the source-bound layout.
const SRC_BITS: usize = 20;

/// Binding value of half `h` (0 = lo, 1 = hi) of the tuple at input position
/// `i` of permute op `k`.
fn bind_coord(k: usize, h: usize, i: usize) -> u64 {
    i as u64 + (((2 * k + h + 1) as u64) << SRC_BITS)
}

/// Whether [`build_gkb2_leaf`] uses the source-bound atoms. Always on outside
/// tests; the soundness PoC builds the pre-fix circuit.
fn use_pair_bind() -> bool {
    #[cfg(test)]
    if let Some(v) = PAIR_BIND.with(|c| c.get()) {
        return v;
    }
    true
}

/// The two source-bound atoms of tuple `r` of an unpacked `f`-table, given the
/// binding values `b_lo`/`b_hi` (constants on the input side, `src + base` on
/// the output side). Callers range-check every field `< 2^MASS_BITS`.
fn atoms_bound(
    b: &mut CircuitBuilder<Challenge>,
    f: &[Vec<ExprId>],
    r: usize,
    shift24: ExprId,
    b_lo: ExprId,
    b_hi: ExprId,
) -> [ExprId; 2] {
    let ff = fld6(f, r); // [e, g₁, g₂, Δ₁, Δ₂, t]
    let lo0 = b.mul_add(ff[1], shift24, ff[0]); // e + g₁·2^24
    let lo1 = b.mul_add(b_lo, shift24, ff[2]); // g₂ + B_lo·2^24
    let atom_lo = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&[lo0, lo1])
        .expect("bound atom_lo");
    let hi0 = b.mul_add(ff[4], shift24, ff[3]); // Δ₁ + Δ₂·2^24
    let hi1 = b.mul_add(b_hi, shift24, ff[5]); // t + B_hi·2^24
    let atom_hi = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&[hi0, hi1])
        .expect("bound atom_hi");
    [atom_lo, atom_hi]
}

/// Input-side binding values of position `i` of permute op `k` (constants).
fn bind_in(b: &mut CircuitBuilder<Challenge>, k: usize, i: usize) -> (ExprId, ExprId) {
    (
        b.alloc_const(Challenge::from_u64(bind_coord(k, 0, i)), "bind_lo"),
        b.alloc_const(Challenge::from_u64(bind_coord(k, 1, i)), "bind_hi"),
    )
}

/// Output-side binding values of permute op `k` from a source witness `src`
/// (range-checked `< 2^SRC_BITS`; both atoms name the same source).
fn bind_out(b: &mut CircuitBuilder<Challenge>, k: usize, src: ExprId) -> (ExprId, ExprId) {
    let _ = b
        .add_range_bits::<Val>(src, SRC_BITS)
        .expect("bind src range");
    let base_lo = b.alloc_const(Challenge::from_u64(bind_coord(k, 0, 0)), "bind_base_lo");
    let base_hi = b.alloc_const(Challenge::from_u64(bind_coord(k, 1, 0)), "bind_base_hi");
    (b.add(src, base_lo), b.add(src, base_hi))
}

/// Native value of a tuple's two permute atoms (source-bound when `bind` is
/// `Some((B_lo, B_hi))`, else the pre-fix `atoms_of` layout).
fn atoms_native(t: &Gk2Tuple, bind: Option<(u64, u64)>) -> [Challenge; 2] {
    use p3_field::BasedVectorSpace;
    let s24 = 1u64 << MASS_BITS;
    let mk = |a: u64, b: u64| {
        Challenge::from_basis_coefficients_slice(&[Val::from_u64(a), Val::from_u64(b)])
            .expect("2 coeffs")
    };
    let e = t.e as u64;
    match bind {
        None => [
            mk(e + t.g * s24, t.g_o + t.delta * s24),
            mk(e + t.delta_o * s24, t.t),
        ],
        Some((blo, bhi)) => [
            mk(e + t.g * s24, t.g_o + blo * s24),
            mk(t.delta + t.delta_o * s24, t.t + bhi * s24),
        ],
    }
}

/// Native atoms of an OUTPUT table of permute op `k` whose tuple `r` names
/// input position `src[r]` (what the circuit's output-side atoms evaluate to).
fn out_atoms_native(ts: &[Gk2Tuple], k: usize, src: &[usize], pair_bind: bool) -> Vec<Challenge> {
    ts.iter()
        .enumerate()
        .flat_map(|(r, t)| {
            atoms_native(
                t,
                pair_bind.then(|| (bind_coord(k, 0, src[r]), bind_coord(k, 1, src[r]))),
            )
        })
        .collect()
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
    /// Test-only override of [`use_pair_bind`] (`Some(false)` = pre-fix atoms).
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
/// **Threshold (revision B6(d)).** `θ` was a free public input "assumed to
/// equal `⌊N_t/s⌋`"; under the default binding the circuit now forces it from
/// the in-circuit `N_t` ([`bind_theta`]; `Binding::Legacy` keeps the pre-fix
/// circuit). One residual assumption remains, shared with the one-sided
/// `prove_gkb`: the Stage-8 mass sum `Σ(g₁+g₂)` is a field add, which cannot
/// wrap the 64-bit Goldilocks prime for any capacity here.
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
    /// Whether the permutes use the source-bound atoms ([`atoms_bound`]; the
    /// shared-PermuteBus + re-pairing fix). Always `true` outside tests.
    pair_bind: bool,
    params: GkbParams,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    /// The composition statement this leaf exposes.
    expose: Expose,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
    /// Commitment mode (revision B2).
    mode: CommitMode,
}

/// Build the reusable GK band-merge leaf circuit for a shape.
pub fn build_gkb2_leaf(params: GkbParams, expose_boundary: bool) -> Gkb2LeafCircuit {
    build_gkb2_leaf_expose(params, Expose::from_bool(expose_boundary))
}

/// Goldilocks GK band-merge leaf with an explicit composition statement
/// ([`Expose`]); `None` / `Boundary` are byte-for-byte [`build_gkb2_leaf`],
/// `Interval` adds the batch index `t` (last public input, after `n_t`) and
/// exposes `(init, final, (t, t), Poseidon2(TAG_LEAF, t, Com(B_t)))`.
/// Uses the process-default [`Binding`]; see [`build_gkb2_leaf_expose_with`].
pub fn build_gkb2_leaf_expose(params: GkbParams, expose: Expose) -> Gkb2LeafCircuit {
    build_gkb2_leaf_expose_with(params, expose, bind::default_binding())
}

/// [`build_gkb2_leaf_expose`] with an explicit [`Binding`]: `Semantic` /
/// `Bound` constrain `θ = ⌊N_t/s⌋` in-circuit ([`bind_theta`], revision
/// B6(d)); `Legacy` is the pre-fix free-`θ` circuit, byte-for-byte (unsound:
/// `tests::gk2_gl_inflated_theta_legacy_accepts_semantic_rejects`). `Bound`
/// equals `Semantic` here (no in-circuit coefficient re-binding). `θ`,
/// `N_{t-1}`, `N_t` stay unexposed: they are functions of the committed
/// boundary states (see the BabyBear
/// [`crate::sketch::gk_bandmerge::build_gkb2_leaf_expose_with`]).
///
/// Plain commitments ([`build_gkb2_leaf_commit`] with [`CommitMode::Plain`]);
/// prove with [`Gkb2LeafCircuit::prove_epoch_at`].
pub fn build_gkb2_leaf_expose_with(
    params: GkbParams,
    expose: Expose,
    binding: Binding,
) -> Gkb2LeafCircuit {
    build_gkb2_leaf_commit(params, expose, binding, CommitMode::Plain)
}

/// [`build_gkb2_leaf_expose_with`] with an explicit [`CommitMode`] (revision
/// B2, [`crate::commitment::hiding`]). `Plain` is the pre-B2 circuit byte for
/// byte (same VK). `Hiding` adds 9 private inputs, the salts of
/// `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)` (init, final, batch; three D = 2
/// Challenges each), allocated as the FIRST private inputs, and hashes each
/// commitment as `[tag, salt…, inputs…]` ([`commit_gk2_state_with`] /
/// [`commit_gk2_batch_with`]) through the same plain sponge as before
/// (`add_hash_slice`; `binding` only gates the `θ` constraint here). `θ`,
/// `N_{t-1}` and `N_t` stay unsalted, unexposed public inputs. The salts are
/// witnesses, so the VK does not depend on them; prove with
/// [`Gkb2LeafCircuit::prove_epoch_commit`].
pub fn build_gkb2_leaf_commit(
    params: GkbParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
) -> Gkb2LeafCircuit {
    let expose_boundary = expose == Expose::Boundary;
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    assert_eq!(total % 2, 0, "total = cap+m must be even");
    let lf = num_rounds(total);
    let num_pairs = total / 2;
    let pair_bind = use_pair_bind();
    assert!(total <= 1 << SRC_BITS, "source-bound atoms support cap+m ≤ 2^{SRC_BITS}");

    // ── Circuit ──
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
    // Shift for the atomic-permute packing (`atoms_of`): every packed field is
    // range-checked `< 2^MASS_BITS`, so `e + g₁·2^24 < 2^48 ≪ p` splits uniquely.
    let shift24 = b.alloc_const(Challenge::from_u64(1u64 << MASS_BITS), "shift24");
    let e_max = b.alloc_const(Challenge::from_u64(E_MAX as u64), "e_max");

    // Private inputs — 3 challenges per tuple. Alloc order == packing order.
    // B2: the salts of (init, final, batch) come FIRST under `Hiding` (9
    // inputs, [`OpeningsGl::private_inputs`] order); `Plain` allocates
    // nothing, so its circuit is byte-identical.
    // `alloc_leaf_salts_first` panics if any private input precedes them.
    let salts = crate::recursion::recursive::leaf_gl::alloc_leaf_salts_first(&mut b, mode);
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
    // Source witnesses of the source-bound atoms: the input position each
    // permute-OUTPUT tuple came from (union, then each round's resort).
    let src_union: Vec<ExprId> = if pair_bind {
        (0..total).map(|_| b.alloc_private_input("src_union")).collect()
    } else {
        Vec::new()
    };
    let src_round: Vec<Vec<ExprId>> = if pair_bind {
        (0..lf)
            .map(|_| (0..total).map(|_| b.alloc_private_input("src_round")).collect())
            .collect()
    } else {
        Vec::new()
    };

    // ── Stage 1: commit bindings ──
    // Salted under `Hiding` (`[tag, salt…, inputs…]`); with no salt,
    // `commit_hash(.., Binding::Semantic)` is exactly the pre-B2
    // `add_hash_slice(cfg, inputs, true)`.
    let commit_cfg = Poseidon2Config::GOLDILOCKS_D2_W8;
    let fam = CommitFamily::GreenwaldKhanna;
    let sponge = Binding::Semantic;
    let h_init = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &commit_cfg,
        CommitKind::State,
        fam,
        salts.as_ref().map(|s| &s.init),
        &init_packed,
        zero,
        sponge,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &commit_cfg,
        CommitKind::State,
        fam,
        salts.as_ref().map(|s| &s.final_),
        &final_packed,
        zero,
        sponge,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(h_final[i], final_pis[i]);
    }
    let h_batch = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &commit_cfg,
        CommitKind::Batch,
        fam,
        salts.as_ref().map(|s| &s.batch),
        &batch_packed,
        zero,
        sponge,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(h_batch[i], batch_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (10th public input, after
    // n_t) and H = Poseidon2(TAG_LEAF, t, h_batch), exposed with the boundary.
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

    // ── Stage 2: decompose (Goldilocks: unpack 2-cell packing → BabyBear shape) ──
    let init_f: Vec<Vec<ExprId>> = unpack_gk_table(&mut b, &init_packed, zero);
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
    // Atomic-cell union permute (closes the cell re-pairing hole). Permuting the
    // 3 raw cells lets a malicious σ re-pair `[g₂,Δ₁]`/`[Δ₂,t]` across tuples (the
    // confirmed exploit swaps two active reps' `[g₂,Δ₁]` → wrong right-masses).
    // Instead permute 2 DERIVED atoms/tuple (`atoms_of`), binding (e,g₁,g₂,Δ₁)
    // into one challenge. Range-check the packed fields on the INPUT side too so
    // the atoms are injective (`uraw_f` is range-checked in Stage 4 below).
    for r in 0..cap {
        let f = fld6(&init_f, r);
        let _ = b.add_range_bits::<Val>(f[0], E_BITS).expect("init e range");
        let _ = b.add_range_bits::<Val>(f[1], MASS_BITS).expect("init g₁ range");
        let _ = b.add_range_bits::<Val>(f[2], MASS_BITS).expect("init g₂ range");
        let _ = b.add_range_bits::<Val>(f[3], MASS_BITS).expect("init Δ₁ range");
    }
    for j in 0..m {
        // batch g₁=g₂=Δ₁=0 (Stage 3 well-formedness above); only e needs bounding.
        let _ = b
            .add_range_bits::<Val>(batch_f[2 * j][0], E_BITS)
            .expect("batch e range");
    }
    if pair_bind {
        // The source-bound atoms also pack Δ₂ and t: bound them on the input
        // side too (batch Δ₂ is pinned to 0 above).
        for r in 0..cap {
            let f = fld6(&init_f, r);
            let _ = b.add_range_bits::<Val>(f[4], MASS_BITS).expect("init Δ₂ range");
            let _ = b.add_range_bits::<Val>(f[5], MASS_BITS).expect("init t range");
        }
        for j in 0..m {
            let _ = b
                .add_range_bits::<Val>(batch_f[2 * j + 1][1], MASS_BITS)
                .expect("batch t range");
        }
    }
    let mut combined_atoms: Vec<ExprId> = Vec::with_capacity(2 * total);
    for r in 0..cap {
        let a = if pair_bind {
            let (bl, bh) = bind_in(&mut b, 0, r);
            atoms_bound(&mut b, &init_f, r, shift24, bl, bh)
        } else {
            atoms_of(&mut b, &init_f, r, shift24)
        };
        combined_atoms.push(a[0]);
        combined_atoms.push(a[1]);
    }
    for j in 0..m {
        let a = if pair_bind {
            let (bl, bh) = bind_in(&mut b, 0, cap + j);
            atoms_bound(&mut b, &batch_f, j, shift24, bl, bh)
        } else {
            atoms_of(&mut b, &batch_f, j, shift24)
        };
        combined_atoms.push(a[0]);
        combined_atoms.push(a[1]);
    }
    let mut union_atoms: Vec<ExprId> = Vec::with_capacity(2 * total);
    for r in 0..total {
        let a = if pair_bind {
            let (bl, bh) = bind_out(&mut b, 0, src_union[r]);
            atoms_bound(&mut b, &uraw_f, r, shift24, bl, bh)
        } else {
            atoms_of(&mut b, &uraw_f, r, shift24)
        };
        union_atoms.push(a[0]);
        union_atoms.push(a[1]);
    }
    // Placeholder identity permutation — `prove_epoch` swaps in the real
    // per-batch σ (2 atoms/tuple via `expand_sigma`) before each run.
    let union_perm = b
        .add_permute(&combined_atoms, (0..2 * total).collect::<Vec<_>>())
        .expect("permute union");
    for i in 0..2 * total {
        b.connect(union_perm[i], union_atoms[i]);
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
        // resort — atomic-cell permute (same fix as the union permute).
        // Range-check the packed INPUT fields so the derived atoms are injective
        // (resort_f is range-checked just below).
        for r in 0..total {
            let f = fld6(&fused_f, r);
            let _ = b.add_range_bits::<Val>(f[0], E_BITS).expect("fused e range");
            let _ = b.add_range_bits::<Val>(f[1], MASS_BITS).expect("fused g₁ range");
            let _ = b.add_range_bits::<Val>(f[2], MASS_BITS).expect("fused g₂ range");
            let _ = b.add_range_bits::<Val>(f[3], MASS_BITS).expect("fused Δ₁ range");
            // The source-bound atoms also pack Δ₂ and t. From round 1 on both
            // are (forced boolean)·(a range-checked resorted field), and t is
            // too in round 0; only round 0's Δ₂ (the neighbor-init sum) needs
            // its own bound.
            if pair_bind && round == 0 {
                let _ = b.add_range_bits::<Val>(f[4], MASS_BITS).expect("fused Δ₂ range");
            }
        }
        let mut fused_atoms: Vec<ExprId> = Vec::with_capacity(2 * total);
        for r in 0..total {
            let a = if pair_bind {
                let (bl, bh) = bind_in(&mut b, round + 1, r);
                atoms_bound(&mut b, &fused_f, r, shift24, bl, bh)
            } else {
                atoms_of(&mut b, &fused_f, r, shift24)
            };
            fused_atoms.push(a[0]);
            fused_atoms.push(a[1]);
        }
        let mut resort_atoms: Vec<ExprId> = Vec::with_capacity(2 * total);
        for r in 0..total {
            let a = if pair_bind {
                let (bl, bh) = bind_out(&mut b, round + 1, src_round[round][r]);
                atoms_bound(&mut b, &resort_f[round], r, shift24, bl, bh)
            } else {
                atoms_of(&mut b, &resort_f[round], r, shift24)
            };
            resort_atoms.push(a[0]);
            resort_atoms.push(a[1]);
        }
        let perm = b
            .add_permute(&fused_atoms, (0..2 * total).collect::<Vec<_>>())
            .expect("permute resort");
        for i in 0..2 * total {
            b.connect(perm[i], resort_atoms[i]);
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
    if expose.exposes() {
        prover.register_expose_table::<2>();
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
        mode,
    }
}

impl Gkb2LeafCircuit {
    /// Prove one epoch on the prebuilt circuit (batch index 1 under the
    /// Interval statement; see [`Self::prove_epoch_at`]).
    pub fn prove_epoch(&mut self, initial_state: Gk2State, batch_vals: Vec<u32>) -> Gk2LeafProof {
        self.prove_epoch_at(1, initial_state, batch_vals)
    }

    /// The statement this leaf exposes ([`Expose`]).
    pub fn expose(&self) -> Expose {
        self.expose
    }

    /// The commitment mode the circuit was built with (revision B2).
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }

    /// The VK (preprocessed commitment, `expose_forest_gl::vk_pin_values`
    /// order) of every proof this prebuilt leaf produces, read from its
    /// prover data (public parameters alone, no proving).
    pub fn vk_pin_values(&self) -> Vec<Challenge> {
        crate::recursion::recursive::expose_forest_gl::common_vk_pin_values(
            self.circuit_prover_data.common_data(),
        )
    }

    /// Prove the epoch of batch `t` (1-based); `t` is part of the Interval
    /// statement (ignored by the other layouts). `Plain` circuits only: on a
    /// `Hiding` circuit this would open every commitment with the public
    /// zero salt, so it panics; use [`Self::prove_epoch_commit`] (or, for
    /// the no-op leaf, [`Self::prove_epoch_public_zero`]).
    pub fn prove_epoch_at(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
    ) -> Gk2LeafProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             OpeningsGl::for_leaf(..)"
        );
        self.prove_epoch_opened(t, initial_state, batch_vals, &OpeningsGl::plain())
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`OpeningsGl::for_leaf(seed, CommitFamily::GreenwaldKhanna, t)` for an
    /// honest prover, `OpeningsGl::for_leaf_after` for leaf 1 of a history
    /// continued after a rotation; ignored by a `Plain` circuit). The proof's
    /// `initial`, `final_` and `batch_commit` are then `Com(S_{t-1};
    /// ρ^S_{t-1})`, `Com(S_t; ρ^S_t)` and `Com(B_t; ρ^B_t)`. A `Hiding`
    /// circuit panics when `openings.final_` or `openings.batch` is the
    /// public zero salt (never an honest PRF output). The init salt may be
    /// zero (leaf 1 opens the public `Com(S_0; 0)`).
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        openings: &OpeningsGl,
    ) -> Gk2LeafProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (OpeningsGl::for_leaf), not the public zero salt"
            );
        }
        self.prove_epoch_opened(t, initial_state, batch_vals, openings)
    }

    /// The no-op VK-derivation leaf's epoch: all three commitments opened
    /// with [`OpeningsGl::public_zero`], so a batch that changes nothing
    /// exposes `init == final` in either mode. The only path that proves a
    /// `Hiding` leaf with zero final/batch salts; it asserts that the batch
    /// is empty (the stream harness's GK no-op: `n` does not move) and that
    /// the state does not move, so it cannot publish a real batch under
    /// deterministic commitments.
    pub fn prove_epoch_public_zero(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
    ) -> Gk2LeafProof {
        assert!(
            batch_vals.is_empty() && apply_batch2(&initial_state, &batch_vals) == initial_state,
            "prove_epoch_public_zero is for the no-op leaf: the batch must be empty and the state \
             must not move"
        );
        self.prove_epoch_opened(t, initial_state, batch_vals, &OpeningsGl::public_zero())
    }

    /// Shared body of the three `prove_epoch_*` entry points (no opening
    /// checks).
    fn prove_epoch_opened(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        openings: &OpeningsGl,
    ) -> Gk2LeafProof {
        let build = self.install_epoch(t, &initial_state, &batch_vals);
        self.prove_build_opened(initial_state, batch_vals, &build, openings)
    }

    /// Run (no proof) the epoch [`Self::prove_epoch_commit`] would prove:
    /// its traces (the row-overhead tests).
    #[cfg(test)]
    fn run_epoch_commit(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        openings: &OpeningsGl,
    ) -> p3_circuit::tables::Traces<Challenge> {
        let build = self.install_epoch(t, &initial_state, &batch_vals);
        self.run_build_opened(initial_state, batch_vals, &build, openings).0
    }

    /// The honest band-merge build of the epoch of batch `t`, with its
    /// permutation hints installed in the prebuilt graph and `t` recorded for
    /// the Interval statement.
    fn install_epoch(&mut self, t: u64, initial_state: &Gk2State, batch_vals: &[u32]) -> Bm2Build {
        self.batch_index = t;
        let params = self.params;
        assert!(batch_vals.len() <= params.batch);
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        assert_eq!(total % 2, 0, "total = cap+m must be even");

        // ── Native replay + commitments ──
        let build = build_bm2(initial_state, batch_vals);
        let lf = num_rounds(total);
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
        build
    }

    /// Pack a (honest or hand-crafted) band-merge witness, run, prove and
    /// self-verify, with Plain openings (the soundness tests' hand-crafted
    /// builds). The Permute ops' hints must already be installed. The source
    /// witnesses are the build's permutations (`sigma_union`, each round's
    /// `sigma`).
    #[cfg(test)]
    fn prove_build(
        &mut self,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        build: &Bm2Build,
    ) -> Gk2LeafProof {
        self.prove_build_opened(initial_state, batch_vals, build, &OpeningsGl::plain())
    }

    /// [`Self::prove_build`] with explicit commitment openings (ignored
    /// under `Plain`).
    fn prove_build_opened(
        &mut self,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        build: &Bm2Build,
        openings: &OpeningsGl,
    ) -> Gk2LeafProof {
        let params = self.params;
        let (traces, initial_commit, final_commit, batch_commit, __witness) =
            self.run_build_opened(initial_state, batch_vals, build, openings);

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

    /// Pack a band-merge witness and run the circuit (no proof): the traces,
    /// the three commitments and the trace-generation time. The Permute ops'
    /// hints must already be installed.
    fn run_build_opened(
        &mut self,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        build: &Bm2Build,
        openings: &OpeningsGl,
    ) -> (
        p3_circuit::tables::Traces<Challenge>,
        Gk2StateCommit,
        Gk2StateCommit,
        Gk2BatchCommit,
        std::time::Duration,
    ) {
        let params = self.params;
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        let final_state = Gk2State {
            tuples: build.final_tuples.clone(),
            params,
            n: build.n_t,
        };
        let mode = self.mode;
        let initial_commit = commit_gk2_state_with(&initial_state, mode, &openings.init);
        let final_commit = commit_gk2_state_with(&final_state, mode, &openings.final_);
        let batch_commit = commit_gk2_batch_with(&batch_vals, m, build.n_prev, mode, &openings.batch);
        let lf = num_rounds(total);
        let num_pairs = total / 2;

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
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            // The salts come first (see `build_gkb2_leaf_commit`).
            private_inputs.extend(openings.private_inputs());
        }
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
        // Source witnesses (source-bound atoms): union, then each round.
        if self.pair_bind {
            for &i in &build.sigma_union {
                private_inputs.push(Challenge::from_u64(i as u64));
            }
            for round in 0..lf {
                for &i in &build.rounds[round].sigma {
                    private_inputs.push(Challenge::from_u64(i as u64));
                }
            }
        }

        // ── Run ──
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
        (traces, initial_commit, final_commit, batch_commit, __witness)
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

/// Public **no-op leaf** of the Goldilocks GK band-merge leaf for root-VK
/// derivation (the Goldilocks counterpart of
/// `noop_leaf::gk2_noop_leaf_expose`): the empty state and an empty batch
/// (the prover pads the fresh-tuple rows with `E_MAX` dummies; `n` does not
/// move; the stream harness's GK no-op), proved at batch index 1 through the
/// explicit zero-salt path ([`Gkb2LeafCircuit::prove_epoch_public_zero`],
/// all three salts [`OpeningsGl::public_zero`]), so it exposes
/// `init == final` in either mode. The salts and the index are witnesses,
/// so its VK is that of every real leaf of the same parameters and mode.
pub fn gk2_gl_noop_leaf_commit(
    params: GkbParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
) -> p3_circuit_prover::BatchStarkProof<ConfigWithFriParams> {
    build_gkb2_leaf_commit(params, expose, binding, mode)
        .prove_epoch_public_zero(1, Gk2State::empty(params), Vec::new())
        .output
        .0
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

    /// (B2 violations, εN rank-interval violations) of a state vs the stream.
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

    /// Malicious witness on the SHARED PermuteBus: the fresh union tuple at
    /// `x_pos` leaves the union permute's output (a dummy takes its slot),
    /// neighbor-init and every fuse round replay honestly without it, and it
    /// re-enters in the LAST round's resort output in place of a dummy with its
    /// committed `Δ₁ = Δ₂ = 0`. Source labels: each output keeps the label of
    /// the row it replaces. `None` if the capacity would overflow.
    fn forge_skip_rounds2(s_old: &Gk2State, batch: &[u32], x_pos: usize) -> Option<Bm2Build> {
        let cap = s_old.params.capacity;
        let honest = build_bm2(s_old, batch);
        let mut ur = honest.union_raw.clone();
        let mut su = honest.sigma_union.clone();
        let x = ur.remove(x_pos);
        let xs = su.remove(x_pos);
        ur.push(Gk2Tuple::dummy());
        su.push(xs);
        let mut f = finish_bm2(s_old, su, ur, honest.n_prev, honest.n_t, honest.theta);
        let last = f.rounds.last_mut()?;
        let dpos = last.resorted.iter().position(|t| *t == Gk2Tuple::dummy())?;
        last.resorted.remove(dpos);
        let ds = last.sigma.remove(dpos);
        let ins = last
            .resorted
            .iter()
            .position(|t| (t.e, t.t) > (x.e, x.t))
            .unwrap_or(last.resorted.len());
        last.resorted.insert(ins, x);
        last.sigma.insert(ins, ds);
        f.final_tuples = last.resorted[..cap].to_vec();
        f.excess = last.resorted[cap..].to_vec();
        if f.excess.iter().any(|t| t.active == 1) {
            return None;
        }
        Some(f)
    }

    /// Run the malicious prover: the union op and the last round's op emit the
    /// forged tables (as atoms, in the circuit's layout).
    fn prove_forged2(
        params: GkbParams,
        s_old: &Gk2State,
        batch: &[u32],
        f: &Bm2Build,
    ) -> std::thread::Result<Gk2LeafProof> {
        let lf = f.rounds.len();
        let mut leaf = build_gkb2_leaf(params, false);
        let pb = leaf.pair_bind;
        let mut sigmas = vec![expand_sigma(&f.sigma_union)];
        for rd in &f.rounds {
            sigmas.push(expand_sigma(&rd.sigma));
        }
        leaf.circuit.update_permute_witnesses(&sigmas).expect("sigmas");
        let u = out_atoms_native(&f.union_raw, 0, &f.sigma_union, pb);
        let l = out_atoms_native(&f.rounds[lf - 1].resorted, lf, &f.rounds[lf - 1].sigma, pb);
        crate::sketch::forge_permute::forge_permute_outputs(&mut leaf.circuit, 0, u);
        crate::sketch::forge_permute::forge_permute_outputs(&mut leaf.circuit, lf, l);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            leaf.prove_build(s_old.clone(), batch.to_vec(), f)
        }))
    }

    /// **Shared-PermuteBus forgery on the Goldilocks two-sided leaf.** A fresh
    /// value is routed around the union output and every fuse round (its
    /// committed `Δ₁ = Δ₂ = 0` never gets the two-sided neighbor-init), so the
    /// certified final breaks the rank guarantee. Mass `Σ(g₁+g₂+1) = N_t`,
    /// sortedness and every fuse decision still hold.
    ///
    /// Pre-fix atoms (`atoms_of`, no op/source binding): ACCEPTED. Source-bound
    /// atoms: REJECTED (the re-entering tuple's atoms carry `B(L_f,·,·)` while
    /// its only input copy carries `B(0,·,·)` → PermuteBus mismatch).
    #[test]
    fn gk2_gl_shared_bus_forgery_rejected() {
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
        assert_eq!(semantic_damage(&honest_final, &stream), (0, 0));
        let _honest = prove_gkb2(params, s1.clone(), b2.clone());

        let mut pick: Option<(usize, Bm2Build, (usize, usize))> = None;
        for (pos, t) in honest.union_raw.iter().enumerate() {
            if t.active != 1 || t.t <= honest.n_prev {
                continue;
            }
            let Some(f) = forge_skip_rounds2(&s1, &b2, pos) else {
                continue;
            };
            let st = Gk2State {
                tuples: f.final_tuples.clone(),
                params,
                n: f.n_t,
            };
            let dmg = semantic_damage(&st, &stream);
            if pick.as_ref().is_none_or(|p| dmg.0 + dmg.1 > p.2.0 + p.2.1) {
                pick = Some((pos, f, dmg));
            }
        }
        let (pos, forged, dmg) = pick.expect("a fresh tuple to route around the rounds");
        println!(
            "[gk2_gl shared bus] fresh e={} skips the union + {} rounds; forged final: {} B2, \
             {} rank-interval violations (honest: 0, 0)",
            honest.union_raw[pos].e,
            forged.rounds.len(),
            dmg.0,
            dmg.1
        );
        assert!(dmg.0 + dmg.1 > 0, "the forged final must break the guarantee");

        PAIR_BIND.with(|c| c.set(Some(false)));
        let pre = prove_forged2(params, &s1, &b2, &forged);
        PAIR_BIND.with(|c| c.set(None));
        match &pre {
            Ok(_) => println!("[gk2_gl shared bus] pre-fix: forged final ACCEPTED (self-verified)"),
            Err(e) => println!("[gk2_gl shared bus] pre-fix: REJECTED: {}", panic_msg(e)),
        }
        assert!(pre.is_ok(), "PoC premise: the pre-fix atoms accept the forgery");
        let post = prove_forged2(params, &s1, &b2, &forged);
        match &post {
            Ok(_) => println!("[gk2_gl shared bus] fixed: forged final ACCEPTED"),
            Err(e) => println!("[gk2_gl shared bus] fixed: REJECTED: {}", panic_msg(e)),
        }
        assert!(post.is_err(), "source-bound atoms must stop the cross-op trade");
    }

    /// **Inflated-threshold PoC on the Goldilocks leaf (revision B6(d)).** The
    /// BabyBear `gk2_inflated_theta_legacy_accepts_semantic_rejects` attack:
    /// every fusion round is replayed under a claimed `θ' > ⌊N_t/s⌋`, so the
    /// certified final over-merges past the `εN` rank guarantee. `Legacy`
    /// (free `θ`): ACCEPTED, `Com(S')` certified. `Semantic`: honest control
    /// verifies, the over-merge is rejected.
    #[test]
    fn gk2_gl_inflated_theta_legacy_accepts_semantic_rejects() {
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s: 3,
        };
        let max_err = |st: &Gk2State, stream: &[u32]| -> u64 {
            let mut qs: Vec<u32> = stream.to_vec();
            qs.extend(stream.iter().map(|&x| x.saturating_sub(1)));
            qs.extend(stream.iter().map(|&x| x + 1));
            qs.iter()
                .map(|&q| {
                    let truth = stream.iter().filter(|&&x| x <= q).count() as u64;
                    st.rank(q).abs_diff(truth)
                })
                .max()
                .unwrap_or(0)
        };
        // Search two-batch streams / inflated θ' for an εN-breaking over-merge.
        let lcg = |seed: u64, n: usize| -> Vec<u32> {
            let mut x = seed | 1;
            (0..n)
                .map(|_| {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    ((x >> 33) as u32) % 1000
                })
                .collect()
        };
        let mut pick: Option<(u64, Gk2State, Vec<u32>, Bm2Build, Vec<u32>)> = None;
        for seed in 1..=24u64 {
            let b1 = lcg(seed, params.batch);
            let b2 = lcg(seed + 1000, params.batch);
            let s1 = apply_batch2(&Gk2State::empty(params), &b1);
            let honest = build_bm2(&s1, &b2);
            let stream: Vec<u32> = b1.iter().chain(b2.iter()).copied().collect();
            let eps_n = honest.n_t / params.s;
            for theta in honest.theta + 1..=honest.n_t {
                let f = finish_bm2(
                    &s1,
                    honest.sigma_union.clone(),
                    honest.union_raw.clone(),
                    honest.n_prev,
                    honest.n_t,
                    theta,
                );
                if f.final_tuples == honest.final_tuples || f.excess.iter().any(|t| t.active == 1) {
                    continue;
                }
                let st = Gk2State {
                    tuples: f.final_tuples.clone(),
                    params,
                    n: f.n_t,
                };
                let margin = max_err(&st, &stream).saturating_sub(eps_n);
                if margin > 0 && pick.as_ref().is_none_or(|p| margin > p.0) {
                    pick = Some((margin, s1.clone(), b2.clone(), f, stream.clone()));
                }
            }
        }
        let (margin, s1, b2, forged, stream) =
            pick.expect("an inflated θ whose over-merge breaks the εN guarantee");
        let honest = build_bm2(&s1, &b2);
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
        assert!(max_err(&honest_final, &stream) <= honest.n_t / params.s);
        println!(
            "[gk2_gl θ] N_t={} true θ={} claimed θ'={}: over-merged final errs by εN + {margin}; \
             B2 violations {:?}",
            honest.n_t,
            honest.theta,
            forged.theta,
            semantic_damage(&forged_final, &stream)
        );

        let prove = |binding: Binding, build: &Bm2Build| {
            let mut leaf = build_gkb2_leaf_expose_with(params, Expose::None, binding);
            let mut sigmas = vec![expand_sigma(&build.sigma_union)];
            for rd in &build.rounds {
                sigmas.push(expand_sigma(&rd.sigma));
            }
            leaf.circuit.update_permute_witnesses(&sigmas).expect("sigmas");
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                leaf.prove_build(s1.clone(), b2.clone(), build)
            }))
        };
        let pre = prove(Binding::Legacy, &forged);
        match &pre {
            Ok(p) => {
                assert_eq!(p.final_.0, commit_gk2_state(&forged_final).0, "certifies Com(S')");
                println!("[gk2_gl θ] Legacy (free θ): over-merged final ACCEPTED (self-verified)");
            }
            Err(e) => panic!("PoC premise: Legacy accepts the over-merge, got {}", panic_msg(e)),
        }
        assert!(prove(Binding::Semantic, &honest).is_ok(), "positive control: honest θ verifies");
        match prove(Binding::Semantic, &forged) {
            Ok(_) => panic!("Semantic must reject the inflated θ"),
            Err(e) => println!("[gk2_gl θ] Semantic: REJECTED: {}", panic_msg(&e)),
        }
    }

    /// Cost of the source-bound atoms (padded trace rows + one prove), pre-fix
    /// vs fixed. Run:
    /// `cargo test --release --lib gk_bandmerge_gl::tests::gk2_gl_fix_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn gk2_gl_fix_overhead() {
        for &(cap, m) in &[(64usize, 16usize), (256, 16), (1024, 16)] {
            let params = GkbParams {
                capacity: cap,
                batch: m,
                s: 8,
            };
            let vals: Vec<u32> = (0..m as u32).map(|i| (i * 7919 + 13) % (1 << 20)).collect();
            for (label, bind) in [("pre-fix", false), ("source-bound", true)] {
                PAIR_BIND.with(|c| c.set(Some(bind)));
                let mut leaf = build_gkb2_leaf(params, false);
                PAIR_BIND.with(|c| c.set(None));
                let t = std::time::Instant::now();
                let _ = leaf.prove_epoch(Gk2State::empty(params), vals.clone());
                println!(
                    "[gk2_gl fix_overhead] cap={cap} m={m} {label:<13} trace_rows={} prove+verify={:?}",
                    leaf.trace_rows,
                    t.elapsed()
                );
            }
        }
    }

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────

    use crate::commitment::hiding::{
        SaltSeed, rho_batch_gl, rho_batch_gl_in, rho_state_gl, rho_state_gl_in,
    };
    use crate::recursion::recursive::expose_forest_gl::{
        batch_log, check_leaves_against_log, check_root_against_log, prove_hiding_merge,
        read_exposed_boundary_proof, read_exposed_statement, root_vk_deriver,
        verify_bound_stark_proof_against_log, vk_pin_values,
    };
    use crate::recursion::recursive::leaf_gl::hiding_probe::{
        leaked_salts, proof_alu_rows, trace_rows, vk_flat, vk_literal,
    };
    use crate::recursion::recursive::root_vk::ForestShape;
    use crate::recursion::recursive::statement::{hash_gl, leaf_digest};
    use crate::sketch::forge;

    const HP: GkbParams = GkbParams { capacity: 8, batch: 4, s: 2 };
    const GK: CommitFamily = CommitFamily::GreenwaldKhanna;

    fn hiding_leaf(binding: Binding) -> Gkb2LeafCircuit {
        build_gkb2_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding)
    }

    fn hp_prior() -> Gk2State {
        apply_batch2(&Gk2State::empty(HP), &[10, 20, 30, 40])
    }

    fn hp_batches() -> Vec<Vec<u32>> {
        vec![vec![15, 25, 35, 45], vec![12, 22, 32, 42]]
    }

    /// Native drift guard: `Plain` is the pre-B2 commitment whatever the
    /// salt; `Hiding` is `MyHash([TAG_STATE | TAG_BATCH, GreenwaldKhanna, ρ…]
    /// ‖ flat)` over exactly the pre-B2 flat stream (the batch's fresh
    /// singletons still carry `n_prev`).
    #[test]
    fn commit_with_modes() {
        use crate::commitment::hiding::{TAG_BATCH, TAG_STATE};
        let seed = SaltSeed::for_tests(9);
        let (r1, r2) = (rho_state_gl(&seed, GK, 1), rho_state_gl(&seed, GK, 2));
        let s = hp_prior();
        assert_eq!(commit_gk2_state_with(&s, CommitMode::Plain, &r1), commit_gk2_state(&s));
        let mut input = vec![Val::from_u64(TAG_STATE), Val::from_u64(GK.id())];
        input.extend_from_slice(&r1.0);
        input.extend(flat_tuples2(&s.tuples));
        let want: [Val; 4] = MyHash::new(make_perm()).hash_iter(input);
        let h1 = commit_gk2_state_with(&s, CommitMode::Hiding, &r1);
        assert_eq!(h1.0, want, "state layout drift");
        assert_ne!(h1, commit_gk2_state_with(&s, CommitMode::Hiding, &r2));
        assert_ne!(h1, commit_gk2_state(&s));
        let rb = rho_batch_gl(&seed, GK, 1);
        let vals = hp_batches()[0].clone();
        assert_eq!(commit_gk2_batch_with(&vals, HP.batch, s.n, CommitMode::Plain, &rb), commit_gk2_batch(&vals, HP.batch, s.n));
        let mut input = vec![Val::from_u64(TAG_BATCH), Val::from_u64(GK.id())];
        input.extend_from_slice(&rb.0);
        input.extend(flat_tuples2(&fresh_tuples2(&vals, HP.batch, s.n)));
        let want: [Val; 4] = MyHash::new(make_perm()).hash_iter(input);
        let hb = commit_gk2_batch_with(&vals, HP.batch, s.n, CommitMode::Hiding, &rb);
        assert_eq!(hb.0, want, "batch layout drift");
        assert_ne!(hb, commit_gk2_batch(&vals, HP.batch, s.n));
        assert_ne!(hb, commit_gk2_batch_with(&vals, HP.batch, s.n + 1, CommitMode::Hiding, &rb), "n_prev is bound");
    }

    /// (1) A hiding leaf's commitments (the proof's `initial/final_/batch`
    /// fields and the exposed statement) equal the NATIVE hiding commitments
    /// under the leaf-`t` openings, under every binding (it gates the `θ`
    /// constraint) and under the Interval and Boundary layouts.
    #[test]
    fn hiding_leaf_exposes_native_hiding_commitments() {
        let seed = SaltSeed::for_tests(21);
        let t = 3u64;
        let vals = hp_batches()[0].clone();
        let prior = hp_prior();
        let expect = apply_batch2(&prior, &vals);
        let init = commit_gk2_state_with(&prior, CommitMode::Hiding, &rho_state_gl(&seed, GK, t - 1));
        let fin = commit_gk2_state_with(&expect, CommitMode::Hiding, &rho_state_gl(&seed, GK, t));
        let bc = commit_gk2_batch_with(&vals, HP.batch, prior.n, CommitMode::Hiding, &rho_batch_gl(&seed, GK, t));
        assert_ne!(init, commit_gk2_state(&prior), "hiding != plain");
        assert_ne!(fin, commit_gk2_state(&expect), "hiding != plain");
        assert_ne!(bc, commit_gk2_batch(&vals, HP.batch, prior.n), "hiding != plain");
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut leaf = hiding_leaf(binding);
            assert_eq!(leaf.commit_mode(), CommitMode::Hiding);
            let r = leaf.prove_epoch_commit(t, prior.clone(), vals.clone(), &OpeningsGl::for_leaf(&seed, GK, t));
            assert_eq!(r.initial, init, "{binding:?}");
            assert_eq!(r.final_, fin, "{binding:?}");
            assert_eq!(r.batch_commit, bc, "{binding:?}");
            let st = read_exposed_statement(&r.output.0);
            assert_eq!(st.init, init.0.to_vec(), "{binding:?}");
            assert_eq!(st.final_, fin.0.to_vec(), "{binding:?}");
            let iv = st.interval.expect("interval layout");
            assert_eq!((iv.lo, iv.hi), (Val::from_u64(t), Val::from_u64(t)));
            assert_eq!(iv.digest, leaf_digest(&hash_gl, 2, t, &bc.0), "{binding:?}: H(TAG_LEAF, t, Com(B_t; ρ))");
        }
        for binding in [Binding::Semantic, Binding::Legacy] {
            let mut bleaf = build_gkb2_leaf_commit(HP, Expose::Boundary, binding, CommitMode::Hiding);
            let r = bleaf.prove_epoch_commit(1, prior.clone(), vals.clone(), &OpeningsGl::for_leaf(&seed, GK, 1));
            let (i, f) = read_exposed_boundary_proof(&r.output.0);
            assert_eq!(i.0, commit_gk2_state_with(&prior, CommitMode::Hiding, &SaltGl::ZERO).0, "{binding:?}");
            assert_eq!(f.0, r.final_.0, "{binding:?}");
            assert_eq!(f.0, commit_gk2_state_with(&expect, CommitMode::Hiding, &rho_state_gl(&seed, GK, 1)).0);
        }
    }

    /// (2) The hiding leaf's VK does not depend on the salts (two different
    /// openings, and the zero-salt no-op leaf, give one VK), differs from the
    /// Plain VK, and the Plain circuit is the pre-B2 circuit: its VK equals
    /// the value recorded on the unmodified Goldilocks leaf (b2-hiding
    /// @94e9f58), through both the old builder and
    /// `build_gkb2_leaf_commit(.., Plain)`, for every layout and binding
    /// (`Bound` equals `Semantic` on this leaf).
    #[test]
    fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
        let recorded = [
            (Expose::None, Binding::Legacy, [17648301630814163799, 5056629490044759552, 18124287673730190577, 10229800710694710351]),
            (Expose::None, Binding::Semantic, [15783120118502133170, 15673227004874413497, 16436335801021612575, 16167864115155413287]),
            (Expose::None, Binding::Bound, [15783120118502133170, 15673227004874413497, 16436335801021612575, 16167864115155413287]),
            (Expose::Boundary, Binding::Legacy, [8877931017855245655, 13239424998823848014, 4664278231825416898, 9226611488382758017]),
            (Expose::Boundary, Binding::Semantic, [14695903512229121464, 7479378755966821786, 14574137524852503798, 16567183074626621323]),
            (Expose::Boundary, Binding::Bound, [14695903512229121464, 7479378755966821786, 14574137524852503798, 16567183074626621323]),
            (Expose::Interval, Binding::Legacy, [17969328576662778145, 15120082042092615866, 4816197231256429130, 10060820669137172799]),
            (Expose::Interval, Binding::Semantic, [1177917408512823668, 7183958709189815382, 5583135678615390458, 15052598159657248002]),
            (Expose::Interval, Binding::Bound, [1177917408512823668, 7183958709189815382, 5583135678615390458, 15052598159657248002]),
        ];
        for (expose, binding, vk) in recorded {
            let old = build_gkb2_leaf_expose_with(HP, expose, binding).vk_pin_values();
            let plain = build_gkb2_leaf_commit(HP, expose, binding, CommitMode::Plain).vk_pin_values();
            assert_eq!(vk_flat(&old), vk_literal(vk), "{expose:?}/{binding:?}: Plain VK drifted from the pre-B2 leaf");
            assert_eq!(plain, old, "{expose:?}/{binding:?}");
            let hid = build_gkb2_leaf_commit(HP, expose, binding, CommitMode::Hiding).vk_pin_values();
            assert_ne!(hid, old, "{expose:?}/{binding:?}: the hiding circuit differs");
        }
        for binding in [Binding::Semantic, Binding::Legacy] {
            let mut leaf = hiding_leaf(binding);
            let vk = leaf.vk_pin_values();
            let vals = hp_batches()[0].clone();
            let o1 = OpeningsGl::for_leaf(&SaltSeed::for_tests(1), GK, 1);
            let o5 = OpeningsGl::for_leaf(&SaltSeed::for_tests(2), GK, 5);
            let a = leaf.prove_epoch_commit(1, hp_prior(), vals.clone(), &o1);
            let b = leaf.prove_epoch_commit(5, hp_prior(), vals, &o5);
            assert_ne!(a.final_, b.final_);
            assert_eq!(vk_pin_values(&a.output.0), vk, "{binding:?}");
            assert_eq!(vk_pin_values(&b.output.0), vk, "{binding:?}");
            let noop = gk2_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
            assert_eq!(vk_pin_values(&noop), vk, "{binding:?}: the zero-salt no-op leaf has the real leaves' VK");
        }
    }

    /// (2b) The Hiding leaf's VK is pinned, one literal per statement layout and binding.
    /// It does not depend on the salts (test (2)), so it is a fixed value per
    /// shape; recorded on b2-gl @77a02a3. The pin guards what the other
    /// tests only compare against the native functions, which would carry the
    /// same change: which sponge each salted commitment uses, the
    /// `(kind, GreenwaldKhanna)` tag constants, and the salt allocation order.
    /// The salted sponges are Semantic under every binding, as the Plain
    /// ones are, so the `Bound` VK equals the `Semantic` one here too.
    #[test]
    fn hiding_leaf_vk_is_pinned() {
        let recorded = [
            (Expose::None, Binding::Legacy, [3029885619994448637, 17441158352762443225, 10853978290850170651, 14097643031452289306]),
            (Expose::None, Binding::Semantic, [2553289518217700547, 11811450157687497045, 7917681042355712433, 16431477266885413259]),
            (Expose::None, Binding::Bound, [2553289518217700547, 11811450157687497045, 7917681042355712433, 16431477266885413259]),
            (Expose::Boundary, Binding::Legacy, [4254308733864687361, 12525722226883359869, 5696773030907435527, 2424577922232817698]),
            (Expose::Boundary, Binding::Semantic, [1326411197357999998, 1628734671836764846, 10759183271107343309, 13359699208043678665]),
            (Expose::Boundary, Binding::Bound, [1326411197357999998, 1628734671836764846, 10759183271107343309, 13359699208043678665]),
            (Expose::Interval, Binding::Legacy, [9782628864113537765, 17236547483427436253, 1394173986358015459, 10953610386781663955]),
            (Expose::Interval, Binding::Semantic, [17948282801466964897, 16583181577784489926, 13993560794779333575, 3530354182268625117]),
            (Expose::Interval, Binding::Bound, [17948282801466964897, 16583181577784489926, 13993560794779333575, 3530354182268625117]),
        ];
        for (expose, binding, vk) in recorded {
            let hid = build_gkb2_leaf_commit(HP, expose, binding, CommitMode::Hiding).vk_pin_values();
            assert_eq!(vk_flat(&hid), vk_literal(vk), "{expose:?}/{binding:?}: Hiding VK drifted");
        }
    }

    /// (3) Equal states at two versions get different hiding commitments,
    /// both different from the plain one; at the proof level, two no-op
    /// (empty-batch) leaves at `t = 1, 2` over the empty summary expose
    /// `Com(S_0; 0) → Com(S_0; ρ_1) → Com(S_0; ρ_2)`: three distinct values
    /// for one state, chained.
    #[test]
    fn equal_states_get_unlinkable_hiding_commitments() {
        let seed = SaltSeed::for_tests(33);
        let s = hp_prior();
        let (r1, r2) = (rho_state_gl(&seed, GK, 1), rho_state_gl(&seed, GK, 2));
        let (c1, c2) = (
            commit_gk2_state_with(&s, CommitMode::Hiding, &r1),
            commit_gk2_state_with(&s, CommitMode::Hiding, &r2),
        );
        assert_ne!(c1, c2);
        assert_ne!(c1, commit_gk2_state(&s));
        assert_ne!(c2, commit_gk2_state(&s));
        assert_eq!(commit_gk2_state_with(&s, CommitMode::Plain, &r1), commit_gk2_state(&s), "Plain ignores the salt");

        let e = Gk2State::empty(HP);
        let mut leaf = hiding_leaf(Binding::Semantic);
        let l1 = leaf.prove_epoch_commit(1, e.clone(), Vec::new(), &OpeningsGl::for_leaf(&seed, GK, 1));
        let l2 = leaf.prove_epoch_commit(2, e.clone(), Vec::new(), &OpeningsGl::for_leaf(&seed, GK, 2));
        let (s1, s2) = (read_exposed_statement(&l1.output.0), read_exposed_statement(&l2.output.0));
        assert_eq!(s1.init, commit_gk2_state_with(&e, CommitMode::Hiding, &SaltGl::ZERO).0.to_vec());
        assert_eq!(s1.final_, commit_gk2_state_with(&e, CommitMode::Hiding, &r1).0.to_vec());
        assert_eq!(s2.init, s1.final_, "leaf 2 opens Com(S_1) with the same ρ_1");
        assert_eq!(s2.final_, commit_gk2_state_with(&e, CommitMode::Hiding, &r2).0.to_vec());
        assert_ne!(s1.init, s1.final_, "the state did not move, the commitment did");
        assert_ne!(s2.init, s2.final_);
    }

    /// (4) Binding in Hiding mode, through the auditor paths: an honest
    /// 2-leaf forest passes the per-batch log check and its root verifies
    /// against the log under the root VK derived from the zero-salt no-op
    /// leaf; another seed's log, a wrong batch salt and a wrong final salt
    /// are rejected; an inconsistent `ρ_1` across the leaf boundary cannot be
    /// merged.
    #[test]
    fn wrong_salt_rejected_by_log_and_inconsistent_salt_breaks_merge() {
        let binding = Binding::Semantic;
        let (a, b) = (SaltSeed::for_tests(41), SaltSeed::for_tests(42));
        let bs = hp_batches();
        let s0 = Gk2State::empty(HP);
        let s1 = apply_batch2(&s0, &bs[0]);
        let s2 = apply_batch2(&s1, &bs[1]);
        let log_for = |seed: &SaltSeed| {
            let bc: Vec<[Val; 4]> = [(&bs[0], s0.n), (&bs[1], s1.n)]
                .iter()
                .enumerate()
                .map(|(k, (v, n))| {
                    commit_gk2_batch_with(v, HP.batch, *n, CommitMode::Hiding, &rho_batch_gl(seed, GK, k as u64 + 1)).0
                })
                .collect();
            batch_log(
                &commit_gk2_state_with(&s0, CommitMode::Hiding, &SaltGl::ZERO).0,
                &commit_gk2_state_with(&s2, CommitMode::Hiding, &rho_state_gl(seed, GK, 2)).0,
                &bc,
            )
        };
        let (log_a, log_b) = (log_for(&a), log_for(&b));
        let mut leaf = hiding_leaf(binding);
        let l1 = leaf.prove_epoch_commit(1, s0.clone(), bs[0].clone(), &OpeningsGl::for_leaf(&a, GK, 1)).output;
        let l2 = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &OpeningsGl::for_leaf(&a, GK, 2)).output;
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log_a, Expose::Interval), Ok(()));
        assert!(check_leaves_against_log(&[&l1.0, &l2.0], &log_b, Expose::Interval).is_err(), "another seed's log");

        let bad_batch = OpeningsGl { batch: rho_batch_gl(&b, GK, 2), ..OpeningsGl::for_leaf(&a, GK, 2) };
        let l2b = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_batch).output;
        let e = check_leaves_against_log(&[&l1.0, &l2b.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("digest")), "{e:?}");
        let bad_final = OpeningsGl { final_: rho_state_gl(&b, GK, 2), ..OpeningsGl::for_leaf(&a, GK, 2) };
        let l2f = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_final).output;
        let e = check_leaves_against_log(&[&l1.0, &l2f.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("Com(S_T)")), "{e:?}");

        let shape = ForestShape::forest(2);
        let root = prove_hiding_merge(&l1, &l2);
        let noop = gk2_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
        let vk = root_vk_deriver(noop).root_vk(&shape);
        verify_bound_stark_proof_against_log(&root.0, &vk, &log_a, &shape);
        assert!(check_root_against_log(&root.0, &log_b, &shape).is_err());

        let bad_init = OpeningsGl { init: rho_state_gl(&b, GK, 1), ..OpeningsGl::for_leaf(&a, GK, 2) };
        let l2i = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_init).output;
        assert_ne!(read_exposed_statement(&l2i.0).init, read_exposed_statement(&l1.0).final_);
        let e = forge::catch_msg(|| prove_hiding_merge(&l1, &l2i)).map(|_| ());
        println!("B2 GL gk inconsistent salt merge: {e:?}");
        assert!(
            e.as_ref().is_err_and(|m| m.contains("WitnessConflict")),
            "leaf 2's init must use leaf 1's final salt: {e:?}"
        );
    }

    /// (5) The zero-salt no-op leaf of a Hiding circuit still exposes
    /// `init == final` (`= Com(S_0; 0)`, the public anchor), so the twin-merge
    /// root-VK derivation works unchanged; the Plain no-op leaf exposes the
    /// pre-B2 anchor.
    #[test]
    fn hiding_noop_leaf_has_init_eq_final() {
        let empty = Gk2State::empty(HP);
        for binding in [Binding::Semantic, Binding::Legacy] {
            let noop = gk2_gl_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
            let st = read_exposed_statement(&noop);
            let anchor = commit_gk2_state_with(&empty, CommitMode::Hiding, &SaltGl::ZERO);
            assert_eq!(st.init, st.final_, "{binding:?}");
            assert_eq!(st.init, anchor.0.to_vec(), "{binding:?}");
            assert_ne!(anchor, commit_gk2_state(&empty), "{binding:?}");
        }
        let plain = gk2_gl_noop_leaf_commit(HP, Expose::Boundary, Binding::Semantic, CommitMode::Plain);
        let (i, f) = read_exposed_boundary_proof(&plain);
        assert_eq!((i.0, f.0), (commit_gk2_state(&empty).0, commit_gk2_state(&empty).0));
    }

    /// (F3, F5) The Hiding leaf costs exactly +2 Poseidon2 rows and +3 ALU
    /// rows per commitment over the Plain leaf (+6 and +9 per leaf) under
    /// every binding, and none of its 18 salt values is a public value of
    /// the proof (positive control: a "salt" equal to an exposed commitment
    /// value is found).
    #[test]
    fn hiding_leaf_row_overhead_and_no_salt_in_public_values() {
        let seed = SaltSeed::for_tests(91);
        let t = 3u64;
        let vals = hp_batches()[0].clone();
        let o = OpeningsGl::for_leaf(&seed, GK, t);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let mut plain = build_gkb2_leaf_commit(HP, Expose::Interval, binding, CommitMode::Plain);
            let mut leaf = hiding_leaf(binding);
            let (p0, a0) = trace_rows(&plain.run_epoch_commit(t, hp_prior(), vals.clone(), &OpeningsGl::plain()));
            let (p1, a1) = trace_rows(&leaf.run_epoch_commit(t, hp_prior(), vals.clone(), &o));
            println!("B2 GL gk leaf rows {binding:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 6, "{binding:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 9, "{binding:?}: ALU rows");
            let hid = leaf.prove_epoch_commit(t, hp_prior(), vals.clone(), &o);
            assert_eq!(proof_alu_rows(&hid.output.0), a1, "{binding:?}: the proof's ALU height");
            assert_eq!(leaked_salts(&hid.output.0, &[o.init, o.final_, o.batch]), vec![], "{binding:?}");
            let mut control = SaltGl::ZERO;
            control.0[0] = hid.initial.0[0];
            assert!(!leaked_salts(&hid.output.0, &[control]).is_empty(), "{binding:?}: the scan sees the statement");
        }
    }

    /// (F1) A Hiding leaf never falls back to zero salts silently: the old
    /// `prove_epoch_at` / `prove_epoch` entry points panic on it, and so does
    /// `prove_epoch_commit` handed a zero final or batch salt. The explicit
    /// no-op path refuses a non-empty batch. Controls: a zero INIT salt is
    /// leaf 1's honest opening, and a Plain leaf still ignores its openings.
    #[test]
    fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
        let seed = SaltSeed::for_tests(81);
        let vals = hp_batches()[0].clone();
        let mut leaf = hiding_leaf(Binding::Semantic);
        let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, hp_prior(), vals.clone()).final_).unwrap_err();
        assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
        assert!(forge::catch(|| leaf.prove_epoch(hp_prior(), vals.clone()).final_).is_none());
        let honest = OpeningsGl::for_leaf(&seed, GK, 2);
        for (what, o) in [
            ("plain", OpeningsGl::plain()),
            ("public_zero", OpeningsGl::public_zero()),
            ("zero final", OpeningsGl { final_: SaltGl::ZERO, ..honest }),
            ("zero batch", OpeningsGl { batch: SaltGl::ZERO, ..honest }),
        ] {
            let msg = forge::catch_msg(|| leaf.prove_epoch_commit(2, hp_prior(), vals.clone(), &o).final_)
                .unwrap_err();
            assert!(msg.contains("public zero salt"), "{what}: {msg}");
        }
        let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, hp_prior(), vals.clone()).final_).unwrap_err();
        assert!(msg.contains("the batch must be empty"), "{msg}");

        let o1 = OpeningsGl::for_leaf(&seed, GK, 1);
        assert!(o1.init.is_zero());
        let r = leaf.prove_epoch_commit(1, hp_prior(), vals.clone(), &o1);
        assert_eq!(r.initial, commit_gk2_state_with(&hp_prior(), CommitMode::Hiding, &SaltGl::ZERO));
        let mut plain = build_gkb2_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Plain);
        let p = plain.prove_epoch_commit(2, hp_prior(), vals.clone(), &OpeningsGl::plain());
        assert_eq!(p.initial, commit_gk2_state(&hp_prior()));
        assert_eq!(p.final_, commit_gk2_state(&apply_batch2(&hp_prior(), &vals)));
        assert_eq!(p.batch_commit, commit_gk2_batch(&vals, HP.batch, hp_prior().n));
    }

    /// (F2) A continued history (the GK rotation after 2^24 records) is
    /// anchored on the previous history's certified final commitment
    /// ([`OpeningsGl::for_leaf_after`]): history 1 restarts `t` at 1 from
    /// history 0's final `S_2`, its leaf 1 exposes exactly the certified
    /// `Com(S_2; ρ_{0,2})`, both leaves pass history 1's log (whose anchor is
    /// taken from history 0, not recomputed), and the zero init salt is
    /// rejected.
    #[test]
    fn continued_history_leaf_opens_the_previous_final_commitment() {
        let seed = SaltSeed::for_tests(71);
        let bs = hp_batches();
        let s1 = apply_batch2(&Gk2State::empty(HP), &bs[0]);
        let s2 = apply_batch2(&s1, &bs[1]);
        let mut leaf = hiding_leaf(Binding::Semantic);
        let h0_last = leaf.prove_epoch_commit(2, s1, bs[1].clone(), &OpeningsGl::for_leaf(&seed, GK, 2));
        let anchor_salt = rho_state_gl(&seed, GK, 2);
        let anchor = h0_last.final_;
        assert_eq!(anchor, commit_gk2_state_with(&s2, CommitMode::Hiding, &anchor_salt));

        let h = 1u64;
        let s3 = apply_batch2(&s2, &bs[0]);
        let s4 = apply_batch2(&s3, &bs[1]);
        let o1 = OpeningsGl::for_leaf_after(&anchor_salt, &seed, GK, h);
        let l1 = leaf.prove_epoch_commit(1, s2.clone(), bs[0].clone(), &o1).output;
        let l2 = leaf.prove_epoch_commit(2, s3.clone(), bs[1].clone(), &OpeningsGl::for_leaf_in(&seed, GK, h, 2)).output;
        assert_eq!(read_exposed_statement(&l1.0).init, anchor.0.to_vec(), "history 1 starts at history 0's final");
        assert_eq!(read_exposed_statement(&l2.0).init, read_exposed_statement(&l1.0).final_);
        let bc: Vec<[Val; 4]> = [(&bs[0], s2.n), (&bs[1], s3.n)]
            .iter()
            .enumerate()
            .map(|(k, (v, n))| {
                commit_gk2_batch_with(v, HP.batch, *n, CommitMode::Hiding, &rho_batch_gl_in(&seed, GK, h, k as u64 + 1)).0
            })
            .collect();
        let fin = commit_gk2_state_with(&s4, CommitMode::Hiding, &rho_state_gl_in(&seed, GK, h, 2));
        let log1 = batch_log(&anchor.0, &fin.0, &bc);
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log1, Expose::Interval), Ok(()));
        let zero_init = OpeningsGl { init: SaltGl::ZERO, ..o1 };
        let l1z = leaf.prove_epoch_commit(1, s2, bs[0].clone(), &zero_init).output;
        let e = check_leaves_against_log(&[&l1z.0, &l2.0], &log1, Expose::Interval);
        assert!(e.as_ref().is_err_and(|m| m.contains("Com(S_0)")), "{e:?}");
    }

    /// (8) Build and prove the Hiding leaf at a tiny shape. Under the DEBUG
    /// profile (`cargo test --lib gk_bandmerge_gl::tests::hiding_leaf_tiny_debug`)
    /// the fork debug-asserts, during the build, that each of the 9 salt
    /// private inputs has an ALU creator.
    #[test]
    fn hiding_leaf_tiny_debug() {
        let p = GkbParams { capacity: 4, batch: 2, s: 2 };
        for binding in [Binding::Semantic, Binding::Legacy] {
            let mut leaf = build_gkb2_leaf_commit(p, Expose::Interval, binding, CommitMode::Hiding);
            let seed = SaltSeed::for_tests(8);
            let r = leaf.prove_epoch_commit(1, Gk2State::empty(p), vec![9, 3], &OpeningsGl::for_leaf(&seed, GK, 1));
            let fin = apply_batch2(&Gk2State::empty(p), &[9, 3]);
            assert_eq!(r.final_, commit_gk2_state_with(&fin, CommitMode::Hiding, &rho_state_gl(&seed, GK, 1)));
        }
    }
}
