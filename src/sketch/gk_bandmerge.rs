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

use crate::commitment::hiding::{
    self, CommitFamily, CommitKind, CommitMode, Openings, SaltBb, commit_flat_bb,
};
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

// ── Fresh-row arrival positions t_j = N_{t-1} + 1 + j ─────────────────────

/// **Bind the fresh batch rows' arrival positions to the record count**: for
/// the `m` fresh rows of the committed batch table (timestamps `t[j]`,
/// activity flags `act[j] = [e_j ≠ E_MAX]`), constrain
/// * `act[j+1]·(1 − act[j]) = 0`: the active rows form a prefix (the
///   [`fresh_tuples2`] layout);
/// * `t[j] = act[j]·(N_{t-1} + 1 + j)`: active row `j` arrives at position
///   `N_{t-1} + 1 + j`, and a dummy carries the fixed `t = 0` of
///   [`Gk2Tuple::dummy`].
///
/// A row's arrival position decides which tuple of a fused pair is newer
/// (`lt = [a.t > b.t]`, hence which of the two fusion tests applies) and
/// whether neighbor-init treats a union row as fresh (`is_fresh =
/// [N_{t-1} < t]`). Before this, `t` was set only natively
/// ([`fresh_tuples2`]) and bound only through `Com(B_t)`, so a prover that
/// commits the batch table itself could permute the batch's arrival order,
/// give a fresh value a stale `t ≤ N_{t-1}` (it skips neighbor-init), leave
/// a gap so a survivor carries `t > N_t` (the next epoch re-initializes it
/// as fresh), or pad with a nonzero dummy `t`
/// (`tests::gk2_forged_arrival_positions_legacy_accepts_semantic_rejects`).
/// With the leaves' `N_t = N_{t-1} + #active(B_t)`, every fresh `t` now
/// lies in `(N_{t-1}, N_t]` and follows the batch's row order. `n_prev` is
/// the leaf's `N_{t-1}` input, which that identity and the mass check pin.
///
/// Cost: `4m − 2` ALU ops (an add and a mul per row, a sub and a mul per
/// adjacent pair), of which the circuit builder shares `m` with ops the leaf
/// already has (`N_{t-1} + 1` from neighbor-init, each `1 − act[j]` from the
/// activity gadget): `+3m − 2` ALU rows, no constants, no range checks, no
/// public inputs (measured with `tests::gk2_theta_bind_overhead`: +22 rows
/// at `m = 8`, +46 at `m = 16`; padded trace rows unchanged at cap 16…256).
/// Generic over the field so the Goldilocks leaf
/// ([`crate::sketch::gk_bandmerge_gl`]) shares it.
pub(crate) fn bind_arrival_positions<F>(
    b: &mut CircuitBuilder<F>,
    t: &[ExprId],
    act: &[ExprId],
    n_prev: ExprId,
    one: ExprId,
    zero: ExprId,
) where
    F: p3_field::Field + std::hash::Hash,
{
    assert_eq!(t.len(), act.len(), "one activity flag per fresh row");
    let mut pos = n_prev;
    for j in 0..t.len() {
        pos = b.add(pos, one); // N_{t-1} + 1 + j
        let want = b.mul(act[j], pos);
        b.connect(t[j], want);
        if j + 1 < t.len() {
            let gap = b.sub(one, act[j]);
            let bad = b.mul(act[j + 1], gap);
            b.connect(bad, zero);
        }
    }
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
///
/// A capacity overflow is a **hard error** (G-cap): this panics with the
/// [`GkCapacityOverflow`] message (which names the capacity, so the harness
/// records the run as `too_large`, a failed run). [`try_apply_batch2`] is the
/// same step returning the error instead. The output for every step that
/// keeps all its survivors is unchanged.
pub fn apply_batch2(s_old: &Gk2State, batch_vals: &[u32]) -> Gk2State {
    try_apply_batch2(s_old, batch_vals).unwrap_or_else(|e| panic!("{e}"))
}

/// [`apply_batch2`] with the capacity overflow as an error value: `Err` when
/// the step would lose a survivor (more than `capacity` live rows after the
/// `L_f` rounds, or a live unpaired last row of an odd `capacity + m` table,
/// which the parity-0 rounds drop). Before M3 release builds dropped those
/// rows silently (the check was a `debug_assert!`); no leaf circuit proves
/// such a step (the SortedCopy leaf pins its excess rows to dummies, the
/// StableCompact leaf pins `α^L_cap = 0` and the mass).
pub fn try_apply_batch2(s_old: &Gk2State, batch_vals: &[u32]) -> Result<Gk2State, GkCapacityOverflow> {
    let b = build_bm2(s_old, batch_vals);
    // The two-sided sketch has no hard case, so a capacity ≥ the Gribelyuk bound
    // 2s·ln(N/s+2)+2 never overflows; bm2 is not a fusion fixed point, so the
    // deployed capacities are empirical and the check is a real error path.
    match b.capacity_error(s_old.params) {
        Some(e) => Err(e),
        None => Ok(Gk2State {
            tuples: b.final_tuples,
            params: s_old.params,
            n: b.n_t,
        }),
    }
}

/// A band-merge step ([`try_apply_batch2`]) that would lose a survivor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GkCapacityOverflow {
    /// The declared capacity `s'`.
    pub capacity: usize,
    /// The leaf batch size `m`.
    pub batch: usize,
    /// Live rows after the `L_f` rounds (`> capacity` on an overflow).
    pub survivors: usize,
    /// Live rows an odd `capacity + m` table dropped as its unpaired last row.
    pub unpaired_dropped: usize,
    /// `N_t` after the step.
    pub n_t: u64,
    /// The LOSSY state release builds returned before M3 (the first
    /// `capacity` rows of the last round, the dropped survivors' mass lost).
    /// NOT a valid summary: kept only so the zk-Analytics ports of that code
    /// (`scripts/baselines/zka/gk_bm2`), which reproduce it, can still be
    /// compared row for row.
    pub lossy_state: Gk2State,
}

impl std::fmt::Display for GkCapacityOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GK capacity overflow: {} survivors > capacity {} at N_t = {} (batch {}{}); the step would \
             lose a survivor, which is a hard error: declare a larger capacity (s' >= 2s·ln(N/s+2)+2)",
            self.survivors,
            self.capacity,
            self.n_t,
            self.batch,
            if self.unpaired_dropped > 0 {
                format!(", {} live unpaired row(s) of the odd table dropped", self.unpaired_dropped)
            } else {
                String::new()
            }
        )
    }
}

impl std::error::Error for GkCapacityOverflow {}

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
    /// Live rows dropped as the unpaired last row of an odd table (never on
    /// the leaves' even tables).
    unpaired_dropped: usize,
}

impl Bm2Build {
    /// The capacity overflow of this replay, if it loses a survivor: a live
    /// excess row (more than `capacity` survivors) or a dropped live unpaired
    /// row. `None` for every step whose output keeps all its survivors.
    fn capacity_error(&self, params: GkbParams) -> Option<GkCapacityOverflow> {
        let live = |ts: &[Gk2Tuple]| ts.iter().filter(|t| is_active2(t)).count();
        let excess = live(&self.excess);
        if excess == 0 && self.unpaired_dropped == 0 {
            return None;
        }
        Some(GkCapacityOverflow {
            capacity: params.capacity,
            batch: params.batch,
            survivors: live(&self.final_tuples) + excess,
            unpaired_dropped: self.unpaired_dropped,
            n_t: self.n_t,
            lossy_state: Gk2State { tuples: self.final_tuples.clone(), params, n: self.n_t },
        })
    }
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
    let mut unpaired_dropped = 0usize;
    for _ in 0..lf {
        // An odd table's last row is never paired and comes out a dummy:
        // a live one is a lost survivor (see `Bm2Build::capacity_error`).
        if total % 2 == 1 && is_active2(&cur[total - 1]) {
            unpaired_dropped += 1;
        }
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
        unpaired_dropped,
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

/// [`commit_gk2_state`] under a [`CommitMode`] (revision B2,
/// [`crate::commitment::hiding`]): `Plain` is exactly [`commit_gk2_state`]
/// (the salt is ignored); `Hiding` is `MyHash([TAG_STATE, GreenwaldKhanna, 0,
/// 0, ρ…] ‖ flat)` over the same flat tuple encoding (8 base values per
/// tuple), the value a `Hiding` band-merge leaf and the GK decoder expose for
/// `Com(S_t; ρ)`.
pub fn commit_gk2_state_with(state: &Gk2State, mode: CommitMode, salt: &SaltBb) -> Gk2StateCommit {
    match mode {
        CommitMode::Plain => commit_gk2_state(state),
        CommitMode::Hiding => Gk2StateCommit(commit_flat_bb(
            mode,
            CommitKind::State,
            CommitFamily::GreenwaldKhanna,
            salt,
            &flat_tuples2(&state.tuples),
        )),
    }
}

/// [`commit_gk2_batch`] under a [`CommitMode`]: `Plain` is exactly
/// [`commit_gk2_batch`]; `Hiding` is `Com(B_t; ρ)` under `TAG_BATCH` over the
/// same fresh-tuple encoding, which still depends on `n_prev` (the fresh
/// tuples' insertion times `t = n_prev + 1 + j`).
pub fn commit_gk2_batch_with(
    vals: &[u32],
    m: usize,
    n_prev: u64,
    mode: CommitMode,
    salt: &SaltBb,
) -> Gk2BatchCommit {
    commit_gk2_rows_with(&fresh_tuples2(vals, m, n_prev), mode, salt)
}

/// [`commit_gk2_batch_with`] over an explicit fresh-row table (honestly
/// [`fresh_tuples2`]; a soundness test may commit forged rows).
fn commit_gk2_rows_with(rows: &[Gk2Tuple], mode: CommitMode, salt: &SaltBb) -> Gk2BatchCommit {
    match mode {
        CommitMode::Plain => {
            let hasher = MyHash::new(make_perm());
            Gk2BatchCommit(hasher.hash_iter(flat_tuples2(rows)))
        }
        CommitMode::Hiding => Gk2BatchCommit(commit_flat_bb(
            mode,
            CommitKind::Batch,
            CommitFamily::GreenwaldKhanna,
            salt,
            &flat_tuples2(rows),
        )),
    }
}

/// The fresh-row table a band-merge leaf witness commits as `B_t` and feeds
/// to the union: [`fresh_tuples2`] (tests may substitute forged rows).
fn leaf_fresh_rows(vals: &[u32], m: usize, n_prev: u64) -> Vec<Gk2Tuple> {
    #[cfg(test)]
    if let Some(rows) = TAMPER_FRESH.with(|c| c.borrow().clone()) {
        return rows;
    }
    fresh_tuples2(vals, m, n_prev)
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

/// Test-only: let a `StableCompact` leaf pack an overflowing batch (so a
/// test can show the circuit itself rejects it). Always `false` outside tests.
fn allow_overflow_for_test() -> bool {
    #[cfg(test)]
    if let Some(v) = ALLOW_OVERFLOW.with(|c| c.get()) {
        return v;
    }
    false
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
    /// Test-only tamper: the fresh-row table the leaf witness commits as
    /// `B_t` and feeds to the union ([`leaf_fresh_rows`]), to PoC-verify
    /// [`bind_arrival_positions`]. `None` = the honest [`fresh_tuples2`].
    static TAMPER_FRESH: std::cell::RefCell<Option<Vec<Gk2Tuple>>> =
        const { std::cell::RefCell::new(None) };
    /// Test-only: lift the StableCompact native overflow hard error.
    static ALLOW_OVERFLOW: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
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
/// **Arrival positions (2026-10-11).** A fresh row's timestamp `t` picks the
/// newer tuple of a fused pair (so which fusion test applies) and gates
/// neighbor-init, but it was set only natively (`fresh_tuples2`) and bound
/// only through `Com(B_t)`: permuted, stale, gapped or nonzero-dummy
/// timestamps were ACCEPTED
/// (`gk2_forged_arrival_positions_legacy_accepts_semantic_rejects`). Under the
/// default binding the circuit forces the active batch rows to a prefix with
/// `t_j = N_{t-1} + 1 + j` and dummies to `t = 0`
/// ([`bind_arrival_positions`]); the arrival order is then the batch's row
/// order, which `Com(B_t)` binds.
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

/// How a band-merge leaf certifies the recompaction after each of its `L_f`
/// fusion rounds. Both variants prove the SAME batch rule, `apply_batch2`
/// (union, two-sided neighbour-init, `L_f` parity-0 rounds of the Gribelyuk
/// Alg-4 test, compaction to `capacity`), the same `Com(S_{t-1})`,
/// `Com(B_t)`, `Com(S_t)` encodings and statement, so the GK decoder and its
/// VK are shared; the leaf (hence merge and root) VKs differ.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Hash)]
pub enum GkRounds {
    /// Today's circuit: per round a committed fused table, a general sorted
    /// copy (one resort permute) and its range + `(e, t)` order checks.
    #[default]
    SortedCopy,
    /// G1 (M3): per round one threshold test selected by the checked
    /// direction bit, a shared survivor update, and a STABLE compaction with
    /// computed destinations (survivors to their rank, dead rows to the
    /// tail) certified by destination-bound permute coordinates that also
    /// carry each row's liveness; union range checks move onto the committed
    /// init ([`build_gkb2_leaf_stable`]).
    StableCompact,
}

impl GkRounds {
    /// The CSV / profile label (`EXP_GK_ROUNDS` value).
    pub fn label(self) -> &'static str {
        match self {
            GkRounds::SortedCopy => "sorted",
            GkRounds::StableCompact => "stable",
        }
    }
}

impl std::str::FromStr for GkRounds {
    type Err = String;
    /// `sorted` / `stable` (any case), the [`GkRounds::label`]s.
    fn from_str(v: &str) -> Result<Self, String> {
        if v.eq_ignore_ascii_case("sorted") {
            Ok(GkRounds::SortedCopy)
        } else if v.eq_ignore_ascii_case("stable") {
            Ok(GkRounds::StableCompact)
        } else {
            Err(format!("GK rounds {v:?}: expected sorted or stable"))
        }
    }
}

/// The round certification the experiment harness uses when `EXP_GK_ROUNDS`
/// is unset (under a bound binding, see [`default_gk_rounds`]). The library
/// builders that predate M3 ([`build_gkb2_leaf_commit`] and friends) keep
/// building [`GkRounds::SortedCopy`] whatever this says, so their VKs and
/// pins never move.
pub const HARNESS_DEFAULT_GK_ROUNDS: GkRounds = GkRounds::StableCompact;

/// Parse an `EXP_GK_ROUNDS` lookup: `Some` variant for `sorted` / `stable`
/// (any case), `None` when unset or empty; anything else panics.
pub fn parse_gk_rounds_env(var: Result<String, std::env::VarError>) -> Option<GkRounds> {
    match var {
        Ok(v) if v.is_empty() => None,
        Ok(v) => Some(v.parse().unwrap_or_else(|e: String| panic!("EXP_GK_ROUNDS: {e}"))),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(v)) => {
            panic!("EXP_GK_ROUNDS={v:?}: not valid UTF-8; expected sorted or stable")
        }
    }
}

/// The experiment harness's GK round certification: `EXP_GK_ROUNDS` when set,
/// else [`HARNESS_DEFAULT_GK_ROUNDS`] under a bound binding and
/// [`GkRounds::SortedCopy`] under `ZKSKETCH_BINDING=legacy` (the StableCompact
/// leaf needs the in-circuit θ). The harness reads it ONCE into the public
/// stream shape (`StreamShape::gk_rounds`), from which the workers, the no-op
/// VK-derivation leaf and the auditor all build the leaf, so one run never
/// mixes the two VKs and the auditor derives them from public parameters.
pub fn default_gk_rounds() -> GkRounds {
    parse_gk_rounds_env(std::env::var("EXP_GK_ROUNDS")).unwrap_or_else(|| {
        if crate::sketch::bind::default_binding().is_bound() {
            HARNESS_DEFAULT_GK_ROUNDS
        } else {
            GkRounds::SortedCopy
        }
    })
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
    /// Padded height of each table (AIR order), as `trace_rows` sums.
    table_rows: Vec<usize>,
    /// Whether the permuted tables use the source-bound layout
    /// ([`pack_bound2`]; the tuple-half re-pairing + shared-PermuteBus fix).
    /// Always `true` outside tests; the soundness PoC builds the pre-fix circuit.
    pair_bind: bool,
    /// The composition statement this leaf exposes.
    expose: Expose,
    /// Whether the three commitments absorb a salt (revision B2).
    mode: CommitMode,
    /// Batch index `t` of the next proof (Interval statement only).
    batch_index: u64,
    /// How the circuit certifies each fusion round's recompaction
    /// ([`GkRounds`]); the batch rule, `Com(S_t)` and the statement are the
    /// same under both, the VKs are not.
    rounds: GkRounds,
    /// The StableCompact checks this leaf was built with (always
    /// [`StableChecks::ALL`] outside tests; the witness packer follows the
    /// liveness-carry switch).
    stable_checks: StableChecks,
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
/// in-circuit ([`bind_theta`], revision B6(d)) and the fresh rows' arrival
/// positions `t_j = N_{t-1} + 1 + j` ([`bind_arrival_positions`]). `Legacy`
/// is the pre-fix circuit, byte-for-byte: its `θ` is a free public input, so
/// a prover can over-merge
/// (`tests::gk2_inflated_theta_legacy_accepts_semantic_rejects`), and its
/// fresh-row `t` is bound only through `Com(B_t)`
/// (`tests::gk2_forged_arrival_positions_legacy_accepts_semantic_rejects`).
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
///
/// Plain commitments ([`build_gkb2_leaf_commit`] with [`CommitMode::Plain`]).
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
/// `Com(S_{t-1})`, `Com(S_t)` and `Com(B_t)` (init, final, batch; three
/// Challenges each), allocated as the FIRST private inputs, and hashes each
/// commitment as `[tag, salt…, inputs…]`, i.e. [`commit_gk2_state_with`] /
/// [`commit_gk2_batch_with`]. The commitment sponges stay the leaf's raw
/// `add_hash_slice` under every binding (`Binding::Semantic` in
/// [`hiding::commit_hash`] is that call), as before. So, unlike Count-Min,
/// `Binding::Bound` does NOT give GK's commitments the zero-IV first row of
/// `bind::hash_slice` (pre-existing: the Semantic and Bound VKs are equal,
/// as on main, and the decoder does the same); routing them through the
/// binding would change the Bound VKs and is a separate decision. The salts
/// are witnesses, so the VK does not depend on them; prove with
/// [`Gkb2LeafCircuit::prove_epoch_commit`].
///
/// This is the [`GkRounds::SortedCopy`] leaf (the pre-M3 circuit byte for
/// byte, whatever `EXP_GK_ROUNDS` says); [`build_gkb2_leaf_rounds`] selects
/// the round certification.
pub fn build_gkb2_leaf_commit(
    params: GkbParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
) -> Gkb2LeafCircuit {
    build_gkb2_leaf_rounds(params, expose, binding, mode, GkRounds::SortedCopy)
}

/// [`build_gkb2_leaf_commit`] with an explicit round certification
/// ([`GkRounds`]). `SortedCopy` is the pre-M3 circuit (same VK);
/// `StableCompact` is the G1 circuit ([`build_gkb2_leaf_stable`]), which
/// proves the same batch rule `apply_batch2` (same `Com(S_t)`, statement and
/// decoder) under its own VK.
pub fn build_gkb2_leaf_rounds(
    params: GkbParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
    rounds: GkRounds,
) -> Gkb2LeafCircuit {
    match rounds {
        GkRounds::SortedCopy => build_gkb2_leaf_sorted(params, expose, binding, mode),
        GkRounds::StableCompact => build_gkb2_leaf_stable(params, expose, binding, mode),
    }
}

/// The `SortedCopy` leaf: per round a fused table, a general sorted copy
/// (resort permute) and its `(e, t)` order checks. Unchanged since before M3.
fn build_gkb2_leaf_sorted(
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

    // B2: the salts of (init, final, batch) are the FIRST 9 private inputs
    // under `Hiding` ([`Openings::private_inputs`] order); `Plain` allocates
    // nothing, so its circuit is byte-identical.
    let salts = hiding::alloc_leaf_salts(&mut b, mode);
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
    // Salted under `Hiding` (`[tag, salt…, inputs…]`); under `Plain` exactly
    // the raw `add_hash_slice(inputs)` (`Binding::Semantic` in
    // `hiding::commit_hash`), under every leaf binding.
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let fam = CommitFamily::GreenwaldKhanna;
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
    // and both padding coeffs 0 (the arrival position t is bound under
    // Semantic/Bound by Stage 10). The union is a permutation of init ‖ batch.
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
    let mut batch_act: Vec<ExprId> = Vec::with_capacity(m);
    for j in 0..m {
        let dj = b.sub(e_max, batch_f[2 * j][0]);
        let actj = force_nz(&mut b, dj, e_inv_batch[j], one, zero);
        count_batch = b.add(count_batch, actj);
        batch_act.push(actj);
    }
    let np_plus_b = b.add(n_prev_pi, count_batch);
    b.connect(np_plus_b, n_t_pi);
    // ── Stage 9: θ = ⌊N_t/s⌋ from the in-circuit N_t (revision B6(d)) ──
    // Appended last so the Legacy circuit is byte-for-byte the pre-fix one.
    if binding.is_bound() {
        bind_theta::<Val, Challenge>(&mut b, theta_pi, n_t_pi, params.s);
    }
    // ── Stage 10: fresh-row arrival positions t_j = N_{t-1} + 1 + j ──
    // Active batch rows form a prefix and carry t_j = N_{t-1}+1+j; dummies
    // carry t = 0 ([`bind_arrival_positions`]). Also after the Legacy circuit.
    if binding.is_bound() {
        let batch_t: Vec<ExprId> = (0..m).map(|j| batch_f[2 * j + 1][1]).collect();
        bind_arrival_positions(&mut b, &batch_t, &batch_act, n_prev_pi, one, zero);
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
    // E-0 table probe (read-only; a no-op unless armed).
    crate::experiments::table_probe::record_leaf(
        "gk_bandmerge2",
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

    Gkb2LeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        table_rows,
        pair_bind,
        expose,
        mode,
        batch_index: 1,
        rounds: GkRounds::SortedCopy,
        stable_checks: StableChecks::ALL,
    }
}

// ══════════════════════════════════════════════════════════════════════════
// G1 (M3): GkRounds::StableCompact — the same batch rule, each round's
// recompaction certified by a STABLE compaction with computed destinations.
// ══════════════════════════════════════════════════════════════════════════
//
// Why the output is the SortedCopy circuit's (= `finish_bm2`'s): after every
// round the SortedCopy circuit turns each folded-away row into the
// `(E_MAX, 0…0)` dummy and re-sorts by `(e, t)`. A fusion only changes a
// survivor's `g₁` or `g₂`; its `(e, t)` key is unchanged, and the round input
// is `(e, t)`-sorted with the live rows first. So the re-sort is exactly
// "survivors in their input order, then dummies": a stable compaction. The
// stable variant moves survivors to their rank (`ρ_i = Σ_{j<i} sflag_j`) and
// dead rows to the tail (reversed, `T−1−#dead-before-i`), keeps the dead rows'
// stale contents (positional liveness marks them dead: they never fuse again
// and are masked to the dummy in the final), and so reproduces every round's
// live prefix bit for bit. `stable_rounds` replays it natively and the prover
// asserts its masked final equals `finish_bm2`'s before every proof.

/// Liveness carry of the destination-bound round layout: the lo coordinate
/// of a round-op element whose row survives the round carries
/// `+ LIVE_CARRY`. Every plain coordinate `bind_coord(k, h, x)` with
/// `k ≤ L_f ≤ 20`, `x < 2^SRC_BITS` is `< 43·2^20 < 2^26`, so plain and
/// carried coordinates are disjoint and `LIVE_CARRY + bind_coord < 2^28 < p`:
/// a coordinate names `(op, half, position, liveness)` uniquely.
const LIVE_CARRY: u64 = 1 << 27;

/// One stable-compaction round of the native replay.
#[derive(Clone)]
struct StableRound {
    /// `lt = [a.t > b.t]` per pair (also on dead pairs: the honest value).
    lt: Vec<u8>,
    /// `cond = [S ≤ θ]` per pair, `S` the lt-selected Alg-4 sum.
    cond: Vec<u8>,
    /// Output rows, `out[p] = emitted[src[p]]` (dead rows keep stale fields).
    out: Vec<Gk2Tuple>,
    /// Output liveness `alive[p] = sflag[src[p]]` (a prefix of ones).
    alive: Vec<u8>,
    /// Input row placed at output position `p` (inverse of the destinations).
    src: Vec<usize>,
}

/// Native witness of the stable-compaction rounds.
#[derive(Clone)]
struct StableBuild {
    rounds: Vec<StableRound>,
    /// The masked final state: live prefix of the last round, then dummies.
    final_tuples: Vec<Gk2Tuple>,
    /// Live rows after the last round (`> cap` is a capacity overflow).
    survivors: usize,
}

/// Replay the `L_f` rounds of `finish_bm2` as stable compactions from the
/// neighbour-initialised union (`union_init`, `(e,t)`-sorted, dummies last).
fn stable_rounds(union_init: &[Gk2Tuple], theta: u64, cap: usize) -> StableBuild {
    let total = union_init.len();
    assert!(total >= 2 && total % 2 == 0, "stable rounds need an even union of >= 2 rows");
    let lf = num_rounds(total);
    let mut cur = union_init.to_vec();
    let mut alive: Vec<u8> = cur.iter().map(|t| (t.e != E_MAX) as u8).collect();
    let mut rounds = Vec::with_capacity(lf);
    for _ in 0..lf {
        let mut emitted = cur.clone();
        let mut sflag = alive.clone();
        let mut lt = Vec::with_capacity(total / 2);
        let mut cond = Vec::with_capacity(total / 2);
        for j in 0..total / 2 {
            let (a, b) = (cur[2 * j], cur[2 * j + 1]);
            let l = a.t > b.t;
            // S = g₂ₐ + g₁_b + (lt ? g₁ₐ + Δ₁_b : g₂_b + Δ₂ₐ) + 1 — Alg 4's sum1 / sum2.
            let c = a.g_o + b.g;
            let selg = if l { a.g } else { b.g_o };
            let seld = if l { b.delta } else { a.delta_o };
            let cd = c + selg + seld + 1 <= theta;
            let merge = cd && alive[2 * j + 1] == 1;
            let mnew = c + selg + 1; // the survivor's new side mass
            if merge {
                debug_assert_eq!(alive[2 * j], 1, "liveness is a prefix");
                if l {
                    emitted[2 * j + 1].g = mnew; // a folds right into b
                    sflag[2 * j] = 0;
                } else {
                    emitted[2 * j].g_o = mnew; // b folds left into a
                    sflag[2 * j + 1] = 0;
                }
            }
            lt.push(l as u8);
            // The circuit gates the threshold test by α_b (a dead b's stale
            // fields may double-count mass), which forces cond = 0 there.
            cond.push((cd && alive[2 * j + 1] == 1) as u8);
        }
        let mut src = vec![usize::MAX; total];
        let mut rho = 0usize;
        for i in 0..total {
            let dest = if sflag[i] == 1 { rho } else { rho + total - 1 - i };
            assert_eq!(src[dest], usize::MAX, "stable destinations form a permutation");
            src[dest] = i;
            rho += sflag[i] as usize;
        }
        let out: Vec<Gk2Tuple> = src.iter().map(|&i| emitted[i]).collect();
        let alive_out: Vec<u8> = src.iter().map(|&i| sflag[i]).collect();
        rounds.push(StableRound {
            lt,
            cond,
            out: out.clone(),
            alive: alive_out.clone(),
            src,
        });
        cur = out;
        alive = alive_out;
    }
    let survivors = alive.iter().filter(|&&a| a == 1).count();
    let final_tuples = (0..cap)
        .map(|p| if alive[p] == 1 { Gk2Tuple { active: 1, ..cur[p] } } else { Gk2Tuple::dummy() })
        .collect();
    StableBuild { rounds, final_tuples, survivors }
}

/// Pack round op `k`'s output table in the destination-bound layout:
/// `lo = (e, g₁, g₂, B(k,0,p) + alive_p·LIVE_CARRY)`, `hi = (Δ₂, t, Δ₁, B(k,1,p))`.
/// The op's input element of row `i` is the same with `p = dest_i` and
/// `alive_p = sflag_i`, so the honest output is the input permuted by `src`.
fn pack_stable_out(ts: &[Gk2Tuple], k: usize, alive: &[u8], live_carry: bool) -> Vec<Challenge> {
    let carry = if live_carry { LIVE_CARRY } else { 0 };
    use p3_field::BasedVectorSpace;
    ts.iter()
        .enumerate()
        .flat_map(|(p, t)| {
            let lo = [
                Val::from_u32(t.e),
                Val::from_u32(t.g as u32),
                Val::from_u32(t.g_o as u32),
                Val::from_u64(bind_coord(k, 0, p) + alive[p] as u64 * carry),
            ];
            let hi = [
                Val::from_u32(t.delta_o as u32),
                Val::from_u32(t.t as u32),
                Val::from_u32(t.delta as u32),
                Val::from_u64(bind_coord(k, 1, p)),
            ];
            [
                Challenge::from_basis_coefficients_slice(&lo).expect("4 lo coeffs"),
                Challenge::from_basis_coefficients_slice(&hi).expect("4 hi coeffs"),
            ]
        })
        .collect()
}

/// **The checks of the StableCompact leaf, one switch each** — the single
/// place that lists them. [`build_gkb2_leaf_stable`] builds every check whose
/// switch is `true`; outside `cfg(test)` all are always on
/// ([`StableChecks::ALL`]). A test removes ONE check with
/// [`with_stable_checks`] to build the positive-control circuit of a
/// trace-level attack (G-sound): with the check off the forgery must verify
/// (and certify a wrong state), with it on the AIR / LogUp / range argument
/// must reject it. Removing a check changes the leaf's VK
/// (`stable_tests::g1_stable_check_switches_are_clean`).
///
/// Stage numbers refer to [`build_gkb2_leaf_stable`]. Hints are the private
/// inputs `is_fresh`, `lt`, `cond`, `alive` (per round), the compacted round
/// tables `out_r` and the inverse hints; every other wire is computed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct StableChecks {
    /// Stage 3: init `e < 2^22` and `g₁, g₂, Δ₁, Δ₂, t < 2^24`, batch
    /// `e < 2^22` (the union range checks, moved onto the committed rows).
    pub init_ranges: bool,
    /// Stage 3: `N_{t-1} − t ∈ [0, 2^24)` on every init row (review
    /// G1-minor: no init row carries `t > N_{t-1}`; dead rows have `t = 0`).
    pub init_t_le_n_prev: bool,
    /// Stage 4: union source binding (`bind_output_pair`, op 0).
    pub union_source: bool,
    /// Stage 4: union `e` non-decreasing (22-bit) and `t` non-decreasing
    /// among equal `e` (24-bit): the `(e, t)` order that makes `α⁰` a prefix.
    pub union_order: bool,
    /// Stage 4: dead union rows are the canonical dummy,
    /// `(1 − α⁰)·{g₁, g₂, Δ₁, Δ₂, t} = 0`.
    pub dead_union_canonical: bool,
    /// Stage 4: `N_{t-1}, N_t < 2^24`.
    pub n_ranges: bool,
    /// Stage 5: `is_fresh` boolean.
    pub fresh_bool: bool,
    /// Stage 5: `is_fresh = [N_{t-1} + 1 ≤ t]` range test (24-bit).
    pub fresh_range: bool,
    /// Stage 5: `Σ is_fresh = #active(B_t)`.
    pub fresh_count: bool,
    /// Stage 6: `lt` boolean.
    pub lt_bool: bool,
    /// Stage 6: `lt = [a.t > b.t]` range test (24-bit).
    pub lt_range: bool,
    /// Stage 6: `cond` boolean.
    pub cond_bool: bool,
    /// Stage 6: `cond = [S ≤ θ]` range test (24-bit, gated by `α_b`).
    pub cond_range: bool,
    /// Stage 6: `α'_p` boolean on every round output row.
    pub alive_bool: bool,
    /// Stage 6: round output position pins, `lo[3] = B(k,0,p) + α'_p·C`,
    /// `hi[3] = B(k,1,p)` (the destination binding).
    pub out_pos_pins: bool,
    /// Stage 6: the liveness carry `+ sflag_i·C` on the emitted lo
    /// coordinate and `+ α'_p·C` on the output pin; off, `α'` is a free
    /// boolean hint not tied to the survivor flags.
    pub live_carry: bool,
    /// Stage 7: `final = α^L ⊙ R^L` on the first `cap` rows (dead rows →
    /// `(E_MAX, 0…0)`); off, the committed final is not tied to the rounds.
    pub final_bind: bool,
    /// Stage 7: `α^L_cap = 0` (at most `cap` survivors).
    pub alive_cap: bool,
    /// Stage 8: `Σ_{p<cap} α(g₁ + g₂ + 1) = N_t`.
    pub mass: bool,
    /// Stage 8: `N_{t-1} + #active(B_t) = N_t`.
    pub n_count: bool,
    /// Stage 9: `θ = ⌊N_t / s⌋` ([`bind_theta`]).
    pub theta: bool,
    /// Stage 10: fresh arrival positions ([`bind_arrival_positions`]).
    pub arrivals: bool,
}

impl StableChecks {
    /// Every check on: the deployed circuit.
    pub const ALL: StableChecks = StableChecks {
        init_ranges: true,
        init_t_le_n_prev: true,
        union_source: true,
        union_order: true,
        dead_union_canonical: true,
        n_ranges: true,
        fresh_bool: true,
        fresh_range: true,
        fresh_count: true,
        lt_bool: true,
        lt_range: true,
        cond_bool: true,
        cond_range: true,
        alive_bool: true,
        out_pos_pins: true,
        live_carry: true,
        final_bind: true,
        alive_cap: true,
        mass: true,
        n_count: true,
        theta: true,
        arrivals: true,
    };

    /// Every switch with its name, all on; a test turns one off by name
    /// ([`Self::without`]).
    #[cfg(test)]
    pub fn names() -> &'static [&'static str] {
        &[
            "init_ranges",
            "init_t_le_n_prev",
            "union_source",
            "union_order",
            "dead_union_canonical",
            "n_ranges",
            "fresh_bool",
            "fresh_range",
            "fresh_count",
            "lt_bool",
            "lt_range",
            "cond_bool",
            "cond_range",
            "alive_bool",
            "out_pos_pins",
            "live_carry",
            "final_bind",
            "alive_cap",
            "mass",
            "n_count",
            "theta",
            "arrivals",
        ]
    }

    /// All checks on except `name` (one of [`Self::names`]).
    #[cfg(test)]
    pub fn without(name: &str) -> StableChecks {
        let mut c = Self::ALL;
        let f = match name {
            "init_ranges" => &mut c.init_ranges,
            "init_t_le_n_prev" => &mut c.init_t_le_n_prev,
            "union_source" => &mut c.union_source,
            "union_order" => &mut c.union_order,
            "dead_union_canonical" => &mut c.dead_union_canonical,
            "n_ranges" => &mut c.n_ranges,
            "fresh_bool" => &mut c.fresh_bool,
            "fresh_range" => &mut c.fresh_range,
            "fresh_count" => &mut c.fresh_count,
            "lt_bool" => &mut c.lt_bool,
            "lt_range" => &mut c.lt_range,
            "cond_bool" => &mut c.cond_bool,
            "cond_range" => &mut c.cond_range,
            "alive_bool" => &mut c.alive_bool,
            "out_pos_pins" => &mut c.out_pos_pins,
            "live_carry" => &mut c.live_carry,
            "final_bind" => &mut c.final_bind,
            "alive_cap" => &mut c.alive_cap,
            "mass" => &mut c.mass,
            "n_count" => &mut c.n_count,
            "theta" => &mut c.theta,
            "arrivals" => &mut c.arrivals,
            other => panic!("unknown StableChecks switch {other:?}"),
        };
        *f = false;
        c
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only: the checks [`build_gkb2_leaf_stable`] builds on this thread.
    static STABLE_CHECKS: std::cell::Cell<StableChecks> = const { std::cell::Cell::new(StableChecks::ALL) };
}

/// The StableCompact checks a leaf built on this thread gets: always
/// [`StableChecks::ALL`] outside tests.
fn stable_checks() -> StableChecks {
    #[cfg(test)]
    {
        STABLE_CHECKS.with(|c| c.get())
    }
    #[cfg(not(test))]
    {
        StableChecks::ALL
    }
}

/// Test-only: build StableCompact leaves inside `f` with `checks` (one check
/// removed, for a positive control); restores the previous set afterwards,
/// also on a panic.
#[cfg(test)]
pub(crate) fn with_stable_checks<R>(checks: StableChecks, f: impl FnOnce() -> R) -> R {
    struct Restore(StableChecks);
    impl Drop for Restore {
        fn drop(&mut self) {
            STABLE_CHECKS.with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(STABLE_CHECKS.with(|c| c.replace(checks)));
    f()
}

/// `cond = [x ≤ y]` from `dm1 = x − y − 1`, in 4 ALU ops plus the range
/// check: `w = dm1 − cond·(2·dm1 + 1)`, i.e. `(1−cond)·(x−y−1) + cond·(y−x)`,
/// the [`force_le`] witness. With `|x − y| < 2^bits ≪ p`, a wrong (boolean)
/// `cond` makes `w ≡ −w_true − 1` wrap to `≈ p` and fail the range check.
/// `(boolean, range)` switch the two halves (test-only positive controls,
/// [`StableChecks`]).
#[allow(clippy::too_many_arguments)]
fn force_le_dm1(
    b: &mut CircuitBuilder<Challenge>,
    cond: ExprId,
    dm1: ExprId,
    one: ExprId,
    two: ExprId,
    bits: usize,
    boolean: bool,
    range: bool,
) {
    if boolean {
        b.assert_bool(cond);
    }
    if range {
        let k = b.mul_add(dm1, two, one);
        let ck = b.mul(cond, k);
        let w = b.sub(dm1, ck);
        let _ = b.add_range_bits::<Val>(w, bits).expect("force_le_dm1 range");
    }
}

/// **The G1 stable-compaction band-merge leaf** (`GkRounds::StableCompact`).
///
/// Same public inputs, commitments (Stage 1), statement and batch rule as
/// [`build_gkb2_leaf_sorted`]; what changes is how each fusion round and
/// its recompaction are certified (per round, per pair `(a, b) = (R[2j],
/// R[2j+1])`, liveness `α`):
///
/// * `lt = [a.t > b.t]` ([`force_le_dm1`], 24-bit), and ONE threshold test
///   `cond = [S ≤ θ]` with `S = g₂ₐ + g₁_b + sel(lt; g₁ₐ, g₂_b) +
///   sel(lt; Δ₁_b, Δ₂ₐ) + 1` (24-bit) — Alg 4's `sum1` when `lt`, `sum2`
///   otherwise, replacing the two 27-bit tests and the per-round `e ≠ E_MAX`
///   activity gadgets;
/// * `merge = cond·α_b`, `d₁ = lt·merge`, `d₂ = merge − d₁`, survivor flags
///   `sflag_a = α_a − d₁`, `sflag_b = α_b − d₂`, and the shared survivor mass
///   `M = g₂ₐ + g₁_b + sel(lt; g₁ₐ, g₂_b) + 1`: `g₁_b ← g₁_b + d₁·(M − g₁_b)`,
///   `g₂ₐ ← g₂ₐ + d₂·(M − g₂ₐ)`; nothing else changes (dead rows go stale);
/// * destinations `dest_i = ρ_i + (1 − sflag_i)·(T−1−i)`, `ρ_i = Σ_{j<i}
///   sflag_j`: survivors to their rank, dead rows to the tail;
/// * one permute (op `k = r+1`): input `lo = (e, g₁, g₂, B(k,0,dest_i) +
///   sflag_i·C)`, `hi = (Δ₂, t, Δ₁, B(k,1,dest_i))`, output position `p`
///   pinned to `B(k,0,p) + α'_p·C`, `B(k,1,p)` with `α'_p` boolean
///   (`C = LIVE_CARRY`). The multiset equality then forces `out[dest_i] =
///   emitted[i]` (a bijection; no half re-pairing, no cross-op trade) and
///   carries the liveness `α'_{dest_i} = sflag_i`, which is a prefix by the
///   destination arithmetic. No range or order check of the output is needed:
///   its fields are the emitted ones, bounded by induction (`merge ⇒ the new
///   side mass + Δ ≤ θ < 2^24`).
///
/// The threshold test is gated by `α_b` (`dm1 = α_b·(S − 1 − θ)`): a dead
/// `b` forces `cond = 0` (it never merges anyway), so stale dead fields,
/// which may double-count mass, never reach the 24-bit test.
///
/// Once per leaf: init fields range-checked (e 22-bit, the rest 24-bit) and
/// batch `e` (22-bit) instead of every union row; `N_{t-1} − t ∈ [0, 2^24)`
/// on every init row (review G1-minor: no init row arrives after
/// `N_{t-1}`); `N_{t-1}, N_t < 2^24`; the union's `(e,t)` order,
/// neighbour-init and source binding as before; union liveness
/// `α⁰ = [e ≠ E_MAX]` with dead union rows pinned to the canonical dummy;
/// `Σ is_fresh = #active(B_t)`; final `= α^L ⊙ R^L` (dead → `(E_MAX, 0…0)`)
/// on the first `cap` rows and `α^L_cap = 0` (overflow is unprovable); mass
/// and `N_t`, θ and arrival bindings as before. Requires a bound binding
/// (`Semantic` / `Bound`): the 24-bit tests rely on the in-circuit
/// `θ ≤ θ_max`. Every check has a test-only switch ([`StableChecks`]).
fn build_gkb2_leaf_stable(
    params: GkbParams,
    expose: Expose,
    binding: Binding,
    mode: CommitMode,
) -> Gkb2LeafCircuit {
    assert!(
        binding.is_bound(),
        "GkRounds::StableCompact needs a Semantic/Bound binding (in-circuit θ and arrival positions)"
    );
    // Every check on outside tests (see `StableChecks`).
    let chk = stable_checks();
    let expose_boundary = expose == Expose::Boundary;
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    assert_eq!(total % 2, 0, "total = cap+m must be even");
    assert!(cap >= 1 && m >= 1, "stable leaf needs cap, m >= 1");
    let lf = num_rounds(total);
    let num_pairs = total / 2;
    check_bind_range(total, lf);
    assert!(
        bind_coord(lf, 1, (1 << SRC_BITS) - 1) < LIVE_CARRY
            && LIVE_CARRY + bind_coord(lf, 1, (1 << SRC_BITS) - 1) < 2_013_265_921,
        "liveness carry must clear every plain coordinate and stay below p"
    );

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
    let two = b.alloc_const(Challenge::from_u64(2), "two");
    let e_max = b.alloc_const(Challenge::from_u64(E_MAX as u64), "e_max");
    let live_c = b.alloc_const(Challenge::from_u64(LIVE_CARRY), "live_carry");

    let salts = hiding::alloc_leaf_salts(&mut b, mode);
    // Private inputs — 2 challenges per tuple. Alloc order == packing order.
    let init_packed: Vec<ExprId> = (0..2 * cap).map(|_| b.alloc_private_input("init")).collect();
    let final_packed: Vec<ExprId> = (0..2 * cap).map(|_| b.alloc_private_input("final")).collect();
    let batch_packed: Vec<ExprId> = (0..2 * m).map(|_| b.alloc_private_input("batch")).collect();
    let union_raw_packed: Vec<ExprId> =
        (0..2 * total).map(|_| b.alloc_private_input("union_raw")).collect();
    let out_packed: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| (0..2 * total).map(|_| b.alloc_private_input("compacted")).collect())
        .collect();
    let is_fresh: Vec<ExprId> = (0..total).map(|_| b.alloc_private_input("is_fresh")).collect();
    let lt: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| (0..num_pairs).map(|_| b.alloc_private_input("lt")).collect())
        .collect();
    let cond: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| (0..num_pairs).map(|_| b.alloc_private_input("cond")).collect())
        .collect();
    let alive: Vec<Vec<ExprId>> = (0..lf)
        .map(|_| (0..total).map(|_| b.alloc_private_input("alive")).collect())
        .collect();
    let e_inv_union: Vec<ExprId> = (0..total).map(|_| b.alloc_private_input("e_inv_u")).collect();
    let e_inv_batch: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("e_inv_batch")).collect();
    let de_inv_union: Vec<ExprId> =
        (0..total - 1).map(|_| b.alloc_private_input("de_inv_u")).collect();

    // ── Stage 1: commit bindings (as the SortedCopy leaf) ──
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let fam = CommitFamily::GreenwaldKhanna;
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

    // ── Stage 3: well-formed committed inputs + union multiset ──
    // Batch rows (v,0,0,0,0,t) with zero pads; init pads zero. The union
    // range checks of the SortedCopy leaf move here, onto the committed rows
    // the union permutes: init fields (e 22-bit, g₁ g₂ Δ₁ Δ₂ t 24-bit) and
    // batch e (22-bit); batch g/Δ are pinned to 0 and batch t is bound by
    // Stage 10 to N_{t-1}+1+j ≤ N_t < 2^24 (or 0).
    for j in 0..m {
        b.connect(batch_f[2 * j][1], zero);
        b.connect(batch_f[2 * j][2], zero);
        b.connect(batch_f[2 * j][3], zero);
        b.connect(batch_f[2 * j + 1][0], zero);
        b.connect(batch_f[2 * j + 1][2], zero);
        b.connect(batch_f[2 * j + 1][3], zero);
        if chk.init_ranges {
            let _ = b.add_range_bits::<Val>(batch_f[2 * j][0], E_BITS).expect("batch e range");
        }
    }
    for i in 0..cap {
        let f = fld6(&init_f, i);
        if chk.init_ranges {
            let _ = b.add_range_bits::<Val>(f[0], E_BITS).expect("init e range");
            for (k, what) in [(1, "init g₁"), (2, "init g₂"), (3, "init Δ₁"), (4, "init Δ₂"), (5, "init t")] {
                let _ = b.add_range_bits::<Val>(f[k], MASS_BITS).expect(what);
            }
        }
        // No init row arrives after N_{t-1} (review G1-minor): `N_{t-1} − t ∈
        // [0, 2^24)`. A dead init row is the canonical dummy (`t = 0`, the
        // Stage-4 pin on its union image), so this is `α_init·(N_{t-1} − t)
        // ∈ [0, 2^24)` without the α; with `t, N_{t-1} < 2^24` a wrap is
        // impossible.
        if chk.init_t_le_n_prev {
            let slack = b.sub(n_prev_pi, f[5]);
            let _ = b.add_range_bits::<Val>(slack, MASS_BITS).expect("init t ≤ N_{t-1}");
        }
    }
    let mut combined: Vec<ExprId> = Vec::with_capacity(2 * total);
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
    let union_perm = b
        .add_permute(&combined, (0..combined.len()).collect::<Vec<_>>())
        .expect("permute union");
    for i in 0..2 * total {
        b.connect(union_perm[i], union_raw_packed[i]);
    }

    // ── Stage 4: union source binding, (e,t) order, liveness ──
    if chk.union_source {
        for r in 0..total {
            bind_output_pair(&mut b, &uraw_f, r, 0);
        }
    }
    if chk.union_order {
        for r in 0..total - 1 {
            let diff = b.sub(uraw_f[2 * (r + 1)][0], uraw_f[2 * r][0]);
            let _ = b.add_range_bits::<Val>(diff, E_BITS).expect("union e sortedness");
            let nz = force_nz(&mut b, diff, de_inv_union[r], one, zero);
            let is_de_zero = b.sub(one, nz);
            let dt = b.sub(uraw_f[2 * (r + 1) + 1][1], uraw_f[2 * r + 1][1]);
            let w = b.mul(is_de_zero, dt);
            let _ = b.add_range_bits::<Val>(w, MASS_BITS).expect("union t tiebreak");
        }
    }
    // α⁰_r = [e_r ≠ E_MAX]: a prefix (e ≤ E_MAX and sorted). Dead union rows
    // must be the canonical dummy (E_MAX, 0…0): the final masks them, so a
    // poisoned dummy would otherwise drop out silently.
    let mut alive_in: Vec<ExprId> = Vec::with_capacity(total);
    for r in 0..total {
        let f = fld6b(&uraw_f, r);
        let de = b.sub(e_max, f[0]);
        let a0 = force_nz(&mut b, de, e_inv_union[r], one, zero);
        if chk.dead_union_canonical {
            let dead = b.sub(one, a0);
            for k in 1..6 {
                let z = b.mul(f[k], dead);
                b.connect(z, zero);
            }
        }
        alive_in.push(a0);
    }
    // N_{t-1}, N_t < 2^24: bounds every fresh t = N_{t-1}+1+j ≤ N_t (Stage 10).
    if chk.n_ranges {
        let _ = b.add_range_bits::<Val>(n_prev_pi, MASS_BITS).expect("N_{t-1} range");
        let _ = b.add_range_bits::<Val>(n_t_pi, MASS_BITS).expect("N_t range");
    }
    // #active(B_t) = Σ [batch.e ≠ E_MAX].
    let mut count_batch = zero;
    let mut batch_act: Vec<ExprId> = Vec::with_capacity(m);
    for j in 0..m {
        let dj = b.sub(e_max, batch_f[2 * j][0]);
        let actj = force_nz(&mut b, dj, e_inv_batch[j], one, zero);
        count_batch = b.add(count_batch, actj);
        batch_act.push(actj);
    }

    // ── Stage 5: is_fresh + two-sided neighbour-init ──
    // is_fresh_r = [N_{t-1}+1 ≤ t_r]; Σ is_fresh = #active(B_t), so no init row
    // carries t > N_{t-1} (dead rows have t = 0, fresh rows t > N_{t-1}).
    let mut fresh_count = zero;
    for r in 0..total {
        let dm1 = b.sub(n_prev_pi, uraw_f[2 * r + 1][1]); // (N_{t-1}+1) − t − 1
        force_le_dm1(&mut b, is_fresh[r], dm1, one, two, MASS_BITS, chk.fresh_bool, chk.fresh_range);
        fresh_count = b.add(fresh_count, is_fresh[r]);
    }
    if chk.fresh_count {
        b.connect(fresh_count, count_batch);
    }
    let mut d1: Vec<ExprId> = vec![zero; total];
    for r in (0..total).rev() {
        let base = if r + 1 < total { b.add(uraw_f[2 * (r + 1)][1], d1[r + 1]) } else { zero };
        let f_part = b.mul(is_fresh[r], base);
        let omf = b.sub(one, is_fresh[r]);
        let o_part = b.mul(omf, fld6b(&uraw_f, r)[3]);
        d1[r] = b.add(f_part, o_part);
    }
    let mut d2: Vec<ExprId> = vec![zero; total];
    for r in 0..total {
        let base = if r >= 1 { b.add(uraw_f[2 * (r - 1)][2], d2[r - 1]) } else { zero };
        let f_part = b.mul(is_fresh[r], base);
        let omf = b.sub(one, is_fresh[r]);
        let o_part = b.mul(omf, uraw_f[2 * r + 1][0]);
        d2[r] = b.add(f_part, o_part);
    }
    let mut cur: Vec<[ExprId; 6]> = (0..total)
        .map(|r| [uraw_f[2 * r][0], uraw_f[2 * r][1], uraw_f[2 * r][2], d1[r], d2[r], uraw_f[2 * r + 1][1]])
        .collect();

    // ── Stage 6: L_f rounds — selected test, survivor update, stable compaction ──
    let tail: Vec<ExprId> = (0..total)
        .map(|i| b.alloc_const(Challenge::from_u64((total - 1 - i) as u64), "tail_offset"))
        .collect();
    for round in 0..lf {
        let k_op = round + 1;
        let mut emitted: Vec<[ExprId; 6]> = cur.clone();
        let mut sflag: Vec<ExprId> = alive_in.clone();
        for j in 0..num_pairs {
            let a = cur[2 * j];
            let bb = cur[2 * j + 1];
            let (al_a, al_b) = (alive_in[2 * j], alive_in[2 * j + 1]);
            // lt = [a.t > b.t] = [b.t + 1 ≤ a.t]
            let dm1t = b.sub(bb[5], a[5]);
            force_le_dm1(&mut b, lt[round][j], dm1t, one, two, MASS_BITS, chk.lt_bool, chk.lt_range);
            // cond = [S ≤ θ], S = g₂ₐ + g₁_b + sel(lt; g₁ₐ, g₂_b) + sel(lt; Δ₁_b, Δ₂ₐ) + 1
            let c = b.add(a[2], bb[1]);
            let dg = b.sub(a[1], bb[2]);
            let selg = b.mul_add(lt[round][j], dg, bb[2]);
            let mprime = b.add(c, selg);
            let dd = b.sub(bb[3], a[4]);
            let seld = b.mul_add(lt[round][j], dd, a[4]);
            let u = b.add(mprime, seld);
            // S − 1 − θ, gated by α_b: a dead b never merges (merge = cond·α_b),
            // and its STALE fields may double-count mass the survivor already
            // absorbed (S up to ≈ 2·N_t + θ), which the 24-bit test could not
            // hold for N_t ≥ 2^23; gated, a dead b forces cond = 0 instead.
            // With α_b = 1 both rows are live (α is a prefix), their masses
            // are disjoint, `S ≤ N_t + θ`, and every operand is < 2^26 ≪ p.
            let dm1c_raw = b.sub(u, theta_pi);
            let dm1c = b.mul(dm1c_raw, al_b);
            force_le_dm1(&mut b, cond[round][j], dm1c, one, two, MASS_BITS, chk.cond_bool, chk.cond_range);
            // merge only a live b (α is a prefix, so then a is live too)
            let merge = b.mul(cond[round][j], al_b);
            let dir1 = b.mul(lt[round][j], merge);
            let dir2 = b.sub(merge, dir1);
            sflag[2 * j] = b.sub(al_a, dir1);
            sflag[2 * j + 1] = b.sub(al_b, dir2);
            // shared survivor mass M = mprime + 1
            let mnew = b.add(mprime, one);
            let ub = b.sub(mnew, bb[1]);
            emitted[2 * j + 1][1] = b.mul_add(dir1, ub, bb[1]);
            let ua = b.sub(mnew, a[2]);
            emitted[2 * j][2] = b.mul_add(dir2, ua, a[2]);
        }
        // destinations: ρ' runs from B(k,0,0); dest_lo_i = ρ'_i + (1−sflag_i)·(T−1−i)
        let base_lo = b.alloc_const(Challenge::from_u64(bind_coord(k_op, 0, 0)), "dest_base_lo");
        let gap = b.alloc_const(
            Challenge::from_u64(bind_coord(k_op, 1, 0) - bind_coord(k_op, 0, 0)),
            "dest_gap",
        );
        let mut rho = base_lo;
        let mut emit_packed: Vec<ExprId> = Vec::with_capacity(2 * total);
        for i in 0..total {
            let v = emitted[i];
            let omsf = b.sub(one, sflag[i]);
            let dest_lo = b.mul_add(omsf, tail[i], rho);
            let lo_coord = if chk.live_carry { b.mul_add(sflag[i], live_c, dest_lo) } else { dest_lo };
            let hi_coord = b.add(dest_lo, gap);
            let lo = b
                .recompose_base_coeffs_to_ext::<Val>(&[v[0], v[1], v[2], lo_coord])
                .expect("emit lo");
            let hi = b
                .recompose_base_coeffs_to_ext::<Val>(&[v[4], v[5], v[3], hi_coord])
                .expect("emit hi");
            emit_packed.push(lo);
            emit_packed.push(hi);
            if i + 1 < total {
                rho = b.add(rho, sflag[i]);
            }
        }
        let perm = b
            .add_permute(&emit_packed, (0..emit_packed.len()).collect::<Vec<_>>())
            .expect("permute stable compaction");
        for i in 0..2 * total {
            b.connect(perm[i], out_packed[round][i]);
        }
        let out_f: Vec<Vec<ExprId>> = out_packed[round].iter().map(|&p| dec(&mut b, p)).collect();
        for p in 0..total {
            let al = alive[round][p];
            if chk.alive_bool {
                b.assert_bool(al);
            }
            if chk.out_pos_pins {
                let c_lo = b.alloc_const(Challenge::from_u64(bind_coord(k_op, 0, p)), "out_lo");
                let c_hi = b.alloc_const(Challenge::from_u64(bind_coord(k_op, 1, p)), "out_hi");
                let want_lo = if chk.live_carry { b.mul_add(al, live_c, c_lo) } else { c_lo };
                b.connect(out_f[2 * p][3], want_lo);
                b.connect(out_f[2 * p + 1][3], c_hi);
            }
        }
        cur = (0..total).map(|p| fld6b(&out_f, p)).collect();
        alive_in = alive[round].clone();
    }

    // ── Stage 7: final = α^L ⊙ R^L on the first cap rows; α^L_cap = 0 ──
    let mut mass = zero;
    let mut count = zero;
    for i in 0..cap {
        let f = cur[i];
        let al = alive_in[i];
        let em = b.sub(f[0], e_max);
        let fe = b.mul_add(al, em, e_max);
        let fg1 = b.mul(al, f[1]);
        let fg2 = b.mul(al, f[2]);
        let fd1 = b.mul(al, f[3]);
        let fd2 = b.mul(al, f[4]);
        let ft = b.mul(al, f[5]);
        if chk.final_bind {
            b.connect(final_f[2 * i][0], fe);
            b.connect(final_f[2 * i][1], fg1);
            b.connect(final_f[2 * i][2], fg2);
            b.connect(final_f[2 * i][3], fd1);
            b.connect(final_f[2 * i + 1][0], fd2);
            b.connect(final_f[2 * i + 1][1], ft);
            b.connect(final_f[2 * i + 1][2], zero);
            b.connect(final_f[2 * i + 1][3], zero);
        }
        // ── Stage 8 (mass): Σ α(g₁+g₂+1) = N_t ──
        let gg = b.add(fg1, fg2);
        mass = b.add(mass, gg);
        count = b.add(count, al);
    }
    // Capacity: the live rows are a prefix, so α^L_cap = 0 ⟺ #survivors ≤ cap.
    if chk.alive_cap {
        b.connect(alive_in[cap], zero);
    }
    if chk.mass {
        mass = b.add(mass, count);
        b.connect(mass, n_t_pi);
    }
    if chk.n_count {
        let np_plus_b = b.add(n_prev_pi, count_batch);
        b.connect(np_plus_b, n_t_pi);
    }
    // ── Stage 9: θ = ⌊N_t/s⌋ ── Stage 10: arrival positions ──
    if chk.theta {
        bind_theta::<Val, Challenge>(&mut b, theta_pi, n_t_pi, params.s);
    }
    if chk.arrivals {
        let batch_t: Vec<ExprId> = (0..m).map(|j| batch_f[2 * j + 1][1]).collect();
        bind_arrival_positions(&mut b, &batch_t, &batch_act, n_prev_pi, one, zero);
    }

    let circuit = b.build().expect("build gkb2 stable circuit");

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
    crate::experiments::table_probe::record_leaf(
        "gk_bandmerge2_stable",
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

    Gkb2LeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        table_rows,
        pair_bind: true,
        expose,
        mode,
        batch_index: 1,
        rounds: GkRounds::StableCompact,
        stable_checks: chk,
    }
}

impl Gkb2LeafCircuit {
    /// Prove one epoch on the prebuilt circuit (`Plain` circuits only, see
    /// [`Self::prove_epoch_at`]).
    pub fn prove_epoch(&mut self, initial_state: Gk2State, batch_vals: Vec<u32>) -> Gk2LeafProof {
        self.prove_epoch_at(1, initial_state, batch_vals)
    }

    /// The statement this leaf exposes ([`Expose`]).
    pub fn expose(&self) -> Expose {
        self.expose
    }

    /// The commitment mode the circuit was built with.
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }

    /// The VK (preprocessed commitment, `expose_forest::vk_pin_values` order)
    /// of every proof this prebuilt leaf produces, read from its prover data
    /// (public parameters only, no proving).
    pub fn vk_pin_values(&self) -> Vec<Challenge> {
        crate::recursion::recursive::expose_forest::common_vk_pin_values(
            self.circuit_prover_data.common_data(),
        )
    }

    /// The round certification this leaf was built with ([`GkRounds`]).
    pub fn rounds(&self) -> GkRounds {
        self.rounds
    }

    /// `Σ 2^degree` over all tables.
    pub fn trace_rows(&self) -> u64 {
        self.trace_rows
    }
    /// Padded height of each table (AIR order).
    pub fn table_rows(&self) -> &[usize] {
        &self.table_rows
    }

    /// Prove the epoch of batch `t` (1-based); `t` is part of the Interval
    /// statement (ignored by the other layouts). `Plain` circuits only: on a
    /// `Hiding` circuit this would open every commitment with the public zero
    /// salt, so it panics; use [`Self::prove_epoch_commit`] (or, for the no-op
    /// leaf, [`Self::prove_epoch_public_zero`]).
    pub fn prove_epoch_at(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
    ) -> Gk2LeafProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             Openings::for_leaf(..)"
        );
        self.prove_epoch_opened(t, initial_state, batch_vals, &Openings::plain())
    }

    /// [`Self::prove_epoch_at`] with the commitment openings of leaf `t`
    /// (`Openings::for_leaf(seed, CommitFamily::GreenwaldKhanna, t)` for an
    /// honest prover; ignored by a `Plain` circuit). The proof's `initial`,
    /// `final_` and `batch_commit` are then `Com(S_{t-1}; ρ^S_{t-1})`,
    /// `Com(S_t; ρ^S_t)` and `Com(B_t; ρ^B_t)` (the batch commitment still over
    /// the fresh tuples at `n_prev = N_{t-1}`). A `Hiding` circuit panics when
    /// `openings.final_` or `openings.batch` is the public zero salt (never an
    /// honest PRF output): a forgotten opening would otherwise give a
    /// consistent, deterministic chain that nothing downstream detects. The
    /// init salt may be zero only at `t = 1` on the empty genesis state (leaf 1
    /// of the genesis history opens the public `Com(S_0; 0)`); a zero init on
    /// any other input panics
    /// ([`assert_zero_init_opens_public_state`](crate::commitment::hiding::assert_zero_init_opens_public_state)).
    pub fn prove_epoch_commit(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        openings: &Openings,
    ) -> Gk2LeafProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (Openings::for_leaf), not the public zero salt"
            );
            crate::commitment::hiding::assert_zero_init_opens_public_state(t, openings.init.is_zero(), || {
                initial_state == Gk2State::empty(self.params)
            });
        }
        self.prove_epoch_opened(t, initial_state, batch_vals, openings)
    }

    /// The no-op VK-derivation leaf's epoch: all three commitments opened
    /// with [`Openings::public_zero`], so a batch that changes nothing
    /// exposes `init == final` in either mode. The only path that proves a
    /// `Hiding` leaf with zero final/batch salts, so it accepts exactly the
    /// VK-derivation leaf's input
    /// ([`gk2_noop_leaf_commit`](crate::recursion::recursive::noop_leaf::gk2_noop_leaf_commit)):
    /// batch index `t = 1`, the EMPTY initial state (whose `Com(S_0; 0)` the
    /// verifier recomputes itself) and an empty batch (the GK no-op: every
    /// fresh-tuple row is an `E_MAX` dummy and `N` does not move); it also
    /// checks that the native final state equals the initial one. A real
    /// state with an empty batch does not move either, so without the
    /// empty-state check it would publish the deterministic, guess-checkable
    /// `Com(S_t; 0)` as both init and final; it cannot publish a real
    /// state, a real batch or a moved state under deterministic commitments.
    pub fn prove_epoch_public_zero(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
    ) -> Gk2LeafProof {
        assert_eq!(t, 1, "prove_epoch_public_zero is for the no-op leaf: it is proved at batch index 1");
        assert!(
            batch_vals.is_empty(),
            "prove_epoch_public_zero is for the no-op leaf: the batch must be empty"
        );
        assert!(
            initial_state == Gk2State::empty(self.params),
            "prove_epoch_public_zero is for the no-op leaf: the initial state must be the empty genesis \
             state (a real state would publish the guess-checkable Com(S; 0))"
        );
        let build = self.native_build(t, &initial_state, &batch_vals);
        assert!(
            build.final_tuples == initial_state.tuples && build.n_t == initial_state.n,
            "prove_epoch_public_zero is for the no-op leaf: the state must not move"
        );
        self.prove_build_opened(initial_state, batch_vals, &build, &Openings::public_zero())
    }

    /// Native side of one epoch: shape checks and the honest band-merge
    /// replay (sets the batch index `t` of the proof).
    fn native_build(&mut self, t: u64, initial_state: &Gk2State, batch_vals: &[u32]) -> Bm2Build {
        self.batch_index = t;
        let params = self.params;
        assert!(batch_vals.len() <= params.batch);
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        assert_eq!(total % 2, 0, "total = cap+m must be even");

        // ── Native replay ──
        let build = build_bm2(initial_state, batch_vals);
        // A capacity overflow is a hard error (G-cap) under both variants:
        // neither circuit can prove it (SortedCopy pins its excess rows to
        // dummies; StableCompact pins `α^L_cap = 0` and the mass), and the
        // caller must see a failed run (the panic names the capacity, so the
        // harness records `too_large`), not a dropped survivor or a witness
        // conflict. Tests may lift it to show the circuit's own rejection.
        if !allow_overflow_for_test() {
            if let Some(e) = build.capacity_error(params) {
                panic!("{e}");
            }
        }
        build
    }

    /// Shared body of the `prove_epoch_*` entry points (no opening checks).
    fn prove_epoch_opened(
        &mut self,
        t: u64,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        openings: &Openings,
    ) -> Gk2LeafProof {
        let build = self.native_build(t, &initial_state, &batch_vals);
        self.prove_build_opened(initial_state, batch_vals, &build, openings)
    }

    /// Pack a (honest or hand-crafted) band-merge witness, install its permute
    /// hints, run, prove and self-verify, under Plain commitments (the
    /// forgery PoCs' path; `Plain` circuits only).
    #[cfg(test)]
    fn prove_build(
        &mut self,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        build: &Bm2Build,
    ) -> Gk2LeafProof {
        assert!(
            !self.mode.is_hiding(),
            "prove_build opens every commitment with the public zero salt: Plain leaves only"
        );
        self.prove_build_opened(initial_state, batch_vals, build, &Openings::plain())
    }

    /// Run the circuit on a packed witness (test-only: the B2 row-overhead
    /// test reads the logical trace heights before any proof).
    #[cfg(test)]
    fn run_epoch_commit(
        &mut self,
        t: u64,
        initial_state: &Gk2State,
        batch_vals: &[u32],
        openings: &Openings,
    ) -> p3_circuit::tables::Traces<Challenge> {
        let build = self.native_build(t, initial_state, batch_vals);
        let w = self.pack_opened(initial_state, batch_vals, &build, openings);
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&w.public_inputs).expect("set pub");
        runner.set_private_inputs(&w.private_inputs).expect("set priv");
        runner.run().expect("run gkb2 circuit")
    }

    /// Pack a (honest or hand-crafted) band-merge witness under explicit
    /// commitment openings (`openings` ignored under `Plain`), install its
    /// permute hints, run, prove and self-verify.
    fn prove_build_opened(
        &mut self,
        initial_state: Gk2State,
        batch_vals: Vec<u32>,
        build: &Bm2Build,
        openings: &Openings,
    ) -> Gk2LeafProof {
        let params = self.params;
        let Gk2Witness { public_inputs, private_inputs, initial_commit, final_commit, batch_commit } =
            self.pack_opened(&initial_state, &batch_vals, build, openings);

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

    /// The three public commitments of an epoch (under `self.mode` and
    /// `openings`), its permute hints swapped into the prebuilt graph, and the
    /// runner inputs. Under `Hiding` the 9 salt Challenges come first in the
    /// private inputs (see [`build_gkb2_leaf_commit`]).
    fn pack_opened(
        &mut self,
        initial_state: &Gk2State,
        batch_vals: &[u32],
        build: &Bm2Build,
        openings: &Openings,
    ) -> Gk2Witness {
        if self.rounds == GkRounds::StableCompact {
            return self.pack_opened_stable(initial_state, batch_vals, build, openings);
        }
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
        // The committed batch table (the fresh rows fed to the union).
        let fresh = leaf_fresh_rows(batch_vals, m, build.n_prev);
        let initial_commit = commit_gk2_state_with(initial_state, mode, &openings.init);
        let final_commit = commit_gk2_state_with(&final_state, mode, &openings.final_);
        let batch_commit = commit_gk2_rows_with(&fresh, mode, &openings.batch);
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
        if mode.is_hiding() {
            // The salts come first (see `build_gkb2_leaf_commit`).
            private_inputs.extend(openings.private_inputs());
        }
        private_inputs.extend_from_slice(&pack_tuples2(&initial_state.tuples));
        private_inputs.extend_from_slice(&pack_tuples2(&final_state.tuples));
        private_inputs.extend_from_slice(&pack_tuples2(&fresh));
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

        Gk2Witness { public_inputs, private_inputs, initial_commit, final_commit, batch_commit }
    }
}

impl Gkb2LeafCircuit {
    /// [`Self::pack_opened`] for a `StableCompact` leaf: replays the rounds as
    /// stable compactions ([`stable_rounds`]) from the same union, asserts the
    /// masked final equals the bm2 replay's (`finish_bm2`), and packs the
    /// stable witness in [`build_gkb2_leaf_stable`]'s allocation order.
    fn pack_opened_stable(
        &mut self,
        initial_state: &Gk2State,
        batch_vals: &[u32],
        build: &Bm2Build,
        openings: &Openings,
    ) -> Gk2Witness {
        use p3_field::Field;
        let params = self.params;
        let cap = params.capacity;
        let m = params.batch;
        let total = cap + m;
        let sb = stable_rounds(&build.union_init, build.theta, cap);
        if sb.survivors <= cap {
            assert!(
                sb.final_tuples == build.final_tuples,
                "G1 stable-compaction replay diverged from the bm2 replay (finish_bm2)"
            );
        }
        let final_state = Gk2State {
            tuples: sb.final_tuples.clone(),
            params,
            n: build.n_t,
        };
        let mode = self.mode;
        let fresh = leaf_fresh_rows(batch_vals, m, build.n_prev);
        let initial_commit = commit_gk2_state_with(initial_state, mode, &openings.init);
        let final_commit = commit_gk2_state_with(&final_state, mode, &openings.final_);
        let batch_commit = commit_gk2_rows_with(&fresh, mode, &openings.batch);
        let lf = num_rounds(total);
        assert_eq!(sb.rounds.len(), lf);

        // Permute hints: the union sort, then each round's compaction.
        let mut sigmas: Vec<Vec<usize>> = Vec::with_capacity(1 + lf);
        sigmas.push(build.sigma_union_chal.clone());
        for rd in &sb.rounds {
            sigmas.push(expand_sigma(&rd.src));
        }
        self.circuit
            .update_permute_witnesses(&sigmas)
            .expect("update permute witnesses (gkb2 stable)");

        let pack = |c: &Gk2StateCommit| pack_commit_to_challenge(&crate::commitment::CountMinCommit(c.0));
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&pack(&initial_commit));
        public_inputs.extend_from_slice(&pack(&final_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&crate::commitment::CountMinCommit(
            batch_commit.0,
        )));
        public_inputs.push(Challenge::from_u64(build.theta));
        let n_prev_pub = {
            #[allow(unused_mut)]
            let mut v = build.n_prev;
            #[cfg(test)]
            if let Some(t) = TAMPER_NPREV.with(|c| c.get()) {
                v = t;
            }
            v
        };
        public_inputs.push(Challenge::from_u64(n_prev_pub));
        public_inputs.push(Challenge::from_u64(build.n_t));
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(self.batch_index));
        }

        let inv = |x: u64| if x == 0 { Challenge::ZERO } else { Challenge::from_u64(x).inverse() };
        let bit = |x: u8| if x == 1 { Challenge::ONE } else { Challenge::ZERO };
        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            private_inputs.extend(openings.private_inputs());
        }
        private_inputs.extend_from_slice(&pack_tuples2(&initial_state.tuples));
        private_inputs.extend_from_slice(&pack_tuples2(&final_state.tuples));
        private_inputs.extend_from_slice(&pack_tuples2(&fresh));
        let src_lo: Vec<usize> = (0..total).map(|r| build.sigma_union_chal[2 * r] / 2).collect();
        let src_hi: Vec<usize> = (0..total).map(|r| build.sigma_union_chal[2 * r + 1] / 2).collect();
        private_inputs.extend_from_slice(&pack_bound2(&build.union_raw, 0, &src_lo, &src_hi));
        for (round, rd) in sb.rounds.iter().enumerate() {
            private_inputs.extend_from_slice(&pack_stable_out(
                &rd.out,
                round + 1,
                &rd.alive,
                self.stable_checks.live_carry,
            ));
        }
        for r in 0..total {
            let t = &build.union_raw[r];
            private_inputs.push(bit((t.t > build.n_prev) as u8));
        }
        for rd in &sb.rounds {
            private_inputs.extend(rd.lt.iter().map(|&x| bit(x)));
        }
        for rd in &sb.rounds {
            private_inputs.extend(rd.cond.iter().map(|&x| bit(x)));
        }
        for rd in &sb.rounds {
            private_inputs.extend(rd.alive.iter().map(|&x| bit(x)));
        }
        for r in 0..total {
            private_inputs.push(inv((E_MAX - build.union_raw[r].e) as u64));
        }
        for j in 0..m {
            private_inputs.push(inv((E_MAX - fresh[j].e) as u64));
        }
        for r in 0..total - 1 {
            private_inputs.push(inv((build.union_raw[r + 1].e - build.union_raw[r].e) as u64));
        }

        Gk2Witness { public_inputs, private_inputs, initial_commit, final_commit, batch_commit }
    }
}

/// Runner inputs and public commitments of one packed band-merge epoch.
struct Gk2Witness {
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    initial_commit: Gk2StateCommit,
    final_commit: Gk2StateCommit,
    batch_commit: Gk2BatchCommit,
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

/// [`prove_gkb2_interval`] with an explicit [`CommitMode`] and the openings
/// of leaf `t` (process default [`Binding`]). Under `Hiding`, zero
/// final/batch salts panic ([`Gkb2LeafCircuit::prove_epoch_commit`]).
pub fn prove_gkb2_interval_commit(
    params: GkbParams,
    t: u64,
    initial_state: Gk2State,
    batch_vals: Vec<u32>,
    mode: CommitMode,
    openings: &Openings,
) -> Gk2LeafProof {
    build_gkb2_leaf_commit(params, Expose::Interval, bind::default_binding(), mode)
        .prove_epoch_commit(t, initial_state, batch_vals, openings)
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

    // ─── Arrival positions (fresh-row t binding, 2026-10-11) ───────────────

    /// A band-merge witness over hand-picked fresh rows `rows` (honestly
    /// `fresh_tuples2(batch, m, s_old.n)`): the `(e,t)`-sorted union of
    /// `s_old ‖ rows`, then neighbor-init, the `L_f` fusion rounds and the
    /// compaction replayed natively, so every hint is consistent with the
    /// rows. `N_t = N_{t-1} + #active(rows)` and `θ = ⌊N_t/s⌋` are honest.
    fn forge_arrivals(s_old: &Gk2State, rows: &[Gk2Tuple]) -> Bm2Build {
        let n_prev = s_old.n;
        let n_t = n_prev + rows.iter().filter(|r| r.active == 1).count() as u64;
        let mut combined = s_old.tuples.clone();
        combined.extend_from_slice(rows);
        let mut idx: Vec<usize> = (0..combined.len()).collect();
        idx.sort_by_key(|&i| (combined[i].e, combined[i].t));
        let union_raw: Vec<Gk2Tuple> = idx.iter().map(|&i| combined[i]).collect();
        let chal = expand_sigma(&idx);
        finish_bm2(s_old, idx, chal, union_raw, n_prev, n_t, n_t / s_old.params.s)
    }

    /// Prove `build` on `leaf` with `rows` as the committed batch table
    /// (`Com(B_t)` over `rows`, which feed the union).
    fn prove_with_rows(
        leaf: &mut Gkb2LeafCircuit,
        s_old: &Gk2State,
        batch: &[u32],
        rows: &[Gk2Tuple],
        build: &Bm2Build,
    ) -> Result<Gk2LeafProof, String> {
        TAMPER_FRESH.with(|c| *c.borrow_mut() = Some(rows.to_vec()));
        let r = crate::sketch::forge::catch_msg(|| leaf.prove_build(s_old.clone(), batch.to_vec(), build));
        TAMPER_FRESH.with(|c| *c.borrow_mut() = None);
        r
    }

    /// One epoch of the arrival-position PoCs: `S_1` (after `B_1`), the
    /// honest fresh rows and build of `B_2`, and the forged `(name, rows,
    /// build)` of the four forgeries.
    struct ArrivalPoc {
        params: GkbParams,
        s1: Gk2State,
        b2: Vec<u32>,
        stream: Vec<u32>,
        honest_rows: Vec<Gk2Tuple>,
        honest: Bm2Build,
        cases: Vec<(&'static str, Vec<Gk2Tuple>, Bm2Build)>,
    }

    /// The arrival-position forgeries of one epoch at accuracy `s` (same
    /// values, honest `N_t` and `θ`, every hint replayed under the forged
    /// rows), or `None` unless each is visible: permuted and stale move
    /// `S_t`, gap leaves a survivor of `S_t` arriving after `N_t`.
    fn arrival_poc(s: u64) -> Option<ArrivalPoc> {
        let params = GkbParams {
            capacity: 16,
            batch: 8,
            s,
        };
        let m = params.batch;
        let b1: Vec<u32> = vec![100, 400, 200, 700, 300, 600, 500, 800];
        // Six values (batch rows 6 and 7 are E_MAX dummies), all above S_1's,
        // so fresh rows meet each other in the fusion pairs and the newer
        // one of a pair is decided by arrival position alone.
        let b2: Vec<u32> = vec![1000, 900, 1200, 1100, 1300, 850];
        let k = b2.len();
        let s1 = apply_batch2(&Gk2State::empty(params), &b1);
        let n_prev = s1.n;
        let honest_rows = fresh_tuples2(&b2, m, n_prev);
        let honest = build_bm2(&s1, &b2);
        assert_eq!(
            forge_arrivals(&s1, &honest_rows).final_tuples,
            honest.final_tuples,
            "the forging replay reproduces the honest build"
        );
        let stream: Vec<u32> = b1.iter().chain(b2.iter()).copied().collect();
        let fits = |f: &Bm2Build| f.excess.iter().all(|t| t.active == 0);
        let moved = |rows: &[Gk2Tuple]| -> Option<Bm2Build> {
            let f = forge_arrivals(&s1, rows);
            (f.final_tuples != honest.final_tuples && fits(&f)).then_some(f)
        };
        // permuted: two arrival positions swapped.
        let permuted = (0..k)
            .flat_map(|i| (i + 1..k).map(move |j| (i, j)))
            .find_map(|(i, j)| {
                let mut rows = honest_rows.clone();
                let (ti, tj) = (rows[i].t, rows[j].t);
                rows[i].t = tj;
                rows[j].t = ti;
                moved(&rows).map(|f| (rows, f))
            })?;
        // stale: a fresh value at an old timestamp t ≤ N_{t-1} (the most
        // semantic damage, if any).
        let stale = (0..k)
            .flat_map(|j| (1..=n_prev).map(move |t| (j, t)))
            .filter_map(|(j, t)| {
                let mut rows = honest_rows.clone();
                rows[j].t = t;
                moved(&rows).map(|f| {
                    let st = Gk2State {
                        tuples: f.final_tuples.clone(),
                        params,
                        n: f.n_t,
                    };
                    let d = semantic_damage(&st, &stream);
                    (d.0 + d.1, rows, f)
                })
            })
            .max_by_key(|(d, _, _)| *d)
            .map(|(_, rows, f)| (rows, f))?;
        // gap: the values keep their order, each at N_{t-1} + 1 + j, but the
        // two dummies sit among them, leaving a survivor arriving after N_t.
        let gap = (0..m)
            .flat_map(|x| (x + 1..m).map(move |y| (x, y)))
            .find_map(|(x, y)| {
                let mut rows = vec![Gk2Tuple::dummy(); m];
                let mut vals = honest_rows[..k].iter();
                for j in (0..m).filter(|&j| j != x && j != y) {
                    rows[j] = *vals.next().expect("k values");
                    rows[j].t = n_prev + 1 + j as u64;
                }
                let f = forge_arrivals(&s1, &rows);
                let late = f.final_tuples.iter().any(|t| t.active == 1 && t.t > f.n_t);
                (late && fits(&f)).then_some((rows, f))
            })?;
        // dummy t: a padding row with t ∈ [1, N_{t-1}] (the is_fresh gate
        // reads t alone, so a larger dummy t would need the hint set to 1).
        let dummy_t = {
            let mut rows = honest_rows.clone();
            rows[m - 1].t = 1;
            let f = forge_arrivals(&s1, &rows);
            fits(&f).then_some((rows, f))?
        };
        let cases = vec![
            ("permuted", permuted.0, permuted.1),
            ("stale", stale.0, stale.1),
            ("gap", gap.0, gap.1),
            ("dummy t", dummy_t.0, dummy_t.1),
        ];
        Some(ArrivalPoc {
            params,
            s1,
            b2,
            stream,
            honest_rows,
            honest,
            cases,
        })
    }

    /// **Forged arrival positions PoC.** A fresh row's timestamp picks the
    /// newer tuple of a fused pair (so which fusion test applies) and gates
    /// neighbor-init, but it was set only natively (`fresh_tuples2`: `t =
    /// N_{t-1} + 1 + j`) and bound only through `Com(B_t)`. A prover that
    /// commits the batch table itself forges one epoch four ways
    /// ([`arrival_poc`], at the first accuracy where each is visible):
    /// * **permuted**: two arrival positions swapped, so the leaf certifies a
    ///   different final state for the same batch values;
    /// * **stale**: a fresh value given an old timestamp `t ≤ N_{t-1}`, so it
    ///   skips neighbor-init and keeps `Δ₁ = Δ₂ = 0`;
    /// * **gap**: the dummies placed among the active rows, each value still
    ///   at `N_{t-1} + 1 + j`, so a survivor of `S_t` arrives after `N_t`
    ///   (the next epoch's `is_fresh` gate would re-initialize it as fresh);
    /// * **dummy t**: a padding row carrying `t ≠ 0` (a second accepted
    ///   `Com(B_t)` for the same batch and the same `S_t`).
    ///
    /// `Legacy` (the pre-fix circuit, byte-for-byte) ACCEPTS each, and the
    /// proof exposes the forged `Com(B_t)`. `Semantic` / `Bound`
    /// ([`bind_arrival_positions`]) reject each; the honest rows verify on the
    /// same leaf (positive control).
    #[test]
    fn gk2_forged_arrival_positions_legacy_accepts_semantic_rejects() {
        let poc = [3u64, 4, 5, 6, 8, 12, 16]
            .into_iter()
            .find_map(arrival_poc)
            .expect("an accuracy s at which every arrival forgery is visible");
        let ArrivalPoc { params, s1, b2, stream, honest_rows, honest, cases } = poc;
        let (m, n_prev) = (params.batch, s1.n);
        let state = |f: &Bm2Build| Gk2State {
            tuples: f.final_tuples.clone(),
            params,
            n: f.n_t,
        };
        println!(
            "[gk2 arrival] s={} N_(t-1)={n_prev} N_t={} θ={}; honest batch t = {:?}",
            params.s,
            honest.n_t,
            honest.theta,
            honest_rows.iter().map(|r| r.t).collect::<Vec<_>>()
        );

        let honest_bc = commit_gk2_batch(&b2, m, n_prev);
        let mut legacy = build_gkb2_leaf_expose_with(params, Expose::None, Binding::Legacy);
        for (name, rows, f) in &cases {
            let st = state(f);
            let late = st.tuples.iter().filter(|t| t.active == 1 && t.t > f.n_t).count();
            println!(
                "[gk2 arrival] {name}: batch t = {:?}; S_t moved: {}, survivors with t > N_t: {late}, \
                 damage (B2, rank) {:?} (honest {:?})",
                rows.iter().map(|r| r.t).collect::<Vec<_>>(),
                f.final_tuples != honest.final_tuples,
                semantic_damage(&st, &stream),
                semantic_damage(&state(&honest), &stream)
            );
            match prove_with_rows(&mut legacy, &s1, &b2, rows, f) {
                Ok(p) => {
                    assert_eq!(p.final_, commit_gk2_state(&st), "{name}: Legacy certifies Com(S')");
                    assert_eq!(p.batch_commit, commit_gk2_rows_with(rows, CommitMode::Plain, &SaltBb::ZERO));
                    assert_ne!(p.batch_commit, honest_bc, "{name}: the forged rows change Com(B_t)");
                    println!("[gk2 arrival] Legacy {name}: ACCEPTED (self-verified)");
                }
                Err(e) => panic!("{name}: PoC premise: the pre-fix circuit accepts it, got {e}"),
            }
        }
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = build_gkb2_leaf_expose_with(params, Expose::None, binding);
            let ok = prove_with_rows(&mut leaf, &s1, &b2, &honest_rows, &honest);
            assert!(ok.is_ok(), "{binding:?}: positive control (honest rows) must verify: {:?}", ok.err());
            assert_eq!(ok.unwrap().batch_commit, honest_bc);
            for (name, rows, f) in &cases {
                match prove_with_rows(&mut leaf, &s1, &b2, rows, f) {
                    Ok(_) => panic!("{binding:?}: the {name} arrival positions must be rejected"),
                    Err(e) => println!("[gk2 arrival] {binding:?} {name}: REJECTED: {e}"),
                }
            }
        }
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

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────

    use crate::commitment::hiding::{SaltSeed, TAG_BATCH, TAG_STATE, rho_batch_bb, rho_state_bb};
    use crate::recursion::recursive::expose_forest::{
        batch_log, check_leaves_against_log, check_root_against_log, prove_hiding_merge,
        read_exposed_statement, root_vk_deriver, verify_bound_stark_proof_against_log,
        vk_pin_values,
    };
    use crate::recursion::recursive::noop_leaf::gk2_noop_leaf_commit;
    use crate::recursion::recursive::root_vk::ForestShape;
    use crate::recursion::recursive::statement::{hash_bb, leaf_digest};
    use crate::sketch::forge;

    /// The smallest shape the GK leaf tests use (`interval_tests`).
    const HP: GkbParams = GkbParams { capacity: 4, batch: 2, s: 2 };
    const GK: CommitFamily = CommitFamily::GreenwaldKhanna;

    fn hiding_leaf(expose: Expose, binding: Binding) -> Gkb2LeafCircuit {
        build_gkb2_leaf_commit(HP, expose, binding, CommitMode::Hiding)
    }

    /// A non-empty prior state `S_{t-1}` (`N = 2`).
    fn hp_prior() -> Gk2State {
        apply_batch2(&Gk2State::empty(HP), &[5, 7])
    }

    fn hp_batches() -> Vec<Vec<u32>> {
        vec![vec![10, 11], vec![20, 21]]
    }

    fn u64s(v: &[Val]) -> Vec<u64> {
        v.iter().map(|x| <Val as p3_field::PrimeField64>::as_canonical_u64(x)).collect()
    }

    /// Flat basis coefficients of VK pin values.
    fn vk_flat(vk: &[Challenge]) -> Vec<u64> {
        vk.iter()
            .flat_map(|c| u64s(<Challenge as p3_field::BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)))
            .collect()
    }

    /// A VK recorded on the pre-B2-GK code (b2-hiding@94e9f58, GK untouched
    /// since main@7089f70): 8 base values, each the first coefficient of one
    /// pin Challenge.
    fn vk_literal(v: [u64; 8]) -> Vec<u64> {
        v.iter().flat_map(|&x| [x, 0, 0, 0]).collect()
    }

    /// Native layout drift guard: `Plain` is the old commitment whatever the
    /// salt; `Hiding` is `MyHash([TAG, 4, 0, 0, ρ…] ‖ flat)` with `TAG_STATE`
    /// for a state and `TAG_BATCH` for a batch (whose fresh tuples still
    /// depend on `n_prev`); two salts give two commitments.
    #[test]
    fn gk2_commit_with_modes() {
        let seed = SaltSeed::for_tests(9);
        let s = hp_prior();
        let (r1, r2) = (rho_state_bb(&seed, GK, 1), rho_state_bb(&seed, GK, 2));
        let hasher = MyHash::new(make_perm());
        assert_eq!(commit_gk2_state_with(&s, CommitMode::Plain, &r1), commit_gk2_state(&s));
        let h1 = commit_gk2_state_with(&s, CommitMode::Hiding, &r1);
        let mut input = vec![Val::from_u64(TAG_STATE), Val::from_u64(4), Val::ZERO, Val::ZERO];
        input.extend_from_slice(&r1.0);
        input.extend(flat_tuples2(&s.tuples));
        let want: [Val; 8] = hasher.hash_iter(input);
        assert_eq!(h1.0, want, "state layout drift");
        assert_ne!(h1, commit_gk2_state_with(&s, CommitMode::Hiding, &r2));
        assert_ne!(h1, commit_gk2_state(&s));

        let rb = rho_batch_bb(&seed, GK, 1);
        let vals = [30u32, 31];
        assert_eq!(commit_gk2_batch_with(&vals, 2, 5, CommitMode::Plain, &rb), commit_gk2_batch(&vals, 2, 5));
        let hb = commit_gk2_batch_with(&vals, 2, 5, CommitMode::Hiding, &rb);
        let mut input = vec![Val::from_u64(TAG_BATCH), Val::from_u64(4), Val::ZERO, Val::ZERO];
        input.extend_from_slice(&rb.0);
        input.extend(flat_tuples2(&fresh_tuples2(&vals, 2, 5)));
        let want: [Val; 8] = hasher.hash_iter(input);
        assert_eq!(hb.0, want, "batch layout drift");
        assert_ne!(hb, commit_gk2_batch_with(&vals, 2, 6, CommitMode::Hiding, &rb), "n_prev is bound");
        assert_ne!(hb.0, commit_gk2_state_with(
            &Gk2State { tuples: fresh_tuples2(&vals, 2, 5), params: HP, n: 0 },
            CommitMode::Hiding,
            &rb,
        ).0, "a batch commitment is never a state commitment");
    }

    /// (1) A hiding leaf's commitments (the proof's `initial / final_ /
    /// batch_commit` fields and the exposed statement) equal the NATIVE hiding
    /// commitments under the leaf-`t` openings, under every binding the leaf
    /// supports (Legacy, Semantic, Bound) and both statement layouts
    /// (Interval, Boundary).
    #[test]
    fn hiding_leaf_exposes_native_hiding_commitments() {
        let seed = SaltSeed::for_tests(21);
        let t = 3u64;
        let ups = hp_batches()[0].clone();
        let prior = hp_prior();
        let fin_state = apply_batch2(&prior, &ups);
        let o = Openings::for_leaf(&seed, GK, t);
        let init = commit_gk2_state_with(&prior, CommitMode::Hiding, &rho_state_bb(&seed, GK, t - 1));
        let fin = commit_gk2_state_with(&fin_state, CommitMode::Hiding, &rho_state_bb(&seed, GK, t));
        let bc = commit_gk2_batch_with(&ups, HP.batch, prior.n, CommitMode::Hiding, &rho_batch_bb(&seed, GK, t));
        assert_ne!(init, commit_gk2_state(&prior), "hiding != plain");
        assert_ne!(fin, commit_gk2_state(&fin_state), "hiding != plain");
        assert_ne!(bc, commit_gk2_batch(&ups, HP.batch, prior.n), "hiding != plain");
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            for expose in [Expose::Interval, Expose::Boundary] {
                let mut leaf = hiding_leaf(expose, binding);
                assert_eq!(leaf.commit_mode(), CommitMode::Hiding);
                let r = leaf.prove_epoch_commit(t, prior.clone(), ups.clone(), &o);
                assert_eq!(r.initial, init, "{binding:?}/{expose:?}");
                assert_eq!(r.final_, fin, "{binding:?}/{expose:?}");
                assert_eq!(r.batch_commit, bc, "{binding:?}/{expose:?}");
                let st = read_exposed_statement(&r.output.0);
                assert_eq!(st.init, init.0.to_vec(), "{binding:?}/{expose:?}");
                assert_eq!(st.final_, fin.0.to_vec(), "{binding:?}/{expose:?}");
                match expose {
                    Expose::Interval => {
                        let iv = st.interval.expect("interval layout");
                        assert_eq!((iv.lo, iv.hi), (Val::from_u64(t), Val::from_u64(t)));
                        assert_eq!(
                            iv.digest,
                            leaf_digest(&hash_bb, 4, t, &bc.0),
                            "{binding:?}: H(TAG_LEAF, t, Com(B_t; ρ))"
                        );
                    }
                    _ => assert!(st.interval.is_none(), "{binding:?}: boundary layout"),
                }
            }
        }
        // The one-call API (process default binding).
        let r = prove_gkb2_interval_commit(HP, t, prior.clone(), ups.clone(), CommitMode::Hiding, &o);
        assert_eq!((r.initial, r.final_, r.batch_commit), (init, fin, bc));
    }

    /// (2) The Plain circuit is the pre-B2 circuit: for every statement layout
    /// and binding its VK equals the value recorded before this change,
    /// through both the old builder and `build_gkb2_leaf_commit(.., Plain)`,
    /// and a Plain proof exposes exactly the recorded commitments and
    /// statement. The hiding leaf's VK differs from the Plain one, does not
    /// depend on the salts (two different openings give one VK) and equals
    /// the zero-salt no-op leaf's VK.
    #[test]
    fn hiding_leaf_vk_is_salt_independent_and_plain_is_unchanged() {
        // Semantic/Bound rows re-recorded 2026-10-11 for the arrival-position
        // binding (`bind_arrival_positions`, Semantic/Bound only); the Legacy
        // rows are unchanged.
        #[cfg(not(feature = "zk"))]
        let recorded = [
            (Expose::None, Binding::Legacy, [136473872, 825731566, 962898407, 309390011, 609662534, 1217038996, 1392535772, 796016774]),
            (Expose::None, Binding::Semantic, [728435930, 1729906957, 636169810, 463001289, 973894502, 1099865253, 754794833, 232237172]),
            (Expose::None, Binding::Bound, [728435930, 1729906957, 636169810, 463001289, 973894502, 1099865253, 754794833, 232237172]),
            (Expose::Boundary, Binding::Legacy, [1959253283, 1123222237, 632241315, 365030987, 1581115715, 17296396, 426616552, 1762281300]),
            (Expose::Boundary, Binding::Semantic, [453529306, 719271565, 1494408462, 1592070196, 499123786, 754865709, 1543101736, 964759909]),
            (Expose::Boundary, Binding::Bound, [453529306, 719271565, 1494408462, 1592070196, 499123786, 754865709, 1543101736, 964759909]),
            (Expose::Interval, Binding::Legacy, [1951736277, 454005402, 1529845001, 1118438533, 1534690931, 1281097441, 1099235087, 1789611541]),
            (Expose::Interval, Binding::Semantic, [497389573, 430418219, 147510905, 234651151, 1008148634, 652055197, 1594950853, 1377077060]),
            (Expose::Interval, Binding::Bound, [497389573, 430418219, 147510905, 234651151, 1008148634, 652055197, 1594950853, 1377077060]),
        ];
        // The same circuits under the `zk` feature: hiding-PCS VKs, recorded on the
        // zk-logup-mask forks (Plonky3 280b1a07, Plonky3_RangeAir 3acdc06), equal
        // across separate processes. The LogUp masks do not move them (main-trace
        // columns; see `config::tests::leaf_opens_logup_mask_columns`).
        #[cfg(feature = "zk")]
        let recorded = [
            (Expose::None, Binding::Legacy, [69744273, 1849456600, 492210391, 582955548, 1941433492, 435265109, 1275377710, 80264505]),
            (Expose::None, Binding::Semantic, [45927312, 1411203255, 1072019975, 641968451, 894852692, 1916664644, 1039726366, 1803062539]),
            (Expose::None, Binding::Bound, [45927312, 1411203255, 1072019975, 641968451, 894852692, 1916664644, 1039726366, 1803062539]),
            (Expose::Boundary, Binding::Legacy, [358448247, 1433590892, 1954585140, 1066362735, 247491272, 1456945772, 1614681218, 1076296925]),
            (Expose::Boundary, Binding::Semantic, [1399710662, 1070536470, 1439052877, 1432823435, 425563339, 1798854306, 10547037, 1096294064]),
            (Expose::Boundary, Binding::Bound, [1399710662, 1070536470, 1439052877, 1432823435, 425563339, 1798854306, 10547037, 1096294064]),
            (Expose::Interval, Binding::Legacy, [883391405, 1926596795, 811071814, 1125540336, 1547079331, 24099729, 1348287992, 524126935]),
            (Expose::Interval, Binding::Semantic, [572517800, 470808891, 1397510267, 1291848049, 307788394, 543387045, 1771415952, 160488972]),
            (Expose::Interval, Binding::Bound, [572517800, 470808891, 1397510267, 1291848049, 307788394, 543387045, 1771415952, 160488972]),
        ];
        for (expose, binding, vk) in recorded {
            let old = build_gkb2_leaf_expose_with(HP, expose, binding);
            assert_eq!(old.commit_mode(), CommitMode::Plain);
            let old = old.vk_pin_values();
            let plain = build_gkb2_leaf_commit(HP, expose, binding, CommitMode::Plain).vk_pin_values();
            assert_eq!(vk_flat(&old), vk_literal(vk), "{expose:?}/{binding:?}: Plain VK drifted");
            assert_eq!(plain, old, "{expose:?}/{binding:?}");
            let hid = build_gkb2_leaf_commit(HP, expose, binding, CommitMode::Hiding).vk_pin_values();
            assert_ne!(hid, old, "{expose:?}/{binding:?}: the hiding circuit differs");
        }
        assert_eq!(build_gkb2_leaf(HP, true).commit_mode(), CommitMode::Plain);

        // Plain proofs (old entry point and the openings API with ignored
        // openings) expose the recorded pre-B2 commitments and statement.
        let s1 = apply_batch2(&Gk2State::empty(HP), &hp_batches()[0]);
        let want_init = [750667096u64, 1226793707, 1397676405, 400638028, 1982030553, 601321200, 1793377865, 53304465];
        let want_final = [822263888u64, 1312373547, 1776859853, 1213666083, 1760077299, 459086526, 786343600, 459146528];
        let want_batch = [1511335652u64, 225702205, 52648565, 313760589, 586200307, 1052990591, 417076801, 1528987270];
        let want_iv = [2u64, 2, 0, 0, 254909523, 1736935061, 729976354, 360887018, 82543764, 171050504, 1940090617, 1876404345];
        let mut plain = build_gkb2_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Plain);
        let seed = SaltSeed::for_tests(3);
        for r in [
            plain.prove_epoch_at(2, s1.clone(), hp_batches()[1].clone()),
            plain.prove_epoch_commit(2, s1.clone(), hp_batches()[1].clone(), &Openings::for_leaf(&seed, GK, 2)),
        ] {
            assert_eq!(u64s(&r.initial.0), want_init);
            assert_eq!(u64s(&r.final_.0), want_final);
            assert_eq!(u64s(&r.batch_commit.0), want_batch);
            let pv = u64s(&crate::commitment::hiding::probe::public_values(&r.output.0));
            let want: Vec<u64> = want_init.iter().chain(&want_final).chain(&want_iv).copied().collect();
            assert_eq!(pv, want, "Plain Interval statement drifted");
        }

        let mut leaf = hiding_leaf(Expose::Interval, Binding::Semantic);
        let vk = leaf.vk_pin_values();
        let ups = hp_batches()[0].clone();
        let e = Gk2State::empty(HP);
        let a = leaf.prove_epoch_commit(1, e.clone(), ups.clone(), &Openings::for_leaf(&SaltSeed::for_tests(1), GK, 1));
        let b = leaf.prove_epoch_commit(5, e, ups, &Openings::for_leaf(&SaltSeed::for_tests(2), GK, 5));
        assert_ne!(a.final_, b.final_);
        assert_eq!(vk_pin_values(&a.output.0), vk);
        assert_eq!(vk_pin_values(&b.output.0), vk);
        let noop = gk2_noop_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Hiding);
        assert_eq!(vk_pin_values(&noop), vk, "the zero-salt no-op leaf has the real leaves' VK");
        let bvk = build_gkb2_leaf_commit(HP, Expose::Boundary, Binding::Legacy, CommitMode::Hiding).vk_pin_values();
        let bnoop = gk2_noop_leaf_commit(HP, Expose::Boundary, Binding::Legacy, CommitMode::Hiding);
        assert_eq!(vk_pin_values(&bnoop), bvk, "Boundary/Legacy no-op leaf VK");
        let pnoop = gk2_noop_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Plain);
        assert_eq!(vk_flat(&vk_pin_values(&pnoop)), vk_literal(recorded[7].2), "Plain no-op leaf VK");
    }

    /// (3) Equal states at two versions get different hiding commitments,
    /// both different from the plain one; at the proof level, two leaves with
    /// an empty batch (the state does not move) at `t = 1, 2` from the empty
    /// genesis state `S` (leaf 1's zero init salt opens only that public
    /// state) expose `Com(S; 0) → Com(S; ρ_1) → Com(S; ρ_2)`: three distinct
    /// values for one state, chained, and two distinct batch commitments for
    /// two equal (empty) batches.
    #[test]
    fn equal_states_get_unlinkable_hiding_commitments() {
        let seed = SaltSeed::for_tests(33);
        let s = hp_prior();
        let (r1, r2) = (rho_state_bb(&seed, GK, 1), rho_state_bb(&seed, GK, 2));
        let (c1, c2) = (
            commit_gk2_state_with(&s, CommitMode::Hiding, &r1),
            commit_gk2_state_with(&s, CommitMode::Hiding, &r2),
        );
        assert_ne!(c1, c2);
        assert_ne!(c1, commit_gk2_state(&s));
        assert_ne!(c2, commit_gk2_state(&s));
        assert_eq!(commit_gk2_state_with(&s, CommitMode::Plain, &r1), commit_gk2_state(&s), "Plain ignores the salt");

        let s = Gk2State::empty(HP);
        let (c1, c2) = (
            commit_gk2_state_with(&s, CommitMode::Hiding, &r1),
            commit_gk2_state_with(&s, CommitMode::Hiding, &r2),
        );
        assert_eq!(apply_batch2(&s, &[]), s, "an empty batch does not move the state");
        let mut leaf = hiding_leaf(Expose::Interval, Binding::Semantic);
        let l1 = leaf.prove_epoch_commit(1, s.clone(), Vec::new(), &Openings::for_leaf(&seed, GK, 1));
        let l2 = leaf.prove_epoch_commit(2, s.clone(), Vec::new(), &Openings::for_leaf(&seed, GK, 2));
        let (s1, s2) = (read_exposed_statement(&l1.output.0), read_exposed_statement(&l2.output.0));
        assert_eq!(s1.init, commit_gk2_state_with(&s, CommitMode::Hiding, &SaltBb::ZERO).0.to_vec());
        assert_eq!(s1.final_, c1.0.to_vec());
        assert_eq!(s2.init, s1.final_, "leaf 2 opens Com(S_1) with the same ρ_1");
        assert_eq!(s2.final_, c2.0.to_vec());
        assert_ne!(s1.init, s1.final_, "the state did not move, the commitment did");
        assert_ne!(s2.init, s2.final_);
        assert_ne!(l1.batch_commit, l2.batch_commit, "equal batches, unlinkable commitments");
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
        let binding = Binding::Semantic;
        let (a, b) = (SaltSeed::for_tests(41), SaltSeed::for_tests(42));
        let bs = hp_batches();
        let s0 = Gk2State::empty(HP);
        let s1 = apply_batch2(&s0, &bs[0]);
        let s2 = apply_batch2(&s1, &bs[1]);
        let n_prev = [s0.n, s1.n];
        let log_for = |seed: &SaltSeed| {
            let bc: Vec<[Val; 8]> = (0..2)
                .map(|k| {
                    let salt = rho_batch_bb(seed, GK, k as u64 + 1);
                    commit_gk2_batch_with(&bs[k], HP.batch, n_prev[k], CommitMode::Hiding, &salt).0
                })
                .collect();
            batch_log(
                &commit_gk2_state_with(&s0, CommitMode::Hiding, &SaltBb::ZERO).0,
                &commit_gk2_state_with(&s2, CommitMode::Hiding, &rho_state_bb(seed, GK, 2)).0,
                &bc,
            )
        };
        let (log_a, log_b) = (log_for(&a), log_for(&b));
        let mut leaf = hiding_leaf(Expose::Interval, binding);
        let l1 = leaf.prove_epoch_commit(1, s0.clone(), bs[0].clone(), &Openings::for_leaf(&a, GK, 1)).output;
        let l2 = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &Openings::for_leaf(&a, GK, 2)).output;
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log_a, Expose::Interval), Ok(()));
        assert!(check_leaves_against_log(&[&l1.0, &l2.0], &log_b, Expose::Interval).is_err(), "another seed's log");

        // Leaf 2 opened with a wrong batch randomizer: its digest H(TAG_LEAF, 2,
        // Com(B_2; ρ')) is not the log's.
        let bad_batch = Openings { batch: rho_batch_bb(&b, GK, 2), ..Openings::for_leaf(&a, GK, 2) };
        let l2b = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_batch).output;
        let e = check_leaves_against_log(&[&l1.0, &l2b.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("digest")), "{e:?}");
        // … with a wrong final randomizer: Com(S_2; ρ') is not the log's Com(S_T).
        let bad_final = Openings { final_: rho_state_bb(&b, GK, 2), ..Openings::for_leaf(&a, GK, 2) };
        let l2f = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_final).output;
        let e = check_leaves_against_log(&[&l1.0, &l2f.0], &log_a, Expose::Interval);
        assert!(e.as_ref().is_err_and(|e| e.contains("Com(S_T)")), "{e:?}");

        // Composition: the honest pair merges and verifies against log A.
        let shape = ForestShape::forest(2);
        let root = prove_hiding_merge(&l1, &l2);
        let noop = gk2_noop_leaf_commit(HP, Expose::Interval, binding, CommitMode::Hiding);
        let vk = root_vk_deriver(noop).root_vk(&shape);
        verify_bound_stark_proof_against_log(&root.0, &vk, &log_a, &shape);
        assert!(check_root_against_log(&root.0, &log_b, &shape).is_err());

        // Inconsistent ρ_1 across the boundary: the merge is unprovable.
        let bad_init = Openings { init: rho_state_bb(&b, GK, 1), ..Openings::for_leaf(&a, GK, 2) };
        let l2i = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &bad_init).output;
        assert_ne!(read_exposed_statement(&l2i.0).init, read_exposed_statement(&l1.0).final_);
        let e = forge::catch_msg(|| prove_hiding_merge(&l1, &l2i)).map(|_| ());
        println!("B2 GK inconsistent ρ_1 merge: {e:?}");
        assert!(
            e.as_ref().is_err_and(|m| m.contains("WitnessConflict")),
            "leaf 2's init must use leaf 1's final randomizer: {e:?}"
        );
    }

    /// (5) The zero-salt no-op leaf of a Hiding circuit still exposes
    /// `init == final` (`= Com(S_0; 0)`, the public anchor), so the twin-merge
    /// root-VK derivation works unchanged, under both layouts and every
    /// binding.
    #[test]
    fn hiding_noop_leaf_has_init_eq_final() {
        let anchor = commit_gk2_state_with(&Gk2State::empty(HP), CommitMode::Hiding, &SaltBb::ZERO);
        assert_ne!(anchor, commit_gk2_state(&Gk2State::empty(HP)));
        for (expose, binding) in [
            (Expose::Interval, Binding::Semantic),
            (Expose::Interval, Binding::Bound),
            (Expose::Interval, Binding::Legacy),
            (Expose::Boundary, Binding::Semantic),
        ] {
            let noop = gk2_noop_leaf_commit(HP, expose, binding, CommitMode::Hiding);
            let st = read_exposed_statement(&noop);
            assert_eq!(st.init, st.final_, "{expose:?}/{binding:?}");
            assert_eq!(st.init, anchor.0.to_vec(), "{expose:?}/{binding:?}");
        }
    }

    /// (F3, F5) The Hiding leaf costs exactly +2 Poseidon2 rows and +3 ALU
    /// rows per commitment over the Plain leaf (3 commitments: +6 and +9)
    /// under every binding, and none of its 36 salt values is a public value
    /// of the proof (the scan's positive control: a "salt" equal to an
    /// exposed commitment value is found).
    #[test]
    fn hiding_leaf_row_overhead_and_no_salt_in_public_values() {
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows, trace_rows};
        let seed = SaltSeed::for_tests(91);
        let t = 3u64;
        let ups = hp_batches()[0].clone();
        let prior = hp_prior();
        let o = Openings::for_leaf(&seed, GK, t);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            for expose in [Expose::Interval, Expose::Boundary] {
                let mut plain = build_gkb2_leaf_commit(HP, expose, binding, CommitMode::Plain);
                let mut leaf = hiding_leaf(expose, binding);
                let (p0, a0) = trace_rows(&plain.run_epoch_commit(t, &prior, &ups, &Openings::plain()));
                let (p1, a1) = trace_rows(&leaf.run_epoch_commit(t, &prior, &ups, &o));
                println!("B2 GK leaf rows {binding:?}/{expose:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
                assert_eq!(p1, p0 + 6, "{binding:?}/{expose:?}: Poseidon2 rows");
                assert_eq!(a1, a0 + 9, "{binding:?}/{expose:?}: ALU rows");
                let hid = leaf.prove_epoch_commit(t, prior.clone(), ups.clone(), &o);
                assert_eq!(proof_alu_rows(&hid.output.0), a1, "{binding:?}/{expose:?}: the proof's ALU height");
                assert_eq!(leaked_salts(&hid.output.0, &[o.init, o.final_, o.batch]), vec![], "{binding:?}/{expose:?}");
                let mut control = SaltBb::ZERO;
                control.0[0] = hid.initial.0[0];
                assert!(!leaked_salts(&hid.output.0, &[control]).is_empty(), "{binding:?}: the scan sees the statement");
            }
        }
    }

    /// (F1) A Hiding leaf never falls back to zero salts silently: the old
    /// `prove_epoch_at` / `prove_epoch` entry points (and the forgery PoCs'
    /// `prove_build`) panic on it, and so does `prove_epoch_commit` (and the
    /// one-call API) handed a zero final or batch salt. The explicit no-op
    /// path refuses a non-empty batch. Controls: a zero INIT salt is leaf 1's
    /// honest opening (from the empty genesis state; a zero init on a real
    /// state is refused, test `hiding_leaf_refuses_zero_init_on_a_real_state`),
    /// and a Plain leaf still ignores its openings.
    #[test]
    fn hiding_leaf_rejects_zero_openings_outside_the_noop_path() {
        let seed = SaltSeed::for_tests(81);
        let ups = hp_batches()[0].clone();
        let mut leaf = hiding_leaf(Expose::Interval, Binding::Semantic);
        let msg = forge::catch_msg(|| leaf.prove_epoch_at(2, hp_prior(), ups.clone()).final_).unwrap_err();
        assert!(msg.contains("prove_epoch_at on a Hiding leaf"), "{msg}");
        assert!(forge::catch(|| leaf.prove_epoch(hp_prior(), ups.clone()).final_).is_none());
        let build = build_bm2(&hp_prior(), &ups);
        let msg = forge::catch_msg(|| leaf.prove_build(hp_prior(), ups.clone(), &build).final_).unwrap_err();
        assert!(msg.contains("Plain leaves only"), "{msg}");
        let honest = Openings::for_leaf(&seed, GK, 2);
        for (what, o) in [
            ("plain", Openings::plain()),
            ("public_zero", Openings::public_zero()),
            ("zero final", Openings { final_: SaltBb::ZERO, ..honest }),
            ("zero batch", Openings { batch: SaltBb::ZERO, ..honest }),
        ] {
            let msg = forge::catch_msg(|| leaf.prove_epoch_commit(2, hp_prior(), ups.clone(), &o).final_)
                .unwrap_err();
            assert!(msg.contains("public zero salt"), "{what}: {msg}");
        }
        let msg = forge::catch_msg(|| {
            prove_gkb2_interval_commit(HP, 2, hp_prior(), ups.clone(), CommitMode::Hiding, &Openings::plain()).final_
        })
        .unwrap_err();
        assert!(msg.contains("public zero salt"), "{msg}");
        let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, hp_prior(), ups.clone()).final_).unwrap_err();
        assert!(msg.contains("the batch must be empty"), "{msg}");

        let o1 = Openings::for_leaf(&seed, GK, 1);
        assert!(o1.init.is_zero());
        let s0 = Gk2State::empty(HP);
        let r = leaf.prove_epoch_commit(1, s0.clone(), ups.clone(), &o1);
        assert_eq!(r.initial, commit_gk2_state_with(&s0, CommitMode::Hiding, &SaltBb::ZERO));
        let mut plain = build_gkb2_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Plain);
        let p = plain.prove_epoch_commit(2, hp_prior(), ups.clone(), &Openings::plain());
        assert_eq!(p.initial, commit_gk2_state(&hp_prior()));
        assert_eq!(p.final_, commit_gk2_state(&apply_batch2(&hp_prior(), &ups)));
        assert_eq!(p.batch_commit, commit_gk2_batch(&ups, HP.batch, hp_prior().n));
    }

    /// (F1, init salt) Under `Hiding` a zero INIT salt opens only the public
    /// genesis `Com(S_0; 0)`: batch index 1 and the empty state. Refused,
    /// under both bindings: a forgotten init opening on a real prior
    /// (`t = 2`), a worker that numbers its leaves locally (`for_leaf(.., 1)`
    /// at global `t = 5` on a real state), leaf 1's openings on a real prior
    /// at `t = 1`, and a zero init at `t = 2` even on the empty state. Each
    /// would otherwise prove a leaf exposing the guess-checkable `Com(S; 0)`
    /// of a secret state. Controls: the genesis leaf (empty state, zero
    /// init) proves and exposes `Com(S_0; 0)`; a Plain leaf ignores its
    /// openings on the same inputs.
    #[test]
    fn hiding_leaf_refuses_zero_init_on_a_real_state() {
        let seed = SaltSeed::for_tests(83);
        let ups = hp_batches()[0].clone();
        let s0 = Gk2State::empty(HP);
        assert_ne!(hp_prior(), s0, "precondition: a real (secret) prior");
        let forgot = Openings { init: SaltBb::ZERO, ..Openings::for_leaf(&seed, GK, 2) };
        let local = Openings::for_leaf(&seed, GK, 1);
        let cases = [
            ("forgotten init, real prior", 2u64, hp_prior(), forgot),
            ("local numbering at global t = 5", 5, hp_prior(), local),
            ("leaf-1 openings on a real prior", 1, hp_prior(), local),
            ("zero init at t = 2 on the empty state", 2, s0.clone(), forgot),
        ];
        for binding in [Binding::Semantic, Binding::Bound] {
            let mut leaf = hiding_leaf(Expose::Interval, binding);
            for (what, t, prior, o) in &cases {
                let msg = forge::catch_msg(|| leaf.prove_epoch_commit(*t, prior.clone(), ups.clone(), o).final_)
                    .unwrap_err();
                assert!(msg.contains("zero init salt"), "{binding:?}/{what}: {msg}");
            }
            let r = leaf.prove_epoch_commit(1, s0.clone(), ups.clone(), &local);
            assert_eq!(r.initial, commit_gk2_state_with(&s0, CommitMode::Hiding, &SaltBb::ZERO), "{binding:?}");
        }
        let mut plain = build_gkb2_leaf_commit(HP, Expose::Interval, Binding::Semantic, CommitMode::Plain);
        for (what, t, prior, o) in &cases {
            let p = plain.prove_epoch_commit(*t, prior.clone(), ups.clone(), o);
            assert_eq!(p.initial, commit_gk2_state(prior), "Plain/{what}");
        }
    }

    /// (L1) The explicit zero-salt path proves only the VK-derivation leaf's
    /// input: the EMPTY state (whose `Com(S_0; 0)` the verifier recomputes
    /// itself) with an empty batch at `t = 1`. A real state with an empty
    /// batch does not move (so the empty-batch and unchanged-state checks
    /// alone let it through), and would publish the deterministic,
    /// guess-checkable `Com(S; 0)` as both init and final; the path now
    /// refuses it, and another batch index, in either mode. Control: the
    /// honest no-op input still proves and exposes `init == final ==
    /// Com(S_0; 0)`.
    #[test]
    fn noop_path_refuses_a_real_state_or_another_index() {
        let s = hp_prior();
        let moved = build_bm2(&s, &[]);
        assert!(moved.final_tuples == s.tuples && moved.n_t == s.n, "precondition: an empty batch leaves S unchanged");
        for mode in [CommitMode::Hiding, CommitMode::Plain] {
            let mut leaf = build_gkb2_leaf_commit(HP, Expose::Interval, Binding::Semantic, mode);
            let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(1, hp_prior(), Vec::new()).final_).unwrap_err();
            assert!(msg.contains("the initial state must be the empty genesis state"), "{mode:?}: {msg}");
            let msg = forge::catch_msg(|| leaf.prove_epoch_public_zero(2, Gk2State::empty(HP), Vec::new()).final_)
                .unwrap_err();
            assert!(msg.contains("batch index 1"), "{mode:?}: {msg}");
        }
        let mut leaf = hiding_leaf(Expose::Interval, Binding::Semantic);
        let r = leaf.prove_epoch_public_zero(1, Gk2State::empty(HP), Vec::new());
        let s0 = commit_gk2_state_with(&Gk2State::empty(HP), CommitMode::Hiding, &SaltBb::ZERO);
        assert_eq!((r.initial, r.final_), (s0, s0));
    }

    /// (F2) A continued history (the GK rotation) is anchored on the previous
    /// history's certified final commitment: history 0 ends at
    /// `Com(S_2; ρ_{0,2})`; history 1 restarts `t` at 1 from `S_2`, its leaf 1
    /// opens the init with that anchor salt ([`Openings::for_leaf_after`]) and
    /// exposes exactly the certified value, and both leaves pass the per-batch
    /// check against history 1's log, whose `Com(S_0)` is that anchor (taken
    /// from history 0, not recomputed). The same batch at the same `t` gets
    /// another commitment in each history. The pre-fix opening (init salt 0)
    /// would expose the guess-checkable `Com(S_2; 0)`: the leaf refuses it. A
    /// nonzero WRONG anchor salt (not detectable by the leaf) exposes another
    /// commitment, and the log rejects it.
    #[test]
    fn continued_history_leaf_opens_the_previous_final_commitment() {
        use crate::commitment::hiding::{rho_batch_bb_in, rho_state_bb_in};
        let seed = SaltSeed::for_tests(71);
        let bs = hp_batches();
        let s1 = apply_batch2(&Gk2State::empty(HP), &bs[0]);
        let s2 = apply_batch2(&s1, &bs[1]);
        let mut leaf = hiding_leaf(Expose::Interval, Binding::Semantic);
        let h0_last = leaf.prove_epoch_commit(2, s1.clone(), bs[1].clone(), &Openings::for_leaf(&seed, GK, 2));
        let anchor_salt = rho_state_bb(&seed, GK, 2);
        let anchor = h0_last.final_;
        assert_eq!(anchor, commit_gk2_state_with(&s2, CommitMode::Hiding, &anchor_salt));

        let h = 1u64;
        let nb = [vec![30u32, 31], vec![40, 41]];
        let s3 = apply_batch2(&s2, &nb[0]);
        let s4 = apply_batch2(&s3, &nb[1]);
        let o1 = Openings::for_leaf_after(&anchor_salt, &seed, GK, h);
        let l1 = leaf.prove_epoch_commit(1, s2.clone(), nb[0].clone(), &o1).output;
        let l2 = leaf.prove_epoch_commit(2, s3.clone(), nb[1].clone(), &Openings::for_leaf_in(&seed, GK, h, 2)).output;
        assert_eq!(read_exposed_statement(&l1.0).init, anchor.0.to_vec(), "history 1 starts at history 0's final");
        assert_eq!(read_exposed_statement(&l2.0).init, read_exposed_statement(&l1.0).final_);
        let n_prev = [s2.n, s3.n];
        let bc: Vec<[Val; 8]> = (0..2)
            .map(|k| {
                let salt = rho_batch_bb_in(&seed, GK, h, k as u64 + 1);
                commit_gk2_batch_with(&nb[k], HP.batch, n_prev[k], CommitMode::Hiding, &salt).0
            })
            .collect();
        let fin = commit_gk2_state_with(&s4, CommitMode::Hiding, &rho_state_bb_in(&seed, GK, h, 2));
        let log1 = batch_log(&anchor.0, &fin.0, &bc);
        assert_eq!(check_leaves_against_log(&[&l1.0, &l2.0], &log1, Expose::Interval), Ok(()));
        let h0_bc1 = commit_gk2_batch_with(&nb[0], HP.batch, n_prev[0], CommitMode::Hiding, &rho_batch_bb(&seed, GK, 1));
        assert_ne!(bc[0], h0_bc1.0, "t restarted, the randomizer did not");

        let zero_init = Openings { init: SaltBb::ZERO, ..o1 };
        let msg = forge::catch_msg(|| leaf.prove_epoch_commit(1, s2.clone(), nb[0].clone(), &zero_init).final_)
            .unwrap_err();
        assert!(msg.contains("zero init salt"), "{msg}");
        let wrong_init = Openings { init: rho_state_bb(&seed, GK, 1), ..o1 };
        let l1w = leaf.prove_epoch_commit(1, s2, nb[0].clone(), &wrong_init).output;
        let e = check_leaves_against_log(&[&l1w.0, &l2.0], &log1, Expose::Interval);
        assert!(e.as_ref().is_err_and(|m| m.contains("Com(S_0)")), "{e:?}");
    }

    /// (8, with `commitment::hiding::tests::salt_private_inputs_have_alu_creators`)
    /// Build and prove the Hiding leaf at a tiny shape. Under the DEBUG
    /// profile (`cargo test --lib gk_bandmerge::tests::hiding_leaf_tiny_debug`)
    /// the fork debug-asserts, during the build, that each of the 9 salt
    /// private inputs has an ALU creator.
    #[test]
    fn hiding_leaf_tiny_debug() {
        let p = GkbParams { capacity: 2, batch: 2, s: 2 };
        let seed = SaltSeed::for_tests(8);
        let vals = vec![9u32, 4];
        for binding in [Binding::Semantic, Binding::Legacy] {
            let mut leaf = build_gkb2_leaf_commit(p, Expose::Interval, binding, CommitMode::Hiding);
            let r = leaf.prove_epoch_commit(1, Gk2State::empty(p), vals.clone(), &Openings::for_leaf(&seed, GK, 1));
            let fin = apply_batch2(&Gk2State::empty(p), &vals);
            assert_eq!(r.final_, commit_gk2_state_with(&fin, CommitMode::Hiding, &rho_state_bb(&seed, GK, 1)));
        }
    }
}

// ── G1 (M3) StableCompact tests ──────────────────────────────────────────
#[cfg(test)]
mod stable_tests {
    use super::*;
    use crate::commitment::hiding::{Openings, SaltSeed};

    /// Small deterministic generator (no external RNG).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
    }

    /// One batch of `k` values in input pattern `mode` (random, ascending,
    /// descending, duplicate-heavy, zigzag, outside-in), offset by `n`.
    fn batch_vals(mode: usize, k: usize, n: u64, rng: &mut Lcg) -> Vec<u32> {
        let n = n as u32;
        match mode {
            0 => (0..k).map(|_| rng.below(1 << 21) as u32).collect(),
            1 => (0..k as u32).map(|i| n + 1 + i).collect(),
            2 => (0..k as u32).map(|i| (1 << 20) - n - i).collect(),
            3 => (0..k).map(|_| rng.below(4) as u32).collect(),
            4 => (0..k as u32)
                .map(|i| if i % 2 == 0 { n + i / 2 } else { (1 << 20) - n - i / 2 })
                .collect(),
            _ => (0..k as u32)
                .map(|i| {
                    let h = i / 2;
                    if i % 2 == 0 { (1 << 19) - 4096 + n % 2048 + h } else { (1 << 19) + 4096 - n % 2048 - h }
                })
                .collect(),
        }
    }

    /// **G1 output equivalence, natively.** The stable-compaction replay of the
    /// rounds ([`stable_rounds`]) equals the bm2 replay (`finish_bm2`, the
    /// SortedCopy circuit's witness) on >= 480 chains of mixed shapes and input
    /// patterns, and both agree on overflow.
    #[test]
    fn g1_stable_rounds_match_bm2_native() {
        let mut rng = Lcg(0x6131_5EED);
        let (mut chains, mut batches, mut overflows) = (0usize, 0usize, 0usize);
        for _ in 0..600 {
            let s = [1u64, 2, 3, 4, 6, 51][rng.below(6) as usize];
            let cap = [4usize, 8, 16, 32, 64][rng.below(5) as usize];
            let mut m = [1usize, 2, 4, 8, 16, 32][rng.below(6) as usize];
            if (cap + m) % 2 == 1 {
                m += 1;
            }
            let mode = rng.below(6) as usize;
            let params = GkbParams { capacity: cap, batch: m, s };
            let mut st = Gk2State::empty(params);
            for _ in 0..1 + rng.below(12) {
                let k = rng.below(m as u64 + 1) as usize;
                let vals = batch_vals(mode, k, st.n, &mut rng);
                let b = build_bm2(&st, &vals);
                let overflow = b.excess.iter().any(|t| t.active == 1);
                let sb = stable_rounds(&b.union_init, b.theta, cap);
                assert_eq!(sb.survivors > cap, overflow, "overflow verdicts differ");
                if overflow {
                    overflows += 1;
                    break;
                }
                assert!(sb.final_tuples == b.final_tuples, "G1 final != bm2 final (s={s} cap={cap} m={m} mode={mode})");
                st = Gk2State { tuples: b.final_tuples, params, n: b.n_t };
                batches += 1;
            }
            chains += 1;
        }
        eprintln!("G1 vs bm2: {chains} chains, {batches} batches equal, {overflows} overflow-terminated");
        assert!(chains >= 480 && batches >= 2000);
    }

    fn stable_leaf(params: GkbParams, expose: Expose, mode: CommitMode) -> Gkb2LeafCircuit {
        build_gkb2_leaf_rounds(params, expose, Binding::Semantic, mode, GkRounds::StableCompact)
    }

    /// **Honest prove/verify of the StableCompact leaf** (Plain, no expose),
    /// three chained epochs with both fusion directions: every proof
    /// self-verifies and certifies the native `apply_batch2` state.
    #[test]
    fn g1_stable_circuit_round_trip_chained() {
        let params = GkbParams { capacity: 16, batch: 8, s: 3 };
        let mut leaf = stable_leaf(params, Expose::None, CommitMode::Plain);
        let batches: [Vec<u32>; 3] = [
            vec![100, 400, 200, 700, 300, 600, 500, 800],
            vec![150, 650, 250, 750, 350, 550, 450, 850],
            vec![10, 20, 30, 40, 900, 910],
        ];
        let mut st = Gk2State::empty(params);
        for (t, b) in batches.iter().enumerate() {
            let p = leaf.prove_epoch_at(t as u64 + 1, st.clone(), b.clone());
            let s2 = apply_batch2(&st, b);
            assert_eq!(p.initial.0, commit_gk2_state(&st).0);
            assert_eq!(p.final_.0, commit_gk2_state(&s2).0, "certified final == native apply_batch2");
            st = s2;
        }
        assert!(st.actives().len() < st.n as usize, "some fusion must have happened");
    }

    /// The deployed statement: Interval + Hiding commitments, honest openings,
    /// two chained leaves, plus the no-op VK-derivation leaf on the same circuit.
    #[test]
    fn g1_stable_interval_hiding_round_trip() {
        let params = GkbParams { capacity: 8, batch: 8, s: 2 };
        let gk = CommitFamily::GreenwaldKhanna;
        let seed = SaltSeed::for_tests(77);
        let mut leaf = stable_leaf(params, Expose::Interval, CommitMode::Hiding);
        let s0 = Gk2State::empty(params);
        let b1 = vec![5u32, 9, 1, 7, 3, 8, 2, 6];
        let p1 = leaf.prove_epoch_commit(1, s0.clone(), b1.clone(), &Openings::for_leaf(&seed, gk, 1));
        let s1 = apply_batch2(&s0, &b1);
        let b2 = vec![4u32, 10, 11, 0];
        let p2 = leaf.prove_epoch_commit(2, s1.clone(), b2.clone(), &Openings::for_leaf(&seed, gk, 2));
        assert_eq!(p1.final_.0, p2.initial.0, "leaf 1's final commitment is leaf 2's init");
        let noop = stable_leaf(params, Expose::Interval, CommitMode::Hiding)
            .prove_epoch_public_zero(1, s0.clone(), Vec::new());
        assert_eq!(noop.initial.0, noop.final_.0);
        assert_eq!(leaf.vk_pin_values(), crate::recursion::recursive::expose_forest::vk_pin_values(&noop.output.0));
    }

    /// The variants have different leaf VKs; the SortedCopy builder is the
    /// default and reproduces the pre-M3 circuit (its pins live in
    /// `commitment::plain_vk_pins`).
    #[test]
    fn g1_stable_vk_differs_from_sorted() {
        let params = GkbParams { capacity: 4, batch: 4, s: 2 };
        let a = build_gkb2_leaf_rounds(params, Expose::Interval, Binding::Semantic, CommitMode::Plain, GkRounds::SortedCopy);
        let b = stable_leaf(params, Expose::Interval, CommitMode::Plain);
        let d = build_gkb2_leaf_commit(params, Expose::Interval, Binding::Semantic, CommitMode::Plain);
        assert_eq!(a.rounds(), GkRounds::SortedCopy);
        // The pre-M3 builder is the SortedCopy leaf whatever EXP_GK_ROUNDS says.
        assert_eq!(d.rounds(), GkRounds::SortedCopy);
        assert_eq!(b.rounds(), GkRounds::StableCompact);
        assert_ne!(a.vk_pin_values(), b.vk_pin_values());
        assert_eq!(a.vk_pin_values(), d.vk_pin_values());
        assert_eq!(parse_gk_rounds_env(Ok("STABLE".into())), Some(GkRounds::StableCompact));
        assert_eq!(parse_gk_rounds_env(Ok("sorted".into())), Some(GkRounds::SortedCopy));
        assert_eq!(parse_gk_rounds_env(Ok(String::new())), None);
        assert_eq!(parse_gk_rounds_env(Err(std::env::VarError::NotPresent)), None);
        assert!(std::panic::catch_unwind(|| parse_gk_rounds_env(Ok("resort".into()))).is_err());
        assert_eq!(GkRounds::default(), GkRounds::SortedCopy, "the type default is the pre-M3 leaf");
        for r in [GkRounds::SortedCopy, GkRounds::StableCompact] {
            assert_eq!(r.label().parse::<GkRounds>(), Ok(r));
        }
    }

    /// The deployed config-B leaf shape (cap 768, m 512, s 51), ZK + Interval +
    /// Hiding as the composition harness builds it: three chained batches of
    /// pseudo-random 20-bit values each prove and verify and certify the
    /// native `apply_batch2` state. Heavy (~4.3 GB, ~7 s per leaf):
    /// `cargo test --release --lib -- --ignored g1_stable_deployed_shape_chain`.
    #[test]
    #[ignore]
    fn g1_stable_deployed_shape_chain() {
        let params = GkbParams { capacity: 768, batch: 512, s: 51 };
        let gk = CommitFamily::GreenwaldKhanna;
        let seed = SaltSeed::for_tests(1016);
        let t0 = std::time::Instant::now();
        let mut leaf = stable_leaf(params, Expose::Interval, CommitMode::Hiding);
        eprintln!("build {:.2}s", t0.elapsed().as_secs_f64());
        let mut rng = Lcg(0xA0C1_2026);
        let mut st = Gk2State::empty(params);
        for t in 1..=3u64 {
            let vals: Vec<u32> = (0..params.batch).map(|_| rng.below(1 << 20) as u32).collect();
            let t1 = std::time::Instant::now();
            let p = leaf.prove_epoch_commit(t, st.clone(), vals.clone(), &Openings::for_leaf(&seed, gk, t));
            let next = apply_batch2(&st, &vals);
            let o = Openings::for_leaf(&seed, gk, t);
            assert_eq!(p.final_.0, commit_gk2_state_with(&next, CommitMode::Hiding, &o.final_).0);
            eprintln!(
                "leaf t={t}: {:.2}s, N={}, survivors={}",
                t1.elapsed().as_secs_f64(),
                next.n,
                next.actives().len()
            );
            st = next;
        }
    }

    /// A state of exactly `cap` survivors whose next batch adds one more
    /// survivor: increasing values that never fuse (s large, θ = 0).
    fn cap_edge(cap: usize) -> (GkbParams, Gk2State, Vec<u32>) {
        let params = GkbParams { capacity: cap, batch: 2, s: 1000 };
        let mut st = Gk2State::empty(params);
        let mut v = 10u32;
        while st.actives().len() + 4 <= cap {
            st = apply_batch2(&st, &[v, v + 1]);
            v += 2;
        }
        (params, st, vec![v, v + 1])
    }

    /// **G-cap: S = cap proves, S = cap + 1 fails everywhere**, under both
    /// round certifications: `apply_batch2` panics with the capacity message
    /// (`try_apply_batch2` returns the error), both leaves refuse it natively
    /// (the harness's failed run), and with the native guard lifted both
    /// CIRCUITS refuse the honest-but-overflowing witness. Positive control:
    /// the StableCompact leaf without its two overflow checks (`α^L_cap = 0`
    /// and the mass) proves it, certifying the lossy truncated state.
    #[test]
    fn g1_stable_capacity_edge() {
        let cap = 6;
        let (params, st, next) = cap_edge(cap);
        assert_eq!(st.actives().len(), cap - 2, "precondition");
        let full = apply_batch2(&st, &next);
        assert_eq!(full.actives().len(), cap, "S = cap");
        let over = vec![next[1] + 1]; // one more survivor: S = cap + 1
        // Native: a hard error with the capacity in its message (the harness
        // maps it to a failed `too_large` run), the typed error from try_.
        let r = std::panic::catch_unwind(|| apply_batch2(&full, &over));
        let msg = r.expect_err("apply_batch2 must refuse an overflow");
        let msg = msg
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| msg.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(msg.contains("capacity"), "overflow message names the capacity: {msg}");
        let err = try_apply_batch2(&full, &over).expect_err("try_apply_batch2 must refuse an overflow");
        assert_eq!((err.capacity, err.survivors, err.unpaired_dropped), (cap, cap + 1, 0));
        assert_eq!(try_apply_batch2(&st, &next), Ok(full.clone()), "S = cap is not an error");
        for rounds in [GkRounds::SortedCopy, GkRounds::StableCompact] {
            let mut leaf = build_gkb2_leaf_rounds(params, Expose::None, Binding::Semantic, CommitMode::Plain, rounds);
            // S = cap proves and certifies the native state.
            let p = leaf.prove_epoch_at(1, st.clone(), next.clone());
            assert_eq!(p.final_.0, commit_gk2_state(&full).0, "{rounds:?}: S = cap");
            // S = cap + 1: refused natively (the harness's failed run) ...
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                leaf.prove_epoch_at(2, full.clone(), over.clone())
            }));
            assert!(r.is_err(), "{rounds:?}: the leaf must refuse an overflow natively");
            // ... and by the circuit itself (native guard lifted).
            ALLOW_OVERFLOW.with(|c| c.set(Some(true)));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                leaf.prove_epoch_at(2, full.clone(), over.clone())
            }));
            ALLOW_OVERFLOW.with(|c| c.set(None));
            assert!(r.is_err(), "{rounds:?}: the circuit must reject S = cap + 1");
        }
        // Positive control: without α^L_cap = 0 and the mass check the
        // StableCompact circuit proves the overflow and certifies the lossy
        // state (the first `cap` survivors, the last survivor's mass lost).
        let weak = StableChecks { alive_cap: false, mass: false, ..StableChecks::ALL };
        let p = with_stable_checks(weak, || {
            let mut leaf = stable_leaf(params, Expose::None, CommitMode::Plain);
            ALLOW_OVERFLOW.with(|c| c.set(Some(true)));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                leaf.prove_epoch_at(2, full.clone(), over.clone())
            }));
            ALLOW_OVERFLOW.with(|c| c.set(None));
            r
        })
        .expect("control: the overflow proves once both overflow checks are removed");
        assert_eq!(p.final_.0, commit_gk2_state(&err.lossy_state).0, "control certifies the lossy state");
    }

    /// An odd `cap + m` table's unpaired last row is dropped by the parity-0
    /// rounds: when it is live (a full table) that is a lost survivor, now a
    /// hard error too (before M3 it vanished silently, mass and all).
    #[test]
    fn odd_full_table_drop_is_an_overflow() {
        let params = GkbParams { capacity: 4, batch: 1, s: 1000 };
        let mut st = Gk2State::empty(params);
        for v in [10u32, 20, 30, 40] {
            st = apply_batch2(&st, &[v]);
        }
        assert_eq!(st.actives().len(), 4);
        let err = try_apply_batch2(&st, &[50]).expect_err("a live unpaired row is lost");
        assert_eq!(err.unpaired_dropped, 1);
        assert_eq!(err.survivors, 4, "the 5th row was dropped, not compacted");
        assert!(err.lossy_state.actives().iter().map(|t| t.mass()).sum::<u64>() < err.n_t);
        assert!(err.to_string().contains("capacity"));
        // A non-full odd table is unaffected.
        let mut st = Gk2State::empty(params);
        st = apply_batch2(&st, &[10]);
        assert_eq!(try_apply_batch2(&st, &[5]).map(|s| s.actives().len()), Ok(2));
    }

    // ── Equivalence: StableCompact == SortedCopy == native apply_batch2 ──

    /// The input patterns of the equivalence chains.
    #[derive(Clone, Copy, Debug)]
    enum Pattern {
        /// Windows of the real AOL key stream (`data/aol.keys`), through
        /// the harness's `gk_vals_of` (21-bit values, pads stripped).
        Aol,
        /// Windows of the frozen uniform stream (`data/uniform.keys`).
        Uniform,
        /// Increasing values (random start and step).
        Ascending,
        /// Decreasing values.
        Descending,
        /// A triangle wave: up `p` steps then down `p` (repeats values).
        Zigzag,
        /// Alternately from both ends of a range, converging to its middle.
        OutsideIn,
    }

    /// The `len`-value stream of one chain in `pat`.
    fn pattern_stream(pat: Pattern, len: usize, rng: &mut Lcg) -> Vec<u32> {
        use crate::experiments::stream_compose::gk_vals_of;
        let window = |keys: &[u32], rng: &mut Lcg| -> Vec<u32> {
            let off = rng.below((keys.len() - len - 1) as u64) as usize;
            gk_vals_of(&keys[off..off + len])
        };
        let base = rng.below(1 << 20) as u32;
        let step = 1 + rng.below(5) as u32;
        match pat {
            Pattern::Aol => window(&crate::dataset::aol().expect("data/aol.keys"), rng),
            Pattern::Uniform => window(&crate::dataset::uniform().expect("data/uniform.keys"), rng),
            Pattern::Ascending => (0..len as u32).map(|i| base + i * step).collect(),
            Pattern::Descending => (0..len as u32).map(|i| (base + len as u32 * step) - i * step).collect(),
            Pattern::Zigzag => {
                let p = 2 + rng.below(4) as u32;
                (0..len as u32)
                    .map(|i| {
                        let ph = i % (2 * p);
                        base + step * if ph < p { ph } else { 2 * p - ph }
                    })
                    .collect()
            }
            Pattern::OutsideIn => (0..len as u32)
                .map(|i| if i % 2 == 0 { base + (i / 2) * step } else { base + 2 * len as u32 * step - (i / 2) * step })
                .collect(),
        }
    }

    type LeafKey = (usize, usize, u64, bool, GkRounds);

    /// **Equivalence of the two round certifications on `chains` short
    /// chained streams of pattern `pat`**: every batch is proved from the
    /// running native state by the SortedCopy and the StableCompact leaf
    /// (Interval statement; Plain and Hiding chains alternate), both proofs
    /// self-verify, they expose the SAME statement (init, final, interval
    /// digest), and it is `Com` of the native `try_apply_batch2` chain. A
    /// step that overflows natively is refused by both leaves and ends the
    /// chain. Returns `(chains, proved batches, overflows)`.
    fn equivalence_chains(pat: Pattern, chains: usize, seed: u64) -> (usize, usize, usize) {
        use crate::recursion::recursive::expose_forest::read_exposed_statement;
        const SHAPES: [(usize, usize, u64); 6] = [(8, 4, 1), (8, 8, 2), (12, 4, 2), (16, 8, 3), (6, 2, 1), (16, 4, 1)];
        let gk = CommitFamily::GreenwaldKhanna;
        let mut rng = Lcg(seed);
        let mut leaves: std::collections::HashMap<LeafKey, Gkb2LeafCircuit> = std::collections::HashMap::new();
        let (mut batches, mut overflows) = (0usize, 0usize);
        for c in 0..chains {
            let (cap, m, s) = SHAPES[rng.below(SHAPES.len() as u64) as usize];
            let params = GkbParams { capacity: cap, batch: m, s };
            let hiding = c % 2 == 1;
            let mode = if hiding { CommitMode::Hiding } else { CommitMode::Plain };
            let salt_seed = SaltSeed::for_tests(seed ^ c as u64);
            let steps = 2 + rng.below(3) as usize;
            let sizes: Vec<usize> = (0..steps)
                .map(|_| if rng.below(8) == 0 { rng.below(m as u64) as usize } else { m })
                .collect();
            let stream = pattern_stream(pat, sizes.iter().sum::<usize>() + 1, &mut rng);
            let mut st = Gk2State::empty(params);
            let mut pos = 0usize;
            for (i, &k) in sizes.iter().enumerate() {
                let t = i as u64 + 1;
                let vals: Vec<u32> = stream[pos.min(stream.len())..(pos + k).min(stream.len())].to_vec();
                pos += k;
                let o = if hiding { Openings::for_leaf(&salt_seed, gk, t) } else { Openings::plain() };
                let mut prove = |rounds: GkRounds, st: &Gk2State| {
                    let leaf = leaves.entry((cap, m, s, hiding, rounds)).or_insert_with(|| {
                        build_gkb2_leaf_rounds(params, Expose::Interval, Binding::Semantic, mode, rounds)
                    });
                    let st = st.clone();
                    let vals = vals.clone();
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if hiding {
                            leaf.prove_epoch_commit(t, st, vals, &o)
                        } else {
                            leaf.prove_epoch_at(t, st, vals)
                        }
                    }))
                };
                match try_apply_batch2(&st, &vals) {
                    Ok(next) => {
                        let ps = prove(GkRounds::SortedCopy, &st).expect("SortedCopy leaf proves");
                        let pg = prove(GkRounds::StableCompact, &st).expect("StableCompact leaf proves");
                        let (ss, sg) = (read_exposed_statement(&ps.output.0), read_exposed_statement(&pg.output.0));
                        let ctx = format!("{pat:?} chain {c} t={t} cap={cap} m={m} s={s} hiding={hiding}");
                        assert_eq!(sg.values(), ss.values(), "{ctx}: exposed statements differ");
                        let want_init = commit_gk2_state_with(&st, mode, &o.init).0;
                        let want_final = commit_gk2_state_with(&next, mode, &o.final_).0;
                        assert_eq!(sg.init, want_init.to_vec(), "{ctx}: exposed init != Com(native S_(t-1))");
                        assert_eq!(sg.final_, want_final.to_vec(), "{ctx}: exposed final != Com(native S_t)");
                        assert_eq!(pg.batch_commit.0, ps.batch_commit.0, "{ctx}: batch commitments differ");
                        st = next;
                        batches += 1;
                    }
                    Err(_) => {
                        assert!(prove(GkRounds::SortedCopy, &st).is_err(), "SortedCopy must refuse an overflow");
                        assert!(prove(GkRounds::StableCompact, &st).is_err(), "StableCompact must refuse an overflow");
                        overflows += 1;
                        break;
                    }
                }
            }
        }
        eprintln!("G1 equivalence {pat:?}: {chains} chains, {batches} batches proved by both leaves, {overflows} overflow-terminated");
        (chains, batches, overflows)
    }

    /// 80 chains per pattern, 480 in all (the M3 functional gate). All six
    /// together: `cargo test --release --lib -- stable_tests::g1_equivalence`
    /// (about 8 min on the 32-core box, 1,436 batches proved by both leaves).
    const EQ_CHAINS: usize = 80;

    #[test]
    fn g1_equivalence_aol() {
        let (c, b, _) = equivalence_chains(Pattern::Aol, EQ_CHAINS, 0xA01);
        assert!(c == EQ_CHAINS && b >= 2 * EQ_CHAINS);
    }

    #[test]
    fn g1_equivalence_uniform() {
        let (c, b, _) = equivalence_chains(Pattern::Uniform, EQ_CHAINS, 0xB02);
        assert!(c == EQ_CHAINS && b >= 2 * EQ_CHAINS);
    }

    #[test]
    fn g1_equivalence_ascending() {
        let (c, b, _) = equivalence_chains(Pattern::Ascending, EQ_CHAINS, 0xC03);
        assert!(c == EQ_CHAINS && b >= 2 * EQ_CHAINS);
    }

    #[test]
    fn g1_equivalence_descending() {
        let (c, b, _) = equivalence_chains(Pattern::Descending, EQ_CHAINS, 0xD04);
        assert!(c == EQ_CHAINS && b >= 2 * EQ_CHAINS);
    }

    #[test]
    fn g1_equivalence_zigzag() {
        let (c, b, _) = equivalence_chains(Pattern::Zigzag, EQ_CHAINS, 0xE05);
        assert!(c == EQ_CHAINS && b >= 2 * EQ_CHAINS);
    }

    #[test]
    fn g1_equivalence_outside_in() {
        let (c, b, _) = equivalence_chains(Pattern::OutsideIn, EQ_CHAINS, 0xF06);
        assert!(c == EQ_CHAINS && b >= 2 * EQ_CHAINS);
    }

    /// Every [`StableChecks`] switch is CLEAN: with exactly that check removed
    /// the leaf still builds and proves an honest chained epoch with fusions
    /// in both directions (no bus imbalance, no missing creator), and its VK
    /// differs from the full circuit's (the switch removes something). The
    /// attack suite builds its positive controls with these switches.
    #[test]
    fn g1_stable_check_switches_are_clean() {
        let params = GkbParams { capacity: 16, batch: 8, s: 3 };
        let b1 = vec![100u32, 400, 200, 700, 300, 600, 500, 800];
        let b2 = vec![150u32, 650, 250, 750, 350, 550, 450, 850];
        let s1 = apply_batch2(&Gk2State::empty(params), &b1);
        let s2 = apply_batch2(&s1, &b2);
        let full_vk = stable_leaf(params, Expose::Interval, CommitMode::Plain).vk_pin_values();
        for &name in StableChecks::names() {
            with_stable_checks(StableChecks::without(name), || {
                let mut leaf = stable_leaf(params, Expose::Interval, CommitMode::Plain);
                assert_ne!(leaf.vk_pin_values(), full_vk, "switch {name} removes nothing");
                let p = leaf.prove_epoch_at(2, s1.clone(), b2.clone());
                assert_eq!(p.final_.0, commit_gk2_state(&s2).0, "switch {name}: honest proof");
            });
        }
        assert_eq!(stable_checks(), StableChecks::ALL, "the switches are restored");
    }

    fn fnv(vals: impl IntoIterator<Item = u64>) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for v in vals {
            for b in v.to_le_bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        h
    }

    fn fnv_vals(v: &[Val]) -> u64 {
        use p3_field::PrimeField32;
        fnv(v.iter().map(|x| x.as_canonical_u32() as u64))
    }

    fn fnv_chals(v: &[Challenge]) -> u64 {
        use p3_field::{BasedVectorSpace, PrimeField32};
        fnv(v.iter().flat_map(|c| {
            <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                .iter()
                .map(|x| x.as_canonical_u32() as u64)
                .collect::<Vec<_>>()
        }))
    }

    /// **Byte-identity of what M3 must not move**: the genesis commitment
    /// `Com(S_0; 0)` (Plain and Hiding), the state and batch commitments and
    /// the packed tuple encoding of a fixed reachable state and batch, and
    /// the GK decoder VK, pinned to the values of the pre-M3 tree (main
    /// 23138f7; these functions are untouched by M3, so the values are the
    /// same on both trees). They do not depend on the round certification by
    /// construction; the decoder's pins live in `commitment::plain_vk_pins`.
    #[test]
    fn genesis_and_encodings_are_unchanged() {
        use crate::commitment::hiding::SaltBb;
        let params = GkbParams { capacity: 8, batch: 4, s: 2 };
        let s0 = Gk2State::empty(params);
        let b1 = vec![17u32, 3, 99, 41];
        let s1 = apply_batch2(&s0, &b1);
        let b2 = vec![5u32, 64];
        let s2 = apply_batch2(&s1, &b2);
        let salt = Openings::for_leaf(&SaltSeed::for_tests(2026), CommitFamily::GreenwaldKhanna, 2);
        let got = [
            fnv_vals(&commit_gk2_state(&s0).0),
            fnv_vals(&commit_gk2_state_with(&s0, CommitMode::Hiding, &SaltBb::ZERO).0),
            fnv_vals(&commit_gk2_state(&s2).0),
            fnv_vals(&commit_gk2_state_with(&s2, CommitMode::Hiding, &salt.final_).0),
            fnv_vals(&commit_gk2_batch(&b2, 4, s1.n).0),
            fnv_vals(&commit_gk2_batch_with(&b2, 4, s1.n, CommitMode::Hiding, &salt.batch).0),
            fnv_chals(&pack_tuples2(&s2.tuples)),
            fnv_chals(&pack_tuples2(&fresh_tuples2(&b2, 4, s1.n))),
        ];
        // [Com(S_0) plain, Com(S_0; 0) hiding, Com(S_2) plain, Com(S_2; ρ)
        // hiding, Com(B_2) plain, Com(B_2; ρ) hiding, pack(S_2), pack(B_2)],
        // recorded on main 23138f7 (an export of that tree, the same probe).
        const PINS: [u64; 8] = [
            0x7479_190e_eb29_aadb,
            0xa98d_b582_4b84_3597,
            0xf0c4_b6ec_cad4_6be4,
            0xde96_30a8_1eb5_b895,
            0xb3ea_4435_4836_6dc0,
            0x6bd7_8344_08ab_6d20,
            0x71eb_2dac_e5df_d04d,
            0xb009_e636_ad22_4b83,
        ];
        assert_eq!(got, PINS, "genesis / state / batch encodings moved: {got:#018x?}");
    }
    /// **G-base at the deployed shapes**: the SortedCopy leaf (through both the
    /// pre-M3 builder and `build_gkb2_leaf_rounds(.., SortedCopy)`) and the GK
    /// decoder keep their VKs byte for byte at cap 384 / m 128 and cap 768 /
    /// m 512 (s 51, Interval, Semantic; Plain and Hiding leaves, Hiding
    /// decoder). The literals were recorded on an export of main 23138f7
    /// (the pre-M3 tree) with the same fingerprint; `zk` build only.
    #[cfg(feature = "zk")]
    #[test]
    fn sorted_leaf_and_decoder_deployed_vks_are_unchanged() {
        use crate::decode::gk_bandmerge::{gk2_decode_vk_commit, Gkb2DecodeParams};
        use crate::decode::ReleasePolicy;
        // (cap, m) -> (Plain leaf, Hiding leaf, Hiding decoder).
        const PINS: [((usize, usize), [u64; 3]); 2] = [
            ((384, 128), [0x4ffc_6719_9b31_bf9b, 0x4866_3b08_7e9f_e266, 0x3a62_d7ed_6d96_45e3]),
            ((768, 512), [0x8f81_be07_530b_7cbe, 0x4e0c_9b44_17c4_db9c, 0xbdbf_480c_d567_7445]),
        ];
        for ((cap, m), pins) in PINS {
            let p = GkbParams { capacity: cap, batch: m, s: 51 };
            for (mode, pin) in [(CommitMode::Plain, pins[0]), (CommitMode::Hiding, pins[1])] {
                let old = build_gkb2_leaf_commit(p, Expose::Interval, Binding::Semantic, mode).vk_pin_values();
                let new = build_gkb2_leaf_rounds(p, Expose::Interval, Binding::Semantic, mode, GkRounds::SortedCopy)
                    .vk_pin_values();
                assert_eq!(fnv_chals(&old), pin, "cap {cap} m {m} {mode:?}: SortedCopy leaf VK moved");
                assert_eq!(new, old, "cap {cap} m {m} {mode:?}: build_gkb2_leaf_rounds(SortedCopy) != the pre-M3 builder");
            }
            let dvk = gk2_decode_vk_commit(
                Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity },
                Binding::Semantic,
                CommitMode::Hiding,
            );
            assert_eq!(fnv_chals(&dvk.commitment), pins[2], "cap {cap}: GK decoder VK moved");
        }
    }
}
