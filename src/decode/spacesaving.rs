//! SpaceSaving **top-`c` query** decode circuit (E3, plonky3/STARK).
//!
//! Implements the paper's *SpaceSaving Top-`c` Query Circuit* (zk1.tex
//! §SpaceSaving Query Circuit). A top-`c` query returns the first `c` active
//! rows of the committed summary under the declared count/key order; \sys
//! answers queries against the closed (committed) state `S_t`. This is the
//! STARK-backend counterpart of the plonky2 `decode::spacesaving` relation.
//!
//! The committed state is an [`SsFullState`] (the same row table the
//! `ss_final_full` update circuit recommits). Its rows are kept in
//! `(active asc, count asc)` order (dummies first, then actives by **ascending**
//! count), so the **top heavy hitters** (highest counts) are the *last* active
//! rows. This decode is unchanged by the update circuit's Misra-Gries
//! `(s+1)`-th-value subtraction: subtracting a constant `τ` from every retained
//! count preserves the count order and the dummies-first layout. The counts it
//! returns (and any released top-`c` mass) are therefore the summary's
//! Misra-Gries **under-estimates** (per-key deficit `≤ N/s`), not exact grouped
//! sums; a `Threshold(θ)` release is evaluated against that under-estimated mass.
//! Each row packs into one `Challenge` as the 4 base coefficients
//! `[key_lo, key_hi, count, active]`, and `commit_ss_state` is the flat
//! Poseidon2 over those rows; `pack_cells` here reproduces that exact
//! flattening so the in-circuit `add_hash_slice` binds the opened cells to the
//! published digest.
//!
//! ### Verification target (paper)
//!
//! Public input is the query size `c`. With `#active = #{active rows}` and
//! `k = min(c, #active)`, the released result table `res` is the first `k`
//! rows of `S_t` under the declared (top-count-first) order, with canonical
//! dummy rows beyond position `k`. For the identity release policy the circuit
//! binds the published answer to `res` (here: the released top-`c` mass
//! `Σ res[z].count`, a deterministic function of the fully-pinned `res`).
//!
//! ### Checks
//!
//! 1. **State opening** — re-hash the `capacity` packed rows, bind to the
//!    committed digest (the `Θ(s)` cost).
//! 2. **Active-prefix structure** — active flags are monotone (here a
//!    contiguous *suffix*: dummies first, actives last).
//! 3. **Distinct-key** — adjacent active rows carry distinct keys (the
//!    grouped summary has no duplicate retained keys); witnessed inverse.
//! 4. **Sortedness** — counts are non-decreasing along the stored order
//!    (range-checked adjacent diff); equivalently the top heavy hitters are
//!    the trailing rows.
//! 5. **Top-`c` selection** — a monotone 0/1 selector `sel` marks exactly
//!    `k = min(c, #active)` rows as released: a *suffix* of the row array
//!    (the highest-count actives), each selected row active, and
//!    `Σ sel = min(c, #active)`.
//! 6. **Release binding** — for identity release `answer = Σ sel·count`
//!    (the released top-`c` mass); for `Threshold(θ)` the mass is gated by
//!    `mass ≥ θ` (same `≥` semantics as the other decode leaves).
//!
//! Scope: keys must fit in one BabyBear limb (`key_hi = 0`, `key < 2^31`),
//! matching `ss_final_full`. Counts/mass fit in `DIFF_BITS − 1` bits at
//! prototype scale. The query size `c` is a verifier-supplied public input.
//!
//! Hiding commitments (revision B2): [`prove_ss_decode_commit`] opens
//! `Com(S_t; ρ)` ([`crate::sketch::ss_final_full::commit_ss_state_with`]),
//! with the salt as the first private input, and is pinned to
//! [`ss_decode_vk_commit`]; the pre-B2 entry points stay `Plain`.

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;

use crate::commitment::hiding::{self, CommitFamily, CommitKind, CommitMode, SaltBb};
use crate::config::{Challenge, Val};
use crate::decode::{DecodeProof, DecodeVk, ReleasePolicy, StdDecodeCircuit};
use crate::recursion::recursive::countmin_leaf::{DIGEST_PACKING, pack_commit_to_challenge};
use crate::sketch::bind::{self, Binding};
use crate::sketch::ss_final_full::{SsFullParams, SsFullRow, SsFullState, commit_ss_state_with};

/// Range-check window for non-negative diffs (count sortedness, the `c −
/// Σsel ≥ 0` selection bound, and the threshold gate). Counts/`c`/mass fit in
/// `DIFF_BITS − 1` bits at prototype scale; a "negative" diff wraps past `2^p`
/// and overflows the check (sound `>= 0`).
const DIFF_BITS: usize = 22;

#[derive(Copy, Clone, Debug)]
pub struct SsDecodeParams {
    pub capacity: usize,
    /// Query size `c` — release the top-`c` heavy hitters by count.
    pub c: usize,
    pub release: ReleasePolicy,
}

impl SsDecodeParams {
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity must be positive, got {}", self.capacity);
        assert!(self.c >= 1, "query size c must be positive, got {}", self.c);
    }
}

/// Pack a SpaceSaving state's rows into Challenge elements (one row / Challenge,
/// 4 base coeffs `[key_lo, key_hi, count, active]`), matching
/// `commit_ss_state`'s flattening and the committed digest.
fn pack_cells(state: &SsFullState) -> Vec<Challenge> {
    state
        .rows
        .iter()
        .map(|r| {
            let lo = (r.key & 0xFFFF_FFFF) as u32;
            let hi = (r.key >> 32) as u32;
            let coeffs =
                [Val::from_u32(lo), Val::from_u32(hi), Val::from_u32(r.count), Val::from_u32(r.active)];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

/// Native top-`c` selection over a stored SpaceSaving state.
///
/// The state rows are in `(active asc, count asc)` order, so the top heavy
/// hitters by count are the trailing rows. Returns, for each row index, a 0/1
/// selector marking the released top-`min(c, #active)` rows (a suffix of the
/// row array), together with the released mass `Σ selected count`.
fn native_select(state: &SsFullState, c: usize) -> (Vec<u32>, u64) {
    let cap = state.rows.len();
    let n_active = state.rows.iter().filter(|r| r.active == 1).count();
    let k = c.min(n_active);
    // Select the trailing `k` rows (the highest-count actives). Because the
    // active rows form the suffix and are count-ascending, the last `k` rows
    // are exactly the top-`k` heavy hitters.
    let mut sel = vec![0u32; cap];
    for r in (0..cap).rev().take(k) {
        sel[r] = 1;
    }
    let mass: u64 = (0..cap).filter(|&r| sel[r] == 1).map(|r| state.rows[r].count as u64).sum();
    (sel, mass)
}

/// Prove a SpaceSaving top-`c` query decode. Returns a [`DecodeProof`]; the
/// prover self-verifies and records the witness/prove/verify split via
/// [`crate::recursion::recursive::timing`]. The `answer` is the released
/// top-`c` mass (the identity image of the `res` table) under the release
/// policy. Uses the process-default [`Binding`] ([`bind::default_binding`]).
pub fn prove_ss_decode(params: SsDecodeParams, state: SsFullState, c: usize) -> DecodeProof {
    prove_ss_decode_with(params, state, c, bind::default_binding())
}

/// [`prove_ss_decode`] with an explicit [`Binding`].
///
/// `Semantic` / `Bound` surface the query statement `(Com(S), c, answer)`
/// through the Expose NPO (16 base values: commit[8], c[4], answer[4]; read
/// it with [`crate::decode::read_exposed_statement`]), so the verifier learns
/// which state was queried, with which `c`, and what the certified answer is
/// (Property 3). [`Binding::Legacy`] is the pre-fix circuit, byte-for-byte:
/// it exposes nothing, so its proof certifies an answer the verifier never
/// sees. This decoder has no in-circuit coefficient re-binding (it relies on
/// the merged fork's `recompose/coeff` binding), so `Bound` builds the same
/// circuit as `Semantic`.
pub fn prove_ss_decode_with(
    params: SsDecodeParams,
    state: SsFullState,
    c: usize,
    binding: Binding,
) -> DecodeProof {
    prove_ss_decode_commit(params, state, c, binding, CommitMode::Plain, &SaltBb::ZERO)
}

/// [`prove_ss_decode_with`] against a commitment made under `mode` (revision
/// B2, [`crate::commitment::hiding`]). `Plain` is the pre-B2 circuit byte for
/// byte (`salt` ignored). Under `Hiding` the decoder opens
/// `Com(S_t; ρ) = commit_ss_state_with(state, Hiding, salt)`: the salt is the
/// FIRST 3 private inputs, and (under `Semantic`/`Bound`) the exposed
/// commitment is the hiding one. For a query at version `t` of history `h`
/// the honest salt is `rho_state_bb_in(seed, CommitFamily::SpaceSaving, h,
/// t)` (`rho_state_bb(seed, .., t)` in the genesis history), the same
/// randomizer leaf `t` closed its final state with; at `t = 0` it is the
/// public zero in the genesis history and the anchor salt in a continued one.
/// So under `Hiding` the public zero salt opens only the empty genesis state
/// ([`SsFullState::empty`], every row the dummy; the one state commitment,
/// `Com(S_0; 0)`, that the verifier recomputes itself): handed
/// [`SaltBb::ZERO`] with any other state (a forgotten salt at `t ≥ 1`) the
/// decoder panics instead of publishing the guess-checkable `Com(S_t; 0)`.
/// A nonzero wrong salt still proves (the circuit does not check the
/// derivation) and exposes a commitment that is not the log's. Pin the proof
/// to [`ss_decode_vk_commit`] with the same `mode`.
pub fn prove_ss_decode_commit(
    params: SsDecodeParams,
    state: SsFullState,
    c: usize,
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> DecodeProof {
    build_ss_decode_commit(params, &state, c, binding, mode, salt).prove("ss decode")
}

/// The trusted verification key of the SpaceSaving top-`c` decoder for
/// `params` under `binding`, derived from public parameters only (a proof over
/// the empty state; the circuit does not depend on the state). Pin query
/// proofs to it with [`crate::decode::verify_decode_proof`]. The Plain
/// decoder's VK (= [`ss_decode_vk_commit`] with [`CommitMode::Plain`]).
pub fn ss_decode_vk(params: SsDecodeParams, binding: Binding) -> DecodeVk {
    let empty = SsFullState::empty(SsFullParams { capacity: params.capacity, batch: 1 });
    build_ss_decode(params, &empty, params.c, binding).derive_vk("ss decode")
}

/// [`ss_decode_vk`] of the decoder built under `mode`: `Plain` is exactly
/// [`ss_decode_vk`]; `Hiding` is the VK of every [`prove_ss_decode_commit`]
/// proof under `Hiding` (the salt is a witness, so the VK does not depend on
/// it; it is derived with the public zero salt over the empty state).
pub fn ss_decode_vk_commit(params: SsDecodeParams, binding: Binding, mode: CommitMode) -> DecodeVk {
    let empty = SsFullState::empty(SsFullParams { capacity: params.capacity, batch: 1 });
    build_ss_decode_commit(params, &empty, params.c, binding, mode, &SaltBb::ZERO).derive_vk("ss decode")
}

/// Build the SpaceSaving top-`c` decode circuit and its witness (Plain
/// commitment).
pub(crate) fn build_ss_decode(
    params: SsDecodeParams,
    state: &SsFullState,
    c: usize,
    binding: Binding,
) -> StdDecodeCircuit {
    build_ss_decode_commit(params, state, c, binding, CommitMode::Plain, &SaltBb::ZERO)
}

/// [`build_ss_decode`] against a commitment made under `mode` with `salt`
/// (see [`prove_ss_decode_commit`]).
pub(crate) fn build_ss_decode_commit(
    params: SsDecodeParams,
    state: &SsFullState,
    c: usize,
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> StdDecodeCircuit {
    let expose = binding.is_bound();
    params.validate();
    assert_eq!(c, params.c, "c argument must match params.c");
    let SsDecodeParams { capacity: cap, c: _c, release } = params;
    assert_eq!(state.rows.len(), cap, "state capacity must match params");
    if mode.is_hiding() && salt.is_zero() {
        assert!(
            state.rows.iter().all(|r| *r == SsFullRow::dummy()),
            "Hiding SS decode: the public zero salt opens only the empty genesis state Com(S_0; 0); \
             a query at t >= 1 (or at version 0 of a continued history) needs its real salt"
        );
    }

    // ─── Native decode ───────────────────────────────────────────────────
    let commit = commit_ss_state_with(state, mode, salt);
    let (sel_native, mass) = native_select(state, c);
    let answer = release.apply(mass);

    // ─── Build circuit ───────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    if expose {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    // PIs: committed state, query size c, released answer.
    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let c_pi = b.alloc_public_input("c");
    let answer_pi = b.alloc_public_input("answer");
    if expose {
        b.add_expose(&[commit_pis[0], commit_pis[1], c_pi, answer_pi])
            .expect("expose (commit, c, answer)");
    }
    b.tag(answer_pi, "ss_dec_answer").expect("tag");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let neg_one = b.alloc_const(-Challenge::ONE, "neg_one");

    // Private witnesses. B2: under `Hiding` the salt of `Com(S_t)` comes
    // first (3 private inputs); `Plain` allocates nothing.
    let salt_t = mode.is_hiding().then(|| hiding::alloc_salt_targets(&mut b));
    let cells_packed: Vec<ExprId> =
        (0..cap).map(|_| b.alloc_private_input("cell_packed")).collect();
    // sel[r] ∈ {0,1}: the top-c selector (released-row indicator).
    let sel: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("sel")).collect();
    // key_inv[r]: inverse of (key[r+1] − key[r]) for the distinct-key check.
    let key_inv: Vec<ExprId> = (0..cap.saturating_sub(1)).map(|_| b.alloc_private_input("key_inv")).collect();
    let flag = if matches!(release, ReleasePolicy::Threshold(_)) {
        Some(b.alloc_private_input("flag"))
    } else {
        None
    };

    // ── Check 1: open the committed state ──
    // Salted under `Hiding` (`[tag, salt…, rows…]`). The decoder's sponge is
    // the plain `add_hash_slice` under every binding, which is
    // `commit_hash(.., None, .., Binding::Semantic)`. So, in both modes and
    // unlike Count-Min, `Binding::Bound` does NOT select the zero-IV
    // `bind::hash_slice_bound` here: the first row's IV rests on the fork's
    // own Poseidon2 IV binding, exactly as in the Plain decoder (whose
    // Semantic and Bound VKs are equal).
    let digest = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &Poseidon2Config::BABY_BEAR_D4_W16,
        CommitKind::State,
        CommitFamily::SpaceSaving,
        salt_t.as_ref(),
        &cells_packed,
        zero,
        Binding::Semantic,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }
    // Decompose each packed row into [key_lo, key_hi, count, active]. Every
    // decompose output that we constrain must flow through an ALU op as the
    // LHS at least once (WitnessChecks discipline), or the prover panics with
    // "GlobalCumulativeMismatch: WitnessChecks". We put each cell coeff FIRST
    // in the muls that consume it below.
    let fields: Vec<Vec<ExprId>> = cells_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose row"))
        .collect();

    // Every decompose coeff is a HINT: it gets its WitnessChecks bus creator
    // ONLY from its first use as an ALU `a`-operand (lhs); used only as a `b`
    // (rhs) it is never created, and used as BOTH operands of one op (e.g.
    // `mul(coeff, coeff)`) it is double-created. Either way the global LogUp
    // bus unbalances (GlobalCumulativeMismatch). So we lift each coeff to a
    // bus-safe ALU copy `coeff·1` exactly once (created cleanly as the `a`-
    // operand, `one` being a const) and build EVERY downstream relation on
    // those copies. `key_hi` is additionally pinned to 0 (single-limb keys).
    let klo: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][0], one)).collect();
    let cnt: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][2], one)).collect();
    let act: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][3], one)).collect();
    for r in 0..cap {
        let key_hi_l = b.mul(fields[r][1], one);
        b.connect(key_hi_l, zero);
    }

    // WitnessChecks bus note (applies to every boolean check below): an ALU op
    // that reads the SAME witness on both the `a` and `b` lanes (e.g.
    // `mul(x, x)`) double-counts it on the global LogUp bus and unbalances it
    // (GlobalCumulativeMismatch). So every `x·x` is written as `x·(x − 1) = 0`
    // with a fresh `x − 1` sub output, reading `x` once per op.

    // ── Check 2: active-prefix structure (active monotone non-decreasing) ──
    // Stored order puts dummies first, actives last → actives form a suffix.
    // active ∈ {0,1} and active[r] ≤ active[r+1].
    for r in 0..cap {
        // active ∈ {0,1}: act·(act − 1) = 0 (distinct operands; see note).
        let a = act[r];
        let a_m1 = b.sub(a, one);
        let bchk = b.mul(a, a_m1);
        b.connect(bchk, zero);
    }
    for r in 0..cap - 1 {
        // active[r+1] − active[r] ∈ {0,1}  ⇒ monotone non-decreasing.
        let neg_ar = b.mul(act[r], neg_one);
        let d = b.add(act[r + 1], neg_ar);
        let one_minus = b.sub(one, d); // const lhs → forward
        let prod = b.mul(d, one_minus);
        b.connect(prod, zero);
    }

    // ── Check 4: sortedness — counts non-decreasing along the stored order ──
    // count[r+1] − count[r] ≥ 0, range-checked (dummies have count 0 so the
    // dummy→active boundary is also non-negative; no gating needed).
    for r in 0..cap - 1 {
        let neg_cr = b.mul(cnt[r], neg_one);
        let cdiff = b.add(cnt[r + 1], neg_cr); // count[r+1] − count[r]
        let _ = b.add_range_bits::<Val>(cdiff, DIFF_BITS).expect("count sortedness");
    }

    // ── Check 3: distinct-key on adjacent ACTIVE rows ──
    // If active[r]·active[r+1] = 1 then key[r+1] ≠ key[r]. With kdiff =
    // key[r+1] − key[r] and witnessed inverse `key_inv[r]`, force
    //   active[r]·active[r+1]·(1 − kdiff·inv) = 0.
    // (When both active, the only way the product vanishes is kdiff·inv = 1,
    // i.e. kdiff ≠ 0.)
    for r in 0..cap - 1 {
        let neg_klo = b.mul(klo[r], neg_one);
        let kdiff = b.add(klo[r + 1], neg_klo); // key_lo[r+1] − key_lo[r]
        let kd_inv = b.mul(kdiff, key_inv[r]);
        let one_minus = b.sub(one, kd_inv); // 1 − kdiff·inv
        let both_active = b.mul(act[r], act[r + 1]);
        let dchk = b.mul(both_active, one_minus);
        b.connect(dchk, zero);
    }

    // ── Check 5: top-c selection ──
    // sel[r] ∈ {0,1}; sel monotone non-decreasing (a suffix); sel ≤ active;
    // Σ sel = min(c, #active).
    //
    // `sel[r]` is a private input. Its mandatory bus creator must come from a
    // SINGLE ALU use as the `a`-operand (lhs). We lift each `sel[r]` to a
    // bus-safe ALU copy `sv[r] = sel[r]·1` (created cleanly as the `a`-operand,
    // `one` being a const), then build the relation on `sv`.
    let sv: Vec<ExprId> = (0..cap).map(|r| b.mul(sel[r], one)).collect();
    for r in 0..cap {
        let s = sv[r];
        // sv ∈ {0,1}: sv·(sv − 1) = 0 (distinct operands; see note).
        let s_m1 = b.sub(s, one);
        let bchk = b.mul(s, s_m1);
        b.connect(bchk, zero);
        // sel ≤ active: sv·(1 − active) = 0 (no selecting a dummy).
        let one_minus_a = b.sub(one, act[r]); // const lhs → forward
        let sel_outside = b.mul(s, one_minus_a);
        b.connect(sel_outside, zero);
    }
    // sv monotone non-decreasing: sv[r+1] − sv[r] ∈ {0,1}.
    for r in 0..cap - 1 {
        let neg_sr = b.mul(sv[r], neg_one);
        let d = b.add(sv[r + 1], neg_sr);
        let one_minus = b.sub(one, d);
        let prod = b.mul(d, one_minus);
        b.connect(prod, zero);
    }
    // n_active = Σ active[r]; sum_sel = Σ sv[r].
    let mut n_active_e = b.mul(act[0], one);
    for r in 1..cap {
        let t = b.mul(act[r], one);
        n_active_e = b.add(n_active_e, t);
    }
    let mut sum_sel_e = b.mul(sv[0], one);
    for r in 1..cap {
        let t = b.mul(sv[r], one);
        sum_sel_e = b.add(sum_sel_e, t);
    }
    // Σ sel = min(c, #active):
    //   c − Σsel ≥ 0   (range-checked; needs sum_sel as a forward `a`-operand)
    //   (c − Σsel)·(#active − Σsel) = 0   (one bound is tight)
    // Combined with sel ≤ active (⇒ Σsel ≤ #active), this pins Σsel = min.
    let neg_sum_sel = b.mul(sum_sel_e, neg_one);
    let c_minus_sel = b.add(c_pi, neg_sum_sel); // c − Σsel  (forward)
    let _ = b.add_range_bits::<Val>(c_minus_sel, DIFF_BITS).expect("c − Σsel ≥ 0");
    let act_minus_sel = b.add(n_active_e, neg_sum_sel); // #active − Σsel (forward)
    let prod = b.mul(c_minus_sel, act_minus_sel);
    b.connect(prod, zero);

    // ── released mass = Σ sel·count ──
    let mut mass_e = b.mul(cnt[0], sv[0]); // count copy FIRST
    for r in 1..cap {
        let t = b.mul(cnt[r], sv[r]);
        mass_e = b.add(mass_e, t);
    }
    // Decompose the mass to base coeffs so the release range checks are sound,
    // pinning the high coeffs to zero (single-limb mass at prototype scale).
    let massc = b.decompose_ext_to_base_coeffs::<Val>(mass_e).expect("decompose mass");
    let mass_b = massc[0];
    b.connect(massc[1], zero);
    b.connect(massc[2], zero);
    b.connect(massc[3], zero);

    // ── Check 6: release policy → answer ──
    match release {
        ReleasePolicy::Identity => {
            // mass coeff FIRST (LHS) so this decompose output gets a bus creator.
            let released = b.mul(mass_b, one);
            b.connect(released, answer_pi);
        }
        ReleasePolicy::Threshold(t) => {
            let fl = flag.unwrap();
            let mass_v = b.mul(mass_b, one);
            let neg_theta = b.alloc_const(-Challenge::from_u64(t), "neg_theta");
            let theta_m1 = b.alloc_const(Challenge::from_u64(t) - Challenge::ONE, "theta_m1");
            // fl ∈ {0,1}: fl·(fl−1) = 0. `sub(fl, one)` keeps fl as a fresh,
            // undefined private input → fl gets its bus creator here.
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            // chosen = fl·(mass−θ) + (1−fl)·(θ−1−mass) ≥ 0  ⇔  fl = [mass ≥ θ].
            let mass_minus_t = b.add(mass_v, neg_theta); // mass − θ (forward)
            let neg_mass = b.mul(mass_v, neg_one); // −mass
            let t_minus_mass_m1 = b.add(neg_mass, theta_m1); // (θ−1) − mass (forward)
            let nf = b.sub(one, fl); // 1 − fl (const lhs → forward)
            let a = b.mul(fl, mass_minus_t);
            let nft = b.mul(nf, t_minus_mass_m1);
            let chosen = b.add(a, nft);
            let _ = b.add_range_bits::<Val>(chosen, DIFF_BITS).expect("chosen >= 0");
            let released = b.mul(fl, mass_v);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build ss decode circuit");

    // ─── Pack public + private values ────────────────────────────────────
    let commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(commit.0));
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_u64(c as u64));
    public_inputs.push(Challenge::from_u64(answer));

    let mut private_inputs: Vec<Challenge> =
        if mode.is_hiding() { salt.packed().to_vec() } else { Vec::new() };
    private_inputs.extend(pack_cells(state));
    // sel
    for r in 0..cap {
        private_inputs.push(if sel_native[r] == 1 { Challenge::ONE } else { Challenge::ZERO });
    }
    // key_inv[r]: inverse of (key_lo[r+1] − key_lo[r]) when non-zero, else 0.
    for r in 0..cap.saturating_sub(1) {
        let lo = |k: u64| (k & 0xFFFF_FFFF) as u32;
        let d = Challenge::from_u64(lo(state.rows[r + 1].key) as u64)
            - Challenge::from_u64(lo(state.rows[r].key) as u64);
        private_inputs.push(if d == Challenge::ZERO { Challenge::ZERO } else { d.inverse() });
    }
    // flag (threshold only)
    if flag.is_some() {
        let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
        private_inputs.push(if mass >= t { Challenge::ONE } else { Challenge::ZERO });
    }

    StdDecodeCircuit::new(circuit, public_inputs, private_inputs, answer, expose, "ss decode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::ss_final_full::commit_ss_state;
    use crate::sketch::ss_final_full::{SsFullParams, apply_batch_ss_full, SsFullState, SsFullUpdate};

    /// Build a SpaceSaving state from a few updates via the native top-`s`
    /// pipeline. Distinct keys 101..104 with weights 1..4 (capacity 4, batch 4),
    /// so the stored rows are `[dummy?... , w=1, w=2, w=3, w=4]` ascending.
    fn state() -> SsFullState {
        let params = SsFullParams { capacity: 4, batch: 4 };
        let s0 = SsFullState::empty(params);
        let batch = vec![
            SsFullUpdate::real(101, 1),
            SsFullUpdate::real(102, 2),
            SsFullUpdate::real(103, 3),
            SsFullUpdate::real(104, 4),
        ];
        apply_batch_ss_full(&s0, &batch).0
    }

    /// Native top-`c` mass: sum of the `min(c, #active)` highest counts.
    fn native_topc_mass(st: &SsFullState, c: usize) -> u64 {
        let mut counts: Vec<u64> = st.rows.iter().filter(|r| r.active == 1).map(|r| r.count as u64).collect();
        counts.sort_unstable_by(|a, b| b.cmp(a)); // descending
        counts.into_iter().take(c).sum()
    }

    #[test]
    fn ss_decode_topc_all() {
        // c ≥ #active ⇒ releases the full mass (1+2+3+4 = 10).
        let st = state();
        assert_eq!(st.active_count(), 4);
        let native = native_topc_mass(&st, 4);
        assert_eq!(native, 10);
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 4, release: ReleasePolicy::Identity },
            st,
            4,
        );
        assert_eq!(p.answer, native, "top-c mass matches native");
    }

    #[test]
    fn ss_decode_topc_larger_than_active() {
        // c > #active ⇒ k = #active, still the full mass.
        let st = state();
        let native = native_topc_mass(&st, 10);
        assert_eq!(native, 10);
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 10, release: ReleasePolicy::Identity },
            st,
            10,
        );
        assert_eq!(p.answer, native);
    }

    #[test]
    fn ss_decode_top2() {
        // Top-2 heavy hitters: weights 4 + 3 = 7.
        let st = state();
        let native = native_topc_mass(&st, 2);
        assert_eq!(native, 7);
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Identity },
            st,
            2,
        );
        assert_eq!(p.answer, native, "top-2 mass = 4 + 3");
    }

    #[test]
    fn ss_decode_top1() {
        // Top-1 heavy hitter: weight 4.
        let st = state();
        let native = native_topc_mass(&st, 1);
        assert_eq!(native, 4);
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 1, release: ReleasePolicy::Identity },
            st,
            1,
        );
        assert_eq!(p.answer, native, "top-1 mass = 4");
    }

    #[test]
    fn ss_decode_threshold_suppresses() {
        // Top-1 mass = 4 < θ = 1000 ⇒ suppressed to 0.
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 1, release: ReleasePolicy::Threshold(1000) },
            state(),
            1,
        );
        assert_eq!(p.answer, 0, "mass below θ ⇒ released 0");
    }

    #[test]
    fn ss_decode_threshold_passes() {
        // Top-2 mass = 7 ≥ θ = 5 ⇒ released raw.
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Threshold(5) },
            state(),
            2,
        );
        assert_eq!(p.answer, 7, "mass 7 ≥ θ=5 ⇒ released raw");
    }

    /// Boundary: mass == θ must be released (the `≥` semantics).
    #[test]
    fn ss_decode_threshold_boundary() {
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Threshold(7) },
            state(),
            2,
        );
        assert_eq!(p.answer, 7, "mass 7 == θ=7 ⇒ released raw");
    }

    /// Soundness: a tampered answer public input must be rejected by the
    /// in-circuit relation (running the circuit fails the constraints).
    #[test]
    fn ss_decode_rejects_wrong_answer() {
        let st = state();
        let cap = 4usize;
        let c = 2usize;
        let commit = commit_ss_state(&st);
        let (sel_native, _mass) = native_select(&st, c);

        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = CircuitBuilder::<Challenge>::new();
            b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
                generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
                default_babybear_poseidon2_16(),
            );
            b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
            b.enable_range(generate_range_trace::<Val, Challenge>);
            let commit_pis: [ExprId; DIGEST_PACKING] =
                std::array::from_fn(|_| b.alloc_public_input("c"));
            let c_pi = b.alloc_public_input("c");
            let answer_pi = b.alloc_public_input("answer");
            let one = b.alloc_const(Challenge::ONE, "one");
            let zero = b.alloc_const(Challenge::ZERO, "zero");
            let neg_one = b.alloc_const(-Challenge::ONE, "neg_one");
            let cells_packed: Vec<ExprId> =
                (0..cap).map(|_| b.alloc_private_input("cell")).collect();
            let sel: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("sel")).collect();
            let key_inv: Vec<ExprId> =
                (0..cap - 1).map(|_| b.alloc_private_input("key_inv")).collect();
            let digest = b
                .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, true)
                .unwrap();
            for i in 0..DIGEST_PACKING {
                b.connect(digest[i], commit_pis[i]);
            }
            let fields: Vec<Vec<ExprId>> = cells_packed
                .iter()
                .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
                .collect();
            for r in 0..cap {
                let key_hi_l = b.mul(fields[r][1], one);
                b.connect(key_hi_l, zero);
            }
            let klo: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][0], one)).collect();
            let cnt: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][2], one)).collect();
            let act: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][3], one)).collect();
            for r in 0..cap {
                let a = act[r];
                let a_m1 = b.sub(a, one);
                let bchk = b.mul(a, a_m1);
                b.connect(bchk, zero);
            }
            for r in 0..cap - 1 {
                let neg_ar = b.mul(act[r], neg_one);
                let d = b.add(act[r + 1], neg_ar);
                let one_minus = b.sub(one, d);
                let prod = b.mul(d, one_minus);
                b.connect(prod, zero);
            }
            for r in 0..cap - 1 {
                let neg_cr = b.mul(cnt[r], neg_one);
                let cdiff = b.add(cnt[r + 1], neg_cr);
                let _ = b.add_range_bits::<Val>(cdiff, DIFF_BITS).unwrap();
            }
            for r in 0..cap - 1 {
                let neg_klo = b.mul(klo[r], neg_one);
                let kdiff = b.add(klo[r + 1], neg_klo);
                let kd_inv = b.mul(kdiff, key_inv[r]);
                let one_minus = b.sub(one, kd_inv);
                let both_active = b.mul(act[r], act[r + 1]);
                let dchk = b.mul(both_active, one_minus);
                b.connect(dchk, zero);
            }
            let sv: Vec<ExprId> = (0..cap).map(|r| b.mul(sel[r], one)).collect();
            for r in 0..cap {
                let s = sv[r];
                let s_m1 = b.sub(s, one);
                let bchk = b.mul(s, s_m1);
                b.connect(bchk, zero);
                let one_minus_a = b.sub(one, act[r]);
                let sel_outside = b.mul(s, one_minus_a);
                b.connect(sel_outside, zero);
            }
            for r in 0..cap - 1 {
                let neg_sr = b.mul(sv[r], neg_one);
                let d = b.add(sv[r + 1], neg_sr);
                let one_minus = b.sub(one, d);
                let prod = b.mul(d, one_minus);
                b.connect(prod, zero);
            }
            let mut n_active_e = b.mul(act[0], one);
            for r in 1..cap {
                let t = b.mul(act[r], one);
                n_active_e = b.add(n_active_e, t);
            }
            let mut sum_sel_e = b.mul(sv[0], one);
            for r in 1..cap {
                let t = b.mul(sv[r], one);
                sum_sel_e = b.add(sum_sel_e, t);
            }
            let neg_sum_sel = b.mul(sum_sel_e, neg_one);
            let c_minus_sel = b.add(c_pi, neg_sum_sel);
            let _ = b.add_range_bits::<Val>(c_minus_sel, DIFF_BITS).unwrap();
            let act_minus_sel = b.add(n_active_e, neg_sum_sel);
            let prod = b.mul(c_minus_sel, act_minus_sel);
            b.connect(prod, zero);
            let mut mass_e = b.mul(cnt[0], sv[0]);
            for r in 1..cap {
                let t = b.mul(cnt[r], sv[r]);
                mass_e = b.add(mass_e, t);
            }
            let massc = b.decompose_ext_to_base_coeffs::<Val>(mass_e).unwrap();
            let mass_b = massc[0];
            b.connect(massc[1], zero);
            b.connect(massc[2], zero);
            b.connect(massc[3], zero);
            let released = b.mul(mass_b, one);
            b.connect(released, answer_pi);
            let circuit = b.build().unwrap();

            let commit_packed =
                pack_commit_to_challenge(&crate::commitment::CountMinCommit(commit.0));
            let mut public_inputs: Vec<Challenge> = Vec::new();
            public_inputs.extend_from_slice(&commit_packed);
            public_inputs.push(Challenge::from_u64(c as u64));
            public_inputs.push(Challenge::from_u64(999)); // WRONG answer (true is 7)
            let mut private_inputs: Vec<Challenge> = pack_cells(&st);
            for r in 0..cap {
                private_inputs
                    .push(if sel_native[r] == 1 { Challenge::ONE } else { Challenge::ZERO });
            }
            for r in 0..cap - 1 {
                let lo = |k: u64| (k & 0xFFFF_FFFF) as u32;
                let d = Challenge::from_u64(lo(st.rows[r + 1].key) as u64)
                    - Challenge::from_u64(lo(st.rows[r].key) as u64);
                private_inputs
                    .push(if d == Challenge::ZERO { Challenge::ZERO } else { d.inverse() });
            }
            let mut runner = circuit.runner();
            runner.set_public_inputs(&public_inputs).unwrap();
            runner.set_private_inputs(&private_inputs).unwrap();
            runner.run().expect("run must fail on wrong answer");
        }));
        assert!(bad.is_err(), "wrong answer must be rejected by the relation");
    }

    // ── Query statement (Property 3): exposed (Com(S), c, answer) ──────────

    use crate::decode::{QueryStatement, check_query_statement, read_exposed_statement};
    use crate::sketch::bind::Binding;

    const QP: SsDecodeParams = SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Identity };

    /// `Semantic` / `Bound` expose `(Com(S), c, answer)`: the statement a
    /// verifier reads off a VERIFIED proof is exactly the queried commitment,
    /// the query size and the native answer, across the release policies.
    /// `Legacy` (the pre-fix circuit) exposes nothing.
    #[test]
    fn ss_decode_exposes_commit_c_answer() {
        let st = state();
        let commit = commit_ss_state(&st).0;
        for (c, release) in [
            (2usize, ReleasePolicy::Identity),
            (4, ReleasePolicy::Identity),
            (1, ReleasePolicy::Threshold(1000)),
            (2, ReleasePolicy::Threshold(5)),
        ] {
            let p = SsDecodeParams { capacity: 4, c, release };
            let answer = release.apply(native_topc_mass(&st, c));
            let want = QueryStatement::new(commit, c as u64, answer);
            for binding in [Binding::Semantic, Binding::Bound] {
                let dc = build_ss_decode(p, &st, c, binding);
                let proof = dc.prove_traces(&dc.run("ss decode")).expect("honest proof verifies");
                assert_eq!(read_exposed_statement(&proof), Some(want), "{binding:?} c={c} {release:?}");
                assert_eq!(check_query_statement(&proof, &want), Ok(()));
            }
            let pr = prove_ss_decode(p, st.clone(), c); // process default = Semantic
            assert_eq!(pr.statement(), Some(want));
        }
        let legacy = prove_ss_decode_with(QP, st.clone(), 2, Binding::Legacy);
        assert_eq!(legacy.statement(), None, "Legacy exposes nothing");
        assert_eq!(legacy.answer, 7);
    }

    /// A tampered answer is rejected (shared checks, see
    /// [`crate::decode::assert_tampered_answer_rejected`]): altering the
    /// exposed answer / query / commitment fails verification; a transplanted
    /// answer wire fails proving (with a positive control through the same
    /// forger); a claimed answer that differs from the exposed one fails the
    /// statement check; the pre-fix Legacy proof exposes nothing to check.
    #[test]
    fn ss_decode_tampered_answer_rejected() {
        let st = state();
        let want = QueryStatement::new(commit_ss_state(&st).0, 2, 7);
        for binding in [Binding::Semantic, Binding::Bound] {
            crate::decode::assert_tampered_answer_rejected(
                &build_ss_decode(QP, &st, 2, binding),
                &build_ss_decode(QP, &st, 2, Binding::Legacy),
                "ss_dec_answer",
                want,
            );
        }
        // Threshold release: the answer wire is `flag·mass`.
        let pt = SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Threshold(5) };
        crate::decode::assert_tampered_answer_rejected(
            &build_ss_decode(pt, &st, 2, Binding::Semantic),
            &build_ss_decode(pt, &st, 2, Binding::Legacy),
            "ss_dec_answer",
            want,
        );
    }

    /// The pinned verifier ([`crate::decode::verify_decode_proof`]): the VK
    /// derived from public parameters (empty state) accepts honest proofs over
    /// other states and returns their statements; it rejects the Legacy proof
    /// and a proof of a circuit that only exposes a lying statement (which the
    /// self-pinned check accepts).
    #[test]
    fn ss_decode_pinned_verifier() {
        let st = state();
        let commit = commit_ss_state(&st).0;
        let vk = ss_decode_vk(QP, Binding::Semantic);
        let partial = {
            let p = SsFullParams { capacity: 4, batch: 4 };
            let batch =
                [SsFullUpdate::real(9, 5), SsFullUpdate::dummy(), SsFullUpdate::dummy(), SsFullUpdate::dummy()];
            apply_batch_ss_full(&SsFullState::empty(p), &batch).0
        };
        let (a, b) = (build_ss_decode(QP, &st, 2, Binding::Semantic), build_ss_decode(QP, &partial, 2, Binding::Semantic));
        crate::decode::assert_pinned_decode_verifier(
            &vk,
            &[
                (&a, QueryStatement::new(commit, 2, 7)),
                (&b, QueryStatement::new(commit_ss_state(&partial).0, 2, 5)),
            ],
            &build_ss_decode(QP, &st, 2, Binding::Legacy),
        );
        // A different query size is a different circuit (c is a public input,
        // but the VK is per params): a c = 3 proof fails the c = 2 pin only if
        // its circuit differs; it does not, so the pin accepts it and the
        // statement names c = 3 — the verifier must compare the query.
        let p3 = SsDecodeParams { capacity: 4, c: 3, release: ReleasePolicy::Identity };
        let d3 = build_ss_decode(p3, &st, 3, Binding::Semantic);
        let proof3 = d3.prove_traces(&d3.run("ss decode")).expect("c = 3 proof");
        let got = crate::decode::verify_decode_proof(&proof3, &vk).expect("same circuit shape");
        assert_eq!(got, QueryStatement::new(commit, 3, 9));
        assert!(check_query_statement(&proof3, &QueryStatement::new(commit, 2, 9)).is_err());
    }

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────

    use crate::commitment::hiding::{CommitFamily, Openings, SaltSeed, rho_state_bb};
    use crate::decode::verify_decode_proof;
    use crate::recursion::recursive::expose_forest::vk_pin_values;
    use crate::sketch::ss_final_full::{build_ss_full_leaf_commit, commit_ss_state_with};
    use p3_field::PrimeField64;

    const SS: CommitFamily = CommitFamily::SpaceSaving;

    fn vk_flat(v: &[Challenge]) -> Vec<u64> {
        v.iter()
            .flat_map(|c| {
                <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                    .iter()
                    .map(|x| x.as_canonical_u64())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// (6) B2: a Hiding decode opens `Com(S_t; ρ)`. The Plain decoder is the
    /// pre-B2 circuit: its pinned VK ([`ss_decode_vk`], and the VK of a Plain
    /// proof) equals the value recorded at b2-hiding@94e9f58, for every
    /// binding and both release policies. Under `Hiding` the answer is
    /// unchanged, the VK does not depend on the salt and is the pinned
    /// [`ss_decode_vk_commit`] (different from the Plain one); under
    /// `Semantic`/`Bound` the decoder exposes the hiding commitment (not the
    /// plain one), the pinned verifier accepts it under the Hiding VK and
    /// rejects cross-mode proofs. A query at version `t` opened with `ρ^S_t`
    /// exposes exactly the final commitment of the hiding leaf `t` (the lemma
    /// in `crate::commitment::hiding`); a wrong salt still proves, but exposes
    /// a commitment that is not the log's.
    #[test]
    fn hiding_decode_exposes_hiding_commit() {
        use crate::recursion::recursive::statement::Expose;
        let pt = SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Threshold(5) };
        let recorded = [
            (QP, Binding::Semantic, [1234796130u64, 1600695541, 1257673928, 717761815, 1443374029, 1308102251, 1978591557, 264335655]),
            (QP, Binding::Bound, [1234796130, 1600695541, 1257673928, 717761815, 1443374029, 1308102251, 1978591557, 264335655]),
            (QP, Binding::Legacy, [1792098982, 1363832560, 1349599348, 687201561, 767526637, 335296869, 6449583, 1244360319]),
            (pt, Binding::Semantic, [1505638691, 1635076016, 407453922, 1183580053, 983916629, 1541970621, 1133455193, 1298685842]),
        ];
        let seed = SaltSeed::for_tests(61);
        let (rho, rho2) = (rho_state_bb(&seed, SS, 4), rho_state_bb(&seed, SS, 5));
        let st = state();
        for (p, binding, vk) in recorded {
            let tag = format!("{binding:?}/{}", p.release.name());
            let want: Vec<u64> = vk.iter().flat_map(|&x| [x, 0, 0, 0]).collect();
            let plain_vk = ss_decode_vk(p, binding);
            assert_eq!(vk_flat(&plain_vk.commitment), want, "{tag}: Plain decode VK drifted");
            assert_eq!(ss_decode_vk_commit(p, binding, CommitMode::Plain), plain_vk, "{tag}");
            let plain = prove_ss_decode_with(p, st.clone(), 2, binding);
            assert_eq!(vk_flat(&vk_pin_values(&plain.output.0)), want, "{tag}");

            let hid = prove_ss_decode_commit(p, st.clone(), 2, binding, CommitMode::Hiding, &rho);
            let hid2 = prove_ss_decode_commit(p, st.clone(), 2, binding, CommitMode::Hiding, &rho2);
            assert_eq!(hid.answer, plain.answer, "{tag}");
            assert_eq!(hid.answer, p.release.apply(native_topc_mass(&st, 2)), "{tag}");
            let hvk = ss_decode_vk_commit(p, binding, CommitMode::Hiding);
            assert_eq!(vk_pin_values(&hid.output.0), hvk.commitment, "{tag}");
            assert_eq!(vk_pin_values(&hid2.output.0), hvk.commitment, "{tag}: salt-independent VK");
            assert_ne!(hvk.commitment, plain_vk.commitment, "{tag}");
            if binding.is_bound() {
                let hc = commit_ss_state_with(&st, CommitMode::Hiding, &rho).0;
                assert_ne!(hc, commit_ss_state(&st).0, "{tag}");
                let want_st = QueryStatement::new(hc, 2, hid.answer);
                assert_eq!(verify_decode_proof(&hid.output.0, &hvk), Ok(want_st), "{tag}");
                assert_eq!(hid.statement(), Some(want_st), "{tag}");
                let c2 = hid2.statement().expect("exposed").commit;
                assert_eq!(c2, commit_ss_state_with(&st, CommitMode::Hiding, &rho2).0, "{tag}");
                assert_ne!(c2, hc, "{tag}: another version, another commitment");
                assert!(verify_decode_proof(&plain.output.0, &hvk).is_err(), "{tag}: a Plain proof under the Hiding pin");
                assert!(verify_decode_proof(&hid.output.0, &plain_vk).is_err(), "{tag}: a Hiding proof under the Plain pin");
            } else {
                assert_eq!(hid.statement(), None, "{tag}: Legacy exposes nothing");
            }
        }

        // Query at version t == leaf t's final commitment.
        let t = 2u64;
        let lp = SsFullParams { capacity: 4, batch: 2 };
        let mut leaf = build_ss_full_leaf_commit(lp, Expose::Interval, CommitMode::Hiding);
        let s_prev =
            apply_batch_ss_full(&SsFullState::empty(lp), &[SsFullUpdate::real(9, 5), SsFullUpdate::real(3, 2)]).0;
        let ups = vec![SsFullUpdate::real(7, 2), SsFullUpdate::real(5, 1)];
        let r = leaf.prove_epoch_commit(t, s_prev.clone(), ups.clone(), &Openings::for_leaf(&seed, SS, t));
        let s_t = apply_batch_ss_full(&s_prev, &ups).0;
        let q = prove_ss_decode_commit(QP, s_t.clone(), 2, Binding::Semantic, CommitMode::Hiding, &rho_state_bb(&seed, SS, t));
        assert_eq!(q.statement().expect("exposed").commit, r.final_.0, "query at t opens leaf t's final commitment");
        let wrong =
            prove_ss_decode_commit(QP, s_t, 2, Binding::Semantic, CommitMode::Hiding, &rho_state_bb(&seed, SS, t + 1));
        assert_ne!(wrong.statement().expect("exposed").commit, r.final_.0, "a wrong salt exposes another commitment");
    }

    /// (F3, F5) Decoder twin of the leaf's overhead test: a Hiding decode
    /// costs exactly +2 Poseidon2 rows and +3 ALU rows (one commitment)
    /// under every binding, and none of its 12 salt values is a public value
    /// of the proof (positive control: the scan sees the exposed statement).
    #[test]
    fn hiding_decode_row_overhead_and_no_salt_in_public_values() {
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows, trace_rows};
        let rho = rho_state_bb(&SaltSeed::for_tests(62), SS, 3);
        let st = state();
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let (p0, a0) = trace_rows(&build_ss_decode(QP, &st, 2, binding).run("ss decode"));
            let hdc = build_ss_decode_commit(QP, &st, 2, binding, CommitMode::Hiding, &rho);
            let (p1, a1) = trace_rows(&hdc.run("ss decode"));
            println!("B2 ss decode rows {binding:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 2, "{binding:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 3, "{binding:?}: ALU rows");
            let hid = prove_ss_decode_commit(QP, st.clone(), 2, binding, CommitMode::Hiding, &rho);
            assert_eq!(proof_alu_rows(&hid.output.0), a1, "{binding:?}: the proof's ALU height");
            assert_eq!(leaked_salts(&hid.output.0, &[rho]), vec![], "{binding:?}");
            if binding.is_bound() {
                let mut control = SaltBb::ZERO;
                control.0[0] = commit_ss_state_with(&st, CommitMode::Hiding, &rho).0[0];
                assert!(!leaked_salts(&hid.output.0, &[control]).is_empty(), "{binding:?}: the scan sees the statement");
            }
        }
    }

    /// The salt is the FIRST 3 private inputs (decoder twin of
    /// `ss_final_full::tests::hiding_leaf_salts_are_the_first_private_inputs`).
    /// Packing: under every binding the Hiding decoder's private inputs are
    /// `salt.packed()` (three distinct nonzero Challenges) followed by the
    /// Plain decoder's. Allocation: the honest proof over them verifies and
    /// exposes the native hiding commitment; control: the same values with
    /// the salt moved last are rejected by the runner.
    #[test]
    fn hiding_decode_salt_is_the_first_private_input() {
        let rho = rho_state_bb(&SaltSeed::for_tests(64), SS, 2);
        let packed = rho.packed();
        assert!(packed.iter().all(|c| *c != Challenge::ZERO), "nonzero salt Challenges");
        assert!(packed[0] != packed[1] && packed[1] != packed[2] && packed[0] != packed[2], "distinct");
        let st = state();
        let hc = commit_ss_state_with(&st, CommitMode::Hiding, &rho).0;
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let plain = build_ss_decode(QP, &st, 2, binding);
            let mut hdc = build_ss_decode_commit(QP, &st, 2, binding, CommitMode::Hiding, &rho);
            assert_eq!(hdc.private_inputs.len(), plain.private_inputs.len() + 3, "{binding:?}");
            assert_eq!(hdc.private_inputs[..3], packed[..], "{binding:?}: the salt comes first");
            assert_eq!(hdc.private_inputs[3..], plain.private_inputs[..], "{binding:?}: then the Plain private inputs");

            let proof = hdc.prove_traces(&hdc.run("ss decode")).expect("honest hiding decode");
            if binding.is_bound() {
                let got = crate::decode::read_exposed_statement(&proof).expect("exposed");
                assert_eq!(got, QueryStatement::new(hc, 2, hdc.answer), "{binding:?}");
            }

            hdc.private_inputs.rotate_left(3);
            assert_eq!(hdc.private_inputs[hdc.private_inputs.len() - 3..], packed[..]);
            let e = crate::sketch::forge::catch_msg(|| hdc.run("ss decode").alu_trace.values.len()).map(|_| ());
            assert!(e.is_err(), "{binding:?}: the salt packed last must not run on the salt-first circuit");
        }
    }

    /// (8) The Hiding decoder at a tiny shape. Under the DEBUG profile
    /// (`cargo test --lib decode::spacesaving::tests::hiding_decode_tiny_debug`)
    /// the fork debug-asserts, during the build, that each of the 3 salt
    /// private inputs has an ALU creator.
    #[test]
    fn hiding_decode_tiny_debug() {
        let p = SsFullParams { capacity: 2, batch: 2 };
        let s = apply_batch_ss_full(&SsFullState::empty(p), &[SsFullUpdate::real(9, 2), SsFullUpdate::real(4, 1)]).0;
        let rho = rho_state_bb(&SaltSeed::for_tests(63), SS, 1);
        let dp = SsDecodeParams { capacity: 2, c: 1, release: ReleasePolicy::Identity };
        let q = prove_ss_decode_commit(dp, s.clone(), 1, Binding::Semantic, CommitMode::Hiding, &rho);
        let want = QueryStatement::new(commit_ss_state_with(&s, CommitMode::Hiding, &rho).0, 1, 2);
        assert_eq!(q.statement(), Some(want));
    }

    /// Under `Hiding` the public zero salt opens only the empty genesis
    /// state, the one state commitment the verifier recomputes itself
    /// (`Com(S_0; 0)`; a continued history's version 0 opens with its
    /// anchor salt). A real state handed the zero salt (a forgotten opening
    /// at `t >= 1`) panics instead of publishing the guess-checkable
    /// `Com(S_t; 0)`, from the builder and the proving entry point alike
    /// (the twin of `decode::gk_bandmerge`'s test). Controls: the Hiding VK
    /// derivation ([`ss_decode_vk_commit`]: empty state, zero salt), a real
    /// state with a real salt, and `Plain` (salt ignored) still build, and a
    /// genesis query proves under the Hiding VK and exposes `Com(S_0; 0)`.
    #[test]
    fn hiding_decode_refuses_zero_salt_on_a_real_state() {
        let rho = rho_state_bb(&SaltSeed::for_tests(65), SS, 2);
        let st = state();
        let empty = SsFullState::empty(SsFullParams { capacity: QP.capacity, batch: 4 });
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let msg = crate::sketch::forge::catch_msg(|| {
                build_ss_decode_commit(QP, &st, 2, binding, CommitMode::Hiding, &SaltBb::ZERO).answer
            })
            .unwrap_err();
            assert!(msg.contains("public zero salt"), "{binding:?}: {msg}");
            let _ = build_ss_decode_commit(QP, &empty, 2, binding, CommitMode::Hiding, &SaltBb::ZERO);
            let _ = build_ss_decode_commit(QP, &st, 2, binding, CommitMode::Hiding, &rho);
            let _ = build_ss_decode_commit(QP, &st, 2, binding, CommitMode::Plain, &SaltBb::ZERO);
        }
        let msg = crate::sketch::forge::catch_msg(|| {
            prove_ss_decode_commit(QP, st.clone(), 2, Binding::Semantic, CommitMode::Hiding, &SaltBb::ZERO).answer
        })
        .unwrap_err();
        assert!(msg.contains("public zero salt"), "{msg}");
        let hvk = ss_decode_vk_commit(QP, Binding::Semantic, CommitMode::Hiding);
        let genesis = prove_ss_decode_commit(QP, empty.clone(), 2, Binding::Semantic, CommitMode::Hiding, &SaltBb::ZERO);
        let want = QueryStatement::new(commit_ss_state_with(&empty, CommitMode::Hiding, &SaltBb::ZERO).0, 2, 0);
        assert_eq!(verify_decode_proof(&genesis.output.0, &hvk), Ok(want), "a genesis query opens Com(S_0; 0)");
    }
}
