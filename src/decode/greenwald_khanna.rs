//! Greenwald-Khanna **approximate-rank / quantile** decode circuit (E3,
//! plonky3/STARK).
//!
//! Implements the paper's GK rank-query relation (zk1.tex `app:gk-decode`,
//! §Pattern-B): the prover supplies a **one-hot bracketing selector** for the
//! pair `e_i ≤ q < e_{i+1}` over the value-sorted committed tuples, and the
//! circuit certifies the **approximate-rank estimator**
//!
//! ```text
//!   P_i      = Σ_{z ≤ i} count_z              (prefix mass; paper g₁+g₂+1)
//!   r_min    = P_i − max_error_i              (paper P_i − Δ₂,ᵢ − g₂,ᵢ)
//!   r_max    = P_i + max_error_{i+1}          (paper P_i + Δ₁,ᵢ₊₁ + g₁,ᵢ₊₁)
//!   res      = ⌊(r_min + r_max) / 2⌋          (rational midpoint, kept integer
//!                                              via a witnessed remainder)
//! ```
//!
//! against a committed GK state (tuples `(value, count, max_error, active)`,
//! value-ascending with dummies first). With the folded 4-field tuple, `count`
//! plays the rank-mass `g` and `max_error` plays the deviation `Δ`. The
//! `±∞` sentinels bracketing every `q` are realised implicitly: the selector
//! ranges over `cap + 1` boundary positions `k ∈ {0,…,cap}` (`k` = number of
//! tuples with `value ≤ q`), so `k = 0` brackets below the table (left sentinel
//! −∞, `max_error_i = 0`) and `k = cap` brackets above it (right sentinel +∞,
//! `max_error_{i+1} = 0`).
//!
//! This reuses the same harness as the working Count-Min decode
//! (`decode::countmin`): Poseidon2 + Recompose tables, no Permute (a decode
//! opens, it does not re-sort — the prover-supplied selector is checked against
//! the opened tuples directly).
//!
//! Stages:
//! 1. Re-hash the `capacity` packed tuples → bind to the committed digest
//!    (the `Θ(s)` cost).
//! 2. Decompose each packed tuple into its `(value, count, max_error, active)`
//!    base coeffs and the query coeff.
//! 3. Per tuple force a `≤`-flag `le_r ∈ {0,1}` to equal `[value_r ≤ q]` via a
//!    single non-negative range-checked diff `big − small ≥ 0` (the Count-Min
//!    min-gadget idiom: both sides are ALU sums). Among **active** tuples the
//!    table is value-sorted, so the active `le` flags are `1…1 0…0`.
//! 4. One-hot boundary selector `sel[k]`, `k ∈ {0,…,cap}`: exactly one is `1`,
//!    and `Σ_r le_r·active_r` boundary correctness ties `k` to the bracket.
//!    Build the prefix mass `P_i`, the left/right deviations
//!    `max_error_i` / `max_error_{i+1}`, then `r_min`, `r_max`, and the
//!    midpoint `res` with a witnessed boolean remainder.
//! 5. Apply the release policy and bind the released value to the public answer.
//!
//! WitnessChecks discipline (the part that makes decode circuits hard):
//! - Every base coeff produced by `decompose_ext_to_base_coeffs` (each tuple
//!   field, and the query coeff) must appear as the LHS (first operand) of an
//!   ALU op at least once, or proving panics with
//!   `GlobalCumulativeMismatch: WitnessChecks`. We put each coeff first in its
//!   product, exactly as the Count-Min template does. `max_error` is consumed
//!   once as an ALU lhs in Stage 3 *before* it is read as the rhs of a selector
//!   product in Stage 4, so its coeff has a bus creator.
//! - The value handed to `decompose_to_bits` for a range check must be a `sub`
//!   of two ALU *sums* (the Count-Min min-gadget idiom), never a raw coeff or a
//!   coeff-difference fed in directly.

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;

use crate::config::{Challenge, Val};
use crate::decode::{DecodeProof, DecodeVk, ReleasePolicy, StdDecodeCircuit};
use crate::recursion::recursive::countmin_leaf::DIGEST_PACKING;
use crate::sketch::bind::{self, Binding};
use crate::sketch::gk_final_full::{GKFullParams, GKFullState, commit_gk_state};

/// Range-check window for the `≤`-flag soundness diff and the midpoint
/// remainder. Per-record `value`, `count`, `max_error`, and the query must fit
/// in `DIFF_BITS − 1` bits; a "negative" diff wraps past `2^p` and overflows
/// the check (sound `≥ 0`).
const DIFF_BITS: usize = 22;

#[derive(Copy, Clone, Debug)]
pub struct GkDecodeParams {
    pub capacity: usize,
    pub release: ReleasePolicy,
}

impl GkDecodeParams {
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity >= 1, got {}", self.capacity);
    }
}

/// Native approximate-rank estimate, mirroring the in-circuit relation.
#[derive(Copy, Clone, Debug)]
struct GkEstimate {
    res: u64,
    k: usize,
    rem: u64,
}

/// Compute the paper GK approximate-rank estimate over the committed state.
///
/// The table is value-ascending (dummies first at value 0). The bracket
/// boundary `k = Σ_r [value_r ≤ q]` (dummies, value 0, satisfy `value ≤ q` so
/// they count toward `k`; they carry count 0 / max_error 0 so they perturb
/// neither `P_i` nor the selected deviations). It selects:
///   - `max_error_i`    = `max_error` of tuple `k-1` (last with value ≤ q), or 0
///     when `k = 0` (left −∞ sentinel);
///   - `max_error_{i+1}` = `max_error` of tuple `k` (first with value > q), or 0
///     when `k = cap` (right +∞ sentinel).
fn native_estimate(state: &GKFullState, q: u64) -> GkEstimate {
    let tuples = &state.tuples;
    let cap = tuples.len();

    let le: Vec<bool> = tuples.iter().map(|t| (t.value as u64) <= q).collect();
    let k = le.iter().filter(|&&b| b).count();

    let p_i: u64 =
        tuples.iter().zip(&le).filter(|&(_, &b)| b).map(|(t, _)| t.count as u64).sum();
    let max_error_i: u64 = if k == 0 { 0 } else { tuples[k - 1].max_error as u64 };
    let max_error_ip1: u64 = if k == cap { 0 } else { tuples[k].max_error as u64 };

    let r_min = p_i.saturating_sub(max_error_i);
    let r_max = p_i + max_error_ip1;
    let num = r_min + r_max;
    GkEstimate { res: num / 2, k, rem: num % 2 }
}

/// Pack a GK state's tuples into Challenge elements (one tuple / Challenge),
/// reproducing `commit_gk_state`'s flattening (`flat_state_vals`:
/// `[value, count, max_error, active]` per tuple, in tuple order) so the open
/// binds to the published digest.
fn pack_cells(state: &GKFullState) -> Vec<Challenge> {
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

/// Pack a GK state commit (`[Val; 8]`) into `DIGEST_PACKING` Challenges, the
/// same split as `pack_commit_to_challenge` (lo = coeffs 0..4, hi = 4..8).
fn pack_commit(digest: &[Val; 8]) -> [Challenge; DIGEST_PACKING] {
    [
        Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 base coeffs"),
        Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 base coeffs"),
    ]
}

/// Prove a Greenwald-Khanna **approximate-rank** quantile decode. Returns a
/// [`DecodeProof`]; the prover self-verifies and records the witness/prove/
/// verify split via [`crate::recursion::recursive::timing`]. Uses the
/// process-default [`Binding`] ([`bind::default_binding`]).
pub fn prove_gk_decode(params: GkDecodeParams, state: GKFullState, query: u64) -> DecodeProof {
    prove_gk_decode_with(params, state, query, bind::default_binding())
}

/// [`prove_gk_decode`] with an explicit [`Binding`].
///
/// `Semantic` / `Bound` surface the query statement `(Com(S), q, answer)`
/// through the Expose NPO (16 base values: commit[8], q[4], answer[4]; read it
/// with [`crate::decode::read_exposed_statement`]) and pin the query's three
/// upper extension coordinates to 0, so the exposed query is exactly the
/// scalar the rank relation used (Property 3). [`Binding::Legacy`] is the
/// pre-fix circuit, byte-for-byte: it exposes nothing, so its proof certifies
/// an answer the verifier never sees. No in-circuit coefficient re-binding
/// (the merged fork binds decompositions), so `Bound` equals `Semantic`.
pub fn prove_gk_decode_with(
    params: GkDecodeParams,
    state: GKFullState,
    query: u64,
    binding: Binding,
) -> DecodeProof {
    build_gk_decode(params, &state, query, binding).prove("gk decode")
}

/// The trusted verification key of the (group-by) GK rank decoder for
/// `params` under `binding`, derived from public parameters only (a proof over
/// the empty state). Pin query proofs to it with
/// [`crate::decode::verify_decode_proof`].
pub fn gk_decode_vk(params: GkDecodeParams, binding: Binding) -> DecodeVk {
    let empty = GKFullState::empty(GKFullParams { capacity: params.capacity, batch: 1 });
    build_gk_decode(params, &empty, 0, binding).derive_vk("gk decode")
}

/// Build the (group-by GK) rank decode circuit and its witness.
pub(crate) fn build_gk_decode(
    params: GkDecodeParams,
    state: &GKFullState,
    query: u64,
    binding: Binding,
) -> StdDecodeCircuit {
    let expose = binding.is_bound();
    params.validate();
    let GkDecodeParams { capacity: cap, release } = params;
    assert_eq!(state.tuples.len(), cap, "state shape must match params");

    // ─── Native decode ───────────────────────────────────────────────────
    let commit = commit_gk_state(state);
    let est = native_estimate(state, query);
    let answer = release.apply(est.res);

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

    // PIs: committed state, query, released answer.
    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let query_pi = b.alloc_public_input("query");
    let answer_pi = b.alloc_public_input("answer");
    if expose {
        b.add_expose(&[commit_pis[0], commit_pis[1], query_pi, answer_pi])
            .expect("expose (commit, query, answer)");
    }
    b.tag(answer_pi, "gk_dec_answer").expect("tag");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let two = b.alloc_const(Challenge::from_u64(2), "two");

    // Private witnesses.
    let cells_packed: Vec<ExprId> =
        (0..cap).map(|_| b.alloc_private_input("cell_packed")).collect();
    let le: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("le")).collect();
    // One-hot boundary selector over k ∈ {0,…,cap} (cap+1 positions).
    let sel: Vec<ExprId> = (0..=cap).map(|_| b.alloc_private_input("sel")).collect();
    // Midpoint witnesses: res and the boolean remainder.
    let res_w = b.alloc_private_input("res");
    let rem_w = b.alloc_private_input("rem");
    let flag = if matches!(release, ReleasePolicy::Threshold(_)) {
        Some(b.alloc_private_input("flag"))
    } else {
        None
    };

    // ── Stage 1: open the committed state ──
    let digest = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, true)
        .expect("hash cells");
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }

    // Query base coeff (its hint coeffs get bus creators from their first ALU
    // lhs use). Using a base coeff in the base-field range-check path mirrors
    // the CM `theta` idiom and keeps the WitnessChecks bus balanced.
    let qc = b.decompose_ext_to_base_coeffs::<Val>(query_pi).expect("decompose query");
    let query_b = qc[0];
    if expose {
        // The exposed query is the whole Challenge: pin its upper coordinates
        // so it is exactly the scalar `q` the relation below uses.
        for &hi in &qc[1..] {
            b.connect(hi, zero);
        }
    }

    // ── Stage 2: decompose each tuple into base coeffs ──
    let fields: Vec<Vec<ExprId>> = cells_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose cell"))
        .collect();

    // ── Stage 3: per-tuple ≤-flag soundness + prefix mass P_i ──
    // For each tuple: force `le_r ∈ {0,1}`; range-check a single non-negative
    // diff that pins `le_r = [value_r ≤ q]`; accumulate the prefix mass
    // `p_acc = Σ active_r · le_r · count_r` (= P_i, since dummies have count 0
    // and the active table is value-sorted so the active le flags are 1…1 0…0).
    //
    // Every cell coeff (value/count/max_error/active) leads an ALU op (lhs) so
    // the WitnessChecks bus claims a creator for it. The range-checked value
    // fed to `decompose_to_bits` is always a `sub` of two ALU *sums*.
    let q_plus_1 = b.add(query_b, one); // query_b = lhs creator
    let mut p_acc = zero;
    for r in 0..cap {
        let value_r = fields[r][0];
        let count_r = fields[r][1];
        let max_error_r = fields[r][2];
        let active_r = fields[r][3];
        let le_r = le[r];

        // le_r boolean.
        let lm1 = b.sub(le_r, one);
        let bchk = b.mul(le_r, lm1);
        b.connect(bchk, zero);

        // Force le_r = [value_r ≤ q] via a single non-negative range-checked
        // diff (CM min-gadget idiom: diff = sub(big_sum, small_sum), both ALU
        // sums):
        //   big   = le_r·q       + (1−le_r)·value_r
        //   small = le_r·value_r + (1−le_r)·(q + 1)
        //   diff  = big − small ≥ 0
        //     le=1: diff = q − value_r ≥ 0 ⇔ value_r ≤ q
        //     le=0: diff = value_r − q − 1 ≥ 0 ⇔ value_r > q
        let nle = b.sub(one, le_r);
        let big_q = b.mul(le_r, query_b); // le·q
        let big_v = b.mul(value_r, nle); // value_r·(1−le)  (value_r = lhs creator)
        let big = b.add(big_q, big_v);
        let small_v = b.mul(value_r, le_r); // value_r·le      (value_r = lhs)
        let small_q = b.mul(nle, q_plus_1); // (1−le)·(q+1)
        let small = b.add(small_v, small_q);
        let diff = b.sub(big, small);
        let _ = b.add_range_bits::<Val>(diff, DIFF_BITS).expect("diff >= 0");

        // P_i prefix mass: active_r · le_r · count_r. active_r and count_r lead
        // (lhs).
        let al = b.mul(active_r, le_r); // active_r = lhs creator
        let contrib = b.mul(count_r, al); // count_r = lhs creator
        p_acc = b.add(p_acc, contrib);

        // Touch max_error here as an ALU lhs so its coeff has a bus creator
        // before being selected (read as rhs) in Stage 4.
        let _ = b.mul(max_error_r, one);
    }

    // ── Stage 4: one-hot boundary selector + bracket estimator ──
    //
    // sel[k] = 1 for exactly one k ∈ {0,…,cap}, where k is the number of tuples
    // with value ≤ q (the bracket boundary). Constraints:
    //   - each sel[k] ∈ {0,1}, Σ sel[k] = 1 (one-hot);
    //   - the chosen k matches the boundary: Σ_k k·sel[k] = Σ_r le_r·active_r.
    //
    // We also build:
    //   max_error_i   = Σ_{k≥1} sel[k]·max_error_{k-1}   (left bracket; 0 at k=0)
    //   max_error_ip1 = Σ_{k<cap} sel[k]·max_error_k      (right bracket; 0 at k=cap)
    //
    // Each max_error coeff leads its selector product (lhs).
    let mut sel_sum = zero;
    let mut k_acc = zero; // Σ k·sel[k]
    let mut me_left = zero; // max_error_i
    let mut me_right = zero; // max_error_{i+1}
    for k in 0..=cap {
        let s = sel[k];
        let sm1 = b.sub(s, one);
        let bchk = b.mul(s, sm1);
        b.connect(bchk, zero);
        sel_sum = b.add(sel_sum, s);

        let kconst = b.alloc_const(Challenge::from_u64(k as u64), "k");
        let ks = b.mul(kconst, s); // k·sel[k]  (const leads; sound)
        k_acc = b.add(k_acc, ks);

        // Left bracket deviation: tuple k-1's max_error (only when k≥1).
        if k >= 1 {
            let me = fields[k - 1][2];
            let t = b.mul(me, s); // max_error coeff leads (lhs)
            me_left = b.add(me_left, t);
        }
        // Right bracket deviation: tuple k's max_error (only when k<cap).
        if k < cap {
            let me = fields[k][2];
            let t = b.mul(me, s); // max_error coeff leads (lhs)
            me_right = b.add(me_right, t);
        }
    }
    b.connect(sel_sum, one);

    // Boundary correctness: Σ_k k·sel[k] = Σ_r le_r, the number of tuples (incl.
    // value-0 dummies) with value ≤ q. Since the table is value-ascending
    // (dummies first, then actives ascending), the le flags are 1…1 0…0 and `k`
    // is the index of the first tuple with value > q — i.e. the bracket
    // boundary. We sum `le_r` (not `le_r·active_r`) so `k` lands on the true
    // table position; dummies carry count 0 / max_error 0 so including them
    // leaves P_i and the selected deviations unchanged.
    let mut le_sum = zero;
    for r in 0..cap {
        let le_r = le[r];
        le_sum = b.add(le_sum, le_r);
    }
    b.connect(k_acc, le_sum);

    // r_min = P_i − max_error_i,  r_max = P_i + max_error_{i+1}.
    // num = r_min + r_max = 2·P_i + max_error_{i+1} − max_error_i.
    // res = ⌊num/2⌋ with witnessed remainder rem ∈ {0,1}:
    //   2·res + rem = num,  rem ∈ {0,1}.
    let r_min = b.sub(p_acc, me_left);
    let r_max = b.add(p_acc, me_right);
    let num = b.add(r_min, r_max);

    // rem boolean.
    let rm1 = b.sub(rem_w, one);
    let bchk = b.mul(rem_w, rm1);
    b.connect(bchk, zero);

    // 2·res + rem = num. `res_w` leads its product (lhs) for the bus.
    let two_res = b.mul(res_w, two); // res coeff leads
    let recon = b.add(two_res, rem_w);
    b.connect(recon, num);

    // Range check res ≥ 0 (it is the floor of a non-negative midpoint), via the
    // CM idiom: diff = sub(ALU sum, ALU sum). A "res" chosen too large would
    // also fail the `recon == num` connect.
    let res_plus0 = b.add(res_w, zero);
    let zero_sum = b.add(zero, zero);
    let diff_res = b.sub(res_plus0, zero_sum);
    let _ = b.add_range_bits::<Val>(diff_res, DIFF_BITS).expect("res >= 0");

    // ── Stage 5: release policy → answer ──
    match release {
        ReleasePolicy::Identity => {
            // `mul(res_w, one)` keeps `res_w` as lhs (matches the CM idiom).
            let released = b.mul(res_w, one);
            b.connect(released, answer_pi);
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.alloc_const(Challenge::from_u64(t), "theta");
            let fl = flag.unwrap();
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            // chosen = fl·(res−θ) + (1−fl)·(θ−res−1) ≥ 0  ⇔  fl = [res ≥ θ].
            let res_minus_t = b.sub(res_w, theta);
            let tm = b.sub(theta, res_w);
            let t_minus_res_m1 = b.sub(tm, one);
            let nf = b.sub(one, fl);
            let a = b.mul(fl, res_minus_t);
            let nft = b.mul(nf, t_minus_res_m1);
            let chosen = b.add(a, nft);
            let _ = b.add_range_bits::<Val>(chosen, DIFF_BITS).expect("chosen >= 0");
            let released = b.mul(fl, res_w);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build gk decode circuit");

    // ─── Pack public + private values ────────────────────────────────────
    let commit_packed = pack_commit(&commit.0);
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_u64(query));
    public_inputs.push(Challenge::from_u64(answer));

    let mut private_inputs: Vec<Challenge> = pack_cells(state);
    // le[r] = [value_r ≤ q]  (matches the in-circuit chosen-flag definition).
    for t in &state.tuples {
        private_inputs
            .push(if (t.value as u64) <= query { Challenge::ONE } else { Challenge::ZERO });
    }
    // sel[k] = [k == bracket boundary].
    for k in 0..=cap {
        private_inputs.push(if k == est.k { Challenge::ONE } else { Challenge::ZERO });
    }
    // res, rem.
    private_inputs.push(Challenge::from_u64(est.res));
    private_inputs.push(Challenge::from_u64(est.rem));
    // flag (threshold only)
    if flag.is_some() {
        let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
        private_inputs.push(if est.res >= t { Challenge::ONE } else { Challenge::ZERO });
    }

    StdDecodeCircuit::new(circuit, public_inputs, private_inputs, answer, expose, "gk decode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::gk_final_full::{GKFullUpdate, apply_batch_full};

    fn state() -> GKFullState {
        let s0 = GKFullState::empty(GKFullParams { capacity: 8, batch: 8 });
        let batch = vec![
            GKFullUpdate::real(5),
            GKFullUpdate::real(5),
            GKFullUpdate::real(9),
            GKFullUpdate::real(12),
            GKFullUpdate::dummy(),
            GKFullUpdate::dummy(),
            GKFullUpdate::dummy(),
            GKFullUpdate::dummy(),
        ];
        apply_batch_full(&s0, &batch).0
    }

    /// Native approximate-rank estimate against the committed state (matches the
    /// in-circuit relation).
    fn native_res(s: &GKFullState, q: u64) -> u64 {
        native_estimate(s, q).res
    }

    #[test]
    fn gk_decode_full_capacity() {
        // 8 active tuples (no dummies): exercises a fully-populated state and a
        // query above every value (bracket boundary k = cap, right sentinel).
        let s0 = GKFullState::empty(GKFullParams { capacity: 8, batch: 8 });
        let batch = vec![
            GKFullUpdate::real(1),
            GKFullUpdate::real(2),
            GKFullUpdate::real(3),
            GKFullUpdate::real(4),
            GKFullUpdate::real(11),
            GKFullUpdate::real(12),
            GKFullUpdate::real(13),
            GKFullUpdate::real(14),
        ];
        let s = apply_batch_full(&s0, &batch).0;
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let proof = prove_gk_decode(p, s.clone(), 100); // all le=1, k=cap
        assert_eq!(proof.answer, native_res(&s, 100));
    }

    #[test]
    fn gk_decode_round_trip() {
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let s = state();
        // q = 5: the two 5s (fused into one tuple with count 2).
        let proof = prove_gk_decode(p, s.clone(), 5);
        assert_eq!(proof.answer, native_res(&s, 5), "res(5) mismatch");
    }

    #[test]
    fn gk_decode_partial() {
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let s = state();
        // q = 8: brackets between the fused 5s (count 2) and the 9.
        let proof = prove_gk_decode(p, s.clone(), 8);
        assert_eq!(proof.answer, native_res(&s, 8), "res(8) mismatch");
    }

    #[test]
    fn gk_decode_all() {
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let s = state();
        // q = 12: everything active ≤ q.
        let proof = prove_gk_decode(p, s.clone(), 12);
        assert_eq!(proof.answer, native_res(&s, 12), "res(12) mismatch");
    }

    #[test]
    fn gk_decode_below_table() {
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let s = state();
        // q = 0: brackets below the smallest active value (k counts only the
        // dummies; left sentinel for the active side). res should be 0.
        let proof = prove_gk_decode(p, s.clone(), 0);
        assert_eq!(proof.answer, native_res(&s, 0), "res(0) mismatch");
    }

    /// With all max_error = 0, the midpoint estimator collapses to the exact
    /// prefix mass — so for a fused-count state the approximate rank equals the
    /// classic exact rank. This pins the estimator to a known value.
    #[test]
    fn gk_decode_matches_exact_rank_when_no_error() {
        let s = state();
        // The fused state from apply_batch_full has max_error = 0 on all tuples
        // (exact value-equality fusion), so res = exact rank.
        assert!(s.tuples.iter().all(|t| t.max_error == 0), "test premise: no error");
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let proof = prove_gk_decode(p, s.clone(), 8);
        assert_eq!(proof.answer, s.rank(8), "res = exact rank when max_error = 0");
        assert_eq!(proof.answer, 2, "only the two fused 5s counted");
    }

    /// Exercise the deviation arithmetic: a hand-built state with non-zero
    /// max_error on the bracketing tuples must yield the midpoint estimator,
    /// not the exact prefix mass.
    #[test]
    fn gk_decode_uses_deviation() {
        use crate::sketch::gk_final_full::GKFullTuple;
        // Value-ascending, dummies first. P_i for q=10 = count(value 5) +
        // count(value 10) = 4 + 6 = 10. Right bracket tuple is value 20 with
        // max_error 3; left bracket tuple is value 10 with max_error 2.
        // r_min = 10 - 2 = 8, r_max = 10 + 3 = 13, num = 21, res = 10.
        let tuples = vec![
            GKFullTuple::dummy(),
            GKFullTuple::dummy(),
            GKFullTuple { value: 5, count: 4, max_error: 1, active: 1 },
            GKFullTuple { value: 10, count: 6, max_error: 2, active: 1 },
            GKFullTuple { value: 20, count: 7, max_error: 3, active: 1 },
            GKFullTuple { value: 30, count: 8, max_error: 4, active: 1 },
        ];
        let s = GKFullState { tuples, params: GKFullParams { capacity: 6, batch: 2 } };
        let est = native_estimate(&s, 10);
        assert_eq!(est.res, 10, "native midpoint estimate");
        let p = GkDecodeParams { capacity: 6, release: ReleasePolicy::Identity };
        let proof = prove_gk_decode(p, s.clone(), 10);
        assert_eq!(proof.answer, 10, "circuit certifies the midpoint estimate");
    }

    #[test]
    fn gk_decode_threshold_suppresses() {
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Threshold(1000) };
        let s = state();
        let proof = prove_gk_decode(p, s, 12);
        assert_eq!(proof.answer, 0, "res below θ ⇒ released 0");
    }

    #[test]
    fn gk_decode_threshold_passes() {
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Threshold(2) };
        let s = state();
        let res = native_res(&s, 12);
        let proof = prove_gk_decode(p, s, 12);
        assert_eq!(proof.answer, res, "res ≥ θ ⇒ released res");
    }

    // ── Query statement (Property 3): exposed (Com(S), q, answer) ──────────

    use crate::decode::{QueryStatement, check_query_statement, read_exposed_statement};
    use crate::sketch::bind::Binding;

    /// `Semantic` / `Bound` expose `(Com(S), q, answer)`: the statement read off
    /// a VERIFIED proof is the queried commitment, the query and the native
    /// estimate. `Legacy` exposes nothing.
    #[test]
    fn gk_decode_exposes_commit_query_answer() {
        let s = state();
        let commit = commit_gk_state(&s).0;
        for (q, release) in [
            (0u64, ReleasePolicy::Identity),
            (8, ReleasePolicy::Identity),
            (12, ReleasePolicy::Threshold(2)),
            (12, ReleasePolicy::Threshold(1000)),
        ] {
            let p = GkDecodeParams { capacity: 8, release };
            let want = QueryStatement::new(commit, q, release.apply(native_res(&s, q)));
            for binding in [Binding::Semantic, Binding::Bound] {
                let dc = build_gk_decode(p, &s, q, binding);
                let proof = dc.prove_traces(&dc.run("gk decode")).expect("honest proof verifies");
                assert_eq!(read_exposed_statement(&proof), Some(want), "{binding:?} q={q} {release:?}");
                assert_eq!(check_query_statement(&proof, &want), Ok(()));
            }
            assert_eq!(prove_gk_decode(p, s.clone(), q).statement(), Some(want));
        }
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let legacy = prove_gk_decode_with(p, s.clone(), 8, Binding::Legacy);
        assert_eq!(legacy.statement(), None, "Legacy exposes nothing");
        assert_eq!(legacy.answer, native_res(&s, 8));
    }

    /// Tampered answers are rejected (shared checks, see
    /// [`crate::decode::assert_tampered_answer_rejected`]).
    #[test]
    fn gk_decode_tampered_answer_rejected() {
        let s = state();
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let want = QueryStatement::new(commit_gk_state(&s).0, 8, native_res(&s, 8));
        for binding in [Binding::Semantic, Binding::Bound] {
            crate::decode::assert_tampered_answer_rejected(
                &build_gk_decode(p, &s, 8, binding),
                &build_gk_decode(p, &s, 8, Binding::Legacy),
                "gk_dec_answer",
                want,
            );
        }
    }

    /// The pinned verifier: the VK derived from public parameters (empty
    /// state) accepts honest proofs and returns their statements; it rejects
    /// the Legacy proof and a lying fake circuit.
    #[test]
    fn gk_decode_pinned_verifier() {
        let s = state();
        let commit = commit_gk_state(&s).0;
        let p = GkDecodeParams { capacity: 8, release: ReleasePolicy::Identity };
        let vk = gk_decode_vk(p, Binding::Semantic);
        let (a, b) = (build_gk_decode(p, &s, 8, Binding::Semantic), build_gk_decode(p, &s, 12, Binding::Semantic));
        crate::decode::assert_pinned_decode_verifier(
            &vk,
            &[
                (&a, QueryStatement::new(commit, 8, native_res(&s, 8))),
                (&b, QueryStatement::new(commit, 12, native_res(&s, 12))),
            ],
            &build_gk_decode(p, &s, 8, Binding::Legacy),
        );
    }
}
