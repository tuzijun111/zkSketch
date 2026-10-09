//! Greenwald–Khanna **approximate-rank / quantile** decode circuit for the
//! **two-sided §4 band-merge** state ([`crate::sketch::gk_bandmerge::Gk2State`],
//! produced by the deployed `bandmerge2` update). The real-GK query counterpart
//! of the group-by [`crate::decode::greenwald_khanna`] decode: where that reads
//! the folded 4-field `GKFullState`, this reads the six-field two-sided tuple
//! `(e, g₁, g₂, Δ₁, Δ₂, t)` and binds the SAME
//! [`commit_gk2_state`](crate::sketch::gk_bandmerge::commit_gk2_state) digest the
//! `bandmerge2` update recommits, so the query chains to that leaf.
//!
//! ### Estimator (S³ / zk1.tex `app:gk-decode`, two-sided form)
//! For a query `q`, the bracket `k = #{tuples with e ≤ q}` selects `e_{k-1} ≤ q
//! < e_k`, and
//! ```text
//!   P_i   = Σ_{e ≤ q} (g₁ + g₂ + 1)              (prefix mass)
//!   r_min = P_i − (g₂_{k-1} + Δ₂_{k-1})          (left bracket; 0 at k=0)
//!   r_max = P_i + (g₁_k     + Δ₁_k)              (right bracket; 0 at k=cap)
//!   res   = ⌊(r_min + r_max) / 2⌋
//! ```
//! Dummies carry `e = E_MAX` and sort last; for the deployed `q < E_MAX` they
//! have `le = 0` and `g₁=g₂=0`, so they perturb neither `P_i`, `k`, nor the
//! bracket deviations.

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;

use crate::commitment::hiding::{self, CommitFamily, CommitKind, CommitMode, SaltBb};
use crate::config::{Challenge, Val};
use crate::decode::{DecodeProof, DecodeVk, ReleasePolicy, StdDecodeCircuit};
use crate::recursion::recursive::countmin_leaf::DIGEST_PACKING;
use crate::sketch::bind::{self, Binding};
use crate::sketch::gk_bandmerge::{E_MAX, Gk2State, Gk2Tuple, GkbParams, commit_gk2_state_with, pack_tuples2};

/// Value/query comparison width (`e, q < 2^22 = E_MAX+1`).
const E_BITS: usize = 22;
/// Rank-mass field width (`g, Δ, t < 2^24`); matches the update circuit.
const MASS_BITS: usize = 24;
/// Rank-quantity width: `P_i, r_min, r_max, res ≤ N ≪ 2^RANK_BITS ≪ p`.
const RANK_BITS: usize = 27;

#[derive(Copy, Clone, Debug)]
pub struct Gkb2DecodeParams {
    pub capacity: usize,
    pub release: ReleasePolicy,
}

impl Gkb2DecodeParams {
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity >= 1, got {}", self.capacity);
    }
}

#[derive(Copy, Clone, Debug)]
struct Est {
    res: u64,
    k: usize,
    rem: u64,
}

/// Two-sided approximate-rank estimate, mirroring the in-circuit relation.
fn native_estimate(state: &Gk2State, q: u32) -> Est {
    let tuples = &state.tuples;
    let cap = tuples.len();
    let le: Vec<bool> = tuples.iter().map(|t| t.e <= q).collect();
    let k = le.iter().filter(|&&b| b).count();

    let p_i: u64 = tuples
        .iter()
        .zip(&le)
        .filter(|(_, b)| **b)
        .map(|(t, _)| t.g + t.g_o + 1)
        .sum();
    let left = if k == 0 { 0 } else { tuples[k - 1].g_o + tuples[k - 1].delta_o };
    let right = if k == cap { 0 } else { tuples[k].g + tuples[k].delta };

    let r_min = p_i.saturating_sub(left);
    let r_max = p_i + right;
    let num = r_min + r_max;
    Est { res: num / 2, k, rem: num % 2 }
}

fn pack_commit(digest: &[Val; 8]) -> [Challenge; DIGEST_PACKING] {
    [
        Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 base coeffs"),
        Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 base coeffs"),
    ]
}

/// Prove a two-sided GK **approximate-rank** quantile decode against a committed
/// [`Gk2State`]. Self-verifies; records the timing split. Uses the
/// process-default [`Binding`] ([`bind::default_binding`]).
pub fn prove_gk2_decode(params: Gkb2DecodeParams, state: Gk2State, query: u32) -> DecodeProof {
    prove_gk2_decode_with(params, state, query, bind::default_binding())
}

/// [`prove_gk2_decode`] with an explicit [`Binding`].
///
/// `Semantic` / `Bound` surface the query statement `(Com(S), q, answer)`
/// through the Expose NPO (16 base values: commit[8], q[4], answer[4]; read it
/// with [`crate::decode::read_exposed_statement`]) and pin the query's three
/// upper extension coordinates to 0, so the exposed query is exactly the
/// scalar the rank relation used (Property 3). [`Binding::Legacy`] is the
/// pre-fix circuit, byte-for-byte: it exposes nothing, so its proof certifies
/// an answer the verifier never sees. No in-circuit coefficient re-binding
/// (the merged fork binds decompositions), so `Bound` equals `Semantic`.
pub fn prove_gk2_decode_with(
    params: Gkb2DecodeParams,
    state: Gk2State,
    query: u32,
    binding: Binding,
) -> DecodeProof {
    prove_gk2_decode_commit(params, state, query, binding, CommitMode::Plain, &SaltBb::ZERO)
}

/// [`prove_gk2_decode_with`] against a commitment made under `mode` (revision
/// B2, [`crate::commitment::hiding`]). `Plain` is the pre-B2 circuit byte for
/// byte (`salt` ignored). Under `Hiding` the decoder opens
/// `Com(S_t; ρ) = commit_gk2_state_with(state, Hiding, salt)`: the salt is the
/// FIRST 3 private inputs, and (under `Semantic`/`Bound`) the exposed
/// commitment is the hiding one. For a query at version `t` of history `h`
/// the honest salt is `rho_state_bb_in(seed, CommitFamily::GreenwaldKhanna,
/// h, t)` (`rho_state_bb(seed, .., t)` in the genesis history), the same
/// randomizer band-merge leaf `t` closed its final state with; at `t = 0` it
/// is the public zero in the genesis history and the anchor salt in a
/// continued one. So under `Hiding` the public zero salt opens only the
/// empty genesis state (the one state commitment, `Com(S_0; 0)`, that the
/// verifier recomputes itself): handed [`SaltBb::ZERO`] with any other state
/// (a forgotten salt at `t ≥ 1`) the decoder panics instead of publishing
/// the guess-checkable `Com(S_t; 0)`. A nonzero wrong salt still proves (the
/// circuit does not check the derivation) and exposes a commitment that is
/// not the log's.
pub fn prove_gk2_decode_commit(
    params: Gkb2DecodeParams,
    state: Gk2State,
    query: u32,
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> DecodeProof {
    build_gk2_decode_commit(params, &state, query, binding, mode, salt).prove("gk2 decode")
}

/// The trusted verification key of the two-sided GK rank decoder for
/// `params` under `binding`, derived from public parameters only (a proof over
/// the empty state). Pin query proofs to it with
/// [`crate::decode::verify_decode_proof`]. Plain commitments
/// ([`gk2_decode_vk_commit`] with [`CommitMode::Plain`]).
pub fn gk2_decode_vk(params: Gkb2DecodeParams, binding: Binding) -> DecodeVk {
    gk2_decode_vk_commit(params, binding, CommitMode::Plain)
}

/// [`gk2_decode_vk`] of the decoder built under `mode` (revision B2): the
/// trusted VK of [`prove_gk2_decode_commit`] proofs. Derived from the empty
/// state with the public zero salt; the salt is a witness, so every `Hiding`
/// decode proof of the same parameters has this VK.
pub fn gk2_decode_vk_commit(params: Gkb2DecodeParams, binding: Binding, mode: CommitMode) -> DecodeVk {
    let empty = Gk2State::empty(GkbParams { capacity: params.capacity, batch: 2, s: 1 });
    build_gk2_decode_commit(params, &empty, 0, binding, mode, &SaltBb::ZERO).derive_vk("gk2 decode")
}

/// Build the two-sided GK rank decode circuit and its witness (Plain
/// commitment; test-only since B2, the entry points go through
/// [`build_gk2_decode_commit`]).
#[cfg(test)]
pub(crate) fn build_gk2_decode(
    params: Gkb2DecodeParams,
    state: &Gk2State,
    query: u32,
    binding: Binding,
) -> StdDecodeCircuit {
    build_gk2_decode_commit(params, state, query, binding, CommitMode::Plain, &SaltBb::ZERO)
}

/// [`build_gk2_decode`] against a commitment made under `mode` with `salt`
/// (see [`prove_gk2_decode_commit`]).
pub(crate) fn build_gk2_decode_commit(
    params: Gkb2DecodeParams,
    state: &Gk2State,
    query: u32,
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> StdDecodeCircuit {
    let expose = binding.is_bound();
    params.validate();
    let Gkb2DecodeParams { capacity: cap, release } = params;
    assert_eq!(state.tuples.len(), cap, "state shape must match params");
    if mode.is_hiding() && salt.is_zero() {
        assert!(
            state.tuples.iter().all(|t| *t == Gk2Tuple::dummy()),
            "Hiding GK decode: the public zero salt opens only the empty genesis state Com(S_0; 0); \
             a query at t >= 1 (or at version 0 of a continued history) needs its real salt"
        );
    }

    let commit = commit_gk2_state_with(state, mode, salt);
    let est = native_estimate(state, query);
    let answer = release.apply(est.res);

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

    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let query_pi = b.alloc_public_input("query");
    let answer_pi = b.alloc_public_input("answer");
    if expose {
        b.add_expose(&[commit_pis[0], commit_pis[1], query_pi, answer_pi])
            .expect("expose (commit, query, answer)");
    }
    b.tag(answer_pi, "gk2_dec_answer").expect("tag");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let two = b.alloc_const(Challenge::from_u64(2), "two");

    // B2: under `Hiding` the salt of `Com(S_t)` is the first 3 private
    // inputs; `Plain` allocates nothing.
    let salt_t = mode.is_hiding().then(|| hiding::alloc_salt_targets(&mut b));
    let cells_packed: Vec<ExprId> =
        (0..2 * cap).map(|_| b.alloc_private_input("cell_packed")).collect();
    let le: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("le")).collect();
    let sel: Vec<ExprId> = (0..=cap).map(|_| b.alloc_private_input("sel")).collect();
    let res_w = b.alloc_private_input("res");
    let rem_w = b.alloc_private_input("rem");
    let flag = if matches!(release, ReleasePolicy::Threshold(_)) {
        Some(b.alloc_private_input("flag"))
    } else {
        None
    };

    // ── Stage 1: open the committed state ──
    // Salted under `Hiding`; under `Plain` exactly the raw
    // `add_hash_slice(cells)` (`Binding::Semantic` in `hiding::commit_hash`).
    let digest = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &Poseidon2Config::BABY_BEAR_D4_W16,
        CommitKind::State,
        CommitFamily::GreenwaldKhanna,
        salt_t.as_ref(),
        &cells_packed,
        zero,
        Binding::Semantic,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }

    let qc = b.decompose_ext_to_base_coeffs::<Val>(query_pi).expect("decompose query");
    let query_b = qc[0];
    if expose {
        // The exposed query is the whole Challenge: pin its upper coordinates
        // so it is exactly the scalar `q` the relation below uses.
        for &hi in &qc[1..] {
            b.connect(hi, zero);
        }
    }

    // ── Stage 2: decompose each tuple (2 challenges → 8 base coeffs) ──
    let f: Vec<Vec<ExprId>> = cells_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose cell"))
        .collect();

    // ── Stage 3: per-tuple ≤-flag + prefix mass P_i ──
    let q_plus_1 = b.add(query_b, one);
    let mut p_acc = zero;
    for r in 0..cap {
        // Range-check every decomposed field — the update circuit's consumption
        // pattern (which balances the WitnessChecks bus for 2 challenges/tuple);
        // the pad coeffs are pinned to 0.
        let e_r = f[2 * r][0];
        let g1_r = f[2 * r][1];
        let g2_r = f[2 * r][2];
        let _ = b.add_range_bits::<Val>(e_r, E_BITS).expect("e range");
        let _ = b.add_range_bits::<Val>(g1_r, MASS_BITS).expect("g1 range");
        let _ = b.add_range_bits::<Val>(g2_r, MASS_BITS).expect("g2 range");
        let _ = b.add_range_bits::<Val>(f[2 * r][3], MASS_BITS).expect("d1 range");
        let _ = b.add_range_bits::<Val>(f[2 * r + 1][0], MASS_BITS).expect("d2 range");
        let _ = b.add_range_bits::<Val>(f[2 * r + 1][1], MASS_BITS).expect("t range");
        b.connect(f[2 * r + 1][2], zero);
        b.connect(f[2 * r + 1][3], zero);
        let le_r = le[r];

        // le_r boolean.
        let lm1 = b.sub(le_r, one);
        let bchk = b.mul(le_r, lm1);
        b.connect(bchk, zero);

        // Force le_r = [e_r ≤ q] via a single non-negative range-checked diff.
        let nle = b.sub(one, le_r);
        let big_q = b.mul(le_r, query_b);
        let big_v = b.mul(e_r, nle);
        let big = b.add(big_q, big_v);
        let small_v = b.mul(e_r, le_r);
        let small_q = b.mul(nle, q_plus_1);
        let small = b.add(small_v, small_q);
        let diff = b.sub(big, small);
        let _ = b.add_range_bits::<Val>(diff, E_BITS).expect("le diff >= 0");

        // P_i += le_r · (g₁ + g₂ + 1).
        let gsum = b.add(g1_r, g2_r);
        let gsa = b.add(gsum, one);
        let contrib = b.mul(le_r, gsa);
        p_acc = b.add(p_acc, contrib);
    }

    // ── Stage 4: one-hot boundary selector + two-sided bracket estimator ──
    let mut sel_sum = zero;
    let mut k_acc = zero;
    let mut left_dev = zero;
    let mut right_dev = zero;
    for k in 0..=cap {
        let s = sel[k];
        let sm1 = b.sub(s, one);
        let bchk = b.mul(s, sm1);
        b.connect(bchk, zero);
        sel_sum = b.add(sel_sum, s);

        let kconst = b.alloc_const(Challenge::from_u64(k as u64), "k");
        let ks = b.mul(kconst, s);
        k_acc = b.add(k_acc, ks);

        if k >= 1 {
            // tuple k-1: g₂ + Δ₂.
            let g2 = f[2 * (k - 1)][2];
            let d2 = f[2 * (k - 1) + 1][0];
            let dev = b.add(g2, d2);
            let t = b.mul(dev, s);
            left_dev = b.add(left_dev, t);
        }
        if k < cap {
            // tuple k: g₁ + Δ₁.
            let g1 = f[2 * k][1];
            let d1 = f[2 * k][3];
            let dev = b.add(g1, d1);
            let t = b.mul(dev, s);
            right_dev = b.add(right_dev, t);
        }
    }
    b.connect(sel_sum, one);

    // Boundary correctness: Σ k·sel[k] = Σ le_r (# tuples with e ≤ q).
    let mut le_sum = zero;
    for r in 0..cap {
        le_sum = b.add(le_sum, le[r]);
    }
    b.connect(k_acc, le_sum);

    // res = ⌊(r_min + r_max)/2⌋ with witnessed remainder.
    let r_min = b.sub(p_acc, left_dev);
    let r_max = b.add(p_acc, right_dev);
    let num = b.add(r_min, r_max);

    let rm1 = b.sub(rem_w, one);
    let bchk = b.mul(rem_w, rm1);
    b.connect(bchk, zero);
    let two_res = b.mul(res_w, two);
    let recon = b.add(two_res, rem_w);
    b.connect(recon, num);

    let res_plus0 = b.add(res_w, zero);
    let zero_sum = b.add(zero, zero);
    let diff_res = b.sub(res_plus0, zero_sum);
    let _ = b.add_range_bits::<Val>(diff_res, RANK_BITS).expect("res >= 0");

    // ── Stage 5: release policy → answer ──
    match release {
        ReleasePolicy::Identity => {
            let released = b.mul(res_w, one);
            b.connect(released, answer_pi);
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.alloc_const(Challenge::from_u64(t), "theta");
            let fl = flag.unwrap();
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            let res_minus_t = b.sub(res_w, theta);
            let tm = b.sub(theta, res_w);
            let t_minus_res_m1 = b.sub(tm, one);
            let nf = b.sub(one, fl);
            let a = b.mul(fl, res_minus_t);
            let nft = b.mul(nf, t_minus_res_m1);
            let chosen = b.add(a, nft);
            let _ = b.add_range_bits::<Val>(chosen, RANK_BITS).expect("chosen >= 0");
            let released = b.mul(fl, res_w);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build gk2 decode circuit");

    let commit_packed = pack_commit(&commit.0);
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_u64(query as u64));
    public_inputs.push(Challenge::from_u64(answer));

    let mut private_inputs: Vec<Challenge> =
        if mode.is_hiding() { salt.packed().to_vec() } else { Vec::new() };
    private_inputs.extend(pack_tuples2(&state.tuples));
    for t in &state.tuples {
        private_inputs.push(if t.e <= query { Challenge::ONE } else { Challenge::ZERO });
    }
    for k in 0..=cap {
        private_inputs.push(if k == est.k { Challenge::ONE } else { Challenge::ZERO });
    }
    private_inputs.push(Challenge::from_u64(est.res));
    private_inputs.push(Challenge::from_u64(est.rem));
    if flag.is_some() {
        let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
        private_inputs.push(if est.res >= t { Challenge::ONE } else { Challenge::ZERO });
    }

    StdDecodeCircuit::new(circuit, public_inputs, private_inputs, answer, expose, "gk2 decode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::gk_bandmerge::{apply_batch2, commit_gk2_state};

    fn built_state(cap: usize) -> Gk2State {
        let params = GkbParams { capacity: cap, batch: 8, s: 2 };
        let mut st = Gk2State::empty(params);
        for chunk in
            [[900u32, 800, 700, 600, 500, 400, 300, 200], [850, 250, 650, 450, 950, 150, 550, 350]]
        {
            st = apply_batch2(&st, &chunk);
        }
        st
    }

    fn native_res(st: &Gk2State, q: u32) -> u64 {
        native_estimate(st, q).res
    }

    #[test]
    fn gk2_decode_matches_native_and_selfverifies() {
        let cap = 16;
        let st = built_state(cap);
        for &q in &[0u32, 175, 400, 500, 675, 950] {
            let params = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
            let proof = prove_gk2_decode(params, st.clone(), q);
            assert_eq!(proof.answer, native_res(&st, q), "decode answer must match native at q={q}");
        }
    }

    #[test]
    fn gk2_decode_within_epsilon_n() {
        let cap = 16;
        let st = built_state(cap);
        let eps_n = st.n / st.params.s;
        let mut seen: Vec<u32> = Vec::new();
        for chunk in
            [[900u32, 800, 700, 600, 500, 400, 300, 200], [850, 250, 650, 450, 950, 150, 550, 350]]
        {
            seen.extend_from_slice(&chunk);
        }
        seen.sort_unstable();
        for &q in &[150u32, 300, 500, 700, 900] {
            let est = native_res(&st, q);
            let truth = seen.partition_point(|&v| v <= q) as u64;
            assert!(est.abs_diff(truth) <= eps_n + 1, "rank est {est} off from {truth} by > εN");
        }
    }

    #[test]
    fn gk2_decode_threshold_release() {
        let cap = 16;
        let st = built_state(cap);
        let q = 500u32;
        let raw = native_res(&st, q);
        let p_hi = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Threshold(raw + 1) };
        assert_eq!(prove_gk2_decode(p_hi, st.clone(), q).answer, 0);
        let p_lo = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Threshold(raw) };
        assert_eq!(prove_gk2_decode(p_lo, st.clone(), q).answer, raw);
    }

    // ── Query statement (Property 3): exposed (Com(S), q, answer) ──────────

    use crate::decode::{QueryStatement, check_query_statement, read_exposed_statement};
    use crate::sketch::bind::Binding;

    /// `Semantic` / `Bound` expose `(Com(S), q, answer)`: the statement read off
    /// a VERIFIED proof is the queried commitment, the query and the native
    /// estimate (identity and threshold release). `Legacy` exposes nothing.
    #[test]
    fn gk2_decode_exposes_commit_query_answer() {
        let cap = 16;
        let st = built_state(cap);
        let commit = commit_gk2_state(&st).0;
        for (q, release) in [
            (0u32, ReleasePolicy::Identity),
            (500, ReleasePolicy::Identity),
            (950, ReleasePolicy::Identity),
            (500, ReleasePolicy::Threshold(1000)),
        ] {
            let p = Gkb2DecodeParams { capacity: cap, release };
            let want = QueryStatement::new(commit, q as u64, release.apply(native_res(&st, q)));
            for binding in [Binding::Semantic, Binding::Bound] {
                let dc = build_gk2_decode(p, &st, q, binding);
                let proof = dc.prove_traces(&dc.run("gk2 decode")).expect("honest proof verifies");
                assert_eq!(read_exposed_statement(&proof), Some(want), "{binding:?} q={q} {release:?}");
                assert_eq!(check_query_statement(&proof, &want), Ok(()));
            }
            assert_eq!(prove_gk2_decode(p, st.clone(), q).statement(), Some(want));
        }
        let p = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
        let legacy = prove_gk2_decode_with(p, st.clone(), 500, Binding::Legacy);
        assert_eq!(legacy.statement(), None, "Legacy exposes nothing");
        assert_eq!(legacy.answer, native_res(&st, 500));
    }

    /// Tampered answers are rejected (shared checks, see
    /// [`crate::decode::assert_tampered_answer_rejected`]).
    #[test]
    fn gk2_decode_tampered_answer_rejected() {
        let cap = 16;
        let st = built_state(cap);
        let q = 500u32;
        let p = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
        let want = QueryStatement::new(commit_gk2_state(&st).0, q as u64, native_res(&st, q));
        for binding in [Binding::Semantic, Binding::Bound] {
            crate::decode::assert_tampered_answer_rejected(
                &build_gk2_decode(p, &st, q, binding),
                &build_gk2_decode(p, &st, q, Binding::Legacy),
                "gk2_dec_answer",
                want,
            );
        }
    }

    /// The exposed query is canonical: a query Challenge with a nonzero upper
    /// coordinate (the relation reads only coordinate 0) has no witness under
    /// `Semantic`, while the pre-fix `Legacy` circuit runs it (control).
    #[test]
    fn gk2_decode_noncanonical_query_rejected() {
        use p3_field::BasedVectorSpace;
        let cap = 16;
        let st = built_state(cap);
        let p = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
        let bump = |dc: &mut crate::decode::StdDecodeCircuit| {
            let q = dc.public_inputs[2].as_basis_coefficients_slice().to_vec();
            dc.public_inputs[2] =
                Challenge::from_basis_coefficients_slice(&[q[0], Val::ONE, q[2], q[3]]).unwrap();
        };
        let mut legacy = build_gk2_decode(p, &st, 500, Binding::Legacy);
        bump(&mut legacy);
        assert!(crate::sketch::forge::catch(|| legacy.run("gk2 decode")).is_some(), "Legacy runs it");
        let mut sem = build_gk2_decode(p, &st, 500, Binding::Semantic);
        bump(&mut sem);
        assert!(crate::sketch::forge::catch(|| sem.run("gk2 decode")).is_none(), "Semantic rejects it");
    }

    /// The pinned verifier: the VK derived from public parameters (empty
    /// state) accepts honest proofs over built states and returns their
    /// statements; it rejects the Legacy proof and a lying fake circuit.
    #[test]
    fn gk2_decode_pinned_verifier() {
        let cap = 16;
        let st = built_state(cap);
        let commit = commit_gk2_state(&st).0;
        let p = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
        let vk = gk2_decode_vk(p, Binding::Semantic);
        let (a, b) = (build_gk2_decode(p, &st, 500, Binding::Semantic), build_gk2_decode(p, &st, 175, Binding::Semantic));
        crate::decode::assert_pinned_decode_verifier(
            &vk,
            &[
                (&a, QueryStatement::new(commit, 500, native_res(&st, 500))),
                (&b, QueryStatement::new(commit, 175, native_res(&st, 175))),
            ],
            &build_gk2_decode(p, &st, 500, Binding::Legacy),
        );
    }

    // ── B2: hiding commitments (`crate::commitment::hiding`) ─────────────────

    /// (6) B2: a Hiding decode opens `Com(S_t; ρ)`. Under `Semantic`/`Bound`
    /// it exposes the hiding commitment (not the plain one) with the same
    /// answer; the Plain decoder is the pre-B2 circuit (VK recorded before
    /// this change, both off a proof and from the pinned [`gk2_decode_vk`]);
    /// the Hiding VK does not depend on the salt and equals
    /// [`gk2_decode_vk_commit`]`(.., Hiding)`, which accepts the Hiding proof
    /// while the Plain pin rejects it. A query at version `t` opened with
    /// `ρ^S_t` exposes exactly the final commitment of the hiding band-merge
    /// leaf `t` (the lemma in `crate::commitment::hiding`); a wrong salt still
    /// proves, but exposes a commitment that is not the log's.
    #[test]
    fn hiding_decode_exposes_hiding_commit() {
        use crate::commitment::hiding::{Openings, SaltSeed, rho_state_bb};
        use crate::decode::verify_decode_proof;
        use crate::recursion::recursive::expose_forest::vk_pin_values;
        use crate::recursion::recursive::statement::Expose;
        use crate::sketch::gk_bandmerge::{build_gkb2_leaf_commit, commit_gk2_state_with};
        use p3_field::PrimeField64;

        let flat = |v: &[Challenge]| -> Vec<u64> {
            v.iter()
                .flat_map(|c| {
                    <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                        .iter()
                        .map(|x| x.as_canonical_u64())
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        #[cfg(not(feature = "zk"))]
        let recorded = [
            (Binding::Semantic, [203355892u64, 237880594, 1750979469, 1997198089, 576604346, 52959881, 1491069700, 322413283]),
            (Binding::Bound, [203355892, 237880594, 1750979469, 1997198089, 576604346, 52959881, 1491069700, 322413283]),
            (Binding::Legacy, [1884057042, 1978897654, 1908599913, 512142752, 520418862, 202716958, 153147690, 1581877963]),
        ];
        // The same circuits under the `zk` feature (hiding PCS, ZK LogUp masks):
        // recorded on the zk-logup-mask forks (Plonky3 280b1a07, Plonky3_RangeAir
        // 3acdc06); equal across separate processes.
        #[cfg(feature = "zk")]
        let recorded = [
            (Binding::Semantic, [902496403u64, 515422773, 159835801, 720520716, 37006762, 1887509070, 1251845308, 1474720669]),
            (Binding::Bound, [902496403, 515422773, 159835801, 720520716, 37006762, 1887509070, 1251845308, 1474720669]),
            (Binding::Legacy, [1444927145, 1247787850, 2006318704, 329517752, 294097233, 916706900, 1968166527, 680753177]),
        ];
        let gk = CommitFamily::GreenwaldKhanna;
        let cap = 16;
        let st = built_state(cap);
        let q = 500u32;
        let p = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
        let seed = SaltSeed::for_tests(61);
        let (rho, rho2) = (rho_state_bb(&seed, gk, 4), rho_state_bb(&seed, gk, 5));
        for (binding, vk) in recorded {
            let want: Vec<u64> = vk.iter().flat_map(|&x| [x, 0, 0, 0]).collect();
            let plain = prove_gk2_decode_with(p, st.clone(), q, binding);
            assert_eq!(flat(&vk_pin_values(&plain.output.0)), want, "{binding:?}: Plain decode VK drifted");
            let plain_vk = gk2_decode_vk(p, binding);
            assert_eq!(flat(&plain_vk.commitment), want, "{binding:?}: pinned Plain decode VK drifted");
            let hid = prove_gk2_decode_commit(p, st.clone(), q, binding, CommitMode::Hiding, &rho);
            assert_eq!(hid.answer, native_res(&st, q), "{binding:?}");
            assert_eq!(hid.answer, plain.answer, "{binding:?}");
            let hid2 = prove_gk2_decode_commit(p, st.clone(), q, binding, CommitMode::Hiding, &rho2);
            assert_eq!(vk_pin_values(&hid.output.0), vk_pin_values(&hid2.output.0), "{binding:?}");
            assert_ne!(vk_pin_values(&hid.output.0), vk_pin_values(&plain.output.0), "{binding:?}");
            let hid_vk = gk2_decode_vk_commit(p, binding, CommitMode::Hiding);
            assert_eq!(hid_vk.commitment, vk_pin_values(&hid.output.0), "{binding:?}: pinned Hiding decode VK");
            assert_eq!(gk2_decode_vk_commit(p, binding, CommitMode::Plain).commitment, plain_vk.commitment);
            if binding.is_bound() {
                let c = commit_gk2_state_with(&st, CommitMode::Hiding, &rho).0;
                assert_ne!(c, commit_gk2_state(&st).0, "{binding:?}");
                let want_st = QueryStatement::new(c, q as u64, native_res(&st, q));
                assert_eq!(hid.statement(), Some(want_st), "{binding:?}");
                assert_ne!(hid2.statement().unwrap().commit, c, "{binding:?}: another version, another commitment");
                assert_eq!(verify_decode_proof(&hid.output.0, &hid_vk), Ok(want_st), "{binding:?}");
                assert!(verify_decode_proof(&hid.output.0, &plain_vk).is_err(), "{binding:?}: the Plain pin");
            } else {
                assert_eq!(hid.statement(), None, "Legacy exposes nothing");
            }
        }

        // Query at version t == band-merge leaf t's final commitment.
        let binding = Binding::Semantic;
        let t = 2u64;
        let lp = GkbParams { capacity: 4, batch: 2, s: 2 };
        let s_prev = apply_batch2(&Gk2State::empty(lp), &[10, 11]);
        let ups = vec![20u32, 21];
        let mut leaf = build_gkb2_leaf_commit(lp, Expose::Interval, binding, CommitMode::Hiding);
        let r = leaf.prove_epoch_commit(t, s_prev.clone(), ups.clone(), &Openings::for_leaf(&seed, gk, t));
        let s_t = apply_batch2(&s_prev, &ups);
        let dp = Gkb2DecodeParams { capacity: lp.capacity, release: ReleasePolicy::Identity };
        let qp = prove_gk2_decode_commit(dp, s_t.clone(), 15, binding, CommitMode::Hiding, &rho_state_bb(&seed, gk, t));
        assert_eq!(qp.statement().unwrap().commit, r.final_.0, "query at t opens leaf t's final commitment");
        let wrong = prove_gk2_decode_commit(dp, s_t, 15, binding, CommitMode::Hiding, &rho_state_bb(&seed, gk, t + 1));
        assert_ne!(wrong.statement().unwrap().commit, r.final_.0, "a wrong salt exposes another commitment");
    }

    /// (F3, F5) Decoder twin of the leaf's overhead test: a Hiding decode
    /// costs exactly +2 Poseidon2 rows and +3 ALU rows (one commitment)
    /// under every binding, and none of its 12 salt values is a public value
    /// of the proof.
    #[test]
    fn hiding_decode_row_overhead_and_no_salt_in_public_values() {
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows, trace_rows};
        use crate::commitment::hiding::{SaltSeed, rho_state_bb};
        let rho = rho_state_bb(&SaltSeed::for_tests(62), CommitFamily::GreenwaldKhanna, 3);
        let cap = 16;
        let st = built_state(cap);
        let p = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let (p0, a0) = trace_rows(&build_gk2_decode(p, &st, 500, binding).run("gk2 decode"));
            let hc = build_gk2_decode_commit(p, &st, 500, binding, CommitMode::Hiding, &rho);
            let (p1, a1) = trace_rows(&hc.run("gk2 decode"));
            println!("B2 GK decode rows {binding:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 2, "{binding:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 3, "{binding:?}: ALU rows");
            let hid = prove_gk2_decode_commit(p, st.clone(), 500, binding, CommitMode::Hiding, &rho);
            assert_eq!(proof_alu_rows(&hid.output.0), a1, "{binding:?}: the proof's ALU height");
            assert_eq!(leaked_salts(&hid.output.0, &[rho]), vec![], "{binding:?}");
        }
    }

    /// (L2) Under `Hiding` the public zero salt opens only the empty genesis
    /// state, the one state commitment the verifier recomputes itself
    /// (`Com(S_0; 0)`; a continued history's version 0 opens with its
    /// anchor salt). A real state handed the zero salt (a forgotten opening
    /// at `t >= 1`) panics instead of publishing the guess-checkable
    /// `Com(S_t; 0)`, from the builder and the proving entry point alike.
    /// Controls: the Hiding VK derivation (empty state, zero salt), a real
    /// state with a real salt, and `Plain` (salt ignored) still build.
    #[test]
    fn hiding_decode_refuses_zero_salt_on_a_real_state() {
        use crate::commitment::hiding::{SaltSeed, rho_state_bb};
        use crate::sketch::forge;
        let cap = 16;
        let st = built_state(cap);
        let p = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
        let rho = rho_state_bb(&SaltSeed::for_tests(63), CommitFamily::GreenwaldKhanna, 2);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let msg = forge::catch_msg(|| {
                build_gk2_decode_commit(p, &st, 500, binding, CommitMode::Hiding, &SaltBb::ZERO).answer
            })
            .unwrap_err();
            assert!(msg.contains("public zero salt"), "{binding:?}: {msg}");
            let empty = Gk2State::empty(GkbParams { capacity: cap, batch: 8, s: 2 });
            let _ = build_gk2_decode_commit(p, &empty, 500, binding, CommitMode::Hiding, &SaltBb::ZERO);
            let _ = build_gk2_decode_commit(p, &st, 500, binding, CommitMode::Hiding, &rho);
            let _ = build_gk2_decode_commit(p, &st, 500, binding, CommitMode::Plain, &SaltBb::ZERO);
        }
        let msg = forge::catch_msg(|| {
            prove_gk2_decode_commit(p, st.clone(), 500, Binding::Semantic, CommitMode::Hiding, &SaltBb::ZERO).answer
        })
        .unwrap_err();
        assert!(msg.contains("public zero salt"), "{msg}");
        let _ = gk2_decode_vk_commit(p, Binding::Semantic, CommitMode::Hiding);
    }
}
