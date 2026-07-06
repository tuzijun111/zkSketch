//! Greenwald–Khanna **approximate-rank / quantile** decode circuit for the
//! **two-sided §4 band-merge** state ([`crate::sketch::gk_bandmerge::Gk2State`],
//! produced by the deployed `bandmerge2` update). The real-GK query counterpart
//! of the group-by [`crate::decode::greenwald_khanna`] decode: where that reads
//! the folded 4-field `GKFullState`, this reads the six-field two-sided tuple
//! `(e, g₁, g₂, Δ₁, Δ₂, t)` and binds the SAME [`commit_gk2_state`] digest the
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

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_range_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        range_air_builders, range_preprocessor, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{DIGEST_PACKING, make_leaf_config};
use crate::sketch::gk_bandmerge::{E_MAX, Gk2State, commit_gk2_state, pack_tuples2};

const LOG_FINAL_POLY_LEN: usize = 6;
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
/// [`Gk2State`]. Self-verifies; records the timing split.
pub fn prove_gk2_decode(params: Gkb2DecodeParams, state: Gk2State, query: u32) -> DecodeProof {
    params.validate();
    let Gkb2DecodeParams { capacity: cap, release } = params;
    assert_eq!(state.tuples.len(), cap, "state shape must match params");

    let commit = commit_gk2_state(&state);
    let est = native_estimate(&state, query);
    let answer = release.apply(est.res);

    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);

    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let query_pi = b.alloc_public_input("query");
    let answer_pi = b.alloc_public_input("answer");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let two = b.alloc_const(Challenge::from_u64(2), "two");

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
    let digest = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, true)
        .expect("hash cells");
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }

    let qc = b.decompose_ext_to_base_coeffs::<Val>(query_pi).expect("decompose query");
    let query_b = qc[0];

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

    let mut private_inputs: Vec<Challenge> = pack_tuples2(&state.tuples);
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

    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run gk2 decode circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false), range_preprocessor::<Val>()];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (gk2 decode)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_range_table::<4>();
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove gk2 decode");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify gk2 decode");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    DecodeProof { output: RecursionOutput(proof, Rc::new(circuit_prover_data)), answer }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::gk_bandmerge::{GkbParams, apply_batch2};

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
}
