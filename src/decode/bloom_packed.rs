//! Membership **query** circuit of the packed-byte Bloom filter
//! ([`crate::sketch::bloom_packed`], design B1): proves
//! `answer = AND_j bit(i_j) of S[j·W/8 + q_j(key)]` against the committed
//! byte state, with the same verifier-visible statement as the bit-array
//! decoder ([`super::bloom`]): the Expose op `(Com(S), record(key), answer)`,
//! 16 values, `record(key) = [k0, k1, k2, k3 + 2^16]`
//! ([`super::bloom::bloom_query_input`]), so
//! [`crate::decode::verify_decode_proof`] pins a proof to
//! [`bloom_packed_decode_vk_commit`] and returns the standard
//! [`crate::decode::QueryStatement`].
//!
//! ## Constraint list (query)
//!
//! | # | constraint | gadget | test switch |
//! |---|---|---|---|
//! | Q1 | every state byte `S_u ∈ [0,256)` | one byte lookup | `cell_pin` |
//! | Q2 | `Com(S) = H(pack(S))` (3 bytes per limb, salted under `Hiding`, family 7) | ALU packing, bound sponge | — |
//! | Q3 | the key is routed as an ACTIVE record (`act = 1`): key bytes, record, bound Poseidon2 digest, canonical split `digest[j] = 2^log_w·hi + 8q_j + i_j` | the leaf's routing gadget | the leaf's B4–B7 switches |
//! | Q4 | per slice a TENSOR one-hot selector: `s1 ∈ {0,1}^{na}`, `s2 ∈ {0,1}^{nb}` (`na·nb = W/8`), `Σ s1 = Σ s2 = 1`, `nb·Σ a·s1_a + Σ b·s2_b = q_j` | BoolCheck + ALU | `onehot_sum` |
//! | Q5 | `o_j = Σ_b s2_b Σ_a s1_a S[j·W/8 + a·nb + b]` (exactly `S[j·W/8 + q_j]`) | ALU | — |
//! | Q6 | split-at-bit of `o_j` at `e_j = 2^{i_j}`: `o_j = (2H + c_j)·e_j + L`, `c_j ∈ {0,1}`, `H, L ∈ [0,256)`, `L < e_j` | the leaf's split gadget | the leaf's D2–D5 switches |
//! | Q7 | `answer = ∏_j c_j` | ALU | — |
//!
//! The selector and the split are exact (both one-hots select one cell; a
//! byte splits uniquely), so the answer is the AND of the `k` filter bits.
//! The circuit is `Θ(M_w)` (the dense re-hash plus `k` tensor selections of
//! `W/8` products) and is rebuilt per query; its VK depends only on
//! `(k, log_w)` and the commitment mode (the state, key, splits and
//! selectors are private witnesses).
//!
//! Changes from the 2026-10-14 prototype: byte pins are direct RangeAir
//! lookups (no ALU rows); the routing gadget is the leaf's (byte-witnessed
//! ranges); the zero-salt guard, VK derivation and switches are added.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4, poseidon2_preprocessor,
        range_air_builders, range_preprocessor, recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::hiding::{self, CommitKind, CommitMode, SaltBb};
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::decode::{DecodeProof, DecodeVk};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::make_leaf_config;
use crate::recursion::recursive::expose_forest::vk_pin_values;
use crate::recursion::recursive::root_vk::bound_proof_shape;
use crate::sketch::bloom_omc::record_vals;
use crate::sketch::bloom_packed::{
    BloomPackedParams, PConsts, RECORD_WITNESSES, byte_pin, checks, commit_hash_packed, commit_packed_with,
    pack_words, packed_empty, packed_positions, pow2_of_bits, record_witness, route_packed, split_at_bit,
    split_count, split_values,
};

const LOG_FINAL_POLY_LEN: usize = 6;

pub use super::bloom::{QUERY_EXPOSED_LEN, bloom_query_input, read_exposed_query};

thread_local! {
    /// Test-only witness tampering of the query (see the injection site).
    static TAMPER: std::cell::Cell<QueryTamper> = const { std::cell::Cell::new(QueryTamper::None) };
}

/// Test-only query forgeries (the circuit is unchanged; only the witness).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QueryTamper {
    None,
    /// Open slice 0 at the next word (`q + 1 mod W/8`), selectors and all.
    ShiftWord,
    /// Slice 0: the two-hot `s1 = e_0 + e_a` (index sum still `a`, selector
    /// sum 2) that opens the sum of two cells (needs `onehot_sum` off).
    TwoHot,
}

/// Run `f` with the query tampering `t` (restored afterwards).
pub fn with_query_tamper<T>(t: QueryTamper, f: impl FnOnce() -> T) -> T {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            TAMPER.with(|c| c.set(QueryTamper::None));
        }
    }
    TAMPER.with(|c| c.set(t));
    let _r = Restore;
    f()
}

/// Tensor dimensions of the per-slice selector: `na·nb = W/8`, `na ≥ nb`.
pub fn selector_dims(p: &BloomPackedParams) -> (usize, usize) {
    let qa = p.q_bits().div_ceil(2);
    (1 << qa, 1 << (p.q_bits() - qa))
}

/// The trusted VK of the packed membership circuit at `(k, log_w)` under
/// `mode`, derived from public parameters only (proved once over the empty
/// filter and key 0 with the public zero salt; every state / key / selector
/// value is a witness). `params.batch` is ignored.
pub fn bloom_packed_decode_vk_commit(params: BloomPackedParams, mode: CommitMode) -> DecodeVk {
    let proof = prove_bloom_packed_query_commit(params, &packed_empty(&params), 0, mode, &SaltBb::ZERO);
    DecodeVk { commitment: vk_pin_values(&proof.output.0), shape: Some(bound_proof_shape(&proof.output.0)) }
}

/// [`bloom_packed_decode_vk_commit`] under `Plain`.
pub fn bloom_packed_decode_vk(params: BloomPackedParams) -> DecodeVk {
    bloom_packed_decode_vk_commit(params, CommitMode::Plain)
}

/// Prove `answer = contains(S, key)` against `Com(S)` (`Plain`).
pub fn prove_bloom_packed_query(params: BloomPackedParams, words: &[u8], key: u64) -> DecodeProof {
    prove_bloom_packed_query_commit(params, words, key, CommitMode::Plain, &SaltBb::ZERO)
}

/// [`prove_bloom_packed_query`] against `Com(S; salt)` under `mode`. Under
/// `Hiding` the public zero salt opens only the empty genesis filter (any
/// other state panics instead of publishing the guess-checkable
/// `Com(S_t; 0)`).
pub fn prove_bloom_packed_query_commit(
    params: BloomPackedParams,
    words: &[u8],
    key: u64,
    mode: CommitMode,
    salt: &SaltBb,
) -> DecodeProof {
    try_prove_bloom_packed_query_commit(params, words, key, mode, salt)
        .unwrap_or_else(|e| panic!("packed bloom query rejected: {e}"))
}

/// [`prove_bloom_packed_query_commit`] reporting the rejecting stage.
pub fn try_prove_bloom_packed_query_commit(
    params: BloomPackedParams,
    words: &[u8],
    key: u64,
    mode: CommitMode,
    salt: &SaltBb,
) -> Result<DecodeProof, String> {
    params.check()?;
    let p = &params;
    let (mw, wps) = (p.m_words(), p.words_per_slice());
    assert_eq!(words.len(), mw, "state must have M_w = k·W/8 bytes");
    if mode.is_hiding() && salt.is_zero() {
        assert!(
            words.iter().all(|&x| x == 0),
            "Hiding packed Bloom decode: the public zero salt opens only the empty genesis state Com(S_0; 0); \
             a query at t >= 1 needs its real salt"
        );
    }
    let ck = checks();
    let (na, nb) = selector_dims(p);
    debug_assert_eq!(na * nb, wps);

    // ─── Circuit ─────────────────────────────────────────────────────────
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    b.enable_expose(generate_expose_trace::<Val, Challenge>);
    let commit_pis: [ExprId; 2] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" }));
    let rec_pi = b.alloc_public_input("record");
    let answer_pi = b.alloc_public_input("answer");
    b.add_expose(&[commit_pis[0], commit_pis[1], rec_pi, answer_pi]).expect("expose query");
    let c = PConsts::new(&mut b, p);
    let idx: Vec<ExprId> = (0..na.max(nb)).map(|i| b.alloc_const(Challenge::from_u64(i as u64), "i")).collect();
    let nb_const = b.alloc_const(Challenge::from_u64(nb as u64), "nb");

    let salt_t = mode.is_hiding().then(|| hiding::alloc_salt_targets(&mut b));
    let cells: Vec<ExprId> = (0..mw).map(|_| b.alloc_private_input("cell")).collect();
    let key_bytes: Vec<ExprId> = (0..RECORD_WITNESSES - 1).map(|_| b.alloc_private_input("key_byte")).collect();
    let split: Vec<ExprId> = (0..split_count(p)).map(|_| b.alloc_private_input("split")).collect();
    let sel: Vec<(Vec<ExprId>, Vec<ExprId>)> = (0..p.k)
        .map(|_| {
            (
                (0..na).map(|_| b.alloc_private_input("s1")).collect(),
                (0..nb).map(|_| b.alloc_private_input("s2")).collect(),
            )
        })
        .collect();
    let ext: Vec<[ExprId; 3]> = (0..p.k).map(|_| std::array::from_fn(|_| b.alloc_private_input("cHL"))).collect();

    // Q1–Q2: the state bytes and their commitment.
    let packed = pack_words(&mut b, &c, p, &cells);
    if ck.cell_pin {
        for &x in &cells {
            byte_pin(&mut b, x);
        }
    }
    let dig = commit_hash_packed(&mut b, &cfg, CommitKind::State, salt_t.as_ref(), &packed, c.zero);
    for i in 0..2 {
        b.connect(dig[i], commit_pis[i]);
    }
    // Q3: route the key as an active record.
    let (rec, _limbs, routes) = route_packed(&mut b, &cfg, &c, p, &key_bytes, c.one, &split, &ck);
    b.connect(rec, rec_pi);
    // Q4–Q7.
    let mut answer = c.one;
    for (j, route) in routes.iter().enumerate() {
        let (s1, s2) = &sel[j];
        let mut sum1 = s1[0];
        let mut ia = b.mul(s1[0], idx[0]);
        b.assert_bool(s1[0]);
        for a in 1..na {
            b.assert_bool(s1[a]);
            sum1 = b.add(sum1, s1[a]);
            ia = b.mul_add(s1[a], idx[a], ia);
        }
        let mut sum2 = s2[0];
        let mut ibx = b.mul(s2[0], idx[0]);
        b.assert_bool(s2[0]);
        for bb in 1..nb {
            b.assert_bool(s2[bb]);
            sum2 = b.add(sum2, s2[bb]);
            ibx = b.mul_add(s2[bb], idx[bb], ibx);
        }
        if ck.onehot_sum {
            b.connect(sum1, c.one);
            b.connect(sum2, c.one);
        }
        let qexpr = b.mul_add(ia, nb_const, ibx);
        b.connect(qexpr, route.q);
        let base = j * wps;
        let mut selv: Option<ExprId> = None;
        for bb in 0..nb {
            let mut r = b.mul(s1[0], cells[base + bb]);
            for a in 1..na {
                r = b.mul_add(s1[a], cells[base + a * nb + bb], r);
            }
            selv = Some(match selv {
                None => b.mul(s2[bb], r),
                Some(acc) => b.mul_add(s2[bb], r, acc),
            });
        }
        let selv = selv.expect("nb ≥ 1");
        let [cb, hh, ll] = ext[j];
        let e = pow2_of_bits(&mut b, &c, &route.ib);
        let v = split_at_bit(&mut b, &c, e, cb, hh, ll, &ck);
        b.connect(v, selv);
        answer = b.mul(answer, cb);
    }
    b.connect(answer, answer_pi);
    let circuit = b.build().map_err(|e| format!("build: {e:?}"))?;

    // ─── Native witness ──────────────────────────────────────────────────
    let tamper = TAMPER.with(|t| t.get());
    let mut opened: Vec<(u64, u64)> = packed_positions(p, Some(key));
    if tamper == QueryTamper::ShiftWord {
        opened[0].0 = (opened[0].0 + 1) % wps as u64;
    }
    let commit = commit_packed_with(p, words, mode, salt);
    let rv = record_vals(Some(key));
    let mut answer_native = 1u64;
    let mut private_inputs: Vec<Challenge> = Vec::with_capacity(mw + 2 * p.k * wps.isqrt() + 64);
    if mode.is_hiding() {
        private_inputs.extend(salt.packed());
    }
    private_inputs.extend(words.iter().map(|&w| Challenge::from_u64(w as u64)));
    private_inputs.extend(record_witness(Some(key))[..RECORD_WITNESSES - 1].iter().map(|&x| Challenge::from(x)));
    private_inputs.extend(split_values(p, Some(key)).into_iter().map(Challenge::from));
    let mut exts: Vec<Challenge> = Vec::with_capacity(3 * p.k);
    for (j, &(q, i)) in opened.iter().enumerate() {
        let (a, bb) = ((q as usize) / nb, (q as usize) % nb);
        let mut s1: Vec<u64> = (0..na).map(|x| u64::from(x == a)).collect();
        let s2: Vec<u64> = (0..nb).map(|x| u64::from(x == bb)).collect();
        let mut v = words[j * wps + q as usize] as u64;
        if j == 0 && tamper == QueryTamper::TwoHot && a >= 1 {
            // Σ a·s1_a = 0 + a: open the cells (0, b) and (a, b), summed.
            s1[0] = 1;
            v = (0..na).map(|x| s1[x] * words[j * wps + x * nb + bb] as u64).sum();
        }
        private_inputs.extend(s1.iter().map(|&x| Challenge::from_u64(x)));
        private_inputs.extend(s2.iter().map(|&x| Challenge::from_u64(x)));
        let e = 1u64 << i;
        let bit = (v >> i) & 1;
        answer_native &= bit;
        exts.extend([bit, v >> (i + 1), v & (e - 1)].map(Challenge::from_u64));
    }
    private_inputs.extend(exts);
    let public_inputs = vec![
        Challenge::from_basis_coefficients_slice(&commit[0..4]).unwrap(),
        Challenge::from_basis_coefficients_slice(&commit[4..8]).unwrap(),
        Challenge::from_basis_coefficients_slice(&rv).unwrap(),
        Challenge::from_u64(answer_native),
    ];
    let t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).map_err(|e| format!("set_public_inputs: {e:?}"))?;
        runner.set_private_inputs(&private_inputs).map_err(|e| format!("set_private_inputs: {e:?}"))?;
        runner.run().map_err(|e| format!("run: {e:?}"))?
    };
    let witness = t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
        range_preprocessor::<Val>(),
        expose_preprocessor::<Val>(),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .map_err(|e| format!("airs: {e:?}"))?;
    crate::experiments::table_probe::record_leaf(
        "bloom_packed_query",
        &table_packing,
        &airs_degrees,
        &non_primitive_columns,
        &primitive_columns,
    );
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(cfg);
    prover.register_recompose_table::<4>(cfg.d() != 4);
    prover.register_range_table::<4>();
    prover.register_expose_table::<4>();
    let t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).map_err(|e| format!("prove: {e:?}"))?;
    let prove = t_p.elapsed();
    let t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).map_err(|e| format!("verify: {e:?}"))?;
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness,
        prove,
        verify: t_v.elapsed(),
        trace_rows,
    });
    Ok(DecodeProof { output: RecursionOutput(proof, Rc::new(circuit_prover_data)), answer: answer_native })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{QueryStatement, check_query_statement, verify_decode_proof};
    use crate::sketch::bloom_omc::{BloomOmcParams, bloom_contains, bloom_empty, bloom_insert};
    use crate::sketch::bloom_packed::{PackedChecks, bits_to_words, commit_packed, packed_contains, packed_insert, with_checks};

    const P: BloomPackedParams = BloomPackedParams { k: 3, log_w: 7, batch: 4 };

    fn keys(n: usize, seed: u64) -> Vec<u64> {
        (0..n as u64).map(|i| (i ^ seed).wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17)).collect()
    }

    fn filled(n: usize, seed: u64) -> (Vec<u8>, Vec<u64>) {
        let ks = keys(n, seed);
        let mut w = packed_empty(&P);
        packed_insert(&mut w, &P, &ks);
        (w, ks)
    }

    /// Plain and Hiding queries answer exactly the bit-array filter's AND
    /// (members and non-members), expose `(Com(S), record(key), answer)` and
    /// verify against the VK derived from public parameters; the Plain and
    /// Hiding VKs differ and each rejects the other's proofs; the bit-array
    /// decoder's VK rejects them too.
    #[test]
    fn packed_query_answers_equal_bloom_omc_and_pin_to_derived_vk() {
        let (w, ks) = filled(12, 0x77);
        let op = BloomOmcParams { k: P.k, log_w: P.log_w, batch: 4 };
        let mut bits = bloom_empty(&op);
        bloom_insert(&mut bits, &op, &ks);
        assert_eq!(bits_to_words(&bits), w);
        let salt = SaltBb([Val::from_u64(9); 12]);
        let vk_p = bloom_packed_decode_vk(P);
        let vk_h = bloom_packed_decode_vk_commit(P, CommitMode::Hiding);
        assert_ne!(vk_p.commitment, vk_h.commitment);
        let omc_vk = crate::decode::bloom::bloom_decode_vk(op);
        let mut probes = vec![ks[0], ks[5], ks[11]];
        probes.extend(keys(6, 0xABCD));
        let (mut members, mut non) = (0, 0);
        for key in probes {
            let want = u64::from(bloom_contains(&bits, &op, key));
            assert_eq!(want, u64::from(packed_contains(&w, &P, key)));
            if want == 1 { members += 1 } else { non += 1 }
            for (mode, vk, other) in [(CommitMode::Plain, &vk_p, &vk_h), (CommitMode::Hiding, &vk_h, &vk_p)] {
                let q = prove_bloom_packed_query_commit(P, &w, key, mode, &salt);
                assert_eq!(q.answer, want, "key {key} {mode:?}");
                let commit = commit_packed_with(&P, &w, mode, &salt);
                let st = QueryStatement::with_query(commit, bloom_query_input(key), want);
                assert_eq!(verify_decode_proof(&q.output.0, vk), Ok(st), "key {key} {mode:?}");
                assert_eq!(check_query_statement(&q.output.0, &st), Ok(()));
                assert!(verify_decode_proof(&q.output.0, other).is_err(), "the other mode's VK rejects");
                assert!(verify_decode_proof(&q.output.0, &omc_vk).is_err(), "the bit-array decoder's VK rejects");
            }
        }
        assert!(members >= 3 && non >= 1, "members {members}, non-members {non}");
        assert_eq!(commit_packed_with(&P, &w, CommitMode::Plain, &salt), commit_packed(&P, &w));
    }

    /// The zero salt opens only the empty genesis filter under `Hiding`.
    #[test]
    fn hiding_query_refuses_zero_salt_on_nonempty_state() {
        let (w, ks) = filled(4, 3);
        let r = crate::sketch::forge::catch_msg(|| {
            prove_bloom_packed_query_commit(P, &w, ks[0], CommitMode::Hiding, &SaltBb::ZERO).answer
        });
        assert!(r.is_err_and(|e| e.contains("public zero salt opens only the empty genesis state")));
        let g = prove_bloom_packed_query_commit(P, &packed_empty(&P), 3, CommitMode::Hiding, &SaltBb::ZERO);
        assert_eq!(g.answer, 0);
    }

    /// Opening the neighbouring word (to flip the answer) is refused: the
    /// selector index no longer equals the routed `q`.
    #[test]
    fn shifted_word_is_rejected() {
        let (mut w, ks) = filled(8, 11);
        let key = ks[2];
        let (q0, _) = packed_positions(&P, Some(key))[0];
        let next = ((q0 + 1) % P.words_per_slice() as u64) as usize;
        w[next] = 0; // the forged opening would answer 0 (a false negative)
        let r = with_query_tamper(QueryTamper::ShiftWord, || {
            try_prove_bloom_packed_query_commit(P, &w, key, CommitMode::Plain, &SaltBb::ZERO)
        });
        let err = r.err().expect("shifted word must be rejected");
        eprintln!("packed query shifted word: {err}");
    }

    /// Positive control for the one-hot sums: with `Σ s1 = 1` removed, a
    /// two-hot selector whose index still sums to `q` opens the SUM of two
    /// cells, and the proof verifies with a wrong answer; with the sums on,
    /// the same witness is refused.
    #[test]
    fn two_hot_selector_needs_the_onehot_sum() {
        // Find a key whose slice-0 word index has a ≥ 2 so the two-hot opens
        // two distinct cells, and whose AND answer the forgery flips.
        let (na, nb) = selector_dims(&P);
        let (w, members) = filled(60, 5);
        let mut chosen = None;
        for key in members.into_iter().chain(keys(400, 0xF00D)) {
            let pos = packed_positions(&P, Some(key));
            let (q, i) = pos[0];
            let (a, bb) = ((q as usize) / nb, (q as usize) % nb);
            if a < 1 || a >= na {
                continue;
            }
            let honest = packed_contains(&w, &P, key);
            let sum: u64 = w[bb] as u64 + w[a * nb + bb] as u64;
            let forged_bit = (sum >> i) & 1 == 1;
            let rest = pos[1..].iter().enumerate().all(|(j, &(q, i))| (w[(j + 1) * P.words_per_slice() + q as usize] >> i) & 1 == 1);
            if sum < 256 && (honest != (forged_bit && rest)) {
                chosen = Some((key, honest));
                break;
            }
        }
        let (key, honest) = chosen.expect("a key the two-hot forgery flips");
        let off = PackedChecks { onehot_sum: false, ..PackedChecks::ALL };
        let forged = with_checks(off, || {
            with_query_tamper(QueryTamper::TwoHot, || {
                try_prove_bloom_packed_query_commit(P, &w, key, CommitMode::Plain, &SaltBb::ZERO)
            })
        })
        .expect("control: the two-hot forgery verifies without the one-hot sums");
        assert_ne!(forged.answer, u64::from(honest), "control: the forged answer is wrong");
        let on = with_query_tamper(QueryTamper::TwoHot, || {
            try_prove_bloom_packed_query_commit(P, &w, key, CommitMode::Plain, &SaltBb::ZERO)
        });
        assert!(on.is_err(), "the one-hot sums reject the two-hot selector");
    }
}
