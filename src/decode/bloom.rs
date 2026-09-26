//! Bloom-filter **membership query** circuit (plonky3/STARK), the query side
//! of [`crate::sketch::bloom_omc`].
//!
//! Proves `answer = AND_j S[j·W + pos_j(key)]` against a committed partitioned
//! Bloom filter `S` (`M = k·W` bit cells, `Com(S) = commit_bloom(S)` — the same
//! digest the update leaf surfaces as its final commitment, so a query chains
//! onto a leaf's output).
//!
//! Stages:
//! 1. Every cell is boolean (pins it to the base field); the cells are packed
//!    4-per-Challenge through the ALU and hashed with the bound sponge →
//!    `Com(S)` (the `Θ(M)` re-hash).
//! 2. The key is routed exactly as the update leaf routes an active record
//!    ([`record_route_gadget`] with `act = 1`): four range-checked 16-bit limbs,
//!    one bound Poseidon2 digest, canonical `(pos, hi)` splits.
//! 3. Per slice a one-hot selector `s_{j,i}` (boolean, `Σ_i s = 1`,
//!    `Σ_i i·s = pos_j`) opens `o_j = Σ_i s_{j,i}·S[j·W + i]` (`Θ(M)` total, the
//!    [`super::countmin`] selector pattern).
//! 4. `answer = ∏_j o_j`.
//!
//! The verifier-visible statement is the Expose op `(Com(S), record(key),
//! answer)`: `record(key) = [k0, k1, k2, k3 + 2^16]` is injective in the key,
//! so the verifier checks it equals [`record_vals`]`(Some(key))`.
//!
//! Soundness caveat: as for the update leaf, this is conditional on the pinned
//! fork binding constant values (see the "constants are not bound" section of
//! [`crate::sketch::bloom_omc`]); the one-hot index constants `i` and the
//! `assert`-targets are constants.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4,
        poseidon2_preprocessor, range_air_builders, range_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::decode::DecodeProof;
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::make_leaf_config;
use crate::sketch::bloom_omc::{
    BloomOmcParams, Consts, bloom_positions, commit_bloom, hash_slice_bound, pack_cells,
    record_route_gadget, record_vals, split_witness_count, split_witness_values,
};

const LOG_FINAL_POLY_LEN: usize = 6;
/// Base values surfaced by the Expose op: `Com(S)` (8), record (4), answer (4).
pub const QUERY_EXPOSED_LEN: usize = 16;

thread_local! {
    /// Test-only: move slice 0's one-hot selector to the next position (and
    /// open that cell), i.e. try to answer from a cell the key does not map to.
    static TAMPER_SHIFT_SELECTOR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Read `(Com(S), record, answer)` from a query proof's Expose table.
pub fn read_exposed_query(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> ([Val; 8], [Val; 4], Val) {
    let pv = proof
        .non_primitives
        .iter()
        .map(|e| &e.public_values)
        .find(|v| v.len() == QUERY_EXPOSED_LEN)
        .expect("bloom query proof must expose (commit, record, answer)");
    (
        std::array::from_fn(|i| pv[i]),
        std::array::from_fn(|i| pv[8 + i]),
        pv[12],
    )
}

/// Prove `answer = contains(S, key)` against `Com(S)`. `params.batch` is
/// ignored (only the shape `k`, `log_w` matters).
pub fn prove_bloom_query(params: BloomOmcParams, bits: &[u8], key: u64) -> DecodeProof {
    try_prove_bloom_query(params, bits, key).unwrap_or_else(|e| panic!("bloom query rejected: {e}"))
}

/// [`prove_bloom_query`] reporting the rejecting stage instead of panicking.
pub fn try_prove_bloom_query(
    params: BloomOmcParams,
    bits: &[u8],
    key: u64,
) -> Result<DecodeProof, String> {
    params.validate();
    let BloomOmcParams { k, log_w, .. } = params;
    let w = params.w();
    let m = params.m_cells();
    assert_eq!(bits.len(), m, "state must have M = k·W bits");
    assert!(bits.iter().all(|&x| x <= 1));

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

    let commit_pis: [ExprId; 2] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let rec_pi = b.alloc_public_input("record");
    let answer_pi = b.alloc_public_input("answer");
    b.add_expose(&[commit_pis[0], commit_pis[1], rec_pi, answer_pi])
        .expect("expose query");

    let c = Consts::new(&mut b, k, log_w);
    let idx_consts: Vec<ExprId> = (0..w)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "i"))
        .collect();

    let cells: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("cell")).collect();
    let limbs: [ExprId; 4] = std::array::from_fn(|_| b.alloc_private_input("key_limb"));
    let split: Vec<ExprId> = (0..split_witness_count(k))
        .map(|_| b.alloc_private_input("split"))
        .collect();
    let sel: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("sel")).collect();

    // Stage 1: bits → Com(S).
    for &cell in &cells {
        b.assert_bool(cell);
    }
    let packed = pack_cells(&mut b, &cells);
    let dig = hash_slice_bound(&mut b, &cfg, &packed, c.zero);
    for i in 0..2 {
        b.connect(dig[i], commit_pis[i]);
    }

    // Stage 2: route the key as an active record.
    let (rec, pos_of) = record_route_gadget(&mut b, &cfg, &c, k, log_w, limbs, c.one, &split, true);
    b.connect(rec, rec_pi);

    // Stage 3: one-hot open per slice; Stage 4: AND.
    let mut answer = c.one;
    for (j, &pos) in pos_of.iter().enumerate() {
        let s = &sel[j * w..(j + 1) * w];
        for &sv in s {
            b.assert_bool(sv);
        }
        let mut sum = s[0];
        let mut idx = b.mul(s[0], idx_consts[0]);
        let mut open = b.mul(s[0], cells[j * w]);
        for i in 1..w {
            sum = b.add(sum, s[i]);
            idx = b.mul_add(s[i], idx_consts[i], idx);
            open = b.mul_add(s[i], cells[j * w + i], open);
        }
        b.connect(sum, c.one);
        b.connect(idx, pos);
        answer = b.mul(answer, open);
    }
    b.connect(answer, answer_pi);

    let circuit = b.build().map_err(|e| format!("build: {e:?}"))?;

    // ─── Native witness ──────────────────────────────────────────────────
    let positions = bloom_positions(k, log_w, key);
    let tamper = TAMPER_SHIFT_SELECTOR.with(|t| t.get());
    let mut opened: Vec<usize> = positions.clone();
    if tamper {
        opened[0] = (opened[0] + 1) % w;
    }
    let answer_native: u64 = opened
        .iter()
        .enumerate()
        .all(|(j, &p)| bits[j * w + p] == 1)
        .into();
    let commit = commit_bloom(bits);
    let rv = record_vals(Some(key));

    let public_inputs: Vec<Challenge> = vec![
        Challenge::from_basis_coefficients_slice(&commit[0..4]).unwrap(),
        Challenge::from_basis_coefficients_slice(&commit[4..8]).unwrap(),
        Challenge::from_basis_coefficients_slice(&rv).unwrap(),
        Challenge::from_u64(answer_native),
    ];

    let mut private_inputs: Vec<Challenge> = Vec::with_capacity(2 * m + 40);
    private_inputs.extend(bits.iter().map(|&x| Challenge::from_u8(x)));
    for i in 0..4 {
        private_inputs.push(Challenge::from_u64((key >> (16 * i)) & 0xFFFF));
    }
    private_inputs.extend(
        split_witness_values(k, log_w, Some(key))
            .into_iter()
            .map(Challenge::from),
    );
    for &p in &opened {
        private_inputs.extend((0..w).map(|i| Challenge::from_bool(i == p)));
    }

    let t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .map_err(|e| format!("set_public_inputs: {e:?}"))?;
        runner
            .set_private_inputs(&private_inputs)
            .map_err(|e| format!("set_private_inputs: {e:?}"))?;
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
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(cfg);
    prover.register_recompose_table::<4>(cfg.d() != 4);
    prover.register_range_table::<4>();
    prover.register_expose_table::<4>();

    let t_p = std::time::Instant::now();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .map_err(|e| format!("prove: {e:?}"))?;
    let prove = t_p.elapsed();
    let t_v = std::time::Instant::now();
    prover
        .verify_all_tables(&proof)
        .map_err(|e| format!("verify: {e:?}"))?;
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness,
        prove,
        verify: t_v.elapsed(),
        trace_rows,
    });

    Ok(DecodeProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        answer: answer_native,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::bloom_omc::{bloom_contains, bloom_empty, bloom_insert, prove_bloom_omc};

    const P: BloomOmcParams = BloomOmcParams {
        k: 3,
        log_w: 7,
        batch: 8,
    };

    fn keys(n: usize, seed: u64) -> Vec<u64> {
        (0..n as u64)
            .map(|i| {
                (i ^ seed)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .rotate_left(17)
            })
            .collect()
    }

    /// Update leaf → query: the query binds the SAME commitment the leaf
    /// exposes as its final state; members answer 1, and every answer
    /// (members and probes) equals the native AND.
    #[test]
    fn bloom_query_chains_onto_update_leaf() {
        let ks = keys(8, 11);
        let leaf = prove_bloom_omc(P, &bloom_empty(&P), &ks);
        let (_, leaf_final, _) = crate::sketch::bloom_omc::read_exposed_commitments(&leaf.output.0);
        let bits = leaf.final_bits.clone();
        let mut native = bloom_empty(&P);
        bloom_insert(&mut native, &P, &ks);
        assert_eq!(bits, native);
        let mut probes = vec![ks[0], ks[5]];
        probes.extend(keys(4, 999));
        for key in probes {
            let q = prove_bloom_query(P, &bits, key);
            let (commit, rec, ans) = read_exposed_query(&q.output.0);
            assert_eq!(
                commit, leaf_final,
                "query binds the leaf's final commitment"
            );
            assert_eq!(rec, record_vals(Some(key)), "exposed record is the key's");
            assert_eq!(q.answer, u64::from(bloom_contains(&bits, &P, key)));
            assert_eq!(ans, Val::from_u64(q.answer));
            if ks.contains(&key) {
                assert_eq!(q.answer, 1, "no false negatives");
            }
        }
    }

    /// Opening a cell the key does not map to (to flip the answer) violates
    /// `Σ i·s = pos` and is rejected.
    #[test]
    fn bloom_query_wrong_selector_rejected() {
        let ks = keys(8, 11);
        let mut bits = bloom_empty(&P);
        bloom_insert(&mut bits, &P, &ks);
        let key = ks[2];
        let pos0 = bloom_positions(P.k, P.log_w, key)[0];
        // Make the shifted cell 0 so the forged answer would be 0 (a false negative).
        let shifted = (pos0 + 1) % P.w();
        bits[shifted] = 0;
        assert!(bloom_contains(&bits, &P, key) || pos0 == shifted);
        TAMPER_SHIFT_SELECTOR.with(|t| t.set(true));
        let res = try_prove_bloom_query(P, &bits, key);
        TAMPER_SHIFT_SELECTOR.with(|t| t.set(false));
        let err = res.err().expect("shifted selector must be rejected");
        eprintln!("bloom query shifted selector: rejected at {err}");
        assert!(err.starts_with("run:"));
    }

    /// `cargo test --release bloom_query_measure -- --ignored --nocapture`
    /// (k = 7, W = 2^14).
    #[test]
    #[ignore = "measurement: M = 7·2^14 cells"]
    fn bloom_query_measure() {
        let p = BloomOmcParams {
            k: 7,
            log_w: 14,
            batch: 1,
        };
        let mut bits = bloom_empty(&p);
        let ks = keys(12_000, 5);
        bloom_insert(&mut bits, &p, &ks);
        let t = std::time::Instant::now();
        let q = prove_bloom_query(p, &bits, ks[17]);
        let total = t.elapsed();
        let tm = crate::recursion::recursive::timing::take();
        assert_eq!(q.answer, 1);
        eprintln!(
            "BLOOM_QUERY k=7 log_w=14 M={} trace_rows={} witness_ms={:.0} prove_ms={:.0} verify_ms={:.0} total_ms={:.0} proof_bytes={}",
            p.m_cells(),
            tm.trace_rows,
            tm.witness.as_secs_f64() * 1e3,
            tm.prove.as_secs_f64() * 1e3,
            tm.verify.as_secs_f64() * 1e3,
            total.as_secs_f64() * 1e3,
            q.proof_size()
        );
    }
}
