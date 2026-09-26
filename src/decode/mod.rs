//! plonky3 (STARK) **decode / query circuits** — prove `answer =
//! release(decode(committed state))`, the STARK-backend counterpart of the
//! plonky2 `decode` family (EVAL_SPEC E3).
//!
//! Unlike the update leaves (which prove a *transition* `Com(S_{t-1}) →
//! Com(S_t)`), a decode circuit proves a **query answer against one committed
//! state**: it re-hashes the whole state in-circuit (binding it to the
//! published `Com(S)`), then proves the family's query relation over the
//! witnessed cells. Cost is therefore `Θ(s)` in the state size `s` (the
//! whole-state re-hash) plus the small per-query relation — exactly the E3
//! dependence on `s`, not on stream length.
//!
//! Decode proofs are **self-contained** (not chained): each prover self-verifies
//! (`verify_all_tables`) internally and returns a [`DecodeProof`] wrapping the
//! batch-STARK output plus the released answer. The per-phase timing split is
//! recorded via [`crate::recursion::recursive::timing`] (read it right after the
//! prove, as the E1/E3 runners do).
//!
//! Families: [`countmin`] (point-frequency = min of `d` cells). SS/HLL/GK decode
//! mirror the same harness over their respective relations.

pub mod bloom;
pub mod countmin;
pub mod gk_bandmerge;
pub mod greenwald_khanna;
pub mod hyperloglog;
pub mod spacesaving;

use std::rc::Rc;

use p3_batch_stark::ProverData;
use p3_circuit::ops::Poseidon2Config;
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4, poseidon2_preprocessor,
        range_air_builders, range_preprocessor, recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::make_leaf_config;
use crate::recursion::recursive::expose_forest::vk_pin_values;
use crate::recursion::recursive::root_vk::{RootVk, bound_proof_shape};

/// A deterministic, in-circuit **release policy** applied to the raw decoded
/// answer (the verifiable counterpart of an output-privacy layer). Matches the
/// plonky2 `decode::ReleasePolicy` semantics exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleasePolicy {
    /// Release the raw answer.
    Identity,
    /// Suppress below `θ`: release `answer` if `answer >= θ`, else `0`.
    Threshold(u64),
}

impl ReleasePolicy {
    pub fn name(&self) -> &'static str {
        match self {
            ReleasePolicy::Identity => "identity",
            ReleasePolicy::Threshold(_) => "threshold",
        }
    }
    /// Native application (matches the in-circuit logic bit-for-bit).
    pub fn apply(&self, raw: u64) -> u64 {
        match self {
            ReleasePolicy::Identity => raw,
            ReleasePolicy::Threshold(t) => {
                if raw >= *t {
                    raw
                } else {
                    0
                }
            }
        }
    }
}

/// A self-contained plonky3 decode proof: the batch-STARK output and the
/// released answer it certifies (a public input). The prover self-verifies, so
/// `output` is already a checked proof.
pub struct DecodeProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub answer: u64,
}

impl DecodeProof {
    /// Serialized proof size in bytes (postcard, matching the E1/E3 size metric).
    pub fn proof_size(&self) -> usize {
        postcard::to_allocvec(&self.output.0).map(|v| v.len()).unwrap_or(0)
    }
}

// ─── Query statement (Property 3) ────────────────────────────────────────────

/// Base values of the `(Com(S), query, answer)` statement a decode proof
/// exposes on BabyBear (D = 4): `Com(S)` (8), the query Challenge (4) and the
/// answer Challenge (4). The Count-Min, SpaceSaving and both GK decoders use
/// it; HyperLogLog (no query) exposes `(Com(S), answer)` (12) and Bloom its
/// own 16-value `(Com(S), record, answer)`.
pub const QUERY_STATEMENT_LEN: usize = 16;

/// The `(Com(S), query, answer)` statement a decode proof exposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryStatement {
    pub commit: [Val; 8],
    /// The query as a Challenge's 4 base coordinates: `(q, 0, 0, 0)` for a
    /// scalar query ([`Self::new`]); the Count-Min decoder's key encoding
    /// under `Binding::Semantic`/`Bound` is the exact 16-bit limbs
    /// `(k0, k1, k2, k3)` ([`Self::with_query`] with
    /// [`crate::sketch::countmin_final::key_hash_input`]).
    pub query: [Val; 4],
    /// The released answer as a Challenge's 4 base coordinates.
    pub answer: [Val; 4],
}

impl QueryStatement {
    /// The statement an honest proof of `answer` to scalar query `query`
    /// against `commit` exposes.
    pub fn new(commit: [Val; 8], query: u64, answer: u64) -> Self {
        use p3_field::PrimeCharacteristicRing;
        let z = Val::ZERO;
        Self {
            commit,
            query: [Val::from_u64(query), z, z, z],
            answer: [Val::from_u64(answer), z, z, z],
        }
    }

    /// The statement with an explicit query encoding (e.g. a Count-Min key's
    /// exact limbs) and a scalar answer.
    pub fn with_query(commit: [Val; 8], query: [Val; 4], answer: u64) -> Self {
        use p3_field::PrimeCharacteristicRing;
        let z = Val::ZERO;
        Self { commit, query, answer: [Val::from_u64(answer), z, z, z] }
    }
}

/// Read the exposed `(Com(S), query, answer)` from a decode proof, or `None`
/// when the proof exposes no such statement (a `Binding::Legacy` decoder).
/// A verifier that has checked the proof (`verify_all_tables`) compares this
/// against the commitment it trusts, the query it asked and the answer it was
/// given: the Expose table binds these values to the circuit's wires, so a
/// proof whose exposed values were altered fails verification.
pub fn read_exposed_statement(proof: &BatchStarkProof<ConfigWithFriParams>) -> Option<QueryStatement> {
    let pv = proof
        .non_primitives
        .iter()
        .map(|e| &e.public_values)
        .find(|v| v.len() == QUERY_STATEMENT_LEN)?;
    Some(QueryStatement {
        commit: std::array::from_fn(|i| pv[i]),
        query: std::array::from_fn(|i| pv[8 + i]),
        answer: std::array::from_fn(|i| pv[12 + i]),
    })
}

/// Verifier-side check of a decode proof's query statement: the proof must
/// expose `(Com(S), query, answer)` and it must equal `want`. The STARK itself
/// is checked separately (`verify_all_tables`); together they certify that
/// `want.answer` is the released answer to `want.query` over the state
/// committed by `want.commit`. A proof that exposes no statement (a
/// `Binding::Legacy` decoder) is rejected: its answer is not verifiable.
pub fn check_query_statement(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    want: &QueryStatement,
) -> Result<(), String> {
    let got = read_exposed_statement(proof)
        .ok_or("decode proof exposes no (commit, query, answer) statement")?;
    if got.commit != want.commit {
        return Err("exposed Com(S) differs from the queried commitment".into());
    }
    if got.query != want.query {
        return Err(format!("exposed query {:?} differs from {:?}", got.query, want.query));
    }
    if got.answer != want.answer {
        return Err(format!("exposed answer {:?} differs from {:?}", got.answer, want.answer));
    }
    Ok(())
}

/// A trusted decode-circuit verification key: the preprocessed commitment (in
/// `vk_pin_values` order) and the proof metadata — the same pin the
/// composition root uses ([`RootVk`]).
pub type DecodeVk = RootVk<Challenge>;

/// The verifier of the standard decode table set (Poseidon2 D = 4, Recompose,
/// Range, Expose), configured independently of any proof.
fn decode_verifier() -> BatchStarkProver<ConfigWithFriParams> {
    const LOG_FINAL_POLY_LEN: usize = 6;
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut v = BatchStarkProver::new(make_leaf_config()).with_table_packing(table_packing);
    v.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    v.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    v.register_range_table::<4>();
    v.register_expose_table::<4>();
    v
}

/// **Pinned verifier of a decode proof** (SpaceSaving and GK decoders; the
/// query-side counterpart of the composition root's pinned verifier). A plain
/// `verify_all_tables` takes the verification key from the proof itself, so
/// on its own it accepts a proof of ANY circuit — including one that merely
/// exposes a chosen `(Com(S), q, answer)` without computing anything. This
/// verifier (1) pins the proof's metadata and preprocessed commitment to the
/// trusted `vk` (derived from public parameters: `ss_decode_vk`,
/// `gk2_decode_vk`, `gk_decode_vk`), (2) verifies the STARK with a verifier
/// configured from the fixed decode table set, and (3) returns the exposed
/// statement, which the caller compares with the commitment it trusts and the
/// query it asked ([`check_query_statement`]) and reads the answer from.
pub fn verify_decode_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    vk: &DecodeVk,
) -> Result<QueryStatement, String> {
    if let Some(shape) = &vk.shape {
        if &bound_proof_shape(proof) != shape {
            return Err("decode proof metadata differs from the trusted decoder VK".into());
        }
    }
    if vk_pin_values(proof) != vk.commitment {
        return Err("decode proof VK differs from the trusted decoder VK (a different circuit)".into());
    }
    decode_verifier()
        .verify_all_tables(proof)
        .map_err(|e| format!("decode proof STARK rejected: {e:?}"))?;
    read_exposed_statement(proof).ok_or_else(|| "decode proof exposes no statement".into())
}

/// Deep copy of a proof (postcard round trip; `BatchStarkProof` is not
/// `Clone`), for tamper tests.
#[cfg(test)]
pub(crate) fn clone_proof(
    p: &BatchStarkProof<ConfigWithFriParams>,
) -> BatchStarkProof<ConfigWithFriParams> {
    postcard::from_bytes(&postcard::to_allocvec(p).expect("serialize proof")).expect("deserialize proof")
}

/// Shared tamper test of a decoder's exposed query statement (the
/// SpaceSaving and GK decoders run it):
///
/// (a) verifier level: the honest proof verifies and exposes `want`;
///     altering its exposed answer or query fails `verify_all_tables` (the
///     Expose table binds the values to the circuit's wires);
/// (b) prover level (transplant): the answer wire (tag `answer_tag`) set to a
///     wrong value in every table fails proving/verification. The positive
///     control writes the HONEST answer through the same plumbing and must
///     verify, so a broken forger cannot make the rejections vacuous;
/// (c) statement level: [`check_query_statement`] accepts `want` and rejects
///     a different answer or query. The pre-fix `legacy` circuit's proof
///     verifies but exposes nothing, so no claimed answer can be checked
///     against it (any answer rides on a verifying proof).
#[cfg(test)]
pub(crate) fn assert_tampered_answer_rejected(
    dc: &StdDecodeCircuit,
    legacy: &StdDecodeCircuit,
    answer_tag: &str,
    want: QueryStatement,
) {
    use crate::sketch::forge;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    let verifies = |c: &StdDecodeCircuit, p: &BatchStarkProof<ConfigWithFriParams>| {
        forge::catch(|| c.prover.verify_all_tables(p).is_ok()).unwrap_or(false)
    };
    let label = answer_tag;
    // (a)
    let honest = dc.prove_traces(&dc.run(label)).expect("honest proof verifies");
    assert!(verifies(dc, &honest));
    assert_eq!(read_exposed_statement(&honest), Some(want), "exposes the queried statement");
    // Positive control of the tamper plumbing: an untouched copy verifies.
    assert!(verifies(dc, &clone_proof(&honest)), "control: the copied proof verifies");
    for (slot, what) in [(12usize, "answer"), (8, "query"), (0, "Com(S)")] {
        let mut forged = clone_proof(&honest);
        let e = forged
            .non_primitives
            .iter_mut()
            .find(|e| e.public_values.len() == QUERY_STATEMENT_LEN)
            .expect("exposed statement");
        e.public_values[slot] += Val::ONE;
        assert!(!verifies(dc, &forged), "a tampered exposed {what} must fail verification");
    }
    // (b)
    let answer = want.answer[0].as_canonical_u64();
    let transplant = |v: u64| -> bool {
        let mut traces = dc.run(label);
        let aw = traces.tag_to_witness[answer_tag];
        forge::set_wid::<Val, Challenge>(&mut traces, aw, Challenge::from_u64(v));
        forge::accepted(|| dc.prove_traces(&traces).map(|_| ()))
    };
    assert!(transplant(answer), "positive control: the honest answer through the forger verifies");
    for bad in [answer + 1, answer ^ 0x55, 999_999] {
        assert!(!transplant(bad), "a transplanted answer {bad} (honest {answer}) must be rejected");
    }
    // (c)
    assert_eq!(check_query_statement(&honest, &want), Ok(()));
    let mut lie = want;
    lie.answer[0] += Val::ONE;
    assert!(check_query_statement(&honest, &lie).is_err(), "a different answer is rejected");
    let mut other_q = want;
    other_q.query[0] += Val::ONE;
    assert!(check_query_statement(&honest, &other_q).is_err(), "a different query is rejected");
    let lp = legacy.prove_traces(&legacy.run(label)).expect("Legacy proof verifies");
    assert!(verifies(legacy, &lp), "pre-fix: the Legacy proof verifies…");
    assert_eq!(read_exposed_statement(&lp), None, "…but exposes no statement");
    assert!(check_query_statement(&lp, &want).is_err(), "…so no answer can be checked against it");
}

/// Shared test of [`verify_decode_proof`] for one decoder: `vk` (derived
/// from public parameters) accepts every honest `(circuit, statement)` in
/// `honest` and returns exactly its statement; it rejects the `legacy`
/// proof; and it rejects a proof of a DIFFERENT circuit that merely exposes a
/// lying statement — which the self-pinned `verify_all_tables` and the
/// statement check alone both ACCEPT (the gap the pin closes).
#[cfg(test)]
pub(crate) fn assert_pinned_decode_verifier(
    vk: &DecodeVk,
    honest: &[(&StdDecodeCircuit, QueryStatement)],
    legacy: &StdDecodeCircuit,
) {
    use crate::sketch::forge;
    use p3_circuit::CircuitBuilder;
    use p3_circuit::ops::{
        generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
        generate_recompose_trace,
    };
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    for (dc, want) in honest {
        let proof = dc.prove_traces(&dc.run("pinned")).expect("honest proof");
        assert_eq!(verify_decode_proof(&proof, vk), Ok(*want), "honest proof verifies under the pin");
    }
    let lp = legacy.prove_traces(&legacy.run("pinned")).expect("legacy proof");
    assert!(verify_decode_proof(&lp, vk).is_err(), "the Legacy (unexposed) circuit is not the pinned one");

    // A "decoder" that computes nothing: it exposes chosen public inputs.
    let (target, _) = honest[0];
    let want = honest[0].1;
    let mut lie = want;
    lie.answer[0] += Val::from_u64(1000);
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<p3_poseidon2_circuit_air::BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, p3_poseidon2_circuit_air::BabyBearD4Width16>,
        p3_baby_bear::default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    b.enable_expose(generate_expose_trace::<Val, Challenge>);
    let pis: Vec<p3_circuit::ExprId> = (0..4).map(|_| b.alloc_public_input("pi")).collect();
    b.add_expose(&pis).expect("expose");
    let _ = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &pis[2..3], true).expect("hash");
    let _ = b.add_range_bits::<Val>(pis[3], 24).expect("range");
    let circuit = b.build().expect("fake decoder");
    let ch = |v: &[Val]| Challenge::from_basis_coefficients_slice(v).expect("4 coeffs");
    let fake = StdDecodeCircuit::new(
        circuit,
        vec![ch(&lie.commit[..4]), ch(&lie.commit[4..]), ch(&lie.query), ch(&lie.answer)],
        vec![],
        0,
        true,
        "fake decoder",
    );
    let fp = fake.prove_traces(&fake.run("fake decoder")).expect("the fake circuit proves");
    let self_pinned = forge::catch(|| fake.prover.verify_all_tables(&fp).is_ok()).unwrap_or(false)
        && forge::catch(|| target.prover.verify_all_tables(&fp).is_ok()).unwrap_or(false);
    assert!(self_pinned, "self-pinned verify_all_tables accepts the fake circuit's proof…");
    assert_eq!(check_query_statement(&fp, &lie), Ok(()), "…and its lying statement");
    let err = verify_decode_proof(&fp, vk).expect_err("the pinned verifier must reject it");
    assert!(err.contains("trusted decoder VK"), "{err}");
}

impl DecodeProof {
    /// The exposed `(Com(S), query, answer)`, if the decoder exposes one.
    pub fn statement(&self) -> Option<QueryStatement> {
        read_exposed_statement(&self.output.0)
    }
}

/// A built decode circuit over the standard BabyBear decode table set
/// (Poseidon2 D = 4, Recompose, Range, and Expose when the circuit exposes a
/// statement), with its witness and registered prover. Shared by the
/// SpaceSaving and GK decoders.
pub(crate) struct StdDecodeCircuit {
    pub(crate) circuit: p3_circuit::Circuit<Challenge>,
    pub(crate) public_inputs: Vec<Challenge>,
    pub(crate) private_inputs: Vec<Challenge>,
    pub(crate) answer: u64,
    pub(crate) prover: BatchStarkProver<ConfigWithFriParams>,
    pub(crate) circuit_prover_data: CircuitProverData<ConfigWithFriParams>,
    pub(crate) trace_rows: u64,
}

impl StdDecodeCircuit {
    /// Prover data for `circuit`. With `expose = false` this is exactly the
    /// pre-Expose setup of these decoders (the Expose preprocessor, AIR and
    /// table are appended last), so a `Legacy` decoder keeps its VK.
    pub(crate) fn new(
        circuit: p3_circuit::Circuit<Challenge>,
        public_inputs: Vec<Challenge>,
        private_inputs: Vec<Challenge>,
        answer: u64,
        expose: bool,
        label: &str,
    ) -> Self {
        const LOG_FINAL_POLY_LEN: usize = 6;
        let config = make_leaf_config();
        let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        let mut preprocessors = vec![
            poseidon2_preprocessor::<Val>(),
            recompose_preprocessor::<Val>(false),
            range_preprocessor::<Val>(),
        ];
        let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
        air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
        air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
        if expose {
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
            .unwrap_or_else(|e| panic!("get_airs_and_degrees_with_prep ({label}): {e:?}"));
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let circuit_prover_data =
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
        let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
        prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
        prover.register_range_table::<4>();
        if expose {
            prover.register_expose_table::<4>();
        }
        Self {
            circuit,
            public_inputs,
            private_inputs,
            answer,
            prover,
            circuit_prover_data,
            trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
        }
    }

    /// Run the honest witness generator.
    pub(crate) fn run(&self, label: &str) -> p3_circuit::tables::Traces<Challenge> {
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&self.public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&self.private_inputs).expect("set_private_inputs");
        runner.run().unwrap_or_else(|e| panic!("run {label} circuit: {e:?}"))
    }

    /// Prove and self-verify (possibly forged) traces.
    pub(crate) fn prove_traces(
        &self,
        traces: &p3_circuit::tables::Traces<Challenge>,
    ) -> Result<BatchStarkProof<ConfigWithFriParams>, String> {
        let proof = self
            .prover
            .prove_all_tables(traces, &self.circuit_prover_data)
            .map_err(|e| format!("prove: {e:?}"))?;
        self.prover.verify_all_tables(&proof).map_err(|e| format!("verify: {e:?}"))?;
        Ok(proof)
    }

    /// The trusted verification key of this decode circuit: its preprocessed
    /// commitment and proof metadata, read off a proof of its own (honest)
    /// witness. Both are functions of the circuit alone — the decoders build
    /// it from the public parameters and the binding; state, query and answer
    /// are witnesses or public inputs — so a verifier derives the VK from
    /// public parameters with any valid state (the `*_decode_vk` functions use
    /// the empty one) and pins every proof to it ([`verify_decode_proof`]).
    pub(crate) fn derive_vk(&self, label: &str) -> DecodeVk {
        let proof = self
            .prove_traces(&self.run(label))
            .unwrap_or_else(|e| panic!("derive {label} VK: {e}"));
        DecodeVk { commitment: vk_pin_values(&proof), shape: Some(bound_proof_shape(&proof)) }
    }

    /// Run, prove and self-verify, recording the witness/prove/verify split
    /// via [`crate::recursion::recursive::timing`].
    pub(crate) fn prove(self, label: &str) -> DecodeProof {
        let t_w = std::time::Instant::now();
        let traces = self.run(label);
        let witness = t_w.elapsed();
        let t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .unwrap_or_else(|e| panic!("prove {label}: {e:?}"));
        let prove = t_p.elapsed();
        let t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .unwrap_or_else(|e| panic!("self-verify {label}: {e:?}"));
        crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
            witness,
            prove,
            verify: t_v.elapsed(),
            trace_rows: self.trace_rows,
        });
        DecodeProof {
            output: RecursionOutput(proof, Rc::new(self.circuit_prover_data)),
            answer: self.answer,
        }
    }
}
