//! Zero-knowledge LogUp sums (`src/config.rs`, "LogUp sums: masked per global
//! interaction").
//!
//! A batch proof reveals one LogUp cumulative sum per global interaction
//! (`BatchProof::global_lookup_data`). Unmasked, each is a deterministic
//! function of the witness and of the lookup challenges, and anyone can
//! replay the transcript up to those challenges from public data (instance
//! bindings, main commitment, public values, preprocessed commitment). A
//! verifier who guesses the witness can then recompute a sum and compare it
//! with the revealed one. The `zk` build masks every revealed sum with a
//! fresh extension-field mask, zero-sum per bus, committed before the
//! challenges.
//!
//! The leaf is a real Count-Min `omc` leaf (d = 4, w = 8, batch 4) under
//! [`Expose::None`], [`Binding::Semantic`] and plain commitments: it exposes no
//! statement, so its public-input table (`Com(S_{t-1})`, `Com(S_t)`,
//! `Com(B_t)`) is witness, and those commitments depend on the batch.
//!
//! - `revealed_sums_are_fresh_per_proof_and_zero_sum_per_bus`: two proofs of
//!   the same leaf and witness.
//! - `guess_and_check_replay_of_revealed_sums`: one batch key is the secret,
//!   4096 candidate keys are tried against the public-input table's revealed
//!   sum, and the constant table's sum (a function of public data only) is
//!   recomputed as a check that the replay itself is exact.
//!
//! Under `zk` (the default) both tests assert the masked behavior. Under
//! `--no-default-features` the same code runs as the unmasked control: the
//! sums repeat across proofs, the constant table's sum is recomputed
//! exactly, and the replay finds exactly the true key.
//!
//! The `zk` negative result ("no candidate matches") is only meaningful if
//! the replay reproduces the `zk` transcript exactly (instance bindings with
//! the doubled hiding domain, hiding-PCS commitments, mask-widened main
//! traces); a replay that drifted after a transcript change would also find
//! nothing. The `--no-default-features` control cannot show that, since it
//! replays a different (non-hiding) transcript. The third test does, in the
//! `zk` build itself: `zero_masks_make_the_zk_replay_exact` proves the same
//! leaf under `zk` with every mask replaced by zero through the forks'
//! test-only mask hook and requires the replay to reproduce the constant
//! table's sum and to single out the secret key. It needs the hook, so it
//! runs only with
//!
//! ```text
//! cargo test --release --features test-hooks,p3-circuit-prover/test-hooks --test zk_logup_blinding
//! ```
//!
//! (an out-of-tree check that zeroed every mask inside the core fork made
//! both `zk` assertions above fail, as expected).

use std::collections::BTreeMap;

use p3_air::BaseAir;
use p3_batch_stark::BatchTranscript;
use p3_circuit::WitnessId;
use p3_circuit::ops::PrimitiveOpType;
use p3_circuit::tables::PublicTrace;
use p3_circuit_prover::air::{ConstAir, PublicAir};
use p3_circuit_prover::{BatchStarkProof, CircuitProverData};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::logup::LogUpGadget;
use p3_lookup::{LookupData, LookupProtocol};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use zksketch::commitment::countmin::{CountMinCommit, commit_countmin};
use zksketch::config::{Challenge, Challenger, Pcs, Val, make_perm};
use zksketch::recursion::recursive::config::ConfigWithFriParams;
use zksketch::recursion::recursive::countmin_leaf::pack_commit_to_challenge;
use zksketch::recursion::recursive::statement::Expose;
use zksketch::sketch::bind::Binding;
use zksketch::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::countmin_omc::{
    CmOmcParams, CountMinOmcProof, build_countmin_omc_leaf_expose, countmin_omc_advance_with,
    countmin_omc_batch_commit_with,
};

type Sc = ConfigWithFriParams;

/// Extension degree of the challenge field.
const D: usize = 4;
/// Instance order of a circuit-prover batch proof: Const, Public, ALU, then
/// the non-primitive tables (`BatchStarkProver::reconstruct_context`).
const CONST_INSTANCE: usize = 0;
const PUBLIC_INSTANCE: usize = 1;

const ZK: bool = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::ZK;
const PARAMS: CmOmcParams = CmOmcParams { d: 4, w: 8, batch: 4 };
const BINDING: Binding = Binding::Semantic;
/// The secret key and the candidate range the verifier enumerates.
const SECRET_KEY: u64 = 2741;
const CANDIDATES: u64 = 1 << 12;

fn prior() -> CountMinState {
    let mut s = CountMinState {
        counters: vec![vec![0; PARAMS.w]; PARAMS.d],
        params: CountMinParams { d: PARAMS.d, w: PARAMS.w },
    };
    countmin_omc_advance_with(
        &mut s,
        &[CountMinUpdate { key: 11, value: 3 }, CountMinUpdate { key: 900_001, value: 1 }],
        BINDING,
    );
    s
}

/// The batch with `key` in the secret slot; the other updates are known.
fn batch(key: u64) -> Vec<CountMinUpdate> {
    vec![
        CountMinUpdate { key: 5, value: 2 },
        CountMinUpdate { key, value: 7 },
        CountMinUpdate { key: 77, value: 1 },
        CountMinUpdate { key: 5, value: 4 },
    ]
}

fn prove_leaf() -> CountMinOmcProof {
    build_countmin_omc_leaf_expose(PARAMS, Expose::None, BINDING).prove_epoch(prior(), batch(SECRET_KEY))
}

/// The public-input values of the leaf for a guessed secret key, in the
/// circuit's allocation order `[Com(S_{t-1}), Com(S_t), Com(B_t)]` (two
/// Challenges each).
fn public_inputs_for(key: u64) -> (Vec<Challenge>, [CountMinCommit; 3]) {
    let s0 = prior();
    let mut s1 = s0.clone();
    countmin_omc_advance_with(&mut s1, &batch(key), BINDING);
    let commits = [
        commit_countmin(&s0),
        commit_countmin(&s1),
        CountMinCommit(countmin_omc_batch_commit_with(&batch(key), BINDING)),
    ];
    (commits.iter().flat_map(pack_commit_to_challenge).collect(), commits)
}

/// Per-instance public values, as the circuit prover passes them to the
/// batch STARK (none for the three primitive tables).
fn public_values(proof: &BatchStarkProof<Sc>) -> Vec<Vec<Val>> {
    let mut pvs = vec![Vec::new(); 3];
    pvs.extend(proof.non_primitives.iter().map(|e| e.public_values.clone()));
    pvs
}

/// Replay the batch transcript from public data only, up to the lookup
/// challenges (as `p3_batch_stark::verify_batch` does), and return every
/// instance's challenges.
fn replay_lookup_challenges(proof: &BatchStarkProof<Sc>, data: &CircuitProverData<Sc>) -> Vec<Vec<Challenge>> {
    let p = &proof.proof;
    let n = p.opened_values.instances.len();
    let mut t = BatchTranscript::<Sc>::new(Challenger::new(make_perm()));
    t.observe_instance_count(n);
    for (i, inst) in p.opened_values.instances.iter().enumerate() {
        let ext_db = p.degree_bits[i];
        t.observe_instance_binding(
            ext_db,
            ext_db - usize::from(ZK),
            inst.base_opened_values.trace_local.len(),
            inst.base_opened_values.quotient_chunks.len(),
        );
    }
    t.observe_main(&p.commitments.main, &public_values(proof));
    let pre = proof.stark_common.preprocessed.as_ref();
    let widths: Vec<usize> = (0..n)
        .map(|i| pre.and_then(|g| g.instances[i].as_ref().map(|m| m.width)).unwrap_or(0))
        .collect();
    t.observe_preprocessed(&widths, pre);
    t.sample_perm_challenges(&data.prover_data.common.lookups, &LogUpGadget::new())
}

/// The global sums of instance `i` recomputed from a guessed main trace.
fn recompute_sums(
    proof: &BatchStarkProof<Sc>,
    data: &CircuitProverData<Sc>,
    challenges: &[Vec<Challenge>],
    i: usize,
    main: &RowMajorMatrix<Val>,
    preprocessed: &Option<RowMajorMatrix<Val>>,
) -> Vec<Challenge> {
    let mut lds: Vec<LookupData<Challenge>> = proof.proof.global_lookup_data[i].clone();
    LogUpGadget::new().generate_permutation::<Sc>(
        main,
        preprocessed,
        &[],
        &data.prover_data.common.lookups[i],
        &mut lds,
        &challenges[i],
    );
    lds.iter().map(|l| l.cumulative_sum).collect()
}

fn revealed(proof: &BatchStarkProof<Sc>, i: usize) -> Vec<Challenge> {
    proof.proof.global_lookup_data[i].iter().map(|l| l.cumulative_sum).collect()
}

/// `bus -> [(instance, global ordinal)]`.
fn buses(proof: &BatchStarkProof<Sc>) -> BTreeMap<String, Vec<(usize, usize)>> {
    let mut m: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    for (i, lds) in proof.proof.global_lookup_data.iter().enumerate() {
        for (g, ld) in lds.iter().enumerate() {
            m.entry(ld.name.clone()).or_default().push((i, g));
        }
    }
    m
}

/// Two proofs of the same leaf and witness. Masked: every revealed sum of a
/// bus with at least two members differs between the proofs; each bus still
/// sums to zero; a one-member bus reveals 0; every instance's opened main
/// width is its AIR width plus `D` per global interaction. Control: the sums
/// repeat exactly.
#[test]
fn revealed_sums_are_fresh_per_proof_and_zero_sum_per_bus() {
    let a = prove_leaf();
    let b = prove_leaf();
    let (pa, pb) = (&a.output.0, &b.output.0);
    assert_eq!(buses(pa), buses(pb), "same circuit, same interactions");
    let lookups = &a.output.1.prover_data.common.lookups;

    let (mut fresh, mut repeated, mut total) = (0, 0, 0);
    for (bus, members) in buses(pa) {
        for p in [pa, pb] {
            let sum = members
                .iter()
                .fold(Challenge::ZERO, |acc, &(i, g)| acc + p.proof.global_lookup_data[i][g].cumulative_sum);
            assert_eq!(sum, Challenge::ZERO, "bus {bus}: revealed sums must balance");
        }
        for &(i, g) in &members {
            let (ca, cb) = (pa.proof.global_lookup_data[i][g].cumulative_sum, pb.proof.global_lookup_data[i][g].cumulative_sum);
            total += 1;
            if members.len() == 1 {
                assert_eq!((ca, cb), (Challenge::ZERO, Challenge::ZERO), "bus {bus}: a one-member bus reveals 0");
            } else if ca == cb {
                repeated += 1;
            } else {
                fresh += 1;
            }
        }
    }

    // Opened main width = AIR width + D per global interaction (masked), on
    // the two tables whose AIR width is known here; and one global
    // interaction per revealed sum.
    for (i, lds) in pa.proof.global_lookup_data.iter().enumerate() {
        let globals = lookups[i].iter().filter(|l| matches!(l.kind, p3_lookup::Kind::Global(_))).count();
        assert_eq!(lds.len(), globals, "instance {i}: one revealed sum per global interaction");
    }
    let opened = |i: usize| pa.proof.opened_values.instances[i].base_opened_values.trace_local.len();
    let mask_cols = |i: usize| if ZK { D * pa.proof.global_lookup_data[i].len() } else { 0 };
    let pub_w = PublicAir::<Val, D>::new(1, pa.table_packing.public_lanes()).width();
    assert_eq!(opened(PUBLIC_INSTANCE), pub_w + mask_cols(PUBLIC_INSTANCE), "public table: opened main width");
    assert_eq!(opened(CONST_INSTANCE), D + mask_cols(CONST_INSTANCE), "const table: opened main width");

    println!("global interactions: {total}, fresh {fresh}, repeated {repeated} (zk = {ZK})");
    assert!(total > 2, "the leaf has global interactions");
    if ZK {
        assert_eq!(repeated, 0, "zk: every multi-member-bus sum is masked afresh per proof");
        assert!(fresh > 0);
    } else {
        assert_eq!(fresh, 0, "non-zk control: the sums are a deterministic function of the witness");
    }
}

/// Guess-and-check replay of one proved leaf. The verifier knows everything
/// but one batch key, replays the transcript to the lookup challenges, and
/// for every candidate key rebuilds the public-input table and recomputes
/// its revealed sum. Returns `(constant-table sums reproduced, constant-table
/// sums, matching candidate keys)`.
fn replay_guess_and_check(leaf: &CountMinOmcProof) -> (usize, usize, Vec<u64>) {
    let (proof, data) = (&leaf.output.0, &*leaf.output.1);

    // The guess function reproduces the leaf's own commitments.
    let (_, commits) = public_inputs_for(SECRET_KEY);
    assert_eq!(commits, [leaf.initial_commit, leaf.final_commit, leaf.batch_commit]);

    let challenges = replay_lookup_challenges(proof, data);
    let min_height = proof.table_packing.min_trace_height();

    // Constant table: preprocessed `[mult, index, value_0..D]`, main = value.
    let const_air = ConstAir::<Val, D>::new_with_preprocessed(0, data.primitive_columns[PrimitiveOpType::Const as usize].clone())
        .with_min_height(min_height);
    let const_pre = const_air.preprocessed_trace();
    let cp = const_pre.as_ref().expect("const preprocessed");
    let pw = cp.width();
    let const_main = RowMajorMatrix::new(
        cp.rows().flat_map(|r| r.into_iter().skip(pw - D).collect::<Vec<_>>()).collect(),
        D,
    );
    let const_sums = recompute_sums(proof, data, &challenges, CONST_INSTANCE, &const_main, &const_pre);
    let const_hits = const_sums.iter().zip(revealed(proof, CONST_INSTANCE)).filter(|(a, b)| **a == *b).count();

    // Public-input table, one candidate key at a time.
    let lanes = proof.table_packing.public_lanes();
    let pub_pre = PublicAir::<Val, D>::new_with_preprocessed(0, lanes, data.primitive_columns[PrimitiveOpType::Public as usize].clone())
        .with_min_height(min_height)
        .preprocessed_trace();
    let want = revealed(proof, PUBLIC_INSTANCE);
    assert!(!want.is_empty(), "the public table has a global interaction");
    let mut hits = Vec::new();
    for key in 0..CANDIDATES {
        let (values, _) = public_inputs_for(key);
        let trace = PublicTrace { index: vec![WitnessId(0); values.len()], values };
        let main = PublicAir::<Val, D>::trace_to_matrix(&trace, lanes, min_height);
        let got = recompute_sums(proof, data, &challenges, PUBLIC_INSTANCE, &main, &pub_pre);
        if got == want {
            hits.push(key);
        }
    }
    (const_hits, const_sums.len(), hits)
}

/// Guess-and-check replay of an honest proof. Masked: no candidate (the true
/// key included) reproduces the public table's revealed sum, and neither
/// does the constant table's sum, which needs no guess at all. Control
/// (`--no-default-features`): the constant table's sum is reproduced and
/// exactly one candidate, the true key, matches.
#[test]
fn guess_and_check_replay_of_revealed_sums() {
    let (const_hits, const_len, hits) = replay_guess_and_check(&prove_leaf());
    println!(
        "zk = {ZK}: const table {const_hits}/{const_len} sums reproduced; public table: {} of {CANDIDATES} keys match ({hits:?}), secret {SECRET_KEY}",
        hits.len()
    );
    if ZK {
        assert_eq!(const_hits, 0, "zk: even a sum of public data only is masked");
        assert!(hits.is_empty(), "zk: no key guess reproduces the revealed sum");
    } else {
        assert_eq!(const_hits, const_len, "control: the replay is exact");
        assert_eq!(hits, vec![SECRET_KEY], "control: the unmasked sum singles out the secret key");
    }
}

/// Positive control in the `zk` build: the same leaf proved under `zk` with
/// every LogUp mask set to zero (through the forks' test-only hook; the proof
/// still verifies, zero masks balance every bus) reveals the true sums, and
/// the same replay then reproduces the constant table's sum and singles out
/// the secret key. So the replay matches the `zk` transcript exactly, and the
/// `zk` result of `guess_and_check_replay_of_revealed_sums` is due to the
/// masks, not to a replay that drifted.
#[cfg(all(feature = "zk", feature = "test-hooks"))]
#[test]
fn zero_masks_make_the_zk_replay_exact() {
    let mut zeroed = 0usize;
    let leaf = build_countmin_omc_leaf_expose(PARAMS, Expose::None, BINDING).prove_epoch_with_mask_hook(
        prior(),
        batch(SECRET_KEY),
        |plan| {
            for m in plan.committed.iter_mut().flatten() {
                *m = Challenge::ZERO;
                zeroed += 1;
            }
        },
    );
    assert!(zeroed > 2, "the hook ran and saw the masks ({zeroed})");
    let (const_hits, const_len, hits) = replay_guess_and_check(&leaf);
    println!(
        "zk = {ZK}, masks zeroed ({zeroed}): const table {const_hits}/{const_len} sums reproduced; public table: {} of {CANDIDATES} keys match ({hits:?}), secret {SECRET_KEY}",
        hits.len()
    );
    assert_eq!(const_hits, const_len, "zero masks: the zk replay is exact");
    assert_eq!(hits, vec![SECRET_KEY], "zero masks: the revealed sum singles out the secret key");
}

/// G-zk for the M3 StableCompact GK leaf (`GkRounds::StableCompact`, cap 16,
/// m 8, s 3, `Expose::None`, Semantic, plain commitments), the same checks as
/// [`revealed_sums_are_fresh_per_proof_and_zero_sum_per_bus`] on two proofs
/// of one witness: masked, every revealed sum of a multi-member bus is fresh
/// per proof, every bus sums to zero, a one-member bus reveals 0, one
/// revealed sum per global interaction; the non-zk control repeats them.
#[test]
fn stable_gk_leaf_revealed_sums_are_fresh_and_zero_sum_per_bus() {
    use zksketch::commitment::hiding::CommitMode;
    use zksketch::sketch::gk_bandmerge::{apply_batch2, build_gkb2_leaf_rounds, Gk2State, GkRounds, GkbParams};
    let params = GkbParams { capacity: 16, batch: 8, s: 3 };
    let prior = apply_batch2(&Gk2State::empty(params), &[100, 400, 200, 700, 300, 600, 500, 800]);
    let batch = vec![150u32, 650, 250, 750, 350, 550, 450, 850];
    let mut leaf = build_gkb2_leaf_rounds(params, Expose::None, BINDING, CommitMode::Plain, GkRounds::StableCompact);
    let a = leaf.prove_epoch(prior.clone(), batch.clone());
    let b = leaf.prove_epoch(prior, batch);
    let (pa, pb) = (&a.output.0, &b.output.0);
    assert_eq!(buses(pa), buses(pb), "same circuit, same interactions");
    let lookups = &a.output.1.prover_data.common.lookups;
    let (mut fresh, mut repeated, mut total) = (0, 0, 0);
    for (bus, members) in buses(pa) {
        for p in [pa, pb] {
            let sum = members
                .iter()
                .fold(Challenge::ZERO, |acc, &(i, g)| acc + p.proof.global_lookup_data[i][g].cumulative_sum);
            assert_eq!(sum, Challenge::ZERO, "bus {bus}: revealed sums must balance");
        }
        for &(i, g) in &members {
            let (ca, cb) = (pa.proof.global_lookup_data[i][g].cumulative_sum, pb.proof.global_lookup_data[i][g].cumulative_sum);
            total += 1;
            if members.len() == 1 {
                assert_eq!((ca, cb), (Challenge::ZERO, Challenge::ZERO), "bus {bus}: a one-member bus reveals 0");
            } else if ca == cb {
                repeated += 1;
            } else {
                fresh += 1;
            }
        }
    }
    for (i, lds) in pa.proof.global_lookup_data.iter().enumerate() {
        let globals = lookups[i].iter().filter(|l| matches!(l.kind, p3_lookup::Kind::Global(_))).count();
        assert_eq!(lds.len(), globals, "instance {i}: one revealed sum per global interaction");
    }
    println!("stable GK leaf: global interactions {total}, fresh {fresh}, repeated {repeated} (zk = {ZK})");
    assert!(total > 2, "the leaf has global interactions");
    if ZK {
        assert_eq!(repeated, 0, "zk: every multi-member-bus sum is masked afresh per proof");
        assert!(fresh > 0);
    } else {
        assert_eq!(fresh, 0, "non-zk control: the sums are a deterministic function of the witness");
    }
}
