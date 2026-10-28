//! LogUp sums revealed by `zk` proofs are masked: fresh per proof, zero-sum per bus, no guess-and-check replay.
//! zero_masks_make_the_zk_replay_exact needs --features test-hooks,p3-circuit-prover/test-hooks.

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
    stable_gk_leaf_sums(Expose::None, CommitMode::Plain);
}

/// The same G-zk checks on the DEPLOYED form of the StableCompact leaf:
/// Interval statement and Hiding commitments (the expose table, the salt
/// inputs and the salted commitment rows), proved twice from one witness with
/// the honest openings of leaf `t = 2` (`Openings::for_leaf`).
#[test]
fn stable_gk_leaf_interval_hiding_revealed_sums_are_fresh_and_zero_sum_per_bus() {
    use zksketch::commitment::hiding::CommitMode;
    stable_gk_leaf_sums(Expose::Interval, CommitMode::Hiding);
}

/// Prove one StableCompact GK epoch twice (cap 16, m 8, s 3; `expose`,
/// `mode`) and check the revealed LogUp sums (see the two tests above).
fn stable_gk_leaf_sums(expose: Expose, mode: zksketch::commitment::hiding::CommitMode) {
    use zksketch::commitment::hiding::{CommitFamily, Openings, SaltSeed};
    use zksketch::sketch::gk_bandmerge::{apply_batch2, build_gkb2_leaf_rounds, Gk2State, GkRounds, GkbParams};
    let params = GkbParams { capacity: 16, batch: 8, s: 3 };
    let prior = apply_batch2(&Gk2State::empty(params), &[100, 400, 200, 700, 300, 600, 500, 800]);
    let batch = vec![150u32, 650, 250, 750, 350, 550, 450, 850];
    let mut leaf = build_gkb2_leaf_rounds(params, expose, BINDING, mode, GkRounds::StableCompact);
    let (a, b) = if mode.is_hiding() {
        let open = Openings::for_leaf(&SaltSeed::for_tests(2026), CommitFamily::GreenwaldKhanna, 2);
        let a = leaf.prove_epoch_commit(2, prior.clone(), batch.clone(), &open);
        let b = leaf.prove_epoch_commit(2, prior, batch, &open);
        assert_eq!(a.final_.0, b.final_.0, "same witness and openings: same Com(S_t; rho)");
        (a, b)
    } else {
        (leaf.prove_epoch(prior.clone(), batch.clone()), leaf.prove_epoch(prior, batch))
    };
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
    println!("stable GK leaf ({expose:?}, {mode:?}): global interactions {total}, fresh {fresh}, repeated {repeated} (zk = {ZK})");
    assert!(total > 2, "the leaf has global interactions");
    if ZK {
        assert_eq!(repeated, 0, "zk: every multi-member-bus sum is masked afresh per proof");
        assert!(fresh > 0);
    } else {
        assert_eq!(fresh, 0, "non-zk control: the sums are a deterministic function of the witness");
    }
}

/// Two proofs of one witness: every revealed LogUp sum of a multi-member bus
/// is fresh (zk) or repeated (non-zk control), every bus sums to zero, a
/// one-member bus reveals 0, one revealed sum per global interaction.
fn assert_sums_fresh(
    pa: &BatchStarkProof<Sc>,
    pb: &BatchStarkProof<Sc>,
    lookups: &[p3_lookup::Lookups<Val>],
    label: &str,
) {
    assert_eq!(buses(pa), buses(pb), "{label}: same circuit, same interactions");
    let (mut fresh, mut repeated, mut total) = (0, 0, 0);
    for (bus, members) in buses(pa) {
        for p in [pa, pb] {
            let sum = members
                .iter()
                .fold(Challenge::ZERO, |acc, &(i, g)| acc + p.proof.global_lookup_data[i][g].cumulative_sum);
            assert_eq!(sum, Challenge::ZERO, "{label}: bus {bus}: revealed sums must balance");
        }
        for &(i, g) in &members {
            let (ca, cb) = (pa.proof.global_lookup_data[i][g].cumulative_sum, pb.proof.global_lookup_data[i][g].cumulative_sum);
            total += 1;
            if members.len() == 1 {
                assert_eq!((ca, cb), (Challenge::ZERO, Challenge::ZERO), "{label}: bus {bus}: a one-member bus reveals 0");
            } else if ca == cb {
                repeated += 1;
            } else {
                fresh += 1;
            }
        }
    }
    for (i, lds) in pa.proof.global_lookup_data.iter().enumerate() {
        let globals = lookups[i].iter().filter(|l| matches!(l.kind, p3_lookup::Kind::Global(_))).count();
        assert_eq!(lds.len(), globals, "{label}: instance {i}: one revealed sum per global interaction");
    }
    println!("{label}: global interactions {total}, fresh {fresh}, repeated {repeated} (zk = {ZK})");
    assert!(total > 2, "{label}: the circuit has global interactions");
    if ZK {
        assert_eq!(repeated, 0, "{label}: zk: every multi-member-bus sum is masked afresh per proof");
        assert!(fresh > 0);
    } else {
        assert_eq!(fresh, 0, "{label}: non-zk control: the sums are a deterministic function of the witness");
    }
}

/// G-zk for the M2 packed-byte Bloom leaf (k = 3, log_w = 7, batch 8, a
/// non-empty prior, a repeated key and a dummy slot) in its standalone form
/// (`Expose::None`, plain commitments) and its DEPLOYED form (Interval,
/// Hiding, the honest openings of leaf `t = 2`), and for its membership
/// query (Hiding): two proofs of one witness each.
#[test]
fn packed_bloom_leaf_and_query_revealed_sums_are_fresh_and_zero_sum_per_bus() {
    use zksketch::commitment::hiding::{CommitFamily, CommitMode, Openings, SaltSeed, rho_state_bb};
    use zksketch::decode::bloom_packed::prove_bloom_packed_query_commit;
    use zksketch::sketch::bloom_packed::{
        BloomPackedParams, build_bloom_packed_leaf_commit, packed_empty, packed_insert,
    };
    let p = BloomPackedParams { k: 3, log_w: 7, batch: 8 };
    let keys: Vec<u64> = (0..20u64).map(|i| (i ^ 7).wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17)).collect();
    let mut prior = packed_empty(&p);
    packed_insert(&mut prior, &p, &keys[..12]);
    let mut batch = keys[12..18].to_vec();
    batch.push(batch[0]);
    let seed = SaltSeed::for_tests(2026);
    for (expose, mode) in [(Expose::None, CommitMode::Plain), (Expose::Interval, CommitMode::Hiding)] {
        let mut leaf = build_bloom_packed_leaf_commit(p, expose, mode);
        let (a, b) = if mode.is_hiding() {
            let open = Openings::for_leaf(&seed, CommitFamily::BloomPacked, 2);
            (leaf.prove_epoch_commit(2, &prior, &batch, &open), leaf.prove_epoch_commit(2, &prior, &batch, &open))
        } else {
            (leaf.prove_epoch_at(2, &prior, &batch), leaf.prove_epoch_at(2, &prior, &batch))
        };
        assert_eq!(a.final_commit.0, b.final_commit.0, "same witness: same commitments");
        let lookups = &a.output.1.prover_data.common.lookups;
        assert_sums_fresh(&a.output.0, &b.output.0, lookups, &format!("packed bloom leaf ({expose:?}, {mode:?})"));
    }
    let mut state = prior.clone();
    packed_insert(&mut state, &p, &batch);
    let salt = rho_state_bb(&seed, CommitFamily::BloomPacked, 2);
    let qa = prove_bloom_packed_query_commit(p, &state, batch[1], CommitMode::Hiding, &salt);
    let qb = prove_bloom_packed_query_commit(p, &state, batch[1], CommitMode::Hiding, &salt);
    assert_eq!(qa.answer, 1);
    let lookups = &qa.output.1.prover_data.common.lookups;
    assert_sums_fresh(&qa.output.0, &qb.output.0, lookups, "packed bloom query (Hiding)");
}
