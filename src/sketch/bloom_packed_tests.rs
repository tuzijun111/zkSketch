use super::*;
use crate::commitment::hiding::SaltSeed;
use crate::recursion::recursive::expose_forest::{read_exposed_statement, vk_pin_values};
use crate::sketch::bloom_omc::{bloom_empty, bloom_insert, commit_bloom_with};
use crate::sketch::forge_permute::forge_permute_outputs;

const P: BloomPackedParams = BloomPackedParams { k: 3, log_w: 7, batch: 8 };

fn keys(n: usize, seed: u64) -> Vec<u64> {
    (0..n as u64).map(|i| (i ^ seed).wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17)).collect()
}

fn prior(p: &BloomPackedParams) -> Vec<u8> {
    let mut w = packed_empty(p);
    packed_insert(&mut w, p, &keys(20, 7));
    w
}

fn expected(p: &BloomPackedParams, initial: &[u8], ks: &[u64]) -> Vec<u8> {
    let mut w = initial.to_vec();
    packed_insert(&mut w, p, ks);
    w
}

// ─── Filter semantics ────────────────────────────────────────────────────────

/// The deployed shape: the packed filter is `bloom_omc`'s bit array, 8 bits
/// per byte, after 5,000 inserts; every member answers 1 and the answers of
/// 2,000 probes agree.
#[test]
fn same_filter_as_bloom_omc() {
    let bp = BloomOmcParams { k: 7, log_w: 14, batch: 1 };
    let pp = BloomPackedParams::from(bp);
    let ks = keys(5000, 3);
    let mut bits = bloom_empty(&bp);
    bloom_insert(&mut bits, &bp, &ks);
    let mut w = packed_empty(&pp);
    packed_insert(&mut w, &pp, &ks);
    assert_eq!(bits_to_words(&bits), w);
    assert_eq!(words_to_bits(&w), bits);
    assert!(ks.iter().all(|&k| packed_contains(&w, &pp, k)));
    for k in keys(2000, 0xBEEF) {
        assert_eq!(packed_contains(&w, &pp, k), crate::sketch::bloom_omc::bloom_contains(&bits, &bp, k));
    }
}

/// Differential fuzz over shapes and batches with duplicates: the native
/// packed insert, the HONEST LEAF WITNESS (the state the circuit proves) and
/// `bloom_omc` agree word for word at every step.
#[test]
fn same_filter_as_bloom_omc_fuzz() {
    for (k, log_w, batch) in [(1usize, 7usize, 5usize), (3, 7, 8), (7, 9, 16), (8, 10, 33), (5, 12, 64)] {
        let pp = BloomPackedParams { k, log_w, batch };
        let bp = pp.omc();
        let mut bits = bloom_empty(&bp);
        let mut w = packed_empty(&pp);
        for round in 0..6u64 {
            let mut ks = keys(batch - (round as usize % 3), 1000 * k as u64 + round);
            if ks.len() > 2 {
                let dup = ks[0];
                ks[1] = dup; // a duplicate inside the batch
            }
            bloom_insert(&mut bits, &bp, &ks);
            let wit = epoch_witness(&pp, &w, &ks);
            packed_insert(&mut w, &pp, &ks);
            assert_eq!(wit.final_bytes(), w, "witness state (k={k} log_w={log_w} round {round})");
            assert_eq!(bits_to_words(&bits), w, "k={k} log_w={log_w} round {round}");
        }
    }
}

#[test]
fn commitments_and_params() {
    // Plain batch commitment is bloom_omc's; Hiding ones differ by family.
    let ks = keys(5, 9);
    assert_eq!(packed_batch_commit(8, &ks), crate::sketch::bloom_omc::bloom_batch_commit(8, &ks));
    let salt = SaltBb([Val::from_u64(3); 12]);
    assert_ne!(
        packed_batch_commit_with(8, &ks, CommitMode::Hiding, &salt),
        crate::sketch::bloom_omc::bloom_batch_commit_with(8, &ks, CommitMode::Hiding, &salt),
        "family 7 vs family 5"
    );
    // Genesis Com(0^{M_w}; 0) differs from bloom_omc's Com(0^M; 0) in both modes.
    let op = P.omc();
    for mode in [CommitMode::Plain, CommitMode::Hiding] {
        assert_ne!(
            commit_packed_with(&P, &packed_empty(&P), mode, &SaltBb::ZERO),
            commit_bloom_with(&bloom_empty(&op), mode, &SaltBb::ZERO)
        );
    }
    // The flat encoding: 3 bytes per limb, padded to a multiple of 4 limbs.
    let pp = BloomPackedParams { k: 7, log_w: 14, batch: 1024 };
    assert_eq!((pp.m_words(), pp.n_limbs()), (14_336, 4_780));
    let mut w = packed_empty(&pp);
    w[0] = 1;
    w[1] = 2;
    w[2] = 3;
    w[14_335] = 0xFF;
    let f = words_flat(&pp, &w);
    assert_eq!(f[0], Val::from_u64(1 + 2 * 256 + 3 * 65536));
    assert_eq!(f[4778], Val::from_u64(0xFF << 8)); // word 14,335 = limb 4,778, byte 1
    assert_eq!(f[4779], Val::ZERO);
    // Timestamps: k·batch < 2^16.
    assert!(BloomPackedParams { k: 7, log_w: 14, batch: 9362 }.check().is_ok());
    assert!(BloomPackedParams { k: 7, log_w: 14, batch: 9363 }.check().is_err());
    assert!(BloomPackedParams { k: 7, log_w: 6, batch: 4 }.check().is_err());
    assert!(BloomPackedParams { k: 9, log_w: 14, batch: 4 }.check().is_err());
}

/// splitmix64: a small deterministic generator for the fuzz tests.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// A random batch of at most `batch` keys (the leaf pads the rest with
/// dummies; a quarter of the batches are full): mostly drawn from `pool`, so
/// keys repeat inside a batch and across batches, sometimes a fresh key or
/// an edge key (`0`, `1`, `2^32 − 1`, `2^63`, `2^64 − 1`).
fn random_batch(rng: &mut SplitMix, pool: &[u64], batch: usize) -> Vec<u64> {
    let n = if rng.below(4) == 0 { batch } else { rng.below(batch + 1) };
    (0..n)
        .map(|_| match rng.below(8) {
            0 => rng.next(),
            1 => [0, 1, u32::MAX as u64, 1 << 63, u64::MAX][rng.below(5)],
            _ => pool[rng.below(pool.len())],
        })
        .collect()
}

/// Differential fuzz against `bloom_omc` on RANDOM batches with duplicates
/// (inside a batch, across batches, edge keys), at the deployed shape
/// (k = 7, W = 2^14, m = 1,024), the test shapes (k = 3, log_w = 7, batch 4
/// and 8) and a spread of others: after every batch
/// `bits_to_words(bloom_insert(..)) == packed_insert(..)` and the HONEST LEAF
/// WITNESS's final state (the per-access timestamped replay the circuit
/// proves) agree word for word, every inserted key is a member of both, and
/// random probes get the same answer from both.
#[test]
fn differential_fuzz_random_batches_vs_bloom_omc() {
    use crate::sketch::bloom_omc::bloom_contains;
    let mut rng = SplitMix(0x00B1_00B1_2026_1016);
    for (k, log_w, batch, rounds) in
        [(7usize, 14usize, 1024usize, 4usize), (3, 7, 4, 40), (3, 7, 8, 30), (1, 7, 3, 20), (8, 10, 64, 10), (2, 20, 16, 3)]
    {
        let pp = BloomPackedParams { k, log_w, batch };
        let bp = pp.omc();
        let pool: Vec<u64> = (0..(batch / 2).max(2)).map(|_| rng.next()).collect();
        let mut bits = bloom_empty(&bp);
        let mut w = packed_empty(&pp);
        let mut inserted: Vec<u64> = Vec::new();
        let (mut dups, mut dummies) = (0usize, 0usize);
        for round in 0..rounds {
            let ks = random_batch(&mut rng, &pool, batch);
            let distinct: std::collections::HashSet<u64> = ks.iter().copied().collect();
            dups += ks.len() - distinct.len();
            dummies += batch - ks.len();
            let wit = epoch_witness(&pp, &w, &ks);
            bloom_insert(&mut bits, &bp, &ks);
            packed_insert(&mut w, &pp, &ks);
            let tag = format!("k={k} log_w={log_w} batch={batch} round {round}");
            assert_eq!(wit.final_bytes(), w, "{tag}: the leaf witness's state");
            assert_eq!(bits_to_words(&bits), w, "{tag}: bloom_omc's bits");
            inserted.extend(&ks);
            for &key in inserted.iter().rev().take(16) {
                assert!(packed_contains(&w, &pp, key) && bloom_contains(&bits, &bp, key), "{tag}: member {key}");
            }
            for _ in 0..32 {
                let key = rng.next();
                assert_eq!(packed_contains(&w, &pp, key), bloom_contains(&bits, &bp, key), "{tag}: probe {key}");
            }
        }
        assert!(dups > 0 && dummies > 0, "k={k} log_w={log_w}: the fuzz saw duplicates ({dups}) and dummies ({dummies})");
    }
}

/// The 16-bit timestamp bound `k·batch < 2^16` (`m ≤ 9,362` at `k = 7`) is
/// enforced with a clear error wherever a shape enters: the parameters, the
/// leaf builder (before any circuit work), and the harness shape
/// (`StreamShape::check_bloom_packed`, which `exp_compose` reports with exit
/// 2 under `EXP_BLOOM_VARIANT=packed`). The bit-array leaf has no such bound,
/// and the membership query ignores the batch size (its VK is the same at
/// any `batch`).
#[test]
fn timestamp_bound_is_enforced_with_a_clear_error() {
    use crate::experiments::stream_compose::StreamShape;
    use crate::sketch::forge::catch_msg;
    use crate::sketch::gk_bandmerge::GkRounds;
    let ok = BloomPackedParams { k: 7, log_w: 14, batch: 9362 };
    let bad = BloomPackedParams { batch: 9363, ..ok };
    assert!(ok.check().is_ok(), "7·9,362 = 65,534 < 2^16");
    let e = bad.check().unwrap_err();
    assert!(e.contains("k·batch = 65541") && e.contains("below 2^16") && e.contains("batch ≤ 9362 at k = 7"), "{e}");
    // k = 8: 8·8,191 = 65,528 is the last legal batch.
    assert!(BloomPackedParams { k: 8, log_w: 14, batch: 8191 }.check().is_ok());
    let e8 = BloomPackedParams { k: 8, log_w: 14, batch: 8192 }.check().unwrap_err();
    assert!(e8.contains("batch ≤ 8191 at k = 8"), "{e8}");
    // The leaf builder refuses before building anything.
    let r = catch_msg(|| {
        build_bloom_packed_leaf_commit(bad, Expose::Interval, CommitMode::Hiding);
    });
    assert!(r.is_err_and(|m| m.contains("16-bit timestamps")));
    // The harness shape (what exp_compose checks for every m).
    let sh = StreamShape {
        d: 4,
        w: 8,
        b: 4,
        capacity: 4,
        gk_s: 2,
        bloom_k: 7,
        bloom_log_w: 14,
        kmv_k: 4,
        gk_rounds: GkRounds::SortedCopy,
    };
    assert_eq!(sh.check_bloom_packed(9362), Ok(ok));
    assert!(sh.check_bloom_packed(9363).is_err_and(|m| m.contains("16-bit timestamps")));
    assert!(catch_msg(|| sh.bloom_packed_params(9363)).is_err_and(|m| m.contains("16-bit timestamps")));
    assert!(sh.check_bloom(9363).is_ok(), "the bit-array leaf has no timestamp bound");
    // The membership query depends on (k, log_w) only.
    let small = BloomPackedParams { k: 3, log_w: 7, batch: 4 };
    let huge = BloomPackedParams { batch: 30_000, ..small };
    assert!(huge.check().is_err() && huge.check_filter().is_ok());
    let vk = |p| crate::decode::bloom_packed::bloom_packed_decode_vk(p).commitment;
    assert_eq!(vk(small), vk(huge), "the query ignores the batch size");
}

// ─── Honest round trips ──────────────────────────────────────────────────────

fn prove_layout(expose: Expose, mode: CommitMode, t: u64, initial: &[u8], ks: &[u64], seed: &SaltSeed) -> BloomPackedProof {
    let mut leaf = build_bloom_packed_leaf_commit(P, expose, mode);
    if mode.is_hiding() {
        leaf.prove_epoch_commit(t, initial, ks, &Openings::for_leaf(seed, FAMILY, t))
    } else {
        leaf.prove_epoch_at(t, initial, ks)
    }
}

/// Every layout in both commitment modes over a non-empty prior, a batch with
/// a repeated key and dummy slots: the proved state is the native insert, and
/// the exposed values are the native commitments (`None`: `(init, final,
/// batch)`; `Interval`: the statement's boundary).
#[test]
fn honest_round_trip_all_layouts_plain_and_hiding() {
    let seed = SaltSeed::for_tests(77);
    let mut ks = keys(5, 0x5000);
    ks.push(ks[0]);
    ks.push(ks[2]);
    let init = prior(&P);
    let want = expected(&P, &init, &ks);
    for mode in [CommitMode::Plain, CommitMode::Hiding] {
        for expose in [Expose::None, Expose::Boundary, Expose::Interval] {
            let t = 3;
            let pr = prove_layout(expose, mode, t, &init, &ks, &seed);
            assert_eq!(pr.final_words, want, "{mode:?} {expose:?}");
            let o = if mode.is_hiding() { Openings::for_leaf(&seed, FAMILY, t) } else { Openings::plain() };
            assert_eq!(pr.initial_commit.0, commit_packed_with(&P, &init, mode, &o.init));
            assert_eq!(pr.final_commit.0, commit_packed_with(&P, &want, mode, &o.final_));
            assert_eq!(pr.batch_commit.0, packed_batch_commit_with(P.batch, &ks, mode, &o.batch));
            match expose {
                Expose::None => {
                    let (i, f, b) = read_exposed_commitments(&pr.output.0);
                    assert_eq!((i, f, b), (pr.initial_commit.0, pr.final_commit.0, pr.batch_commit.0));
                }
                Expose::Interval => {
                    let st = read_exposed_statement(&pr.output.0);
                    assert_eq!(st.init, pr.initial_commit.0.to_vec());
                    assert_eq!(st.final_, pr.final_commit.0.to_vec());
                }
                Expose::Boundary => {}
            }
        }
    }
}

/// An all-dummy batch is a no-op (`init == final`), in both modes through
/// their public entry points.
#[test]
fn all_dummy_batch_is_noop() {
    let init = prior(&P);
    let pr = build_bloom_packed_leaf_expose(P, Expose::Interval).prove_epoch_at(1, &init, &[]);
    assert_eq!(pr.final_words, init);
    assert_eq!(pr.initial_commit.0, pr.final_commit.0);
    let noop = build_bloom_packed_leaf_commit(P, Expose::Interval, CommitMode::Hiding).prove_epoch_public_zero(
        1,
        &packed_empty(&P),
        &[],
    );
    assert_eq!(noop.initial_commit.0, noop.final_commit.0);
    assert_eq!(noop.initial_commit.0, commit_packed_with(&P, &packed_empty(&P), CommitMode::Hiding, &SaltBb::ZERO));
}

/// The hiding entry points refuse the public zero salt where it would publish
/// a guess-checkable commitment of a secret state.
#[test]
fn hiding_guards() {
    use crate::sketch::forge::catch_msg;
    let init = prior(&P);
    let ks = keys(3, 1);
    let hiding = || build_bloom_packed_leaf_commit(P, Expose::Interval, CommitMode::Hiding);
    let r = catch_msg(|| {
        hiding().prove_epoch_at(1, &init, &ks);
    });
    assert!(r.is_err_and(|e| e.contains("Com(S; 0)")));
    let r = catch_msg(|| {
        hiding().prove_epoch_commit(2, &init, &ks, &Openings::plain());
    });
    assert!(r.is_err_and(|e| e.contains("secret randomizers")));
    let seed = SaltSeed::for_tests(3);
    let mut o = Openings::for_leaf(&seed, FAMILY, 2);
    o.init = SaltBb::ZERO;
    let r = catch_msg(|| {
        hiding().prove_epoch_commit(2, &init, &ks, &o);
    });
    assert!(r.is_err_and(|e| e.contains("zero init salt")));
    let r = catch_msg(|| {
        hiding().prove_epoch_public_zero(1, &init, &[]);
    });
    assert!(r.is_err_and(|e| e.contains("no-op leaf")));
}

/// The leaf's VK does not depend on the data (the no-op leaf's VK is every
/// leaf's), and differs between layouts and commitment modes.
#[test]
fn vk_is_data_independent() {
    let a = build_bloom_packed_leaf_expose(P, Expose::Interval).prove_epoch_at(1, &packed_empty(&P), &[]);
    let b = build_bloom_packed_leaf_expose(P, Expose::Interval).prove_epoch_at(5, &prior(&P), &keys(8, 2));
    assert_eq!(vk_pin_values(&a.output.0), vk_pin_values(&b.output.0));
    let c = build_bloom_packed_leaf_expose(P, Expose::Boundary).prove_epoch_at(1, &packed_empty(&P), &[]);
    assert_ne!(vk_pin_values(&a.output.0), vk_pin_values(&c.output.0));
    let h = build_bloom_packed_leaf_commit(P, Expose::Interval, CommitMode::Hiding).prove_epoch_public_zero(
        1,
        &packed_empty(&P),
        &[],
    );
    assert_ne!(vk_pin_values(&a.output.0), vk_pin_values(&h.output.0));
}

/// Proved differential at the test shape (k = 3, log_w = 7, batch = 4): the
/// same chain of random batches (repeated keys, dummy slots, an all-dummy
/// batch) is proved epoch by epoch in BOTH commitment modes with the
/// composition statement (Interval; Hiding with the honest openings of leaf
/// `t`). Every proved state is `bits_to_words` of `bloom_omc`'s, every leaf
/// starts at the previous leaf's exposed `Com(S_t)` (genesis
/// `Com(0^{M_w}; 0)`), and proved membership queries of the packed decoder
/// answer exactly what proved queries of the bit-array decoder answer.
#[test]
fn proved_differential_vs_bloom_omc_at_test_shape() {
    use crate::decode::bloom::prove_bloom_query;
    use crate::decode::bloom_packed::prove_bloom_packed_query;
    use crate::sketch::bloom_omc::bloom_contains;
    let p = BloomPackedParams { k: 3, log_w: 7, batch: 4 };
    let op = p.omc();
    let mut rng = SplitMix(0x7E57_5A9E);
    let pool: Vec<u64> = (0..5).map(|_| rng.next()).collect();
    let mut batches: Vec<Vec<u64>> = (0..4).map(|_| random_batch(&mut rng, &pool, p.batch)).collect();
    batches[1] = vec![pool[0], pool[1], pool[0]]; // a repeat inside the batch, one dummy
    batches.push(Vec::new()); // an all-dummy batch
    let seed = SaltSeed::for_tests(41);
    let mut finals: Vec<Vec<u8>> = Vec::new();
    for mode in [CommitMode::Plain, CommitMode::Hiding] {
        let mut leaf = build_bloom_packed_leaf_commit(p, Expose::Interval, mode);
        let (mut words, mut bits) = (packed_empty(&p), bloom_empty(&op));
        let mut prev = commit_packed_with(&p, &words, mode, &SaltBb::ZERO);
        for (bi, ks) in batches.iter().enumerate() {
            let t = bi as u64 + 1;
            let pr = if mode.is_hiding() {
                leaf.prove_epoch_commit(t, &words, ks, &Openings::for_leaf(&seed, FAMILY, t))
            } else {
                leaf.prove_epoch_at(t, &words, ks)
            };
            bloom_insert(&mut bits, &op, ks);
            packed_insert(&mut words, &p, ks);
            assert_eq!(pr.final_words, words, "{mode:?} leaf {t}");
            assert_eq!(bits_to_words(&bits), pr.final_words, "{mode:?} leaf {t}: bloom_omc's bits");
            assert_eq!(pr.initial_commit.0, prev, "{mode:?}: leaf {t} starts where leaf {} ended", t - 1);
            let st = read_exposed_statement(&pr.output.0);
            assert_eq!((st.init, st.final_), (prev.to_vec(), pr.final_commit.0.to_vec()), "{mode:?} leaf {t}");
            prev = pr.final_commit.0;
        }
        finals.push(words);
    }
    assert_eq!(finals[0], finals[1], "both modes certify the same filter");
    let words = &finals[0];
    let bits = words_to_bits(words);
    let mut probes: Vec<u64> = batches.iter().flatten().copied().take(4).collect();
    probes.extend((0..4).map(|_| rng.next()));
    let (mut ones, mut zeros) = (0, 0);
    for key in probes {
        let want = u64::from(bloom_contains(&bits, &op, key));
        assert_eq!(prove_bloom_packed_query(p, words, key).answer, want, "packed query {key}");
        assert_eq!(prove_bloom_query(op, &bits, key).answer, want, "bit-array query {key}");
        if want == 1 { ones += 1 } else { zeros += 1 }
    }
    assert!(ones >= 4 && zeros >= 1, "members {ones}, non-members {zeros}");
}

/// The DEPLOYED filter shape (k = 7, W = 2^14, M_w = 14,336 bytes) through
/// the circuits in the deployed form (Interval statement, Hiding
/// commitments): a 16-slot leaf over a 2,000-key prior, with a key repeated
/// in the batch, a key already in the prior and dummy slots, certifies
/// exactly `bits_to_words` of `bloom_omc`'s insert; membership queries of the
/// certified filter (members and non-members) answer `bloom_omc`'s AND and
/// verify against the decode VK derived from public parameters.
#[test]
fn deployed_shape_leaf_and_queries_match_bloom_omc() {
    use crate::decode::bloom::bloom_query_input;
    use crate::decode::bloom_packed::{bloom_packed_decode_vk_commit, prove_bloom_packed_query_commit};
    use crate::decode::{QueryStatement, verify_decode_proof};
    use crate::sketch::bloom_omc::bloom_contains;
    let p = BloomPackedParams { k: 7, log_w: 14, batch: 16 };
    let op = p.omc();
    let prior_keys = keys(2000, 0xD0D0);
    let mut bits = bloom_empty(&op);
    bloom_insert(&mut bits, &op, &prior_keys);
    let init = bits_to_words(&bits);
    let mut ks = keys(10, 0xFEED);
    ks.push(ks[3]);
    ks.push(prior_keys[17]);
    let seed = SaltSeed::for_tests(1416);
    let t = 2;
    let open = Openings::for_leaf(&seed, FAMILY, t);
    let pr = build_bloom_packed_leaf_commit(p, Expose::Interval, CommitMode::Hiding).prove_epoch_commit(t, &init, &ks, &open);
    bloom_insert(&mut bits, &op, &ks);
    assert_eq!(pr.final_words, bits_to_words(&bits), "the certified filter is bloom_omc's");
    let st = read_exposed_statement(&pr.output.0);
    assert_eq!(st.init, commit_packed_with(&p, &init, CommitMode::Hiding, &open.init).to_vec());
    assert_eq!(st.final_, commit_packed_with(&p, &pr.final_words, CommitMode::Hiding, &open.final_).to_vec());
    let vk = bloom_packed_decode_vk_commit(p, CommitMode::Hiding);
    let commit = pr.final_commit.0;
    let non: Vec<u64> = keys(500, 0xABBA).into_iter().filter(|&k| !bloom_contains(&bits, &op, k)).take(2).collect();
    assert_eq!(non.len(), 2);
    for key in [ks[0], ks[11], prior_keys[1999], non[0], non[1]] {
        let want = u64::from(bloom_contains(&bits, &op, key));
        let q = prove_bloom_packed_query_commit(p, &pr.final_words, key, CommitMode::Hiding, &open.final_);
        assert_eq!(q.answer, want, "key {key}");
        assert_eq!(
            verify_decode_proof(&q.output.0, &vk),
            Ok(QueryStatement::with_query(commit, bloom_query_input(key), want)),
            "key {key}"
        );
    }
}

/// Every test switch ([`PackedChecks`]) is clean: with exactly one check
/// removed, the leaf and the query still prove an honest witness (repeated
/// key, dummy slot; a member query); the leaf's VK changes iff the check
/// belongs to the leaf and the query's VK iff it belongs to the query; no
/// two switches build the same circuit; the switches cover every field; and
/// `with_checks` restores the deployed set.
#[test]
fn check_switches_are_clean() {
    use crate::decode::bloom_packed::try_prove_bloom_packed_query_commit;
    let p = BloomPackedParams { k: 3, log_w: 7, batch: 4 };
    let init = prior(&p);
    let mut ks = keys(2, 0x5150);
    ks.push(ks[0]);
    let want = expected(&p, &init, &ks);
    let member = ks[1];
    let query = || try_prove_bloom_packed_query_commit(p, &want, member, CommitMode::Plain, &SaltBb::ZERO);
    let leaf_vk = build_bloom_packed_leaf_expose(p, Expose::Interval).vk_values();
    let query_vk = vk_pin_values(&query().expect("deployed query").output.0);
    let (mut leaf_vks, mut query_vks) = (vec![leaf_vk.clone()], vec![query_vk.clone()]);
    let mut cleared = PackedChecks::ALL;
    for (name, in_leaf, in_query) in PackedChecks::SWITCHES {
        let off = PackedChecks::without(name);
        let mut leaf = with_checks(off, || build_bloom_packed_leaf_expose(p, Expose::Interval));
        let pr = leaf.prove_epoch_at(2, &init, &ks);
        assert_eq!(pr.final_words, want, "{name}: the honest witness still proves");
        let lv = vk_pin_values(&pr.output.0);
        assert_eq!(lv != leaf_vk, in_leaf, "{name}: the leaf VK changes iff the check is in the leaf");
        let q = with_checks(off, query).unwrap_or_else(|e| panic!("{name}: honest query: {e}"));
        assert_eq!(q.answer, 1, "{name}");
        let qv = vk_pin_values(&q.output.0);
        assert_eq!(qv != query_vk, in_query, "{name}: the query VK changes iff the check is in the query");
        if in_leaf {
            assert!(!leaf_vks.contains(&lv), "{name}: a leaf circuit no other switch builds");
            leaf_vks.push(lv);
        }
        if in_query {
            assert!(!query_vks.contains(&qv), "{name}: a query circuit no other switch builds");
            query_vks.push(qv);
        }
        let text = format!("{off:?}");
        assert!(text.matches("false").count() == 1 && text.contains(&format!("{name}: false")), "{name}: turns off its own field only");
        cleared = and(cleared, off);
    }
    assert!(!format!("{cleared:?}").contains("true"), "the switches cover every field: {cleared:?}");
    assert_eq!(checks(), PackedChecks::ALL, "with_checks restores the deployed set");
}

/// Field-wise AND of two switch sets (a struct literal: a new field must be
/// added here, and then to `PackedChecks::SWITCHES` for the coverage check).
fn and(a: PackedChecks, b: PackedChecks) -> PackedChecks {
    PackedChecks {
        o_pin: a.o_pin && b.o_pin,
        n_pin: a.n_pin && b.n_pin,
        ft_range: a.ft_range && b.ft_range,
        act_bool: a.act_bool && b.act_bool,
        key_range: a.key_range && b.key_range,
        dummy_canon: a.dummy_canon && b.dummy_canon,
        i_bool: a.i_bool && b.i_bool,
        q_range: a.q_range && b.q_range,
        canon: a.canon && b.canon,
        unused_limbs: a.unused_limbs && b.unused_limbs,
        c_bool: a.c_bool && b.c_bool,
        h_range: a.h_range && b.h_range,
        l_nonneg: a.l_nonneg && b.l_nonneg,
        l_lt_e: a.l_lt_e && b.l_lt_e,
        ts_lt_tau: a.ts_lt_tau && b.ts_lt_tau,
        cell_pin: a.cell_pin && b.cell_pin,
        sel_bool: a.sel_bool && b.sel_bool,
        onehot_sum: a.onehot_sum && b.onehot_sum,
    }
}

// ─── Forgeries ───────────────────────────────────────────────────────────────

/// The honest view of one pair during a replay.
#[derive(Copy, Clone, Debug)]
struct Seen {
    pidx: usize,
    /// Record and slice.
    r: usize,
    j: usize,
    u: u64,
    i: u64,
    act: u64,
    /// The word's current (honest-replay) value and last-write time.
    v: u64,
    ts: u64,
}

/// How a forger overrides one pair.
#[derive(Clone, Debug, Default)]
struct Over {
    /// `[c, H, L, dlo, dhi]` (unset: honest for the claimed `v`, `ts`).
    w: Option<[Val; PAIR_WITNESSES]>,
    /// Self-read: the pair's write is consumed by its own read; the state
    /// continues from the previous write.
    self_read: bool,
    /// Routing override of the pair's record slice: `(split values of the
    /// slice, forged word address, forged e)`.
    route: Option<(Vec<Val>, u64, Val)>,
}

/// The split witness values of one used slice from field values; a value
/// that does not fit its bytes goes entirely into byte 0 (the forger's
/// choice; the byte lookups object when on).
fn slice_vals(p: &BloomPackedParams, q: Val, ib: [Val; 3], hi: Val, dd: Val, dinv: Val) -> Vec<Val> {
    let (nq, nh) = (q_bytes(p.log_w), hi_bytes(p.log_w));
    let enc = |x: Val, n: usize| -> Vec<Val> {
        let v = x.as_canonical_u64();
        if v < 1u64 << (8 * n) {
            bytes_of(v, n).collect()
        } else {
            let mut out = vec![Val::ZERO; n];
            out[0] = x;
            out
        }
    };
    let mut out = enc(q, nq);
    out.extend(ib);
    out.extend(enc(hi, nh));
    out.extend(enc(dd, nh));
    out.push(dinv);
    out
}

/// Width of one used slice in the split layout.
fn slice_width(p: &BloomPackedParams) -> usize {
    q_bytes(p.log_w) + 3 + 2 * hi_bytes(p.log_w) + 1
}

/// Replay one epoch, letting `pick` override the first pair it returns
/// `Some` for. Returns the forged witness and the overridden pair, or `None`
/// if no pair was picked. Panics if the honest part of the replay meets a
/// non-byte word (pick targets whose forged write stays a byte).
fn replay(
    p: &BloomPackedParams,
    initial: &[u8],
    ks: &[u64],
    pick: &dyn Fn(&Seen) -> Option<Over>,
) -> Option<(PackedWitness, Seen)> {
    let mut wit = epoch_witness(p, initial, ks);
    let wps = p.words_per_slice() as u64;
    let mut words: Vec<Val> = wit.initial.clone();
    let mut last: Vec<Val> = vec![Val::ZERO; p.m_words()];
    let mut picked: Option<Seen> = None;
    let routes: Vec<(u64, u64, u64)> = wit
        .recs
        .iter()
        .flat_map(|rec| {
            let act = u64::from(rec.is_some());
            packed_positions(p, *rec).into_iter().enumerate().map(move |(j, (q, i))| (j as u64 * wps + q, i, act))
        })
        .collect();
    for pidx in 0..p.pairs() {
        let (r, j) = (pidx / p.k, pidx % p.k);
        let (u0, i, act) = routes[pidx];
        let mut u = u0;
        let cur_v = |u: u64, words: &[Val]| words[u as usize].as_canonical_u64();
        let mut seen = Seen { pidx, r, j, u, i, act, v: cur_v(u, &words), ts: last[u as usize].as_canonical_u64() };
        let over = if picked.is_none() { pick(&seen) } else { None };
        let mut pr = wit.pairs[pidx];
        pr.act = act;
        pr.e = Val::from_u64(1 << i);
        if let Some(o) = &over {
            if let Some((vals, fu, fe)) = &o.route {
                let sw = slice_width(p);
                wit.split[r][j * sw..(j + 1) * sw].copy_from_slice(vals);
                u = *fu;
                pr.e = *fe;
                seen.u = u;
                seen.v = cur_v(u, &words);
                seen.ts = last[u as usize].as_canonical_u64();
            }
        }
        pr.u = u;
        let (v, ts) = (seen.v, seen.ts);
        assert!(v < 256, "replay met a non-byte word {v} at pair {pidx}");
        // The bit the (possibly re-routed) pair addresses.
        let i = (0..8).find(|&b| pr.e == Val::from_u64(1 << b)).unwrap_or(i);
        let honest_w = |v: u64, ts: u64| -> [Val; PAIR_WITNESSES] {
            let e = 1u64 << i;
            let d = (Val::from_u64(pidx as u64) - Val::from_u64(ts)).as_canonical_u64();
            let (dlo, dhi) = if d < 1 << 16 { (d & 0xFF, d >> 8) } else { (d, 0) };
            [(v >> i) & 1, v >> (i + 1), v & (e - 1), dlo, dhi].map(Val::from_u64)
        };
        pr.w = match &over {
            Some(Over { w: Some(w), .. }) => *w,
            _ => honest_w(v, ts),
        };
        pr.derive(pidx);
        let self_read = over.as_ref().is_some_and(|o| o.self_read);
        if !self_read {
            words[u as usize] = pr.cur;
            last[u as usize] = Val::from_u64(pidx as u64 + 1);
        }
        wit.pairs[pidx] = pr;
        if over.is_some() {
            picked = Some(seen);
        }
    }
    let seen = picked?;
    wit.final_words = words;
    wit.ft = last;
    let unmatched = wit.match_sigma();
    assert_eq!(unmatched, 0, "the forged witness must still be a permutation (else use forge_permute_outputs)");
    Some((wit, seen))
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Proved and self-verified, with the final state it committed to.
    Accepted(Vec<u8>),
    Prover,
    Verifier,
    /// The honest runner refused: NOT an acceptable rejection.
    Runner(String),
}

/// Prove a forged witness on a leaf built with `checks` (Plain, Interval).
fn run_forged(checks: PackedChecks, ks: &[u64], wit: PackedWitness, forge_outputs: bool) -> Verdict {
    let mut leaf = with_checks(checks, || build_bloom_packed_leaf_expose(P, Expose::Interval));
    if forge_outputs {
        // The Permute op emits the claimed reads (targets) directly.
        let (_, target) = wit.elements();
        let outs: Vec<Challenge> = target
            .iter()
            .map(|&(a, b, c)| Challenge::from_basis_coefficients_slice(&[a, b, c, Val::ZERO]).unwrap())
            .collect();
        leaf.circuit.update_permute_witnesses(&[wit.sigma.clone()]).unwrap();
        forge_permute_outputs(&mut leaf.circuit, 0, outs);
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        leaf.prove_witness(2, ks, &Openings::plain(), wit)
    }));
    match r {
        Ok(Ok(pr)) => Verdict::Accepted(pr.final_words),
        Ok(Err(PackedProveError::Prove(_))) | Err(_) => Verdict::Prover,
        Ok(Err(PackedProveError::Verify(_))) => Verdict::Verifier,
        Ok(Err(PackedProveError::Run(e))) => Verdict::Runner(e.chars().take(160).collect()),
    }
}

/// The attack against the leaf without `off`'s checks must certify a wrong
/// state; against the deployed leaf it must be rejected by the prover or the
/// verifier.
fn assert_attack(name: &str, off: PackedChecks, ks: &[u64], wit: PackedWitness, honest_final: &[u8]) {
    let control = run_forged(off, ks, wit.clone(), false);
    match &control {
        Verdict::Accepted(fin) => assert_ne!(fin, honest_final, "{name}: the control must certify a WRONG state"),
        other => panic!("{name}: positive control not accepted: {other:?}"),
    }
    let deployed = run_forged(PackedChecks::ALL, ks, wit, false);
    eprintln!("{name}: control certified a wrong state; deployed leaf: {deployed:?}");
    assert!(
        matches!(deployed, Verdict::Prover | Verdict::Verifier),
        "{name}: the deployed leaf must reject in the prover/verifier, got {deployed:?}"
    );
}

fn attack_input() -> (Vec<u8>, Vec<u64>, Vec<u8>) {
    let init = prior(&P);
    let ks = keys(7, 0x5000);
    let honest = expected(&P, &init, &ks);
    (init, ks, honest)
}

fn wv(x: [i64; PAIR_WITNESSES]) -> [Val; PAIR_WITNESSES] {
    x.map(|v| if v < 0 { Val::ZERO - Val::from_u64((-v) as u64) } else { Val::from_u64(v as u64) })
}

fn honest_gap(s: &Seen) -> (i64, i64) {
    let d = s.pidx as i64 - s.ts as i64;
    (d & 0xFF, d >> 8)
}

/// A1 (suppress, negative `L`): at an active pair whose bit is 0, claim
/// `c = 1` with `H = H'`, `L = L' − e`; the insert is dropped. Control: the
/// `L ≥ 0` lookup removed.
#[test]
fn attack_suppress_negative_l() {
    let (init, ks, honest) = attack_input();
    let (wit, s) = replay(&P, &init, &ks, &|s| {
        let e = 1i64 << s.i;
        ((s.act == 1) && (s.v >> s.i) & 1 == 0).then(|| {
            let (dlo, dhi) = honest_gap(s);
            let v = s.v as i64;
            Over { w: Some(wv([1, v >> (s.i + 1), (v & (e - 1)) - e, dlo, dhi])), ..Default::default() }
        })
    })
    .expect("an active pair with an unset bit");
    eprintln!("A1 at {s:?}");
    assert_attack("A1 suppress (L < 0)", PackedChecks { l_nonneg: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// A1' (suppress, non-byte `H`): `c = 1` at an unset bit with
/// `H = (v − L − e)·(2e)^{-1} mod p`. Control: the `H` lookup removed.
#[test]
fn attack_suppress_huge_h() {
    let (init, ks, honest) = attack_input();
    let (wit, _) = replay(&P, &init, &ks, &|s| {
        ((s.act == 1) && (s.v >> s.i) & 1 == 0).then(|| {
            let e = Val::from_u64(1 << s.i);
            let (dlo, dhi) = honest_gap(s);
            let l = Val::from_u64(s.v & ((1 << s.i) - 1));
            let h = (Val::from_u64(s.v) - l - e) * (e + e).inverse();
            let mut w = wv([1, 0, 0, dlo, dhi]);
            w[1] = h;
            w[2] = l;
            Over { w: Some(w), ..Default::default() }
        })
    })
    .unwrap();
    assert_attack("A1' suppress (H huge)", PackedChecks { h_range: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// A2 (carry via negative `L`): at a set bit claim `c = 0`, `H = H' + 1`,
/// `L = L' − e`; the write `v + e` clears the bit. Control: `L ≥ 0` removed.
#[test]
fn attack_carry_negative_l() {
    let (init, ks, honest) = attack_input();
    let (wit, _) = replay(&P, &init, &ks, &|s| {
        let e = 1i64 << s.i;
        ((s.act == 1) && (s.v >> s.i) & 1 == 1 && s.v + (1 << s.i) < 256).then(|| {
            let (dlo, dhi) = honest_gap(s);
            let v = s.v as i64;
            Over { w: Some(wv([0, (v >> (s.i + 1)) + 1, (v & (e - 1)) - e, dlo, dhi])), ..Default::default() }
        })
    })
    .expect("an active pair at a set bit");
    assert_attack("A2 carry (L < 0)", PackedChecks { l_nonneg: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// A2b: at a set bit claim `c = 0`, `H = H'`, `L = L' + e` (a byte, but not
/// `< e`). Control: the `L < e` lookup removed.
#[test]
fn attack_carry_l_plus_e() {
    let (init, ks, honest) = attack_input();
    let (wit, _) = replay(&P, &init, &ks, &|s| {
        let e = 1i64 << s.i;
        ((s.act == 1) && (s.v >> s.i) & 1 == 1 && s.v + (1 << s.i) < 256).then(|| {
            let (dlo, dhi) = honest_gap(s);
            let v = s.v as i64;
            Over { w: Some(wv([0, v >> (s.i + 1), (v & (e - 1)) + e, dlo, dhi])), ..Default::default() }
        })
    })
    .unwrap();
    assert_attack("A2b carry (L ≥ e)", PackedChecks { l_lt_e: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// A2c: at a set bit claim `c = 0`, `L = L'`, `H = (v − L)·(2e)^{-1} mod p`.
/// Control: the `H` lookup removed.
#[test]
fn attack_carry_huge_h() {
    let (init, ks, honest) = attack_input();
    let (wit, _) = replay(&P, &init, &ks, &|s| {
        ((s.act == 1) && (s.v >> s.i) & 1 == 1 && s.v + (1 << s.i) < 256).then(|| {
            let e = Val::from_u64(1 << s.i);
            let (dlo, dhi) = honest_gap(s);
            let l = Val::from_u64(s.v & ((1 << s.i) - 1));
            let mut w = wv([0, 0, 0, dlo, dhi]);
            w[1] = (Val::from_u64(s.v) - l) * (e + e).inverse();
            w[2] = l;
            Over { w: Some(w), ..Default::default() }
        })
    })
    .unwrap();
    assert_attack("A2c carry (H huge)", PackedChecks { h_range: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// Non-boolean `c`: at an unset bit with a set higher bit claim `c = 2`,
/// `H = H' − 1`; the write `v − e` borrows. Control: `c ∈ {0,1}` removed.
#[test]
fn attack_nonboolean_c() {
    let (init, ks, honest) = attack_input();
    let (wit, _) = replay(&P, &init, &ks, &|s| {
        let e = 1i64 << s.i;
        ((s.act == 1) && (s.v >> s.i) & 1 == 0 && (s.v >> (s.i + 1)) >= 1).then(|| {
            let (dlo, dhi) = honest_gap(s);
            let v = s.v as i64;
            Over { w: Some(wv([2, (v >> (s.i + 1)) - 1, v & (e - 1), dlo, dhi])), ..Default::default() }
        })
    })
    .expect("an active pair at an unset bit below a set bit");
    assert_attack("c = 2", PackedChecks { c_bool: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// A4 (self-read): an active pair at an unset bit reads its OWN write
/// `(u, v | e, τ_p)` (`ts = τ_p`, gap `−1`); the two cancel and the insert
/// is lost. Control: the gap lookups (`ts ≤ τ − 1`) removed.
#[test]
fn attack_self_read() {
    let (init, ks, honest) = attack_input();
    let (wit, _) = replay(&P, &init, &ks, &|s| {
        ((s.act == 1) && (s.v >> s.i) & 1 == 0).then(|| {
            let e = 1i64 << s.i;
            let v = (s.v as i64) | e;
            Over { w: Some(wv([1, v >> (s.i + 1), v & (e - 1), -1, 0])), self_read: true, ..Default::default() }
        })
    })
    .unwrap();
    assert_attack("A4 self-read", PackedChecks { ts_lt_tau: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// A8 (non-boolean position bits): at an active pair with `(i_0, i_1) =
/// (0, 1)` claim `(i_0, i_1) = (2, 0)` — the same `i`, but `e = 3·(1+15i_2)`
/// is not a power of two, so the OR writes the wrong bits. Control: the
/// position-bit BoolChecks removed.
#[test]
fn attack_nonboolean_position_bits() {
    let (init, ks, honest) = attack_input();
    let p = P;
    let (wit, _) = replay(&p, &init, &ks, &|s| {
        let e_forged = 3 * (1 + 15 * ((s.i >> 2) & 1));
        ((s.act == 1) && s.i & 3 == 2 && s.v + e_forged < 256 && (s.v >> s.i) & 1 == 0).then(|| {
            let rec = keys(7, 0x5000)[s.r];
            let d = record_digest(Some(rec))[s.j].as_canonical_u64();
            let (pos, hi) = (d & ((1 << p.log_w) - 1), d >> p.log_w);
            let i2 = (s.i >> 2) & 1;
            let ib = [Val::TWO, Val::ZERO, Val::from_u64(i2)];
            let dd = hi_max(p.log_w) - hi;
            let vals = slice_vals(&p, Val::from_u64(pos >> 3), ib, Val::from_u64(hi), Val::from_u64(dd), Val::from_u64(dd).try_inverse().unwrap_or(Val::ZERO));
            let e = 3 * (1 + 15 * i2);
            let (dlo, dhi) = honest_gap(s);
            let v = s.v as i64;
            let e_i = e as i64;
            Over {
                w: Some(wv([(v / e_i) % 2, v / (2 * e_i), v % e_i, dlo, dhi])),
                route: Some((vals, s.u, Val::from_u64(e))),
                ..Default::default()
            }
        })
    })
    .expect("an active pair with i mod 4 = 2");
    assert_attack("A8 i bits", PackedChecks { i_bool: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// A8b (word index out of range): route a slice-`j < k−1` pair to the same
/// word of slice `j + 1` (`q' = q + W/8`, `hi' = hi − 1`, so the digest limb
/// is unchanged). Control: the `q` range removed.
#[test]
fn attack_word_index_shift() {
    let (init, ks, honest) = attack_input();
    let p = P;
    let wps = p.words_per_slice() as u64;
    let (wit, _) = replay(&p, &init, &ks, &|s| {
        let rec = keys(7, 0x5000).get(s.r).copied()?;
        let d = record_digest(Some(rec))[s.j].as_canonical_u64();
        let (pos, hi) = (d & ((1 << p.log_w) - 1), d >> p.log_w);
        (s.act == 1 && s.j + 1 < p.k && hi >= 1 && (s.v >> s.i) & 1 == 0).then(|| {
            let ib = [s.i & 1, (s.i >> 1) & 1, (s.i >> 2) & 1].map(Val::from_u64);
            let (q2, hi2) = ((pos >> 3) + wps, hi - 1);
            let dd = hi_max(p.log_w) - hi2;
            let vals = slice_vals(&p, Val::from_u64(q2), ib, Val::from_u64(hi2), Val::from_u64(dd), Val::from_u64(dd).inverse());
            Over { route: Some((vals, s.u + wps, Val::from_u64(1 << s.i))), ..Default::default() }
        })
    })
    .unwrap();
    assert_attack("A8b q + W/8", PackedChecks { q_range: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// A7 (non-canonical split): a digest limb `x < 2^27 − 1` also splits as the
/// integer `x + p`, whose position is `(x + 1) mod W`. Control: the
/// canonicity checks (`hi ≤ HI_MAX`, the edge) removed. The batch leads with
/// a key that has such a limb.
#[test]
fn attack_noncanonical_split() {
    let p = P;
    let wps = p.words_per_slice() as u64;
    let init = prior(&p);
    // A limb below 2^31 − p whose honest and forged bits are both unset in
    // the prior (the lead record's pairs come first), so the forgery moves a
    // bit the state does not already hold.
    let bit = |j: usize, pos: u64| (init[j * wps as usize + (pos >> 3) as usize] >> (pos & 7)) & 1;
    let low = |key: u64| {
        (0..p.k).find(|&j| {
            let x = record_digest(Some(key))[j].as_canonical_u64();
            let m = (1u64 << p.log_w) - 1;
            x + p_u64() < 1 << 31 && bit(j, x & m) == 0 && bit(j, (x + p_u64()) & m) == 0
        })
    };
    let lead = keys(4000, 0xCA70).into_iter().find(|&k| low(k).is_some()).expect("a key with a limb below 2^31 − p");
    let mut ks = vec![lead];
    ks.extend(keys(6, 0x5000));
    let honest = expected(&p, &init, &ks);
    let (j0, ks2) = (low(lead).unwrap(), ks.clone());
    let picked = replay(&p, &init, &ks, &|s| {
        (s.r == 0 && s.j == j0).then(|| {
            let x = record_digest(Some(ks2[0]))[s.j].as_canonical_u64();
            let xp = x + p_u64();
            let (pos, hi) = (xp & ((1 << p.log_w) - 1), xp >> p.log_w);
            let ib = [pos & 1, (pos >> 1) & 1, (pos >> 2) & 1].map(Val::from_u64);
            let dd = Val::from_u64(hi_max(p.log_w)) - Val::from_u64(hi);
            // dinv = dd^{-1} satisfies the edge check (dd ≠ 0), so only the
            // `hi ≤ HI_MAX` lookups can object.
            let vals = slice_vals(&p, Val::from_u64(pos >> 3), ib, Val::from_u64(hi), dd, dd.inverse());
            Over { route: Some((vals, s.j as u64 * wps + (pos >> 3), Val::from_u64(1 << (pos & 7)))), ..Default::default() }
        })
    });
    let (wit, s) = picked.expect("the lead record's low limb");
    eprintln!("A7 at {s:?}");
    assert_attack("A7 x + p", PackedChecks { canon: false, ..PackedChecks::ALL }, &ks, wit, &honest);
}

/// `X^k` in the challenge field.
fn xpow(k: u64) -> Challenge {
    Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE, Val::ZERO, Val::ZERO]).unwrap().exp_u64(k)
}

/// A6 (extension-valued new-state byte): for a touched word `u = 3l` (the
/// first byte of limb `l`, `l mod 4 < 3`) claim `N'_u = N_u + δ·X` with
/// `δ = ft_u` and `ft'_u = 0`. The final read `u + N'·X + ft'·X²` is still
/// the true `(u, N_u, ft_u)`, but the packed commitment absorbs `δ·X` into
/// limb `l + 1`: `Com(S_t)` is the commitment of the byte state with word
/// `3(l + 1)` raised by `δ` — a different, well-formed state. Control: the
/// new-state byte pins removed.
#[test]
fn attack_extension_valued_new_byte() {
    let (init, ks, _honest) = attack_input();
    let mut wit = epoch_witness(&P, &init, &ks);
    let mw = P.m_words();
    let u = (0..mw)
        .step_by(3)
        .find(|&u| {
            let l = u / 3;
            let ft = wit.ft[u].as_canonical_u64();
            let nxt = 3 * (l + 1);
            ft >= 1 && l % 4 < 3 && nxt < mw && wit.final_words[nxt].as_canonical_u64() + ft < 256
        })
        .expect("a touched first-of-limb word");
    let delta = wit.ft[u];
    let nxt = 3 * (u / 3 + 1);
    // Private inputs (Plain): O (mw), N (mw), ft bytes (2 per word).
    let n_u = Challenge::from(wit.final_words[u]) + Challenge::from(delta) * xpow(1);
    wit.priv_patch = vec![(mw + u, n_u), (2 * mw + 2 * u, Challenge::ZERO), (2 * mw + 2 * u + 1, Challenge::ZERO)];
    let mut claim = wit.final_words.clone();
    claim[nxt] += delta;
    wit.claim_final = Some(claim.clone());
    let control = run_forged(PackedChecks { n_pin: false, ..PackedChecks::ALL }, &ks, wit.clone(), false);
    let claim_bytes: Vec<u8> = claim.iter().map(|x| x.as_canonical_u64() as u8).collect();
    let honest_commit = commit_packed(&P, &expected(&P, &init, &ks));
    assert_ne!(commit_packed(&P, &claim_bytes), honest_commit);
    assert!(matches!(control, Verdict::Accepted(_)), "A6 control: {control:?}");
    let deployed = run_forged(PackedChecks::ALL, &ks, wit, false);
    eprintln!("A6 N_u + δX (claims word {nxt} + {delta}): control accepted; deployed leaf: {deployed:?}");
    assert!(matches!(deployed, Verdict::Prover | Verdict::Verifier), "A6: {deployed:?}");
}

/// A11 (extension-valued final timestamp): two untouched words `u, u'` with
/// different bytes swap their final values, and each final timestamp is the
/// extension element `((u' − u)/W)·X²` (`X^4 = W`), which moves the final
/// read's ADDRESS coordinate: the reads `(u', O_{u'}, 0)` and `(u, O_u, 0)`
/// still consume the two init writes, while `Com(S_t)` commits the swapped
/// bytes. Control: the final-timestamp byte lookups removed.
#[test]
fn attack_final_timestamp_transplant() {
    let (init, ks, honest) = attack_input();
    let mut wit = epoch_witness(&P, &init, &ks);
    let mw = P.m_words();
    let untouched: Vec<usize> = (0..mw).filter(|&u| wit.ft[u] == Val::ZERO).collect();
    let (u, v) = untouched
        .iter()
        .flat_map(|&a| untouched.iter().map(move |&b| (a, b)))
        .find(|&(a, b)| a < b && init[a] != init[b])
        .expect("two untouched words with different bytes");
    let w = xpow(4); // X^4 = W (a base element)
    let shift = |from: usize, to: usize| -> Challenge {
        (Challenge::from_u64(to as u64) - Challenge::from_u64(from as u64)) * w.inverse() * xpow(2)
    };
    wit.final_words[u] = Val::from_u8(init[v]);
    wit.final_words[v] = Val::from_u8(init[u]);
    // Final read of u consumes v's init write and vice versa.
    wit.sigma[u] = v;
    wit.sigma[v] = u;
    wit.priv_patch = vec![
        (2 * mw + 2 * u, shift(u, v)),
        (2 * mw + 2 * u + 1, Challenge::ZERO),
        (2 * mw + 2 * v, shift(v, u)),
        (2 * mw + 2 * v + 1, Challenge::ZERO),
    ];
    let control = run_forged(PackedChecks { ft_range: false, ..PackedChecks::ALL }, &ks, wit.clone(), false);
    match &control {
        Verdict::Accepted(fin) => assert_ne!(fin, &honest, "A11 control: the swapped state is wrong"),
        other => panic!("A11 control not accepted: {other:?}"),
    }
    let deployed = run_forged(PackedChecks::ALL, &ks, wit, false);
    eprintln!("A11 ft transplant (swap words {u}, {v}): control accepted; deployed leaf: {deployed:?}");
    assert!(matches!(deployed, Verdict::Prover | Verdict::Verifier), "A11: {deployed:?}");
}

/// Memory-checking forgeries no permutation can match: (A3) a pair reads the
/// INITIAL value of a word an earlier pair of the batch wrote, (A5) a final
/// word differs from the last write (an untouched word flipped). The
/// Permute op is forged to emit the claimed elements; the PermuteBus
/// rejects (no check to remove: the permutation is the relation).
#[test]
fn attack_memory_checking_unmatched() {
    let (init, ks, _honest) = attack_input();
    // A5: flip an untouched final word.
    let mut wit = epoch_witness(&P, &init, &ks);
    let u = (0..P.m_words()).find(|&u| wit.ft[u] == Val::ZERO).unwrap();
    wit.final_words[u] += Val::ONE;
    assert!(wit.match_sigma() > 0);
    let v = run_forged(PackedChecks::ALL, &ks, wit, true);
    eprintln!("A5 tampered untouched final word: {v:?}");
    assert!(matches!(v, Verdict::Prover | Verdict::Verifier), "A5: {v:?}");
    // A3: the second access of a word reads the initial value (ts 0).
    let mut wit = epoch_witness(&P, &init, &ks);
    let mut seen = std::collections::HashSet::new();
    let pidx = (0..wit.pairs.len()).find(|&i| !seen.insert(wit.pairs[i].u)).expect("a word touched twice");
    let pr = &mut wit.pairs[pidx];
    let u = pr.u as usize;
    let v0 = init[u] as u64;
    let i = (0..8).find(|&i| Val::from_u64(1 << i) == pr.e).unwrap();
    let e = 1u64 << i;
    pr.w = [(v0 >> i) & 1, v0 >> (i + 1), v0 & (e - 1), pidx as u64 & 0xFF, pidx as u64 >> 8].map(Val::from_u64);
    pr.derive(pidx);
    let _ = wit.match_sigma();
    let v = run_forged(PackedChecks::ALL, &ks, wit, true);
    eprintln!("A3 stale read: {v:?}");
    assert!(matches!(v, Verdict::Prover | Verdict::Verifier), "A3: {v:?}");
}

/// A12 (documents the word size): with 16-bit words the split identity
/// wraps mod p — `(2·30,721 + 0)·2^15 ≡ 65,535 (mod p)` — so a 16-bit word
/// would admit a second split with the other bit value. With bytes the split
/// is below 2^16 and exact.
#[test]
fn sixteen_bit_words_would_wrap() {
    let e = Val::from_u64(1 << 15);
    let lhs = (Val::from_u64(2 * 30_721)) * e;
    assert_eq!(lhs, Val::from_u64(65_535));
    // 65,535 = (2·1 + 1)·2^15 + 32,767: bit 15 set; also ≡ (2·30,721 + 0)·2^15 + 0.
    assert_eq!(Val::from_u64(3 * (1 << 15) + 32_767), Val::from_u64(65_535) + Val::from_u64(65_536));
    // Bytes: (2·255 + 1)·128 + 127 < 2^16 ≪ p.
    assert!(511 * 128 + 127 < 1 << 16);
}

/// ConstAir regression: the word-address and timestamp constants are bound
/// by the VK. A leaf built with ONE timestamp constant `τ_p − 1` raised by
/// one (which would admit the self-read) or ONE word-address constant moved
/// has a different VK (the auditor pins the derived VK), and the pinned fork
/// binds constant values at all (`fork_binds_const`).
#[test]
fn const_values_are_bound() {
    assert!(crate::sketch::bind::probe::fork_binds_const(), "the pinned fork binds constant values");
    let deployed = build_bloom_packed_leaf_expose(P, Expose::Interval).prove_epoch_at(1, &packed_empty(&P), &[]);
    let vk = vk_pin_values(&deployed.output.0);
    // A circuit identical but for one constant: rebuild by hand through the
    // test hook (shift `τ_3 − 1` and, separately, the address of word 5).
    assert_eq!(build_bloom_packed_leaf_expose(P, Expose::Interval).vk_values(), vk, "structural VK = proof VK");
    for skew in [ConstSkew::Tau(3), ConstSkew::Word(5)] {
        let other = with_skew(skew, || build_bloom_packed_leaf_expose(P, Expose::Interval)).vk_values();
        assert_ne!(other, vk, "{skew:?}: a moved constant must change the VK");
    }
    // The timestamp constant is load-bearing: with `τ_p − 1` raised to `τ_p`
    // at the self-read pair, the self-read forgery proves (under that other
    // circuit, whose VK the auditor does not accept).
    let (init, ks, honest) = attack_input();
    let (wit, s) = replay(&P, &init, &ks, &|s| {
        ((s.act == 1) && (s.v >> s.i) & 1 == 0).then(|| {
            let e = 1i64 << s.i;
            let v = (s.v as i64) | e;
            // ts = τ_p: the gap against τ_p (not τ_p − 1) is 0.
            Over { w: Some(wv([1, v >> (s.i + 1), v & (e - 1), -1, 0])), self_read: true, ..Default::default() }
        })
    })
    .unwrap();
    let mut wit = wit;
    wit.pairs[s.pidx].w[3] = Val::ZERO; // gap 0 against the skewed constant
    let mut leaf = with_skew(ConstSkew::Tau(s.pidx), || build_bloom_packed_leaf_expose(P, Expose::Interval));
    let pr = leaf.prove_witness(2, &ks, &Openings::plain(), wit).expect("self-read under the skewed timestamp");
    assert_ne!(pr.final_words, honest, "the skewed circuit certified a dropped insert");
    assert_ne!(vk_pin_values(&pr.output.0), vk, "and its VK is not the deployed one");
}
