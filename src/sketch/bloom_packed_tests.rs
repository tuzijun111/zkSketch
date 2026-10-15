//! Tests of the packed-byte Bloom leaf ([`super`]): filter equality with
//! `bloom_omc`, honest round trips in every layout and commitment mode, the
//! hiding guards, and forgeries with positive controls.
//!
//! **Forgeries.** Each attack builds a forged epoch witness by replaying the
//! batch with one (record, slice) pair or one routing split overridden; the
//! rest of the replay is honest and consistent with the forgery, so the
//! honest witness RUNNER accepts the forged private inputs (it evaluates
//! connects, not range lookups or BoolChecks) and the forgery reaches the
//! prover. With the targeted check removed ([`PackedChecks`], a different
//! circuit) the forgery must prove, self-verify and commit to a WRONG final
//! state (positive control). Against the deployed circuit it must be rejected
//! by the prover or the verifier ([`PackedProveError::Prove`] /
//! [`PackedProveError::Verify`]), never by the runner
//! ([`PackedProveError::Run`] fails the test). Memory-checking forgeries
//! (stale read, tampered final word) cannot be matched by any permutation, so
//! their Permute op is forged to emit the claimed reads directly
//! ([`forge_permute_outputs`]): only the PermuteBus can object.

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
