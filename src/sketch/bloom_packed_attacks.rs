//! **G-sound, attack round 1: trace-level forgeries against the DEPLOYED
//! packed Bloom layout** (the leaf with the `Interval` statement and `Hiding`
//! commitments, family 7; the query under `Hiding`).
//!
//! A malicious prover may hand `prove_all_tables` ANY traces. Every forgery
//! here is turned into traces by a forger that the honest runner cannot
//! veto:
//!
//! * the private inputs are written by the forger (the leaf's input layout is
//!   rebuilt here, [`Wit::private_inputs`]); the commitments it claims are
//!   computed by a field-exact mirror of the circuit ([`Wit`]), so a forgery
//!   that satisfies every `connect` reaches the prover unchanged;
//! * a forgery that must break a `connect` goes through the split-wire
//!   pre-pass ([`split_conflicting_wires`]): the offending ALU / NPO output is
//!   re-pointed to a scratch slot of a CLONE of the circuit, while the prover
//!   data (built from the deployed circuit) still names the original witness
//!   id, so only the WitnessChecks LogUp bus can object;
//! * memory-checking forgeries that no permutation can match go through
//!   [`forge_permute_outputs`] (only the PermuteBus can object);
//! * constant forgeries patch one `Op::Const` value of the runner's clone
//!   (only the ConstAir binding can object);
//! * the query is forged through the decoder's test-only
//!   [`with_query_forger`] hook, which replaces the runner with the same
//!   tools; the decoder still proves with the prover data of the circuit it
//!   built.
//!
//! **Positive controls.** Each forgery against a circuit without the
//! targeted check ([`PackedChecks`], test-only; or, for a constant, the
//! circuit whose constant IS the forged value) must prove, verify, carry that
//! circuit's VK (not the deployed one), use NO split wire, and certify a WRONG
//! state (a final commitment that opens to a byte state other than the
//! native insert) or a WRONG answer. Against the deployed circuit the same
//! forgery must be rejected by the prover or the verifier; a refusal of the
//! runner or of the split pre-pass fails the test. The pipeline is
//! transparent on honest witnesses (`pipeline_is_transparent_on_honest_witnesses`).
//!
//! Forgeries whose check is a `connect` (the relation itself, no switch:
//! selector index, selected value, digest recomposition, `HI_MAX − hi = dd`,
//! the canonicity edge, the dummy rule) are attempted with split wires, and
//! their control is the forgery that the same goal admits once a SWITCHABLE
//! check is removed (stated per attack). Unbalanced memory-checking
//! forgeries (pure stale read, tampered final word) have no switch (the
//! permutation is the relation); their control is the balanced variant that
//! the timestamp or final-timestamp check stops.
//!
//! Run: `cargo test --release --lib -- bloom_packed::attacks::` (the
//! test-shape suite takes about 25 s; the two
//! `attacks_at_the_deployed_filter_shape_*` tests repeat every attack at
//! `k = 7, W = 2^14`, about 2 min and 1.5 GB together).

use super::*;

use std::cell::Cell;

use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, Op};

use crate::commitment::hiding::SaltSeed;
use crate::decode::bloom_packed::{
    QueryForger, bloom_packed_decode_vk_commit, read_exposed_query, selector_dims,
    try_prove_bloom_packed_query_commit, with_query_forger,
};
use crate::decode::{DecodeVk, verify_decode_proof};
use crate::recursion::recursive::expose_forest::{read_exposed_statement, vk_pin_values};
use crate::sketch::forge::{catch_msg, split_conflicting_wires};
use crate::sketch::forge_permute::forge_permute_outputs;

type C = Challenge;

/// The test shape (as `plain_vk_pins`' family shape, batch 8).
const P: BloomPackedParams = BloomPackedParams { k: 3, log_w: 7, batch: 8 };
/// A shape whose timestamps outnumber the word addresses (`L = 72 > M_w = 48`),
/// so some timestamp constants are pure timestamps.
const P24: BloomPackedParams = BloomPackedParams { k: 3, log_w: 7, batch: 24 };
/// A wider slice for the canonicity-edge forgery (a digest limb `< W − 1`
/// is found in about 2^17 keys).
const P12: BloomPackedParams = BloomPackedParams { k: 3, log_w: 12, batch: 8 };
/// The deployed filter shape with a short batch.
const PD: BloomPackedParams = BloomPackedParams { k: 7, log_w: 14, batch: 16 };
/// Batch index of every forged leaf (Interval statement).
const T: u64 = 2;
const PMOD: u64 = 2_013_265_921;

// ─── Small helpers ─────────────────────────────────────────────────────────

fn cu(x: u64) -> C {
    C::from_u64(x)
}

fn cv(x: Val) -> C {
    C::from(x)
}

/// A signed integer as a field element.
fn ci(x: i64) -> C {
    if x < 0 { C::ZERO - cu((-x) as u64) } else { cu(x as u64) }
}

fn basis(i: usize) -> C {
    let mut c = [Val::ZERO; 4];
    c[i] = Val::ONE;
    C::from_basis_coefficients_slice(&c).unwrap()
}

fn coeffs(x: C) -> [Val; 4] {
    let s = x.as_basis_coefficients_slice();
    [s[0], s[1], s[2], s[3]]
}

/// `x` as a small non-negative integer (base field, `< 2^32`), if it is one.
fn small(x: C) -> Option<u64> {
    let c = coeffs(x);
    (c[1..].iter().all(|z| *z == Val::ZERO) && c[0].as_canonical_u64() < 1 << 32).then(|| c[0].as_canonical_u64())
}

fn keys(n: usize, seed: u64) -> Vec<u64> {
    (0..n as u64).map(|i| (i ^ seed).wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17)).collect()
}

fn prior(p: &BloomPackedParams, n: usize) -> Vec<u8> {
    let mut w = packed_empty(p);
    packed_insert(&mut w, p, &keys(n, 7));
    w
}

fn expected(p: &BloomPackedParams, initial: &[u8], ks: &[u64]) -> Vec<u8> {
    let mut w = initial.to_vec();
    packed_insert(&mut w, p, ks);
    w
}

fn openings() -> Openings {
    Openings::for_leaf(&SaltSeed::for_tests(0xA77A_C4E5), FAMILY, T)
}

fn per_slice(p: &BloomPackedParams) -> usize {
    q_bytes(p.log_w) + 3 + 2 * hi_bytes(p.log_w) + 1
}

/// The split values of one used slice from field values; a value that does
/// not fit its bytes goes entirely into byte 0 (the forger's choice).
fn slice_vals(p: &BloomPackedParams, q: C, ib: [C; 3], hi: C, dd: C, dinv: C) -> Vec<C> {
    let (nq, nh) = (q_bytes(p.log_w), hi_bytes(p.log_w));
    let enc = |x: C, n: usize| -> Vec<C> {
        match small(x) {
            Some(v) if v < 1u64 << (8 * n) => (0..n).map(|i| cu((v >> (8 * i)) & 0xFF)).collect(),
            _ => {
                let mut out = vec![C::ZERO; n];
                out[0] = x;
                out
            }
        }
    };
    let mut out = enc(q, nq);
    out.extend(ib);
    out.extend(enc(hi, nh));
    out.extend(enc(dd, nh));
    out.push(dinv);
    out
}

/// The honest split values of a used slice for the digest limb `x` (the
/// canonical integer split, or any integer `x' ≡ x` the forger picks).
fn slice_for_int(p: &BloomPackedParams, x: u64) -> Vec<C> {
    let pos = x & ((1u64 << p.log_w) - 1);
    let hi = x >> p.log_w;
    let ib = [pos & 1, (pos >> 1) & 1, (pos >> 2) & 1].map(cu);
    let dd = cu(hi_max(p.log_w)) - cu(hi);
    let dinv = dd.try_inverse().unwrap_or(C::ZERO);
    slice_vals(p, cu(pos >> 3), ib, cu(hi), dd, dinv)
}

/// Split values of a whole record from its Poseidon2 digest (the layout of
/// [`split_count`]; `split_values` for an arbitrary record encoding).
fn split_for_digest(p: &BloomPackedParams, d: &[Val; 8]) -> Vec<C> {
    let mut out = Vec::with_capacity(split_count(p));
    for (t, &limb) in d.iter().enumerate() {
        let x = limb.as_canonical_u64();
        if t < p.k {
            out.extend(slice_for_int(p, x));
        } else {
            out.extend((0..4).map(|i| cu((x >> (8 * i)) & 0xFF)));
        }
    }
    out
}

fn digest_of(rec: [Val; 4]) -> [Val; 8] {
    MyHash::new(make_perm()).hash_iter(rec)
}

/// `[c, H, L, dlo, dhi]` of an honest split of the byte `v` at `e` (any small
/// `e`: `v = (2H + c)·e + L`, `L < e`) and an honest gap `gapb − ts`.
fn honest_pair(v: u64, e: u64, gapb: C, ts: C) -> [C; PAIR_WITNESSES] {
    let d = gapb - ts;
    let (dlo, dhi) = match small(d) {
        Some(x) if x < 1 << TS_BITS => (cu(x & 0xFF), cu(x >> 8)),
        _ => (d, C::ZERO),
    };
    [cu((v / e) % 2), cu(v / (2 * e)), cu(v % e), dlo, dhi]
}

/// Square root mod the BabyBear prime (Tonelli–Shanks), if one exists.
fn sqrt_mod(a: u64) -> Option<u64> {
    let pw = |b: u64, mut e: u64| -> u64 {
        let (mut r, mut b) = (1u64, b % PMOD);
        while e > 0 {
            if e & 1 == 1 {
                r = r * b % PMOD;
            }
            b = b * b % PMOD;
            e >>= 1;
        }
        r
    };
    let a = a % PMOD;
    if a == 0 {
        return Some(0);
    }
    if pw(a, (PMOD - 1) / 2) != 1 {
        return None;
    }
    let (q, s) = (15u64, 27u32);
    let z = (2..).find(|&z| pw(z, (PMOD - 1) / 2) == PMOD - 1).unwrap();
    let (mut m, mut c, mut t, mut r) = (s, pw(z, q), pw(a, q), pw(a, q.div_ceil(2)));
    while t != 1 {
        let (mut i, mut t2) = (0u32, t);
        while t2 != 1 {
            t2 = t2 * t2 % PMOD;
            i += 1;
        }
        let b = pw(c, 1u64 << (m - i - 1));
        m = i;
        c = b * b % PMOD;
        t = t * c % PMOD;
        r = r * b % PMOD;
    }
    Some(r)
}

/// Non-boolean position bits `(i0, i1, i2)` with `i0 + 2i1 + 4i2 = i − 8`
/// (so the word index can be `q + 1` with the digest limb unchanged) whose
/// `e = (1+i0)(1+3i1)(1+15i2)` is the power of two `2^s`: the pair then
/// writes bit `s` of word `q + 1`. Returns `(bits, s)`.
fn bits_for_next_word(i: u64) -> ([C; 3], u64) {
    let fv = |x: u64| Val::from_u64(x % PMOD);
    for t in 0..64u64 {
        for s in 0..8u64 {
            let k = Val::from_u64(1 << s) * (Val::ONE + Val::from_u64(15) * fv(t)).inverse();
            // i0 = A − 2 i1, A = i − 8 − 4t; (1 + A − 2 i1)(1 + 3 i1) = K:
            // 6 i1² − (3A + 1) i1 − (1 + A − K) = 0.
            let a = Val::from_u64(i) - Val::from_u64(8) - Val::from_u64(4) * fv(t);
            let b = Val::from_u64(3) * a + Val::ONE;
            let disc = b * b + Val::from_u64(24) * (Val::ONE + a - k);
            let Some(r) = sqrt_mod(disc.as_canonical_u64()) else { continue };
            let i1 = (b + Val::from_u64(r)) * Val::from_u64(12).inverse();
            let i0 = a - i1 - i1;
            let i2 = fv(t);
            let e = (Val::ONE + i0) * (Val::ONE + Val::from_u64(3) * i1) * (Val::ONE + Val::from_u64(15) * i2);
            assert_eq!(e, Val::from_u64(1 << s));
            assert_eq!(i0 + i1 + i1 + Val::from_u64(4) * i2 + Val::from_u64(8), Val::from_u64(i));
            return ([cv(i0), cv(i1), cv(i2)], s);
        }
    }
    panic!("no non-boolean position bits for i = {i}");
}

// ─── The forger's witness: a field-exact mirror of the leaf ─────────────────

/// The constants the circuit uses for word addresses and timestamps (a
/// constant forgery patches them; [`Consts::patched`]).
#[derive(Clone)]
struct Consts {
    /// Word address constant of word `u` (init and final elements).
    addr: Vec<C>,
    /// Write timestamp `τ_p` of pair `p`.
    tau: Vec<C>,
    /// Gap base `τ_p − 1` of pair `p`.
    gapb: Vec<C>,
}

impl Consts {
    fn new(p: &BloomPackedParams) -> Self {
        Consts {
            addr: (0..p.m_words()).map(|u| cu(u as u64)).collect(),
            tau: (0..p.pairs()).map(|q| cu(q as u64 + 1)).collect(),
            gapb: (0..p.pairs()).map(|q| cu(q as u64)).collect(),
        }
    }

    /// Every use of the pooled constant `old` replaced by `new`.
    fn patched(&self, old: u64, new: u64) -> Self {
        let f = |v: &Vec<C>| v.iter().map(|&x| if x == cu(old) { cu(new) } else { x }).collect();
        Consts { addr: f(&self.addr), tau: f(&self.tau), gapb: f(&self.gapb) }
    }
}

/// Every private input of one epoch but the salts, as the circuit consumes
/// them (field values: a forger may plant anything).
#[derive(Clone)]
struct Wit {
    p: BloomPackedParams,
    o: Vec<C>,
    n: Vec<C>,
    ft: Vec<[C; 2]>,
    recs: Vec<[C; RECORD_WITNESSES]>,
    split: Vec<Vec<C>>,
    pairs: Vec<[C; PAIR_WITNESSES]>,
}

type Elem = [u32; 4];

fn key_of(x: C) -> Elem {
    coeffs(x).map(|c| c.as_canonical_u64() as u32)
}

impl Wit {
    /// The honest witness (the leaf's own `epoch_witness`).
    fn honest(p: &BloomPackedParams, initial: &[u8], ks: &[u64]) -> Wit {
        let w = epoch_witness(p, initial, ks);
        let ftb = |x: Val| -> [C; 2] {
            let v = x.as_canonical_u64();
            [cu(v & 0xFF), cu(v >> 8)]
        };
        Wit {
            p: *p,
            o: w.initial.iter().map(|&x| cv(x)).collect(),
            n: w.final_words.iter().map(|&x| cv(x)).collect(),
            ft: w.ft.iter().map(|&x| ftb(x)).collect(),
            recs: w.recs.iter().map(|r| record_witness(*r).map(cv)).collect(),
            split: w.split.iter().map(|s| s.iter().map(|&x| cv(x)).collect()).collect(),
            pairs: w.pairs.iter().map(|pr| pr.w.map(cv)).collect(),
        }
    }

    /// `(q, [i0, i1, i2])` of slice `j` of record `r`.
    fn slice(&self, r: usize, j: usize) -> (C, [C; 3]) {
        let nq = q_bytes(self.p.log_w);
        let per = per_slice(&self.p);
        let s = &self.split[r][j * per..(j + 1) * per];
        let mut q = s[nq - 1];
        for i in (0..nq - 1).rev() {
            q = q * cu(256) + s[i];
        }
        (q, [s[nq], s[nq + 1], s[nq + 2]])
    }

    /// Replace the split values of slice `j` of record `r`.
    fn set_slice(&mut self, r: usize, j: usize, vals: &[C]) {
        let per = per_slice(&self.p);
        assert_eq!(vals.len(), per);
        self.split[r][j * per..(j + 1) * per].copy_from_slice(vals);
    }

    /// `(u, e, act)` of pair `(r, j)` as the circuit computes them.
    fn route(&self, r: usize, j: usize) -> (C, C, C) {
        let (q, ib) = self.slice(r, j);
        let u = if j == 0 { q } else { q + cu((j * self.p.words_per_slice()) as u64) };
        let e = (ib[0] + C::ONE) * (ib[1] * cu(3) + C::ONE) * (ib[2] * cu(15) + C::ONE);
        (u, e, self.recs[r][8])
    }

    /// `(u, v, ts, cur)` of pair `pidx` as the circuit computes them.
    fn pair_vals(&self, pidx: usize, k: &Consts) -> (C, C, C, C) {
        let (r, j) = (pidx / self.p.k, pidx % self.p.k);
        let (u, e, act) = self.route(r, j);
        let [c, h, l, dlo, dhi] = self.pairs[pidx];
        let v = (h * cu(2) + c) * e + l;
        let a = (C::ZERO - act) * c + act;
        let cur = a * e + v;
        let ts = k.gapb[pidx] - (dhi * cu(256) + dlo);
        (u, v, ts, cur)
    }

    /// The record Challenge of slot `r`: `[k0, k1, k2, k3 + 2^16·act]` (ALU).
    fn rec(&self, r: usize) -> C {
        let b = &self.recs[r];
        let limb = |j: usize| b[2 * j + 1] * cu(256) + b[2 * j];
        let l3 = b[8] * cu(ACT_SHIFT) + limb(3);
        limb(0) + limb(1) * basis(1) + limb(2) * basis(2) + l3 * basis(3)
    }

    /// `(input, target)` of the Permute op (writes, reads), in circuit order.
    fn elements(&self, k: &Consts) -> (Vec<C>, Vec<C>) {
        let (x, x2) = (basis(1), basis(2));
        let mw = self.p.m_words();
        let mut input: Vec<C> = (0..mw).map(|u| self.o[u] * x + k.addr[u]).collect();
        let mut target: Vec<C> = (0..mw)
            .map(|u| {
                let ft = self.ft[u][1] * cu(256) + self.ft[u][0];
                ft * x2 + (self.n[u] * x + k.addr[u])
            })
            .collect();
        for pidx in 0..self.p.pairs() {
            let (u, v, ts, cur) = self.pair_vals(pidx, k);
            target.push(ts * x2 + (v * x + u));
            input.push(k.tau[pidx] * x2 + (cur * x + u));
        }
        (input, target)
    }

    /// σ with `input[σ[i]] == target[i]` where possible, and the number of
    /// targets no write matches.
    fn sigma(&self, k: &Consts) -> (Vec<usize>, usize) {
        let (input, target) = self.elements(k);
        let mut buckets: HashMap<Elem, Vec<usize>> = HashMap::new();
        for (i, e) in input.iter().enumerate().rev() {
            buckets.entry(key_of(*e)).or_default().push(i);
        }
        let mut sigma: Vec<Option<usize>> =
            target.iter().map(|t| buckets.get_mut(&key_of(*t)).and_then(|v| v.pop())).collect();
        let unmatched = sigma.iter().filter(|s| s.is_none()).count();
        let mut left: Vec<usize> = buckets.into_values().flatten().collect();
        for s in sigma.iter_mut() {
            if s.is_none() {
                *s = left.pop();
            }
        }
        (sigma.into_iter().map(|s| s.unwrap()).collect(), unmatched)
    }

    /// The packed state Challenges the circuit hashes (3 bytes per limb, 4
    /// limbs per Challenge, ALU arithmetic: an extension-valued byte spills
    /// into the next coefficient).
    fn packed(&self, words: &[C]) -> Vec<C> {
        let limbs: Vec<C> = (0..self.p.n_limbs())
            .map(|l| {
                let g = |s: usize| words.get(3 * l + s).copied();
                match (g(0), g(1), g(2)) {
                    (None, _, _) => C::ZERO,
                    (Some(w0), None, _) => w0,
                    (Some(w0), Some(w1), None) => w1 * cu(256) + w0,
                    (Some(w0), Some(w1), Some(w2)) => w2 * cu(65536) + (w1 * cu(256) + w0),
                }
            })
            .collect();
        limbs.chunks(4).map(|ch| (0..4).map(|i| ch[i] * basis(i)).sum()).collect()
    }

    fn flat(chs: &[C]) -> Vec<Val> {
        chs.iter().flat_map(|&c| coeffs(c)).collect()
    }

    /// The public inputs this witness claims: `Com(S_{t-1})`, `Com(S_t)`,
    /// `Com(B_t)` under family `fam` (salted, Hiding) and `t`.
    fn public_inputs(&self, fam: CommitFamily, open: &Openings) -> Vec<C> {
        let com = |kind, salt: &SaltBb, flat: &[Val]| pack_commit(&hiding::commit_flat_bb(CommitMode::Hiding, kind, fam, salt, flat));
        let recs: Vec<C> = (0..self.p.batch).map(|r| self.rec(r)).collect();
        let mut v = Vec::with_capacity(7);
        v.extend(com(CommitKind::State, &open.init, &Self::flat(&self.packed(&self.o))));
        v.extend(com(CommitKind::State, &open.final_, &Self::flat(&self.packed(&self.n))));
        v.extend(com(CommitKind::Batch, &open.batch, &Self::flat(&recs)));
        v.push(cu(T));
        v
    }

    /// Every private input in allocation order (`Hiding`: the salts first).
    fn private_inputs(&self, open: &Openings) -> Vec<C> {
        let mut v = open.private_inputs();
        v.extend(&self.o);
        v.extend(&self.n);
        for f in &self.ft {
            v.extend(f);
        }
        for r in &self.recs {
            v.extend(r);
        }
        for s in &self.split {
            v.extend(s);
        }
        for pr in &self.pairs {
            v.extend(pr);
        }
        v
    }

    /// The certified state as bytes, when every final word is a byte.
    fn final_bytes(&self) -> Option<Vec<u8>> {
        self.n.iter().map(|&x| small(x).and_then(|v| u8::try_from(v).ok())).collect()
    }
}

/// The honest view of a pair during a replay (the memory before its access).
#[derive(Copy, Clone, Debug)]
struct Seen {
    pidx: usize,
    r: usize,
    j: usize,
    u: usize,
    /// `log2 e` when `e` is a power of two.
    i: Option<u64>,
    act: u64,
    /// Current value and timestamp of the word (small integers).
    v: u64,
    ts: u64,
}

/// How a forger overrides the first pair `pick` selects.
#[derive(Clone, Default)]
struct Over {
    /// `[c, H, L, dlo, dhi]` (unset: honest for the memory at the routed word).
    w: Option<[C; PAIR_WITNESSES]>,
    /// The pair reads its OWN write; the memory keeps the previous write.
    self_read: bool,
    /// New split values of the pair's slice (a routing forgery).
    slice: Option<Vec<C>>,
}

/// Replay one epoch from `wit` (whose `o`, `recs`, `split` are taken as
/// given) under the constants `k`, letting `pick` override the first pair it
/// returns `Some` for; every other pair is honest for the memory it sees.
/// Sets `pairs`, `n`, `ft`. Returns the picked pair (after re-routing).
fn replay(mut wit: Wit, k: &Consts, pick: &mut dyn FnMut(&Seen, &Wit) -> Option<Over>) -> (Wit, Option<Seen>) {
    let p = wit.p;
    let mw = p.m_words();
    let mut words: Vec<C> = wit.o.clone();
    let mut last: Vec<C> = vec![C::ZERO; mw];
    let mut picked = None;
    for pidx in 0..p.pairs() {
        let (r, j) = (pidx / p.k, pidx % p.k);
        let seen_at = |wit: &Wit, words: &[C], last: &[C]| -> Seen {
            let (u, e, act) = wit.route(r, j);
            let u = small(u).expect("routed address") as usize;
            assert!(u < mw, "routed address {u} outside the state");
            let e = small(e);
            Seen {
                pidx,
                r,
                j,
                u,
                i: e.filter(|e| e.is_power_of_two() && *e <= 128).map(|e| e.trailing_zeros() as u64),
                act: small(act).unwrap_or(u64::MAX),
                v: small(words[u]).unwrap_or(u64::MAX),
                ts: small(last[u]).unwrap_or(u64::MAX),
            }
        };
        let mut seen = seen_at(&wit, &words, &last);
        let over = if picked.is_none() { pick(&seen, &wit) } else { None };
        if let Some(sv) = over.as_ref().and_then(|o| o.slice.as_ref()) {
            wit.set_slice(r, j, sv);
            seen = seen_at(&wit, &words, &last);
        }
        let (_, e, _) = wit.route(r, j);
        let w = match over.as_ref().and_then(|o| o.w) {
            Some(w) => w,
            None => {
                let e = small(e).expect("a small e for an honest split");
                assert!(seen.v < 256, "replay met a non-byte word at pair {pidx}");
                honest_pair(seen.v, e, k.gapb[pidx], last[seen.u])
            }
        };
        wit.pairs[pidx] = w;
        let (_, _, _, cur) = wit.pair_vals(pidx, k);
        if !over.as_ref().is_some_and(|o| o.self_read) {
            words[seen.u] = cur;
            last[seen.u] = k.tau[pidx];
        }
        if over.is_some() {
            picked = Some(seen);
        }
    }
    wit.n = words;
    wit.ft = last
        .iter()
        .map(|&t| match small(t) {
            Some(v) if v < 1 << TS_BITS => [cu(v & 0xFF), cu(v >> 8)],
            _ => [t, C::ZERO],
        })
        .collect();
    (wit, picked)
}

// ─── Leaf rigs, attempts and verdicts ───────────────────────────────────────

/// A leaf circuit and the prover data built from it.
struct Rig {
    circuit: Circuit<C>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    pd: Rc<CircuitProverData<ConfigWithFriParams>>,
    vk: Vec<C>,
}

/// The deployed leaf (`checks = ALL`) or a control leaf (one check off),
/// `Interval` + `Hiding`.
fn rig(p: &BloomPackedParams, checks: PackedChecks) -> Rig {
    let leaf = with_checks(checks, || build_bloom_packed_leaf_commit(*p, Expose::Interval, CommitMode::Hiding));
    Rig { vk: leaf.vk_values(), circuit: leaf.circuit, prover: leaf.prover, pd: leaf.circuit_prover_data }
}

/// Prover data of an arbitrary leaf circuit (the build tail of
/// [`build_bloom_packed_leaf_commit`]): the control of a constant forgery is
/// the circuit whose constant is the forged value.
fn rig_from_circuit(circuit: Circuit<C>) -> Rig {
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
        permute_preprocessor::<Val>(),
        range_preprocessor::<Val>(),
        expose_preprocessor::<Val>(),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
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
        .expect("airs of a patched leaf");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let pd = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(cfg);
    prover.register_recompose_table::<4>(cfg.d() != 4);
    prover.register_permute_table::<4>();
    prover.register_range_table::<4>();
    prover.register_expose_table::<4>();
    let vk = crate::recursion::recursive::expose_forest::common_vk_pin_values(&pd.prover_data.common);
    Rig { circuit, prover, pd: Rc::new(pd), vk }
}

/// Replace the value of the (unique) constant `old` by `new`; panics unless
/// exactly one `Op::Const` holds `old`.
fn patch_const(c: &mut Circuit<C>, old: C, new: C) {
    let mut n = 0;
    for op in c.ops.iter_mut() {
        if let Op::Const { val, .. } = op
            && *val == old
        {
            *val = new;
            n += 1;
        }
    }
    assert_eq!(n, 1, "constant {old:?}: {n} Const ops");
}

/// How a forged witness becomes traces.
#[derive(Clone)]
struct Attempt {
    wit: Wit,
    k: Consts,
    /// The family the claimed commitments are computed under.
    fam: CommitFamily,
    /// The Permute op emits the claimed reads directly.
    forge_outputs: bool,
    /// Split the wires the runner would refuse.
    split: bool,
    /// `Op::Const` values patched in the runner's clone.
    consts: Vec<(C, C)>,
}

impl Attempt {
    fn new(wit: Wit) -> Self {
        let k = Consts::new(&wit.p);
        Attempt { wit, k, fam: FAMILY, forge_outputs: false, split: false, consts: Vec::new() }
    }
    fn split(mut self) -> Self {
        self.split = true;
        self
    }
    fn outputs(mut self) -> Self {
        self.forge_outputs = true;
        self
    }
}

#[derive(Debug)]
#[allow(dead_code)] // the payloads are read through `Debug` in failure messages
enum Verdict {
    /// Proved and verified: the exposed statement, the proof's VK, splits.
    Accepted { st: statement::Statement<Val>, vk: Vec<C>, splits: usize },
    /// The prover or the verifier rejected the traces.
    Rejected(String),
    /// The runner or the split pre-pass refused: NOT a trace-level rejection.
    Runner(String),
}

fn short(s: &str) -> String {
    s.chars().take(150).collect()
}

/// Turn `a` into traces for `rig` and prove + verify.
fn attempt(rig: &Rig, a: &Attempt) -> Verdict {
    let open = openings();
    let (sigma, _) = a.wit.sigma(&a.k);
    let mut c = rig.circuit.clone();
    for &(old, new) in &a.consts {
        patch_const(&mut c, old, new);
    }
    if let Err(e) = c.update_permute_witnesses(&[sigma]) {
        return Verdict::Runner(format!("sigma: {e:?}"));
    }
    if a.forge_outputs {
        let (_, target) = a.wit.elements(&a.k);
        forge_permute_outputs(&mut c, 0, target);
    }
    let public = a.wit.public_inputs(a.fam, &open);
    let private = a.wit.private_inputs(&open);
    let mut splits = 0;
    if a.split {
        match catch_msg(|| split_conflicting_wires(&mut c, &public, &private)) {
            Ok(Ok(n)) => splits = n,
            Ok(Err(e)) => return Verdict::Runner(format!("split pre-pass: {e}")),
            Err(p) => return Verdict::Runner(format!("split pre-pass panicked: {p}")),
        }
    }
    let traces = match catch_msg(|| -> Result<Traces<C>, String> {
        let mut r = c.runner();
        r.set_public_inputs(&public).map_err(|e| format!("{e:?}"))?;
        r.set_private_inputs(&private).map_err(|e| format!("{e:?}"))?;
        r.run().map_err(|e| format!("{e:?}"))
    }) {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Verdict::Runner(short(&e)),
        Err(p) => return Verdict::Runner(format!("runner panicked: {}", short(&p))),
    };
    let res = catch_msg(|| -> Result<_, String> {
        let proof = rig.prover.prove_all_tables(&traces, &rig.pd).map_err(|e| format!("prove: {e:?}"))?;
        rig.prover.verify_all_tables(&proof).map_err(|e| format!("verify: {e:?}"))?;
        Ok(proof)
    });
    match res {
        Ok(Ok(proof)) => Verdict::Accepted { st: read_exposed_statement(&proof), vk: vk_pin_values(&proof), splits },
        Ok(Err(e)) => Verdict::Rejected(format!("{} [split wires: {splits}]", short(&e))),
        Err(p) => Verdict::Rejected(format!("prover panicked: {} [split wires: {splits}]", short(&p))),
    }
}

/// What the honest prover would certify for `(initial, ks)` (the deployed
/// statement the forgery competes with).
struct Honest {
    init: [Val; 8],
    final_: [Val; 8],
    final_words: Vec<u8>,
    batch_digest: Vec<Val>,
}

fn honest_statement(p: &BloomPackedParams, initial: &[u8], ks: &[u64]) -> Honest {
    let open = openings();
    let fin = expected(p, initial, ks);
    let batch = packed_batch_commit_with(p.batch, ks, CommitMode::Hiding, &open.batch);
    Honest {
        init: commit_packed_with(p, initial, CommitMode::Hiding, &open.init),
        final_: commit_packed_with(p, &fin, CommitMode::Hiding, &open.final_),
        final_words: fin,
        batch_digest: statement::leaf_digest::<Val>(&statement::hash_bb, 4, T, &batch),
    }
}

/// A control must be accepted under ITS OWN circuit's VK (not the deployed
/// one), without a split wire, with the honest `Com(S_{t-1})`; returns the
/// exposed statement.
fn expect_control(name: &str, v: Verdict, rig: &Rig, deployed_vk: &[C], h: &Honest) -> statement::Statement<Val> {
    match v {
        Verdict::Accepted { st, vk, splits } => {
            assert_eq!(splits, 0, "{name}: a control must not need a split wire");
            assert_eq!(vk, rig.vk, "{name}: the control proof carries the control circuit's VK");
            assert_ne!(vk, deployed_vk, "{name}: the control circuit differs from the deployed one");
            assert_eq!(st.init, h.init.to_vec(), "{name}: the forgery starts from the honest Com(S_(t-1))");
            let iv = st.interval.as_ref().expect("Interval statement");
            assert_eq!((iv.lo, iv.hi), (Val::from_u64(T), Val::from_u64(T)), "{name}: batch index");
            st
        }
        other => panic!("{name}: POSITIVE CONTROL not accepted: {other:?}"),
    }
}

/// The control certifies the byte state `claim` (≠ the native insert) under
/// the honest batch commitment.
fn expect_wrong_state(name: &str, st: &statement::Statement<Val>, p: &BloomPackedParams, claim: &[u8], h: &Honest) {
    let open = openings();
    assert_ne!(claim, &h.final_words[..], "{name}: the claimed state must be WRONG");
    assert_eq!(st.final_, commit_packed_with(p, claim, CommitMode::Hiding, &open.final_).to_vec(), "{name}: Com(S_t) opens to the claim");
    assert_ne!(st.final_, h.final_.to_vec(), "{name}: not the honest Com(S_t)");
    assert_eq!(st.interval.as_ref().unwrap().digest, h.batch_digest, "{name}: the honest Com(B_t)");
}

/// The deployed leaf must reject in the prover or verifier.
fn expect_rejected(name: &str, v: Verdict) -> String {
    match v {
        Verdict::Rejected(e) => e,
        other => panic!("{name}: the DEPLOYED circuit must reject in the prover/verifier, got {other:?}"),
    }
}

/// One full duel: control (`off`, no split) certifies a wrong state, the
/// deployed leaf rejects (with split wires when `split_deployed`). Returns
/// the rejection message.
#[allow(clippy::too_many_arguments)]
fn duel(
    name: &str,
    p: &BloomPackedParams,
    deployed: &Rig,
    off: PackedChecks,
    a: &Attempt,
    initial: &[u8],
    ks: &[u64],
    split_deployed: bool,
) -> String {
    let h = honest_statement(p, initial, ks);
    let control = rig(p, off);
    let st = expect_control(name, attempt(&control, a), &control, &deployed.vk, &h);
    let claim = a.wit.final_bytes().unwrap_or_else(|| panic!("{name}: the claimed final words are bytes"));
    expect_wrong_state(name, &st, p, &claim, &h);
    let mut d = a.clone();
    d.split = split_deployed;
    let why = expect_rejected(name, attempt(deployed, &d));
    eprintln!("ATTACK {name}: control (without {}) ACCEPTED a wrong state; deployed REJECTED: {why}", off_name(off));
    why
}

fn off_name(c: PackedChecks) -> String {
    let s = format!("{c:?}");
    s.split(", ")
        .filter(|f| f.contains("false"))
        .map(|f| f.split(':').next().unwrap().trim_start_matches("PackedChecks { ").to_string())
        .collect::<Vec<_>>()
        .join("+")
}

fn without(name: &str) -> PackedChecks {
    PackedChecks::without(name)
}

// ─── Leaf forgeries ─────────────────────────────────────────────────────────

/// Per word, the pairs that touch it (honest routing of `wit`).
fn accesses(wit: &Wit) -> Vec<Vec<usize>> {
    let p = wit.p;
    let mut acc = vec![Vec::new(); p.m_words()];
    for pidx in 0..p.pairs() {
        let (u, _, _) = wit.route(pidx / p.k, pidx % p.k);
        acc[small(u).unwrap() as usize].push(pidx);
    }
    acc
}

/// The honest gap bytes of a pair that reads the current memory.
fn gap(s: &Seen) -> (C, C) {
    let d = s.pidx as u64 - s.ts;
    (cu(d & 0xFF), cu(d >> 8))
}

/// Replay with ONE pair's `[c, H, L, dlo, dhi]` forged: the first active
/// pair that is the LAST access of its word (so the forged write is the
/// final word) and for which `pick` returns witnesses.
fn split_forgery(p: &BloomPackedParams, init: &[u8], ks: &[u64], pick: &dyn Fn(&Seen, u64) -> Option<[C; PAIR_WITNESSES]>) -> (Wit, Seen) {
    let w0 = Wit::honest(p, init, ks);
    let acc = accesses(&w0);
    let (wit, s) = replay(w0, &Consts::new(p), &mut |s, _| {
        let i = s.i?;
        if s.act != 1 || acc[s.u].last() != Some(&s.pidx) {
            return None;
        }
        pick(s, i).map(|w| Over { w: Some(w), ..Default::default() })
    });
    (wit, s.expect("a pair to attack"))
}

/// A1 / A2 family and `c = 2`: the split-at-bit forgeries (all leaf pair
/// checks D2–D5). Each returns the rejection messages.
fn split_attacks(p: &BloomPackedParams, init: &[u8], ks: &[u64], deployed: &Rig) {
    type Pick = Box<dyn Fn(&Seen, u64) -> Option<[C; PAIR_WITNESSES]>>;
    let cases: Vec<(&str, &str, Pick)> = vec![
        // A1: suppress at an unset bit, `c = 1`, `L = L' − e` (negative).
        ("A1 suppress, L = L'-e < 0", "l_nonneg", Box::new(|s: &Seen, i: u64| {
            let (e, v) = (1u64 << i, s.v);
            ((v >> i) & 1 == 0).then(|| {
                let (dlo, dhi) = gap(s);
                [C::ONE, cu(v >> (i + 1)), ci((v & (e - 1)) as i64 - e as i64), dlo, dhi]
            })
        })),
        // A2b (plan): suppress at an unset bit, `c = 1`, `H = H' − 1`, `L = L' + e`.
        ("A2b suppress, H = H'-1, L = L'+e", "l_lt_e", Box::new(|s: &Seen, i: u64| {
            let (e, v) = (1u64 << i, s.v);
            ((v >> i) & 1 == 0 && (v >> (i + 1)) >= 1 && (v & (e - 1)) + e < 256).then(|| {
                let (dlo, dhi) = gap(s);
                [C::ONE, cu((v >> (i + 1)) - 1), cu((v & (e - 1)) + e), dlo, dhi]
            })
        })),
        // A2c (plan) / A1': suppress, `c = 1`, `H = (v − L − e)·(2e)^{-1}`.
        ("A2c suppress, H = (v-L-e)/(2e)", "h_range", Box::new(|s: &Seen, i: u64| {
            let (e, v) = (1u64 << i, s.v);
            ((v >> i) & 1 == 0).then(|| {
                let (dlo, dhi) = gap(s);
                let l = cu(v & (e - 1));
                let h = (cu(v) - l - cu(e)) * (cu(2 * e)).inverse();
                [C::ONE, h, l, dlo, dhi]
            })
        })),
        // A2: carry at a set bit, `c = 0`, `H = H' + 1`, `L = L' − e`.
        ("A2 carry, L = L'-e < 0", "l_nonneg", Box::new(|s: &Seen, i: u64| {
            let (e, v) = (1u64 << i, s.v);
            ((v >> i) & 1 == 1 && v + e < 256).then(|| {
                let (dlo, dhi) = gap(s);
                [C::ZERO, cu((v >> (i + 1)) + 1), ci((v & (e - 1)) as i64 - e as i64), dlo, dhi]
            })
        })),
        // A2': carry at a set bit, `c = 0`, `H = H'`, `L = L' + e`.
        ("A2' carry, L = L'+e", "l_lt_e", Box::new(|s: &Seen, i: u64| {
            let (e, v) = (1u64 << i, s.v);
            ((v >> i) & 1 == 1 && v + e < 256).then(|| {
                let (dlo, dhi) = gap(s);
                [C::ZERO, cu(v >> (i + 1)), cu((v & (e - 1)) + e), dlo, dhi]
            })
        })),
        // A2c': carry at a set bit, `c = 0`, `H = (v − L)·(2e)^{-1}`.
        ("A2c' carry, H = (v-L)/(2e)", "h_range", Box::new(|s: &Seen, i: u64| {
            let (e, v) = (1u64 << i, s.v);
            ((v >> i) & 1 == 1 && v + e < 256).then(|| {
                let (dlo, dhi) = gap(s);
                let l = cu(v & (e - 1));
                [C::ZERO, (cu(v) - l) * cu(2 * e).inverse(), l, dlo, dhi]
            })
        })),
        // c = 2 at an unset bit below a set bit: `H = H' − 1`; the write borrows.
        ("c = 2 borrow", "c_bool", Box::new(|s: &Seen, i: u64| {
            let (e, v) = (1u64 << i, s.v);
            ((v >> i) & 1 == 0 && (v >> (i + 1)) >= 1).then(|| {
                let (dlo, dhi) = gap(s);
                [cu(2), cu((v >> (i + 1)) - 1), cu(v & (e - 1)), dlo, dhi]
            })
        })),
    ];
    for (name, off, pick) in cases {
        let (wit, s) = split_forgery(p, init, ks, &*pick);
        eprintln!("{name}: pair {} (record {}, slice {}, word {}, bit {:?}, v = {})", s.pidx, s.r, s.j, s.u, s.i, s.v);
        duel(name, p, deployed, without(off), &Attempt::new(wit), init, ks, false);
    }
}

/// A4 self-read: an active pair at an unset bit (the last access of its
/// word) reads its OWN write `(u, v | e, τ_p)` (gap −1); the insert is lost.
fn self_read_forgery(p: &BloomPackedParams, init: &[u8], ks: &[u64], k: &Consts, only: Option<usize>) -> Option<(Wit, Seen)> {
    let w0 = Wit::honest(p, init, ks);
    let acc = accesses(&w0);
    let (wit, s) = replay(w0, k, &mut |s, _| {
        let i = s.i?;
        if s.act != 1 || (s.v >> i) & 1 == 1 || acc[s.u].last() != Some(&s.pidx) || only.is_some_and(|o| o != s.pidx) {
            return None;
        }
        let e = 1u64 << i;
        let x = s.v | e;
        // ts = gapb − d must equal the pair's own write timestamp τ_p.
        let d = k.gapb[s.pidx] - k.tau[s.pidx];
        let (dlo, dhi) = match small(d) {
            Some(v) if v < 1 << 16 => (cu(v & 0xFF), cu(v >> 8)),
            _ => (d, C::ZERO),
        };
        Some(Over { w: Some([C::ONE, cu(x >> (i + 1)), cu(x & (e - 1)), dlo, dhi]), self_read: true, slice: None })
    });
    s.map(|s| (wit, s))
}

/// A word touched by exactly two ACTIVE pairs whose bits the initial word
/// lacks: `(u, p1, p2, e1, e2)`.
fn two_access_word(wit: &Wit, distinct_bits: bool) -> (usize, usize, usize, u64, u64) {
    let p = wit.p;
    let acc = accesses(wit);
    let route = |pidx: usize| {
        let (_, e, act) = wit.route(pidx / p.k, pidx % p.k);
        (small(e).unwrap(), small(act).unwrap())
    };
    (0..p.m_words())
        .find_map(|u| {
            let a = &acc[u];
            if a.len() != 2 {
                return None;
            }
            let ((e1, a1), (e2, a2)) = (route(a[0]), route(a[1]));
            let o = small(wit.o[u]).unwrap();
            let ok = if distinct_bits { e1 != e2 && o & e1 == 0 } else { (o & (e1 | e2)) != (e1 | e2) };
            (a1 == 1 && a2 == 1 && ok).then_some((u, a[0], a[1], e1, e2))
        })
        .expect("a word with exactly two active accesses whose bits are new")
}

/// A4' future read = A3 stale final read (balanced): with `X = O_u | e1 | e2`,
/// pair `p1` reads `p2`'s write `(u, X, τ_{p2})` (a FUTURE read), `p2` reads
/// `p1`'s write `(u, X, τ_{p1})`, and the final read consumes the INIT write
/// `(u, O_u, 0)` (a stale read): both inserts are lost.
fn future_read_forgery(p: &BloomPackedParams, init: &[u8], ks: &[u64]) -> (Wit, usize) {
    let mut wit = Wit::honest(p, init, ks);
    let (u, p1, p2, e1, e2) = two_access_word(&wit, false);
    let o = small(wit.o[u]).unwrap();
    let x = o | e1 | e2;
    let w = |e: u64, d: i64| -> [C; PAIR_WITNESSES] {
        let (dlo, dhi) = if d >= 0 { (cu(d as u64 & 0xFF), cu(d as u64 >> 8)) } else { (ci(d), C::ZERO) };
        [cu((x / e) % 2), cu(x / (2 * e)), cu(x % e), dlo, dhi]
    };
    wit.pairs[p1] = w(e1, p1 as i64 - (p2 as i64 + 1));
    wit.pairs[p2] = w(e2, p2 as i64 - (p1 as i64 + 1));
    wit.n[u] = wit.o[u];
    wit.ft[u] = [C::ZERO, C::ZERO];
    eprintln!("future read at word {u}: pairs {p1} < {p2}, O = {o:#04x}, X = {x:#04x}");
    (wit, u)
}

/// Final-read transplant through an extension-valued `ft` (A5 touched / A11
/// untouched): the final read of `u1` consumes the LAST write of `u2` and
/// vice versa, so the two final words swap. `ft = τ' + (u' − u)·X^{-2}`
/// moves the read's address coordinate.
fn swap_finals(wit: &mut Wit, u1: usize, u2: usize) {
    let ftv = |w: &Wit, u: usize| w.ft[u][1] * cu(256) + w.ft[u][0];
    let (t1, t2) = (ftv(wit, u1), ftv(wit, u2));
    let (n1, n2) = (wit.n[u1], wit.n[u2]);
    let xinv2 = basis(2).inverse();
    wit.n[u1] = n2;
    wit.n[u2] = n1;
    wit.ft[u1] = [t2 + (cu(u2 as u64) - cu(u1 as u64)) * xinv2, C::ZERO];
    wit.ft[u2] = [t1 + (cu(u1 as u64) - cu(u2 as u64)) * xinv2, C::ZERO];
}

fn memory_checking_attacks(p: &BloomPackedParams, init: &[u8], ks: &[u64], deployed: &Rig) {
    let k = Consts::new(p);
    // A4 self-read.
    let (wit, s) = self_read_forgery(p, init, ks, &k, None).expect("an active pair at an unset bit");
    eprintln!("A4 self-read at pair {} (word {}, bit {:?})", s.pidx, s.u, s.i);
    duel("A4 self-read", p, deployed, without("ts_lt_tau"), &Attempt::new(wit), init, ks, false);
    // A4' future read (= the balanced A3 stale final read).
    let (wit, _) = future_read_forgery(p, init, ks);
    duel("A4'/A3 future read + stale final read", p, deployed, without("ts_lt_tau"), &Attempt::new(wit), init, ks, false);

    // A3 pure stale read: the SECOND access of a word reads the initial value
    // (unbalanced: the init write is consumed twice), Permute outputs forged.
    let mut wit = Wit::honest(p, init, ks);
    let (u, _p1, p2, _e1, e2) = two_access_word(&wit, true);
    let o = small(wit.o[u]).unwrap();
    wit.pairs[p2] = honest_pair(o, e2, k.gapb[p2], C::ZERO);
    let (_, _, _, cur) = wit.pair_vals(p2, &k);
    wit.n[u] = cur;
    assert!(wit.sigma(&k).1 > 0, "a pure stale read is unbalanced");
    let claim = wit.final_bytes().unwrap();
    assert_ne!(claim, expected(p, init, ks), "A3 claims a wrong state");
    let why = expect_rejected("A3 stale read", attempt(deployed, &Attempt::new(wit).outputs()));
    eprintln!("ATTACK A3 pure stale read (forged Permute outputs): deployed REJECTED: {why}");

    // A5 tampered final words (unbalanced), Permute outputs forged.
    let base = Wit::honest(p, init, ks);
    let acc = accesses(&base);
    let untouched = (0..p.m_words()).find(|&u| acc[u].is_empty()).unwrap();
    let touched = (0..p.m_words()).find(|&u| !acc[u].is_empty()).unwrap();
    for (what, u) in [("untouched", untouched), ("touched", touched)] {
        let mut wit = base.clone();
        wit.n[u] = cu(small(wit.n[u]).unwrap() ^ 1);
        assert!(wit.sigma(&k).1 > 0);
        let why = expect_rejected("A5", attempt(deployed, &Attempt::new(wit).outputs()));
        eprintln!("ATTACK A5 tampered {what} final word {u} (forged Permute outputs): deployed REJECTED: {why}");
    }
    // A5 control / A11: swap two final words through an extension-valued ft
    // (balanced), touched and untouched.
    let pairs_of = |pred: &dyn Fn(usize) -> bool| -> (usize, usize) {
        let ws: Vec<usize> = (0..p.m_words()).filter(|&u| pred(u)).collect();
        ws.iter()
            .flat_map(|&a| ws.iter().map(move |&b| (a, b)))
            .find(|&(a, b)| a < b && base.n[a] != base.n[b])
            .expect("two words with different final bytes")
    };
    for (name, (u1, u2)) in [
        ("A5 touched-word swap (ft extension)", pairs_of(&|u| !acc[u].is_empty())),
        ("A11 untouched-word swap (ft extension)", pairs_of(&|u| acc[u].is_empty())),
    ] {
        let mut wit = base.clone();
        swap_finals(&mut wit, u1, u2);
        assert_eq!(wit.sigma(&k).1, 0, "{name}: balanced");
        eprintln!("{name}: words {u1} <-> {u2}");
        duel(name, p, deployed, without("ft_range"), &Attempt::new(wit), init, ks, false);
    }
}

/// A6: extension-valued byte transplants that keep the commitment.
/// `O` side: `O'_{3l} = S_{3l} + δ·X`, `O'_{3l+3} = S_{3l+3} − δ` (the
/// packing absorbs `δ·X` into limb `l + 1`, so `Com(S_{t-1})` is the HONEST
/// one) clears bit `log2 δ` of word `3l + 3` from the memory the batch is
/// applied to; the init write of `3l` becomes `(3l, S, δ)` and an untouched
/// `3l` is read back with `ft = δ`. `N` side: `N'_{3l} = N + δ·X` with
/// `δ = ft_{3l}`, `ft' = 0`: the final read is still the true last write
/// while `Com(S_t)` raises word `3l + 3` by `δ`.
fn extension_byte_attacks(p: &BloomPackedParams, init: &[u8], ks: &[u64], deployed: &Rig) {
    let base = Wit::honest(p, init, ks);
    let acc = accesses(&base);
    let mw = p.m_words();
    let honest_final = expected(p, init, ks);
    // O side.
    let (a, b, beta) = (0..mw / 3)
        .filter(|l| l % 4 < 3 && 3 * l + 3 < mw)
        .find_map(|l| {
            let (a, b) = (3 * l, 3 * l + 3);
            if !acc[a].is_empty() {
                return None;
            }
            // A bit of S_b that the batch does not set again.
            (0..8u64).find(|&bt| (init[b] >> bt) & 1 == 1 && (honest_final[b] >> bt) & 1 == 1 && {
                let mut w = init.to_vec();
                w[b] &= !(1 << bt);
                expected(p, &w, ks)[b] != honest_final[b]
            }).map(|bt| (a, b, bt))
        })
        .expect("an untouched first-of-limb word followed by a word with a removable bit");
    let delta = 1u64 << beta;
    let mut w0 = base.clone();
    w0.o[a] = cu(init[a] as u64) + cu(delta) * basis(1);
    w0.o[b] = cu(init[b] as u64 - delta);
    assert_eq!(w0.packed(&w0.o), base.packed(&base.o), "the old-state packing is unchanged");
    let (mut wit, _) = replay(w0, &Consts::new(p), &mut |_, _| None);
    wit.n[a] = cu(init[a] as u64);
    wit.ft[a] = [cu(delta), C::ZERO];
    assert_eq!(wit.sigma(&Consts::new(p)).1, 0);
    eprintln!("A6-O: O'_{a} = S + {delta}X, O'_{b} = S - {delta} (clears bit {beta} of word {b})");
    duel("A6 extension-valued OLD byte", p, deployed, without("o_pin"), &Attempt::new(wit), init, ks, false);

    // N side.
    let (a, b) = (0..mw / 3)
        .filter(|l| l % 4 < 3 && 3 * l + 3 < mw)
        .map(|l| (3 * l, 3 * l + 3))
        .find(|&(a, b)| {
            let ft = small(base.ft[a][0]).unwrap() + 256 * small(base.ft[a][1]).unwrap();
            ft >= 1 && honest_final[b] as u64 + ft < 256
        })
        .expect("a touched first-of-limb word");
    let mut wit = base.clone();
    let delta = wit.ft[a][1] * cu(256) + wit.ft[a][0];
    wit.n[a] += delta * basis(1);
    wit.ft[a] = [C::ZERO, C::ZERO];
    assert_eq!(wit.sigma(&Consts::new(p)).1, 0);
    let mut claim = honest_final.clone();
    claim[b] += small(delta).unwrap() as u8;
    let mut want = base.clone();
    want.n[b] += delta;
    assert_eq!(wit.packed(&wit.n), want.packed(&want.n), "Com(S_t) is the commitment of the claim");
    eprintln!("A6-N: N'_{a} = N + {delta:?}X (claims word {b} + δ)");
    let h = honest_statement(p, init, ks);
    let control = rig(p, without("n_pin"));
    let st = expect_control("A6 N", attempt(&control, &Attempt::new(wit.clone())), &control, &deployed.vk, &h);
    expect_wrong_state("A6 N", &st, p, &claim, &h);
    let why = expect_rejected("A6 N", attempt(deployed, &Attempt::new(wit)));
    eprintln!("ATTACK A6 extension-valued NEW byte: control (without n_pin) ACCEPTED a wrong state; deployed REJECTED: {why}");
}

/// The first key of `cands` with a used digest limb satisfying `pred(j, x)`.
fn key_with_limb(p: &BloomPackedParams, cands: impl Iterator<Item = u64>, pred: &dyn Fn(usize, u64) -> bool) -> (u64, usize, u64) {
    let h = MyHash::new(make_perm());
    for key in cands {
        let d: [Val; 8] = h.hash_iter(record_vals(Some(key)));
        if let Some(j) = (0..p.k).find(|&j| pred(j, d[j].as_canonical_u64())) {
            return (key, j, d[j].as_canonical_u64());
        }
    }
    panic!("no key with such a limb");
}

/// A7: the non-canonical split `x + p` of a digest limb `x` (position
/// `(x + 1) mod W`). (a) all checks but the canonicity lookups honoured:
/// `dd = HI_MAX − hi'` is negative (byte lookups); (b) `dd` bytes in range,
/// only the `HI_MAX − hi = dd` connect broken (split wire); (c) the EDGE:
/// `x < W − 1`, `x + p = HI_MAX·W + (x + 1)`, `dd = 0`, only the
/// `(HI_MAX − hi = 0) ⇒ pos = 0` connect broken (split wire; shape `p_edge`).
fn canonicity_attacks(p: &BloomPackedParams, init: &[u8], p_edge: &BloomPackedParams, deployed: &Rig, deployed_edge: &Rig) {
    let w = 1u64 << p.log_w;
    let bit = |st: &[u8], j: usize, pos: u64| (st[j * p.words_per_slice() + (pos >> 3) as usize] >> (pos & 7)) & 1;
    let (lead, j0, x) = key_with_limb(p, keys(20_000, 0xCA70).into_iter(), &|j, x| {
        x + PMOD < 1 << (p.log_w + 24) && bit(init, j, x % w) == 0 && bit(init, j, (x + 1) % w) == 0
    });
    let mut ks = vec![lead];
    ks.extend(keys(p.batch - 2, 0x5000));
    for (name, dd_in_range) in [("A7 x+p split (dd < 0)", false), ("A7b x+p split, HI_MAX-hi=dd connect", true)] {
        let mut w0 = Wit::honest(p, init, &ks);
        let xp = x + PMOD;
        let mut sv = slice_for_int(p, xp);
        if dd_in_range {
            // dd := 1 (a byte), dinv := 1: the lookups and the edge hold;
            // HI_MAX − hi' ≠ dd.
            sv = slice_vals(p, cu((xp & (w - 1)) >> 3), [xp & 1, (xp >> 1) & 1, (xp >> 2) & 1].map(cu), cu(xp >> p.log_w), C::ONE, C::ONE);
        }
        w0.set_slice(0, j0, &sv);
        let (wit, _) = replay(w0, &Consts::new(p), &mut |_, _| None);
        eprintln!("{name}: key {lead:#x}, slice {j0}, x = {x}");
        duel(name, p, deployed, without("canon"), &Attempt::new(wit), init, &ks, dd_in_range);
    }
    // (c) the edge, at a wider slice.
    let pe = p_edge;
    let we = 1u64 << pe.log_w;
    let init_e = prior(pe, 20);
    let (lead, j0, x) = key_with_limb(pe, (0..2_000_000u64).map(|i| i.wrapping_mul(0x2545_F491_4F6C_DD1D)), &|j, x| {
        x + 1 < we && {
            let b = |pos: u64| (init_e[j * pe.words_per_slice() + (pos >> 3) as usize] >> (pos & 7)) & 1;
            b(x) == 0 && b(x + 1) == 0
        }
    });
    let mut ks = vec![lead];
    ks.extend(keys(pe.batch - 2, 0x5000));
    let mut w0 = Wit::honest(pe, &init_e, &ks);
    let sv = slice_for_int(pe, x + PMOD);
    assert_eq!(small(sv[sv.len() - 1]), Some(0), "dd = 0 at the edge");
    w0.set_slice(0, j0, &sv);
    let (wit, _) = replay(w0, &Consts::new(pe), &mut |_, _| None);
    eprintln!("A7c edge: key {lead:#x}, slice {j0}, x = {x} < W - 1: x + p = HI_MAX·W + {}", x + 1);
    duel("A7c canonicity edge (hi = HI_MAX, pos != 0)", pe, deployed_edge, without("canon"), &Attempt::new(wit), &init_e, &ks, true);
}

/// A8: position-bit forgeries. (a) non-boolean bits with the same `i` but
/// `e = 3·(1 + 15 i_2)`; (b) `q` off by one: `q' = q + 1` with non-boolean
/// bits summing to `i − 8` whose `e` is the power of two `2^s` (the pair
/// writes bit `s` of the NEXT word); (c) `q' = q + W/8`, `hi' = hi − 1`
/// (the next slice's word).
fn position_attacks(pr: &BloomPackedParams, init: &[u8], ks: &[u64], deployed: &Rig) {
    let p = *pr;
    let wps = p.words_per_slice() as u64;
    let hm = hi_max(p.log_w);
    let digest_x = |wit: &Wit, s: &Seen| -> u64 {
        let rec = wit.recs[s.r];
        let key = (0..8).fold(0u64, |acc, b| acc | (small(rec[b]).unwrap() << (8 * b)));
        record_digest(Some(key))[s.j].as_canonical_u64()
    };
    type Route = Box<dyn Fn(&Seen, &Wit, u64, u64) -> Option<Vec<C>>>;
    let cases: Vec<(&str, &str, Route)> = vec![
        ("A8a non-boolean i bits (e = 3(1+15 i2))", "i_bool", Box::new(move |s: &Seen, _: &Wit, x: u64, i: u64| {
            let e = 3 * (1 + 15 * ((i >> 2) & 1));
            (i & 3 == 2 && s.v + e < 256).then(|| {
                let (pos, hi) = (x & ((1u64 << p.log_w) - 1), x >> p.log_w);
                let dd = cu(hm - hi);
                slice_vals(&p, cu(pos >> 3), [cu(2), C::ZERO, cu((i >> 2) & 1)], cu(hi), dd, dd.inverse())
            })
        })),
        ("A8b q off by one (non-boolean bits, e = 2^s)", "i_bool", Box::new(move |_: &Seen, _: &Wit, x: u64, i: u64| {
            let (pos, hi) = (x & ((1u64 << p.log_w) - 1), x >> p.log_w);
            ((pos >> 3) + 1 < wps).then(|| {
                let (ib, _s) = bits_for_next_word(i);
                let dd = cu(hm - hi);
                slice_vals(&p, cu((pos >> 3) + 1), ib, cu(hi), dd, dd.inverse())
            })
        })),
        ("A8c q + W/8 (next slice)", "q_range", Box::new(move |s: &Seen, _: &Wit, x: u64, i: u64| {
            let (pos, hi) = (x & ((1u64 << p.log_w) - 1), x >> p.log_w);
            (s.j + 1 < p.k && hi >= 1).then(|| {
                let dd = cu(hm - (hi - 1));
                slice_vals(&p, cu((pos >> 3) + wps), [i & 1, (i >> 1) & 1, (i >> 2) & 1].map(cu), cu(hi - 1), dd, dd.inverse())
            })
        })),
    ];
    for (name, off, route) in cases {
        let w0 = Wit::honest(&p, init, ks);
        let acc = accesses(&w0);
        let (wit, s) = replay(w0, &Consts::new(&p), &mut |s, wit| {
            let i = s.i?;
            if s.act != 1 || (s.v >> i) & 1 == 1 || acc[s.u].last() != Some(&s.pidx) {
                return None;
            }
            let x = digest_x(wit, s);
            route(s, wit, x, i).map(|sv| Over { slice: Some(sv), ..Default::default() })
        });
        let s = s.expect("a pair to re-route");
        eprintln!("{name}: pair {} (record {}, slice {}) re-routed to word {}", s.pidx, s.r, s.j, s.u);
        duel(name, &p, deployed, without(off), &Attempt::new(wit), init, ks, false);
    }
}

/// `l3 = (H0 − l0 − l1·X − l2·X²)·X^{-3}`: the extension-valued unused limb
/// that makes `recompose(l0, l1, l2, l3) = H0` for ANY base `l0..l2`.
fn compensating_limb(h0: C, l: [C; 3]) -> C {
    (h0 - l[0] - l[1] * basis(1) - l[2] * basis(2)) * basis(3).inverse()
}

/// The digest Challenge `h[c]` (limbs `4c..4c+4`) of a record.
fn digest_chunk(d: &[Val; 8], c: usize) -> C {
    C::from_basis_coefficients_slice(&d[4 * c..4 * c + 4]).unwrap()
}

/// Routing and record forgeries.
/// (a) `unused_limbs`: route an active pair of slice `j < 3` to another bit
///     and absorb the change into the extension-valued unused limb 3, so the
///     digest recomposition still holds; (b) the same re-route WITHOUT the
///     compensation: only the digest-recomposition connect breaks (split
///     wire); (c) `key_range`: an ACTIVE record re-encoded as a dummy
///     (`act = 0`) with extension-valued key limbs `k0 = −k3`,
///     `k3 = R·(X³ − 1)^{-1}` (so `Σ k = 0` and the record Challenge is
///     still `R`): the honest `Com(B_t)`, the honest routing, no insert;
///     (d) `dummy_canon`: a dummy slot carrying a key with `act = 0`
///     (certifies a non-canonical `Com(B_t)`, no wrong state; the deployed
///     leaf is attacked with a split wire on the dummy rule).
fn record_and_routing_attacks(p: &BloomPackedParams, init: &[u8], ks: &[u64], deployed: &Rig) {
    let per = per_slice(p);
    // The slices whose limb shares a digest Challenge with an unused limb.
    let (unused, chunk) = if p.k <= 3 { (3usize, 0usize) } else { (7, 1) };
    let first = 4 * chunk;
    let w0 = Wit::honest(p, init, ks);
    let acc = accesses(&w0);
    let honest_final = expected(p, init, ks);
    let (r, j, x, i) = (0..p.pairs())
        .find_map(|pidx| {
            let (r, j) = (pidx / p.k, pidx % p.k);
            if j < first || j >= first + 3 || j >= p.k {
                return None;
            }
            let (u, e, act) = w0.route(r, j);
            let (u, e) = (small(u).unwrap() as usize, small(e).unwrap());
            let key = ks.get(r)?;
            let x = record_digest(Some(*key))[j].as_canonical_u64();
            (small(act) == Some(1) && acc[u].last() == Some(&pidx) && honest_final[u] as u64 & e != 0
                && init[u] as u64 & e == 0)
                .then_some((r, j, x, e.trailing_zeros() as u64))
        })
        .expect("an active pair that sets a new bit as the last access of its word");
    // Re-route to bit (i + 1) mod 8 of the same word.
    let i2 = (i + 1) % 8;
    let x2 = (x & !7) | i2;
    let d = record_digest(Some(ks[r]));
    for (name, compensate) in [("unused_limbs: re-route absorbed by the unused limb", true), ("digest recomposition re-route (split wire)", false)] {
        let mut w = w0.clone();
        w.set_slice(r, j, &slice_for_int(p, x2));
        if compensate {
            let ls: [C; 3] = std::array::from_fn(|t| {
                let jj = first + t;
                cu(if jj == j { x2 } else { d[jj].as_canonical_u64() })
            });
            let l3 = compensating_limb(digest_chunk(&d, chunk), ls);
            let off = p.k * per + 4 * (unused - p.k);
            w.split[r][off..off + 4].copy_from_slice(&[l3, C::ZERO, C::ZERO, C::ZERO]);
        }
        let (wit, _) = replay(w, &Consts::new(p), &mut |_, _| None);
        eprintln!("{name}: record {r} slice {j} bit {i} -> {i2}");
        if compensate {
            duel(name, p, deployed, without("unused_limbs"), &Attempt::new(wit), init, ks, false);
        } else {
            // The goal is the one the compensated forgery reaches once
            // `unused_limbs` is off (its control above); here the limbs stay
            // base and only the recomposition connect can object.
            let why = expect_rejected(name, attempt(deployed, &Attempt::new(wit).split()));
            eprintln!("ATTACK {name}: (control = the unused_limbs forgery above) deployed REJECTED: {why}");
        }
    }

    // (c) key_range: an active record re-encoded as a dummy.
    let rr = (0..ks.len())
        .find(|&r| {
            let mut w = init.to_vec();
            packed_insert(&mut w, p, &[&ks[..r], &ks[r + 1..]].concat());
            w != honest_final
        })
        .expect("a record whose insert matters");
    let rec = cv(Val::ZERO) + {
        let rv = record_vals(Some(ks[rr]));
        C::from_basis_coefficients_slice(&rv).unwrap()
    };
    let x3m1 = basis(3) - C::ONE;
    let k3 = rec * x3m1.inverse();
    let mut w = w0.clone();
    w.recs[rr] = [C::ZERO - k3, C::ZERO, C::ZERO, C::ZERO, C::ZERO, C::ZERO, k3, C::ZERO, C::ZERO];
    assert_eq!(w.rec(rr), rec, "the dummy re-encoding hashes as the active record");
    let (wit, _) = replay(w, &Consts::new(p), &mut |_, _| None);
    eprintln!("key_range: record {rr} (key {:#x}) re-encoded with act = 0", ks[rr]);
    duel("key_range: active record re-encoded as a dummy", p, deployed, without("key_range"), &Attempt::new(wit), init, ks, false);

    // (d) dummy_canon: a dummy slot with a key (act = 0).
    assert!(ks.len() < p.batch, "a dummy slot");
    let slot = ks.len();
    let kk = 0xD00D_F00D_u64;
    let mut w = w0.clone();
    let mut rv = [C::ZERO; RECORD_WITNESSES];
    for b in 0..8 {
        rv[b] = cu((kk >> (8 * b)) & 0xFF);
    }
    w.recs[slot] = rv;
    let raw: [Val; 4] = std::array::from_fn(|t| Val::from_u64((kk >> (16 * t)) & 0xFFFF));
    w.split[slot] = split_for_digest(p, &digest_of(raw));
    let (wit, _) = replay(w, &Consts::new(p), &mut |_, _| None);
    let control = rig(p, without("dummy_canon"));
    let h = honest_statement(p, init, ks);
    match attempt(&control, &Attempt::new(wit.clone())) {
        Verdict::Accepted { st, vk, splits } => {
            assert_eq!((splits, vk != deployed.vk), (0, true));
            assert_eq!(st.final_, h.final_.to_vec(), "dummy_canon: the state is the honest one");
            assert_ne!(st.interval.unwrap().digest, h.batch_digest, "dummy_canon: a non-canonical Com(B_t)");
        }
        other => panic!("dummy_canon control not accepted: {other:?}"),
    }
    let why = expect_rejected("dummy_canon", attempt(deployed, &Attempt::new(wit).split()));
    eprintln!("ATTACK dummy_canon (non-canonical dummy, no wrong state reachable): control ACCEPTED a non-canonical Com(B_t); deployed (split wire on the dummy rule) REJECTED: {why}");

    // (e) act_bool: a dummy slot (key 0, so the dummy rule holds for any act)
    // with act = a ≥ 2: record [0, 0, 0, a·2^16] (no key encodes it) whose
    // pairs write `v + a(1 − c)·e` instead of `v | e`. A
    // non-boolean act cannot keep the honest Com(B_t) (an extension act
    // that recomposes to a key's record makes the written value leave the
    // base field unless the key is 0), so the control certifies wrong bits
    // under a NON-canonical Com(B_t).
    // The first act = a ≥ 2 whose record lands where every write stays a byte.
    let (a_val, wit, claim) = (2u64..64)
        .find_map(|a| {
            let raw = [Val::ZERO, Val::ZERO, Val::ZERO, Val::from_u64(a * ACT_SHIFT)];
            let mut w = w0.clone();
            w.recs[slot][8] = cu(a);
            w.split[slot] = split_for_digest(p, &digest_of(raw));
            assert_eq!(w.rec(slot), C::from_basis_coefficients_slice(&raw).unwrap());
            let (wit, _) = catch_msg(|| replay(w, &Consts::new(p), &mut |_, _| None)).ok()?;
            let claim = wit.final_bytes()?;
            (claim != honest_final).then_some((a, wit, claim))
        })
        .expect("an act value whose writes stay bytes");
    let control = rig(p, without("act_bool"));
    let open = openings();
    match attempt(&control, &Attempt::new(wit.clone())) {
        Verdict::Accepted { st, vk, splits } => {
            assert_eq!((splits, vk != deployed.vk), (0, true));
            assert_eq!(st.final_, commit_packed_with(p, &claim, CommitMode::Hiding, &open.final_).to_vec(), "act_bool: certifies the wrong bits");
            assert_ne!(st.interval.unwrap().digest, h.batch_digest, "act_bool: under a non-canonical Com(B_t)");
        }
        other => panic!("act_bool control not accepted: {other:?}"),
    }
    let why = expect_rejected("act_bool", attempt(deployed, &Attempt::new(wit)));
    eprintln!("ATTACK act_bool (act = {a_val} on a key-0 slot: shifted bits, non-canonical Com(B_t)): control ACCEPTED; deployed REJECTED: {why}");
}

/// Constant values the leaf's gadgets use (a constant forgery must pick a
/// word-address or timestamp constant with no other use).
fn gadget_consts(p: &BloomPackedParams) -> Vec<u64> {
    let mut v = vec![0, 1, 2, 3, 4, 8, 15, 256, 65536, ACT_SHIFT, 1u64 << p.log_w, hi_max(p.log_w)];
    v.extend((0..p.k).map(|j| (j * p.words_per_slice()) as u64));
    let r = p.q_bits() - 8 * (q_bytes(p.log_w) - 1);
    if r < 8 {
        v.push(1u64 << (8 - r));
    }
    v
}

/// A10: the cross-family commitment. The runner's clone carries the
/// family-5 (`Bloom`) tags instead of family 7 in the STATE and BATCH
/// commitments, so the leaf exposes `Com_5(·)` of the packed state. Control:
/// the circuit whose tags ARE family 5 (it certifies family-5 commitments,
/// which differ from the family-7 ones); deployed: rejected (ConstAir binds
/// the tag). Also: the bit-array (family 5) leaf's VK is not the packed one.
fn cross_family_attack(p: &BloomPackedParams, init: &[u8], ks: &[u64], deployed: &Rig, compare_omc_vk: bool) {
    let tag = |kind, fam| hiding::tag_challenge::<Val, C>(kind, fam);
    let consts = vec![
        (tag(CommitKind::State, CommitFamily::BloomPacked), tag(CommitKind::State, CommitFamily::Bloom)),
        (tag(CommitKind::Batch, CommitFamily::BloomPacked), tag(CommitKind::Batch, CommitFamily::Bloom)),
    ];
    let mut patched = deployed.circuit.clone();
    for &(o, n) in &consts {
        patch_const(&mut patched, o, n);
    }
    let control = rig_from_circuit(patched);
    assert_ne!(control.vk, deployed.vk, "A10: the tag is part of the VK");
    let mut a = Attempt::new(Wit::honest(p, init, ks));
    a.fam = CommitFamily::Bloom;
    let open = openings();
    let fin = expected(p, init, ks);
    let com = |fam, kind, salt: &SaltBb, flat: &[Val]| hiding::commit_flat_bb(CommitMode::Hiding, kind, fam, salt, flat).to_vec();
    match attempt(&control, &a) {
        Verdict::Accepted { st, vk, splits } => {
            assert_eq!((splits, &vk), (0, &control.vk));
            let i5 = com(CommitFamily::Bloom, CommitKind::State, &open.init, &words_flat(p, init));
            let f5 = com(CommitFamily::Bloom, CommitKind::State, &open.final_, &words_flat(p, &fin));
            assert_eq!((&st.init, &st.final_), (&i5, &f5), "A10 control: family-5 commitments");
            assert_ne!(st.init, commit_packed_with(p, init, CommitMode::Hiding, &open.init).to_vec(), "family 5 != family 7");
            assert_ne!(st.final_, commit_packed_with(p, &fin, CommitMode::Hiding, &open.final_).to_vec());
        }
        other => panic!("A10 control not accepted: {other:?}"),
    }
    a.consts = consts;
    let why = expect_rejected("A10", attempt(deployed, &a));
    eprintln!("ATTACK A10 cross-family (family-5 tags in a packed leaf): control (family-5 circuit) ACCEPTED Com_5; deployed REJECTED: {why}");
    if compare_omc_vk {
        // (A bit-array leaf at k = 7, W = 2^14 needs about 7.6 GB: test shape only.)
        let omc = crate::sketch::bloom_omc::build_bloom_omc_leaf_commit(p.omc(), Expose::Interval, CommitMode::Hiding)
            .prove_epoch_public_zero(1, &crate::sketch::bloom_omc::bloom_empty(&p.omc()), &[]);
        assert_ne!(vk_pin_values(&omc.output.0), deployed.vk, "A10: the family-5 leaf's VK is not the packed leaf's");
    }
}

/// ConstAir regression (word address): the runner's clone moves the address
/// constant of word `u0` to `u0 + 1`, so two untouched words share address
/// `u0 + 1` and their final values swap. Control: the circuit whose constant
/// IS `u0 + 1`; deployed: rejected.
fn word_address_attack(p: &BloomPackedParams, init: &[u8], ks: &[u64], deployed: &Rig) {
    let base = Wit::honest(p, init, ks);
    let acc = accesses(&base);
    let g = gadget_consts(p);
    let u0 = (p.pairs() + 1..p.m_words() - 1)
        .find(|&u| acc[u].is_empty() && acc[u + 1].is_empty() && init[u] != init[u + 1] && !g.contains(&(u as u64)) && !g.contains(&(u as u64 + 1)))
        .expect("two adjacent untouched words with a pure address constant");
    let k = Consts::new(p).patched(u0 as u64, u0 as u64 + 1);
    let mut wit = base.clone();
    wit.n[u0] = wit.o[u0 + 1];
    wit.n[u0 + 1] = wit.o[u0];
    assert_eq!(wit.sigma(&k).1, 0);
    let mut patched = deployed.circuit.clone();
    patch_const(&mut patched, cu(u0 as u64), cu(u0 as u64 + 1));
    let control = rig_from_circuit(patched);
    let h = honest_statement(p, init, ks);
    let mut a = Attempt::new(wit.clone());
    a.k = k;
    let st = expect_control("ConstAir word address", attempt(&control, &a), &control, &deployed.vk, &h);
    expect_wrong_state("ConstAir word address", &st, p, &wit.final_bytes().unwrap(), &h);
    a.consts = vec![(cu(u0 as u64), cu(u0 as u64 + 1))];
    let why = expect_rejected("ConstAir word address", attempt(deployed, &a));
    eprintln!("ATTACK ConstAir word address {u0} -> {}: control ACCEPTED swapped words; deployed REJECTED: {why}", u0 + 1);
}

/// ConstAir regression (timestamp): the runner's clone raises the pure
/// timestamp constant `p0` (= `τ_{p0−1}` = `τ_{p0} − 1`) to `p0 + 1`, which
/// admits the self-read at pair `p0`. Control: the circuit whose constant IS
/// `p0 + 1`; deployed: rejected.
fn tau_attack(p: &BloomPackedParams, init: &[u8], ks: &[u64], deployed: &Rig) {
    let base = Wit::honest(p, init, ks);
    let acc = accesses(&base);
    let g = gadget_consts(p);
    let found = (p.m_words() + 1..p.pairs()).find_map(|p0| {
        if g.contains(&(p0 as u64)) || g.contains(&(p0 as u64 + 1)) {
            return None;
        }
        let (u, _, _) = base.route(p0 / p.k, p0 % p.k);
        if acc[small(u).unwrap() as usize].contains(&(p0 - 1)) {
            return None;
        }
        let k = Consts::new(p).patched(p0 as u64, p0 as u64 + 1);
        self_read_forgery(p, init, ks, &k, Some(p0)).map(|(w, s)| (p0, k, w, s))
    });
    let (p0, k, wit, s) = found.expect("a pure timestamp constant at an active pair");
    assert_eq!(wit.sigma(&k).1, 0);
    let mut patched = deployed.circuit.clone();
    patch_const(&mut patched, cu(p0 as u64), cu(p0 as u64 + 1));
    let control = rig_from_circuit(patched);
    let h = honest_statement(p, init, ks);
    let mut a = Attempt::new(wit.clone());
    a.k = k;
    let st = expect_control("ConstAir timestamp", attempt(&control, &a), &control, &deployed.vk, &h);
    expect_wrong_state("ConstAir timestamp", &st, p, &wit.final_bytes().unwrap(), &h);
    a.consts = vec![(cu(p0 as u64), cu(p0 as u64 + 1))];
    let why = expect_rejected("ConstAir timestamp", attempt(deployed, &a));
    eprintln!("ATTACK ConstAir timestamp {p0} -> {} (self-read at pair {}, word {}): control ACCEPTED; deployed REJECTED: {why}", p0 + 1, s.pidx, s.u);
}

// ─── Query forgeries ────────────────────────────────────────────────────────

fn q_salt() -> SaltBb {
    hiding::rho_state_bb(&SaltSeed::for_tests(0x0E7), FAMILY, 3)
}

/// The query's private-input layout (`Hiding`).
#[derive(Clone, Copy)]
struct QLay {
    p: BloomPackedParams,
    na: usize,
    nb: usize,
}

impl QLay {
    fn new(p: &BloomPackedParams) -> Self {
        let (na, nb) = selector_dims(p);
        QLay { p: *p, na, nb }
    }
    fn cell(&self, u: usize) -> usize {
        3 + u
    }
    fn split(&self) -> usize {
        3 + self.p.m_words() + RECORD_WITNESSES - 1
    }
    fn slice(&self, j: usize) -> usize {
        self.split() + j * per_slice(&self.p)
    }
    fn unused(&self, t: usize) -> usize {
        self.split() + self.p.k * per_slice(&self.p) + 4 * (t - self.p.k)
    }
    fn sel(&self, j: usize) -> usize {
        self.split() + split_count(&self.p) + j * (self.na + self.nb)
    }
    fn ext(&self, j: usize) -> usize {
        self.split() + split_count(&self.p) + self.p.k * (self.na + self.nb) + 3 * j
    }
    /// Selectors of slice `j`: the 1-entries `s1 ⊂ [0, na)`, `s2 ⊂ [0, nb)`.
    fn set_sel(&self, v: &mut [C], j: usize, s1: &[usize], s2: &[usize]) {
        let o = self.sel(j);
        for x in 0..self.na {
            v[o + x] = cu(u64::from(s1.contains(&x)));
        }
        for y in 0..self.nb {
            v[o + self.na + y] = cu(u64::from(s2.contains(&y)));
        }
    }
    /// `[c, H, L]` of slice `j`: the honest split of `val` at `e`.
    fn set_ext(&self, v: &mut [C], j: usize, val: u64, e: u64) {
        let o = self.ext(j);
        v[o] = cu((val / e) % 2);
        v[o + 1] = cu(val / (2 * e));
        v[o + 2] = cu(val % e);
    }
    /// The answer public input := `Π c_j` of the (forged) private inputs.
    fn set_answer(&self, pubs: &mut [C], privs: &[C]) {
        pubs[3] = (0..self.p.k).fold(C::ONE, |acc, j| acc * privs[self.ext(j)]);
    }
}

type Modify = Rc<dyn Fn(&QLay, &mut Vec<C>, &mut Vec<C>)>;

enum QVerdict {
    Accepted { proof: crate::decode::DecodeProof, answer: Val, splits: usize },
    Rejected(String),
    Runner(String),
}

fn qv_str(v: &QVerdict) -> String {
    match v {
        QVerdict::Accepted { answer, splits, .. } => format!("Accepted(answer {answer}, splits {splits})"),
        QVerdict::Rejected(e) => format!("Rejected({e})"),
        QVerdict::Runner(e) => format!("Runner({e})"),
    }
}

/// Prove a (forged) query: the decoder builds the circuit with `checks`, the
/// forger rewrites the inputs with `modify`, optionally splits wires, and
/// runs a clone; the decoder proves and verifies with its prover data.
fn q_attempt(p: &BloomPackedParams, words: &[u8], key: u64, checks: PackedChecks, split: bool, modify: Modify) -> QVerdict {
    let lay = QLay::new(p);
    let splits = Rc::new(Cell::new(0usize));
    let sc = splits.clone();
    let forger: QueryForger = Rc::new(move |circuit: &Circuit<C>, public: &[C], private: &[C]| {
        let (mut pubs, mut privs) = (public.to_vec(), private.to_vec());
        modify(&lay, &mut pubs, &mut privs);
        let mut c = circuit.clone();
        if split {
            let n = catch_msg(|| split_conflicting_wires(&mut c, &pubs, &privs))
                .map_err(|e| format!("split pre-pass panicked: {e}"))?
                .map_err(|e| format!("split pre-pass: {e}"))?;
            sc.set(n);
        }
        catch_msg(|| -> Result<Traces<C>, String> {
            let mut r = c.runner();
            r.set_public_inputs(&pubs).map_err(|e| format!("{e:?}"))?;
            r.set_private_inputs(&privs).map_err(|e| format!("{e:?}"))?;
            r.run().map_err(|e| format!("runner: {}", short(&format!("{e:?}"))))
        })
        .map_err(|e| format!("runner panicked: {e}"))?
    });
    let (salt, words, p) = (q_salt(), words.to_vec(), *p);
    let res = catch_msg(move || {
        with_checks(checks, || {
            with_query_forger(forger, || try_prove_bloom_packed_query_commit(p, &words, key, CommitMode::Hiding, &salt))
        })
    });
    match res {
        Err(panic) => QVerdict::Rejected(format!("panicked: {}", short(&panic))),
        Ok(Err(e)) if e.starts_with("prove:") || e.starts_with("verify:") => {
            QVerdict::Rejected(format!("{} [split wires: {}]", short(&e), splits.get()))
        }
        Ok(Err(e)) => QVerdict::Runner(short(&e)),
        Ok(Ok(proof)) => {
            let (_, _, answer) = read_exposed_query(&proof.output.0);
            QVerdict::Accepted { proof, answer, splits: splits.get() }
        }
    }
}

fn q_reject(name: &str, p: &BloomPackedParams, words: &[u8], key: u64, split: bool, modify: Modify) -> String {
    match q_attempt(p, words, key, PackedChecks::ALL, split, modify) {
        QVerdict::Rejected(e) => e,
        other => panic!("{name}: the DEPLOYED query must reject in the prover/verifier, got {}", qv_str(&other)),
    }
}

/// Query duel: against the query without `off` (no split) the forgery must
/// verify against THAT circuit's derived decode VK with the honest `Com(S)`
/// and record and a WRONG answer (and the deployed decode VK must refuse that
/// proof); against the deployed query it must be rejected.
#[allow(clippy::too_many_arguments)]
fn q_duel(name: &str, p: &BloomPackedParams, words: &[u8], key: u64, off: PackedChecks, split_deployed: bool, modify: Modify) -> String {
    let honest = u64::from(packed_contains(words, p, key));
    let vk_dep: DecodeVk = bloom_packed_decode_vk_commit(*p, CommitMode::Hiding);
    let vk_off: DecodeVk = with_checks(off, || bloom_packed_decode_vk_commit(*p, CommitMode::Hiding));
    assert_ne!(vk_off.commitment, vk_dep.commitment, "{name}: the control query circuit differs");
    match q_attempt(p, words, key, off, false, modify.clone()) {
        QVerdict::Accepted { proof, answer, splits } => {
            assert_eq!(splits, 0, "{name}: a control must not need a split wire");
            let st = verify_decode_proof(&proof.output.0, &vk_off)
                .unwrap_or_else(|e| panic!("{name}: control vs its derived decode VK: {e}"));
            assert_eq!(st.commit, commit_packed_with(p, words, CommitMode::Hiding, &q_salt()), "{name}: honest Com(S)");
            assert_eq!(st.query, record_vals(Some(key)), "{name}: honest record");
            assert_eq!(st.answer[0], answer);
            assert_ne!(answer, Val::from_u64(honest), "{name}: the control must certify a WRONG answer");
            assert!(verify_decode_proof(&proof.output.0, &vk_dep).is_err(), "{name}: the deployed decode VK refuses it");
        }
        other => panic!("{name}: POSITIVE CONTROL not accepted: {}", qv_str(&other)),
    }
    let why = q_reject(name, p, words, key, split_deployed, modify);
    eprintln!("ATTACK {name}: control (without {}) ACCEPTED a wrong answer (honest {honest}); deployed REJECTED: {why}", off_name(off));
    why
}

/// A filled filter and its members / non-members.
fn q_fixture(p: &BloomPackedParams, n: usize) -> (Vec<u8>, Vec<u64>, Vec<u64>) {
    let members = keys(n, 0x77);
    let mut w = packed_empty(p);
    packed_insert(&mut w, p, &members);
    let non: Vec<u64> = keys(4000, 0xABCD).into_iter().filter(|&k| !packed_contains(&w, p, k)).collect();
    (w, members, non)
}

/// Honest `(q, i)` per slice and bit per slice of `key`.
fn q_route(p: &BloomPackedParams, words: &[u8], key: u64) -> Vec<(usize, u64, u64)> {
    let wps = p.words_per_slice();
    packed_positions(p, Some(key))
        .into_iter()
        .enumerate()
        .map(|(j, (q, i))| (q as usize, i, ((words[j * wps + q as usize] >> i) & 1) as u64))
        .collect()
}

fn subsets(n: usize) -> Vec<Vec<usize>> {
    let mut v = vec![vec![]];
    v.extend((0..n).map(|x| vec![x]));
    for x in 0..n {
        for y in x + 1..n {
            v.push(vec![x, y]);
        }
    }
    v
}

/// A9: query selector forgeries. With the one-hot sums off, a selector that
/// is not one-hot but keeps `nb·Σa·s1_a + Σb·s2_b = q` opens a value other
/// than `S[q]`: a column two-hot `s2 = e_{b1} + e_{b2}` (a SHIFT within the
/// row when one cell is zero), a row two-hot, a zero-hot (opens nothing).
/// Deployed: the same selectors (split wires on the one-hot sums). Then the
/// connect-only forgeries, deployed with split wires: the one-hot SHIFT
/// (`S[q ± 1]`, index connect), the WRONG SLICE (`v = S[j'·W/8 + q]`,
/// selected-value connect) and the WRONG BIT (position bits changed, digest
/// recomposition connect; its control is the unused-limb compensation with
/// `unused_limbs` off).
fn query_selector_attacks(p: &BloomPackedParams, n_members: usize) {
    let (words, members, non) = q_fixture(p, n_members);
    let lay = QLay::new(p);
    let (na, nb, wps) = (lay.na, lay.nb, p.words_per_slice());
    let s1s = subsets(na);
    // The subsets of [0, nb) of size ≤ 2 with sum `rem`.
    let s2_with_sum = |rem: usize| -> Vec<Vec<usize>> {
        let mut v = Vec::new();
        if rem == 0 {
            v.push(vec![]);
        }
        if rem < nb {
            v.push(vec![rem]);
        }
        for y in 0..nb {
            let z = rem.wrapping_sub(y);
            if z > y && z < nb {
                v.push(vec![y, z]);
            }
        }
        v
    };
    let mut found: Vec<(&'static str, u64, usize, Vec<usize>, Vec<usize>, u64, u64)> = Vec::new();
    for &key in members.iter().take(300).chain(non.iter().take(300)) {
        if found.len() == 3 {
            break;
        }
        let route = q_route(p, &words, key);
        let honest: u64 = route.iter().map(|r| r.2).product();
        for (j, &(q, i, _)) in route.iter().enumerate() {
            let (a, b) = (q / nb, q % nb);
            for s1 in &s1s {
                let used = nb * s1.iter().sum::<usize>();
                if used > q {
                    continue;
                }
                for s2 in &s2_with_sum(q - used) {
                    if s1 == &vec![a] && s2 == &vec![b] {
                        continue;
                    }
                    let cat = match (s1.len(), s2.len()) {
                        (1, 2) => "A9 column two-hot (shift)",
                        (2, 1) => "A9 row two-hot",
                        (0, _) | (_, 0) => "A9 zero-hot",
                        _ => continue,
                    };
                    if found.iter().any(|f| f.0 == cat) {
                        continue;
                    }
                    let selv: u64 = s1.iter().flat_map(|&x| s2.iter().map(move |&y| (x, y))).map(|(x, y)| words[j * wps + x * nb + y] as u64).sum();
                    if selv >> (i + 1) > 255 {
                        continue;
                    }
                    let forged = route.iter().enumerate().map(|(jj, r)| if jj == j { (selv >> i) & 1 } else { r.2 }).product::<u64>();
                    if forged != honest {
                        found.push((cat, key, j, s1.clone(), s2.clone(), selv, forged));
                    }
                }
            }
        }
    }
    let cats: Vec<&str> = found.iter().map(|f| f.0).collect();
    assert_eq!(cats.len(), 3, "every selector category found: {cats:?}");
    for (cat, key, j, s1, s2, selv, forged) in found {
        let i = q_route(p, &words, key)[j].1;
        eprintln!("{cat}: key {key:#x} slice {j} s1 {s1:?} s2 {s2:?} opens {selv} (answer -> {forged})");
        let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
            lay.set_sel(privs, j, &s1, &s2);
            lay.set_ext(privs, j, selv, 1 << i);
            lay.set_answer(pubs, privs);
        });
        q_duel(cat, p, &words, key, without("onehot_sum"), true, m);
    }

    // Connect-only forgeries on a member key.
    let member = |pred: &dyn Fn(u64, &[(usize, u64, u64)]) -> bool| -> u64 {
        *members.iter().find(|&&k| pred(k, &q_route(p, &words, k))).expect("a member key for the forgery")
    };
    // One-hot shift to q ± 1 where bit i is 0.
    let cell = |j: usize, q: usize, i: u64| (words[j * wps + q] >> i) & 1;
    let key = member(&|_, r| (0..p.k).any(|j| [r[j].0.wrapping_sub(1), r[j].0 + 1].iter().any(|&q2| q2 < wps && cell(j, q2, r[j].1) == 0)));
    let r = q_route(p, &words, key);
    let (j, q2) = (0..p.k)
        .find_map(|j| [r[j].0.wrapping_sub(1), r[j].0 + 1].into_iter().find(|&q2| q2 < wps && cell(j, q2, r[j].1) == 0).map(|q2| (j, q2)))
        .unwrap();
    let (i, v2) = (r[j].1, words[j * wps + q2] as u64);
    let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
        lay.set_sel(privs, j, &[q2 / lay.nb], &[q2 % lay.nb]);
        lay.set_ext(privs, j, v2, 1 << i);
        lay.set_answer(pubs, privs);
    });
    let why = q_reject("A9 one-hot shift", p, &words, key, true, m);
    eprintln!("ATTACK A9 one-hot shift (slice {j}: S[{q2}] instead of S[{}], index connect): deployed REJECTED: {why}", r[j].0);

    // Wrong slice: the split opens S[j'·W/8 + q_j].
    let key = member(&|_, r| (0..p.k).any(|j| (0..p.k).any(|j2| j2 != j && cell(j2, r[j].0, r[j].1) == 0)));
    let r = q_route(p, &words, key);
    let (j, j2) = (0..p.k).flat_map(|j| (0..p.k).map(move |j2| (j, j2))).find(|&(j, j2)| j2 != j && cell(j2, r[j].0, r[j].1) == 0).unwrap();
    let (i, v2) = (r[j].1, words[j2 * wps + r[j].0] as u64);
    let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
        lay.set_ext(privs, j, v2, 1 << i);
        lay.set_answer(pubs, privs);
    });
    let why = q_reject("A9 wrong slice", p, &words, key, true, m);
    eprintln!("ATTACK A9 wrong slice (slice {j} opens slice {j2}'s word, selected-value connect): deployed REJECTED: {why}");

    // Wrong bit: the position bits of a slice changed to i' (bit 0 in S[q]).
    let (unused, chunk) = if p.k <= 3 { (3usize, 0usize) } else { (7, 1) };
    let first = 4 * chunk;
    let key = member(&|_, r| (first..(first + 3).min(p.k)).any(|j| (0..8).any(|i2| cell(j, r[j].0, i2) == 0)));
    let r = q_route(p, &words, key);
    let (j, i2) = (first..(first + 3).min(p.k)).find_map(|j| (0..8u64).find(|&i2| cell(j, r[j].0, i2) == 0).map(|i2| (j, i2))).unwrap();
    let (q, v) = (r[j].0, words[j * wps + r[j].0] as u64);
    let d = record_digest(Some(key));
    let x = d[j].as_canonical_u64();
    let x2 = (x & !7) | i2;
    let pp = *p;
    let build = move |compensate: bool| -> Modify {
        Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
            let o = lay.slice(j);
            let sv = slice_for_int(&pp, x2);
            privs[o..o + sv.len()].copy_from_slice(&sv);
            if compensate {
                let ls: [C; 3] = std::array::from_fn(|t| cu(if first + t == j { x2 } else { d[first + t].as_canonical_u64() }));
                let l3 = compensating_limb(digest_chunk(&d, chunk), ls);
                let u = lay.unused(unused);
                privs[u..u + 4].copy_from_slice(&[l3, C::ZERO, C::ZERO, C::ZERO]);
            }
            lay.set_ext(privs, j, v, 1 << i2);
            lay.set_answer(pubs, privs);
        })
    };
    let _ = q;
    q_duel("A9 wrong bit, unused-limb compensation", p, &words, key, without("unused_limbs"), false, build(true));
    let why = q_reject("A9 wrong bit (digest connect)", p, &words, key, true, build(false));
    eprintln!("ATTACK A9 wrong bit (slice {j}: bit {i2} instead of {}, digest recomposition connect; control = the unused_limbs forgery above): deployed REJECTED: {why}", r[j].1);
}

/// The query's other checks: state-byte pins, selector booleans, the split,
/// the position bits and the canonical split.
fn query_value_attacks(p: &BloomPackedParams, n_members: usize) {
    let (words, members, non) = q_fixture(p, n_members);
    let lay = QLay::new(p);
    let (na, nb, wps) = (lay.na, lay.nb, p.words_per_slice());
    let cell = |j: usize, q: usize, i: u64| (words[j * wps + q] >> i) & 1;

    // cell_pin: S'_{3l} = S + δX, S'_{3l+3} = S − δ (same Com(S)) opens a
    // selected word with its bit cleared.
    let (key, j, u, l) = members
        .iter()
        .find_map(|&k| {
            let r = q_route(p, &words, k);
            (0..p.k).find_map(|j| {
                let u = j * wps + r[j].0;
                let others: Vec<usize> = (0..p.k).map(|jj| jj * wps + r[jj].0).collect();
                (u % 3 == 0 && u >= 3 && (u / 3) % 4 != 0 && !others.contains(&(u - 3))).then_some((k, j, u, u / 3 - 1))
            })
        })
        .expect("a member whose selected word starts a limb");
    let i = q_route(p, &words, key)[j].1;
    let e = 1u64 << i;
    let s = words[u] as u64;
    let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
        privs[lay.cell(3 * l)] += cu(e) * basis(1);
        privs[lay.cell(u)] -= cu(e);
        lay.set_ext(privs, j, s - e, e);
        lay.set_answer(pubs, privs);
    });
    q_duel("Q cell_pin: extension-valued state byte", p, &words, key, without("cell_pin"), false, m);

    // sel_bool: s1 = e_a + t·(e_x − 2e_y + e_z) (sum 1, index a) opens
    // S[a,b] − e.
    let (key, j, a, b, xyz, dsum) = members
        .iter()
        .find_map(|&k| {
            let r = q_route(p, &words, k);
            (0..p.k).find_map(|j| {
                let (a, b) = (r[j].0 / nb, r[j].0 % nb);
                (0..na.saturating_sub(2)).find_map(|x| {
                    let dsum = words[j * wps + x * nb + b] as i64 - 2 * words[j * wps + (x + 1) * nb + b] as i64
                        + words[j * wps + (x + 2) * nb + b] as i64;
                    (dsum != 0).then_some((k, j, a, b, x, dsum))
                })
            })
        })
        .expect("a member with a non-flat column");
    let i = q_route(p, &words, key)[j].1;
    let e = 1u64 << i;
    let s = words[j * wps + a * nb + b] as u64;
    let t = (C::ZERO - cu(e)) * ci(dsum).inverse();
    let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
        let o = lay.sel(j);
        for xx in 0..lay.na {
            privs[o + xx] = cu(u64::from(xx == a));
        }
        privs[o + xyz] += t;
        privs[o + xyz + 1] -= t + t;
        privs[o + xyz + 2] += t;
        lay.set_ext(privs, j, s - e, e);
        lay.set_answer(pubs, privs);
    });
    q_duel("Q sel_bool: non-boolean selector", p, &words, key, without("sel_bool"), false, m);

    // The split (D3–D5 in the query): false negative / false positive.
    let key = members[0];
    let r = q_route(p, &words, key);
    let j = (0..p.k).find(|&j| (words[j * wps + r[j].0] as u64 & ((1 << r[j].1) - 1)) + (1 << r[j].1) < 256).unwrap();
    let (i, v) = (r[j].1, words[j * wps + r[j].0] as u64);
    let e = 1u64 << i;
    let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
        let o = lay.ext(j);
        privs[o] = C::ZERO;
        privs[o + 1] = cu(v >> (i + 1));
        privs[o + 2] = cu((v & (e - 1)) + e);
        lay.set_answer(pubs, privs);
    });
    q_duel("Q l_lt_e: member answered 0 (L = L'+e)", p, &words, key, without("l_lt_e"), false, m);
    // A non-member: every zero slice forged to c = 1.
    let key = non[0];
    let r = q_route(p, &words, key);
    let zeros: Vec<(usize, u64, u64)> =
        (0..p.k).filter(|&j| r[j].2 == 0).map(|j| (j, r[j].1, words[j * wps + r[j].0] as u64)).collect();
    assert!(!zeros.is_empty());
    for (name, off, huge) in [("Q l_nonneg: non-member answered 1 (L = L'-e)", "l_nonneg", false), ("Q h_range: non-member answered 1 (H huge)", "h_range", true)] {
        let zs = zeros.clone();
        let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
            for &(j, i, v) in &zs {
                let e = 1u64 << i;
                let o = lay.ext(j);
                let l = cu(v & (e - 1));
                privs[o] = C::ONE;
                if huge {
                    privs[o + 1] = (cu(v) - l - cu(e)) * cu(2 * e).inverse();
                    privs[o + 2] = l;
                } else {
                    privs[o + 1] = cu(v >> (i + 1));
                    privs[o + 2] = l - cu(e);
                }
            }
            lay.set_answer(pubs, privs);
        });
        q_duel(name, p, &words, key, without(off), false, m);
    }

    // i_bool in the query: q off by one through non-boolean bits.
    let hm = hi_max(p.log_w);
    let (key, j) = members
        .iter()
        .find_map(|&k| {
            let r = q_route(p, &words, k);
            (0..p.k).find_map(|j| {
                let (ib, s) = bits_for_next_word(r[j].1);
                let _ = ib;
                (r[j].0 + 1 < wps && cell(j, r[j].0 + 1, s) == 0).then_some((k, j))
            })
        })
        .expect("a member whose next word lacks the forged bit");
    let x = record_digest(Some(key))[j].as_canonical_u64();
    let (pos, hi) = (x & ((1u64 << p.log_w) - 1), x >> p.log_w);
    let (ib, s) = bits_for_next_word(pos & 7);
    let q2 = (pos >> 3) as usize + 1;
    let v2 = words[j * wps + q2] as u64;
    let pp = *p;
    let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
        let dd = cu(hm - hi);
        let sv = slice_vals(&pp, cu(q2 as u64), ib, cu(hi), dd, dd.inverse());
        let o = lay.slice(j);
        privs[o..o + sv.len()].copy_from_slice(&sv);
        lay.set_sel(privs, j, &[q2 / lay.nb], &[q2 % lay.nb]);
        lay.set_ext(privs, j, v2, 1 << s);
        lay.set_answer(pubs, privs);
    });
    q_duel("Q i_bool: q off by one (non-boolean bits)", p, &words, key, without("i_bool"), false, m);

    // canon in the query: the x + p split opens position (x + 1) mod W.
    let w = 1u64 << p.log_w;
    let found = members.iter().chain(non.iter()).find_map(|&k| {
        let d = record_digest(Some(k));
        let r = q_route(p, &words, k);
        let honest: u64 = r.iter().map(|x| x.2).product();
        (0..p.k).find_map(|j| {
            let x = d[j].as_canonical_u64();
            if x + PMOD >= 1 << (p.log_w + 24) {
                return None;
            }
            let pos2 = (x + PMOD) & (w - 1);
            let b2 = cell(j, (pos2 >> 3) as usize, pos2 & 7) as u64;
            let forged: u64 = r.iter().enumerate().map(|(jj, x)| if jj == j { b2 } else { x.2 }).product();
            (forged != honest).then_some((k, j, x))
        })
    });
    let (key, j, x) = found.expect("a key whose x + p split flips the answer");
    let xp = x + PMOD;
    let pos2 = xp & (w - 1);
    let v2 = words[j * wps + (pos2 >> 3) as usize] as u64;
    let m: Modify = Rc::new(move |lay: &QLay, pubs: &mut Vec<C>, privs: &mut Vec<C>| {
        let sv = slice_for_int(&pp, xp);
        let o = lay.slice(j);
        privs[o..o + sv.len()].copy_from_slice(&sv);
        let q2 = (pos2 >> 3) as usize;
        lay.set_sel(privs, j, &[q2 / lay.nb], &[q2 % lay.nb]);
        lay.set_ext(privs, j, v2, 1 << (pos2 & 7));
        lay.set_answer(pubs, privs);
    });
    q_duel("Q canon: x + p split", p, &words, key, without("canon"), false, m);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// The forging pipeline is transparent: the mirror reproduces the leaf's
/// honest witness and commitments; the honest witness through the forger
/// (plain, with split wires, with forged Permute outputs) is accepted by the
/// deployed leaf with ZERO splits and the honest statement; the rebuilt
/// prover data of the deployed circuit has the deployed VK; an honest query
/// through the query forger (with the split pass) verifies against the
/// derived decode VK with zero splits.
#[test]
fn pipeline_is_transparent_on_honest_witnesses() {
    let init = prior(&P, 20);
    let mut ks = keys(6, 0x5000);
    ks.push(ks[1]);
    let deployed = rig(&P, PackedChecks::ALL);
    assert_eq!(rig_from_circuit(deployed.circuit.clone()).vk, deployed.vk, "rebuilt prover data = deployed VK");
    let h = honest_statement(&P, &init, &ks);
    let wit = Wit::honest(&P, &init, &ks);
    let k = Consts::new(&P);
    assert_eq!(wit.final_bytes().unwrap(), h.final_words);
    assert_eq!(wit.sigma(&k).1, 0);
    let (rw, none) = replay(wit.clone(), &k, &mut |_, _| None);
    assert!(none.is_none());
    assert_eq!((rw.n.clone(), rw.pairs.clone(), rw.ft.clone()), (wit.n.clone(), wit.pairs.clone(), wit.ft.clone()), "replay == epoch_witness");
    let pr = build_bloom_packed_leaf_commit(P, Expose::Interval, CommitMode::Hiding).prove_epoch_commit(T, &init, &ks, &openings());
    assert_eq!(pr.final_commit.0, h.final_);
    for (what, a) in [
        ("plain", Attempt::new(wit.clone())),
        ("split", Attempt::new(wit.clone()).split()),
        ("forged outputs", Attempt::new(wit.clone()).outputs()),
    ] {
        match attempt(&deployed, &a) {
            Verdict::Accepted { st, vk, splits } => {
                assert_eq!((splits, &vk), (0, &deployed.vk), "{what}");
                assert_eq!((st.init, st.final_), (h.init.to_vec(), h.final_.to_vec()), "{what}");
                assert_eq!(st.interval.unwrap().digest, h.batch_digest, "{what}");
            }
            other => panic!("{what}: honest witness through the forger: {other:?}"),
        }
    }
    let (words, members, _) = q_fixture(&P, 12);
    let vk = bloom_packed_decode_vk_commit(P, CommitMode::Hiding);
    for key in [members[0], keys(1, 0xF00)[0]] {
        let want = u64::from(packed_contains(&words, &P, key));
        let noop: Modify = Rc::new(|_: &QLay, _: &mut Vec<C>, _: &mut Vec<C>| {});
        match q_attempt(&P, &words, key, PackedChecks::ALL, true, noop) {
            QVerdict::Accepted { proof, answer, splits } => {
                assert_eq!((splits, answer), (0, Val::from_u64(want)));
                assert_eq!(verify_decode_proof(&proof.output.0, &vk).unwrap().answer[0], Val::from_u64(want));
            }
            other => panic!("honest query through the forger: {}", qv_str(&other)),
        }
    }
}

/// A1, A2, A2b, A2c (and the carry and `c = 2` variants): the split-at-bit.
#[test]
fn a1_a2_split_at_bit_forgeries() {
    let init = prior(&P, 20);
    let ks = keys(7, 0x5000);
    split_attacks(&P, &init, &ks, &rig(&P, PackedChecks::ALL));
}

/// A batch (over `init`) with a repeated key and a word that two DIFFERENT
/// bits of two active pairs touch.
fn batch_with_collision(p: &BloomPackedParams, init: &[u8]) -> Vec<u64> {
    (0x5000u64..0x5400)
        .map(|seed| {
            let mut ks = keys(p.batch - 2, seed);
            ks.push(ks[0]);
            ks
        })
        .find(|ks| {
            let w = Wit::honest(p, init, ks);
            let ok = |d: bool| catch_msg(|| two_access_word(&w, d)).is_ok();
            ok(true) && ok(false)
        })
        .expect("a batch with a two-access word")
}

/// A3 (stale read), A4 (self / future read), A5 (tampered touched /
/// untouched final word), A11 (final-timestamp transplant).
#[test]
fn a3_a4_a5_a11_memory_checking_forgeries() {
    let init = prior(&P, 20);
    let ks = batch_with_collision(&P, &init);
    memory_checking_attacks(&P, &init, &ks, &rig(&P, PackedChecks::ALL));
}

/// A6: extension-valued old / new state bytes.
#[test]
fn a6_extension_valued_state_bytes() {
    let init = prior(&P, 20);
    let ks = keys(7, 0x5000);
    extension_byte_attacks(&P, &init, &ks, &rig(&P, PackedChecks::ALL));
}

/// A7: the non-canonical split (lookups, `HI_MAX − hi = dd`, the edge).
#[test]
fn a7_noncanonical_split_forgeries() {
    let init = prior(&P, 20);
    canonicity_attacks(&P, &init, &P12, &rig(&P, PackedChecks::ALL), &rig(&P12, PackedChecks::ALL));
}

/// A8: position-bit forgeries.
#[test]
fn a8_position_bit_forgeries() {
    let init = prior(&P, 20);
    let ks = keys(7, 0x5000);
    position_attacks(&P, &init, &ks, &rig(&P, PackedChecks::ALL));
}

/// Record and routing forgeries (`unused_limbs`, the digest connect,
/// `key_range`, `dummy_canon`).
#[test]
fn record_and_routing_forgeries() {
    let init = prior(&P, 20);
    let ks = keys(7, 0x5000);
    record_and_routing_attacks(&P, &init, &ks, &rig(&P, PackedChecks::ALL));
}

/// A9: query selector shift / wrong slice / wrong bit.
#[test]
fn a9_query_selector_forgeries() {
    query_selector_attacks(&P, 12);
}

/// The query's byte pins, selector booleans, split, bits and canonicity.
#[test]
fn query_value_forgeries() {
    query_value_attacks(&P, 12);
}

/// A10: the cross-family commitment.
#[test]
fn a10_cross_family_commitment() {
    let init = prior(&P, 20);
    let ks = keys(7, 0x5000);
    cross_family_attack(&P, &init, &ks, &rig(&P, PackedChecks::ALL), true);
}

/// A12 (documents the word size): every byte split is unique — for all
/// `v < 256`, `i < 8` exactly one `(H, c, L)` with `H < 256`, `c ∈ {0,1}`,
/// `L < e` satisfies `(2H + c)·e + L ≡ v (mod p)`, and it is the bit
/// decomposition — while a 16-bit word admits a second split with the OTHER
/// bit value (`(2·30,721 + 0)·2^15 ≡ 65,535`, whose bit 15 is 1).
#[test]
fn a12_word_size_split_uniqueness() {
    for v in 0..256u64 {
        for i in 0..8u64 {
            let e = 1u64 << i;
            let mut sols = Vec::new();
            for h in 0..256u64 {
                for c in 0..2u64 {
                    let l = (Val::from_u64(v) - Val::from_u64((2 * h + c) * e)).as_canonical_u64();
                    if l < e {
                        sols.push((h, c, l));
                    }
                }
            }
            assert_eq!(sols, vec![(v >> (i + 1), (v >> i) & 1, v & (e - 1))], "v = {v}, i = {i}");
        }
    }
    let (e, v) = (1u64 << 15, 65_535u64);
    let mut sols = Vec::new();
    for h in 0..1u64 << 16 {
        for c in 0..2u64 {
            let l = (Val::from_u64(v) - Val::from_u64((2 * h + c) * e)).as_canonical_u64();
            if l < e {
                sols.push((h, c, l));
            }
        }
    }
    assert!(sols.contains(&(0, 1, 32_767)) && sols.contains(&(30_721, 0, 0)), "16-bit splits: {sols:?}");
    eprintln!("A12: 16-bit word 65,535 at bit 15 has {} splits {sols:?}; bytes have exactly one", sols.len());
}

/// ConstAir binding regression at the trace level: a moved word-address
/// constant (P) and a moved timestamp constant (P24, a pure timestamp).
#[test]
fn const_binding_forgeries() {
    let init = prior(&P, 20);
    let ks = keys(7, 0x5000);
    word_address_attack(&P, &init, &ks, &rig(&P, PackedChecks::ALL));
    let init = prior(&P24, 20);
    let ks = keys(P24.batch - 1, 0x7A0);
    tau_attack(&P24, &init, &ks, &rig(&P24, PackedChecks::ALL));
}

/// Every leaf attack at the DEPLOYED filter shape (`k = 7`, `W = 2^14`,
/// `M_w = 14,336` bytes, a 16-slot batch over a 2,000-key prior; limb 7
/// absorbs the re-routes of slices 4–6).
#[test]
fn attacks_at_the_deployed_filter_shape_leaf() {
    let p = PD;
    let init = prior(&p, 2000);
    let ks = keys(p.batch - 1, 0x5000);
    let deployed = rig(&p, PackedChecks::ALL);
    split_attacks(&p, &init, &ks, &deployed);
    let ks_c = batch_with_collision(&p, &init);
    memory_checking_attacks(&p, &init, &ks_c, &deployed);
    extension_byte_attacks(&p, &init, &ks, &deployed);
    canonicity_attacks(&p, &init, &p, &deployed, &deployed);
    position_attacks(&p, &init, &ks, &deployed);
    record_and_routing_attacks(&p, &init, &ks, &deployed);
    cross_family_attack(&p, &init, &ks, &deployed, false);
}

/// Every query attack at the deployed filter shape (`64 × 32` selector).
#[test]
fn attacks_at_the_deployed_filter_shape_query() {
    query_selector_attacks(&PD, 2000);
    query_value_attacks(&PD, 2000);
}
