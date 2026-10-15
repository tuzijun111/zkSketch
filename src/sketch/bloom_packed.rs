//! **Packed-byte Bloom-filter leaf (`bloom_packed`, design B1, milestone M2)**
//! — the same partitioned Bloom filter as [`super::bloom_omc`], with its state
//! stored as BYTES instead of one field element per bit.
//!
//! ## Filter (unchanged, bit for bit)
//!
//! `k` slices of `W = 2^log_w` bits; a record `key` is hashed ONCE with
//! Poseidon2 (the [`record_vals`] / [`record_digest`] encoding of
//! `bloom_omc`) and digest limb `j < k` gives slice `j`'s position
//! `pos_j = digest[j] mod W` (canonical split). Insert sets the `k` bits, a
//! membership query ANDs them. The bit array is exactly `bloom_omc`'s:
//! [`bits_to_words`]`(bloom_insert(..)) == packed_insert(..)` and the query
//! answers are equal (tests `same_filter_as_bloom_omc*`, `query_answers_*`).
//!
//! ## State and commitment
//!
//! `M_w = k·W/8` bytes; word `u = j·W/8 + q` holds the bits
//! `j·W + 8q .. j·W + 8q + 7`, bit `i` of word `u` is global bit `8u + i`
//! (LSB first; [`bits_to_words`]). `Com(S)` absorbs the bytes 3 per base
//! limb (`w_0 + 2^8·w_1 + 2^16·w_2`, little-endian, zero-padded to a multiple
//! of 4 limbs; [`words_flat`]): `MyHash(limbs)` under `Plain`,
//! `MyHash([TAG_STATE, BloomPacked = 7, 0, 0, ρ] ‖ limbs)` under `Hiding`
//! ([`commit_packed_with`]). The batch commitment is `bloom_omc`'s record
//! sequence (`Plain`: byte-identical to [`super::bloom_omc::bloom_batch_commit`];
//! `Hiding`: family 7). Genesis is `Com(0^{M_w}; 0)`.
//!
//! ## Update relation: per-access timestamped memory checking, no sort
//!
//! The `L = k·batch` (record, slice) pairs are taken in record-major order
//! `p = r·k + j`; pair `p` reads and writes its word `u_p` once, at the public
//! timestamp `τ_p = p + 1` (Blum et al. / Spice):
//!
//! ```text
//!   WS = {(u, O_u, 0) : u < M_w}  ⊎  {(u_p, cur_p, τ_p) : p < L}
//!   RS = {(u, N_u, ft_u) : u < M_w} ⊎ {(u_p, v_p, ts_p) : p < L}
//!   WS == RS   (ONE Permute op over 4-coordinate elements a + b·X + c·X²)
//!   ts_p ≤ τ_p − 1   (d_p = τ_p − 1 − ts_p ∈ [0, 2^16))
//! ```
//!
//! Every coordinate of every element is pinned to the base field (`u` by
//! constants and the routing, `O, N` by byte lookups, `v, cur` by the split
//! below, `ts` by the gap bytes, `ft` by its two bytes), so the encoding is
//! injective. Write timestamps are distinct (`0` once per word, `τ_p` once per
//! pair) and every read consumes a strictly earlier write, so — by induction
//! over the pairs touching a word — pair `p` reads exactly the latest value of
//! `u_p` and the final read of every word consumes its last write (`N_u` is the
//! last `cur`, or `O_u` for an untouched word). There is only one Permute op,
//! so the fork's shared PermuteBus cannot mix multisets.
//!
//! The per-pair OR is proved with a **split-at-bit**: `e = 2^i` from the three
//! position bits, `v = (2H + c)·e + L` with `c ∈ {0,1}`, `H, L ∈ [0,256)` and
//! `e + 255 − L ∈ [0,256)` (i.e. `L < e`); since `v` is a byte (it equals a
//! write), `(2H + c)·e + L ≤ 511·128 + 127 < 2^16 ≪ p` is an exact integer
//! identity, so `c` is bit `i` of `v`, and
//! `cur = v + (act − act·c)·e = v OR act·2^i` (carry-free). A repeated bit
//! simply sees `c = 1`: no sort, no dedupe. Dummy records (`act = 0`) rewrite
//! their word unchanged. Words of 8 bits keep the split exact; 16-bit words
//! would wrap mod `p` (e.g. `H = 30,721`, `e = 2^15`), which is why bytes were
//! chosen (plan §2 B1).
//!
//! ## Constraint list (leaf)
//!
//! Private inputs, in allocation order: the 9 salts (`Hiding` only); `O_u`,
//! `N_u` (`M_w` each); `(flo_u, fhi_u)` per word; per record
//! `[b_0..b_7, act]` (the key's 8 bytes); per record the split witnesses
//! ([`split_count`]); per pair `[c, H, L, dlo, dhi]` ([`PAIR_WITNESSES`]).
//!
//! | # | constraint | gadget | test switch ([`PackedChecks`]) |
//! |---|---|---|---|
//! | A1 | `O_u, N_u ∈ [0,256)` | one byte lookup each | `o_pin`, `n_pin` |
//! | A2 | `ft_u = flo + 2^8·fhi`, bytes ∈ [0,256) | 1 `mul_add`, 2 lookups | `ft_range` |
//! | A3 | `Com(S_{t-1}) = H(pack(O))`, `Com(S_t) = H(pack(N))` | ALU packing, bound sponge | — |
//! | B1 | `act ∈ {0,1}`, key limb `k_j = b_{2j} + 2^8·b_{2j+1}`, bytes ∈ [0,256) | BoolCheck, 4 `mul_add`, 8 lookups | — |
//! | B2 | `act = 0 ⇒ k_0 + k_1 + k_2 + k_3 = 0` | 5 ALU | `dummy_canon` |
//! | B3 | `rec = [k0, k1, k2, k3 + 2^16·act]`, `h = Poseidon2(rec)` (zero IV) | ALU recompose, bound sponge | — |
//! | B4 | per slice: `i_0, i_1, i_2 ∈ {0,1}` | 3 BoolCheck | `i_bool` |
//! | B5 | per slice: `q` from its bytes, `q ∈ [0, 2^{log_w−3})` exact | Horner + lookups (+1 shifted lookup) | `q_range` |
//! | B6 | per slice: `hi` from bytes, `HI_MAX − hi` from bytes, `(HI_MAX − hi = 0) ⇒ pos = 0` | Horner + lookups, inverse trick | `canon` |
//! | B7 | `digest[j] = 2^log_w·hi + 8q + i_0 + 2i_1 + 4i_2`, unused limbs from 4 bytes; `recompose(limbs) = h` | ALU | — |
//! | B8 | `Com(B_t) = H(recs)`; Interval: `t` pinned, `H(TAG_LEAF, t, Com(B_t))` exposed | bound sponge | — |
//! | D1 | `e = (1 + i_0)(1 + 3i_1)(1 + 15i_2)` | 5 ALU | — |
//! | D2 | `c ∈ {0,1}` | BoolCheck | `c_bool` |
//! | D3 | `H ∈ [0,256)` | lookup | `h_range` |
//! | D4 | `L ∈ [0,256)` | lookup | `l_nonneg` |
//! | D5 | `L + 256 − e ∈ [0,256)` | 2 ALU + lookup | `l_lt_e` |
//! | D6 | `v = (2H + c)·e + L` | 2 ALU | — |
//! | D7 | `cur = v + (act − act·c)·e` | 2 ALU | — |
//! | D8 | `d = dlo + 2^8·dhi`, bytes ∈ [0,256); `ts = (τ_p − 1) − d` | 2 ALU + 2 lookups | `ts_lt_tau` |
//! | D9 | read `u + v·X + ts·X²`, write `u + cur·X + τ_p·X²` | 4 ALU | — |
//! | D10 | `[init writes] ‖ [pair writes]` is a permutation of `[final reads] ‖ [pair reads]` | one Permute op | — |
//!
//! `u = q + j·W/8` (word-address constants), `τ_p − 1` and `τ_p` are constants
//! (pooled with the word addresses), so soundness relies on the pinned fork's
//! ConstAir binding (constant values are in the VK; `const_values_are_bound`
//! below is the regression test). The routing hash, canonical split, key
//! encoding and dummy rule are `bloom_omc`'s (module doc there), computed with
//! byte witnesses instead of hint-decomposed range checks.
//!
//! **Changes from the 2026-10-14 prototype** (`latex/redesign_20261014/b1out`;
//! same relation, cheaper gadgets; see `docs` in the M2 report):
//! byte pins are direct RangeAir lookups (`add_range`, which forces the
//! three higher coefficients to zero and the base one into `[0,256)`, 0 ALU
//! ops) instead of `add_range_bits(x, 8)` (2 ALU ops each); every multi-byte
//! range (`ft`, the timestamp gap, `q`, `hi`, `HI_MAX − hi`, key limbs,
//! unused digest limbs) is recomposed from prover-witnessed bytes (1 ALU op
//! per extra byte) instead of `add_range_bits` (2 ALU ops per byte); `v` is the
//! split's ALU output, not a separate private input; `cur` uses one `mul_add`
//! for `act − act·c`; the timestamp is derived from its gap
//! (`ts = τ_p − 1 − d`); all three statement layouts ([`Expose`]) and the
//! hiding entry points (zero-salt guards, the public no-op path) are
//! implemented.
//!
//! Cost: `Θ(M_w + k·batch)`, dominated by the per-pair split and the dense
//! byte commitments (`M_w = M/8`).

use std::collections::HashMap;
use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_permute_trace, generate_poseidon2_trace,
    generate_range_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d4, poseidon2_preprocessor, range_air_builders, range_preprocessor,
        recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::commitment::hiding::{
    self, CommitFamily, CommitKind, CommitMode, Openings, SaltBb, SaltTargets,
};
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::sketch::bind::Binding;
use crate::sketch::bloom_omc::{
    BloomOmcParams, KEY_LIMB_BITS, MAX_K, bloom_addresses, hash_slice_bound, record_digest,
    record_vals,
};

const LOG_FINAL_POLY_LEN: usize = 6;
/// Bits per state word.
pub const WORD_BITS: usize = 8;
/// `act` sits at bit 16 of the fourth record coefficient (as in `bloom_omc`).
const ACT_SHIFT: u64 = 1u64 << KEY_LIMB_BITS;
/// Width of the timestamps and of the read-timestamp gap: `k·batch < 2^16`.
pub const TS_BITS: usize = 16;
/// The commitment family of the packed filter (salts and tags are keyed by it).
pub const FAMILY: CommitFamily = CommitFamily::BloomPacked;
/// Number of base values surfaced by the standalone ([`Expose::None`]) leaf.
pub const EXPOSED_LEN: usize = 3 * 8;
/// Private witnesses per (record, slice) pair: `[c, H, L, dlo, dhi]`.
pub const PAIR_WITNESSES: usize = 5;
/// Private witnesses per record before the split: the key's 8 bytes and `act`.
pub const RECORD_WITNESSES: usize = 9;

fn p_u64() -> u64 {
    <Val as PrimeField64>::ORDER_U64
}

// ─── Test switches ────────────────────────────────────────────────────────

/// Which checks a leaf / query circuit is BUILT with. Every field is `true`
/// in production; tests clear one at a time (via [`with_checks`]) to show the
/// check is load-bearing (positive controls). A cleared check keeps its
/// witnesses consumed by the remaining ALU rows, so the circuit still builds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PackedChecks {
    /// D2: `c ∈ {0,1}`.
    pub c_bool: bool,
    /// D3: `H ∈ [0,256)`.
    pub h_range: bool,
    /// D4: `L ∈ [0,256)` (`L ≥ 0`).
    pub l_nonneg: bool,
    /// D5: `L < e`.
    pub l_lt_e: bool,
    /// D8: the read-timestamp gap bytes (`ts ≤ τ − 1`).
    pub ts_lt_tau: bool,
    /// A2: the final-timestamp bytes.
    pub ft_range: bool,
    /// A1: the old-state byte pins.
    pub o_pin: bool,
    /// A1: the new-state byte pins.
    pub n_pin: bool,
    /// B4: the position bits.
    pub i_bool: bool,
    /// B5: the in-slice word index range.
    pub q_range: bool,
    /// B6: `hi ≤ HI_MAX` and the `hi = HI_MAX ⇒ pos = 0` edge.
    pub canon: bool,
    /// B2: dummy records are canonical.
    pub dummy_canon: bool,
    /// Query: the one-hot selector sums (`Σ s = 1`).
    pub onehot_sum: bool,
    /// Query: the opened cells' byte pins.
    pub cell_pin: bool,
}

impl PackedChecks {
    /// Every check on (the deployed circuits).
    pub const ALL: Self = PackedChecks {
        c_bool: true,
        h_range: true,
        l_nonneg: true,
        l_lt_e: true,
        ts_lt_tau: true,
        ft_range: true,
        o_pin: true,
        n_pin: true,
        i_bool: true,
        q_range: true,
        canon: true,
        dummy_canon: true,
        onehot_sum: true,
        cell_pin: true,
    };
}

thread_local! {
    static CHECKS: std::cell::Cell<PackedChecks> = const { std::cell::Cell::new(PackedChecks::ALL) };
}

/// Run `f` (which builds circuits) with `checks` in force on this thread,
/// then restore every check (test-only positive controls).
pub fn with_checks<T>(checks: PackedChecks, f: impl FnOnce() -> T) -> T {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            CHECKS.with(|c| c.set(PackedChecks::ALL));
        }
    }
    CHECKS.with(|c| c.set(checks));
    let _r = Restore;
    f()
}

pub(crate) fn checks() -> PackedChecks {
    CHECKS.with(|c| c.get())
}

/// Test-only: build the leaf with ONE constant moved (the ConstAir binding
/// regression): `Tau(p)` uses the constant `τ_p` (instead of `τ_p − 1`) in
/// pair `p`'s timestamp gap, `Word(u)` uses the address `u + 1` (mod `M_w`)
/// in word `u`'s init / final elements. Never set outside tests.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConstSkew {
    None,
    Tau(usize),
    Word(usize),
}

thread_local! {
    static SKEW: std::cell::Cell<ConstSkew> = const { std::cell::Cell::new(ConstSkew::None) };
}

/// Run `f` with the constant skew `s` in force (test-only; restored after).
pub fn with_skew<T>(s: ConstSkew, f: impl FnOnce() -> T) -> T {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            SKEW.with(|c| c.set(ConstSkew::None));
        }
    }
    SKEW.with(|c| c.set(s));
    let _r = Restore;
    f()
}

// ─── Parameters ───────────────────────────────────────────────────────────

/// Shape of a packed Bloom filter and its leaf: the same `(k, log_w, batch)`
/// as [`BloomOmcParams`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BloomPackedParams {
    /// Number of slices = hash positions per key (`1..=8`).
    pub k: usize,
    /// Bits per slice `W = 2^log_w` (`7..=20`).
    pub log_w: usize,
    /// Record slots per epoch; shorter batches are padded with canonical dummies.
    pub batch: usize,
}

impl From<BloomOmcParams> for BloomPackedParams {
    fn from(p: BloomOmcParams) -> Self {
        BloomPackedParams { k: p.k, log_w: p.log_w, batch: p.batch }
    }
}

impl BloomPackedParams {
    /// The bit-array filter with the same shape (same bits, same answers).
    pub fn omc(&self) -> BloomOmcParams {
        BloomOmcParams { k: self.k, log_w: self.log_w, batch: self.batch }
    }
    pub fn w(&self) -> usize {
        1 << self.log_w
    }
    /// Bits of the in-slice word index `q = pos >> 3`.
    pub fn q_bits(&self) -> usize {
        self.log_w - 3
    }
    /// Words per slice, `W/8`.
    pub fn words_per_slice(&self) -> usize {
        1 << self.q_bits()
    }
    /// State words `M_w = k·W/8`.
    pub fn m_words(&self) -> usize {
        self.k * self.words_per_slice()
    }
    /// Filter bits `M = k·W`.
    pub fn m_bits(&self) -> usize {
        self.k * self.w()
    }
    /// (record, slice) pairs per epoch, `L = k·batch`.
    pub fn pairs(&self) -> usize {
        self.k * self.batch
    }
    /// Base limbs of the state encoding (3 bytes each, padded to a multiple of 4).
    pub fn n_limbs(&self) -> usize {
        self.m_words().div_ceil(3).div_ceil(4) * 4
    }
    pub fn validate(&self) {
        if let Err(e) = self.check() {
            panic!("{e}");
        }
    }
    /// [`Self::validate`] without the panic.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=MAX_K).contains(&self.k) {
            return Err(format!("k must be in 1..={MAX_K}, got {}", self.k));
        }
        // log_w ≥ 7 keeps HI_MAX < 2^24 (3 bytes) and a whole number of bytes
        // per slice; log_w ≤ 20 as in bloom_omc.
        if !(7..=20).contains(&self.log_w) {
            return Err(format!("log_w must be in 7..=20, got {}", self.log_w));
        }
        if self.batch < 1 {
            return Err("batch must be ≥ 1".into());
        }
        if self.pairs() >= 1 << TS_BITS {
            return Err(format!(
                "k·batch = {} must be below 2^{TS_BITS} (16-bit timestamps; batch ≤ {} at k = {})",
                self.pairs(),
                ((1usize << TS_BITS) - 1) / self.k,
                self.k
            ));
        }
        Ok(())
    }
}

/// `HI_MAX = (p−1) / 2^log_w`.
fn hi_max(log_w: usize) -> u64 {
    let pm1 = p_u64() - 1;
    assert_eq!(pm1 % (1u64 << log_w), 0, "p−1 must be divisible by 2^log_w");
    pm1 >> log_w
}

/// Whole bytes that hold `HI_MAX` (both `hi` and `HI_MAX − hi` are taken
/// over this many bytes).
fn hi_bytes(log_w: usize) -> usize {
    let bl = 64 - hi_max(log_w).leading_zeros() as usize;
    bl.div_ceil(8)
}

/// Bytes of the in-slice word index.
fn q_bytes(log_w: usize) -> usize {
    (log_w - 3).div_ceil(8)
}

// ─── Native model ─────────────────────────────────────────────────────────

/// The empty filter (`M_w` zero bytes).
pub fn packed_empty(p: &BloomPackedParams) -> Vec<u8> {
    vec![0u8; p.m_words()]
}

/// Pack a `bloom_omc` bit array (one byte per bit) 8 bits per word, LSB first.
pub fn bits_to_words(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| c.iter().enumerate().fold(0u8, |acc, (i, &b)| acc | ((b & 1) << i)))
        .collect()
}

/// Inverse of [`bits_to_words`].
pub fn words_to_bits(words: &[u8]) -> Vec<u8> {
    words.iter().flat_map(|&w| (0..8).map(move |i| (w >> i) & 1)).collect()
}

/// Native insert of a batch — exactly the update the leaf proves.
pub fn packed_insert(words: &mut [u8], p: &BloomPackedParams, keys: &[u64]) {
    assert_eq!(words.len(), p.m_words());
    for &key in keys {
        for a in bloom_addresses(p.k, p.log_w, key) {
            words[a >> 3] |= 1 << (a & 7);
        }
    }
}

/// Native membership query (AND of the `k` bits).
pub fn packed_contains(words: &[u8], p: &BloomPackedParams, key: u64) -> bool {
    bloom_addresses(p.k, p.log_w, key).into_iter().all(|a| (words[a >> 3] >> (a & 7)) & 1 == 1)
}

/// The state encoding `Com(S)` absorbs: 3 bytes per base limb
/// (little-endian), limbs zero-padded to a multiple of 4.
pub fn words_flat(p: &BloomPackedParams, words: &[u8]) -> Vec<Val> {
    assert_eq!(words.len(), p.m_words(), "state must have M_w = k·W/8 bytes");
    (0..p.n_limbs())
        .map(|l| {
            let g = |s: usize| words.get(3 * l + s).copied().unwrap_or(0) as u64;
            Val::from_u64(g(0) | (g(1) << 8) | (g(2) << 16))
        })
        .collect()
}

/// `Com(S)` under `Plain`: `MyHash(words_flat(S))`.
pub fn commit_packed(p: &BloomPackedParams, words: &[u8]) -> [Val; 8] {
    MyHash::new(make_perm()).hash_iter(words_flat(p, words))
}

/// `Com(S; ρ)` under `mode`: `Plain` is [`commit_packed`] (salt ignored),
/// `Hiding` is `MyHash([TAG_STATE, BloomPacked, 0, 0, ρ] ‖ words_flat(S))`.
pub fn commit_packed_with(p: &BloomPackedParams, words: &[u8], mode: CommitMode, salt: &SaltBb) -> [Val; 8] {
    hiding::commit_flat_bb(mode, CommitKind::State, FAMILY, salt, &words_flat(p, words))
}

fn padded_slots(batch: usize, keys: &[u64]) -> Vec<Option<u64>> {
    assert!(keys.len() <= batch, "{} keys exceed batch {}", keys.len(), batch);
    let mut v: Vec<Option<u64>> = keys.iter().map(|&k| Some(k)).collect();
    v.resize(batch, None);
    v
}

/// `Com(B_t)` under `Plain` over the `batch` padded record slots — the same
/// value as [`super::bloom_omc::bloom_batch_commit`].
pub fn packed_batch_commit(batch: usize, keys: &[u64]) -> [Val; 8] {
    packed_batch_commit_with(batch, keys, CommitMode::Plain, &SaltBb::ZERO)
}

/// `Com(B_t; ρ)` under `mode` (`Hiding`: family 7).
pub fn packed_batch_commit_with(batch: usize, keys: &[u64], mode: CommitMode, salt: &SaltBb) -> [Val; 8] {
    let flat: Vec<Val> = padded_slots(batch, keys).into_iter().flat_map(record_vals).collect();
    hiding::commit_flat_bb(mode, CommitKind::Batch, FAMILY, salt, &flat)
}

/// Per used digest limb `(q, i)`: word index in the slice and bit in the word.
pub fn packed_positions(p: &BloomPackedParams, key: Option<u64>) -> Vec<(u64, u64)> {
    let d = record_digest(key);
    (0..p.k)
        .map(|j| {
            let pos = d[j].as_canonical_u64() & ((1u64 << p.log_w) - 1);
            (pos >> 3, pos & 7)
        })
        .collect()
}

/// Little-endian bytes of `x`.
fn bytes_of(x: u64, n: usize) -> impl Iterator<Item = Val> {
    (0..n).map(move |i| Val::from_u64((x >> (8 * i)) & 0xFF))
}

/// Split witnesses per record: per used limb `[q bytes, i0, i1, i2, hi bytes,
/// (HI_MAX − hi) bytes, dinv]`, then 4 bytes per unused limb.
pub fn split_count(p: &BloomPackedParams) -> usize {
    let per = q_bytes(p.log_w) + 3 + 2 * hi_bytes(p.log_w) + 1;
    per * p.k + 4 * (MAX_K - p.k)
}

/// Native split witnesses of one record (layout of [`split_count`]).
pub(crate) fn split_values(p: &BloomPackedParams, key: Option<u64>) -> Vec<Val> {
    let d = record_digest(key);
    let (nq, nh, hm) = (q_bytes(p.log_w), hi_bytes(p.log_w), hi_max(p.log_w));
    let mut out = Vec::with_capacity(split_count(p));
    for (t, &limb) in d.iter().enumerate() {
        let x = limb.as_canonical_u64();
        if t < p.k {
            let pos = x & ((1u64 << p.log_w) - 1);
            let hi = x >> p.log_w;
            let (q, i) = (pos >> 3, pos & 7);
            let dd = hm - hi;
            out.extend(bytes_of(q, nq));
            out.extend([i & 1, (i >> 1) & 1, (i >> 2) & 1].map(Val::from_u64));
            out.extend(bytes_of(hi, nh));
            out.extend(bytes_of(dd, nh));
            out.push(Val::from_u64(dd).try_inverse().unwrap_or(Val::ZERO));
        } else {
            out.extend(bytes_of(x, 4));
        }
    }
    out
}

/// The record's 8 key bytes and `act` (a dummy is all zero).
pub(crate) fn record_witness(key: Option<u64>) -> [Val; RECORD_WITNESSES] {
    let mut w = [Val::ZERO; RECORD_WITNESSES];
    if let Some(k) = key {
        for (i, b) in bytes_of(k, 8).enumerate() {
            w[i] = b;
        }
        w[8] = Val::ONE;
    }
    w
}

/// Read `(init, final, batch)` from a standalone ([`Expose::None`]) leaf proof.
pub fn read_exposed_commitments(proof: &BatchStarkProof<ConfigWithFriParams>) -> ([Val; 8], [Val; 8], [Val; 8]) {
    let pv = proof
        .non_primitives
        .iter()
        .map(|e| &e.public_values)
        .find(|v| v.len() == EXPOSED_LEN)
        .expect("packed bloom leaf proof must expose (init, final, batch)");
    let take = |o: usize| -> [Val; 8] { std::array::from_fn(|i| pv[o + i]) };
    (take(0), take(8), take(16))
}

// ─── In-circuit gadgets ───────────────────────────────────────────────────

/// Constants shared by the leaf and query gadgets.
pub(crate) struct PConsts {
    pub(crate) one: ExprId,
    pub(crate) zero: ExprId,
    two: ExprId,
    three: ExprId,
    four: ExprId,
    eight: ExprId,
    fifteen: ExprId,
    c256: ExprId,
    c65536: ExprId,
    act_shift: ExprId,
    pow_log_w: ExprId,
    hi_max: ExprId,
    /// `j·W/8` word offsets (index 0 unused).
    word_off: Vec<ExprId>,
    pub(crate) e1: ExprId,
    pub(crate) e2: ExprId,
}

impl PConsts {
    pub(crate) fn new(b: &mut CircuitBuilder<Challenge>, p: &BloomPackedParams) -> Self {
        let basis = |i: usize| -> Challenge {
            let mut c = [Val::ZERO; 4];
            c[i] = Val::ONE;
            Challenge::from_basis_coefficients_slice(&c).unwrap()
        };
        let mut c = |v: u64| b.alloc_const(Challenge::from_u64(v), "packed_const");
        let one = c(1);
        let zero = c(0);
        let two = c(2);
        let three = c(3);
        let four = c(4);
        let eight = c(8);
        let fifteen = c(15);
        let c256 = c(256);
        let c65536 = c(65536);
        let act_shift = c(ACT_SHIFT);
        let pow_log_w = c(1u64 << p.log_w);
        let hi_max = c(hi_max(p.log_w));
        let word_off = (0..p.k).map(|j| c((j * p.words_per_slice()) as u64)).collect();
        PConsts {
            one,
            zero,
            two,
            three,
            four,
            eight,
            fifteen,
            c256,
            c65536,
            act_shift,
            pow_log_w,
            hi_max,
            word_off,
            e1: b.alloc_const(basis(1), "X"),
            e2: b.alloc_const(basis(2), "X^2"),
        }
    }
}

/// One byte lookup: `x ∈ [0,256)` and its three higher coefficients zero. No
/// ALU op; `x` must have a WitnessChecks creator (an ALU output, or a private
/// input that some ALU row uses) and be defined before this op runs.
pub(crate) fn byte_pin(b: &mut CircuitBuilder<Challenge>, x: ExprId) {
    b.add_range(&[x]).expect("byte lookup");
}

/// `x = Σ_i 2^{8i}·bytes[i]` (Horner, `len − 1` ALU ops) with every byte in
/// `[0,256)` and, when `n` is not a multiple of 8, the top byte `< 2^{n mod 8}`
/// (one more `mul` and lookup), so `x ∈ [0, 2^n)` exactly when `check`.
pub(crate) fn from_bytes(b: &mut CircuitBuilder<Challenge>, c: &PConsts, bytes: &[ExprId], n: usize, check: bool) -> ExprId {
    let k = n.div_ceil(8);
    assert_eq!(bytes.len(), k, "{n}-bit value from {} bytes", bytes.len());
    let r = n - 8 * (k - 1);
    let top = bytes[k - 1];
    let mut acc = top;
    for i in (0..k - 1).rev() {
        acc = b.mul_add(acc, c.c256, bytes[i]);
    }
    if check {
        for &x in bytes {
            byte_pin(b, x);
        }
        if r < 8 {
            let shift = b.alloc_const(Challenge::from_u64(1u64 << (8 - r)), "top_byte_shift");
            let s = b.mul(top, shift);
            byte_pin(b, s);
        }
    }
    acc
}

/// `e = 2^i` from the three bits of `i`: `(1 + i_0)(1 + 3i_1)(1 + 15i_2)`.
pub(crate) fn pow2_of_bits(b: &mut CircuitBuilder<Challenge>, c: &PConsts, ib: &[ExprId; 3]) -> ExprId {
    let f0 = b.add(ib[0], c.one);
    let f1 = b.mul_add(ib[1], c.three, c.one);
    let f2 = b.mul_add(ib[2], c.fifteen, c.one);
    let e01 = b.mul(f0, f1);
    b.mul(e01, f2)
}

/// Split-at-bit: returns `v = (2H + c)·e + L` after constraining `c ∈ {0,1}`,
/// `H, L ∈ [0,256)` and `L < e` (each behind its [`PackedChecks`] switch). For
/// a byte `v` this is an exact integer identity, so `c` is bit `log2 e` of `v`.
pub(crate) fn split_at_bit(
    b: &mut CircuitBuilder<Challenge>,
    c: &PConsts,
    e: ExprId,
    cbit: ExprId,
    hh: ExprId,
    ll: ExprId,
    ck: &PackedChecks,
) -> ExprId {
    if ck.c_bool {
        b.assert_bool(cbit);
    }
    let hc = b.mul_add(hh, c.two, cbit);
    let v = b.mul_add(hc, e, ll);
    if ck.h_range {
        byte_pin(b, hh);
    }
    if ck.l_nonneg {
        byte_pin(b, ll);
    }
    if ck.l_lt_e {
        // L + 256 − e ∈ [0,256) with L ∈ [0,256), e ∈ [1,128]: L < e.
        let em = b.sub(e, c.c256);
        let w = b.sub(ll, em);
        byte_pin(b, w);
    }
    v
}

/// Pack bytes (each already byte-pinned) 3 per base limb and 4 limbs per
/// Challenge through the ALU, matching [`words_flat`].
pub(crate) fn pack_words(b: &mut CircuitBuilder<Challenge>, c: &PConsts, p: &BloomPackedParams, words: &[ExprId]) -> Vec<ExprId> {
    let limbs: Vec<ExprId> = (0..p.n_limbs())
        .map(|l| {
            let g = |s: usize| words.get(3 * l + s).copied();
            match (g(0), g(1), g(2)) {
                (None, _, _) => c.zero,
                (Some(w0), None, _) => b.mul_add(w0, c.one, c.zero),
                (Some(w0), Some(w1), None) => b.mul_add(w1, c.c256, w0),
                (Some(w0), Some(w1), Some(w2)) => {
                    let t = b.mul_add(w1, c.c256, w0);
                    b.mul_add(w2, c.c65536, t)
                }
            }
        })
        .collect();
    limbs
        .chunks(4)
        .map(|ch| b.recompose_base_coeffs_to_ext_via_alu::<Val>(ch).expect("pack limbs"))
        .collect()
}

/// An in-circuit commitment of the packed family with the bound sponge:
/// `hash_slice_bound(inputs)` (`Plain`) or
/// `hash_slice_bound([tag(kind, BloomPacked), salt, inputs…])` (`Hiding`).
pub(crate) fn commit_hash_packed(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    kind: CommitKind,
    salt: Option<&SaltTargets>,
    inputs: &[ExprId],
    zero: ExprId,
) -> Vec<ExprId> {
    match salt {
        None => hash_slice_bound(b, cfg, inputs, zero),
        Some(st) => {
            let salted = hiding::salted_hash_inputs::<Val, Challenge>(b, kind, FAMILY, st, inputs);
            hash_slice_bound(b, cfg, &salted, zero)
        }
    }
}

/// One routed slice of a record: the word address `u = j·W/8 + q`, the word
/// index `q` and the three position bits.
pub(crate) struct Route {
    pub(crate) u: ExprId,
    pub(crate) q: ExprId,
    pub(crate) ib: [ExprId; 3],
}

/// Record routing shared by the leaf and the membership query: key limbs from
/// the 8 byte witnesses, the record Challenge `[k0, k1, k2, k3 + 2^16·act]`,
/// its bound Poseidon2 digest, and per used limb the canonical split
/// `digest[j] = 2^log_w·hi + 8q + i` (bytes / bits as private witnesses,
/// [`split_count`] layout). Returns `(record, limbs [k0..k3], routes)`; `act`
/// must already be boolean.
pub(crate) fn route_packed(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    c: &PConsts,
    p: &BloomPackedParams,
    key_bytes: &[ExprId],
    act: ExprId,
    split: &[ExprId],
    ck: &PackedChecks,
) -> (ExprId, [ExprId; 4], Vec<Route>) {
    assert_eq!(key_bytes.len(), 8);
    assert_eq!(split.len(), split_count(p));
    let limbs: [ExprId; 4] =
        std::array::from_fn(|j| from_bytes(b, c, &key_bytes[2 * j..2 * j + 2], KEY_LIMB_BITS, true));
    let l3 = b.mul_add(act, c.act_shift, limbs[3]);
    let rec = b
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&[limbs[0], limbs[1], limbs[2], l3])
        .expect("record");
    let h = hash_slice_bound(b, cfg, &[rec], c.zero);
    let (nq, nh) = (q_bytes(p.log_w), hi_bytes(p.log_w));
    let mut digest_limbs = Vec::with_capacity(MAX_K);
    let mut routes = Vec::with_capacity(p.k);
    let mut it = split.iter().copied();
    let mut take = |n: usize| -> Vec<ExprId> { (0..n).map(|_| it.next().unwrap()).collect() };
    for t in 0..MAX_K {
        if t < p.k {
            let qb = take(nq);
            let ibv = take(3);
            let ib: [ExprId; 3] = [ibv[0], ibv[1], ibv[2]];
            let hib = take(nh);
            let ddb = take(nh);
            let dinv = take(1)[0];
            if ck.i_bool {
                for &x in &ib {
                    b.assert_bool(x);
                }
            }
            let q = from_bytes(b, c, &qb, p.q_bits(), ck.q_range);
            let t1 = b.mul_add(ib[1], c.two, ib[0]);
            let i = b.mul_add(ib[2], c.four, t1);
            let pos = b.mul_add(q, c.eight, i);
            // hi ∈ [0, 2^{8nh}) and HI_MAX − hi ∈ [0, 2^{8nh}) ⇒ hi ≤ HI_MAX
            // (both < 2^24, no wrap); HI_MAX − hi = 0 ⇒ pos = 0.
            let hi = from_bytes(b, c, &hib, 8 * nh, ck.canon);
            let dd = from_bytes(b, c, &ddb, 8 * nh, ck.canon);
            if ck.canon {
                let d = b.sub(c.hi_max, hi);
                b.connect(d, dd);
                let e = b.mul(dd, dinv);
                let z = b.sub(c.one, e);
                let chk = b.mul(pos, z);
                b.connect(chk, c.zero);
            } else {
                // Keep `dd` and `dinv` consumed by an ALU row.
                let _ = b.mul(dd, dinv);
            }
            digest_limbs.push(b.mul_add(hi, c.pow_log_w, pos));
            let u = if t == 0 { q } else { b.add(q, c.word_off[t]) };
            routes.push(Route { u, q, ib });
        } else {
            // Unused limb: only needs to be base-field (four byte lookups) so
            // the recomposition below is unique.
            let ub = take(4);
            digest_limbs.push(from_bytes(b, c, &ub, 32, true));
        }
    }
    let h0 = b.recompose_base_coeffs_to_ext_via_alu::<Val>(&digest_limbs[0..4]).expect("digest lo");
    let h1 = b.recompose_base_coeffs_to_ext_via_alu::<Val>(&digest_limbs[4..8]).expect("digest hi");
    b.connect(h0, h[0]);
    b.connect(h1, h[1]);
    (rec, limbs, routes)
}

fn pack_commit(c: &[Val; 8]) -> [Challenge; 2] {
    pack_commit_to_challenge(&CountMinCommit(*c))
}

// ─── Leaf ──────────────────────────────────────────────────────────────────

/// A self-verified packed Bloom leaf proof (commitments computed natively).
pub struct BloomPackedProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: CountMinCommit,
    pub final_commit: CountMinCommit,
    pub batch_commit: CountMinCommit,
    pub final_words: Vec<u8>,
    pub params: BloomPackedParams,
}

impl BloomPackedProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

/// Where a (tampered) epoch was rejected.
#[derive(Debug)]
pub enum PackedProveError {
    /// The honest witness runner refused (an unsatisfied `connect`).
    Run(String),
    /// Trace → proof failed (a constraint or bus failed while proving).
    Prove(String),
    /// The self-verifier rejected the proof.
    Verify(String),
}

/// A built, reusable packed Bloom leaf. Build once per shape; each epoch
/// swaps in its permutation.
pub struct BloomPackedLeafCircuit {
    params: BloomPackedParams,
    expose: Expose,
    mode: CommitMode,
    pub(crate) circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    table_rows: Vec<usize>,
}

/// The standalone leaf (`Expose::None`, `Plain`).
pub fn build_bloom_packed_leaf(params: BloomPackedParams) -> BloomPackedLeafCircuit {
    build_bloom_packed_leaf_commit(params, Expose::None, CommitMode::Plain)
}

/// [`build_bloom_packed_leaf_commit`] under `Plain`.
pub fn build_bloom_packed_leaf_expose(params: BloomPackedParams, expose: Expose) -> BloomPackedLeafCircuit {
    build_bloom_packed_leaf_commit(params, expose, CommitMode::Plain)
}

/// Build the packed leaf with statement layout `expose` (as
/// `bloom_omc::build_bloom_omc_leaf_expose`: `None` = 24 values
/// `(init, final, batch)`, `Boundary` = `(init, final)`, `Interval` = the
/// 28-value composition statement) under commitment mode `mode` (`Hiding`:
/// the 9 salts are the first private inputs).
pub fn build_bloom_packed_leaf_commit(
    params: BloomPackedParams,
    expose: Expose,
    mode: CommitMode,
) -> BloomPackedLeafCircuit {
    params.validate();
    let p = &params;
    let (mw, l, batch) = (p.m_words(), p.pairs(), p.batch);
    let ck = checks();
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    b.enable_expose(generate_expose_trace::<Val, Challenge>);

    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));
    match expose {
        Expose::None => b
            .add_expose(&[init_pis[0], init_pis[1], final_pis[0], final_pis[1], batch_pis[0], batch_pis[1]])
            .expect("expose (init, final, batch)"),
        Expose::Boundary => b
            .add_expose(&[init_pis[0], init_pis[1], final_pis[0], final_pis[1]])
            .expect("expose (init, final)"),
        Expose::Interval => {}
    }
    let c = PConsts::new(&mut b, p);
    // Word addresses 0..M_w and timestamps 0..L (pooled by value).
    let word_const: Vec<ExprId> = (0..mw).map(|u| b.alloc_const(Challenge::from_u64(u as u64), "u")).collect();
    let tau_const: Vec<ExprId> = (0..=l).map(|t| b.alloc_const(Challenge::from_u64(t as u64), "tau")).collect();

    // ── Private inputs (allocation order == push order in the prover) ──
    let salts = hiding::alloc_leaf_salts(&mut b, mode);
    let o: Vec<ExprId> = (0..mw).map(|_| b.alloc_private_input("o")).collect();
    let n: Vec<ExprId> = (0..mw).map(|_| b.alloc_private_input("n")).collect();
    let ftb: Vec<[ExprId; 2]> = (0..mw).map(|_| std::array::from_fn(|_| b.alloc_private_input("ft"))).collect();
    let rec_w: Vec<Vec<ExprId>> =
        (0..batch).map(|_| (0..RECORD_WITNESSES).map(|_| b.alloc_private_input("rec")).collect()).collect();
    let split_w: Vec<Vec<ExprId>> =
        (0..batch).map(|_| (0..split_count(p)).map(|_| b.alloc_private_input("split")).collect()).collect();
    let pair_w: Vec<[ExprId; PAIR_WITNESSES]> =
        (0..l).map(|_| std::array::from_fn(|_| b.alloc_private_input("pair"))).collect();

    // ── Stage A: the two dense states and their commitments ──
    let skew = SKEW.with(|s| s.get());
    let mut input: Vec<ExprId> = Vec::with_capacity(mw + l);
    let mut target: Vec<ExprId> = Vec::with_capacity(mw + l);
    for u in 0..mw {
        let ft = from_bytes(&mut b, &c, &ftb[u], TS_BITS, ck.ft_range);
        let addr = if skew == ConstSkew::Word(u) { word_const[(u + 1) % mw] } else { word_const[u] };
        input.push(b.mul_add(o[u], c.e1, addr)); // init write (u, O_u, 0)
        let fr = b.mul_add(n[u], c.e1, addr);
        target.push(b.mul_add(ft, c.e2, fr)); // final read (u, N_u, ft_u)
    }
    let init_packed = pack_words(&mut b, &c, p, &o);
    let final_packed = pack_words(&mut b, &c, p, &n);
    for u in 0..mw {
        if ck.o_pin {
            byte_pin(&mut b, o[u]);
        }
        if ck.n_pin {
            byte_pin(&mut b, n[u]);
        }
    }
    let dig_init = commit_hash_packed(&mut b, &cfg, CommitKind::State, salts.as_ref().map(|s| &s.init), &init_packed, c.zero);
    let dig_final =
        commit_hash_packed(&mut b, &cfg, CommitKind::State, salts.as_ref().map(|s| &s.final_), &final_packed, c.zero);
    for i in 0..DIGEST_PACKING {
        b.connect(dig_init[i], init_pis[i]);
        b.connect(dig_final[i], final_pis[i]);
    }

    // ── Stage B: records → batch commitment; digests → canonical word positions ──
    let mut recs = Vec::with_capacity(batch);
    let mut routes: Vec<(ExprId, ExprId, Route)> = Vec::with_capacity(l); // (act, act − act·c helper, route)
    for r in 0..batch {
        let act = rec_w[r][8];
        b.assert_bool(act);
        let (rec, limbs, out) = route_packed(&mut b, &cfg, &c, p, &rec_w[r][0..8], act, &split_w[r], &ck);
        if ck.dummy_canon {
            // act = 0 ⇒ k0 + k1 + k2 + k3 = 0 ⇒ every limb 0 (each < 2^16).
            let s01 = b.add(limbs[0], limbs[1]);
            let s012 = b.add(s01, limbs[2]);
            let s = b.add(s012, limbs[3]);
            let oma = b.sub(c.one, act);
            let dchk = b.mul(oma, s);
            b.connect(dchk, c.zero);
        }
        let nact = b.sub(c.zero, act);
        recs.push(rec);
        for route in out {
            routes.push((act, nact, route));
        }
    }
    let hb = commit_hash_packed(&mut b, &cfg, CommitKind::Batch, salts.as_ref().map(|s| &s.batch), &recs, c.zero);
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_pis[i]);
    }
    if expose.is_interval() {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b, &cfg, &init_pis, &final_pis, &hb, c.zero, Binding::Bound, IndexPin::Range,
        );
    }

    // ── Stage D: per-access timestamped memory checking over words ──
    for (pidx, (act, nact, route)) in routes.iter().enumerate() {
        let [cbit, hh, ll, dlo, dhi] = pair_w[pidx];
        let e = pow2_of_bits(&mut b, &c, &route.ib);
        let v = split_at_bit(&mut b, &c, e, cbit, hh, ll, &ck);
        // a = act − act·c = act·(1 − c); cur = v + a·e = v OR act·2^i.
        let a = b.mul_add(*nact, cbit, *act);
        let cur = b.mul_add(a, e, v);
        // ts = (τ_p − 1) − d, d = dlo + 2^8·dhi ∈ [0, 2^16): ts ≤ τ_p − 1.
        let d = from_bytes(&mut b, &c, &[dlo, dhi], TS_BITS, ck.ts_lt_tau);
        let tau_m1 = if skew == ConstSkew::Tau(pidx) { tau_const[pidx + 1] } else { tau_const[pidx] };
        let ts = b.sub(tau_m1, d);
        let rd0 = b.mul_add(v, c.e1, route.u);
        target.push(b.mul_add(ts, c.e2, rd0)); // read (u, v, ts)
        let wr0 = b.mul_add(cur, c.e1, route.u);
        input.push(b.mul_add(tau_const[pidx + 1], c.e2, wr0)); // write (u, cur, τ)
    }
    let permuted = b.add_permute(&input, (0..mw + l).collect()).expect("permute (memory checking)");
    for i in 0..mw + l {
        b.connect(permuted[i], target[i]);
    }

    let circuit = b.build().expect("build bloom_packed leaf");
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
        .expect("get_airs_and_degrees_with_prep (bloom_packed)");
    crate::experiments::table_probe::record_leaf(
        "bloom_packed",
        &table_packing,
        &airs_degrees,
        &non_primitive_columns,
        &primitive_columns,
    );
    crate::experiments::table_probe::maybe_stop();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(cfg);
    prover.register_recompose_table::<4>(cfg.d() != 4);
    prover.register_permute_table::<4>();
    prover.register_range_table::<4>();
    prover.register_expose_table::<4>();
    BloomPackedLeafCircuit {
        params,
        expose,
        mode,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
        table_rows: ext_degrees.iter().map(|&d| 1usize << d).collect(),
    }
}

// ─── Native epoch witness ─────────────────────────────────────────────────

/// One (record, slice) pair as the circuit sees it. Field values, so a test
/// may plant out-of-range ("negative") witnesses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct PairWit {
    /// Word address `u_p`.
    pub(crate) u: u64,
    /// `e = 2^i` as the circuit computes it from the position bits (a test
    /// may plant non-boolean bits, hence any field value).
    pub(crate) e: Val,
    pub(crate) act: u64,
    /// `[c, H, L, dlo, dhi]`.
    pub(crate) w: [Val; PAIR_WITNESSES],
    /// The read value `v` and timestamp `ts`, and the written `cur` (as the
    /// circuit computes them from `w`).
    pub(crate) v: Val,
    pub(crate) ts: Val,
    pub(crate) cur: Val,
}

/// The prover's witness for one epoch (all private inputs but the salts,
/// plus the permutation).
#[derive(Clone, Debug)]
pub(crate) struct PackedWitness {
    pub(crate) recs: Vec<Option<u64>>,
    pub(crate) split: Vec<Vec<Val>>,
    pub(crate) pairs: Vec<PairWit>,
    pub(crate) initial: Vec<Val>,
    pub(crate) final_words: Vec<Val>,
    pub(crate) ft: Vec<Val>,
    pub(crate) sigma: Vec<usize>,
}

impl PairWit {
    /// Recompute `v`, `ts`, `cur` from the witnesses as the circuit does
    /// (`τ_p − 1 = pidx`).
    pub(crate) fn derive(&mut self, pidx: usize) {
        let [c, h, l, dlo, dhi] = self.w;
        let e = self.e;
        self.v = (h + h + c) * e + l;
        let act = Val::from_u64(self.act);
        self.cur = self.v + (act - act * c) * e;
        self.ts = Val::from_u64(pidx as u64) - (dlo + Val::from_u64(256) * dhi);
    }
}

type Elem = (Val, Val, Val);

impl PackedWitness {
    /// `(input, target)` multisets of the Permute op, in circuit order.
    pub(crate) fn elements(&self) -> (Vec<Elem>, Vec<Elem>) {
        let mw = self.initial.len();
        let mut input: Vec<Elem> = (0..mw).map(|u| (Val::from_u64(u as u64), self.initial[u], Val::ZERO)).collect();
        let mut target: Vec<Elem> = (0..mw).map(|u| (Val::from_u64(u as u64), self.final_words[u], self.ft[u])).collect();
        for (pidx, pr) in self.pairs.iter().enumerate() {
            input.push((Val::from_u64(pr.u), pr.cur, Val::from_u64(pidx as u64 + 1)));
            target.push((Val::from_u64(pr.u), pr.v, pr.ts));
        }
        (input, target)
    }

    /// σ with `input[σ[i]] == target[i]` where one exists; best effort
    /// otherwise (an unmatchable witness is then refused by the runner or
    /// rejected in-circuit, never silently fixed here).
    pub(crate) fn match_sigma(&mut self) -> usize {
        let (input, target) = self.elements();
        let mut buckets: HashMap<Elem, Vec<usize>> = HashMap::new();
        for (idx, e) in input.iter().enumerate().rev() {
            buckets.entry(*e).or_default().push(idx);
        }
        let mut sigma: Vec<Option<usize>> = target.iter().map(|t| buckets.get_mut(t).and_then(|v| v.pop())).collect();
        let mut left: Vec<usize> = buckets.into_values().flatten().collect();
        let unmatched = sigma.iter().filter(|s| s.is_none()).count();
        for s in sigma.iter_mut() {
            if s.is_none() {
                *s = left.pop();
            }
        }
        self.sigma = sigma.into_iter().map(|s| s.unwrap()).collect();
        unmatched
    }

    /// The new state as bytes (panics on a non-byte value).
    #[cfg(test)]
    pub(crate) fn final_bytes(&self) -> Vec<u8> {
        self.final_words
            .iter()
            .map(|x| u8::try_from(x.as_canonical_u64()).expect("final word is a byte"))
            .collect()
    }
}

/// The honest witness of one epoch from `initial` and `keys`.
pub(crate) fn epoch_witness(p: &BloomPackedParams, initial: &[u8], keys: &[u64]) -> PackedWitness {
    let (mw, wps) = (p.m_words(), p.words_per_slice() as u64);
    let recs = padded_slots(p.batch, keys);
    let mut split = Vec::with_capacity(recs.len());
    let mut words: Vec<u64> = initial.iter().map(|&w| w as u64).collect();
    let mut last = vec![0u64; mw];
    let mut pairs = Vec::with_capacity(p.pairs());
    for rec in &recs {
        split.push(split_values(p, *rec));
        let act = u64::from(rec.is_some());
        for (j, (q, i)) in packed_positions(p, *rec).into_iter().enumerate() {
            let pidx = pairs.len();
            let u = j as u64 * wps + q;
            let uu = u as usize;
            let (v, ts) = (words[uu], last[uu]);
            let e = 1u64 << i;
            let d = pidx as u64 - ts;
            let w = [(v >> i) & 1, v >> (i + 1), v & (e - 1), d & 0xFF, d >> 8].map(Val::from_u64);
            let mut pr = PairWit { u, e: Val::from_u64(e), act, w, v: Val::ZERO, ts: Val::ZERO, cur: Val::ZERO };
            pr.derive(pidx);
            debug_assert_eq!(pr.v, Val::from_u64(v));
            debug_assert_eq!(pr.ts, Val::from_u64(ts));
            let cur = v | (act << i);
            debug_assert_eq!(pr.cur, Val::from_u64(cur));
            words[uu] = cur;
            last[uu] = pidx as u64 + 1;
            pairs.push(pr);
        }
    }
    let mut wit = PackedWitness {
        recs,
        split,
        pairs,
        initial: initial.iter().map(|&w| Val::from_u8(w)).collect(),
        final_words: words.iter().map(|&w| Val::from_u64(w)).collect(),
        ft: last.iter().map(|&t| Val::from_u64(t)).collect(),
        sigma: Vec::new(),
    };
    let unmatched = wit.match_sigma();
    assert_eq!(unmatched, 0, "honest memory-checking matching must exist");
    wit
}

impl BloomPackedLeafCircuit {
    pub fn params(&self) -> BloomPackedParams {
        self.params
    }
    /// `Σ 2^degree` over all tables.
    pub fn trace_rows(&self) -> u64 {
        self.trace_rows
    }
    /// Padded height of each table (AIR order).
    pub fn table_rows(&self) -> &[usize] {
        &self.table_rows
    }
    pub fn expose(&self) -> Expose {
        self.expose
    }
    pub fn commit_mode(&self) -> CommitMode {
        self.mode
    }

    /// The VK pin values (preprocessed commitment) of every proof this leaf
    /// produces, read from its prover data without proving
    /// ([`crate::recursion::recursive::expose_forest::common_vk_pin_values`]).
    pub fn vk_values(&self) -> Vec<Challenge> {
        crate::recursion::recursive::expose_forest::common_vk_pin_values(&self.circuit_prover_data.prover_data.common)
    }

    /// Prove one epoch at batch index 1 (`Plain` only); panics on rejection.
    pub fn prove_epoch(&mut self, initial: &[u8], keys: &[u64]) -> BloomPackedProof {
        self.prove_epoch_at(1, initial, keys)
    }

    /// Prove batch `t` (1-based; part of the Interval statement). `Plain`
    /// circuits only (a `Hiding` circuit would publish `Com(S; 0)`).
    pub fn prove_epoch_at(&mut self, t: u64, initial: &[u8], keys: &[u64]) -> BloomPackedProof {
        self.try_prove_epoch_at(t, initial, keys)
            .unwrap_or_else(|e| panic!("bloom_packed epoch rejected: {e:?}"))
    }

    /// [`Self::prove_epoch_at`] with the openings of leaf `t`
    /// (`Openings::for_leaf(seed, CommitFamily::BloomPacked, t)` for an honest
    /// prover; ignored under `Plain`). A `Hiding` circuit refuses the public
    /// zero salt on the final and batch commitments, and on the init
    /// commitment except at `t = 1` over the empty filter.
    pub fn prove_epoch_commit(&mut self, t: u64, initial: &[u8], keys: &[u64], openings: &Openings) -> BloomPackedProof {
        if self.mode.is_hiding() {
            assert!(
                !openings.final_.is_zero() && !openings.batch.is_zero(),
                "Hiding leaf t = {t}: the final and batch commitments need secret randomizers \
                 (Openings::for_leaf), not the public zero salt"
            );
            hiding::assert_zero_init_opens_public_state(t, openings.init.is_zero(), || initial.iter().all(|&x| x == 0));
        }
        self.try_prove_epoch_opened(t, initial, keys, openings)
            .unwrap_or_else(|e| panic!("bloom_packed epoch rejected: {e:?}"))
    }

    /// The no-op VK-derivation leaf: all three salts the public zero, batch
    /// index 1, the empty filter and an all-dummy batch only.
    pub fn prove_epoch_public_zero(&mut self, t: u64, initial: &[u8], keys: &[u64]) -> BloomPackedProof {
        assert!(
            initial.iter().all(|&x| x == 0) && keys.is_empty(),
            "prove_epoch_public_zero is for the no-op leaf: the public no-op input only (the empty \
             filter and an all-dummy batch)"
        );
        assert_eq!(t, 1, "prove_epoch_public_zero is for the no-op leaf: it is proved at batch index 1");
        self.try_prove_epoch_opened(t, initial, keys, &Openings::public_zero())
            .unwrap_or_else(|e| panic!("bloom_packed epoch rejected: {e:?}"))
    }

    /// [`Self::prove_epoch_at`] reporting where a witness was rejected.
    pub fn try_prove_epoch_at(&mut self, t: u64, initial: &[u8], keys: &[u64]) -> Result<BloomPackedProof, PackedProveError> {
        assert!(
            !self.mode.is_hiding(),
            "prove_epoch_at on a Hiding leaf would publish Com(S; 0): use prove_epoch_commit with \
             Openings::for_leaf(..)"
        );
        self.try_prove_epoch_opened(t, initial, keys, &Openings::plain())
    }

    fn try_prove_epoch_opened(
        &mut self,
        t: u64,
        initial: &[u8],
        keys: &[u64],
        openings: &Openings,
    ) -> Result<BloomPackedProof, PackedProveError> {
        let p = self.params;
        assert_eq!(initial.len(), p.m_words(), "initial state must have M_w = k·W/8 bytes");
        let wit = epoch_witness(&p, initial, keys);
        self.prove_witness(t, keys, openings, wit)
    }

    /// Prove a given witness (honest or forged). The commitments are the
    /// native ones of `wit.initial`, `wit.final_words` and the padded `keys`.
    pub(crate) fn prove_witness(
        &mut self,
        t: u64,
        keys: &[u64],
        openings: &Openings,
        wit: PackedWitness,
    ) -> Result<BloomPackedProof, PackedProveError> {
        let p = self.params;
        let mode = self.mode;
        let flat = |ws: &[Val]| -> Vec<Val> {
            (0..p.n_limbs())
                .map(|l| {
                    let g = |s: usize| ws.get(3 * l + s).copied().unwrap_or(Val::ZERO);
                    g(0) + g(1) * Val::from_u64(256) + g(2) * Val::from_u64(65536)
                })
                .collect()
        };
        let initial_commit = hiding::commit_flat_bb(mode, CommitKind::State, FAMILY, &openings.init, &flat(&wit.initial));
        let final_commit =
            hiding::commit_flat_bb(mode, CommitKind::State, FAMILY, &openings.final_, &flat(&wit.final_words));
        let batch_commit = packed_batch_commit_with(p.batch, keys, mode, &openings.batch);
        self.circuit
            .update_permute_witnesses(&[wit.sigma.clone()])
            .map_err(|e| PackedProveError::Run(format!("update_permute_witnesses: {e:?}")))?;
        let mut public_inputs: Vec<Challenge> = Vec::with_capacity(7);
        public_inputs.extend(pack_commit(&initial_commit));
        public_inputs.extend(pack_commit(&final_commit));
        public_inputs.extend(pack_commit(&batch_commit));
        if self.expose.is_interval() {
            public_inputs.push(Challenge::from_u64(t));
        }
        let base = |x: Val| Challenge::from(x);
        let mut private_inputs: Vec<Challenge> = Vec::new();
        if mode.is_hiding() {
            private_inputs.extend(openings.private_inputs());
        }
        private_inputs.extend(wit.initial.iter().map(|&x| base(x)));
        private_inputs.extend(wit.final_words.iter().map(|&x| base(x)));
        let c256 = Val::from_u64(256);
        for &ft in &wit.ft {
            // ft = flo + 256·fhi: the honest bytes of a 16-bit value, or a
            // (test) field value carried entirely by flo.
            let v = ft.as_canonical_u64();
            let (lo, hi) = if v < 1 << TS_BITS { (Val::from_u64(v & 0xFF), Val::from_u64(v >> 8)) } else { (ft, Val::ZERO) };
            debug_assert_eq!(lo + c256 * hi, ft);
            private_inputs.extend([base(lo), base(hi)]);
        }
        for rec in &wit.recs {
            private_inputs.extend(record_witness(*rec).into_iter().map(base));
        }
        for sv in &wit.split {
            private_inputs.extend(sv.iter().map(|&x| base(x)));
        }
        for pr in &wit.pairs {
            private_inputs.extend(pr.w.iter().map(|&x| base(x)));
        }
        let t_w = std::time::Instant::now();
        let traces = {
            let mut runner = self.circuit.runner();
            runner
                .set_public_inputs(&public_inputs)
                .map_err(|e| PackedProveError::Run(format!("set_public_inputs: {e:?}")))?;
            runner
                .set_private_inputs(&private_inputs)
                .map_err(|e| PackedProveError::Run(format!("set_private_inputs: {e:?}")))?;
            runner.run().map_err(|e| PackedProveError::Run(format!("{e:?}")))?
        };
        let witness = t_w.elapsed();
        let t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .map_err(|e| PackedProveError::Prove(format!("{e:?}")))?;
        let prove = t_p.elapsed();
        let t_v = std::time::Instant::now();
        self.prover.verify_all_tables(&proof).map_err(|e| PackedProveError::Verify(format!("{e:?}")))?;
        crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
            witness,
            prove,
            verify: t_v.elapsed(),
            trace_rows: self.trace_rows,
        });
        let final_words: Vec<u8> = wit
            .final_words
            .iter()
            .map(|x| u8::try_from(x.as_canonical_u64()).unwrap_or(0xFF))
            .collect();
        Ok(BloomPackedProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial_commit: CountMinCommit(initial_commit),
            final_commit: CountMinCommit(final_commit),
            batch_commit: CountMinCommit(batch_commit),
            final_words,
            params: p,
        })
    }
}

/// One-shot: build the standalone leaf and prove one epoch.
pub fn prove_bloom_packed(params: BloomPackedParams, initial: &[u8], keys: &[u64]) -> BloomPackedProof {
    build_bloom_packed_leaf(params).prove_epoch(initial, keys)
}

#[cfg(test)]
#[path = "bloom_packed_tests.rs"]
mod tests;
