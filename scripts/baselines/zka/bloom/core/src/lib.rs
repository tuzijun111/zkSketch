#![no_std]
//! Partitioned Bloom filter epoch summary for the zk-Analytics pipeline (baseline port, ours †).
//!
//! zk-Analytics (SIGCOMM'26, commit d4a5a9a) ships three epoch summary types (samples,
//! histogram, cm) and no membership filter. This crate adds one in THEIR architecture
//! and with THEIR plumbing, exactly as ../../hll/core does for HyperLogLog:
//!
//! * aggregation (`process_bloom_aggr_with_state`) is `process_cm_aggr_with_state`
//!   (aggregator/core/src/lib.rs:1215-1301) with the CM table + heap replaced by a
//!   partitioned Bloom filter: verify the source SHA-256 batch hash chain
//!   (`verify_and_compute_chain`, verbatim), flatten the batches, build the epoch's
//!   filter from scratch one record at a time, hash the state with an unsalted, tagged
//!   SHA-256, and link it into the epoch chain with their `EpochChainLink::new`.
//! * query (`run_bloom_query`) is `run_cm_query` (querier/core/src/lib.rs:249-371) with
//!   the CM sum + min-lookup replaced by the Bloom union (bitwise OR of the n epoch
//!   filters) + membership test: verify the epoch chain links
//!   (`verify_epoch_chain_integrity`, verbatim), recompute every epoch's state
//!   commitment, merge, answer, and publish the chain boundaries + state commits + the
//!   queried key and its answer, with their low-support suppression.
//!
//! The filter is the textbook partitioned Bloom filter (Bloom 1970; the partitioned
//! form of Chang, Feng and Li, INFOCOM 2004 / Almeida et al. 2007): k slices of W bits,
//! one position per slice, insert sets the k bits, a lookup ANDs them. Plain Rust
//! executed as a RISC Zero guest, exactly as their three summaries are: no oblivious
//! padding, no memory checking, no sorting certificate, no algebraic hash.
//!
//! The functions that are private upstream are include!d verbatim from
//! `upstream_verbatim.rs` (generated and checked by ../gen_upstream.sh; byte-identical
//! to ../../hll/core/src/upstream_verbatim.rs).

extern crate alloc;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use hashbrown::HashMap;
#[cfg(target_os = "zkvm")]
use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
#[cfg(not(target_os = "zkvm"))]
use rust_crypto::{Digest as _, Sha256};
use serde::{Deserialize, Serialize};
use zkvm_common::{Event, HASH_BYTES_LEN, KEY_BYTES_LEN};

// Public upstream items, reused by path dependency.
pub use aggregator_core::{batch_chain_hash, key_to_u64, BatchInput, EpochChainLink, CM_SEEDS};
pub use querier_core::MIN_SUPPORT;

// Private upstream items, copied verbatim (see gen_upstream.sh for the line ranges):
// TAG_SHARD_CHAIN, sha256_bytes, events_commit, chain_tips_to_sorted_vec,
// verify_and_compute_chain, TAG_EPOCH_CHAIN, verify_epoch_chain_integrity.
include!("upstream_verbatim.rs");

// ------------------------------------------------------------------ parameters
/// Number of slices = hash functions (zkSketch's `EXP_BLOOM_K` default).
pub const BLOOM_K: usize = 7;
/// log2 of the bits per slice (zkSketch's `EXP_BLOOM_LOGW` default).
pub const BLOOM_LOG_W: u32 = 14;
/// Bits per slice W = 2^14.
pub const BLOOM_W: usize = 1 << BLOOM_LOG_W;
/// Total filter bits M = k W = 114,688.
pub const BLOOM_BITS: usize = BLOOM_K * BLOOM_W;
/// The filter is stored as a packed bitset of M / 8 = 14,336 bytes.
pub const BLOOM_BYTES: usize = BLOOM_BITS / 8;
const _: () = assert!(BLOOM_W % 32 == 0, "slices must be whole words");

/// Per-slice seeds. Slices 0..3 reuse their three CM row seeds
/// (aggregator/core/src/lib.rs:41) in order; zk-Analytics has no fourth seed, so
/// slices 3..7 use four fixed odd constants of ours (the MurmurHash3 fmix32
/// multipliers and xxHash32 primes 4 and 5), chosen before any measurement.
pub const BLOOM_SEEDS: [u32; BLOOM_K] = [
    CM_SEEDS[0], CM_SEEDS[1], CM_SEEDS[2], // their CM row seeds
    0x85eb_ca6b, 0xc2b2_ae35, 0x27d4_eb2f, 0x1656_67b1, // ours
];

/// Domain separator for the Bloom state commitment, named after their per-type tags
/// (TAG_CM_STATE_COMMIT etc., aggregator/core/src/lib.rs:46-48). Ours, not upstream.
const TAG_BLOOM_STATE_COMMIT: &[u8] = b"ZKTLM_BLOOM_STATE_COMMIT_V1";

// ------------------------------------------------------------------------ hash
/// Position of a key in slice `slice`: their `cm_bucket_index`
/// (aggregator/core/src/lib.rs:1055-1063) with CM_COLS -> W and the slice's seed.
/// `fold` is their FNV-1a `key_to_u64(key_id)` (aggregator/core/src/lib.rs:342),
/// computed once per record and shared by the k slices (their CM recomputes it per
/// row; hoisting it only makes this baseline cheaper).
#[inline]
pub fn bloom_slice_pos(fold: u64, slice: usize) -> usize {
    let seed = BLOOM_SEEDS[slice];
    let mut x = fold ^ (((seed as u64) << 32) | seed as u64);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x % BLOOM_W as u64) as usize
}

/// Global bit index (slice * W + position) of the key's bit in every slice.
#[inline]
pub fn bloom_bit_indices(key_id: &[u8; KEY_BYTES_LEN]) -> [usize; BLOOM_K] {
    let fold = key_to_u64(key_id);
    let mut out = [0usize; BLOOM_K];
    for (j, o) in out.iter_mut().enumerate() {
        *o = j * BLOOM_W + bloom_slice_pos(fold, j);
    }
    out
}

/// Textbook insert: set the key's bit in each of the k slices.
#[inline]
pub fn bloom_insert(bits: &mut [u8], key_id: &[u8; KEY_BYTES_LEN]) {
    for i in bloom_bit_indices(key_id) {
        bits[i >> 3] |= 1u8 << (i & 7);
    }
}

/// Textbook lookup: the AND of the key's k bits.
#[inline]
pub fn bloom_contains(bits: &[u8], key_id: &[u8; KEY_BYTES_LEN]) -> bool {
    bloom_bit_indices(key_id)
        .iter()
        .all(|&i| bits[i >> 3] & (1u8 << (i & 7)) != 0)
}

// ----------------------------------------------------------------------- state
/// Epoch state: the event count and the k W filter bits as a packed bitset, bit i =
/// bit (i mod 8) of byte i / 8, slice j = bits [j W, (j+1) W). The bytes travel as a
/// packed byte string (4 bytes per zkVM word, risc0 serde's bulk path), as the HLL
/// port's registers do: risc0's serde reads a Vec<u32> / Vec<u8> element by element
/// at about 150 cycles per word, the byte string in bulk (see README, "Caveats").
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BloomEpochState {
    pub total_count: u64,
    #[serde(with = "packed_bytes")]
    pub bits: Vec<u8>,
}

/// Unsalted SHA-256 over the serialized state, in the style of their
/// `cm_epoch_state_commit` (aggregator/core/src/lib.rs:1009-1029): tag, then the scalar
/// field big-endian, then the state body (the bitset bytes), hashed in one `update`.
pub fn bloom_epoch_state_commit(state: &BloomEpochState) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    sha.update(TAG_BLOOM_STATE_COMMIT);
    sha.update(&state.total_count.to_be_bytes());
    sha.update(&state.bits);
    sha.finalize().into()
}

/// Their aggregation input, reused unchanged (as the HLL port does): `CmAggrInput`
/// (aggregator/core/src/lib.rs:945-955) is field-for-field identical to
/// `SamplesAggrInput` and `HistogramAggrInput` and carries nothing CM-specific.
pub type BloomAggrInput = aggregator_core::CmAggrInput;

/// Public journal of the aggregation guest: `CmAggrOutput`
/// (aggregator/core/src/lib.rs:1033-1053) minus its CM-specific Merkle roots
/// (row_roots, cm_root, heap_root), exactly as the HLL port's `HllAggrOutput`. No
/// query guest of theirs reads those roots; dropping them makes this baseline cheaper.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BloomAggrOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

pub fn process_bloom_aggr(input: &BloomAggrInput) -> BloomAggrOutput {
    let (_, out) = process_bloom_aggr_with_state(input);
    out
}

pub fn process_bloom_aggr_with_state(input: &BloomAggrInput) -> (BloomEpochState, BloomAggrOutput) {
    process_bloom_aggr_probed(input, &mut || {})
}

/// Aggregation with a phase probe. `probe` is called after each phase (4 calls:
/// chain, flatten, update, commit); the guest records its cycle counter there, the
/// host passes a no-op. The computation is the same in both.
pub fn process_bloom_aggr_probed(
    input: &BloomAggrInput,
    probe: &mut dyn FnMut(),
) -> (BloomEpochState, BloomAggrOutput) {
    // --- from process_cm_aggr_with_state (aggregator/core/src/lib.rs:1216-1239), unchanged
    let source_chain_tips = if !input.batches.is_empty() {
        Some(verify_and_compute_chain(
            &input.batches,
            &input.prev_source_chain_tips,
        ))
    } else {
        None
    };
    let final_source_chain_tips = source_chain_tips
        .map(chain_tips_to_sorted_vec)
        .unwrap_or_default();
    probe(); // phase 1: source batch hash-chain verification

    let mut all_events: Vec<Event> = Vec::new();
    for batch in &input.batches {
        all_events.extend(batch.events.iter().cloned());
    }
    probe(); // phase 2: flatten batches

    // --- the summary: textbook partitioned Bloom insert, built from scratch per epoch
    let mut total_count = 0u64;
    let mut bits = vec![0u8; BLOOM_BYTES];
    for ev in &all_events {
        total_count = total_count.saturating_add(1);
        bloom_insert(&mut bits, &ev.key_id);
    }
    let state = BloomEpochState { total_count, bits };
    probe(); // phase 3: Bloom update

    // --- state commit + epoch link, as every upstream epoch type does
    let state_commit = bloom_epoch_state_commit(&state);
    let epoch_chain_link = EpochChainLink::new(input.prev_chain_hash, state_commit);
    let out = BloomAggrOutput {
        epoch_chain_link,
        state_commit,
        n_events: all_events.len() as u64,
        final_source_chain_tips,
    };
    probe(); // phase 4: state commit + epoch chain link
    (state, out)
}

// ----------------------------------------------------------------------- query
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BloomQuery {
    /// Membership of one key in the union of the queried epochs (their CM
    /// `Estimate { key }` shape: the key is a 15-byte key_id).
    Contains { key: [u8; KEY_BYTES_LEN] },
}

/// Same shape as their `CmQueryInput` (querier/core/src/lib.rs:186-196).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BloomQueryInput {
    pub query: BloomQuery,
    pub epoch_states: Vec<BloomEpochState>,
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BloomQueryResult {
    /// The queried key and the filter's answer ("possibly present" = true).
    Contains { key: [u8; KEY_BYTES_LEN], member: bool },
}

/// Same shape as their `CmQueryOutput` (querier/core/src/lib.rs:207-228).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BloomQueryOutput {
    pub chain_prev_hash: [u8; 32],
    pub chain_final_hash: [u8; 32],
    pub state_commits: Vec<[u8; 32]>,
    pub result: BloomQueryResult,
    /// Records the filter summarises (sum of the epochs' total_count).
    pub support: u64,
    pub suppressed: bool,
}

impl BloomQueryOutput {
    /// Their suppressed-sentinel rule (querier/core/src/lib.rs:236-247 for CM):
    /// support < MIN_SUPPORT replaces the answer with a fixed placeholder (member =
    /// false) and zeroes support. The queried key is the query's own input and stays.
    pub fn suppress_if_low_support(mut self) -> Self {
        if self.support < MIN_SUPPORT {
            self.result = match self.result {
                BloomQueryResult::Contains { key, .. } => BloomQueryResult::Contains { key, member: false },
            };
            self.support = 0;
            self.suppressed = true;
        }
        self
    }
}

pub fn run_bloom_query(input: &BloomQueryInput) -> BloomQueryOutput {
    run_bloom_query_probed(input, &mut || {})
}

/// OR a packed filter (`BLOOM_BYTES` bytes) into `merged`, one native-endian u32 word at
/// a time. The deserialized byte buffer is 4-aligned in practice, so the word view covers
/// all of it; an unaligned buffer takes the same word-wise path through `chunks_exact`.
fn or_words_into(merged: &mut [u32], bits: &[u8]) {
    // SAFETY: every bit pattern is a valid u32; `align_to` returns only the aligned middle.
    let (head, words, tail) = unsafe { bits.align_to::<u32>() };
    if head.is_empty() && tail.is_empty() && words.len() == merged.len() {
        for (m, &w) in merged.iter_mut().zip(words) {
            *m |= w;
        }
    } else {
        for (m, c) in merged.iter_mut().zip(bits.chunks_exact(4)) {
            *m |= u32::from_ne_bytes([c[0], c[1], c[2], c[3]]);
        }
    }
}

/// Query with a phase probe (4 calls: chain links, state commits, merge, answer).
pub fn run_bloom_query_probed(input: &BloomQueryInput, probe: &mut dyn FnMut()) -> BloomQueryOutput {
    let epochs = input.epoch_states.len();

    // --- from run_cm_query (querier/core/src/lib.rs:251-269), unchanged except the
    //     state-commit function; the two phases are probed separately.
    if !input.epoch_chain_links.is_empty() {
        verify_epoch_chain_integrity(&input.epoch_chain_links);
        assert!(
            input.epoch_chain_links.len() == epochs,
            "epoch_chain_links length != epoch_states length"
        );
    }
    probe(); // phase 1: epoch chain-link verification
    if !input.epoch_chain_links.is_empty() {
        for (i, (state, link)) in input.epoch_states.iter().zip(input.epoch_chain_links.iter()).enumerate() {
            let computed_commit = bloom_epoch_state_commit(state);
            assert!(
                computed_commit == link.state_commit,
                "epoch {} state_commit mismatch: computed != chain_link",
                i
            );
        }
    }
    probe(); // phase 2: per-epoch state commitment recomputation

    // --- from run_cm_query (querier/core/src/lib.rs:271-284), unchanged
    let (chain_prev_hash, chain_final_hash) = if input.epoch_chain_links.is_empty() {
        ([0u8; 32], [0u8; 32])
    } else {
        (
            input.epoch_chain_links[0].prev_chain_hash,
            input.epoch_chain_links.last().unwrap().final_chain_hash,
        )
    };
    let state_commits: Vec<[u8; 32]> = input.epoch_chain_links.iter()
        .map(|link| link.state_commit)
        .collect();

    // --- merge at query time: filters by bitwise OR (the Bloom union), counts by sum
    // OR a 32-bit word at a time, as upstream's CM merge works on u32 elements.
    let mut merged = vec![0u32; BLOOM_BYTES / 4];
    let mut support = 0u64;
    for state in &input.epoch_states {
        assert!(state.bits.len() == BLOOM_BYTES, "epoch state has {} bytes, expected {}", state.bits.len(), BLOOM_BYTES);
        support = support.wrapping_add(state.total_count);
        or_words_into(&mut merged, &state.bits);
    }
    probe(); // phase 3: merge

    // SAFETY: every bit pattern is a valid u8, and a u32 slice is always u8-aligned.
    let merged_bytes: &[u8] = unsafe { merged.align_to::<u8>().1 };
    let result = match input.query {
        BloomQuery::Contains { key } => BloomQueryResult::Contains { key, member: bloom_contains(merged_bytes, &key) },
    };
    probe(); // phase 4: answer

    BloomQueryOutput {
        chain_prev_hash,
        chain_final_hash,
        state_commits,
        result,
        support,
        suppressed: false,
    }
}

// ------------------------------------------------- naive-serde input variant
/// The same query input with the filter as a `Vec<u32>` bitset in serde's DEFAULT
/// encoding: one zkVM word per 32 filter bits, which risc0's serde reads element by
/// element (the packed byte string above has the same number of words but is read in
/// bulk). This is the form of their `CmEpochState::counts: Vec<u32>`
/// (aggregator/core/src/lib.rs:978), i.e. what a direct port in the style of their CM
/// state would send. Used only by the `bloom_query_words` guest, a sensitivity row
/// (the pattern of ../../hll's `hll_query_words`): the guest converts the words to the
/// packed bytes (a copy, its "convert" phase) and then runs the identical query, so the
/// journal is the same.
///
/// Word w holds bytes 4w..4w+4 little-endian, so filter bit i is bit (i mod 32) of word
/// i / 32 and the conversion is exact in both directions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BloomEpochStateWords {
    pub total_count: u64,
    pub words: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BloomQueryInputWords {
    pub query: BloomQuery,
    pub epoch_states: Vec<BloomEpochStateWords>,
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

impl From<BloomQueryInputWords> for BloomQueryInput {
    fn from(w: BloomQueryInputWords) -> Self {
        BloomQueryInput {
            query: w.query,
            epoch_states: w
                .epoch_states
                .into_iter()
                .map(|s| {
                    let mut bits = Vec::with_capacity(s.words.len() * 4);
                    for x in &s.words {
                        bits.extend_from_slice(&x.to_le_bytes());
                    }
                    BloomEpochState { total_count: s.total_count, bits }
                })
                .collect(),
            epoch_chain_links: w.epoch_chain_links,
        }
    }
}

impl From<&BloomQueryInput> for BloomQueryInputWords {
    fn from(p: &BloomQueryInput) -> Self {
        BloomQueryInputWords {
            query: p.query.clone(),
            epoch_states: p
                .epoch_states
                .iter()
                .map(|s| {
                    assert!(s.bits.len() % 4 == 0, "bitset of {} bytes is not whole words", s.bits.len());
                    BloomEpochStateWords {
                        total_count: s.total_count,
                        words: s.bits.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect(),
                    }
                })
                .collect(),
            epoch_chain_links: p.epoch_chain_links.clone(),
        }
    }
}

// ---------------------------------------------------------------- serde helper
/// Serializes a Vec<u8> through serde's bytes type, which risc0's serde packs four
/// bytes per word (risc0-zkvm serde/serializer.rs serialize_bytes) and deserializes
/// without a copy (visit_byte_buf). Plain serde, no extra crate. Copied unchanged from
/// ../../hll/core/src/lib.rs (ours, not upstream).
mod packed_bytes {
    use alloc::vec::Vec;
    use core::fmt;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = a.next_element()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

// ----------------------------------------------------------------------- tests
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use risc0_zkvm::serde::{from_slice, to_vec};
    use std::collections::HashSet;

    /// Epoch inputs for `keys` split into epochs of `m`, batches of `cbs`, chained as
    /// their aggregator host does (the same construction as the host driver).
    fn epochs(keys: &[u64], m: usize, cbs: usize) -> (Vec<(BloomAggrInput, BloomEpochState)>, Vec<EpochChainLink>) {
        let (mut tip, mut seq) = ([0u8; 32], 0u64);
        let mut prev_chain_hash = [0u8; 32];
        let mut prev_tips = Vec::new();
        let (mut outs, mut links) = (Vec::new(), Vec::new());
        for (e, chunk) in keys.chunks(m).enumerate() {
            let evs: Vec<Event> = chunk
                .iter()
                .enumerate()
                .map(|(i, &k)| Event { ts: (e * m + i) as u32, key_id: Event::make_key_id(0, k), value: 1 })
                .collect();
            let mut batches = Vec::new();
            for b in evs.chunks(cbs) {
                let prev = if seq == 0 { [0u8; 32] } else { tip };
                let h = batch_chain_hash(prev, b);
                batches.push(BatchInput { source_id: 0, source_batch_seq: seq, events: b.to_vec(), sent_batch_hash: h });
                tip = h;
                seq += 1;
            }
            let inp = BloomAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
            let (st, out) = process_bloom_aggr_with_state(&inp);
            prev_chain_hash = out.epoch_chain_link.final_chain_hash;
            prev_tips = out.final_source_chain_tips.clone();
            links.push(out.epoch_chain_link);
            outs.push((inp, st));
        }
        (outs, links)
    }

    fn query_input(keys: &[u64], m: usize, probe: u64) -> BloomQueryInput {
        let (outs, links) = epochs(keys, m, 8);
        BloomQueryInput {
            query: BloomQuery::Contains { key: Event::make_key_id(0, probe) },
            epoch_states: outs.into_iter().map(|(_, s)| s).collect(),
            epoch_chain_links: links,
        }
    }

    fn lcg_keys(n: usize, modulus: u64) -> Vec<u64> {
        let mut x = 0x1234_5678u64;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (x >> 17) % modulus
            })
            .collect()
    }

    fn member(q: &BloomQueryOutput) -> bool {
        let BloomQueryResult::Contains { member, .. } = q.result;
        member
    }

    #[test]
    fn positions_match_cm_bucket_index_on_their_seeds() {
        // For the three slices that reuse their CM seeds, the position is exactly
        // their cm_bucket_index reduced mod W (CM_COLS = 1024 divides W = 2^14).
        for k in [0u64, 1, 7, 12345, 0xFFFF_FFFF] {
            let id = Event::make_key_id(0, k);
            let fold = key_to_u64(&id);
            for r in 0..3 {
                assert_eq!(
                    bloom_slice_pos(fold, r) % aggregator_core::CM_COLS,
                    aggregator_core::cm_bucket_index(&id, r) as usize
                );
            }
        }
    }

    #[test]
    fn no_false_negatives_and_merge_is_union() {
        let keys = lcg_keys(4 * 2048, 50_000);
        let (outs, _) = epochs(&keys, 2048, 8);
        // OR of the epoch filters == the filter of the whole stream
        let (whole, _) = epochs(&keys, keys.len(), 8);
        let mut or = vec![0u8; BLOOM_BYTES];
        for (_, s) in &outs {
            for (a, b) in or.iter_mut().zip(&s.bits) {
                *a |= *b;
            }
        }
        assert_eq!(or, whole[0].1.bits);
        for &k in &keys {
            assert!(bloom_contains(&or, &Event::make_key_id(0, k)), "false negative {k}");
        }
        let q = run_bloom_query(&query_input(&keys, 2048, keys[0]));
        assert!(member(&q));
        assert_eq!(q.support, keys.len() as u64);
        assert!(!q.suppressed);
        assert_eq!(q.state_commits.len(), 4);
    }

    #[test]
    fn false_positive_rate_is_near_theory() {
        let keys = lcg_keys(16_384, 1 << 40);
        let distinct = keys.iter().collect::<HashSet<_>>().len() as f64;
        let (whole, _) = epochs(&keys, keys.len(), 64);
        let set: HashSet<u64> = keys.iter().copied().collect();
        let (mut fp, mut n) = (0u32, 0u32);
        let mut c = 1u64 << 41;
        while n < 100_000 {
            c += 1;
            if set.contains(&c) {
                continue;
            }
            n += 1;
            fp += bloom_contains(&whole[0].1.bits, &Event::make_key_id(0, c)) as u32;
        }
        let measured = fp as f64 / n as f64;
        let w = BLOOM_W as f64;
        let theory = (1.0 - (1.0 - 1.0 / w).powf(distinct)).powi(BLOOM_K as i32);
        assert!((measured - theory).abs() < 0.35 * theory + 1e-4, "measured {measured} theory {theory}");
    }

    #[test]
    fn absent_key_is_usually_rejected() {
        let keys = lcg_keys(2 * 1024, 5_000);
        let q = run_bloom_query(&query_input(&keys, 1024, 9_999_999));
        assert!(!member(&q)); // fill ~ 1.2%; FPR ~ 1e-13 at this load
    }

    #[test]
    #[should_panic(expected = "state_commit mismatch")]
    fn tampered_state_is_rejected() {
        let mut q = query_input(&lcg_keys(2 * 1024, 5_000), 1024, 1);
        q.epoch_states[1].bits[7] ^= 1;
        run_bloom_query(&q);
    }

    #[test]
    #[should_panic(expected = "chain broken")]
    fn reordered_epochs_are_rejected() {
        let mut q = query_input(&lcg_keys(3 * 1024, 5_000), 1024, 1);
        q.epoch_states.swap(1, 2);
        q.epoch_chain_links.swap(1, 2);
        run_bloom_query(&q);
    }

    #[test]
    #[should_panic(expected = "batch_hash mismatch")]
    fn forged_batch_is_rejected() {
        let (mut outs, _) = epochs(&lcg_keys(1024, 5_000), 1024, 8);
        outs[0].0.batches[3].events[0].key_id = Event::make_key_id(0, 999_999);
        process_bloom_aggr(&outs[0].0);
    }

    #[test]
    fn low_support_is_suppressed() {
        let q = run_bloom_query(&query_input(&[1, 2, 3], 3, 1)).suppress_if_low_support();
        assert!(q.suppressed);
        assert_eq!(q.support, 0);
        assert!(!member(&q));
    }

    #[test]
    fn bit_layout_is_slice_major_lsb_first() {
        // the bits a key sets are exactly bit (i mod 8) of byte i / 8 for its k indices
        let id = Event::make_key_id(0, 4242);
        let mut bits = vec![0u8; BLOOM_BYTES];
        bloom_insert(&mut bits, &id);
        let idx = bloom_bit_indices(&id);
        let set: Vec<usize> = (0..BLOOM_BITS).filter(|&i| bits[i / 8] >> (i % 8) & 1 == 1).collect();
        let mut want = idx.to_vec();
        want.sort_unstable();
        want.dedup();
        assert_eq!(set, want);
        for (j, &i) in idx.iter().enumerate() {
            assert_eq!(i / BLOOM_W, j, "slice {j} index {i} outside its slice");
        }
    }

    #[test]
    fn zkvm_serde_roundtrip_and_packing() {
        let q = query_input(&lcg_keys(2 * 1024, 5_000), 1024, 1);
        let words = to_vec(&q).unwrap();
        assert_eq!(from_slice::<BloomQueryInput, _>(&words).unwrap(), q);
        // variant + 15 key bytes (one word each, as serde sends [u8; N]) + states
        // (len; per epoch: total_count 2 words, byte length 1 + 14,336 / 4 packed words)
        // + links (len; per epoch 3 x 32 bytes, one word each)
        assert_eq!(words.len(), 1 + KEY_BYTES_LEN + 1 + 2 * (2 + 1 + BLOOM_BYTES / 4) + 1 + 2 * 3 * 32);
    }

    #[test]
    fn words_variant_is_the_same_input_and_query() {
        let q = query_input(&lcg_keys(2 * 1024, 5_000), 1024, 1);
        let w = BloomQueryInputWords::from(&q);
        // bit i of the filter is bit (i mod 32) of word i / 32
        let s = &q.epoch_states[0];
        for i in (0..BLOOM_BITS).step_by(37) {
            assert_eq!(s.bits[i / 8] >> (i % 8) & 1, (w.epoch_states[0].words[i / 32] >> (i % 32) & 1) as u8);
        }
        let ww = to_vec(&w).unwrap();
        let back = BloomQueryInput::from(from_slice::<BloomQueryInputWords, _>(&ww).unwrap());
        assert_eq!(back, q);
        assert_eq!(run_bloom_query(&back), run_bloom_query(&q));
        // the same number of zkVM words as the packed encoding (len + 3,584 per state):
        // the difference is how risc0's serde reads them, element by element
        assert_eq!(ww.len(), to_vec(&q).unwrap().len());
    }
}
