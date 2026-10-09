#![no_std]
//! KMV (k minimum values / bottom-k) epoch summary for the zk-Analytics pipeline
//! (baseline port, ours †).
//!
//! zk-Analytics (SIGCOMM'26, commit d4a5a9a) ships three epoch summary types (samples,
//! histogram, cm) and no distinct-count sketch. This crate adds a KMV summary in THEIR
//! architecture and with THEIR plumbing, exactly as ../../hll/core does for HyperLogLog:
//!
//! * aggregation (`process_kmv_aggr_with_state`) is `process_cm_aggr_with_state`
//!   (aggregator/core/src/lib.rs:1215-1301) with the CM table + heap replaced by the k
//!   smallest distinct 64-bit key hashes: verify the source SHA-256 batch hash chain
//!   (`verify_and_compute_chain`, verbatim), flatten the batches, build the epoch's
//!   bottom-k set from scratch one record at a time, hash the state with an unsalted,
//!   tagged SHA-256, and link it into the epoch chain with their `EpochChainLink::new`.
//! * query (`run_kmv_query`) is `run_cm_query` (querier/core/src/lib.rs:249-371) with
//!   the CM merge + lookup replaced by the KMV union (bottom-k of the union of the n
//!   epoch sets) + the distinct-count estimator: verify the epoch chain links
//!   (`verify_epoch_chain_integrity`, verbatim), recompute every epoch's state
//!   commitment, merge, answer, and publish the chain boundaries + state commits +
//!   result, with their low-support suppression.
//!
//! The sketch is the textbook KMV of Bar-Yossef, Jayram, Kumar, Sivakumar and Trevisan
//! (RANDOM 2002) / bottom-k of Cohen and Kaplan (PODC 2007), with the unbiased
//! estimator (k-1)/U_(k) of Beyer et al. (SIGMOD 2007). Plain Rust executed as a RISC
//! Zero guest, exactly as their three summaries are: no oblivious padding, no memory
//! checking, no sorting certificate, no algebraic hash.
//!
//! The functions that are private upstream are include!d verbatim from
//! `upstream_verbatim.rs` (generated and checked by ../gen_upstream.sh; byte-identical
//! to ../../hll/core/src/upstream_verbatim.rs).

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::format;
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
/// Number of minimum hash values kept (zkSketch's KMV k = 1024).
pub const KMV_K: usize = 1024;
/// Seed of the key hash. Their CM row-0 seed (aggregator/core/src/lib.rs:41), the same
/// hash as the HLL port's `hll_hash64`.
pub const KMV_SEED: u32 = CM_SEEDS[0];

/// Domain separator for the KMV state commitment, named after their per-type tags
/// (TAG_CM_STATE_COMMIT etc., aggregator/core/src/lib.rs:46-48). Ours, not upstream.
const TAG_KMV_STATE_COMMIT: &[u8] = b"ZKTLM_KMV_STATE_COMMIT_V1";

// ------------------------------------------------------------------------ hash
/// 64-bit key hash: their FNV-1a key fold `key_to_u64` (aggregator/core/src/lib.rs:342)
/// followed by the seeded splitmix64 finaliser of their `cm_bucket_index`
/// (aggregator/core/src/lib.rs:1055-1063), without the final `% CM_COLS`. Values are
/// taken as uniform on [0, 2^64).
#[inline]
pub fn kmv_hash64(key_id: &[u8; KEY_BYTES_LEN]) -> u64 {
    let seed = KMV_SEED;
    let mut x = key_to_u64(key_id) ^ (((seed as u64) << 32) | seed as u64);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

// ----------------------------------------------------------------------- state
/// Epoch state: the event count and the (at most k) smallest DISTINCT hash values of
/// the epoch's keys, ascending. The values travel as one packed byte string (their
/// big-endian image, 2 zkVM words per value, read in bulk by risc0's serde), the
/// analogue of the HLL port's packed registers: risc0's serde reads a plain Vec<u64>
/// element by element at about 150 cycles per word (see README, "Caveats").
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmvEpochState {
    pub total_count: u64,
    #[serde(with = "packed_u64")]
    pub values: Vec<u64>,
}

/// The values' big-endian byte image (the commitment body and the wire format).
pub fn kmv_values_be_bytes(values: &[u64]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(values.len() * 8);
    for v in values {
        body.extend_from_slice(&v.to_be_bytes());
    }
    body
}

/// Unsalted SHA-256 over the serialized state, in the style of their
/// `cm_epoch_state_commit` (aggregator/core/src/lib.rs:1009-1029): tag, then the scalar
/// fields big-endian (total_count, then the value count as u32), then the state body
/// (the values big-endian, ascending), hashed in one `update`.
pub fn kmv_epoch_state_commit(state: &KmvEpochState) -> [u8; HASH_BYTES_LEN] {
    let body = kmv_values_be_bytes(&state.values);
    let mut sha = Sha256::new();
    sha.update(TAG_KMV_STATE_COMMIT);
    sha.update(&state.total_count.to_be_bytes());
    sha.update(&(state.values.len() as u32).to_be_bytes());
    sha.update(&body);
    sha.finalize().into()
}

/// Their aggregation input, reused unchanged (as the HLL port does): `CmAggrInput`
/// (aggregator/core/src/lib.rs:945-955) is field-for-field identical to
/// `SamplesAggrInput` and `HistogramAggrInput` and carries nothing CM-specific.
pub type KmvAggrInput = aggregator_core::CmAggrInput;

/// Public journal of the aggregation guest: `CmAggrOutput`
/// (aggregator/core/src/lib.rs:1033-1053) minus its CM-specific Merkle roots
/// (row_roots, cm_root, heap_root), exactly as the HLL port's `HllAggrOutput`. No
/// query guest of theirs reads those roots; dropping them makes this baseline cheaper.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmvAggrOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

/// Textbook per-record bottom-k insert into an ordered set: keep h if fewer than k
/// values are held, or if h is below the current k-th smallest and not already held
/// (then the largest is evicted). Duplicates of a held value change nothing.
#[inline]
pub fn kmv_insert(set: &mut BTreeSet<u64>, h: u64, k: usize) {
    if set.len() < k {
        set.insert(h);
    } else if h < *set.last().expect("k >= 1") && set.insert(h) {
        set.pop_last();
    }
}

pub fn process_kmv_aggr(input: &KmvAggrInput) -> KmvAggrOutput {
    let (_, out) = process_kmv_aggr_with_state(input);
    out
}

pub fn process_kmv_aggr_with_state(input: &KmvAggrInput) -> (KmvEpochState, KmvAggrOutput) {
    process_kmv_aggr_probed(input, &mut || {})
}

/// Aggregation with a phase probe. `probe` is called after each phase (4 calls:
/// chain, flatten, update, commit); the guest records its cycle counter there, the
/// host passes a no-op. The computation is the same in both.
pub fn process_kmv_aggr_probed(
    input: &KmvAggrInput,
    probe: &mut dyn FnMut(),
) -> (KmvEpochState, KmvAggrOutput) {
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

    // --- the summary: textbook KMV update, built from scratch per epoch
    let mut total_count = 0u64;
    let mut set: BTreeSet<u64> = BTreeSet::new();
    for ev in &all_events {
        total_count = total_count.saturating_add(1);
        kmv_insert(&mut set, kmv_hash64(&ev.key_id), KMV_K);
    }
    let state = KmvEpochState { total_count, values: set.into_iter().collect() };
    probe(); // phase 3: KMV update (+ the ordered set's in-order walk into the state)

    // --- state commit + epoch link, as every upstream epoch type does
    let state_commit = kmv_epoch_state_commit(&state);
    let epoch_chain_link = EpochChainLink::new(input.prev_chain_hash, state_commit);
    let out = KmvAggrOutput {
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
pub enum KmvQuery {
    /// Distinct-count estimate over the union of the queried epochs.
    Estimate,
}

/// Same shape as their `CmQueryInput` (querier/core/src/lib.rs:186-196).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmvQueryInput {
    pub query: KmvQuery,
    pub epoch_states: Vec<KmvEpochState>,
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KmvQueryResult {
    Estimate {
        /// The distinct-count answer (see `kmv_estimate`).
        estimate: u64,
        /// Values in the merged bottom-k set (min(k, distinct hash values)).
        kept: u32,
        /// The k-th smallest merged value (0 when fewer than k are kept).
        v_k: u64,
        /// True when fewer than k values are kept: the answer is then the exact number
        /// of distinct hash values, not an estimate.
        exact_count: bool,
    },
}

/// Same shape as their `CmQueryOutput` (querier/core/src/lib.rs:207-228).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmvQueryOutput {
    pub chain_prev_hash: [u8; 32],
    pub chain_final_hash: [u8; 32],
    pub state_commits: Vec<[u8; 32]>,
    pub result: KmvQueryResult,
    /// Records the estimate is computed over (sum of the epochs' total_count).
    pub support: u64,
    pub suppressed: bool,
}

impl KmvQueryOutput {
    /// Their suppressed-sentinel rule (querier/core/src/lib.rs:236-247 for CM):
    /// support < MIN_SUPPORT zeroes every numeric result field and support.
    pub fn suppress_if_low_support(mut self) -> Self {
        if self.support < MIN_SUPPORT {
            self.result = match self.result {
                KmvQueryResult::Estimate { .. } => KmvQueryResult::Estimate {
                    estimate: 0,
                    kept: 0,
                    v_k: 0,
                    exact_count: false,
                },
            };
            self.support = 0;
            self.suppressed = true;
        }
        self
    }
}

/// Bottom-k of the union of two ascending, duplicate-free lists: the textbook KMV
/// union (the k smallest distinct values of A u B), by a linear merge that stops after
/// k outputs.
pub fn merge_bottom_k(a: &[u64], b: &[u64], k: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(k.min(a.len() + b.len()));
    let (mut i, mut j) = (0usize, 0usize);
    while out.len() < k && (i < a.len() || j < b.len()) {
        let v = if j >= b.len() || (i < a.len() && a[i] < b[j]) {
            i += 1;
            a[i - 1]
        } else if i >= a.len() || b[j] < a[i] {
            j += 1;
            b[j - 1]
        } else {
            // equal: one distinct value
            i += 1;
            j += 1;
            a[i - 1]
        };
        out.push(v);
    }
    out
}

/// KMV distinct-count answer from an ascending bottom-k set of 64-bit hash values.
///
/// * Fewer than k values: the exact number of distinct hash values (= kept).
/// * k values: the unbiased estimator (k-1)/U_(k) of Beyer et al. with U_(k) =
///   v_k / 2^64 the k-th smallest value scaled to [0, 1), evaluated in integer
///   arithmetic as floor((k-1) * 2^64 / v_k) in u128 (exact; (k-1) * 2^64 < 2^75)
///   and saturated to u64::MAX. v_k > 0 always holds for k >= 2 distinct values. This
///   is zkSketch's `kmv_estimate` formula with its 2^27 hash range replaced by 2^64.
pub fn kmv_estimate(values: &[u64], k: usize) -> KmvQueryResult {
    if values.len() < k {
        KmvQueryResult::Estimate { estimate: values.len() as u64, kept: values.len() as u32, v_k: 0, exact_count: true }
    } else {
        let v_k = values[k - 1];
        assert!(v_k > 0, "v_k = 0 is impossible for k >= 2 distinct values");
        let est = (((k as u128) - 1) << 64) / v_k as u128;
        KmvQueryResult::Estimate {
            estimate: est.min(u64::MAX as u128) as u64,
            kept: k as u32,
            v_k,
            exact_count: false,
        }
    }
}

pub fn run_kmv_query(input: &KmvQueryInput) -> KmvQueryOutput {
    run_kmv_query_probed(input, &mut || {})
}

/// Query with a phase probe (4 calls: chain links, state commits, merge, estimate).
pub fn run_kmv_query_probed(input: &KmvQueryInput, probe: &mut dyn FnMut()) -> KmvQueryOutput {
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
            let computed_commit = kmv_epoch_state_commit(state);
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

    // --- merge at query time: bottom-k of the union, epoch by epoch; counts by sum
    let mut merged: Vec<u64> = Vec::new();
    let mut support = 0u64;
    for state in &input.epoch_states {
        assert!(state.values.len() <= KMV_K, "epoch state has {} values, more than k = {}", state.values.len(), KMV_K);
        support = support.wrapping_add(state.total_count);
        merged = merge_bottom_k(&merged, &state.values, KMV_K);
    }
    probe(); // phase 3: merge

    let result = match input.query {
        KmvQuery::Estimate => kmv_estimate(&merged, KMV_K),
    };
    probe(); // phase 4: estimate

    KmvQueryOutput {
        chain_prev_hash,
        chain_final_hash,
        state_commits,
        result,
        support,
        suppressed: false,
    }
}

// ------------------------------------------------- naive-serde input variant
/// The same query input with the values as a `Vec<u64>` in serde's DEFAULT encoding:
/// two zkVM words per value, which risc0's serde reads element by element (the packed
/// image above has the same number of words but is read in bulk). This is the form of
/// their `CmEpochState::heap_vals: Vec<u64>` (aggregator/core/src/lib.rs:982), i.e.
/// what a direct port in the style of their CM state would send. Used only by the
/// `kmv_query_words` guest, a sensitivity row (the pattern of ../../hll's
/// `hll_query_words`): the conversion to `KmvQueryInput` is a move (no copy), the query
/// is identical and so is the journal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmvEpochStateWords {
    pub total_count: u64,
    pub values: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmvQueryInputWords {
    pub query: KmvQuery,
    pub epoch_states: Vec<KmvEpochStateWords>,
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

impl From<KmvQueryInputWords> for KmvQueryInput {
    fn from(w: KmvQueryInputWords) -> Self {
        KmvQueryInput {
            query: w.query,
            epoch_states: w
                .epoch_states
                .into_iter()
                .map(|s| KmvEpochState { total_count: s.total_count, values: s.values })
                .collect(),
            epoch_chain_links: w.epoch_chain_links,
        }
    }
}

impl From<&KmvQueryInput> for KmvQueryInputWords {
    fn from(p: &KmvQueryInput) -> Self {
        KmvQueryInputWords {
            query: p.query.clone(),
            epoch_states: p
                .epoch_states
                .iter()
                .map(|s| KmvEpochStateWords { total_count: s.total_count, values: s.values.clone() })
                .collect(),
            epoch_chain_links: p.epoch_chain_links.clone(),
        }
    }
}

// ---------------------------------------------------------------- serde helper
/// Serializes a Vec<u64> as one byte string (the values' big-endian image) through
/// serde's bytes type, which risc0's serde packs four bytes per word and reads in bulk
/// (risc0-zkvm serde deserializer.rs deserialize_bytes); the deserializer converts the
/// image back, 8 bytes per value. The pattern of the HLL port's `packed_bytes` helper
/// (ours, not upstream). Plain serde, no extra crate.
mod packed_u64 {
    use alloc::vec::Vec;
    use core::fmt;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u64>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&super::kmv_values_be_bytes(v))
    }

    fn from_image<E: Error>(b: &[u8]) -> Result<Vec<u64>, E> {
        if b.len() % 8 != 0 {
            return Err(E::custom("packed u64 image length is not a multiple of 8"));
        }
        Ok(b.chunks_exact(8)
            .map(|c| u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
            .collect())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<u64>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a byte string of big-endian u64 values")
            }
            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Vec<u64>, E> {
                from_image(v)
            }
            fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Vec<u64>, E> {
                from_image(&v)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Vec<u64>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = a.next_element::<u8>()? {
                    out.push(b);
                }
                from_image(&out)
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
    fn epochs(keys: &[u64], m: usize, cbs: usize) -> (Vec<(KmvAggrInput, KmvEpochState)>, Vec<EpochChainLink>) {
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
            let inp = KmvAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
            let (st, out) = process_kmv_aggr_with_state(&inp);
            prev_chain_hash = out.epoch_chain_link.final_chain_hash;
            prev_tips = out.final_source_chain_tips.clone();
            links.push(out.epoch_chain_link);
            outs.push((inp, st));
        }
        (outs, links)
    }

    fn query_input(keys: &[u64], m: usize) -> KmvQueryInput {
        let (outs, links) = epochs(keys, m, 8);
        KmvQueryInput {
            query: KmvQuery::Estimate,
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

    /// Reference bottom-k: every distinct hash, sorted, first k.
    fn reference(keys: &[u64]) -> Vec<u64> {
        let mut h: Vec<u64> = keys.iter().map(|&k| kmv_hash64(&Event::make_key_id(0, k))).collect();
        h.sort_unstable();
        h.dedup();
        h.truncate(KMV_K);
        h
    }

    fn estimate_of(q: &KmvQueryOutput) -> (u64, bool) {
        let KmvQueryResult::Estimate { estimate, exact_count, .. } = q.result;
        (estimate, exact_count)
    }

    #[test]
    fn hash_is_the_hll_hash() {
        // the HLL port's hll_hash64 with the same seed (copied expression)
        let id = Event::make_key_id(0, 42);
        let seed = CM_SEEDS[0];
        let mut x = key_to_u64(&id) ^ (((seed as u64) << 32) | seed as u64);
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94d049bb133111eb);
        x ^= x >> 31;
        assert_eq!(kmv_hash64(&id), x);
    }

    #[test]
    fn epoch_state_is_bottom_k_and_merge_is_union() {
        let keys = lcg_keys(4 * 4096, 50_000);
        let (outs, _) = epochs(&keys, 4096, 8);
        for (e, (_, s)) in outs.iter().enumerate() {
            assert_eq!(s.values, reference(&keys[e * 4096..(e + 1) * 4096]));
        }
        let q = run_kmv_query(&query_input(&keys, 4096));
        let want = reference(&keys);
        let direct = kmv_estimate(&want, KMV_K);
        assert_eq!(q.result, direct);
        let exact = keys.iter().collect::<HashSet<_>>().len() as f64;
        let (est, ec) = estimate_of(&q);
        assert!(!ec);
        // standard error 1/sqrt(k-2) = 3.1%; allow 4 sigma
        assert!(((est as f64 - exact) / exact).abs() < 0.125, "estimate {est} exact {exact}");
        assert_eq!(q.support, keys.len() as u64);
        assert!(!q.suppressed);
    }

    #[test]
    fn below_k_is_exact() {
        let keys = lcg_keys(2 * 512, 300);
        let q = run_kmv_query(&query_input(&keys, 512));
        let exact = keys.iter().collect::<HashSet<_>>().len() as u64;
        assert_eq!(estimate_of(&q), (exact, true));
    }

    #[test]
    fn merge_bottom_k_edges() {
        assert_eq!(merge_bottom_k(&[], &[], 4), Vec::<u64>::new());
        assert_eq!(merge_bottom_k(&[1, 3, 5], &[], 2), [1, 3]);
        assert_eq!(merge_bottom_k(&[1, 3, 5], &[1, 2, 5, 9], 10), [1, 2, 3, 5, 9]);
        assert_eq!(merge_bottom_k(&[2, 4], &[1, 3], 3), [1, 2, 3]);
        assert_eq!(merge_bottom_k(&[7], &[7], 1), [7]);
    }

    #[test]
    fn insert_order_and_duplicates_do_not_matter() {
        let keys = lcg_keys(5000, 3000);
        let mut a = BTreeSet::new();
        let mut b = BTreeSet::new();
        for &k in &keys {
            kmv_insert(&mut a, kmv_hash64(&Event::make_key_id(0, k)), KMV_K);
        }
        for &k in keys.iter().rev() {
            kmv_insert(&mut b, kmv_hash64(&Event::make_key_id(0, k)), KMV_K);
        }
        assert_eq!(a, b);
        assert_eq!(a.into_iter().collect::<Vec<_>>(), reference(&keys));
    }

    #[test]
    fn estimator_integer_arithmetic() {
        // v_k = 2^64 / 4 with k = 1024 values: (k-1) * 4
        let mut v: Vec<u64> = (1..KMV_K as u64).collect();
        v.push(1u64 << 62);
        let KmvQueryResult::Estimate { estimate, v_k, .. } = kmv_estimate(&v, KMV_K);
        assert_eq!((estimate, v_k), (4 * (KMV_K as u64 - 1), 1 << 62));
        // smallest possible v_k = k-1 saturates at u64::MAX instead of overflowing
        let w: Vec<u64> = (0..KMV_K as u64).collect();
        let KmvQueryResult::Estimate { estimate, .. } = kmv_estimate(&w, KMV_K);
        assert_eq!(estimate, u64::MAX);
    }

    #[test]
    #[should_panic(expected = "state_commit mismatch")]
    fn tampered_state_is_rejected() {
        let mut q = query_input(&lcg_keys(2 * 1024, 5_000), 1024);
        q.epoch_states[1].values[7] ^= 1;
        run_kmv_query(&q);
    }

    #[test]
    #[should_panic(expected = "chain broken")]
    fn reordered_epochs_are_rejected() {
        let mut q = query_input(&lcg_keys(3 * 1024, 5_000), 1024);
        q.epoch_states.swap(1, 2);
        q.epoch_chain_links.swap(1, 2);
        run_kmv_query(&q);
    }

    #[test]
    #[should_panic(expected = "batch_hash mismatch")]
    fn forged_batch_is_rejected() {
        let (mut outs, _) = epochs(&lcg_keys(1024, 5_000), 1024, 8);
        outs[0].0.batches[3].events[0].key_id = Event::make_key_id(0, 999_999);
        process_kmv_aggr(&outs[0].0);
    }

    #[test]
    fn low_support_is_suppressed() {
        let q = run_kmv_query(&query_input(&[1, 2, 3], 3)).suppress_if_low_support();
        assert!(q.suppressed);
        assert_eq!(q.support, 0);
        assert_eq!(estimate_of(&q), (0, false));
    }

    #[test]
    fn zkvm_serde_roundtrip() {
        let q = query_input(&lcg_keys(2 * 4096, 50_000), 4096);
        let words = to_vec(&q).unwrap();
        assert_eq!(from_slice::<KmvQueryInput, _>(&words).unwrap(), q);
        // variant + states (len; per epoch: total_count 2, byte length 1 + 8 bytes = 2
        // packed words per value) + links (len; per epoch 3 x 32 bytes, one word each)
        let vals: usize = q.epoch_states.iter().map(|s| s.values.len()).sum();
        assert_eq!(words.len(), 1 + 1 + 2 * 3 + 2 * vals + 1 + 2 * 3 * 32);
        assert!(q.epoch_states.iter().all(|s| s.values.len() == KMV_K));
    }

    #[test]
    fn packed_image_roundtrip() {
        // short image (3 values = 24 bytes = 6 packed words), byte order big-endian
        let s = KmvEpochState { total_count: 3, values: std::vec![1, 2, u64::MAX] };
        let v = to_vec(&s).unwrap();
        assert_eq!(from_slice::<KmvEpochState, _>(&v).unwrap(), s);
        assert_eq!(kmv_values_be_bytes(&s.values)[8..16], 2u64.to_be_bytes());
    }

    #[test]
    fn words_variant_is_the_same_input_and_query() {
        let q = query_input(&lcg_keys(2 * 4096, 50_000), 4096);
        let ww = to_vec(&KmvQueryInputWords::from(&q)).unwrap();
        let back = KmvQueryInput::from(from_slice::<KmvQueryInputWords, _>(&ww).unwrap());
        assert_eq!(back, q);
        assert_eq!(run_kmv_query(&back), run_kmv_query(&q));
        // the same number of zkVM words as the packed image (len + 2 per value): the
        // difference is how risc0's serde reads them, element by element
        assert_eq!(ww.len(), to_vec(&q).unwrap().len());
    }
}
