#![no_std]
//! HyperLogLog epoch summary for the zk-Analytics pipeline (baseline port, ours).
//!
//! zk-Analytics (SIGCOMM'26, commit d4a5a9a) ships three epoch summary types (samples,
//! histogram, cm) and no distinct-count sketch. This crate adds a fourth one in THEIR
//! architecture and with THEIR plumbing, and nothing else:
//!
//! * aggregation (`process_hll_aggr_with_state`) is `process_cm_aggr_with_state`
//!   (aggregator/core/src/lib.rs:1215-1301) with the CM table + heap replaced by 2^14
//!   HyperLogLog registers: verify the source SHA-256 batch hash chain
//!   (`verify_and_compute_chain`, verbatim), flatten the batches, build the epoch's
//!   summary from scratch, hash the state with an unsalted, tagged SHA-256, and link it
//!   into the epoch chain with their `EpochChainLink::new`.
//! * query (`run_hll_query`) is `run_cm_query` (querier/core/src/lib.rs:249-371) with
//!   the CM merge + lookup replaced by an elementwise-max register merge and the
//!   HyperLogLog estimator: verify the epoch chain links (`verify_epoch_chain_integrity`,
//!   verbatim), recompute every epoch's state commitment, merge, answer, and publish
//!   the chain boundaries + state commits + result, with their low-support suppression.
//!
//! The sketch is the textbook plaintext algorithm (Flajolet, Fusy, Gandouet, Meunier
//! 2007). No oblivious padding, memory checking, sorting certificate or algebraic hash:
//! plain Rust executed as a RISC Zero guest, exactly as their three summaries are.
//!
//! The functions that are private upstream are include!d verbatim from
//! `upstream_verbatim.rs` (generated and checked by ../gen_upstream.sh).

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
/// Register-index bits (the zkSketch paper default b = 14).
pub const HLL_P: u32 = 14;
/// Number of registers m = 2^b.
pub const HLL_M: usize = 1 << HLL_P;
/// Bits left after the index; rank = 1 + leading zeros of these bits, so 1..=51.
pub const HLL_W_BITS: u32 = 64 - HLL_P;
pub const HLL_MAX_RANK: u32 = HLL_W_BITS + 1;
/// Seed of the key hash. Reuses their CM row-0 seed (aggregator/core/src/lib.rs:41).
pub const HLL_SEED: u32 = CM_SEEDS[0];

/// Domain separator for the HLL state commitment, named after their per-type tags
/// (TAG_CM_STATE_COMMIT etc., aggregator/core/src/lib.rs:46-48). Ours, not upstream.
const TAG_HLL_STATE_COMMIT: &[u8] = b"ZKTLM_HLL_STATE_COMMIT_V1";

// ------------------------------------------------------------------------ hash
/// 64-bit key hash: their FNV-1a key fold `key_to_u64` (aggregator/core/src/lib.rs:342)
/// followed by the seeded splitmix64 finaliser of their `cm_bucket_index`
/// (aggregator/core/src/lib.rs:1055-1063), without the final `% CM_COLS`.
#[inline]
pub fn hll_hash64(key_id: &[u8; KEY_BYTES_LEN]) -> u64 {
    let seed = HLL_SEED;
    let mut x = key_to_u64(key_id) ^ (((seed as u64) << 32) | seed as u64);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

/// (register index, rank): index = low b bits of the hash, rank = 1 + number of
/// leading zeros of the remaining 64-b bits (51 when they are all zero).
#[inline]
pub fn hll_index_rank(h: u64) -> (usize, u8) {
    let idx = (h as usize) & (HLL_M - 1);
    let w = h >> HLL_P; // < 2^(64-b), so leading_zeros(w) >= b
    let rank = (w.leading_zeros() - HLL_P + 1) as u8;
    (idx, rank)
}

// ----------------------------------------------------------------------- state
/// Epoch state: the event count and the m registers (u8 each). The registers travel
/// as a packed byte string (4 registers per zkVM word) instead of one word per u8.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HllEpochState {
    pub total_count: u64,
    #[serde(with = "packed_bytes")]
    pub registers: Vec<u8>,
}

/// Unsalted SHA-256 over the serialized state, in the style of their
/// `cm_epoch_state_commit` (aggregator/core/src/lib.rs:1009-1029): tag, then the
/// scalar fields big-endian, then the state body.
pub fn hll_epoch_state_commit(state: &HllEpochState) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    sha.update(TAG_HLL_STATE_COMMIT);
    sha.update(&state.total_count.to_be_bytes());
    sha.update(&state.registers);
    sha.finalize().into()
}

/// Their aggregation input, reused unchanged: `CmAggrInput`
/// (aggregator/core/src/lib.rs:945-955) is field-for-field identical to
/// `SamplesAggrInput` and `HistogramAggrInput` and carries nothing CM-specific:
/// prev_chain_hash, batches (events + producer batch hashes), prev_source_chain_tips.
pub type HllAggrInput = aggregator_core::CmAggrInput;

/// Public journal of the aggregation guest: `CmAggrOutput`
/// (aggregator/core/src/lib.rs:1033-1053) minus its CM-specific Merkle roots
/// (row_roots, cm_root, heap_root). Those roots are not read by any of their query
/// guests; dropping them only makes this baseline cheaper.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HllAggrOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

pub fn process_hll_aggr(input: &HllAggrInput) -> HllAggrOutput {
    let (_, out) = process_hll_aggr_with_state(input);
    out
}

pub fn process_hll_aggr_with_state(input: &HllAggrInput) -> (HllEpochState, HllAggrOutput) {
    process_hll_aggr_probed(input, &mut || {})
}

/// Aggregation with a phase probe. `probe` is called after each phase (4 calls:
/// chain, flatten, update, commit); the guest records its cycle counter there, the
/// host passes a no-op. The computation is the same in both.
pub fn process_hll_aggr_probed(
    input: &HllAggrInput,
    probe: &mut dyn FnMut(),
) -> (HllEpochState, HllAggrOutput) {
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

    // --- the summary: textbook HyperLogLog update, built from scratch per epoch
    let mut total_count = 0u64;
    let mut registers = vec![0u8; HLL_M];
    for ev in &all_events {
        total_count = total_count.saturating_add(1);
        let (idx, rank) = hll_index_rank(hll_hash64(&ev.key_id));
        if rank > registers[idx] {
            registers[idx] = rank;
        }
    }
    let state = HllEpochState { total_count, registers };
    probe(); // phase 3: HLL update

    // --- state commit + epoch link, as every upstream epoch type does
    let state_commit = hll_epoch_state_commit(&state);
    let epoch_chain_link = EpochChainLink::new(input.prev_chain_hash, state_commit);
    let out = HllAggrOutput {
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
pub enum HllQuery {
    /// Distinct-count estimate over the union of the queried epochs.
    Estimate,
}

/// Same shape as their `CmQueryInput` (querier/core/src/lib.rs:186-196).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HllQueryInput {
    pub query: HllQuery,
    pub epoch_states: Vec<HllEpochState>,
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HllQueryResult {
    Estimate {
        /// Final estimate, rounded to the nearest integer.
        estimate: u64,
        /// Raw HLL estimate alpha_m m^2 / sum 2^-M[j], rounded (before the small-range correction).
        raw_estimate: u64,
        /// Number of merged registers (m).
        registers: u32,
        /// Merged registers still zero (V).
        zero_registers: u32,
        /// Whether the small-range correction (linear counting m ln(m/V)) was applied.
        linear_counting: bool,
    },
}

/// Same shape as their `CmQueryOutput` (querier/core/src/lib.rs:207-228).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HllQueryOutput {
    pub chain_prev_hash: [u8; 32],
    pub chain_final_hash: [u8; 32],
    pub state_commits: Vec<[u8; 32]>,
    pub result: HllQueryResult,
    /// Records the estimate is computed over (sum of the epochs' total_count).
    pub support: u64,
    pub suppressed: bool,
}

impl HllQueryOutput {
    /// Their suppressed-sentinel rule (querier/core/src/lib.rs:236-247 for CM):
    /// support < MIN_SUPPORT zeroes every numeric result field and support.
    pub fn suppress_if_low_support(mut self) -> Self {
        if self.support < MIN_SUPPORT {
            self.result = match self.result {
                HllQueryResult::Estimate { registers, .. } => HllQueryResult::Estimate {
                    estimate: 0,
                    raw_estimate: 0,
                    registers,
                    zero_registers: 0,
                    linear_counting: false,
                },
            };
            self.support = 0;
            self.suppressed = true;
        }
        self
    }
}

/// Standard HyperLogLog estimator with the small-range (linear counting) correction.
/// With a 64-bit hash no large-range correction applies. The sum of 2^-M[j] is formed
/// exactly (register-value histogram, u128 fixed point) and converted to f64 once;
/// ln comes from `libm`, so the result is bit-identical on the host and in the guest.
pub fn hll_estimate(registers: &[u8]) -> HllQueryResult {
    hll_estimate_probed(registers, &mut || {})
}

/// `probe` is called once, after the pass over the registers (before the f64 part).
pub fn hll_estimate_probed(registers: &[u8], probe: &mut dyn FnMut()) -> HllQueryResult {
    let mut hist = [0u32; HLL_MAX_RANK as usize + 1];
    for &r in registers {
        hist[r as usize] += 1;
    }
    probe();
    let mut sum_fixed: u128 = 0; // sum_j 2^(MAX_RANK - M[j])
    for (r, &c) in hist.iter().enumerate() {
        sum_fixed += (c as u128) << (HLL_MAX_RANK - r as u32);
    }
    let m = registers.len() as f64;
    let z = sum_fixed as f64 / ((1u64 << HLL_MAX_RANK) as f64); // sum_j 2^-M[j]
    let alpha = 0.7213 / (1.0 + 1.079 / m);
    let raw = alpha * m * m / z;
    let zeros = hist[0];
    let (est, lc) = if raw <= 2.5 * m && zeros != 0 {
        (m * libm::log(m / zeros as f64), true)
    } else {
        (raw, false)
    };
    HllQueryResult::Estimate {
        estimate: libm::round(est) as u64,
        raw_estimate: libm::round(raw) as u64,
        registers: registers.len() as u32,
        zero_registers: zeros,
        linear_counting: lc,
    }
}

pub fn run_hll_query(input: &HllQueryInput) -> HllQueryOutput {
    run_hll_query_probed(input, &mut || {})
}

/// Query with a phase probe (5 calls: chain links, state commits, merge, estimator
/// register pass, estimator f64 part).
pub fn run_hll_query_probed(input: &HllQueryInput, probe: &mut dyn FnMut()) -> HllQueryOutput {
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
            let computed_commit = hll_epoch_state_commit(state);
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

    // --- merge at query time: registers by elementwise max, counts by sum
    let mut merged = vec![0u8; HLL_M];
    let mut support = 0u64;
    for state in &input.epoch_states {
        assert!(state.registers.len() == HLL_M, "epoch state has {} registers, expected {}", state.registers.len(), HLL_M);
        support = support.wrapping_add(state.total_count);
        for (m, &r) in merged.iter_mut().zip(state.registers.iter()) {
            if r > *m {
                *m = r;
            }
        }
    }
    probe(); // phase 3: merge

    let result = match input.query {
        HllQuery::Estimate => hll_estimate_probed(&merged, probe), // phase 4: register pass
    };
    probe(); // phase 5: estimator f64 part (u128 sum, f64 arithmetic, libm ln, rounding)

    HllQueryOutput {
        chain_prev_hash,
        chain_final_hash,
        state_commits,
        result,
        support,
        suppressed: false,
    }
}

// ------------------------------------------------- naive-serde input variant
/// The same query input with the registers in serde's DEFAULT encoding for Vec<u8>,
/// which risc0's serde writes as one 32-bit word per register (4x the words of the
/// packed encoding above). Used only by the `hll_query_words` guest, a sensitivity
/// row: it is what a direct port in the style of their `CmEpochState` would get
/// (`heap_occ: Vec<u8>` is serialized this way, aggregator/core/src/lib.rs:984).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HllEpochStateWords {
    pub total_count: u64,
    pub registers: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HllQueryInputWords {
    pub query: HllQuery,
    pub epoch_states: Vec<HllEpochStateWords>,
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

impl From<HllQueryInputWords> for HllQueryInput {
    fn from(w: HllQueryInputWords) -> Self {
        HllQueryInput {
            query: w.query,
            epoch_states: w
                .epoch_states
                .into_iter()
                .map(|s| HllEpochState { total_count: s.total_count, registers: s.registers })
                .collect(),
            epoch_chain_links: w.epoch_chain_links,
        }
    }
}

impl From<&HllQueryInput> for HllQueryInputWords {
    fn from(p: &HllQueryInput) -> Self {
        HllQueryInputWords {
            query: p.query.clone(),
            epoch_states: p
                .epoch_states
                .iter()
                .map(|s| HllEpochStateWords { total_count: s.total_count, registers: s.registers.clone() })
                .collect(),
            epoch_chain_links: p.epoch_chain_links.clone(),
        }
    }
}

// ---------------------------------------------------------------- serde helper
/// Serializes a Vec<u8> through serde's bytes type, which risc0's serde packs four
/// bytes per word (risc0-zkvm serde/serializer.rs serialize_bytes) and deserializes
/// without a copy (visit_byte_buf). Plain serde, no extra crate.
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

    /// Epoch inputs for `keys` split into epochs of `m`, batches of `cbs`, chained as
    /// their aggregator host does (the same construction as the host driver).
    fn epochs(keys: &[u64], m: usize, cbs: usize) -> (Vec<(HllAggrInput, HllEpochState)>, Vec<EpochChainLink>) {
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
            let inp = HllAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
            let (st, out) = process_hll_aggr_with_state(&inp);
            prev_chain_hash = out.epoch_chain_link.final_chain_hash;
            prev_tips = out.final_source_chain_tips.clone();
            links.push(out.epoch_chain_link);
            outs.push((inp, st));
        }
        (outs, links)
    }

    fn query_input(keys: &[u64], m: usize) -> HllQueryInput {
        let (outs, links) = epochs(keys, m, 8);
        HllQueryInput {
            query: HllQuery::Estimate,
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

    #[test]
    fn rank_edges() {
        assert_eq!(hll_index_rank(0), (0, HLL_MAX_RANK as u8)); // remaining bits all zero
        assert_eq!(hll_index_rank(1u64 << 63), (0, 1));
        assert_eq!(hll_index_rank(1u64 << HLL_P), (0, HLL_W_BITS as u8));
        assert_eq!(hll_index_rank((1u64 << HLL_P) - 1).0, HLL_M - 1);
    }

    #[test]
    fn merge_is_union_and_estimate_is_close() {
        let keys = lcg_keys(4 * 4096, 50_000);
        let q = run_hll_query(&query_input(&keys, 4096));
        // registers of the union == elementwise max of the per-epoch registers
        let (whole, _) = epochs(&keys, keys.len(), 8);
        let HllQueryResult::Estimate { estimate, zero_registers, .. } = q.result;
        let direct = hll_estimate(&whole[0].1.registers);
        assert_eq!(direct, q.result);
        let exact = keys.iter().collect::<std::collections::HashSet<_>>().len() as f64;
        assert!(((estimate as f64 - exact) / exact).abs() < 0.03, "estimate {estimate} exact {exact}");
        assert!(zero_registers > 0);
        assert_eq!(q.support, keys.len() as u64);
        assert!(!q.suppressed);
    }

    #[test]
    fn raw_estimator_branch() {
        // enough distinct keys that alpha m^2/Z > 2.5 m: no linear counting
        let keys: Vec<u64> = (0..200_000u64).collect();
        let (whole, _) = epochs(&keys, keys.len(), 64);
        let r = hll_estimate(&whole[0].1.registers);
        let HllQueryResult::Estimate { estimate, linear_counting, .. } = r;
        assert!(!linear_counting);
        assert!(((estimate as f64 - 200_000.0) / 200_000.0).abs() < 0.03, "{estimate}");
    }

    #[test]
    #[should_panic(expected = "state_commit mismatch")]
    fn tampered_state_is_rejected() {
        let mut q = query_input(&lcg_keys(2 * 1024, 5_000), 1024);
        let r = &mut q.epoch_states[1].registers;
        r[7] = r[7].wrapping_add(1);
        run_hll_query(&q);
    }

    #[test]
    #[should_panic(expected = "chain broken")]
    fn reordered_epochs_are_rejected() {
        let mut q = query_input(&lcg_keys(3 * 1024, 5_000), 1024);
        q.epoch_states.swap(1, 2);
        q.epoch_chain_links.swap(1, 2);
        run_hll_query(&q);
    }

    #[test]
    #[should_panic(expected = "batch_hash mismatch")]
    fn forged_batch_is_rejected() {
        let (mut outs, _) = epochs(&lcg_keys(1024, 5_000), 1024, 8);
        outs[0].0.batches[3].events[0].key_id = Event::make_key_id(0, 999_999);
        process_hll_aggr(&outs[0].0);
    }

    #[test]
    #[cfg(feature = "root")]
    fn root_variants_agree_except_root() {
        let (outs, _) = epochs(&lcg_keys(3 * 1024, 5_000), 1024, 8);
        for (inp, st) in &outs {
            let (_, legacy) = process_hll_aggr_with_state(inp);
            let (sd, d) = process_hll_aggr_root(inp, HllRoot::Buckets64);
            let (sn, n) = process_hll_aggr_root(inp, HllRoot::None);
            assert_eq!(&sd, st);
            assert_eq!(&sn, st);
            assert_eq!(d.without_root(), legacy);
            assert_eq!(n.without_root(), legacy);
            assert_eq!(n.buckets_root, [0u8; 32]);
            assert_ne!(d.buckets_root, [0u8; 32]);
            // independent recomputation: 64 leaves over 256-register groups, their fold
            let leaves: Vec<[u8; 32]> = (0..64)
                .map(|j| {
                    let mut sha = <rust_crypto::Sha256 as rust_crypto::Digest>::new();
                    rust_crypto::Digest::update(&mut sha, b"ZKA_PORT_HLL_BUCKET_V1");
                    rust_crypto::Digest::update(&mut sha, &st.registers[256 * j..256 * (j + 1)]);
                    rust_crypto::Digest::finalize(sha).into()
                })
                .collect();
            assert_eq!(d.buckets_root, aggregator_core::samples_buckets_root_from_leaves(&leaves));
            // the root binds every group: flipping one register changes it
            let mut r2 = st.registers.clone();
            r2[HLL_M - 1] ^= 1;
            assert_ne!(hll_buckets_root(&r2), d.buckets_root);
        }
    }

    #[test]
    fn low_support_is_suppressed() {
        let q = run_hll_query(&query_input(&[1, 2, 3], 3)).suppress_if_low_support();
        assert!(q.suppressed);
        assert_eq!(q.support, 0);
    }

    #[test]
    fn zkvm_serde_roundtrip_and_packing() {
        let q = query_input(&lcg_keys(2 * 1024, 5_000), 1024);
        let packed = to_vec(&q).unwrap();
        assert_eq!(from_slice::<HllQueryInput, _>(&packed).unwrap(), q);
        let w = HllQueryInputWords::from(&q);
        let words = to_vec(&w).unwrap();
        assert_eq!(HllQueryInput::from(from_slice::<HllQueryInputWords, _>(&words).unwrap()), q);
        // 2 epochs x (16384 - 4096) extra words for the unpacked registers
        assert_eq!(words.len() - packed.len(), 2 * (HLL_M - HLL_M / 4));
    }
}

// The six-sketch root variants (root.rs), compiled only with the `root` feature: the
// hll aggr_root guest and the host driver enable it; the legacy guests build this crate
// without it, i.e. exactly as before the variants were added (same code, same cycles).
#[cfg(feature = "root")]
mod root;
#[cfg(feature = "root")]
pub use root::*;
