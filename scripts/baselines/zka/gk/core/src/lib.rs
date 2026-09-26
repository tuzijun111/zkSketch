#![no_std]

//! Greenwald-Khanna (GK) quantile summary run inside zk-Analytics' own epoch
//! pipeline (Zhu et al., "Zero-Knowledge Cloud Analytics", SIGCOMM '26; code at
//! commit d4a5a9a). zk-Analytics does not ship a GK summary. This crate is OUR
//! instantiation of their general-purpose method for one:
//!
//!   aggregation (one guest run per epoch)
//!     1. verify the data source's SHA-256 batch hash chain  -- their code, verbatim
//!     2. build the epoch's summary FROM SCRATCH             -- textbook GK, plain Rust
//!     3. Merkle root over the state entries                 -- their per-type pattern
//!     4. unsalted SHA-256 state commitment                  -- their pattern
//!     5. link the commitment into the epoch hash chain      -- their EpochChainLink
//!   query (one guest run per query)
//!     1. re-verify the epoch chain links                    -- their code, verbatim
//!     2. recompute every epoch's state commitment           -- their pattern
//!     3. MERGE the per-epoch summaries at query time        -- one-shot GK union
//!     4. answer; low-support suppression                    -- their MIN_SUPPORT rule
//!
//! Only the summary update (step 2), its merge and its query are ours. Nothing here
//! uses zkSketch's circuit techniques (no oblivious padding, no memory checking, no
//! sorting certificates, no Poseidon). Every cycle the guest spends is ordinary
//! RISC-V execution of the code below, so the cycle count is data-dependent.
//!
//! Upstream items that are `pub` are imported. Items that are private upstream are
//! copied VERBATIM below, each with its upstream file:line at commit d4a5a9a.

extern crate alloc;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use hashbrown::HashMap;
#[cfg(target_os = "zkvm")]
use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
#[cfg(not(target_os = "zkvm"))]
use rust_crypto::{Digest as _, Sha256};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};
use zkvm_common::{Event, HASH_BYTES_LEN};

use aggregator_core::merkle::MerkleTree;
pub use aggregator_core::{batch_chain_hash, BatchInput, EpochChainLink};
pub use querier_core::MIN_SUPPORT;

// ===========================================================================
// Parameters (compile-time constants, bound by the guest image ID exactly like
// their HISTOGRAM_SLOTS / CM_TOPK_SLOTS).
// ===========================================================================

/// epsilon = 1 / GK_EPS_DEN  (the zkSketch paper's GK default, eps = 1/51).
pub const GK_EPS_DEN: u64 = 51;
/// COMPRESS runs every floor(1/(2 eps)) observations = floor(51/2) = 25.
pub const GK_COMPRESS_EVERY: u64 = GK_EPS_DEN / 2;

/// Domain separators, named after their TAG_* scheme (aggregator/core/src/lib.rs:44-64).
const TAG_GK_STATE_COMMIT: &[u8] = b"ZKTLM_GK_STATE_COMMIT_V1";
const TAG_GK_TUPLE_LEAF: &[u8] = b"ZKTLM_GK_TUPLE_LEAF_V1";

// ===========================================================================
// VERBATIM copies of private zk-Analytics items (commit d4a5a9a).
// ===========================================================================

/// aggregator/core/src/lib.rs:56-57 (private there)
/// Tag for batch-level shard chain (matches data_source and kafka_producer)
const TAG_SHARD_CHAIN: &[u8] = b"ZKTLM_SHARD_CHAIN_V1";

/// aggregator/core/src/lib.rs:82-91 (private there)
const fn next_pow2_ge(value: usize) -> usize {
    if value <= 1 {
        return 1;
    }
    let mut v = 1usize;
    while v < value {
        v <<= 1;
    }
    v
}

/// aggregator/core/src/lib.rs:93-99 (private there; querier/core/src/lib.rs:43-49 is
/// the same function with the return type spelled [u8; 32])
fn sha256_bytes(parts: &[&[u8]]) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    for p in parts {
        sha.update(p);
    }
    sha.finalize().into()
}

/// aggregator/core/src/lib.rs:295-305 (private there)
/// Compute commitment of events: SHA256(key_id || value || ts) for each event
/// Matches data_source and kafka_producer format (no TAG prefix)
fn events_commit(events: &[Event]) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    for ev in events {
        sha.update(&ev.key_id);                // 15 bytes key
        sha.update(&ev.value.to_be_bytes());   // 4 bytes value
        sha.update(&ev.ts.to_be_bytes());      // 4 bytes timestamp
    }
    sha.finalize().into()
}

/// aggregator/core/src/lib.rs:331-339 (private there)
/// Helper to convert HashMap chain tips to sorted Vec
fn chain_tips_to_sorted_vec(tips: HashMap<u32, (u64, [u8; HASH_BYTES_LEN])>) -> Vec<(u32, u64, [u8; HASH_BYTES_LEN])> {
    let mut vec: Vec<(u32, u64, [u8; HASH_BYTES_LEN])> = tips
        .into_iter()
        .map(|(source_id, (seq, tip))| (source_id, seq, tip))
        .collect();
    vec.sort_by_key(|(source_id, _, _)| *source_id);
    vec
}

/// aggregator/core/src/lib.rs:499-603 (private there), verbatim, doc comment trimmed.
/// Verify and compute batch-level per-source chain integrity inside ZK proof.
///   batch_hash = SHA256(TAG_SHARD_CHAIN || chain_prev || events_commit)
///   events_commit = SHA256(key_id || value || ts for each event in batch)
/// Returns: HashMap of source_id -> (last_processed_seq, final_chain_tip) after verification
/// NOTE: like upstream, this hashes every batch's events twice (`ev_commit` for the
/// debug message, then again inside batch_chain_hash); the copy keeps that cost.
fn verify_and_compute_chain(
    batches: &[BatchInput],
    prev_source_chain_tips: &[(u32, u64, [u8; HASH_BYTES_LEN])],
) -> HashMap<u32, (u64, [u8; HASH_BYTES_LEN])> {
    // Initialize chain state from aggregator's stored state: (last_seq, tip)
    let mut chain_state: HashMap<u32, (u64, [u8; HASH_BYTES_LEN])> = prev_source_chain_tips
        .iter()
        .map(|(source_id, seq, tip)| (*source_id, (*seq, *tip)))
        .collect();

    for batch in batches {
        let source_id = batch.source_id;
        let source_batch_seq = batch.source_batch_seq;

        // Determine expected chain_prev based on source_batch_seq and stored state
        let chain_prev = if source_batch_seq == 0 {
            // seq=0: chain always starts with [0;32] (producer fresh start)
            [0u8; HASH_BYTES_LEN]
        } else if let Some(&(last_seq, stored_tip)) = chain_state.get(&source_id) {
            // Validate sequence continuity: incoming seq must be last_seq + 1
            if source_batch_seq != last_seq + 1 {
                panic!(
                    "batch sequence gap for source_id={}: expected seq={} but got seq={}\n\
                     (last_seq={}, stored_tip={:?})",
                    source_id, last_seq + 1, source_batch_seq,
                    last_seq, stored_tip
                );
            }
            // Use stored chain tip from previous batch
            stored_tip
        } else {
            // First batch from this source in this epoch, seq must be 0
            if source_batch_seq != 0 {
                panic!(
                    "first batch from source_id={} has seq={} but expected seq=0 (no prior state)",
                    source_id, source_batch_seq
                );
            }
            [0u8; HASH_BYTES_LEN]
        };

        // Compute events_commit separately for debugging
        let ev_commit = events_commit(&batch.events);

        // RECOMPUTE batch_hash from events
        let computed_hash = batch_chain_hash(chain_prev, &batch.events);

        // VERIFY producer's hash matches recomputed hash
        if computed_hash != batch.sent_batch_hash {
            // Build detailed debug message for hash mismatch
            let mut msg = format!(
                "batch_hash mismatch for source_id={} source_batch_seq={}\n\
                 chain_prev={:?}\n\
                 events_commit={:?}\n\
                 TAG_SHARD_CHAIN={:?}\n\
                 num_events={}\n",
                source_id, source_batch_seq, chain_prev, ev_commit, TAG_SHARD_CHAIN, batch.events.len()
            );
            // Log first few events for debugging
            for (i, ev) in batch.events.iter().take(3).enumerate() {
                msg.push_str(&format!(
                    "event[{}]: key_id={:?} value={} ts={}\n",
                    i, ev.key_id, ev.value, ev.ts
                ));
            }
            if batch.events.len() > 3 {
                msg.push_str(&format!("... and {} more events\n", batch.events.len() - 3));
            }
            msg.push_str(&format!(
                "producer_hash={:?}\ncomputed_hash={:?}",
                batch.sent_batch_hash, computed_hash
            ));
            panic!("{}", msg);
        }

        // Update chain state (seq, tip) for next batch
        chain_state.insert(source_id, (source_batch_seq, computed_hash));
    }

    chain_state
}

/// querier/core/src/lib.rs:41 (private there)
const TAG_EPOCH_CHAIN: &[u8] = b"ZKTLM_EPOCH_CHAIN_V1";

/// querier/core/src/lib.rs:98-136 (private there), verbatim.
/// Verify epoch hash chain integrity inside ZK proof.
/// Verifies:
/// 1. Each epoch's final_chain_hash is computed correctly: hash(TAG || prev || state_commit)
/// 2. Chain is linked: prev_chain_hash[n] == final_chain_hash[n-1]
fn verify_epoch_chain_integrity(chain_links: &[EpochChainLink]) {
    for (i, link) in chain_links.iter().enumerate() {
        // Verify epoch hash computation: final_chain_hash = hash(TAG || prev || state_commit)
        let computed_hash = sha256_bytes(&[
            TAG_EPOCH_CHAIN,
            &link.prev_chain_hash,
            &link.state_commit,
        ]);
        assert!(
            computed_hash == link.final_chain_hash,
            "epoch {} hash mismatch: computed != expected",
            i
        );

        // Verify chain linkage within each aggregator's chain. In the distributed
        // deployment the queried epochs come from multiple independent per-aggregator
        // chains, each rooted at the genesis hash ([0u8; 32]). A link whose
        // prev_chain_hash is genesis starts a new chain, so it is not linked to the
        // previous (different-chain) epoch. Callers sort epochs by
        // (aggregator_id, sequence) so each chain is contiguous and ordered; the
        // per-epoch hash computation above is still verified for every link.
        const GENESIS: [u8; 32] = [0u8; 32];
        if i > 0 && link.prev_chain_hash != GENESIS {
            let prev_link = &chain_links[i - 1];
            assert!(
                link.prev_chain_hash == prev_link.final_chain_hash,
                "epoch {} chain broken: prev_hash != prev_epoch_final_hash",
                i
            );
        }
    }
}

// ===========================================================================
// Textbook GK (Greenwald & Khanna, SIGMOD 2001), plain Rust.
//
//   S = <t_0 .. t_{s-1}>, t_i = (v_i, g_i, Delta_i), sorted by v.
//   rmin(v_i) = sum_{j<=i} g_j ;  rmax(v_i) = rmin(v_i) + Delta_i.
//   To add the (n+1)-st observation v:
//     if n = 0 mod floor(1/(2 eps)) then COMPRESS()
//     INSERT(v); n = n + 1
//   INSERT(v): find the smallest i with v_{i-1} <= v < v_i and insert (v, 1, floor(2 eps n))
//     before t_i; if v is the new minimum or maximum seen, insert (v, 1, 0).
//   COMPRESS(): for i from s-2 down to 1 (t_0 is kept, see below):
//     if BAND(Delta_i, 2 eps n) <= BAND(Delta_{i+1}, 2 eps n) and
//        g*_i + g_{i+1} + Delta_{i+1} < 2 eps n
//     then delete t_i and all its descendants, g_{i+1} += g*_i
//     (g*_i = g of t_i plus all its descendants; the parent of t_i is the nearest
//      t_j, j > i, with a strictly larger band.)
//   band_0 = {p};  band_a = {Delta : p - 2^a - (p mod 2^a) < Delta <= p - 2^(a-1) - (p mod 2^(a-1))},
//   p = floor(2 eps n).
// Delta = floor(2 eps n) uses n = observations BEFORE this one, as in the paper.
//
// Minimum and maximum. The paper (section 2.1) states: "We ensure that, at all times,
// the maximum and the minimum values are part of the summary. In other words, v_0 and
// v_{s-1} always correspond to the minimum and the maximum elements seen so far", and
// the j = 0 case of its Proposition 1 needs it. Its Figure 2 pseudocode loops down to
// i = 0, which would let COMPRESS merge t_0 into t_1 whenever t_1 also has Delta = 0
// (a former minimum). We follow the stated invariant: the loop stops at i = 1 and t_0
// is always kept. t_{s-1} is never deleted by construction (deletions go right).
// t_0 has Delta = 0, which for p >= 1 is alone in the top band floor(log2 p) + 1, so
// t_0 is never inside another tuple's descendant block (asserted in compress()).
//
// Band special case. The paper puts "the first 1/2eps observations, with Delta = 0,
// in a band of their own". With the band formula above this holds automatically:
// for p >= 1, Delta = 0 is the only member of band floor(log2 p) + 1 (tested in
// band_delta0_is_alone_in_top_band), and for p = 0 nothing can merge because the
// capacity test g*_i + g_{i+1} + Delta_{i+1} < 2 eps n < 1 fails for g >= 1.
// ===========================================================================

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkTuple {
    pub v: u32,
    pub g: u32,
    pub delta: u32,
}

/// Epoch state: the GK tuple list and the number of observations it summarises.
/// This is what the host stores privately and the query guest re-hashes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkEpochState {
    pub total_count: u64,
    pub tuples: Vec<GkTuple>,
}

/// Phase marks. The measured guests pass a no-op closure (compiled away); only the
/// separate profiling guest reads the cycle counter at these points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    ChainVerified,
    EventsFlattened,
    CompressBegin,
    CompressEnd,
    SummaryBuilt,
    RootDone,
    CommitDone,
    LinkDone,
}

/// BAND(Delta, 2 eps n) with p = floor(2 eps n); requires delta <= p.
pub fn gk_band(delta: u64, p: u64) -> u32 {
    if delta == p {
        return 0;
    }
    debug_assert!(delta < p);
    let x = p - delta;
    let mut a = 1u32;
    loop {
        let m = 1u64 << a;
        // band_a: 2^(a-1) + (p mod 2^(a-1)) <= p - Delta < 2^a + (p mod 2^a); the
        // lower edge holds for the smallest such a because the bands tile [1, inf).
        if x < m + (p & (m - 1)) {
            return a;
        }
        a += 1;
    }
}

/// floor(2 eps n) for eps = 1/GK_EPS_DEN.
#[inline]
fn two_eps_n_floor(n: u64) -> u64 {
    2 * n / GK_EPS_DEN
}

pub struct GkBuilder {
    n: u64,
    tuples: Vec<GkTuple>,
}

impl Default for GkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GkBuilder {
    pub fn new() -> Self {
        Self { n: 0, tuples: Vec::new() }
    }

    #[inline]
    pub fn observe<F: FnMut(Mark)>(&mut self, v: u32, mark: &mut F) {
        if self.n % GK_COMPRESS_EVERY == 0 {
            mark(Mark::CompressBegin);
            self.compress();
            mark(Mark::CompressEnd);
        }
        self.insert(v);
        self.n += 1;
    }

    fn insert(&mut self, v: u32) {
        // smallest i with v < v_i (so v_{i-1} <= v)
        let pos = self.tuples.partition_point(|t| t.v <= v);
        // t_0 is the minimum and t_{s-1} the maximum seen so far (COMPRESS keeps both),
        // so pos == 0 is exactly "new minimum" and pos == s exactly "new maximum".
        let new_min = pos == 0;
        let new_max = pos == self.tuples.len();
        let delta = if new_min || new_max { 0 } else { two_eps_n_floor(self.n) as u32 };
        self.tuples.insert(pos, GkTuple { v, g: 1, delta });
    }

    fn compress(&mut self) {
        let s = self.tuples.len();
        if s < 2 {
            return;
        }
        let n = self.n;
        let p = two_eps_n_floor(n);
        let t = &self.tuples;
        let bands: Vec<u32> = t.iter().map(|x| gk_band(x.delta as u64, p)).collect();
        // start[i]: first index of {t_i and its descendants} = the maximal run directly
        // left of t_i whose bands are < band(t_i). Monotone stack, O(s).
        let mut start = vec![0usize; s];
        let mut stack: Vec<usize> = Vec::with_capacity(s);
        for i in 0..s {
            while let Some(&k) = stack.last() {
                if bands[k] < bands[i] {
                    stack.pop();
                } else {
                    break;
                }
            }
            start[i] = match stack.last() {
                Some(&k) => k + 1,
                None => 0,
            };
            stack.push(i);
        }
        let mut pre = vec![0u64; s + 1];
        for i in 0..s {
            pre[i + 1] = pre[i] + t[i].g as u64;
        }
        // Right-to-left pass (i = s-2 .. 1). `out` holds the kept tuples in reverse;
        // its last element is the current t_{i+1}. Deleted blocks lie left of i.
        // t_0 (the minimum) is never a merge candidate; it is pushed after the loop.
        let mut out: Vec<GkTuple> = Vec::with_capacity(s);
        out.push(t[s - 1]);
        let mut right_band = bands[s - 1];
        let mut i = s as isize - 2;
        while i >= 1 {
            let iu = i as usize;
            let j = start[iu];
            let gstar = pre[iu + 1] - pre[j];
            let right = out.last_mut().unwrap();
            // g*_i + g_{i+1} + Delta_{i+1} < 2 eps n   <=>   D * (...) < 2 n
            if bands[iu] <= right_band
                && GK_EPS_DEN * (gstar + right.g as u64 + right.delta as u64) < 2 * n
            {
                right.g += gstar as u32;
                i = j as isize - 1;
            } else {
                out.push(t[iu]);
                right_band = bands[iu];
                i -= 1;
            }
        }
        // i == -1 would mean t_0 fell inside a deleted descendant block; impossible,
        // since t_0 (Delta = 0) has the strictly largest band whenever p >= 1, and
        // nothing merges when p = 0. Checked on every call (656 calls per epoch).
        assert!(i == 0, "GK compress: t_0 inside a deleted block");
        out.push(t[0]);
        out.reverse();
        self.tuples = out;
    }

    pub fn finish(self) -> GkEpochState {
        GkEpochState { total_count: self.n, tuples: self.tuples }
    }
}

impl GkEpochState {
    /// Certified bounds [lo, hi] on rank(x) = #{observations <= x} in this epoch:
    /// lo = rmin of the last tuple with v <= x; hi = rmax of the first tuple with
    /// v > x, minus 1 (that tuple's element is > x), or n if there is none.
    pub fn rank_bounds(&self, x: u32) -> (u64, u64) {
        let k = self.tuples.partition_point(|t| t.v <= x);
        let lo: u64 = self.tuples[..k].iter().map(|t| t.g as u64).sum();
        let hi = if k == self.tuples.len() {
            self.total_count
        } else {
            lo + self.tuples[k].g as u64 + self.tuples[k].delta as u64 - 1
        };
        (lo, hi)
    }
}

// ===========================================================================
// State commitment and Merkle root (their per-type pattern).
// ===========================================================================

/// Unsalted SHA-256 over the full epoch state, field by field, big-endian, in the
/// style of histogram_state_commit (aggregator/core/src/lib.rs:830-849).
pub fn gk_epoch_state_commit(state: &GkEpochState) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    sha.update(TAG_GK_STATE_COMMIT);
    sha.update(&state.total_count.to_be_bytes());
    for t in &state.tuples {
        sha.update(&t.v.to_be_bytes());
        sha.update(&t.g.to_be_bytes());
        sha.update(&t.delta.to_be_bytes());
    }
    sha.finalize().into()
}

/// Leaf hash per state entry, in the style of cm_heap_leaf_hash
/// (aggregator/core/src/lib.rs:1143-1151: tag, slot index, fields).
fn gk_tuple_leaf_hash(idx: u32, t: &GkTuple) -> [u8; HASH_BYTES_LEN] {
    sha256_bytes(&[
        TAG_GK_TUPLE_LEAF,
        &idx.to_be_bytes(),
        &t.v.to_be_bytes(),
        &t.g.to_be_bytes(),
        &t.delta.to_be_bytes(),
    ])
}

/// Merkle root over the tuples, following hist_per_key_root
/// (aggregator/core/src/lib.rs:786-818): zero hash when empty, pad with zero leaves
/// to a power of two, their MerkleTree (aggregator_core::merkle, SHA-256).
/// Every upstream aggregation journal carries such a root (buckets_root /
/// cm_root+heap_root); no upstream query guest reads it.
pub fn gk_tuples_root(tuples: &[GkTuple]) -> [u8; HASH_BYTES_LEN] {
    if tuples.is_empty() {
        return [0u8; HASH_BYTES_LEN];
    }
    let leaf_hashes: Vec<Digest> = tuples
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let hash = gk_tuple_leaf_hash(i as u32, t);
            Digest::try_from(&hash[..]).unwrap()
        })
        .collect();
    let num_leaves = next_pow2_ge(leaf_hashes.len());
    let mut padded_leaves = leaf_hashes;
    let zero_hash = [0u8; HASH_BYTES_LEN];
    while padded_leaves.len() < num_leaves {
        padded_leaves.push(Digest::try_from(&zero_hash[..]).unwrap());
    }
    let tree = MerkleTree::new(padded_leaves);
    tree.root().into()
}

// ===========================================================================
// Aggregation guest logic (structure of process_histogram_aggr_with_state,
// aggregator/core/src/lib.rs:851-943).
// ===========================================================================

/// Field-for-field the same as HistogramAggrInput (aggregator/core/src/lib.rs:687-697).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkAggrInput {
    pub prev_chain_hash: [u8; HASH_BYTES_LEN],
    /// Batches with events grouped (not flattened) for per-batch hash verification.
    pub batches: Vec<BatchInput>,
    /// Previous epoch's final chain tips per source_id for cross-epoch verification.
    /// Format: Vec<(source_id, last_processed_seq, chain_tip)>
    #[serde(default)]
    pub prev_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

/// Public journal (only commitments), shaped like HistogramAggrOutput
/// (aggregator/core/src/lib.rs:744-762) with `tuples_root` in place of `buckets_root`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkAggrOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub tuples_root: [u8; HASH_BYTES_LEN],
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

pub fn process_gk_aggr(input: &GkAggrInput) -> GkAggrOutput {
    let (_, out) = process_gk_aggr_with_state(input);
    out
}

pub fn process_gk_aggr_with_state(input: &GkAggrInput) -> (GkEpochState, GkAggrOutput) {
    process_gk_aggr_marked(input, &mut |_| {})
}

pub fn process_gk_aggr_marked<F: FnMut(Mark)>(
    input: &GkAggrInput,
    mark: &mut F,
) -> (GkEpochState, GkAggrOutput) {
    // Each epoch is processed independently -- NO incremental accumulation across epochs.
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
    mark(Mark::ChainVerified);

    // Flatten batches to events for processing (as upstream does)
    let mut all_events: Vec<Event> = Vec::new();
    for batch in &input.batches {
        all_events.extend(batch.events.iter().cloned());
    }
    mark(Mark::EventsFlattened);

    // The summary update: textbook GK over ev.value, one record at a time.
    let mut gk = GkBuilder::new();
    for ev in &all_events {
        gk.observe(ev.value, mark);
    }
    let state = gk.finish();
    mark(Mark::SummaryBuilt);

    let tuples_root = gk_tuples_root(&state.tuples);
    mark(Mark::RootDone);

    let state_commit = gk_epoch_state_commit(&state);
    mark(Mark::CommitDone);

    // Build epoch chain link: final_chain_hash = hash(TAG || prev || state_commit)
    let epoch_chain_link = EpochChainLink::new(input.prev_chain_hash, state_commit);
    mark(Mark::LinkDone);

    let out = GkAggrOutput {
        epoch_chain_link,
        state_commit,
        tuples_root,
        n_events: all_events.len() as u64,
        final_source_chain_tips,
    };
    (state, out)
}

// ===========================================================================
// Query-time merge: one-shot union of the per-epoch GK summaries.
//
// Rank: each epoch gives certified bounds [lo_e, hi_e] on its rank(x) with
//   hi_e - lo_e = g + Delta - 1 <= floor(2 eps n_e); the union's bounds are the sums,
//   so the estimate (L + U) / 2 is within (U - L) / 2 <= eps N of the truth.
// Quantile: the union summary is GK's COMBINE generalised to k summaries, under ONE
//   total order of all N elements: (value, epoch index, position within the epoch).
//   For a stored tuple t = (v, e, i) and every other epoch e':
//     e' < e: its elements with value <= v precede t's element:
//             lower bound rmin_{e'}(last tuple with v' <= v),
//             upper bound rmax_{e'}(first tuple with v' > v) - 1  (n_{e'} if none);
//     e' > e: its elements with value <  v precede t's element:
//             lower bound rmin_{e'}(last tuple with v' <  v),
//             upper bound rmax_{e'}(first tuple with v' >= v) - 1 (n_{e'} if none).
//   rmin_U(t) = rmin_e(i) + sum of the lower bounds, rmax_U(t) = rmax_e(i) + sum of the
//   upper bounds; t's element sits at a union position in [rmin_U, rmax_U]. In the
//   sweep over all tuples sorted by (v, e, i), "the e'-tuples before t" are exactly
//   the e'-tuples already swept, so one pointer per epoch suffices.
//   A single total order matters. Bounding each other epoch's contribution under ANY
//   tie order (last v' < v, first v' > v) is also sound, but near a value stored in
//   many epochs the per-epoch spans then add up over all copies and the certificate
//   can exceed eps N (review finding; e.g. AOL n = 16 reached 5,828 > 5,140).
//   With the total order, consecutive union tuples are at most
//   sum_e floor(2 eps n_e) + 1 <= 2 eps N + 1 apart in (rmax - rmin), the first has
//   rmax_U = 1 and the last rmin_U = N (each epoch keeps its min and max), so by
//   GK's Proposition 1 the tuple minimising max(r - rmin_U, rmax_U - r) has
//   certified error <= eps N + 1/2 (the 1/2 is the paper's INSERT slack, see the
//   README). No recompression (Agarwal et al., one-shot merge).
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CombinedTuple {
    pub v: u32,
    pub rmin: u64,
    pub rmax: u64,
}

pub struct GkUnion<'a> {
    pub epochs: &'a [GkEpochState],
    pub total_count: u64,
}

impl<'a> GkUnion<'a> {
    pub fn merge(epochs: &'a [GkEpochState]) -> Self {
        let total_count = epochs.iter().map(|s| s.total_count).sum();
        Self { epochs, total_count }
    }

    pub fn rank_bounds(&self, x: u32) -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for s in self.epochs {
            let (l, h) = s.rank_bounds(x);
            lo += l;
            hi += h;
        }
        (lo, hi)
    }

    /// The union summary, sorted by the total order (value, epoch, position).
    pub fn combined_tuples(&self) -> Vec<CombinedTuple> {
        let k = self.epochs.len();
        assert!(k < (1 << 12), "too many epochs for the packed sort key");
        // Per-epoch prefix rmin: pref[e][i] = sum_{j<=i} g_j.
        let pref: Vec<Vec<u64>> = self
            .epochs
            .iter()
            .map(|s| {
                assert!(s.tuples.len() < (1 << 20), "too many tuples for the packed sort key");
                let mut acc = 0u64;
                s.tuples
                    .iter()
                    .map(|t| {
                        acc += t.g as u64;
                        acc
                    })
                    .collect()
            })
            .collect();
        // With q epoch-e tuples before the sweep point:
        //   lo_at(e, q) = rmin of the last of them (0 if q = 0)       -- lower bound
        //   hi_at(e, q) = rmax of the next one - 1 (n_e if q = s_e)   -- upper bound
        // on the number of epoch-e elements before the sweep point.
        let lo_at = |e: usize, q: usize| -> u64 { if q == 0 { 0 } else { pref[e][q - 1] } };
        let hi_at = |e: usize, q: usize| -> u64 {
            let s = &self.epochs[e];
            if q < s.tuples.len() {
                pref[e][q] + s.tuples[q].delta as u64 - 1
            } else {
                s.total_count
            }
        };
        let total: usize = self.epochs.iter().map(|s| s.tuples.len()).sum();
        let mut keys: Vec<u64> = Vec::with_capacity(total);
        for (e, s) in self.epochs.iter().enumerate() {
            for (i, t) in s.tuples.iter().enumerate() {
                keys.push(((t.v as u64) << 32) | ((e as u64) << 20) | i as u64);
            }
        }
        // Sorting the packed key IS the total order (value, epoch, position in epoch).
        keys.sort_unstable();

        let mut lo_e = vec![0u64; k];
        let mut hi_e: Vec<u64> = (0..k).map(|e| hi_at(e, 0)).collect();
        let mut lsum = 0u64;
        let mut hsum: u64 = hi_e.iter().sum();
        let mut out = Vec::with_capacity(total);
        for &key in &keys {
            let v = (key >> 32) as u32;
            let e = ((key >> 20) & 0xFFF) as usize;
            let i = (key & 0xF_FFFF) as usize;
            // Epoch e's own tuples are swept in position order, so exactly i of them
            // precede this one; the other epochs' pointers stand where the total order
            // puts them. Subtract epoch e's own term and add its tuple's bounds.
            let own_rmin = pref[e][i];
            let own_rmax = own_rmin + self.epochs[e].tuples[i].delta as u64;
            out.push(CombinedTuple { v, rmin: own_rmin + (lsum - lo_e[e]), rmax: own_rmax + (hsum - hi_e[e]) });
            // advance epoch e's pointer past this tuple (q = i + 1)
            let (nl, nh) = (lo_at(e, i + 1), hi_at(e, i + 1));
            lsum = lsum - lo_e[e] + nl;
            hsum = hsum - hi_e[e] + nh;
            lo_e[e] = nl;
            hi_e[e] = nh;
        }
        out
    }

    /// phi = phi_num / phi_den; target rank r = ceil(phi N) clamped to [1, N].
    /// Returns (r, value, rmin_U, rmax_U) of the tuple with the least certified error.
    pub fn quantile(&self, phi_num: u32, phi_den: u32) -> (u64, u32, u64, u64) {
        let n = self.total_count;
        if n == 0 {
            return (0, 0, 0, 0);
        }
        let r = ((phi_num as u128 * n as u128).div_ceil(phi_den as u128) as u64).clamp(1, n);
        let mut best: Option<(u64, CombinedTuple)> = None;
        for c in self.combined_tuples() {
            let err = r.saturating_sub(c.rmin).max(c.rmax.saturating_sub(r));
            if best.map_or(true, |(b, _)| err < b) {
                best = Some((err, c));
            }
        }
        let (_, c) = best.unwrap();
        (r, c.v, c.rmin, c.rmax)
    }
}

// ===========================================================================
// Query guest logic (structure of run_histogram_query, querier/core/src/lib.rs:482-643).
// ===========================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GkQuery {
    /// rank(value) = #{observations <= value} over all queried epochs.
    Rank { value: u32 },
    /// phi-quantile, phi = phi_num / phi_den (p50 = 1/2, p90 = 9/10, p99 = 99/100).
    Quantile { phi_num: u32, phi_den: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkQueryInput {
    pub query: GkQuery,
    /// Typed epoch states from the aggregator, verified against chain links.
    pub epoch_states: Vec<GkEpochState>,
    /// Epoch chain links (prev_chain_hash, state_commit, final_chain_hash).
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GkQueryResult {
    /// estimate = floor((lo + hi) / 2); certified |estimate - rank| <= ceil((hi - lo) / 2).
    Rank { value: u32, estimate: u64, lo: u64, hi: u64, total_count: u64 },
    /// value is a stored observation whose union position lies in [rmin, rmax];
    /// certified error = max(target_rank - rmin, rmax - target_rank).
    Quantile {
        phi_num: u32,
        phi_den: u32,
        target_rank: u64,
        value: u32,
        rmin: u64,
        rmax: u64,
        total_count: u64,
    },
}

impl GkQueryResult {
    /// The certified rank error bound the result itself carries.
    pub fn cert_err(&self) -> u64 {
        match *self {
            GkQueryResult::Rank { estimate, lo, hi, .. } => (estimate - lo).max(hi - estimate),
            GkQueryResult::Quantile { target_rank, rmin, rmax, .. } => {
                target_rank.saturating_sub(rmin).max(rmax.saturating_sub(target_rank))
            }
        }
    }
}

/// Shaped like HistogramQueryOutput (querier/core/src/lib.rs:424-442).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkQueryOutput {
    pub chain_prev_hash: [u8; 32],
    pub chain_final_hash: [u8; 32],
    pub state_commits: Vec<[u8; 32]>,
    pub result: GkQueryResult,
    /// Number of contributing observations (the union's N).
    pub support: u64,
    pub suppressed: bool,
}

impl GkQueryOutput {
    /// Their LOW-SUPPORT rule (querier/core/src/lib.rs:21-34, 444-480): below
    /// MIN_SUPPORT, zero every numeric result field and set `suppressed`.
    pub fn suppress_if_low_support(mut self) -> Self {
        if self.support < MIN_SUPPORT {
            self.result = match self.result {
                GkQueryResult::Rank { value, .. } => GkQueryResult::Rank {
                    value,
                    estimate: 0,
                    lo: 0,
                    hi: 0,
                    total_count: 0,
                },
                GkQueryResult::Quantile { phi_num, phi_den, .. } => GkQueryResult::Quantile {
                    phi_num,
                    phi_den,
                    target_rank: 0,
                    value: 0,
                    rmin: 0,
                    rmax: 0,
                    total_count: 0,
                },
            };
            self.support = 0;
            self.suppressed = true;
        }
        self
    }
}

pub fn run_gk_query(input: &GkQueryInput) -> GkQueryOutput {
    let epochs = input.epoch_states.len();

    // Verify epoch hash chain inside the proof (cryptographically proven)
    if !input.epoch_chain_links.is_empty() {
        verify_epoch_chain_integrity(&input.epoch_chain_links);
        assert!(
            input.epoch_chain_links.len() == epochs,
            "epoch_chain_links length != epoch_states length"
        );

        // Verify each epoch state hashes to the state_commit in the chain link
        for (i, (state, link)) in input.epoch_states.iter().zip(input.epoch_chain_links.iter()).enumerate() {
            let computed_commit = gk_epoch_state_commit(state);
            assert!(
                computed_commit == link.state_commit,
                "epoch {} state_commit mismatch: computed != chain_link",
                i
            );
        }
    }

    // Extract chain boundaries for output
    let (chain_prev_hash, chain_final_hash) = if input.epoch_chain_links.is_empty() {
        ([0u8; 32], [0u8; 32])
    } else {
        (
            input.epoch_chain_links[0].prev_chain_hash,
            input.epoch_chain_links.last().unwrap().final_chain_hash,
        )
    };

    // Collect state_commits for output
    let state_commits: Vec<[u8; 32]> = input.epoch_chain_links.iter()
        .map(|link| link.state_commit)
        .collect();

    // Merge the verified per-epoch summaries, then query the merged summary.
    let merged = GkUnion::merge(&input.epoch_states);
    let total_count = merged.total_count;
    let result = match input.query {
        GkQuery::Rank { value } => {
            let (lo, hi) = merged.rank_bounds(value);
            GkQueryResult::Rank { value, estimate: (lo + hi) / 2, lo, hi, total_count }
        }
        GkQuery::Quantile { phi_num, phi_den } => {
            assert!(phi_den > 0 && phi_num <= phi_den, "phi must be in [0, 1]");
            let (target_rank, value, rmin, rmax) = merged.quantile(phi_num, phi_den);
            GkQueryResult::Quantile { phi_num, phi_den, target_rank, value, rmin, rmax, total_count }
        }
    };

    GkQueryOutput {
        chain_prev_hash,
        chain_final_hash,
        state_commits,
        result,
        support: total_count,
        suppressed: false,
    }
}

// ===========================================================================
// Tests (native).
//
// The AOL checks read data/aol.keys (gitignored; scripts/fetch_datasets.py). Override
// the path with GK_AOL_KEYS; GK_SKIP_AOL=1 skips them (the test then prints SKIPPED).
// ===========================================================================
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;
    use std::vec::Vec;

    fn lcg(seed: &mut u64) -> u32 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) as u32
    }

    fn build(vals: &[u32]) -> GkEpochState {
        let mut b = GkBuilder::new();
        for &v in vals {
            b.observe(v, &mut |_| {});
        }
        b.finish()
    }

    fn eps_n(n: u64) -> f64 {
        n as f64 / GK_EPS_DEN as f64
    }

    /// AOL values (key & 0x1FFFFF), or None when GK_SKIP_AOL=1.
    fn aol_values() -> Option<Vec<u32>> {
        if std::env::var("GK_SKIP_AOL").map_or(false, |v| v == "1") {
            std::eprintln!("SKIPPED: AOL checks (GK_SKIP_AOL=1)");
            return None;
        }
        let path = std::env::var("GK_AOL_KEYS").unwrap_or_else(|_| {
            std::format!("{}/../../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR"))
        });
        let b = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("cannot read {path}: {e} (set GK_AOL_KEYS, or GK_SKIP_AOL=1 to skip the AOL checks)")
        });
        Some(b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) & 0x1F_FFFF).collect())
    }
    const AOL_EPOCH: usize = 16_384;

    /// Named phis of the per-epoch check (the host's aggr rows use the same list).
    const NAMED_PHIS: [(u32, u32); 6] = [(0, 1), (1, 1000), (1, 100), (1, 2), (99, 100), (1, 1)];

    /// Distance from target rank r to the true position range [lt+1, le] of value v.
    fn true_err(sorted: &[u32], r: u64, v: u32) -> (u64, u64, u64) {
        let lt = sorted.partition_point(|&w| w < v) as u64;
        let le = sorted.partition_point(|&w| w <= v) as u64;
        assert!(le > lt, "returned value {v} is not an observation");
        let err = if r < lt + 1 { lt + 1 - r } else if r > le { r - le } else { 0 };
        (err, lt, le)
    }

    /// Quantile checks at the given phis: the true position range of the answer meets
    /// [rmin, rmax] (soundness), err <= cert, and cert <= eps N. Returns (worst err,
    /// worst cert).
    fn check_quantiles(name: &str, states: &[GkEpochState], sorted: &[u32], phis: &[(u32, u32)]) -> (u64, u64) {
        let u = GkUnion::merge(states);
        let n = sorted.len() as u64;
        assert_eq!(u.total_count, n);
        let epsn = eps_n(n);
        let (mut we, mut wc) = (0u64, 0u64);
        for &(pn, pd) in phis {
            let (r, v, rmin, rmax) = u.quantile(pn, pd);
            let (err, lt, le) = true_err(sorted, r, v);
            let cert = r.saturating_sub(rmin).max(rmax.saturating_sub(r));
            assert!(lt < rmax && rmin <= le, "{name} phi={pn}/{pd}: [{rmin},{rmax}] misses [{},{le}]", lt + 1);
            assert!(err <= cert, "{name} phi={pn}/{pd}: err {err} > cert {cert}");
            assert!(err as f64 <= epsn, "{name} phi={pn}/{pd}: err {err} > eps N {epsn:.2}");
            assert!(cert as f64 <= epsn, "{name} phi={pn}/{pd}: cert {cert} > eps N {epsn:.2}");
            we = we.max(err);
            wc = wc.max(cert);
        }
        (we, wc)
    }

    fn sweep_phis() -> Vec<(u32, u32)> {
        (0..=1000u32).map(|q| (q, 1000)).collect()
    }

    /// Union rank checks over (a sample of) the distinct values, plus 0 and u32::MAX.
    fn check_ranks(name: &str, states: &[GkEpochState], sorted: &[u32]) -> u64 {
        let u = GkUnion::merge(states);
        let epsn = eps_n(sorted.len() as u64);
        let mut xs = sorted.to_vec();
        xs.dedup();
        let step = (xs.len() / 4000).max(1);
        let mut xs: Vec<u32> = xs.into_iter().step_by(step).collect();
        xs.push(0);
        xs.push(u32::MAX);
        let mut worst = 0u64;
        for &x in &xs {
            let (lo, hi) = u.rank_bounds(x);
            let exact = sorted.partition_point(|&v| v <= x) as u64;
            assert!(lo <= exact && exact <= hi, "{name} x={x}: {exact} not in [{lo},{hi}]");
            let est = (lo + hi) / 2;
            let err = est.abs_diff(exact);
            // midpoint half-width: provably <= eps N + 1/2 (odd sum of floors)
            assert!((est - lo).max(hi - est) as f64 <= epsn + 0.5, "{name} x={x}: rank cert");
            assert!(err as f64 <= epsn, "{name} x={x}: rank err {err} > {epsn:.2}");
            worst = worst.max(err);
        }
        worst
    }

    fn check_state(st: &GkEpochState, vals: &[u32]) {
        let n = vals.len() as u64;
        assert_eq!(st.total_count, n);
        assert_eq!(st.tuples.iter().map(|t| t.g as u64).sum::<u64>(), n);
        assert!(st.tuples.windows(2).all(|w| w[0].v <= w[1].v));
        let mut sorted = vals.to_vec();
        sorted.sort_unstable();
        // the minimum and the maximum are kept (paper section 2.1)
        assert_eq!(st.tuples[0], GkTuple { v: sorted[0], g: 1, delta: 0 }, "t_0 is not (min, 1, 0)");
        let last = st.tuples.last().unwrap();
        assert_eq!((last.v, last.delta), (*sorted.last().unwrap(), 0), "t_(s-1) is not (max, _, 0)");
        // every stored value is an observation
        for t in &st.tuples {
            assert!(sorted.binary_search(&t.v).is_ok());
        }
        let p = two_eps_n_floor(n);
        for (i, t) in st.tuples.iter().enumerate() {
            assert!(t.delta as u64 <= p, "tuple {i}: delta {} > p {p}", t.delta);
            // rank-interval width g + delta - 1 <= floor(2 eps n)
            assert!((t.g + t.delta) as u64 - 1 <= p, "tuple {i}: g+delta-1 > floor(2eps n)");
        }
        let mut xs: Vec<u32> = sorted.clone();
        xs.dedup();
        xs.push(0);
        xs.push(u32::MAX);
        for &x in &xs {
            let (lo, hi) = st.rank_bounds(x);
            let exact = sorted.partition_point(|&v| v <= x) as u64;
            assert!(lo <= exact && exact <= hi, "x={x}: {exact} not in [{lo},{hi}]");
            assert!(hi - lo <= p);
            let est = (lo + hi) / 2;
            assert!((est as f64 - exact as f64).abs() <= eps_n(n));
        }
        check_quantiles("single", core::slice::from_ref(st), &sorted, &NAMED_PHIS);
    }

    // ------------------------------------------------------------------ bands

    // Band straight from the paper's set definition (p = floor(2 eps n)).
    fn band_ref(delta: u64, p: u64) -> u32 {
        if delta == p {
            return 0;
        }
        let (pi, d) = (p as i128, delta as i128);
        let mut a = 1u32;
        loop {
            let (hi, lo) = (1i128 << a, 1i128 << (a - 1));
            if pi - hi - (pi % hi) < d && d <= pi - lo - (pi % lo) {
                return a;
            }
            a += 1;
            assert!(a < 64);
        }
    }

    #[test]
    fn band_matches_paper_definition() {
        for p in 0u64..700 {
            let mut prev = u32::MAX;
            for delta in 0..=p {
                let a = gk_band(delta, p);
                if delta == p {
                    assert_eq!(a, 0);
                } else {
                    let (lo_m, hi_m) = (1u64 << (a - 1), 1u64 << a);
                    let d = delta as i128;
                    let pi = p as i128;
                    assert!(pi - hi_m as i128 - ((p % hi_m) as i128) < d, "p={p} delta={delta} a={a}");
                    assert!(d <= pi - lo_m as i128 - (p % lo_m) as i128, "p={p} delta={delta} a={a}");
                }
                // bands are non-increasing in delta
                assert!(a <= prev);
                prev = a;
            }
        }
        for p in (700u64..5000).chain([65_535, 65_536, 65_537, 1 << 20]) {
            let step = if p > 5000 { 997 } else { 1 };
            let mut d = 0;
            while d <= p {
                assert_eq!(gk_band(d, p), band_ref(d, p), "p={p} d={d}");
                d += step;
            }
        }
    }

    /// The paper's band special case ("the first 1/2eps observations, with Delta = 0,
    /// in a band of their own") holds without special code: for p >= 1, Delta = 0 is
    /// the only member of the top band floor(log2 p) + 1; for p = 0 nothing can merge.
    #[test]
    fn band_delta0_is_alone_in_top_band() {
        for p in (1u64..5000).chain([65_535, 65_536, 65_537, 1 << 20, (1 << 20) + 12_345]) {
            let top = gk_band(0, p);
            assert_eq!(top, 64 - p.leading_zeros(), "p={p}");
            let step = if p > 5000 { 97 } else { 1 };
            let mut d = 1;
            while d <= p {
                assert!(gk_band(d, p) < top, "p={p} d={d}");
                d += step;
            }
        }
        for n in 0..=4 * GK_COMPRESS_EVERY {
            if two_eps_n_floor(n) == 0 {
                // smallest possible g*_i + g_{i+1} + Delta_{i+1} is 2
                assert!(GK_EPS_DEN * 2 >= 2 * n, "n={n}: a merge would be possible at p = 0");
            }
        }
    }

    // --------------------------------------------------------- single epoch

    fn streams() -> Vec<(String, Vec<u32>)> {
        let mut out: Vec<(String, Vec<u32>)> = Vec::new();
        let mut seed = 99u64;
        out.push(("uniform".into(), (0..30_000).map(|_| lcg(&mut seed) & 0x1F_FFFF).collect()));
        out.push(("dup5".into(), (0..30_000).map(|_| lcg(&mut seed) % 5).collect()));
        out.push(("const".into(), (0..5_000).map(|_| 7).collect()));
        let mut asc: Vec<u32> = (0..20_000).map(|_| lcg(&mut seed) & 0xFFFF).collect();
        asc.sort_unstable();
        out.push(("asc".into(), asc.clone()));
        asc.reverse();
        out.push(("desc".into(), asc));
        out.push(("zigzag".into(), (0..20_000u32).map(|i| if i % 2 == 0 { i } else { 1_000_000 - i }).collect()));
        out.push(("skew97sq".into(), (0..20_000).map(|_| (lcg(&mut seed) % 97).pow(2)).collect()));
        out
    }

    #[test]
    fn gk_single_epoch_uniform_and_skewed() {
        let mut seed = 7u64;
        let uni: Vec<u32> = (0..20_000).map(|_| lcg(&mut seed) & 0x1F_FFFF).collect();
        let st = build(&uni);
        check_state(&st, &uni);
        assert!(st.tuples.len() < 2000, "summary did not compress: {}", st.tuples.len());
        // skewed with many duplicates, sorted and reverse-sorted inputs
        let skew: Vec<u32> = (0..20_000).map(|_| (lcg(&mut seed) % 97).pow(2)).collect();
        check_state(&build(&skew), &skew);
        let mut asc = uni.clone();
        asc.sort_unstable();
        check_state(&build(&asc), &asc);
        asc.reverse();
        check_state(&build(&asc), &asc);
        // every prefix length keeps the invariants
        for len in [1usize, 2, 25, 26, 51, 52, 53, 100, 777] {
            check_state(&build(&uni[..len]), &uni[..len]);
        }
    }

    /// t_0 = (running minimum, 1, 0) and t_(s-1).v = running maximum after EVERY
    /// observation (hence after every COMPRESS), on synthetic streams and on all 64
    /// AOL epochs. Before the keep-minimum fix, 60 of the 64 AOL epochs lost t_0.
    #[test]
    fn min_and_max_kept_after_every_compress() {
        let mut all = streams();
        if let Some(k) = aol_values() {
            for e in 0..64 {
                all.push((std::format!("aol{e}"), k[e * AOL_EPOCH..(e + 1) * AOL_EPOCH].to_vec()));
            }
        }
        let mut compress_calls = 0u64;
        for (name, s) in &all {
            let mut b = GkBuilder::new();
            let (mut mn, mut mx) = (u32::MAX, 0u32);
            for (k, &v) in s.iter().enumerate() {
                if b.n % GK_COMPRESS_EVERY == 0 {
                    compress_calls += 1;
                }
                b.observe(v, &mut |_| {});
                mn = mn.min(v);
                mx = mx.max(v);
                assert_eq!(b.tuples[0], GkTuple { v: mn, g: 1, delta: 0 }, "{name}: t_0 lost the minimum at k={k}");
                assert_eq!(b.tuples.last().unwrap().v, mx, "{name}: lost the maximum at k={k}");
            }
        }
        std::println!("min/max kept on {} streams, {compress_calls} COMPRESS calls", all.len());
    }

    // Literal paper pseudocode (Figure 2 / Figure 3) with the stated keep-minimum
    // invariant: list deletions, explicit descendant walk, band from the set definition.
    struct RefGk {
        n: u64,
        t: Vec<GkTuple>,
    }
    impl RefGk {
        fn observe(&mut self, v: u32) {
            if self.n % GK_COMPRESS_EVERY == 0 {
                self.compress();
            }
            let pos = self.t.iter().position(|x| v < x.v).unwrap_or(self.t.len());
            let extreme = pos == 0 || pos == self.t.len();
            let d = if extreme { 0 } else { (2 * self.n / GK_EPS_DEN) as u32 };
            self.t.insert(pos, GkTuple { v, g: 1, delta: d });
            self.n += 1;
        }
        fn compress(&mut self) {
            if self.t.len() < 2 {
                return;
            }
            let p = 2 * self.n / GK_EPS_DEN;
            let mut i = self.t.len() as isize - 2;
            while i >= 1 {
                let iu = i as usize;
                let bi = band_ref(self.t[iu].delta as u64, p);
                let bn = band_ref(self.t[iu + 1].delta as u64, p);
                let mut j = iu; // descendants: maximal run left of i with band < bi
                while j > 0 && band_ref(self.t[j - 1].delta as u64, p) < bi {
                    j -= 1;
                }
                assert!(j >= 1, "reference: t_0 inside a descendant block");
                let gstar: u64 = self.t[j..=iu].iter().map(|x| x.g as u64).sum();
                let nx = self.t[iu + 1];
                if bi <= bn && (GK_EPS_DEN as u128) * ((gstar + nx.g as u64 + nx.delta as u64) as u128) < 2 * self.n as u128 {
                    self.t[iu + 1].g += gstar as u32;
                    self.t.drain(j..=iu);
                    i = j as isize - 1;
                } else {
                    i -= 1;
                }
            }
        }
    }

    #[test]
    fn fast_compress_equals_paper_reference() {
        let mut all = streams();
        if let Some(k) = aol_values() {
            for e in [0usize, 2, 63] {
                all.push((std::format!("aol{e}"), k[e * AOL_EPOCH..(e + 1) * AOL_EPOCH].to_vec()));
            }
        }
        for (name, s) in &all {
            let mut a = GkBuilder::new();
            let mut r = RefGk { n: 0, t: Vec::new() };
            for (k, &v) in s.iter().enumerate() {
                a.observe(v, &mut |_| {});
                r.observe(v);
                if k % 97 == 0 || k + 1 == s.len() {
                    assert_eq!(a.tuples, r.t, "{name}: diverged at k={k}");
                }
            }
            std::println!("{name}: n={} tuples={} (fast == reference)", s.len(), a.tuples.len());
        }
    }

    /// Per-epoch invariants, rank containment and the named-phi quantile check at
    /// sampled steps of every stream.
    #[test]
    fn invariants_during_stream() {
        let mut all = streams();
        if let Some(k) = aol_values() {
            all.push(("aol0".into(), k[..AOL_EPOCH].to_vec()));
        }
        for (name, s) in &all {
            let mut b = GkBuilder::new();
            for (k, &v) in s.iter().enumerate() {
                b.observe(v, &mut |_| {});
                if k % 1009 == 0 || k + 1 == s.len() {
                    let st = GkEpochState { total_count: b.n, tuples: b.tuples.clone() };
                    check_state(&st, &s[..=k]);
                }
            }
            std::println!("{name}: invariants hold at every 1009th step");
        }
    }

    /// Random single streams at low and high phi (the case the lost minimum broke:
    /// before the fix phi = 0 reached 1.96 x eps n on such streams).
    #[test]
    fn single_epoch_all_phis_random_streams() {
        let mut seed = 3u64;
        let (mut worst_err, mut worst_cert) = (0f64, 0f64);
        for trial in 0..300 {
            let n = 2000 + (lcg(&mut seed) % 20_000) as usize;
            let v: Vec<u32> = match trial % 3 {
                0 => (0..n).map(|_| lcg(&mut seed) & 0xFFFFF).collect(),
                1 => (0..n).map(|i| (i as u32 * 7919) % 100_003).collect(),
                _ => {
                    let mut x: Vec<u32> = (0..n).map(|_| lcg(&mut seed) & 0xFFFFF).collect();
                    x.sort_unstable();
                    x.reverse();
                    x
                }
            };
            let st = build(&v);
            let mut s = v.clone();
            s.sort_unstable();
            let (e, c) = check_quantiles("random", core::slice::from_ref(&st), &s, &NAMED_PHIS);
            worst_err = worst_err.max(e as f64 / eps_n(n as u64));
            worst_cert = worst_cert.max(c as f64 / eps_n(n as u64));
        }
        std::println!("300 random streams, named phis: worst err {worst_err:.3} x eps n, worst cert {worst_cert:.3} x eps n");
    }

    // ------------------------------------------------------------------ union

    /// Per-tuple reference of the total-order COMBINE (binary search per other epoch).
    fn combine_bruteforce(st: &[GkEpochState]) -> Vec<CombinedTuple> {
        let rmin_upto = |s: &GkEpochState, q: usize| -> u64 { s.tuples[..q].iter().map(|t| t.g as u64).sum() };
        let hi_from = |s: &GkEpochState, q: usize| -> u64 {
            if q == s.tuples.len() { s.total_count } else { rmin_upto(s, q + 1) + s.tuples[q].delta as u64 - 1 }
        };
        let mut keyed: Vec<((u32, usize, usize), CombinedTuple)> = Vec::new();
        for (e, s) in st.iter().enumerate() {
            for (i, t) in s.tuples.iter().enumerate() {
                let own = rmin_upto(s, i + 1);
                let (mut lo, mut hi) = (own, own + t.delta as u64);
                for (e2, s2) in st.iter().enumerate() {
                    if e2 == e {
                        continue;
                    }
                    let q = if e2 < e {
                        s2.tuples.partition_point(|x| x.v <= t.v)
                    } else {
                        s2.tuples.partition_point(|x| x.v < t.v)
                    };
                    lo += rmin_upto(s2, q);
                    hi += hi_from(s2, q);
                }
                keyed.push(((t.v, e, i), CombinedTuple { v: t.v, rmin: lo, rmax: hi }));
            }
        }
        keyed.sort_by_key(|(k, _)| *k);
        keyed.into_iter().map(|(_, c)| c).collect()
    }

    fn adversarial_unions() -> Vec<(String, Vec<Vec<u32>>)> {
        let mut seed = 5u64;
        let mut out: Vec<(String, Vec<Vec<u32>>)> = Vec::new();
        out.push(("disjoint16".into(), (0..16).map(|e| (0..4096).map(|_| e * 100_000 + (lcg(&mut seed) % 100_000)).collect()).collect()));
        out.push(("const16".into(), (0..16).map(|_| std::vec![42u32; 4096]).collect()));
        out.push(("ties3x16".into(), (0..16).map(|_| (0..4096).map(|_| lcg(&mut seed) % 3).collect()).collect()));
        out.push((
            "sorted_reverse_mix9".into(),
            (0..9)
                .map(|e| {
                    let mut v: Vec<u32> = (0..(500 + 700 * e)).map(|_| lcg(&mut seed) & 0xFFFFF).collect();
                    v.sort_unstable();
                    if e % 2 == 1 {
                        v.reverse();
                    }
                    v
                })
                .collect(),
        ));
        out.push(("tiny40".into(), (0..40).map(|_| (0..(1 + lcg(&mut seed) % 30)).map(|_| lcg(&mut seed) % 50).collect()).collect()));
        out.push((
            "zipfish32".into(),
            (0..32).map(|_| (0..4096).map(|_| { let x = lcg(&mut seed) % 1000; x * x / 1000 }).collect()).collect(),
        ));
        // one heavy value stored in every epoch (the AOL failure mode: value 985491)
        out.push((
            "heavy_shared64".into(),
            (0..64)
                .map(|_| (0..4096).map(|_| if lcg(&mut seed) % 10 < 3 { 985_491 } else { lcg(&mut seed) & 0x1F_FFFF }).collect())
                .collect(),
        ));
        out.push((
            "uniform_vs_mod3000_7".into(),
            (0..7).map(|e| (0..777).map(|_| if e % 2 == 0 { lcg(&mut seed) & 0x1F_FFFF } else { (lcg(&mut seed) % 1000) * 3 }).collect()).collect(),
        ));
        out.push(("single_record_epochs".into(), (0..60).map(|e| std::vec![(e * 37 % 11) as u32]).collect()));
        out
    }

    #[test]
    fn combine_sweep_equals_bruteforce() {
        let mut cases = adversarial_unions();
        if let Some(k) = aol_values() {
            cases.push(("aol16".into(), (0..16).map(|e| k[e * AOL_EPOCH..(e + 1) * AOL_EPOCH].to_vec()).collect()));
        }
        for (name, epochs) in &cases {
            let states: Vec<GkEpochState> = epochs.iter().map(|e| build(e)).collect();
            let u = GkUnion::merge(&states);
            let fast = u.combined_tuples();
            assert_eq!(fast, combine_bruteforce(&states), "{name}");
            // rmin is non-decreasing along the total order (rmax need not be: GK's own
            // rmax = rmin + Delta is not monotone, e.g. a tuple with a large Delta
            // just before the maximum)
            assert!(fast.windows(2).all(|w| w[0].rmin <= w[1].rmin), "{name}: rmin not monotone");
            assert_eq!(fast.first().unwrap().rmax, 1, "{name}: first union tuple rmax");
            assert_eq!(fast.last().unwrap().rmin, u.total_count, "{name}: last union tuple rmin");
        }
    }

    #[test]
    fn union_rank_and_quantiles_within_eps_n() {
        let mut seed = 11u64;
        for &(k, m) in &[(1usize, 4096usize), (4, 3000), (16, 1024), (7, 777)] {
            let mut all = Vec::new();
            let mut states = Vec::new();
            for e in 0..k {
                let vals: Vec<u32> = (0..m)
                    .map(|_| if e % 2 == 0 { lcg(&mut seed) & 0x1F_FFFF } else { (lcg(&mut seed) % 1000) * 3 })
                    .collect();
                states.push(build(&vals));
                all.extend(vals);
            }
            all.sort_unstable();
            let comb = GkUnion::merge(&states).combined_tuples();
            assert_eq!(comb.len(), states.iter().map(|s| s.tuples.len()).sum::<usize>());
            check_ranks("synthetic", &states, &all);
            let (e, c) = check_quantiles("synthetic", &states, &all, &sweep_phis());
            std::println!("synthetic k={k} m={m}: 1,001 phis worst err {e}, worst cert {c}, eps N {:.2}", eps_n(all.len() as u64));
        }
    }

    /// 1,001 phis (q/1000) over AOL unions of n = 1, 4, 16, 64 epochs:
    /// err <= cert <= eps N and the exact answer inside the certified interval.
    #[test]
    fn union_phi_sweep_aol() {
        let Some(k) = aol_values() else { return };
        for n in [1usize, 4, 16, 64] {
            let states: Vec<GkEpochState> = (0..n).map(|e| build(&k[e * AOL_EPOCH..(e + 1) * AOL_EPOCH])).collect();
            let mut all = k[..n * AOL_EPOCH].to_vec();
            all.sort_unstable();
            let wr = check_ranks("aol", &states, &all);
            let (e, c) = check_quantiles(&std::format!("aol n={n}"), &states, &all, &sweep_phis());
            std::println!(
                "AOL n={n}: eps N {:.2}; rank worst err {wr}; 1,001 phis worst err {e}, worst cert {c} ({:.3} x eps N)",
                eps_n(all.len() as u64),
                c as f64 / eps_n(all.len() as u64)
            );
        }
    }

    /// 1,001 phis over adversarial splits (disjoint epochs, constant, 3-value ties,
    /// sorted/reverse mixes of different sizes, tiny epochs, skewed, one heavy value
    /// shared by every epoch, one-record epochs).
    #[test]
    fn union_phi_sweep_adversarial() {
        for (name, epochs) in adversarial_unions() {
            let states: Vec<GkEpochState> = epochs.iter().map(|e| build(e)).collect();
            let mut all: Vec<u32> = epochs.concat();
            all.sort_unstable();
            let wr = check_ranks(&name, &states, &all);
            let (e, c) = check_quantiles(&name, &states, &all, &sweep_phis());
            std::println!(
                "{name}: k={} N={} eps N {:.2}; rank worst err {wr}; 1,001 phis worst err {e}, worst cert {c}",
                epochs.len(),
                all.len(),
                eps_n(all.len() as u64)
            );
        }
    }

    #[test]
    fn commit_changes_with_state() {
        let a = build(&[5, 1, 9]);
        let mut b = a.clone();
        b.tuples[1].g += 1;
        assert_ne!(gk_epoch_state_commit(&a), gk_epoch_state_commit(&b));
        assert_ne!(gk_tuples_root(&a.tuples), gk_tuples_root(&b.tuples));
    }
}
