#![no_std]

// Misra-Gries (Misra & Gries 1982, "Frequent") as a zk-Analytics-style epoch
// summary: the zk-Analytics pipeline (Zhu et al., SIGCOMM '26; code at d4a5a9a)
// with only the summary swapped in. Same pipeline, same helpers and same
// commitment style as the SpaceSaving port in ../../spacesaving (kept as a
// separate baseline); only the per-record rule, the entry layout (key, count:
// Misra-Gries keeps no error term) and the query-time merge differ.
//
//   aggregation (one epoch, rebuilt from scratch):
//     verify the sources' SHA-256 batch hash chains      -- their code, verbatim
//     flatten the batches into events                     -- their pattern
//     textbook Misra-Gries update per record              -- ours (plain Rust)
//     canonical state (entries sorted by key_id)          -- their pattern
//     Merkle root over 64 hash buckets of entries         -- their samples pattern (samples_buckets_root)
//     unsalted SHA-256 state commitment                   -- their pattern
//     epoch chain link                                    -- their EpochChainLink
//   query (n epochs):
//     re-verify epoch chain links                         -- their code, verbatim
//     recompute each epoch's state commitment             -- their pattern
//     top-k: merge the per-epoch summaries at query time  -- ours (the mergeable Misra-Gries merge of
//                                                            Agarwal et al., PODS 2012)
//     point query: one scan over every epoch's entries    -- their SumExactKey pattern (no merge)
//     low-support suppression                             -- their rule (MIN_SUPPORT)
//
// Nothing here is oblivious: no padding, no memory checking, no sorting
// certificates, no Poseidon. The guest's cycle count therefore depends on the data.
//
// Functions marked "VERBATIM" are private in zk-Analytics and are copied
// unchanged from the named file:line of the clone at commit d4a5a9a.
//
// Security note (theirs, aggregator/core/src/lib.rs:3-5, applies here too):
// "commitments" are deterministic, unsalted hashes.

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use core::hash::{BuildHasherDefault, Hash, Hasher};
use hashbrown::HashMap;
#[cfg(target_os = "zkvm")]
use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
#[cfg(not(target_os = "zkvm"))]
use rust_crypto::{Digest as _, Sha256};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

use aggregator_core::merkle::MerkleTree;
use aggregator_core::samples_buckets_root_from_leaves;
pub use aggregator_core::{batch_chain_hash, key_to_u64, BatchInput, EpochChainLink};
pub use querier_core::MIN_SUPPORT;
pub use zkvm_common::{Event, HASH_BYTES_LEN, KEY_BYTES_LEN};

// Domain separators. Distinct prefix: these are our port's tags, not theirs.
const TAG_MG_STATE_COMMIT: &[u8] = b"ZKA_PORT_MG_STATE_COMMIT_V1";
const TAG_MG_BUCKET_LEAF: &[u8] = b"ZKA_PORT_MG_BUCKET_V1"; // cf. their TAG_BUCKET_LEAF, aggregator/core/src/lib.rs:44
const TAG_MG_LEAF: &[u8] = b"ZKA_PORT_MG_LEAF_V1"; // per-key leaves (MgRoot::PerKey sensitivity variant only)

// ============================================================ verbatim helpers

/// VERBATIM aggregator/core/src/lib.rs:82-91 (private there).
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

/// VERBATIM aggregator/core/src/lib.rs:93-99 (private there).
fn sha256_bytes(parts: &[&[u8]]) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    for p in parts {
        sha.update(p);
    }
    sha.finalize().into()
}

/// Tag for batch-level shard chain (matches data_source and kafka_producer)
/// VERBATIM aggregator/core/src/lib.rs:56-57 (private there; used only in the
/// debug message of verify_and_compute_chain below).
const TAG_SHARD_CHAIN: &[u8] = b"ZKTLM_SHARD_CHAIN_V1";

/// Compute commitment of events: SHA256(key_id || value || ts) for each event
/// Matches data_source and kafka_producer format (no TAG prefix)
/// VERBATIM aggregator/core/src/lib.rs:295-305 (private there).
fn events_commit(events: &[Event]) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    for ev in events {
        sha.update(&ev.key_id);                // 15 bytes key
        sha.update(&ev.value.to_be_bytes());   // 4 bytes value
        sha.update(&ev.ts.to_be_bytes());      // 4 bytes timestamp
    }
    sha.finalize().into()
}

/// Helper to convert HashMap chain tips to sorted Vec
/// VERBATIM aggregator/core/src/lib.rs:331-339 (private there).
fn chain_tips_to_sorted_vec(tips: HashMap<u32, (u64, [u8; HASH_BYTES_LEN])>) -> Vec<(u32, u64, [u8; HASH_BYTES_LEN])> {
    let mut vec: Vec<(u32, u64, [u8; HASH_BYTES_LEN])> = tips
        .into_iter()
        .map(|(source_id, (seq, tip))| (source_id, seq, tip))
        .collect();
    vec.sort_by_key(|(source_id, _, _)| *source_id);
    vec
}

/// Verify and compute batch-level per-source chain integrity inside ZK proof.
/// VERBATIM aggregator/core/src/lib.rs:499-603 (private there; doc comment trimmed).
///
/// Returns: HashMap of source_id -> (last_processed_seq, final_chain_tip) after verification
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

/// VERBATIM querier/core/src/lib.rs:41 (private there).
const TAG_EPOCH_CHAIN: &[u8] = b"ZKTLM_EPOCH_CHAIN_V1";

/// Verify epoch hash chain integrity inside ZK proof.
/// VERBATIM querier/core/src/lib.rs:98-136 (private there). It hashes with the
/// sha256_bytes above, which is byte-identical to querier/core/src/lib.rs:43-49.
///
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

// ============================================================ Misra-Gries

/// Hash-map key: the full 15-byte key id. It is hashed the way zk-Analytics' CM
/// hashes keys: FNV-1a over all 15 bytes (their pub key_to_u64,
/// aggregator/core/src/lib.rs:341-350), then the splitmix64 finaliser of their
/// cm_bucket_index (aggregator/core/src/lib.rs:1058-1062, without the row seed).
/// The key itself is stored and compared in full, so a 64-bit collision only
/// costs a probe; it can never merge two keys.
#[derive(Clone, Copy, PartialEq, Eq)]
struct MapKey([u8; KEY_BYTES_LEN]);

impl Hash for MapKey {
    fn hash<H: Hasher>(&self, h: &mut H) {
        h.write_u64(key_to_u64(&self.0));
    }
}

#[derive(Default)]
struct FnvSplitmix(u64);

impl Hasher for FnvSplitmix {
    // MapKey only calls write_u64; FNV-1a continuation for completeness.
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
    fn write_u64(&mut self, x: u64) {
        self.0 ^= x;
    }
    fn finish(&self) -> u64 {
        let mut x = self.0;
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94d049bb133111eb);
        x ^= x >> 31;
        x
    }
}

type KeyIndex = HashMap<MapKey, u32, BuildHasherDefault<FnvSplitmix>>;

/// Textbook Misra-Gries with `capacity` counters, one unit update per record:
/// a monitored key's counter is incremented; an unmonitored key takes a free
/// counter with count 1; otherwise every counter is decremented by 1, the
/// counters that reach 0 are released, and the record is dropped. Each decrement
/// step removes `capacity + 1` units of mass (one from every counter and the
/// record itself), so a stream of N records has at most N / (capacity + 1) such
/// steps and their O(capacity) cost amortizes to O(1) per record. Counters live
/// in two parallel arrays; the index maps a key to its slot. For every key,
/// count <= f <= count + d, with d = (N - sum of counts) / (capacity + 1) the
/// number of decrement steps (count = 0 for an unmonitored key).
pub struct MisraGries {
    capacity: usize,
    keys: Vec<[u8; KEY_BYTES_LEN]>,
    counts: Vec<u32>,
    index: KeyIndex,
    total: u64,
}

impl MisraGries {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1 && capacity < u32::MAX as usize, "Misra-Gries capacity must be in 1..2^32-1");
        let mut index = KeyIndex::default();
        index.reserve(capacity);
        Self {
            capacity,
            keys: Vec::with_capacity(capacity),
            counts: Vec::with_capacity(capacity),
            index,
            total: 0,
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    /// One unit-weight Misra-Gries update.
    pub fn update(&mut self, key: &[u8; KEY_BYTES_LEN]) {
        self.total += 1;
        if let Some(&c) = self.index.get(&MapKey(*key)) {
            self.counts[c as usize] += 1;
            return;
        }
        if self.keys.len() < self.capacity {
            self.index.insert(MapKey(*key), self.keys.len() as u32);
            self.keys.push(*key);
            self.counts.push(1);
            return;
        }
        // Decrement every counter and compact the survivors in place.
        let mut w = 0usize;
        for r in 0..self.keys.len() {
            let c = self.counts[r] - 1;
            if c == 0 {
                self.index.remove(&MapKey(self.keys[r]));
                continue;
            }
            if w != r {
                self.keys[w] = self.keys[r];
                *self.index.get_mut(&MapKey(self.keys[w])).expect("monitored key is indexed") = w as u32;
            }
            self.counts[w] = c;
            w += 1;
        }
        self.keys.truncate(w);
        self.counts.truncate(w);
    }

    /// The monitored (key, count) entries in canonical order (sorted by key_id,
    /// as their SamplesEpochState::from sorts per_key, aggregator/core/src/lib.rs:189-199).
    pub fn entries_sorted(&self) -> Vec<MgEntry> {
        let mut entries: Vec<MgEntry> = self
            .keys
            .iter()
            .zip(self.counts.iter())
            .map(|(k, &c)| MgEntry { key_id: *k, count: c })
            .collect();
        entries.sort_by_key(|e| e.key_id);
        entries
    }
}

// ============================================================ epoch state

/// One monitored counter. Per-epoch counts fit u32 (their convention for per-epoch
/// counts, e.g. BucketEntry.count / KeyHistogram.count); the query widens to u64.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MgEntry {
    pub key_id: [u8; KEY_BYTES_LEN],
    pub count: u32,
}

/// Serializable epoch state: what the provider stores and the query guest re-hashes.
/// `entries` holds the <= capacity monitored counters, sorted by key_id.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MgEpochState {
    pub capacity: u32,
    pub total_count: u64,
    pub entries: Vec<MgEntry>,
}

/// Unsalted SHA-256 state commitment, in the style of their
/// samples_epoch_state_commit / cm_epoch_state_commit (aggregator/core/src/lib.rs:204-221,
/// 1009-1029): tag, scalars, then every entry in the stored (key-sorted) order.
pub fn mg_epoch_state_commit(state: &MgEpochState) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    sha.update(TAG_MG_STATE_COMMIT);
    sha.update(&state.capacity.to_be_bytes());
    sha.update(&state.total_count.to_be_bytes());
    for e in &state.entries {
        sha.update(&e.key_id);
        sha.update(&e.count.to_be_bytes());
    }
    sha.finalize().into()
}

// ------------------------------------------------------------ Merkle root
//
// Every one of their aggregation modes publishes a Merkle root in its journal
// (samples buckets_root, histogram buckets_root, cm cm_root + heap_root), which
// their host folds into out_commit; none of their query guests reads it. The
// port therefore computes one too, as the SpaceSaving port does: Misra-Gries
// state is a key -> count map, the same shape as their samples state
// (key -> BucketEntry), so the measured guest roots it the way samples does. The
// other variants are sensitivity rows only (aggr_mg_rootvar).

/// Which root the aggregation journal carries.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MgRoot {
    /// HEADLINE (the aggr_mg guest). Their samples construction at their
    /// benchmark geometry, SAMPLES_HT_BUCKETS = 64 (scripts/lib/common.sh:13):
    /// entries hashed into 64 buckets by their samples_bucket_index mix, one leaf
    /// per bucket = SHA(tag || the bucket's entries sorted by key_id), folded by
    /// their samples_buckets_root_from_leaves.
    Buckets64,
    /// The same construction at aggregator-core's build default,
    /// SAMPLES_HT_BUCKETS = 1024 (aggregator/core/build.rs:9).
    Buckets1024,
    /// One leaf per entry, zero-padded to a power of two: their per-key histogram
    /// construction (hist_per_key_root, aggregator/core/src/lib.rs:786-818).
    PerKey,
    /// No root at all (the journal field is zero).
    None,
}

impl MgRoot {
    pub const HEADLINE: MgRoot = MgRoot::Buckets64;
    pub fn name(self) -> &'static str {
        match self {
            MgRoot::Buckets64 => "buckets64",
            MgRoot::Buckets1024 => "buckets1024",
            MgRoot::PerKey => "perkey",
            MgRoot::None => "none",
        }
    }
}

/// Their samples_bucket_index (aggregator/core/src/lib.rs:352-361), copied
/// VERBATIM except that the bucket count is a parameter instead of their
/// build-time SAMPLES_HT_BUCKETS: FNV-1a key_to_u64, a murmur3 finaliser, then
/// & (buckets - 1). Their function is pub, but calling it across the crate
/// boundary costs 0.8M extra cycles per s = 2^14 epoch, which their own guest
/// (same crate) does not pay. The unit test
/// bucket_index_equals_their_function_at_64_and_1024 checks this copy against
/// their pub function for 100,000 keys.
pub fn mg_bucket_index(key_id: &[u8; KEY_BYTES_LEN], buckets: usize) -> usize {
    // Deterministic mixing then mod 64.
    let mut x = key_to_u64(key_id);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    (x as usize) & (buckets - 1)
}

/// Pattern of their samples_buckets_leaves + samples_bucket_leaf_hash +
/// samples_buckets_root (aggregator/core/src/lib.rs:363-422), step for step:
/// number of leaves = next_pow2_ge(max bucket index + 1); group the entries by
/// bucket; leaf = SHA(tag || the bucket's entries sorted by key_id), with MgEntry
/// fields in place of BucketEntry fields; fold with their pub
/// samples_buckets_root_from_leaves (lib.rs:381-391, called unmodified). The
/// leaf hash is a closure, as in the SpaceSaving port (the cheaper codegen).
pub fn mg_buckets_root(entries: &[MgEntry], nb: usize) -> [u8; HASH_BYTES_LEN] {
    // Find actual number of buckets needed (max bucket index + 1, rounded to pow2)
    let max_bucket = entries.iter().map(|e| mg_bucket_index(&e.key_id, nb)).max().unwrap_or(0);
    let num_buckets = next_pow2_ge(max_bucket + 1);

    // Group entries by bucket index
    let mut bucket_entries: Vec<Vec<MgEntry>> = (0..num_buckets).map(|_| Vec::new()).collect();
    for e in entries {
        bucket_entries[mg_bucket_index(&e.key_id, nb)].push(*e);
    }

    // Compute leaf hash for each bucket
    let leaves: Vec<[u8; HASH_BYTES_LEN]> = bucket_entries
        .iter()
        .map(|b| {
            // Hash entries in sorted order by key_id for determinism
            let mut sorted_entries = b.clone();
            sorted_entries.sort_by_key(|e| e.key_id);
            let mut sha = Sha256::new();
            sha.update(TAG_MG_BUCKET_LEAF);
            for e in &sorted_entries {
                sha.update(&e.key_id);
                sha.update(&e.count.to_be_bytes());
            }
            let leaf: [u8; HASH_BYTES_LEN] = sha.finalize().into();
            leaf
        })
        .collect();
    samples_buckets_root_from_leaves(&leaves)
}

fn mg_leaf_hash(e: &MgEntry) -> [u8; HASH_BYTES_LEN] {
    sha256_bytes(&[TAG_MG_LEAF, &e.key_id, &e.count.to_be_bytes()])
}

/// MgRoot::PerKey (sensitivity only): Merkle root over the key-sorted per-key
/// leaves, padded with zero digests to a power of two. Same construction as their
/// hist_per_key_root (aggregator/core/src/lib.rs:786-818).
pub fn mg_entries_root(entries: &[MgEntry]) -> [u8; HASH_BYTES_LEN] {
    if entries.is_empty() {
        return [0u8; HASH_BYTES_LEN];
    }
    let leaf_hashes: Vec<Digest> = entries
        .iter()
        .map(|e| Digest::try_from(&mg_leaf_hash(e)[..]).unwrap())
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

pub fn mg_root(entries: &[MgEntry], root: MgRoot) -> [u8; HASH_BYTES_LEN] {
    match root {
        MgRoot::Buckets64 => mg_buckets_root(entries, 64),
        MgRoot::Buckets1024 => mg_buckets_root(entries, 1024),
        MgRoot::PerKey => mg_entries_root(entries),
        MgRoot::None => [0u8; HASH_BYTES_LEN],
    }
}

// ============================================================ aggregation

/// Aggregation input: their CmAggrInput / SamplesAggrInput fields plus the
/// Misra-Gries capacity s (a run-time input here, bound by the state commitment
/// and published in the journal; their CM_TOPK_SLOTS is a build-time constant).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MgAggrInput {
    pub capacity: u32,
    pub prev_chain_hash: [u8; HASH_BYTES_LEN],
    pub batches: Vec<BatchInput>,
    #[serde(default)]
    pub prev_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

/// Public journal of the aggregation guest (only commitments), field for field
/// their SamplesAggrOutput (aggregator/core/src/lib.rs:276-293) plus `capacity`.
/// `buckets_root` is the MgRoot::HEADLINE root in aggr_mg, and the selected
/// variant's root in the aggr_mg_rootvar guest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MgAggrOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub buckets_root: [u8; HASH_BYTES_LEN],
    pub capacity: u32,
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

pub fn process_mg_aggr(input: &MgAggrInput) -> MgAggrOutput {
    process_mg_aggr_with_state(input).1
}

pub fn process_mg_aggr_with_state(input: &MgAggrInput) -> (MgEpochState, MgAggrOutput) {
    process_mg_aggr_hooked(input, MgRoot::HEADLINE, |_| {})
}

/// The aggregation with a chosen root (aggr_mg_rootvar guest).
pub fn process_mg_aggr_root(input: &MgAggrInput, root: MgRoot) -> MgAggrOutput {
    process_mg_aggr_hooked(input, root, |_| {}).1
}

/// The aggregation, with `mark(phase)` called after each phase. The measured
/// guest passes MgRoot::HEADLINE and a no-op closure (compiled away); the
/// profiling guest records env::cycle_count() there.
pub fn process_mg_aggr_hooked<F: FnMut(&'static str)>(
    input: &MgAggrInput,
    root: MgRoot,
    mut mark: F,
) -> (MgEpochState, MgAggrOutput) {
    // Their chain step (process_cm_aggr_with_state, aggregator/core/src/lib.rs:1216-1232).
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
    mark("chain");

    // Flatten batches to events for processing (their pattern, lib.rs:1234-1238).
    let mut all_events: Vec<Event> = Vec::new();
    for batch in &input.batches {
        all_events.extend(batch.events.iter().cloned());
    }
    mark("flatten");

    // Textbook Misra-Gries, one unit update per record (records carry value = 1).
    let mut mg = MisraGries::new(input.capacity as usize);
    for ev in &all_events {
        mg.update(&ev.key_id);
    }
    mark("update");

    let state = MgEpochState {
        capacity: input.capacity,
        total_count: mg.total(),
        entries: mg.entries_sorted(),
    };
    mark("canon");

    // Their samples flow computes the root right before the state commitment
    // (process_samples_aggr_with_state, aggregator/core/src/lib.rs:669-672).
    let buckets_root = mg_root(&state.entries, root);
    mark("merkle");

    let state_commit = mg_epoch_state_commit(&state);
    let epoch_chain_link = EpochChainLink::new(input.prev_chain_hash, state_commit);
    mark("commit");

    let out = MgAggrOutput {
        epoch_chain_link,
        state_commit,
        buckets_root,
        capacity: input.capacity,
        n_events: all_events.len() as u64,
        final_source_chain_tips,
    };
    (state, out)
}

// ============================================================ query

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MgQuery {
    /// Heavy hitters: the `limit` largest counters of the merged summary
    /// (mg_merge), keys included.
    Topk { limit: u16 },
    /// Point frequency of one key: their SumExactKey pattern
    /// (querier/core/src/lib.rs:808-821), one pass over every epoch's entries
    /// summing the key's count. No merge, no sort, no truncation.
    Estimate { key: [u8; KEY_BYTES_LEN] },
    /// SENSITIVITY ONLY: the key's entry in the merged summary, i.e. a full
    /// mg_merge followed by a lookup (a key outside the merged summary reads 0).
    EstimateMerged { key: [u8; KEY_BYTES_LEN] },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MgQueryInput {
    pub query: MgQuery,
    pub epoch_states: Vec<MgEpochState>,
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

/// A merged counter. Unlike their CmTopkItem / SamplesSumTopkItem (counts only,
/// querier/core/src/lib.rs:169-176, 644-648), the key is in the journal.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MgItem {
    pub key_id: [u8; KEY_BYTES_LEN],
    pub count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MgQueryResult {
    Topk { items: Vec<MgItem> },
    /// Estimate: count summed over the epochs that monitor the key;
    /// `monitored = false` means no epoch monitors it (count = 0).
    /// EstimateMerged: the key's merged entry; `monitored = false` means it is
    /// not in the merged summary (count = 0).
    Estimate { key_id: [u8; KEY_BYTES_LEN], count: u64, monitored: bool },
}

/// Query journal: their *QueryOutput shape (chain boundaries, state commits,
/// result, support, suppressed; querier/core/src/lib.rs:205-228) plus the merged
/// capacity and stream length.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MgQueryOutput {
    pub chain_prev_hash: [u8; 32],
    pub chain_final_hash: [u8; 32],
    pub state_commits: Vec<[u8; 32]>,
    pub capacity: u32,
    pub total_count: u64,
    pub result: MgQueryResult,
    /// Topk: total records across the epochs (as their SumTopk support);
    /// Estimate / EstimateMerged: the returned count (as their SumExactKey
    /// support, the key's summed count).
    pub support: u64,
    pub suppressed: bool,
}

impl MgQueryOutput {
    /// Their low-support rule (e.g. SamplesQueryOutput::suppress_if_low_support,
    /// querier/core/src/lib.rs:720-743): below MIN_SUPPORT, zero every numeric
    /// result field and support, set suppressed. The queried key is kept (it is
    /// a query input, as their AllKey keeps key/mask).
    pub fn suppress_if_low_support(mut self) -> Self {
        if self.support < MIN_SUPPORT {
            self.result = match self.result {
                MgQueryResult::Topk { .. } => MgQueryResult::Topk { items: Vec::new() },
                MgQueryResult::Estimate { key_id, .. } => {
                    MgQueryResult::Estimate { key_id, count: 0, monitored: false }
                }
            };
            self.total_count = 0;
            self.support = 0;
            self.suppressed = true;
        }
        self
    }
}

/// Query-time merge of per-epoch Misra-Gries summaries: the mergeable
/// Misra-Gries merge (Agarwal, Cormode, Huang, Phillips, Wei, Yi, PODS 2012).
/// Sum the counts of equal keys; if more than `capacity` keys remain, subtract
/// the (capacity+1)-th largest summed count from every counter and keep the
/// positive ones (at most `capacity`). Written the way their SumTopk merges
/// per-key entries (querier/core/src/lib.rs:868-913): concatenate, sort by key,
/// aggregate runs in place, sort by count (ties: smaller key_id first).
///
/// The result is a Misra-Gries summary of the union: with N the total records
/// and C the sum of the merged counters, every key satisfies
/// count <= f <= count + (N - C) / (capacity + 1) (count = 0 if absent).
pub fn mg_merge(states: &[MgEpochState], capacity: usize) -> Vec<MgItem> {
    let total: usize = states.iter().map(|s| s.entries.len()).sum();
    let mut all: Vec<MgItem> = Vec::with_capacity(total);
    for state in states {
        for e in &state.entries {
            all.push(MgItem { key_id: e.key_id, count: e.count as u64 });
        }
    }
    if all.is_empty() {
        return all;
    }
    // Stable sort: each epoch's entries are already key-sorted, so this merges runs.
    all.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    let mut merged: Vec<MgItem> = Vec::new();
    let mut cur = all[0];
    cur.count = 0;
    for it in all {
        if it.key_id != cur.key_id {
            merged.push(cur);
            cur = MgItem { key_id: it.key_id, count: 0 };
        }
        cur.count = cur.count.wrapping_add(it.count);
    }
    merged.push(cur);
    merged.sort_unstable_by(|a, b| b.count.cmp(&a.count).then(a.key_id.cmp(&b.key_id)));
    if merged.len() > capacity {
        let tau = merged[capacity].count;
        merged.truncate(capacity);
        for it in merged.iter_mut() {
            it.count -= tau;
        }
        // Counts are sorted descending, so the zeros are a suffix.
        while merged.last().map_or(false, |it| it.count == 0) {
            merged.pop();
        }
    }
    merged
}

pub fn run_mg_query(input: &MgQueryInput) -> MgQueryOutput {
    run_mg_query_hooked(input, |_| {})
}

pub fn run_mg_query_hooked<F: FnMut(&'static str)>(input: &MgQueryInput, mut mark: F) -> MgQueryOutput {
    let epochs = input.epoch_states.len();

    // Their chain/commit verification (run_samples_query, querier/core/src/lib.rs:748-766).
    if !input.epoch_chain_links.is_empty() {
        verify_epoch_chain_integrity(&input.epoch_chain_links);
        assert!(
            input.epoch_chain_links.len() == epochs,
            "epoch_chain_links length != epoch_states length"
        );
    }
    mark("chain");
    if !input.epoch_chain_links.is_empty() {
        // Verify each epoch state hashes to the state_commit in the chain link
        for (i, (state, link)) in input.epoch_states.iter().zip(input.epoch_chain_links.iter()).enumerate() {
            let computed_commit = mg_epoch_state_commit(state);
            assert!(
                computed_commit == link.state_commit,
                "epoch {} state_commit mismatch: computed != chain_link",
                i
            );
        }
    }
    mark("commits");

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

    // Every epoch must use the same capacity; the merged summary keeps at most that many counters.
    let capacity = input.epoch_states.first().map(|s| s.capacity).unwrap_or(0);
    let mut total_count = 0u64;
    for state in &input.epoch_states {
        assert!(state.capacity == capacity, "epoch states disagree on capacity");
        total_count = total_count.wrapping_add(state.total_count);
    }

    let (result, support) = match input.query {
        MgQuery::Topk { limit } => {
            let merged = mg_merge(&input.epoch_states, capacity as usize);
            mark("merge");
            let k = (limit as usize).min(merged.len());
            (MgQueryResult::Topk { items: merged[..k].to_vec() }, total_count)
        }
        MgQuery::Estimate { ref key } => {
            // Their SumExactKey loop (querier/core/src/lib.rs:808-821): scan every
            // entry of every epoch, sum the matches. Support = the summed count.
            // Guarantee: count <= f <= count + the sum of the epochs' decrement
            // counts (N_e - C_e) / (capacity + 1).
            let mut count = 0u64;
            let mut monitored = false;
            for state in &input.epoch_states {
                for entry in &state.entries {
                    if entry.key_id == *key {
                        count = count.wrapping_add(entry.count as u64);
                        monitored = true;
                    }
                }
            }
            mark("scan");
            (MgQueryResult::Estimate { key_id: *key, count, monitored }, count)
        }
        MgQuery::EstimateMerged { ref key } => {
            let merged = mg_merge(&input.epoch_states, capacity as usize);
            mark("merge");
            match merged.iter().find(|it| it.key_id == *key) {
                Some(it) => (MgQueryResult::Estimate { key_id: *key, count: it.count, monitored: true }, it.count),
                None => (MgQueryResult::Estimate { key_id: *key, count: 0, monitored: false }, 0),
            }
        }
    };
    mark("answer");

    MgQueryOutput {
        chain_prev_hash,
        chain_final_hash,
        state_commits,
        capacity,
        total_count,
        result,
        support,
        suppressed: false,
    }
}
