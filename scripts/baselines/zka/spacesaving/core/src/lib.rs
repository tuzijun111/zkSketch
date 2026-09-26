#![no_std]

// SpaceSaving (Metwally, Agrawal, El Abbadi, ICDT 2005) as a zk-Analytics-style
// epoch summary: the zk-Analytics pipeline (Zhu et al., SIGCOMM '26; code at
// d4a5a9a) with only the summary swapped in.
//
//   aggregation (one epoch, rebuilt from scratch):
//     verify the sources' SHA-256 batch hash chains      -- their code, verbatim
//     flatten the batches into events                     -- their pattern
//     textbook SpaceSaving update per record              -- ours (plain Rust)
//     canonical state (entries sorted by key_id)          -- their pattern
//     Merkle root over 64 hash buckets of entries         -- their samples pattern (samples_buckets_root)
//     unsalted SHA-256 state commitment                   -- their pattern
//     epoch chain link                                    -- their EpochChainLink
//   query (n epochs):
//     re-verify epoch chain links                         -- their code, verbatim
//     recompute each epoch's state commitment             -- their pattern
//     top-k: merge the per-epoch summaries at query time  -- ours (sum equal keys, keep top s)
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
const TAG_SS_STATE_COMMIT: &[u8] = b"ZKA_PORT_SS_STATE_COMMIT_V1";
const TAG_SS_BUCKET_LEAF: &[u8] = b"ZKA_PORT_SS_BUCKET_V1"; // cf. their TAG_BUCKET_LEAF, aggregator/core/src/lib.rs:44
const TAG_SS_LEAF: &[u8] = b"ZKA_PORT_SS_LEAF_V1"; // per-key leaves (SsRoot::PerKey sensitivity variant only)

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

// ============================================================ SpaceSaving

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

const NIL: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Counter {
    key: [u8; KEY_BYTES_LEN],
    error: u32,
    bucket: u32,
    prev: u32,
    next: u32,
}

#[derive(Clone, Copy)]
struct Bucket {
    count: u32,
    head: u32,
    tail: u32,
    prev: u32,
    next: u32,
}

/// SpaceSaving with Metwally et al.'s Stream-Summary: counters with equal counts
/// share a bucket, buckets form a list in increasing count order, and each
/// bucket holds a doubly linked list of its counters. With unit updates every
/// operation is O(1): a hit moves one counter to the neighbouring bucket, a miss
/// either takes a free counter or replaces the oldest counter of the minimum
/// bucket (new count = min + 1, error = min). A counter enters a bucket at the
/// tail and eviction takes the head, so the victim is the minimum-count counter
/// that reached its count earliest (the reference model in the host driver
/// re-implements exactly this rule with a linear scan and must agree).
/// Lists use u32 indices into two arenas, so there are no pointers and no
/// per-update allocation.
pub struct SpaceSaving {
    capacity: usize,
    counters: Vec<Counter>,
    buckets: Vec<Bucket>,
    free_buckets: Vec<u32>,
    min_bucket: u32,
    index: KeyIndex,
    total: u64,
}

impl SpaceSaving {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1 && capacity < NIL as usize, "SpaceSaving capacity must be in 1..2^32-1");
        let mut index = KeyIndex::default();
        index.reserve(capacity);
        Self {
            capacity,
            counters: Vec::with_capacity(capacity),
            buckets: Vec::with_capacity(capacity),
            free_buckets: Vec::new(),
            min_bucket: NIL,
            index,
            total: 0,
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    fn new_bucket(&mut self, count: u32) -> u32 {
        let b = Bucket { count, head: NIL, tail: NIL, prev: NIL, next: NIL };
        if let Some(i) = self.free_buckets.pop() {
            self.buckets[i as usize] = b;
            i
        } else {
            self.buckets.push(b);
            (self.buckets.len() - 1) as u32
        }
    }

    /// Link bucket `b` right after `after` (NIL: as the new minimum bucket).
    fn link_bucket_after(&mut self, b: u32, after: u32) {
        let next = if after == NIL { self.min_bucket } else { self.buckets[after as usize].next };
        self.buckets[b as usize].prev = after;
        self.buckets[b as usize].next = next;
        if next != NIL {
            self.buckets[next as usize].prev = b;
        }
        if after == NIL {
            self.min_bucket = b;
        } else {
            self.buckets[after as usize].next = b;
        }
    }

    fn unlink_bucket(&mut self, b: u32) {
        let Bucket { prev, next, .. } = self.buckets[b as usize];
        if prev != NIL {
            self.buckets[prev as usize].next = next;
        } else {
            self.min_bucket = next;
        }
        if next != NIL {
            self.buckets[next as usize].prev = prev;
        }
        self.free_buckets.push(b);
    }

    fn push_tail(&mut self, c: u32, b: u32) {
        let tail = self.buckets[b as usize].tail;
        let ct = &mut self.counters[c as usize];
        ct.bucket = b;
        ct.prev = tail;
        ct.next = NIL;
        if tail != NIL {
            self.counters[tail as usize].next = c;
        } else {
            self.buckets[b as usize].head = c;
        }
        self.buckets[b as usize].tail = c;
    }

    fn detach(&mut self, c: u32) {
        let Counter { bucket: b, prev, next, .. } = self.counters[c as usize];
        if prev != NIL {
            self.counters[prev as usize].next = next;
        } else {
            self.buckets[b as usize].head = next;
        }
        if next != NIL {
            self.counters[next as usize].prev = prev;
        } else {
            self.buckets[b as usize].tail = prev;
        }
    }

    /// count(c) += 1, keeping the bucket list sorted.
    fn increment(&mut self, c: u32) {
        let b = self.counters[c as usize].bucket;
        let Bucket { count, head, tail, next, .. } = self.buckets[b as usize];
        let alone = head == c && tail == c;
        if next != NIL && self.buckets[next as usize].count == count + 1 {
            self.detach(c);
            self.push_tail(c, next);
            if alone {
                self.unlink_bucket(b);
            }
        } else if alone {
            // Sole member: bump the bucket in place (the next bucket, if any, is > count+1).
            self.buckets[b as usize].count = count + 1;
        } else {
            let nb = self.new_bucket(count + 1);
            self.link_bucket_after(nb, b);
            self.detach(c);
            self.push_tail(c, nb);
        }
    }

    /// One unit-weight SpaceSaving update.
    pub fn update(&mut self, key: &[u8; KEY_BYTES_LEN]) {
        self.total += 1;
        if let Some(&c) = self.index.get(&MapKey(*key)) {
            self.increment(c);
            return;
        }
        if self.counters.len() < self.capacity {
            let c = self.counters.len() as u32;
            self.counters.push(Counter { key: *key, error: 0, bucket: NIL, prev: NIL, next: NIL });
            self.index.insert(MapKey(*key), c);
            let b = if self.min_bucket != NIL && self.buckets[self.min_bucket as usize].count == 1 {
                self.min_bucket
            } else {
                let nb = self.new_bucket(1);
                self.link_bucket_after(nb, NIL);
                nb
            };
            self.push_tail(c, b);
        } else {
            // Replace the oldest counter of the minimum bucket.
            let b = self.min_bucket;
            let c = self.buckets[b as usize].head;
            let min = self.buckets[b as usize].count;
            let old = self.counters[c as usize].key;
            self.index.remove(&MapKey(old));
            self.counters[c as usize].key = *key;
            self.counters[c as usize].error = min;
            self.index.insert(MapKey(*key), c);
            self.increment(c);
        }
    }

    /// The monitored (key, count, error) entries in canonical order (sorted by key_id,
    /// as their SamplesEpochState::from sorts per_key, aggregator/core/src/lib.rs:189-199).
    pub fn entries_sorted(&self) -> Vec<SsEntry> {
        let mut entries: Vec<SsEntry> = self
            .counters
            .iter()
            .map(|c| SsEntry { key_id: c.key, count: self.buckets[c.bucket as usize].count, error: c.error })
            .collect();
        entries.sort_by_key(|e| e.key_id);
        entries
    }
}

// ============================================================ epoch state

/// One monitored counter. Per-epoch counts fit u32 (their convention for per-epoch
/// counts, e.g. BucketEntry.count / KeyHistogram.count); the query widens to u64.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsEntry {
    pub key_id: [u8; KEY_BYTES_LEN],
    pub count: u32,
    pub error: u32,
}

/// Serializable epoch state: what the provider stores and the query guest re-hashes.
/// `entries` holds the <= capacity monitored counters, sorted by key_id.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsEpochState {
    pub capacity: u32,
    pub total_count: u64,
    pub entries: Vec<SsEntry>,
}

/// Unsalted SHA-256 state commitment, in the style of their
/// samples_epoch_state_commit / cm_epoch_state_commit (aggregator/core/src/lib.rs:204-221,
/// 1009-1029): tag, scalars, then every entry in the stored (key-sorted) order.
pub fn ss_epoch_state_commit(state: &SsEpochState) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    sha.update(TAG_SS_STATE_COMMIT);
    sha.update(&state.capacity.to_be_bytes());
    sha.update(&state.total_count.to_be_bytes());
    for e in &state.entries {
        sha.update(&e.key_id);
        sha.update(&e.count.to_be_bytes());
        sha.update(&e.error.to_be_bytes());
    }
    sha.finalize().into()
}

// ------------------------------------------------------------ Merkle root
//
// Every one of their aggregation modes publishes a Merkle root in its journal
// (samples buckets_root, histogram buckets_root, cm cm_root + heap_root), which
// their host folds into out_commit; none of their query guests reads it. The
// port therefore computes one too. Which of their root constructions applies is
// a choice: SpaceSaving state is a key -> (count, error) map, the same shape as
// their samples state (key -> BucketEntry), so the measured guest roots it the
// way samples does. The other variants are sensitivity rows only (aggr_ss_rootvar).

/// Which root the aggregation journal carries.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SsRoot {
    /// HEADLINE (the aggr_ss guest). Their samples construction at their
    /// benchmark geometry, SAMPLES_HT_BUCKETS = 64 (scripts/lib/common.sh:13):
    /// entries hashed into 64 buckets by their samples_bucket_index mix, one leaf
    /// per bucket = SHA(tag || the bucket's entries sorted by key_id), folded by
    /// their samples_buckets_root_from_leaves.
    Buckets64,
    /// The same construction at aggregator-core's build default,
    /// SAMPLES_HT_BUCKETS = 1024 (aggregator/core/build.rs:9). The shipped arm's
    /// aggr_samples (../cyc) was built with this default.
    Buckets1024,
    /// One leaf per entry, zero-padded to a power of two: their per-key histogram
    /// construction (hist_per_key_root, aggregator/core/src/lib.rs:786-818).
    /// This was v1 of this port's headline; it is kept as a sensitivity row.
    PerKey,
    /// No root at all (the journal field is zero).
    None,
}

impl SsRoot {
    pub const HEADLINE: SsRoot = SsRoot::Buckets64;
    pub fn name(self) -> &'static str {
        match self {
            SsRoot::Buckets64 => "buckets64",
            SsRoot::Buckets1024 => "buckets1024",
            SsRoot::PerKey => "perkey",
            SsRoot::None => "none",
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
pub fn ss_bucket_index(key_id: &[u8; KEY_BYTES_LEN], buckets: usize) -> usize {
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
/// bucket; leaf = SHA(tag || the bucket's entries sorted by key_id), with SsEntry
/// fields in place of BucketEntry fields; fold with their pub
/// samples_buckets_root_from_leaves (lib.rs:381-391, called unmodified).
///
/// The leaf hash is written as a closure. The same code as a separate function
/// (their layout) compiles 1.3M cycles slower per s = 2^14 epoch (the per-bucket
/// sort is code-generated differently); the work is identical, and the cheaper
/// form is kept so as not to charge the baseline for codegen.
pub fn ss_buckets_root(entries: &[SsEntry], nb: usize) -> [u8; HASH_BYTES_LEN] {
    // Find actual number of buckets needed (max bucket index + 1, rounded to pow2)
    let max_bucket = entries.iter().map(|e| ss_bucket_index(&e.key_id, nb)).max().unwrap_or(0);
    let num_buckets = next_pow2_ge(max_bucket + 1);

    // Group entries by bucket index
    let mut bucket_entries: Vec<Vec<SsEntry>> = (0..num_buckets).map(|_| Vec::new()).collect();
    for e in entries {
        bucket_entries[ss_bucket_index(&e.key_id, nb)].push(*e);
    }

    // Compute leaf hash for each bucket
    let leaves: Vec<[u8; HASH_BYTES_LEN]> = bucket_entries
        .iter()
        .map(|b| {
            // Hash entries in sorted order by key_id for determinism
            let mut sorted_entries = b.clone();
            sorted_entries.sort_by_key(|e| e.key_id);
            let mut sha = Sha256::new();
            sha.update(TAG_SS_BUCKET_LEAF);
            for e in &sorted_entries {
                sha.update(&e.key_id);
                sha.update(&e.count.to_be_bytes());
                sha.update(&e.error.to_be_bytes());
            }
            let leaf: [u8; HASH_BYTES_LEN] = sha.finalize().into();
            leaf
        })
        .collect();
    samples_buckets_root_from_leaves(&leaves)
}

fn ss_leaf_hash(e: &SsEntry) -> [u8; HASH_BYTES_LEN] {
    sha256_bytes(&[TAG_SS_LEAF, &e.key_id, &e.count.to_be_bytes(), &e.error.to_be_bytes()])
}

/// SsRoot::PerKey (sensitivity only): Merkle root over the key-sorted per-key
/// leaves, padded with zero digests to a power of two. Same construction as their
/// hist_per_key_root (aggregator/core/src/lib.rs:786-818).
pub fn ss_entries_root(entries: &[SsEntry]) -> [u8; HASH_BYTES_LEN] {
    if entries.is_empty() {
        return [0u8; HASH_BYTES_LEN];
    }
    let leaf_hashes: Vec<Digest> = entries
        .iter()
        .map(|e| Digest::try_from(&ss_leaf_hash(e)[..]).unwrap())
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

pub fn ss_root(entries: &[SsEntry], root: SsRoot) -> [u8; HASH_BYTES_LEN] {
    match root {
        SsRoot::Buckets64 => ss_buckets_root(entries, 64),
        SsRoot::Buckets1024 => ss_buckets_root(entries, 1024),
        SsRoot::PerKey => ss_entries_root(entries),
        SsRoot::None => [0u8; HASH_BYTES_LEN],
    }
}

// ============================================================ aggregation

/// Aggregation input: their CmAggrInput / SamplesAggrInput fields plus the
/// SpaceSaving capacity s (a run-time input here, bound by the state commitment
/// and published in the journal; their CM_TOPK_SLOTS is a build-time constant).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsAggrInput {
    pub capacity: u32,
    pub prev_chain_hash: [u8; HASH_BYTES_LEN],
    pub batches: Vec<BatchInput>,
    #[serde(default)]
    pub prev_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

/// Public journal of the aggregation guest (only commitments), field for field
/// their SamplesAggrOutput (aggregator/core/src/lib.rs:276-293) plus `capacity`.
/// `buckets_root` is the SsRoot::HEADLINE root in aggr_ss, and the selected
/// variant's root in the aggr_ss_rootvar sensitivity guest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsAggrOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub buckets_root: [u8; HASH_BYTES_LEN],
    pub capacity: u32,
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

pub fn process_ss_aggr(input: &SsAggrInput) -> SsAggrOutput {
    process_ss_aggr_with_state(input).1
}

pub fn process_ss_aggr_with_state(input: &SsAggrInput) -> (SsEpochState, SsAggrOutput) {
    process_ss_aggr_hooked(input, SsRoot::HEADLINE, |_| {})
}

/// The aggregation with a chosen root (aggr_ss_rootvar sensitivity guest).
pub fn process_ss_aggr_root(input: &SsAggrInput, root: SsRoot) -> SsAggrOutput {
    process_ss_aggr_hooked(input, root, |_| {}).1
}

/// The aggregation, with `mark(phase)` called after each phase. The measured
/// guest passes SsRoot::HEADLINE and a no-op closure (compiled away); the
/// profiling guest records env::cycle_count() there.
pub fn process_ss_aggr_hooked<F: FnMut(&'static str)>(
    input: &SsAggrInput,
    root: SsRoot,
    mut mark: F,
) -> (SsEpochState, SsAggrOutput) {
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

    // Textbook SpaceSaving, one unit update per record (records carry value = 1).
    let mut ss = SpaceSaving::new(input.capacity as usize);
    for ev in &all_events {
        ss.update(&ev.key_id);
    }
    mark("update");

    let state = SsEpochState {
        capacity: input.capacity,
        total_count: ss.total(),
        entries: ss.entries_sorted(),
    };
    mark("canon");

    // Their samples flow computes the root right before the state commitment
    // (process_samples_aggr_with_state, aggregator/core/src/lib.rs:669-672).
    let buckets_root = ss_root(&state.entries, root);
    mark("merkle");

    let state_commit = ss_epoch_state_commit(&state);
    let epoch_chain_link = EpochChainLink::new(input.prev_chain_hash, state_commit);
    mark("commit");

    let out = SsAggrOutput {
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
pub enum SsQuery {
    /// Heavy hitters: the `limit` largest counters of the merged summary
    /// (ss_merge), keys included.
    Topk { limit: u16 },
    /// Point frequency of one key: their SumExactKey pattern
    /// (querier/core/src/lib.rs:808-821), one pass over every epoch's entries
    /// summing the key's count and error. No merge, no sort, no truncation.
    Estimate { key: [u8; KEY_BYTES_LEN] },
    /// SENSITIVITY ONLY (v1 of this port's point query): the key's entry in the
    /// merged, truncated summary, i.e. a full ss_merge followed by a lookup.
    /// Different semantics (a key outside the merged top s reads 0) and an upper
    /// bound on what a point query needs to cost.
    EstimateMerged { key: [u8; KEY_BYTES_LEN] },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsQueryInput {
    pub query: SsQuery,
    pub epoch_states: Vec<SsEpochState>,
    #[serde(default)]
    pub epoch_chain_links: Vec<EpochChainLink>,
}

/// A merged counter. Unlike their CmTopkItem / SamplesSumTopkItem (counts only,
/// querier/core/src/lib.rs:169-176, 644-648), the key is in the journal.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsItem {
    pub key_id: [u8; KEY_BYTES_LEN],
    pub count: u64,
    pub error: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SsQueryResult {
    Topk { items: Vec<SsItem> },
    /// Estimate: count/error summed over the epochs that monitor the key;
    /// `monitored = false` means no epoch monitors it (count = error = 0).
    /// EstimateMerged: the key's merged entry; `monitored = false` means it is
    /// not among the merged top-`capacity` counters (count = error = 0).
    Estimate { key_id: [u8; KEY_BYTES_LEN], count: u64, error: u64, monitored: bool },
}

/// Query journal: their *QueryOutput shape (chain boundaries, state commits,
/// result, support, suppressed; querier/core/src/lib.rs:205-228) plus the merged
/// capacity and stream length.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsQueryOutput {
    pub chain_prev_hash: [u8; 32],
    pub chain_final_hash: [u8; 32],
    pub state_commits: Vec<[u8; 32]>,
    pub capacity: u32,
    pub total_count: u64,
    pub result: SsQueryResult,
    /// Topk: total records across the epochs (as their SumTopk support);
    /// Estimate / EstimateMerged: the returned count (as their SumExactKey
    /// support, the key's summed count).
    pub support: u64,
    pub suppressed: bool,
}

impl SsQueryOutput {
    /// Their low-support rule (e.g. SamplesQueryOutput::suppress_if_low_support,
    /// querier/core/src/lib.rs:720-743): below MIN_SUPPORT, zero every numeric
    /// result field and support, set suppressed. The queried key is kept (it is
    /// a query input, as their AllKey keeps key/mask).
    pub fn suppress_if_low_support(mut self) -> Self {
        if self.support < MIN_SUPPORT {
            self.result = match self.result {
                SsQueryResult::Topk { .. } => SsQueryResult::Topk { items: Vec::new() },
                SsQueryResult::Estimate { key_id, .. } => {
                    SsQueryResult::Estimate { key_id, count: 0, error: 0, monitored: false }
                }
            };
            self.total_count = 0;
            self.support = 0;
            self.suppressed = true;
        }
        self
    }
}

/// Query-time merge of per-epoch SpaceSaving summaries: the sum-and-truncate
/// merge specified for this baseline. Sum the counts (and errors) of equal keys,
/// then keep the `capacity` largest counters (ties: smaller key_id first).
/// Written the way their SumTopk merges per-key entries
/// (querier/core/src/lib.rs:868-913): concatenate, sort by key, aggregate runs
/// in place, sort by count.
///
/// This is NOT the Agarwal et al. (PODS 2012) MG/SpaceSaving merge, which also
/// subtracts the (s+1)-th merged counter. Its guarantee is looser. With N the
/// total records and s the capacity:
///   - count - error <= f for every merged entry (f = true frequency);
///   - for a retained key, f - count <= the sum of the minimum counters of the
///     epochs where it was unmonitored, which is <= N/s (so it can undercount);
///   - count - f <= error <= N/s;
///   - a key dropped by the truncation has f <= C_{s+1} + N/s <= 2N/s, where
///     C_{s+1} <= N/(s+1) is the (s+1)-th largest merged count.
pub fn ss_merge(states: &[SsEpochState], capacity: usize) -> Vec<SsItem> {
    let total: usize = states.iter().map(|s| s.entries.len()).sum();
    let mut all: Vec<SsItem> = Vec::with_capacity(total);
    for state in states {
        for e in &state.entries {
            all.push(SsItem { key_id: e.key_id, count: e.count as u64, error: e.error as u64 });
        }
    }
    if all.is_empty() {
        return all;
    }
    // Stable sort: each epoch's entries are already key-sorted, so this merges runs.
    all.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    let mut merged: Vec<SsItem> = Vec::new();
    let mut cur = all[0];
    cur.count = 0;
    cur.error = 0;
    for it in all {
        if it.key_id != cur.key_id {
            merged.push(cur);
            cur = SsItem { key_id: it.key_id, count: 0, error: 0 };
        }
        cur.count = cur.count.wrapping_add(it.count);
        cur.error = cur.error.wrapping_add(it.error);
    }
    merged.push(cur);
    merged.sort_unstable_by(|a, b| b.count.cmp(&a.count).then(a.key_id.cmp(&b.key_id)));
    merged.truncate(capacity);
    merged
}

pub fn run_ss_query(input: &SsQueryInput) -> SsQueryOutput {
    run_ss_query_hooked(input, |_| {})
}

pub fn run_ss_query_hooked<F: FnMut(&'static str)>(input: &SsQueryInput, mut mark: F) -> SsQueryOutput {
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
            let computed_commit = ss_epoch_state_commit(state);
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

    // Every epoch must use the same capacity; the merged summary keeps that many counters.
    let capacity = input.epoch_states.first().map(|s| s.capacity).unwrap_or(0);
    let mut total_count = 0u64;
    for state in &input.epoch_states {
        assert!(state.capacity == capacity, "epoch states disagree on capacity");
        total_count = total_count.wrapping_add(state.total_count);
    }

    let (result, support) = match input.query {
        SsQuery::Topk { limit } => {
            let merged = ss_merge(&input.epoch_states, capacity as usize);
            mark("merge");
            let k = (limit as usize).min(merged.len());
            (SsQueryResult::Topk { items: merged[..k].to_vec() }, total_count)
        }
        SsQuery::Estimate { ref key } => {
            // Their SumExactKey loop (querier/core/src/lib.rs:808-821): scan every
            // entry of every epoch, sum the matches. Support = the summed count.
            // Guarantee: count - error <= f <= count + the sum of the minimum
            // counters of the epochs that do not monitor the key (0 for epochs
            // whose summary never filled, e.g. s = 2^14 on AOL).
            let mut count = 0u64;
            let mut error = 0u64;
            let mut monitored = false;
            for state in &input.epoch_states {
                for entry in &state.entries {
                    if entry.key_id == *key {
                        count = count.wrapping_add(entry.count as u64);
                        error = error.wrapping_add(entry.error as u64);
                        monitored = true;
                    }
                }
            }
            mark("scan");
            (SsQueryResult::Estimate { key_id: *key, count, error, monitored }, count)
        }
        SsQuery::EstimateMerged { ref key } => {
            let merged = ss_merge(&input.epoch_states, capacity as usize);
            mark("merge");
            match merged.iter().find(|it| it.key_id == *key) {
                Some(it) => (
                    SsQueryResult::Estimate { key_id: *key, count: it.count, error: it.error, monitored: true },
                    it.count,
                ),
                None => (SsQueryResult::Estimate { key_id: *key, count: 0, error: 0, monitored: false }, 0),
            }
        }
    };
    mark("answer");

    SsQueryOutput {
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
