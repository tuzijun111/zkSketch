#![no_std]

//! zkSketch's Greenwald-Khanna batch rule run inside zk-Analytics' own epoch pipeline
//! (Zhu et al., "Zero-Knowledge Cloud Analytics", SIGCOMM '26; code at commit d4a5a9a):
//! the MATCHED GK port of the six-sketch comparison.
//!
//! `../../gk` runs textbook Greenwald-Khanna (INSERT / COMPRESS per record, a summary
//! built from scratch per epoch, a k-way COMBINE at query time) in their pipeline. That
//! is a different function from the one zkSketch's GK circuit certifies, so its cost is
//! not the cost of the same work. This crate keeps their pipeline step for step and
//! swaps only the summary update for zkSketch's, so both systems compute the same
//! sketch state from the same records:
//!
//!   aggregation (one guest run per epoch of B records)
//!     1. verify the data source's SHA-256 batch hash chain   -- their code, verbatim
//!     2. flatten the batches to events                       -- as upstream
//!     3. take the CARRIED previous state S_{e-1} and check it against the previous
//!        epoch's state commitment through the epoch hash chain (their
//!        EpochChainLink::compute_final_hash); epoch 0 starts from the empty state
//!     4. map the records with zkSketch's gk_vals_of (drop PAD_KEY, mask to 21 bits)
//!     5. apply ceil(B / m_sub) successive zkSketch batch steps
//!        S <- apply_batch2(S, values[j*m_sub .. (j+1)*m_sub])   -- ../../gk_bm2/core,
//!        GkbParams { capacity, batch: m_sub, s }; a capacity overflow is a HARD ERROR
//!     6. (variant) Merkle root over the state entries        -- their per-type pattern
//!     7. unsalted SHA-256 state commitment                    -- their pattern (over the
//!        parameters, n and the active tuples: `compact_words`)
//!     8. link the commitment into the epoch hash chain        -- their EpochChainLink
//!   query (one guest run per query)
//!     1. re-verify the epoch chain links                      -- their code, verbatim
//!     2. recompute the LATEST epoch's state commitment and check it against the last
//!        link (the carried state summarises every epoch, so only it is opened)
//!     3. rank(v) with zkSketch's GK decoder estimator         -- src/decode/gk_bandmerge.rs
//!     4. low-support suppression                              -- their MIN_SUPPORT rule
//!
//! zkSketch proves the same B records as m_sub-record leaves composed in a proof
//! forest; the function it certifies for the epoch is exactly the chain of step 5
//! (`apply_batch2` once per leaf, from the previous state). The host checks the guest
//! against zkSketch's native `apply_batch2` chain tuple by tuple and against the
//! commitments zkSketch's GK leaf circuit exposes (`../host`, `--mode check|certify`).
//!
//! Three implementations of the one transition are selectable (`GkmImpl`, ported and
//! tested in ../../gk_bm2): `Fast` (the default, the steelman: a data-dependent
//! schedule a zkVM may use), `FixedLinear` (zkSketch's fixed schedule, linear-time
//! tables) and `Literal` (zkSketch's code statement for statement). They give the
//! same state; the guest's cycle count depends on the choice.
//!
//! Upstream items that are `pub` are imported. Items that are private upstream are
//! copied VERBATIM below, each with its upstream file:line at commit d4a5a9a.

extern crate alloc;

use alloc::format;
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
pub use gk_bm2_core as bm2;
use gk_bm2_core::{Params, State, Tuple};
pub use querier_core::MIN_SUPPORT;

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
// Configuration (bound by the journal and, through the state encoding, by the state
// commitment: the gk_bm2 word encoding starts with capacity, batch = m_sub and s).
// ===========================================================================

/// The genesis epoch-chain hash (their querier/core GENESIS, `[0u8; 32]`).
pub const GENESIS: [u8; HASH_BYTES_LEN] = [0u8; HASH_BYTES_LEN];

/// Which implementation of zkSketch's batch transition the guest runs. All three give
/// the same state (../../gk_bm2/README.md); only the guest's cycle count differs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GkmImpl {
    /// `apply_batch2_fast`: data-dependent schedule (active prefix only, early stop).
    /// The default: the efficient implementation a zkVM programmer would write.
    Fast,
    /// `apply_batch2_fixed`: zkSketch's fixed schedule (full capacity + m_sub table,
    /// every round, every pair) with linear-time union and compaction.
    FixedLinear,
    /// `apply_batch2`: zkSketch's native code statement for statement.
    Literal,
}

impl GkmImpl {
    pub const ALL: [GkmImpl; 3] = [GkmImpl::Fast, GkmImpl::FixedLinear, GkmImpl::Literal];
    pub fn name(self) -> &'static str {
        match self {
            GkmImpl::Fast => "fast",
            GkmImpl::FixedLinear => "fixed_linear",
            GkmImpl::Literal => "literal",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        GkmImpl::ALL.into_iter().find(|i| i.name() == s)
    }
}

/// zkSketch's GK parameters for one deployment: `GkbParams { capacity, batch: m_sub, s }`
/// (`EXP_GK_CAP`, the leaf size, `EXP_GK_S`) plus the implementation choice.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkmConfig {
    /// Summary capacity s' (rows of the state, actives + dummies).
    pub capacity: u32,
    /// Records per zkSketch leaf: each epoch is applied as ceil(B / m_sub) steps.
    pub m_sub: u32,
    /// Accuracy parameter s = 1/eps; threshold theta_t = floor(N_t / s).
    pub s: u32,
    pub implementation: GkmImpl,
}

impl GkmConfig {
    pub fn params(&self) -> Params {
        Params { capacity: self.capacity as usize, batch: self.m_sub as usize, s: self.s as u64 }
    }
    pub fn validate(&self) {
        assert!(self.capacity >= 1 && self.m_sub >= 1 && self.s >= 1, "GK config: capacity, m_sub and s must be >= 1");
    }
}

/// One step of zkSketch's GK batch rule with the chosen implementation.
pub fn apply_step(implementation: GkmImpl, s: &State, vals: &[u32]) -> State {
    match implementation {
        GkmImpl::Fast => bm2::apply_batch2_fast(s, vals),
        GkmImpl::FixedLinear => bm2::apply_batch2_fixed(s, vals),
        GkmImpl::Literal => bm2::apply_batch2(s, vals),
    }
}

/// Mass of the leading active rows: sum of g + g° + 1 over the canonical active prefix.
pub fn prefix_mass(s: &State) -> u64 {
    s.tuples.iter().take_while(|t| t.active == 1).map(Tuple::mass).sum()
}

/// `None` if the state carries all N_t records, else why not. Fusions conserve the
/// mass g + g° + 1, so a state chained from the empty one has active mass exactly
/// N_t unless `apply_batch2` cut active rows past `capacity` (zkSketch's native code
/// truncates silently in release builds; its leaf circuit refuses to prove). The
/// prefix sum is enough: it is at most the full active mass, which is at most N_t,
/// so prefix == N_t means nothing was dropped.
pub fn capacity_violation(s: &State) -> Option<(u64, u64)> {
    let m = prefix_mass(s);
    if m == s.n { None } else { Some((m, s.n)) }
}

/// The epoch's sub-batch steps: `vals` in chunks of `m_sub`, each one apply_batch2
/// step from the previous state; panics (a HARD ERROR: the guest proves nothing) on a
/// capacity overflow. Returns the new state and the number of steps.
pub fn apply_epoch(cfg: &GkmConfig, s_prev: State, vals: &[u32]) -> (State, u32) {
    let mut s = s_prev;
    let mut steps = 0u32;
    for chunk in vals.chunks(cfg.m_sub as usize) {
        s = apply_step(cfg.implementation, &s, chunk);
        if let Some((mass, n)) = capacity_violation(&s) {
            panic!(
                "GK capacity overflow at step {} of the epoch: capacity {} kept mass {} of N_t = {} records \
                 (raise the capacity; zkSketch's leaf circuit cannot prove this step either)",
                steps, cfg.capacity, mass, n
            );
        }
        steps += 1;
    }
    (s, steps)
}

// ===========================================================================
// Root variants (six-sketch comparison, ../../README.md "Root variants of the
// zk-Analytics aggregation proofs"), as in ../../gk/core/src/root.rs, over the
// state's ACTIVE tuples (its entries; the dummy rows are padding):
//   designed (Buckets64)  their samples pattern, 64 contiguous groups of tuples, leaf j =
//                         SHA-256(tag || the group's tuples, fields big-endian), folded by
//                         their pub samples_buckets_root_from_leaves
//   noroot   (None)       no root, `tuples_root` zero: the headline
//   pertuple (PerTuple)   one leaf per tuple, their MerkleTree (sensitivity)
// Every variant computes the same state, state commitment and epoch link.
// ===========================================================================

/// Buckets of the designed root: their benchmark SAMPLES_HT_BUCKETS (scripts/lib/common.sh:13).
pub const ROOT_BUCKETS: usize = 64;
const TAG_GKM_BUCKET_LEAF: &[u8] = b"ZKA_PORT_GKM_BUCKET_V1";
const TAG_GKM_TUPLE_LEAF: &[u8] = b"ZKA_PORT_GKM_TUPLE_LEAF_V1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GkmRoot {
    Buckets64,
    None,
    PerTuple,
}

impl GkmRoot {
    pub fn construction(self) -> &'static str {
        match self {
            GkmRoot::Buckets64 => "samples64",
            GkmRoot::None => "none",
            GkmRoot::PerTuple => "pertuple",
        }
    }
}

fn tuple_fields(sha: &mut Sha256, t: &Tuple) {
    sha.update(&t.e.to_be_bytes());
    sha.update(&t.g.to_be_bytes());
    sha.update(&t.g_o.to_be_bytes());
    sha.update(&t.delta.to_be_bytes());
    sha.update(&t.delta_o.to_be_bytes());
    sha.update(&t.t.to_be_bytes());
}

/// The state's active tuples (the canonical prefix).
pub fn actives(s: &State) -> &[Tuple] {
    let k = s.tuples.iter().take_while(|t| t.active == 1).count();
    &s.tuples[..k]
}

pub fn gkm_buckets_root(tuples: &[Tuple]) -> [u8; HASH_BYTES_LEN] {
    let n = tuples.len();
    let max_bucket = if n == 0 { 0 } else { (n - 1) * ROOT_BUCKETS / n };
    let num_buckets = next_pow2_ge(max_bucket + 1);
    let mut leaves: Vec<[u8; HASH_BYTES_LEN]> = Vec::with_capacity(num_buckets);
    let mut i = 0usize;
    for j in 0..num_buckets {
        let mut sha = Sha256::new();
        sha.update(TAG_GKM_BUCKET_LEAF);
        while i < n && i * ROOT_BUCKETS / n == j {
            tuple_fields(&mut sha, &tuples[i]);
            i += 1;
        }
        leaves.push(sha.finalize().into());
    }
    aggregator_core::samples_buckets_root_from_leaves(&leaves)
}

/// One leaf per tuple (tag, index, fields), zero-padded to a power of two, their
/// MerkleTree; zero hash when empty (the hist_per_key_root pattern, as ../../gk).
pub fn gkm_tuples_root(tuples: &[Tuple]) -> [u8; HASH_BYTES_LEN] {
    if tuples.is_empty() {
        return [0u8; HASH_BYTES_LEN];
    }
    let mut leaves: Vec<Digest> = tuples
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut sha = Sha256::new();
            sha.update(TAG_GKM_TUPLE_LEAF);
            sha.update(&(i as u32).to_be_bytes());
            tuple_fields(&mut sha, t);
            let h: [u8; HASH_BYTES_LEN] = sha.finalize().into();
            Digest::try_from(&h[..]).unwrap()
        })
        .collect();
    let num_leaves = next_pow2_ge(leaves.len());
    while leaves.len() < num_leaves {
        leaves.push(Digest::try_from(&[0u8; HASH_BYTES_LEN][..]).unwrap());
    }
    MerkleTree::new(leaves).root().into()
}

pub fn gkm_root(s: &State, root: GkmRoot) -> [u8; HASH_BYTES_LEN] {
    match root {
        GkmRoot::Buckets64 => gkm_buckets_root(actives(s)),
        GkmRoot::None => [0u8; HASH_BYTES_LEN],
        GkmRoot::PerTuple => gkm_tuples_root(actives(s)),
    }
}

// ===========================================================================
// Aggregation guest logic (structure of process_histogram_aggr_with_state,
// aggregator/core/src/lib.rs:851-943, as ../../gk), with the carried state.
// ===========================================================================

/// The previous epoch's state, carried into this one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkmCarried {
    /// The previous epoch link's prev_chain_hash (so the guest can recompute that
    /// link's final_chain_hash, which is this epoch's prev_chain_hash).
    pub link_prev_hash: [u8; HASH_BYTES_LEN],
    /// S_{e-1} as compact words ([`compact_words`]: parameters, n, the active tuples).
    pub state_words: Vec<u32>,
}

/// HistogramAggrInput's fields (aggregator/core/src/lib.rs:687-697) plus the GK
/// configuration and the carried state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkmAggrInput {
    pub prev_chain_hash: [u8; HASH_BYTES_LEN],
    /// Batches with events grouped (not flattened) for per-batch hash verification.
    pub batches: Vec<BatchInput>,
    /// Previous epoch's final chain tips per source_id for cross-epoch verification.
    #[serde(default)]
    pub prev_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
    pub config: GkmConfig,
    /// None exactly at genesis (prev_chain_hash == GENESIS): S_{-1} = the empty state.
    pub carried: Option<GkmCarried>,
}

/// Public journal (only commitments), shaped like HistogramAggrOutput
/// (aggregator/core/src/lib.rs:744-762) with `tuples_root` in place of `buckets_root`,
/// plus the configuration and the carried state's commitment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkmAggrOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub tuples_root: [u8; HASH_BYTES_LEN],
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
    pub config: GkmConfig,
    /// Com(S_{e-1}); at genesis the empty state's commitment.
    pub prev_state_commit: [u8; HASH_BYTES_LEN],
    /// apply_batch2 steps this epoch: ceil(records / m_sub).
    pub steps: u32,
}

/// Phase marks (the guest reads its cycle counter at each; the order is the call order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    ChainVerified,
    EventsFlattened,
    CarriedChecked,
    Mapped,
    Updated,
    RootDone,
    CommitDone,
    LinkDone,
}
/// Profile column names of the marks, in order.
pub const MARK_NAMES: [&str; 8] = ["chain", "flatten", "carry", "map", "update", "root", "commit", "link"];

// ===========================================================================
// State encoding and commitment. zkSketch's state is `capacity` rows: the active tuples
// (a value-sorted prefix) padded with identical dummies (a circuit's fixed table). The
// zk-Analytics side stores, ships and hashes only what a zkVM program needs: the
// parameters, n and the active tuples (the COMPACT words). A canonical state and its
// compact words determine each other (pad with dummies to `capacity` / drop the dummy
// suffix), so this is the same state, not a summary of it.
// ===========================================================================

/// Domain tag of the state commitment, in their TAG_* naming (as ../../gk's).
const TAG_GKM_STATE_COMMIT: &[u8] = b"ZKTLM_GKM_STATE_COMMIT_V1";

/// Compact words: `bm2::state_to_words` of the state restricted to its active prefix
/// (header capacity, m_sub, s, n and the active count k, then k rows of 12 words).
pub fn compact_words(s: &State) -> Vec<u32> {
    bm2::state_to_words(&State { tuples: actives(s).to_vec(), params: s.params, n: s.n })
}

/// The canonical state of compact words: their k rows (all active, k <= capacity)
/// followed by `capacity - k` dummies.
pub fn from_compact_words(w: &[u32]) -> State {
    let mut s = bm2::state_from_words(w);
    assert!(s.tuples.len() <= s.params.capacity, "compact state has more rows than its capacity");
    assert!(s.tuples.iter().all(|t| t.active == 1), "compact state holds a non-active row");
    s.tuples.resize(s.params.capacity, Tuple::dummy());
    s
}

/// Unsalted SHA-256 over compact words: SHA-256(TAG || their little-endian bytes).
pub fn commit_words(w: &[u32]) -> [u8; HASH_BYTES_LEN] {
    let mut sha = Sha256::new();
    sha.update(TAG_GKM_STATE_COMMIT);
    sha.update(bytemuck::cast_slice::<u32, u8>(w));
    sha.finalize().into()
}

/// The state commitment (their pattern: one flat unsalted SHA-256 over the whole state).
pub fn gkm_state_commit(s: &State) -> [u8; HASH_BYTES_LEN] {
    commit_words(&compact_words(s))
}

pub fn process_gkm_aggr(input: &GkmAggrInput, root: GkmRoot) -> (State, GkmAggrOutput) {
    process_gkm_aggr_marked(input, root, &mut |_| {})
}

pub fn process_gkm_aggr_marked<F: FnMut(Mark)>(
    input: &GkmAggrInput,
    root: GkmRoot,
    mark: &mut F,
) -> (State, GkmAggrOutput) {
    // 1. Their batch-chain verification (verbatim copy above).
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

    // 2. Flatten batches to events for processing (as upstream does)
    let mut all_events: Vec<Event> = Vec::new();
    for batch in &input.batches {
        all_events.extend(batch.events.iter().cloned());
    }
    mark(Mark::EventsFlattened);

    // 3. The carried state S_{e-1}, bound to the previous epoch's journal: its
    //    commitment must reproduce that epoch's final_chain_hash, which is this
    //    epoch's prev_chain_hash.
    let cfg = input.config;
    cfg.validate();
    let params = cfg.params();
    let (s_prev, prev_state_commit) = match &input.carried {
        None => {
            assert!(
                input.prev_chain_hash == GENESIS,
                "no carried state, but prev_chain_hash is not the genesis hash"
            );
            let s = State::empty(params);
            let c = gkm_state_commit(&s);
            (s, c)
        }
        Some(c) => {
            let com = commit_words(&c.state_words);
            assert!(
                EpochChainLink::compute_final_hash(c.link_prev_hash, com) == input.prev_chain_hash,
                "carried state does not match the previous epoch's state_commit"
            );
            let s = from_compact_words(&c.state_words);
            assert!(s.params == params, "carried state's GK parameters differ from the configuration");
            (s, com)
        }
    };
    mark(Mark::CarriedChecked);

    // 4. zkSketch's gk_vals_of mapping of the records (PAD_KEY dropped, 21-bit mask).
    let values: Vec<u32> = all_events.iter().map(|ev| ev.value).collect();
    let vals = bm2::vals_of(&values);
    mark(Mark::Mapped);

    // 5. The summary update: ceil(|vals| / m_sub) zkSketch batch steps from S_{e-1}.
    let (state, steps) = apply_epoch(&cfg, s_prev, &vals);
    mark(Mark::Updated);

    let tuples_root = gkm_root(&state, root);
    mark(Mark::RootDone);

    let state_commit = gkm_state_commit(&state);
    mark(Mark::CommitDone);

    // Build epoch chain link: final_chain_hash = hash(TAG || prev || state_commit)
    let epoch_chain_link = EpochChainLink::new(input.prev_chain_hash, state_commit);
    mark(Mark::LinkDone);

    let out = GkmAggrOutput {
        epoch_chain_link,
        state_commit,
        tuples_root,
        n_events: all_events.len() as u64,
        final_source_chain_tips,
        config: cfg,
        prev_state_commit,
        steps,
    };
    (state, out)
}

// ===========================================================================
// Query guest logic (structure of run_histogram_query, querier/core/src/lib.rs:482-643).
// ===========================================================================

/// zkSketch's GK decoder estimator, `native_estimate` of src/decode/gk_bandmerge.rs
/// (the relation its decode circuit proves), over all `capacity` rows of the state:
///   k = #{rows with e <= q}, P = sum over those rows of (g + g° + 1),
///   r_min = P - (g°_{k-1} + Delta°_{k-1})  (0 at k = 0; saturating),
///   r_max = P + (g_k + Delta_k)             (+0 at k = capacity),
///   estimate = floor((r_min + r_max) / 2).
/// Dummies have e = E_MAX > q for every q < 2^21, so they never count.
/// Returns (r_min, r_max, estimate).
pub fn gkm_rank(s: &State, q: u32) -> (u64, u64, u64) {
    let tuples = &s.tuples;
    let cap = tuples.len();
    let mut k = 0usize;
    let mut p_i = 0u64;
    for t in tuples {
        if t.e <= q {
            k += 1;
            p_i += t.g + t.g_o + 1;
        }
    }
    let left = if k == 0 { 0 } else { tuples[k - 1].g_o + tuples[k - 1].delta_o };
    let right = if k == cap { 0 } else { tuples[k].g + tuples[k].delta };
    let r_min = p_i.saturating_sub(left);
    let r_max = p_i + right;
    (r_min, r_max, (r_min + r_max) / 2)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkmQueryInput {
    /// rank(value) = #{records with mapped value <= value}.
    pub value: u32,
    /// The latest epoch's state as compact words; it summarises every epoch.
    pub state_words: Vec<u32>,
    /// Epoch chain links (prev_chain_hash, state_commit, final_chain_hash) of every
    /// epoch, in order; the last one commits to `state_words`.
    pub epoch_chain_links: Vec<EpochChainLink>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkmRankResult {
    pub value: u32,
    /// floor((lo + hi) / 2), zkSketch's decoder answer.
    pub estimate: u64,
    /// r_min, r_max of zkSketch's decoder: certified bounds on the rank.
    pub lo: u64,
    pub hi: u64,
    pub total_count: u64,
}

/// Shaped like HistogramQueryOutput (querier/core/src/lib.rs:424-442), as ../../gk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkmQueryOutput {
    pub chain_prev_hash: [u8; 32],
    pub chain_final_hash: [u8; 32],
    pub state_commits: Vec<[u8; 32]>,
    pub result: GkmRankResult,
    /// Number of contributing records (N).
    pub support: u64,
    pub suppressed: bool,
}

impl GkmQueryOutput {
    /// Their LOW-SUPPORT rule (querier/core/src/lib.rs:21-34, 444-480): below
    /// MIN_SUPPORT, zero every numeric result field and set `suppressed`.
    pub fn suppress_if_low_support(mut self) -> Self {
        if self.support < MIN_SUPPORT {
            self.result =
                GkmRankResult { value: self.result.value, estimate: 0, lo: 0, hi: 0, total_count: 0 };
            self.support = 0;
            self.suppressed = true;
        }
        self
    }
}

pub fn run_gkm_query(input: &GkmQueryInput) -> GkmQueryOutput {
    // Verify epoch hash chain inside the proof (their verify_epoch_chain_integrity).
    assert!(!input.epoch_chain_links.is_empty(), "a query needs the chain links of at least one epoch");
    verify_epoch_chain_integrity(&input.epoch_chain_links);
    // Their check lets a link that starts at the genesis hash begin a new chain (one chain
    // per aggregator, each summary opened separately). Here the latest state summarises
    // every queried epoch only along ONE unbroken chain (each epoch's guest checked its
    // carried state against the previous link), so a restart is refused.
    for w in input.epoch_chain_links.windows(2) {
        assert!(
            w[1].prev_chain_hash == w[0].final_chain_hash,
            "epoch chain restarts: the latest carried state would not cover every queried epoch"
        );
    }
    let last = input.epoch_chain_links.last().unwrap();
    // The latest state hashes to the state_commit of the last link.
    let computed_commit = commit_words(&input.state_words);
    assert!(
        computed_commit == last.state_commit,
        "latest state_commit mismatch: computed != last chain link"
    );
    let chain_prev_hash = input.epoch_chain_links[0].prev_chain_hash;
    let chain_final_hash = last.final_chain_hash;
    let state_commits: Vec<[u8; 32]> = input.epoch_chain_links.iter().map(|link| link.state_commit).collect();

    let state = from_compact_words(&input.state_words);
    let (lo, hi, estimate) = gkm_rank(&state, input.value);
    GkmQueryOutput {
        chain_prev_hash,
        chain_final_hash,
        state_commits,
        result: GkmRankResult { value: input.value, estimate, lo, hi, total_count: state.n },
        support: state.n,
        suppressed: false,
    }
}
