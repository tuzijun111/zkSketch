//! Root variants of the aggregation journal (six-sketch comparison); compiled only with the `root` feature.

// The parent's imports come with the glob, its Sha256 and Digest trait included.
use super::*;

// ------------------------------------------------------------ root variants
//
// Every one of their aggregation modes publishes, next to the flat SHA-256 state commit
// that the epoch chain and the query guests use, a Merkle root over its state (samples
// buckets_root, histogram buckets_root, cm row_roots + cm_root + heap_root) that their host
// folds into an out_commit and that no query guest or verifier reads. The legacy port
// above builds none. The six-sketch comparison reports two consistent variants instead
// (../../README.md "Six-sketch comparison"), run by the bloom_aggr_root guest:
//   designed (BloomRoot::Buckets64)  zk-Analytics as designed, with the cheapest of their
//          root constructions applied uniformly to all five ports: their samples pattern at
//          their benchmark geometry SAMPLES_HT_BUCKETS = 64. The filter words are array
//          cells, so the cell -> bucket map is the fixed partition of the packed bitset into
//          64 contiguous groups of BLOOM_BYTES / 64 = 224 bytes (56 32-bit words, 1,792 filter
//          bits; bucket j = bytes [224 j, 224 (j+1))); leaf j = SHA-256(tag || those bytes in
//          index order); the 64 leaves are folded by their pub
//          samples_buckets_root_from_leaves (aggregator/core/src/lib.rs:381-391).
//   noroot   (BloomRoot::None)       no root, journal field zero: apples-to-apples with
//          zkSketch, which commits its state but publishes no per-bucket root.
// Both variants compute the same state, state commitment and epoch link as the legacy
// port; only `buckets_root` differs.

/// Buckets of the designed root: their benchmark SAMPLES_HT_BUCKETS (their
/// scripts/lib/common.sh:13), the geometry of the SpaceSaving port's headline root.
pub const ROOT_BUCKETS: usize = 64;
const _: () = assert!(BLOOM_BYTES % (4 * ROOT_BUCKETS) == 0, "the filter must split into equal whole-word buckets");

/// Bucket-leaf domain separator, cf. their TAG_BUCKET_LEAF (aggregator/core/src/lib.rs:44).
/// Ours (port prefix, as the SpaceSaving port's TAG_SS_BUCKET_LEAF).
const TAG_BLOOM_BUCKET_LEAF: &[u8] = b"ZKA_PORT_BLOOM_BUCKET_V1";

/// Which root the aggregation journal carries (read by the bloom_aggr_root guest before
/// its input, and committed with the journal).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BloomRoot {
    /// designed: 64-bucket samples-pattern root (see above).
    Buckets64,
    /// noroot: no root; `buckets_root` is zero.
    None,
}

impl BloomRoot {
    pub fn construction(self) -> &'static str {
        match self {
            BloomRoot::Buckets64 => "samples64",
            BloomRoot::None => "none",
        }
    }
}

/// The designed root over the packed filter (fixed partition into ROOT_BUCKETS contiguous
/// groups; every group is non-empty, so the samples pattern's next_pow2_ge(max bucket + 1)
/// is ROOT_BUCKETS leaves).
pub fn bloom_buckets_root(bits: &[u8]) -> [u8; HASH_BYTES_LEN] {
    let per = bits.len() / ROOT_BUCKETS;
    let leaves: Vec<[u8; HASH_BYTES_LEN]> = bits
        .chunks_exact(per)
        .map(|cells| {
            let mut sha = Sha256::new();
            sha.update(TAG_BLOOM_BUCKET_LEAF);
            sha.update(cells);
            let leaf: [u8; HASH_BYTES_LEN] = sha.finalize().into();
            leaf
        })
        .collect();
    aggregator_core::samples_buckets_root_from_leaves(&leaves)
}

pub fn bloom_root(bits: &[u8], root: BloomRoot) -> [u8; HASH_BYTES_LEN] {
    match root {
        BloomRoot::Buckets64 => bloom_buckets_root(bits),
        BloomRoot::None => [0u8; HASH_BYTES_LEN],
    }
}

/// Journal of the bloom_aggr_root guest (committed as `(BloomRoot, BloomAggrRootOutput)`):
/// field for field their SamplesAggrOutput (aggregator/core/src/lib.rs:276-293), i.e. the
/// legacy BloomAggrOutput plus `buckets_root` in their position.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BloomAggrRootOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub buckets_root: [u8; HASH_BYTES_LEN],
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

impl BloomAggrRootOutput {
    /// The journal without its root: what every variant must agree on.
    pub fn without_root(&self) -> BloomAggrOutput {
        BloomAggrOutput {
            epoch_chain_link: self.epoch_chain_link.clone(),
            state_commit: self.state_commit,
            n_events: self.n_events,
            final_source_chain_tips: self.final_source_chain_tips.clone(),
        }
    }
}

pub fn process_bloom_aggr_root(input: &BloomAggrInput, root: BloomRoot) -> (BloomEpochState, BloomAggrRootOutput) {
    process_bloom_aggr_root_probed(input, root, &mut || {})
}

/// The legacy aggregation, `process_bloom_aggr_probed` itself (unchanged, the code the
/// legacy guest runs: chain verification, flatten, update, state commitment + epoch link),
/// then the root over the committed state. Their samples flow computes the root right
/// before the state commitment (process_samples_aggr_with_state,
/// aggregator/core/src/lib.rs:669-672); the order does not change the work, and calling
/// the legacy function keeps the variants' aggregation code identical to the legacy
/// guest's (a separate copy of the same source compiled measurably differently).
/// `probe` is called after each phase (5 calls: chain, flatten, update, commit, root).
pub fn process_bloom_aggr_root_probed(
    input: &BloomAggrInput,
    root: BloomRoot,
    probe: &mut dyn FnMut(),
) -> (BloomEpochState, BloomAggrRootOutput) {
    let (state, out) = process_bloom_aggr_probed(input, probe);
    let buckets_root = bloom_root(&state.bits, root);
    probe(); // phase 5: Merkle root (designed) / nothing (noroot)
    let BloomAggrOutput { epoch_chain_link, state_commit, n_events, final_source_chain_tips } = out;
    let out = BloomAggrRootOutput { epoch_chain_link, state_commit, buckets_root, n_events, final_source_chain_tips };
    (state, out)
}
