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
// (../../README.md "Six-sketch comparison"), run by the kmv_aggr_root guest:
//   designed (KmvRoot::Buckets64)  zk-Analytics as designed, with the cheapest of their root
//          constructions applied uniformly to all five ports: their samples pattern at their
//          benchmark geometry SAMPLES_HT_BUCKETS = 64, step for step as the SpaceSaving
//          port's headline root. The held values are KEYED cells (like samples entries), so
//          the cell -> bucket map is the mixing of their samples_bucket_index applied to the
//          value (`kmv_bucket_index`); number of leaves = next_pow2_ge(max bucket + 1); leaf =
//          SHA-256(tag || the bucket's values ascending, big-endian); the leaves are folded by
//          their pub samples_buckets_root_from_leaves (aggregator/core/src/lib.rs:381-391).
//   noroot   (KmvRoot::None)       no root, journal field zero: apples-to-apples with
//          zkSketch, which commits its state but publishes no per-bucket root.
// Both variants compute the same state, state commitment and epoch link as the legacy
// port; only `buckets_root` differs.

/// Buckets of the designed root: their benchmark SAMPLES_HT_BUCKETS (their
/// scripts/lib/common.sh:13), the geometry of the SpaceSaving port's headline root.
pub const ROOT_BUCKETS: usize = 64;

/// Bucket-leaf domain separator, cf. their TAG_BUCKET_LEAF (aggregator/core/src/lib.rs:44).
/// Ours (port prefix, as the SpaceSaving port's TAG_SS_BUCKET_LEAF).
const TAG_KMV_BUCKET_LEAF: &[u8] = b"ZKA_PORT_KMV_BUCKET_V1";

/// Which root the aggregation journal carries (read by the kmv_aggr_root guest before its
/// input, and committed with the journal).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KmvRoot {
    /// designed: 64-bucket samples-pattern root (see above).
    Buckets64,
    /// noroot: no root; `buckets_root` is zero.
    None,
}

impl KmvRoot {
    pub fn construction(self) -> &'static str {
        match self {
            KmvRoot::Buckets64 => "samples64",
            KmvRoot::None => "none",
        }
    }
}

/// Bucket of a held value: their samples_bucket_index (aggregator/core/src/lib.rs:352-361),
/// the murmur3 fmix64 finaliser then `& (buckets - 1)`, applied to the value itself. A value
/// already is a 64-bit key hash, so it takes the place of their `key_to_u64(key_id)` fold.
#[inline]
pub fn kmv_bucket_index(v: u64) -> usize {
    // Deterministic mixing then mod 64.
    let mut x = v;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    (x as usize) & (ROOT_BUCKETS - 1)
}

/// The designed root: the pattern of their samples_buckets_leaves + samples_bucket_leaf_hash
/// + samples_buckets_root (aggregator/core/src/lib.rs:363-422), step for step, with the
/// held values as the entries (as ../../spacesaving's ss_buckets_root does for its counters).
pub fn kmv_buckets_root(values: &[u64]) -> [u8; HASH_BYTES_LEN] {
    // Find actual number of buckets needed (max bucket index + 1, rounded to pow2;
    // their next_pow2_ge, which equals usize::next_power_of_two for arguments >= 1)
    let max_bucket = values.iter().map(|&v| kmv_bucket_index(v)).max().unwrap_or(0);
    let num_buckets = (max_bucket + 1).next_power_of_two();

    // Group values by bucket index
    let mut bucket_values: Vec<Vec<u64>> = (0..num_buckets).map(|_| Vec::new()).collect();
    for &v in values {
        bucket_values[kmv_bucket_index(v)].push(v);
    }

    // Compute leaf hash for each bucket
    let leaves: Vec<[u8; HASH_BYTES_LEN]> = bucket_values
        .iter()
        .map(|b| {
            // Hash values in sorted order for determinism
            let mut sorted = b.clone();
            sorted.sort();
            let mut sha = Sha256::new();
            sha.update(TAG_KMV_BUCKET_LEAF);
            for v in &sorted {
                sha.update(&v.to_be_bytes());
            }
            let leaf: [u8; HASH_BYTES_LEN] = sha.finalize().into();
            leaf
        })
        .collect();
    aggregator_core::samples_buckets_root_from_leaves(&leaves)
}

pub fn kmv_root(values: &[u64], root: KmvRoot) -> [u8; HASH_BYTES_LEN] {
    match root {
        KmvRoot::Buckets64 => kmv_buckets_root(values),
        KmvRoot::None => [0u8; HASH_BYTES_LEN],
    }
}

/// Journal of the kmv_aggr_root guest (committed as `(KmvRoot, KmvAggrRootOutput)`): field
/// for field their SamplesAggrOutput (aggregator/core/src/lib.rs:276-293), i.e. the legacy
/// KmvAggrOutput plus `buckets_root` in their position.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmvAggrRootOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub buckets_root: [u8; HASH_BYTES_LEN],
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

impl KmvAggrRootOutput {
    /// The journal without its root: what every variant must agree on.
    pub fn without_root(&self) -> KmvAggrOutput {
        KmvAggrOutput {
            epoch_chain_link: self.epoch_chain_link.clone(),
            state_commit: self.state_commit,
            n_events: self.n_events,
            final_source_chain_tips: self.final_source_chain_tips.clone(),
        }
    }
}

pub fn process_kmv_aggr_root(input: &KmvAggrInput, root: KmvRoot) -> (KmvEpochState, KmvAggrRootOutput) {
    process_kmv_aggr_root_probed(input, root, &mut || {})
}

/// The legacy aggregation, `process_kmv_aggr_probed` itself (unchanged, the code the
/// legacy guest runs: chain verification, flatten, update, state commitment + epoch link),
/// then the root over the committed state. Their samples flow computes the root right
/// before the state commitment (process_samples_aggr_with_state,
/// aggregator/core/src/lib.rs:669-672); the order does not change the work, and calling
/// the legacy function keeps the variants' aggregation code identical to the legacy
/// guest's (a separate copy of the same source compiled measurably differently).
/// `probe` is called after each phase (5 calls: chain, flatten, update, commit, root).
pub fn process_kmv_aggr_root_probed(
    input: &KmvAggrInput,
    root: KmvRoot,
    probe: &mut dyn FnMut(),
) -> (KmvEpochState, KmvAggrRootOutput) {
    let (state, out) = process_kmv_aggr_probed(input, probe);
    let buckets_root = kmv_root(&state.values, root);
    probe(); // phase 5: Merkle root (designed) / nothing (noroot)
    let KmvAggrOutput { epoch_chain_link, state_commit, n_events, final_source_chain_tips } = out;
    let out = KmvAggrRootOutput { epoch_chain_link, state_commit, buckets_root, n_events, final_source_chain_tips };
    (state, out)
}
