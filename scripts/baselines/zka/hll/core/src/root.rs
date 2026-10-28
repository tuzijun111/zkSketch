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
// (../../README.md "Six-sketch comparison"), run by the hll_aggr_root guest:
//   designed (HllRoot::Buckets64)  zk-Analytics as designed, with the cheapest of their
//          root constructions applied uniformly to all five ports: their samples pattern at
//          their benchmark geometry SAMPLES_HT_BUCKETS = 64. The 2^14 registers are array
//          cells, so the cell -> bucket map is the fixed partition into 64 contiguous groups
//          of 256 registers (bucket j = registers [256 j, 256 (j+1))); leaf j = SHA-256(tag ||
//          those 256 register bytes in index order); the 64 leaves are folded by their pub
//          samples_buckets_root_from_leaves (aggregator/core/src/lib.rs:381-391).
//   noroot   (HllRoot::None)       no root, journal field zero: apples-to-apples with
//          zkSketch, which commits its state but publishes no per-bucket root.
// Both variants compute the same state, state commitment and epoch link as the legacy
// port; only `buckets_root` differs.

/// Buckets of the designed root: their benchmark SAMPLES_HT_BUCKETS (their
/// scripts/lib/common.sh:13), the geometry of the SpaceSaving port's headline root.
pub const ROOT_BUCKETS: usize = 64;
const _: () = assert!(HLL_M % ROOT_BUCKETS == 0, "registers must split into equal buckets");

/// Bucket-leaf domain separator, cf. their TAG_BUCKET_LEAF (aggregator/core/src/lib.rs:44).
/// Ours (port prefix, as the SpaceSaving port's TAG_SS_BUCKET_LEAF).
const TAG_HLL_BUCKET_LEAF: &[u8] = b"ZKA_PORT_HLL_BUCKET_V1";

/// Which root the aggregation journal carries (read by the hll_aggr_root guest before its
/// input, and committed with the journal).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HllRoot {
    /// designed: 64-bucket samples-pattern root (see above).
    Buckets64,
    /// noroot: no root; `buckets_root` is zero.
    None,
}

impl HllRoot {
    pub fn construction(self) -> &'static str {
        match self {
            HllRoot::Buckets64 => "samples64",
            HllRoot::None => "none",
        }
    }
}

/// The designed root over the registers (fixed partition into ROOT_BUCKETS contiguous
/// groups; every group is non-empty, so the samples pattern's next_pow2_ge(max bucket + 1)
/// is ROOT_BUCKETS leaves).
pub fn hll_buckets_root(registers: &[u8]) -> [u8; HASH_BYTES_LEN] {
    let per = registers.len() / ROOT_BUCKETS;
    let leaves: Vec<[u8; HASH_BYTES_LEN]> = registers
        .chunks_exact(per)
        .map(|cells| {
            let mut sha = Sha256::new();
            sha.update(TAG_HLL_BUCKET_LEAF);
            sha.update(cells);
            let leaf: [u8; HASH_BYTES_LEN] = sha.finalize().into();
            leaf
        })
        .collect();
    aggregator_core::samples_buckets_root_from_leaves(&leaves)
}

pub fn hll_root(registers: &[u8], root: HllRoot) -> [u8; HASH_BYTES_LEN] {
    match root {
        HllRoot::Buckets64 => hll_buckets_root(registers),
        HllRoot::None => [0u8; HASH_BYTES_LEN],
    }
}

/// Journal of the hll_aggr_root guest (committed as `(HllRoot, HllAggrRootOutput)`):
/// field for field their SamplesAggrOutput (aggregator/core/src/lib.rs:276-293), i.e. the
/// legacy HllAggrOutput plus `buckets_root` in their position.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HllAggrRootOutput {
    pub epoch_chain_link: EpochChainLink,
    pub state_commit: [u8; HASH_BYTES_LEN],
    pub buckets_root: [u8; HASH_BYTES_LEN],
    pub n_events: u64,
    pub final_source_chain_tips: Vec<(u32, u64, [u8; HASH_BYTES_LEN])>,
}

impl HllAggrRootOutput {
    /// The journal without its root: what every variant must agree on.
    pub fn without_root(&self) -> HllAggrOutput {
        HllAggrOutput {
            epoch_chain_link: self.epoch_chain_link.clone(),
            state_commit: self.state_commit,
            n_events: self.n_events,
            final_source_chain_tips: self.final_source_chain_tips.clone(),
        }
    }
}

pub fn process_hll_aggr_root(input: &HllAggrInput, root: HllRoot) -> (HllEpochState, HllAggrRootOutput) {
    process_hll_aggr_root_probed(input, root, &mut || {})
}

/// The legacy aggregation, `process_hll_aggr_probed` itself (unchanged, the code the
/// legacy guest runs: chain verification, flatten, update, state commitment + epoch link),
/// then the root over the committed state. Their samples flow computes the root right
/// before the state commitment (process_samples_aggr_with_state,
/// aggregator/core/src/lib.rs:669-672); the order does not change the work, and calling
/// the legacy function keeps the variants' aggregation code identical to the legacy
/// guest's (a separate copy of the same source compiled measurably differently).
/// `probe` is called after each phase (5 calls: chain, flatten, update, commit, root).
pub fn process_hll_aggr_root_probed(
    input: &HllAggrInput,
    root: HllRoot,
    probe: &mut dyn FnMut(),
) -> (HllEpochState, HllAggrRootOutput) {
    let (state, out) = process_hll_aggr_probed(input, probe);
    let buckets_root = hll_root(&state.registers, root);
    probe(); // phase 5: Merkle root (designed) / nothing (noroot)
    let HllAggrOutput { epoch_chain_link, state_commit, n_events, final_source_chain_tips } = out;
    let out = HllAggrRootOutput { epoch_chain_link, state_commit, buckets_root, n_events, final_source_chain_tips };
    (state, out)
}
