//! Root variants of the aggregation journal (compiled with the `root` feature).

// The parent's imports come with the glob, its Sha256 and Digest trait included.
use super::*;

// ===========================================================================
// Root variants (six-sketch comparison, ../../README.md "Six-sketch comparison").
//
// Every upstream aggregation journal carries, next to the flat SHA-256 state commit that
// the epoch chain and the query guests use, a Merkle root over the state that no query
// guest or verifier reads. aggr_gk (the guest of the committed 2026-10-09 reference rows,
// `legacy`) builds the per-tuple root above (their histogram pattern). The comparison now
// reports two variants that are consistent across all five ports, run by the aggr_gk_root
// guest (journal = (GkRoot, GkAggrOutput), `tuples_root` holding the selected root):
//   designed (GkRoot::Buckets64)  zk-Analytics as designed, with the cheapest of their root
//          constructions applied uniformly to all five ports: their samples pattern at their
//          benchmark geometry SAMPLES_HT_BUCKETS = 64. The tuples are ARRAY cells (a
//          value-ordered list), so the cell -> bucket map is the fixed partition of the n
//          tuples into 64 contiguous groups, tuple i -> bucket i * 64 / n; number of leaves =
//          next_pow2_ge(max bucket + 1) (64 once n >= 2); leaf j = SHA-256(tag || the group's
//          tuples (v, g, delta big-endian) in index order); the leaves are folded by their pub
//          samples_buckets_root_from_leaves (aggregator/core/src/lib.rs:381-391).
//   noroot   (GkRoot::None)       no root, `tuples_root` zero: apples-to-apples with
//          zkSketch, which commits its state but publishes no per-bucket root.
//   pertuple (GkRoot::PerTuple)   SENSITIVITY: gk_tuples_root, the legacy construction, in
//          the same guest.
// Every variant computes the same state, state commitment and epoch link.
// ===========================================================================

/// Buckets of the designed root: their benchmark SAMPLES_HT_BUCKETS (their
/// scripts/lib/common.sh:13), the geometry of the SpaceSaving port's headline root.
pub const ROOT_BUCKETS: usize = 64;

/// Bucket-leaf domain separator, cf. their TAG_BUCKET_LEAF (aggregator/core/src/lib.rs:44).
const TAG_GK_BUCKET_LEAF: &[u8] = b"ZKA_PORT_GK_BUCKET_V1";

/// Which root the aggr_gk_root journal carries (read before the input, committed with it).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GkRoot {
    /// designed: 64-bucket samples-pattern root (see above).
    Buckets64,
    /// noroot: no root; `tuples_root` is zero.
    None,
    /// sensitivity: the per-tuple root of the legacy aggr_gk (gk_tuples_root).
    PerTuple,
}

impl GkRoot {
    pub fn construction(self) -> &'static str {
        match self {
            GkRoot::Buckets64 => "samples64",
            GkRoot::None => "none",
            GkRoot::PerTuple => "pertuple",
        }
    }
}

/// The designed root over the tuples (fixed partition into ROOT_BUCKETS contiguous groups;
/// the groups are consecutive runs of the tuple list, so one pass hashes them in order).
pub fn gk_buckets_root(tuples: &[GkTuple]) -> [u8; HASH_BYTES_LEN] {
    let n = tuples.len();
    // Find actual number of buckets needed (max bucket index + 1, rounded to pow2)
    let max_bucket = if n == 0 { 0 } else { (n - 1) * ROOT_BUCKETS / n };
    let num_buckets = next_pow2_ge(max_bucket + 1);
    let mut leaves: Vec<[u8; HASH_BYTES_LEN]> = Vec::with_capacity(num_buckets);
    let mut i = 0usize;
    for j in 0..num_buckets {
        let mut sha = Sha256::new();
        sha.update(TAG_GK_BUCKET_LEAF);
        while i < n && i * ROOT_BUCKETS / n == j {
            let t = &tuples[i];
            sha.update(&t.v.to_be_bytes());
            sha.update(&t.g.to_be_bytes());
            sha.update(&t.delta.to_be_bytes());
            i += 1;
        }
        leaves.push(sha.finalize().into());
    }
    aggregator_core::samples_buckets_root_from_leaves(&leaves)
}

pub fn gk_root(tuples: &[GkTuple], root: GkRoot) -> [u8; HASH_BYTES_LEN] {
    match root {
        GkRoot::Buckets64 => gk_buckets_root(tuples),
        GkRoot::None => [0u8; HASH_BYTES_LEN],
        GkRoot::PerTuple => gk_tuples_root(tuples),
    }
}

pub fn process_gk_aggr_root(input: &GkAggrInput, root: GkRoot) -> (GkEpochState, GkAggrOutput) {
    process_gk_aggr_root_marked(input, root, &mut |_| {})
}

/// process_gk_aggr_marked with the root construction chosen by `root` (same phases, same
/// marks; the root step sits where their samples flow computes it, before the commitment).
pub fn process_gk_aggr_root_marked<F: FnMut(Mark)>(
    input: &GkAggrInput,
    root: GkRoot,
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

    let tuples_root = gk_root(&state.tuples, root);
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
