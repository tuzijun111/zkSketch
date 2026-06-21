//! **Input-commitment + history-fold over real batches** — the end-to-end tie
//! between the *input commitment* and the *history root* that E5/E6 (which
//! measure only the composition layer, over synthetic leaves) do not exercise.
//!
//! For a stream of `n` real batches it: (1) proves each transition with the real
//! per-family leaf circuit, which **binds the batch's records to `Com(B_t)`** in
//! circuit (the §5 S1 step) — its prove time is the *input-binding* cost; and
//! (2) folds the resulting **real** `Com(B_t)` (carried in each `EpochLeaf`) into
//! a single history root `R(t)` via the §4 streaming forest — its merge count is
//! the *fold* cost. A soundness check confirms that tampering one real
//! `Com(B_t)` changes `R(t)` (so the root binds the committed inputs).
//!
//! This is `Count-Min` in the library helper + test (always-on, fast); the
//! runner `examples/exp_inputfold.rs` does all four families.

use crate::config::Val;
use crate::recursion::digest::ChainDigest;
use crate::recursion::framework::{root_commitment, EpochLeaf, StreamingForest};

use super::families::{cm_empty, cm_epoch, EpochOutcome};
use crate::sketch::countmin_final::CountMinFinalParams;

/// `IntervalProof` composition-layer size (BabyBear = 4 bytes/elt).
pub const INTERVAL_PROOF_BYTES: u64 = 96;

/// Per-batch ingest record: the cost of binding this batch's records to its
/// input commitment `Com(B_t)` (the leaf prove) plus the proof it produced.
#[derive(Clone, Debug)]
pub struct IngestRow {
    pub batch_index: u64,
    pub input_records: usize,
    pub leaf_prove_ms: f64,
    pub proof_bytes: usize,
    /// `true` iff the leaf's committed final state matches the native update —
    /// i.e. the real `Com(B_t)`/`Com(S_t)` binding verified.
    pub correct: bool,
}

/// Result of folding the real per-batch commitments into one history root.
#[derive(Clone, Debug)]
pub struct FoldSummary {
    pub n_batches: u64,
    pub total_merges: u64,
    pub worst_cascade: u64,
    pub verifier_checks: u64,
    pub root_proof_bytes: u64,
}

/// Build an `EpochLeaf` (the §4 boundary record, carrying the real `Com(B_t)`)
/// from a proved epoch outcome.
pub fn leaf_of(index: u64, o: &EpochOutcome) -> EpochLeaf {
    EpochLeaf::new(index, o.com_before, o.com_after, o.batch_commit, index)
}

/// The input-binding row for a proved epoch (any family).
pub fn row_of(index: u64, o: &EpochOutcome, input_records: usize) -> IngestRow {
    IngestRow {
        batch_index: index,
        input_records,
        leaf_prove_ms: o.prove_ms(),
        proof_bytes: o.proof_bytes,
        correct: o.correct,
    }
}

/// Deterministic batch of `m` keys using exactly `distinct` distinct values,
/// salted by `salt` so different epochs touch different keys.
fn cm_keys(m: usize, distinct: usize, salt: usize) -> Vec<u32> {
    (0..m)
        .map(|j| (((salt * distinct + (j % distinct)) as u64 + 1).wrapping_mul(0x9E37_79B9) as u32) | 1)
        .collect()
}

/// Ingest `n` real Count-Min batches, threading the state, returning the
/// per-batch input-binding rows and the boundary leaves (carrying real
/// `Com(B_t)`).
pub fn ingest_cm(params: CountMinFinalParams, n: u64) -> (Vec<IngestRow>, Vec<EpochLeaf>) {
    let distinct = params.distinct_bound.min(params.batch);
    let mut state = cm_empty(params.d, params.w);
    let mut rows = Vec::new();
    let mut leaves = Vec::new();
    for i in 1..=n {
        let keys = cm_keys(params.batch, distinct, i as usize);
        let (o, next) = cm_epoch(params, &state, &keys);
        rows.push(IngestRow {
            batch_index: i,
            input_records: params.batch,
            leaf_prove_ms: o.prove_ms(),
            proof_bytes: o.proof_bytes,
            correct: o.correct,
        });
        leaves.push(leaf_of(i, &o));
        state = next;
    }
    (rows, leaves)
}

/// Fold the real per-batch commitments into a single history root via the
/// streaming forest, returning the fold cost and the root `R(t)`.
pub fn fold(leaves: &[EpochLeaf]) -> (FoldSummary, ChainDigest) {
    let mut forest = StreamingForest::new();
    let (mut total, mut worst) = (0u64, 0u64);
    for l in leaves {
        let before = forest.num_trees() as u64;
        forest.insert(l).expect("forest insert (real boundary-consistent leaves)");
        let merges = before + 1 - forest.num_trees() as u64;
        total += merges;
        worst = worst.max(merges);
    }
    let root = forest.finalize().expect("finalize");
    let summary = FoldSummary {
        n_batches: leaves.len() as u64,
        total_merges: total,
        worst_cascade: worst,
        verifier_checks: 1, // one finalized root
        root_proof_bytes: INTERVAL_PROOF_BYTES,
    };
    (summary, root_commitment(&root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn real_batch_commitments_bind_and_fold_into_root() {
        let params = CountMinFinalParams { d: 2, w: 4, batch: 4, distinct_bound: 4 };
        let (rows, leaves) = ingest_cm(params, 4);
        // Every real batch's records were bound to Com(B_t) and the transition
        // verified (the leaf self-verifies its STARK; `correct` checks the commit).
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|r| r.correct), "each real batch input commitment must bind");
        assert!(rows.iter().all(|r| r.proof_bytes > 0 && r.leaf_prove_ms > 0.0));

        // The real Com(B_t) fold to one root, deterministically.
        let (summary, root) = fold(&leaves);
        assert_eq!(summary.n_batches, 4);
        assert_eq!(summary.verifier_checks, 1);
        let (_, root2) = fold(&leaves);
        assert_eq!(root, root2, "fold is deterministic");

        // Soundness: tampering one *real* batch commitment changes R(t).
        let mut bad = leaves.clone();
        bad[1].batch_commit = [Val::from_u64(0xBADBEEF); 8];
        let (_, bad_root) = fold(&bad);
        assert_ne!(root, bad_root, "tampering a real Com(B_t) must change R(t)");
    }
}
