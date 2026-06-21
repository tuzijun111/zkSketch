//! **E5 — composition ladder** (EVAL_SPEC §2 E5). The composition story's
//! headline: as you climb the ladder, the *auditor's* cost falls from `Θ(E)` to
//! `O(1)` while the prover's online merge cost stays amortised `O(1)`.
//!
//! Four settings over an audit window of `E` epochs:
//! - `no_composition` — every epoch is an independent proof; the auditor must
//!   re-verify all `E` of them (`verifier_checks = E`, no online merges).
//! - `per_batch_chain` — each batch links to the previous; the auditor still
//!   walks the whole `E`-long boundary chain (`verifier_checks = E`), but the
//!   prover does one `merge_atom` per insert.
//! - `recursive_linear` — the linear chain is folded into a single root
//!   ([`compose_chain`]); the auditor checks **one** root digest
//!   (`verifier_checks = 1`).
//! - `streaming_forest` — the MMR forest ([`StreamingForest`]); amortised
//!   `O(1)` online merges (`< 1` per insert), worst-case `⌈log₂E⌉` cascade, and
//!   the finalised root is **one** digest (`verifier_checks = 1`).
//!
//! **Leaf-shape-agnostic** (the paper states composition is): we drive it with
//! cheap synthetic, boundary-consistent epoch leaves to reach larger windows.
//!
//! **Honest caveat (option (i)).** This prototype has no in-circuit recursive
//! verifier (Phase 1.5), so a "merge"/"root check" is a Poseidon2 boundary
//! digest, **not** a full recursive-SNARK fold. The `verifier_checks` /
//! `root_proof_bytes` columns therefore report the **composition-layer**
//! structure (`Θ(E)→O(1)`); the absolute byte/ms numbers are the lightweight
//! digest cost, not STARK-proof sizes. The structural collapse is the signal.

use std::hint::black_box;

use p3_field::PrimeCharacteristicRing;

use crate::config::Val;
use crate::recursion::framework::{
    EpochLeaf, IntervalProof, StreamingForest, compose_chain, epoch_leaf_digest, root_commitment,
    verify_epoch_chain,
};

use super::metrics::{bench, read_vmrss_kb, BenchCfg, RunOutcome};
use super::time_it;

// ── Composition-layer artifact sizes (BabyBear canonical = 4 bytes/elt) ──────
const VAL_BYTES: u64 = 4;
const COMMIT_BYTES: u64 = 8 * VAL_BYTES; // [Val; 8]
const DIGEST_BYTES: u64 = 4 * VAL_BYTES; // ChainDigest = [Val; 4]
/// `EpochLeaf` = index(8) + com_before + com_after + batch_commit + descriptor(8).
const EPOCH_LEAF_BYTES: u64 = 8 + 3 * COMMIT_BYTES + 8;
/// `IntervalProof` = lo(8) + hi(8) + com_before + com_after + digest.
const INTERVAL_PROOF_BYTES: u64 = 8 + 8 + 2 * COMMIT_BYTES + DIGEST_BYTES;

/// The four rungs of the composition ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    NoComposition,
    PerBatchChain,
    RecursiveLinear,
    StreamingForest,
}

impl Setting {
    pub const ALL: [Setting; 4] = [
        Setting::NoComposition,
        Setting::PerBatchChain,
        Setting::RecursiveLinear,
        Setting::StreamingForest,
    ];
    pub fn name(&self) -> &'static str {
        match self {
            Setting::NoComposition => "no_composition",
            Setting::PerBatchChain => "per_batch_chain",
            Setting::RecursiveLinear => "recursive_linear",
            Setting::StreamingForest => "streaming_forest",
        }
    }
}

/// One measured ladder row (matches the E5 CSV schema).
#[derive(Clone, Debug)]
pub struct E5Row {
    pub setting: &'static str,
    pub e: u64,
    pub prover_compositions_per_insert: f64,
    pub worst_case_cascade: u64,
    pub verifier_checks: u64,
    pub verify_ms_median: f64,
    pub root_proof_bytes: u64,
    pub peak_rss_mb_median: f64,
}

impl E5Row {
    pub fn header() -> Vec<&'static str> {
        vec![
            "setting",
            "E",
            "prover_compositions_per_insert",
            "worst_case_cascade",
            "verifier_checks",
            "verify_ms_median",
            "root_proof_size_bytes",
            "peak_rss_mb_median",
            "status",
        ]
    }
    pub fn fields(&self) -> Vec<String> {
        vec![
            self.setting.into(),
            self.e.to_string(),
            format!("{:.4}", self.prover_compositions_per_insert),
            self.worst_case_cascade.to_string(),
            self.verifier_checks.to_string(),
            format!("{:.4}", self.verify_ms_median),
            self.root_proof_bytes.to_string(),
            format!("{:.1}", self.peak_rss_mb_median),
            "ok".into(),
        ]
    }
}

/// Synthesise a contiguous, boundary-consistent epoch chain of length `e`.
pub fn synth_chain(e: u64) -> Vec<EpochLeaf> {
    let commit = |x: u64| -> [Val; 8] {
        let mut c = [Val::ZERO; 8];
        for (lane, slot) in c.iter_mut().enumerate() {
            *slot = Val::from_u64(x.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(lane as u64));
        }
        c
    };
    (1..=e)
        .map(|i| EpochLeaf::new(i, commit(i - 1), commit(i), commit(0xB000 + i), i))
        .collect()
}

/// Prover-side online merge counts for the streaming forest: amortised merges
/// per insert and the worst single-insert cascade.
fn forest_merge_stats(leaves: &[EpochLeaf]) -> (f64, u64) {
    if leaves.is_empty() {
        return (0.0, 0);
    }
    let mut forest = StreamingForest::new();
    let mut total = 0u64;
    let mut worst = 0u64;
    for leaf in leaves {
        let before = forest.num_trees() as u64;
        forest.insert(leaf).expect("forest insert");
        let merges = before + 1 - forest.num_trees() as u64;
        total += merges;
        worst = worst.max(merges);
    }
    (total as f64 / leaves.len() as f64, worst)
}

/// The prover-side fold (run **once**, not per-insert): for the composed
/// settings it produces the single root the auditor will re-check. Returns
/// `None` for the uncomposed settings (the auditor works over the leaves).
fn prover_root(setting: Setting, leaves: &[EpochLeaf]) -> Option<IntervalProof> {
    match setting {
        Setting::NoComposition | Setting::PerBatchChain => None,
        Setting::RecursiveLinear => Some(compose_chain(leaves).expect("compose chain")),
        Setting::StreamingForest => {
            let mut forest = StreamingForest::new();
            for l in leaves {
                forest.insert(l).expect("insert");
            }
            Some(forest.finalize().expect("finalize"))
        }
    }
}

/// Run the **auditor's** verification appropriate to `setting` — and only the
/// auditor's: for composed settings the prover's fold is already done
/// ([`prover_root`]), so the auditor just re-checks the `O(1)` root digest.
/// Returns the number of digest/proof checks performed.
fn audit(setting: Setting, leaves: &[EpochLeaf], root: &Option<IntervalProof>) -> u64 {
    match setting {
        // Re-verify each epoch independently: E self-digests.
        Setting::NoComposition => {
            for l in leaves {
                let _ = black_box(epoch_leaf_digest(l));
            }
            leaves.len() as u64
        }
        // Verify each epoch proof AND walk the boundary chain: Θ(E), strictly
        // more than no_composition (the chain adds order-binding link checks but
        // gives the auditor no speedup — that only arrives with a folded root).
        Setting::PerBatchChain => {
            for l in leaves {
                let _ = black_box(epoch_leaf_digest(l));
            }
            verify_epoch_chain(leaves, 1).expect("chain verifies");
            leaves.len() as u64
        }
        // Re-check the single composed root: O(1), independent of E.
        Setting::RecursiveLinear | Setting::StreamingForest => {
            let r = root.as_ref().expect("composed root");
            let _ = black_box(root_commitment(r));
            1
        }
    }
}

/// Measure one `(setting, E)` ladder cell.
pub fn measure(setting: Setting, e: u64, cfg: BenchCfg) -> E5Row {
    let leaves = synth_chain(e);

    let (compositions_per_insert, worst_case_cascade) = match setting {
        Setting::NoComposition => (0.0, 0),
        Setting::PerBatchChain => (1.0, 1),
        Setting::RecursiveLinear => (1.0, 1),
        Setting::StreamingForest => forest_merge_stats(&leaves),
    };

    let root_proof_bytes = match setting {
        // Auditor must hold all E leaf artifacts (no compression).
        Setting::NoComposition | Setting::PerBatchChain => e * EPOCH_LEAF_BYTES,
        // One root.
        Setting::RecursiveLinear | Setting::StreamingForest => INTERVAL_PROOF_BYTES,
    };

    // The prover folds once up-front (untimed — its cost is the merge *count*
    // above); the auditor then re-checks only the root. Bench measures the
    // auditor's verify path: O(E) for the uncomposed settings, O(1) for the
    // composed ones.
    let root = prover_root(setting, &leaves);
    let mut verifier_checks = 0u64;
    let agg = bench(cfg, || {
        let (checks, dt) = time_it(|| audit(setting, &leaves, &root));
        verifier_checks = checks;
        RunOutcome {
            witness_gen: std::time::Duration::ZERO,
            prove: std::time::Duration::ZERO,
            verify: dt,
            proof_size_bytes: root_proof_bytes,
            trace_rows: 0,
            num_columns: 0,
        }
    });

    // Sub-ms verify work may leave the RSS sampler with no sample → fall back to
    // a direct read so the column is never a misleading 0.0.
    let peak = if agg.peak_rss_mb_median > 0.0 {
        agg.peak_rss_mb_median
    } else {
        read_vmrss_kb().map(|k| k as f64 / 1024.0).unwrap_or(0.0)
    };

    E5Row {
        setting: setting.name(),
        e,
        prover_compositions_per_insert: compositions_per_insert,
        worst_case_cascade,
        verifier_checks,
        verify_ms_median: agg.verify_ms_median,
        root_proof_bytes,
        peak_rss_mb_median: peak,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quick() -> BenchCfg {
        BenchCfg { warmup: 0, trials: 1 }
    }

    #[test]
    fn verifier_checks_collapse_from_e_to_one() {
        let e = 64;
        let no = measure(Setting::NoComposition, e, quick());
        let chain = measure(Setting::PerBatchChain, e, quick());
        let rec = measure(Setting::RecursiveLinear, e, quick());
        let forest = measure(Setting::StreamingForest, e, quick());
        // Θ(E) auditors.
        assert_eq!(no.verifier_checks, e);
        assert_eq!(chain.verifier_checks, e);
        // O(1) auditors.
        assert_eq!(rec.verifier_checks, 1);
        assert_eq!(forest.verifier_checks, 1);
    }

    #[test]
    fn forest_amortised_under_one_and_worst_is_log() {
        let e = 256u64;
        let row = measure(Setting::StreamingForest, e, quick());
        assert!(
            row.prover_compositions_per_insert < 1.0,
            "amortised merges < 1: {}",
            row.prover_compositions_per_insert
        );
        assert!(row.worst_case_cascade <= (e as f64).log2().ceil() as u64 + 1);
    }

    #[test]
    fn root_artifact_collapses_to_o1() {
        let e = 1024u64;
        let chain = measure(Setting::PerBatchChain, e, quick());
        let rec = measure(Setting::RecursiveLinear, e, quick());
        // Θ(E) artifact vs O(1) artifact.
        assert!(chain.root_proof_bytes > rec.root_proof_bytes * 100);
        assert_eq!(rec.root_proof_bytes, INTERVAL_PROOF_BYTES);
    }
}
