//! **E6 — streaming forest: cores × batch size** (EVAL_SPEC §2 E6). The
//! parallel-ingest story: a streaming forest proves independent epoch leaves in
//! parallel (the `t/k` term of the work–depth `O(t/k + log t)`), then folds them
//! with `O(log t)` cheap merges.
//!
//! Unlike E5 (leaf-shape-agnostic, synthetic leaves), E6 must measure **real
//! proving** to expose core scaling — the §4 composition merges are a handful of
//! single-threaded Poseidon2 hashes and don't parallelise, so the only thing the
//! core count moves is leaf-proof generation. We use the cheapest real family
//! (Count-Min) as the leaf:
//!
//! 1. Precompute the epoch state sequence `S₀ → S₁ → … → S_t` **natively**
//!    (cheap) so every leaf's boundary commitments are known up front.
//! 2. Prove the `t` independent transition leaves `S_{i-1} → S_i` **in parallel**
//!    on a `k`-thread pool ([`with_pool`]) — this is the part core count moves.
//! 3. Ingest the (boundary-consistent) leaves into a [`StreamingForest`] and
//!    finalise — `O(log t)` cheap merges.
//!
//! `forest_completion_ms` = parallel leaf-gen + forest fold; `speedup_vs_1core`
//! = `completion(k=1) / completion(k)`; `v` = the **sustained** insert rate
//! (`t / completion`, inserts/sec) — the prototype reports the rate it can
//! actually achieve rather than throttling to a synthetic target.

use std::time::Duration;

use rayon::prelude::*;

use crate::recursion::framework::{EpochLeaf, StreamingForest};
use crate::sketch::countmin::CountMinUpdate;
use crate::sketch::countmin_final::{apply_update_prf, CountMinFinalParams};

use super::families::{cm_empty, cm_epoch};
use super::metrics::{bench, read_vmrss_kb, BenchCfg, RunOutcome};
use super::{time_it, with_pool};

const CM_D: usize = 4;
const CM_W: usize = 8;
/// Distinct keys per batch (caps the compaction bound so the leaf stays cheap
/// while the batch size `m` sweeps the record count). Kept small so the
/// canonical core-sweep runs in a couple of minutes; the speedup is what E6
/// measures, not the absolute per-leaf cost.
const DISTINCT_BOUND: usize = 16;
/// `IntervalProof` composition-layer size (BabyBear = 4 bytes/elt).
const INTERVAL_PROOF_BYTES: u64 = 8 + 8 + 2 * 32 + 16;

/// Deterministic distinct key for record `j` of leaf `i`.
fn key_mix(i: usize, j: usize) -> u32 {
    (((i as u64) << 20 ^ (j as u64 + 1)).wrapping_mul(0x9E37_79B9) as u32) | 1
}

/// One measured forest cell (the cross-`k` speedup is computed by the caller).
#[derive(Clone, Debug)]
pub struct E6Cell {
    pub forest_completion_ms_median: f64,
    pub peak_rss_mb_median: f64,
}

/// Measure forest completion at core count `k`, batch size `m`, `t` inserts.
pub fn measure(k: usize, m: usize, t: usize, cfg: BenchCfg) -> E6Cell {
    let distinct = DISTINCT_BOUND.min(m);
    let params = CountMinFinalParams { d: CM_D, w: CM_W, batch: m, distinct_bound: distinct };

    // Batches of `m` records each, exactly `distinct` distinct keys per batch.
    let batches: Vec<Vec<u32>> =
        (0..t).map(|i| (0..m).map(|j| key_mix(i, j % distinct)).collect()).collect();

    // Native state sequence S₀..S_t (cheap) → known boundary commitments.
    let mut states = Vec::with_capacity(t + 1);
    states.push(cm_empty(CM_D, CM_W));
    for batch in &batches {
        let mut ns = states.last().unwrap().clone();
        for &key in batch {
            apply_update_prf(&mut ns, &CountMinUpdate { key: key as u64, value: 1 });
        }
        states.push(ns);
    }

    let agg = bench(cfg, || {
        // (2) prove the t independent transition leaves in parallel on k cores.
        let (outcomes, t_gen) = time_it(|| {
            with_pool(Some(k), || {
                (0..t)
                    .into_par_iter()
                    .map(|i| cm_epoch(params, &states[i], &batches[i]).0)
                    .collect::<Vec<_>>()
            })
        });
        // (3) ingest into the streaming forest + finalise (cheap merges).
        let (_root, t_merge) = time_it(|| {
            let mut forest = StreamingForest::new();
            for (i, o) in outcomes.iter().enumerate() {
                let leaf = EpochLeaf::new(
                    (i + 1) as u64,
                    o.com_before,
                    o.com_after,
                    o.batch_commit,
                    (i + 1) as u64,
                );
                forest.insert(&leaf).expect("forest insert (boundary-consistent)");
            }
            forest.finalize().expect("finalize")
        });
        RunOutcome {
            witness_gen: Duration::ZERO,
            prove: t_gen + t_merge,
            verify: Duration::ZERO,
            proof_size_bytes: INTERVAL_PROOF_BYTES,
            trace_rows: 0,
            num_columns: 0,
        }
    });

    let peak = if agg.peak_rss_mb_median > 0.0 {
        agg.peak_rss_mb_median
    } else {
        read_vmrss_kb().map(|kb| kb as f64 / 1024.0).unwrap_or(0.0)
    };

    E6Cell {
        // witness_gen=0 ⇒ prove_total == prove == leaf-gen + fold.
        forest_completion_ms_median: agg.prove_total_ms_median,
        peak_rss_mb_median: peak,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forest_completion_is_measured_and_chains() {
        // Tiny: 4 inserts, batch 8, single core — just proves the path runs,
        // the leaves chain into a finalisable forest, and timing is non-zero.
        let cell = measure(1, 8, 4, BenchCfg { warmup: 0, trials: 1 });
        assert!(cell.forest_completion_ms_median > 0.0, "completion must be measured");
    }
}
