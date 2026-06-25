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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::commitment::CountMinBatchCommit;
use crate::config::Val;
use crate::recursion::framework::{EpochLeaf, StreamingForest};
use crate::recursion::recursive::countmin_chain_v9::prove_countmin_chain_v9;
use crate::recursion::recursive::countmin_forest_v9::prove_countmin_forest_v9;
use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;
use crate::recursion::recursive::countmin_leaf_v9::CountMinLeafProofV9;
use crate::recursion::recursive::expose_forest::prove_forest_over;
use crate::sketch::countmin::{CountMinState, CountMinUpdate};
use crate::sketch::countmin_c_merkle::{
    prove_countmin_c_merkle_exposed, prove_countmin_c_merkle_leaf, CountMinCMerkleParams,
};
use crate::sketch::countmin_final::{
    apply_update_prf, hash_cell_prf, prove_countmin_final, prove_countmin_final_exposed,
    CountMinFinalParams,
};
use crate::sketch::countmin_merkle::combined_commit;
use crate::sketch::countmin_omc::{prove_countmin_omc, prove_countmin_omc_exposed, CmOmcParams};

use super::families::{cm_empty, cm_epoch};
use super::metrics::{bench, read_vmrss_kb, BenchCfg, RunOutcome};
use super::time_it;

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

/// Which Count-Min leaf prover the streaming forest uses per epoch. All three
/// share the same per-record `hash_cell_prf` cell hashing, so the natively
/// chained state sequence `S₀..S_t` is consistent with every variant and the
/// forest boundary check (`leaf[i].com_after == leaf[i+1].com_before`) holds.
/// (`hash_cell_prf` reduces the key with `Val::from_u64` — i.e. mod p — before
/// hashing, so passing the full key (native chain / omc) or a pre-reduced
/// `key mod p` (c_merkle) yields identical cell positions; the chain holds
/// regardless of key magnitude, NOT because keys happen to be below p.) They
/// differ only in the Step-5 rebind / commitment scheme — matching the
/// `EXP_CM_VARIANT` vocabulary in `examples/exp_e1.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmLeaf {
    /// §5.2 flat-commit leaf (`countmin_final`) — the original E6 leaf.
    OneHot,
    /// Lookup-table rebind. In a hash-STARK (multiset EQUALITY only, no LogUp
    /// inclusion) the faithful realisation is the sound OMC leaf
    /// (`countmin_omc`, `M_old ⊎ W = M_new ⊎ R`); it commits the dense state
    /// with `commit_countmin`, the same boundary scheme as `one_hot`.
    Lookup,
    /// Sparse Merkle-commit rebind (`countmin_c_merkle`, `compress=false`):
    /// per-row Merkle roots folded into one digest via `combined_commit`.
    Merkle,
}

impl CmLeaf {
    /// Parse an `EXP_E6_CM_VARIANT` token. `omc` is an alias for `lookup`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "one_hot" => Some(Self::OneHot),
            "lookup" | "omc" => Some(Self::Lookup),
            "merkle" => Some(Self::Merkle),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::OneHot => "one_hot",
            Self::Lookup => "lookup",
            Self::Merkle => "merkle",
        }
    }
}

/// The three boundary commitments the §4 forest chains per leaf.
struct LeafBoundary {
    com_before: [Val; 8],
    com_after: [Val; 8],
    batch_commit: [Val; 8],
}

/// Prove one epoch `initial → initial + batch` with the chosen leaf variant,
/// returning only the boundary commitments the forest needs. `t_max` bounds the
/// distinct touched cells per row for the Merkle rebind (ignored otherwise).
fn prove_leaf(
    variant: CmLeaf,
    d: usize,
    w: usize,
    m: usize,
    t_max: usize,
    initial: &CountMinState,
    batch: &[u32],
) -> LeafBoundary {
    match variant {
        CmLeaf::OneHot => {
            let o = cm_epoch(CountMinFinalParams { d, w, batch: m }, initial, batch).0;
            LeafBoundary { com_before: o.com_before, com_after: o.com_after, batch_commit: o.batch_commit }
        }
        CmLeaf::Lookup => {
            let updates: Vec<CountMinUpdate> =
                batch.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
            let pr = prove_countmin_omc(CmOmcParams { d, w, batch: m }, initial.clone(), updates);
            LeafBoundary {
                com_before: pr.initial_commit.0,
                com_after: pr.final_commit.0,
                batch_commit: pr.batch_commit.0,
            }
        }
        CmLeaf::Merkle => {
            let updates: Vec<CountMinUpdate> =
                batch.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
            let cp = CountMinCMerkleParams { d, w, batch: m, t_max, compress: false, group_by: false };
            let pr = prove_countmin_c_merkle_leaf(cp, initial.clone(), updates);
            LeafBoundary {
                com_before: combined_commit(&pr.initial_roots).0,
                com_after: combined_commit(&pr.final_roots).0,
                batch_commit: pr.batch_commit.0,
            }
        }
    }
}

/// Like [`prove_leaf`] but keeps the **full** leaf proof (wrapped as a
/// [`CountMinLeafProofV9`]), so the real recursive merge can verify it
/// in-circuit. All three variants are proved with the same `make_leaf_config`,
/// so the v9 forest aggregation verifies any of them (confirmed by
/// `tests/spike_recursive_stream_merge.rs`). The wrapper only differs in how the
/// boundary commitments are read off each leaf's proof.
fn prove_leaf_full(
    variant: CmLeaf,
    d: usize,
    w: usize,
    m: usize,
    t_max: usize,
    initial: &CountMinState,
    batch: &[u32],
) -> CountMinLeafProofV9 {
    let updates: Vec<CountMinUpdate> =
        batch.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
    match variant {
        // countmin_final already returns a CountMinLeafProofV9.
        CmLeaf::OneHot => {
            prove_countmin_final(CountMinFinalParams { d, w, batch: m }, initial.clone(), updates)
        }
        CmLeaf::Lookup => {
            let pr = prove_countmin_omc(CmOmcParams { d, w, batch: m }, initial.clone(), updates);
            CountMinLeafProofV9 {
                output: pr.output,
                initial: pr.initial_commit,
                final_: pr.final_commit,
                batch_commit: CountMinBatchCommit(pr.batch_commit.0),
                params: CountMinLeafParams::default(),
            }
        }
        CmLeaf::Merkle => {
            let cp = CountMinCMerkleParams { d, w, batch: m, t_max, compress: false, group_by: false };
            let pr = prove_countmin_c_merkle_leaf(cp, initial.clone(), updates);
            CountMinLeafProofV9 {
                output: pr.output,
                initial: combined_commit(&pr.initial_roots),
                final_: combined_commit(&pr.final_roots),
                batch_commit: CountMinBatchCommit(pr.batch_commit.0),
                params: CountMinLeafParams::default(),
            }
        }
    }
}

/// One measured forest cell (the cross-`k` speedup is computed by the caller).
#[derive(Clone, Debug)]
pub struct E6Cell {
    /// Whole-stream prove time = `leafgen + merge` (the headline).
    pub forest_completion_ms_median: f64,
    /// Time to prove all `t` leaves (parallel, the dominant term).
    pub leafgen_ms_median: f64,
    /// Time for the §4 streaming-forest fold over the `t` leaves (the merges) —
    /// expected to be tiny (Poseidon2 hashing of commitments, not recursive
    /// STARK proving).
    pub merge_ms_median: f64,
    pub peak_rss_mb_median: f64,
}

/// Measure forest completion at parallelism `k`, batch size `m`, `t` inserts,
/// using `variant` as the per-epoch Count-Min leaf prover. Synthetic E6 leaf:
/// `m`-record batches of `DISTINCT_BOUND` distinct keys at the canonical
/// `(d, w) = (CM_D, CM_W)` shape. Thin wrapper over [`measure_batches`] with one
/// core per concurrent leaf (`k` leaves proved at once, 1 core each — the E6
/// core-scaling baseline).
pub fn measure(k: usize, m: usize, t: usize, variant: CmLeaf, cfg: BenchCfg) -> E6Cell {
    let distinct = DISTINCT_BOUND.min(m);
    // Batches of `m` records each, exactly `distinct` distinct keys per batch.
    let batches: Vec<Vec<u32>> =
        (0..t).map(|i| (0..m).map(|j| key_mix(i, j % distinct)).collect()).collect();
    measure_batches(k, 1, variant, CM_D, CM_W, &batches, cfg)
}

/// Prove the `t` leaves with `workers` proofs running concurrently, **each
/// pinned to its own `cores_per_leaf`-thread pool** — the distributed model.
/// Models a cluster of `workers` machines × `cores_per_leaf` cores: leaves are
/// pulled work-stealing from a shared counter, so wall-clock ≈
/// `⌈t/workers⌉ × per-leaf(cores_per_leaf)`. Confining each leaf's internal
/// rayon to its own pool is the whole point — otherwise one leaf's prover would
/// grab the global pool and starve the others.
#[allow(clippy::too_many_arguments)]
fn prove_leaves_distributed(
    workers: usize,
    cores_per_leaf: usize,
    variant: CmLeaf,
    d: usize,
    w: usize,
    m: usize,
    t_max: usize,
    states: &[CountMinState],
    batches: &[Vec<u32>],
) -> Vec<LeafBoundary> {
    let t = batches.len();
    let next = AtomicUsize::new(0);
    let mut collected: Vec<(usize, LeafBoundary)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers.max(1))
            .map(|_| {
                scope.spawn(|| {
                    // One dedicated pool per worker → each leaf's prover uses
                    // exactly `cores_per_leaf` cores.
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(cores_per_leaf.max(1))
                        .build()
                        .expect("inner leaf pool");
                    let mut local = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= t {
                            break;
                        }
                        let b = pool
                            .install(|| prove_leaf(variant, d, w, m, t_max, &states[i], &batches[i]));
                        local.push((i, b));
                    }
                    local
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().expect("leaf worker panicked")).collect()
    });
    // Restore epoch order so the forest fold sees a valid (chaining) history.
    collected.sort_by_key(|(i, _)| *i);
    collected.into_iter().map(|(_, b)| b).collect()
}

/// Measure forest completion for a caller-supplied sequence of `batches` at the
/// `(d, w)` sketch shape, in the **distributed** parallelism model: `workers`
/// leaf proofs run concurrently, each on its own `cores_per_leaf`-thread pool.
///
/// Generalises [`measure`] to arbitrary `d`/`w` and arbitrary (e.g. real
/// dataset) keys — the dataset-driven stream runner (`exp_stream`) calls this
/// with `workers = k`, `cores_per_leaf = ⌊total_cores / k⌋` to model `k`
/// machines sharing a fixed core budget. Every batch must have the same length
/// `m`. The Merkle `t_max` is computed **exactly** as the largest number of
/// distinct touched cells in any (batch, row) — sound (the realised maximum,
/// always ≤ `w`) and tight. Caller must validate the shape is legal for
/// `variant` (e.g. the `lookup`/omc leaf needs `d·w % 4 == 0`); a capacity panic
/// here is the runner's `catch_unwind`'s job, not this function's.
pub fn measure_batches(
    workers: usize,
    cores_per_leaf: usize,
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
) -> E6Cell {
    let t = batches.len();
    assert!(t >= 1, "need at least one batch");
    let m = batches[0].len();
    assert!(batches.iter().all(|b| b.len() == m), "all batches must have the same length m");

    // Exact, sound Merkle t_max: the largest distinct-touched-cell count in any
    // (batch, row). Bounded by `w`, so always a valid `CountMinCMerkleParams`.
    let mut t_max = 1usize;
    for batch in batches {
        for i in 0..d {
            let mut seen = std::collections::HashSet::new();
            for &key in batch {
                seen.insert(hash_cell_prf(i, key as u64, w));
            }
            t_max = t_max.max(seen.len());
        }
    }

    // Native state sequence S₀..S_t (cheap) → known boundary commitments.
    let mut states = Vec::with_capacity(t + 1);
    states.push(cm_empty(d, w));
    for batch in batches {
        let mut ns = states.last().unwrap().clone();
        for &key in batch {
            apply_update_prf(&mut ns, &CountMinUpdate { key: key as u64, value: 1 });
        }
        states.push(ns);
    }

    let agg = bench(cfg, || {
        // (2) prove the t leaves: `workers` concurrent, each on `cores_per_leaf`.
        let (boundaries, t_gen) = time_it(|| {
            prove_leaves_distributed(
                workers,
                cores_per_leaf,
                variant,
                d,
                w,
                m,
                t_max,
                &states,
                batches,
            )
        });
        // (3) ingest into the streaming forest + finalise (cheap merges).
        let (_root, t_merge) = time_it(|| {
            let mut forest = StreamingForest::new();
            for (i, b) in boundaries.iter().enumerate() {
                let leaf = EpochLeaf::new(
                    (i + 1) as u64,
                    b.com_before,
                    b.com_after,
                    b.batch_commit,
                    (i + 1) as u64,
                );
                forest.insert(&leaf).expect("forest insert (boundary-consistent)");
            }
            forest.finalize().expect("finalize")
        });
        // Reuse the RunOutcome split to carry the two phases separately:
        // witness_gen = leaf-gen, prove = merge. prove_total = their sum (the
        // headline), so the total is unchanged while leafgen/merge are exposed.
        RunOutcome {
            witness_gen: t_gen,
            prove: t_merge,
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
        // prove_total = witness_gen (leafgen) + prove (merge) = whole-stream time.
        forest_completion_ms_median: agg.prove_total_ms_median,
        leafgen_ms_median: agg.witness_gen_ms_median,
        merge_ms_median: agg.prove_ms_median,
        peak_rss_mb_median: peak,
    }
}

/// Measure whole-stream prove time with the **real recursive merge** (§4.3(c)):
/// leaves are proved sequentially (their proofs hold an `Rc`, so they can't
/// cross threads) and folded with [`prove_countmin_forest_v9`], whose every
/// merge **recursively verifies its two children in-circuit**. Unlike
/// [`measure_batches`]'s cheap digest fold, here `merge_ms` is the actual
/// in-circuit child-verification cost — expect it to dominate, and to grow with
/// the leaf count `t`. The distributed `k`/cores split does NOT apply (leaf-gen
/// is sequential, the cascade is sequential); both phases use the ambient pool.
///
/// With a single batch there is nothing to merge (`merge_ms = 0`).
pub fn measure_batches_recursive(
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
) -> E6Cell {
    let t = batches.len();
    assert!(t >= 1, "need at least one batch");
    let m = batches[0].len();
    assert!(batches.iter().all(|b| b.len() == m), "all batches must have the same length m");

    // Exact, sound Merkle t_max (same as measure_batches).
    let mut t_max = 1usize;
    for batch in batches {
        for i in 0..d {
            let mut seen = std::collections::HashSet::new();
            for &key in batch {
                seen.insert(hash_cell_prf(i, key as u64, w));
            }
            t_max = t_max.max(seen.len());
        }
    }

    let mut states = Vec::with_capacity(t + 1);
    states.push(cm_empty(d, w));
    for batch in batches {
        let mut ns = states.last().unwrap().clone();
        for &key in batch {
            apply_update_prf(&mut ns, &CountMinUpdate { key: key as u64, value: 1 });
        }
        states.push(ns);
    }

    let agg = bench(cfg, || {
        // Leaf-gen: sequential — the leaf proofs are `!Send` (Rc), so they can't
        // be collected across worker threads; each prover uses the global pool.
        let (leaves, t_gen) = time_it(|| {
            (0..t)
                .map(|i| prove_leaf_full(variant, d, w, m, t_max, &states[i], &batches[i]))
                .collect::<Vec<CountMinLeafProofV9>>()
        });
        // Real recursive merge: every fold verifies its two children in-circuit.
        let (_root, t_merge) = time_it(|| {
            if leaves.len() >= 2 {
                let _ = prove_countmin_forest_v9(&leaves).expect("recursive forest fold");
            }
            // t == 1 ⇒ a single leaf, nothing to merge.
        });
        RunOutcome {
            witness_gen: t_gen,
            prove: t_merge,
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
        forest_completion_ms_median: agg.prove_total_ms_median,
        leafgen_ms_median: agg.witness_gen_ms_median,
        merge_ms_median: agg.prove_ms_median,
        peak_rss_mb_median: peak,
    }
}

/// Like [`measure_batches_recursive`] but folds the leaves with the **linear
/// §4.3 chain** ([`prove_countmin_chain_v9`]) instead of the Bentley–Saxe tree
/// ([`prove_countmin_forest_v9`]). Leaf-gen is byte-for-byte identical
/// (sequential `prove_leaf_full`, proofs are `!Send`); only the merge schedule
/// differs — `Π^(t) = merge(Π^(t-1), π_t)`, a strict left-leaning fold of
/// `t - 1` `agg+leaf` merges (`O(t)` depth) rather than the tree's `O(log t)`.
/// So `merge_ms` here is the linear-chain composition cost, directly comparable
/// to [`measure_batches_recursive`]'s tree cost on the same leaves. The
/// distributed `k`/cores split does NOT apply (sequential). Works for every CM
/// leaf variant (`one_hot`/`lookup`/`merkle`), since each wraps into the same
/// `CountMinLeafProofV9` the chain consumes.
pub fn measure_batches_chain(
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
) -> E6Cell {
    let t = batches.len();
    assert!(t >= 1, "need at least one batch");
    let m = batches[0].len();
    assert!(batches.iter().all(|b| b.len() == m), "all batches must have the same length m");

    // Exact, sound Merkle t_max (same as measure_batches).
    let mut t_max = 1usize;
    for batch in batches {
        for i in 0..d {
            let mut seen = std::collections::HashSet::new();
            for &key in batch {
                seen.insert(hash_cell_prf(i, key as u64, w));
            }
            t_max = t_max.max(seen.len());
        }
    }

    let mut states = Vec::with_capacity(t + 1);
    states.push(cm_empty(d, w));
    for batch in batches {
        let mut ns = states.last().unwrap().clone();
        for &key in batch {
            apply_update_prf(&mut ns, &CountMinUpdate { key: key as u64, value: 1 });
        }
        states.push(ns);
    }

    let agg = bench(cfg, || {
        // Leaf-gen: sequential (leaf proofs are `!Send`), each prover uses the
        // global pool — identical to measure_batches_recursive.
        let (leaves, t_gen) = time_it(|| {
            (0..t)
                .map(|i| prove_leaf_full(variant, d, w, m, t_max, &states[i], &batches[i]))
                .collect::<Vec<CountMinLeafProofV9>>()
        });
        // Linear chain fold: init(l0,l1) then extend left-to-right; every merge
        // verifies its two children in-circuit (the previous chain root + the
        // fresh leaf).
        let (_root, t_merge) = time_it(|| {
            if leaves.len() >= 2 {
                let _ = prove_countmin_chain_v9(&leaves).expect("recursive chain fold");
            }
            // t == 1 ⇒ a single leaf, nothing to merge.
        });
        RunOutcome {
            witness_gen: t_gen,
            prove: t_merge,
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
        forest_completion_ms_median: agg.prove_total_ms_median,
        leafgen_ms_median: agg.witness_gen_ms_median,
        merge_ms_median: agg.prove_ms_median,
        peak_rss_mb_median: peak,
    }
}

/// Like [`measure_batches_recursive`] but the recursive fold is **boundary-bound
/// in-circuit** (`expose_forest::prove_forest_over`): each leaf exposes its
/// `(initial, final)` commitment via the Expose NPO, and every merge binds
/// `left.final == right.initial` IN-CIRCUIT (not natively) and re-exposes only
/// the outer boundary — closing the NPO-public-value gap. The root surfaces
/// exactly `(Com(S_0), Com(S_E))`, bound to the verified leaves.
///
/// All three leaves now have boundary-exposing provers
/// ([`prove_countmin_final_exposed`] / [`prove_countmin_omc_exposed`] /
/// [`prove_countmin_c_merkle_exposed`]), so `recursive_bound` supports every
/// variant.
pub fn measure_batches_recursive_bound(
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
) -> E6Cell {
    let t = batches.len();
    assert!(t >= 1, "need at least one batch");
    let m = batches[0].len();
    assert!(batches.iter().all(|b| b.len() == m), "all batches must have the same length m");

    // Exact, sound Merkle t_max (only used by the merkle leaf).
    let mut t_max = 1usize;
    for batch in batches {
        for i in 0..d {
            let mut seen = std::collections::HashSet::new();
            for &key in batch {
                seen.insert(hash_cell_prf(i, key as u64, w));
            }
            t_max = t_max.max(seen.len());
        }
    }

    // Native state sequence (the leaves' exposed boundaries chain along it).
    let mut states = Vec::with_capacity(t + 1);
    states.push(cm_empty(d, w));
    for batch in batches {
        let mut ns = states.last().unwrap().clone();
        for &key in batch {
            apply_update_prf(&mut ns, &CountMinUpdate { key: key as u64, value: 1 });
        }
        states.push(ns);
    }

    let agg = bench(cfg, || {
        // Sequential leaf-gen with the boundary-EXPOSING prover (proofs !Send).
        let (outputs, t_gen) = time_it(|| {
            (0..t)
                .map(|i| {
                    let updates: Vec<CountMinUpdate> =
                        batches[i].iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
                    match variant {
                        CmLeaf::OneHot => {
                            prove_countmin_final_exposed(CountMinFinalParams { d, w, batch: m }, states[i].clone(), updates).output
                        }
                        CmLeaf::Lookup => {
                            prove_countmin_omc_exposed(CmOmcParams { d, w, batch: m }, states[i].clone(), updates).output
                        }
                        CmLeaf::Merkle => {
                            let cp = CountMinCMerkleParams { d, w, batch: m, t_max, compress: false, group_by: false };
                            prove_countmin_c_merkle_exposed(cp, states[i].clone(), updates).output
                        }
                    }
                })
                .collect::<Vec<_>>()
        });
        // In-circuit boundary-bound fold: each merge verifies + binds the chain.
        let (_root, t_merge) = time_it(move || {
            if outputs.len() >= 2 {
                let _ = prove_forest_over(outputs);
            }
        });
        RunOutcome {
            witness_gen: t_gen,
            prove: t_merge,
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
        forest_completion_ms_median: agg.prove_total_ms_median,
        leafgen_ms_median: agg.witness_gen_ms_median,
        merge_ms_median: agg.prove_ms_median,
        peak_rss_mb_median: peak,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forest_completion_is_measured_and_chains() {
        // Tiny: 2 inserts, batch 8, single core — for each leaf variant just
        // proves the path runs, the leaves chain into a finalisable forest
        // (a panic on `forest.insert` would mean the boundary commitments don't
        // chain), and timing is non-zero.
        for variant in [CmLeaf::OneHot, CmLeaf::Lookup, CmLeaf::Merkle] {
            let cell = measure(1, 8, 2, variant, BenchCfg { warmup: 0, trials: 1 });
            assert!(
                cell.forest_completion_ms_median > 0.0,
                "completion must be measured ({variant:?})"
            );
        }
    }
}
