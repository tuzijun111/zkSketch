//! **Multi-family streaming proof composition** (paper §Streaming Proof
//! Composition, generalised beyond Count-Min).
//!
//! Benchmarks the three composition modes — **per-batch proof chain**, the
//! **recursive linear chain**, and the **streaming forest** — over a stream of
//! `t = ⌈N/m⌉` transition leaves, for four sketch families each pinned to one
//! leaf variant:
//!
//! | family | variant           | leaf prover (exposed)          |
//! |--------|-------------------|--------------------------------|
//! | cm     | omc               | `prove_countmin_omc_exposed`   |
//! | hll    | omc               | `prove_hll_omc_exposed`        |
//! | ss     | certified         | `prove_ss_full_exposed`        |
//! | gk     | bandmerge2        | `prove_gkb2_exposed`           |
//!
//! All four leaves surface their `(Com(S_{i-1}), Com(S_i))` boundary via the
//! Expose NPO, so the **family-agnostic** folds
//! ([`prove_forest_over`](crate::recursion::recursive::expose_forest::prove_forest_over)
//! Bentley–Saxe tree, [`prove_chain_over`] left-leaning linear) compose any of
//! them and bind `left.final == right.initial` in-circuit. The per-batch mode
//! folds nothing — it stores the `t` leaf proofs to a folder and the verifier
//! holds all of them.
//!
//! ## Mixed updates + queries (`query_every`)
//!
//! With `query_every = k > 0`, a **query leaf** (the family's `src/decode/*`
//! circuit: cm point count, hll cardinality, ss top-1 mass, gk rank) is proved
//! after every `k`-th batch against the state at that point. The query circuit
//! re-hashes the state and binds the same `Com(S_{t'})` the update leaf just
//! exposed (asserted by the harness), so the verifier checks the answer against
//! the composition proof(s) live at `t'`: all `t'` leaves (per_batch), the
//! current fold (chain), or the `popcount(t')` Bentley–Saxe peaks (forest).
//! Query costs are reported separately (`query_*` fields) and the per-mode
//! verifier context is the structural `query_ctx_verifies` count — interior
//! boundaries are hidden by the final root, so mid-stream queries verify
//! against the composition state at query time, not the end-of-stream root.
//!
//! ## Cores and machines
//!
//! Every mode honours a **cores** budget: the whole measurement runs inside a
//! `cores`-thread rayon pool, so each leaf/merge proof uses exactly that many
//! cores (the per-machine budget). The `per_batch` and `forest` modes
//! additionally honour a **machines** count `M`: leaves are independent, so `M`
//! machines prove them in parallel. Recursion proofs are `!Send`
//! (`Rc<CircuitProverData>`) and cannot be combined across threads, so we do NOT
//! fake a parallel fold; instead the parallel leaf-gen wall-clock is the
//! **work-partition makespan** — the `t` leaves are split into `M` contiguous
//! segments and `leafgen = max` over segments of the segment's real per-leaf
//! prove times (measured at the machine's core budget). The recursive fold then
//! runs sequentially on one machine (the `O(log t)` depth tail the paper's
//! `O(t/M + log t)` predicts), yielding one real `O(1)` root whose size and
//! verify time are reported. `chain` is inherently sequential (each fold needs
//! its predecessor), so it ignores `machines`.

use std::path::Path;
use std::time::Duration;

use rayon::ThreadPoolBuilder;

use crate::config::Val;
use crate::decode::countmin::{prove_cm_decode, CmDecodeParams};
use crate::decode::gk_bandmerge::{prove_gk2_decode, Gkb2DecodeParams};
use crate::decode::hyperloglog::{prove_hll_decode_omc, HllDecodeParams};
use crate::decode::spacesaving::{prove_ss_decode, SsDecodeParams};
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::expose_forest::{
    prove_chain_over, prove_forest_over, verify_bound_proof,
};
use crate::recursion::recursive::timing;
use p3_recursion::RecursionOutput;

use crate::sketch::countmin::CountMinUpdate;
use crate::sketch::countmin_final::apply_update_prf;
use crate::sketch::countmin_omc::{prove_countmin_omc_exposed, CmOmcParams};
use crate::sketch::gk_bandmerge::{
    apply_batch2, commit_gk2_state, prove_gkb2_exposed, Gk2State, GkbParams,
};
use crate::sketch::hll_omc::{
    commit_hll_omc, hll_omc_advance, hll_omc_empty, prove_hll_omc_exposed, HllOmcParams,
};
use crate::sketch::ss_final_full::{
    apply_batch_ss_full, commit_ss_state, prove_ss_full_exposed, SsFullParams, SsFullState,
    SsFullUpdate,
};

use super::families::cm_empty;
use super::metrics::{bench, read_vmrss_kb, BenchCfg, RunOutcome};
use super::proof_size;

use crate::commitment::countmin::commit_countmin;

/// The four (family, variant) leaf types the composition benchmark folds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamFamily {
    /// Count-Min, offline-memory-checking rebind (`prove_countmin_omc_exposed`).
    CmOmc,
    /// HyperLogLog, offline-memory-checking rebind (`prove_hll_omc_exposed`).
    HllOmc,
    /// SpaceSaving, certified full top-s leaf (`prove_ss_full_exposed`).
    SsCertified,
    /// Greenwald–Khanna, two-sided band-merge (`prove_gkb2_exposed`).
    GkBandmerge2,
}

impl StreamFamily {
    /// Parse a `family` token; the variant is fixed per family.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cm" | "cm_omc" | "countmin" => Some(Self::CmOmc),
            "hll" | "hll_omc" | "hyperloglog" => Some(Self::HllOmc),
            "ss" | "ss_certified" | "spacesaving" => Some(Self::SsCertified),
            "gk" | "gk_bandmerge2" | "bandmerge2" | "greenwald_khanna" => Some(Self::GkBandmerge2),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::CmOmc => "cm_omc",
            Self::HllOmc => "hll_omc",
            Self::SsCertified => "ss_certified",
            Self::GkBandmerge2 => "gk_bandmerge2",
        }
    }
    pub fn family(self) -> &'static str {
        match self {
            Self::CmOmc => "cm",
            Self::HllOmc => "hll",
            Self::SsCertified => "ss",
            Self::GkBandmerge2 => "gk",
        }
    }
}

/// The three composition modes of §Streaming Proof Composition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMode {
    /// One independent proof per batch, NO fold; proofs stored to a folder.
    PerBatch,
    /// Recursive linear chain `Π^(t) = merge(Π^(t-1), π_t)` (`O(t)` depth).
    Chain,
    /// Streaming forest — Bentley–Saxe tree fold (`O(log t)` depth).
    Forest,
}

impl StreamMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "per_batch" | "perbatch" | "per-batch" | "flat" => Some(Self::PerBatch),
            "chain" | "linear" => Some(Self::Chain),
            // `recursive` accepted as a back-compat alias for the renamed forest.
            "forest" | "recursive" | "tree" => Some(Self::Forest),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::PerBatch => "per_batch",
            Self::Chain => "chain",
            Self::Forest => "forest",
        }
    }
}

/// Sketch shape — only the fields relevant to the chosen family are used.
#[derive(Clone, Copy, Debug)]
pub struct StreamShape {
    /// Count-Min depth.
    pub d: usize,
    /// Count-Min width.
    pub w: usize,
    /// HLL register-index bits (`m = 2^b` registers).
    pub b: usize,
    /// SS / GK summary capacity `s'`.
    pub capacity: usize,
    /// GK accuracy parameter `s = 1/ε`.
    pub gk_s: u64,
}

/// One measured composition cell.
#[derive(Clone, Debug)]
pub struct ComposeCell {
    /// Whole-stream prove time = `leafgen + merge` (leafgen = parallel makespan).
    pub total_time_ms: f64,
    /// Parallel leaf-gen: the `M`-machine work-partition makespan (= sequential
    /// sum when `machines = 1`).
    pub leafgen_ms: f64,
    /// Sequential leaf-gen (Σ per-leaf), for reference / speedup denominator.
    pub leafgen_seq_ms: f64,
    /// Recursive fold time (0 for per_batch).
    pub merge_ms: f64,
    /// Verifier cost: Σ leaf verifies + links (per_batch), or the single root
    /// verify (chain/forest).
    pub verify_ms: f64,
    /// Verifier-facing artifact bytes: Σ leaf proofs (per_batch, `Θ(t)`) or the
    /// single root proof (chain/forest, `O(1)`).
    pub proof_bytes: u64,
    pub peak_rss_mb: f64,
    /// Mixed workload: number of interleaved query events (0 = updates only).
    pub n_queries: usize,
    /// Σ query-leaf prove time over all query events.
    pub query_prove_ms: f64,
    /// Σ query-leaf self-verify time over all query events.
    pub query_verify_ms: f64,
    /// Σ query-leaf proof bytes over all query events.
    pub query_proof_bytes: u64,
    /// Σ over query events of the number of COMPOSITION proofs the verifier must
    /// check at query time to trust the bound state commitment `Com(S_{t'})`:
    /// `t'` leaf proofs (per_batch), the 1 current fold (chain), or the
    /// `popcount(t')` Bentley–Saxe peaks (forest). Structural count — the folds
    /// exist at query time in a live stream; this harness does not re-time them.
    pub query_ctx_verifies: u64,
}

/// A boundary-exposing leaf proof plus the Send metrics we keep off-thread.
struct LeafArt {
    output: RecursionOutput<ConfigWithFriParams>,
    initial: [Val; 8],
    final_: [Val; 8],
    prove_ms: f64,
    verify_ms: f64,
}

/// One interleaved query event's Send metrics (the query proof itself is
/// dropped — only its cost and size are kept).
struct QueryArt {
    /// Number of leaves covered when the query fired (`t'`, 1-based).
    at_leaf: usize,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: u64,
}

/// Record one query event: take the decode prover's self-timings, check the
/// harness-level binding (the state the query circuit hashed must be exactly
/// the leaf-boundary commitment at `t'` — the decode proof binds it in-circuit
/// via public inputs, this asserts the two sides agree), and keep the metrics.
fn record_query(
    queries: &mut Vec<QueryArt>,
    at_leaf: usize,
    dp: &DecodeProof,
    native_commit: [Val; 8],
    leaf_final: [Val; 8],
) {
    let tm = timing::take();
    assert_eq!(
        native_commit, leaf_final,
        "query state commitment must equal the leaf boundary at t'={at_leaf}"
    );
    queries.push(QueryArt {
        at_leaf,
        prove_ms: (tm.witness + tm.prove).as_secs_f64() * 1000.0,
        verify_ms: tm.verify.as_secs_f64() * 1000.0,
        proof_bytes: dp.proof_size() as u64,
    });
}

/// Prove the `t` exposed, boundary-chained leaves for `family` at `shape`,
/// returning them (leaves stay on the calling thread — they are `!Send`) plus
/// the canonical empty-state commitment `Com(S_0)` for the per-batch anchor and
/// the interleaved query events (empty when `query_every == 0`).
///
/// Mixed workload: when `query_every = k > 0`, after every `k`-th batch a
/// **query leaf** (the family's decode circuit, `src/decode/*`) is proved
/// against the state at that point — it re-hashes the state in-circuit and
/// binds the SAME commitment the update leaf just exposed as its `final_`
/// boundary (asserted here), so a verifier holding the composition proof(s) at
/// `t'` can check the answer against `Com(S_{t'})`. Probes mirror the per-family
/// key masks: cm = first key of the batch (point count), hll = cardinality (no
/// probe), ss = top-1 heavy-hitter mass, gk = rank of the first masked value.
fn prove_leaves(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    query_every: usize,
) -> (Vec<LeafArt>, [Val; 8], Vec<QueryArt>) {
    let m = batches[0].len();
    let mut leaves: Vec<LeafArt> = Vec::with_capacity(batches.len());
    let mut queries: Vec<QueryArt> = Vec::new();
    let query_due = |bi: usize| query_every > 0 && (bi + 1) % query_every == 0;
    // Capture each leaf's real self-timing right after proving.
    let mut push = |output: RecursionOutput<ConfigWithFriParams>, initial: [Val; 8], final_: [Val; 8]| {
        let tm = timing::take();
        leaves.push(LeafArt {
            output,
            initial,
            final_,
            prove_ms: (tm.witness + tm.prove).as_secs_f64() * 1000.0,
            verify_ms: tm.verify.as_secs_f64() * 1000.0,
        });
    };

    let empty_commit = match family {
        StreamFamily::CmOmc => {
            let StreamShape { d, w, .. } = shape;
            let mut state = cm_empty(d, w);
            let e = commit_countmin(&state).0;
            for (bi, batch) in batches.iter().enumerate() {
                let ups: Vec<CountMinUpdate> =
                    batch.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
                let leaf = prove_countmin_omc_exposed(
                    CmOmcParams { d, w, batch: m },
                    state.clone(),
                    ups.clone(),
                );
                let leaf_final = leaf.final_commit.0;
                push(leaf.output, leaf.initial_commit.0, leaf_final);
                for u in &ups {
                    apply_update_prf(&mut state, u);
                }
                if query_due(bi) {
                    // Point-count query for the batch's first key. NOTE the cm
                    // decode circuit caps w <= 16 (one-hot column selector).
                    let dp = prove_cm_decode(
                        CmDecodeParams { d, w, release: ReleasePolicy::Identity },
                        state.clone(),
                        batch[0] as u64,
                    );
                    record_query(&mut queries, bi + 1, &dp, commit_countmin(&state).0, leaf_final);
                }
            }
            e
        }
        StreamFamily::HllOmc => {
            let StreamShape { b, .. } = shape;
            let m_reg = 1usize << b;
            let mut regs = hll_omc_empty(b);
            let e = commit_hll_omc(&regs, b);
            for (bi, batch) in batches.iter().enumerate() {
                let keys: Vec<u64> = batch.iter().map(|&k| k as u64).collect();
                let leaf = prove_hll_omc_exposed(
                    HllOmcParams { b, batch: m },
                    regs.clone(),
                    keys.clone(),
                );
                let leaf_final = leaf.final_commit.0;
                push(leaf.output, leaf.initial_commit.0, leaf_final);
                hll_omc_advance(&mut regs, &keys, m_reg);
                if query_due(bi) {
                    // Cardinality query (no probe key).
                    let dp = prove_hll_decode_omc(
                        HllDecodeParams { b, release: ReleasePolicy::Identity },
                        regs.clone(),
                        0,
                    );
                    record_query(&mut queries, bi + 1, &dp, commit_hll_omc(&regs, b), leaf_final);
                }
            }
            e
        }
        StreamFamily::SsCertified => {
            let StreamShape { capacity, .. } = shape;
            let params = SsFullParams { capacity, batch: m };
            let mut state = SsFullState::empty(params);
            let e = commit_ss_state(&state).0;
            for (bi, batch) in batches.iter().enumerate() {
                // SS binds keys to `[0, 2^KEY_DIFF_BITS)` with KEY_DIFF_BITS=29
                // (the union-sort diff range-check), so mask to 29 bits — NOT the
                // 30-bit mask families.rs used to use, which overflows for large
                // keys. Low bit forced 1 so no real key collides with the 0 dummy.
                let ups: Vec<SsFullUpdate> = batch
                    .iter()
                    .map(|&k| SsFullUpdate::real(((k & 0x1FFF_FFFF) | 1) as u64, 1))
                    .collect();
                let leaf = prove_ss_full_exposed(params, state.clone(), ups.clone());
                let leaf_final = leaf.final_.0;
                push(leaf.output, leaf.initial.0, leaf_final);
                state = apply_batch_ss_full(&state, &ups).0;
                if query_due(bi) {
                    // Top-1 heavy-hitter mass query.
                    let dp = prove_ss_decode(
                        SsDecodeParams { capacity, c: 1, release: ReleasePolicy::Identity },
                        state.clone(),
                        1,
                    );
                    record_query(&mut queries, bi + 1, &dp, commit_ss_state(&state).0, leaf_final);
                }
            }
            e
        }
        StreamFamily::GkBandmerge2 => {
            let StreamShape { capacity, gk_s, .. } = shape;
            let params = GkbParams { capacity, batch: m, s: gk_s };
            let mut state = Gk2State::empty(params);
            let e = commit_gk2_state(&state).0;
            for (bi, batch) in batches.iter().enumerate() {
                // GK is over values; the leaf reserves E_MAX = 2^22-1 for dummies,
                // so mask to 21 bits (< E_MAX) — strictly below the reserved value
                // (families.rs's 22-bit mask can hit E_MAX exactly).
                let vals: Vec<u32> = batch.iter().map(|&k| k & 0x001F_FFFF).collect();
                let leaf = prove_gkb2_exposed(params, state.clone(), vals.clone());
                let leaf_final = leaf.final_.0;
                push(leaf.output, leaf.initial.0, leaf_final);
                state = apply_batch2(&state, &vals);
                if query_due(bi) {
                    // Rank query for the batch's first (masked) value.
                    let dp = prove_gk2_decode(
                        Gkb2DecodeParams { capacity, release: ReleasePolicy::Identity },
                        state.clone(),
                        batch[0] & 0x001F_FFFF,
                    );
                    record_query(&mut queries, bi + 1, &dp, commit_gk2_state(&state).0, leaf_final);
                }
            }
            e
        }
    };

    (leaves, empty_commit, queries)
}

/// `M`-machine work-partition makespan of `per_leaf` prove times: split the
/// leaves into `M` contiguous segments and take the max segment sum. Models `M`
/// machines each proving a disjoint contiguous range at the machine's core
/// budget. `machines <= 1` ⇒ the sequential sum.
fn makespan(per_leaf: &[f64], machines: usize) -> f64 {
    let t = per_leaf.len();
    if machines <= 1 || t == 0 {
        return per_leaf.iter().sum();
    }
    let per = t.div_ceil(machines);
    let mut worst = 0.0f64;
    let mut i = 0;
    while i < t {
        let end = (i + per).min(t);
        worst = worst.max(per_leaf[i..end].iter().sum());
        i = end;
    }
    worst
}

/// Measure one `(family, shape, mode, cores, machines)` composition cell over
/// `batches` (raw dataset keys, all of length `m`). The whole measurement runs
/// inside a `cores`-thread pool so each proof uses that many cores. `proof_dir`
/// is the folder the per-batch mode stores its `t` proofs under (ignored by the
/// composed modes). `query_every = k > 0` interleaves one query leaf after every
/// `k`-th batch (mixed updates+queries workload); its costs are reported in the
/// separate `query_*` fields, NOT folded into the update-side totals.
#[allow(clippy::too_many_arguments)]
pub fn measure_compose(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    machines: usize,
    proof_dir: &Path,
    query_every: usize,
) -> ComposeCell {
    assert!(!batches.is_empty(), "need at least one batch");
    let m = batches[0].len();
    assert!(batches.iter().all(|b| b.len() == m), "all batches must share length m");

    let pool = ThreadPoolBuilder::new()
        .num_threads(cores.max(1))
        .build()
        .expect("compose leaf pool");

    // One measured pass, inside the core-limited pool. bench() wraps it with the
    // RSS sampler; the closure returns only Send metrics (proofs are dropped
    // inside it), so !Send never crosses the pool boundary.
    // Sequential leaf-gen (Σ per-leaf) written out at full f64 precision — a
    // reference / speedup denominator, captured via a mutable rather than
    // squeezed through the u64 RunOutcome fields (trials = 1, set once).
    // Query-event aggregates are captured the same way (trials = 1, set once).
    let mut leafgen_seq_out = 0.0f64;
    let mut q_out = (0usize, 0.0f64, 0.0f64, 0u64, 0u64);
    let agg = pool.install(|| {
        bench(BenchCfg { warmup: 0, trials: 1 }, || {
            let (leaves, empty_commit, query_arts) =
                prove_leaves(family, shape, batches, query_every);
            let prove_ms: Vec<f64> = leaves.iter().map(|l| l.prove_ms).collect();
            let leafgen_seq: f64 = prove_ms.iter().sum();
            leafgen_seq_out = leafgen_seq;
            // Mixed-workload aggregates. `ctx` = composition proofs the verifier
            // checks at query time to trust Com(S_{t'}): t' stored leaves
            // (per_batch), the current fold (chain), or the Bentley–Saxe peaks
            // popcount(t') (forest).
            q_out = (
                query_arts.len(),
                query_arts.iter().map(|q| q.prove_ms).sum(),
                query_arts.iter().map(|q| q.verify_ms).sum(),
                query_arts.iter().map(|q| q.proof_bytes).sum(),
                query_arts
                    .iter()
                    .map(|q| match mode {
                        StreamMode::PerBatch => q.at_leaf as u64,
                        StreamMode::Chain => 1u64,
                        StreamMode::Forest => q.at_leaf.count_ones() as u64,
                    })
                    .sum(),
            );

            match mode {
                StreamMode::PerBatch => {
                    // Store each leaf proof to the folder (fresh per run); the
                    // verifier holds all t (Θ(t) size + verify).
                    let _ = std::fs::remove_dir_all(proof_dir);
                    std::fs::create_dir_all(proof_dir).expect("create per-batch proof dir");
                    let mut total_bytes = 0u64;
                    let mut total_verify = 0.0f64;
                    for (i, l) in leaves.iter().enumerate() {
                        let bytes =
                            postcard::to_allocvec(&l.output.0).expect("serialize leaf proof");
                        total_bytes += bytes.len() as u64;
                        std::fs::write(proof_dir.join(format!("leaf_{i:04}.bin")), &bytes)
                            .expect("write leaf proof");
                        total_verify += l.verify_ms;
                    }
                    // Verifier's chain links: anchor (π₁.initial == Com(S₀)) +
                    // (t-1) boundary equalities. Native compares — negligible but
                    // real (the paper's Θ(t) link cost).
                    let mut ok = leaves[0].initial == empty_commit;
                    for pair in leaves.windows(2) {
                        ok &= pair[0].final_ == pair[1].initial;
                    }
                    assert!(ok, "per-batch chain boundary/anchor check failed");

                    // machines: parallel independent leaf proving (no fold).
                    let leafgen = makespan(&prove_ms, machines);
                    RunOutcome {
                        witness_gen: Duration::from_secs_f64(leafgen / 1000.0),
                        prove: Duration::ZERO, // no fold
                        verify: Duration::from_secs_f64(total_verify / 1000.0),
                        proof_size_bytes: total_bytes,
                        trace_rows: 0,
                        num_columns: 0,
                    }
                }
                StreamMode::Chain | StreamMode::Forest => {
                    // A single leaf has nothing to compose. Its proof still
                    // carries the sketch's Permute table, which the aggregation
                    // verifier (`verify_bound_proof`) does not register — so for
                    // t == 1 we report the leaf's own self-verify (run at prove
                    // time) rather than re-verifying the raw leaf.
                    let single_leaf = leaves.len() < 2;
                    let single_verify_ms = leaves[0].verify_ms;
                    let outputs: Vec<RecursionOutput<ConfigWithFriParams>> =
                        leaves.into_iter().map(|l| l.output).collect();
                    // Real recursive fold → one O(1) root. Timed as merge.
                    let t0 = std::time::Instant::now();
                    let root = if !single_leaf {
                        match mode {
                            StreamMode::Chain => prove_chain_over(outputs),
                            _ => prove_forest_over(outputs),
                        }
                    } else {
                        outputs.into_iter().next().expect(">=1 leaf")
                    };
                    let merge_ms = t0.elapsed().as_secs_f64() * 1000.0;
                    let bytes = proof_size(&root.0) as u64;
                    // Verifier: one succinct check of the merged root (t == 1 uses
                    // the leaf's self-verify, see above).
                    let verify_ms = if single_leaf {
                        single_verify_ms
                    } else {
                        let tv = std::time::Instant::now();
                        verify_bound_proof(&root);
                        tv.elapsed().as_secs_f64() * 1000.0
                    };
                    // Chain is sequential (fold depends on predecessor); forest
                    // parallelises leaf-gen across machines.
                    let leafgen = match mode {
                        StreamMode::Forest => makespan(&prove_ms, machines),
                        _ => leafgen_seq,
                    };
                    RunOutcome {
                        witness_gen: Duration::from_secs_f64(leafgen / 1000.0),
                        prove: Duration::from_secs_f64(merge_ms / 1000.0),
                        verify: Duration::from_secs_f64(verify_ms / 1000.0),
                        proof_size_bytes: bytes,
                        trace_rows: 0,
                        num_columns: 0,
                    }
                }
            }
        })
    });

    let peak = if agg.peak_rss_mb_median > 0.0 {
        agg.peak_rss_mb_median
    } else {
        read_vmrss_kb().map(|kb| kb as f64 / 1024.0).unwrap_or(0.0)
    };

    ComposeCell {
        total_time_ms: agg.prove_total_ms_median,
        leafgen_ms: agg.witness_gen_ms_median,
        leafgen_seq_ms: leafgen_seq_out,
        merge_ms: agg.prove_ms_median,
        verify_ms: agg.verify_ms_median,
        proof_bytes: agg.proof_size_bytes,
        peak_rss_mb: peak,
        n_queries: q_out.0,
        query_prove_ms: q_out.1,
        query_verify_ms: q_out.2,
        query_proof_bytes: q_out.3,
        query_ctx_verifies: q_out.4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> StreamShape {
        StreamShape { d: 4, w: 8, b: 4, capacity: 4, gk_s: 2 }
    }

    /// Two batches, every family/mode — proves the leaves chain (a broken
    /// boundary would panic the fold's in-circuit bind), the three modes run,
    /// and per_batch stores one file per batch with a Θ(t) artifact.
    #[test]
    fn all_families_all_modes_smoke() {
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 1) as u32).collect()).collect();
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
        ] {
            for mode in [StreamMode::PerBatch, StreamMode::Chain, StreamMode::Forest] {
                let dir = std::env::temp_dir()
                    .join(format!("zksketch_compose_{}_{}", family.label(), mode.label()));
                let _ = std::fs::remove_dir_all(&dir);
                let cell =
                    measure_compose(family, shape(), &batches, mode, 1, 1, &dir, 0);
                assert!(
                    cell.total_time_ms > 0.0,
                    "measured ({family:?}, {mode:?})"
                );
                assert!(cell.proof_bytes > 0, "artifact ({family:?}, {mode:?})");
                assert_eq!(cell.n_queries, 0, "updates-only run has no queries");
                if mode == StreamMode::PerBatch {
                    let files = std::fs::read_dir(&dir).map(|it| it.count()).unwrap_or(0);
                    assert_eq!(files, 2, "one proof/batch ({family:?})");
                    assert_eq!(cell.merge_ms, 0.0, "per_batch no fold ({family:?})");
                }
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }

    /// Mixed updates+queries: every batch is followed by a query leaf. Checks
    /// the query events fire, carry real costs, bind the leaf boundary (a
    /// mismatch would panic `record_query`'s assert), and the per-mode verifier
    /// context counts are the structural values: forest peaks = popcount(t'),
    /// per_batch = t', chain = 1.
    #[test]
    fn mixed_queries_smoke() {
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 1) as u32).collect()).collect();
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
        ] {
            let dir = std::env::temp_dir().join(format!("zksketch_mixed_{}", family.label()));
            let _ = std::fs::remove_dir_all(&dir);
            let cell =
                measure_compose(family, shape(), &batches, StreamMode::Forest, 1, 1, &dir, 1);
            assert_eq!(cell.n_queries, 2, "one query per batch ({family:?})");
            assert!(cell.query_prove_ms > 0.0, "query prove timed ({family:?})");
            assert!(cell.query_proof_bytes > 0, "query artifact ({family:?})");
            // Forest peaks at t'=1 and t'=2: popcount(1)+popcount(2) = 1+1.
            assert_eq!(cell.query_ctx_verifies, 2, "forest peaks ctx ({family:?})");
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Mode-dependent ctx on one family: per_batch = 1+2, chain = 1+1.
        let dir = std::env::temp_dir().join("zksketch_mixed_ctx");
        let cell = measure_compose(
            StreamFamily::CmOmc, shape(), &batches, StreamMode::PerBatch, 1, 1, &dir, 1,
        );
        assert_eq!(cell.query_ctx_verifies, 3, "per_batch ctx = t' sum");
        let cell = measure_compose(
            StreamFamily::CmOmc, shape(), &batches, StreamMode::Chain, 1, 1, &dir, 1,
        );
        assert_eq!(cell.query_ctx_verifies, 2, "chain ctx = 1 per query");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A single-leaf (t=1) stream: chain/forest have nothing to compose, so the
    /// "root" is the lone leaf. Regression for the case where verifying that raw
    /// leaf via the aggregation verifier (which lacks the Permute table) would
    /// panic — t=1 must fall back to the leaf's own self-verify.
    #[test]
    fn single_leaf_chain_forest_no_panic() {
        let batches: Vec<Vec<u32>> = vec![(0..4).map(|j| (j + 1) as u32).collect()];
        let dir = std::env::temp_dir().join("zksketch_compose_t1");
        for mode in [StreamMode::Chain, StreamMode::Forest] {
            let cell = measure_compose(StreamFamily::CmOmc, shape(), &batches, mode, 1, 1, &dir, 0);
            assert!(cell.total_time_ms > 0.0, "t=1 measured ({mode:?})");
            assert!(cell.proof_bytes > 0, "t=1 artifact ({mode:?})");
            // No real fold — the "root" is the lone leaf (sub-ms to select).
            assert!(cell.merge_ms < 10.0, "t=1 has no real merge ({mode:?})");
            assert!(cell.verify_ms > 0.0, "t=1 uses the leaf self-verify ({mode:?})");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
