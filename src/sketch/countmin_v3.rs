//! Plaintext v3 Count-Min plan (group by key, group by counter, sparse patch); the
//! in-circuit `countmin_leaf_v3` is tested against it.

use crate::sketch::countmin::{CountMin, CountMinParams, CountMinState, CountMinUpdate, hash_cell};
use crate::sketch::Sketch;

/// One row of the key-sorted batch `B↑k`. The pipeline supplies this with
/// equal-key rows already adjacent; inactive entries (used when `B` is padded
/// to a fixed length) carry `active = false` and dummy field values.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SortedBatchRow {
    pub active: bool,
    pub key: u64,
    pub value: u32,
}

/// One row of the grouped-key table `G`. The bin-aggregate `value_sum`
/// accumulates every `B↑k` row with the same key.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GroupedRow {
    pub active: bool,
    pub key: u64,
    pub value_sum: u32,
}

/// One row of the counter-update table `U_ctr`. Each grouped-key row spawns
/// `d` such rows — one per Count-Min sketch row `i ∈ [0, d)` — carrying the
/// counter location `(i, bucket = h_i(key))` and the same `value_sum`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CounterUpdateRow {
    pub active: bool,
    pub key: u64,
    pub row: usize,
    pub bucket: usize,
    pub value: u32,
}

/// One row of the sparse patch `A`. Aggregates every `U_ctr` row touching
/// the same counter `(row, bucket)` into a single net delta.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SparsePatchRow {
    pub active: bool,
    pub row: usize,
    pub bucket: usize,
    pub delta: u32,
}

/// Full §5.2 v3 pipeline output.
///
/// All intermediate tables are exposed so the in-circuit leaf can witness
/// each step. `b_sorted` is one valid key-grouped arrangement of the input
/// batch (any arrangement where equal keys are adjacent is acceptable;
/// `build` produces a stable one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3Pipeline {
    pub params: CountMinParams,
    pub b_sorted: Vec<SortedBatchRow>,
    pub g: Vec<GroupedRow>,
    pub u_ctr: Vec<CounterUpdateRow>,
    pub u_ctr_sorted: Vec<CounterUpdateRow>,
    pub a: Vec<SparsePatchRow>,
}

impl V3Pipeline {
    /// Number of active (non-dummy) rows in `G`.
    pub fn distinct_keys(&self) -> usize {
        self.g.iter().filter(|g| g.active).count()
    }

    /// Number of active rows in `A` — the count of distinct counters touched.
    pub fn touched_counters(&self) -> usize {
        self.a.iter().filter(|a| a.active).count()
    }
}

/// Build the §5.2 pipeline for a batch against a Count-Min state.
///
/// The output `V3Pipeline` carries every intermediate table; applying its
/// sparse patch `A` to `state` reproduces the same state as replaying every
/// `CountMinUpdate` in `batch` via `CountMin::update`.
pub fn build(state: &CountMinState, batch: &[CountMinUpdate]) -> V3Pipeline {
    let params = state.params;
    let m = batch.len();
    let d = params.d;
    let w = params.w;

    // Step 1+2: produce a key-grouped arrangement of the batch. We sort by
    // key purely for determinism — the §5.2 circuit only needs equal keys
    // adjacent, not globally sorted, but a stable sort is the simplest way
    // to satisfy that.
    let mut indexed: Vec<(u64, u32, usize)> = batch
        .iter()
        .enumerate()
        .map(|(i, u)| (u.key, u.value, i))
        .collect();
    indexed.sort_by_key(|&(k, _, i)| (k, i));
    let b_sorted: Vec<SortedBatchRow> = indexed
        .iter()
        .map(|&(k, v, _)| SortedBatchRow { active: true, key: k, value: v })
        .collect();

    // Step 3: aggregate values per distinct key. Walk `b_sorted` and emit
    // one `G` row per equal-key run. The grouped table is padded to length
    // `m` with inactive dummies so it has a fixed shape.
    let mut g: Vec<GroupedRow> = Vec::with_capacity(m);
    let mut i = 0;
    while i < b_sorted.len() {
        let k = b_sorted[i].key;
        let mut sum: u32 = 0;
        let mut j = i;
        while j < b_sorted.len() && b_sorted[j].key == k {
            sum = sum.saturating_add(b_sorted[j].value);
            j += 1;
        }
        g.push(GroupedRow { active: true, key: k, value_sum: sum });
        i = j;
    }
    while g.len() < m {
        g.push(GroupedRow { active: false, key: 0, value_sum: 0 });
    }

    // Step 4: for each grouped row, compute the `d` counter locations and
    // spawn `d` `U_ctr` rows. The table has shape `m × d` (padded with
    // inactive rows for inactive grouped slots).
    let mut u_ctr: Vec<CounterUpdateRow> = Vec::with_capacity(m * d);
    for gr in &g {
        for row in 0..d {
            if gr.active {
                let bucket = hash_cell(row, gr.key, w);
                u_ctr.push(CounterUpdateRow {
                    active: true,
                    key: gr.key,
                    row,
                    bucket,
                    value: gr.value_sum,
                });
            } else {
                u_ctr.push(CounterUpdateRow {
                    active: false,
                    key: 0,
                    row,
                    bucket: 0,
                    value: 0,
                });
            }
        }
    }

    // Step 5: counter-sort. Sort `u_ctr` by counter id `(row, bucket)`. As
    // with step 2 only adjacency on the sort key is needed for §5.2, but a
    // stable sort gives a deterministic witness.
    let mut u_ctr_sorted: Vec<CounterUpdateRow> = u_ctr.clone();
    u_ctr_sorted.sort_by_key(|r| (!r.active, r.row, r.bucket, r.key));
    // ^ inactive rows placed last (active = true sorts before active = false
    // because `!true = false < !false = true`).

    // Step 6: segment-aggregate equal-counter runs in `u_ctr_sorted` into
    // the sparse patch `A`. Padded to length `m * d`.
    let mut a: Vec<SparsePatchRow> = Vec::with_capacity(m * d);
    let mut i = 0;
    while i < u_ctr_sorted.len() {
        if !u_ctr_sorted[i].active {
            break;
        }
        let row = u_ctr_sorted[i].row;
        let bucket = u_ctr_sorted[i].bucket;
        let mut delta: u32 = 0;
        let mut j = i;
        while j < u_ctr_sorted.len()
            && u_ctr_sorted[j].active
            && u_ctr_sorted[j].row == row
            && u_ctr_sorted[j].bucket == bucket
        {
            delta = delta.saturating_add(u_ctr_sorted[j].value);
            j += 1;
        }
        a.push(SparsePatchRow { active: true, row, bucket, delta });
        i = j;
    }
    while a.len() < m * d {
        a.push(SparsePatchRow { active: false, row: 0, bucket: 0, delta: 0 });
    }

    V3Pipeline { params, b_sorted, g, u_ctr, u_ctr_sorted, a }
}

// ───────────────────────────────────────────────────────────────────────
// Batch introspection + alternative generators (Phase 8e)
// ───────────────────────────────────────────────────────────────────────

/// Stats produced by [`analyze_batch`]. Inspect a batch's duplicate-key
/// distribution without running the prover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchStats {
    /// Total record count.
    pub records: usize,
    /// Number of unique keys.
    pub distinct_keys: usize,
    /// Frequency of the most-repeated key (1 if all keys are distinct).
    pub max_repetitions: u32,
    /// `{repetition_count -> #keys_with_that_count}`. For example, a batch
    /// with 1000 distinct keys gives `{1: 1000}`; a batch of 100 distinct
    /// keys each appearing 10 times gives `{10: 100}`.
    pub histogram: std::collections::BTreeMap<u32, usize>,
}

/// Compute [`BatchStats`] for any `&[CountMinUpdate]`. Decoupled from
/// batch generation so callers can analyse user-supplied batches too.
pub fn analyze_batch(records: &[CountMinUpdate]) -> BatchStats {
    use std::collections::{BTreeMap, HashMap};

    let mut counts: HashMap<u64, u32> = HashMap::with_capacity(records.len());
    for r in records {
        *counts.entry(r.key).or_insert(0) += 1;
    }

    let distinct_keys = counts.len();
    let max_repetitions = counts.values().copied().max().unwrap_or(0);
    let mut histogram: BTreeMap<u32, usize> = BTreeMap::new();
    for &c in counts.values() {
        *histogram.entry(c).or_insert(0) += 1;
    }

    BatchStats {
        records: records.len(),
        distinct_keys,
        max_repetitions,
        histogram,
    }
}

/// Reproduce the deterministic batch that [`bench_v3_prover`] uses
/// internally. Exposed so callers can inspect the records (e.g. via
/// [`analyze_batch`]) without running the prover. Producing the same
/// output for the same `params` is a documented contract; the existing
/// inlined version inside `bench_v3_prover` stays in sync.
pub fn gen_default_batch(
    params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
) -> Vec<CountMinUpdate> {
    let crate::recursion::recursive::countmin_leaf::CountMinLeafParams { d, w, batch } = params;
    (0..batch)
        .map(|i| CountMinUpdate {
            key: (i as u64).wrapping_mul(0x9E37_79B9) ^ ((d * w * batch) as u64),
            value: 1 + (i as u32 % 7),
        })
        .collect()
}

/// Generate a batch of length `params.batch` using only `distinct`
/// unique keys, each appearing roughly `params.batch / distinct`
/// times. Keys are deterministic for reproducible runs.
///
/// Useful for measuring how v3's prove time varies with duplicate-key
/// density — feed the result to [`bench_v3_prover_on_batch`].
///
/// # Panics
///
/// Panics if `distinct == 0` or `distinct > params.batch`.
pub fn gen_batch_with_distinct_keys(
    params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
    distinct: usize,
) -> Vec<CountMinUpdate> {
    assert!(distinct > 0, "distinct must be positive");
    assert!(
        distinct <= params.batch,
        "distinct ({distinct}) must be ≤ params.batch ({})",
        params.batch
    );
    let crate::recursion::recursive::countmin_leaf::CountMinLeafParams { d, w, batch } = params;
    let salt = (d * w * batch) as u64;
    (0..batch)
        .map(|i| {
            let key_idx = (i % distinct) as u64;
            CountMinUpdate {
                // Same mixing as gen_default_batch, but cycling through
                // only `distinct` key indices.
                key: key_idx.wrapping_mul(0x9E37_79B9) ^ salt,
                value: 1 + (i as u32 % 7),
            }
        })
        .collect()
}

/// Off-circuit key-grouping: aggregate `records` by `key`, summing
/// `value`s. Returns a `Vec<CountMinUpdate>` with one record per distinct
/// key, ordered by first occurrence.
///
/// ### Why this exists
///
/// Count-Min is additive: applying records `[(k, v1), (k, v2)]` to a
/// state is equivalent to applying a single record `(k, v1 + v2)`. The
/// prover can therefore aggregate equal-key records *before* invoking
/// the v9 leaf, shrinking the effective batch size from `m` (raw record
/// count) to `|distinct|` (unique-key count). This is exactly the §5.2
/// step 2/3 ("group by key") performed natively rather than in-circuit.
///
/// Because our circuit shape is fixed at compile time and witness count
/// scales with `params.batch`, doing the grouping off-circuit is the
/// only way to *actually reduce* prove time — the witness count, FFT
/// size, and per-cell selectors all shrink with the smaller `params.batch`.
/// In-circuit key-grouping (the literal §5.2 step 2/3) would only
/// restructure the data flow at fixed circuit size; it wouldn't shrink
/// the witness count.
///
/// ### Caller responsibility
///
/// The result is meant to be passed to `bench_v3_prover_on_batch` (or
/// the v9 equivalent) with a `params.batch == result.len()`. Mismatching
/// the batch size and the aggregated batch length will panic the
/// downstream `params.validate()` or the leaf's input-length assertions.
///
/// # Value bound caveat
///
/// Aggregated values can exceed the per-record range. For a raw batch
/// of m records with per-record values ≤ V_max, an aggregated record's
/// value can be up to `m · V_max`. For the v9 leaf, this must stay
/// below `SHIFT_VAL = 2^20 = 1 048 576`; for `m=1000, V_max=7` (the
/// `gen_batch_with_distinct_keys` workload) the worst-case is `7000`,
/// comfortably under the bound. Use `u32::saturating_add` so overflow
/// is graceful if a future workload pushes past `2^32`.
pub fn aggregate_by_key(records: &[CountMinUpdate]) -> Vec<CountMinUpdate> {
    use std::collections::HashMap;
    let mut order: Vec<u64> = Vec::new(); // first-occurrence ordering
    let mut sums: HashMap<u64, u32> = HashMap::with_capacity(records.len());
    for r in records {
        if let std::collections::hash_map::Entry::Vacant(e) = sums.entry(r.key) {
            order.push(r.key);
            e.insert(r.value);
        } else {
            let v = sums.get_mut(&r.key).unwrap();
            *v = v.saturating_add(r.value);
        }
    }
    order
        .into_iter()
        .map(|k| CountMinUpdate { key: k, value: sums[&k] })
        .collect()
}

/// Benchmark the v3 in-circuit leaf prover at a flexible `(d, w, batch)`.
///
/// Used by the `#[ignore]`'d `v3_proving_time_sweep` test below, and exposed
/// `pub` so future demos / criterion benches can reuse the helper without
/// re-implementing the deterministic-batch idiom.
///
/// The batch is generated deterministically from the params (so re-running
/// at the same grid point is reproducible) but varies across grid points
/// (so different cells get touched at different shapes). Keys mix via the
/// same `0x9E3779B9` constant used by `examples/countmin_sweep.rs` so the
/// per-record collision pattern matches the v1 sweep — useful for
/// apples-to-apples cross-comparisons in future analysis.
///
/// `num_threads` controls the size of the Rayon thread pool the STARK
/// prover runs inside. The Plonky3 crates have the `parallel` feature
/// enabled in `Cargo.toml`, so the prover internally uses Rayon for FFTs,
/// trace generation, polynomial evaluation, etc. Pass:
///
/// - `None` → use Rayon's global pool (defaults to the number of logical
///   CPUs; can be overridden globally via the `RAYON_NUM_THREADS` env var
///   before the first Rayon call).
/// - `Some(n)` → spin up a temporary `rayon::ThreadPool` with exactly `n`
///   worker threads and run the prove call inside it via `pool.install`.
///   Useful for scan-the-thread-count benchmarks where you want to compare
///   1, 4, 8, 16-thread proving without restarting the process.
///
/// Returns the wall-clock prove time. Self-verification is already performed
/// inside `prove_countmin_leaf_v3_with_params`, so a successful return means
/// the proof was generated AND verified. The leaf proof itself is dropped on
/// return; if you need the serialized size, use `postcard::to_allocvec` from
/// an `examples/` binary where dev-dependencies are visible.
///
/// # Panics
///
/// Panics if `params.validate()` rejects the shape (e.g., `d * w` not a
/// multiple of `CELL_ALIGNMENT = 4`, `d > 16`, or any dimension zero), or
/// if `rayon::ThreadPoolBuilder::build` fails (e.g., when asked for `0`
/// threads).
pub fn bench_v3_prover(
    params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
    num_threads: Option<usize>,
) -> std::time::Duration {
    use crate::recursion::recursive::countmin_leaf_v3::prove_countmin_leaf_v3_with_params;
    use std::time::Instant;

    params.validate();
    let crate::recursion::recursive::countmin_leaf::CountMinLeafParams { d, w, batch } = params;

    let initial = CountMin::new(&CountMinParams { d, w });
    let records: Vec<CountMinUpdate> = (0..batch)
        .map(|i| CountMinUpdate {
            key: (i as u64).wrapping_mul(0x9E37_79B9) ^ ((d * w * batch) as u64),
            value: 1 + (i as u32 % 7),
        })
        .collect();

    // The work that we want to time. Boxed as a `FnOnce()` so we can either
    // call it directly (global pool) or hand it to `pool.install` (custom
    // pool). `install` propagates the surrounding thread-pool context to
    // every Rayon parallel iterator spawned inside the prover.
    let prove_call = move || {
        let t = Instant::now();
        let _leaf = prove_countmin_leaf_v3_with_params(params, initial, records);
        t.elapsed()
    };

    match num_threads {
        None => prove_call(),
        Some(n) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("v3-bench-{i}"))
                .build()
                .expect("build rayon thread pool");
            pool.install(prove_call)
        }
    }
}

/// Like [`bench_v3_prover`], but timing a caller-supplied batch instead of
/// the deterministic one. Lets you measure how v3's prove time varies with
/// the batch's key distribution — pair with [`gen_batch_with_distinct_keys`]
/// to scan duplicate-key density at fixed record count.
///
/// `batch.len()` must equal `params.batch`. Per-record `value` must fit in
/// `u32` (already enforced by [`CountMinUpdate`]'s type) and stay under the
/// v3 leaf's `SHIFT_VAL = 2^20` encoding bound for the PermuteAir
/// row-binding to remain sound — see the soundness sketch in
/// `src/recursion/recursive/countmin_leaf_v3.rs`.
///
/// # Panics
///
/// Same panic surface as [`bench_v3_prover`], plus a length-mismatch panic
/// if `batch.len() != params.batch`.
pub fn bench_v3_prover_on_batch(
    params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
    batch: Vec<CountMinUpdate>,
    num_threads: Option<usize>,
) -> std::time::Duration {
    use crate::recursion::recursive::countmin_leaf_v3::prove_countmin_leaf_v3_with_params;
    use std::time::Instant;

    params.validate();
    assert_eq!(
        batch.len(),
        params.batch,
        "batch length ({}) must equal params.batch ({})",
        batch.len(),
        params.batch
    );

    let crate::recursion::recursive::countmin_leaf::CountMinLeafParams { d, w, .. } = params;
    let initial = CountMin::new(&CountMinParams { d, w });

    let prove_call = move || {
        let t = Instant::now();
        let _leaf = prove_countmin_leaf_v3_with_params(params, initial, batch);
        t.elapsed()
    };

    match num_threads {
        None => prove_call(),
        Some(n) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("v3-bench-on-batch-{i}"))
                .build()
                .expect("build rayon thread pool");
            pool.install(prove_call)
        }
    }
}

/// Bench the **privacy-preserving v9** leaf on a user-supplied batch.
///
/// Same shape as `bench_v3_prover_on_batch` but invoking the v9 prover
/// (`countmin_leaf_v9::prove_countmin_leaf_v9_with_params`), which
/// operates over private keys + an in-circuit hash + the batch commit.
/// **Pass the raw batch directly** — the v9 leaf performs the §5.2
/// key-grouping in-circuit (verified via PermuteAir + adjacent-equality
/// tags). Pre-aggregating off-circuit and shrinking `params.batch` would
/// be unsound: `batch_commit` would then bind the aggregated batch, not
/// the raw one. See the Phase 9g entry of
/// `plans/velvet-hatching-flask.md` for the soundness analysis.
///
/// Typical workflow for measuring duplicate-density savings:
///
/// ```ignore
/// let params = CountMinLeafParams { d: 4, w: 8, batch: 1000 };
/// let raw_batch = gen_batch_with_distinct_keys(params, 100);
/// let t = bench_v9_prover_on_batch(params, raw_batch, Some(8));
/// ```
///
/// `params.batch` always equals the raw record count; the in-circuit
/// key-grouping handles duplicates. Expected curve: mostly flat with a
/// modest downward slope as `|distinct|` shrinks (cell-level savings,
/// not the dominant hash cost).
///
/// # Constraints
///
/// `params.w` must be a power of 2 in `{2, 4, 8, 16}` (v9 leaf
/// requirement). `batch.len()` must equal `params.batch`. The
/// `params.validate()` check still requires `d * w` to be a multiple of 4.
pub fn bench_v9_prover_on_batch(
    params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
    batch: Vec<CountMinUpdate>,
    num_threads: Option<usize>,
) -> std::time::Duration {
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_with_params;
    use crate::sketch::countmin_v9::CountMinV9;
    use std::time::Instant;

    params.validate();
    assert_eq!(
        batch.len(),
        params.batch,
        "batch length ({}) must equal params.batch ({})",
        batch.len(),
        params.batch
    );

    let crate::recursion::recursive::countmin_leaf::CountMinLeafParams { d, w, .. } = params;
    let initial = CountMinV9::new(&CountMinParams { d, w });

    let prove_call = move || {
        let t = Instant::now();
        let _leaf = prove_countmin_leaf_v9_with_params(params, initial, batch);
        t.elapsed()
    };

    match num_threads {
        None => prove_call(),
        Some(n) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("v9-bench-on-batch-{i}"))
                .build()
                .expect("build rayon thread pool");
            pool.install(prove_call)
        }
    }
}

/// Time the **Phase 9h** (compact-G) v9 leaf prover on a caller-supplied
/// batch. Mirrors [`bench_v9_prover_on_batch`] but takes a
/// `CountMinLeafParamsV9h` so the caller can dial in `distinct_bound` —
/// the compile-time upper bound on the number of distinct keys per batch.
///
/// The v9h leaf compacts the segment-end values into a fixed-size G
/// table of length `distinct_bound` and bounds the in-circuit hash loop
/// by that. So for a batch with many duplicates and a tight
/// `distinct_bound`, the hash + counter-grouping cost drops by roughly
/// `m / distinct_bound`. The compaction itself adds one extra
/// PermuteAir layer of overhead.
///
/// # Panics
///
/// - `params.validate()` failures (alignment, range, distinct_bound shape).
/// - `batch.len() != params.batch`.
/// - The batch's actual distinct-key count exceeds `distinct_bound`
///   (the v9h prover surfaces this as a native assertion).
pub fn bench_v9h_prover_on_batch(
    params: crate::recursion::recursive::countmin_leaf_v9h::CountMinLeafParamsV9h,
    batch: Vec<CountMinUpdate>,
    num_threads: Option<usize>,
) -> std::time::Duration {
    use crate::recursion::recursive::countmin_leaf_v9h::prove_countmin_leaf_v9h_with_params;
    use crate::sketch::countmin_v9::CountMinV9;
    use std::time::Instant;

    params.validate();
    assert_eq!(
        batch.len(),
        params.batch,
        "batch length ({}) must equal params.batch ({})",
        batch.len(),
        params.batch
    );

    let initial = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });

    let prove_call = move || {
        let t = Instant::now();
        let _leaf = prove_countmin_leaf_v9h_with_params(params, initial, batch);
        t.elapsed()
    };

    match num_threads {
        None => prove_call(),
        Some(n) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("v9h-bench-on-batch-{i}"))
                .build()
                .expect("build rayon thread pool");
            pool.install(prove_call)
        }
    }
}

/// Bench the **§4.2 recursive merge** over two freshly-proven v9 leaves.
/// Returns `(leaf1_prove, leaf2_prove, merge)` so the caller can attribute
/// cost between the leaf-proving step and the merge step.
///
/// Workflow: builds an empty v9 state, proves a leaf for batch `b1`,
/// applies `b1` natively, proves a second leaf for batch `b2`, and then
/// invokes `merge_two_countmin_v9` to aggregate both leaves into one
/// recursive batch-STARK. All three calls are timed with `Instant::now()`.
///
/// Both batches are deterministic — `b1` uses `gen_default_batch(params)`
/// (all distinct keys); `b2` reuses the same generator with the indices
/// shifted by `params.batch` to give a structurally similar but distinct
/// second batch.
///
/// Set `num_threads = Some(n)` to confine the prover to a dedicated
/// Rayon pool of `n` threads; `None` uses the global Rayon pool.
pub fn bench_v9_merge(
    params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
    num_threads: Option<usize>,
) -> (std::time::Duration, std::time::Duration, std::time::Duration) {
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_with_params;
    use crate::recursion::recursive::countmin_merge_v9::merge_two_countmin_v9;
    use crate::sketch::countmin_v9::CountMinV9;
    use std::time::Instant;

    params.validate();
    let crate::recursion::recursive::countmin_leaf::CountMinLeafParams { d, w, batch: m } =
        params;

    let bench = move || {
        let s0 = CountMinV9::new(&CountMinParams { d, w });

        // Batch 1 — `gen_default_batch` (all distinct keys).
        let b1 = gen_default_batch(params);
        let t1 = Instant::now();
        let l1 = prove_countmin_leaf_v9_with_params(params, s0.clone(), b1.clone());
        let leaf1_time = t1.elapsed();

        // Apply b1 natively → s1, which becomes the input state for l2.
        let mut s1 = s0;
        for u in &b1 {
            CountMinV9::update(&mut s1, u);
        }

        // Batch 2 — same generator but shifted indices, so b2 ≠ b1 (still
        // all-distinct keys, deterministic).
        let salt = (d * w * m) as u64;
        let b2: Vec<CountMinUpdate> = (0..m)
            .map(|i| {
                let key_idx = (i as u64 + m as u64).wrapping_mul(0x9E37_79B9);
                CountMinUpdate {
                    key: key_idx ^ salt,
                    value: 1 + (i as u32 % 7),
                }
            })
            .collect();
        let t2 = Instant::now();
        let l2 = prove_countmin_leaf_v9_with_params(params, s1, b2);
        let leaf2_time = t2.elapsed();

        // §4.2 merge step — the thing we actually came here to time.
        let tm = Instant::now();
        let _chain = merge_two_countmin_v9(&l1, &l2).expect("merge_two_countmin_v9");
        let merge_time = tm.elapsed();

        (leaf1_time, leaf2_time, merge_time)
    };

    match num_threads {
        None => bench(),
        Some(n) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("v9-merge-bench-{i}"))
                .build()
                .expect("build rayon thread pool");
            pool.install(bench)
        }
    }
}

/// Bench the **§4.2 additive (parallel) merge** over two freshly-proven
/// v9 leaves built from an *empty* initial state. Unlike `bench_v9_merge`
/// (sequential), the merge step here **explicitly includes per-cell
/// accumulation** — `M[i][j] = A_1[i][j] + A_2[i][j]` is proven in-
/// circuit alongside the recursive verification of both leaves' STARKs.
///
/// Returns `(leaf1, leaf2, cell_sum_prove, recursive_agg)` so the caller
/// can see exactly where each piece of work lands. `cell_sum_prove` is
/// the proving time of the small cell-add STARK; `recursive_agg` is the
/// time of `build_and_prove_aggregation_layer` (verifying both leaves).
/// The "merge step" in this design is `cell_sum_prove + recursive_agg`.
///
/// Both leaves use deterministic batches via `gen_default_batch(params)`
/// (b1) and a shifted-index variant (b2).
pub fn bench_v9_merge_additive(
    params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
    num_threads: Option<usize>,
) -> (
    std::time::Duration,
    std::time::Duration,
    std::time::Duration,
    std::time::Duration,
) {
    use crate::commitment::countmin::commit_countmin;
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_with_params;
    use crate::recursion::recursive::countmin_merge_v9_additive::prove_cell_sum;
    use crate::sketch::countmin_v9::CountMinV9;
    use p3_recursion::{BatchOnly, build_and_prove_aggregation_layer};
    use std::time::Instant;

    params.validate();
    let crate::recursion::recursive::countmin_leaf::CountMinLeafParams { d, w, batch: m } =
        params;

    let bench = move || {
        // Both leaves start from empty.
        let s0 = CountMinV9::new(&CountMinParams { d, w });

        // Batch 1 — all-distinct keys.
        let b1 = gen_default_batch(params);
        let t1 = Instant::now();
        let l1 = prove_countmin_leaf_v9_with_params(params, s0.clone(), b1.clone());
        let leaf1_time = t1.elapsed();

        // Batch 2 — same generator, shifted indices (so b2 ≠ b1).
        let salt = (d * w * m) as u64;
        let b2: Vec<CountMinUpdate> = (0..m)
            .map(|i| {
                let key_idx = (i as u64 + m as u64).wrapping_mul(0x9E37_79B9);
                CountMinUpdate {
                    key: key_idx ^ salt,
                    value: 1 + (i as u32 % 7),
                }
            })
            .collect();
        let t2 = Instant::now();
        let l2 = prove_countmin_leaf_v9_with_params(params, s0.clone(), b2.clone());
        let leaf2_time = t2.elapsed();

        // Materialize a1 = apply(b1, empty), a2 = apply(b2, empty) cells.
        let mut a1 = s0.clone();
        for u in &b1 {
            CountMinV9::update(&mut a1, u);
        }
        let mut a2 = s0;
        for u in &b2 {
            CountMinV9::update(&mut a2, u);
        }
        assert_eq!(commit_countmin(&a1), l1.final_, "a1 commit mismatch");
        assert_eq!(commit_countmin(&a2), l2.final_, "a2 commit mismatch");

        // Materialize M = A_1 + A_2 cell-wise.
        let mut merged = a1.clone();
        for i in 0..d {
            for j in 0..w {
                merged.counters[i][j] = a1.counters[i][j].saturating_add(a2.counters[i][j]);
            }
        }

        // Time the cell-sum STARK on its own (the per-cell accumulation).
        let t_cs = Instant::now();
        let _cs = prove_cell_sum(&a1, &a2, &merged).expect("cell-sum prove");
        let cell_sum_time = t_cs.elapsed();

        // Time the recursive aggregation (verifies both leaves' STARKs).
        let config = crate::recursion::recursive::countmin_leaf::make_leaf_config();
        let backend = crate::recursion::recursive::backend::make_backend();
        let recursion_params = p3_recursion::ProveNextLayerParams {
            table_packing:
                p3_circuit_prover::TablePacking::new(2, 2).with_fri_params(6, crate::config::LOG_BLOWUP),
            constraint_profile: p3_circuit_prover::ConstraintProfile::Standard,
        };
        let left_input = l1.output.into_recursion_input::<BatchOnly>();
        let right_input = l2.output.into_recursion_input::<BatchOnly>();
        let t_agg = Instant::now();
        let _agg = build_and_prove_aggregation_layer::<
            crate::recursion::recursive::config::ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            crate::recursion::recursive::backend::Backend,
            { crate::recursion::recursive::config::D },
        >(
            &left_input,
            &right_input,
            &config,
            &backend,
            &recursion_params,
            None,
        )
        .expect("aggregate");
        let recursive_agg_time = t_agg.elapsed();

        (leaf1_time, leaf2_time, cell_sum_time, recursive_agg_time)
    };

    match num_threads {
        None => bench(),
        Some(n) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("v9-merge-additive-bench-{i}"))
                .build()
                .expect("build rayon thread pool");
            pool.install(bench)
        }
    }
}

/// Step 7: apply the sparse patch `A` to a Count-Min state. The in-circuit
/// leaf checks the same per-cell relation; this is the plaintext oracle.
pub fn apply(state: &CountMinState, pipeline: &V3Pipeline) -> CountMinState {
    assert_eq!(state.params, pipeline.params, "state/pipeline param mismatch");
    let mut out = state.clone();
    for row in &pipeline.a {
        if !row.active {
            continue;
        }
        out.counters[row.row][row.bucket] =
            out.counters[row.row][row.bucket].saturating_add(row.delta);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_state(d: usize, w: usize) -> CountMinState {
        CountMin::new(&CountMinParams { d, w })
    }

    /// Pipeline must agree with the naive per-record replay.
    #[test]
    fn build_then_apply_matches_naive() {
        let s0 = empty_state(2, 4);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let pipeline = build(&s0, &batch);
        let by_pipeline = apply(&s0, &pipeline);

        let mut by_replay = s0.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }
        assert_eq!(by_pipeline.counters, by_replay.counters);
    }

    /// Pipeline at the runtime-param `(4, 4)` shape. Includes duplicate keys
    /// to flex the grouped-key path.
    #[test]
    fn build_then_apply_matches_naive_at_4_4() {
        let s0 = empty_state(4, 4);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 42, value: 1 },
        ];
        let pipeline = build(&s0, &batch);
        let by_pipeline = apply(&s0, &pipeline);

        let mut by_replay = s0.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }
        assert_eq!(by_pipeline.counters, by_replay.counters);
    }

    /// Step 3's key-grouping reduces `|G|` below `|B|` when duplicate keys
    /// are present. With two distinct keys in a four-record batch, |G_active| = 2.
    #[test]
    fn duplicate_key_in_batch_aggregates_once() {
        let s0 = empty_state(2, 4);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 9 },
            CountMinUpdate { key: 11, value: 1 },
        ];
        let pipeline = build(&s0, &batch);
        assert_eq!(pipeline.distinct_keys(), 2, "G must hold one row per distinct key");

        // The grouped values must equal the per-key sums.
        let key7_sum: u32 = pipeline
            .g
            .iter()
            .filter(|g| g.active && g.key == 7)
            .map(|g| g.value_sum)
            .sum();
        let key11_sum: u32 = pipeline
            .g
            .iter()
            .filter(|g| g.active && g.key == 11)
            .map(|g| g.value_sum)
            .sum();
        assert_eq!(key7_sum, 3 + 9);
        assert_eq!(key11_sum, 5 + 1);

        // Still must apply correctly.
        let by_pipeline = apply(&s0, &pipeline);
        let mut by_replay = s0.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }
        assert_eq!(by_pipeline.counters, by_replay.counters);
    }

    /// Step 6's counter-aggregation re-merges collisions: when two distinct
    /// keys hash to the same counter `(i, b)`, their separate contributions
    /// land in one sparse-patch row.
    ///
    /// The Count-Min hash family `(k * prime_i) ^ offset_i mod w` has a
    /// structural quirk at power-of-2 widths: XOR is bit-local and the
    /// primes are odd, so `h_i(k) mod 2^L` depends only on `k mod 2^L`.
    /// That means at `w = 2^L`, any two distinct (mod w) keys either collide
    /// on EVERY row or on NO row, and a row-0-only collision cannot exist.
    /// We use `w = 6` (non-power-of-2), where the mod step couples the high
    /// bits enough that the rows become independent and row-0-only
    /// collisions become common.
    #[test]
    fn hash_collision_aggregates_at_counter() {
        let w = 6;
        let mut maybe_collision: Option<(u64, u64)> = None;
        'outer: for ka in 0u64..2048 {
            for kb in (ka + 1)..2048 {
                if hash_cell(0, ka, w) == hash_cell(0, kb, w)
                    && hash_cell(1, ka, w) != hash_cell(1, kb, w)
                {
                    maybe_collision = Some((ka, kb));
                    break 'outer;
                }
            }
        }
        let (ka, kb) = maybe_collision.expect("a row-0-only collision must exist with w=6");

        let s0 = empty_state(2, w);
        let batch = vec![
            CountMinUpdate { key: ka, value: 3 },
            CountMinUpdate { key: kb, value: 5 },
        ];
        let pipeline = build(&s0, &batch);

        // Row 0 collision: one sparse-patch entry at row 0 with delta = 3 + 5.
        let row0_active: Vec<&SparsePatchRow> =
            pipeline.a.iter().filter(|a| a.active && a.row == 0).collect();
        assert_eq!(row0_active.len(), 1, "row 0 must coalesce into one patch row");
        assert_eq!(row0_active[0].delta, 8);

        // Row 1 stayed distinct: two sparse-patch entries.
        let row1_active: Vec<&SparsePatchRow> =
            pipeline.a.iter().filter(|a| a.active && a.row == 1).collect();
        assert_eq!(row1_active.len(), 2, "row 1 must have two distinct patches");

        let by_pipeline = apply(&s0, &pipeline);
        let mut by_replay = s0.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }
        assert_eq!(by_pipeline.counters, by_replay.counters);
    }

    /// Proving-time sweep for the v3 in-circuit leaf at flexible
    /// `(d, w, batch)` shapes. `#[ignore]`'d to keep regular `cargo test`
    /// fast; run on demand:
    ///
    /// ```bash
    /// # Default — Rayon picks the number of threads (all logical CPUs).
    /// cargo test --release --lib v3_proving_time_sweep -- --ignored --nocapture
    ///
    /// # Pin to 4 threads.
    /// V3_SWEEP_THREADS=4 cargo test --release --lib v3_proving_time_sweep -- --ignored --nocapture
    ///
    /// # Force single-threaded — useful for measuring the per-core baseline.
    /// V3_SWEEP_THREADS=1 cargo test --release --lib v3_proving_time_sweep -- --ignored --nocapture
    /// ```
    ///
    /// The thread count is read from the `V3_SWEEP_THREADS` env var. When
    /// unset (or unparseable), the sweep uses Rayon's default pool size —
    /// usually the number of logical CPUs. The grid stays the same across
    /// invocations, so you can compare 1-thread vs 4-thread vs 16-thread
    /// numbers directly.
    ///
    /// The five grid points exercise each axis (depth `d`, width `w`, batch
    /// `m`) independently from a `(2, 4, 2)` baseline, all aligned to
    /// `d * w % 4 == 0`. `n_ctr = m * d` drives the selector-table cost in
    /// the v3 leaf (see `countmin_leaf_v3.rs`), so prove time should grow
    /// fastest along the `(d, batch)` axes — `(8, 4, 8)` is the worst-case
    /// here with `n_ctr = 64` and `sel_a` covering `64 * 64 = 4096` boolean
    /// witnesses.
    #[test]
    #[ignore]
    fn v3_proving_time_sweep() {
        use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;

        let num_threads: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());

        // For the header, surface the *actual* worker count Rayon will use.
        // When V3_SWEEP_THREADS is set we already know; when unset we ask
        // Rayon's global pool how many threads it's running with — that's
        // what `pool.install` would inherit, and what every prove call ends
        // up scheduling on. `current_num_threads()` returns the global
        // pool's size (initialised lazily from RAYON_NUM_THREADS or
        // num_cpus::get()).
        let (effective_threads, source) = match num_threads {
            Some(n) => (n, format!("V3_SWEEP_THREADS={n}")),
            None => {
                let n = rayon::current_num_threads();
                let src = match std::env::var("RAYON_NUM_THREADS") {
                    Ok(v) => format!("Rayon global pool, RAYON_NUM_THREADS={v}"),
                    Err(_) => "Rayon global pool, default = num_cpus::get()".to_string(),
                };
                (n, src)
            }
        };

        println!();
        println!("v3 proving-time sweep — §5.2 Count-Min update circuit");
        println!("=====================================================");
        println!("  threads: {effective_threads}  ({source})");
        println!();

        let grid: Vec<CountMinLeafParams> = vec![
            // CountMinLeafParams { d: 2, w: 4, batch: 2 }, // baseline
            // CountMinLeafParams { d: 2, w: 4, batch: 4 }, // batch ↑
            // CountMinLeafParams { d: 4, w: 4, batch: 4 }, // depth + batch ↑
            CountMinLeafParams { d: 4, w: 1000, batch: 100 }, // width ↑
            // CountMinLeafParams { d: 8, w: 4, batch: 8 }, // depth + batch ↑↑ (worst case)
        ];

        for params in grid {
            let CountMinLeafParams { d, w, batch } = params;
            let n_ctr = batch * d;
            let prove_time = bench_v3_prover(params, num_threads);
            println!(
                "  d={:>2}  w={:>3}  batch={:>3}  cells={:>4}  n_ctr={:>3}  prove {:>10.2?}",
                d, w, batch, d * w, n_ctr, prove_time
            );
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Phase 8e — batch-distribution analyzers
    // ───────────────────────────────────────────────────────────────────

    /// The deterministic batch `bench_v3_prover` generates has all keys
    /// distinct (multiplying by an odd prime is a bijection on u64, so
    /// `i ↦ (i · 0x9E3779B9) XOR salt` is injective). This test pins
    /// that behavior so anyone changing the batch formula is forced to
    /// reconsider whether duplicate keys should appear.
    #[test]
    fn default_batch_has_no_duplicate_keys() {
        let params = crate::recursion::recursive::countmin_leaf::CountMinLeafParams {
            d: 4,
            w: 8,
            batch: 1000,
        };
        let batch = gen_default_batch(params);
        let stats = analyze_batch(&batch);
        assert_eq!(stats.records, 1000);
        assert_eq!(stats.distinct_keys, 1000, "default batch must have all distinct keys");
        assert_eq!(stats.max_repetitions, 1);
        assert_eq!(stats.histogram.get(&1).copied().unwrap_or(0), 1000);
    }

    /// Duplicate-key-density sweep — measure v3's prove time at fixed
    /// `(d, w, batch)` while varying the number of *distinct* keys in the
    /// batch from "all distinct" down to "all the same key."
    ///
    /// Run on demand (with `V3_SWEEP_THREADS=N` to pin the Rayon pool):
    ///
    /// ```bash
    /// cargo test --release --lib v3_duplicate_key_sweep -- --ignored --nocapture
    /// ```
    ///
    /// # Choosing `(d, w)`
    ///
    /// `d * w` **must be a multiple of 4** (the Challenge extension degree —
    /// see `CELL_ALIGNMENT` in `src/recursion/recursive/countmin_leaf.rs`).
    /// This is a project-wide invariant shared by v1/v2/v3. Examples that
    /// pass: `(4, 8)`, `(7, 8)`, `(7, 12)`, `(8, 10)`, `(8, 12)`, `(4, 16)`.
    /// Examples that panic at `validate()`: `(7, 10)` (70 cells), `(3, 5)`
    /// (15 cells), `(5, 6)` (30 cells).
    ///
    /// `d ≤ 16` (limited by the public hash-family table size in
    /// `src/sketch/countmin.rs`). Bumping `d` past 16 requires adding more
    /// entries to `HASH_PRIMES` / `HASH_OFFSETS`.
    ///
    /// For most-informative hash-collision behavior pick a *non*-power-of-2
    /// width like `w = 6, 10, 12, 14`: power-of-2 widths have a structural
    /// quirk where `h_i(k) mod w` depends only on `k mod w`, so all `d` rows
    /// collide identically for any given key residue.
    ///
    /// Hypothesis: prove time is roughly flat across `distinct`, because
    /// v3's in-circuit leaf skips §5.2's key-grouping step (it groups by
    /// counter only). The counter-grouping step at the cell level
    /// handles aggregation regardless of how many records share a key, so
    /// the n_ctr = `m * d` table size doesn't shrink with duplicate keys.
    /// A meaningful curve in the output would be a signal that wiring §5.2's
    /// key-grouping step (currently skipped) is worth its constraint cost.
    #[test]
    #[ignore]
    fn v3_duplicate_key_sweep() {
        use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;

        let num_threads: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let (effective_threads, source) = match num_threads {
            Some(n) => (n, format!("V3_SWEEP_THREADS={n}")),
            None => {
                let n = rayon::current_num_threads();
                let src = match std::env::var("RAYON_NUM_THREADS") {
                    Ok(v) => format!("Rayon global pool, RAYON_NUM_THREADS={v}"),
                    Err(_) => "Rayon global pool, default = num_cpus::get()".to_string(),
                };
                (n, src)
            }
        };

        let params = CountMinLeafParams { d: 7, w: 12, batch: 100 };
        // Fail fast on alignment / range errors before the slow bench loop.
        // `d * w` must be a multiple of 4 (CELL_ALIGNMENT); `d` must be ≤ 16
        // (HASH_PRIMES table size). See the doc comment above for valid
        // examples near common targets.
        params.validate();
        let CountMinLeafParams { d, w, batch } = params;
        let n_ctr = d * batch;

        println!();
        println!("v3 duplicate-key sweep — fixed (d, w, batch) = ({d}, {w}, {batch})");
        println!("=================================================================");
        println!("  threads: {effective_threads}  ({source})");
        println!("  n_ctr = d * batch = {n_ctr}");
        println!();

        // Span: all distinct → half distinct → 10% → 5% → 1% → 0.5% → all same.
        // let distinct_grid = [1000usize, 500, 100, 50, 10, 5, 1];
        let distinct_grid = [10];
        for &distinct in &distinct_grid {
            let batch_vec = gen_batch_with_distinct_keys(params, distinct);
            let stats = analyze_batch(&batch_vec);
            let prove_time = bench_v3_prover_on_batch(params, batch_vec, num_threads);
            println!(
                "  distinct={:>5}  max_rep={:>5}  hist_modes={:>2}  prove {:>10.2?}",
                stats.distinct_keys,
                stats.max_repetitions,
                stats.histogram.len(),
                prove_time
            );
        }
    }

    /// **Phase 9g — duplicate-density sweep for the privacy-preserving v9
    /// leaf, with in-circuit key-grouping verification.**
    ///
    /// History note: the original Phase 9f version of this sweep called
    /// `aggregate_by_key` natively *before* submitting to the v9 prover,
    /// shrinking `params.batch` to `|distinct|` and producing a dramatic
    /// (~140×) downward-sloping curve. That was a **soundness gap**: the
    /// proof's `batch_commit` ended up binding the aggregated batch, not
    /// the raw 1000-record input — a malicious prover could fabricate any
    /// G without a corresponding raw B. (See the user-acknowledged bug
    /// report in the Phase 9g entry of `plans/velvet-hatching-flask.md`.)
    ///
    /// The Phase 9g restructure moved the key-grouping *into* the v9
    /// leaf: the raw batch is the ground truth (`batch_commit = Hash(B)`),
    /// the aggregation is verified in-circuit via PermuteAir on key
    /// payloads + adjacent-equality tags + running-sum, and a `g_active`
    /// gate zeroes out non-segment-end contributions to the U_ctr
    /// payload. This sweep now uses the **honest** workflow: submit the
    /// raw 1000-record batch directly.
    ///
    /// Expected curve: **mostly flat with a modest downward slope**. The
    /// in-circuit hash count stays at `m · d` regardless of `|distinct|`
    /// (every raw record gets `d` position hashes), but
    /// `g_active`-gating prunes inactive rows from contributing to the
    /// counter-aggregation step. So the only savings come from cell-
    /// level work, not from the dominant hash cost.
    ///
    /// Run on demand:
    ///
    /// ```bash
    /// cargo test --release --lib v9_duplicate_key_sweep -- --ignored --nocapture
    /// ```
    ///
    /// Restricts `w` to `{2, 4, 8, 16}` (v9 leaf constraint).
    #[test]
    #[ignore]
    fn v9_duplicate_key_sweep() {
        use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;

        let num_threads: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let (effective_threads, source) = match num_threads {
            Some(n) => (n, format!("V3_SWEEP_THREADS={n}")),
            None => {
                let n = rayon::current_num_threads();
                let src = match std::env::var("RAYON_NUM_THREADS") {
                    Ok(v) => format!("Rayon global pool, RAYON_NUM_THREADS={v}"),
                    Err(_) => "Rayon global pool, default = num_cpus::get()".to_string(),
                };
                (n, src)
            }
        };

        // Raw workload — `params.batch` stays at the raw record count
        // (1000). The v9 leaf verifies the key-grouping in-circuit; the
        // duplicate-density savings come from `g_active`-gated cell-level
        // contributions, not from a shrunken `params.batch`.
        let (d, w) = (4usize, 8usize);
        let raw_batch_size = 1000usize;
        let params = CountMinLeafParams { d, w, batch: raw_batch_size };

        println!();
        println!("v9 duplicate-key sweep — privacy-preserving §5.2 (Phase 9g)");
        println!("============================================================");
        println!("  threads: {effective_threads}  ({source})");
        println!("  d={d}, w={w}, raw batch size={raw_batch_size}");
        println!("  aggregation: in-circuit (verified via PermuteAir + adjacent-equality)");
        println!();

        let distinct_grid = [1000usize, 500, 100, 50, 10, 5, 1];
        for &distinct in &distinct_grid {
            let raw_batch = gen_batch_with_distinct_keys(params, distinct);
            let stats = analyze_batch(&raw_batch);
            let prove_time = bench_v9_prover_on_batch(params, raw_batch, num_threads);
            println!(
                "  distinct={:>5}  raw={:>5}  max_rep={:>5}  prove {:>10.2?}",
                stats.distinct_keys,
                stats.records,
                stats.max_repetitions,
                prove_time
            );
        }
    }

    /// **Phase 9h compact-G sweep**: measure how prove time changes as we
    /// shrink `distinct_bound` (the in-circuit G-table size) to match the
    /// batch's actual distinct-key count. Unlike `v9_duplicate_key_sweep`
    /// (Phase 9g, flat curve), this should slope *downward* — the §5.2
    /// promise that "only distinct keys pay the hash cost" finally
    /// realized.
    ///
    /// Each grid point fixes `raw batch size = 1000`, varies both
    /// `distinct` (actual unique-key count) and `distinct_bound` (the
    /// circuit's G-table capacity). For the workload where the two match
    /// exactly, the compaction PermuteAir is tight: every G_table slot
    /// holds a real segment-end, no padding.
    ///
    /// Run on demand:
    ///
    /// ```bash
    /// cargo test --release --lib v9h_duplicate_key_compact_sweep -- --ignored --nocapture
    /// ```
    ///
    /// Threads via `V3_SWEEP_THREADS=N`; default = full Rayon pool.
    #[test]
    #[ignore]
    fn v9h_duplicate_key_compact_sweep() {
        use crate::recursion::recursive::countmin_leaf_v9h::CountMinLeafParamsV9h;

        let num_threads: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let (effective_threads, source) = match num_threads {
            Some(n) => (n, format!("V3_SWEEP_THREADS={n}")),
            None => {
                let n = rayon::current_num_threads();
                let src = match std::env::var("RAYON_NUM_THREADS") {
                    Ok(v) => format!("Rayon global pool, RAYON_NUM_THREADS={v}"),
                    Err(_) => "Rayon global pool, default = num_cpus::get()".to_string(),
                };
                (n, src)
            }
        };

        let (d, w) = (4usize, 8usize);
        let raw_batch_size = 1000usize;

        println!();
        println!("v9h compact-G sweep — Phase 9h: compile-time `distinct_bound` shrinks hash loop");
        println!("================================================================================");
        println!("  threads: {effective_threads}  ({source})");
        println!("  d={d}, w={w}, raw batch size={raw_batch_size}");
        println!("  varying: distinct_bound (and matching actual `distinct` keys)");
        println!();

        let grid = [1000usize, 500, 100, 50, 10, 5, 1];
        for &distinct in &grid {
            let params = CountMinLeafParamsV9h {
                d,
                w,
                batch: raw_batch_size,
                distinct_bound: distinct,
            };
            let base = crate::recursion::recursive::countmin_leaf::CountMinLeafParams {
                d, w, batch: raw_batch_size,
            };
            let raw_batch = gen_batch_with_distinct_keys(base, distinct);
            let stats = analyze_batch(&raw_batch);
            let prove_time = bench_v9h_prover_on_batch(params, raw_batch, num_threads);
            println!(
                "  distinct_bound={:>5}  actual={:>5}  raw={:>5}  prove {:>10.2?}",
                distinct,
                stats.distinct_keys,
                stats.records,
                prove_time
            );
        }
    }

    /// **§4.2 recursive merge proving-time check** at `(d, w, batch) =
    /// (4, 8, 1000)` — two v9 (privacy-preserving) leaves are proven and
    /// then aggregated via `merge_two_countmin_v9`. Reports per-leaf
    /// prove time and merge time separately.
    ///
    /// To bench a different `(d, w, batch)`, edit the constants below or
    /// call `bench_v9_merge(params, num_threads)` directly. Both batches
    /// use the same generator so prove time per leaf matches what
    /// `v9_duplicate_key_sweep` reports at `distinct = batch` (no
    /// duplicates).
    ///
    /// Run on demand:
    ///
    /// ```bash
    /// V3_SWEEP_THREADS=8 cargo test --release --lib v9_merge_proving_time -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn v9_merge_proving_time() {
        use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;

        let num_threads: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let (effective_threads, source) = match num_threads {
            Some(n) => (n, format!("V3_SWEEP_THREADS={n}")),
            None => {
                let n = rayon::current_num_threads();
                let src = match std::env::var("RAYON_NUM_THREADS") {
                    Ok(v) => format!("Rayon global pool, RAYON_NUM_THREADS={v}"),
                    Err(_) => "Rayon global pool, default = num_cpus::get()".to_string(),
                };
                (n, src)
            }
        };

        let (d, w) = (4usize, 8usize);
        let raw_batch_size = 1000usize;
        let params = CountMinLeafParams { d, w, batch: raw_batch_size };

        println!();
        println!("v9 merge proving-time check — §4.2 recursive merge over two leaves");
        println!("====================================================================");
        println!("  threads: {effective_threads}  ({source})");
        println!("  d={d}, w={w}, batch={raw_batch_size}");
        println!("  workflow: prove l1 → apply → prove l2 → merge_two_countmin_v9");
        println!();

        let (l1_time, l2_time, m_time) = bench_v9_merge(params, num_threads);

        println!("  leaf 1 prove:        {l1_time:>10.2?}");
        println!("  leaf 2 prove:        {l2_time:>10.2?}");
        println!("  §4.2 merge step:     {m_time:>10.2?}");
        println!("  ─────────────────────────────────");
        println!(
            "  total wall-clock:    {:>10.2?}",
            l1_time + l2_time + m_time
        );
    }

    /// **§4.2 ADDITIVE merge proving-time check** at `(d, w, batch) =
    /// (4, 8, 1000)`. Unlike `v9_merge_proving_time` (sequential), this
    /// uses the parallel/additive design — both leaves prove `0 → A_i`
    /// from an *empty* initial state, and the merge step **explicitly
    /// includes per-cell accumulation** (`M[i][j] = A_1[i][j] + A_2[i][j]`
    /// proven in-circuit by the small cell-sum STARK) alongside the
    /// recursive verification of both leaves' STARKs.
    ///
    /// Run on demand:
    ///
    /// ```bash
    /// V3_SWEEP_THREADS=8 cargo test --release --lib v9_merge_additive_proving_time -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn v9_merge_additive_proving_time() {
        use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;

        let num_threads: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let (effective_threads, source) = match num_threads {
            Some(n) => (n, format!("V3_SWEEP_THREADS={n}")),
            None => {
                let n = rayon::current_num_threads();
                let src = match std::env::var("RAYON_NUM_THREADS") {
                    Ok(v) => format!("Rayon global pool, RAYON_NUM_THREADS={v}"),
                    Err(_) => "Rayon global pool, default = num_cpus::get()".to_string(),
                };
                (n, src)
            }
        };

        let (d, w) = (4usize, 8usize);
        let raw_batch_size = 10000usize;
        let params = CountMinLeafParams { d, w, batch: raw_batch_size };

        println!();
        println!("v9 ADDITIVE merge proving-time check — parallel §4.2");
        println!("======================================================");
        println!("  threads: {effective_threads}  ({source})");
        println!("  d={d}, w={w}, batch={raw_batch_size}");
        println!("  workflow: prove l1 (0→A_1), prove l2 (0→A_2),");
        println!("            cell-sum STARK (M = A_1 + A_2 cell-wise),");
        println!("            recursive aggregation (verify l1, l2 STARKs)");
        println!();

        let (l1_time, l2_time, cell_sum_time, recursive_agg_time) =
            bench_v9_merge_additive(params, num_threads);
        let merge_step_total = cell_sum_time + recursive_agg_time;

        println!("  leaf 1 prove (0→A_1):       {l1_time:>10.2?}");
        println!("  leaf 2 prove (0→A_2):       {l2_time:>10.2?}");
        println!("  ───── merge step ───────────────────────");
        println!("  cell-sum STARK (per-cell):  {cell_sum_time:>10.2?}");
        println!("  recursive agg (verify l1, l2): {recursive_agg_time:>7.2?}");
        println!("  merge step subtotal:        {merge_step_total:>10.2?}");
        println!("  ─────────────────────────────────────────");
        println!(
            "  total wall-clock:           {:>10.2?}",
            l1_time + l2_time + merge_step_total
        );
    }

    /// `aggregate_by_key` on a batch of all-distinct keys is the identity.
    #[test]
    fn aggregate_distinct_batch_is_identity() {
        let params = crate::recursion::recursive::countmin_leaf::CountMinLeafParams {
            d: 4,
            w: 8,
            batch: 1000,
        };
        let batch = gen_default_batch(params);
        let aggregated = aggregate_by_key(&batch);
        assert_eq!(aggregated.len(), batch.len(), "no duplicates → no shrinkage");
        // The values are preserved as-is (no actual summing happens).
        for (a, b) in aggregated.iter().zip(batch.iter()) {
            assert_eq!(a.key, b.key);
            assert_eq!(a.value, b.value);
        }
    }

    /// `aggregate_by_key` on a batch where every record shares one key
    /// collapses to one record with the summed value.
    #[test]
    fn aggregate_all_same_key_collapses_to_one() {
        let batch: Vec<CountMinUpdate> = (0..100)
            .map(|i| CountMinUpdate { key: 42, value: 1 + (i % 7) })
            .collect();
        let aggregated = aggregate_by_key(&batch);
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].key, 42);
        let expected_sum: u32 = (0..100).map(|i: u32| 1 + (i % 7)).sum();
        assert_eq!(aggregated[0].value, expected_sum);
    }

    /// `gen_batch_with_distinct_keys(p, k)` then `aggregate_by_key` gives
    /// a `k`-record batch, each with value summed across the cycle.
    #[test]
    fn aggregate_mixed_batch_matches_gen_distinct() {
        let params = crate::recursion::recursive::countmin_leaf::CountMinLeafParams {
            d: 4,
            w: 8,
            batch: 1000,
        };
        let batch = gen_batch_with_distinct_keys(params, 100);
        let aggregated = aggregate_by_key(&batch);
        assert_eq!(aggregated.len(), 100);
        // Each distinct key appears `params.batch / 100 = 10` times in
        // the raw batch; the aggregated value is the sum of `1 + (i % 7)`
        // over those 10 occurrences.
        // For the i-th distinct key, occurrences happen at indices
        // {i, i+100, i+200, ..., i+900} — values `1 + ((i + j*100) % 7)`
        // for j in 0..10.
        for (idx, rec) in aggregated.iter().enumerate() {
            let expected: u32 = (0..10)
                .map(|j| 1 + (((idx + j * 100) as u32) % 7))
                .sum();
            assert_eq!(
                rec.value, expected,
                "aggregated value for distinct-key index {idx} mismatch"
            );
        }
    }

    /// `gen_batch_with_distinct_keys(params, k)` produces exactly `k`
    /// distinct keys, each appearing `params.batch / k` times when the
    /// division is exact.
    #[test]
    fn gen_with_distinct_keys_yields_expected_distribution() {
        let params = crate::recursion::recursive::countmin_leaf::CountMinLeafParams {
            d: 4,
            w: 8,
            batch: 1000,
        };
        let batch = gen_batch_with_distinct_keys(params, 100);
        let stats = analyze_batch(&batch);
        assert_eq!(stats.records, 1000);
        assert_eq!(stats.distinct_keys, 100);
        assert_eq!(stats.max_repetitions, 10);
        assert_eq!(stats.histogram.get(&10).copied().unwrap_or(0), 100);
    }
}


// v3 proving-time sweep — §5.2 Count-Min update circuit
// =====================================================
//   threads: 64  (Rayon global pool, default = num_cpus::get())

//   d= 4  w=  8  batch=1000  cells=  32  n_ctr=4000  prove      2.89s
