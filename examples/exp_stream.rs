//! **Streaming-forest total-time runner** — fixed total stream size `N`, over a
//! real (or synthetic) dataset, swept over batch size `m` and core count `k`,
//! for the `omc` and `merkle` Count-Min leaf provers at an arbitrary `(d, w)`
//! sketch shape.
//!
//! Unlike E6 (`exp_e6`, which fixes the epoch count `t`, the shape `(4, 8)`, and
//! synthetic keys), this runner fixes the **total number of stream records** `N`
//! (e.g. 2^16) and derives `t = ⌈N/m⌉`, draws the keys from a chosen dataset,
//! and measures — in a **single run** (no warm-up, no trials, no target rate) —
//! the **total wall-clock to prove the whole stream**.
//!
//! **Distributed parallelism model.** `k` (= `EXP_STREAM_CORES`) is the number
//! of leaf proofs run **concurrently** (think `k` machines), and each one is
//! pinned to its own `⌊total_cores / k⌋`-thread pool — so the fixed core budget
//! is split `k` ways. `k=1` proves one leaf at a time on all cores; `k=total`
//! proves `total` leaves at once, 1 core each. Wall-clock ≈
//! `⌈t/k⌉ × per-leaf(⌊total/k⌋ cores)`. (Use `run_experiments.sh e1` with
//! `EXP_CORES=c` to measure a single leaf at `c` cores and predict this.)
//!
//! It reuses the run_experiments.sh `e1` vocabulary (`EXP_DATASET`, `EXP_D`,
//! `EXP_W`, `EXP_CM_VARIANT`) for the sketch shape + dataset, plus its own
//! `EXP_STREAM_*` knobs for the stream geometry.
//!
//! Run:    cargo run --release --example exp_stream
//! Config: EXP_STREAM_N=2^16              total stream records (default 65536; `2^k` ok)
//!         EXP_STREAM_BATCHES=64,256,1024 batch sizes m (default; `2^k` tokens ok)
//!         EXP_STREAM_CORES=1,2,4,8,16,32,64  k = #concurrent leaf proofs (each gets ⌊total/k⌋ cores; clamped to avail)
//!         EXP_DATASET=uniform            uniform|gaussian|zipf|aol|netflix|comma-list (default uniform)
//!         EXP_D=4                        Count-Min depth d (1..=8)
//!         EXP_W=8                        Count-Min width w (power of two ≥ 2)
//!         EXP_CM_VARIANT=omc,merkle   leaf prover(s): one_hot|omc|merkle
//!                                        (EXP_STREAM_CM_VARIANT also accepted)
//!         EXP_STREAM_MERGE=digest        digest | recursive | recursive_bound | chain (default digest)
//!
//! Merge model: `digest` (default) folds leaf boundary commitments with cheap
//! Poseidon2 hashing (the §4.2 composition — each leaf is verified once at
//! creation; merge_ms is ~µs). `recursive` uses the §4.3(c) fold
//! (`prove_countmin_forest_v9`) where **every merge recursively verifies its two
//! children in-circuit** — merge_ms is then the real (large) verification cost.
//! `recursive_bound` additionally binds `left.final == right.initial`
//! **in-circuit** via the Expose NPO (`expose_forest::prove_forest_over`),
//! closing the NPO-public-value gap so the root surfaces a bound
//! `(Com(S_0), Com(S_E))` — supports all three variants (one_hot/omc/merkle).
//! `chain` folds the same leaves with the **linear §4.3 chain**
//! (`prove_countmin_chain_v9`, `Π^(t)=merge(Π^(t-1),π_t)`) instead of the
//! Bentley–Saxe tree — the comparison baseline (O(t)-depth left-leaning fold vs
//! the tree's O(log t)); same in-circuit child verification per merge.
//! Recursive/chain modes prove leaves SEQUENTIALLY (proofs are !Send) and do one
//! pass per (dataset, variant, m); the distributed `k`/EXP_STREAM_CORES sweep is
//! ignored. Use small N/few leaves — each merge is a full recursive proof.
//!
//! The omc leaf requires `d·w % 4 == 0` (Challenge packing); the
//! `merkle` leaf requires `w` a power of two. Real datasets must be fetched
//! first (`python3 scripts/fetch_datasets.py`) — a missing one is skipped.
//!
//! Output: results/stream_forest.csv with columns
//!   dataset,variant,d,w,n,m,t,k,cores_per_leaf,merge_mode,total_time_ms,leafgen_ms,merge_ms,records_per_sec,speedup,peak_rss_mb,status
//! `total_time_ms = leafgen_ms + merge_ms` (leaf proving vs the forest fold);
//! `merge_mode` is `digest` (merge ~µs), `recursive`/`recursive_bound`/`chain`
//! (merge = real in-circuit child verification). `k` = concurrent leaf proofs,
//! `cores_per_leaf` = ⌊total/k⌋ (both = 1/all in the sequential modes); `n` is the actual
//! records proven (`t·m`, ≥ requested N when m∤N); `speedup` is vs the smallest k
//! per (dataset, variant, m); `status` is `ok` or `too_large` (capacity panic —
//! the sweep continues).
//!
//! Runtime: total work ≈ N records of proving; at k cores ≈ (N·per-record)/k,
//! so the smallest-k cells dominate. For N=2^16 a k=1 cell can take tens of
//! minutes — set EXP_STREAM_CORES to a high-core subset for a quick run.
//!
//! Count ceiling: the leaf circuits range-check each cell count to a fixed bit
//! width (c_merkle uses `COUNT_BITS=24`, max 2^24−1 per cell). With `value=1`
//! per record a single cell can accumulate up to ~N increments worst-case, so
//! keep `N < ~2^24` (16M). The default 2^16 is far under it.

use std::panic::{catch_unwind, AssertUnwindSafe};

use zksketch::dataset::{aol, netflix, synthetic_stream, zipf_stream, Synthetic};
use zksketch::experiments::e6_forest::{
    measure_batches, measure_batches_chain, measure_batches_recursive,
    measure_batches_recursive_bound, CmLeaf, E6Cell,
};
use zksketch::experiments::metrics::{append_csv, write_env_json, BenchCfg};
use zksketch::experiments::results_dir;

/// Parse a `usize` that may be written as `base^exp` (e.g. `2^16` → 65536) or a
/// plain integer.
fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    if let Some((base, exp)) = s.split_once('^') {
        let b: u64 = base.trim().parse().ok()?;
        let e: u32 = exp.trim().parse().ok()?;
        b.checked_pow(e).map(|v| v as usize)
    } else {
        s.parse().ok()
    }
}

/// Scalar size env var. A set-but-unparseable value is a hard error (exit 2)
/// rather than a silent fall-back — these runs are long, so a typo should not
/// silently run the wrong size.
fn env_size(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(s) => parse_size(&s).unwrap_or_else(|| {
            eprintln!("{key}='{s}' is not a valid size (a positive integer or `2^k`)");
            std::process::exit(2);
        }),
        Err(_) => default,
    }
}

/// Comma-list size env var. Unparseable tokens are warned about (not silently
/// dropped), matching the variant parser.
fn env_size_list(key: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(key) {
        Ok(s) => s
            .split(',')
            .filter_map(|x| {
                let x = x.trim();
                if x.is_empty() {
                    return None;
                }
                let v = parse_size(x);
                if v.is_none() {
                    eprintln!("ignoring unparseable {key} token '{x}' (integer or `2^k`)");
                }
                v
            })
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Load the raw key vector for a dataset (synthetic generated to `n`; real read
/// in full). `None` when a real dataset file has not been fetched.
fn load_base(dataset: &str, n: usize) -> Option<Vec<u32>> {
    match dataset {
        "uniform" => Some(synthetic_stream(Synthetic::Uniform, n, 1)),
        "gaussian" => Some(synthetic_stream(Synthetic::Gaussian, n, 1)),
        "zipf" => Some(zipf_stream(1.0, n.max(16), n, 1)),
        "aol" => aol(),
        "netflix" => netflix(),
        _ => {
            eprintln!("unknown dataset '{dataset}' (uniform|gaussian|zipf|aol|netflix)");
            None
        }
    }
}

/// `t` uniform batches of `m` keys cut from `base`, cycling if `base` is shorter
/// than `t·m` so every batch is full and the whole N-record stream is covered.
fn batches_from(base: &[u32], m: usize, t: usize) -> Vec<Vec<u32>> {
    (0..t)
        .map(|i| (0..m).map(|j| base[(i * m + j) % base.len()]).collect())
        .collect()
}

/// Run `measure_batches`, catching a *capacity* panic so an over-large sweep
/// point is recorded as `too_large` and the sweep continues instead of aborting
/// the whole process. Mirrors `bench_guarded` in `examples/exp_e1.rs`: the
/// panics this guards are BabyBear's `bits <= TWO_ADICITY` ceiling (the FRI
/// domain tops out at `2^27` rows), a circuit's own selector/`t_max` budget
/// assert, or an OOM — hard limits of the plonky3/BabyBear backend reachable via
/// the free `EXP_STREAM_BATCHES` / `EXP_W` knobs, not transient errors.
fn measure_guarded(
    workers: usize,
    cores_per_leaf: usize,
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
) -> Option<E6Cell> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // silence the expected capacity panic
    let r = catch_unwind(AssertUnwindSafe(|| {
        measure_batches(workers, cores_per_leaf, variant, d, w, batches, cfg)
    }));
    std::panic::set_hook(prev);
    r.ok()
}

/// Guarded variant for the real recursive merge (`measure_batches_recursive`).
fn measure_guarded_recursive(
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
) -> Option<E6Cell> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(|| {
        measure_batches_recursive(variant, d, w, batches, cfg)
    }));
    std::panic::set_hook(prev);
    r.ok()
}

/// Guarded variant for the linear §4.3 chain fold (`measure_batches_chain`).
fn measure_guarded_chain(
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
) -> Option<E6Cell> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(|| {
        measure_batches_chain(variant, d, w, batches, cfg)
    }));
    std::panic::set_hook(prev);
    r.ok()
}

/// Guarded variant for the in-circuit boundary-BOUND recursive merge.
fn measure_guarded_recursive_bound(
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
) -> Option<E6Cell> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(|| {
        measure_batches_recursive_bound(variant, d, w, batches, cfg)
    }));
    std::panic::set_hook(prev);
    r.ok()
}

/// Build an `ok` CSV row. `mode` is `digest` or `recursive`.
#[allow(clippy::too_many_arguments)]
fn ok_row(
    dataset: &str, variant: &str, d: usize, w: usize, n: usize, m: usize, t: usize,
    k: usize, cpl: usize, mode: &str, cell: &E6Cell, total: f64, rps: u64, speedup: f64,
) -> Vec<String> {
    vec![
        dataset.into(), variant.into(), d.to_string(), w.to_string(), n.to_string(),
        m.to_string(), t.to_string(), k.to_string(), cpl.to_string(), mode.into(),
        format!("{total:.3}"),
        format!("{:.3}", cell.leafgen_ms_median),
        format!("{:.3}", cell.merge_ms_median),
        rps.to_string(), format!("{speedup:.2}"),
        format!("{:.1}", cell.peak_rss_mb_median), "ok".into(),
    ]
}

/// Build a `too_large` CSV row (six `n/a` metric cells + status).
#[allow(clippy::too_many_arguments)]
fn skip_row(
    dataset: &str, variant: &str, d: usize, w: usize, n: usize, m: usize, t: usize,
    k: usize, cpl: usize, mode: &str,
) -> Vec<String> {
    let mut r = vec![
        dataset.into(), variant.into(), d.to_string(), w.to_string(), n.to_string(),
        m.to_string(), t.to_string(), k.to_string(), cpl.to_string(), mode.into(),
    ];
    r.extend(std::iter::repeat("n/a".to_string()).take(6)); // total,leafgen,merge,rps,speedup,peak
    r.push("too_large".into());
    r
}

fn main() {
    let avail = rayon::current_num_threads();
    let n = env_size("EXP_STREAM_N", 1 << 16);
    let batches_m = env_size_list("EXP_STREAM_BATCHES", &[64, 256, 1024]);
    // Core counts, clamped to the machine and deduped (no forced k=1 — the
    // speedup baseline is the smallest k actually swept).
    let mut cores: Vec<usize> = env_size_list("EXP_STREAM_CORES", &[1, 2, 4, 8, 16, 32, 64])
        .into_iter()
        .map(|k| k.clamp(1, avail))
        .collect();
    cores.sort_unstable();
    cores.dedup();
    if cores.is_empty() {
        cores.push(1);
    }

    // Merge model: `digest` (default — the cheap §4.2 commitment fold) or
    // `recursive` (the real §4.3(c) fold whose every merge verifies its two
    // children in-circuit). Recursive mode proves leaves sequentially and does
    // ONE pass per (dataset, variant, m) — the distributed `k` split and the
    // EXP_STREAM_CORES sweep do not apply (leaf-gen + cascade are sequential).
    // (recursive, bound, chain). `recursive`/`chain` are both sequential
    // full-leaf folds (k-sweep ignored); they differ only in the merge schedule
    // — `recursive` = Bentley–Saxe tree (O(log t) depth), `chain` = linear §4.3
    // IVC `Π^(t)=merge(Π^(t-1),π_t)` (O(t) depth). `bound` ⇒ tree + in-circuit
    // boundary binding.
    let (recursive, bound, chain) = match env_str("EXP_STREAM_MERGE", "digest").trim().to_ascii_lowercase().as_str() {
        "digest" | "" => (false, false, false),
        "recursive" | "recursion" | "real" => (true, false, false),
        // Boundary-bound: the recursive fold binds left.final==right.initial
        // in-circuit (NPO gap closed). omc + merkle.
        "recursive_bound" | "bound" | "in_circuit" => (true, true, false),
        // Linear §4.3 chain over the same leaves — the comparison baseline vs
        // the tree fold. Every CM variant (one_hot/omc/merkle).
        "chain" | "linear" => (false, false, true),
        other => {
            eprintln!("unknown EXP_STREAM_MERGE='{other}' (digest|recursive|recursive_bound|chain); using digest");
            (false, false, false)
        }
    };

    // Sketch shape + dataset — the run_experiments.sh `e1` vocabulary.
    let d = env_size("EXP_D", 4);
    let w = env_size("EXP_W", 8);
    let dataset_str = env_str("EXP_DATASET", "uniform");
    let datasets: Vec<String> = dataset_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Leaf prover(s). Accept the e1 name EXP_CM_VARIANT (what run_experiments.sh
    // uses), falling back to EXP_STREAM_CM_VARIANT, then the default.
    let variant_str = std::env::var("EXP_CM_VARIANT")
        .or_else(|_| std::env::var("EXP_STREAM_CM_VARIANT"))
        .unwrap_or_else(|_| "omc,merkle".to_string());
    let variants: Vec<CmLeaf> = variant_str
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            let v = CmLeaf::parse(s);
            if v.is_none() && !s.is_empty() {
                eprintln!("ignoring unknown CM variant token '{s}' (one_hot|omc|merkle)");
            }
            v
        })
        .collect();

    // The stream runner is Count-Min only; flag a non-cm EXP_FAMILY rather than
    // silently honouring nothing.
    if let Ok(fam) = std::env::var("EXP_FAMILY") {
        if !fam.split(',').any(|f| f.trim().eq_ignore_ascii_case("cm")) {
            eprintln!("note: EXP_FAMILY='{fam}' — the stream runner is Count-Min only; ignoring it");
        }
    }

    if n == 0 {
        eprintln!("EXP_STREAM_N must be > 0");
        std::process::exit(2);
    }
    if batches_m.is_empty() || batches_m.iter().any(|&m| m == 0) {
        eprintln!("EXP_STREAM_BATCHES must be a non-empty list of positive integers");
        std::process::exit(2);
    }
    if variants.is_empty() {
        eprintln!("EXP_CM_VARIANT must list one or more of one_hot|omc|merkle");
        std::process::exit(2);
    }
    if datasets.is_empty() {
        eprintln!("EXP_DATASET must name at least one dataset");
        std::process::exit(2);
    }
    if !(1..=8).contains(&d) {
        eprintln!("EXP_D must be in 1..=8 (got {d})");
        std::process::exit(2);
    }
    if !(w.is_power_of_two() && w >= 2) {
        eprintln!("EXP_W must be a power of two ≥ 2 (got {w})");
        std::process::exit(2);
    }
    // Both the omc and one_hot (countmin_final) leaves pack the dense
    // d·w state into Challenge words and assert d·w % 4 == 0. The merkle leaf
    // commits per-row roots and has no such constraint.
    let needs_dw_mult4 = variants.iter().any(|v| matches!(v, CmLeaf::Omc | CmLeaf::OneHot));
    if needs_dw_mult4 && (d * w) % 4 != 0 {
        eprintln!(
            "the omc and one_hot (flat-commit) leaves require d·w % 4 == 0 (got d={d}, w={w} → {})",
            d * w
        );
        std::process::exit(2);
    }

    let merge_mode = if chain {
        "chain"
    } else if bound {
        "recursive_bound"
    } else if recursive {
        "recursive"
    } else {
        "digest"
    };
    // `recursive` and `chain` both prove sequentially with an in-circuit fold.
    let sequential = recursive || chain;
    if sequential {
        let schedule = if chain { "linear §4.3 chain" } else { "Bentley–Saxe tree" };
        println!(
            "Stream forest (plonky3, RECURSIVE merge [{merge_mode}], {schedule}) — N={n} d={d} w={w} datasets={datasets:?} variants={variant_str} batches={batches_m:?} (sequential leaf-gen + in-circuit fold; k-sweep ignored)"
        );
    } else {
        println!(
            "Stream forest (plonky3, DISTRIBUTED, digest merge) — N={n} d={d} w={w} datasets={datasets:?} variants={variant_str} k(workers)={cores:?} cores/leaf=⌊{avail}/k⌋ batches={batches_m:?} (single run)"
        );
    }

    let dir = results_dir();
    write_env_json(
        &dir,
        &[
            ("backend", "plonky3".into()),
            ("field", "BabyBear".into()),
            ("hash", "Poseidon2".into()),
            ("experiment", "stream_forest".into()),
            ("leaf_family", "cm".into()),
            ("cm_variants", variant_str.clone()),
            ("dataset", dataset_str.clone()),
            ("d", d.to_string()),
            ("w", w.to_string()),
            ("stream_n", n.to_string()),
            ("total_cores", avail.to_string()),
            ("merge_mode", merge_mode.into()),
            ("parallelism_model", "distributed: k workers × floor(total/k) cores each".into()),
            ("avail_threads", avail.to_string()),
        ],
    );
    let hdr: Vec<String> = [
        "dataset",
        "variant",
        "d",
        "w",
        "n",
        "m",
        "t",
        "k",
        "cores_per_leaf",
        "merge_mode",
        "total_time_ms",
        "leafgen_ms",
        "merge_ms",
        "records_per_sec",
        "speedup",
        "peak_rss_mb",
        "status",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let _ = std::fs::remove_file(dir.join("stream_forest.csv"));

    // Single run per cell: no warm-up, no measured-trial median.
    let cfg = BenchCfg { warmup: 0, trials: 1 };

    for dataset in &datasets {
        // Enough keys to cover the largest per-m need (= max t·m ≥ N). Loaded
        // once per dataset; batches are cut (cycling) from this base per m.
        let max_need = batches_m.iter().map(|&m| n.div_ceil(m) * m).max().unwrap_or(n);
        let base = match load_base(dataset, max_need) {
            Some(b) if !b.is_empty() => b,
            _ => {
                eprintln!(
                    "dataset '{dataset}' unavailable (fetch real ones with `python3 scripts/fetch_datasets.py`) — skipping"
                );
                continue;
            }
        };
        println!("-- dataset={dataset} ({} keys loaded) --", base.len());

        for &variant in &variants {
            for &m in &batches_m {
                // Epochs to cover the whole stream (ceil so all N records are
                // proven). `actual_n = t·m` is what the measured time covers.
                let t = n.div_ceil(m);
                let actual_n = t * m;
                let batches = batches_from(&base, m, t);
                let vl = variant.label();

                if sequential {
                    // Sequential in-circuit fold: ONE pass (sequential leaf-gen +
                    // the in-circuit fold). k/cores_per_leaf don't apply, so we
                    // record k=1, cores_per_leaf=all. `chain` ⇒ linear §4.3
                    // schedule; `bound` ⇒ tree + in-circuit boundary binding (NPO
                    // gap closed); else ⇒ the plain Bentley–Saxe tree fold.
                    let guarded = if chain {
                        measure_guarded_chain(variant, d, w, &batches, cfg)
                    } else if bound {
                        measure_guarded_recursive_bound(variant, d, w, &batches, cfg)
                    } else {
                        measure_guarded_recursive(variant, d, w, &batches, cfg)
                    };
                    match guarded {
                        Some(cell) => {
                            let total = cell.forest_completion_ms_median;
                            let rps =
                                if total > 0.0 { (actual_n as f64 * 1000.0 / total).round() as u64 } else { 0 };
                            let row = ok_row(dataset, vl, d, w, actual_n, m, t, 1, avail, merge_mode, &cell, total, rps, 1.0);
                            append_csv(&dir, "stream_forest", &hdr, &row);
                            println!(
                                "  ds={dataset:<8} {vl:<7} d={d} w={w:<5} m={m:<5} t={t:<5} [{merge_mode}] total={:.2}s (leafgen={:.2}s merge={:.2}s) {rps} rec/s rss={:.1}MB",
                                total / 1000.0,
                                cell.leafgen_ms_median / 1000.0,
                                cell.merge_ms_median / 1000.0,
                                cell.peak_rss_mb_median
                            );
                        }
                        None => {
                            let row = skip_row(dataset, vl, d, w, actual_n, m, t, 1, avail, merge_mode);
                            append_csv(&dir, "stream_forest", &hdr, &row);
                            eprintln!("  ds={dataset} {vl} d={d} w={w} m={m} t={t} [{merge_mode}]: SKIPPED — too_large / recursive-fold panic");
                        }
                    }
                    continue;
                }

                // Digest merge (default): the distributed k-sweep.
                let mut base_time: Option<f64> = None; // smallest k (per dataset×variant×m)
                for &k in &cores {
                    // Distributed model: k workers share the fixed core budget, so
                    // each concurrent leaf proof gets ⌊total/k⌋ cores.
                    let cpl = (avail / k).max(1);
                    match measure_guarded(k, cpl, variant, d, w, &batches, cfg) {
                        Some(cell) => {
                            let total = cell.forest_completion_ms_median;
                            if base_time.is_none() {
                                base_time = Some(total);
                            }
                            let speedup = match base_time {
                                Some(b) if b > 0.0 && total > 0.0 => b / total,
                                _ => 1.0,
                            };
                            let rps =
                                if total > 0.0 { (actual_n as f64 * 1000.0 / total).round() as u64 } else { 0 };
                            let row = ok_row(dataset, vl, d, w, actual_n, m, t, k, cpl, merge_mode, &cell, total, rps, speedup);
                            append_csv(&dir, "stream_forest", &hdr, &row);
                            println!(
                                "  ds={dataset:<8} {vl:<7} d={d} w={w:<5} m={m:<5} t={t:<5} k={k:<2}×{cpl:<2}c total={:.2}s (leafgen={:.2}s merge={:.1}ms) {rps} rec/s speedup={speedup:.2}x rss={:.1}MB",
                                total / 1000.0,
                                cell.leafgen_ms_median / 1000.0,
                                cell.merge_ms_median,
                                cell.peak_rss_mb_median
                            );
                        }
                        None => {
                            let row = skip_row(dataset, vl, d, w, actual_n, m, t, k, cpl, merge_mode);
                            append_csv(&dir, "stream_forest", &hdr, &row);
                            eprintln!(
                                "  ds={dataset} {vl} d={d} w={w} m={m} t={t} k={k}×{cpl}c: SKIPPED — too_large (FRI 2^27 ceiling / selector budget / OOM)"
                            );
                        }
                    }
                }
            }
        }
    }
    println!("done → {}", dir.join("stream_forest.csv").display());
}
