//! Count-Min whole-stream prove time over batch size m and k concurrent leaf proofs; writes results/stream_forest.csv.
//! Usage: [EXP_STREAM_N=65536 EXP_STREAM_BATCHES=64,256,1024 EXP_STREAM_MERGE=digest] cargo run --release --example exp_stream

use std::panic::{catch_unwind, AssertUnwindSafe};

use zksketch::dataset::{aol, netflix, synthetic_stream, zipf_stream, Synthetic};
use zksketch::experiments::e6_forest::{
    measure_batches, measure_batches_chain, measure_batches_per_batch, measure_batches_recursive,
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

/// Guarded variant for the per-batch proof chain (`measure_batches_per_batch`) —
/// proves the `t` leaves in isolation and stores each proof to `proof_dir`.
fn measure_guarded_per_batch(
    variant: CmLeaf,
    d: usize,
    w: usize,
    batches: &[Vec<u32>],
    cfg: BenchCfg,
    proof_dir: &std::path::Path,
) -> Option<E6Cell> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(|| {
        measure_batches_per_batch(variant, d, w, batches, cfg, proof_dir)
    }));
    std::panic::set_hook(prev);
    r.ok()
}

/// Build an `ok` CSV row. `mode` is `digest`|`per_batch`|`chain`|`recursive`|
/// `recursive_bound`. `verify_ms` and `proof_bytes` are the verifier-facing
/// metrics that separate the three composition modes: `Θ(t)` for `per_batch`,
/// `O(1)` for the composed roots.
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
        format!("{:.3}", cell.verify_ms_median),
        cell.proof_bytes.to_string(),
        rps.to_string(), format!("{speedup:.2}"),
        format!("{:.1}", cell.peak_rss_mb_median), "ok".into(),
    ]
}

/// Build a `too_large` CSV row (eight `n/a` metric cells + status).
#[allow(clippy::too_many_arguments)]
fn skip_row(
    dataset: &str, variant: &str, d: usize, w: usize, n: usize, m: usize, t: usize,
    k: usize, cpl: usize, mode: &str,
) -> Vec<String> {
    let mut r = vec![
        dataset.into(), variant.into(), d.to_string(), w.to_string(), n.to_string(),
        m.to_string(), t.to_string(), k.to_string(), cpl.to_string(), mode.into(),
    ];
    // total,leafgen,merge,verify,proof_bytes,rps,speedup,peak
    r.extend(std::iter::repeat("n/a".to_string()).take(8));
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

    // Merge mode: `digest` (default — the cheap §4.2 commitment fold) or
    // `recursive` (the real §4.3(c) fold whose every merge verifies its two
    // children in-circuit). Recursive mode proves leaves sequentially and does
    // ONE pass per (dataset, variant, m) — the distributed `k` split and the
    // EXP_STREAM_CORES sweep do not apply (leaf-gen + cascade are sequential).
    // (recursive, bound, chain). `recursive`/`chain` are both sequential
    // full-leaf folds (k-sweep ignored); they differ only in the merge schedule
    // — `recursive` = Bentley–Saxe tree (O(log t) depth), `chain` = linear §4.3
    // IVC `Π^(t)=merge(Π^(t-1),π_t)` (O(t) depth). `bound` ⇒ tree + in-circuit
    // boundary binding.
    let (recursive, bound, chain, per_batch) = match env_str("EXP_STREAM_MERGE", "digest").trim().to_ascii_lowercase().as_str() {
        "digest" | "" => (false, false, false, false),
        "recursive" | "recursion" | "real" => (true, false, false, false),
        // Boundary-bound: the recursive fold binds left.final==right.initial
        // in-circuit (NPO gap closed). omc + merkle.
        "recursive_bound" | "bound" | "in_circuit" => (true, true, false, false),
        // Linear §4.3 chain over the same leaves — the recursive-linear-chain
        // mode. Every CM variant (one_hot/omc/merkle).
        "chain" | "linear" => (false, false, true, false),
        // Per-batch proof chain: one independent proof per batch, NO fold. Each
        // proof is stored to the proof folder; the verifier holds all t of them
        // (Θ(t) size + verify). The prover-friendly / verifier-expensive baseline.
        "per_batch" | "perbatch" | "per-batch" | "flat" => (false, false, false, true),
        other => {
            eprintln!("unknown EXP_STREAM_MERGE='{other}' (digest|per_batch|chain|recursive|recursive_bound); using digest");
            (false, false, false, false)
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
    // Revision B2: the leaves here are the plain ones (see the module doc).
    match std::env::var("ZKSKETCH_COMMIT") {
        Ok(v) if v.is_empty() || v.eq_ignore_ascii_case("plain") => {}
        Ok(v) if v.eq_ignore_ascii_case("hiding") => {
            eprintln!(
                "ZKSKETCH_COMMIT=hiding: the stream runner proves PLAIN commitments only (hiding is \
                 not wired into e6_forest); use scripts/run_compose.sh for hiding-mode composition, \
                 or set ZKSKETCH_COMMIT=plain"
            );
            std::process::exit(2);
        }
        Ok(v) => {
            eprintln!("ZKSKETCH_COMMIT={v:?}: expected plain or hiding");
            std::process::exit(2);
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("ZKSKETCH_COMMIT is not valid UTF-8; expected plain or hiding");
            std::process::exit(2);
        }
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

    let merge_mode = if per_batch {
        "per_batch"
    } else if chain {
        "chain"
    } else if bound {
        "recursive_bound"
    } else if recursive {
        "recursive"
    } else {
        "digest"
    };
    // `per_batch`, `recursive`, and `chain` all prove the leaves sequentially
    // (one pass; the distributed k-sweep does not apply). `per_batch` does no
    // fold — it just stores the t proofs; the other two fold in-circuit.
    let sequential = recursive || chain || per_batch;
    if sequential {
        let schedule = if per_batch {
            "no fold (store t proofs)"
        } else if chain {
            "linear §4.3 chain"
        } else {
            "Bentley–Saxe tree"
        };
        let kind = if per_batch { "PER-BATCH chain" } else { "RECURSIVE merge" };
        println!(
            "Stream compose (plonky3, {kind} [{merge_mode}], {schedule}) — N={n} d={d} w={w} datasets={datasets:?} variants={variant_str} batches={batches_m:?} (sequential leaf-gen; k-sweep ignored) commit=plain"
        );
    } else {
        println!(
            "Stream forest (plonky3, DISTRIBUTED, digest merge) — N={n} d={d} w={w} datasets={datasets:?} variants={variant_str} k(workers)={cores:?} cores/leaf=⌊{avail}/k⌋ batches={batches_m:?} (single run) commit=plain"
        );
    }

    let dir = results_dir();
    // The single folder the per-batch chain stores its proofs under (one
    // subfolder per (dataset,variant,d,w,m) cell). Overridable so a run can
    // point it at scratch/ or a RAM disk. Only touched in `per_batch` mode.
    let proof_base = std::env::var("EXP_STREAM_PROOF_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| dir.join("per_batch_proofs"));
    if per_batch {
        let _ = std::fs::remove_dir_all(&proof_base); // start clean
        println!("per-batch proofs → {}", proof_base.display());
    }
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
            // Revision B2: plain leaves only (hiding is not wired here).
            ("commit", "plain".into()),
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
        "verify_ms",
        "proof_bytes",
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
                    // Sequential ONE pass (sequential leaf-gen). k/cores_per_leaf
                    // don't apply, so we record k=1, cores_per_leaf=all.
                    // `per_batch` ⇒ store t proofs, NO fold; `chain` ⇒ linear §4.3
                    // schedule; `bound` ⇒ tree + in-circuit boundary binding (NPO
                    // gap closed); else ⇒ the plain Bentley–Saxe tree fold.
                    let guarded = if per_batch {
                        // One folder per (dataset,variant,d,w,m) cell holds this
                        // stream's t proofs; the recorded proof_bytes = their sum.
                        let cell_dir = proof_base
                            .join(format!("{dataset}_{vl}_d{d}_w{w}_m{m}"));
                        measure_guarded_per_batch(variant, d, w, &batches, cfg, &cell_dir)
                    } else if chain {
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
                                "  ds={dataset:<8} {vl:<7} d={d} w={w:<5} m={m:<5} t={t:<5} [{merge_mode}] total={:.2}s (leafgen={:.2}s merge={:.2}s) verify={:.2}s proof={:.1}KB {rps} rec/s rss={:.1}MB",
                                total / 1000.0,
                                cell.leafgen_ms_median / 1000.0,
                                cell.merge_ms_median / 1000.0,
                                cell.verify_ms_median / 1000.0,
                                cell.proof_bytes as f64 / 1024.0,
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
                    // k leaf proofs run concurrently on the fixed core budget,
                    // each with ⌊total/k⌋ cores.
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
