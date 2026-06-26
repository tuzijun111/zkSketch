//! E6 — streaming-forest cores × batch runner (EVAL_SPEC E6). Sweeps core count
//! `k` and batch size `m`, proving `t` independent Count-Min transition leaves in
//! parallel on a `k`-thread pool and folding them into a streaming forest. The
//! headline is `speedup_vs_1core` (the `t/k` term of the work–depth bound) and
//! the sustained insert rate `v` (`t / completion`, inserts/sec).
//!
//! Run:    cargo run --release --example exp_e6
//! Config: EXP_E6_CORES=1,2,4,8   EXP_E6_BATCHES=32,64   EXP_E6_INSERTS=8
//!         EXP_E6_TRIALS=2        EXP_E6_WARMUP=1
//!         EXP_E6_CM_VARIANT=one_hot   (leaf prover: one_hot|omc|merkle; default one_hot)
//!
//! The leaf variants share the per-record hash + counter front half and differ
//! only in the §5 rebind: `omc` = the sound OMC leaf (`countmin_omc`),
//! `merkle` = the sparse Merkle-commit rebind (`countmin_c_merkle`), `one_hot` =
//! the §5.2 flat-commit leaf (`countmin_final`). A `variant` column is the first
//! CSV field; the k=1 speedup baseline is per (variant, m).
//!
//! This is real STARK proving (the only part core count moves — the §4
//! composition merges are single-threaded Poseidon2), so it is heavier than E5.
//! Cores are clamped to the machine's available threads. `k=1` is always
//! measured (the speedup baseline).

use zksketch::experiments::e6_forest::{measure, CmLeaf};
use zksketch::experiments::metrics::{append_csv, write_env_json, BenchCfg};
use zksketch::experiments::{env_usize, results_dir};

fn env_list(key: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(key) {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => default.to_vec(),
    }
}

fn main() {
    let avail = rayon::current_num_threads();
    // Clamp to available threads, dedup, ensure k=1 is present (speedup base).
    let mut cores: Vec<usize> = env_list("EXP_E6_CORES", &[1, 2, 4, 8])
        .into_iter()
        .map(|k| k.clamp(1, avail))
        .collect();
    cores.sort_unstable();
    cores.dedup();
    if cores.first() != Some(&1) {
        cores.insert(0, 1);
    }
    let batches = env_list("EXP_E6_BATCHES", &[32, 64]);
    let t = env_usize("EXP_E6_INSERTS", 8);
    let cfg = BenchCfg {
        warmup: env_usize("EXP_E6_WARMUP", 1),
        trials: env_usize("EXP_E6_TRIALS", 2),
    };
    // Which Count-Min leaf prover(s) the forest folds. Comma-list of
    // one_hot | omc | merkle. Default is `one_hot` — the original E6
    // leaf (countmin_final flat-commit) — so `run_experiments.sh e6` reproduces
    // the baseline; pass e.g. EXP_E6_CM_VARIANT=omc,merkle for the rebind
    // comparison.
    let variant_str = std::env::var("EXP_E6_CM_VARIANT").unwrap_or_else(|_| "one_hot".to_string());
    let variants: Vec<CmLeaf> = variant_str
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            let v = CmLeaf::parse(s);
            if v.is_none() && !s.is_empty() {
                eprintln!("ignoring unknown EXP_E6_CM_VARIANT token '{s}' (one_hot|omc|merkle)");
            }
            v
        })
        .collect();
    if variants.is_empty() {
        eprintln!("EXP_E6_CM_VARIANT must list one or more of one_hot|omc|merkle");
        std::process::exit(2);
    }
    if batches.is_empty() || batches.iter().any(|&m| m == 0) {
        eprintln!("EXP_E6_BATCHES must be a non-empty list of positive integers");
        std::process::exit(2);
    }
    if t == 0 {
        eprintln!("EXP_E6_INSERTS must be > 0");
        std::process::exit(2);
    }
    if cfg.trials == 0 {
        eprintln!("EXP_E6_TRIALS must be > 0");
        std::process::exit(2);
    }
    println!(
        "E6 streaming forest (plonky3) — variants={variant_str} cores={cores:?} (avail {avail}) batches={batches:?} inserts={t} trials={}",
        cfg.trials
    );

    let dir = results_dir();
    write_env_json(
        &dir,
        &[
            ("backend", "plonky3".into()),
            ("field", "BabyBear".into()),
            ("hash", "Poseidon2".into()),
            ("experiment", "e6_forest".into()),
            ("leaf_family", "cm".into()),
            ("cm_variants", variant_str.clone()),
            ("avail_threads", avail.to_string()),
        ],
    );
    let hdr: Vec<String> = [
        "variant",
        "k",
        "m",
        "v",
        "t",
        "per_insert_latency_ms_median",
        "forest_completion_ms_median",
        "speedup_vs_1core",
        "peak_rss_mb_median",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let _ = std::fs::remove_file(dir.join("e6_forest.csv"));

    for &variant in &variants {
        for &m in &batches {
            let mut base_completion: Option<f64> = None; // completion at k=1 (per variant×m)
            for &k in &cores {
                let cell = measure(k, m, t, variant, cfg);
                let completion = cell.forest_completion_ms_median;
                if k == 1 {
                    base_completion = Some(completion);
                }
                let speedup = base_completion
                    .map(|b| if completion > 0.0 { b / completion } else { 1.0 })
                    .unwrap_or(1.0);
                let per_insert = completion / t as f64;
                // One insert == one epoch leaf == one batch, so inserts/sec == the
                // spec's batches/sec. Reports the sustained (achieved) rate.
                let rate = if completion > 0.0 { (t as f64 * 1000.0 / completion).round() as u64 } else { 0 };
                let row = vec![
                    variant.label().to_string(),
                    k.to_string(),
                    m.to_string(),
                    rate.to_string(),
                    t.to_string(),
                    format!("{per_insert:.3}"),
                    format!("{completion:.3}"),
                    format!("{speedup:.2}"),
                    format!("{:.1}", cell.peak_rss_mb_median),
                ];
                append_csv(&dir, "e6_forest", &hdr, &row);
                println!(
                    "  variant={:<7} k={k:<2} m={m:<4} completion={completion:.1}ms per_insert={per_insert:.1}ms speedup={speedup:.2}x rate={rate}/s rss={:.1}MB",
                    variant.label(),
                    cell.peak_rss_mb_median
                );
            }
        }
    }
    println!("done → {}", dir.join("e6_forest.csv").display());
}
