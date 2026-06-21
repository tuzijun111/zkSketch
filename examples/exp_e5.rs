//! E5 — composition-ladder runner (EVAL_SPEC E5). For each rung
//! (`no_composition`, `per_batch_chain`, `recursive_linear`, `streaming_forest`)
//! and audit window `E`, records the prover's online merge cost and the
//! **auditor's** cost — the headline is `verifier_checks` collapsing from `Θ(E)`
//! to `O(1)`. Composition is leaf-shape-agnostic (synthetic leaves), so this
//! runner is fast and offline.
//!
//! Run:    cargo run --release --example exp_e5
//! Config: EXP_E5_WINDOWS=16,64,256,1024   EXP_TRIALS=5   EXP_WARMUP=1
//!
//! Honest caveat: this prototype has no in-circuit recursive verifier, so a
//! "check" is a Poseidon2 boundary digest, not a recursive-SNARK fold. The
//! `verifier_checks`/`root_proof_size_bytes` columns report the composition-layer
//! `Θ(E)→O(1)` structure; absolute ms/bytes are the lightweight digest cost.

use zksketch::experiments::e5_ladder::{measure, E5Row, Setting};
use zksketch::experiments::metrics::{append_csv, write_env_json, BenchCfg};
use zksketch::experiments::{env_usize, results_dir};

fn env_list(key: &str, default: &[u64]) -> Vec<u64> {
    match std::env::var(key) {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => default.to_vec(),
    }
}

fn main() {
    let windows = env_list("EXP_E5_WINDOWS", &[16, 64, 256, 1024]);
    let cfg = BenchCfg { warmup: env_usize("EXP_WARMUP", 1), trials: env_usize("EXP_TRIALS", 5) };
    if windows.is_empty() || windows.iter().any(|&e| e == 0) {
        eprintln!("EXP_E5_WINDOWS must be a non-empty list of positive integers");
        std::process::exit(2);
    }
    if cfg.trials == 0 {
        eprintln!("EXP_TRIALS must be > 0");
        std::process::exit(2);
    }
    println!("E5 composition ladder (plonky3) — windows={windows:?} trials={}", cfg.trials);

    let dir = results_dir();
    write_env_json(
        &dir,
        &[
            ("backend", "plonky3".into()),
            ("field", "BabyBear".into()),
            ("hash", "Poseidon2".into()),
            ("experiment", "e5_ladder".into()),
            ("composition", "option_i_boundary_digest".into()),
        ],
    );
    let hdr: Vec<String> = E5Row::header().iter().map(|s| s.to_string()).collect();
    let _ = std::fs::remove_file(dir.join("e5_ladder.csv"));

    for setting in Setting::ALL {
        for &e in &windows {
            let row = measure(setting, e, cfg);
            append_csv(&dir, "e5_ladder", &hdr, &row.fields());
            println!(
                "  {:<16} E={:<5} comps/insert={:.3} worst_cascade={} checks={} verify={:.4}ms root={}B",
                row.setting,
                row.e,
                row.prover_compositions_per_insert,
                row.worst_case_cascade,
                row.verifier_checks,
                row.verify_ms_median,
                row.root_proof_bytes,
            );
        }
    }
    println!("done → {}", dir.join("e5_ladder.csv").display());
}
