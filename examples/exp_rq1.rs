//! RQ1 — Capability runner (paper §Evaluation `sec:rq1`).
//!
//! `cargo run --release --example exp_rq1`
//! Knobs: `EXP_RQ1_EPOCHS` (1-a window), `EXP_RQ1_TRIALS` (1-c trials),
//! `V3_SWEEP_THREADS` (Rayon pool size). Writes `results/rq1*.csv`.

use zksketch::experiments::{resolve_threads, rq1_capability, with_pool};

fn main() {
    let (n, label) = resolve_threads();
    println!("zkSketch — RQ1 Capability   [{label}]");
    println!("=========================================");
    with_pool(n, || {
        for t in rq1_capability::run() {
            t.emit();
        }
    });
    println!("\nRQ1 done. Plot with: python3 scripts/plot_experiments.py");
}
