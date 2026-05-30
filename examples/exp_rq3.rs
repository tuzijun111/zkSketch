//! RQ3 — Pattern-A / Pattern-B optimisation runner (paper §Evaluation `sec:rq3`).
//!
//! `cargo run --release --example exp_rq3`
//! Knob: `V3_SWEEP_THREADS`. Writes `results/rq3*.csv`.

use zksketch::experiments::{resolve_threads, rq3_optimisations, with_pool};

fn main() {
    let (n, label) = resolve_threads();
    println!("zkSketch — RQ3 Optimisations   [{label}]");
    println!("============================================");
    with_pool(n, || {
        for t in rq3_optimisations::run() {
            t.emit();
        }
    });
    println!("\nRQ3 done. Plot with: python3 scripts/plot_experiments.py");
}
