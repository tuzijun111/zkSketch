//! RQ2 scalability runner; writes results/rq2*.csv.
//! Usage: [EXP_RQ2_MAX_E=.. V3_SWEEP_THREADS=..] cargo run --release --example exp_rq2

use zksketch::experiments::{resolve_threads, rq2_scalability, with_pool};

fn main() {
    let (n, label) = resolve_threads();
    println!("zkSketch — RQ2 Scalability   [{label}]");
    println!("==========================================");
    with_pool(n, || {
        for t in rq2_scalability::run() {
            t.emit();
        }
    });
    println!("\nRQ2 done. Plot with: python3 scripts/plot_experiments.py");
}
