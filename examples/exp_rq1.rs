//! RQ1 capability runner; writes results/rq1*.csv.
//! Usage: [EXP_RQ1_EPOCHS=.. EXP_RQ1_TRIALS=.. V3_SWEEP_THREADS=..] cargo run --release --example exp_rq1

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
