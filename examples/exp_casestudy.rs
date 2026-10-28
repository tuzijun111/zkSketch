//! End-to-end case study on the Gaussian and Uniform streams, plus AOL/Netflix when fetched; writes results/casestudy*.csv.
//! Usage: [EXP_CASE_EPOCHS=4 V3_SWEEP_THREADS=n] cargo run --release --example exp_casestudy

use zksketch::experiments::{casestudy, resolve_threads, with_pool};

fn main() {
    let (n, label) = resolve_threads();
    println!("zkSketch — End-to-End Case Study   [{label}]");
    println!("=================================================");
    with_pool(n, || {
        for t in casestudy::run() {
            t.emit();
        }
    });
    println!("\nCase study done. Plot with: python3 scripts/plot_experiments.py");
}
