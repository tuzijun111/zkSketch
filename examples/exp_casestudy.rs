//! End-to-end case study runner (paper §Evaluation `sec:rq5-casestudy`).
//!
//! `cargo run --release --example exp_casestudy`
//! Uses the fetched AOL/Netflix datasets when present (run
//! `python3 scripts/fetch_datasets.py` first), else synthetic streams.
//! Knobs: `EXP_CASE_EPOCHS`, `V3_SWEEP_THREADS`. Writes `results/casestudy*.csv`.

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
