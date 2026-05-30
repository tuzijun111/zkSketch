//! RQ4 — Composition topology + maintenance policy runner
//! (paper §Evaluation `sec:rq4`).
//!
//! `cargo run --release --example exp_rq4`
//! Knob: `EXP_RQ4_MAX_E` (max audit window). Writes `results/rq4*.csv`.
//! Composition is leaf-shape-agnostic, so this runs in milliseconds.

use zksketch::experiments::rq4_topology;

fn main() {
    println!("zkSketch — RQ4 Topology + Policy");
    println!("================================");
    for t in rq4_topology::run() {
        t.emit();
    }
    println!("\nRQ4 done. Plot with: python3 scripts/plot_experiments.py");
}
