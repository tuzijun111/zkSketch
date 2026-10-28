//! RQ4 composition topology and maintenance-policy runner; writes results/rq4*.csv.
//! Usage: [EXP_RQ4_MAX_E=..] cargo run --release --example exp_rq4

use zksketch::experiments::rq4_topology;

fn main() {
    println!("zkSketch — RQ4 Topology + Policy");
    println!("================================");
    for t in rq4_topology::run() {
        t.emit();
    }
    println!("\nRQ4 done. Plot with: python3 scripts/plot_experiments.py");
}
