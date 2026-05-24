//! Workload sweep on the Count-Min update leaf (Phase 3c).
//!
//! Scans a small grid of `(d, w, batch)` and reports leaf prove time and
//! proof size at each grid point. Recursive aggregation isn't measured
//! here — the per-leaf cost is what the workload-axis experiments
//! quantify (the merge cost is leaf-shape-agnostic).
//!
//! Run with: `cargo run --release --example countmin_sweep`.

use std::time::Instant;

use zksketch::recursion::recursive::countmin_leaf::{
    CountMinLeafParams, prove_countmin_leaf_with_params,
};
use zksketch::sketch::Sketch;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};

fn run(params: CountMinLeafParams) {
    params.validate();
    let CountMinLeafParams { d, w, batch } = params;

    let initial = CountMin::new(&CountMinParams { d, w });
    // Deterministic but varied batch.
    let records: Vec<CountMinUpdate> = (0..batch)
        .map(|i| CountMinUpdate {
            key: (i as u64).wrapping_mul(0x9E37_79B9) ^ ((d * w * batch) as u64),
            value: 1 + (i as u32 % 7),
        })
        .collect();

    let t = Instant::now();
    let leaf = prove_countmin_leaf_with_params(params, initial, records);
    let prove_time = t.elapsed();
    let proof_size = serialized_size(&leaf.output.0);

    println!(
        "  d={:>2}  w={:>3}  batch={:>3}  cells={:>4}  prove {:>10.2?}  proof {:>7} bytes",
        d, w, batch, d * w, prove_time, proof_size
    );
}

fn main() {
    println!("zkSketch — Count-Min workload sweep (Phase 3c)");
    println!("===============================================");
    println!();
    println!("Measures leaf prove time + proof size as a function of (d, w, batch).");
    println!("The §5.1 strawman pays per-cell-per-record constraints, so witness");
    println!("scales as Θ(d·w·batch). Watch the prove time climb accordingly.");
    println!();

    let grid: Vec<CountMinLeafParams> = vec![
        // Baseline (matches Phase 2/3a/3b demos).
        CountMinLeafParams { d: 2, w: 4, batch: 2 },
        // Vary one dimension at a time from baseline.
        CountMinLeafParams { d: 2, w: 4, batch: 4 },
        CountMinLeafParams { d: 2, w: 4, batch: 8 },
        CountMinLeafParams { d: 2, w: 8, batch: 2 },
        CountMinLeafParams { d: 2, w: 16, batch: 2 },
        CountMinLeafParams { d: 4, w: 4, batch: 2 },
        CountMinLeafParams { d: 8, w: 4, batch: 2 },
        // A larger combined point.
        CountMinLeafParams { d: 4, w: 16, batch: 8 },
    ];

    for params in grid {
        run(params);
    }

    println!();
    println!("--- Takeaway ---");
    println!("Prove time grows roughly linearly in d·w·batch (the strawman's witness");
    println!("count). This motivates Phase 3d: the §5.4 sort + segment-aggregate +");
    println!("sparse patch pipeline reduces the witness to O(m·d + T), where T is");
    println!("the touched-cell capacity (independent of w) and m is the batch.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
