//! HyperLogLog leaf prove time and proof size over a small (b, batch) grid.
//! Usage: cargo run --release --example hll_sweep

use std::time::Instant;

use zksketch::recursion::recursive::hll_leaf::{HllLeafParams, prove_hll_leaf_with_params};
use zksketch::sketch::Sketch;
use zksketch::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogUpdate};

fn run(params: HllLeafParams) {
    params.validate();
    let HllLeafParams { b, batch } = params;
    let m = params.m();

    let initial = HyperLogLog::new(&HyperLogLogParams { b });
    // Deterministic but varied batch.
    let records: Vec<HyperLogLogUpdate> = (0..batch)
        .map(|i| HyperLogLogUpdate {
            key: (i as u64).wrapping_mul(0x9E37_79B9) ^ ((m * batch) as u64),
        })
        .collect();

    let t = Instant::now();
    let leaf = prove_hll_leaf_with_params(params, initial, records);
    let prove_time = t.elapsed();
    let proof_size = serialized_size(&leaf.output.0);

    println!(
        "  b={:>2}  m={:>4}  batch={:>3}  prove {:>10.2?}  proof {:>7} bytes",
        b, m, batch, prove_time, proof_size
    );
}

fn main() {
    println!("zkSketch — HyperLogLog workload sweep (Phase 4c)");
    println!("=================================================");
    println!();
    println!("Measures leaf prove time + proof size as a function of (b, batch).");
    println!("The §5.1 strawman pays per-register bit-decomp + per-record max-correctness");
    println!("constraints, so witness scales roughly with m * batch * REGISTER_WIDTH (6).");
    println!();

    let grid: Vec<HllLeafParams> = vec![
        // Baseline (matches Phase 4 demos).
        HllLeafParams { b: 3, batch: 2 },
        // Vary batch at fixed m.
        HllLeafParams { b: 3, batch: 4 },
        HllLeafParams { b: 3, batch: 8 },
        // Vary m at fixed batch.
        HllLeafParams { b: 4, batch: 2 },
        HllLeafParams { b: 5, batch: 2 },
        // Combined.
        HllLeafParams { b: 4, batch: 4 },
        HllLeafParams { b: 5, batch: 4 },
    ];

    for params in grid {
        run(params);
    }

    println!();
    println!("--- Takeaway ---");
    println!("Prove time grows with m * batch (the dominant cost in the §5.1 strawman),");
    println!("with REGISTER_WIDTH bit-decomp constraints per register per candidate.");
    println!("Appendix F (Phase 4d) replaces the per-register loop with a wide-output");
    println!("Poseidon2 + batched IPA/KZG patch, reducing the per-record cost.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
