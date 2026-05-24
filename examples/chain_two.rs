//! Demo: side-by-side comparison of the §4.1 flat chain (Phase 1) and the
//! §4.2 recursive merge (Phase 1.5).
//!
//! Run with: `cargo run --release --example chain_two`.

use std::time::Instant;

use zksketch::prover::{Boundary, prove_fib_leaf, verify_fib_leaf};
use zksketch::recursion::flat::{merge_two as flat_merge_two, verify_chain as flat_verify_chain};
use zksketch::recursion::recursive::{
    merge_two as rec_merge_two, prove_leaf as prove_recursive_leaf,
    verify_chain as rec_verify_chain,
};

fn main() {
    println!("zkSketch — two-leaf chain demo");
    println!("==============================");
    println!();
    println!("Comparing two recursive-composition strategies on two adjacent");
    println!("epochs of a toy Fibonacci-style transition:");
    println!("  - flat chain (§4.1): bundle two leaf STARKs, re-verify each");
    println!("  - recursive merge (§4.2): one aggregated STARK certifies both");
    println!();

    // ---------------------------------------------------------------
    // §4.1 — flat chain over uni-stark FibAir leaves.
    // ---------------------------------------------------------------
    println!("--- Phase 1: §4.1 flat chain (uni-stark FibAir) ---");

    let t = Instant::now();
    let f1 = prove_fib_leaf(Boundary::new(0, 1), 6).expect("flat prove l1");
    let flat_prove_l1 = t.elapsed();
    let f1_size = serialized_size(&f1.proof);

    let t = Instant::now();
    verify_fib_leaf(&f1).expect("flat verify l1");
    let flat_verify_l1 = t.elapsed();

    let t = Instant::now();
    let f2 = prove_fib_leaf(f1.final_, 6).expect("flat prove l2");
    let flat_prove_l2 = t.elapsed();
    let f2_size = serialized_size(&f2.proof);

    let t = Instant::now();
    verify_fib_leaf(&f2).expect("flat verify l2");
    let flat_verify_l2 = t.elapsed();

    let t = Instant::now();
    let flat_chain = flat_merge_two(f1, f2).expect("flat merge");
    let flat_merge = t.elapsed();

    let t = Instant::now();
    flat_verify_chain(&flat_chain).expect("flat verify chain");
    let flat_verify_chain_time = t.elapsed();

    println!("  leaf 1: prove {:>10.2?}   verify {:>8.2?}   proof {:>6} bytes",
        flat_prove_l1, flat_verify_l1, f1_size);
    println!("  leaf 2: prove {:>10.2?}   verify {:>8.2?}   proof {:>6} bytes",
        flat_prove_l2, flat_verify_l2, f2_size);
    println!("  merge:  build {:>10.2?}", flat_merge);
    println!("  chain:  verify {:>9.2?}   ({} leaves re-verified)",
        flat_verify_chain_time, flat_chain.leaves.len());
    println!();

    // ---------------------------------------------------------------
    // §4.2 — recursive merge over CircuitBuilder leaves.
    // ---------------------------------------------------------------
    println!("--- Phase 1.5: §4.2 recursive merge (CircuitBuilder Fibonacci) ---");

    let t = Instant::now();
    let r1 = prove_recursive_leaf(Boundary::new(0, 1));
    let rec_prove_l1 = t.elapsed();
    let r1_size = serialized_size(&r1.output.0);

    let t = Instant::now();
    let r2 = prove_recursive_leaf(r1.final_);
    let rec_prove_l2 = t.elapsed();
    let r2_size = serialized_size(&r2.output.0);

    let t = Instant::now();
    let rec_chain = rec_merge_two(&r1, &r2).expect("recursive merge");
    let rec_merge_time = t.elapsed();
    let rec_chain_size = serialized_size(&rec_chain.recursive_proof.0);

    let t = Instant::now();
    rec_verify_chain(&rec_chain).expect("recursive verify");
    let rec_verify_time = t.elapsed();

    println!("  leaf 1: prove {:>10.2?}   proof {:>6} bytes", rec_prove_l1, r1_size);
    println!("  leaf 2: prove {:>10.2?}   proof {:>6} bytes", rec_prove_l2, r2_size);
    println!("  merge:  prove {:>10.2?}   proof {:>6} bytes", rec_merge_time, rec_chain_size);
    println!("  chain:  verify {:>9.2?}   (one batch-STARK, O(1) regardless of leaf count)",
        rec_verify_time);
    println!();

    println!("--- Summary ---");
    println!("§4.1 flat chain re-runs each leaf STARK natively (verifier work Θ(E)).");
    println!("§4.2 recursive merge produces ONE batch-STARK that certifies both leaves;");
    println!("verifier work is O(1) regardless of leaf count. The aggregation prover");
    println!("step dominates the prove time (one verifier circuit instantiated for the");
    println!("inner STARK), so it's much heavier than the leaf-only proof — that's the");
    println!("standard prover/verifier tradeoff the paper's §4 discusses.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value)
        .map(|v| v.len())
        .unwrap_or(0)
}
