//! Side-by-side comparison of the §4.1 flat chain and the §4.2 recursive
//! merge on the **real** Count-Min sketch — Phase 3a demo.
//!
//! Runs both paths on the same two Count-Min update epochs (`d = 2`,
//! `w = 4`, batch = 2 records), prints prove times, merge times, verify
//! times, and proof sizes, and ends with a one-line summary of the
//! observed asymptotic delta.
//!
//! Run with: `cargo run --release --example countmin_chain_two`.

use std::time::Instant;

use zksketch::recursion::countmin_flat::{
    flat_merge_two_countmin, verify_chain_flat_countmin,
};
use zksketch::recursion::recursive::countmin_leaf::{D, W, prove_countmin_leaf};
use zksketch::recursion::recursive::countmin_merge::{
    merge_two_countmin, verify_chain_countmin,
};
use zksketch::sketch::Sketch;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};

fn main() {
    println!("zkSketch — Count-Min two-leaf chain demo (Phase 3a)");
    println!("====================================================");
    println!();
    println!("(d, w) = ({D}, {W}), batch = 2 records per epoch.");
    println!();
    println!("Comparing two recursive-composition strategies on the same");
    println!("two Count-Min update epochs:");
    println!("  - §4.1 flat chain: bundle two leaf batch-STARKs, re-verify each");
    println!("  - §4.2 recursive merge: one aggregated batch-STARK certifies both");
    println!();

    // ---------------------------------------------------------------
    // Set up two adjacent epochs against the same starting state.
    // ---------------------------------------------------------------
    let s0 = CountMin::new(&CountMinParams { d: D, w: W });
    let b1 = [
        CountMinUpdate { key: 42, value: 7 },
        CountMinUpdate { key: 99, value: 1 },
    ];
    let mut s1 = s0.clone();
    for u in &b1 {
        CountMin::update(&mut s1, u);
    }
    let b2 = [
        CountMinUpdate { key: 42, value: 3 },
        CountMinUpdate { key: 7, value: 9 },
    ];

    // ---------------------------------------------------------------
    // Prove each leaf once. We prove twice total (once per leaf) and
    // reuse the resulting proofs for both flat and recursive paths.
    // ---------------------------------------------------------------
    let t = Instant::now();
    let l1_flat = prove_countmin_leaf(s0.clone(), b1);
    let prove_l1 = t.elapsed();
    let l1_size = serialized_size(&l1_flat.output.0);

    let t = Instant::now();
    let l2_flat = prove_countmin_leaf(s1.clone(), b2);
    let prove_l2 = t.elapsed();
    let l2_size = serialized_size(&l2_flat.output.0);

    // Make another pair for the recursive path. The leaf proof is the
    // same logically — proving twice is a fair cost both paths must pay,
    // and keeps the two paths' inputs structurally independent.
    let l1_rec = prove_countmin_leaf(s0, b1);
    let l2_rec = prove_countmin_leaf(s1, b2);

    // ---------------------------------------------------------------
    // §4.1 flat chain (Phase 3a).
    // ---------------------------------------------------------------
    println!("--- §4.1 flat chain (Count-Min, Phase 3a) ---");

    let t = Instant::now();
    let flat_chain = flat_merge_two_countmin(l1_flat, l2_flat).expect("flat merge");
    let flat_merge_time = t.elapsed();

    let t = Instant::now();
    verify_chain_flat_countmin(&flat_chain).expect("flat verify");
    let flat_verify_time = t.elapsed();

    let flat_chain_size: usize = flat_chain
        .leaves
        .iter()
        .map(|l| serialized_size(&l.output.0))
        .sum();

    println!("  leaf 1: prove {:>10.2?}   proof {:>6} bytes", prove_l1, l1_size);
    println!("  leaf 2: prove {:>10.2?}   proof {:>6} bytes", prove_l2, l2_size);
    println!("  merge:  bundle {:>9.2?}                       (digest combined)", flat_merge_time);
    println!("  chain:  verify {:>9.2?}   ({} leaves re-verified \u{2014} Θ(E))",
        flat_verify_time, flat_chain.leaves.len());
    println!("  total proof size: {} bytes (sum of both leaf proofs)", flat_chain_size);
    println!();

    // ---------------------------------------------------------------
    // §4.2 recursive merge (Phase 2c).
    // ---------------------------------------------------------------
    println!("--- §4.2 recursive merge (Count-Min, Phase 2c) ---");

    let t = Instant::now();
    let rec_chain = merge_two_countmin(&l1_rec, &l2_rec).expect("recursive merge");
    let rec_merge_time = t.elapsed();
    let rec_chain_size = serialized_size(&rec_chain.recursive_proof.0);

    let t = Instant::now();
    verify_chain_countmin(&rec_chain).expect("recursive verify");
    let rec_verify_time = t.elapsed();

    println!("  leaf 1: prove {:>10.2?}   proof {:>6} bytes",
        prove_l1, serialized_size(&l1_rec.output.0));
    println!("  leaf 2: prove {:>10.2?}   proof {:>6} bytes",
        prove_l2, serialized_size(&l2_rec.output.0));
    println!("  merge:  prove {:>10.2?}   proof {:>6} bytes", rec_merge_time, rec_chain_size);
    println!("  chain:  verify {:>9.2?}   (one batch-STARK, O(1) regardless of leaf count)",
        rec_verify_time);
    println!();

    // ---------------------------------------------------------------
    // Summary.
    // ---------------------------------------------------------------
    let ratio = flat_verify_time.as_nanos() as f64 / rec_verify_time.as_nanos().max(1) as f64;
    let size_ratio =
        flat_chain_size as f64 / (rec_chain_size as f64).max(1.0);
    println!("--- Summary ---");
    println!("§4.1 verifier cost scales \u{0398}(E) in leaf count; §4.2 stays O(1).");
    println!("At E = 2 the verifier costs and proof sizes are:");
    println!("  flat:      verify {:>9.2?}   proof size {} bytes", flat_verify_time, flat_chain_size);
    println!("  recursive: verify {:>9.2?}   proof size {} bytes", rec_verify_time, rec_chain_size);
    println!("  flat / recursive: verify {:.2}×, proof {:.2}×", ratio, size_ratio);
    println!();
    println!("The recursive prove cost ({:.2?}) is much larger than flat's bundle ({:.2?}) \u{2014}",
        rec_merge_time, flat_merge_time);
    println!("that's the standard prover/verifier trade-off the paper's §4 discusses.");
    println!("As E grows, the flat verifier cost climbs linearly (and total proof size");
    println!("with it) while the recursive verifier cost stays roughly flat \u{2014} that's");
    println!("where the §4.2 atom pays off, especially for E \u{226B} 2.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
