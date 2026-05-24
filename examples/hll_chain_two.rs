//! Side-by-side comparison of the §4.1 flat chain and the §4.2 recursive
//! merge on **HyperLogLog** — Phase 4c analog of `countmin_chain_two`.
//!
//! Same shape as the Count-Min comparison demo: two adjacent HLL update
//! epochs (`b = 3`, `m = 8`, batch = 2 records) proven once each, then run
//! through both chain strategies. Prints prove times, merge/bundle times,
//! verify times, and proof sizes for both paths.
//!
//! Run with: `cargo run --release --example hll_chain_two`.

use std::time::Instant;

use zksketch::recursion::hll_flat::{flat_merge_two_hll, verify_chain_flat_hll};
use zksketch::recursion::recursive::hll_leaf::{B, prove_hll_leaf};
use zksketch::recursion::recursive::hll_merge::{merge_two_hll, verify_chain_hll};
use zksketch::sketch::Sketch;
use zksketch::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogUpdate};

fn main() {
    println!("zkSketch — HyperLogLog two-leaf chain demo (Phase 4c)");
    println!("=====================================================");
    println!();
    println!("(b, m) = ({B}, {}), batch = 2 records per epoch.", 1usize << B);
    println!();
    println!("Comparing two recursive-composition strategies on the same");
    println!("two HyperLogLog update epochs (Pattern A max, paper §5.3 / Appendix F):");
    println!("  - §4.1 flat chain: bundle two leaf batch-STARKs, re-verify each");
    println!("  - §4.2 recursive merge: one aggregated batch-STARK certifies both");
    println!();

    let s0 = HyperLogLog::new(&HyperLogLogParams { b: B });
    let b1 = [
        HyperLogLogUpdate { key: 0xDEAD_BEEF_0000_0042 },
        HyperLogLogUpdate { key: 0xC0FFEE_FACE_0099 },
    ];
    let mut s1 = s0.clone();
    for u in &b1 {
        HyperLogLog::update(&mut s1, u);
    }
    let b2 = [
        HyperLogLogUpdate { key: 0x1234_5678_9ABC_DEF0 },
        HyperLogLogUpdate { key: 0xCAFE_BABE_5555_AAAA },
    ];

    let t = Instant::now();
    let l1_flat = prove_hll_leaf(s0.clone(), b1);
    let prove_l1 = t.elapsed();
    let l1_size = serialized_size(&l1_flat.output.0);

    let t = Instant::now();
    let l2_flat = prove_hll_leaf(s1.clone(), b2);
    let prove_l2 = t.elapsed();
    let l2_size = serialized_size(&l2_flat.output.0);

    // Make another pair for the recursive path. Proving twice is a fair
    // cost both paths must pay, and keeps the paths' inputs independent.
    let l1_rec = prove_hll_leaf(s0, b1);
    let l2_rec = prove_hll_leaf(s1, b2);

    // §4.1 flat chain.
    println!("--- §4.1 flat chain (HyperLogLog, Phase 4c) ---");
    let t = Instant::now();
    let flat_chain = flat_merge_two_hll(l1_flat, l2_flat).expect("flat merge");
    let flat_merge_time = t.elapsed();
    let t = Instant::now();
    verify_chain_flat_hll(&flat_chain).expect("flat verify");
    let flat_verify_time = t.elapsed();
    let flat_chain_size: usize = flat_chain
        .leaves
        .iter()
        .map(|l| serialized_size(&l.output.0))
        .sum();

    println!("  leaf 1: prove {:>10.2?}   proof {:>6} bytes", prove_l1, l1_size);
    println!("  leaf 2: prove {:>10.2?}   proof {:>6} bytes", prove_l2, l2_size);
    println!("  merge:  bundle {:>9.2?}                       (digest combined)", flat_merge_time);
    println!("  chain:  verify {:>9.2?}   ({} leaves re-verified \u{2014} \u{0398}(E))",
        flat_verify_time, flat_chain.leaves.len());
    println!("  total proof size: {} bytes (sum of both leaf proofs)", flat_chain_size);
    println!();

    // §4.2 recursive merge.
    println!("--- §4.2 recursive merge (HyperLogLog, Phase 4c) ---");
    let t = Instant::now();
    let rec_chain = merge_two_hll(&l1_rec, &l2_rec).expect("recursive merge");
    let rec_merge_time = t.elapsed();
    let rec_chain_size = serialized_size(&rec_chain.recursive_proof.0);
    let t = Instant::now();
    verify_chain_hll(&rec_chain).expect("recursive verify");
    let rec_verify_time = t.elapsed();

    println!("  leaf 1: prove {:>10.2?}   proof {:>6} bytes",
        prove_l1, serialized_size(&l1_rec.output.0));
    println!("  leaf 2: prove {:>10.2?}   proof {:>6} bytes",
        prove_l2, serialized_size(&l2_rec.output.0));
    println!("  merge:  prove {:>10.2?}   proof {:>6} bytes", rec_merge_time, rec_chain_size);
    println!("  chain:  verify {:>9.2?}   (one batch-STARK, O(1) regardless of leaf count)",
        rec_verify_time);
    println!();

    let ratio = flat_verify_time.as_nanos() as f64 / rec_verify_time.as_nanos().max(1) as f64;
    let size_ratio = flat_chain_size as f64 / (rec_chain_size as f64).max(1.0);
    println!("--- Summary ---");
    println!("§4.1 verifier cost scales \u{0398}(E) in leaf count; §4.2 stays O(1).");
    println!("At E = 2 the verifier costs and proof sizes are:");
    println!("  flat:      verify {:>9.2?}   proof size {} bytes", flat_verify_time, flat_chain_size);
    println!("  recursive: verify {:>9.2?}   proof size {} bytes", rec_verify_time, rec_chain_size);
    println!("  flat / recursive: verify {:.2}\u{00D7}, proof {:.2}\u{00D7}", ratio, size_ratio);
    println!();
    println!("Same trade-off as Count-Min: the recursive prove cost ({:.2?}) is much",
        rec_merge_time);
    println!("larger than flat's bundle ({:.2?}), but the verifier cost stays flat", flat_merge_time);
    println!("as the chain extends — that's the §4.2 win for E \u{226B} 2.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
