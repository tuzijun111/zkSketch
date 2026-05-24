//! Multi-leaf §4.3 recursive chain sweep on Count-Min.
//!
//! Builds chains of length `E ∈ {2, 4, 8}` and prints prove time per
//! merge, total prove time, verify time, and proof size at each `E`.
//! Compared to the `examples/countmin_chain_two.rs` demo, this is where
//! the paper's central `O(1)` verifier claim should become visible: as
//! `E` grows, the recursive chain's verify cost stays roughly flat while
//! a hypothetical flat baseline would scale linearly.
//!
//! Run with: `cargo run --release --example countmin_chain_n`.

use std::time::Instant;

use zksketch::recursion::recursive::countmin_chain::CountMinChainState;
use zksketch::recursion::recursive::countmin_leaf::{D, W, prove_countmin_leaf};
use zksketch::recursion::recursive::countmin_merge::verify_chain_countmin;
use zksketch::sketch::Sketch;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinState, CountMinUpdate};

fn empty_state() -> CountMinState {
    CountMin::new(&CountMinParams { d: D, w: W })
}

fn build_batches(e: usize) -> Vec<[CountMinUpdate; 2]> {
    (0..e)
        .map(|i| {
            let base = (i as u64) * 13 + 1;
            [
                CountMinUpdate { key: base, value: 3 },
                CountMinUpdate { key: base + 7, value: 5 },
            ]
        })
        .collect()
}

fn run_chain_at(e: usize) {
    assert!(e >= 2, "chain length must be at least 2");
    let batches = build_batches(e);

    // Prove all E leaves natively first; track total leaf-prove time.
    let mut state = empty_state();
    let mut leaves = Vec::with_capacity(e);
    let mut total_leaf_prove = std::time::Duration::ZERO;
    let mut total_leaf_proof_bytes = 0usize;
    for batch in &batches {
        let t = Instant::now();
        let leaf = prove_countmin_leaf(state.clone(), *batch);
        total_leaf_prove += t.elapsed();
        total_leaf_proof_bytes += serialized_size(&leaf.output.0);
        // Advance the plaintext state for the next leaf's `initial`.
        for u in batch {
            CountMin::update(&mut state, u);
        }
        leaves.push(leaf);
    }

    // Merge chain: init(l1, l2), then E-2 extends.
    let mut iter = leaves.iter();
    let l1 = iter.next().unwrap();
    let l2 = iter.next().unwrap();

    let t = Instant::now();
    let mut chain = CountMinChainState::init(l1, l2).expect("init");
    let mut total_merge_prove = t.elapsed();
    let mut merge_times = vec![total_merge_prove];

    for next in iter {
        let t = Instant::now();
        chain.extend(next).expect("extend");
        let dt = t.elapsed();
        total_merge_prove += dt;
        merge_times.push(dt);
    }

    // Verify and time it.
    let t = Instant::now();
    verify_chain_countmin(&chain.root).expect("verify");
    let verify_time = t.elapsed();

    let chain_proof_size = serialized_size(&chain.root.recursive_proof.0);
    // Hypothetical §4.1 baseline: re-verify each leaf independently.
    // We can estimate the verify cost as E × (per-leaf verify), but the
    // most honest measure is "E leaves' proofs bundled", whose size is the
    // sum of leaf proof bytes.
    let flat_proof_size_estimate = total_leaf_proof_bytes;

    println!("E = {e}:");
    println!("  leaves:   {} prove + {} merges = {} aggregator runs",
        e, e - 1, e - 1);
    println!("  leaf prove total:     {:>10.2?}   ({:>8.2?} per leaf avg)",
        total_leaf_prove, total_leaf_prove / e as u32);
    println!("  merge prove total:    {:>10.2?}   ({:>8.2?} per merge avg)",
        total_merge_prove, total_merge_prove / (e as u32 - 1));
    let merge_list: Vec<String> = merge_times.iter().map(|d| format!("{:.2?}", d)).collect();
    println!("  merge prove sequence: [{}]", merge_list.join(", "));
    println!("  chain verify:         {:>10.2?}", verify_time);
    println!("  recursive proof size: {} bytes", chain_proof_size);
    println!("  flat-baseline size:   {} bytes ({}× recursive)",
        flat_proof_size_estimate,
        flat_proof_size_estimate as f64 / chain_proof_size.max(1) as f64);
    println!();
}

fn main() {
    println!("zkSketch — Count-Min recursive chain sweep (Phase 3b)");
    println!("======================================================");
    println!();
    println!("(d, w) = ({D}, {W}), batch = 2 records per epoch.");
    println!();
    println!("Each `E` builds a chain `init(l1, l2)` then `extend(l_k)` for k = 3..=E.");
    println!("Verifier cost should stay roughly flat across E — that's the O(1) claim.");
    println!("Recursive proof size also stays roughly flat (one batch-STARK regardless of E).");
    println!();

    for &e in &[2usize, 4, 8] {
        run_chain_at(e);
    }

    println!("--- Takeaway ---");
    println!("The `chain verify` and `recursive proof size` rows should be roughly the");
    println!("same across E. The `flat-baseline size` row scales linearly with E,");
    println!("so the size ratio (flat / recursive) grows linearly too — that's where");
    println!("§4.2 wins as the chain extends.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
