//! HyperLogLog recursive chain over E = 2, 4, 8 leaves: prove and verify time, proof size.
//! Usage: cargo run --release --example hll_chain_n

use std::time::Instant;

use zksketch::recursion::recursive::hll_chain::HllChainState;
use zksketch::recursion::recursive::hll_leaf::{B, prove_hll_leaf};
use zksketch::recursion::recursive::hll_merge::verify_chain_hll;
use zksketch::sketch::Sketch;
use zksketch::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogState, HyperLogLogUpdate};

fn empty_state() -> HyperLogLogState {
    HyperLogLog::new(&HyperLogLogParams { b: B })
}

fn build_batches(e: usize) -> Vec<[HyperLogLogUpdate; 2]> {
    (0..e)
        .map(|i| {
            let base = (i as u64).wrapping_mul(0x9E37_79B9) ^ 0xDEAD_BEEF;
            [
                HyperLogLogUpdate { key: base },
                HyperLogLogUpdate { key: base.wrapping_add(0xC0FFEE) },
            ]
        })
        .collect()
}

fn run_chain_at(e: usize) {
    assert!(e >= 2, "chain length must be at least 2");
    let batches = build_batches(e);

    let mut state = empty_state();
    let mut leaves = Vec::with_capacity(e);
    let mut total_leaf_prove = std::time::Duration::ZERO;
    let mut total_leaf_proof_bytes = 0usize;
    for batch in &batches {
        let t = Instant::now();
        let leaf = prove_hll_leaf(state.clone(), *batch);
        total_leaf_prove += t.elapsed();
        total_leaf_proof_bytes += serialized_size(&leaf.output.0);
        for u in batch {
            HyperLogLog::update(&mut state, u);
        }
        leaves.push(leaf);
    }

    let mut iter = leaves.iter();
    let l1 = iter.next().unwrap();
    let l2 = iter.next().unwrap();

    let t = Instant::now();
    let mut chain = HllChainState::init(l1, l2).expect("init");
    let mut total_merge_prove = t.elapsed();
    let mut merge_times = vec![total_merge_prove];

    for next in iter {
        let t = Instant::now();
        chain.extend(next).expect("extend");
        let dt = t.elapsed();
        total_merge_prove += dt;
        merge_times.push(dt);
    }

    let t = Instant::now();
    verify_chain_hll(&chain.root).expect("verify");
    let verify_time = t.elapsed();

    let chain_proof_size = serialized_size(&chain.root.recursive_proof.0);
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
    println!("  flat-baseline size:   {} bytes ({}\u{00D7} recursive)",
        flat_proof_size_estimate,
        flat_proof_size_estimate as f64 / chain_proof_size.max(1) as f64);
    println!();
}

fn main() {
    println!("zkSketch — HyperLogLog recursive chain sweep (Phase 4c)");
    println!("========================================================");
    println!();
    println!("(b, m) = ({B}, {}), batch = 2 records per epoch.", 1usize << B);
    println!();
    println!("Each `E` builds a chain `init(l1, l2)` then `extend(l_k)` for k = 3..=E.");
    println!("Verifier cost should stay roughly flat across E — that's the O(1) claim,");
    println!("now exercised on HLL (Pattern A max) just like Count-Min (Pattern A linear).");
    println!();

    for &e in &[2usize, 4, 8] {
        run_chain_at(e);
    }

    println!("--- Takeaway ---");
    println!("The `chain verify` and `recursive proof size` rows should be roughly the");
    println!("same across E. The `flat-baseline size` row scales linearly with E,");
    println!("so the size ratio (flat / recursive) grows linearly too. The §4.2");
    println!("merge atom is sketch-agnostic — same O(1) claim, same verifier cost.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
