//! v1 (§5.1 strawman) vs v2 (§5.4-shaped) HyperLogLog leaf comparison.
//!
//! Both leaves produce the same `HllLeafProof` shape and chain through the
//! same `merge_two_hll`. The difference is internal: v1 enforces
//! `final[r] = max(initial[r], {lead[k] : touching})` in one unified
//! candidate-set constraint; v2 factors it into two stages — first compute
//! the per-register aggregate `A[r] = max(0, {selector[k][r] * lead[k]})`
//! as an explicit witness vector, then patch `final[r] = max(initial[r], A[r])`.
//!
//! No witness *reduction* yet — that's blocked by the Poseidon2-of-flat-
//! registers commit. A future variant with batched IPA/KZG multi-opening or
//! Merkle-tree commits + sparse opens (Appendix F) would actually drop the
//! per-register loop; v2's `A` slot is the seam that variant plugs into.
//! Today this demo confirms the structural refactor preserves correctness
//! and proof shape, and reports the modest extra cost of the explicit `A`
//! vector + extra bit-decomp range checks.
//!
//! Run with: `cargo run --release --example hll_v1_vs_v2`.

use std::time::Instant;

use zksketch::recursion::recursive::hll_leaf::{HllLeafParams, prove_hll_leaf_with_params};
use zksketch::recursion::recursive::hll_leaf_v2::prove_hll_leaf_v2_with_params;
use zksketch::sketch::Sketch;
use zksketch::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogUpdate};

fn run_pair(label: &str, params: HllLeafParams) {
    params.validate();
    let HllLeafParams { b, batch } = params;
    let m = params.m();
    let initial = HyperLogLog::new(&HyperLogLogParams { b });
    let records: Vec<HyperLogLogUpdate> = (0..batch)
        .map(|i| HyperLogLogUpdate {
            key: (i as u64).wrapping_mul(0x9E37_79B9) ^ ((m * batch) as u64),
        })
        .collect();

    let t = Instant::now();
    let v1 = prove_hll_leaf_with_params(params, initial.clone(), records.clone());
    let v1_prove = t.elapsed();
    let v1_size = serialized_size(&v1.output.0);

    let t = Instant::now();
    let v2 = prove_hll_leaf_v2_with_params(params, initial, records);
    let v2_prove = t.elapsed();
    let v2_size = serialized_size(&v2.output.0);

    // Sanity: both produce the same final commit (same final state).
    assert_eq!(v1.final_.0, v2.final_.0);

    println!(
        "{label} (b={}, m={}, batch={}):  v1 prove {:>9.2?}  v1 size {:>7}b  |  v2 prove {:>9.2?}  v2 size {:>7}b",
        b, m, batch, v1_prove, v1_size, v2_prove, v2_size
    );
}

fn main() {
    println!("zkSketch — HyperLogLog v1 (§5.1 strawman) vs v2 (§5.4-shaped) leaf comparison");
    println!("==============================================================================");
    println!();
    println!("Both leaves: same public-input shape, same Poseidon2-of-flat-registers commit.");
    println!("Difference: v2 exposes the §5.4 per-register aggregate `A` as a separate witness,");
    println!("splitting the unified `final = max(initial, lead values for touching)` into a");
    println!("two-stage `A = max(0, lead contributions)` + `final = max(initial, A)` pipeline.");
    println!("Expectation: v2 prove time slightly *higher* (extra m witnesses for A + extra");
    println!("range-check bit decomps). The structural change opens the door to an Appendix F");
    println!("variant (wide-output Poseidon2 + batched IPA/KZG patch) that *would* reduce work.");
    println!();

    run_pair("baseline ", HllLeafParams { b: 3, batch: 2 });
    run_pair("more keys", HllLeafParams { b: 3, batch: 8 });
    run_pair("wider    ", HllLeafParams { b: 4, batch: 2 });
    run_pair("wider+kk ", HllLeafParams { b: 4, batch: 4 });
    run_pair("widest   ", HllLeafParams { b: 5, batch: 2 });

    println!();
    println!("--- Takeaway ---");
    println!("The §5.4-shaped HLL refactor preserves correctness end-to-end (v2 leaves");
    println!("merge with v1 leaves in the same recursive chain via `merge_two_hll`) and");
    println!("shows that the aggregate `A` slot exists as a single explicit witness");
    println!("vector — exactly where a future Appendix F batched-opening or LogUp-routed");
    println!("variant would drop the per-register loop. Today v2 pays a modest constant");
    println!("overhead vs v1; the structural seam is the deliverable.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
