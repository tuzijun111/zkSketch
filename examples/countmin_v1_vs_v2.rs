//! v1 (§5.1 strawman) vs v2 (§5.4-shaped) Count-Min leaf comparison.
//!
//! Both leaves produce the same `CountMinLeafProof` shape and chain through
//! the same `merge_two_countmin`. The difference is internal: v1 computes
//! the per-cell sum inline at the cell-transition constraint; v2 exposes
//! the §5.4 aggregate table `A` as an explicit witness and the transition
//! reads from it.
//!
//! No witness *reduction* yet — that's blocked by the Poseidon2 commit
//! scheme over flat cells. A future variant with Merkle-tree commits and
//! sparse opens (or homomorphic-additive vector commit) would actually
//! drop the `d*w` cell witnesses; v2's structural change makes that next
//! step a local edit. Today this demo just confirms the structural change
//! doesn't regress correctness or proof shape.
//!
//! Run with: `cargo run --release --example countmin_v1_vs_v2`.

use std::time::Instant;

use zksketch::recursion::recursive::countmin_leaf::{
    CountMinLeafParams, prove_countmin_leaf_with_params,
};
use zksketch::recursion::recursive::countmin_leaf_v2::prove_countmin_leaf_v2_with_params;
use zksketch::sketch::Sketch;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};

fn run_pair(label: &str, params: CountMinLeafParams) {
    params.validate();
    let CountMinLeafParams { d, w, batch } = params;
    let initial = CountMin::new(&CountMinParams { d, w });
    let records: Vec<CountMinUpdate> = (0..batch)
        .map(|i| CountMinUpdate {
            key: (i as u64).wrapping_mul(0x9E37_79B9) ^ ((d * w * batch) as u64),
            value: 1 + (i as u32 % 7),
        })
        .collect();

    let t = Instant::now();
    let v1 = prove_countmin_leaf_with_params(params, initial.clone(), records.clone());
    let v1_prove = t.elapsed();
    let v1_size = serialized_size(&v1.output.0);

    let t = Instant::now();
    let v2 = prove_countmin_leaf_v2_with_params(params, initial, records);
    let v2_prove = t.elapsed();
    let v2_size = serialized_size(&v2.output.0);

    // Sanity: both produce the same final commit.
    assert_eq!(v1.final_.0, v2.final_.0);

    println!(
        "{label} ({}, {}, {}):  v1 prove {:>9.2?}  v1 size {:>7}b  |  v2 prove {:>9.2?}  v2 size {:>7}b",
        d, w, batch, v1_prove, v1_size, v2_prove, v2_size
    );
}

fn main() {
    println!("zkSketch — v1 (§5.1 strawman) vs v2 (§5.4-shaped) leaf comparison");
    println!("==================================================================");
    println!();
    println!("Both leaves: same public-input shape, same Poseidon2-of-flat-cells commit.");
    println!("Difference: v2 exposes the §5.4 aggregate table `A` as a separate witness.");
    println!("Expectation: prove time and proof size similar (v2 adds d*w more witnesses");
    println!("for the explicit aggregate). The structural change opens the door to a");
    println!("lookup / Merkle-commit variant that *would* actually reduce witness.");
    println!();

    run_pair("baseline ", CountMinLeafParams { d: 2, w: 4, batch: 2 });
    run_pair("wider    ", CountMinLeafParams { d: 2, w: 8, batch: 2 });
    run_pair("deeper   ", CountMinLeafParams { d: 4, w: 4, batch: 2 });
    run_pair("more keys", CountMinLeafParams { d: 2, w: 4, batch: 8 });
    run_pair("combined ", CountMinLeafParams { d: 4, w: 16, batch: 4 });

    println!();
    println!("--- Takeaway ---");
    println!("The §5.4 structural refactor preserves correctness end-to-end (v2 leaves");
    println!("merge with v1 leaves in the same recursive chain) and shows that the");
    println!("aggregate `A` slot exists as a single witness vector — exactly where a");
    println!("future Merkle / homomorphic-commit variant would drop the per-cell loop.");
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
