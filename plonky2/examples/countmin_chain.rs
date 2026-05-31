//! Side-by-side demo: §4.1 flat chain vs §4.2 recursive merge vs §4.3 chain,
//! on real Count-Min update epochs. Mirrors `../examples/countmin_chain_two.rs`.
//!
//! Run with:  `cargo run --release --example countmin_chain`

use std::time::Instant;

use anyhow::Result;
use zksketch_snark::leaf::countmin::{build_countmin_leaf, CmLeafParams};
use zksketch_snark::recursion::{flat_verify, merge, verify_node};
use zksketch_snark::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};

fn b(k0: u64, v0: u64, k1: u64, v1: u64) -> Vec<CountMinUpdate> {
    vec![
        CountMinUpdate { key: k0, value: v0 },
        CountMinUpdate { key: k1, value: v1 },
    ]
}

fn main() -> Result<()> {
    let params = CmLeafParams { d: 2, w: 4, batch: 2 };
    println!(
        "=== Count-Min recursive proofs on plonky2 (d={}, w={}, batch={}) ===\n",
        params.d, params.w, params.batch
    );

    let t = Instant::now();
    let leaf = build_countmin_leaf(params);
    println!("leaf circuit built in {:?}\n", t.elapsed());

    // Three adjacent epochs threaded by their boundary states.
    let s0 = CountMinState::new(&CountMinParams { d: 2, w: 4 });
    let (e1, e2, e3) = (b(7, 3, 11, 5), b(7, 1, 13, 9), b(2, 4, 9, 6));

    let t = Instant::now();
    let n1 = leaf.prove(&s0, &e1, 1)?;
    println!("leaf 1: prove {:?}   proof {} bytes", t.elapsed(), n1.proof.to_bytes().len());

    let mut s1 = s0.clone();
    for u in &e1 {
        s1.update(u);
    }
    let t = Instant::now();
    let n2 = leaf.prove(&s1, &e2, 2)?;
    println!("leaf 2: prove {:?}   proof {} bytes", t.elapsed(), n2.proof.to_bytes().len());

    let mut s2 = s1.clone();
    for u in &e2 {
        s2.update(u);
    }
    let n3 = leaf.prove(&s2, &e3, 3)?;

    let nodes = vec![n1, n2];

    // §4.1 flat baseline: verify each leaf natively + boundary + digest. Θ(E).
    let t = Instant::now();
    let flat_digest = flat_verify(&nodes)?;
    println!("\n§4.1 flat:      verify {:?}   (re-verifies every leaf — Θ(E))", t.elapsed());

    // §4.2 recursive merge: one aggregated proof. O(1) verify.
    let t = Instant::now();
    let root = merge(&nodes[0], &nodes[1])?;
    println!(
        "§4.2 merge:     prove  {:?}   proof {} bytes",
        t.elapsed(),
        root.proof.to_bytes().len()
    );
    let t = Instant::now();
    verify_node(&root)?;
    println!("§4.2 recursive: verify {:?}   (one proof — O(1) regardless of E)", t.elapsed());
    println!("   flat and recursive root digests match: {}", root.digest == flat_digest);

    // §4.3 chain extension: fold leaf 3 onto the running root.
    let root3 = merge(&root, &n3)?;
    verify_node(&root3)?;
    println!(
        "\n§4.3 chain:     root now covers leaves {:?}  (E={}),  proof {} bytes",
        root3.interval,
        root3.num_leaves(),
        root3.proof.to_bytes().len()
    );
    println!("   verify is still one O(1) proof check.");

    Ok(())
}
