//! Two toy Fibonacci leaves merged by the flat chain and verified.

use zksketch::prover::{Boundary, prove_fib_leaf};
use zksketch::recursion::{merge_two, verify_chain};

#[test]
fn honest_two_leaf_chain_end_to_end() {
    // First epoch — start from the natural Fibonacci seed.
    let l1 = prove_fib_leaf(Boundary::new(0, 1), 4).expect("prove leaf 1");
    // Second epoch — start exactly where leaf 1 left off.
    let l2 = prove_fib_leaf(l1.final_, 4).expect("prove leaf 2");

    let chain = merge_two(l1, l2).expect("merge two leaves");
    verify_chain(&chain).expect("verify chain");
}

#[test]
fn mismatched_boundary_is_rejected_at_merge() {
    let l1 = prove_fib_leaf(Boundary::new(0, 1), 4).expect("prove leaf 1");
    // Wrong starting boundary for leaf 2 — should fail the §4.2 shared-boundary
    // check (performed natively in Phase 1).
    let l2 = prove_fib_leaf(Boundary::new(99, 100), 4).expect("prove leaf 2");

    match merge_two(l1, l2) {
        Err(zksketch::recursion::MergeError::BoundaryMismatch { .. }) => {}
        Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
        Ok(_) => panic!("merge must reject mismatched boundary"),
    }
}
