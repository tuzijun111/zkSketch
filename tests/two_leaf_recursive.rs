//! Two toy Fibonacci leaves aggregated into one recursive proof and verified.

use zksketch::prover::Boundary;
use zksketch::recursion::recursive::{merge_two, prove_leaf, verify_chain};

#[test]
fn recursive_leaf_round_trip() {
    // The leaf alone (CircuitBuilder Fibonacci + BatchStarkProver) works
    // end-to-end. This is the Phase 1.5 prover-side checkpoint.
    let l1 = prove_leaf(Boundary::new(0, 1));
    let l2 = prove_leaf(l1.final_);
    assert_eq!(l2.initial, l1.final_);
}

#[test]
fn mismatched_boundary_recursive_rejected() {
    let l1 = prove_leaf(Boundary::new(0, 1));
    let l2 = prove_leaf(Boundary::new(7, 8));
    match merge_two(&l1, &l2) {
        Err(zksketch::recursion::recursive::MergeError::BoundaryMismatch { .. }) => {}
        Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
        Ok(_) => panic!("merge must reject mismatched boundary"),
    }
}

#[test]
fn honest_two_leaf_recursive_end_to_end() {
    let l1 = prove_leaf(Boundary::new(0, 1));
    let l2 = prove_leaf(l1.final_);
    let chain = merge_two(&l1, &l2).expect("merge");
    verify_chain(&chain).expect("verify");
}
