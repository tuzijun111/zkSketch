//! Flat Count-Min chain: flat_merge_two_countmin and verify_chain_flat_countmin.

use zksketch::recursion::countmin_flat::{
    CountMinFlatError, flat_merge_two_countmin, verify_chain_flat_countmin,
};
use zksketch::recursion::recursive::countmin_leaf::{D, W, prove_countmin_leaf};
use zksketch::sketch::Sketch;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};

fn empty_state() -> zksketch::sketch::countmin::CountMinState {
    CountMin::new(&CountMinParams { d: D, w: W })
}

#[test]
fn honest_two_leaf_countmin_flat_end_to_end() {
    let s0 = empty_state();
    let b1 = [
        CountMinUpdate { key: 42, value: 7 },
        CountMinUpdate { key: 99, value: 1 },
    ];
    let l1 = prove_countmin_leaf(s0.clone(), b1);

    let mut s1 = s0;
    for u in &b1 {
        CountMin::update(&mut s1, u);
    }

    let b2 = [
        CountMinUpdate { key: 42, value: 3 },
        CountMinUpdate { key: 7, value: 9 },
    ];
    let l2 = prove_countmin_leaf(s1, b2);

    let chain = flat_merge_two_countmin(l1, l2).expect("merge");
    verify_chain_flat_countmin(&chain).expect("verify");
}

#[test]
fn mismatched_boundary_countmin_flat_rejected() {
    let s0 = empty_state();
    let b1 = [
        CountMinUpdate { key: 42, value: 7 },
        CountMinUpdate { key: 99, value: 1 },
    ];
    let l1 = prove_countmin_leaf(s0, b1);

    let s1_wrong = empty_state();
    let b2 = [
        CountMinUpdate { key: 42, value: 3 },
        CountMinUpdate { key: 7, value: 9 },
    ];
    let l2 = prove_countmin_leaf(s1_wrong, b2);

    match flat_merge_two_countmin(l1, l2) {
        Err(CountMinFlatError::BoundaryMismatch { .. }) => {}
        Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
        Ok(_) => panic!("flat merge must reject mismatched boundary"),
    }
}
