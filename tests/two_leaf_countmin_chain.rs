//! Integration test for the §4.3 recursive chain over Count-Min epochs.
//!
//! Mirrors `tests/two_leaf_countmin.rs` (§4.2 two-leaf merge) but exercises
//! `CountMinChainState::extend` to grow the chain past two leaves.

use zksketch::recursion::recursive::countmin_chain::CountMinChainState;
use zksketch::recursion::recursive::countmin_leaf::{D, W, prove_countmin_leaf};
use zksketch::recursion::recursive::countmin_merge::{
    CountMinMergeError, verify_chain_countmin,
};
use zksketch::sketch::Sketch;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinState, CountMinUpdate};

fn empty_state() -> CountMinState {
    CountMin::new(&CountMinParams { d: D, w: W })
}

#[test]
fn chain_of_three_countmin_end_to_end() {
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
    let l2 = prove_countmin_leaf(s1.clone(), b2);

    let mut s2 = s1;
    for u in &b2 {
        CountMin::update(&mut s2, u);
    }
    let b3 = [
        CountMinUpdate { key: 11, value: 4 },
        CountMinUpdate { key: 42, value: 2 },
    ];
    let l3 = prove_countmin_leaf(s2, b3);

    let mut state = CountMinChainState::init(&l1, &l2).expect("init");
    state.extend(&l3).expect("extend");

    verify_chain_countmin(&state.root).expect("verify");
    assert_eq!(state.root.num_leaves(), 3);
}

#[test]
fn extend_with_wrong_boundary_countmin_rejected() {
    let s0 = empty_state();
    let b1 = [
        CountMinUpdate { key: 1, value: 1 },
        CountMinUpdate { key: 2, value: 1 },
    ];
    let l1 = prove_countmin_leaf(s0.clone(), b1);

    let mut s1 = s0;
    for u in &b1 {
        CountMin::update(&mut s1, u);
    }
    let b2 = [
        CountMinUpdate { key: 3, value: 1 },
        CountMinUpdate { key: 4, value: 1 },
    ];
    let l2 = prove_countmin_leaf(s1, b2);

    let s_wrong = empty_state();
    let b3 = [
        CountMinUpdate { key: 5, value: 1 },
        CountMinUpdate { key: 6, value: 1 },
    ];
    let l3 = prove_countmin_leaf(s_wrong, b3);

    let mut state = CountMinChainState::init(&l1, &l2).expect("init");
    match state.extend(&l3) {
        Err(CountMinMergeError::BoundaryMismatch { .. }) => {}
        Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
        Ok(_) => panic!("extend must reject mismatched boundary"),
    }
}
