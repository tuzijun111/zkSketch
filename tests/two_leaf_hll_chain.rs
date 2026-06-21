//! Integration test for the §4.3 recursive chain over HyperLogLog epochs (Phase 4c).
//!
//! Mirrors `tests/two_leaf_countmin_chain.rs`. Exercises `HllChainState::extend`
//! to grow the chain past two leaves and confirms `verify_chain_hll` accepts.

use zksketch::recursion::recursive::hll_chain::HllChainState;
use zksketch::recursion::recursive::hll_leaf::{B, prove_hll_leaf};
use zksketch::recursion::recursive::hll_merge::{HllMergeError, verify_chain_hll};
use zksketch::sketch::Sketch;
use zksketch::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogState, HyperLogLogUpdate};

fn empty_state() -> HyperLogLogState {
    HyperLogLog::new(&HyperLogLogParams { b: B })
}

#[test]
fn chain_of_three_hll_end_to_end() {
    let s0 = empty_state();
    let b1 = [
        HyperLogLogUpdate { key: 0x42 },
        HyperLogLogUpdate { key: 0x99 },
    ];
    let l1 = prove_hll_leaf(s0.clone(), b1);

    let mut s1 = s0;
    for u in &b1 {
        HyperLogLog::update(&mut s1, u);
    }
    let b2 = [
        HyperLogLogUpdate { key: 0x4242 },
        HyperLogLogUpdate { key: 0x7 },
    ];
    let l2 = prove_hll_leaf(s1.clone(), b2);

    let mut s2 = s1;
    for u in &b2 {
        HyperLogLog::update(&mut s2, u);
    }
    let b3 = [
        HyperLogLogUpdate { key: 0x11 },
        HyperLogLogUpdate { key: 0x4242 },
    ];
    let l3 = prove_hll_leaf(s2, b3);

    let mut state = HllChainState::init(&l1, &l2).expect("init");
    state.extend(&l3).expect("extend");

    verify_chain_hll(&state.root).expect("verify");
    assert_eq!(state.root.num_leaves(), 3);
}

#[test]
fn extend_with_wrong_boundary_hll_rejected() {
    let s0 = empty_state();
    let b1 = [
        HyperLogLogUpdate { key: 0x1 },
        HyperLogLogUpdate { key: 0x2 },
    ];
    let l1 = prove_hll_leaf(s0.clone(), b1);

    let mut s1 = s0;
    for u in &b1 {
        HyperLogLog::update(&mut s1, u);
    }
    let b2 = [
        HyperLogLogUpdate { key: 0x3 },
        HyperLogLogUpdate { key: 0x4 },
    ];
    let l2 = prove_hll_leaf(s1, b2);

    let s_wrong = empty_state();
    let b3 = [
        HyperLogLogUpdate { key: 0x5 },
        HyperLogLogUpdate { key: 0x6 },
    ];
    let l3 = prove_hll_leaf(s_wrong, b3);

    let mut state = HllChainState::init(&l1, &l2).expect("init");
    match state.extend(&l3) {
        Err(HllMergeError::BoundaryMismatch { .. }) => {}
        Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
        Ok(_) => panic!("extend must reject mismatched boundary"),
    }
}
