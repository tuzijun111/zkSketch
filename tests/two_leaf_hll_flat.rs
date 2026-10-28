//! Flat HyperLogLog chain: flat_merge_two_hll and verify_chain_flat_hll.

use zksketch::recursion::hll_flat::{
    HllFlatError, flat_merge_two_hll, verify_chain_flat_hll,
};
use zksketch::recursion::recursive::hll_leaf::{B, prove_hll_leaf};
use zksketch::sketch::Sketch;
use zksketch::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogUpdate};

fn empty_state() -> zksketch::sketch::hyperloglog::HyperLogLogState {
    HyperLogLog::new(&HyperLogLogParams { b: B })
}

#[test]
fn honest_two_leaf_hll_flat_end_to_end() {
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
    let l2 = prove_hll_leaf(s1, b2);

    let chain = flat_merge_two_hll(l1, l2).expect("merge");
    verify_chain_flat_hll(&chain).expect("verify");
}

#[test]
fn mismatched_boundary_hll_flat_rejected() {
    let s0 = empty_state();
    let b1 = [
        HyperLogLogUpdate { key: 0x42 },
        HyperLogLogUpdate { key: 0x99 },
    ];
    let l1 = prove_hll_leaf(s0, b1);

    let s1_wrong = empty_state();
    let b2 = [
        HyperLogLogUpdate { key: 0x4242 },
        HyperLogLogUpdate { key: 0x7 },
    ];
    let l2 = prove_hll_leaf(s1_wrong, b2);

    match flat_merge_two_hll(l1, l2) {
        Err(HllFlatError::BoundaryMismatch { .. }) => {}
        Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
        Ok(_) => panic!("flat merge must reject mismatched boundary"),
    }
}
