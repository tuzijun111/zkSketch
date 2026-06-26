//! Feasibility spike: can the REAL recursive forest (`prove_countmin_forest_v9`,
//! whose merges verify their two children in-circuit) recursively verify the
//! stream runner's OMC (`omc`) leaves — not just the native v9 leaves?
//!
//! If this passes, the stream runner can keep its leaf proofs, wrap them as
//! `CountMinLeafProofV9`, and fold them with the real recursive merge so
//! `merge_ms` reflects actual in-circuit child verification.

use zksketch::commitment::CountMinBatchCommit;
use zksketch::recursion::recursive::countmin_chain_v9::prove_countmin_chain_v9;
use zksketch::recursion::recursive::countmin_forest_v9::{
    prove_countmin_forest_v9, verify_forest_countmin_v9,
};
use zksketch::recursion::recursive::countmin_merge_v9::verify_chain_countmin_v9;
use zksketch::recursion::recursive::countmin_leaf::CountMinLeafParams;
use zksketch::recursion::recursive::countmin_leaf_v9::CountMinLeafProofV9;
use zksketch::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::countmin_c_merkle::{
    prove_countmin_c_merkle_exposed, prove_countmin_c_merkle_leaf, CountMinCMerkleParams,
};
use zksketch::sketch::countmin_final::apply_update_prf;
use zksketch::sketch::countmin_merkle::combined_commit;
use zksketch::sketch::countmin_omc::{prove_countmin_omc, prove_countmin_omc_exposed, CmOmcParams};

fn empty_state(d: usize, w: usize) -> CountMinState {
    CountMinState { counters: vec![vec![0u32; w]; d], params: CountMinParams { d, w } }
}

/// Prove one OMC leaf and re-wrap it in the v9 forest's leaf-proof envelope
/// (same `output`, same boundary commitments; only the digest/params metadata
/// the cascade ignores differs).
fn omc_leaf_as_v9(d: usize, w: usize, initial: CountMinState, batch: Vec<CountMinUpdate>) -> CountMinLeafProofV9 {
    let p = CmOmcParams { d, w, batch: batch.len() };
    let pr = prove_countmin_omc(p, initial, batch);
    CountMinLeafProofV9 {
        output: pr.output,
        initial: pr.initial_commit,
        final_: pr.final_commit,
        batch_commit: CountMinBatchCommit(pr.batch_commit.0),
        params: CountMinLeafParams::default(),
    }
}

#[test]
#[ignore = "spike: heavy recursive proving; run explicitly"]
fn omc_leaves_recursively_merge() {
    let (d, w) = (2usize, 4usize); // d·w = 8 (omc needs %4==0); tiny for speed

    let batch0 = vec![
        CountMinUpdate { key: 7, value: 1 },
        CountMinUpdate { key: 7, value: 1 },
    ];
    let batch1 = vec![
        CountMinUpdate { key: 9, value: 1 },
        CountMinUpdate { key: 7, value: 1 },
    ];

    // Chained states: leaf1's initial = leaf0's final.
    let s0 = empty_state(d, w);
    let mut s1 = s0.clone();
    for u in &batch0 {
        apply_update_prf(&mut s1, u);
    }

    let l0 = omc_leaf_as_v9(d, w, s0, batch0);
    let l1 = omc_leaf_as_v9(d, w, s1, batch1);
    assert_eq!(l0.final_, l1.initial, "chain boundary must match");

    // The real recursive merge: this aggregation verifies BOTH omc leaf proofs
    // in-circuit. If it returns Ok, the stream runner can use it for merge_ms.
    let root = prove_countmin_forest_v9(&[l0, l1])
        .expect("recursive forest over 2 OMC leaves should prove");
    verify_forest_countmin_v9(&root).expect("recursive OMC forest root should verify");
    assert_eq!(root.num_leaves(), 2);
}

fn cmerkle_leaf_as_v9(d: usize, w: usize, initial: CountMinState, batch: Vec<CountMinUpdate>) -> CountMinLeafProofV9 {
    let t_max = w; // safe upper bound on distinct touched cells per row (batch ≤ w here)
    let p = CountMinCMerkleParams { d, w, batch: batch.len(), t_max, compress: false, group_by: false };
    let pr = prove_countmin_c_merkle_leaf(p, initial, batch);
    CountMinLeafProofV9 {
        output: pr.output,
        initial: combined_commit(&pr.initial_roots),
        final_: combined_commit(&pr.final_roots),
        batch_commit: CountMinBatchCommit(pr.batch_commit.0),
        params: CountMinLeafParams::default(),
    }
}

#[test]
#[ignore = "spike: heavy recursive proving; run explicitly"]
fn merkle_leaves_recursively_merge() {
    let (d, w) = (2usize, 4usize);
    let batch0 = vec![CountMinUpdate { key: 7, value: 1 }, CountMinUpdate { key: 7, value: 1 }];
    let batch1 = vec![CountMinUpdate { key: 9, value: 1 }, CountMinUpdate { key: 7, value: 1 }];
    let s0 = empty_state(d, w);
    let mut s1 = s0.clone();
    for u in &batch0 {
        apply_update_prf(&mut s1, u);
    }
    let l0 = cmerkle_leaf_as_v9(d, w, s0, batch0);
    let l1 = cmerkle_leaf_as_v9(d, w, s1, batch1);
    assert_eq!(l0.final_, l1.initial, "chain boundary must match");
    let root = prove_countmin_forest_v9(&[l0, l1])
        .expect("recursive forest over 2 c_merkle leaves should prove");
    verify_forest_countmin_v9(&root).expect("recursive c_merkle forest root should verify");
    assert_eq!(root.num_leaves(), 2);
}

/// NPO-gap closure for the stream's `omc` leaf: two omc-EXPOSED leaves
/// folded by the in-circuit boundary-bound forest. The merge binds
/// `left.final == right.initial` IN-CIRCUIT (not natively), and the root
/// surfaces exactly the real outer boundary (Com(S_0), Com(S_2)).
#[test]
#[ignore = "spike: heavy recursive proving; run explicitly"]
fn omc_bound_forest_closes_npo_gap() {
    use zksketch::commitment::countmin::commit_countmin;
    use zksketch::recursion::recursive::expose_forest::{
        prove_forest_over, read_exposed_boundary, verify_bound_proof,
    };

    let (d, w) = (2usize, 4usize);
    let s0 = empty_state(d, w);
    let c0 = commit_countmin(&s0);
    let batch0 = vec![
        CountMinUpdate { key: 7, value: 3 },
        CountMinUpdate { key: 11, value: 5 },
    ];
    let batch1 = vec![
        CountMinUpdate { key: 13, value: 2 },
        CountMinUpdate { key: 7, value: 4 },
    ];

    let leaf0 =
        prove_countmin_omc_exposed(CmOmcParams { d, w, batch: batch0.len() }, s0.clone(), batch0.clone());
    let mut s1 = s0.clone();
    for u in &batch0 {
        apply_update_prf(&mut s1, u);
    }
    let leaf1 =
        prove_countmin_omc_exposed(CmOmcParams { d, w, batch: batch1.len() }, s1.clone(), batch1.clone());
    let mut s2 = s1.clone();
    for u in &batch1 {
        apply_update_prf(&mut s2, u);
    }
    let c2 = commit_countmin(&s2);

    // Each exposed leaf surfaces its REAL boundary commitment.
    assert_eq!(read_exposed_boundary(&leaf0.output).0, c0, "leaf0 exposes real Com(S_0)");

    // In-circuit boundary-bound fold: prove_forest_over → prove_hiding_merge,
    // which binds left.final == right.initial in-circuit (the NPO gap closed).
    let root = prove_forest_over(vec![leaf0.output, leaf1.output]);
    verify_bound_proof(&root);
    let (initial, final_) = read_exposed_boundary(&root);
    assert_eq!(initial, c0, "root initial = real Com(S_0), bound in-circuit");
    assert_eq!(final_, c2, "root final = real Com(S_2), bound in-circuit");
}

/// NPO-gap closure for the stream's `merkle` (c_merkle) leaf. The boundary here
/// is `combined_commit(per-row roots)`, hashed IN-CIRCUIT (d=2 exercises the
/// hash path, not the d==1 shortcut). Two c_merkle-EXPOSED leaves fold through
/// the in-circuit boundary-bound forest; the root surfaces the real combined
/// (Com(S_0), Com(S_2)), bound in-circuit.
#[test]
#[ignore = "spike: heavy recursive proving; run explicitly"]
fn merkle_bound_forest_closes_npo_gap() {
    use zksketch::recursion::recursive::expose_forest::{
        prove_forest_over, read_exposed_boundary, verify_bound_proof,
    };

    let (d, w) = (2usize, 4usize);
    let s0 = empty_state(d, w);
    let batch0 = vec![
        CountMinUpdate { key: 7, value: 3 },
        CountMinUpdate { key: 11, value: 5 },
    ];
    let batch1 = vec![
        CountMinUpdate { key: 13, value: 2 },
        CountMinUpdate { key: 7, value: 4 },
    ];
    let cp = |bn: usize| CountMinCMerkleParams {
        d,
        w,
        batch: bn,
        t_max: w,
        compress: false,
        group_by: false,
    };

    let leaf0 = prove_countmin_c_merkle_exposed(cp(batch0.len()), s0.clone(), batch0.clone());
    let mut s1 = s0.clone();
    for u in &batch0 {
        apply_update_prf(&mut s1, u);
    }
    let leaf1 = prove_countmin_c_merkle_exposed(cp(batch1.len()), s1.clone(), batch1.clone());

    let c0 = combined_commit(&leaf0.initial_roots);
    let c2 = combined_commit(&leaf1.final_roots);

    // The IN-CIRCUIT combined_commit must equal the native combined_commit.
    assert_eq!(read_exposed_boundary(&leaf0.output).0, c0, "leaf0 exposes real combined Com(S_0)");
    assert_eq!(
        read_exposed_boundary(&leaf0.output).1,
        combined_commit(&leaf0.final_roots),
        "leaf0 exposes real combined Com(S_1)"
    );

    let root = prove_forest_over(vec![leaf0.output, leaf1.output]);
    verify_bound_proof(&root);
    let (initial, final_) = read_exposed_boundary(&root);
    assert_eq!(initial, c0, "root initial = real combined Com(S_0), bound in-circuit");
    assert_eq!(final_, c2, "root final = real combined Com(S_2), bound in-circuit");
}

/// Coverage: the c_merkle IN-CIRCUIT combined_commit equals native for d∈{1,3,5}
/// — d=1 (short-circuit), d=3/5 (odd, multi-block sponge). Leaf-level only (no
/// fold), so cheap; guards the rate-alignment path the d=2 spike can't.
#[test]
#[ignore = "spike: heavy recursive proving; run explicitly"]
fn merkle_exposed_boundary_matches_native_various_d() {
    use zksketch::recursion::recursive::expose_forest::read_exposed_boundary;
    let w = 4;
    for d in [1usize, 3, 5] {
        let s0 = empty_state(d, w);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let p = CountMinCMerkleParams { d, w, batch: batch.len(), t_max: w, compress: false, group_by: false };
        let leaf = prove_countmin_c_merkle_exposed(p, s0, batch);
        let (init, fin) = read_exposed_boundary(&leaf.output);
        assert_eq!(init, combined_commit(&leaf.initial_roots), "d={d}: exposed init == native combined_commit");
        assert_eq!(fin, combined_commit(&leaf.final_roots), "d={d}: exposed final == native combined_commit");
    }
}

/// NPO-gap closure for the stream's `one_hot` (countmin_final §5.2) leaf: two
/// exposed leaves folded by the in-circuit boundary-bound forest. Boundary is
/// commit_countmin (like omc). Root surfaces the real (Com(S_0), Com(S_2)).
#[test]
#[ignore = "spike: heavy recursive proving; run explicitly"]
fn one_hot_bound_forest_closes_npo_gap() {
    use zksketch::commitment::countmin::commit_countmin;
    use zksketch::recursion::recursive::expose_forest::{
        prove_forest_over, read_exposed_boundary, verify_bound_proof,
    };
    use zksketch::sketch::countmin_final::{prove_countmin_final_exposed, CountMinFinalParams};

    let (d, w) = (4usize, 8usize); // d·w % 4 == 0; the canonical §5.2 shape
    let s0 = empty_state(d, w);
    let c0 = commit_countmin(&s0);
    let batch0 = vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }];
    let batch1 = vec![CountMinUpdate { key: 13, value: 2 }, CountMinUpdate { key: 7, value: 4 }];
    let p = |bn: usize| CountMinFinalParams { d, w, batch: bn };

    let leaf0 = prove_countmin_final_exposed(p(batch0.len()), s0.clone(), batch0.clone());
    let mut s1 = s0.clone();
    for u in &batch0 {
        apply_update_prf(&mut s1, u);
    }
    let leaf1 = prove_countmin_final_exposed(p(batch1.len()), s1.clone(), batch1.clone());
    let mut s2 = s1.clone();
    for u in &batch1 {
        apply_update_prf(&mut s2, u);
    }
    let c2 = commit_countmin(&s2);

    assert_eq!(read_exposed_boundary(&leaf0.output).0, c0, "leaf0 exposes real Com(S_0)");

    let root = prove_forest_over(vec![leaf0.output, leaf1.output]);
    verify_bound_proof(&root);
    let (initial, final_) = read_exposed_boundary(&root);
    assert_eq!(initial, c0, "root initial = real Com(S_0), bound in-circuit");
    assert_eq!(final_, c2, "root final = real Com(S_2), bound in-circuit");
}

/// Linear §4.3 chain (`Π^(t)=merge(Π^(t-1),π_t)`) over the stream's `omc`
/// (omc) leaves — the comparison baseline against the tree fold
/// (`prove_countmin_forest_v9`). Three omc leaves wrapped as v9 are chained
/// `init(l0,l1)` then `extend(l2)` (so the chain does one `leaf+leaf` then one
/// `agg+leaf`); the root certifies `[1,3]` and verifies under the
/// linear-chain verifier. This is the omc analog of the forest's
/// `omc_leaves_recursively_merge`.
#[test]
#[ignore = "spike: heavy recursive proving; run explicitly"]
fn omc_leaves_linear_chain() {
    let (d, w) = (2usize, 4usize);
    let s0 = empty_state(d, w);
    let batch0 = vec![CountMinUpdate { key: 7, value: 1 }, CountMinUpdate { key: 7, value: 1 }];
    let batch1 = vec![CountMinUpdate { key: 9, value: 1 }, CountMinUpdate { key: 7, value: 1 }];
    let batch2 = vec![CountMinUpdate { key: 5, value: 1 }, CountMinUpdate { key: 9, value: 1 }];

    let mut s1 = s0.clone();
    for u in &batch0 {
        apply_update_prf(&mut s1, u);
    }
    let mut s2 = s1.clone();
    for u in &batch1 {
        apply_update_prf(&mut s2, u);
    }

    let l0 = omc_leaf_as_v9(d, w, s0, batch0);
    let l1 = omc_leaf_as_v9(d, w, s1, batch1);
    let l2 = omc_leaf_as_v9(d, w, s2, batch2);
    assert_eq!(l0.final_, l1.initial, "chain boundary 0→1 must match");
    assert_eq!(l1.final_, l2.initial, "chain boundary 1→2 must match");

    let chain = prove_countmin_chain_v9(&[l0, l1, l2]).expect("linear chain over 3 omc leaves");
    verify_chain_countmin_v9(&chain).expect("linear omc chain root verifies");
    assert_eq!(chain.num_leaves(), 3);
    assert_eq!(chain.interval, (1, 3));
}

/// Linear §4.3 chain over the stream's `merkle` (c_merkle) leaves — the
/// comparison baseline against the tree fold. Three c_merkle leaves wrapped as
/// v9 are chained `init+extend`; the root certifies `[1,3]` and verifies. The
/// c_merkle analog of the forest's `merkle_leaves_recursively_merge`.
#[test]
#[ignore = "spike: heavy recursive proving; run explicitly"]
fn merkle_leaves_linear_chain() {
    let (d, w) = (2usize, 4usize);
    let s0 = empty_state(d, w);
    let batch0 = vec![CountMinUpdate { key: 7, value: 1 }, CountMinUpdate { key: 7, value: 1 }];
    let batch1 = vec![CountMinUpdate { key: 9, value: 1 }, CountMinUpdate { key: 7, value: 1 }];
    let batch2 = vec![CountMinUpdate { key: 5, value: 1 }, CountMinUpdate { key: 9, value: 1 }];

    let mut s1 = s0.clone();
    for u in &batch0 {
        apply_update_prf(&mut s1, u);
    }
    let mut s2 = s1.clone();
    for u in &batch1 {
        apply_update_prf(&mut s2, u);
    }

    let l0 = cmerkle_leaf_as_v9(d, w, s0, batch0);
    let l1 = cmerkle_leaf_as_v9(d, w, s1, batch1);
    let l2 = cmerkle_leaf_as_v9(d, w, s2, batch2);
    assert_eq!(l0.final_, l1.initial, "chain boundary 0→1 must match");
    assert_eq!(l1.final_, l2.initial, "chain boundary 1→2 must match");

    let chain = prove_countmin_chain_v9(&[l0, l1, l2]).expect("linear chain over 3 c_merkle leaves");
    verify_chain_countmin_v9(&chain).expect("linear c_merkle chain root verifies");
    assert_eq!(chain.num_leaves(), 3);
    assert_eq!(chain.interval, (1, 3));
}
