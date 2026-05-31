//! End-to-end tests through the public API (mirrors `../tests/`).

use anyhow::Result;
use zksketch_snark::leaf::countmin::{build_countmin_leaf, CmLeafParams};
use zksketch_snark::leaf::hyperloglog::{build_hll_leaf, HllLeafParams};
use zksketch_snark::recursion::{flat_verify, merge, verify_node};
use zksketch_snark::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch_snark::sketch::hyperloglog::{HllParams, HllState, HllUpdate};

#[test]
fn countmin_two_leaf_flat_and_recursive_agree() -> Result<()> {
    let leaf = build_countmin_leaf(CmLeafParams { d: 2, w: 4, batch: 2 });
    let s0 = CountMinState::new(&CountMinParams { d: 2, w: 4 });
    let e1 = vec![
        CountMinUpdate { key: 7, value: 3 },
        CountMinUpdate { key: 11, value: 5 },
    ];
    let n1 = leaf.prove(&s0, &e1, 1)?;
    let mut s1 = s0.clone();
    for u in &e1 {
        s1.update(u);
    }
    let e2 = vec![
        CountMinUpdate { key: 7, value: 1 },
        CountMinUpdate { key: 13, value: 9 },
    ];
    let n2 = leaf.prove(&s1, &e2, 2)?;

    let nodes = vec![n1, n2];
    let flat_digest = flat_verify(&nodes)?;
    let root = merge(&nodes[0], &nodes[1])?;
    verify_node(&root)?;
    assert_eq!(root.digest, flat_digest, "flat and recursive digests must agree");
    assert_eq!(root.num_leaves(), 2);
    Ok(())
}

#[test]
fn hll_two_leaf_end_to_end() -> Result<()> {
    let leaf = build_hll_leaf(HllLeafParams { b: 3, batch: 2 });
    let s0 = HllState::new(&HllParams { b: 3 });
    let e1 = vec![HllUpdate { key: 42 }, HllUpdate { key: 1337 }];
    let n1 = leaf.prove(&s0, &e1, 1)?;
    let mut s1 = s0.clone();
    for u in &e1 {
        s1.update(u);
    }
    let e2 = vec![HllUpdate { key: 9 }, HllUpdate { key: 42 }];
    let n2 = leaf.prove(&s1, &e2, 2)?;
    let root = merge(&n1, &n2)?;
    verify_node(&root)
}

#[test]
fn mismatched_boundary_rejected_at_merge() -> Result<()> {
    let leaf = build_countmin_leaf(CmLeafParams { d: 2, w: 4, batch: 2 });
    let s0 = CountMinState::new(&CountMinParams { d: 2, w: 4 });
    let e = vec![
        CountMinUpdate { key: 7, value: 3 },
        CountMinUpdate { key: 11, value: 5 },
    ];
    // Both leaves start from the empty state, so leaf2.initial != leaf1.final.
    let n1 = leaf.prove(&s0, &e, 1)?;
    let n2 = leaf.prove(&s0, &e, 2)?;
    assert!(merge(&n1, &n2).is_err(), "non-threaded boundary must be rejected");
    Ok(())
}
