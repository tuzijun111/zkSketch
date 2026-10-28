//! CM omc, HLL omc, SS and GK bandmerge2 each prove 4 chained epochs and compose them with compose_tree.

use anyhow::Result;

use zksketch_snark::leaf::countmin_final::apply_update_prf;
use zksketch_snark::leaf::countmin_omc::{build_countmin_omc_leaf, CmOmcParams};
use zksketch_snark::leaf::gk_bandmerge2::build_gk2_bm2_leaf;
use zksketch_snark::leaf::hll_omc::{build_hll_omc_leaf, hll_omc_advance, HllOmcParams};
use zksketch_snark::leaf::spacesaving::{build_spacesaving_leaf, empty_state, SsLeafParams};
use zksketch_snark::recursion::topology::compose_tree;
use zksketch_snark::recursion::verify_node;
use zksketch_snark::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch_snark::sketch::gk_bandmerge2::{apply_batch2, Gk2Params, Gk2State};
use zksketch_snark::sketch::spacesaving::{apply_batch, SsUpdate};

/// CM omc: 4 chained epochs → forest root.
#[test]
fn cm_omc_forest_four_leaves() -> Result<()> {
    let params = CmOmcParams { d: 2, w: 4, batch: 2 };
    let leaf = build_countmin_omc_leaf(params);
    let mut state = CountMinState::new(&CountMinParams { d: 2, w: 4 });
    let mut nodes = Vec::new();
    for i in 0..4u64 {
        let batch = vec![
            CountMinUpdate { key: i * 7 + 1, value: 1 },
            CountMinUpdate { key: i * 11 + 3, value: 2 },
        ];
        nodes.push(leaf.prove(&state, &batch, i + 1)?);
        for u in &batch {
            apply_update_prf(&mut state, u);
        }
    }
    let root = compose_tree(nodes)?;
    verify_node(&root)?;
    assert_eq!(root.num_leaves(), 4);
    Ok(())
}

/// HLL omc: 4 chained epochs → forest root.
#[test]
fn hll_omc_forest_four_leaves() -> Result<()> {
    let params = HllOmcParams { b: 3, batch: 4 };
    let m = params.m();
    let leaf = build_hll_omc_leaf(params);
    let mut regs = vec![0u64; m];
    let mut nodes = Vec::new();
    for i in 0..4u64 {
        let keys: Vec<u64> = (0..4).map(|j| i.wrapping_mul(0xABCD).wrapping_add(j) ^ 0x7).collect();
        nodes.push(leaf.prove(&regs, &keys, i + 1)?);
        hll_omc_advance(&mut regs, &keys, params.b);
    }
    let root = compose_tree(nodes)?;
    verify_node(&root)?;
    assert_eq!(root.num_leaves(), 4);
    Ok(())
}

/// SS certified: 4 chained epochs → forest root.
#[test]
fn ss_certified_forest_four_leaves() -> Result<()> {
    let leaf = build_spacesaving_leaf(SsLeafParams { capacity: 4, batch: 4 });
    let mut state = empty_state(4, 4);
    let mut nodes = Vec::new();
    for i in 0..4u64 {
        let batch = vec![
            SsUpdate::real(7 + i, 5),
            SsUpdate::real(11 + i, 3),
            SsUpdate::real(7, 2),
            SsUpdate::dummy(),
        ];
        nodes.push(leaf.prove(&state, &batch, i + 1)?);
        state = apply_batch(&state, &batch).0;
    }
    let root = compose_tree(nodes)?;
    verify_node(&root)?;
    assert_eq!(root.num_leaves(), 4);
    Ok(())
}

/// GK bandmerge2 (two-sided): 4 chained epochs → forest root.
#[test]
fn gk_bandmerge2_forest_four_leaves() -> Result<()> {
    let params = Gk2Params { capacity: 12, batch: 4, s: 2 };
    let leaf = build_gk2_bm2_leaf(params);
    let mut state = Gk2State::empty(params);
    let mut nodes = Vec::new();
    for i in 0..4u32 {
        let vals: Vec<u32> = vec![5 + i, 7 + i, 11 + i, 13 + i];
        nodes.push(leaf.prove(&state, &vals, (i + 1) as u64)?);
        state = apply_batch2(&state, &vals);
    }
    let root = compose_tree(nodes)?;
    verify_node(&root)?;
    assert_eq!(root.num_leaves(), 4);
    Ok(())
}
