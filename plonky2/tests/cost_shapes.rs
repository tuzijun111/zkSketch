//! Cost-shape verification for the four deployed-forest leaves. Confirms the
//! framework's predicted shape empirically: the leaf circuit size is governed by
//! the declared **sketch capacity** (d·w for Count-Min, 2^b for HyperLogLog,
//! `capacity` for SpaceSaving/GK), and is fixed by the public parameters — it does
//! not depend on the stream length or which epoch a leaf certifies
//! (history-independent: the circuit is built once per shape and reused for every
//! epoch). We measure `degree_bits` (log₂ of the padded execution-trace length),
//! the plonky2 cost proxy, and assert it grows with capacity.
//!
//! Run with `--nocapture` to see the numbers.

use zksketch_snark::leaf::countmin_omc::{build_countmin_omc_leaf, CmOmcParams};
use zksketch_snark::leaf::gk_bandmerge2::build_gk2_bm2_leaf;
use zksketch_snark::leaf::hll_omc::{build_hll_omc_leaf, HllOmcParams};
use zksketch_snark::leaf::spacesaving::{build_spacesaving_leaf, SsLeafParams};
use zksketch_snark::sketch::gk_bandmerge2::Gk2Params;

/// Each family: circuit size (degree_bits) must be **monotone non-decreasing in
/// capacity** and larger at the big capacity than the small one — the
/// capacity-governed shape. (`degree_bits` is quantized to a power of two, so we
/// require strictly-greater across a 4× capacity jump; under `zk` the blinding
/// floor at 2^14 moves the strict check to larger capacities, see below.)
#[test]
fn cost_is_capacity_governed() {
    // (label, small-shape bits, big-shape bits)
    let cm_small = build_countmin_omc_leaf(CmOmcParams { d: 2, w: 4, batch: 2 }).data.common.degree_bits();
    let cm_big = build_countmin_omc_leaf(CmOmcParams { d: 2, w: 32, batch: 2 }).data.common.degree_bits();

    let hll_small = build_hll_omc_leaf(HllOmcParams { b: 3, batch: 4 }).data.common.degree_bits();
    let hll_big = build_hll_omc_leaf(HllOmcParams { b: 6, batch: 4 }).data.common.degree_bits();

    let ss_small = build_spacesaving_leaf(SsLeafParams { capacity: 4, batch: 4 }).data.common.degree_bits();
    let ss_big = build_spacesaving_leaf(SsLeafParams { capacity: 32, batch: 4 }).data.common.degree_bits();

    let gk_small = build_gk2_bm2_leaf(Gk2Params { capacity: 8, batch: 4, s: 2 }).data.common.degree_bits();
    let gk_big = build_gk2_bm2_leaf(Gk2Params { capacity: 60, batch: 4, s: 2 }).data.common.degree_bits();

    println!("cost-shape (degree_bits = log2 padded trace):");
    println!("  cm_omc      d·w 8 → 64 : {cm_small} → {cm_big}");
    println!("  hll_omc     2^b 8 → 64 : {hll_small} → {hll_big}");
    println!("  ss_certified cap 4 → 32: {ss_small} → {ss_big}");
    println!("  gk_bandmrg2  cap 8 → 60: {gk_small} → {gk_big}");

    // Under `zk`, plonky2's blinding rows (~10.7k at 2^14, 36 queries) floor every
    // circuit with at most ~5.7k real gates at degree 2^14, so these ~8× capacity
    // jumps can land on the same degree: only non-decreasing is meaningful there.
    // Strict growth is checked below on shapes large enough to leave the floor.
    let grows = |big: usize, small: usize| if cfg!(feature = "zk") { big >= small } else { big > small };
    assert!(grows(cm_big, cm_small), "CM omc: circuit must grow with capacity d·w");
    assert!(grows(hll_big, hll_small), "HLL omc: circuit must grow with capacity 2^b");
    assert!(grows(ss_big, ss_small), "SS certified: circuit must grow with capacity");
    assert!(grows(gk_big, gk_small), "GK bandmerge2: circuit must grow with capacity");

    if cfg!(feature = "zk") {
        // Capacities that cross the 2^14 zk floor (measured: CM d·w 4096, HLL 2^12
        // and GK cap 60 reach 2^15; SS is still on the floor at cap 512).
        let cm_huge = build_countmin_omc_leaf(CmOmcParams { d: 2, w: 2048, batch: 2 }).data.common.degree_bits();
        let hll_huge = build_hll_omc_leaf(HllOmcParams { b: 12, batch: 4 }).data.common.degree_bits();
        println!("  zk, past the 2^14 floor: cm_omc d·w 8 → 4096: {cm_small} → {cm_huge}");
        println!("  zk, past the 2^14 floor: hll_omc 2^b 8 → 4096: {hll_small} → {hll_huge}");
        assert!(cm_huge > cm_small, "CM omc (zk): circuit must grow with capacity d·w past the floor");
        assert!(hll_huge > hll_small, "HLL omc (zk): circuit must grow with capacity 2^b past the floor");
        assert!(gk_big > gk_small, "GK bandmerge2 (zk): circuit must grow with capacity past the floor");
    }
}

/// History-independence + build-once reuse: a leaf circuit built for a shape is a
/// fixed object whose size does not depend on the batch *values* or the epoch — it
/// is reused for every epoch. We assert two builds of the same shape are identical
/// in size (deterministic, value-independent), and that at a fixed capacity the
/// circuit is not blown up by a larger batch beyond the modest `Θ(batch)` term.
#[test]
fn cost_is_history_independent_and_batch_modest() {
    let a = build_gk2_bm2_leaf(Gk2Params { capacity: 16, batch: 4, s: 2 }).data.common.degree_bits();
    let b = build_gk2_bm2_leaf(Gk2Params { capacity: 16, batch: 4, s: 2 }).data.common.degree_bits();
    assert_eq!(a, b, "same shape ⇒ identical circuit (history-independent, value-free)");

    // At a fixed capacity, the batch term is Θ(batch) — a 2× batch must not more
    // than double the padded trace (degree_bits grows by at most ~1 per doubling).
    let small_batch = build_hll_omc_leaf(HllOmcParams { b: 5, batch: 4 }).data.common.degree_bits();
    let big_batch = build_hll_omc_leaf(HllOmcParams { b: 5, batch: 8 }).data.common.degree_bits();
    println!("hll_omc b=5 batch 4 → 8: {small_batch} → {big_batch} degree_bits");
    assert!(big_batch <= small_batch + 1, "batch doubling must add ≤1 degree_bit (Θ(batch), capacity-floored)");
}
