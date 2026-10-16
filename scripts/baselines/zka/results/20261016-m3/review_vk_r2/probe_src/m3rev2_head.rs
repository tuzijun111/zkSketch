//! Reviewer round-2 probe (scratch only, HEAD export): G-zk table budget and
//! auditor-derived VK == builder VK for the StableCompact leaf, explicit
//! variant (not env).
use p3_field::{BasedVectorSpace, PrimeField32};

use crate::commitment::hiding::CommitMode;
use crate::config::{Challenge, Val, MIN_TABLE_HEIGHT};
use crate::experiments::dist_compose::{derive_dist_leaf_vk, derive_dist_root_vk};
use crate::experiments::stream_compose::{StreamFamily, StreamMode, StreamShape};
use crate::recursion::recursive::statement::Expose;
use crate::sketch::bind::Binding;
use crate::sketch::gk_bandmerge::*;

fn fnv(vals: impl IntoIterator<Item = u64>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for v in vals {
        for b in v.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}
fn fc(v: &[Challenge]) -> u64 {
    fnv(v.iter().flat_map(|c| {
        <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
            .iter()
            .map(|x| x.as_canonical_u32() as u64)
            .collect::<Vec<_>>()
    }))
}

fn shape(cap: usize, gk_s: u64, r: GkRounds) -> StreamShape {
    StreamShape { d: 4, w: 8, b: 4, capacity: cap, gk_s, bloom_k: 3, bloom_log_w: 7, kmv_k: 4, gk_rounds: r }
}

#[test]
fn m3rev2_tables_and_derivation() {
    #[cfg(feature = "zk")]
    let budget = crate::config::ZK_HIDING_BUDGET;
    #[cfg(not(feature = "zk"))]
    let budget = 0usize;
    println!("M3REV2 MIN_TABLE_HEIGHT = {MIN_TABLE_HEIGHT}, ZK_HIDING_BUDGET = {budget}");
    for (cap, m, s) in [(4usize, 4usize, 2u64), (16, 8, 3), (768, 512, 51)] {
        for mode in [CommitMode::Plain, CommitMode::Hiding] {
            for r in [GkRounds::SortedCopy, GkRounds::StableCompact] {
                let p = GkbParams { capacity: cap, batch: m, s };
                let leaf = build_gkb2_leaf_rounds(p, Expose::Interval, Binding::Semantic, mode, r);
                let rows = leaf.table_rows().to_vec();
                let mn = *rows.iter().min().unwrap();
                println!("M3REV2 tables cap {cap} m {m} {mode:?} {r:?}: rows {rows:?} (min {mn}, total {})", leaf.trace_rows());
                assert!(mn >= MIN_TABLE_HEIGHT && mn >= budget, "table below the hiding budget");
                let built = fc(&leaf.vk_pin_values());
                if cap != 768 || r == GkRounds::StableCompact {
                    // The auditor's derivation (no-op leaf from public params).
                    let lv = derive_dist_leaf_vk(StreamFamily::GkBandmerge2, &shape(cap, s, r), m, mode);
                    let derived = fc(&lv.commitment);
                    println!("M3REV2 leaf vk cap {cap} m {m} {mode:?} {r:?}: built {built:#018x} derived {derived:#018x}");
                    assert_eq!(built, derived, "auditor-derived leaf VK == builder VK");
                }
            }
        }
    }
    // Forest root over 4 stable leaves at the test shape vs the sorted one.
    let a = derive_dist_root_vk(StreamFamily::GkBandmerge2, &shape(4, 2, GkRounds::StableCompact), 4, StreamMode::Forest, 4, 1, CommitMode::Hiding);
    let b = derive_dist_root_vk(StreamFamily::GkBandmerge2, &shape(4, 2, GkRounds::SortedCopy), 4, StreamMode::Forest, 4, 1, CommitMode::Hiding);
    println!("M3REV2 root4 hiding stable {:#018x} sorted {:#018x}", fc(&a.commitment), fc(&b.commitment));
    assert_ne!(a.commitment, b.commitment);
}
