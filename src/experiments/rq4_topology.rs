//! RQ4: composition topology (4-a/4-b) and peak-fold policy (4-c/4-d), on synthetic leaves.
//! `lazy_ms`/`queryburst_ms` = merge count × the measured `merge_atom` time (a Poseidon2 digest).

use crate::config::Val;
use crate::recursion::framework::{EpochLeaf, StreamingForest, lift_leaf, merge_atom};

use super::{Table, env_usize, time_it};
use p3_field::PrimeCharacteristicRing;

pub fn run() -> Vec<Table> {
    let merge_us = measure_merge_cost();
    vec![panel_4ab(merge_us), panel_4cd(merge_us)]
}

/// Synthesise a contiguous, boundary-consistent epoch chain of length `e`.
fn synth_chain(e: u64) -> Vec<EpochLeaf> {
    let commit = |x: u64| -> [Val; 8] {
        let mut c = [Val::ZERO; 8];
        for (lane, slot) in c.iter_mut().enumerate() {
            *slot = Val::from_u64(x.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(lane as u64));
        }
        c
    };
    (1..=e)
        .map(|i| EpochLeaf::new(i, commit(i - 1), commit(i), commit(0xB000 + i), i))
        .collect()
}

/// Mean microseconds per `merge_atom` (the option-(i) composition cost τ).
fn measure_merge_cost() -> f64 {
    let leaves = synth_chain(2);
    let a = lift_leaf(&leaves[0]);
    let b = lift_leaf(&leaves[1]);
    let reps = 2000u32;
    let (_, dt) = time_it(|| {
        for _ in 0..reps {
            let _ = merge_atom(&a, &b).expect("merge");
        }
    });
    dt.as_secs_f64() * 1e6 / reps as f64
}

// ─── 4-a / 4-b: topology online cost ─────────────────────────────────────────

fn panel_4ab(merge_us: f64) -> Table {
    let max_e = env_usize("EXP_RQ4_MAX_E", 1024) as u64;
    let mut t = Table::new(
        "rq4ab_topology_online",
        "4-a/4-b: per-update merge cost by topology (merge τ measured for the option-(i) digest)",
        &[
            "E",
            "chain_per_insert",
            "tree_spine_depth",
            "forest_amortized",
            "forest_worst_insert",
            "merge_us",
        ],
    );
    let mut e = 16u64;
    while e <= max_e {
        let leaves = synth_chain(e);

        // Forest: measured amortised + worst-case single-insert merges.
        let mut forest = StreamingForest::new();
        let mut total = 0u64;
        let mut worst = 0u64;
        for leaf in &leaves {
            let before = forest.num_trees() as u64;
            forest.insert(leaf).expect("forest insert");
            let merges = before + 1 - forest.num_trees() as u64;
            total += merges;
            worst = worst.max(merges);
        }
        let amortized = total as f64 / e as f64;
        let tree_spine = (e as f64).log2().ceil() as u64;

        t.push(vec![
            e.to_string(),
            "1".into(),
            tree_spine.to_string(),
            format!("{amortized:.3}"),
            worst.to_string(),
            format!("{merge_us:.3}"),
        ]);
        e *= 2;
    }
    t
}

// ─── 4-c / 4-d: maintenance policy (peak-chain folding) ──────────────────────

fn panel_4cd(merge_us: f64) -> Table {
    let mut t = Table::new(
        "rq4cd_policy",
        "4-c/4-d: lazy sequential peak-fold (ℓ-1) vs query-burst parallel fold (⌈log₂ℓ⌉)",
        &[
            "t",
            "surviving_peaks",
            "lazy_merges",
            "lazy_ms",
            "queryburst_merges",
            "queryburst_ms",
            "speedup_x",
        ],
    );
    // Sweep stream length t; ℓ = popcount(t) surviving peaks in the forest.
    for &t_len in &[255u64, 1023, 4095, 65535, 1_048_575] {
        let forest_peaks = build_forest_peaks(t_len);
        let l = forest_peaks; // == popcount(t)
        let lazy = l.saturating_sub(1);
        let qburst = if l <= 1 { 0 } else { (l as f64).log2().ceil() as u64 };
        let speedup = if qburst == 0 { 1.0 } else { lazy as f64 / qburst as f64 };
        t.push(vec![
            t_len.to_string(),
            l.to_string(),
            lazy.to_string(),
            format!("{:.3}", lazy as f64 * merge_us / 1000.0),
            qburst.to_string(),
            format!("{:.3}", qburst as f64 * merge_us / 1000.0),
            format!("{speedup:.2}"),
        ]);
    }
    t
}

/// Number of surviving forest peaks after ingesting `t` epochs (`popcount(t)`),
/// counted by running the cascade for `t ≤ 8192`, else taken as `popcount(t)`.
fn build_forest_peaks(t: u64) -> u64 {
    if t <= 8192 {
        let leaves = synth_chain(t);
        let mut forest = StreamingForest::new();
        for leaf in &leaves {
            forest.insert(leaf).expect("insert");
        }
        forest.num_trees() as u64
    } else {
        t.count_ones() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forest_amortized_is_near_one_and_worst_is_log() {
        let t = panel_4ab(0.1);
        for row in &t.rows {
            let e: u64 = row[0].parse().unwrap();
            let amortized: f64 = row[3].parse().unwrap();
            let worst: u64 = row[4].parse().unwrap();
            assert!(amortized < 1.0, "amortised merges < 1 at E={e}: {amortized}");
            // Worst-case single insert equals the largest carry run ≤ log2(E).
            assert!(worst <= (e as f64).log2().ceil() as u64 + 1);
        }
    }

    #[test]
    fn queryburst_beats_lazy_for_many_peaks() {
        let t = panel_4cd(10.0);
        // Largest t row should show a meaningful speedup.
        let last = t.rows.last().unwrap();
        let speedup: f64 = last[6].parse().unwrap();
        assert!(speedup > 1.5, "query-burst should beat lazy for many peaks: {speedup}");
    }
}
