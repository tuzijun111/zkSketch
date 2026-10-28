//! RQ3 panels: naive vs optimised CM leaf (3-a), Zipf skew (3-d),
//! SS retention vs GK rounds (3-e), SS capacity sweep (3-f).

use crate::dataset::{Synthetic, synthetic_stream};
use crate::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};
use crate::sketch::countmin_final::CountMinFinalParams;
use crate::sketch::gk_final_full::{
    GKFullParams, GKFullState, GKFullUpdate, num_fusion_rounds, prove_gk_full_with_rounds,
};
use crate::recursion::recursive::countmin_leaf::{CountMinLeafParams, prove_countmin_leaf_with_params};
use crate::sketch::Sketch;

use super::families::{cm_empty, cm_epoch, ss_empty, ss_epoch};
use super::{Table, ms_str, proof_size, time_it};

pub fn run() -> Vec<Table> {
    vec![panel_3a(), panel_3e(), panel_3f()]
}

// ─── 3-a: optimised CM vs naive strawman ─────────────────────────────────────

fn panel_3a() -> Table {
    let mut t = Table::new(
        "rq3a_naive_vs_optimised",
        "3-a: naive §5.1 strawman (Θ(d·w·batch)) vs optimised §5.2 CM (Θ(distinct·d + d·w))",
        &["variant", "d", "w", "batch", "prove_ms", "proof_bytes"],
    );
    // Small grids so the per-record-replay strawman still compiles.
    let grid = [(2usize, 4usize, 4usize), (3, 8, 8), (4, 8, 8)];
    for &(d, w, batch) in &grid {
        let keys = synthetic_stream(Synthetic::Uniform, batch, 400 + (d * w * batch) as u64);
        let updates: Vec<CountMinUpdate> =
            keys.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();

        // Naive §5.1 strawman leaf (v1).
        let initial = CountMin::new(&CountMinParams { d, w });
        let lp = CountMinLeafParams { d, w, batch };
        let (naive, naive_t) =
            time_it(|| prove_countmin_leaf_with_params(lp, initial, updates.clone()));
        t.push(vec![
            "naive_strawman".into(),
            d.to_string(),
            w.to_string(),
            batch.to_string(),
            ms_str(naive_t),
            proof_size(&naive.output.0).to_string(),
        ]);

        // Optimised §5.2 leaf.
        let p = CountMinFinalParams { d, w, batch };
        let (o, _) = cm_epoch(p, &cm_empty(d, w), &keys);
        t.push(vec![
            "optimised".into(),
            d.to_string(),
            w.to_string(),
            batch.to_string(),
            ms_str(o.prove),
            o.proof_bytes.to_string(),
        ]);
    }
    t
}

// ─── 3-e: SS single-round retention vs GK multi-round fusion ─────────────────

fn panel_3e() -> Table {
    let mut t = Table::new(
        "rq3e_retention_vs_fusion",
        "3-e: SS single-pass retention vs GK ⌈log₂⌉-round fusion (round count is a GK cost lever)",
        &["shape", "capacity", "batch", "rounds", "prove_ms", "proof_bytes"],
    );
    let (capacity, batch) = (16usize, 16usize);

    // SS: single-round top-s retention.
    {
        let p = crate::sketch::ss_final_full::SsFullParams { capacity, batch };
        let keys = synthetic_stream(Synthetic::Uniform, batch, 600);
        let (o, _) = ss_epoch(p, &ss_empty(p), &keys);
        t.push(vec![
            "SS_retention".into(),
            capacity.to_string(),
            batch.to_string(),
            "1".into(),
            ms_str(o.prove),
            o.proof_bytes.to_string(),
        ]);
    }

    // GK: full ⌈log₂(total)⌉ rounds, and a reduced 2-round circuit.
    let gp = GKFullParams { capacity, batch };
    let total = gp.capacity + gp.batch;
    let full_rounds = num_fusion_rounds(total);
    let keys = synthetic_stream(Synthetic::Uniform, batch, 610);
    let updates: Vec<GKFullUpdate> =
        keys.iter().map(|&k| GKFullUpdate::real(k & 0x003F_FFFF)).collect();
    for &rounds in &[full_rounds, 2usize.min(full_rounds)] {
        let (leaf, dt) = time_it(|| {
            prove_gk_full_with_rounds(gp, GKFullState::empty(gp), updates.clone(), rounds)
        });
        t.push(vec![
            format!("GK_fusion"),
            capacity.to_string(),
            batch.to_string(),
            rounds.to_string(),
            ms_str(dt),
            proof_size(&leaf.output.0).to_string(),
        ]);
    }
    t
}

// ─── 3-f: SS capacity sweep ──────────────────────────────────────────────────

fn panel_3f() -> Table {
    let mut t = Table::new(
        "rq3f_ss_capacity",
        "3-f: SS total prove cost vs capacity s (component breakdown needs introspection — future work)",
        &["capacity", "batch", "prove_ms", "proof_bytes"],
    );
    let batch = 16usize;
    for &s in &[4usize, 8, 16, 32] {
        let p = crate::sketch::ss_final_full::SsFullParams { capacity: s, batch };
        let keys = synthetic_stream(Synthetic::Uniform, batch, 700 + s as u64);
        let (o, _) = ss_epoch(p, &ss_empty(p), &keys);
        t.push(vec![
            s.to_string(),
            batch.to_string(),
            ms_str(o.prove),
            o.proof_bytes.to_string(),
        ]);
    }
    t
}

