//! RQ2 panels: batch size (2-a), state size (2-c), audit-window length (2-d).
//! Rows 2-e/2-f are not measured: a formula ratio and a fixed 100-1000x range (`kind=analytical`).

use crate::config::Val;
use crate::dataset::{Synthetic, synthetic_stream};
use crate::recursion::framework::{
    EpochLeaf, StreamingForest, compose_chain, compose_tree, root_commitment, verify_epoch_chain,
};
use crate::sketch::countmin_final::CountMinFinalParams;
use crate::sketch::gk_final_full::GKFullParams;
use crate::sketch::hll_final_full::HllFullParams;
use crate::sketch::ss_final_full::SsFullParams;

use super::families::{cm_empty, cm_epoch, gk_empty, gk_epoch, hll_empty, hll_epoch, ss_empty, ss_epoch};
use super::{Table, env_usize, ms_str, time_it};
use p3_field::PrimeCharacteristicRing;

pub fn run() -> Vec<Table> {
    vec![panel_2a(), panel_2c(), panel_2d(), panel_2ef_analytical()]
}

// ─── 2-a: batch-size linearity ───────────────────────────────────────────────

fn panel_2a() -> Table {
    let mut t = Table::new(
        "rq2a_batch_size",
        "2-a: prove time + proof size vs batch size m (expect ~linear in m)",
        &["family", "m", "prove_ms", "proof_bytes"],
    );
    let batches = [4usize, 8, 16, 32];
    for &m in &batches {
        // CM
        let p = CountMinFinalParams { d: 4, w: 8, batch: m };
        let keys = synthetic_stream(Synthetic::Uniform, m, 200 + m as u64);
        let (o, _) = cm_epoch(p, &cm_empty(4, 8), &keys);
        t.push(vec!["CM".into(), m.to_string(), ms_str(o.prove), o.proof_bytes.to_string()]);
        // GK
        let p = GKFullParams { capacity: 16, batch: m };
        let keys = synthetic_stream(Synthetic::Uniform, m, 210 + m as u64);
        let (o, _) = gk_epoch(p, &gk_empty(p), &keys);
        t.push(vec!["GK".into(), m.to_string(), ms_str(o.prove), o.proof_bytes.to_string()]);
        // HLL
        let p = HllFullParams { b: 6, batch: m };
        let keys = synthetic_stream(Synthetic::Uniform, m, 220 + m as u64);
        let (o, _) = hll_epoch(p, &hll_empty(p), &keys);
        t.push(vec!["HLL".into(), m.to_string(), ms_str(o.prove), o.proof_bytes.to_string()]);
        // SS
        let p = SsFullParams { capacity: 16, batch: m };
        let keys = synthetic_stream(Synthetic::Uniform, m, 230 + m as u64);
        let (o, _) = ss_epoch(p, &ss_empty(p), &keys);
        t.push(vec!["SS".into(), m.to_string(), ms_str(o.prove), o.proof_bytes.to_string()]);
    }
    t
}

// ─── 2-b: touched-cell / distinct-bound linearity (CM) ───────────────────────

// ─── 2-c: state-size scaling ─────────────────────────────────────────────────

fn panel_2c() -> Table {
    let mut t = Table::new(
        "rq2c_state_size",
        "2-c: prove time vs state size s (flat commitment ⇒ grows with s; sparse rebind is future work)",
        &["family", "state_size", "prove_ms", "proof_bytes"],
    );
    // CM: vary width w (state size = d·w). Fix batch + distinct_bound.
    let (d, batch) = (4usize, 8usize);
    for &w in &[2usize, 4, 8, 16] {
        let p = CountMinFinalParams { d, w, batch };
        let keys = synthetic_stream(Synthetic::Uniform, batch, 300 + w as u64);
        let (o, _) = cm_epoch(p, &cm_empty(d, w), &keys);
        t.push(vec!["CM".into(), (d * w).to_string(), ms_str(o.prove), o.proof_bytes.to_string()]);
    }
    // HLL: vary register count m = 2^b. Fix batch.
    let batch = 8usize;
    for &b in &[4usize, 5, 6] {
        let p = HllFullParams { b, batch };
        let keys = synthetic_stream(Synthetic::Uniform, batch, 350 + b as u64);
        let (o, _) = hll_epoch(p, &hll_empty(p), &keys);
        t.push(vec!["HLL".into(), p.m().to_string(), ms_str(o.prove), o.proof_bytes.to_string()]);
    }
    t
}

// ─── 2-d: audit-window length E (framework) — also 1-b ───────────────────────

/// Synthesise a contiguous, boundary-consistent epoch chain of length `e`.
fn synth_chain(e: u64) -> Vec<EpochLeaf> {
    let commit = |x: u64| -> [Val; 8] {
        let mut c = [Val::ZERO; 8];
        for (lane, slot) in c.iter_mut().enumerate() {
            *slot = Val::from_u64(x.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(lane as u64));
        }
        c
    };
    let mut leaves = Vec::with_capacity(e as usize);
    for i in 1..=e {
        leaves.push(EpochLeaf::new(
            i,
            commit(i - 1), // com_before == previous com_after
            commit(i),
            commit(0xB000 + i), // batch commit
            i,                  // descriptor
        ));
    }
    leaves
}

fn panel_2d() -> Table {
    let max_e = env_usize("EXP_RQ2_MAX_E", 256) as u64;
    let mut t = Table::new(
        "rq2d_audit_window",
        "2-d/1-b: root digest + verify O(1) in E; chain verify Θ(E); per-topology merges",
        &[
            "E",
            "root_digest_bytes",
            "root_verify_ms",
            "chain_verify_ms",
            "chain_merges",
            "tree_merges",
            "forest_total_merges",
            "forest_worst_insert_merges",
        ],
    );
    let mut e = 16u64;
    while e <= max_e {
        let leaves = synth_chain(e);

        // Chain compose + Θ(E) full-chain verify.
        let (chain_root, _) = time_it(|| compose_chain(&leaves).expect("chain"));
        let (_, chain_verify) = time_it(|| verify_epoch_chain(&leaves, 1).expect("verify chain"));

        // Root digest (constant size) + O(1) root recompute/verify.
        let (root_digest, root_verify) = time_it(|| root_commitment(&chain_root));
        let root_bytes = root_digest.len() * core::mem::size_of::<Val>();

        // Balanced binary tree (power-of-two E ⇒ E-1 merges, log2(E) spine depth).
        let tree_merges = if e.is_power_of_two() {
            let _ = compose_tree(&leaves).expect("tree");
            e - 1
        } else {
            0
        };

        // Streaming forest: measure total + worst-case single-insert merges
        // via the num_trees bookkeeping (each merge drops the root count by 1).
        let mut forest = StreamingForest::new();
        let mut total_merges = 0u64;
        let mut worst_insert = 0u64;
        for leaf in &leaves {
            let before = forest.num_trees() as u64;
            forest.insert(leaf).expect("forest insert");
            let after = forest.num_trees() as u64;
            let merges = before + 1 - after;
            total_merges += merges;
            worst_insert = worst_insert.max(merges);
        }

        t.push(vec![
            e.to_string(),
            root_bytes.to_string(),
            ms_str(root_verify),
            ms_str(chain_verify),
            (e - 1).to_string(),
            tree_merges.to_string(),
            total_merges.to_string(),
            worst_insert.to_string(),
        ]);
        e *= 2;
    }
    t
}

// ─── 2-e/2-f: not measured (no exact-index or zkVM baseline here) ───────────

fn panel_2ef_analytical() -> Table {
    // 2-e: the ratio H·log2(n) / (d + L) of per-record costs, exact index
    // (H·log2(n) hashing) vs optimised CM (d + L lookups), with the fixed
    // constants below; a formula, not a measurement.
    let mut t = Table::new(
        "rq2ef_analytical",
        "2-e/2-f: analytical projections (exact-index ratio, zkVM gap) — NOT measured here",
        &["panel", "n_or_param", "metric", "predicted", "kind"],
    );
    let h = 200.0f64; // per-hash cost
    let l = 5.0f64; // per-lookup cost
    let d = 7.0f64;
    for &log2n in &[15u32, 20, 25, 30] {
        let ratio = h * log2n as f64 / (d + l);
        t.push(vec![
            "2-e".into(),
            format!("n=2^{log2n}"),
            "exact_index/CM_per_record".into(),
            format!("{ratio:.0}x"),
            "analytical".into(),
        ]);
    }
    // 2-f: a fixed constant, 100-1000x per-batch prove gap (2–3 orders of
    // magnitude, ZK-Value-style); not measured.
    t.push(vec![
        "2-f".into(),
        "RISC0".into(),
        "per_batch_prove_gap".into(),
        "100-1000x".into(),
        "analytical".into(),
    ]);
    t.push(vec![
        "2-f".into(),
        "SP1".into(),
        "per_batch_prove_gap".into(),
        "100-1000x".into(),
        "analytical".into(),
    ]);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_window_root_is_constant_size() {
        let t = panel_2d();
        // root_digest_bytes column (index 1) must be identical across all E.
        let first = t.rows[0][1].clone();
        for row in &t.rows {
            assert_eq!(row[1], first, "root digest size must be constant in E");
        }
        // forest total merges = E - popcount(E) (binary-counter identity).
        for row in &t.rows {
            let e: u64 = row[0].parse().unwrap();
            let total: u64 = row[6].parse().unwrap();
            assert_eq!(total, e - e.count_ones() as u64, "forest merge identity");
        }
    }
}
