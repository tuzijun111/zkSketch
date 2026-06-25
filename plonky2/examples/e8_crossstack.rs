//! E8 — cross-stack head-to-head, **plonky2 (SNARK)** side (EVAL_SPEC E8). The
//! plonky2 counterpart of `examples/exp_e8.rs`: the same certified Count-Min leaf
//! shape (d=4, w=8) and a recursive merge of two chainable leaves, on Goldilocks
//! + Poseidon + native recursion. `scripts/run_experiments.sh e8` merges this
//! into `results/e8_crossstack.csv` (the `backend` column distinguishes it from
//! the plonky3 rows).
//!
//! Two ops here:
//! - `leaf` — build + prove one CM leaf (§1 split via `prove_timed`).
//! - `recursive_merge` — `recursion::merge` of two chainable CM Nodes (a **real**
//!   recursive SNARK that verifies both children in-circuit).
//!
//! Cross-family (cm+hll) merge is **omitted on plonky2**: the recursive `merge`
//! requires both Nodes to thread on the same state commitment, but CM (d·w cells)
//! and HLL (2^b registers) commit different state shapes with no unified
//! commitment — a documented gap (the plonky3 side composes them via the §4
//! framework digest instead).
//!
//! Run: cargo run --release --example e8_crossstack
//! Env: EXP_E8_M=64  EXP_E8_DB=32  EXP_E8_TRIALS=2

use std::time::Duration;

use zksketch_snark::leaf::countmin_final::{apply_update_prf, build_countmin_final_leaf, CmFinalParams};
use zksketch_snark::metrics::{append_csv, bench, results_dir, time_it, write_env_json, AggRow, BenchCfg, RunOutcome};
use zksketch_snark::recursion::{merge, verify_node};
use zksketch_snark::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d)
}
fn keys(m: usize, distinct: usize, salt: usize) -> Vec<CountMinUpdate> {
    (0..m)
        .map(|j| CountMinUpdate {
            key: (((salt * distinct + (j % distinct)) as u64 + 1).wrapping_mul(0x9E37_79B9)) | 1,
            value: 1,
        })
        .collect()
}
fn row(op: &str, families: &str, agg: &AggRow) -> Vec<String> {
    vec![
        "plonky2".into(), op.into(), families.into(),
        format!("{:.3}", agg.prove_total_ms_median),
        format!("{:.3}", agg.verify_ms_median),
        agg.proof_size_bytes.to_string(),
        format!("{:.1}", agg.peak_rss_mb_median),
    ]
}

fn main() {
    let m = env_usize("EXP_E8_M", 64);
    let db = env_usize("EXP_E8_DB", 32);
    let trials = env_usize("EXP_E8_TRIALS", 2);
    let leaf_cfg = BenchCfg { warmup: 1, trials };
    let merge_cfg = BenchCfg { warmup: 0, trials: 1 };
    println!("E8 cross-stack (plonky2 SNARK) — CM d=4 w=8 m={m} distinct_bound={db}");

    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky2".into()), ("field", "Goldilocks".into()),
        ("experiment", "e8_crossstack".into()), ("cm_shape", format!("d4_w8_m{m}_db{db}")),
    ]);
    let hdr: Vec<String> = ["backend", "op", "families", "prove_total_ms_median",
        "verify_ms_median", "proof_size_bytes", "peak_rss_mb_median"]
        .iter().map(|s| s.to_string()).collect();
    let _ = std::fs::remove_file(dir.join("e8_crossstack.csv"));

    let params = CmFinalParams { d: 4, w: 8, batch: m };
    let leaf = build_countmin_final_leaf(params);
    let empty = CountMinState::new(&CountMinParams { d: 4, w: 8 });
    let batch1 = keys(m, db, 0);
    let batch2 = keys(m, db, 1);

    // ── op = leaf ─────────────────────────────────────────────────────────────
    let agg = bench(leaf_cfg, || {
        let (node, wg, pv) = leaf.prove_timed(&empty, &batch1, 0).expect("cm leaf");
        let (vr, vt) = time_it(|| verify_node(&node));
        vr.expect("verify leaf");
        RunOutcome { witness_gen: wg, prove: pv, verify: vt,
            proof_size_bytes: node.proof.to_bytes().len() as u64, trace_rows: 0, num_columns: 0 }
    });
    append_csv(&dir, "e8_crossstack", &hdr, &row("leaf", "cm", &agg));
    println!("  leaf            prove={:.1}ms verify={:.2}ms size={}B", agg.prove_total_ms_median, agg.verify_ms_median, agg.proof_size_bytes);

    // ── op = recursive_merge (cm+cm, real recursive SNARK) ─────────────────────
    let node1 = leaf.prove(&empty, &batch1, 0).expect("leaf1");
    let mut s1 = empty.clone();
    for u in &batch1 { apply_update_prf(&mut s1, u); }
    let node2 = leaf.prove(&s1, &batch2, 1).expect("leaf2");
    let agg = bench(merge_cfg, || {
        let (merged, tm) = time_it(|| merge(&node1, &node2).expect("merge"));
        let (vr, tv) = time_it(|| verify_node(&merged));
        vr.expect("verify merged");
        RunOutcome { witness_gen: Duration::ZERO, prove: tm, verify: tv,
            proof_size_bytes: merged.proof.to_bytes().len() as u64, trace_rows: 0, num_columns: 0 }
    });
    append_csv(&dir, "e8_crossstack", &hdr, &row("recursive_merge", "cm", &agg));
    println!("  recursive_merge prove={:.1}ms verify={:.2}ms size={}B (real recursive SNARK)", agg.prove_total_ms_median, agg.verify_ms_median, agg.proof_size_bytes);

    println!("done → {}", dir.join("e8_crossstack.csv").display());
    println!("note: cross_family_merge (cm+hll) omitted on plonky2 — no unified state commitment (see module doc).");
}
