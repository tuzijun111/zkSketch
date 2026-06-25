//! E8 — cross-stack head-to-head, **plonky3 (STARK)** side (EVAL_SPEC E8). Same
//! certified Count-Min leaf shape on both backends, plus a recursive merge of two
//! leaves and one cross-family (cm+hll) merge. Pairs with the plonky2 runner
//! `plonky2/examples/e8_crossstack.rs`; the two CSVs merge into
//! `results/e8_crossstack.csv` (a `backend` column distinguishes them).
//!
//! Three ops:
//! - `leaf` — prove one CM leaf (§1 metrics).
//! - `recursive_merge` — `merge_two_countmin_v9` of two chainable CM leaves. This
//!   is a **real recursive batch-STARK** (it re-verifies both leaves in-circuit).
//! - `cross_family_merge` (cm+hll) — composed via the §4 framework's option-(i)
//!   boundary digest (`merge_atom`), **not** a recursive STARK: the recursive
//!   cross-family merge is a gap (CM and HLL have different state commitments /
//!   PI shapes), so the framework digest path is the only cross-family composition
//!   the prototype supports. Flagged accordingly.
//!
//! Run:    cargo run --release --example exp_e8
//! Config: EXP_E8_M=64 (spec target 1000; scaled down — the recursive v9 merge is
//!         ~10s+ each at this prototype) EXP_E8_DB=32 EXP_E8_TRIALS=2

use std::hint::black_box;
use std::time::Duration;

use zksketch::experiments::families::{cm_empty, cm_epoch, hll_empty, hll_epoch};
use zksketch::experiments::metrics::{append_csv, bench, write_env_json, AggRow, BenchCfg, RunOutcome};
use zksketch::experiments::{env_usize, proof_size, results_dir, time_it};
use zksketch::recursion::framework::{lift_leaf, merge_atom, root_commitment, EpochLeaf};
use zksketch::recursion::recursive::countmin_leaf::CountMinLeafParams;
use zksketch::recursion::recursive::countmin_merge_v9::{merge_two_countmin_v9, verify_chain_countmin_v9};
use zksketch::recursion::recursive::timing;
use zksketch::sketch::countmin::CountMinUpdate;
use zksketch::sketch::countmin_final::{apply_update_prf, prove_countmin_final, CountMinFinalParams};
use zksketch::sketch::hll_final_full::HllFullParams;

fn keys(m: usize, distinct: usize, salt: usize) -> Vec<u32> {
    (0..m)
        .map(|j| (((salt * distinct + (j % distinct)) as u64 + 1).wrapping_mul(0x9E37_79B9) as u32) | 1)
        .collect()
}
fn ups(ks: &[u32]) -> Vec<CountMinUpdate> {
    ks.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect()
}

fn row(op: &str, families: &str, agg: &AggRow) -> Vec<String> {
    vec![
        "plonky3".into(), op.into(), families.into(),
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
    let merge_cfg = BenchCfg { warmup: 0, trials: 1 }; // recursive merge is ~10s+; one honest sample
    println!("E8 cross-stack (plonky3) — CM d=4 w=8 m={m} distinct_bound={db}");

    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky3".into()), ("field", "BabyBear".into()),
        ("hash", "Poseidon2".into()), ("experiment", "e8_crossstack".into()),
        ("cm_shape", format!("d4_w8_m{m}_db{db}")),
    ]);
    let hdr: Vec<String> = ["backend", "op", "families", "prove_total_ms_median",
        "verify_ms_median", "proof_size_bytes", "peak_rss_mb_median"]
        .iter().map(|s| s.to_string()).collect();
    let _ = std::fs::remove_file(dir.join("e8_crossstack.csv"));

    let p = CountMinFinalParams { d: 4, w: 8, batch: m };
    let _ = CountMinLeafParams { d: 4, w: 8, batch: m }; // (shape parity with plonky2)
    let batch1 = ups(&keys(m, db, 0));
    let batch2 = ups(&keys(m, db, 1));

    // ── op = leaf ─────────────────────────────────────────────────────────────
    let agg = bench(leaf_cfg, || {
        let l = prove_countmin_final(p, cm_empty(4, 8), batch1.clone());
        let t = timing::take();
        RunOutcome { witness_gen: t.witness, prove: t.prove, verify: t.verify,
            proof_size_bytes: proof_size(&l.output.0) as u64, trace_rows: 0, num_columns: 0 }
    });
    append_csv(&dir, "e8_crossstack", &hdr, &row("leaf", "cm", &agg));
    println!("  leaf            prove={:.1}ms verify={:.2}ms size={}B", agg.prove_total_ms_median, agg.verify_ms_median, agg.proof_size_bytes);

    // ── op = recursive_merge (cm+cm, real recursive batch-STARK) ───────────────
    let l1 = prove_countmin_final(p, cm_empty(4, 8), batch1.clone());
    let mut s1 = cm_empty(4, 8);
    for u in &batch1 { apply_update_prf(&mut s1, u); }
    let l2 = prove_countmin_final(p, s1.clone(), batch2.clone());
    let agg = bench(merge_cfg, || {
        let (chain, tm) = time_it(|| merge_two_countmin_v9(&l1, &l2).expect("v9 merge"));
        let (vr, tv) = time_it(|| verify_chain_countmin_v9(&chain));
        vr.expect("verify chain");
        RunOutcome { witness_gen: Duration::ZERO, prove: tm, verify: tv,
            proof_size_bytes: proof_size(&chain.recursive_proof.0) as u64, trace_rows: 0, num_columns: 0 }
    });
    append_csv(&dir, "e8_crossstack", &hdr, &row("recursive_merge", "cm", &agg));
    println!("  recursive_merge prove={:.1}ms verify={:.2}ms size={}B (real recursive STARK)", agg.prove_total_ms_median, agg.verify_ms_median, agg.proof_size_bytes);

    // ── op = cross_family_merge (cm+hll, §4 framework digest — option (i)) ──────
    let me = if m % 2 == 0 { m } else { m + 1 };
    let cm_keys = keys(m, db, 2);
    let (cm_o, _) = cm_epoch(p, &cm_empty(4, 8), &cm_keys);
    let hp = HllFullParams { b: 4, batch: me };
    let hll_keys = keys(me, me.min(64), 3);
    let (hll_o, _) = hll_epoch(hp, &hll_empty(hp), &hll_keys);
    // SYNTHETIC boundary: we set epoch-2's com_before := epoch-1's com_after so
    // the two heterogeneous leaves form a syntactically valid 2-epoch chain. This
    // is NOT a semantically valid CM→HLL state transition (no such conversion
    // exists); it measures the framework's *composition-layer* cost of binding two
    // different-family leaves under one root, which is sketch-agnostic by design.
    let e1 = EpochLeaf::new(1, cm_o.com_before, cm_o.com_after, cm_o.batch_commit, 1);
    let e2 = EpochLeaf::new(2, cm_o.com_after, hll_o.com_after, hll_o.batch_commit, 2);
    let agg = bench(leaf_cfg, || {
        let (root, tm) = time_it(|| merge_atom(&lift_leaf(&e1), &lift_leaf(&e2)).expect("cross-family merge"));
        let (_, tv) = time_it(|| {
            let _ = black_box(root_commitment(&root));
        });
        RunOutcome { witness_gen: Duration::ZERO, prove: tm, verify: tv,
            proof_size_bytes: 96, trace_rows: 0, num_columns: 0 } // IntervalProof digest artifact
    });
    append_csv(&dir, "e8_crossstack", &hdr, &row("cross_family_merge", "cm+hll", &agg));
    println!("  cross_family    prove={:.4}ms verify={:.4}ms size=96B (framework digest, NOT recursive; synthetic cm→hll boundary — composition-layer cost only)", agg.prove_total_ms_median, agg.verify_ms_median);

    // ── op = cross_family_merge_recursive (cm+hll, REAL recursive batch-STARK) ──
    // Genuinely aggregates a CM leaf proof AND an HLL leaf proof into ONE
    // recursive proof that re-verifies BOTH leaves (vs. the digest row above).
    // There is no shared boundary (independent families); the proof binds both
    // leaves' (initial, final) commitments under one combined digest.
    {
        use zksketch::recursion::recursive::countmin_leaf::{prove_countmin_leaf, D as CMD, W as CMW};
        use zksketch::recursion::recursive::cross_family_merge::{merge_cm_hll, verify_cm_hll};
        use zksketch::recursion::recursive::hll_leaf::{prove_hll_leaf, B as HLLB};
        use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};
        use zksketch::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogUpdate};
        use zksketch::sketch::Sketch;
        let cmleaf = prove_countmin_leaf(
            CountMin::new(&CountMinParams { d: CMD, w: CMW }),
            [CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }],
        );
        let hllleaf = prove_hll_leaf(
            HyperLogLog::new(&HyperLogLogParams { b: HLLB }),
            [HyperLogLogUpdate { key: 0xDEAD_BEEF }, HyperLogLogUpdate { key: 0xC0FFEE }],
        );
        let agg = bench(merge_cfg, || {
            let (m2, tm) = time_it(|| merge_cm_hll(&cmleaf, &hllleaf).expect("real cross-family merge"));
            let (vr, tv) = time_it(|| verify_cm_hll(&m2));
            vr.expect("verify cross-family");
            RunOutcome {
                witness_gen: Duration::ZERO, prove: tm, verify: tv,
                proof_size_bytes: proof_size(&m2.recursive_proof.0) as u64, trace_rows: 0, num_columns: 0,
            }
        });
        append_csv(&dir, "e8_crossstack", &hdr, &row("cross_family_merge_recursive", "cm+hll", &agg));
        println!("  cross_family(REAL) prove={:.1}ms verify={:.2}ms size={}B (real recursive STARK aggregating a CM leaf + an HLL leaf)",
            agg.prove_total_ms_median, agg.verify_ms_median, agg.proof_size_bytes);
    }

    println!("done → {}", dir.join("e8_crossstack.csv").display());
}
