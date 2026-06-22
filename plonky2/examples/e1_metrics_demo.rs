//! E1 — circuit-cost runner for the **plonky2 (SNARK)** backend (EVAL_SPEC E1/§1).
//!
//! Benches each certified family leaf (CM, HLL, SS, GK) over a configurable
//! S³-dataset slice with `1 warm-up + N trials`, capturing the full §1 metric
//! set via [`zksketch_snark::metrics`] — witness/prove/verify split (the leaves'
//! `prove_timed`), `prove_total` median+p95, proof size, trace_rows·num_columns,
//! and **peak RSS** — and appends one row per `(family, m)` to
//! `plonky2/results/e1_circuit.csv` plus an `env.json`. The schema matches the
//! plonky3 runner (`../examples/exp_e1.rs`) so the two CSVs merge directly.
//!
//! Run (small slice, default): `cargo +nightly run --release --example e1_metrics_demo`
//! Configure (env): EXP_DATASET=uniform|gaussian|zipf|aol|netflix
//!   EXP_M=4,8,16,32   EXP_TRIALS=5   EXP_WARMUP=1
//! Real datasets need `python3 ../scripts/fetch_datasets.py` first (shared
//! `../data/*.keys`). The runner consumes `max(EXP_M)` keys per family (a small
//! testing slice); raise EXP_M for larger runs.

use zksketch_snark::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch_snark::leaf::countmin_final::{build_countmin_final_leaf, empty_state as cm_empty, CmFinalParams};
use zksketch_snark::leaf::countmin_merkle::{build_cm_merkle_leaf, CmMerkleParams};
use zksketch_snark::leaf::hll_merkle::{build_hll_merkle_leaf, HllMerkleParams};
use zksketch_snark::leaf::greenwald_khanna::{build_gk_leaf, empty_state as gk_empty, GkLeafParams};
use zksketch_snark::leaf::hyperloglog::{build_hll_leaf, HllLeafParams};
use zksketch_snark::leaf::spacesaving::{build_spacesaving_leaf, empty_state as ss_empty, SsLeafParams};
use zksketch_snark::metrics::{append_csv, bench, results_dir, time_it, write_env_json, AggRow, BenchCfg, RunOutcome};
use zksketch_snark::sketch::countmin::CountMinUpdate;
use zksketch_snark::sketch::greenwald_khanna::GkUpdate;
use zksketch_snark::sketch::hyperloglog::{HllParams, HllState, HllUpdate};
use zksketch_snark::sketch::spacesaving::SsUpdate;

fn env_str(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}
fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d)
}
fn env_list(k: &str, d: &[usize]) -> Vec<usize> {
    match std::env::var(k) {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => d.to_vec(),
    }
}

fn keys_for(name: &str, n: usize) -> Option<Vec<u32>> {
    match name {
        "uniform" => Some(synthetic_stream(Synthetic::Uniform, n, 1)),
        "gaussian" => Some(synthetic_stream(Synthetic::Gaussian, n, 1)),
        "zipf" => Some(zipf_stream(1.0, n.max(16), n, 1)),
        "aol" => aol().map(|k| take(&k, n)),
        "netflix" => netflix().map(|k| take(&k, n)),
        _ => None,
    }
}

fn hdr() -> Vec<String> {
    let mut h: Vec<String> =
        ["backend", "family", "variant", "m", "d", "w", "s"].iter().map(|s| s.to_string()).collect();
    h.extend(AggRow::header().iter().map(|s| s.to_string()));
    h.push("status".into());
    h
}

fn row(family: &str, variant: &str, m: usize, d: usize, w: usize, s: usize, agg: &AggRow) -> Vec<String> {
    let mut r = vec![
        "plonky2".into(), family.into(), variant.into(),
        m.to_string(), d.to_string(), w.to_string(), s.to_string(),
    ];
    r.extend(agg.fields());
    r.push("ok".into());
    r
}

fn main() {
    let dataset = env_str("EXP_DATASET", "uniform");
    let ms = env_list("EXP_M", &[4, 8, 16, 32]);
    let max_m = *ms.iter().max().unwrap_or(&32);
    // EXP_FAMILY filters which families run: "all" (default) or a comma-list of
    // cm|gk|hll|ss (e.g. EXP_FAMILY=cm runs only Count-Min).
    let family_sel = env_str("EXP_FAMILY", "all");
    let want = |f: &str| family_sel == "all" || family_sel.split(',').any(|x| x.trim() == f);
    // Count-Min knobs: EXP_D depth (1..=4 on plonky2), EXP_W comma-list of widths
    // (powers of two), EXP_CM_VARIANT = comma-list of certified|merkle (default
    // certified). `merkle` = the sparse Merkle-commit leaf (cost Θ(distinct·d·log w),
    // flat in w); e.g. EXP_CM_VARIANT=certified,merkle for the head-to-head.
    let cm_d = env_usize("EXP_D", 4);
    let cm_ws = env_list("EXP_W", &[8]);
    let cm_variant = env_str("EXP_CM_VARIANT", "certified");
    let cm_wants = |v: &str| cm_variant.split(',').any(|x| x.trim() == v);
    let cfg = BenchCfg { warmup: env_usize("EXP_WARMUP", 1), trials: env_usize("EXP_TRIALS", 5) };
    println!("E1 (plonky2 SNARK) — dataset={dataset}  m={ms:?}  family={family_sel}  trials={}", cfg.trials);

    let Some(keys) = keys_for(&dataset, max_m) else {
        eprintln!("dataset '{dataset}' unavailable (real ones need ../scripts/fetch_datasets.py). Use EXP_DATASET=uniform offline.");
        std::process::exit(2);
    };

    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky2".into()),
        ("field", "Goldilocks".into()),
        ("hash", "Poseidon".into()),
        ("ext_degree_D", "2".into()),
        ("dataset", dataset.clone()),
    ]);
    let header = hdr();

    for &m in &ms {
        let slice = take(&keys, m);
        // CM — flat `certified` vs sparse `merkle`, sweeping width (EXP_W).
        if want("cm") {
            let ups: Vec<CountMinUpdate> = slice.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
            for &cm_w in &cm_ws {
                let s_cells = cm_d * cm_w;
                // Flat-commit certified circuit (cost Θ(d·w)).
                if cm_wants("certified") {
                    let leaf = build_countmin_final_leaf(CmFinalParams { d: cm_d, w: cm_w, batch: m, distinct_bound: m });
                    let tr = leaf.data.common.degree() as u64;
                    let nc = leaf.data.common.config.num_wires as u64;
                    let agg = bench(cfg, || {
                        let (node, wg, pv) = leaf.prove_timed(&cm_empty(cm_d, cm_w), &ups, 1).expect("cm prove");
                        let proof_size_bytes = node.proof.to_bytes().len() as u64;
                        let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                        vr.expect("verify");
                        RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
                    });
                    append_csv(&dir, "e1_circuit", &header, &row("cm", "certified", m, cm_d, cm_w, s_cells, &agg));
                }
                // Sparse Merkle-commit leaf (cost Θ(t_max·d·log w), flat in w).
                if cm_wants("merkle") {
                    let t_max = m.min(cm_w);
                    let leaf = build_cm_merkle_leaf(CmMerkleParams { d: cm_d, w: cm_w, batch: m, t_max });
                    let tr = leaf.data.common.degree() as u64;
                    let nc = leaf.data.common.config.num_wires as u64;
                    let initial = vec![vec![0u64; cm_w]; cm_d];
                    let agg = bench(cfg, || {
                        let (node, wg, pv) = leaf.prove_timed(&initial, &ups, 1).expect("cm merkle prove");
                        let proof_size_bytes = node.proof.to_bytes().len() as u64;
                        let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                        vr.expect("verify");
                        RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
                    });
                    append_csv(&dir, "e1_circuit", &header, &row("cm", "merkle", m, cm_d, cm_w, s_cells, &agg));
                }
            }
        }
        // HLL — flat `certified` vs sparse `merkle`, sweeping b (m = 2^b).
        //   EXP_HLL_B        comma-list of b values        (default 4)
        //   EXP_HLL_VARIANT  certified|merkle|comma-list   (default certified)
        if want("hll") {
            let hll_bs = env_list("EXP_HLL_B", &[4]);
            let hll_variant = env_str("EXP_HLL_VARIANT", "certified");
            let hll_wants = |v: &str| hll_variant.split(',').any(|x| x.trim() == v);
            let keys_u: Vec<u64> = slice.iter().map(|&k| k as u64).collect();
            for &hb in &hll_bs {
                let m_reg = 1usize << hb;
                if hll_wants("certified") {
                    let leaf = build_hll_leaf(HllLeafParams { b: hb, batch: m });
                    let ups: Vec<HllUpdate> = slice.iter().map(|&k| HllUpdate { key: k as u64 }).collect();
                    let st = HllState::new(&HllParams { b: hb });
                    let tr = leaf.data.common.degree() as u64;
                    let nc = leaf.data.common.config.num_wires as u64;
                    let agg = bench(cfg, || {
                        let (node, wg, pv) = leaf.prove_timed(&st, &ups, 1).expect("hll prove");
                        let proof_size_bytes = node.proof.to_bytes().len() as u64;
                        let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                        vr.expect("verify");
                        RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
                    });
                    append_csv(&dir, "e1_circuit", &header, &row("hll", "certified", m, 0, 0, m_reg, &agg));
                }
                if hll_wants("merkle") {
                    let t_max = m.min(m_reg);
                    let leaf = build_hll_merkle_leaf(HllMerkleParams { b: hb, batch: m, t_max });
                    let tr = leaf.data.common.degree() as u64;
                    let nc = leaf.data.common.config.num_wires as u64;
                    let initial = vec![0u64; m_reg];
                    let agg = bench(cfg, || {
                        let (node, wg, pv) = leaf.prove_timed(&initial, &keys_u, 1).expect("hll merkle prove");
                        let proof_size_bytes = node.proof.to_bytes().len() as u64;
                        let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                        vr.expect("verify");
                        RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
                    });
                    append_csv(&dir, "e1_circuit", &header, &row("hll", "merkle", m, 0, 0, m_reg, &agg));
                }
            }
        }
        // SS (capacity 8).
        if want("ss") {
            let leaf = build_spacesaving_leaf(SsLeafParams { capacity: 8, batch: m });
            let ups: Vec<SsUpdate> = slice.iter().map(|&k| SsUpdate::real(((k & 0x3FFF_FFFF) | 1) as u64, 1)).collect();
            let tr = leaf.data.common.degree() as u64;
            let nc = leaf.data.common.config.num_wires as u64;
            let agg = bench(cfg, || {
                let (node, wg, pv) = leaf.prove_timed(&ss_empty(8, m), &ups, 1).expect("ss prove");
                let proof_size_bytes = node.proof.to_bytes().len() as u64;
                let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                vr.expect("verify");
                RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
            });
            append_csv(&dir, "e1_circuit", &header, &row("ss", "certified", m, 0, 0, 8, &agg));
        }
        // GK (capacity 8; batch must be even).
        if want("gk") && m % 2 == 0 {
            let leaf = build_gk_leaf(GkLeafParams { capacity: 8, batch: m });
            let ups: Vec<GkUpdate> = slice.iter().map(|&k| GkUpdate::real((k & 0x000F_FFFF) as u64)).collect();
            let tr = leaf.data.common.degree() as u64;
            let nc = leaf.data.common.config.num_wires as u64;
            let agg = bench(cfg, || {
                let (node, wg, pv) = leaf.prove_timed(&gk_empty(8, m), &ups, 1).expect("gk prove");
                let proof_size_bytes = node.proof.to_bytes().len() as u64;
                let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                vr.expect("verify");
                RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
            });
            append_csv(&dir, "e1_circuit", &header, &row("gk", "certified", m, 0, 0, 8, &agg));
        }
        println!("  m={m:<4} done");
    }
    println!("done. results in {}", dir.display());
}
