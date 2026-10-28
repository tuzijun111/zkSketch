//! E1 on plonky2: leaf circuit cost per family (time, proof size, RSS), appended to plonky2/results/e1_circuit.csv.
//! Usage: cd plonky2 && EXP_DATASET=uniform EXP_M=4,8,16,32 cargo run --release --example e1_metrics_demo

use zksketch_snark::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch_snark::leaf::countmin_final::{build_countmin_final_leaf, empty_state as cm_empty, CmFinalParams};
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
    let mut h: Vec<String> = ["backend", "dataset", "family", "variant", "m", "d", "w", "s"]
        .iter().map(|s| s.to_string()).collect();
    h.extend(AggRow::header().iter().map(|s| s.to_string()));
    // The plonky3 runner's per-row commitment mode; plonky2 is plain-only.
    h.push("commit".into());
    h.push("status".into());
    h
}

// The CSV row builders `row` / `row_skip` are closures inside `main` so they can
// capture this run's `dataset` for the leading `dataset` column (mirrors the
// plonky3 runner so the two CSVs merge).

fn main() {
    let dataset_arg = env_str("EXP_DATASET", "uniform");
    // EXP_DATASET may be a comma-list of datasets — sweep each in turn.
    let datasets: Vec<String> =
        dataset_arg.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let ms = env_list("EXP_M", &[4, 8, 16, 32]);
    let max_m = *ms.iter().max().unwrap_or(&32);
    // EXP_FAMILY filters which families run: "all" (default) or a comma-list of
    // cm|gk|hll|ss (e.g. EXP_FAMILY=cm runs only Count-Min).
    let family_sel = env_str("EXP_FAMILY", "all");
    let want = |f: &str| family_sel == "all" || family_sel.split(',').any(|x| x.trim() == f);
    // Count-Min knobs: EXP_D depth (any d>=1; the PRF hash draws ceil(d/4)
    // digests per key), EXP_W comma-list of widths (powers of two). CM is
    // `one_hot`-only on plonky2 — the flat one-hot sparse-patch leaf; the retired
    // replay/merkle leaves remain in the tree but are no longer wired into E1
    // (plonky2 has no Merkle-commit `merkle` variant).
    let cm_d = env_usize("EXP_D", 4);
    let cm_ws = env_list("EXP_W", &[8]);
    let cm_variant = env_str("EXP_CM_VARIANT", "one_hot");
    let cm_wants = |v: &str| cm_variant.split(',').any(|x| x.trim() == v);
    // E1 always runs each config exactly once (no warm-up, one trial) — the CSV
    // reports a single value per metric, not median/p95.
    let cfg = BenchCfg { warmup: 0, trials: 1 };
    println!("E1 (plonky2 SNARK) — datasets={datasets:?}  m={ms:?}  family={family_sel}  trials={}", cfg.trials);

    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky2".into()),
        ("field", "Goldilocks".into()),
        ("hash", "Poseidon".into()),
        ("ext_degree_D", "2".into()),
        ("dataset", dataset_arg.clone()),
    ]);
    let header = hdr();

    for dataset in &datasets {
        let Some(keys) = keys_for(dataset, max_m) else {
            eprintln!("dataset '{dataset}' unavailable (real ones need ../scripts/fetch_datasets.py) — skipping");
            continue;
        };
        // CSV row builders — capture this dataset for the leading `dataset` column.
        let row = |family: &str, variant: &str, m: usize, d: usize, w: usize, s: usize, agg: &AggRow| -> Vec<String> {
            let mut r = vec![
                "plonky2".into(), dataset.clone(), family.into(), variant.into(),
                m.to_string(), d.to_string(), w.to_string(), s.to_string(),
            ];
            r.extend(agg.fields());
            r.push("plain".into());
            r.push("ok".into());
            r
        };
        let row_skip = |family: &str, variant: &str, m: usize, d: usize, w: usize, s: usize, status: &str| -> Vec<String> {
            let mut r = vec![
                "plonky2".into(), dataset.clone(), family.into(), variant.into(),
                m.to_string(), d.to_string(), w.to_string(), s.to_string(),
            ];
            r.extend(std::iter::repeat("n/a".to_string()).take(AggRow::header().len()));
            r.push("plain".into());
            r.push(status.into());
            r
        };
        println!("-- dataset={dataset} --");
        for &m in &ms {
            let slice = take(&keys, m);
            // CM — `one_hot` flat-commit leaf (plonky2 has no merkle), sweeping width (EXP_W).
            if want("cm") {
                let ups: Vec<CountMinUpdate> = slice.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
                for &cm_w in &cm_ws {
                    let s_cells = cm_d * cm_w;
                    // Flat-commit certified circuit (cost Θ(d·w)).
                    if cm_wants("one_hot") {
                        let leaf = build_countmin_final_leaf(CmFinalParams { d: cm_d, w: cm_w, batch: m });
                        let tr = leaf.data.common.degree() as u64;
                        let nc = leaf.data.common.config.num_wires as u64;
                        let agg = bench(cfg, || {
                            let (node, wg, pv) = leaf.prove_timed(&cm_empty(cm_d, cm_w), &ups, 1).expect("cm prove");
                            let proof_size_bytes = node.proof.to_bytes().len() as u64;
                            let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                            vr.expect("verify");
                            RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
                        });
                        append_csv(&dir, "e1_circuit", &header, &row("cm", "one_hot", m, cm_d, cm_w, s_cells, &agg));
                    }
                }
            }
            // HLL — flat `certified` vs sparse `merkle`, sweeping b (m = 2^b).
            //   EXP_HLL_B        comma-list of b values        (default 4)
            //   EXP_HLL_VARIANT  one_hot|merkle|comma-list     (default one_hot)
            if want("hll") {
                let hll_bs = env_list("EXP_HLL_B", &[4]);
                let hll_variant = env_str("EXP_HLL_VARIANT", "one_hot");
                let hll_wants = |v: &str| hll_variant.split(',').any(|x| x.trim() == v);
                // Selector-cell budget for the flat O(m·batch) `certified` leaf
                // (registers·batch). Beyond it the eager build allocates a scatter
                // that OOM-kills the prover BEFORE proving — and an OOM is a SIGKILL,
                // not a catchable panic — so we skip pre-build, not catch it. Same
                // knob (and default) as the plonky3 leaf's HLL_FULL_MAX_SEL_CELLS, so
                // both backends draw the certified/merkle line at the same point;
                // raise it on a big box, lower it on a small one. Large m → `merkle`.
                let hll_max_sel_cells = env_usize("HLL_FULL_MAX_SEL_CELLS", 4_194_304);
                let keys_u: Vec<u64> = slice.iter().map(|&k| k as u64).collect();
                for &hb in &hll_bs {
                    let m_reg = 1usize << hb;
                    if hll_wants("one_hot") {
                        let sel_cells = m_reg.saturating_mul(m);
                        if sel_cells > hll_max_sel_cells {
                            println!("  hll one_hot m={m} b={hb} (regs={m_reg}): SKIPPED — too large (flat O(m·batch)={sel_cells} > HLL_FULL_MAX_SEL_CELLS={hll_max_sel_cells}; build OOMs). Raise the cap or use EXP_HLL_VARIANT=merkle.");
                            append_csv(&dir, "e1_circuit", &header, &row_skip("hll", "one_hot", m, 0, 0, m_reg, "too_large"));
                        } else {
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
                            append_csv(&dir, "e1_circuit", &header, &row("hll", "one_hot", m, 0, 0, m_reg, &agg));
                        }
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
            // SpaceSaving — size = capacity (top-s). EXP_SS_CAP = comma-list of
            // capacities (default 8); each rounded up to even ≥2 (SS fusion needs an
            // even union, so batch is evened to `me` too).
            if want("ss") {
                let me = m.max(2) + (m % 2);
                let slice_e = take(&keys, me);
                let ups: Vec<SsUpdate> = slice_e.iter().map(|&k| SsUpdate::real(((k & 0x3FFF_FFFF) | 1) as u64, 1)).collect();
                for &cap in &env_list("EXP_SS_CAP", &[8]) {
                    let cap = cap.max(2) + (cap % 2);
                    let leaf = build_spacesaving_leaf(SsLeafParams { capacity: cap, batch: me });
                    let tr = leaf.data.common.degree() as u64;
                    let nc = leaf.data.common.config.num_wires as u64;
                    let agg = bench(cfg, || {
                        let (node, wg, pv) = leaf.prove_timed(&ss_empty(cap, me), &ups, 1).expect("ss prove");
                        let proof_size_bytes = node.proof.to_bytes().len() as u64;
                        let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                        vr.expect("verify");
                        RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
                    });
                    append_csv(&dir, "e1_circuit", &header, &row("ss", "certified", me, 0, 0, cap, &agg));
                }
            }
            // GK quantile summary — size = capacity (tuple budget). EXP_GK_CAP =
            // comma-list of capacities (default 8); each rounded up to even ≥2. Batch
            // is evened to `me` (pairwise fusion needs an even union).
            if want("gk") {
                let me = m.max(2) + (m % 2);
                let slice_e = take(&keys, me);
                let ups: Vec<GkUpdate> = slice_e.iter().map(|&k| GkUpdate::real((k & 0x000F_FFFF) as u64)).collect();
                for &cap in &env_list("EXP_GK_CAP", &[8]) {
                    let cap = cap.max(2) + (cap % 2);
                    let leaf = build_gk_leaf(GkLeafParams { capacity: cap, batch: me });
                    let tr = leaf.data.common.degree() as u64;
                    let nc = leaf.data.common.config.num_wires as u64;
                    let agg = bench(cfg, || {
                        let (node, wg, pv) = leaf.prove_timed(&gk_empty(cap, me), &ups, 1).expect("gk prove");
                        let proof_size_bytes = node.proof.to_bytes().len() as u64;
                        let (vr, verify) = time_it(|| node.data.verify(node.proof.clone()));
                        vr.expect("verify");
                        RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes, trace_rows: tr, num_columns: nc }
                    });
                    append_csv(&dir, "e1_circuit", &header, &row("gk", "certified", me, 0, 0, cap, &agg));
                }
            }
            println!("  m={m:<4} done");
        }
    }
    println!("done. results in {}", dir.display());
}
