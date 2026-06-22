//! E1 — circuit-cost runner for the **plonky3 (STARK)** backend (EVAL_SPEC E1/§1).
//!
//! Benches each certified family leaf over a configurable dataset slice with
//! `1 warm-up + N trials`, capturing the full §1 metric set — witness/prove/
//! verify split (from `recursion::recursive::timing`, recorded inside each
//! `prove_*`), `prove_total` median+p95, proof size, summed trace rows, and
//! **peak RSS** — and appends one row per `(family, m)` to
//! `results/e1_circuit.csv`, plus an `env.json`.
//!
//! **Fair-comparison note:** `witness_gen` = trace generation, `prove` =
//! `prove_all_tables`; the per-call circuit *build* is excluded (amortized),
//! matching plonky2's build-once/prove pattern so the two backends'
//! `prove_total` are comparable (the COMPARISON.md caveat). plonky3's
//! multi-table batch-STARK has no single `num_columns`, so we set it to 1 and
//! report `trace_rows` = Σ padded heights (constraint_count = trace_rows).
//!
//! Run (small slice, default):
//!   cargo run --release --example exp_e1
//! Configure (env): EXP_DATASET=uniform|gaussian|zipf|aol|netflix,
//!   EXP_M=4,8,16,32   EXP_TRIALS=5   EXP_WARMUP=1
//! Whole vs partial dataset: this runner consumes `max(EXP_M)` keys per family
//! (a *small slice* — fine for testing). To exercise the real datasets, fetch
//! them first (`python3 scripts/fetch_datasets.py`) and set EXP_DATASET=aol.

use zksketch::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch::experiments::metrics::{append_csv, bench, write_env_json, AggRow, BenchCfg, RunOutcome};
use zksketch::experiments::{env_usize, proof_size, results_dir};
use zksketch::recursion::recursive::timing;

use zksketch::experiments::families::cm_empty;
use zksketch::recursion::recursive::countmin_leaf::{prove_countmin_leaf_with_params, CountMinLeafParams};
use zksketch::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::countmin_final::{generate_proof as cm_prove, CountMinFinalParams};
use zksketch::sketch::countmin_merkle::{prove_countmin_merkle_leaf, CountMinMerkleParams};
use zksketch::sketch::hll_merkle::{prove_hll_merkle_leaf, HllMerkleParams};
use zksketch::sketch::gk_final_full::{generate_proof as gk_prove, GKFullParams, GKFullUpdate};
use zksketch::sketch::hll_final_full::{generate_proof as hll_prove, HllFullParams, HllFullUpdate};
use zksketch::sketch::ss_final_full::{generate_proof as ss_prove, SsFullParams, SsFullUpdate};

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
fn env_list(key: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(key) {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => default.to_vec(),
    }
}

/// `n` keys from the named dataset (synthetic generated; real sliced). `None`
/// when a real dataset hasn't been fetched.
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

fn cfg() -> BenchCfg {
    BenchCfg { warmup: env_usize("EXP_WARMUP", 0), trials: env_usize("EXP_TRIALS", 1) }
}

fn outcome(proof_bytes: u64) -> RunOutcome {
    let t = timing::take();
    RunOutcome {
        witness_gen: t.witness,
        prove: t.prove,
        verify: t.verify,
        proof_size_bytes: proof_bytes,
        trace_rows: t.trace_rows,
        num_columns: 1, // batch-STARK has no single column count; see module note
    }
}

fn row(family: &str, variant: &str, m: usize, d: usize, w: usize, s: usize, agg: &AggRow) -> Vec<String> {
    let mut r = vec![
        "plonky3".into(), family.into(), variant.into(),
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
    // cm|gk|hll|ss (e.g. EXP_FAMILY=cm runs only Count-Min, both variants).
    let family_sel = env_str("EXP_FAMILY", "all");
    let want = |f: &str| family_sel == "all" || family_sel.split(',').any(|x| x.trim() == f);
    println!(
        "E1 (plonky3 STARK) — dataset={dataset}  m={ms:?}  family={family_sel}  trials={}",
        cfg().trials
    );

    let Some(keys) = keys_for(&dataset, max_m) else {
        eprintln!(
            "dataset '{dataset}' unavailable (real datasets need `python3 scripts/fetch_datasets.py`). \
             Falling back to nothing — set EXP_DATASET=uniform for an offline run."
        );
        std::process::exit(2);
    };

    let dir = results_dir();
    write_env_json(
        &dir,
        &[
            ("backend", "plonky3".into()),
            ("field", "BabyBear".into()),
            ("hash", "Poseidon2".into()),
            ("ext_degree_D", "4".into()),
            ("dataset", dataset.clone()),
        ],
    );
    let hdr: Vec<String> = {
        let mut h: Vec<String> = ["backend", "family", "variant", "m", "d", "w", "s"]
            .iter().map(|s| s.to_string()).collect();
        h.extend(AggRow::header().iter().map(|s| s.to_string()));
        h.push("status".into());
        h
    };

    let c = cfg();
    // Count-Min width-sweep knobs (used when EXP_FAMILY includes cm):
    //   EXP_D            depth d                      (default 4, must be 1..=8)
    //   EXP_W            comma-list of widths w        (default 8; powers of two)
    //   EXP_CM_VARIANT   certified | replay | merkle | both | comma-list
    //                    (default both = certified+replay). `merkle` = the
    //                    sparse Merkle-commit leaf (cost Θ(distinct·d·log w),
    //                    independent of w — the head-to-head vs the flat
    //                    `certified` circuit). e.g. EXP_CM_VARIANT=certified,merkle
    //   EXP_DISTINCT_BOUND  certified-only distinct-key cap (see below)
    // The certified §5.2 circuit guards its selector budget; for big widths set
    // EXP_CM_VARIANT=certified (the replay strawman is O(d·w·batch) and has no
    // guard), and raise COUNTMIN_MAX_SEL_CELLS if you hit the budget panic.
    //
    // distinct_bound knob — the lever for scaling batch. The certified circuit's
    // dominant cost is `distinct_bound·d·(d·w)`, NOT batch; batch only feeds the
    // cheaper size-`batch` table + compaction stages. By default we pin
    // `distinct_bound = m` (the worst case: every key distinct), which is what
    // makes raising EXP_M blow the selector budget. To grow the batch cheaply,
    // bound the distinct-key count instead via EXP_DISTINCT_BOUND:
    //   <unset>  → m            (worst-case baseline; unchanged behaviour)
    //   <n>      → min(n, m)    (must be ≥ the slice's actual distinct count, or
    //                            the v9h leaf panics "… distinct keys but …")
    //   auto     → actual distinct keys in the slice (smallest always-safe value)
    let cm_d = env_usize("EXP_D", 4);
    let cm_ws = env_list("EXP_W", &[8]);
    let cm_variant = env_str("EXP_CM_VARIANT", "both");
    // `both` = certified+replay (back-compat); otherwise a comma-list of
    // certified|replay|merkle.
    let cm_wants = |v: &str| {
        if cm_variant == "both" {
            v == "certified" || v == "replay"
        } else {
            cm_variant.split(',').any(|x| x.trim() == v)
        }
    };
    let cm_db = env_str("EXP_DISTINCT_BOUND", "");
    for &m in &ms {
        let slice = take(&keys, m);
        let me = m.max(2) + (m % 2); // even batch for GK/SS/HLL
        let slice_e = take(&keys, me);

        if want("cm") {
            let ups: Vec<CountMinUpdate> =
                slice.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
            // distinct_bound for the certified circuit (independent of w).
            let distinct_bound = match cm_db.as_str() {
                "" => m,
                "auto" => {
                    let mut u = slice.clone();
                    u.sort_unstable();
                    u.dedup();
                    u.len().max(1)
                }
                s => s.parse::<usize>().unwrap_or(m).clamp(1, m),
            };
            if cm_wants("certified") {
                println!("  cm certified: m={m} distinct_bound={distinct_bound} (sel cells/w = distinct_bound·d·d·w)");
            }
            for &cm_w in &cm_ws {
                let s_cells = cm_d * cm_w;
                // CM certified (§5.2) FLAT-commit circuit. Cost = distinct_bound·d·(d·w).
                if cm_wants("certified") {
                    let p = CountMinFinalParams { d: cm_d, w: cm_w, batch: m, distinct_bound };
                    let agg = bench(c, || { let r = cm_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
                    append_csv(&dir, "e1_circuit", &hdr, &row("cm", "certified", m, cm_d, cm_w, s_cells, &agg));
                }
                // CM replay baseline (§5.1 strawman: naive per-record in-circuit replay).
                if cm_wants("replay") {
                    let lp = CountMinLeafParams { d: cm_d, w: cm_w, batch: m };
                    let agg = bench(c, || {
                        let leaf = prove_countmin_leaf_with_params(lp, cm_empty(cm_d, cm_w), ups.clone());
                        outcome(proof_size(&leaf.output.0) as u64)
                    });
                    append_csv(&dir, "e1_circuit", &hdr, &row("cm", "replay", m, cm_d, cm_w, s_cells, &agg));
                }
                // CM sparse Merkle-commit leaf (§5.2 RQ2-c). Cost Θ(t_max·d·log w),
                // INDEPENDENT of w — the whole point of the comparison. t_max
                // bounds distinct touched cells per row (≤ min(m, w)).
                if cm_wants("merkle") {
                    let t_max = m.min(cm_w);
                    let initial = CountMinState {
                        counters: vec![vec![0u32; cm_w]; cm_d],
                        params: CountMinParams { d: cm_d, w: cm_w },
                    };
                    let mp = CountMinMerkleParams { d: cm_d, w: cm_w, batch: m, t_max };
                    let agg = bench(c, || {
                        let r = prove_countmin_merkle_leaf(mp, initial.clone(), ups.clone());
                        outcome(r.proof_size() as u64)
                    });
                    append_csv(&dir, "e1_circuit", &hdr, &row("cm", "merkle", m, cm_d, cm_w, s_cells, &agg));
                }
            }
        }

        if want("gk") {
            // GK (capacity 8).
            let p = GKFullParams { capacity: 8, batch: me };
            let ups: Vec<GKFullUpdate> = slice_e.iter().map(|&k| GKFullUpdate::real(k & 0x003F_FFFF)).collect();
            let agg = bench(c, || { let r = gk_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
            append_csv(&dir, "e1_circuit", &hdr, &row("gk", "certified", me, 0, 0, 8, &agg));
        }

        if want("hll") {
            // HLL — flat `certified` vs sparse `merkle`, sweeping b (m = 2^b).
            //   EXP_HLL_B        comma-list of b values        (default 4)
            //   EXP_HLL_VARIANT  certified|merkle|comma-list   (default certified)
            // merkle = the sparse Merkle-commit leaf (cost Θ(t_max·log m), flat
            // in m); e.g. EXP_HLL_VARIANT=certified,merkle for the head-to-head.
            let hll_bs = env_list("EXP_HLL_B", &[4]);
            let hll_variant = env_str("EXP_HLL_VARIANT", "certified");
            let hll_wants = |v: &str| hll_variant.split(',').any(|x| x.trim() == v);
            let keys_e: Vec<u64> = slice_e.iter().map(|&k| k as u64).collect();
            for &hb in &hll_bs {
                let m_reg = 1usize << hb;
                if hll_wants("certified") {
                    let p = HllFullParams { b: hb, batch: me };
                    let ups: Vec<HllFullUpdate> = slice_e.iter().map(|&k| HllFullUpdate::real(k as u64)).collect();
                    let agg = bench(c, || { let r = hll_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
                    append_csv(&dir, "e1_circuit", &hdr, &row("hll", "certified", me, 0, 0, m_reg, &agg));
                }
                if hll_wants("merkle") {
                    let t_max = me.min(m_reg);
                    let initial = vec![0u64; m_reg];
                    let mp = HllMerkleParams { b: hb, batch: me, t_max };
                    let agg = bench(c, || {
                        let r = prove_hll_merkle_leaf(mp, initial.clone(), keys_e.clone());
                        outcome(r.proof_size() as u64)
                    });
                    append_csv(&dir, "e1_circuit", &hdr, &row("hll", "merkle", me, 0, 0, m_reg, &agg));
                }
            }
        }

        if want("ss") {
            // SS (capacity 8).
            let p = SsFullParams { capacity: 8, batch: me };
            let ups: Vec<SsFullUpdate> = slice_e.iter().map(|&k| SsFullUpdate::real(((k & 0x3FFF_FFFF) | 1) as u64, 1)).collect();
            let agg = bench(c, || { let r = ss_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
            append_csv(&dir, "e1_circuit", &hdr, &row("ss", "certified", me, 0, 0, 8, &agg));
        }

        println!("  m={m:<4} done (family={family_sel}) → {}", dir.display());
    }
    println!("done. results in {}", dir.display());
}
