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
use zksketch::sketch::countmin::CountMinUpdate;
use zksketch::sketch::countmin_final::{generate_proof as cm_prove, CountMinFinalParams};
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
    BenchCfg { warmup: env_usize("EXP_WARMUP", 1), trials: env_usize("EXP_TRIALS", 5) }
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
    println!("E1 (plonky3 STARK) — dataset={dataset}  m={ms:?}  trials={}", cfg().trials);

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
    for &m in &ms {
        let slice = take(&keys, m);
        let me = m.max(2) + (m % 2); // even batch for GK/SS/HLL
        let slice_e = take(&keys, me);

        // CM (d=4, w=8, distinct_bound=m) — certified (§5.2) circuit.
        let p = CountMinFinalParams { d: 4, w: 8, batch: m, distinct_bound: m };
        let ups: Vec<CountMinUpdate> = slice.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
        let agg = bench(c, || { let r = cm_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
        append_csv(&dir, "e1_circuit", &hdr, &row("cm", "certified", m, 4, 8, 32, &agg));

        // CM replay baseline (§5.1 strawman: naive per-record in-circuit replay).
        let lp = CountMinLeafParams { d: 4, w: 8, batch: m };
        let agg = bench(c, || {
            let leaf = prove_countmin_leaf_with_params(lp, cm_empty(4, 8), ups.clone());
            outcome(proof_size(&leaf.output.0) as u64)
        });
        append_csv(&dir, "e1_circuit", &hdr, &row("cm", "replay", m, 4, 8, 32, &agg));

        // GK (capacity 8).
        let p = GKFullParams { capacity: 8, batch: me };
        let ups: Vec<GKFullUpdate> = slice_e.iter().map(|&k| GKFullUpdate::real(k & 0x003F_FFFF)).collect();
        let agg = bench(c, || { let r = gk_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
        append_csv(&dir, "e1_circuit", &hdr, &row("gk", "certified", me, 0, 0, 8, &agg));

        // HLL (b=4 → 16 registers).
        let p = HllFullParams { b: 4, batch: me };
        let ups: Vec<HllFullUpdate> = slice_e.iter().map(|&k| HllFullUpdate::real(k as u64)).collect();
        let agg = bench(c, || { let r = hll_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
        append_csv(&dir, "e1_circuit", &hdr, &row("hll", "certified", me, 0, 0, 16, &agg));

        // SS (capacity 8).
        let p = SsFullParams { capacity: 8, batch: me };
        let ups: Vec<SsFullUpdate> = slice_e.iter().map(|&k| SsFullUpdate::real(((k & 0x3FFF_FFFF) | 1) as u64, 1)).collect();
        let agg = bench(c, || { let r = ss_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
        let path = append_csv(&dir, "e1_circuit", &hdr, &row("ss", "certified", me, 0, 0, 8, &agg));

        println!("  m={m:<4} done (cm/gk/hll/ss) → {}", path.display());
    }
    println!("done. results in {}", dir.display());
}
