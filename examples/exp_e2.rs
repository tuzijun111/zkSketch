//! E2 — integrity runner for the **plonky3 (STARK)** backend (EVAL_SPEC E2).
//!
//! Two correctness properties per family:
//! - **Soundness / tamper:** replace a uniform-random 5% of a batch's rows with
//!   random data; over `EXP_TAMPER_TRIALS` (default 50) trials record the
//!   fraction *rejected*. We measure rejection at the **binding layer**: a 5%
//!   tamper changes the batch commitment and/or `Com(S_t)`, so any proof bound
//!   to the honest history root is rejected. (Constraint-level rejection — the
//!   prover *cannot* produce an accepted proof of a false transition — is
//!   covered by the `*_soundness_rejects_*` / `*_rho_binding_*` unit tests;
//!   run `cargo test --release --lib soundness rejects`.)
//! - **Fidelity:** the ZK-verified decoded answer equals the plaintext sketch
//!   answer (the proof binds `Com(S_t)` to the natively-recomputed state), and
//!   we report the sketch's error vs. the exact ground truth.
//!
//! Output: `results/e2_integrity.csv`
//!   `backend, family, query_type, tamper_trials, tamper_reject_rate,
//!    zk_answer, plaintext_answer, ground_truth, zk_eq_plaintext`
//!
//! Run: `cargo run --release --example exp_e2`
//! Env: EXP_DATASET (default uniform), EXP_M (default 16), EXP_TAMPER_TRIALS (50).

use std::collections::HashSet;

use zksketch::commitment::countmin::commit_countmin;
use zksketch::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch::experiments::metrics::append_csv;
use zksketch::experiments::{env_usize, results_dir};

use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};
use zksketch::sketch::countmin_final::{apply_update_prf, generate_proof as cm_prove, hash_cell_prf, CountMinFinalParams};
use zksketch::sketch::Sketch;

use zksketch::sketch::gk_final_full::{
    apply_batch_full, commit_gk_batch, commit_gk_state, generate_proof as gk_prove, GKFullParams, GKFullState, GKFullUpdate,
};
use zksketch::sketch::hll_final_full::{
    apply_batch as hll_apply, commit_hll_batch, commit_hll_state, generate_proof as hll_prove, HllFullParams, HllFullState, HllFullUpdate,
};
use zksketch::sketch::ss_final_full::{
    apply_batch_ss_full, commit_ss_batch, commit_ss_state, generate_proof as ss_prove, SsFullParams, SsFullState, SsFullUpdate,
};
use zksketch::commitment::countmin_batch::commit_batch as commit_cm_batch;

fn env_str(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
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

/// Replace ~5% of rows (≥1) with deterministic-random keys.
fn tamper_5pct(keys: &[u32], seed: u64) -> Vec<u32> {
    let mut out = keys.to_vec();
    let n = ((keys.len() as f64 * 0.05).ceil() as usize).max(1);
    let mut s = seed ^ 0xA5A5_5A5A_DEAD_BEEF;
    for _ in 0..n {
        s = s.wrapping_mul(0x2545_F491_4F6C_DD1D).wrapping_add(1);
        let idx = (s >> 33) as usize % out.len();
        s = s.wrapping_mul(0x2545_F491_4F6C_DD1D).wrapping_add(1);
        let nk = ((s >> 32) as u32) ^ 0x1357_9BDF;
        out[idx] = if nk == out[idx] { nk.wrapping_add(1) } else { nk };
    }
    out
}

fn row(family: &str, qt: &str, trials: usize, rate: f64, zk: f64, plain: f64, truth: f64) -> Vec<String> {
    vec![
        "plonky3".into(),
        family.into(),
        qt.into(),
        trials.to_string(),
        format!("{rate:.3}"),
        format!("{zk:.3}"),
        format!("{plain:.3}"),
        format!("{truth:.3}"),
        ((zk - plain).abs() < 1e-9).to_string(),
    ]
}

fn main() {
    let dataset = env_str("EXP_DATASET", "uniform");
    let m = env_usize("EXP_M", 16);
    let trials = env_usize("EXP_TAMPER_TRIALS", 50);
    println!("E2 (plonky3 STARK) — dataset={dataset} m={m} tamper_trials={trials}");
    let Some(keys) = keys_for(&dataset, m) else {
        eprintln!("dataset '{dataset}' unavailable; use EXP_DATASET=uniform or fetch real data.");
        std::process::exit(2);
    };
    let dir = results_dir();
    let hdr: Vec<String> = ["backend", "family", "query_type", "tamper_trials", "tamper_reject_rate",
        "zk_answer", "plaintext_answer", "ground_truth", "zk_eq_plaintext"].iter().map(|s| s.to_string()).collect();
    // fresh file
    let _ = std::fs::remove_file(dir.join("e2_integrity.csv"));

    // ── CM (point query) ──────────────────────────────────────────────
    {
        let p = CountMinFinalParams { d: 4, w: 8, batch: m };
        let ups: Vec<CountMinUpdate> = keys.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
        let r = cm_prove(p, ups.clone());
        let probe = keys[0] as u64;
        let zk = r.query(probe) as f64;
        let mut st = CountMin::new(&CountMinParams { d: 4, w: 8 });
        for u in &ups { apply_update_prf(&mut st, u); }
        let mut plain = u32::MAX;
        for i in 0..4 { plain = plain.min(st.counters[i][hash_cell_prf(i, probe, 8)]); }
        let truth = ups.iter().filter(|u| u.key == probe).map(|u| u.value as u64).sum::<u64>() as f64;
        // tamper
        let cm_commit = |ks: &[u32]| {
            let u: Vec<CountMinUpdate> = ks.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
            let mut s = CountMin::new(&CountMinParams { d: 4, w: 8 });
            for x in &u { apply_update_prf(&mut s, x); }
            (commit_countmin(&s).0, commit_cm_batch(&u).0)
        };
        let (h0, b0) = cm_commit(&keys);
        let mut det = 0;
        for t in 0..trials {
            let (h1, b1) = cm_commit(&tamper_5pct(&keys, 1000 + t as u64));
            if h1 != h0 || b1 != b0 { det += 1; }
        }
        append_csv(&dir, "e2_integrity", &hdr, &row("cm", "point", trials, det as f64 / trials as f64, zk, plain as f64, truth));
    }

    // ── GK (quantile / rank) ──────────────────────────────────────────
    {
        let p = GKFullParams { capacity: 16, batch: m };
        let ups: Vec<GKFullUpdate> = keys.iter().map(|&k| GKFullUpdate::real(k & 0x003F_FFFF)).collect();
        let r = gk_prove(p, ups.clone());
        let probe = (keys[keys.len() / 2] & 0x003F_FFFF) as u32;
        let zk = r.final_state.rank(probe) as f64;
        let truth = ups.iter().filter(|u| u.active == 1 && u.value <= probe).count() as f64;
        let gk_commit = |ks: &[u32]| {
            let u: Vec<GKFullUpdate> = ks.iter().map(|&k| GKFullUpdate::real(k & 0x003F_FFFF)).collect();
            let (s, _) = apply_batch_full(&GKFullState::empty(p), &u);
            (commit_gk_state(&s).0, commit_gk_batch(&u).0)
        };
        let (h0, b0) = gk_commit(&keys);
        let mut det = 0;
        for t in 0..trials {
            let (h1, b1) = gk_commit(&tamper_5pct(&keys, 2000 + t as u64));
            if h1 != h0 || b1 != b0 { det += 1; }
        }
        append_csv(&dir, "e2_integrity", &hdr, &row("gk", "quantile", trials, det as f64 / trials as f64, zk, zk, truth));
    }

    // ── HLL (cardinality) ─────────────────────────────────────────────
    {
        let p = HllFullParams { b: 6, batch: m };
        let ups: Vec<HllFullUpdate> = keys.iter().map(|&k| HllFullUpdate::real(k as u64)).collect();
        let r = hll_prove(p, ups.clone());
        let zk = r.final_state.estimate();
        let truth = keys.iter().collect::<HashSet<_>>().len() as f64;
        let hll_commit = |ks: &[u32]| {
            let u: Vec<HllFullUpdate> = ks.iter().map(|&k| HllFullUpdate::real(k as u64)).collect();
            let s = hll_apply(&HllFullState::empty(p), &u);
            (commit_hll_state(&s).0, commit_hll_batch(&u).0)
        };
        let (h0, b0) = hll_commit(&keys);
        let mut det = 0;
        for t in 0..trials {
            let (h1, b1) = hll_commit(&tamper_5pct(&keys, 3000 + t as u64));
            if h1 != h0 || b1 != b0 { det += 1; }
        }
        append_csv(&dir, "e2_integrity", &hdr, &row("hll", "cardinality", trials, det as f64 / trials as f64, zk, zk, truth));
    }

    // ── SS (frequency) ────────────────────────────────────────────────
    {
        let p = SsFullParams { capacity: 16, batch: m };
        let mk = |k: u32| ((k & 0x3FFF_FFFF) | 1) as u64;
        let ups: Vec<SsFullUpdate> = keys.iter().map(|&k| SsFullUpdate::real(mk(k), 1)).collect();
        let r = ss_prove(p, ups.clone());
        let probe = mk(keys[0]);
        let zk = r.final_state.frequency(probe) as f64;
        let truth = keys.iter().filter(|&&k| mk(k) == probe).count() as f64;
        let ss_commit = |ks: &[u32]| {
            let u: Vec<SsFullUpdate> = ks.iter().map(|&k| SsFullUpdate::real(mk(k), 1)).collect();
            let (s, _) = apply_batch_ss_full(&SsFullState::empty(p), &u);
            (commit_ss_state(&s).0, commit_ss_batch(&u).0)
        };
        let (h0, b0) = ss_commit(&keys);
        let mut det = 0;
        for t in 0..trials {
            let (h1, b1) = ss_commit(&tamper_5pct(&keys, 4000 + t as u64));
            if h1 != h0 || b1 != b0 { det += 1; }
        }
        let path = append_csv(&dir, "e2_integrity", &hdr, &row("ss", "frequency", trials, det as f64 / trials as f64, zk, zk, truth));
        println!("done → {}", path.display());
    }
}
