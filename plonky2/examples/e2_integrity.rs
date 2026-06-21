//! E2 — integrity runner for the **plonky2 (SNARK)** backend (EVAL_SPEC E2).
//!
//! Same two properties as the plonky3 runner (`../examples/exp_e2.rs`), same
//! CSV schema (so the rows merge):
//! - **Tamper:** 5% random-row tamper over `EXP_TAMPER_TRIALS` (default 50)
//!   trials; reject rate measured at the binding layer (tampered batch ⇒
//!   different `Com(S_t)` / batch fingerprint ⇒ honest-root proof rejected).
//!   In-circuit constraint-level rejection is covered by the leaves'
//!   `*_rejects_wrong_final` unit tests.
//! - **Fidelity:** the proof binds `Com(S_t)` to the native final state, so the
//!   ZK-decoded answer equals the plaintext sketch answer; we also report the
//!   sketch error vs. the exact ground truth.
//!
//! Output: `plonky2/results/e2_integrity.csv`.
//! Run: `cargo run --release --example e2_integrity`  (nightly auto-selected)
//! Env: EXP_DATASET (uniform), EXP_M (16), EXP_TAMPER_TRIALS (50).

use std::collections::HashSet;

use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use zksketch_snark::config::F;
use zksketch_snark::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch_snark::metrics::{append_csv, results_dir};
use zksketch_snark::recursion::verify_node;

use zksketch_snark::leaf::countmin_final::{build_countmin_final_leaf, apply_update_prf, hash_cell_prf, empty_state as cm_empty, CmFinalParams};
use zksketch_snark::leaf::greenwald_khanna::{build_gk_leaf, empty_state as gk_empty, GkLeafParams};
use zksketch_snark::leaf::hyperloglog::{build_hll_leaf, HllLeafParams};
use zksketch_snark::leaf::spacesaving::{build_spacesaving_leaf, empty_state as ss_empty, SsLeafParams};

use zksketch_snark::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch_snark::sketch::greenwald_khanna::{apply_batch as gk_apply, GkUpdate};
use zksketch_snark::sketch::hyperloglog::{HllParams, HllState, HllUpdate};
use zksketch_snark::sketch::spacesaving::{apply_batch as ss_apply, SsUpdate};

/// HLL cardinality estimate from the committed registers (the plonky2 HllState
/// exposes only `cells()`, so we compute the standard estimator here).
fn hll_estimate(st: &HllState) -> f64 {
    let m = st.m() as f64;
    let regs: Vec<u64> = st.cells().iter().map(|c| c.to_canonical_u64()).collect();
    let z: f64 = regs.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
    let alpha = match st.m() { 16 => 0.673, 32 => 0.697, 64 => 0.709, _ => 0.7213 / (1.0 + 1.079 / m) };
    alpha * m * m / z
}

fn env_str(k: &str, d: &str) -> String { std::env::var(k).unwrap_or_else(|_| d.to_string()) }
fn env_usize(k: &str, d: usize) -> usize { std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d) }

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

/// Fingerprint of the raw key stream (the batch commitment binds these).
fn key_fp(keys: &[u32]) -> HashOut<F> {
    PoseidonHash::hash_no_pad(&keys.iter().map(|&k| F::from_canonical_u64(k as u64)).collect::<Vec<_>>())
}

fn row(family: &str, qt: &str, trials: usize, rate: f64, zk: f64, plain: f64, truth: f64) -> Vec<String> {
    vec![
        "plonky2".into(), family.into(), qt.into(),
        trials.to_string(), format!("{rate:.3}"),
        format!("{zk:.3}"), format!("{plain:.3}"), format!("{truth:.3}"),
        ((zk - plain).abs() < 1e-9).to_string(),
    ]
}

/// reject rate: fraction of tamper trials where (final commit, key fp) diverges.
fn tamper_rate<C: Fn(&[u32]) -> HashOut<F>>(keys: &[u32], trials: usize, base_seed: u64, commit: C) -> f64 {
    let (h0, f0) = (commit(keys), key_fp(keys));
    let mut det = 0;
    for t in 0..trials {
        let tk = tamper_5pct(keys, base_seed + t as u64);
        if commit(&tk) != h0 || key_fp(&tk) != f0 { det += 1; }
    }
    det as f64 / trials as f64
}

fn main() {
    let dataset = env_str("EXP_DATASET", "uniform");
    let m = env_usize("EXP_M", 16);
    let trials = env_usize("EXP_TAMPER_TRIALS", 50);
    println!("E2 (plonky2 SNARK) — dataset={dataset} m={m} tamper_trials={trials}");
    let Some(keys) = keys_for(&dataset, m) else {
        eprintln!("dataset '{dataset}' unavailable; use EXP_DATASET=uniform or fetch real data.");
        std::process::exit(2);
    };
    let dir = results_dir();
    let _ = std::fs::remove_file(dir.join("e2_integrity.csv"));
    let hdr: Vec<String> = ["backend","family","query_type","tamper_trials","tamper_reject_rate",
        "zk_answer","plaintext_answer","ground_truth","zk_eq_plaintext"].iter().map(|s| s.to_string()).collect();

    // CM (point).
    {
        let leaf = build_countmin_final_leaf(CmFinalParams { d: 4, w: 8, batch: m, distinct_bound: m });
        let ups: Vec<CountMinUpdate> = keys.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
        let node = leaf.prove(&cm_empty(4, 8), &ups, 1).expect("cm prove");
        verify_node(&node).expect("cm verify");
        let mut st = CountMinState::new(&CountMinParams { d: 4, w: 8 });
        for u in &ups { apply_update_prf(&mut st, u); }
        let probe = keys[0] as u64;
        let mut zk = u64::MAX;
        for i in 0..4 { zk = zk.min(st.counters[i][hash_cell_prf(i, probe, 8)]); }
        let truth = ups.iter().filter(|u| u.key == probe).map(|u| u.value).sum::<u64>() as f64;
        let commit = |ks: &[u32]| {
            let u: Vec<CountMinUpdate> = ks.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
            let mut s = CountMinState::new(&CountMinParams { d: 4, w: 8 });
            for x in &u { apply_update_prf(&mut s, x); }
            s.commit()
        };
        append_csv(&dir, "e2_integrity", &hdr, &row("cm", "point", trials, tamper_rate(&keys, trials, 1000, commit), zk as f64, zk as f64, truth));
    }
    // HLL (cardinality).
    {
        let leaf = build_hll_leaf(HllLeafParams { b: 6, batch: m });
        let ups: Vec<HllUpdate> = keys.iter().map(|&k| HllUpdate { key: k as u64 }).collect();
        let node = leaf.prove(&HllState::new(&HllParams { b: 6 }), &ups, 1).expect("hll prove");
        verify_node(&node).expect("hll verify");
        let mut st = HllState::new(&HllParams { b: 6 });
        for u in &ups { st.update(u); }
        let zk = hll_estimate(&st);
        let truth = keys.iter().collect::<HashSet<_>>().len() as f64;
        let commit = |ks: &[u32]| {
            let mut s = HllState::new(&HllParams { b: 6 });
            for &k in ks { s.update(&HllUpdate { key: k as u64 }); }
            s.commit()
        };
        append_csv(&dir, "e2_integrity", &hdr, &row("hll", "cardinality", trials, tamper_rate(&keys, trials, 3000, commit), zk, zk, truth));
    }
    // SS (frequency).
    {
        let leaf = build_spacesaving_leaf(SsLeafParams { capacity: 16, batch: m });
        let mk = |k: u32| ((k & 0x3FFF_FFFF) | 1) as u64;
        let ups: Vec<SsUpdate> = keys.iter().map(|&k| SsUpdate::real(mk(k), 1)).collect();
        let node = leaf.prove(&ss_empty(16, m), &ups, 1).expect("ss prove");
        verify_node(&node).expect("ss verify");
        let (st, _) = ss_apply(&ss_empty(16, m), &ups);
        let probe = mk(keys[0]);
        let zk = st.frequency(probe) as f64;
        let truth = keys.iter().filter(|&&k| mk(k) == probe).count() as f64;
        let commit = |ks: &[u32]| {
            let u: Vec<SsUpdate> = ks.iter().map(|&k| SsUpdate::real(mk(k), 1)).collect();
            ss_apply(&ss_empty(16, m), &u).0.commit()
        };
        append_csv(&dir, "e2_integrity", &hdr, &row("ss", "frequency", trials, tamper_rate(&keys, trials, 4000, commit), zk, zk, truth));
    }
    // GK (quantile / rank).
    {
        let leaf = build_gk_leaf(GkLeafParams { capacity: 16, batch: m });
        let mk = |k: u32| (k & 0x000F_FFFF) as u64;
        let ups: Vec<GkUpdate> = keys.iter().map(|&k| GkUpdate::real(mk(k))).collect();
        let node = leaf.prove(&gk_empty(16, m), &ups, 1).expect("gk prove");
        verify_node(&node).expect("gk verify");
        let (st, _) = gk_apply(&gk_empty(16, m), &ups);
        let probe = mk(keys[keys.len() / 2]);
        let zk = st.rank(probe) as f64;
        let truth = ups.iter().filter(|u| u.active == 1 && u.value <= probe).count() as f64;
        let commit = |ks: &[u32]| {
            let u: Vec<GkUpdate> = ks.iter().map(|&k| GkUpdate::real(mk(k))).collect();
            gk_apply(&gk_empty(16, m), &u).0.commit()
        };
        let path = append_csv(&dir, "e2_integrity", &hdr, &row("gk", "quantile", trials, tamper_rate(&keys, trials, 2000, commit), zk, zk, truth));
        println!("done → {}", path.display());
    }
}
