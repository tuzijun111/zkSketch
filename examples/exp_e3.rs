//! E3 — decode/query cost runner for the **plonky3 (STARK)** backend
//! (EVAL_SPEC E3). The plonky2 leg (`plonky2/examples/e3_decode.rs`) covers all
//! four families; this is the STARK-backend counterpart (was the missing
//! "plonky3 decode AIR" gap). For each family it benches the decode proof against
//! a committed state, **sweeping the state size `s`** — the decode cost's only
//! structural dependence (it re-hashes the whole committed state) — plus a
//! release-policy variant.
//!
//! Output: `results/e3_decode.csv` (same schema as the plonky2 leg, merged):
//!   `backend, family, query_type, s, release_policy, constraint_count,
//!    prove_total_ms_median, verify_ms_median, proof_size_bytes, peak_rss_mb_median`
//!
//! Run: `cargo run --release --example exp_e3`
//! Env: EXP_DATASET (uniform), EXP_TRIALS (3).

use zksketch::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch::decode::countmin::{prove_cm_decode, CmDecodeParams};
use zksketch::decode::greenwald_khanna::{prove_gk_decode, GkDecodeParams};
use zksketch::decode::hyperloglog::{prove_hll_decode, HllDecodeParams};
use zksketch::decode::spacesaving::{prove_ss_decode, SsDecodeParams};
use zksketch::decode::ReleasePolicy;
use zksketch::experiments::metrics::{append_csv, bench, write_env_json, BenchCfg, RunOutcome};
use zksketch::experiments::results_dir;
use zksketch::recursion::recursive::timing;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::countmin_omc::countmin_omc_advance;
use zksketch::sketch::gk_final_full::{apply_batch_full, GKFullParams, GKFullState, GKFullUpdate};
use zksketch::sketch::hll_final_full::{apply_update as hll_apply, HllFullParams, HllFullState, HllFullUpdate};
use zksketch::sketch::ss_final_full::{apply_batch_ss_full, SsFullParams, SsFullState, SsFullUpdate};
use zksketch::sketch::Sketch;

fn env_str(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}
fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d)
}

fn keys_for(name: &str, n: usize) -> Vec<u32> {
    match name {
        "gaussian" => synthetic_stream(Synthetic::Gaussian, n, 1),
        "zipf" => zipf_stream(1.0, n.max(16), n, 1),
        "aol" => aol().map(|k| take(&k, n)).unwrap_or_else(|| synthetic_stream(Synthetic::Uniform, n, 1)),
        "netflix" => netflix().map(|k| take(&k, n)).unwrap_or_else(|| synthetic_stream(Synthetic::Uniform, n, 1)),
        _ => synthetic_stream(Synthetic::Uniform, n, 1),
    }
}

/// The state the omc leaf certifies for `keys` (process default binding),
/// which the default-binding decoder routes by.
fn cm_state(d: usize, w: usize, keys: &[u32]) -> CountMinState {
    let mut s = CountMin::new(&CountMinParams { d, w });
    let ups: Vec<CountMinUpdate> =
        keys.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
    countmin_omc_advance(&mut s, &ups);
    s
}

fn outcome(proof_bytes: u64) -> RunOutcome {
    let t = timing::take();
    RunOutcome {
        witness_gen: t.witness,
        prove: t.prove,
        verify: t.verify,
        proof_size_bytes: proof_bytes,
        trace_rows: t.trace_rows,
        num_columns: 1,
    }
}

fn main() {
    let dataset = env_str("EXP_DATASET", "uniform");
    let cfg = BenchCfg { warmup: 1, trials: env_usize("EXP_TRIALS", 3) };
    println!("E3 decode (plonky3 STARK) — dataset={dataset} trials={}", cfg.trials);
    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky3".into()), ("field", "BabyBear".into()),
        ("hash", "Poseidon2".into()), ("experiment", "e3_decode".into()),
        ("dataset", dataset.clone()),
    ]);
    let hdr: Vec<String> = ["backend", "family", "query_type", "s", "release_policy",
        "constraint_count", "prove_total_ms_median", "verify_ms_median", "proof_size_bytes",
        "peak_rss_mb_median"]
        .iter().map(|s| s.to_string()).collect();
    let _ = std::fs::remove_file(dir.join("e3_decode.csv"));

    let push = |family: &str, qt: &str, s: usize, rp: ReleasePolicy, agg: &zksketch::experiments::metrics::AggRow| {
        let row = vec![
            "plonky3".into(), family.into(), qt.into(), s.to_string(), rp.name().into(),
            agg.constraint_count.to_string(),
            format!("{:.3}", agg.prove_total_ms_median),
            format!("{:.3}", agg.verify_ms_median),
            agg.proof_size_bytes.to_string(),
            format!("{:.1}", agg.peak_rss_mb_median),
        ];
        append_csv(&dir, "e3_decode", &hdr, &row);
        println!("  {family:<4} {qt:<11} s={s:<3} {:<9} prove={:.1}ms verify={:.2}ms {}B",
            rp.name(), agg.prove_total_ms_median, agg.verify_ms_median, agg.proof_size_bytes);
    };

    // ── Count-Min point-frequency: sweep s = d·w over w ∈ {4,8,16} (d=4) ──
    let d = 4;
    for &w in &[4usize, 8, 16] {
        let s = d * w;
        let keys = keys_for(&dataset, 64);
        let state = cm_state(d, w, &keys);
        let query = keys[0] as u64;
        for rp in [ReleasePolicy::Identity, ReleasePolicy::Threshold(2)] {
            let agg = bench(cfg, || {
                let p = prove_cm_decode(CmDecodeParams { d, w, release: rp }, state.clone(), query);
                outcome(p.proof_size() as u64)
            });
            push("cm", "frequency", s, rp, &agg);
        }
    }

    // ── SpaceSaving top-c heavy-hitter query: sweep s = capacity ∈ {8,16,32} ──
    for &cap in &[8usize, 16, 32] {
        let keys = keys_for(&dataset, cap);
        let params = SsFullParams { capacity: cap, batch: cap };
        let batch: Vec<SsFullUpdate> =
            (0..cap).map(|i| SsFullUpdate::real(keys[i % keys.len()] as u64, 1)).collect();
        let state = apply_batch_ss_full(&SsFullState::empty(params), &batch).0;
        let c = (cap / 4).max(1); // top-c query size
        for rp in [ReleasePolicy::Identity, ReleasePolicy::Threshold(2)] {
            let agg = bench(cfg, || {
                let p = prove_ss_decode(SsDecodeParams { capacity: cap, c, release: rp }, state.clone(), c);
                outcome(p.proof_size() as u64)
            });
            push("ss", "topc", cap, rp, &agg);
        }
    }

    // ── HyperLogLog cardinality: sweep s = m = 2^b over b ∈ {4,5} ──
    for &bb in &[4usize, 5] {
        let m = 1usize << bb;
        let keys = keys_for(&dataset, 64);
        let mut state = HllFullState::empty(HllFullParams { b: bb, batch: 2 });
        for &k in &keys {
            hll_apply(&mut state, &HllFullUpdate::real(k as u64));
        }
        let agg = bench(cfg, || {
            let p = prove_hll_decode(HllDecodeParams { b: bb, release: ReleasePolicy::Identity }, state.clone(), 0);
            outcome(p.proof_size() as u64)
        });
        push("hll", "cardinality", m, ReleasePolicy::Identity, &agg);
    }

    // ── Greenwald-Khanna rank/quantile: sweep s = capacity ∈ {8,16,32} ──
    for &cap in &[8usize, 16, 32] {
        let keys = keys_for(&dataset, cap);
        let params = GKFullParams { capacity: cap, batch: cap };
        let batch: Vec<GKFullUpdate> =
            (0..cap).map(|i| GKFullUpdate::real(keys[i % keys.len()] & 0x000F_FFFF)).collect();
        let state = apply_batch_full(&GKFullState::empty(params), &batch).0;
        let query = (keys[0] & 0x000F_FFFF) as u64;
        for rp in [ReleasePolicy::Identity, ReleasePolicy::Threshold(2)] {
            let agg = bench(cfg, || {
                let p = prove_gk_decode(GkDecodeParams { capacity: cap, release: rp }, state.clone(), query);
                outcome(p.proof_size() as u64)
            });
            push("gk", "quantile", cap, rp, &agg);
        }
    }

    println!("done → {}", dir.join("e3_decode.csv").display());
}
