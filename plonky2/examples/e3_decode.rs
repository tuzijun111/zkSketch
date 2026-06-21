//! E3 — decode/query cost runner for the **plonky2 (SNARK)** backend
//! (EVAL_SPEC E3). For each `(family, query_type)` it benches the decode proof
//! against a committed state, **sweeping the state size `s`** (the decode cost's
//! only structural dependence — it re-hashes the whole committed state) and
//! adding a **release-policy** variant. Uses the shared metrics harness.
//!
//! Output: `plonky2/results/e3_decode.csv`
//!   `backend, family, query_type, s, release_policy, constraint_count,
//!    prove_total_ms_median, verify_ms_median, proof_size_bytes, peak_rss_mb_median`
//!
//! Run: `cargo run --release --example e3_decode`
//! Env: EXP_DATASET (uniform), EXP_TRIALS (5).
//! Note: decode circuits exist on plonky2 here; the plonky3 decode (AIR) is
//! future work, so E3 is plonky2-only for now.

use plonky2::field::types::PrimeField64;

use zksketch_snark::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch_snark::decode::countmin::{build_cm_decode, CmDecodeParams};
use zksketch_snark::decode::greenwald_khanna::{build_gk_decode, GkDecodeParams};
use zksketch_snark::decode::hyperloglog::{build_hll_decode, HllDecodeParams};
use zksketch_snark::decode::spacesaving::{build_ss_decode, SsDecodeParams};
use zksketch_snark::decode::ReleasePolicy;
use zksketch_snark::metrics::{append_csv, bench, results_dir, time_it, write_env_json, BenchCfg, RunOutcome};

use zksketch_snark::leaf::countmin_final::apply_update_prf;
use zksketch_snark::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch_snark::sketch::greenwald_khanna::{apply_batch as gk_apply, GkParams, GkState, GkUpdate};
use zksketch_snark::sketch::hyperloglog::{HllParams, HllState, HllUpdate};
use zksketch_snark::sketch::spacesaving::{apply_batch as ss_apply, SsParams, SsState, SsUpdate};

fn env_str(k: &str, d: &str) -> String { std::env::var(k).unwrap_or_else(|_| d.to_string()) }
fn env_usize(k: &str, d: usize) -> usize { std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d) }

fn keys_for(name: &str, n: usize) -> Vec<u32> {
    match name {
        "gaussian" => synthetic_stream(Synthetic::Gaussian, n, 1),
        "zipf" => zipf_stream(1.0, n.max(16), n, 1),
        "aol" => aol().map(|k| take(&k, n)).unwrap_or_else(|| synthetic_stream(Synthetic::Uniform, n, 1)),
        "netflix" => netflix().map(|k| take(&k, n)).unwrap_or_else(|| synthetic_stream(Synthetic::Uniform, n, 1)),
        _ => synthetic_stream(Synthetic::Uniform, n, 1),
    }
}

fn hdr() -> Vec<String> {
    ["backend", "family", "query_type", "s", "release_policy", "constraint_count",
     "prove_total_ms_median", "verify_ms_median", "proof_size_bytes", "peak_rss_mb_median"]
        .iter().map(|s| s.to_string()).collect()
}

fn main() {
    let dataset = env_str("EXP_DATASET", "uniform");
    let cfg = BenchCfg { warmup: 1, trials: env_usize("EXP_TRIALS", 5) };
    println!("E3 decode (plonky2 SNARK) — dataset={dataset} trials={}", cfg.trials);
    let dir = results_dir();
    write_env_json(&dir, &[("backend", "plonky2".into()), ("field", "Goldilocks".into()), ("experiment", "e3_decode".into()), ("dataset", dataset.clone())]);
    let hdr = hdr();
    let _ = std::fs::remove_file(dir.join("e3_decode.csv"));

    let push = |family: &str, qt: &str, s: usize, rp: ReleasePolicy, agg: &zksketch_snark::metrics::AggRow| {
        // Read named AggRow fields (robust to column-order changes).
        let row = vec![
            "plonky2".into(), family.into(), qt.into(), s.to_string(), rp.name().into(),
            agg.constraint_count.to_string(),
            format!("{:.3}", agg.prove_total_ms_median),
            format!("{:.3}", agg.verify_ms_median),
            agg.proof_size_bytes.to_string(),
            format!("{:.1}", agg.peak_rss_mb_median),
        ];
        append_csv(&dir, "e3_decode", &hdr, &row);
    };

    // ── CM point: sweep state size s = d*w (d=4) ─────────────────────────
    for &w in &[4usize, 8, 16] {
        let keys = keys_for(&dataset, w * 4);
        let mut st = CountMinState::new(&CountMinParams { d: 4, w });
        for &k in &keys { apply_update_prf(&mut st, &CountMinUpdate { key: k as u64, value: 1 }); }
        let query = keys[0] as u64;
        for rp in [ReleasePolicy::Identity, ReleasePolicy::Threshold(2)] {
            let leaf = build_cm_decode(CmDecodeParams { d: 4, w, release: rp });
            let tr = leaf.data.common.degree() as u64;
            let nc = leaf.data.common.config.num_wires as u64;
            let agg = bench(cfg, || {
                let (dp, wg, pv) = leaf.prove_timed(&st, query).expect("cm decode");
                let (vr, verify) = time_it(|| dp.verify());
                vr.expect("verify");
                RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes: dp.proof_bytes() as u64, trace_rows: tr, num_columns: nc }
            });
            push("cm", "point", 4 * w, rp, &agg);
        }
    }

    // ── SS frequency: sweep capacity ─────────────────────────────────────
    for &cap in &[8usize, 16, 32] {
        let keys = keys_for(&dataset, cap);
        let ups: Vec<SsUpdate> = keys.iter().map(|&k| SsUpdate::real(((k & 0x3FFF_FFFF) | 1) as u64, 1)).collect();
        let (st, _) = ss_apply(&SsState::empty(SsParams { capacity: cap, batch: cap }), &ups);
        let query = st.rows.iter().find(|r| r.active == 1).map(|r| r.key).unwrap_or(1);
        for rp in [ReleasePolicy::Identity, ReleasePolicy::Threshold(1)] {
            let leaf = build_ss_decode(SsDecodeParams { capacity: cap, release: rp });
            let tr = leaf.data.common.degree() as u64;
            let nc = leaf.data.common.config.num_wires as u64;
            let agg = bench(cfg, || {
                let (dp, wg, pv) = leaf.prove_timed(&st, query).expect("ss decode");
                let (vr, verify) = time_it(|| dp.verify());
                vr.expect("verify");
                RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes: dp.proof_bytes() as u64, trace_rows: tr, num_columns: nc }
            });
            push("ss", "frequency", cap, rp, &agg);
        }
    }

    // ── GK rank: sweep capacity ──────────────────────────────────────────
    for &cap in &[8usize, 16, 32] {
        let keys = keys_for(&dataset, cap);
        let ups: Vec<GkUpdate> = keys.iter().map(|&k| GkUpdate::real((k & 0x000F_FFFF) as u64)).collect();
        let (st, _) = gk_apply(&GkState::empty(GkParams { capacity: cap, batch: cap }), &ups);
        let query = st.tuples.iter().filter(|t| t.active == 1).map(|t| t.value).max().unwrap_or(0);
        for rp in [ReleasePolicy::Identity, ReleasePolicy::Threshold(1)] {
            let leaf = build_gk_decode(GkDecodeParams { capacity: cap, release: rp });
            let tr = leaf.data.common.degree() as u64;
            let nc = leaf.data.common.config.num_wires as u64;
            let agg = bench(cfg, || {
                let (dp, wg, pv) = leaf.prove_timed(&st, query).expect("gk decode");
                let (vr, verify) = time_it(|| dp.verify());
                vr.expect("verify");
                RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes: dp.proof_bytes() as u64, trace_rows: tr, num_columns: nc }
            });
            push("gk", "quantile", cap, rp, &agg);
        }
    }

    // ── HLL cardinality: sweep register count m = 2^b (identity only) ─────
    for &b in &[4usize, 5, 6] {
        let m = 1usize << b;
        let keys = keys_for(&dataset, m * 4);
        let mut st = HllState::new(&HllParams { b });
        for &k in &keys { st.update(&HllUpdate { key: k as u64 }); }
        // guard: registers must be ≤ HLL_B (small slices keep them tiny).
        let max_reg = st.cells().iter().map(|c| c.to_canonical_u64()).max().unwrap_or(0);
        if max_reg as usize > zksketch_snark::decode::hyperloglog::HLL_B {
            eprintln!("  hll b={b}: max register {max_reg} > HLL_B; skipping (raise HLL_B)");
            continue;
        }
        let leaf = build_hll_decode(HllDecodeParams { b });
        let tr = leaf.data.common.degree() as u64;
        let nc = leaf.data.common.config.num_wires as u64;
        let agg = bench(cfg, || {
            let (dp, wg, pv) = leaf.prove_timed(&st).expect("hll decode");
            let (vr, verify) = time_it(|| dp.verify());
            vr.expect("verify");
            RunOutcome { witness_gen: wg, prove: pv, verify, proof_size_bytes: dp.proof_bytes() as u64, trace_rows: tr, num_columns: nc }
        });
        push("hll", "cardinality", m, ReleasePolicy::Identity, &agg);
    }

    println!("done → {}", dir.join("e3_decode.csv").display());
}
