//! E7 — maintenance-policy × query-rate runner (EVAL_SPEC E7). Structural
//! simulation of the lazy/eager/smoothed finalisation trade-off on the streaming
//! forest, driven by the measured per-merge cost `τ` and root-verify cost
//! (option-(i) composition; the merge *counts* are the signal, not the absolute
//! ms — same caveat as RQ4/E5).
//!
//! Run:    cargo run --release --example exp_e7
//! Config: EXP_E7_STREAM=65535  EXP_E7_V=100
//! Output: results/e7_policy.csv

use zksketch::experiments::e7_policy::{
    agg, measure_merge_us, measure_real_merge_ms, measure_root_verify_us, query_with_backlog_ms,
    simulate, Policy,
};
use zksketch::experiments::metrics::{append_csv, write_env_json};
use zksketch::experiments::{env_usize, results_dir};

fn main() {
    let t = env_usize("EXP_E7_STREAM", 65535) as u64;
    let v = env_usize("EXP_E7_V", 100) as u64; // inserts/sec
    // EXP_E7_REAL=1 drives the simulation with the REAL recursive-merge cost
    // (one real STARK fold + verify) instead of the option-(i) digest cost.
    let real = std::env::var("EXP_E7_REAL").map(|s| s == "1").unwrap_or(false);
    let (tau_ms, verify_ms, comp) = if real {
        let (tau, ver) = measure_real_merge_ms();
        (tau, ver, "real_recursive_aggregation")
    } else {
        (measure_merge_us() / 1000.0, measure_root_verify_us() / 1000.0, "option_i_boundary_digest")
    };
    println!("E7 policy (plonky3) — stream t={t} v={v}/s  τ={tau_ms:.5}ms verify_base={verify_ms:.5}ms  [{comp}]");

    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky3".into()), ("experiment", "e7_policy".into()),
        ("composition", comp.into()),
        ("tau_ms", format!("{tau_ms:.6}")), ("verify_base_ms", format!("{verify_ms:.6}")),
    ]);
    let hdr: Vec<String> = ["policy", "c", "v", "q", "backlog", "query_latency_ms_median",
        "query_latency_ms_p95", "insert_tail_latency_ms_p95", "finalisation_compositions"]
        .iter().map(|s| s.to_string()).collect();
    let _ = std::fs::remove_file(dir.join("e7_policy.csv"));

    // q ∈ {1/sec, 1/min}: query every v/q inserts (v inserts per sec).
    let q_axes = [("1/sec", v), ("1/min", v * 60)];
    let policies = [Policy::Lazy, Policy::Eager, Policy::Smoothed(1), Policy::Smoothed(2), Policy::Smoothed(4)];

    for (qlabel, query_every) in q_axes {
        for p in policies {
            let sim = simulate(p, t, query_every, tau_ms, verify_ms);
            let (q_med, q_p95, ins_p95, fc) = agg(&sim);
            let row = vec![
                p.name().into(), p.c().to_string(), v.to_string(), qlabel.into(), "-".into(),
                format!("{q_med:.5}"), format!("{q_p95:.5}"), format!("{ins_p95:.5}"), fc.to_string(),
            ];
            append_csv(&dir, "e7_policy", &hdr, &row);
            println!("  {:<9} c={} q={:<5} query_med={q_med:.4}ms query_p95={q_p95:.4}ms insert_tail_p95={ins_p95:.4}ms fc={fc}",
                p.name(), p.c(), qlabel);
        }
    }

    // query-mid-backlog: a query arriving with |Q| unfinalised peaks (lazy).
    for backlog in [8u64, 32, 128] {
        let lat = query_with_backlog_ms(backlog, tau_ms, verify_ms);
        let row = vec![
            "lazy".into(), "0".into(), v.to_string(), "-".into(), backlog.to_string(),
            format!("{lat:.5}"), format!("{lat:.5}"), "-".into(), backlog.saturating_sub(1).to_string(),
        ];
        append_csv(&dir, "e7_policy", &hdr, &row);
        println!("  lazy backlog={backlog:<4} query_latency={lat:.4}ms");
    }

    println!("done → {}", dir.join("e7_policy.csv").display());
}
