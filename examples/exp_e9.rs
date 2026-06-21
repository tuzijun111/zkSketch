//! E9 — optimisation ablations (EVAL_SPEC E9, appendix). Each ablation isolates
//! one of the paper's circuit optimisations. Output: results/e9_optim.csv with
//! `ablation, params, metric, value, kind` (kind = measured | analytical).
//!
//! - **hll_dedup** — under Zipf skew, hashing once per *distinct* key instead of
//!   per record. The hash-invocation saving is `n / u` (records / realised
//!   distinct); reported analytically from the realised distinct count, since the
//!   prototype's HLL circuit hashes per record (the dedup is the §F optimisation).
//! - **hll_wide_output** — one wide-output hash split into two lanes vs. two
//!   separate hashes per distinct key (hash count: 1 vs 2).
//! - **ss_single_round** — SpaceSaving's single-pass retention vs. GK's
//!   multi-round fusion (measured prove time at matched capacity).
//! - **sparse_rebind** — re-committing only the `T_max` touched cells vs. the
//!   whole `s`-cell state (the RQ2-c finding: needs a sparse-opening commit;
//!   reported analytically as the cell-count ratio).
//!
//! Run: cargo run --release --example exp_e9

use std::collections::HashSet;

use zksketch::dataset::zipf_stream;
use zksketch::experiments::families::{gk_empty, gk_epoch, ss_empty, ss_epoch};
use zksketch::experiments::metrics::{append_csv, write_env_json};
use zksketch::experiments::results_dir;
use zksketch::sketch::gk_final_full::GKFullParams;
use zksketch::sketch::ss_final_full::SsFullParams;

fn main() {
    println!("E9 optimisation ablations (plonky3)");
    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky3".into()), ("field", "BabyBear".into()),
        ("experiment", "e9_optim".into()),
    ]);
    let hdr: Vec<String> = ["ablation", "params", "metric", "value", "kind"]
        .iter().map(|s| s.to_string()).collect();
    let _ = std::fs::remove_file(dir.join("e9_optim.csv"));
    let mut push = |ablation: &str, params: String, metric: &str, value: String, kind: &str| {
        let row = vec![ablation.into(), params, metric.into(), value, kind.into()];
        append_csv(&dir, "e9_optim", &hdr, &row);
        println!("  {ablation:<16} {} {metric}={} ({kind})", row[1], row[3]);
    };

    // ── hll_dedup: hash-once-per-distinct saving vs Zipf skew α ───────────────
    let (n, universe) = (1024usize, 1024usize);
    for &alpha in &[0.0f64, 0.5, 1.0, 1.5, 2.0] {
        let keys = zipf_stream(alpha, universe, n, 1);
        let distinct = keys.iter().copied().collect::<HashSet<_>>().len();
        let saving = n as f64 / distinct as f64;
        push("hll_dedup", format!("alpha={alpha};n={n}"), "realised_distinct", distinct.to_string(), "analytical");
        push("hll_dedup", format!("alpha={alpha};n={n}"), "hash_saving_x", format!("{saving:.3}"), "analytical");
    }

    // ── hll_wide_output: hashes per distinct key (1 wide split vs 2 hashes) ────
    push("hll_wide_output", "two_hashes".into(), "hashes_per_distinct", "2".into(), "analytical");
    push("hll_wide_output", "wide_split".into(), "hashes_per_distinct", "1".into(), "analytical");

    // ── sparse_rebind: re-commit T_max touched cells vs whole s-cell state ─────
    let s = 1usize << 14;
    for &t_max in &[8usize, 64, 512, 2048] {
        push("sparse_rebind", format!("T_max={t_max}"), "rebind_cells_sparse", t_max.to_string(), "analytical");
        push("sparse_rebind", format!("s={s}"), "rebind_cells_whole", s.to_string(), "analytical");
        push("sparse_rebind", format!("T_max={t_max};s={s}"), "saving_x", format!("{:.1}", s as f64 / t_max as f64), "analytical");
    }

    // ── ss_single_round: SS single-pass vs GK multi-round fusion (measured) ────
    let cap = 16;
    let keys: Vec<u32> = (0..cap as u32).map(|i| (i.wrapping_mul(0x9E37_79B9) | 1)).collect();
    let (o_ss, _) = ss_epoch(SsFullParams { capacity: cap, batch: cap }, &ss_empty(SsFullParams { capacity: cap, batch: cap }), &keys);
    push("ss_single_round", format!("ss_1pass;cap={cap}"), "prove_ms", format!("{:.3}", o_ss.prove_ms()), "measured");
    let (o_gk, _) = gk_epoch(GKFullParams { capacity: cap, batch: cap }, &gk_empty(GKFullParams { capacity: cap, batch: cap }), &keys);
    push("ss_single_round", format!("gk_multiround;cap={cap}"), "prove_ms", format!("{:.3}", o_gk.prove_ms()), "measured");

    println!("done → {}", dir.join("e9_optim.csv").display());
}
