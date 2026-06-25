//! E4 — scalability sweeps for the **plonky3 (STARK)** backend (EVAL_SPEC E4).
//! Four sub-sweeps over the certified Count-Min leaf, each isolating one axis of
//! the cost model:
//!
//! - **e4a** batch size `m` (all keys distinct) → prove/witness grow ~linearly
//!   in `m` (the no-dedup worst case). (`constraint_count` on plonky3 is the
//!   summed FRI log-degree, so it grows only ~logarithmically — the linear
//!   signal is in `prove_total_ms`.)
//! - **e4c** state size `s = d·w` at fixed `m` → with the prototype's **flat**
//!   whole-state Poseidon2 commit, cost grows ~linearly in `s` (recorded via the
//!   `commit_mode` column; the sublinear-in-`s` claim needs a sparse-opening
//!   commit — Phase-10 future work).
//! - **e4d** **stream length** `n` ingested as consecutive batches (state
//!   threaded) → per-batch `prove_total` is **flat in `n`** (history-independent
//!   transitions) and the per-leaf self-verify is constant. The O(1)-in-`n` root
//!   verify is the E5 composition result.
//!
//! Run:    cargo run --release --example exp_e4
//! Config: EXP_E4A_M=16,32,64  EXP_E4B_DB=8,16,32  EXP_E4C_W=8,16,32
//!         EXP_E4D_EPOCHS=8     EXP_TRIALS=2  EXP_WARMUP=1
//! Output: results/e4_scaling.csv

use zksketch::experiments::families::cm_empty;
use zksketch::experiments::metrics::{
    append_csv, bench, median, read_vmrss_kb, write_env_json, AggRow, BenchCfg, RunOutcome,
};
use zksketch::experiments::{env_usize, ms, proof_size, results_dir};
use zksketch::recursion::recursive::timing;
use zksketch::sketch::countmin::CountMinUpdate;
use zksketch::sketch::countmin_final::{apply_update_prf, prove_countmin_final, CountMinFinalParams};

const CM_D: usize = 4;

fn env_list(key: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(key) {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => default.to_vec(),
    }
}
fn cfg() -> BenchCfg {
    BenchCfg { warmup: env_usize("EXP_WARMUP", 1), trials: env_usize("EXP_TRIALS", 2) }
}

/// Deterministic key whose value spreads out (so distinct indices ⇒ distinct keys).
fn key(x: usize) -> u64 {
    ((x as u64 + 1).wrapping_mul(0x9E37_79B9) | 1) & 0xFFFF_FFFF
}
/// `m` records using exactly `distinct` distinct keys (cycled), salted by `salt`
/// so different epochs touch different keys (state actually evolves).
fn batch(m: usize, distinct: usize, salt: usize) -> Vec<CountMinUpdate> {
    (0..m).map(|j| CountMinUpdate { key: key(salt * distinct + (j % distinct)), value: 1 }).collect()
}

fn outcome(bytes: u64) -> RunOutcome {
    let t = timing::take();
    RunOutcome {
        witness_gen: t.witness,
        prove: t.prove,
        verify: t.verify,
        proof_size_bytes: bytes,
        trace_rows: t.trace_rows,
        num_columns: 1, // batch-STARK: no single column count (see exp_e1)
    }
}

#[allow(clippy::too_many_arguments)]
fn row(
    sweep: &str, m: usize, w: usize, t_max: usize, n: &str, batch_index: &str, commit_mode: &str,
    cc: u64, prove_ms: f64, verify_ms: f64, bytes: u64, rss: f64,
) -> Vec<String> {
    vec![
        sweep.into(), "plonky3".into(), "cm".into(),
        m.to_string(), CM_D.to_string(), w.to_string(), (CM_D * w).to_string(),
        t_max.to_string(), n.into(), batch_index.into(), commit_mode.into(),
        cc.to_string(), format!("{prove_ms:.3}"), format!("{verify_ms:.3}"),
        bytes.to_string(), format!("{rss:.1}"), "ok".into(),
    ]
}

fn hdr() -> Vec<String> {
    ["sweep", "backend", "family", "m", "d", "w", "s", "T_max", "n", "batch_index",
     "commit_mode", "constraint_count", "prove_total_ms_median", "verify_ms_median",
     "proof_size_bytes", "peak_rss_mb_median", "status"]
        .iter().map(|s| s.to_string()).collect()
}

fn main() {
    let c = cfg();
    let e4a = env_list("EXP_E4A_M", &[16, 32, 64]);
    // CM caps w to {2,4,8,16}, so the state-size axis maxes at s = d·w = 64
    // (the prototype's documented w≤16 cap); invalid w are skipped below.
    let e4c = env_list("EXP_E4C_W", &[4, 8, 16]);
    let e4d_n = env_usize("EXP_E4D_EPOCHS", 8);
    if c.trials == 0 {
        eprintln!("EXP_TRIALS must be > 0");
        std::process::exit(2);
    }
    if e4d_n == 0 {
        eprintln!("EXP_E4D_EPOCHS must be > 0");
        std::process::exit(2);
    }
    println!("E4 scaling (plonky3) — a(m)={e4a:?} c(w)={e4c:?} d(epochs)={e4d_n} trials={}", c.trials);

    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky3".into()), ("field", "BabyBear".into()),
        ("hash", "Poseidon2".into()), ("experiment", "e4_scaling".into()),
        ("commit_mode", "flat_whole_state".into()),
    ]);
    let hdr = hdr();
    let _ = std::fs::remove_file(dir.join("e4_scaling.csv"));

    // ── e4a: batch size m, all keys distinct (distinct_bound = m) ────────────
    for &m in &e4a {
        let p = CountMinFinalParams { d: CM_D, w: 8, batch: m };
        let ups = batch(m, m, 0);
        let agg = bench(c, || { let l = prove_countmin_final(p, cm_empty(CM_D, 8), ups.clone()); outcome(proof_size(&l.output.0) as u64) });
        emit(&dir, &hdr, "a", &agg, m, 8, m * CM_D, "-", "-");
    }
    // ── e4c: state size s = d·w, fixed m=32, flat commit ─────────────────────
    let (m_c, db_c) = (32, 16);
    for &w in &e4c {
        if !matches!(w, 2 | 4 | 8 | 16) {
            eprintln!("  e4c: skipping w={w} (CM requires w ∈ {{2,4,8,16}}, s = d·w ≤ 64)");
            continue;
        }
        let p = CountMinFinalParams { d: CM_D, w, batch: m_c };
        let ups = batch(m_c, db_c, 0);
        let agg = bench(c, || { let l = prove_countmin_final(p, cm_empty(CM_D, w), ups.clone()); outcome(proof_size(&l.output.0) as u64) });
        emit(&dir, &hdr, "c", &agg, m_c, w, db_c * CM_D, "-", "-");
    }
    // ── e4d: stream length n, per-batch prove flat in n (state threaded) ──────
    {
        let (m, db, w) = (32, 32, 8);
        let p = CountMinFinalParams { d: CM_D, w, batch: m };
        let mut per_epoch: Vec<Vec<f64>> = vec![Vec::new(); e4d_n];
        let (mut cc, mut bytes, mut verify, mut rss) = (0u64, 0u64, 0f64, 0f64);
        for trial in 0..(c.warmup + c.trials) {
            let mut state = cm_empty(CM_D, w);
            for epoch in 0..e4d_n {
                let ups = batch(m, db, epoch + 1);
                let leaf = prove_countmin_final(p, state.clone(), ups.clone());
                let t = timing::take();
                for u in &ups { apply_update_prf(&mut state, u); } // thread native state
                if trial >= c.warmup {
                    per_epoch[epoch].push(ms(t.witness + t.prove));
                    cc = t.trace_rows;
                    verify = ms(t.verify);
                    bytes = proof_size(&leaf.output.0) as u64;
                    rss = read_vmrss_kb().map(|k| k as f64 / 1024.0).unwrap_or(0.0);
                }
            }
        }
        for (epoch, times) in per_epoch.iter().enumerate() {
            let pm = median(times);
            let r = row("d", m, w, db * CM_D, &e4d_n.to_string(), &epoch.to_string(), "flat", cc, pm, verify, bytes, rss);
            append_csv(&dir, "e4_scaling", &hdr, &r);
        }
        let flat = per_epoch.iter().map(|t| median(t)).collect::<Vec<_>>();
        let (lo, hi) = (flat.iter().cloned().fold(f64::MAX, f64::min), flat.iter().cloned().fold(0.0, f64::max));
        println!("  e4d per-batch prove: min={lo:.1}ms max={hi:.1}ms over n={e4d_n} epochs (flat ⇒ history-independent)");
    }

    println!("done → {}", dir.join("e4_scaling.csv").display());
}

#[allow(clippy::too_many_arguments)]
fn emit(dir: &std::path::Path, hdr: &[String], sweep: &str, agg: &AggRow, m: usize, w: usize, t_max: usize, n: &str, bi: &str) {
    let r = row(
        sweep, m, w, t_max, n, bi, "flat",
        agg.constraint_count, agg.prove_total_ms_median, agg.verify_ms_median,
        agg.proof_size_bytes, agg.peak_rss_mb_median,
    );
    let path = append_csv(dir, "e4_scaling", hdr, &r);
    println!("  e4{sweep} m={m:<4} w={w:<3} T_max={t_max:<4} cc={:<7} prove={:.1}ms → {}",
        agg.constraint_count, agg.prove_total_ms_median, path.display());
}
