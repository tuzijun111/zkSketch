//! **Streaming proof-composition — plonky2 (SNARK) backend.**
//!
//! The plonky2 sibling of `../../examples/exp_compose.rs`. Proves `t = ⌈N/m⌉`
//! batch leaves per family and composes them under per_batch / chain / forest
//! via the process-level distributed engine (`experiments::dist_compose`): one
//! pinned OS process per machine, socket IPC, measured cross-machine comm. Same
//! CSV schema as the plonky3 runner so the two backends compare directly.
//! Optionally binds the four family roots pairwise cross-family.
//!
//! Env (subset of the plonky3 contract):
//!   EXP_COMPOSE_N        total records (int or 2^k)          (default 16)
//!   EXP_COMPOSE_BATCHES  batch size m                        (default 4)
//!   EXP_COMPOSE_FAMILY   cm,hll,ss,gk comma-list             (default all four)
//!   EXP_D / EXP_W        Count-Min depth / width             (default 2 / 4)
//!   EXP_HLL_B            HyperLogLog register bits           (default 4)
//!   EXP_SS_CAP           SpaceSaving capacity                (default 4)
//!   EXP_GK_CAP           Greenwald–Khanna capacity           (default 4)
//!   EXP_COMPOSE_MODE     per_batch|chain|forest comma-list   (default all three)
//!   EXP_COMPOSE_MACHINES machines (forest/per_batch)         (default 1)
//!   EXP_COMPOSE_CORES    cores per machine                   (default 4)
//!   EXP_COMPOSE_CROSS_FAMILY  1 = also bind the 4 roots cross-family (default 0)
//!   EXP_NET_MBPS / EXP_NET_RTT_MS  network model             (default 200 / 0.2)
//!   EXP_OUT / $1         output CSV name                     (default stream_compose_p2)
//!
//! Run:  cd plonky2 && cargo run --release --example exp_compose

use zksketch_snark::experiments::dist_compose::{
    cross_family_pairs, maybe_run_child, measure_compose_dist, DistCell, Family, FamShape, Mode,
};
use zksketch_snark::metrics::{append_csv, results_dir, write_env_json};

fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    if let Some((b, e)) = s.split_once('^') {
        let b: u64 = b.trim().parse().ok()?;
        let e: u32 = e.trim().parse().ok()?;
        b.checked_pow(e).map(|v| v as usize)
    } else {
        s.parse().ok()
    }
}
fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|s| parse_size(&s)).unwrap_or(d)
}
fn env_f64(k: &str, d: f64) -> f64 {
    std::env::var(k).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(d)
}
fn env_str(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn synthetic_batches(n: usize, m: usize) -> Vec<Vec<u64>> {
    let t = n / m;
    (0..t)
        .map(|i| (0..m).map(|j| ((i * m + j) as u64).wrapping_mul(2_654_435_761) % 1024 + 1).collect())
        .collect()
}

fn main() -> anyhow::Result<()> {
    if maybe_run_child() {
        return Ok(());
    }

    let n = env_usize("EXP_COMPOSE_N", 16);
    let m = env_usize("EXP_COMPOSE_BATCHES", 4);
    let cores = env_usize("EXP_COMPOSE_CORES", 4);
    let machines = env_usize("EXP_COMPOSE_MACHINES", 1).max(1);
    let mbps = env_f64("EXP_NET_MBPS", 200.0);
    let rtt = env_f64("EXP_NET_RTT_MS", 0.2);
    let cross_family = env_usize("EXP_COMPOSE_CROSS_FAMILY", 0) != 0;
    let shape = FamShape {
        d: env_usize("EXP_D", 2),
        w: env_usize("EXP_W", 4),
        b: env_usize("EXP_HLL_B", 4),
        ss_cap: env_usize("EXP_SS_CAP", 4),
        gk_cap: env_usize("EXP_GK_CAP", 4),
        batch: m,
    };
    let families: Vec<Family> = env_str("EXP_COMPOSE_FAMILY", "cm,hll,ss,gk")
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            let f = Family::parse(s);
            if f.is_none() && !s.is_empty() {
                eprintln!("ignoring unknown family '{s}'");
            }
            f
        })
        .collect();
    let modes: Vec<Mode> = env_str("EXP_COMPOSE_MODE", "per_batch,chain,forest")
        .split(',')
        .filter_map(|s| Mode::parse(s.trim()))
        .collect();
    assert!(!families.is_empty() && !modes.is_empty(), "need families + modes");
    assert!(m >= 1 && n >= m, "need N >= m >= 1");

    let t = n / m;
    let batches = synthetic_batches(n, m);
    let actual_n = t * m;

    println!(
        "Stream compose (plonky2 SNARK) — N={actual_n} t={t} m={m} families={:?} modes={:?} machines={machines} cores={cores}{}",
        families.iter().map(|x| x.label()).collect::<Vec<_>>(),
        modes.iter().map(|x| x.label()).collect::<Vec<_>>(),
        if cross_family { " +cross_family" } else { "" },
    );

    let dir = results_dir();
    write_env_json(
        &dir,
        &[
            ("backend", "plonky2".into()),
            ("field", "Goldilocks".into()),
            ("hash", "Poseidon".into()),
            ("experiment", "stream_compose".into()),
            ("merge_wire", "proof+common+verifier_only".into()),
            ("net_mbps", format!("{mbps}")),
            ("net_rtt_ms", format!("{rtt}")),
            ("stream_n", actual_n.to_string()),
        ],
    );

    let hdr: Vec<String> = [
        "backend", "family", "mode", "shape", "n", "m", "t", "cores", "machines", "procs",
        "total_time_ms", "witness_pass_ms", "scatter_ms", "leafgen_ms", "leafgen_seq_ms",
        "merge_ms", "local_fold_ms", "merges_local", "merges_cross", "cross_rounds", "verify_ms",
        "proof_bytes", "records_per_sec", "peak_rss_mb", "comm_msgs", "comm_bytes",
        "comm_model_ms", "status",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out_name = std::env::var("EXP_OUT")
        .ok()
        .or_else(|| std::env::args().nth(1))
        .unwrap_or_else(|| "stream_compose_p2".into());
    let out_name = out_name.trim_end_matches(".csv").to_string();
    let proof_dir = dir.join("compose_per_batch_proofs_p2");

    let shape_str = |f: Family| match f {
        Family::Cm => format!("d{}_w{}", shape.d, shape.w),
        Family::Hll => format!("b{}", shape.b),
        Family::Ss => format!("cap{}", shape.ss_cap),
        Family::Gk => format!("cap{}", shape.gk_cap),
    };

    for &family in &families {
        for &mode in &modes {
            let cell: DistCell =
                measure_compose_dist(family, shape, &batches, mode, cores, machines, &proof_dir, mbps, rtt)?;
            let rps = if cell.total_time_ms > 0.0 {
                (actual_n as f64 * 1000.0 / cell.total_time_ms).round() as u64
            } else {
                0
            };
            let row: Vec<String> = vec![
                "plonky2".into(),
                family.label().into(),
                mode.label().into(),
                shape_str(family),
                actual_n.to_string(),
                m.to_string(),
                cell.t.to_string(),
                cores.to_string(),
                cell.machines_eff.to_string(),
                cell.procs.to_string(),
                format!("{:.3}", cell.total_time_ms),
                format!("{:.3}", cell.witness_pass_ms),
                format!("{:.3}", cell.scatter_ms),
                format!("{:.3}", cell.leafgen_ms),
                format!("{:.3}", cell.leafgen_seq_ms),
                format!("{:.3}", cell.merge_ms),
                format!("{:.3}", cell.local_fold_ms),
                cell.merges_local.to_string(),
                cell.merges_cross.to_string(),
                cell.cross_rounds.to_string(),
                format!("{:.3}", cell.verify_ms),
                cell.proof_bytes.to_string(),
                rps.to_string(),
                format!("{:.1}", cell.peak_rss_mb),
                cell.comm_msgs.to_string(),
                cell.comm_bytes.to_string(),
                format!("{:.3}", cell.comm_model_ms),
                "ok".into(),
            ];
            append_csv(&dir, &out_name, &hdr, &row);
            println!(
                "  {:<3} {:<10} m={m:<4} t={:<3} [{:<9}] mach={} total={:.2}s (leaf={:.2}s merge={:.2}s) verify={:.3}s proof={:.1}KB comm={:.1}KB/{} msgs rss={:.0}MB",
                family.label(),
                shape_str(family),
                cell.t,
                mode.label(),
                cell.machines_eff,
                cell.total_time_ms / 1000.0,
                cell.leafgen_ms / 1000.0,
                cell.merge_ms / 1000.0,
                cell.verify_ms / 1000.0,
                cell.proof_bytes as f64 / 1024.0,
                cell.comm_bytes as f64 / 1024.0,
                cell.comm_msgs,
                cell.peak_rss_mb,
            );
        }
    }

    if cross_family {
        let cf = cross_family_pairs(shape, &batches)?;
        println!(
            "  cross-family: {} families → {} pairwise roots (cm⊕hll, ss⊕gk) family_roots={:.2}s cross_merge={:.2}s verify={:.3}s proof={:.1}KB",
            cf.families,
            cf.pairs,
            cf.family_roots_ms / 1000.0,
            cf.cross_merge_ms / 1000.0,
            cf.verify_ms / 1000.0,
            cf.proof_bytes as f64 / 1024.0,
        );
        // Emit a synthetic row so the artifact is captured in the CSV.
        let row: Vec<String> = vec![
            "plonky2".into(),
            "xfamily".into(),
            "cross".into(),
            "cm+hll+ss+gk".into(),
            actual_n.to_string(),
            m.to_string(),
            cf.t.to_string(),
            cores.to_string(),
            "1".into(),
            "1".into(),
            format!("{:.3}", cf.total_time_ms),
            "0.000".into(),
            "0.000".into(),
            format!("{:.3}", cf.family_roots_ms),
            format!("{:.3}", cf.family_roots_ms),
            format!("{:.3}", cf.cross_merge_ms),
            "0.000".into(),
            "0".into(),
            cf.pairs.to_string(),
            "0".into(),
            format!("{:.3}", cf.verify_ms),
            cf.proof_bytes.to_string(),
            "0".into(),
            format!("{:.1}", cf.peak_rss_mb),
            "0".into(),
            "0".into(),
            "0.000".into(),
            "ok".into(),
        ];
        append_csv(&dir, &out_name, &hdr, &row);
    }

    println!("results -> {}", dir.join(format!("{out_name}.csv")).display());
    Ok(())
}
