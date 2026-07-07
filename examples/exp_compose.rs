//! **Streaming proof-composition comparison** — the three §Streaming-Proof-
//! Composition modes (**per-batch chain**, **recursive linear chain**,
//! **streaming forest**) over four sketch families, each pinned to one leaf
//! variant: cm/omc, hll/omc, ss/certified, gk/bandmerge2.
//!
//! Fixes a total stream size `N`, derives `t = ⌈N/m⌉` leaves per batch size `m`,
//! draws keys from a chosen dataset, and for each (family, mode, cores,
//! machines) reports the whole-stream prove time, the verifier-facing proof size
//! + verify time, and the per-batch proof folder. This is the family-generic
//! sibling of `exp_stream` (which studies the CM omc-vs-merkle leaf across `w`).
//!
//! ## Modes (`EXP_COMPOSE_MODE`, comma-list; default per_batch,chain,forest)
//! - `per_batch` — one independent proof per batch, NO fold; each proof is
//!   stored under `EXP_COMPOSE_PROOF_DIR` and the verifier holds all `t`
//!   (`proof_bytes` + `verify_ms` are `Θ(t)`).
//! - `chain` — recursive linear chain `Π^(t)=merge(Π^(t-1),π_t)` (`O(t)` depth);
//!   one `O(1)` root.
//! - `forest` — streaming forest, Bentley–Saxe tree fold (`O(log t)` depth); one
//!   `O(1)` root. (`recursive` is accepted as a back-compat alias.)
//!
//! ## Cores, machines & the execution engine (`EXP_COMPOSE_EXEC`)
//! - `EXP_COMPOSE_CORES` (comma-list; default all) — cores per machine/proof.
//! - `EXP_COMPOSE_MACHINES` (comma-list; default 1) — number of machines.
//! - `EXP_COMPOSE_EXEC=procs|sim` — the execution engine. Default: `procs`
//!   whenever machines > 1 is requested.
//!   - `procs` (`experiments::dist_compose`): REAL distributed emulation —
//!     one OS process per machine, pinned to disjoint physical cores
//!     (numactl/taskset + NUMA membind), all cross-machine data serialized
//!     over sockets with measured bytes + a network model at `EXP_NET_MBPS`
//!     (default 200 Mb/s) and `EXP_NET_RTT_MS` (default 0.2). `per_batch`/
//!     `forest` distribute leaf
//!     proving over the machines; the `chain` is inherently sequential and
//!     runs on ONE machine, folding in place (each fold consumes the previous
//!     prefix proof — the `machines` knob does not apply). `forest` composes
//!     IN-PLACE on the leaf machines (local Bentley–Saxe cascade + log₂M
//!     cross-machine reduction rounds shipping M−1 root proofs).
//!   - `sim` (legacy `stream_compose`): one process; the machines column is
//!     a work-partition makespan projection; chain ignores machines.
//!
//! ## Shape (per family)
//! - cm:  `EXP_D` (d, default 4), `EXP_W` (w, default 8)  — needs `d·w % 4 == 0`.
//! - hll: `EXP_HLL_B` (register bits b, default 4)        — needs `2^b % 4 == 0`.
//! - ss:  `EXP_SS_CAP` (capacity, default 8).
//! - gk:  `EXP_GK_CAP` (capacity = the GK sketch size, default 64) — needs
//!        `cap + m` even. The accuracy `s = 1/ε` is **derived from cap** (their
//!        space-accuracy coupling `cap ≳ s·log(N/s)`), so cap alone sets the GK
//!        size like the other families. Set `EXP_GK_S` only to override (a value
//!        too big for the cap fragments → too_large; unset it to auto-derive).
//!
//! Config: `EXP_COMPOSE_FAMILY` (cm,hll,ss,gk; default all four),
//! `EXP_COMPOSE_N` (`2^k` ok; default 32), `EXP_COMPOSE_BATCHES` (m list;
//! default 8), `EXP_DATASET` (uniform|gaussian|zipf|aol|netflix; default
//! uniform), `EXP_OUT`/`$1` (rename CSV).
//!
//! ## Mixed updates + queries (`EXP_COMPOSE_QUERY_EVERY`, default 0 = off)
//! With `EXP_COMPOSE_QUERY_EVERY=k`, one **query leaf** (the family's decode
//! circuit: cm point count, hll cardinality, ss top-1 mass, gk rank) is proved
//! after every `k`-th batch against the state commitment the update leaf just
//! exposed. Query costs land in the `query_*` columns (kept separate from the
//! update-side totals); `query_ctx_verifies` counts the composition proofs the
//! verifier checks at query time to trust `Com(S_{t'})` — `t'` (per_batch),
//! `1` (chain), `popcount(t')` Bentley–Saxe peaks (forest). NOTE the cm decode
//! circuit caps `w <= 16`, so with queries on keep `EXP_W` small (default 8).
//!
//! Output: results/stream_compose.csv. Legacy columns (same meanings under
//! both engines), then the procs-engine extension block (n/a under sim):
//!   dataset,family,variant,mode,shape,n,m,t,cores,machines,total_time_ms,
//!   leafgen_ms,leafgen_seq_ms,merge_ms,verify_ms,proof_bytes,records_per_sec,
//!   peak_rss_mb,n_queries,query_prove_ms,query_verify_ms,query_proof_bytes,
//!   query_ctx_verifies,exec,procs,witness_pass_ms,scatter_ms,
//!   scatter_state_bytes,scatter_data_bytes,leaf_busy_min_ms,leaf_busy_max_ms,
//!   local_fold_ms,merges_local,merges_cross,cross_rounds,
//!   comm_msgs,comm_bytes,comm_ms_measured,comm_model_ms,status
//!
//! RUNTIME WARNING: every leaf and every merge is a real STARK proof. Under
//! `sim` everything proves sequentially (the k-machine split is a makespan
//! projection); under `procs` the machines prove concurrently for real, but
//! each merge is still a full recursive proof (~seconds) — budget ~t·merge
//! for the chain and ~(t/M + log M)·merge for the forest.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use zksketch::dataset::{aol, netflix, synthetic_stream, zipf_stream, Synthetic};
use zksketch::experiments::dist_compose::{measure_compose_dist, DistCell};
use zksketch::experiments::metrics::write_env_json;
use zksketch::experiments::results_dir;
use zksketch::experiments::stream_compose::{
    measure_compose, ComposeCell, StreamFamily, StreamMode, StreamShape,
};

fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    if let Some((base, exp)) = s.split_once('^') {
        let b: u64 = base.trim().parse().ok()?;
        let e: u32 = exp.trim().parse().ok()?;
        b.checked_pow(e).map(|v| v as usize)
    } else {
        s.parse().ok()
    }
}

fn env_size(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(s) => parse_size(&s).unwrap_or_else(|| {
            eprintln!("{key}='{s}' is not a valid size");
            std::process::exit(2);
        }),
        Err(_) => default,
    }
}

fn env_size_list(key: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(key) {
        Ok(s) => s
            .split(',')
            .filter_map(|x| {
                let x = x.trim();
                if x.is_empty() {
                    return None;
                }
                let v = parse_size(x);
                if v.is_none() {
                    eprintln!("ignoring unparseable {key} token '{x}'");
                }
                v
            })
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Largest GK accuracy `s = 1/ε` the capacity supports at stream length `N` — the
/// space-accuracy coupling `capacity ≳ s·log2(N/s)`, inverted with a 2× safety
/// factor (using `log2 N ≥ log2(N/s)` so the result is conservative and never
/// fragments). Lets a single `EXP_GK_CAP` knob set the GK sketch size: bigger
/// cap → larger `s` → finer accuracy, exactly the GK space/accuracy tradeoff.
fn derive_gk_s(cap: usize, n: usize) -> u64 {
    let logn = (n.max(4) as f64).log2().ceil().max(1.0);
    ((cap as f64 / (2.0 * logn)).floor() as u64).max(2)
}

fn load_base(dataset: &str, n: usize) -> Option<Vec<u32>> {
    match dataset {
        "uniform" => Some(synthetic_stream(Synthetic::Uniform, n, 1)),
        "gaussian" => Some(synthetic_stream(Synthetic::Gaussian, n, 1)),
        "zipf" => Some(zipf_stream(1.0, n.max(16), n, 1)),
        "aol" => aol(),
        "netflix" => netflix(),
        _ => {
            eprintln!("unknown dataset '{dataset}'");
            None
        }
    }
}

fn batches_from(base: &[u32], m: usize, t: usize) -> Vec<Vec<u32>> {
    (0..t)
        .map(|i| (0..m).map(|j| base[(i * m + j) % base.len()]).collect())
        .collect()
}

/// A short shape string for the CSV (only the family's relevant fields).
fn shape_str(family: StreamFamily, s: &StreamShape) -> String {
    match family {
        StreamFamily::CmOmc => format!("d{}_w{}", s.d, s.w),
        StreamFamily::HllOmc => format!("b{}", s.b),
        StreamFamily::SsCertified => format!("cap{}", s.capacity),
        StreamFamily::GkBandmerge2 => format!("cap{}_s{}", s.capacity, s.gk_s),
    }
}

/// Guarded `measure_compose`: a capacity / shape panic records `too_large` and
/// the sweep continues (mirrors the other runners' `catch_unwind`).
#[allow(clippy::too_many_arguments)]
fn measure_guarded(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    machines: usize,
    proof_dir: &std::path::Path,
    query_every: usize,
) -> Option<ComposeCell> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(|| {
        measure_compose(family, shape, batches, mode, cores, machines, proof_dir, query_every)
    }));
    std::panic::set_hook(prev);
    r.ok()
}

/// Guarded `measure_compose_dist`: machine failures already surface as `Err`;
/// this additionally catches coordinator-side panics (e.g. a fragmenting GK
/// witness pass) so a bad shape records a status row instead of aborting the
/// sweep. Child processes are killed by their drop guards.
#[allow(clippy::too_many_arguments)]
fn dist_guarded(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    machines: usize,
    proof_dir: &std::path::Path,
    mbps: f64,
    rtt_ms: f64,
) -> Result<DistCell, String> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(|| {
        measure_compose_dist(family, shape, batches, mode, cores, machines, proof_dir, mbps, rtt_ms)
    }));
    std::panic::set_hook(prev);
    match r {
        Ok(res) => res,
        Err(p) => Err(p
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".into())),
    }
}

/// Map a failure reason onto the CSV status token: shape/capacity blow-ups
/// keep the sim engine's `too_large`, anything else is `error` (full reason
/// goes to stderr — CSV cells must stay comma-free).
fn status_token(reason: &str) -> &'static str {
    let r = reason.to_ascii_lowercase();
    if r.contains("too large")
        || r.contains("too_large")
        || r.contains("fragment")
        || r.contains("capacity")
        || r.contains("exceeds")
    {
        "too_large"
    } else {
        "error"
    }
}

fn main() {
    // Distributed-engine child dispatch MUST come first: when this binary was
    // re-executed as a pinned machine (worker role), serve the role
    // and never fall through to the coordinator sweep.
    if zksketch::experiments::dist_compose::maybe_run_child() {
        return;
    }
    // Drop the pinned-child exe snapshot on ANY exit path (return or panic).
    let _exe_guard = zksketch::experiments::dist_compose::ExeSnapshotGuard::new();
    let avail = rayon::current_num_threads();
    let n = env_size("EXP_COMPOSE_N", 32);
    let batches_m = env_size_list("EXP_COMPOSE_BATCHES", &[8]);
    // Mixed workload: prove one query leaf after every k-th batch (0 = off).
    // NOTE the cm decode circuit caps w <= 16; with queries on, larger EXP_W
    // records the cm cells as too_large.
    let query_every = env_size("EXP_COMPOSE_QUERY_EVERY", 0);
    let cores_list: Vec<usize> = env_size_list("EXP_COMPOSE_CORES", &[avail])
        .into_iter()
        .map(|c| c.clamp(1, avail))
        .collect();
    let machines_list = env_size_list("EXP_COMPOSE_MACHINES", &[1]);

    // Execution engine: `procs` = the real process-level distributed
    // emulation (one pinned OS process per machine, serialized socket IPC,
    // measured communication — see experiments::dist_compose); `sim` = the
    // legacy single-process run whose machines column is a work-partition
    // makespan projection. Default: procs whenever a multi-machine sweep is
    // requested, since that is the claim being defended.
    let mut exec_procs = match std::env::var("EXP_COMPOSE_EXEC").ok().as_deref() {
        Some("procs") => true,
        Some("sim") => false,
        Some(other) => {
            eprintln!("unknown EXP_COMPOSE_EXEC '{other}' (sim|procs)");
            std::process::exit(2);
        }
        None => machines_list.iter().copied().max().unwrap_or(1) > 1,
    };
    if exec_procs && query_every > 0 {
        eprintln!(
            "note: EXP_COMPOSE_QUERY_EVERY is only wired into the sim engine — running sim"
        );
        exec_procs = false;
    }
    // Modeled network link for the procs engine's comm_model_ms column (bytes
    // are measured; these set the bandwidth + per-message RTT of the model).
    let net_mbps: f64 = std::env::var("EXP_NET_MBPS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&b: &f64| b > 0.0)
        .unwrap_or(200.0);
    let net_rtt_ms: f64 = std::env::var("EXP_NET_RTT_MS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0.2);

    let families: Vec<StreamFamily> = env_str("EXP_COMPOSE_FAMILY", "cm,hll,ss,gk")
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            let f = StreamFamily::parse(s);
            if f.is_none() && !s.is_empty() {
                eprintln!("ignoring unknown family '{s}' (cm|hll|ss|gk)");
            }
            f
        })
        .collect();
    let modes: Vec<StreamMode> = env_str("EXP_COMPOSE_MODE", "per_batch,chain,forest")
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            let mo = StreamMode::parse(s);
            if mo.is_none() && !s.is_empty() {
                eprintln!("ignoring unknown mode '{s}' (per_batch|chain|forest)");
            }
            mo
        })
        .collect();

    // SS and GK may want different capacities; keep them independent. GK needs a
    // bigger summary than SS: it must hold ~s·log(N/s) tuples to compact, so on
    // real data cap=8 fragments — default 64.
    let ss_cap = env_size("EXP_SS_CAP", 8);
    let gk_cap = env_size("EXP_GK_CAP", 64);
    // GK's accuracy s = 1/ε is LINKED to the capacity (their space-accuracy
    // coupling), so a single EXP_GK_CAP knob sets the GK sketch size — like the
    // other families. Unless EXP_GK_S is set explicitly, derive the largest
    // accuracy the capacity supports at stream length N (s ≈ cap/(2·log2 N)),
    // which stays clear of the fragmentation edge for any capacity.
    let gk_explicit = std::env::var("EXP_GK_S").is_ok();
    let gk_s: u64 = match std::env::var("EXP_GK_S") {
        Ok(v) => v.trim().parse().unwrap_or_else(|_| {
            eprintln!("EXP_GK_S='{v}' invalid; deriving from capacity");
            derive_gk_s(gk_cap, n)
        }),
        Err(_) => derive_gk_s(gk_cap, n),
    };
    if families.contains(&StreamFamily::GkBandmerge2) {
        println!(
            "gk: capacity={gk_cap}, s=1/ε={gk_s} ({})",
            if gk_explicit { "EXP_GK_S set" } else { "derived from cap (set EXP_GK_S to override)" }
        );
        // A manual EXP_GK_S that is too big for the cap fragments → flag it.
        if gk_explicit {
            let logn = (n.max(1) as f64 / gk_s.max(1) as f64).max(2.0).log2();
            let need = (gk_s as f64 * logn).ceil() as usize;
            if gk_cap < need {
                eprintln!(
                    "warning: EXP_GK_CAP={gk_cap} may be too small for EXP_GK_S={gk_s} at N={n} \
                     (GK needs capacity ≳ s·log2(N/s) ≈ {need}; below it the band-merge fragments \
                     and reports too_large, NOT 'too large'). Raise EXP_GK_CAP, lower EXP_GK_S, or \
                     unset EXP_GK_S to auto-derive."
                );
            }
        }
    }
    let shape = StreamShape {
        d: env_size("EXP_D", 4),
        w: env_size("EXP_W", 8),
        b: env_size("EXP_HLL_B", 4),
        capacity: gk_cap, // overridden per-family below (ss uses ss_cap, gk uses gk_cap)
        gk_s,
    };

    let dataset_str = env_str("EXP_DATASET", "uniform");
    let datasets: Vec<String> = dataset_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if families.is_empty() || modes.is_empty() || batches_m.is_empty() || n == 0 {
        eprintln!("need non-empty EXP_COMPOSE_FAMILY / _MODE / _BATCHES and N > 0");
        std::process::exit(2);
    }

    let dir = results_dir();
    let proof_base = std::env::var("EXP_COMPOSE_PROOF_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir.join("compose_per_batch_proofs"));
    let _ = std::fs::remove_dir_all(&proof_base);

    println!(
        "Stream compose (plonky3) — N={n} datasets={datasets:?} families={:?} modes={:?} m={batches_m:?} cores={cores_list:?} machines={machines_list:?} exec={} (avail={avail}){}",
        families.iter().map(|f| f.label()).collect::<Vec<_>>(),
        modes.iter().map(|m| m.label()).collect::<Vec<_>>(),
        if exec_procs { "procs" } else { "sim" },
        if query_every > 0 {
            format!(" MIXED: query every {query_every} batch(es)")
        } else {
            String::new()
        },
    );
    if exec_procs {
        println!(
            "procs engine: one pinned OS process per machine (numactl/taskset, disjoint \
             physical cores), all cross-machine data over serialized sockets; the chain runs \
             sequentially on ONE machine (folds in place), forest composes in-place on the leaf \
             machines. Communication bytes are measured; the comm_model_ms column uses \
             EXP_NET_MBPS={net_mbps}Mb/s + EXP_NET_RTT_MS={net_rtt_ms}ms."
        );
    }
    if modes.contains(&StreamMode::PerBatch) {
        println!("per-batch proofs → {}", proof_base.display());
    }

    write_env_json(
        &dir,
        &[
            ("backend", "plonky3".into()),
            ("field", "BabyBear".into()),
            ("hash", "Poseidon2".into()),
            ("experiment", "stream_compose".into()),
            ("exec", if exec_procs { "procs" } else { "sim" }.into()),
            ("net_mbps", format!("{net_mbps}")),
            ("net_rtt_ms", format!("{net_rtt_ms}")),
            ("dataset", dataset_str.clone()),
            ("stream_n", n.to_string()),
            ("total_cores", avail.to_string()),
            ("families", families.iter().map(|f| f.label()).collect::<Vec<_>>().join(",")),
            ("modes", modes.iter().map(|m| m.label()).collect::<Vec<_>>().join(",")),
        ],
    );

    // Legacy columns first (same names/meanings as the sim engine), then the
    // procs-engine extension block (n/a under sim), status last.
    let hdr: Vec<String> = [
        "dataset", "family", "variant", "mode", "shape", "n", "m", "t", "cores", "machines",
        "total_time_ms", "leafgen_ms", "leafgen_seq_ms", "merge_ms", "verify_ms", "proof_bytes",
        "records_per_sec", "peak_rss_mb", "n_queries", "query_prove_ms", "query_verify_ms",
        "query_proof_bytes", "query_ctx_verifies",
        // ── procs-engine extension ──
        "exec", "procs", "witness_pass_ms", "scatter_ms", "scatter_state_bytes",
        "scatter_data_bytes", "leaf_busy_min_ms", "leaf_busy_max_ms", "local_fold_ms",
        "merges_local", "merges_cross", "cross_rounds", "comm_msgs",
        "comm_bytes", "comm_ms_measured", "comm_model_ms", "merge_total_ms", "status",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // Write rows to a PID-private intermediate, not the shared
    // `stream_compose.csv`, so two concurrent sweeps on the same host can't
    // interleave/clobber each other's rows. It's renamed to the caller's
    // EXP_OUT name (or to `stream_compose.csv`) once the sweep completes.
    let csv = dir.join(format!("stream_compose.{}.part.csv", std::process::id()));
    let _ = std::fs::remove_file(&csv);
    write_row(&csv, &hdr);

    for dataset in &datasets {
        let max_need = batches_m.iter().map(|&m| n.div_ceil(m) * m).max().unwrap_or(n);
        let base = match load_base(dataset, max_need) {
            Some(b) if !b.is_empty() => b,
            _ => {
                eprintln!("dataset '{dataset}' unavailable — skipping");
                continue;
            }
        };
        println!("-- dataset={dataset} ({} keys) --", base.len());

        for &family in &families {
            // Per-family shape (ss/gk capacities are independent knobs).
            let mut fshape = shape;
            match family {
                StreamFamily::SsCertified => fshape.capacity = ss_cap,
                StreamFamily::GkBandmerge2 => fshape.capacity = gk_cap,
                _ => {}
            }
            for &m in &batches_m {
                let t = n.div_ceil(m);
                let actual_n = t * m;
                let batches = batches_from(&base, m, t);
                for &mode in &modes {
                    // The chain is inherently sequential (each fold consumes
                    // the previous prefix proof), so it runs on ONE machine in
                    // both engines — sweeping `machines` for it is meaningless.
                    // per_batch and forest distribute leaves over the machines.
                    let machs: Vec<usize> = if mode == StreamMode::Chain {
                        vec![1]
                    } else {
                        machines_list.clone()
                    };
                    for &cores in &cores_list {
                        for &machines in &machs {
                            let cell_dir = proof_base.join(format!(
                                "{}_{}_{}_m{m}",
                                dataset,
                                family.label(),
                                shape_str(family, &fshape),
                            ));
                            let vl = family.label();
                            let sh = shape_str(family, &fshape);
                            // The 10 identity columns every row shares.
                            let prefix = |machines_col: usize| -> Vec<String> {
                                vec![
                                    dataset.clone(), family.family().into(), vl.into(),
                                    mode.label().into(), sh.clone(), actual_n.to_string(),
                                    m.to_string(), t.to_string(), cores.to_string(),
                                    machines_col.to_string(),
                                ]
                            };
                            const N_LEGACY_METRICS: usize = 13; // total_time..query_ctx
                            const N_EXT_AFTER_EXEC: usize = 16; // procs..comm_model_ms, merge_total_ms

                            if exec_procs {
                                match dist_guarded(
                                    family, fshape, &batches, mode, cores, machines, &cell_dir,
                                    net_mbps, net_rtt_ms,
                                ) {
                                    Ok(c) => {
                                        let rps = if c.total_time_ms > 0.0 {
                                            (actual_n as f64 * 1000.0 / c.total_time_ms).round()
                                                as u64
                                        } else {
                                            0
                                        };
                                        let mut row = prefix(c.machines_eff);
                                        row.extend([
                                            format!("{:.3}", c.total_time_ms),
                                            format!("{:.3}", c.leafgen_ms),
                                            format!("{:.3}", c.leafgen_seq_ms),
                                            format!("{:.3}", c.merge_ms),
                                            format!("{:.3}", c.verify_ms),
                                            c.proof_bytes.to_string(),
                                            rps.to_string(),
                                            format!("{:.1}", c.peak_rss_mb),
                                            // procs engine is updates-only.
                                            "0".into(), "0.000".into(), "0.000".into(),
                                            "0".into(), "0".into(),
                                            "procs".into(),
                                            c.procs.to_string(),
                                            format!("{:.3}", c.witness_pass_ms),
                                            format!("{:.3}", c.scatter_ms),
                                            c.scatter_state_bytes.to_string(),
                                            c.scatter_data_bytes.to_string(),
                                            format!("{:.3}", c.leaf_busy_min_ms),
                                            format!("{:.3}", c.leaf_busy_max_ms),
                                            format!("{:.3}", c.local_fold_ms),
                                            c.merges_local.to_string(),
                                            c.merges_cross.to_string(),
                                            c.cross_rounds.to_string(),
                                            c.comm_msgs.to_string(),
                                            c.comm_bytes.to_string(),
                                            format!("{:.3}", c.comm_ms_measured),
                                            format!("{:.3}", c.comm_model_ms),
                                            // merge_total_ms: ALL merge proving = local
                                            // Bentley–Saxe folds (in-worker) + cross-machine
                                            // merges. `merge_ms` alone is only the cross part.
                                            format!("{:.3}", c.local_fold_ms + c.merge_ms),
                                            "ok".into(),
                                        ]);
                                        write_row(&csv, &row);
                                        println!(
                                            "  {vl:<13} {sh:<10} m={m:<4} t={t:<3} [{:<9}] cores={cores} mach={} procs={} total={:.2}s (wpass={:.2}s leaf={:.2}s merge={:.1}s [fold {:.1}s + xmerge {:.2}s]) verify={:.3}s proof={:.1}KB comm={:.1}KB/{} msgs ({:.0}Mbps model {:.1}ms) rss={:.0}MB",
                                            mode.label(), c.machines_eff, c.procs,
                                            c.total_time_ms / 1000.0,
                                            c.witness_pass_ms / 1000.0,
                                            c.leafgen_ms / 1000.0,
                                            (c.local_fold_ms + c.merge_ms) / 1000.0,
                                            c.local_fold_ms / 1000.0, c.merge_ms / 1000.0,
                                            c.verify_ms / 1000.0,
                                            c.proof_bytes as f64 / 1024.0,
                                            c.comm_bytes as f64 / 1024.0, c.comm_msgs,
                                            net_mbps, c.comm_model_ms, c.peak_rss_mb,
                                        );
                                    }
                                    Err(reason) => {
                                        let status = status_token(&reason);
                                        let mut row = prefix(machines);
                                        row.extend(
                                            std::iter::repeat("n/a".to_string())
                                                .take(N_LEGACY_METRICS),
                                        );
                                        row.push("procs".into());
                                        row.extend(
                                            std::iter::repeat("n/a".to_string())
                                                .take(N_EXT_AFTER_EXEC),
                                        );
                                        row.push(status.into());
                                        write_row(&csv, &row);
                                        eprintln!(
                                            "  {vl} {sh} m={m} t={t} [{}] cores={cores} mach={machines}: SKIPPED ({status}) — {reason}",
                                            mode.label()
                                        );
                                    }
                                }
                            } else {
                                match measure_guarded(
                                    family, fshape, &batches, mode, cores, machines, &cell_dir,
                                    query_every,
                                ) {
                                    Some(c) => {
                                        let rps = if c.total_time_ms > 0.0 {
                                            (actual_n as f64 * 1000.0 / c.total_time_ms).round()
                                                as u64
                                        } else {
                                            0
                                        };
                                        let mut row = prefix(machines);
                                        row.extend([
                                            format!("{:.3}", c.total_time_ms),
                                            format!("{:.3}", c.leafgen_ms),
                                            format!("{:.3}", c.leafgen_seq_ms),
                                            format!("{:.3}", c.merge_ms),
                                            format!("{:.3}", c.verify_ms),
                                            c.proof_bytes.to_string(),
                                            rps.to_string(),
                                            format!("{:.1}", c.peak_rss_mb),
                                            c.n_queries.to_string(),
                                            format!("{:.3}", c.query_prove_ms),
                                            format!("{:.3}", c.query_verify_ms),
                                            c.query_proof_bytes.to_string(),
                                            c.query_ctx_verifies.to_string(),
                                            "sim".into(),
                                        ]);
                                        row.extend(
                                            std::iter::repeat("n/a".to_string())
                                                .take(N_EXT_AFTER_EXEC),
                                        );
                                        row.push("ok".into());
                                        write_row(&csv, &row);
                                        let qstr = if c.n_queries > 0 {
                                            format!(
                                                " q={} qprove={:.2}s qverify={:.3}s qproof={:.1}KB qctx={}",
                                                c.n_queries, c.query_prove_ms / 1000.0,
                                                c.query_verify_ms / 1000.0,
                                                c.query_proof_bytes as f64 / 1024.0,
                                                c.query_ctx_verifies,
                                            )
                                        } else {
                                            String::new()
                                        };
                                        println!(
                                            "  {vl:<13} {sh:<10} m={m:<4} t={t:<3} [{:<9}] cores={cores} mach={machines} total={:.2}s (leafgen={:.2}s merge={:.2}s) verify={:.3}s proof={:.1}KB rss={:.0}MB{qstr}",
                                            mode.label(), c.total_time_ms / 1000.0,
                                            c.leafgen_ms / 1000.0, c.merge_ms / 1000.0,
                                            c.verify_ms / 1000.0, c.proof_bytes as f64 / 1024.0,
                                            c.peak_rss_mb,
                                        );
                                    }
                                    None => {
                                        let mut row = prefix(machines);
                                        row.extend(
                                            std::iter::repeat("n/a".to_string())
                                                .take(N_LEGACY_METRICS),
                                        );
                                        row.push("sim".into());
                                        row.extend(
                                            std::iter::repeat("n/a".to_string())
                                                .take(N_EXT_AFTER_EXEC),
                                        );
                                        row.push("too_large".into());
                                        write_row(&csv, &row);
                                        eprintln!(
                                            "  {vl} {sh} m={m} t={t} [{}] cores={cores} mach={machines}: SKIPPED — too_large / shape panic",
                                            mode.label()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Move the PID-private intermediate to the caller-chosen file (or the
    // default `stream_compose.csv`). The exe snapshot is cleaned up by
    // `_exe_guard` on return. (A concurrent no-EXP_OUT sweep can still race on
    // the default name, but each renamed file is internally consistent — the
    // per-row interleaving that corrupted a shared file is gone.)
    let out = std::env::var("EXP_OUT").ok().or_else(|| std::env::args().nth(1));
    let final_csv = match out {
        Some(name) => dir.join(format!("{}.csv", name.trim_end_matches(".csv"))),
        None => dir.join("stream_compose.csv"),
    };
    if final_csv != csv {
        let _ = std::fs::rename(&csv, &final_csv);
    }
    println!("results -> {}", final_csv.display());
}

/// Append one CSV row.
fn write_row(path: &std::path::Path, row: &[String]) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open compose csv");
    writeln!(f, "{}", row.join(",")).expect("write row");
}
