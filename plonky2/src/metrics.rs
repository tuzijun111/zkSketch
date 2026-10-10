//! Backend-agnostic measurement harness for the EVAL_SPEC §1 metrics.
//!
//! Pure-std (no proof-system types), so the **identical** harness is mirrored in
//! the plonky3 crate (`../src/experiments/metrics.rs`); both stacks report the
//! same columns the spec mandates:
//!
//! - `witness_gen_ms`, `prove_ms`, `prove_total_ms`, `verify_ms` — wall-clock,
//!   split per phase (the experiment times each phase inside its `run` closure).
//! - `peak_rss_mb` — peak resident memory **during** the run, sampled by a
//!   background thread polling `/proc/self/status:VmRSS` (per-run max; VmHWM is
//!   a process-lifetime high-water mark and can't be reset, so we sample
//!   current RSS and take the max — the honest per-run peak).
//! - `proof_size_bytes`, `trace_rows`, `num_columns`, `constraint_count` —
//!   deterministic, single value (constraint_count = trace_rows·num_columns,
//!   the backend-independent trace-cell measure).
//!
//! Timing protocol: [`bench`] can aggregate `warmup + trials` runs to median/p95
//! internally, but the emitted CSV ([`AggRow::header`]/[`AggRow::fields`]) reports
//! a **single value per metric** (E1 runs each config once).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// What one full measured run reports back to the harness.
#[derive(Clone, Copy, Debug)]
pub struct RunOutcome {
    pub witness_gen: Duration,
    pub prove: Duration,
    pub verify: Duration,
    pub proof_size_bytes: u64,
    pub trace_rows: u64,
    pub num_columns: u64,
}

impl RunOutcome {
    pub fn constraint_count(&self) -> u64 {
        self.trace_rows * self.num_columns
    }
    pub fn prove_total(&self) -> Duration {
        self.witness_gen + self.prove
    }
}

/// Trial protocol knobs.
#[derive(Clone, Copy, Debug)]
pub struct BenchCfg {
    pub warmup: usize,
    pub trials: usize,
}

impl Default for BenchCfg {
    fn default() -> Self {
        Self { warmup: 1, trials: 5 }
    }
}

// ─── Peak-RSS sampler ────────────────────────────────────────────────────────

/// Current resident set size (KiB) from `/proc/self/status`.
pub fn read_vmrss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.trim().split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Background sampler that tracks the max VmRSS seen while it runs.
struct RssSampler {
    stop: Arc<AtomicBool>,
    peak_kb: Arc<AtomicU64>,
    handle: Option<thread::JoinHandle<()>>,
}

impl RssSampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak_kb = Arc::new(AtomicU64::new(read_vmrss_kb().unwrap_or(0)));
        let (s, p) = (stop.clone(), peak_kb.clone());
        let handle = thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                if let Some(kb) = read_vmrss_kb() {
                    p.fetch_max(kb, Ordering::Relaxed);
                }
                thread::sleep(Duration::from_micros(1500));
            }
            // Final reading in case the peak landed right at the end.
            if let Some(kb) = read_vmrss_kb() {
                p.fetch_max(kb, Ordering::Relaxed);
            }
        });
        Self { stop, peak_kb, handle: Some(handle) }
    }

    /// Stop sampling; return peak RSS in MB.
    fn stop(mut self) -> f64 {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.peak_kb.load(Ordering::Relaxed) as f64 / 1024.0
    }
}

// ─── Aggregation ─────────────────────────────────────────────────────────────

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Nearest-rank percentile of an unsorted slice (`q` in `[0,1]`).
pub fn percentile(values: &[f64], q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let rank = (q * v.len() as f64).ceil() as usize;
    v[rank.saturating_sub(1).min(v.len() - 1)]
}

pub fn median(values: &[f64]) -> f64 {
    percentile(values, 0.5)
}

/// Aggregated per-config metrics row (the EVAL_SPEC §1 metric columns).
#[derive(Clone, Debug)]
pub struct AggRow {
    pub trials: usize,
    pub trace_rows: u64,
    pub num_columns: u64,
    pub constraint_count: u64,
    pub proof_size_bytes: u64,
    pub witness_gen_ms_median: f64,
    pub prove_ms_median: f64,
    pub prove_total_ms_median: f64,
    pub prove_total_ms_p95: f64,
    pub verify_ms_median: f64,
    pub peak_rss_mb_median: f64,
    pub peak_rss_mb_p95: f64,
}

impl AggRow {
    /// The metric column headers, in `fields()` order. Experiment runners
    /// prepend their config columns (backend, family, m, …) and append `status`.
    pub fn header() -> Vec<&'static str> {
        // Single run per config (trials=1): one value per metric, no median/p95.
        vec![
            "trace_rows",
            "num_columns",
            "constraint_count",
            "witness_gen_ms",
            "prove_ms",
            "prove_total_ms",
            "verify_ms",
            "proof_size_bytes",
            "peak_rss_mb",
        ]
    }

    pub fn fields(&self) -> Vec<String> {
        // Order matches EVAL_SPEC §1 (proof_size_bytes after verify_ms). The
        // `*_median` struct fields hold the single run's value when trials=1.
        vec![
            self.trace_rows.to_string(),
            self.num_columns.to_string(),
            self.constraint_count.to_string(),
            format!("{:.3}", self.witness_gen_ms_median),
            format!("{:.3}", self.prove_ms_median),
            format!("{:.3}", self.prove_total_ms_median),
            format!("{:.3}", self.verify_ms_median),
            self.proof_size_bytes.to_string(),
            format!("{:.1}", self.peak_rss_mb_median),
        ]
    }
}

/// Run `warmup` discarded runs then `trials` measured runs, wrapping each
/// measured run with the RSS sampler, and aggregate to median/p95.
pub fn bench<R: FnMut() -> RunOutcome>(cfg: BenchCfg, mut run: R) -> AggRow {
    for _ in 0..cfg.warmup {
        let _ = run();
    }
    let mut wit = Vec::new();
    let mut prv = Vec::new();
    let mut tot = Vec::new();
    let mut ver = Vec::new();
    let mut rss = Vec::new();
    let mut last = None;
    for _ in 0..cfg.trials {
        let sampler = RssSampler::start();
        let out = run();
        let peak = sampler.stop();
        wit.push(ms(out.witness_gen));
        prv.push(ms(out.prove));
        tot.push(ms(out.prove_total()));
        ver.push(ms(out.verify));
        rss.push(peak);
        last = Some(out);
    }
    let last = last.expect("at least one trial");
    AggRow {
        trials: cfg.trials,
        trace_rows: last.trace_rows,
        num_columns: last.num_columns,
        constraint_count: last.constraint_count(),
        proof_size_bytes: last.proof_size_bytes,
        witness_gen_ms_median: median(&wit),
        prove_ms_median: median(&prv),
        prove_total_ms_median: median(&tot),
        prove_total_ms_p95: percentile(&tot, 0.95),
        verify_ms_median: median(&ver),
        peak_rss_mb_median: median(&rss),
        peak_rss_mb_p95: percentile(&rss, 0.95),
    }
}

/// Time a closure, returning `(result, elapsed)`.
pub fn time_it<T, Fn1: FnOnce() -> T>(f: Fn1) -> (T, Duration) {
    let t = Instant::now();
    let out = f();
    (out, t.elapsed())
}

// ─── env.json ────────────────────────────────────────────────────────────────

fn proc_field(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.split_once(':').filter(|(k, _)| k.trim() == key) {
            return Some(rest.1.trim().to_string());
        }
    }
    None
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Write `env.json` capturing the machine + backend environment. `extras` are
/// backend-specific `(key, value)` pairs (field, hash, FRI params, commit hash).
/// Always records `zero_knowledge` (`on` / `off`) from [`crate::config::circuit_config`]:
/// this backend's proofs are not zero-knowledge (`off`), unlike the plonky3
/// backend's default `zk` build.
pub fn write_env_json(dir: &std::path::Path, extras: &[(&str, String)]) -> std::path::PathBuf {
    std::fs::create_dir_all(dir).expect("create results dir");
    let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    let cpu = proc_field("/proc/cpuinfo", "model name").unwrap_or_else(|| "unknown".into());
    let mem = proc_field("/proc/meminfo", "MemTotal").unwrap_or_else(|| "unknown".into());
    let rustc = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    let mut pairs: Vec<(String, String)> = vec![
        ("os".into(), std::env::consts::OS.into()),
        ("arch".into(), std::env::consts::ARCH.into()),
        ("cores".into(), cores.to_string()),
        ("cpu_model".into(), cpu),
        ("mem_total".into(), mem),
        ("rustc".into(), rustc),
        (
            "zero_knowledge".into(),
            if crate::config::circuit_config().zero_knowledge { "on" } else { "off" }.into(),
        ),
    ];
    for (k, v) in extras {
        pairs.push((k.to_string(), v.clone()));
    }
    let body = pairs
        .iter()
        .map(|(k, v)| format!("  \"{}\": \"{}\"", json_escape(k), json_escape(v)))
        .collect::<Vec<_>>()
        .join(",\n");
    let json = format!("{{\n{body}\n}}\n");
    let path = dir.join("env.json");
    std::fs::write(&path, json).expect("write env.json");
    path
}

/// Append a CSV row to `dir/<name>.csv`, writing `header` first if the file is new.
pub fn append_csv(dir: &std::path::Path, name: &str, header: &[String], row: &[String]) -> std::path::PathBuf {
    use std::io::Write;
    std::fs::create_dir_all(dir).expect("create results dir");
    let path = dir.join(format!("{name}.csv"));
    let want_header = header.join(",");
    // If a file already exists, its first line must match the header we're
    // about to use. When the CSV schema changes between runs (e.g. a new
    // `dataset` column), appending a wider/narrower row under the stale header
    // silently misaligns every column. Rather than corrupt the file, rotate
    // the stale one aside to a non-clobbering `.bak[N]` and start fresh.
    let mut fresh = true;
    if path.exists() {
        let cur_header = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.lines().next().map(str::to_string));
        if cur_header.as_deref() == Some(want_header.as_str()) {
            fresh = false;
        } else {
            let mut bak = dir.join(format!("{name}.csv.bak"));
            let mut i = 1;
            while bak.exists() {
                bak = dir.join(format!("{name}.csv.bak{i}"));
                i += 1;
            }
            let _ = std::fs::rename(&path, &bak);
            eprintln!(
                "append_csv: {}'s header changed (schema differs); rotated the stale file to {} and started a fresh CSV",
                path.display(),
                bak.display(),
            );
        }
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).expect("open csv");
    if fresh {
        writeln!(f, "{}", want_header).expect("write header");
    }
    writeln!(f, "{}", row.join(",")).expect("write row");
    path
}

/// `results/` under the crate root.
pub fn results_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_nearest_rank() {
        let v = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        assert_eq!(median(&v), 30.0);
        assert_eq!(percentile(&v, 0.95), 50.0);
        assert_eq!(percentile(&v, 1.0), 50.0);
    }

    #[test]
    fn rss_sampler_reads_something() {
        let s = RssSampler::start();
        // Touch some memory.
        let v: Vec<u8> = vec![7u8; 4 << 20];
        std::hint::black_box(&v);
        let peak = s.stop();
        assert!(peak > 0.0, "should read a positive RSS");
    }

    #[test]
    fn bench_aggregates_trials() {
        let mut n = 0u64;
        let row = bench(BenchCfg { warmup: 1, trials: 5 }, || {
            n += 1;
            RunOutcome {
                witness_gen: Duration::from_millis(1),
                prove: Duration::from_millis(2),
                verify: Duration::from_micros(500),
                proof_size_bytes: 123,
                trace_rows: 16,
                num_columns: 4,
            }
        });
        assert_eq!(n, 6, "1 warmup + 5 trials");
        assert_eq!(row.constraint_count, 64);
        assert_eq!(row.proof_size_bytes, 123);
        assert!(row.prove_total_ms_median >= 3.0);
    }
}
