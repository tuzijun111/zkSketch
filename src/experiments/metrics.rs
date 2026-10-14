//! Backend-agnostic measurement harness for the EVAL_SPEC §1 metrics.
//!
//! **Mirror of `plonky2/src/metrics.rs`** (pure-std, no proof-system types), so
//! the plonky3 (STARK) and plonky2 (SNARK) stacks report the *same* columns:
//! witness/prove/verify timing split, `prove_total` median+p95, `peak_rss_mb`
//! (sampled from `/proc/self/status:VmRSS` during the run), and the
//! deterministic `proof_size_bytes` / `trace_rows` / `num_columns` /
//! `constraint_count` (= trace_rows·num_columns). [`bench`] can still aggregate
//! `warmup + trials` runs to median/p95 internally, but the emitted CSV
//! ([`AggRow::header`]/[`AggRow::fields`]) reports a **single value per metric**
//! (E1 runs each config once); multi-trial callers see the median.
//!
//! [`super::time_it`] and [`super::results_dir`] live in the parent module;
//! this submodule adds the trial/aggregation/RSS/env machinery on top.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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

/// Trial protocol knobs (default 1 warm-up + 5 measured trials).
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

/// `EXP_MALLOC_TRIM` (M0 harness switch): `0` disables [`trim_heap`] (the
/// pre-M0 behaviour, where glibc keeps every freed heap page resident: an
/// idle procs worker holds 2-3 GB of freed proving memory). Default on.
pub fn malloc_trim_enabled() -> bool {
    !std::env::var("EXP_MALLOC_TRIM").is_ok_and(|v| v.trim() == "0")
}

/// Return freed heap pages to the OS (`malloc_trim(0)`, glibc only; a no-op
/// elsewhere and under `EXP_MALLOC_TRIM=0`). Memory only: nothing a proof
/// contains depends on it. Returns whether it trimmed.
pub fn trim_heap() -> bool {
    if !malloc_trim_enabled() {
        return false;
    }
    trim_heap_now()
}

/// [`trim_heap`] regardless of the switch.
pub fn trim_heap_now() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        unsafe extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        // SAFETY: glibc's malloc_trim takes the arena locks itself and only
        // releases free memory; it is safe to call from any thread.
        unsafe { malloc_trim(0) };
        true
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
    }
}

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
            if let Some(kb) = read_vmrss_kb() {
                p.fetch_max(kb, Ordering::Relaxed);
            }
        });
        Self { stop, peak_kb, handle: Some(handle) }
    }
    fn stop(mut self) -> f64 {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.peak_kb.load(Ordering::Relaxed) as f64 / 1024.0
    }
}

impl Drop for RssSampler {
    /// Stop and join the sampling thread even if the measured closure unwinds
    /// (a guarded `too_large` capacity panic). Without this, an unwind between
    /// `start()` and `stop()` would detach the thread, which would then poll
    /// `/proc/self/status` forever — accumulating zombie pollers across a sweep
    /// and perturbing later RSS readings. Idempotent with `stop()` (which takes
    /// the handle), so the normal path joins exactly once.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Nearest-rank percentile (`q` in `[0,1]`).
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

/// Run `warmup` discarded runs then `trials` measured runs (each wrapped with
/// the RSS sampler), and aggregate to median/p95.
pub fn bench<R: FnMut() -> RunOutcome>(cfg: BenchCfg, mut run: R) -> AggRow {
    for _ in 0..cfg.warmup {
        let _ = run();
    }
    let (mut wit, mut prv, mut tot, mut ver, mut rss) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
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

// ─── env.json + CSV ──────────────────────────────────────────────────────────

fn proc_field(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Write `env.json` capturing the machine + backend environment.
///
/// Always records the plonky3 proof system of the binary that writes it:
/// `pcs` (`hiding` under the default `zk` feature, else `nonhiding`) and
/// `logup_mask` (`on` when the linked core fork masks the revealed LogUp sums,
/// see [`crate::config`]). The plonky2 backend writes its own env.json.
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
        ("pcs".into(), crate::config::pcs_label().into()),
        ("logup_mask".into(), crate::config::logup_mask_label().into()),
    ];
    for (k, v) in extras {
        pairs.push((k.to_string(), v.clone()));
    }
    let body = pairs
        .iter()
        .map(|(k, v)| format!("  \"{}\": \"{}\"", json_escape(k), json_escape(v)))
        .collect::<Vec<_>>()
        .join(",\n");
    let path = dir.join("env.json");
    std::fs::write(&path, format!("{{\n{body}\n}}\n")).expect("write env.json");
    path
}

/// Append a CSV row to `dir/<name>.csv`, writing `header` first if new.
pub fn append_csv(
    dir: &std::path::Path,
    name: &str,
    header: &[String],
    row: &[String],
) -> std::path::PathBuf {
    use std::io::Write;
    std::fs::create_dir_all(dir).expect("create results dir");
    let path = dir.join(format!("{name}.csv"));
    let want_header = header.join(",");
    // If a file already exists, its first line must match the header we're
    // about to use. When the CSV schema changes between runs, appending a
    // wider/narrower row under the stale header silently misaligns every
    // column. Rather than corrupt the file, rotate the stale one aside to a
    // non-clobbering `.bak[N]` and start fresh.
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
    let mut f =
        std::fs::OpenOptions::new().create(true).append(true).open(&path).expect("open csv");
    if fresh {
        writeln!(f, "{}", want_header).expect("write header");
    }
    writeln!(f, "{}", row.join(",")).expect("write row");
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_and_bench_aggregate() {
        let v = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        assert_eq!(median(&v), 30.0);
        assert_eq!(percentile(&v, 0.95), 50.0);

        let mut n = 0u64;
        let row = bench(BenchCfg { warmup: 1, trials: 5 }, || {
            n += 1;
            RunOutcome {
                witness_gen: Duration::from_millis(1),
                prove: Duration::from_millis(2),
                verify: Duration::from_micros(500),
                proof_size_bytes: 99,
                trace_rows: 8,
                num_columns: 3,
            }
        });
        assert_eq!(n, 6);
        assert_eq!(row.constraint_count, 24);
        assert!(row.prove_total_ms_median >= 3.0);
    }

    #[test]
    fn rss_sampler_positive() {
        let s = RssSampler::start();
        let v: Vec<u8> = vec![1u8; 2 << 20];
        std::hint::black_box(&v);
        assert!(s.stop() > 0.0);
    }
}
