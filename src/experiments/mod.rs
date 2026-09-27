//! **Evaluation harness — the experiments behind `latex/zk1.tex` §Evaluation.**
//!
//! This module turns the paper's Evaluation *plan* (RQ1–RQ4, the end-to-end
//! case study, and cost-model validation) into runnable, small-scale
//! experiments over the four sketch circuits (`countmin_final`,
//! `gk_final_full`, `hll_final_full`, `ss_final_full`) and the §4 composition
//! framework. Each research question is its own submodule; each returns a
//! [`Table`] of results that the example runners (`examples/exp_*.rs`) write to
//! `results/<name>.csv` for the plotting scripts (`scripts/plot_experiments.py`).
//!
//! ## What is *measured* vs *analytical*
//!
//! The prototype proves real STARKs, so prover time, proof size, correctness,
//! and tamper-rejection are **measured**. A few experiments in the paper need
//! baselines this prototype does not implement (RISC0/SP1 zkVMs, a Merkle exact
//! ZK index, in-circuit constraint introspection); those rows are produced
//! **analytically** from the cost model and are clearly flagged as such in the
//! `note`/`kind` column. The §4 framework composes via the paper's *option (i)*
//! lifting (boundary-digest binding, not an in-circuit recursive verifier), so
//! RQ4's per-merge cost is the lightweight composition cost, not a full
//! recursive-SNARK fold — again flagged in the output.
//!
//! ## Running
//!
//! ```bash
//! cargo run --release --example exp_rq1        # capability
//! cargo run --release --example exp_rq2        # scalability
//! cargo run --release --example exp_rq3        # optimisations
//! cargo run --release --example exp_rq4        # topology + policy
//! cargo run --release --example exp_casestudy  # end-to-end on AOL/Netflix
//! python3 scripts/plot_experiments.py          # render results/figures/*.pdf
//! ```
//!
//! Scale is deliberately small (the paper notes the camera-ready will use the
//! full sweeps); override the default thread pool with `V3_SWEEP_THREADS=k`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

pub mod casestudy;
pub mod audit;
pub mod dist_compose;
pub mod e5_ladder;
pub mod e6_forest;
pub mod e7_policy;
pub mod families;
pub mod inputfold;
pub mod metrics;
pub mod prover_commit;
pub mod rq1_capability;
pub mod rq2_scalability;
pub mod stream_compose;
pub mod table_probe;
pub mod rq3_optimisations;
pub mod rq4_topology;

// ─── Result tables ─────────────────────────────────────────────────────────

/// A simple, dependency-free results table: a named header + string rows.
/// Serialises to CSV (numbers/identifiers only — no embedded commas) for the
/// Python plotting layer, and pretty-prints to stdout for the runner.
#[derive(Clone, Debug)]
pub struct Table {
    /// File stem (`results/<name>.csv`) and figure key.
    pub name: String,
    /// One-line description shown above the printed table.
    pub caption: String,
    pub header: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(name: &str, caption: &str, header: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            caption: caption.to_string(),
            header: header.iter().map(|s| s.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    /// Append a row. Panics (in debug) if the column count disagrees with the
    /// header — a guard against silently misaligned CSVs.
    pub fn push(&mut self, row: Vec<String>) {
        debug_assert_eq!(
            row.len(),
            self.header.len(),
            "row width {} != header width {} in table '{}'",
            row.len(),
            self.header.len(),
            self.name
        );
        self.rows.push(row);
    }

    /// Write `results/<name>.csv`. Returns the path written.
    pub fn write_csv(&self) -> PathBuf {
        let dir = results_dir();
        std::fs::create_dir_all(&dir).expect("create results dir");
        let path = dir.join(format!("{}.csv", self.name));
        let mut out = String::new();
        out.push_str(&self.header.join(","));
        out.push('\n');
        for row in &self.rows {
            out.push_str(&row.join(","));
            out.push('\n');
        }
        std::fs::write(&path, out).expect("write csv");
        path
    }

    /// Pretty-print the table to stdout with the caption.
    pub fn print(&self) {
        println!("\n# {}  ({})", self.name, self.caption);
        // Column widths.
        let mut widths: Vec<usize> = self.header.iter().map(|h| h.len()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(cell.len());
                }
            }
        }
        let fmt_row = |cells: &[String]| -> String {
            cells
                .iter()
                .enumerate()
                .map(|(i, c)| format!("{:>w$}", c, w = widths[i]))
                .collect::<Vec<_>>()
                .join("  ")
        };
        println!("  {}", fmt_row(&self.header));
        println!("  {}", "-".repeat(widths.iter().sum::<usize>() + 2 * (widths.len() - 1)));
        for row in &self.rows {
            println!("  {}", fmt_row(row));
        }
    }

    /// Print + write in one call; returns the CSV path.
    pub fn emit(&self) -> PathBuf {
        self.print();
        let path = self.write_csv();
        println!("  → wrote {}", path.display());
        path
    }
}

// ─── Timing + serialisation helpers ──────────────────────────────────────────

/// Time a closure, returning its result alongside the wall-clock duration.
pub fn time_it<T, F: FnOnce() -> T>(f: F) -> (T, Duration) {
    let t = Instant::now();
    let out = f();
    (out, t.elapsed())
}

/// Serialised (postcard) byte size of a proof object — the proof-size metric.
pub fn proof_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}

/// Milliseconds (f64) of a duration — the canonical CSV time unit.
pub fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Format a millisecond count for CSV (3 decimal places).
pub fn ms_str(d: Duration) -> String {
    format!("{:.3}", ms(d))
}

/// `CARGO_MANIFEST_DIR/results` — where every experiment writes its CSV.
pub fn results_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results")
}

/// Read a `usize` knob from the environment, falling back to `default`.
/// Lets the example runners scale an experiment up without recompiling
/// (e.g. `EXP_RQ1_EPOCHS=64`).
pub fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

// ─── Shared thread-pool control (mirrors the per-circuit bench helpers) ──────

/// Resolve a Rayon thread count from `V3_SWEEP_THREADS` (shared with the
/// per-circuit sweeps so the whole suite honours one knob).
pub fn resolve_threads() -> (Option<usize>, String) {
    let n: Option<usize> = std::env::var("V3_SWEEP_THREADS").ok().and_then(|s| s.parse().ok());
    let label = match n {
        Some(k) => format!("V3_SWEEP_THREADS={k}"),
        None => format!("Rayon default pool ({} threads)", rayon::current_num_threads()),
    };
    (n, label)
}

/// Run `f` on a fixed-size pool when `n` is `Some`, else inline on the default
/// pool. Lets the runner pin a core count for single-core RQ4 panels.
pub fn with_pool<F: FnOnce() -> T + Send, T: Send>(n: Option<usize>, f: F) -> T {
    match n {
        None => f(),
        Some(k) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(k)
                .thread_name(|i| format!("zksketch-exp-{i}"))
                .build()
                .expect("build rayon thread pool");
            pool.install(f)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_csv_round_trips() {
        let mut t = Table::new("smoke_table", "harness self-test", &["a", "b"]);
        t.push(vec!["1".into(), "2".into()]);
        t.push(vec!["3".into(), "4".into()]);
        let path = t.write_csv();
        let txt = std::fs::read_to_string(&path).unwrap();
        assert_eq!(txt, "a,b\n1,2\n3,4\n");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn timing_and_proof_size_helpers_work() {
        let (v, d) = time_it(|| 2 + 2);
        assert_eq!(v, 4);
        assert!(d.as_nanos() < u128::MAX);
        let bytes = proof_size(&vec![1u32, 2, 3]);
        assert!(bytes > 0);
    }
}
