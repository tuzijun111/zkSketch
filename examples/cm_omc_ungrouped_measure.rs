//! One Count-Min leaf (omc|ungrouped|ungrouped_affine) at one shape: times, peak RSS, unpadded rows; one CSV row.
//! Usage: VARIANT=ungrouped D=3 W=1024 M=64 [TRIALS=1] cargo run --release --example cm_omc_ungrouped_measure

use std::sync::Mutex;
use std::time::Instant;

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

use zksketch::recursion::recursive::timing;
use zksketch::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::countmin_final::apply_update_prf;
use zksketch::sketch::countmin_omc::{CmOmcParams, build_countmin_omc_leaf};
use zksketch::sketch::countmin_omc_ungrouped::{
    CmOmcUngroupedParams, build_countmin_omc_ungrouped_leaf,
};

fn env_usize(k: &str, default: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn splitmix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn peak_rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<f64>().ok())
        })
        .map(|kb| kb / 1024.0)
        .unwrap_or(f64::NAN)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn min(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::INFINITY, f64::min)
}

// ─── Capture of the prover's `AIR shape` log (unpadded table sizes) ─────────

#[derive(Clone, Debug, Default)]
struct Shape {
    table: String,
    rows: u64,
    lanes: u64,
    main_cols: u64,
}

static SHAPES: Mutex<Vec<Shape>> = Mutex::new(Vec::new());

#[derive(Default)]
struct ShapeVisitor {
    is_shape: bool,
    s: Shape,
}

impl Visit for ShapeVisitor {
    fn record_u64(&mut self, f: &Field, v: u64) {
        match f.name() {
            "rows" => self.s.rows = v,
            "lanes" => self.s.lanes = v,
            "main_cols" => self.s.main_cols = v,
            _ => {}
        }
    }
    fn record_i64(&mut self, f: &Field, v: i64) {
        self.record_u64(f, v as u64);
    }
    fn record_str(&mut self, f: &Field, v: &str) {
        if f.name() == "table" {
            self.s.table = v.to_string();
        }
    }
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        match f.name() {
            "message" => self.is_shape = format!("{v:?}") == "AIR shape",
            "table" => self.s.table = format!("{v:?}").trim_matches('"').to_string(),
            _ => {}
        }
    }
}

struct ShapeCapture;

impl<S: tracing::Subscriber> Layer<S> for ShapeCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut v = ShapeVisitor::default();
        event.record(&mut v);
        if v.is_shape {
            if v.s.lanes == 0 {
                v.s.lanes = 1; // CONST / PUBLIC omit `lanes` unless packed
            }
            SHAPES.lock().unwrap().push(v.s);
        }
    }
}

/// Short, stable table names (`NpoTypeId` debug strings are verbose).
fn short_name(t: &str) -> String {
    let l = t.to_ascii_lowercase();
    for (k, n) in [
        ("poseidon2", "p2"),
        ("recompose", "recomp"),
        ("permute", "perm"),
        ("range", "range"),
        ("expose", "expose"),
    ] {
        if l.contains(k) {
            return n.into();
        }
    }
    l.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

fn main() {
    // Only the prover's `AIR shape` info events reach the layer; spans are
    // filtered out per-layer so the capture does not perturb timing.
    tracing_subscriber::registry()
        .with(ShapeCapture.with_filter(tracing_subscriber::filter::filter_fn(|m| {
            m.is_event() && m.target().starts_with("p3_circuit_prover")
        })))
        .init();

    let variant = std::env::var("VARIANT").unwrap_or_else(|_| "ungrouped".into());
    let d = env_usize("D", 3);
    let w = env_usize("W", 1024);
    let m = env_usize("M", 64);
    let trials = env_usize("TRIALS", 1).max(1);

    // Non-empty prior (one seeded batch) + `trials` fresh batches (32-bit keys).
    let mut seed = 0x5eed_u64 ^ ((d as u64) << 40) ^ ((w as u64) << 8) ^ m as u64;
    let mut prior = CountMinState {
        counters: vec![vec![0u32; w]; d],
        params: CountMinParams { d, w },
    };
    for _ in 0..m {
        let key = splitmix(&mut seed) & 0xFFFF_FFFF;
        apply_update_prf(&mut prior, &CountMinUpdate { key, value: 1 });
    }
    let batches: Vec<Vec<CountMinUpdate>> = (0..trials)
        .map(|_| {
            (0..m)
                .map(|_| CountMinUpdate {
                    key: splitmix(&mut seed) & 0xFFFF_FFFF,
                    value: 1,
                })
                .collect()
        })
        .collect();

    let t_b = Instant::now();
    let (mut prove_one, rows, heights): (Box<dyn FnMut(Vec<CountMinUpdate>) -> usize>, u64, String) =
        match variant.as_str() {
            "omc" => {
                let mut leaf = build_countmin_omc_leaf(CmOmcParams { d, w, batch: m }, false);
                let p = prior.clone();
                (
                    Box::new(move |b| leaf.prove_epoch(p.clone(), b).proof_size()),
                    0,
                    String::new(),
                )
            }
            "ungrouped" | "ungrouped_affine" => {
                let params = CmOmcUngroupedParams {
                    d,
                    w,
                    batch: m,
                    affine_enc: variant == "ungrouped_affine",
                };
                let mut leaf = build_countmin_omc_ungrouped_leaf(params, false);
                let rows = leaf.trace_rows();
                let heights = leaf
                    .log_heights()
                    .iter()
                    .map(|h| h.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                let p = prior.clone();
                (
                    Box::new(move |b| leaf.prove_epoch(p.clone(), b).proof_size()),
                    rows,
                    heights,
                )
            }
            v => panic!("unknown VARIANT {v}"),
        };
    let build_ms = t_b.elapsed().as_secs_f64() * 1e3;

    let (mut wit, mut prv, mut ver) = (vec![], vec![], vec![]);
    let mut trace_rows = rows;
    let mut proof_bytes = 0usize;
    let mut shapes: Vec<Shape> = Vec::new();
    for b in batches {
        SHAPES.lock().unwrap().clear();
        proof_bytes = prove_one(b);
        shapes = SHAPES.lock().unwrap().clone();
        let t = timing::take();
        wit.push(t.witness.as_secs_f64() * 1e3);
        prv.push(t.prove.as_secs_f64() * 1e3);
        ver.push(t.verify.as_secs_f64() * 1e3);
        trace_rows = t.trace_rows;
    }
    let alu = shapes
        .iter()
        .find(|s| s.table == "ALU")
        .cloned()
        .unwrap_or_default();
    let alu_ops = alu.rows * alu.lanes;
    let alu_pad = alu.rows.max(1).next_power_of_two();
    let unpadded_rows: u64 = shapes.iter().map(|s| s.rows).sum();
    let unpadded_cells: u64 = shapes.iter().map(|s| s.rows * s.main_cols).sum();
    let tables = shapes
        .iter()
        .map(|s| {
            format!(
                "{}={}x{}w{}",
                short_name(&s.table),
                s.rows,
                s.lanes,
                s.main_cols
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .unwrap_or_default();
    println!(
        "variant,d,w,m,trials,trace_rows,alu_ops,alu_pad,unpadded_rows,unpadded_cells,build_ms,witness_ms,prove_ms,prove_min_ms,verify_ms,proof_bytes,peak_rss_mb,load1,log_heights,tables"
    );
    println!(
        "{variant},{d},{w},{m},{trials},{trace_rows},{alu_ops},{alu_pad},{unpadded_rows},{unpadded_cells},{build_ms:.1},{:.1},{:.1},{:.1},{:.1},{proof_bytes},{:.0},{load},{heights},{tables}",
        median(wit),
        median(prv.clone()),
        min(&prv),
        median(ver),
        peak_rss_mb()
    );
}
