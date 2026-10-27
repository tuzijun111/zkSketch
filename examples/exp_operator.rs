//! Per-phase proving cost of the deployed Count-Min (`countmin_omc`) and
//! Greenwald--Khanna (`gk_bandmerge2_stable`) leaves: the data behind the
//! paper's "operator performance" breakdown (one bar per paper phase, as
//! PoneglyphDB's Fig. 8 shows one bar per proof-generation step).
//!
//! Two measurements per family (`EXP_FAMILIES=cm,mg`, `gk` optional), at the
//! six-sketch comparison's leaf shapes:
//!
//! 1. **Rows per table per phase.** Shapes-only prefix builds
//!    (`table_probe::capture_prefix_shapes(k, ..)`, `k = 1..K`): prefix `k`
//!    holds the first `k` paper phases, so phase `k`'s rows in each table are
//!    the difference between prefixes `k` and `k-1`. Nothing is proved (a
//!    prefix build is stopped after its shapes are recorded).
//! 2. **Prover time per table and per stage.** One warm-up leaf proof (the
//!    genesis leaf, `t = 1`), then `EXP_REPEATS` timed leaf proofs on a
//!    non-empty state, under a `tracing` layer that times every span of the
//!    fork's prover (per-table `*::build_trace`, per-AIR `compute quotient`,
//!    the joint `commit` / `FRI prover` / `query phase` spans), plus the
//!    witness / prove / verify split of `timing::take()`; then one query
//!    (decode) proof per family, timed the same way.
//!
//! Output (`EXP_OUT_DIR`, default `results/operator/`):
//! `<fam>_phases.csv` (fam,phase,table,rows), `<fam>_tables.csv`
//! (fam,idx,table,log_h,rows,width,lanes), `<fam>_spans.csv`
//! (fam,run,repeat,seq,depth,target,name,fields,ms), `operator_summary.csv`
//! (fam,run,repeat,witness_ms,prove_ms,verify_ms,trace_rows).
//!
//! ```bash
//! RAYON_NUM_THREADS=32 taskset -c 0-31 cargo run --release --example exp_operator
//! # knobs: EXP_FAMILIES=cm,mg[,gk] EXP_D=3 EXP_W=16384 EXP_M_CM=16384
//! #        EXP_SS_CAP=16384 EXP_M_MG=16384 EXP_SS_C=1
//! #        EXP_GK_CAP=768 EXP_GK_S=51 EXP_M_GK=512 EXP_REPEATS=3 EXP_CORES=32
//! ```
//! Defaults are the paper's default parameters (Section 8.1: Count-Min d = 3,
//! w = 2^14; Misra--Gries s = 2^14; batches of m = 2^14 records); GK keeps the
//! six-sketch comparison's leaf shape.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

use zksketch::commitment::hiding::{CommitFamily, CommitMode, SaltSeed};
use zksketch::decode::countmin::{prove_cm_decode_commit, CmDecodeParams};
use zksketch::decode::gk_bandmerge::{prove_gk2_decode_commit, Gkb2DecodeParams};
use zksketch::decode::spacesaving::{prove_ss_decode_commit, SsDecodeParams};
use zksketch::decode::ReleasePolicy;
use zksketch::experiments::prover_commit::ProverCommit;
use zksketch::experiments::table_probe::{capture_prefix_shapes, quiet_shapes_only_panics, TableShape};
use zksketch::experiments::results_dir;
use zksketch::recursion::recursive::statement::composition_expose;
use zksketch::recursion::recursive::timing;
use zksketch::sketch::bind::default_binding;
use zksketch::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::countmin_omc::{build_countmin_omc_leaf_commit, countmin_omc_advance, CmOmcParams};
use zksketch::sketch::gk_bandmerge::{
    apply_batch2, build_gkb2_leaf_rounds, default_gk_rounds, Gk2State, GkbParams,
};
use zksketch::sketch::ss_final_full::{apply_batch_ss_full, build_ss_full_leaf_commit, SsFullParams, SsFullState, SsFullUpdate};

// ─── span timing + "AIR shape" capture ──────────────────────────────────

struct Started(Instant);
struct Fields(String);

#[derive(Clone, Debug)]
struct SpanRec {
    depth: usize,
    target: String,
    name: &'static str,
    fields: String,
    ms: f64,
}

#[derive(Clone, Debug, Default)]
struct Shape {
    table: String,
    rows: u64,
    lanes: u64,
    main_cols: u64,
}

static SPANS: Mutex<Vec<SpanRec>> = Mutex::new(Vec::new());
static SHAPES: Mutex<Vec<Shape>> = Mutex::new(Vec::new());

#[derive(Default)]
struct FieldsVisitor(String);

impl Visit for FieldsVisitor {
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push(';');
        }
        let _ = write!(self.0, "{}={:?}", f.name(), v);
    }
}

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

struct Timing;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Timing {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut v = FieldsVisitor::default();
            attrs.record(&mut v);
            let mut ext = span.extensions_mut();
            ext.insert(Started(Instant::now()));
            ext.insert(Fields(v.0));
        }
    }
    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            let depth = span.scope().count().saturating_sub(1);
            let ext = span.extensions();
            let ms = ext.get::<Started>().map_or(0.0, |s| s.0.elapsed().as_secs_f64() * 1e3);
            let fields = ext.get::<Fields>().map_or(String::new(), |f| f.0.clone());
            SPANS.lock().unwrap().push(SpanRec {
                depth,
                target: span.metadata().target().to_string(),
                name: span.name(),
                fields,
                ms,
            });
        }
    }
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut v = ShapeVisitor::default();
        event.record(&mut v);
        if v.is_shape {
            if v.s.lanes == 0 {
                v.s.lanes = 1;
            }
            SHAPES.lock().unwrap().push(v.s);
        }
    }
}

fn take_spans() -> Vec<SpanRec> {
    std::mem::take(&mut *SPANS.lock().unwrap())
}
fn take_shapes() -> Vec<Shape> {
    std::mem::take(&mut *SHAPES.lock().unwrap())
}

// ─── knobs ─────────────────────────────────────────────────────────────

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(d)
}

/// A small deterministic PRNG (xorshift64*) for keys and values; the
/// circuits are oblivious, so the data only has to be well formed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Rows per table of prefixes 1..=k_max of a builder (shapes only).
fn probe_phases(site: &str, k_max: usize, build: &dyn Fn()) -> Vec<(usize, Vec<TableShape>)> {
    let mut out = Vec::new();
    for k in 1..=k_max {
        let shapes = capture_prefix_shapes(k, || build()).unwrap_or_else(|e| panic!("prefix {k} of {site}: {e}"));
        let shape = shapes
            .into_iter()
            .find(|s| s.site == site)
            .unwrap_or_else(|| panic!("prefix {k}: no shape recorded for {site}"));
        eprintln!(
            "[exp_operator] {site} prefix {k}: {}",
            shape.tables.iter().map(|t| format!("{}={}", t.name, t.rows)).collect::<Vec<_>>().join(" ")
        );
        out.push((k, shape.tables));
    }
    out
}

struct Out {
    phases: String,
    tables: String,
    spans: String,
    summary: String,
}

impl Out {
    fn new() -> Self {
        Self {
            phases: "fam,phase,table,rows\n".into(),
            tables: "fam,idx,table,log_h,rows,width,lanes\n".into(),
            spans: "fam,run,repeat,seq,depth,target,name,fields,ms\n".into(),
            summary: "fam,run,repeat,witness_ms,prove_ms,verify_ms,trace_rows\n".into(),
        }
    }
    fn phases(&mut self, fam: &str, prefixes: &[(usize, Vec<TableShape>)]) {
        let mut prev: Vec<(String, usize)> = Vec::new();
        for (k, tables) in prefixes {
            for t in tables {
                let before = prev.iter().find(|(n, _)| *n == t.name).map_or(0, |(_, r)| *r);
                let _ = writeln!(self.phases, "{fam},{k},{},{}", t.name, t.rows.saturating_sub(before));
            }
            prev = tables.iter().map(|t| (t.name.clone(), t.rows)).collect();
        }
        // the full circuit's padded shape (last prefix = every phase)
        if let Some((_, tables)) = prefixes.last() {
            for t in tables {
                let _ = writeln!(self.tables, "{fam},{},{},{},{},{},", t.idx, t.name, t.log_h, t.rows, t.width);
            }
        }
    }
    fn shapes(&mut self, fam: &str, shapes: &[Shape]) {
        for (i, s) in shapes.iter().enumerate() {
            let _ = writeln!(self.tables, "{fam},{i},{},,{},{},{}", s.table, s.rows, s.main_cols, s.lanes);
        }
    }
    fn spans(&mut self, fam: &str, run: &str, repeat: usize, spans: &[SpanRec]) {
        for (seq, s) in spans.iter().enumerate() {
            let fields = s.fields.replace(',', ";").replace('"', "");
            let _ = writeln!(
                self.spans,
                "{fam},{run},{repeat},{seq},{},{},{},{},{:.3}",
                s.depth, s.target, s.name, fields, s.ms
            );
        }
    }
    fn summary(&mut self, fam: &str, run: &str, repeat: usize, t: timing::LeafTiming) {
        let _ = writeln!(
            self.summary,
            "{fam},{run},{repeat},{:.3},{:.3},{:.3},{}",
            t.witness.as_secs_f64() * 1e3,
            t.prove.as_secs_f64() * 1e3,
            t.verify.as_secs_f64() * 1e3,
            t.trace_rows
        );
    }
    fn write(&self, dir: &PathBuf, fams: &[String]) {
        std::fs::create_dir_all(dir).expect("mkdir");
        let tag = fams.join("_");
        for (name, body) in [
            (format!("{tag}_phases.csv"), &self.phases),
            (format!("{tag}_tables.csv"), &self.tables),
            (format!("{tag}_spans.csv"), &self.spans),
            ("operator_summary.csv".to_string(), &self.summary),
        ] {
            std::fs::write(dir.join(&name), body).expect("write csv");
            eprintln!("[exp_operator] wrote {}", dir.join(name).display());
        }
    }
}

fn main() {
    tracing_subscriber::registry()
        .with(Timing.with_filter(tracing_subscriber::filter::filter_fn(|m| {
            let t = m.target();
            t.starts_with("p3_") && !t.starts_with("p3_dft") && !t.starts_with("p3_matrix")
        })))
        .init();
    quiet_shapes_only_panics();

    let cores = env_usize("EXP_CORES", 32);
    let _ = rayon::ThreadPoolBuilder::new().num_threads(cores).build_global();
    let repeats = env_usize("EXP_REPEATS", 3).max(1);
    let fams: Vec<String> = std::env::var("EXP_FAMILIES")
        .unwrap_or_else(|_| "cm,mg".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let out_dir = std::env::var("EXP_OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| results_dir().join("operator"));
    let mode = CommitMode::Hiding;
    let commit = ProverCommit::hiding(SaltSeed::for_tests(7));
    let mut out = Out::new();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

    for fam in &fams {
        match fam.as_str() {
            "cm" => {
                let d = env_usize("EXP_D", 3);
                let w = env_usize("EXP_W", 16384);
                let m = env_usize("EXP_M_CM", 16384);
                let params = CmOmcParams { d, w, batch: m };
                let cf = CommitFamily::CountMin;
                eprintln!("[exp_operator] cm: d={d} w={w} m={m}, prefix probes");
                let build = || {
                    let _ = build_countmin_omc_leaf_commit(params, composition_expose(), default_binding(), mode);
                };
                let prefixes = probe_phases("countmin_omc", 5, &build);
                out.phases("cm", &prefixes);

                eprintln!("[exp_operator] cm: full build");
                let t0 = Instant::now();
                let mut leaf = build_countmin_omc_leaf_commit(params, composition_expose(), default_binding(), mode);
                eprintln!("[exp_operator] cm: built in {:.1} s", t0.elapsed().as_secs_f64());
                let mut state = CountMinState {
                    counters: vec![vec![0u32; w]; d],
                    params: CountMinParams { d, w },
                };
                let mut batch = |rng: &mut Rng| -> Vec<CountMinUpdate> {
                    (0..m)
                        .map(|_| CountMinUpdate { key: rng.next() & 0xFFFF_FFFF, value: 1 + (rng.next() % 100) as u32 })
                        .collect()
                };
                // warm-up: the genesis leaf (t = 1 opens the public zero init salt)
                let b1 = batch(&mut rng);
                let _ = take_spans();
                let _ = take_shapes();
                let _ = leaf.prove_epoch_commit(1, state.clone(), b1.clone(), &commit.openings(cf, 1));
                out.summary("cm", "warmup", 0, timing::take());
                countmin_omc_advance(&mut state, &b1);
                let shapes = take_shapes();
                out.shapes("cm", &shapes);
                let _ = take_spans();
                let mut t = 1u64;
                for r in 0..repeats {
                    t += 1;
                    let bt = batch(&mut rng);
                    let _ = take_spans();
                    let _ = leaf.prove_epoch_commit(t, state.clone(), bt.clone(), &commit.openings(cf, t));
                    let tm = timing::take();
                    eprintln!(
                        "[exp_operator] cm leaf {r}: witness {:.0} ms, prove {:.0} ms, verify {:.0} ms",
                        tm.witness.as_secs_f64() * 1e3,
                        tm.prove.as_secs_f64() * 1e3,
                        tm.verify.as_secs_f64() * 1e3
                    );
                    out.summary("cm", "leaf", r, tm);
                    out.spans("cm", "leaf", r, &take_spans());
                    countmin_omc_advance(&mut state, &bt);
                }
                // query: a point query at version t
                let key = b1[0].key;
                let qp = CmDecodeParams { d, w, release: ReleasePolicy::Identity };
                for r in 0..repeats {
                    let _ = take_spans();
                    let _ = prove_cm_decode_commit(qp, state.clone(), key, default_binding(), mode, &commit.state_salt(cf, t));
                    let tm = timing::take();
                    eprintln!(
                        "[exp_operator] cm query {r}: witness {:.0} ms, prove {:.0} ms, verify {:.0} ms",
                        tm.witness.as_secs_f64() * 1e3,
                        tm.prove.as_secs_f64() * 1e3,
                        tm.verify.as_secs_f64() * 1e3
                    );
                    out.summary("cm", "query", r, tm);
                    out.spans("cm", "query", r, &take_spans());
                    if r == 0 {
                        out.shapes("cm_query", &take_shapes());
                    }
                }
            }
            "mg" => {
                let cap = env_usize("EXP_SS_CAP", 16384);
                let m = env_usize("EXP_M_MG", 16384);
                let c = env_usize("EXP_SS_C", 1);
                let params = SsFullParams { capacity: cap, batch: m };
                let cf = CommitFamily::SpaceSaving;
                eprintln!("[exp_operator] mg: cap={cap} m={m}, prefix probes");
                let build = || {
                    let _ = build_ss_full_leaf_commit(params, composition_expose(), mode);
                };
                let prefixes = probe_phases("ss_final_full", 5, &build);
                out.phases("mg", &prefixes);

                eprintln!("[exp_operator] mg: full build");
                let t0 = Instant::now();
                let mut leaf = build_ss_full_leaf_commit(params, composition_expose(), mode);
                eprintln!("[exp_operator] mg: built in {:.1} s", t0.elapsed().as_secs_f64());
                let mut state = SsFullState::empty(params);
                // keys from a small hot set plus a long tail, so the summary fills and reduces
                let mut batch = |rng: &mut Rng| -> Vec<SsFullUpdate> {
                    (0..m)
                        .map(|_| {
                            let r = rng.next();
                            // keys are single 29-bit limbs in this circuit (KEY_DIFF_BITS); 0 is the dummy key
                            let key = if r % 4 == 0 { 1 + r % 200 } else { 1 + ((r >> 8) & 0x0FFF_FFFF) };
                            SsFullUpdate { key, value: 1 + (rng.next() % 100) as u32, active: 1 }
                        })
                        .collect()
                };
                let b1 = batch(&mut rng);
                let _ = take_spans();
                let _ = take_shapes();
                let _ = leaf.prove_epoch_commit(1, state.clone(), b1.clone(), &commit.openings(cf, 1));
                out.summary("mg", "warmup", 0, timing::take());
                state = apply_batch_ss_full(&state, &b1).0;
                out.shapes("mg", &take_shapes());
                let _ = take_spans();
                let mut t = 1u64;
                for r in 0..repeats {
                    t += 1;
                    let bt = batch(&mut rng);
                    let _ = take_spans();
                    let _ = leaf.prove_epoch_commit(t, state.clone(), bt.clone(), &commit.openings(cf, t));
                    let tm = timing::take();
                    eprintln!(
                        "[exp_operator] mg leaf {r}: witness {:.0} ms, prove {:.0} ms, verify {:.0} ms",
                        tm.witness.as_secs_f64() * 1e3,
                        tm.prove.as_secs_f64() * 1e3,
                        tm.verify.as_secs_f64() * 1e3
                    );
                    out.summary("mg", "leaf", r, tm);
                    out.spans("mg", "leaf", r, &take_spans());
                    state = apply_batch_ss_full(&state, &bt).0;
                }
                let qp = SsDecodeParams { capacity: cap, c, release: ReleasePolicy::Identity };
                for r in 0..repeats {
                    let _ = take_spans();
                    let _ = prove_ss_decode_commit(qp, state.clone(), c, default_binding(), mode, &commit.state_salt(cf, t));
                    let tm = timing::take();
                    eprintln!(
                        "[exp_operator] mg query {r}: witness {:.0} ms, prove {:.0} ms, verify {:.0} ms",
                        tm.witness.as_secs_f64() * 1e3,
                        tm.prove.as_secs_f64() * 1e3,
                        tm.verify.as_secs_f64() * 1e3
                    );
                    out.summary("mg", "query", r, tm);
                    out.spans("mg", "query", r, &take_spans());
                    if r == 0 {
                        out.shapes("mg_query", &take_shapes());
                    }
                }
            }
            "gk" => {
                let cap = env_usize("EXP_GK_CAP", 768);
                let s = env_usize("EXP_GK_S", 51);
                let m = env_usize("EXP_M_GK", 512);
                let params = GkbParams { capacity: cap, batch: m, s: s as u64 };
                let cf = CommitFamily::GreenwaldKhanna;
                eprintln!("[exp_operator] gk: cap={cap} s={s} m={m}, prefix probes");
                let build = || {
                    let _ = build_gkb2_leaf_rounds(params, composition_expose(), default_binding(), mode, default_gk_rounds());
                };
                let prefixes = probe_phases("gk_bandmerge2_stable", 6, &build);
                out.phases("gk", &prefixes);

                eprintln!("[exp_operator] gk: full build");
                let t0 = Instant::now();
                let mut leaf =
                    build_gkb2_leaf_rounds(params, composition_expose(), default_binding(), mode, default_gk_rounds());
                eprintln!("[exp_operator] gk: built in {:.1} s", t0.elapsed().as_secs_f64());
                let mut state = Gk2State::empty(params);
                let mut vals = |rng: &mut Rng| -> Vec<u32> { (0..m).map(|_| (rng.next() & 0x001F_FFFF) as u32).collect() };
                let v1 = vals(&mut rng);
                let _ = take_spans();
                let _ = take_shapes();
                let _ = leaf.prove_epoch_commit(1, state.clone(), v1.clone(), &commit.openings(cf, 1));
                out.summary("gk", "warmup", 0, timing::take());
                state = apply_batch2(&state, &v1);
                out.shapes("gk", &take_shapes());
                let _ = take_spans();
                let mut t = 1u64;
                for r in 0..repeats {
                    t += 1;
                    let vt = vals(&mut rng);
                    let _ = take_spans();
                    let _ = leaf.prove_epoch_commit(t, state.clone(), vt.clone(), &commit.openings(cf, t));
                    let tm = timing::take();
                    eprintln!(
                        "[exp_operator] gk leaf {r}: witness {:.0} ms, prove {:.0} ms, verify {:.0} ms",
                        tm.witness.as_secs_f64() * 1e3,
                        tm.prove.as_secs_f64() * 1e3,
                        tm.verify.as_secs_f64() * 1e3
                    );
                    out.summary("gk", "leaf", r, tm);
                    out.spans("gk", "leaf", r, &take_spans());
                    state = apply_batch2(&state, &vt);
                }
                let qval = v1[0];
                let qp = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
                for r in 0..repeats {
                    let _ = take_spans();
                    let _ = prove_gk2_decode_commit(qp, state.clone(), qval, default_binding(), mode, &commit.state_salt(cf, t));
                    let tm = timing::take();
                    eprintln!(
                        "[exp_operator] gk query {r}: witness {:.0} ms, prove {:.0} ms, verify {:.0} ms",
                        tm.witness.as_secs_f64() * 1e3,
                        tm.prove.as_secs_f64() * 1e3,
                        tm.verify.as_secs_f64() * 1e3
                    );
                    out.summary("gk", "query", r, tm);
                    out.spans("gk", "query", r, &take_spans());
                    if r == 0 {
                        out.shapes("gk_query", &take_shapes());
                    }
                }
            }
            other => panic!("EXP_FAMILIES: unknown family {other} (cm|mg|gk)"),
        }
    }
    out.write(&out_dir, &fams);
}
