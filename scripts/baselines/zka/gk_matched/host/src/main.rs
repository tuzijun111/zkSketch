// zk-Analytics-architecture GREENWALD-KHANNA arm with zkSketch's GK ALGORITHM: our
// guests (aggr_gkm, querier_gkm) run in zk-Analytics' own epoch pipeline on REAL AOL
// records, and the summary update is zkSketch's two-sided band-merge batch rule
// (apply_batch2, src/sketch/gk_bandmerge.rs), not textbook GK. Both systems then compute
// the same sketch state from the same records, so the comparison is the cost of the
// same work (../README.md; the textbook port ../../gk stays as a labelled reference).
//
// Records (as ../../gk): data/aol.keys (flat little-endian u32). Epoch e holds keys
// [e*B, (e+1)*B), B = --epoch-size.
//   key_id = Event::make_key_id(0, key)   (zkvm-common/src/lib.rs:76)
//   value  = key & 0x1F_FFFF              (zkSketch's gk_vals_of mask; the guest applies
//                                          gk_vals_of again, which keeps these values)
//   ts     = global record index
// Batches: source 0, stream order, --batch records each (default 8, their
// --commit-batch-size default); SHA-256 batch chain, source_batch_seq and
// prev_source_chain_tips carried across epochs as their aggregator host does. Epoch e's
// prev_chain_hash is epoch e-1's final_chain_hash, and epoch e's guest takes S_{e-1}
// (checked against epoch e-1's state_commit through that link).
// GK configuration (zkSketch's GkbParams of the run being matched):
//   --capacity C   (default 2048; EXP_GK_CAP / SIX_GK_CAP)
//   --m-sub M      (default = --epoch-size; zkSketch's leaf size: each epoch is applied as
//                   B / M successive apply_batch2 steps. B must be a multiple of M, so the
//                   steps are exactly zkSketch's leaves)
//   --s S          (default 51; EXP_GK_S)
//   --impl tuned|fast|fixed_linear|literal   (default tuned, the steelman; the guest's
//                   implementation of the one transition: tuned = ../core apply_epoch_tuned,
//                   the others ../../gk_bm2/README.md; same state, different cycles)
// A capacity overflow is a HARD ERROR: the native reference detects it first and the
// driver exits 3 without running a guest; the guest itself also panics on one.
// zk-Analytics epochs are never padded, so the guest's gk_vals_of PAD_KEY strip is a no-op
// here (the driver masks value = key & 0x1FFFFF): the driver refuses a dataset with a key
// equal to PAD_KEY (u32::MAX) in the epochs it runs, where zkSketch would strip that record.
//
// Modes:
//   --mode aggr [--epoch-index i] [--root designed|noroot|pertuple] [--emit-state] [--prove]
//        chain epochs 0..i natively, execute (and with --prove prove) aggr_gkm on epoch i.
//        Root variants as ../../gk's aggr_gk_root (designed = 64-bucket samples-pattern
//        root, noroot = none (default), pertuple = one leaf per tuple); `legacy` (the
//        committed textbook-GK guest) does not exist here and is refused.
//        Checks: journal == native (journal_eq_native); the native state == zkSketch's
//        own apply_batch2 chain over the same records, tuple by tuple
//        (state_eq_zksketch; with --emit-state also the guest's emitted state); every
//        root variant and every implementation gives the same state, commitment and link
//        (variants_agree).
//   --mode query --epochs n --query rank --rank-value v [--prove]
//        chain epochs 0..n-1 natively, execute (prove) querier_gkm on the latest state.
//        Checks: journal == native; the answer's bounds == zkSketch's
//        Gk2State::rank_interval on zkSketch's own chain (query_eq_zksketch).
//   --mode check --epochs K [--impl all|<list>]
//        equivalence sweep: for every epoch e < K and implementation, execute aggr_gkm
//        WITH the new state emitted and compare it tuple by tuple with zkSketch's native
//        chain; execute querier_gkm at n = e+1 on the hot value (the most frequent masked
//        value of the prefix, the zkSketch EXP_QUERY_KEY_MODE=hot rule) and compare with
//        zkSketch's rank_interval. One row per (epoch, implementation).
//   --mode certify --epochs K [--commit hiding|plain] [--seed N]
//        zkSketch's OWN leaf circuit on the same records: build the GK band-merge leaf
//        exactly as exp_compose does (build_gkb2_leaf_commit(params, composition_expose(),
//        default_binding(), mode)) and prove every m_sub-record leaf of epochs 0..K-1
//        (global batch index t, openings of a ProverCommit with the public test seed N),
//        and check that each epoch's last leaf exposes Com(S) of the state the zk-Analytics
//        guest computed (emitted by aggr_gkm, executed); also prove zkSketch's GK decoder on
//        that state at the hot value and compare its answer with querier_gkm's. Heavy
//        (real STARK proofs; ~6 s per cap-384/128 leaf). One row per epoch.
//   --header
//   common: [--keys PATH] [--epoch-size 2048] [--batch 8]
// Nothing runs in RISC0_DEV_MODE. Exit status: 0 ok; 1 a check failed (row printed);
// 2 bad arguments; 3 capacity overflow.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gk_matched_core::{
    actives, batch_chain_hash, bm2, compact_words, gkm_rank, gkm_state_commit, padded, process_gkm_aggr, run_gkm_query,
    BatchInput, EpochChainLink, GkmAggrInput, GkmAggrOutput, GkmCarried, GkmConfig, GkmImpl, GkmQueryInput,
    GkmQueryOutput, GkmRoot, MARK_NAMES,
};
use gk_matched_methods::{AGGR_GKM_ELF, AGGR_GKM_ID, QUERIER_GKM_ELF, QUERIER_GKM_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, SessionInfo};
use zksketch::experiments::stream_compose::gk_vals_of;
use zksketch::sketch::gk_bandmerge::{apply_batch2, Gk2State, Gk2Tuple, GkbParams};
use zkvm_common::Event;

const VALUE_MASK: u32 = 0x001F_FFFF;
/// MODELED prove time: segments x 30.1 s, envelope 29.73 .. 30.79 s/segment (the four
/// CPU CM anchors in ../../README.md "Modeled prove time and the anchors behind it").
const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] = &[
    "--mode", "--query", "--epochs", "--epoch-index", "--keys", "--epoch-size", "--batch", "--rank-value", "--root",
    "--capacity", "--m-sub", "--s", "--impl", "--commit", "--seed",
];
const BOOL_FLAGS: &[&str] = &["--prove", "--header", "--emit-state"];

fn validate_args() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < a.len() {
        let s = a[i].as_str();
        if BOOL_FLAGS.contains(&s) {
            i += 1;
        } else if VALUE_FLAGS.contains(&s) {
            if i + 1 >= a.len() {
                die(&format!("'{s}' requires a value"));
            }
            i += 2;
        } else {
            die(&format!(
                "unknown argument '{s}' (value flags: {}; bool flags: {})",
                VALUE_FLAGS.join(" "),
                BOOL_FLAGS.join(" ")
            ));
        }
    }
}
fn die(msg: &str) -> ! {
    eprintln!("gk_matched: {msg}");
    std::process::exit(2);
}
fn arg_str(name: &str) -> Option<String> {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == name {
            return it.next();
        }
    }
    None
}
fn arg_u64(name: &str, default: u64) -> u64 {
    match arg_str(name) {
        None => default,
        Some(v) => v.parse().unwrap_or_else(|_| die(&format!("{name}='{v}' is not a non-negative integer"))),
    }
}
fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}
fn dev_mode_set() -> bool {
    match std::env::var("RISC0_DEV_MODE") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "no" | "off"),
        Err(_) => false,
    }
}

// ------------------------------------------------------------------- records
fn load_keys(path: &str) -> Vec<u32> {
    let b = std::fs::read(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    if b.len() % 4 != 0 {
        die(&format!("{path}: length {} is not a multiple of 4", b.len()));
    }
    b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

/// Source 0's SHA-256 batch chain, continued across epochs exactly as their aggregator
/// host carries it (same as ../../gk/host and ../../cyc/src/bin/shipped.rs SourceChain).
struct SourceChain {
    tip: [u8; 32],
    next_seq: u64,
}
impl SourceChain {
    fn batches(&mut self, events: &[Event], cbs: usize) -> Vec<BatchInput> {
        let mut out = Vec::with_capacity(events.len().div_ceil(cbs));
        for chunk in events.chunks(cbs) {
            let evs = chunk.to_vec();
            // seq 0 always restarts from the zero tip (aggregator/core/src/lib.rs:538-540)
            let prev = if self.next_seq == 0 { [0u8; 32] } else { self.tip };
            let h = batch_chain_hash(prev, &evs);
            out.push(BatchInput { source_id: 0, source_batch_seq: self.next_seq, events: evs, sent_batch_hash: h });
            self.tip = h;
            self.next_seq += 1;
        }
        out
    }
}

fn epoch_events(keys: &[u32], e: usize, m: usize) -> Vec<Event> {
    (e * m..(e + 1) * m)
        .map(|i| Event { ts: i as u32, key_id: Event::make_key_id(0, keys[i] as u64), value: keys[i] & VALUE_MASK })
        .collect()
}

/// The most frequent masked value of the first `len` records, ties to the smaller value:
/// zkSketch's EXP_QUERY_KEY_MODE=hot rule for GK (select_query_key), as six/jobs.py.
fn hot_value(keys: &[u32], len: usize) -> u32 {
    let mut c: HashMap<u32, u64> = HashMap::new();
    for &k in &keys[..len] {
        if k != u32::MAX {
            *c.entry(k & VALUE_MASK).or_insert(0) += 1;
        }
    }
    c.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0))).map(|(v, _)| v).unwrap_or(0)
}

// ------------------------------------------------------- zkSketch <-> port glue
fn zk_params(cfg: &GkmConfig) -> GkbParams {
    GkbParams { capacity: cfg.capacity as usize, batch: cfg.m_sub as usize, s: cfg.s as u64 }
}
fn to_port(s: &Gk2State) -> bm2::State {
    bm2::State {
        tuples: s
            .tuples
            .iter()
            .map(|t| bm2::Tuple { e: t.e, g: t.g, g_o: t.g_o, delta: t.delta, delta_o: t.delta_o, t: t.t, active: t.active })
            .collect(),
        params: bm2::Params { capacity: s.params.capacity, batch: s.params.batch, s: s.params.s },
        n: s.n,
    }
}
fn from_port(s: &bm2::State) -> Gk2State {
    Gk2State {
        tuples: s
            .tuples
            .iter()
            .map(|t| Gk2Tuple { e: t.e, g: t.g, g_o: t.g_o, delta: t.delta, delta_o: t.delta_o, t: t.t, active: t.active })
            .collect(),
        params: GkbParams { capacity: s.params.capacity, batch: s.params.batch, s: s.params.s },
        n: s.n,
    }
}
fn fields(t: &Gk2Tuple) -> [u64; 7] {
    [t.e as u64, t.g, t.g_o, t.delta, t.delta_o, t.t, t.active as u64]
}
fn port_fields(t: &bm2::Tuple) -> [u64; 7] {
    [t.e as u64, t.g, t.g_o, t.delta, t.delta_o, t.t, t.active as u64]
}
/// Tuple-by-tuple comparison of a port state with zkSketch's (all 7 fields of every row,
/// n and the parameters); `Err` names the first difference.
fn compare_state(native: &Gk2State, got: &bm2::State) -> Result<(), String> {
    let np = (native.params.capacity, native.params.batch, native.params.s);
    let gp = (got.params.capacity, got.params.batch, got.params.s);
    if np != gp {
        return Err(format!("params zkSketch={np:?} got={gp:?}"));
    }
    if native.n != got.n {
        return Err(format!("n zkSketch={} got={}", native.n, got.n));
    }
    if native.tuples.len() != got.tuples.len() {
        return Err(format!("row count zkSketch={} got={}", native.tuples.len(), got.tuples.len()));
    }
    for (i, (a, b)) in native.tuples.iter().zip(&got.tuples).enumerate() {
        if fields(a) != port_fields(b) {
            return Err(format!("row {i}: zkSketch (e,g,g°,Δ,Δ°,t,active)={:?} got={:?}", fields(a), port_fields(b)));
        }
    }
    Ok(())
}
fn zk_mass(s: &Gk2State) -> u64 {
    s.tuples.iter().filter(|t| t.active == 1).map(|t| t.g + t.g_o + 1).sum()
}

// ------------------------------------------------------- the native pipeline
/// One epoch of the native pipeline.
struct EpochNative {
    input: GkmAggrInput,
    /// S_e as our core computes it (host build of the guest code), in its full form.
    state: bm2::State,
    /// The noroot journal output.
    out: GkmAggrOutput,
    /// zkSketch's own apply_batch2 chain at the end of the epoch.
    zk_state: Gk2State,
    /// Our state == zkSketch's, tuple by tuple.
    zk_eq: Result<(), String>,
}

/// Epochs 0..n of the pipeline natively, chaining epochs, source tips and states as their
/// host does, next to zkSketch's own chain over the same records in m_sub-record batches
/// (exp_compose's batches_from + gk_vals_of + apply_batch2). Exits 3 on a capacity
/// overflow (detected on zkSketch's chain: active mass != N after a step).
fn chain(keys: &[u32], n: usize, m: usize, cbs: usize, cfg: GkmConfig) -> (Vec<EpochNative>, Vec<EpochChainLink>) {
    let ms = cfg.m_sub as usize;
    let params = zk_params(&cfg);
    let mut zk = Gk2State::empty(params);
    let mut source = SourceChain { tip: [0u8; 32], next_seq: 0 };
    let mut prev_chain_hash = [0u8; 32];
    let mut prev_link_prev = [0u8; 32];
    let mut prev_tips: Vec<(u32, u64, [u8; 32])> = Vec::new();
    let mut prev_state: Option<bm2::State> = None;
    let mut outs = Vec::with_capacity(n);
    let mut links = Vec::with_capacity(n);
    for e in 0..n {
        // zkSketch's reference chain over this epoch's m_sub-record batches
        for j in 0..m / ms {
            let lo = e * m + j * ms;
            let vals = gk_vals_of(&keys[lo..lo + ms]);
            zk = apply_batch2(&zk, &vals);
            let mass = zk_mass(&zk);
            if mass != zk.n {
                eprintln!(
                    "gk_matched: GK CAPACITY OVERFLOW at epoch {e}, step {j} (zkSketch batch t = {}): capacity {} keeps mass \
                     {mass} of N = {} records; zkSketch's leaf circuit refuses this step and the guest would panic. \
                     Raise --capacity (SIX_GK_CAP).",
                    e * (m / ms) + j + 1,
                    cfg.capacity,
                    zk.n
                );
                std::process::exit(3);
            }
        }
        let batches = source.batches(&epoch_events(keys, e, m), cbs);
        let carried = prev_state
            .as_ref()
            .map(|s| GkmCarried { link_prev_hash: prev_link_prev, state_words: compact_words(s) });
        let input =
            GkmAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone(), config: cfg, carried };
        let (state, out) = process_gkm_aggr(&input, GkmRoot::None);
        let state = padded(state);
        assert_eq!(out.n_events as usize, m);
        assert_eq!(out.epoch_chain_link.prev_chain_hash, prev_chain_hash);
        let zk_eq = compare_state(&zk, &state);
        prev_link_prev = prev_chain_hash;
        prev_chain_hash = out.epoch_chain_link.final_chain_hash;
        prev_tips = out.final_source_chain_tips.clone();
        links.push(out.epoch_chain_link.clone());
        prev_state = Some(state.clone());
        outs.push(EpochNative { input, state, out, zk_state: zk.clone(), zk_eq });
    }
    (outs, links)
}

/// The same input under another implementation (the configuration is part of the input
/// and of the journal).
fn with_impl(input: &GkmAggrInput, i: GkmImpl) -> GkmAggrInput {
    let mut x = input.clone();
    x.config.implementation = i;
    x
}

/// Every root variant x every implementation, natively on the same input: same state,
/// state commitment, epoch link, n_events, tips and steps; the root field as specified.
fn variants_agree(input: &GkmAggrInput) -> bool {
    let (st, base) = process_gkm_aggr(input, GkmRoot::None);
    let st = padded(st);
    let blank = |o: &GkmAggrOutput| {
        let mut o = o.clone();
        o.tuples_root = [0u8; 32];
        o.config.implementation = GkmImpl::Fast;
        o
    };
    let per_tuple = gk_matched_core::gkm_tuples_root(actives(&st));
    GkmImpl::ALL.iter().all(|&i| {
        [GkmRoot::Buckets64, GkmRoot::None, GkmRoot::PerTuple].iter().all(|&r| {
            let (s2, o) = process_gkm_aggr(&with_impl(input, i), r);
            padded(s2) == st
                && blank(&o) == blank(&base)
                && match r {
                    GkmRoot::None => o.tuples_root == [0u8; 32],
                    GkmRoot::PerTuple => o.tuples_root == per_tuple,
                    GkmRoot::Buckets64 => o.tuples_root != [0u8; 32],
                }
        })
    })
}

// ------------------------------------------------------------------ zkVM runs
struct Exec {
    user_cycles: u64,
    padded_cycles: u64,
    segments: usize,
    max_po2: u32,
    exec_s: f64,
    input_bytes: usize,
    journal_bytes: usize,
    marks: Vec<u64>,
    emitted: Option<Vec<u32>>,
    session: SessionInfo,
}

fn execute<T: serde::Serialize>(input: &T, elf: &[u8], n_marks: usize) -> Exec {
    let input_bytes = risc0_zkvm::serde::to_vec(input).expect("serialize input").len() * 4;
    let mut out: Vec<u8> = Vec::new();
    let t = Instant::now();
    let session = {
        let env = ExecutorEnv::builder().write(input).unwrap().stdout(&mut out).build().unwrap();
        default_executor().execute(env, elf).unwrap_or_else(|e| {
            eprintln!("gk_matched: guest execution failed: {e:?}");
            std::process::exit(1);
        })
    };
    let exec_s = t.elapsed().as_secs_f64();
    let (marks, emitted) = if n_marks == 0 {
        (Vec::new(), None)
    } else {
        if out.len() < 8 * n_marks {
            die(&format!("guest stdout too short ({} bytes)", out.len()));
        }
        let marks: Vec<u64> =
            out[..8 * n_marks].chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
        let rest = &out[8 * n_marks..];
        let emitted = if rest.is_empty() {
            None
        } else {
            Some(rest.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect())
        };
        (marks, emitted)
    };
    Exec {
        user_cycles: session.cycles(),
        padded_cycles: session.segments.iter().map(|s| 1u64 << s.po2).sum(),
        segments: session.segments.len(),
        max_po2: session.segments.iter().map(|s| s.po2).max().unwrap_or(0),
        exec_s,
        input_bytes,
        journal_bytes: session.journal.bytes.len(),
        marks,
        emitted,
        session,
    }
}

const N_AGGR_MARKS: usize = MARK_NAMES.len() + 3;

/// Execute aggr_gkm: input (root, input, emit) -> journal (root, output).
fn exec_aggr(root: GkmRoot, input: &GkmAggrInput, emit: bool) -> Exec {
    execute(&(root, input, emit), AGGR_GKM_ELF, N_AGGR_MARKS)
}

/// Phase split from the guest's cycle_count marks (start, read, one per phase, journal);
/// cycle_count reports user cycles, so pre + every phase + post = user_cycles.
/// Same format as ../../kmv and ../../hll (`read` and `chain` are what six/table.py reads).
fn prof(x: &Exec) -> String {
    let m = &x.marks;
    let k = MARK_NAMES.len();
    if m.len() != k + 3 {
        return format!("marks={}", m.len());
    }
    let mut s = format!("pre={};read={}", m[0], m[1] - m[0]);
    for (i, n) in MARK_NAMES.iter().enumerate() {
        s.push_str(&format!(";{n}={}", m[i + 2] - m[i + 1]));
    }
    s.push_str(&format!(";journal={};post={}", m[k + 2] - m[k + 1], x.user_cycles as i64 - m[k + 2] as i64));
    s
}

struct Proved {
    prove_s: f64,
    verify_ms: f64,
    receipt_bytes: usize,
    segments: usize,
    total_cycles: u64,
    user_cycles: u64,
    peak_rss_mb: f64,
    contention: Contention,
}

/// What else ran on the box during the prove, sampled from /proc (read-only).
#[derive(Default)]
struct Contention {
    foreign_pids: usize,
    foreign_max: usize,
    foreign_samples: usize,
    samples: usize,
    foreign_cpu_s: f64,
    load1_max: f64,
}
/// A row is labelled proved_contended when foreign r0vm processes burned at least this
/// many CPU seconds during the prove (as ../../gk).
const CONTENDED_CPU_S: f64 = 10.0;
impl Contention {
    fn seen(&self) -> bool {
        self.foreign_cpu_s >= CONTENDED_CPU_S
    }
    fn csv(&self) -> String {
        if self.foreign_pids > 0 {
            format!(
                "foreign_r0vm={};foreign_max={};foreign_samples={}/{};foreign_cpu_s={:.1};load1_max={:.1}",
                self.foreign_pids, self.foreign_max, self.foreign_samples, self.samples, self.foreign_cpu_s, self.load1_max
            )
        } else {
            format!("none;samples={};load1_max={:.1}", self.samples, self.load1_max)
        }
    }
}

/// Descendant pids of `root` (the r0vm prover runs as a child of this driver). Reads /proc only.
fn descendants(root: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(p) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(format!("/proc/{p}/task")) {
            for t in rd.flatten() {
                if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                    for c in s.split_whitespace().filter_map(|c| c.parse::<u32>().ok()) {
                        out.push(c);
                        stack.push(c);
                    }
                }
            }
        }
    }
    out
}
fn all_r0vm() -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for d in rd.flatten() {
            if let Some(pid) = d.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                if std::fs::read_to_string(format!("/proc/{pid}/comm")).map_or(false, |c| c.trim() == "r0vm") {
                    out.push(pid);
                }
            }
        }
    }
    out
}
fn cpu_ticks(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}
fn load1() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(f64::NAN)
}
fn vm_hwm_kb(pid: &str) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.to_string()))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

/// Their shipped tier: ProverOpts::succinct(). Checks the PROVED journal against the
/// native output; verify_ms = best of 5 in-process verify calls (all 5 and a bincode
/// decode of the receipt go to stderr as VERIFY_TIMES_MS, as the other drivers).
fn prove<T: serde::Serialize, J: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
    input: &T, elf: &[u8], id: [u32; 8], expect: &J,
) -> Proved {
    if dev_mode_set() {
        die("RISC0_DEV_MODE is set: refusing to report a fake proof");
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let me = std::process::id();
    let sampler = std::thread::spawn(move || {
        let mut peak = 0u64;
        let mut ct = Contention::default();
        let mut foreign: HashMap<u32, (u64, u64)> = HashMap::new();
        loop {
            let mine = descendants(me);
            for c in &mine {
                peak = peak.max(vm_hwm_kb(&c.to_string()));
            }
            let others: Vec<u32> = all_r0vm().into_iter().filter(|p| !mine.contains(p)).collect();
            for &p in &others {
                if let Some(t) = cpu_ticks(p) {
                    foreign.entry(p).and_modify(|e| e.1 = t).or_insert((t, t));
                }
            }
            ct.samples += 1;
            ct.foreign_max = ct.foreign_max.max(others.len());
            ct.foreign_samples += (!others.is_empty()) as usize;
            ct.load1_max = ct.load1_max.max(load1());
            if stop2.load(Ordering::Relaxed) {
                ct.foreign_pids = foreign.len();
                ct.foreign_cpu_s = foreign.values().map(|(a, b)| (b - a) as f64 / 100.0).sum();
                return (peak, ct);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
    // The aggregation guest writes its cycle marks to its private stdout: discard them
    // here (they would otherwise land on this driver's stdout, next to the CSV row).
    let env = ExecutorEnv::builder().write(input).unwrap().stdout(std::io::sink()).build().unwrap();
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct()).expect("prove failed");
    let prove_s = t.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    let (peak_kb, contention) = sampler.join().unwrap_or((0, Contention::default()));
    let receipt = info.receipt;
    assert!(receipt.inner.succinct().is_ok(), "expected a succinct receipt");
    let mut times: Vec<f64> = Vec::with_capacity(5);
    for _ in 0..5 {
        let t2 = Instant::now();
        receipt.verify(id).expect("verify failed");
        times.push(t2.elapsed().as_secs_f64() * 1000.0);
    }
    let best = times.iter().cloned().fold(f64::MAX, f64::min);
    {
        let rb = bincode::serialize(&receipt).expect("serialize receipt");
        let t3 = Instant::now();
        let back: risc0_zkvm::Receipt = bincode::deserialize(&rb).expect("deserialize receipt");
        let dec_ms = t3.elapsed().as_secs_f64() * 1000.0;
        drop(back);
        let all: Vec<String> = times.iter().map(|x| format!("{x:.3}")).collect();
        eprintln!("VERIFY_TIMES_MS,{},receipt_decode_ms={dec_ms:.3}", all.join(";"));
    }
    let got: J = receipt.journal.decode().expect("decode proved journal");
    assert_eq!(&got, expect, "proved journal != native");
    eprintln!(
        "gk_matched: proved in {prove_s:.1} s, {} segments, total_cycles={} user_cycles={} paging={} reserved={}; r0vm peak RSS {:.1} MB; driver VmHWM {:.1} MB; contention {}",
        info.stats.segments, info.stats.total_cycles, info.stats.user_cycles, info.stats.paging_cycles,
        info.stats.reserved_cycles, peak_kb as f64 / 1024.0, vm_hwm_kb("self") as f64 / 1024.0, contention.csv()
    );
    Proved {
        prove_s,
        verify_ms: best,
        receipt_bytes: bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0),
        segments: info.stats.segments,
        total_cycles: info.stats.total_cycles,
        user_cycles: info.stats.user_cycles,
        peak_rss_mb: peak_kb as f64 / 1024.0,
        contention,
    }
}

// ------------------------------------------------------------------ output
const HEADER: &str = "system,arm,mode,guest,family,algorithm,implementation,query,s,capacity,m_sub,steps,epochs,epoch_index,epoch_records,records,batch,value_enc,n_total,actives,theta,input_bytes,user_cycles,padded_cycles,segments,max_po2,exec_s,journal_bytes,state_commits,journal_eq_native,state_eq_zksketch,query_eq_zksketch,certified_eq,result,exact,abs_err,cert_err,eps_n,exact_in_cert,cert_le_eps_n,prof,prove_s,verify_ms,receipt_bytes,s_per_segment,proved_segments,proved_total_cycles,proved_user_cycles,r0vm_peak_rss_mb,contention,MODELED_prove_s,MODELED_prove_s_lo,MODELED_prove_s_hi,model,image_id,root_variant,root_construction,variants_agree,state_commit";

/// One CSV row, filled by column name (unset columns print `-`).
struct Row(HashMap<&'static str, String>);
impl Row {
    fn new() -> Self {
        Row(HashMap::new())
    }
    fn put(&mut self, k: &'static str, v: impl ToString) -> &mut Self {
        assert!(HEADER.split(',').any(|c| c == k), "column {k} not in HEADER");
        let v = v.to_string();
        assert!(!v.contains(',') && !v.contains('\n'), "column {k}: value '{v}' would break the CSV");
        self.0.insert(k, v);
        self
    }
    fn print(&self) {
        let cols: Vec<String> =
            HEADER.split(',').map(|c| self.0.get(c).cloned().unwrap_or_else(|| "-".to_string())).collect();
        println!("{}", cols.join(","));
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn image_id(id: [u32; 8]) -> String {
    risc0_zkvm::sha::Digest::from(id).to_string()
}

fn common_cols(r: &mut Row, cfg: &GkmConfig, m: usize, cbs: usize) {
    r.put("system", "zka")
        .put("family", "gk")
        .put("algorithm", "bm2")
        .put("implementation", cfg.implementation.name())
        .put("s", cfg.s)
        .put("capacity", cfg.capacity)
        .put("m_sub", cfg.m_sub)
        .put("steps", m / cfg.m_sub as usize)
        .put("epoch_records", m)
        .put("batch", cbs)
        .put("value_enc", "key&0x1FFFFF")
        .put("model", "MODELED=segments*30.1 s/seg (CM-guest CPU anchors; not measured)");
}

fn exec_cols(r: &mut Row, x: &Exec, p: Option<Proved>) {
    let seg = x.segments as f64;
    r.put("input_bytes", x.input_bytes)
        .put("user_cycles", x.user_cycles)
        .put("padded_cycles", x.padded_cycles)
        .put("segments", x.segments)
        .put("max_po2", x.max_po2)
        .put("exec_s", format!("{:.3}", x.exec_s))
        .put("journal_bytes", x.journal_bytes)
        .put("MODELED_prove_s", format!("{:.1}", seg * S_PER_SEG))
        .put("MODELED_prove_s_lo", format!("{:.1}", seg * S_PER_SEG_LO))
        .put("MODELED_prove_s_hi", format!("{:.1}", seg * S_PER_SEG_HI));
    match p {
        Some(p) => {
            if p.contention.seen() {
                let arm = r.0.get("arm").cloned().unwrap_or_default();
                r.put("arm", format!("{arm}_contended"));
            }
            r.put("prove_s", format!("{:.3}", p.prove_s))
                .put("verify_ms", format!("{:.3}", p.verify_ms))
                .put("receipt_bytes", p.receipt_bytes)
                .put("s_per_segment", format!("{:.3}", p.prove_s / p.segments.max(1) as f64))
                .put("proved_segments", p.segments)
                .put("proved_total_cycles", p.total_cycles)
                .put("proved_user_cycles", p.user_cycles)
                .put("r0vm_peak_rss_mb", format!("{:.1}", p.peak_rss_mb))
                .put("contention", p.contention.csv());
        }
        None => {
            r.put("prove_s", "NaN")
                .put("verify_ms", "NaN")
                .put("receipt_bytes", 0)
                .put("s_per_segment", "NaN")
                .put("proved_segments", 0)
                .put("proved_total_cycles", 0)
                .put("proved_user_cycles", 0)
                .put("r0vm_peak_rss_mb", "NaN");
        }
    }
}

/// Native accuracy of a state over every distinct value of the records it summarises:
/// (max |estimate - exact rank|, max certified half-width max(est - lo, hi - est),
/// every exact rank inside [lo, hi], eps N).
fn state_accuracy(st: &bm2::State, vals: &[u32], s: u32) -> (u64, u64, bool, f64) {
    let mut sorted = vals.to_vec();
    sorted.sort_unstable();
    let mut xs = sorted.clone();
    xs.dedup();
    let (mut ae, mut ce, mut inside) = (0u64, 0u64, true);
    for &x in &xs {
        let (lo, hi, est) = gkm_rank(st, x);
        let exact = sorted.partition_point(|&v| v <= x) as u64;
        ae = ae.max(est.abs_diff(exact));
        ce = ce.max((est - lo).max(hi - est));
        inside &= lo <= exact && exact <= hi;
    }
    (ae, ce, inside, vals.len() as f64 / s as f64)
}

fn parse_root() -> (&'static str, GkmRoot) {
    match arg_str("--root").as_deref() {
        None | Some("noroot") => ("noroot", GkmRoot::None),
        Some("designed") => ("designed", GkmRoot::Buckets64),
        Some("pertuple") => ("pertuple", GkmRoot::PerTuple),
        Some("legacy") => die(
            "--root legacy is the committed 2026-10-09 TEXTBOOK-GK guest (../gk, SIX_ZKA_GK=textbook); \
             the matched port has designed|noroot|pertuple",
        ),
        Some(o) => die(&format!("--root {o}: expected designed|noroot|pertuple")),
    }
}

fn parse_impls(default_all: bool) -> Vec<GkmImpl> {
    match arg_str("--impl").as_deref() {
        None if default_all => GkmImpl::ALL.to_vec(),
        None => vec![GkmImpl::Literal], // zkSketch's apply_batch2 as written: the baseline
        Some("all") => GkmImpl::ALL.to_vec(),
        Some(list) => list
            .split(',')
            .map(|s| GkmImpl::parse(s).unwrap_or_else(|| die(&format!("--impl {s}: expected tuned|fast|fixed_linear|literal|all"))))
            .collect(),
    }
}

/// zkSketch's own leaf circuit and decoder on the same records (`--mode certify`).
mod certify {
    use super::*;
    use zksketch::commitment::hiding::{CommitFamily, SaltSeed};
    use zksketch::decode::gk_bandmerge::{prove_gk2_decode_commit, Gkb2DecodeParams};
    use zksketch::decode::ReleasePolicy;
    use zksketch::experiments::prover_commit::ProverCommit;
    use zksketch::recursion::recursive::statement::composition_expose;
    use zksketch::sketch::bind::default_binding;
    use zksketch::sketch::gk_bandmerge::{build_gkb2_leaf_commit, commit_gk2_state_with};

    pub struct Epoch {
        pub leaves: usize,
        pub leaf_prove_s: f64,
        /// every leaf's exposed initial / final commitment == Com of zkSketch's native chain
        pub chain_ok: bool,
        /// the epoch's last leaf exposes Com(S) of the GUEST's state
        pub certified_eq: bool,
        pub decode_answer: u64,
        pub decode_s: f64,
    }

    pub struct Certifier {
        pc: ProverCommit,
        leaf: zksketch::sketch::gk_bandmerge::Gkb2LeafCircuit,
        params: GkbParams,
        st: Gk2State,
        t: u64,
        pub mode_label: &'static str,
    }

    impl Certifier {
        pub fn new(cfg: &GkmConfig, hiding: bool, seed: u64) -> Self {
            let pc = if hiding { ProverCommit::hiding(SaltSeed::for_tests(seed)) } else { ProverCommit::plain() };
            let params = zk_params(cfg);
            let t0 = Instant::now();
            // exactly exp_compose's leaf (src/experiments/stream_compose.rs prove_leaves)
            let leaf = build_gkb2_leaf_commit(params, composition_expose(), default_binding(), pc.mode());
            eprintln!("gk_matched certify: zkSketch GK leaf circuit built in {:.1} s ({})", t0.elapsed().as_secs_f64(), pc.label());
            Certifier { mode_label: pc.label(), pc, leaf, params, st: Gk2State::empty(params), t: 0 }
        }

        /// Prove zkSketch's leaves for one epoch's m_sub-record batches (continuing the
        /// global batch index), then compare with the guest's state and prove the decoder.
        pub fn epoch(&mut self, keys: &[u32], e: usize, m: usize, guest_state: &bm2::State, q: u32) -> Epoch {
            let ms = self.params.batch;
            let mode = self.pc.mode();
            let fam = CommitFamily::GreenwaldKhanna;
            let mut chain_ok = true;
            let mut prove_s = 0.0;
            let mut last_final = None;
            for j in 0..m / ms {
                self.t += 1;
                let t = self.t;
                let lo = e * m + j * ms;
                let vals = gk_vals_of(&keys[lo..lo + ms]);
                let t0 = Instant::now();
                let lp = self.leaf.prove_epoch_commit(t, self.st.clone(), vals.clone(), &self.pc.openings(fam, t));
                prove_s += t0.elapsed().as_secs_f64();
                let init_want = commit_gk2_state_with(&self.st, mode, &self.pc.state_salt(fam, t - 1)).0;
                self.st = apply_batch2(&self.st, &vals);
                let final_want = commit_gk2_state_with(&self.st, mode, &self.pc.state_salt(fam, t)).0;
                let ok = lp.initial.0 == init_want && lp.final_.0 == final_want;
                if !ok {
                    eprintln!("gk_matched certify: MISMATCH leaf t={t}: exposed commitments != Com(zkSketch native chain)");
                }
                chain_ok &= ok;
                last_final = Some(lp.final_.0);
            }
            let gs = from_port(guest_state);
            let salt = self.pc.state_salt(fam, self.t);
            let certified_eq = last_final == Some(commit_gk2_state_with(&gs, mode, &salt).0);
            let t1 = Instant::now();
            let dp = prove_gk2_decode_commit(
                Gkb2DecodeParams { capacity: self.params.capacity, release: ReleasePolicy::Identity },
                gs,
                q,
                default_binding(),
                mode,
                &salt,
            );
            Epoch {
                leaves: m / ms,
                leaf_prove_s: prove_s,
                chain_ok,
                certified_eq,
                decode_answer: dp.answer,
                decode_s: t1.elapsed().as_secs_f64(),
            }
        }
    }
}

fn main() {
    validate_args();
    if flag("--header") {
        println!("{HEADER}");
        return;
    }
    if dev_mode_set() {
        die("RISC0_DEV_MODE is set; unset it (nothing here may run in dev mode)");
    }
    let mode = arg_str("--mode").unwrap_or_else(|| die("--mode aggr|query|check|certify is required"));
    let keys_path =
        arg_str("--keys").unwrap_or_else(|| format!("{}/../../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR")));
    let m = arg_u64("--epoch-size", 2048) as usize;
    let cbs = arg_u64("--batch", 8) as usize;
    if m == 0 || cbs == 0 {
        die("--epoch-size and --batch must be > 0");
    }
    let cap = arg_u64("--capacity", 2048);
    let m_sub = arg_u64("--m-sub", m as u64);
    let s = arg_u64("--s", 51);
    if cap == 0 || m_sub == 0 || s == 0 || cap > u32::MAX as u64 || m_sub > u32::MAX as u64 || s > u32::MAX as u64 {
        die("--capacity, --m-sub and --s must be in 1..2^32");
    }
    if m as u64 % m_sub != 0 {
        die(&format!(
            "--epoch-size {m} is not a multiple of --m-sub {m_sub}: the epoch's steps would straddle zkSketch's \
             {m_sub}-record leaves"
        ));
    }
    if (cap + m_sub) % 2 != 0 {
        die(&format!(
            "capacity + m_sub = {} is odd: zkSketch's GK leaf circuit needs an even table, so there is no zkSketch \
             counterpart to match",
            cap + m_sub
        ));
    }
    if arg_str("--root").is_some() && mode != "aggr" {
        die("--root applies to --mode aggr only (query guests read no root; check/certify use noroot)");
    }
    if arg_str("--rank-value").is_some() && mode != "query" {
        die("--rank-value belongs to --mode query (check/certify query the hot value)");
    }
    let impls = parse_impls(mode == "check");
    if mode != "check" && impls.len() != 1 {
        die("--impl takes one implementation outside --mode check");
    }
    let base_cfg =
        GkmConfig { capacity: cap as u32, m_sub: m_sub as u32, s: s as u32, implementation: impls[0] };
    let keys = load_keys(&keys_path);
    let need = |n: usize| {
        if n * m > keys.len() {
            die(&format!("{n} epochs of {m} need {} keys, {keys_path} has {}", n * m, keys.len()));
        }
        // zkSketch drops a PAD_KEY record (gk_vals_of); here it would arrive masked to
        // 0x1FFFFF and be kept, so such a dataset has no matched counterpart.
        if let Some(i) = keys[..n * m].iter().position(|&k| k == bm2::PAD_KEY) {
            die(&format!(
                "{keys_path}: record {i} is PAD_KEY (u32::MAX), which zkSketch's gk_vals_of drops; zk-Analytics \
                 epochs carry no padding, so the matched configuration needs a PAD_KEY-free dataset"
            ));
        }
    };

    match mode.as_str() {
        "aggr" => {
            if arg_str("--query").is_some() || arg_str("--epochs").is_some() {
                die("--query/--epochs belong to --mode query/check/certify");
            }
            let (root_name, root) = parse_root();
            let do_prove = flag("--prove");
            let emit = flag("--emit-state");
            let idx = arg_u64("--epoch-index", 0) as usize;
            need(idx + 1);
            let cfg = base_cfg;
            let (eps, _links) = chain(&keys, idx + 1, m, cbs, cfg);
            let ep = &eps[idx];
            let (st, native) = process_gkm_aggr(&ep.input, root);
            let st = padded(st);
            let expect: (GkmRoot, GkmAggrOutput) = (root, native.clone());
            let agree = variants_agree(&ep.input);
            let x = exec_aggr(root, &ep.input, emit);
            let got: (GkmRoot, GkmAggrOutput) = x.session.journal.decode().unwrap();
            let eq = got == expect;
            let emitted_eq = x.emitted.as_ref().map(|w| compare_state(&ep.zk_state, &padded(bm2::state_from_words(w))));
            if let Some(Err(e)) = &emitted_eq {
                eprintln!("gk_matched: MISMATCH guest-emitted state vs zkSketch: {e}");
            }
            if let Err(e) = &ep.zk_eq {
                eprintln!("gk_matched: MISMATCH native state vs zkSketch: {e}");
            }
            let state_eq = ep.zk_eq.is_ok() && emitted_eq.as_ref().map_or(true, |r| r.is_ok());
            let covered: Vec<u32> = keys[..(idx + 1) * m].iter().map(|&k| k & VALUE_MASK).collect();
            let (ae, ce, inside, eps_n) = state_accuracy(&st, &covered, cfg.s);
            let ok = eq && agree && state_eq;
            let proved = if do_prove && ok {
                Some(prove(&(root, &ep.input, false), AGGR_GKM_ELF, AGGR_GKM_ID, &expect))
            } else {
                None
            };
            let mut r = Row::new();
            r.put("arm", if proved.is_some() { "proved" } else { "exec" })
                .put("mode", "aggr")
                .put("guest", "aggr_gkm");
            common_cols(&mut r, &cfg, m, cbs);
            r.put("epochs", 1)
                .put("epoch_index", idx)
                .put("records", m)
                .put("n_total", st.n)
                .put("actives", actives(&st).len())
                .put("theta", st.n / cfg.s as u64)
                .put("state_commits", 1)
                .put("journal_eq_native", eq)
                .put("state_eq_zksketch", if emit { format!("{state_eq}(tuples)") } else { state_eq.to_string() })
                .put(
                    "result",
                    format!("steps={};actives={};n={};prev_commit={}", native.steps, actives(&st).len(), st.n, &hex(&native.prev_state_commit)[..16]),
                )
                .put("exact", format!("covered_records={}", covered.len()))
                .put("abs_err", ae)
                .put("cert_err", ce)
                .put("eps_n", format!("{eps_n:.2}"))
                .put("exact_in_cert", inside)
                .put("cert_le_eps_n", ce as f64 <= eps_n)
                .put("prof", prof(&x))
                .put("image_id", image_id(AGGR_GKM_ID))
                .put("root_variant", root_name)
                .put("root_construction", root.construction())
                .put("variants_agree", agree)
                .put("state_commit", hex(&native.state_commit));
            exec_cols(&mut r, &x, proved);
            r.print();
            if !eq {
                eprintln!("gk_matched: WARNING aggregation journal != native output");
            }
            if !agree {
                eprintln!("gk_matched: WARNING root variants / implementations disagree outside the root field");
            }
            if !inside {
                eprintln!("gk_matched: WARNING an exact rank lies outside zkSketch's decoder bounds (accuracy, not equivalence)");
            }
            if !ok {
                std::process::exit(1);
            }
        }
        "query" => {
            if flag("--emit-state") {
                die("--emit-state belongs to --mode aggr");
            }
            let do_prove = flag("--prove");
            let n = arg_u64("--epochs", 1) as usize;
            if n == 0 {
                die("--epochs must be >= 1");
            }
            need(n);
            let qname = arg_str("--query").unwrap_or_else(|| "rank".into());
            if qname != "rank" {
                die(&format!(
                    "--query {qname}: the matched GK port answers rank (zkSketch's GK decoder is a rank decoder); \
                     quantiles are ../gk's (textbook) only"
                ));
            }
            let value = arg_u64("--rank-value", 1 << 20);
            if value > VALUE_MASK as u64 {
                die("--rank-value must be a 21-bit value (< 2^21)");
            }
            let value = value as u32;
            let cfg = base_cfg;
            let (eps, links) = chain(&keys, n, m, cbs, cfg);
            let last = eps.last().unwrap();
            let input = GkmQueryInput { value, state_words: compact_words(&last.state), epoch_chain_links: links };
            let native = run_gkm_query(&input).suppress_if_low_support();
            let x = execute(&input, QUERIER_GKM_ELF, 0);
            let got: GkmQueryOutput = x.session.journal.decode().unwrap();
            let eq = got == native;
            // zkSketch's own estimator on zkSketch's own chain
            let (zlo, zhi) = last.zk_state.rank_interval(value);
            let qeq = last.zk_eq.is_ok() && (zlo, zhi) == (got.result.lo, got.result.hi) && last.zk_state.rank(value) == got.result.estimate;
            let mut vals: Vec<u32> = keys[..n * m].iter().map(|&k| k & VALUE_MASK).collect();
            vals.sort_unstable();
            let exact = vals.partition_point(|&v| v <= value) as u64;
            let rr = &got.result;
            let eps_n = vals.len() as f64 / cfg.s as f64;
            let cert = (rr.estimate - rr.lo).max(rr.hi - rr.estimate);
            let inside = rr.lo <= exact && exact <= rr.hi;
            let ok = eq && qeq;
            let proved =
                if do_prove && ok { Some(prove(&input, QUERIER_GKM_ELF, QUERIER_GKM_ID, &native)) } else { None };
            let sup = if got.suppressed { " SUPPRESSED" } else { "" };
            let mut r = Row::new();
            r.put("arm", if proved.is_some() { "proved" } else { "exec" })
                .put("mode", "query")
                .put("guest", "querier_gkm");
            common_cols(&mut r, &cfg, m, cbs);
            r.put("query", "rank")
                .put("epochs", n)
                .put("records", n * m)
                .put("n_total", last.state.n)
                .put("actives", actives(&last.state).len())
                .put("theta", last.state.n / cfg.s as u64)
                .put("state_commits", got.state_commits.len())
                .put("journal_eq_native", eq)
                .put("state_eq_zksketch", last.zk_eq.is_ok())
                .put("query_eq_zksketch", qeq)
                .put("result", format!("rank({value}) est={};lo={};hi={}{sup}", rr.estimate, rr.lo, rr.hi))
                .put("exact", format!("rank({value})={exact}"))
                .put("abs_err", rr.estimate.abs_diff(exact))
                .put("cert_err", cert)
                .put("eps_n", format!("{eps_n:.2}"))
                .put("exact_in_cert", inside)
                .put("cert_le_eps_n", cert as f64 <= eps_n)
                .put("image_id", image_id(QUERIER_GKM_ID));
            exec_cols(&mut r, &x, proved);
            r.print();
            if !eq {
                eprintln!("gk_matched: WARNING query journal != native output");
            }
            if !qeq {
                eprintln!("gk_matched: WARNING query bounds != zkSketch's rank_interval on its own chain");
            }
            if !inside {
                eprintln!("gk_matched: WARNING the exact rank lies outside zkSketch's decoder bounds (accuracy, not equivalence)");
            }
            if !ok {
                std::process::exit(1);
            }
        }
        "check" => {
            if flag("--prove") || flag("--emit-state") {
                die("--mode check always emits the state and never proves");
            }
            let k = arg_u64("--epochs", 2) as usize;
            if k == 0 {
                die("--epochs must be >= 1");
            }
            need(k);
            let (eps, links) = chain(&keys, k, m, cbs, base_cfg);
            let mut all_ok = true;
            for (e, ep) in eps.iter().enumerate() {
                // the query at n = e + 1 on the hot value (implementation-independent)
                let q = hot_value(&keys, (e + 1) * m);
                let qin = GkmQueryInput { value: q, state_words: compact_words(&ep.state), epoch_chain_links: links[..=e].to_vec() };
                let qnat = run_gkm_query(&qin).suppress_if_low_support();
                let qx = execute(&qin, QUERIER_GKM_ELF, 0);
                let qgot: GkmQueryOutput = qx.session.journal.decode().unwrap();
                let (zlo, zhi) = ep.zk_state.rank_interval(q);
                let qeq = qgot == qnat
                    && (zlo, zhi) == (qgot.result.lo, qgot.result.hi)
                    && ep.zk_state.rank(q) == qgot.result.estimate;
                for &i in &impls {
                    let cfg = GkmConfig { implementation: i, ..base_cfg };
                    let input = with_impl(&ep.input, i);
                    let (st, native) = process_gkm_aggr(&input, GkmRoot::None);
                    let st = padded(st);
                    let x = exec_aggr(GkmRoot::None, &input, true);
                    let got: (GkmRoot, GkmAggrOutput) = x.session.journal.decode().unwrap();
                    let eq = got == (GkmRoot::None, native.clone());
                    let cmp = match &x.emitted {
                        Some(w) => compare_state(&ep.zk_state, &padded(bm2::state_from_words(w))),
                        None => Err("guest emitted no state".into()),
                    };
                    // the journal's commitment is SHA-256 of zkSketch's own state (its
                    // compact words): the commitment's preimage is zkSketch's state
                    let com_eq = native.state_commit == gkm_state_commit(&to_port(&ep.zk_state));
                    let ok = eq && cmp.is_ok() && com_eq && qeq && st == ep.state;
                    if let Err(d) = &cmp {
                        eprintln!("gk_matched check: MISMATCH epoch {e} impl {}: {d}", i.name());
                    }
                    all_ok &= ok;
                    let mut r = Row::new();
                    r.put("arm", "check").put("mode", "check").put("guest", "aggr_gkm+querier_gkm");
                    common_cols(&mut r, &cfg, m, cbs);
                    r.put("query", "rank")
                        .put("epochs", e + 1)
                        .put("epoch_index", e)
                        .put("records", m)
                        .put("n_total", st.n)
                        .put("actives", actives(&st).len())
                        .put("theta", st.n / cfg.s as u64)
                        .put("state_commits", qgot.state_commits.len())
                        .put("journal_eq_native", eq)
                        .put("state_eq_zksketch", format!("{}(tuples)", cmp.is_ok() && com_eq))
                        .put("query_eq_zksketch", qeq)
                        .put(
                            "result",
                            format!(
                                "steps={};rank({q}) est={};lo={};hi={}",
                                native.steps, qgot.result.estimate, qgot.result.lo, qgot.result.hi
                            ),
                        )
                        .put("exact", format!("rank({q})={}", keys[..(e + 1) * m].iter().filter(|&&k| k & VALUE_MASK <= q).count()))
                        .put("prof", prof(&x))
                        .put("image_id", image_id(AGGR_GKM_ID))
                        .put("root_variant", "noroot")
                        .put("root_construction", "none")
                        .put("variants_agree", "-")
                        .put("state_commit", hex(&native.state_commit));
                    exec_cols(&mut r, &x, None);
                    r.print();
                }
            }
            if !all_ok {
                eprintln!("gk_matched check: FAILED (see MISMATCH lines)");
                std::process::exit(1);
            }
        }
        "certify" => {
            if flag("--prove") || flag("--emit-state") {
                die("--mode certify proves zkSketch's circuits, not the zkVM guests; it takes no --prove/--emit-state");
            }
            let k = arg_u64("--epochs", 2) as usize;
            if k == 0 {
                die("--epochs must be >= 1");
            }
            need(k);
            let hiding = match arg_str("--commit").as_deref() {
                None | Some("hiding") => true,
                Some("plain") => false,
                Some(o) => die(&format!("--commit {o}: expected hiding|plain")),
            };
            let seed = arg_u64("--seed", 1);
            let cfg = base_cfg;
            let (eps, links) = chain(&keys, k, m, cbs, cfg);
            let mut cert = certify::Certifier::new(&cfg, hiding, seed);
            let mut all_ok = true;
            for (e, ep) in eps.iter().enumerate() {
                let x = exec_aggr(GkmRoot::None, &ep.input, true);
                let got: (GkmRoot, GkmAggrOutput) = x.session.journal.decode().unwrap();
                let eq = got == (GkmRoot::None, ep.out.clone());
                let gstate = match &x.emitted {
                    Some(w) => padded(bm2::state_from_words(w)),
                    None => die("guest emitted no state"),
                };
                let q = hot_value(&keys, (e + 1) * m);
                let qin = GkmQueryInput { value: q, state_words: compact_words(&gstate), epoch_chain_links: links[..=e].to_vec() };
                let qx = execute(&qin, QUERIER_GKM_ELF, 0);
                let qgot: GkmQueryOutput = qx.session.journal.decode().unwrap();
                let c = cert.epoch(&keys, e, m, &gstate, q);
                let ok = eq && c.chain_ok && c.certified_eq && c.decode_answer == qgot.result.estimate;
                all_ok &= ok;
                eprintln!(
                    "gk_matched certify: epoch {e}: {} zkSketch leaves proved in {:.1} s (t = {}..{}), leaf chain ok {}, \
                     last leaf's Com(S) == Com(guest state) {}; decoder proof {:.1} s answer {} vs querier_gkm {}",
                    c.leaves, c.leaf_prove_s, e * c.leaves + 1, (e + 1) * c.leaves, c.chain_ok, c.certified_eq,
                    c.decode_s, c.decode_answer, qgot.result.estimate
                );
                let mut r = Row::new();
                r.put("arm", "certify").put("mode", "certify").put("guest", "aggr_gkm+querier_gkm");
                common_cols(&mut r, &cfg, m, cbs);
                r.put("query", "rank")
                    .put("epochs", e + 1)
                    .put("epoch_index", e)
                    .put("records", m)
                    .put("n_total", gstate.n)
                    .put("actives", actives(&gstate).len())
                    .put("theta", gstate.n / cfg.s as u64)
                    .put("journal_eq_native", eq)
                    .put("state_eq_zksketch", format!("{}(tuples)", compare_state(&ep.zk_state, &gstate).is_ok()))
                    .put("query_eq_zksketch", c.decode_answer == qgot.result.estimate)
                    .put("certified_eq", c.certified_eq && c.chain_ok)
                    .put(
                        "result",
                        format!(
                            "zks_leaves={};zks_commit={};zks_leaf_prove_s={:.1};zks_decode_answer={};rank({q}) est={};lo={};hi={}",
                            c.leaves, cert.mode_label, c.leaf_prove_s, c.decode_answer, qgot.result.estimate, qgot.result.lo,
                            qgot.result.hi
                        ),
                    )
                    .put("prof", prof(&x))
                    .put("image_id", image_id(AGGR_GKM_ID))
                    .put("root_variant", "noroot")
                    .put("root_construction", "none")
                    .put("variants_agree", "-")
                    .put("state_commit", hex(&ep.out.state_commit));
                exec_cols(&mut r, &x, None);
                r.print();
            }
            if !all_ok {
                eprintln!("gk_matched certify: FAILED");
                std::process::exit(1);
            }
        }
        o => die(&format!("--mode {o}: expected aggr|query|check|certify")),
    }
}

// ===========================================================================
// Native tests (no zkVM): the core against zkSketch's own code. `--release` keeps them
// fast:  cargo test --release --locked -p gk-matched-host
// A debug build runs them too: there zkSketch's apply_batch2 stops at its debug_assert!
// on a step that loses a record (a release build truncates silently), and `zk_step`
// counts either outcome as the loss.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use gk_matched_core::{apply_epoch, capacity_violation, commit_words, process_gkm_aggr_marked, Mark};

    fn aol() -> Vec<u32> {
        load_keys(&format!("{}/../../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR")))
    }
    fn cfg(cap: u32, ms: u32, i: GkmImpl) -> GkmConfig {
        GkmConfig { capacity: cap, m_sub: ms, s: 51, implementation: i }
    }
    /// One step of zkSketch's native chain, or None where the step loses a record: in a
    /// release build apply_batch2 truncates silently (active mass != n afterwards), in a
    /// debug build it panics at its debug_assert! on the dropped rows.
    fn zk_step(zk: &Gk2State, vals: &[u32]) -> Option<Gk2State> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| apply_batch2(zk, vals)))
            .ok()
            .filter(|s| zk_mass(s) == s.n)
    }

    /// Configs A (cap 384, 16 leaves of 128) and B (cap 768, 4 leaves of 512) plus the
    /// six-sketch default (cap 2048, one leaf of 2048): every epoch of every
    /// implementation equals zkSketch's apply_batch2 chain, tuple by tuple.
    #[test]
    fn chain_equals_zksketch_configs() {
        let keys = aol();
        for (cap, ms, epochs) in [(384u32, 128u32, 4usize), (768, 512, 4), (2048, 2048, 2), (64, 256, 3)] {
            for i in GkmImpl::ALL {
                let (eps, _) = chain(&keys, epochs, 2048, 8, cfg(cap, ms, i));
                for (e, ep) in eps.iter().enumerate() {
                    assert!(ep.zk_eq.is_ok(), "cap {cap} m_sub {ms} {} epoch {e}: {:?}", i.name(), ep.zk_eq);
                    assert_eq!(ep.out.steps as usize, 2048 / ms as usize);
                    assert_eq!(ep.out.state_commit, gkm_state_commit(&to_port(&ep.zk_state)));
                    assert!(capacity_violation(&ep.state).is_none());
                }
            }
        }
    }

    /// The carried state is checked: a tampered state, a wrong previous link, a missing
    /// state after genesis and a changed configuration are all refused (`fast` and `tuned`
    /// read the carried state differently: full and compact form).
    #[test]
    fn carried_state_is_bound() {
        for i in [GkmImpl::Fast, GkmImpl::Tuned] {
            carried_state_is_bound_for(i);
        }
    }
    fn carried_state_is_bound_for(i: GkmImpl) {
        let keys = aol();
        let (eps, _) = chain(&keys, 2, 2048, 8, cfg(384, 128, i));
        let good = eps[1].input.clone();
        assert!(std::panic::catch_unwind(|| process_gkm_aggr(&good, GkmRoot::None)).is_ok());
        let mut bad = good.clone();
        let w = &mut bad.carried.as_mut().unwrap().state_words;
        w[bm2::STATE_HDR_WORDS + 1] += 1; // g of row 0
        assert!(std::panic::catch_unwind(|| process_gkm_aggr(&bad, GkmRoot::None)).is_err(), "tampered state");
        let mut bad = good.clone();
        bad.carried.as_mut().unwrap().link_prev_hash[0] ^= 1;
        assert!(std::panic::catch_unwind(|| process_gkm_aggr(&bad, GkmRoot::None)).is_err(), "wrong previous link");
        let mut bad = good.clone();
        bad.carried = None;
        assert!(std::panic::catch_unwind(|| process_gkm_aggr(&bad, GkmRoot::None)).is_err(), "no state after genesis");
        let mut bad = good.clone();
        bad.config.capacity = 386;
        assert!(std::panic::catch_unwind(|| process_gkm_aggr(&bad, GkmRoot::None)).is_err(), "config mismatch");
        let mut bad = eps[0].input.clone();
        bad.prev_chain_hash[0] = 1;
        assert!(std::panic::catch_unwind(|| process_gkm_aggr(&bad, GkmRoot::None)).is_err(), "fake genesis");
    }

    /// A carried state that is correctly linked but is not what an honest epoch outputs is
    /// refused: rows out of (e, t) order (by the implementations that rely on the canonical
    /// form, `fast` and `tuned`; zkSketch's literal code re-sorts them) and an active mass
    /// other than n (by all four).
    #[test]
    fn linked_but_malformed_state_is_refused() {
        let keys = aol();
        let (eps, _) = chain(&keys, 2, 2048, 8, cfg(384, 128, GkmImpl::Tuned));
        let relink = |w: &[u32], i: GkmImpl| {
            let mut x = with_impl(&eps[1].input, i);
            let c = x.carried.as_mut().unwrap();
            x.prev_chain_hash = EpochChainLink::compute_final_hash(c.link_prev_hash, commit_words(w));
            c.state_words = w.to_vec();
            x
        };
        let w = eps[1].input.carried.as_ref().unwrap().state_words.clone();
        let (h, tw) = (bm2::STATE_HDR_WORDS, bm2::TUPLE_WORDS);
        let mut swapped = w.clone();
        for j in 0..tw {
            swapped.swap(h + j, h + tw + j);
        }
        let mut heavy = w.clone();
        heavy[h + 1] += 1; // g of row 0: active mass n + 1
        for i in GkmImpl::ALL {
            let x = relink(&w, i);
            assert!(std::panic::catch_unwind(|| process_gkm_aggr(&x, GkmRoot::None)).is_ok(), "{}: control", i.name());
            let x = relink(&heavy, i);
            assert!(std::panic::catch_unwind(|| process_gkm_aggr(&x, GkmRoot::None)).is_err(), "{}: mass != n", i.name());
        }
        for i in [GkmImpl::Fast, GkmImpl::Tuned] {
            let x = relink(&swapped, i);
            assert!(std::panic::catch_unwind(|| process_gkm_aggr(&x, GkmRoot::None)).is_err(), "{}: rows out of order", i.name());
        }
    }

    /// `tuned` against zkSketch's own apply_batch2 chain beyond the measured configurations:
    /// odd tables (zkSketch never pairs their last row), capacities at and below the
    /// overflow point, many repeated values, and the state carried between two epochs in
    /// compact and in full form. Wherever zkSketch's chain keeps every record, tuned's state
    /// equals it row for row; wherever zkSketch's chain loses one (see `zk_step`),
    /// tuned panics.
    #[test]
    fn tuned_matches_zksketch_at_the_edges() {
        let keys = aol();
        let aol_vals: Vec<u32> = keys[..4096].iter().map(|&k| k & VALUE_MASK).collect();
        let dup_vals: Vec<u32> = (0..4096u32).map(|i| (i * 7919) % 37).collect();
        let (mut kept, mut lost) = (0, 0);
        for vals in [&aol_vals, &dup_vals] {
            for (cap, ms) in [(16usize, 64usize), (31, 64), (33, 32), (48, 64), (63, 64), (64, 64), (95, 128), (128, 128), (200, 64), (385, 128), (384, 128)] {
                let p = GkbParams { capacity: cap, batch: ms, s: 51 };
                let mut zk = Gk2State::empty(p);
                let mut lossy = false;
                for c in vals.chunks(ms) {
                    match zk_step(&zk, c) {
                        Some(next) => zk = next,
                        None => {
                            lossy = true;
                            break;
                        }
                    }
                }
                let c = cfg(cap as u32, ms as u32, GkmImpl::Tuned);
                let whole = std::panic::catch_unwind(|| apply_epoch(&c, bm2::State::empty(c.params()), vals));
                // two epochs: the first two steps from the compact genesis, the rest from
                // that state, once compact and once padded to its full form
                let split = |full: bool| {
                    let (s1, _) = apply_epoch(&c, bm2::State { tuples: Vec::new(), params: c.params(), n: 0 }, &vals[..2 * ms]);
                    let s1 = if full { padded(s1) } else { s1 };
                    apply_epoch(&c, s1, &vals[2 * ms..]).0
                };
                if lossy {
                    lost += 1;
                    assert!(whole.is_err(), "cap {cap} m {ms}: zkSketch lost a record, tuned must panic");
                } else {
                    kept += 1;
                    let (st, steps) = whole.unwrap();
                    assert_eq!(steps as usize, vals.len().div_ceil(ms));
                    assert!(st.tuples.iter().all(|t| t.active == 1), "tuned returns the compact state");
                    assert_eq!(compare_state(&zk, &padded(st)), Ok(()), "cap {cap} m {ms}");
                    for full in [false, true] {
                        assert_eq!(compare_state(&zk, &padded(split(full))), Ok(()), "cap {cap} m {ms} split full={full}");
                    }
                }
            }
        }
        assert!(kept >= 4 && lost >= 4, "both outcomes covered: kept {kept}, lost {lost}");
    }

    /// The query opens the latest carried state against an unbroken chain: the honest links
    /// pass; a chain that restarts at the genesis hash (accepted by their
    /// verify_epoch_chain_integrity) and a state that is not the last link's are refused.
    #[test]
    fn query_needs_one_unbroken_chain() {
        let keys = aol();
        let (eps, links) = chain(&keys, 2, 2048, 8, cfg(384, 128, GkmImpl::Fast));
        let words = compact_words(&eps[1].state);
        let good = GkmQueryInput { value: 1 << 20, state_words: words.clone(), epoch_chain_links: links.clone() };
        assert!(std::panic::catch_unwind(|| run_gkm_query(&good)).is_ok());
        let restart = vec![links[0].clone(), EpochChainLink::new([0u8; 32], eps[1].out.state_commit)];
        let bad = GkmQueryInput { value: 1 << 20, state_words: words.clone(), epoch_chain_links: restart };
        assert!(std::panic::catch_unwind(|| run_gkm_query(&bad)).is_err(), "genesis restart");
        let stale = GkmQueryInput { value: 1 << 20, state_words: compact_words(&eps[0].state), epoch_chain_links: links };
        assert!(std::panic::catch_unwind(|| run_gkm_query(&stale)).is_err(), "not the last link's state");
    }

    /// A capacity that zkSketch's chain overflows is a hard error in the core (all
    /// implementations panic), never a truncated state.
    #[test]
    fn overflow_is_a_hard_error() {
        let keys = aol();
        let vals: Vec<u32> = keys[..2048].iter().map(|&k| k & VALUE_MASK).collect();
        // zkSketch's native chain loses records at capacity 16 (see zk_step)
        let p = GkbParams { capacity: 16, batch: 256, s: 51 };
        let mut zk = Gk2State::empty(p);
        let mut truncated = false;
        for c in vals.chunks(256) {
            match zk_step(&zk, &gk_vals_of(c)) {
                Some(next) => zk = next,
                None => {
                    truncated = true;
                    break;
                }
            }
        }
        assert!(truncated, "capacity 16 must overflow on AOL");
        for i in GkmImpl::ALL {
            let c = cfg(16, 256, i);
            let r = std::panic::catch_unwind(|| apply_epoch(&c, bm2::State::empty(c.params()), &vals));
            assert!(r.is_err(), "{}: overflow must panic", i.name());
        }
    }

    /// The query estimator is zkSketch's: gkm_rank == Gk2State::rank_interval / rank on
    /// every value of the domain prefix it summarises, at several epochs.
    #[test]
    fn rank_equals_zksketch_decoder() {
        let keys = aol();
        let (eps, _) = chain(&keys, 3, 2048, 8, cfg(384, 128, GkmImpl::Fast));
        for ep in &eps {
            let mut qs: Vec<u32> = ep.state.tuples.iter().filter(|t| t.active == 1).flat_map(|t| [t.e.saturating_sub(1), t.e, t.e + 1]).collect();
            qs.extend([0, 1, 1 << 20, VALUE_MASK]);
            // the query guest ranks over the active rows only; it must agree with the padded table
            let padded = gk_matched_core::from_compact_words(&compact_words(&ep.state));
            let act: Vec<bm2::Tuple> = ep.state.tuples.iter().copied().filter(|t| t.active == 1).collect();
            for q in qs {
                let (lo, hi, est) = gkm_rank(&ep.state, q);
                assert_eq!((lo, hi), ep.zk_state.rank_interval(q), "q={q}");
                assert_eq!(est, ep.zk_state.rank(q), "q={q}");
                assert_eq!(gk_matched_core::gkm_rank_rows(&act, q), (lo, hi, est), "active rows, q={q}");
                assert_eq!(gkm_rank(&padded, q), (lo, hi, est), "padded, q={q}");
            }
        }
    }

    /// Root variants and implementations agree on everything but the root; the marks fire
    /// once each, in order.
    #[test]
    fn variants_and_marks() {
        let keys = aol();
        let (eps, _) = chain(&keys, 2, 2048, 8, cfg(768, 512, GkmImpl::Fast));
        for ep in &eps {
            assert!(variants_agree(&ep.input));
            let mut seen = Vec::new();
            process_gkm_aggr_marked(&ep.input, GkmRoot::Buckets64, &mut |m: Mark| seen.push(m));
            assert_eq!(seen.len(), MARK_NAMES.len());
        }
    }
}
