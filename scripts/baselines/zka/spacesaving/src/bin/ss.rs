// SpaceSaving port on zk-Analytics' pipeline: runs aggr_ss / query_ss on AOL epochs, executor only unless --prove.
// Usage: ss --mode aggr|query --capacity S [--epochs N] [--query topk|estimate|estimate_merged] [--root R] [--prove]

#[path = "../reference.rs"]
mod reference;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aggregator_core::batch_chain_hash;
use reference::{absent_min_sum, exact_counts, exact_top, naive_merge, naive_point, NaiveSs};
use risc0_zkvm::{compute_image_id, default_executor, default_prover, ExecutorEnv, ProverOpts, SessionInfo};
use ss_core::{
    process_ss_aggr_root, process_ss_aggr_with_state, run_ss_query, ss_epoch_state_commit, ss_merge, BatchInput,
    EpochChainLink, Event, SsAggrInput, SsAggrOutput, SsEpochState, SsQuery, SsQueryInput, SsQueryOutput,
    SsQueryResult, SsRoot, KEY_BYTES_LEN, MIN_SUPPORT,
};
use ss_methods::{
    AGGR_SS_ELF, AGGR_SS_ID, AGGR_SS_PROF_ELF, AGGR_SS_PROF_ID, AGGR_SS_ROOTVAR_ELF, AGGR_SS_ROOTVAR_ID, QUERY_SS_ELF,
    QUERY_SS_ID, QUERY_SS_PROF_ELF, QUERY_SS_PROF_ID,
};

// MODELED_prove_s = segments x S_PER_SEG (computed, not measured), from the four CPU-proved CM guest runs
// in scripts/baselines/zka/README.md: S_PER_SEG is aggr_cm T=100, n=512 (661.3 s / 22 segments = 30.06 s)
// rounded; _lo/_hi use 29.73 and 30.79 s, the lowest and highest s/segment of the four.
const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] = &[
    "--mode", "--capacity", "--query", "--epochs", "--epoch-index", "--limit", "--keys", "--epoch-size",
    "--batch", "--point-rank", "--root", "--image-id-of",
];
const BOOL_FLAGS: &[&str] = &["--prove", "--header", "--profile"];

fn die(msg: &str) -> ! {
    eprintln!("ss: {msg}");
    std::process::exit(2);
}
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
            die(&format!("unknown argument '{s}' (value flags: {}; bool flags: {})",
                VALUE_FLAGS.join(" "), BOOL_FLAGS.join(" ")));
        }
    }
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
fn arg_usize(name: &str, default: usize) -> usize {
    match arg_str(name) {
        None => default,
        Some(v) => v.parse().unwrap_or_else(|_| die(&format!("{name}='{v}' is not a non-negative integer"))),
    }
}
fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

// ------------------------------------------------------------------- records
fn load_keys(path: &str) -> Vec<u32> {
    let b = std::fs::read(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    if b.len() % 4 != 0 {
        die(&format!("{path}: length {} is not a multiple of 4", b.len()));
    }
    b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

fn key_id(k: u32) -> [u8; KEY_BYTES_LEN] {
    Event::make_key_id(0, k as u64)
}
fn key_of(id: &[u8; KEY_BYTES_LEN]) -> u64 {
    Event::extract_key_index(id)
}

/// Source 0's SHA-256 batch chain, continued across epochs as their aggregator
/// host carries it (same as shipped.rs SourceChain).
struct SourceChain {
    tip: [u8; 32],
    next_seq: u64,
}
impl SourceChain {
    fn batches(&mut self, events: &[Event], cbs: usize) -> Vec<BatchInput> {
        let mut out = Vec::with_capacity(events.len().div_ceil(cbs));
        for chunk in events.chunks(cbs) {
            let evs = chunk.to_vec();
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
    (e * m..(e + 1) * m).map(|i| Event { ts: i as u32, key_id: key_id(keys[i]), value: 1 }).collect()
}

/// Aggregate epochs 0..n natively with ss-core, chaining epochs and source tips.
fn aggregate(keys: &[u32], n: usize, m: usize, cbs: usize, cap: u32) -> (Vec<(SsAggrInput, SsEpochState)>, Vec<EpochChainLink>) {
    let mut chain = SourceChain { tip: [0u8; 32], next_seq: 0 };
    let mut prev_chain_hash = [0u8; 32];
    let mut prev_tips: Vec<(u32, u64, [u8; 32])> = Vec::new();
    let mut outs = Vec::with_capacity(n);
    let mut links = Vec::with_capacity(n);
    for e in 0..n {
        let batches = chain.batches(&epoch_events(keys, e, m), cbs);
        let inp = SsAggrInput { capacity: cap, prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
        let (st, out) = process_ss_aggr_with_state(&inp);
        assert_eq!(ss_epoch_state_commit(&st), out.state_commit, "epoch {e}: commit mismatch");
        assert_eq!(out.n_events as usize, m);
        assert_eq!(out.epoch_chain_link.prev_chain_hash, prev_chain_hash);
        prev_chain_hash = out.epoch_chain_link.final_chain_hash;
        prev_tips = out.final_source_chain_tips.clone();
        links.push(out.epoch_chain_link.clone());
        outs.push((inp, st));
    }
    (outs, links)
}

/// Every epoch state must equal the independent linear-scan reference.
fn states_match_reference(keys: &[u32], states: &[SsEpochState], m: usize, cap: usize) -> bool {
    states.iter().enumerate().all(|(e, st)| {
        let mut r = NaiveSs::new(cap);
        for &k in &keys[e * m..(e + 1) * m] {
            r.update(&key_id(k));
        }
        r.entries_sorted() == st.entries && st.total_count == m as u64
    })
}

// ------------------------------------------------------------ r0vm peak RSS
/// Samples VmHWM of this process's own r0vm children (read-only; never signals
/// anything). The prover and executor each run in a child `r0vm` process.
struct RssWatch {
    stop: Arc<AtomicBool>,
    peak_kb: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}
impl RssWatch {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak_kb = Arc::new(AtomicU64::new(0));
        let (s, p) = (stop.clone(), peak_kb.clone());
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                for pid in own_children() {
                    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                    if comm.trim() != "r0vm" {
                        continue;
                    }
                    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                    if let Some(kb) = status
                        .lines()
                        .find(|l| l.starts_with("VmHWM:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse::<u64>().ok())
                    {
                        p.fetch_max(kb, Ordering::Relaxed);
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        RssWatch { stop, peak_kb, handle: Some(handle) }
    }
    fn finish(mut self) -> Option<f64> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let kb = self.peak_kb.load(Ordering::Relaxed);
        (kb > 0).then(|| kb as f64 / 1024.0)
    }
}
fn own_children() -> Vec<u32> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc/self/task") {
        for t in rd.flatten() {
            if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                v.extend(s.split_whitespace().filter_map(|x| x.parse::<u32>().ok()));
            }
        }
    }
    v
}

// ------------------------------------------------------ prover contention
/// Read-only contention monitor for proved runs. Once a second it counts the
/// r0vm processes on the box (any user) that are not this driver's own
/// children, and samples the 1-minute load average. It never signals anything.
struct BoxWatch {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<BoxStats>>,
}
#[derive(Default, Clone, Copy)]
struct BoxStats {
    samples: u32,
    with_other: u32,
    load_sum: f64,
    load_max: f64,
}
impl BoxWatch {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let handle = std::thread::spawn(move || {
            let mut st = BoxStats::default();
            loop {
                let own = own_children();
                let other = all_r0vm().into_iter().filter(|p| !own.contains(p)).count();
                let load = std::fs::read_to_string("/proc/loadavg")
                    .ok()
                    .and_then(|l| l.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()));
                st.samples += 1;
                if other > 0 {
                    st.with_other += 1;
                }
                if let Some(l) = load {
                    st.load_sum += l;
                    st.load_max = st.load_max.max(l);
                }
                for _ in 0..10 {
                    if s.load(Ordering::Relaxed) {
                        return st;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
        BoxWatch { stop, handle: Some(handle) }
    }
    fn finish(mut self) -> BoxStats {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().and_then(|h| h.join().ok()).unwrap_or_default()
    }
}
fn all_r0vm() -> Vec<u32> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) {
                if std::fs::read_to_string(format!("/proc/{pid}/comm")).map(|c| c.trim() == "r0vm").unwrap_or(false) {
                    v.push(pid);
                }
            }
        }
    }
    v
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
    rss_mb: Option<f64>,
    session: SessionInfo,
}

fn execute<T: serde::Serialize>(input: &T, elf: &[u8]) -> Exec {
    let input_bytes = risc0_zkvm::serde::to_vec(input).expect("serialize input").len() * 4;
    let env = ExecutorEnv::builder().write(input).unwrap().build().unwrap();
    let w = RssWatch::start();
    let t = Instant::now();
    let session = default_executor().execute(env, elf).expect("guest execution failed");
    let exec_s = t.elapsed().as_secs_f64();
    let rss_mb = w.finish();
    Exec {
        user_cycles: session.cycles(),
        padded_cycles: session.segments.iter().map(|s| 1u64 << s.po2).sum(),
        segments: session.segments.len(),
        max_po2: session.segments.iter().map(|s| s.po2).max().unwrap_or(0),
        exec_s,
        input_bytes,
        journal_bytes: session.journal.bytes.len(),
        rss_mb,
        session,
    }
}

struct Proved {
    prove_s: f64,
    verify_ms: f64,
    receipt_bytes: usize,
    rss_mb: Option<f64>,
    boxw: BoxStats,
}

/// Their shipped tier: ProverOpts::succinct(). Asserts the PROVED journal equals
/// the native output.
fn prove<T, O>(input: &T, elf: &[u8], id: [u32; 8], expect: &O) -> Proved
where
    T: serde::Serialize,
    O: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let env = ExecutorEnv::builder().write(input).unwrap().build().unwrap();
    let w = RssWatch::start();
    let bw = BoxWatch::start();
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct()).expect("prove failed");
    let prove_s = t.elapsed().as_secs_f64();
    let boxw = bw.finish();
    let rss_mb = w.finish();
    let receipt = info.receipt;
    // verify_ms = the best of 5 in-process calls (unchanged); every call, and a
    // bincode decode of the serialized receipt, go to stderr for the six-sketch
    // verify-protocol comparison (../README.md).
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
    let got: O = receipt.journal.decode().expect("decode proved journal");
    assert_eq!(&got, expect, "proved journal != native");
    Proved {
        prove_s,
        verify_ms: best,
        receipt_bytes: bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0),
        rss_mb,
        boxw,
    }
}

/// Phase deltas from a *_prof journal's (phase, cycle_count) marks. Percentages
/// are of (last mark - first mark): the cycles between the guest's first and
/// last env::cycle_count() call.
fn phases(marks: &[(String, u64)]) -> String {
    let first = marks.first().map(|m| m.1).unwrap_or(0);
    let total = marks.last().map(|m| m.1).unwrap_or(0).saturating_sub(first).max(1);
    marks
        .windows(2)
        .map(|w| {
            let d = w[1].1.saturating_sub(w[0].1);
            format!("{}={}({:.1}%)", w[1].0, d, 100.0 * d as f64 / total as f64)
        })
        .collect::<Vec<_>>()
        .join(";")
}

// ------------------------------------------------------------------ output
/// The `root_construction` label: SS's `buckets64` (its own `root` column keeps that name) is the
/// samples pattern with 64 buckets, which the other ports call `samples64`.
fn construction_label(root: &str) -> &str {
    if root == "buckets64" { "samples64" } else { root }
}

const HEADER: &str = "system,arm,mode,guest,family,query,root,capacity,epochs,epoch_index,epoch_records,records,batch,limit,point_rank,distinct_keys,state_entries,input_bytes,user_cycles,padded_cycles,segments,max_po2,exec_s,r0vm_peak_rss_mb,journal_bytes,state_commits,journal_eq_native,ref_eq,invariants_ok,result,exact,accuracy,phases,prove_s,verify_ms,receipt_bytes,s_per_segment,prove_r0vm_peak_rss_mb,prove_condition,prove_other_r0vm_samples,prove_load1_mean,prove_load1_max,MODELED_prove_s,MODELED_prove_s_lo,MODELED_prove_s_hi,model,image_id,root_variant,root_construction,variants_agree,state_commit";

#[derive(Default)]
struct Row {
    mode: &'static str,
    guest: &'static str,
    query: String,
    root: &'static str,
    /// six-sketch root variant (legacy|designed|noroot|buckets1024|perkey), "-" for queries
    root_variant: &'static str,
    variants_agree: String,
    state_commit: String,
    capacity: u32,
    epochs: usize,
    epoch_index: String,
    m: usize,
    records: usize,
    cbs: usize,
    limit: String,
    point_rank: String,
    distinct: usize,
    state_entries: usize,
    eq_native: bool,
    ref_eq: bool,
    invariants_ok: String,
    state_commits: usize,
    result: String,
    exact: String,
    accuracy: String,
    phases: String,
    image_id: [u32; 8],
}

fn fmt_opt(x: Option<f64>) -> String {
    x.map(|v| format!("{v:.1}")).unwrap_or_else(|| "NaN".into())
}

fn emit(r: Row, x: &Exec, p: Option<Proved>) {
    let (ps, vm, rb, sps, prss, cond, other, lmean, lmax) = match p {
        Some(p) => (
            format!("{:.3}", p.prove_s),
            format!("{:.3}", p.verify_ms),
            p.receipt_bytes.to_string(),
            format!("{:.3}", p.prove_s / x.segments.max(1) as f64),
            fmt_opt(p.rss_mb),
            if p.boxw.with_other == 0 { "clean" } else { "contended" }.to_string(),
            format!("{}/{}", p.boxw.with_other, p.boxw.samples),
            format!("{:.1}", p.boxw.load_sum / p.boxw.samples.max(1) as f64),
            format!("{:.1}", p.boxw.load_max),
        ),
        None => (
            "NaN".into(), "NaN".into(), "0".into(), "NaN".into(), "NaN".into(),
            "-".into(), "-".into(), "NaN".into(), "NaN".into(),
        ),
    };
    let seg = x.segments as f64;
    let clean = |s: &str| s.replace(',', " ");
    println!(
        "zka-port,ss,{},{},ss,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.3},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.1},{:.1},{:.1},MODELED=segments*{} s/seg (CM-guest CPU anchors; not measured),{},{},{},{},{}",
        r.mode, r.guest, r.query, r.root, r.capacity, r.epochs, r.epoch_index, r.m, r.records, r.cbs, r.limit,
        r.point_rank, r.distinct, r.state_entries, x.input_bytes, x.user_cycles, x.padded_cycles, x.segments,
        x.max_po2, x.exec_s, fmt_opt(x.rss_mb), x.journal_bytes, r.state_commits, r.eq_native, r.ref_eq,
        r.invariants_ok, clean(&r.result), clean(&r.exact), clean(&r.accuracy), clean(&r.phases), ps, vm, rb, sps,
        prss, cond, other, lmean, lmax, seg * S_PER_SEG, seg * S_PER_SEG_LO, seg * S_PER_SEG_HI, S_PER_SEG,
        risc0_zkvm::sha::Digest::from(r.image_id), r.root_variant, construction_label(r.root), r.variants_agree, r.state_commit,
    );
}

/// --root -> (root_variant name, None = legacy aggr_ss | Some(SsRoot of aggr_ss_rootvar)).
fn parse_root(v: &str) -> (&'static str, Option<SsRoot>) {
    match v {
        "legacy" => ("legacy", None),
        "designed" | "buckets64" => ("designed", Some(SsRoot::Buckets64)),
        "noroot" | "none" => ("noroot", Some(SsRoot::None)),
        "buckets1024" => ("buckets1024", Some(SsRoot::Buckets1024)),
        "perkey" => ("perkey", Some(SsRoot::PerKey)),
        o => die(&format!("--root {o}: expected legacy|designed|noroot|buckets1024|perkey (or buckets64|none)")),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fmt_items(items: &[ss_core::SsItem]) -> String {
    items.iter().map(|i| format!("{}:{}/e{}", key_of(&i.key_id), i.count, i.error)).collect::<Vec<_>>().join(";")
}
fn fmt_exact(v: &[(u32, u64)]) -> String {
    v.iter().map(|(k, c)| format!("{k}:{c}")).collect::<Vec<_>>().join(";")
}

// ------------------------------------------------------------------ main
fn main() {
    validate_args();
    if flag("--header") {
        println!("{HEADER}");
        return;
    }
    if let Some(path) = arg_str("--image-id-of") {
        let blob = std::fs::read(&path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
        let id = compute_image_id(&blob).unwrap_or_else(|e| die(&format!("{path}: not a combined guest image: {e}")));
        println!("{id}");
        return;
    }
    if let Ok(v) = std::env::var("RISC0_DEV_MODE") {
        if !v.is_empty() && v != "0" && v.to_ascii_lowercase() != "false" {
            die("RISC0_DEV_MODE is set; refusing (no dev-mode numbers are reported by this harness)");
        }
    }
    let mode = arg_str("--mode").unwrap_or_else(|| die("--mode aggr|query is required"));
    let cap = arg_usize("--capacity", 0);
    if cap == 0 || cap > u32::MAX as usize - 1 {
        die("--capacity S (>= 1) is required");
    }
    let keys_path = arg_str("--keys")
        .unwrap_or_else(|| format!("{}/../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR")));
    let m = arg_usize("--epoch-size", 16_384);
    let cbs = arg_usize("--batch", 8);
    let do_prove = flag("--prove");
    let profile = flag("--profile");
    if m == 0 || cbs == 0 {
        die("--epoch-size and --batch must be > 0");
    }
    if do_prove && profile {
        die("--prove and --profile are exclusive (the profiling twin is never proved)");
    }
    if arg_str("--root").is_some() && mode != "aggr" {
        die("--root applies to --mode aggr only (query guests read no root)");
    }
    let keys = load_keys(&keys_path);

    match mode.as_str() {
        "aggr" => {
            let idx = arg_usize("--epoch-index", 0);
            if (idx + 1) * m > keys.len() {
                die(&format!("epoch {idx} needs {} keys, {keys_path} has {}", (idx + 1) * m, keys.len()));
            }
            let (root_name, root_var) = arg_str("--root").map_or(("legacy", None), |v| parse_root(&v));
            if root_var.is_some() && profile {
                die("--profile runs aggr_ss_prof (the legacy headline root); it takes no --root other than legacy");
            }
            let (outs, _links) = aggregate(&keys, idx + 1, m, cbs, cap as u32);
            let (inp, st) = &outs[idx];
            let slice = &keys[idx * m..(idx + 1) * m];
            let counts = exact_counts(slice);
            let native: SsAggrOutput = match root_var {
                None => process_ss_aggr_with_state(inp).1,
                Some(r) => process_ss_aggr_root(inp, r),
            };
            // Every root construction run natively on the same input: same state and journal
            // except buckets_root (zero for None, non-zero otherwise).
            let headline = process_ss_aggr_with_state(inp);
            let blank = |o: &SsAggrOutput| SsAggrOutput { buckets_root: [0u8; 32], ..o.clone() };
            let agree = &headline.0 == st
                && [SsRoot::Buckets64, SsRoot::Buckets1024, SsRoot::PerKey, SsRoot::None].iter().all(|&r| {
                    let o = process_ss_aggr_root(inp, r);
                    blank(&o) == blank(&headline.1) && ((r == SsRoot::None) == (o.buckets_root == [0u8; 32]))
                })
                && process_ss_aggr_root(inp, SsRoot::HEADLINE) == headline.1;

            let (guest, x, eq, ph, image_id) = if let Some(r) = root_var {
                // The guest reads the SsRoot, then the input: a tuple serializes as the two in sequence.
                let x = execute(&(r, inp), AGGR_SS_ROOTVAR_ELF);
                let got: (SsRoot, SsAggrOutput) = x.session.journal.decode().unwrap();
                ("aggr_ss_rootvar", x, got.0 == r && got.1 == native, "-".into(), AGGR_SS_ROOTVAR_ID)
            } else if profile {
                let x = execute(inp, AGGR_SS_PROF_ELF);
                let (got, marks): (SsAggrOutput, Vec<(String, u64)>) = x.session.journal.decode().unwrap();
                let ph = phases(&marks);
                ("aggr_ss_prof", x, got == native, ph, AGGR_SS_PROF_ID)
            } else {
                let x = execute(inp, AGGR_SS_ELF);
                let got: SsAggrOutput = x.session.journal.decode().unwrap();
                ("aggr_ss", x, got == native, "-".into(), AGGR_SS_ID)
            };
            let p = do_prove.then(|| match root_var {
                None => prove(inp, AGGR_SS_ELF, AGGR_SS_ID, &native),
                Some(r) => prove(&(r, inp), AGGR_SS_ROOTVAR_ELF, AGGR_SS_ROOTVAR_ID, &(r, native.clone())),
            });

            // Independent reference + SpaceSaving invariants against exact counts.
            let ref_eq = states_match_reference(slice, std::slice::from_ref(st), m, cap);
            let n = m as u64;
            let sum: u64 = st.entries.iter().map(|e| e.count as u64).sum();
            let full = st.entries.len() == cap;
            let min_count = if full { st.entries.iter().map(|e| e.count).min().unwrap_or(0) } else { 0 };
            let mut inv = sum == n && st.total_count == n;
            let (mut exact_entries, mut max_over, mut err_sum) = (0usize, 0u64, 0u64);
            let mut monitored: HashMap<u64, ()> = HashMap::new();
            for e in &st.entries {
                let k = key_of(&e.key_id);
                monitored.insert(k, ());
                let f = *counts.get(&(k as u32)).unwrap_or(&0);
                let (c, er) = (e.count as u64, e.error as u64);
                // f <= count, count - error <= f, count - f <= N/s; error <= min counter
                // (min is non-decreasing), and no error at all if never full.
                inv &= c >= f && c - er <= f && (c - f) * cap as u64 <= n;
                inv &= if full { er <= min_count as u64 } else { er == 0 };
                if c == f {
                    exact_entries += 1;
                }
                max_over = max_over.max(c - f);
                err_sum += er;
            }
            if full {
                // unmonitored keys: f <= min counter
                inv &= counts.iter().all(|(k, &f)| monitored.contains_key(&(*k as u64)) || f <= min_count as u64);
            }
            let top = exact_top(&counts, 10);
            let mut ss_top: Vec<&ss_core::SsEntry> = st.entries.iter().collect();
            ss_top.sort_by(|a, b| b.count.cmp(&a.count).then(a.key_id.cmp(&b.key_id)));
            let f10 = top.last().map(|t| t.1).unwrap_or(0);
            let rec = ss_top.iter().take(10).filter(|e| *counts.get(&(key_of(&e.key_id) as u32)).unwrap_or(&0) >= f10).count();
            if !eq {
                eprintln!("ss: WARNING aggregation journal != native output");
            }
            if !agree {
                eprintln!("ss: WARNING root variants disagree outside the root field");
            }
            emit(
                Row {
                    mode: "aggr",
                    guest,
                    query: "-".into(),
                    root: root_var.unwrap_or(SsRoot::HEADLINE).name(),
                    root_variant: root_name,
                    variants_agree: agree.to_string(),
                    state_commit: hex(&native.state_commit),
                    capacity: cap as u32,
                    epochs: 1,
                    epoch_index: idx.to_string(),
                    m,
                    records: m,
                    cbs,
                    limit: "-".into(),
                    point_rank: "-".into(),
                    distinct: counts.len(),
                    state_entries: st.entries.len(),
                    eq_native: eq,
                    ref_eq,
                    invariants_ok: inv.to_string(),
                    state_commits: 1,
                    result: format!("entries={} full={} min_count={}", st.entries.len(), full, min_count),
                    exact: format!("distinct={} top10={}", counts.len(), fmt_exact(&top)),
                    accuracy: format!(
                        "exact_entries={}/{} max_overcount={} sum_error={} N/s={:.2} top10_recall={}/10",
                        exact_entries, st.entries.len(), max_over, err_sum, n as f64 / cap as f64, rec
                    ),
                    phases: ph,
                    image_id,
                },
                &x,
                p,
            );
            if !eq || !agree {
                std::process::exit(1);
            }
        }
        "query" => {
            let n = arg_usize("--epochs", 1);
            if n == 0 || n * m > keys.len() {
                die(&format!("--epochs {n} needs {} keys, {keys_path} has {}", n * m, keys.len()));
            }
            let limit = arg_usize("--limit", 10);
            if limit == 0 || limit > u16::MAX as usize {
                die("--limit must be in 1..=65535");
            }
            let q = arg_str("--query").unwrap_or_else(|| die("--query topk|estimate|estimate_merged is required"));
            let rank = arg_usize("--point-rank", 1);
            let (outs, links) = aggregate(&keys, n, m, cbs, cap as u32);
            let prefix = &keys[..n * m];
            let counts = exact_counts(prefix);
            let states: Vec<SsEpochState> = outs.into_iter().map(|(_, s)| s).collect();
            let entries: usize = states.iter().map(|s| s.entries.len()).sum();
            let ref_states = states_match_reference(prefix, &states, m, cap);
            let merged = ss_merge(&states, cap);
            let ref_merge = naive_merge(&states, cap) == merged;

            let (query, qname, point_rank, exact_str) = match q.as_str() {
                "topk" => (SsQuery::Topk { limit: limit as u16 }, "topk", "-".to_string(),
                    format!("top={}", fmt_exact(&exact_top(&counts, limit)))),
                "estimate" | "estimate_merged" => {
                    if rank == 0 || rank > counts.len() {
                        die(&format!("--point-rank must be in 1..={}", counts.len()));
                    }
                    let (k, c) = exact_top(&counts, rank)[rank - 1];
                    let key = key_id(k);
                    let (query, name) = if q == "estimate" {
                        (SsQuery::Estimate { key }, "estimate")
                    } else {
                        (SsQuery::EstimateMerged { key }, "estimate_merged")
                    };
                    (query, name, rank.to_string(), format!("key={k} exact={c}"))
                }
                o => die(&format!("--query {o}: expected topk|estimate|estimate_merged")),
            };
            let input = SsQueryInput { query, epoch_states: states, epoch_chain_links: links };
            let native: SsQueryOutput = run_ss_query(&input).suppress_if_low_support();

            let (guest, x, got, ph, image_id) = if profile {
                let x = execute(&input, QUERY_SS_PROF_ELF);
                let (got, marks): (SsQueryOutput, Vec<(String, u64)>) = x.session.journal.decode().unwrap();
                let ph = phases(&marks);
                ("query_ss_prof", x, got, ph, QUERY_SS_PROF_ID)
            } else {
                let x = execute(&input, QUERY_SS_ELF);
                let got: SsQueryOutput = x.session.journal.decode().unwrap();
                ("query_ss", x, got, "-".into(), QUERY_SS_ID)
            };
            let eq = got == native;
            let p = do_prove.then(|| prove(&input, QUERY_SS_ELF, QUERY_SS_ID, &native));

            // The journal answer must equal the answer computed by the independent
            // references (naive_merge for topk / estimate_merged, a per-epoch binary
            // search for estimate), after their low-support suppression rule.
            let total_n = (n * m) as u64;
            let ref_answer = match &input.query {
                SsQuery::Topk { limit } => {
                    let want = &merged[..(*limit as usize).min(merged.len())];
                    let suppress = total_n < MIN_SUPPORT;
                    got.suppressed == suppress
                        && matches!(&got.result, SsQueryResult::Topk { items }
                            if (suppress && items.is_empty()) || (!suppress && items[..] == want[..]))
                }
                SsQuery::Estimate { key } | SsQuery::EstimateMerged { key } => {
                    let (c, e, mon) = if matches!(input.query, SsQuery::Estimate { .. }) {
                        naive_point(&input.epoch_states, key)
                    } else {
                        merged.iter().find(|i| i.key_id == *key).map(|i| (i.count, i.error, true)).unwrap_or((0, 0, false))
                    };
                    let suppress = c < MIN_SUPPORT;
                    let (c, e, mon) = if suppress { (0, 0, false) } else { (c, e, mon) };
                    got.suppressed == suppress
                        && matches!(&got.result, SsQueryResult::Estimate { key_id, count, error, monitored }
                            if key_id == key && *count == c && *error == e && *monitored == mon)
                }
            };

            // Bound check vs exact counts. For any key, summed over the epochs that
            // monitor it: count - error <= f <= count + slack, slack = the minimum
            // counters of the full epochs that do not monitor it (absent_min_sum).
            let bound_ok = |kid: &[u8; KEY_BYTES_LEN], count: u64, error: u64, f: u64| {
                count.saturating_sub(error) <= f && f <= count + absent_min_sum(&input.epoch_states, kid)
            };
            let (result, accuracy) = match &got.result {
                SsQueryResult::Topk { items } => {
                    let top = exact_top(&counts, limit);
                    let fk = top.last().map(|t| t.1).unwrap_or(0);
                    let f = |i: &ss_core::SsItem| *counts.get(&(key_of(&i.key_id) as u32)).unwrap_or(&0);
                    let recall = items.iter().filter(|i| f(i) >= fk).count();
                    let max_abs = items.iter().map(|i| (i.count as i64 - f(i) as i64).unsigned_abs()).max().unwrap_or(0);
                    let max_rel = items
                        .iter()
                        .map(|i| (i.count as f64 - f(i) as f64).abs() / (f(i).max(1) as f64))
                        .fold(0.0f64, f64::max);
                    let within = items.iter().filter(|i| i.count >= f(i) && i.count - i.error <= f(i)).count();
                    let bounded = items.iter().filter(|i| bound_ok(&i.key_id, i.count, i.error, f(i))).count();
                    let order_eq = items.iter().map(|i| key_of(&i.key_id) as u32).collect::<Vec<_>>()
                        == top.iter().map(|t| t.0).collect::<Vec<_>>();
                    (
                        format!("top={}{}", fmt_items(items), if got.suppressed { " SUPPRESSED" } else { "" }),
                        format!(
                            "recall@{limit}={recall}/{limit} key_order_eq={order_eq} max_abs_err={max_abs} max_rel_err={max_rel:.4} in_[c-e,c]={within}/{} in_[c-e,c+slack]={bounded}/{} merged_entries={}",
                            items.len(), items.len(), merged.len()
                        ),
                    )
                }
                SsQueryResult::Estimate { key_id: kid, count, error, monitored } => {
                    let fx = *counts.get(&(key_of(kid) as u32)).unwrap_or(&0);
                    let slack = absent_min_sum(&input.epoch_states, kid);
                    let bound = if got.suppressed || !monitored {
                        "n/a".to_string()
                    } else {
                        bound_ok(kid, *count, *error, fx).to_string()
                    };
                    (
                        format!("key={} count={count} error={error} monitored={monitored}{}", key_of(kid),
                            if got.suppressed { " SUPPRESSED" } else { "" }),
                        format!(
                            "abs_err={} rel_err={:.4} in_[c-e,c]={} slack={slack} in_[c-e,c+slack]={bound} {}",
                            (*count as i64 - fx as i64).unsigned_abs(),
                            (*count as f64 - fx as f64).abs() / fx.max(1) as f64,
                            *count >= fx && count.saturating_sub(*error) <= fx,
                            if qname == "estimate" { format!("scanned_entries={entries}") } else { format!("merged_entries={}", merged.len()) }
                        ),
                    )
                }
            };
            if !eq {
                eprintln!("ss: WARNING query journal != native output");
            }
            emit(
                Row {
                    mode: "query",
                    guest,
                    query: qname.into(),
                    root: "-",
                    root_variant: "-",
                    variants_agree: "-".into(),
                    state_commit: "-".into(),
                    capacity: cap as u32,
                    epochs: n,
                    epoch_index: "-".into(),
                    m,
                    records: n * m,
                    cbs,
                    limit: if qname == "topk" { limit.to_string() } else { "-".into() },
                    point_rank,
                    distinct: counts.len(),
                    state_entries: entries,
                    eq_native: eq,
                    ref_eq: ref_states && ref_merge && ref_answer,
                    invariants_ok: "-".into(),
                    state_commits: got.state_commits.len(),
                    result,
                    exact: exact_str,
                    accuracy,
                    phases: ph,
                    image_id,
                },
                &x,
                p,
            );
        }
        o => die(&format!("--mode {o}: expected aggr|query")),
    }
}

