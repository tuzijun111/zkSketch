// KMV / bottom-k baseline in zk-Analytics' architecture (ours †): host driver.
//
// Patterned on ../../hll/host/src/main.rs (itself on ../../cyc/src/bin/shipped.rs); the
// prove-time RSS / contention sampler follows ../../gk/host/src/main.rs. The epochs,
// the source batch hash chain and the epoch chain are built exactly as there:
//   records  data/aol.keys (flat little-endian u32). Epoch e = keys [e*m, (e+1)*m),
//            m = --epoch-size (default 2,048: the planned zkSketch-vs-zk-Analytics
//            configuration, 8 epochs/batches of 2,048 records).
//   key_id   Event::make_key_id(0, key)  (zkvm-common/src/lib.rs:76, as shipped.rs)
//   value    1 (ignored by KMV);  ts = global record index
//   batches  one source (id 0), stream order, --batch records per batch (default 8, their
//            --commit-batch-size default); SHA-256 batch chain continued across epochs
//            (prev_source_chain_tips carried, source_batch_seq continues); epoch e's
//            prev_chain_hash = epoch e-1's final_chain_hash.
//
// Modes (every guest run is EXECUTED; with --prove it is also PROVED):
//   --mode aggr  [--epoch-index i]     the kmv_aggr guest on epoch i (earlier epochs are
//                                      aggregated natively only to carry the chain tips)
//   --mode query --epochs n            aggregate epochs 0..n natively, then the kmv_query
//                                      guest over the n epoch states
//   --mode exec  --epochs N [--query-at 1,2,4,8]
//                                      the whole per-epoch pipeline: kmv_aggr on every
//                                      epoch 0..N-1 in order, each epoch's chain hash and
//                                      source tips taken from the PREVIOUS GUEST JOURNAL
//                                      (as their aggregator host carries them), and after
//                                      epoch n-1 the kmv_query guest over epochs 0..n for
//                                      every n in --query-at (default N)
//   --prove      ProverOpts::succinct() (their shipped tier), CPU r0vm; the proved
//                journal is asserted equal to the native output; records prove_s,
//                verify_ms (best of 5), receipt bytes, the r0vm peak RSS and foreign-r0vm
//                contention during the prove
//
// Checks on every row (the driver exits 1 when one fails; the row is still printed):
//   journal_eq_native  the guest journal equals the same core function run natively
//   ref_check          an independent host reference (own FNV-1a + splitmix64 code; every
//                      distinct hash of the covered keys, sorted, first k) equals the
//                      guest's epoch state (aggr) / merged set (query), and the f64
//                      estimator (k-1) / (v_k / 2^64) agrees with the integer answer
//                      within 1
//   accuracy           exact = distinct keys of the covered records; rel_err against it;
//                      std_err = 1/sqrt(k-2) (KMV's relative standard error);
//                      accuracy_ok = (answer == exact) on the exact branch (fewer than k
//                      distinct hashes), |rel_err| <= 5 std_err on the estimator branch
//
// Usage:
//   kmv --header
//   kmv --mode aggr  [--epoch-index 0] [common] [--prove]
//   kmv --mode query --epochs N [common] [--prove]
//   kmv --mode exec  --epochs N [--query-at 1,2,4,8] [common] [--prove]
//   common: [--epoch-size 2048] [--batch 8] [--keys PATH]

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, SessionInfo};
use zka_kmv_core::{
    batch_chain_hash, kmv_epoch_state_commit, kmv_estimate, merge_bottom_k, process_kmv_aggr_with_state,
    run_kmv_query, BatchInput, EpochChainLink, KmvAggrInput, KmvAggrOutput, KmvEpochState, KmvQuery,
    KmvQueryInput, KmvQueryOutput, KmvQueryResult, KMV_K, KMV_SEED,
};
use zka_kmv_methods::{KMV_AGGR_ELF, KMV_AGGR_ID, KMV_QUERY_ELF, KMV_QUERY_ID};
use zkvm_common::Event;

/// MODELED prove time: segments x s/segment. Central value and envelope are the four
/// CPU CM prove anchors in ../README.md ("Modeled prove time and the anchors behind it").
const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] = &["--mode", "--epochs", "--epoch-index", "--keys", "--epoch-size", "--batch", "--query-at"];
const BOOL_FLAGS: &[&str] = &["--prove", "--header"];

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
fn die(msg: &str) -> ! {
    eprintln!("kmv: {msg}");
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
fn arg_usize(name: &str, default: usize) -> usize {
    match arg_str(name) {
        None => default,
        Some(v) => v.parse().unwrap_or_else(|_| die(&format!("{name}='{v}' is not a non-negative integer"))),
    }
}
fn arg_list(name: &str) -> Option<Vec<usize>> {
    arg_str(name).map(|v| {
        v.split(',')
            .map(|s| s.trim().parse().unwrap_or_else(|_| die(&format!("{name}: '{s}' is not an integer"))))
            .collect()
    })
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

/// Source 0's SHA-256 batch chain, continued across epochs (as in shipped.rs).
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
    (e * m..(e + 1) * m)
        .map(|i| Event { ts: i as u32, key_id: Event::make_key_id(0, keys[i] as u64), value: 1 })
        .collect()
}

// ----------------------------------------------------- independent reference
/// The KMV hash written out here (FNV-1a over the 15-byte key_id, then the seeded
/// splitmix64 finaliser), not the core's key_to_u64 / kmv_hash64.
fn ref_hash(key: u32) -> u64 {
    let id = Event::make_key_id(0, key as u64);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in id {
        h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    let s = KMV_SEED as u64;
    let mut x = h ^ (s << 32 | s);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}
/// Every distinct hash of the keys, sorted, first k.
fn ref_bottom_k(keys: &[u32]) -> Vec<u64> {
    let mut h: Vec<u64> = keys.iter().map(|&k| ref_hash(k)).collect();
    h.sort_unstable();
    h.dedup();
    h.truncate(KMV_K);
    h
}
/// "ok" iff the guest's set equals the reference bottom-k and the f64 estimator agrees.
fn ref_check(values: &[u64], keys: &[u32], answer: u64) -> String {
    let r = ref_bottom_k(keys);
    if r != values {
        let diff = r.iter().zip(values).filter(|(a, b)| a != b).count() + r.len().abs_diff(values.len());
        return format!("FAIL(bottom-k differs at {diff})");
    }
    let e = if r.len() < KMV_K { r.len() as f64 } else { (KMV_K - 1) as f64 / (r[KMV_K - 1] as f64 / 2f64.powi(64)) };
    if (e - answer as f64).abs() <= 1.0 + 1e-9 * e { "ok".into() } else { format!("FAIL(ref_estimate={e:.3})") }
}


// --------------------------------------------- r0vm RSS / contention sampler
// Read-only /proc sampling, as ../../gk/host/src/main.rs: the r0vm executor/prover runs
// as a child of this driver; nothing is ever signalled.
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
fn vm_hwm_kb(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.to_string()))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

/// Busy clock ticks of the whole box (all CPUs), first line of /proc/stat:
/// user + nice + system + irq + softirq + steal.
fn box_busy_ticks() -> u64 {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines().next().map(|l| {
                let f: Vec<u64> = l.split_whitespace().skip(1).filter_map(|v| v.parse().ok()).collect();
                [0usize, 1, 2, 5, 6, 7].iter().filter_map(|&i| f.get(i)).sum()
            })
        })
        .unwrap_or(0)
}

/// What else ran on the box while a guest ran (foreign = not this driver or a process
/// descended from it).
#[derive(Default)]
struct Contention {
    foreign_pids: usize,
    foreign_max: usize,
    foreign_samples: usize,
    samples: usize,
    /// CPU seconds burned by foreign r0vm processes (the GK driver's measure)
    foreign_cpu_s: f64,
    /// average CPU cores busy with ANY foreign process over the window: box busy ticks
    /// minus this driver's and its descendants' ticks, divided by the wall time
    /// (approximate: a descendant's last 100 ms before it exits may count as foreign)
    other_cores_avg: f64,
    load1_max: f64,
}
/// A proved row is labelled proved_contended when foreign r0vm processes burned at
/// least this many CPU seconds during the prove (the GK driver's rule) ...
const CONTENDED_CPU_S: f64 = 10.0;
/// ... or when foreign processes of any kind kept this many cores busy on average
/// (an idle shared box here shows well under one core).
const CONTENDED_CORES: f64 = 4.0;
impl Contention {
    fn contended(&self) -> bool {
        self.foreign_cpu_s >= CONTENDED_CPU_S || self.other_cores_avg >= CONTENDED_CORES
    }
    fn csv(&self) -> String {
        if self.foreign_pids > 0 {
            format!(
                "foreign_r0vm={};foreign_max={};foreign_samples={}/{};foreign_cpu_s={:.1};other_cores_avg={:.1};load1_max={:.1}",
                self.foreign_pids, self.foreign_max, self.foreign_samples, self.samples, self.foreign_cpu_s,
                self.other_cores_avg, self.load1_max
            )
        } else {
            format!("none;samples={};other_cores_avg={:.1};load1_max={:.1}", self.samples, self.other_cores_avg, self.load1_max)
        }
    }
}

struct Sampler {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<(u64, Contention)>,
}
impl Sampler {
    fn start() -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let me = std::process::id();
        let handle = std::thread::spawn(move || {
            let mut peak = 0u64;
            let mut ct = Contention::default();
            let mut foreign: std::collections::HashMap<u32, (u64, u64)> = std::collections::HashMap::new();
            // our descendants: pid -> (ticks at window start, last ticks seen); a process
            // first seen after the first sample started inside the window (base 0)
            let mut mine_ticks: std::collections::HashMap<u32, (u64, u64)> = std::collections::HashMap::new();
            let (t0, busy0, self0) = (Instant::now(), box_busy_ticks(), cpu_ticks(me).unwrap_or(0));
            let mut first = true;
            loop {
                let mine = descendants(me);
                for &c in &mine {
                    peak = peak.max(vm_hwm_kb(c));
                    if let Some(t) = cpu_ticks(c) {
                        let base = if first { t } else { 0 };
                        mine_ticks.entry(c).and_modify(|e| e.1 = t).or_insert((base, t));
                    }
                }
                first = false;
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
                    // clock ticks to seconds: USER_HZ is 100 on Linux
                    ct.foreign_pids = foreign.len();
                    ct.foreign_cpu_s = foreign.values().map(|(a, b)| (b - a) as f64 / 100.0).sum();
                    let ours: u64 = mine_ticks.values().map(|(a, b)| b - a).sum::<u64>()
                        + cpu_ticks(me).unwrap_or(self0).saturating_sub(self0);
                    let other = box_busy_ticks().saturating_sub(busy0).saturating_sub(ours) as f64 / 100.0;
                    ct.other_cores_avg = other / t0.elapsed().as_secs_f64().max(1e-3);
                    return (peak, ct);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Sampler { stop, handle }
    }
    /// (peak VmHWM of our r0vm descendants in MB, or NaN if none was sampled; contention)
    fn finish(self) -> (f64, Contention) {
        self.stop.store(true, Ordering::Relaxed);
        let (kb, ct) = self.handle.join().unwrap_or((0, Contention::default()));
        (if kb == 0 { f64::NAN } else { kb as f64 / 1024.0 }, ct)
    }
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
    session: SessionInfo,
}

fn execute<T: serde::Serialize>(input: &T, elf: &[u8]) -> Exec {
    let input_bytes = risc0_zkvm::serde::to_vec(input).expect("serialize input").len() * 4;
    let mut out: Vec<u8> = Vec::new();
    let env = ExecutorEnv::builder().write(input).unwrap().stdout(&mut out).build().unwrap();
    let t = Instant::now();
    let session = default_executor().execute(env, elf).expect("guest execution failed");
    let exec_s = t.elapsed().as_secs_f64();
    let marks = out.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    Exec {
        user_cycles: session.cycles(),
        padded_cycles: session.segments.iter().map(|s| 1u64 << s.po2).sum(),
        segments: session.segments.len(),
        max_po2: session.segments.iter().map(|s| s.po2).max().unwrap_or(0),
        exec_s,
        input_bytes,
        journal_bytes: session.journal.bytes.len(),
        marks,
        session,
    }
}

/// Phase split from the guest's cycle_count marks (start, read, one per phase, journal).
/// cycle_count reports user cycles, so pre + all phases + post = user_cycles.
fn prof(x: &Exec, names: &[&str]) -> String {
    let m = &x.marks;
    let k = names.len();
    if m.len() != k + 3 {
        return format!("marks={}", m.len());
    }
    let mut s = format!("pre={};read={}", m[0], m[1] - m[0]);
    for (i, n) in names.iter().enumerate() {
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
    paging_cycles: u64,
    rss_mb: f64,
    contention: Contention,
}

/// --prove: succinct receipt (their ProverOpts::succinct()), journal checked against native.
fn prove<T: serde::Serialize, J: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
    input: &T, elf: &[u8], id: [u32; 8], expect: &J,
) -> Proved {
    let mut sink: Vec<u8> = Vec::new();
    let env = ExecutorEnv::builder().write(input).unwrap().stdout(&mut sink).build().unwrap();
    let s = Sampler::start();
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct()).expect("prove failed");
    let prove_s = t.elapsed().as_secs_f64();
    let (rss_mb, contention) = s.finish();
    let receipt = info.receipt;
    assert!(receipt.inner.succinct().is_ok(), "expected a succinct receipt");
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t2 = Instant::now();
        receipt.verify(id).expect("verify failed");
        best = best.min(t2.elapsed().as_secs_f64() * 1000.0);
    }
    let got: J = receipt.journal.decode().expect("decode proved journal");
    assert_eq!(&got, expect, "proved journal != native");
    eprintln!(
        "kmv: proved in {prove_s:.1} s, {} segments, total_cycles={} user_cycles={} paging={}; r0vm peak RSS {rss_mb:.1} MB; contention {}",
        info.stats.segments, info.stats.total_cycles, info.stats.user_cycles, info.stats.paging_cycles, contention.csv()
    );
    Proved {
        prove_s,
        verify_ms: best,
        receipt_bytes: bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0),
        segments: info.stats.segments,
        total_cycles: info.stats.total_cycles,
        user_cycles: info.stats.user_cycles,
        paging_cycles: info.stats.paging_cycles,
        rss_mb,
        contention,
    }
}

fn image_id_hex(id: [u32; 8]) -> String {
    id.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

// ----------------------------------------------------------------------- rows

// ----------------------------------------------------------------------- rows
const COLS: &[&str] = &[
    "system", "arm", "family", "mode", "step", "guest", "query", "kmv_k", "epochs", "epoch_index", "epoch_records",
    "records", "batch", "hash", "distinct_keys", "input_bytes", "user_cycles", "padded_cycles", "segments",
    "max_po2", "cycles_per_record", "exec_s", "journal_bytes", "state_commits", "journal_eq_native", "ref_check",
    "answer", "exact", "rel_err", "std_err", "estimator", "kept", "v_k", "support", "suppressed", "accuracy_ok",
    "prof", "prove_s", "verify_ms", "receipt_bytes", "s_per_segment", "prove_segments",
    "prove_total_cycles", "prove_user_cycles", "prove_paging_cycles", "prove_r0vm_peak_rss_mb", "contention",
    "MODELED_prove_s", "MODELED_prove_s_lo", "MODELED_prove_s_hi", "model", "image_id",
];

/// One CSV row; `emit` checks the columns arrive in exactly the COLS order.
struct Row(Vec<(&'static str, String)>);
impl Row {
    fn new() -> Row {
        Row(Vec::with_capacity(COLS.len()))
    }
    fn put(&mut self, name: &'static str, v: impl std::fmt::Display) -> &mut Row {
        self.0.push((name, v.to_string()));
        self
    }
    fn emit(&self) {
        let names: Vec<&str> = self.0.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, COLS, "row columns out of order");
        let vals: Vec<&str> = self.0.iter().map(|(_, v)| v.as_str()).collect();
        assert!(vals.iter().all(|v| !v.contains(',')), "comma in a value: {vals:?}");
        println!("{}", vals.join(","));
    }
}

struct Ctx {
    mode: String,
    m: usize,
    cbs: usize,
    do_prove: bool,
    fails: usize,
}

#[allow(clippy::too_many_arguments)]
fn common_cols(
    r: &mut Row, ctx: &Ctx, arm: &str, step: &str, guest: &str, query: &str, epochs: usize, epoch_index: String,
    records: usize, distinct: usize, x: &Exec,
) {
    r.put("system", "zka-arch")
        .put("arm", arm)
        .put("family", "kmv")
        .put("mode", &ctx.mode)
        .put("step", step)
        .put("guest", guest)
        .put("query", query)
        .put("kmv_k", KMV_K)
        .put("epochs", epochs)
        .put("epoch_index", epoch_index)
        .put("epoch_records", ctx.m)
        .put("records", records)
        .put("batch", ctx.cbs)
        .put("hash", "fnv1a+splitmix64")
        .put("distinct_keys", distinct)
        .put("input_bytes", x.input_bytes)
        .put("user_cycles", x.user_cycles)
        .put("padded_cycles", x.padded_cycles)
        .put("segments", x.segments)
        .put("max_po2", x.max_po2)
        .put("cycles_per_record", format!("{:.1}", x.user_cycles as f64 / records as f64))
        .put("exec_s", format!("{:.3}", x.exec_s))
        .put("journal_bytes", x.journal_bytes);
}

/// answer .. accuracy_ok. Returns accuracy_ok (true for a suppressed answer, which has
/// no estimate to check; its row says `estimator=suppressed`, `accuracy_ok=-`).
fn result_cols(r: &mut Row, res: &KmvQueryResult, distinct: usize, prefix: &str, support: u64, suppressed: &str) -> bool {
    let KmvQueryResult::Estimate { estimate, kept, v_k, exact_count } = *res;
    let rel = (estimate as f64 - distinct as f64) / distinct as f64;
    let se = 1.0 / ((KMV_K - 2) as f64).sqrt();
    let was_suppressed = suppressed == "true";
    let ok = was_suppressed || if exact_count { estimate == distinct as u64 } else { rel.abs() <= 5.0 * se };
    let estimator = if was_suppressed { "suppressed" } else if exact_count { "exact_below_k" } else { "kmv_(k-1)/U_k" };
    r.put("answer", format!("{prefix}estimate={estimate}"))
        .put("exact", distinct)
        .put("rel_err", format!("{rel:.6}"))
        .put("std_err", format!("{se:.6}"))
        .put("estimator", estimator)
        .put("kept", kept)
        .put("v_k", v_k)
        .put("support", support)
        .put("suppressed", suppressed)
        .put("accuracy_ok", if was_suppressed { "-".to_string() } else { ok.to_string() });
    ok
}

fn tail_cols(r: &mut Row, x: &Exec, prof: String, p: Option<Proved>, id: [u32; 8]) {
    let fmt_mb = |v: f64| if v.is_nan() { "NaN".to_string() } else { format!("{v:.1}") };
    r.put("prof", prof);
    match p {
        Some(p) => {
            r.put("prove_s", format!("{:.3}", p.prove_s))
                .put("verify_ms", format!("{:.3}", p.verify_ms))
                .put("receipt_bytes", p.receipt_bytes)
                .put("s_per_segment", format!("{:.3}", p.prove_s / p.segments.max(1) as f64))
                .put("prove_segments", p.segments)
                .put("prove_total_cycles", p.total_cycles)
                .put("prove_user_cycles", p.user_cycles)
                .put("prove_paging_cycles", p.paging_cycles)
                .put("prove_r0vm_peak_rss_mb", fmt_mb(p.rss_mb))
                .put("contention", p.contention.csv());
        }
        None => {
            r.put("prove_s", "NaN")
                .put("verify_ms", "NaN")
                .put("receipt_bytes", 0)
                .put("s_per_segment", "NaN")
                .put("prove_segments", 0)
                .put("prove_total_cycles", 0)
                .put("prove_user_cycles", 0)
                .put("prove_paging_cycles", 0)
                .put("prove_r0vm_peak_rss_mb", "NaN")
                .put("contention", "-");
        }
    }
    let seg = x.segments as f64;
    r.put("MODELED_prove_s", format!("{:.1}", seg * S_PER_SEG))
        .put("MODELED_prove_s_lo", format!("{:.1}", seg * S_PER_SEG_LO))
        .put("MODELED_prove_s_hi", format!("{:.1}", seg * S_PER_SEG_HI))
        .put("model", format!("MODELED=segments*{S_PER_SEG} s/seg (CM-guest CPU anchors; not measured)"))
        .put("image_id", image_id_hex(id));
}

fn arm_of(p: &Option<Proved>) -> &'static str {
    match p {
        None => "exec",
        Some(p) if p.contention.contended() => "proved_contended",
        Some(_) => "proved",
    }
}

/// One aggregation guest run (execute, and prove with --prove) on a prepared epoch input.
/// Returns the GUEST journal (the pipeline carries the chain from it).
fn aggr_step(ctx: &mut Ctx, inp: &KmvAggrInput, st: &KmvEpochState, e: usize, slice: &[u32]) -> KmvAggrOutput {
    let (_, native) = process_kmv_aggr_with_state(inp);
    let x = execute(inp, KMV_AGGR_ELF);
    let got: KmvAggrOutput = x.session.journal.decode().expect("decode journal");
    let eq = got == native && kmv_epoch_state_commit(st) == native.state_commit;
    let p = ctx.do_prove.then(|| prove(inp, KMV_AGGR_ELF, KMV_AGGR_ID, &native));
    let distinct = slice.iter().collect::<HashSet<_>>().len();
    // The aggregation journal holds commitments only; the per-epoch answer is computed
    // natively from the committed state, for the accuracy columns.
    let res = kmv_estimate(&st.values, KMV_K);
    let KmvQueryResult::Estimate { estimate, .. } = res;
    let refc = ref_check(&st.values, slice, estimate);
    let mut r = Row::new();
    common_cols(&mut r, ctx, arm_of(&p), "aggr", "kmv_aggr", "-", 1, e.to_string(), ctx.m, distinct, &x);
    r.put("state_commits", 1).put("journal_eq_native", eq).put("ref_check", &refc);
    let acc_ok = result_cols(&mut r, &res, distinct, "journal=commits_only;native_epoch_", st.total_count, "-");
    tail_cols(&mut r, &x, prof(&x, &["chain", "flatten", "update", "commit"]), p, KMV_AGGR_ID);
    r.emit();
    if !eq || refc != "ok" || !acc_ok {
        eprintln!("kmv: FAIL aggr epoch {e}: journal_eq_native={eq} ref_check={refc} accuracy_ok={acc_ok}");
        ctx.fails += 1;
    }
    got
}

/// One query guest run over the given epoch states and chain links.
fn query_step(ctx: &mut Ctx, states: &[KmvEpochState], links: &[EpochChainLink], prefix: &[u32]) {
    let n = states.len();
    let input = KmvQueryInput { query: KmvQuery::Estimate, epoch_states: states.to_vec(), epoch_chain_links: links.to_vec() };
    let native = run_kmv_query(&input).suppress_if_low_support();
    let x = execute(&input, KMV_QUERY_ELF);
    let got: KmvQueryOutput = x.session.journal.decode().expect("decode journal");
    let eq = got == native;
    let p = ctx.do_prove.then(|| prove(&input, KMV_QUERY_ELF, KMV_QUERY_ID, &native));
    let distinct = prefix.iter().collect::<HashSet<_>>().len();
    // the merged set the guest must have formed
    let mut merged: Vec<u64> = Vec::new();
    for s in states {
        merged = merge_bottom_k(&merged, &s.values, KMV_K);
    }
    let KmvQueryResult::Estimate { estimate, .. } = got.result;
    let refc = if got.suppressed { "suppressed".to_string() } else { ref_check(&merged, prefix, estimate) };
    let mut r = Row::new();
    common_cols(&mut r, ctx, arm_of(&p), "query", "kmv_query", "estimate", n, "-".into(), n * ctx.m, distinct, &x);
    r.put("state_commits", got.state_commits.len()).put("journal_eq_native", eq).put("ref_check", &refc);
    let acc = result_cols(
        &mut r, &got.result, distinct, if got.suppressed { "SUPPRESSED;" } else { "" }, got.support,
        &got.suppressed.to_string(),
    );
    let acc_ok = got.suppressed || acc;
    tail_cols(&mut r, &x, prof(&x, &["links", "commits", "merge", "estimate"]), p, KMV_QUERY_ID);
    r.emit();
    if !eq || !(refc == "ok" || refc == "suppressed") || !acc_ok {
        eprintln!("kmv: FAIL query n={n}: journal_eq_native={eq} ref_check={refc} accuracy_ok={acc_ok}");
        ctx.fails += 1;
    }
}

/// Aggregate epochs 0..n natively, chaining epochs and source tips as their host does.
fn aggregate_native(keys: &[u32], n: usize, m: usize, cbs: usize) -> (Vec<(KmvAggrInput, KmvEpochState)>, Vec<EpochChainLink>) {
    let mut chain = SourceChain { tip: [0u8; 32], next_seq: 0 };
    let mut prev_chain_hash = [0u8; 32];
    let mut prev_tips: Vec<(u32, u64, [u8; 32])> = Vec::new();
    let mut outs = Vec::with_capacity(n);
    let mut links = Vec::with_capacity(n);
    for e in 0..n {
        let batches = chain.batches(&epoch_events(keys, e, m), cbs);
        let inp = KmvAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
        let (st, out) = process_kmv_aggr_with_state(&inp);
        assert_eq!(out.n_events as usize, m);
        prev_chain_hash = out.epoch_chain_link.final_chain_hash;
        prev_tips = out.final_source_chain_tips.clone();
        links.push(out.epoch_chain_link);
        outs.push((inp, st));
    }
    (outs, links)
}

fn main() {
    validate_args();
    if flag("--header") {
        println!("{}", COLS.join(","));
        return;
    }
    if std::env::var("RISC0_DEV_MODE").map(|v| !v.is_empty()).unwrap_or(false) {
        die("RISC0_DEV_MODE is set; unset it (nothing here may run in dev mode)");
    }
    let mode = arg_str("--mode").unwrap_or_else(|| die("--mode exec|aggr|query is required"));
    let keys_path = arg_str("--keys")
        .unwrap_or_else(|| format!("{}/../../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR")));
    let m = arg_usize("--epoch-size", 2048);
    let cbs = arg_usize("--batch", 8);
    if m == 0 || cbs == 0 {
        die("--epoch-size and --batch must be > 0");
    }
    let keys = load_keys(&keys_path);
    let mut ctx = Ctx { mode: mode.clone(), m, cbs, do_prove: flag("--prove"), fails: 0 };

    match mode.as_str() {
        "aggr" => {
            let idx = arg_usize("--epoch-index", 0);
            if (idx + 1) * m > keys.len() {
                die(&format!("epoch {idx} needs {} keys, {keys_path} has {}", (idx + 1) * m, keys.len()));
            }
            let (outs, _) = aggregate_native(&keys, idx + 1, m, cbs);
            let (inp, st) = &outs[idx];
            aggr_step(&mut ctx, inp, st, idx, &keys[idx * m..(idx + 1) * m]);
        }
        "query" => {
            let n = arg_usize("--epochs", 1);
            if n == 0 || n * m > keys.len() {
                die(&format!("--epochs {n} needs {} keys, {keys_path} has {}", n * m, keys.len()));
            }
            let (outs, links) = aggregate_native(&keys, n, m, cbs);
            let states: Vec<KmvEpochState> = outs.into_iter().map(|(_, s)| s).collect();
            query_step(&mut ctx, &states, &links, &keys[..n * m]);
        }
        "exec" => {
            let big_n = arg_usize("--epochs", 1);
            if big_n == 0 || big_n * m > keys.len() {
                die(&format!("--epochs {big_n} needs {} keys, {keys_path} has {}", big_n * m, keys.len()));
            }
            let query_at = arg_list("--query-at").unwrap_or_else(|| vec![big_n]);
            if query_at.iter().any(|&q| q == 0 || q > big_n) {
                die(&format!("--query-at values must be in 1..={big_n}"));
            }
            let mut chain = SourceChain { tip: [0u8; 32], next_seq: 0 };
            let mut prev_chain_hash = [0u8; 32];
            let mut prev_tips: Vec<(u32, u64, [u8; 32])> = Vec::new();
            let mut states = Vec::with_capacity(big_n);
            let mut links = Vec::with_capacity(big_n);
            for e in 0..big_n {
                let batches = chain.batches(&epoch_events(&keys, e, m), cbs);
                let inp = KmvAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
                let (st, _) = process_kmv_aggr_with_state(&inp);
                let got = aggr_step(&mut ctx, &inp, &st, e, &keys[e * m..(e + 1) * m]);
                // carry the chain from the guest's journal, as their aggregator host does
                prev_chain_hash = got.epoch_chain_link.final_chain_hash;
                prev_tips = got.final_source_chain_tips.clone();
                links.push(got.epoch_chain_link);
                states.push(st);
                let n = e + 1;
                if query_at.contains(&n) {
                    query_step(&mut ctx, &states, &links, &keys[..n * m]);
                }
            }
        }
        o => die(&format!("--mode {o}: expected exec|aggr|query")),
    }
    if ctx.fails > 0 {
        eprintln!("kmv: {} check(s) failed", ctx.fails);
        std::process::exit(1);
    }
}
