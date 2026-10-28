// Host driver for the Bloom port: executes the guests (and proves them with --prove), one CSV row per guest run.
// Usage: bloom --header | bloom --mode aggr|query|exec [--epochs N] [--probe first|absent] [--prove] ...

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, SessionInfo};
use zka_bloom_core::{
    batch_chain_hash, bloom_contains, bloom_epoch_state_commit, process_bloom_aggr_root,
    process_bloom_aggr_with_state, run_bloom_query, BatchInput, BloomAggrInput, BloomAggrOutput,
    BloomAggrRootOutput, BloomEpochState, BloomQuery, BloomQueryInput, BloomQueryInputWords, BloomQueryOutput,
    BloomQueryResult, BloomRoot, EpochChainLink, BLOOM_BITS, BLOOM_K, BLOOM_BYTES, BLOOM_SEEDS, BLOOM_W,
};
use zka_bloom_methods::{
    BLOOM_AGGR_ELF, BLOOM_AGGR_ID, BLOOM_AGGR_ROOT_ELF, BLOOM_AGGR_ROOT_ID, BLOOM_QUERY_ELF, BLOOM_QUERY_ID,
    BLOOM_QUERY_WORDS_ELF, BLOOM_QUERY_WORDS_ID,
};
use zkvm_common::Event;

/// MODELED_prove_s = segments x S_PER_SEG (computed, not measured), from the four CPU-proved CM guest runs
/// in scripts/baselines/zka/README.md: S_PER_SEG is aggr_cm T=100, n=512 (661.3 s / 22 segments = 30.06 s)
/// rounded; _lo/_hi use 29.73 and 30.79 s, the lowest and highest s/segment of the four.
const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] = &[
    "--mode", "--epochs", "--epoch-index", "--keys", "--epoch-size", "--batch", "--query-at", "--probe", "--absent",
    "--gate", "--arm-tag", "--root",
];
const BOOL_FLAGS: &[&str] = &["--prove", "--header", "--words"];

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
    eprintln!("bloom: {msg}");
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

/// splitmix64 as a deterministic sequence generator for the absent-key set.
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
/// `count` distinct 32-bit keys that occur NOWHERE in the dataset file (so they are
/// absent from every prefix), in a fixed pseudo-random order.
fn absent_keys(all: &HashSet<u32>, count: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(count);
    let mut seen = HashSet::new();
    let mut i = 0u64;
    while out.len() < count {
        let c = (splitmix64(i ^ 0xD1B5_4A32_D192_ED03) & 0xFFFF_FFFF) as u32;
        i += 1;
        if !all.contains(&c) && seen.insert(c) {
            out.push(c);
        }
    }
    out
}

// ----------------------------------------------------- independent reference
/// FNV-1a over the 15-byte key_id, written out here (not the core's key_to_u64).
fn ref_fold(key: u32) -> u64 {
    let id = Event::make_key_id(0, key as u64);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in id {
        h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
fn ref_pos(key: u32, slice: usize) -> usize {
    let s = BLOOM_SEEDS[slice] as u64;
    let mut x = ref_fold(key) ^ (s << 32 | s);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    (x % BLOOM_W as u64) as usize
}
/// One Vec<bool> per slice, straight from the raw keys.
fn ref_filter(keys: &[u32]) -> Vec<Vec<bool>> {
    let mut f = vec![vec![false; BLOOM_W]; BLOOM_K];
    for &k in keys {
        for (j, s) in f.iter_mut().enumerate() {
            s[ref_pos(k, j)] = true;
        }
    }
    f
}
fn ref_contains(f: &[Vec<bool>], key: u32) -> bool {
    (0..BLOOM_K).all(|j| f[j][ref_pos(key, j)])
}
/// "ok" iff the guest bits equal the reference bits (and, for a query, the reference
/// answer equals the guest's).
fn ref_check(bits: &[u8], keys: &[u32], probe: Option<(u32, bool)>) -> String {
    let f = ref_filter(keys);
    let mut diff = 0usize;
    for (j, s) in f.iter().enumerate() {
        for (p, &b) in s.iter().enumerate() {
            let i = j * BLOOM_W + p;
            if (bits[i / 8] >> (i % 8) & 1 == 1) != b {
                diff += 1;
            }
        }
    }
    if diff != 0 {
        return format!("FAIL(bits differ at {diff})");
    }
    if let Some((key, member)) = probe {
        if ref_contains(&f, key) != member {
            return format!("FAIL(reference answer for {key} != {member})");
        }
    }
    "ok".into()
}

// --------------------------------------------------------------- accuracy
struct Accuracy {
    bits_set: u64,
    fill: f64,
    fn_inserted: usize,
    inserted: usize,
    fp_absent: usize,
    absent: usize,
    fpr_measured: f64,
    fpr_fill: f64,
    fpr_theory: f64,
}
fn accuracy(bits: &[u8], inserted: &HashSet<u32>, absent: &[u32]) -> Accuracy {
    let pop = |w: &[u8]| w.iter().map(|x| x.count_ones() as u64).sum::<u64>();
    let bits_set = pop(bits);
    let per_slice = BLOOM_W / 8;
    let fpr_fill: f64 = (0..BLOOM_K)
        .map(|j| pop(&bits[j * per_slice..(j + 1) * per_slice]) as f64 / BLOOM_W as f64)
        .product();
    let fn_inserted = inserted.iter().filter(|&&k| !bloom_contains(bits, &Event::make_key_id(0, k as u64))).count();
    let fp_absent = absent.iter().filter(|&&k| bloom_contains(bits, &Event::make_key_id(0, k as u64))).count();
    let n = inserted.len() as f64;
    Accuracy {
        bits_set,
        fill: bits_set as f64 / BLOOM_BITS as f64,
        fn_inserted,
        inserted: inserted.len(),
        fp_absent,
        absent: absent.len(),
        fpr_measured: fp_absent as f64 / absent.len().max(1) as f64,
        fpr_fill,
        fpr_theory: (1.0 - (1.0 - 1.0 / BLOOM_W as f64).powf(n)).powi(BLOOM_K as i32),
    }
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
    let got: J = receipt.journal.decode().expect("decode proved journal");
    assert_eq!(&got, expect, "proved journal != native");
    eprintln!(
        "bloom: proved in {prove_s:.1} s, {} segments, total_cycles={} user_cycles={} paging={}; r0vm peak RSS {rss_mb:.1} MB; contention {}",
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
const COLS: &[&str] = &[
    "system", "arm", "family", "mode", "step", "guest", "query", "bloom_k", "bloom_w", "epochs", "epoch_index",
    "epoch_records", "records", "batch", "hash", "distinct_keys", "input_bytes", "user_cycles", "padded_cycles",
    "segments", "max_po2", "cycles_per_record", "exec_s", "journal_bytes", "state_commits", "journal_eq_native",
    "ref_check", "probe_mode", "probe_key", "answer", "exact", "answer_ok", "support", "suppressed", "bits_set",
    "fill", "fn_inserted", "inserted_checked", "fp_absent", "absent_checked", "fpr_measured", "fpr_fill",
    "fpr_theory", "accuracy_ok", "prof", "prove_s", "verify_ms", "receipt_bytes",
    "s_per_segment", "prove_segments", "prove_total_cycles", "prove_user_cycles", "prove_paging_cycles",
    "prove_r0vm_peak_rss_mb", "contention", "MODELED_prove_s", "MODELED_prove_s_lo", "MODELED_prove_s_hi", "model",
    "image_id", "root_variant", "root_construction", "variants_agree", "state_commit",
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
    words: bool,
    /// --gate, recorded in the contention column of proved rows
    gate: String,
    /// --arm-tag, appended to the arm of proved rows
    arm_tag: Option<String>,
    /// --root: its name, and None = legacy (bloom_aggr) / Some(r) = bloom_aggr_root with r
    root_name: &'static str,
    root: Option<BloomRoot>,
    fails: usize,
}

/// --root: (name, None = legacy | Some(variant of the bloom_aggr_root guest)).
fn parse_root() -> (&'static str, Option<BloomRoot>) {
    match arg_str("--root").as_deref() {
        None | Some("legacy") => ("legacy", None),
        Some("designed") => ("designed", Some(BloomRoot::Buckets64)),
        Some("noroot") => ("noroot", Some(BloomRoot::None)),
        Some(o) => die(&format!("--root {o}: expected legacy|designed|noroot")),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The four root-variant columns (last in COLS).
fn root_cols(r: &mut Row, variant: &str, construction: &str, agree: &str, state_commit: &str) {
    r.put("root_variant", variant)
        .put("root_construction", construction)
        .put("variants_agree", agree)
        .put("state_commit", state_commit);
}

#[allow(clippy::too_many_arguments)]
fn common_cols(
    r: &mut Row, ctx: &Ctx, arm: &str, step: &str, guest: &str, query: &str, epochs: usize, epoch_index: String,
    records: usize, distinct: usize, x: &Exec,
) {
    r.put("system", "zka-arch")
        .put("arm", arm)
        .put("family", "bloom")
        .put("mode", &ctx.mode)
        .put("step", step)
        .put("guest", guest)
        .put("query", query)
        .put("bloom_k", BLOOM_K)
        .put("bloom_w", BLOOM_W)
        .put("epochs", epochs)
        .put("epoch_index", epoch_index)
        .put("epoch_records", ctx.m)
        .put("records", records)
        .put("batch", ctx.cbs)
        .put("hash", "fnv1a+splitmix64/slice")
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

fn accuracy_cols(r: &mut Row, a: &Accuracy) -> bool {
    let ok = a.fn_inserted == 0;
    r.put("bits_set", a.bits_set)
        .put("fill", format!("{:.6}", a.fill))
        .put("fn_inserted", a.fn_inserted)
        .put("inserted_checked", a.inserted)
        .put("fp_absent", a.fp_absent)
        .put("absent_checked", a.absent)
        .put("fpr_measured", format!("{:.3e}", a.fpr_measured))
        .put("fpr_fill", format!("{:.3e}", a.fpr_fill))
        .put("fpr_theory", format!("{:.3e}", a.fpr_theory))
        .put("accuracy_ok", ok);
    ok
}

fn tail_cols(r: &mut Row, ctx: &Ctx, x: &Exec, prof: String, p: Option<Proved>, id: [u32; 8]) {
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
                .put("contention", format!("{};gate={}", p.contention.csv(), ctx.gate));
        }
        None => {
            for c in ["prove_s", "verify_ms"] {
                r.put(c, "NaN");
            }
            for c in ["receipt_bytes"] {
                r.put(c, 0);
            }
            r.put("s_per_segment", "NaN");
            for c in ["prove_segments", "prove_total_cycles", "prove_user_cycles", "prove_paging_cycles"] {
                r.put(c, 0);
            }
            r.put("prove_r0vm_peak_rss_mb", "NaN").put("contention", "-");
        }
    }
    let seg = x.segments as f64;
    r.put("MODELED_prove_s", format!("{:.1}", seg * S_PER_SEG))
        .put("MODELED_prove_s_lo", format!("{:.1}", seg * S_PER_SEG_LO))
        .put("MODELED_prove_s_hi", format!("{:.1}", seg * S_PER_SEG_HI))
        .put("model", format!("MODELED=segments*{S_PER_SEG} s/seg (CM-guest CPU anchors; not measured)"))
        .put("image_id", image_id_hex(id));
}

/// exec | proved | proved_contended, then _<arm-tag> on proved rows when one was given.
fn arm_of(ctx: &Ctx, p: &Option<Proved>) -> String {
    let base = match p {
        None => return "exec".into(),
        Some(p) if p.contention.contended() => "proved_contended",
        Some(_) => "proved",
    };
    match &ctx.arm_tag {
        Some(t) => format!("{base}_{t}"),
        None => base.into(),
    }
}

/// One aggregation guest run (execute, and prove with --prove) on a prepared epoch input,
/// with the --root variant's guest. Returns the GUEST journal without its root (the
/// pipeline carries the chain from it).
fn aggr_step(ctx: &mut Ctx, inp: &BloomAggrInput, st: &BloomEpochState, e: usize, slice: &[u32], absent: &[u32]) -> BloomAggrOutput {
    // Every variant run natively on the same input: same state and journal except the root.
    let (_, native) = process_bloom_aggr_with_state(inp);
    let (sd, designed) = process_bloom_aggr_root(inp, BloomRoot::Buckets64);
    let (sn, noroot) = process_bloom_aggr_root(inp, BloomRoot::None);
    let agree = &sd == st && &sn == st && designed.without_root() == native && noroot.without_root() == native
        && noroot.buckets_root == [0u8; 32] && designed.buckets_root != [0u8; 32];
    let (guest, x, got, guest_eq, p, id, construction) = match ctx.root {
        None => {
            let x = execute(inp, BLOOM_AGGR_ELF);
            let got: BloomAggrOutput = x.session.journal.decode().expect("decode journal");
            let p = ctx.do_prove.then(|| prove(inp, BLOOM_AGGR_ELF, BLOOM_AGGR_ID, &native));
            let eq = got == native;
            ("bloom_aggr", x, got, eq, p, BLOOM_AGGR_ID, "none")
        }
        Some(rv) => {
            let expect: (BloomRoot, BloomAggrRootOutput) = (rv, if rv == BloomRoot::None { noroot } else { designed });
            // The guest reads the BloomRoot, then the input: a tuple serializes as the two in sequence.
            let x = execute(&(rv, inp), BLOOM_AGGR_ROOT_ELF);
            let got: (BloomRoot, BloomAggrRootOutput) = x.session.journal.decode().expect("decode journal");
            let p = ctx.do_prove.then(|| prove(&(rv, inp), BLOOM_AGGR_ROOT_ELF, BLOOM_AGGR_ROOT_ID, &expect));
            let eq = got == expect;
            ("bloom_aggr_root", x, got.1.without_root(), eq, p, BLOOM_AGGR_ROOT_ID, rv.construction())
        }
    };
    let eq = guest_eq && bloom_epoch_state_commit(st) == native.state_commit;
    let inserted: HashSet<u32> = slice.iter().copied().collect();
    let refc = ref_check(&st.bits, slice, None);
    let mut r = Row::new();
    common_cols(&mut r, ctx, &arm_of(ctx, &p), "aggr", guest, "-", 1, e.to_string(), ctx.m, inserted.len(), &x);
    r.put("state_commits", 1)
        .put("journal_eq_native", eq)
        .put("ref_check", &refc)
        .put("probe_mode", "-")
        .put("probe_key", "-")
        .put("answer", "journal=commits_only")
        .put("exact", "-")
        .put("answer_ok", "-")
        .put("support", st.total_count)
        .put("suppressed", "-");
    // per-epoch filter accuracy, computed natively from the committed state
    let acc_ok = accuracy_cols(&mut r, &accuracy(&st.bits, &inserted, absent));
    let phases: &[&str] =
        if ctx.root.is_some() { &["chain", "flatten", "update", "commit", "root"] } else { &["chain", "flatten", "update", "commit"] };
    tail_cols(&mut r, ctx, &x, prof(&x, phases), p, id);
    root_cols(&mut r, ctx.root_name, construction, &agree.to_string(), &hex(&native.state_commit));
    r.emit();
    if !eq || refc != "ok" || !acc_ok || !agree {
        eprintln!("bloom: FAIL aggr epoch {e}: journal_eq_native={eq} ref_check={refc} accuracy_ok={acc_ok} variants_agree={agree}");
        ctx.fails += 1;
    }
    got
}

/// One query guest run over the given epoch states and chain links: `bloom_query`, then
/// with --words also `bloom_query_words` on the same input.
#[allow(clippy::too_many_arguments)]
fn query_step(
    ctx: &mut Ctx, states: &[BloomEpochState], links: &[EpochChainLink], prefix: &[u32], probe_mode: &str,
    probe: u32, absent: &[u32],
) {
    let n = states.len();
    let input = BloomQueryInput {
        query: BloomQuery::Contains { key: Event::make_key_id(0, probe as u64) },
        epoch_states: states.to_vec(),
        epoch_chain_links: links.to_vec(),
    };
    let native = run_bloom_query(&input).suppress_if_low_support();
    let winput = ctx.words.then(|| BloomQueryInputWords::from(&input));
    // the merged filter the guest must have formed
    let mut merged = vec![0u8; BLOOM_BYTES];
    for s in states {
        for (a, &b) in merged.iter_mut().zip(&s.bits) {
            *a |= b;
        }
    }
    let inserted: HashSet<u32> = prefix.iter().copied().collect();
    let in_stream = inserted.contains(&probe);
    let mut variants = vec![("bloom_query", false)];
    if winput.is_some() {
        variants.push(("bloom_query_words", true));
    }
    for (guest, words) in variants {
        let (elf, id) = if words { (BLOOM_QUERY_WORDS_ELF, BLOOM_QUERY_WORDS_ID) } else { (BLOOM_QUERY_ELF, BLOOM_QUERY_ID) };
        let x = match &winput {
            Some(w) if words => execute(w, elf),
            _ => execute(&input, elf),
        };
        let got: BloomQueryOutput = x.session.journal.decode().expect("decode journal");
        let eq = got == native;
        let p = ctx.do_prove.then(|| match &winput {
            Some(w) if words => prove(w, elf, id, &native),
            _ => prove(&input, elf, id, &native),
        });
        let BloomQueryResult::Contains { key, member } = got.result;
        assert_eq!(key, Event::make_key_id(0, probe as u64), "journal key != probe key");
        let refc = if got.suppressed { "suppressed".to_string() } else { ref_check(&merged, prefix, Some((probe, member))) };
        let answer_ok = got.suppressed || !in_stream || member;
        let answer = format!(
            "member={member}{}{}",
            if member && !in_stream { "(false_positive)" } else { "" },
            if got.suppressed { " SUPPRESSED" } else { "" }
        );
        let mut r = Row::new();
        common_cols(&mut r, ctx, &arm_of(ctx, &p), "query", guest, "contains", n, "-".into(), n * ctx.m, inserted.len(), &x);
        r.put("state_commits", got.state_commits.len())
            .put("journal_eq_native", eq)
            .put("ref_check", &refc)
            .put("probe_mode", probe_mode)
            .put("probe_key", probe)
            .put("answer", answer)
            .put("exact", format!("in_stream={in_stream}"))
            .put("answer_ok", answer_ok)
            .put("support", got.support)
            .put("suppressed", got.suppressed);
        let acc_ok = accuracy_cols(&mut r, &accuracy(&merged, &inserted, absent));
        let phases: &[&str] =
            if words { &["convert", "links", "commits", "merge", "answer"] } else { &["links", "commits", "merge", "answer"] };
        tail_cols(&mut r, ctx, &x, prof(&x, phases), p, id);
        root_cols(&mut r, "-", "-", "-", "-");
        r.emit();
        if !eq || !(refc == "ok" || refc == "suppressed") || !answer_ok || !acc_ok {
            eprintln!("bloom: FAIL {guest} n={n} probe={probe}: journal_eq_native={eq} ref_check={refc} answer_ok={answer_ok} accuracy_ok={acc_ok}");
            ctx.fails += 1;
        }
    }
}

fn probe_keys(spec: &str, keys: &[u32], n: usize, m: usize, absent: &[u32]) -> Vec<(String, u32)> {
    spec.split(',')
        .map(|s| {
            let s = s.trim();
            match s {
                "first" => ("first".to_string(), keys[(n - 1) * m]),
                "absent" => ("absent".to_string(), absent[0]),
                _ => match s.strip_prefix("key:").and_then(|v| v.parse::<u32>().ok()) {
                    Some(k) => ("key".to_string(), k),
                    None => die(&format!("--probe '{s}': expected first|absent|key:<u32>")),
                },
            }
        })
        .collect()
}

/// Aggregate epochs 0..n natively, chaining epochs and source tips as their host does.
fn aggregate_native(keys: &[u32], n: usize, m: usize, cbs: usize) -> (Vec<(BloomAggrInput, BloomEpochState)>, Vec<EpochChainLink>) {
    let mut chain = SourceChain { tip: [0u8; 32], next_seq: 0 };
    let mut prev_chain_hash = [0u8; 32];
    let mut prev_tips: Vec<(u32, u64, [u8; 32])> = Vec::new();
    let mut outs = Vec::with_capacity(n);
    let mut links = Vec::with_capacity(n);
    for e in 0..n {
        let batches = chain.batches(&epoch_events(keys, e, m), cbs);
        let inp = BloomAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
        let (st, out) = process_bloom_aggr_with_state(&inp);
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
    let n_absent = arg_usize("--absent", 10_000);
    let probe_spec = arg_str("--probe").unwrap_or_else(|| "first".into());
    if m == 0 || cbs == 0 || n_absent == 0 {
        die("--epoch-size, --batch and --absent must be > 0");
    }
    let keys = load_keys(&keys_path);
    let all: HashSet<u32> = keys.iter().copied().collect();
    let absent = absent_keys(&all, n_absent);
    let gate = arg_str("--gate").unwrap_or_else(|| "none".into());
    let arm_tag = arg_str("--arm-tag");
    if gate.contains(',') {
        die("--gate must not contain a comma (it goes into a CSV cell)");
    }
    if let Some(t) = &arm_tag {
        if t.is_empty() || !t.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            die(&format!("--arm-tag '{t}': use [a-z0-9_]+"));
        }
    }
    let (root_name, root) = parse_root();
    if arg_str("--root").is_some() && mode == "query" {
        die("--root applies to --mode aggr and exec only (query guests read no root)");
    }
    let mut ctx = Ctx {
        root_name,
        root,
        mode: mode.clone(),
        m,
        cbs,
        do_prove: flag("--prove"),
        words: flag("--words"),
        gate,
        arm_tag,
        fails: 0,
    };

    match mode.as_str() {
        "aggr" => {
            let idx = arg_usize("--epoch-index", 0);
            if (idx + 1) * m > keys.len() {
                die(&format!("epoch {idx} needs {} keys, {keys_path} has {}", (idx + 1) * m, keys.len()));
            }
            let (outs, _) = aggregate_native(&keys, idx + 1, m, cbs);
            let (inp, st) = &outs[idx];
            aggr_step(&mut ctx, inp, st, idx, &keys[idx * m..(idx + 1) * m], &absent);
        }
        "query" => {
            let n = arg_usize("--epochs", 1);
            if n == 0 || n * m > keys.len() {
                die(&format!("--epochs {n} needs {} keys, {keys_path} has {}", n * m, keys.len()));
            }
            let (outs, links) = aggregate_native(&keys, n, m, cbs);
            let states: Vec<BloomEpochState> = outs.into_iter().map(|(_, s)| s).collect();
            for (pm, pk) in probe_keys(&probe_spec, &keys, n, m, &absent) {
                query_step(&mut ctx, &states, &links, &keys[..n * m], &pm, pk, &absent);
            }
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
                let inp = BloomAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
                let (st, _) = process_bloom_aggr_with_state(&inp);
                let got = aggr_step(&mut ctx, &inp, &st, e, &keys[e * m..(e + 1) * m], &absent);
                // carry the chain from the guest's journal, as their aggregator host does
                prev_chain_hash = got.epoch_chain_link.final_chain_hash;
                prev_tips = got.final_source_chain_tips.clone();
                links.push(got.epoch_chain_link);
                states.push(st);
                let n = e + 1;
                if query_at.contains(&n) {
                    for (pm, pk) in probe_keys(&probe_spec, &keys, n, m, &absent) {
                        query_step(&mut ctx, &states, &links, &keys[..n * m], &pm, pk, &absent);
                    }
                }
            }
        }
        o => die(&format!("--mode {o}: expected exec|aggr|query")),
    }
    if ctx.fails > 0 {
        eprintln!("bloom: {} check(s) failed", ctx.fails);
        std::process::exit(1);
    }
}
