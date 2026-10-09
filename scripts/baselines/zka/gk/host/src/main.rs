// zk-Analytics-architecture GREENWALD-KHANNA arm: our GK guests (aggr_gk, querier_gk)
// run in zk-Analytics' own epoch pipeline on REAL AOL records. zk-Analytics ships no
// quantile summary with a rank guarantee (its histogram is per-key log2 bins, P90
// only); this measures what their general-purpose method costs for one.
//
// Patterned on ../../cyc/src/bin/shipped.rs (records, batching, chain carrying,
// executor measurement, journal == native check, MODELED column).
//
// Records: data/aol.keys (flat little-endian u32). Epoch e holds keys [e*m, (e+1)*m),
// m = --epoch-size (16,384 default: epoch 0 is our matched epoch).
//   key_id = Event::make_key_id(0, key)   (zkvm-common/src/lib.rs:76, as shipped.rs)
//   value  = key & 0x1F_FFFF              (as shipped.rs's histogram arm and zkSketch's
//                                          gk_vals_of; values in [0, 2^21))
//   ts     = global record index
// Batches: source 0, stream order, --batch records each (default 8, their
// --commit-batch-size default); SHA-256 batch chain, source_batch_seq and
// prev_source_chain_tips carried across epochs as their aggregator host does. Epoch
// e's prev_chain_hash is epoch e-1's final_chain_hash.
//
// Modes:
//   --mode aggr  [--epoch-index i]        execute aggr_gk on epoch i (earlier epochs
//                                         are aggregated natively only for the chain tips)
//        [--profile]                      execute the PROFILING guest instead (phase split)
//        [--prove]                        also prove it (ProverOpts::succinct(), their tier)
//   --mode query --epochs n --query rank|p50|p90|p99 [--rank-value v]
//                                         aggregate epochs 0..n natively, execute querier_gk
//        [--prove]                        also prove it (ProverOpts::succinct(); added for the
//                                         six-sketch comparison, ../README.md)
//   --header
//   common: [--keys PATH] [--epoch-size 16384] [--batch 8]
//
// Every run checks the guest journal against the native function on the same input
// and compares the answer with the exact answer over the covered values. Every row
// also carries NATIVE accuracy checks of the same summaries (not guest work):
//   min_kept      t_0.v / t_(s-1).v equal the epoch minimum / maximum (every epoch covered)
//   q_named       aggr rows: per-epoch quantile at phi in {0, 1/1000, 1/100, 1/2, 99/100, 1},
//                 as err/cert pairs
//   q_sweep_1001  quantile at phi = q/1000, q = 0..1000, over the row's epoch (aggr) or
//                 union (query): worst actual error, worst certified error, worst cert/eps N
//   q_ok          every named and swept phi: exact answer inside the certified interval
//                 and actual error <= certified error <= eps N
//   cert_over_eps_n  this row's certified error / eps N
// Proved rows also record `contention`: foreign r0vm processes (not descendants of
// this driver) seen by the 250 ms sampler during the prove, their CPU seconds in that
// window, and the max 1-minute load. arm = proved_contended when those foreign r0vm
// processes burned >= CONTENDED_CPU_S (10) CPU seconds in the window.
// The driver exits 1 (row still printed) when a journal or accuracy check fails.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gk_methods::{AGGR_GK_ELF, AGGR_GK_ID, AGGR_GK_PROF_ELF, QUERIER_GK_ELF, QUERIER_GK_ID};
use gk_zka_core::{
    batch_chain_hash, gk_epoch_state_commit, process_gk_aggr_with_state, run_gk_query, BatchInput,
    EpochChainLink, GkAggrInput, GkAggrOutput, GkEpochState, GkQuery, GkQueryInput, GkQueryOutput,
    GkQueryResult, GkUnion, GK_COMPRESS_EVERY, GK_EPS_DEN,
};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, SessionInfo};
use zkvm_common::Event;

const VALUE_MASK: u32 = 0x001F_FFFF;
/// MODELED prove time: segments x 30.1 s, envelope 29.73 .. 30.79 s/segment (the four
/// CPU CM anchors in ../README.md "Modeled prove time and the anchors behind it").
const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] =
    &["--mode", "--query", "--epochs", "--epoch-index", "--keys", "--epoch-size", "--batch", "--rank-value"];
const BOOL_FLAGS: &[&str] = &["--prove", "--header", "--profile"];

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
    eprintln!("gk: {msg}");
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

/// Aggregate epochs 0..n natively, chaining epochs and source tips as their host does.
fn aggregate(keys: &[u32], n: usize, m: usize, cbs: usize) -> (Vec<(GkAggrInput, GkEpochState)>, Vec<EpochChainLink>) {
    let mut chain = SourceChain { tip: [0u8; 32], next_seq: 0 };
    let mut prev_chain_hash = [0u8; 32];
    let mut prev_tips: Vec<(u32, u64, [u8; 32])> = Vec::new();
    let mut outs = Vec::with_capacity(n);
    let mut links = Vec::with_capacity(n);
    for e in 0..n {
        let batches = chain.batches(&epoch_events(keys, e, m), cbs);
        let inp = GkAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
        let (st, out) = process_gk_aggr_with_state(&inp);
        assert_eq!(gk_epoch_state_commit(&st), out.state_commit, "epoch {e}: commit mismatch");
        assert_eq!(out.n_events as usize, m);
        assert_eq!(out.epoch_chain_link.prev_chain_hash, prev_chain_hash);
        prev_chain_hash = out.epoch_chain_link.final_chain_hash;
        prev_tips = out.final_source_chain_tips.clone();
        links.push(out.epoch_chain_link);
        outs.push((inp, st));
    }
    (outs, links)
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
    session: SessionInfo,
}

fn execute<T: serde::Serialize>(input: &T, elf: &[u8]) -> Exec {
    let input_bytes = risc0_zkvm::serde::to_vec(input).expect("serialize input").len() * 4;
    let env = ExecutorEnv::builder().write(input).unwrap().build().unwrap();
    let t = Instant::now();
    let session = default_executor().execute(env, elf).expect("guest execution failed");
    let exec_s = t.elapsed().as_secs_f64();
    Exec {
        user_cycles: session.cycles(),
        padded_cycles: session.segments.iter().map(|s| 1u64 << s.po2).sum(),
        segments: session.segments.len(),
        max_po2: session.segments.iter().map(|s| s.po2).max().unwrap_or(0),
        exec_s,
        input_bytes,
        journal_bytes: session.journal.bytes.len(),
        session,
    }
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
    /// distinct foreign r0vm pids seen
    foreign_pids: usize,
    /// max foreign r0vm processes alive in one sample
    foreign_max: usize,
    /// samples with at least one foreign r0vm / all samples
    foreign_samples: usize,
    samples: usize,
    /// CPU seconds the foreign r0vm processes consumed between first and last sight
    foreign_cpu_s: f64,
    load1_max: f64,
}
/// A row is labelled proved_contended when foreign r0vm processes burned at least this
/// many CPU seconds during the prove (a competing 64-thread prover burns ~64 per
/// second; an idle r0vm server or a momentary executor stays far below).
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

/// VmHWM of every descendant process (the r0vm prover runs as a child of this driver).
/// Only reads /proc; never signals anything.
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
/// pids of every process named r0vm on the box (any user), from /proc/*/comm.
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
/// utime + stime of a process in clock ticks (fields 14 and 15 of /proc/pid/stat).
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

/// Their shipped tier: ProverOpts::succinct() at every prove site. Checks the PROVED
/// journal against the native output. Used for both guests (aggr_gk, querier_gk).
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
        // foreign r0vm pid -> (ticks at first sight, ticks at last sight)
        let mut foreign: std::collections::HashMap<u32, (u64, u64)> = std::collections::HashMap::new();
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
                // clock ticks to seconds: USER_HZ (getconf CLK_TCK) is 100 on Linux
                ct.foreign_pids = foreign.len();
                ct.foreign_cpu_s = foreign.values().map(|(a, b)| (b - a) as f64 / 100.0).sum();
                return (peak, ct);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
    let env = ExecutorEnv::builder().write(input).unwrap().build().unwrap();
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct()).expect("prove failed");
    let prove_s = t.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    let (peak_kb, contention) = sampler.join().unwrap_or((0, Contention::default()));
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
        "gk: proved in {prove_s:.1} s, {} segments, total_cycles={} user_cycles={} paging={} reserved={}; r0vm peak RSS {:.1} MB; driver VmHWM {:.1} MB; contention {}",
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
const HEADER: &str = "system,arm,mode,guest,family,query,eps,compress_every,epochs,epoch_index,epoch_records,records,batch,value_enc,state_tuples,input_bytes,user_cycles,padded_cycles,segments,max_po2,exec_s,journal_bytes,state_commits,journal_eq_native,result,exact,abs_err,cert_err,eps_n,abs_err_le_eps_n,cert_err_le_eps_n,exact_in_cert,cert_over_eps_n,min_kept,q_named,q_sweep_1001,q_ok,prove_s,verify_ms,receipt_bytes,s_per_segment,proved_segments,proved_total_cycles,proved_user_cycles,r0vm_peak_rss_mb,contention,MODELED_prove_s,MODELED_prove_s_lo,MODELED_prove_s_hi,model";

struct Acc {
    abs_err: u64,
    cert_err: u64,
    eps_n: f64,
    exact_in_cert: bool,
}

/// Native quantile checks of a summary set (one epoch for aggr rows, the union for
/// query rows); see the header comment.
struct QChecks {
    min_kept: bool,
    named: String,
    sweep: String,
    ok: bool,
}
impl QChecks {
    fn all_ok(&self, acc: &Acc) -> bool {
        self.min_kept && self.ok && acc.exact_in_cert && acc.abs_err as f64 <= acc.eps_n && acc.cert_err as f64 <= acc.eps_n
    }
}

const NAMED_PHIS: [(u32, u32); 6] = [(0, 1), (1, 1000), (1, 100), (1, 2), (99, 100), (1, 1)];

/// (actual error, certified error, sound) of the union's phi-quantile against the
/// sorted covered values.
fn quantile_check(u: &GkUnion, sorted: &[u32], pn: u32, pd: u32) -> (u64, u64, bool) {
    let (r, v, rmin, rmax) = u.quantile(pn, pd);
    let lt = sorted.partition_point(|&w| w < v) as u64;
    let le = sorted.partition_point(|&w| w <= v) as u64;
    let err = if r < lt + 1 { lt + 1 - r } else if r > le { r - le } else { 0 };
    let cert = r.saturating_sub(rmin).max(rmax.saturating_sub(r));
    (err, cert, le > lt && lt < rmax && rmin <= le && err <= cert)
}

fn q_checks(states: &[GkEpochState], epoch_vals: &[&[u32]], named: bool) -> QChecks {
    let min_kept = states.iter().zip(epoch_vals).all(|(st, v)| {
        st.tuples.first().map(|t| t.v) == v.iter().min().copied() && st.tuples.last().map(|t| t.v) == v.iter().max().copied()
    });
    let mut sorted: Vec<u32> = epoch_vals.concat();
    sorted.sort_unstable();
    let eps_n = sorted.len() as f64 / GK_EPS_DEN as f64;
    let u = GkUnion::merge(states);
    let mut ok = true;
    let named_s = if named {
        NAMED_PHIS
            .iter()
            .map(|&(pn, pd)| {
                let (e, c, sound) = quantile_check(&u, &sorted, pn, pd);
                ok &= sound && c as f64 <= eps_n;
                if pd == 1 { format!("{pn}:{e}/{c}") } else { format!("{pn}/{pd}:{e}/{c}") }
            })
            .collect::<Vec<_>>()
            .join(";")
    } else {
        "-".into()
    };
    let (mut we, mut wc) = (0u64, 0u64);
    for q in 0..=1000u32 {
        let (e, c, sound) = quantile_check(&u, &sorted, q, 1000);
        ok &= sound && c as f64 <= eps_n;
        we = we.max(e);
        wc = wc.max(c);
    }
    QChecks {
        min_kept,
        named: named_s,
        sweep: format!("max_err={we};max_cert={wc};max_cert_over_eps_n={:.4}", wc as f64 / eps_n),
        ok,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    arm: &str, mode: &str, guest: &str, query: &str, epochs: usize, epoch_index: String, m: usize, records: usize,
    cbs: usize, tuples: usize, x: &Exec, state_commits: usize, eq: bool, result: String, exact: String, acc: &Acc,
    qc: &QChecks, p: Option<Proved>,
) {
    let contention = p.as_ref().map_or_else(|| "-".to_string(), |p| p.contention.csv());
    let arm = match &p {
        Some(p) if p.contention.seen() => format!("{arm}_contended"),
        _ => arm.to_string(),
    };
    let (ps, vm, rb, sps, pseg, ptot, pusr, rss) = match p {
        Some(p) => (
            format!("{:.3}", p.prove_s),
            format!("{:.3}", p.verify_ms),
            p.receipt_bytes.to_string(),
            format!("{:.3}", p.prove_s / p.segments.max(1) as f64),
            p.segments.to_string(),
            p.total_cycles.to_string(),
            p.user_cycles.to_string(),
            format!("{:.1}", p.peak_rss_mb),
        ),
        None => ("NaN".into(), "NaN".into(), "0".into(), "NaN".into(), "0".into(), "0".into(), "0".into(), "NaN".into()),
    };
    let seg = x.segments as f64;
    println!(
        "zka,{arm},{mode},{guest},gk,{query},1/{GK_EPS_DEN},{GK_COMPRESS_EVERY},{epochs},{epoch_index},{m},{records},{cbs},key&0x1FFFFF,{tuples},{},{},{},{},{},{:.3},{},{state_commits},{eq},{result},{exact},{},{},{:.2},{},{},{},{:.4},{},{},{},{},{ps},{vm},{rb},{sps},{pseg},{ptot},{pusr},{rss},{contention},{:.1},{:.1},{:.1},MODELED=segments*{S_PER_SEG} s/seg (CM-guest CPU anchors; not measured)",
        x.input_bytes, x.user_cycles, x.padded_cycles, x.segments, x.max_po2, x.exec_s, x.journal_bytes,
        acc.abs_err, acc.cert_err, acc.eps_n, acc.abs_err as f64 <= acc.eps_n, acc.cert_err as f64 <= acc.eps_n,
        acc.exact_in_cert, acc.cert_err as f64 / acc.eps_n, qc.min_kept, qc.named, qc.sweep, qc.ok,
        seg * S_PER_SEG, seg * S_PER_SEG_LO, seg * S_PER_SEG_HI,
    );
}

/// Native accuracy of one epoch summary over every distinct value of the epoch:
/// max |midpoint - exact rank|, max certified half-width, all exact ranks inside bounds.
fn epoch_accuracy(st: &GkEpochState, vals: &[u32]) -> (Acc, usize, u64) {
    let mut sorted = vals.to_vec();
    sorted.sort_unstable();
    let mut xs = sorted.clone();
    xs.dedup();
    let mut acc = Acc { abs_err: 0, cert_err: 0, eps_n: vals.len() as f64 / GK_EPS_DEN as f64, exact_in_cert: true };
    for &x in &xs {
        let (lo, hi) = st.rank_bounds(x);
        let exact = sorted.partition_point(|&v| v <= x) as u64;
        let est = (lo + hi) / 2;
        acc.abs_err = acc.abs_err.max(est.abs_diff(exact));
        acc.cert_err = acc.cert_err.max((est - lo).max(hi - est));
        acc.exact_in_cert &= lo <= exact && exact <= hi;
    }
    let max_gd = st.tuples.iter().map(|t| (t.g + t.delta) as u64).max().unwrap_or(0);
    (acc, xs.len(), max_gd)
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
    let mode = arg_str("--mode").unwrap_or_else(|| die("--mode aggr|query is required"));
    let keys_path =
        arg_str("--keys").unwrap_or_else(|| format!("{}/../../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR")));
    let m = arg_u64("--epoch-size", 16_384) as usize;
    let cbs = arg_u64("--batch", 8) as usize;
    if m == 0 || cbs == 0 {
        die("--epoch-size and --batch must be > 0");
    }
    let keys = load_keys(&keys_path);

    match mode.as_str() {
        "aggr" => {
            if arg_str("--query").is_some() || arg_str("--epochs").is_some() {
                die("--query/--epochs belong to --mode query");
            }
            let profile = flag("--profile");
            let do_prove = flag("--prove");
            if profile && do_prove {
                die("--profile and --prove are exclusive (the profiling guest is never proved)");
            }
            let idx = arg_u64("--epoch-index", 0) as usize;
            if (idx + 1) * m > keys.len() {
                die(&format!("epoch {idx} needs {} keys, {keys_path} has {}", (idx + 1) * m, keys.len()));
            }
            let (outs, _links) = aggregate(&keys, idx + 1, m, cbs);
            let (inp, st) = &outs[idx];
            let (_, native) = process_gk_aggr_with_state(inp);
            let vals: Vec<u32> = keys[idx * m..(idx + 1) * m].iter().map(|&k| k & VALUE_MASK).collect();
            let (acc, distinct_vals, max_gd) = epoch_accuracy(st, &vals);
            let qc = q_checks(core::slice::from_ref(st), &[&vals[..]], true);
            let checks_ok = qc.all_ok(&acc);
            let p = 2 * m as u64 / GK_EPS_DEN;
            let result_base = format!("tuples={};max_g_plus_delta={max_gd};floor_2eps_n={p}", st.tuples.len());
            let exact = format!("distinct_values={distinct_vals};max_rank_err_over_all_values={}", acc.abs_err);
            if profile {
                let x = execute(inp, AGGR_GK_PROF_ELF);
                let (got, ph): (GkAggrOutput, [u64; 10]) = x.session.journal.decode().unwrap();
                let eq = got == native;
                let result = format!(
                    "{result_base};PHASES startup={} input_read={} chain_verify={} flatten={} gk_insert={} gk_compress={} merkle_root={} state_commit={} epoch_link={} unaccounted={} compress_calls={}",
                    ph[9], ph[8], ph[0], ph[1], ph[2], ph[3], ph[4], ph[5], ph[6],
                    x.user_cycles.saturating_sub(ph[0..7].iter().sum::<u64>() + ph[8] + ph[9]), ph[7]
                );
                emit("profile", "aggr", "aggr_gk_prof", "-", 1, idx.to_string(), m, m, cbs, st.tuples.len(), &x, 1, eq,
                    result, exact, &acc, &qc, None);
                if !eq {
                    eprintln!("gk: WARNING profiling journal != native output");
                }
                if !checks_ok {
                    eprintln!("gk: WARNING accuracy check failed (min_kept/q_ok/rank columns)");
                }
                if !eq || !checks_ok {
                    std::process::exit(1);
                }
                return;
            }
            let x = execute(inp, AGGR_GK_ELF);
            let got: GkAggrOutput = x.session.journal.decode().unwrap();
            let eq = got == native;
            if !eq {
                eprintln!("gk: WARNING aggregation journal != native output");
            }
            if !checks_ok {
                eprintln!("gk: WARNING accuracy check failed (min_kept/q_ok/rank columns)");
            }
            let proved = if do_prove && eq && checks_ok { Some(prove(inp, AGGR_GK_ELF, AGGR_GK_ID, &native)) } else { None };
            emit(if proved.is_some() { "proved" } else { "exec" }, "aggr", "aggr_gk", "-", 1, idx.to_string(), m, m,
                cbs, st.tuples.len(), &x, 1, eq, result_base, exact, &acc, &qc, proved);
            if !eq || !checks_ok {
                std::process::exit(1);
            }
        }
        "query" => {
            if flag("--profile") {
                die("--profile is only wired for --mode aggr");
            }
            let do_prove = flag("--prove");
            let n = arg_u64("--epochs", 1) as usize;
            if n == 0 || n * m > keys.len() {
                die(&format!("--epochs {n} needs {} keys, {keys_path} has {}", n * m, keys.len()));
            }
            let qname = arg_str("--query").unwrap_or_else(|| die("--query rank|p50|p90|p99 is required"));
            let query = match qname.as_str() {
                "rank" => GkQuery::Rank { value: arg_u64("--rank-value", 1 << 20) as u32 },
                "p50" => GkQuery::Quantile { phi_num: 1, phi_den: 2 },
                "p90" => GkQuery::Quantile { phi_num: 9, phi_den: 10 },
                "p99" => GkQuery::Quantile { phi_num: 99, phi_den: 100 },
                o => die(&format!("--query {o}: expected rank|p50|p90|p99")),
            };
            let (outs, links) = aggregate(&keys, n, m, cbs);
            let states: Vec<GkEpochState> = outs.into_iter().map(|(_, s)| s).collect();
            let tuples: usize = states.iter().map(|s| s.tuples.len()).sum();
            let epoch_vals: Vec<Vec<u32>> =
                (0..n).map(|e| keys[e * m..(e + 1) * m].iter().map(|&k| k & VALUE_MASK).collect()).collect();
            let epoch_refs: Vec<&[u32]> = epoch_vals.iter().map(|v| &v[..]).collect();
            let qc = q_checks(&states, &epoch_refs, false);
            let input = GkQueryInput { query, epoch_states: states, epoch_chain_links: links };
            let native = run_gk_query(&input).suppress_if_low_support();
            let x = execute(&input, QUERIER_GK_ELF);
            let got: GkQueryOutput = x.session.journal.decode().unwrap();
            let eq = got == native;

            let mut vals: Vec<u32> = keys[..n * m].iter().map(|&k| k & VALUE_MASK).collect();
            vals.sort_unstable();
            let nn = vals.len() as u64;
            let eps_n = nn as f64 / GK_EPS_DEN as f64;
            let cert_err = got.result.cert_err();
            let sup = if got.suppressed { " SUPPRESSED" } else { "" };
            let (result, exact, acc) = match got.result {
                GkQueryResult::Rank { value, estimate, lo, hi, .. } => {
                    let ex = vals.partition_point(|&v| v <= value) as u64;
                    (
                        format!("rank({value}) est={estimate};lo={lo};hi={hi}{sup}"),
                        format!("rank({value})={ex}"),
                        Acc { abs_err: estimate.abs_diff(ex), cert_err, eps_n, exact_in_cert: lo <= ex && ex <= hi },
                    )
                }
                GkQueryResult::Quantile { phi_num, phi_den, target_rank: r, value, rmin, rmax, .. } => {
                    // true position range of the returned value, distance to the target rank
                    let lt = vals.partition_point(|&v| v < value) as u64;
                    let le = vals.partition_point(|&v| v <= value) as u64;
                    let err = if r < lt + 1 { lt + 1 - r } else if r > le { r - le } else { 0 };
                    let exq = vals[(r.max(1) - 1) as usize];
                    (
                        format!("q({phi_num}/{phi_den}) r={r};value={value};rmin={rmin};rmax={rmax}{sup}"),
                        format!("q={exq};returned_value_true_ranks=[{}..{le}]", lt + 1),
                        Acc { abs_err: err, cert_err, eps_n, exact_in_cert: lt < rmax && rmin <= le && le > lt },
                    )
                }
            };
            let checks_ok = qc.all_ok(&acc);
            let proved =
                if do_prove && eq && checks_ok { Some(prove(&input, QUERIER_GK_ELF, QUERIER_GK_ID, &native)) } else { None };
            emit(if proved.is_some() { "proved" } else { "exec" }, "query", "querier_gk", &qname, n, "-".into(), m,
                n * m, cbs, tuples, &x, got.state_commits.len(), eq, result, exact, &acc, &qc, proved);
            if !eq {
                eprintln!("gk: WARNING query journal != native output");
            }
            if !checks_ok {
                eprintln!("gk: WARNING accuracy check failed (min_kept/q_ok/rank columns)");
            }
            if !eq || !checks_ok {
                std::process::exit(1);
            }
        }
        o => die(&format!("--mode {o}: expected aggr|query")),
    }
}

