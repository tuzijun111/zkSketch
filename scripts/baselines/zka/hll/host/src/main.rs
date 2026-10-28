// Host driver for the HLL port: executes the guests (and proves them with --prove), one CSV row per guest run.
// Usage: hll --header | hll --mode aggr|query [--epochs N] [--epoch-index I] [--words] [--prove] ...

use std::collections::HashSet;
use std::time::Instant;

use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, SessionInfo};
use zka_hll_core::{
    batch_chain_hash, hll_epoch_state_commit, hll_estimate, hll_hash64, process_hll_aggr_root,
    process_hll_aggr_with_state, run_hll_query, BatchInput, EpochChainLink, HllAggrInput, HllAggrOutput,
    HllAggrRootOutput, HllEpochState, HllQuery, HllQueryInput, HllQueryInputWords, HllQueryOutput, HllQueryResult,
    HllRoot, HLL_M, HLL_P,
};
use zka_hll_methods::{
    HLL_AGGR_ELF, HLL_AGGR_ID, HLL_AGGR_ROOT_ELF, HLL_AGGR_ROOT_ID, HLL_QUERY_ELF, HLL_QUERY_ID, HLL_QUERY_WORDS_ELF,
    HLL_QUERY_WORDS_ID,
};
use zkvm_common::Event;

/// MODELED_prove_s = segments x S_PER_SEG (computed, not measured), from the four CPU-proved CM guest runs
/// in scripts/baselines/zka/README.md: S_PER_SEG is aggr_cm T=100, n=512 (661.3 s / 22 segments = 30.06 s)
/// rounded; _lo/_hi use 29.73 and 30.79 s, the lowest and highest s/segment of the four.
const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] = &["--mode", "--epochs", "--epoch-index", "--keys", "--epoch-size", "--batch", "--root"];
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
    eprintln!("hll: {msg}");
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

/// Aggregate epochs 0..n natively, chaining epochs and source tips as their host does.
fn aggregate(keys: &[u32], n: usize, m: usize, cbs: usize) -> (Vec<(HllAggrInput, HllEpochState)>, Vec<EpochChainLink>) {
    let mut chain = SourceChain { tip: [0u8; 32], next_seq: 0 };
    let mut prev_chain_hash = [0u8; 32];
    let mut prev_tips: Vec<(u32, u64, [u8; 32])> = Vec::new();
    let mut outs = Vec::with_capacity(n);
    let mut links = Vec::with_capacity(n);
    for e in 0..n {
        let batches = chain.batches(&epoch_events(keys, e, m), cbs);
        let inp = HllAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
        let (st, out) = process_hll_aggr_with_state(&inp);
        assert_eq!(hll_epoch_state_commit(&st), out.state_commit, "epoch {e}: commit mismatch");
        assert_eq!(out.n_events as usize, m);
        assert_eq!(out.epoch_chain_link.prev_chain_hash, prev_chain_hash);
        prev_chain_hash = out.epoch_chain_link.final_chain_hash;
        prev_tips = out.final_source_chain_tips.clone();
        links.push(out.epoch_chain_link);
        outs.push((inp, st));
    }
    (outs, links)
}

// ----------------------------------------------------- independent reference
/// Registers straight from the raw keys, with index/rank computed by a bit loop
/// instead of the core's leading_zeros arithmetic.
fn ref_registers(keys: &[u32]) -> Vec<u8> {
    let mut regs = vec![0u8; HLL_M];
    for &k in keys {
        let h = hll_hash64(&Event::make_key_id(0, k as u64));
        let idx = (h & ((1u64 << HLL_P) - 1)) as usize;
        let mut rank = 1u8;
        let mut bit = 63i32;
        while bit >= HLL_P as i32 && (h >> bit) & 1 == 0 {
            rank += 1;
            bit -= 1;
        }
        if rank > regs[idx] {
            regs[idx] = rank;
        }
    }
    regs
}
/// Textbook estimator in plain f64 with std's ln.
fn ref_estimate(regs: &[u8]) -> f64 {
    let m = regs.len() as f64;
    let z: f64 = regs.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
    let raw = 0.7213 / (1.0 + 1.079 / m) * m * m / z;
    let v = regs.iter().filter(|&&r| r == 0).count();
    if raw <= 2.5 * m && v > 0 { m * (m / v as f64).ln() } else { raw }
}
fn ref_check(regs_guest: &[u8], keys: &[u32], est_guest: u64) -> String {
    let regs = ref_registers(keys);
    if regs != regs_guest {
        let diff = regs.iter().zip(regs_guest).filter(|(a, b)| a != b).count();
        return format!("FAIL(registers differ at {diff})");
    }
    let e = ref_estimate(&regs);
    if (e - est_guest as f64).abs() <= 0.5 + 1e-9 * e { "ok".into() } else { format!("FAIL(ref_estimate={e:.3})") }
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
    paging_cycles: u64,
}

/// --prove: succinct receipt (their ProverOpts::succinct()), journal checked against native.
fn prove<T: serde::Serialize, J: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
    input: &T, elf: &[u8], id: [u32; 8], expect: &J,
) -> Proved {
    let mut sink: Vec<u8> = Vec::new();
    let env = ExecutorEnv::builder().write(input).unwrap().stdout(&mut sink).build().unwrap();
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct()).expect("prove failed");
    let prove_s = t.elapsed().as_secs_f64();
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
    let got: J = receipt.journal.decode().expect("decode proved journal");
    assert_eq!(&got, expect, "proved journal != native");
    Proved {
        prove_s,
        verify_ms: best,
        receipt_bytes: bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0),
        segments: info.stats.segments,
        total_cycles: info.stats.total_cycles,
        paging_cycles: info.stats.paging_cycles,
    }
}

fn image_id_hex(id: [u32; 8]) -> String {
    id.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

const HEADER: &str = "system,arm,family,mode,guest,query,hll_p,registers,epochs,epoch_index,epoch_records,records,batch,value_enc,hash,distinct_keys,input_bytes,user_cycles,padded_cycles,segments,max_po2,cycles_per_record,cycles_per_epoch,exec_s,journal_bytes,state_commits,journal_eq_native,ref_check,result,exact,rel_err,prof,prove_s,verify_ms,receipt_bytes,s_per_segment,prove_segments,prove_total_cycles,prove_paging_cycles,MODELED_prove_s,MODELED_prove_s_lo,MODELED_prove_s_hi,model,image_id,root_variant,root_construction,variants_agree,state_commit";

/// Root variant columns of a row: (root_variant, root_construction, variants_agree, state_commit).
struct RootCols {
    variant: &'static str,
    construction: &'static str,
    agree: String,
    state_commit: String,
}
impl RootCols {
    fn query() -> Self {
        RootCols { variant: "-", construction: "-", agree: "-".into(), state_commit: "-".into() }
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// --root: None = legacy (the hll_aggr guest), Some(r) = the hll_aggr_root guest with r.
fn parse_root() -> (&'static str, Option<HllRoot>) {
    match arg_str("--root").as_deref() {
        None | Some("legacy") => ("legacy", None),
        Some("designed") => ("designed", Some(HllRoot::Buckets64)),
        Some("noroot") => ("noroot", Some(HllRoot::None)),
        Some(o) => die(&format!("--root {o}: expected legacy|designed|noroot")),
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    mode: &str, guest: &str, query: &str, epochs: usize, epoch_index: String, m: usize, records: usize,
    cbs: usize, distinct: usize, x: &Exec, state_commits: usize, eq: bool, refc: &str, result: String,
    exact: String, rel_err: f64, prof: String, p: Option<Proved>, id: [u32; 8], rc: &RootCols,
) {
    let (ps, vm, rb, sps, pseg, ptot, ppag) = match p {
        Some(p) => (
            format!("{:.3}", p.prove_s),
            format!("{:.3}", p.verify_ms),
            p.receipt_bytes.to_string(),
            format!("{:.3}", p.prove_s / p.segments.max(1) as f64),
            p.segments.to_string(),
            p.total_cycles.to_string(),
            p.paging_cycles.to_string(),
        ),
        None => ("NaN".into(), "NaN".into(), "0".into(), "NaN".into(), "0".into(), "0".into(), "0".into()),
    };
    let seg = x.segments as f64;
    println!(
        "zka-arch,hll,hll,{mode},{guest},{query},{HLL_P},{HLL_M},{epochs},{epoch_index},{m},{records},{cbs},1,fnv1a+splitmix64,{distinct},{},{},{},{},{},{:.1},{:.1},{:.3},{},{state_commits},{eq},{refc},{result},{exact},{rel_err:.6},{prof},{ps},{vm},{rb},{sps},{pseg},{ptot},{ppag},{:.1},{:.1},{:.1},MODELED=segments*{S_PER_SEG} s/seg (CM-guest CPU anchors; not measured),{},{},{},{},{}",
        x.input_bytes, x.user_cycles, x.padded_cycles, x.segments, x.max_po2,
        x.user_cycles as f64 / records as f64, x.user_cycles as f64 / epochs as f64, x.exec_s, x.journal_bytes,
        seg * S_PER_SEG, seg * S_PER_SEG_LO, seg * S_PER_SEG_HI, image_id_hex(id),
        rc.variant, rc.construction, rc.agree, rc.state_commit,
    );
}

fn result_str(r: &HllQueryResult) -> (u64, String) {
    match r {
        HllQueryResult::Estimate { estimate, raw_estimate, registers, zero_registers, linear_counting } => (
            *estimate,
            format!("estimate={estimate};raw={raw_estimate};m={registers};zero_registers={zero_registers};linear_counting={linear_counting}"),
        ),
    }
}

fn main() {
    validate_args();
    if flag("--header") {
        println!("{HEADER}");
        return;
    }
    if std::env::var("RISC0_DEV_MODE").map(|v| !v.is_empty()).unwrap_or(false) {
        die("RISC0_DEV_MODE is set; unset it (nothing here may run in dev mode)");
    }
    let mode = arg_str("--mode").unwrap_or_else(|| die("--mode aggr|query is required"));
    let keys_path = arg_str("--keys")
        .unwrap_or_else(|| format!("{}/../../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR")));
    let m = arg_usize("--epoch-size", 16_384);
    let cbs = arg_usize("--batch", 8);
    let do_prove = flag("--prove");
    if m == 0 || cbs == 0 {
        die("--epoch-size and --batch must be > 0");
    }
    let (root_name, root) = parse_root();
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
            let (outs, _links) = aggregate(&keys, idx + 1, m, cbs);
            let (inp, st) = &outs[idx];
            let slice = &keys[idx * m..(idx + 1) * m];
            let distinct = slice.iter().collect::<HashSet<_>>().len();

            // Every variant run natively on the same input: same state and journal except the root.
            let (_, legacy) = process_hll_aggr_with_state(inp);
            let (sd, designed) = process_hll_aggr_root(inp, HllRoot::Buckets64);
            let (sn, noroot) = process_hll_aggr_root(inp, HllRoot::None);
            let agree = &sd == st && &sn == st && designed.without_root() == legacy && noroot.without_root() == legacy
                && noroot.buckets_root == [0u8; 32] && designed.buckets_root != [0u8; 32];
            let (guest, x, eq, p, id, construction) = match root {
                None => {
                    let x = execute(inp, HLL_AGGR_ELF);
                    let got: HllAggrOutput = x.session.journal.decode().expect("decode journal");
                    let p = do_prove.then(|| prove(inp, HLL_AGGR_ELF, HLL_AGGR_ID, &legacy));
                    ("hll_aggr", x, got == legacy, p, HLL_AGGR_ID, "none")
                }
                Some(r) => {
                    let native: (HllRoot, HllAggrRootOutput) =
                        (r, if r == HllRoot::None { noroot.clone() } else { designed.clone() });
                    // The guest reads the HllRoot, then the input: a tuple serializes as the two in sequence.
                    let x = execute(&(r, inp), HLL_AGGR_ROOT_ELF);
                    let got: (HllRoot, HllAggrRootOutput) = x.session.journal.decode().expect("decode journal");
                    let p = do_prove.then(|| prove(&(r, inp), HLL_AGGR_ROOT_ELF, HLL_AGGR_ROOT_ID, &native));
                    ("hll_aggr_root", x, got == native, p, HLL_AGGR_ROOT_ID, r.construction())
                }
            };
            // The aggregation journal holds commitments only; the per-epoch estimate is
            // computed natively from the committed state, for the accuracy column.
            let (est, res) = result_str(&hll_estimate(&st.registers));
            let refc = ref_check(&st.registers, slice, est);
            if !eq {
                eprintln!("hll: WARNING aggregation journal != native output");
            }
            if !agree {
                eprintln!("hll: WARNING root variants disagree outside the root field");
            }
            let names: &[&str] = if root.is_some() {
                &["chain", "flatten", "update", "commit", "root"]
            } else {
                &["chain", "flatten", "update", "commit"]
            };
            let rc = RootCols { variant: root_name, construction, agree: agree.to_string(), state_commit: hex(&legacy.state_commit) };
            emit("aggr", guest, "-", 1, idx.to_string(), m, m, cbs, distinct, &x, 1, eq, &refc,
                format!("journal=commits_only;native_epoch_{res}"), format!("distinct={distinct}"),
                (est as f64 - distinct as f64) / distinct as f64, prof(&x, names), p, id, &rc);
            if !eq || !agree {
                std::process::exit(1);
            }
        }
        "query" => {
            let n = arg_usize("--epochs", 1);
            if n == 0 || n * m > keys.len() {
                die(&format!("--epochs {n} needs {} keys, {keys_path} has {}", n * m, keys.len()));
            }
            let (outs, links) = aggregate(&keys, n, m, cbs);
            let prefix = &keys[..n * m];
            let distinct = prefix.iter().collect::<HashSet<_>>().len();
            let states: Vec<HllEpochState> = outs.into_iter().map(|(_, s)| s).collect();
            let input = HllQueryInput { query: HllQuery::Estimate, epoch_states: states, epoch_chain_links: links };
            let native = run_hll_query(&input).suppress_if_low_support();
            let words = flag("--words");
            let (guest, elf, id) = if words {
                ("hll_query_words", HLL_QUERY_WORDS_ELF, HLL_QUERY_WORDS_ID)
            } else {
                ("hll_query", HLL_QUERY_ELF, HLL_QUERY_ID)
            };
            let winput = HllQueryInputWords::from(&input);
            let x = if words { execute(&winput, elf) } else { execute(&input, elf) };
            let got: HllQueryOutput = x.session.journal.decode().expect("decode journal");
            let eq = got == native;
            let (est, res) = result_str(&got.result);
            // Reference over the merged registers the guest must have formed.
            let mut merged = vec![0u8; HLL_M];
            for s in &input.epoch_states {
                for (a, &b) in merged.iter_mut().zip(&s.registers) {
                    *a = (*a).max(b);
                }
            }
            let refc = ref_check(&merged, prefix, est);
            let p = do_prove.then(|| if words { prove(&winput, elf, id, &native) } else { prove(&input, elf, id, &native) });
            if !eq {
                eprintln!("hll: WARNING query journal != native output");
            }
            emit("query", guest, "estimate", n, "-".into(), m, n * m, cbs, distinct, &x,
                got.state_commits.len(), eq, &refc,
                format!("{res}{}", if got.suppressed { " SUPPRESSED" } else { "" }),
                format!("distinct={distinct}"), (est as f64 - distinct as f64) / distinct as f64,
                prof(&x, &["links", "commits", "merge", "est_pass", "est_f64"]), p, id, &RootCols::query());
        }
        o => die(&format!("--mode {o}: expected aggr|query")),
    }
}
