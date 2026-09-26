// HyperLogLog baseline in zk-Analytics' architecture: host driver.
//
// Patterned on ../../cyc/src/bin/shipped.rs (the shipped-structure arm). The epochs,
// the source batch hash chain and the epoch chain are built exactly as there:
//   records  data/aol.keys (flat little-endian u32). Epoch e = keys [e*m, (e+1)*m),
//            m = --epoch-size (16,384 = zkSketch's matched epoch; epoch 0 is our CM epoch).
//   key_id   Event::make_key_id(0, key)  (zkvm-common/src/lib.rs:88, as shipped.rs)
//   value    1 (ignored by HLL);  ts = global record index
//   batches  one source (id 0), stream order, --batch records per batch (default 8, their
//            --commit-batch-size default); SHA-256 batch chain continued across epochs
//            (prev_source_chain_tips carried, source_batch_seq continues); epoch e's
//            prev_chain_hash = epoch e-1's final_chain_hash.
//
// Modes:
//   --mode aggr  : execute the HLL AGGREGATION guest on epoch --epoch-index (earlier
//                  epochs are aggregated natively only to carry the chain tips).
//   --mode query : aggregate epochs 0..n natively, then execute the HLL QUERY guest
//                  over all n epoch states (chain links + state commits re-verified).
// EXECUTOR ONLY unless --prove (succinct receipt, their ProverOpts::succinct()).
//
// Checks on every run:
//   journal_eq_native  the guest journal equals the same core function run natively
//   ref_check          an independent host HLL (own index/rank code, f64 sum of 2^-M,
//                      std ln) over the raw keys matches the guest's registers/estimate
//   exact / rel_err    the exact distinct count of the covered keys
//
// Usage:
//   hll --header
//   hll --mode aggr  [--epoch-index 0] [--epoch-size 16384] [--batch 8] [--keys PATH] [--prove]
//   hll --mode query --epochs N [--words] [--epoch-size 16384] [--batch 8] [--keys PATH] [--prove]
//   --words: run the hll_query_words guest (same computation and journal; registers sent
//            in serde's default Vec<u8> encoding, one zkVM word each) -- sensitivity row.

use std::collections::HashSet;
use std::time::Instant;

use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, SessionInfo};
use zka_hll_core::{
    batch_chain_hash, hll_epoch_state_commit, hll_estimate, hll_hash64, process_hll_aggr_with_state,
    run_hll_query, BatchInput, EpochChainLink, HllAggrInput, HllAggrOutput, HllEpochState, HllQuery,
    HllQueryInput, HllQueryInputWords, HllQueryOutput, HllQueryResult, HLL_M, HLL_P,
};
use zka_hll_methods::{
    HLL_AGGR_ELF, HLL_AGGR_ID, HLL_QUERY_ELF, HLL_QUERY_ID, HLL_QUERY_WORDS_ELF, HLL_QUERY_WORDS_ID,
};
use zkvm_common::Event;

/// MODELED prove time: segments x s/segment. Central value and envelope are the four
/// CPU CM prove anchors in ../README.md ("Modeled prove time and the anchors behind it").
const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] = &["--mode", "--epochs", "--epoch-index", "--keys", "--epoch-size", "--batch"];
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
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t2 = Instant::now();
        receipt.verify(id).expect("verify failed");
        best = best.min(t2.elapsed().as_secs_f64() * 1000.0);
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

const HEADER: &str = "system,arm,family,mode,guest,query,hll_p,registers,epochs,epoch_index,epoch_records,records,batch,value_enc,hash,distinct_keys,input_bytes,user_cycles,padded_cycles,segments,max_po2,cycles_per_record,cycles_per_epoch,exec_s,journal_bytes,state_commits,journal_eq_native,ref_check,result,exact,rel_err,prof,prove_s,verify_ms,receipt_bytes,s_per_segment,prove_segments,prove_total_cycles,prove_paging_cycles,MODELED_prove_s,MODELED_prove_s_lo,MODELED_prove_s_hi,model,image_id";

#[allow(clippy::too_many_arguments)]
fn emit(
    mode: &str, guest: &str, query: &str, epochs: usize, epoch_index: String, m: usize, records: usize,
    cbs: usize, distinct: usize, x: &Exec, state_commits: usize, eq: bool, refc: &str, result: String,
    exact: String, rel_err: f64, prof: String, p: Option<Proved>, id: [u32; 8],
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
        "zka-arch,hll,hll,{mode},{guest},{query},{HLL_P},{HLL_M},{epochs},{epoch_index},{m},{records},{cbs},1,fnv1a+splitmix64,{distinct},{},{},{},{},{},{:.1},{:.1},{:.3},{},{state_commits},{eq},{refc},{result},{exact},{rel_err:.6},{prof},{ps},{vm},{rb},{sps},{pseg},{ptot},{ppag},{:.1},{:.1},{:.1},MODELED=segments*{S_PER_SEG} s/seg (CM-guest CPU anchors; not measured),{}",
        x.input_bytes, x.user_cycles, x.padded_cycles, x.segments, x.max_po2,
        x.user_cycles as f64 / records as f64, x.user_cycles as f64 / epochs as f64, x.exec_s, x.journal_bytes,
        seg * S_PER_SEG, seg * S_PER_SEG_LO, seg * S_PER_SEG_HI, image_id_hex(id),
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

            let x = execute(inp, HLL_AGGR_ELF);
            let (_, native) = process_hll_aggr_with_state(inp);
            let got: HllAggrOutput = x.session.journal.decode().expect("decode journal");
            let eq = got == native;
            // The aggregation journal holds commitments only; the per-epoch estimate is
            // computed natively from the committed state, for the accuracy column.
            let (est, res) = result_str(&hll_estimate(&st.registers));
            let refc = ref_check(&st.registers, slice, est);
            let p = do_prove.then(|| prove(inp, HLL_AGGR_ELF, HLL_AGGR_ID, &native));
            if !eq {
                eprintln!("hll: WARNING aggregation journal != native output");
            }
            emit("aggr", "hll_aggr", "-", 1, idx.to_string(), m, m, cbs, distinct, &x, 1, eq, &refc,
                format!("journal=commits_only;native_epoch_{res}"), format!("distinct={distinct}"),
                (est as f64 - distinct as f64) / distinct as f64,
                prof(&x, &["chain", "flatten", "update", "commit"]), p, HLL_AGGR_ID);
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
                prof(&x, &["links", "commits", "merge", "est_pass", "est_f64"]), p, id);
        }
        o => die(&format!("--mode {o}: expected aggr|query")),
    }
}
