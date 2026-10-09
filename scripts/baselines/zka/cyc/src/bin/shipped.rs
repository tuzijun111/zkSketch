// SHIPPED-STRUCTURE ARM (revision Step 3, arm A): zk-Analytics' OWN three epoch
// summary types, run on REAL AOL records, for the query classes zkSketch covers.
//
//   family     | aggregation guest            | query guest (query)                     | our analogue
//   -----------+------------------------------+-----------------------------------------+-------------
//   samples    | aggr_samples  (AGGR_SAMPLES) | querier-guest-samples (SumTopk{limit})  | SS heavy hitters
//   histogram  | aggr_histogram               | querier-guest-histogram (P90)           | GK quantiles
//   cm         | aggr_cm                      | querier-guest-cm (Estimate{key}, Topk)  | CM point query
//
// Nothing about their structures is reimplemented. Every epoch state comes out of
// THEIR aggregation entry points (aggregator/core/src/lib.rs process_*_aggr_with_state),
// every chain link is the one their aggregation journal would publish, and the
// guests are their unmodified ELFs (aggregator/methods, querier/methods @ d4a5a9a).
//
// Records: data/aol.keys (flat little-endian u32, 2^20 keys). Epoch e holds keys
// [e*m, (e+1)*m) -- the same slicing as zkSketch's exp_compose batches_from() with
// m = 16,384, so epoch 0 is exactly the records of our matched CM epoch.
//   key_id = Event::make_key_id(0, key as u64)   (their canonical 15-byte key id,
//            zkvm-common/src/lib.rs:76; same encoding as acc_zka.rs)
//   value  = 1 for samples and cm (frequency counting: samples sums become exact
//            per-key counts, the CM table a frequency table, as in cmp.rs/acc_zka.rs)
//          = key & 0x1F_FFFF for histogram (the 21-bit coordinate zkSketch's GK
//            leaf summarises, src/experiments/stream_compose.rs gk_vals_of)
//   ts     = global record index
// Batches: one source (id 0), stream order, chunks of --batch records (default 8,
// their --commit-batch-size default), SHA-256 batch hash chain continued across
// epochs exactly as their aggregator host does (prev_source_chain_tips carried,
// source_batch_seq continues). Epoch chain: epoch e's prev_chain_hash is epoch
// e-1's final_chain_hash (one aggregator).
//
// Modes:
//   --mode aggr  : execute the family's AGGREGATION guest on epoch --epoch-index
//                  (default 0; earlier epochs are processed natively only to obtain
//                  the carried chain tips).
//   --mode query : aggregate epochs 0..n natively (their code), then execute the
//                  family's QUERY guest over all n populated epoch states.
// EXECUTOR ONLY unless --prove is passed (opt-in; not used by the shipped arm).
//
// Every run checks the guest journal against their native function on the same
// input (aggregation: full output equality; query: output equality after
// suppress_if_low_support, exactly what the guest commits), and reports the exact
// plaintext answer next to theirs.
//
// Usage:
//   shipped --header
//   shipped --mode aggr  --family samples|histogram|cm [--epoch-index 0]
//   shipped --mode query --family samples   --epochs N [--limit 10]              (SumTopk)
//   shipped --mode query --family histogram --epochs N                           (P90)
//   shipped --mode query --family cm        --epochs N --query estimate|topk [--limit 10]
//   common: [--keys PATH] [--epoch-size 16384] [--batch 8] [--prove]
//           [--key-id aol|const]   (const: histogram only, see key_id_mode())

use std::collections::HashMap;
use std::time::Instant;

use aggregator_core::{
    batch_chain_hash, cm_epoch_state_commit, histogram_bucket_index, histogram_epoch_state_commit,
    process_cm_aggr_with_state, process_histogram_aggr_with_state, process_samples_aggr_with_state,
    samples_epoch_state_commit, BatchInput, CmAggrInput, CmEpochState, EpochChainLink,
    HistogramAggrInput, HistogramEpochState, SamplesAggrInput, SamplesEpochState, CM_TOPK_SLOTS,
    HISTOGRAM_SLOTS,
};
use aggregator_methods::{
    AGGR_CM_ELF, AGGR_CM_ID, AGGR_HISTOGRAM_ELF, AGGR_HISTOGRAM_ID, AGGR_SAMPLES_ELF,
    AGGR_SAMPLES_ID,
};
use querier_core::{
    CmQuery, CmQueryInput, CmQueryOutput, CmQueryResult, HistogramQuery, HistogramQueryInput,
    HistogramQueryOutput, HistogramQueryResult, SamplesQuery, SamplesQueryInput,
    SamplesQueryOutput, SamplesQueryResult,
};
use querier_methods::{
    QUERIER_GUEST_CM_ELF, QUERIER_GUEST_CM_ID, QUERIER_GUEST_HISTOGRAM_ELF,
    QUERIER_GUEST_HISTOGRAM_ID, QUERIER_GUEST_SAMPLES_ELF, QUERIER_GUEST_SAMPLES_ID,
};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, SessionInfo};
use zkvm_common::{Event, KEY_BYTES_LEN};

const HIST_VALUE_MASK: u32 = 0x001F_FFFF;

// ------------------------------------------------------------------ arguments
// Strict: an unknown flag or an unparsable value is an error, never a silent default.
const VALUE_FLAGS: &[&str] = &[
    "--mode", "--family", "--query", "--epochs", "--epoch-index", "--limit", "--keys",
    "--epoch-size", "--batch", "--key-id",
];
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
    eprintln!("shipped: {msg}");
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Samples,
    Histogram,
    Cm,
}
impl Family {
    fn name(self) -> &'static str {
        match self {
            Family::Samples => "samples",
            Family::Histogram => "histogram",
            Family::Cm => "cm",
        }
    }
    fn value_of(self, key: u32) -> u32 {
        match self {
            Family::Histogram => key & HIST_VALUE_MASK,
            _ => 1,
        }
    }
    fn value_enc(self) -> &'static str {
        match self {
            Family::Histogram => "key&0x1FFFFF",
            _ => "1",
        }
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

/// Source 0's SHA-256 batch chain, continued across epochs exactly as their
/// aggregator host carries it (prev_source_chain_tips + a continuing seq).
struct SourceChain {
    tip: [u8; 32],
    next_seq: u64,
}
impl SourceChain {
    fn batches(&mut self, events: &[Event], cbs: usize) -> Vec<BatchInput> {
        let mut out = Vec::with_capacity(events.len().div_ceil(cbs));
        for chunk in events.chunks(cbs) {
            let evs = chunk.to_vec();
            // seq 0 always restarts from the zero tip (aggregator/core/src/lib.rs verify_and_compute_chain)
            let prev = if self.next_seq == 0 { [0u8; 32] } else { self.tip };
            let h = batch_chain_hash(prev, &evs);
            out.push(BatchInput { source_id: 0, source_batch_seq: self.next_seq, events: evs, sent_batch_hash: h });
            self.tip = h;
            self.next_seq += 1;
        }
        out
    }
}

/// `--key-id aol` (default): key_id = the AOL key. `--key-id const` (histogram only):
/// every record carries key_id 0 and only the value varies -- the cheapest valid
/// encoding of a GLOBAL quantile in their per-key histogram (one KeyHistogram per
/// epoch instead of one per distinct key), i.e. the steelman for their P90 cost.
fn key_id_mode() -> &'static str {
    match arg_str("--key-id").as_deref() {
        None | Some("aol") => "aol",
        Some("const") => "const",
        Some(o) => die(&format!("--key-id {o}: expected aol|const")),
    }
}

fn epoch_events(keys: &[u32], e: usize, m: usize, fam: Family) -> Vec<Event> {
    let constant = key_id_mode() == "const";
    (e * m..(e + 1) * m)
        .map(|i| Event {
            ts: i as u32,
            key_id: Event::make_key_id(0, if constant { 0 } else { keys[i] as u64 }),
            value: fam.value_of(keys[i]),
        })
        .collect()
}

// One epoch's aggregation input + the state/link THEIR native code produces for it.
enum EpochOut {
    S(SamplesAggrInput, SamplesEpochState),
    H(HistogramAggrInput, HistogramEpochState),
    C(CmAggrInput, CmEpochState),
}

/// Aggregate epochs 0..n natively with their entry points, chaining epochs and
/// source tips as their host does. Returns per-epoch (input, state) and links.
fn aggregate(keys: &[u32], n: usize, m: usize, cbs: usize, fam: Family) -> (Vec<EpochOut>, Vec<EpochChainLink>) {
    let mut chain = SourceChain { tip: [0u8; 32], next_seq: 0 };
    let mut prev_chain_hash = [0u8; 32];
    let mut prev_tips: Vec<(u32, u64, [u8; 32])> = Vec::new();
    let mut outs = Vec::with_capacity(n);
    let mut links = Vec::with_capacity(n);
    for e in 0..n {
        let batches = chain.batches(&epoch_events(keys, e, m, fam), cbs);
        let (link, tips, eo) = match fam {
            Family::Samples => {
                let inp = SamplesAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
                let (st, out) = process_samples_aggr_with_state(&inp);
                let es = SamplesEpochState::from(&st);
                assert_eq!(samples_epoch_state_commit(&es), out.state_commit, "samples epoch {e}: commit mismatch");
                assert_eq!(out.n_events as usize, m);
                (out.epoch_chain_link, out.final_source_chain_tips, EpochOut::S(inp, es))
            }
            Family::Histogram => {
                let inp = HistogramAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
                let (st, out) = process_histogram_aggr_with_state(&inp);
                assert_eq!(histogram_epoch_state_commit(&st), out.state_commit, "histogram epoch {e}: commit mismatch");
                assert_eq!(out.n_events as usize, m);
                (out.epoch_chain_link, out.final_source_chain_tips, EpochOut::H(inp, st))
            }
            Family::Cm => {
                let inp = CmAggrInput { prev_chain_hash, batches, prev_source_chain_tips: prev_tips.clone() };
                let (st, out) = process_cm_aggr_with_state(&inp);
                let es = CmEpochState::from(&st);
                assert_eq!(cm_epoch_state_commit(&es), out.state_commit, "cm epoch {e}: commit mismatch");
                assert_eq!(out.n_events as usize, m);
                (out.epoch_chain_link, out.final_source_chain_tips, EpochOut::C(inp, es))
            }
        };
        assert_eq!(link.prev_chain_hash, prev_chain_hash);
        prev_chain_hash = link.final_chain_hash;
        prev_tips = tips;
        links.push(link);
        outs.push(eo);
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

impl Exec {
    fn from_session(session: SessionInfo, exec_s: f64, input_bytes: usize) -> Self {
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
}

// Macros rather than generic fns: a `T: serde::Serialize` bound would need serde as
// a direct dependency, which changes cyc/Cargo.lock and breaks the --locked builds.
macro_rules! execute {
    ($input:expr, $elf:expr) => {{
        let input = $input;
        let input_bytes = risc0_zkvm::serde::to_vec(input).expect("serialize input").len() * 4;
        let env = ExecutorEnv::builder().write(input).unwrap().build().unwrap();
        let t = Instant::now();
        let session = default_executor().execute(env, $elf).expect("guest execution failed");
        Exec::from_session(session, t.elapsed().as_secs_f64(), input_bytes)
    }};
}

struct Proved {
    prove_s: f64,
    verify_ms: f64,
    receipt_bytes: usize,
}

/// Opt-in (--prove). Their shipped tier: ProverOpts::succinct() at every prove site.
/// Checks the PROVED journal against their native output of type $T.
macro_rules! prove {
    ($input:expr, $elf:expr, $id:expr, $expect:expr, $T:ty) => {{
        let env = ExecutorEnv::builder().write($input).unwrap().build().unwrap();
        let t = Instant::now();
        let info = default_prover().prove_with_opts(env, $elf, &ProverOpts::succinct()).expect("prove failed");
        let prove_s = t.elapsed().as_secs_f64();
        let receipt = info.receipt;
        // verify_ms = the best of 5 in-process calls (unchanged); every call, and a
        // bincode decode of the serialized receipt, go to stderr for the six-sketch
        // verify-protocol comparison (../README.md).
        let mut times: Vec<f64> = Vec::with_capacity(5);
        for _ in 0..5 {
            let t2 = Instant::now();
            receipt.verify($id).expect("verify failed");
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
        let got: $T = receipt.journal.decode().expect("decode proved journal");
        assert_eq!(&got, $expect, "proved journal != native");
        Proved { prove_s, verify_ms: best, receipt_bytes: bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0) }
    }};
}

// ------------------------------------------------------------ ground truth
fn exact_counts(keys: &[u32]) -> HashMap<u32, u64> {
    let mut c = HashMap::new();
    for &k in keys {
        *c.entry(k).or_insert(0u64) += 1;
    }
    c
}
/// (count desc, key asc) -- deterministic
fn exact_top(counts: &HashMap<u32, u64>, l: usize) -> Vec<(u32, u64)> {
    let mut v: Vec<(u32, u64)> = counts.iter().map(|(&k, &c)| (k, c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(l);
    v
}
fn join<T: std::fmt::Display>(v: &[T]) -> String {
    v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(";")
}

const HEADER: &str = "system,arm,mode,guest,family,query,topk_slots,histogram_slots,epochs,epoch_index,epoch_records,records,batch,value_enc,limit,distinct_keys,per_key_entries,input_bytes,user_cycles,padded_cycles,segments,max_po2,exec_s,journal_bytes,state_commits,journal_eq_native,result,exact,prove_s,verify_ms,receipt_bytes,s_per_segment,key_id";

#[allow(clippy::too_many_arguments)]
fn emit(
    mode: &str, guest: &str, fam: Family, query: &str, epochs: usize, epoch_index: String, m: usize,
    records: usize, cbs: usize, limit: String, distinct: usize, per_key_entries: usize, x: &Exec,
    state_commits: usize, eq: bool, result: String, exact: String, p: Option<Proved>,
) {
    let (ps, vm, rb, sps) = match p {
        Some(p) => (
            format!("{:.3}", p.prove_s),
            format!("{:.3}", p.verify_ms),
            p.receipt_bytes.to_string(),
            format!("{:.3}", p.prove_s / x.segments.max(1) as f64),
        ),
        None => ("NaN".into(), "NaN".into(), "0".into(), "NaN".into()),
    };
    println!(
        "zka,shipped,{mode},{guest},{},{query},{},{},{epochs},{epoch_index},{m},{records},{cbs},{},{limit},{distinct},{per_key_entries},{},{},{},{},{},{:.3},{},{state_commits},{eq},{result},{exact},{ps},{vm},{rb},{sps},{}",
        fam.name(), CM_TOPK_SLOTS, HISTOGRAM_SLOTS, fam.value_enc(), x.input_bytes, x.user_cycles,
        x.padded_cycles, x.segments, x.max_po2, x.exec_s, x.journal_bytes, key_id_mode(),
    );
}

fn main() {
    validate_args();
    if flag("--header") {
        println!("{HEADER}");
        return;
    }
    let mode = arg_str("--mode").unwrap_or_else(|| die("--mode aggr|query is required"));
    let fam = match arg_str("--family").as_deref() {
        Some("samples") => Family::Samples,
        Some("histogram") => Family::Histogram,
        Some("cm") => Family::Cm,
        _ => die("--family samples|histogram|cm is required"),
    };
    let keys_path = arg_str("--keys").unwrap_or_else(|| {
        format!("{}/../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR"))
    });
    let m = arg_usize("--epoch-size", 16_384);
    let cbs = arg_usize("--batch", 8);
    let do_prove = flag("--prove");
    if m == 0 || cbs == 0 {
        die("--epoch-size and --batch must be > 0");
    }
    if key_id_mode() == "const" && fam != Family::Histogram {
        die("--key-id const is only meaningful for --family histogram");
    }
    let keys = load_keys(&keys_path);

    match mode.as_str() {
        "aggr" => {
            let idx = arg_usize("--epoch-index", 0);
            if (idx + 1) * m > keys.len() {
                die(&format!("epoch {idx} needs {} keys, {keys_path} has {}", (idx + 1) * m, keys.len()));
            }
            let (outs, _links) = aggregate(&keys, idx + 1, m, cbs, fam);
            let slice = &keys[idx * m..(idx + 1) * m];
            let counts = exact_counts(slice);
            let distinct = counts.len();
            // The aggregation guest commits only commitments; equality with their
            // native output is the correctness check. The "result" column records
            // the epoch-state size the query side will later have to re-hash.
            let (guest, x, eq, entries, result, proved) = match &outs[idx] {
                EpochOut::S(inp, es) => {
                    let x = execute!(inp, AGGR_SAMPLES_ELF);
                    let (_, native) = process_samples_aggr_with_state(inp);
                    let got: aggregator_core::SamplesAggrOutput = x.session.journal.decode().unwrap();
                    let p = do_prove.then(|| prove!(inp, AGGR_SAMPLES_ELF, AGGR_SAMPLES_ID, &native, aggregator_core::SamplesAggrOutput));
                    ("aggr_samples", x, got == native, es.per_key.len(), format!("state_entries={}", es.per_key.len()), p)
                }
                EpochOut::H(inp, st) => {
                    let x = execute!(inp, AGGR_HISTOGRAM_ELF);
                    let (_, native) = process_histogram_aggr_with_state(inp);
                    let got: aggregator_core::HistogramAggrOutput = x.session.journal.decode().unwrap();
                    let p = do_prove.then(|| prove!(inp, AGGR_HISTOGRAM_ELF, AGGR_HISTOGRAM_ID, &native, aggregator_core::HistogramAggrOutput));
                    let e = st.per_key_histograms.len();
                    ("aggr_histogram", x, got == native, e, format!("state_entries={e}"), p)
                }
                EpochOut::C(inp, es) => {
                    let x = execute!(inp, AGGR_CM_ELF);
                    let (_, native) = process_cm_aggr_with_state(inp);
                    let got: aggregator_core::CmAggrOutput = x.session.journal.decode().unwrap();
                    let p = do_prove.then(|| prove!(inp, AGGR_CM_ELF, AGGR_CM_ID, &native, aggregator_core::CmAggrOutput));
                    let occ = es.heap_occ.iter().filter(|&&o| o != 0).count();
                    ("aggr_cm", x, got == native, occ, format!("heap_occupied={occ}"), p)
                }
            };
            if !eq {
                eprintln!("shipped: WARNING aggregation journal != native output");
            }
            emit("aggr", guest, fam, "-", 1, idx.to_string(), m, m, cbs, "-".into(), distinct, entries, &x, 1, eq,
                result, format!("distinct={distinct}"), proved);
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
            let (outs, links) = aggregate(&keys, n, m, cbs, fam);
            let prefix = &keys[..n * m];
            let counts = exact_counts(prefix);
            let distinct = counts.len();
            match fam {
                Family::Samples => {
                    let states: Vec<SamplesEpochState> =
                        outs.into_iter().map(|o| if let EpochOut::S(_, s) = o { s } else { unreachable!() }).collect();
                    let entries: usize = states.iter().map(|s| s.per_key.len()).sum();
                    let input = SamplesQueryInput {
                        query: SamplesQuery::SumTopk { limit: limit as u16 },
                        epoch_states: states,
                        epoch_chain_links: links,
                    };
                    let native = querier_core::run_samples_query(&input).suppress_if_low_support();
                    let x = execute!(&input, QUERIER_GUEST_SAMPLES_ELF);
                    let got: SamplesQueryOutput = x.session.journal.decode().unwrap();
                    let items: Vec<u64> = match &got.result {
                        SamplesQueryResult::SumTopk { items } => items.iter().map(|i| i.sum).collect(),
                        _ => unreachable!(),
                    };
                    let ex: Vec<u64> = exact_top(&counts, limit.min(CM_TOPK_SLOTS)).iter().map(|p| p.1).collect();
                    let p = do_prove.then(|| prove!(&input, QUERIER_GUEST_SAMPLES_ELF, QUERIER_GUEST_SAMPLES_ID, &native, SamplesQueryOutput));
                    emit("query", "querier_samples", fam, "sum_topk", n, "-".into(), m, n * m, cbs, limit.to_string(),
                        distinct, entries, &x, got.state_commits.len(), got == native,
                        format!("top={}{}", join(&items), if got.suppressed { " SUPPRESSED" } else { "" }),
                        format!("top={}", join(&ex)), p);
                }
                Family::Histogram => {
                    let states: Vec<HistogramEpochState> =
                        outs.into_iter().map(|o| if let EpochOut::H(_, s) = o { s } else { unreachable!() }).collect();
                    let entries: usize = states.iter().map(|s| s.per_key_histograms.len()).sum();
                    let input = HistogramQueryInput { query: HistogramQuery::P90, epoch_states: states, epoch_chain_links: links };
                    let native = querier_core::run_histogram_query(&input).suppress_if_low_support();
                    let x = execute!(&input, QUERIER_GUEST_HISTOGRAM_ELF);
                    let got: HistogramQueryOutput = x.session.journal.decode().unwrap();
                    let p90 = match &got.result {
                        HistogramQueryResult::P90 { p90_value, .. } => *p90_value,
                        _ => unreachable!(),
                    };
                    // Exact P90 of the same values, and the log2 bin it lies in:
                    // histogram_bucket_index(v) = floor(log2 v) => bin b holds [2^b, 2^(b+1)).
                    let mut vals: Vec<u64> = prefix.iter().map(|&k| fam.value_of(k) as u64).collect();
                    vals.sort_unstable();
                    let rank = (vals.len() * 9).div_ceil(10).max(1); // nearest-rank P90
                    let ex = vals[rank - 1];
                    let b = histogram_bucket_index(ex);
                    let p = do_prove.then(|| prove!(&input, QUERIER_GUEST_HISTOGRAM_ELF, QUERIER_GUEST_HISTOGRAM_ID, &native, HistogramQueryOutput));
                    emit("query", "querier_histogram", fam, "p90", n, "-".into(), m, n * m, cbs, "-".into(),
                        distinct, entries, &x, got.state_commits.len(), got == native,
                        format!("p90_value={p90}{}", if got.suppressed { " SUPPRESSED" } else { "" }),
                        format!("p90={ex} bin={b} [{}..{})", 1u64 << b, 1u64 << (b + 1)), p);
                }
                Family::Cm => {
                    let q = arg_str("--query").unwrap_or_else(|| die("cm needs --query estimate|topk"));
                    let states: Vec<CmEpochState> =
                        outs.into_iter().map(|o| if let EpochOut::C(_, s) = o { s } else { unreachable!() }).collect();
                    let occ: usize = states.iter().map(|s| s.heap_occ.iter().filter(|&&o| o != 0).count()).sum();
                    let top = exact_top(&counts, limit);
                    let (query, qname, exact) = match q.as_str() {
                        // Heavy-key point query: the heaviest key of the whole prefix.
                        "estimate" => {
                            let (k, c) = top[0];
                            let key: [u8; KEY_BYTES_LEN] = Event::make_key_id(0, k as u64);
                            (CmQuery::Estimate { key }, "estimate", format!("key={k} exact={c}"))
                        }
                        "topk" => (
                            CmQuery::Topk { limit: limit as u16 },
                            "topk",
                            format!("top={}", join(&top.iter().map(|p| p.1).collect::<Vec<_>>())),
                        ),
                        o => die(&format!("--query {o}: expected estimate|topk")),
                    };
                    let input = CmQueryInput { query, epoch_states: states, epoch_chain_links: links };
                    let native = querier_core::run_cm_query(&input).suppress_if_low_support();
                    let x = execute!(&input, QUERIER_GUEST_CM_ELF);
                    let got: CmQueryOutput = x.session.journal.decode().unwrap();
                    let res = match &got.result {
                        CmQueryResult::Estimate { estimate } => format!("estimate={estimate}"),
                        CmQueryResult::Topk { items } => {
                            format!("top={}", join(&items.iter().map(|i| i.count).collect::<Vec<_>>()))
                        }
                    };
                    let p = do_prove.then(|| prove!(&input, QUERIER_GUEST_CM_ELF, QUERIER_GUEST_CM_ID, &native, CmQueryOutput));
                    emit("query", "querier_cm", fam, qname, n, "-".into(), m, n * m, cbs,
                        if qname == "topk" { limit.to_string() } else { "-".into() },
                        distinct, occ, &x, got.state_commits.len(), got == native,
                        format!("{res}{}", if got.suppressed { " SUPPRESSED" } else { "" }), exact, p);
                }
            }
        }
        o => die(&format!("--mode {o}: expected aggr|query")),
    }
}
