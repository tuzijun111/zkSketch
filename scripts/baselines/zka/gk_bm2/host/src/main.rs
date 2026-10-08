// zkSketch's two-sided GK band-merge BATCH TRANSITION executed in a RISC Zero guest
// (gk_bm2_step), for an executor-cycle cost comparison against zkSketch's GK leaf.
// Matched semantics: the guest computes exactly zkSketch's
// apply_batch2(S_{t-1}, gk_vals_of(batch_t)) (src/sketch/gk_bandmerge.rs:1426,
// src/experiments/stream_compose.rs:550) and journals (Com_old, Com_batch, Com_new),
// unsalted SHA-256. Unlike scripts/baselines/zka/gk (textbook GK in zk-Analytics'
// pipeline), nothing here is zk-Analytics code or architecture; it is the zkVM
// ("general-purpose method") cost of zkSketch's own leaf statement.
//
// Records, exactly as zkSketch's exp_compose harness batches them:
//   aol      data/aol.keys (zksketch::dataset::aol(), or --keys PATH), flat LE u32
//   uniform  zksketch::dataset::synthetic_stream(Uniform, N, seed 1), what
//            exp_compose's load_base("uniform") generates (prefix-consistent in N)
//   batching plain: batch e = base[(e*m + j) % len], j < m (exp_compose batches_from)
//            --query-every Q: zksketch's build_query_schedule_batches(base, K*m, m, Q,
//            GkBandmerge2), the mixed-workload batcher (early-sealed batches padded
//            with PAD_KEY), to exercise the sentinel path
//   values   gk_vals_of (drop PAD_KEY slots, mask to 21 bits), inside the guest
//   params   GkbParams { capacity, batch: m, s } (deployed: 2048, 16384, 51)
//
// Modes:
//   --mode exec  --dataset aol|uniform --epoch-index e [--variant V] [--emit-state]
//        Chain zkSketch's native apply_batch2 over epochs 0..e (every step also checked
//        against the four ports natively), then EXECUTE the guest on epoch e. One CSV
//        row per variant. Without --emit-state the guest writes only its cycle probes to
//        stdout; the journal is checked against the native commitments.
//   --mode check --dataset aol|uniform --epochs K [--variant V] [--query-every Q]
//        Chain over epochs 0..K-1 (all batches of the schedule with --query-every),
//        executing the guest at EVERY epoch with the new state emitted, and compare
//        it with zkSketch's native apply_batch2 output tuple by tuple (and n, params),
//        plus the journal against the native commitments. One row per (epoch, variant).
//   --header
//   common: [--capacity 2048] [--s 51] [--epoch-size 16384] [--keys PATH]
//   V: comma-separated literal,literal_reuse,fixed_linear,fast, or all (default).
//      See ../core: literal = zkSketch's code statement for statement; literal_reuse =
//      the same with per-round tables reused (no fresh pages per round under risc0's
//      bump allocator); fixed_linear = zkSketch's fixed schedule (full table, every
//      round, every pair) with a linear-time union and an in-place linear re-sort;
//      fast = the same output with a data-dependent schedule.
//
// Every row also carries the guest's merge census (direction-1 / direction-2 fusions,
// summed over the rounds), checked against the native ports' census. Any mismatch
// (guest state, journal, census, or a native port vs zkSketch) prints a MISMATCH line
// on stderr and exits 1 right after that row; the shell runner keeps such rows out of
// the CSV. Nothing is proved: --prove does not exist here. MODELED prove time =
// segments x 30.1 s/segment (envelope 29.73 .. 30.79), the CPU CM-guest anchors of
// scripts/baselines/zka/README.md; it is a model, not a measurement.

use std::time::Instant;

use gk_bm2_core as port;
use gk_bm2_methods::{GK_BM2_STEP_ELF, GK_BM2_STEP_ID};
use risc0_zkvm::{default_executor, ExecutorEnv};
use zksketch::dataset::{synthetic_stream, Synthetic};
use zksketch::experiments::stream_compose::{build_query_schedule_batches, gk_vals_of, StreamFamily, PAD_KEY};
use zksketch::sketch::gk_bandmerge::{apply_batch2, Gk2State, Gk2Tuple, GkbParams};

const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;
/// exp_compose's Uniform seed (load_base("uniform"): synthetic_stream(Uniform, n, 1)).
const UNIFORM_SEED: u64 = 1;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] = &[
    "--mode", "--dataset", "--epoch-index", "--epochs", "--variant", "--capacity", "--s", "--epoch-size",
    "--keys", "--query-every",
];
const BOOL_FLAGS: &[&str] = &["--header", "--emit-state"];

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
    eprintln!("gk_bm2: {msg}");
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
fn load_keys_file(path: &str) -> Vec<u32> {
    let b = std::fs::read(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    if b.is_empty() || b.len() % 4 != 0 {
        die(&format!("{path}: length {} is not a positive multiple of 4", b.len()));
    }
    b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

/// The dataset's key stream; `need` = number of keys the run reads (Uniform is
/// generated at that length; the generator is prefix-consistent).
fn load_base(dataset: &str, need: usize) -> Vec<u32> {
    match dataset {
        "aol" => match arg_str("--keys") {
            Some(p) => load_keys_file(&p),
            None => zksketch::dataset::aol()
                .unwrap_or_else(|| die("data/aol.keys missing (run scripts/fetch_datasets.py) or pass --keys")),
        },
        "uniform" => synthetic_stream(Synthetic::Uniform, need, UNIFORM_SEED),
        o => die(&format!("--dataset {o}: expected aol|uniform")),
    }
}

/// examples/exp_compose.rs:206-210 (`batches_from`, private there), verbatim.
fn batches_from(base: &[u32], m: usize, t: usize) -> Vec<Vec<u32>> {
    (0..t).map(|i| (0..m).map(|j| base[(i * m + j) % base.len()]).collect()).collect()
}

// ------------------------------------------------------- native <-> port glue
fn to_port(s: &Gk2State) -> port::State {
    port::State {
        tuples: s
            .tuples
            .iter()
            .map(|t| port::Tuple {
                e: t.e,
                g: t.g,
                g_o: t.g_o,
                delta: t.delta,
                delta_o: t.delta_o,
                t: t.t,
                active: t.active,
            })
            .collect(),
        params: port::Params { capacity: s.params.capacity, batch: s.params.batch, s: s.params.s },
        n: s.n,
    }
}

fn fields(t: &Gk2Tuple) -> [u64; 7] {
    [t.e as u64, t.g, t.g_o, t.delta, t.delta_o, t.t, t.active as u64]
}
fn port_fields(t: &port::Tuple) -> [u64; 7] {
    [t.e as u64, t.g, t.g_o, t.delta, t.delta_o, t.t, t.active as u64]
}

/// Tuple-by-tuple comparison of a port state with zkSketch's; `Err` names the
/// first difference.
fn compare_state(native: &Gk2State, got: &port::State) -> Result<(), String> {
    let np = (native.params.capacity, native.params.batch, native.params.s);
    let gp = (got.params.capacity, got.params.batch, got.params.s);
    if np != gp {
        return Err(format!("params native={np:?} got={gp:?}"));
    }
    if native.n != got.n {
        return Err(format!("n native={} got={}", native.n, got.n));
    }
    if native.tuples.len() != got.tuples.len() {
        return Err(format!("tuple count native={} got={}", native.tuples.len(), got.tuples.len()));
    }
    for (i, (a, b)) in native.tuples.iter().zip(&got.tuples).enumerate() {
        if fields(a) != port_fields(b) {
            return Err(format!(
                "tuple {i}: native (e,g,g°,Δ,Δ°,t,active)={:?} got={:?}",
                fields(a),
                port_fields(b)
            ));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ zkVM run
struct Exec {
    user_cycles: u64,
    total_cycles: u64,
    segments: usize,
    max_po2: u32,
    exec_s: f64,
    input_bytes: usize,
    journal: Vec<u8>,
    probes: [u64; port::N_PROBES],
    emitted: Option<Vec<u32>>,
}

fn execute(variant: u32, emit: bool, state_words: &[u32], keys: &[u32]) -> Exec {
    let hdr = [port::IN_MAGIC, variant, emit as u32, state_words.len() as u32, keys.len() as u32];
    let input_bytes = 4 * (hdr.len() + state_words.len() + keys.len());
    let mut out: Vec<u8> = Vec::new();
    let t = Instant::now();
    let session = {
        let env = ExecutorEnv::builder()
            .write_slice(&hdr[..])
            .write_slice(state_words)
            .write_slice(keys)
            .stdout(&mut out)
            .build()
            .unwrap();
        default_executor().execute(env, GK_BM2_STEP_ELF).expect("guest execution failed")
    };
    let exec_s = t.elapsed().as_secs_f64();

    let words: Vec<u32> = out.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    let np = port::N_PROBES;
    if words.len() < 2 + 2 * np || words[0] != port::OUT_MAGIC || words[1] as usize != np {
        die(&format!("guest stdout malformed ({} bytes)", out.len()));
    }
    let mut probes = [0u64; port::N_PROBES];
    for (i, p) in probes.iter_mut().enumerate() {
        *p = words[2 + 2 * i] as u64 | (words[3 + 2 * i] as u64) << 32;
    }
    let rest = &words[2 + 2 * np..];
    let emitted = if emit {
        Some(rest.to_vec())
    } else {
        if !rest.is_empty() {
            die("guest emitted a state although emit_state=0");
        }
        None
    };
    Exec {
        user_cycles: session.cycles(),
        total_cycles: session.segments.iter().map(|s| 1u64 << s.po2).sum(),
        segments: session.segments.len(),
        max_po2: session.segments.iter().map(|s| s.po2).max().unwrap_or(0),
        exec_s,
        input_bytes,
        journal: session.journal.bytes.clone(),
        probes,
        emitted,
    }
}

// ------------------------------------------------------------------ output
const HEADER: &str = "system,arm,guest,variant,dataset,batching,epoch_index,epoch_slots,capacity,batch_m,s,n_prev,n_t,theta,vals_active,pad_slots,actives_old,actives_new,mass_eq_n,rounds_lf,rounds_run,fold_right,fold_left,input_bytes,journal_bytes,user_cycles,total_cycles,segments,max_po2,exec_s,cyc_start,cyc_read,cyc_commit_in,cyc_decode_map,cyc_union,cyc_neighbor_init,cyc_rounds,cyc_compact,cyc_commit_out,cyc_journal,cyc_tail,cyc_ingest_commit,cyc_transition,journal_eq_native,state_eq_native,merges_eq_native,port_eq_native,com_new,image_id,MODELED_prove_s,MODELED_prove_s_lo,MODELED_prove_s_hi,model";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn variant_name(v: u32) -> &'static str {
    match v {
        port::VARIANT_LITERAL => "literal",
        port::VARIANT_LITERAL_REUSE => "literal_reuse",
        port::VARIANT_FIXED_LINEAR => "fixed_linear",
        port::VARIANT_FAST => "fast",
        _ => "?",
    }
}

struct Ctx<'a> {
    arm: &'a str,
    dataset: &'a str,
    batching: String,
}

/// Execute the guest on one epoch, check it against zkSketch, print the row.
/// Returns false on any mismatch (after printing the row and a MISMATCH line).
fn run_epoch(
    ctx: &Ctx, e: usize, variant: u32, emit: bool, s_old: &Gk2State, step: &Step, batch: &[u32],
) -> bool {
    let (s_new, port_ok) = (&step.next, step.port_ok);
    let p_old = to_port(s_old);
    let x = execute(variant, emit, &port::state_to_words(&p_old), batch);
    let mut expect = Vec::with_capacity(port::JOURNAL_BYTES);
    expect.extend_from_slice(&port::state_commit(&p_old));
    expect.extend_from_slice(&port::batch_commit(batch));
    expect.extend_from_slice(&port::state_commit(&to_port(s_new)));
    let journal_eq = x.journal == expect;
    let state_cmp = x.emitted.as_ref().map(|w| compare_state(s_new, &port::state_from_words(w)));
    let state_eq = match &state_cmp {
        None => "-".to_string(),
        Some(r) => r.is_ok().to_string(),
    };

    let p = &x.probes;
    let merges_eq = [p[11], p[12]] == step.merges;
    let d = |a: usize, b: usize| p[b].saturating_sub(p[a]);
    let transition = d(3, 7);
    let vals_active = batch.iter().filter(|&&k| k != PAD_KEY).count();
    let params = s_old.params;
    let seg = x.segments as f64;
    let actives = |st: &Gk2State| st.tuples.iter().filter(|t| t.active == 1).count();
    // Same order as HEADER.
    let row: Vec<String> = vec![
        "zkvm".into(),
        ctx.arm.into(),
        "gk_bm2_step".into(),
        variant_name(variant).into(),
        ctx.dataset.into(),
        ctx.batching.clone(),
        e.to_string(),
        batch.len().to_string(),
        params.capacity.to_string(),
        params.batch.to_string(),
        params.s.to_string(),
        s_old.n.to_string(),
        s_new.n.to_string(),
        (s_new.n / params.s).to_string(),
        vals_active.to_string(),
        (batch.len() - vals_active).to_string(),
        actives(s_old).to_string(),
        actives(s_new).to_string(),
        (to_port(s_new).active_mass() == s_new.n).to_string(),
        port::num_rounds(params.capacity + params.batch).to_string(),
        p[10].to_string(),
        p[11].to_string(),
        p[12].to_string(),
        x.input_bytes.to_string(),
        x.journal.len().to_string(),
        x.user_cycles.to_string(),
        x.total_cycles.to_string(),
        x.segments.to_string(),
        x.max_po2.to_string(),
        format!("{:.3}", x.exec_s),
        p[0].to_string(),
        d(0, 1).to_string(),
        d(1, 2).to_string(),
        d(2, 3).to_string(),
        d(3, 4).to_string(),
        d(4, 5).to_string(),
        d(5, 6).to_string(),
        d(6, 7).to_string(),
        d(7, 8).to_string(),
        d(8, 9).to_string(),
        x.user_cycles.saturating_sub(p[9]).to_string(),
        x.user_cycles.saturating_sub(transition).to_string(),
        transition.to_string(),
        journal_eq.to_string(),
        state_eq,
        merges_eq.to_string(),
        port_ok.to_string(),
        hex(&expect[64..]),
        risc0_zkvm::sha::Digest::from(GK_BM2_STEP_ID).to_string(),
        format!("{:.1}", seg * S_PER_SEG),
        format!("{:.1}", seg * S_PER_SEG_LO),
        format!("{:.1}", seg * S_PER_SEG_HI),
        format!("MODELED=segments*{S_PER_SEG} s/seg (CM-guest CPU anchors; not measured)"),
    ];
    assert_eq!(row.len(), HEADER.split(',').count(), "row/header column count");
    println!("{}", row.join(","));
    let mut ok = true;
    if !journal_eq {
        eprintln!(
            "gk_bm2: MISMATCH epoch {e} variant {}: journal {} != native commitments {}",
            variant_name(variant),
            hex(&x.journal),
            hex(&expect)
        );
        ok = false;
    }
    if !merges_eq {
        eprintln!(
            "gk_bm2: MISMATCH epoch {e} variant {}: guest merges (dir1, dir2) = ({}, {}) != native {:?}",
            variant_name(variant),
            p[11],
            p[12],
            step.merges
        );
        ok = false;
    }
    if let Some(Err(why)) = state_cmp {
        eprintln!("gk_bm2: MISMATCH epoch {e} variant {}: guest state != zkSketch apply_batch2: {why}", variant_name(variant));
        ok = false;
    }
    if !port_ok {
        eprintln!("gk_bm2: MISMATCH epoch {e}: the native port differs from zkSketch apply_batch2 (see above)");
        ok = false;
    }
    ok
}

/// One native transition: zkSketch's output, whether the four ports (re-run
/// natively on the same input) all reproduce it tuple by tuple with the same
/// merge census, and that census (direction-1, direction-2 merges).
struct Step {
    next: Gk2State,
    port_ok: bool,
    merges: [u64; 2],
}

/// A port run (native) with its merge census.
fn port_run(variant: u32, s: &port::State, vals: &[u32]) -> (port::State, [u64; 2]) {
    let mut c = [0u64; 2];
    let mut mark = |m: port::Mark| {
        if let port::Mark::RoundDone { fold_right, fold_left } = m {
            c[0] += fold_right as u64;
            c[1] += fold_left as u64;
        }
    };
    let st = match variant {
        port::VARIANT_LITERAL => port::apply_batch2_marked(s, vals, &mut mark),
        port::VARIANT_LITERAL_REUSE => port::apply_batch2_reuse_marked(s, vals, &mut mark),
        port::VARIANT_FIXED_LINEAR => port::apply_batch2_fixed_marked(s, vals, &mut mark),
        port::VARIANT_FAST => port::apply_batch2_fast_marked(s, vals, &mut mark),
        _ => unreachable!("unknown variant {variant}"),
    };
    (st, c)
}

/// zkSketch's native step, with the four ports re-run natively on the same input
/// and compared tuple by tuple.
fn native_step(s: &Gk2State, batch: &[u32], e: usize) -> Step {
    let vals = gk_vals_of(batch);
    let ours = port::vals_of(batch);
    let mut ok = true;
    if vals != ours {
        eprintln!("gk_bm2: MISMATCH epoch {e}: vals_of != gk_vals_of");
        ok = false;
    }
    let next = apply_batch2(s, &vals);
    let p = to_port(s);
    let mut census: Option<[u64; 2]> = None;
    for v in ALL_VARIANTS {
        let (got, c) = port_run(v, &p, &vals);
        if let Err(why) = compare_state(&next, &got) {
            eprintln!("gk_bm2: MISMATCH epoch {e}: native {} port != zkSketch apply_batch2: {why}", variant_name(v));
            ok = false;
        }
        match census {
            None => census = Some(c),
            Some(c0) if c0 != c => {
                eprintln!("gk_bm2: MISMATCH epoch {e}: {} port merges {c:?} != literal port {c0:?}", variant_name(v));
                ok = false;
            }
            _ => {}
        }
    }
    Step { next, port_ok: ok, merges: census.unwrap_or_default() }
}

const ALL_VARIANTS: [u32; 4] =
    [port::VARIANT_LITERAL, port::VARIANT_LITERAL_REUSE, port::VARIANT_FIXED_LINEAR, port::VARIANT_FAST];

/// `--variant` as a comma-separated list of literal, literal_reuse, fixed_linear, fast,
/// or all (default).
fn variants() -> Vec<u32> {
    let spec = arg_str("--variant").unwrap_or_else(|| "all".into());
    if spec == "all" {
        return ALL_VARIANTS.to_vec();
    }
    spec.split(',')
        .map(|v| {
            *ALL_VARIANTS
                .iter()
                .find(|&&x| variant_name(x) == v)
                .unwrap_or_else(|| die(&format!("--variant {v}: expected literal|literal_reuse|fixed_linear|fast|all")))
        })
        .collect()
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
    let mode = arg_str("--mode").unwrap_or_else(|| die("--mode exec|check is required"));
    let dataset = arg_str("--dataset").unwrap_or_else(|| die("--dataset aol|uniform is required"));
    let capacity = arg_u64("--capacity", 2048) as usize;
    let s = arg_u64("--s", 51);
    let m = arg_u64("--epoch-size", 16_384) as usize;
    if capacity == 0 || m == 0 || s == 0 {
        die("--capacity, --epoch-size and --s must be > 0");
    }
    let params = GkbParams { capacity, batch: m, s };
    let vs = variants();

    match mode.as_str() {
        "exec" => {
            if arg_str("--epochs").is_some() || arg_str("--query-every").is_some() {
                die("--epochs/--query-every belong to --mode check");
            }
            let idx = arg_u64("--epoch-index", 0) as usize;
            let base = load_base(&dataset, (idx + 1) * m);
            if (idx + 1) * m > base.len() {
                die(&format!("epoch {idx} needs {} keys, the {dataset} stream has {}", (idx + 1) * m, base.len()));
            }
            let batches = batches_from(&base, m, idx + 1);
            let mut st = Gk2State::empty(params);
            let mut port_ok = true;
            for (e, b) in batches[..idx].iter().enumerate() {
                let step = native_step(&st, b, e);
                port_ok &= step.port_ok;
                st = step.next;
            }
            let mut step = native_step(&st, &batches[idx], idx);
            step.port_ok &= port_ok;
            let ctx = Ctx { arm: "exec", dataset: &dataset, batching: "plain".into() };
            let mut all = true;
            for &v in &vs {
                all &= run_epoch(&ctx, idx, v, flag("--emit-state"), &st, &step, &batches[idx]);
            }
            if !all {
                std::process::exit(1);
            }
        }
        "check" => {
            if arg_str("--epoch-index").is_some() || flag("--emit-state") {
                die("--epoch-index/--emit-state belong to --mode exec (check always emits the state)");
            }
            let k = arg_u64("--epochs", 4) as usize;
            if k == 0 {
                die("--epochs must be > 0");
            }
            let q = arg_u64("--query-every", 0) as usize;
            let base = load_base(&dataset, k * m);
            let (batches, batching) = if q > 0 {
                let (b, qat, pads, splits) =
                    build_query_schedule_batches(&base, k * m, m, q, StreamFamily::GkBandmerge2);
                eprintln!(
                    "gk_bm2: query schedule over {} positions, Q={q}: {} batches, {} queries, {pads} pad slots, {splits} padded batches",
                    k * m,
                    b.len(),
                    qat.len()
                );
                (b, format!("q{q}"))
            } else {
                if k * m > base.len() {
                    die(&format!("{k} epochs need {} keys, the {dataset} stream has {}", k * m, base.len()));
                }
                (batches_from(&base, m, k), "plain".to_string())
            };
            let ctx = Ctx { arm: "check", dataset: &dataset, batching };
            let mut st = Gk2State::empty(params);
            for (e, b) in batches.iter().enumerate() {
                let step = native_step(&st, b, e);
                for &v in &vs {
                    if !run_epoch(&ctx, e, v, true, &st, &step, b) {
                        std::process::exit(1);
                    }
                }
                st = step.next;
            }
            eprintln!("gk_bm2: check passed: {} epochs x {} variant(s), every guest state == zkSketch apply_batch2", batches.len(), vs.len());
        }
        o => die(&format!("--mode {o}: expected exec|check")),
    }
}

// ------------------------------------------------------------------ tests
// Native-only (no zkVM): every port against zkSketch's apply_batch2 on many small
// shapes, chained, with pads, odd tables and capacity overflow. Run with --release.
#[cfg(test)]
mod tests {
    use super::*;

    fn splitmix(s: &mut u64) -> u64 {
        *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A raw key batch of `m` slots: keys drawn from a domain of `dom` values
    /// (spread over 32 bits), the last `pads` slots PAD_KEY.
    fn raw_batch(seed: &mut u64, m: usize, dom: u64, pads: usize) -> Vec<u32> {
        (0..m)
            .map(|j| if j >= m - pads { PAD_KEY } else { ((splitmix(seed) % dom).wrapping_mul(0x9E37_79B9) as u32) | 1 })
            .collect()
    }

    /// Returns (final actives, whether any epoch truncated, merges by direction).
    fn chain(
        cap: usize, m: usize, s: u64, epochs: usize, dom: u64, seed0: u64, pad_every: usize,
    ) -> (usize, bool, [u64; 2]) {
        let params = GkbParams { capacity: cap, batch: m, s };
        let mut st = Gk2State::empty(params);
        let mut seed = seed0;
        let mut truncated = false;
        let mut dirs = [0u64; 2];
        for e in 0..epochs {
            let pads = if pad_every > 0 && e % pad_every == pad_every - 1 { m / 3 } else { 0 };
            let b = raw_batch(&mut seed, m, dom, pads);
            let step = native_step(&st, &b, e);
            assert!(step.port_ok, "cap={cap} m={m} s={s} dom={dom} seed={seed0} epoch {e}: port mismatch");
            // the guest's wire format round-trips
            let p = to_port(&step.next);
            assert_eq!(port::state_from_words(&port::state_to_words(&p)), p);
            truncated |= p.active_mass() != step.next.n;
            dirs[0] += step.merges[0];
            dirs[1] += step.merges[1];
            st = step.next;
        }
        (st.tuples.iter().filter(|t| t.active == 1).count(), truncated, dirs)
    }

    /// Includes shapes whose capacity overflows (s large for the capacity): zkSketch's
    /// overflow check is a debug_assert!, so under --release both sides truncate and
    /// must still agree tuple for tuple. Odd `capacity + m` tables are included.
    #[test]
    fn ports_equal_zksketch_on_small_shapes() {
        assert!(!cfg!(debug_assertions), "run with --release (zkSketch debug_asserts on overflow)");
        let (mut runs, mut overflowed) = (0, 0);
        for &(cap, m) in &[(4usize, 4usize), (5, 8), (8, 7), (16, 16), (32, 64), (64, 256), (7, 33), (128, 512)] {
            for &s in &[1u64, 2, 3, 5, 8] {
                for &dom in &[3u64, 50, 1 << 21, 1 << 32] {
                    for seed in 0..3u64 {
                        let (_, truncated, _) = chain(cap, m, s, 12, dom, seed * 7919 + cap as u64, 4);
                        overflowed += truncated as usize;
                        runs += 1;
                    }
                }
            }
        }
        assert!(runs == 480 && overflowed > 0, "runs={runs} overflowed={overflowed}");
    }

    #[test]
    fn ports_equal_zksketch_with_heavy_compression() {
        // capacity near the Gribelyuk bound: many fusions per round, both directions
        for seed in 0..4u64 {
            let (act, truncated, dirs) = chain(256, 4096, 6, 8, 1 << 32, seed, 3);
            assert!(act > 0 && !truncated && dirs[0] > 0 && dirs[1] > 0, "act={act} dirs={dirs:?}");
        }
    }

    /// The never-paired last row of an odd, FULL table (old state at capacity plus a
    /// full batch) is the one place where zkSketch drops an active tuple without a
    /// merge; make sure the chains reach it and every port reproduces it.
    #[test]
    fn ports_equal_zksketch_on_odd_full_tables() {
        let mut full_odd = 0;
        for &(cap, m) in &[(8usize, 7usize), (5, 8), (16, 33)] {
            let params = GkbParams { capacity: cap, batch: m, s: 51 };
            let mut st = Gk2State::empty(params);
            let mut seed = cap as u64;
            for e in 0..10 {
                let b = raw_batch(&mut seed, m, 1 << 32, 0);
                let old_act = st.tuples.iter().filter(|t| t.active == 1).count();
                full_odd += ((cap + m) % 2 == 1 && old_act + m == cap + m) as usize;
                let step = native_step(&st, &b, e);
                assert!(step.port_ok, "cap={cap} m={m} epoch {e}: port mismatch");
                st = step.next;
            }
        }
        assert!(full_odd >= 10, "full odd tables reached: {full_odd}");
    }

    #[test]
    fn fast_refuses_non_canonical_state() {
        let params = port::Params { capacity: 4, batch: 2, s: 2 };
        let mut st = port::State::empty(params);
        st.tuples[1] = port::Tuple { e: 5, g: 0, g_o: 0, delta: 0, delta_o: 0, t: 0, active: 1 };
        assert!(port::canonical_violation(&st).is_some());
        assert!(std::panic::catch_unwind(|| port::apply_batch2_fast(&st, &[1, 2])).is_err());
    }

    #[test]
    fn fixed_linear_refuses_non_canonical_state() {
        let params = port::Params { capacity: 4, batch: 2, s: 2 };
        let mut st = port::State::empty(params);
        // an inactive row that is not the exact dummy: a stable (e, t) sort would
        // keep it among the actives, the compaction would not
        st.tuples[0] = port::Tuple { e: 5, g: 0, g_o: 0, delta: 0, delta_o: 0, t: 0, active: 0 };
        assert!(port::canonical_violation(&st).is_some());
        assert!(std::panic::catch_unwind(|| port::apply_batch2_fixed(&st, &[1, 2])).is_err());
    }
}
