// zkSketch's SpaceSaving batch rule (mergeable Misra-Gries) as a RISC Zero guest:
// executor-only cost runs plus an equivalence check against zkSketch's own
// native code. See ../../README.md.
//
// Records: the stream is cut exactly as zkSketch's harness cuts it
// (examples/exp_compose.rs batches_from): epoch e holds keys
// base[(e*m + j) % len], j < m, m = --epoch-size (16,384).
//   aol      data/aol.keys (flat little-endian u32, 2^20 keys)
//   uniform  zksketch::dataset::synthetic_stream(Uniform, 64*m, 1), the stream
//            exp_compose / exp_stream / exp_e1 load for EXP_DATASET=uniform
//            (seed 1; prefix-stable, so epoch e does not depend on the length)
// Each raw key is mapped by zkSketch's ss_updates_of inside the guest.
//
// Native reference (the zksketch crate of this checkout, by path):
//   S_0 = SsFullState::empty(SsFullParams { capacity: s, batch: m })
//   S_{e+1} = apply_batch_ss_full(&S_e, &ss_updates_of(batch_e)).0
// exactly the loop of src/experiments/stream_compose.rs (SsCertified arms).
//
// Modes:
//   exec   S_E computed natively (epochs 0..E-1), ONE guest run on (S_E, batch_E).
//   chain  guest runs on epochs 0..K-1, each fed the GUEST's previous output;
//          also checks Com_old(e) == Com_new(e-1).
// Every guest run is checked, and any failed check aborts with exit code 1
// before a row is printed:
//   state_eq_native        guest S_new (host-only stdout channel) == zkSketch's
//                          S_{e+1}, row by row and field by field (key, count, active)
//   journal_eq_native      guest journal == ss-mg-core run natively on the same input
//   com_eq_native          Com_old / Com_batch / Com_new == SHA-256 of zkSketch's
//                          native S_e / ss_updates_of(batch_e) / S_{e+1}
//   core_eq_native_prefix  (exec) ss-mg-core run natively == zkSketch on every
//                          epoch 0..E, plus the mapped batch == ss_updates_of
//   link_ok                (chain) Com_old(e) == Com_new(e-1)
//   probes_ok              the guest's env::cycle_count() marks increase, and they
//                          agree with the executor's user-cycle count: fewer than
//                          PROBE_SLACK cycles before the first mark (pre_main) and
//                          0 <= user_cycles - last mark < PROBE_SLACK (post).
//                          pre_main + the phase deltas + post == user_cycles holds
//                          by construction (post is the remainder); the bounds
//                          are the check.
//
// Cycle columns: user_cycles is the executor's count of executed guest cycles
// (the probes split it into phases); padded_cycles = sum over segments of
// 2^po2, what the prover pays; overhead_cycles = padded - user = paging
// (page-in/out of every page a segment touches), the per-segment reserve and
// the po2 padding. The overhead belongs to no phase: transition_pct_user is
// transition / user, transition_pct_padded is transition / padded.
//
// Usage:
//   ss_mg --header
//   ss_mg --image-id [--guest G]
//   ss_mg --mode exec  --dataset aol|uniform --capacity S [--epoch-index E]
//   ss_mg --mode chain --dataset aol|uniform --capacity S [--epochs K]
//   common: [--guest ss_mg|ss_mg_serde] [--sort radix|std] [--keys PATH] (aol) [--epoch-size 16384]
//
// --guest ss_mg (default, the headline) reads its input with env::read_slice;
// ss_mg_serde reads the same data as an SsMgInput through risc0 serde
// (env::read), the zka guests' read path. Everything after the read is the
// same ss-mg-core code; the read-path sensitivity rows use ss_mg_serde.
// --sort radix (default, the headline) or std picks ss-mg-core's sort (an input
// word, not committed); std is the comparison-sort sensitivity row.
//
// Executor only: this driver never proves. MODELED prove time = segments x 30.1 s
// (envelope 29.73..30.79), the CM-guest CPU anchors of ../../README.md. NOT measured.

use std::time::Instant;

use risc0_zkvm::{default_executor, ExecutorEnv, ExitCode};
use ss_mg_core::{
    apply_batch_mg, batch_commit, empty_rows, input_words, map_batch, run_hooked, state_commit, Commit, MgStats,
    SortAlgo, SsMgInput, SsMgJournal, PAD_KEY, PHASES, ROW_WORDS,
};
use ss_mg_methods::{SS_MG_ELF, SS_MG_ID, SS_MG_SERDE_ELF, SS_MG_SERDE_ID};
use zksketch::dataset::{synthetic_stream, Synthetic};
use zksketch::experiments::stream_compose::ss_updates_of;
use zksketch::sketch::ss_final_full::{apply_batch_ss_full, SsFullParams, SsFullState, SsFullUpdate};

// MODELED prove time: segments x 30.1 s, envelope 29.73..30.79 s/segment = the
// per-anchor min/max of the four CPU CM anchors in ../../README.md.
const S_PER_SEG: f64 = 30.1;
const S_PER_SEG_LO: f64 = 29.73;
const S_PER_SEG_HI: f64 = 30.79;

/// Guest marks: start, read, the ss-mg-core PHASES, journal.
const N_MARKS: usize = PHASES.len() + 3;
/// Length of the deployed stream in epochs (2^20 records at m = 16,384).
const STREAM_EPOCHS: usize = 64;
/// Bound on the user cycles outside the probes: before the first mark
/// (pre_main, 360 measured) and after the last (post: the host-only stdout
/// write, about 2,630 measured at every s).
const PROBE_SLACK: u64 = 10_000;

// ------------------------------------------------------------------ arguments
const VALUE_FLAGS: &[&str] =
    &["--mode", "--dataset", "--capacity", "--epoch-index", "--epochs", "--keys", "--epoch-size", "--guest", "--sort"];
const BOOL_FLAGS: &[&str] = &["--header", "--image-id"];

fn die(msg: &str) -> ! {
    eprintln!("ss_mg: {msg}");
    std::process::exit(2);
}
fn fail(msg: &str) -> ! {
    eprintln!("ss_mg: CHECK FAILED: {msg}");
    std::process::exit(1);
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
            die(&format!("unknown argument '{s}' (value flags: {}; bool flags: {})", VALUE_FLAGS.join(" "), BOOL_FLAGS.join(" ")));
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
    if b.is_empty() || b.len() % 4 != 0 {
        die(&format!("{path}: length {} is not a positive multiple of 4", b.len()));
    }
    b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

/// examples/exp_compose.rs `batches_from`, one batch.
fn batch_of(base: &[u32], m: usize, e: usize) -> Vec<u32> {
    (0..m).map(|j| base[(e * m + j) % base.len()]).collect()
}

// ------------------------------------------------------- zkSketch <-> words
/// zkSketch's flat_state_vals layout: (key_lo, key_hi, count, active) per row.
fn state_words(s: &SsFullState) -> Vec<u32> {
    s.rows.iter().flat_map(|r| [r.key as u32, (r.key >> 32) as u32, r.count, r.active]).collect()
}
/// zkSketch's flat_batch_vals layout: (key_lo, key_hi, value, active) per record.
fn batch_words(b: &[SsFullUpdate]) -> Vec<u32> {
    b.iter().flat_map(|u| [u.key as u32, (u.key >> 32) as u32, u.value, u.active]).collect()
}

/// Field-by-field comparison of guest rows with zkSketch's state. Returns the
/// number of differing rows and prints the first few.
fn diff_rows(what: &str, guest: &[u32], native: &SsFullState) -> usize {
    if guest.len() != native.rows.len() * ROW_WORDS {
        eprintln!("{what}: guest state has {} words, zkSketch state has {} rows", guest.len(), native.rows.len());
        return usize::MAX;
    }
    let mut bad = 0usize;
    for (i, (g, n)) in guest.chunks_exact(ROW_WORDS).zip(&native.rows).enumerate() {
        let gk = g[0] as u64 | ((g[1] as u64) << 32);
        if gk != n.key || g[2] != n.count || g[3] != n.active {
            if bad < 5 {
                eprintln!(
                    "{what}: row {i}: guest (key {gk}, count {}, active {}) != zkSketch (key {}, count {}, active {})",
                    g[2], g[3], n.key, n.count, n.active
                );
            }
            bad += 1;
        }
    }
    bad
}

fn hex(c: &Commit) -> String {
    c.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------ zkVM runs
#[derive(Clone, Copy, PartialEq, Eq)]
enum Guest {
    /// headline: input via env::read_slice
    Slice,
    /// sensitivity: input via risc0 serde env::read
    Serde,
}
impl Guest {
    fn parse(v: &str) -> Self {
        match v {
            "ss_mg" => Guest::Slice,
            "ss_mg_serde" => Guest::Serde,
            o => die(&format!("--guest {o}: expected ss_mg|ss_mg_serde")),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Guest::Slice => "ss_mg",
            Guest::Serde => "ss_mg_serde",
        }
    }
    fn elf(self) -> &'static [u8] {
        match self {
            Guest::Slice => SS_MG_ELF,
            Guest::Serde => SS_MG_SERDE_ELF,
        }
    }
    fn id(self) -> [u32; 8] {
        match self {
            Guest::Slice => SS_MG_ID,
            Guest::Serde => SS_MG_SERDE_ID,
        }
    }
}

struct Exec {
    user_cycles: u64,
    /// sum over segments of 2^po2
    padded_cycles: u64,
    segments: usize,
    max_po2: u32,
    exec_s: f64,
    input_bytes: usize,
    journal_bytes: usize,
    journal: SsMgJournal,
    marks: [u64; N_MARKS],
    new_rows: Vec<u32>,
}

fn execute(guest: Guest, input: &SsMgInput) -> Exec {
    let words = input_words(input);
    let input_bytes = match guest {
        Guest::Slice => words.len() * 4,
        Guest::Serde => risc0_zkvm::serde::to_vec(input).expect("serialize input").len() * 4,
    };
    let mut out: Vec<u8> = Vec::new();
    let t = Instant::now();
    let session = {
        let mut b = ExecutorEnv::builder();
        match guest {
            Guest::Slice => b.write_slice(&words),
            Guest::Serde => b.write(input).unwrap(),
        };
        let env = b.stdout(&mut out).build().unwrap();
        default_executor().execute(env, guest.elf()).unwrap_or_else(|e| fail(&format!("guest execution failed: {e}")))
    };
    let exec_s = t.elapsed().as_secs_f64();
    if !matches!(session.exit_code, ExitCode::Halted(0)) {
        fail(&format!("guest exit code {:?}", session.exit_code));
    }
    let journal = SsMgJournal::from_bytes(&session.journal.bytes)
        .unwrap_or_else(|| fail(&format!("journal has {} bytes, expected {}", session.journal.bytes.len(), SsMgJournal::BYTES)));
    let want = 8 * N_MARKS + 4 * ROW_WORDS * input.capacity as usize;
    if out.len() != want {
        fail(&format!("guest stdout has {} bytes, expected {want}", out.len()));
    }
    let mut marks = [0u64; N_MARKS];
    for (i, c) in out[..8 * N_MARKS].chunks_exact(8).enumerate() {
        marks[i] = u64::from_le_bytes(c.try_into().unwrap());
    }
    let new_rows = out[8 * N_MARKS..].chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    Exec {
        user_cycles: session.cycles(),
        padded_cycles: session.segments.iter().map(|s| 1u64 << s.po2).sum(),
        segments: session.segments.len(),
        max_po2: session.segments.iter().map(|s| s.po2).max().unwrap_or(0),
        exec_s,
        input_bytes,
        journal_bytes: session.journal.bytes.len(),
        journal,
        marks,
        new_rows,
    }
}

/// The guest's cycle marks must increase and agree with the executor's
/// user-cycle count up to PROBE_SLACK at both ends. pre_main + the phase
/// deltas + post sums to user_cycles whatever the marks are (post is the
/// remainder), so the bounds are what tests that env::cycle_count() counts the
/// same session-wide user cycles as the executor (not per segment, not with
/// paging).
fn check_probes(label: &str, x: &Exec) {
    let last = x.marks[N_MARKS - 1];
    if x.marks.windows(2).any(|w| w[1] <= w[0]) {
        fail(&format!("{label}: guest cycle marks do not increase: {:?}", x.marks));
    }
    if x.marks[0] >= PROBE_SLACK || last > x.user_cycles || x.user_cycles - last >= PROBE_SLACK {
        fail(&format!(
            "{label}: guest cycle marks disagree with the executor: first mark {}, last mark {last}, user cycles {} (slack {PROBE_SLACK})",
            x.marks[0], x.user_cycles
        ));
    }
}

/// One guest run on (S_e, batch_e), checked against zkSketch's native
/// transition. Aborts (exit 1) on any mismatch. Returns the run, the native
/// S_{e+1}, the ss-mg-core stats and the batch's (pad records, distinct keys).
fn checked_run(
    guest: Guest,
    algo: SortAlgo,
    label: &str,
    cap: usize,
    m: usize,
    old_guest_rows: Vec<u32>,
    old_native: &SsFullState,
    raw: &[u32],
) -> (Exec, SsFullState, MgStats, usize, usize) {
    let ups = ss_updates_of(raw);
    let native_new = apply_batch_ss_full(old_native, &ups).0;
    let input = SsMgInput {
        capacity: cap as u32,
        batch: m as u32,
        sort: algo as u32,
        old_rows: old_guest_rows,
        keys: raw.to_vec(),
    };
    let (core_journal, core_rows, stats) = run_hooked(input.capacity, input.batch, algo, &input.old_rows, &input.keys, |_| {});
    let x = execute(guest, &input);
    check_probes(label, &x);

    let bad = diff_rows(label, &x.new_rows, &native_new);
    if bad != 0 {
        fail(&format!("{label}: guest S_new differs from zkSketch apply_batch_ss_full in {bad} rows"));
    }
    if x.journal != core_journal || x.new_rows != core_rows {
        fail(&format!("{label}: guest journal/state differs from ss-mg-core run natively"));
    }
    let com_old = state_commit(cap as u32, m as u32, &state_words(old_native));
    let com_batch = batch_commit(m as u32, &batch_words(&ups));
    let com_new = state_commit(cap as u32, m as u32, &state_words(&native_new));
    if (x.journal.com_old, x.journal.com_batch, x.journal.com_new) != (com_old, com_batch, com_new) {
        fail(&format!(
            "{label}: commitments differ from SHA-256 of zkSketch's native objects (old {} batch {} new {})",
            x.journal.com_old == com_old,
            x.journal.com_batch == com_batch,
            x.journal.com_new == com_new
        ));
    }
    let pads = raw.iter().filter(|&&k| k == PAD_KEY).count();
    let mut keys: Vec<u64> = ups.iter().filter(|u| u.active == 1).map(|u| u.key).collect();
    keys.sort_unstable();
    keys.dedup();
    (x, native_new, stats, pads, keys.len())
}

// ------------------------------------------------------------------ output
const HEADER: &str = "system,arm,dataset,guest,sort,capacity,epoch_size,epoch_index,state_source,pad_records,batch_distinct,old_active,union_distinct,tau,new_active,input_bytes,journal_bytes,user_cycles,padded_cycles,segments,max_po2,exec_s,pre_main_cycles,read_cycles,commit_old_cycles,map_cycles,commit_batch_cycles,transition_cycles,commit_new_cycles,journal_cycles,post_cycles,ingest_commit_cycles,transition_pct_user,overhead_cycles,transition_pct_padded,state_eq_native,journal_eq_native,com_eq_native,core_eq_native_prefix,link_ok,probes_ok,MODELED_prove_s,MODELED_prove_s_lo,MODELED_prove_s_hi,model,image_id,com_old,com_batch,com_new";

#[allow(clippy::too_many_arguments)]
fn emit(guest: Guest, algo: SortAlgo, arm: &str, dataset: &str, cap: usize, m: usize, e: usize, source: &str, pads: usize, distinct: usize, st: &MgStats, x: &Exec, core_prefix: &str, link: &str) {
    // marks: start, read, commit_old, map, commit_batch, transition, commit_new, journal
    let d: Vec<u64> = x.marks.windows(2).map(|w| w[1].saturating_sub(w[0])).collect();
    let (read, commit_old, map, commit_batch, transition, commit_new, journal) = (d[0], d[1], d[2], d[3], d[4], d[5], d[6]);
    // pre_main + the deltas + post == user_cycles by construction (post is the
    // remainder); check_probes bounded pre_main and post.
    let pre_main = x.marks[0];
    let post = x.user_cycles - x.marks[N_MARKS - 1];
    let ingest_commit = read + commit_old + map + commit_batch + commit_new + journal;
    // paging + per-segment reserve + po2 padding: in no phase
    let overhead = x.padded_cycles.checked_sub(x.user_cycles).unwrap_or_else(|| fail("padded cycles below user cycles"));
    let seg = x.segments as f64;
    println!(
        "zka-port,{arm},{dataset},{},{},{cap},{m},{e},{source},{pads},{distinct},{},{},{},{},{},{},{},{},{},{},{:.3},{pre_main},{read},{commit_old},{map},{commit_batch},{transition},{commit_new},{journal},{post},{ingest_commit},{:.2},{overhead},{:.2},true,true,true,{core_prefix},{link},true,{:.1},{:.1},{:.1},MODELED=segments*{} s/seg (CM-guest CPU anchors; not measured),{},{},{},{}",
        guest.name(), algo.name(), st.old_active, st.union_distinct, st.tau, st.new_active, x.input_bytes, x.journal_bytes,
        x.user_cycles, x.padded_cycles, x.segments, x.max_po2, x.exec_s,
        100.0 * transition as f64 / x.user_cycles.max(1) as f64,
        100.0 * transition as f64 / x.padded_cycles.max(1) as f64,
        seg * S_PER_SEG, seg * S_PER_SEG_LO, seg * S_PER_SEG_HI, S_PER_SEG,
        risc0_zkvm::sha::Digest::from(guest.id()),
        hex(&x.journal.com_old), hex(&x.journal.com_batch), hex(&x.journal.com_new),
    );
}

// ------------------------------------------------------------------ main
fn main() {
    validate_args();
    if flag("--header") {
        println!("{HEADER}");
        return;
    }
    let guest = Guest::parse(&arg_str("--guest").unwrap_or_else(|| "ss_mg".into()));
    let algo = match arg_str("--sort").as_deref() {
        None | Some("radix") => SortAlgo::Radix,
        Some("std") => SortAlgo::Std,
        Some(o) => die(&format!("--sort {o}: expected radix|std")),
    };
    if flag("--image-id") {
        println!("{}", risc0_zkvm::sha::Digest::from(guest.id()));
        return;
    }
    if let Ok(v) = std::env::var("RISC0_DEV_MODE") {
        if !v.is_empty() && v != "0" && v.to_ascii_lowercase() != "false" {
            die("RISC0_DEV_MODE is set; refusing (no dev-mode numbers are reported by this harness)");
        }
    }
    let mode = arg_str("--mode").unwrap_or_else(|| die("--mode exec|chain is required"));
    let dataset = arg_str("--dataset").unwrap_or_else(|| die("--dataset aol|uniform is required"));
    let cap = arg_usize("--capacity", 0);
    let m = arg_usize("--epoch-size", 16_384);
    if cap < 2 || cap % 2 != 0 || m < 2 || m % 2 != 0 || cap > u32::MAX as usize / 16 || m > u32::MAX as usize / 16 {
        die("--capacity and --epoch-size must be even and >= 2 (zkSketch SsFullParams::validate)");
    }
    let (first, epochs) = match mode.as_str() {
        "exec" => (arg_usize("--epoch-index", 0), 1),
        "chain" => (0, arg_usize("--epochs", 4)),
        o => die(&format!("--mode {o}: expected exec|chain")),
    };
    if epochs == 0 {
        die("--epochs must be >= 1");
    }
    let last = first + epochs - 1;
    let base = match dataset.as_str() {
        "aol" => load_keys(
            &arg_str("--keys").unwrap_or_else(|| format!("{}/../../../../data/aol.keys", env!("CARGO_MANIFEST_DIR"))),
        ),
        "uniform" => synthetic_stream(Synthetic::Uniform, STREAM_EPOCHS.max(last + 1) * m, 1),
        o => die(&format!("--dataset {o}: expected aol|uniform")),
    };

    let params = SsFullParams { capacity: cap, batch: m };
    let mut native = SsFullState::empty(params);
    if mode == "exec" {
        // S_E natively, with ss-mg-core (both sorts) run natively alongside on every epoch.
        let mut core_rows = empty_rows(cap);
        let mut core_rows_other = empty_rows(cap);
        let other = if algo == SortAlgo::Radix { SortAlgo::Std } else { SortAlgo::Radix };
        for e in 0..first {
            let raw = batch_of(&base, m, e);
            let ups = ss_updates_of(&raw);
            let words = map_batch(&raw);
            if words != batch_words(&ups) {
                fail(&format!("epoch {e}: ss-mg-core key mapping != zkSketch ss_updates_of"));
            }
            native = apply_batch_ss_full(&native, &ups).0;
            core_rows = apply_batch_mg(cap, &core_rows, &words, algo).0;
            core_rows_other = apply_batch_mg(cap, &core_rows_other, &words, other).0;
            let bad = diff_rows(&format!("prefix epoch {e} ({})", algo.name()), &core_rows, &native);
            let bad_other = diff_rows(&format!("prefix epoch {e} ({})", other.name()), &core_rows_other, &native);
            if bad != 0 || bad_other != 0 {
                fail(&format!("epoch {e}: ss-mg-core (native) differs from zkSketch in {bad} / {bad_other} rows"));
            }
        }
        let raw = batch_of(&base, m, first);
        if map_batch(&raw) != batch_words(&ss_updates_of(&raw)) {
            fail(&format!("epoch {first}: ss-mg-core key mapping != zkSketch ss_updates_of"));
        }
        let label = format!("{dataset} s={cap} epoch {first}");
        let (x, _, st, pads, distinct) = checked_run(guest, algo, &label, cap, m, state_words(&native), &native, &raw);
        let source = if first == 0 { "empty".to_string() } else { format!("native(0..{})", first - 1) };
        emit(guest, algo, "exec", &dataset, cap, m, first, &source, pads, distinct, &st, &x, "true", "-");
    } else {
        // Guest-chained: each run reads the previous GUEST output.
        let mut guest_rows = empty_rows(cap);
        let mut prev_new: Option<Commit> = None;
        for e in 0..epochs {
            let raw = batch_of(&base, m, e);
            let label = format!("{dataset} s={cap} chain epoch {e}");
            let (x, native_new, st, pads, distinct) = checked_run(guest, algo, &label, cap, m, guest_rows, &native, &raw);
            if let Some(p) = prev_new {
                if x.journal.com_old != p {
                    fail(&format!("{label}: Com_old != previous run's Com_new"));
                }
            }
            prev_new = Some(x.journal.com_new);
            let source = if e == 0 { "empty".to_string() } else { "guest-chain".to_string() };
            emit(guest, algo, "chain", &dataset, cap, m, e, &source, pads, distinct, &st, &x, "-", if e == 0 { "-" } else { "true" });
            guest_rows = x.new_rows;
            native = native_new;
        }
    }
}

// ------------------------------------------------------------------ tests
// ss-mg-core's transition vs zkSketch's apply_batch_ss_full on small random
// shapes chosen to hit the corner cases of the batch rule: count ties across the
// top-s cut, counters equal to tau (dropped), under-full unions, pad records
// (u32::MAX) and raw keys that collide under the 29-bit mask / forced low bit.
// Native only (no executor): the guest runs the same ss-mg-core code, and every
// executor run is checked against zkSketch anyway.
#[cfg(test)]
mod tests {
    use super::*;

    fn next(s: &mut u64) -> u64 {
        *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A raw key from a small pool, its mask / low-bit aliases, or the pad sentinel.
    fn raw_key(s: &mut u64, pool: u32) -> u32 {
        let k = (next(s) % pool as u64) as u32 + 1;
        match next(s) % 10 {
            0 => PAD_KEY,
            1 => k | 0x2000_0000, // aliases k under the 29-bit mask
            2 => k & !1,          // aliases k | 1 after the forced low bit (0 maps to 1)
            3 => u32::MAX - 1,    // the largest real raw key (maps to 0x1FFF_FFFF)
            _ => k,
        }
    }

    /// Chains `epochs` random batches through both implementations; returns
    /// (epochs with tau > 0, epochs where counters equal to tau were dropped).
    fn check_chain(cap: usize, m: usize, pool: u32, epochs: usize, seed: u64, algo: SortAlgo) -> (u64, u64) {
        let mut s = seed;
        let mut native = SsFullState::empty(SsFullParams { capacity: cap, batch: m });
        let mut rows = empty_rows(cap);
        let (mut evict, mut tie_drop) = (0u64, 0u64);
        for e in 0..epochs {
            let raw: Vec<u32> = (0..m).map(|_| raw_key(&mut s, pool)).collect();
            let ups = ss_updates_of(&raw);
            assert_eq!(map_batch(&raw), batch_words(&ups), "mapping, seed {seed} epoch {e}");
            native = apply_batch_ss_full(&native, &ups).0;
            let (r, st) = apply_batch_mg(cap, &rows, &map_batch(&raw), algo);
            rows = r;
            let label = format!("{} cap {cap} m {m} pool {pool} seed {seed} epoch {e}", algo.name());
            assert_eq!(diff_rows(&label, &rows, &native), 0);
            assert_eq!(st.new_active as usize, native.active_count());
            evict += (st.tau > 0) as u64;
            tie_drop += (st.union_distinct as usize > cap && (st.new_active as usize) < cap) as u64;
        }
        (evict, tie_drop)
    }

    fn random_small_shapes(algo: SortAlgo) {
        let (mut evict, mut tie_drop, mut chains) = (0u64, 0u64, 0u64);
        for &cap in &[2usize, 4, 6, 8, 16] {
            for &m in &[2usize, 4, 8, 16, 32] {
                for &pool in &[3u32, 8, 40, 1000] {
                    for seed in 0..12u64 {
                        let seed = seed * 7919 + (cap * 131 + m) as u64 * 31 + pool as u64;
                        let (a, b) = check_chain(cap, m, pool, 24, seed, algo);
                        evict += a;
                        tie_drop += b;
                        chains += 1;
                    }
                }
            }
        }
        eprintln!(
            "{}: {chains} chains x 24 epochs: {evict} epochs with tau > 0, {tie_drop} with counters dropped at tau",
            algo.name()
        );
        assert!(evict > 1000 && tie_drop > 100, "corner cases not exercised: {evict} / {tie_drop}");
    }

    #[test]
    fn radix_transition_matches_zksketch_on_random_small_shapes() {
        random_small_shapes(SortAlgo::Radix);
    }

    #[test]
    fn std_transition_matches_zksketch_on_random_small_shapes() {
        random_small_shapes(SortAlgo::Std);
    }

    /// Keys over all 29 bits and counts past 2^11 (four non-constant radix digits).
    #[test]
    fn transition_matches_zksketch_on_wide_keys_and_counts() {
        for algo in [SortAlgo::Radix, SortAlgo::Std] {
            let (cap, m) = (64usize, 256usize);
            let mut s = 99u64;
            let mut native = SsFullState::empty(SsFullParams { capacity: cap, batch: m });
            let mut rows = empty_rows(cap);
            for e in 0..40 {
                // a few very heavy keys (counts past 2^11) plus a wide random tail
                let raw: Vec<u32> = (0..m)
                    .map(|j| if j % 4 != 0 { (j % 3) as u32 + 7 } else { next(&mut s) as u32 })
                    .collect();
                native = apply_batch_ss_full(&native, &ss_updates_of(&raw)).0;
                rows = apply_batch_mg(cap, &rows, &map_batch(&raw), algo).0;
                assert_eq!(diff_rows(&format!("{} wide epoch {e}", algo.name()), &rows, &native), 0);
            }
            assert!(native.rows.iter().any(|r| r.count > 2048), "heavy counts not reached");
        }
    }

    #[test]
    fn commitments_bind_every_word_and_the_params() {
        let cap = 4;
        let mut rows = empty_rows(cap);
        rows[12..16].copy_from_slice(&[7, 0, 3, 1]);
        let c = state_commit(cap as u32, 2, &rows);
        for w in 0..rows.len() {
            let mut r2 = rows.clone();
            r2[w] ^= 1;
            assert_ne!(state_commit(cap as u32, 2, &r2), c, "word {w} not bound");
        }
        assert_ne!(state_commit(cap as u32 + 2, 2, &rows), c);
        assert_ne!(state_commit(cap as u32, 4, &rows), c);
        let b = map_batch(&[5, PAD_KEY]);
        assert_ne!(batch_commit(2, &b), batch_commit(2, &map_batch(&[5, 7])));
    }

    #[test]
    #[should_panic(expected = "inactive row is not the all-zero dummy")]
    fn malformed_dummy_rejected() {
        let mut rows = empty_rows(2);
        rows[2] = 5; // a count on an inactive row
        apply_batch_mg(2, &rows, &map_batch(&[1, 2]), SortAlgo::Radix);
    }

    #[test]
    #[should_panic(expected = "active key is 0")]
    fn active_key_zero_rejected() {
        let mut rows = empty_rows(2);
        rows[4..8].copy_from_slice(&[0, 0, 1, 1]);
        apply_batch_mg(2, &rows, &map_batch(&[1, 2]), SortAlgo::Std);
    }
}
