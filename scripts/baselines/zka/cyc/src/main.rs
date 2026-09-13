use aggregator_core::{batch_chain_hash, BatchInput, CmAggrInput};
use aggregator_methods::AGGR_CM_ELF;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use risc0_zkvm::{ExecutorEnv, default_executor, default_prover, ProverOpts};
use zkvm_common::Event;

/// Env flags here are read with `is_ok()` semantics by risc0-era scripts, which
/// means `PROVE=0` would still PROVE. Treat 0/false/no/off/empty as OFF so a
/// deliberate "don't prove" cannot silently take a prover slot on a shared box.
fn env_on(k: &str) -> bool {
    match std::env::var(k) {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "no" | "off"),
        Err(_) => false,
    }
}

/// Positional args parsed with `unwrap_or(default)` turn a typo into a silently
/// WRONG configuration (`./cyc 2O48` -> n=4096) instead of an error.
fn pos(i: usize, name: &str, default: usize) -> usize {
    match std::env::args().nth(i) {
        None => default,
        Some(s) => s.parse().unwrap_or_else(|_| {
            eprintln!("cyc: argument {i} ({name}) = '{s}' is not an integer");
            std::process::exit(2);
        }),
    }
}

fn main() {
    // The steelman's cross-epoch CM state carry (steelman_plan.md item A10) is
    // NOT implemented in this binary. Without this guard `CARRY=1 ./cyc ...`
    // would run the plain no-carry path and report a 0% cycle delta as if the
    // patch were in place -- a silently wrong experiment, not an error.
    if std::env::var_os("CARRY").is_some() {
        eprintln!("cyc: CARRY is set but cross-epoch state carry is NOT implemented in this binary.");
        eprintln!("  Apply steelman_plan.md A10 (prev_state on CmAggrInput) and wire it here first;");
        eprintln!("  otherwise the carry arm is identical to the baseline and the delta is meaningless.");
        std::process::exit(2);
    }
    let n: usize = pos(1, "n_records", 4096);
    let keys: u64 = pos(2, "distinct_keys", 1024) as u64;
    let cbs: usize = pos(3, "chunk_batch_size", 8);
    let mut rng = StdRng::seed_from_u64(7);
    let mut evs: Vec<Event> = Vec::with_capacity(n);
    for _ in 0..n {
        let ki = (rng.next_u64()) % keys;
        evs.push(Event { ts: rng.next_u32() % 1_000_000, key_id: Event::make_key_id(0, ki), value: 1 + rng.next_u32() % 100 });
    }
    let mut batches = Vec::new();
    let mut tip = [0u8; 32];
    let mut seq = 0u64;
    for chunk in evs.chunks(cbs) {
        let events = chunk.to_vec();
        let h = batch_chain_hash(tip, &events);
        tip = h;
        batches.push(BatchInput { source_id: 0, source_batch_seq: seq, events, sent_batch_hash: h });
        seq += 1;
    }
    let input = CmAggrInput { prev_chain_hash: [0u8; 32], batches, prev_source_chain_tips: vec![] };
    let input2 = input.clone();
    let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let t = std::time::Instant::now();
    let info = default_executor().execute(env, AGGR_CM_ELF).unwrap();
    let el = t.elapsed();
    let cycles = info.cycles();
    // SEGMENT COUNT is what makes the prove-time model determinate. risc0 proves
    // segment-by-segment then lifts/joins, so prove_s is far better predicted by
    // `k * segments` than by a cycle-linear fit -- and the two models disagree by
    // up to 36% at small n. The executor yields segments for free and
    // deterministically, so every prove-time extrapolation can be anchored on a
    // measured s/segment instead of an assumed kHz. (qsweep.rs:325 does the same.)
    let segments = info.segments.len();
    println!("n={} keys={} cbs={} total_cycles={} cycles_per_record={:.1} segments={} cycles_per_segment={:.0} exec_s={:.2}",
        n, keys, cbs, cycles, cycles as f64 / n as f64,
        segments, cycles as f64 / segments.max(1) as f64, el.as_secs_f64());
    if env_on("PROVE") {
        let opts = if env_on("SUCCINCT") { ProverOpts::succinct() } else { ProverOpts::default() };
        let env2 = ExecutorEnv::builder().write(&input2).unwrap().build().unwrap();
        let t2 = std::time::Instant::now();
        let pi = default_prover().prove_with_opts(env2, AGGR_CM_ELF, &opts).unwrap();
        let e2 = t2.elapsed().as_secs_f64();
        let bytes = bincode_len(&pi.receipt);
        println!("PROVE opts={} prove_s={:.1} khz={:.1} rec_per_s={:.3} receipt_bytes={} s_per_segment={:.3}",
            if env_on("SUCCINCT") {"succinct"} else {"composite"},
            e2, cycles as f64/ e2 /1000.0, n as f64/e2, bytes,
            e2 / segments.max(1) as f64);
    }
}

fn bincode_len(r: &risc0_zkvm::Receipt) -> usize {
    bincode::serialize(r).map(|v| v.len()).unwrap_or(0)
}
