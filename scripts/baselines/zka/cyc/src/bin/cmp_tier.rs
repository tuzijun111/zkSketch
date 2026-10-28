// zk-Analytics' CM aggregation guest proved as composite, then compressed to succinct; both steps timed.
// Usage: [VERIFY_REPS=1] cmp_tier <n_records> <distinct_keys> <chunk_batch>
use aggregator_core::{batch_chain_hash, BatchInput, CmAggrInput};
use aggregator_methods::{AGGR_CM_ELF, AGGR_CM_ID};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};
use zkvm_common::Event;

fn verify_min_of(receipt: &Receipt, reps: usize) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..reps {
        let t = std::time::Instant::now();
        receipt.verify(AGGR_CM_ID).unwrap();
        let e = t.elapsed().as_secs_f64();
        if e < best {
            best = e;
        }
    }
    best * 1000.0
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(16384);
    let keys: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(1024);
    let cbs: usize = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(8);
    // Verify reps: keep it symmetric with whatever the zkSketch side reports.
    // zkSketch's stream_compose runs bench(warmup:0, trials:1) -> ONE cold
    // verify.  cmp's min-of-5 is a warm best-case and is NOT comparable to it.
    let vreps: usize = std::env::var("VERIFY_REPS").ok().and_then(|s| s.parse().ok()).unwrap_or(1);

    let mut rng = StdRng::seed_from_u64(7);
    let mut evs: Vec<Event> = Vec::with_capacity(n);
    for _ in 0..n {
        let ki = rng.next_u64() % keys;
        // value=1: their table does saturating_add(ev.value) (lib.rs:1250), so
        // value must be 1 for it to be a FREQUENCY table matching our CM.
        evs.push(Event { ts: rng.next_u32() % 1_000_000, key_id: Event::make_key_id(0, ki), value: 1 });
    }
    let mut batches = Vec::new();
    let (mut tip, mut seq) = ([0u8; 32], 0u64);
    for chunk in evs.chunks(cbs) {
        let events = chunk.to_vec();
        let h = batch_chain_hash(tip, &events);
        tip = h;
        batches.push(BatchInput { source_id: 0, source_batch_seq: seq, events, sent_batch_hash: h });
        seq += 1;
    }
    let input = CmAggrInput { prev_chain_hash: [0u8; 32], batches, prev_source_chain_tips: vec![] };

    // ---- tier 1: COMPOSITE (segment STARKs only, no recursion) ----
    let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let prover = default_prover();
    let t0 = std::time::Instant::now();
    let info = prover
        .prove_with_opts(env, AGGR_CM_ELF, &ProverOpts::default()) // ReceiptKind::Composite
        .unwrap();
    let composite_s = t0.elapsed().as_secs_f64();
    let cycles = info.stats.total_cycles;
    let segments = info.stats.segments;
    let comp = info.receipt;
    let comp_bytes = bincode::serialize(&comp).map(|v| v.len()).unwrap_or(0);
    let comp_verify_ms = verify_min_of(&comp, vreps);

    // ---- tier 2: SUCCINCT (lift/join recursion over those segments) ----
    let t1 = std::time::Instant::now();
    let succ = prover.compress(&ProverOpts::succinct(), &comp).unwrap();
    let compress_s = t1.elapsed().as_secs_f64();
    let succ_bytes = bincode::serialize(&succ).map(|v| v.len()).unwrap_or(0);
    let succ_verify_ms = verify_min_of(&succ, vreps);

    let total_s = composite_s + compress_s;
    println!("tier,n,keys,cycles,segments,prove_s,khz,rec_per_s,verify_ms,receipt_bytes,verify_reps");
    println!(
        "composite,{n},{keys},{cycles},{segments},{composite_s:.3},{:.2},{:.4},{comp_verify_ms:.3},{comp_bytes},{vreps}",
        cycles as f64 / composite_s / 1000.0,
        n as f64 / composite_s
    );
    println!(
        "succinct,{n},{keys},{cycles},{segments},{total_s:.3},{:.2},{:.4},{succ_verify_ms:.3},{succ_bytes},{vreps}",
        cycles as f64 / total_s / 1000.0,
        n as f64 / total_s
    );
    eprintln!("compress_s={compress_s:.3} (composite->succinct recursion tree; the tier zkSketch's raw leaf does NOT pay)");
    eprintln!("check: composite_s + compress_s = {total_s:.3} should match cmp's prove_s at the same n/TOPK");
}
