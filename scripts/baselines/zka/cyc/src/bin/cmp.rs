// Proves zk-Analytics' CM aggregation guest (succinct): cycles, prove/verify time, receipt size.
// Usage: cmp <n_records> <distinct_keys> <chunk_batch>
use aggregator_core::{batch_chain_hash, BatchInput, CmAggrInput};
use aggregator_methods::{AGGR_CM_ELF, AGGR_CM_ID};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};
use zkvm_common::Event;

// VmHWM of this driver only; r0vm proves in its own process (compare.sh samples that one).
fn peak_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(16384);
    let keys: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(1024);
    let cbs: usize = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(8);

    let mut rng = StdRng::seed_from_u64(7);
    let mut evs: Vec<Event> = Vec::with_capacity(n);
    for _ in 0..n {
        let ki = rng.next_u64() % keys;
        // value=1 so their value-sum table is a frequency table, matching our CM
        evs.push(Event {
            ts: rng.next_u32() % 1_000_000,
            key_id: Event::make_key_id(0, ki),
            value: 1,
        });
    }
    let mut batches = Vec::new();
    let (mut tip, mut seq) = ([0u8; 32], 0u64);
    for chunk in evs.chunks(cbs) {
        let events = chunk.to_vec();
        let h = batch_chain_hash(tip, &events);
        tip = h;
        batches.push(BatchInput {
            source_id: 0,
            source_batch_seq: seq,
            events,
            sent_batch_hash: h,
        });
        seq += 1;
    }
    let input = CmAggrInput {
        prev_chain_hash: [0u8; 32],
        batches,
        prev_source_chain_tips: vec![],
    };

    // cycles (executor only)
    let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let cycles = default_executor().execute(env, AGGR_CM_ELF).unwrap().cycles();

    // prove — succinct is the tier their artifact ships at every prove site
    let env2 = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let t = std::time::Instant::now();
    let info = default_prover()
        .prove_with_opts(env2, AGGR_CM_ELF, &ProverOpts::succinct())
        .unwrap();
    let prove_s = t.elapsed().as_secs_f64();
    let peak_rss = peak_rss_kb();

    let receipt = info.receipt;
    let bytes = bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0);

    // verify — min of 5
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t2 = std::time::Instant::now();
        receipt.verify(AGGR_CM_ID).unwrap();
        let e = t2.elapsed().as_secs_f64();
        if e < best {
            best = e;
        }
    }

    println!(
        "n={} keys={} cycles={} cycles_per_record={:.1} prove_s={:.3} khz={:.2} \
         rec_per_s={:.4} verify_ms={:.3} receipt_bytes={} peak_rss_mb={:.1}",
        n,
        keys,
        cycles,
        cycles as f64 / n as f64,
        prove_s,
        cycles as f64 / prove_s / 1000.0,
        n as f64 / prove_s,
        best * 1000.0,
        bytes,
        peak_rss as f64 / 1024.0
    );
}
