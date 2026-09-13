// M2: whole-prefix Count-Min QUERY sweep for zk-Analytics (rev d4a5a9a9).
//
// One process == one data point (n epochs), so the shell harness can be resumed.
// State generation is a verbatim port of their own bench harness so the numbers
// are directly comparable:
//   zka/querier/host/src/bin/bench_queries.rs:93-135  select_epoch_sources
//   zka/querier/host/src/bin/bench_queries.rs:145-158 cm_bucket_index
//   zka/querier/host/src/bin/bench_queries.rs:225-292 generate_cm_epoch_multi_source
//   zka/querier/host/src/bin/bench_queries.rs:300-347 order_by_aggregator / build_chain_links
//   zka/querier/host/src/bin/bench_queries.rs:489-556 run_cm_benchmark (prove/verify/size)
//
// Differences from their bench_queries, all additive:
//   * only the CM guest runs, and only ONE CmQuery per process (theirs always
//     runs BOTH cm/estimate and cm/topk -- there is no --skip-cm-topk).
//   * full-precision journal bytes + raw public-output bytes are emitted
//     (theirs prints journal size only through format_size(), lossy, and drops
//     it entirely from its CSVROW line, bench_queries.rs:1191-1198).
//   * executor-only mode (default) so nothing proves unless --prove is passed.
//
// Usage:
//   qsweep --epochs N [--query estimate|topk] [--keys-per-source K]
//          [--events-per-key E] [--num-sources S] [--sources-per-epoch P]
//          [--num-aggregators A] [--seed X] [--prove] [--header]
// Default is EXECUTOR ONLY. --prove is opt-in.

use aggregator_core::{
    cm_epoch_state_commit, CmEpochState, EpochChainLink, CM_COLS, CM_ROWS, CM_SEEDS,
    CM_TOPK_SLOTS,
};
use querier_core::{CmQuery, CmQueryInput, CmQueryOutput, CmQueryResult};
use querier_methods::{QUERIER_GUEST_CM_ELF, QUERIER_GUEST_CM_ID};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};
use sha2::{Digest as _, Sha256};
use std::time::Instant;
use zkvm_common::KEY_BYTES_LEN;

const TAG_EPOCH_CHAIN: &[u8] = b"ZKTLM_EPOCH_CHAIN_V1";

// Hand-rolled parsers silently ignoring an unknown flag is how a typo becomes a
// silently WRONG configuration instead of an error (their own bench_queries.rs:63-91
// has exactly this failure mode). We validate the whole argv up front and refuse
// to run on anything unrecognised, and we refuse to silently default a value that
// does not parse.
const VALUE_FLAGS: &[&str] = &[
    "--epochs",
    "--events-per-key",
    "--seed",
    "--num-sources",
    "--keys-per-source",
    "--sources-per-epoch",
    "--num-aggregators",
    "--query",
];
const BOOL_FLAGS: &[&str] = &["--prove", "--header"];

fn validate_args() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if BOOL_FLAGS.contains(&a) {
            i += 1;
        } else if VALUE_FLAGS.contains(&a) {
            if i + 1 >= args.len() {
                eprintln!("qsweep: '{a}' requires a value");
                std::process::exit(2);
            }
            i += 2;
        } else {
            eprintln!("qsweep: unknown argument '{a}'");
            eprintln!("  value flags: {}", VALUE_FLAGS.join(" "));
            eprintln!("  bool  flags: {}", BOOL_FLAGS.join(" "));
            std::process::exit(2);
        }
    }
}

fn arg_u64(name: &str, default: u64) -> u64 {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == name {
            let v = it.next().expect("validated above");
            return v.parse().unwrap_or_else(|_| {
                eprintln!("qsweep: {name}='{v}' is not a non-negative integer");
                std::process::exit(2);
            });
        }
    }
    default
}
fn arg_str(name: &str, default: &str) -> String {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == name {
            if let Some(v) = it.next() {
                return v;
            }
        }
    }
    default.to_string()
}
fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

// bench_queries.rs:95-99
fn make_key_id(source_id: u32, key_index: u64) -> [u8; KEY_BYTES_LEN] {
    let mut key_id = [0u8; KEY_BYTES_LEN];
    key_id[3..7].copy_from_slice(&source_id.to_be_bytes());
    key_id[15 - 8..].copy_from_slice(&key_index.to_be_bytes());
    key_id
}

// bench_queries.rs:112-135
fn select_epoch_sources(
    epoch_idx: u64,
    num_sources: u32,
    sources_per_epoch: u32,
    rng: &mut StdRng,
) -> Vec<u32> {
    use rand::seq::SliceRandom;
    let epoch_seed = rng.next_u64().wrapping_add(epoch_idx);
    let mut epoch_rng = StdRng::seed_from_u64(epoch_seed);
    let mut all: Vec<u32> = (0..num_sources).collect();
    all.shuffle(&mut epoch_rng);
    let mut sel: Vec<u32> = all.into_iter().take(sources_per_epoch as usize).collect();
    sel.sort_unstable();
    sel
}

fn sha256_bytes(parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Sha256::new();
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}

// bench_queries.rs:145-158 (identical to querier/core/src/lib.rs:147-156)
fn cm_bucket_index(key: &[u8; KEY_BYTES_LEN], row: usize) -> usize {
    fn key_to_u64(key: &[u8; KEY_BYTES_LEN]) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for &b in key.iter() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
    let seed = CM_SEEDS[row];
    let mut x = key_to_u64(key) ^ (((seed as u64) << 32) | seed as u64);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x as usize) % CM_COLS
}

// bench_queries.rs:229-292
fn generate_cm_epoch(
    source_ids: &[u32],
    keys_per_source: u64,
    events_per_key: u32,
    value_mod: u32,
    rng: &mut StdRng,
) -> CmEpochState {
    let mut counts = vec![0u32; CM_ROWS * CM_COLS];
    let mut total_sum = 0u64;
    let mut key_counts: std::collections::HashMap<[u8; KEY_BYTES_LEN], u64> =
        std::collections::HashMap::new();

    for &source_id in source_ids {
        for key_idx in 0..keys_per_source {
            let key_id = make_key_id(source_id, key_idx);
            let mut key_total = 0u64;
            for _ in 0..events_per_key {
                let value = rng.next_u32() % value_mod;
                for r in 0..CM_ROWS {
                    let col = cm_bucket_index(&key_id, r);
                    let idx = r * CM_COLS + col;
                    counts[idx] = counts[idx].saturating_add(value);
                }
                key_total += value as u64;
                total_sum += value as u64;
            }
            *key_counts.entry(key_id).or_insert(0) += key_total;
        }
    }

    let mut sorted: Vec<_> = key_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    let mut heap_keys = vec![[0u8; KEY_BYTES_LEN]; CM_TOPK_SLOTS];
    let mut heap_vals = vec![0u64; CM_TOPK_SLOTS];
    let mut heap_occ = vec![0u8; CM_TOPK_SLOTS];
    for (i, (k, c)) in sorted.into_iter().take(CM_TOPK_SLOTS).enumerate() {
        heap_keys[i] = k;
        heap_vals[i] = c;
        heap_occ[i] = 1;
    }
    CmEpochState { counts, heap_keys, heap_vals, heap_occ, total_sum }
}

// bench_queries.rs:300-311
fn order_by_aggregator<S: Clone>(states: &[S], agg_ids: &[u32]) -> (Vec<S>, Vec<u32>) {
    let mut order: Vec<usize> = (0..states.len()).collect();
    order.sort_by_key(|&i| agg_ids[i]); // stable
    (
        order.iter().map(|&i| states[i].clone()).collect(),
        order.iter().map(|&i| agg_ids[i]).collect(),
    )
}

// bench_queries.rs:320-347
fn build_chain_links<S, F>(states: &[S], agg_ids: &[u32], commit: F) -> Vec<EpochChainLink>
where
    F: Fn(&S) -> [u8; 32],
{
    let mut links = Vec::with_capacity(states.len());
    let mut prev = [0u8; 32];
    let mut cur: Option<u32> = None;
    for (s, &a) in states.iter().zip(agg_ids.iter()) {
        if cur != Some(a) {
            prev = [0u8; 32];
            cur = Some(a);
        }
        let sc = commit(s);
        let fh = sha256_bytes(&[TAG_EPOCH_CHAIN, &prev, &sc]);
        links.push(EpochChainLink { prev_chain_hash: prev, state_commit: sc, final_chain_hash: fh });
        prev = fh;
    }
    links
}

fn main() {
    validate_args();
    if flag("--header") {
        println!("system,mode,query,epochs,num_sources,sources_per_epoch,keys_per_source,keys_total,events_per_key,topk_slots,cycles,segments,host_gen_s,prove_s,verify_ms,receipt_bytes,journal_bincode_bytes,pubout_raw_bytes,state_commits,query_receipts,agg_receipts_implied,total_receipts,estimate,suppressed,driver_rss_mb");
        return;
    }

    let n_epochs = arg_u64("--epochs", 1);
    let events_per_key = arg_u64("--events-per-key", 50) as u32;
    let seed = arg_u64("--seed", 0xBEEF);
    let num_sources = arg_u64("--num-sources", 4) as u32;
    let keys_per_source = arg_u64("--keys-per-source", 25);
    let sources_per_epoch = arg_u64("--sources-per-epoch", 2) as u32;
    let num_aggregators = arg_u64("--num-aggregators", 1).max(1) as u32;
    let query_name = arg_str("--query", "estimate");
    let do_prove = flag("--prove");
    let value_mod = 10_000u32;

    assert!(n_epochs >= 1, "--epochs must be >= 1");
    assert!(sources_per_epoch >= 1 && sources_per_epoch <= num_sources);

    let t_gen = Instant::now();

    // Epoch -> source assignment. bench_queries.rs:805-865, single-aggregator path.
    let sources_per_aggregator = num_sources / num_aggregators;
    let epochs_per_agg = if num_aggregators > 1 {
        (n_epochs + num_aggregators as u64 - 1) / num_aggregators as u64
    } else {
        n_epochs
    };
    let mut master = StdRng::seed_from_u64(seed);
    let mut agg_epochs: Vec<Vec<Vec<u32>>> = Vec::new();
    for agg in 0..num_aggregators {
        let start = agg * sources_per_aggregator;
        let mut v = Vec::new();
        for e in 0..epochs_per_agg {
            let sel = select_epoch_sources(
                e,
                sources_per_aggregator,
                sources_per_epoch.min(sources_per_aggregator),
                &mut master,
            );
            v.push(sel.iter().map(|&l| start + l).collect::<Vec<u32>>());
        }
        agg_epochs.push(v);
    }
    let mut assignments: Vec<Vec<u32>> = Vec::new();
    let mut agg_ids: Vec<u32> = Vec::new();
    for round in 0..epochs_per_agg as usize {
        for agg in 0..num_aggregators as usize {
            if round < agg_epochs[agg].len() {
                assignments.push(agg_epochs[agg][round].clone());
                agg_ids.push(agg as u32);
            }
        }
    }
    assignments.truncate(n_epochs as usize);
    agg_ids.truncate(n_epochs as usize);

    let mut rng = StdRng::seed_from_u64(seed);
    let states: Vec<CmEpochState> = assignments
        .iter()
        .map(|s| generate_cm_epoch(s, keys_per_source, events_per_key, value_mod, &mut rng))
        .collect();
    let (states, ordered_ids) = order_by_aggregator(&states, &agg_ids);
    let links = build_chain_links(&states, &ordered_ids, cm_epoch_state_commit);

    // bench_queries.rs:974-980: estimate query targets the hottest key of epoch 0.
    let first_key = if !states.is_empty() && states[0].heap_occ[0] != 0 {
        states[0].heap_keys[0]
    } else {
        make_key_id(assignments[0][0], 0)
    };
    let query = match query_name.as_str() {
        "topk" => CmQuery::Topk { limit: 10 },
        "estimate" => CmQuery::Estimate { key: first_key },
        other => panic!("unknown --query {other} (estimate|topk)"),
    };

    let input = CmQueryInput {
        query,
        epoch_states: states,
        epoch_chain_links: links,
    };
    let host_gen_s = t_gen.elapsed().as_secs_f64();

    // Executor: cycles + segments. Cheap, always run.
    let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let session = default_executor().execute(env, QUERIER_GUEST_CM_ELF).unwrap();
    let cycles = session.cycles();
    let segments = session.segments.len();

    // The executor already yields the journal (SessionInfo.journal, risc0-zkvm
    // 3.0.6 host/api/mod.rs:393), so public-output size and the state-commit
    // count are measured for free -- no prover needed.
    let mut journal_bincode = bincode::serialize(&session.journal).map(|v| v.len()).unwrap_or(0);
    let mut pubout_raw = session.journal.bytes.len();
    let exec_out: CmQueryOutput = session.journal.decode().unwrap();
    let mut state_commits = exec_out.state_commits.len();
    let mut suppressed = exec_out.suppressed;
    let mut estimate = match exec_out.result {
        CmQueryResult::Estimate { estimate } => estimate,
        CmQueryResult::Topk { ref items } => items.first().map(|i| i.count).unwrap_or(0),
    };

    let mut prove_s = f64::NAN;
    let mut verify_ms = f64::NAN;
    let mut receipt_bytes = 0usize;
    let mode = if do_prove { "prove" } else { "exec" };

    if do_prove {
        let env2 = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
        let t = Instant::now();
        let info = default_prover()
            .prove_with_opts(env2, QUERIER_GUEST_CM_ELF, &ProverOpts::succinct())
            .unwrap();
        prove_s = t.elapsed().as_secs_f64();
        let receipt = info.receipt;

        let mut best = f64::MAX;
        for _ in 0..5 {
            let t2 = Instant::now();
            receipt.verify(QUERIER_GUEST_CM_ID).unwrap();
            best = best.min(t2.elapsed().as_secs_f64() * 1000.0);
        }
        verify_ms = best;
        receipt_bytes = bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0);
        journal_bincode = bincode::serialize(&receipt.journal).map(|v| v.len()).unwrap_or(0);
        pubout_raw = receipt.journal.bytes.len();
        let out: CmQueryOutput = receipt.journal.decode().unwrap();
        state_commits = out.state_commits.len();
        suppressed = out.suppressed;
        estimate = match out.result {
            CmQueryResult::Estimate { estimate } => estimate,
            CmQueryResult::Topk { ref items } => items.first().map(|i| i.count).unwrap_or(0),
        };
    }

    // Driver RSS is NOT the prover peak (risc0 proves in a separate r0vm process);
    // the shell harness samples r0vm's VmHWM. Emitted only as a sanity column.
    let driver_rss_mb = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<f64>().ok()))
        })
        .unwrap_or(0.0)
        / 1024.0;

    // Receipt accounting: the query guest verifies only a SHA-256 chain over
    // host-supplied state commits (querier/core/src/lib.rs:253-269) and republishes
    // them (lib.rs:282-284, 216). env::verify / add_assumption appear nowhere in the
    // tree, so the n per-epoch aggregation receipts are NOT folded in and a verifier
    // must check them separately to bind those commits.
    let query_receipts = 1u64;
    let agg_receipts_implied = n_epochs;

    println!(
        "zka,{mode},cm/{query_name},{n_epochs},{num_sources},{sources_per_epoch},{keys_per_source},{},{events_per_key},{},{cycles},{segments},{host_gen_s:.3},{prove_s:.3},{verify_ms:.3},{receipt_bytes},{journal_bincode},{pubout_raw},{state_commits},{query_receipts},{agg_receipts_implied},{},{estimate},{suppressed},{driver_rss_mb:.1}",
        num_sources as u64 * keys_per_source,
        CM_TOPK_SLOTS,
        query_receipts + agg_receipts_implied,
    );
}
