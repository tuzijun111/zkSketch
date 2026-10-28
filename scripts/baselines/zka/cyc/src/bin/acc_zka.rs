//! CM accuracy, zk-Analytics side: their aggregation and CM point query on a key stream.
//! Usage: acc_zka [--batch 8] < stream.txt      (prints key,exact,estimate)

use std::collections::BTreeMap;
use std::io::{Read, Write};

use aggregator_core::{
    batch_chain_hash, process_cm_aggr_with_state, BatchInput, CmAggrInput, CmEpochState, CM_COLS,
    CM_ROWS,
};
use querier_core::{CmQuery, CmQueryInput, CmQueryResult};
use zkvm_common::{Event, KEY_BYTES_LEN};

fn arg(name: &str, default: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    for i in 0..a.len() {
        if a[i] == name {
            if let Some(v) = a.get(i + 1) {
                return v.clone();
            }
        }
    }
    default.to_string()
}

fn main() {
    let batch_size: usize = arg("--batch", "8").parse().unwrap();

    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).unwrap();
    let keys: Vec<u64> = buf
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().parse::<u64>().unwrap())
        .collect();

    let mut exact: BTreeMap<u64, u64> = BTreeMap::new();
    for k in &keys {
        *exact.entry(*k).or_insert(0) += 1;
    }

    // Build their per-source hash-chained batches over the stream, in stream
    // order (their generator groups by key first; grouping does not change the
    // CM table, which is order-independent).
    let events: Vec<Event> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| Event {
            ts: i as u32,
            key_id: Event::make_key_id(0, *k),
            value: 1,
        })
        .collect();

    let mut batches: Vec<BatchInput> = Vec::new();
    let mut chain_tip = [0u8; 32];
    let mut seq = 0u64;
    for chunk in events.chunks(batch_size) {
        let evs: Vec<Event> = chunk.to_vec();
        let bh = batch_chain_hash(chain_tip, &evs);
        chain_tip = bh;
        batches.push(BatchInput {
            source_id: 0,
            source_batch_seq: seq,
            events: evs,
            sent_batch_hash: bh,
        });
        seq += 1;
    }

    let input = CmAggrInput {
        prev_chain_hash: [0u8; 32],
        batches,
        prev_source_chain_tips: Vec::new(),
    };
    let (state, out) = process_cm_aggr_with_state(&input);
    assert_eq!(out.n_events as usize, keys.len());
    let epoch_state = CmEpochState::from(&state);
    assert_eq!(epoch_state.counts.len(), CM_ROWS * CM_COLS);

    let stdout = std::io::stdout();
    let mut w = std::io::BufWriter::new(stdout.lock());
    writeln!(w, "key,exact,estimate").unwrap();
    for (&k, &c) in &exact {
        let key_id: [u8; KEY_BYTES_LEN] = Event::make_key_id(0, k);
        // Their query guest logic, one epoch. epoch_chain_links left empty so
        // the (already-exercised) chain verification is skipped; it does not
        // touch the estimate.
        let qin = CmQueryInput {
            query: CmQuery::Estimate { key: key_id },
            epoch_states: vec![epoch_state.clone()],
            epoch_chain_links: Vec::new(),
        };
        let est = match querier_core::run_cm_query(&qin).result {
            CmQueryResult::Estimate { estimate } => estimate,
            _ => unreachable!(),
        };
        writeln!(w, "{k},{c},{est}").unwrap();
    }
    w.flush().unwrap();
}
