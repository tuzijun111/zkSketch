//! Accuracy harness, OUR side (zkSketch Count-Min, cm_omc addressing).
//!
//! Reads a key stream (one decimal u64 key per line) on stdin, folds it into a
//! d x w Count-Min sketch using EXACTLY the addressing the `cm_omc` /
//! `countmin_final` circuit uses -- `zksketch::sketch::countmin_final::
//! hash_cell_prf` (Poseidon2 sponge over BabyBear, digest element `row` mod w)
//! -- and prints, for every distinct key, `key,exact,estimate`.
//!
//! Value per record is 1 (frequency counting), so the CM error is directly
//! comparable to the classical eps*||f||_1 bound with ||f||_1 = n_records.
//!
//! Usage: acc_ours --d 3 --w 1024 < stream.txt

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};

use zksketch::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch::commitment::countmin::commit_countmin;
use zksketch::commitment::countmin_batch::commit_batch;
use zksketch::sketch::countmin_final::{apply_update_prf, hash_cell_prf};

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
    let d: usize = arg("--d", "3").parse().unwrap();
    let w: usize = arg("--w", "1024").parse().unwrap();
    let selfcheck = arg("--selfcheck", "0") == "1";

    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).unwrap();
    let keys: Vec<u64> = buf
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().parse::<u64>().unwrap())
        .collect();

    // Exact per-key frequencies.
    let mut exact: BTreeMap<u64, u64> = BTreeMap::new();
    for k in &keys {
        *exact.entry(*k).or_insert(0) += 1;
    }

    // Count-Min table. CM is linear and `saturating_add` never saturates at
    // these magnitudes, so folding `exact[key]` once per distinct key is
    // identical to replaying every record; it just avoids re-running the
    // Poseidon2 sponge n_records times. `--selfcheck 1` proves the identity
    // against the real per-record `apply_update_prf` replay.
    let mut table: Vec<Vec<u64>> = vec![vec![0u64; w]; d];
    let mut cols: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (&k, &c) in &exact {
        let mut kc = Vec::with_capacity(d);
        for r in 0..d {
            let j = hash_cell_prf(r, k, w);
            table[r][j] += c;
            kc.push(j);
        }
        cols.insert(k, kc);
    }

    if selfcheck {
        let mut st: CountMinState = CountMinState {
            counters: vec![vec![0u32; w]; d],
            params: CountMinParams { d, w },
        };
        for k in &keys {
            apply_update_prf(&mut st, &CountMinUpdate { key: *k, value: 1 });
        }
        for r in 0..d {
            for j in 0..w {
                assert_eq!(
                    st.counters[r][j] as u64, table[r][j],
                    "selfcheck: replay != folded at ({r},{j})"
                );
            }
        }
        eprintln!("[acc_ours] selfcheck OK: per-record apply_update_prf replay == folded table");
    }

    // Optional plaintext-cost measurement: the same analytics the cm_omc
    // circuit proves, run natively (min of `reps` full replays).
    if let Ok(reps) = arg("--bench", "0").parse::<u32>() {
        if reps > 0 {
            let mut best = u128::MAX;
            for _ in 0..reps {
                let mut st = CountMinState {
                    counters: vec![vec![0u32; w]; d],
                    params: CountMinParams { d, w },
                };
                let t = std::time::Instant::now();
                for k in &keys {
                    apply_update_prf(&mut st, &CountMinUpdate { key: *k, value: 1 });
                }
                best = best.min(t.elapsed().as_nanos());
                std::hint::black_box(&st);
            }
            // ---- SCOPE-MATCHED arm (fairness) ----
            // The line above times apply_update_prf ONLY: d PRF cell bumps per
            // record, no commitment of any kind.  zk-Analytics' native_baseline
            // times process_cm_aggr_with_state (aggregator/core/src/lib.rs:1215),
            // which ALSO does: per-batch SHA-256 chain verify, the top-k heap,
            // 3 CM row Merkle roots over 1024 leaves each, the heap root, and
            // the epoch state commit.  Dividing their ZK time by THAT plaintext
            // and our ZK time by the line above compares two different
            // denominators, so the two "ZK/plain" ratios are not comparable.
            // This arm adds our leaf's own binding work -- commit_batch over all
            // records (the in-circuit batch digest, countmin_omc.rs:281/349) and
            // commit_countmin over the d*w state (the boundary commitment) --
            // so the denominator covers the same class of work as theirs.
            let recs: Vec<CountMinUpdate> =
                keys.iter().map(|k| CountMinUpdate { key: *k, value: 1 }).collect();
            let mut best_full = u128::MAX;
            for _ in 0..reps {
                let mut st = CountMinState {
                    counters: vec![vec![0u32; w]; d],
                    params: CountMinParams { d, w },
                };
                let t = std::time::Instant::now();
                for r in &recs {
                    apply_update_prf(&mut st, r);
                }
                let bc = commit_batch(&recs);
                let sc = commit_countmin(&st);
                best_full = best_full.min(t.elapsed().as_nanos());
                std::hint::black_box((&st, &bc, &sc));
            }
            eprintln!(
                "zksketch_native_scopematched_ms={:.4}",
                best_full as f64 / 1e6
            );
            eprintln!("zksketch_native_single_thread_ms={:.4}", best as f64 / 1e6);
            eprintln!("zksketch_native_records={}", keys.len());
            eprintln!("zksketch_native_d={d} zksketch_native_w={w}");
            let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            for l in s.lines() {
                if l.starts_with("VmHWM:") {
                    eprintln!("zksketch_native_peak_rss_kb={}", l.split_whitespace().nth(1).unwrap_or("0"));
                }
            }
        }
    }

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    writeln!(out, "key,exact,estimate").unwrap();
    for (&k, &c) in &exact {
        let kc = &cols[&k];
        let est = (0..d).map(|r| table[r][kc[r]]).min().unwrap_or(0);
        writeln!(out, "{k},{c},{est}").unwrap();
    }
    out.flush().unwrap();
    let _ = std::io::stdin().lock().lines();
}
