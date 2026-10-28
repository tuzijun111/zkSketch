//! Proves only zkSketch's CM decode (point query) circuit on a natively built d x w state.
//! Usage: [D=3 W=1024 N=16384 DATASET=uniform KEY_MODE=first TRIALS=1 SEEDS=1 CSV=out.csv
//!        CORES=N (default: all threads) TAG=zks_cm_decode DRY_RUN=1 (plaintext only, no proof)] cmq

use std::collections::BTreeMap;
use std::io::Write;
use std::time::Instant;

use zksketch::commitment::countmin::commit_countmin;
use zksketch::decode::countmin::{prove_cm_decode, CmDecodeParams};
use zksketch::decode::ReleasePolicy;
use zksketch::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch::recursion::recursive::timing;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::countmin_final::{apply_update_prf, hash_cell_prf};
use zksketch::sketch::Sketch;

fn env_str(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}
fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d)
}

/// Peak RSS of THIS process, from /proc/self/status VmHWM (kB -> MB).
/// In-process prover: there is no child to sample (contrast the risc0 driver,
/// which must sample the separate `r0vm` process).
fn peak_rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<f64>().ok()))
        })
        .map(|kb| kb / 1024.0)
        .unwrap_or(0.0)
}

// ---- copies of splitmix64 / select_query_key (private in src/experiments/stream_compose.rs; same logic, mode passed as a string) ----
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn select_query_key(
    mode: &str,
    freq: &BTreeMap<u64, u64>,
    first: u64,
    seed: u64,
    domain_mask: u64,
) -> u64 {
    match mode {
        "hot" => freq
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, _)| *k)
            .unwrap_or(first),
        "uniform_stream" => {
            let total: u64 = freq.values().sum();
            if total == 0 {
                return first;
            }
            let mut r = splitmix64(seed) % total;
            for (k, c) in freq {
                if r < *c {
                    return *k;
                }
                r -= *c;
            }
            first
        }
        "absent" => {
            let mut cand = splitmix64(seed ^ 0xD1B5_4A32_D192_ED03) & domain_mask;
            for _ in 0..128 {
                if !freq.contains_key(&cand) {
                    return cand;
                }
                cand = splitmix64(cand) & domain_mask;
            }
            cand
        }
        _ => first, // "first" — the harness default
    }
}

fn keys_for(name: &str, n: usize, seed: u64) -> Vec<u32> {
    match name {
        "gaussian" => synthetic_stream(Synthetic::Gaussian, n, seed),
        "zipf" => zipf_stream(1.0, n.max(16), n, seed),
        "aol" => aol().map(|k| take(&k, n)).unwrap_or_else(|| synthetic_stream(Synthetic::Uniform, n, seed)),
        "netflix" => netflix().map(|k| take(&k, n)).unwrap_or_else(|| synthetic_stream(Synthetic::Uniform, n, seed)),
        _ => synthetic_stream(Synthetic::Uniform, n, seed),
    }
}

fn cm_state(d: usize, w: usize, keys: &[u32]) -> CountMinState {
    let mut s = CountMin::new(&CountMinParams { d, w });
    for &k in keys {
        apply_update_prf(&mut s, &CountMinUpdate { key: k as u64, value: 1 });
    }
    s
}

fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let d = env_usize("D", 3);
    let w = env_usize("W", 1024);
    let n = env_usize("N", 16384);
    let trials = env_usize("TRIALS", 1);
    let seeds = env_usize("SEEDS", 1);
    let dataset = env_str("DATASET", "uniform");
    let key_mode = env_str("KEY_MODE", "first");
    let cores = env_usize("CORES", rayon::current_num_threads());
    let tag = env_str("TAG", "zks_cm_decode");
    // DRY_RUN=1: plaintext only (state build + probe selection + ground truth
    // + commitment). Proves NOTHING. Used to smoke the harness on a shared box
    // without taking a prover slot.
    let dry = env_usize("DRY_RUN", 0) == 1;
    let csv = env_str("CSV", "");

    let hdr = "tag,system,family,variant,d,w,state_cells,n_records,dataset,key_mode,seed,\
trial_count,cores,query_prove_ms,query_verify_ms,query_proof_bytes,answer,native_est,\
true_count,rel_err,peak_rss_mb,status";
    println!("{hdr}");
    let mut sink = if csv.is_empty() {
        None
    } else {
        let fresh = !std::path::Path::new(&csv).exists();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&csv).unwrap();
        if fresh {
            writeln!(f, "{hdr}").unwrap();
        }
        Some(f)
    };

    let pool = rayon::ThreadPoolBuilder::new().num_threads(cores.max(1)).build().unwrap();

    for s in 0..seeds {
        let seed = (s as u64) + 1;
        let keys = keys_for(&dataset, n, seed);
        let st = cm_state(d, w, &keys);

        // ground truth + native PRF-consistent estimate (mirrors
        // `run_cm` in examples/exp_decode.rs)
        let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
        for &k in &keys {
            *freq.entry(k as u64).or_insert(0) += 1;
        }
        let probe = select_query_key(&key_mode, &freq, keys[0] as u64, seed, 0xFFFF_FFFF);
        let true_count = *freq.get(&probe).unwrap_or(&0);
        let native_est = (0..d)
            .map(|row| st.counters[row][hash_cell_prf(row, probe, w)] as u64)
            .min()
            .unwrap();
        let commit = commit_countmin(&st).0;

        let mut pv = Vec::new();
        let mut vv = Vec::new();
        let mut bytes = 0u64;
        let mut answer = 0u64;
        let mut ok = true;
        for _ in 0..trials {
            if dry {
                pv.push(0.0);
                vv.push(0.0);
                answer = native_est;
                continue;
            }
            let t0 = Instant::now();
            // `DecodeProof` holds an `Rc` and is NOT `Send`, so, as with
            // `QueryArt` in src/experiments/stream_compose.rs, only the Send
            // metrics cross the pool boundary.
            let (prove_ms, verify_ms, b, a) = pool.install(|| {
                let _ = timing::take(); // clear anything left over
                let p = prove_cm_decode(
                    CmDecodeParams { d, w, release: ReleasePolicy::Identity },
                    st.clone(),
                    probe,
                );
                let tm = timing::take();
                // prove_ms mirrors `record_query` in src/experiments/stream_compose.rs
                // (witness + prove).
                (
                    (tm.witness + tm.prove).as_secs_f64() * 1e3,
                    tm.verify.as_secs_f64() * 1e3,
                    p.proof_size() as u64,
                    p.answer,
                )
            });
            let wall = t0.elapsed().as_secs_f64() * 1e3;
            pv.push(if prove_ms > 0.0 { prove_ms } else { wall });
            vv.push(verify_ms);
            bytes = b;
            answer = a;
            ok &= a == native_est && a >= true_count;
        }
        let rel = if true_count > 0 {
            (answer as f64 - true_count as f64) / true_count as f64
        } else {
            f64::NAN
        };
        let row = format!(
            "{tag},zksketch,cm,cm_omc,{d},{w},{},{n},{dataset},{key_mode},{seed},{trials},{cores},\
{:.3},{:.3},{bytes},{answer},{native_est},{true_count},{:.6},{:.1},{}",
            d * w,
            median(pv),
            median(vv),
            rel,
            peak_rss_mb(),
            if dry { "dry" } else if ok { "ok" } else { "MISMATCH" }
        );
        println!("{row}");
        if let Some(f) = sink.as_mut() {
            writeln!(f, "{row}").unwrap();
        }
        // commit is bound in-circuit by the decode AIR; print it once for the
        // binding audit trail (matches stream_compose::record_query's assert).
        eprintln!("  seed={seed} probe={probe} Com(S)[0]={:?} cells={}", commit[0], d * w);
    }
}
