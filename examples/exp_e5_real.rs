//! E5 with real recursive proofs: E Count-Min leaves verified one by one vs folded into one proof.
//! Usage: [EXP_E5R_WINDOWS=2,4,8] cargo run --release --example exp_e5_real

use std::time::{Duration, Instant};

use zksketch::experiments::metrics::{append_csv, write_env_json};
use zksketch::experiments::results_dir;
use zksketch::recursion::recursive::countmin_chain::CountMinChainState;
use zksketch::recursion::recursive::countmin_leaf::{prove_countmin_leaf, D, W};
use zksketch::recursion::recursive::countmin_merge::verify_chain_countmin;
use zksketch::recursion::recursive::timing;
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::Sketch;

fn env_windows() -> Vec<usize> {
    match std::env::var("EXP_E5R_WINDOWS") {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).filter(|&e| e >= 2).collect(),
        Err(_) => vec![2, 4, 8],
    }
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}

fn empty_state() -> CountMinState {
    CountMin::new(&CountMinParams { d: D, w: W })
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    let windows = env_windows();
    println!("E5 REAL recursive composition (plonky3) — (d,w)=({D},{W}), windows={windows:?}");

    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky3".into()), ("field", "BabyBear".into()),
        ("hash", "Poseidon2".into()), ("experiment", "e5_real".into()),
        ("composition", "real_recursive_aggregation".into()),
    ]);
    let hdr: Vec<String> = ["setting", "E", "verifier_checks", "verify_ms",
        "root_proof_bytes", "merge_prove_total_ms", "leaf_prove_total_ms"]
        .iter().map(|s| s.to_string()).collect();
    let _ = std::fs::remove_file(dir.join("e5_real.csv"));

    for &e in &windows {
        // Build E real leaves, threading plaintext state; read each leaf's
        // self-verify time (recorded by the prover) for the no-composition rung.
        let mut state = empty_state();
        let mut leaves = Vec::with_capacity(e);
        let (mut leaf_prove_total, mut leaf_verify_total) = (Duration::ZERO, Duration::ZERO);
        let mut leaf_bytes_total = 0usize;
        for i in 0..e {
            let base = (i as u64) * 13 + 1;
            let batch = [
                CountMinUpdate { key: base, value: 3 },
                CountMinUpdate { key: base + 7, value: 5 },
            ];
            let leaf = prove_countmin_leaf(state.clone(), batch);
            let t = timing::take(); // this leaf's witness/prove/verify split
            leaf_prove_total += t.witness + t.prove;
            leaf_verify_total += t.verify;
            leaf_bytes_total += serialized_size(&leaf.output.0);
            for u in &batch {
                CountMin::update(&mut state, u);
            }
            leaves.push(leaf);
        }

        // Fold into one recursive batch-STARK: init(l1,l2) + (E-2) extends.
        let t = Instant::now();
        let mut chain = CountMinChainState::init(&leaves[0], &leaves[1]).expect("init");
        for next in &leaves[2..] {
            chain.extend(next).expect("extend");
        }
        let merge_prove_total = t.elapsed();

        // Real verify of the single folded proof.
        let t = Instant::now();
        verify_chain_countmin(&chain.root).expect("verify chain");
        let chain_verify = t.elapsed();
        let chain_bytes = serialized_size(&chain.root.recursive_proof.0);

        // Rung 1: no composition — Θ(E) verifier checks + Σ leaf bytes.
        append_csv(&dir, "e5_real", &hdr, &vec![
            "no_composition".into(), e.to_string(), e.to_string(),
            format!("{:.3}", ms(leaf_verify_total)), leaf_bytes_total.to_string(),
            "0.000".into(), format!("{:.3}", ms(leaf_prove_total)),
        ]);
        // Rung 2: real recursive linear chain — O(1) verifier: one proof.
        let path = append_csv(&dir, "e5_real", &hdr, &vec![
            "recursive_linear".into(), e.to_string(), "1".into(),
            format!("{:.3}", ms(chain_verify)), chain_bytes.to_string(),
            format!("{:.3}", ms(merge_prove_total)), format!("{:.3}", ms(leaf_prove_total)),
        ]);

        println!(
            "  E={e:<2}: no-comp {} checks / {} B / verify {:.2}ms   ||   recursive 1 check / {} B / verify {:.2}ms  (fold {:.1}ms)",
            e, leaf_bytes_total, ms(leaf_verify_total),
            chain_bytes, ms(chain_verify), ms(merge_prove_total)
        );
        let _ = path;
    }
    println!("done → {}", dir.join("e5_real.csv").display());
}
