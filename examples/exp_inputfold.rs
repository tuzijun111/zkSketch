//! Input-commitment + history-fold over real batches (plonky3). For each family
//! it ingests `n` real batches — each leaf binds the batch's records to `Com(B_t)`
//! in circuit (the prove time is the **input-binding** cost) — then folds the
//! real `Com(B_t)` into a single history root `R(t)` via the streaming forest
//! (the merge count is the **fold** cost). This is the end-to-end tie between the
//! input commitment and the root that E5/E6 (composition only, synthetic leaves)
//! don't exercise.
//!
//! Run:    cargo run --release --example exp_inputfold
//! Config: EXP_IF_BATCHES=8   EXP_IF_M=16
//! Output: results/input_fold.csv
//!   phase=ingest rows (one per real batch): leaf_prove_ms, proof_size_bytes
//!   phase=fold rows (one per family): fold_merges, verifier_checks, root size

use zksketch::experiments::families::{
    cm_empty, cm_epoch, gk_empty, gk_epoch, hll_empty, hll_epoch, ss_empty, ss_epoch, EpochOutcome,
};
use zksketch::experiments::inputfold::{fold, leaf_of, row_of, IngestRow};
use zksketch::experiments::metrics::{append_csv, write_env_json};
use zksketch::experiments::{env_usize, results_dir};
use zksketch::recursion::framework::EpochLeaf;
use zksketch::recursion::mmr::{verify_inclusion, Mmr};
use zksketch::sketch::countmin_final::CountMinFinalParams;
use zksketch::sketch::gk_final_full::GKFullParams;
use zksketch::sketch::hll_final_full::HllFullParams;
use zksketch::sketch::ss_final_full::SsFullParams;

fn keys(m: usize, distinct: usize, salt: usize, mask: u32, nonzero: bool) -> Vec<u32> {
    (0..m)
        .map(|j| {
            let k = (((salt * distinct + (j % distinct)) as u64 + 1).wrapping_mul(0x9E37_79B9) as u32) & mask;
            if nonzero { k | 1 } else { k }
        })
        .collect()
}

fn main() {
    let n = env_usize("EXP_IF_BATCHES", 8) as u64;
    let m = env_usize("EXP_IF_M", 16);
    let me = if m % 2 == 0 { m } else { m + 1 };
    println!("input-commitment + fold (plonky3) — batches={n} m={m}");

    let dir = results_dir();
    write_env_json(&dir, &[
        ("backend", "plonky3".into()), ("field", "BabyBear".into()),
        ("hash", "Poseidon2".into()), ("experiment", "input_fold".into()),
    ]);
    let hdr: Vec<String> = ["phase", "family", "batch_index", "n_batches", "input_records",
        "leaf_prove_ms", "proof_size_bytes", "fold_merges", "worst_cascade", "verifier_checks",
        "root_proof_bytes"]
        .iter().map(|s| s.to_string()).collect();
    let _ = std::fs::remove_file(dir.join("input_fold.csv"));

    // family → (rows, leaves) ingest closures, threading real state.
    let mut emit = |family: &str, rows: &[IngestRow], leaves: &[EpochLeaf]| {
        for r in rows {
            let row = vec![
                "ingest".into(), family.into(), r.batch_index.to_string(), n.to_string(),
                r.input_records.to_string(), format!("{:.3}", r.leaf_prove_ms),
                r.proof_bytes.to_string(), "-".into(), "-".into(), "-".into(), "-".into(),
            ];
            append_csv(&dir, "input_fold", &hdr, &row);
        }
        let (s, _root) = fold(leaves);
        let avg_bind: f64 = rows.iter().map(|r| r.leaf_prove_ms).sum::<f64>() / rows.len() as f64;
        let fold_row = vec![
            "fold".into(), family.into(), "-".into(), s.n_batches.to_string(), "-".into(),
            "-".into(), "-".into(), s.total_merges.to_string(), s.worst_cascade.to_string(),
            s.verifier_checks.to_string(), s.root_proof_bytes.to_string(),
        ];
        append_csv(&dir, "input_fold", &hdr, &fold_row);
        println!(
            "  {family:<4} {n} real batches: avg input-bind {avg_bind:.1}ms/batch | fold {} merges → 1 root ({} checks, {}B), all bound={}",
            s.total_merges, s.verifier_checks, s.root_proof_bytes,
            rows.iter().all(|r| r.correct)
        );
        // Standalone MMR (ULog) over the same real Com(B_t): publish one root,
        // prove membership of a batch in O(log t) — decoupled from the proof.
        let mut mmr = Mmr::new();
        for l in leaves {
            mmr.append(l.batch_commit);
        }
        let mmr_root = mmr.root();
        let probe = leaves.len() / 2;
        let proof = mmr.prove(probe);
        let ok = verify_inclusion(&mmr_root, &leaves[probe].batch_commit, &proof);
        let proof_bytes = (proof.path.len() + proof.peaks.len()) * 32 + 24; // 8 Val × 4 B per digest
        let mmr_row = vec![
            "mmr".into(), family.into(), probe.to_string(), n.to_string(), "-".into(),
            "-".into(), proof_bytes.to_string(), mmr.num_peaks().to_string(), "-".into(),
            (ok as u64).to_string(), "32".into(),
        ];
        append_csv(&dir, "input_fold", &hdr, &mmr_row);
        println!(
            "       MMR(ULog) over {} real Com(B_t): {} peaks, root 32B; inclusion proof for batch {} = {}B, verified={}",
            leaves.len(), mmr.num_peaks(), probe, proof_bytes, ok
        );
    };

    // ── CM ───────────────────────────────────────────────────────────────────
    {
        let params = CountMinFinalParams { d: 4, w: 8, batch: m, distinct_bound: m };
        let mut state = cm_empty(4, 8);
        let (mut rows, mut leaves) = (Vec::new(), Vec::new());
        for i in 1..=n {
            let ks = keys(m, m, i as usize, 0xFFFF_FFFF, false);
            let (o, next): (EpochOutcome, _) = cm_epoch(params, &state, &ks);
            rows.push(row_of(i, &o, m));
            leaves.push(leaf_of(i, &o));
            state = next;
        }
        emit("cm", &rows, &leaves);
    }
    // ── GK ───────────────────────────────────────────────────────────────────
    {
        let params = GKFullParams { capacity: 8, batch: me };
        let mut state = gk_empty(params);
        let (mut rows, mut leaves) = (Vec::new(), Vec::new());
        for i in 1..=n {
            let ks = keys(me, me, i as usize, 0x003F_FFFF, false);
            let (o, next) = gk_epoch(params, &state, &ks);
            rows.push(row_of(i, &o, me));
            leaves.push(leaf_of(i, &o));
            state = next;
        }
        emit("gk", &rows, &leaves);
    }
    // ── HLL ──────────────────────────────────────────────────────────────────
    {
        let params = HllFullParams { b: 4, batch: me };
        let mut state = hll_empty(params);
        let (mut rows, mut leaves) = (Vec::new(), Vec::new());
        for i in 1..=n {
            let ks = keys(me, me, i as usize, 0xFFFF_FFFF, false);
            let (o, next) = hll_epoch(params, &state, &ks);
            rows.push(row_of(i, &o, me));
            leaves.push(leaf_of(i, &o));
            state = next;
        }
        emit("hll", &rows, &leaves);
    }
    // ── SS ───────────────────────────────────────────────────────────────────
    {
        let params = SsFullParams { capacity: 8, batch: me };
        let mut state = ss_empty(params);
        let (mut rows, mut leaves) = (Vec::new(), Vec::new());
        for i in 1..=n {
            let ks = keys(me, me, i as usize, 0x3FFF_FFFF, true);
            let (o, next) = ss_epoch(params, &state, &ks);
            rows.push(row_of(i, &o, me));
            leaves.push(leaf_of(i, &o));
            state = next;
        }
        emit("ss", &rows, &leaves);
    }

    println!("done → {}", dir.join("input_fold.csv").display());
}
