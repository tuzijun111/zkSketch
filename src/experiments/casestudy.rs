//! **End-to-end case study** (paper §Evaluation, `sec:rq5-casestudy`).
//!
//! Runs the full pipeline on the real S³ datasets (AOL user-click stream,
//! Netflix-Prize rating stream), treating each as a single-operator
//! deployment. We exercise all four families over each stream, ingesting it in
//! epochs while maintaining the committed sketch object + a per-epoch history
//! chain, then an independent verifier replays the public log:
//!
//! - **Ingest** (`casestudy_ingest`): total prover wall-clock, mean/max
//!   per-epoch latency, the final decoded answer, and an all-epochs-correct
//!   flag, for each (dataset, family).
//! - **Audit** (`casestudy_audit`): the verifier replays the CM history —
//!   `Θ(E)` per-epoch chain check vs `O(1)` root-digest check — and a
//!   tamper-injection trial (corrupt one epoch boundary) that the chain
//!   verifier rejects.
//!
//! Real datasets are used when fetched (`scripts/fetch_datasets.py`); the
//! synthetic Gaussian/Uniform streams are always included so the case study
//! runs offline.

use crate::dataset::{self, Synthetic};
use crate::recursion::framework::{
    EpochLeaf, FrameworkError, compose_chain, root_commitment, verify_epoch_chain,
};
use crate::sketch::countmin_final::CountMinFinalParams;
use crate::sketch::gk_final_full::GKFullParams;
use crate::sketch::hll_final_full::HllFullParams;
use crate::sketch::ss_final_full::SsFullParams;

use super::families::{
    cm_empty, cm_epoch, gk_empty, gk_epoch, hll_empty, hll_epoch, ss_empty, ss_epoch,
};
use super::{Table, env_usize, ms_str, time_it};

pub fn run() -> Vec<Table> {
    let epochs = env_usize("EXP_CASE_EPOCHS", 4);
    let batch = 8usize;

    let mut ingest = Table::new(
        "casestudy_ingest",
        "End-to-end ingest: all four families over each stream, in epochs",
        &[
            "dataset",
            "family",
            "epochs",
            "batch",
            "total_prove_ms",
            "mean_epoch_ms",
            "max_epoch_ms",
            "final_answer",
            "all_correct",
        ],
    );
    let mut audit = Table::new(
        "casestudy_audit",
        "End-to-end audit: Θ(E) chain verify vs O(1) root; tamper rejected",
        &["dataset", "epochs", "chain_verify_ms", "root_verify_ms", "tamper_detected"],
    );

    for (name, keys) in sources(epochs * batch) {
        // ── Ingest each family ──────────────────────────────────────────
        let (cm_row, cm_leaves) = ingest_cm(&name, &keys, epochs, batch);
        ingest.push(cm_row);
        ingest.push(ingest_gk(&name, &keys, epochs, batch));
        ingest.push(ingest_hll(&name, &keys, epochs, batch));
        ingest.push(ingest_ss(&name, &keys, epochs, batch));

        // ── Audit the CM history chain ──────────────────────────────────
        let (_, chain_verify) = time_it(|| verify_epoch_chain(&cm_leaves, 1));
        let root = compose_chain(&cm_leaves).expect("compose chain");
        let (_, root_verify) = time_it(|| root_commitment(&root));
        let tamper_detected = tamper_breaks_chain(&cm_leaves);
        audit.push(vec![
            name.clone(),
            epochs.to_string(),
            ms_str(chain_verify),
            ms_str(root_verify),
            tamper_detected.to_string(),
        ]);
    }

    vec![ingest, audit]
}

/// Streams to run the case study on: the real S³ datasets when fetched, plus
/// the always-available synthetic pair. `n` keys taken from each.
fn sources(n: usize) -> Vec<(String, Vec<u32>)> {
    let mut v: Vec<(String, Vec<u32>)> = Vec::new();
    if let Some(k) = dataset::aol() {
        v.push(("aol".into(), dataset::take(&k, n)));
    }
    if let Some(k) = dataset::netflix() {
        v.push(("netflix".into(), dataset::take(&k, n)));
    }
    // Prefer the frozen canonical synthetic files (byte-portable); fall back to
    // in-code generation at the same canonical seeds. Byte-identical either way.
    let gauss = match dataset::gaussian() {
        Some(k) if k.len() >= n => dataset::take(&k, n),
        _ => dataset::synthetic_stream(Synthetic::Gaussian, n, dataset::GAUSSIAN_SEED),
    };
    let unif = match dataset::uniform() {
        Some(k) if k.len() >= n => dataset::take(&k, n),
        _ => dataset::synthetic_stream(Synthetic::Uniform, n, dataset::UNIFORM_SEED),
    };
    v.push(("gaussian".into(), gauss));
    v.push(("uniform".into(), unif));
    v
}

// ─── Per-family ingest loops (thread evolving state across epochs) ───────────

fn ingest_cm(name: &str, keys: &[u32], epochs: usize, batch: usize) -> (Vec<String>, Vec<EpochLeaf>) {
    let (d, w) = (4usize, 8usize);
    let params = CountMinFinalParams { d, w, batch };
    let mut state = cm_empty(d, w);
    let mut leaves = Vec::with_capacity(epochs);
    let (mut total, mut mx, mut all_ok, mut answer) = (0.0f64, 0.0f64, true, 0.0f64);
    for e in 0..epochs {
        let slice = &keys[e * batch..(e + 1) * batch];
        let (o, next) = cm_epoch(params, &state, slice);
        total += o.prove_ms();
        mx = mx.max(o.prove_ms());
        all_ok &= o.correct;
        answer = o.answer;
        leaves.push(EpochLeaf::new(
            (e + 1) as u64,
            o.com_before,
            o.com_after,
            o.batch_commit,
            (e + 1) as u64,
        ));
        state = next;
    }
    let row = vec![
        name.to_string(),
        "CM".into(),
        epochs.to_string(),
        batch.to_string(),
        format!("{total:.3}"),
        format!("{:.3}", total / epochs as f64),
        format!("{mx:.3}"),
        format!("{answer:.3}"),
        all_ok.to_string(),
    ];
    (row, leaves)
}

fn ingest_gk(name: &str, keys: &[u32], epochs: usize, batch: usize) -> Vec<String> {
    let params = GKFullParams { capacity: 16, batch };
    let mut state = gk_empty(params);
    let (mut total, mut mx, mut all_ok, mut answer) = (0.0f64, 0.0f64, true, 0.0f64);
    for e in 0..epochs {
        let slice = &keys[e * batch..(e + 1) * batch];
        let (o, next) = gk_epoch(params, &state, slice);
        total += o.prove_ms();
        mx = mx.max(o.prove_ms());
        all_ok &= o.correct;
        answer = o.answer;
        state = next;
    }
    family_row(name, "GK", epochs, batch, total, mx, answer, all_ok)
}

fn ingest_hll(name: &str, keys: &[u32], epochs: usize, batch: usize) -> Vec<String> {
    let params = HllFullParams { b: 6, batch };
    let mut state = hll_empty(params);
    let (mut total, mut mx, mut all_ok, mut answer) = (0.0f64, 0.0f64, true, 0.0f64);
    for e in 0..epochs {
        let slice = &keys[e * batch..(e + 1) * batch];
        let (o, next) = hll_epoch(params, &state, slice);
        total += o.prove_ms();
        mx = mx.max(o.prove_ms());
        all_ok &= o.correct;
        answer = o.answer;
        state = next;
    }
    family_row(name, "HLL", epochs, batch, total, mx, answer, all_ok)
}

fn ingest_ss(name: &str, keys: &[u32], epochs: usize, batch: usize) -> Vec<String> {
    let params = SsFullParams { capacity: 16, batch };
    let mut state = ss_empty(params);
    let (mut total, mut mx, mut all_ok, mut answer) = (0.0f64, 0.0f64, true, 0.0f64);
    for e in 0..epochs {
        let slice = &keys[e * batch..(e + 1) * batch];
        let (o, next) = ss_epoch(params, &state, slice);
        total += o.prove_ms();
        mx = mx.max(o.prove_ms());
        all_ok &= o.correct;
        answer = o.answer;
        state = next;
    }
    family_row(name, "SS", epochs, batch, total, mx, answer, all_ok)
}

#[allow(clippy::too_many_arguments)]
fn family_row(
    name: &str,
    family: &str,
    epochs: usize,
    batch: usize,
    total: f64,
    mx: f64,
    answer: f64,
    all_ok: bool,
) -> Vec<String> {
    vec![
        name.to_string(),
        family.to_string(),
        epochs.to_string(),
        batch.to_string(),
        format!("{total:.3}"),
        format!("{:.3}", total / epochs as f64),
        format!("{mx:.3}"),
        format!("{answer:.3}"),
        all_ok.to_string(),
    ]
}

/// Corrupt one epoch's *input* boundary and confirm the chain verifier
/// rejects. We flip `com_before` of a non-first leaf (index `≥ 1`), which
/// breaks the shared join with its predecessor — robust even for a 2-epoch
/// chain (where the last leaf's `com_after` is the chain endpoint and is bound
/// to nothing downstream).
fn tamper_breaks_chain(leaves: &[EpochLeaf]) -> bool {
    if leaves.len() < 2 {
        return false;
    }
    let mut tampered = leaves.to_vec();
    let idx = (tampered.len() / 2).max(1); // ≥ 1, so a real internal boundary breaks
    use p3_field::PrimeCharacteristicRing;
    tampered[idx].com_before[0] += crate::config::Val::ONE; // flip one lane
    matches!(
        verify_epoch_chain(&tampered, 1),
        Err(FrameworkError::BoundaryMismatch { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casestudy_runs_offline_on_synthetic() {
        // Force a tiny run (2 epochs × batch 8) — synthetic sources always
        // present, so this exercises ingest + audit end-to-end.
        let n = 2 * 8;
        let (name, keys) = sources(n).into_iter().last().unwrap(); // "uniform"
        assert_eq!(name, "uniform");
        let (row, leaves) = ingest_cm(&name, &keys, 2, 8);
        assert_eq!(row.last().unwrap(), "true", "all CM epochs correct");
        assert!(verify_epoch_chain(&leaves, 1).is_ok(), "honest chain verifies");
        assert!(tamper_breaks_chain(&leaves), "tamper must break the chain");
    }
}
