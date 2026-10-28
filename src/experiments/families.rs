//! Single-epoch provers for each family, shared by the RQ runners.

use std::time::Duration;

use crate::config::Val;

use crate::commitment::countmin::commit_countmin;
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::countmin_final::{
    CountMinFinalParams, apply_update_prf, hash_cell_prf, prove_countmin_final,
};

use crate::sketch::gk_final_full::{
    GKFullParams, GKFullState, GKFullUpdate, apply_batch_full, commit_gk_state, prove_gk_full,
};
use crate::sketch::hll_final_full::{
    HllFullParams, HllFullState, HllFullUpdate, apply_batch as hll_apply_batch, commit_hll_state,
    prove_hll_full,
};
use crate::sketch::ss_final_full::{
    SsFullParams, SsFullState, SsFullUpdate, apply_batch_ss_full, commit_ss_state, prove_ss_full,
};

use super::{ms, proof_size, time_it};

/// The four sketch families, in paper order.
pub const FAMILIES: [&str; 4] = ["CM", "GK", "HLL", "SS"];

/// Uniform outcome of proving a single epoch for any family.
#[derive(Clone, Debug)]
pub struct EpochOutcome {
    pub family: &'static str,
    /// Wall-clock to prove (includes witness-gen + prove + self-verify).
    pub prove: Duration,
    /// Serialised (postcard) proof size in bytes.
    pub proof_bytes: usize,
    /// `true` iff the leaf's committed final state equals the natively
    /// recomputed state — the RQ1-d "ZK answer == plaintext answer" check.
    pub correct: bool,
    /// State-size metric: nonzero CM cells / active GK tuples / touched HLL
    /// registers / active SS rows.
    pub state_metric: usize,
    /// A representative decoded answer (CM count / GK rank / HLL cardinality /
    /// SS frequency) — both for sanity and for RQ1-d.
    pub answer: f64,
    /// `Com(S_{t-1})` and `Com(S_t)` — the boundary the framework chains.
    pub com_before: [Val; 8],
    pub com_after: [Val; 8],
    /// `C_B` — the binding commitment to the (private) epoch batch.
    pub batch_commit: [Val; 8],
}

impl EpochOutcome {
    pub fn prove_ms(&self) -> f64 {
        ms(self.prove)
    }
}

// ─── Count-Min ───────────────────────────────────────────────────────────────

/// Prove one CM epoch from `initial`, returning the outcome and the new state.
/// `keys.len()` must equal `params.batch`.
pub fn cm_epoch(
    params: CountMinFinalParams,
    initial: &CountMinState,
    keys: &[u32],
) -> (EpochOutcome, CountMinState) {
    assert_eq!(keys.len(), params.batch, "CM: keys.len != batch");
    let updates: Vec<CountMinUpdate> =
        keys.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();

    let mut final_state = initial.clone();
    for u in &updates {
        apply_update_prf(&mut final_state, u);
    }
    let com_before = commit_countmin(initial).0;
    let com_after = commit_countmin(&final_state).0;

    let (leaf, prove) = time_it(|| prove_countmin_final(params, initial.clone(), updates.clone()));
    let proof_bytes = proof_size(&leaf.output.0);
    let correct = leaf.final_.0 == com_after;

    // Decoded answer: count-min point estimate for the first key.
    let probe = keys[0] as u64;
    let mut est = u32::MAX;
    for i in 0..params.d {
        let j = hash_cell_prf(i, probe, params.w);
        est = est.min(final_state.counters[i][j]);
    }
    let state_metric = final_state.counters.iter().flatten().filter(|&&c| c > 0).count();

    let outcome = EpochOutcome {
        family: "CM",
        prove,
        proof_bytes,
        correct,
        state_metric,
        answer: est as f64,
        com_before,
        com_after,
        batch_commit: leaf.batch_commit.0,
    };
    (outcome, final_state)
}

/// Convenience: an empty CM state of the given shape.
pub fn cm_empty(d: usize, w: usize) -> CountMinState {
    use crate::sketch::Sketch;
    crate::sketch::countmin::CountMin::new(&CountMinParams { d, w })
}

// ─── Greenwald–Khanna (quantiles) ────────────────────────────────────────────

/// Prove one GK epoch from `initial`. `keys` are mapped to 22-bit values.
pub fn gk_epoch(
    params: GKFullParams,
    initial: &GKFullState,
    keys: &[u32],
) -> (EpochOutcome, GKFullState) {
    assert_eq!(keys.len(), params.batch, "GK: keys.len != batch");
    let updates: Vec<GKFullUpdate> =
        keys.iter().map(|&k| GKFullUpdate::real(k & 0x003F_FFFF)).collect();

    let (final_state, _excess) = apply_batch_full(initial, &updates);
    let com_before = commit_gk_state(initial).0;
    let com_after = commit_gk_state(&final_state).0;

    let (leaf, prove) = time_it(|| prove_gk_full(params, initial.clone(), updates.clone()));
    let proof_bytes = proof_size(&leaf.output.0);
    let correct = leaf.final_.0 == com_after;

    // Decoded answer: rank of the median probe value.
    let probe = (keys[keys.len() / 2] & 0x003F_FFFF) as u32;
    let answer = final_state.rank(probe) as f64;

    let outcome = EpochOutcome {
        family: "GK",
        prove,
        proof_bytes,
        correct,
        state_metric: final_state.active_count(),
        answer,
        com_before,
        com_after,
        batch_commit: leaf.batch_commit.0,
    };
    (outcome, final_state)
}

// ─── HyperLogLog (distinct count) ─────────────────────────────────────────────

/// Prove one HLL epoch from `initial`. `keys` used directly as 64-bit keys.
pub fn hll_epoch(
    params: HllFullParams,
    initial: &HllFullState,
    keys: &[u32],
) -> (EpochOutcome, HllFullState) {
    assert_eq!(keys.len(), params.batch, "HLL: keys.len != batch");
    let updates: Vec<HllFullUpdate> =
        keys.iter().map(|&k| HllFullUpdate::real(k as u64)).collect();

    let final_state = hll_apply_batch(initial, &updates);
    let com_before = commit_hll_state(initial).0;
    let com_after = commit_hll_state(&final_state).0;

    let (leaf, prove) = time_it(|| prove_hll_full(params, initial.clone(), updates.clone()));
    let proof_bytes = proof_size(&leaf.output.0);
    let correct = leaf.final_.0 == com_after;

    let outcome = EpochOutcome {
        family: "HLL",
        prove,
        proof_bytes,
        correct,
        state_metric: final_state.touched(),
        answer: final_state.estimate(),
        com_before,
        com_after,
        batch_commit: leaf.batch_commit.0,
    };
    (outcome, final_state)
}

// ─── SpaceSaving (heavy hitters) ──────────────────────────────────────────────

/// Prove one SS epoch from `initial`. `keys` masked to 30-bit non-zero.
pub fn ss_epoch(
    params: SsFullParams,
    initial: &SsFullState,
    keys: &[u32],
) -> (EpochOutcome, SsFullState) {
    assert_eq!(keys.len(), params.batch, "SS: keys.len != batch");
    let updates: Vec<SsFullUpdate> = keys
        .iter()
        .map(|&k| SsFullUpdate::real(((k & 0x1FFF_FFFF) | 1) as u64, 1))
        .collect();

    let (final_state, _residual) = apply_batch_ss_full(initial, &updates);
    let com_before = commit_ss_state(initial).0;
    let com_after = commit_ss_state(&final_state).0;

    let (leaf, prove) = time_it(|| prove_ss_full(params, initial.clone(), updates.clone()));
    let proof_bytes = proof_size(&leaf.output.0);
    let correct = leaf.final_.0 == com_after;

    // Decoded answer: frequency of the first probe key.
    let probe = ((keys[0] & 0x1FFF_FFFF) | 1) as u64;
    let answer = final_state.frequency(probe) as f64;

    let outcome = EpochOutcome {
        family: "SS",
        prove,
        proof_bytes,
        correct,
        state_metric: final_state.active_count(),
        answer,
        com_before,
        com_after,
        batch_commit: leaf.batch_commit.0,
    };
    (outcome, final_state)
}

// ─── Empty-state constructors (uniform access for the case study) ─────────────

pub fn gk_empty(params: GKFullParams) -> GKFullState {
    GKFullState::empty(params)
}
pub fn hll_empty(params: HllFullParams) -> HllFullState {
    HllFullState::empty(params)
}
pub fn ss_empty(params: SsFullParams) -> SsFullState {
    SsFullState::empty(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    // One tiny epoch per family — keeps the always-on suite honest that the
    // shared runners compile, prove, self-verify, and round-trip.
    #[test]
    fn cm_epoch_round_trips() {
        let params = CountMinFinalParams { d: 2, w: 4, batch: 2 };
        let keys = [11u32, 22];
        let (o, _s) = cm_epoch(params, &cm_empty(2, 4), &keys);
        assert!(o.correct, "CM committed final must equal native");
        assert!(o.proof_bytes > 0 && o.prove_ms() > 0.0);
    }

    #[test]
    fn gk_epoch_round_trips() {
        let params = GKFullParams { capacity: 4, batch: 2 };
        let (o, _s) = gk_epoch(params, &gk_empty(params), &[5u32, 9]);
        assert!(o.correct);
    }

    #[test]
    fn hll_epoch_round_trips() {
        let params = HllFullParams { b: 4, batch: 2 };
        let (o, _s) = hll_epoch(params, &hll_empty(params), &[123u32, 456]);
        assert!(o.correct);
    }

    #[test]
    fn ss_epoch_round_trips() {
        let params = SsFullParams { capacity: 4, batch: 2 };
        let (o, _s) = ss_epoch(params, &ss_empty(params), &[7u32, 13]);
        assert!(o.correct);
    }
}
