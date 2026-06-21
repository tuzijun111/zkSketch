//! **E7 — maintenance policy × query rate** (EVAL_SPEC §2 E7). The
//! lazy/eager/smoothed trade-off on the streaming forest: when do you fold the
//! `popcount(t)` surviving peaks into a single verified root?
//!
//! - **lazy** — never fold between queries. Inserts are cheap (just the MMR
//!   carry cascade); a query must fold all `popcount(t)−1` peaks ⇒ high query
//!   latency.
//! - **eager** — fold to a single root after every insert. Inserts pay the fold
//!   (high insert tail); queries hit a fresh root ⇒ ~`verify_base` only.
//! - **smoothed(c)** — drain `c` peak-merges per insert; bounds both the insert
//!   tail and the residual query fold. Sits between lazy and eager.
//!
//! Like E5, this is **leaf-shape-agnostic**: it's a structural simulation driven
//! by the measured per-merge cost `τ` (the option-(i) composition cost — a
//! Poseidon2 boundary digest, **not** a recursive-SNARK fold) and the measured
//! `verify_base` (one root re-check). The merge *counts* are the structural
//! signal; the absolute ms are this lightweight cost (flagged, as in RQ4/E5).

use std::hint::black_box;
use std::time::Instant;

use crate::recursion::framework::{lift_leaf, merge_atom, root_commitment};

use super::e5_ladder::synth_chain;
use super::metrics::{median, percentile};

/// Maintenance policy. `Smoothed(c)` drains `c` peak-merges per insert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Lazy,
    Eager,
    Smoothed(u64),
}

impl Policy {
    pub fn name(&self) -> &'static str {
        match self {
            Policy::Lazy => "lazy",
            Policy::Eager => "eager",
            Policy::Smoothed(_) => "smoothed",
        }
    }
    pub fn c(&self) -> u64 {
        match self {
            Policy::Smoothed(c) => *c,
            _ => 0,
        }
    }
}

/// Mean microseconds per `merge_atom` (the option-(i) composition cost `τ`).
pub fn measure_merge_us() -> f64 {
    let leaves = synth_chain(2);
    let a = lift_leaf(&leaves[0]);
    let b = lift_leaf(&leaves[1]);
    let reps = 4000u32;
    let t = Instant::now();
    for _ in 0..reps {
        let _ = black_box(merge_atom(&a, &b).expect("merge"));
    }
    t.elapsed().as_secs_f64() * 1e6 / reps as f64
}

/// Microseconds to re-check one composed root (the auditor's `verify_base`).
pub fn measure_root_verify_us() -> f64 {
    let leaves = synth_chain(2);
    let root = merge_atom(&lift_leaf(&leaves[0]), &lift_leaf(&leaves[1])).expect("merge");
    let reps = 4000u32;
    let t = Instant::now();
    for _ in 0..reps {
        let _ = black_box(root_commitment(&root));
    }
    t.elapsed().as_secs_f64() * 1e6 / reps as f64
}

/// Simulated latencies (in **ms**) over a stream of `t` inserts, querying every
/// `query_every` inserts. `tau_ms`/`verify_ms` are the measured per-merge and
/// root-verify costs.
#[derive(Clone, Debug)]
pub struct E7Sim {
    pub query_latency_ms: Vec<f64>,
    pub insert_tail_ms: Vec<f64>,
    pub finalisation_compositions: Vec<u64>,
}

pub fn simulate(policy: Policy, t: u64, query_every: u64, tau_ms: f64, verify_ms: f64) -> E7Sim {
    let mut query_latency_ms = Vec::new();
    let mut insert_tail_ms = Vec::new();
    let mut finalisation_compositions = Vec::new();
    let c = policy.c();
    for i in 1..=t {
        // MMR carry merges on insert == trailing ones of (i-1).
        let auto_cascade = (i - 1).trailing_ones() as u64;
        let peaks = i.count_ones() as u64;
        let insert_fold = match policy {
            Policy::Lazy => 0,
            Policy::Eager => peaks.saturating_sub(1),
            Policy::Smoothed(c) => c.min(peaks.saturating_sub(1)),
        };
        insert_tail_ms.push((auto_cascade + insert_fold) as f64 * tau_ms);
        if query_every > 0 && i % query_every == 0 {
            let pending = match policy {
                Policy::Lazy => peaks.saturating_sub(1),
                Policy::Eager => 0,
                Policy::Smoothed(_) => peaks.saturating_sub(1).saturating_sub(c),
            };
            query_latency_ms.push(pending as f64 * tau_ms + verify_ms);
            finalisation_compositions.push(pending);
        }
    }
    E7Sim { query_latency_ms, insert_tail_ms, finalisation_compositions }
}

/// Query latency (ms) for a query arriving with `backlog` unfinalised peaks
/// (the "query-mid-backlog" case) under lazy finalisation.
pub fn query_with_backlog_ms(backlog: u64, tau_ms: f64, verify_ms: f64) -> f64 {
    backlog.saturating_sub(1) as f64 * tau_ms + verify_ms
}

/// Convenience aggregates for a sim.
pub fn agg(sim: &E7Sim) -> (f64, f64, f64, u64) {
    let q_med = median(&sim.query_latency_ms);
    let q_p95 = percentile(&sim.query_latency_ms, 0.95);
    let ins_p95 = percentile(&sim.insert_tail_ms, 0.95);
    let fc = median(&sim.finalisation_compositions.iter().map(|&x| x as f64).collect::<Vec<_>>()) as u64;
    (q_med, q_p95, ins_p95, fc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eager_query_cheap_lazy_insert_cheap() {
        let (tau, vb) = (0.01, 0.003); // synthetic ms
        let t = 4096;
        let qe = 100;
        let lazy = simulate(Policy::Lazy, t, qe, tau, vb);
        let eager = simulate(Policy::Eager, t, qe, tau, vb);
        let smoothed = simulate(Policy::Smoothed(2), t, qe, tau, vb);
        let (lq, _, li, _) = agg(&lazy);
        let (eq, _, ei, _) = agg(&eager);
        let (sq, _, si, _) = agg(&smoothed);
        // Eager: cheap query, expensive insert. Lazy: the reverse.
        assert!(eq < lq, "eager query {eq} < lazy query {lq}");
        assert!(li < ei, "lazy insert {li} < eager insert {ei}");
        // Smoothed sits between on both axes (median query, p95 insert).
        assert!(sq <= lq && sq >= eq, "smoothed query {sq} between {eq}..{lq}");
        assert!(si >= li && si <= ei, "smoothed insert {si} between {li}..{ei}");
    }

    #[test]
    fn backlog_query_grows_with_backlog() {
        let (tau, vb) = (0.01, 0.003);
        let a = query_with_backlog_ms(8, tau, vb);
        let b = query_with_backlog_ms(128, tau, vb);
        assert!(b > a, "bigger backlog ⇒ higher query latency: {b} > {a}");
    }
}
