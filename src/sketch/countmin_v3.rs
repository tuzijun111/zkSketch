//! Plaintext §5.2 Count-Min maintenance plan (the v3 design).
//!
//! The new §5.2 Count-Min update circuit refactors the per-cell strawman
//! transition `final = initial + Σ(selector · value)` into a database-style
//! maintenance plan:
//!
//! ```text
//! B ──group by key──▶ G ──compute counter ids──▶ U_ctr ──group by counter──▶ A ──sparse patch──▶ S_t
//! ```
//!
//! This module implements the plan as a pure Rust pipeline. It does NOT run
//! inside a circuit — it is the reference oracle that the in-circuit leaf
//! `countmin_leaf_v3` is verified against. Three round-trip tests below
//! exercise the soundness-equivalence:
//!
//! 1. Pipeline output applied to `S_old` equals the naive `CountMin::update`
//!    replay (`build_then_apply_matches_naive`).
//! 2. Duplicate keys in `B` get aggregated into a single grouped row
//!    (`duplicate_key_in_batch_aggregates_once`).
//! 3. Distinct keys whose row-`i` hash collides to the same counter end up in
//!    one `A` row (`hash_collision_aggregates_at_counter`).
//!
//! Per the user's clarification (and PoneglyphDB §4.3 group-by pattern), the
//! key-sort and counter-sort do NOT need range-checked sortedness; only the
//! group-by property — equal keys (and equal `(i, b)` pairs) are adjacent —
//! is required. The accompanying in-circuit leaf enforces this via the fork's
//! `PermuteAir` (multiset equality) plus PoneglyphDB-style adjacent-equality
//! tags. The counter-aggregation step's own group-by re-merges any split
//! duplicate-key bins because both halves compute the same `(i, b)`.

use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate, hash_cell};
#[cfg(test)]
use crate::sketch::Sketch;
#[cfg(test)]
use crate::sketch::countmin::CountMin;

/// One row of the key-sorted batch `B↑k`. The pipeline supplies this with
/// equal-key rows already adjacent; inactive entries (used when `B` is padded
/// to a fixed length) carry `active = false` and dummy field values.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SortedBatchRow {
    pub active: bool,
    pub key: u64,
    pub value: u32,
}

/// One row of the grouped-key table `G`. The bin-aggregate `value_sum`
/// accumulates every `B↑k` row with the same key.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GroupedRow {
    pub active: bool,
    pub key: u64,
    pub value_sum: u32,
}

/// One row of the counter-update table `U_ctr`. Each grouped-key row spawns
/// `d` such rows — one per Count-Min sketch row `i ∈ [0, d)` — carrying the
/// counter location `(i, bucket = h_i(key))` and the same `value_sum`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CounterUpdateRow {
    pub active: bool,
    pub key: u64,
    pub row: usize,
    pub bucket: usize,
    pub value: u32,
}

/// One row of the sparse patch `A`. Aggregates every `U_ctr` row touching
/// the same counter `(row, bucket)` into a single net delta.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SparsePatchRow {
    pub active: bool,
    pub row: usize,
    pub bucket: usize,
    pub delta: u32,
}

/// Full §5.2 v3 pipeline output.
///
/// All intermediate tables are exposed so the in-circuit leaf can witness
/// each step. `b_sorted` is one valid key-grouped arrangement of the input
/// batch (any arrangement where equal keys are adjacent is acceptable;
/// `build` produces a stable one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3Pipeline {
    pub params: CountMinParams,
    pub b_sorted: Vec<SortedBatchRow>,
    pub g: Vec<GroupedRow>,
    pub u_ctr: Vec<CounterUpdateRow>,
    pub u_ctr_sorted: Vec<CounterUpdateRow>,
    pub a: Vec<SparsePatchRow>,
}

impl V3Pipeline {
    /// Number of active (non-dummy) rows in `G`.
    pub fn distinct_keys(&self) -> usize {
        self.g.iter().filter(|g| g.active).count()
    }

    /// Number of active rows in `A` — the count of distinct counters touched.
    pub fn touched_counters(&self) -> usize {
        self.a.iter().filter(|a| a.active).count()
    }
}

/// Build the §5.2 pipeline for a batch against a Count-Min state.
///
/// The output `V3Pipeline` carries every intermediate table; applying its
/// sparse patch `A` to `state` reproduces the same state as replaying every
/// `CountMinUpdate` in `batch` via `CountMin::update`.
pub fn build(state: &CountMinState, batch: &[CountMinUpdate]) -> V3Pipeline {
    let params = state.params;
    let m = batch.len();
    let d = params.d;
    let w = params.w;

    // Step 1+2: produce a key-grouped arrangement of the batch. We sort by
    // key purely for determinism — the §5.2 circuit only needs equal keys
    // adjacent, not globally sorted, but a stable sort is the simplest way
    // to satisfy that.
    let mut indexed: Vec<(u64, u32, usize)> = batch
        .iter()
        .enumerate()
        .map(|(i, u)| (u.key, u.value, i))
        .collect();
    indexed.sort_by_key(|&(k, _, i)| (k, i));
    let b_sorted: Vec<SortedBatchRow> = indexed
        .iter()
        .map(|&(k, v, _)| SortedBatchRow { active: true, key: k, value: v })
        .collect();

    // Step 3: aggregate values per distinct key. Walk `b_sorted` and emit
    // one `G` row per equal-key run. The grouped table is padded to length
    // `m` with inactive dummies so it has a fixed shape.
    let mut g: Vec<GroupedRow> = Vec::with_capacity(m);
    let mut i = 0;
    while i < b_sorted.len() {
        let k = b_sorted[i].key;
        let mut sum: u32 = 0;
        let mut j = i;
        while j < b_sorted.len() && b_sorted[j].key == k {
            sum = sum.saturating_add(b_sorted[j].value);
            j += 1;
        }
        g.push(GroupedRow { active: true, key: k, value_sum: sum });
        i = j;
    }
    while g.len() < m {
        g.push(GroupedRow { active: false, key: 0, value_sum: 0 });
    }

    // Step 4: for each grouped row, compute the `d` counter locations and
    // spawn `d` `U_ctr` rows. The table has shape `m × d` (padded with
    // inactive rows for inactive grouped slots).
    let mut u_ctr: Vec<CounterUpdateRow> = Vec::with_capacity(m * d);
    for gr in &g {
        for row in 0..d {
            if gr.active {
                let bucket = hash_cell(row, gr.key, w);
                u_ctr.push(CounterUpdateRow {
                    active: true,
                    key: gr.key,
                    row,
                    bucket,
                    value: gr.value_sum,
                });
            } else {
                u_ctr.push(CounterUpdateRow {
                    active: false,
                    key: 0,
                    row,
                    bucket: 0,
                    value: 0,
                });
            }
        }
    }

    // Step 5: counter-sort. Sort `u_ctr` by counter id `(row, bucket)`. As
    // with step 2 only adjacency on the sort key is needed for §5.2, but a
    // stable sort gives a deterministic witness.
    let mut u_ctr_sorted: Vec<CounterUpdateRow> = u_ctr.clone();
    u_ctr_sorted.sort_by_key(|r| (!r.active, r.row, r.bucket, r.key));
    // ^ inactive rows placed last (active = true sorts before active = false
    // because `!true = false < !false = true`).

    // Step 6: segment-aggregate equal-counter runs in `u_ctr_sorted` into
    // the sparse patch `A`. Padded to length `m * d`.
    let mut a: Vec<SparsePatchRow> = Vec::with_capacity(m * d);
    let mut i = 0;
    while i < u_ctr_sorted.len() {
        if !u_ctr_sorted[i].active {
            break;
        }
        let row = u_ctr_sorted[i].row;
        let bucket = u_ctr_sorted[i].bucket;
        let mut delta: u32 = 0;
        let mut j = i;
        while j < u_ctr_sorted.len()
            && u_ctr_sorted[j].active
            && u_ctr_sorted[j].row == row
            && u_ctr_sorted[j].bucket == bucket
        {
            delta = delta.saturating_add(u_ctr_sorted[j].value);
            j += 1;
        }
        a.push(SparsePatchRow { active: true, row, bucket, delta });
        i = j;
    }
    while a.len() < m * d {
        a.push(SparsePatchRow { active: false, row: 0, bucket: 0, delta: 0 });
    }

    V3Pipeline { params, b_sorted, g, u_ctr, u_ctr_sorted, a }
}

/// Step 7: apply the sparse patch `A` to a Count-Min state. The in-circuit
/// leaf checks the same per-cell relation; this is the plaintext oracle.
pub fn apply(state: &CountMinState, pipeline: &V3Pipeline) -> CountMinState {
    assert_eq!(state.params, pipeline.params, "state/pipeline param mismatch");
    let mut out = state.clone();
    for row in &pipeline.a {
        if !row.active {
            continue;
        }
        out.counters[row.row][row.bucket] =
            out.counters[row.row][row.bucket].saturating_add(row.delta);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_state(d: usize, w: usize) -> CountMinState {
        CountMin::new(&CountMinParams { d, w })
    }

    /// Pipeline must agree with the naive per-record replay.
    #[test]
    fn build_then_apply_matches_naive() {
        let s0 = empty_state(2, 4);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let pipeline = build(&s0, &batch);
        let by_pipeline = apply(&s0, &pipeline);

        let mut by_replay = s0.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }
        assert_eq!(by_pipeline.counters, by_replay.counters);
    }

    /// Pipeline at the runtime-param `(4, 4)` shape. Includes duplicate keys
    /// to flex the grouped-key path.
    #[test]
    fn build_then_apply_matches_naive_at_4_4() {
        let s0 = empty_state(4, 4);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 42, value: 1 },
        ];
        let pipeline = build(&s0, &batch);
        let by_pipeline = apply(&s0, &pipeline);

        let mut by_replay = s0.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }
        assert_eq!(by_pipeline.counters, by_replay.counters);
    }

    /// Step 3's key-grouping reduces `|G|` below `|B|` when duplicate keys
    /// are present. With two distinct keys in a four-record batch, |G_active| = 2.
    #[test]
    fn duplicate_key_in_batch_aggregates_once() {
        let s0 = empty_state(2, 4);
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 9 },
            CountMinUpdate { key: 11, value: 1 },
        ];
        let pipeline = build(&s0, &batch);
        assert_eq!(pipeline.distinct_keys(), 2, "G must hold one row per distinct key");

        // The grouped values must equal the per-key sums.
        let key7_sum: u32 = pipeline
            .g
            .iter()
            .filter(|g| g.active && g.key == 7)
            .map(|g| g.value_sum)
            .sum();
        let key11_sum: u32 = pipeline
            .g
            .iter()
            .filter(|g| g.active && g.key == 11)
            .map(|g| g.value_sum)
            .sum();
        assert_eq!(key7_sum, 3 + 9);
        assert_eq!(key11_sum, 5 + 1);

        // Still must apply correctly.
        let by_pipeline = apply(&s0, &pipeline);
        let mut by_replay = s0.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }
        assert_eq!(by_pipeline.counters, by_replay.counters);
    }

    /// Step 6's counter-aggregation re-merges collisions: when two distinct
    /// keys hash to the same counter `(i, b)`, their separate contributions
    /// land in one sparse-patch row.
    ///
    /// The Count-Min hash family `(k * prime_i) ^ offset_i mod w` has a
    /// structural quirk at power-of-2 widths: XOR is bit-local and the
    /// primes are odd, so `h_i(k) mod 2^L` depends only on `k mod 2^L`.
    /// That means at `w = 2^L`, any two distinct (mod w) keys either collide
    /// on EVERY row or on NO row, and a row-0-only collision cannot exist.
    /// We use `w = 6` (non-power-of-2), where the mod step couples the high
    /// bits enough that the rows become independent and row-0-only
    /// collisions become common.
    #[test]
    fn hash_collision_aggregates_at_counter() {
        let w = 6;
        let mut maybe_collision: Option<(u64, u64)> = None;
        'outer: for ka in 0u64..2048 {
            for kb in (ka + 1)..2048 {
                if hash_cell(0, ka, w) == hash_cell(0, kb, w)
                    && hash_cell(1, ka, w) != hash_cell(1, kb, w)
                {
                    maybe_collision = Some((ka, kb));
                    break 'outer;
                }
            }
        }
        let (ka, kb) = maybe_collision.expect("a row-0-only collision must exist with w=6");

        let s0 = empty_state(2, w);
        let batch = vec![
            CountMinUpdate { key: ka, value: 3 },
            CountMinUpdate { key: kb, value: 5 },
        ];
        let pipeline = build(&s0, &batch);

        // Row 0 collision: one sparse-patch entry at row 0 with delta = 3 + 5.
        let row0_active: Vec<&SparsePatchRow> =
            pipeline.a.iter().filter(|a| a.active && a.row == 0).collect();
        assert_eq!(row0_active.len(), 1, "row 0 must coalesce into one patch row");
        assert_eq!(row0_active[0].delta, 8);

        // Row 1 stayed distinct: two sparse-patch entries.
        let row1_active: Vec<&SparsePatchRow> =
            pipeline.a.iter().filter(|a| a.active && a.row == 1).collect();
        assert_eq!(row1_active.len(), 2, "row 1 must have two distinct patches");

        let by_pipeline = apply(&s0, &pipeline);
        let mut by_replay = s0.clone();
        for u in &batch {
            CountMin::update(&mut by_replay, u);
        }
        assert_eq!(by_pipeline.counters, by_replay.counters);
    }
}
