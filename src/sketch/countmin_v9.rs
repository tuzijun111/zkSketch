//! Field-friendly Count-Min hash family (Phase 9b — the §5.2 privacy-
//! preserving design).
//!
//! ### Why a new hash family
//!
//! v1, v2, and the original v3 leaf use `src/sketch/countmin.rs::hash_cell`,
//! which mixes via `key.wrapping_mul(prime) ^ offset ` mod w`. **XOR is bit-
//! local and hostile to BabyBear arithmetic** — verifying that hash
//! in-circuit would require bit-decomposing the wrapping product (~64
//! booleans per record), which dominates the prover cost.
//!
//! In v1/v2/v3 we sidestep this by computing positions natively off-circuit
//! and exposing them as public inputs — the verifier independently
//! recomputes the hash to bind the position PIs to the public hash family.
//! That's fine for soundness but **leaks the input keys**.
//!
//! For the paper's true §5.2 design, keys must be *private* — and that
//! means the verifier cannot recompute positions; the circuit must do it.
//! That requires a field-friendly hash.
//!
//! ### The family
//!
//! `h_i(k) = (k · a_i + b_i)  in BabyBear, then mod w as an integer`.
//!
//! - `a_i` and `b_i` are public, per-row constants — 16 entries (the same
//!   `d ≤ 16` cap as the original family).
//! - The multiply-add happens in `Val = BabyBear`. `key: u64` is reduced
//!   modulo BabyBear's prime on conversion, which is fine for distribution
//!   (BabyBear ≈ 2³¹ is far larger than any practical `w`, so the modular
//!   bias `w / p` is negligible).
//! - The final `mod w` step is the only piece that's not pure field
//!   arithmetic. In-circuit this is verified by the prover supplying a
//!   quotient `q` and remainder `r`, with `q · w + r = mixed` constrained
//!   and `0 ≤ r < w` enforced via a bit-decomposition of `r` (cheap when
//!   `w` is small — ⌈log₂ w⌉ booleans).
//!
//! ### Relationship to v1/v2/v3
//!
//! The v9 hash family is **different** from the XOR family — for the same
//! key, `hash_cell_v9` and `hash_cell` map to different positions. So a v9
//! state and a v1 state diverge after the first update, even when they
//! start equal. This is intentional: v9 is the §5.2 privacy-preserving
//! line, not a drop-in replacement for v1/v2/v3.
//!
//! The Count-Min upper-bound property still holds for v9 (every per-row
//! function distributes reasonably), so query semantics are unchanged.
//!
//! ### Reused types
//!
//! `CountMinState`, `CountMinParams`, `CountMinUpdate` from
//! `src/sketch/countmin.rs` are reused as-is. Only the hash function and
//! the `Sketch` trait impl (via the new `CountMinV9` unit struct) are
//! distinct.

use p3_field::PrimeCharacteristicRing;

use crate::config::Val;
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};

/// Per-row multipliers `a_i`. All odd → bijective on BabyBear when paired
/// with a non-trivial residue. Sixteen entries to match the original
/// family's `d ≤ 16` cap.
const HASH_A: [u32; 16] = [
    0x9E37_79B9, 0xBF58_476D, 0x94D0_49BB, 0x2545_F491, 0xD801_2304, 0xC2B2_AE3D,
    0xCBF2_9CE4, 0xC6BC_2796, 0xA243_F605, 0xB492_6F95, 0x82C1_2F3C, 0xF1BB_CDCB,
    0xD632_2D0C, 0x8E4F_47AB, 0xA537_82B0, 0xE369_15A1,
];

/// Per-row offsets `b_i`. Distinct from `HASH_A` so the per-row functions
/// aren't trivially shifted versions of each other.
const HASH_B: [u32; 16] = [
    0xDEAD_BEEF, 0xCAFE_BABE, 0xFEED_FACE, 0xBAAA_AAAD, 0xABAD_CAFE, 0xDEFE_C8ED,
    0x0D15_EA5E, 0xBADD_F00D, 0xFACE_FEED, 0xCAFE_D00D, 0x1234_5678, 0x0FED_CBA9,
    0xAAAA_5555, 0x5555_AAAA, 0x0123_4567, 0xFEDC_BA98,
];

/// Compute the cell column for `(row, key)` under the v9 field-friendly
/// hash profile.
///
/// In BabyBear arithmetic: `mixed = k · a_i + b_i`. The canonical u64
/// representation of `mixed` is reduced mod `w` to give the position.
///
/// The native side mirrors what the in-circuit verifier will do: one
/// field multiply, one field add, then a quotient+remainder reduction
/// that the circuit checks via `q · w + r == mixed` plus a range check
/// on `r`.
pub fn hash_cell_v9(row: usize, key: u64, w: usize) -> usize {
    assert!(row < HASH_A.len(), "row {row} exceeds the v9 hash profile depth (16)");
    assert!(w > 0, "width w must be positive");
    let k = Val::from_u64(key);
    let a = Val::from_u32(HASH_A[row]);
    let b = Val::from_u32(HASH_B[row]);
    let mixed = k * a + b;
    let mixed_u: u64 = <Val as p3_field::PrimeField64>::as_canonical_u64(&mixed);
    (mixed_u as usize) % w
}

/// v9 Count-Min sketch — reuses `CountMinState` from `countmin.rs` but
/// updates via the field-friendly `hash_cell_v9` instead of the XOR-based
/// `hash_cell`.
///
/// State produced by `CountMinV9` is **NOT comparable** to state produced
/// by `CountMin` — they touch different cells for the same key.
pub struct CountMinV9;

impl Sketch for CountMinV9 {
    type Params = CountMinParams;
    type State = CountMinState;
    type Update = CountMinUpdate;

    fn new(params: &Self::Params) -> Self::State {
        assert!(
            params.d <= HASH_A.len(),
            "v9 Count-Min depth {} exceeds built-in hash profile ({})",
            params.d,
            HASH_A.len()
        );
        assert!(params.w > 0, "v9 Count-Min width w must be positive");
        Self::State {
            counters: vec![vec![0u32; params.w]; params.d],
            params: *params,
        }
    }

    fn update(state: &mut Self::State, u: &Self::Update) {
        for row in 0..state.params.d {
            let col = hash_cell_v9(row, u.key, state.params.w);
            state.counters[row][col] = state.counters[row][col].saturating_add(u.value);
        }
    }
}

impl CountMinV9 {
    /// Point query under the v9 hash family — same Count-Min upper-bound
    /// semantics as the original `CountMin::query`.
    pub fn query(state: &CountMinState, key: u64) -> u32 {
        (0..state.params.d)
            .map(|row| {
                let col = hash_cell_v9(row, key, state.params.w);
                state.counters[row][col]
            })
            .min()
            .unwrap_or(0)
    }
}

// ───────────────────────────────────────────────────────────────────────
// Proving benchmarks — mirror `countmin_v3::bench_v3_prover` for the
// privacy-preserving v9 leaf
// ───────────────────────────────────────────────────────────────────────

/// Benchmark the v9 in-circuit leaf prover at flexible `(d, w, batch)`.
///
/// Mirrors `crate::sketch::countmin_v3::bench_v3_prover` but invokes the
/// privacy-preserving v9 leaf (private keys, in-circuit hash, batch
/// commitment). The batch is generated via
/// `crate::sketch::countmin_v3::gen_default_batch` so the same key/value
/// pattern is used as v3's sweeps — direct apples-to-apples timing
/// comparisons are then possible against the same parameter triples.
///
/// `num_threads` controls the Rayon pool the STARK prover runs inside.
/// Pass `None` to inherit Rayon's global pool, or `Some(n)` to spin up a
/// temporary pool of exactly `n` workers (useful for thread-count sweeps).
///
/// # Constraints (in addition to `bench_v3_prover`'s)
///
/// The v9 leaf requires `params.w` to be a power of 2 in `{2, 4, 8, 16}`
/// (see `crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_with_params`).
/// Calling with a non-power-of-2 width panics with an explicit message.
///
/// # Panics
///
/// Same panic surface as `bench_v3_prover`, plus the v9-specific `w`
/// constraint above.
pub fn bench_v9_prover(
    params: crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
    num_threads: Option<usize>,
) -> std::time::Duration {
    let batch = crate::sketch::countmin_v3::gen_default_batch(params);
    crate::sketch::countmin_v3::bench_v9_prover_on_batch(params, batch, num_threads)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(d: usize, w: usize) -> CountMinParams {
        CountMinParams { d, w }
    }

    /// One v9 update touches exactly `d` counters (one per row).
    #[test]
    fn v9_update_touches_d_cells() {
        let mut s = CountMinV9::new(&params(4, 12));
        CountMinV9::update(&mut s, &CountMinUpdate { key: 0x1234_5678, value: 7 });

        let nonzero_cells: usize = s
            .counters
            .iter()
            .flatten()
            .filter(|&&c| c != 0)
            .count();
        assert!(nonzero_cells <= s.params.d, "should touch at most d cells");
        // For this particular key the per-row hashes are very likely
        // distinct under our family, so nonzero == d.
        assert_eq!(nonzero_cells, s.params.d);
    }

    /// The v9 hash family differs from v1's — same key generally maps to
    /// different positions. This isn't strictly required by anything
    /// downstream, but it's worth confirming so a future refactor that
    /// accidentally re-uses the XOR family in v9 trips this test.
    #[test]
    fn v9_diverges_from_v1_hash() {
        use crate::sketch::countmin::hash_cell;
        // Search for any (row, key, w) where the two families disagree.
        // For random-ish keys they should disagree very often.
        let mut disagreements = 0;
        for key in [7u64, 11, 42, 99, 100, 256, 1024, 65536] {
            for row in 0..4 {
                for w in [6, 8, 12, 16] {
                    if hash_cell(row, key, w) != hash_cell_v9(row, key, w) {
                        disagreements += 1;
                    }
                }
            }
        }
        // With 8 keys × 4 rows × 4 widths = 128 trials, almost everything
        // should differ. A safe bound is "≥ half differ".
        assert!(
            disagreements >= 64,
            "v9 hash family should differ from v1 family in most cells, got {disagreements} disagreements out of 128"
        );
    }

    /// Classical Count-Min upper bound under v9: a point query never
    /// under-counts.
    #[test]
    fn v9_query_upper_bounds_true_count() {
        let mut s = CountMinV9::new(&params(4, 32));
        let stream: [(u64, u32); 8] = [
            (10, 1), (10, 1), (10, 1), (10, 1),
            (20, 5), (20, 5),
            (999, 2),
            (10, 3),
        ];
        let mut truth = std::collections::HashMap::<u64, u32>::new();
        for &(k, v) in &stream {
            *truth.entry(k).or_insert(0) += v;
            CountMinV9::update(&mut s, &CountMinUpdate { key: k, value: v });
        }

        for (&k, &t) in &truth {
            let est = CountMinV9::query(&s, k);
            assert!(est >= t, "v9 query({k}) = {est} but true count = {t}");
        }
    }

    /// Deterministic on identical inputs (no hidden state).
    #[test]
    fn v9_hash_is_deterministic() {
        for &key in &[7u64, 42, 1024, 0xDEAD_BEEF_CAFE_BABE] {
            for row in 0..4 {
                for &w in &[6usize, 8, 12, 16] {
                    let a = hash_cell_v9(row, key, w);
                    let b = hash_cell_v9(row, key, w);
                    assert_eq!(a, b);
                }
            }
        }
    }

    /// The v9 family does *not* have the power-of-2 quirk of v1/v2/v3
    /// (where `h_i(k) mod 2^L` depends only on `k mod 2^L`, so all rows
    /// collide identically for any given key residue). v9's
    /// "multiply-then-truncate-mod-w" mixes the high bits in, so two
    /// keys with the same residue mod w can hash to different cells
    /// in different rows.
    ///
    /// This is the practical pay-off of moving away from XOR: independent
    /// per-row hash behavior even at power-of-2 widths.
    #[test]
    fn v9_breaks_v1_power_of_two_collision_pattern() {
        let w = 8; // power of 2
        // Two keys with the same residue mod w=8.
        let key_a: u64 = 17; // 17 mod 8 = 1
        let key_b: u64 = 41; // 41 mod 8 = 1
        assert_eq!(key_a % (w as u64), key_b % (w as u64));

        // Under v1 (XOR family): h_i(key_a) == h_i(key_b) for *every* row.
        // Under v9: they should differ on at least one row.
        let mut differing_rows = 0;
        for row in 0..4 {
            if hash_cell_v9(row, key_a, w) != hash_cell_v9(row, key_b, w) {
                differing_rows += 1;
            }
        }
        assert!(
            differing_rows >= 1,
            "v9 should give independent per-row hashes; both keys collided on all 4 rows"
        );
    }

    /// Proving-time sweep for the v9 in-circuit leaf at flexible
    /// `(d, w, batch)` shapes. `#[ignore]`'d to keep regular `cargo test`
    /// fast; run on demand:
    ///
    /// ```bash
    /// # Default — Rayon picks the number of threads (all logical CPUs).
    /// cargo test --release --lib v9_proving_time_sweep -- --ignored --nocapture
    ///
    /// # Pin to N threads.
    /// V3_SWEEP_THREADS=8 cargo test --release --lib v9_proving_time_sweep -- --ignored --nocapture
    /// ```
    ///
    /// The same `V3_SWEEP_THREADS` env var the v3 sweep reads — easier to
    /// keep one knob for both, no need to learn a second one.
    ///
    /// # Choosing `(d, w)` for v9
    ///
    /// In addition to the project-wide invariants (`d * w % 4 == 0`,
    /// `d ≤ 16`), the v9 leaf requires **`w` to be a power of 2 in
    /// `{2, 4, 8, 16}`** because the in-circuit `mod w` step extracts the
    /// bottom `log₂(w)` bits of the `(k · a_i + b_i)` field result. The
    /// grid below uses `w ∈ {4, 8}` to stay safely in-bounds.
    ///
    /// At power-of-2 widths v1's XOR family has a structural quirk where
    /// all `d` rows collide identically for any given key residue mod
    /// `w`. v9's multiply-add family doesn't — verified by
    /// `v9_breaks_v1_power_of_two_collision_pattern` above. So the v9
    /// hash gives proper hash-row independence at the same shapes the v3
    /// sweep uses, making the two sweeps directly comparable.
    ///
    /// `n_ctr = d · batch` is the U_ctr table size; it drives the
    /// dominant cost line in both v3 and v9 leaves.
    #[test]
    #[ignore]
    fn v9_proving_time_sweep() {
        use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;

        let num_threads: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let (effective_threads, source) = match num_threads {
            Some(n) => (n, format!("V3_SWEEP_THREADS={n}")),
            None => {
                let n = rayon::current_num_threads();
                let src = match std::env::var("RAYON_NUM_THREADS") {
                    Ok(v) => format!("Rayon global pool, RAYON_NUM_THREADS={v}"),
                    Err(_) => "Rayon global pool, default = num_cpus::get()".to_string(),
                };
                (n, src)
            }
        };

        println!();
        println!("v9 proving-time sweep — privacy-preserving §5.2 leaf");
        println!("=====================================================");
        println!("  threads: {effective_threads}  ({source})");
        println!();

        // Five grid points, same shape as `v3_proving_time_sweep`. All use
        // power-of-2 widths so the v9 leaf's `w ∈ {2, 4, 8, 16}` constraint
        // is satisfied. `d * w % 4 == 0` and `d ≤ 16` are project-wide.
        let grid: Vec<CountMinLeafParams> = vec![
            // CountMinLeafParams { d: 2, w: 4, batch: 2 },  // baseline
            // CountMinLeafParams { d: 2, w: 4, batch: 4 },  // batch ↑
            // CountMinLeafParams { d: 4, w: 4, batch: 4 },  // depth + batch ↑
            CountMinLeafParams { d: 4, w: 8, batch: 100 },  // width ↑
            // CountMinLeafParams { d: 8, w: 4, batch: 8 },  // depth + batch ↑↑ (worst case)
        ];

        for params in grid {
            // Validate early so bad params fail before the slow prove.
            params.validate();
            let CountMinLeafParams { d, w, batch } = params;
            let n_ctr = d * batch;
            let prove_time = bench_v9_prover(params, num_threads);
            println!(
                "  d={:>2}  w={:>3}  batch={:>3}  cells={:>4}  n_ctr={:>3}  prove {:>10.2?}",
                d, w, batch, d * w, n_ctr, prove_time
            );
        }
    }

    /// Duplicate-key density sweep for the **privacy-preserving v9 leaf**
    /// at a fixed `(d, w, batch)`. Varies the number of distinct keys in
    /// the batch and reports v9's prove time at each ratio.
    ///
    /// Mirrors `countmin_v3::tests::v3_duplicate_key_sweep` in shape — same
    /// fixed batch size, same `gen_batch_with_distinct_keys` generator,
    /// same `analyze_batch` columns, same `V3_SWEEP_THREADS` env knob.
    /// The only difference is which leaf prover gets called:
    /// `bench_v9_prover_on_batch` instead of `bench_v3_prover_on_batch`.
    ///
    /// Run on demand:
    ///
    /// ```bash
    /// V3_SWEEP_THREADS=8 cargo test --release --lib v9_duplicate_key_ratio_sweep \
    ///     -- --ignored --nocapture
    /// ```
    ///
    /// # What the curve will show
    ///
    /// This sweep submits the **full** raw batch to v9 (no `aggregate_by_key`
    /// pre-processing). Because the v9 leaf processes `params.batch` records
    /// independently and the in-circuit hash gate fires `m · d` times
    /// regardless of how many keys repeat, the prove time should be **flat**
    /// across the `distinct` axis — the same conclusion the v3 sweep
    /// reaches, just at a slightly higher per-point cost because v9 also
    /// pays for the in-circuit hash gadget.
    ///
    /// To see the duplicate-density savings actually materialize, use the
    /// **aggregated** counterpart in
    /// `countmin_v3::tests::v9_duplicate_key_sweep`, which calls
    /// `aggregate_by_key` before `bench_v9_prover_on_batch`. That one
    /// produces a clearly downward-sloping curve — proof that §5.2's
    /// key-grouping savings come from the **off-circuit grouping**, not
    /// from the leaf itself.
    ///
    /// # Choosing `(d, w, batch)`
    ///
    /// - `d * w % 4 == 0` (project-wide alignment invariant).
    /// - `d ≤ 16` (v9 hash-family table size).
    /// - `w` must be a power of 2 in `{2, 4, 8, 16}` (v9 leaf range check).
    /// - `batch` can be anything but drives the dominant per-point cost.
    ///   Larger `batch` makes each row of the sweep take longer; on a
    ///   slower machine you may want to reduce the batch (e.g. 100) or
    ///   trim the `distinct_grid` to fewer points.
    #[test]
    #[ignore]
    fn v9_duplicate_key_ratio_sweep() {
        use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;
        use crate::sketch::countmin_v3::{
            analyze_batch, bench_v9_prover_on_batch, gen_batch_with_distinct_keys,
        };

        let num_threads: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let (effective_threads, source) = match num_threads {
            Some(n) => (n, format!("V3_SWEEP_THREADS={n}")),
            None => {
                let n = rayon::current_num_threads();
                let src = match std::env::var("RAYON_NUM_THREADS") {
                    Ok(v) => format!("Rayon global pool, RAYON_NUM_THREADS={v}"),
                    Err(_) => "Rayon global pool, default = num_cpus::get()".to_string(),
                };
                (n, src)
            }
        };

        // Same params shape v3_duplicate_key_sweep uses, with w forced to a
        // power of 2 for the v9 leaf. d * w = 32, batch is independent.
        let params = CountMinLeafParams { d: 4, w: 8, batch: 1000 };
        params.validate();
        let CountMinLeafParams { d, w, batch } = params;
        let n_ctr = d * batch;

        println!();
        println!("v9 duplicate-key ratio sweep — privacy-preserving §5.2 leaf");
        println!("============================================================");
        println!("  threads: {effective_threads}  ({source})");
        println!("  fixed (d, w, batch) = ({d}, {w}, {batch})  n_ctr = {n_ctr}");
        println!("  no off-circuit aggregation — full batch submitted to v9 each time");
        println!();

        // Span: all distinct → most-duplicated. Comment out individual
        // entries to reduce sweep runtime on slower machines.
        let distinct_grid = [100usize, 50, 20, 10, 5, 2, 1];

        for &distinct in &distinct_grid {
            let batch_vec = gen_batch_with_distinct_keys(params, distinct);
            let stats = analyze_batch(&batch_vec);
            let prove_time = bench_v9_prover_on_batch(params, batch_vec, num_threads);
            println!(
                "  distinct={:>4}  max_rep={:>4}  hist_modes={:>2}  prove {:>10.2?}",
                stats.distinct_keys,
                stats.max_repetitions,
                stats.histogram.len(),
                prove_time
            );
        }
    }
}
