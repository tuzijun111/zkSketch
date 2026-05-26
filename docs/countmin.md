# Count-Min — current circuit design & proving-time knobs

This document describes the **latest** in-circuit Count-Min update design (Phase 9h "compact-G v9h leaf") and the parameters that govern its proving time. For the full lab notebook of how we got here — earlier designs, every measured number, every gotcha — see [`docs/EXPERIMENTS.md`](EXPERIMENTS.md).

If you only have two minutes, jump to:
- [What's the latest design](#whats-the-latest-design)
- [How to run the prover](#how-to-run-the-prover)
- [Parameters that affect proving time](#parameters-that-affect-proving-time)

---

## Table of contents

1. [What's the latest design](#whats-the-latest-design)
2. [Where the code lives](#where-the-code-lives)
3. [The §5.2 pipeline at a glance](#the-§52-pipeline-at-a-glance)
4. [Public-input shape (privacy)](#public-input-shape-privacy)
5. [How to run the prover](#how-to-run-the-prover)
6. [Parameters that affect proving time](#parameters-that-affect-proving-time)
   - [Circuit-shape parameters](#circuit-shape-parameters-d-w-batch-distinct_bound)
   - [Workload-shape parameters](#workload-shape-parameters-batch-composition--key-distribution)
   - [Runtime parameters](#runtime-parameters-thread-count)
7. [Measured numbers](#measured-numbers)
8. [Choosing `distinct_bound`](#choosing-distinct_bound)
9. [Sweep tests — how to reproduce](#sweep-tests--how-to-reproduce)
10. [Earlier baselines](#earlier-baselines-kept-side-by-side)
11. [Soundness notes](#soundness-notes)
12. [References](#references)

---

## What's the latest design

The latest leaf is **Phase 9h — the compact-G v9h leaf**:

- **Privacy-preserving**: keys and per-record values are *private witnesses* — only a Poseidon2 `batch_commit` of the raw batch is exposed as a public input.
- **In-circuit aggregation**: the prover supplies a fixed-size *G table* (length `distinct_bound`) as a hint, and the circuit *verifies* it is the correct key-aggregation of the raw batch (PermuteAir multiset equality + adjacent-equality tags + running sum). No off-circuit "trust the prover's aggregation".
- **§5.2 hash-work savings**: the hash gadget runs `distinct_bound · d` times instead of `batch · d` times. For duplicate-heavy workloads with a tight `distinct_bound`, this is the speedup the paper promises.

The leaf is **chain-mergeable** via the existing Phase 9d merge function — two v9h leaves at the *same* `(d, w, batch, distinct_bound)` combine into one recursive batch-STARK whose verifier cost is O(1) regardless of how many leaves were folded in.

## Where the code lives

| Path | What it is |
| ---- | ---------- |
| `src/sketch/countmin_v9.rs` | The §5.2 sketch + field-friendly hash family `h_i(k) = (k·a_i + b_i) mod w`. `pub fn hash_cell_v9`. |
| `src/commitment/countmin_batch.rs` | `CountMinBatchCommit` + `commit_batch(records)` — Poseidon2-over-(key_lo, key_hi, value, padding). The PI binding for the *raw* batch. |
| **`src/recursion/recursive/countmin_leaf_v9h.rs`** | **The latest leaf — Phase 9h.** `CountMinLeafParamsV9h { d, w, batch, distinct_bound }` and `prove_countmin_leaf_v9h_with_params(...)`. |
| `src/recursion/recursive/countmin_leaf_v9.rs` | Phase 9g leaf — same privacy guarantees, *no* compact G (every raw row pays the hash cost). Kept as baseline. |
| `src/recursion/recursive/countmin_merge_v9.rs` | `merge_two_countmin_v9` + `verify_chain_countmin_v9` — §4.2 recursive merge over v9/v9h leaves. |
| `src/sketch/countmin_v3.rs` | Plaintext §5.2 pipeline + benchmark/sweep helpers (`bench_v9h_prover_on_batch`, `gen_batch_with_distinct_keys`, `analyze_batch`, `aggregate_by_key`). |

## The §5.2 pipeline at a glance

The paper's §5.2 design (database-style maintenance plan):

```
raw batch B  ──group by key──▶  aggregated G  ──compute counter ids──▶  U_ctr  ──group by counter──▶  patch A  ──sparse apply──▶  S_t
```

What v9h does in-circuit:

1. **Bind the raw batch** — Poseidon2 hash of `(key_lo, key_hi, value, 0)` per record, connected to the `batch_commit` PI.
2. **Sort B by key** — PermuteAir #1 enforces multiset equality between the raw batch and a sorted-by-key view supplied as a witness.
3. **Adjacent-equality tags + running sum** — PoneglyphDB §4.3 group-by gate aggregates consecutive equal-key rows; emits `(key_acc[r], g_active[r])` for `r ∈ 0..batch`.
4. **Compaction (Phase 9h's contribution)** — PermuteAir #2 rearranges the length-`batch` segment-end vector so the `actual_distinct` non-zero entries land at positions `[0, actual_distinct)`. Constrained equal to a fixed-size G table of length `distinct_bound` (with zero-padding past `actual_distinct`).
5. **Per-G-row hash** — for each `j ∈ 0..distinct_bound`: compute `h_i(key_table[j]) = (key_table[j]·a_i + b_i) mod w` via a multiply-add + bit-decomposition. Build U_ctr payload of length `distinct_bound · d`.
6. **Sort U_ctr by counter** — PermuteAir #3.
7. **Counter-grouping + sparse patch** — adjacent-equality + running sum produces patch rows; per-cell selectors fold them into the final state.
8. **State-transition equation** — `final_cells[idx] = initial_cells[idx] + Σ_r sel_a_cell[r][idx] · acc[r]`. The initial and final state commitments are bound via Poseidon2 hashes of the packed cells.

Stages 1–3 verify the prover's aggregation hint is correct. Stages 4–7 are where Phase 9h's "only distinct keys pay the hash cost" lives. Stage 8 closes the loop with the state commitments.

## Public-input shape (privacy)

```
(initial_commit_lo, initial_commit_hi,    // 2 Challenge slots
 final_commit_lo,   final_commit_hi,      // 2 Challenge slots
 batch_commit_lo,   batch_commit_hi)      // 2 Challenge slots
```

Total: 6 Challenge elements. **No per-record data is exposed.** Compare to v1/v2/v3, which exposed `(key, value, pos[0..d])` per record — useful for non-private demos, but a privacy leak.

## How to run the prover

Smallest end-to-end example, taken from `countmin_leaf_v9h.rs`'s test suite:

```rust
use zksketch::recursion::recursive::countmin_leaf_v9h::{
    CountMinLeafParamsV9h, prove_countmin_leaf_v9h_with_params,
};
use zksketch::sketch::countmin::{CountMinParams, CountMinUpdate};
use zksketch::sketch::countmin_v9::CountMinV9;
use zksketch::sketch::Sketch;

let params = CountMinLeafParamsV9h {
    d: 4,
    w: 8,
    batch: 10,
    distinct_bound: 3,  // expecting at most 3 distinct keys per batch
};

// Initial state must use the v9 update function (different hash family from v1).
let initial = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });

// 10 records cycling through 3 distinct keys.
let batch: Vec<CountMinUpdate> = (0..params.batch as usize)
    .map(|i| CountMinUpdate {
        key: ((i % 3) as u64).wrapping_mul(0x9E37_79B9) + 1,
        value: 1 + (i as u32 % 5),
    })
    .collect();

let leaf = prove_countmin_leaf_v9h_with_params(params, initial, batch);
// `leaf` is a CountMinLeafProofV9 — chain-mergeable with merge_two_countmin_v9.
```

Two leaves at the same `(d, w, batch, distinct_bound)` merge to a `CountMinChainProofV9`:

```rust
use zksketch::recursion::recursive::countmin_merge_v9::{
    merge_two_countmin_v9, verify_chain_countmin_v9,
};

let chain = merge_two_countmin_v9(&l1, &l2).expect("v9h chain-merge");
verify_chain_countmin_v9(&chain).expect("v9h chain verify");
```

For benchmarking, the `bench_v9h_prover_on_batch` helper in `src/sketch/countmin_v3.rs` times one prove call with a configurable thread count:

```rust
use zksketch::sketch::countmin_v3::{bench_v9h_prover_on_batch, gen_batch_with_distinct_keys};

let base = CountMinLeafParams { d: 4, w: 8, batch: 1000 };
let batch = gen_batch_with_distinct_keys(base, 100);  // 1000 records, 100 distinct keys
let params = CountMinLeafParamsV9h { d: 4, w: 8, batch: 1000, distinct_bound: 100 };
let duration = bench_v9h_prover_on_batch(params, batch, Some(8));
```

## Parameters that affect proving time

### Circuit-shape parameters (`d`, `w`, `batch`, `distinct_bound`)

These appear in `CountMinLeafParamsV9h` and **determine the circuit's shape and hence the verification key**. Changing any of them produces a different circuit; two leaves can only chain-merge when all four match.

| Param | What it controls | Hard constraints | Effect on prove time |
| ----- | ---------------- | ---------------- | -------------------- |
| **`d`** | Number of sketch rows (hash-family depth) | `1 ≤ d ≤ 16` (hash-family table size) | Linear in `d` for the hash loop (`distinct_bound · d` hash gadget invocations). Sub-linear for the rest. |
| **`w`** | Number of buckets per row | `w ∈ {2, 4, 8, 16}` (power of 2 ≤ 16, see [soundness notes](#soundness-notes)) | Bit-decomposition uses `log₂(w)` booleans per hash. Sparse-patch sees `num_cells = d·w` cells per state-transition equation. |
| **`batch`** | Raw record count per epoch | `d·w` must be a multiple of 4 (Challenge extension degree); `batch ≥ 1` | **`O(batch)`** for the per-record bookkeeping: batch-commit hash, key-sort PermuteAir, adjacent-equality + running sum, compaction PermuteAir. |
| **`distinct_bound`** | Compile-time upper bound on `\|distinct(keys)\|` | `1 ≤ distinct_bound ≤ batch` | **`O(distinct_bound · d)`** for the hash loop, counter-grouping, and sparse-patch selectors — the §5.2 win. |

The big take-away: prove time is roughly

```
T(d, w, batch, distinct_bound)  ≈  α · batch  +  β · (distinct_bound · d) · log₂ w  +  γ · d · w
```

with `α` being the per-record bookkeeping cost (paid regardless of duplicates), `β` the per-hash + counter-grouping cost (the bulk of the work, scales with `distinct_bound`), and `γ` the per-cell sparse-patch cost.

For duplicate-heavy workloads, making `distinct_bound` small is by far the biggest lever. See [measured numbers](#measured-numbers).

### Workload-shape parameters (batch composition / key distribution)

These don't change the circuit shape (so the same proving key works), but they change *how the circuit fills*:

- **Number of actual distinct keys in the batch**. Must be `≤ distinct_bound` or the prover fails (the compaction PermuteAir cannot balance multisets). At a fixed `distinct_bound`, prove time is essentially independent of how many distinct keys are *actually* present below the bound — padding rows in the G table still pay the hash gadget cost, contributing zero deltas.
- **Per-record `value`**. The encoding `key · 2²⁰ + value` requires `value < 2²⁰ = 1 048 576`. Aggregated values (segment totals) must also stay under `2²⁰`. For `batch = 1000` with per-record `value ≤ 7` the worst-case aggregated value is `7 000`, comfortably under the bound.
- **`key = 0` corner case**. Zero is reserved as the compaction PermuteAir's padding sentinel. A real `key = 0` is safe **unless** all its records have `value = 0` (degenerate — has no effect on the sketch anyway). See `countmin_leaf_v9h.rs` module docstring.

Helpers in `src/sketch/countmin_v3.rs`:

- `gen_default_batch(params)` — deterministic 1000-record batch with all-distinct keys.
- `gen_batch_with_distinct_keys(params, distinct)` — cycle through exactly `distinct` distinct keys.
- `analyze_batch(records) -> BatchStats { records, distinct_keys, max_repetitions, histogram }` — inspect a batch's key distribution.
- `aggregate_by_key(records) -> Vec<CountMinUpdate>` — collapse equal-key records (sum values). The same operation the v9h leaf verifies in-circuit; useful as a plaintext oracle.

### Runtime parameters (thread count)

Independent of circuit shape — affects how the prover uses CPU cores.

- **`bench_v9h_prover_on_batch(params, batch, num_threads)`** accepts an optional thread count. `None` uses Rayon's global pool (default = `num_cpus::get()`); `Some(N)` spawns a dedicated pool of `N` threads.
- Sweeps respect the **`V3_SWEEP_THREADS`** env var. `V3_SWEEP_THREADS=8 cargo test --release --lib v9h_duplicate_key_compact_sweep -- --ignored --nocapture`.
- Plonky3's parallel features are enabled by default in this crate's `Cargo.toml`. If `cargo test` defaults to debug, see `.vscode/settings.json` (`rust-analyzer.runnables.extraArgs: ["--release"]` for VS Code's Run Test button).

Empirically: Rayon scales well up to ~8 threads; past that, contention on the small problem sizes used here yields diminishing returns. The default global pool is fine for most measurements.

## Measured numbers

Phase 9h compact-G sweep, fixed `(d, w, batch) = (4, 8, 1000)`, 8 threads, measured 2026-05-26 on the user's local machine:

| `distinct_bound` | actual distinct | prove time |
| ---------------- | --------------- | ---------- |
| 1000 (no compaction) | 1000 | 7.24 s |
| 500              | 500              | 3.58 s     |
| 100              | 100              | 846 ms     |
| 50               | 50               | 454 ms     |
| 10               | 10               | 270 ms     |
| 5                | 5                | 286 ms     |
| 1                | 1                | 175 ms     |

For comparison, Phase 9g (no compaction) at the same `(d, w, batch)` is **flat at ~7 s** regardless of how many distinct keys the batch actually contains — the §5.2 promise was not realized without `distinct_bound`.

Reproduce: `V3_SWEEP_THREADS=8 cargo test --release --lib v9h_duplicate_key_compact_sweep -- --ignored --nocapture`.

## Choosing `distinct_bound`

Pick the **smallest** value that's still ≥ the maximum number of distinct keys you expect in any single epoch. Trade-offs:

- **Too small** → some batches in your workload will be rejected at prove time (compaction PermuteAir can't balance).
- **Too large** → padding rows in the G table still consume hash-gadget effort. At `distinct_bound = batch`, you pay the no-compaction baseline (~7 s for 1000 records) plus a small overhead for the compaction PermuteAir itself.
- **Different epochs need different `distinct_bound`** → use different verification keys per epoch, or pick a single conservative bound across all epochs (paying for the worst case).

The verification key is keyed by `(d, w, batch, distinct_bound)`. Two leaves can chain-merge only when *all four* match.

A practical recipe: profile your real workload with `analyze_batch` to estimate the 99th-percentile distinct-key count, round up to the next power of 2 or convenient size, and set `distinct_bound` there. The remaining 1% of epochs that exceed the bound need a fall-back (e.g. split into smaller sub-epochs each below the bound).

## Sweep tests — how to reproduce

All sweep tests live as `#[ignore]`'d unit tests so `cargo test --release` doesn't pay their cost. Invoke explicitly:

```bash
# Phase 9h compact-G sweep (the latest — slopes downward with distinct_bound).
V3_SWEEP_THREADS=8 cargo test --release --lib v9h_duplicate_key_compact_sweep -- --ignored --nocapture

# Phase 9g flat baseline (no compaction; same circuit shape at any duplicate density).
V3_SWEEP_THREADS=8 cargo test --release --lib v9_duplicate_key_sweep -- --ignored --nocapture

# v9 (d, w, batch) workload sweep (no duplicate-density axis).
V3_SWEEP_THREADS=8 cargo test --release --lib v9_proving_time_sweep -- --ignored --nocapture

# v3 (positions-as-PIs) (d, w, batch) workload sweep.
V3_SWEEP_THREADS=8 cargo test --release --lib v3_proving_time_sweep -- --ignored --nocapture
```

The `--nocapture` flag is needed because the timing tables are printed via `println!`. Drop `V3_SWEEP_THREADS` to use Rayon's default global pool.

## Earlier baselines (kept side-by-side)

Per the project's "keep baselines when adding new methods" rule, every earlier design is preserved:

| Leaf | File | What it is | Privacy? | Use when |
| ---- | ---- | ---------- | -------- | -------- |
| **v9h** | `countmin_leaf_v9h.rs` | Phase 9h, compact-G | **Yes** — only `(initial, final, batch_commit)` PIs | Best for duplicate-heavy workloads; needs an upfront `distinct_bound` |
| v9 | `countmin_leaf_v9.rs` | Phase 9g, no compact-G | **Yes** | Privacy + unknown distinct count; flat ~7 s prove |
| v3 | `countmin_leaf_v3.rs` | §5.2 with positions-as-PIs (no key privacy) | No | Demo / debugging; positions are visible |
| v2 | `countmin_leaf_v2.rs` | §5.4-shaped flat aggregate (no §5.2 grouping) | No | Smallest constraint count for tiny batches |
| v1 | `countmin_leaf.rs` | §5.1 strawman (per-cell additive) | No | Original baseline |

v1, v2, v3 all expose `(key, value, pos)` per record as PIs and are cross-mergeable via the original `merge_two_countmin`. v9 and v9h share a different PI shape (`batch_commit` instead of per-record) and merge via `merge_two_countmin_v9`. You cannot chain a v9-family leaf with a v1/v2/v3 leaf.

## Soundness notes

- **Aggregation is verified, not trusted.** The prover supplies the aggregated G table as a hint; the compaction PermuteAir + adjacent-equality tags + running sum force it to be the unique correct aggregation of the raw batch.
- **`w` must be a power of 2 in `{2, 4, 8, 16}`** because the in-circuit "mod w" reduction is implemented as a bit-decomposition's bottom `log₂(w)` bits. Non-power-of-2 `w` would need an explicit `r < w` range check (deferred — would cost extra constraints).
- **Capacity overflow is a clean failure.** If a batch has more distinct keys than `distinct_bound`, the native side asserts before invoking the prover (`assert!(actual_distinct ≤ distinct_bound)`). Caller-side recoverable.
- **Per-record `value` and aggregated segment totals must be `< 2²⁰`** because the encoding `key · 2²⁰ + value` needs to be uniquely decodable. The bound is `α = SHIFT_VAL_BITS = 20`; widen by changing the constant in both `countmin_leaf_v9.rs` and `countmin_leaf_v9h.rs` together (and re-checking the Challenge-field bit budget).
- **The Count-Min upper-bound property (every estimate `≥` true count)** is preserved — v9's field-friendly `h_i` distributes reasonably, so the standard `δ = e/w`, `error = ε` bounds still apply with `d` hash rows.

## References

- **Paper**: `paper/zkSketch.pdf` §5.2 — the database-style maintenance plan; §4.2 — recursive merge atom; §4.1 — flat chain (baseline).
- **PoneglyphDB §4.3 (Eq 7-8)**: the multiset-equality + adjacent-equality group-by gate this design uses.
- **Plan file**: `/home/binbin/.claude/plans/velvet-hatching-flask.md` — phase-by-phase design notes.
- **Experiment log**: [`docs/EXPERIMENTS.md`](EXPERIMENTS.md) — every measured number with reproduction commands.
- **Plonky3 fork patch (Phase 8d)**: `/home/binbin/Plonky3-recursion-fork` — enables multi-NPO PermuteAir at extension degree `D > 1`.
