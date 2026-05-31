# plonky2 vs plonky3 — `countmin_final` performance

Head-to-head on the **three `#[ignore]` performance benchmarks** in `countmin_final`
(the canonical §5.2 Count-Min update leaf), at the **same shape**
`(d, w, batch) = (4, 8, 1000)`, on the **same machine (64 threads, Rayon default pool)**.

- **plonky3** (STARK): `../zkSketch/src/sketch/countmin_final.rs`
- **plonky2** (SNARK): `src/leaf/countmin_final.rs` (this crate)

All numbers below are **measured** — each stack run once as a combined
`--test-threads=1` pass (single run; treat as ±10–20% indicative, not a controlled
benchmark). Reproduce:

```bash
# plonky3 baseline
cd ../zkSketch && cargo test --release --lib countmin_final::tests \
  -- --ignored --nocapture --test-threads=1
# plonky2
cd ../zkSketch_SNARK && cargo test --release leaf::countmin_final::tests \
  -- --ignored --nocapture --test-threads=1
```

## What's comparable, and the one big caveat

The two circuits implement the **same algorithm and the same three benchmarks**, each
in its framework's idiomatic style:

| | plonky3 | plonky2 |
|---|---|---|
| Field | BabyBear (31-bit) | Goldilocks (64-bit) |
| Sorts / compaction | dedicated `PermuteAir` tables (multi-table batch-STARK) | in-circuit grand-product args + `split_le` range checks |
| Hash | Poseidon2 width-16 AIR | `PoseidonHash` gadget |
| §4.2 merge | `plonky3-recursion` aggregation layer | native `builder.verify_proof` |

**Build vs prove — the caveat that drives the leaf rows.** plonky3's
`prove_countmin_final` *rebuilds the circuit inside every call*, so its "leaf prove"
number is **build+prove**. plonky2 splits the two: `build_countmin_final_leaf()` (heavy
`builder.build()` preprocessing) then `leaf.prove()`, and Tests 2/3 build once and reuse.
Therefore:

- **Test 1 times build+prove on *both* sides → the clean apples-to-apples comparison.**
- **Tests 2 & 3 report plonky2 leaf *prove-only*** (build hoisted out & amortized), while
  plonky3's leaf number is build+prove. Don't compare those leaf rows directly — use
  Test 1 for leaves. The **merge** and **proof-size** rows are fully comparable.

Subtracting Test 1 (build+prove) − Test 2/3 (prove-only) gives plonky2's split:
at distinct=1000, **build ≈ 6.6 s, prove ≈ 2.6 s**; at distinct=100,
**build ≈ 0.54 s, prove ≈ 0.30 s**. Both build and prove scale with the distinct-key count.

## Test 1 — proving time vs. distinct-key count (build+prove, BOTH sides)

The §5.2 win: cost falls as the distinct-key count drops, at fixed `batch=1000`.

| distinct_bound | plonky3 | plonky2 | plonky3 faster by |
|---:|---:|---:|---:|
| 1000 | 4.66 s    | 9.19 s    | 2.0× |
| 500  | 2.31 s    | 3.94 s    | 1.7× |
| 100  | 602.40 ms | 840.28 ms | 1.4× |
| 50   | 346.71 ms | 420.92 ms | 1.2× |
| 10   | 165.98 ms | 387.52 ms | 2.3× |
| 5    | 170.18 ms | 204.48 ms | 1.2× |
| 1    | 124.52 ms | 193.28 ms | 1.6× |

Both curves slope down with fewer distinct keys — **§5.2 confirmed on both stacks**.
plonky3 is **~1.2–2.3× faster** at the leaf throughout (the gap is largest at the two
ends — the big circuit, where plonky2's grand-product permutations cost most, and the
tiny circuit, where plonky2's fixed build/FRI floor dominates).

## Test 2 — two leaves + §4.2 recursive merge (distinct_bound = batch = 1000)

| step | plonky3 | plonky2 | note |
|---|---:|---:|---|
| leaf 1 | 4.79 s *(build+prove)* | 2.57 s *(prove-only; +~6.6 s one-time build)* | not directly comparable — see caveat |
| leaf 2 | 4.61 s *(build+prove)* | 2.28 s *(prove-only; build reused)* | use Test 1 for the fair leaf number |
| **§4.2 merge** | **1.21 s** | **0.91 s** | comparable → **plonky2 1.3× faster** |
| total wall-clock | 10.61 s | 5.76 s* | *plonky2 total omits its one-time build (~6.6 s); see caveat |

Fair leaf build+prove at distinct=1000 (Test 1): plonky3 **4.66 s** vs plonky2 **9.19 s**
→ plonky3 ~2× faster. But the **merge step is faster on plonky2** (0.91 s vs 1.21 s).

## Test 3 — generate two proofs, persist, merge (distinct_bound = 100)

| metric | plonky3 | plonky2 | winner |
|---|---:|---:|---|
| leaf 1 | 702.55 ms *(build+prove)* | 296.44 ms *(prove-only)* | not directly comparable |
| leaf 2 | 670.31 ms *(build+prove)* | 270.75 ms *(prove-only)* | (use Test 1) |
| **§4.2 merge** | **1.00 s** | **0.94 s** | plonky2 (≈even, 1.06×) |
| **leaf proof size** | **540,192 bytes** | **146,212 bytes** | **plonky2 (3.7×)** |

Fair leaf build+prove at distinct=100 (Test 1): plonky3 **602 ms** vs plonky2 **840 ms**
→ plonky3 ~1.4× faster.

**Proof size is the clearest plonky2 win:** ~146 KB vs ~540 KB. plonky2 emits a single
monolithic circuit → one FRI proof; plonky3's `countmin_final` is a multi-table
batch-STARK (Poseidon2 + recompose + 3× PermuteAir), and each table contributes its own
commitments/openings, inflating the aggregate proof — enough to outweigh plonky2's larger
(8-byte Goldilocks vs 4-byte BabyBear) field elements.

## Takeaways (measured)

1. **Leaf build+prove: plonky3 wins, by ~1.2–2.3×** (Test 1, the clean comparison) — not
   the order-of-magnitude gap one might expect. Its 31-bit BabyBear field + dedicated AIR
   tables beat plonky2's grand-product permutations + range checks, but plonky2 stays
   within ~2×.
2. **Merge: plonky2 wins** (0.91–0.94 s vs 1.00–1.21 s, up to 1.3×). Its mature native
   `verify_proof` recursion edges out the plonky3-recursion aggregation layer here.
3. **Proof size: plonky2 wins ~3.7×** (146 KB vs 540 KB), thanks to its single-circuit /
   single-FRI-proof structure vs plonky3's multi-table batch-STARK.
4. **The §5.2 distinct-key optimization holds on both stacks** — time tracks the
   distinct-key count, not the raw batch size.

Net for *this* workload: **plonky3 is the faster leaf prover (~1.2–2.3×); plonky2 merges
faster (~1.3×) and produces a ~3.7× smaller proof.** A hybrid — plonky3 leaves wrapped by
plonky2/SNARK recursion — could in principle combine both, at the cost of a field-crossing
bridge.

*Methodology: one combined release run per stack, 64 threads, `--test-threads=1`. plonky2
Test 2/3 leaf rows are prove-only (build hoisted & amortized); all merge and proof-size
rows are directly comparable; use Test 1 for the fair leaf comparison.*
