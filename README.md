# zkSketch

Research prototype exploring the ideas in the **zkSketch** paper (`paper/zkSketch.pdf`):
non-interactive, verifiable, privacy-preserving sketch-based analytics built on
recursive STARKs. The framework is implemented on top of
[plonky3](https://github.com/Plonky3/Plonky3) and
[plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion).

> **Looking for the experiment log / reproduction recipe?** See
> [`docs/EXPERIMENTS.md`](docs/EXPERIMENTS.md). It walks each phase end-to-end
> with measured numbers, every test annotated, the gotchas we hit (and how we
> fixed them), and one-command recipes to re-run every result.

## What's here today

Three end-to-end paths live side by side so prove/verify times and proof
sizes can be compared directly:

**Phase 1 — §4.1 flat proof chain (toy AIR).** Two adjacent epochs are
proven as uni-stark `FibAir` leaves (`src/air/fib.rs`, `src/prover/leaf.rs`).
The `flat::ChainProof` bundles both leaf proofs; `flat::verify_chain`
re-checks each leaf and asserts the shared-boundary equality natively.
Verifier work is `Θ(E)` in the number of epochs.

**Phase 1.5 — §4.2 recursive merge (toy AIR).** Each leaf is a
`CircuitBuilder` Fibonacci proven via `BatchStarkProver`
(`src/recursion/recursive/leaf.rs`). `recursive::merge_two` aggregates both
via `p3_recursion::build_and_prove_aggregation_layer`, producing one
batch-STARK that certifies both leaves. Verifier work is **O(1) regardless
of leaf count**, with the intermediate boundary checked natively against the
exposed public inputs.

**Phase 2 — Count-Min update epochs, §4.2 recursive merge.** Each leaf is a
real Count-Min update circuit (paper §5.1 strawman: per-cell additive delta
with in-circuit Poseidon2 binding of the state commit). Fixed
`(d, w, batch) = (2, 4, 2)` so the 8-cell state aligns to the Challenge
extension degree for hashing. `recursive::countmin_merge::merge_two_countmin`
aggregates two epochs into one recursive batch-STARK; verifier work is
again O(1). This is the §4.2 chain instantiated on a real sketch.

**Phase 3a — §4.1 vs §4.2 comparison on Count-Min.** `recursion::countmin_flat`
adds a §4.1 flat chain over `CountMinLeafProof`s for side-by-side
benchmarking. `examples/countmin_chain_two.rs` runs both paths on the same
two epochs and prints prove/verify times and proof sizes. At E = 2 the
recursive verify is already slightly cheaper than the flat one (≈ 13 ms vs
15 ms) and the recursive proof is smaller (≈ 514 KB vs 546 KB).

**Phase 3b — Multi-leaf scaling.** `CountMinChainState::extend` grows the
chain past two leaves by folding the running root with each new leaf via
`build_and_prove_aggregation_layer`. `examples/countmin_chain_n.rs` sweeps
E ∈ {2, 4, 8} and confirms the paper's O(1)-verifier claim: chain verify
stays at ≈ 12 ms across all E, while the §4.1 flat-baseline proof size
scales linearly (1.06× → 2.26× → 4.52× the recursive proof size as E
goes 2 → 4 → 8).

**Phase 3c — Workload sweep.** The leaf prover accepts runtime `(d, w,
batch)` via `prove_countmin_leaf_with_params`; the existing `(2, 4, 2)`
API remains as a wrapper. `examples/countmin_sweep.rs` runs a small
(d, w, batch) grid and prints prove time / proof size per combo.

**Phase 3d — §5.4-shaped v2 leaf (structural).** `recursion::recursive::
countmin_leaf_v2` exposes the §5.4 per-cell aggregate table `A` as an
explicit in-circuit witness; the transition reads `final = initial + A`
rather than computing the sum inline at each cell. v2 leaves are a
drop-in replacement for v1 (same `CountMinLeafProof` shape; same §4.2
recursive merge accepts them — exercised by the `v2_leaf_merges_with_v1`
test). **Caveat**: this is the structural refactor only. The genuine
§5.4 witness reduction to `O(m·d + T)` needs a commitment-scheme change
(homomorphic-additive vector commit or Merkle-tree sparse opens), since
the current Poseidon2-of-flat-cells commit forces both states to live in
the witness. v2 lands the algorithmic seam where that change drops in.
`examples/countmin_v1_vs_v2.rs` compares prove time / proof size at a
small grid; today v1 and v2 are within noise of each other.

**Phase 4 — HyperLogLog end-to-end (Pattern A max).** The second sketch
family. `src/sketch/hyperloglog.rs` + `src/commitment/hyperloglog.rs`
deliver the plaintext sketch and Poseidon2 commit (Phase 4a). The HLL
update leaf at `src/recursion/recursive/hll_leaf.rs` (Phase 4b) is a
§5.1-style strawman with *sound* max-correctness: per register, bit-decompose
`initial[r]` and `final[r]` into `REGISTER_WIDTH = 6` bits each, build the
candidate set `{initial[r]} ∪ {lead[k] : selector[k][r] = 1}`, enforce
`Π(final[r] - candidate_i) = 0` (final is one of the candidates) and
bit-decomp of each `final[r] - candidate_i` (final ≥ each candidate) →
final = max(set). The §4.2 recursive merge, §4.3 chain, and §4.1 flat
layers (`hll_merge`, `hll_chain`, `hll_flat`) are sketch-agnostic
type-substitutions of their Count-Min siblings (Phase 4c). At E ∈ {2, 4,
8} the recursive verifier stays ≈ 12 ms across HLL just like it does
across Count-Min — the §4.2 atom is leaf-agnostic.

**Phase 4d — HLL §5.4-shaped v2 leaf (structural).** Mirror of Phase 3d
for HLL. `src/recursion/recursive/hll_leaf_v2.rs` exposes the Appendix F
per-register aggregate table `A` as an explicit witness, factoring the
unified `final = max(initial, ...)` constraint into two stages:
`A[r] = max(0, {selector[k][r] * lead[k]})` then `final[r] = max(initial[r], A[r])`.
Same `HllLeafProof` shape so v2 leaves chain with v1 leaves in the same
`merge_two_hll` — the `hll_v2_leaf_merges_with_v1` test exercises that
cross-compatibility. **Caveat**: this is the structural refactor only,
same as Count-Min v2. The genuine Appendix F win (wide-output Poseidon2,
batched IPA/KZG patch over touched registers) lands when the commit
scheme moves. v2's `A` slot is the seam that variant plugs into. The
`examples/hll_v1_vs_v2.rs` demo confirms v2 is correctness-preserving;
prove time is slightly higher than v1 today (extra range checks).

**Phase 5 — SpaceSaving (Pattern B, plaintext + commit).** The framework's
first Pattern B sketch (paper §5.3, Appendix G). `src/sketch/spacesaving.rs`
implements classical Misra-Gries (match / free-slot / evict branches);
`src/commitment/spacesaving.rs` is the Poseidon2-of-flattened-`(key, count)`-pairs
commit. **Scope deferred**: the in-circuit leaf + recursive merge + chain
+ flat. Pattern B's proper in-circuit shape is the §G four-gate pipeline
(SS-Union → Sort+SegGroup → TopS → ReplaceState); a simplified strawman
that just hash-binds (the trick that works for Pattern A) trips a
`WitnessChecks` cumulative-sum mismatch because Pattern B's decomposed
witnesses need the four gates' natural consumers to balance the bus.
Plaintext + commit is the foundation a future Phase 5b/c can build on.

**Phase 6 — Greenwald-Khanna (Pattern B, plaintext + commit).** A
second Pattern B sketch — bounded-capacity sorted summary with
merge-on-overflow compression. `src/sketch/greenwald_khanna.rs`
maintains a `(value, count, max_error)` triple list with a cheap
merge rule (combine the adjacent tuples with smallest `count + max_error`
sum). **Scope deferred** matches Phase 5: in-circuit leaf is future
work. The simplified plaintext intentionally relaxes GK's ε-bound
guarantee on rank-query accuracy; the framework's purpose here is to
have a second Pattern B sketch alongside SpaceSaving, not a faithful GK
implementation.

The plaintext sketch + `StateCommit` foundation lives in `src/sketch/` and
`src/commitment/`. The next phase will optimise the leaf circuit to §5.4
Pattern A linear (sort + segment-aggregate + sparse patch), replacing the
strawman's full-cell-replay constraints with delta-certified ones.

## Prerequisites

- Rust 1.85 or newer (edition 2024).
- A working network connection on first build — `Cargo.toml` pulls `plonky3`
  and `plonky3-recursion` from GitHub at pinned revisions (no `crates.io`
  release). First build takes a few minutes; subsequent builds are warm.

## Run it

```bash
# Build once. Release is strongly recommended for anything touching the
# recursive merge — its prover is ~50× slower in debug.
cargo build --release

# All tests (64 lib + 17 integration = 81 tests, ~75 s in release).
cargo test --release

# Just the §4.1 flat chain (fast — uni-stark only, ~50 ms total).
cargo test --release --test two_leaf_chain
cargo test --release --lib  recursion::flat

# Just the §4.2 recursive merge with the toy AIR.
cargo test --release --test two_leaf_recursive
cargo test --release --lib  recursion::recursive::tests
cargo test --release --lib  recursion::recursive::leaf

# Phase 2 / 3 — real Count-Min update epochs (slow: each prove runs the
# aggregation prover with in-circuit Poseidon2 hashing).
cargo test --release --test two_leaf_countmin
cargo test --release --test two_leaf_countmin_flat
cargo test --release --test two_leaf_countmin_chain
cargo test --release --lib  countmin

# Phase 4 — HyperLogLog (Pattern A max). Same prove-cost regime as Count-Min.
cargo test --release --test two_leaf_hll
cargo test --release --test two_leaf_hll_flat
cargo test --release --test two_leaf_hll_chain
cargo test --release --lib  hyperloglog
cargo test --release --lib  hll_

# Phases 5+6 — SpaceSaving + Greenwald-Khanna (Pattern B, plaintext + commit only).
# In-circuit Pattern B leaves are future work (§G four-gate pipeline).
cargo test --release --lib  spacesaving
cargo test --release --lib  greenwald_khanna

# Side-by-side comparison + scaling demos.
cargo run  --release --example chain_two            # Phase 1 vs 1.5 (toy AIR)
cargo run  --release --example countmin_chain_two   # Phase 3a (real Count-Min, E=2)
cargo run  --release --example countmin_chain_n     # Phase 3b (sweep E ∈ {2, 4, 8})
cargo run  --release --example countmin_sweep       # Phase 3c (workload sweep)
cargo run  --release --example countmin_v1_vs_v2    # Phase 3d (§5.1 strawman vs §5.4-shaped)
cargo run  --release --example hll_chain_two        # Phase 4c (HLL §4.1 vs §4.2)
cargo run  --release --example hll_chain_n          # Phase 4c (HLL sweep E ∈ {2, 4, 8})
cargo run  --release --example hll_sweep            # Phase 4c (HLL workload sweep)
cargo run  --release --example hll_v1_vs_v2         # Phase 4d (HLL §5.1 strawman vs §5.4-shaped)
```

Debug builds work too (`cargo test` without `--release`) but `cargo test --lib
recursion::recursive::tests::honest_two_leaf_recursive_accepts` and the
recursive integration test take ~2 minutes each instead of ~6 seconds.

Sample demo output (BabyBear, 64-row leaf trace, release build):

```
--- Phase 1: §4.1 flat chain (uni-stark FibAir) ---
  leaf 1: prove    26.07ms   verify   1.40ms   proof  63856 bytes
  leaf 2: prove     4.14ms   verify   1.39ms   proof  63951 bytes
  merge:  build     2.93µs
  chain:  verify    2.74ms   (2 leaves re-verified)

--- Phase 1.5: §4.2 recursive merge (CircuitBuilder Fibonacci) ---
  leaf 1: prove    43.41ms   proof 152786 bytes
  leaf 2: prove    34.84ms   proof 152677 bytes
  merge:  prove      5.80s   proof 474476 bytes
  chain:  verify   11.85ms   (one batch-STARK, O(1) regardless of leaf count)
```

The verifier cost is the metric to watch: §4.1 grows linearly with the
number of leaves; §4.2 stays flat regardless. The prover cost is the
flip side — aggregation is much heavier than a leaf prove because it has
to materialise the recursive verifier circuit. This is exactly the
trade-off paper §4 discusses.

## Tests — what each one covers

### Lib unit tests (64)

These run inside `cargo test --release --lib`.

**`src/air/fib.rs::tests`** — the toy Fibonacci AIR
- `last_pair_matches_trace` — confirms the generated trace's last row matches
  the in-field Fibonacci computation; a sanity check on the trace generator.

**`src/prover/leaf.rs::tests`** — uni-stark `FibAir` leaf prover (§4.1)
- `leaf_round_trip_small` — `prove_fib_leaf` followed by `verify_fib_leaf`
  accepts; the recovered final boundary matches the in-field computation
  (16-row trace starting from `(0, 1)` ends at `(610, 987)`).
- `tampered_final_rejected` — mutate `LeafProof.final_.a` after proving;
  verifier rejects (PI mismatch).
- `boundary_threads_between_leaves` — leaf 2 begins exactly where leaf 1
  ended, demonstrating the chain composes at the boundary.

**`src/recursion/digest.rs::tests`** — Poseidon2 ordered-update digest (§4.2)
- `leaf_digest_is_deterministic` — same inputs ⇒ same digest.
- `leaf_digest_separates_distinct_inputs` — different leaf indices ⇒
  different digests, ensuring membership is bound to position.
- `combine_digest_orders_children` — swapping left/right children ⇒
  different parent digest, ensuring child *order* is bound.

**`src/recursion/flat.rs::tests`** — §4.1 flat chain
- `honest_two_leaf_chain_accepts` — `merge_two` then `verify_chain` accepts
  an honest two-leaf chain.
- `boundary_mismatch_rejected_at_merge` — adjacent leaves with non-matching
  boundary; `merge_two` rejects at the shared-boundary check.
- `tampered_leaf_rejected_at_verify` — corrupt one byte of the bundled leaf
  proof; `verify_chain` rejects.

**`src/recursion/recursive/leaf.rs::tests`** — §4.2 CircuitBuilder leaf
- `recursive_leaf_round_trip` — `prove_recursive_leaf` produces a final
  boundary that matches the in-field Fibonacci computation; the leaf's
  internal `BatchStarkProver::verify_all_tables` self-check passes.

**`src/recursion/recursive/mod.rs::tests`** — §4.2 recursive merge (toy AIR)
- `upstream_pattern_aggregates` — adapts the upstream `recursive_aggregation`
  example's dummy-circuit pipeline to our config. Sanity-checks the §4.2
  aggregation API against our `ConfigWithFriParams` + `FriRecursionBackend`
  setup without any leaf-specific logic. Slow (~6 s release / ~2 min debug)
  but proves the recursion plumbing is sound.
- `honest_two_leaf_recursive_accepts` — `merge_two(&l1, &l2)` then
  `verify_chain` accepts the full two-leaf recursive chain.
- `boundary_mismatch_recursive_rejected` — mismatched boundary rejected at
  merge time, before the (expensive) aggregation prover runs.

**`src/sketch/countmin.rs::tests`** — Phase 2a plaintext sketch
- `update_increments_d_cells` — one insertion bumps exactly `d` cells.
- `point_query_upper_bounds_true_count` — Count-Min upper bound holds, tight when no collisions.
- `delta_aggregates_batch` — §5.3 Pattern A linear invariant: per-cell deltas commute.

**`src/commitment/countmin.rs::tests`** — Phase 2a Poseidon2 commit
- `commit_is_deterministic`
- `commit_distinguishes_states` (any counter change ⇒ different commit)
- `commit_matches_make_perm` (drift guard against `crate::config::make_perm`)

**`src/recursion/recursive/countmin_leaf.rs::tests`** — Phase 2b in-circuit update
- `countmin_leaf_round_trip` — `prove_countmin_leaf` produces a final commit that matches the native plaintext computation; the in-circuit hash of cells matches the off-circuit `commit_countmin`.

**`src/recursion/recursive/countmin_merge.rs::tests`** — Phase 2c recursive merge
- `honest_two_leaf_countmin_chain_accepts` — two adjacent Count-Min epochs merged via `build_and_prove_aggregation_layer` and re-verified.
- `boundary_mismatch_countmin_rejected` — mismatched boundary rejected at merge time.

**`src/recursion/countmin_flat.rs::tests`** — Phase 3a §4.1 Count-Min flat chain
- `honest_two_leaf_countmin_flat_accepts` — both leaves verified natively + boundary equality + digest re-derivation.
- `boundary_mismatch_countmin_flat_rejected` — mismatched boundary rejected at merge time.

**`src/recursion/recursive/countmin_chain.rs::tests`** — Phase 3b multi-leaf chain
- `chain_of_three_accepts` — init(l1, l2) then extend(l3) verifies; full boundary structure (initial + 2 internal + final) is preserved.
- `extend_with_bad_boundary_rejected` — `extend(l3)` rejects when `l3.initial != chain.final_`.

**`src/recursion/recursive/countmin_leaf.rs::tests`** — Phase 2b + 3c runtime-param tests
- `countmin_leaf_round_trip` — Phase 2b default (d=2, w=4, batch=2).
- `countmin_leaf_round_trip_at_4_4_4` — Phase 3c: same logic at (d=4, w=4, batch=4) via `prove_countmin_leaf_with_params`.
- `misaligned_params_rejected` — Phase 3c: `validate()` panics when `d*w % 4 != 0`.

**`src/recursion/recursive/countmin_leaf_v2.rs::tests`** — Phase 3d §5.4-shaped leaf
- `v2_leaf_round_trip` — v2 produces a leaf whose final commit matches the plaintext computation.
- `v2_leaf_merges_with_v1` — a v2 leaf chained with a v1 leaf in the same `merge_two_countmin` verifies, confirming `CountMinLeafProof` is shape-compatible across the two.

**`src/sketch/hyperloglog.rs::tests`** — Phase 4a plaintext sketch
- `update_writes_one_register` — one insertion touches exactly one HLL register.
- `register_max_is_monotone` — re-inserting the same key is idempotent (Pattern A max).
- `delta_aggregates_batch_via_max` — §5.3 Pattern A max invariant: per-register max commutes.
- `rejects_b_below_two` — `HyperLogLog::new(b=1)` panics; the alignment guard for `m ≥ CELL_ALIGNMENT = 4`.

**`src/commitment/hyperloglog.rs::tests`** — Phase 4a Poseidon2 commit
- `commit_is_deterministic`
- `commit_distinguishes_states` (register change ⇒ different commit)
- `commit_matches_make_perm` (drift guard against `crate::config::make_perm`)

**`src/recursion/recursive/hll_leaf.rs::tests`** — Phase 4b in-circuit HLL update leaf
- `hll_leaf_round_trip` — `(b=3, batch=2)` leaf prove succeeds; in-circuit hash matches off-circuit `commit_hll`; final registers match plaintext.
- `hll_leaf_round_trip_at_b4_batch4` — same logic at `(b=4, batch=4)` via the runtime-param API.
- `hll_misaligned_params_rejected` — `validate()` panics on `b < 2`.

**`src/recursion/recursive/hll_merge.rs::tests`** — Phase 4c §4.2 HLL recursive merge
- `honest_two_leaf_hll_chain_accepts` — two adjacent HLL epochs merged into one batch-STARK and re-verified.
- `boundary_mismatch_hll_rejected` — mismatched boundary rejected at merge time.

**`src/recursion/recursive/hll_chain.rs::tests`** — Phase 4c §4.3 HLL recursive chain
- `hll_chain_of_three_accepts` — `init(l1, l2)` + `extend(l3)` produces a 3-leaf chain that verifies.
- `hll_extend_with_bad_boundary_rejected` — extend rejects when boundary doesn't match.

**`src/recursion/hll_flat.rs::tests`** — Phase 4c §4.1 HLL flat chain
- `honest_two_leaf_hll_flat_accepts` — both leaves verified natively + boundary equality + digest re-derivation.
- `boundary_mismatch_hll_flat_rejected` — mismatched boundary rejected at flat-merge time.

**`src/recursion/recursive/hll_leaf_v2.rs::tests`** — Phase 4d §5.4-shaped HLL leaf
- `hll_v2_leaf_round_trip` — v2 produces a leaf whose final commit matches the plaintext computation at the default `(b=3, batch=2)` workload.
- `hll_v2_leaf_merges_with_v1` — a v2 HLL leaf chained with a v1 leaf in the same `merge_two_hll` verifies, confirming `HllLeafProof` shape compatibility across the two.

**`src/sketch/spacesaving.rs::tests`** — Phase 5a plaintext sketch
- `insert_fills_first_free_slot` — first insert lands in slot 0.
- `repeat_insert_increments_existing_row` — Misra-Gries match-branch.
- `eviction_replaces_min_count_row` — Misra-Gries evict-branch on full summary.
- `delta_replay_matches` — `apply_delta` reproduces replay.

**`src/commitment/spacesaving.rs::tests`** — Phase 5a Poseidon2 commit
- `commit_is_deterministic` / `commit_distinguishes_states` / `commit_matches_make_perm` — same shape as Count-Min / HLL drift guards.

**`src/sketch/greenwald_khanna.rs::tests`** — Phase 6a plaintext sketch
- `insert_into_empty_appends_active_tuple` — first insert into slot 0.
- `insertions_stay_sorted` — sorted invariant preserved.
- `overflow_triggers_compression` — merge-on-overflow keeps active count ≤ capacity.
- `delta_replay_matches` — `apply_delta` reproduces replay.
- `misaligned_capacity_rejected` — `new(capacity=6)` panics; alignment guard.

**`src/commitment/greenwald_khanna.rs::tests`** — Phase 6a Poseidon2 commit
- `commit_is_deterministic` / `commit_distinguishes_states` / `commit_matches_make_perm` — drift guards.

### Integration tests (17)

These run inside `cargo test --release --test <name>`. They exercise the
same paths as the lib tests above, but only through the public API — so a
breaking API change shows up here even when the lib tests pass.

**`tests/two_leaf_chain.rs`** — §4.1 flat chain end-to-end
- `honest_two_leaf_chain_end_to_end` — full chain via public API.
- `mismatched_boundary_is_rejected_at_merge` — negative test via public API.

**`tests/two_leaf_recursive.rs`** — §4.2 recursive merge end-to-end (toy AIR)
- `recursive_leaf_round_trip` — leaf prove via public API.
- `mismatched_boundary_recursive_rejected` — negative test via public API.
- `honest_two_leaf_recursive_end_to_end` — full §4.2 chain via public API.

**`tests/two_leaf_countmin.rs`** — §4.2 Count-Min chain end-to-end (Phase 2)
- `honest_two_leaf_countmin_chain_end_to_end` — two adjacent Count-Min epochs proven, merged into a single batch-STARK, and re-verified via the public API.
- `mismatched_boundary_countmin_rejected` — negative test via public API.

**`tests/two_leaf_countmin_flat.rs`** — §4.1 Count-Min flat chain end-to-end (Phase 3a)
- `honest_two_leaf_countmin_flat_end_to_end` — flat chain accepted via the public API.
- `mismatched_boundary_countmin_flat_rejected` — negative test via public API.

**`tests/two_leaf_countmin_chain.rs`** — §4.3 recursive chain end-to-end (Phase 3b)
- `chain_of_three_countmin_end_to_end` — init + extend produces a 3-leaf chain that verifies via public API.
- `extend_with_wrong_boundary_countmin_rejected` — extend rejects mismatched boundary via public API.

**`tests/two_leaf_hll.rs`** — §4.2 HLL chain end-to-end (Phase 4c)
- `honest_two_leaf_hll_chain_end_to_end` — two HLL epochs merged via `merge_two_hll` and re-verified via the public API.
- `mismatched_boundary_hll_rejected` — negative test via public API.

**`tests/two_leaf_hll_flat.rs`** — §4.1 HLL flat chain end-to-end (Phase 4c)
- `honest_two_leaf_hll_flat_end_to_end` — flat HLL chain accepted via public API.
- `mismatched_boundary_hll_flat_rejected` — negative test via public API.

**`tests/two_leaf_hll_chain.rs`** — §4.3 HLL recursive chain end-to-end (Phase 4c)
- `chain_of_three_hll_end_to_end` — init + extend produces a 3-leaf HLL chain that verifies via public API.
- `extend_with_wrong_boundary_hll_rejected` — extend rejects mismatched boundary via public API.

## Layout

| Path | What's in it |
| --- | --- |
| `src/config.rs` | BabyBear + Poseidon2 + two-adic FRI `StarkConfig`. `make_perm` returns the canonical `default_babybear_poseidon2_16` permutation. |
| `src/air/fib.rs` | Toy `FibAir`: 2-column trace, 4 public values `[a0, b0, aT, bT]`. |
| `src/prover/leaf.rs` | `prove_fib_leaf` / `verify_fib_leaf` + `LeafProof`. |
| `src/commitment/` | `StateCommit` trait + `Boundary` re-export. |
| `src/sketch/` | `Sketch` / `DeltaCert` traits + Count-Min stub (Phase 2). |
| `src/recursion/digest.rs` | Poseidon2 leaf + interval digests (paper §4.2). |
| `src/recursion/flat.rs` | §4.1 `ChainProof`, `merge_two`, `verify_chain`. |
| `src/recursion/recursive/` | §4.2 in-circuit merge: `config`, `backend`, `leaf` (toy Fibonacci), `countmin_leaf` (Phase 2 + 3c Count-Min update, runtime params), `countmin_leaf_v2` (Phase 3d §5.4-shaped variant), `countmin_merge` (Phase 2c two-leaf merge), `countmin_chain` (Phase 3b accumulating chain), top-level `merge_two` / `verify_chain`. |
| `src/recursion/countmin_flat.rs` | Phase 3a §4.1 flat chain for Count-Min (`flat_merge_two_countmin`, `verify_chain_flat_countmin`). |
| `src/recursion/hll_flat.rs` | Phase 4c §4.1 flat chain for HyperLogLog (`flat_merge_two_hll`, `verify_chain_flat_hll`). |
| `src/sketch/hyperloglog.rs` + `src/commitment/hyperloglog.rs` | Phase 4a plaintext HLL + Poseidon2 commit (Pattern A max). |
| `src/recursion/recursive/hll_leaf.rs` | Phase 4b HLL update leaf with sound max-correctness (bit-decomp + product-of-differences). |
| `src/recursion/recursive/hll_leaf_v2.rs` | Phase 4d §5.4-shaped HLL leaf — explicit aggregate `A` slot, two-stage max. |
| `src/recursion/recursive/hll_merge.rs` + `hll_chain.rs` | Phase 4c §4.2 HLL merge + §4.3 chain accumulator. Sketch-agnostic recursion plumbing. |
| `src/sketch/spacesaving.rs` + `src/commitment/spacesaving.rs` | Phase 5a plaintext SpaceSaving (Misra-Gries) + Poseidon2 commit (Pattern B). In-circuit leaf deferred to Phase 5b. |
| `src/sketch/greenwald_khanna.rs` + `src/commitment/greenwald_khanna.rs` | Phase 6a plaintext GK (sorted summary with merge-on-overflow) + commit (Pattern B). In-circuit leaf deferred to Phase 6b. |
| `src/recursion/chain.rs` | `ChainState` accumulator (`extend` is future work — chain extension beyond two leaves). |
| `tests/two_leaf_chain.rs` | §4.1 honest end-to-end + boundary mismatch (toy AIR). |
| `tests/two_leaf_recursive.rs` | §4.2 honest end-to-end + boundary mismatch + leaf round trip (toy AIR). |
| `tests/two_leaf_countmin.rs` | §4.2 Count-Min chain end-to-end (Phase 2). |
| `tests/two_leaf_countmin_flat.rs` | §4.1 Count-Min flat chain end-to-end (Phase 3a). |
| `tests/two_leaf_countmin_chain.rs` | §4.3 recursive chain end-to-end on 3 leaves (Phase 3b). |
| `tests/two_leaf_hll.rs` | §4.2 HLL chain end-to-end (Phase 4c). |
| `tests/two_leaf_hll_flat.rs` | §4.1 HLL flat chain end-to-end (Phase 4c). |
| `tests/two_leaf_hll_chain.rs` | §4.3 HLL recursive chain end-to-end on 3 leaves (Phase 4c). |
| `examples/chain_two.rs` | Side-by-side prove/verify/size comparison (toy AIR). |
| `examples/countmin_chain_two.rs` | Side-by-side prove/verify/size comparison on real Count-Min (Phase 3a). |
| `examples/countmin_chain_n.rs` | Recursive chain sweep E ∈ {2, 4, 8} on Count-Min (Phase 3b). |
| `examples/countmin_sweep.rs` | Workload sweep (d, w, batch) on the Count-Min leaf prover (Phase 3c). |
| `examples/countmin_v1_vs_v2.rs` | §5.1 strawman vs §5.4-shaped leaf comparison (Phase 3d). |
| `examples/hll_chain_two.rs` | §4.1 vs §4.2 comparison on HyperLogLog at E=2 (Phase 4c). |
| `examples/hll_chain_n.rs` | HLL recursive chain sweep E ∈ {2, 4, 8} (Phase 4c). |
| `examples/hll_sweep.rs` | HLL `(b, batch)` workload sweep (Phase 4c). |
| `examples/hll_v1_vs_v2.rs` | HLL §5.1 strawman vs §5.4-shaped leaf comparison (Phase 4d). |

## Implementation notes

The Poseidon2 permutation used by the leaf STARK must use the **canonical
hardcoded round constants** (`p3_baby_bear::default_babybear_poseidon2_16`) —
the same constants the recursive verifier circuit hardcodes via
`Poseidon2Config::BABY_BEAR_D4_W16`. An earlier version built the
permutation from a seeded RNG; the resulting constants differed from the
verifier's, the leaf proof's Merkle hashes didn't match what the in-circuit
FRI verifier recomputed, and the §4.2 aggregation tripped a `WitnessConflict`
at the first compared witness. See `src/config.rs::make_perm`.

## Phase 2/3 — Count-Min update epochs

The leaf circuits live in `src/recursion/recursive/`:

- **`countmin_leaf` (Phase 2b/c + 3c)** — §5.1 *strawman*. Each leaf
  takes the d×w cells (private), the batch's `(key, value)` pairs (PIs),
  and per-record hash positions (PIs); constrains a one-hot selector per
  `(record × row)`, then `final = initial + Σ(selector · value)` per
  cell; hashes both states via in-circuit Poseidon2 and connects to the
  `CountMinCommit` PIs. Runtime-parameterised `(d, w, batch)` (Phase 3c).
- **`countmin_leaf_v2` (Phase 3d)** — §5.4-*shaped* variant. Exposes the
  per-cell aggregate table `A` as an explicit witness; the transition
  reads `final = initial + A` rather than computing the sum inline. Same
  `CountMinLeafProof` shape so v2 leaves merge with v1 leaves in the
  §4.2 recursive chain. Today there's no witness reduction (the
  Poseidon2-of-flat-cells commit still forces all d·w cells into the
  witness); the real `O(m·d + T)` win lands by swapping the commit for
  Merkle-tree sparse opens or a homomorphic-additive vector commit, with
  v2's aggregate slot as the seam.

Two leaves chain through `merge_two_countmin` (§4.2 two-leaf merge,
Phase 2c) or `CountMinChainState::extend` (§4.3 recursive chain, Phase
3b). The §4.1 flat baseline lives in `recursion::countmin_flat`. All
three meet at the same `CountMinLeafProof` interface.
