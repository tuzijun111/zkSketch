# zkSketch Framework — Verifiable Streaming Sketch Maintenance (paper §4)

This document describes the **proof-orchestration layer** of zkSketch — the
techniques in the paper's §4 *"zkSketch Framework: Verifiable Streaming
Sketch Maintenance"* — how they're implemented, and the explicit tests you
can run for **each** technique (the same accept-/reject-test discipline we
use for the four sketch circuits).

The framework sits *above* the per-family update circuits of §5 (the four
sketches). It is **sketch-agnostic**: it composes per-epoch transition
proofs into one auditable root, whether the leaves are Count-Min, GK, HLL,
or SpaceSaving.

For the per-sketch update circuits themselves, see
[`docs/countmin.md`](countmin.md) (Count-Min) and the module docs of
`gk_final_full`, `hll_final_full`, `ss_final_full`.

---

## Table of contents

1. [Where the code lives](#where-the-code-lives)
2. [The four techniques at a glance](#the-four-techniques-at-a-glance)
3. [§4.1 Per-epoch transition-proof chain](#41-per-epoch-transition-proof-chain)
4. [§4.2 Interval proofs + the merge atom](#42-interval-proofs--the-merge-atom)
5. [§4.3 Composition topologies](#43-composition-topologies)
   - [(a) Linear chain](#a-linear-chain)
   - [(b) Balanced binary tree](#b-balanced-binary-tree)
   - [(c) Streaming forest (cascade)](#c-streaming-forest-cascade)
6. [Root `R(t)` and the verifier interface](#root-rt-and-the-verifier-interface)
7. [Realization model & soundness](#realization-model--soundness)
8. [Composing real sketch leaves (end-to-end)](#composing-real-sketch-leaves-end-to-end)
9. [Tests — one command per technique](#tests--one-command-per-technique)
10. [The four sketch circuits the framework composes](#the-four-sketch-circuits-the-framework-composes)

---

## Where the code lives

| Concern | File |
| ------- | ---- |
| **Generic §4 framework** (all techniques below) | `src/recursion/framework.rs` |
| Ordered-epoch digest `H[i,j] = H(i,m,j,·,·)` | `src/recursion/digest.rs` |
| Count-Min-specific merge atom / chain (real STARK proofs) | `src/recursion/recursive/countmin_merge.rs`, `countmin_chain.rs` |
| HLL-specific merge / chain | `src/recursion/recursive/hll_merge.rs`, `hll_chain.rs` |
| §4.1 *flat* chain (Θ(E) verifier baseline) | `src/recursion/flat.rs`, `countmin_flat.rs`, `hll_flat.rs` |

`framework.rs` is the **generic, sketch-agnostic** realization; the
`recursive::*` modules are the older per-sketch realizations that carry the
actual leaf STARK proofs for Count-Min/HLL. The generic layer operates on
the public **boundary** of each leaf (`(index, Com(S_{i-1}), C_{B_i},
Com(S_i), D_i)`), which is what the four `*_final[_full]` leaves expose.

---

## The four techniques at a glance

```
                          §4.1  per-epoch leaves  π_1 … π_E
                                (each: Com(S_{i-1}) --B_i--> Com(S_i))
                                          │  lift_leaf
                                          ▼
                          §4.2  interval proofs Π[i,j] + merge_atom
                                          │  scheduled by …
              ┌───────────────────────────┼───────────────────────────┐
        §4.3(a) linear chain        §4.3(b) balanced tree       §4.3(c) streaming forest
        compose_chain               compose_tree                StreamingForest::insert/finalize
              └───────────────────────────┼───────────────────────────┘
                                          ▼
                          Root R(t) = H(1,t,Com(S_0),Com(S_t),H[1,t],M)
                                root_commitment  (O(1) verifier digest)
```

All three topologies share the **same merge atom**; they differ only in the
*schedule* of merges (and therefore in latency/parallelism trade-offs).

---

## §4.1 Per-epoch transition-proof chain

Each closed epoch `B_i` produces a leaf with public boundary
`(D_i, Com(S_{i-1}), C_{B_i}, Com(S_i), M)` (this is exactly what each
`*_final[_full]` prover returns: `initial`, `final_`, `batch_commit`).
Consecutive leaves are **chained** through their boundary commitments:
leaf `i`'s output `Com(S_i)` must equal leaf `i+1`'s input.

- Type: `EpochLeaf { index, com_before, com_after, batch_commit, descriptor }`
- Direct verifier: `verify_epoch_chain(&[EpochLeaf], start_index)` — checks
  contiguity (`index` runs `start, start+1, …`) and boundary agreement
  (`leaf[k].com_after == leaf[k+1].com_before`). This is the **Θ(E)** verifier
  §4.2 then collapses.

## §4.2 Interval proofs + the merge atom

An `IntervalProof Π[lo,hi]` certifies `Com(S_{lo-1}) → Com(S_hi)` and carries
the order-binding digest `H[lo,hi]`.

- `lift_leaf(&EpochLeaf) -> IntervalProof` — a single-epoch interval `Π[j,j]`
  with `H[j,j] = H(j, D_j, C_{b_j}, Com(S_{j-1}), Com(S_j))` (`epoch_leaf_digest`).
- `merge_atom(left, right) -> Result<IntervalProof>` — composes two
  **adjacent** intervals. It enforces:
  1. **contiguity** `left.hi + 1 == right.lo` (else `NonAdjacent`),
  2. **shared boundary** `left.com_after == right.com_before` — the
     absorbed `Com(S_m)` (else `BoundaryMismatch`),
  3. **order-binding** `H[i,j] = H(i, m, j, H[i,m], H[m+1,j])` via
     `combine_digest`.

  The parent exposes only the outer boundary `(Com(S_{lo-1}), Com(S_hi))`;
  the join `Com(S_m)` is absorbed.

## §4.3 Composition topologies

Three *schedules* over the same merge atom.

### (a) Linear chain

`compose_chain(&[EpochLeaf]) -> IntervalProof` — fold the merge atom
left-to-right (the accumulating root: `Π(t) = merge(Π(t-1), Π[t,t])`).
`O(1)` ready root, sequential. Same digest shape as `countmin_chain`.

### (b) Balanced binary tree

`compose_tree(&[EpochLeaf]) -> IntervalProof` — for a **power-of-two**
history, merge disjoint subtrees level by level (`⌈log₂E⌉` depth). Parallel
across cores; the natural choice for windowed batch processing. Returns
`NotPowerOfTwo(n)` otherwise.

### (c) Streaming forest (cascade)

`StreamingForest` — for a live stream of unknown length `t`, hold a forest of
perfect subtrees whose sizes are the set bits of `t` (Bentley–Saxe /
Merkle-Mountain-Range layout). `insert(&EpochLeaf)` appends a size-1 leaf on
the right and runs a **binary-counter cascade** (merge equal-sized
neighbours); `finalize()` chains the `ℓ ≤ ⌈log₂(t+1)⌉` surviving roots into
one `Π[1,t]` on demand.

- `num_trees()` `== popcount(t)`; `root_sizes()` are strictly decreasing
  powers of two. E.g. at `t = 11 = 8+2+1` the forest holds roots of sizes
  `[8, 2, 1]`.

## Root `R(t)` and the verifier interface

`root_commitment(&IntervalProof) -> R(t) = H(1, t, Com(S_0), Com(S_t),
H[1,t], M)` — the `O(1)`-size digest published with `Π(t)`. The verifier
recomputes `R(t)` from the interval proof's exposed boundary (and, in a full
recursive backend, verifies `Π(t)` itself). Tampering any epoch's batch
commitment or boundary changes `H[1,t]` and hence `R(t)`.

## Realization model & soundness

The per-family leaves of §5 **self-verify their STARK proof at creation**.
This framework layer adds the *composition soundness* §4 is about:

- **contiguity + ordering** (epoch indices form a gap-free run),
- **boundary agreement** (the absorbed `Com(S_m)` matches on both sides),
- **order-binding** via the recursive digest.

The merge digest is **shape-dependent** — it encodes the split `m`, exactly
as the paper's `H(i,m,j,·,·)` does — so the chain and the balanced tree
produce *different* digests for the same history (they record different
schedules) but certify the **same outer boundary** `Com(S_0) → Com(S_t)`.
The verifier recomputes the digest by replaying the agreed topology. A
re-ordered, dropped, or tampered epoch breaks a boundary and/or changes the
digest, so it is rejected (see the reject-tests below).

> Note on full recursion: a production deployment runs the SNARK verifier
> *in-circuit* in the merge atom (true recursive composition). The generic
> `framework` module above verifies each leaf proof natively and binds the
> composition via the boundary + digest checks — the paper's "option (i)"
> lifting (`view Π[j,j] as π_j presented with its public record`). The
> §4.3 topologies are identical either way. The **recursive** realization of
> option (ii) — every merge recursively verifies its children inside one
> aggregation proof — is implemented for Count-Min v9 in
> `recursion::recursive::countmin_forest_v9` (see next section).

## §4.3(c) realized recursively — `countmin_forest_v9`

`framework::StreamingForest` composes per-epoch *digests*. The module
`recursion::recursive::countmin_forest_v9` composes the actual STARK proofs
in the **same** Bentley–Saxe/MMR schedule: `prove_countmin_forest_v9(&[leaf])`
runs a binary-counter cascade where each merge is one
`build_and_prove_aggregation_layer` call that **recursively verifies both
children in-circuit**, so the single root proof recursively verifies *all*
leaves. The cascade folds `agg+agg` (≥ 4 leaves) and `agg+leaf` (e.g. 3
leaves) — the `agg+agg` case the linear `countmin_chain` never exercises.

**Verified property — the root folds the intermediates away.** An aggregation
proof's public inputs are FRI proof-structure values *only*, fixed by the FRI
config and independent of how many leaves are underneath
(`recursion::recursive::tests::probe_aggregation_public_inputs` measures this:
a leaf's own boundary value is provably *absent* from the parent's public
inputs). So the per-epoch state commitments `Com(S_i)` are **not** exposed,
and the root proof is `O(1)`. Measured (`forest_root_size_does_not_grow_with_leaves`):

| epochs `E` | root recursive-proof size |
| ---------- | ------------------------- |
| 4          | ~486 KB                   |
| 8          | ~486 KB                   |

Doubling the history leaves the root proof flat — the root only verifies its
two direct children, never the whole history. This is the literal "single
proof over the intermediates, folded away" property at the proof level.

In `countmin_forest_v9` the outer boundaries `Com(S_0)` / `Com(S_E)` and the
tree-schedule digest are carried alongside the proof and checked natively at
`O(1)` (`verify_forest_countmin_v9` replays the cascade to recompute the
digest). The **in-circuit** binding of those outer boundaries is realized
separately — see the next section.

## In-circuit boundary binding — `expose_forest`

`recursion::recursive::expose_forest` closes the last gap: a recursive
streaming forest whose **single root proof's public values are exactly
`(Com(S_0), Com(S_E))`, bound in-circuit** — intermediates neither exposed nor
natively trusted, contiguity enforced by the proof itself.

The enabling primitive is a new **"Expose" non-primitive op** (in the
recursion fork): the only NPO whose AIR declares `num_public_values() > 0` and
whose table prover sets `BatchTableInstance.public_values`. It binds
`public_value == trace_cell == witness` and surfaces those values as the
proof's recursion `air_public_targets` — the one channel that carries an
application value from a verified child into the parent's public statement.
(Primitive `public_input()` values are bound by trace verification but are
*not* re-exposed to a verifying parent — verified by
`tests::probe_aggregation_public_inputs`.)

On that primitive:

- **Leaf** (`prove_boundary_leaf`) surfaces its `(Com_before, Com_after)` via
  `add_expose`.
- **Hiding merge** (`prove_hiding_merge`) recursively verifies both children,
  reads their surfaced boundaries as `air_public_targets`, binds
  `left.final == right.initial` in-circuit, repacks (recompose) the outer
  boundary to stay `O(1)`, and re-exposes only `(left.initial, right.final)`.
- **Forest** (`prove_bound_forest`) runs the Bentley–Saxe cascade over hiding
  merges; the root surfaces exactly `(Com(S_0), Com(S_E))`, read with
  `read_exposed_boundary`.

Tests (`expose_forest::tests`): a known value surfaces through aggregation
(vs. provably absent for a primitive public input); a 2-leaf merge exposes
*only* the outer boundary and verifies; a non-contiguous history is rejected
*in-circuit* (the merge proof can't be produced); a 4-leaf forest (exercising
`agg+agg`) yields a root exposing only `(Com(S_0), Com(S_4))`.

**Real Count-Min.** `prove_countmin_leaf_v9_exposed_with_params` is the v9
Count-Min leaf with the boundary `add_expose` added (behind a flag, so the
unexposed v9 baseline is unchanged). Test
`real_v9_bound_forest_exposes_outer_boundary` composes two such leaves —
proving actual Count-Min updates — through the hiding merge; the root surfaces
only the real `(Com(S_0), Com(S_2))`. So the bound forest runs over genuine
sketch transitions, not just the minimal boundary-claim leaf.

## Composing real sketch leaves (end-to-end)

`framework_composes_real_gk_history` builds a real 4-epoch GK history with
the complete §5.4 circuit (`gk_final_full::prove_gk_full`), lifts each
transition proof into an `EpochLeaf`, and composes it through **all three**
topologies — asserting every topology certifies the same `Com(S_0) →
Com(S_4)` and that those equal the natively-recomputed state commitments.
This is the framework wired end-to-end over a per-family circuit; swapping
in `ss_final_full` / `hll_final_full` / `countmin_final` leaves works the
same way (each exposes `initial` / `final_` / `batch_commit`).

## Tests — one command per technique

All framework tests live in `src/recursion/framework.rs` and run in
milliseconds (the pure-composition ones use synthetic commitments; the
end-to-end one builds real GK proofs).

```bash
# Everything at once
cargo test --release --lib recursion::framework

# §4.1 per-epoch chain  (accept + reject boundary break + reject reorder)
cargo test --release --lib recursion::framework::tests::epoch_chain_

# §4.2 merge atom  (compose + reject non-adjacent + reject boundary mismatch)
cargo test --release --lib recursion::framework::tests::merge_atom_

# §4.3(a) linear chain
cargo test --release --lib recursion::framework::tests::chain_

# §4.3(b) balanced binary tree
cargo test --release --lib recursion::framework::tests::tree_
cargo test --release --lib recursion::framework::tests::chain_and_tree_agree_on_boundary

# §4.3(c) streaming forest  (cascade + finalize + pow2-matches-tree + reject out-of-order)
cargo test --release --lib recursion::framework::tests::forest_

# Root R(t)  (binds history + verifier recompute detects tamper)
cargo test --release --lib recursion::framework::tests::root_

# End-to-end: real GK §5.4 leaves composed via all three topologies
cargo test --release --lib framework_composes_real_gk_history
```

| Technique | Accept test | Reject (soundness) test |
| --------- | ----------- | ----------------------- |
| §4.1 epoch chain | `epoch_chain_accepts_valid_history` | `epoch_chain_rejects_boundary_break`, `epoch_chain_rejects_reorder` |
| §4.2 merge atom | `merge_atom_composes_adjacent` | `merge_atom_rejects_non_adjacent`, `merge_atom_rejects_boundary_mismatch` |
| §4.3(a) chain | `chain_composes_to_root` | `chain_rejects_reordered_history` |
| §4.3(b) tree | `tree_composes_power_of_two` | `tree_rejects_non_power_of_two` |
| §4.3(c) forest | `forest_cascade_tracks_binary_counter`, `forest_finalizes_to_single_root`, `forest_power_of_two_matches_tree_boundary` | `forest_rejects_out_of_order_insert` |
| Root `R(t)` | `root_commitment_binds_history` | `root_verifier_recompute_detects_tamper` |
| End-to-end | `framework_composes_real_gk_history` | — |

## The four sketch circuits the framework composes

Each produces a per-epoch transition proof whose `(initial, final_,
batch_commit)` boundary lifts directly into an `EpochLeaf`:

| Sketch | Complete circuit | Leaf prover | Tests |
| ------ | ---------------- | ----------- | ----- |
| Count-Min (§5.2) | `sketch::countmin_final` / `recursion::recursive::countmin_leaf_v9h` | `prove_countmin_leaf_v9h_with_params` | `cargo test --release --lib countmin_final` |
| Greenwald–Khanna (§5.4) | `sketch::gk_final_full` | `prove_gk_full` / `prove_gk_full_with_rounds` | `cargo test --release --lib gk_full` |
| HyperLogLog (App F) | `sketch::hll_final_full` | `prove_hll_full` | `cargo test --release --lib hll_full_` |
| SpaceSaving (App G) | `sketch::ss_final_full` | `prove_ss_full` | `cargo test --release --lib ss_full_` |

Each of these has the same accept / soundness-reject / proving-time test
shape; see their module docs for the per-circuit details.
