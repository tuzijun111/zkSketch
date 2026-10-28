# What's implemented

This page describes the four original families; the Bloom filter (`src/sketch/bloom_packed.rs`, packed bytes, the default, and the earlier `bloom_omc.rs`) and KMV (`src/sketch/kmv.rs`) leaves, with their decoders in `src/decode/`, follow the same commitment discipline, and the GK leaf's default round certification is the stable-compaction circuit (`EXP_GK_ROUNDS=stable`).

### The four sketch circuits

Each circuit follows the paper's **commitment discipline**: every epoch leaf
takes `(Com(S_{t-1}), Com(B_t), Com(S_t))` as public inputs and, in-circuit,
**opens** the prior state, **binds** the batch input commitment, applies the
update, and **commits** the new state — so the prover cannot tamper with the
records or the state transition.

The **deployed** leaf per family — the one the composition layer instantiates
and the paper measures — is `omc` / `omc` / `certified` / `bandmerge2`:

| Family | Pattern | plonky3 (deployed circuit) | plonky2 (in-circuit leaf) |
| --- | --- | --- | --- |
| **Count-Min** | A (sparse patch) | `src/sketch/countmin_omc.rs` (offline memory checking: `M_old ⊎ W = M_new ⊎ R`) | `plonky2/src/leaf/countmin_final.rs` (+ `countmin_merkle.rs`, Merkle sparse rebind) |
| **HyperLogLog** | A (register max) | `src/sketch/hll_omc.rs` (offline-memory-checked max-update rebind) | `plonky2/src/leaf/hyperloglog.rs` |
| **SpaceSaving** | B (bounded top-`s`) | `src/sketch/ss_final_full.rs` (§G union → sort+seg-group → top-s → replace) | `plonky2/src/leaf/spacesaving.rs` |
| **Greenwald–Khanna** | B (fusion) | `src/sketch/gk_bandmerge.rs` (§5.4 two-sided band-merge: union → value-sort → neighbor-init → threshold → band-merge rounds → compaction) | `plonky2/src/leaf/greenwald_khanna.rs` |

The **baselines** plotted against them in the batch sweep live alongside:
`countmin_final.rs` / `hll_final_full.rs` are the dense `one_hot` replays;
`countmin_merkle.rs` / `hll_merkle.rs` are the Merkle sparse-opening leaves;
`gk_final_full.rs` collapses equal values only (an exact per-value aggregation,
not an approximate-quantile sketch) and is kept as a baseline. Count-Min also
carries side-by-side variants: `countmin_leaf` (§5.1 strawman replay), `_v2`
(§5.4-shaped seam), `_v3` (PermuteAir group-by), `_v9` (private-batch +
in-circuit aggregation), `_v9h` (compact-`G` table that realizes the §5.2
hash-work savings for high-duplicate batches).

> **Prototype commitment caveat.** The deployed leaves commit state as a *flat*
> Poseidon2 hash over all cells, so both states live in the witness and each
> batch pays the `Θ(|S|)` recommit floor the paper accounts for. The
> sublinear-in-`s` path needs a sparse-opening commitment (Merkle / homomorphic
> vector commit); plonky3 already realizes it in `src/sketch/countmin_merkle.rs`
> and `hll_merkle.rs` (the `merkle` variant in the batch sweep), and plonky2 in
> its `countmin_merkle` leaf.

### The §4 composition layer (plonky3)

- **`src/recursion/framework.rs`** — generic §4 machinery: `EpochLeaf` (binds
  `index, com_before, com_after, batch_commit, descriptor`), `merge_atom`,
  `compose_chain` / `compose_tree`, and a **streaming forest** (MMR-shaped) whose
  `root_commitment` is the unified history root `R(t)`.
- **§4.1 flat chains** (`flat.rs`, `countmin_flat.rs`, `hll_flat.rs`) — bundle
  leaf proofs; verifier work `Θ(E)`.
- **§4.2 recursive merge + §4.3 chains** (`recursion/recursive/`) — verify two
  leaf proofs *inside* one batch-STARK; verifier work `O(1)` regardless of `E`.
- **Composition statement + auditor** (`recursion/recursive/{statement,
  expose_forest, expose_forest_gl, root_vk, noop_leaf}.rs`) — the harness
  default is the Interval statement (`ZKSKETCH_STATEMENT`): each leaf exposes
  its batch index and `H(TAG_LEAF, t, Com(B_t))`, the hiding merge enforces
  index adjacency and folds `H(TAG_MERGE, i, h, j, H_L, H_R)`, and the auditor
  pins the root VK derived from public parameters (`root_vk.rs`, from a no-op
  leaf, `noop_leaf.rs`), verifies the STARK, and recomputes the root digest
  from the public batch log under the run's bracketing (forest, chain, or the
  multi-machine forest `dist_forest(t, M)`, so the auditor must know the mode
  and `M`). Leaf proofs the auditor receives directly (per_batch; a one-batch
  stream) are pinned to the leaf VK the same way
  (`verify_leaves_against_log`). The auditor's log check costs `O(T)` native
  hashes per verification (inside the timed verify).
- **`src/recursion/mmr.rs`** — a standalone append-only Merkle Mountain Range
  ("upload log") over the batch input commitments `{Com(B_t)}`: one published
  root, `O(log t)` inclusion proofs, decoupled from the transition proofs.

