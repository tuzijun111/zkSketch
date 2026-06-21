# zkSketch — plonky2 (SNARK) implementation

This directory is the **in-tree plonky2 implementation** of zkSketch, living inside the original
repo (the parent dir, `..`) as a self-contained crate **alongside — not replacing — the original
plonky3 sources**. An identical standalone copy also lives at `../../zkSketch_SNARK`.

It re-implements zkSketch — non-interactive, verifiable, privacy-preserving sketch-based analytics
with recursive proof aggregation.

The original (in `..`) is built on **plonky3 + plonky3-recursion** (recursive **STARKs**
over the BabyBear field). This crate rebuilds the same architecture on **[plonky2]**, whose
first-class recursion is the natural SNARK analog of plonky3-recursion's in-circuit verifier.

> **Build note:** this crate is its own Cargo workspace (`[workspace]` in `Cargo.toml`) and builds
> on **nightly** (plonky2 needs `#![feature(specialization)]`), fully decoupled from the parent's
> stable/plonky3 build. It does inherit the parent's `.cargo/config.toml`, whose plonky3-fork
> `[patch]` entries are unused here — that's the only (harmless) "patch not used" warning at build.

[plonky2]: https://github.com/0xPolygonZero/plonky2

## "STARK vs SNARK" — where plonky2 sits

plonky2 is, like plonky3, a hash-based **FRI** proof system (transparent, post-quantum) — but:

- it is a *succinct non-interactive argument of knowledge* (a SNARK in the general sense), and
- it has **native, cheap recursion** (`CircuitBuilder::verify_proof` verifies a proof *inside*
  a circuit), and
- its proofs can be **wrapped to a pairing-SNARK** (Groth16/PLONK over BN254) for constant-size,
  ~300k-gas on-chain verification.

So this is the recursive-SNARK counterpart of the recursive-STARK original. (For a true
pairing/KZG backend — e.g. halo2-KZG + `snark-verifier`, or a Nova folding scheme — see the
feasibility notes; plonky2 was the requested target here and is the closest drop-in because its
recursion model matches plonky3-recursion's.)

## Architecture — plonky3 → plonky2 mapping

| Concept | `..` (plonky3) | this crate (plonky2) |
| --- | --- | --- |
| Field | BabyBear (31-bit) + degree-4 ext | Goldilocks (64-bit), degree-2 ext |
| Hash / commitment | Poseidon2, width 16 | Poseidon (`PoseidonHash`) |
| Leaf proof | AIR + `uni-stark` | `CircuitBuilder` gate circuit |
| In-circuit verifier (§4.2) | `p3_recursion::build_and_prove_aggregation_layer` | `builder.verify_proof::<C>(…)` |
| State commit | Poseidon2 of packed cells | `commit()` = Poseidon of cells |
| Cell packing | pack 4 cells / ext element (alignment) | **none** — each cell is one field element |

Because Goldilocks is 64-bit, a counter / register is a single field element, so the BabyBear
"pack 4 cells into one extension element (and require `d·w % 4 == 0`)" dance disappears.

## What's implemented

- **Sketches** (`src/sketch/`): all four families — Count-Min (Pattern A linear), HyperLogLog
  (Pattern A max), SpaceSaving (Pattern B top-`s`), and Greenwald–Khanna (Pattern B fusion) —
  plaintext update rules + native Poseidon commitments.
- **Leaves** (`src/leaf/`): in-circuit update epochs.
  - `countmin`: one-hot selector per `(record, row)`, `final = initial + Σ selector·value`, with
    in-circuit Poseidon binding both state commits.
  - `countmin_final`: the §5.2 distinct-key-compacted leaf (sort + group + sparse patch).
  - `hyperloglog`: one-hot selector, and a **sound `max`** via product-of-differences
    (`Π(final − candidate) = 0`, so `final` is *some* candidate) plus range checks
    (`final − candidate ∈ [0, 2^6)`, so `final ≥ every` candidate) ⇒ `final = max`.
  - `spacesaving`: §G top-`s` retention — union → key-group-sum → count-sort → top-`s` split,
    with the grouping tags forced by an `is_zero` gadget (Pattern B needs exact grouping).
  - `greenwald_khanna`: §5.4 quantile fusion — union → value-sort → `⌈log₂(total)⌉` parity-0
    fusion rounds → split. Each round's fuse + resort is a grand-product permutation.
  - The Pattern-B permutations are plonky2 grand-product arguments (`leaf/gadgets.rs`:
    `assert_perm_cols`), the SNARK stand-in for plonky3's `PermuteAir`.
  - `fib`: a toy leaf used to smoke-test the recursion plumbing.
- **Recursion** (`src/recursion/`): sketch-agnostic, everything is a [`Node`].
  - `merge` — §4.2 two-input recursive merge: verifies both children in-circuit, glues the shared
    boundary (`left.final == right.initial`), emits one proof. **O(1) verification.**
  - `flat_verify` — §4.1 baseline: verify each node natively + boundary + digest. **Θ(E).**
  - §4.3 chain — just repeated `merge` of the running root with a new leaf.
  - Leaf and merged nodes share the same first 8 public inputs (`initial[0..4]`, `final[0..4]`),
    so a Count-Min node and an HLL node merge through the *same* code.

The §4.2 boundary/chain **digest** (`leaf_digest` / `combine_digest`, paper §4.2) is tracked
natively and re-derived at verify time — the flat and recursive chains produce the *identical*
root digest.

## Measured (debug build, deps at opt-level 3)

From `cargo run --example countmin_chain` (`d=2, w=4, batch=2`):

```
leaf 1: prove 17.5ms    proof 121556 bytes
§4.1 flat:      verify 2.5ms    (re-verifies every leaf — Θ(E))
§4.2 merge:     prove  177ms    proof 133300 bytes
§4.2 recursive: verify 2.1ms    (one proof — O(1) regardless of E)
§4.3 chain:     root covers leaves (1,3) (E=3),  proof 133300 bytes
```

The recursive proof size is **constant** as `E` grows (133 KB at both E=2 and E=3) and verify is
O(1), while the flat baseline re-verifies every leaf — exactly the paper §4 trade-off.

## Build & run

plonky2 requires **nightly Rust** (it uses `#![feature(specialization)]`); `rust-toolchain.toml`
pins it automatically.

```bash
cargo test                              # full suite (lib + integration), ~30s
cargo run --release --example countmin_chain   # timings / proof sizes
```

## Status / not yet ported

- **All four families now have in-circuit leaves** (Pattern A: Count-Min, HyperLogLog;
  Pattern B: SpaceSaving, Greenwald–Khanna), each with round-trip, two-epoch recursive-merge,
  and wrong-final soundness tests. SS/GK are the faithful counterparts of plonky3's
  `ss_final_full` / `gk_final_full`.
- GK fusion uses the same one-directional eligibility latitude as the plonky3 original
  (`decision ⇒ eligible`; an honest prover fully fuses, matching the native update), and the
  exact value-equality fusion policy (no band-merge of different values).
- The `key → (pos / register_idx, leading_run)` hash relation is exposed as public input but
  checked **natively** (as in the original), not re-derived in-circuit.
- §4.3 `merge` rebuilds a recursion circuit per extension (correct, O(1) verify, but extra prover
  work). A fixed-shape cyclic-recursion (IVC) node would amortize that — a natural next step.
