# zkSketch

Research prototype for the paper **"zkSketch: Verifiable and Privacy-Preserving
Sketch-Based Analytics via NIZKs"** (`paper/zkSketch.pdf`, `latex/zk1.tex`):
non-interactive, verifiable, privacy-preserving sketch maintenance built on
recursive proofs.

Four sketch families (Count-Min, HyperLogLog, SpaceSaving, Greenwald–Khanna) are
implemented end-to-end on **two interchangeable proof backends**, so prove time,
verify time, and proof size can be compared head-to-head:

| Backend | Crate | Proof system | Field / hash | Toolchain |
| --- | --- | --- | --- | --- |
| **plonky3** (this repo root) | `zksketch` | recursive **STARK** (batch-STARK + in-circuit FRI verifier) | BabyBear (31-bit) + Poseidon2 | stable |
| **plonky2** (`plonky2/`) | `zksketch_snark` | recursive **SNARK** (native `verify_proof`) | Goldilocks (64-bit) + Poseidon | nightly (auto) |

> **No trusted setup.** Both backends are transparent, hash-based **FRI** systems
> — there is no SRS, no powers-of-tau, no toxic waste (unlike Halo2-KZG). The only
> one-time artifact is circuit preprocessing (the AIR/`StarkConfig` on plonky3, the
> `CircuitData` on plonky2), built in code; nothing needs to be generated once and
> reloaded.

---

## Table of contents

- [Quick start](#quick-start)
- [Prerequisites & build](#prerequisites--build)
- [What's implemented](#whats-implemented)
- [Datasets](#datasets)
- [Running the experiments](#running-the-experiments)  ← the evaluation suite + scripts
- [Tests](#tests)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)

---

## Quick start

```bash
# Build the plonky3 (STARK) backend. Release is essential — the recursive
# prover is ~50× slower in debug. First build pulls pinned Plonky3 + fork
# crates from GitHub (a few minutes); subsequent builds are warm.
cargo build --release

# Run the full plonky3 test suite (library unit tests + tests/ integration).
cargo test --release

# Build/test the plonky2 (SNARK) backend (auto-selects nightly via its
# rust-toolchain.toml — no manual switch needed).
cd plonky2 && cargo test --release && cd ..

# Materialize the deterministic synthetic datasets (committed; regenerable).
cargo run --release --example gen_synthetic

# Run an evaluation experiment on both backends (see "Running the experiments").
scripts/run_experiments.sh e1
```

---

## Prerequisites & build

- **plonky3 (root):** stable Rust ≥ 1.85 (edition 2024). No `rust-toolchain.toml`
  at the root — it builds on whatever stable toolchain is active.
- **plonky2 (`plonky2/`):** a self-contained Cargo workspace pinned to **nightly**
  via `plonky2/rust-toolchain.toml` (rustup auto-installs/selects it when you `cd
  plonky2`). It is fully decoupled from the root build.
- **Network on first build:** dependencies are pinned to exact GitHub revisions
  (no crates.io release). Plonky3 core is pinned to one rev; the recursion crates
  come from a fork (`tuzijun111/Plonky3_Permute`) that adds extension-degree-`D>1`
  `PermuteAir` support this project needs.
- **Optional local fork iteration:** to hack on the recursion fork, copy
  `.cargo/config.toml.example` → `.cargo/config.toml` and point the four
  `p3-{recursion,circuit,circuit-prover,poseidon2-circuit-air}` crates at a local
  clone. This file is git-ignored; without it, a fresh clone builds the fork
  straight from GitHub.
- **Python (experiments plots):** `python3` + `matplotlib` for
  `scripts/plot_experiments.py`; stdlib only for `fetch_datasets.py` /
  `cost_model_e10.py`.

---

## What's implemented

### The four sketch circuits

Each circuit follows the paper's **commitment discipline**: every epoch leaf
takes `(Com(S_{t-1}), Com(B_t), Com(S_t))` as public inputs and, in-circuit,
**opens** the prior state, **binds** the batch input commitment, applies the
update, and **commits** the new state — so the prover cannot tamper with the
records or the state transition.

| Family | Pattern | plonky3 (complete circuit) | plonky2 (in-circuit leaf) |
| --- | --- | --- | --- |
| **Count-Min** | A (sparse patch) | `src/sketch/countmin_final.rs` (§5.2 database-style: group-by → counter-derive → counter-group → sparse patch) | `plonky2/src/leaf/countmin_final.rs` (+ `countmin_merkle.rs`, Merkle sparse rebind) |
| **HyperLogLog** | A (register max) | `src/sketch/hll_final_full.rs` | `plonky2/src/leaf/hyperloglog.rs` |
| **SpaceSaving** | B (bounded top-`s`) | `src/sketch/ss_final_full.rs` (§G union → sort+seg-group → top-s → replace) | `plonky2/src/leaf/spacesaving.rs` |
| **Greenwald–Khanna** | B (fusion) | `src/sketch/gk_final_full.rs` (§5.4 union → sort → L-round fusion → compaction → threshold) | `plonky2/src/leaf/greenwald_khanna.rs` |

Count-Min has several side-by-side leaf variants kept as baselines (see
[`docs/countmin.md`](docs/countmin.md)): `countmin_leaf` (§5.1 strawman replay),
`_v2` (§5.4-shaped seam), `_v3` (PermuteAir group-by), `_v9` (private-batch +
in-circuit aggregation), `_v9h` (compact-`G` table that realizes the §5.2
hash-work savings for high-duplicate batches).

> **Prototype commitment caveat.** The state commitment is a *flat* Poseidon2
> hash over all cells, so both states live in the witness. The paper's
> sublinear-in-`s` cost needs a sparse-opening commitment (Merkle / homomorphic
> vector commit) — the plonky2 `countmin_merkle` leaf demonstrates that path;
> the variant seams (`_v2`/`_v9h`) are where it drops in on plonky3.

### The §4 composition layer (plonky3)

- **`src/recursion/framework.rs`** — generic §4 machinery: `EpochLeaf` (binds
  `index, com_before, com_after, batch_commit, descriptor`), `merge_atom`,
  `compose_chain` / `compose_tree`, and a **streaming forest** (MMR-shaped) whose
  `root_commitment` is the unified history root `R(t)`.
- **§4.1 flat chains** (`flat.rs`, `countmin_flat.rs`, `hll_flat.rs`) — bundle
  leaf proofs; verifier work `Θ(E)`.
- **§4.2 recursive merge + §4.3 chains** (`recursion/recursive/`) — verify two
  leaf proofs *inside* one batch-STARK; verifier work `O(1)` regardless of `E`.
- **`src/recursion/mmr.rs`** — a standalone append-only Merkle Mountain Range
  ("upload log") over the batch input commitments `{Com(B_t)}`: one published
  root, `O(log t)` inclusion proofs, decoupled from the transition proofs.

---

## Datasets

All datasets are 32-bit key streams in the domain `[2³²]`, stored as flat
**little-endian `u32`** files (`file_len / 4` keys) under `data/`. Key derivation
matches S³ (the Streaming-MPC reference, `alibaba-edu/mpc4j`) so inputs are
comparable. See [`docs/datasets.md`](docs/datasets.md).

| Dataset | Kind | Source / recipe | File |
| --- | --- | --- | --- |
| `gaussian` | synthetic | μ=2³¹, σ=2¹³ (seed 1) | `data/gaussian.keys` |
| `uniform` | synthetic | uniform over `[0,2³²)` (seed 2) | `data/uniform.keys` |
| `zipf` | synthetic | α=1.0, universe 2¹⁶ (seed 1) | `data/zipf.keys` |
| `aol` | real | AOL search log → `CRC32(normalized ClickURL) & 2³²−1` | `data/aol.keys` |
| `netflix` | real | Netflix-Prize → first integer (CustomerID) `& 2³²−1` | `data/netflix.keys` |

**Synthetic data is deterministic and regenerable** — the generators in
`src/dataset.rs` are seeded, and `examples/gen_synthetic.rs` freezes them
byte-for-byte (provenance in `data/synthetic.manifest.json`):

```bash
cargo run --release --example gen_synthetic                    # 200k keys/file (default)
GEN_SYNTH_N=1048576 cargo run --release --example gen_synthetic # 2^20 keys/file
```

Freezing matters because the Gaussian/Zipf path uses libm transcendentals whose
last-ULP rounding can differ across platforms; the frozen files give byte-exact
cross-machine reproduction (Uniform is pure-integer and portable regardless).
Unlike mpc4j — which ships **no** datasets and seeds synthetic data with an
*unseeded* `Random` — our streams are fully reproducible.

**Real data** is processed by the fetch script (streamed and capped, so only a
small prefix of the multi-hundred-MB corpora is pulled):

```bash
python3 scripts/fetch_datasets.py                                   # both, default 1M-key cap
AOL_MAX_KEYS=1048576 NETFLIX_MAX_KEYS=1048576 python3 scripts/fetch_datasets.py --force  # 2^20
python3 scripts/fetch_datasets.py aol                               # just one
```

The committed real slices are 2²⁰ = 1,048,576 keys each (S³'s data-size axis runs
to 2²⁰–2²³). Note that **dataset size ≠ per-epoch circuit batch**: zkSketch proves
a small batch per epoch and composes epochs, so a larger file means *more epochs*,
not bigger proofs. Both crates read the same `data/` directory.

---

## Running the experiments

The evaluation suite (`latex/EVAL_SPEC.md`) is **E1–E10 + inputfold**. The driver
runs the relevant backend(s), merges rows into a combined `results/<exp>.csv` with
a `backend` column, and writes per-backend `env.json` (CPU/RAM/OS/rustc + config).

```bash
scripts/run_experiments.sh            # E1 (default), both backends, small slice
scripts/run_experiments.sh e2         # by name: e1 e2 e3 e4 e5 e6 e7 e8 e9 e10 inputfold
EXP_DATASET=aol scripts/run_experiments.sh e1
BACKENDS=plonky2 scripts/run_experiments.sh e8
```

| Exp | What it measures | Backends | Command | Output |
| --- | --- | --- | --- | --- |
| **E1** | per-family circuit cost (witness/prove/verify split, proof size, peak RSS) | both | `run_experiments.sh e1` | `results/e1_circuit.csv` |
| **E2** | integrity: tamper-rejection + fidelity vs. plaintext | both | `run_experiments.sh e2` | `results/e2_integrity.csv` |
| **E3** | decode / query cost vs. state size `s` (all 4 families) | both | `run_experiments.sh e3` | `results/e3_decode.csv` |
| **E4** | scalability sweeps (certified Count-Min) | plonky3 | `run_experiments.sh e4` | `results/e4_scaling.csv` |
| **E5** | composition ladder — verifier cost flat vs. recursive | plonky3 | `run_experiments.sh e5` | `results/e5_ladder.csv` |
| **E6** | streaming forest: cores × batch size | plonky3 | `run_experiments.sh e6` | `results/e6_forest.csv` |
| **E7** | maintenance policy × query rate | plonky3 | `run_experiments.sh e7` | `results/e7_policy.csv` |
| **E8** | cross-stack head-to-head (plonky2 vs plonky3) | both | `run_experiments.sh e8` | `results/e8_crossstack.csv` |
| **E9** | optimisation ablations | plonky3 | `run_experiments.sh e9` | `results/e9_optim.csv` |
| **E10** | cost-model validation (post-processes E1/E3/E4 CSVs) | — | `run_experiments.sh e10` | console report |
| **inputfold** | input-commitment binding + history-fold into `R(t)` + MMR ULog over real `Com(B_t)` | plonky3 | `run_experiments.sh inputfold` | `results/input_fold.csv` |
| **casestudy** | AOL/Netflix end-to-end: ingest + audit + tamper across all four families | plonky3 | `run_experiments.sh casestudy` | `results/casestudy_{ingest,audit}.csv` |

**Config (env vars, forwarded to the runners):**

| Var | Meaning | Default |
| --- | --- | --- |
| `EXP_DATASET` | `uniform` \| `gaussian` \| `zipf` \| `aol` \| `netflix` | `uniform` |
| `EXP_M` | E1 batch sizes (CSV, e.g. `4,8,16,32`); E2 single batch | `4,8,16,32` / `16` |
| `EXP_TRIALS` / `EXP_WARMUP` | measured trials / warm-ups for median+p95 | `5` / `1` |
| `EXP_TAMPER_TRIALS` | E2 tamper trials | `50` |
| `BACKENDS` | `plonky3` \| `plonky2` \| `both` | `both` |

### Figures (RQ panels)

A second track maps to the paper's RQ figures. Run the RQ runners, then render:

```bash
cargo run --release --example exp_rq1   # … exp_rq2, exp_rq3, exp_rq4, exp_casestudy
python3 scripts/plot_experiments.py     # → results/figures/*.pdf (+ .png)
python3 scripts/plot_experiments.py rq2a rq4ab   # just some panels
```

### Standalone comparison demos

Quick side-by-side prove/verify/size demos (no CSV):

```bash
cargo run --release --example chain_two            # §4.1 flat vs §4.2 recursive (toy AIR)
cargo run --release --example countmin_chain_n     # recursive chain sweep E ∈ {2,4,8}
cargo run --release --example countmin_v1_vs_v2    # §5.1 strawman vs §5.4-shaped leaf
cargo run --release --example hll_chain_n          # HLL chain sweep
cargo run --release --example exp_inputfold        # input-commit + fold + MMR over real batches
```

Full per-experiment details, expected output, and the partial-vs-whole-dataset
guidance live in [`docs/REPRODUCE.md`](docs/REPRODUCE.md).

---

## Tests

```bash
cargo test --release                       # plonky3: ~200 lib unit tests + tests/ integration
cargo test --release --lib dataset::       # one module
cargo test --release --test two_leaf_hll   # one integration suite
(cd plonky2 && cargo test --release)       # plonky2 backend (nightly auto)
```

Heavy proving-time sweeps are `#[ignore]`d by default; run on demand, e.g.:

```bash
cargo test --release --lib v9h_duplicate_key_compact_sweep -- --ignored --nocapture
```

The `tests/` directory holds the §4 chain/merge end-to-end suites (flat +
recursive, Count-Min + HLL). Negative tests (tampered proofs, mismatched
boundaries) accompany every honest path.

---

## Repository layout

| Path | What's in it |
| --- | --- |
| `src/config.rs` | BabyBear + Poseidon2 + two-adic FRI `StarkConfig`; `make_perm` = canonical `default_babybear_poseidon2_16`. |
| `src/sketch/` | Plaintext sketches + **complete circuits**: `countmin_final`, `hll_final_full`, `ss_final_full`, `gk_final_full` (+ `*_v3/_v9` Count-Min variants). |
| `src/commitment/` | Poseidon2 state commitments per family. |
| `src/recursion/framework.rs` | §4 generic composition (epoch leaves, merge atom, streaming forest, `R(t)`). |
| `src/recursion/recursive/` | §4.2 in-circuit merge + §4.3 chains; leaf circuits (`countmin_leaf{,_v2,_v3,_v9,_v9h}`, `hll_leaf{,_v2}`) + merges. |
| `src/recursion/{flat,countmin_flat,hll_flat}.rs` | §4.1 flat chains. |
| `src/recursion/mmr.rs` | Standalone MMR upload-log over `{Com(B_t)}`. |
| `src/dataset.rs` | Synthetic generators + real/synthetic loaders + `gen_synthetic` helpers. |
| `src/experiments/` | Metrics harness + runners: `rq1`–`rq4`, `casestudy`, `e5_ladder`, `e6_forest`, `e7_policy`, `inputfold`, `families`. |
| `examples/` | Experiment runners (`exp_*`), the dataset generator (`gen_synthetic`), and comparison demos. |
| `tests/` | §4 chain/merge integration suites (Count-Min + HLL). |
| `plonky2/` | The SNARK backend: `src/sketch/`, `src/leaf/` (in-circuit leaves + `countmin_merkle`), `src/decode/` (query circuits, E3), `src/recursion/`, `src/metrics.rs`, its own `examples/`. |
| `scripts/` | `run_experiments.sh`, `fetch_datasets.py`, `plot_experiments.py`, `cost_model_e10.py`. |
| `data/` | Key streams: synthetic (`gaussian/uniform/zipf.keys` + manifest) and real (`aol/netflix.keys`). |
| `docs/` | Documentation (see below). |
| `paper/`, `latex/` | Paper PDF + `zk1.tex` source and `EVAL_SPEC.md`. |

---

## Documentation

| Doc | Contents |
| --- | --- |
| [`docs/REPRODUCE.md`](docs/REPRODUCE.md) | End-to-end reproduction recipe: every experiment's command, config, expected output, partial-vs-whole dataset. |
| [`docs/EVALUATION.md`](docs/EVALUATION.md) | RQ → figure mapping and how the plots are produced. |
| [`docs/datasets.md`](docs/datasets.md) | Dataset recipe (S³-matched), reproducibility model, materialization. |
| [`docs/framework.md`](docs/framework.md) | The §4 composition framework (chain / merge atom / streaming forest). |
| [`docs/countmin.md`](docs/countmin.md) | Count-Min circuit variants (v1 → v9h) and the §5.2 design. |
| [`docs/EXPERIMENTS.md`](docs/EXPERIMENTS.md) | Phase-by-phase build log with measured numbers and gotchas. |

`latex/EVAL_SPEC.md` is the authoritative evaluation spec (metrics, trial counts,
E1–E10 definitions).
