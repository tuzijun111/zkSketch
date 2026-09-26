# zkSketch

Research prototype for the paper **"zkSketch: Verifiable and Privacy-Preserving
Sketch-Based Analytics via NIZKs"**: non-interactive, verifiable,
privacy-preserving sketch maintenance built on recursive proofs.

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
>
> **Same security target.** Both backends are parameterized to the same
> **124-bit conjectured FRI security target**, so cross-stack proof sizes and
> verify times compare at parity. plonky3 sets `SECURITY_LEVEL = 124` in
> `src/config.rs`, which derives the query count from the target: at rate `1/4`
> with 15 PoW bits it takes `(124−15)/2 = 54` queries, i.e. `2×54 + 15 = 123`
> conjectured bits (the integer division floors one bit off the target).
> plonky2 is configured by `circuit_config()` in `plonky2/src/config.rs`, which
> **raises** plonky2's stock `standard_recursion_config` from its default
> **100** bits (rate `1/8`, 28 queries, 16 PoW: `3×28 + 16`) to **124** by
> taking the query rounds to 36 (`3×36 + 16`). The stock 100-bit config is
> never used here.

---

## Table of contents

- [Quick start](#quick-start)
- [Prerequisites & build](#prerequisites--build)
- [What's implemented](#whats-implemented)
- [Datasets](#datasets)
- [Running the experiments](#running-the-experiments)  ← the evaluation suite + scripts
  - [Reproducing the paper's results](#reproducing-the-papers-results)  ← every paper command
- [Tests](#tests)
- [Repository layout](#repository-layout)

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

- **plonky3 (root):** stable Rust ≥ 1.88 (edition 2024; `rust-version` in
  `Cargo.toml`). Older toolchains fail inside the Plonky3 dependencies. Install
  Rust with [rustup](https://rustup.rs); distro `rustc` packages are too old. No
  `rust-toolchain.toml` at the root — it builds on whatever stable toolchain is
  active (the paper's numbers used 1.97.1). A C linker is needed
  (`build-essential`).
- **plonky2 (`plonky2/`):** a self-contained Cargo workspace pinned to a dated
  **nightly** (`nightly-2026-05-31`) via `plonky2/rust-toolchain.toml` (rustup
  auto-installs/selects it when you `cd plonky2`). It is fully decoupled from the
  root build.
- **Network on first build:** dependencies are pinned to exact GitHub revisions
  (no crates.io release). Plonky3 core is pinned to one rev; the recursion crates
  come from a fork (`July620/Plonky3_RangeAir`) that adds the extension-degree-
  `D>1` `PermuteAir`, `ExposeAir`, and byte-table `RangeAir` support this project
  needs. Both that fork and Plonky3 core are **public** — no GitHub credentials
  or authentication are required to build.
- **Spurious `failed to authenticate` / `revision … not found` on first build?**
  That is a transient hiccup in cargo's built-in git client (libgit2) on an
  *anonymous* fetch of the public forks — not a real access problem. Re-run
  through the system git CLI, which fetches them reliably:
  `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release` (or set
  `git-fetch-with-cli = true` under a `[net]` table in `.cargo/config.toml`).
- **Optional local fork iteration:** to hack on the recursion fork, copy
  `.cargo/config.toml.example` → `.cargo/config.toml` and point the four
  `p3-{recursion,circuit,circuit-prover,poseidon2-circuit-air}` crates at a local
  clone. This file is git-ignored; without it, a fresh clone builds the fork
  straight from GitHub.
- **Python (experiment plots):** `python3` + `matplotlib` for
  `scripts/plot_eval.py` (the paper's batch-sweep figure) and
  `scripts/plot_experiments.py`; stdlib only for `fetch_datasets.py` /
  `cost_model_e10.py`.
- **External baselines (optional):** the zk-Analytics and zkStream comparisons
  under `scripts/baselines/` need their own toolchains. `scripts/baselines/fetch_baselines.sh`
  clones both systems at the paper's revisions and installs ZoKrates 0.8.8; it
  also prints the RISC Zero (`rzup`, `r0vm` 3.0.6) setup. Both harnesses need
  `curl`, GNU time at `/usr/bin/time` (package `time`), `taskset`, and `python3`
  with `numpy`; zk-Analytics' bindgen needs `libclang` (`libclang-dev`); the
  zkStream drivers need a systemd user session (without a login session:
  `loginctl enable-linger $USER` and `export XDG_RUNTIME_DIR=/run/user/$(id -u)`).
  Use a git clone, not a ZIP download (`sketch_run.sh` exports sources with
  `git archive`). See `scripts/baselines/{zka,zkstream}/README.md`.
- **Paper result CSVs:** `results/` is git-ignored, so a clone has no measured
  CSVs; the commands in [Reproducing the paper's results](#reproducing-the-papers-results)
  regenerate them.
- **Hardware for the paper's runs.** The smoke-test defaults run anywhere, but
  the deployed configuration is memory-hungry and the distributed study needs a
  multi-socket box:
  - **RAM:** peak prover RSS at `m=2^14` is ~17–81 GiB per machine depending on
    the family (Greenwald–Khanna is the worst); an `M=4` forest run needs that
    much *per live machine*. The paper's testbed is a 128-core AMD EPYC 9555
    (4 NUMA nodes, ~2.2 TiB).
  - **`numactl`** (optional but recommended): the `procs` engine pins each
    machine with `numactl --physcpubind --membind`, falling back to `taskset`,
    then to unpinned. Without it the multi-machine timings are noisier.
  - **`EXP_COMPOSE_NODES=0,2`** names NUMA nodes **by index**, and those indices
    are specific to the paper's testbed: it has four nodes across two sockets,
    so `0,2` is one node per socket. The default placement (machine `i` → node
    `i mod n`) spreads machines across nodes but is **socket-unaware** — on that
    same testbed it would put machines 0 and 1 on nodes 0 and 1, i.e. both on
    socket 0, which is the co-residency this knob exists to avoid. An index that
    does not exist on your machine is silently ignored *for that machine*, which
    then takes the default. Read your own `numactl --hardware` and pick one node
    per socket.
  - The `procs` engine refuses to oversubscribe: `machines × cores` must be
    `≤` the CPU count (for staged runs, `wave_size × cores`).

---

## What's implemented

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
python3 scripts/fetch_datasets.py                                   # both, default 2^20-key cap
AOL_MAX_KEYS=1048576 NETFLIX_MAX_KEYS=1048576 python3 scripts/fetch_datasets.py --force  # 2^20
python3 scripts/fetch_datasets.py aol                               # just one
```

The committed real slices are 2²⁰ = 1,048,576 keys each (S³'s data-size axis runs
to 2²⁰–2²³). Note that **dataset size ≠ per-epoch circuit batch**: zkSketch proves
a small batch per epoch and composes epochs, so a larger file means *more epochs*,
not bigger proofs. Both crates read the same `data/` directory.

---

## Running the experiments

The paper's evaluation is produced by exactly
**two** of the surfaces below: `run_experiments.sh e1` (the batch-sweep figure)
and `run_compose.sh` (every table). The others remain live and supported, but no
current paper result depends on them. `run_experiments.sh` runs the relevant
backend(s), merges rows into a combined `results/<exp>.csv` with a `backend`
column, and writes per-backend `env.json` (CPU/RAM/OS/rustc + config);
`run_compose.sh` is **dual-backend** (`EXP_COMPOSE_BACKEND=plonky3|plonky2`),
while `run_stream.sh` and `run_decode.sh` are plonky3-only.

```bash
scripts/run_experiments.sh            # e1 (default), both backends, small slice
EXP_DATASET=aol scripts/run_experiments.sh e1
scripts/run_compose.sh                # real recursive composition (+ mixed queries)
scripts/run_stream.sh                 # whole-stream total prove time
scripts/run_decode.sh                 # decode/query circuits (tests + table)
```

| Surface | What it measures | Backends | Output |
| --- | --- | --- | --- |
| `run_experiments.sh e1` | **the per-family circuit-cost matrix**: family × variant × batch sweep (witness/prove/verify split, proof size, peak RSS), incl. the naive replay baselines and the CM/HLL rebind variants | both | `results/e1_circuit.csv` (rename per run via `EXP_OUT`) | 
| `run_compose.sh` | composition over **real recursive proofs**: 4 families × {per_batch, chain, forest}, cores/machines budgets, multi-machine staging; **mixed updates+queries** via `EXP_COMPOSE_QUERY_EVERY_OPS=Q` | **both** (`EXP_COMPOSE_BACKEND`) | `results/stream_compose.csv`, or `$1`/`EXP_OUT` | 


**`run_experiments.sh` config (the most common; full lists in the script header):**

| Var | Meaning | Default |
| --- | --- | --- |
| `EXP_DATASET` | `uniform` \| `gaussian` \| `zipf` \| `aol` \| `netflix` | `uniform` |
| `EXP_M` | e1 batch sizes. **Comma list only** — unparseable entries (`...`, `16..64`) are dropped *silently*, yielding a short sweep with exit 0 | `4,8,16,32` |
| `EXP_FAMILY` | e1: `all` or comma-list of `cm,gk,hll,ss` | `all` |
| `EXP_{CM,HLL}_VARIANT` | e1 rebind variant: `one_hot` \| `merkle` \| `omc` (+ CM `merkle_fast`/`merkle_gb`/`memcheck`) | `one_hot` |
| `EXP_SS_VARIANT` | e1: `certified` \| `naive` \| `both` | `certified` |
| `EXP_GK_VARIANT` | e1: `bandmerge2` (the **deployed** circuit) \| `bandmerge2_naive` (its replay baseline) \| `certified` \| `naive` \| `bandmerge` \| `both` | `certified` |
| `EXP_D`, `EXP_W` | CM depth `d` / width `w` | `4` / `8` |
| `EXP_HLL_B`, `EXP_SS_CAP`, `EXP_GK_CAP` | HLL precision `b` (registers `2^b`) / SS capacity / GK capacity. Comma-lists. (The `run_compose.sh` surface defaults `EXP_GK_CAP` to `64` instead.) | `4` / `8` / `8` |
| `EXP_OUT` | rename the output CSV so successive runs don't overwrite | per-exp name |
| `EXP_CORES` | e1/plonky3: cores-per-proof pin (distributed-setting knob) | all cores |
| `BACKENDS` | `plonky3` \| `plonky2` \| `both` | `both` |

**`run_compose.sh` config (the surface behind every paper table):**

| Var | Meaning | Default |
| --- | --- | --- |
| `EXP_COMPOSE_BACKEND` | `plonky3` \| `plonky2`. plonky2 takes **single** values for machines/cores, and silently ignores `EXP_COMPOSE_EXEC`, `EXP_COMPOSE_NODES`, `EXP_COMPOSE_WAVE_SIZE`, `EXP_GK_S`, and all three mixed-query knobs | `plonky3` |
| `EXP_COMPOSE_N` | total stream records — integer or `2^k` | `32` |
| `EXP_COMPOSE_BATCHES` | batch sizes `m`, comma-list | `8` |
| `EXP_COMPOSE_FAMILY` | comma-list of `cm,hll,ss,gk`, and the Goldilocks ports `cm_gl,hll_gl,ss_gl,gk_gl` | `cm,hll,ss,gk` |
| `EXP_COMPOSE_MODE` | `per_batch` \| `chain` \| `forest`, comma-list | all three |
| `EXP_COMPOSE_MACHINES` / `_CORES` | machine count / cores per machine, comma-list on plonky3 | `1` / all |
| `EXP_COMPOSE_EXEC` | `procs` (real pinned processes + socket IPC) \| `sim` (projection). **Defaults to `procs` only when machines > 1** — pass it explicitly at `MACHINES=1` to get real process measurements | `procs` iff machines > 1 |
| `EXP_COMPOSE_NODES` | explicit NUMA-node assignment, e.g. `0,2` (one machine per socket) | round-robin |
| `EXP_COMPOSE_WAVE_SIZE` | staged-wave execution: run machines in time-shifted waves of this size (see the paper's staged-wave methodology). **plonky3 BabyBear + `forest` only**, and needs `wave_size < machines`; ignored otherwise | off |
| `EXP_NET_MBPS`, `EXP_NET_RTT_MS` | modeled link for the `comm_model_ms` column (bytes are **measured**) | `200` / `0.2` |
| `EXP_COMPOSE_QUERY_EVERY_OPS` | **mixed operation stream** (the paper's model): every `Q`-th stream *position* is a query. plonky3 only | `0` (off) |
| `EXP_COMPOSE_QUERY_EVERY` | mixed *per-batch* variant: one query after every `k`-th batch. Mutually exclusive with `_OPS`; plonky3 only | `0` (off) |
| `EXP_QUERY_KEY_MODE` | probe key for keyed queries: `first` \| `uniform_stream` \| `hot` \| `absent`. plonky3 only | `first` |
| `EXP_OUT` / `$1` | output name; `results/<name>.csv` (the `.csv` suffix is optional) | `stream_compose.csv` (plonky3) / `stream_compose_p2.csv` (plonky2) |

**Soundness knobs (plonky3, every surface):**

| Var | Meaning | Default |
| --- | --- | --- |
| `ZKSKETCH_BINDING` | binding mode of the circuits that implement it: the Count-Min `omc` and `memcheck` leaves, the HyperLogLog `omc` and `one_hot` (`hll_final_full`) leaves (the `omc` leaves on BabyBear and Goldilocks), the standalone `countmin_merkle` leaf (no runner selects it), the GK band-merge leaves (`bandmerge`, `bandmerge2` on BabyBear and Goldilocks: the in-circuit threshold `θ = ⌊N_t/s⌋`) and the CM/HLL/SpaceSaving/GK decoders (the exposed query statement). CM `one_hot`, CM `merkle`/`merkle_fast`/`merkle_gb` (`countmin_c_merkle`), HLL `merkle`, the GK `bandmerge2_naive` baseline and the SS/GK-group-by update leaves ignore it. Modes: `semantic` (canonical positions, coordinate sort keys, base pins, GK `θ` bound to `N_t`, decoder statements exposed; relies on the fork for coefficient + IV binding), `bound` (adds in-circuit ALU coefficient re-binding and a zero-IV sponge where implemented (CM/HLL) — the fallback for an unfixed fork; the GK/SS circuits build the `semantic` circuit), `legacy` (the pre-fix zkSketch circuits, byte-for-byte against the same fork, for side-by-side cost runs; the merged fork itself changes even the pristine circuits, so `legacy` rows do not reproduce numbers measured at fork rev 19dcb37; **unsound** — only the fork-level fixes still apply; selecting it prints a loud warning to stderr, once per process). Any other value, including a non-UTF-8 one, panics. The variant knobs (`EXP_{CM,HLL}_VARIANT`, `EXP_SS_VARIANT`, `EXP_GK_VARIANT`) are unchanged | `semantic` |
| `ZKSKETCH_STATEMENT` | composition statement the harness leaves expose and the auditor checks (`statement::composition_expose`): `interval` = `(Com(S_{t-1}), Com(S_t), (t, t), H(TAG_LEAF, t, Com(B_t)))` per leaf, folded by the merge atom (index adjacency + merge digest) and checked at the root against the public batch log (`Com(S_0)`, `Com(S_T)`, every `Com(B_t)`) under the run's bracketing; `boundary` = the pre-B6(b) `(Com(S_{i-1}), Com(S_j))` leaves and merges, byte for byte, with a loud warning that the batch log is not checked. `ZKSKETCH_BINDING=legacy` also selects `boundary` unless this is set. Any other value, including a non-UTF-8 one, panics | `interval` |
| `EXP_ROOT_VK` | where the auditor's trusted VK comes from: for a composed (chain/forest, `t >= 2`) root the ROOT VK, and wherever the auditor receives leaf proofs directly (per_batch; a one-batch stream) the LEAF VK, against which each leaf is pinned (commitment + metadata) and STARK-verified by a verifier configured from public parameters before its statement is checked against the log. `derive` = from public parameters only (a no-op leaf, plus the fold's tree shape for a root; `O(log t)` dummy merges outside every timed phase), `self` = the legacy self-pin read from the root itself, with per_batch / lone-leaf proofs not re-verified by the auditor (the provers' self-verify is reported). Under `self` the batch-log check is worthless, since any circuit can expose the log's values (loud warning; side-by-side timing only). Or a path to a postcard `RootVk` file (`dist_compose` only; a per_batch or `t = 1` run expects the leaf VK). Files saved before the Interval statement (B6(b)) hold the Boundary-layout VK and now fail closed: re-derive them. A derivation or file error aborts the run | `derive` |
| `EXP_ROOT_VK_SAVE` | `dist_compose` with `EXP_ROOT_VK=derive`: also write the derived root (or leaf) VK to this path | unset |

`semantic` is only sound on the merged soundness fork (decompose coefficients
bound through `recompose/coeff`, zero IV on every `new_start` sponge row, bound
constants, full top-byte range check). `Cargo.toml` pins that fork
(`July620/Plonky3_RangeAir` @ `fbcc78f`), so a plain clone links it; no
`[patch]` or local fork checkout is needed.
`cargo test --release --lib bind::tests::fork_probe_report -- --nocapture`
prints which of these the linked fork provides.

Earlier modes of the E1–E10 ladder (**e3, e4, e5real, e6, e7, e9, e10, inputfold,
casestudy**) and the RQ1–RQ4 figure track are **retired from the driver** —
each was superseded by one of the surfaces above. Their runners stay in
`examples/` and remain directly runnable via `cargo run --release --example
exp_<name>`.

### Reproducing the paper's results

The exact commands behind each figure/table, at the deployed configuration
(Count-Min `d=7, w=2^14`; HyperLogLog `b=14`; SpaceSaving `s=2^14`;
Greenwald–Khanna `s'=2^11`; `N=2^20` AOL records in `t=64` batches of `m=2^14`;
32 cores/machine). These are **long** runs — the full set is on the order of
days of prover time on the 128-core testbed.

**Figure `fig:eval-batch` — batch-size sweep** (`results/{cm,hll,ss,gk}_batch_*.csv`,
plotted by `scripts/plot_eval.py`). Baselines stop where the padded trace
exceeds the backend's `2^27` FRI domain; those points are recorded as
`status=too_large` and drawn as the infeasibility ✗:

```bash
# Count-Min: one-hot replay / Merkle sparse-opening / deployed memory-checked
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=one_hot \
  EXP_M=16,32,64 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=cm_batch_one_hot.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=merkle \
  EXP_M=16,32,64,128,256,512,1024,2048 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=cm_batch_merkle.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=omc \
  EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=cm_batch_omc.csv scripts/run_experiments.sh e1

# HyperLogLog
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=one_hot \
  EXP_M=16,32,64,128,256,512,1024,2048 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=hll_batch_one_hot.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=merkle \
  EXP_M=16,32,64,128,256,512,1024,2048,4096 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=hll_batch_merkle.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=omc \
  EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=hll_batch_omc.csv scripts/run_experiments.sh e1

# SpaceSaving: per-record replay baseline / deployed certified leaf
EXP_DATASET=aol EXP_FAMILY=ss EXP_SS_CAP=16384 EXP_SS_VARIANT=naive \
  EXP_M=16,32,64,128 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=ss_batch_naive.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=ss EXP_SS_CAP=16384 EXP_SS_VARIANT=certified \
  EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=ss_batch_certified.csv scripts/run_experiments.sh e1

# Greenwald–Khanna: replay baseline / deployed band-merge leaf
EXP_DATASET=aol EXP_FAMILY=gk EXP_GK_CAP=2048 EXP_GK_VARIANT=bandmerge2_naive \
  EXP_M=16,32,64,128,256 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=gk_batch_naive.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=gk EXP_GK_CAP=2048 EXP_GK_VARIANT=bandmerge2 \
  EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=gk_batch_certified.csv scripts/run_experiments.sh e1

python3 scripts/plot_eval.py        # -> results/zkSketch_eval_batch.pdf
```

**The deployed reference run** — one command feeds five artifacts: the forest
column of `tab:compose-schedules`, the `M=1` column of `tab:compose-scale`, the
`2^20` Plonky3 row of `tab:stream-scale`, the AOL column of `tab:eval-datasets`,
and the Plonky3 (BabyBear) rows of `tab:p2-forest`. Run it first:

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky3 \
scripts/run_compose.sh frame_out_1machine_plonky3.csv
```

**Tables `tab:compose-schedules`, `tab:compose-scale` — composition schedules.**
The per-batch chain (the verifier-cost baseline), and the multi-machine forest.
`EXP_COMPOSE_NODES=0,2` puts one machine per socket; `EXP_COMPOSE_WAVE_SIZE=2`
runs `M≥3` in time-shifted waves of two so every machine owns a full socket
(`exec=staged` in the CSV; `M=2` runs concurrently as `exec=procs`):

```bash
# per-batch chain (same 64 leaves, no folds)
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=per_batch \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky3 \
scripts/run_compose.sh frame_out_1machine_plonky3_perbatch.csv

# forest on M = 2, 3, 4 machines (staged waves)
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=2,3,4 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky3 \
EXP_COMPOSE_NODES=0,2 EXP_COMPOSE_WAVE_SIZE=2 \
scripts/run_compose.sh frame_out_staged_m234_plonky3.csv
```

`frame_out_staged_m234_plonky3.csv` holds all 12 rows (4 families × 3 machine
counts); `results/frame_out_{2,3,4}machine_plonky3.csv` are that file split by
machine count. `tab:eval-memory`'s forest column reads the `M=4` rows.

**Table `tab:stream-scale` — stream scaling on both backends.** `k=16..19` only:
the `2^20` row is the deployed reference run above (Plonky3) and the
`frame_out_1machine_plonky2.csv` run below (Plonky2), not a `k=20` sweep point.

```bash
for k in 16 17 18 19; do
  EXP_DATASET=aol \
  EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
  EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
  EXP_COMPOSE_N=2^$k EXP_COMPOSE_BATCHES=16384 \
  EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
  EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
  EXP_COMPOSE_BACKEND=plonky3 \
  scripts/run_compose.sh forest_plonky3_1machine_verify_2e$k.csv
done

for k in 16 17 18 19; do
  EXP_DATASET=aol \
  EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
  EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
  EXP_COMPOSE_N=2^$k EXP_COMPOSE_BATCHES=16384 \
  EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
  EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
  EXP_COMPOSE_BACKEND=plonky2 \
  scripts/run_compose.sh forest_plonky2_1machine_verify_2e$k.csv
done
```

**Table `tab:p2-forest` — cross-backend at stream scale.** The Plonky3
(BabyBear) rows are the reference run above; add the Goldilocks port and Plonky2:

```bash
# Plonky3 over Goldilocks (the *_gl family ports)
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm_gl,hll_gl,ss_gl,gk_gl EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs \
scripts/run_compose.sh frame_out_1machine_Goldilocks.csv

# Plonky2 (Goldilocks)
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky2 \
scripts/run_compose.sh frame_out_1machine_plonky2.csv
```

**Table `tab:mixed` — query-rate sweep.** One query every `Q` stream positions:

```bash
for Q in 1000 10000 100000 1000000; do
  EXP_DATASET=uniform EXP_COMPOSE_N=2^20 EXP_COMPOSE_BATCHES=16384 \
  EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
  EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
  EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
  EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
  EXP_COMPOSE_QUERY_EVERY_OPS="$Q" EXP_QUERY_KEY_MODE=uniform_stream \
  scripts/run_compose.sh s3_plonky3_1machine_mixed_q$Q.csv
done
```



**Table `tab:eval-datasets` — dataset sensitivity.** Three datasets here; the
AOL column is the deployed reference run above:

```bash
EXP_DATASET=uniform,gaussian,netflix EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
scripts/run_compose.sh frame_out_1machine_datasets_plonky3.csv
```

**Where each result lives.** Most tables read `total_time_ms` directly as the
prover time (with leaf-gen `= leafgen_ms` and the fold total `= merge_total_ms`).
Two artifacts derive their columns: `tab:stream-scale` is the only one that
splits wall-clock into setup `+` prove, using
`prove = leaf_busy_max_ms`, `setup = total_time_ms − leaf_busy_max_ms` on
Plonky3 and `prove = leafgen_seq_ms + merge_total_ms`, `setup = total − prove`
on Plonky2; and `tab:mixed`'s amortized per-element cost is
`(total_time_ms + query_prove_ms)/N`.

| Paper artifact | `results/` file(s) |
| --- | --- |
| `fig:eval-batch` | `{cm,hll}_batch_{one_hot,merkle,omc}.csv`, `{ss,gk}_batch_{naive,certified}.csv` (plotted by `scripts/plot_eval.py`) |
| `tab:compose-schedules` | `frame_out_1machine_plonky3_perbatch.csv` (per-batch) + `frame_out_1machine_plonky3.csv` (forest) |
| `tab:compose-scale` | `frame_out_1machine_plonky3.csv` (M=1) + `frame_out_staged_m234_plonky3.csv` (M=2,3,4) |
| `tab:stream-scale` | `forest_plonky{3,2}_1machine_verify_2e{16..19}.csv` + `frame_out_1machine_plonky{3,2}.csv` (the `2^20` row) |
| `tab:mixed` | `s3_plonky3_1machine_mixed_q{1000,10000,100000,1000000}.csv` |
| `tab:eval-datasets` | `frame_out_1machine_datasets_plonky3.csv` + `frame_out_1machine_plonky3.csv` (AOL) |
| `tab:eval-memory` | `{cm,hll}_batch_omc.csv`, `{ss,gk}_batch_certified.csv` at `m=2^14` (leaf) + `frame_out_4machine_plonky3.csv` (forest) |
| `tab:p2-forest` | `frame_out_1machine_plonky3.csv`, `frame_out_1machine_Goldilocks.csv`, `frame_out_1machine_plonky2.csv` |

> **Superseded** (kept for provenance; no current table reads them): the `_old`
> and `_new` suffixes, `forest_plonky3_1machine_verify_2e20.csv`, and the
> pre-rename / M=4-era leftovers `frame_out_1machine.csv`,
> `frame_out_4machine.csv`, `frame_out_4machine_{datasets_plonky3,plonky2,ssgk_Goldilocks}.csv`,
> `s3_mixed_q*.csv` and `s3_plonky3_mixed_q100000.csv`.
>
> **Still live**, despite looking like leftovers: `frame_out_{2,3,4}machine_plonky3_coresident.csv`
> and `frame_out_1machine_plonky3_busysib.csv` are the co-residency controls
> behind the appendix's staged-wave fidelity argument (the ~6% package-sharing
> penalty), produced by `scripts/run_m1_busy_sibling.sh`.

### Standalone comparison demos

Quick side-by-side prove/verify/size demos (no CSV):

```bash
cargo run --release --example chain_two            # §4.1 flat vs §4.2 recursive (toy AIR)
cargo run --release --example countmin_chain_n     # recursive chain sweep E ∈ {2,4,8}
cargo run --release --example countmin_v1_vs_v2    # §5.1 strawman vs §5.4-shaped leaf
cargo run --release --example hll_chain_n          # HLL chain sweep
```

---

## Tests

```bash
cargo test --release                       # plonky3: 524 lib unit tests (+66 #[ignore]d) + tests/ integration
cargo test --release --lib dataset::       # one module
cargo test --release --test two_leaf_hll   # one integration suite
(cd plonky2 && cargo test --release)       # plonky2 backend (nightly auto)
```

Heavy proving-time sweeps are `#[ignore]`d by default; run on demand, e.g.:

```bash
cargo test --release --lib v9h_duplicate_key_compact_sweep -- --ignored --nocapture
```

The `tests/` directory holds the §4 chain/merge end-to-end suites (flat +
recursive, Count-Min + HLL), where each honest two-leaf path is paired with a
mismatched-boundary rejection test. Tamper-rejection (mutated proofs and
public inputs) is covered by the unit tests in `src/`, not by `tests/`.

---

## Repository layout

| Path | What's in it |
| --- | --- |
| `src/config.rs` | BabyBear + Poseidon2 + two-adic FRI `StarkConfig`; `make_perm` = canonical `default_babybear_poseidon2_16`. |
| `src/sketch/` | Plaintext sketches + **complete circuits**. Deployed leaves: `countmin_omc`, `hll_omc`, `ss_final_full`, `gk_bandmerge`. Baselines: `countmin_final`, `hll_final_full`, `gk_final_full`, the `*_merkle` sparse-opening leaves, and the `*_v3/_v9` Count-Min variants. |
| `src/commitment/` | Poseidon2 state commitments per family. |
| `src/recursion/framework.rs` | §4 generic composition (epoch leaves, merge atom, streaming forest, `R(t)`). |
| `src/recursion/recursive/` | §4.2 in-circuit merge + §4.3 chains; leaf circuits (`countmin_leaf{,_v2,_v3,_v9,_v9h}`, `hll_leaf{,_v2}`) + merges; the family-agnostic hiding merge atom (`expose_forest{,_gl}.rs`), the Interval composition statement and its log auditor (`statement.rs`), public-parameter root/leaf VK derivation (`root_vk.rs`, `noop_leaf.rs`), and their end-to-end attack tests (`interval_tests.rs`). |
| `src/recursion/{flat,countmin_flat,hll_flat}.rs` | §4.1 flat chains. |
| `src/recursion/mmr.rs` | Standalone MMR upload-log over `{Com(B_t)}`. |
| `src/dataset.rs` | Synthetic generators + real/synthetic loaders + `gen_synthetic` helpers. |
| `src/experiments/` | Metrics harness + runners: `rq1`–`rq4`, `casestudy`, `e5_ladder`, `e6_forest`, `e7_policy`, `inputfold`, `families`. |
| `examples/` | Experiment runners (`exp_*`), the dataset generator (`gen_synthetic`), and comparison demos. |
| `tests/` | §4 chain/merge integration suites (Count-Min + HLL). |
| `plonky2/` | The SNARK backend: `src/sketch/`, `src/leaf/` (in-circuit leaves + `countmin_merkle`), `src/decode/` (query circuits, E3), `src/recursion/`, `src/metrics.rs`, its own `examples/`. |
| `scripts/` | `run_experiments.sh` (e1/e2/e5/e8 driver), `run_compose.sh` (both backends), `run_stream.sh`, `run_decode.sh`, `plot_eval.py` (the paper's batch-sweep figure), `fetch_datasets.py`; legacy: `plot_experiments.py` (RQ figures), `cost_model_e10.py`. |
| `data/` | Key streams: synthetic (`gaussian/uniform/zipf.keys` + manifest) and real (`aol/netflix.keys`). |
| `docs/` | [`datasets.md`](docs/datasets.md): the dataset recipe, reproducibility model, and materialization. |

---

