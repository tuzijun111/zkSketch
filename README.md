# zkSketch

Research prototype for the paper **"zkSketch: Verifiable and Privacy-Preserving
Sketch-Based Analytics via NIZKs"**: non-interactive, verifiable,
privacy-preserving sketch maintenance built on recursive proofs.

Four sketch families (Count-Min, HyperLogLog, SpaceSaving, Greenwald–Khanna) are
implemented end-to-end on **two interchangeable proof backends**, so prove time,
verify time, and proof size can be compared head-to-head (Bloom and KMV circuits,
plonky3 only, join them in the [six-sketch comparison with
zk-Analytics](#reproducing-the-zksketch-vs-zk-analytics-comparison-six-sketches-one-machine)):

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
- [Reproducing the zkSketch vs zk-Analytics comparison (six sketches, one machine)](#reproducing-the-zksketch-vs-zk-analytics-comparison-six-sketches-one-machine)  ← clone, check, build, quick, full
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
  (no crates.io release). Plonky3 core comes from a fork (`tuzijun111/Plonky3`,
  branch `zk-logup-mask`: the zero-knowledge LogUp masks); the recursion crates
  come from a fork (`tuzijun111/Plonky3_RangeAir`, branch `zk-logup-mask`) that
  adds the extension-degree-`D>1` `PermuteAir`, `ExposeAir`, byte-table
  `RangeAir` and in-circuit mask support this project needs; the plonky2 backend
  uses `tuzijun111/plonky2` (branch `zk-blinding-fix`). All three forks are
  **public** — no GitHub credentials or authentication are required to build.
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
- **Zero knowledge (on by default).** The default `zk` Cargo feature proves
  every plonky3 leaf, merge, root and query proof with the hiding PCS
  (`HidingFriPcs` over the plain Merkle MMCS, mask RNG `ZkRng`: OS-seeded,
  reseeded on every clone) and masks the LogUp sums the proofs reveal. A proof
  reveals one LogUp sum per *global interaction* (several per table); unmasked,
  each is a deterministic function of the witness and of challenges anyone can
  replay, so a verifier could test witness guesses against it. Under `zk`
  each global interaction gets an extension-field mask, zero-sum per bus,
  stored as 4 constant main columns (2 on Goldilocks) and committed before
  the lookup challenges; the revealed sums are then uniform subject to the
  per-bus zero sum (`tests/zk_logup_blinding.rs` runs the guess-and-check
  replay: no candidate matches under `zk`, the true one does without it).
  This needs the `zk-logup-mask` branches of the Plonky3 core fork
  (`tuzijun111/Plonky3` @ `280b1a0`) and of `tuzijun111/Plonky3_RangeAir`
  (@ `e11b1a6`); `Cargo.toml` pins both, so a plain clone builds them.
  The default build refuses to compile without them: `src/config.rs` names
  one fork-only item of each fork outside any test, so a `zk` build against
  the unforked pins fails (library, binaries, examples and tests) instead of
  proving with unmasked sums. Every `env.json` and every `exp_compose` /
  `exp_e0` CSV row records `pcs` (`hiding` / `nonhiding`) and `logup_mask`
  (`on` / `off`); `commit` is only the state-commitment mode.
  `--no-default-features` builds the non-hiding PCS, whose proofs and VKs are
  byte-identical to the unmasked builds, and still builds against the
  upstream pins; use it to reproduce stored non-ZK numbers. The VK pin tests
  carry one table per build; the `zk` tables pin the hiding PCS's VKs, which
  the masks do not change (a leaf or decoder VK commits only preprocessed
  data; the masks are main-trace columns). The masks are checked by
  `config::tests::leaf_opens_logup_mask_columns` (opened main width = AIR
  width + 4 per global interaction) and `tests/zk_logup_blinding.rs`; they do
  change every merge and root circuit, hence every derived root VK.
  - *Hiding budget (precondition):* a randomized column stays hidden only if
    its table is taller than what the verifier learns about it,
    `2(q + 2D) = 2(54 + 8) = 124` rows here; every table of every
    circuit-prover proof (all sketch leaves, merges, roots and decoders) is
    padded to at least 512 (`TablePacking::with_fri_params(6, LOG_BLOWUP)`),
    the fork's prover refuses a ZK proof below 128 rows, and a `const`
    assertion plus `config::tests::hiding_budget_*` keep the two in step.
    Lowering `log_final_poly_len`, `LOG_BLOWUP` or the security level must
    re-check it. The exception is the Phase-1 toy `FibAir` leaf
    (`prover::prove_fib_leaf`, a plain uni-stark proof used only by tests and
    the `chain_two` example, 16-64 rows): it is below the budget and is not
    claimed to hide anything.
  - *Cost:* small at the leaf, large in the recursion layer, because every
    merge re-verifies masked proofs in-circuit (measured masked vs unmasked
    hiding builds; details in `src/config.rs`, "Cost of the masks"). Leaf
    prove time +9-11%, proof +5-6%. The in-circuit verifier grows ~14%, which
    pushes the L1 merge's ALU table past 2^17 rows for all four families
    (also over paper-geometry m = 4096 children), so that table doubles: one
    CM merge proves in 5.7 s instead of 3.8 s. A small composed run (forest,
    N = 32, m = 8, 16 cores) takes +40% (CM) / +55% (HLL) wall time and +46%
    peak RSS; at the six-sketch comparison shape (m = 2,048, t = 8), +16% /
    +18%. Stored `zk` numbers measured before the masks (`zk2_*`) understate
    the cost.
  - *Still public, or only heuristic:* table heights (operation and batch
    counts); every Expose / NPO public value; with `ZKSKETCH_COMMIT=plain`, the
    unsalted state and batch commitments (statement-level guess-and-check).
    Upstream calls `HidingFriPcs` only statistically zero-knowledge; the
    plain-MMCS (unsalted Merkle leaves) argument and the LogUp masking are our
    own constructions, argued in `src/config.rs`, not upstream guarantees. All
    of this is the plonky3 backend; the plonky2 backend (`plonky2/`) is not
    covered by it.
- **Python (experiment plots):** `python3` + `matplotlib` for
  `scripts/plot_eval.py` (the paper's batch-sweep figure) and
  `scripts/plot_experiments.py`; stdlib only for `fetch_datasets.py` /
  `cost_model_e10.py`.
- **External baselines (optional):** the six-sketch zkSketch vs zk-Analytics
  comparison has its own short prerequisite list and a single entry point; see
  [Reproducing the zkSketch vs zk-Analytics comparison](#reproducing-the-zksketch-vs-zk-analytics-comparison-six-sketches-one-machine).
  The other zk-Analytics and zkStream experiments under `scripts/baselines/` need
  more: `scripts/baselines/fetch_baselines.sh` clones both systems at the paper's
  revisions, installs ZoKrates 0.8.8 and prints the RISC Zero (`rzup`, `r0vm`
  3.0.6) setup. Those harnesses need `curl`, GNU time at `/usr/bin/time` (package
  `time`), `taskset`, and `python3` with `numpy`; zk-Analytics' `bench_queries`
  build (`a234.sh`, `compare.sh`) compiles RocksDB through bindgen and needs
  `libclang` (`libclang-dev`) and, with GCC >= 13, `CXXFLAGS='-include cstdint'`;
  set `LIBCLANG_PATH` (the directory of `libclang.so`) or
  `BINDGEN_EXTRA_CLANG_ARGS=-I$(gcc -print-file-name=include)` only if bindgen
  cannot find libclang or `stddef.h` (`native_baseline` needs none of this); the zkStream drivers
  need a systemd user session (without a login session: `loginctl enable-linger
  $USER` and `export XDG_RUNTIME_DIR=/run/user/$(id -u)`). Use a git clone, not a
  ZIP download (`sketch_run.sh` exports sources with `git archive`). See
  `scripts/baselines/{zka,zkstream}/README.md`.
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
| `EXP_COMPOSE_FAMILY` | comma-list of `cm,hll,ss,gk`, the opt-in BabyBear-only `bloom` (`EXP_BLOOM_K`, `EXP_BLOOM_LOGW`) and `kmv` (KMV / bottom-`k` distinct count, capacity `EXP_KMV_K`, default `1024`: a multiple of 4 in `4..=32768` with `k + m < 2^24`, a bad value exits 2), and the Goldilocks ports `cm_gl,hll_gl,ss_gl,gk_gl` | `cm,hll,ss,gk` |
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
| `ZKSKETCH_BINDING` | binding mode of the circuits that implement it: the Count-Min `omc` and `memcheck` leaves, the HyperLogLog `omc` and `one_hot` (`hll_final_full`) leaves (the `omc` leaves on BabyBear and Goldilocks), the standalone `countmin_merkle` leaf (no runner selects it), the GK band-merge leaves (`bandmerge`, `bandmerge2` on BabyBear and Goldilocks: the in-circuit threshold `θ = ⌊N_t/s⌋`) and the CM/HLL/SpaceSaving/GK decoders (the exposed query statement), and the KMV `kmv` leaf and decoder (`semantic` / `bound` only: there is no pre-fix KMV circuit, so `legacy` builds the `semantic` KMV leaf and decoder and a `legacy` KMV row reports the `semantic` cost; the `exp_compose` CSV has no binding column, so the row does not show this). CM `one_hot`, CM `merkle`/`merkle_fast`/`merkle_gb` (`countmin_c_merkle`), HLL `merkle`, the GK `bandmerge2_naive` baseline and the SS/GK-group-by update leaves ignore it. Modes: `semantic` (canonical positions, coordinate sort keys, base pins, GK `θ` bound to `N_t`, decoder statements exposed; relies on the fork for coefficient + IV binding), `bound` (adds in-circuit ALU coefficient re-binding and a zero-IV sponge where implemented (CM/HLL) — the fallback for an unfixed fork; the GK/SS circuits build the `semantic` circuit), `legacy` (the pre-fix zkSketch circuits, byte-for-byte against the same fork, for side-by-side cost runs; the merged fork itself changes even the pristine circuits, so `legacy` rows do not reproduce numbers measured at fork rev 19dcb37; **unsound** — only the fork-level fixes still apply; selecting it prints a loud warning to stderr, once per process). Any other value, including a non-UTF-8 one, panics. The variant knobs (`EXP_{CM,HLL}_VARIANT`, `EXP_SS_VARIANT`, `EXP_GK_VARIANT`) are unchanged | `semantic` |
| `ZKSKETCH_STATEMENT` | composition statement the harness leaves expose and the auditor checks (`statement::composition_expose`): `interval` = `(Com(S_{t-1}), Com(S_t), (t, t), H(TAG_LEAF, t, Com(B_t)))` per leaf, folded by the merge atom (index adjacency + merge digest) and checked at the root against the public batch log (`Com(S_0)`, `Com(S_T)`, every `Com(B_t)`) under the run's bracketing; `boundary` = the pre-B6(b) `(Com(S_{i-1}), Com(S_j))` leaves and merges, byte for byte, with a loud warning that the batch log is not checked. `ZKSKETCH_BINDING=legacy` also selects `boundary` unless this is set. Any other value, including a non-UTF-8 one, panics | `interval` |
| `ZKSKETCH_COMMIT` | state / batch commitment mode (revision B2, `commitment::hiding`), read once per run by `exp_compose` (both engines, every family including the Bloom filter `bloom`, commitment family id 5, and the KMV sketch `kmv`, family id 6), `exp_decode` and the deployed `exp_e1` variants (cm `omc`, hll `omc`, ss `certified`, gk `bandmerge2`; every baseline stays plain): `hiding` = every published `Com(S_t)` (`t ≥ 1`) and `Com(B_t)` absorbs a secret per-version randomizer derived from the prover's salt seed (leaf `t` opens with `Openings::for_leaf(seed, family, t)` at its global batch index; query-sealed and padded batches are real leaves; a query at version `t` opens `Com(S_t; ρ_t)`); the batch log is built prover-side, and the auditor takes only that log, the proofs and public parameters (it recomputes the genesis `Com(S_0; 0)` itself); in the mixed workload each query proof is pinned to the decoder VK of the run's mode (derived from public parameters: the empty state under the public zero salt) and its exposed salted `Com(S_t')` is bound to the prefix certificate checked against that published log (`query_bind_ms`); `plain` = the pre-B2 circuits, commitments and VKs byte for byte. The mode (never the seed) lands in the `exp_compose` CSV `commit` column, in the `exp_e1` CSV `commit` column (per row: the run's mode for the deployed variants, `plain` for every baseline and for the plonky2 leg) and in env.json. `exp_stream` (`run_stream.sh`) proves plain leaves only: it records `commit=plain` and refuses an explicit `hiding`. The external-baseline scripts (`scripts/baselines/zka/compare.sh`, `our_query.sh`, `scripts/baselines/zkstream/run_ours.sh`) pin `plain` (the mode of their stored comparison rows) unless `ZKSKETCH_COMMIT` is set, and write hiding runs to `*_hiding.csv` files. With `ZKSKETCH_BINDING=legacy` and this unset, `plain`. Any other value, including a non-UTF-8 one, panics. The randomizers are hidden only by the zero-knowledge PCS (B1, the default `zk` build); a `--no-default-features` build can still reveal them through its openings | `hiding` |
| `ZKSKETCH_SALT_SEED` | under `ZKSKETCH_COMMIT=hiding`: the prover's 256-bit salt seed as exactly 64 hex characters, for reproducible runs; unset or empty = drawn from the OS RNG. PROVER-side only: never printed or logged (a malformed value panics without echoing it); the distributed engine ships it to its own worker processes inside the task message, never to the auditor. The `salt_seed` CSV column / env.json key records its source (`env` / `os`; `n/a` under `plain`). Every stream is the seed's genesis history, so reuse a seed only for reproducibility, not across deployments | OS RNG |
| `EXP_ROOT_VK` | where the auditor's trusted VK comes from: for a composed (chain/forest, `t >= 2`) root the ROOT VK, and wherever the auditor receives leaf proofs directly (per_batch; a one-batch stream) the LEAF VK, against which each leaf is pinned (commitment + metadata) and STARK-verified by a verifier configured from public parameters before its statement is checked against the log. `derive` = from public parameters only (a no-op leaf, plus the fold's tree shape for a root; `O(log t)` dummy merges outside every timed phase), `self` = the legacy self-pin read from the root itself, with per_batch / lone-leaf proofs not re-verified by the auditor (the provers' self-verify is reported). Under `self` the batch-log check is worthless, since any circuit can expose the log's values (loud warning; side-by-side timing only). Or a path to a postcard `RootVk` file (`dist_compose` only; a per_batch or `t = 1` run expects the leaf VK). Files saved before the Interval statement (B6(b)) hold the Boundary-layout VK and now fail closed: re-derive them. A derivation or file error aborts the run | `derive` |
| `EXP_ROOT_VK_SAVE` | `dist_compose` with `EXP_ROOT_VK=derive`: also write the derived root (or leaf) VK to this path | unset |

`semantic` is only sound on the merged soundness fork (decompose coefficients
bound through `recompose/coeff`, zero IV on every `new_start` sponge row, bound
constants, full top-byte range check). `Cargo.toml` pins that fork
(`tuzijun111/Plonky3_RangeAir` @ `e11b1a6`, branch `zk-logup-mask`, which
also carries the LogUp masks, over the Plonky3 core fork `tuzijun111/Plonky3`
@ `280b1a0`), so a plain clone links it; no `[patch]` or local fork checkout is
needed.
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

## Reproducing the zkSketch vs zk-Analytics comparison (six sketches, one machine)

**What it measures.** zkSketch against zk-Analytics (Zhu et al., "Zero-Knowledge
Cloud Analytics", SIGCOMM '26; a RISC Zero zkVM pipeline, cloned at `d4a5a9a`) on
six sketches: Count-Min (3 x 1024), HyperLogLog (b = 14), SpaceSaving / Misra-Gries
(1,024 counters), Greenwald-Khanna (eps = 1/51), Bloom (7 x 2^14) and KMV
(k = 1,024), over the same AOL records (`data/aol.keys`, tracked in git, so there is
nothing to download). zk-Analytics ships only Count-Min. **For the other five
sketches the zk-Analytics side is our plain textbook per-record code inside their
per-epoch RISC Zero pipeline (marked † in every table), not zk-Analytics code.**
Per sketch it reports update proving (per epoch and for the whole stream), query
proving after n = 1, 2, 4, 8 epochs, the verifier's work and bytes to accept one
answer, peak memory, and answers vs exact. Both systems run on the same machine, one
job at a time. zkSketch runs its default build, which is zero-knowledge
(`pcs=hiding`, `logup_mask=on` in its CSV rows); RISC Zero's succinct receipts are
zero-knowledge too.

**Machine.** Linux x86_64 with glibc >= 2.34 and the libstdc++ of GCC >= 12 (Ubuntu 22.04+,
Debian 12+, Fedora 37+; NOT RHEL / Rocky / Alma 9 or Amazon Linux 2023, whose GCC 11
libstdc++ cannot run RISC Zero's compiler; `check` tests this); at least
16 GiB RAM for `quick`, and for `full` at least 96 GiB (128 GiB recommended: its
zkSketch GK run peaks at 59 GiB; `check` accepts 15 / 90 GiB of `MemTotal`, which is
what 16 / 96 GiB machines report); about 30 GB of free disk (zk-Analytics builds
~13 GB, `~/.risc0` ~1.8 GB, the Rust toolchain and cargo cache ~1 GB, zkSketch's
`target/` ~0.3 GB; a fresh install measured about 16 GB in all). The paper
configuration runs zkSketch on 32 physical cores; on a smaller machine it uses the
physical cores there are (`SIX_CORES`). The reference numbers come from an AMD
Threadripper PRO 9975WX (32 cores / 64 threads).

**Prerequisites**, once per machine (`run_all.sh check` verifies all of them and
prints the fix for anything missing):

```bash
# 1. System packages (the only step that needs sudo; numactl is optional).
sudo apt-get update
sudo apt-get install -y build-essential git curl ca-certificates python3 procps util-linux numactl
#    (Fedora 37+: sudo dnf install -y gcc gcc-c++ make git curl ca-certificates python3 procps-ng util-linux numactl)
# 2. Rust via rustup (distro rustc packages are too old), pinned to the reference
#    toolchain 1.97.1. Any stable >= 1.90 builds (1.99.0 is tested too); with rustup
#    already installed, `rustup toolchain install 1.97.1 --profile minimal && rustup default 1.97.1`.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.1
. "$HOME/.cargo/env"
# 3. RISC Zero at the exact versions used (the installer needs rustc from step 2 on PATH).
curl -L https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$PATH"
rzup install rust 1.97.0    # guest toolchain
rzup install r0vm 3.0.6     # prover; the drivers link risc0-zkvm 3.0.6 and accept r0vm 3.0.x only
rzup default rust 1.97.0    # the guests build with rzup's DEFAULT rust. rzup 0.5.0's `install` already makes
rzup default r0vm 3.0.6     # the version the default (also when it was installed before); these two lines are a
                            # safeguard for other rzup versions
```

Tested with rzup 0.5.0 (the installer fetches the latest rzup; `check` reads its
`settings.toml`). The machine needs outbound HTTPS to github.com, crates.io /
static.crates.io, sh.rustup.rs / static.rust-lang.org and risczero.com. Of
`build-essential`, only a C compiler (`cc`) is actually used.

Not needed here: clang / libclang, cmake, protoc, OpenSSL headers, numpy, GNU time,
Docker, the rzup `cpp` toolchain, the plonky2 nightly. Without sudo, steps 2 and 3
are per-user anyway; you then need `cc`, `git`, `curl` and `python3` (>= 3.8,
standard library only) on PATH.

**Run**, from a fresh clone (the scripts work from any directory). If the
repository is private (it is as of 2026-10-12), `git clone` needs your GitHub
credentials: run `gh auth login` first (then `gh repo clone tuzijun111/zkSketch`), clone over SSH
(`git clone git@github.com:tuzijun111/zkSketch.git`), or give a personal access token
as the HTTPS password. Nothing else needs credentials: zk-Analytics and the pinned
Plonky3 / plonky2 forks are public.

```bash
git clone https://github.com/tuzijun111/zkSketch.git
cd zkSketch
scripts/baselines/zka/six/run_all.sh check    # OK / WARN / MISSING per item; exit 1 if anything blocks
scripts/baselines/zka/six/run_all.sh build    # clone zk-Analytics @ d4a5a9a into ~/ext-baselines; build both sides
scripts/baselines/zka/six/run_all.sh quick    # smoke test of the whole pipeline at tiny scale
scripts/baselines/zka/six/run_all.sh full     # the paper configuration
```

`run_all.sh assemble <results dir>` re-runs only the tables of a finished run;
`run_all.sh` alone prints the usage. Build in the clone's final location: `exp_compose`
records the repository path at compile time, so after moving or renaming the clone run
`run_all.sh build` again.

What success looks like: `check` ends with `check: ok`; `build` prints about 20 Rust
compiler warnings for the zkSketch library, which are harmless, and ends with every
step `ok`; `quick` exits with status 0 and its last line is `quick: OK in ...`, with
the speedup tables just above it. With `GATE_WAIT_S=0` (the `quick` default) the
`gate failed for <job>: ... -- running anyway` lines are expected, not errors.

| step | what it does | time | peak RAM | disk |
|---|---|---|---|---|
| `check` | tools and versions, RAM, cores, disk, dataset, builds | seconds | - | - |
| `build` | clones zk-Analytics (5 MB); builds the 6 zk-Analytics-side drivers (their CM; our † ports) and zkSketch's `exp_compose` | about 7-8 min on the 32-core reference machine, including the first-time download of crates, the pinned forks and zk-Analytics (a cold build with an empty cargo cache took 7 min 16 s: the six zk-Analytics-side drivers 5 min 10 s, `exp_compose` 2 min 5 s); much faster when nothing changed | 1.8 GB for `exp_compose` (zk-Analytics side not measured) | ~13 GB under `$BASELINE_DIR/build`, ~0.3 GB in `target/` |
| `quick` | zkSketch: 7 runs at N = 512 (2 batches of 256). zk-Analytics: executor for all six, 3 real proofs (`kmv:aggr:0`, `gk:query:1:<v>`, `bloom:query:1:key:<k>`), the other 23 planned jobs ESTIMATED | about 8 min here (zkSketch 6.5-7 min, zk-Analytics executor 5 s, the 3 proofs 1 min) | ~9.2 GiB (one r0vm proof; zkSketch runs up to 8.5 GiB) | < 1 MB |
| `full` | zkSketch: 7 runs at N = 16,384 (8 batches of 2,048). zk-Analytics: executor, then 40 proofs (aggregation epochs 0 and 7 of every family; queries at n = 1, 2, 4, 8; Bloom with an inserted and an absent key) | about 3-3.5 h of running: in the reference run zkSketch's 7 runs took ~10 min (non-ZK build; the default ZK build is slower: GK alone took 14 min here, and the 7 runs are estimated at 30-40 min, see Notes), the zk-Analytics executor ~1 min and the 40 proofs 2 h 25 min; plus the quiet-machine waits (1 h 17 min there; see Notes) | zkSketch GK run 59 GiB (ZK build; see Notes); r0vm ~9.2 GiB per proof; one job at a time | < 100 MB |

`full --dry-run` prints the plan, including the 40 zk-Analytics jobs, and runs
nothing. Times are for the 32-core machine above.

**Outputs.** Every `quick` / `full` writes a fresh, git-ignored directory
`results/six/<mode>-<YYYYmmdd-HHMMSS>/`; the run prints its path and the speedup
tables at the end.

- `six_sketch_table.md`: all tables, in this order: update proving (per epoch, and
  for the whole stream including zkSketch's merges), proof bytes on the update side,
  query proving at each n, the verifier's work and bytes to accept one answer at each
  n, peak RSS, the answers next to the exact ones, and the zk-Analytics guest
  profile. `ratio` = zk-Analytics time / zkSketch time, so above 1 means zkSketch is
  faster. The console summary at the end of a run shows the update-side and
  query-proving tables.
- `six_sketch_comparison.csv`: one row per (family, system, operation);
  `provenance` says measured, sampled, derived or ESTIMATED, and `detail` says how.
- `manifest.txt` (configuration, commits, tool versions, per-step times),
  `run_all.log` (the console), and the raw files: zkSketch
  `six_zksketch_<tag>.csv/.log` and `six_zksketch_runs.csv`; zk-Analytics
  `six_zka_<family>_exec.csv` + `six_zka_exec.log` (executor),
  `six_zka_<family>_prove.csv/.log` (proved families only) + `six_zka_jobs.csv`,
  `six_zka_prof_{ss,gk}.csv` + `six_zka_prof.log` (guest profile), `zka_plan.txt`,
  and in `quick` also `six_zka_<family>_qexec.csv`, `six_zka_qexec.log`,
  `six_zka_qexec_jobs.csv` (the cycle counts behind the estimates). Per-batch proofs
  go to a `work/` scratch subdirectory that is deleted after each zkSketch run.
  Outside the results directory, each zkSketch run also (over)writes
  `results/env.json` at the repository root (exp_compose's machine snapshot;
  git-ignored).

`quick` checks the pipeline end to end; it is not a measurement. With 2 batches of
256 records its costs and ratios differ from `full`, and its `est` cells are the
executor's padded cycle count x the seconds per 2^20 padded cycles of that run's 3
proofs. Over the 40 proofs of the reference run this model gave between 5% below and
9% above the measured time for proofs of at least 2^19 padded cycles, and 19-37% below
for proofs of at most 2^18 (fixed overhead).

**Knobs** (environment variables):

| variable | default | meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | zk-Analytics clone and its builds (~13 GB) |
| `RESULTS` | `results/six/<mode>-<stamp>` | output directory; must be new or empty |
| `SIX_CORES` | physical cores, at most 32 | cores of zkSketch's prover process, pinned to CPUs 0 .. SIX_CORES-1 |
| `GATE_WAIT_S` | `quick` 0, `full` 1800 | seconds each timed job waits for a quiet machine; then it runs anyway and its row records the load |
| `GATE_MAX_LOAD`, `GATE_MAX_BUSY` | CPUs / 8 (2 below 16 CPUs), 4 | "quiet": 1-minute load <= `GATE_MAX_LOAD`, fewer than `GATE_MAX_BUSY` busy cores, and no `r0vm`, `exp_compose`, `cargo` or `rustc` of any user |
| `SIX_QUICK_PROVE` | `kmv:aggr:0,gk:query:1,bloom:query:1:key` | the jobs `quick` proves for real |
| `SIX_ALLOW_STALE` | unset | `1` lets `quick` / `full` use binaries older than their sources (see Notes) |
| `TMPDIR` | `/tmp` | zkSketch's worker runs from a copy there and binds a unix socket: it must allow exec and be at most 60 characters long, else the scripts use `/tmp` |
| `EXP_VERIFY_REPEATS` | 5 | how often each zkSketch query proof and prefix certificate is verified (logged as `QLOG_VERIFY` / `QLOG_BINDV`); the tables report the best, as for the zk-Analytics drivers' 5 calls |
| `RISC0_HOME` | `~/.risc0` | where rzup installed RISC Zero (rzup's own variable); the scripts put its `bin/` on `PATH` |

Notes:

- Use an otherwise idle machine: all times are wall-clock. With the default gate,
  `full` lets the load settle before each of its 47 timed jobs (30-180 s each on a
  quiet machine, about 1 h 17 min in all in the reference run; up to 30 min per job on a
  busy one). On an otherwise idle machine that wait is the previous job's own load
  decaying out of the 1-minute average. `GATE_WAIT_S=0` never waits; that is why `quick`
  rows often record `gate=busy:load1=...` even on an idle machine.
- `full` takes hours: start it so that it survives a closed terminal, e.g. inside
  `tmux` / `screen`, or `nohup scripts/baselines/zka/six/run_all.sh full > full.out 2>&1 &`
  (the console is also saved in the results directory as `run_all.log`).
- Ctrl-C stops the running job together with its child processes (each job runs in
  its own process group) and exits; nothing else is touched. A failed zkSketch run
  stops `quick` at once; in `full` the remaining zkSketch runs still execute, then
  `full` stops before the zk-Analytics side. A failed zk-Analytics proof stops
  `quick`, while `full` carries on with the other proofs, shows `-` for the failed one
  and exits 1. A failed zk-Analytics executor step (`run_zka.sh exec`) stops `full`
  before any proof; fix it and start `full` again.
- To finish a `full` run whose zk-Analytics proofs failed or were interrupted, without
  starting over: prove the jobs of its `zka_plan.txt` that have no `rc=0` line in its
  `six_zka_jobs.csv` yet (`run_zka.sh prove` takes any number of jobs and appends to
  the run's files), then rebuild the tables. From the repository root:

  ```bash
  D=results/six/full-YYYYmmdd-HHMMSS     # that run's directory
  RESULTS=$D scripts/baselines/zka/six/run_zka.sh prove \
    $(grep -vxFf <(awk -F, 'NR > 1 && $13 == 0 {print $1}' "$D/six_zka_jobs.csv" 2>/dev/null) "$D/zka_plan.txt")
  scripts/baselines/zka/six/run_all.sh assemble "$D"
  ```

  If it stopped before its first proof (no `six_zka_jobs.csv` yet), also re-run
  `RESULTS=$D scripts/baselines/zka/six/prof_exec.sh` first. Without a `zka_plan.txt`
  (it stopped during the zkSketch runs or the executor), start `full` again.
- `quick` and `full` refuse to run with binaries older than their sources (`check`
  warns): re-run `run_all.sh build` after pulling changes or editing sources, or when
  reusing a `BASELINE_DIR` built from an older checkout (it is much faster when cargo
  has little to recompile). `SIX_ALLOW_STALE=1` skips the check.
- After switching the Rust toolchain, `run_all.sh build` recompiles everything next
  to the old artifacts (another ~13 GB; `check` does not notice a toolchain switch,
  and the old builds stay usable). To reclaim the space, delete the old builds first,
  from the repository root: `rm -rf ~/ext-baselines/build/{cyc-t1,hll,zka-ss,zka-gk,zka-bloom,zka-kmv} target`
  (with `BASELINE_DIR` set, use that instead of `~/ext-baselines`).
- If cargo fails to fetch the pinned Plonky3 forks (`failed to authenticate`), retry
  with `CARGO_NET_GIT_FETCH_WITH_CLI=true scripts/baselines/zka/six/run_all.sh build`
  (see "Prerequisites & build").
- zkSketch's worker is pinned with `numactl --physcpubind --membind` (else `taskset`).
  In a Docker container `--membind` needs `--cap-add SYS_NICE`; inside a cpuset, CPUs
  0 .. SIX_CORES-1 must be allowed (`run_all.sh check` tests the latter).
- The reference numbers in `scripts/baselines/zka/README.md` (2026-10-09) were
  measured before zkSketch's default build became zero-knowledge; `full` measures
  the zero-knowledge build, which costs zkSketch more. At this shape it is much
  heavier for GK: one GK run of the default build here (2026-10-12, on a shared,
  loaded machine) took 824 s and peaked at 58.8 GiB RSS, with 70 s of proving per
  batch, against 215 s, 19.4 GiB and 14.7 s per batch for the non-ZK reference run
  (`six_zksketch_r2_gk`). The other five sketches have not been run at this shape on
  the zero-knowledge build, and `full` as a whole has not been run on it yet. At 2
  batches of 2,048 on the zero-knowledge build (2026-10-12, same machine) the 7 runs
  took 14.7 min in all: GK 371 s and 58 GiB, Bloom 126 s and 15 GiB per run (two
  runs), CM / HLL / SS / KMV 38-95 s and 5-8 GiB each; the 30-40 min estimate for
  `full`'s 7 zkSketch runs is extrapolated from those runs and GK's full-shape run.
  This probe needs as much RAM as `full` (GK peaks about the same at 2 and 8 batches).
  To see each sketch's time and memory at the full batch size on a new machine
  (~15 min here) before starting `full`:
  `RESULTS=$PWD/results/six/m2048t2 SIX_M=2048 SIX_T=2 GATE_WAIT_S=0 scripts/baselines/zka/six/run_zks.sh`
  (the 7 zkSketch runs at 2 batches of 2,048; `wall_s` and `desc_peak_rss_mb` in
  that directory's `six_zksketch_runs.csv`).
- On another machine the proving times change with the CPU. The guest ELF hashes and
  exact `user_cycles` also depend on `$HOME` and the checkout path (panic-location
  strings); expect `user_cycles` within about 0.02% and identical segment and padded
  cycle counts.
- Step by step, the exact configuration, what is ours vs upstream, the reference
  results and caveats: [`scripts/baselines/zka/README.md`](scripts/baselines/zka/README.md),
  section "Six-sketch comparison (small scale)".

---

## Tests

```bash
cargo test --release                       # plonky3 (zk build): 752 lib unit tests (+67 #[ignore]d) + tests/ integration
cargo test --release --no-default-features # the same suites on the non-hiding build (non-ZK VK pins; 751 lib: the fork-guard test is zk-only)
cargo test --release --test zk_logup_blinding  # LogUp-mask freshness + guess-and-check replay (control without zk)
# + the zero-mask positive control in the zk build (needs the forks' test-only mask hook):
cargo test --release --features test-hooks,p3-circuit-prover/test-hooks --test zk_logup_blinding
cargo test --release --lib dataset::       # one module
cargo test --release --test two_leaf_hll   # one integration suite
cargo test --release --test staged_queries # procs: staged-wave engine + bound queries, both commit modes
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
| `scripts/baselines/` | External comparisons: `zka/six/run_all.sh` (the six-sketch zkSketch vs zk-Analytics comparison above), the zk-Analytics-side drivers (`zka/{cyc,hll,spacesaving,gk,bloom,kmv}/`), their reference results (`zka/results/`) and docs (`zka/README.md`); `fetch_baselines.sh` clones the external systems. |
| `scripts/` | `run_experiments.sh` (e1/e2/e5/e8 driver), `run_compose.sh` (both backends), `run_stream.sh`, `run_decode.sh`, `plot_eval.py` (the paper's batch-sweep figure), `fetch_datasets.py`; legacy: `plot_experiments.py` (RQ figures), `cost_model_e10.py`. |
| `data/` | Key streams: synthetic (`gaussian/uniform/zipf.keys` + manifest) and real (`aol/netflix.keys`). |
| `docs/` | [`datasets.md`](docs/datasets.md): the dataset recipe, reproducibility model, and materialization. |

---

