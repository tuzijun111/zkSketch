# Prerequisites, build and the zero-knowledge default

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
    merge re-verifies masked proofs in-circuit (masked vs unmasked hiding
    builds of the same tree on a shared 64-thread Threadripper PRO 9975WX:
    leaves and one CM merge from `exp_e0` `E0_COST`, m = 1024, 2 runs each;
    merge table heights from `exp_e0` `E0_MERGE=only`; end to end from
    `exp_compose`, procs, forest). Leaf prove time +9-11%, proof +5-6%. The
    in-circuit verifier grows ~14%, which pushes the L1 merge's ALU table
    past 2^17 rows for all four families (also over paper-geometry m = 4096
    children), so that table doubles: one CM merge proves in 5.7 s instead
    of 3.8 s. A small composed run (forest, N = 32, m = 8, 16 cores) takes
    +40% (CM) / +55% (HLL) wall time and +46% peak RSS; at the six-sketch
    comparison shape (m = 2,048, t = 8), +16% / +18%. Stored `zk` numbers
    measured before the masks (`zk2_*`) understate the cost.
  - *Still public, or only heuristic:* table heights (operation and batch
    counts); every Expose / NPO public value; with `ZKSKETCH_COMMIT=plain`, the
    unsalted state and batch commitments (statement-level guess-and-check).
    Upstream calls `HidingFriPcs` only statistically zero-knowledge; the
    plain-MMCS (unsalted Merkle leaves) argument and the LogUp masking are our
    own constructions, not upstream guarantees. All of this is the plonky3
    backend; the plonky2 backend (`plonky2/`) is not covered by it.
- **Python (experiment plots):** `python3` + `matplotlib` for
  `scripts/plot_eval.py` (the paper's batch-sweep figure) and
  `scripts/plot_experiments.py`; stdlib only for `fetch_datasets.py` /
  `cost_model_e10.py`.
- **External baselines (optional):** the six-sketch zkSketch vs zk-Analytics
  comparison has its own short prerequisite list and a single entry point; see
  [Reproducing the zkSketch vs zk-Analytics comparison](six_sketch_comparison.md).
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
  CSVs; the commands in [Reproducing the paper's results](experiments.md#reproducing-the-papers-results)
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

