# zkSketch

Research prototype for the paper **"zkSketch: Verifiable and Privacy-Preserving
Sketch-Based Analytics via NIZKs"**: verifiable, privacy-preserving sketch
maintenance built on recursive proofs. Six sketches (Count-Min, HyperLogLog,
SpaceSaving / Misra-Gries, Greenwald-Khanna, Bloom, KMV) are implemented as
plonky3 STARK circuits with a recursive composition layer; the first four also run
on a plonky2 SNARK backend. Every plonky3 proof is zero-knowledge by default.

| Backend | Crate | Proof system | Field / hash | Toolchain |
| --- | --- | --- | --- | --- |
| **plonky3** (this repo root) | `zksketch` | recursive **STARK** (batch-STARK + in-circuit FRI verifier) | BabyBear (31-bit) + Poseidon2 | stable |
| **plonky2** (`plonky2/`) | `zksketch_snark` | recursive **SNARK** (native `verify_proof`) | Goldilocks (64-bit) + Poseidon | nightly (auto) |

Both backends are transparent, hash-based FRI systems (no trusted setup), set to
the same 124-bit conjectured FRI security target so proof sizes and verify times
compare at parity. Details on the build, the forks and the zero-knowledge default:
[docs/build.md](docs/build.md). What each circuit does: [docs/implemented.md](docs/implemented.md).

This README covers only what is needed to run the experiments:

- [Build](#build)
- [Experiment 1: zkSketch vs zk-Analytics, six sketches](#experiment-1-zksketch-vs-zk-analytics-six-sketches-one-machine)
- [Experiment 2: the paper's evaluation suite](#experiment-2-the-papers-evaluation-suite)
- [Datasets](#datasets), [Tests](#tests), [Repository layout](#repository-layout)

---

## Build

```bash
cargo build --release                  # plonky3; release is essential (the recursive prover is ~50x slower in debug)
cargo test --release                   # plonky3: library unit tests + tests/ integration suites
(cd plonky2 && cargo test --release)   # plonky2 backend (rustup auto-selects its pinned nightly)
```

- **Rust** >= 1.88 stable via [rustup](https://rustup.rs) (distro packages are too old;
  the paper used 1.97.1). `plonky2/` pins `nightly-2026-05-31` in its own
  `rust-toolchain.toml`. A C linker (`build-essential`) is needed.
- **First build fetches pinned GitHub revisions** of three public forks
  (`tuzijun111/Plonky3`, `tuzijun111/Plonky3_RangeAir`, `tuzijun111/plonky2`); no
  credentials are needed. If cargo reports `failed to authenticate`, retry with
  `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release`.
- **Zero knowledge is on by default** (Cargo feature `zk`: hiding FRI PCS plus
  masked LogUp sums). `--no-default-features` builds the non-hiding variant used for
  the stored non-ZK numbers. Every CSV row records `pcs` and `logup_mask`.
- **Plots:** `python3` + `matplotlib`.

---

## Experiment 1: zkSketch vs zk-Analytics (six sketches, one machine)

**What it measures.** zkSketch against zk-Analytics (Zhu et al., "Zero-Knowledge
Cloud Analytics", SIGCOMM '26; a RISC Zero zkVM pipeline cloned at `d4a5a9a`) on
Count-Min (3 x 1024), HyperLogLog (b = 14), SpaceSaving / Misra-Gries (1,024
counters), Greenwald-Khanna (eps = 1/51), Bloom (7 x 2^14) and KMV (k = 1,024) over
the same AOL records (`data/aol.keys`, tracked in git). Per sketch: update proving
per epoch and for the whole stream, query proving after n = 1, 2, 4, 8 epochs, the
verifier's work and bytes, peak memory, and answers vs exact. Both systems run on
the same machine, one job at a time, both with zero knowledge.

Two things to know when reading the tables:

- zk-Analytics ships only Count-Min. **For the other five sketches the zk-Analytics
  side is our code inside their per-epoch RISC Zero pipeline (marked † everywhere):**
  plain textbook per-record HLL, SpaceSaving, Bloom and KMV, and for Greenwald-Khanna
  zkSketch's own GK batch rule as written (`SIX_ZKA_GK=matched`, the default), so both
  sides compute the same function. Textbook GK stays as a labelled reference.
- The headline zk-Analytics variant is **`noroot`**: their aggregation guests minus a
  per-bucket Merkle root that their code builds but nothing in their protocol or code
  reads. Their shipped Count-Min, roots included, is still proved as a reference row.

**Machine.** Linux x86_64, glibc >= 2.34 and the libstdc++ of GCC >= 12 (Ubuntu 22.04+,
Debian 12+, Fedora 37+; not RHEL/Rocky/Alma 9 or Amazon Linux 2023). RAM: 16 GiB for
`quick`, 96 GiB or more for `full` (its zkSketch GK run peaks at ~59 GiB). About
30 GB of free disk. The reference numbers come from a 32-core AMD Threadripper PRO
9975WX; a smaller machine uses the physical cores it has (`SIX_CORES`).

**Prerequisites**, once per machine (`run_all.sh check` verifies them and prints the fix
for anything missing):

```bash
# 1. System packages (the only step that needs sudo; numactl is optional).
sudo apt-get install -y build-essential git curl ca-certificates python3 procps util-linux diffutils numactl
# 2. Rust via rustup, pinned to the reference toolchain (any stable >= 1.90 builds).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.1
. "$HOME/.cargo/env"
# 3. RISC Zero at the exact versions used.
curl -L https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$PATH"
rzup install rust 1.97.0 && rzup default rust 1.97.0     # guest toolchain
rzup install r0vm 3.0.6 && rzup default r0vm 3.0.6       # prover
```

**Run**, from a clone (the scripts work from any directory; while the repository is
private, as it was on 2026-10-13, cloning needs your GitHub credentials):

```bash
git clone https://github.com/tuzijun111/zkSketch.git && cd zkSketch
scripts/baselines/zka/six/run_all.sh check    # OK / WARN / MISSING per item; exit 1 if anything blocks
scripts/baselines/zka/six/run_all.sh build    # clone zk-Analytics into ~/ext-baselines; build both sides (~5-8 min)
scripts/baselines/zka/six/run_all.sh quick    # smoke test of the whole pipeline at tiny scale (5-11 min)
scripts/baselines/zka/six/run_all.sh full     # the paper configuration (hours; run it under tmux / nohup)
scripts/baselines/zka/six/run_all.sh memmatch # the memory-matched shape of the final GK/Bloom numbers (hours; --quick: ~10 min)
```

| step | what it does | time (32 cores) | peak RAM |
|---|---|---|---|
| `check` | tools and versions, RAM, cores, disk, dataset, stale builds | seconds | - |
| `build` | clones zk-Analytics @ `d4a5a9a`; builds its 7 drivers (their CM; our † ports; GK matched + textbook) and zkSketch's `exp_compose` | ~5-8 min | ~2 GB |
| `quick` | zkSketch: 7 runs at N = 512 (2 batches of 256). zk-Analytics: executor for all six, 4 real proofs, the other planned jobs ESTIMATED from their cycle counts | ~5-11 min | ~9 GiB |
| `full` | zkSketch: 7 runs at N = 16,384 (8 batches of 2,048). zk-Analytics: executor, then 42 proofs (aggregation epochs 0 and 7 of every family as `noroot`; queries at n = 1, 2, 4, 8; their shipped Count-Min at epochs 0 and 7 as the reference) | ~3 h 30 min plus quiet-machine waits (estimate) | zkSketch GK ~59 GiB; r0vm ~9 GiB |
| `memmatch` | one epoch per family (GK 2,048 records, the others 16,384), proved by zkSketch as a forest of small leaves (GK capacity 768 in leaves of 512; CM, HLL, Bloom 1,024; SS, KMV 4,096) and by zk-Analytics as one receipt; 14 proofs. `--quick`: the same pipeline at tiny scale | ~5 h 30 min (estimate); `--quick` ~10 min | zkSketch < 9 GiB; r0vm ~9 GiB |

`quick` checks the pipeline end to end; it is not a measurement. `full --dry-run`
prints the plan and runs nothing. `run_all.sh assemble <dir>` re-runs only the tables.
Success looks like `check: ok`, every `build` step `ok`, and `quick`/`full` ending in
`quick: OK in ...` / `full: OK in ...` after printing the summary tables.

**Outputs.** Each `quick` / `full` / `memmatch` writes a fresh, git-ignored directory
`results/six/<mode>-<YYYYmmdd-HHMMSS>/`:

- `six_sketch_table.md`: all tables (update proofs side by side with the ratio
  zk-Analytics / zkSketch, the Count-Min reference, query proving per n, verifier work
  and bytes, peak RSS, answers vs exact, cycle profiles). Ratios above 1 mean zkSketch
  is faster, smaller or lighter.
- `six_sketch_comparison.csv`: one row per (family, system, root variant, operation);
  `provenance` says measured, sampled, derived or ESTIMATED.
- `manifest.txt` (configuration, commits, tool versions), `run_all.log`, and the raw
  `six_zksketch_*.csv/.log` and `six_zka_*.csv/.log` files.

**Knobs** (environment variables; the defaults are the paper configuration):

| variable | default | meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | zk-Analytics clone and its builds (~13 GB) |
| `RESULTS` | `results/six/<mode>-<stamp>` | output directory; must be new or empty |
| `SIX_CORES` | physical cores, at most 32 | cores of zkSketch's prover, pinned to CPUs 0 .. SIX_CORES-1 |
| `GATE_WAIT_S` | `quick` 0, `full` 1800 | seconds each timed job waits for a quiet machine before running anyway |
| `SIX_ZKA_ROOTS` | `noroot` | zk-Analytics aggregation variants proved: comma list of `noroot`, `designed` (as shipped, roots included), `legacy` |
| `SIX_ZKA_CM_REF` | `1` | also prove their shipped Count-Min as the reference (`0`: 40 proofs instead of 42) |
| `SIX_ZKA_GK` | `matched` | zk-Analytics side's GK: zkSketch's rule in their pipeline, or `textbook` |
| `SIX_ZKA_GK_IMPL` | `literal` | the matched GK guest: zkSketch's `apply_batch2` as written (the baseline); `tuned`, `fast`, `fixed_linear` are our rewrites, sensitivity only |
| `SIX_GK_ROUNDS` | `stable` | zkSketch's GK leaf: the stable-compaction circuit, or `sorted` (the earlier circuit) |
| `SIX_BLOOM_VARIANT` | `packed` | zkSketch's Bloom leaf: packed bytes, or `omc` (one field element per bit) |
| `SIX_ALLOW_STALE` | unset | `1` lets `quick` / `full` run binaries older than their sources |

Notes:

- Use an otherwise idle machine; all times are wall-clock. `quick`, `full` and `memmatch` refuse
  binaries older than their sources: re-run `run_all.sh build` after pulling or editing.
- `full` takes hours: run it inside `tmux` / `screen` or with `nohup ... &`. Ctrl-C stops
  the running job and exits. A failed zk-Analytics proof does not stop `full`; the
  table shows `-` for it and the exit status is 1. To finish an interrupted run without
  starting over, see the full guide.
- **Memory-matched shape.** `full` proves one zkSketch leaf per 2,048-record epoch (GK
  capacity 2,048; the 59 GiB GK peak was measured with the earlier `sorted` circuit).
  `memmatch` is the shape of the final GK / Bloom numbers
  (`scripts/baselines/zka/results/{memmatch-20261014,20261016-m2,20261016-m3}/README.md`):
  zkSketch's "1 epoch" is its k leaves + k - 1 merges, its query at epoch n is the one
  after leaf n x k, and the tables add the coordinator's and the combined (worker +
  coordinator) peak next to the worker's, plus each run's circuit variant.
  `memmatch --dry-run` prints the plan; `--epochs T` proves T epochs per family. Only
  `memmatch --quick` has been run through `run_all.sh` so far (2026-10-19).

Full guide (every knob, times per step, recovery, caveats):
[docs/six_sketch_comparison.md](docs/six_sketch_comparison.md). Exact configuration,
what is ours vs upstream, the reference results and their caveats:
[scripts/baselines/zka/README.md](scripts/baselines/zka/README.md), section
"Six-sketch comparison (small scale)".

---

## Experiment 2: the paper's evaluation suite

Two surfaces produce the paper's evaluation: `scripts/run_experiments.sh e1` (the
per-family circuit-cost matrix behind the batch-sweep figure) and
`scripts/run_compose.sh` (real recursive composition behind every table). Both default
to a small slice that runs anywhere:

```bash
scripts/run_experiments.sh e1         # family x variant x batch sweep, both backends -> results/e1_circuit.csv
scripts/run_compose.sh                # per_batch / chain / forest composition          -> results/stream_compose.csv
```

The deployed configuration (Count-Min `d=7, w=2^14`; HyperLogLog `b=14`; SpaceSaving
`s=2^14`; Greenwald-Khanna capacity 2,048; `N=2^20` AOL records in 64 batches of
`m=2^14`; 32 cores) is a long run: one command feeds five paper artifacts:

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs \
EXP_COMPOSE_BACKEND=plonky3 scripts/run_compose.sh frame_out_1machine_plonky3.csv
```

The most used knobs:

| variable | surface | meaning | default |
|---|---|---|---|
| `EXP_DATASET` | both | `uniform` \| `gaussian` \| `zipf` \| `aol` \| `netflix` (comma list on `run_compose.sh`) | `uniform` |
| `EXP_M` | e1 | batch sizes, comma list | `4,8,16,32` |
| `EXP_FAMILY` / `EXP_COMPOSE_FAMILY` | e1 / compose | `cm,hll,ss,gk`; compose also takes `bloom`, `kmv` and the Goldilocks `*_gl` ports | `all` / `cm,hll,ss,gk` |
| `EXP_{CM,HLL}_VARIANT`, `EXP_SS_VARIANT`, `EXP_GK_VARIANT` | e1 | deployed circuit vs its baselines (`omc` / `one_hot` / `merkle`; `certified` / `naive`; `bandmerge2` / `bandmerge2_naive`) | `one_hot`, `certified`, `certified` |
| `EXP_D`, `EXP_W`, `EXP_HLL_B`, `EXP_SS_CAP`, `EXP_GK_CAP`, `EXP_BLOOM_K`, `EXP_BLOOM_LOGW`, `EXP_KMV_K` | both | sketch sizes | small |
| `EXP_COMPOSE_N`, `EXP_COMPOSE_BATCHES`, `EXP_COMPOSE_MODE` | compose | stream length (`2^k` allowed), batch size `m`, `per_batch` \| `chain` \| `forest` | `32`, `8`, all three |
| `EXP_COMPOSE_MACHINES`, `EXP_COMPOSE_CORES`, `EXP_COMPOSE_EXEC` | compose | machines, cores per machine, `procs` (real pinned processes) \| `sim`; pass `EXP_COMPOSE_EXEC=procs` explicitly at one machine | `1`, all, `procs` iff machines > 1 |
| `EXP_COMPOSE_QUERY_EVERY_OPS` / `EXP_COMPOSE_QUERY_EVERY` | compose | mixed updates + queries: a query every Q stream positions / after every k-th batch | off |
| `EXP_COMPOSE_BACKEND`, `BACKENDS` | compose / e1 | `plonky3` \| `plonky2` (\| `both` for e1) | `plonky3` / `both` |
| `EXP_OUT` / `$1` | both | output CSV name under `results/` | per surface |
| `ZKSKETCH_COMMIT`, `ZKSKETCH_BINDING`, `ZKSKETCH_STATEMENT` | plonky3 | `hiding` \| `plain` commitments; `semantic` \| `bound` \| `legacy` binding; `interval` \| `boundary` statement | `hiding`, `semantic`, `interval` |

Every paper command (figure and table by name), where each result file lives, the
retired modes and the full knob lists: [docs/experiments.md](docs/experiments.md); the
hardware notes for the paper's testbed (RAM per machine, NUMA placement):
[docs/build.md](docs/build.md). `results/` is git-ignored; a clone has no measured CSVs.

---

## Datasets

32-bit key streams under `data/` (flat little-endian `u32` files), with the same key
derivation as S³ so inputs are comparable. The synthetic files are seeded and frozen
byte-for-byte; the real slices are 2^20 keys each. Recipe, regeneration and fetching:
[docs/datasets.md](docs/datasets.md).

| Dataset | Kind | Recipe | File |
| --- | --- | --- | --- |
| `gaussian` | synthetic | mu = 2^31, sigma = 2^13 (seed 1) | `data/gaussian.keys` |
| `uniform` | synthetic | uniform over [0, 2^32) (seed 2) | `data/uniform.keys` |
| `zipf` | synthetic | alpha = 1.0, universe 2^16 (seed 1) | `data/zipf.keys` |
| `aol` | real | AOL search log, `CRC32(normalized ClickURL)` | `data/aol.keys` |
| `netflix` | real | Netflix Prize, CustomerID | `data/netflix.keys` |

```bash
cargo run --release --example gen_synthetic     # regenerate the synthetic files
python3 scripts/fetch_datasets.py               # re-fetch the real ones (streamed, capped)
```

---

## Tests

```bash
cargo test --release                            # plonky3, zero-knowledge build
cargo test --release --no-default-features      # the same suites on the non-hiding build
cargo test --release --test zk_logup_blinding   # LogUp-mask freshness + guess-and-check replay
(cd plonky2 && cargo test --release)            # plonky2 backend
```

Heavy proving-time sweeps are `#[ignore]`d; run one on demand with
`cargo test --release --lib <name> -- --ignored --nocapture`. Each circuit's unit
tests include tamper-rejection cases (mutated proofs and public inputs); `tests/` holds
the chain / merge end-to-end suites.

---

## Repository layout

| Path | What's in it |
| --- | --- |
| `src/sketch/` | Plaintext sketches and the circuits. Deployed leaves: `countmin_omc`, `hll_omc`, `ss_final_full`, `gk_bandmerge` (stable compaction), `bloom_packed`, `kmv`; baselines alongside. |
| `src/decode/` | Query (decode) circuits per family. |
| `src/recursion/` | The composition layer: in-circuit merge, chains, streaming forest, composition statement and auditor, root-VK derivation. |
| `src/experiments/`, `examples/` | Experiment runners (`exp_compose`, `exp_e1`, ...) and the dataset generator. |
| `scripts/` | `run_experiments.sh`, `run_compose.sh`, `run_stream.sh`, `run_decode.sh`, `plot_eval.py`, `fetch_datasets.py`. |
| `scripts/baselines/zka/` | The zkSketch vs zk-Analytics comparison: `six/run_all.sh` (entry point), the zk-Analytics-side drivers (`cyc`, `cm_noroot`, `hll`, `spacesaving`, `gk`, `gk_matched`, `bloom`, `kmv`), reference results (`results/`) and the detailed `README.md`. |
| `plonky2/` | The SNARK backend: its own leaves, decoders, recursion and examples. |
| `data/`, `docs/`, `tests/` | Key streams; the documents linked above; integration suites. |
