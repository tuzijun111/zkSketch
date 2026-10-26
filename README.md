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
  the stored non-ZK numbers. Every env.json and every `exp_compose` / `exp_e0` CSV row
  records `pcs` and `logup_mask`.
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
`quick`, `memmatch` and `queryrate`, 32 GiB for `full` (its largest process, zkSketch's GK run, peaks at ~15 GiB),
~80 GiB for `sweep` (zkSketch's GK leaf at m = 2^14 peaks at 74 GiB).
About 30 GB of free disk. The reference numbers come from a 32-core AMD Threadripper PRO
9975WX; a smaller machine uses the physical cores it has (`SIX_CORES`).

**Prerequisites**, once per machine (`run_all.sh check` verifies them and prints the fix
for anything missing):

```bash
# 1. System packages (the only step that needs sudo; numactl is optional).
sudo apt-get install -y build-essential git curl ca-certificates python3 procps util-linux diffutils numactl
# 2. Rust via rustup, pinned to the reference toolchain (any stable >= 1.90 builds; the zk-Analytics hosts need 1.90).
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
scripts/baselines/zka/six/run_all.sh build    # clone zk-Analytics into ~/ext-baselines; build both sides (~7-8 min cold)
scripts/baselines/zka/six/run_all.sh quick    # smoke test of the whole pipeline at tiny scale (5-11 min)
scripts/baselines/zka/six/run_all.sh full     # one zkSketch leaf per 2,048-record epoch, 8 epochs (~3 h; run it under tmux / nohup)
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh memmatch             # the paper's zkSketch-vs-zk-Analytics table: one epoch per sketch under the 8 GiB memory budget (8 h 12 min here)
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh memmatch --epochs 64 # the same at the paper's stream length N = 2^20 (GK 2^17): about two days (estimate; not yet run)
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh sweep                 # batch-size sweep, one batch of m = 2^6 .. 2^14 records, both systems (~12-16 h, estimate)
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh queryrate             # query-rate experiment: zkSketch measured, zk-Analytics modeled (~14 h, estimate)
```

The `taskset -c 0-31` mask gives both sides the same 32 physical cores: zkSketch pins its
prover itself, but zk-Analytics' `r0vm` takes every hardware thread it can see (129 threads
on this 64-thread machine). If CPUs 0-31 are not 32 distinct physical cores on your
machine, change the mask; `run_all.sh check` verifies the pinning target.

| step | what it does | time (32 cores) | peak RAM |
|---|---|---|---|
| `check` | tools and versions, RAM, cores, disk, dataset, stale builds | seconds | - |
| `build` | clones zk-Analytics @ `d4a5a9a`; builds its 7 drivers (their CM; our † ports; GK matched + textbook) and zkSketch's `exp_compose` | ~7-8 min cold; a few minutes when little changed | ~2 GB |
| `quick` | zkSketch: 7 runs at N = 512 (2 batches of 256). zk-Analytics: executor for all six, 4 real proofs, the other planned jobs ESTIMATED from their cycle counts | ~5-11 min | ~9 GiB |
| `full` | zkSketch: 7 runs at N = 16,384 (8 batches of 2,048). zk-Analytics: executor, then 42 proofs (aggregation epochs 0 and 7 of every family as `noroot`; queries at n = 1, 2, 4, 8; their shipped Count-Min at epochs 0 and 7 as the reference) | ~3 h 15 min plus quiet-machine waits (estimate) | zkSketch GK ~15 GiB; r0vm ~9 GiB |
| `memmatch` | the paper's zkSketch-vs-zk-Analytics table. Each sketch's epoch (16,384 AOL records; GK 2,048 at capacity 768) is proved by zkSketch as k leaves + k - 1 merges in one forest (CM / HLL / Bloom 16 x 1,024, SS / KMV 4 x 4,096, GK 4 x 512) under an 8 GiB budget, and by zk-Analytics as one receipt; all 14 zk-Analytics proofs are real (6 aggregation, 7 queries at n = 1, the Count-Min reference) | 8 h 12 min on 2026-10-22 (zkSketch 29 min, zk-Analytics 7 h 42 min) | zkSketch 4.8-7.3 GiB; r0vm 9.2 GiB |
| `memmatch --epochs 64` | the same shape over N = 2^20 records (64 epochs; GK 2^17): zkSketch 1,024 or 256 leaves per family, zk-Analytics 63 proofs (epochs 0 and 63 of every family, queries at n = 1, 2, 4, ..., 64, the reference), the stream total derived as 64 x the mean of the two proved epochs | about two days (estimate) | as `memmatch` (forest depth untested) |
| `sweep` | batch-size scaling: both systems on ONE batch of m = 2^E records per size, E = 6..14, all six sketches. zkSketch one leaf per batch (GK capacity 2,048; Bloom `packed` up to m = 8,192, `omc` at 16,384), zk-Analytics one `noroot` receipt per batch (6 real proofs per size, no CM reference); `sweep.csv` / `sweep_table.md` give prove time, ms per record, zkA / zkS, verify, proof bytes and peak RSS per sketch x m (`--dry-run` prints the plan, `--resume` continues a stopped sweep, `--quick` = m = 64 and 128 at GK capacity 512, ~15-20 min). The run behind the paper's sweep figure is kept in `scripts/baselines/zka/results/sweep-20261024-195453/` | 19 h 47 min on 2026-10-24/25 (zkSketch 1 h 27 min, zk-Analytics proofs 18 h 20 min; the 2^14 size alone 8 h 46 min) | zkSketch GK / HLL leaves at 2^13-2^14: tens of GiB (not the 8 GiB shape); r0vm ~9 GiB |
| `queryrate` | the query-rate experiment: one query every Q = 1,000 / 10,000 / 100,000 positions of a 2^17-position AOL stream plus the query-free baseline, all six families. zkSketch measured (12 forest runs at the memmatch leaf sizes; a mid-leaf query seals and pads the leaf); zk-Analytics MODELED from measured parts (`queryrate_model.py`: aggregation proofs at E = Q, real for E <= 10,000, else from padded cycles; query proofs vs the number of merged epochs at n = 1..64 over 4,096-record epochs, real at n = 1 and 8; total = T A(Q) + a T + b T(T+1)/2 for T = N/Q queries); a GK capacity preflight runs first (`--quick` = N = 1,024, Q = 100 and 1,000, ~40 min). The run behind the paper's query-rate table is kept in `scripts/baselines/zka/results/queryrate-20261023-230106/` | 17 h 40 min on 2026-10-23/24 (zkSketch 10 h 15 min, zk-Analytics proofs 7 h 20 min) | zkSketch 4.8-7.3 GiB; r0vm ~9.4 GiB |

`quick` checks the pipeline end to end; it is not a measurement. `full --dry-run` /
`memmatch --dry-run` print the plan and run nothing. `run_all.sh assemble <dir>` re-runs only the tables.
Success looks like `check: ok`, every `build` step `ok`, and `quick`/`full`/`memmatch`
ending in `<mode>: OK in ...` after printing the summary tables.

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

**Knobs** (environment variables; the defaults are those of the commands above):

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
  capacity 2,048). `run_all.sh memmatch` is the shape of the paper's comparison table:
  zkSketch's "1 epoch" is its k leaves + k - 1 merges, its query at epoch n is the one
  after leaf n x k, and the tables add the coordinator's and the combined (worker +
  coordinator) peak next to the worker's, plus each run's circuit variant.
  One epoch per family by default, `--epochs T` for more; `--dry-run` prints the plan;
  `--quick` is its ~8 min smoke test. The one-epoch run behind the paper's table
  (2026-10-22, 32 cores on both sides) is kept in
  `scripts/baselines/zka/results/memmatch-20261022-205419/` (`six_sketch_table.md`,
  `six_sketch_comparison.csv`, manifest and logs). The multi-epoch form has only been
  smoke-tested (`--quick --epochs 2`).

Full guide (every knob, times per step, recovery, caveats):
[docs/six_sketch_comparison.md](docs/six_sketch_comparison.md). Exact configuration,
what is ours vs upstream, the reference results and their caveats:
[scripts/baselines/zka/README.md](scripts/baselines/zka/README.md), section
"Six-sketch comparison (small scale)".

---

## Experiment 2: the paper's evaluation suite

Two surfaces produce the paper's own evaluation: `scripts/run_experiments.sh e1` (the
per-family circuit-cost matrix behind the batch-sweep figure) and
`scripts/run_compose.sh` (real recursive composition behind the composition and scaling
tables). Both default to a small slice that runs anywhere:

```bash
scripts/run_experiments.sh e1         # family x variant x batch sweep, both backends -> results/e1_circuit.csv
scripts/run_compose.sh                # per_batch / chain / forest composition          -> results/stream_compose.csv
```

### Every command behind the paper's tables and figures

Run from the repository root. Deployed sizes: Count-Min `d=7, w=2^14`; HyperLogLog
`b=14`; SpaceSaving `s=2^14`; Greenwald-Khanna capacity 2,048 with `s=51`; Bloom 7 slices
of `2^14` bits; KMV `k=2^14`; `N=2^20` AOL records in batches of `m=2^14`; 32 cores per
machine. The zk-Analytics comparisons use the shapes of Experiment 1. Times are estimates
unless marked measured; outputs land in `results/` (git-ignored). Re-running the Figure 5, Table 3
and Table 8 commands overwrites the published CSVs of the same names, and the two plot scripts
overwrite `latex/pics/*.pdf` when that directory exists: copy them aside first.

**Table 2 (`tab:zka`), zkSketch vs zk-Analytics, one epoch** (measured 8 h 12 min; its
`N = 2^20` block is derived from the same run):

```bash
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh memmatch
```

**Figure 6 (`fig:eval-sweep`), batch-size sweep against zk-Analytics** (measured 19 h 47 min;
the plot needs matplotlib):

```bash
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh sweep
python3 scripts/plot_sweep.py results/six/sweep-<YYYYmmdd-HHMMSS>    # -> latex/pics/ if present, else results/
```

**Table 6 (`tab:mixed`), query-rate scaling, zkSketch measured, zk-Analytics modeled**
(measured 17 h 40 min):

```bash
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh queryrate
```

**Figure 5 (`fig:eval-batch`), batch-size sweep against the in-circuit baselines** (four
sketches; the published figure is the earlier circuits with zero knowledge off. Today's default
build proves with zero knowledge, which caps a table at `2^24` rows rather than the `2^27` FRI
domain, so the baselines reach `too_large` earlier, the Count-Min one-hot leaf already at
`m = 16`):

```bash
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=one_hot EXP_M=16,32,64 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=cm_batch_one_hot.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=merkle EXP_M=16,32,64,128,256,512,1024,2048 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=cm_batch_merkle.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=omc EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=cm_batch_omc.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=one_hot EXP_M=16,32,64,128,256,512,1024,2048 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=hll_batch_one_hot.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=merkle EXP_M=16,32,64,128,256,512,1024,2048,4096 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=hll_batch_merkle.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=omc EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=hll_batch_omc.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=ss EXP_SS_CAP=16384 EXP_SS_VARIANT=naive EXP_M=16,32,64,128 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=ss_batch_naive.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=ss EXP_SS_CAP=16384 EXP_SS_VARIANT=certified EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=ss_batch_certified.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=gk EXP_GK_CAP=2048 EXP_GK_VARIANT=bandmerge2_naive EXP_M=16,32,64,128,256 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=gk_batch_naive.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=gk EXP_GK_CAP=2048 EXP_GK_VARIANT=bandmerge2 EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 EXP_OUT=gk_batch_certified.csv scripts/run_experiments.sh e1
python3 scripts/plot_eval.py                                          # -> latex/pics/ if present, else results/
```

**Table 3 (`tab:compose-schedules`), per-batch chain vs forest** (four sketches, the published
commands; the published rows are the earlier circuits with zero knowledge off, so a re-run
measures today's circuits, whose leaves cost 1.4-4.4x more. The forest run is also the M = 1
column of Table 4, the `N = 2^20` column of Table 5 and the AOL column of Table 8):

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=per_batch EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 EXP_COMPOSE_BACKEND=plonky3 scripts/run_compose.sh frame_out_1machine_plonky3_perbatch.csv
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 EXP_COMPOSE_BACKEND=plonky3 scripts/run_compose.sh frame_out_1machine_plonky3.csv
```

**Table 4 (`tab:compose-scale`), forest parallelism on M = 1..4 machines** (the published table
is four sketches: Table 3's forest run for M = 1 plus the staged M = 2, 3, 4 command in
docs/experiments.md; this command re-measures all six on the current circuits. It needs the
paper's two-socket, four-NUMA-node server: machines on nodes 0 and 2, one per socket, M >= 3 in
time-shifted waves of two, up to two ~117 GiB machines live at once; about a day):

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=omc EXP_KMV_K=16384 EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1,2,3,4 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 EXP_COMPOSE_BACKEND=plonky3 EXP_COMPOSE_NODES=0,2 EXP_COMPOSE_WAVE_SIZE=2 scripts/run_compose.sh frame_out_m1234_plonky3_6fam.csv
```

**Table 5 (`tab:stream-scale`), stream scaling N = 2^16..2^20, six sketches** (one 32-core
machine, CM peaks at ~117 GiB; about 17-18 h; k = 20 repeats Table 4's M = 1 rows. The published
CM / HLL / SS / GK rows are the four-sketch loop of docs/experiments.md plus Table 3's forest run;
the Bloom and KMV rows are ESTIMATED from the two-leaf run on the second line):

```bash
for k in 16 17 18 19 20; do EXP_DATASET=aol EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=omc EXP_KMV_K=16384 EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest EXP_COMPOSE_N=2^$k EXP_COMPOSE_BATCHES=16384 EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 EXP_COMPOSE_BACKEND=plonky3 scripts/run_compose.sh forest_plonky3_1machine_6fam_2e$k.csv; done
EXP_DATASET=aol EXP_COMPOSE_N=2^15 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=omc EXP_KMV_K=16384 EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 EXP_COMPOSE_BACKEND=plonky3 scripts/run_compose.sh forest6_deployed_n2e15.csv   # the estimate's input (kept as results/smoke_forest6_deployed_n2e15.csv)
```

**Table 8 (`tab:eval-datasets`, appendix), dataset sensitivity** (four sketches, the published
command, earlier circuits as for Table 3; the AOL column is Table 3's forest run, the leaf-memory
column the `m = 2^14` rows of Figure 5's `{cm,hll}_batch_omc.csv` / `{ss,gk}_batch_certified.csv`,
the M = 4 column the staged M = 4 rows of Table 4's published run):

```bash
EXP_DATASET=uniform,gaussian,netflix EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 scripts/run_compose.sh frame_out_1machine_datasets_plonky3.csv
```

**Appendix staged-wave controls** (the ~6% package-sharing penalty and the fully concurrent
M = 2, 3, 4 times):

```bash
for M in 2 3 4; do EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=$M EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh frame_out_${M}machine_plonky3_coresident.csv; done
scripts/run_m1_busy_sibling.sh frame_out_1machine_plonky3_busysib.csv ss
```

The six-sketch commands select the bit-array Bloom leaf (`EXP_BLOOM_VARIANT=omc`) because the
default packed leaf needs `7 m < 2^16` and the run exits at `m = 16384`. GK's `1/eps` is derived
from its capacity and `N` (`s = floor(2048 / (2 ceil(log2 N)))`: 51 at `N = 2^20`, 64, 60, 56, 53 at
`2^16..2^19`, as in the published rows); `EXP_GK_S` overrides it. The single-batch Bloom and KMV
timings in the paper's update-cost section (73.5 s and 35.0 s on 32 unpinned threads) came from a
standalone measurement that is not in the repository; one leaf of the Table 5 configuration
(column `leafgen_seq_ms` of the two-leaf run above) approximates them at 71.7 s and 35.4 s. How
each table's columns are read from the CSVs (e.g. Table 5's `prove = leaf_busy_max_ms`), the
Plonky2 and Goldilocks cross-backend runs, and the older four-sketch versions:
[docs/experiments.md](docs/experiments.md).

The most used knobs:

| variable | surface | meaning | default |
|---|---|---|---|
| `EXP_DATASET` | both | `uniform` \| `gaussian` \| `zipf` \| `aol` \| `netflix` (comma list on `run_compose.sh`) | `uniform` |
| `EXP_M` | e1 | batch sizes, comma list | `4,8,16,32` |
| `EXP_FAMILY` / `EXP_COMPOSE_FAMILY` | e1 / compose | `cm,hll,ss,gk`; compose also takes `bloom`, `kmv` and the Goldilocks `*_gl` ports | `all` / `cm,hll,ss,gk` |
| `EXP_{CM,HLL}_VARIANT`, `EXP_SS_VARIANT`, `EXP_GK_VARIANT` | e1 | deployed circuit vs its baselines (`omc` / `one_hot` / `merkle`; `certified` / `naive`; `bandmerge2` / `bandmerge2_naive`) | `one_hot`, `certified`, `certified` |
| `EXP_D`, `EXP_W`, `EXP_HLL_B`, `EXP_SS_CAP`, `EXP_GK_CAP` | both | sketch sizes | small (GK capacity 8 on e1, 64 on compose) |
| `EXP_BLOOM_K`, `EXP_BLOOM_LOGW`, `EXP_KMV_K` | compose | Bloom slices, log2 bits per slice, KMV k | 7, 14 (the deployed filter), 1024 (deployed: 16384) |
| `EXP_COMPOSE_N`, `EXP_COMPOSE_BATCHES`, `EXP_COMPOSE_MODE` | compose | stream length (`2^k` allowed), batch size `m`, `per_batch` \| `chain` \| `forest` | `32`, `8`, all three (plonky2 runner: N 16, m 4, cores 4, and d 2, w 4, SS/GK capacity 4) |
| `EXP_COMPOSE_MACHINES`, `EXP_COMPOSE_CORES`, `EXP_COMPOSE_EXEC` | compose | machines, cores per machine, `procs` (real pinned processes) \| `sim`; pass `EXP_COMPOSE_EXEC=procs` explicitly at one machine | `1`, all, `procs` iff machines > 1 |
| `EXP_COMPOSE_QUERY_EVERY_OPS` / `EXP_COMPOSE_QUERY_EVERY` | compose | mixed updates + queries: a query every Q stream positions / after every k-th batch | off |
| `EXP_COMPOSE_BACKEND`, `BACKENDS` | compose / e1 | `plonky3` \| `plonky2` (\| `both` for e1) | `plonky3` / `both` |
| `EXP_OUT` | both | output CSV name under `results/`; also positional: `$1` of `run_compose.sh`, `$2` of `run_experiments.sh` (after the experiment id) | per surface |
| `ZKSKETCH_COMMIT`, `ZKSKETCH_BINDING`, `ZKSKETCH_STATEMENT` | plonky3 | `hiding` \| `plain` commitments; `semantic` \| `bound` \| `legacy` binding; `interval` \| `boundary` statement | `hiding`, `semantic`, `interval` |

Every paper command (figure and table by name), where each result file lives, the
retired modes and the full knob lists: [docs/experiments.md](docs/experiments.md); the
hardware notes for the paper's testbed (RAM per machine, NUMA placement):
[docs/build.md](docs/build.md). `results/` is git-ignored; a clone has no measured CSVs.

---

## Datasets

32-bit key streams under `data/` (flat little-endian `u32` files), with the same key
derivation as S³ so inputs are comparable. The synthetic files are seeded and frozen
byte-for-byte; the real slices are 2^20 keys each. The experiment runners load only
`aol` and `netflix` from these files: for `uniform`, `gaussian` and `zipf` they regenerate
the stream in code (seed 1, and a Zipf universe of N keys), so their inputs differ from
the frozen `uniform.keys` (seed 2) and `zipf.keys` (universe 2^16). Recipe, regeneration
and fetching: [docs/datasets.md](docs/datasets.md).

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
