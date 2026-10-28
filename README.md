# zkSketch

**zkSketch** is a zero-knowledge proof framework for verifiable streaming sketches.
Built on [Plonky3](https://github.com/Plonky3/Plonky3) recursive STARKs (BabyBear field,
Poseidon2 hash, no trusted setup), it lets a server prove that a sketch was correctly
maintained over a committed stream and that a query answer is read from that sketch,
without revealing the stream. Every proof is zero-knowledge by default.


## Project Structure

```
src/
  sketch/         # Update circuits for the six sketches, plus the baselines they are compared with
  decode/         # Query circuits
  recursion/      # Recursive composition: in-circuit merge, chain, proof forest
  commitment/     # Hiding commitments to sketch states
  experiments/    # Experiment code shared by the runners
examples/
  exp_compose.rs  # Proof-forest runs: composition, machines, stream length, query rate
  exp_operator.rs # Per-phase proving cost (Figure 6)
scripts/
  run_compose.sh        # Runs exp_compose; CSVs go to results/
  sweep_memmatch.py     # Figure 5 data: joins the batch-size sweep with the Table 2 run
  plot_sweep.py         # Figure 5
  plot_operator.py      # Figure 6
  forest_tables.py      # Tables 4 and 5 from the Table 2 run
  run_m1_busy_sibling.sh  # One machine next to a busy neighbour (appendix)
  baselines/zka/        # zk-Analytics baseline (RISC Zero); six/run_all.sh runs the comparison
data/             # Key streams: AOL and Netflix (real), synthetic streams
docs/             # Long-form notes: build details, circuits, every experiment knob
tests/            # Integration tests
```


## Benchmarks

| Sketch | Default size | Query |
|--------|-------------|-------|
| Count-Min | d = 3, w = 2^14 | Point frequency |
| HyperLogLog | 2^14 registers | Distinct count |
| Misra-Gries (MG; `ss` in the code) | s = 2^14 slots | Top-K counter sum |
| Greenwald-Khanna | capacity 2^11, 1/eps = 51 | Rank |
| Bloom | k = 7 slices of 2^14 bits | Membership |
| KMV | s = 2^14 | Distinct count |



Datasets: **AOL** (default) and **Netflix** (2^20 keys each, in `data/`), and synthetic
**Uniform** and **Gaussian** streams.


## Getting Started

### Prerequisites

- **Rust**, stable toolchain >= 1.90 (the paper used 1.97.1), and a C linker (`build-essential`).
- For the zk-Analytics comparison: [RISC Zero](https://risczero.com) with guest Rust 1.97.0 and `r0vm` 3.0.6
  (Linux x86_64 with glibc >= 2.34, e.g. Ubuntu 22.04+):

  ```bash
  curl -L https://risczero.com/install | bash && export PATH="$HOME/.risc0/bin:$PATH"
  rzup install rust 1.97.0 && rzup default rust 1.97.0
  rzup install r0vm 3.0.6 && rzup default r0vm 3.0.6
  ```

- `python3` (>= 3.8), plus `matplotlib` for the figures.
- Hardware: items 1-4 ran on a 32-core AMD Threadripper PRO 9975WX, items 6-8 on an AMD EPYC 9555
  server (two sockets, four NUMA nodes; each "machine" is one process pinned to the 32 cores of one
  node). Items 1 and 2 need 16 GiB of RAM, item 3 about 80 GiB, item 4 about 64 GiB, and items 6-8 up
  to ~120 GiB per machine.

### Build

```bash
cargo build --release
scripts/baselines/zka/six/run_all.sh check    # checks the tools above
scripts/baselines/zka/six/run_all.sh build    # clones zk-Analytics into ~/ext-baselines and builds both systems
scripts/baselines/zka/six/run_all.sh quick    # ~10 min smoke test of the comparison at tiny scale
```


## Running the Experiments


**1. zkSketch vs zk-Analytics, whole stream**:

```bash
SIX_ZKA_HH=spacesaving taskset -c 0-31 scripts/baselines/zka/six/run_all.sh memmatch
```

**2. Query rate**. zk-Analytics' cost per Q is computed from its epoch and query
proofs and their cycle counts by `six/queryrate_model.py`, which the command runs:

```bash
SIX_ZKA_HH=spacesaving taskset -c 0-31 scripts/baselines/zka/six/run_all.sh queryrate
```

**3. Batch size**. The sweep proves one batch of m = 2^6 .. 2^14 records per size on both
systems (~20 h; Figure 5 uses its zk-Analytics receipts); `batches.sh` proves zkSketch's batch of every
size in Table 2's setting and one zk-Analytics GK receipt at capacity 768 (~1.5 h); `sweep_memmatch.py`
joins them with item 1's run:

```bash
SIX_ZKA_HH=spacesaving taskset -c 0-31 scripts/baselines/zka/six/run_all.sh sweep
taskset -c 0-31 scripts/baselines/zka/six/batches.sh --zka-gk
python3 scripts/sweep_memmatch.py --sweep results/six/sweep-<date> --batches results/six/batches-<date> --memmatch results/six/memmatch-<date>
python3 scripts/plot_sweep.py
```

**4. Proving cost by phase**:

```bash
RAYON_NUM_THREADS=32 taskset -c 0-31 cargo run --release --example exp_operator
python3 scripts/plot_operator.py
```

**5. Stream length, machine count and datasets**, computed from item 1's run with
the speedups of item 6 and the per-dataset ratios of item 7:

```bash
python3 scripts/forest_tables.py
```

**6. Forest on M = 1-4 machines**:

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh frame_out_1machine_plonky3.csv
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=2,3,4 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_COMPOSE_NODES=0,2 EXP_COMPOSE_WAVE_SIZE=2 scripts/run_compose.sh frame_out_staged_m234_plonky3.csv
```

**7. Datasets**:

```bash
EXP_DATASET=uniform,gaussian,netflix EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh frame_out_1machine_datasets_plonky3.csv
```

**8. Fully concurrent machines** (appendix): all M machines live at once, and one machine next to a busy neighbour:

```bash
for M in 2 3 4; do EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=$M EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh frame_out_${M}machine_plonky3_coresident.csv; done
scripts/run_m1_busy_sibling.sh frame_out_1machine_plonky3_busysib.csv ss
```


