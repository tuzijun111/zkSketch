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
  exp_e1.rs       # Per-sketch batch-size sweep
scripts/
  run_compose.sh        # Runs exp_compose; CSVs go to results/
  run_experiments.sh    # Runs exp_e1; CSVs go to results/
  plot_eval.py          # Figure 5
  plot_sweep.py         # Figure 6
  run_m1_busy_sibling.sh  # One machine next to a busy neighbour (appendix)
  baselines/zka/        # zk-Analytics baseline (RISC Zero); six/run_all.sh runs the comparison
data/             # Key streams: AOL and Netflix (real), synthetic streams
docs/             # Long-form notes: build details, circuits, every experiment knob
tests/            # Integration tests
```


## Benchmarks

| Sketch | Parameters | Query |
|--------|-----------|-------|
| Count-Min | d = 7, w = 2^14 (d = 3 in Tables 4 and 5) | Point frequency |
| HyperLogLog | 2^14 registers | Distinct count |
| SpaceSaving (Misra-Gries) | s = 2^14 slots | Top-K counter sum |
| Greenwald-Khanna | capacity 2^11, 1/eps = 51 | Rank |
| Bloom | k = 7 slices of 2^14 bits | Membership |
| KMV | s = 2^14 | Distinct count |

The default stream is N = 2^20 AOL records in batches of m = 2^14. The zk-Analytics
comparisons (experiments 1-3) use zk-Analytics' sizes: Count-Min 3 x 1024, s = 1024 for
SpaceSaving and KMV, and GK capacity 768 in experiments 1 and 3.

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
- Hardware: experiments 1-3 ran on a 32-core AMD Threadripper PRO 9975WX, experiments 4-9 on
  an AMD EPYC 9555 server (two sockets, four NUMA nodes; each "machine" is one process pinned
  to the 32 cores of one node). Experiments 1 and 3 need 16 GiB of RAM and experiment 2 about
  80 GiB; experiments 4-9 need up to ~120 GiB per machine (a Count-Min leaf at d = 7 and
  m = 2^14 peaks at 117 GiB).

### Build

```bash
cargo build --release
scripts/baselines/zka/six/run_all.sh check    # checks the tools above
scripts/baselines/zka/six/run_all.sh build    # clones zk-Analytics into ~/ext-baselines and builds both systems
scripts/baselines/zka/six/run_all.sh quick    # ~10 min smoke test of the comparison at tiny scale
```


## Running the Experiments

Run from the repository root. zkSketch CSVs are written to `results/`; each zk-Analytics
comparison writes its tables (`*_table.md`) and CSVs to `results/six/<mode>-<date>/`.
The `taskset -c 0-31` mask gives both systems the same 32 physical cores (zk-Analytics'
prover otherwise uses every hardware thread).

**1. zkSketch vs zk-Analytics** on one epoch per sketch (Table 2; ~8 h):

```bash
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh memmatch
```

**2. Batch size, zkSketch vs zk-Analytics**, one batch of m = 2^6 .. 2^14 records (Figure 6; ~20 h):

```bash
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh sweep
python3 scripts/plot_sweep.py results/six/sweep-<date>
```

**3. Query rate, zkSketch vs zk-Analytics** (Table 6; ~18 h; the zk-Analytics side is modeled
from its measured proofs and cycle counts):

```bash
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh queryrate
```

**4. Batch size, zkSketch vs in-circuit baselines** (Figure 5):

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
python3 scripts/plot_eval.py
```

**5. Per-batch chain vs proof forest** (Table 3):

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=per_batch EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh frame_out_1machine_plonky3_perbatch.csv
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh frame_out_1machine_plonky3.csv
```

**6. Forest on M = 1-4 machines** (Table 4). The measured rows are item 5's forest run (M = 1) and this
run (needs a two-socket server; `EXP_COMPOSE_NODES=0,2` puts the machines on different sockets of the paper's server):

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=2,3,4 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_COMPOSE_NODES=0,2 EXP_COMPOSE_WAVE_SIZE=2 scripts/run_compose.sh frame_out_staged_m234_plonky3.csv
```

All six sketches, Count-Min at d = 3 (about a day):

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=3 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=omc EXP_KMV_K=16384 EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1,2,3,4 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs EXP_COMPOSE_NODES=0,2 EXP_COMPOSE_WAVE_SIZE=2 scripts/run_compose.sh frame_out_m1234_plonky3_6fam.csv
```

**7. Stream length N = 2^16 .. 2^20** (Table 5). The measured rows are item 5's forest run (N = 2^20) and:

```bash
for k in 16 17 18 19; do EXP_DATASET=aol EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_N=2^$k EXP_COMPOSE_BATCHES=16384 EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh forest_plonky3_1machine_verify_2e$k.csv; done
```

All six sketches, Count-Min at d = 3 (~15 h):

```bash
for k in 16 17 18 19 20; do EXP_DATASET=aol EXP_D=3 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=omc EXP_KMV_K=16384 EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest EXP_COMPOSE_N=2^$k EXP_COMPOSE_BATCHES=16384 EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh forest_plonky3_1machine_6fam_2e$k.csv; done
```

The Count-Min (d = 3), Bloom and KMV rows of Tables 4 and 5 are estimated from the runs above and
these short runs of two 2^14-record batches:

```bash
EXP_DATASET=aol EXP_COMPOSE_N=2^15 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=omc EXP_KMV_K=16384 EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh forest6_deployed_n2e15.csv
EXP_DATASET=aol EXP_COMPOSE_N=2^15 EXP_COMPOSE_BATCHES=16384 EXP_D=3 EXP_W=16384 EXP_COMPOSE_FAMILY=cm EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh forest6_deployed_cm_d3.csv
```

**8. Datasets** (Table 8; its AOL column is item 5's forest run, its memory columns come from items 4 and 6):

```bash
EXP_DATASET=uniform,gaussian,netflix EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh frame_out_1machine_datasets_plonky3.csv
```

**9. Fully concurrent machines** (appendix): all M machines live at once, and one machine next to a busy neighbour:

```bash
for M in 2 3 4; do EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=$M EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs scripts/run_compose.sh frame_out_${M}machine_plonky3_coresident.csv; done
scripts/run_m1_busy_sibling.sh frame_out_1machine_plonky3_busysib.csv ss
```

Figure 5, Table 3, Table 8 and the measured rows of Tables 4 and 5 were measured on an earlier
version of the circuits without zero knowledge. These commands run the current zero-knowledge
circuits, so their times differ from the paper's. The single-batch Bloom and KMV times in the
update-cost section (73.5 s and 35.0 s) come from a standalone measurement that is not in this
repository. How each table is read from the CSVs, and every knob:
[docs/experiments.md](docs/experiments.md) and [docs/six_sketch_comparison.md](docs/six_sketch_comparison.md).



