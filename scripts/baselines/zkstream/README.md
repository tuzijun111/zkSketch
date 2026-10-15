# zkStream comparison harness

A Count-Min update operator built in zkStream's toolchain (ZoKrates 0.8.8,
Groth16 over BN254), following the stateful-operator design in zkStream's §4.4
(Swalens et al., Middleware '24). zkStream ships no sketch and no stateful
operator, so **this is our circuit**. Report it as "a Count-Min operator
following zkStream's design", never as "zkStream".

zkStream's code is not vendored: `../fetch_baselines.sh` clones it at `33c0d68f`
into `$BASELINE_DIR` (default `~/ext-baselines`). Every ZoKrates artifact is
written under `$BASELINE_DIR/build/zkstream`, outside this repo.

## Running

Small scale only: these runs test the harness and give a first conclusion.

```bash
scripts/baselines/zkstream/run_zkstream.py --k 16 64 256 --chunks 4 --tamper
scripts/baselines/zkstream/run_ours.sh
scripts/baselines/zkstream/fit.py
```

Run the two drivers one after the other, never together. Both refuse to start
while a `zokrates`, `exp_compose` or `r0vm` of yours is running, and both pin to
the same 32 hardware threads.

| Variable | Default | Meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | zkStream clone, ZoKrates binary, build dir |
| `BUILD` | `$BASELINE_DIR/build/zkstream` | ZoKrates artifacts |
| `RESULTS` | `results/` next to the scripts | CSVs |
| `PIN_CPUS` | `0-31` | `taskset` CPU list for both provers |
| `MS`, `REPS` | `16 64 256`, `3` | zkSketch batch sizes and repetitions (`run_ours.sh`) |

| Script | Proves | Writes to `$RESULTS` | Measures |
|---|---|---|---|
| `run_zkstream.py` | yes | `zkstream_small.csv` | constraints, compile, setup, witness, prove, verify, bytes and RSS per chunk; forgery rejection |
| `run_ours.sh` | yes | `zks_small.csv` | zkSketch leaf prove, verify, proof bytes and RSS at the same d, w and batch sizes |
| `fit.py` | no | stdout | `a + b·records` fits for both sides, checked against the measured 2^14 leaf |
| `gen.sh` | no | the build dir | instantiates the two templates for one (N, D, W) |
| `sketch_run.sh` | yes | `zkstream_{hll,ss,gk}*.csv`, `zks_sketch_small.csv` | the HLL, SpaceSaving and GK operators and their matched zkSketch leaves; see [the section below](#sketch-family-replay-operators-hll-spacesaving-gk-zkstream-method-our-circuits) |

## How the operator works

- `cm_op.zok.tpl` is proven. It opens a salted Poseidon commitment to the table,
  checks its records against a public batch digest, derives each record's columns
  from one in-circuit hash, applies the increments, and returns the commitment to
  the updated table. Its public statement is three field elements.
- `cm_helper.zok.tpl` is the same body with the asserts turned into outputs. It
  runs through `compute-witness` only, to give the driver the next table and its
  commitment without reimplementing BN254 Poseidon. It is never set up or proven,
  and its time is not charged to the prover.
- Consecutive chunks share a commitment: the driver checks that each chunk's
  `com_in` equals the previous `com_out` and that every proof verifies.
- Counters are 21-bit lanes, so a single counter overflows after 2^21-1 hits.
  That is ample at small scale; a 2^20-record run needs 31-bit lanes (same
  constraint count, since lane weights are constants).

## Reading the results

Both sides pay a fixed cost per batch: the operator pays two commitment chains
and a digest per chunk, and a zkSketch leaf pays a per-batch table term. `fit.py`
therefore fits intercept and slope separately, labels every extrapolation
MODELED, and checks zkSketch's fit against its measured 2^14 leaf before quoting
anything.

At d=3, w=1024 the Groth16 intercept is the larger of the two (about 1.1 s
against 0.1 s), so zkSketch is cheaper per batch at every size measured and
there is no break-even. That depends on the geometry: zkSketch's table term
grows with d*w, so re-check the break-even before quoting it at d=7, w=2^14.

Neither side's small-scale slope is its large-scale slope. zkSketch's slope from
m=16..256 over-predicts its measured 2^14 leaf by about 22%, and the Groth16
prove rate rises with circuit size (83K to 128K constraints/s across k=16..256).

This comparison cannot speak to the proof forest: ZoKrates can express only a
per-batch chain or a Nova recursive chain, never a tree.

## Layout

- `probes/packed8/` holds the probe that established the encoding (1,516
  constraints per record at d=3, w=1024; committed N=16 operator in 44 s / 3.8 GB).
- `probes/port/` holds the first committed-operator and Nova probes.
- `probes/selector/` holds the one-hot selector probes that the packed encoding
  replaced.
- Moved here from `scripts/baselines/{zkstream_cm,zkstream_port,probes}` on
  2026-09-13. The q5b forgery reproduction is deliberately **not** in this repo;
  it lives at `$BASELINE_DIR/private/` pending responsible disclosure.

## Sketch-family replay operators (HLL, SpaceSaving, GK): zkStream method, our circuits

`hll/`, `ss/` and `gk/` hold a HyperLogLog, a SpaceSaving and a Greenwald-Khanna
update operator. zkStream ships none of these sketches and no stateful operator, so
we built each one with zkStream's own general-purpose method. **They are our ZoKrates
circuits.** Call them "a HyperLogLog / SpaceSaving / GK operator following zkStream's
design (our circuit)", never "zkStream". Each family's README has the full method,
soundness evidence and per-point tables. This section puts the three side by side
with zkSketch's own leaves at the same shapes.

### Method (the "replay" baseline)

Each chunk of k records is one Groth16 proof with the public statement
`(com_in, batch_digest, com_out)`, the same as the Count-Min operator. The chunk:

1. opens the salted Poseidon commitment to the previous state (commit-in);
2. checks the records against a public Poseidon batch digest;
3. applies the textbook per-record update, record by record, using fixed-shape loops
   over the whole state. Prover hints (a slot or an insert position) are allowed only
   where the circuit checks them fully;
4. asserts the salted Poseidon commitment to the new state (commit-out).

Chunk c's `com_in` is chunk c-1's `com_out`: zkStream's confidential proof chaining
(Sec 4.3/4.4; `q4a.poseidon.zok:48`, `q4b.poseidon.zok:28-32`, `shared.zok:224-230`).
The engineering follows `packed8`: several state values per field element, strict
unpacking, and "wire refresh" through a private `one` asserted equal to 1.

None of zkSketch's techniques appear:

- no batch-effect certificate;
- no multiset, LogUp or permutation argument;
- no memory-checked recommit;
- no sort-then-group certificate over the batch.

| Family | State | Per-record update in the circuit | Per record at the deployed state (constraints) |
|---|---|---|---|
| HLL | s 6-bit registers, 32 per element | Poseidon(key), strict 254-bit unpack, rank = 1 + leading zeros; mux-tree read, 7-bit compare, one-hot write | 2,124 at s = 2^14 |
| SpaceSaving | s slots (K, C, E), 3 per element | equality scan over all s keys; checked one-hot slot hint; on a miss, s range-checked differences prove the minimum | 511,307 at s = 2^14 |
| GK | n and s' sorted (v, g, Delta) tuples, 1 per element | INSERT at a checked one-hot position with conditional shifts; hint-free COMPRESS (Figure 2 loop) every floor(1/(2 eps)) records | 39,691 at s' = 2^11, eps = 1/51 |

### Configuration

| | ZoKrates operators (ours, zkStream's method) | zkSketch leaves |
|---|---|---|
| Code | `hll/`, `ss/`, `gk/` in this directory | `98113ce` (branch `revision-soundness`, merged into `main`; after the soundness fixes, before hiding), exported with `git archive`, built outside the repo |
| Circuit | `hll_op`, `ss_op`, `gk_op` | `hll_omc`, `ss_final_full`, `gk_bandmerge2` (the pre-M3 `sorted` GK leaf, pinned by `sketch_run.sh` as `OURS_GK_ROUNDS=sorted`; `OURS_GK_ROUNDS=stable` measures the M3 stable-compaction leaf, labelled `gk_bandmerge2_stable`), default binding, Interval statement |
| Proof system | Groth16 (ark) over BN254, per-circuit trusted setup, **zero-knowledge** | batch-STARK (Plonky3) over BabyBear (degree-4 extension), Poseidon2, FRI with log-blowup 2, 54 queries and 15-bit query PoW (124-bit target, `src/config.rs`), transparent, **not zero-knowledge yet** |
| One proof covers | one chunk of k records | one batch of m records (a leaf) |
| Prover cost measured | witness (`compute-witness`) + `generate-proof`, median of the 4 (5 at k=1) chained chunks | trace generation + `prove_all_tables`, median of 5 runs, each a fresh leaf over the first m AOL keys. Both circuits are fixed-shape, so the cost does not depend on the state |
| Verify measured | `zokrates verify` CLI, process start included | in-process leaf audit: pinned to the leaf VK derived from public parameters, STARK-verified, statement checked against the batch log |
| Proof bytes | 997 B JSON (128 B compressed binary) | serialized leaf proof, 355-807 KiB |
| Peak RSS | `/usr/bin/time` around `generate-proof` | sampled `VmRSS` of the process during the measured pass (`proc_max_rss_mb` in the CSV is `/usr/bin/time`) |
| One-time per shape | compile + setup, reported separately | circuit build, not separated (see `proc_wall_s` below) |
| Records | first keys of `data/aol.keys` | the same keys: HLL hashes the key, SS masks it to 29 bits, GK takes `key & 0x1FFFFF` |
| Machine | Threadripper PRO 9975WX, 559 GB, CPUs 0-31 pinned (32 threads), shared | same CPUs pinned, `EXP_COMPOSE_CORES=32` |

**Matched shape.** zkSketch runs at the same state size (registers s, counters s,
or capacity s' and 1/eps) and with m = k records per batch. There is one exception:
`ss_final_full` needs an even batch of at least 2, so its match for the ZoKrates
k = 1 point is m = 2.

The zkSketch runs are `exp_compose` with `EXP_COMPOSE_MODE=forest`, `EXEC=sim` and
`N = m`. That is one batch, so the artifact is the lone leaf and nothing is folded.

`proc_wall_s` is the whole process. It includes loading the dataset, building the
circuit twice and proving twice: the auditor derives the leaf VK by proving a no-op
leaf of the same shape. It is therefore an upper bound on zkSketch's one-time cost
per shape, which is the analog of ZoKrates' compile + setup.

### Running

```bash
scripts/baselines/zkstream/sketch_run.sh --dry-run            # the plan and every command
scripts/baselines/zkstream/sketch_run.sh                      # hll ss gk ours fit compare (several hours)
scripts/baselines/zkstream/sketch_run.sh --deployed ours compare   # zkSketch side only (about 20 min)
scripts/baselines/zkstream/sketch_run.sh --skip-refusals hll ss gk fit
```

| Stage | Runs | Regenerates |
|---|---|---|
| `hll` | `probes grid deployed wall edge`, the sequence of `hll/run_all.sh` | `zkstream_hll.csv`, `zkstream_hll_{constraint,packing}_probe.csv`, `zkstream_hll_<run>.log` |
| `ss` | `grid scaling large deployed`, the commands in `ss/README.md` | `zkstream_ss.csv`, `zkstream_ss_<stage>_<ts>.log` |
| `gk` | `grid sweep validate probes`, the argv lines recorded in `zkstream_gk_20260926.log` | `zkstream_gk.csv`, `zkstream_gk_<ts>.log` |
| `ours` | zkSketch leaves at every ZoKrates point, at the refused and dropped points, and (with `--deployed`) at the deployed shapes | `zks_sketch_small.csv` |
| `fit` | `hll/fit.py`, `ss/fit_ss.py`, `gk/fit_gk.py` | `zkstream_ss_fit.log` |
| `compare` | the tables below, from the CSVs (no proving) | stdout |

- A single sub-stage can be named, e.g. `ss:grid`. `hll:refresh` is opt-in and
  recompiles the wire-refresh probe into `zkstream_hll_refresh_probe_regen.csv`.
  `zkstream_hll_refresh_probe.csv` was assembled by hand, and its CK=none rows come
  from the retired v1 template.
- Every run writes into `results/sketch_run.<ts>.<pid>.tmp/` (gitignored).
- A family's canonical CSVs are replaced only if three conditions hold:
  - all of the family's sub-stages ran and exited 0;
  - no row has `ok=0`, except a compile the budget refused;
  - the expected number of proven points is present (20 / 16 / 18).

  Otherwise the canonical files stay as they are. The previous files are kept under
  `<staging>/<family>/prev/`.
- **Load guard.** Before a family's first command, and before the first `ours` point,
  the script waits until the 1-minute load is at most `MAX_LOAD` (default 8) and no
  `zokrates`, `exp_compose` or `r0vm` of this user is running. After `WAIT_S`
  (default 1800 s) it refuses. Before later commands it waits only for those
  processes, because our own finished runs still lift the load average.
- **Budget.** Every compile runs under `timeout 45m systemd-run --user --scope -p
  MemoryMax=150G`, in the drivers, and every zkSketch run gets the same cap here. The
  script refuses to raise either cap. The cap needs a systemd user session (not docker,
  cron or `su`); the drivers and `require_tools` check for one and stop if it is missing.
- **`ours` revision.** The `ours` stage measures `OURS_REV` (default `HEAD`), exported
  with `git archive`, so it needs a git clone, not a ZIP download. The committed
  `ours` rows were measured at `98113ce`: pass `OURS_REV=98113ce` to reproduce them.
- `--skip-refusals` skips the two compiles known to hit the 45 min limit (HLL s = 2^14
  with k = 1024, and SS s = 2^14 with k = 1) and carries their previous rows over.
  Without it, those two compiles alone take 1.5 h.

### Matched small shapes: ZoKrates vs zkSketch (MEASURED)

MEASURED on 2026-09-26.

- The ZoKrates rows are the family CSVs (shared box, load1 3-8).
- The zkSketch rows are `zks_sketch_small.csv`: 62 points, 298 runs. `sketch_run.sh`
  saw no other prover at any point, and its `load1` column is mostly the load left by
  the harness's own back-to-back 32-thread runs.
- In the tables:
  - "w+p" is witness + prove for one chunk or leaf.
  - "ratio" is ZoKrates w+p / zkSketch w+p.
  - "constraints" is the ZoKrates R1CS size.
- Every ZoKrates proof is 997 B, and every ZoKrates point verified a 4-chunk chain and
  rejected all forgeries. The run-to-run spread of zkSketch's w+p has a median
  (max/min) of 1.11 and a worst case of 1.84, at a 48 ms point.
- `sketch_run.sh compare` prints these tables.

**HyperLogLog** (s registers, k records):

| s | k | constraints | ZoKrates w+p | zkSketch w+p | ratio | ZoKrates verify | zkSketch verify | zkSketch proof | ZoKrates RSS | zkSketch RSS |
|---|---|---|---|---|---|---|---|---|---|---|
| 16 | 4 | 5,191 | 0.088 s | 0.042 s | 2.1x | 6.2 ms | 11.9 ms | 359 KiB | 36 MB | 27 MB |
| 16 | 16 | 17,429 | 0.259 s | 0.060 s | 4.3x | 7.2 ms | 13.3 ms | 404 KiB | 81 MB | 42 MB |
| 16 | 64 | 65,366 | 0.811 s | 0.115 s | 7.0x | 7.1 ms | 14.6 ms | 454 KiB | 241 MB | 100 MB |
| 64 | 4 | 5,650 | 0.101 s | 0.043 s | 2.4x | 6.8 ms | 12.3 ms | 359 KiB | 37 MB | 27 MB |
| 64 | 16 | 19,245 | 0.278 s | 0.059 s | 4.7x | 6.8 ms | 13.3 ms | 404 KiB | 84 MB | 42 MB |
| 64 | 64 | 72,612 | 0.862 s | 0.105 s | 8.2x | 7.6 ms | 14.5 ms | 454 KiB | 265 MB | 100 MB |
| 256 | 4 | 6,410 | 0.110 s | 0.048 s | 2.3x | 6.8 ms | 12.1 ms | 370 KiB | 41 MB | 32 MB |
| 256 | 16 | 20,131 | 0.272 s | 0.066 s | 4.1x | 7.0 ms | 13.3 ms | 404 KiB | 89 MB | 43 MB |
| 256 | 64 | 74,014 | 0.881 s | 0.116 s | 7.6x | 7.5 ms | 14.6 ms | 452 KiB | 271 MB | 99 MB |
| 1024 | 4 | 10,152 | 0.189 s | 0.084 s | 2.3x | 6.6 ms | 14.5 ms | 440 KiB | 62 MB | 63 MB |
| 1024 | 16 | 24,449 | 0.346 s | 0.082 s | 4.2x | 6.3 ms | 14.4 ms | 440 KiB | 110 MB | 65 MB |
| 1024 | 64 | 80,684 | 0.979 s | 0.127 s | 7.7x | 7.2 ms | 16.0 ms | 478 KiB | 302 MB | 106 MB |
| 4096 | 4 | 24,466 | 0.432 s | 0.226 s | 1.9x | 7.2 ms | 16.3 ms | 494 KiB | 141 MB | 197 MB |
| 4096 | 16 | 41,139 | 0.628 s | 0.228 s | 2.8x | 7.2 ms | 16.9 ms | 518 KiB | 206 MB | 197 MB |
| 4096 | 64 | 107,070 | 1.30 s | 0.241 s | 5.4x | 7.3 ms | 16.1 ms | 494 KiB | 417 MB | 203 MB |
| 16384 | 4 | 82,424 | 1.41 s | 0.602 s | 2.3x | 7.5 ms | 14.7 ms | 553 KiB | 462 MB | 730 MB |
| 16384 | 16 | 108,673 | 1.65 s | 0.549 s | 3.0x | 7.2 ms | 15.4 ms | 577 KiB | 550 MB | 710 MB |
| 16384 | 64 | 213,676 | 2.73 s | 0.626 s | 4.4x | 7.4 ms | 17.4 ms | 578 KiB | 910 MB | 722 MB |
| 16384 | 256 | 634,705 | 7.55 s | 0.570 s | 13.2x | 7.0 ms | 15.0 ms | 553 KiB | 2404 MB | 728 MB |
| 16384 | 512 | 1,195,738 | 14.45 s | 1.05 s | 13.8x | 7.3 ms | 18.5 ms | 599 KiB | 4360 MB | 1235 MB |
| 16384 | 1024 | (2,317,804) | compile **refused** (45 min) | 1.14 s | - | - | 18.9 ms | 599 KiB | - | 1308 MB |

**SpaceSaving** (s counters, k records):

| s | k | constraints | ZoKrates w+p | zkSketch w+p | ratio | ZoKrates verify | zkSketch verify | zkSketch proof | ZoKrates RSS | zkSketch RSS |
|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 4 | 3,106 | 0.067 s | 0.043 s | 1.5x | 7.0 ms | 11.9 ms | 355 KiB | 29 MB | 28 MB |
| 8 | 16 | 7,199 | 0.126 s | 0.051 s | 2.5x | 6.6 ms | 13.1 ms | 389 KiB | 44 MB | 34 MB |
| 8 | 64 | 22,538 | 0.311 s | 0.090 s | 3.4x | 7.1 ms | 13.7 ms | 412 KiB | 97 MB | 63 MB |
| 16 | 4 | 5,418 | 0.104 s | 0.055 s | 1.9x | 6.7 ms | 13.1 ms | 389 KiB | 38 MB | 33 MB |
| 16 | 16 | 12,503 | 0.199 s | 0.063 s | 3.1x | 6.9 ms | 13.5 ms | 402 KiB | 64 MB | 44 MB |
| 16 | 64 | 39,794 | 0.506 s | 0.085 s | 5.9x | 7.3 ms | 14.2 ms | 437 KiB | 155 MB | 65 MB |
| 32 | 4 | 9,358 | 0.153 s | 0.063 s | 2.4x | 6.5 ms | 13.4 ms | 402 KiB | 53 MB | 44 MB |
| 32 | 16 | 22,427 | 0.316 s | 0.070 s | 4.5x | 7.0 ms | 13.4 ms | 401 KiB | 98 MB | 45 MB |
| 32 | 64 | 73,622 | 0.864 s | 0.087 s | 10.0x | 7.8 ms | 14.3 ms | 437 KiB | 250 MB | 67 MB |
| 64 | 4 | 17,264 | 0.259 s | 0.084 s | 3.1x | 7.0 ms | 14.2 ms | 437 KiB | 83 MB | 65 MB |
| 64 | 16 | 42,361 | 0.553 s | 0.084 s | 6.6x | 7.0 ms | 14.3 ms | 437 KiB | 171 MB | 65 MB |
| 64 | 64 | 141,604 | 1.54 s | 0.109 s | 14.1x | 7.4 ms | 14.9 ms | 448 KiB | 453 MB | 101 MB |
| 128 | 4 | 33,050 | 0.456 s | 0.105 s | 4.3x | 7.3 ms | 14.8 ms | 448 KiB | 144 MB | 101 MB |
| 128 | 16 | 82,143 | 0.978 s | 0.106 s | 9.2x | 7.3 ms | 14.9 ms | 448 KiB | 302 MB | 102 MB |
| 128 | 64 | 277,242 | 2.96 s | 0.132 s | 22.5x | 7.2 ms | 15.5 ms | 475 KiB | 857 MB | 113 MB |
| 4096 | 1 (zkSketch m=2) | 641,525 | 8.70 s | 2.35 s | 3.7x | 7.8 ms | 16.2 ms | 608 KiB | 2541 MB | 2403 MB |
| 16384 | 1 (zkSketch m=2) | (2,561,735) | compile **refused** twice (45 min) | 7.21 s | - | - | 17.9 ms | 675 KiB | - | 9378 MB |

**Greenwald-Khanna** (1/eps, k records, capacity s'). ZoKrates uses NB = 10 widths
on the grid and NB = 21 on the s' >= 512 probes. zkSketch uses fixed widths.

| 1/eps | k | s' | constraints | ZoKrates w+p | zkSketch w+p | ratio | ZoKrates verify | zkSketch verify | zkSketch proof | ZoKrates RSS | zkSketch RSS |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 4 | 16 | 6,910 | 0.115 s | 0.088 s | 1.3x | 6.2 ms | 14.3 ms | 438 KiB | 45 MB | 67 MB |
| 8 | 4 | 32 | 12,293 | 0.203 s | 0.135 s | 1.5x | 6.6 ms | 15.5 ms | 476 KiB | 66 MB | 111 MB |
| 8 | 4 | 64 | 23,478 | 0.350 s | 0.205 s | 1.7x | 7.1 ms | 15.9 ms | 492 KiB | 113 MB | 198 MB |
| 8 | 16 | 16 | 17,845 | 0.251 s | 0.081 s | 3.1x | 7.3 ms | 14.2 ms | 439 KiB | 80 MB | 70 MB |
| 8 | 16 | 32 | 32,987 | 0.440 s | 0.125 s | 3.5x | 7.0 ms | 15.5 ms | 477 KiB | 137 MB | 116 MB |
| 8 | 16 | 64 | 64,947 | 0.763 s | 0.197 s | 3.9x | 7.3 ms | 15.9 ms | 493 KiB | 242 MB | 206 MB |
| 8 | 64 | 32 | 114,746 | 1.25 s | 0.200 s | 6.2x | 7.1 ms | 15.9 ms | 493 KiB | 366 MB | 208 MB |
| 8 | 64 | 64 | 229,806 | 2.45 s | 0.400 s | 6.1x | 7.2 ms | 17.1 ms | 535 KiB | 739 MB | 380 MB |
| 16 | 4 | 16 | 6,752 | 0.123 s | 0.091 s | 1.3x | 6.5 ms | 14.3 ms | 437 KiB | 44 MB | 67 MB |
| 16 | 4 | 32 | 11,991 | 0.193 s | 0.124 s | 1.6x | 6.8 ms | 15.4 ms | 476 KiB | 65 MB | 111 MB |
| 16 | 4 | 64 | 22,888 | 0.338 s | 0.197 s | 1.7x | 7.0 ms | 15.9 ms | 492 KiB | 111 MB | 198 MB |
| 16 | 16 | 32 | 21,410 | 0.324 s | 0.123 s | 2.6x | 6.8 ms | 15.4 ms | 477 KiB | 100 MB | 114 MB |
| 16 | 16 | 64 | 40,160 | 0.550 s | 0.253 s | 2.2x | 7.2 ms | 15.9 ms | 493 KiB | 178 MB | 207 MB |
| 16 | 64 | 32 | 68,435 | 0.807 s | 0.228 s | 3.5x | 7.0 ms | 16.0 ms | 493 KiB | 254 MB | 210 MB |
| 16 | 64 | 64 | 130,655 | 1.53 s | 0.433 s | 3.5x | 7.3 ms | 17.1 ms | 535 KiB | 459 MB | 390 MB |
| 64 | 32 | 512 | 323,452 | 6.55 s | 1.24 s | 5.3x | 7.7 ms | 18.6 ms | 596 KiB | 2168 MB | 1449 MB |
| 64 | 32 | 1024 | 655,005 | 16.99 s | 4.07 s | 4.2x | 7.5 ms | 17.9 ms | 692 KiB | 5447 MB | 4905 MB |
| 64 | 32 | 2048 | 1,337,224 | 50.31 s | 7.93 s | 6.3x | 8.0 ms | 18.4 ms | 717 KiB | 15426 MB | 9855 MB |

The three GK points that ZoKrates dropped hold at most 16 tuples, which is too few
for the textbook chain; the compiled operator rejects their overflow. zkSketch's
band-merge leaf proves the same three shapes:

- 1/eps = 8, k = 64: 0.241 s;
- 1/eps = 16, k = 16: 0.085 s;
- 1/eps = 16, k = 64: 0.227 s.

Its batch-merge semantics compact differently, so these rows are not matched.

**Reading the tables.**

- **The ratio grows with the records per chunk.** Each extra record adds a full
  O(state) replay to the R1CS. zkSketch's leaf cost is dominated by tables sized to
  the state and to powers of two, so it is nearly flat in m at small m. At the
  largest matched points the ratio is:
  - HLL: 13.8x (s = 2^14, k = 512);
  - SpaceSaving: 22.5x (s = 128, k = 64);
  - GK: 6.3x (s' = 2^11, k = 32).
- **At k = 4 the two sides are close.** The ratio is 1.3-2.4x for HLL and GK and
  1.5-4.3x for SpaceSaving. Groth16's fixed cost is small, and zkSketch pays its
  state-sized tables at any batch size.
- **Memory depends on k.** zkSketch uses more RSS than ZoKrates at GK k = 4 (every
  s'), at HLL s = 2^14 with k <= 16, and at HLL s = 4096 with k = 4. At larger k,
  ZoKrates' prover memory grows with the circuit and passes zkSketch's: 3.5x more at
  HLL s = 2^14, k = 512, and 7.6x more at SpaceSaving s = 128, k = 64.
- **Proofs and verify.** zkSketch's proofs are about 360-810 KiB against 997 B, and
  its verify takes 12-21 ms (in process) against about 7 ms (CLI). Both are the price
  of a transparent hash-based STARK.
- **One-time cost per shape.** At HLL s = 2^14, k = 512:
  - ZoKrates compiles in 1298 s, sets up in 10.7 s and writes a 517 MB proving key;
  - zkSketch's whole process, including two circuit builds and two proves, takes 3.5 s.

### Fits (MEASURED points, fitted; MODELED beyond them)

ZoKrates side, from the family fit scripts (`fit`):

- **HLL.** Constraints follow an exact closed form, checked on 20 compiles plus 22
  probes (`hll/README.md`).
  - Witness + prove = 0.083 s + 11.98 us x constraints (R^2 0.999).
  - Per chunk: a_s + b_s x k, with b = 14.1 ms/record at s = 1024 and 26.3 ms/record
    at s = 2^14.
- **SpaceSaving.** Constraints are exactly 31 x s per record plus fixed terms,
  residual 0 over 18 compiles.
  - Prove = 9.26 us x constraints, a rate of 62K-134K constraints/s.
  - At s = 2^14 that is 511,307 constraints per record: about 3.8-4.9 s of proving
    per record (MODELED).
- **GK.** Constraints are fitted within 11 constraints over 40 compiles.
  - Per record: 557-3,439 constraints at s' = 16..64.
  - At NB = 21 (the reviewed figures): 7,809 at s' = 512, 15,913 at s' = 1024 and
    32,697 at s' = 2048.
  - 39,691 at the deployed eps = 1/51, s' = 2^11.
  - The prove rate falls with size: 134K constraints/s at 7K constraints, 43K/s at
    1.34M.

zkSketch side, least squares over `zks_sketch_small.csv`. Here w+p = a + b x m at a
fixed state:

| Family, state | m measured | a | b (per record) | ZoKrates per record at the same state |
|---|---|---|---|---|
| HLL, s = 2^14 | 4 .. 16,384 (7 sizes) | 0.50 s | 0.83 ms | 26.3 ms (fit), 32x |
| SpaceSaving, s = 2^14 | 2, 16,384 | 7.21 s | 0.44 ms | about 3.8-4.9 s (MODELED), about 10^4 x |
| GK, s' = 2^11 | 32 (1/eps = 64), 16,384 (1/eps = 51) | 7.9 s | 3.3 ms | about 1.9 s (MODELED: 48 s per 25-record chunk), about 580x |

At small m the zkSketch cost is flat. It barely changes from m = 4 to m = 256 at
HLL s = 2^14, so small-shape slopes on this side mostly measure padding steps. The
per-record figures above use the deployed m = 2^14 point.

### Deployed-size costs and feasibility (MODELED unless marked)

The deployed shapes are:

- HLL: s = 2^14 registers;
- SpaceSaving: s = 2^14 counters;
- GK: s' = 2^11 tuples, eps = 1/51. This is the capacity zkSketch's GK is measured
  at, so the baseline's capacity is not inflated.

All three take m = 2^14 records per batch, over a 2^20-record stream (64 batches).
The zkSketch leaves at these shapes are MEASURED (`sketch_run.sh --deployed ours`,
one run each, load1 15-18 from the harness's own preceding runs, no other prover).

| | HLL | SpaceSaving | GK |
|---|---|---|---|
| ZoKrates circuit for one m = 2^14 batch | 35,983,852 constraints | 8.38e9 constraints (31x over the 2^28 radix-2 FFT domain) | 651 M constraints |
| ZoKrates compile at the deployed state | exceeds the 45 min / 150 GB budget. **MEASURED**: k = 1024 refused at 2701 s, and a larger chunk only adds code. Modeled 258 h / 393 GB | exceeds the budget. **MEASURED**: even k = 1 refused twice at 45 min, still running at 55.6 GB | 487x the largest compile that finished (1.34 M, 24 min, 45.8 GB). Not attempted; the constraint model predicts the held-out s' = 2048 compile to within 0.005% |
| ZoKrates, largest feasible chunking | k <= 785 (modeled compile wall). **Derived from measured per-chunk cost**: k = 512, 2,048 proofs x 14.45 s = **8.2 h** (floor 7.65 h) | none compiles at s = 2^14. If it did: prover RAM caps k at 289, giving 3,629 proofs and **46-60 days** | a chunk must contain a COMPRESS pass (k >= 25, 1.28 M constraints, inside the envelope): 41,943 proofs x about 48 s = **about 561 h** |
| zkSketch leaf, m = 2^14 (**MEASURED**) | 14.1 s w+p, 21 ms verify, 693 KiB, 17.3 GB RSS | 14.5 s, 21 ms, 689 KiB, 17.9 GB | 62.2 s, 20 ms, 807 KiB, 82.3 GB |
| zkSketch, 64 leaves for 2^20 records (derived: 64 x measured leaf, no fold) | **15.1 min** | **15.4 min** | **66 min** |
| ZoKrates / zkSketch, whole stream | about 33x (30x at the ZoKrates floor) | about 4,300-5,600x | about 510x |
| Verifier, whole stream | ZoKrates: 2,048 proofs, 2 MB JSON, about 14 s CLI. zkSketch: 64 leaves, 45 MB, about 1.4 s | ZoKrates: 3,629 proofs (modeled). zkSketch: 64 leaves, 45 MB, about 1.4 s | ZoKrates: 41,943 proofs, 42 MB JSON. zkSketch: 64 leaves, 53 MB, about 1.3 s |
| Feasible in ZoKrates at the deployed batch? | **no**, compile over budget; only chunked (k <= 785) | **no**: not even k = 1 compiled within the budget (two attempts), and the modeled prover time is months | **no**, 487x the compile wall |

Notes on the table:

- Both whole-stream columns leave out aggregation. The ZoKrates chain hands the
  verifier every proof, and zkSketch is costed in its per-batch mode. zkSketch's
  forest fold, which gives one O(1) root, adds merge proofs that are not measured here.
- zkSketch's process wall at the deployed shapes is 49 s (HLL), 56 s (SS) and 306 s
  (GK). That includes the second circuit build and prove for the VK derivation.
- **SpaceSaving range.** 46-60 days spans the prove rate: 46 days at the best measured
  Groth16 rate (134K constraints/s), 58-60 days at the fitted and largest-point rates.
- **GK sensitivity.** The 561 h is scaled linearly from the s' = 2048 probe, which ran
  at load1 8.2. The k = 25, eps = 1/51 shape cannot be generated, because `gk/gen.sh`
  needs a power-of-two 1/eps. The stream's total proving work scales with s':
  - about 41.6 G constraints at s' = 2^11;
  - about 9.9 G at s' = 512;
  - about 4.9 G at s' = 256, where a 2^14-record chunk is still 76 M constraints, 57x
    the compile wall.

### Caveats

- **Our circuits, not zkStream.** The ZoKrates operators follow zkStream's method and
  toolchain, but zkStream ships no sketch. Never report them as "zkStream".
- **Zero knowledge.** Groth16 is zero-knowledge, and zkSketch's prover currently is
  not: hiding is not implemented. The comparison therefore puts a hiding baseline next
  to a non-hiding zkSketch. The zkSketch numbers come from `98113ce`
  (merged into `main`), after the soundness fixes and before hiding.
- **Different proof systems and fields.** The two sides differ in several ways:

  | | ZoKrates operators | zkSketch |
  |---|---|---|
  | Proof system | pairing-based SNARK | hash-based STARK |
  | Field | BN254, 254-bit | BabyBear, 31-bit with a degree-4 extension |
  | Setup | per-circuit trusted setup | transparent |
  | Soundness | Groth16's | conjectured FRI soundness, 124-bit target |
  | Proof size | 128 B binary | 355-807 KiB |

  Hash functions (Poseidon vs Poseidon2) and HLL rank definitions also differ. The
  estimates differ statistically, but the cost class does not.
- **Semantics per family.**
  - SpaceSaving: the ZoKrates operator replaces any minimum, while zkSketch keeps a
    certified top-s.
  - GK: the ZoKrates operator runs textbook INSERT/COMPRESS with eps = 1/2^j, while
    zkSketch's leaf is a two-sided band merge of the batch.
  - Both SS and GK are valid instances of their algorithm; the committed states are
    not bit-identical.
- **Small-shape slopes may not hold at scale.**
  - ZoKrates: the Groth16 prove rate rises and then falls with circuit size, and
    compile time is superlinear, a property of ZoKrates itself.
  - zkSketch: cost moves in power-of-two steps.
  - Every deployed ZoKrates figure extrapolates from at most 1.34 M constraints.
- **Binding favours the baseline.** Records are bound by a batch digest, not by
  zkStream's per-message EdDSA signatures, which would cost more per record.
- **Anchoring the chain.** The verifier must check that chunk 0's `com_in` equals the
  commitment to the empty state with a revealed salt.
  - This matters most for SS and GK. `ss_op` opens any committed state whose limbs
    are in range, and `gk_op` opens any committed state: it does not check sortedness
    or the sentinel suffix (its first COMPRESS pass bit-decomposes every word, which
    fixes the field widths only). Their invariants (distinct keys and
    K=0 <=> C=0 for SS; sorted tuples with a sentinel suffix for GK) hold only
    inductively from an empty genesis.
  - The batch digests are unsalted, as in the CM operator. At k = 1 a u32 key can
    therefore be recovered from the public digest by brute force (2^32 Poseidon
    evaluations).
- **Measurement conditions.**
  - The ZoKrates grids ran on a shared box (load1 3-8), and their compile times are
    upper bounds under contention. Prove steps waited for other provers.
  - The zkSketch runs saw no other prover, and each ran under the same 45 min /
    150 GB cap.
  - Integration re-check on a quiet box (load1 0.3-1.5, staged, not promoted):
    `sketch_run.sh ss:scaling` reproduced the SS compile probes with identical
    constraint counts (41,417 / 161,303 / 641,525) in 12 / 49 / 303 s, against the
    recorded 12 / 54 / 313 s.
  - Verify times are not like for like: the ZoKrates CLI includes process start,
    while zkSketch's audit runs in process.
