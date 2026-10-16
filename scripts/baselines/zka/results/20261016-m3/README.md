# M3 (2026-10-16): GK stable compaction (G1), measured

This README covers the **measurer's** run on 2026-10-16, 00:39-01:13 (+08:00), at branch `m3-gk-stable`
commit `62c20e2`. The other directories here (`implementer/`, `attacker_r*/`, `fixer_r1/`, `review_vk_r*/`,
`sandbox/`, `worktree/`) hold the earlier rounds' logs. Their numbers were taken at older commits and are
superseded by the numbers below.

## Verdict

At **config B** (cap 768, m_leaf 512, 4 leaves + 3 merges per 2,048-record batch), every proof is
zero-knowledge and the scalar build is used. Answers are identical to the old circuit's.

| | old circuit (`sorted`, bm2 as before) | **new circuit (`stable`, G1)** | change |
|---|---|---|---|
| batch time, one 2,048-record batch (T = 4) | 107.1 / 105.3 s (mean 106.2) | **43.8 / 44.1 s (mean 43.96)** | **2.42x faster** |
| batch time, two batches (T = 8), per batch | not run | 42.45 / 42.45 s | |
| per leaf / per merge | 21.2 s / 5.5 s | **6.1 s / 5.9 s** | leaf 3.5x faster |
| combined peak RSS over the whole run (worker + coordinator) | **17,177-17,184 MiB: fails 8 GiB** | **5,152-5,203 MiB: passes** (≤ 8,192; also ≤ the 7,400 target) | 3.3x lower |
| leaf ALU rows (table_probe) | 634,878 → 2^20 | **218,691 → 2^18 (fill 0.834)** | 2.9x fewer rows |

**Comparison with zk-Analytics** (same function, B = 2,048, config B):

- **matched `literal` guest** (zkSketch's `apply_batch2` as written, in their pipeline): 31 segments,
  31,981,568 padded cycles = 30.5 x 2^20. At 30.58-30.62 s per padded 2^20 cycles (from M1's real proofs)
  that is **about 933 s. This is an ESTIMATE, not a real proof.**
  - G1 is **21.2x** faster than it (21.15-21.32x; 22.0x per batch at T = 8).
  - The 10x threshold is about 93.3 s. G1 is at 0.047x of zk-Analytics' time and **passes with 2.1x margin**.
  - The old circuit (106.2 s) is 8.8x and misses.
- **Caveat, the `tuned` guest with real proofs** (M1's headline zk-Analytics number: 336.33 s, real proofs
  334.57 / 338.10 s): G1 is **7.65x** faster (7.59-7.72x). That **misses 10x**, whose threshold is 33.6 s.
  M1 projected 7.3-7.8x for G1 here.
- The plan's G1 estimate for config B was 43-46 s. The measured 43.8-44.1 s is inside it.

**Config A** (cap 384, m 128, T = 16), for comparison with M1's 177 s / 5.2 GiB:

| | old | new |
|---|---|---|
| batch time | 178.7 s (M1: 177.13) | **122.9 / 124.0 s (mean 123.5)** |
| combined peak | 5,229 MiB (M1: 5,200) | **4,866 / 4,872 MiB** |

That is 1.45x faster than the old circuit. Against zk-Analytics `literal` (37 segments, about 1,132 s
ESTIMATED) it is 9.2x; against the `tuned` real proof (352.09 s) it is 2.85x.

## Build and environment

| item | value |
|---|---|
| zkSketch | sandbox clone `/home/binbin/six-repro-verify/round-shared/home-r3cold/zkSketch` at `62c20e284` (branch `m3-gk-stable`), 0 changed files |
| zkSketch binaries | `exp_compose` md5 `cfdce387e772` and `exp_e0` `ee54920ac72c`, built with `cargo build --release --locked` (default features = ZK: `pcs=hiding`, `logup_mask=on`, `commit=hiding`; scalar, no `RUSTFLAGS`) |
| toolchain | rustc / cargo 1.97.1, r0vm 3.0.6 |
| zk-Analytics | zka `d4a5a9a90f74`. `run_all.sh build`: 8 builds rc 0. `run_all.sh check`: ok |
| zk-Analytics driver and guests | `gk_matched` driver md5 `5da238eeaea6`. Guest image ID `3d746b3b…` is the same as M1's. The ELF file md5s differ from M1's (`aggr_gkm` `e0874db097d3`, `querier_gkm` `eacf136f8240`), but the image ID, the loaded program, is identical. |
| host | SPRL6201019991: Threadripper PRO 9975WX, 32 cores / 64 threads, 559 GiB |
| cores | zkSketch worker pinned to cores 0-31 |

Environment: `runner/env.sh` (the sandbox `HOME`, `PATH=/usr/local/bin:/usr/bin:/bin`, cargo and risc0 env;
`CARGO_HOME`, `RUSTUP_HOME`, `CARGO_TARGET_DIR`, `RISC0_HOME` and `RUSTFLAGS` unset).

## Method

- **Harness.** `scripts/baselines/zka/six/run_zks.sh gk`:
  - forest mode, procs engine, 1 machine x 32 cores;
  - AOL keys, a query after every leaf;
  - hiding commitments, `EXP_VERIFY_REPEATS=5`;
  - M0 defaults: no M0 switch set;
  - `SIX_GK_ROUNDS=stable|sorted` picks the variant.
- **Memory.** `runner/memsample.py` is the same file as `latex/redesign_20261014/profile/memsample.py`. It
  sums VmRSS over the whole process tree every 0.1 s. `runner/phases.py` splits the samples at the harness's
  `QLOG_PHASE` marks. "Combined" means coordinator (`exp_compose`) plus worker (`zks_dc_exe_*`).
- **Time.**
  - "Batch time" is the forest makespan (`total_time_ms`: leaves + merges + spawn and witness).
  - The T = 4 runs prove exactly one 2,048-record batch.
  - The T = 8 runs prove two batches: 8 leaves + 7 merges, including 1 cross-batch merge. Their per-batch
    figure is makespan / 2.
  - Leaves are `leafgen_seq_ms`; merges are `local_fold_ms`.
- **Scheduling.** Each run went through `runner/gated.sh`:
  - a 45 s cool-down;
  - then a wait until other users' busy cores were < 6 for 60 s (`runner/loadsample.py`, 5 s samples);
  - a run is CONTAMINATED if other users averaged > 6 busy cores during it.
- **Root VK.** A two-line `zks_bin.sh` wrapper sets `EXP_ROOT_VK_SAVE`, so every run also saves the root VK
  that its auditor derived from public parameters (`root_vk.bin`).
- **Order** (one job at a time, each under 10 min): stB8_1, soB4_1, stB4_1, stA16_1, soA16_1, stA16_2,
  stB4_2, soB4_2, stB8_2. All 9 runs were clean on the first try.

## (1) table_probe of the new leaf (`probe/`, `probe_extra/`; static heights, nothing proved)

`exp_e0`, `E0_FAMILY=gk`, s = 51, hiding commitments, Semantic binding, Interval statement.

| leaf | ALU rows (padded, fill) | range rows (padded) | recompose | permute | const | Poseidon2 | sum of padded rows | fits |
|---|---|---|---|---|---|---|---|---|
| **stable, cap 768, m 512 (config B, the chosen leaf)** | **218,691 (2^18, 0.834)** | 79,376 (2^17) | 62,976 (2^16) | 30,720 (2^15) | 32,011 (2^15) | 2,056 (2^12) | **529,408** | hiding: yes |
| sorted, cap 768, m 512 | 634,878 (2^20, 0.605) | 570,941 (2^20) | 64,000 | 30,720 | 30,739 | 2,056 | 2,233,344 | yes |
| stable, cap 768, m 1,024 | 302,787 (**2^19**, 0.578) | 105,488 (2^17) | 87,552 | 43,008 | 44,811 | 2,568 | 922,624 | yes |
| sorted, cap 768, m 1,024 | 2^20 (0.845, alu+range) | | | | | | 2,364,416 | yes |
| stable, cap 384, m 128 (config A) | 76,036 (2^17, 0.580) | 30,224 (2^15) | 21,248 | 10,240 | 10,763 | 904 | 231,424 | yes |
| sorted, cap 384, m 128 | 212,491 (2^18, 0.811) | 192,587 (2^18) | 21,504 | 10,240 | 10,259 | 904 | 591,872 | yes |

- **m 512 is the chosen leaf size at cap 768.** m 1,024 spills to a 2^19 ALU table, as the plan predicted.
  The extra probes (`probe_extra/`) show that cap 768 / m 768 fits 2^18 at fill 0.995, but 768 does not divide
  2,048. Cap 384 / m 1,024 fits 2^18 at fill 0.898, but cap 384 is not the declared capacity.
- **ALU model.** The plan's G1 model, 22.5·T·L + 42T + 63·cap + 15m ops (T = 1,280, L = 11), gives 426,624
  ops = 213,312 rows at 2 ops per row. The final leaf has 218,691 rows (+2.5 %), after the attack and review
  rounds added checks; the implementer's first build at `4f4d7c0` had 213,635.
- **One honest ZK no-op prove** (`E0_PROVE=1`, cores 0-31): every table's `degree_bits` equals log_h + 1.
  - stable, config B: build + prove 6.9 s, HWM 4,264 MiB;
  - stable, cap 384 m 128: 3.4 s, 1,940 MiB.

## (2) Forest runs (`runs/`, `runtable.md`)

| run | variant | cap / m / T | batch time s (per 2,048 records) | leaves s (per leaf) | merges s (per merge; cache hits/misses) | VK phase s / combined peak MiB | worker phase peak MiB (coord + worker) | audit s / peak | queries s / peak | **whole-run combined peak MiB** | root VK md5 | others' busy cores mean / max |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| stB4_1 | stable | 768 / 512 / 4 | **43.8** | 24.1 (6.03) | 17.7 (5.90; 1/2) | 7.7 / 4,304 | 5,152 (97 + 5,055) | 11.8 / 4,548 | 5.0 / 704 | **5,152** | `988556d9c3df` | 1.14 / 1.32 |
| stB4_2 | stable | 768 / 512 / 4 | **44.1** | 24.6 (6.15) | 17.6 (5.85; 1/2) | 7.4 / 4,354 | 5,190 (94 + 5,096) | 11.5 / 4,558 | 4.9 / 673 | **5,190** | `988556d9c3df` | 1.11 / 1.44 |
| stB8_1 | stable | 768 / 512 / 8 | **42.4** (84.9 / 2); 4 leaves + 3 merges = 38.7 | 46.6 (5.82) | 35.9 (5.13; 3/4) | 7.4 / 4,349 | 5,203 (92 + 5,111) | 16.2 / 4,492 | 9.8 / 698 | **5,203** | `63a26ee79a26` | 1.19 / 2.01 |
| stB8_2 | stable | 768 / 512 / 8 | **42.5** (84.9 / 2); 38.6 | 46.1 (5.77) | 36.2 (5.18; 3/4) | 7.5 / 4,332 | 5,195 (98 + 5,097) | 16.1 / 4,534 | 9.5 / 680 | **5,195** | `63a26ee79a26` | 1.12 / 1.28 |
| soB4_1 | sorted | 768 / 512 / 4 | **107.1** | 85.8 (21.45) | 16.4 (5.46; 1/2) | 23.1 / 16,476 | 17,184 (111 + 17,073) | 11.7 / 4,512 | 5.0 / 685 | **17,184** | `672e75ab9b18` | 1.16 / 1.92 |
| soB4_2 | sorted | 768 / 512 / 4 | **105.3** | 83.7 (20.92) | 16.7 (5.55; 1/2) | 23.0 / 16,451 | 17,177 (112 + 17,065) | 12.1 / 4,533 | 5.0 / 691 | **17,177** | `672e75ab9b18` | 1.13 / 1.68 |
| stA16_1 | stable | 384 / 128 / 16 | **122.9** | 44.4 (2.77) | 76.1 (5.07; 7/8) | 3.8 / 1,979 | 4,866 (98 + 4,768) | 20.6 / 4,533 | 12.0 / 408 | **4,866** | `188a3688cb50` | 1.14 / 1.31 |
| stA16_2 | stable | 384 / 128 / 16 | **124.0** | 43.6 (2.73) | 77.9 (5.20; 7/8) | 3.8 / 1,994 | 4,872 (87 + 4,785) | 20.6 / 4,528 | 12.4 / 410 | **4,872** | `188a3688cb50` | 1.13 / 1.43 |
| soA16_1 | sorted | 384 / 128 / 16 | **178.7** | 97.3 (6.08) | 78.2 (5.21; 7/8) | 7.0 / 4,373 | 5,229 (102 + 5,127) | 20.8 / 4,545 | 12.5 / 417 | **5,229** | `aa12f25422fe` | 1.18 / 1.80 |

**Where a config B batch now goes.** Using stB4 means:

| part | stable G1 | sorted (old) |
|---|---|---|
| 4 leaves | 24.4 s (55 %) | 84.7 s (80 %) |
| 3 merges | 17.6 s (40 %) | 16.5 s (16 %) |
| spawn, witness, first circuit build | about 2 s | about 5 s |

- Merges now cost about as much as a leaf: 5.9 s against 6.1 s. They are the next lever (C1 merge caching
  and bare proofs, or C2).
- Two batches (T = 8) do not grow the memory: the worker phase peaks at 5,195-5,203 MiB, against 5,152-5,190
  MiB at T = 4. That is the M0 trim at work.

**Memory verdict (G-mem).** Config B with G1 peaks at **5,152-5,203 MiB** combined over the whole run, which
passes 8,192 MiB and the 7,400 MiB target. The peak is in the worker phase. The other phases peak lower:

| phase | stable G1 (MiB) | old sorted circuit (MiB) |
|---|---|---|
| VK derivation | 4,304-4,354 | 16,451-16,476 |
| audit | 4,492-4,558 | |
| queries | 673-704 | |

The old circuit fails at 17,177-17,184 MiB, in line with M1's 17,172-17,181.

**GK decode peak at cap 768** (the plan's open item):

- The coordinator's high-water mark while proving one decode (`QLOG_MEM query_hwm_mb`, reset per query) is
  **644-692 MiB** over 24 decodes in the stable config B runs, and 645-684 MiB in the sorted ones.
- Each decode proves in 0.79-0.90 s (mean 0.84) and its proof is about 735 KB.
- The query phase's combined peak is 673-704 MiB; the worker has already exited.
- The decoder is the same circuit for both variants. At cap 384 the decode peaks at 379-410 MiB.

**VK identity (G-base, G-vk).**

- **The old circuit is unchanged.** The `sorted` root VKs that the auditor derived at `62c20e2` are
  byte-identical to M1's at `235c87b`:
  - config B: `672e75ab9b18224e02ab150ff6fa8ab7` = `20261015-m1/measure/runs/gk768x4_*`;
  - config A: `aa12f25422fe57e84bb4d0b9f0090bde` = `gkA_*`.
- **The new variant has its own root VKs**, the same in both repetitions:

  | shape | root VK md5 |
  |---|---|
  | B, T = 4 | `988556d9c3dfc9ac5cfdfe2df675e978` |
  | B, T = 8 | `63a26ee79a261c95354c62995aa13b8b` |
  | A, T = 16 | `188a3688cb505881576e67e241a950a1` |

- **The variant is recorded per run.** The CSV `variant` is `gk_bandmerge2_stable` or `gk_bandmerge2`, and
  `gk_rounds` is `stable` or `sorted`. `m`, `t` and `shape` (`cap768_s51`) are recorded with them.
- Every run has `pcs=hiding`, `logup_mask=on`, `commit=hiding` and `status=ok`. The root verifies in about
  19 ms (best of 5), with a proof of about 791 KB.

## (3) Answers (`answers.txt`, `gkcheck.txt`)

| shape | answers (rank of the hot key after each leaf) | identical across runs and variants |
|---|---|---|
| B, T = 4 | `321 900 1354 1780` | yes: stB4_1/2 = soB4_1/2 |
| B, T = 8 | `321 900 1354 1780 2224 2665 3120 3551` | yes. The first 4 equal the T = 4 runs. Leaves 4 and 8 (1780, 3551) equal zk-Analytics' matched query guest after batches 1 and 2 (`exec/matched_check.csv`: `est=1780`, `est=3551` for all 4 implementations). |
| A, T = 16 | `44 170 252 327 395 481 782 896 1002 1116 1231 1343 1454 1550 1664 1778` | yes: stA16_1/2 = soA16_1, and the same as M0's and M1's GK A answers |

- **Within εN.** `gkcheck.py` compares each answer with the exact rank over the first n·m AOL values
  (key & 0x1FFFFF). The result is ALL_OK in every checked run (stB8_1, stB4_1, soB4_1, stA16_1, soA16_1), with
  err = 0 against the [<v, ≤v] interval every time (εN = N/51).
- **The QLOG_KEY lines are identical** across all runs of each shape.

## (4) zk-Analytics side (`exec/`; executor only, no new proof)

- **The executor matrix at `62c20e2`** (`runner/exec_matrix.sh`, M1 round 3's script) is cycle-for-cycle
  identical to M1's in every matched row. At config B, `literal` epoch 0 has 25,295,367 user cycles,
  31,981,568 padded, 31 segments; epoch 1 has 32,505,856 padded, 31 segments. `journal_eq_native` and
  `state_eq_zksketch` are true in every row. In the 16 `check` rows, state and query both equal zkSketch's.
- **Overflow control.** cap 16 exits with rc 3 and "GK CAPACITY OVERFLOW".
- **The estimate:**
  - padded 2^20 cycles × s per 2^20 = 30.5 × 30.58-30.62 = **932.7-933.9 s, about 933 s (ESTIMATED)**;
  - with epoch 1 (carried state) it is about 948 s, so epoch 0 is the conservative choice;
  - config A: 38,797,312 padded (37.0 × 2^20) gives about 1,132 s, ESTIMATED.
- The real zk-Analytics proofs remain M1's, with the `tuned` guest: 336.33 s (B) and 352.09 s (A). r0vm peaks
  at 9,390-9,401 MiB, above 8 GiB.

## Other checks

- **G-cap in the harness, re-run at `62c20e2`** (`overflow/`). `run_zks.sh gk` with cap 8, m 8, T 4 fails
  with rc 1 and `status=too_large` for both variants:

  > GK capacity overflow: 16 survivors > capacity 8 ... hard error

  This measurer did not re-run the in-circuit and native S = cap / cap + 1 tests; see `attacker_r2/` and
  `fixer_r1/`.
- **Load.** The load sampler ran from 00:39 to 01:12. Over every run window, other users averaged 1.11-1.19
  busy cores, with a maximum of 2.01 (`loadwin.md`). The 1-minute load during runs (18-27) is mostly this
  measurement itself, at about 22 busy cores. Earlier in the evening (before 00:40) the box had a load of
  28-31 from another user's training job; no run overlapped it.

## Files (`measure/`)

| path | contents |
|---|---|
| `runner/` | `build.sh` (sync + build + zk-Analytics build/check), `probe.sh`, `runzks.sh` (one gated run under memsample), `gated.sh` / `gate.py` / `loadsample.py`, `phases.py`, `m3table.py`, `answers.py`, `gkcheck.py`, `loadwin.py`, `exec_matrix.sh`, `jobs.txt` |
| `build.log.gz` | the build |
| `probe/`, `probe_extra/` | exp_e0 logs and `e0_tables` / `e0_summary` CSVs |
| `runs/<label>/` | `meta.txt`, `out/six_zksketch_gk.{log,csv}`, `mem.csv.gz` (gzip it back to `mem.csv` before re-running `phases.py`), `memsum.txt`, `phases.{json,txt}`, `root_vk.bin` |
| `runtable.md`, `answers.txt`, `gkcheck.txt`, `loadwin.md`, `load.csv`, `gated.log` | summaries |
| `exec/` | zk-Analytics executor matrix |
| `overflow/` | the harness overflow runs |
