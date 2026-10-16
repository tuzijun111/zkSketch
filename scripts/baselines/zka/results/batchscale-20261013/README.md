# Batch-size scaling: HLL, SpaceSaving/MG, GK, zkSketch vs zk-Analytics (2026-10-13)

This run compares HyperLogLog, SpaceSaving/MG and Greenwald-Khanna on zkSketch and on the
zk-Analytics architecture at larger batches. A batch (one zk-Analytics epoch) holds
**M = 2,048** or **M = 8,192** records, with **T = 2** batches, on the AOL keys
(`data/aol.keys`; the first 4,096 or 16,384 keys). Queries are at n = 1 and 2.

- **zkSketch:** the default **zero-knowledge** build (`pcs=hiding`, `logup_mask=on`).
  `exp_compose` forest, procs engine, 1 machine with 32 cores, a query after every batch.
- **zk-Analytics:** their pipeline with our textbook ports of HLL, SS and GK (†), using the
  `noroot` aggregation guests (the headline variant). The CM reference is off
  (`SIX_ZKA_CM_REF=0`).
- **Families:** hll, ss and gk only. zkSketch cm, bloom and kmv were **not** run. The
  zk-Analytics executor (`run_zka.sh exec`) always executes all six families, so cm, bloom and
  kmv appear only in the two executor-only tables at the end of each `six_sketch_table.md`.
  Their other rows are `-`.

Run on 2026-10-13 from 21:02 to 21:56 (+08:00), on host SPRL6201019991: AMD Ryzen Threadripper
PRO 9975WX, 32 cores / 64 threads, 559 GiB.

## Build

| | |
|---|---|
| zkSketch | sandbox clone `/home/binbin/six-repro-verify/round-shared/home-r3cold/zkSketch` @ `6a4d984` (0 changed files); binaries built there and current (`run_all.sh check`: ok, 0 warnings, nothing stale, no rebuild); `exp_compose` md5 `792368fe2c7a`; features `default:pcs=hiding;logup_mask=on` (recorded per run in `six_zksketch_runs.csv`) |
| zk-Analytics | `d4a5a9a90f74` in that sandbox's `ext-baselines/zka`; drivers and guest ELFs under its `ext-baselines/build` (ELF md5s in every `six_zka_*_prove.log`) |
| toolchain | rustc 1.97.1, r0vm 3.0.6 (CPU, `ProverOpts::succinct()`), rzup 0.5.0, RISC Zero rust 1.97.0, Python 3.14.4 |

The environment for every command was `HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold`,
with `$HOME/.cargo/env` sourced, `$HOME/.risc0/bin` on PATH and the working directory `$HOME/zkSketch`.

## What was run

This replicates the `run_all.sh quick` chain for custom shapes (`runner/*.sh` are the exact
wrappers). Common environment: `SIX_T=2 SIX_GK_CAP=2048 GATE_WAIT_S=0 SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=0 EXP_VERIFY_REPEATS=5`,
with `SIX_M` and `RESULTS=/home/binbin/zkSketch/results/six/batchscale-20261013/m<M>` set per size.

1. `run_all.sh check`: ok. MemAvailable was 438.3 GiB and the load 0.24.
2. **M = 2048**
   1. `run_zks.sh hll ss gk`. Wall times: 91 s, 48 s and 341 s.
   2. `run_zka.sh exec`.
   3. Plan: `jobs.py --keys data/aol.keys --m 2048 --t 2 --qns 1,2 --aggr 0,1 --roots noroot --cm-ref 0 --select hll,ss,gk --lines > zka_plan.txt`
      (12 jobs). The plan derives the GK rank values natively, because `jobs.py --logs` also needs a
      `bloom_absent` log, which this run lacks. They were checked by hand against the zkSketch
      GK log's `QLOG_KEY` lines: 1810625 at both n, equal.
   4. `run_zka.sh qexec <the 6 planned query jobs>`.
   5. `prof_exec.sh`.
3. **M = 8192**
   1. `run_zks.sh hll ss`. Wall times: 184 s and 95 s.
   2. `run_zka.sh exec`, the plan as above with `--m 8192`, `qexec` and `prof_exec.sh`.
   3. `run_zks.sh gk`, as a separate call. It started at 436 GiB MemAvailable (required: at
      least 300). A watchdog would have aborted it below 40 GiB; the minimum was 280.6 GiB.
      Wall time 808 s. The rank values were 1810625 at n = 1 and 985491 at n = 2, equal to the
      derived plan.
4. **One real zk-Analytics proof at the new scale.** `run_zka.sh prove hll:aggr:0:noroot gk:query:1:1810625`
   in the M = 8192 directory. The launch waited 80 s for our own load average to drop to 8 or
   below; `hll:aggr:0` was then gate=quiet. Results:
   - `hll:aggr:0:noroot`: 43 segments, 1,342.2 s.
   - `gk:query:1:1810625`: 6.0 s.

   No new proof was made at M = 2048, by design.
5. **Assemble.**
   - **M = 8192:** `assemble.py <dir> data/aol.keys --zka six_zka --zks six_zksketch --plan zka_plan.txt`,
     then `table.py`, both unchanged. k = 31.817 s per 2^20 padded cycles, from this directory's
     two proofs.
   - **M = 2048** (no proof in the directory): `runner/assemble_m2048.sh` runs `assemble_cal.py`,
     which is `six/assemble.py` plus `runner/assemble_cal.patch` (made by `runner/mk_assemble_cal.py`).
     The patch adds one branch: when the env var `CAL_K` is set and the directory holds no
     proof, it uses an external calibration instead of exiting. Nothing else changes.
     - CAL_K = 30.073281609195405 = sum(prove_s) / sum(padded_cycles / 2^20) over the 12
       aggregation proofs of the committed 2026-10-09 run (`scripts/baselines/zka/results/six_zka_*_prove.csv`,
       M = 2048, legacy guests, epochs 0 and 7 of all six families).
     - CAL_VERIFY_MS = 10.784 and CAL_RECEIPT_BYTES = 224,854 are the means of the same 12 receipts.

     `table.py` is unchanged. The `est` note of the M = 2048 table names this source.

## Measured vs estimated

| | measured | estimated / derived |
|---|---|---|
| zkSketch (both M) | everything: whole-stream prove (2 leaves + 1 merge), leaf times, root verify (best of 5), proof bytes, worker and coordinator peak RSS, per-query prove / verify / bytes / RSS | "1 epoch" = leafgen_seq_ms / 2 (derived from measured leaves) |
| zk-Analytics, M = 8192 | `hll:aggr:0:noroot` (1,342.206 s, 43 segments, 44,302,336 padded cycles, verify 10.034 ms best of 5, 224,818 B, r0vm peak 9,429 MB); `gk:query:1:1810625` (6.034 s, 1 segment, 131,072 padded, 9.682 ms, 224,106 B, r0vm 1,392 MB); executor cycles of every job | all other prove times = padded cycles x 31.817 s / 2^20 (`est`); their verify / bytes = mean of the 2 measured receipts |
| zk-Analytics, M = 2048 | executor cycles only | **every** prove time = padded cycles x 30.073 s / 2^20 from the committed 2026-10-09 proofs (`est`); verify / bytes = means of those 12 receipts; no RSS |

**Segment model at the new scale.** The one M = 8192 aggregation proof took **31.77 s per 2^20
padded cycles** (31.21 s per segment). The 2,048-record model of 30.07 s per 2^20 predicts
1,270.6 s for it; the measured time is **5.6 % above** that prediction. The committed HLL proof
at 2,048 records took 29.32 s per 2^20. One real proof cannot separate a scale effect from
noise. A foreign single-threaded process (another user, ~100 % of one CPU) ran throughout this
proof.

With k = 30.073 instead of 31.817, every M = 8192 zk-Analytics estimate would be 5.5 % lower:
- per epoch: HLL 1,274 s, SS 1,534 s, GK 1,596 s;
- whole-stream ratios: 34x, 72x and 7.9x instead of 36x, 77x and 8.4x.

## Headline (zkA = zk-Analytics noroot / zkS = zkSketch ZK; s)

| sketch | M | zkA cycles e0 (segments) | zkA prove / epoch | zkS leaf alone | ratio | zkA 2 epochs | zkS 2 batches incl. merge | ratio | zkS peak RSS worker / coordinator (GB = 2^30 B) |
|---|---|---|---|---|---|---|---|---|---|
| HLL | 2048 | 10,383,921 (11) | 330.8 est | 9.25 | 36x est | 661.6 est | 27.28 | 24x est | 6.8 / 8.0 |
| HLL | 8192 | 41,303,437 (43) | 1,347.2 (e0 measured 1,342.2) | 30.45 | 44x | 2,694.4 | 74.93 | 36x | 26.1 / 26.2 |
| SS | 2048 | 13,158,936 (14) | 421.0 est | 5.38 | 78x est | 842.1 est | 19.06 | 44x est | 4.9 / 4.9 |
| SS | 8192 | 49,317,705 (51) | 1,622.7 est | 15.89 | 102x est | 3,245.3 est | 42.36 | 77x est | 13.3 / 13.4 |
| GK | 2048 | 12,983,145 (14) | 406.0 est | 69.93 | 5.8x est | 812.0 est | 166.0 | 4.9x est | 57.8 / 57.9 |
| GK | 8192 | 51,634,168 (54) | 1,688.3 est | 172.6 | 9.8x est | 3,376.6 est | 403.7 | 8.4x est | 133.3 / 133.3 |

The table counts proving time only. zkSketch's run wall time also includes deriving the
verifying key from public parameters: HLL 16.1 / 38.6 s, SS 12.6 / 24.0 s, GK 82.7 / 197.8 s
at M = 2048 / 8192. That derivation sets the GK coordinator's peak.

- **Scaling from 2,048 to 8,192 records (4x).** zk-Analytics user cycles grow 3.98x for HLL
  and GK and 3.75x for SS. zkSketch grows less:
  - leaf: HLL 3.29x, SS 2.95x, GK 2.47x;
  - whole stream: 2.75x, 2.22x, 2.43x.

  So the zkA/zkS gap widens with the batch size for all three.
- **Verify.** zkS root, best of 5: 22.8 / 22.7 / 22.4 ms at M = 2048 and 19.1 / 22.7 / 19.1 ms
  at 8192. zkA is about 10 ms per receipt, one receipt per epoch.
- **Proof size.** zkS root about 804 KB; zkA about 225 KB per epoch receipt.
- **Queries, zkA / zkS proving (s).**

  | sketch | M = 2048, n = 1 | M = 2048, n = 2 | M = 8192, n = 1 | M = 8192, n = 2 |
  |---|---|---|---|---|
  | HLL | 15.04 est / 8.00 | 30.07 est / 7.88 | 15.91 est / 7.93 | 31.82 est / 7.98 |
  | SS | 157.9 est / 0.510 | 330.8 est / 0.448 | 167.0 est / 0.506 | 350.0 est / 0.455 |
  | GK | 3.76 est / 1.59 | 7.52 est / 1.53 | **6.03 measured** / 1.66 | 7.95 est / 1.50 |

  The measured M = 8192 GK query took 6.03 s against an estimate of 3.98 s: a 1-segment
  proof of 2^17 cycles carries fixed overhead, at 48 s per 2^20.

## Caveats

- **The zk-Analytics GK port fails its own native accuracy check at M = 8192.** In both
  aggregation epochs, the certified rank error is 161 > εN = 160.63 (cert/εN = 1.0023), and
  max(g+Δ) = 322 > ⌊2εN⌋ = 321. The actual error is 160 ≤ εN, the journal equals the native
  output and the variants agree.
  - `run_zka.sh exec` and `prof_exec.sh` therefore exit 1 at M = 8192. The rows and cycle
    counts are still written, and the chain was continued by hand (`runner/zka_exec_rest.sh`).
  - The driver proves only when these checks pass, so it would **refuse to prove**
    `gk:aggr:<e>` at this shape. The GK aggregation times at M = 8192 are estimates of a proof
    the driver would not produce.
  - At M = 2048 the check passes (cert 40 ≤ 40.16), although g+Δ = 81 > 80 there too.
  - The GK query rows pass at both sizes.
- **HLL ‡.** zkSketch certifies the raw HLL estimator. Its answers (12,422.5 / 13,011.8 at
  M = 2048; 14,078.0 / 16,373.6 at 8192) are far from exact (1,234 / 2,372; 4,432 / 8,433).
  zk-Analytics applies the linear-counting branch and lands near exact.
- **SS §.** zkSketch releases the top-1 MG count only. The zk-Analytics port releases key,
  count and error.
- **Gate marks.** The `busy:load1=...` marks in `six_zksketch_runs.csv` and `six_zka_jobs.csv`
  come from the 1-minute load average left by the preceding run in this same sequence;
  `gate.sh` found no heavy process of any user. One foreign process (another user's
  single-threaded python) ran from 21:25, during the M = 8192 GK zkSketch run and the HLL
  proof.

## Files

- `m2048/`, `m8192/` hold the small files of `/home/binbin/zkSketch/results/six/batchscale-20261013/m<M>`
  (no proofs were kept; zkSketch's per-batch proofs are deleted by `run_zks.sh`):
  - `six_sketch_table.md`: all tables;
  - `six_sketch_comparison.csv`: one row per operation, with provenance measured / derived / ESTIMATED;
  - `six_zksketch_*`: zkSketch CSVs, logs and run notes;
  - `six_zka_*`: zk-Analytics executor, qexec, profile and proof CSVs and logs;
  - `zka_plan.txt`: the 12 planned jobs;
  - `manifest.txt`: configuration, versions, step return codes and notes.
- `runner/` holds:
  - the wrapper scripts as run, which source a session-scratch `env.sh` that sets the
    environment above;
  - `assemble_cal.patch` and its generator;
  - the wrappers' console output (`*.out.txt`);
  - the memory-watchdog logs.

**Update (2026-10-13, later): the GK accuracy failure is fixed.** The zk-Analytics-side GK port now uses the corrected
INSERT Delta = floor(2 eps (n+1)) - 1 (see `scripts/baselines/zka/gk/README.md`, "INSERT's Delta"). Re-checked with the
executor at 64-16,384 records per epoch (epochs 0 and 1): every accuracy check passes; at 8,192 records max g + Delta is 321
= floor(2 eps N) and the certified error 160 <= eps N = 160.63; noroot user cycles at epoch 0 are 51,465,681 (53 segments)
instead of the 51,634,168 (54) used above, so the GK 8,192 estimates in this directory are about 0.3% high. Its aggregation
can now be proved; it was not re-proved here.
