# Memory-matched comparison: zkSketch with an 8 GiB cap vs zk-Analytics (2026-10-14)

**Question.** zkSketch proves each batch as one monolithic leaf STARK, so its peak memory grows with the batch
size. zk-Analytics (RISC Zero) splits execution into fixed 2^20-cycle segments, so its prover stays at about
9.2-9.4 GB. Is zkSketch still faster when its memory is capped?

**Budget.** At most **8,192 MiB** (8.0 GiB) of peak RSS. "Peak RSS" is VmHWM / 1024, as `rss_tree.sh`
reports it. The budget applies to two processes:

- the procs-engine **worker**, which proves the leaves and the merges;
- the **coordinator**, which derives the auditor's verifying keys, proves the per-batch query, and verifies.

Every number below gives both, in that order.

**Method.** RISC Zero caps its segment size; here zkSketch caps its leaf size instead. A batch of B records
is proved as k = B / m_leaf leaves plus (k - 1) merges in zkSketch's proof forest:

- `exp_compose` forest mode, procs engine;
- 1 machine with 32 pinned cores;
- the default **zero-knowledge** build (`pcs=hiding`, `logup_mask=on`);
- AOL keys;
- a query after every leaf.

B follows the paper: **16,384** records for CM, HLL, SS, Bloom and KMV, and **2,048** for GK.

What smaller leaves change:

- **CM, HLL, Bloom, KMV:** updates commute, so the final sketch is the same. The final answers match the
  monolithic leaf exactly: CM 185, HLL 4191638, KMV 8484, Bloom 1.
- **SS, GK:** smaller leaves are smaller batches. That means more merges, and the answers stay within the
  guarantees:
  - SS: the top-1 MG count is 175 for the 4-leaf forest and 177 for the monolithic leaf. The true count is
    180, and the bound is N/(cap+1) = 16.
  - GK: every rank answer is within εN (see `gk_accuracy.txt`).

Run on 2026-10-14 from 13:21 to 14:55 (+08:00), on host SPRL6201019991: AMD Ryzen Threadripper PRO 9975WX,
32 cores / 64 threads, 559 GiB.

## Build

| | |
|---|---|
| zkSketch | sandbox clone `/home/binbin/six-repro-verify/round-shared/home-r3cold/zkSketch` @ `b391842af` (0 changed files). `d4e66a9` (main) differs from it only in two READMEs. `run_all.sh check`: ok, 0 warnings, nothing stale, **no rebuild**. `exp_compose` md5 `792368fe2c7a` (built 2026-10-13 22:14). Features `default:pcs=hiding;logup_mask=on`, recorded per run in `runs/*/six_zksketch_runs.csv`. |
| zk-Analytics | `d4a5a9a90f74` in that sandbox's `ext-baselines/zka`, with the drivers under its `ext-baselines/build`. The GK driver (built 2026-10-13 22:14) has the corrected INSERT Delta. |
| toolchain | rustc 1.97.1, r0vm 3.0.6, rzup 0.5.0 |

Environment for every command:

```
HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold
PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"
PATH="$HOME/.risc0/bin:$PATH"
cd $HOME/zkSketch
```

`runner/env.sh` is this environment.

## Commands (`runner/`)

The scripts ran from a session scratch directory. In these copies, that absolute path is replaced by the
script's own directory; nothing else was changed.

- **`zks.sh <tag> <m> <T> [cap]`:** one harness run:

  ```
  RESULTS=<dir> SIX_M=<m> SIX_T=<T> SIX_GK_CAP=<cap> GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 \
    scripts/baselines/zka/six/run_zks.sh <tag>
  ```

  It uses the per-family environment of `run_zks.sh`:

  | family | settings |
  |---|---|
  | CM | `EXP_D=3 EXP_W=1024` |
  | HLL | `EXP_HLL_B=14` |
  | SS | `EXP_SS_CAP=1024` |
  | GK | `EXP_GK_CAP=<cap> EXP_GK_S=51` |
  | Bloom | `EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14` |
  | KMV | `EXP_KMV_K=1024` |

  The output goes to `results/six/memmatch-20261014/<tag>-m<m>[-cap<c>][-t<T>]`, copied here to `runs/`.
- **`mono.sh <tag> <m> [cap]`:** `zks.sh` with T = 1, which is one monolithic leaf. It runs with a
  MemAvailable watchdog (`memwatch.sh`) that aborts below 60 GiB; the minimum seen was 352 GiB.
- **`chain.sh bloom 256 8`:** the same `exp_compose` command as `run_zks.sh`, with `EXP_COMPOSE_MODE=chain`
  instead of forest. It is a probe only.
- **`zka_exec.sh <M>`:**

  ```
  RESULTS=<dir> SIX_M=<M> SIX_T=1 SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=1 run_zka.sh exec
  ```

  This is the executor only, no proof: epoch 0 of all six families, with the noroot guests plus designed.
  For CM, designed is their shipped guest, the reference. It ran at M = 16,384 and at M = 2,048 (for GK).
  Each driver call took 0.2-1.3 s.
- **`analyze.py`:** writes `memmatch_runs.csv` and `memmatch_estimates.csv`. **`gkcheck.py`:** checks every
  GK answer against the true rank of the first n x m values (key & 0x1FFFFF), which gives `gk_accuracy.txt`.

Formulas:

- **leaf_s** = `leafgen_seq_ms / t`, the mean leaf (witness + prove).
- **merge_s** = `(total_time_ms - leafgen_seq_ms) / (t - 1)`. This is the merges plus the run's other prover
  work: worker spawn, one leaf-circuit build, per-leaf verify. `fold_per_merge_s` = `local_fold_ms / merges`
  is the merge proofs alone.
- **zkSketch time for one batch** = k x leaf_s + (k - 1) x merge_s, on one machine, sequential. Where the
  whole batch (k leaves) was run, the measured `total_time_ms` is used instead.
- **Peak memory** = the run's measured worker and coordinator peaks.
- **zk-Analytics prove time (ESTIMATED)** = padded_cycles / 2^20 x k_s, with two values of k_s:
  - k_s = 30.07 s: the 2026-10-09 run, sum(prove_s) / sum(padded / 2^20) over its 12 aggregation proofs;
  - k_s = 31.77 s: the 2026-10-13 measured 8,192-record HLL proof, 1,342.2 s for 44,302,336 padded cycles.
- **Speedup** = zka / zkS.

None of these times includes the auditor's one-time verifying-key derivation (listed separately below).

## Step 1: check

`run_all.sh check`: ok (0 warnings). At the start, the load was 2.25 and MemAvailable 432 GiB.

## Step 2: leaf-size search, and why T = 2 is not enough

T = 2 runs (2 leaves + 1 merge) first, sized from the known peaks. All are measured, in MiB.

| family | m_leaf | T | worker | coordinator | within 8 GiB |
|---|---|---|---|---|---|
| CM (d3, w1024) | 2048 | 2 | 7,469 | 7,538 | yes |
| CM | 2048 | **8** | **8,725** | 7,538 | **no (worker)** |
| CM | 1024 | 16 | 6,259 | 5,038 | yes |
| HLL (b14) | 2048 | 2 | 6,990 | **8,207** (query phase; 7,077 before queries) | **no (coordinator only)** |
| HLL | 1024 | 2 | 5,034 | 8,191 (query phase; 6,681 before queries) | yes, by 1.4 MiB |
| HLL | 1024 | 16 | 6,183 | **8,540** (query phase; 6,680 before queries) | **no (coordinator only, query phase)** |
| SS (cap 1024) | 4096 | 2 | 6,906 | 6,982 | yes |
| SS | 4096 | 4 | 7,443 | 6,979 | yes |
| KMV (k 1024) | 4096 | 2 | 5,071 | 5,295 | yes |
| KMV | 8192 | 2 | 8,405 | 8,433 | no |
| KMV | 4096 | 4 | 5,605 | 5,169 | yes |
| Bloom (k7, W 2^14) | 512 | 2 | 13,686 | 13,799 | no |
| Bloom | 256 | 2 | 7,745 | 8,029 | yes |
| Bloom | 256 | 8 | **8,489** | 7,970 | **no (worker)** |
| Bloom (chain mode) | 256 | 8 | **8,286** | 8,134 | **no (worker)** |
| Bloom | 256 | 16 | **8,855** | 8,168 | **no (worker)** |
| GK cap 256 | 256 | 2 | 5,096 | 5,362 | yes |
| GK cap 256 | 512 | 2 | 8,573 | 8,665 | no |
| GK cap 256 | 256 | 8 | 5,945 | 5,352 | yes |
| GK cap 128 | 256 | 8 | 5,903 | 5,015 | yes |
| GK cap 128 | 512 | 4 | 8,056 | 7,534 | yes (136 MiB margin) |
| **GK cap 64** | **512** | **4** | **5,610** | **5,396** | **yes** |
| GK cap 64 | 1024 | 2 | 14,838 | 14,921 | no |
| GK cap 32 | 512 | 4 | n/a | n/a | **status=error**: the circuit rejects the capacity overflow (WitnessConflict at the excess rows) |
| GK cap 384 | 128 | 16 | 6,294 | 5,176 | yes |

Findings:

1. **The worker's peak grows with the forest's depth.** It rises by about 0.35-0.6 GiB per doubling of the
   leaf count:
   - CM 2048: +1,256 MiB from T = 2 to 8;
   - GK: +849 from 2 to 8;
   - Bloom: +744 from 2 to 8, then +366 from 8 to 16;
   - SS: +537 from 2 to 4;
   - KMV: +534 from 2 to 4.

   So a T = 2 run understates the peak of a whole batch. CM at m = 2048 passes at T = 2 and fails at T = 8.
   The chosen sizes were therefore **checked by running the whole batch of B records**, except Bloom.

   A likely cause, NOT verified: each live forest peak is a `RecursionOutput`, which keeps an
   `Rc<CircuitProverData>` of the merge circuit that produced it, although the next merge reads only the
   proof. Chain mode keeps a single accumulator and still grew (Bloom 8,286 MiB at T = 8), so part of the
   growth is allocator creep.
2. **HLL (b = 14) and Bloom (7 x 2^14 bits): the query proof alone peaks the coordinator at about 8.0-8.5
   GB, whatever the leaf size.** The query-decode proof is state-sized. Its working set is about 6.6 GB on
   top of a base RSS that creeps by about 20 MiB per query. With a query after each of 16 batches, the HLL
   coordinator reaches 8,540 MiB; before the queries it peaks at 6,680 MiB, from the verifying-key
   derivation. **For HLL only the coordinator exceeds the budget, and only in its query phase.** The batch
   proving fits.
3. **Bloom is state-dominated.** The leaf costs about 7.6 GB even at tiny m (m = 64 was about 7.7 GB
   earlier), and the forest growth then pushes the worker over budget from T = 8 on. **No leaf size meets
   8 GiB for a whole 16,384-record Bloom batch in the current code.** The best is m = 256: within budget at
   T = 2, 8,855 MiB at T = 16, and about 9,600 MiB estimated at k = 64. That estimate is 8,855 + 2 x ~370
   MiB per doubling.
4. **GK capacity.** Every cap from 64 to 2,048 gives status=ok with every rank answer within εN = N/51
   (`gk_accuracy.txt`).
   - **64 is the smallest power of two that is valid on these runs.** With cap 32, the leaf circuit refuses
     to prove: the summary does not fit, the excess rows must be dummies, and the result is WitnessConflict
     with status=error. A cap that is too small is therefore a liveness failure (no proof), never a wrong
     answer.
   - 64 is below the worst-case bound. The `exp_compose` heuristic s·log2(N/s) gives 272, and the
     two-sided sketch's guarantee 2s·ln(N/s + 2) + 2 gives 383.6 at N = 2,048, 451.9 at 4,096 and 591.4 at
     16,384. So the cap-384 forest (m = 128, k = 16) is reported as the worst-case-safe configuration.
   - For comparison, the zk-Analytics GK port holds 66 tuples at 2,048 records.
5. **Merges of merges cost what leaf merges cost.** This is the step-3 check. `fold_per_merge_s` at T = 2
   versus deeper forests:

   | family | T = 2 | deeper forest |
   |---|---|---|
   | KMV | 6.88 | 6.25 (T = 4, 3 merges, one a merge of merges) |
   | SS | 6.46 | 6.18 (T = 4) |
   | CM 2048 | 6.68 | 5.68 (T = 8) |
   | GK cap 256 | 6.54 | 5.49 (T = 8) |
   | Bloom | 4.63 | 4.65 (T = 16) |

6. **The T = 2 formula is conservative.** k x leaf_s + (k - 1) x merge_s, taken from the T = 2 run,
   overestimates the measured whole-batch totals:

   | family | formula (s) | measured (s) | over by |
   |---|---|---|---|
   | HLL, k = 16 | 181.8 | 164.8 | 10 % |
   | SS, k = 4 | 59.0 | 55.1 | 7 % |
   | KMV, k = 4 | 48.3 | 43.3 | 11 % |
   | GK cap 256, k = 8 | 102.1 | 86.3 | 18 % |
   | Bloom, k = 16 | 260.9 | 231.0 | 13 % |

   The reason: T = 2 charges the one-time worker spawn and circuit build to its single merge.

## Steps 4 and 5: per family at the paper batch size B

zkSketch "forest" is the memory-matched configuration; "mono" is one monolithic B-record leaf, measured
here with T = 1. zka is zk-Analytics with the noroot guest, executor-measured cycles and ESTIMATED prove
times (no zka proof was made in this run).

| family | B | chosen m_leaf (k) | zkS forest, 1 batch (s) | forest worker / coord (MiB) | zka user cycles | segments | padded cycles | zka est (s) at k = 30.07 / 31.77 | speedup forest | zkS mono leaf / total (s) | mono worker / coord (MiB) | speedup mono (total) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CM | 16,384 | 1024 (16) | **158.64** measured | 6,259 / 5,038 | 88,650,995 | 91 | 94,896,128 | 2,721.6 / 2,875.2 | **17.2x / 18.1x** | 70.92 / 91.82 | 58,910 / 58,990 | 29.6x / 31.3x |
| HLL | 16,384 | 1024 (16) | **164.84** measured | 6,183 / **8,540** (6,680 before queries) | 82,527,841 | 85 | 88,604,672 | 2,541.2 / 2,684.6 | **15.4x / 16.3x** | 62.69 / 77.92 | 52,656 / 52,729 | 32.6x / 34.5x |
| SS | 16,384 | 4096 (4) | **55.09** measured | 7,443 / 6,979 | 96,967,708 | 100 | 104,857,600 | 3,007.3 / 3,177.0 | **54.6x / 57.7x** | 32.25 / 40.31 | 27,198 / 27,301 | 74.6x / 78.8x |
| GK (cap 64, smallest valid) | 2,048 | 512 (4) | **42.68** measured | 5,610 / 5,396 | 12,862,178 | 14 | 13,893,632 | 398.5 / 421.0 | **9.3x / 9.9x** | cap 64: 38.19 / 47.54 | 29,622 / 29,798 | 8.4x / 8.9x |
| GK (cap 384, worst-case-safe) | 2,048 | 128 (16) | **181.12** measured | 6,294 / 5,176 | same | 14 | same | 398.5 / 421.0 | **2.2x / 2.3x** | paper cap 2048: 71.80 / 91.51 | 59,167 / 59,248 | 4.4x / 4.6x |
| Bloom | 16,384 | 256 (64) | **938.5 ESTIMATED** = 64 x 9.848 + 63 x 4.893, from the T = 16 run (1,064.9 from T = 2) | **~9,600 est (exceeds)** / 8,168 at T = 16 | 88,144,348 | 90 | 94,371,840 | 2,706.6 / 2,859.3 | **2.9x / 3.0x** (est) | 75.43 / 98.37 | 60,967 / 61,056 | 27.5x / 29.1x |
| KMV | 16,384 | 4096 (4) | **43.30** measured | 5,605 / 5,169 | 85,011,047 | 87 | 91,226,112 | 2,616.4 / 2,764.0 | **60.4x / 63.8x** | 19.34 / 23.84 | 15,189 / 15,308 | 109.8x / 116.0x |
| CM, zka designed (their shipped guest, reference) | 16,384 | | 158.64 | | 100,439,836 | 104 | 108,134,400 | 3,101.3 / 3,276.3 | 19.5x / 20.7x | | | |

Reading the table:

- **Memory-matched vs monolithic.**
  - Capping zkSketch at 8 GiB costs 1.4x-2.1x in time against the monolithic leaf's total:

    | family | time cost | worker memory saved |
    |---|---|---|
    | SS | 1.37x | 3.7x |
    | CM | 1.73x | 9.4x |
    | KMV | 1.82x | 2.7x |
    | HLL | 2.12x | 8.5x |

    Cap-64 GK is even faster than its monolithic leaf (42.68 s vs 47.54 s): GK's leaf cost grows faster than
    linearly in m.
  - zkSketch stays **15x-64x** ahead of zk-Analytics' estimate for CM, HLL, SS and KMV, and **9-10x** for
    GK at cap 64. zk-Analytics' own prover peaks at 9.2-9.4 GB, *above* this budget; that was measured
    earlier, not re-run here.
  - Bloom is the exception: about 3x, and it does not fit the budget.
- **zka time model.** This is a CPU prover with default 2^20-cycle segments. Proving with a tighter memory
  limit would need smaller segments (po2 19), which was not measured.
- **Verifying keys.** The auditor derives them from public parameters once per (family, m, forest depth),
  outside the times above:

  | configuration | derivation time (s) |
  |---|---|
  | CM, m = 1024, T = 16 | 25.8 |
  | HLL, m = 1024, T = 16 | 25.3 |
  | SS, m = 4096, T = 4 | 20.1 |
  | KMV, m = 4096, T = 4 | 17.4 |
  | GK cap 64, m = 512, T = 4 | 17.5 |
  | Bloom, m = 256, T = 16 | 29.2 |

  The monolithic B leaves take 20-87 s (`vk_derive_s` in `memmatch_runs.csv`). These derivation phases fit
  the budget for every chosen configuration; the coordinator's peak before its queries is
  `coord_before_queries_mib` in that file.

## Measured vs estimated

| | measured | estimated |
|---|---|---|
| zkSketch CM, HLL, SS, KMV, GK | the whole memory-matched batch of B records (k leaves + k - 1 merges) and every monolithic B leaf: time, worker and coordinator peaks, answers | none |
| zkSketch Bloom | T = 2, 8 and 16 at m = 256 (8 / 16 leaves; 4,096 records at most); the monolithic 16,384-record leaf | the 64-leaf time (k x leaf_s + (k - 1) x merge_s) and its worker peak (~9.6 GiB, extrapolated per doubling). The 64-leaf run itself would take about 24 min with its 64 queries, so it was not run |
| zk-Analytics | executor cycles of every family at B (`zka-m16384/`, `zka-m2048/`) | every prove time = padded / 2^20 x 30.07 or 31.77 s; no proof was made. The r0vm peak of 9.2-9.4 GB is from earlier runs |

## Caveats

- **Shared machine.**
  - Another user's single-threaded python ran throughout. From about 14:20, another user's multi-process
    python jobs added a few busy cores, during the monolithic runs.
  - The `busy:load1=...` gate marks in `six_zksketch_runs.csv` mostly come from the 1-minute load left by
    this run's previous job (GATE_WAIT_S=0, sequential, one heavy job at a time).
  - Timings may be a few percent noisy.
- **HLL m = 1024 at T = 2 fits by 1.4 MiB**, and its coordinator peak is set by the m-independent query
  proof. On 2026-10-13, the same m = 2048 run peaked at 8,168 MiB; today it peaked at 8,207. Peaks this
  close to the budget vary by about ±40 MiB from run to run.
- `runs/*/six_zksketch_*.csv` are the raw `exp_compose` rows. The per-batch proofs were deleted by
  `run_zks.sh`; no `.bin` files were kept.

## Files

- `README.md`: this file.
- `memmatch_runs.csv`: one row per zkSketch run.
- `memmatch_estimates.csv`: per family at B.
- `gk_accuracy.txt`: GK rank answers against the true ranks.
- `runs/<family>-m<m>[-cap<c>][-t<T>][-chain]/`: zkSketch CSVs, logs and `six_zksketch_runs.csv`.
- `runs/zka-m16384/`, `runs/zka-m2048/`: the zk-Analytics executor CSVs and `six_zka_exec.log`.
- `runner/`: the wrapper scripts as run, their console output (`out_*.txt`) and the watchdog logs.
