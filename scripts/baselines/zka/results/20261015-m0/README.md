# M0 harness fixes: A/B measurement (2026-10-15)

This file holds three rounds. The **final measurement is round 2 (measurer)**, directly below, taken on
the branch head `3fd232e`. The two earlier rounds follow it unchanged as history: round 1 (measurer, at
`3fa3e39`) and round 2 (fixer, which produced `f699656` and `3fd232e`).

# Round 2 (measurer), 2026-10-15 06:36-07:36, at `3fd232e`

**Verdict: every M0 measurement exit criterion holds** (plan §5 and §4.1).

| criterion | A: all switches off | B: M0 defaults | result |
|---|---|---|---|
| GK cap 384, m 128, T 16: combined peak ≤ 6.2 GiB (6,349 MiB) | 7,200 MiB (7,211 / 7,188) | **5,214 MiB** (5,201 / 5,227) | **pass**: −1,986 MiB (−27.6 %). The largest B run is 5,227 MiB, 1,122 MiB under the limit (5,239 MiB and 1,110 MiB with the two wrapper shells counted). |
| GK: time no worse than A | update makespan 180.3 s (180.4 / 180.2); wall 251.1 s | update makespan **179.9 s** (179.5 / 180.3); wall **221.9 s** | **pass**: makespan −0.4 s, wall −29.2 s (−11.6 %). With the identity runs added (A 181.3 s, B 179.5 s), the makespan means are A 180.6 s and B 179.8 s. |
| Bloom m 256, T 8: peak reduced by ≥ 1.5 GiB (1,536 MiB) | 11,040 MiB (11,170 / 10,910) | **8,291 MiB** (8,295 / 8,287) | **pass**: −2,749 MiB (−2.68 GiB). The worst pairing (smallest A, largest B) still gives −2,615 MiB. B stays above 8 GiB (8,192 MiB) by about 100 MiB, as the plan expected before B1. |
| Answers identical between A and B | | | **pass**: in all 8 measured runs and all 4 identity runs, the queried keys and the answers are the same. Every query was bound, and every CSV has `status=ok`. |
| Root-VK bytes identical between A and B | | | **pass**: GK `aa12f25422fe57e8` (197 B) and Bloom `657e3dc3b028f1f4` (195 B), in both A and B. These are the same bytes as in round 1, at `3fa3e39`. |

**These numbers agree with round 1** (at `3fa3e39`, three hours earlier):

| | round 1 (A → B) | this round (A → B) |
|---|---|---|
| GK peak | 7,186 → 5,208 MiB | 7,200 → 5,214 MiB |
| Bloom peak | 11,012 → 8,287 MiB | 11,040 → 8,291 MiB |
| GK makespan | 185.6 → 185.1 s | 180.3 → 179.9 s |

Both A and B are about 5 s faster than in round 1, which used the binary built from `3fa3e39` (md5 `ee43a527`). The fixer round, with this round's binary, also measured A at 180.3 s. The shift affects A and B alike.

## Build

| | |
|---|---|
| code | Branch `m0-harness` @ `3fd232e` (tree `a294152c`), fetched from `/home/binbin/zkSketch` into the sandbox clone `$HOME/zkSketch` (`git fetch /home/binbin/zkSketch m0-harness && git checkout -q -B m0-harness FETCH_HEAD`). Status: clean. Every run log records `HEAD=3fd232e4a dirty_files_outside_results=0`. |
| build | `cargo build --release --locked --example exp_compose` finished in 0.03 s with nothing to rebuild: `exp_compose` md5 `38c33b46bc13`, built 04:55, the same binary the fixer measured. `3fd232e` changes only `tests/m0_rss_trim.rs`, which is not part of the example. |
| features | Default: `pcs=hiding`, `logup_mask=on` (zero knowledge), recorded in every CSV row. |
| toolchain | rustc 1.97.1 (8bab26f4f 2026-07-14) |
| A vs B | **The same binary.** A sets `EXP_FOREST_RETAIN_PREP=1 EXP_MALLOC_TRIM=0 EXP_EXIT_BEFORE_AUDIT=0 EXP_MERGE_CACHE=0`. B leaves every switch unset, which gives the defaults: bare peaks, trim after every leaf and cascade step, exit before the audit, and the merge cache with 1 entry. Each log header records the switches (`# m0 switches: ...`), and each `QLOG_WORKER` line records what the worker actually did. A: `merge_cache=off, retain_prep=true, trim=Off`. B: `merge_cache=hits=7;misses=8` for GK and `hits=3;misses=4` for Bloom, `retain_prep=false, trim=Every`. |

## Host and load

**Host.** SPRL6201019991: AMD Threadripper PRO 9975WX, 32 cores / 64 threads, 559 GiB. MemAvailable was about 439 GiB.

**Other users.** Another user's PyTorch job (one python process plus 8 data workers) ran throughout.

**Load sampler.** `runner/loadsample.py` ran for the whole batch. Every 5 s it recorded the 1-minute load and the busy cores of this uid versus other uids, from `/proc/<pid>/stat` deltas.

| run | window | 1-min load, mean / max | other users' busy cores, mean / max | our busy cores, mean |
|---|---|---|---|---|
| gk_A1 | 06:38:11-06:42:24 | 24.2 / 38.5 | 2.92 / 3.75 | 22.6 |
| gk_B1 | 06:43:24-06:47:06 | 28.1 / 32.9 | 3.18 / 3.76 | 21.6 |
| bloom_A1 | 06:48:06-06:52:15 | 28.7 / 35.7 | 3.27 / 3.93 | 24.4 |
| bloom_B1 | 06:53:15-06:57:01 | 24.4 / 31.0 | 3.24 / 4.02 | 23.0 |
| gk_A2 | 06:58:01-07:02:13 | 24.3 / 38.2 | 2.77 / 4.14 | 23.2 |
| gk_B2 | 07:03:13-07:06:56 | 26.1 / 38.1 | 3.26 / 3.80 | 21.5 |
| bloom_A2 | 07:07:56-07:12:03 | 27.9 / 40.3 | 3.22 / 3.96 | 23.8 |
| bloom_B2 | 07:13:03-07:16:48 | 27.0 / 35.7 | 3.23 / 3.78 | 22.9 |

- The external load was steady, at 2.8-3.3 busy cores, so it did not drift between A and B.
- A was re-run anyway, because plan §4.0 (G-time) asks for at least 2 repetitions.
- The 1-minute load is mostly our own 32-core run.
- At each start, the 1-minute load was 4.2 for the first run and 11.5-15.1 after that. It was still decaying from the previous run, after 60 s of cool-down.

## Commands

The environment (`runner/env.sh`) is the sandbox:

```
HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold; PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"; PATH="$HOME/.risc0/bin:$PATH"; unset CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR RISC0_HOME
TMPDIR=/tmp; cd $HOME/zkSketch
```

**One measured run.** `runner/runab.sh <label> <gk|bloom> <m> <T> <cap> <A|B>` runs (the same script as in the earlier rounds):

```
RESULTS=<fresh dir> SIX_M=<m> SIX_T=<T> SIX_GK_CAP=<cap> GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 \
  scripts/baselines/zka/six/run_zks.sh <gk|bloom>
```

- It runs in the background.
- `memsample.py` (the profile's sampler, unchanged) is rooted at the `run_zks.sh` PID and samples the process tree every 0.1 s.
- The sampler's start time is recorded, so that its samples can be aligned with `QLOG_PHASE ... unix_ms`.
- `run_zks.sh` fixes the rest of the configuration:
  - forest mode, procs engine, 1 machine with 32 pinned cores, AOL keys;
  - a query after every batch (the memmatch schedule);
  - GK: `EXP_GK_CAP=384 EXP_GK_S=51`, key mode hot;
  - Bloom: `EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14`, key mode first.

The calls:

- GK: `runab.sh gk_<A|B><n> gk 128 16 384 <A|B>`;
- Bloom: `runab.sh bloom_<A|B><n> bloom 256 8 2048 <A|B>` (the cap does not apply to Bloom).

**Order** (`runner/batch.sh`). The runs went one at a time, with 60 s of cool-down before each:

1. GK A1, GK B1, Bloom A1, Bloom B1;
2. GK A2, GK B2, Bloom A2, Bloom B2.

Every measured run took 3.7-4.2 min of wall time.

**Root-VK identity** (`runner/idrun.sh`, 07:17-07:36):

- the same `exp_compose` environment as `run_zks.sh`, plus `EXP_ROOT_VK_SAVE`, which `run_zks.sh` drops;
- 45 s apart, in the order GK A, GK B, Bloom A, Bloom B;
- not memory-sampled.

**Analysis.**

- `phases.py` splits each trace at the `QLOG_PHASE` marks (`phases.json` per run).
- `table.py` writes `per_run_table.md`; `means.py` writes `means.txt` and `means.json`.
- `answers.py` writes `answers.txt`; `floor.py` writes `floors.txt`; `loadwin.py` writes `load_windows.md`.
- **"Combined"** is the coordinator (`exp_compose`) plus the worker (`zks_dc_exe_*`), VmRSS summed at the same 0.1 s sample. The `run_zks.sh` / `rss_tree.sh` shells add 12 MiB; they are left out here and listed as `peak_tree` in `phases.json`.

## Results by phase (mean of 2 runs; per-run values in `per_run_table.md` and `means.txt`)

**Phase bounds** (`QLOG_PHASE` marks):

| phase | starts at | ends at |
|---|---|---|
| VK derivation | `exp_compose` start | `auditor_new` (`QueryAudit::new`: decode VK and prefix auditor) |
| worker | `auditor_new` | `root_received` (leaves and merges) |
| audit, A | `root_received` | `audit_done`; Exit follows (0.2 s) |
| audit, B | `workers_exited` (Exit and reap, about 0.05 s after `root_received`) | `audit_done` |
| query | `before_query_phase` | `queries_done` |

A peak written "x (c + w)" is the combined peak, with the coordinator's and the worker's RSS at that sample.

### GK (bm2) cap 384, m 128, T 16

| phase | A: time, combined peak | B: time, combined peak | change |
|---|---|---|---|
| VK derivation | 7.5 s, 4,386 MiB | 7.4 s, 4,355 MiB | none (not touched by M0) |
| worker: update makespan | 180.3 s, 7,064 MiB (765 + 6,299) | 179.9 s, **5,214 MiB** (108 + 5,106) | −1,850 MiB: no retained prover data, and trim |
| of which leaves / merges | 94.5 s / 83.9 s | 98.3 s / 78.2 s | leaves +3.8 s (trim page faults); merges −5.7 s (the cache) |
| audit | 27.7 s, **7,200 MiB** (4,565 + 2,635 idle worker) | 21.7 s, 4,514 MiB (coordinator only) | the old whole-run peak is gone |
| query phase (16 queries) | 35.1 s, 5,132 MiB | 12.8 s, 419 MiB | prefix VKs reused from the audit |
| audit + queries | 62.8 s | 34.5 s | −28.3 s |
| **whole run** | **7,200 MiB** (at the audit), wall 251.1 s | **5,214 MiB** (in the worker), wall 221.9 s | |

### Bloom m 256, T 8

| phase | A: time, combined peak | B: time, combined peak | change |
|---|---|---|---|
| VK derivation | 19.3 s, 7,762 MiB | 19.3 s, 7,780 MiB | none (not touched by M0) |
| worker: update makespan | 111.8 s, 9,570 MiB (1,147 + 8,423) | 114.1 s, **8,291 MiB** (122 + 8,169) | −1,279 MiB; +2.3 s |
| of which leaves / merges | 77.5 s / 31.2 s | 79.6 s / 30.5 s | leaves +2.1 s (trim page faults); merges −0.7 s |
| audit | 25.1 s, **11,040 MiB** (7,817 + 3,223 idle worker) | 15.1 s, 3,104 MiB (coordinator only) | the old whole-run peak is gone |
| query phase (8 queries) | 90.9 s, 8,067 MiB | 76.6 s, 6,675 MiB | |
| audit + queries | 116.0 s | 91.7 s | −24.3 s |
| **whole run** | **11,040 MiB** (at the audit), wall 247.6 s | **8,291 MiB** (in the worker), wall 225.3 s | |

### Worker RSS between proofs (`floors.txt`)

The floor is the minimum of each valley below 42 % of the worker's peak, from the 0.1 s trace.

| | GK A | GK B | Bloom A | Bloom B |
|---|---|---|---|---|
| after the first leaf | 1,126-1,168 MiB | 698-774 MiB | 1,508-1,632 MiB | 1,163-1,176 MiB |
| median later floor | 2,399-2,400 MiB | 1,356-1,390 MiB | 2,954-3,002 MiB | 1,618-1,633 MiB |

- In B, the median floor sits about 0.45-0.65 GB above the post-first-leaf level. That difference is the one merge-cache entry, as in the fixer round.
- In A, the floor climbs by 1.2-1.4 GB: the retained prover data plus glibc's kept heap.
- The highest B valleys (2.1 GB for GK, 3.0 GB for Bloom) fall between the merges of a single multi-merge cascade, for example the 4 merges that leaf 16 triggers. Trim runs after a leaf's whole cascade, not between its merges, so these valleys are not trimmed.
- The plan's "within about 0.2 GB" test is `tests/m0_rss_trim.rs`, which the fixer ran on `3fd232e`. It was not re-run here.

## Answers and VKs (`answers.txt`, `idruns/summary.txt`)

**GK.**

- Answers at batches 1-16: `44 170 252 327 395 481 782 896 1002 1116 1231 1343 1454 1550 1664 1778`.
- These are the same in all 4 measured runs and both identity runs, and the same as in round 1, the fixer round and memmatch-20261014.
- The `QLOG_KEY` lines (the queried keys) have md5 `7b91ae66`, as in the earlier rounds.
- There are 16 `QLOG_BIND` and 16 `QLOG_BINDV` lines in every run.

**Bloom.**

- Every answer at batches 1-8 is `1`.
- The `QLOG_KEY` md5 is `c72119ec`, as in the earlier rounds.
- There are 8 binds in every run.

**Root VK** (saved by the auditor, `EXP_ROOT_VK_SAVE`):

| | A | B |
|---|---|---|
| GK | `aa12f25422fe57e8` (197 B) | `aa12f25422fe57e8` |
| Bloom | `657e3dc3b028f1f4` (195 B) | `657e3dc3b028f1f4` |

- B derives it through `QueryAudit::trusted_vk` after the workers exit; A derives it with a fresh `derive_dist_root_vk`.
- The identity runs also timed the update makespan:
  - GK: A 181.3 s, B 179.5 s;
  - Bloom: A 114.0 s, B 115.0 s.

## Observations (none blocks an exit criterion)

1. **Bloom B's update makespan is 2.3 s (2 %) slower than A** (114.1 vs 111.8 s; with the identity runs, 114.4 vs 112.5 s).
   - The leaves account for it: +2.1 s, from the pages that the per-proof `malloc_trim(0)` returns being faulted back in.
   - The plan sets no Bloom time criterion.
   - Bloom's wall time is 22 s shorter in B, from the shorter audit and query phases.
   - The fixer round measured `EXP_MALLOC_TRIM=idle` for Bloom: 110.4 s at 8,350 MiB.
2. **GK has the same trade-off.**
   - B's leaves are 3.8 s slower, and its merges 5.7 s faster (7 cache hits).
   - The net makespan is level with A, not the plan's 162-170 s.
   - The exit criterion ("no worse than A") holds.
3. **Bloom B stays about 100 MiB above 8 GiB.**
   - The worker's leaf, at 8.17 GB with the cache entry, sets the peak.
   - So does the coordinator's `QueryAudit::new`, at 7.78 GB, which M0 does not touch.
   - Round 1 measured `EXP_MERGE_CACHE=0` for Bloom at 7,851 MiB; not repeated here.
   - Either way, Bloom has less than 0.4 GiB of headroom until B1.
4. **The B coordinator peaks are now the next levers for GK.**
   - `QueryAudit::new`: 4.36 GB.
   - The audit's root-VK derivation: 4.5 GB.
   - Neither overlaps the worker any more.

## Files (`measurer_round2/`, plain copies, not git-added)

- **`runs/<label>/`**, one directory per measured run:
  - `meta.txt`: start and end time, load, head, binary md5, switches;
  - `run_zks.stderr`;
  - `six_zksketch_<tag>.log`: the full harness log, with the `QLOG_PHASE` marks, answers, `QLOG_WORKER` and `RSSTREE`;
  - `six_zksketch_<tag>.csv` and `six_zksketch_runs.csv`;
  - `mem.csv.gz`: the `memsample.py` trace;
  - `memsum.txt`;
  - `phases.json`.
- **`idruns/<label>/`**: `log`, `root_vk.bin` and the CSV of each identity run; `summary.txt` holds the VK md5 sums.
- **`per_run_table.md`, `means.txt`, `means.json`, `answers.txt`, `floors.txt`, `load_windows.md`, `load.csv`, `batch.log.gz`.**
- **`runner/`**:
  - the scripts used: `env.sh`, `runab.sh`, `batch.sh`, `idrun.sh`, `memsample.py`, `loadsample.py`, `phases.py`, `table.py`, `means.py`, `answers.py`, `floor.py`, `loadwin.py`;
  - they ran from the session scratch directory `.../scratchpad/m0/r2measure/`, and `batch.sh` hard-codes that path.

---

# History: round 1 (measurer), 2026-10-15 03:16-04:37, at `3fa3e39`

**Verdict: the M0 exit criteria for the measurements hold.**

| criterion (plan §5) | A: all switches off | B: M0 defaults | result |
|---|---|---|---|
| GK cap 384, m 128, T 16: combined peak ≤ 6.2 GiB (6,349 MiB) | 7,186 MiB (7,174 / 7,196 / 7,189) | **5,208 MiB** (5,203 / 5,181 / 5,239) | **pass**: −1,978 MiB (−27.5 %); the largest B run is 5,239 MiB |
| GK: time no worse than A (update makespan) | 185.6 s (188.4 / 183.9 / 184.6) | **185.1 s** (185.6 / 186.2 / 183.4) | **pass**: −0.5 s, which is within run noise (about ±2.5 s). Wall time 255.1 → 226.5 s (−11 %) |
| Bloom m 256, T 8: peak reduced by ≥ 1.5 GiB (1,536 MiB) | 11,012 MiB (11,085 / 10,940) | **8,287 MiB** (8,294 / 8,280) | **pass**: −2,725 MiB (−2.66 GiB). Still above 8 GiB (8,192 MiB), as the plan expected |
| Answers identical between A and B | | | **pass** in every run: GK's 16 rank answers, Bloom's 8 membership answers and the queried keys |
| Root-VK bytes identical between A and B, at these exact shapes | | | **pass**: GK `aa12f25422fe57e8` (197 B) and Bloom `657e3dc3b028f1f4` (195 B), in both A and B (`measure/idruns/`) |

**Two caveats** (details under "Findings"):

- **GK is not faster, contrary to the plan's expectation of 162-170 s.**
  - The merge cache saves about 6 s in merges.
  - `malloc_trim(0)` after every leaf and cascade step costs about 4 s in leaves plus about 4 s in merges.
  - With `EXP_MALLOC_TRIM=0` (one diagnostic run), the makespan is 171.6 s, but the peak is 6,379 MiB, 30 MiB over the 6.2 GiB limit.
- **Bloom fits 8 GiB once the merge cache is off.** With `EXP_MERGE_CACHE=0` (one diagnostic run), the peak is 7,851 MiB at the same time. The plan's statement that Bloom stays above 8 GiB until B1 is true only of the default cache setting.

## Build

| | |
|---|---|
| code | Branch `m0-harness` @ `3fa3e39` (tree `21a71c83`), fetched from `/home/binbin/zkSketch` into the sandbox clone `$HOME/zkSketch` (HOME below). Clean status. |
| build | `cargo build --release --locked --example exp_compose` did nothing: `Finished` in 0.04 s, because the implementer had built this commit. `exp_compose` md5 `ee43a527af87`, built 2026-10-15 03:13. |
| features | Default: `pcs=hiding`, `logup_mask=on` (zero knowledge), recorded in every CSV row. |
| toolchain | rustc 1.97.1 |
| A vs B | **The same binary.** A sets `EXP_FOREST_RETAIN_PREP=1 EXP_MALLOC_TRIM=0 EXP_EXIT_BEFORE_AUDIT=0 EXP_MERGE_CACHE=0`. B leaves all five switches unset, which gives the M0 defaults; `EXP_MERGE_CACHE_ENTRIES` is unset, so 1 entry. Each `run_zks.sh` log header records the switches (`# m0 switches: ...`). |

**Host.** SPRL6201019991: AMD Threadripper PRO 9975WX, 32 cores / 64 threads, 559 GiB.

- MemAvailable was 434-435 GiB throughout.
- Another user's PyTorch job (1 python process at about 100 % plus 8 data workers) ran the whole time.
- Before each run, the gate's 2 s window measured 1.1-1.5 busy cores.
- The 1-minute load at each start was 6-9, or 16.5 / 11.5 when a run followed the previous one quickly. That figure lags our own 32-core runs; each run had about 60-75 s of cool-down before it. During a run, the load was 24-31.

## Commands

The environment (`measure/runner/env.sh`) is the sandbox:

```
HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold; PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"; PATH="$HOME/.risc0/bin:$PATH"; unset CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR RISC0_HOME
TMPDIR=/tmp; cd $HOME/zkSketch
```

**`measure/runner/runab.sh <label> <gk|bloom> <m> <T> <cap> <A|B> [VAR=val ...]`** runs one measurement:

```
RESULTS=<fresh dir> SIX_M=<m> SIX_T=<T> SIX_GK_CAP=<cap> GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 \
  scripts/baselines/zka/six/run_zks.sh <gk|bloom>
```

- It runs in the background, with `memsample.py` (the profile's sampler, unchanged) rooted at the `run_zks.sh` PID and sampling every 0.1 s.
- The sampler's start time is printed, so that its samples can be aligned with `QLOG_PHASE ... unix_ms`.
- `run_zks.sh` fixes the rest of the configuration:
  - forest mode, procs engine, 1 machine with 32 pinned cores, AOL keys;
  - a query after every batch (the memmatch schedule);
  - GK: `EXP_GK_CAP=384 EXP_GK_S=51`, key mode hot;
  - Bloom: `EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14`, key mode first.

Calls:

- GK: `runab.sh gk_<A|B><n> gk 128 16 384 <A|B>`
- Bloom: `runab.sh bloom_<A|B><n> bloom 256 8 2048 <A|B>` (the cap does not apply to Bloom)

**Order.** The runs went one at a time, from 03:16 to 04:18:

1. GK A1, GK B1, Bloom A1, Bloom B1;
2. the re-runs: GK A2, GK B2, Bloom A2, Bloom B2;
3. diagnostic GK B + `EXP_MALLOC_TRIM=0`;
4. a third pair, GK A3 and GK B3, because the GK time difference was within noise;
5. diagnostic Bloom B + `EXP_MERGE_CACHE=0`.

Every run took less than 4.5 minutes of wall time.

**Root-VK identity** (`measure/runner/idrun.sh`, `idall.sh`, 04:19-04:37):

- the same `exp_compose` environment as `run_zks.sh`, plus `EXP_ROOT_VK_SAVE`, which `run_zks.sh` drops;
- GK A, then GK B, then Bloom A, then Bloom B;
- these runs were not memory-sampled; their update times appear below as extra timing samples.

**Analysis.**

- **`phases.py`** splits each trace at the `QLOG_PHASE` marks and writes `phases.json` per run.
- **`table.py`** writes `measure/per_run_table.md`.
- **"Combined"** is coordinator (`exp_compose`) plus worker (`zks_dc_exe_*`) VmRSS, summed at the same 0.1 s sample. The tree also holds the `run_zks.sh` and `rss_tree.sh` shells, which add 12 MiB; they are excluded from the figures here and listed as `peak_tree` in `phases.json`.

## Results by phase (means; per-run values in `measure/per_run_table.md`)

The phases are bounded by `QLOG_PHASE` marks:

| phase | from | to |
|---|---|---|
| VK derivation | `exp_compose` start | `auditor_new` (`QueryAudit::new`: decode VK and prefix auditor) |
| worker | `auditor_new` | `root_received` (leaves and merges) |
| audit | A: `root_received`; B: `workers_exited` | `audit_done` (root-VK derivation and verification) |
| query | `before_query_phase` | `queries_done` |

In B, Exit and reaping the worker took 0.1 s. In A, Exit came after the audit and took 0.2 s.

### GK (bm2) cap 384, m 128, T 16 (3 A runs, 3 B runs)

| phase | A: time, combined peak (coordinator + worker at the peak) | B: time, combined peak |
|---|---|---|
| VK derivation | 7.3 s, 4,363 MiB | 7.4 s, 4,380 MiB |
| worker (update makespan) | 185.6 s, 7,101 MiB (about 780 + 6,322) | 185.1 s, **5,208 MiB** (about 105 + 5,100) |
| of which leaves / merges | 97.3 s / 86.5 s | 101.0 s / 80.5 s (merge cache: 7 hits, 8 misses) |
| audit | 27.2 s, **7,186 MiB** (4,561 + an idle worker of 2,625: the old peak) | 21.3 s, 4,491 MiB (coordinator only) |
| query phase (16 queries) | 34.6 s, 5,171 MiB | 12.6 s, 421 MiB |
| whole run (peak, wall) | **7,186 MiB**, 255.1 s | **5,208 MiB**, 226.5 s |

In the update phase:

- **A:** the worker's RSS floor between proofs climbs from 1.25 GB to 3.26 GB (the retained prover data), and its peak reaches 6.3 GB.
- **B:** the floor stays at 1.3-1.45 GB, about 0.6 GB above the post-first-leaf level of 0.69-0.76 GB. That difference is the one merge-cache entry. The peak stays flat at 5.0-5.1 GB.

The B query phase is shorter and smaller because the query binding reuses the subtree VKs that the audit derived through `QueryAudit`. Query proving itself went from 7.22 to 7.89 s summed over the 16 queries, probably because pages are faulted back in after each trim.

### Bloom m 256, T 8 (2 A runs, 2 B runs)

| phase | A: time, combined peak | B: time, combined peak |
|---|---|---|
| VK derivation | 19.1 s, 7,768 MiB | 19.2 s, 7,788 MiB |
| worker (update makespan) | 115.3 s, 9,573 MiB (about 1,120 + 8,450) | 113.9 s, **8,287 MiB** (about 120 + 8,168) |
| of which leaves / merges | 79.3 s / 33.0 s | 79.0 s / 31.0 s (merge cache: 3 hits, 4 misses) |
| audit | 24.3 s, **11,012 MiB** (7,815 + an idle worker of 3,198: the old peak) | 14.5 s, 3,128 MiB |
| query phase (8 queries) | 90.1 s, 8,086 MiB | 75.9 s, 6,695 MiB |
| whole run (peak, wall) | **11,012 MiB**, 249.3 s | **8,287 MiB**, 223.7 s |

Bloom B is now limited by three single-process peaks of about the same size: the worker's leaf at 8.17 GB with the cache entry (7.76 GB without it), the coordinator's `QueryAudit::new` at 7.79 GB, and the coordinator's query decode at 6.7 GB.

### Extra timing samples (identity runs, no memory sampling)

| run | update makespan | merges |
|---|---|---|
| GK A | 186.9 s | 86.8 s |
| GK B | 184.5 s | 80.9 s |
| Bloom A | 117.9 s | 33.1 s |
| Bloom B | 117.4 s | 32.1 s |

They agree with the measured runs. Over all samples:

- GK: A 186.0 s mean (4 runs), B 184.9 s mean (4 runs).
- Bloom: A 116.2 s (3 runs), B 115.0 s (3 runs).

## Answers and VKs

- **Answers.** GK answers at batches 1-16 are `44 170 252 327 395 481 782 896 1002 1116 1231 1343 1454 1550 1664 1778` in every A, B, diagnostic and identity run; they are the same as the memmatch-20261014 run. Bloom answers are `1` at batches 1-8 in every run.
  - The `QLOG_KEY` lines, which give the queried keys, have identical md5 sums between A and B.
  - Every run binds 16 (GK) or 8 (Bloom) queries (`QLOG_BIND` / `QLOG_BINDV`), and every run has CSV `status=ok`.
- **Root VK.** The root VK saved by the auditor at the measured shapes is byte-identical between A and B:
  - GK: md5 `aa12f25422fe57e8`, 197 bytes;
  - Bloom: md5 `657e3dc3b028f1f4`, 195 bytes.
  - B derives it through `QueryAudit::trusted_vk` after the workers exit; A derives it with a fresh `derive_dist_root_vk`.
- **Not re-run here:** the lib and VK-pin tests, including `plain_vk_pins` with the switches on and off. The implementer ran them; see `implementer_tests/`.

## Diagnostics (one run each, not part of the A/B)

| run | update makespan (leaves + merges) | combined peak | reading |
|---|---|---|---|
| GK B + `EXP_MALLOC_TRIM=0` | **171.6 s** (93.5 + 76.4) | 6,379 MiB (worker 5,618) | Trimming costs about 13.5 s, 7 % of the makespan, and saves about 1.2 GB. Without trim, the cache and bare peaks give the expected speed-up, but the peak is 30 MiB over 6.2 GiB. |
| Bloom B + `EXP_MERGE_CACHE=0` | 116.5 s (79.8 + 32.7) | **7,851 MiB** (worker 7,758) | The one cache entry pins about 0.4-0.5 GB in the Bloom worker; the worker floor is 1.2 GB without it and 1.6-1.7 GB with it. Without the cache, Bloom fits under 8 GiB with 341 MiB to spare, at a time within A's range. |

## Findings for the next round (none blocks the exit criteria)

1. **`malloc_trim(0)` after every leaf and cascade step cancels the time win.**
   - Mean B leaves are 3.7 s slower than A, and B merges are about 4 s slower than with trim off.
   - Freed pages are faulted back in on the next proof.
   - A middle ground could give both: trim only before an idle period or the audit, trim every k steps, keep a pad (`malloc_trim(pad)`, or `mallopt(M_TRIM_THRESHOLD/M_TOP_PAD)` of about 1 GB), or trim only when RSS exceeds a threshold.
   - The no-trim diagnostic already reaches 171.6 s at 6,379 MiB.
2. **The default merge-cache size of 1 entry costs about 0.4-0.6 GB of resident memory** in every run. Bloom's T = 8 forest gets only 3 hits. A per-family default, or turning the cache off when a leaf is near the budget, would bring Bloom under 8 GiB now (7,851 MiB).
3. **The 0.2 GB "RSS returns to the post-first-leaf level" check** (plan §4.1) holds in the worker only without the cache: the Bloom no-cache floor stays within about 0.1 GB. With the default cache, the floor sits about 0.6 GB higher, by design. The unit test `tests/m0_rss_trim.rs` covers the bare + trim path.
4. **Next GK memory levers.** In B the coordinator's audit peaks at about 4.5 GB on its own, and `QueryAudit::new` at about 4.4 GB, both just under the worker's 5.1-5.2 GB. They do not overlap any more.

## Files

- **`measure/runs/<label>/`**, one directory per measurement run:
  - `meta.txt`: start and end time, load, head, binary md5, switches;
  - `run_zks.stderr`;
  - `six_zksketch_<tag>.log`: the full harness log, including the `QLOG_PHASE` marks, answers and `RSSTREE`;
  - `six_zksketch_<tag>.csv` and `six_zksketch_runs.csv`;
  - `mem.csv.gz`: the `memsample.py` trace, with per-process RSS every 0.1 s;
  - `memsum.txt`: the sampler summary and its start time;
  - `phases.json`.
- **`measure/per_run_table.md`**: all 12 measurement runs, per phase.
- **`measure/idruns/<label>/`**: `log`, `root_vk.bin` and the CSV of each identity run; `summary.txt` holds the VK md5 sums.
- **`measure/runner/`**: the scripts used (`env.sh`, `runab.sh`, `idrun.sh`, `idall.sh`, `phases.py`, `table.py`, and a copy of `memsample.py`). They ran from a session scratch directory and write under their parent directory.
- **`implementer_tests/`**: the implementer's test logs and tiny A/B identity runs.

---

# History: round 2 (fixer), 2026-10-15 05:00-06:35

**Code.** Branch `m0-harness` @ `3fd232e` (two commits on top of the measured `3fa3e39`: `f699656` code and tests, `3fd232e` an RSS-test assertion only). Sandbox `exp_compose` md5 `38c33b46bc13`. No circuit, VK, statement or genesis code changed; every switch's off value still restores the pre-M0 path.

**What changed:**

- **Merge-cache memory is now accounted for** (review: major).
  - `ForestCascade::holds_prover_data()` now counts the merge cache's entries.
  - `peaks_hold_prover_data()` is the peaks-only check.
  - `MergeCache::holds_prover_data()` is new.
- **The cascade test now has three arms** (`m0_cascade_over_noop_leaves_holds_no_prover_data`):
  - bare without the cache: holds nothing after any push;
  - bare with the default one-entry cache: the peaks hold nothing, and the only prover data is the single cache entry from t = 2 on;
  - retaining: the peaks hold prover data.
- **`tests/m0_rss_trim.rs` has a cache-on arm.** The plan's 0.2 GB criterion is restated for the cache: RSS stays within 200 MiB of (post-first-leaf + the one entry), where the entry is measured as the RSS step at the merge that fills it.
  - Result: entry +581 to +587 MiB, worst later growth +12 to +20 MiB.
  - Bare + trim: +66 to +68 MiB.
  - Control, retaining and untrimmed: +1,475 to +1,770 MiB.
- **Fingerprint wording fixed.** The docs no longer say the fork's fingerprint is a "second guard". On a hit, the fork fingerprints the cached circuit against itself, so the cache key is the only guard. Soundness is unaffected: the tests pin every hit to the VK derived without the cache, and the auditor never uses the cache.
- **Cache hit/miss counts now include finalization merges** (`ForestCascade::finalize_with_stats`, logged after finalize in `QLOG_WORKER`). GK T = 16 and Bloom T = 8 are perfect trees with 0 finalize merges, so the round-1 counts were already complete.
- **New opt-in trim policy, `EXP_MALLOC_TRIM=idle`.** It trims only before a process idles (coordinator: after VK derivation, after the audit and around queries; worker: after its slice and after cross-slice merges), not between a worker's proofs.
  - The default (unset) is unchanged: trim after every leaf and cascade step as well.
  - `EXP_MALLOC_TRIM=0` is unchanged: never trim.
  - The worker now also trims once after reporting its slice, outside every timing. This was a no-op in the measured runs.

## Tests, on the committed tree

Logs are in `fixer_round2/tests/`. Each log header records `head`, `tree` and `porcelain_lines=0`, so the evidence is tied to a commit.

| log | commit | switches | tests | result |
|---|---|---|---|---|
| `lib_on.txt` | f699656 | on | m0_*, plain_vk_pins (3), dist_root_vk_derivable_* (4), derived_root_vks_match_* (3), inproc_workers_* (3), hiding_end_to_end_{cm_omc, gk_bandmerge2, bloom_omc} (+ GL variants), procs_query_replay, cm_honest_forest_chain_dist, cm_query_prefix_certified_by_live_peaks, audit::, metrics:: | **30 passed**, 30.5 min |
| `lib_off.txt` | f699656 | off (all four) | the same set, without metrics:: | **28 passed**, 30.3 min |
| `rss_on2.txt` | 3fd232e | on | `tests/m0_rss_trim.rs`, all three arms | **passed** |

`3fd232e` changes only `tests/m0_rss_trim.rs`, so the lib evidence on `f699656` stands for it.

## Measurements, same session (06:05-06:33)

Setup: the same `runab.sh`, the same `run_zks.sh` configuration and `memsample.py`, one run at a time with 60 s of cool-down. Load at start was 11-17, with the other user's job running throughout. Files are in `fixer_round2/measure/`.

| run | update makespan s (leaves + merges) | worker-phase peak | combined peak | audit + queries s |
|---|---|---|---|---|
| gk_A4 (all off) | 180.3 (94.3 + 84.1) | 7,157 | **7,353** (audit) | 27.6 + 34.5 = 62.1 |
| gk_B4 (M0 default) | 182.5 (99.3 + 79.8) | 5,201 | **5,201** (5,213 with the shells) | 21.2 + 12.4 = 33.6 |
| gk_Bnocache (B + `EXP_MERGE_CACHE=0`) | 189.9 (99.5 + 86.9) | 5,269 | 5,269 | 21.3 + 12.5 = 33.8 |
| gk_Bidle1 (B + `EXP_MALLOC_TRIM=idle`) | 179.5 (98.0 + 79.6) | 5,760 | 5,760 | 21.3 + 12.3 = 33.6 |
| gk_Bidle2 (B + `EXP_MALLOC_TRIM=idle`) | 172.0 (93.7 + 76.3) | 5,761 | 5,761 | 21.5 + 12.9 = 34.4 |
| bloom_Bidle1 (B + `EXP_MALLOC_TRIM=idle`) | 110.4 (78.0 + 29.3) | 8,350 | 8,350 | 14.8 + 76.2 = 91.0 |

**Answers and queried keys** (`QLOG_KEY` and answer md5) are identical to round 1's A and B in every run: GK `7b91ae66` / `ad3cb35b`, Bloom `c72119ec` / `773e277a`. Every query was bound, and every run has status=ok.

**Readings:**

- **The default still passes the exit criteria in this session.**
  - GK peak 5,201 MiB, against the 6,349 MiB limit.
  - Makespan 182.5 vs A 180.3 s: within the about ±4 s run-to-run noise seen today. Round 1 measured 185.1 vs 185.6.
- **Use wall clock and audit + queries together for time comparisons, not per-phase sums.** B derives the root VK through `QueryAudit`, so the prefix-VK derivations move from the query phase into the audit phase, and A's second no-op leaf disappears.
  - GK audit + queries: A 62.1 s, B 33.6 s.
  - Trim calls fall outside `prove_ms` / `cascade_ms`, but the page faults they cause land inside the next proof. "Leaves" in B therefore include the trim cost: B leaves are 4-5 s slower than A in both sessions.
- **The merge cache for GK:** without it, merges take +7.1 s (86.9 vs 79.8). Its peak cost is nil (5,269 vs 5,201): GK's peak is a merge's high-water mark, and a hit merge does not rebuild the prep. Per the worker floor, the entry itself is about 0.55-0.6 GB (no-cache floor 0.65-0.8 GB, cached 1.27-1.37 GB).
- **The `idle` trim policy for GK:** mean 175.8 s (179.5 / 172.0), against B's mean of 184.4 s over its 5 samples today and in round 1. The cost is +560 MiB (5,761). Without per-proof trims, the worker floor creeps 1.9 → 2.85 GB and the peak 5.04 → 5.66 GB, saturating. It stays under 6.2 GiB with 588 MiB to spare.
- **The `idle` trim policy for Bloom:** 8,350 vs B's 8,280-8,294 (+60 MiB). Bloom's peak is set by the leaf, not by allocator creep.
- **The plan's 162-170 s GK expectation is not reached by any harness setting tried.**
  - Leaves are 94-99 s (16 × about 6 s) and are untouched by M0.
  - A one-entry cache serves 7 of 15 merges and saves about 7 s.
  - No trim between proofs saves about 4-9 s.
  - More cache entries (`EXP_MERGE_CACHE_ENTRIES`) could save about 1 s per further hit, at about 0.6 GB per entry; not measured.
  - The remainder is leaf and merge proving cost, which no harness change removes. The M0 exit criterion, "no worse than A", holds.

## Issue dispositions

- **Review, major (cache keeps prover data; test claims and RSS check ignored it):** **fixed**, see above.
- **Review, minor (fingerprint "second guard"):** **fixed in the docs.** A real second guard would mean rebuilding the circuit on every hit (about 0.37 s per merge). It is not added: correctness rests on the key, and soundness on the auditor-derived VKs.
- **Review, minor (test evidence not tied to the commit):** **fixed**, with re-run, stamped logs (above).
- **Review, minor (per-phase timings not like-for-like; cache counts exclude finalize):** **fixed.** `finalize_with_stats` covers the counts, and this README now reports audit + queries together and wall-clock makespan.
- **Measurement, minor (trim cancels the cache's time gain):** **partly addressed.** `EXP_MALLOC_TRIM=idle` is implemented and measured: GK about 176 s at 5.76 GiB. **The default is unchanged** (trim after every step, as plan §5 specifies). Choosing time over memory, per family, is the user's call.
- **Measurement, minor (one cache entry keeps Bloom above 8 GiB):** **not changed; data recorded.** The cache costs Bloom +436 MiB for about 2 s, and costs GK nothing for about 7 s. A per-family setting (for example `EXP_MERGE_CACHE=0` for Bloom in `run_zks.sh`) is the user's call. The plan's line "Bloom stays above 8 GiB until B1" holds only with the cache on: with it off, Bloom M0 peaks at 7,851 MiB (round 1).
- **Measurement, minor (0.2 GB criterion with the cache):** **fixed** by the restated criterion and the cache-on arm of `tests/m0_rss_trim.rs`.
