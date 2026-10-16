# M2 packed-byte Bloom (B1): measurement (2026-10-16)

The other folders here are the implementation, gate, attack and review rounds. This file covers the
**measurer round** (05:49-06:24 +08:00), run on the branch head `63157ed`. The raw data is in `measure/`.

## Verdict

| criterion (plan §4.3, §4.0) | measured | result |
|---|---|---|
| Leaf ALU fill at m = 1,024 after wiring ≤ 0.95 (otherwise m = 960) | **0.707** (185,353 of 2^18 rows, 76,791 rows of headroom) | **pass**: m = 1,024 stays |
| Time for one 16,384-record batch (16 leaves of 1,024 + 15 merges, procs forest, real AOL keys) | **163.9 s** (mean of 4 batches: 164.4 / 161.9 / 163.4 / 165.9 s) | |
| ≤ 0.1 × zk-Analytics Bloom at B = 16,384, i.e. ≤ ~271 s | zk-Analytics is **2,706.6 s ESTIMATED** (k_s 30.07; 2,859.3 s at k_s 31.77). It is not a real proof (user decision) | **16.5x** (16.3-16.7x over the 4 batches; 17.4x at k_s 31.77). This is 107 s under the 10x line (~271 s) |
| Combined peak (worker + coordinator, 0.1 s samples, whole run, ≥ 2 batches, a query per leaf) ≤ 8,192 MiB, target ≤ 7,400 | **4,918 / 4,940 MiB** (two runs) | **pass**: 3.2 GiB under the cap and 2.4 GiB under the target |
| Answers equal `bloom_omc`'s at the same keys, for inserted and absent keys | at m 256, T 8, the omc and packed runs give the same keys and answers, for both tags. All 80 proven answers also equal the native `bloom_omc` and the native packed filter | **pass** |
| Old `bloom_omc` (m 256, T 8) still matches M0 | 113.7 / 113.7 s, 8,288 / 8,275 MiB; M0 had 114.1 s and 8,291 MiB | **reproduced** |

**10x margin.** At 163.9 s, the 10x claim holds as long as the real zk-Analytics Bloom proof takes at least
1,639 s. That is 0.61 × the estimate, or k_s ≥ 18.2 s per 2^20-cycle segment over its 90 segments. The other
families measured k_s at 30.07-31.77 s.

**If queries are counted.** The batch time above follows the memmatch method, which leaves out queries. A
batch's 16 per-leaf queries add 16 × (0.466 s prove + 0.051 s bind) = 8.3 s, for **172.2 s** (15.7x).

**Compared with the old leaf.** `bloom_omc` cannot fit a 16,384-record batch under 8 GiB at any leaf size.
Its best memory-matched forest is m = 256 with 64 leaves, estimated at **938.5 s** and about 9.6 GiB
(memmatch-20261014, 2.9x). The packed leaf is **5.7x faster per batch** at about half the memory.

## Build and load

| | |
|---|---|
| code | Branch `m2-bloom-packed` @ `63157ed0b`, fetched from `/home/binbin/zkSketch` into the sandbox clone `$HOME/zkSketch` (`git fetch /home/binbin/zkSketch m2-bloom-packed && git checkout -q -B m2-bloom-packed FETCH_HEAD`). Status: clean. Every run log records `HEAD=63157ed0b dirty_files_outside_results=0`. |
| build | `cargo build --release --locked --example exp_compose --example exp_bloom_packed --example exp_e0` took 2 min 10 s (05:46-05:48, `measure/build.log`). md5: `exp_compose` `f03e752f6a9e`, `exp_bloom_packed` `1210c36954d9`, `exp_e0` `f4136c81ecb5`. The zk-Analytics side was not built or run, because only its estimate is used. |
| toolchain | rustc 1.97.1 (8bab26f4f 2026-07-14), fresh sandbox toolchains (`HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold`, `RUSTFLAGS` unset) |
| features | Default (zero knowledge): `pcs=hiding`, `logup_mask=on`, recorded in every CSV row. The state commitments are `hiding`, family 7 for packed. |
| harness | **M0 defaults**: every M0 switch is unset. Each `QLOG_WORKER` line confirms `retain_prep=false, trim=Every` and the merge cache (1 entry). In the T = 32 runs it reports `hits=15;misses=16`. |
| host | SPRL6201019991: AMD Threadripper PRO 9975WX, 32 cores / 64 threads, 559 GiB, MemAvailable 431 GiB. All proving is pinned to cores 0-31. |
| load | Another user's PyTorch job ran throughout. It used **1.1 busy cores** (mean; max 2.1), from `runner/loadsample.py` every 5 s (`measure/load_windows.md`). The 1-minute load averaged 17-25 per run, almost all of it from our own 32-core prover. Runs went one at a time, with 60 s of cool-down before each (30 s between isolation probes). |

## 1. Isolated circuits (`measure/iso/`, `runner/iso.sh`)

**Table probe** (`exp_e0 E0_FAMILY=bloom_packed`, `exp_bloom_packed B1_KIND=shapes|all|merge`; Hiding, Interval statement, k = 7, W = 2^14):

| circuit | ALU rows / height (fill, headroom) | other tables | max log h | main / ZK-committed cells | fits hiding |
|---|---|---|---|---|---|
| leaf m = 1,024 (chosen) | 185,353 / 2^18 (**0.707**, 76,791) | range 170,245 / 2^18 (0.649); const 21,515 and permute 21,504 / 2^15; Poseidon2 2,740 / 2^12 | 18 | 14.48 M / 43.32 M | yes |
| leaf m = 960 (fallback) | 176,457 / 2^18 (0.673) | range 163,205 (0.623) | 18 | 14.48 M / 43.32 M | yes |
| leaf m = 768 (fallback) | 149,769 / 2^18 (0.571) | range 142,085 (0.542) | 18 | same padded size | yes |
| decoder (query) | 15,558 / 2^14 (**0.950**, 826) | range 14,688 / 2^14 (0.896); Poseidon2 601 / 2^10 | 14 | 1.12 M / 2.93 M | yes |
| merge (two packed leaves) | 123,012 / 2^17 (0.939, 8,060) | Poseidon2 46,577 / 2^16; recompose 44,742 / 2^16 | 17 | 25.71 M / 42.52 M | yes |

**Prove times in isolation** (32 cores, Hiding; HWM = VmHWM after a reset, in MiB):

| circuit | prove | total (witness + prove + verify) | verify | HWM | proof |
|---|---|---|---|---|---|
| leaf m = 1,024 (3 reps, batch 2 over an 8,000-key prior) | 5.65-6.13 s | 5.75-6.23 s | 21-23 ms | 4,290-4,309 | 862 KB |
| query (3 reps; answers 1 / 0 / 1) | 0.54-0.62 s | 0.63-0.71 s | 17-18 ms | 326-331 | 653 KB |
| merge (2 runs, merge circuit built cold) | | 4.89 / 5.18 s | | 3,479 | 791 KB |

- Leaf circuit build: 0.99 s. Query VK derivation: 0.65 s.
- Compared with the prototype (ALU 245,257 rows, 0.936; leaf 6.0-6.5 s; 4.34-4.39 GB; merge 4.8-5.0 s), the wired leaf is 24 % smaller in ALU rows and as fast or faster.
- The ALU-cliff risk at m = 1,024 is gone.
- **Both remaining full tables have shapes that do not depend on m:**
  - the decoder, at 0.950;
  - the merge, at 0.939.

  Any gate added to either one would double that table's height.

## 2. Two 16,384-record batches in one procs forest (`measure/runs/packed_*_m1024_T32`)

**Command** (`runner/run1.sh <label> <tag> packed 1024 32`, under `memsample.py` rooted at `run_zks.sh`):

```
RESULTS=<dir> SIX_M=1024 SIX_T=32 SIX_BLOOM_VARIANT=packed GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 \
  scripts/baselines/zka/six/run_zks.sh <bloom|bloom_absent>
```

That is:

- forest mode, procs engine, 1 machine with 32 pinned cores;
- N = 32,768 real AOL records in 32 leaves of 1,024, which makes 2 batches of 16 leaves;
- a query after every leaf (the memmatch schedule);
- key mode `first` for `bloom` and `absent` for `bloom_absent`.

Each run took 6.4 min of wall time, under 10 min, so no split was needed.

**Per-batch time.**

- Batch 1 starts at `auditor_new` (worker spawn) and ends with batch 1's own last merge. Batch 2 runs from there to batch 2's own last merge. The remainder is the cross-batch merge and shipping the root.
- The boundaries come from the worker's RSS trace (`runner/humps.py`, `runner/batchsplit.py`): every proof is one RSS hump, and all 63 humps (32 leaves + 31 merges) were found in the Bentley-Saxe order (`runs/*/humps.txt`).
- The CSV formula (memmatch) is (total − one merge) / 2.

| run | batch 1 | batch 2 | cross-batch merge + root | CSV formula, per batch | leaves (s per leaf) | merges (s per merge) | other |
|---|---|---|---|---|---|---|---|
| bloom | 164.4 s | 161.9 s | 5.0 s | 163.5 s | 193.0 s (6.03) | 132.6 s (4.28) | 5.8 s |
| bloom_absent | 163.4 s | 165.9 s | 4.5 s | 164.7 s | 194.6 s (6.08) | 133.3 s (4.30) | 5.9 s |

**Split of one batch.**

- 16 leaves: about 97 s (59 %).
- 15 merges: about 64 s (39 %). The plan expected about 43 %.
- Other (spawn, per-leaf verify): about 3 s.

The in-forest merge (4.29 s) is faster than the cold isolated one (4.9-5.2 s), because the merge cache reuses the circuit.

**Combined peak per phase** (coordinator `exp_compose` + worker `zks_dc_exe_*`, VmRSS summed per 0.1 s sample; `runner/phases.py`):

| phase | bloom: time, combined peak (coord + worker) | bloom_absent: time, combined peak |
|---|---|---|
| VK derivation (decode + prefix auditor) | 7.0 s, 4,292 MiB (coordinator only) | 7.0 s, 4,298 MiB |
| worker: 32 leaves + 31 merges | 331.4 s, **4,918 MiB** (96 + 4,822) | 333.8 s, **4,940 MiB** (101 + 4,839) |
| audit (root-VK derivation, after the worker exits) | 23.6 s, 3,083 MiB | 23.6 s, 3,117 MiB |
| query phase (32 queries + binding) | 24.0 s, 519 MiB | 23.8 s, 420 MiB |
| **whole run** | wall 386.1 s, **4,918 MiB** (4,931 with the 2 wrapper shells) | wall 388.2 s, **4,940 MiB** (4,953) |

- The peak falls on the last leaves (leaves 31-32).
- In the forest, a leaf's worker hump is 4.7-4.8 GB, against 4.3 GB isolated. The difference is the one merge-cache entry plus the kept heap.
- Merge humps are 3.6-4.1 GB.
- The VK derivation (4.3 GB) ends before the worker starts, so the two never overlap.

**Answers.**

| run | answers | proof checks |
|---|---|---|
| bloom (`first`) | all 32 are `1` | 32 `QLOG_BIND` lines, every CSV `status=ok` |
| bloom_absent | all 32 are `0`; every probe key is absent from the inserted prefix | the same |

- Per query: 466 ms prove, 638 KB, 2.5 context proofs, and a 51 ms bind.
- Root proof: 773 KB, verified in 19 ms.

## 3. A/B against `bloom_omc` at m 256, T 8, the M0 configuration (`measure/runs/{omc,packed}_*_m256_T8`)

The same harness, the same binary and the same keys: `SIX_BLOOM_VARIANT=omc|packed SIX_M=256 SIX_T=8`, with both tags.

| phase | omc bloom / absent | packed bloom / absent | M0 B (omc, 2026-10-15) |
|---|---|---|---|
| VK derivation | 18.6 / 18.7 s, 7,786 / 7,764 MiB | 4.1 / 4.0 s, 2,189 / 2,204 MiB | 19.3 s, 7,780 MiB |
| worker: update makespan | **113.7 / 113.7 s**, **8,288 / 8,275 MiB** | **55.8 / 58.4 s**, **3,806 / 3,806 MiB** | 114.1 s, 8,291 MiB |
| of which leaves (s per leaf) / merges (s per merge) | 79.4 (9.92) / 30.5 (4.35); 80.1 (10.01) / 29.8 (4.26) | 24.7 (3.09) / 29.5 (4.21); 26.4 (3.30) / 30.5 (4.35) | 79.6 / 30.5 |
| audit | 14.3 / 14.2 s, 3,104 / 3,110 MiB | 14.3 / 14.3 s, 3,082 / 3,056 MiB | 15.1 s, 3,104 MiB |
| query phase (8 queries) | 73.1 / 74.4 s, 6,691 / 6,578 MiB; 7.2-7.4 s prove per query | 6.3 / 6.2 s, 419 / 392 MiB; 0.49-0.50 s prove per query | 76.6 s, 6,675 MiB |
| whole run | 8,288 / 8,275 MiB (8,302 / 8,287 with the shells) | 3,806 / 3,806 MiB (3,819 / 3,819) | 8,291 MiB |

- **omc reproduces M0:** makespan within 0.4 s, and the peak within 16 MiB.
- At the same m, the packed leaf is about 3x faster: 3.1-3.3 s against 9.9-10.0 s per leaf.
- The merges cost the same in both, because the merge circuit verifies leaf proofs of similar size.
- The packed whole-run peak is 4.4 GiB lower.

**Same keys, same answers.**

| tag | `QLOG_KEY` md5, omc and packed | answers, omc and packed |
|---|---|---|
| bloom | `c72119ec`, the same as M0 and memmatch | all 8 are `1` |
| bloom_absent | `842ebd8b` | all 8 are `0` |

**Native cross-check** (`measure/anscheck/`, a scratch crate linked to the sandbox `zksketch`, outside the repo; `anscheck_m1024.txt`, `anscheck_m256.txt`):

- It rebuilds exp_compose's stream (batch i = AOL keys [i·m, (i+1)·m)).
- After every leaf, it asserts `bits_to_words(bloom_omc bits) == packed bytes`.
- It recomputes each logged query natively with `bloom_contains` (omc) and `packed_contains`.
- Result: **80 / 80 proven answers equal both natives**, with 0 mismatches. That is 32 + 32 at m 1,024 / T 32, and 4 × 8 at m 256 / T 8.

After 32,768 records (16,308 distinct keys), 72,197 of the 114,688 filter bits are set. None of the 40 absent probes was a false positive, so the runs did not exercise a `1` answer on an absent key. The unit test `bloom_variants_answer_identically` covers that case.

## Caveats

- **The zk-Analytics Bloom time is an ESTIMATE:** 94,371,840 padded cycles / 2^20 × k_s (memmatch-20261014), not a real proof. Every multiplier above inherits this.
- **The batch time follows the memmatch method.** It is sequential leaves and merges on one 32-core machine. It excludes the auditor's one-time VK derivation (7 s) and the audit (24 s), and it excludes queries unless stated.
- **Load.** The box is shared, but the external load was light (about 1.1 busy cores). Across the two T = 32 runs, the 4 batches span 161.9-165.9 s (±2 s), and the two whole-run peaks differ by 22 MiB.

## Files (`measure/`)

| path | contents |
|---|---|
| `runner/` | `env.sh`, `run1.sh` (one run under `memsample.py`), `batch.sh`, `iso.sh`, `phases.py`, `humps.py`, `batchsplit.py`, `loadsample.py`, `loadwin.py`, `floor.py`, `memsample.py` (copy of the profile's, unchanged) |
| `iso/` | table probes and isolated leaf, query and merge logs; `index.txt` |
| `runs/<label>/` | harness log and CSV, `meta.txt`, `memsum.txt`, `mem.csv.gz` (0.1 s trace), `phases.json`, `humps.txt` |
| `phases.txt`, `batchsplit.txt`, `load_windows.md`, `load_*.csv`, `batch_*.log` | analysis outputs, load samples and batch logs |
| `anscheck/`, `anscheck_*.txt` | the native answer check: source and output |
