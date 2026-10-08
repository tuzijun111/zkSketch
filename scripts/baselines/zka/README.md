# zk-Analytics comparison harness

Drivers, results and provenance for the zkSketch vs zk-Analytics comparison
(Zhu et al., "Zero-Knowledge Cloud Analytics", SIGCOMM '26). Their code is not
vendored: `../fetch_baselines.sh` clones it at `d4a5a9a` into `$BASELINE_DIR`
(default `~/ext-baselines`), and the zk-Analytics-side builds go under that
directory too (see Layout).

## Running

```bash
scripts/baselines/fetch_baselines.sh
scripts/baselines/zka/a1_cycles.sh
```

Scripts run from any directory; `common.sh` resolves locations.

| Variable | Default | Meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | zk-Analytics clone and its builds |
| `RESULTS` | `results/` next to the scripts | where CSVs and logs are written |
| `CM_TOPK_SLOTS` | per script | zk-Analytics top-k heap slots, a build-time constant |

`ourcm/`, `zksq/` and `ss_mg/` build against the zkSketch checkout they sit in,
so a worktree measures its own sources.

| Script | Proves | Writes to `$RESULTS` | Measures |
|---|---|---|---|
| `a1_cycles.sh` | no | `a1_cycles.csv` | their CM aggregation guest cycles, T in {100, 8, 1} |
| `sha_accel_control.sh` | no | `sha_accel_control.csv` | the same guest with and without risc0's SHA-256 accelerator patch |
| `accuracy.sh` | no | `accuracy_parity.csv`, `accuracy_parity_summary.txt`, `native_baseline.txt` | Count-Min error laws of both systems; plaintext cost |
| `q_sweep.sh` | yes (`--exec`: no) | `zka_query_sweep.csv` | their whole-prefix CM query over n epochs |
| `our_query.sh` | yes (`DRY_RUN=1`: no) | `zks_query_matched.csv` | zkSketch query cost at the matched d=3, w=1024 |
| `compare.sh` | yes, hours | `zks_matched_*.csv`, `zka_matched.csv`, `q_n*.log` | four-metric update comparison, their query sweep |
| `a234.sh` | yes | `a2_anchor.csv`, `a4_native.log`, `a3_n*.log` | prove-time anchors, their native baseline, query slope |
| `rss_watch.sh` | no | stdout | wraps a command and reports r0vm peak RSS |
| `shipped_exec.sh` | no | `zka_shipped_exec.csv`, `zka_shipped_exec.log` | their three shipped epoch summaries on real AOL epochs, executor only (see below) |
| `sketch_exec.sh` | no (`--prove`: yes) | `zka_{hll,ss,gk}_*.csv` / `.log`, `zka_sketch_exec.log` | OUR HLL, SpaceSaving and GK guests (†) in their architecture; builds and regenerates all executor CSVs (see "Sketch-family guests") |
| `ss_mg/ss_mg_exec.sh` | no | `zka_ss_mg_exec.csv`, `zka_ss_mg_equiv.csv`, `zka_ss_mg_exec.log` | OUR RISC Zero guest running zkSketch's exact SS batch rule (mergeable Misra-Gries), checked against zkSketch's native code (see "zkSketch's SpaceSaving batch rule as a RISC Zero guest") |

`compare.sh`, `q_sweep.sh` and `rss_watch.sh` refuse to start while an `r0vm`
of yours is running, then kill this user's `r0vm` processes around their own
runs. `our_query.sh` kills this user's leftover `exp_compose` workers on exit.
Don't run them next to another job of yours.

## Layout

- `cyc/` drives their guests. It is built once per `CM_TOPK_SLOTS` value into
  `$BASELINE_DIR/build/cyc-t<T>`: T is baked into both the host binary and the
  guest ELF, and a shared target dir let a T=1 build relink binaries another
  script expected at T=100. Its path dependencies go through `.zka`, an
  untracked symlink to the clone that `common.sh` creates.
- Other build locations: `build/ourcm`, `build/zksq`, `build/shaccel` and
  `build/zka-ss-mg` under `$BASELINE_DIR`; `nb-target-<T>` (`accuracy.sh
  native`) and `zka/target` (`a234.sh`, `compare.sh`) inside the clone's
  directory. `compare.sh` S1/S2 and
  `our_query.sh` Q1 build zkSketch's `exp_compose` in this checkout's `target/`.
- `sha2-risc0-accel.patch` is the complete accelerator change: the root
  `[patch.crates-io]`, the `=0.10.6` pins in `aggregator/core` and
  `querier/core`, and the `Cargo.lock` hunk. The `[patch]` section on its own
  does nothing, because the lock keeps sha2 0.10.9.
- `cyc/Cargo.lock` pins the host binaries and builds use `--locked`. The guest
  ELFs resolve from the clone's own `Cargo.lock`; `RISC0_BUILD_LOCKED=1` makes
  risc0-build's nested guest build honour it.
- `results/*.log` are the raw console logs behind the CSVs; `.gitignore`
  re-includes them against the repo-wide `*.log` rule.
- `steelman_plan.md` is a plan snapshot. It cites the pre-move `~/ext-baselines`
  paths, and its premise that their guests run software SHA-256 was later
  refuted (see `sha_accel_control.sh`).

## Provenance

Copied from `~/ext-baselines` on 2026-09-13 and checked by re-running from here:

- all 14 guest ELFs rebuilt at T=1 and T=100 are byte-identical to the ones
  that produced `results/`;
- `a1_cycles.sh` reproduces every cycle count in `a1_cycles.csv`;
- `accuracy.sh accuracy` reproduces `accuracy_parity.csv` and its summary byte for byte;
- `q_sweep.sh --exec` reproduces the measured cycle count at n=4;
- `our_query.sh` with `PHASES=q0 DRY_RUN=1` builds `cmq` from here and runs its
  no-proof path with the same configuration as the measured rows.

Prover timings were not re-run.

`sha_accel_control.csv` was re-measured on 2026-09-13. The 2026-09-12 file had
the same numbers, but its "accel" arm ran the unpatched guest, the same ELF as
the baseline. The new file records both ELF hashes (`90fce45d…` baseline,
`bab5ef8f…` patched). The cycle counts are still identical because their guest
already calls risc0's accelerated SHA-256.

## Shipped-structure arm (revision Step 3, arm A): executor only

`shipped_exec.sh` drives `cyc/src/bin/shipped.rs`. The driver runs zk-Analytics'
own three epoch summary types, unmodified, on real AOL records, for the query
classes zkSketch covers. It measures executor cycles and segment counts only.
**Nothing here was proved.** Every prove-time number below is a model.

| their structure | aggregation guest | query guest, query | our analogue |
|---|---|---|---|
| samples: exact per-key hash table | `aggr_samples` | `querier-guest-samples`, `SumTopk{limit: 10}` | SS heavy hitters |
| histogram: per-key log2 bins, `HISTOGRAM_SLOTS=32` | `aggr_histogram` | `querier-guest-histogram`, `P90` (the only quantile it offers) | GK quantiles |
| cm: 3x1024 table plus a `CM_TOPK_SLOTS` heap | `aggr_cm` | `querier-guest-cm`, `Estimate{key}` and `Topk{limit: 10}` | CM point query |

### Exact configuration

- **Code.** zk-Analytics `d4a5a9a90f74` with unmodified guests. The ELF md5s are
  in the header of `zka_shipped_exec.log` and are unchanged since the 2026-09-13
  validated builds; `aggr_cm` at T=1 is still `90fce45d…`. Guest crates use
  risc0-zkvm **3.0.5** (the clone's `Cargo.lock`, `RISC0_BUILD_LOCKED=1`). The
  host driver uses risc0-zkvm **3.0.6** (`cyc/Cargo.lock`). The executor is
  **r0vm 3.0.6**, reached over IPC through `default_executor()`.
- **Build-time constants.** `CM_TOPK_SLOTS` is 100 (their default) or 1, each in
  its own target dir. `HISTOGRAM_SLOTS=32`, `SAMPLES_HT_BUCKETS=1024` and
  `CM_ROWS x CM_COLS = 3 x 1024` are left at their defaults.
- **Hashing.** Everything the guests hash (batch chain, state commits, Merkle
  roots) is SHA-256 through risc0's accelerated `sha::rust_crypto`. CM columns
  use FNV-1a over the 15-byte key, then a splitmix64 finaliser with the per-row
  `CM_SEEDS`.
- **Records.**
  - Source: `data/aol.keys`, a flat little-endian u32 stream of 2^20 keys.
  - Slicing: epoch e is keys `[e*16384, (e+1)*16384)`. This matches zkSketch's
    `exp_compose` `batches_from()`, so epoch 0 is exactly our matched CM epoch.
  - `key_id`: `Event::make_key_id(0, key)`, the same encoding as `acc_zka`.
  - `value`: 1 for samples and cm (frequency). For histogram it is `key & 0x1FFFFF`,
    the 21-bit coordinate our GK leaf summarises (`gk_vals_of`).
  - `ts`: the global record index.
  - Batching: one source, stream order, batches of 8 records (their
    `--commit-batch-size` default). The batch hash chain, `source_batch_seq` and
    `prev_source_chain_tips` carry across epochs as their aggregator host carries
    them. The epoch chain links epoch e-1's `final_chain_hash` into epoch e.
- **Query inputs.**
  - Epoch states come from their own `process_*_aggr_with_state`. The chain links
    are the ones their aggregation journals publish, and the guest re-verifies
    them in full.
  - `Estimate` targets the heaviest key of the queried prefix, AOL key 3780053395
    (a heavy-key query).
  - `limit=10` for `SumTopk` and `Topk` is their `bench_queries` default. Their
    `SumTopk` also caps `limit` at `CM_TOPK_SLOTS`, so samples queries run at T=100.
- **Steelman histogram (`key_id=const`).** A global P90 does not need their
  per-key breakdown. With every record carrying `key_id` 0, each epoch holds one
  `KeyHistogram` instead of about 8.4k. The value stream and the answer are
  unchanged. This is the cheapest valid encoding of our quantile workload in
  their structure, and it is reported next to the per-key default.
- **Checks on every row.**
  - The guest journal equals their native function on the same input
    (`journal_eq_native=true` on all 31 rows); for queries this is after
    `suppress_if_low_support`.
  - No result was suppressed (`MIN_SUPPORT=10`).
  - The exact plaintext answer is in the `exact` column.
  - Repeated full runs gave identical cycles, segments and answers: three runs
    for the key_id=aol rows, two for the key_id=const rows.
- **CSV columns.** `per_key_entries` is the stored state the query guest
  re-hashes: the total per-key entries across epochs (samples, histogram), or the
  occupied heap slots across epochs (cm). `input_bytes` is the risc0-serde guest
  input. `padded_cycles` is the sum of 2^po2 over segments.

### Results (executor; `MODELED` = segments x 30.1 s, NOT measured)

Aggregation guest on one epoch (16,384 AOL records, 8,433 distinct keys):

| guest | T | key_id | state entries | user cycles | cycles/rec | segments | MODELED prove |
|---|---|---|---|---|---|---|---|
| aggr_samples | 100 (T=1 identical) | aol | 8,433 | 131,981,406 | 8,055.5 | 152 | 4,575 s |
| aggr_histogram | 100 (T=1 identical) | aol | 8,433 | 272,843,799 | 16,653.1 | 318 | 9,572 s |
| aggr_histogram | 100 | const | 1 | 86,498,951 | 5,279.5 | 89 | 2,679 s |
| aggr_cm | 100 | aol | heap 100 | 274,155,148 | 16,733.1 | 277 | 8,338 s |
| aggr_cm | 1 | aol | heap 1 | 100,439,836 | 6,130.4 | 104 | 3,130 s (proved anchor on synthetic keys: 3,202 s) |

On real AOL the T=1 CM epoch is within 0.26% of the synthetic 1,024-key anchor
(100,696,165 cycles, 104 segments). At T=100 it is 11.1% cheaper than that
anchor (308.3M cycles, 311 segments). A plausible cause, not verified: on skewed
keys more updates find their key already in the heap, so `cm_heap_update`
returns early.

Query guest over n populated epochs (segments, with MODELED prove time in parentheses):

| query | n=1 | n=4 | n=16 | n=64 (2^20 records) | cycles fit (R^2) |
|---|---|---|---|---|---|
| samples SumTopk (T=100) | 91 (2,739 s) | 385 (11,589 s) | 1,538 (46,294 s) | 6,356 (191,316 s = 53.1 h) | 96.24M n - 20.2M (0.99995) |
| histogram P90, key_id=aol | 121 (3,642 s) | 500 (15,050 s) | 1,941 (58,424 s) | 7,832 (235,743 s = 65.5 h) | 117.87M n - 1.8M (0.99999) |
| histogram P90, key_id=const | 1 (30 s) | 1 (30 s) | 1 (30 s) | 3 (90 s) | 37,968 n + 13,616 (1.0) |
| cm Estimate (T=100) | 2 (60 s) | 5 (151 s) | 20 (602 s) | 77 (2,318 s) | 1,173,019 n + 14,581 (1.0) |
| cm Topk (T=100) | 2 (60 s) | 6 (181 s) | 25 (753 s) | 100 (3,010 s) | 1.526M n - 0.26M (0.99999) |
| cm Estimate (T=1) | 1 (30 s) | 4 (120 s) | 14 (421 s) | 55 (1,656 s) | 830,861 n + 14,581 (1.0) |

- **CM estimate.** Populated epochs reproduce the empty-stream fits in
  `cost_model.txt` exactly (1,173,019 n + 14,581 at T=100; 830,861 n + 14,581 at
  T=1). The CM query cost does not depend on the data, so the old
  `keys_total=1` query rows were not biased.
- **CM topk.** The cost depends on the data: 1.526M n populated versus 1.453M n
  on the empty stream (+5%), because every epoch heap is full.
- **Samples and histogram (key_id=aol).** These scale with the stored per-key
  entries (sum over epochs of distinct keys: 8,433 at n=1, 546,948 at n=64). The
  query input reaches 111.6 MB (samples) and 109.4 MB (histogram) at n=64.
- **Receipts.** Every query also needs the n per-epoch aggregation receipts,
  verified separately (no `env::verify` anywhere in their tree), so the
  aggregation rows above recur once per epoch.

### Modeled prove time and the anchors behind it

MODELED prove time is `segments x 30.1 s/segment`. The CSV carries an envelope
of `segments x 29.73` to `segments x 30.79`, the per-anchor minimum and maximum
of the four CPU prove anchors. All four are CM guests, `ProverOpts::succinct()`,
r0vm 3.0.6, CPU only, on this 32-core box:

| anchor | prove_s | segments | s/segment | source |
|---|---|---|---|---|
| aggr_cm T=100, n=512 | 661.3 | 22 | 30.06 | `a2_anchor.csv` |
| aggr_cm T=1, n=16,384 | 3,202.0 | 104 | 30.79 | `zka_matched.csv` |
| querier_cm estimate, n=4 | 151.3 | 5 | 30.26 | `zka_query_sweep.csv` |
| querier_cm estimate, n=16 | 594.6 | 20 | 29.73 | `zka_query_sweep.csv` |

Every full segment is a po2=20 trace, so per-segment cost should depend little
on the instruction mix. That is an argument, not a measurement: **the samples
and histogram guests have no proved anchor yet**, and their MODELED seconds are
extrapolated from CM guests only. The GPU prover was not used. Run one small
proved anchor per non-CM guest in a quiet window. Each command below is sized
from the executor. `rss_watch.sh` refuses to start if an r0vm of yours is
running, and it `pkill`s this user's r0vm on exit, so run nothing else under
this account meanwhile.

```bash
cd scripts/baselines/zka && source ./common.sh && B=$(cyc_target 100)/release/shipped
./rss_watch.sh anchor_aggr_samples    $B --mode aggr  --family samples   --epoch-size 2048 --prove            # 22 segments
./rss_watch.sh anchor_aggr_histogram  $B --mode aggr  --family histogram --epoch-size 2048 --prove            # 39 segments
./rss_watch.sh anchor_query_samples   $B --mode query --family samples   --epochs 1 --epoch-size 2048 --prove # 14 segments
./rss_watch.sh anchor_query_histogram $B --mode query --family histogram --epochs 1 --epoch-size 2048 --prove # 18 segments
```

`--prove` fills the `prove_s`, `verify_ms`, `receipt_bytes` and `s_per_segment`
columns and asserts that the proved journal equals their native output. That
path is compiled but has **not** been run.

### Caveats

- **Top-K keys are not proved.**
  - `cm Topk`: the journal commits counts only. Their query server attaches keys
    from its own unproven computation, zipping them onto the proven counts
    (`querier/server/src/main_parts/queries.rs:815-823`).
  - `samples SumTopk`: the journal commits sums only, and the server returns no
    keys at all (`queries.rs:2054`).
  - Neither proof says WHICH keys are heavy.
- **Their P90 is not a rank quantile.**
  - `histogram_bucket_index(v) = floor(log2 v)`, so bin b holds `[2^b, 2^(b+1))`.
  - The P90 query returns `2^(b-1)` for the crossing bin b, which is half the
    bin's lower edge (`querier/core/src/lib.rs:560-573`).
  - Measured at every n: exact P90 is about 1.87M, in bin 20 = [1,048,576, 2,097,152),
    and the guest returns 524,288 = 2^19.
  - P90 is the only quantile the guest exposes.
- **Semantics differ from our SS/GK.**
  - Samples is an exact per-key table whose state grows with the number of
    distinct keys. It is not bounded-space, so its query answers are exact where
    SS is approximate with bounded capacity.
  - Histogram is 32 per-key log2 bins, a factor-2 value resolution, with no
    epsilon-rank guarantee.
  - CM `Topk` re-estimates the union of per-epoch heap candidates. Its counts
    over-estimate the truth (n=64: 18,251 vs exact 17,564 for the top key).
- **CM point queries are only meaningful for heavy keys.** The estimate for the
  heaviest key is +3.9% at n=64, so the heavy-key choice matters.
- **Timing and hardware.** `exec_s` is wall-clock on a shared box and is not a
  metric. Cycles and segments are deterministic. All MODELED seconds assume
  CPU-only r0vm on this Threadripper.

## Sketch-family guests (HLL, SpaceSaving, Greenwald-Khanna): zk-Analytics method, our implementation (†)

zk-Analytics ships three epoch summaries (samples, histogram, cm; see the
shipped-structure arm above). None is a distinct-count, bounded-space
heavy-hitter or rank-quantile sketch. `hll/`, `spacesaving/` and `gk/` add those
three families to **their** pipeline with **their** general-purpose method: the
textbook plaintext algorithm, written in ordinary Rust and executed as a RISC
Zero guest. The rest of the pipeline is theirs, mostly copied verbatim:
- a per-epoch aggregation guest that verifies the source's SHA-256 batch hash
  chain, builds the epoch summary from scratch, commits to it with an unsalted
  SHA-256 and links the commitment into their epoch hash chain;
- a query guest that re-verifies the epoch chain links, recomputes every epoch's
  state commitment, merges the per-epoch summaries at query time and answers.

None of zkSketch's circuit techniques is used: no oblivious padding, memory
checking, sorting certificates or Poseidon.

**These are OUR implementations of zk-Analytics' per-epoch design, not
zk-Analytics code.** Every row is marked † below. Cite them as "our HLL / SS / GK
instantiation of zk-Analytics' per-epoch / query-time-merge architecture (†)",
never as "zk-Analytics' HLL / SS / GK". The per-family READMEs
(`hll/README.md`, `spacesaving/README.md`, `gk/README.md`) have the full detail:
algorithm, tests, phase profiles and every sensitivity row.

### Running

```bash
scripts/baselines/zka/sketch_exec.sh                    # build + executor sweep of all three; regenerates the CSVs; proves nothing
scripts/baselines/zka/sketch_exec.sh --only gk          # one family (hll, ss, gk; comma-separated)
scripts/baselines/zka/sketch_exec.sh --dry-run --prove  # print the plan and every command; writes nothing
scripts/baselines/zka/sketch_exec.sh --skip-build --no-exec --prove   # the three proved anchors only, in a quiet window
```

- **Executor sweep.** It builds each family (`--locked`,
  `RISC0_BUILD_LOCKED=1`, into `$BASELINE_DIR/build/{hll,zka-ss,zka-gk}`).
  It then runs the family scripts with the configuration pinned to the values
  below: `hll/run_exec.sh` (twice: main rows, then data-dependence rows),
  `hll/seed_spread.py`, `spacesaving/ss_exec.sh` and `gk/gk_exec.sh`. With
  cached builds the whole sweep took 7.5 minutes on this box; SpaceSaving
  accounts for 6.8 of them, mostly its n=64 queries.
- **Staged regeneration.** Every family writes into
  `results/sketch_exec.<ts>.<pid>.tmp/` (gitignored). A family replaces its CSVs
  only when all its runs succeed and every row passes validation:
  - `journal_eq_native=true`;
  - the family's checks: `ref_check=ok` (HLL); `ref_eq` and `invariants_ok`
    (SS); `q_ok`, `min_kept`, `exact_in_cert` and both error-vs-eps N columns
    (GK);
  - the expected row count;
  - no proved row.

  After a successful family:
  - the previous CSV is kept as `<name>.csv.prev` (gitignored);
  - the staged raw log is appended to the family's log, which therefore keeps
    every earlier run, including the raw record of each proved anchor;
  - proved rows of the previous CSV are carried over verbatim after the new rows,
    with a check that the ELF they proved is still the current one (GK keeps its
    anchor inside `zka_gk_exec.csv`);
  - the deterministic columns (all but `exec_s` and `r0vm_peak_rss_mb`) are
    compared with the previous CSV, and the result is logged.

  A failing family leaves its canonical files untouched and its staged files in
  place. Each run's record goes to `results/zka_sketch_exec.log`.
- **Proving only with `--prove`.** After the executor phase it runs each
  family's one small anchor (`hll/prove_anchor.sh`, `spacesaving/ss_anchor.sh`,
  `gk/gk_prove_anchor.sh`: the aggregation guest on the first 2,048 AOL records,
  `ProverOpts::succinct()`, CPU), one at a time.
  - Before each anchor it waits, up to `WAIT_S` (1,800 s), until the 1-minute
    load average is at most `MAX_LOAD` (24, the families' default) and no `r0vm`
    of any user is running.
  - The anchor scripts re-check `MAX_LOAD` themselves and refuse above it
    (exit 3). `sketch_exec.sh` never raises it, and it removes `EPOCH_SIZE`,
    `CAP` and `OUT` from the anchors' environment, so the executor settings
    cannot leak into a proof.
  - Anchors append to `zka_hll_anchor.csv`, `zka_ss_anchor.csv` and
    `zka_gk_exec.csv` (each family's own convention).
- **Safety.** `RISC0_DEV_MODE` is refused. A lock in `$BASELINE_DIR/build/`
  stops two sweeps running at once. Nothing is signalled, and
  `rss_watch.sh` is not used (it pkills every `r0vm` of this account).
- **Verified on 2026-09-26.** A full `sketch_exec.sh` run from this directory
  (17:50-17:57; 1-minute load 1.6-4.1 where sampled) passed validation for all three
  families. It reproduced every executor row in every deterministic column
  (HLL 9 + 3 + 40, SS 70, GK 21) and carried the GK anchor row over byte for
  byte, with the same ELF. The builds were no-ops, and every guest ELF md5 is
  unchanged. The anchor CSVs were not touched.

| results file | rows | produced by | notes |
|---|---|---|---|
| `zka_hll_exec.csv` / `.log` | 9 | `hll/run_exec.sh` | aggregation, epoch 0; `hll_query` and `hll_query_words` at n = 1, 4, 16, 64 |
| `zka_hll_exec_datadep.csv` / `.log` | 3 | `hll/run_exec.sh` | aggregation on epochs 1, 31, 63 |
| `zka_hll_seed_spread.csv` | 40 | `hll/seed_spread.py` | numpy re-implementation, 10 hash seeds; must reproduce every committed estimate |
| `zka_hll_seed_spread_200.csv` | 800 | `hll/seed_spread.py` with 200 seeds (command in `hll/README.md`) | the same check over the guest seed plus 199 seeds from `numpy.random.default_rng(200)`; not part of the sweep |
| `zka_hll_anchor.csv` / `.log` | 1 proved | `hll/prove_anchor.sh` | separate anchor CSV; not regenerated without `--prove` |
| `zka_ss_exec.csv` / `.log` | 70 | `spacesaving/ss_exec.sh` | s = 2^14 and 1,024; aggregation, profiling twins, root variants, epoch 63; topk / estimate / estimate_merged |
| `zka_ss_anchor.csv` / `.log` | 3 proved | `spacesaving/ss_anchor.sh` | separate anchor CSV with a `prove_condition` column. Two rows come from the superseded first build (per-key root, image `1e73f3f3...`), one of them `contended`; only the `clean` `buckets64` row of the current `aggr_ss` image (`0aff21e3...`) is a valid anchor |
| `zka_gk_exec.csv` / `.log` | 21 + 1 proved | `gk/gk_exec.sh`, `gk/gk_prove_anchor.sh` | GK keeps its anchor inside the executor CSV (HLL and SS use separate anchor CSVs): the proved row has `arm=proved` and a `contention` column |
| `zka_{ss,gk}_exec_v1_before_fix.*` | - | first builds | superseded by review fixes; kept for side-by-side comparison only; **do not use** |
| `zka_sketch_exec.log` | - | `sketch_exec.sh` | one record per sweep: validation, comparison, carry-over and anchor outcomes |

### Exact configuration

Common to all three families:

- **Code and toolchain.**
  - zk-Analytics `d4a5a9a90f74`, read-only through `.zka`.
  - Guests link risc0-zkvm **3.0.5**, as theirs do: each guest lockfile was
    seeded from the clone's `Cargo.lock`, and no version changed.
  - The hosts use risc0-zkvm 3.0.6, with lockfiles seeded from `cyc/Cargo.lock`.
  - The executor and prover are r0vm 3.0.6 on CPU.
  - ELF md5s are in each log header; HLL and SS also record the `image_id` in
    their CSVs.
- **Records.** Identical to `cyc/src/bin/shipped.rs`:
  - source: `data/aol.keys` (md5 `01dd7d5c8a73`); epoch e is keys
    `[e*16384, (e+1)*16384)`, so epoch 0 is the matched CM epoch (16,384
    records, 8,433 distinct keys);
  - `key_id = Event::make_key_id(0, key)` and `ts` = the global index;
  - one source, batches of 8;
  - the batch chain, `source_batch_seq` and tips carry across epochs, and epoch
    e-1's `final_chain_hash` links into epoch e.

  The aggregation input is their `Event`-batch format, 1.41 MB per epoch, byte
  for byte what their `aggr_*` guests read (`input_bytes` = 1,409,160 on epoch 0;
  SS adds its 4-byte capacity).
- **Queries.** They run over the first n epochs, n in {1, 4, 16, 64}; n = 64 is
  all 2^20 records. Every answer, its keys or bounds included, is in the
  committed journal, together with the chain boundaries and the n state commits.
  Their `MIN_SUPPORT = 10` suppression applies. There is one guest run (one
  proof) per query, as in their query guests.
- **Prove-time model.** MODELED = segments x 30.1 s, with an envelope of
  segments x 29.73 to x 30.79, from the four CM-guest CPU anchors above.

| | HLL † | SpaceSaving † | GK † |
|---|---|---|---|
| parameters | b = 14 (2^14 u8 registers) | s = 2^14 (matched; exact per AOL epoch, no eviction) and s = 1,024 (eviction exercised) | eps = 1/51, COMPRESS every 25 records |
| update (plain Rust) | textbook HLL, Flajolet et al. 2007 | Metwally et al., unit weight, Stream-Summary buckets (O(1) per record) | Greenwald-Khanna SIGMOD'01 INSERT / band COMPRESS; t_0 (the minimum) always kept, per the paper's section 2.1 invariant |
| hash / value | their FNV-1a `key_to_u64` (`aggregator/core/src/lib.rs:342`) + the seeded splitmix64 finaliser of their `cm_bucket_index` (`:1055-1063`, without `% CM_COLS`), CM row-0 seed `0x6d0f27bd` | the same mix without the seed, for the key-to-counter map; keys are compared in full | `value = key & 0x1FFFFF` (21 bits; the task text said 22-bit, the histogram arm's mask is the authority); `key_id` only enters the batch chain |
| epoch state, unsalted SHA-256 commit | `total_count` + 16 KB of registers | capacity, `total_count`, <= s `(key_id, count, error)` sorted by key | `total_count` + tuples `(v, g, Delta)` |
| per-type Merkle root in the aggregation journal (no query reads it) | **none** (dropped; cheaper than a literal port) | their samples pattern: 64 hash buckets (their benchmark `SAMPLES_HT_BUCKETS=64`), folded by their `samples_buckets_root_from_leaves` | their `hist_per_key_root` pattern over tuples, their `MerkleTree` |
| query-time merge | elementwise max of registers | top-k: sum equal keys, keep the top s (sum-and-truncate, as specified; not Agarwal's MG merge). Point: their `SumExactKey` scan, no merge | one-shot k-way GK COMBINE under one total order (value, epoch, position), summed rank bounds, no recompression |
| queries | cardinality: HLL estimator with small-range (linear counting) correction, f64 in the guest (`libm`) | top-10 `(key, count, error)` (**keys in the journal**, unlike their CM `Topk` / samples `SumTopk`); point frequency of the rank-1 and rank-100 keys | rank(2^20); p50, p90, p99 (answer + certified bounds + N) |

### Reused from upstream vs written by us

| item (upstream `d4a5a9a`) | HLL † | SS † | GK † |
|---|---|---|---|
| `verify_and_compute_chain` (`aggregator/core/src/lib.rs:499-603`) | copied verbatim | copied verbatim | copied verbatim |
| `verify_epoch_chain_integrity` (`querier/core/src/lib.rs:98-136`) | copied verbatim | copied verbatim | copied verbatim |
| `events_commit`, `chain_tips_to_sorted_vec`, `sha256_bytes`, `TAG_SHARD_CHAIN`, `TAG_EPOCH_CHAIN` | copied verbatim | copied verbatim (+ `next_pow2_ge`) | copied verbatim (+ `next_pow2_ge`) |
| `Event`, `make_key_id` (`zkvm-common/src/lib.rs:76`), `BatchInput`, `EpochChainLink::new`, `batch_chain_hash`, `MIN_SUPPORT` | path dependency | path dependency | path dependency |
| `key_to_u64`, `CM_SEEDS` | path dependency | `key_to_u64` | - |
| aggregation input type | `CmAggrInput` as is (field-for-field their samples/histogram input) | own type, same fields + `capacity` | own type, `HistogramAggrInput` shape |
| Merkle helpers | - | `samples_buckets_root_from_leaves`; `samples_bucket_index` copied verbatim with the mask as a parameter; `MerkleTree` (per-key sensitivity variant only) | `MerkleTree` |
| structure mirrored step for step | `process_cm_aggr_with_state`, `run_cm_query` | `process_cm_aggr_with_state`, `run_samples_query`, `SumTopk`, `SumExactKey` | `process_histogram_aggr_with_state`, `run_histogram_query` |
| **written by us** | the HLL update, register merge, estimator, state type and tag, the `hll_query_words` variant, cycle probes, host driver | Stream-Summary SpaceSaving, merge, point-query glue, state type, root variants, profiling twins, host driver and references | GK INSERT / COMPRESS, total-order COMBINE, rank/quantile answers, state type, profiling guest, host driver and tests |

The verbatim copies were re-checked against the clone during integration:
`hll/gen_upstream.sh --check` passes, and an extractor diff of each copied
function in `spacesaving/core/src/lib.rs` and `gk/core/src/lib.rs` finds them
identical. The clone is clean at `d4a5a9a90f74`.

### Results (executor unless stated; MODELED = segments x 30.1 s, NOT measured)

**Aggregation guest, one AOL epoch** (epoch 0: 16,384 records, 8,433 distinct keys):

| guest | config | user cycles | cycles/rec | segments | MODELED prove | sketch update share | data dependence (other epochs) |
|---|---|---|---|---|---|---|---|
| `hll_aggr` † | b = 14 | 82,646,548 | 5,044 | 85 | 2,558 s | 3.27M (4.0%, 200/rec) | epochs 1, 31, 63: 82.65M, 85 segments each (0.01%) |
| `aggr_ss` † | s = 2^14 | 113,584,313 | 6,933 | 124 | 3,732 s | 10.3M (9.1%, 629/rec); + canonical sort 13.3%, root 5.1% | epoch 63: 127 segments |
| `aggr_ss` † | s = 1,024 | 97,874,942 | 5,974 | 101 | 3,040 s | 15.8M (16.2%, 966/rec) | epoch 63: 102 segments |
| `aggr_gk` † | eps = 1/51 | 103,407,361 | 6,311 | 107 | 3,221 s | 24.5M (23.5%: INSERT 12.1%, COMPRESS 11.4%) | epochs 1, 16, 63: 102.10-103.11M, 105-106 segments |
| their `aggr_cm`, T=1 | 3x1024 | 100,439,836 | 6,130 | 104 | 3,130 s (proved on synthetic keys: 3,202 s) | - | - |
| their `aggr_samples` | exact table | 131,981,406 | 8,056 | 152 | 4,575 s | - | - |
| their `aggr_histogram`, key_id=const | 32 log2 bins | 86,498,951 | 5,280 | 89 | 2,679 s | - | - |

- **Their framework dominates.** Reading their `Event` batches costs 60.8M
  cycles (risc0 serde, one word per `key_id` byte), and verifying the batch
  chain 17.8-18.0M. Together that is about 78.7M cycles for any summary type:
  69-95% of each † row, measured with each family's profiling marks. The sketch
  update itself is 4-24%. Do not read these totals as sketch cost.
- **SS root sensitivity** (`aggr_ss_rootvar`, s = 2^14): no root 117 segments,
  64 buckets 124 (headline), 1,024 buckets 128, per-key 176. At s = 1,024 the
  range is 100-105.

**Query guest over n epochs** (segments, with MODELED prove time in parentheses):

| query | n=1 | n=4 | n=16 | n=64 (2^20 records) | user-cycle fit (R^2) |
|---|---|---|---|---|---|
| HLL cardinality † (packed registers, headline) | 1 (30 s) | 2 (60 s) | 5 (151 s) | 16 (482 s) | 214,812 n + 156,500 (0.999995) |
| HLL cardinality †, one word per register (sensitivity) | 3 (90 s) | 11 (331 s) | 43 (1,294 s) | 172 (5,177 s) | 2,670,816 n + 156,518 (1.0) |
| SS top-10 †, s = 2^14 | 48 (1,445 s) | 208 (6,261 s) | 820 (24,682 s) | 3,288 (98,969 s = 27.5 h) | 47.67M n + 3.7M (0.99999) |
| SS top-10 †, s = 1,024 | 6 (181 s) | 23 (692 s) | 98 (2,950 s) | 405 (12,191 s = 3.4 h) | 5.94M n - 1.5M (0.99999) |
| SS point frequency †, s = 2^14 | 29 (873 s) | 118 (3,552 s) | 456 (13,726 s) | 1,838 (55,324 s = 15.4 h) | 28.58M n - 0.4M (0.99999) |
| SS point frequency †, s = 1,024 | 4 (120 s) | 14 (421 s) | 56 (1,686 s) | 222 (6,682 s) | 3.45M n + 0.02M (1.0) |
| GK rank(2^20) † | 1 (30 s) | 1 (30 s) | 2 (60 s) | 5 (151 s) | 65,544 n + 15,958 (0.99998) |
| GK p50 † (p90 and p99 within 0.2%) | 1 (30 s) | 1 (30 s) | 2 (60 s) | 6 (181 s) | 86,928 n + 2,976 (0.999997) |
| their samples `SumTopk` (T=100) | 91 | 385 | 1,538 | 6,356 | 96.24M n - 20.2M |
| their histogram P90, key_id=const | 1 | 1 | 1 | 3 | 37,968 n + 13,616 |
| their cm `Estimate` (T=1) | 1 | 4 | 14 | 55 | 830,861 n + 14,581 |

The fits were recomputed from the CSVs during integration. Query cost scales
with the stored state that the guest re-hashes and merges:
- HLL: 16 KB per epoch;
- SS: n x min(s, distinct keys per epoch) entries (8,433 to 546,948 at s = 2^14);
- GK: about 54 tuples per epoch.

**Proved anchors** (aggregation guest, first 2,048 AOL records, `ProverOpts::succinct()`, CPU r0vm 3.0.6):

| guest | segments | prove_s | s/segment | MODELED | conditions | receipt | verify | r0vm peak RSS |
|---|---|---|---|---|---|---|---|---|
| `hll_aggr` † | 11 | 332.1 | 30.19 | 331.1 s | 1-min load 11.4 at start; the driver has no contention sampler, and no other family's prover overlapped (by the logs' timestamps) | 224,554 B | 9.8 ms | 9,383 MB |
| `aggr_ss` † (64-bucket root, current image `0aff21e3...`) | 16 | 473.4 | 29.59 | 481.6 s | `clean`: foreign r0vm in 0 of 470 samples | 224,818 B | 10.2 ms | 9,401 MB |
| `aggr_gk` † (fixed build, ELF `d0f88f7b...`) | 14 | 414.5 | 29.61 | 421.4 s | `contention=none`: 0 foreign r0vm in 1,607 samples; the builder's own nice-19 test build overlapped the first minute | 224,810 B | 11.6 ms | 9,389 MB |

- All three proved journals were asserted equal to the native output.
- The three non-CM guests land at 29.59-30.19 s/segment, within 2% of MODELED,
  against the CM envelope of 29.73-30.79.
- `zka_ss_anchor.csv` also holds two rows from the superseded first build
  (v1 image `1e73f3f3...`, per-key root): 672.4 s `clean` and 958.8 s
  `contended`. Neither is the current guest, and the contended one must never be
  used. Only the `clean` row for the current image (`0aff21e3...`) is a valid
  anchor.

**Accuracy against exact answers:**

| family | measure | n=1 | n=4 | n=16 | n=64 |
|---|---|---|---|---|---|
| HLL † | estimate / exact distinct | 8,472 / 8,433 (+0.46%, LC) | 29,330 / 29,390 (-0.20%, LC) | 87,301 / 87,540 (-0.27%) | 241,155 / 245,620 (-1.82%) |
| SS † s = 2^14 | top-10 and both point keys | exact | exact | exact | exact |
| SS † s = 1,024 | top-10 recall; max abs (rel) count error | 10/10; 10 (12.3%) | 10/10; 9 (3.4%) | 10/10; 41 (4.9%) | 10/10; 160 (5.9%) |
| SS † s = 1,024 | rank-100 point answer (count / exact) | suppressed (no epoch tracks it) | 50 / 41 | 162 / 134 | 511 / 489 |
| GK † | p50 actual / certified rank error | 241 / 241 | 113 / 931 | 462 / 4,003 | 159 / 16,257 |
| GK † | worst certified error over 1,001 phis / eps N | 321 / 321.25 | 1,240 / 1,285 | 4,561 / 5,140 | 17,739 / 20,560 |

- **HLL.** `seed_spread.py` reproduces every committed estimate bit for bit.
  Its 10 seeds are too few to compare the spread with theory. The same numpy
  code over 200 seeds (the guest's plus 199 from `default_rng(200)`; saved in
  `zka_hll_seed_spread_200.csv`, command in `hll/README.md`) gives sd
  0.60 / 0.70 / 0.71 / 0.80% at n = 1 / 4 / 16 / 64. Theory is 0.60% and 0.78%
  for the linear-counting rows and 0.81% for the raw rows, and every mean is
  within ±0.04%. So the hash is fine, and -1.82% at n = 64 is a -2.3 sigma
  draw of this one seed (third-lowest of the 200), chosen before seeing results.
- **SS.** One merged top-10 count at s = 1,024 is below the truth (n = 4, key
  3630187757: 158 vs 160). The specified sum-and-truncate merge adds nothing for
  epochs that did not track a key. Every answer satisfies
  count - error <= f <= count + slack (see `spacesaving/README.md`).
- **GK.** Every row has the exact answer inside the certified interval, and
  actual <= certified <= eps N, on the named quantiles and over 1,001 phis. The
  provable bound is eps N + 1/2 (the paper's INSERT slack); every measured value
  is <= eps N.

### Caveats

- **These are ours (†).** They instantiate zk-Analytics' per-epoch
  architecture with our own guests. zk-Analytics ships none of these sketches.
  Mark them † in any table, and never call them "zk-Analytics' HLL / SS / GK".
  The comparison mostly measures a zkVM running plain code against an AIR
  circuit, which their paper concedes. The guests are also a data point for the
  zkVM's programmability.
- **Cycle counts are data-dependent.** There is no oblivious padding, matching
  their design, so cycles, segments and prove time leak properties of the input,
  exactly as their own guests do.
  - HLL moves 0.01% across epochs and GK 1.3% (105-107 segments). SS epoch 63
    is +1.9% at s = 2^14 (127 vs 124 segments) and +0.8% at s = 1,024.
  - SS aggregation depends on the hit/miss/eviction mix; its queries scale with
    the number of tracked keys.
  - Every number is exact only for these AOL epochs, this batch size and these
    parameters.
- **MODELED prove times rest on the four CM-guest anchors.** Each family has one
  proved anchor, for the aggregation guest at 2,048 records only. Those anchors
  agree with the model within 2%, but every full-epoch and every query prove
  time is an extrapolation. No query guest was proved.
  - The whole-segment model overstates rows whose last segment is partial.
    `padded_cycles / 2^20 x 30.1 s` is the lower sensitivity bound, and the gap
    matters only for small query guests. With the model value first and the
    bound second:
    - GK: n = 1, 30 s vs 3.8 s (po2 17); n = 4, 30 s vs 15 s; n = 16, 60 s vs
      34-45 s; rank at n = 64, 151 s vs 136 s.
    - HLL: n = 1, 30 s vs 15 s; n = 4, 60 s vs 38 s; n = 16, 151 s vs 124 s.
    - SS at s = 1,024, n = 1: 8-12%.

    Every other row is overstated by 2% or less.
  - The anchors ran on a shared box. The SS and GK drivers sample for foreign
    `r0vm` processes; the HLL driver does not.
- **CPU-only r0vm 3.0.6** on this 64-thread Threadripper. The GPU prover was not
  used. All MODELED seconds are CPU seconds.
- **zkSketch-side numbers must be re-measured after the soundness fixes.** Do
  not pair these rows with zkSketch HLL / SS / GK numbers measured before the
  pending circuit soundness fixes. Re-run zkSketch's side first, and state which
  build each ratio uses.
- **Design choices that move the cost are disclosed, and the conservative
  (cheaper-baseline) choice is the headline.**
  - HLL packs registers 4 per word. A literal `CmEpochState`-style port (one
    word per register) makes the query about 12x dearer (`hll_query_words`
    rows).
  - HLL drops the per-type Merkle root. Not measured, but hashing the 16 KB of
    registers costs about 44K cycles in the query guest, so a root would add on
    the order of 0.1% to `hll_aggr`.
  - SS roots its entries the samples way (5.1% of the guest). The first build's
    per-key root was 42% dearer and was dropped after review.
  - SS answers point queries with their `SumExactKey` scan. The first build's
    merge-then-lookup overstated them 1.5-1.8x; those rows are kept as
    `estimate_merged`.
  - GK's root costs 0.2%.
  - About 1% of SS's cycles depend on how the root code is written, for the same
    work (see `spacesaving/README.md`).
- **Their framework's fixed costs are inherited unchanged.**
  - Input deserialisation plus chain verification is about 78.7M cycles per
    epoch.
  - Each query needs the n per-epoch aggregation receipts, verified separately:
    their tree has no `env::verify`, so the aggregation cost recurs once per
    epoch.
  - Commitments are unsalted SHA-256, as in their code. Their paper's hiding
    commitment with fresh randomness does not exist in the code or in these
    ports.
- **Semantics.**
  - SS top-10 keys are committed in the journal. This does not replicate their
    CM top-K, whose keys are attached outside the proof.
  - SS's merge is the specified sum-and-truncate. It is not Agarwal et al.'s
    MG merge, and its bound is looser.
  - GK's guarantee is eps N + 1/2.
  - HLL answers carry the estimator branch taken.
- **Provenance.**
  - Each family was built, then reviewed independently.
  - SS and GK had blocking review findings, which were fixed and re-measured:
    - SS: the root pattern, the point-query path and the anchor hygiene;
    - GK: the lost minimum and a certificate that could exceed eps N.
  - HLL was accepted with non-blocking nits, still open: the `make_key_id` line
    cited as `:88` in `hll/host/src/main.rs:7` should be `:76`; `hll_dirty` does
    not pin the sources. (The 10-seed spread nit is answered by the saved 200-seed
    file above.)
  - ELF md5s and image IDs depend on the absolute source path (panic strings);
    cycle counts do not.
  - `exec_s` is wall-clock on a shared box and is not a metric.

## zkSketch's SpaceSaving batch rule as a RISC Zero guest (`ss_mg`, ours †): executor only

`ss_mg/` runs, as a RISC Zero guest, **exactly the batch transition that
zkSketch's SS leaf circuit certifies** (`src/sketch/ss_final_full.rs`
`apply_batch_ss_full`). That transition is mergeable Misra-Gries with top-s
retention, on the records, batches and state representation of zkSketch's
harness. One guest run is one zkSketch SS leaf:

- input: S_old and the epoch's m raw keys;
- journal: Com_old || Com_batch || Com_new.

So the comparison is between two ways of handling the same batch transition
(same rule, records and state layout): zkSketch's AIR circuit certifies it,
and this guest executes it in a zkVM (executor only here; prove time
MODELED). It is not a comparison of two algorithms, but the two statements are
not identical either: hash, compute-vs-verify and in-guest key mapping differ
(see "Statement differences" under Caveats).

The SpaceSaving port above (`spacesaving/`, `zka_ss_exec.csv`) is a different
baseline and stays unchanged: textbook per-record SpaceSaving inside
zk-Analytics' full aggregation pipeline, merged at query time by
sum-and-truncate. Never mix the two in one table.
`ss_mg/README.md` has the full detail.

**Nothing here was proved.** Every prove time is MODELED = segments x 30.1 s
(envelope x 29.73 to x 30.79), the model of the sections above.

### What is zkSketch's, ours and upstream

| item | source |
|---|---|
| batch rule, tie-break, tau, dummy handling, state layout and order | zkSketch: `ss_final_full.rs` `build_ss` (:481), `group_by_key` (:408), `compress_from_gsorted` (:452), `apply_batch_ss_full` (:575); re-implemented, and every run is checked against the native function |
| key mapping (29-bit mask, low bit forced to 1, `u32::MAX` gives the dummy) | zkSketch `ss_updates_of` (`src/experiments/stream_compose.rs:535`) |
| epoch slicing, Uniform stream | zkSketch `examples/exp_compose.rs` `batches_from` (:206) and `load_base` (:192, seed 1) |
| plain-Rust transition (`ss-mg-core`, radix and std sorts), the two guests, cycle probes, host driver, equivalence checks, runner | ours |
| unsalted SHA-256 commitments through risc0's accelerated `sha::rust_crypto` | zk-Analytics' style. **No zk-Analytics code is used**: no `Event` batches, no batch chain, no epoch chain, no Merkle root. zkSketch's leaf statement has none of them |

### Exact configuration

- **Batches.** m = 16,384 records per epoch: epoch e is keys `[e*m, (e+1)*m)`.
- **Datasets.**
  - AOL: `data/aol.keys`, md5 `01dd7d5c8a73`.
  - Uniform: `synthetic_stream(Uniform, 2^20, seed 1)`, the
    `EXP_DATASET=uniform` stream of `exp_compose`. This is not the frozen
    `data/uniform.keys`.
  - No record equals `u32::MAX` (`pad_records` = 0 on every row).
- **Capacities.** s = 16,384 (deployed) and 1,024. The state starts from
  `SsFullState::empty`. The AOL epoch-63 rows carry S_63 computed natively from
  epochs 0..62, with `ss-mg-core` checked against zkSketch on every one of them.
- **Guests.**
  - `ss_mg` (headline) reads its input with `env::read_slice`.
  - `ss_mg_serde` (sensitivity) reads the same data through risc0 serde
    (`env::read`), the way the zka guests read.
  - Either can use the radix sort (headline) or core's `sort_unstable` with
    `select_nth_unstable` (sensitivity).
  - ELF md5s: `ss_mg` `87153a58…`, image `271123b7…`; `ss_mg_serde`
    `ccdc2adc…`, image `512c7d48…`.
- **Toolchain.** Guest risc0-zkvm 3.0.5; host 3.0.6; executor r0vm 3.0.6 on
  CPU, through `default_executor()`.
- **Native reference.** The zksketch crate of this checkout
  (`7089f70`, `native_reference_dirty_files=0` in the log), by path.
- **Probes.** `env::cycle_count()` probes split the user cycles of every run
  into phases. `post_cycles` is defined as user cycles minus the last mark, so
  `pre_main` + the phase deltas + `post` equals the user cycles by
  construction; that sum checks nothing. The check (`probes_ok`; the driver
  exits 1 otherwise) is that the marks increase and that `pre_main` and `post`
  both stay under 10,000 cycles. That holds only if `env::cycle_count()` counts
  the same session-wide user cycles as the executor. On all 306 rows
  `pre_main` = 360 and `post` = 2,632-2,633 (the host-only write). Setting
  the bound to 2,000 made the driver fail as expected (tried by hand, then
  reverted).
- **Cycle columns.** `user_cycles` are executed guest cycles. `padded_cycles`
  is the sum of 2^po2 over segments, what the prover pays (same name as in
  `zka_ss_exec.csv`). `overhead_cycles` = padded - user: paging plus the
  per-segment reserve and po2 padding. The runner also records r0vm's own
  session summary (`RISC0_INFO=1`) as `r0vm_paging_cycles` and
  `r0vm_reserved_cycles` and checks, on every row, that r0vm's user and
  total cycles equal `user_cycles` and `padded_cycles` and that
  user + paging + reserved = total.
- **Run record.** `ss_mg/ss_mg_exec.sh`, about 1 minute per run. It was run
  five times on 2026-10-08; `results/zka_ss_mg_exec.log` holds runs 4 and 5.
  - Runs 1-3 were development runs, and their log records were deleted.
    - Run 1 used 8-epoch chains.
    - Run 2 exited 1 because of a runner bug: `cargo test` got `--release`
      after `--`. No check failed.
    - Run 3's CSVs were kept as `*.prev` until run 5. They matched run 4's in
      every column but `exec_s`.
  - Run 4 (23:15) used the earlier column set. It had no overhead, probe or
    r0vm columns, and named `padded_cycles` and `transition_pct_user`
    `total_cycles` and `transition_pct`.
  - Run 5 (23:35) wrote the current CSVs. On all 306 rows it matches run 4 in
    all 46 columns the two runs share, `exec_s` excepted.

### Equivalence (`zka_ss_mg_equiv.csv`, 288 guest runs, all passing)

Every guest run is checked against zkSketch's native code, and any mismatch
exits 1 before a row is written:
- S_new, row by row and field by field (key, count, active), against
  `apply_batch_ss_full`;
- the journal against `ss-mg-core` run natively;
- all three commitments against SHA-256 of zkSketch's native S_e,
  `ss_updates_of(batch)` and S_{e+1}.

Two bookkeeping checks also run on every row:
- the cycle-mark bounds (`probes_ok`);
- in the runner, r0vm's own session summary against the row's cycle counts.

Both are described under "Exact configuration".

The guest-chained runs feed each epoch the previous guest's output, and check
Com_old(e) against Com_new(e-1):
- radix sort: all 64 epochs, i.e. the whole 2^20-record stream;
- std sort: 8 epochs;
- each for AOL and Uniform, at both s.

Eviction (tau > 0) is exercised:
- AOL: 33 of 64 epochs at s = 16,384, all 64 at s = 1,024;
- Uniform: 42 of 64 epochs at s = 16,384, all 64 at s = 1,024.

Unit tests compare both sorts with `apply_batch_ss_full` on 1,200 random
24-epoch chains of small shapes (ties at the cut, pads, mask aliases). A
by-hand mutation check (off-by-one tau, reversed tie order) was caught by them.

### Results (executor; MODELED = segments x 30.1 s, NOT measured)

Headline guest (`ss_mg`, radix). The phase split covers **user cycles
only**:
- "Ingest + commit" is read + Com_old + key mapping + Com_batch + Com_new +
  journal.
- The remaining 2,993 user cycles fall before `main` and after the last probe.
- "Overhead" (padded - user) is paging plus the per-segment reserve and po2
  padding. It is not in any phase, yet it is 27-34% of the padded cycles that
  set the segment count, and so the MODELED seconds.

| dataset, epoch | s | S_old active | union keys | tau | S_new active | user cycles | padded cycles (sum 2^po2) | overhead (paging + reserved) | segments | MODELED prove | ingest + commit | transition | transition, % of user | transition, % of padded |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AOL, 0 | 16,384 | 0 | 8,433 | 0 | 8,433 | 5,240,072 | 7,602,176 | 2,362,104 (2,034,292 + 327,812) | 8 | 240.8 s | 2,399,680 | 2,837,399 | 54.1% | 37.3% |
| AOL, 63 | 16,384 | 8,061 | 15,062 | 0 | 15,062 | 7,048,931 | 10,485,760 | 3,436,829 (2,781,128 + 655,701) | 10 | 301.0 s | 2,399,680 | 4,646,258 | 65.9% | 44.3% |
| Uniform, 0 | 16,384 | 0 | 16,384 | 0 | 16,384 | 5,554,676 | 8,388,608 | 2,833,932 (2,142,946 + 690,986) | 8 | 240.8 s | 2,399,680 | 3,152,003 | 56.7% | 37.6% |
| AOL, 0 | 1,024 | 0 | 8,433 | 3 | 626 | 3,591,132 | 5,242,880 | 1,651,748 (1,192,116 + 459,632) | 5 | 150.5 s | 1,104,274 | 2,483,865 | 69.2% | 47.4% |
| AOL, 63 | 1,024 | 802 | 9,450 | 3 | 1,002 | 4,005,449 | 5,505,024 | 1,499,575 (1,219,347 + 280,228) | 6 | 180.6 s | 1,104,274 | 2,898,182 | 72.4% | 52.6% |
| Uniform, 0 | 1,024 | 0 | 16,384 | 1 | 0 | 3,704,270 | 5,242,880 | 1,538,610 (1,192,734 + 345,876) | 5 | 150.5 s | 1,104,274 | 2,597,003 | 70.1% | 49.5% |

Ingest and commit phases (user cycles; identical on every row with the same s):

| s | read | Com_old | map | Com_batch | Com_new | journal |
|---|---|---|---|---|---|---|
| 16,384 | 30,620 | 680,116 | 327,847 | 680,044 | 680,103 | 950 |
| 1,024 | 8,060 | 43,693 | 327,847 | 680,044 | 43,680 | 950 |

Each commitment costs about 166 cycles per 64-byte SHA-256 block. A state row
is 16 bytes, so Com_old and Com_new grow with s; Com_batch hashes 16,384
records of 16 bytes at both s.

These are user cycles. Paging is not counted in any phase. A segment pays to
page in every page it touches and to page out every page it writes, whichever
phase touches them. For example, the read's 30,620 user cycles leave out the
paging of the 320 KB its input lands in (s = 16,384), and later segments pay to
page those buffers in again. The IPC executor reports paging per session only
(the overhead column above), so paging per phase was not measured.

Whole stream (the 64-epoch guest chains, sequential, one proof per epoch):

| dataset, s | segments per epoch (mean, range) | segments over 64 epochs | MODELED over 64 epochs |
|---|---|---|---|
| AOL, 16,384 | 10.7 (8-12) | 685 | 20,619 s (5.7 h) |
| AOL, 1,024 | 5.8 (5-6) | 373 | 11,227 s (3.1 h) |
| Uniform, 16,384 | 9.3 (8-12) | 596 | 17,940 s (5.0 h) |
| Uniform, 1,024 | 5.3 (5-6) | 342 | 10,294 s (2.9 h) |

Sensitivity (user cycles / segments / MODELED):

| row | `ss_mg`, radix (headline) | `ss_mg`, std sort | `ss_mg_serde`, radix |
|---|---|---|---|
| AOL 0, s = 16,384 | 5,240,072 / 8 / 241 s | 8,587,142 / 11 / 331 s | 17,498,422 / 20 / 602 s |
| AOL 63, s = 16,384 | 7,048,931 / 10 / 301 s | 12,646,956 / 15 / 452 s | 19,307,281 / 22 / 662 s |
| Uniform 0, s = 16,384 | 5,554,676 / 8 / 241 s | 7,590,943 / 10 / 301 s | 17,813,026 / 20 / 602 s |
| AOL 0, s = 1,024 | 3,591,132 / 5 / 151 s | 5,691,132 / 7 / 211 s | 6,656,042 / 8 / 241 s |
| AOL 63, s = 1,024 | 4,005,449 / 6 / 181 s | 5,987,939 / 7 / 211 s | 7,070,359 / 9 / 271 s |
| Uniform 0, s = 1,024 | 3,704,270 / 5 / 151 s | 6,162,109 / 8 / 241 s | 6,769,180 / 8 / 241 s |

- **Std sort.** The transition alone costs 1.6-2.2x the radix transition.
- **Serde read.** Reading through risc0 serde costs about 150 cycles per input
  word (12.29M cycles at s = 16,384 and 3.07M at s = 1,024) against 30,620 and
  8,060 with `env::read_slice`. That is the same per-word cost behind the 60.8M
  `Event` read of the ports above.
- **Context, not a comparison.** On the same AOL epoch 0 at s = 2^14,
  `aggr_ss` above takes 124 segments; this guest takes 8. Most of the gap is
  zk-Analytics' framework (`Event` deserialisation and batch-chain checks,
  about 78.7M cycles), which zkSketch's leaf statement does not contain. The
  two guests also compute different summaries.

### Caveats

- **No proved anchor for this guest.** Every second above is MODELED from the
  four CM-guest CPU anchors. The three non-CM anchors (HLL, SS, GK) agreed with
  the model within 2%, but this guest is not one of them.
  - The whole-segment model overstates rows whose last segment is partial. The
    lower bound, `padded_cycles / 2^20 x 30.1 s`, gives 218 s for AOL 0 at
    s = 16,384 (240.8 s modeled) and 158 s for AOL 63 at s = 1,024 (180.6 s).
    The other headline rows have only full segments.
- **CPU-only r0vm 3.0.6 on this box** (AMD Threadripper PRO 9975WX, 32 cores /
  64 threads). The GPU prover was not used.
- **Cross-hardware.** The paper's zkSketch timing tables were measured on EPYC
  machines. Cycles and segments do not depend on the hardware; seconds do. A
  ratio of these MODELED seconds to EPYC-measured zkSketch seconds is a
  cross-hardware ratio and must say so. Better: re-measure zkSketch's SS leaf
  on this box, from a build with the pending soundness fixes, and state which
  build each side uses.
- **Cycles depend on the data.** There is no oblivious padding, as in every
  zka guest. Across the 64 AOL epochs at s = 16,384 the guest takes 5.24M-8.45M
  user cycles (8-12 segments).
  - The measured epochs 0 and 63 both have tau = 0 at s = 16,384. Eviction
    epochs cost more, so whole-stream claims should use the chain totals.
  - Uniform data nearly empties the summary under Misra-Gries: almost every
    count is 1, so tau >= 1 leaves 0-3 counters at s = 1,024. This is the
    rule's semantics, not a bug.
- **Implementation choices move the cost, and the headline is the cheapest we
  built** (radix sort, `read_slice`). It is not proven cycle-optimal: a
  hash-based grouping, or a merge that exploits S_old's existing (count, key)
  order, might be cheaper. Neither was tried.
- **Statement differences from zkSketch's leaf.**
  - Commitments are SHA-256, not Poseidon2, and unsalted, so they do not hide
    the state (as in zk-Analytics' code).
  - The guest maps the raw keys itself (328K cycles, the `map` column).
    zkSketch maps them natively and binds the mapped batch; Com_batch here
    binds the same mapped layout.
  - The guest computes S_new. zkSketch's circuit verifies it, with range
    checks, sortedness and permutation arguments; the guest checks only that
    its input is well formed.
  - The guest binds S_old only through Com_old. Linking Com_old to the previous
    epoch's Com_new is the verifier's job, as with zkSketch's per-leaf
    boundaries.
- **The phase split covers user cycles only.** Paging, the per-segment
  reserve and po2 padding (27-34% of the padded cycles of the headline rows)
  are not attributed to any phase. A phase's share of the prover's work can
  therefore differ from its share of user cycles: the transition is 54-72% of
  user cycles but 37-53% of padded cycles.
- **The host-only stdout channel** (marks and S_new, for the equivalence
  check) is included in the user cycles. It costs about 2,600 cycles per run.
- **Host build.** The host `Cargo.lock` is the union of the SS port's and
  zkSketch's. Where they disagreed, 19 crates were raised to the newer patch
  version; no Plonky3 crate was among them. This touches only the native
  reference build, not the guests.
- **ELF md5s and image IDs** were built from this worktree's path. We expect
  them to differ when built from another path, as for the other ports, with
  the same cycle counts; this was not checked for this guest.
- `exec_s` is wall-clock on a shared box and is not a metric.
