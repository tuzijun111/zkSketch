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

`ourcm/` and `zksq/` build against the zkSketch checkout they sit in, so a
worktree measures its own sources.

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
- Other build locations: `build/ourcm`, `build/zksq` and `build/shaccel` under
  `$BASELINE_DIR`; `nb-target-<T>` (`accuracy.sh native`) and `zka/target`
  (`a234.sh`, `compare.sh`) inside the clone's directory. `compare.sh` S1/S2 and
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
