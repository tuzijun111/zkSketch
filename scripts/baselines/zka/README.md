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

For the six-sketch comparison (zkSketch vs zk-Analytics on CM, HLL, SS, GK, Bloom,
KMV) use the single entry point `six/run_all.sh` (`check`, `build`, `quick`, `full`);
see "Six-sketch comparison (small scale)" below, the top-level README and
`docs/six_sketch_comparison.md` (the full guide). Its
scripts write to `results/six/` at the repository root, never into `results/` here.

| Variable | Default | Meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | zk-Analytics clone and its builds |
| `RESULTS` | `results/` next to the scripts | where CSVs and logs are written (`six/` scripts: `<repo>/results/six/...`; they refuse a directory holding tracked files) |
| `CM_TOPK_SLOTS` | per script | zk-Analytics top-k heap slots, a build-time constant |

`ourcm/`, `zksq/`, `ss_mg/`, `gk_bm2/` and `gk_matched/` build against the zkSketch
checkout they sit in, so a worktree measures its own sources.

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
| `bloom/run_exec.sh` | no (`PROVE=1`: yes) | `zka_bloom_exec.csv` (`PROVE=1`: `zka_bloom_prove.csv`) + `.log` | OUR partitioned Bloom filter guests (†) in their architecture: per-epoch aggregation and query-time OR merge, the whole pipeline in one run, plus the `bloom_query_words` state-encoding sensitivity (see "Bloom filter and KMV guests") |
| `kmv/run_exec.sh` | no (`PROVE=1`: yes) | `zka_kmv_exec.csv` (`PROVE=1`: `zka_kmv_prove.csv`) + `.log` | OUR KMV / bottom-k guests (†) in their architecture: per-epoch aggregation and query-time bottom-k union, plus the `kmv_query_words` sensitivity (see "Bloom filter and KMV guests") |
| `mg/` (built by `six/build.sh`) | - | - | OUR textbook Misra-Gries guests (†) in their architecture: the zk-Analytics side of family `ss` in the six-sketch runs since 2026-10-26 (see `mg/README.md`) |
| `ss_mg/ss_mg_exec.sh` | no | `zka_ss_mg_exec.csv`, `zka_ss_mg_equiv.csv`, `zka_ss_mg_exec.log` | OUR RISC Zero guest running zkSketch's exact SS batch rule (mergeable Misra-Gries), checked against zkSketch's native code (see "zkSketch's SpaceSaving batch rule as a RISC Zero guest") |
| `gk_bm2/gk_bm2_exec.sh` | no | `zka_gk_bm2_check.csv`, `zka_gk_bm2_exec.csv` (+ `.log`) | zkSketch's own GK band-merge batch transition in a RISC Zero guest, checked tuple by tuple against zkSketch's native `apply_batch2`; executor cycles at the deployed config (see "GK band-merge transition, matched semantics") |
| `gk_matched/gk_matched_check.sh` | no (`CERTIFY=1`: zkSketch's GK leaf and decoder proofs) | `zka_gk_matched_{check,aggr,certify}.csv` + `zka_gk_matched_check.log` | zkSketch's GK rule inside zk-Analytics' pipeline (the six-sketch GK default): equivalence with zkSketch's native chain, its leaf circuit and its decoder at configs (384, 128) and (768, 512) (see "GK with zkSketch's algorithm in their pipeline") |
| `six/run_all.sh` (entry point: `check`, `build`, `quick`, `full`); it drives `six/build.sh`, `six/run_zks.sh`, `six/run_zka.sh`, `six/prof_exec.sh`, `six/jobs.py`, `six/assemble.py`, `six/table.py` | yes: `quick` ~5-11 min, `full` ~3 h 30 min (zk-Analytics proofs at ~30 s per segment; see "Six-sketch comparison (small scale)", Running) plus gate waits (32 cores) | `<repo>/results/six/<mode>-<stamp>/` (git-ignored; the committed `six_*` here are the 2026-10-09 reference run) | zkSketch vs zk-Analytics on six sketches (CM theirs; HLL, SS, GK, Bloom, KMV our ports †; GK = zkSketch's own GK rule in their pipeline, `gk_matched/`) at 8 x 2,048 AOL records: update proving per epoch (zk-Analytics `noroot`, the headline; their shipped CM as a reference), query proving at n = 1, 2, 4, 8, verifier work, sizes, RSS, accuracy (see "Six-sketch comparison (small scale)") |

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
- `cm_noroot/` (ours) is the noroot variant of their CM aggregation, driven by `cyc`'s
  `shipped --family cm --root noroot` (its path dependency; built into the same
  `cyc-t<T>`): `core/` include!s line ranges that `gen_upstream.sh` cuts from the clone
  (`--check` re-verifies them), with one marked block replaced; `guests/` has
  `aggr_cm_noroot` and the validation twin `aggr_cm_twin`, with a lock derived from
  `hll/guests/Cargo.lock`. See "Root variants" under "Six-sketch comparison".
- Other build locations: `build/ourcm`, `build/zksq`, `build/shaccel`,
  `build/zka-mg`, `build/zka-ss-mg`, `build/zka-gk-bm2`, `build/zka-gk-matched`, `build/zka-bloom`
  and `build/zka-kmv` under `$BASELINE_DIR`;
  `nb-target-<T>` (`accuracy.sh native`) and `zka/target` (`a234.sh`,
  `compare.sh`) inside the clone's directory. `compare.sh` S1/S2 and
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
**Nothing here was proved.** Every prove time below is segments x 30.1 s (see below).

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

### Results (executor only; prove time = segments x 30.1 s, not measured)

Aggregation guest on one epoch (16,384 AOL records, 8,433 distinct keys):

| guest | T | key_id | state entries | user cycles | cycles/rec | segments | prove (segments x 30.1 s) |
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

Query guest over n populated epochs (segments, with segments x 30.1 s in parentheses):

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

### Prove time from segment counts, and the anchors behind it

The prove times above are `segments x 30.1 s/segment` (CSV column
`MODELED_prove_s`). The CSV also carries an envelope of `segments x 29.73` to
`segments x 30.79` (`MODELED_prove_s_lo`, `MODELED_prove_s_hi`), the per-anchor
minimum and maximum of the four CPU prove anchors. All four are CM guests, `ProverOpts::succinct()`,
r0vm 3.0.6, CPU only, on this 32-core box:

| anchor | prove_s | segments | s/segment | source |
|---|---|---|---|---|
| aggr_cm T=100, n=512 | 661.3 | 22 | 30.06 | `a2_anchor.csv` |
| aggr_cm T=1, n=16,384 | 3,202.0 | 104 | 30.79 | `zka_matched.csv` |
| querier_cm estimate, n=4 | 151.3 | 5 | 30.26 | `zka_query_sweep.csv` |
| querier_cm estimate, n=16 | 594.6 | 20 | 29.73 | `zka_query_sweep.csv` |

Every full segment is a po2=20 trace, so per-segment cost should depend little
on the instruction mix. That is an argument, not a measurement: **the samples
and histogram guests have no proved anchor yet**, and their seconds use the
s/segment of the CM guests only. The GPU prover was not used. Run one small
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
  metric. Cycles and segments are deterministic. All segments x 30.1 s figures
  assume CPU-only r0vm on this Threadripper.

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
| `zka_ss_anchor.csv` / `.log` | 3 proved | `spacesaving/ss_anchor.sh` | separate anchor CSV with a `prove_condition` column. Two rows come from the superseded first build (per-key root, image `1e73f3f3...`), one of them `contended`; only the `clean` `buckets64` row of the 64-bucket `aggr_ss` (image `0aff21e3...`) is a valid anchor |
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
- **Prove time.** Segments x 30.1 s, with an envelope of segments x 29.73 to
  x 30.79, from the four CM-guest CPU anchors above; not proved except where stated.

| | HLL † | SpaceSaving † | GK † |
|---|---|---|---|
| parameters | b = 14 (2^14 u8 registers) | s = 2^14 (matched; exact per AOL epoch, no eviction) and s = 1,024 (eviction exercised) | eps = 1/51, COMPRESS every 25 records |
| update (plain Rust) | textbook HLL, Flajolet et al. 2007 | Metwally et al., unit weight, Stream-Summary buckets (O(1) per record) | Greenwald-Khanna SIGMOD'01 INSERT / band COMPRESS; t_0 (the minimum) always kept, per the paper's section 2.1 invariant |
| hash / value | their FNV-1a `key_to_u64` (`aggregator/core/src/lib.rs:342`) + the seeded splitmix64 finaliser of their `cm_bucket_index` (`:1055-1063`, without `% CM_COLS`), CM row-0 seed `0x6d0f27bd` | the same mix without the seed, for the key-to-counter map; keys are compared in full | `value = key & 0x1FFFFF` (21 bits; the task text said 22-bit, the histogram arm's mask is the authority); `key_id` only enters the batch chain |
| epoch state, unsalted SHA-256 commit | `total_count` + 16 KB of registers | capacity, `total_count`, <= s `(key_id, count, error)` sorted by key | `total_count` + tuples `(v, g, Delta)` |
| per-type Merkle root in the aggregation journal (no query reads it) | legacy guest `hll_aggr`: **none** (dropped; cheaper than a literal port). The six-sketch comparison also runs `designed` (their samples pattern, 64 buckets) and `noroot`: see "Root variants of the zk-Analytics aggregation proofs" | their samples pattern: 64 hash buckets (their benchmark `SAMPLES_HT_BUCKETS=64`), folded by their `samples_buckets_root_from_leaves` | their `hist_per_key_root` pattern over tuples, their `MerkleTree` |
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

### Results (executor unless stated; prove time = segments x 30.1 s, not measured)

**Aggregation guest, one AOL epoch** (epoch 0: 16,384 records, 8,433 distinct keys):

| guest | config | user cycles | cycles/rec | segments | prove (segments x 30.1 s) | sketch update share | data dependence (other epochs) |
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

**Query guest over n epochs** (segments, with segments x 30.1 s in parentheses):

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

| guest | segments | prove_s | s/segment | segments x 30.1 s | conditions | receipt | verify | r0vm peak RSS |
|---|---|---|---|---|---|---|---|---|
| `hll_aggr` † | 11 | 332.1 | 30.19 | 331.1 s | 1-min load 11.4 at start; the driver has no contention sampler, and no other family's prover overlapped (by the logs' timestamps) | 224,554 B | 9.8 ms | 9,383 MB |
| `aggr_ss` † (64-bucket root, image `0aff21e3...`) | 16 | 473.4 | 29.59 | 481.6 s | `clean`: foreign r0vm in 0 of 470 samples | 224,818 B | 10.2 ms | 9,401 MB |
| `aggr_gk` † (fixed build, ELF `d0f88f7b...`) | 14 | 414.5 | 29.61 | 421.4 s | `contention=none`: 0 foreign r0vm in 1,607 samples; the builder's own nice-19 test build overlapped the first minute | 224,810 B | 11.6 ms | 9,389 MB |

- All three proved journals were asserted equal to the native output.
- The three non-CM guests land at 29.59-30.19 s/segment, within 2% of 30.1 s,
  against the CM envelope of 29.73-30.79.
- `zka_ss_anchor.csv` also holds two rows from the superseded first build
  (v1 image `1e73f3f3...`, per-key root): 672.4 s `clean` and 958.8 s
  `contended`. Neither is the current guest, and the contended one must never be
  used. Only the `clean` row for the 64-bucket image (`0aff21e3...`) is a valid
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
  provable bound is eps N with the corrected INSERT the port uses since
  2026-10-13 (eps N + 1/2 with the paper's original INSERT, which these committed
  rows used; every measured value was <= eps N). See `gk/README.md`, "INSERT's Delta".

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
- **The prove times rest on the four CM-guest anchors.** Each family has one
  proved anchor, for the aggregation guest at 2,048 records only. Those anchors
  agree with 30.1 s per segment within 2%, but every full-epoch and every query
  prove time is segments x 30.1 s, not a proof. No query guest was proved here
  (the six-sketch comparison below proves them at 2,048-record epochs).
  - Counting whole segments overstates rows whose last segment is partial.
    `padded_cycles / 2^20 x 30.1 s` is the lower sensitivity bound, and the gap
    matters only for small query guests. With segments x 30.1 s first and the
    bound second:
    - GK: n = 1, 30 s vs 3.8 s (po2 17); n = 4, 30 s vs 15 s; n = 16, 60 s vs
      34-45 s; rank at n = 64, 151 s vs 136 s.
    - HLL: n = 1, 30 s vs 15 s; n = 4, 60 s vs 38 s; n = 16, 151 s vs 124 s.
    - SS at s = 1,024, n = 1: 8-12%.

    Every other row is overstated by 2% or less.
  - The anchors ran on a shared box. The SS and GK drivers sample for foreign
    `r0vm` processes; the HLL driver does not.
- **CPU-only r0vm 3.0.6** on this 64-thread Threadripper. The GPU prover was not
  used. All segments x 30.1 s figures are CPU seconds.
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
  - GK's guarantee is eps N (since 2026-10-13; eps N + 1/2 for the committed
    2026-10-09 rows, which used the paper's original INSERT).
  - HLL answers carry the estimator branch taken.
- **Provenance.**
  - Each family was built, then reviewed independently.
  - SS and GK had blocking review findings, which were fixed and re-measured:
    - SS: the root pattern, the point-query path and the anchor hygiene;
    - GK: the lost minimum and a certificate that could exceed eps N.
  - HLL was accepted with non-blocking nits, still open: `hll_dirty` does not pin
    the sources. (The 10-seed spread nit is answered by the saved 200-seed file
    above.)
  - ELF md5s and image IDs depend on the absolute source path and on source line
    numbers (panic locations), comment lines included; cycle counts do not.
  - `exec_s` is wall-clock on a shared box and is not a metric.

## Bloom filter and KMV guests: zk-Analytics method, our implementation (†)

`bloom/` and `kmv/` add the last two of the six compared sketches (Count-Min, HLL,
SpaceSaving, GK, Bloom, KMV) to zk-Analytics' pipeline, built exactly like `hll/`
above: the textbook plaintext algorithm, one record at a time, in ordinary Rust,
executed as a RISC Zero guest inside **their** per-epoch architecture.
- A per-epoch aggregation guest verifies the source's SHA-256 batch hash chain
  (their code, verbatim), builds the epoch summary from scratch, commits to it with
  an unsalted SHA-256 (risc0's accelerated `sha::rust_crypto`) and links the
  commitment into their epoch hash chain (`EpochChainLink::new`). Its journal is
  theirs (`CmAggrOutput`) minus the CM Merkle roots: epoch link, state commit, event
  count, source chain tips.
- A query guest re-verifies the epoch chain links (their code, verbatim), recomputes
  every epoch's state commitment, **merges the n epoch states at query time** and
  answers, with their `MIN_SUPPORT = 10` suppression.

Neither uses zkSketch's batch rules or certificates (no oblivious padding, memory
checking, sorting certificates or Poseidon). **They are OUR implementations of
zk-Analytics' design, not zk-Analytics code**: mark every row †, cite them as "our
Bloom / KMV instantiation of zk-Analytics' per-epoch / query-time-merge architecture
(†)", never as "zk-Analytics' Bloom filter / KMV". The per-family READMEs
(`bloom/README.md`, `kmv/README.md`) have the full detail.

**Status: built and validated at tiny scale (2026-10-09); the comparison
measurement (8 epochs of 2,048 AOL records; aggregation proved on epochs 0 and 7,
queries proved at n = 1, 2, 4, 8) was run later the same day through
`six/run_zka.sh`, which calls these drivers directly: see "Six-sketch comparison
(small scale)".** `sketch_exec.sh` does not cover these two families; each has its
own runner.

### Running

```bash
scripts/baselines/zka/bloom/run_exec.sh              # executor: 8 x 2048 pipeline, queries n = 1 2 4 8, probes first,absent (+ words variant)
scripts/baselines/zka/kmv/run_exec.sh                # executor: 8 x 2048 pipeline, queries n = 1 2 4 8 (+ words variant)
PROVE=1 scripts/baselines/zka/bloom/run_exec.sh      # the planned measurement, proved: 8 aggregation + 4 query proofs
PROVE=1 scripts/baselines/zka/kmv/run_exec.sh        # (run one after the other, on a quiet machine)
```

- The drivers (`bloom`, `kmv`) have three modes: `aggr` (one aggregation guest),
  `query` (one query guest over natively aggregated epochs) and `exec` (the whole
  pipeline: the aggregation guest on every epoch in order, each epoch's chain taken
  from the previous guest journal, and the query guest after epoch n for every n in
  `--query-at`). With `--prove` every guest run of the invocation is also proved
  (`ProverOpts::succinct()`, CPU), its journal asserted equal to the native output.
  `--words` also runs each query as the `*_query_words` guest (sensitivity, as
  `hll_query_words`: the same query and journal, the state in serde's default
  `Vec<u32>` / `Vec<u64>` encoding, the form of their `CmEpochState`). The runners
  pass it by default for executor runs and not under `PROVE=1`; under `PROVE=1` the
  Bloom runner's default probe is `first` only, so `PROVE=1 run_exec.sh` as is runs
  the planned 12 proofs per family.
- CSV columns: user / padded cycles, segments, max po2, the guest's phase split,
  `prove_s`, `verify_ms`, `receipt_bytes`, `prove_r0vm_peak_rss_mb` (VmHWM of the
  driver's r0vm descendants), `contention` (foreign r0vm CPU seconds,
  `other_cores_avg` = the cores busy with anything else, and the runner's load gate
  `gate=load1_start=..;max_load=..;waited_s=..`), the answer, the exact answer,
  `journal_eq_native`, an independent host reference (`ref_check`) and the accuracy
  columns. The driver exits 1 if any check fails.
- **Which proved rows are timing-grade.** `arm = proved_contended` at >= 10 foreign
  r0vm CPU s or >= 4 other cores busy; `MAX_LOAD` raised above its default 24 appends
  `_override`, and `ARM_TAG=<tag>` appends `_<tag>` (the validation proofs below use
  `validation`). Only `arm = proved`, in `zka_{bloom,kmv}_prove.csv`, is a timing
  measurement; the runner prints a re-run command for every contended row.
- **`PROVE=1` gate.** The runner takes `$BASELINE_DIR/build/zka-prove.lock` (shared
  by the two families: a second Bloom or KMV prover refuses), then waits up to
  `WAIT_S` (1,800 s) until the 1-minute load is <= `MAX_LOAD` (24) and no `r0vm` of
  any user runs (`sketch_exec.sh`'s rule), and refuses (exit 3) otherwise. Rows reach
  the CSV and the log as each guest run finishes, so an interrupted run keeps them.
- Builds: `$BASELINE_DIR/build/zka-{bloom,kmv}`, `--locked`, `RISC0_BUILD_LOCKED=1`.

### Exact configuration

| | Bloom † | KMV † |
|---|---|---|
| parameters | partitioned, k = 7 slices x W = 2^14 bits (zkSketch's `EXP_BLOOM_K` / `EXP_BLOOM_LOGW` defaults) | k = 1,024 (zkSketch's KMV k) |
| update (plain Rust, per record) | set the key's bit in each slice | insert the key's hash into an ordered set of the k smallest distinct hashes (evict the largest) |
| hash | slice j: their `cm_bucket_index` formula (`aggregator/core/src/lib.rs:1055-1063`): FNV-1a `key_to_u64` XOR `(seed << 32 \| seed)`, splitmix64 finaliser, `mod W`. Seeds: their 3 CM seeds for slices 0-2, 4 fixed constants of ours for slices 3-6 | the HLL port's 64-bit hash (`key_to_u64` + seeded splitmix64, CM row-0 seed `0x6d0f27bd`) |
| epoch state, unsalted SHA-256 commit | `total_count` + 14,336-byte packed bitset | `total_count` + <= k values ascending (big-endian) |
| query-time merge | bitwise OR of the n filters | bottom-k of the union (linear merge of the sorted sets, dedup) |
| query (answer in the journal) | membership of one key: the key and `member` | distinct count: `D` if fewer than k values, else `floor((k-1) 2^64 / v_k)` in u128 (the (k-1)/U_(k) estimator); plus `kept`, `v_k`, branch |
| accuracy columns | false negatives over all inserted keys (must be 0); measured FPR on 10,000 keys absent from the dataset vs the filter's own expected FPR and the textbook `(1 - (1-1/W)^n)^k` | relative error against the exact distinct count; std err 1/sqrt(k-2) = 3.13% |

Records, batching and chains are those of the families above (`data/aol.keys`; epoch e
= keys `[e*m, (e+1)*m)`, default m = 2,048; one source, batches of 8; chains carried
across epochs). Both state types travel as packed byte strings (the HLL port's
`packed_bytes` pattern), the cheaper encoding; the `*_query_words` guests measure the
default encoding (see Caveats).

### Reused from upstream vs written by us

| item (upstream `d4a5a9a`) | Bloom † | KMV † |
|---|---|---|
| `verify_and_compute_chain`, `verify_epoch_chain_integrity`, `events_commit`, `chain_tips_to_sorted_vec`, `sha256_bytes`, `TAG_SHARD_CHAIN`, `TAG_EPOCH_CHAIN` | copied verbatim (`gen_upstream.sh`; the file is byte-identical to `hll/`'s) | copied verbatim (same) |
| `Event`, `make_key_id`, `BatchInput`, `CmAggrInput`, `EpochChainLink::new`, `batch_chain_hash`, `key_to_u64`, `CM_SEEDS`, `MIN_SUPPORT` | path dependency | path dependency |
| structure mirrored step for step | `process_cm_aggr_with_state`, `run_cm_query`, guests `aggr_cm` / `querier-guest-cm` | same |
| **written by us** | insert / lookup / OR merge, 4 extra seeds, state type, tag, packing, the `bloom_query_words` variant, probes, host driver (reference filter, FPR, `exec` mode, RSS/contention sampler), runner | bottom-k insert, merge, integer estimator, state type, tag, packing, the `kmv_query_words` variant, probes, host driver (reference bottom-k, `exec` mode, sampler), runner |

### Validation results (VALIDATION ONLY; executor unless stated)

AOL, batches of 8; every row passed `journal_eq_native`, `ref_check` and the
accuracy checks. Rows: `results/zka_{bloom,kmv}_validation.csv` (26 and 18 rows, with
`.log`; regenerated 2026-10-09 with the words variants, the gate column and the
`validation` arm tag).

| guest | epoch size | n | user cycles | segments | per record / per epoch | answer vs exact |
|---|---|---|---|---|---|---|
| `bloom_aggr` † | 256 | 1 (epoch 0) | 1,445,193 | 2 | 5,645 / rec | 0 false negatives; 0 / 10,000 FP |
| `bloom_aggr` † | 2,048 | 1 (epoch 0) | 11,091,937 | 12 | 5,416 / rec (update 543) | 0 false negatives; 0 / 10,000 FP |
| `bloom_query` † | 256 or 2,048 | 1 | 104,907 (byte-loop merge: 180,159) | 1 | - | inserted key: true; absent key: false |
| `bloom_query` † | 256 or 2,048 | 2 | 192,870 (byte-loop merge: 343,378) | 1 | +87,963 / epoch | inserted key: true; absent key: false |
| `bloom_query_words` † | 256 or 2,048 | 1 | 705,882 (byte-loop merge: 777,550) | 1 | - | same journal as `bloom_query` |
| `bloom_query_words` † | 256 or 2,048 | 2 | 1,394,596 (byte-loop merge: 1,537,936) | 2 | +688,714 / epoch | same journal as `bloom_query` |
| `kmv_aggr` † | 256 | 1 (epoch 0) | 1,404,153 | 2 | 5,485 / rec | 174 = exact (exact branch) |
| `kmv_aggr` † | 2,048 | 1 (epoch 0) | 11,104,487 | 12 | 5,422 / rec (update 543) | 1,232 vs 1,234 (-0.16%) |
| `kmv_query` † | 2,048 | 1 | 151,365 | 1 (po2 18) | - | 1,232 vs 1,234 (-0.16%) |
| `kmv_query` † | 2,048 | 2 | 296,524 | 1 (po2 19) | +145,159 / epoch | 2,290 vs 2,372 (-3.46%, 1.1 std err) |
| `kmv_query` † | 256 | 1 / 2 | 56,610 / 109,515 | 1 | - | 174 / 365 = exact |
| `kmv_query_words` † | 2,048 | 1 / 2 | 421,894 / 837,466 | 1 (po2 19 / 20) | +415,572 / epoch | same journal as `kmv_query` |
| `kmv_query_words` † | 256 | 1 / 2 | 102,495 / 207,781 | 1 | - | same journal as `kmv_query` |

- As for HLL, SS and GK, their framework dominates the aggregation: reading the
  `Event` batches is ~68.5% of both guests (~3,710 cycles per record) and the batch
  chain ~20%; the sketch update is ~10% (543 cycles per record).
- One tiny **proved** pipeline per family (epoch size 256, 1 epoch: one aggregation,
  one query and one words-query proof, `ARM_TAG=validation`) validated `--prove`;
  every proved journal equals the native output. `bloom_aggr` 2 segments (po2 20 +
  19), 50.3 s; `bloom_query` 1 segment, 9.6 s; `bloom_query_words` 1 segment (po2
  20), 29.6 s; `kmv_aggr` 2 segments (po2 20 + 19), 50.4 s; `kmv_query` 1 segment,
  6.4 s; `kmv_query_words` 1 segment, 9.5 s; receipts 224,082-224,554 B, verify
  9.7-9.8 ms, r0vm peak RSS 9.4 GB (aggregation, `bloom_query_words`) and 1.4-2.4 GB
  (the other queries). A sibling job kept 4.9-10.2 other cores busy, so every proved
  row is `arm = proved_contended_validation`: these are not timing measurements.

### Caveats

- **Ours (†).** zk-Analytics ships neither sketch.
- **Measured since.** The rows above are the tiny validation. The 8 x 2,048
  measurement (executor on all 8 epochs, proofs of epochs 0 and 7 and of the
  queries at n = 1, 2, 4, 8) is in "Six-sketch comparison (small scale)" below.
- **State encoding is a lever (measured).** risc0's serde reads a `Vec<u32>` /
  `Vec<u8>` / `Vec<u64>` one element per word at ~150 cycles per word, a byte string
  in bulk; both encodings are the same number of words. With the state in the
  default encoding the n = 1 query costs 4.3x (Bloom: 777,550 vs 180,159; reading
  one filter 559,215 vs 23,043 cycles, plus 61,206 to copy the words into bytes) and
  2.8x (KMV at 2,048 records: 421,894 vs 151,365; reading one full state 315,794 vs
  45,380). The packed form (cheaper baseline) is the headline, as for HLL.
- **Cheaper than a literal port**, as for HLL: no per-type Merkle root; Bloom hoists
  the FNV fold out of the per-slice loop (their CM recomputes it per row); one
  SHA-256 `update` per state commit; KMV merges linearly.
- **KMV hash width differs from zkSketch's** (64 vs 27 bits): estimates differ by the
  hash draw, so compare error distributions, not individual rows.
- **Inherited from their code, unchanged**: unsalted (non-hiding) commitments; chain
  checks only when links are supplied; genesis links start a new chain; each query
  also needs the n aggregation receipts, verified separately.
- **ELF md5s and image IDs depend on the absolute source path**; the validation rows
  were built in a worktree, so their `image_id`s differ from a main-checkout build.
  Cycle counts do not depend on it.
- **Cycle counts do depend on the build.** Adding the words types to the core crates
  changed the aggregation ELFs, though the guests do not use the types: `kmv_aggr`
  moved by -0.10% (-11,443 cycles at 2,048 records; batch-chain verification -60
  cycles per batch) and `bloom_aggr` by -19 cycles. The query guests did not move.
  The measurement must use one build for all rows.

## Six-sketch comparison (small scale)

zkSketch against zk-Analytics (Zhu et al., SIGCOMM '26; RISC Zero zkVM; clone at
`d4a5a9a`) on six sketches, on one small, identical workload. zk-Analytics ships only
Count-Min. **For HLL, Misra-Gries, Bloom and KMV the zk-Analytics side is our
plain textbook per-record code in their per-epoch pipeline with query-time merge
(the ports above, marked †), not zk-Analytics code. For GK it is zkSketch's own GK
algorithm in their pipeline (`gk_matched/`, †; since 2026-10-15, `SIX_ZKA_GK=matched`,
the default):** both sides then run the same function, zkSketch's two-sided band-merge
batch rule with zkSketch's capacity, s and leaf size, the state carried from epoch to
epoch, so the GK comparison prices the same work. Textbook GK (`gk/`, a summary rebuilt
per epoch plus a query-time merge, a different algorithm) stays as a labelled reference
(`SIX_ZKA_GK=textbook`); the committed 2026-10-09 rows below are textbook. See "GK with
zkSketch's algorithm in their pipeline". The other matched-rule guests (`ss_mg/`,
`gk_bm2/`) are not used here (`gk_matched/` reuses `gk_bm2/`'s transition code).

> **Zero knowledge.** RISC Zero succinct receipts are zero-knowledge. zkSketch now
> builds with zero knowledge ON by default (Cargo feature `zk`, default since
> 2026-10-10: `HidingFriPcs` plus masked LogUp sums, from the forks pinned in
> `Cargo.toml`); its CSV rows then say `pcs=hiding,logup_mask=on`, and
> `six/run_all.sh` measures that build. **The committed `six_zksketch_*` and
> `six_zksketch_r2_*` rows below (2026-10-09, `features=default`) PREDATE it**: they
> used the plain `TwoAdicFriPcs`, not `HidingFriPcs`, so those proofs are **not**
> zero-knowledge, and the Results tables below are those non-ZK numbers. Zero
> knowledge costs zkSketch more (at this shape the LogUp masks alone add +16% (CM) /
> +18% (HLL) end to end over an unmasked hiding build; `docs/build.md`, "Zero knowledge
> (on by default)", *Cost*), and much more for GK at this shape: one GK run of the default (ZK) build
> on 2026-10-12, on a shared, loaded machine, took 824 s wall, 70 s of leaf proving
> per batch and 58.8 GiB peak RSS (worker; coordinator 57.9 GiB while deriving the
> root VK), against 215 s, 14.7 s and 19.4 GiB in `six_zksketch_r2_gk`. That run used
> the pre-M3 `sorted` GK circuit; the default `stable` circuit at 2 batches of 2,048
> (2026-10-19) took 86 s wall, 19.3 s of leaf proving per batch and 15.1 GiB. Re-run with
> `six/run_all.sh full` before quoting zero-knowledge numbers. The committed `quick_zksketch_*` rows (2026-10-10,
> 256 records per batch, `pcs=hiding,logup_mask=on`) are from the ZK build. Both
> zkSketch builds use hiding (salted Poseidon2) state commitments (`ZKSKETCH_COMMIT`
> default `hiding`, OS-seeded salt); zk-Analytics commits with unsalted SHA-256.
>
> **The `zk` rows are pre-masking.** `zk2_zksketch_*` and `tiny_zksketch_*`
> (`features=zk-default`, zkSketch `da4ff6e`) and any `six_zksketch_zk_*` set were
> measured with `HidingFriPcs` on the UNFORKED Plonky3 / Plonky3_RangeAir pins,
> i.e. before the LogUp masks (`docs/build.md`, "Zero knowledge (on by default)"):
> their proofs reveal unmasked LogUp sums, which a verifier can
> test witness guesses against, so they are not zero-knowledge either (e.g.
> `zk2_zksketch_cm.csv` has a 752,564-byte root; a re-run of that exact CM shape
> on 2026-10-10 gave 752,728 bytes unmasked and 804,048 masked, and took 26.2 s
> unmasked vs 30.3 s masked). The masking costs the composed run more than the
> leaf (`docs/build.md`, "Zero knowledge (on by default)", *Cost*); re-measure on the masked build
> (its CSV rows say `pcs=hiding,logup_mask=on`) before quoting zkSketch
> zero-knowledge numbers.

### Configuration (both sides identical)

- **Data.** `data/aol.keys` (md5 `01dd7d5c8a73`), the first 16,384 records, cut into
  8 epochs / batches of 2,048 consecutive records (epoch e = records
  `[2048 e, 2048 (e+1))` on both sides). zk-Analytics side: one source, batches of 8
  records (their `--commit-batch-size` default), the SHA-256 batch chain and epoch
  chain carried across epochs.
- **Parameters.**

  | sketch | zk-Analytics side | zkSketch side | query (both sides) |
  |---|---|---|---|
  | Count-Min | their `aggr_cm` / `querier-guest-cm`, 3 x 1024, `CM_TOPK_SLOTS=1` | `cm` (omc leaf), `EXP_D=3 EXP_W=1024` | point count of the heaviest key of the queried prefix (their `Estimate` target rule; zkSketch `EXP_QUERY_KEY_MODE=hot`; ties to the smaller key on both sides; the same key on both sides at each n: 3,011,223,745 for n <= 5, 3,780,053,395 for n >= 6) |
  | HyperLogLog | `hll/` †, b = 14 | `hll` (omc), `EXP_HLL_B=14` | cardinality |
  | Misra-Gries | `mg/` †, textbook Misra-Gries s = 1,024 per epoch, mergeable Misra-Gries merge at query time (until 2026-10-26: `spacesaving/` †, SpaceSaving with a sum-and-truncate merge; the published runs used it) | `ss` (certified MG), `EXP_SS_CAP=1024` | top-1: theirs `topk --limit 1` (key, count); ours the top-1 mass (`c = 1`, count only, no key). This is the closest pair the two query sets allow |
  | Greenwald-Khanna | `gk_matched/` † (default, `SIX_ZKA_GK=matched`): zkSketch's band-merge rule, `--capacity $SIX_GK_CAP --s 51 --m-sub $SIX_GK_MSUB` (= 2048 / 51 / 2048: one `apply_batch2` step per epoch), state carried across epochs, guest implementation `literal` (`SIX_ZKA_GK_IMPL`; `tuned` / `fast` / `fixed_linear` are sensitivity rows). Reference (`SIX_ZKA_GK=textbook`, and the committed rows): `gk/` †, textbook GK, eps = 1/51, COMPRESS every 25 records | `gk` (band-merge), `EXP_GK_CAP=2048 EXP_GK_S=51 EXP_GK_ROUNDS=$SIX_GK_ROUNDS` (`SIX_GK_ROUNDS`, default `stable`: the M3 stable-compaction leaf, CSV `variant` `gk_bandmerge2_stable`, `gk_rounds` `stable`; `sorted` = the pre-M3 leaf byte for byte, `variant` `gk_bandmerge2`, which every zkSketch GK row recorded before M3, 2026-10-15, used) | rank of the same value on both sides: the most frequent 21-bit value of the prefix (zkSketch `EXP_QUERY_KEY_MODE=hot`; 1,810,625 for n <= 5, 985,491 for n >= 6), passed to theirs as `--rank-value`; the matched port answers with zkSketch's decoder estimator on the latest state |
  | Bloom (partitioned) | `bloom/` †, k = 7 x W = 2^14 | `bloom`, `EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14` | membership of the same two keys per n: an inserted key (the first record of batch n; zkSketch `first`, theirs `--probe first`) and an absent key (zkSketch `EXP_QUERY_KEY_MODE=absent`, a second zkSketch run; the key it drew is passed to theirs as `--probe key:<k>`) |
  | KMV / bottom-k | `kmv/` †, k = 1,024, 64-bit hash | `kmv`, `EXP_KMV_K=1024`, 27-bit hash | distinct count |

- **zk-Analytics side.** `ProverOpts::succinct()`, CPU r0vm 3.0.6 (guests link
  risc0-zkvm 3.0.5, hosts 3.0.6), GPU not used, r0vm free to use all 64 hardware
  threads. Executor over all 8 aggregation epochs of every family (cycles,
  segments). **Proved: aggregation epochs 0 and 7 only (2 samples per family;
  "sampled" below = their mean)**, and the query guest at n = 1, 2, 4, 8.
  Every proved journal is asserted equal to the native output. A `six/run_all.sh`
  run proves the aggregation epochs as `noroot` (the headline) and their shipped CM
  (`designed`) as a reference (next subsection); the committed 2026-10-09 run is the
  `legacy` variant.
- **zkSketch side.** `examples/exp_compose`, release build of this commit,
  `EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=procs EXP_COMPOSE_MACHINES=1
  EXP_COMPOSE_CORES=32 EXP_COMPOSE_N=16384 EXP_COMPOSE_BATCHES=2048
  EXP_COMPOSE_QUERY_EVERY=1 EXP_DATASET=aol`, default (hiding) commitments, one run
  per family (two for Bloom). The procs engine is set explicitly: it is the
  documented default only for more than one machine, and it gives true per-process
  RSS. `EXP_QUERY_LOG=1` (added for this comparison; logging only, no proof or
  timing change) prints one line per query with its probe key, prove / verify
  time, proof bytes, answer, and the prefix certificate it was bound to with
  `query_bind_ms`, which the CSV only reports as sums.
- **Quiet box.** Every timed run (each zkSketch run, each zk-Analytics proof) waited
  until the 1-minute load was <= 8, fewer than 4 cores were busy (2 s `/proc/stat`
  window) and no `r0vm`, `exp_compose`, procs-engine worker, `cargo` or `rustc` of
  any user ran (`six/gate.sh`; polled every 30 s). The load at start and end of each
  run is in `six_zka_jobs.csv` / `six_zksketch_runs.csv`. Runs were strictly
  sequential. Box: AMD Threadripper PRO 9975WX, 32 cores / 64 threads, 559 GiB,
  CPU only.

### Root variants of the zk-Analytics aggregation proofs (designed / noroot / legacy)

**In plain words.** Besides updating the sketch, every zk-Analytics aggregation proof,
as their code ships, also builds a Merkle tree over the sketch's buckets and outputs its
root: a short hash that would let someone check one bucket without the whole state.
zk-Analytics' code does this in every summary type it ships (samples, histogram,
Count-Min), but that root is not part of their protocol, and nothing uses it:

- **The paper.** In Section 5.2 (Algorithm 2) an epoch publishes the per-source
  hash-chain boundaries, the epoch hash-chain values and one commitment to the whole
  epoch state; in Section 5.3 (Algorithm 3) the query proof opens that one commitment
  for each epoch it reads. Per-bucket roots appear nowhere; the paper's only Merkle
  mention (Section 4) says the data sources commit their logs with hash chains instead
  of Merkle trees because membership proofs are not required at that stage.
- **The code.** The roots go into the aggregation journal and into the `out_commit`
  the host stores in its database; no query guest, verifier or other code reads them,
  and their per-bucket inclusion-proof helpers (`samples_merkle_proof_for_bucket`,
  `samples_merkle_root_from_leaf_and_siblings`) are never called. A per-key
  Merkle-proof query mode exists only as a TODO comment in their querier
  (`querier/core/src/lib.rs`, `EpochData`); no implemented path uses the roots. The next
  epoch and every query guest read the flat SHA-256 commitment of the state.

zkSketch commits to its state too, but publishes no such per-bucket root. The root is
not free: for Count-Min it is about half of every aggregation proof at 2,048 records per
epoch (11.2M of 22.5M cycles, 24 segments vs 12). So:

- **`noroot`** = their guests with only the root work removed (for CM, their own code
  minus only the Merkle lines): **the default and the headline**, for all six sketches;
- **`designed`** (a historical name: as their code ships, root included, not as their
  paper designs it) = the guests with the root: for CM their shipped guest unchanged, which
  is proved as a **reference** only (`zkA shipped CM`, its own table), so the numbers can
  be related to zk-Analytics' published ones, which include that cost; for the † ports
  their samples-pattern root with 64 buckets, an option (`SIX_ZKA_ROOTS=designed,noroot`)
  that is not in the default plan or headline tables.

Both variants hold the same state, produce the same `state_commit` and epoch link, and
give the same query answers (checked on every run); query proofs read no root, so they
are proved once and hold for both. One more paper-vs-code difference, which favours
zk-Analytics slightly and which we keep: the paper's state commitment is hiding (fresh
randomness r_t per epoch), but their code commits with unsalted SHA-256. The committed
2026-10-09 results in this directory are the `legacy` variant (CM their shipped roots,
SS samples pattern with 64 buckets, GK a per-tuple root, HLL / Bloom / KMV none) and are
labelled so wherever they are read.

**In detail.** Each of zk-Analytics' summary types builds, inside every epoch's
aggregation proof, a per-type Merkle root over its state IN ADDITION to the flat SHA-256
`state_commit` that the epoch chain and every query guest use: samples `buckets_root`
(`samples_buckets_root_from_leaves` over `SAMPLES_HT_BUCKETS` hash buckets), histogram
`buckets_root` (`hist_per_key_root`, one leaf per key), CM `row_roots` (one SHA-256 leaf
per counter, 3 x 1,024, each row folded by their `MerkleTree`) + `cm_root` + `heap_root`
(`aggregator/core/src/lib.rs`). Their host folds the roots into an `out_commit` kept in its
database; no query guest or verifier reads them. For CM the root work is about 11.1-11.2M
cycles per epoch whatever the number of records (11.2M at 2,048 records; below). The committed 2026-10-09 ports
were inconsistent about it (SpaceSaving: samples pattern, 64 buckets; GK: per-tuple root;
HLL / Bloom / KMV: none). Every aggregation driver now takes `--root`, and the comparison
uses two consistent variants (`noroot` the default and headline; `designed` for the CM
reference and as an option):

| `--root` | meaning | CM | HLL, SS, GK, Bloom, KMV (†) |
|---|---|---|---|
| `designed` | zk-Analytics as their code ships it, root included (CM: the reference; ports: an option) | their `aggr_cm`, unchanged (same ELF) | the cheapest of their root constructions applied uniformly: their samples pattern with 64 buckets (cells -> 64 buckets, leaf = SHA-256(tag \|\| the bucket's cells in canonical order), folded by their pub `samples_buckets_root_from_leaves`; the number of leaves is `next_pow2_ge(max bucket + 1)`, 64 in every run here) |
| `noroot` | the default and the headline: zk-Analytics' protocol without the root its code adds (zkSketch commits its state but publishes no per-bucket root either) | `aggr_cm_noroot` (`cm_noroot/`): their `process_cm_aggr_with_state` cut byte for byte from the clone by `cm_noroot/gen_upstream.sh` (which `six/build.sh` runs with `--check`), with only lines 1262-1274 (row_roots, cm_root, heap_root) replaced by zeros; chain verification, flattening, table and heap update, `state_commit`, epoch link and journal type unchanged | the same guest as `designed`, root field zero |
| `legacy` (the drivers' default `--root`) | the guests of the committed 2026-10-09 reference rows (family `ss` now runs the Misra-Gries port, whose legacy guest is `aggr_mg`, 64-bucket root compiled in) (GK: since 2026-10-13 with the corrected INSERT, like every GK guest, so a re-run gives about 1% fewer cycles than those rows; see `gk/README.md`, "INSERT's Delta") | `aggr_cm` | `hll_aggr`, `aggr_ss`, `aggr_gk`, `bloom_aggr`, `kmv_aggr`: SS samples-pattern 64 buckets, GK per-tuple root, HLL / Bloom / KMV none |
| sensitivity | | `twin` (validation only, below) | SS `buckets1024`, `perkey`; GK `pertuple` |

The designed / noroot guests of the ports read the variant before their input and commit
it with the journal: `hll_aggr_root`, `bloom_aggr_root`, `kmv_aggr_root` (`guests/aggr_root`),
`aggr_gk_root` (`gk/guests/aggr_root`), and for family `ss` the Misra-Gries port's `aggr_mg_rootvar`
(`mg/`; the committed rows used SpaceSaving's `aggr_ss_rootvar`). HLL,
Bloom and KMV run their legacy aggregation function itself and then the root step; GK and
SS run the legacy steps with the root construction chosen at run time. The variant code
of HLL / Bloom / KMV / GK lives in each core crate's `src/root.rs`, compiled only with the
crate feature `root` (enabled by `guests/aggr_root` and the host driver), so adding the
variants left every pre-existing guest ELF of the six families byte-identical. The cell ->
bucket map, per family:

| family | cells | cell -> bucket (64 buckets) | leaf body, canonical order |
|---|---|---|---|
| SS | monitored entries (keyed) | their `samples_bucket_index` mix of the key id (FNV-1a fold, murmur3 fmix64, `& 63`): `ss_bucket_index` | entries sorted by key id: key id, count, error |
| KMV | held 64-bit hash values (keyed) | the same mix applied to the value itself (it already is a 64-bit key hash): `kmv_bucket_index` | the bucket's values ascending, big-endian |
| HLL | 2^14 one-byte registers (array) | fixed partition: register i -> i / 256 (64 contiguous groups of 256) | the 256 register bytes in index order |
| Bloom | 3,584 32-bit filter words = 14,336 bytes (array) | fixed partition: byte i -> i / 224 (64 contiguous groups of 56 words, 1,792 bits) | the 224 bytes in index order |
| GK | the n tuples of the value-ordered summary (array) | fixed partition: tuple i -> i * 64 / n | the group's tuples (v, g, delta, big-endian) in index order |
| GK, matched (`gk_matched/`, the default since 2026-10-15) | the k active tuples of zkSketch's state (array) | fixed partition: tuple i -> i * 64 / k | the group's tuples (e, g, g°, Delta, Delta°, t, big-endian) in index order |

The matched GK guest `aggr_gkm` has `designed`, `noroot` and `pertuple` (one guest, the
variant read before the input, as `aggr_gk_root`) and **no `legacy`**: `legacy` is the
committed textbook-GK guest, so `SIX_ZKA_ROOTS` with `legacy` needs `SIX_ZKA_GK=textbook`
(`six_common.sh` and `run_all.sh` refuse the combination).

Leaves are tagged `ZKA_PORT_<FAM>_BUCKET_V1` (ours; cf. their `TAG_BUCKET_LEAF`). Query
guests read no root, so query proofs do not depend on the variant (the drivers refuse
`--root` with `--mode query`; Bloom / KMV `--mode exec` carry the chain from the variant's
journals and their query rows are identical across variants). Every aggregation row of all
six drivers ends with `root_variant,root_construction,variants_agree,state_commit`
(`-` on query rows): `variants_agree` = every variant of that family run natively on the
same input gives the same state, `state_commit`, epoch link, `n_events` and source chain
tips, with a zero root exactly for `noroot` (CM: their aggregation vs the noroot copy); the
drivers exit 1 when it or `journal_eq_native` fails.

**Validation (2026-10-13; executor, AOL, batches of 8; fresh-server sandbox, rustc 1.97.1,
r0vm 3.0.6).** At 64 and 256 records per epoch, epochs 0 and 1, every family x variant
(incl. CM `twin`, SS `buckets1024` / `perkey`, GK `pertuple`): `journal_eq_native` and
`variants_agree` true, one `state_commit` across all variants, noroot cycles below designed.
The query guests and the Bloom / KMV pipelines (`--mode exec`) give identical rows under
every `--root`. All core unit tests pass (`cargo test -p <core> --features root`; each port
has a `root_variants_agree_except_root` test that recomputes the designed root
independently). CM `designed` is their ELF: 12,103,251 cycles at 128 records and 12,799,204
at 256 (the numbers of the root-cost analysis), 22,540,245 at 2,048. The CM `twin` guest
(`cm_noroot/core/src/lib.rs`, "twin"), an unedited copy of their code compiled in our crate,
costs aggr_cm + 0.40M cycles at every size; a pprof profile (`RISC0_PPROF_OUT`) puts all of
it inside their generic `MerkleTree` (monomorphized in our crate with different inlining)
and none in the rest, so `noroot` costs what their aggregation costs without its Merkle
work. Epoch 0 at 2,048 records (this configuration; segments of 2^20):

| family | designed: cycles (segments) | noroot: cycles (segments) | root work | legacy: cycles (construction) |
|---|---|---|---|---|
| CM | 22,540,245 (24) | 11,364,064 (12) | 11,176,181 | 22,540,245 (their roots; = designed) |
| HLL | 10,679,099 (11) | 10,383,921 (11) | 295,178 | 10,395,108 (none) |
| SS | 14,067,446 (15) | 13,158,936 (14) | 908,510 | 14,067,391 (samples, 64 buckets, compiled in) |
| GK | 13,207,588 (14) | 12,983,145 (14) | 224,443 | 13,407,572 (per-tuple) |
| Bloom | 11,353,107 (12) | 11,080,766 (12) | 272,341 | 11,091,953 (none) |
| KMV | 11,526,366 (12) | 11,108,717 (12) | 417,649 | 11,104,487 (none) |

The CM, HLL, Bloom and KMV legacy numbers equal the committed `six_zka_*_exec.csv` epoch 0
exactly; SS and GK differ from them by +832 and +1,664 cycles already in this sandbox's
build of the unchanged sources. noroot - legacy for HLL / Bloom / KMV is -11,187 /
-11,187 / +4,230 cycles (the root guest reads one more word and commits 132 more journal
bytes; HLL and Bloom's chain verification compiles 15K cycles cheaper in it).

Toy proofs of every new guest (2026-10-13, 64 records, epoch 0, `--prove`:
`ProverOpts::succinct()`, CPU r0vm; one at a time on a shared box at 1-minute load ~60-75
from other users' jobs, so the times are indicative only; peak RSS from `six/rss_tree.sh`).
Every proved journal equals the native output:

| family | variant | user cycles | padded (po2) | prove_s | verify_ms (best of 5) | receipt bytes | r0vm peak RSS MB |
|---|---|---|---|---|---|---|---|
| CM | noroot | 663,500 | 2^20 | 31.2 | 10.6 | 225,834 | 9,347 |
| HLL | designed | 693,607 | 2^20 | 30.8 | 9.9 | 224,818 | 9,351 |
| HLL | noroot | 398,429 | 2^19 | 18.0 | 9.9 | 224,818 | 4,704 |
| SS | designed | 687,530 | 2^20 | 34.6 | 10.7 | 224,826 | 9,353 |
| SS | noroot | 435,722 | 2^19 | 19.0 | 9.8 | 224,826 | 4,704 |
| GK | designed | 629,480 | 2^20 | 32.5 | 10.5 | 224,818 | 9,344 |
| GK | noroot | 405,281 | 2^19 | 19.1 | 9.8 | 224,818 | 4,701 |
| Bloom | designed | 687,425 | 2^20 | 36.9 | 10.6 | 224,818 | 9,354 |
| Bloom | noroot | 415,084 | 2^19 | 19.6 | 10.6 | 224,818 | 4,690 |
| KMV | designed | 605,837 | 2^20 | 36.1 | 10.6 | 224,818 | 9,345 |
| KMV | noroot | 374,635 | 2^19 | 19.5 | 11.0 | 224,818 | 4,684 |

CM `designed` (their `aggr_cm`, 11,755,177 cycles = 13 segments of 2^20 at 64 records) was
not proved at toy size; at 30.1-33.7 s per 2^20-cycle segment it would take about 6.5-7.5
minutes. Succinct receipts are the same size whatever the variant (the journal differs by
the root field); peak RSS follows the largest segment (2^20: ~9.35 GB, 2^19: ~4.7 GB).

**How the comparison runs them.** Two knobs (environment; `run_all.sh`, `run_zka.sh` and
`six_common.sh` read them, `jobs.py` takes them as `--roots` / `--cm-ref`):

- `SIX_ZKA_ROOTS` (default `noroot`; any comma list of `designed`, `noroot`, `legacy`):
  the variants executed and proved for all six families.
- `SIX_ZKA_CM_REF` (default `1`): also prove their shipped CM aggregation
  (`cm:aggr:<e>:designed`) at the proved epochs, as the reference. It is skipped when
  `SIX_ZKA_ROOTS` already has `designed` or `legacy` (both are their unchanged `aggr_cm`).
  `0` turns it off.

What the scripts do with them:

- `six/run_zka.sh exec` executes every aggregation epoch once per variant of
  `SIX_ZKA_ROOTS`, plus `designed` for all six families when the CM reference is on
  (executor only, about a minute at this configuration: it gives the reference's cycle
  counts, from which `quick` computes the reference's prove time, and the root-work table). Bloom and KMV run their
  `--mode exec` pipeline once per variant; the query rows are kept once, after a check
  that they are identical under every variant (all columns but `exec_s`). Then, per family
  and epoch, it checks that all variants give one `state_commit`, with `journal_eq_native`
  and `variants_agree` true; otherwise it exits 1.
- `jobs.py --roots R --cm-ref C` plans every proved aggregation epoch once per variant of
  R, as `<fam>:aggr:<epoch>:<variant>`, then the 28 queries (planned once), then, with
  C = 1, the CM reference `cm:aggr:<e>:designed` (last, so a run stopped early still has
  the headline). A job without the suffix means `legacy`, the drivers' default and the
  form of the committed run's jobs. `full` thus proves 2 epochs x 6 families = 12
  `noroot` aggregation jobs + 28 query jobs + 2 reference jobs = **42** at the defaults;
  40 with `SIX_ZKA_CM_REF=0`; 52 with `SIX_ZKA_ROOTS=designed,noroot` (the earlier default:
  24 aggregation jobs, the CM `designed` ones being the reference); 40 with
  `SIX_ZKA_ROOTS=legacy` (the committed run's plan). `run_zka.sh prove` passes the variant
  to the driver as `--root`, and it also accepts the sensitivity variants
  (`ss:aggr:<e>:buckets1024`, `ss:aggr:<e>:perkey`, `gk:aggr:<e>:pertuple`) by hand.
  `six_zka_jobs.csv` stores an aggregation job's variant in its `arg` column (`-` =
  legacy).
- `assemble.py` writes one zk-Analytics update row per family x variant x operation. Two
  columns are appended, `variant` and `root_construction`; query rows and zkSketch rows say
  `-`; the CM `designed` rows say in `note` that they are the reference. It also checks that
  each proved row is the variant its job asked for, and that every executor and proved row
  of an epoch has the same `state_commit`.
- `table.py` puts `zkA` (= `noroot`, the headline) and zkSketch side by side, with the
  ratio zkA / zkS. The first table, "Update proofs side by side", has for each sketch
  proving time (one epoch and the whole stream), verification time, proof size and peak
  memory. Right after it, a separate table "Reference, not the headline: zk-Analytics'
  shipped Count-Min aggregation" gives the same metrics for their shipped CM (`zkA
  shipped CM (reference)`), next to the headline and zkSketch, with its ratio to zkS and
  the root work it carries (designed - noroot user cycles at epoch 0). With several
  variants in the run (e.g. `SIX_ZKA_ROOTS=designed,noroot`) every update-side and accept
  table shows one zkA column per variant (`zkA designed`, `zkA noroot`), with a ratio
  against each, and the reference table is printed as well. The last table lists each
  executed variant's root construction, its executor cycles at epoch 0, and the root work
  (designed - noroot). Query tables have one zkA column and say that it holds for every
  variant.

### Running

One entry point, from the repository root (prerequisites, times and outputs: the
top-level README, "Experiment 1", and the full guide `docs/six_sketch_comparison.md`):

```bash
scripts/baselines/zka/six/run_all.sh check   # prerequisites; exit 1 + the fix if anything blocking is missing
scripts/baselines/zka/six/run_all.sh build   # fetch zk-Analytics @ d4a5a9a into $BASELINE_DIR; build both sides
scripts/baselines/zka/six/run_all.sh quick   # smoke test of the whole pipeline (N = 512 = 2 x 256), ~5-11 min
scripts/baselines/zka/six/run_all.sh full    # this configuration (N = 16,384 = 8 x 2,048), ~3 h 30 min (proofs at ~30 s per segment) + gate waits
scripts/baselines/zka/six/run_all.sh full --dry-run   # the plan and the 42 jobs, nothing run
SIX_ZKA_ROOTS=designed,noroot scripts/baselines/zka/six/run_all.sh full   # the earlier two-variant plan, 52 jobs
SIX_ZKA_GK=textbook scripts/baselines/zka/six/run_all.sh full   # textbook GK on the zk-Analytics side (the reference)
```

GK on the zk-Analytics side (`six_common.sh`): `SIX_ZKA_GK=matched` (default) runs
`gk_matched/` with zkSketch's capacity `SIX_GK_CAP`, s = 51 and leaf size `SIX_GK_MSUB`
(default `SIX_M`: one `apply_batch2` step per epoch, as zkSketch's `SIX_M`-record leaves),
implementation `SIX_ZKA_GK_IMPL` (`literal`, the default since 2026-10-15: zkSketch's GK
algorithm as its original code, `apply_batch2` statement for statement; `tuned`, `fast`,
`fixed_linear` are our rewrites of it, which compact survivors instead of re-sorting (the
idea of zkSketch's planned stable-compaction circuit), so they are sensitivity rows only); `SIX_ZKA_GK=textbook` runs `gk/`. To match a zkSketch GK run with smaller
leaves than the zk-Analytics epoch (a memory-matched forest: zkSketch held to the 8 GiB
cap; zk-Analytics' own proof of the epoch peaks at about 9.2 GiB, see "zk-Analytics' own
memory" under the matched GK results), run the two sides separately with the same
capacity, e.g. zkSketch `SIX_M=128 SIX_T=16 SIX_GK_CAP=384 run_zks.sh gk` and zk-Analytics
`SIX_M=2048 SIX_T=1 SIX_GK_CAP=384 SIX_GK_MSUB=128 run_zka.sh exec`
(`run_zks.sh` always uses `SIX_M` as its leaf size, and `assemble.py` wants one `(M, T)`).
`assemble.py` names the matched rows' system `zk-Analytics arch. (port †, zkSketch GK
rule)`, puts the configuration in their `note` and warns when it differs from the zkSketch
GK CSV's capacity, s or leaf size; `table.py` labels the GK row "same rule both sides"
(textbook: "zkA: textbook GK").

Every `quick` / `full` writes a fresh `results/six/<mode>-<YYYYmmdd-HHMMSS>/` at the
repository root (git-ignored; `RESULTS=...` to choose; never this directory):
`manifest.txt` (configuration, versions), `run_all.log`, `six_sketch_table.md` (the
tables of Results below and more, in a newer layout: zkA (noroot) / zkS side by side, a
separate reference table for their shipped CM, zkA / zkS in one cell for queries, `est`
on zk-Analytics times computed from cycle counts), `six_sketch_comparison.csv`, and the raw files of the table below. `quick`
executes `noroot` and `designed` (the latter for the CM reference and the root-work
table) and proves four zk-Analytics jobs for real, all `noroot` or queries
(`cm:aggr:0:noroot`, `kmv:aggr:0:noroot`, `gk:query:1:<v>`, `bloom:query:1:key:<k>`;
`SIX_QUICK_PROVE` to change, as `jobs.py --select` selectors, default
`cm:aggr:0:noroot,kmv:aggr:0:noroot,gk:query:1,bloom:query:1:key`). Of its 28 planned
jobs (12 `noroot` aggregation, 14 queries, 2 CM reference) it does not prove 24; for those
it reports padded cycles x the seconds per 2^20 padded cycles measured over this run's
proofs, each variant from its own executor cycle counts (the CM reference at 256 records is
14 segments, about 7 min if proved; it is not proved). Those cells say `cyc`;
`provenance` says `FROM CYCLES`. Across the 40 proofs of the measured run, padded cycles x
k = 30.06 s per 2^20 gave between 5% below and 9% above the measured time for proofs
of >= 2^19 padded cycles (2^20 and up: -5.0% .. +9.3%, 28 proofs; 2^19: -4.3% .. -2.3%, 7 proofs)
and 19-37% below the measured time for proofs of <= 2^18 cycles (fixed overhead; 5 proofs).

What `build` and `full` run, step by step (the first two commands are `build`), from the repository root (the relative paths below
assume it; each script also runs on its own; defaults = this configuration; `RESULTS`
must be the same fresh directory for all steps):

```bash
export RESULTS=$PWD/results/six/manual-1   # fresh, git-ignored; the six/ scripts refuse a directory with tracked files
scripts/baselines/fetch_baselines.sh zka    # zk-Analytics only (no argument: also zkStream + ZoKrates)
scripts/baselines/zka/six/build.sh          # both sides, not timed; exits 1 if any build fails
scripts/baselines/zka/six/run_zks.sh        # zkSketch, 7 timed runs: cm hll ss gk bloom bloom_absent kmv
scripts/baselines/zka/six/run_zka.sh exec   # zk-Analytics executor: all 8 aggregation epochs of every family,
                                            # noroot (SIX_ZKA_ROOTS, default noroot) + designed (SIX_ZKA_CM_REF=1)
scripts/baselines/zka/six/prof_exec.sh      # executor only: SS (and textbook-GK) guest phase profile (legacy profiling
                                            # twins); the matched GK carries its profile in its exec rows
# the 42 zk-Analytics jobs (--roots noroot --cm-ref 1 are the defaults); the GK rank values and Bloom
# absent keys are read from this run's zkSketch logs (QLOG_KEY lines) and cross-checked
# against a native re-derivation:
JOBS=$(python3 -I scripts/baselines/zka/six/jobs.py --keys data/aol.keys --logs "$RESULTS" --roots noroot --cm-ref 1)
scripts/baselines/zka/six/run_zka.sh prove $JOBS   # timed, one at a time
python3 -I scripts/baselines/zka/six/assemble.py "$RESULTS" data/aol.keys --zka six_zka --zks six_zksketch \
  --out "$RESULTS/six_sketch_comparison.csv"
python3 -I scripts/baselines/zka/six/table.py "$RESULTS/six_sketch_comparison.csv" > "$RESULTS/six_sketch_table.md"
```

For this configuration `jobs.py` prints these 42 jobs:

```
cm:aggr:0:noroot cm:aggr:7:noroot hll:aggr:0:noroot hll:aggr:7:noroot
ss:aggr:0:noroot ss:aggr:7:noroot gk:aggr:0:noroot gk:aggr:7:noroot
bloom:aggr:0:noroot bloom:aggr:7:noroot kmv:aggr:0:noroot kmv:aggr:7:noroot
cm:query:1 cm:query:2 cm:query:4 cm:query:8 hll:query:1 hll:query:2 hll:query:4 hll:query:8
gk:query:1:1810625 gk:query:2:1810625 gk:query:4:1810625 gk:query:8:985491
bloom:query:1:first bloom:query:2:first bloom:query:4:first bloom:query:8:first
bloom:query:1:key:4010659695 bloom:query:2:key:3455829011 bloom:query:4:key:2391383811 bloom:query:8:key:1608305708
kmv:query:1 kmv:query:2 kmv:query:4 kmv:query:8 ss:query:1 ss:query:2 ss:query:4 ss:query:8
cm:aggr:0:designed cm:aggr:7:designed
```

The last two are the CM reference (their shipped `aggr_cm`). With `--cm-ref 0` it prints
the first 40. With `--roots designed,noroot` it prints the 52 jobs of the earlier default:
each aggregation epoch once `designed` and once `noroot` (`cm:aggr:0:designed
cm:aggr:0:noroot cm:aggr:7:designed cm:aggr:7:noroot hll:aggr:0:designed ...`), then the
same 28 queries, and no separate reference (the CM `designed` jobs are it). With `--roots
legacy` it prints the 40 jobs of the measured run (12 aggregation jobs
`<fam>:aggr:<0|7>:legacy`, the run wrote them without the suffix, which means the same, and
the same 28 queries).

Proving time, computed from the executor's segment counts at ~30 s per segment of 2^20
cycles (30.07 s per 2^20 padded cycles over the 12 aggregation proofs of the measured run),
not measured: the 12 `noroot` aggregation proofs are 150 segments (147 x 2^20 padded
cycles), about 74 min; the 2 CM reference proofs are 48 segments, about 24 min (the same
ELF took 712 and 713 s in the measured run); the 28 queries took 58 min in the measured
run. The GK figure in the 150 segments is the textbook GK's; the matched GK with its
default `literal` implementation (zkSketch's `apply_batch2` as written) needs about 29.25 +
30.0 x 2^20 padded cycles for its two aggregation proofs at (2048, 2048), about 33 more
segments, ~17 min more. So the default 42 proofs take about 2 h 50 min, 40 with
`SIX_ZKA_CM_REF=0` about 2 h 25 min, and the 52 of `SIX_ZKA_ROOTS=designed,noroot` about
3 h 55 min (its 12
`designed` aggregation proofs are 176 segments, ~88 min; the 12 legacy proofs of the
measured run were also 176 segments, 174 x 2^20 padded cycles; CM is the same ELF), against the measured 2 h 25 min
for the 40 legacy proofs. With zkSketch's 7 runs (~30-40 min on the zero-knowledge build)
and the executor, `full` runs about 3 h 30 min at the defaults (3 h 5 min without the
reference, 4 h 30 min with `designed,noroot`), plus the gate waits.

Knobs (environment): `BASELINE_DIR`, `RESULTS`, `SIX_CORES` (zkSketch cores;
default: physical cores, at most 32); `SIX_ZKA_ROOTS` (zk-Analytics aggregation variants
executed and proved, default `noroot`; `run_all.sh` and `run_zka.sh exec` read it,
`jobs.py` takes `--roots`); `SIX_ZKA_CM_REF` (default `1`: their shipped CM proved as the
reference and `designed` executed for all six; `0` off; `jobs.py` takes `--cm-ref`);
`SIX_QUICK_PROVE` (the jobs `quick` proves, above); `GATE_WAIT_S` (default 1800; `quick` 0),
`GATE_MAX_LOAD` (default CPUs / 8; 2 below 16 CPUs), `GATE_MAX_BUSY` (default 4);
`EXP_VERIFY_REPEATS` (default 5); `SIX_GK_ROUNDS` (`stable` | `sorted`, default `stable`:
the zkSketch GK leaf's round certification, passed to `exp_compose` as `EXP_GK_ROUNDS`; both
prove the same `apply_batch2` rule, commitments and decoder with different leaf/merge/root VKs,
the run's CSV records it in `variant` and `gk_rounds`, and `run_all.sh` keeps it for `quick` /
`full` and writes it to the manifest; `sorted` reproduces the pre-M3 rows); `SIX_BLOOM_VARIANT`
(`packed` | `omc`, default `packed` since M2: the zkSketch Bloom leaf, passed to `exp_compose` as
`EXP_BLOOM_VARIANT`; `packed` is the M2 packed-byte leaf, `src/sketch/bloom_packed.rs`, which
proves the same filter and answers with different leaf/decode/merge/root VKs and commitment family
7, and needs `7 x SIX_M < 2^16`; the run's CSV records it in `variant`, `bloom_omc` |
`bloom_packed`, and `run_all.sh` writes it to the manifest). The run shape `SIX_M`, `SIX_T` (records per epoch,
epochs; `N = M x T`), `SIX_GK_CAP` and `SIX_QNS` (query points) applies only to the
individual `six/*.sh` scripts (`jobs.py` takes `--m`, `--t`, `--qns`): `run_all.sh
quick` / `full` use their fixed shapes and say so when these are set. The run
scripts ignore inherited `EXP_*` / `ZKSKETCH_*` / `RAYON_NUM_THREADS` settings and
RISC Zero's `BONSAI_API_*`, `RISC0_PROVER` and `RISC0_DEV_MODE`, and exit non-zero when a run fails (a non-zero exit code, a missing
CSV, a zkSketch CSV `status` other than `ok`, or a proof that wrote no row). Ctrl-C
stops the running job: each one runs in its own process group, which is stopped as a
whole; no process is killed by name. `run_all.sh quick` / `full` refuse binaries
older than their sources, i.e. sources changed since the last `run_all.sh build`, which
refreshes them (`SIX_ALLOW_STALE=1` overrides; a `BASELINE_DIR` built from an older
checkout, for instance, lacks the GK driver's query `--prove` path), and the
`six/` scripts refuse a `RESULTS` directory holding git-tracked files
(`SIX_ALLOW_TRACKED=1` overrides).

To re-tabulate the committed reference run (this directory), write elsewhere:
`assemble.py` refuses to overwrite the tracked `six_sketch_comparison.csv`, which the
`6cac471` version of `assemble.py` produced (148 rows, 12 columns; `table.py` at
`6cac471` prints the Results tables below from it). The current scripts give a
318-row, 20-column CSV from the same inputs, with the same-day repeat run r2
(`six_zksketch_r2_*`) as the primary zkSketch run instead of r1 (`six_zksketch_*`),
so their zkSketch numbers differ from the Results tables by a few percent. The
zk-Analytics rows are labelled with the root variant `legacy` in the two columns added
for the root variants (`variant`, `root_construction`: CM `cm_rows+cm+heap`, SS
`samples64`, GK `pertuple`, HLL / Bloom / KMV `none`; query and zkSketch rows `-`).
Without those two columns the CSV is byte-identical to the one of the scripts before
the root variants. `table.py` prints the earlier tables unchanged, adding a legacy note
at the top, the "Update proofs side by side" table and the root-variant table at the end:

```bash
python3 -I scripts/baselines/zka/six/assemble.py scripts/baselines/zka/results data/aol.keys --out /tmp/six.csv
python3 -I scripts/baselines/zka/six/table.py /tmp/six.csv --raw scripts/baselines/zka/results
```

- The measured run (2026-10-09, 14:47-18:43) predates `run_all.sh`: it ran
  `build.sh`, `run_zka.sh exec`, `run_zks.sh` and `run_zka.sh prove` with the 40
  jobs of `jobs.py --roots legacy` (written without the `:legacy` suffix), in that
  order, with `RESULTS` = this directory and `BASELINE_DIR` set to a private scratch
  directory whose `zka/` is a symlink to `~/ext-baselines/zka`;
  `run_zks.sh` was invoked twice (`cm`, then the other six tags). The scripts ran
  from that scratch directory with the same logic; only their path variables differ
  from the tracked copies of that day. Absolute paths in the committed `six_*` logs
  were rewritten to `$BASELINE_DIR` and `$ZKS` (the later `quick_*` / `zk2_*` /
  `tiny_*` logs keep theirs).
- Wall time: zkSketch, 7 runs, 586 s of running plus 423 s of gate waits;
  zk-Analytics, 40 proofs, 8,703 s (2 h 25 min) of running plus 4,219 s (1 h 10 min)
  of gate waits; the executor phase took about a minute.
- `assemble.py` checks, for every zkSketch run, that the per-query log lines add up
  to the CSV's summed `query_*` columns, and that every zk-Analytics proved row
  matches its job line; exact answers are recomputed from the same 16,384 records.

| file | rows | what |
|---|---|---|
| `six_sketch_comparison.csv` | 148 | the comparison: one row per (family, system, operation), `provenance` = `measured` / `sampled` (mean of the proved epochs) / `derived` (computed from those rows, e.g. 8 x the per-epoch mean), `detail` gives the computation (written by `assemble.py` as of `6cac471`; see above) |
| `six_zka_{cm,hll,ss,gk,bloom,kmv}_exec.csv` + `six_zka_exec.log` | 8 / 8 / 8 / 8 / 16 / 12 | executor, all 8 aggregation epochs (Bloom, KMV: their `--mode exec` pipeline, query executes included) |
| `six_zka_{family}_prove.csv` / `.log` | 6 per family (Bloom 10) | proved rows: aggregation epochs 0 and 7, queries at n = 1, 2, 4, 8 (Bloom: inserted and absent key) |
| `six_zka_jobs.csv` | 40 | one line per proof: gate result, load at start / end, busy cores at start, wall time, r0vm peak RSS (`arg` `-` on the aggregation jobs: the legacy variant) |
| `six_zksketch_{cm,hll,ss,gk,bloom,bloom_absent,kmv}.csv` / `.log` | 1 each | exp_compose's CSV row and the run's console log (per-query `QLOG_*` lines, `RSSTREE`) |
| `six_zksketch_runs.csv` | 7 | one line per zkSketch run: gate, load at start / end, wall, coordinator / worker peak RSS, commitment mode |

All 40 proofs and all 60 executor rows passed their checks (journal equals
native output on every row; the ports' reference and accuracy checks; GK
`q_ok`; Bloom `answer_ok`). Every proof started on a quiet box (1-minute load
5.2-7.9, at most 3.6 busy cores); the SS, GK, Bloom and KMV drivers' own samplers
saw no foreign r0vm during any proof. During most Bloom and KMV proofs 2.3-2.8
other cores were busy on average (`other_cores_avg`; another user's light job),
below those drivers' contention threshold of 4.

### Results

These tables are run r1 (`six_zksketch_*` with the zk-Analytics rows), as `table.py`
at `6cac471` prints them from the committed `six_sketch_comparison.csv`; they are not
zero-knowledge on the zkSketch side (see the note at the top of this section).
Re-tabulating with the current scripts (above) makes r2 primary, which moves the
zkSketch numbers by a few percent (e.g. CM leaf 2.22 s instead of 2.26 s, GK 14.7 s
instead of 14.59 s).

**The zk-Analytics numbers here are the `legacy` root variant** ("Root variants" above):
CM with their shipped per-counter Merkle roots, SS with the samples-pattern root (64
buckets), GK with a per-tuple root, HLL / Bloom / KMV with no root. They are neither
`designed` (every family with a root) nor `noroot` (no family with a root, the
headline of a `six/run_all.sh` run, which shows their shipped CM as a reference). The largest
difference is CM: its `noroot` aggregation guest needs 12 segments per epoch instead of
24 (executor), so roughly half the per-epoch prove time below; for the five ports the
root costs 0-1 segment of 11-15.

† marks the families whose zk-Analytics side is our port. zkA = zk-Analytics side,
zkS = zkSketch. Ratios are zkA / zkS.

**Update side** (one epoch = one batch of 2,048 records)

| sketch | zk-Analytics prove / epoch (s) | zkSketch prove / leaf (s) | ratio | zk-Analytics 8 epochs (s) | zkSketch 8 batches incl. merges (s) | ratio | zk-Analytics receipt / epoch | zkSketch root proof | peak RSS zk-Analytics (r0vm) | peak RSS zkSketch (worker) |
|---|---|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 712.3 (e0 711.6, e7 713.0) | 2.26 | 315x | 5,699 | 30.0 | 190x | 226 KB x 8 kept | 528 KB (one root) | 9.2 GB | 2.9 GB |
| HLL b=14 † | 322.9 (e0 322.5, e7 323.4) | 1.89 | 170x | 2,584 | 25.7 | 100x | 225 KB x 8 kept | 528 KB (one root) | 9.2 GB | 2.7 GB |
| SS / MG s=1,024 † | 449.3 (e0 444.8, e7 453.7) | 1.02 | 440x | 3,594 | 18.0 | 199x | 225 KB x 8 kept | 529 KB (one root) | 9.2 GB | 1.9 GB |
| GK eps=1/51 † | 420.0 (e0 415.4, e7 424.6) | 14.59 | 29x | 3,360 | 142.2 | 24x | 225 KB x 8 kept | 528 KB (one root) | 9.2 GB | 19.4 GB |
| Bloom 7x2^14 † | 355.2 (e0 354.2, e7 356.1) | 3.97 | 90x | 2,841 | 44.9 | 63x | 225 KB x 8 kept | 529 KB (one root) | 9.2 GB | 5.3 GB |
| KMV k=1,024 † | 356.7 (e0 355.3, e7 358.1) | 0.73 | 486x | 2,854 | 16.2 | 176x | 225 KB x 8 kept | 529 KB (one root) | 9.2 GB | 1.5 GB |

**Query proving time** (s; the query proof alone)

| sketch | n=1 zkA | n=1 zkS | n=2 zkA | n=2 zkS | n=4 zkA | n=4 zkS | n=8 zkA | n=8 zkS | ratio at n=8 |
|---|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 27.88 | 0.074 | 59.02 | 0.073 | 106.79 | 0.074 | 210.00 | 0.077 | 2,724x |
| HLL b=14 † | 15.39 | 2.02 | 27.76 | 1.70 | 39.57 | 1.83 | 70.77 | 1.89 | 37x |
| SS / MG s=1,024 † | 163.24 | 0.118 | 334.91 | 0.130 | 688.36 | 0.154 | 1,412.78 | 0.116 | 12,159x |
| GK eps=1/51 † | 5.93 | 0.381 | 9.27 | 0.373 | 15.63 | 0.333 | 27.75 | 0.307 | 90x |
| Bloom 7x2^14 † (inserted key) | 9.36 | 2.11 | 15.40 | 1.73 | 15.65 | 1.76 | 28.14 | 1.82 | 15x |
| Bloom 7x2^14 † (absent key) | 9.28 | 1.89 | 15.66 | 1.67 | 15.71 | 1.64 | 27.50 | 1.68 | 16x |
| KMV k=1,024 † | 9.33 | 0.118 | 15.53 | 0.111 | 27.70 | 0.105 | 46.93 | 0.093 | 502x |

**Verifier work to accept one answer at n** (ms; zk-Analytics: n aggregation receipts + 1 query receipt; zkSketch: the live forest peak(s) + 1 query proof)

| sketch | n=1 zkA | n=1 zkS | n=2 zkA | n=2 zkS | n=4 zkA | n=4 zkS | n=8 zkA | n=8 zkS | ratio at n=8 |
|---|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 21.2 | 34.2 | 32.8 | 31.6 | 55.8 | 27.5 | 101.7 | 30.7 | 3.3x |
| HLL b=14 † | 21.1 | 31.6 | 32.9 | 29.4 | 55.6 | 33.9 | 101.6 | 28.5 | 3.6x |
| SS / MG s=1,024 † | 21.3 | 32.1 | 32.9 | 29.7 | 57.9 | 28.7 | 104.1 | 26.4 | 3.9x |
| GK eps=1/51 † | 22.1 | 35.4 | 33.0 | 30.9 | 52.4 | 27.3 | 94.9 | 27.2 | 3.5x |
| Bloom 7x2^14 † (inserted key) | 19.4 | 33.8 | 29.2 | 32.1 | 48.6 | 33.7 | 87.6 | 32.4 | 2.7x |
| Bloom 7x2^14 † (absent key) | 19.4 | 34.0 | 29.2 | 30.0 | 50.5 | 31.0 | 89.4 | 33.6 | 2.7x |
| KMV k=1,024 † | 19.5 | 28.0 | 29.2 | 26.5 | 48.7 | 29.2 | 87.9 | 25.6 | 3.4x |

**Bytes the verifier receives for one answer at n** (zk-Analytics: n + 1 receipts; zkSketch: peak proof(s) + query proof)

| sketch | n=1 zkA | n=1 zkS | n=2 zkA | n=2 zkS | n=4 zkA | n=4 zkS | n=8 zkA | n=8 zkS | ratio at n=8 |
|---|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 450 KB | 1,085 KB | 676 KB | 993 KB | 1,128 KB | 955 KB | 2,033 KB | 955 KB | 2.1x |
| HLL b=14 † | 449 KB | 1,222 KB | 673 KB | 1,160 KB | 1,123 KB | 1,123 KB | 2,022 KB | 1,122 KB | 1.8x |
| SS / MG s=1,024 † | 449 KB | 1,110 KB | 674 KB | 1,034 KB | 1,124 KB | 996 KB | 2,025 KB | 995 KB | 2.0x |
| GK eps=1/51 † | 449 KB | 1,281 KB | 674 KB | 1,090 KB | 1,124 KB | 1,052 KB | 2,024 KB | 1,052 KB | 1.9x |
| Bloom 7x2^14 † (inserted key) | 449 KB | 1,229 KB | 674 KB | 1,158 KB | 1,123 KB | 1,120 KB | 2,022 KB | 1,121 KB | 1.8x |
| Bloom 7x2^14 † (absent key) | 449 KB | 1,228 KB | 674 KB | 1,158 KB | 1,123 KB | 1,120 KB | 2,022 KB | 1,120 KB | 1.8x |
| KMV k=1,024 † | 449 KB | 987 KB | 673 KB | 955 KB | 1,123 KB | 955 KB | 2,022 KB | 955 KB | 2.1x |

**Peak RSS while proving one query** (zk-Analytics: r0vm of that proof; zkSketch: the coordinator over the whole run, see caveats)

| sketch | n=1 zkA | n=2 zkA | n=4 zkA | n=8 zkA | zkSketch coordinator |
|---|---|---|---|---|---|
| Count-Min 3x1024 | 9.1 GB | 9.2 GB | 9.2 GB | 9.2 GB | 2.5 GB |
| HLL b=14 † | 4.6 GB | 9.1 GB | 9.1 GB | 9.2 GB | 3.1 GB |
| SS / MG s=1,024 † | 9.2 GB | 9.2 GB | 9.2 GB | 9.2 GB | 1.7 GB |
| GK eps=1/51 † | 1.4 GB | 2.3 GB | 4.6 GB | 9.1 GB | 19.0 GB |
| Bloom 7x2^14 † | 2.3 GB | 4.6 GB | 4.6 GB | 9.1 GB | 5.0 GB |
| KMV k=1,024 † | 2.3 GB | 4.6 GB | 9.1 GB | 9.1 GB | 1.4 GB |

**Answers vs exact** (same 16,384 AOL records; exact computed natively)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | 115 | 115 | 115 |
| Count-Min 3x1024 | 2 | 116 | 115 | 115 |
| Count-Min 3x1024 | 4 | 119 | 118 | 115 |
| Count-Min 3x1024 | 8 | 189 | 185 | 180 |
| HLL b=14 † | 1 | 1232 | 12422.5 | 1234 |
| HLL b=14 † | 2 | 2397 | 13011.8 | 2372 |
| HLL b=14 † | 4 | 4461 | 14078.0 | 4432 |
| HLL b=14 † | 8 | 8472 | 16373.6 | 8433 |
| SS / MG s=1,024 † | 1 | key 3011223745 count 115 (error 0) | count 114 (no key) | key 3011223745 count 115 |
| SS / MG s=1,024 † | 2 | key 3011223745 count 115 (error 0) | count 113 (no key) | key 3011223745 count 115 |
| SS / MG s=1,024 † | 4 | key 3011223745 count 115 (error 0) | count 111 (no key) | key 3011223745 count 115 |
| SS / MG s=1,024 † | 8 | key 3780053395 count 180 (error 0) | count 172 (no key) | key 3780053395 count 180 |
| GK eps=1/51 † | 1 | 1789 [1750..1829] | 1786 | 1789 |
| GK eps=1/51 † | 2 | 3595 [3518..3672] | 3557 | 3569 |
| GK eps=1/51 † | 4 | 7150 [7014..7287] | 7095 | 7115 |
| GK eps=1/51 † | 8 | 7985 [7718..8253] | 7927 | 7967 |
| Bloom 7x2^14 † (inserted key) | 1 | true | true | true |
| Bloom 7x2^14 † (inserted key) | 2 | true | true | true |
| Bloom 7x2^14 † (inserted key) | 4 | true | true | true |
| Bloom 7x2^14 † (inserted key) | 8 | true | true | true |
| Bloom 7x2^14 † (absent key) | 1 | false | false | false |
| Bloom 7x2^14 † (absent key) | 2 | false | false | false |
| Bloom 7x2^14 † (absent key) | 4 | false | false | false |
| Bloom 7x2^14 † (absent key) | 8 | false | false | false |
| KMV k=1,024 † | 1 | 1232 | 1241 | 1234 |
| KMV k=1,024 † | 2 | 2290 | 2320 | 2372 |
| KMV k=1,024 † | 4 | 4405 | 4365 | 4432 |
| KMV k=1,024 † | 8 | 8202 | 8484 | 8433 |

### Who wins where

(The committed `legacy` numbers above; see "Root variants" for `designed` / `noroot`.)

- **Update proving: zkSketch, on every family.** Per epoch of 2,048 records,
  zkSketch's leaf is 29x (GK) to 486x (KMV) faster than the zk-Analytics
  aggregation guest: CM 315x, HLL 170x, SS 440x, Bloom 90x. Counting zkSketch's 7
  forest merges, the whole 8-batch stream is 24x (GK) to 199x (SS) faster (CM 190x).
  r0vm was not core-restricted (the 1-minute load reached 58-64 during the GK,
  Bloom and KMV aggregation proofs, where the drivers sample it); zkSketch was
  given 32 cores.
- **Query proving: zkSketch, on every family, and the gap grows with n.** Their
  query guest re-hashes and merges all n epoch states, so its cost grows with n,
  while zkSketch's decode proof reads one state. At n = 1 zkSketch is 4.4x (Bloom)
  to 1,387x (SS) faster, at n = 8 15x (Bloom) to 12,159x (SS): CM 2,724x, HLL 37x,
  GK 90x, KMV 502x.
- **Verifier work: zk-Analytics at n = 1, zkSketch from n = 4.** At n = 1 the
  zk-Analytics verifier checks two ~10 ms receipts (19-22 ms) and zkSketch a leaf
  proof plus a query proof (28-35 ms). At n = 2 they are within 12% of each other,
  either way. At n = 8 zk-Analytics checks 9 receipts (88-104 ms) and zkSketch one
  forest peak plus the query proof (26-34 ms): 2.7-3.9x less.
- **Bytes to the verifier: same crossover.** zk-Analytics sends 449 KB at n = 1
  against zkSketch's 1.0-1.3 MB; at n = 4 they are equal (1.12 MB vs 0.96-1.12 MB);
  at n = 8 zkSketch is 1.8-2.1x smaller (0.96-1.12 MB vs 2.02-2.03 MB).
- **Memory: zkSketch, except GK** (GB = 2^30 bytes here and in the tables). Every
  multi-segment r0vm proof peaks at 9.1-9.2 GB. zkSketch's update worker peaks at
  1.5-5.3 GB, but at 19.4 GB for GK; its coordinator (query side) at 1.4-5.0 GB,
  but at 19.0 GB for GK.
- **Accuracy: mixed, decided by the sketches' semantics, not by the proof
  systems.** CM: both over-estimate the heavy key by at most 5% (n = 8: zkA 189,
  zkS 185, exact 180). HLL: **the port wins clearly** (within 1.1%), because
  zkSketch's HLL decoder releases the raw estimator without small-range correction
  (1.9-10x too high here; see caveats). SS: the port returns the exact top-1 key and
  count (error 0); zkSketch's MG returns the count only, 0.9-4.4% low. GK: both
  well inside eps N (zkS 3-40 below the exact rank, zkA 0-35 above, eps N = 40-321).
  Bloom: both correct on all 8 probes. KMV: both within 3.5% (one standard error is
  3.1%).

### Caveats

- **Zero knowledge (read this first).** RISC Zero succinct receipts are
  zero-knowledge; zkSketch's proofs in the committed 2026-10-09 rows of this section
  are not (`TwoAdicFriPcs`; the `zk` feature that swaps in `HidingFriPcs` was off; the
  later `zk` rows are pre-masking, see the note at the top of this section). A new
  `six/run_all.sh` run uses the zero-knowledge default build. Turning it on costs zkSketch prove time that
  these rows do not contain. In the other direction, zkSketch's state commitments
  are hiding (salted) and zk-Analytics' are unsalted SHA-256, which does not hide
  the epoch state.
- **CPU only, one machine.** Both sides ran on this Threadripper PRO 9975WX
  (32 cores / 64 threads), not on the paper's EPYC machines; the GPU prover was not
  used. r0vm was not core-restricted (it may use all 64 hardware threads);
  zkSketch was given 32 cores (`EXP_COMPOSE_CORES=32`, the matched-comparison
  setting of `compare.sh`), its query proofs a 32-thread pool on the coordinator.
- **Sampled epochs (zk-Analytics).** Only aggregation epochs 0 and 7 were proved per
  family; "per epoch" is their mean and "8 epochs" is 8 x that mean. The
  executor shows how much the other six epochs can differ, in segments per epoch
  (user cycles): CM 24 in every epoch (22.540M-22.547M), HLL 11 (10.395M-10.402M),
  SS 15 (13.995M-14.166M), GK 14-15 (13.144M-13.617M), Bloom 12
  (11.092M-11.099M), KMV 12 (11.042M-11.129M). The two proved epochs of each
  family differ by at most 2.2% in prove time (GK; CM 0.2%).
- **What each zkSketch number is.** Per-leaf prove = `leafgen_seq_ms / t` (the sum of
  the 8 measured leaf proofs over 8). "8 batches incl. merges" = `total_time_ms`
  (leaves plus the 7 forest merges, 1 machine). Query prove / verify / bytes and
  `query_bind_ms` come per query from the `EXP_QUERY_LOG` lines (their sums match
  the CSV's `query_*` columns). zkSketch's query RSS is the coordinator's whole-run
  peak (it also derives the auditor's VKs and binds every query), an upper bound for
  a single query; update RSS is the worker's peak. zk-Analytics RSS is the peak of
  the r0vm process of that one proof (`six/rss_tree.sh`).
- **What "accept at n" counts.** zk-Analytics: the n aggregation receipts (their tree
  has no `env::verify`, so the verifier checks each; verify time and size = the
  mean of the two proved epochs) plus the query receipt (measured).
  zkSketch: the pinned verification of the live Bentley-Saxe peak(s) at version n
  (one peak for n = 1, 2, 4, 8) plus the statement checks against the batch log
  (`query_bind_ms`, measured), plus the query proof's verification (measured). At
  n = 3, 5, 6, 7 zkSketch needs 2-3 peaks (in the logs, not in the table).
- **Proof sizes** are bincode-serialized receipts (zk-Analytics) and
  postcard-serialized proofs (zkSketch).
- **Per-family semantics differ; compare accuracy with that in mind.**
  - *Count-Min.* Same 3 x 1024 geometry, different hashes (theirs FNV-1a +
    seeded splitmix64; ours Poseidon2 in-circuit), so collisions differ. Theirs keeps
    one CM per epoch and the query sums the n epoch tables; ours keeps one cumulative
    table.
  - *HLL.* **zkSketch's HLL decode certifies the raw estimator
    `alpha m^2 / Z` in fixed point (beta = 8) with no small-range (linear counting)
    branch.** At these cardinalities (1,234-8,433 distinct keys against
    m = 16,384 registers) the raw estimator is far off: 12,422 / 13,012 / 14,078 /
    16,374 against 1,234 / 2,372 / 4,432 / 8,433 exact at n = 1 / 2 / 4 / 8 (10.1x
    down to 1.9x). The port † applies linear counting (`linear_counting=true` in its journal); its own raw
    estimate on the same data is 12,416 / 12,999 / 14,088 / 16,376, within 0.2% of
    zkSketch's answers, so the gap is the missing branch, not the hash or the
    proof. This is a property of zkSketch's decoder, not of the comparison.
  - *MG.* Ours is mergeable Misra-Gries with 1,024 counters on keys
    mapped to `(k & 0x1FFFFFFF) | 1`, and the query releases the top-1 count only
    (an under-estimate, no key). Theirs, since 2026-10-26, is per-epoch textbook
    Misra-Gries with 1,024 counters (`mg/`), merged at query time by the mergeable
    Misra-Gries merge, and the query releases key and count (an under-estimate). In
    the committed rows it is per-epoch SpaceSaving with 1,024 counters merged by
    sum-and-truncate, releasing key, count and error (count is an over-estimate per
    epoch); MG with s counters is roughly SpaceSaving with s + 1.
  - *GK.* Same value domain on both sides (`key & 0x1FFFFF`, 21 bits) and the same
    rank value. Ours is the two-sided band-merge summary (s = 51, capacity 2,048)
    and releases the bracket midpoint; theirs, in these committed rows, is per-epoch
    textbook GK (eps = 1/51) combined at query time and releases an estimate with
    certified bounds: a different algorithm. Since 2026-10-15 a `six/run_all.sh` run
    puts zkSketch's own rule on their side instead (`gk_matched/`), and both sides
    then return the same answer (see "GK with zkSketch's algorithm in their pipeline").
  - *Bloom.* Same partitioned shape (7 x 2^14 bits); different hash functions and
    seeds (theirs FNV-1a + splitmix64 with their 3 CM seeds and 4 constants of ours;
    ours Poseidon2 routing), so false-positive sets differ. Both answered all 8 probes
    correctly.
  - *KMV.* k = 1,024 on both sides; hash width 27 bits (ours, Poseidon2) vs 64 bits
    (theirs), so estimates differ by the hash draw (std err ~ 1/sqrt(k-2) = 3.1%).
- **† ports are ours.** zk-Analytics ships only Count-Min. The HLL, SS, GK, Bloom and
  KMV rows on their side are our code in their per-epoch pipeline, not zk-Analytics
  code (see the sections above): textbook per-record algorithms, except GK in a run
  with `SIX_ZKA_GK=matched` (the default since 2026-10-15), which is zkSketch's GK rule. The GK driver's query
  `--prove` path was added for this comparison (`gk/host/src/main.rs`; the proved
  journal is asserted equal to the native output, as for aggregation).
- **Build provenance.** zk-Analytics-side binaries were built with the commands of
  `six/build.sh` into a private `BASELINE_DIR` whose `zka/` links to `~/ext-baselines/zka`
  (`d4a5a9a`), so no other job's build dir was touched; the ELF md5s are in the
  log headers (`aggr_cm` T=1 is `90fce45d…`, the validated build). zkSketch:
  this commit, default features, release.

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
and this guest executes it in a zkVM (executor only here; prove time =
segments x 30.1 s). It is not a comparison of two algorithms, but the two statements are
not identical either: hash, compute-vs-verify and in-guest key mapping differ
(see "Statement differences" under Caveats).

The SpaceSaving port above (`spacesaving/`, `zka_ss_exec.csv`) is a different
baseline and stays unchanged: textbook per-record SpaceSaving inside
zk-Analytics' full aggregation pipeline, merged at query time by
sum-and-truncate. Never mix the two in one table.
`ss_mg/README.md` has the full detail.

**Nothing here was proved.** Every prove time is segments x 30.1 s
(envelope x 29.73 to x 30.79), as in the sections above.

### What is zkSketch's, ours and upstream

| item | source |
|---|---|
| batch rule, tie-break, tau, dummy handling, state layout and order | zkSketch: `ss_final_full.rs` `build_ss`, `group_by_key`, `compress_from_gsorted`, `apply_batch_ss_full`; re-implemented, and every run is checked against the native function |
| key mapping (29-bit mask, low bit forced to 1, `u32::MAX` gives the dummy) | zkSketch `ss_updates_of` (`src/experiments/stream_compose.rs`) |
| epoch slicing, Uniform stream | zkSketch `examples/exp_compose.rs` `batches_from` and `load_base` (seed 1) |
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

### Results (executor only; prove time = segments x 30.1 s, not measured)

Headline guest (`ss_mg`, radix). The phase split covers **user cycles
only**:
- "Ingest + commit" is read + Com_old + key mapping + Com_batch + Com_new +
  journal.
- The remaining 2,993 user cycles fall before `main` and after the last probe.
- "Overhead" (padded - user) is paging plus the per-segment reserve and po2
  padding. It is not in any phase, yet it is 27-34% of the padded cycles that
  set the segment count, and so the computed seconds.

| dataset, epoch | s | S_old active | union keys | tau | S_new active | user cycles | padded cycles (sum 2^po2) | overhead (paging + reserved) | segments | prove (segments x 30.1 s) | ingest + commit | transition | transition, % of user | transition, % of padded |
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

| dataset, s | segments per epoch (mean, range) | segments over 64 epochs | segments x 30.1 s over 64 epochs |
|---|---|---|---|
| AOL, 16,384 | 10.7 (8-12) | 685 | 20,619 s (5.7 h) |
| AOL, 1,024 | 5.8 (5-6) | 373 | 11,227 s (3.1 h) |
| Uniform, 16,384 | 9.3 (8-12) | 596 | 17,940 s (5.0 h) |
| Uniform, 1,024 | 5.3 (5-6) | 342 | 10,294 s (2.9 h) |

Sensitivity (user cycles / segments / segments x 30.1 s):

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

- **No proved anchor for this guest.** Every second above is segments x 30.1 s,
  the rate of the four CM-guest CPU anchors. The three non-CM anchors (HLL, SS,
  GK) agreed with that rate within 2%, but this guest is not one of them.
  - Counting whole segments overstates rows whose last segment is partial. The
    lower bound, `padded_cycles / 2^20 x 30.1 s`, gives 218 s for AOL 0 at
    s = 16,384 (240.8 s by segments) and 158 s for AOL 63 at s = 1,024 (180.6 s).
    The other headline rows have only full segments.
- **CPU-only r0vm 3.0.6 on this box** (AMD Threadripper PRO 9975WX, 32 cores /
  64 threads). The GPU prover was not used.
- **Cross-hardware.** The paper's zkSketch timing tables were measured on EPYC
  machines. Cycles and segments do not depend on the hardware; seconds do. A
  ratio of these computed seconds to EPYC-measured zkSketch seconds is a
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

## GK band-merge transition, matched semantics (`gk_bm2/`): executor only

`gk/` (above) runs textbook GK (per-record INSERT / COMPRESS) inside zk-Analytics'
pipeline. That is not the function zkSketch's GK circuit certifies. `gk_bm2/`
executes **exactly zkSketch's batch transition** in a RISC Zero guest, one guest
run per epoch:

    S_t = apply_batch2(S_{t-1}, gk_vals_of(batch_t))
    journal = Com_old ‖ Com_batch ‖ Com_new        (unsalted SHA-256, risc0-accelerated)

`apply_batch2` is in `src/sketch/gk_bandmerge.rs`; `gk_vals_of` is in
`src/experiments/stream_compose.rs`. `gk_bm2/README.md` has the full detail:
the statement, the port, every check and the phase profile. Nothing was proved.

### Method

- **Guest (`gk_bm2_step`).**
  - Reads the old state and the epoch's m raw u32 keys with `env::read_slice`.
  - Commits the old state and the raw batch.
  - Maps the keys with `gk_vals_of`: drop `PAD_KEY` slots, mask to 21 bits.
  - Runs the transition.
  - Commits the new state, and journals the three 32-byte commitments.
  - `env::cycle_count()` probes split ingest + commit from the transition, in
    user cycles. They go to the guest's private stdout, never to the journal.
- **Four implementations of the one function** (an input word selects one):
  - `literal`: zkSketch's code statement for statement. It uses the fixed
    `capacity + m` table, all 15 fuse rounds over every row, a comparison sort
    for the union, and a fresh table plus a stable `(e, t)` re-sort after each
    round.
  - `literal_reuse`: the same, with the per-round tables allocated once (risc0's
    guest allocator never frees).
  - `fixed_linear`: zkSketch's fixed schedule (the full table, all 15 rounds,
    every pair visited, every row rewritten each round) with a linear-time
    union (radix sort + merge) and an in-place fuse-and-compact per round in
    one table. On a canonical state the compaction is the stable re-sort.
  - `fast`: the same output on a data-dependent schedule: the union as in
    `fixed_linear`, rounds over the active prefix only, and a stop at the first
    no-op round. A zkVM may run that; zkSketch's oblivious circuit cannot.
- **Equivalence (`zka_gk_bm2_check.csv`, 236 rows).** At every epoch the guest's
  new state is emitted and compared, tuple by tuple (all `capacity` rows, `n`,
  the parameters), with zkSketch's native `apply_batch2` on the same input. The
  driver also checks:
  - the journal against host-computed commitments;
  - the guest's merge census (fusions by direction) against the native one;
  - all four ports, re-run natively, against zkSketch.

  The chains, all four variants each, with every row equal:

  | config (capacity, s, m) | chains |
  |---|---|
  | deployed (2048, 51, 16384) | AOL 4 epochs; Uniform 4 epochs; AOL under the mixed-workload batcher, 7 batches carrying 49,158 `PAD_KEY` slots |
  | (64, 51, 16384) | AOL 8 epochs; Uniform 8 epochs |
  | (48, 51, 16384), overflow | AOL 4 epochs |
  | (256, 6, 4096) | AOL 8 epochs; Uniform 8 epochs |
  | (8, 51, 4095), odd and full | AOL 4 epochs; Uniform 4 epochs |

  - **Capacity 64** runs the sketch at 72-88% occupancy. It does not change the
    fusion schedule: θ = ⌊N_t / s⌋ does not depend on capacity, and `L_f` is
    15 for both 64 and 2048 at m = 16,384. Its epochs 0-3 repeat the deployed
    chain's merges exactly and differ only in the final slice.
  - **s = 6** is the chain with a different θ regime (θ 682 to 5,461,
    `L_f` = 13).
  - **Capacity 48** is below the sketch, so zkSketch's release build truncates
    silently, and the ports match it.
  - **Capacity 8 with m = 4,095** gives an odd 4,103-row table that is full
    from epoch 1, the one place where zkSketch drops the never-paired last row.
  - **Unit tests.** `cargo test --release -p gk-bm2-host` (5 tests) adds 480
    short native chains (odd tables, overflow, pads), odd full tables, and the
    refusal of non-canonical states.
- **Not † and not zk-Analytics.** No zk-Analytics code or architecture is used:
  no `Event` batches, batch chain or epoch chain. Cite it as "zkSketch's GK
  batch transition executed in RISC Zero (general-purpose zkVM baseline, ours)".

### Ours vs upstream

| item | source |
|---|---|
| the transition (`Tuple`, `State`, `apply_batch2`, `fuse_round_fixed2`, neighbour init, `num_rounds`, `gk_vals_of`, `E_MAX`, `PAD_KEY`) | zkSketch `gk_bandmerge.rs` / `stream_compose.rs`, ported statement for statement into `gk_bm2/core` (`literal`; only the circuit-witness captures dropped) |
| `literal_reuse`, `fixed_linear`, `fast`, the word encoding, the SHA-256 commitments and tags, the guest, the host driver and its checks, the runner | written by us |
| datasets, batching, the mixed-workload batcher, the reference `apply_batch2` | the zkSketch crate itself, a path dependency of the host (as `ourcm/` and `zksq/`) |
| accelerated SHA-256, `read_slice` / `commit_slice` / `cycle_count` | risc0-zkvm 3.0.5 (guest) |
| zk-Analytics (`d4a5a9a`) | nothing |

Against `gk/`, the zk-Analytics-architecture GK (†):

| | `gk/` `aggr_gk` (†) | `gk_bm2` |
|---|---|---|
| algorithm | textbook GK, per record, summary built from scratch per epoch | zkSketch's two-sided band-merge batch transition, carrying `S_{t-1}` |
| statement | their epoch pipeline: batch hash chain, Merkle root, epoch chain link | `Com_old`, `Com_batch`, `Com_new` (zkSketch's leaf statement, SHA-256 in place of Poseidon2) |
| input | their `Event` batches through risc0 serde (1.41 MB) | raw u32 keys + the state's words through `read_slice` (163,900 B) |
| AOL epoch 0 | 103.4M user cycles, 107 segments (about 78.7M of them their framework) | 5.3M (`fast`), 23.3M (`fixed_linear`) or 82.1M (`literal`) user cycles; 8, 37 or 129 segments |

### Exact configuration

- **Parameters.** `GkbParams { capacity: 2048, batch: 16384, s: 51 }`, the
  deployed config; `s = 51` is `exp_compose`'s `derive_gk_s(2048, 2^20)`.
- **Records.** AOL is `data/aol.keys` (md5 `01dd7d5c8a73`). Uniform is
  `synthetic_stream(Uniform, N, seed 1)`, `exp_compose`'s
  `load_base("uniform")`, not the seed-2 `data/uniform.keys`. Epoch e is keys
  `[e*16384, (e+1)*16384)`. For epoch 63 the state is carried by zkSketch's
  native `apply_batch2` over epochs 0..62.
- **Toolchain.**
  - Guest: risc0-zkvm 3.0.5. Its lock was seeded from `gk/guests/Cargo.lock` and
    no third-party version changed.
  - Host: risc0-zkvm 3.0.6, plus the zkSketch crate.
  - Executor: r0vm 3.0.6 over IPC, CPU.
  - Builds go to `$BASELINE_DIR/build/zka-gk-bm2` with `--locked` and
    `RISC0_BUILD_LOCKED=1`.
  - The ELF md5 and image ID are in the log headers and in the `image_id`
    column (measured ELF `b429918d`).
- **Running.** `gk_bm2/gk_bm2_exec.sh` builds, runs the equivalence check,
  then the measurement, and stages each CSV (`.tmp`, then a move). It took
  4.5 minutes with a cached build. `CHECK=0 SKIP_BUILD=1` gives the
  measurement only. The first, three-variant version's rows are kept as
  `zka_gk_bm2_{exec,check}_v1_3variants.csv`.

### Results (executor only; prove time = segments x 30.1 s, not measured)

`zka_gk_bm2_exec.csv`, one 16,384-record epoch at the deployed config. Ingest +
commit and transition are guest probes in **user cycles**:

| row | variant | user cycles | total cycles (Σ 2^po2) | segments | prove (segments x 30.1 s) | ingest + commit | transition |
|---|---|---|---|---|---|---|---|
| AOL epoch 0 | literal | 82,065,236 | 135,266,304 | 129 | 3,883 s | 869,752 | 81,195,484 |
| AOL epoch 0 | literal_reuse | 69,069,283 | 114,294,784 | 109 | 3,281 s | 869,752 | 68,199,531 |
| AOL epoch 0 | fixed_linear | 23,288,159 | 38,273,024 | 37 | 1,114 s | 869,752 | 22,418,407 |
| AOL epoch 0 | fast | 5,271,282 | 8,388,608 | 8 | 241 s | 869,752 | 4,401,530 |
| AOL epoch 63 | literal | 82,088,781 | 135,266,304 | 129 | 3,883 s | 869,752 | 81,219,029 |
| AOL epoch 63 | literal_reuse | 69,092,828 | 114,294,784 | 109 | 3,281 s | 869,752 | 68,223,076 |
| AOL epoch 63 | fixed_linear | 23,499,790 | 38,273,024 | 37 | 1,114 s | 869,752 | 22,630,038 |
| AOL epoch 63 | fast | 5,489,126 | 8,388,608 | 8 | 241 s | 869,752 | 4,619,374 |
| Uniform epoch 0 | literal | 82,022,165 | 135,266,304 | 129 | 3,883 s | 869,752 | 81,152,413 |
| Uniform epoch 0 | literal_reuse | 69,026,212 | 114,294,784 | 109 | 3,281 s | 869,752 | 68,156,460 |
| Uniform epoch 0 | fixed_linear | 23,230,989 | 37,748,736 | 36 | 1,084 s | 869,752 | 22,361,237 |
| Uniform epoch 0 | fast | 5,244,975 | 8,388,608 | 8 | 241 s | 869,752 | 4,375,223 |

- **The transition dominates, in user cycles.** Ingest plus the three SHA-256
  commitments costs 0.87M user cycles on every row: 1.1% of `literal`, 3.7% of
  `fixed_linear`, 16.5% of `fast`. Segments also carry paging (total/user is
  1.59x-1.65x), which the executor does not split by phase, so the ingest
  share of the segments and of the computed time is not measured.
- **`literal` vs `fast` is 15.6x in user cycles (16x in segments), but most of
  that is the literal port's implementation, not the oblivious schedule.**
  At AOL epoch 0, of the 76.8M user-cycle gap:
  - 13.0M is the bump allocator (fresh tables every round; `literal_reuse`);
  - 8.9M is the comparison-sort union (vs radix sort + merge);
  - 36.8M is each round's fresh `fused` table and stable `(e, t)` re-sort and
    gather (vs fusing and compacting in place in one table);
  - 18.0M is the fixed schedule itself: `fixed_linear` visits all 18,432 rows
    in all 15 rounds, `fast` only the active prefix and 10-12 rounds;
  - the remaining 0.04M is neighbour init and final rows.
- **The like-for-like ratio is `fixed_linear` vs `fast`: 4.4x in user cycles,
  4.6x in segments** (23.3M vs 5.3M, 37 vs 8). That is this implementation of
  the fixed schedule, not a lower bound for every implementation.
- **Data dependence.** `literal` and `literal_reuse` move by at most 0.1%
  across the three rows, `fixed_linear` by 1.2% (36-37 segments), `fast` by
  4.7%.
- **Determinism.** Two full runs with the measured ELF agreed on all 248 rows
  in every column but `exec_s`.

### Caveats

- **No proved anchor for this guest.** The 30.1 s per segment comes from the
  four CM-guest CPU anchors (envelope 29.73-30.79 s/segment). The non-CM
  aggregation anchors above landed within 2% of it, but none is `gk_bm2_step`.
  Counting whole segments overstates partial last segments: AOL `fixed_linear`
  is 1,114 s by segments against 1,099 s pro rata.
- **Cycle counts belong to one ELF.** Rebuilding with other code in the guest
  moved `literal` (source unchanged) by -0.3% and one segment, and `fast` by
  +1.4%. `fast`'s rows fill exactly 8 x 2^20 total cycles, on the 8/9-segment
  boundary; quote it as **8-9 segments (241-271 s at 30.1 s per segment)** and use user
  cycles as the primary metric. Details in `gk_bm2/README.md`.
- **CPU-only r0vm 3.0.6** on this 64-thread Threadripper; the GPU prover was not
  used. `exec_s` is wall-clock and not a metric.
- **Cross-hardware.** The paper's zkSketch tables were measured on an EPYC
  machine. Cycles and segments are hardware-independent; the computed seconds
  use this box's CPU rate. Any ratio against an EPYC zkSketch time crosses machines
  and must say so. No same-box zkSketch GK leaf was measured here, and the
  zkSketch-side caveat above applies.
- **Which row to quote.** `fixed_linear` is the like-for-like fixed schedule.
  `fast` is the conservative (cheapest) zkVM baseline for the identical
  function; its cycle count leaks data properties, as zk-Analytics' guests do.
  `literal` is the statement-for-statement port; do not quote `literal` vs
  `fast` as the cost of obliviousness.
- **Not hiding, not a pipeline.** The commitments are unsalted. Each run is one
  transition: linking `Com_new` to the next `Com_old`, verifying receipts and
  answering queries are not measured.

## GK with zkSketch's algorithm in their pipeline (`gk_matched/`, ours †): the six-sketch GK default

**Why.** For a fair comparison both systems must run the same GK *algorithm*, not two
different summaries with the same eps. `gk/` (textbook Greenwald-Khanna: per-record
INSERT / band COMPRESS, a summary rebuilt every epoch, a k-way COMBINE at query time) is a
different function from the one zkSketch certifies, and `gk_bm2/` runs zkSketch's function
but outside their pipeline (no Event batches, no batch chain, no epoch link). `gk_matched/`
is both at once: zk-Analytics' aggregation and query pipeline, step for step as the other
ports, with zkSketch's GK batch rule as the summary update. Since 2026-10-15 it is the
zk-Analytics GK of `six/` (`SIX_ZKA_GK=matched`, the default); `gk/` is the labelled
reference (`SIX_ZKA_GK=textbook`). Full detail: `gk_matched/README.md`.

### What is the same, what is theirs, what is ours

| | zkSketch (`exp_compose`, GK forest) | zk-Analytics side (`gk_matched/`) |
|---|---|---|
| records | AOL `key & 0x1FFFFF`, B per paper batch | the same records, B per epoch, as their Events (`key_id`, `value`, `ts`), batches of 8 |
| GK function | `apply_batch2` once per m_sub-record leaf, from the previous leaf's state (`GkbParams { capacity, m_sub, s = 51 }`) | the same `apply_batch2` chain: B / m_sub steps per epoch from the carried state (default `literal`, zkSketch's `apply_batch2` as written, since 2026-10-15; `tuned`: `gk_matched/core` `apply_epoch_tuned`; `fast` / `fixed_linear` / `literal`: `gk_bm2/core`, unchanged) |
| state carried | leaf boundary commitments, chained by the forest | `state_commit` in their epoch chain link; the next epoch's guest checks its input state against it |
| capacity overflow | the leaf circuit refuses to prove | the guest panics (no receipt); the driver exits 3 first |
| query | decoder proof: rank(v) by `native_estimate`, midpoint of [r_min, r_max] | query guest: their chain-link check, the latest state opened against the last link, the same estimator |
| commitments | Poseidon2, hiding (salted) | unsalted SHA-256 (their pattern), over the parameters, n and the active tuples |
| framework | zkSketch's proof forest | their batch-chain check (verbatim), Event deserialisation, flatten, epoch link (`EpochChainLink`) |

### Equivalence (`results/20261015-m1/` holds the files)

- **Guest = zkSketch's native chain, tuple by tuple.** `gk_matched --mode check` at
  (capacity, m_sub) = (384, 128) [16 steps per 2,048-record epoch], (768, 512) [4 steps]
  and (2048, 2048) [1 step], epochs 0 and 1, AOL, implementations `fast`,
  `fixed_linear`, `literal`: 18 rows (round 1); `tuned`, the default since round 2: 26
  more rows, (384, 128) epochs 0-3 (with `fast` and `fixed_linear`), (768, 512) epochs 0-1
  (all four), (2048, 2048) epochs 0-1 (with `fast`) and (64, 256) epochs 0-1. Each row has
  the guest's emitted state equal to zkSketch's `apply_batch2` chain in all 7 fields of
  every row, n and the parameters, `journal_eq_native=true`, and the query guest's bounds
  equal to zkSketch's `Gk2State::rank_interval` on its own chain; at each epoch every
  implementation gives the same `state_commit`.
- **Guest = what zkSketch's leaf circuit certifies.** `gk_matched --mode certify` proved
  zkSketch's GK leaf, built as `exp_compose` builds it (hiding commitments), for every
  leaf of epochs 0 and 1: 32 leaves at (384, 128) (90 s per epoch) and 8 at (768, 512)
  (74 s per epoch, 16.9 GB peak RSS). Every leaf's exposed initial / final commitment equals
  Com of zkSketch's native chain, each epoch's last leaf exposes Com(S) of the state the
  zk-Analytics guest computed, and zkSketch's GK decoder proved on that state at the hot
  value answers what the query guest answers: 1,778 / 3,539 at (384, 128), 1,780 / 3,551
  at (768, 512) (rank(1,810,625) after 2,048 / 4,096 records; exact 1,789 / 3,569).
- **`exp_compose` runs agree.** The 2026-10-14 memory-matched forests
  (`results/memmatch-20261014/runs/`) answered 1,778 (`gk-m128-cap384-t16`, leaf 16),
  1,780 (`gk-m512-cap{64,128}-t4`, leaf 4) and 1,786 (`gk-m2048-cap2048-t1`) for the same
  query after the same 2,048 records: the query guest's answers at those configurations.
  Over eight carried epochs the committed `six_zksketch{,_r2}_gk` runs (capacity 2,048,
  8 x 2,048) answered 1,786, 3,557, 5,274, 7,095, 8,916, 5,877, 6,915, 7,927 at n = 1..8,
  and the matched query guest gives the same eight answers. A fresh six-harness smoke test
  at 2 x 256 records (cap 512) gave 171 / 330 on both sides.
- **Native unit tests** (8): the chain at four configurations, carried-state binding
  (tampered state, wrong previous link, missing state, changed configuration, fake
  genesis are refused; so is a correctly linked state with rows out of order or a mass
  other than n), overflow = panic in all implementations (capacity 16, where
  zkSketch's native code loses records: it truncates silently in a release build and
  stops at a `debug_assert!` in a debug build; the tests pass in both), `tuned` against
  zkSketch's chain on 22 edge shapes (odd tables, capacities at and below overflow: equal
  where zkSketch keeps every record, a panic where it loses one), the estimator, the root
  variants, and the query's one-unbroken-chain rule (a genesis restart, which their link
  check accepts, and a stale state are refused).

### Executor results, one 2,048-record AOL epoch (noroot; `results/20261015-m1/`)

**Correction (2026-10-15, after M1): the baseline is `literal`, not `tuned`.** The
zk-Analytics side must run zkSketch's GK *algorithm* as its original code, not a program
re-engineered with zkSketch's circuit-design insights. `tuned` (the default during M1
rounds 2-3, and the 352 / 336 s real proofs below) and `fast` compact the survivors instead
of re-sorting, the observation behind zkSketch's planned stable-compaction circuit, so
they stay only as labelled sensitivity rows. `literal` at B = 2,048 is 37 segments
(38.8M padded cycles) at (384, 128) and 31 segments (32.0M) at (768, 512): about 1,133 s
and 933 s at the 30.6 s per 2^20 padded cycles of the real `tuned` proofs (cycles x that
rate, not proved here; a real `literal` proof takes 16-19 min). `read` is their
Event deserialisation plus, from epoch 1 on, the carried state's words (see Caveats).

| zk-Analytics GK | impl | epoch | user cycles | segments (padded, x 2^20) | read (Events + carried state) | batch chain | GK update | everything else | padded x 30.07 s |
|---|---|---|---|---|---|---|---|---|---|
| matched, (384, 128), 16 steps | **tuned** | 0 | 10,979,416 | **12** (11.5) | 7,605,761 | 2,245,159 | 965,322 | 163,174 | 345.8 s |
| matched, (384, 128) | tuned | 1 | 11,085,631 | 12 (11.5) | 7,714,745 | 2,245,658 | 952,085 | 173,143 | 345.8 s |
| matched, (384, 128) | fast | 0 | 11,879,837 | 13 (13.0) | 7,605,761 | 2,245,159 | 1,841,352 | 187,565 | 390.9 s |
| matched, (768, 512), 4 steps | **tuned** | 0 | 10,693,564 | **11** (11.0) | 7,605,761 | 2,245,159 | 680,565 | 162,079 | 330.8 s |
| matched, (768, 512) | tuned | 1 | 10,822,662 | 12 (11.25) | 7,705,745 | 2,245,658 | 698,971 | 172,288 | 338.3 s |
| matched, (768, 512) | fast | 0 | 11,047,367 | 12 (12.0) | 7,605,761 | 2,245,159 | 987,885 | 208,562 | 360.8 s |
| matched, (2048, 2048), 1 step | **tuned** | 0 | 10,569,752 | **11** (11.0) | 7,605,761 | 2,245,159 | 555,837 | 162,995 | 330.8 s |
| matched, (2048, 2048) | tuned | 7 | 10,716,409 | 12 (11.125) | 7,703,945 | 2,245,658 | 595,196 | 171,610 | 334.5 s |
| matched, (2048, 2048) | fast | 0 | 10,872,657 | 12 (11.5) | 7,605,762 | 2,245,157 | 737,882 | 283,856 | 345.8 s |
| textbook (`gk/`, memmatch 2026-10-14) | | 0 | 12,862,178 | 14 (13.25) | | | | | 398.5 s |

- The epoch costs about the same with either GK: 89-93% of the user cycles are their
  framework (Event deserialisation and the batch-chain check), identical in every port.
  zkSketch's rule is cheaper in their pipeline than textbook GK (0.56M-0.97M with `tuned`
  vs about 3M user cycles for the summary at 2,048 records), so the matched baseline is
  FASTER than the textbook one: 11.5 / 11.0 padded segments at configs A / B instead of
  13.25, i.e. about 346 / 331 s instead of 398.5 s at k_s = 30.07 s per padded 2^20 cycles.
- **Real proofs** (M1, `results/20261015-m1/`; their shipped tier `ProverOpts::succinct()`,
  CPU r0vm 3.0.6, epoch 0, noroot, gated on a quiet box, journal == native):

  | config | impl | prove_s | segments (padded, x 2^20) | s per padded 2^20 | verify | receipt | r0vm peak RSS |
  |---|---|---|---|---|---|---|---|
  | A (384, 128), 16 steps | **tuned** | 352.4 / 351.8, mean **352.1** | 12 (11.5) | 30.64 / 30.59 | 9.7 / 11.6 ms | 225,114 B | 9,398 / 9,401 MiB |
  | A | fast (round 1) | 392.7 | 13 (13.0) | 30.20 | 11.5 ms | 225,114 B | 9,388 MiB |
  | B (768, 512), 4 steps | **tuned** | 338.1 / 334.6, mean **336.3** | 11 (11.0) | 30.74 / 30.42 | 9.8 / 11.6 ms | 225,114 B | 9,390 / 9,398 MiB |
  | B | fast (round 1) | 363.0 | 12 (12.0) | 30.25 | 11.5 ms | 225,114 B | 9,397 MiB |

  `tuned` was proved twice with the same binary (image `3d746b3b...`): the fixer's proof,
  then the round-2 measurer's repeat. So the 10x threshold for zkSketch's 2,048-record GK
  batch is **35.2 s at (384, 128)** and **33.6 s at (768, 512)** (means of the two proofs;
  39.3 / 36.3 s against `fast`). These are epoch-0 proofs, from the empty state with no
  carried state. The carried-state epoch is 11.5 padded segments at (384, 128), as at epoch
  0, and 11.25 instead of 11.0 at (768, 512) (+2%, about +8 s at 30.4-30.7 s per 2^20), so
  a steady-state zk-Analytics epoch costs the same or slightly more: the epoch-0 thresholds
  are conservative for zkSketch.
- **Implementations** (check rows, epoch 0, user cycles / segments; check rows carry a few
  thousand to 38k cycles for emitting the state):

  | config | `tuned` | `fast` | `fixed_linear` | `literal` |
  |---|---|---|---|---|
  | (384, 128), 16 steps | 10.98M / 12 | 11.92M / 13 | 16.71M / 18 | 30.36M / 37 |
  | (768, 512), 4 steps | 10.70M / 11 | 11.12M / 12 | 14.85M / 16 | 25.37M / 31 |
  | (2048, 2048), 1 step | 10.58M / 11 | 11.08M / 12 | 14.35M / 16 | 23.69M / 30 |

  `fast` calls `apply_batch2_fast` once per step, and each call re-checks the canonical
  form of all `capacity` rows, clears and prefix-sums two 2,049-entry radix tables, pads
  its output to `capacity` with dummies and allocates fresh buffers (and epoch 0 builds a
  `capacity`-row empty state). `tuned` runs the same schedule as one loop over the
  epoch: the state stays compact, the canonical check runs once on the carried state, the
  radix digits are sized to the batch, the buffers are allocated once. Same 2,048 AOL
  records at capacity 384, GK update cycles by leaf size: m_sub 2048 / 512 / 256 / 128
  (1 / 4 / 8 / 16 steps) = 555,837 / 680,565 / 774,181 / 965,322 with `tuned` (11 / 11 /
  12 / 12 segments), against 586,458 / 848,102 / 1,178,141 / 1,841,333 with `fast` (12 /
  12 / 12 / 13). `tuned`'s remaining cost per extra step, about 27k cycles at m_sub 128,
  is close to the work the schedule needs per step (merging about 180 rows, two neighbour
  passes, about six shrinking fuse rounds).
- **zk-Analytics' own memory.** A real proof of one of these epochs peaks at about
  9.2 GiB of r0vm RSS (r0vm 9,388-9,401 MiB, 9,404-9,428 MiB with the driver, in M1; r0vm's default
  po2-20 segment prover, not tuned): any "8 GiB" statement about zkSketch is not one about
  both sides.

### Caveats

- **Their pipeline, our port (†).** zk-Analytics ships no rank-guaranteed quantile summary;
  the GK update is zkSketch's (`literal` by default, `tuned` in the M1 measurements, the other implementations from `gk_bm2/core`),
  the rest is their code or pattern.
- **The carried state departs from their architecture.** Their aggregators build each
  epoch's summary fresh and independently (one chain per aggregator; epochs can be
  aggregated in parallel, by different aggregators) and merge the n summaries at query
  time. The matched port carries S_{e-1} into epoch e, forces one sequential chain
  (a chain that restarts at genesis is refused), and its query opens the latest state
  without a merge. That is forced by the same-function requirement: zkSketch's function is
  the `apply_batch2` chain from the previous state, and a fresh-per-epoch summary merged at
  query time is a different sketch (textbook `gk/` is one). Extra cost to zk-Analytics per
  epoch, from epoch 1 on (`tuned`, AOL): the carried words' read, through risc0 serde like
  every other input word (epoch 1 minus epoch 0 of `read`: 108,984 at (384, 128), 99,984 at
  (768, 512), 107,184 at (2048, 2048), of which about 6.2k is the one source chain-tip
  entry every port reads from epoch 1 on, so about 102.8k / 93.8k / 101.0k), plus the
  `carry` phase (commitment check and decoding: 12,653 / 11,798 / 12,522; 1,603 at epoch
  0). About 0.11-0.12M user cycles, 1.0-1.1% of the epoch; the state commitment itself
  (12-14k) is paid by every port.
- **Data-dependent.** `tuned` and `fast` exploit the data (active prefix, early stop), as a
  zkVM may; zkSketch's circuit is oblivious. `fixed_linear` is the fixed schedule.
- **No padding on their side.** zkSketch's `gk_vals_of` drops `PAD_KEY` slots (only its
  early-sealed batches have them). A zk-Analytics epoch has none, so the guest's drop is a
  no-op, and the driver refuses a dataset holding a key equal to `PAD_KEY` (`u32::MAX`),
  which the two sides would summarise differently. `data/aol.keys` has none.
- **Leaf size.** A six run uses `SIX_M` for both (one step per epoch). A zkSketch forest
  with smaller leaves (`SIX_M=128`, 16 leaves per 2,048 records) is matched by running the
  zk-Analytics side at `SIX_M=2048 SIX_GK_MSUB=128` with the same `SIX_GK_CAP`. When the two
  sides' capacity, s or leaf size differ, `assemble.py` says CONFIG MISMATCH in the note and
  `table.py` labels the GK row "CONFIG MISMATCH: same rule, NOT the same function".
- **Accuracy columns are native checks** of the state (exact rank inside [lo, hi] for every
  distinct value covered; certified half-width vs eps N), not guest work: 37 / 77 at
  (384, 128) against eps N = 40.2 / 80.3.
