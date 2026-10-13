# SpaceSaving on the zk-Analytics pipeline (our port)

A baseline for zkSketch's SpaceSaving (SS) heavy-hitters summary, built on
zk-Analytics' own general-purpose method (Zhu et al., "Zero-Knowledge Cloud
Analytics", SIGCOMM '26; RISC Zero zkVM; code `d4a5a9a`). zk-Analytics does not
ship SpaceSaving. **This is our instantiation of their per-epoch-aggregation /
query-time-merge architecture with our own RISC Zero guests (†). It is not
zk-Analytics code.** Do not call it "zk-Analytics's SpaceSaving".

What is theirs and what is ours:

| step | where it comes from |
|---|---|
| verify each data source's SHA-256 batch hash chain | their `verify_and_compute_chain`, copied verbatim |
| flatten batches into events, rebuild the epoch summary from scratch | their pattern |
| **SpaceSaving update per record** | **ours**: textbook Metwally et al., plain Rust |
| canonical state (entries sorted by `key_id`), unsalted SHA-256 state commitment | their pattern |
| Merkle root over 64 hash buckets of entries in the aggregation journal | their samples pattern (`samples_buckets_root`, their benchmark `SAMPLES_HT_BUCKETS=64`) |
| epoch hash chain link | their `EpochChainLink` |
| query: re-verify epoch links, recompute each epoch's state commitment | their `verify_epoch_chain_integrity`, copied verbatim; their pattern |
| **top-10: query-time merge (sum equal keys, keep top s)** | **ours**, written the way their `SumTopk` merges |
| point frequency: one scan over every epoch's entries, one sum | their `SumExactKey` loop |
| low-support suppression | their rule (`MIN_SUPPORT`) |

The guests are plain code. There is no oblivious padding, memory checking,
sorting certificate or Poseidon, and none of zkSketch's circuit techniques.

## Layout

| path | what |
|---|---|
| `core/` | `ss-core`, a no_std library used by both guests and the host: the SpaceSaving structure, epoch state, commitment, aggregation, merge and query |
| `methods/` | the RISC Zero methods crate. `guests/` is its own cargo workspace with `aggr_ss`, `query_ss` (the measured guests), `aggr_ss_prof`, `query_ss_prof` (profiling twins) and `aggr_ss_rootvar` (the aggregation with a run-time choice of Merkle root, for sensitivity rows only) |
| `src/bin/ss.rs` | host driver: builds AOL epochs, runs the executor (or the prover), checks journals and writes one CSV row per run |
| `src/reference.rs` | independent references and unit tests: linear-scan SpaceSaving, BTreeMap merge, binary-search point query, exact counts |
| `ss_exec.sh` | the executor sweep behind `../results/zka_ss_exec.csv` (executor rows only) |
| `ss_anchor.sh` | the proved anchor (aggregation, 2,048 records) behind `../results/zka_ss_anchor.csv` (proved rows only) |
| `common_ss.sh` | build routing and CSV/log helpers, on top of `../common.sh` |

Results files (all under `../results/`):

| file | what |
|---|---|
| `zka_ss_exec.csv` / `.log` | the current executor sweep; every row has `prove_s = NaN` |
| `zka_ss_anchor.csv` / `.log` | every proved run, with `prove_condition` = `clean` or `contended`. Only `clean` rows are anchors |
| `zka_ss_exec_v1_before_fix.csv` / `.log` | the first version's 36 executor rows, kept for side-by-side comparison (per-key Merkle root; point query through the full merge). Its two proved rows moved to `zka_ss_anchor.csv` |

## How to run

```bash
scripts/baselines/fetch_baselines.sh                            # the zk-Analytics clone at d4a5a9a
scripts/baselines/zka/spacesaving/ss_exec.sh                    # builds, then runs the executor sweep
SKIP_BUILD=1 scripts/baselines/zka/spacesaving/ss_anchor.sh     # proves one small aggregation epoch
                                                                # (refuses if load > 24 or any r0vm is running)
# unit tests: Stream-Summary vs linear scan on tiny capacities; merge vs BTreeMap;
# bucket index vs their samples_bucket_index; bucket root vs an independent grouping;
# point-query scan vs binary search
cd scripts/baselines/zka/spacesaving && CARGO_TARGET_DIR=~/ext-baselines/build/zka-ss-test \
  RISC0_BUILD_LOCKED=1 cargo test --release --locked --bin ss
```

- Builds go to `$BASELINE_DIR/build/zka-ss` (default `~/ext-baselines`).
- The host build is pinned by `Cargo.lock`. That file was seeded from
  `../cyc/Cargo.lock` and cargo only added this port's three crates, so every
  shared crate has the same version as in `cyc` (host risc0-zkvm 3.0.6).
- The guests are pinned by `methods/guests/Cargo.lock`. That file was seeded
  from the clone's `Cargo.lock`, and cargo only added this port's crates, so
  guest risc0-zkvm is **3.0.5**, as in their guests. The seeding kept every
  version unchanged, which was checked by diffing the two lockfiles.
- As in `../common.sh`, `RISC0_BUILD_LOCKED=1` makes risc0-build's nested guest
  cargo honour the guest lockfile.
- Path dependencies reach the read-only clone through `../.zka`, the untracked
  symlink that `../common.sh` maintains.
- A fresh target directory rebuilt all five guest ELFs byte for byte; the md5s
  are in the header of `../results/zka_ss_exec.log`, and every CSV row carries
  its guest's `image_id`. The rebuild is byte-identical only from the same
  absolute source path: panic-location strings embed the path. A build from
  another path gives different md5s and image IDs but identical cycle counts.
- Driver flags: `ss --mode aggr|query --capacity S [--epochs N] [--query topk|estimate|estimate_merged] [--limit 10] [--point-rank R] [--root legacy|designed|noroot|buckets1024|perkey] [--epoch-size 16384] [--batch 8] [--profile|--prove]`,
  `--root` (the six-sketch root variants (`../README.md`, "Six-sketch comparison", "Root variants")): `legacy` (the default) runs `aggr_ss`, the
  measured guest of this README; every other value runs `aggr_ss_rootvar` with that
  root (designed = `buckets64`, noroot = `none`; both older names are still accepted) and
  can be proved,
  and `ss --image-id-of <guest>.bin`. Unknown flags are errors. The driver
  refuses to run if `RISC0_DEV_MODE` is set.
- Both scripts append to their CSV and refuse to append under a different header.
  `ss_anchor.sh` refuses to write proved rows into the executor CSV.

## Configuration

- **Records.**
  - Source: `data/aol.keys`, epoch e = keys `[e*16384, (e+1)*16384)`. This is the
    slicing of `../cyc/src/bin/shipped.rs`, so epoch 0 is the matched CM epoch
    (16,384 records, 8,433 distinct keys).
  - `key_id = Event::make_key_id(0, key)`, `value = 1`, `ts` = global record index.
  - Batching: one source, batches of 8 records (their `--commit-batch-size`
    default). The batch chain, sequence number and source tips carry across
    epochs, and the epoch chain links e-1 to e, all as in `shipped.rs`.
- **SpaceSaving.**
  - Unit-weight Metwally update: a present key increments; otherwise a free
    counter is used if there is one; otherwise the minimum counter is replaced
    with count = min+1 and error = min.
  - Data structure: Metwally's own **Stream-Summary**. Counters with equal counts
    share a bucket, and buckets are kept in count order. It is implemented as
    index-linked arenas, with O(1) work and no allocation per update.
  - Key lookup is a `hashbrown` map keyed by the full 15-byte `key_id`.
  - Tie rule: the evicted counter is the oldest counter in the minimum bucket.
    `reference::NaiveSs` re-implements that rule with a linear scan, and the two
    must agree exactly.
  - Why this structure: it is the textbook one, and a zk-Analytics author
    writing plain Rust would pick an O(1) structure. Their CM heap's linear scan
    over the slots (`cm_heap_update`, `aggregator/core/src/lib.rs:1103-1141`)
    would cost O(s) per miss at s = 2^14.
- **Hash.** The map hashes keys the way their CM does. It applies FNV-1a over all
  15 bytes (their pub `key_to_u64`, `aggregator/core/src/lib.rs:341-350`), then
  the splitmix64 finaliser of `cm_bucket_index` (`lib.rs:1058-1062`, without the
  row seed). Keys are compared in full, so a hash collision can never merge two keys.
- **Capacities.**
  - s = 2^14 is the matched parameter. An AOL epoch has 8,433 distinct keys
    (< 2^14), so per-epoch SS is exact there and never evicts.
  - s = 1,024 exercises eviction.
  - s is a run-time input. It is bound by the state commitment and published in
    both journals. Their `CM_TOPK_SLOTS`, by contrast, is a build-time constant.
- **Epoch state.**
  - Fields: `capacity`, `total_count` and the ≤ s monitored `(key_id, count u32, error u32)`
    entries, sorted by `key_id`.
  - State commitment: SHA-256 over a tag, the scalars and every entry. It is
    unsalted, as theirs.
- **Aggregation journal.** Their `SamplesAggrOutput` fields plus `capacity`:
  `epoch_chain_link`, `state_commit`, `buckets_root`, `capacity`, `n_events`,
  `final_source_chain_tips`.
- **Merkle root (`buckets_root`).** Every one of their aggregation modes
  publishes a root, which their host folds into `out_commit`; none of their
  query guests reads it. SpaceSaving state is a key → (count, error) map, the
  same shape as their samples state, so the measured guest roots it the way
  samples does (`samples_buckets_leaves` / `samples_bucket_leaf_hash` /
  `samples_buckets_root`, `aggregator/core/src/lib.rs:363-422`):
  - buckets: their `samples_bucket_index` mix (FNV-1a `key_to_u64`, a murmur3
    finaliser) masked to 64 buckets, their benchmark `SAMPLES_HT_BUCKETS=64`
    (`scripts/lib/common.sh:13`);
  - leaf = SHA-256(tag ‖ the bucket's entries sorted by `key_id`);
  - leaves = next power of two ≥ max bucket index + 1, folded by their pub
    `samples_buckets_root_from_leaves`, called unmodified.
  - Sensitivity rows (guest `aggr_ss_rootvar`) use the same construction at
    aggregator-core's build default of 1,024 buckets (which the shipped arm's
    `aggr_samples` was built with), a per-key root (their `hist_per_key_root`
    pattern; the first version of this port used it as the headline), and no
    root at all.
- **Query-time merge (top-k only).** The sum-and-truncate merge specified for
  this baseline: sum the counts and errors of equal keys, then keep the s largest
  counters (ties go to the smaller `key_id`). It is written the way their
  `SumTopk` merges: concatenate, stable sort by key (which merges the per-epoch
  key-sorted runs), aggregate runs, then sort by count. It is **not** the
  Agarwal et al. (PODS 2012) mergeable-summaries merge, which also subtracts the
  (s+1)-th merged counter; its guarantee is looser (see Caveats).
- **Queries.**
  - `Topk{limit: 10}` returns `(key_id, count, error)` for the 10 largest merged
    counters. **The keys are in the committed journal.** This deliberately does
    not replicate their CM `Topk` / samples `SumTopk`, which commit counts only
    and whose keys, if any, come from unproven server code
    (`querier/server/src/main_parts/queries.rs:815-823`, `:2054`).
  - `Estimate{key}` is their `SumExactKey` loop (`querier/core/src/lib.rs:808-821`):
    one pass over every entry of every epoch, summing the key's count and error.
    There is no merge, sort or truncation. It returns `(count, error, monitored)`,
    where `monitored` means at least one epoch tracks the key. The key is echoed
    in the journal.
  - `EstimateMerged{key}` (sensitivity only) is the first version's point query:
    the full top-k merge, then a lookup. A key outside the merged top s reads 0.
    Its rows show what the merge costs a point query that does not need it.
  - Point keys are the exact rank-1 key of the queried prefix (as `shipped.rs`'s
    CM `Estimate`) and the exact rank-100 key.
  - Support follows their conventions: `Topk` uses the total record count (their
    `SumTopk`); the point queries use the returned count (their `SumExactKey`
    support). Results below `MIN_SUPPORT = 10` are suppressed exactly as theirs are.
- **Checks on every row.** Each check is a column in the CSV.
  - `journal_eq_native`: the guest journal equals ss-core run natively on the same input.
  - `ref_eq`: every epoch state involved equals `NaiveSs`. For queries, the merge
    also equals `naive_merge`, and the journal answer equals the reference
    answer (`naive_merge` for `topk` / `estimate_merged`, a per-epoch binary
    search for `estimate`) after their suppression rule.
  - `invariants_ok` (aggregation only) checks the SpaceSaving invariants against
    exact counts:
    - for each monitored key: f ≤ count, count − error ≤ f, and count − f ≤ N/s;
    - error ≤ the minimum counter, and error = 0 if the summary never filled;
    - unmonitored f ≤ the minimum counter;
    - Σ count = N.
  - All three checks are `true` on all 70 executor rows of `zka_ss_exec.csv` and
    on the 3 proved rows of `zka_ss_anchor.csv` (`invariants_ok` is `-` on
    query rows).
  - The unit tests cover capacities 1–256, alphabets of 1–5,000 keys and
    eviction storms (Stream-Summary vs `NaiveSs`), the merge vs `naive_merge`,
    the bucket index vs their pub `samples_bucket_index` (100,000 keys), the
    bucket root vs an independent grouping, and the point-query scan vs a
    binary search.

## Results (executor; `MODELED` = segments x 30.1 s, NOT measured)

`MODELED` prove time uses the CM-guest CPU anchors of `../README.md`. The CSV
carries the envelope segments x 29.73 to segments x 30.79. Cycles and segments
are deterministic. `padded_cycles` = Σ 2^po2 over segments. Total cycles
including paging are not exposed by `SessionInfo`, so they are not reported.

### Aggregation guest, one AOL epoch (16,384 records, 8,433 distinct keys)

Headline guest `aggr_ss` (their samples-style 64-bucket root):

| s | state entries | user cycles | cycles/rec | padded cycles | segments | MODELED prove |
|---|---|---|---|---|---|---|
| 16,384 | 8,433 (exact, no eviction) | 113,584,313 | 6,932.6 | 129,499,136 | **124** | **3,732 s** |
| 1,024 | 1,024 (full; min counter 13) | 97,874,942 | 5,973.8 | 105,906,176 | **101** | **3,040 s** |

Root sensitivity (`aggr_ss_rootvar`; segments, with user cycles in parentheses).
No query reads any of these roots.

| s | no root | **64 buckets (headline)** | 1,024 buckets | per-key (v1 headline) |
|---|---|---|---|---|
| 16,384 | 117 (107.8M) | **124 (113.6M)** | 128 (117.0M) | 176 (162.6M) |
| 1,024 | 100 (97.0M) | **101 (97.9M)** | 105 (101.2M) | 105 (100.8M) |

- The first version rooted every entry as its own Merkle leaf, the pattern of
  their per-key histogram family. That made the s = 2^14 epoch 176 segments
  (5,298 s MODELED), 42% above the samples pattern. Their samples family holds
  the same kind of state (key → count), so its root is the one that applies.
- The `buckets64` row of `aggr_ss_rootvar` costs 55 cycles more than `aggr_ss`
  (the extra `SsRoot` read), so the sensitivity rows compare like for like.
- Late-epoch spot check (`aggr_ss` on epoch 63, 9,099 distinct keys): the guest
  journal equals the native output at both capacities (127 segments at 2^14,
  102 at 1,024). The query rows' epoch states 1..63 come from that native code.

For scale, on the same epoch 0 their shipped guests take (`../results/zka_shipped_exec.csv`):

| their guest | segments |
|---|---|
| `aggr_samples` (1,024-bucket root, their crate default) | 152 |
| `aggr_histogram` | 318 |
| `aggr_cm` T=100 | 277 |
| `aggr_cm` T=1 | 104 |

Their samples entry carries a 32-byte chain tip and a 64-bit sum besides the
key and count, so their state commitment and leaves hash 60 bytes per entry
against our 23; that is most of the gap between `aggr_samples` (152) and our
1,024-bucket row (128).

Phase breakdown from the profiling twin (percentages of the cycles between the
first and last marker). The deltas sum to within 0.04% of the session's user
cycles.

| phase | s = 16,384 | s = 1,024 |
|---|---|---|
| read input (`env::read` of 2,048 batches) | 60.8M (53.5%) | 60.8M (62.1%) |
| verify batch hash chain | 18.0M (15.8%) | 18.0M (18.4%) |
| flatten | 0.6M (0.5%) | 0.6M (0.6%) |
| **SpaceSaving updates** | **10.3M (9.1%)**, 629 cycles/rec | **15.8M (16.2%)**, 966 cycles/rec |
| canonical sort of entries | 15.2M (13.3%) | 1.4M (1.4%) |
| Merkle root (64 buckets) | 5.8M (5.1%) | 0.9M (0.9%) |
| state commitment + epoch link | 3.0M (2.6%) | 0.4M (0.4%) |

- The sketch update itself is 9–16% of the guest.
- Two costs are fixed by their input format and chain design: reading the
  input, about 3,700 cycles per record (risc0 serde, one word per `key_id`
  byte), and chain verification. Together they are 69–81% of the guest.
- The s = 1,024 profiling twin lands at 102 segments against 101 for `aggr_ss`:
  its markers push it over a segment boundary.

### Query guest over n populated epochs

Each cell gives user cycles, segments and MODELED prove time.

Top-10 (`topk`: verification preamble, full merge, top 10 with keys):

| s | n=1 | n=4 | n=16 | n=64 (2^20 records) | cycles fit (R^2) |
|---|---|---|---|---|---|
| 16,384 | 46.1M, 48 seg, 1,445 s | 197.8M, 208, 6,261 s | 769.0M, 820, 24,682 s | 3,054M, 3,288, 98,969 s (27.5 h) | 47.67M n + 3.7M (0.99999) |
| 1,024 | 5.1M, 6 seg, 181 s | 22.1M, 23, 692 s | 92.9M, 98, 2,950 s | 378.8M, 405, 12,191 s (3.4 h) | 5.94M n − 1.5M (0.99999) |

Point frequency (`estimate`: verification preamble, their `SumExactKey` scan;
the rank-1 and rank-100 keys cost the same to within 1,500 cycles):

| s | n=1 | n=4 | n=16 | n=64 (2^20 records) | cycles fit (R^2) |
|---|---|---|---|---|---|
| 16,384 | 28.2M, 29 seg, 873 s | 116.7M, 118, 3,552 s | 453.2M, 456, 13,726 s | 1,829M, 1,838, 55,324 s (15.4 h) | 28.58M n − 0.4M (0.99999) |
| 1,024 | 3.5M, 4 seg, 120 s | 13.8M, 14, 421 s | 55.1M, 56, 1,686 s | 220.6M, 222, 6,682 s (1.9 h) | 3.45M n + 0.02M (1.00000) |

- **The first version answered point queries through the full merge**
  (now `estimate_merged`, kept as a sensitivity row). That costs the same
  segments as `topk` in every cell: 48 / 208 / 820 / 3,288 at s = 2^14 and
  6 / 23 / 98 / 405 at s = 1,024. (User cycles agree within 0.04%, except
  s = 1,024, n = 1, rank 100: the key is not in the merged summary, so the
  lookup scans all of it, +1.5%.) So those rows overstated this baseline's
  point-query cost by 1.5–1.8x in segments (1.79x at n = 64, s = 2^14). The
  top-k query needs the merge; a point query does not.
- Phase split (from `query_ss_prof`, stable across n):
  - `topk`: 50–58% reading the input, 6–7% recomputing state commitments,
    34–43% merging (concatenate, sort by key, aggregate, sort by count).
  - `estimate`: 86–87% reading the input, 10.5–10.6% recomputing state
    commitments, 2.7–2.8% the scan itself.
  - Epoch-link checks are about 1,500 cycles per epoch.
- Their `SumExactKey` is a linear scan, and so is the port's. A binary search
  over the key-sorted entries would save at most the 2.8% scan phase (the
  review's binary-search variant measured 442 and 1,784 segments at n = 16 / 64,
  s = 2^14, against 456 / 1,838 here).
- Stored state the query re-hashes (and, for `topk`, merges):
  - s = 2^14: 8,433 to 546,948 entries.
  - s = 1,024: 1,024 n entries.
- Query input sizes:
  - s = 2^14: 0.57 MB at n=1 and 37.2 MB at n=64.
  - s = 1,024: 4.5 MB at n=64.
- For scale, their shipped queries over the same epochs (`../results/zka_shipped_exec.csv`):
  - samples `SumTopk` (per-key state, like SpaceSaving at s = 2^14): 91 / 385 /
    1,538 / 6,356 segments at n = 1 / 4 / 16 / 64;
  - CM `Estimate` (a fixed 3×1,024 table per epoch): 2 / 5 / 20 / 77.
- Every query also needs the n per-epoch aggregation receipts, which are
  verified separately (as theirs), so the aggregation cost recurs once per epoch.

### Accuracy vs exact counts

The first four columns are the top-10 query; the last two are `estimate`.

| s | n | recall@10 | key order = exact | max abs (rel) count error | rank-1 point | rank-100 point |
|---|---|---|---|---|---|---|
| 16,384 | 1, 4, 16, 64 | 10/10 | yes | 0 | exact | exact |
| 1,024 | 1 | 10/10 | no | 10 (12.3%) | exact | no epoch monitors it → count 0 (exact 13), **suppressed** (support < 10) |
| 1,024 | 4 | 10/10 | no | 9 (3.4%) | exact | 50 (error 15) vs 41 |
| 1,024 | 16 | 10/10 | yes | 41 (4.9%) | exact | 162 (error 74) vs 134 |
| 1,024 | 64 | 10/10 | yes | 160 (5.9%) | 17,566 vs 17,564 | 511 (error 308) vs 489 |

- **s = 2^14 is exact on the top-10 and on both point keys at every n.** Per
  epoch, SS at 2^14 is an exact table on AOL.
- The merged top-k summary is truncated to 2^14 counters. At n=64 there are
  245,620 distinct keys, so tail keys are dropped, but the top-10 survive. The
  point query does not truncate.
- At s = 1,024, one merged top-10 count fell below the truth: n=4, key
  3630187757, 158 vs 160. The specified merge adds nothing for epochs in which a
  key was not monitored (see Caveats). Every top-10 item and every monitored
  point answer satisfies the bound count − error ≤ f ≤ count + slack
  (`in_[c-e c+slack]` in the CSV), where slack is the summed minimum counters of
  the full epochs that do not monitor the key.
- On these keys `estimate` and `estimate_merged` return the same answers,
  because every queried key that some epoch monitors survives the merge.

### Proved anchors (aggregation guest, 2,048 records) — `../results/zka_ss_anchor.csv`

`ss_anchor.sh` proves the aggregation guest on the first 2,048 AOL records
(1,234 distinct keys, s = 2^14) with `ProverOpts::succinct()`, their shipped
tier, on CPU with r0vm 3.0.6. Proved rows go only to `zka_ss_anchor.csv`, never
to the executor CSV. The proved journal equals the native output in every row.

`prove_condition` is set by the driver: once a second during the proof it
counts, read-only, the r0vm processes of any user that are not its own child.
One sighting makes the row `contended`. `prove_other_r0vm_samples` (sightings /
samples) and `prove_load1_mean` / `_max` carry the evidence. **Use only `clean`
rows.**

| guest (root) | condition | segments | prove_s | s/segment | verify | receipt | r0vm peak RSS | MODELED (30.1 s/seg) |
|---|---|---|---|---|---|---|---|---|
| **current `aggr_ss` (buckets64)** | **clean** (other r0vm 0/470 samples; load mean 48, max 61) | 16 | **473.4 s** | **29.59** | 10.2 ms | 224,818 B | 9,401 MB | 481.6 s |
| v1 `aggr_ss` (perkey) | clean (0/132 samples at 5 s; load mean 49, max 60) | 23 | 672.4 s | 29.23 | 11.5 ms | 224,818 B | 9,411 MB | 692.3 s |
| v1 `aggr_ss` (perkey) | **contended** (another job's prover ran 13 of 16 min; load averaged 101) | 23 | 958.8 s | 41.69 | 9.8 ms | 224,818 B | 9,400 MB | 692.3 s |

- The current guest's anchor is 1.7% below its MODELED time; at 29.59 s/segment
  it sits 0.5% under the low end of the CM-anchor envelope (29.73–30.79). The
  v1 guest's clean anchor gave 29.23 s/segment. Both support applying the
  segment model to these non-CM guests.
- The load on both clean runs is this prover itself (about 50 threads) plus
  another user's small job; no other r0vm ran.
- The two v1 rows were measured before the review fixes, on the v1 ELF (image
  ID `1e73f3f3…`). Their condition and load columns were filled from the notes
  in their log (the v1 driver had no per-second sampler); the raw log is at the
  top of `zka_ss_anchor.log`. The contended row is kept for the record and
  must not be used.
- It is one anchor per guest version on a shared box; the per-segment cost is
  not characterised beyond that. The query guest has no proved anchor; its
  MODELED times rest on the four CM anchors plus these aggregation anchors.

## What is reused from upstream (clone `d4a5a9a`, read-only)

Via path dependencies, unmodified:

- `aggregator_core::{BatchInput, EpochChainLink, batch_chain_hash, key_to_u64}`
- `aggregator_core::samples_buckets_root_from_leaves` (`aggregator/core/src/lib.rs:381-391`),
  which folds the bucket leaves of the headline root
- `aggregator_core::merkle::MerkleTree`: their SHA-256 Merkle wrapper over
  `merkle_light`, `aggregator/core/src/merkle.rs` (used by the per-key sensitivity root)
- `aggregator_core::{samples_bucket_index, SAMPLES_HT_BUCKETS}`, in a unit test only
- `querier_core::MIN_SUPPORT`
- `zkvm_common::{Event, Event::make_key_id, KEY_BYTES_LEN, HASH_BYTES_LEN}`

Copied verbatim, because they are private in their crates (each copy names its
source in a comment, and `diff` against the clone is empty):

| item | source |
|---|---|
| `verify_and_compute_chain` | `aggregator/core/src/lib.rs:523-603` |
| `events_commit` | `aggregator/core/src/lib.rs:297-305` |
| `chain_tips_to_sorted_vec` | `aggregator/core/src/lib.rs:332-339` |
| `next_pow2_ge` | `aggregator/core/src/lib.rs:82-91` |
| `sha256_bytes` | `aggregator/core/src/lib.rs:93-99` (identical to `querier/core/src/lib.rs:43-49`) |
| `TAG_SHARD_CHAIN` | `aggregator/core/src/lib.rs:57` |
| `verify_epoch_chain_integrity` | `querier/core/src/lib.rs:105-136` |
| `TAG_EPOCH_CHAIN` | `querier/core/src/lib.rs:41` |
| `samples_bucket_index` body, as `ss_bucket_index` | `aggregator/core/src/lib.rs:352-361`; only the mask is a parameter instead of `SAMPLES_HT_BUCKETS` (unit-tested equal to their pub function for 100,000 keys) |

Followed as patterns, with our types:

| pattern | their source |
|---|---|
| aggregation structure | `process_cm_aggr_with_state` (`aggregator/core/src/lib.rs:1215-1301`) |
| state commitment | `samples_epoch_state_commit` / `cm_epoch_state_commit` |
| Merkle root (headline) | `samples_buckets_leaves` / `samples_bucket_leaf_hash` / `samples_buckets_root` (`:363-422`) |
| Merkle root (per-key sensitivity variant) | `hist_per_key_root` (`:786-818`) |
| query verification preamble and output shape | `run_samples_query` (`querier/core/src/lib.rs:745-790`) |
| top-k merge | `SumTopk` (`:868-913`) |
| point query | `SumExactKey` (`:808-821`) |
| suppression | `suppress_if_low_support` (`:720-743`) |
| guest `main`s | `aggregator/methods/guest_cm`, `querier/methods/guest_samples` |

Their SHA-256 in the guest is risc0's accelerated `sha::rust_crypto`, and ours
is the same.

## Caveats

- **Cycle counts depend on the data.** Nothing is padded.
  - Aggregation cost depends on the hit/miss/eviction mix. On epoch 0,
    s = 1,024 updates cost 966 cycles per record vs 629 at 2^14.
  - It also depends on the number of monitored keys, through the sort, the
    Merkle root and the commitment.
  - Query cost scales with the stored entries: n · min(s, distinct keys per epoch).
  - Code generation moves cycle counts by about 1%. The headline root's leaf
    hash is written as a closure; the same code as a separate function (their
    layout) costs 1.3M more cycles per s = 2^14 epoch, and calling their pub
    `samples_bucket_index` across the crate boundary instead of the local copy
    costs 0.8M more. Together that is 115.8M cycles and 126 segments instead
    of 113.6M and 124, for the same work. The cheaper form is the headline.
  - Another stream, or another epoch of AOL, gives different counts. Cycle
    counts and segments are exact for these inputs only.
- **Nothing here was proved except the aggregation anchors.** Every other prove time is
  MODELED from the four CM-guest CPU anchors of `../README.md` (29.73–30.79
  s/segment, r0vm 3.0.6, `ProverOpts::succinct()`). The GPU prover was not used.
- **Merge semantics (top-k).** Summing only where a key is present, then
  truncating to s, is the specified merge. It is not Agarwal et al.'s MG /
  SpaceSaving merge (which subtracts the (s+1)-th merged counter) and its
  guarantee is looser. With N records in total, f a key's true frequency, and
  count / error its merged values:
  - count − error ≤ f always;
  - count − f ≤ error ≤ N/s;
  - for a retained key, f − count ≤ the summed minimum counters of the epochs
    that do not monitor it (≤ N/s), so a merged count can be *below* the truth;
  - a key dropped by the truncation has f ≤ C_{s+1} + N/s ≤ 2N/s, where
    C_{s+1} ≤ N/(s+1) is the (s+1)-th largest merged count.
  - A merged count is exact in the no-eviction regime (s = 2^14 on AOL).
  - Adding each full epoch's minimum counter for keys it does not monitor
    (Cafaro / Berinde style) would keep counts as upper bounds; the specified
    merge does not.
- **Point-query semantics.** `Estimate` sums over the epochs that monitor the
  key, with no truncation, so the same first three bounds hold for any key:
  count − error ≤ f ≤ count + slack, where slack is the summed minimum counters
  of the full epochs that do not monitor it. The accuracy column checks this
  bound (`in_[c-e c+slack]`) against exact counts. `monitored = false` means no
  epoch monitors the key, which for s = 2^14 on AOL means it never occurred.
- **Suppression.** A point query whose count is below `MIN_SUPPORT = 10`
  (including a key that is not monitored, count 0) triggers their suppression.
  The journal then says `suppressed = true` and carries no count.
- **The Merkle root is included, following their samples pattern, although no
  query uses it.** The sensitivity rows give the full range from no root to the
  per-key root.
- **Profiling twins.** `aggr_ss_prof` and `query_ss_prof` run the same ss-core
  code with host-reported `env::cycle_count()` markers, which the circuit does
  not constrain. They cost 5–35k cycles more than the measured guests, and
  their rows are labelled with `guest=*_prof`. Use the `aggr_ss` / `query_ss`
  rows for measurements. Phase percentages are of (last mark − first mark),
  the cycles between the guest's first and last `env::cycle_count()` call.
- **Sensitivity guest.** `aggr_ss_rootvar` reads its `SsRoot` before the input
  and commits `(root, journal)`, so its `buckets64` row costs 55 cycles more
  than `aggr_ss`. Its rows are labelled `guest=aggr_ss_rootvar`.
- **Semantics vs zkSketch.**
  - This is a zkVM running a plain algorithm; zkSketch's SS leaf is a custom AIR
    circuit. The comparison mostly measures zkVM vs AIR.
  - Their state commitments are unsalted hashes, and zero knowledge is the
    provider's concern in their model. This port inherits both.
  - The keys in our top-10 journal are real journal data. Their CM top-K keys are not.
- **RSS.** `r0vm_peak_rss_mb` is sampled by the driver from its own `r0vm` child
  every 200 ms. It is NaN when the run ends before the first sample.
  `../rss_watch.sh` is not used, because it pkill's every r0vm of the account on
  exit, which is unsafe while other jobs share the account.
- **Timing.** `exec_s` is wall-clock on a shared box and is not a metric.
