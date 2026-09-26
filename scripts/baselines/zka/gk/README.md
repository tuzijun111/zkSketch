# Greenwald-Khanna in zk-Analytics' architecture (†)

zk-Analytics (Zhu et al., SIGCOMM '26; clone at `d4a5a9a`) ships no quantile
summary with a rank guarantee. Its histogram keeps per-key log2 bins and answers
only P90 (see `../README.md`, "Shipped-structure arm"). This directory builds
**our** GK guests and runs them in **their** general-purpose pipeline, so the cost
is that of their method, not of zkSketch's circuit techniques. Call it "our GK
instantiation of zk-Analytics' per-epoch / query-time-merge architecture (†)",
never "zk-Analytics's GK".

Everything the guests do is ordinary RISC-V execution of plain Rust:

| step | aggregation guest `aggr_gk` (one run per epoch) | source |
|---|---|---|
| 1 | verify source 0's SHA-256 batch hash chain | their `verify_and_compute_chain`, copied verbatim |
| 2 | build the epoch's GK summary from scratch, one record at a time | textbook GK (below) |
| 3 | Merkle root over the tuples (`tuples_root`) | their `hist_per_key_root` pattern + their `MerkleTree` |
| 4 | unsalted SHA-256 state commitment | their `histogram_state_commit` pattern |
| 5 | link it into the epoch chain | their `EpochChainLink::new` |

| step | query guest `querier_gk` (one run per query) | source |
|---|---|---|
| 1 | re-verify every epoch chain link | their `verify_epoch_chain_integrity`, copied verbatim |
| 2 | recompute every epoch's state commitment | as `run_histogram_query` |
| 3 | merge the per-epoch summaries at query time | one-shot GK union (below) |
| 4 | answer, then apply the low-support rule | their `MIN_SUPPORT` / `suppress_if_low_support` shape |

There is no oblivious padding, no memory checking, no sorting certificate and no
Poseidon anywhere.

## Configuration

- **Summary.** GK with epsilon = 1/51. COMPRESS runs every floor(1/(2 eps)) = 25
  observations. Both are compile-time constants (`GK_EPS_DEN`,
  `GK_COMPRESS_EVERY`), bound by the image ID like their `HISTOGRAM_SLOTS`.
- **Records.** They are exactly those of the shipped arm's histogram rows:
  - Keys: `data/aol.keys`; epoch e is keys `[e*16384, (e+1)*16384)`.
  - `key_id`: `Event::make_key_id(0, key)`.
  - `value`: `key & 0x1FFFFF`. That is 21 bits, values in `[0, 2^21)`, the same
    as zkSketch's `gk_vals_of`. (The task text said "22-bit"; the mask is the
    authority.)
  - `ts`: the global record index.
  - Batching: one source, batches of 8. The batch chain, `source_batch_seq`,
    `prev_source_chain_tips` and the epoch chain carry across epochs.
- **GK summarises one global value stream.** The key only enters the batch hash
  chain. This is the setting of their `key_id=const` histogram steelman.
- **Queries.**
  - `rank(2^20)` = #{values <= 1,048,576}.
  - p50, p90, p99, with target rank r = ceil(phi N).
  - The answer, its certified bounds and N are all in the committed journal. No
    part of the answer is attached outside the proof.
- **Toolchain.**
  - Guest crates: risc0-zkvm 3.0.5. `guests/Cargo.lock` was seeded from the
    clone's `Cargo.lock`, and every third-party version is identical to it.
  - Host: risc0-zkvm 3.0.6. `Cargo.lock` was seeded from `../cyc/Cargo.lock`,
    again with identical third-party versions.
  - Executor: r0vm 3.0.6 over IPC.
  - Builds go to `~/ext-baselines/build/zka-gk` with `--locked` and
    `RISC0_BUILD_LOCKED=1`.

## GK as implemented (`core/src/lib.rs`)

This is Greenwald & Khanna (SIGMOD 2001), checked tuple for tuple against a
literal reproduction of the paper's pseudocode (test
`fast_compress_equals_paper_reference`). It departs from the paper's Figure 2
pseudocode in one place, to keep an invariant the paper's text states (below).

- **Tuples.** Each tuple is `(v, g, Delta)`; rmin(v_i) = sum_{j<=i} g_j and
  rmax = rmin + Delta.
- **Adding the (n+1)-st value.** If n = 0 mod 25, COMPRESS runs first. Then
  INSERT, then n += 1.
- **INSERT.** Binary search for the smallest i with v < v_i, then insert
  `(v, 1, floor(2 eps n))`, where n counts the values seen before this one. A
  new minimum (i = 0) or maximum (i = s) gets `(v, 1, 0)`.
- **COMPRESS.** For i = s-2 down to **1**: if `BAND(Delta_i) <= BAND(Delta_{i+1})`
  and `g*_i + g_{i+1} + Delta_{i+1} < 2 eps n`, delete t_i and all its
  descendants into t_{i+1}. t_0 is always kept.
  - `band_0 = {p}` and `band_a = {Delta : p - 2^a - (p mod 2^a) < Delta <= p - 2^(a-1) - (p mod 2^(a-1))}`,
    with p = floor(2 eps n).
  - Descendants: the parent of t_i is the nearest t_j to its right with a
    strictly larger band.
  - Implementation: one right-to-left pass, a monotone stack for the descendant
    blocks, prefix sums for g*. O(s) per call.
  - The tuple list is a `Vec`, so INSERT is a memmove.
- **Why the loop stops at i = 1.** The paper, section 2.1: "We ensure that, at
  all times, the maximum and the minimum values are part of the summary. In
  other words, v_0 and v_{s-1} always correspond to the minimum and the maximum
  elements seen so far." The j = 0 case of its Proposition 1 needs this. Its
  Figure 2 loop runs down to i = 0, which lets COMPRESS merge t_0 into t_1 when
  t_1 also has Delta = 0 (a former minimum).
  - The first build followed Figure 2. It lost the minimum in 60 of the 64 AOL
    epochs; epoch 0 stored t_0 = (12205, g=96, Delta=0) while the true minimum is
    203. The phi = 0 answer on single epochs then had actual rank error up to 637
    (epoch 45; epoch 2: 568), above eps n = 321.25. That build's rows are in
    `../results/zka_gk_exec_v1_before_fix.csv` and must not be used.
  - t_0 (Delta = 0) is in the top band, so it can never fall inside another
    tuple's descendant block. `compress()` asserts this on every call.
  - The test `min_and_max_kept_after_every_compress` checks t_0 = (running
    minimum, 1, 0) and t_(s-1) = running maximum after every observation of 7
    synthetic streams and all 64 AOL epochs.
- **The band special case holds without extra code.** The paper puts "the first
  1/2eps observations, with Delta = 0, in a band of their own". With the band
  formula above, Delta = 0 is the only member of the top band floor(log2 p) + 1
  whenever p >= 1. When p = 0 (n <= 25) nothing can merge, because
  g*_i + g_{i+1} + Delta_{i+1} >= 2 > 2 eps n. The test
  `band_delta0_is_alone_in_top_band` checks both.
- **The paper's Delta has an off-by-<1 slack.** INSERT's Delta = floor(2 eps n)
  can leave g + Delta = floor(2 eps n) + 1 > 2 eps n. The measured epochs have
  max g + Delta = 643 against 2 eps n = 642.5.
  - Per-epoch rank bounds [rmin(t_k), rmax(t_{k+1}) - 1] still have width
    g + Delta - 1 <= floor(2 eps n).
  - The slack costs at most 1/2 in the error bounds below.
- **Query-time merge.**
  - **Rank.** The union's bounds [L, U] are the sums of the per-epoch bounds, and
    the estimate is floor((L+U)/2). Its certified error ceil((U-L)/2) is at most
    ceil(sum_e floor(2 eps n_e) / 2) <= eps N + 1/2. On these data every
    floor(2 eps n_e) is 642, which is even, so it is <= eps N.
  - **Quantile.** The union summary is GK's COMBINE generalised to k summaries,
    under ONE total order of all N elements: (value, epoch index, position in
    the epoch). For a stored tuple (v, e, i) and each other epoch e':
    - e' < e: the elements of e' with value <= v precede it. Lower bound: rmin of the
      last e'-tuple with v' <= v. Upper bound: rmax of the first e'-tuple with
      v' > v, minus 1 (n_{e'} if none).
    - e' > e: the elements of e' with value < v precede it. Lower bound: rmin of the
      last e'-tuple with v' < v. Upper bound: rmax of the first e'-tuple with
      v' >= v, minus 1 (n_{e'} if none).
    - rmin_U = rmin_e(i) + the lower bounds; rmax_U = rmax_e(i) + the upper
      bounds. Over the tuples sorted by (v, e, i), "the e'-tuples before this
      one" are exactly those already swept, so one pointer per epoch suffices
      (O(total tuples) after the sort). A brute-force reference is compared in
      `combine_sweep_equals_bruteforce`.
  - The answer is the tuple minimising max(r - rmin_U, rmax_U - r), which is its
    certified error.
  - **Bound.** Consecutive union tuples are at most sum_e floor(2 eps n_e) + 1
    <= 2 eps N + 1 apart (rmax of the next minus rmin of this one). The first
    union tuple has rmax_U = 1 and the last has rmin_U = N, because every epoch
    keeps its minimum and maximum. So GK's Proposition 1 gives a certified error
    of at most eps N + 1/2. There is no recompression (Agarwal et al., one-shot
    merge).
  - **Measured.** On every row and in every 1,001-phi sweep (AOL and the
    adversarial splits), the certified error is <= eps N. Worst over phi = q/1000
    on AOL: 321, 1,240, 4,561 and 17,739 for n = 1, 4, 16 and 64, against eps N =
    321.25, 1,285, 5,140 and 20,560.
  - **Why the single total order matters.** The first build bounded each other
    epoch's contribution under any tie order (last v' < v, first v' > v). That is
    sound (the exact answer always lay inside the interval), but near a value
    stored in many epochs the per-epoch spans add up over every copy, and the
    certificate exceeded eps N. Examples: 16 epochs of one constant gave 61,440
    against eps N = 1,285; AOL n = 16 at phi = 0.366 gave 5,243 > 5,140; the
    reviewer's AOL sweeps reached 5,828 > 5,140 (n = 16) and 23,303 > 20,560
    (n = 64). With the lost minimum, AOL n = 4 at phi = 0 gave 1,337 > 1,285.
- **Tests.** `cargo test -p gk-zka-core` runs 12 tests. The AOL checks read
  `data/aol.keys`; `GK_AOL_KEYS` overrides the path and `GK_SKIP_AOL=1` skips
  them, printing SKIPPED.
  - `band_matches_paper_definition`: the band function against the paper's set
    definition, exhaustively for p < 5,000 and sampled at 2^16 +- 1 and 2^20.
  - `band_delta0_is_alone_in_top_band`: the band special case (above).
  - `gk_single_epoch_uniform_and_skewed`: invariants, t_0 = (min, 1, 0),
    t_(s-1) = (max, _, 0), rank containment, and the six named quantiles, on
    uniform, skewed, sorted, reverse-sorted and short streams.
  - `min_and_max_kept_after_every_compress`: see above; 47,784 COMPRESS calls.
  - `fast_compress_equals_paper_reference`: the O(s) COMPRESS equals the literal
    pseudocode (with the keep-minimum rule) on 7 synthetic streams and AOL epochs
    0, 2 and 63.
  - `invariants_during_stream`: the per-epoch checks at every 1,009th step.
  - `single_epoch_all_phis_random_streams`: 300 random streams (uniform,
    stride-permuted, descending), phi in {0, 1/1000, 1/100, 1/2, 99/100, 1}.
  - `combine_sweep_equals_bruteforce`: the sweep equals the per-tuple reference;
    rmin_U is monotone; the first union tuple has rmax_U = 1 and the last has
    rmin_U = N.
  - `union_rank_and_quantiles_within_eps_n`: synthetic unions of 1 to 16 epochs,
    1,001 phis, plus rank checks.
  - `union_phi_sweep_aol`: 1,001 phis over AOL unions of n = 1, 4, 16 and 64.
  - `union_phi_sweep_adversarial`: 1,001 phis over disjoint epochs, 16 constant
    epochs, 3-value ties, sorted/reverse mixes of different sizes, 40 tiny
    epochs, a skewed mix, one heavy value shared by 64 epochs, and 60
    one-record epochs.
  - `commit_changes_with_state`: the commitment and the root depend on the state.
  - Every quantile check asserts that the exact answer lies inside
    [rmin_U, rmax_U], and that actual error <= certified error <= eps N.
  - **Mutation check.** Put back into a scratch copy, the old COMPRESS fails 8 of
    the 12 tests, and the old COMBINE fails 3.

## Running

```bash
cd scripts/baselines/zka/gk
./gk_exec.sh                  # executor sweep: aggr + profile + data-dependence + queries n in {1,4,16,64}
./gk_prove_anchor.sh          # ONE proved anchor, aggr_gk at 2048 records; refuses if 1-min load > 24
CARGO_TARGET_DIR=~/ext-baselines/build/zka-gk cargo test --release --locked -p gk-zka-core
```

- **Output.** Both scripts append to `../results/zka_gk_exec.csv`. The header is
  written once, and a file with a different header is refused. They also append
  to the raw `../results/zka_gk_exec.log`, which records the load, the zka
  commit, r0vm, the key md5, the source md5 and the ELF md5s.
  - A run whose journal differs from the native output, or that fails an
    accuracy check, exits 1. Its row goes to the log, marked `[FAIL]`, and never
    to the CSV.
  - `../results/zka_gk_exec_v1_before_fix.{csv,log}` hold the first build's rows
    (both defects above). They are kept for provenance only.
- **Accuracy columns.** These are NATIVE checks of the same summaries the guest
  commits to; they are not guest work.
  - `abs_err`, `cert_err`, `exact_in_cert`: the row's own answer. On aggr rows,
    they cover the rank bounds over every distinct value of the epoch.
  - `cert_over_eps_n`: the row's certified error divided by eps N.
  - `min_kept`: t_0 and t_(s-1) are the minimum and maximum of every covered
    epoch.
  - `q_named` (aggr rows): the epoch's quantile at phi in {0, 1/1000, 1/100, 1/2,
    99/100, 1}, as actual/certified error pairs.
  - `q_sweep_1001`: worst actual error, worst certified error and worst
    certified/eps N over phi = q/1000, q = 0..1000, for the epoch (aggr rows) or
    the union (query rows).
  - `q_ok`: every named and swept phi has the exact answer inside the certified
    interval and actual <= certified <= eps N.
- **`contention` (proved rows).** The driver samples `/proc` every 250 ms for
  `r0vm` processes that are not its own descendants, from any user or agent. It
  records how many it saw, their CPU seconds during the prove, and the maximum
  1-minute load. If those processes burned at least 10 CPU seconds, the driver
  writes `arm=proved_contended` itself; nothing is relabelled by hand.
- **Environment variables.**
  - `SKIP_BUILD=1` skips the build.
  - `DD_EPOCHS="1 16 63"` sets the extra aggregation epochs.
  - `KEYS`, `OUT` and `MAX_LOAD` override their defaults.
- **Driver.** Its usage is in the header comment of `host/src/main.rs`.
  The driver refuses to run when `RISC0_DEV_MODE` is set.
- **The driver signals nothing.** Peak RSS comes from reading `/proc/*/status`
  VmHWM of the driver's own descendant processes. `../rss_watch.sh` is not used:
  it `pkill`s every r0vm of this account, which on this box may belong to
  another run.

## Results (executor, `../results/zka_gk_exec.csv`)

All rows below are from the fixed build: `aggr_gk` ELF `d0f88f7b...`,
`querier_gk` ELF `d7f473a8...` (md5s in the log). The exec sweep ran with gk
sources `5bf6a50f2b80`. The final sources `d0142d1c717e` differ only in the
driver's `proved_contended` rule, and they reproduce every exec row byte for
byte except `exec_s`; the anchor ran with them.

`MODELED` means segments x 30.1 s/segment, the CPU CM anchors of `../README.md`,
with an envelope of 29.73 to 30.79 s. It is a model, not a measurement.

### Aggregation guest `aggr_gk`, one 16,384-record epoch

| epoch | tuples | user cycles | cycles/rec | segments | padded cycles | MODELED prove |
|---|---|---|---|---|---|---|
| 0 (matched epoch) | 55 | 103,407,361 | 6,311 | 107 | 111,673,344 | 3,221 s |
| 1 | 52 | 103,106,294 | 6,293 | 106 | 111,149,056 | 3,191 s |
| 16 | 52 | 102,732,809 | 6,270 | 106 | 111,149,056 | 3,191 s |
| 63 | 52 | 102,098,098 | 6,232 | 105 | 110,100,480 | 3,161 s |

- journal == native on every row. The fix moved the cycle counts by about
  +0.12% and the segment counts not at all. Each summary now keeps its minimum,
  one tuple more.
- **Rank accuracy.** Across the four epochs, max |midpoint - exact rank| over
  every distinct value of the epoch is 321, and so is the certified half-width.
  eps n is 321.25, and every exact rank lies inside its bounds.
- **Quantile accuracy per epoch** (`q_named`, actual/certified):

  | epoch | phi=0 | 1/1000 | 1/100 | 1/2 | 99/100 | 1 | 1,001-phi worst cert |
  |---|---|---|---|---|---|---|---|
  | 0 | 0/0 | 16/16 | 68/68 | 241/241 | 161/163 | 0/0 | 321 |
  | 1 | 0/0 | 16/16 | 51/51 | 124/124 | 33/36 | 0/0 | 312 |
  | 16 | 0/0 | 16/16 | 78/80 | 35/48 | 160/162 | 0/0 | 314 |
  | 63 | 0/0 | 16/16 | 163/163 | 63/79 | 163/163 | 0/0 | 319 |

  All are within eps n = 321.25, and `min_kept` is true on every row.

For reference, their shipped guests on the same epoch 0 records:
- `aggr_histogram`, key_id=const: 86.5M cycles, 89 segments;
- `aggr_histogram`, per-key: 272.8M cycles, 318 segments;
- `aggr_cm`, T=1: 100.4M cycles, 104 segments.

**Where the cycles go.** The profiling guest `aggr_gk_prof` runs the same code
with cycle-counter reads at phase marks. Epoch 0, 103.99M total:

| phase | cycles | share |
|---|---|---|
| `env::read` of the 1.41 MB input (risc0 serde: every `u8` of a key id is a word) | 60,792,980 | 58.5% |
| batch hash-chain verification (their code; hashes each batch twice) | 17,836,327 | 17.2% |
| GK INSERT (16,384 calls) | 12,582,113 | 12.1% |
| GK COMPRESS (656 calls) | 11,888,207 | 11.4% |
| flatten batches, Merkle root, state commit, epoch link, start-up, commit | about 0.9M | 0.9% |

The summary update is about 24.5M cycles (about 1,494 per record). The other
79M is their pipeline: the input format and chain check are identical for any
summary type, and dominate the cost.

### Query guest `querier_gk` over n populated epochs (one guest run per query)

| query | n=1 | n=4 | n=16 | n=64 (2^20 records) | cycles fit (R^2) |
|---|---|---|---|---|---|
| rank(2^20) | 78,723 / 1 seg | 272,027 / 1 | 1,075,954 / 2 | 4,208,405 / 5 (150 s MODELED) | 65,544 n + 15,958 (0.99998) |
| p50 | 92,589 / 1 | 344,457 / 1 | 1,398,080 / 2 | 5,565,627 / 6 (181 s) | 86,928 n + 2,976 (0.999997) |
| p90 | 92,771 / 1 | 344,908 / 1 | 1,399,910 / 2 | 5,572,368 / 6 (181 s) | 87,032 n + 3,062 (0.999997) |
| p99 | 92,789 / 1 | 344,999 / 1 | 1,400,279 / 2 | 5,573,939 / 6 (181 s) | 87,057 n + 3,049 (0.999997) |

- The total-order COMBINE is a simpler sweep than the first build's: quantile
  queries are about 3% cheaper at n = 64. Rank queries are about 1% dearer
  because each state has one more tuple to hash. Segment counts are unchanged.
- **Accuracy.** Each cell reads actual error / certified error (certified/eps N).
  - n=64 (eps N = 20,560): rank 342 / 15,940 (0.78); p50 159 / 16,257 (0.79);
    p90 922 / 15,235 (0.74); p99 7,600 / 10,389 (0.51).
  - Worst certified error over the 1,001-phi sweep of the same union: 321
    (0.999), 1,240 (0.965), 4,561 (0.887) and 17,739 (0.863 of eps N) for
    n = 1, 4, 16 and 64.
  - Every row, n in {1, 4, 16, 64}, passes: journal == native, actual error <=
    eps N, certified error <= eps N, the exact answer inside the certified
    interval, `min_kept`, and `q_ok` over the 1,001-phi sweep.
- **State size.** The stored state averages about 54 tuples per epoch (3,464
  tuples over 64 epochs, 66.9 KB of query input at n=64). Their per-key
  histogram's query input is 109 MB at n=64.

## Proved anchor (`aggr_gk`, first 2,048 AOL records, `ProverOpts::succinct()`, CPU r0vm 3.0.6)

| run | prove_s | segments | s/segment | total / user / paging / reserved cycles | receipt | verify | r0vm peak RSS | journal == native |
|---|---|---|---|---|---|---|---|---|
| **16:54, the anchor, fixed build** (`arm=proved`, `contention=none`) | **414.5** | 14 | **29.61** | 14,680,064 / 13,405,908 / 697,089 / 577,067 | 224,810 B | 11.6 ms | 9,389.3 MB | yes (asserted on the proved journal) |

- **Conditions.**
  - Launched at 1-minute load 1.75 with no `r0vm` running.
  - The driver's `/proc` sampler saw no foreign `r0vm` in 1,607 samples. The
    maximum 1-minute load was 56.7, about one 64-thread prover's worth.
  - One overlap is not an `r0vm`, so the sampler cannot see it: in the first
    minute I ran a short `nice -n 19` incremental build and run of this crate's
    native tests. It was a single-crate rebuild; its effect on `prove_s` is small
    but not zero.
- **Model check.**
  - 29.61 s/segment is 0.4% below the lower edge of the CM-anchor envelope
    (29.73 to 30.79 s), and 1.6% below the 30.1 s used for MODELED.
  - The executor model at this size is 14 segments = 421.4 s (416.2 to
    431.1 s). The measured 414.5 s is 1.6% below 421.4.
- **Other results.**
  - The proved journal equals the native output. The row also passes every
    accuracy check: rank 40/40 against eps n = 40.16, `min_kept`, and `q_ok`
    with a worst swept certificate of 39.
  - Total cycles equal padded cycles (14 x 2^20). Of these, 1.27M are paging
    and reserved cycles, which the executor's user count omits.
  - Peak RSS is the VmHWM of the prover `r0vm` (a child of the driver), sampled
    every 250 ms. The driver itself peaks at 14 MB.
- **Earlier anchors, on the pre-fix ELF.** These are in
  `../results/zka_gk_exec_v1_before_fix.{csv,log}`, ELF `e34f62c6...`, with
  13,398,092 user cycles and 14 segments.
  - 16:19: 432.0 s (30.86 s/segment). The SS family's prover overlapped its first
    ~40 s, so the clean time was bracketed at [392, 432] s.
  - 16:01: 766.9 s. It ran fully contended; its `proved_contended` label was
    typed by hand, which is disclosed in that log.
  - 16:00: stopped after 6 s.
  - They agree with the fixed-build anchor on segments (14), receipt size and
    RSS. The fixed build only adds one tuple and a bounded loop.

## What is reused from upstream (`d4a5a9a`)

**Imported as library items (path dependencies through `../.zka`):**
- `aggregator_core::{batch_chain_hash, BatchInput, EpochChainLink, merkle::MerkleTree}`;
- `zkvm_common::{Event, HASH_BYTES_LEN}` and `Event::make_key_id`;
- `querier_core::MIN_SUPPORT`.

**Copied verbatim, because they are private upstream.** The bodies were checked
byte-identical with `diff` against the clone.

| copied item | upstream location |
|---|---|
| `verify_and_compute_chain` | `aggregator/core/src/lib.rs:499-603` |
| `events_commit` | `aggregator/core/src/lib.rs:295-305` |
| `chain_tips_to_sorted_vec` | `aggregator/core/src/lib.rs:331-339` |
| `next_pow2_ge` | `aggregator/core/src/lib.rs:82-91` |
| `sha256_bytes` | `aggregator/core/src/lib.rs:93-99` |
| `TAG_SHARD_CHAIN` | `aggregator/core/src/lib.rs:57` |
| `verify_epoch_chain_integrity` | `querier/core/src/lib.rs:98-136` |
| `TAG_EPOCH_CHAIN` | `querier/core/src/lib.rs:41` |

**Mirrored in structure, with GK fields:**

| item here | modelled on |
|---|---|
| `process_gk_aggr_with_state` | `process_histogram_aggr_with_state`, `:851-943` |
| `GkAggrInput` / `GkAggrOutput` | `HistogramAggrInput` / `HistogramAggrOutput`, `:687-762` |
| `gk_epoch_state_commit` | `histogram_state_commit`, `:830-849` |
| `gk_tuples_root` | `hist_per_key_root`, `:786-818` |
| leaf hash | `cm_heap_leaf_hash`, `:1143-1151` |
| `run_gk_query` | `run_histogram_query`, `querier/core/src/lib.rs:482-643` |
| `GkQueryOutput` and its `suppress_if_low_support` | `HistogramQueryOutput`, `:424-480` |
| guest `main`s and Cargo manifests | `guest_histogram` (aggregator and querier) |
| methods crate | `aggregator/methods` |

## Caveats

- **The cycle count is data-dependent.** GK INSERT's memmove length and
  COMPRESS's work depend on the summary size, which depends on the values. The
  four measured epochs span 102.10M to 103.41M cycles (105 to 107 segments).
  Other data, or another epsilon, will move the GK share (currently 24%).
- **MODELED is a model.**
  - All four s/segment anchors are CM guests.
  - GK has one proved anchor on the fixed build, at 2,048 records: 29.61
    s/segment, which agrees with the model (see above). The 16,384-record rows
    remain extrapolations.
  - `exec_s` is wall-clock on a shared box and is not a metric.
- **The receipts are separate.** A query also needs the n per-epoch aggregation
  receipts, verified separately; there is no `env::verify` in their design. The
  aggregation cost therefore recurs once per epoch.
- **Commitments are unsalted SHA-256, as in their code.** Their paper's (A4)
  assumes a hiding `Commit(state; r)` with fresh randomness. The code, and
  therefore this port, has none.
- **`tuples_root` follows their per-type journal pattern.** Every upstream
  aggregation journal has such a root. No query guest reads it, and it costs
  0.24M cycles (0.2%).
- **One query per guest run (per proof), as their query guests do.** The chain
  and commitment re-verification is therefore paid again by each of the four
  queries.
- **Sources of the GK algorithm.** The original paper's Delta = floor(2 eps n)
  is used. Some lecture-note versions use floor(2 eps n) - 1 with n counting the
  new value, which closes the <1 slack noted above. The difference in cost is
  negligible. The one departure from the paper's Figure 2 (COMPRESS stops at
  i = 1) follows the paper's own stated invariant; see "GK as implemented".
- **Profiling guest.** `aggr_gk_prof` is a separate ELF, and its counter reads
  are syscalls: 103.99M cycles versus 103.41M for `aggr_gk`. Only the split is
  read from it. It is never proved and never used as a cost row.
- **Semantics versus their histogram.** Their P90 is not a rank quantile: it
  returns 2^(b-1) for the crossing log2 bin, 524,288 on these data. GK answers
  any phi with a certified rank error of at most eps N + 1/2 (the 1/2 is the
  paper's INSERT slack). On every measured row and 1,001-phi sweep it was at
  most eps N. The two are not equivalent summaries.
