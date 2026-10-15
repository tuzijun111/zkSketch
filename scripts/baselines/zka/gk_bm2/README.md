# zkSketch's GK band-merge transition in a RISC Zero guest (`gk_bm2`)

`../gk` runs textbook Greenwald-Khanna (per-record INSERT / COMPRESS, a k-way
COMBINE at query time) inside zk-Analytics' pipeline. That is not the function
zkSketch's GK circuit certifies, so its cycle counts cannot be set against a
zkSketch GK leaf as "the same work". This directory executes **exactly
zkSketch's batch transition** in a RISC Zero guest instead:

    S_t = apply_batch2(S_{t-1}, gk_vals_of(batch_t))

with `apply_batch2` from `src/sketch/gk_bandmerge.rs:1426` and `gk_vals_of` from
`src/experiments/stream_compose.rs:550`, at the deployed configuration
`GkbParams { capacity: 2048, batch: 16384, s: 51 }`. It measures executor cycles
only; nothing is proved. `../gk` is unchanged and stays the
zk-Analytics-architecture baseline.

Nothing here is zk-Analytics code or architecture: there are no `Event` batches,
no batch hash chain and no epoch chain link. Cite it as "zkSketch's GK batch
transition executed in RISC Zero (general-purpose zkVM baseline, ours)", not as a
zk-Analytics result.

## Statement and guest

One guest run per epoch (`guests/step`, ELF `gk_bm2_step`):

| step | what | cost probe |
|---|---|---|
| 1 | read the old state's words and the epoch's `m` raw u32 keys (`env::read_slice`, no serde) | `cyc_read` |
| 2 | `Com_old` = SHA-256 of the old state, `Com_batch` = SHA-256 of the raw keys | `cyc_commit_in` |
| 3 | decode the state; map the keys with `gk_vals_of` (drop `PAD_KEY` slots, mask to 21 bits) | `cyc_decode_map` |
| 4 | the transition (one of four implementations, below) | `cyc_union`, `cyc_neighbor_init`, `cyc_rounds`, `cyc_compact` |
| 5 | `Com_new` = SHA-256 of the new state | `cyc_commit_out` |
| 6 | journal = `Com_old ‖ Com_batch ‖ Com_new` (96 raw bytes, `env::commit_slice`) | `cyc_journal` |

- **Commitments.** Unsalted SHA-256 through risc0's accelerated
  `sha::rust_crypto`, as in the other zka guests.
  - `Com(S) = SHA-256("ZKSK_GK_BM2_STATE_V1" ‖ words(S))`. `words(S)` is the
    little-endian u32 encoding of `(capacity, batch, s, n, #tuples)` followed by
    every tuple `(e, g, g°, Δ, Δ°, t, active)`, with u64 fields as (lo, hi) words.
  - So the parameters, `n` and all `capacity` rows, dummies included, are bound.
  - `Com(batch) = SHA-256("ZKSK_GK_BM2_BATCH_V1" ‖ u32 m ‖ the m raw keys)`. It
    is taken over the wire batch, `PAD_KEY` slots included, before the mapping.
- **Chaining.** Epoch t's `Com_new` is epoch t+1's `Com_old`. The guest does not
  link journals itself, just as a zkSketch leaf exposes its boundary commitments
  for the composition to link.
- **Probes.** `env::cycle_count()` readings are cumulative user cycles: in r0vm
  3.0.6 the syscall returns the session's user-cycle counter, the counter
  `session.cycles()` sums. The guest writes them to its private stdout, not to
  the journal. With `--emit-state` (always on in `--mode check`) it also writes
  the new state's words there. That costs 71 user cycles on every variant (AOL
  epoch 0, `literal`: check row 82,065,307 vs exec row 82,065,236) and no
  segment.
- **Statement vs zkSketch's leaf.** The function is the same. The hashes differ:
  zkSketch's leaf commits with Poseidon2 over BabyBear, hashing the tuples
  (`commit_gk2_state`) and the batch's fresh tuples (`commit_gk2_batch`). Here
  SHA-256 covers the full state encoding and the raw keys. The zkVM statement
  has no counterpart to zkSketch's in-circuit sort certificates, θ binding or
  range checks, because the guest re-executes the code and the image ID binds
  the code.

## The transition as ported (`core/src/lib.rs`)

`Tuple`, `Params` and `State` mirror `Gk2Tuple`, `GkbParams` and `Gk2State`
field for field and width for width. Four implementations compute one function;
the guest picks one by an input word (`variant`):

- **`literal`** (`apply_batch2`) is zkSketch's code statement for statement:
  - `combined` = old tuples ++ one fresh singleton per value (`g = g° = Δ = Δ° = 0`,
    `t = n_prev + 1 + j`), padded with `(E_MAX, 0, 0, 0, 0, 0, inactive)`
    dummies to `capacity + m` rows;
  - a stable `sort_by_key((e, t))` of an index permutation, then a gather;
  - two-sided neighbour init (`Δ` right to left, `Δ°` left to right, fresh rows
    only);
  - θ = ⌊N_t / s⌋ and `L_f = ceil(log2(capacity + m))` = 15 rounds at the
    deployed shape;
  - each round is the parity-0 fuse (`fuse_round_fixed2`) over every row, then a
    stable re-sort by `(e, t)`, with fresh tables allocated every round;
  - the result is the first `capacity` rows, and `n = N_t`.
  - Left out: only the circuit-witness captures that zkSketch retains (per-round
    `fused`, a clone of `resorted`, `sigma`, direction and condition vectors,
    `union_raw`, `union_init`, `expand_sigma`, `excess`). None feeds the output.
  - zkSketch checked the excess only by `debug_assert!`, which its release
    builds compile out, so a capacity overflow truncated silently in both.
    Since M3 (2026-10-16) zkSketch's `apply_batch2` refuses an overflow (a
    hard error); the guest still truncates as before (unchanged image), and
    the host compares an overflowing step with `try_apply_batch2`'s
    `lossy_state`, the pre-M3 output row for row. Deployed shapes never
    overflow (the host's check mode reports it).
- **`literal_reuse`** (`apply_batch2_reuse`) is the same statements and sorts
  with the per-round tables allocated once. risc0's default guest allocator is a
  bump allocator that never frees, so `literal` allocates and zero-fills about
  28 MB of fresh tables over its 15 rounds. This variant removes that cost.
- **`fixed_linear`** (`apply_batch2_fixed`) keeps zkSketch's fixed schedule and
  drops the literal port's other implementation costs.
  - Kept: the materialised `capacity + m` table, the neighbour init over every
    row, all `L_f` rounds whatever the data, every pair `(2i, 2i+1)` visited
    under `fuse_round_fixed2`'s rule, every row rewritten every round, and the
    odd table's never-paired last row.
  - Changed: the union is `fast`'s radix sort and merge, padded with dummies
    (linear, where `literal` comparison-sorts all 18,432 rows). Each round fuses
    and compacts the survivors in place in one table allocated once, where
    `literal` writes a fresh `fused` table and stable-sorts it by `(e, t)`.
  - On a canonical old state the compaction is that stable sort. Every row is
    either an active below `E_MAX` or the exact dummy, the actives form a prefix
    in increasing `(e, t)`, and a fuse only turns actives into dummies while a
    survivor keeps its own `(e, t)`. So, like `fast`, it refuses (panics on) a
    non-canonical old state.
  - The rows and rounds it visits are fixed; the work per pair still branches
    on the data (a dummy or kept pair costs less than a merge), as in `literal`.
    Its cycle count is therefore not data-independent.
  - It is one implementation of the fixed schedule, in place with one table. A
    different one (for example two tables, or a branch-free pair rule) would
    land elsewhere.
- **`fast`** (`apply_batch2_fast`) produces the same output on a data-dependent
  schedule. A zkVM may use one; zkSketch's circuit cannot.
  - The fresh values are sorted by a stable two-digit LSD radix sort on 11-bit
    digits, then merged into the already-sorted old actives.
  - Rounds run over the active prefix only, and compaction takes the place of
    the re-sort. zkSketch's re-sort only moves merge-induced dummies to the back.
  - It stops after the first round that changes nothing; every later round is
    then the identity.
  - It refuses (panics on) an old state that is not in `apply_batch2`'s canonical
    form, the only domain where these shortcuts could diverge. A chain that
    starts from `State::empty` never leaves that form.
- **Odd tables.** For an odd `capacity + m`, zkSketch never pairs the last row
  and the round turns it into a dummy, which drops an active tuple when the
  table is full. All four variants reproduce this; the guest check runs two
  odd, full chains, and the unit tests cover odd shapes.

## Configuration

- **Parameters.** `capacity = 2048`, `m = 16384`, `s = 51` (eps = 1/51).
  - `s = 51` is `exp_compose`'s `derive_gk_s(2048, 2^20)`.
  - θ = ⌊N_t / 51⌋: 321 at epoch 0, 20,560 at epoch 63.
- **Records.** They come exactly as zkSketch's `exp_compose` harness batches
  them. The host path-depends on the zkSketch crate and calls its own loaders
  and mappings.
  - `aol`: `data/aol.keys` (md5 `01dd7d5c8a73`).
  - `uniform`: `zksketch::dataset::synthetic_stream(Uniform, N, seed 1)`, which
    is `load_base("uniform")` in `exp_compose`, `exp_e1` and `exp_stream`. The
    generator is prefix-consistent in `N`. This is not `data/uniform.keys`,
    which is the seed-2, 200k-key frozen copy.
  - Batching: epoch e = `base[e*m .. (e+1)*m]` (`exp_compose`'s `batches_from`).
    `--query-every Q` uses zkSketch's `build_query_schedule_batches` instead.
    That is the mixed-workload batcher: early-sealed batches padded with
    `PAD_KEY`.
  - Mapping: `gk_vals_of`, run inside the guest on the raw keys.
  - Epoch 63: the host chains zkSketch's native `apply_batch2` over epochs
    0..62 and executes only epoch 63 (old state: 46 actives, n = 1,032,192).
- **Toolchain.**
  - Guest: risc0-zkvm **3.0.5**. `guests/Cargo.lock` was seeded from
    `../gk/guests/Cargo.lock`, itself seeded from the zk-Analytics clone, and
    no third-party version changed (only the two local crates were added).
  - Host: risc0-zkvm **3.0.6**. `Cargo.lock` was seeded from `../gk/Cargo.lock`
    and then resolved the zkSketch crate's dependencies.
  - Executor: r0vm **3.0.6** over IPC (`default_executor()`).
  - Builds go to `~/ext-baselines/build/zka-gk-bm2` with `--locked` and
    `RISC0_BUILD_LOCKED=1`.
  - The ELF md5 and image ID are in each log header and in the `image_id`
    column. As with the other guests, both depend on the absolute source path;
    the cycle counts do not.

## Running

```bash
scripts/baselines/zka/gk_bm2/gk_bm2_exec.sh                     # build, equivalence check, measurement
CHECK=0 SKIP_BUILD=1 scripts/baselines/zka/gk_bm2/gk_bm2_exec.sh  # measurement rows only
# native port-vs-zkSketch unit tests (no zkVM); --release is required
cd scripts/baselines/zka/gk_bm2 && CARGO_TARGET_DIR=~/ext-baselines/build/zka-gk-bm2 \
  RISC0_BUILD_LOCKED=1 cargo test --release --locked -p gk-bm2-host
# single invocations
B=~/ext-baselines/build/zka-gk-bm2/release/gk_bm2
$B --mode exec  --dataset aol --epoch-index 63 [--variant fixed_linear,fast] [--emit-state]
$B --mode check --dataset uniform --epochs 4 [--capacity 64] [--s 6 --epoch-size 4096] [--query-every 10000]
```

- **Outputs.** The runner writes `../results/zka_gk_bm2_check.csv` (236 rows)
  and `../results/zka_gk_bm2_exec.csv` (12 rows), and appends the raw console
  record to the matching `.log`.
  - Each log header records the load, r0vm, the zkSketch commit, md5s of the
    key file, of zkSketch's reference sources (`gk_bandmerge.rs`,
    `stream_compose.rs`, `dataset.rs`) and of this directory's sources, and the
    ELF md5.
  - It also records `dirty_excl_results`, the checkout's `git status` line
    count without the harness's results directories, so the runner's own
    CSVs and logs do not change it. The md5s are what pin the rows.
  - The first version of this arm (three variants, ELF `2eca39a3`) is kept as
    `../results/zka_gk_bm2_exec_v1_3variants.csv` and
    `../results/zka_gk_bm2_check_v1_3variants.csv`; its raw record is the first
    block of each `.log`, whose header still has the older `dirty=[N]` field.
  - A CSV is built in `<name>.csv.tmp` and replaces `<name>.csv` only when
    every run of its phase passed; the previous CSV is kept as `.csv.prev`
    (gitignored).
  - A failed check exits 1. Its rows stay in the log, marked `[FAIL]`, and the
    measurement does not run.
- **Run time.** The whole runner took 4.5 minutes with a cached build, on a
  box at load 66: each deployed `literal` execution takes about 3-5 s,
  `fixed_linear` about 1 s and `fast` 0.25 s. The runner signals no process;
  each executor run starts and reaps its own r0vm.
- `RISC0_DEV_MODE` is refused, and there is no `--prove`.

## Equivalence check (`zka_gk_bm2_check.csv`)

Every epoch of every chain is executed in the guest with the new state emitted.
The driver then compares, tuple by tuple, the 7 fields of all `capacity` rows,
plus `n` and the parameters, with zkSketch's native `apply_batch2` on the same
input. It also checks:

- the journal against host-computed commitments of zkSketch's states and the
  raw batch;
- the guest's merge census against the native one;
- each of the four ports, re-run natively, against zkSketch, with an equal
  census.

The census is the number of direction-1 (left folds into right) and
direction-2 (right folds into left) fusions, summed over the rounds.

The state is carried natively from epoch to epoch. Any mismatch prints
`MISMATCH` and exits 1.

| chain (capacity, s, m) | epochs | actives after each epoch | merges dir-1 / dir-2 (all epochs) | what it exercises |
|---|---|---|---|---|
| deployed (2048, 51, 16384), aol | 4 | 51, 49, 46, 47 | 22,170 / 43,319 | the measured shape |
| deployed, uniform | 4 | 56, 52, 48, 49 | 32,746 / 32,741 | the measured shape |
| deployed, aol, query every 10,000 positions over 4 x 16,384 | 7 batches | 50, 53, 49, 49, 49, 48, 50 | 22,593 / 42,887 | 49,158 `PAD_KEY` slots (the sentinel path) |
| (64, 51, 16384), aol | 8 | 46 to 51 | 43,492 / 87,531 | 72-88% occupancy |
| (64, 51, 16384), uniform | 8 | 48 to 56 | 65,524 / 65,499 | 72-88% occupancy |
| (48, 51, 16384), aol | 4 | 48, 47, 45, 46 | 22,141 / 43,346 | overflow: silent truncation (`mass_eq_n=false`) |
| (256, 6, 4096), aol | 8 | 6, 7, 5, 5, 5, 5, 5, 5 | 11,812 / 20,951 | another θ regime: θ 682 to 5,461, `L_f` = 13 |
| (256, 6, 4096), uniform | 8 | 6, then 7 | 16,427 / 16,334 | another θ regime |
| (8, 51, 4095), aol | 4 | 8, 8, 8, 8 | 5,637 / 10,615 | odd table (4,103 rows), full from epoch 1: the never-paired last row is dropped (overflow, `mass_eq_n=false`) |
| (8, 51, 4095), uniform | 4 | 8, 8, 8, 8 | 8,118 / 8,145 | odd and full, as above |

- **236 rows** (59 epochs x 4 variants), each with `journal_eq_native`,
  `state_eq_native`, `merges_eq_native` and `port_eq_native` all `true`.
- **Capacity 64 repeats the deployed fusions.** Capacity enters the fusion
  schedule only through `L_f = ceil(log2(capacity + m))`, the table's parity
  and whether the table is full; θ = ⌊N_t / s⌋ does not depend on it, and
  dummies never fuse.
  - At m = 16,384, `L_f` is 15 for both 64 and 2048, both tables are even, and
    neither fills. So epochs 0-3 of the capacity-64 chains have the deployed
    chains' actives and per-epoch merge counts. The states differ only in the
    final slice (fewer trailing dummies).
  - The chain checks the guest near full occupancy. At `s = 51` the band-merge
    keeps only 46-56 actives, and the deployed 2048 slots are 37-45x oversized
    against that (Gribelyuk's worst-case bound at N = 2^20 is 1,015).
  - The `s = 6` chains are the ones with a different fusion schedule.
- **Capacity 48** is a deliberately misconfigured shape (below the sketch size)
  that exercises the silent-truncation path. The ports must truncate exactly as
  zkSketch does, and they do.
- **The odd, full chains** reach the one place where zkSketch drops an active
  tuple without a merge: from epoch 1 the 8 old actives plus 4,095 fresh rows
  fill all 4,103 rows, and round 1 never pairs the last one. That is 3 epochs
  per dataset in the guest.
- **Unit tests** (`cargo test --release -p gk-bm2-host`, 5 tests, native only):
  - 480 short chains (8 shapes including odd tables, 5 values of `s`, 4 value
    domains from 3 values to 2^32, 3 seeds; 12 epochs each, every 4th batch a
    third `PAD_KEY`), comparing every port with zkSketch tuple by tuple and
    round-tripping the word encoding. Some of them overflow.
  - 4 heavy-compression chains (capacity 256, m 4096, s 6) asserting merges in
    both directions.
  - 3 odd shapes chained 10 epochs at `s = 51`, asserting that at least 10
    epochs start from a full odd table.
  - The `fast` and `fixed_linear` ports' refusal of a non-canonical state.

## Results (executor; MODELED = segments x 30.1 s, NOT measured)

Deployed configuration, one epoch (16,384 records), `zka_gk_bm2_exec.csv`:

| row | variant | user cycles | total cycles (Σ 2^po2) | segments | MODELED prove (envelope) | rounds evaluated |
|---|---|---|---|---|---|---|
| AOL epoch 0 | literal | 82,065,236 | 135,266,304 | 129 | 3,883 s (3,835-3,972) | 15 |
| AOL epoch 0 | literal_reuse | 69,069,283 | 114,294,784 | 109 | 3,281 s | 15 |
| AOL epoch 0 | fixed_linear | 23,288,159 | 38,273,024 | 37 | 1,114 s (1,100-1,139) | 15 |
| AOL epoch 0 | fast | 5,271,282 | 8,388,608 | 8 | 241 s (238-246) | 11 |
| AOL epoch 63 | literal | 82,088,781 | 135,266,304 | 129 | 3,883 s | 15 |
| AOL epoch 63 | literal_reuse | 69,092,828 | 114,294,784 | 109 | 3,281 s | 15 |
| AOL epoch 63 | fixed_linear | 23,499,790 | 38,273,024 | 37 | 1,114 s | 15 |
| AOL epoch 63 | fast | 5,489,126 | 8,388,608 | 8 | 241 s | 10 |
| Uniform epoch 0 | literal | 82,022,165 | 135,266,304 | 129 | 3,883 s | 15 |
| Uniform epoch 0 | literal_reuse | 69,026,212 | 114,294,784 | 109 | 3,281 s | 15 |
| Uniform epoch 0 | fixed_linear | 23,230,989 | 37,748,736 | 36 | 1,084 s | 15 |
| Uniform epoch 0 | fast | 5,244,975 | 8,388,608 | 8 | 241 s | 12 |

AOL epoch 63 starts from 46 actives with n = 1,032,192 (θ = 20,560); the other
two rows start from the empty state (θ = 321).

Ingest/commit vs transition split, AOL epoch 0 (guest probes, **user cycles**
only):

| phase | literal | literal_reuse | fixed_linear | fast |
|---|---|---|---|---|
| start-up, before `main` | 371 | 371 | 371 | 371 |
| read input (163,900 B, `read_slice`) | 15,610 | 15,610 | 15,610 | 15,610 |
| `Com_old` + `Com_batch` (SHA-256) | 180,933 | 180,933 | 180,933 | 180,933 |
| decode state + `gk_vals_of` | 356,317 | 356,317 | 356,317 | 356,317 |
| **transition** | **81,195,484** | **68,199,531** | **22,418,407** | **4,401,530** |
| of which: union (comparison sort + gather / radix + merge) | 11,067,252 | 11,067,252 | 2,142,301 | 2,023,485 |
| of which: neighbour init | 743,520 | 743,520 | 778,330 | 655,444 |
| of which: fuse rounds | 69,310,717 (15 rounds) | 56,314,750 (15) | 19,497,631 (15) | 1,600,617 (11) |
| of which: final rows | 73,995 | 74,009 | 145 | 121,984 |
| `Com_new` (encode + SHA-256) | 313,336 | 313,336 | 313,336 | 313,336 |
| journal commit | 532 | 532 | 532 | 532 |
| after the last probe (probe write, exit) | 2,653 | 2,653 | 2,653 | 2,653 |
| **ingest + commit (all but the transition)** | **869,752** | **869,752** | **869,752** | **869,752** |

- **The transition is the cost, not the I/O, in user cycles.** Ingest plus the
  three commitments is 869,752 user cycles on every row, because the state
  encoding has a fixed size. That is 1.1% of `literal`'s user cycles, 3.7% of
  `fixed_linear`'s and 16.5% of `fast`'s.
  - The probes count user cycles only (`env::cycle_count`). Segments, and so
    the MODELED time, also carry paging and reserved cycles: total/user is
    1.65x for the literal variants, 1.64x for `fixed_linear` and 1.59x for
    `fast`. The executor does not split those by phase, so the ingest share
    of the segments or of the MODELED time is not measured.
- **`literal` vs `fast` is 15.6x in user cycles and 16x in segments** (82.1M vs
  5.3M, 129 vs 8; 5,009 vs 322 user cycles per record). Both compute the same
  2048-slot state, which holds 46-56 actives. This is NOT the price of the
  fixed schedule alone. Most of it is the literal port's implementation:

  | step (AOL epoch 0, user cycles) | saves | leaves |
  |---|---|---|
  | `literal` | | 82,065,236 |
  | allocate the per-round tables once (`literal_reuse`) | 12,995,953 | 69,069,283 |
  | union by radix sort + merge instead of a comparison sort of 18,432 rows | 8,924,951 | |
  | each round: fuse and compact in place in one table, instead of a fresh `fused` table plus a stable `(e, t)` re-sort | 36,817,119 | |
  | neighbour init and final rows (net) | 39,054 | 23,288,159 (`fixed_linear`) |
  | data-dependent schedule: the active prefix only, stop at the first no-op round (`fast`) | 18,016,877 | 5,271,282 |

  - So the comparison-sort union, the allocator and the two-table round
    account for 58.8M of the 76.8M user-cycle gap.
  - What is left, **`fixed_linear` vs `fast` = 4.4x in user cycles and 4.6x
    in segments** (23.3M vs 5.3M, 37 vs 8), is the price of the fixed
    schedule in this implementation. Almost all of it (17.9M) is the 15 rounds
    over all 18,432 rows. After the first rounds most of those rows are
    dummies (at most 16,384 actives go in, 46-56 come out), which `fast` never
    visits, and `fast` also stops 3-5 rounds early.
  - The runner does not split the 36.8M round saving between the per-round
    sort and the second table. A scratch build, not shipped and not in the
    CSV, kept `literal_reuse`'s two tables but replaced the stable sort and
    gather with a linear partition. Its rounds cost 31.3M user cycles at AOL
    epoch 0. So about 25.0M of the 36.8M is the per-round sort and gather, and
    about 11.8M is writing a second table instead of compacting in place.
- **Data dependence** (the three measurement rows):
  - `literal` and `literal_reuse` vary by at most 0.1%, through the comparison
    sort and the old actives in the union.
  - `fixed_linear` varies by 1.2% (23.23M-23.50M) and one segment (36-37):
    the merge with the old actives, and branch outcomes per pair.
  - `fast` varies by 4.7% (5.24M-5.49M), through its round count, its merge
    pattern and the merge with the old actives. Over the 8 deployed-config
    plain epochs of the check CSV it ranges 5.25M-5.50M, 8-9 segments.
- **Against the textbook-GK guest.** `../gk`'s `aggr_gk` measures 103.4M user
  cycles and 107 segments on the same AOL epoch, of which about 78.7M is
  zk-Analytics' framework (Event deserialisation, batch-chain verification) and
  24.5M is GK. It is a different algorithm and statement, so its numbers are
  not interchangeable with these.

## Caveats

- **No proved anchor.** Every prove time here is `segments x 30.1 s`. The model
  comes from the four CM-guest CPU anchors in `../README.md` (envelope 29.73-30.79
  s/segment). The HLL, SS and GK aggregation anchors there landed within 2% of
  it, but none is this guest. The whole-segment model overstates rows whose last
  segment is partial: AOL `fixed_linear` is 37 segments, the last at po2 19, so
  1,114 s modeled against 1,099 s pro rata. Every other row here is whole po2-20
  segments.
- **Cycle counts belong to one ELF.** Code generation elsewhere in the guest
  moves them, even when a variant's own source does not change.
  - Between the first version of this arm (three variants, ELF `2eca39a3`,
    `../results/zka_gk_bm2_exec_v1_3variants.csv`) and this one, `literal`'s
    source was unchanged. Its user cycles still moved by -0.28% to -0.33%,
    and it went from 130 to 129 segments.
  - `fast`, whose union moved into a helper shared with `fixed_linear` (same
    statements), moved by +1.3% to +1.4%. At AOL epoch 63 it went from 5,419,110
    user cycles and 9 segments to 5,489,126 and 8: more user cycles, one segment
    fewer. The segment count follows paging, and paging follows code and data
    layout.
  - Edits to comments only, which shifted line numbers in the panic
    locations, left all four AOL epoch 0 rows unchanged (ELF `e8b3e2f7` vs the
    measured `b429918d`).
  - `fast`'s three measurement rows fill exactly 8 x 2^20 total cycles
    (8,388,608), so they sit on the 8/9-segment boundary, and the deployed
    check rows show 8-9 segments. Quote `fast` as **8-9 segments (241-271 s
    MODELED)**, with user cycles as the primary metric and segment ratios as
    approximate.
- **CPU-only r0vm 3.0.6** on this 64-thread Threadripper box; the GPU prover was
  not used. `exec_s` is wall-clock on a shared box and is not a metric. For a
  fixed ELF, cycles and segments are deterministic. Two full runs of the
  runner with ELF `b429918d` agreed on all 248 rows in every column except
  `exec_s`; the CSVs in `../results` come from the first, and the second went
  to a scratch directory and was not kept. Both log headers recorded
  `dirty_excl_results=[2]`.
- **Cross-hardware.** The paper's zkSketch timing tables come from an EPYC
  machine. Cycles and segments do not depend on hardware, but the MODELED
  seconds are this box's CPU prover rate. A ratio between a zkSketch EPYC
  prove time and a MODELED second here crosses machines and must say so. A
  same-box zkSketch GK leaf at this configuration was not measured here, and
  zkSketch-side numbers should come from the current build (see
  `../README.md`).
- **Which row to quote.**
  - `fixed_linear` is the like-for-like row: zkSketch's fixed schedule (the
    full table, every round, every row) without the literal port's
    allocation and comparison-sort costs. It is one implementation of that
    schedule, not a lower bound for every implementation.
  - `fast` is the conservative baseline: the cheapest zkVM implementation of
    the identical function that this directory has. It exploits data
    dependence that the zkVM leaks through its cycle count. zkSketch's circuit
    is oblivious, and zk-Analytics' guests leak in the same way.
  - `literal` is zkSketch's native code ported statement for statement. Its
    extra cost over `fixed_linear` (3.5x in user cycles) comes from how that
    native code builds its tables, not from the schedule the circuit
    certifies. Do not quote `literal` vs `fast` as the cost of obliviousness.
- **Not hiding.** The commitments are unsalted SHA-256, as in the other zka
  guests.
- **Not a pipeline.** This is one transition per guest run. Linking `Com_new` to
  the next `Com_old`, verifying receipts and answering queries are not part of
  this arm.
