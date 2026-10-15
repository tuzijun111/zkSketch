# zkSketch's GK algorithm in zk-Analytics' pipeline (`gk_matched`, ours †)

**Why this exists.** zkSketch and zk-Analytics are compared on the same sketch. For
Greenwald-Khanna that means the same *algorithm* on both sides, not just "a GK with
eps = 1/51". `../gk` is textbook Greenwald-Khanna 2001: INSERT and band COMPRESS per
record, a summary rebuilt from scratch every epoch, and a k-way COMBINE at query time.
zkSketch certifies a different function: its two-sided band-merge batch rule
(`apply_batch2`, `src/sketch/gk_bandmerge.rs`; Gribelyuk-Sawettamalya-Wu-Yu 2024), applied
once per leaf to the state carried from the previous leaf. This directory runs **that rule**
inside zk-Analytics' own epoch pipeline, so both systems compute the same sketch state from
the same records and the comparison prices the same work. It is the zk-Analytics GK of the
six-sketch comparison by default (`six/`, `SIX_ZKA_GK=matched`); `../gk` stays as a
labelled reference (`SIX_ZKA_GK=textbook`, and the committed 2026-10-09 rows).

Cite it as "zkSketch's GK rule in zk-Analytics' pipeline (our port †)", never as
zk-Analytics' GK: zk-Analytics ships no rank-guaranteed quantile summary.

## What runs where

Aggregation guest `aggr_gkm`, one run per epoch of B records:

| step | what | source |
|---|---|---|
| 1 | verify source 0's SHA-256 batch hash chain | their `verify_and_compute_chain`, copied verbatim |
| 2 | flatten the batches to events | as upstream |
| 3 | take the **carried** state S_{e-1} and check it: SHA-256 of its words must reproduce the previous epoch's `final_chain_hash` (= this epoch's `prev_chain_hash`) through their `EpochChainLink::compute_final_hash`; epoch 0 (genesis hash) starts from the empty state | ours, their link function |
| 4 | map the records with zkSketch's `gk_vals_of` (drop `PAD_KEY`, mask to 21 bits; zk-Analytics epochs carry no padding, so the drop is a no-op here, see Configuration) | `../gk_bm2/core` `vals_of` |
| 5 | **B / m_sub successive `apply_batch2` steps** with `GkbParams { capacity, batch: m_sub, s }`, each from the previous step's state; a **capacity overflow panics** (no receipt) | `apply_epoch_tuned` here (`tuned`, the default), or `../gk_bm2/core` (unchanged) through `apply_epoch` |
| 6 | root of the selected variant (designed = their samples pattern over 64 groups of tuples, noroot = none, pertuple = one leaf per tuple) | their pattern, as `../gk` |
| 7 | unsalted SHA-256 state commitment | their pattern |
| 8 | link it into the epoch chain | their `EpochChainLink::new` |

Journal: `(GkmRoot, GkmAggrOutput)`: the epoch link, `state_commit`, `tuples_root`,
`n_events`, the source chain tips (their `HistogramAggrOutput` shape), plus the GK
configuration, `prev_state_commit` and the number of steps.

Query guest `querier_gkm`, one run per query:

| step | what | source |
|---|---|---|
| 1 | re-verify every epoch chain link, and require ONE unbroken chain (their check lets a link at the genesis hash start a new per-aggregator chain; the carried state covers every queried epoch only along one chain) | their `verify_epoch_chain_integrity`, verbatim, plus our linkage check |
| 2 | recompute the **latest** state's commitment and check it against the last link (the carried state summarises every epoch, so only it is opened) | their pattern |
| 3 | rank(v): zkSketch's GK decoder estimator (`native_estimate`, `src/decode/gk_bandmerge.rs`): k = #{rows with e <= v}, P = sum of g + g° + 1 over them, lo = P - (g°+Delta° of row k-1), hi = P + (g + Delta of row k), answer floor((lo + hi) / 2) | ported (`gkm_rank`) |
| 4 | their low-support suppression (`MIN_SUPPORT`) | as upstream |

zkSketch proves the same B records as B / m_sub leaves of m_sub records, folded by its
proof forest; the function its leaves certify for the epoch is exactly step 5's chain, and
its decoder proves step 3's answer.

## Configuration

- **Records** (identical to `../gk` and the other ports). `data/aol.keys`; epoch e =
  keys `[e*B, (e+1)*B)`; `key_id = Event::make_key_id(0, key)`, `value = key & 0x1FFFFF`,
  `ts` = the global index; one source, batches of 8, batch chain, source tips and epoch
  chain carried across epochs.
- **No padding.** zkSketch's `gk_vals_of` drops `PAD_KEY` (`u32::MAX`) slots, which only
  its early-sealed (mixed-workload) batches contain. A zk-Analytics epoch has no padding,
  and the driver hands the guest `value = key & 0x1FFFFF`, so the guest's `PAD_KEY` drop
  never fires. A dataset with a key equal to `PAD_KEY` would therefore be summarised
  differently by the two sides; the driver refuses one (exit 2). `data/aol.keys` has none.
- **GK parameters** = zkSketch's: `--capacity` (`EXP_GK_CAP`, `SIX_GK_CAP`), `--s 51`
  (`EXP_GK_S`), `--m-sub` = zkSketch's leaf size (`SIX_GK_MSUB`, default the epoch size).
  B must be a multiple of m_sub, so the steps are exactly zkSketch's leaves, and
  capacity + m_sub must be even (zkSketch's leaf table needs it).
- **Implementation** (`--impl`, `SIX_ZKA_GK_IMPL`). One function, four implementations,
  all tested tuple-equal to zkSketch's chain here (and the three from `../gk_bm2/core`
  there too):
  - `tuned` (default, the steelman: what a zkVM programmer would write;
    `core/src/lib.rs` `apply_epoch_tuned`): `fast`'s data-dependent schedule (merge the
    sorted fresh values into the sorted old actives, fuse over the active prefix only,
    compact instead of re-sorting, stop after the first round that changes nothing)
    written as ONE loop over the epoch's B / m_sub steps. The state stays compact (its
    active rows) from step to step, the canonical form and the mass are checked once on
    the carried state, the fresh values are radix-sorted with digits sized to the batch
    (3 digits of 7 bits at m_sub 128), the buffers are allocated once per epoch, and an
    overflow is detected from the rows a step drops (exactly `capacity_violation`'s
    condition: fusions conserve the mass).
  - `fast` (`apply_batch2_fast`, one call per step): the same schedule, but every call
    re-checks the canonical form of all `capacity` rows, clears and prefix-sums two
    2,049-entry radix tables, pads its output to `capacity` with dummies and allocates
    fresh buffers. At m_sub 128 (16 steps per 2,048 records) that per-step overhead is
    0.88M of its 1.84M update cycles and costs zk-Analytics a whole segment (13 instead
    of 12 at config A); it was the default until 2026-10-15 (round 2 of M1) and stays
    for comparison.
  - `fixed_linear` (zkSketch's fixed schedule: every row of the capacity + m_sub table,
    every one of the ceil(log2(capacity + m_sub)) rounds) and `literal` (zkSketch's
    native code statement for statement), for sensitivity.
- **State encoding.** zkSketch's state is `capacity` rows: the active tuples, a
  value-sorted prefix, padded with identical dummies (a circuit's fixed table). This side
  stores, ships, hashes and carries only the *compact words*: capacity, m_sub, s, n, the
  active count and the active tuples `(e, g, g°, Delta, Delta°, t)`. A canonical state and
  its compact words determine each other (pad / drop the dummy suffix), so this is the same
  state. `state_commit = SHA-256("ZKTLM_GKM_STATE_COMMIT_V1" || compact words)`; its preimage
  is zkSketch's own state (the check below compares exactly that).
- **Capacity overflow** is a hard error everywhere: the host detects it on zkSketch's
  native chain (active mass != N after a step) and exits 3 without running a guest; the
  guest panics on it (`capacity_violation`: fusions conserve g + g° + 1, so a state chained
  from the empty one has active mass N exactly unless rows were cut; `tuned` checks the
  carried state's mass once and then the rows every step drops, the same condition);
  zkSketch's own leaf
  circuit refuses to prove such a step (its native `apply_batch2` truncates silently in a
  release build, which is why the check is ours).
- **Root variants** as `../gk`'s `aggr_gk_root`: `designed`, `noroot` (the headline),
  `pertuple`. There is no `legacy` (that is the committed textbook guest); the driver
  refuses it.
- **Toolchain.** Guests: risc0-zkvm 3.0.5; `guests/Cargo.lock` has exactly the
  third-party entries of `../gk/guests/Cargo.lock` (seeded from the zk-Analytics clone),
  only the local crates differ. Host: risc0-zkvm 3.0.6; `Cargo.lock` was resolved from a
  priority merge of `../gk/Cargo.lock`, the zkSketch `Cargo.lock` and
  `../gk_bm2/Cargo.lock` (every third-party entry is in one of them). Builds go to
  `$BASELINE_DIR/build/zka-gk-matched` with `--locked` and `RISC0_BUILD_LOCKED=1`.

## Equivalence evidence

`gk_matched_check.sh` (and the driver's `--mode check|certify`) produces it:

- **Native unit tests** (`cargo test --release --locked -p gk-matched-host`, 8 tests):
  every epoch of every implementation equals zkSketch's `apply_batch2` chain tuple by tuple
  at (capacity, m_sub) = (384, 128), (768, 512), (2048, 2048), (64, 256), with the
  commitment equal to SHA-256 of zkSketch's state; a tampered carried state, a wrong
  previous link, a missing state after genesis, a changed configuration and a fake genesis
  are refused (`fast` and `tuned`), and so is a correctly linked carried state whose rows
  are out of order (`fast`, `tuned`) or whose mass is not n (all four); capacity 16 (where
  zkSketch's native code truncates) panics in all four implementations; `tuned` equals
  zkSketch's chain, or panics exactly where zkSketch's chain loses a record, on 22 more
  shapes (odd tables, capacities at and below overflow, 37 distinct values, the state
  carried compact and full); `gkm_rank` equals zkSketch's `Gk2State::rank_interval` / `rank`; the root
  variants and implementations agree off the root; the query refuses a chain that restarts
  at the genesis hash and a state that is not the last link's.
- **`--mode check`** (guest executed, new state emitted on the private stdout): at every
  epoch and implementation the guest's state equals zkSketch's native chain in all 7 fields
  of every row, n and the parameters; the journal equals the native one; the query guest's
  bounds equal zkSketch's `rank_interval` on its own chain.
- **`--mode certify`**: zkSketch's GK leaf circuit, built exactly as `exp_compose` builds
  it (`build_gkb2_leaf_commit(params, composition_expose(), default_binding(), Hiding)`),
  proves every m_sub-record leaf of the epochs (global batch index t, openings of a public
  test seed); every leaf's exposed initial / final commitment equals Com of zkSketch's
  native chain, and each epoch's last leaf exposes **Com(S) of the state the zk-Analytics
  guest computed**; zkSketch's GK decoder, proved on that state at the hot value, gives
  the query guest's answer.
- **`exp_compose` itself.** The 2026-10-14 memory-matched runs
  (`../results/memmatch-20261014/runs/`) proved the same AOL records with zkSketch's
  forest and queried after every leaf: at the end of the first 2,048 records
  (`gk-m128-cap384-t16` leaf 16, `gk-m512-cap{64,128}-t4` leaf 4, `gk-m2048-cap2048-t1`
  leaf 1) they answered rank(1,810,625) = 1,778, 1,780 and 1,786: the query guest's answers
  at the same configurations, (384, 128), (128, 512) / (64, 512) and (2048, 2048)
  (`exp_compose_crosscheck.csv`). No `exp_compose` run exists at config B (768, 512); there
  the evidence is `--mode certify` (zkSketch's leaf circuit) and the M1 measurement runs
  (`../results/20261015-m1/`: 1,780 after 2,048 records on both sides). Over eight carried epochs, the committed
  six-sketch zkSketch runs (`../results/six_zksketch{,_r2}_gk.log`, capacity 2,048, 8 x 2,048
  records) answered 1,786, 3,557, 5,274, 7,095, 8,916 (rank(1,810,625), n = 1..5) and 5,877,
  6,915, 7,927 (rank(985,491), n = 6..8); the query guest gives the same eight answers
  (`../results/20261015-m1/`).

## Running

```bash
scripts/baselines/zka/gk_matched/gk_matched_check.sh           # build, unit tests, check + aggr rows, configs A and B
CERTIFY=1 SKIP_BUILD=1 scripts/baselines/zka/gk_matched/gk_matched_check.sh   # + zkSketch leaf proofs (~4 min)
B=$BASELINE_DIR/build/zka-gk-matched/release/gk_matched
$B --mode aggr  --epoch-index 1 --capacity 384 --m-sub 128 [--root designed|noroot|pertuple] [--impl tuned|fast|fixed_linear|literal] [--emit-state] [--prove]
$B --mode query --epochs 2 --rank-value 1810625 --capacity 384 --m-sub 128 [--prove]
$B --mode check   --epochs 2 --capacity 768 --m-sub 512 [--impl all]
$B --mode certify --epochs 2 --capacity 768 --m-sub 512 [--commit hiding|plain] [--seed N]
```

`six/run_zka.sh` calls the same driver with `--capacity $SIX_GK_CAP --m-sub $SIX_GK_MSUB
--s 51 --impl $SIX_ZKA_GK_IMPL`. CSV columns: as `../gk`'s where they mean the same thing
(`mode`, `epoch_index`, `epoch_records`, `user_cycles`, `padded_cycles`, `segments`,
`journal_eq_native`, `result` = `rank(v) est=..;lo=..;hi=..` on query rows, `prove_s`,
`verify_ms`, `receipt_bytes`, `r0vm_peak_rss_mb`, the four root-variant columns at the end),
plus `algorithm=bm2`, `implementation`, `capacity`, `m_sub`, `steps`, `state_eq_zksketch`,
`query_eq_zksketch`, `certified_eq` and `prof` (the guest's phase split in user cycles:
`pre`, `read` = their Event deserialisation, `chain` = their batch-chain check, `flatten`,
`carry`, `map`, `update` = the GK steps, `root`, `commit`, `link`, `journal`, `post`).
Exit codes: 0 ok, 1 a check failed (row printed), 2 bad arguments, 3 capacity overflow.
`RISC0_DEV_MODE` is refused.

## Caveats

- **Carrying the state departs from their architecture.** zk-Analytics' aggregators build
  each epoch's summary fresh and independently (one chain per aggregator, so epochs can be
  aggregated in parallel or by different aggregators) and merge the n summaries at query
  time. This port carries S_{e-1} into epoch e, refuses a chain that restarts at genesis,
  and its query opens one state with no merge. That is forced by the same-function
  requirement: zkSketch's function is the `apply_batch2` chain from the previous state, and
  a fresh-per-epoch summary merged at query time would be a different sketch (as `../gk` is).
  What the carry costs zk-Analytics, per epoch from epoch 1 on, is the carried words' read
  (risc0 serde, about 170 user cycles per word, like every other input word) plus the
  `carry` phase (the commitment check and the decoding); at epoch 0 only the empty state's
  commitment. With `tuned`, AOL, B = 2,048 (epoch 1 minus epoch 0 for the read):

  | config | read of the carried words | `carry` phase | extra user cycles | share of the epoch |
  |---|---|---|---|---|
  | A (384, 128) | 108,984 | 12,653 (epoch 0: 1,603) | about 0.12M | 1.1% |
  | B (768, 512) | 99,984 | 11,798 (1,603) | about 0.11M | 1.0% |
  | D (2048, 2048) | 107,184 | 12,522 (1,603) | about 0.12M | 1.1% |

  The `read` column of the CSV (`prof`) is their Event deserialisation plus, from epoch 1
  on, the carried words. A raw `env::read_slice` of the words would save most of the read;
  it is not used (all input goes through their serde path).
- **Data-dependent.** `tuned` and `fast` exploit the data (active prefix, early stop), as a
  zkVM may; zkSketch's circuit is oblivious. `fixed_linear` is the fixed schedule.
- **Further tuning.** `tuned` spends about 27k user cycles per extra step at m_sub 128
  (0.97M for 16 steps against 0.56M for one 2,048-record step at the same records), close
  to the work the schedule itself needs (merging about 180 rows, two neighbour passes,
  about six shrinking fuse rounds over 48-byte tuples). Narrower tuple fields or in-place
  rounds could shave part of it; at config A that is at most a few percent of the epoch.
