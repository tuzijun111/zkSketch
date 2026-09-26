# HyperLogLog in zk-Analytics' architecture (our port)

zk-Analytics (Zhu et al., SIGCOMM '26; clone `d4a5a9a`, read-only) ships three epoch
summaries (samples, histogram, cm) and no distinct-count sketch. This directory adds a
HyperLogLog summary to **their** pipeline with **their** general-purpose method: the
textbook plaintext algorithm, written in ordinary Rust and executed as a RISC Zero
guest. It is our instantiation of their per-epoch / query-time-merge architecture,
so label it as ours (for example with a dagger) and never call it "zk-Analytics' HLL".
Nothing from zkSketch is used here: no oblivious padding, no memory checking, no
sorting certificates, no Poseidon.

## What runs

| step | guest | what it does |
|---|---|---|
| aggregation, one per epoch | `hll_aggr` | verifies the source SHA-256 batch hash chain, builds a 2^14-register HLL of the epoch from scratch, hashes the state with an unsalted tagged SHA-256, and links that commitment into the epoch chain |
| query over n epochs | `hll_query` | re-verifies the n epoch chain links, recomputes each epoch's state commitment, merges the registers by elementwise max, and commits the estimate with the chain boundaries and the n state commits (their low-support suppression, `MIN_SUPPORT = 10`) |
| sensitivity only | `hll_query_words` | the same computation and journal, but the registers travel in serde's default `Vec<u8>` encoding, one zkVM word per register |

### Configuration

- **Records.** `data/aol.keys` sliced as in `../cyc/src/bin/shipped.rs`:
  - epoch e holds keys `[e*16384, (e+1)*16384)`, so epoch 0 is our matched CM epoch;
  - `key_id = Event::make_key_id(0, key)`, `value = 1`, `ts` = global index;
  - one source, batches of 8 records (their default);
  - the batch chain, `source_batch_seq` and tips carry across epochs;
  - epoch e's `prev_chain_hash` is epoch e-1's `final_chain_hash`.
- **Sketch.** `b = 14` (m = 16,384 registers, u8 each).
  - Hash: their FNV-1a key fold `key_to_u64` (aggregator/core/src/lib.rs:342), then the
    seeded splitmix64 finaliser of their `cm_bucket_index` (lib.rs:1055-1063) without the
    `% CM_COLS`. The seed is their CM row-0 seed `0x6d0f27bd`.
  - Index = low 14 bits of the hash; rank = 1 + leading zeros of the other 50 bits (1..=51).
- **State and commitment.**
  - State = `{ total_count: u64, registers: Vec<u8> }`.
  - Commitment = `SHA-256("ZKTLM_HLL_STATE_COMMIT_V1" || total_count_be || registers)`, in
    the style of their `cm_epoch_state_commit`. The tag is ours.
  - Link: their `EpochChainLink::new(prev, commit)`.
- **Aggregation journal.** `epoch_chain_link, state_commit, n_events, final_source_chain_tips`:
  their `CmAggrOutput` minus the CM Merkle roots.
- **Estimator.** Flajolet et al. 2007 with the small-range (linear counting) correction.
  - No large-range correction, because the hash is 64-bit.
  - The sum of 2^-M[j] is formed exactly in u128 and converted to f64 once.
  - ln comes from `libm`, so the f64 result is bit-identical on the host and in the guest.
  - The journal carries the rounded estimate, the raw estimate, m, the zero-register
    count and the branch taken.
- **Versions.** Guests link risc0-zkvm 3.0.5: `guests/Cargo.lock` was derived from their
  `Cargo.lock`, with no version changed. The host uses 3.0.6: `Cargo.lock` was derived from
  `../cyc/Cargo.lock`. The executor and prover are r0vm 3.0.6 on CPU. ELF md5s and image
  IDs are in the logs and the CSV `image_id` column.

## Running

```bash
cd scripts/baselines/zka/hll
./run_exec.sh                 # executor: aggr epoch 0; queries n = 1 4 16 64 (+ words variant)
./prove_anchor.sh             # ONE proved anchor: hll_aggr at 2048 records (skips if 1-min load > 24)
python3 seed_spread.py        # numpy re-implementation: must reproduce every committed estimate
# the same code over 200 seeds (the guest's + 199 from default_rng(200)) -> zka_hll_seed_spread_200.csv
python3 -c "import sys, numpy as np, seed_spread as s; s.SEEDS = [s.GUEST_SEED] + [int(x) for x in np.random.default_rng(200).integers(1, 1 << 32, 199)]; sys.argv = ['seed_spread.py', '--out', '../results/zka_hll_seed_spread_200.csv']; s.main()"
./gen_upstream.sh --check     # verbatim copies still match the clone at d4a5a9a
CARGO_TARGET_DIR=~/ext-baselines/build/hll cargo test --release --locked -p zka-hll-core
```

- Builds go to `$BASELINE_DIR/build/hll` with `--locked` and `RISC0_BUILD_LOCKED=1`.
  Path dependencies go through `../.zka`, which `../common.sh` creates.
- `run_exec.sh` appends to `../results/zka_hll_exec.csv` (the header is written once, and the
  script refuses to append under a different header). The raw log is `zka_hll_exec.log`.
  - `AGGR_EPOCHS="1 31 63" QUERY_EPOCHS=""` with `OUT=.../zka_hll_exec_datadep.csv` produced
    the data-dependence rows.
- `prove_anchor.sh` writes `zka_hll_anchor.csv` and `.log`.
  - Peak RSS comes from `rss_child.sh`, which samples only r0vm processes descended from its
    own command and kills nothing.
  - `../rss_watch.sh` is not usable here: it refuses to start while any r0vm of this
    account is running, and it pkills every r0vm of this account on exit, which would hit
    the sibling SS/GK jobs.
- Every run checks four things:
  - `journal_eq_native`: the guest journal equals the same core function run natively.
  - `ref_check`: a separate host HLL over the raw keys (same hash; bit-loop rank, f64 sum,
    std `ln`) matches the registers and the estimate. `seed_spread.py` re-implements
    everything, the hash included, in numpy.
  - `exact`: the exact distinct count of the covered keys.
  - `prof`: the guest's cycle split per phase, from `env::cycle_count()` marks written to
    STDOUT, not to the journal.

## Results (2026-09-26; executor unless stated; MODELED = segments x 30.1 s, NOT measured)

**Aggregation, one epoch** (16,384 records, 8,433 distinct keys):

- 82,646,548 user cycles (5,044 per record), 85 segments, 88.6M padded cycles.
- MODELED 2,558 s (envelope 2,527-2,617 s).
- Their `aggr_cm` at T=1 on the same epoch takes 100.4M cycles and 104 segments.

| phase | cycles | share | per record |
|---|---|---|---|
| deserialize input (`env::read`, their `Event` batches) | 60,792,980 | 73.6% | 3,710 |
| batch hash-chain verification (their code) | 17,905,927 | 21.7% | 1,093 |
| flatten batches (their code) | 581,151 | 0.7% | 35 |
| **HLL update** (hash, rank, register max) | 3,274,924 | 4.0% | 200 |
| state commit + epoch link | 45,202 | 0.1% | - |

**Query over n epochs** (merge + estimate):

| n | records | exact distinct | estimate (rel. err) | `hll_query` cycles | segs | MODELED | `hll_query_words` cycles | segs | MODELED |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 16,384 | 8,433 | 8,472 (+0.46%, LC) | 387,064 | 1 (po2 19) | 30 s | 2,843,086 | 3 | 90 s |
| 4 | 65,536 | 29,390 | 29,330 (-0.20%, LC) | 1,013,846 | 2 | 60 s | 10,837,880 | 11 | 331 s |
| 16 | 262,144 | 87,540 | 87,301 (-0.27%) | 3,575,205 | 5 | 151 s | 42,871,287 | 43 | 1,294 s |
| 64 | 1,048,576 | 245,620 | 241,155 (-1.82%) | 13,908,942 | 16 | 482 s | 171,093,216 | 172 | 5,177 s |

- **Cost fits.** `hll_query` = 214,812 n + 156,500 cycles (R² 0.999995).
  `hll_query_words` = 2,670,816 n + 156,518 (R² 1.0).
- **Per-epoch cost at n=64**, packed encoding:
  - register merge 146K cycles (8.9 per register);
  - state-commit SHA-256 over 16 KB, 44K;
  - input read 20K;
  - chain link 1.5K.
- **Estimator (constant in n).** 164,087 cycles for the pass over the 16,384 registers,
  plus 4.4K cycles (raw branch) or 7.8K cycles (linear counting, with `libm::log`) for the
  f64 part.
- **Accuracy.** HLL's standard error at b=14 is 0.81%.
  - The -1.82% at n=64 is the draw of this one hash function.
  - `seed_spread.py` reproduces every committed estimate bit-exactly.
  - Over 10 seeds at n=64 the error ranges from -2.21% to +1.28% (mean +0.02%, sd 1.15%).
  - Per-n spreads are in `zka_hll_seed_spread.csv`.
  - Over 200 seeds (`zka_hll_seed_spread_200.csv`, command under Running; the script's
    console label still says "10 seeds") the sd is 0.60 / 0.70 / 0.71 / 0.80% at
    n = 1 / 4 / 16 / 64 and every mean is within ±0.04%. At n=64 the guest seed's -1.82%
    is about -2.3 sd, the third-lowest of the 200.

**Proved anchor** (`hll_aggr`, epoch 0 at 2,048 records, `ProverOpts::succinct()`, CPU):

| metric | value |
|---|---|
| user cycles | 10,395,108 |
| segments | 11 (all po2 20) |
| total cycles | 11,534,336 (paging 455,463) |
| prove time | **332.1 s** |
| s/segment | **30.19** (inside the 29.73-30.79 CM envelope) |
| receipt | 224,554 B |
| verify | 9.8 ms (best of 5) |
| r0vm peak RSS | 9.38 GB |
| 1-min load | 11.4 before, 42.4 after (mostly this prover's own threads) |

A non-CM guest thus lands on the CM s/segment. The proved journal was asserted
equal to the native output.

## Reused from upstream (d4a5a9a)

- **By path dependency** (unmodified crates):
  - `zkvm_common::Event` and `make_key_id`;
  - `aggregator_core::{BatchInput, CmAggrInput, EpochChainLink, batch_chain_hash, key_to_u64, CM_SEEDS}`;
  - `querier_core::MIN_SUPPORT`.
  - `CmAggrInput` is the aggregation input type as is. It is field-for-field identical to
    their samples and histogram inputs and holds nothing CM-specific.
- **Copied verbatim** because they are private upstream. `core/src/upstream_verbatim.rs` is
  generated by `gen_upstream.sh`, which also re-diffs it.
  - From `aggregator/core/src/lib.rs`: `TAG_SHARD_CHAIN` (:57), `sha256_bytes` (:93-99),
    `events_commit` (:295-305), `chain_tips_to_sorted_vec` (:331-339) and
    `verify_and_compute_chain` (:499-603).
  - From `querier/core/src/lib.rs`: `TAG_EPOCH_CHAIN` (:41) and
    `verify_epoch_chain_integrity` (:98-136).
- **Structure mirrored step for step** (cited in `core/src/lib.rs`):
  - `process_cm_aggr_with_state`: chain verification, flatten, build, commit, link, output.
  - `run_cm_query`: chain checks, commit checks, boundaries, state commits, merge, answer,
    `suppress_if_low_support`.
  - The guest `main`s mirror `aggr_cm` and `querier-guest-cm`, with the same risc0-zkvm
    feature sets.
- **Ours.** The HLL update, the register merge, the estimator, the state type and its tag,
  the words variant, the cycle-count probes and the host driver.

## Caveats

- **The cycle count is data-dependent.** This is plain code with no padding, so cycles and
  prove time leak input properties, exactly as in their guests.
  - Aggregation: the update phase depends on how many records raise a register. Epochs 0, 1,
    31 and 63 span 82,646,548-82,654,215 cycles (0.01%). The read and chain phases depend
    on the record count and batch size.
  - Query: the merge branch depends on the data; the f64 part differs by branch
    (7.8K cycles for linear counting, 4.4K raw).
  - Another dataset or batch size gives different numbers.
- **The register encoding is a 12x lever.** Packed (4 registers per word) is the steelman
  and our headline.
  - A direct port in the style of their `CmEpochState` (`heap_occ: Vec<u8>` is encoded one
    word per element) pays about 151 cycles per register word in `env::read`: 2.67M cycles
    per epoch against 0.21M.
  - Both are reported. The packed rows are the conservative choice for comparisons, because
    they are the cheaper baseline.
- **Aggregation is dominated by their input format.** 74% of the cycles deserialize their
  `Event` batches: about 21.5 words per record (17 per `Event`, plus per-batch fields
  including the 32-word batch hash), at about 173 cycles per word. Any summary in their
  framework pays this. We did not change it.
- **This baseline is cheaper than a literal port.**
  - The aggregation journal drops the per-type Merkle roots their three types compute
    (`buckets_root`, `row_roots`/`cm_root`/`heap_root`). No query guest reads those roots.
  - The state commitment hashes the register bytes in one `update`.
- **Inherited from their query code, kept unchanged.**
  - Chain and commit checks run only when `epoch_chain_links` is non-empty.
  - A link whose `prev_chain_hash` is genesis starts a new chain.
  - Commitments are unsalted hashes (their own security note).
- **The query cost excludes aggregation receipts.** Every query also needs the n per-epoch
  aggregation receipts, verified separately. Their tree has no `env::verify`, so the
  aggregation rows recur once per epoch.
- **MODELED is a model.**
  - It is `segments x 30.1 s`, with the envelope from the four CM anchors
    (`../README.md`).
  - The one HLL anchor measured 30.19 s/segment, which supports but does not prove the model
    for the larger runs.
  - At n=1 the single query segment is po2 19 (half size), so 30 s overstates it.
  - The anchor ran on a shared box with other users' jobs; the load before starting was 11.4.
- **The probes add a few hundred cycles.** The guests read `env::cycle_count()` 7-8 times
  and write one small STDOUT record. This is included in every count. The marks are user
  cycles: pre + phases + post = `user_cycles` on every row.
- **HLL needs no top-K key caveat.** The whole answer (estimate, branch, zero registers) is
  in the committed journal.

## Files

| file | purpose |
|---|---|
| `core/` | `zka-hll-core` (no_std): the HLL epoch type, aggregation, query, estimator; `upstream_verbatim.rs`; unit tests (tamper, reorder, forged batch, suppression, serde packing, both estimator branches) |
| `methods/`, `guests/aggr`, `guests/query` | risc0 methods crate and the guests (`hll_aggr`, `hll_query`, `hll_query_words`) |
| `host/` | driver `hll` (`--mode aggr` / `--mode query [--words]`, `--prove`) |
| `run_exec.sh`, `prove_anchor.sh`, `hll_common.sh`, `rss_child.sh` | runners |
| `gen_upstream.sh`, `seed_spread.py` | provenance check and accuracy cross-check |
