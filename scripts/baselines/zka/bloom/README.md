# Partitioned Bloom filter in zk-Analytics' architecture (our port †)

zk-Analytics (Zhu et al., SIGCOMM '26; clone `d4a5a9a`, read-only) ships three epoch
summaries (samples, histogram, cm) and no membership filter. This directory adds a
partitioned Bloom filter to **their** pipeline with **their** general-purpose method:
the textbook plaintext algorithm, written in ordinary Rust and executed as a RISC Zero
guest, exactly like `../hll/`. It is our instantiation of their per-epoch /
query-time-merge architecture, so label it as ours (†) and never call it
"zk-Analytics' Bloom filter". Nothing from zkSketch is used here: no oblivious padding,
no memory checking, no sorting certificates, no Poseidon, and not zkSketch's batch
rule or certificate (zkSketch's `bloom_omc` leaf proves a timestamped
offline-memory-checking rebind of the OR update; this guest just executes the update).

## What runs

| step | guest | what it does |
|---|---|---|
| aggregation, one per epoch | `bloom_aggr` | verifies the source SHA-256 batch hash chain (their code), builds the epoch's k = 7 x W = 2^14-bit partitioned filter from scratch one record at a time, hashes the state with an unsalted tagged SHA-256, and links that commitment into the epoch chain (their `EpochChainLink::new`) |
| query over n epochs | `bloom_query` | re-verifies the n epoch chain links (their code), recomputes each epoch's state commitment, merges the n filters by bitwise OR (the Bloom union), tests one key, and commits the key, the answer, the chain boundaries and the n state commits (their low-support suppression, `MIN_SUPPORT = 10`) |

The host driver `bloom` (`host/src/main.rs`) has three modes; every guest run is
executed, and also proved with `--prove` (`ProverOpts::succinct()`, their shipped
tier, CPU r0vm):

| `--mode` | runs |
|---|---|
| `aggr --epoch-index i` | `bloom_aggr` on epoch i (earlier epochs aggregated natively only to carry the chain tips) |
| `query --epochs n` | epochs 0..n aggregated natively, then `bloom_query` over the n states |
| `exec --epochs N --query-at 1,2,4,8` | the whole per-epoch pipeline: `bloom_aggr` on every epoch in order, each epoch's `prev_chain_hash` and source tips taken from the previous **guest journal** (as their aggregator host carries them), and after epoch n the `bloom_query` guest over epochs 0..n for every n in `--query-at` |

### Configuration

- **Records.** `data/aol.keys` sliced as in `../cyc/src/bin/shipped.rs`, at the planned
  comparison size by default:
  - epoch e holds keys `[e*m, (e+1)*m)`, m = `--epoch-size` (default 2,048);
  - `key_id = Event::make_key_id(0, key)`, `value = 1`, `ts` = global index;
  - one source, batches of 8 records (their default);
  - the batch chain, `source_batch_seq` and tips carry across epochs;
  - epoch e's `prev_chain_hash` is epoch e-1's `final_chain_hash`.
- **Sketch.** Partitioned Bloom filter (Bloom 1970; partitioned form as in Chang et
  al. 2004 / Almeida et al. 2007), the zkSketch defaults `EXP_BLOOM_K = 7`,
  `EXP_BLOOM_LOGW = 14`: k = 7 slices of W = 16,384 bits, M = 114,688 bits.
  - Positions: slice j's position is their `cm_bucket_index`
    (`aggregator/core/src/lib.rs:1055-1063`) with `CM_COLS` replaced by W and the
    slice's seed: their FNV-1a `key_to_u64` fold, XOR `(seed << 32 | seed)`, the
    splitmix64 finaliser, `mod W`.
  - Seeds: slices 0-2 use their three CM row seeds `0x6d0f27bd, 0x9e3779b9,
    0x94d049bb`; zk-Analytics has no further seed, so slices 3-6 use four fixed odd
    constants of ours (`0x85ebca6b, 0xc2b2ae35`, the MurmurHash3 fmix32 multipliers,
    and `0x27d4eb2f, 0x165667b1`, xxHash32 primes 3 and 5), chosen before any run.
    For slices 0-2, `pos mod 1024` equals their `cm_bucket_index` exactly (unit test).
  - The FNV fold is computed once per record and shared by the 7 slices; their CM
    recomputes it per row. Hoisting it only makes this baseline cheaper.
  - Insert sets the 7 bits; a lookup ANDs them (short-circuiting on the first 0).
- **State and commitment.**
  - State = `{ total_count: u64, bits: Vec<u8> }`, a packed bitset: bit i is bit
    `i mod 8` of byte `i / 8`, slice j = bits `[jW, (j+1)W)`; 14,336 bytes.
  - The bytes travel as one packed byte string (`packed_bytes`, the HLL port's helper,
    4 bytes per zkVM word, read in bulk). See Caveats for why this matters.
  - Commitment = `SHA-256("ZKTLM_BLOOM_STATE_COMMIT_V1" || total_count_be || bits)`, in
    the style of their `cm_epoch_state_commit`. The tag is ours. Their risc0-accelerated
    SHA-256 (`risc0_zkvm::sha::rust_crypto`) in the guest.
  - Link: their `EpochChainLink::new(prev, commit)`.
- **Aggregation journal.** `epoch_chain_link, state_commit, n_events,
  final_source_chain_tips`: their `CmAggrOutput` minus the CM Merkle roots, exactly as
  the HLL port.
- **Query.** `Contains { key }` (their CM `Estimate { key }` shape, 15-byte key_id).
  Journal: chain boundaries, the n state commits, `Contains { key, member }`,
  `support` (sum of the epochs' `total_count`) and `suppressed`. Below
  `MIN_SUPPORT = 10` records the answer is replaced by `member = false` and support 0
  (the key, the query's own input, stays).
- **Probe keys** (`--probe`, comma-separated, one query guest run each): `first` = the
  first record of the last queried epoch (zkSketch's `EXP_QUERY_KEY_MODE=first`, the
  batch's first key; always inserted); `absent` = the first of the absent keys below
  (in no record of the dataset); `key:<u32>` = any key.
- **Versions.** Guests link risc0-zkvm 3.0.5: `guests/Cargo.lock` was derived from
  `../hll/guests/Cargo.lock` (itself from their `Cargo.lock`); only the members'
  entries differ (renamed; `libm` dropped from the core's dependency list). The host
  uses 3.0.6: `Cargo.lock` was derived from `../hll/Cargo.lock` the same way. The
  executor and prover are r0vm 3.0.6 on CPU. ELF md5s are in the logs, image IDs in
  the CSV `image_id` column.

## Running

```bash
cd scripts/baselines/zka/bloom
./run_exec.sh                         # executor: --mode exec, 8 epochs x 2048, queries at n = 1 2 4 8, probes first,absent
PROVE=1 PROBES=first ./run_exec.sh    # the same pipeline PROVED (8 aggregation + 4 query proofs; refuses if 1-min load > 24)
MODE=aggr EPOCH_INDEX=3 ./run_exec.sh # one aggregation guest
MODE=query EPOCHS=4 ./run_exec.sh     # one query guest per probe over epochs 0..4
./gen_upstream.sh --check             # verbatim copies still match the clone at d4a5a9a
CARGO_TARGET_DIR=~/ext-baselines/build/zka-bloom cargo test --release --locked -p zka-bloom-core
```

- Builds go to `$BASELINE_DIR/build/zka-bloom` with `--locked` and
  `RISC0_BUILD_LOCKED=1`. Path dependencies go through `../.zka`, which
  `../common.sh` creates.
- `run_exec.sh` appends to `../results/zka_bloom_exec.csv` (`PROVE=1`:
  `zka_bloom_prove.csv`; any file via `OUT=`). The header is written once, and the
  script refuses to append under a different header. The raw log (provenance header,
  ELF md5s, command, stderr, rows) is the `.log` next to it; paths inside the checkout
  are logged as `$ZKS/...`.
- Env: `MODE EPOCHS EPOCH_SIZE QUERY_AT PROBES EPOCH_INDEX BATCH ABSENT PROVE MAX_LOAD
  OUT SKIP_BUILD KEYS`.
- Every row checks, and the driver exits 1 if any fails (the row is still written):
  - `journal_eq_native`: the guest journal equals the same core function run natively
    (for proved rows the PROVED journal too, asserted).
  - `ref_check`: a separate host filter (own FNV-1a + splitmix64 code, one `Vec<bool>`
    per slice) built from the raw keys has exactly the guest's bits (aggregation: the
    epoch state; query: the OR of the n states) and gives the same answer.
  - accuracy (`accuracy_ok`): `fn_inserted` = inserted keys the filter rejects, must
    be 0 (no false negatives); `fp_absent / absent_checked` = measured false-positive
    rate on `ABSENT` (10,000) keys that occur in no record of the dataset
    (deterministic splitmix64 sequence), next to `fpr_fill` (the product of the 7
    slice fills, the filter's own expected FPR) and `fpr_theory` =
    `(1 - (1 - 1/W)^n)^k`, n = distinct inserted keys.
  - `answer_ok` (query rows): an inserted probe key must be answered `true`; a `true`
    on an absent key is allowed and labelled `(false_positive)`.
  - `prof`: the guest's cycle split per phase, from `env::cycle_count()` marks written
    to STDOUT, not to the journal.
- Proved rows also record `prove_s`, `verify_ms` (best of 5), `receipt_bytes`,
  `s_per_segment`, the prover's segment/cycle stats, `prove_r0vm_peak_rss_mb` (VmHWM of
  the r0vm processes descended from the driver, sampled every 100 ms; nothing is
  signalled) and `contention`: foreign r0vm processes and their CPU seconds (the GK
  driver's measure), plus `other_cores_avg`, the average number of cores busy with
  any process that is not the driver or its descendants (box busy ticks from
  `/proc/stat` minus ours). `arm = proved_contended` when foreign r0vm burned >= 10
  CPU s or `other_cores_avg >= 4`.

## Validation results (2026-10-09; VALIDATION ONLY, not the measurement)

This phase built and validated the guests at tiny scale; the comparison measurement
(8 epochs x 2,048, proved) is to be run later on a quiet machine. All rows are in
`../results/zka_bloom_validation.csv` (+ `.log`). Every row passed every check.

Commands (from this directory's parent; `OUT=../results/zka_bloom_validation.csv`):
`MODE=exec EPOCHS=2 EPOCH_SIZE=256 QUERY_AT="1 2"`, the same at `EPOCH_SIZE=2048`,
`MODE=aggr EPOCH_INDEX=1 EPOCH_SIZE=2048`, `MODE=query EPOCHS=2 EPOCH_SIZE=2048
PROBES=first`, and the proved run `PROVE=1 MAX_LOAD=200 MODE=exec EPOCHS=1
EPOCH_SIZE=256 QUERY_AT=1 PROBES=first`, each as `./run_exec.sh`.

**Aggregation guest `bloom_aggr`** (executor; AOL, batches of 8):

| epoch size | epoch | distinct keys | user cycles | cycles/rec | segments (padded) | read | chain | update | commit | bits set (fill) | false neg. | FP on 10,000 absent | `fpr_fill` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 256 | 0 | 174 | 1,445,206 | 5,645 | 2 (2.10M) | 956,084 | 280,041 | 139,159 | 39,947 | 1,210 (1.06%) | 0 | 0 | 1.5e-14 |
| 256 | 1 | 199 | 1,451,897 | 5,672 | 2 (2.10M) | 962,270 | 280,538 | 139,159 | 39,947 | 1,388 (1.21%) | 0 | 0 | 3.8e-14 |
| 2,048 | 0 | 1,234 | 11,091,956 | 5,416 | 12 (12.06M) | 7,604,628 (68.6%) | 2,238,473 (20.2%) | 1,112,215 (10.0%; 543/rec) | 39,947 | 8,312 (7.25%) | 0 | 0 | 1.1e-8 |
| 2,048 | 1 | 1,252 | 11,098,647 | 5,419 | 12 (12.06M) | 7,610,814 | 2,238,970 | 1,112,215 | 39,947 | 8,419 (7.34%) | 0 | 0 | 1.1e-8 |

**Query guest `bloom_query`** (executor). The cycles are the same at both epoch sizes,
because the state has a fixed size; first number = `first` probe (inserted, answered
`member=true`), second = `absent` probe (answered `member=false`), at both sizes:

| n | user cycles | segments (po2) | read | links | commits | merge (OR) | answer |
|---|---|---|---|---|---|---|---|
| 1 | 180,159 / 180,094 | 1 (18) | 23,043 | 1,427 | 38,724 | 100,810 | 712 / 647 |
| 2 | 343,378 / 343,313 | 1 (19) | 42,538 | 2,960 | 77,326 | 201,229 | 712 / 647 |

- The increment from n = 1 to n = 2 is 163,219 cycles per epoch (read ~20K, commit
  recomputation ~39K, OR merge ~101K, chain link ~1.5K). Linear extrapolation to the
  planned n = 8 gives ~1.3M cycles (2 segments); that is an extrapolation, not a run.
- Merged 2-epoch filter at 2,048 records per epoch: 15,430 bits set (13.45%),
  `fpr_fill` 8.0e-7, `fpr_theory` 8.1e-7, 0 false positives in 10,000 absent keys
  (expected 0.008). At the planned 8 x 2,048 records (8,433 distinct AOL keys) the
  textbook FPR is (1 - e^(-8433/16384))^7 = 1.7e-3, about 17 of the 10,000 absent
  keys, so the measured rate becomes informative there.
- The single-guest modes (`MODE=aggr EPOCH_INDEX=1`, `MODE=query EPOCHS=2`) reproduce
  the pipeline's rows exactly (11,098,647 and 343,378 cycles): the chain carried from
  the guest journals equals the natively computed one.

**Proved run** (validates the `--prove` path; NOT a timing measurement: the shared
box had a concurrent job, `other_cores_avg` 3.0, 1-minute load 4.2 before and up to
35.4 during, including this prover). `ProverOpts::succinct()`, CPU r0vm 3.0.6; both
proved journals were asserted equal to the native output:

| guest | input | segments | prove_s | s/segment | verify (best of 5) | receipt | r0vm peak RSS |
|---|---|---|---|---|---|---|---|
| `bloom_aggr` | epoch 0, 256 records | 2 (po2 20, 20) | 58.5 | 29.26 | 9.7 ms | 224,554 B | 9,389 MB |
| `bloom_query` | n = 1, `first` probe | 1 (po2 18) | 9.4 | 9.35 | 9.7 ms | 224,162 B | 2,351 MB |

## Reused from upstream (d4a5a9a)

- **By path dependency** (unmodified crates): `zkvm_common::Event` and `make_key_id`;
  `aggregator_core::{BatchInput, CmAggrInput, EpochChainLink, batch_chain_hash,
  key_to_u64, CM_SEEDS}`; `querier_core::MIN_SUPPORT`. `CmAggrInput` is the
  aggregation input type as is (field-for-field their samples and histogram input).
- **Copied verbatim** because they are private upstream: `core/src/upstream_verbatim.rs`,
  generated and re-diffed by `gen_upstream.sh`, byte-identical to
  `../hll/core/src/upstream_verbatim.rs`:
  - from `aggregator/core/src/lib.rs`: `TAG_SHARD_CHAIN` (:57), `sha256_bytes`
    (:93-99), `events_commit` (:295-305), `chain_tips_to_sorted_vec` (:331-339),
    `verify_and_compute_chain` (:499-603);
  - from `querier/core/src/lib.rs`: `TAG_EPOCH_CHAIN` (:41),
    `verify_epoch_chain_integrity` (:98-136).
- **Structure mirrored step for step** (cited in `core/src/lib.rs`):
  `process_cm_aggr_with_state` (chain verification, flatten, build, commit, link,
  output) and `run_cm_query` (chain checks, commit checks, boundaries, state commits,
  merge, answer, `suppress_if_low_support`); the guest `main`s mirror `aggr_cm` and
  `querier-guest-cm`, with the same risc0-zkvm feature sets.
- **Position hash:** their `cm_bucket_index` formula, with W and per-slice seeds.
- **Ours.** The Bloom insert / lookup / OR merge, the 4 extra seeds, the state type,
  its tag and packing (the HLL port's `packed_bytes`), the cycle probes, the host driver
  (independent reference, accuracy, `exec` pipeline mode, RSS/contention sampler after
  `../gk/host`), the runner.

## Caveats

- **Ours (†).** zk-Analytics ships no Bloom filter. Mark every row † and never call it
  "zk-Analytics' Bloom filter".
- **Data-dependent cost.** Plain code, no padding, exactly as their guests: cycles
  leak input properties. The aggregation cost depends on the record count and batch
  size (read + chain dominate); the update phase was identical on epochs 0 and 1
  (1,112,215 cycles at 2,048 records), and epoch 1's +6.7K cycles come from the source
  tip it carries in. The lookup short-circuits, so an absent key costs ~65 cycles less
  than a member.
- **The state encoding is a ~4x lever on the query.** risc0's serde reads a plain
  `Vec<u32>` (or `Vec<u8>`) one element per word at ~150 cycles per word, but a byte
  string in bulk. A development build that kept the filter as `Vec<u32>` words (one
  word per 32 bits, default serde) spent 559,214 cycles reading one epoch state and
  702,100 cycles on the n = 1 query, against 23,043 and 180,159 with the packed bytes
  (same records; that build is not in the tree). The packed form is the headline: it is
  the cheaper (conservative) baseline, as for HLL.
- **Byte-wise OR merge.** The query merges with a byte loop, ~7 cycles per byte
  (100,810 cycles per epoch). A word-wise OR would need the bytes converted, which
  costs about what it saves in safe Rust; no `unsafe` reinterpretation is used.
- **Aggregation is dominated by their input format.** About 69% of `bloom_aggr`'s
  cycles deserialize their `Event` batches (~3,710 cycles per record, the same as the
  HLL port) and 20% verify the batch chain. Any summary in their framework pays this.
- **Cheaper than a literal port.** No per-type Merkle root in the aggregation journal
  (no query of theirs reads one); the FNV fold is hoisted out of the per-slice loop;
  the state is committed in one SHA-256 `update`.
- **Inherited from their query code, unchanged.** Chain and commit checks run only
  when `epoch_chain_links` is non-empty; a link whose `prev_chain_hash` is genesis
  starts a new chain; commitments are unsalted hashes (their own security note: no
  hiding).
- **The query cost excludes aggregation receipts.** Each query also needs the n
  per-epoch aggregation receipts, verified separately (their tree has no
  `env::verify`), so the aggregation cost recurs once per epoch.
- **MODELED is a model.** `MODELED_prove_s = segments x 30.1 s` (envelope 29.73-30.79,
  the CM anchors in `../README.md`); small and partial segments prove faster.
- **ELF md5s and image IDs depend on the absolute source path** (panic strings carry
  it); cycle counts do not. The validation rows were built from a worktree path, so
  their `image_id`s differ from a build in the main checkout.

## Files

| file | purpose |
|---|---|
| `core/` | `zka-bloom-core` (no_std): the filter, epoch type, aggregation, query; `upstream_verbatim.rs`; unit tests (CM-index agreement, union = OR, no false negatives, FPR vs theory, bit layout, tamper / reorder / forged batch, suppression, serde packing) |
| `methods/`, `guests/aggr`, `guests/query` | risc0 methods crate and the guests `bloom_aggr`, `bloom_query` |
| `host/` | driver `bloom` (modes `exec`, `aggr`, `query`; `--prove`) |
| `run_exec.sh`, `bloom_common.sh` | runner (executor or `PROVE=1`) and its build/log helpers |
| `gen_upstream.sh` | regenerates / checks the verbatim copies |
