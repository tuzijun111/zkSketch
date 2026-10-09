# KMV / bottom-k in zk-Analytics' architecture (our port †)

zk-Analytics (Zhu et al., SIGCOMM '26; clone `d4a5a9a`, read-only) ships three epoch
summaries (samples, histogram, cm) and no distinct-count sketch. This directory adds a
KMV (k minimum values, bottom-k) summary to **their** pipeline with **their**
general-purpose method: the textbook plaintext algorithm, written in ordinary Rust and
executed as a RISC Zero guest, exactly like `../hll/`. It is our instantiation of their
per-epoch / query-time-merge architecture, so label it as ours (†) and never call it
"zk-Analytics' KMV". Nothing from zkSketch is used here: no oblivious padding, no
memory checking, no sorting certificates, no Poseidon, and not zkSketch's batch rule
or certificate (zkSketch's `kmv` leaf certifies a verified sorted reduction over
27-bit Poseidon2 hashes; this guest just executes per-record bottom-k insertion over
64-bit hashes).

## What runs

| step | guest | what it does |
|---|---|---|
| aggregation, one per epoch | `kmv_aggr` | verifies the source SHA-256 batch hash chain (their code), builds the epoch's bottom-k set (k = 1,024 smallest distinct 64-bit key hashes) from scratch one record at a time, hashes the state with an unsalted tagged SHA-256, and links that commitment into the epoch chain (their `EpochChainLink::new`) |
| query over n epochs | `kmv_query` | re-verifies the n epoch chain links (their code), recomputes each epoch's state commitment, merges the n sets (bottom-k of their union), and commits the distinct-count answer with the chain boundaries and the n state commits (their low-support suppression, `MIN_SUPPORT = 10`) |

The host driver `kmv` (`host/src/main.rs`) has three modes; every guest run is
executed, and also proved with `--prove` (`ProverOpts::succinct()`, their shipped
tier, CPU r0vm):

| `--mode` | runs |
|---|---|
| `aggr --epoch-index i` | `kmv_aggr` on epoch i (earlier epochs aggregated natively only to carry the chain tips) |
| `query --epochs n` | epochs 0..n aggregated natively, then `kmv_query` over the n states |
| `exec --epochs N --query-at 1,2,4,8` | the whole per-epoch pipeline: `kmv_aggr` on every epoch in order, each epoch's `prev_chain_hash` and source tips taken from the previous **guest journal** (as their aggregator host carries them), and after epoch n the `kmv_query` guest over epochs 0..n for every n in `--query-at` |

### Configuration

- **Records.** Exactly as `../bloom/` and `../hll/`: `data/aol.keys`, epoch e = keys
  `[e*m, (e+1)*m)`, m = `--epoch-size` (default 2,048); `key_id =
  Event::make_key_id(0, key)`, `value = 1`, `ts` = global index; one source, batches
  of 8; batch chain, `source_batch_seq`, tips and the epoch chain carried across
  epochs.
- **Hash.** The HLL port's 64-bit hash: their FNV-1a `key_to_u64`
  (`aggregator/core/src/lib.rs:342`), XOR `(seed << 32 | seed)` with their CM row-0
  seed `0x6d0f27bd`, then the splitmix64 finaliser of their `cm_bucket_index`
  (`:1055-1063`) without the `% CM_COLS`. Values are taken as uniform on `[0, 2^64)`.
- **Sketch.** KMV of Bar-Yossef et al. (RANDOM 2002) / bottom-k of Cohen and Kaplan
  (PODC 2007), k = 1,024 (zkSketch's KMV k).
  - Per record, `kmv_insert`: keep h if fewer than k values are held, or if h is
    below the current k-th smallest and not already held (then the largest is
    evicted); duplicates change nothing. The set is an ordered `BTreeSet<u64>`.
  - State = `{ total_count: u64, values: Vec<u64> }`, the at most k values ascending.
- **Commitment.** `SHA-256("ZKTLM_KMV_STATE_COMMIT_V1" || total_count_be ||
  len_be(u32) || values as big-endian u64s)`, in the style of their
  `cm_epoch_state_commit`. The tag is ours. Their risc0-accelerated SHA-256 in the
  guest. Link: their `EpochChainLink::new(prev, commit)`.
- **Wire format.** The values travel as one packed byte string (their big-endian
  image; `packed_u64`, the pattern of the HLL port's `packed_bytes`), read in bulk and
  converted back in the guest. See Caveats.
- **Aggregation journal.** `epoch_chain_link, state_commit, n_events,
  final_source_chain_tips`: their `CmAggrOutput` minus the CM Merkle roots, exactly as
  the HLL port.
- **Merge.** Bottom-k of the union of the n epoch sets, folded epoch by epoch with a
  linear two-pointer merge of the ascending lists that drops duplicates and stops after
  k outputs (`merge_bottom_k`).
- **Estimator.** With D = the number of merged values:
  - D < k: the answer is D, the exact number of distinct hash values
    (`exact_count = true`);
  - D = k: the unbiased estimator (k-1)/U_(k) of Beyer et al. (SIGMOD 2007), U_(k) =
    v_k / 2^64 the k-th smallest value scaled to [0, 1). It is evaluated in integer
    arithmetic as `floor((k-1) * 2^64 / v_k)` in u128 (exact: (k-1) * 2^64 < 2^75),
    saturated to `u64::MAX` (reachable only if v_k = k-1, i.e. the hashes 0..k-1). This
    is zkSketch's `kmv_estimate` formula with its 2^27 hash range replaced by 2^64.
  - The relative standard error is 1/sqrt(k-2) = 3.13% at k = 1,024.
  - Journal: `Estimate { estimate, kept, v_k, exact_count }`, `support` (sum of the
    epochs' `total_count`) and `suppressed`; below `MIN_SUPPORT` every numeric field is
    zeroed (their rule).
- **Versions.** As `../bloom/`: guests risc0-zkvm 3.0.5 (`guests/Cargo.lock` derived
  from `../hll/guests/Cargo.lock`, itself from their lock), host 3.0.6 (`Cargo.lock`
  derived from `../hll/Cargo.lock`); only the members' entries differ. r0vm 3.0.6 on
  CPU.

## Running

```bash
cd scripts/baselines/zka/kmv
./run_exec.sh                         # executor: --mode exec, 8 epochs x 2048, queries at n = 1 2 4 8
PROVE=1 ./run_exec.sh                 # the same pipeline PROVED (8 aggregation + 4 query proofs; refuses if 1-min load > 24)
MODE=aggr EPOCH_INDEX=3 ./run_exec.sh # one aggregation guest
MODE=query EPOCHS=4 ./run_exec.sh     # one query guest over epochs 0..4
./gen_upstream.sh --check             # verbatim copies still match the clone at d4a5a9a
CARGO_TARGET_DIR=~/ext-baselines/build/zka-kmv cargo test --release --locked -p zka-kmv-core
```

- Builds go to `$BASELINE_DIR/build/zka-kmv` (`--locked`, `RISC0_BUILD_LOCKED=1`).
- `run_exec.sh` appends to `../results/zka_kmv_exec.csv` (`PROVE=1`:
  `zka_kmv_prove.csv`; any file via `OUT=`), with the same header guard and raw log as
  `../bloom/run_exec.sh`. Env: `MODE EPOCHS EPOCH_SIZE QUERY_AT EPOCH_INDEX BATCH
  PROVE MAX_LOAD OUT SKIP_BUILD KEYS`.
- Every row checks, and the driver exits 1 if any fails (the row is still written):
  - `journal_eq_native`: the guest journal equals the same core function run natively
    (for proved rows the PROVED journal too, asserted);
  - `ref_check`: a separate host reference (own FNV-1a + splitmix64 code; every
    distinct hash of the covered keys, sorted, first k) equals the guest's epoch state
    (aggregation) / merged set (query), and the f64 estimator `(k-1) / (v_k / 2^64)`
    agrees with the integer answer within 1;
  - accuracy: `exact` = distinct keys of the covered records, `rel_err` against it,
    `std_err` = 1/sqrt(k-2); `accuracy_ok` = (answer == exact) on the exact branch,
    |rel_err| <= 5 std_err on the estimator branch (a sanity bound, not a claim).
    Aggregation rows report the native estimate of the committed epoch state (the
    aggregation journal holds commitments only). A suppressed query (support < 10
    records) has `estimator = suppressed` and `accuracy_ok = -`.
- Proved rows carry the same prove, RSS and contention columns as `../bloom/`
  (`arm = proved_contended` when foreign r0vm burned >= 10 CPU s or
  `other_cores_avg >= 4`).

## Validation results (2026-10-09; VALIDATION ONLY, not the measurement)

This phase built and validated the guests at tiny scale; the comparison measurement
(8 epochs x 2,048, proved) is to be run later on a quiet machine. All rows are in
`../results/zka_kmv_validation.csv` (+ `.log`). Every row passed every check.

Commands (`OUT=../results/zka_kmv_validation.csv`): `MODE=exec EPOCHS=2
EPOCH_SIZE=256 QUERY_AT="1 2"`, the same at `EPOCH_SIZE=2048`, `MODE=aggr
EPOCH_INDEX=1 EPOCH_SIZE=2048`, `MODE=query EPOCHS=2 EPOCH_SIZE=2048`, and the proved
run `PROVE=1 MAX_LOAD=200 MODE=exec EPOCHS=1 EPOCH_SIZE=256 QUERY_AT=1`, each as
`./run_exec.sh`.

**Aggregation guest `kmv_aggr`** (executor; AOL, batches of 8). The answer column is
the native estimate of the committed epoch state:

| epoch size | epoch | distinct keys | user cycles | cycles/rec | segments (padded) | read | chain | update | commit | kept | answer (rel. err) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 256 | 0 | 174 | 1,405,459 | 5,490 | 2 (1.57M) | 956,084 | 280,039 | 125,272 | 14,096 | 174 | 174 (exact branch) |
| 256 | 1 | 199 | 1,418,452 | 5,541 | 2 (1.57M) | 962,270 | 280,536 | 129,988 | 15,682 | 199 | 199 (exact branch) |
| 2,048 | 0 | 1,234 | 11,115,930 | 5,428 | 12 (12.06M) | 7,604,628 (68.4%) | 2,238,471 (20.1%) | 1,107,941 (10.0%; 541/rec) | 68,210 | 1,024 | 1,232 (-0.16%) |
| 2,048 | 1 | 1,252 | 11,115,970 | 5,428 | 12 (12.06M) | 7,610,814 | 2,238,968 | 1,101,290 | 68,210 | 1,024 | 1,235 (-1.36%) |

**Query guest `kmv_query`** (executor):

| epoch size | n | merged values | user cycles | segments (po2) | read | links | commits | merge | estimate | answer / exact (rel. err) |
|---|---|---|---|---|---|---|---|---|---|---|
| 256 | 1 | 174 | 56,610 | 1 (17) | 23,524 | 1,445 | 12,854 | 4,172 | 116 | 174 / 174 (exact branch) |
| 256 | 2 | 365 | 109,515 | 1 (18) | 46,919 | 2,995 | 27,179 | 14,636 | 116 | 365 / 365 (exact branch) |
| 2,048 | 1 | 1,024 | 151,365 | 1 (18) | 45,380 | 1,445 | 66,968 | 22,021 | 1,052 | 1,232 / 1,234 (-0.16%) |
| 2,048 | 2 | 1,024 | 296,524 | 1 (19) | 89,993 | 2,995 | 133,821 | 50,924 | 1,121 | 2,290 / 2,372 (-3.46%) |

- Both estimator branches ran: the exact branch at 256 records per epoch (fewer than
  k distinct hashes) and the (k-1)/U_(k) branch at 2,048. The -3.46% at n = 2 is 1.1
  standard errors (1/sqrt(1022) = 3.13%). One hash draw; no seed spread was run.
- With full epoch states (2,048 records) the query costs ~145K cycles per epoch (read
  ~45K, commit recomputation ~67K, merge ~22-29K). Linear extrapolation to the planned
  n = 8 gives ~1.2M cycles (2 segments); that is an extrapolation, not a run.
- The single-guest modes (`MODE=aggr EPOCH_INDEX=1`, `MODE=query EPOCHS=2`) reproduce
  the pipeline's rows exactly (11,115,970 and 296,524 cycles).

**Proved run** (validates the `--prove` path; NOT a timing measurement: the shared
box had a concurrent job, `other_cores_avg` 2.0-2.3, 1-minute load up to 42.5
including this prover and the Bloom prove just before it). `ProverOpts::succinct()`,
CPU r0vm 3.0.6; both proved journals were asserted equal to the native output:

| guest | input | segments | prove_s | s/segment | verify (best of 5) | receipt | r0vm peak RSS |
|---|---|---|---|---|---|---|---|
| `kmv_aggr` | epoch 0, 256 records | 2 (po2 20, 19) | 45.6 | 22.81 | 9.8 ms | 224,554 B | 9,387 MB |
| `kmv_query` | n = 1 | 1 (po2 17) | 6.0 | 6.04 | 9.7 ms | 224,082 B | 1,430 MB |

## Reused from upstream (d4a5a9a)

- **By path dependency** (unmodified crates): `zkvm_common::Event` and `make_key_id`;
  `aggregator_core::{BatchInput, CmAggrInput, EpochChainLink, batch_chain_hash,
  key_to_u64, CM_SEEDS}`; `querier_core::MIN_SUPPORT`. `CmAggrInput` is the
  aggregation input type as is.
- **Copied verbatim** because they are private upstream: `core/src/upstream_verbatim.rs`,
  generated and re-diffed by `gen_upstream.sh`, byte-identical to
  `../hll/core/src/upstream_verbatim.rs` (`TAG_SHARD_CHAIN`, `sha256_bytes`,
  `events_commit`, `chain_tips_to_sorted_vec`, `verify_and_compute_chain`;
  `TAG_EPOCH_CHAIN`, `verify_epoch_chain_integrity`; line ranges in the file).
- **Structure mirrored step for step**: `process_cm_aggr_with_state` and
  `run_cm_query`; the guest `main`s mirror `aggr_cm` and `querier-guest-cm`, with the
  same risc0-zkvm feature sets.
- **Hash:** their `key_to_u64` + `cm_bucket_index` finaliser (the HLL port's hash).
- **Ours.** The KMV insert, the bottom-k merge, the estimator, the state type, its tag
  and packing, the cycle probes, the host driver (independent reference, accuracy,
  `exec` pipeline mode, RSS/contention sampler after `../gk/host`), the runner.

## Caveats

- **Ours (†).** zk-Analytics ships no KMV. Mark every row † and never call it
  "zk-Analytics' KMV".
- **Data-dependent cost.** Plain code, no padding: the update phase depends on how
  many records enter or evict from the ordered set (epochs 0 and 1 at 2,048 records:
  1,107,941 vs 1,101,290 cycles), and the merge on how the epoch sets interleave.
  Cycles leak input properties, exactly as in their guests.
- **The state encoding is a lever.** risc0's serde reads a plain `Vec<u64>` one word
  at a time (~150 cycles per word, 2 words per value: ~0.3M cycles per full epoch
  state, by the per-word cost measured for the HLL and Bloom ports; not measured for
  KMV). The packed byte image is read in bulk and converted (45,380 cycles for one
  full state's read phase). The packed form is the headline: it is the cheaper
  (conservative) baseline, as for HLL.
- **Aggregation is dominated by their input format.** About 68% of `kmv_aggr`'s
  cycles deserialize their `Event` batches and 20% verify the batch chain; the KMV
  update is ~10%.
- **Cheaper than a literal port.** No per-type Merkle root in the aggregation journal;
  the state is committed in one SHA-256 `update`; the query merges linearly instead of
  sorting the concatenated sets.
- **64-bit vs 27-bit hash.** zkSketch's KMV hashes to 27 bits (a field constraint);
  this port uses 64 bits, as a plaintext implementation would. Collisions are
  negligible here (about n^2 / 2^65), so the two estimates differ by the hash draw,
  not by a systematic undercount; compare them by error distribution, not row by row.
- **Inherited from their query code, unchanged.** Chain and commit checks run only
  when `epoch_chain_links` is non-empty; a genesis `prev_chain_hash` starts a new
  chain; commitments are unsalted hashes (no hiding).
- **The query cost excludes aggregation receipts** (verified separately, once per
  epoch, as for every port here).
- **MODELED is a model** (`segments x 30.1 s`, see `../README.md`).
- **ELF md5s and image IDs depend on the absolute source path**; cycle counts do not.
  The validation rows were built from a worktree path.

## Files

| file | purpose |
|---|---|
| `core/` | `zka-kmv-core` (no_std): hash, bottom-k insert, merge, estimator, epoch type, aggregation, query; `upstream_verbatim.rs`; unit tests (per-epoch state = reference bottom-k, merge = union, insertion order, merge edges, exact branch, estimator integer arithmetic and saturation, tamper / reorder / forged batch, suppression, serde packing) |
| `methods/`, `guests/aggr`, `guests/query` | risc0 methods crate and the guests `kmv_aggr`, `kmv_query` |
| `host/` | driver `kmv` (modes `exec`, `aggr`, `query`; `--prove`) |
| `run_exec.sh`, `kmv_common.sh` | runner (executor or `PROVE=1`) and its build/log helpers |
| `gen_upstream.sh` | regenerates / checks the verbatim copies |
