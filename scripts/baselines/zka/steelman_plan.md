# M6 Steelman Probe — patching zk-Analytics for cross-epoch CM state + receipt folding

Target: `/home/binbin/ext-baselines/zka` @ `d4a5a9a9` ("Fix artifact proof waits and run benchmark queries locally").
Prover: risc0 `3.0.5` per `Cargo.lock:3767-3768` (toolchain on PATH is 3.0.6 — see §6 note).
Matched geometry: `CM_ROWS=3`, `CM_COLS=1024` (`aggregator/core/src/lib.rs:39-40`), `CM_SEEDS` (`:41`),
`CM_TOPK_SLOTS` build-time env (`:42`, `aggregator/core/build.rs:13`, default `100`).

**Status: PLAN ONLY. No patch applied, no prover run.**

---

## 1. Premise verification (all VERIFIED by grep over the tree, `/target/` excluded)

### 1.1 No risc0 composition anywhere

| Probe | Hits |
|---|---|
| `env::verify` | **0** |
| `add_assumption` | **0** |
| `assumption` (case-insensitive, `*.rs`/`*.toml`/`*.md`) | **0** |
| `composit` / `recursion` / `fold` | **0 relevant** — only `Iterator::fold`/`rfold` at `aggregator/host/src/bin/recovery_bench.rs:211`, `aggregator/core/src/merkle.rs:165`, `querier/core/src/merkle.rs:143` |

VERIFIED: zk-Analytics performs **no** proof composition. Every epoch and every query yields an
independent, separately-verified receipt.

### 1.2 Every zkVM prove site uses `ProverOpts::succinct()`

| file:line | call |
|---|---|
| `aggregator/host/src/main.rs:1959` | `prover.prove_with_opts(env, elf, &ProverOpts::succinct())` |
| `aggregator/host/src/main.rs:2132` | `prove_with_opts(..., &ProverOpts::succinct())` |
| `aggregator/host/src/main.rs:2309` | `prove_with_opts(..., &ProverOpts::succinct())` — **the CM epoch path** |
| `aggregator/host/src/main.rs:3827-3828` | `let opts = ProverOpts::succinct();` → `prove_with_opts(env, AGGR_SAMPLES_ELF, &opts)` |
| `aggregator/host/src/main.rs:3919-3920` | … `AGGR_HISTOGRAM_ELF` |
| `aggregator/host/src/main.rs:4012-4013` | … `AGGR_CM_ELF` — **the CM bench path** |
| `querier/host/src/bin/bench_queries.rs:459,462` | histogram query |
| `querier/host/src/bin/bench_queries.rs:526,529` | **CM query** |
| `querier/host/src/bin/bench_queries.rs:599,602` | samples query |
| `querier/host/src/bin/bench_queries.rs:663,666` | raw query |
| `querier/server/src/main_parts/common.rs:983,985` | server query path |

(`tree.prove(...)` at `aggregator/core/src/lib.rs:462`, `aggregator/core/src/merkle.rs:332,342,355`,
`querier/core/src/merkle.rs:295,305,318` are **Merkle** inclusion proofs, not zkVM proofs.)

VERIFIED: `ProverOpts::succinct()` = `ReceiptKind::Succinct` + poseidon2
(`risc0-zkvm-3.0.6/src/host/client/prove/opts.rs:146-155`). This **is** the composable receipt kind —
`resolve()` consumes `SuccinctReceipt` directly
(`risc0-zkvm-3.0.6/src/host/server/prove/mod.rs:376-379`).

> **Conclusion.** They are already paying the full cost of succinct receipts — the exact prerequisite
> for composition — and get none of the benefit. Folding is available to them for free at the
> receipt-kind level. Our claim must not be "they cannot compose"; it must be "they do not, and here
> is what changes if they do."

### 1.3 CM state is zeroed every epoch

`aggregator/core/src/lib.rs:1240-1244`:
```rust
let mut total_sum = 0u64;
let mut table: Box<[[u32; CM_COLS]; CM_ROWS]> = Box::new([[0u32; CM_COLS]; CM_ROWS]);
let mut heap_keys = [[0u8; KEY_BYTES_LEN]; CM_TOPK_SLOTS];
let mut heap_vals = [0u64; CM_TOPK_SLOTS];
let mut heap_occ  = [0u8; CM_TOPK_SLOTS];
```
`CmAggrInput` (`:946-954`) carries **only** `prev_chain_hash`, `batches`, `prev_source_chain_tips`.
The hash chain (`EpochChainLink`, `:135-156`) chains *commitments to* independent per-epoch tables;
it never feeds a table back in. VERIFIED.

### 1.4 The query guest re-derives the prefix, Θ(n)

`querier/core/src/lib.rs:249-295`, `CmQueryInput.epoch_states: Vec<CmEpochState>` (`:190`):
- `:273-280` — one `cm_epoch_state_commit(state)` **per epoch** (SHA over 12,288 B of table + heap).
- `:286-295` — element-wise sum of all `n` tables into `sum_counts`, i.e. `n · CM_ROWS · CM_COLS`
  = `n · 3072` additions.

VERIFIED: query cost is Θ(n · d · w) in the number of epochs in range.

---

## 2. Cost model (fitted from our own measurements — used throughout below)

Fit `cycles(n) = F + c·n` at `TOPK=100, keys=1024` from `results/a2_anchor.csv` (n=512) and
`results/a1_cycles.csv` (n=16384):

```
c = 18,131.6 cycles/record      F = 11,237,301 cycles/epoch (fixed)
```

Fixed-cost decomposition (SHA-256 compressions per epoch):
`3 row roots × (1024 leaves + 1023 nodes)` = 6141 (`cm_row_root`, `lib.rs:1075-1088`)
`+ 3` row-tree nodes `+ 255` heap root (128 padded leaves, `cm_heap_root`, `:1153-1175`)
`+ 231` state commit (`cm_state_commit`, `:1188-1208`) = **6630 compressions**
→ `11,237,301 / 6630 = ` **1,695 cycles per SHA-256 compression**.

> **Correction (2026-09-13):** the software-SHA-256 conclusion in the next paragraph is refuted.
> Their guest imports `risc0_zkvm::sha::rust_crypto` (the accelerated implementation) under
> `cfg(target_os = "zkvm")` and in `merkle.rs`, and patching `sha2` to risc0's fork leaves the cycle
> count unchanged (`sha_accel_control.sh`, `results/sha_accel_control.csv`). 1,695 cycles per
> compression is a fitted constant, not a SHA cost; estimates below that price hashing with it are unverified.

That number is the load-bearing one. It confirms — independently — that **the guests use software
SHA-256, not the risc0 precompile**: there is no `[patch.crates-io]` anywhere in the tree
(`Cargo.toml`, `.cargo/config`, all guest manifests checked), and `aggregator/core/Cargo.toml:7` /
`querier/core/Cargo.toml:11` pull plain `sha2 0.10`. 1,695 cyc/block is the right order for
software SHA-256 under rv32im; the precompile would be ~1-2 orders cheaper.

**Non-circular cross-check.** Re-deriving `F` from the compression count at each `TOPK` and
subtracting from the measured `cycles_per_record` gives the marginal per-record cost, and the
implied per-heap-slot linear-scan cost (`cm_heap_update`, `:1103-1141`) agrees to 6%:

| TOPK | heap leaves | derived F | marginal c (cyc/rec) | implied cyc per heap slot |
|---|---|---|---|---|
| 1 | 1 | 10,744,605 | 5,490 | — |
| 8 | 8 | 10,771,725 | 6,334 | 120.6 |
| 100 | 128 | 11,237,850 | 18,132 | 127.7 |

The model reproduces the measured `n=16384, TOPK=1` total to within 0.001%
(100,696,064 predicted vs 100,695,728 measured, `results/zka_matched.csv`).

---

## 3. Part (a) — carry the CM table across epochs

### 3.1 Design

Add `prev_state` + `prev_state_commit` to `CmAggrInput`; the guest verifies
`cm_epoch_state_commit(prev_state) == prev_state_commit` and seeds the table from it; the journal
re-exposes `prev_state_commit` so an external verifier chains epochs by
`epoch_i.prev_state_commit == epoch_{i-1}.state_commit`.

Two soundness notes, both real:
- `cm_epoch_state_commit` (`lib.rs:1008-1029`) and `cm_state_commit` (`:1188-1208`) hash the same
  preimage in the same order (TAG ‖ total_sum ‖ table row-major ‖ heap). **There is no test in the
  tree asserting they agree** (grep for `cm_epoch_state_commit` in `aggregator/*/tests` → 0 hits).
  The patch must add one; the whole binding rests on it.
- Neither function checks `counts.len()`/`heap_*.len()`. A short host-supplied vector panics rather
  than forging (liveness, not soundness) — the same latent pattern already exists unguarded at
  `querier/core/src/lib.rs:275`. Add explicit `assert!`s.

### 3.2 Diff plan

| # | file:line (anchor) | change | ~lines |
|---|---|---|---|
| A1 | `aggregator/core/src/lib.rs:946-954` (`CmAggrInput`) | add `#[serde(default)] pub prev_state: Option<CmEpochState>` and `#[serde(default)] pub prev_state_commit: [u8; HASH_BYTES_LEN]` | 8 |
| A2 | `aggregator/core/src/lib.rs:989-1004` (`impl From<&CmState> for CmEpochState`) | add the inverse `fn cm_state_from_epoch_state(&CmEpochState) -> CmState` with length asserts | 22 |
| A3 | `aggregator/core/src/lib.rs:1240-1244` | replace the five zero-inits with: if `prev_state` is `Some`, assert `cm_epoch_state_commit(p) == input.prev_state_commit`, then seed `table`/`heap_*`/`total_sum` from `cm_state_from_epoch_state(p)`; else keep zeros and assert `prev_state_commit == [0u8;32]` | 22 |
| A4 | `aggregator/core/src/lib.rs:1033-1053` (`CmAggrOutput`) | add `pub prev_state_commit: [u8; HASH_BYTES_LEN]` | 4 |
| A5 | `aggregator/core/src/lib.rs:1290-1298` (`let out = CmAggrOutput {`) | populate `prev_state_commit: input.prev_state_commit` | 1 |
| A6 | `aggregator/core/src/lib.rs:1241,1250` | widen `table` to `u64` (decl `:1241`, add `:1250`) **or** add an explicit `assert!(v <= u32::MAX - delta)`; see §5 R2 | 6 |
| A7 | `aggregator/methods/guest_cm/src/main.rs` | **zero lines.** The guest is `env::read` → `process_cm_aggr` → `env::commit` (`:12-14`); all logic lives in core | 0 |
| A8 | `aggregator/host/src/main.rs:2294-2302` and `:3988-3994` | thread `prev_cm_state: Option<CmEpochState>` + `prev_cm_state_commit` alongside the existing `prev_chain_hash` (declared `:1446`, `:3696`; updated `:2336`, `:4047`) | 20 |
| A9 | `native_baseline/src/main.rs:210,323,485` | add the two new fields at three `CmAggrInput` construction sites | 12 |
| A10 | `/home/binbin/ext-baselines/cyc/src/bin/cyc.rs` (`CmAggrInput` at ~line 28) and `src/bin/cmp.rs` | add the two fields; add a `--carry` scale flag | 14 |
| A11 | `aggregator/core/src/lib.rs` tests | (i) `cm_state_commit ≡ cm_epoch_state_commit`; (ii) carry-equivalence: 2 epochs × 512 logs with carry produces the identical `table`/`total_sum` as 1 epoch × 1024 | 45 |

**≈ 105 lines of production code, ≈ 155 with tests.** Touches 5 files. The guest is untouched — but
the guest ELF and image ID still change (core is a guest dependency), so a full guest rebuild is
required and every `AGGR_CM_ID` consumer must be re-linked.

### 3.3 What it costs their prover — small

Marginal in-guest hashing = **exactly one additional `cm_state_commit`**, a cost the epoch already
pays once (`lib.rs:1285`). At 1,695 cyc/compression:

| config | state-commit preimage | blocks | extra cycles | share of epoch |
|---|---|---|---|---|
| TOPK=1, n=16,384 | 12,344 B | 194 | 328,814 | **0.33%** |
| TOPK=1, n=1,024 | 12,344 B | 194 | 328,814 | **2.01%** |
| TOPK=100, n=16,384 | 14,720 B | 231 | 391,545 | 0.13% |

Plus `env::read` of a 12,288 B table (~3,072 words) — bounded well under 10^5 cycles, to be
measured, not asserted.

**Methodological warning for the lead:** at `n=1024`, the fixed overhead `F` is 66% of the epoch, so
the state-carry delta reads **6× larger** relatively (2.01%) than it does at the matched full scale
(0.33%). Do not quote the small-scale percentage as the headline.

**Does state carry serialize their proving pipeline? NO — and we must not claim it does.** The host
runs `process_cm_aggr_with_state` **natively first** (`main.rs:2299-2302`, `:3994`) and only then
proves, checking the journal against the native result (`:4021+`). So the host can compute all `N`
states natively in one pass and then fan out `N` independent epoch proofs exactly as today. State
carry costs them no parallelism.

---

## 4. Part (b) — fold per-epoch receipts

### 4.1 API (risc0 3.0.6, verified in crate source)

- Guest: `risc0_zkvm::guest::env::verify(image_id: impl Into<Digest>, journal: &[impl Pod])`
  — `risc0-zkvm-3.0.6/src/guest/env/verify.rs:46`. Emits `sys_verify_integrity` and pushes an
  `Assumption` (`:55-64`). Requires the assumed receipt to have `ExitCode::Halted(0)`/`Paused(0)`,
  an **empty assumptions list**, and an all-zero input hash (`:31-33`).
- Host: `ExecutorEnv::builder().add_assumption(receipt)` —
  `risc0-zkvm-3.0.6/src/host/client/env.rs:419-426`; `impl From<Receipt> for AssumptionReceipt` at
  `src/receipt.rs:690-695`.
- Resolution: for each assumption the prover runs one recursion-circuit `resolve` —
  `src/host/server/prove/mod.rs:374-388`, trait decl `:111-115`.

### 4.2 Folding guest (self-recursive chain, 1 new crate)

```rust
// aggregator/methods/guest_fold/src/main.rs
#![no_main] #![no_std]
extern crate alloc;
use risc0_zkvm::{guest::env, sha::Digest, serde::to_vec};
use aggregator_core::{CmAggrOutput, FoldJournal, HASH_BYTES_LEN};
risc0_zkvm::guest::entry!(main);

fn main() {
    let aggr_cm_id: Digest              = env::read();  // AGGR_CM_ID
    let self_id:    Digest              = env::read();  // THIS guest's image id (see gotcha)
    let prev:  Option<FoldJournal>      = env::read();
    let epoch: CmAggrOutput             = env::read();

    env::verify(aggr_cm_id, &to_vec(&epoch).unwrap()).unwrap();

    let (chain_first, first_state_commit, n) = match prev {
        Some(p) => {
            assert_eq!(p.self_id, self_id);                       // pin the recursion
            assert_eq!(p.aggr_cm_id, aggr_cm_id);
            env::verify(self_id, &to_vec(&p).unwrap()).unwrap();
            assert_eq!(p.chain_final, epoch.epoch_chain_link.prev_chain_hash);
            assert_eq!(p.last_state_commit, epoch.prev_state_commit); // needs §3 A4
            (p.chain_first, p.first_state_commit, p.n_epochs + 1)
        }
        None => (epoch.epoch_chain_link.prev_chain_hash, epoch.prev_state_commit, 1u64),
    };

    env::commit(&FoldJournal {
        self_id, aggr_cm_id, chain_first, first_state_commit,
        chain_final: epoch.epoch_chain_link.final_chain_hash,
        last_state_commit: epoch.state_commit,
        n_epochs: n,
    });
}
```

**Gotcha that must be written down:** a guest cannot know its own image ID at compile time (the ID is
a hash of the ELF that contains it). The standard workaround — used above — is to read `self_id` as
input, commit it to the journal, and have the *external* verifier assert
`journal.self_id == AGGR_FOLD_ID`. Omitting that final check makes the whole fold chain forgeable.

Host loop: `ExecutorEnv::builder().add_assumption(epoch_receipt).add_assumption(prev_fold_receipt)
.write(...)` then `prove_with_opts(env, AGGR_FOLD_ELF, &ProverOpts::succinct())`.

### 4.3 Cost

- **Guest cycles:** 2 × `env::verify`. Each is one journal SHA (the `CmAggrOutput` journal is
  ~300-500 B → ~8 compressions → ~14 K cycles) plus a syscall. Total fold-guest execution
  ≈ 10^5 cycles → a single rv32im segment.
- **Prover:** 1 segment proof + 1 `lift` + **2 `resolve`s** (one per assumption,
  `prove/mod.rs:376-388`) ≈ 4 recursion units.
- **Upper bound from our own data:** `DEFAULT_MAX_PO2 = 22` (`src/receipt.rs:899`) ⇒ the matched
  `n=16,384` run (100.7 M cycles) splits into ~24 segments ⇒ 24 `lift`s + 23 `join`s = 47 recursion
  units already inside its 3,202 s. So one recursion unit ≤ 68 s, and a fold ≤ ~270 s — **≤ 8.5% of
  one epoch's prove time, and realistically ~1%**, since that bound charges the rv32im segment
  proving entirely to recursion. MEASURE, do not quote the bound.
- **New crate + wiring:** `aggregator/methods/guest_fold/` + `Cargo.toml` workspace member
  (root `Cargo.toml:14-17` block) + `methods.toml` + host loop ≈ 120 lines.

---

## 5. Prediction test — where our claim holds and where it breaks

Our stated prediction: *folding collapses their verifier receipt count but removes neither (i) the
Θ(n) in-guest state re-derivation at query time nor (ii) the per-record cycle gap.*

**(i) is CORRECT AS LITERALLY STATED BUT THE FRAMING IS WRONG — report this honestly.**

Folding *alone* touches only aggregator receipts. `run_cm_query` still receives
`Vec<CmEpochState>` (`querier/core/src/lib.rs:190`), still hashes each
(`:275`), still sums all `n` tables (`:288-295`). Nothing in §4 changes that. ✅

**But the full steelman includes §3, and state carry DOES kill the Θ(n) query prefix.** Once epoch
`i` contains the cumulative table, the querier is handed a **single** latest `CmEpochState` and
`run_cm_query` already handles `len == 1` with no code change at all — the loop at `:288-295`
degenerates to one iteration. Query cost drops from Θ(n·d·w) to Θ(d·w).

⇒ **Our Θ(n)-query-prefix claim does not survive the steelman.** It is a claim about what they
*built*, not about what their architecture *forces*. The paper must frame it that way, or drop it.

**(ii) is CORRECT and survives both patches.** The per-event loop
(`aggregator/core/src/lib.rs:1246-1260`) is byte-identical under state carry — only the *initial
value* of `table` changes at `:1241`. Marginal cost stays 5,490 cyc/rec (TOPK=1) / 18,132 cyc/rec
(TOPK=100, their shipped default). Against `results/zks_matched_t1.csv` (690 rec/s) vs
`results/zka_matched.csv` (5.1168 rec/s) that is a **135× gap at TOPK=1**, and our matched run was
generous to them: at their shipped `TOPK=100` their per-record cost is **3.30×** higher again
(18,817.5 / 6,146.0), which is what M1 would confirm. ✅

### Residuals that survive the *full* steelman — this is where the structural claim now lives

- **R1 (the surviving headline).** Per-record cycle gap, 135× at TOPK=1 and ~3.3× worse at their
  shipped config. Untouched by both patches.
- **R2 — saturating counters become a live correctness cliff.** `table[r][idx].saturating_add(...)`
  (`lib.rs:1250`) over `u32` (`:1241`). Within one 16,384-log epoch saturation is unreachable.
  Carried across an unbounded stream it is reachable, and it fails **silently** — there is no
  in-circuit detection, so a saturated proof is still a valid proof of a wrong count. Same for
  `total_sum` (`:1247`). The steelman patch must widen to `u64` or add an explicit range assert
  (item A6). This is a defect *created by* the steelman, and it is worth stating as such.
- **R3 — the top-k heap does not survive carry.** `cm_heap_update` (`:1103-1141`) stores
  `score = cm_estimate_count(&table, key)` sampled **at insertion time** (`:1252-1259`). Carried
  `heap_vals` are therefore stale estimates taken against an *earlier* table, and the evict-worst
  rule (`:1126-1139`) then compares stale values against fresh ones. Within one epoch this is
  self-consistent; across epochs it is not, and top-k becomes order-dependent and wrong. Fixing it
  correctly requires re-scoring all `CM_TOPK_SLOTS` entries against the current table — i.e. exactly
  the verified bounded-replacement problem our Pattern-B work solves. **The steelman does not have a
  cheap fix here**, and this is the strongest structural finding in this probe.
- **R4.** No length validation on `CmEpochState` vectors before indexing (`lib.rs:1014-1024`,
  `querier/core/src/lib.rs:275`). Liveness only, but the patch must add asserts.

---

## 6. Effort and the smallest validating experiment

### Person-day estimate

| work | days |
|---|---|
| §3 state carry (105 LoC + 2 tests) incl. guest rebuild & image-ID re-link | 1.0 |
| §4 fold guest (new crate, methods wiring, host loop, self-ID verifier check) | 1.5 |
| R2 + R3 correctness fixes (u64 widening; heap re-scoring is the hard one) | 1.0 – 3.0 |
| small-scale validation runs + CSV harness | 0.5 |
| **total** | **4.0 – 6.0 person-days** (3.0 if R3 is left broken and merely disclosed) |

### Smallest experiment that validates the plan — 2 epochs × 1,024 logs, TOPK=1, keys=1024

Rationale for `n=1024`: below that, `F` (10.74 M cycles) swamps everything and the per-record term
vanishes; `n=1024` still yields a 16.37 M-cycle epoch ≈ **520 s** at the measured 31.45 kHz, so a
four-proof matrix is ~35 min of serialized prover time.

**Stage 0 — free, no prover (run this first, it can falsify the plan on its own):**
1. Native equivalence: 2 epochs × 512 logs *with carry* must produce byte-identical `table` and
   `total_sum` to 1 epoch × 1024 (test A11-ii). If this fails, the seeding in A3 is wrong.
2. `cm_state_commit ≡ cm_epoch_state_commit` (test A11-i).
3. Executor-only cycle delta (< 30 s, allowed): `carry` vs `nocarry` at `n=1024`. **Predicted
   +330 K cycles + read cost ⇒ +2.0 ± 0.5%.** A delta materially above ~4% means `env::read` of the
   12 KB state is far more expensive than modelled, and §3.3 needs revising.

**Stage 1 — prover, 4 proofs, ~35 min serialized (lead-scheduled):**

| arm | epochs | what it shows |
|---|---|---|
| `nocarry` e1, e2 | 2 | baseline per-epoch prove at n=1024 |
| `carry` e1, e2 | 2 | state-carry overhead — predicted ≤ +2% wall clock |

**Stage 2 — folding, 2 additional proofs, ~5-15 min:** fold e1 then fold(e1)+e2. Measures the
per-epoch `resolve` cost directly and replaces the ≤68 s/unit upper bound in §4.3 with a number.
Verifier check: **1** receipt instead of 2, and `journal.self_id == AGGR_FOLD_ID`.

**Stage 3 — query side, free at this scale:** run the executor on `QUERIER_CM_ELF` with
`epoch_states.len() ∈ {1, 2}` (no proving needed; cycles alone prove the point). Confirms the Θ(n)
slope at `:288-295` and confirms it collapses to Θ(1) under carry. This is the measurement that
settles §5(i) against us.

### Harness requirements (per the standing rules)
`SCALE` = `n` (logs/epoch) and `EPOCHS`; one CSV line per data point:
`mode,n,epochs,topk,cycles,cycles_per_record,prove_s,khz,verify_ms,receipt_bytes,r0vm_peak_rss_mb`.
Peak RSS must be sampled from **`r0vm`'s** `/proc/<pid>/status:VmHWM`, not the driver's (the driver
reads ~9 MB and is meaningless). `r0vm --port` is spawned as a **separate process that outlives its
parent** — the harness must trap `EXIT`/`INT`/`TERM` and reap it, or the next run inherits it.

### Open risks
- The guest ELF changes ⇒ `AGGR_CM_ID` changes ⇒ any stored receipt or FoundationDB artifact from
  earlier runs is invalidated. Use a scratch data dir.
- `Cargo.lock:3767` pins `risc0-zkvm 3.0.5` while the installed toolchain is 3.0.6. Composition API
  is identical across the two, but the fold crate must not silently bump the lock — pin explicitly.
- R3 (heap under carry) may not have a cheap fix. If so, the honest steelman is
  **"cross-epoch CM estimate: yes, cheaply; cross-epoch top-k: no"** — and their shipped
  `CM_TOPK_SLOTS=100` default means top-k is the configuration they actually ship.
