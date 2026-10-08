# zkSketch's SpaceSaving batch rule on RISC Zero (`ss_mg`, ours †)

A matched-semantics baseline for zkSketch's SpaceSaving (SS) leaf. The RISC
Zero guest executes **exactly the batch transition that zkSketch's
`ss_final_full` circuit certifies** (mergeable Misra-Gries with top-s
retention), on the same records, batches and state representation. The
comparison is therefore between two ways of handling the same batch
transition, not between two algorithms:
- zkSketch's AIR circuit certifies it;
- this guest executes it in a zkVM. Only the executor ran here; prove time is
  MODELED.

The two statements still differ in hash (SHA-256 vs Poseidon2), in
compute-vs-verify and in who maps the raw keys (see `../README.md`, Caveats).

`../spacesaving/` is a different baseline and is unchanged: textbook per-record
SpaceSaving (Metwally et al.) inside zk-Analytics' full aggregation pipeline,
with a sum-and-truncate merge at query time. That is not what zkSketch
certifies. Keep both; do not mix their rows.

**This is our guest, not zk-Analytics code (†).** It uses no zk-Analytics code
at all: no `Event` batches, no SHA-256 batch chain, no epoch chain link. It
takes from zk-Analytics only the commitment style (unsalted SHA-256 through
risc0's accelerated `sha::rust_crypto`, as their aggregator does).

## The statement (one guest run = one zkSketch SS leaf)

| step | what the guest does | where the rule comes from |
|---|---|---|
| read | S_old (`capacity` rows) and the epoch's `m` raw u32 dataset keys | - |
| Com_old | SHA-256(tag, s, m, S_old rows) | zka style; layout = zkSketch `flat_state_vals` |
| map | each raw key k becomes a record: `u32::MAX` (PAD_KEY) gives the dummy (0, 0, 0, 0); otherwise ((k & 0x1FFF_FFFF) \| 1, 0, 1, 1) | zkSketch `ss_updates_of`, `src/experiments/stream_compose.rs:535` |
| Com_batch | SHA-256(tag, m, mapped records) | layout = zkSketch `flat_batch_vals` |
| transition | S_new = `apply_batch_ss_full(S_old, batch).0` | zkSketch `src/sketch/ss_final_full.rs:575` (`build_ss`:481, `group_by_key`:408, `compress_from_gsorted`:452) |
| Com_new | SHA-256(tag, s, m, S_new rows) | as Com_old |
| journal | Com_old \|\| Com_batch \|\| Com_new (96 raw bytes, `env::commit_slice`) | - |

The batch rule, as zkSketch implements it:

1. Union the `s` old rows with the `m` batch records.
2. Sort by key and group equal keys, summing counts (a u64 running sum, stored `as u32`).
3. Sort the grouped table by (active, count, key), ascending.
4. Set tau = `g_sorted[m-1].count`, the (s+1)-th largest grouped count. It is
   0 when the union has at most s distinct keys.
5. Keep `g_sorted[m..]`, the top s, subtract tau from each, and turn every
   counter that reaches 0 into a dummy.

The state is exactly `capacity` rows of `(key_lo, key_hi, count, active)` u32
words: dummies (0, 0, 0, 0) first, then active rows by (count asc, key asc). The
guest reproduces this row sequence exactly, ties included.

Per epoch, the host feeds the guest the previous state and the next `m` keys,
starting from `SsFullState::empty`. This is the loop of
`stream_compose.rs:758-761` and `:961-972`, over the batches of
`examples/exp_compose.rs` `batches_from`.

## Implementation (ours)

`core/src/lib.rs` (`ss-mg-core`, no_std) is shared by both guests and the host.
It is a plain-Rust implementation of the rule, not a line-by-line port of
`build_ss`:

- It sorts only active rows, packed as `key << 32 | count` (union) and
  `count << 32 | key` (grouped). Dummy rows only ever form zkSketch's key-0
  dummy segment, which groups to a dummy.
- **Radix sort (headline).** Two stable LSD radix sorts of at most 11-bit
  digits over one u32 word. The first sorts the union by key. The second sorts
  the key-ordered grouped table by count only; stability keeps ties
  key-ascending. The top s is a suffix.
- **Std sort (sensitivity).** core's `sort_unstable` (pdqsort) on the union.
  When the union overflows, `select_nth_unstable` finds the cut, then only the
  kept rows are sorted.
- The sort is chosen by an input word and is not committed; both sorts give
  the same S_new.
- The guest asserts well-formed input:
  - an inactive row or record is the all-zero dummy;
  - an active row has active = 1, key_hi = 0 and key != 0.

  zkSketch's keys are below 2^29 and its dummy key is 0, so honest states and
  batches always pass. On such input the packed implementation equals the
  literal one, and the host checks this on every run.

Two guests share that code; they differ only in how they read their input:

| guest | input read | role |
|---|---|---|
| `ss_mg` | `env::read_slice` of raw words: `[s, m, sort]`, state, keys (`ss_mg_core::input_words`) | headline |
| `ss_mg_serde` | `env::read::<SsMgInput>()`, risc0 serde, as the zka guests read | read-path sensitivity |

**Probes.** Both guests call `env::cycle_count()` at the start, after the read,
after each `ss-mg-core` phase (commit_old, map, commit_batch, transition,
commit_new) and after the journal commit.
- The cycles before the first mark (`pre_main_cycles`, 360) and after the last
  (`post_cycles`, 2,632-2,633) are their own columns. `post_cycles` is user
  cycles minus the last mark, so `pre_main` + the deltas + `post` equals user
  cycles by construction, and that sum checks nothing.
- The real check is `probes_ok`. The driver exits 1 unless the marks increase
  and both `pre_main` and `post` are below 10,000 (`PROBE_SLACK`). That holds
  only if `env::cycle_count()` counts the same session-wide user cycles as the
  executor (not per segment, not including paging). Setting the bound to 2,000
  made the driver fail as expected (tried by hand, then reverted).
- The marks split **user cycles only**. Paging, the per-segment reserve and po2
  padding are in no phase (see "Cycle columns" below).
- The probes are part of the measured guest; there is no probe-free twin.
  They cost a handful of cycles each.

**Host-only channel.** After the last mark the guest writes the marks and S_new
to its stdout with `env::write_slice`. This is not the journal and not part of
the statement; the host uses it for the field-by-field check. It costs about
2,600 cycles at both s (`post_cycles`, one syscall).

## Equivalence check (fails loudly)

`ss_mg` (`src/bin/ss_mg.rs`) runs the executor and checks every guest run
against zkSketch's own code. The zkSketch crate of this checkout is a path
dependency; the driver calls `apply_batch_ss_full`, `ss_updates_of` and
`dataset::synthetic_stream` from it.

On any mismatch it prints the first differing rows and exits 1, before
printing a CSV row. The runner then keeps the canonical CSVs untouched.

| check | what |
|---|---|
| `state_eq_native` | guest S_new == zkSketch `apply_batch_ss_full(S_e, ss_updates_of(batch_e)).0`, every row, every field (key, count, active) |
| `journal_eq_native` | guest journal and S_new == `ss-mg-core` run natively on the same input |
| `com_eq_native` | Com_old, Com_batch, Com_new == SHA-256 of zkSketch's native S_e, `ss_updates_of(batch_e)` and S_{e+1} |
| `core_eq_native_prefix` | (`--mode exec`) `ss-mg-core`, **both** sorts, run natively == zkSketch after every epoch 0..E-1 that builds S_E; the key mapping == `ss_updates_of` on each of those batches |
| `link_ok` | (`--mode chain`) Com_old(e) == Com_new(e-1) |
| `probes_ok` | the cycle marks increase, with fewer than 10,000 user cycles before the first and after the last (see Probes) |
| r0vm summary (runner) | r0vm's own session summary (`RISC0_INFO=1`) has user cycles == `user_cycles`, total == `padded_cycles`, and user + paging + reserved == total; its paging and reserved cycles become the last two CSV columns |

There are two modes:
- **`--mode chain`.** Each run reads the previous **guest** output.
  `ss_mg_exec.sh` chains all 64 epochs (the whole 2^20-record stream) with the
  radix sort, and 8 epochs with the std sort. It does this for AOL and Uniform,
  at s = 16,384 and 1,024. That gives 288 guest runs in
  `../results/zka_ss_mg_equiv.csv`, all passing.
  - Eviction (tau > 0) occurs in 33 of the 64 AOL epochs at s = 16,384, every
    epoch at s = 1,024, and 42 of the 64 Uniform epochs at s = 16,384.
  - The AOL epoch-63 chain rows, whose state came through 63 guest runs,
    match the epoch-63 cost rows, whose state was built natively. Cycles,
    segments, phases, the transition statistics and all three commitments
    are identical. Only `arm`, `state_source`, the mode-specific check
    columns and `exec_s` differ.
- **`--mode exec`.** S_E is computed natively; one guest run.

**Unit tests** (`cargo test --release --locked --bin ss_mg`, native only):
- `ss-mg-core` vs `apply_batch_ss_full`, both sorts, over 1,200 random chains
  of 24 epochs each. The shapes are s in {2..16} and m in {2..32}, with key
  pools of 3 to 1,000 keys plus `u32::MAX` pads, 29-bit-mask aliases and
  low-bit aliases. They contain 12,787 epochs with tau > 0, and 9,445 in which
  counters equal to tau were dropped.
- One wide case: keys over all 29 bits, counts above 2^11.
- Commitment binding, and rejection of malformed rows.

**Mutation check, by hand (not in the suite),** on the final `core/src/lib.rs`,
each applied alone in a scratch build and then reverted:

| mutation | caught by |
|---|---|
| tau off by one on the radix path (`g_sorted[m]`, the bug `build_ss` warns about) | the radix random-shape test, with a field-level diff |
| key-descending ties on the radix path (reverse the grouped table before the stable count sort) | the radix random-shape test |
| key-descending ties on the std path (key packed as `0x1FFF_FFFF - key`) | the std random-shape test |

The restored source is byte-identical to the backup taken before mutating, and
it rebuilds to the same guest ELF md5s that produced the CSVs.

## Layout

| path | what |
|---|---|
| `core/` | `ss-mg-core`: mapping, commitments, transition (both sorts), input layout |
| `methods/` | RISC Zero methods crate; `guests/` is its own workspace with `ss_mg` and `ss_mg_serde` |
| `src/bin/ss_mg.rs` | host driver and equivalence checks; unit tests at the bottom |
| `ss_mg_exec.sh` | unit tests, guest-chained equivalence, cost rows; regenerates both CSVs |

## Running

```bash
scripts/baselines/zka/ss_mg/ss_mg_exec.sh        # build, test, check, measure; about 1 minute with cached builds
SKIP_BUILD=1 SKIP_TESTS=1 scripts/baselines/zka/ss_mg/ss_mg_exec.sh
# one row by hand:
~/ext-baselines/build/zka-ss-mg/release/ss_mg --mode exec --dataset aol --capacity 16384 --epoch-index 63
```

- **Builds** go to `$BASELINE_DIR/build/zka-ss-mg` (default `~/ext-baselines`).
  The zk-Analytics clone is not needed.
- **Guest lockfile.** `methods/guests/Cargo.lock` was seeded from
  `../spacesaving/methods/guests/Cargo.lock`. Cargo only pruned that port's
  crates and added these two, with no version change (checked by diff), so the
  guests link risc0-zkvm **3.0.5**, as zk-Analytics' guests do.
  `RISC0_BUILD_LOCKED=1` makes risc0-build honour it.
- **Host lockfile.** `Cargo.lock` is the union of `../spacesaving/Cargo.lock`
  (host risc0-zkvm **3.0.6**) and the zkSketch root `Cargo.lock`, resolved
  once by cargo.
  - Where the two pinned different patch versions of one crate, the union
    keeps the higher one. That happened for 19 crates: aho-corasick, chacha20,
    cpufeatures, either, libc, log, memchr, num-integer, proc-macro2, quote,
    regex-automata, serde, serde_core, serde_derive, smallvec, spin, syn,
    thiserror and thiserror-impl.
  - So the native reference here builds against a few patch versions newer
    than zkSketch's own lock. No Plonky3 crate is among them; those are pinned
    by git rev.
  - Builds use `--locked`.
- **Executor.** r0vm 3.0.6 over IPC (`default_executor()`), CPU.
  `RISC0_DEV_MODE` is refused.
- **Config.** `--epoch-size 16384`. Uniform is
  `synthetic_stream(Uniform, 64*m, 1)`, the `EXP_DATASET=uniform` stream of
  `exp_compose`, `exp_stream`, `exp_e1` and `exp_e2`. It is seed 1, not the
  frozen `data/uniform.keys` (seed 2). AOL is `data/aol.keys` (md5
  `01dd7d5c8a73`). Neither AOL nor the Uniform stream contains `u32::MAX`
  (`pad_records` = 0 on every row).

Driver flags: `ss_mg --mode exec|chain --dataset aol|uniform --capacity S
[--epoch-index E | --epochs K] [--guest ss_mg|ss_mg_serde] [--sort radix|std]
[--keys PATH] [--epoch-size 16384]`, plus `--header` and `--image-id [--guest G]`.

**Cycle columns.**

| column | meaning |
|---|---|
| `user_cycles` | executed guest cycles; the probes split these into phases |
| `padded_cycles` | sum over segments of 2^po2: what the prover pays, and what sets `segments` |
| `overhead_cycles` | padded - user: paging (a segment pages in every page it touches and pages out every page it writes), the per-segment reserve and po2 padding. It belongs to no phase |
| `transition_pct_user`, `transition_pct_padded` | the transition's share of user cycles and of padded cycles |
| `r0vm_paging_cycles`, `r0vm_reserved_cycles` | the split of `overhead_cycles` from r0vm's own session summary |

The two r0vm columns are added by `ss_mg_exec.sh`, which runs the driver with
`RISC0_INFO=1`. r0vm then logs its session summary to the stdout it shares with
the driver. A bare driver run prints the row without these two columns.

**Run log.** `ss_mg_exec.sh` only ever appends to
`../results/zka_ss_mg_exec.log`, with one header per run, failed runs included.
The log starts at the fourth run; the records of the three development runs
before it were deleted (see `../README.md`, "Run record").

## Results

See `../README.md` ("zkSketch's SpaceSaving batch rule as a RISC Zero guest")
for the table and caveats. The raw rows are in
`../results/zka_ss_mg_exec.csv`; the run record is in
`../results/zka_ss_mg_exec.log`.
