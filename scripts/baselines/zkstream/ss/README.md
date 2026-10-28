# zkStream-style SpaceSaving operator (replay baseline)

A SpaceSaving (heavy hitters) update operator built with zkStream's own
general-purpose method: a ZoKrates 0.8.8 program proved with Groth16 over BN254,
chained through salted Poseidon commitments (zkStream's "confidential proof
chaining", Swalens et al., Middleware '24, Sec 4.3/4.4). zkStream ships no sketch
and no stateful operator, so **this is our circuit**. Report it as "a SpaceSaving
operator following zkStream's design", never as "zkStream".

It is the SpaceSaving sibling of the Count-Min operator one directory up
(`../cm_op.zok.tpl`, `../run_zkstream.py`) and has the same shape: the public
statement is `(com_in, batch_digest, com_out)`, three field elements.

## Running

```bash
scripts/baselines/zkstream/ss/run_ss.py --s 8 16 32 64 128 --k 4 16 64 --chunks 4 --prune
scripts/baselines/zkstream/ss/run_ss.py --s 256 1024 4096 --k 1 --compile-only   # compile-scaling probes
scripts/baselines/zkstream/ss/run_ss.py --s 4096 --k 1 --chunks 5 --prune        # largest proven state
scripts/baselines/zkstream/ss/run_ss.py --s 16384 --k 1 --chunks 5 --prune       # deployed state size (refused)
scripts/baselines/zkstream/ss/fit_ss.py                                          # gates, fits, deployed-size costs from the fits
```

| Variable / flag | Default | Meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | ZoKrates binary and stdlib (`zok/`), zkStream clone |
| `BUILD` | `$BASELINE_DIR/build/zkstream_ss` | ZoKrates artifacts, one directory per `(s, k, cb, spe)` |
| `RESULTS` | `../results` | `zkstream_ss.csv` is appended there |
| `PIN_CPUS` | `0-31` | `taskset` CPU list, the same 32 hardware threads as the CM driver |
| `--cb` | `21` | count bits: counts < 2^21, enough for a 2^20-record stream (zkSketch's SS uses the same bound) |
| `--spe` | `3` | slots packed per committed field element (1 = the first layout, see History) |
| `--timeout`, `--mem-max` | `45m`, `150G` | every compile runs under `timeout 45m systemd-run --user --scope -p MemoryMax=150G` |
| `--max-wait` | `900` | before setup/prove, wait up to this long for other provers of this user (`zokrates setup/generate-proof`, `exp_compose`, `r0vm`) to finish |

A compile that hits the time or memory cap is written as a row with `ok=0` and
`REFUSED/OVER BUDGET` in the note. It is a measured outcome and is not retried.

| File | Role |
|---|---|
| `ss_op.zok.tpl` | the proven operator |
| `ss_helper.zok.tpl` | witness helper: Poseidon commitments `(com_in, batch_com, com_out)` of a transition the driver computed. `compute-witness` only, never set up or proven, not charged to the prover |
| `gen.sh <N> <S> <outdir> [CB] [SPE]` | instantiates both templates by textual constant replacement (zkStream's `zokrates.rs:85-87` idiom) |
| `run_ss.py` | driver: native SpaceSaving reference, compile, setup, chained chunks, witness, prove (`ark`, `g16`), verify, forgeries. One CSV row per step. Imports the path, key-reader and inspect helpers of `../run_zkstream.py` |
| `fit_ss.py` | soundness gate, exact constraint-count formula, time and memory fits, deployed-size costs from the fits |

CSV columns: `run, system, s, k, cb, spe, chunk, step, constraints, wall_s,
peak_rss_mb, bytes, public_inputs, ok, load1, foreign, note`. `load1` is the
1-minute load average when the row was written. `foreign` is `all/provers`: how
many of this user's other `zokrates`/`exp_compose`/`r0vm` processes were running
when the step started (the HLL and GK families run on the same box), and how many
of those were multi-threaded provers. Wall times come from `/usr/bin/time -v`
around the CLI, so they include process start. Verify is the CLI.

## The operator (one chunk of k records)

1. **commit-in.** Open the salted Poseidon commitment to the previous state. A slot
   `(K, C, E)` is the 75-bit word `K + C*2^33 + E*2^54`. Three slots share one field
   element (225 bits), and the packed elements are hashed as a Poseidon chain seeded
   with `poseidon([salt])`, five per call (the CM operator's chain). Opening
   range-checks all three limbs of every slot (`K` < 2^33, `C` and `E` < 2^21), so a
   packed element has exactly one decomposition.
2. **batch digest.** The k record keys must hash (Poseidon chain) to the public
   `batch_com`.
3. **textbook update, record by record.** A stored key is `key+1`, so key 0 marks an
   empty slot. For record `x` (`v = x+1`) the prover supplies a one-hot selector
   `sel` (the slot index as a hint), and the circuit checks it completely:
   - equality scan: `z_i = (K_i == v)` for all s slots (exact isZero gadget), `hit = sum z_i`;
   - `sel` is boolean and sums to 1;
   - hit: `z_i = 1` forces `sel_i = 1`, so the selected slot holds the key and no
     other slot does;
   - miss: every `z_i = 0` (key absent everywhere), and `C_i - C_j` is in
     `[0, 2^21)` for every slot `i` (s range-checked differences), so `C_j` is a
     minimum count. A free slot has count 0, so while one exists this selects a free
     slot and the update below gives count 1, error 0, which is "insert into a free
     slot". Otherwise it is "replace a minimum: count min+1, error min". As in the
     textbook algorithm, any minimum may be replaced. The driver's prover picks the
     lowest index, and the driver checks that the circuit also accepts a different
     equal-count slot (`semantics_other_min_accepted`).
   - update: `C_j += 1`; on a miss, also `K_j = v` and `E_j = C_j(old)`.

   The loops have a fixed shape over the s slots, with one-hot selects and
   compare-and-select only. There is no data-dependent indexing.
4. **commit-out.** Return the salted Poseidon commitment to the new state.

The native reference and the circuit must agree bit for bit on the honest path. The
driver checks this: the circuit's output must equal the helper's commitment to the
reference state.

**ZoKrates engineering (not algorithmic).** ZoKrates inlines every linear
combination. An s-term running sum (such as `hit`, or the selects `sum sel_i*C_i`)
therefore costs O(s^2) compiler memory. A per-record delta used by all s slot
updates (`v - K_j`) also puts an s-term combination into every slot's constraint,
which gives O(s^2) R1CS non-zeros per record. The operator therefore does three
things:

- It computes the three per-record deltas as products (`(1-hit)*...`).
- It multiplies the running sums, every 64 slots, by a private input `one` that is asserted to equal 1.
- It does the same for the key and error arrays every 16 records.

This costs about 0.2% more constraints. Against the previous layout, which lacked these steps and
enforced a lowest-index tie-break through prefix sums (`results/zkstream_ss_v2_spe3_tiebreak.csv`,
run on the same shared box), at s=128, k=64 it cut the compiled program (`.out`)
from 406 MB to 167 MB (the `.r1cs` file from 238 MB to 89 MB) and the witness+prove
time from 4.67 s to 2.96 s. At s=4096, k=1 it cut compile memory from 21.1 GB to
14.0 GB. The tamper case `materializer_not_one` checks that the assertion is present.

**Constraints per chunk.** The following is exact over every compiled point
(residual 0, `fit_ss.py`):

```
cons(s, k) = 31*s*k + 7*k + 5*k*floor(s/64) + 2*s*floor(k/16)
           + 78*s + 6*ceil(s/3) + 678*ceil(ceil(s/3)/5) + 339*ceil(k/5) + 427
```

The terms are:

- **`31*s` per record.** Per slot: 2 for the equality test, 1 booleanity, 1 hit/selector link, 3 selects, 22 for the 21-bit difference range check, and 2 writes.
- **Per-record extras.** 7 per record, 5 materialisation cuts per 64 slots, and 2 per slot every 16 records.
- **`78*s` opening range checks, per chunk.** 75 bits plus 3 recompositions per slot.
- **Two Poseidon chains (339 per call, 15 slots per call), per chunk.**
- **The key digest (339 per 5 keys), per chunk.**

### Which parts are zkStream's idiom and which are ours

| Element | Source |
|---|---|
| ZoKrates 0.8.8 program, Groth16 over BN254 via `ark`, one proof per operator invocation | zkStream |
| Circuit sizes fixed by textual constant rewriting | zkStream (`nexmark/zokrates-nexmark/src/zokrates.rs:85-87`) |
| Salted Poseidon output commitment, which the consumer re-derives (confidential proof chaining) | zkStream (`q4a.poseidon.zok:48`, `q4b.poseidon.zok:28-32`, `shared.zok:224-230`) |
| State passed as a confidential value between invocations (stateful operator) | zkStream Sec 4.4 (proposed there, not implemented) |
| Fixed-size loops over padded arrays; prover computes outside the proof and the circuit checks the result (the sorted-order and sqrt hints) | zkStream (`zkgadgets/gadgets.zok`, paper Listing 2) |
| Public batch digest over the chunk's keys, in place of zkStream's per-message EdDSA signatures | ours, as in the CM operator (signatures would add cost to every record) |
| SpaceSaving itself, the checked slot hint, 3-limb/3-slot packing with strict range checks, the linear-combination cuts | ours |

Nothing from zkSketch is used: no batch-effect certificate, no multiset, LogUp or
permutation argument, no memory-checked recommit, no sort-then-group over the
batch. Each record is applied to the full state in stream order.

## Soundness checks

For each measured point the driver proves a chain of 4 chunks over the first `4k`
AOL keys (5 chunks at k=1, so that a repeated key produces a hit) (`data/aol.keys`, little-endian u32). Every chunk must pass three checks:

- Its witness output equals the helper's commitment to the native reference state.
- Its `com_in` equals the previous chunk's `com_out`, checked on the public inputs of the proofs.
- Its proof verifies.

After the chain, `compute-witness` must reject each forgery below, and a valid proof
with its public `com_out` changed must fail `verify`:

| Case | What is forged | Rejected by |
|---|---|---|
| `com_in_plus1`, `salt_in_plus1` | commitment or salt | commit-in assertion |
| `stale_state` | chunk 1 opened against chunk 0's input state | commit-in assertion |
| `batch_com_plus1`, `key_not_in_digest` | digest or one key | digest assertion |
| `dropped_record` | record 0 dropped (last repeated), honest hints for that sequence | digest assertion |
| `hit_updates_min_slot` | a hit record's selector moved to the min slot (this would duplicate the key) | hit/selector link |
| `miss_evicts_nonmin` | a miss evicts a slot with a strictly larger count | difference range check |
| `selector_two_hot` | two slots selected | `sum sel = 1` |
| `materializer_not_one` | the private `one` set to 2 | `one == 1` assertion |
| `alias_key_count`, `alias_count_error` | same packed element, key or count limb out of range | opening range checks |
| `alias_error_absorbs_count` | count +1 (in range), with the error limb absorbing the difference mod p | opening range check on `E` |
| `alias_across_slots` | a slot's error limb absorbs a unit of the next slot's key in the same packed element | opening range check on `E` |
| `tamper_verify_com_out_plus1` | public output of a valid proof +1 | Groth16 verify |

For every `alias_*` case the driver first confirms, with the helper, that the forged
opening still hashes to `com_in`. The range checks are therefore the only thing
that rejects it. A failed range check shows up in ZoKrates as `Execution failed:
Sum check failed` (the unpack recomposition constraint). ZoKrates drops an unpack
whose bits are never read, so every range-checked value is rebuilt from its bits.

## Results (final layout, `results/zkstream_ss.csv`)

MEASURED on a Threadripper PRO 9975WX (32 threads pinned, shared box; `load1` in every row).
The grid's compile times were measured under contention (load1 about 5-8, sibling
compiles running) and are upper bounds: a reviewer's quiet reruns, not archived, were
about 20-30% faster. Prove times are not affected in this way, because every prove
waited for the other provers on the box.

| s | k | constraints | compile | setup | witness + prove | verify (CLI) | proof | prove RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 4 | 3,106 | 1.3 s / 0.14 GB | 0.05 s | 0.07 s | 6.9 ms | 997 B | 0.03 GB |
| 32 | 16 | 22,427 | 4.6 s / 0.38 GB | 0.24 s | 0.32 s | 7.0 ms | 997 B | 0.10 GB |
| 128 | 4 | 33,050 | 7.7 s / 0.60 GB | 0.33 s | 0.45 s | 7.3 ms | 997 B | 0.14 GB |
| 128 | 64 | 277,242 | 127 s / 2.35 GB | 2.2 s | 2.96 s | 7.2 ms | 997 B | 0.84 GB |
| 4096 | 1 | 641,525 | 313 s / 14.0 GB | 5.8 s | 8.8 s | 7.8 ms | 997 B | 2.48 GB |

All 15 grid points plus s=4096 are in the CSV. Every chain verified, and every
forgery was rejected.

Groth16 (ark) proves at 62K-134K constraints/s across the grid. The per-record
cost is `31*s` constraints: about 3.8-4.9 s of 32-thread proving per record at s=2^14,
whatever k is (3.8 s at the best measured rate, 4.7-4.9 s at the fitted
per-constraint cost and at the rate of the largest proven point). The DEPLOYED-SIZE
section of `fit_ss.py` (s=2^14 counters, 2^20 records) prints the numbers below.
They are computed from the fits, except where marked MEASURED:

- **Prover memory limits k.** Prover RAM on this 559 GB machine gives k <= 289,
  and this bound binds first. The radix-2 FFT domain of BN254 (2^28) gives k <= 520
  records per chunk. That is not a hard cap, since mixed-radix domains may allow
  more, and it does not change the conclusions.
- **Prover time is 46-60 days** (computed, not run). A 2^20-record stream is about 5.4e11
  constraints of proving: 46 days of 32-thread Groth16 time at the best measured prove
  rate (134K constraints/s), 58-60 days at the fitted per-constraint cost and at the
  rate of the largest proven point. The measured rate rises with circuit size across
  the grid, so this range is an uncertainty band, not a floor. At k=1 it is about 290
  days, because the per-chunk commitments dominate.
- **Compile (MEASURED).** The operator at the deployed state size s=2^14, even with a
  single record per chunk (k=1, 2,561,735 constraints), did not compile within the
  45 min / 150 GB budget in two attempts (still running at 55.6 GB RSS when the
  timeout fired). The first try ran next to 2-4 other compiles. The second ran on a
  quiet box (load ~1, nothing else running). A larger k only adds code, so every k at
  s=2^14 is over budget.
- **Why the compile is slow.** ZoKrates' frontend is superlinear in the size of the
  arrays it unrolls over. The archived k=1 compile rows show it: compile time at
  k=1 went 12 s, 54 s, 313 s for s = 256, 1024, 4096 (local exponent 1.3 and
  growing). An ad-hoc probe with bounded linear combinations (`sum a_i + b_i*c` over
  n inputs), run by hand and not archived (no script or log in the repo), showed the
  same superlinear growth. This is a property of the toolchain, not of Groth16 or of
  the replay method.
- **Verdict: INFEASIBLE at the deployed size.** The verdict stands on the prover
  time computed above. The circuit did not compile at s=2^14 within the budget in two
  attempts, and even if it did, the prover would need about 46-60 days of 32-thread
  time per 2^20-record stream (47-60 days at k=289, the largest k that fits in RAM).
  That k produces 3,629 proofs of 997 B each (128 B binary), plus 3,629 verifications.

## History

The per-record slope stayed at 31 constraints per slot throughout. Every recorded
run passed the same soundness gate.

- **v1 (`spe=1`, one slot per field element, lowest-index tie-break).** Results are
  in `results/zkstream_ss_v1_spe1.csv` and `results/zkstream_ss_v1_spe1_*.log`. The
  exact constraint-count formula was `31*s*k + 6*k + 84*s + 678*ceil(s/5) + 339*ceil(k/5) + 426`. At
  s=4096, k=1 the compile took 765 s and 39.0 GB.
- **v2 (`spe=3`, lowest-index tie-break through prefix sums).** Results are in
  `results/zkstream_ss_v2_spe3_tiebreak.csv` and `_*.log`. A third of the Poseidon
  calls. At s=4096, k=1 the compile took 341 s and 21.1 GB. The prefix sums and the
  inlined `v - K_j` delta gave O(s^2) R1CS non-zeros per record (a 2.36 GB `.out`
  at s=4096, k=1).
- **final (`spe=3`, any minimum, linear-combination cuts).** Results are in
  `results/zkstream_ss.csv`. The raw console logs are
  `results/zkstream_ss_{grid,compile_scaling,large_s4096,deployed_s16384,deployed_s16384_retry}_*.log`,
  and the `fit_ss.py` output is in `results/zkstream_ss_fit.log`.
- **A soundness bug caught before v1.** A draft did not range-check the top limb `E`,
  and the tamper case `alias_error_absorbs_count` was ACCEPTED: a count could be
  raised while `E` absorbed the difference mod p. Every recorded run range-checks all
  limbs.

## Caveats

- **Small state sizes, plus probes.** The prove/witness fits cover 3K-642K
  constraints. The largest point is s=4096, k=1, proven on a quiet box. Every figure
  `fit_ss.py` prints for a deployed size is computed from the fits, with the
  per-constraint prove cost held constant. The measured prove rate rises with size across the grid, while
  at the 10^8-constraint circuits a feasible k needs, MSM and FFT grow as n log n and
  the machine becomes memory-bound. The true time may therefore differ from these
  figures by about 2x in either direction.
- **The min check follows the spec.** The spec prescribes the textbook min check: s
  range-checked comparisons per miss. A Stream-Summary layout would need only O(1)
  range checks per record: the 22-constraint range check per slot disappears, and a
  second one-hot selector for the swap adds about 7 per slot. That is roughly 16s
  instead of 31s constraints per record, about 2x. In that layout, slots stay sorted
  by count, and an increment swaps the slot to the end of its equal-count block. It
  was not built, so the 2x is a constraint count, not a measurement. It keeps a different data-structure
  invariant, and the comparison is about the textbook scan.
- **Keys are not range-checked.** The batch digest binds them to the source's u32
  keys, as in the CM operator. A key of `p-1` would make `v = 0` collide with empty
  slots.
- **Chain anchor.** The verifier must anchor chunk 0: its `com_in` must equal
  Commit(empty state, salt_0) with salt_0 revealed (or com_0 fixed). The circuit opens
  any well-formed committed state (limbs in range), and the SpaceSaving invariants
  (distinct keys; K = 0 exactly when C = 0) hold only inductively from the empty
  genesis.
- **The batch digest is unsalted**, as in the CM operator. At small k a u32 key can
  therefore be recovered from the public digest by brute force (2^32 Poseidon
  evaluations at k = 1). A salt would cost one extra absorption.
- **Counts must stay below `2^cb`.** `cb=21` covers a 2^20-record stream. Each extra
  bit adds 1 constraint per slot per record.
- **Proof size.** Proof bytes are ZoKrates' JSON encoding (997 B). A binary Groth16
  proof is 128 B compressed.
- **The box is shared.** The HLL and GK families compile and prove on it at the same
  time. The driver waits for their multi-threaded provers before its own setup and
  prove steps, and records `load1` and `foreign` on every row. A compile can still
  overlap their single-threaded compiles. The grid ran at load1 about 5-8, while
  those families were compiling. The s=4096 point and the second s=2^14 attempt ran
  at load1 about 1.
