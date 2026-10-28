# HyperLogLog operator following zkStream's design ("replay" baseline)

A HyperLogLog update operator built with zkStream's own method and toolchain
(ZoKrates 0.8.8, Groth16 over BN254, salted-Poseidon confidential proof chaining;
Swalens et al., Middleware '24, §4.3-4.4). zkStream ships no sketch and no stateful
operator, so **this is our circuit**. Report it as "a HyperLogLog operator following
zkStream's design", never as "zkStream". It is the HLL sibling of the Count-Min
operator one directory up (`../cm_op.zok.tpl`) and follows its layout.

## Method

One Groth16 proof per chunk of k records. The operator:

1. opens the salted Poseidon commitment to the previous register array (commit-in);
2. checks the chunk's keys against a public batch digest (Poseidon chain, as `cm_op`);
3. applies the **textbook per-record HLL update**, record by record: `h = Poseidon(key, 0)`
   with a strict 254-bit unpack; register index = low b bits of h; rank = 1 + leading
   zeros of the next Q = 64 - b bits (a standard 64-bit HLL hash word, rank <= 65 - b);
   `R[idx] = max(R[idx], rank)`, through fixed-shape loops over the whole state;
4. checks the salted Poseidon commitment to the new array (commit-out).

Public statement: `(com_in, batch_com, com_out)`, three field elements, like the
Count-Min operator. Consecutive chunks share a commitment: chunk c's `com_in` is chunk
c-1's `com_out`. The only prover-supplied values beyond the keys, the state and the
salts are two kinds, and the circuit checks both fully:

- ZoKrates' own bit decompositions;
- a private input `one`, asserted equal to 1 (see "Wire refresh").

### State encoding and update (reasonable ZoKrates engineering)

- **Packing.** 6-bit registers, P = min(32, s) per field element (6 * 32 = 192 bits, so
  every word has exactly one bit decomposition). s = 2^b registers become S = s/P words.
  Register i is lane i mod P of word i div P.
- **Read.** A mux tree over the slot bits selects the word (S - 1 constraints), a
  6P-bit unpack splits it, and a mux tree over the lane bits selects the register.
- **Compare.** `rank - cur + 63` lies in [1, 124]; its 7-bit decomposition gives
  `rank > cur`, and `delta = [rank > cur] * (rank - cur)`.
- **Write.** A one-hot slot decoder whose root carries `delta * 2^(6 * lane)` (S - 1
  constraints) is added to every word. The new lane value is `max(cur, rank) <= 63`,
  so no carry leaves the lane.
- **Wire refresh** (CK = 8). After every CK-th record, and after the last one, each
  updated word is multiplied by a private input `one`, which the operator asserts is 1.
  This costs S constraints per refresh.
  - The problem it fixes: without the refresh, ZoKrates' optimizer inlines the free
    additions `w + oh`. Word j then becomes a linear combination of every earlier
    write, and every later mux read carries it. Constraint count stays linear, but
    density, compile time and memory grow as k^2. Our first encoding (v1) did this: at
    s = 2^14 and k = 256 it compiled in 509 s and 17.2 GiB, with a 4.1 GB program.
  - Its cost: CK = 1 would add S per record (+25% at s = 2^14). CK = 8 adds S/8 (+3%),
    at the same compile time and a 9% larger program (`results/zkstream_hll_refresh_probe.csv`).
  - That CSV was assembled by hand, and `run_all.sh` cannot regenerate it. Its CK = 1
    rows come from prototype templates (equal to the final ones at CK = 1) compiled in a
    scratch build, its CK = none rows are copied from the v1 CSV, and the k = 64 CK = 1
    and CK = 8 compiles ran concurrently. CK was swept only over {1, 8}.
  - v1's rows are kept, not used, in `results/zkstream_hll*_v1_lincomb_growth*`.

Why pack: the per-record cost is `2S + 7P` plus a fixed part, and the two commitments
together cost about 142 constraints per word (about 71 each). Packing 32 registers per
word divides both S-terms by 32. At s = 1024, a one-record chunk costs 149,790
constraints unpacked (P = 1) and 6,840 packed (P = 32). The compile takes 110 s and
8.6 GiB instead of 4 s and 0.4 GiB (`results/zkstream_hll_packing_probe.csv`). P = 32
is the most the field allows with power-of-two lanes. At the deployed s = 2^14 it is
also the optimum for any k, since the unconstrained optimum sqrt(2s/7) is about 68.
The default P = min(32, s) is over-packed for s <= 256. At 7 of the 9 grid points with
s <= 256 the best power-of-two P needs 6-13% fewer constraints than the measured circuit
(e.g. s = 64, k = 64: 63,262 at P = 8 vs 72,612 at P = 32); at s = 256 with k = 4 or 16
the gap is 0-1% (exact formula). The s >= 1024 grid points and every s = 2^14 point
already use the optimal P.

### Exact constraint count

Checked on every compile, both probes and measured points
(`fit.py` prints the check):

```
cons(k, s, P, CK) = 427 + 678*ceil(S/5) + 6*S + 339*ceil(k/5) + S*ceil(k/CK)
                  + k * (764 + 2*S + Q + 7*(P-1) + log2 P),     S = s/P, Q = 64 - log2 s
```

Per record: 764 covers the key's Poseidon-3, the strict 254-bit unpack, the rank
window, the compare and the lane weight. Then 2S covers the slot read and write, Q the
leading-zero prefix products, and 7(P-1) + log2 P the word unpack and lane mux. The
fixed part is two commitment chains, 354 per Poseidon-6 block, less 3 for each
zero-padded lane. `S*ceil(k/CK)` is the wire refresh.

## What is zkStream's idiom and what is ours

| Element | Source |
|---|---|
| ZoKrates 0.8.8, Groth16 (ark) over BN254 | zkStream's toolchain |
| Salted Poseidon hash of a confidential value, recomputed by the next operator | zkStream §4.4 "confidential proof chaining" (`q4a.poseidon.zok:48` producer, `q4b.poseidon.zok:28-32` consumer, `shared.zok:224-230` `hashOutputPoseidon`) |
| State passed as a confidential value between invocations | zkStream §4.4, "Stateful operators" (proposed there, not implemented) |
| Fixed-size loops, sizes rewritten textually per instance | zkStream's zkgadgets and `zokrates.rs:85-87` |
| HyperLogLog itself, register packing, mux-tree read, value-rooted one-hot write, 7-bit compare | ours, standard R1CS engineering |
| Batch digest binding the records | ours, same as `cm_op`. zkStream binds each message with an EdDSA signature or a per-message salted hash, which would cost more per record |
| `com_out` as an asserted public input, not a return value | ours. The statement is the same, and compute-witness can now reject a forged next state |
| Wire refresh through a private `one` (asserted equal to 1) every CK = 8 records | ours, ZoKrates-specific engineering (see above) |

Not used anywhere: batch-effect certificates, multiset, permutation or LogUp arguments,
memory-checked recommitment, sort-then-group over the batch. Every record's update
touches the whole state, so the cost is Theta(s/P) per record.

## Files

| File | Role |
|---|---|
| `hll_lib.zok.tpl` | shared body: commitment, digest, per-record update |
| `hll_op.zok.tpl` | the proven operator (imports `hll_lib`) |
| `hll_helper.zok.tpl` | witness helper: the same functions, with the asserts turned into outputs. Never set up or proven, and its time is not charged |
| `gen.sh <N> <s> <outdir> [P]` | instantiates the three templates (`CK` from the environment, default 8) |
| `native.py` | native reference: BN254 Poseidon, bit-exact with the ZoKrates stdlib (constants parsed from it; self-test `python3 native.py`), the index/rank map, packing, commitment, digest and HLL estimate |
| `run_hll.py` | driver, patterned on `../run_zkstream.py` (imports its `timed`, `constraints_of`, ...) |
| `run_all.sh [stage...]` | the exact measurement sequence behind the CSVs: `probes grid deployed wall edge` |
| `fit.py [CK]` | soundness gate, exact-formula check, fits, deployed-size costs from the fits |
| `probes/constraint_probe.sh` | compile-only probe (constraint formula, P sweep) |

Results, all in `../results/`:

| File | Contents |
|---|---|
| `zkstream_hll.csv` | one row per measured step: constraints, wall, peak RSS, bytes, public inputs, load1, ok |
| `zkstream_hll_<run>.log` | raw console record of each driver run |
| `zkstream_hll_constraint_probe.csv`, `zkstream_hll_packing_probe.csv` | compile-only probes |
| `zkstream_hll_refresh_probe.csv` | compile-only wire-refresh comparison |
| `*_v1_lincomb_growth*` | the superseded v1 encoding, kept for the record, not used by `fit.py` |

## Running

```bash
scripts/baselines/zkstream/hll/run_all.sh          # all stages, about 2 h (the k=1024 refusal alone takes 45 min)
scripts/baselines/zkstream/hll/fit.py
```

Artifacts go under `$BUILD` (default `~/ext-baselines/build/zkstream_hll`, several GB
at s = 2^14, k >= 256). For every (s, k), the driver:

- compiles the operator and the helper, each under
  `timeout 45m systemd-run --user --scope -p MemoryMax=150G`. A refused compile is
  recorded as a row with `ok=0`, not retried;
- sets up the operator once;
- proves a 4-chunk chain over the first AOL keys. For each chunk it:
  - runs the helper and checks its state and both commitments against `native.py`;
  - runs the operator's witness on the helper's statement;
  - proves, then checks that the proof's public inputs equal
    `(com_in, batch_com, com_out)`;
  - verifies, and checks that `com_in` equals the previous `com_out`.

`--no-helper` skips the helper, whose compile would double the cost, and takes the
statement from `native.py`. It is used only for the `edge` point.

With `--tamper`, twelve forgeries at chunk 1 must be rejected by compute-witness, and
a proof shown with a modified public `com_out` must fail verification. The forgeries
are:

- wrong update at one slot;
- dropped record, either in the claimed state or padded out of the private batch;
- stale state, meaning the previous chunk's input state;
- one altered input register;
- a key not in the digest;
- replace-not-max, which falls back to decreasing a register when no record of the
  chunk qualifies;
- `com_out = com_in`;
- `com_in`, `batch_com` or `salt_out` off by one;
- `one = 2`.

Every CSV row carries the 1-minute load average. Before each setup and prove, the
driver waits for other zokrates provers on the box to finish and notes any concurrent
zokrates process.

## Results

Measured on 2026-09-26 on a Threadripper PRO 9975WX (pinned to CPUs 0-31, 559 GiB,
shared, load1 3-7). `fit.py` reproduces every number below from the CSVs.

Units: memory (RSS, the 150 GiB cap, the box's RAM) is in MiB / GiB, as `/usr/bin/time`
reports it and `fit.py` prints it (its "G" is GiB). File sizes (program, proving key,
proofs) are decimal MB / GB (bytes / 10^6 or 10^9), as `fit.py` prints them.

**Soundness.** Over 20 points (s x k), 260 forgeries were rejected: 12 by
compute-witness plus 1 by the verifier at each point.

- All 12 compute-witness forgeries fail at one of the operator's four top-level asserts
  (`one == 1`, commit-in, digest, commit-out). They therefore test the statement
  relation, not the update constraints against a malicious witness: compute-witness
  recomputes the update itself, so no forged update ever reaches the R1CS.
- Only the verifier-side forgery (a valid proof shown with a modified public `com_out`)
  touches the R1CS.
- Soundness of the update rests on the structural argument: the operator has no free
  hints. Beyond the keys, the state and the salts, the prover supplies only ZoKrates'
  own bit decompositions and the asserted `one` (see Method).

All 20 four-chunk chains hold: `com_in` equals the previous `com_out`, every proof
verifies, and the public inputs equal `(com_in, batch_com, com_out)`. The helper state
matches `native.py` on 19 points; the `--no-helper` point takes its statement from
`native.py`. The HLL estimate over the 4 chunks is within the expected error, e.g. 1233
vs 1234 distinct at s = 2^14, k = 512. The exact constraint formula matches all 20
measured compiles and all 22 probe compiles.

**Per point** (MEASURED). Witness and prove are medians over the 4 chunks. Verify is
the CLI, about 7 ms. Every proof is 997 B of JSON.

|     s |    k | constraints | compile | compile RSS |  setup | pk MB | witness |  prove | prove RSS |
|------:|-----:|------------:|--------:|------------:|-------:|------:|--------:|-------:|----------:|
|    16 |    4 |       5,191 |   1.5 s |    0.16 GiB | 0.07 s |   2.2 |  0.02 s | 0.07 s |    36 MiB |
|    16 |   64 |      65,366 |  11.1 s |    0.84 GiB | 0.54 s |  25.1 |  0.21 s | 0.60 s |   242 MiB |
|    64 |   64 |      72,612 |  12.3 s |    0.88 GiB | 0.66 s |  31.6 |  0.21 s | 0.66 s |   266 MiB |
|   256 |   64 |      74,014 |  13.0 s |    0.93 GiB | 0.66 s |  32.0 |  0.21 s | 0.67 s |   272 MiB |
|  1024 |   64 |      80,684 |  16.0 s |    1.18 GiB | 0.74 s |  34.2 |  0.24 s | 0.73 s |   303 MiB |
|  4096 |   64 |     107,070 |  28.0 s |    2.10 GiB | 1.00 s |  42.6 |  0.35 s | 0.95 s |   417 MiB |
| 16384 |    4 |      82,424 |  52.6 s |    4.43 GiB | 1.00 s |  34.9 |  0.39 s | 1.03 s |   463 MiB |
| 16384 |   64 |     213,676 |  92.0 s |    5.86 GiB | 1.96 s |  85.3 |  0.77 s | 1.96 s |   911 MiB |
| 16384 |  256 |     634,705 | 453.1 s |   10.41 GiB | 5.85 s | 270.1 |  2.02 s | 5.53 s |   2.3 GiB |
| 16384 |  512 |   1,195,738 |  1298 s |   16.49 GiB | 10.7 s | 516.5 |  3.71 s | 10.7 s |   4.3 GiB |
| 16384 | 1024 |  (2,317,804) | **REFUSED**: 45 min timeout at 19.4 GiB | | | | | | |

The full grid (s in {16, 64, 256, 1024, 4096} x k in {4, 16, 64}, plus s = 2^14 at
k in {4, 16, 64, 256, 512}) is in the CSV and in `fit.py`'s table.

**Fits** (least squares over all 20 measured points; n = constraints):

| Quantity | Fit | R^2 |
|---|---|---|
| witness + prove | 0.083 s + 11.98 us * n, about 83k constraints/s marginal | 0.999 |
| prove alone | 8.87 us * n | |
| witness alone | 3.11 us * n | |
| setup | 8.99 us * n | |
| proving key | 431 B * n | |
| prove RSS | 3.65e-3 MiB (3.74 KiB) * n | |

A power law over the 10 points with n >= 50k gives n^0.97.

- **Per chunk, in k and s:** witness + prove = a_s + b_s * k with
  `b_s = 11.98 us * (764 + 2S + Q + 7(P-1) + log2 P + S/8 + 68)`.
  - At s = 2^14 that is a = 0.96 s, b = 26.3 ms/record. It predicts the measured
    k = 256 and k = 512 chunks within 2%.
  - At s = 1024, b = 14.1 ms/record.
- **Compile at s = 2^14:** time = 45.7 + 0.698 k + 3.42e-3 k^2 s (R^2 0.9998), and
  memory = 4.34 GiB + 24.3 MiB * k (R^2 1.0000). The k = 1024 refusal is consistent with
  this fit, which gives 4,343 s. The largest chunk that fits the wall is about
  **k = 785**, bound by time.

**Deployed size, s = 2^14 registers and one proof per m = 2^14-record batch** (computed
from the fits unless marked MEASURED):

- 35,983,852 constraints (exact formula), 30x the largest measured circuit.
- **Compile: exceeds the 45 min / 150 GiB budget.** The evidence is MEASURED: the
  k = 1024 compile was refused at 2701 s. The k = 16384 program strictly contains the
  k = 1024 one (the same commitments and per-record update, over more records), so
  compile time is monotone in k and the deployed compile is refused too. The fits
  are secondary: the quadratic time fit and the linear memory fit give 258 h and
  393 GiB, and even the measured marginal rate (3.3 s/record at k = 256..512, a lower
  bound if growth were only linear) gives 14.9 h. The fitted 393 GiB is 2.6x the
  150 GiB cap but below the box's 559 GiB, so this is a budget verdict, not an
  impossibility.
- If it did compile: setup 323 s, a 15.5 GB proving key, and 431 s of witness+prove
  per batch (393 s from the power law) at 128 GiB RSS. The 64 batches of a 2^20 stream
  would take 7.7 h.
- **Feasible chunking** keeps k at or below about 785. At k = 512, a 2^20-record
  stream is 2,048 chained proofs at 14.45 s each: **8.2 h of proving**, 2 MB of JSON
  proofs and 2,048 verifications. This is the measured per-chunk cost times 2,048: 4
  chunks were measured and every chunk is taken to cost the same (`fit.py` prints these
  rows as "MEASURED chunking").
  - Computed the same way, k = 256 gives 8.6 h, and k = 64 gives 12.4 h.
  - The per-record floor is 2^20 x 2,192 constraints x 11.98 us = **7.65 h**.
  - One-time cost per shape at k = 512: a 21.6 min compile and a 10.7 s setup.

## Caveats

- **Shared machine.** The runs shared the box with other jobs (load1 3-7):
  - sibling SS/GK zokrates compiles and proves;
  - unrelated GPU training jobs.

  Proves waited for other zokrates provers, but compiles overlapped. A compile is
  single-threaded, so the effect is small but not zero. See `load1` and the
  `concurrent_zokrates` notes in the CSV. In particular, the k = 512 `edge` run was
  started by hand while the `wall` stage's k = 1024 compile was still running, so the
  two compiles shared the box. `run_all.sh` runs them one after the other.
- **Initial state.** The chain starts from the all-zero array. A verifier needs the
  initial commitment's opening, which is public for an empty sketch, to anchor the
  chain. The driver uses a fresh random salt.
- **Semantics vs zkSketch's HLL.** Both use valid geometric ranks, so the estimates
  differ statistically but the cost class does not:
  - this operator: leading zeros over a 64-bit window of a BN254 Poseidon output;
  - zkSketch: trailing zeros over a 31-bit window of a BabyBear Poseidon2 output.

  On 50k AOL keys the native estimate is within 1-2 standard errors at b = 6..12.
- **Verify time and proof bytes.** Verify time is the ZoKrates CLI, process start
  included. Proof bytes are the JSON encoding (997 B). A raw BN254 Groth16 proof is
  128 B compressed.
- **One-time costs per circuit shape (s, k).** Groth16 needs a circuit-specific trusted
  setup, and the compile is also per shape. Both are reported separately from proving.
- **Compile-time growth is ZoKrates' own.** At s = 2^14, compile time grows
  superlinearly in k. The phase that grows is the reducer ("Reduce program": 49.5 s at
  k = 64, 122.5 s at k = 128, from `RUST_LOG=debug`). The Count-Min operator shows the
  same pattern (k = 64 -> 256: 58 -> 185 s). Memory stays linear in k.
