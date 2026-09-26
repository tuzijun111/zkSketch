# Greenwald-Khanna replay operator in zkStream's toolchain

A Greenwald-Khanna (GK, SIGMOD '01) quantile-summary update operator built with
zkStream's own general-purpose method: a ZoKrates 0.8.8 program proved with Groth16
over BN254, chained through salted Poseidon commitments, as zkStream's §4.4 proposes
for stateful operators (Swalens et al., Middleware '24). zkStream ships no sketch and
no stateful operator, so **this is our circuit**. Report it as "a GK operator
following zkStream's design (replay)", never as "zkStream".

It is the GK member of the zkStream-style baselines next to the Count-Min operator in
`..` (`cm_op.zok.tpl`, `run_zkstream.py`). It uses **none** of zkSketch's circuit
techniques. There is no batch-effect certificate, no multiset, LogUp or permutation
argument, no memory-checked recommit and no sort-then-group certificate. Every record
is applied to the summary one at a time, exactly as the textbook algorithm does.

## Running

```bash
# the measured grid (15 points, 4-chunk chains, 12 forgery checks per point)
scripts/baselines/zkstream/gk/run_gk.py --E 8 16 --k 4 16 64 --cap 16 32 64 \
    --chunks 4 --tamper --prune --overflow-demo
# compile-only constraint sweep (the model's data), e.g.
scripts/baselines/zkstream/gk/run_gk.py --compile-only --E 32 --k 1 4 16 --cap 16 32 64 --nb 14
# large-capacity probes (the compile scaling toward s' = 2^11)
scripts/baselines/zkstream/gk/run_gk.py --E 64 --k 32 --cap 512 --nb 21 --chunks 4 --tamper --prune
# circuit == native reference over ~1000 records, witness only
scripts/baselines/zkstream/gk/run_gk.py --E 8 --k 16 --cap 32 --chunks 0 --validate-chunks 250 --stream fewdistinct
scripts/baselines/zkstream/gk/fit_gk.py        # gate, tables, fits, deployed-size model
scripts/baselines/zkstream/gk/gk_ref.py        # native reference self-test
```

| Variable | Default | Meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | ZoKrates binary and stdlib |
| `BUILD` | `$BASELINE_DIR/build/zkstream_gk` | ZoKrates artifacts (`.out`, keys, witnesses, proofs) |
| `RESULTS` | `../results` | `zkstream_gk.csv` and the raw logs |
| `PIN_CPUS` | `0-31` | `taskset` CPU list, the same as the Count-Min driver |

- Every compile runs under `timeout 45m systemd-run --user --scope -q -p MemoryMax=150G`. A
  compile that is refused or over budget is written as a row with `ok=0`. It is not retried.
- The box is shared. Before each setup and prove, the driver waits (up to `--max-wait` s) until
  no other `zokrates setup|generate-proof` of this user is running. Every CSV row records the
  1-minute load average.

## Files

| File | Role |
|---|---|
| `gk_op.zok.tpl` | the proven operator. Public statement (com_in, batch_digest, com_out) |
| `gk_helper.zok.tpl` | witness helper, never proven. It computes com_in, the digest and the commitment of the NATIVE next summary |
| `gen.sh` | `gen.sh <K> <S> <E> <NB> <outdir>` textual instantiation, as zkStream sizes its circuits (`zokrates.rs:85-87`) |
| `gk_ref.py` | native textbook GK (mirrors `../../zka/gk` `RefGk`), state packing, self-test of the fixed-shape formulation |
| `run_gk.py` | driver: capacity check, compile, setup, chained prove/verify, tamper, validation. Patterned on `../run_zkstream.py` |
| `fit_gk.py` | soundness gate, per-point table, constraint model, time fits, deployed-size model |
| `../results/zkstream_gk.csv` | one row per measured step |
| `../results/zkstream_gk_*.log` | raw console record behind the CSV |

## Configuration

- **Summary.** GK with eps = 1/E for E in {8, 16}, so COMPRESS runs every floor(1/(2 eps)) =
  E/2 = 4 or 8 records. Capacity s' in {16, 32, 64} tuples, a public constant of the circuit.
- **Records.** Keys are the first keys of `data/aol.keys` (little-endian u32). The value is
  v = key & 0x1FFFFF, the same as the other GK baselines. It is computed in-circuit from
  the key's bits.
- **Chunks.** k in {4, 16, 64} records. Each point runs a 4-chunk chain: com_in of chunk c equals
  com_out of chunk c-1, all four proofs verify, and each proof's public inputs are
  (com_in, batch_com, com_out).
- **Widths.** NB = 10 (record count n < 1024). g, Delta and p = floor(2 eps n) then fit in
  L = NB - log2(E) + 1 bits (8 or 7). The large-capacity probes use NB = 21, which gives the
  bit widths a 2^20-record stream needs.
- **Capacity.** The native reference runs first and drops any point whose s' is too small for
  its chain. Three were dropped: (1/8, k=64, 16), (1/16, k=16, 16) and (1/16, k=64, 16).
  For each of them the compiled operator was shown to reject the overflowing chunk
  (`overflow_rejected`).

## Method: what each chunk proves

`gk_op.zok.tpl`, one chunk of K records:

1. **commit-in.** Poseidon(salt_in, n, w_0 .. w_{S-1}) == com_in. The sponge-style chain absorbs
   5 elements per block, the same as the Count-Min operator. The state is the record count n
   and S tuple slots sorted by v. Each tuple is packed into one field element as
   `v * 2^(2L) + g * 2^L + Delta`. Empty slots hold the sentinel `2^21 * 2^(2L)`
   (v = 2^21, above every value), so slots 0..s-1 are the summary.
2. **batch digest.** Poseidon chain over the K keys == batch_com.
3. **Textbook update, record by record, in stream order.** Before record i, if
   n = 0 mod E/2, run COMPRESS. Then INSERT the record, and n += 1.
   - **INSERT.** The prover supplies a one-hot position. The circuit checks
     v_{pos-1} <= v < v_pos, which is the paper's "smallest i with v < v_i", unique even
     with duplicates, and checks that the last slot is a sentinel (no overflow). It then
     shifts slots >= pos up with conditional moves. The new tuple is (v, 1, floor(2 eps n)),
     or (v, 1, 0) for a new minimum (pos = 0) or maximum (v_pos is the sentinel).
   - **COMPRESS** takes no hints. Fixed-shape passes over the S slots recompute exactly
     the paper's Figure 2 loop (i = s-2 down to 1):
     1. `BAND(Delta_i, p)` as a thermometer. band > a iff ceil(Delta/2^a) < floor(p/2^a),
        which an MSB-first automaton over the bits of p and Delta computes.
     2. `g*_i` (t_i plus its descendants): per-band accumulators, left to right.
     3. The right-to-left pass. It tracks the current right neighbour (g, Delta, band,
        including merged g's) and the descendant block of the last merged tuple. The merge
        condition is `BAND(Delta_i) <= BAND(Delta_{i+1})` and
        `E * (g*_i + g_{i+1} + Delta_{i+1}) < 2n`.
     4. Merged g's are written into their kept right neighbours.
     5. An order-preserving compaction network restores a dense sorted array. Each kept
        tuple moves left by d, the number of deleted slots before it. It goes one bit per
        stage, LSB first: at stage b it carries its remaining shift r = d >> b and moves 2^b
        iff r is odd. This is collision-free because d is monotone along the kept tuples. The
        circuit also asserts that t_0 never falls inside a deleted block, the check that the
        reference asserts.
4. **commit-out.** It returns Poseidon(salt_out, n + K, w') as the public output.

## zkStream's idiom vs ours

| | zkStream (artifact @ `33c0d68f`, paper) | this operator |
|---|---|---|
| language / proof | ZoKrates 0.8.8, Groth16 (ark) over BN254 | same |
| sizing | constants rewritten per instance (`zokrates.rs:85-87`) | same (`gen.sh`) |
| chaining | salted Poseidon hash of an operator's output, re-opened by the consumer (`q4a.poseidon.zok:48`, `q4b.poseidon.zok:28-32`, `shared.zok:224-230`) | same idiom, applied to the whole summary (commit-in / commit-out) |
| state | §4.4: pass state as a confidential value between invocations (not implemented in the artifact) | the summary is that confidential value |
| data shapes | fixed-size loops over padded arrays with a length (`gadgets.zok` `Array_u64<N>`) | fixed S-slot array, sentinels mark the length |
| ordering | §4.3: sort outside the proof, assert sortedness inside (`assert_sorted`); the permutation check is left to the verifier via public message IDs | the prover supplies each insert position, the circuit checks v_{pos-1} <= v < v_pos. The committed state carries the multiset, so no external permutation check is needed |
| arithmetic | `u64` values (64-bit decompositions for every comparison) | field elements with narrow strict decompositions (22 to 2L+22 bits), tuples packed one per field element as the CM operator's "packed8" does. This is engineering that makes the baseline cheaper, not slower |
| input authentication | EdDSA signature per message (also `*.nosig.zok` variants) | batch digest, no signatures (same as the CM operator) |

COMPRESS as fixed-shape passes (thermometer bands, prefix accumulators, a scan with
carried state, a shift network) is ordinary oblivious programming, needed because a circuit
cannot branch. It replays the algorithm, one pass per textbook COMPRESS call. It does not
certify a batch effect.

## Correctness and soundness evidence

- **Native reference.** `gk_ref.py` is the paper's pseudocode (literal list deletions and
  descendant walk). Its self-test checks two things:
  - the band automaton equals the BAND set definition for every p < 300;
  - a Python mirror of the circuit's passes equals the reference after every record of 24
    streams (AOL, uniform, 20-value, monotone). GK's invariants hold throughout.
- **Circuit == reference, every chunk.** The helper commits the NATIVE next summary. The operator
  recomputes it in-circuit, and its output must equal that commitment (binding). This held for:
  - all 60 proven chunks of the grid and all 12 of the large-capacity probes;
  - 656 witness-only validation chunks over about 1000 records. These covered AOL and a
    24-value synthetic stream (more descendant blocks), E = 8 and 16, and the k < E/2 path
    where COMPRESS is conditional.
- **Forgeries** (every point, against the last proven chunk, whose state holds merged tuples).
  compute-witness rejects all 11 input forgeries:
  - com_in + 1, batch_com + 1, salt_in + 1, n_in + 1;
  - the previous chunk's (stale) state;
  - one tuple's g + 1;
  - a key not in the digest;
  - a dropped record;
  - the insert position +1 or -1 (the -1 case puts a record in front of an equal value);
  - a two-hot position.

  verify rejects the honest proof carrying a com_out for a summary that is wrong in one slot.
- **ZoKrates pitfall 1 (soundness), found here.** ZoKrates 0.8.8 silently removes an `unpack`
  whose bits are never read, so a bare `unpack::<N>(x)` is **not** a range check. For example,
  `bool[8] c = unpack::<8>(b - a)` with c unused compiles to one constraint in total. The first
  development build accepted wrong insert positions because of this. Every pure range check
  now re-packs its bits and asserts equality (`range_check` in the template). The tamper cases
  insert_pos_plus1/minus1 guard against a regression. The Count-Min operator reads all its
  bits and is not affected. Any other ZoKrates baseline that range-checks with a bare
  `unpack` should be re-checked.
- **ZoKrates pitfall 2 (compile time).** ZoKrates 0.8.8 copies the whole array on every element
  assignment. A loop writing N slots compiles in 0.26 s, 0.96 s and 4.0 s for N = 1024, 2048
  and 4096, which is quadratic. The first template (v1) kept per-slot 2-D tables (bands, shift
  bits), and its compile time grew as about s'^2 (391 s at s' = 512). The current template (v2)
  keeps only 1-D arrays and carries a single remaining-shift field through the compaction.
  That cuts the s' = 512 compile to 103 s, with about the same constraint count (-2% at
  s' = 512, +1% at s' = 16). The v1 rows are kept, not used, in
  `../results/zkstream_gk_v1_before_restructure.{csv,log}`. v1 was sound: every chain,
  forgery and validation passed.

## Results

Measured on the Threadripper PRO 9975WX (32 cores pinned, 559 GiB, shared, load1 about 4-8).
Full rows are in `../results/zkstream_gk.csv`, and `fit_gk.py` prints the tables.

### Per chunk (MEASURED, median of 4 chained chunks)

Witness+prove is the prover's cost per chunk, and w+p/rec divides it by k. Every point
passed the chain check (4 of 4) and rejected all 12 forgeries.

| 1/eps | k | s' | constraints | compile | GB | setup | witness | prove | w+p/rec | verify | load1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 4 | 16 | 6,910 | 2.7 s | 0.27 | 0.09 s | 0.03 s | 0.08 s | 28.5 ms | 6.2 ms | 3.96 |
| 8 | 4 | 32 | 12,293 | 4.5 s | 0.43 | 0.14 s | 0.06 s | 0.15 s | 50.9 ms | 6.6 ms | 3.90 |
| 8 | 4 | 64 | 23,478 | 8.0 s | 0.71 | 0.25 s | 0.10 s | 0.25 s | 87.2 ms | 7.1 ms | 3.85 |
| 8 | 16 | 16 | 17,845 | 4.3 s | 0.42 | 0.18 s | 0.07 s | 0.18 s | 15.6 ms | 7.3 ms | 3.94 |
| 8 | 16 | 32 | 32,987 | 6.5 s | 0.62 | 0.32 s | 0.11 s | 0.33 s | 27.5 ms | 6.9 ms | 3.95 |
| 8 | 16 | 64 | 64,947 | 12.0 s | 1.03 | 0.57 s | 0.22 s | 0.54 s | 47.6 ms | 7.4 ms | 3.69 |
| 8 | 64 | 32 | 114,746 | 14.9 s | 1.29 | 0.94 s | 0.35 s | 0.89 s | 19.4 ms | 7.1 ms | 3.79 |
| 8 | 64 | 64 | 229,806 | 31.7 s | 2.26 | 1.75 s | 0.73 s | 1.72 s | 38.2 ms | 7.2 ms | 4.82 |
| 16 | 4 | 16 | 6,752 | 2.8 s | 0.27 | 0.08 s | 0.03 s | 0.09 s | 30.7 ms | 6.5 ms | 5.64 |
| 16 | 4 | 32 | 11,991 | 4.4 s | 0.43 | 0.13 s | 0.05 s | 0.14 s | 48.2 ms | 6.8 ms | 5.39 |
| 16 | 4 | 64 | 22,888 | 7.6 s | 0.71 | 0.24 s | 0.09 s | 0.24 s | 84.2 ms | 7.0 ms | 4.81 |
| 16 | 16 | 32 | 21,410 | 5.8 s | 0.54 | 0.23 s | 0.08 s | 0.24 s | 20.3 ms | 6.8 ms | 4.58 |
| 16 | 16 | 64 | 40,160 | 10.4 s | 0.86 | 0.40 s | 0.16 s | 0.39 s | 34.4 ms | 7.2 ms | 4.62 |
| 16 | 64 | 32 | 68,435 | 11.4 s | 0.99 | 0.61 s | 0.22 s | 0.58 s | 12.6 ms | 7.0 ms | 4.34 |
| 16 | 64 | 64 | 130,655 | 19.8 s | 1.61 | 1.15 s | 0.45 s | 1.08 s | 23.8 ms | 7.3 ms | 3.76 |
| 64 | 32 | 512 | 323,452 | 102.5 s | 6.52 | 4.56 s | 2.20 s | 4.35 s | 205 ms | 7.7 ms | 3.72 |
| 64 | 32 | 1024 | 655,005 | 331.4 s | 16.23 | 11.38 s | 6.12 s | 10.87 s | 531 ms | 7.5 ms | 3.76 |
| 64 | 32 | 2048 | 1,337,224 | 1439 s | 45.8 | 32.9 s | 19.4 s | 30.8 s | 1.57 s | 8.0 ms | 8.23 |

- The last three rows are the large-capacity probes. They use 1/eps = 64 (one COMPRESS pass
  per 32-record chunk) and NB = 21, so g, Delta and p are 16 bits wide, the widths a
  2^20-record stream needs.
- **s' = 2048 is the deployed capacity.** That chunk compiled (24 min, 46 GB) and set up
  (33 s, 553 MB proving key). Each of its 4 chained chunks was proved in 31 s (prover RSS
  15.4 GB) after a 19 s witness. It is the largest ZoKrates compile in this harness,
  2.9x the Count-Min operator's 461 K.
- Proofs are 997 B (JSON, 3 public inputs). Prover peak RSS ranges from 45 MB to 15.4 GB.
  Proving-key size is about 414 B per constraint.
- The three dropped points (s' = 16 too small) are listed under Configuration.

### Constraint model (MEASURED, 40 compiles)

Least squares over every compile: the grid, a compile-only sweep over 1/eps in {4, 8, 16, 32,
64}, k in {1..64}, s' in {8..2048} and NB in {10..22}, and the probes. The fit is within 11
constraints (0.21%) of every compile, and its coefficients come out close to integers, not
exactly integers: the fitted terms include NC = -76.09, k = 44.25, cond*S = 1.18 and
NB = -0.13 (`fit_gk.py` prints every term). The formula below rounds the coefficients and
leaves out the small NC, cond*S and NB terms. Refitted without the s' = 2048 probe, the fit
predicts that compile to within 70 constraints (+0.005%):

    constraints ~= 440 + 708 * ceil((s'+1)/5)          two state commitments (354 per Poseidon block)
                 + 340 * ceil(k/5)                    batch digest
                 + k * (5 s' + 2 (22 + 2L) + 44)      INSERT, per record
                 + NC * s' * (9L + (M + 2Q) + LOGS(LOGS+1)/2 + 6 LOGS + 32)    COMPRESS, per pass

Here NC = number of COMPRESS passes in the chunk, L is the width of g, Delta and p,
M = NB + log2(E) + 2, Q = bitlen(L) and LOGS = log2(s').

- INSERT is 5 constraints per slot: one-hot booleanity, the two neighbour selects, and the
  two-product conditional shift.
- COMPRESS is 9L per slot for unpacking, the band automaton and g*. The three scan
  comparisons cost M + 2Q, and the compaction network costs LOGS(LOGS+1)/2 + 6 LOGS.

Both are linear in s', so the per-record cost is O(s') for INSERT plus O(s' log^2 s') every
1/(2 eps) records for COMPRESS. At the measured sizes that is 557 to 3,439 constraints per
record (s' = 16..64, NB = 10), then, at NB = 21 (the widths a 2^20-record stream needs),
7,809 at s' = 512, 15,913 at s' = 1024 and 32,697 at s' = 2048 (1/eps = 64). `fit_gk.py`
evaluates each point at its own NB.

### Time and memory (MEASURED, then fitted)

- **Prove rate falls with size.** Groth16 (ark) proves 134 K constraints/s at 7 K constraints,
  60 K/s at 655 K and 43 K/s at 1.34 M. A power law through the points >= 100 K gives
  prove ~ c^1.47 and witness ~ c^1.66.
  - The k = 25 deployed shape (0.96x the largest point) is costed from the s' = 2048 probe,
    scaled linearly.
  - The deployed-chunk prove times below are bounds from measured rates, not extrapolations.
- **Compile.** The one-pass series (1/eps = 64, k = 32) compiles as s'^1.38 overall:
  - 11 s / 1.0 GB at s' = 64;
  - 44 s / 3.2 GB at s' = 256;
  - 103 s / 6.5 GB at s' = 512;
  - 331 s / 16.2 GB at s' = 1024;
  - 1439 s / 45.8 GB at s' = 2048.

  The step from 1024 to 2048 is 4.3x in time, about s'^2. The O(s'^2) array copying of
  pitfall 2 comes back at the largest size, even in the v2 template.

### Deployed size (MODELED): eps = 1/51, s' = 2^11, m = 2^14 records per chunk

The inputs are 656 COMPRESS passes per chunk (one every 25 records) and 17-bit
g/Delta/p (n < 2^21).

- **One chunk costs 651 M constraints**: fixed 291 K, plus 16,384 records at 39.7 K each.
  - That is 487x the largest ZoKrates compile that finished (1.34 M, above).
  - INSERT alone is 172 M, 128x that compile, even if COMPRESS were free.
  - Were it compilable, the proving key would be about 269 GB.
  - Proving would take at least 1.4 h per chunk at the best measured rate, and 4.2 h at
    the rate of the largest point. The 64 chunks of a 2^20 stream would take at least 86 h.
- **Smallest chunk shape.** A chunk has to contain a COMPRESS pass every 25 records.
  - One pass over 2^11 slots is 730 K constraints. A 25-record chunk with its pass is
    1.28 M. That is inside the measured envelope: the 32-record probe at s' = 2048
    compiled.
  - A 2^20-record stream then needs 41,943 chained proofs. Scaling the probe's measured
    50 s per chunk to 1.28 M constraints gives about 48 s each, so about 561 h (23 days) of
    witness+prove on 32 cores, plus 42 MB of proofs to verify.
  - Two caveats on that number. The s' = 2048 probe it is scaled from was measured at
    load1 about 8.2, so the 48 s may be inflated. And the k = 25, eps = 1/51 shape cannot
    be built by `gen.sh`, which takes only power-of-two 1/eps, so it is costed, not
    compiled.
- **VERDICT: infeasible at the deployed chunk size.**
  - A 2^14-record chunk is 487x beyond anything ZoKrates compiled here.
  - Shrinking the chunk does not help. The per-record cost at s' = 2^11 is about 40 K
    constraints (O(s') INSERT plus O(s' log^2 s') COMPRESS). A 2^20 stream therefore needs
    about 42 G constraints of proving in any chunking. At the smallest compilable shape
    that is about 561 h of witness+prove.
- **Capacity sensitivity** (MODELED, same fitted terms and deployed widths). s' = 2^11
  matches the capacity zkSketch's GK is measured at, so the comparison does not inflate
  the baseline's capacity. A smaller s' shrinks the cost but not the verdict:
  - at s' = 256 a 2^14-record chunk is about 76 M constraints, still about 57x the
    1.34 M compile wall, so it stays INFEASIBLE;
  - the whole-stream proving work, 41.6 G constraints at s' = 2^11, falls to about
    9.9 G at s' = 512 and 4.9 G at s' = 256.

## Caveats

- **COMPRESS rule.** The task text paraphrased it as "g_i + g_{i+1} + Delta_{i+1} <=
  floor(2 eps n)". We implement the paper's rule, which uses g*_i (t_i with its descendants),
  the band order and a strict `< 2 eps n`. It matches `../../zka/gk`, so the GK baselines agree.
- **Minimum kept.** COMPRESS stops at i = 1, so t_0 stays the minimum, as the paper's §2.1
  requires (see `../../zka/gk/README.md` for why the Figure 2 loop to i = 0 loses it).
- **eps = 1/2^j.** The circuit computes p = floor(2n/E) by a bit shift, so E must be a power of
  two. eps = 1/51 (the deployed setting) would need a floor-division hint, two range checks per
  pass. The deployed model keeps every other term at the deployed widths.
- **Capacity.**
  - s' is a public constant sized from the AOL prefix that was measured. The textbook
    worst-case bound (11/(2 eps)) log(2 eps n) is far larger.
  - A stream that exceeds s' makes the operator reject. That is a liveness failure, not a
    soundness one.
  - The deployed capacity s' = 2^11 is the figure this comparison fixes (with eps = 1/51 and
    m = 2^14). It matches the capacity zkSketch's GK is measured at; the capacity
    sensitivity under Deployed size covers smaller s'. On AOL, textbook GK at
    eps = 1/51 held at most 130 tuples over 2^16 records. The worst-case bound at
    n = 2^20 is about 4,300.
- **Chain anchor.** Each statement links com_in to the previous com_out, and soundness is
  inductive from a well-formed state. Nothing in-circuit pins the first com_in to the empty
  summary, and `gk_op.zok.tpl` never checks that w_in is sorted or sentinel-suffixed. Its
  only structural check on the input state is `w[S-1] == SENTW` (in INSERT); the first
  COMPRESS pass bit-decomposes every word, which fixes the field widths but no ordering or
  GK invariant. A deployment must therefore fix com_0 = commit(0, all-sentinel, salt_0),
  and the verifier must recompute it. This is stricter than for the Count-Min operator,
  where any table is a legal state.
- **Helper.** The helper computes Poseidon only. The next summary comes from the native
  reference, and the operator must reproduce it. The helper's time is not charged.
- **Measurements.** Verify times are the CLI with process start. Proof bytes are ZoKrates'
  JSON. Groth16 setup is per circuit (per eps, k, s', NB) and one-time, and it is reported.
  Timings come from a shared box, with the load in every row.
