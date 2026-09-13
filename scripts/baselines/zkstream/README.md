# zkStream comparison harness

A Count-Min update operator built in zkStream's toolchain (ZoKrates 0.8.8,
Groth16 over BN254), following the stateful-operator design in zkStream's §4.4
(Swalens et al., Middleware '24). zkStream ships no sketch and no stateful
operator, so **this is our circuit**. Report it as "a Count-Min operator
following zkStream's design", never as "zkStream".

zkStream's code is not vendored: `../fetch_baselines.sh` clones it at `33c0d68f`
into `$BASELINE_DIR` (default `~/ext-baselines`). Every ZoKrates artifact is
written under `$BASELINE_DIR/build/zkstream`, outside this repo.

## Running

Small scale only: these runs test the harness and give a first conclusion.

```bash
scripts/baselines/zkstream/run_zkstream.py --k 16 64 256 --chunks 4 --tamper
scripts/baselines/zkstream/run_ours.sh
scripts/baselines/zkstream/fit.py
```

Run the two drivers one after the other, never together. Both refuse to start
while a `zokrates`, `exp_compose` or `r0vm` of yours is running, and both pin to
the same 32 hardware threads.

| Variable | Default | Meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | zkStream clone, ZoKrates binary, build dir |
| `BUILD` | `$BASELINE_DIR/build/zkstream` | ZoKrates artifacts |
| `RESULTS` | `results/` next to the scripts | CSVs |
| `PIN_CPUS` | `0-31` | `taskset` CPU list for both provers |
| `MS`, `REPS` | `16 64 256`, `3` | zkSketch batch sizes and repetitions (`run_ours.sh`) |

| Script | Proves | Writes to `$RESULTS` | Measures |
|---|---|---|---|
| `run_zkstream.py` | yes | `zkstream_small.csv` | constraints, compile, setup, witness, prove, verify, bytes and RSS per chunk; forgery rejection |
| `run_ours.sh` | yes | `zks_small.csv` | zkSketch leaf prove, verify, proof bytes and RSS at the same d, w and batch sizes |
| `fit.py` | no | stdout | `a + b·records` fits for both sides, checked against the measured 2^14 leaf |
| `gen.sh` | no | the build dir | instantiates the two templates for one (N, D, W) |

## How the operator works

- `cm_op.zok.tpl` is proven. It opens a salted Poseidon commitment to the table,
  checks its records against a public batch digest, derives each record's columns
  from one in-circuit hash, applies the increments, and returns the commitment to
  the updated table. Its public statement is three field elements.
- `cm_helper.zok.tpl` is the same body with the asserts turned into outputs. It
  runs through `compute-witness` only, to give the driver the next table and its
  commitment without reimplementing BN254 Poseidon. It is never set up or proven,
  and its time is not charged to the prover.
- Consecutive chunks share a commitment: the driver checks that each chunk's
  `com_in` equals the previous `com_out` and that every proof verifies.
- Counters are 21-bit lanes, so a single counter overflows after 2^21-1 hits.
  That is ample at small scale; a 2^20-record run needs 31-bit lanes (same
  constraint count, since lane weights are constants).

## Reading the results

Both sides pay a fixed cost per batch: the operator pays two commitment chains
and a digest per chunk, and a zkSketch leaf pays a per-batch table term. `fit.py`
therefore fits intercept and slope separately, labels every extrapolation
MODELED, and checks zkSketch's fit against its measured 2^14 leaf before quoting
anything.

At d=3, w=1024 the Groth16 intercept is the larger of the two (about 1.1 s
against 0.1 s), so zkSketch is cheaper per batch at every size measured and
there is no break-even. That depends on the geometry: zkSketch's table term
grows with d*w, so re-check the break-even before quoting it at d=7, w=2^14.

Neither side's small-scale slope is its large-scale slope. zkSketch's slope from
m=16..256 over-predicts its measured 2^14 leaf by about 22%, and the Groth16
prove rate rises with circuit size (83K to 128K constraints/s across k=16..256).

This comparison cannot speak to the proof forest: ZoKrates can express only a
per-batch chain or a Nova recursive chain, never a tree.

## Layout

- `probes/packed8/` holds the probe that established the encoding (1,516
  constraints per record at d=3, w=1024; committed N=16 operator in 44 s / 3.8 GB).
- `probes/port/` holds the first committed-operator and Nova probes.
- `probes/selector/` holds the one-hot selector probes that the packed encoding
  replaced.
- Moved here from `scripts/baselines/{zkstream_cm,zkstream_port,probes}` on
  2026-09-13. The q5b forgery reproduction is deliberately **not** in this repo;
  it lives at `$BASELINE_DIR/private/` pending responsible disclosure.
