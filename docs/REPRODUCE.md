# Reproducing the zkSketch experiments

This is the single "how to run and configure the experiments" reference. The
current evaluation (`latex/zk1.tex` §Evaluation) runs through **four script
surfaces**:

| Surface | What it measures | Backends |
| ------- | ---------------- | -------- |
| `scripts/run_experiments.sh e1` | per-family **circuit-cost matrix**: family × variant × batch sweep, incl. the naive replay baselines (witness/prove/verify split, proof size, peak RSS) | both |
| `scripts/run_experiments.sh e2` | **integrity**: tamper-rejection rate + ZK-vs-plaintext fidelity | both |
| `scripts/run_experiments.sh e5` | **composition-topology ladder** (structural, digest lift): auditor cost Θ(E)→O(1) | plonky3 |
| `scripts/run_experiments.sh e8` | **cross-stack head-to-head**: plonky2 SNARK vs plonky3 STARK, leaf + recursive merge | both |
| [`scripts/run_compose.sh`](../scripts/run_compose.sh) | composition over **real recursive proofs**: all four families × {per_batch, chain, forest}, cores/machines budgets, plus **mixed updates+queries** (`EXP_COMPOSE_QUERY_EVERY`) | plonky3 |
| [`scripts/run_stream.sh`](../scripts/run_stream.sh) | **whole-stream total prove time**: fixed N, sweep batch size × cores, omc vs merkle CM leaves | plonky3 |
| [`scripts/run_decode.sh`](../scripts/run_decode.sh) | **decode/query circuits** of the deployed variants: unit tests + proven results table | plonky3 |

Earlier E-series modes (e3, e4, e6, e7, e9, e10, inputfold, casestudy, and the
RQ1–RQ4 figure track) are **retired from the driver** — each was superseded by
one of the surfaces above. Their runners stay in `examples/` and remain
directly runnable; see [§Archived experiments](#archived-experiments) at the
bottom.

## TL;DR — one command

```bash
# default: e1, both backends, small synthetic slice (offline, ~1–2 min)
scripts/run_experiments.sh
# → results/e1_circuit.csv   (plonky3 + plonky2 rows merged)
#   results/env.json, plonky2/results/env.json

scripts/run_experiments.sh e2      # integrity (tamper + fidelity) → results/e2_integrity.csv
scripts/run_compose.sh             # real recursive composition   → results/stream_compose.csv
scripts/run_stream.sh              # whole-stream total time      → results/stream_forest.csv
scripts/run_decode.sh              # decode tests + results table
```

On a small AOL slice instead (fetch first, see below):

```bash
python3 scripts/fetch_datasets.py
EXP_DATASET=aol scripts/run_experiments.sh
```

## Prerequisites

- **Rust stable** for the plonky3 crate (repo root).
- **Rust nightly** for the plonky2 crate (`plonky2/`); this is pinned
  automatically by `plonky2/rust-toolchain.toml`, so `cargo run` in that dir
  selects nightly with no `+nightly` needed. (`rustup toolchain install nightly`
  if you don't have it.)
- Network access on first build (both pull pinned git deps) and to fetch the
  real datasets. The Plonky3 forks are public — no GitHub auth needed. If cargo's
  built-in git client flakes on the anonymous fetch (`failed to authenticate` /
  `revision … not found`), re-run with `CARGO_NET_GIT_FETCH_WITH_CLI=true` so the
  fetch goes through the system git CLI instead.
- Linux for `peak_rss_mb` (sampled from `/proc/self/status`); on other OSes the
  RSS column reads 0 but everything else works.

## Datasets — synthetic (free) vs real (fetch)

| Dataset | Kind | Needs fetching? |
| ------- | ---- | --------------- |
| `uniform`, `gaussian`, `zipf` | synthetic (deterministic, S³-matched) | no — shipped as `data/{gaussian,uniform,zipf}.keys` (git-tracked), or regenerate (below) |
| `aol`, `netflix` | real S³ datasets (S³'s exact key recipe) | **yes** — see below |

The synthetic datasets are **git-tracked** (frozen, byte-portable — un-ignored so
they ship with the repo) and also regenerable deterministically — no download.
The in-code generators are the offline fallback if the files are absent:

```bash
cargo run --release --example gen_synthetic        # → data/{gaussian,uniform,zipf}.keys + manifest
GEN_SYNTH_N=1000000 cargo run --release --example gen_synthetic   # larger streams
```

Fetch the real datasets (capped, streamed — only a small prefix downloads):

```bash
python3 scripts/fetch_datasets.py                 # both, default 1M-key cap
AOL_MAX_KEYS=200000 NETFLIX_MAX_KEYS=200000 python3 scripts/fetch_datasets.py
python3 scripts/fetch_datasets.py aol             # just one
python3 scripts/fetch_datasets.py --force         # re-download
```

Keys land in `data/aol.keys` / `data/netflix.keys` (shared by both crates). These
processed 32-bit key streams are tracked in git (the raw corpora are not); re-run
the script to refresh or grow them. The keys use **S³'s exact derivation**
(AOL = `CRC32(normalised ClickURL) & 2³²−1`, Netflix = per-record customer id), so
our inputs match S³ bit-for-bit. See [datasets.md](datasets.md).

## Partial (testing) vs whole (real-run) dataset

**Each runner consumes `max(EXP_M)` keys per family — a small slice.** That's
the default and is intended for *testing* (fast, fits in memory). The dataset
behind it can be tiny or huge; the runner only pulls the prefix it needs.

- **Partial / testing (default):** small `EXP_M` (e.g. `4,8,16,32`) → a few
  dozen keys per family. This is what `scripts/run_experiments.sh` does out of
  the box.
- **Whole / larger runs:** fetch more keys (raise the `*_MAX_KEYS` caps) and
  raise `EXP_M` to consume a bigger slice, e.g.:
  ```bash
  AOL_MAX_KEYS=1000000 python3 scripts/fetch_datasets.py --force
  EXP_DATASET=aol EXP_M=256,1024 scripts/run_experiments.sh
  ```
  (Large `m` pushes prover time/memory up fast; start small and scale.)

## E1 — the per-family circuit-cost matrix

The main experiment: one row per `backend × family × variant × shape × m`.

```bash
scripts/run_experiments.sh e1
# separate invocations accumulate distinct CSVs via EXP_OUT (or positional $2):
EXP_FAMILY=cm EXP_CM_VARIANT=omc EXP_D=7 EXP_W=16384 EXP_M=16,64,256,1024 \
  BACKENDS=plonky3 scripts/run_experiments.sh e1 cm_batch_omc.csv
EXP_FAMILY=ss EXP_SS_VARIANT=naive EXP_SS_CAP=16384 EXP_M=16,32,64 \
  BACKENDS=plonky3 scripts/run_experiments.sh e1 ss_batch_naive.csv
```

### Configuration (env vars)

| Var | Meaning | Default |
| --- | ------- | ------- |
| `EXP_DATASET` | `uniform`\|`gaussian`\|`zipf`\|`aol`\|`netflix` | `uniform` |
| `EXP_FAMILY` | `all` or comma-list of `cm,gk,hll,ss` | `all` |
| `EXP_M` | comma-separated batch sizes. **Comma lists only** — range syntax (`16..1024`) is silently dropped → empty sweep | `4,8,16,32` |
| `EXP_D` / `EXP_W` | CM depth `d` (1..=8) / comma-list of widths `w` (powers of 2) | `4` / `8` |
| `EXP_CM_VARIANT` | `one_hot`\|`merkle`\|`merkle_fast`\|`merkle_gb`\|`memcheck`\|`omc`\|comma-list. See the [script header](../scripts/run_experiments.sh) and [countmin.md](countmin.md) for what each rebind is | `one_hot` |
| `COUNTMIN_MAX_SEL_CELLS` | one_hot selector budget (`batch·d·d·w`); at `d=7,w=16384` only `m=16` fits the default | `16777216` |
| `EXP_HLL_B` | comma-list of HLL precisions `b`; registers = `2^b` | `4` |
| `EXP_HLL_VARIANT` | `one_hot`\|`merkle`\|`omc`\|comma-list (`omc` = OMC max-update rebind, Θ(m+batch)) | `one_hot` |
| `HLL_FULL_MAX_SEL_CELLS` | skip one_hot cells whose `32·2^b·m` ALU table exceeds this (`status=too_large` instead of OOM). Real per-table ceiling ≈ `1048576` — lower it when sweeping `b=14` with `m>64` | `4194304` |
| `EXP_SS_CAP` | comma-list of SpaceSaving capacities (rounded up to even ≥2) | `8` |
| `EXP_SS_VARIANT` | `certified`\|`naive`\|`both`\|comma-list. `naive` = per-record replay baseline, Θ(m·cap) | `certified` |
| `EXP_GK_CAP` | comma-list of GK capacities (rounded up to even ≥2) | `8` |
| `EXP_GK_VARIANT` | `certified`\|`naive`\|`bandmerge`\|`bandmerge2`\|`both`\|comma-list. `bandmerge2` = the deployed single-pass group-by band-merge; `naive` = Θ(m·cap) replay | `certified` |
| `EXP_GK_S` | pin the band-merge accuracy `s=1/ε`. Unset, `s` is derived per cell from `(cap, m)` and **drifts across an m-sweep** — pin it for iso-accuracy comparisons | derived |
| `EXP_CORES` | plonky3-only: pin the prover to N cores (the cores-per-proof knob); adds a `cores` CSV column | all cores |
| `BACKENDS` | `plonky3`\|`plonky2`\|`both` | `both` |
| `EXP_OUT` | rename the combined CSV to `results/<EXP_OUT>` (also positional `$2`) | per-experiment name |

**Measurement note:** e1 runs each cell exactly **once** (no warm-up, single
value per metric — the CSV has no median/p95 spread). `EXP_TRIALS`/`EXP_WARMUP`
apply to e5/e8, not e1.

**Feasibility at the headline shapes** (32-core box, per-table trace ceiling
2²⁵ padded rows): the naive SS/GK baselines are Θ(m·cap) — at `cap=16384` they
are only feasible for small `m` (≲128–256), and an over-big cell can **OOM the
whole process**, killing later sweep cells. Run naive baselines in their own
invocation (separate `EXP_OUT`), certified/optimized sweeps in another. At
`d=7,w=16384` CM `one_hot` fits only `m=16`; `merkle` dies past `m=1024`
(use `merkle_gb` beyond); `omc` fits the full sweep.

### Running a single backend manually

```bash
# plonky3 (STARK) — writes results/e1_circuit.csv + results/env.json
EXP_DATASET=uniform EXP_M=4,8 cargo run --release --example exp_e1

# plonky2 (SNARK) — writes plonky2/results/e1_circuit.csv + env.json
cd plonky2 && EXP_DATASET=uniform EXP_M=4,8 cargo run --release --example e1_metrics_demo
```

### Output

`results/e1_circuit.csv` (one row per `backend × family × variant × shape × m`):

```
backend, family, variant, m, d, w, s,
trace_rows, num_columns, constraint_count, proof_size_bytes,
witness_gen_ms_median, prove_ms_median, prove_total_ms_median, prove_total_ms_p95,
verify_ms_median, peak_rss_mb_median, peak_rss_mb_p95, status
```

- `prove_total = witness_gen + prove`; both exclude the one-time **circuit
  build** (amortized) so the two backends' prove times are comparable — the
  same convention as `plonky2/COMPARISON.md`.
- **plonky3** is a multi-table batch-STARK with no single column count, so
  `num_columns = 1` and `trace_rows` is the **sum of padded table heights**
  (`constraint_count = trace_rows`). **plonky2** is a single PLONKish circuit:
  `trace_rows = degree`, `num_columns = num_wires`, `constraint_count =
  trace_rows · num_columns`. Cross-backend comparisons should use **prove time,
  proof size, and peak memory** (constraint_count is shaped differently per
  backend).
- `env.json` records CPU/cores/RAM/OS/rustc + backend field/hash/extension.

All `data/*.keys` (synthetic + real) and the root `results/*.csv` are tracked in
git, so a fresh clone has them; everything is regenerable by re-running the
commands above. Only `plonky2/results/` is git-ignored (the merged combined CSVs
live under the root `results/`).

## E2 — integrity (tamper + fidelity)

```bash
scripts/run_experiments.sh e2                 # both backends → results/e2_integrity.csv
EXP_DATASET=aol EXP_TAMPER_TRIALS=50 scripts/run_experiments.sh e2
```

Per family it reports the **tamper reject rate** (5%-row tamper over
`EXP_TAMPER_TRIALS` trials, default 50; measured at the binding layer — a
tampered batch changes `Com(S_t)`/the batch fingerprint, so the honest-root
proof is rejected) and **fidelity** (`zk_answer` == `plaintext_answer`, plus
the sketch error vs. exact `ground_truth`). Columns:
`backend, family, query_type, tamper_trials, tamper_reject_rate, zk_answer,
plaintext_answer, ground_truth, zk_eq_plaintext`. In-circuit *constraint-level*
rejection (the prover can't even produce an accepted false-transition proof) is
covered by the unit tests — `cargo test --release --lib soundness rejects`
(plonky3) and the `*_rejects_wrong_final` tests (plonky2).

## E5 — composition-topology ladder (verifier cost is the headline)

```bash
scripts/run_experiments.sh e5                 # plonky3 only → results/e5_ladder.csv
EXP_E5_WINDOWS=16,64,256,1024 EXP_TRIALS=5 scripts/run_experiments.sh e5
```

Four rungs of the §4 composition framework over an audit window of `E` epochs;
the headline is the **auditor's** cost collapsing from `Θ(E)` to `O(1)` while the
prover's online merge cost stays amortised `O(1)`:

| setting | prover merges/insert | worst cascade | verifier_checks | root size |
| ------- | -------------------- | ------------- | --------------- | --------- |
| `no_composition` | 0 (re-prove each) | 0 | **E** | `E·112` B |
| `per_batch_chain` | 1 | 1 | **E** | `E·112` B |
| `recursive_linear` | 1 | 1 | **1** | 96 B |
| `streaming_forest` | `< 1` (→1) | `⌈log₂E⌉` | **1** | 96 B |

Composition is **leaf-shape-agnostic**, so e5 drives it with cheap synthetic,
boundary-consistent epoch leaves — it's fast and fully offline, and it's the
runner behind the topology-law table (compositions/insert vs. `E`). Columns:
`setting, E, prover_compositions_per_insert, worst_case_cascade,
verifier_checks, verify_ms_median, root_proof_size_bytes, peak_rss_mb_median,
status`.

**Caveat (option (i)):** an e5 "merge"/"root check" is a Poseidon2 boundary
digest (~µs), not a recursive STARK fold — it isolates the composition-layer
`Θ(E)→O(1)` *structure*. The same ladder over **real recursive proofs** is
`scripts/run_compose.sh` (modes `per_batch`/`chain`/`forest`); use that for
absolute times and proof sizes.

## E8 — cross-stack head-to-head (plonky2 vs plonky3)

```bash
scripts/run_experiments.sh e8                 # BOTH backends → results/e8_crossstack.csv
EXP_E8_M=64 EXP_E8_TRIALS=2 scripts/run_experiments.sh e8
```

The same certified CM leaf shape (`d=4, w=8`) on both constraint systems, plus a
recursive merge of two chainable leaves, and (plonky3 only) a cross-family
`cm+hll` composition. Three ops:

| op | what it measures |
| -- | ---------------- |
| `leaf` | one CM leaf (§1 metrics) |
| `recursive_merge` | merge two CM leaves — a **real recursive** proof (re-verifies both leaves in-circuit) on both backends |
| `cross_family_merge` (cm+hll) | **plonky3 only**, via the §4 framework boundary digest (option-(i)), *not* a recursive STARK. The cm→hll boundary is **synthetic** (no real cross-family state transition exists) — it measures the sketch-agnostic *composition-layer* cost of binding two heterogeneous leaves under one root |

Knobs: `EXP_E8_M` (batch, default 64 — the spec's `m=1000` is scaled down; the
recursive merge is ~1 s+ each at this prototype), `EXP_E8_DB` (distinct-key
bound of the synthetic batch — a workload knob, default 32), `EXP_E8_TRIALS`
(default 2). Columns: `backend, op, families, prove_total_ms_median,
verify_ms_median, proof_size_bytes, peak_rss_mb_median`.

**Honest gap.** A **recursive** cross-family merge is missing on both backends
(CM and HLL commit different state shapes / PI layouts, with no unified
commitment); only the framework digest composes them, and only on plonky3. The
plonky2 cross-family row is therefore omitted.

## Composition over real recursive proofs — `run_compose.sh`

```bash
scripts/run_compose.sh
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=per_batch,chain,forest scripts/run_compose.sh
EXP_COMPOSE_QUERY_EVERY=2 EXP_DATASET=aol scripts/run_compose.sh mixed_aol.csv
```

Compares the three §Streaming-Proof-Composition modes — per-batch chain,
recursive linear chain, streaming forest — over all four families, each pinned
to its deployed leaf variant (`cm→omc, hll→omc, ss→certified, gk→bandmerge2`).
Every leaf **and every merge is a real STARK proof**. `EXP_COMPOSE_QUERY_EVERY=k`
turns on **mixed updates+queries**: after every k-th batch it proves the
family's decode leaf against the state commitment at that point, reporting query
costs in separate `query_*` columns. Full knob list (`EXP_COMPOSE_N`, `_BATCHES`,
`_CORES`, `_MACHINES`, per-family shape…) in the
[script header](../scripts/run_compose.sh).
Output: `results/stream_compose.csv`.

## Whole-stream total time — `run_stream.sh`

```bash
scripts/run_stream.sh
EXP_STREAM_N=2^16 EXP_STREAM_BATCHES=64,256,1024 EXP_STREAM_CORES=16,32,64 scripts/run_stream.sh
```

Fixes the TOTAL stream size N and measures the wall-clock to prove the whole
stream: `t = ceil(N/m)` CM leaves proved on a k-slot pool, then folded. Sweeps
batch size × concurrency for the `omc` and `merkle` leaf provers;
`EXP_STREAM_MERGE` selects the fold (`digest` proxy or real
`per_batch`/`chain`/`recursive`/`recursive_bound`). Full knob list in the
[script header](../scripts/run_stream.sh). Output: `results/stream_forest.csv`.

## Decode / query circuits — `run_decode.sh`

```bash
scripts/run_decode.sh          # unit tests + proven results table
scripts/run_decode.sh tests    # just the authoritative correctness gate
```

Runs the decode/query STARKs of the **deployed** update variants
(`cm omc → prove_cm_decode` point frequency, `hll omc → prove_hll_decode_omc`
cardinality, `ss certified → prove_ss_decode` top-c mass,
`gk bandmerge2 → prove_gk2_decode` two-sided rank). Each decode proof re-hashes
the committed state (binding `Com(S_t)`) and proves the query answer — cost is
Θ(s) in the state size, not the stream length. The same decode leaves are what
`EXP_COMPOSE_QUERY_EVERY` proves mid-stream. The CM decode circuit takes any
power-of-two `w` (same in-circuit position derivation as the leaf; cost ∝ `d·w`).

---

## Archived experiments

These modes were part of the earlier E1–E10 ladder (`latex/EVAL_SPEC.md`) and
are **no longer dispatched by `run_experiments.sh`** — each was superseded by a
live surface above. The runner sources stay in `examples/` (and
`plonky2/examples/`), so the old measurements remain reproducible with the
direct commands below. Full historical write-ups: this file's git history
(`git log -- docs/REPRODUCE.md`) and [EVALUATION.md](EVALUATION.md).

| Mode | What it measured | Superseded by | Direct command |
| ---- | ---------------- | ------------- | -------------- |
| `e3` | decode cost vs state size `s` | `run_decode.sh` — e3 benches **non-deployed** decode variants (flat HLL/GK state instead of omc/bandmerge2) | `cargo run --release --example exp_e3`; plonky2 leg: `(cd plonky2 && cargo run --release --example e3_decode)` |
| `e4` | CM scaling sweeps a/b/c/d (batch, distinct-bound, state size, stream length) | the e1 `EXP_M`/`EXP_W` axes + `run_stream.sh` (stream-length axis). The distinct-bound axis (e4b) is obsolete: the per-record CM refactor dropped `distinct_bound` | `cargo run --release --example exp_e4` |
| `e5real` | composition ladder over real recursive proofs (CM only, E∈{2,4,8}) | `run_compose.sh` (all four families, chain+forest, real proofs) | `cargo run --release --example exp_e5_real` |
| `e6` | streaming forest: per-insert latency & sustained rate across cores × batch | `run_stream.sh` (whole-stream total time over the same axes) | `cargo run --release --example exp_e6` |
| `e7` | lazy/eager/smoothed maintenance-policy **simulation** | `run_compose.sh` with `EXP_COMPOSE_QUERY_EVERY` (real mixed updates+queries; `query_ctx_verifies` counts the folds a query pays) | `cargo run --release --example exp_e7` |
| `e9` | optimisation ablations (dedup / wide-output / sparse-rebind / ss-vs-gk rounds) | mostly analytical rows; the `ss_single_round` premise is gone — GK is single-pass now | `cargo run --release --example exp_e9` |
| `e10` | cost-model validation (post-processed e1/e3/e4 CSVs) | retired with its inputs; its variant filter predates the current e1 schema | `python3 scripts/cost_model_e10.py` |
| `inputfold` | input-commitment binding + history-fold + MMR ULog over real `Com(B_t)` | `run_compose.sh` (every compose leaf binds `Com(B_t)` in-circuit; the fold is a real recursive proof). The tamper property is the lib test `inputfold::real_batch_commitments_bind_and_fold_into_root`; the MMR has its own unit tests (`recursion::mmr::tests`) | `cargo run --release --example exp_inputfold` |
| `casestudy` | AOL/Netflix end-to-end ingest + audit + tamper (digest chain) | `run_compose.sh` on `EXP_DATASET=aol\|netflix` — real recursive composition + mid-stream queries across all four families | `cargo run --release --example exp_casestudy` |
| RQ1–RQ4 | the original figure track (`rq*.csv` panels → `plot_experiments.py`) | the surfaces above; several panels (rq2b, rq3d, e4b) are obsolete after the per-record CM refactor | `cargo run --release --example exp_rq1` (…`rq2` `rq3` `rq4`), then `python3 scripts/plot_experiments.py` |

## What's wired now

- **e1** (per-family circuit-cost matrix, certified + naive baselines, variant
  sweeps) — both backends.
- **e2** (integrity: tamper + fidelity) — both backends, all four families.
- **e5** (composition-topology ladder, digest lift) — plonky3.
- **e8** (cross-stack head-to-head, leaf + recursive merge) — both backends.
- **compose** (real recursive composition + mixed updates/queries) — plonky3,
  all four families.
- **stream** (whole-stream total prove time) — plonky3, CM omc/merkle.
- **decode** (query circuits of the deployed variants) — plonky3, all four
  families (plonky2 decode remains available via its own `e3_decode` example).
