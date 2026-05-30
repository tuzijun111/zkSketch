# Evaluation — implementing `latex/zk1.tex` §Evaluation

This document maps every experiment in the paper's **Evaluation** section
(`\section{Evaluation (in progress)}`, RQ1–RQ4 + end-to-end case study +
cost-model validation) to a runnable experiment in this repo, says how to run
it, what metric it emits, and flags which panels are **measured** vs
**analytical/planned**.

Everything runs at **small scale** by design (the paper notes the camera-ready
uses the full sweeps); the numbers below are a real prototype run on a 64-core
sandbox and will vary by hardware. The point of the small-scale run is to show
each experiment *works end-to-end and exhibits the predicted shape*.

## Layout

| Concern | File |
| ------- | ---- |
| Harness (CSV sink, timer, proof-size, thread pool) | `src/experiments/mod.rs` |
| Shared per-family single-epoch provers | `src/experiments/families.rs` |
| RQ1 — Capability | `src/experiments/rq1_capability.rs` |
| RQ2 — Scalability | `src/experiments/rq2_scalability.rs` |
| RQ3 — Pattern-A/B optimisations | `src/experiments/rq3_optimisations.rs` |
| RQ4 — Topology + maintenance policy | `src/experiments/rq4_topology.rs` |
| End-to-end case study | `src/experiments/casestudy.rs` |
| Runner binaries | `examples/exp_{rq1,rq2,rq3,rq4,casestudy}.rs` |
| Datasets (synthetic + Zipf + real loaders) | `src/dataset.rs`, `scripts/fetch_datasets.py` |
| Plotting | `scripts/plot_experiments.py` |
| Outputs (git-ignored) | `results/*.csv`, `results/figures/*.{pdf,png}` |

## Quick start

```bash
# Optional: fetch the real S³ datasets (else synthetic-only, still runs)
python3 scripts/fetch_datasets.py

# Run each research question (writes results/*.csv, prints tables)
cargo run --release --example exp_rq1          # Capability     (~1 min)
cargo run --release --example exp_rq2          # Scalability    (~1–2 min)
cargo run --release --example exp_rq3          # Optimisations  (~1 min)
cargo run --release --example exp_rq4          # Topology+policy (<1 s)
cargo run --release --example exp_casestudy    # AOL/Netflix end-to-end (~1–2 min)

# Render figures → results/figures/*.pdf
python3 scripts/plot_experiments.py
```

Knobs (env vars): `V3_SWEEP_THREADS=k` (Rayon pool size), `EXP_RQ1_EPOCHS`,
`EXP_RQ1_TRIALS`, `EXP_RQ2_MAX_E`, `EXP_RQ4_MAX_E`, `EXP_CASE_EPOCHS`.

## What is measured vs analytical

The prototype proves **real STARKs** (Plonky3, BabyBear, FRI), so prover time,
proof size, correctness (committed final state == native), and tamper-rejection
are *measured*. Three things in the paper need machinery this prototype does
not have; they are emitted as clearly-flagged **analytical** rows or noted as
future work:

- **No constraint-count introspection.** We report **prover time** (≈ linear in
  constraint count on FRI) and **proof size** as the backend-independent cost
  proxies. Per-component constraint breakdowns (e.g. RQ3-f comparator share)
  need circuit introspection — future work.
- **No exact-ZK-index / zkVM baselines** (RQ2-e, RQ2-f). Emitted as analytical
  projections from the cost model (`results/rq2ef_analytical.csv`,
  `kind=analytical`).
- **Framework composition uses *option (i)* lifting** (boundary-digest binding,
  not an in-circuit recursive verifier). So RQ4 merge *counts* are the
  structural signal; the per-merge time τ is the lightweight digest cost
  (sub-µs), not a recursive-SNARK fold.

---

## RQ1 — Capability (`sec:rq1`) → `exp_rq1`

| Panel | Implemented | CSV | Metric | Result shape (small-scale run) |
| ----- | ----------- | --- | ------ | ------------------------------ |
| **1-a** history-independent per-epoch cost | ✅ measured | `rq1a_history_independence` | prove time + proof size vs epoch `t` (CM, threaded state) | flat ≈ 110 ms, proof ≈ 380 KB across 12 epochs; cells saturate at `d·w` |
| **1-b** constant root proof + verifier | ✅ (in RQ2-d) | `rq2d_audit_window` | root-digest size + verify time vs `E` | root = 16 B, verify O(1), constant across `E∈[16,256]` |
| **1-c** tamper detection | ✅ measured | `rq1c_tamper_detection` | detection rate over 5%-row tamper, 4 families | **1.000** for CM/GK/HLL/SS |
| **1-d** ZK answer == plaintext answer | ✅ measured | `rq1d_answer_fidelity` | ZK-decoded vs plaintext vs ground truth, 4 families | ZK == plaintext (abs diff 0); HLL shows sketch error vs truth |

**1-c note.** This panel measures the *binding-layer* detection: a 5%-row
tamper diverges both the batch commitment and `Com(S_t)`, so any proof bound to
the honest history root is rejected. *Constraint-level* rejection inside each
circuit (the prover cannot even produce an accepted proof of a false transition)
is separately covered by the unit tests `gk_full_fusion_soundness_rejects_bad_table`,
`hll_full_soundness_rejects_bad_state`, `ss_full_soundness_rejects_bad_table`,
and the `*_rho_binding_*` / threshold-gate tests.

---

## RQ2 — Scalability (`sec:rq2`) → `exp_rq2`

| Panel | Implemented | CSV | Result shape |
| ----- | ----------- | --- | ------------ |
| **2-a** batch-size `m` | ✅ measured | `rq2a_batch_size` | prove time rises with `m`; HLL steepest (`O(m·register)` scatter), SS flat (single pass) |
| **2-b** touched-cell / distinct_bound | ✅ measured | `rq2b_distinct_bound` | CM prove time linear in `distinct_bound` (hash gadget runs `db·d` times): 85→247 ms for db 2→32 |
| **2-c** state-size `s` | ✅ measured | `rq2c_state_size` | **honest finding:** flat Poseidon2 commit ⇒ cost grows with `s`. The paper's *sublinear-in-`s`* needs the sparse-rebind commitment (Merkle/IPA opening of touched cells only) — future work |
| **2-d** audit window `E` | ✅ measured | `rq2d_audit_window` | root digest constant (16 B), root verify O(1); chain merges Θ(E); forest merges = `E − popcount(E)`, worst insert = `log₂E` |
| **2-e** sketch vs exact index | ⚠️ analytical | `rq2ef_analytical` | predicted ratio `H·log₂n/(d+L)` = 250×–500× for n=2¹⁵–2³⁰ |
| **2-f** zkVM (RISC0/SP1) | ⚠️ analytical | `rq2ef_analytical` | predicted 100–1000× per-batch prover-time gap (ZK-Value-style) |
| **2-g** per-family decode cost | ⚠️ folded | — | decode is native off the committed state today; separate decode circuits are future work |

---

## RQ3 — Pattern-A/B optimisations (`sec:rq3`) → `exp_rq3`

| Panel | Implemented | CSV | Result shape |
| ----- | ----------- | --- | ------------ |
| **3-a** optimised CM vs `naive-zkSketch` | ✅ measured | `rq3a_naive_vs_optimised` | **honest finding:** at toy `w≤16` the optimised pipeline's permutation/compaction NPO overhead *dominates* (naive is faster); the Θ(d·w·batch) vs Θ(distinct·d + d·w) crossover needs realistic `w=2¹⁶`, which the prototype's `w∈{2,4,8,16}` validation does not yet reach |
| **3-b** HLL hash-once-per-distinct (Zipf) | ✅ analogue | `rq3d_dedup_skew` | realised by the Pattern-A CM dedup (same principle); saving 1.05×→1.80× as α 0→2 shrinks `u` 16→6 |
| **3-c** HLL wide-output two-field split | ⚠️ planned | — | not a separate circuit knob yet; analytical 2× |
| **3-d** sparse register-rebind (HLL/CM) | ✅ measured | `rq3d_dedup_skew` | provisioning `distinct_bound=u` shrinks hash work; bounded by O(m) sort overhead (the Phase-9h analysis) |
| **3-e** SS single-round vs GK multi-round | ✅ measured | `rq3e_retention_vs_fusion` | SS single pass 77 ms < GK 5-round 119 ms; GK 2-round 89 ms (round-count is a cost lever) |
| **3-f** SS comparator share bounded | ✅ partial | `rq3f_ss_capacity` | total prove time rises gently with capacity (66→76 ms for s 4→32); per-component split needs introspection |

---

## RQ4 — Topology + maintenance policy (`sec:rq4`) → `exp_rq4`

Composition is leaf-shape-agnostic, so this runs in milliseconds on synthetic
epoch leaves.

| Panel | Implemented | CSV | Result shape |
| ----- | ----------- | --- | ------------ |
| **4-a/4-b** insert-rate topology cost | ✅ measured | `rq4ab_topology_online` | per-insert merges: chain = 1, tree spine = `log₂E`, forest amortised → 1.0 (0.938→0.999), forest worst = `log₂E` |
| **4-c/4-d** lazy vs query-burst peak fold | ✅ measured | `rq4cd_policy` | surviving peaks `ℓ=popcount(t)`; lazy `ℓ−1` sequential vs query-burst `⌈log₂ℓ⌉`; speedup 2.3×→3.8× as `t`→2²⁰ (ℓ≈20), matching the paper's ~3× example |

---

## End-to-end case study (`sec:rq5-casestudy`) → `exp_casestudy`

Ingests the AOL + Netflix streams (and synthetic Gaussian/Uniform) in epochs
across **all four families**, maintaining the committed object + history chain,
then an independent verifier replays the chain and a tamper trial.

- `casestudy_ingest`: total prover wall-clock, mean/max per-epoch latency,
  decoded answer, all-epochs-correct flag, per (dataset, family). Small-scale
  (4 epochs × batch 8): CM ≈ 110 ms/epoch, GK ≈ 110, HLL ≈ 155, SS ≈ 67, all
  `all_correct=true` on AOL/Netflix/synthetic.
- `casestudy_audit`: Θ(E) chain verify vs O(1) root (16 B), and
  `tamper_detected=true` (a corrupted epoch boundary breaks the chain).

---

## Cost-model validation (`sec:cost-model-validation`)

Each measured panel reports prover time / proof size alongside the predicted
*shape* from Appendix `app:constraint-budget`. Two panels surfaced **honest
deviations** that the paper invites as reportable findings rather than failures:

1. **2-c / sparse rebind:** the flat whole-state Poseidon2 commitment makes
   per-batch cost grow with `s`; the sublinear claim needs a sparse-opening
   commitment (Phase-10 future work).
2. **3-a / structural gap:** at the prototype's capped `w≤16`, the optimised
   circuit's fixed NPO-table overhead dominates the naive strawman's
   `Θ(d·w·batch)`; the asymptotic gap is a large-`w` phenomenon.

Both are written into the paper's evaluation draft as small-scale caveats with
the asymptotic argument retained.

## Reproducing the figures

`python3 scripts/plot_experiments.py` reads `results/*.csv` and writes
`results/figures/fig_*.{pdf,png}` (one per panel above). Pass figure keys to
render a subset, e.g. `python3 scripts/plot_experiments.py rq2a rq4ab`.
