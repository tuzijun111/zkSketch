#!/usr/bin/env bash
# Reproduce the zkSketch evaluation experiments on both backends.
#
# This driver covers the experiments that are still part of the current
# evaluation (latex/zk1.tex §Evaluation):
#
#   e1  per-family circuit-cost matrix (the main experiment: family × variant ×
#       batch sweep, incl. the naive replay baselines)          — both backends
#   e2  integrity: tamper-rejection rate + ZK-vs-plaintext fidelity
#       (the tamper/fidelity columns of the per-family table)   — both backends
#   e5  composition-topology ladder (no-comp / per-batch chain / recursive
#       chain / streaming forest; auditor cost Θ(E)→O(1); digest-lift
#       structural sweep — the real-proof runs live in run_compose.sh)
#                                                               — plonky3 only
#   e8  cross-stack head-to-head (plonky2 SNARK vs plonky3 STARK: leaf +
#       recursive merge)                                        — both backends
#
# The rest of the evaluation runs through the sibling scripts:
#   scripts/run_compose.sh   composition over REAL recursive proofs, all four
#                            families × {per_batch, chain, forest}, plus mixed
#                            updates+queries (EXP_COMPOSE_QUERY_EVERY)
#   scripts/run_stream.sh    whole-stream total prove time (fixed N, sweep
#                            batch size × cores; omc vs merkle CM leaves)
#   scripts/run_decode.sh    decode/query circuits of the DEPLOYED variants
#                            (unit tests + proven results table)
#
# Retired modes (e3 e4 e5real e6 e7 e9 e10 inputfold casestudy) are no longer
# dispatched here — each was superseded by one of the surfaces above; asking
# for one prints what replaced it and the direct cargo command (the runner
# sources stay in examples/). See README.md §Running the experiments.
#
# The driver runs the plonky3 (STARK) and plonky2 (SNARK) runners and merges
# their rows into one combined CSV under results/ (with a `backend` column),
# plus per-backend env.json.
#
# Usage:
#   scripts/run_experiments.sh            # e1, both backends, small slice
#   scripts/run_experiments.sh e2         # e2 integrity
#   EXP_DATASET=aol scripts/run_experiments.sh e1
#   BACKENDS=plonky2 scripts/run_experiments.sh e8
#   EXP_FAMILY=ss EXP_SS_VARIANT=naive EXP_SS_CAP=16384 EXP_M=16,32,64 \
#     scripts/run_experiments.sh e1 ss_batch_naive.csv
#
# Config (env, forwarded to both runners):
#   EXP_DATASET  uniform|gaussian|zipf|aol|netflix     (default uniform)
#   EXP_FAMILY   E1: which families — all | comma-list of cm,gk,hll,ss
#                (e.g. EXP_FAMILY=cm runs only Count-Min)   (default all)
#   EXP_M        E1: comma-separated batch sizes (default 4,8,16,32).
#                Comma lists ONLY — range syntax like 16..1024 is NOT parsed
#                (unparseable entries are dropped silently → empty sweep).
#                E2: single batch size (default 16)
#   --- E1 per-family shape + variant knobs ---
#   EXP_D        E1/cm: Count-Min depth d (1..=8)           (default 4)
#   EXP_W        E1/cm: comma-list of widths w (powers of 2, sweeps width)
#                                                            (default 8)
#   EXP_CM_VARIANT  E1/cm: one_hot|merkle|merkle_fast|merkle_gb|memcheck|omc|
#                comma-list (default one_hot). All hash per record and group
#                by counter (no key-grouping); they differ only in the Step-5
#                rebind. one_hot = flat one-hot sparse patch over all d·w cells
#                (Θ(n_ctr·d·w)); merkle = sparse Merkle rebind opening only touched
#                cells (Θ(t_max·d·log w), flat in w); merkle_fast = merkle with a
#                1-perm 2:1 compression climb (the AIR swaps by the bit for free —
#                1.86× at large w); merkle_gb = merkle_fast + the group-by routing
#                replacing the m·t_max·d selector with the O(m·d) group-by (1.86×
#                at large batch m); memcheck = sparse-patch-commit rebind, NO dense
#                d·w / NO Merkle (Θ(batch·d·log(d·w)), flat in w), empty-init only;
#                omc = sound offline-memory-checking M_old⊎W=M_new⊎R against a real
#                prior state (Θ(d·w), dense commit, batch factor below one_hot) — in
#                a hash-STARK (multiset equality only, no LogUp inclusion) this OMC
#                circuit IS the faithful §5 "lookup table" realization (the former
#                separate `lookup` label was a duplicate of `omc` and is removed).
#                (Retired replay/merkle leaves remain in-tree, unwired.)
#   COUNTMIN_MAX_SEL_CELLS  cap on the one_hot circuit's selector budget
#                (batch·d·d·w); raise for big widths (default 16M). At the
#                headline shape d=7,w=16384 only m=16 fits the default budget.
#   EXP_HLL_B    E1/hll: comma-list of precision b; registers = 2^b (default 4)
#   EXP_HLL_VARIANT  E1/hll: one_hot|merkle|omc|comma-list  (default one_hot)
#                    (omc = offline-memory-checking max-update rebind, Θ(m+batch))
#   HLL_FULL_MAX_SEL_CELLS  cap on the one_hot HLL circuit's 32·2^b·m ALU table
#                (skips too-big cells with status=too_large instead of OOM).
#                Default 4194304; the real per-table ceiling is ~1048576 —
#                lower it when sweeping b=14 with m>64.
#   EXP_SS_CAP   E1/ss: comma-list of SpaceSaving capacities s (default 8;
#                rounded up to even ≥2)
#   EXP_SS_VARIANT  E1/ss: certified|naive|both|comma-list (default certified).
#                naive = per-record replay baseline, Θ(m·cap) — only feasible
#                for small m at large cap (m≳512 at cap=16384 OOMs the process,
#                killing the rest of the sweep; run naive in its own invocation)
#   EXP_GK_CAP   E1/gk: comma-list of Greenwald-Khanna capacities (default 8;
#                rounded up to even ≥2)
#   EXP_GK_VARIANT  E1/gk: certified|naive|bandmerge|bandmerge2|both|comma-list
#                (default certified). bandmerge2 = the deployed single-pass
#                group-by band-merge; naive = Θ(m·cap) replay baseline (same
#                small-m-only caveat as SS — separate invocation recommended)
#   EXP_GK_S     E1/gk: pin the band-merge accuracy s=1/ε. Default derives
#                s from (cap, m) PER CELL, which drifts across an m-sweep —
#                pin it for iso-accuracy comparisons (e.g. EXP_GK_S=73 at
#                cap=2048 is valid for the full m sweep)
#   --- measurement + output ---
#   EXP_CORES    E1 (plonky3): pin the STARK prover to this many cores — the
#                "cores-per-proof" knob for the distributed-setting study (one
#                proof per machine of N cores). Adds a `cores` CSV column. Unset =
#                all cores, no column. plonky3-only (do not combine with the
#                plonky2 leg). e.g. EXP_CORES=32 ... e1   (default: all cores)
#   EXP_TRIALS   e5/e8 measured trials (median/p95)      (default 5)
#   EXP_WARMUP   e5/e8 warm-up runs                       (default 1)
#                (e1 always runs each cell exactly once — single value per
#                metric, no median/p95; EXP_TRIALS/EXP_WARMUP do not apply)
#   EXP_TAMPER_TRIALS  E2 tamper trials                  (default 50)
#   BACKENDS     plonky3|plonky2|both|comma-list         (default both)
#                (e.g. BACKENDS=plonky3,plonky2 == both)
#   EXP_OUT      rename the combined output CSV to results/<EXP_OUT> so runs
#                under different settings don't overwrite each other; the .csv
#                suffix is optional. Also accepted as the positional 2nd arg
#                (`run_experiments.sh e1 cm_circuit_1.csv`). Default: the
#                experiment's standard name (e.g. e1_circuit.csv).
#
# Partial vs whole dataset: each runner consumes a small key slice (testing
# default). Fetch more (`python3 scripts/fetch_datasets.py`, raise *_MAX_KEYS)
# and raise EXP_M for larger runs. See README.md §Reproducing the paper's results.
set -euo pipefail
cd "$(dirname "$0")/.."

EXPERIMENT="${1:-e1}"
# Caller-chosen output filename (env EXP_OUT preferred; positional $2 accepted).
OUT_CSV="${EXP_OUT:-${2:-}}"

# Retired modes: print what superseded them + the direct command, then exit.
# The runner sources stay in examples/ (and plonky2/examples/) so the old
# measurements remain reproducible; see README.md §Running the experiments.
retired() { # $1 mode, $2 superseded-by, $3 direct command
  echo "'$1' was retired from this driver — superseded by $2."
  echo "Still runnable directly:  $3"
  echo "Details: README.md §Running the experiments"
  exit 2
}
case "$EXPERIMENT" in
  e3)        retired e3 "scripts/run_decode.sh (decode circuits of the DEPLOYED variants; the old runner benches non-deployed ones)" \
                     "cargo run --release --example exp_e3   # plonky2 leg: (cd plonky2 && cargo run --release --example e3_decode)" ;;
  e4)        retired e4 "the e1 sweeps (EXP_M/EXP_W axes) + run_stream.sh (stream-length axis); the distinct-bound axis (e4b) is obsolete since the per-record CM refactor" \
                     "cargo run --release --example exp_e4" ;;
  e5real)    retired e5real "run_compose.sh (real recursive chain/forest composition for all four families)" \
                     "cargo run --release --example exp_e5_real" ;;
  e6)        retired e6 "run_stream.sh (whole-stream total time over batch × cores)" \
                     "cargo run --release --example exp_e6" ;;
  e7)        retired e7 "run_compose.sh with EXP_COMPOSE_QUERY_EVERY (real mixed updates+queries instead of the structural policy sim)" \
                     "cargo run --release --example exp_e7" ;;
  e9)        retired e9 "nothing directly — the ss_single_round ablation's premise is gone (GK is single-pass now) and the rest are analytical rows" \
                     "cargo run --release --example exp_e9" ;;
  e10)       retired e10 "nothing — it post-processed the retired e3/e4 CSVs and its variant filter predates the current e1 schema" \
                     "python3 scripts/cost_model_e10.py" ;;
  inputfold) retired inputfold "run_compose.sh (every compose leaf binds Com(B_t) in-circuit; the fold is a real recursive proof) + the lib test inputfold::real_batch_commitments_bind_and_fold_into_root" \
                     "cargo run --release --example exp_inputfold" ;;
  casestudy) retired casestudy "run_compose.sh on the real datasets (EXP_DATASET=aol|netflix): real recursive composition + mixed queries across all four families" \
                     "cargo run --release --example exp_casestudy" ;;
esac

EXP_DATASET="${EXP_DATASET:-uniform}"
EXP_TRIALS="${EXP_TRIALS:-5}"
EXP_WARMUP="${EXP_WARMUP:-1}"
EXP_TAMPER_TRIALS="${EXP_TAMPER_TRIALS:-50}"
BACKENDS="${BACKENDS:-both}"
export EXP_DATASET EXP_TRIALS EXP_WARMUP EXP_TAMPER_TRIALS

case "$EXPERIMENT" in
  e1) CSV="e1_circuit.csv";   P3_EX="exp_e1";  P2_EX="e1_metrics_demo"; export EXP_M="${EXP_M:-4,8,16,32}" ;;
  e2) CSV="e2_integrity.csv"; P3_EX="exp_e2";  P2_EX="e2_integrity";    export EXP_M="${EXP_M:-16}" ;;
  # e5 composition-topology ladder (§4 framework, digest lift) → plonky3 only.
  e5) CSV="e5_ladder.csv";    P3_EX="exp_e5";  P2_EX="";  BACKENDS="plonky3"; export EXP_M="${EXP_M:-n/a}" ;;
  # e8 cross-stack head-to-head → BOTH backends (the whole point).
  e8) CSV="e8_crossstack.csv"; P3_EX="exp_e8"; P2_EX="e8_crossstack"; export EXP_M="${EXP_M:-n/a}" ;;
  *) echo "unknown experiment '$EXPERIMENT' (supported: e1, e2, e5, e8; retired: e3, e4, e5real, e6, e7, e9, e10, inputfold, casestudy)"; exit 1 ;;
esac
# Normalise BACKENDS into two flags so "both", "plonky3", "plonky2", and
# comma/space lists like "plonky3,plonky2" all work — an unknown value warns
# instead of silently running nothing.
want_p3=0; want_p2=0
for b in ${BACKENDS//,/ }; do
  case "$b" in
    both)             want_p3=1; want_p2=1 ;;
    plonky3|p3|stark) want_p3=1 ;;
    plonky2|p2|snark) want_p2=1 ;;
    *) echo "warning: unknown backend '$b' (use plonky3|plonky2|both)" >&2 ;;
  esac
done
if [[ "$want_p3" == 0 && "$want_p2" == 0 ]]; then
  echo "error: BACKENDS='$BACKENDS' selected no runnable backend (use plonky3|plonky2|both)" >&2
  exit 2
fi
if [[ -z "$P3_EX" && "$want_p3" == 1 ]]; then
  echo "note: $EXPERIMENT has no plonky3 runner; running plonky2 only"
  want_p3=0; want_p2=1
fi
if [[ -z "$P2_EX" && "$want_p2" == 1 ]]; then
  echo "note: $EXPERIMENT has no plonky2 runner; running plonky3 only"
  want_p2=0
fi
# EXP_CORES (E1 cores-per-proof) adds a `cores` column to the plonky3 CSV that the
# plonky2 leg doesn't emit, which would misalign the merge. Enforce plonky3-only.
if [[ -n "${EXP_CORES:-}" && "$want_p2" == 1 && "$EXPERIMENT" == "e1" ]]; then
  echo "note: EXP_CORES is plonky3-only (its 'cores' column would misalign the plonky2 merge); running plonky3 only" >&2
  want_p2=0
fi

sel=""
if [[ "$want_p3" == 1 ]]; then sel+="plonky3 "; fi
if [[ "$want_p2" == 1 ]]; then sel+="plonky2 "; fi
echo "== zkSketch $EXPERIMENT == dataset=$EXP_DATASET m=$EXP_M backends=${sel% }"
mkdir -p results
rm -f "results/$CSV" "plonky2/results/$CSV"

if [[ "$want_p3" == 1 ]]; then
  echo "-- plonky3 (STARK) --"
  cargo run --release --example "$P3_EX"
fi
if [[ "$want_p2" == 1 ]]; then
  echo "-- plonky2 (SNARK) --"  # plonky2/ pins nightly via rust-toolchain.toml
  ( cd plonky2 && cargo run --release --example "$P2_EX" )
fi

# Merge into one combined results/$CSV.
if [[ "$want_p3" == 1 && "$want_p2" == 1 && -f "plonky2/results/$CSV" ]]; then
  if [[ -f "results/$CSV" ]]; then
    tail -n +2 "plonky2/results/$CSV" >> "results/$CSV"
  else
    cp "plonky2/results/$CSV" "results/$CSV"
  fi
elif [[ "$want_p2" == 1 && "$want_p3" == 0 ]]; then
  cp -f "plonky2/results/$CSV" "results/$CSV"
fi

# Rename the combined output to the caller-chosen name (EXP_OUT or positional
# $2), so successive runs under different settings accumulate distinct files.
FINAL_CSV="$CSV"
if [[ -n "$OUT_CSV" && -f "results/$CSV" ]]; then
  FINAL_CSV="${OUT_CSV%.csv}.csv"
  if [[ "$FINAL_CSV" != "$CSV" ]]; then
    mkdir -p "$(dirname "results/$FINAL_CSV")"
    mv -f "results/$CSV" "results/$FINAL_CSV"
  fi
fi

echo "combined -> results/$FINAL_CSV"
[[ -f "results/$FINAL_CSV" ]] && column -t -s, "results/$FINAL_CSV" | sed -n '1,40p'
echo "env.json: results/env.json (plonky3), plonky2/results/env.json (plonky2)"
