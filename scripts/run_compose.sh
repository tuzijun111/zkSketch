#!/usr/bin/env bash
# Streaming proof-composition COMPARISON (plonky3 / STARK).
#
# Compares the three §Streaming-Proof-Composition modes — per-batch chain,
# recursive linear chain, and streaming forest — over four sketch families, each
# pinned to one leaf variant:
#     cm → omc, hll → omc, ss → certified, gk → bandmerge2.
#
# For a stream of N records cut into t = ceil(N/m) batches, each cell reports the
# whole-stream prove time (leafgen + merge), the verifier-facing proof size +
# verify time (Θ(t) for per_batch = sum of the t leaf proofs it stores to a
# folder; O(1) for chain/forest = the single recursive root), and the peak RSS.
#
# Every mode honours a CORES budget; per_batch and forest additionally honour a
# MACHINES count (parallel leaf-gen). Recursion proofs are !Send, so the fold
# cannot cross machines — parallel leaf-gen is the M-machine work-partition
# makespan and the fold runs sequentially (the O(log t) tail).
#
# Usage:
#   scripts/run_compose.sh
#   EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=per_batch,chain,forest scripts/run_compose.sh
#   EXP_COMPOSE_MACHINES=1,2,4,8 EXP_COMPOSE_CORES=8 scripts/run_compose.sh forest.csv
#
# Config (env):
#   EXP_COMPOSE_FAMILY   cm|hll|ss|gk comma-list                 (default cm,hll,ss,gk)
#   EXP_COMPOSE_MODE     per_batch|chain|forest comma-list       (default all three;
#                        `recursive` is accepted as an alias for forest)
#   EXP_COMPOSE_N        total stream records — int or `2^k`      (default 32)
#   EXP_COMPOSE_BATCHES  batch sizes m, comma-list                (default 8)
#   EXP_COMPOSE_CORES    cores per machine/proof, comma-list      (default all)
#   EXP_COMPOSE_MACHINES machines (per_batch + forest), comma-list(default 1)
#   EXP_COMPOSE_PROOF_DIR folder the per_batch mode stores proofs (default results/compose_per_batch_proofs)
#   EXP_COMPOSE_QUERY_EVERY  MIXED updates+queries: prove one query leaf (the
#                        family's decode circuit — cm point count, hll cardinality,
#                        ss top-1 mass, gk rank) after every k-th batch, bound to
#                        the state commitment at that point (default 0 = off).
#                        Query costs land in the query_* columns, separate from
#                        the update-side totals; query_ctx_verifies counts the
#                        composition proofs the verifier checks at query time
#                        (t' for per_batch, 1 for chain, popcount(t') peaks for
#                        forest). NOTE: cm decode caps w <= 16 — keep EXP_W small.
#   --- per-family shape ---
#   EXP_D / EXP_W        Count-Min d, w    (default 4, 8; needs d·w % 4 == 0)
#   EXP_HLL_B            HLL register bits  (default 4; needs 2^b % 4 == 0)
#   EXP_SS_CAP           SS capacity        (default 8)
#   EXP_GK_CAP           GK capacity = the GK sketch SIZE (default 64; cap+m even).
#                        The accuracy s=1/ε is DERIVED from cap (s ≈ cap/(2·log2 N),
#                        the GK space-accuracy coupling), so cap alone sets the GK
#                        size like d·w / 2^b / capacity for the other families —
#                        bigger cap → finer accuracy.
#   EXP_GK_S             override the derived s (optional). A value too big for the
#                        cap fragments and reports too_large (it's "cap too small
#                        for s", not "too large"); unset it to auto-derive.
#   EXP_DATASET          uniform|gaussian|zipf|aol|netflix        (default uniform)
#   EXP_OUT / $1         rename output to results/<name>.csv
#
# Output: results/stream_compose.csv with columns
#   dataset,family,variant,mode,shape,n,m,t,cores,machines,total_time_ms,
#   leafgen_ms,leafgen_seq_ms,merge_ms,verify_ms,proof_bytes,records_per_sec,
#   peak_rss_mb,n_queries,query_prove_ms,query_verify_ms,query_proof_bytes,
#   query_ctx_verifies,status
#   (total_time_ms = leafgen_ms + merge_ms; leafgen_ms = M-machine makespan,
#    leafgen_seq_ms = sequential Σ; proof_bytes/verify_ms are Θ(t) for per_batch
#    vs O(1) for chain/forest.)
#
# RUNTIME WARNING: every leaf AND every merge is a real STARK proof, proved
# sequentially (the machines split is a makespan projection). Each merge is a
# full recursive proof (~seconds), so keep N/t small — a handful of leaves.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_CSV="${EXP_OUT:-${1:-}}"
mkdir -p results

echo "== zkSketch stream-compose == N=${EXP_COMPOSE_N:-32} dataset=${EXP_DATASET:-uniform} families=${EXP_COMPOSE_FAMILY:-cm,hll,ss,gk} modes=${EXP_COMPOSE_MODE:-per_batch,chain,forest} m=${EXP_COMPOSE_BATCHES:-8} cores=${EXP_COMPOSE_CORES:-all} machines=${EXP_COMPOSE_MACHINES:-1}"

echo "-- plonky3 (STARK) --"
# EXP_OUT is consumed by the example itself for the rename; pass it through.
EXP_OUT="${OUT_CSV}" cargo run --release --example exp_compose

FINAL_CSV="results/stream_compose.csv"
if [[ -n "$OUT_CSV" ]]; then
  FINAL_CSV="results/${OUT_CSV%.csv}.csv"
fi
if [[ -f "$FINAL_CSV" ]]; then
  echo "results -> $FINAL_CSV"
  column -t -s, "$FINAL_CSV" | sed -n '1,200p'
fi
echo "env.json: results/env.json"
