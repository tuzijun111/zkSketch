#!/usr/bin/env bash
# Streaming-forest TOTAL-TIME benchmark (plonky3 / STARK).
#
# Fixes the TOTAL stream size N (e.g. 2^16) and measures the total wall-clock to
# prove the whole stream: prove t = ceil(N/m) independent Count-Min transition
# leaves in parallel on a k-thread pool, then fold them into a streaming forest.
# Swept over batch size m and core count k, for the `omc` and `merkle` leaf
# provers. SINGLE run — no warm-up, no measured trials, no target insert-rate.
#
# (Contrast with `run_experiments.sh e6`, which fixes the epoch count and
# reports per-insert latency + sustained insert-rate. This runner answers
# "how long to ingest the whole 2^16-record stream?".)
#
# Usage:
#   scripts/run_stream.sh
#   EXP_STREAM_N=2^16 scripts/run_stream.sh
#   EXP_STREAM_BATCHES=64,256,1024 EXP_STREAM_CORES=8,16,32,64 scripts/run_stream.sh
#   EXP_STREAM_CM_VARIANT=omc,merkle scripts/run_stream.sh
#   scripts/run_stream.sh stream_2p16.csv            # rename output CSV
#
# Config (env):
#   EXP_STREAM_N          total stream records — plain int or `2^k`  (default 65536)
#   EXP_STREAM_BATCHES    comma-list of batch sizes m (int or `2^k`) (default 64,256,1024)
#   EXP_STREAM_CORES      k = #leaf proofs run CONCURRENTLY (clamped to nproc);
#                         each gets floor(total/k) cores — the distributed model
#                         (k machines sharing a fixed core budget). k=1 → one leaf
#                         on all cores; k=nproc → nproc leaves, 1 core each.
#                                                                    (default 1,2,4,8,16,32,64)
#   --- sketch shape + dataset (the run_experiments.sh `e1` vocabulary) ---
#   EXP_DATASET           uniform|gaussian|zipf|aol|netflix|comma-list (default uniform)
#                         (fetch real ones first: python3 scripts/fetch_datasets.py)
#   EXP_D                 Count-Min depth d, 1..=8                    (default 4)
#   EXP_W                 Count-Min width w, power of two ≥ 2         (default 8)
#   EXP_CM_VARIANT        one_hot|omc|merkle|comma-list           (default omc,merkle)
#                         (EXP_STREAM_CM_VARIANT also accepted; the stream runner is CM-only)
#   EXP_STREAM_MERGE      digest | recursive | recursive_bound | chain  (default digest)
#                         digest = cheap §4.2 commitment fold (merge ~µs); recursive =
#                         §4.3(c) fold where every merge verifies its two children
#                         in-circuit (merge = real, large); recursive_bound = recursive
#                         + binds left.final==right.initial IN-circuit via the Expose NPO
#                         (NPO gap closed; all variants); chain = the linear §4.3 IVC
#                         Π^(t)=merge(Π^(t-1),π_t) over the same leaves (comparison
#                         baseline vs the recursive tree — O(t) vs O(log t) depth).
#                         recursive*/chain prove leaves sequentially, k-sweep ignored
#                         — use small N / few leaves.
#   EXP_OUT / $1          rename output to results/<name>.csv (the .csv is optional)
#
# The omc leaf needs d·w % 4 == 0; the merkle leaf needs w a power of 2.
#
# Output: results/stream_forest.csv with columns
#   dataset,variant,d,w,n,m,t,k,cores_per_leaf,merge_mode,total_time_ms,leafgen_ms,merge_ms,records_per_sec,speedup,peak_rss_mb,status
#   (total_time_ms = leafgen_ms + merge_ms — leaf proving vs the forest fold;
#    merge_mode = digest | recursive | recursive_bound | chain)
#
# RUNTIME WARNING: total proving work ≈ N records of real STARK proving, so at
# k cores it is ~ (N · per-record-cost)/k and the smallest-k cells dominate. For
# N=2^16 a k=1 cell can take tens of minutes — set EXP_STREAM_CORES to a
# high-core subset (e.g. 16,32,64) for a quick run.
set -euo pipefail
cd "$(dirname "$0")/.."

# Caller-chosen output filename (env EXP_OUT preferred; positional $1 accepted).
OUT_CSV="${EXP_OUT:-${1:-}}"
CSV="stream_forest.csv"

echo "== zkSketch stream-forest == N=${EXP_STREAM_N:-65536} dataset=${EXP_DATASET:-uniform} d=${EXP_D:-4} w=${EXP_W:-8} batches=${EXP_STREAM_BATCHES:-64,256,1024} cores=${EXP_STREAM_CORES:-1,2,4,8,16,32,64} variants=${EXP_CM_VARIANT:-${EXP_STREAM_CM_VARIANT:-omc,merkle}} merge=${EXP_STREAM_MERGE:-digest} (single run)"
mkdir -p results
rm -f "results/$CSV"

echo "-- plonky3 (STARK) --"
cargo run --release --example exp_stream

# Rename the output to the caller-chosen name, so successive runs under
# different settings accumulate distinct files.
FINAL_CSV="$CSV"
if [[ -n "$OUT_CSV" && -f "results/$CSV" ]]; then
  FINAL_CSV="${OUT_CSV%.csv}.csv"
  if [[ "$FINAL_CSV" != "$CSV" ]]; then
    mkdir -p "$(dirname "results/$FINAL_CSV")"
    mv -f "results/$CSV" "results/$FINAL_CSV"
  fi
fi

echo "results -> results/$FINAL_CSV"
# Cap the pretty-print so a full sweep doesn't flood the terminal (rows beyond
# the first 200 are still in the CSV).
if [[ -f "results/$FINAL_CSV" ]]; then
  column -t -s, "results/$FINAL_CSV" | sed -n '1,200p'
  rows=$(($(wc -l < "results/$FINAL_CSV") - 1))
  [[ "$rows" -gt 200 ]] && echo "… ($rows data rows total; see results/$FINAL_CSV)"
fi
echo "env.json: results/env.json"
