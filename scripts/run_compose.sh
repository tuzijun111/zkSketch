#!/usr/bin/env bash
# Streaming proof-composition COMPARISON.
#
# Backend-selectable via EXP_COMPOSE_BACKEND (default plonky3 / STARK; set
# plonky2 for the SNARK backend — same distributed engine, same CSV schema).
#
# Compares the three §Streaming-Proof-Composition modes — per-batch chain,
# recursive linear chain, and streaming forest — over four sketch families, each
# pinned to one leaf variant:
#     cm → omc, hll → omc, ss → certified, gk → bandmerge2,
# plus the opt-in Bloom filter (bloom → omc) and KMV / bottom-k distinct-count
# sketch (kmv), both plonky3/BabyBear only.
#
# For a stream of N records cut into t = ceil(N/m) batches, each cell reports the
# whole-stream prove time (leafgen + merge), the verifier-facing proof size +
# verify time (Θ(t) for per_batch = sum of the t leaf proofs it stores to a
# folder; O(1) for chain/forest = the single recursive root), and the peak RSS.
#
# Every mode honours a CORES budget and a MACHINES count. With MACHINES > 1 the
# run defaults to the PROCESS-LEVEL distributed engine (EXP_COMPOSE_EXEC=procs):
# one OS process per machine, pinned to disjoint physical cores (numactl/
# taskset + NUMA membind), every cross-machine artifact serialized over real
# sockets with measured byte counts and 1/10/25 Gbps critical-path network
# models. per_batch and forest distribute LEAF proving over the machines (the
# plaintext witness pass makes leaves independent). The recursive linear chain
# is inherently sequential — each fold consumes the previous prefix proof — so
# it runs on ONE machine, folding in place (the MACHINES knob does not apply to
# it); only its single O(1) root leaves that machine. The forest composes
# in-place on the leaf machines (local Bentley–Saxe cascades, then log2(M)
# cross-machine rounds shipping only M-1 subtree roots) — the small
# communication it pays to unlock the parallelism the chain lacks.
# EXP_COMPOSE_EXEC=sim restores the legacy single-process makespan projection.
#
# Usage:
#   scripts/run_compose.sh
#   EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=per_batch,chain,forest scripts/run_compose.sh
#   EXP_COMPOSE_MACHINES=1,2,4,8 EXP_COMPOSE_CORES=8 scripts/run_compose.sh forest.csv
#
# Config (env):
#   EXP_COMPOSE_BACKEND  plonky3|plonky2  (default plonky3). plonky2 runs the
#                        SNARK port (plonky2/examples/exp_compose): same three
#                        modes, same four families, same pinned multi-process
#                        forest + measured comm, over Goldilocks/Poseidon/FRI.
#                        Caveats vs plonky3: EXP_COMPOSE_CORES/_MACHINES take a
#                        SINGLE value (no comma-sweep); it ignores
#                        EXP_COMPOSE_EXEC / EXP_GK_S / EXP_COMPOSE_QUERY_EVERY;
#                        and it adds EXP_COMPOSE_CROSS_FAMILY=1 to also bind the
#                        four family roots pairwise cross-family. Each
#                        cross-machine root ships proof+CommonCircuitData
#                        (merge_wire tag in env.json), so its comm bytes run a
#                        bit above plonky3's proof-only wire. Builds on nightly
#                        (pinned by plonky2/rust-toolchain.toml, auto-selected).
#   EXP_COMPOSE_FAMILY   cm|hll|ss|gk|bloom|kmv comma-list       (default cm,hll,ss,gk)
#                        plus the Goldilocks cm_gl|hll_gl|ss_gl|gk_gl. bloom and
#                        kmv are opt-in (not in the default list) and BabyBear
#                        only: there is no bloom_gl / kmv_gl (rejected with a
#                        message), and the plonky2 backend has neither family
#                        (it ignores 'bloom' and 'kmv').
#   EXP_COMPOSE_MODE     per_batch|chain|forest comma-list       (default all three;
#                        `recursive` is accepted as an alias for forest)
#   EXP_COMPOSE_N        total stream records — int or `2^k`      (default 32)
#   EXP_COMPOSE_BATCHES  batch sizes m, comma-list                (default 8)
#   EXP_COMPOSE_CORES    cores per machine/proof, comma-list      (default all)
#   EXP_COMPOSE_MACHINES machines, comma-list                     (default 1)
#   EXP_COMPOSE_EXEC     procs|sim (default: procs when machines>1). procs =
#                        real pinned processes + socket IPC (see above); needs
#                        machines*cores <= CPUs. sim = legacy projection
#                        (chain then ignores machines).
#   EXP_NET_MBPS         modeled link bandwidth (Mb/s) for the comm_model_ms
#                        column (default 200; bytes are MEASURED, only the
#                        model uses this). comm_bytes lets you derive any other.
#   EXP_NET_RTT_MS       modeled per-message RTT for comm_model_ms (default 0.2)
#   EXP_COMPOSE_PROOF_DIR folder the per_batch mode stores proofs (default results/compose_per_batch_proofs)
#   EXP_COMPOSE_QUERY_EVERY  MIXED updates+queries: prove one query leaf (the
#                        family's decode circuit — cm point count, hll cardinality,
#                        ss top-1 mass, gk rank, bloom membership, kmv distinct
#                        count) after every
#                        k-th batch, bound to the state commitment at that point
#                        (default 0 = off).
#                        Query costs land in the query_* columns, separate from
#                        the update-side totals; query_ctx_verifies counts the
#                        composition proofs the verifier checks at query time
#                        (t' for per_batch, 1 for chain, popcount(t') peaks for
#                        forest). Each answer is bound to the certified history:
#                        query_bind_ms is the measured cost of verifying those
#                        interval proofs (pinned VKs) and matching the query's
#                        Com(S); it reads `unbound` under the legacy opt-ins
#                        (ZKSKETCH_BINDING=legacy, ZKSKETCH_STATEMENT=boundary,
#                        EXP_ROOT_VK=self). (cm decode takes any power-of-two w,
#                        same as the leaf — EXP_W is unconstrained by queries.)
#                        Also emits amortized-per-query columns (query_*_avg =
#                        Σ query_* / n_queries) — the headline proven cost of one
#                        query. Runs under BOTH engines: sim interleaves the
#                        queries; procs proves them on the coordinator after the
#                        distributed update makespan (total_time_ms stays
#                        update-only). plonky3 only (plonky2 ignores QUERY_EVERY).
#   EXP_COMPOSE_QUERY_EVERY_OPS  MIXED OPERATION stream (the paper's streaming
#                        model; mutually exclusive with the per-batch knob
#                        above): the stream is N operations and a query
#                        OCCUPIES a stream position — every Q-th position is a
#                        query, the rest are updates, so N points carry
#                        N - floor(N/Q) update records (100 points, Q=10 ⇒ 10
#                        queries + 90 updates). Q >= 2, no batch alignment
#                        needed. A query landing mid-batch seals the batch
#                        EARLY and pads its tail with the family's provable
#                        no-op records (cm value-0 update, ss circuit dummy,
#                        gk E_MAX dummy via a short batch, bloom act=0 dummy
#                        via a short batch, kmv act=0 dummy record in place,
#                        hll repeated key — max is
#                        idempotent), so the state is committed at the
#                        exact stream position with a uniform circuit shape.
#                        The early-sealed leaves are the honest "query at any
#                        point" premium (query_split_leaves/query_pad_records);
#                        the CSV n column = TOTAL stream operations (updates =
#                        n - n_queries; records_per_sec counts updates only;
#                        the stream tail is pad-sealed, not extended).
#                        plonky3 only.
#   EXP_QUERY_KEY_MODE   which probe key a KEYED query targets (cm point-count,
#                        gk rank, bloom membership; no effect on hll/ss/kmv
#                        which are keyless):
#                        first (default — the batch's first key, the baseline) |
#                        uniform_stream (frequency-weighted sample of keys seen
#                        so far, S³-style) | hot (most-frequent key) | absent
#                        (an in-domain key NOT in the stream). Deterministic /
#                        reproducible. plonky3 only.
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
#   EXP_BLOOM_K          Bloom slices = hash positions per key (default 7; 1..=8)
#   EXP_BLOOM_LOGW       Bloom bits per slice W = 2^logw   (default 14; 7..=20)
#                        Defaults are the deployed M = 7·2^14 filter; set e.g.
#                        3 / 7 for quick smokes. An out-of-range value exits 2
#                        with the reason. CSV shape column: k{k}_logw{logw}.
#   EXP_KMV_K            KMV capacity k = the number of smallest distinct
#                        27-bit key hashes kept (default 1024): a multiple of 4
#                        in 4..=32768 with k + m < 2^24; set e.g. 4 for quick
#                        smokes. A bad value exits 2 with the reason. CSV shape
#                        column: k{k}.
#   EXP_DATASET          uniform|gaussian|zipf|aol|netflix        (default uniform)
#   EXP_OUT / $1         rename output to results/<name>.csv
#   --- commitments (plonky3; revision B2, see README) ---
#   ZKSKETCH_COMMIT      hiding|plain (default hiding; plain under
#                        ZKSKETCH_BINDING=legacy). hiding: every leaf commits
#                        Com(S_t)/Com(B_t) with the prover's per-version
#                        randomizers, the batch log is built prover-side and the
#                        auditor sees only that log, the proofs and public
#                        parameters. plain: the pre-B2 circuits, commitments and
#                        VKs byte for byte. Every BabyBear family has hiding
#                        commitments (Bloom family id 5, KMV family id 6).
#   ZKSKETCH_SALT_SEED   the prover's salt seed, 64 hex chars (reproducible
#                        runs); unset = OS RNG. Never printed; the salt_seed
#                        column records only its source (env|os; n/a if plain).
#
# Output: results/stream_compose.csv — the legacy columns
#   dataset,family,variant,mode,shape,n,m,t,cores,machines,total_time_ms,
#   leafgen_ms,leafgen_seq_ms,merge_ms,verify_ms,proof_bytes,records_per_sec,
#   peak_rss_mb,n_queries,query_prove_ms,query_verify_ms,query_proof_bytes,
#   query_ctx_verifies,query_prove_ms_avg,query_verify_ms_avg,
#   query_proof_bytes_avg,query_ctx_verifies_avg,query_split_leaves,
#   query_pad_records
# plus the procs-engine extension block (n/a under sim)
#   exec,procs,witness_pass_ms,scatter_ms,scatter_state_bytes,
#   scatter_data_bytes,leaf_busy_min_ms,leaf_busy_max_ms,local_fold_ms,
#   merges_local,merges_cross,cross_rounds,comm_msgs,
#   comm_bytes,comm_ms_measured,comm_model_ms,merge_total_ms,
#   query_bind_ms,query_bind_ms_avg,commit,salt_seed,status
#   (commit = plain|hiding, salt_seed = env|os|n/a: plonky3 only)
#   (procs: total_time_ms = measured end-to-end wall (witness pass → root);
#    leafgen_ms = real parallel slice-phase wall; merge_ms = cross-machine
#    composition wall; proof_bytes/verify_ms are Θ(t) for per_batch vs O(1)
#    for chain/forest.)
#
# RUNTIME WARNING: every leaf AND every merge is a real STARK proof. Each merge
# is a full recursive proof (~seconds): budget ~t·merge for the chain and
# ~(t/M + log M)·merge for the forest.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_CSV="${EXP_OUT:-${1:-}}"
BACKEND="${EXP_COMPOSE_BACKEND:-plonky3}"
mkdir -p results

echo "== zkSketch stream-compose == backend=$BACKEND N=${EXP_COMPOSE_N:-32} dataset=${EXP_DATASET:-uniform} families=${EXP_COMPOSE_FAMILY:-cm,hll,ss,gk} modes=${EXP_COMPOSE_MODE:-per_batch,chain,forest} m=${EXP_COMPOSE_BATCHES:-8} cores=${EXP_COMPOSE_CORES:-all} machines=${EXP_COMPOSE_MACHINES:-1} commit=${ZKSKETCH_COMMIT:-default}"

case "$BACKEND" in
  plonky3|p3|stark)
    echo "-- plonky3 (STARK) --"
    # EXP_OUT is consumed by the example itself for the rename; pass it through.
    NAME="${OUT_CSV:-stream_compose}"; NAME="${NAME%.csv}"
    EXP_OUT="$NAME" cargo run --release --example exp_compose
    FINAL_CSV="results/${NAME}.csv"
    ENV_JSON="results/env.json"
    ;;
  plonky2|p2|snark)
    echo "-- plonky2 (SNARK) --  (dataset=${EXP_DATASET:-uniform}; single-value CORES/MACHINES; nightly via plonky2/rust-toolchain.toml)"
    NAME="${OUT_CSV:-stream_compose_p2}"; NAME="${NAME%.csv}"
    # plonky2/ is a self-contained crate; run its example there and surface the
    # CSV in the shared results/ dir so both backends land side by side.
    ( cd plonky2 && EXP_OUT="$NAME" cargo run --release --example exp_compose )
    [[ -f "plonky2/results/${NAME}.csv" ]] && cp -f "plonky2/results/${NAME}.csv" "results/${NAME}.csv"
    FINAL_CSV="results/${NAME}.csv"
    ENV_JSON="plonky2/results/env.json"
    ;;
  *)
    echo "error: unknown EXP_COMPOSE_BACKEND='$BACKEND' (use plonky3|plonky2)" >&2
    exit 2
    ;;
esac

if [[ -f "$FINAL_CSV" ]]; then
  echo "results -> $FINAL_CSV"
  if command -v column >/dev/null; then column -t -s, "$FINAL_CSV"; else cat "$FINAL_CSV"; fi | sed -n '1,200p'
fi
echo "env.json: $ENV_JSON"
