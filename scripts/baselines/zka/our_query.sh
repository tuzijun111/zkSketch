#!/usr/bin/env bash
# zkSketch Count-Min query proofs at zk-Analytics' geometry (d = 3, w = 1024, m = 16,384) -> zks_query_matched.csv.
# Phase q0 proves the decoder alone on a native state; q1 runs exp_compose with a query after every batch.
# Usage: [SCALE=1] [PHASES=q0,q1] [MODES=per_batch,chain,forest] ./our_query.sh
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"   # ZKS = the checkout this script lives in
ZKSQ=$HERE/zksq; ZKSQ_TARGET=$BASELINE_DIR/build/zksq
OUTDIR=$RESULTS
# ---- commitment mode (revision B2) -----------------------------------------
# Pinned EXPLICITLY, never inherited from exp_compose's library default
# (hiding): the matched rows these columns are placed next to were measured
# with PLAIN commitments (results/zks_matched_*.csv, compare.sh, taken before
# B2), and Q0's `cmq` isolate proves the plain decoder `prove_cm_decode` only.
#   ZKSKETCH_COMMIT=plain  (default)  Q0 + Q1, rows -> zks_query_matched.csv
#   ZKSKETCH_COMMIT=hiding            Q1 only (hiding leaves + queries, salt seed
#                                     from ZKSKETCH_SALT_SEED or the OS RNG),
#                                     rows -> zks_query_matched_hiding.csv
# The two modes never share an output file, so every row's mode is known from
# the file it is in (exp_compose's raw CSV also carries a `commit` column).
COMMIT=$(printf %s "${ZKSKETCH_COMMIT:-plain}" | tr "[:upper:]" "[:lower:]")
case "$COMMIT" in
  plain)  OUT=$OUTDIR/zks_query_matched.csv ;;
  hiding) OUT=$OUTDIR/zks_query_matched_hiding.csv ;;
  *) echo "ZKSKETCH_COMMIT must be plain or hiding (got '$COMMIT')" >&2; exit 2 ;;
esac
export ZKSKETCH_COMMIT=$COMMIT

# ---- knobs -----------------------------------------------------------------
SCALE=${SCALE:-1}                 # number of matched epochs = number of leaves t
M=${M:-16384}                     # batch size = their epoch (16,384 logs)
D=${D:-3}; W=${W:-1024}           # matched CM geometry
# DEFAULTS MUST MATCH THE ALREADY-MEASURED BASELINE ROWS, or the query columns
# cannot be placed next to them:
#   results/zks_matched_t1.csv / _t64_{forest,chain}.csv were taken with
#   EXP_DATASET=aol and EXP_COMPOSE_CORES=32 (compare.sh:33-47).
# A `uniform` default would also saturate d=3/w=1024 at 16,384 records
# (~16 counts/cell), making the decoded answer ~16x the truth.
DATASET=${DATASET:-aol}
KEY_MODE=${KEY_MODE:-first}       # first|uniform_stream|hot|absent
MODES=${MODES:-per_batch,chain,forest}
# 32 = EXP_COMPOSE_CORES in compare.sh, NOT $(nproc)=64. Changing it makes this
# run incomparable with the measured update-side rows.
CORES=${CORES:-32}
MACHINES=${MACHINES:-1}
PHASES=${PHASES:-q0,q1}           # q0 = isolate, q1 = integrated
if [ "$COMMIT" = hiding ] && [[ ",$PHASES," == *,q0,* ]]; then
  echo "REFUSING: Q0 (cmq) proves the plain decoder only; with ZKSKETCH_COMMIT=hiding run PHASES=q1" >&2
  exit 2
fi
SEEDS=${SEEDS:-1}                 # q0 only: independent states
TRIALS=${TRIALS:-1}               # q0 only: repeats per state (median)
QEVERY=${QEVERY:-1}               # q1: query after every k-th batch (0 = off)
QPOS=${QPOS:-0}                   # q1: operation-stream Q instead (0 = off)
FORCE=${FORCE:-0}                 # 1 = re-run a data point already in the CSV
N=$(( SCALE * M ))

mkdir -p "$OUTDIR"

# ---- cleanup ---------------------------------------------------------------
cleanup() {
  # Pinned procs-engine workers that outlived their coordinator. Match the process
  # NAME (the /tmp snapshot's basename), never -f: a full-command-line match also hits
  # any shell whose command text merely mentions the pattern, and kill -9s it.
  for p in $(pgrep -u "$(id -u)" '^zks_dc_exe_' 2>/dev/null); do
    kill -9 "$p" 2>/dev/null
  done
  for p in $(pgrep -u "$(id -u)" exp_compose 2>/dev/null); do
    if tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -q '^ZKS_COMPOSE_ROLE='; then
      kill -9 "$p" 2>/dev/null
    fi
  done
  rm -f /tmp/zks_dc_exe_* 2>/dev/null
  rm -f "${RAW:-}" 2>/dev/null   # raw q0 rows of an interrupted run
  # Restore the non-tracked env.json exp_compose rewrites.
  [ -f "$ENVBAK" ] && mv -f "$ENVBAK" "$ZKS/results/env.json" 2>/dev/null
}
ENVBAK=""
trap cleanup EXIT INT TERM

# ---- padding guard ---------------------------------------------------------
if [ "$QPOS" -gt 0 ]; then
  if [ $(( (QPOS - 1) % M )) -ne 0 ]; then
    per=$(( (M - ((QPOS - 1) % M)) % M ))
    echo "REFUSING: QPOS=$QPOS with m=$M pays $per pad records per query" >&2
    echo "  (build_query_schedule_batches in src/experiments/stream_compose.rs)." >&2
    echo "  Pick QPOS with (QPOS-1) % $M == 0, e.g. $((M+1)), $((2*M+1))." >&2
    exit 2
  fi
  QEVERY=0
fi

# ---- output schema ---------------------------------------------------------
if [ ! -f "$OUT" ]; then
  cat > "$OUT" <<'HDR'
phase,system,family,variant,d,w,state_cells,mode,exec,n_records,m,t,cores,machines,dataset,key_mode,n_queries,query_prove_ms,query_verify_ms,query_proof_bytes,query_ctx_verifies,query_prove_ms_avg,query_verify_ms_avg,query_proof_bytes_avg,query_ctx_verifies_avg,query_split_leaves,query_pad_records,update_total_ms,peak_rss_mb,seed,status
HDR
fi
CELLS=$(( D * W ))

echo "== M3: zkSketch query side, matched CM d=$D w=$W m=$M SCALE=$SCALE (n=$N, t=$SCALE) commit=$COMMIT -> $OUT"

# =================== Q0 : query-cost isolate (no update leaf) ===============
# Resumability: a data point already present in $OUT is skipped unless FORCE=1.
# Keyed on (phase, d, w, n_records, dataset, key_mode) for q0 and additionally
# on (mode, t) for q1 -- these harnesses APPEND, so without this a re-run after
# a Ctrl-C silently duplicates rows and any later mean is wrong.
have_q0() {
  [ -f "$OUT" ] || return 1
  awk -F, -v d="$D" -v w="$W" -v n="$M" -v ds="$DATASET" -v km="$KEY_MODE" \
    '$1=="q0_isolate" && $5==d && $6==w && $10==n && $15==ds && $16==km && $NF!="dry" {f=1} END{exit !f}' "$OUT"
}
have_q1() {  # $1 = composition mode
  [ -f "$OUT" ] || return 1
  awk -F, -v m="$1" -v n="$N" -v mm="$M" -v ds="$DATASET" \
    '$1=="q1_integrated" && $8==m && $10==n && $11==mm && $15==ds {f=1} END{exit !f}' "$OUT"
}

if [[ ",$PHASES," == *,q0,* ]] && [ "$FORCE" != 1 ] && have_q0; then
  echo "-- Q0 skip: d=$D w=$W n=$M dataset=$DATASET key_mode=$KEY_MODE already in $OUT (FORCE=1 to redo)"
  PHASES=$(echo "$PHASES" | sed 's/q0//')
fi
if [[ ",$PHASES," == *,q1,* ]] && [ "$FORCE" != 1 ]; then
  REMAIN=""
  for m in ${MODES//,/ }; do
    if have_q1 "$m"; then echo "-- Q1 skip: mode=$m n=$N m=$M dataset=$DATASET already in $OUT"
    else REMAIN="${REMAIN:+$REMAIN,}$m"; fi
  done
  if [ -z "$REMAIN" ]; then
    echo "-- Q1 skip: every requested mode already measured (FORCE=1 to redo)"
    PHASES=$(echo "$PHASES" | sed 's/q1//')
  else
    MODES="$REMAIN"
  fi
fi

if [[ ",$PHASES," == *,q0,* ]]; then
  # aol/netflix are FILE-BACKED fixed streams (zkSketch/src/dataset.rs, `aol()`/`netflix()`
  # -> take(&keys, n) = the first n keys, seed-independent). SEEDS>1 on those
  # yields IDENTICAL states and identical probe keys: useful as timing repeats,
  # but NOT seed variance. Only gaussian/zipf/uniform actually vary with seed.
  case "$DATASET" in
    aol|netflix)
      if [ "$SEEDS" -gt 1 ]; then
        echo "   NOTE: DATASET=$DATASET is a fixed file stream -- the $SEEDS 'seeds' are"
        echo "         identical repeats, not independent draws. Use zipf/gaussian/uniform"
        echo "         for an error DISTRIBUTION (M5); keep aol for timing comparability."
      fi;;
  esac
  echo "-- Q0 isolate: prove_cm_decode only, SEEDS=$SEEDS TRIALS=$TRIALS"
  ( cd "$ZKSQ" && CARGO_TARGET_DIR=$ZKSQ_TARGET cargo build --release --locked --bin cmq >/dev/null 2>&1 ) || {
    echo "Q0: build failed" >&2; exit 1; }
  RAW=$OUTDIR/.zks_q0_raw.$$.csv; rm -f "$RAW"
  # DRY_RUN=1 proves nothing; its rows must not contaminate the real CSV.
  Q0DEST="$OUT"; [ "${DRY_RUN:-0}" = 1 ] && Q0DEST="$OUT.dry" 
  D=$D W=$W N=$M DATASET=$DATASET KEY_MODE=$KEY_MODE SEEDS=$SEEDS TRIALS=$TRIALS \
    CORES=$CORES TAG=q0_isolate CSV="$RAW" "$ZKSQ_TARGET/release/cmq" >/dev/null
  # normalize -> one line per (phase, seed)
  awk -F, -v OFS=, -v cells="$CELLS" -v ds="$DATASET" -v km="$KEY_MODE" \
      -v m="$M" -v cores="$CORES" 'NR>1 {
        # cmq columns: 5 d 6 w 8 n_records 11 seed 14 prove_ms 15 verify_ms
        # 16 proof_bytes 21 peak_rss_mb 22 status
        print "q0_isolate","zksketch","cm","cm_omc",$5,$6,cells,"none","inproc",
              $8,m,0,cores,1,ds,km,1,$14,$15,$16,0,$14,$15,$16,0,0,0,0,$21,$11,$22
      }' "$RAW" >> "$Q0DEST"
  [ "${DRY_RUN:-0}" = 1 ] && echo "   (DRY_RUN: rows went to $Q0DEST, NOT $OUT)"
  rm -f "$RAW"
fi

# =================== Q1 : integrated (update leaves + query leaves) =========
if [[ ",$PHASES," == *,q1,* ]]; then
  # procs whenever t>1: sim's peak_rss_mb accumulates over the whole
  # single-process replay and is NOT a per-batch peak.
  if [ "$SCALE" -gt 1 ] || [ "$MACHINES" -gt 1 ]; then EXEC=procs; else EXEC=${EXEC:-procs}; fi
  echo "-- Q1 integrated: exp_compose modes=$MODES exec=$EXEC QEVERY=$QEVERY QPOS=$QPOS"

  # A rebuild RELINKS target/release/examples/exp_compose.  dist_compose
  # snapshots its own exe to survive that (`take_exe_snapshot` in dist_compose.rs), but do
  # not relink under another live sweep if you can avoid it:  SKIP_BUILD=1.
  if [ "${SKIP_BUILD:-0}" != "1" ]; then
    ( cd "$ZKS" && cargo build --release --example exp_compose >/dev/null 2>&1 ) || {
      echo "Q1: build failed" >&2; exit 1; }
  elif [ ! -x "$ZKS/target/release/examples/exp_compose" ]; then
    echo "Q1: SKIP_BUILD=1 but target/release/examples/exp_compose is missing" >&2; exit 1
  fi

  # exp_compose writes into $ZKS/results (hard-coded in `results_dir()` in
  # src/experiments/mod.rs).  Keep a UNIQUE EXP_OUT name so nothing
  # existing is touched, and save/restore the untracked env.json it rewrites.
  ENVBAK=$(mktemp /tmp/zks_envjson.XXXXXX)
  [ -f "$ZKS/results/env.json" ] && cp -f "$ZKS/results/env.json" "$ENVBAK"
  STAMP=$(date +%Y%m%d_%H%M%S)
  RAWNAME="zks_query_matched_raw_s${SCALE}_${STAMP}.csv"

  ( cd "$ZKS" && \
    EXP_COMPOSE_FAMILY=cm \
    EXP_COMPOSE_MODE="$MODES" \
    EXP_COMPOSE_N="$N" \
    EXP_COMPOSE_BATCHES="$M" \
    EXP_D="$D" EXP_W="$W" \
    EXP_DATASET="$DATASET" \
    EXP_COMPOSE_EXEC="$EXEC" \
    EXP_COMPOSE_CORES="$CORES" \
    EXP_COMPOSE_MACHINES="$MACHINES" \
    EXP_COMPOSE_QUERY_EVERY="$QEVERY" \
    EXP_COMPOSE_QUERY_EVERY_OPS="$QPOS" \
    EXP_QUERY_KEY_MODE="$KEY_MODE" \
    EXP_COMPOSE_PROOF_DIR=/tmp/zks_q1_proofs.$$ \
    EXP_OUT="$RAWNAME" \
    "$ZKS/target/release/examples/exp_compose" )
  rc=$?
  rm -rf /tmp/zks_q1_proofs.$$

  RAWPATH="$ZKS/results/$RAWNAME"
  if [ $rc -eq 0 ] && [ -f "$RAWPATH" ]; then
    # exp_compose column indices (the `hdr` list in examples/exp_compose.rs):
    #  1 dataset 2 family 3 variant 4 mode 5 shape 6 n 7 m 8 t 9 cores
    # 10 machines 11 total_time_ms ... 18 peak_rss_mb 19 n_queries
    # 20 query_prove_ms 21 query_verify_ms 22 query_proof_bytes
    # 23 query_ctx_verifies 24-27 *_avg 28 query_split_leaves
    # 29 query_pad_records 30 exec ... last = status
    awk -F, -v OFS=, -v cells="$CELLS" -v km="$KEY_MODE" -v dd="$D" -v ww="$W" 'NR>1 && NF>30 {
      print "q1_integrated","zksketch",$2,$3,dd,ww,cells,$4,$30,$6,$7,$8,$9,$10,$1,km,
            $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$11,$18,0,$NF
    }' "$RAWPATH" >> "$OUT"
    echo "   raw kept at $RAWPATH (new file; nothing existing was touched)"
    # A schema drift in exp_compose's 47-column row would make the awk above
    # match nothing and we would "succeed" with no data. Fail loudly instead.
    added=$(awk -F, 'NR>1 && NF>30' "$RAWPATH" | wc -l)
    if [ "$added" -eq 0 ]; then
      echo "Q1 ERROR: exp_compose produced $(( $(wc -l < "$RAWPATH") - 1 )) raw rows but NONE had >30 fields" >&2
      echo "  -> column schema drifted; the awk mapping in $0 must be re-checked against" >&2
      echo "     the hdr column list in examples/exp_compose.rs before any row is trusted." >&2
      exit 4
    fi
    # Sanity: QEVERY>0 must yield n_queries>0, else the query columns are all zero
    # and the whole point of M3 is missing.
    if [ "$QEVERY" -gt 0 ] || [ "$QPOS" -gt 0 ]; then
      nq=$(awk -F, 'NR>1 && NF>30 {s+=$19} END{print s+0}' "$RAWPATH")
      [ "$nq" -eq 0 ] && echo "Q1 WARNING: n_queries=0 despite QEVERY=$QEVERY QPOS=$QPOS -- query side UNMEASURED" >&2
    fi
  else
    echo "Q1: exp_compose failed (rc=$rc) — no rows appended" >&2
  fi
fi

echo "== wrote $OUT"
column -s, -t < "$OUT" | tail -n 12
