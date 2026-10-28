#!/usr/bin/env bash
# zk-Analytics Count-Min query proofs over n epochs: prove and verify time, receipt size, r0vm peak RSS.
# n values already in the CSV are skipped.
# Usage: ./q_sweep.sh [options] <n1> [n2 ...]
#   --query estimate|topk|both   default estimate
#   --scale K                    keys per source; default 1 (estimate) or CM_TOPK_SLOTS (topk)
#   --events-per-key E           default 1
#   --seed X                     default 48879 (their bench default)
#   --exec                       executor only, no proving
#   --out FILE                   default results/zka_query_sweep.csv
#   --dry-run                    print the plan and exit
# Env: CM_TOPK_SLOTS (top-k slots, build time; default 100), SKIP_BUILD=1
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"   # RESULTS build_cyc cyc_target
TOPK=${CM_TOPK_SLOTS:-100}      # one target dir per value (common.sh), so BIN is always built at TOPK
BIN=$(cyc_target "$TOPK")/release/qsweep
OUT=$RESULTS/zka_query_sweep.csv
QUERY=estimate
SCALE=""
EPK=1
SEED=48879
MODE=prove
DRYRUN=0
EPOCHS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --query)          QUERY="$2"; shift 2;;
    --scale)          SCALE="$2"; shift 2;;
    --events-per-key) EPK="$2"; shift 2;;
    --seed)           SEED="$2"; shift 2;;
    --out)            OUT="$2"; shift 2;;
    --exec)           MODE=exec; shift;;
    --dry-run)        DRYRUN=1; shift;;
    -h|--help)        sed -n '2,12p' "$0"; exit 0;;
    -*)               echo "unknown option $1" >&2; exit 2;;
    *)                EPOCHS+=("$1"); shift;;
  esac
done

[[ ${#EPOCHS[@]} -eq 0 ]] && { echo "usage: $0 [options] <n1> [n2 ...]" >&2; exit 2; }
case "$QUERY" in
  estimate|topk) QUERIES=("$QUERY");;
  both)          QUERIES=(estimate topk);;
  *)             echo "--query must be estimate|topk|both" >&2; exit 2;;
esac

# Build qsweep at TOPK -- but never next to an in-flight proof of ours (an all-core
# compile would perturb its prove_s, and a relink would swap the binary under it),
# and never for --dry-run. The reaper-arming check further down still runs.
if [[ $DRYRUN == 0 ]] && pgrep -x -u "$(id -u)" r0vm >/dev/null 2>&1; then
  echo "REFUSING TO START: an r0vm owned by $(id -un) is already running (nothing built, no r0vm touched)" >&2
  pgrep -ax -u "$(id -u)" r0vm >&2; exit 3
fi
if [[ ${SKIP_BUILD:-0} != 1 && $DRYRUN == 0 ]]; then
  build_cyc "$TOPK" --bin qsweep >&2 || { echo "qsweep build failed (CM_TOPK_SLOTS=$TOPK)" >&2; exit 2; }
fi
[[ -x $BIN ]] || { echo "missing $BIN -- run once without --dry-run / SKIP_BUILD=1" >&2; exit 2; }

# ---------------------------------------------------------------- r0vm hygiene
# risc0 proves in a SEPARATE `r0vm` process that survives killing its parent, and
# a surviving server's VmHWM is a high-water mark across every run it served --
# so it is killed before AND after each data point, making each peak per-run.
# SHARED BOX: every pgrep/pkill here is scoped to -u $(id -u), so another user's
# r0vm is never touched. If one of OUR OWN r0vm processes is already up when the
# script starts, we refuse to run rather than kill a job in flight.
kill_r0vm() {
  local pids
  pids=$(pgrep -x -u "$(id -u)" r0vm 2>/dev/null)
  [[ -n "$pids" ]] || return 0
  kill -TERM $pids 2>/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -x -u "$(id -u)" r0vm >/dev/null 2>&1 || return 0
    sleep 0.3
  done
  pkill -KILL -x -u "$(id -u)" r0vm 2>/dev/null
  return 0
}

POLLER_PID=""
# MAY_KILL gates the r0vm reaper. It stays 0 until we have PROVED that no r0vm
# of ours was already running (the refusal check below) -- otherwise the EXIT
# trap would kill the very in-flight proving job the refusal exists to protect,
# and a --dry-run would kill a proof that is already running.
MAY_KILL=0
cleanup() {
  [[ -n "$POLLER_PID" ]] && kill "$POLLER_PID" 2>/dev/null
  [[ $MAY_KILL == 1 ]] && kill_r0vm
  return 0
}
trap 'cleanup; exit 130' INT TERM
trap 'cleanup' EXIT

# Poll every r0vm process' VmHWM (its own high-water mark, in kB) and keep the
# max in $1. The driver's /proc/self/status is ~8 MB and meaningless here.
start_poller() {
  local f="$1"
  echo 0 > "$f"
  (
    while :; do
      for p in $(pgrep -x -u "$(id -u)" r0vm 2>/dev/null); do
        v=$(awk '/^VmHWM:/{print $2}' "/proc/$p/status" 2>/dev/null)
        [[ -n "${v:-}" ]] || continue
        cur=$(cat "$f" 2>/dev/null || echo 0)
        (( v > cur )) && echo "$v" > "$f"
      done
      sleep 0.2
    done
  ) &
  POLLER_PID=$!
}

# ------------------------------------------------------------------------- CSV
mkdir -p "$(dirname "$OUT")"
if [[ ! -s $OUT ]]; then
  { "$BIN" --header | tr -d '\n'; echo ",r0vm_peak_rss_mb,wall_s"; } > "$OUT"
fi

# already-done key: mode,query,epochs,keys_per_source,events_per_key,topk_slots
have_row() {
  awk -F, -v m="$1" -v q="$2" -v n="$3" -v k="$4" -v e="$5" -v t="$TOPK" \
    '$2==m && $3=="cm/"q && $4==n && $7==k && $9==e && $10==t {found=1} END{exit !found}' "$OUT"
}

if [[ $DRYRUN == 0 ]] && pgrep -x -u "$(id -u)" r0vm >/dev/null 2>&1; then
  echo "REFUSING TO START: an r0vm owned by $(id -un) is already running:" >&2
  pgrep -ax -u "$(id -u)" r0vm >&2
  echo "Another proving job is in flight. Wait for it, or kill it yourself first." >&2
  echo "(No r0vm was touched: the reaper stays disarmed until this check passes.)" >&2
  exit 3
fi
# Only now is it safe to reap r0vm on exit: every r0vm that appears from here on
# is one WE spawned. --dry-run never spawns one, so it never arms the reaper.
[[ $DRYRUN == 0 ]] && MAY_KILL=1

echo "=== zk-Analytics CM query sweep ==="
echo "out       : $OUT"
echo "mode      : $MODE   (prove = ProverOpts::succinct(), their shipped tier)"
echo "queries   : ${QUERIES[*]}"
echo "epochs    : ${EPOCHS[*]}"
echo "geometry  : CM_ROWS=3 CM_COLS=1024 (aggregator/core/src/lib.rs:39-40), CM_TOPK_SLOTS=$TOPK (build-time, baked into $BIN)"
echo

for q in "${QUERIES[@]}"; do
  if [[ -n $SCALE ]]; then k=$SCALE; elif [[ $q == topk ]]; then k=$TOPK; else k=1; fi
  for n in "${EPOCHS[@]}"; do
    if have_row "$MODE" "$q" "$n" "$k" "$EPK"; then
      echo "[skip] $MODE cm/$q n=$n keys=$k (already in CSV)"
      continue
    fi
    args=(--epochs "$n" --query "$q" --num-sources 1 --sources-per-epoch 1
          --keys-per-source "$k" --events-per-key "$EPK" --seed "$SEED")
    [[ $MODE == prove ]] && args+=(--prove)
    if [[ $DRYRUN == 1 ]]; then echo "[plan] $BIN ${args[*]}"; continue; fi

    echo "[run ] $MODE cm/$q n=$n keys=$k ..."
    kill_r0vm
    RSSF=$(mktemp); start_poller "$RSSF"
    t0=$(date +%s.%N)
    line=$("$BIN" "${args[@]}")
    rc=$?
    t1=$(date +%s.%N)
    kill "$POLLER_PID" 2>/dev/null; POLLER_PID=""
    kill_r0vm
    rss_kb=$(cat "$RSSF" 2>/dev/null || echo 0); rm -f "$RSSF"

    if [[ $rc -ne 0 || -z $line ]]; then echo "[FAIL] n=$n rc=$rc" >&2; continue; fi
    rss_mb=$(awk -v k="$rss_kb" 'BEGIN{printf "%.1f", k/1024}')
    wall=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", b-a}')
    echo "${line},${rss_mb},${wall}" >> "$OUT"
    echo "       -> $line,${rss_mb},${wall}"
  done
done

echo
echo "done. rows now in $OUT: $(( $(wc -l < "$OUT") - 1 ))"
