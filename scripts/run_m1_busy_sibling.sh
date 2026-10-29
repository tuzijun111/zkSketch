#!/usr/bin/env bash
# M = 1 forest run on NUMA node 0 while a dummy prover keeps node 1 busy, as in the M >= 2 runs.
# Usage: scripts/run_m1_busy_sibling.sh <out.csv> [families, default cm,hll,ss,gk,bloom,kmv]
set -u
OUT="${1:?usage: run_m1_busy_sibling.sh <out.csv> [families]}"
FAMILIES="${2:-cm,hll,ss,gk,bloom,kmv}"

export EXP_DATASET="${EXP_DATASET:-aol}"
export EXP_COMPOSE_N="${EXP_COMPOSE_N:-1048576}"
export EXP_COMPOSE_BATCHES="${EXP_COMPOSE_BATCHES:-16384}"
export EXP_D="${EXP_D:-3}" EXP_W="${EXP_W:-16384}" EXP_HLL_B="${EXP_HLL_B:-14}"
export EXP_SS_CAP="${EXP_SS_CAP:-16384}" EXP_GK_CAP="${EXP_GK_CAP:-2048}" EXP_KMV_K="${EXP_KMV_K:-16384}"
export EXP_BLOOM_VARIANT="${EXP_BLOOM_VARIANT:-omc}"   # the packed Bloom leaf needs 7 m < 2^16
export EXP_COMPOSE_MODE=forest EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES="${EXP_COMPOSE_CORES:-32}"
export EXP_COMPOSE_EXEC=procs EXP_NET_MBPS="${EXP_NET_MBPS:-200}" EXP_NET_RTT_MS="${EXP_NET_RTT_MS:-0.2}"
export EXP_COMPOSE_BACKEND="${EXP_COMPOSE_BACKEND:-plonky3}"

DUMMY_N=$(( ${EXP_COMPOSE_N/2^/} ))
# accept 2^k form for N in the dummy doubling
case "$EXP_COMPOSE_N" in
  2^*) DUMMY_N="2^$(( ${EXP_COMPOSE_N#2^} + 1 ))" ;;
  *)   DUMMY_N=$(( EXP_COMPOSE_N * 2 )) ;;
esac

IFS=',' read -ra FAMS <<< "$FAMILIES"
BASE="${OUT%.csv}"   # each family writes results/<BASE>_<fam>.csv (a run replaces its output file); merged below
for fam in "${FAMS[@]}"; do
  echo "== [$fam] starting dummy replica on sibling node (node offset 1, N=$DUMMY_N) =="
  dummy_log=$(mktemp /tmp/busy_sibling_dummy.XXXXXX.log)
  ( EXP_COMPOSE_NODE_OFFSET=1 EXP_COMPOSE_N="$DUMMY_N" EXP_COMPOSE_FAMILY="$fam" \
      scripts/run_compose.sh "/tmp/busy_sibling_dummy_$fam.csv" >"$dummy_log" 2>&1 ) &
  dummy_pid=$!
  # wait for the dummy's leaf phase to begin (build + setup pass): first leaf line
  echo "   waiting for dummy build+setup (log: $dummy_log)"
  for _ in $(seq 1 120); do
    grep -q "procs engine\|leaf=" "$dummy_log" 2>/dev/null && break
    sleep 5
  done
  sleep 120   # let the dummy get well into leaf proving
  echo "== [$fam] dummy busy; running the M=1 measurement on node 0 =="
  EXP_COMPOSE_FAMILY="$fam" scripts/run_compose.sh "${BASE}_$fam.csv"
  echo "== [$fam] measurement done; stopping dummy (pid $dummy_pid) =="
  pkill -P "$dummy_pid" 2>/dev/null; kill "$dummy_pid" 2>/dev/null
  pkill -f "busy_sibling_dummy_$fam.csv" 2>/dev/null
  sleep 5
done
merged="results/$BASE.csv"; : > "$merged"; hdr=0
for fam in "${FAMS[@]}"; do
  f="results/${BASE}_$fam.csv"
  [[ -s $f ]] || { echo "warning: no $f (the $fam run failed?)" >&2; continue; }
  (( hdr )) || { head -n1 "$f" > "$merged"; hdr=1; }
  tail -n +2 "$f" >> "$merged"
done
echo "all families done -> $merged"
