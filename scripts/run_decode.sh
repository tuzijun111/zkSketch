#!/usr/bin/env bash
# Query-circuit (decode) test harness for all four sketch families.
#
# Each family's *deployed* update variant produces a committed final state; the
# matching decode/query STARK re-hashes that state (binding the commitment) and
# proves a query answer against it. This script runs the two independent checks:
#
#   1. TESTS  — the per-family decode unit tests (cargo). These assert the
#               in-circuit answer == an independent native reference AND that the
#               proof self-verifies (verify_all_tables). This is the authoritative
#               correctness gate.
#   2. RUNNER — examples/exp_decode.rs. Builds each deployed final state, runs the
#               query circuit, and prints a results table (answer vs native,
#               prove/verify time, proof bytes). Exits non-zero on any mismatch.
#
# Families / mapping (paper §Decode, EVAL_SPEC E3):
#   CM  omc        -> prove_cm_decode        (point frequency)
#   HLL omc        -> prove_hll_decode_omc   (cardinality)
#   SS  certified  -> prove_ss_decode        (top-c heavy-hitter mass)
#   GK  bandmerge2 -> prove_gk2_decode       (two-sided approximate rank)
#
# Usage:
#   scripts/run_decode.sh            # tests + runner (default)
#   scripts/run_decode.sh tests      # only the decode unit tests
#   scripts/run_decode.sh run        # only the results-table runner
#
# Run from the repo root.
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="${1:-all}"

run_tests() {
  echo "==> [1/2] decode unit tests (answer == native + self-verify)"
  # `decode::` runs every family's decode tests (CM/HLL/SS/GK). A failing test
  # prints its own `decode::<family>::<name> ... FAILED`, so the family is named.
  cargo test --release --lib decode:: 2>&1 \
    | grep -E "running [0-9]+ tests|test result|FAILED|panicked" || true
  echo
}

run_runner() {
  echo "==> [2/2] exp_decode runner (proven results table)"
  cargo run --release --example exp_decode
  echo
}

case "$MODE" in
  tests) run_tests ;;
  run)   run_runner ;;
  all)   run_tests; run_runner ;;
  *) echo "usage: $0 [all|tests|run]" >&2; exit 2 ;;
esac

echo "done."
