#!/usr/bin/env bash
# Decode (query) circuits of the four families: the cargo unit tests, then the exp_decode results table.
# Usage: scripts/run_decode.sh [all|tests|run]
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="${1:-all}"

run_tests() {
  echo "==> [1/2] decode unit tests (answer == native + self-verify)"
  # `decode::` runs every family's decode tests (CM/HLL/SS/GK). A failing test
  # prints its own `decode::<family>::<name> ... FAILED`, so the family is named.
  # The filtered summary must not hide a failure: pipefail keeps cargo's status.
  local rc=0
  cargo test --release --lib decode:: 2>&1 \
    | { grep -E "^error|running [0-9]+ tests|test result|FAILED|panicked" || true; } || rc=$?
  echo
  if (( rc != 0 )); then echo "decode unit tests FAILED (cargo exit $rc)" >&2; exit "$rc"; fi
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
