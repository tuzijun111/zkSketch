#!/usr/bin/env bash
# usage: run_tests.sh <tag> <on|off> <filters...>
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0/env.sh
tag=$1; sw=$2; shift 2
if [[ $sw == off ]]; then export EXP_FOREST_RETAIN_PREP=1 EXP_MALLOC_TRIM=0 EXP_EXIT_BEFORE_AUDIT=0 EXP_MERGE_CACHE=0; fi
cd $SB
L=$S/tests_$tag.log
{ echo "# $(date -Is) tag=$tag switches=$sw load=$(cut -d' ' -f1-3 /proc/loadavg) head=$(git rev-parse --short HEAD) dirty=$(git status --porcelain | wc -l)"
  echo "# filters: $*"; env | grep -E '^EXP_' | sort; } > $L
( time cargo test --release --locked --lib -- "$@" ) >> $L 2>&1
echo "exit=$?" >> $L
