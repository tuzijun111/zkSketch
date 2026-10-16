#!/usr/bin/env bash
# usage: run_tests.sh <tag> <on|off> <lib|test:NAME> <filters...>
# Stamped with the sandbox clone's HEAD + tree hash (git write-tree of the index, after checking the tree is clean).
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0fix/env.sh
tag=$1; sw=$2; tgt=$3; shift 3
unset EXP_FOREST_RETAIN_PREP EXP_MALLOC_TRIM EXP_EXIT_BEFORE_AUDIT EXP_MERGE_CACHE EXP_MERGE_CACHE_ENTRIES
if [[ $sw == off ]]; then export EXP_FOREST_RETAIN_PREP=1 EXP_MALLOC_TRIM=0 EXP_EXIT_BEFORE_AUDIT=0 EXP_MERGE_CACHE=0; fi
cd $SB
case $tgt in lib) T=(--lib) ;; test:*) T=(--test "${tgt#test:}") ;; esac
L=$S/tests_$tag.log
{ echo "# $(date -Is) tag=$tag switches=$sw target=$tgt load=$(cut -d' ' -f1-3 /proc/loadavg)"
  echo "# head=$(git rev-parse HEAD) tree=$(git rev-parse 'HEAD^{tree}') index_tree=$(git write-tree) porcelain_lines=$(git status --porcelain --untracked-files=no | wc -l) (0 = the committed tree)"
  echo "# filters: $*"; env | grep -E '^EXP_' | sort; } > $L
( time cargo test --release --locked "${T[@]}" -- "$@" ) >> $L 2>&1
echo "exit=$?" >> $L
