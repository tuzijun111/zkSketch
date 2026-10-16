# executor-only follow-ups from the sandbox clone (after the A+B evidence run)
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m1/env.sh
cd $HOME/zkSketch
OUT=$SP/sbx_check
OUT_DIR=$OUT/D SKIP_BUILD=1 CONFIGS="D:2048:2048" EPOCHS=2 scripts/baselines/zka/gk_matched/gk_matched_check.sh > $OUT/D/runner.out 2>&1; echo "D rc=$?"
B=$BASELINE_DIR/build/zka-gk-matched/release/gk_matched; K=$HOME/zkSketch/data/aol.keys
{ $B --header
  for n in 1 2 3 4 5 6 7 8; do v=1810625; (( n >= 6 )) && v=985491
    $B --mode query --epochs $n --rank-value $v --capacity 2048 --m-sub 2048 --epoch-size 2048 --keys $K; done
  for c in "128 512" "64 512"; do set -- $c
    $B --mode query --epochs 1 --rank-value 1810625 --capacity $1 --m-sub $2 --epoch-size 2048 --keys $K; done
} > $OUT/zka_gk_matched_query.csv 2> $OUT/zka_gk_matched_query.err; echo "query rc=$?"
