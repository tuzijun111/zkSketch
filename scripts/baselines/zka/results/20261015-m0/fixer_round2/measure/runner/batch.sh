#!/usr/bin/env bash
# Fixer-round measurements, one at a time, with a 60 s cool-down before each.
R=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0fix/measure/runner
O=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0fix/measure/batch.log
run() { sleep 60; echo "$(date -Is) start $1 load=$(cut -d' ' -f1-3 /proc/loadavg)" >> $O; "$R/runab.sh" "$@" >> $O 2>&1; echo "$(date -Is) end $1" >> $O; }
run gk_B4 gk 128 16 384 B
run gk_Bidle1 gk 128 16 384 B EXP_MALLOC_TRIM=idle
run gk_Bnocache gk 128 16 384 B EXP_MERGE_CACHE=0
run bloom_Bidle1 bloom 256 8 2048 B EXP_MALLOC_TRIM=idle
run gk_A4 gk 128 16 384 A
run gk_Bidle2 gk 128 16 384 B EXP_MALLOC_TRIM=idle
echo BATCHDONE >> $O
