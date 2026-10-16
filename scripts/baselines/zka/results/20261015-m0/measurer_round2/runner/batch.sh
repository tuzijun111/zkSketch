#!/usr/bin/env bash
# Measurer round 2: A/B one at a time, 60 s cool-down before each; then root-VK identity runs.
R=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0/r2measure/runner
O=$(dirname $R)/batch.log
rm -f $(dirname $R)/load.stop
python3 -I $R/loadsample.py $(dirname $R)/load.csv $(dirname $R)/load.stop 5 &
LS=$!
run() { sleep 60; echo "$(date -Is) start $1 load=$(cut -d' ' -f1-3 /proc/loadavg)" >> $O; "$R/runab.sh" "$@" >> $O 2>&1; echo "$(date -Is) end $1" >> $O; }
idr() { sleep 45; echo "$(date -Is) start id $1 load=$(cut -d' ' -f1-3 /proc/loadavg)" >> $O; "$R/idrun.sh" "$@" >> $O 2>&1; echo "$(date -Is) end id $1" >> $O; }
run gk_A1 gk 128 16 384 A
run gk_B1 gk 128 16 384 B
run bloom_A1 bloom 256 8 2048 A
run bloom_B1 bloom 256 8 2048 B
run gk_A2 gk 128 16 384 A
run gk_B2 gk 128 16 384 B
run bloom_A2 bloom 256 8 2048 A
run bloom_B2 bloom 256 8 2048 B
idr gk_A gk 128 16 A
idr gk_B gk 128 16 B
idr bloom_A bloom 256 8 A
idr bloom_B bloom 256 8 B
touch $(dirname $R)/load.stop; wait $LS
echo BATCHDONE >> $O
