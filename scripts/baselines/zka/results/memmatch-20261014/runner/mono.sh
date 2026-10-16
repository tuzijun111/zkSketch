#!/usr/bin/env bash
# usage: mono.sh <tag> <m> [cap]: one monolithic leaf of m records (T=1), with a MemAvailable watchdog
SP=$(cd "$(dirname "$0")" && pwd)   # the runner directory (a session scratch dir when run)
$SP/zks.sh "$1" "$2" 1 "${3:-2048}" > $SP/out_mono_$1_m$2.txt 2>&1 &
W=$!
$SP/memwatch.sh $W $SP/memwatch_mono_$1_m$2.log &
wait $W; rc=$?
wait
cat $SP/out_mono_$1_m$2.txt $SP/memwatch_mono_$1_m$2.log
exit $rc
