#!/usr/bin/env bash
# batch.sh <name> <label:tag:variant:m:T>...: run1.sh one at a time, 60 s cool-down before each, under the load sampler.
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
NAME=$1; shift
O=$S/batch_$NAME.log
rm -f $S/load_$NAME.stop
python3 -I $R/loadsample.py $S/load_$NAME.csv $S/load_$NAME.stop 5 &
LS=$!
for spec in "$@"; do
  IFS=: read -r lbl tag var m t <<< "$spec"
  sleep 60
  echo "$(date -Is) start $lbl load=$(cut -d' ' -f1-3 /proc/loadavg)" >> $O
  "$R/run1.sh" "$lbl" "$tag" "$var" "$m" "$t" >> $O 2>&1
  echo "$(date -Is) end $lbl" >> $O
done
touch $S/load_$NAME.stop; wait $LS
echo BATCHDONE >> $O
