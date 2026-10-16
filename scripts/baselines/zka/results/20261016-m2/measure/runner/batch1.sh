#!/usr/bin/env bash
# batch1.sh: the load sampler around iso.sh (isolation probes).
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
rm -f $S/load1.stop
python3 -I $R/loadsample.py $S/load_iso.csv $S/load1.stop 5 &
LS=$!
"$R/iso.sh" > $S/iso.out 2>&1
touch $S/load1.stop; wait $LS
echo ISODONE >> $S/iso.out
