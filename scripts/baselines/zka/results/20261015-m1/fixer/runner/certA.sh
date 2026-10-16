#!/usr/bin/env bash
R="$(cd "$(dirname "$0")" && pwd)"; . "$R/env.sh"
O=$R/clean/certA; mkdir -p $O
GKM=$BASELINE_DIR/build/zka-gk-matched/release/gk_matched
echo "# certify A start $(date -Is) load=[$(cut -d' ' -f1-3 /proc/loadavg)] head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) gk_matched=$(md5sum < $GKM | cut -c1-12)" > $O/certify.log
"$GKM" --header > $O/zka_gk_matched_certify.csv
/usr/bin/time -v "$GKM" --mode certify --epochs 2 --capacity 384 --m-sub 128 --epoch-size 2048 --keys data/aol.keys >> $O/zka_gk_matched_certify.csv 2>> $O/certify.log
echo "# rc=$? end $(date -Is)" >> $O/certify.log
