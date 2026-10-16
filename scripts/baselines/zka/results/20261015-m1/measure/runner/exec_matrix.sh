#!/usr/bin/env bash
# exec_matrix.sh <outdir>: zk-Analytics matched GK executor rows at B = 2,048 (AOL, noroot),
# configs A (cap 384, m_sub 128) and B (cap 768, m_sub 512), epochs 0 and 1, impls
# fast / fixed_linear / literal; plus the textbook GK (../gk) reference at B = 2,048, epochs 0 and 1.
R="$(cd "$(dirname "$0")" && pwd)"
. "$R/env.sh"
O=$1; mkdir -p "$O"
EB=$BASELINE_DIR/build
GKM=$EB/zka-gk-matched/release/gk_matched
GKT=$EB/zka-gk/release/gk
KEYS=$HOME/zkSketch/data/aol.keys
{
  echo "# exec_matrix $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
  echo "# zkSketch=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) r0vm=$(r0vm --version) zka=$(git -C $BASELINE_DIR/zka rev-parse --short=12 HEAD)"
  echo "# gk_matched md5=$(md5sum < $GKM | cut -c1-12) gk md5=$(md5sum < $GKT | cut -c1-12) keys md5=$(md5sum < $KEYS | cut -c1-12)"
} > "$O/exec.log"
"$GKM" --header > "$O/matched_exec.csv"
for cfg in "384 128" "768 512"; do
  set -- $cfg
  for impl in fast fixed_linear literal; do
    for e in 0 1; do
      echo "# matched cap=$1 m_sub=$2 impl=$impl epoch=$e $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$O/exec.log"
      "$GKM" --mode aggr --epoch-index $e --root noroot --epoch-size 2048 --batch 8 --keys "$KEYS" \
        --capacity $1 --m-sub $2 --s 51 --impl $impl >> "$O/matched_exec.csv" 2>> "$O/exec.log"
      echo "# rc=$?" >> "$O/exec.log"
    done
  done
done
"$GKT" --header > "$O/textbook_exec.csv"
for e in 0 1; do
  echo "# textbook epoch=$e $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$O/exec.log"
  "$GKT" --mode aggr --epoch-index $e --root noroot --epoch-size 2048 --batch 8 --keys "$KEYS" >> "$O/textbook_exec.csv" 2>> "$O/exec.log"
  echo "# rc=$?" >> "$O/exec.log"
done
echo "# end $(date -Is)" >> "$O/exec.log"
