#!/usr/bin/env bash
# usage: memwatch.sh <wrapper pid> <log>: while the wrapper lives, sample MemAvailable every 1 s;
# log the minimum; if it drops below 40 GiB, TERM the run_zks.sh child of the wrapper (it stops
# exp_compose's process group through rss_tree.sh), then KILL whatever is left of that tree after 30 s.
W=$1; LOG=$2; LIM=$((40 * 1048576)); MIN=999999999999
echo "memwatch start $(date -Is) wrapper=$W limit_kb=$LIM" >> "$LOG"
tree() { local p; for p in $(cat /proc/"$1"/task/*/children 2>/dev/null); do echo "$p"; tree "$p"; done; }
while kill -0 "$W" 2>/dev/null; do
  a=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
  if (( a < MIN )); then MIN=$a; echo "min $(date -Is) MemAvailable_gib=$(awk -v k=$a 'BEGIN{printf "%.1f", k/1048576}')" >> "$LOG"; fi
  if (( a < LIM )); then
    echo "ABORT $(date -Is) MemAvailable below 40 GiB ($a kB); stopping the run" >> "$LOG"
    for p in $(pgrep -P "$W"); do kill -TERM "$p" 2>/dev/null; done
    for _ in $(seq 30); do kill -0 "$W" 2>/dev/null || break; sleep 1; done
    for p in $(tree "$W"); do kill -KILL "$p" 2>/dev/null; done
    echo "ABORTED $(date -Is)" >> "$LOG"
    exit 3
  fi
  sleep 1
done
echo "memwatch end $(date -Is) min_MemAvailable_gib=$(awk -v k=$MIN 'BEGIN{printf "%.1f", k/1048576}')" >> "$LOG"
