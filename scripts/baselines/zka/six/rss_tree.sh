#!/usr/bin/env bash
# Run a command and report peak RSS (VmHWM, a kernel high-water mark) of
#   main      the command's own process
#   r0vm      the largest r0vm process descending from it (RISC Zero proves in r0vm)
#   desc      the largest descendant of any name (e.g. the procs-engine workers)
# Samples /proc every 0.5 s (read-only; signals nothing it did not start).
# Usage: rss_tree.sh <label> <cmd...>     -> one RSSTREE line on stderr at the end
set -uo pipefail
LBL=${1:?usage: rss_tree.sh <label> <cmd...>}; shift
STATE=$(mktemp)
echo "0 0 0" > "$STATE"
"$@" & CMD=$!

hwm() { awk '/^VmHWM:/{print $2}' "/proc/$1/status" 2>/dev/null; }
descendants() {  # all descendants of $1
  local p c
  for p in $(cat /proc/"$1"/task/*/children 2>/dev/null); do
    echo "$p"
    descendants "$p"
  done
}

( while kill -0 "$CMD" 2>/dev/null; do
    read -r M R D < "$STATE"
    v=$(hwm "$CMD"); [[ -n ${v:-} && $v -gt $M ]] && M=$v
    for p in $(descendants "$CMD"); do
      v=$(hwm "$p"); [[ -z ${v:-} ]] && continue
      (( v > D )) && D=$v
      if [[ "$(cat /proc/"$p"/comm 2>/dev/null)" == r0vm ]] && (( v > R )); then R=$v; fi
    done
    echo "$M $R $D" > "$STATE"
    sleep 0.5
  done ) & POLL=$!

T0=$(date +%s.%N)
wait "$CMD"; RC=$?
T1=$(date +%s.%N)
wait "$POLL" 2>/dev/null
read -r M R D < "$STATE"; rm -f "$STATE"
mb() { awk -v k="$1" 'BEGIN{printf "%.1f", k/1024}'; }
echo "RSSTREE,$LBL,main_peak_rss_mb=$(mb "$M"),r0vm_peak_rss_mb=$(mb "$R"),desc_peak_rss_mb=$(mb "$D"),wall_s=$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.1f", b-a}'),rc=$RC" >&2
exit $RC
