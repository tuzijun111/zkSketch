#!/usr/bin/env bash
# Run a command and report peak RSS (VmHWM, a kernel high-water mark) of
#   main      the command's own process
#   r0vm      the largest r0vm process descending from it (RISC Zero proves in r0vm)
#   desc      the largest descendant of any name (e.g. the procs-engine workers)
#   tree      the whole tree at once: the largest sum of VmRSS over the command and all its
#             descendants in one sample (e.g. zkSketch's coordinator + worker together; a sample
#             can miss a peak shorter than the interval, the per-process VmHWM values cannot)
# Samples /proc every 0.5 s.
# The command runs in its own session and process group (setsid). On INT/TERM/HUP this
# script stops that group (TERM, then KILL) and exits 130; when the command exits, any
# process of its group still alive (e.g. a worker that outlived the coordinator) is killed.
# It never signals a process outside the group it started.
# Usage: rss_tree.sh <label> <cmd...>     -> one RSSTREE line on stderr at the end
#   RSSTREE,<label>,main_peak_rss_mb=,r0vm_peak_rss_mb=,desc_peak_rss_mb=,wall_s=,rc=,tree_peak_rss_mb=
set -uo pipefail
LBL=${1:?usage: rss_tree.sh <label> <cmd...>}; shift
STATE=$(mktemp)
echo "0 0 0 0" > "$STATE"
T0=$(date +%s.%N)
setsid "$@" & CMD=$!
# setsid does not fork here (a background job of a non-interactive shell is not a group
# leader), so CMD becomes the new group's id once the child has called setsid(). Wait for
# that; should it never happen, fall back to signalling the single PID.
GRP=$CMD

stop_group() {  # TERM, a grace period, then KILL; only the group started above
  kill -TERM -- "$GRP" 2>/dev/null || return 0
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 -- "$GRP" 2>/dev/null || return 0; sleep 0.5; done
  kill -KILL -- "$GRP" 2>/dev/null
}
on_signal() {
  echo "rss_tree: interrupted; stopping process group $CMD ($LBL)" >&2
  stop_group
  wait "$CMD" 2>/dev/null
  rm -f "$STATE"
  exit 130
}
trap on_signal INT TERM HUP
for _ in $(seq 40); do  # pgrp = 3rd field after "pid (comm) "
  pg=$(sed 's/^.*) //' "/proc/$CMD/stat" 2>/dev/null | cut -d' ' -f3) || pg=
  if [[ -z $pg || $pg == "$CMD" ]]; then GRP=-$CMD; break; fi
  sleep 0.05
done

hwm() { awk '/^VmHWM:/{h=$2} /^VmRSS:/{r=$2} END{if (h != "") print h, r + 0}' "/proc/$1/status" 2>/dev/null; }  # "VmHWM VmRSS" (kB)
if [[ -r /proc/$$/task/$$/children ]]; then
  descendants() {  # all descendants of $1
    local p
    for p in $(cat /proc/"$1"/task/*/children 2>/dev/null); do
      echo "$p"
      descendants "$p"
    done
  }
else  # kernel without CONFIG_PROC_CHILDREN: walk the parent links instead
  descendants() {
    ps -e -o pid=,ppid= | awk -v root="$1" '{par[$1] = $2}
      END { for (p in par) { q = p; while ((q in par) && q != root && par[q] > 1) q = par[q]; if (q == root && p != root) print p } }'
  }
fi

( while kill -0 "$CMD" 2>/dev/null; do
    read -r M R D X < "$STATE"
    S=0
    read -r v r <<< "$(hwm "$CMD")"; [[ -n ${v:-} && $v -gt $M ]] && M=$v; S=$((S + ${r:-0}))
    for p in $(descendants "$CMD"); do
      read -r v r <<< "$(hwm "$p")"; [[ -z ${v:-} ]] && continue
      S=$((S + r))
      (( v > D )) && D=$v
      if [[ "$(cat /proc/"$p"/comm 2>/dev/null)" == r0vm ]] && (( v > R )); then R=$v; fi
    done
    (( S > X )) && X=$S
    echo "$M $R $D $X" > "$STATE"
    sleep 0.5
  done ) & POLL=$!

wait "$CMD"; RC=$?
T1=$(date +%s.%N)
wait "$POLL" 2>/dev/null
if kill -0 -- "$GRP" 2>/dev/null; then
  echo "rss_tree: $LBL exited (rc=$RC) but processes of its group are still alive; stopping them" >&2
  stop_group
fi
read -r M R D X < "$STATE"; rm -f "$STATE"
mb() { awk -v k="$1" 'BEGIN{printf "%.1f", k/1024}'; }
echo "RSSTREE,$LBL,main_peak_rss_mb=$(mb "$M"),r0vm_peak_rss_mb=$(mb "$R"),desc_peak_rss_mb=$(mb "$D"),wall_s=$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.1f", b-a}'),rc=$RC,tree_peak_rss_mb=$(mb "$X")" >&2
exit $RC
