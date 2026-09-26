#!/usr/bin/env bash
# Run a command and report the peak RSS (VmHWM) of the r0vm processes IT spawns.
#
# Why not ../rss_watch.sh: that script refuses to start while ANY r0vm of this uid is
# running and pkills every r0vm of this uid on exit. Other jobs of the same account
# (for example the sibling SS/GK baselines) may be executing or proving at the same
# time, so here only r0vm processes that descend from our own command are sampled,
# and nothing is ever killed except this script's own sampler subshell.
#
# risc0 proves inside a separate `r0vm` process (the driver's own RSS is meaningless);
# VmHWM is the kernel's high-water mark, so a late sample still sees the true peak.
#
# Usage: ./rss_child.sh <label> <cmd...>     (stdout/stderr of cmd pass through)
set -uo pipefail
LBL=${1:?usage: rss_child.sh <label> <cmd...>}; shift
MAXF=$(mktemp); echo 0 > "$MAXF"
"$@" & CMD=$!

descends_from() {  # descends_from <pid> <ancestor>
  local p=$1
  while [[ -n $p && $p -gt 1 ]]; do
    [[ $p == "$2" ]] && return 0
    p=$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null)
  done
  return 1
}

( while kill -0 "$CMD" 2>/dev/null; do
    for p in $(pgrep -u "$(id -u)" -x r0vm 2>/dev/null); do
      descends_from "$p" "$CMD" || continue
      v=$(awk '/VmHWM/{print $2}' "/proc/$p/status" 2>/dev/null)
      [[ -n ${v:-} && $v -gt $(cat "$MAXF") ]] && echo "$v" > "$MAXF"
    done
    sleep 0.5
  done ) & POLL=$!

T0=$(date +%s.%N)
wait "$CMD"; RC=$?
T1=$(date +%s.%N)
wait "$POLL" 2>/dev/null   # the sampler exits by itself once CMD is gone
KB=$(cat "$MAXF"); rm -f "$MAXF"
echo "RSSCHILD,$LBL,r0vm_peak_rss_mb=$(awk -v k="$KB" 'BEGIN{printf "%.1f", k/1024}'),wall_s=$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.1f", b-a}'),rc=$RC" >&2
exit $RC
