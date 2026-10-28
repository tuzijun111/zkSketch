#!/usr/bin/env bash
# Run a command and report the peak RSS of this user's r0vm processes (risc0 proves in r0vm, not in the caller).
# Usage: ./rss_watch.sh <label> <cmd...>
set -uo pipefail
LBL=${1:?usage: rss_watch.sh <label> <cmd...>}; shift
UID_=$(id -u)
# Match the PROCESS NAME (-x r0vm), never the full command line (-f 'r0vm --port').
# A -f pattern also matches the invoking shell whenever that shell's own command
# line happens to contain the pattern text -- which makes a guard misfire and,
# worse, makes a `pkill -9 -f 'r0vm --port'` kill the caller.
if pgrep -u "$UID_" -x r0vm >/dev/null 2>&1; then
  echo "REFUSING: one of OUR r0vm processes is already running. Let it finish." >&2
  echo "  (No r0vm was touched.)" >&2
  exit 3
fi
MAXF=$(mktemp); echo 0 > "$MAXF"
( while :; do
    for p in $(pgrep -u "$UID_" -x r0vm 2>/dev/null); do
      v=$(awk '/VmHWM/{print $2}' "/proc/$p/status" 2>/dev/null)
      [ -n "${v:-}" ] && [ "$v" -gt "$(cat "$MAXF")" ] && echo "$v" > "$MAXF"
    done
    sleep 0.5
  done ) & POLL=$!
cleanup(){ { kill -9 "$POLL"; wait "$POLL"; } 2>/dev/null; pkill -9 -u "$UID_" -x r0vm 2>/dev/null; }
trap cleanup EXIT INT TERM
T0=$(date +%s.%N)
"$@"; RC=$?
T1=$(date +%s.%N)
{ kill -9 "$POLL"; wait "$POLL"; } 2>/dev/null
KB=$(cat "$MAXF"); rm -f "$MAXF"
echo "RSSWATCH,$LBL,r0vm_peak_rss_mb=$(awk -v k="$KB" 'BEGIN{printf "%.1f", k/1024}'),wall_s=$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.1f", b-a}'),rc=$RC"
exit $RC
