# Quiet-box gate for TIMED runs (sourced).
#   quiet := 1-minute load <= GATE_MAX_LOAD (default: CPUs / 8, i.e. 8 on a 64-thread box; 2 below 16 CPUs)
#            AND no r0vm / exp_compose / procs-engine worker / cargo / rustc of ANY user
#            AND < GATE_MAX_BUSY (default 4) cores busy over a 2 s /proc/stat window.
# Polls every 30 s for up to GATE_WAIT_S (default 1800 s); then the run starts anyway and its
# row records gate=busy:<why>. GATE_WAIT_S=0 checks once and never waits (smoke runs).
# Sets GATE_L0, GATE_WAITED_S, GATE_BUSY, GATE_WHY. Only reads /proc; never signals anything.
GATE_NCPU=$(grep -c '^cpu[0-9]' /proc/stat)
GATE_MAX_LOAD=${GATE_MAX_LOAD:-$(( GATE_NCPU >= 16 ? GATE_NCPU / 8 : 2 ))}
GATE_MAX_BUSY=${GATE_MAX_BUSY:-4}
GATE_WAIT_S=${GATE_WAIT_S:-1800}

busy_cores() {  # cores busy over a 2 s window, from /proc/stat (all CPUs, whatever our affinity)
  local a b
  read -r -a a < /proc/stat
  sleep 2
  read -r -a b < /proc/stat
  local busy=$(( (b[1]-a[1]) + (b[2]-a[2]) + (b[3]-a[3]) + (b[6]-a[6]) + (b[7]-a[7]) + (b[8]-a[8]) ))
  local idle=$(( (b[4]-a[4]) + (b[5]-a[5]) ))
  awk -v b="$busy" -v i="$idle" -v nc="$GATE_NCPU" 'BEGIN{printf "%.1f", (b+i) ? nc*b/(b+i) : 0}'
}

heavy_procs() {  # heavy processes of ANY user (process-name matches, never -f)
  local out=""
  if pgrep -x r0vm >/dev/null 2>&1; then out+="r0vm($(pgrep -x r0vm | wc -l)) "; fi
  if pgrep -x exp_compose >/dev/null 2>&1; then out+="exp_compose "; fi
  if pgrep '^zks_dc_exe_' >/dev/null 2>&1; then out+="zks_dc_exe "; fi
  if pgrep -x cargo >/dev/null 2>&1; then out+="cargo "; fi
  if pgrep -x rustc >/dev/null 2>&1; then out+="rustc "; fi
  echo -n "$out"
}

gate_settings() {  # one line for logs / the manifest
  echo "GATE_MAX_LOAD=$GATE_MAX_LOAD GATE_MAX_BUSY=$GATE_MAX_BUSY GATE_WAIT_S=$GATE_WAIT_S (cpus=$GATE_NCPU)"
}

gate() {
  local t0=$SECONDS last=-1000 hp
  GATE_BUSY=NA
  while :; do
    GATE_L0=$(cut -d' ' -f1 /proc/loadavg)
    hp=$(heavy_procs)
    GATE_WAITED_S=$((SECONDS - t0))
    if awk -v l="$GATE_L0" -v m="$GATE_MAX_LOAD" 'BEGIN{exit !(l <= m)}' && [[ -z $hp ]]; then
      GATE_BUSY=$(busy_cores)
      if awk -v b="$GATE_BUSY" -v m="$GATE_MAX_BUSY" 'BEGIN{exit !(b < m)}'; then GATE_WHY=quiet; return 0; fi
      hp="busy_cores=$GATE_BUSY"
    fi
    if (( GATE_WAITED_S >= GATE_WAIT_S )); then GATE_WHY="busy:load1=$GATE_L0;$hp"; return 1; fi
    if (( SECONDS - last >= 300 )); then
      echo "gate: waiting for a quiet box (load1=$GATE_L0 > $GATE_MAX_LOAD or: $hp); up to ${GATE_WAIT_S}s, then runs anyway" >&2
      last=$SECONDS
    fi
    sleep 30
  done
}
