#!/usr/bin/env bash
# gated.sh <jobfile>: run each line "<kind zka|zks> <label> <args...>" one at a time. Before each run: 45 s
# cool-down, then gate.py wait (other users' busy cores < 6 for 60 s; up to MAXWAIT s). After each run, the
# window's other-user load is checked: mean > 6 busy cores => the run is CONTAMINATED, its directory is kept
# as CONTAM_<label>_try<k> and the run is repeated (at most 3 tries).
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
MAXWAIT=${MAXWAIT:-10800}
while read -r kind label rest; do
  [[ -z $kind || $kind == \#* ]] && continue
  for try in 1 2 3; do
    sleep 45
    echo "== $kind $label try=$try gate-wait start $(date -Is)"
    python3 -I "$R/gate.py" wait "${LOADCSV:-$S/load.csv}" "$MAXWAIT"; g=$?
    (( g == 0 )) || { echo "== $label: gate timeout, stopping the batch $(date -Is)"; exit 3; }
    echo "== $kind $label try=$try run start $(date -Is) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
    case $kind in
      zka) "$R/zka_prove.sh" "$label" $rest; base=$S/zka ;;
      zks) "$R/runzks.sh" "$label" $rest; base=$S/runs ;;
    esac
    m=$base/$label/meta.txt
    st=$(sed -n 's/^start=\(\S*\).*/\1/p' "$m"); en=$(sed -n 's/^end=\(\S*\).*/\1/p' "$m")
    w=$(python3 -I "$R/gate.py" window "${LOADCSV:-$S/load.csv}" "$st" "$en"); echo "$w" | tee -a "$m"
    om=$(sed -n 's/.*others_mean=\([0-9.]*\).*/\1/p' <<< "$w")
    if awk -v o="$om" 'BEGIN{exit !(o > 6)}'; then
      echo "== $label try=$try CONTAMINATED ($w)"; mv "$base/$label" "$base/CONTAM_${label}_try$try"
    else
      echo "== $label try=$try clean"; break
    fi
  done
done < "$1"
echo "== gated batch end $(date -Is)"
