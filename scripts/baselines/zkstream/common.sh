# Sourced by every script here. Mirrors ../zka/common.sh.
#
#   HERE          this directory (harness sources and results, tracked)
#   ZKS           the zkSketch checkout containing HERE
#   BASELINE_DIR  external clones and builds; default ~/ext-baselines, the same
#                 default as ../fetch_baselines.sh
#   ZSTREAM       zkStream clone @ 33c0d68f (read only; its stdlib idioms are the reference)
#   ZOK           ZoKrates 0.8.8 binary; ZOK_STDLIB its stdlib
#   BUILD         every ZoKrates artifact (.out .r1cs keys witnesses proofs), outside the repo
#   RESULTS       CSV/log destination; default results/ next to this file
# Paths are made absolute: the drivers cd into per-k build directories.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZKS="$(cd "$HERE/../../.." && pwd)"
BASELINE_DIR="$(realpath -m -- "${BASELINE_DIR:-$HOME/ext-baselines}")"
ZSTREAM="$BASELINE_DIR/zkstream-repo"
ZOK="${ZOK:-$BASELINE_DIR/zok/zokrates}"
ZOK_STDLIB="${ZOK_STDLIB:-$BASELINE_DIR/zok/stdlib}"
BUILD="$(realpath -m -- "${BUILD:-$BASELINE_DIR/build/zkstream}")"
RESULTS="$(realpath -m -- "${RESULTS:-$HERE/results}")"
export BASELINE_DIR ZOK ZOK_STDLIB BUILD RESULTS
export PATH="$HOME/.cargo/bin:$PATH"

# Both provers run on the same 32 hardware threads.
PIN_CPUS="${PIN_CPUS:-0-31}"
export PIN_CPUS RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-32}"

require_tools() {
  [[ -x $ZOK ]]         || { echo "missing $ZOK -- see ../fetch_baselines.sh" >&2; return 2; }
  [[ -d $ZOK_STDLIB ]]  || { echo "missing $ZOK_STDLIB" >&2; return 2; }
  [[ -x /usr/bin/time ]] || { echo "missing /usr/bin/time (needed for peak RSS)" >&2; return 2; }
  # every compile and zkSketch run is capped by `systemd-run --user --scope`
  systemd-run --user --scope -q true 2>/dev/null \
    || { echo "systemd-run --user --scope unavailable: needs a systemd user session (log in normally, or" \
              "loginctl enable-linger \$USER and export XDG_RUNTIME_DIR=/run/user/\$(id -u))" >&2; return 2; }
}

# Refuse to start next to another prover of this user: timings would be contended.
# Matches process NAMES (-x). `pgrep -f` would also match the invoking shell.
refuse_if_busy() {
  local p busy=""
  for p in zokrates exp_compose r0vm; do
    pgrep -u "$(id -u)" -x "$p" >/dev/null && busy="$busy $p"
  done
  [[ -z $busy ]] || { echo "refusing to start: running$busy" >&2; return 3; }
}
