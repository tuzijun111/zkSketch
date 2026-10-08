# Sourced by gk_bm2_exec.sh. Reuses ../common.sh for locations (ZKS, BASELINE_DIR,
# RESULTS, PATH) and adds the gk_bm2 build. Nothing here needs the zk-Analytics clone:
# this arm runs zkSketch's own GK transition, not their pipeline.
GKB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$GKB_DIR/../common.sh"
GKB_TARGET="$BASELINE_DIR/build/zka-gk-bm2"
GKB_BIN="$GKB_TARGET/release/gk_bm2"
KEYS=${KEYS:-$ZKS/data/aol.keys}
OUT=${OUT:-$RESULTS/zka_gk_bm2_exec.csv}
CHECK_OUT=${CHECK_OUT:-$RESULTS/zka_gk_bm2_check.csv}

# Host resolves from gk_bm2/Cargo.lock (seeded from ../gk/Cargo.lock: risc0-zkvm 3.0.6,
# plus the zkSketch crate's dependencies); RISC0_BUILD_LOCKED=1 makes risc0-build's
# nested guest build honour gk_bm2/guests/Cargo.lock (seeded from
# ../gk/guests/Cargo.lock: risc0-zkvm 3.0.5, no third-party version changed).
build_gk_bm2() {
  ( cd "$GKB_DIR" && CARGO_TARGET_DIR="$GKB_TARGET" RISC0_BUILD_LOCKED=1 cargo build --release --locked --bin gk_bm2 )
}

gkb_elf() { echo "$GKB_TARGET/riscv-guest/gk-bm2-methods/gk_bm2_step/riscv32im-risc0-zkvm-elf/release/gk_bm2_step"; }

# gkb_preflight <logs...>: refuse dev mode, build (unless SKIP_BUILD=1), write the log
# headers (one per CSV) with everything the rows depend on. The key file is logged
# relative to the zkSketch checkout when it lies inside it.
gkb_preflight() {
  case "${RISC0_DEV_MODE:-}" in ""|0|false|no|off) ;; *) echo "RISC0_DEV_MODE is set; refusing" >&2; exit 2;; esac
  [[ -s $KEYS ]] || { echo "missing $KEYS (dataset; run scripts/fetch_datasets.py)" >&2; exit 2; }
  if [[ ${SKIP_BUILD:-0} != 1 ]]; then
    build_gk_bm2 >&2 || { echo "build failed" >&2; exit 2; }
  fi
  [[ -x $GKB_BIN ]] || { echo "missing $GKB_BIN -- run without SKIP_BUILD" >&2; exit 2; }
  mkdir -p "$RESULTS"
  # Dirty count of the checkout, not counting the harness's results directories
  # (this runner's own CSVs and logs would otherwise change it within and between
  # runs); the source and reference md5s below pin what the rows depend on.
  local dirty pathspec=(. ":(exclude)${HERE#"$ZKS"/}/results")
  [[ $RESULTS == "$ZKS"/* ]] && pathspec+=(":(exclude)${RESULTS#"$ZKS"/}")
  dirty=$(git -C "$ZKS" status --porcelain -- "${pathspec[@]}" | wc -l)
  local log
  for log in "$@"; do
    {
      echo "# $(basename "$0") $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] nproc=$(nproc)"
      echo "# r0vm=$(r0vm --version 2>/dev/null) zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD) dirty_excl_results=[$dirty] keys=${KEYS#"$ZKS"/} md5=$(md5sum < "$KEYS" | cut -c1-12)"
      echo "# zkSketch reference: src/sketch/gk_bandmerge.rs md5=$(md5sum < "$ZKS/src/sketch/gk_bandmerge.rs" | cut -c1-12) src/experiments/stream_compose.rs md5=$(md5sum < "$ZKS/src/experiments/stream_compose.rs" | cut -c1-12) src/dataset.rs md5=$(md5sum < "$ZKS/src/dataset.rs" | cut -c1-12)"
      echo "# gk_bm2 sources: $(cd "$GKB_DIR" && find core host methods guests -name '*.rs' -o -name Cargo.toml -o -name Cargo.lock | sort | xargs md5sum | md5sum | cut -c1-12) (md5 of per-file md5s)"
      echo "# elf gk_bm2_step md5=$(md5sum < "$(gkb_elf)" | cut -d' ' -f1) bin md5=$(md5sum < "$(gkb_elf).bin" | cut -d' ' -f1)"
    } >> "$log"
  done
}

# gkb_run <csv> <log> <args...>: one driver invocation (one or more rows). Rows go to
# the CSV only if the driver exits 0 (every journal / state / merge / port check
# passed); a failing invocation keeps its rows in the log, marked [FAIL].
gkb_run() {
  local csv=$1 log=$2; shift 2
  echo "[run ] gk_bm2 $*" | tee -a "$log" >&2
  local out rc
  out=$("$GKB_BIN" "$@" --keys "$KEYS" 2>>"$log"); rc=$?
  [[ -n $out ]] && echo "$out" >> "$log"
  if [[ $rc -ne 0 || -z $out ]]; then echo "[FAIL] rc=$rc: $*" | tee -a "$log" >&2; return 1; fi
  echo "$out" >> "$csv"
  # variant,dataset,batching,epoch_index,capacity,s,actives_new,user_cycles,segments,
  # journal/state/merges/port_eq_native,MODELED_prove_s
  cut -d, -f4-7,9,11,18,26,28,44-47,50 <<< "$out" | sed 's/^/       -> /' >&2
}
