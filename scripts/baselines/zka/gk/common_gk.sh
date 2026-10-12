# Sourced by gk_exec.sh and gk_prove_anchor.sh. Reuses ../common.sh for locations
# (ZKS, ZKA, BASELINE_DIR, RESULTS, PATH, link_zka) and adds the GK build.
GK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$GK_DIR/../common.sh"
GK_TARGET="$BASELINE_DIR/build/zka-gk"
GK_BIN="$GK_TARGET/release/gk"
KEYS=${KEYS:-$ZKS/data/aol.keys}
OUT=${OUT:-$RESULTS/zka_gk_exec.csv}
LOG=${OUT%.csv}.log

# Host resolves from gk/Cargo.lock (seeded from cyc/Cargo.lock, risc0-zkvm 3.0.6);
# RISC0_BUILD_LOCKED=1 makes risc0-build's nested guest build honour
# gk/guests/Cargo.lock (seeded from the clone's Cargo.lock, risc0-zkvm 3.0.5).
build_gk() {
  link_zka || return
  ( cd "$GK_DIR" && CARGO_TARGET_DIR="$GK_TARGET" RISC0_BUILD_LOCKED=1 cargo build --release --locked --bin gk )
}

gk_elf() { echo "$GK_TARGET/riscv-guest/gk-methods/$1/riscv32im-risc0-zkvm-elf/release/$1"; }

gk_preflight() {
  case "${RISC0_DEV_MODE:-}" in ""|0|false|no|off) ;; *) echo "RISC0_DEV_MODE is set; refusing" >&2; exit 2;; esac
  [[ -s $KEYS ]] || { echo "missing $KEYS (it is tracked in git; re-checkout data/aol.keys)" >&2; exit 2; }
  if [[ ${SKIP_BUILD:-0} != 1 ]]; then
    build_gk >&2 || { echo "build failed" >&2; exit 2; }
  fi
  [[ -x $GK_BIN ]] || { echo "missing $GK_BIN -- run without SKIP_BUILD" >&2; exit 2; }
  mkdir -p "$(dirname "$OUT")"
  local hdr; hdr=$("$GK_BIN" --header)
  if [[ ! -s $OUT ]]; then
    echo "$hdr" > "$OUT"
  elif [[ "$(head -n1 "$OUT")" != "$hdr" ]]; then
    echo "$OUT has a different header; move it away first (nothing written)" >&2; exit 2
  fi
  {
    echo "# $(basename "$0") $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] args=[$*]"
    echo "# zka=$(git -C "$ZKA" rev-parse --short=9 HEAD) dirty=[$(git -C "$ZKA" status --short | wc -l)] r0vm=$(r0vm --version 2>/dev/null) keys=$KEYS md5=$(md5sum < "$KEYS" | cut -c1-12)"
    echo "# gk sources: $(cd "$GK_DIR" && find core host methods guests -name '*.rs' -o -name Cargo.toml -o -name Cargo.lock | sort | xargs md5sum | md5sum | cut -c1-12) (md5 of per-file md5s)"
    for g in aggr_gk querier_gk aggr_gk_prof; do
      echo "# elf $g md5=$(md5sum < "$(gk_elf $g)" | cut -d' ' -f1)"
    done
  } >> "$LOG"
}

# run <args...>: one driver invocation -> one CSV row (appended) + raw log line.
# A failing run (journal != native, or a failed accuracy check: the driver exits 1)
# leaves its row in the log only, marked [FAIL], never in the CSV.
gk_run() {
  echo "[run ] gk $*" | tee -a "$LOG" >&2
  local line rc
  line=$("$GK_BIN" "$@" --keys "$KEYS" 2>>"$LOG"); rc=$?
  [[ -n $line ]] && echo "$line" >> "$LOG"
  if [[ $rc -ne 0 || -z $line ]]; then echo "[FAIL] rc=$rc: $*" | tee -a "$LOG" >&2; return 1; fi
  echo "$line" >> "$OUT"
  # arm,mode,query,epochs,epoch_index,user_cycles,segments,journal_eq_native,
  # abs_err..exact_in_cert,cert_over_eps_n,min_kept,q_sweep_1001,q_ok
  echo "       -> $(cut -d, -f2,3,6,9,10,17,19,24,27-34,36,37 <<< "$line")" >&2
}
