#!/bin/bash
# Harness G-cap check: a GK run whose capacity overflows must be a FAILED run.
set -u
export HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold
export PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"
export PATH="$HOME/.risc0/bin:$PATH"
unset CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR RISC0_HOME RUSTFLAGS
OUT=$1; mkdir -p "$OUT"; cd $HOME/zkSketch
for rounds in stable sorted; do
  R=$OUT/overflow_$rounds; rm -rf "$R"; mkdir -p "$R"
  RESULTS=$R SIX_M=8 SIX_T=4 SIX_GK_CAP=8 SIX_GK_ROUNDS=$rounds GATE_WAIT_S=0 EXP_VERIFY_REPEATS=0 \
    scripts/baselines/zka/six/run_zks.sh gk > "$OUT/overflow_$rounds.out" 2>&1
  echo "rounds=$rounds run_zks_rc=$?" >> "$OUT/overflow_status.txt"
done
