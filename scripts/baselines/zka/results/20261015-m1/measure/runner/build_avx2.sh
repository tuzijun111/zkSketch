#!/usr/bin/env bash
R="$(cd "$(dirname "$0")" && pwd)"
. "$R/env.sh"
echo "# build_avx2 $(date -Is) head=$(git rev-parse --short=9 HEAD) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
export CARGO_TARGET_DIR=$HOME/target-avx2 RUSTFLAGS="-C target-cpu=x86-64-v3"
echo "# CARGO_TARGET_DIR=$CARGO_TARGET_DIR RUSTFLAGS=$RUSTFLAGS"
time cargo build --release --locked --example exp_compose
echo "rc=$?"
echo "# end $(date -Is)"
