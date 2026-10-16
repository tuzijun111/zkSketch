#!/bin/bash
set -u
export HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold
export PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"
export PATH="$HOME/.risc0/bin:$PATH"
unset CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR RISC0_HOME RUSTFLAGS
OUT=$1; mkdir -p "$OUT"
git -C $HOME/zkSketch fetch -q /home/binbin/zkSketch m3-gk-stable && git -C $HOME/zkSketch checkout -q -B m3-gk-stable FETCH_HEAD || exit 3
cd $HOME/zkSketch
{ git log --oneline -1; rustc --version; cargo --version; } > "$OUT/commit.txt"
( time cargo build --release --locked --example exp_compose ) > "$OUT/build.log" 2>&1 || exit 4
md5sum target/release/examples/exp_compose >> "$OUT/commit.txt"
