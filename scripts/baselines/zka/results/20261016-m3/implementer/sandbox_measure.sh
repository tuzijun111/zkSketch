#!/bin/bash
# M3 sandbox measurement: build exp_compose at branch m3-gk-stable with the
# sandbox's fresh toolchains, then GK config B (cap 768, m_leaf 512, s 51,
# EXP_GK_ROUNDS=stable) through six/run_zks.sh (forest, procs, 1 machine x 32
# cores, AOL, a query after every leaf, ZK default build), sampling the summed
# VmRSS of the whole process tree every 0.1 s (memsample.py).
# usage: sandbox_measure.sh <out_dir> <T> [rounds] [tag]
set -u
SPD="$(cd "$(dirname "$0")" && pwd)"
export HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold
export PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"
export PATH="$HOME/.risc0/bin:$PATH"
unset CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR RISC0_HOME RUSTFLAGS
OUT=$1; T=$2; ROUNDS=${3:-stable}; TAG=${4:-t$T}
mkdir -p "$OUT"
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  git -C $HOME/zkSketch fetch -q /home/binbin/zkSketch m3-gk-stable && git -C $HOME/zkSketch checkout -q -B m3-gk-stable FETCH_HEAD || exit 3
  ( cd $HOME/zkSketch && time cargo build --release --locked --example exp_compose ) > "$OUT/build.log" 2>&1 || exit 4
fi
cd $HOME/zkSketch
{ git log --oneline -1; rustc --version; cargo --version; md5sum target/release/examples/exp_compose; } > "$OUT/commit_$TAG.txt"
R="$OUT/$TAG"
rm -rf "$R"; mkdir -p "$R"
echo "start $(date -Is) T=$T rounds=$ROUNDS load=\"$(cut -d' ' -f1-3 /proc/loadavg)\" memavail_gib=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo)" > "$OUT/status_$TAG.txt"
RESULTS=$R SIX_M=512 SIX_T=$T SIX_GK_CAP=768 SIX_GK_ROUNDS=$ROUNDS GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 \
  scripts/baselines/zka/six/run_zks.sh gk > "$OUT/run_$TAG.out" 2>&1 &
PID=$!
python3 "$SPD/memsample.py" $PID "$OUT/mem_$TAG.csv" 0.1 > "$OUT/memsample_$TAG.txt" 2>&1
wait $PID; rc=$?
echo "end $(date -Is) rc=$rc load=\"$(cut -d' ' -f1-3 /proc/loadavg)\"" >> "$OUT/status_$TAG.txt"
grep '^RSSTREE' "$R"/six_zksketch_gk.log >> "$OUT/status_$TAG.txt"
exit $rc
