#!/bin/bash
set -u
export HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold
export PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"
export PATH="$HOME/.risc0/bin:$PATH"
unset CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR RISC0_HOME RUSTFLAGS
OUT=$1
mkdir -p $OUT
git -C $HOME/zkSketch fetch -q /home/binbin/zkSketch m3-gk-stable && git -C $HOME/zkSketch checkout -q -B m3-gk-stable FETCH_HEAD || exit 3
cd $HOME/zkSketch
git log --oneline -1 > $OUT/commit.txt
rustc --version >> $OUT/commit.txt; cargo --version >> $OUT/commit.txt
( time cargo build --release --example exp_e0 ) > $OUT/build.log 2>&1 || exit 4
for v in sorted stable; do
  for cfg in "384 128" "768 256" "768 512" "384 1024" "768 1024"; do
    set -- $cfg
    EXP_GK_ROUNDS=$v E0_FAMILY=gk EXP_GK_CAP=$1 EXP_GK_S=51 E0_M=$2 timeout 600 ./target/release/examples/exp_e0 > $OUT/probe_${v}_c$1_m$2.log 2>&1
    echo "$v cap $1 m $2 exit $?" >> $OUT/status.txt
  done
done
# one ZK no-op prove per (variant, shape) on cores 0-31 (memmatch convention), small shapes only for sorted
for run in "stable 768 512" "stable 384 128" "sorted 384 128"; do
  set -- $run
  uptime >> $OUT/status.txt
  EXP_GK_ROUNDS=$1 E0_PROVE=1 E0_FAMILY=gk EXP_GK_CAP=$2 EXP_GK_S=51 E0_M=$3 /usr/bin/time -v taskset -c 0-31 timeout 600 ./target/release/examples/exp_e0 > $OUT/prove_$1_c$2_m$3.log 2>&1
  echo "prove $1 cap $2 m $3 exit $?" >> $OUT/status.txt
done
cp results/e0_tables.csv results/e0_summary.csv $OUT/ 2>/dev/null
echo DONE >> $OUT/status.txt
