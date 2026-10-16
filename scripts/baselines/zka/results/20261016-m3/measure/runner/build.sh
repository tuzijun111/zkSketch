#!/usr/bin/env bash
# build.sh: sync the sandbox clone to branch m3-gk-stable, build exp_compose + exp_e0 (release, --locked,
# default features = ZK, scalar) and the zk-Analytics side (six/run_all.sh build + check).
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
. "$R/env.sh"
{
git -C $HOME/zkSketch fetch -q /home/binbin/zkSketch m3-gk-stable && git -C $HOME/zkSketch checkout -q -B m3-gk-stable FETCH_HEAD || { echo "sync failed"; exit 3; }
echo "# build start $(date -Is) head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
rustc --version; cargo --version; r0vm --version
echo "# pre exp_compose md5=$(md5sum < target/release/examples/exp_compose | cut -c1-12) exp_e0 md5=$(md5sum < target/release/examples/exp_e0 | cut -c1-12)"
( time cargo build --release --locked --example exp_compose --example exp_e0 ) 2>&1 | tail -5; echo "# cargo rc=${PIPESTATUS[0]}"
echo "# post exp_compose md5=$(md5sum < target/release/examples/exp_compose | cut -c1-12) exp_e0 md5=$(md5sum < target/release/examples/exp_e0 | cut -c1-12)"
scripts/baselines/zka/six/run_all.sh build; echo "# run_all build rc=$?"
EB=$BASELINE_DIR/build
echo "# gk_matched md5=$(md5sum < $EB/zka-gk-matched/release/gk_matched | cut -c1-12) gk md5=$(md5sum < $EB/zka-gk/release/gk | cut -c1-12)"
for g in aggr_gkm querier_gkm; do echo "# elf $g md5=$(md5sum < $EB/zka-gk-matched/riscv-guest/gk-matched-methods/$g/riscv32im-risc0-zkvm-elf/release/$g | cut -c1-12)"; done
scripts/baselines/zka/six/run_all.sh check; echo "# check rc=$?"
echo "# exp_compose md5=$(md5sum < target/release/examples/exp_compose | cut -c1-12) (after run_all build)"
echo "# end $(date -Is)"
} > "$S/build.log" 2>&1
