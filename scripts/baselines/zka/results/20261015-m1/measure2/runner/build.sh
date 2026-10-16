#!/usr/bin/env bash
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
. "$R/env.sh"
{
echo "# build start $(date -Is) head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
echo "# pre exp_compose md5=$(md5sum < target/release/examples/exp_compose | cut -c1-12) avx2 md5=$(md5sum < $HOME/target-avx2/release/examples/exp_compose | cut -c1-12)"
scripts/baselines/zka/six/run_all.sh build; echo "# build rc=$?"
echo "# post exp_compose md5=$(md5sum < target/release/examples/exp_compose | cut -c1-12) avx2 md5=$(md5sum < $HOME/target-avx2/release/examples/exp_compose | cut -c1-12)"
EB=$BASELINE_DIR/build
echo "# gk_matched md5=$(md5sum < $EB/zka-gk-matched/release/gk_matched | cut -c1-12) gk md5=$(md5sum < $EB/zka-gk/release/gk | cut -c1-12)"
for g in aggr_gkm querier_gkm; do echo "# elf $g md5=$(md5sum < $EB/zka-gk-matched/riscv-guest/gk-matched-methods/$g/riscv32im-risc0-zkvm-elf/release/$g | cut -c1-12)"; done
scripts/baselines/zka/six/run_all.sh check; echo "# check rc=$?"
echo "# end $(date -Is)"
} > "$S/build.log" 2>&1
