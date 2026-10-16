#!/bin/sh
export EXP_ROOT_VK_SAVE=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m1/meas/runs/bloom_avx2_1/root_vk.bin
exec /home/binbin/six-repro-verify/round-shared/home-r3cold/target-avx2/release/examples/exp_compose "$@"
