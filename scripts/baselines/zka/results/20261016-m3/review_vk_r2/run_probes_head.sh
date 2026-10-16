#!/bin/bash
# Round-2 head probes (sources touched so the shared target rebuilds HEAD).
S=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m3rev_vk_r2
set -u
export CARGO_TARGET_DIR=$S/zk_target
U="env -u EXP_GK_ROUNDS -u ZKSKETCH_BINDING -u EXP_ROOT_VK -u ZKSKETCH_COMMIT"
cd $S/head_export && ( time $U EXP_GK_ROUNDS=sorted timeout 590 cargo test --release --lib -- m3rev_probe --nocapture ) > $S/logs/p2_head_sorted.log 2>&1; echo "EXIT $?" >> $S/logs/p2_head_sorted.log
cd $S/head_export && ( time $U EXP_GK_ROUNDS=stable timeout 590 cargo test --release --lib -- m3rev_probe::m3rev_small m3rev_probe::m3rev_deployed --nocapture ) > $S/logs/p2_head_stable.log 2>&1; echo "EXIT $?" >> $S/logs/p2_head_stable.log
cd $S/head_export && ( time $U timeout 590 cargo test --release --lib -- m3rev2_head --nocapture ) > $S/logs/p2_head_extra.log 2>&1; echo "EXIT $?" >> $S/logs/p2_head_extra.log
echo ALLDONE > $S/logs/probes_head.done
