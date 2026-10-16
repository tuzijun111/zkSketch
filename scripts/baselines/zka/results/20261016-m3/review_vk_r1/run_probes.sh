#!/bin/bash
# Reviewer probes: base (23138f7) vs head (353981e), zk; then head non-zk pins.
S=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m3rev_vk
set -u
cd $S/base_export && ( time CARGO_TARGET_DIR=$S/zk_target cargo test --release --lib -- m3rev_probe --nocapture ) > $S/logs/p_base.log 2>&1; echo rc=$? >> $S/logs/p_base.log
cd $S/head_export && ( time EXP_GK_ROUNDS=sorted CARGO_TARGET_DIR=$S/zk_target cargo test --release --lib -- m3rev_probe --nocapture ) > $S/logs/p_head_sorted.log 2>&1; echo rc=$? >> $S/logs/p_head_sorted.log
cd $S/head_export && ( time EXP_GK_ROUNDS=stable CARGO_TARGET_DIR=$S/zk_target cargo test --release --lib -- m3rev_probe --nocapture ) > $S/logs/p_head_stable.log 2>&1; echo rc=$? >> $S/logs/p_head_stable.log
cd $S/head_export && ( time CARGO_TARGET_DIR=$S/nozk_target cargo test --release --lib --no-default-features -- commitment::plain_vk_pins ) > $S/logs/p_head_nozk_pins.log 2>&1; echo rc=$? >> $S/logs/p_head_nozk_pins.log
echo ALLDONE > $S/logs/probes.done
