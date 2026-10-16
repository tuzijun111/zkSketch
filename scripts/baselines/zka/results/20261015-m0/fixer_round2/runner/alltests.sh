#!/usr/bin/env bash
R=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0fix/run_tests.sh
F=(plain_vk_pins dist_root_vk_derivable inproc_workers_ hiding_end_to_end_cm_omc hiding_end_to_end_gk_bandmerge2 hiding_end_to_end_bloom_omc derived_root_vks_match cm_query_prefix_certified_by_live_peaks cm_honest_forest_chain_dist m0_ audit:: procs_query_replay)
$R rss_on on test:m0_rss_trim --nocapture
$R lib_on on lib "${F[@]}" metrics:: --nocapture
$R lib_off off lib "${F[@]}" --nocapture
echo ALLDONE > /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0fix/tests_done.txt
