M2 implementer pass on branch m2-bloom-packed, commit 366fb79 (worktree .claude/worktrees/m2-bloom-packed), 2026-10-16.
Logs (zk default build unless noted; shared box, load 2-36):
  t1_bloom_packed.log        all `bloom_packed` lib tests before the dist_compose additions (35 pass)
  t2_pins.log                plain_vk_pins (5 pass; bloom_omc pins and packed pins unchanged)
  t3_bloom.log               bloom_omc / bit-array decoder / variant tests (37 pass)
  t4_zk.log                  tests/zk_logup_blinding packed_bloom (G-zk replay, 1 pass)
  t5_inproc5.log             old 5-case inproc_workers_ship_certificates_that_bind_queries_both_modes: >590 s, timed out (not a failure);
                             its five cases were then run one by one through the refactored helper (temporary per-case tests, not committed):
                             CmOmc 9.3 s, HllOmc 458.4 s, BloomOmc 205.4 s, GkBandmerge2 294.4 s, KmvSketch 429.9 s, all ok (1,397 s total)
  t6_final_bloom_packed.log  all `bloom_packed` lib tests at 366fb79 (37 pass)
  t7_nozk_pins.log           --no-default-features: plain_vk_pins + switch cleanliness (7 pass)
  exp_compose_refuse_*.txt   exp_compose exit 2: packed m = 9,363 (k·m >= 2^16), EXP_BLOOM_VARIANT=bogus
Also run (ok): inflated_genesis_rejected_by_the_anchor_check_bb (refactored, 168.5 s), _bloom_packed (25.0 s).
