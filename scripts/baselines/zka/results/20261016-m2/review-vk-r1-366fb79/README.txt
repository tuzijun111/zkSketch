VK / ZK / regression review, round 1, of branch m2-bloom-packed at 366fb79 (2026-10-16).
All runs on clean `git archive` snapshots of 62c20e2 (main) and 366fb79 (HEAD), each with its own
target dir (the shared worktree had another agent's uncommitted edits during the review).
  probe.rs                      reviewer probe (not committed): bloom_omc leaf VK (None/Boundary/Interval),
                                decoder VK, root VKs (forest2, chain3, dist3x2 over Boundary and Interval
                                leaves), Plain and Hiding, k=3 log_w=7 batch=4
  p_main.txt / p_head.txt       probe output, zk build: byte-identical (20 VKs)
  pn_main.txt / pn_head.txt     probe output, --no-default-features: byte-identical (20 VKs)
  pins_zk_snapshot.log          plain_vk_pins + check_switches_are_clean, zk: 7 pass
  pins_nozk.log                 the same plus hiding_budget_fits, non-zk: 8 pass
  t_bloom_packed.log            every lib test matching bloom_packed: 37 pass (123 s)
  t_bloom_omc.log               the other Bloom tests (bloom_omc, bit-array decoder, bloom_omc dist): 36 pass, 3 ignored (measure)
  t_harness.log                 bloom_variants_answer_identically, query_binding_rejects_mismatched_certificates,
                                commitment::hiding, genesis tests (incl. inflated_genesis_*_bb/_gl/_bloom_packed): 23 pass
  t_inproc.log                  inproc_workers_bind_packed_bloom_queries_both_modes: pass (181 s)
  t_zk.log                      tests/zk_logup_blinding.rs (all 5, incl. packed leaf None/Plain, Interval/Hiding, query/Hiding): pass
  shapes.log / query.log        deployed k=7 log_w=14 table shapes (m 256/1024/9362; query): every table >= 2^9, fits_hiding
  compose_*                     tiny exp_compose runs (sim forest+per_batch; procs forest+chain, 2 machines) with
                                EXP_BLOOM_VARIANT=packed: variant=bloom_packed, audit ok; token bloom_packed without the
                                env var -> env.json bloom_variant "omc" (minor provenance mismatch)
