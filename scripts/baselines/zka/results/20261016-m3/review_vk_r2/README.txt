VK / ZK / regression review, round 2, of branch m3-gk-stable at 3b5e499 (base 23138f7).
Tests ran in the worktree (clean HEAD binary, before another agent's uncommitted test-only edit) and in
scratch exports of 23138f7 and 3b5e499 with their own CARGO_TARGET_DIR.
r1_zk_lib.log           zk: pins (old + new), deployed byte-identity, genesis/encodings, decoder, derivation, e2e auditor, hiding budget, overflow: 29/29
r2_zk_logup.log         zk: tests/zk_logup_blinding.rs 4/4 (stable leaf 31 + 38 interactions, all fresh, every bus zero)
r4_nozk_pins.log        non-zk: plain_vk_pins incl. stable twins + add_range_bits fork checks 9/9
r4b_nozk_logup.log      non-zk control: sums repeat (31/31, 38/38), replay finds the secret key
p2_base.log             probe on base export (78 fingerprints; the round-1 48 reproduce exactly)
p2_head_sorted.log      probe on HEAD export, EXP_GK_ROUNDS=sorted, rebuilt (887 filtered): == base, all 78
p2_head_sorted.INVALID_base_binary.log  NOT a HEAD run: shared target + git-archive mtimes reused the base binary
p2_head_stable.log      probe on HEAD, stable: == round-1 353981e stable values (no drift)
p2_head_extra.log       stable/sorted leaf table heights (zk-extended domain = 2x padded; min padded 512 >= 128 budget);
                        derived (no-op) leaf VK == builder VK at cap4/m4, cap16/m8, cap768/m512 (stable)
r5a_gk_regress.log      HEAD export zk: old GK tests, stable_attacks, fork_soundness, stable tests: 79 ok, 4 ignored (overhead benches)
r5b_gl_regress.log      HEAD export zk: Goldilocks GK module + cross-module apply_batch2 callers: 22 ok, 1 ignored
r6_build_examples.log   exp_compose, exp_e0, exp_e1, exp_decode and tests/staged_queries compile at HEAD
knob/                   exp_compose sim runs: unset -> stable, sorted, bogus -> panic before work, legacy -> sorted
