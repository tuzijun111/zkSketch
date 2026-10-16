M2 packed Bloom, attack round 1 (attacker), branch m2-bloom-packed.
Tests: src/sketch/bloom_packed_attacks.rs (cargo test --release --lib -- bloom_packed::attacks::)
Deployed layout = Interval statement + Hiding commitments (family 7); query under Hiding.

final_testshape.log    12 tests at k=3, log_w=7 (batch 8; P24 batch 24 for the timestamp constant; P12 log_w=12 for the canonicity edge): 44 attack lines, 25.6 s, 0.2 GB
t_deployed3_leaf.log   every leaf attack at k=7, W=2^14, batch 16, 2,000-key prior: 28 attack lines, 88 s, 1.6 GB
t_deployed2_query.log  every query attack at k=7, W=2^14 (64 x 32 selector): 14 attack lines, 27 s, 0.4 GB
t_regress.log          sketch::bloom_packed:: + decode::bloom_packed:: + plain_vk_pins + decode::bloom:: : 52 pass, 1 ignored (measurement)
t_forge_users.log      commitment::hiding, statement, decode::tests, sketch::kmv: 39 pass
t_pipeline.log         transparency + A12 (first run)
Each ATTACK line: the control (one check off / the patched-constant circuit) ACCEPTED a wrong state or answer with 0 split wires and its own VK;
the deployed circuit REJECTED in the verifier: RangeBus / WitnessChecks / PermuteBus LogUp, or an AIR (OodEvaluationMismatch: leaf table 0 = Const, 2 = ALU, 5 = Range; query table 2 = ALU, 4 = Range).
