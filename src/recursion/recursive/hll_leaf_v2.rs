//! §5.4-shaped HyperLogLog update leaf (Phase 4d).
//!
//! Mirror of `countmin_leaf_v2` for HLL: exposes the §5.4 per-register
//! aggregate table `A` as an explicit in-circuit witness vector, and
//! factors the transition into two steps:
//!
//!   - **Aggregate**: `A[r] = max(0, {selector[k][r] * lead[k] : k ∈ batch})`,
//!     i.e., the maximum leading-run statistic contributed by records that
//!     actually touch register `r`. Records not touching `r` collapse to 0
//!     (via `selector[k][r] = 0`).
//!   - **Sparse patch**: `final[r] = max(initial[r], A[r])`, a simple 2-way
//!     max that applies the aggregate to the prior register state.
//!
//! Compared to the §5.1 strawman in `hll_leaf.rs`, the constraints are
//! reorganised so the per-register transition reads `final = max(initial, A)`
//! instead of the unified `final = max(initial, {lead[k] : touching})` over
//! the joined candidate set. That makes the place where a future Appendix F
//! optimisation (wide-output Poseidon2, LogUp-routed selectors, batched
//! IPA/KZG multi-opening for the sparse patch) lands explicit.
//!
//! What this module **does not** do: reduce the witness count. The m
//! registers of both states still appear as private inputs because the
//! commitment is Poseidon2-of-flat-registers (same as v1). The genuine
//! §5.4 / Appendix F witness reduction needs either a batched IPA/KZG
//! multi-opening (so the patch verifies only touched registers via a
//! succinct opening) or a Merkle-tree register commitment with sparse
//! opens. Both are substantial follow-ups; this module is the structural
//! scaffold they would build on.
//!
//! The produced proof has the same public-inputs layout and
//! `HllLeafProof` shape as v1, so it plugs into the §4.2 `merge_two_hll`,
//! §4.3 `HllChainState::extend`, and §4.1 `flat_merge_two_hll` paths
//! without any changes — the `v2_leaf_merges_with_v1` test exercises that
//! cross-compatibility.

use std::rc::Rc;

use p3_batch_stark::ProverData;
use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::hyperloglog::commit_hll;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::hll_leaf::{
    BATCH, DIGEST_PACKING, HllLeafParams, HllLeafProof, REGISTER_WIDTH, make_leaf_config,
    pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::hyperloglog::{
    HyperLogLog, HyperLogLogState, HyperLogLogUpdate, hash_register,
};

/// FRI parameters — must equal the leaf-config's `LOG_FINAL_POLY_LEN = 6`
/// so a v2 leaf can chain with v1 leaves in the same recursive merge.
const LOG_FINAL_POLY_LEN: usize = 6;

/// Pack the flattened registers into Challenge elements (same layout as v1).
fn pack_registers_to_challenge(state: &HyperLogLogState) -> Vec<Challenge> {
    let flat: Vec<Val> = state
        .registers
        .iter()
        .map(|&r| Val::from_u32(r as u32))
        .collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Decompose a u8 register value into `REGISTER_WIDTH` little-endian bits.
fn bits_of(v: u8) -> [Challenge; REGISTER_WIDTH] {
    let mut out = [Challenge::ZERO; REGISTER_WIDTH];
    for i in 0..REGISTER_WIDTH {
        out[i] = if (v >> i) & 1 == 1 { Challenge::ONE } else { Challenge::ZERO };
    }
    out
}

/// Compute the per-register aggregate table `A` natively.
///
/// `A[r] = max over k of (lead[k] : selector[k][r] = 1)`, with the
/// convention that the empty max is 0 (no records touching register `r`).
fn build_aggregate(b: usize, batch: &[HyperLogLogUpdate]) -> Vec<u8> {
    let m = 1usize << b;
    let mut a = vec![0u8; m];
    for u in batch {
        let (idx, lr) = hash_register(b, u.key);
        if lr > a[idx] {
            a[idx] = lr;
        }
    }
    a
}

/// Prove one HyperLogLog update epoch using the §5.4-shaped v2 leaf.
///
/// Convenience wrapper at the default `(B, BATCH) = (3, 2)`.
pub fn prove_hll_leaf_v2(
    initial_state: HyperLogLogState,
    batch: [HyperLogLogUpdate; BATCH],
) -> HllLeafProof {
    let params = HllLeafParams::default();
    prove_hll_leaf_v2_with_params(params, initial_state, batch.to_vec())
}

/// Runtime-parameterised version. Same input contract as
/// `prove_hll_leaf_with_params` in v1; the resulting `HllLeafProof` is
/// verified by exactly the same downstream chains, merges and flat paths.
pub fn prove_hll_leaf_v2_with_params(
    params: HllLeafParams,
    initial_state: HyperLogLogState,
    batch: Vec<HyperLogLogUpdate>,
) -> HllLeafProof {
    params.validate();
    assert_eq!(initial_state.params.b, params.b);
    assert_eq!(batch.len(), params.batch);

    let m = params.m();
    let batch_size = params.batch;
    let cell_packing = params.cell_packing();

    let mut final_state = initial_state.clone();
    for u in &batch {
        HyperLogLog::update(&mut final_state, u);
    }
    let initial_commit = commit_hll(&initial_state);
    let final_commit = commit_hll(&final_state);
    let aggregate = build_aggregate(params.b, &batch);

    let mut b_c = CircuitBuilder::<Challenge>::new();
    b_c.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b_c.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // ---- Public inputs (identical to v1) ----
    let initial_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b_c.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b_c.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let mut record_pis: Vec<(ExprId, ExprId, ExprId)> = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let key = b_c.alloc_public_input("key");
        let reg = b_c.alloc_public_input("reg_idx");
        let lead = b_c.alloc_public_input("lead");
        record_pis.push((key, reg, lead));
    }

    // ---- Private inputs ----
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b_c.alloc_private_input("init_reg_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b_c.alloc_private_input("final_reg_packed"))
        .collect();

    // v2-specific: per-register aggregate vector A as explicit private witnesses.
    let agg: Vec<ExprId> = (0..m).map(|_| b_c.alloc_private_input("aggregate")).collect();

    // Selectors (one-hot per record).
    let mut selectors: Vec<Vec<ExprId>> = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let s: Vec<ExprId> = (0..m).map(|_| b_c.alloc_private_input("sel")).collect();
        selectors.push(s);
    }

    // Bit decomp witnesses for initial and final registers.
    let mut initial_bits: Vec<Vec<ExprId>> = Vec::with_capacity(m);
    let mut final_bits: Vec<Vec<ExprId>> = Vec::with_capacity(m);
    for _ in 0..m {
        let ib: Vec<ExprId> = (0..REGISTER_WIDTH)
            .map(|_| b_c.alloc_private_input("init_bit"))
            .collect();
        let fb: Vec<ExprId> = (0..REGISTER_WIDTH)
            .map(|_| b_c.alloc_private_input("final_bit"))
            .collect();
        initial_bits.push(ib);
        final_bits.push(fb);
    }

    // Bit decomp witnesses for the agg-side range checks: per (r, k_or_zero),
    // (agg[r] - agg_candidate[k_or_zero]) ∈ [0, 64). Candidates count: 1 ("zero baseline") + batch_size (per-record lead contributions).
    let agg_candidates_per_r = batch_size + 1;
    let mut agg_diff_bits: Vec<Vec<Vec<ExprId>>> =
        vec![vec![vec![]; agg_candidates_per_r]; m];
    for r in 0..m {
        for c in 0..agg_candidates_per_r {
            agg_diff_bits[r][c] = (0..REGISTER_WIDTH)
                .map(|_| b_c.alloc_private_input("agg_diff_bit"))
                .collect();
        }
    }

    // Bit decomp witnesses for the patch-side range checks: per r,
    // (final[r] - initial[r]) ∈ [0, 64) and (final[r] - agg[r]) ∈ [0, 64).
    let patch_candidates_per_r = 2;
    let mut patch_diff_bits: Vec<Vec<Vec<ExprId>>> =
        vec![vec![vec![]; patch_candidates_per_r]; m];
    for r in 0..m {
        for c in 0..patch_candidates_per_r {
            patch_diff_bits[r][c] = (0..REGISTER_WIDTH)
                .map(|_| b_c.alloc_private_input("patch_diff_bit"))
                .collect();
        }
    }

    // ---- Constraints ----

    let one = b_c.alloc_const(Challenge::ONE, "one");
    let zero = b_c.alloc_const(Challenge::ZERO, "zero");

    // 1. Hash packed initial / final.
    let digest_init = b_c
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &initial_packed, true)
        .expect("add_hash_slice(initial)");
    for i in 0..DIGEST_PACKING {
        b_c.connect(digest_init[i], initial_commit_pis[i]);
    }
    let digest_final = b_c
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("add_hash_slice(final)");
    for i in 0..DIGEST_PACKING {
        b_c.connect(digest_final[i], final_commit_pis[i]);
    }

    // Decompose packed registers.
    let initial_regs: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| b_c.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    let final_regs: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| b_c.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();

    let r_consts: Vec<ExprId> = (0..m)
        .map(|r| b_c.alloc_const(Challenge::from_u64(r as u64), "r"))
        .collect();
    let pow2: Vec<ExprId> = (0..REGISTER_WIDTH)
        .map(|i| b_c.alloc_const(Challenge::from_u64(1u64 << i), "pow2"))
        .collect();

    // 2. Selector validity. Same as v1: boolean check via (1-s)*s = 0,
    //    sum_r(s[r]) == 1, sum_r(s[r] * r) == register_idx_k.
    for k in 0..batch_size {
        let s = &selectors[k];
        for &sr in s {
            let one_minus = b_c.sub(one, sr);
            let prod = b_c.mul(one_minus, sr);
            b_c.connect(prod, zero);
        }
        let mut sum = s[0];
        for r in 1..m {
            sum = b_c.add(sum, s[r]);
        }
        b_c.connect(sum, one);

        let mut weighted = zero;
        for r in 0..m {
            let term = b_c.mul(s[r], r_consts[r]);
            weighted = b_c.add(weighted, term);
        }
        b_c.connect(weighted, record_pis[k].1);
    }

    // 3. Bit decomp + range check for initial[r] and final[r].
    for r in 0..m {
        for &bit in &initial_bits[r] {
            let one_minus = b_c.sub(one, bit);
            let prod = b_c.mul(one_minus, bit);
            b_c.connect(prod, zero);
        }
        let mut sum = b_c.mul(initial_bits[r][0], pow2[0]);
        for i in 1..REGISTER_WIDTH {
            let term = b_c.mul(initial_bits[r][i], pow2[i]);
            sum = b_c.add(sum, term);
        }
        b_c.connect(sum, initial_regs[r]);

        for &bit in &final_bits[r] {
            let one_minus = b_c.sub(one, bit);
            let prod = b_c.mul(one_minus, bit);
            b_c.connect(prod, zero);
        }
        let mut sum = b_c.mul(final_bits[r][0], pow2[0]);
        for i in 1..REGISTER_WIDTH {
            let term = b_c.mul(final_bits[r][i], pow2[i]);
            sum = b_c.add(sum, term);
        }
        b_c.connect(sum, final_regs[r]);
    }

    // 4. §5.4 segment-aggregation per register r:
    //    A[r] = max(0, {selector[k][r] * lead[k] : k ∈ batch})
    //    Candidates: agg_candidate[0] = 0, agg_candidate[k+1] = s[k][r] * lead[k].
    //    Constraint: Π(A[r] - agg_candidate_i) = 0 AND each (A[r] - agg_candidate_i) is
    //    a non-negative REGISTER_WIDTH-bit integer (range check).
    for r in 0..m {
        let mut agg_candidates: Vec<ExprId> = Vec::with_capacity(agg_candidates_per_r);
        agg_candidates.push(zero); // baseline candidate: 0 (empty-max).
        for k in 0..batch_size {
            let s_kr = selectors[k][r];
            let lead = record_pis[k].2;
            let contrib = b_c.mul(s_kr, lead);
            agg_candidates.push(contrib);
        }

        // Π(A[r] - agg_candidate_i) = 0
        let mut factors: Vec<ExprId> = Vec::with_capacity(agg_candidates_per_r);
        for c in &agg_candidates {
            factors.push(b_c.sub(agg[r], *c));
        }
        let prod = b_c.mul_many(&factors);
        b_c.connect(prod, zero);

        // Range check: each (A[r] - agg_candidate_i) in [0, 64).
        for c_idx in 0..agg_candidates_per_r {
            let diff = b_c.sub(agg[r], agg_candidates[c_idx]);
            for &bit in &agg_diff_bits[r][c_idx] {
                let one_minus = b_c.sub(one, bit);
                let prod = b_c.mul(one_minus, bit);
                b_c.connect(prod, zero);
            }
            let mut sum = b_c.mul(agg_diff_bits[r][c_idx][0], pow2[0]);
            for i in 1..REGISTER_WIDTH {
                let term = b_c.mul(agg_diff_bits[r][c_idx][i], pow2[i]);
                sum = b_c.add(sum, term);
            }
            b_c.connect(sum, diff);
        }
    }

    // 5. §5.4 sparse-patch application per register r:
    //    final[r] = max(initial[r], A[r])
    //    Candidates: patch_candidate[0] = initial[r], patch_candidate[1] = A[r].
    //    Constraint: (final[r] - initial[r]) * (final[r] - A[r]) = 0
    //    Range: (final[r] - initial[r]) and (final[r] - A[r]) in [0, 64).
    for r in 0..m {
        let patch_candidates = [initial_regs[r], agg[r]];
        // Product
        let mut factors: Vec<ExprId> = Vec::with_capacity(patch_candidates_per_r);
        for c in &patch_candidates {
            factors.push(b_c.sub(final_regs[r], *c));
        }
        let prod = b_c.mul_many(&factors);
        b_c.connect(prod, zero);

        // Range
        for c_idx in 0..patch_candidates_per_r {
            let diff = b_c.sub(final_regs[r], patch_candidates[c_idx]);
            for &bit in &patch_diff_bits[r][c_idx] {
                let one_minus = b_c.sub(one, bit);
                let prod = b_c.mul(one_minus, bit);
                b_c.connect(prod, zero);
            }
            let mut sum = b_c.mul(patch_diff_bits[r][c_idx][0], pow2[0]);
            for i in 1..REGISTER_WIDTH {
                let term = b_c.mul(patch_diff_bits[r][c_idx][i], pow2[i]);
                sum = b_c.add(sum, term);
            }
            b_c.connect(sum, diff);
        }
    }

    let circuit = b_c.build().expect("build v2 leaf circuit");

    // ---- Pack public + private values and run the circuit ----
    let initial_commit_packed = pack_commit_to_challenge(&initial_commit);
    let final_commit_packed = pack_commit_to_challenge(&final_commit);

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&initial_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    let mut record_meta: Vec<(usize, u8)> = Vec::with_capacity(batch_size);
    for u in &batch {
        let (idx, lr) = hash_register(params.b, u.key);
        public_inputs.push(Challenge::from_u64(u.key));
        public_inputs.push(Challenge::from_u64(idx as u64));
        public_inputs.push(Challenge::from_u32(lr as u32));
        record_meta.push((idx, lr));
    }

    let initial_regs_packed = pack_registers_to_challenge(&initial_state);
    let final_regs_packed = pack_registers_to_challenge(&final_state);
    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&initial_regs_packed);
    private_inputs.extend_from_slice(&final_regs_packed);

    // Aggregate vector A in register order.
    for &a in &aggregate {
        private_inputs.push(Challenge::from_u32(a as u32));
    }

    // Selectors.
    for k in 0..batch_size {
        let (idx, _lr) = record_meta[k];
        for r in 0..m {
            private_inputs.push(if r == idx { Challenge::ONE } else { Challenge::ZERO });
        }
    }

    // initial_bits[r], final_bits[r].
    for r in 0..m {
        for &bit in &bits_of(initial_state.registers[r]) {
            private_inputs.push(bit);
        }
        for &bit in &bits_of(final_state.registers[r]) {
            private_inputs.push(bit);
        }
    }

    // agg_diff_bits[r][c]: A[r] - agg_candidate[c].
    for r in 0..m {
        // Reconstruct the candidates for this register in the SAME order as the circuit.
        let mut candidates_v: Vec<u8> = Vec::with_capacity(agg_candidates_per_r);
        candidates_v.push(0); // baseline
        for k in 0..batch_size {
            let (idx, lr) = record_meta[k];
            let contrib = if idx == r { lr } else { 0 };
            candidates_v.push(contrib);
        }
        let agg_v = aggregate[r];
        for &cv in &candidates_v {
            let diff = agg_v.checked_sub(cv).expect("agg < candidate: invalid v2 transition");
            for &bit in &bits_of(diff) {
                private_inputs.push(bit);
            }
        }
    }

    // patch_diff_bits[r][c]: final[r] - {initial[r], A[r]}.
    for r in 0..m {
        let final_v = final_state.registers[r];
        let init_v = initial_state.registers[r];
        let agg_v = aggregate[r];
        for &cv in &[init_v, agg_v] {
            let diff = final_v.checked_sub(cv).expect("final < candidate: invalid v2 patch");
            for &bit in &bits_of(diff) {
                private_inputs.push(bit);
            }
        }
    }

    let traces = {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .expect("set_public_inputs");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set_private_inputs");
        runner.run().expect("run v2 circuit")
    };

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (hll v2)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (hll v2)");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify hll v2 leaf");

    HllLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch,
        params,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::hyperloglog::HyperLogLogParams;

    fn empty_state() -> HyperLogLogState {
        HyperLogLog::new(&HyperLogLogParams { b: crate::recursion::recursive::hll_leaf::B })
    }

    #[test]
    fn hll_v2_leaf_round_trip() {
        let initial = empty_state();
        let batch = [
            HyperLogLogUpdate { key: 0xDEAD_BEEF_0000_1111 },
            HyperLogLogUpdate { key: 0xC0FFEE_FACE_FACE },
        ];
        let leaf = prove_hll_leaf_v2(initial.clone(), batch);

        let mut expected = initial;
        for u in &batch {
            HyperLogLog::update(&mut expected, u);
        }
        let expected_commit = commit_hll(&expected);
        assert_eq!(leaf.final_.0, expected_commit.0);
        assert_eq!(leaf.batch.len(), BATCH);
    }

    /// A v2 HLL leaf must be a drop-in replacement for a v1 leaf in the §4.2
    /// recursive merge — same `HllLeafProof` shape, same `merge_two_hll`.
    #[test]
    fn hll_v2_leaf_merges_with_v1() {
        use crate::recursion::recursive::hll_leaf::prove_hll_leaf;
        use crate::recursion::recursive::hll_merge::{merge_two_hll, verify_chain_hll};

        let s0 = empty_state();
        let b1 = [
            HyperLogLogUpdate { key: 0x42 },
            HyperLogLogUpdate { key: 0x99 },
        ];
        let l1 = prove_hll_leaf_v2(s0.clone(), b1);

        let mut s1 = s0;
        for u in &b1 {
            HyperLogLog::update(&mut s1, u);
        }
        let b2 = [
            HyperLogLogUpdate { key: 0x4242 },
            HyperLogLogUpdate { key: 0x7 },
        ];
        // Second leaf via v1 to confirm interoperability.
        let l2 = prove_hll_leaf(s1, b2);

        let chain = merge_two_hll(&l1, &l2).expect("merge");
        verify_chain_hll(&chain).expect("verify");
    }
}
