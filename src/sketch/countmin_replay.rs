//! Count-Min `replay` leaf (baseline): per-record in-circuit hashing and one-hot routing
//! over a flat Poseidon2 commitment of all d·w cells.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
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
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::commitment::countmin::commit_countmin;
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::countmin::{CountMinState, CountMinUpdate};
use crate::sketch::countmin_final::{apply_update_prf, hash_cell_prf};

const LOG_FINAL_POLY_LEN: usize = 6;

// ─── Parameters ────────────────────────────────────────────────────────────

/// Shape of a replay (flat-commit) leaf: `d` rows of `w` counters, `batch`
/// records. `d·w` must be a multiple of 4 (Challenge packing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountMinReplayParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CountMinReplayParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    pub fn cell_packing(&self) -> usize {
        self.num_cells() / 4
    }
    pub fn validate(&self) {
        assert!(self.d >= 1 && self.d <= 8, "d must be in 1..=8, got {}", self.d);
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of two ≥ 2");
        assert!(self.batch >= 1, "batch must be positive");
        assert!(self.num_cells() % 4 == 0, "d·w must be a multiple of 4");
    }
}

// ─── Public proof type ──────────────────────────────────────────────────────

pub struct CountMinReplayProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: CountMinCommit,
    pub final_: CountMinCommit,
    pub batch_commit: CountMinCommit,
    pub params: CountMinReplayParams,
}

impl CountMinReplayProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

// ─── Prover ──────────────────────────────────────────────────────────────────

/// Prove one replay-update epoch (per-record in-circuit hashing) over a `d × w`
/// Count-Min state, committing the state flatly.
pub fn prove_countmin_replay_leaf(
    params: CountMinReplayParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinReplayProof {
    params.validate();
    let CountMinReplayParams { d, w, batch: m } = params;
    assert_eq!(initial_state.params.d, d, "state.d / params.d mismatch");
    assert_eq!(initial_state.params.w, w, "state.w / params.w mismatch");
    assert_eq!(batch.len(), m, "batch.len() != params.batch");
    let num_cells = params.num_cells();
    let cell_packing = params.cell_packing();
    let w_log2 = w.trailing_zeros() as usize;
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;

    // ─── Native side ─────────────────────────────────────────────────────────
    let mut final_state = initial_state.clone();
    for u in &batch {
        apply_update_prf(&mut final_state, u);
    }
    let initial_commit = commit_countmin(&initial_state);
    let final_commit = commit_countmin(&final_state);
    // Reduced keys (the PRF reduces to a BabyBear Val; one Challenge per key).
    let red_key: Vec<u64> =
        batch.iter().map(|u| Val::from_u64(u.key).as_canonical_u64()).collect();
    let batch_commit: [Val; 8] = {
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = batch
            .iter()
            .flat_map(|u| {
                [
                    Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO,
                    Val::from_u32(u.value), Val::ZERO, Val::ZERO, Val::ZERO,
                ]
            })
            .collect();
        hasher.hash_iter(flat.iter().copied())
    };

    // ─── Build circuit ───────────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // Public inputs: initial/final state commits + batch commit. Keys stay private.
    let initial_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let pow2: Vec<ExprId> =
        (0..w_log2).map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j")).collect();
    let j_consts: Vec<ExprId> =
        (0..w).map(|j| b.alloc_const(Challenge::from_u64(j as u64), "j")).collect();

    // ── Private witnesses (allocation order MUST match the value-push order) ──
    let key_coeff: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("key_coeff")).collect();
    let values: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("value")).collect();
    let key_h0: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("key_h0")).collect();
    let key_h1: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("key_h1")).collect();
    let initial_packed: Vec<ExprId> =
        (0..cell_packing).map(|_| b.alloc_private_input("init_cell_packed")).collect();
    let final_packed: Vec<ExprId> =
        (0..cell_packing).map(|_| b.alloc_private_input("final_cell_packed")).collect();
    // selectors[k][r][j]: one-hot over w cells for record k in row r.
    let selectors: Vec<Vec<Vec<ExprId>>> = (0..m)
        .map(|_| (0..d).map(|_| (0..w).map(|_| b.alloc_private_input("sel")).collect()).collect())
        .collect();

    // keys[k] = recompose(key_coeff[k]) — a WitnessChecks bus creator for the
    // key (which is otherwise fed only to hashes).
    let keys: Vec<ExprId> = (0..m)
        .map(|k| {
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_coeff[k], zero, zero, zero])
                .expect("recompose key")
        })
        .collect();

    // ── S1: open the batch commitment over interleaved (key, value) ──────────
    let mut batch_pre: Vec<ExprId> = Vec::with_capacity(2 * m);
    for k in 0..m {
        batch_pre.push(keys[k]);
        batch_pre.push(values[k]);
    }
    let hb = b.add_hash_slice(&cfg, &batch_pre, true).expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_commit_pis[i]);
    }

    // ── S2: flat state commitments (Poseidon2 over all d·w packed cells) ─────
    let digest_init = b.add_hash_slice(&cfg, &initial_packed, true).expect("hash initial");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], initial_commit_pis[i]);
    }
    let digest_final = b.add_hash_slice(&cfg, &final_packed, true).expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
    }
    let initial_cells: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose init"))
        .collect();
    let final_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose final"))
        .collect();
    assert_eq!(initial_cells.len(), num_cells);
    assert_eq!(final_cells.len(), num_cells);

    // ── S3: per-record PRF — derive pos_r = Poseidon2(key)[r] mod w in-circuit ─
    // This is the replay update's anti-forgery: the prover cannot choose the
    // cell, it is the hash of the (private) key.
    for k in 0..m {
        let hashed = b.add_hash_slice(&cfg, &[keys[k]], true).expect("hash key");
        b.connect(hashed[0], key_h0[k]);
        b.connect(hashed[1], key_h1[k]);
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(key_h0[k]).expect("decompose h0");
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(key_h1[k]).expect("decompose h1");
        for elem in 0..8 {
            let coeff = if elem < 4 { c0[elem] } else { c1[elem - 4] };
            let bits = b.decompose_to_bits::<Val>(coeff, Val::bits()).expect("bits");
            if elem < d {
                // pos = bottom w_log2 bits of digest element `elem`.
                let mut pos = zero;
                for j in 0..w_log2 {
                    pos = b.mul_add(bits[j], pow2[j], pos);
                }
                // selector validity for (record k, row elem): one-hot summing to
                // 1, with its weighted index equal to the derived position.
                let sel = &selectors[k][elem];
                let mut sum = zero;
                let mut weighted = zero;
                for j in 0..w {
                    let sm1 = b.sub(sel[j], one);
                    let chk = b.mul(sel[j], sm1);
                    b.connect(chk, zero);
                    sum = b.add(sum, sel[j]);
                    weighted = b.mul_add(sel[j], j_consts[j], weighted);
                }
                b.connect(sum, one);
                b.connect(weighted, pos);
            }
        }
    }

    // ── S4: flat state transition — final[i·w+j] = initial[...] + Σ_k sel·value ─
    for i in 0..d {
        for j in 0..w {
            let idx = i * w + j;
            let mut accum = initial_cells[idx];
            for k in 0..m {
                accum = b.mul_add(selectors[k][i][j], values[k], accum);
            }
            b.connect(accum, final_cells[idx]);
        }
    }

    let circuit = b.build().expect("build cm replay leaf circuit");

    // ─── Pack public + private values (same order as allocation) ─────────────
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&pack_commit_to_challenge(&initial_commit));
    public_inputs.extend_from_slice(&pack_commit_to_challenge(&final_commit));
    public_inputs.extend_from_slice(&pack_commit_to_challenge(&CountMinCommit(batch_commit)));

    let mut private_inputs: Vec<Challenge> = Vec::new();
    for &rk in &red_key {
        private_inputs.push(Challenge::from_u64(rk));
    }
    for u in &batch {
        private_inputs.push(Challenge::from_u32(u.value));
    }
    {
        use p3_field::BasedVectorSpace;
        let hasher = MyHash::new(make_perm());
        let digests: Vec<[Challenge; 2]> = batch
            .iter()
            .map(|u| {
                let input = [Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO];
                let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
                [
                    Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 coeffs"),
                    Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 coeffs"),
                ]
            })
            .collect();
        for dgt in &digests {
            private_inputs.push(dgt[0]);
        }
        for dgt in &digests {
            private_inputs.push(dgt[1]);
        }
    }
    private_inputs.extend_from_slice(&pack_cells_to_challenge(&initial_state));
    private_inputs.extend_from_slice(&pack_cells_to_challenge(&final_state));
    for k in 0..m {
        for r in 0..d {
            let pos = hash_cell_prf(r, batch[k].key, w);
            for j in 0..w {
                private_inputs.push(if j == pos { Challenge::ONE } else { Challenge::ZERO });
            }
        }
    }

    // ─── Run + prove ─────────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run cm replay circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false)];
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
        .expect("get_airs_and_degrees_with_prep (cm replay)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&dd| dd + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove cm replay");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify cm replay leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&dd| 1u64 << dd).sum(),
    });

    CountMinReplayProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit: CountMinCommit(batch_commit),
        params,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::countmin::CountMinParams;

    fn state(d: usize, w: usize, fill: impl Fn(usize, usize) -> u32) -> CountMinState {
        let counters = (0..d).map(|i| (0..w).map(|j| fill(i, j)).collect()).collect();
        CountMinState { counters, params: CountMinParams { d, w } }
    }

    /// Round-trip: the proof's final commit equals the native flat commit of the
    /// replayed state.
    fn check(proof: &CountMinReplayProof, initial: &CountMinState, batch: &[CountMinUpdate]) {
        let mut s = initial.clone();
        for u in batch {
            apply_update_prf(&mut s, u);
        }
        assert_eq!(proof.final_, commit_countmin(&s), "final commit");
        assert_eq!(proof.initial, commit_countmin(initial), "initial commit");
    }

    #[test]
    fn replay_min() {
        let params = CountMinReplayParams { d: 1, w: 8, batch: 2 };
        let initial = state(1, 8, |_, j| (j * 2 + 1) as u32);
        let batch = vec![
            CountMinUpdate { key: 5, value: 1 },
            CountMinUpdate { key: 9, value: 1 },
        ];
        let proof = prove_countmin_replay_leaf(params, initial.clone(), batch.clone());
        check(&proof, &initial, &batch);
    }

    #[test]
    fn replay_d_rows_repeats() {
        let params = CountMinReplayParams { d: 4, w: 16, batch: 4 };
        let initial = state(4, 16, |_, _| 0);
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let proof = prove_countmin_replay_leaf(params, initial.clone(), batch.clone());
        check(&proof, &initial, &batch);
    }
}
