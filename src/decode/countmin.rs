//! Count-Min **point-frequency** decode circuit (E3, plonky3/STARK).
//!
//! Proves `answer = release( min_i  S[i][ h_i(key) ] )` against a committed
//! Count-Min state `S`, where `h_i(key) = Poseidon2(key)[i] mod w` is derived
//! **in-circuit** (so the prover can't pick favourable cells). This mirrors the
//! plonky2 `decode::countmin` relation on the STARK backend, reusing the
//! `countmin_final` prove harness (Poseidon2 + Recompose, no Permute).
//!
//! Stages:
//! 1. Re-hash the `d·w` cells → bind to the committed digest (the `Θ(s)` cost).
//! 2. Derive the `d` query positions from `Poseidon2(key)`; select each row's
//!    cell via a one-hot selector bound to that position.
//! 3. Min gadget: `mn ≤ every selected cell` (range-checked diffs) and
//!    `∏(cell − mn) = 0` (so `mn` is one of them).
//! 4. Apply the release policy and bind the released value to the public answer.

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
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::countmin::commit_countmin;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::countmin::CountMinState;
use crate::sketch::countmin_final::hash_cell_prf;

const LOG_FINAL_POLY_LEN: usize = 6;
/// Range-check window for the min-gadget diffs. Counts fit in
/// `DIFF_BITS − 1` bits at prototype scale; a "negative" diff wraps past `2^p`
/// and overflows the check (sound min).
const DIFF_BITS: usize = 22;

#[derive(Copy, Clone, Debug)]
pub struct CmDecodeParams {
    pub d: usize,
    pub w: usize,
    pub release: ReleasePolicy,
}

impl CmDecodeParams {
    pub fn validate(&self) {
        assert!(self.d >= 1 && self.d <= 8, "d in 1..=8 (PRF rows), got {}", self.d);
        assert!(
            self.w.is_power_of_two() && (1..=16).contains(&self.w),
            "w power of 2 in {{2,4,8,16}}, got {}",
            self.w
        );
        assert!((self.d * self.w) % 4 == 0, "d·w must be a multiple of 4 (Challenge align)");
    }
}

/// Pack a Count-Min state's cells into Challenge elements (4 cells / Challenge),
/// matching `countmin_final`'s `pack_cells_to_challenge` and the committed digest.
fn pack_cells(state: &CountMinState) -> Vec<Challenge> {
    let flat: Vec<Val> = state.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Prove a Count-Min point-frequency decode. Returns a [`DecodeProof`]; the
/// prover self-verifies and records the witness/prove/verify split via
/// [`crate::recursion::recursive::timing`].
pub fn prove_cm_decode(params: CmDecodeParams, state: CountMinState, key: u64) -> DecodeProof {
    params.validate();
    let CmDecodeParams { d, w, release } = params;
    assert_eq!((state.params.d, state.params.w), (d, w), "state shape must match params");
    let num_cells = d * w;
    let cell_packing = num_cells / 4;
    let w_log2 = w.trailing_zeros() as usize;

    // ─── Native decode ───────────────────────────────────────────────────
    let commit = commit_countmin(&state);
    let mut vals_native: Vec<u32> = Vec::with_capacity(d);
    for i in 0..d {
        vals_native.push(state.counters[i][hash_cell_prf(i, key, w)]);
    }
    let mn = *vals_native.iter().min().unwrap();
    let answer = release.apply(mn as u64);

    // ─── Build circuit ───────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    // PIs: committed state, query key, released answer.
    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let query_key_pi = b.alloc_public_input("query_key");
    let answer_pi = b.alloc_public_input("answer");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let pow2: Vec<ExprId> =
        (0..w_log2).map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j")).collect();
    let col_idx: Vec<ExprId> =
        (0..w).map(|j| b.alloc_const(Challenge::from_u64(j as u64), "col")).collect();

    // Private witnesses.
    let cells_packed: Vec<ExprId> =
        (0..cell_packing).map(|_| b.alloc_private_input("cell_packed")).collect();
    let sel: Vec<Vec<ExprId>> = (0..d)
        .map(|_| (0..w).map(|_| b.alloc_private_input("sel")).collect())
        .collect();
    let mn_w = b.alloc_private_input("mn");
    let h0 = b.alloc_private_input("h0");
    let h1 = b.alloc_private_input("h1");
    let flag = if matches!(release, ReleasePolicy::Threshold(_)) {
        Some(b.alloc_private_input("flag"))
    } else {
        None
    };

    // ── Stage 1: open the committed state ──
    let digest = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, true)
        .expect("hash cells");
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }
    let cells: Vec<ExprId> = cells_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();

    // Bind `mn` to the base domain (coeffs 1..4 = 0) so the range checks below
    // are sound, and use the base coeff `mn_b` in all arithmetic (every
    // decompose output must flow through an ALU op — WitnessChecks discipline).
    // The query key needs no such binding: it is a verifier-supplied public
    // input that feeds the hash directly, so the prover has no freedom there.
    let mnc = b.decompose_ext_to_base_coeffs::<Val>(mn_w).unwrap();
    let mn_b = mnc[0];
    b.connect(mnc[1], zero);
    b.connect(mnc[2], zero);
    b.connect(mnc[3], zero);

    // ── Stage 2: derive positions h_i(key) and select cells ──
    let hashed = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &[query_key_pi], true)
        .expect("hash query key");
    b.connect(hashed[0], h0);
    b.connect(hashed[1], h1);
    let c0 = b.decompose_ext_to_base_coeffs::<Val>(h0).unwrap();
    let c1 = b.decompose_ext_to_base_coeffs::<Val>(h1).unwrap();
    let h_vals: [ExprId; 8] = [c0[0], c0[1], c0[2], c0[3], c1[0], c1[1], c1[2], c1[3]];

    let mut vals_expr: Vec<ExprId> = Vec::with_capacity(d);
    for i in 0..d {
        let bits = b.decompose_to_bits::<Val>(h_vals[i], Val::bits()).expect("bits h_val");
        let mut pos = b.mul(bits[0], pow2[0]);
        for jb in 1..w_log2 {
            let t = b.mul(bits[jb], pow2[jb]);
            pos = b.add(pos, t);
        }
        // one-hot selector over the w cells of row i.
        let row = &sel[i];
        let mut sum = zero;
        let mut idx_acc = zero;
        let mut val = zero;
        for j in 0..w {
            let sm1 = b.sub(row[j], one);
            let bchk = b.mul(row[j], sm1);
            b.connect(bchk, zero);
            sum = b.add(sum, row[j]);
            let it = b.mul(col_idx[j], row[j]);
            idx_acc = b.add(idx_acc, it);
            // Cell coeff goes FIRST (lhs) so this decompose-coeff gets a bus
            // creator (WitnessChecks: a coeff read only as rhs has no creator).
            let ct = b.mul(cells[i * w + j], row[j]);
            val = b.add(val, ct);
        }
        b.connect(sum, one);
        b.connect(idx_acc, pos);
        vals_expr.push(val);
    }
    // Consume the unused digest limbs (WitnessChecks discipline).
    for k in d..8 {
        let _ = b.decompose_to_bits::<Val>(h_vals[k], Val::bits()).expect("consume h_val");
    }

    // ── Stage 3: min gadget ──
    let mut prod = one;
    for &v in &vals_expr {
        let diff = b.sub(v, mn_b);
        let _ = b.decompose_to_bits::<Val>(diff, DIFF_BITS).expect("v - mn >= 0"); // range check
        prod = b.mul(prod, diff);
    }
    b.connect(prod, zero);

    // ── Stage 4: release policy → answer ──
    match release {
        ReleasePolicy::Identity => {
            // `mul(mn_b, one)` puts the `mn` coeff first (lhs) so it gets a bus
            // creator covering its rhs reads in the min gadget above.
            let released = b.mul(mn_b, one);
            b.connect(released, answer_pi);
        }
        ReleasePolicy::Threshold(t) => {
            let theta = b.alloc_const(Challenge::from_u64(t), "theta");
            let fl = flag.unwrap();
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            // chosen = fl·(mn−θ) + (1−fl)·(θ−mn−1) ≥ 0  ⇔  fl = [mn ≥ θ].
            let mn_minus_t = b.sub(mn_b, theta);
            let tm = b.sub(theta, mn_b);
            let t_minus_mn_m1 = b.sub(tm, one);
            let nf = b.sub(one, fl);
            let a = b.mul(fl, mn_minus_t);
            let nft = b.mul(nf, t_minus_mn_m1);
            let chosen = b.add(a, nft);
            let _ = b.decompose_to_bits::<Val>(chosen, DIFF_BITS).expect("chosen >= 0");
            let released = b.mul(fl, mn_b);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build cm decode circuit");

    // ─── Pack public + private values ────────────────────────────────────
    let commit_packed = pack_commit_to_challenge(&commit);
    let key_val = Val::from_u64(key);
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(
        Challenge::from_basis_coefficients_slice(&[key_val, Val::ZERO, Val::ZERO, Val::ZERO])
            .expect("4 base coeffs"),
    );
    public_inputs.push(Challenge::from_u64(answer));

    let mut private_inputs: Vec<Challenge> = pack_cells(&state);
    // sel[i][j]
    for i in 0..d {
        let pos = hash_cell_prf(i, key, w);
        for j in 0..w {
            private_inputs.push(if j == pos { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    // mn
    private_inputs.push(Challenge::from_u64(mn as u64));
    // h0, h1 (digest of the key)
    {
        let hasher = crate::config::MyHash::new(crate::config::make_perm());
        use p3_symmetric::CryptographicHasher;
        let input = [key_val, Val::ZERO, Val::ZERO, Val::ZERO];
        let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
        private_inputs
            .push(Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 coeffs"));
        private_inputs
            .push(Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 coeffs"));
    }
    // flag (threshold only)
    if flag.is_some() {
        let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
        private_inputs.push(if (mn as u64) >= t { Challenge::ONE } else { Challenge::ZERO });
    }

    // ─── Run + prove ─────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run cm decode circuit")
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
        .expect("get_airs_and_degrees_with_prep (cm decode)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove cm decode");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify cm decode");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    DecodeProof { output: RecursionOutput(proof, Rc::new(circuit_prover_data)), answer }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_final::apply_update_prf;

    fn state() -> CountMinState {
        let mut s = CountMin::new(&CountMinParams { d: 4, w: 8 });
        for k in [7u64, 7, 11, 7, 11, 3] {
            apply_update_prf(&mut s, &CountMinUpdate { key: k, value: 1 });
        }
        s
    }

    #[test]
    fn cm_decode_round_trip() {
        let p = CmDecodeParams { d: 4, w: 8, release: ReleasePolicy::Identity };
        let proof = prove_cm_decode(p, state(), 7);
        // Count-Min estimate of key 7 is an upper bound on its true count (3).
        assert!(proof.answer >= 3, "cm estimate >= true count, got {}", proof.answer);
    }

    #[test]
    fn cm_decode_threshold_suppresses() {
        let p = CmDecodeParams { d: 4, w: 8, release: ReleasePolicy::Threshold(1000) };
        let proof = prove_cm_decode(p, state(), 7);
        assert_eq!(proof.answer, 0, "estimate below θ ⇒ released 0");
    }
}
