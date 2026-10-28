//! Count-Min point-query decode: `answer = release(min_i S[i][h_i(key)])` against `Com(S)`.
//! The positions `h_i(key)` are computed in-circuit from `Poseidon2(key)`.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4, poseidon2_preprocessor,
        range_air_builders, range_preprocessor, recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::countmin::commit_countmin_with;
use crate::commitment::hiding::{self, CommitFamily, CommitKind, CommitMode, SaltBb};
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::decode::{DecodeProof, DecodeVk, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::expose_forest::vk_pin_values;
use crate::recursion::recursive::root_vk::bound_proof_shape;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::countmin::CountMinState;
use crate::sketch::bind::{self, Binding};
use crate::sketch::countmin_final::{hash_cell_prf_with, key_hash_input};

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
        // `w` must be a power of two: the in-circuit position is the low
        // `log2(w)` bits of the PRF digest, which equals `% w` only for powers
        // of two. This is the SAME derivation as the `countmin_final` leaf,
        // which already runs at arbitrary power-of-two `w`; the old `w ≤ 16`
        // cap here was a stale copy of the leaf's crude proxy. There is no fixed
        // upper bound — the real limit is the selector-cost guard below. (`w ≥ 2`
        // also because `w = 1` gives an empty `pow2`/position basis.)
        assert!(
            self.w.is_power_of_two() && self.w >= 2,
            "w must be a power of two ≥ 2, got {}",
            self.w
        );
        assert!((self.d * self.w) % 4 == 0, "d·w must be a multiple of 4 (Challenge align)");
        // Cost guard. The one-hot selector is `d × w` private witnesses — the
        // decode circuit's dominant cost. A single point query has no batch, so
        // this is far cheaper than the leaf's `batch·d·(d·w)`; still reject the
        // catastrophic case with a clean panic. Shares `COUNTMIN_MAX_SEL_CELLS`
        // with the leaf so one knob raises both.
        let sel_cells = self.d.saturating_mul(self.w);
        let max_sel = std::env::var("COUNTMIN_MAX_SEL_CELLS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(16_000_000);
        assert!(
            sel_cells <= max_sel,
            "selector budget exceeded: d·w = {sel_cells} > {max_sel} (d={}, w={}). \
             Reduce w, or raise COUNTMIN_MAX_SEL_CELLS (expect heavy RAM/time).",
            self.d,
            self.w
        );
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
    prove_cm_decode_with(params, state, key, bind::default_binding())
}

/// [`prove_cm_decode`] with an explicit [`Binding`].
///
/// [`Binding::Legacy`] is the pre-fix circuit, unchanged. It is unsound: the
/// cells are unbound from the commitment, the query-key sponge has a
/// prover-chosen IV, and the digest limbs are unbound from the digest, so
/// the answer and the positions are both free. It also exposes nothing, so
/// the verifier sees no answer. [`Binding::Bound`] (see
/// [`crate::sketch::bind`]) binds every cell (base pin + ALU recompose),
/// hashes with a zero IV, derives each position by a canonical split of an
/// ALU-bound digest limb, and surfaces `(commit, query_key, answer)` through
/// the Expose NPO (16 base values: commit[8], key[4], answer[4]).
///
/// Key encoding. `Semantic` and `Bound` take the query key as its four
/// exact 16-bit limbs `[k0, k1, k2, k3]` (each range-checked in-circuit, so
/// the exposed `key[4]` is the unique encoding of one 64-bit key) and hash
/// them, which is how the `omc` leaf routes a record under those bindings
/// ([`crate::sketch::countmin_final::key_hash_input`]). `Legacy` hashes
/// `[key mod p, 0, 0, 0]`, so keys congruent mod `p` read the same cells.
/// The decoder therefore answers point queries on states built with the
/// same binding's routing.
pub fn prove_cm_decode_with(
    params: CmDecodeParams,
    state: CountMinState,
    key: u64,
    binding: Binding,
) -> DecodeProof {
    prove_cm_decode_commit(params, state, key, binding, CommitMode::Plain, &SaltBb::ZERO)
}

/// [`prove_cm_decode_with`] against a commitment made under `mode` (revision
/// B2, [`crate::commitment::hiding`]). `Plain` is the pre-B2 circuit byte for
/// byte (`salt` ignored). Under `Hiding` the decoder opens
/// `Com(S_t; ρ) = commit_countmin_with(state, Hiding, salt)`: the salt is the
/// FIRST 3 private inputs, and (under `Semantic`/`Bound`) the exposed
/// commitment is the hiding one. For a query at version `t` of history `h`
/// the honest salt is `rho_state_bb_in(seed, CommitFamily::CountMin, h, t)`
/// (`rho_state_bb(seed, .., t)` in the genesis history), the same randomizer
/// leaf `t` closed its final state with; at `t = 0` it is the public zero in
/// the genesis history and the anchor salt in a continued one. So under
/// `Hiding` the public zero salt opens only the empty genesis state (the one
/// state commitment, `Com(S_0; 0)`, that the verifier recomputes itself):
/// handed [`SaltBb::ZERO`] with any other state (a forgotten salt at
/// `t ≥ 1`) the decoder panics instead of publishing the guess-checkable
/// `Com(S_t; 0)`. A nonzero wrong salt still proves (the circuit does not
/// check the derivation) and exposes a commitment that is not the log's.
pub fn prove_cm_decode_commit(
    params: CmDecodeParams,
    state: CountMinState,
    key: u64,
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> DecodeProof {
    let dc = build_cm_decode_commit(params, &state, key, binding, mode, salt);
    let __t_w = std::time::Instant::now();
    let traces = dc.run();
    let __witness = __t_w.elapsed();
    let __t_p = std::time::Instant::now();
    let proof = dc
        .prover
        .prove_all_tables(&traces, &dc.circuit_prover_data)
        .expect("prove cm decode");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    dc.prover.verify_all_tables(&proof).expect("self-verify cm decode");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: dc.trace_rows,
    });

    DecodeProof { output: RecursionOutput(proof, Rc::new(dc.circuit_prover_data)), answer: dc.answer }
}

/// A built decode circuit together with its witness and registered prover.
struct CmDecodeCircuit {
    circuit: p3_circuit::Circuit<Challenge>,
    public_inputs: Vec<Challenge>,
    private_inputs: Vec<Challenge>,
    answer: u64,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: CircuitProverData<ConfigWithFriParams>,
    trace_rows: u64,
}

impl CmDecodeCircuit {
    fn run(&self) -> p3_circuit::tables::Traces<Challenge> {
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&self.public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&self.private_inputs).expect("set_private_inputs");
        runner.run().expect("run cm decode circuit")
    }

    #[cfg(test)]
    fn prove_traces(
        &self,
        traces: &p3_circuit::tables::Traces<Challenge>,
    ) -> Result<p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>, String> {
        let proof = self
            .prover
            .prove_all_tables(traces, &self.circuit_prover_data)
            .map_err(|e| format!("prove: {e:?}"))?;
        self.prover.verify_all_tables(&proof).map_err(|e| format!("verify: {e:?}"))?;
        Ok(proof)
    }

    /// This circuit's VK (preprocessed commitment + proof metadata), read off
    /// a proof of its own honest witness.
    fn derive_vk(&self) -> DecodeVk {
        let proof = self
            .prover
            .prove_all_tables(&self.run(), &self.circuit_prover_data)
            .expect("prove cm decode (VK derivation)");
        self.prover.verify_all_tables(&proof).expect("self-verify cm decode (VK derivation)");
        DecodeVk { commitment: vk_pin_values(&proof), shape: Some(bound_proof_shape(&proof)) }
    }
}

/// The trusted VK of the Count-Min decode circuit at `params` and `binding`,
/// derived from public parameters only: the circuit is built over the empty
/// `d × w` state and key 0 (the cells are witnesses and the key a public
/// input, so neither shapes the circuit), proved once, and its preprocessed
/// commitment and metadata read off. A verifier pins every Count-Min query
/// proof to it with [`crate::decode::verify_decode_proof`], never to the VK
/// a proof carries. The Plain decoder's VK ([`cm_decode_vk_commit`] with
/// [`CommitMode::Plain`]).
pub fn cm_decode_vk(params: CmDecodeParams, binding: Binding) -> DecodeVk {
    cm_decode_vk_commit(params, binding, CommitMode::Plain)
}

/// [`cm_decode_vk`] of the decoder built under `mode` (revision B2): the
/// trusted VK of every [`prove_cm_decode_commit`] proof of that mode. `Plain`
/// is exactly [`cm_decode_vk`]; `Hiding` is derived over the empty state with
/// the public zero salt (the one state a `Hiding` decoder opens with it); the
/// salt is a witness, so every `Hiding` proof of the same parameters has this
/// VK.
pub fn cm_decode_vk_commit(params: CmDecodeParams, binding: Binding, mode: CommitMode) -> DecodeVk {
    use crate::sketch::Sketch;
    let empty = crate::sketch::countmin::CountMin::new(&crate::sketch::countmin::CountMinParams {
        d: params.d,
        w: params.w,
    });
    build_cm_decode_commit(params, &empty, 0, binding, mode, &SaltBb::ZERO).derive_vk()
}

#[cfg(test)]
fn build_cm_decode(
    params: CmDecodeParams,
    state: &CountMinState,
    key: u64,
    binding: Binding,
) -> CmDecodeCircuit {
    build_cm_decode_commit(params, state, key, binding, CommitMode::Plain, &SaltBb::ZERO)
}

fn build_cm_decode_commit(
    params: CmDecodeParams,
    state: &CountMinState,
    key: u64,
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> CmDecodeCircuit {
    params.validate();
    let bound = binding.is_bound();
    let CmDecodeParams { d, w, release } = params;
    assert_eq!((state.params.d, state.params.w), (d, w), "state shape must match params");
    if mode.is_hiding() && salt.is_zero() {
        assert!(
            state.counters.iter().flatten().all(|&c| c == 0),
            "Hiding CM decode: the public zero salt opens only the empty genesis state Com(S_0; 0); \
             a query at t >= 1 (or at version 0 of a continued history) needs its real salt"
        );
    }
    let num_cells = d * w;
    let cell_packing = num_cells / 4;
    let w_log2 = w.trailing_zeros() as usize;
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;

    // ─── Native decode ───────────────────────────────────────────────────
    let commit = commit_countmin_with(state, mode, salt);
    let mut vals_native: Vec<u32> = Vec::with_capacity(d);
    for i in 0..d {
        vals_native.push(state.counters[i][hash_cell_prf_with(i, key, w, binding)]);
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
    b.enable_range(generate_range_trace::<Val, Challenge>);
    if bound {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    // PIs: committed state, query key, released answer.
    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let query_key_pi = b.alloc_public_input("query_key");
    let answer_pi = b.alloc_public_input("answer");
    if bound {
        b.add_expose(&[commit_pis[0], commit_pis[1], query_key_pi, answer_pi])
            .expect("expose (commit, key, answer)");
    }
    b.tag(query_key_pi, "cm_dec_key").expect("tag");
    b.tag(answer_pi, "cm_dec_answer").expect("tag");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let pow2: Vec<ExprId> =
        (0..w_log2).map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j")).collect();
    let col_idx: Vec<ExprId> =
        (0..w).map(|j| b.alloc_const(Challenge::from_u64(j as u64), "col")).collect();
    let split_c = bound.then(|| bind::SplitConsts::new::<Val, Challenge>(&mut b, w_log2, one, zero));

    // Private witnesses. B2: under `Hiding` the salt of `Com(S_t)` comes
    // first (3 private inputs); `Plain` allocates nothing.
    let salt_t = mode.is_hiding().then(|| hiding::alloc_salt_targets(&mut b));
    let cells_packed: Vec<ExprId> =
        (0..cell_packing).map(|_| b.alloc_private_input("cell_packed")).collect();
    for (q, &p) in cells_packed.iter().enumerate() {
        b.tag(p, format!("cm_dec_cell_{q}")).expect("tag");
    }
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
    // Bound: the canonical split `(pos, hi, dinv)` of each row's digest limb.
    let split_w: Vec<[ExprId; 3]> = if bound {
        (0..d).map(|_| std::array::from_fn(|_| b.alloc_private_input("split"))).collect()
    } else {
        Vec::new()
    };

    // ── Stage 1: open the committed state ──
    let digest = hiding::commit_hash::<Val, Challenge>(
        &mut b,
        &cfg,
        CommitKind::State,
        CommitFamily::CountMin,
        salt_t.as_ref(),
        &cells_packed,
        zero,
        binding,
    );
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }
    let cells: Vec<ExprId> = cells_packed
        .iter()
        .flat_map(|&p| {
            bind::decompose::<Val, Challenge>(
                &mut b,
                p,
                binding,
                bind::no_pin,
                bind::pin_all_base::<Val, Challenge>,
            )
        })
        .collect();

    // Bind `mn` to the base domain (coeffs 1..4 = 0) so the range checks below
    // are sound, and use the base coeff `mn_b` in all arithmetic (every
    // decompose output must flow through an ALU op — WitnessChecks discipline).
    // (`mn_b` is not bound to `mn_w` here, but the min gadget below pins it:
    // `v − mn_b` range-checked and `∏(v − mn_b) = 0` force `mn_b = min v`.)
    // The query key needs no such binding: it is a verifier-supplied public
    // input that feeds the hash directly, so the prover has no freedom there.
    let mnc = b.decompose_ext_to_base_coeffs::<Val>(mn_w).unwrap();
    let mn_b = mnc[0];
    b.connect(mnc[1], zero);
    b.connect(mnc[2], zero);
    b.connect(mnc[3], zero);

    // ── Stage 2: derive positions h_i(key) and select cells ──
    if bound {
        // Exact-limb key: every coefficient of the public key is an exact
        // 16-bit limb (range-checked), so it names one 64-bit key.
        bind::assert_key_limbs::<Val, Challenge>(&mut b, query_key_pi, binding);
    }
    let hashed = bind::hash_slice(&mut b, &cfg, &[query_key_pi], zero, binding);
    b.connect(hashed[0], h0);
    b.connect(hashed[1], h1);
    // One-hot selector over the w cells of row i, bound to `pos`; returns the
    // selected cell.
    let select = |b: &mut CircuitBuilder<Challenge>, i: usize, pos: ExprId| -> ExprId {
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
        val
    };
    let mut vals_expr: Vec<ExprId> = Vec::with_capacity(d);
    if let Some(sc) = &split_c {
        // Limb i < d = canonical split (yields pos_i); other limbs of an
        // ALU-bound Challenge are base-pinned. For d ≤ 4 the second digest
        // Challenge is unused.
        let split_limb = |b: &mut CircuitBuilder<Challenge>, t: usize, c: ExprId| {
            if t < d {
                let [pos, hi, dinv] = split_w[t];
                let x = bind::canonical_split_gadget::<Val, Challenge>(b, pos, hi, dinv, sc);
                b.connect(x, c);
            }
        };
        let pin_unused = |b: &mut CircuitBuilder<Challenge>, t: usize, c: ExprId| {
            if t >= d {
                bind::pin_base::<Val, Challenge>(b, c);
            }
        };
        let _ = bind::decompose::<Val, Challenge>(&mut b, h0, binding, split_limb, pin_unused);
        if d > 4 {
            let _ = bind::decompose::<Val, Challenge>(
                &mut b,
                h1,
                binding,
                |b, i, c| split_limb(b, 4 + i, c),
                |b, i, c| pin_unused(b, 4 + i, c),
            );
        }
        for (i, sw) in split_w.iter().enumerate() {
            vals_expr.push(select(&mut b, i, sw[0]));
        }
    } else {
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(h0).unwrap();
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(h1).unwrap();
        let h_vals: [ExprId; 8] = [c0[0], c0[1], c0[2], c0[3], c1[0], c1[1], c1[2], c1[3]];
        for i in 0..d {
            let bits = b.decompose_to_bits::<Val>(h_vals[i], Val::bits()).expect("bits h_val");
            let mut pos = b.mul(bits[0], pow2[0]);
            for jb in 1..w_log2 {
                let t = b.mul(bits[jb], pow2[jb]);
                pos = b.add(pos, t);
            }
            vals_expr.push(select(&mut b, i, pos));
        }
        // Consume the unused digest limbs (WitnessChecks discipline).
        for k in d..8 {
            let _ = b.add_range_bits::<Val>(h_vals[k], Val::bits()).expect("consume h_val");
        }
    }

    // ── Stage 3: min gadget ──
    let mut prod = one;
    for &v in &vals_expr {
        let diff = b.sub(v, mn_b);
        let _ = b.add_range_bits::<Val>(diff, DIFF_BITS).expect("v - mn >= 0"); // range check
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
            let _ = b.add_range_bits::<Val>(chosen, DIFF_BITS).expect("chosen >= 0");
            let released = b.mul(fl, mn_b);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build cm decode circuit");

    // ─── Pack public + private values ────────────────────────────────────
    let commit_packed = pack_commit_to_challenge(&commit);
    let key_input = key_hash_input(key, binding);
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_basis_coefficients_slice(&key_input).expect("4 base coeffs"));
    public_inputs.push(Challenge::from_u64(answer));

    let mut private_inputs: Vec<Challenge> =
        if mode.is_hiding() { salt.packed().to_vec() } else { Vec::new() };
    private_inputs.extend(pack_cells(state));
    // sel[i][j]
    for i in 0..d {
        let pos = hash_cell_prf_with(i, key, w, binding);
        for j in 0..w {
            private_inputs.push(if j == pos { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    // mn
    private_inputs.push(Challenge::from_u64(mn as u64));
    // h0, h1 (digest of the key)
    let digest_native: [Val; 8] = crate::sketch::countmin_final::key_digest(key, binding);
    private_inputs
        .push(Challenge::from_basis_coefficients_slice(&digest_native[0..4]).expect("4 coeffs"));
    private_inputs
        .push(Challenge::from_basis_coefficients_slice(&digest_native[4..8]).expect("4 coeffs"));
    // flag (threshold only)
    if flag.is_some() {
        let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
        private_inputs.push(if (mn as u64) >= t { Challenge::ONE } else { Challenge::ZERO });
    }
    if bound {
        for limb in digest_native.iter().take(d) {
            private_inputs.extend(bind::canonical_split_vals::<Val>(*limb, w_log2).map(Challenge::from));
        }
    }

    // ─── Prover data ─────────────────────────────────────────────────────
    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false), range_preprocessor::<Val>()];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
    if bound {
        preprocessors.push(expose_preprocessor::<Val>());
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
    }

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
    prover.register_range_table::<4>();
    if bound {
        prover.register_expose_table::<4>();
    }

    CmDecodeCircuit {
        circuit,
        public_inputs,
        private_inputs,
        answer,
        prover,
        circuit_prover_data,
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::countmin::commit_countmin;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_final::apply_update_prf_with;

    /// A `d=4, w=8` state built with `binding`'s routing (the omc leaf's
    /// native model for that binding).
    fn state_with(binding: Binding) -> CountMinState {
        let mut s = CountMin::new(&CountMinParams { d: 4, w: 8 });
        for k in [7u64, 7, 11, 7, 11, 3] {
            apply_update_prf_with(&mut s, &CountMinUpdate { key: k, value: 1 }, binding);
        }
        s
    }

    /// [`state_with`] the process default binding (what `prove_cm_decode` uses).
    fn state() -> CountMinState {
        state_with(bind::default_binding())
    }

    /// The pinned verifier with the VK derived from public parameters
    /// accepts honest proofs over other states and keys and returns their
    /// exposed statement; it rejects the Legacy circuit and another family's
    /// decode proof.
    #[test]
    fn cm_decode_vk_pins_proofs() {
        use crate::decode::{QueryStatement, verify_decode_proof};
        let binding = bind::default_binding();
        if binding == Binding::Legacy {
            return;
        }
        let p = CmDecodeParams { d: 4, w: 8, release: ReleasePolicy::Identity };
        let vk = cm_decode_vk(p, binding);
        for key in [7u64, 11, 0xDEAD_BEEF_0042] {
            let proof = prove_cm_decode(p, state(), key);
            let want = QueryStatement::with_query(
                commit_countmin(&state()).0,
                key_hash_input(key, binding),
                proof.answer,
            );
            assert_eq!(verify_decode_proof(&proof.output.0, &vk), Ok(want), "key {key}");
        }
        let legacy = prove_cm_decode_with(p, state_with(Binding::Legacy), 7, Binding::Legacy);
        assert!(verify_decode_proof(&legacy.output.0, &vk).is_err(), "Legacy circuit");
        let other = prove_cm_decode(CmDecodeParams { d: 4, w: 16, release: ReleasePolicy::Identity }, {
            let mut s = CountMin::new(&CountMinParams { d: 4, w: 16 });
            apply_update_prf_with(&mut s, &CountMinUpdate { key: 7, value: 1 }, binding);
            s
        }, 7);
        assert!(verify_decode_proof(&other.output.0, &vk).is_err(), "another width's circuit");
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

    /// The decode circuit proves and self-verifies at w > 16 (the old `w ≤ 16`
    /// cap was a stale copy of the leaf's proxy; the in-circuit position
    /// derivation is identical to the leaf, which already runs at large w). The
    /// point-count answer stays a sound overestimate of the true count.
    #[test]
    fn cm_decode_large_w_round_trips() {
        for w in [32usize, 64] {
            let mut s = CountMin::new(&CountMinParams { d: 4, w });
            for k in [7u64, 7, 11, 7, 11, 3, 42, 99, 42] {
                apply_update_prf_with(&mut s, &CountMinUpdate { key: k, value: 1 }, bind::default_binding());
            }
            let p = CmDecodeParams { d: 4, w, release: ReleasePolicy::Identity };
            let proof = prove_cm_decode(p, s, 7);
            assert!(proof.answer >= 3, "w={w}: estimate >= true count 3, got {}", proof.answer);
        }
    }

    // ── Binding (see `crate::sketch::bind`): legacy-vs-bound forgery tests ──

    use crate::config::make_perm;
    use crate::sketch::forge;
    use p3_circuit::ops::{NpoTypeId, Poseidon2Trace};

    const P4: CmDecodeParams = CmDecodeParams { d: 4, w: 8, release: ReleasePolicy::Identity };

    fn native_estimate(s: &CountMinState, key: u64, binding: Binding) -> u32 {
        (0..s.params.d)
            .map(|i| s.counters[i][hash_cell_prf_with(i, key, s.params.w, binding)])
            .min()
            .unwrap()
    }

    /// The 16 exposed base values `(commit[8], key[4], answer[4])`.
    fn exposed16(proof: &DecodeProof) -> Vec<Val> {
        proof
            .output
            .0
            .non_primitives
            .iter()
            .map(|e| e.public_values.clone())
            .find(|v| v.len() == 16)
            .expect("exposed (commit, key, answer)")
    }

    /// Bound exposes `(commit, key, answer)`, the key as its exact 16-bit
    /// limbs; honest runs agree with native under every binding.
    #[test]
    fn bound_decode_exposes_commit_key_answer() {
        let s = state_with(Binding::Bound);
        let proof = prove_cm_decode_with(P4, s.clone(), 7, Binding::Bound);
        let pv = exposed16(&proof);
        assert_eq!(&pv[0..8], &commit_countmin(&s).0[..]);
        assert_eq!(&pv[8..12], &[Val::from_u64(7), Val::ZERO, Val::ZERO, Val::ZERO]);
        assert_eq!(pv[12].as_canonical_u64(), native_estimate(&s, 7, Binding::Bound) as u64);
        assert_eq!(proof.answer, native_estimate(&s, 7, Binding::Bound) as u64);
        for binding in [Binding::Semantic, Binding::Legacy] {
            let sb = state_with(binding);
            let other = prove_cm_decode_with(P4, sb.clone(), 7, binding);
            assert_eq!(other.answer, native_estimate(&sb, 7, binding) as u64, "{binding:?}");
            assert!(other.answer >= 3, "{binding:?}: estimate >= true count 3");
        }
        // d > 4: the second digest Challenge (split rows 4..d); a 64-bit key
        // fills every exposed limb.
        let key = 0x0123_4567_89AB_CDEF_u64;
        for binding in [Binding::Bound, Binding::Semantic] {
            let mut s7 = CountMin::new(&CountMinParams { d: 7, w: 16 });
            for k in [key, key, 11, 3] {
                apply_update_prf_with(&mut s7, &CountMinUpdate { key: k, value: 1 }, binding);
            }
            let p7 = CmDecodeParams { d: 7, w: 16, release: ReleasePolicy::Identity };
            let pr = prove_cm_decode_with(p7, s7.clone(), key, binding);
            assert_eq!(pr.answer, native_estimate(&s7, key, binding) as u64);
            assert_eq!(&exposed16(&pr)[8..12], &bind::key_limbs::<Val>(key)[..]);
            assert_eq!(&exposed16(&pr)[8..12], &[0xCDEF, 0x89AB, 0x4567, 0x0123].map(Val::from_u64)[..]);
        }
    }

    /// (6) B2: a Hiding decode opens `Com(S_t; ρ)`. Under `Semantic`/`Bound`
    /// it exposes the hiding commitment (not the plain one) with the same
    /// answer; the Plain decoder is the pre-B2 circuit (VK recorded at
    /// main@7089f70) and the Hiding VK does not depend on the salt. A query at
    /// version `t` opened with `ρ^S_t` exposes exactly the final commitment of
    /// the hiding leaf `t`; a wrong salt still proves, but exposes a
    /// commitment that is not the log's.
    #[test]
    fn hiding_decode_exposes_hiding_commit() {
        use crate::commitment::hiding::{CommitFamily, Openings, SaltSeed, rho_state_bb};
        use crate::recursion::recursive::expose_forest::vk_pin_values;
        use crate::recursion::recursive::statement::Expose;
        use crate::sketch::countmin_omc::{CmOmcParams, build_countmin_omc_leaf_commit};

        let flat = |v: &[Challenge]| -> Vec<u64> {
            v.iter()
                .flat_map(|c| {
                    <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                        .iter()
                        .map(|x| x.as_canonical_u64())
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        #[cfg(not(feature = "zk"))]
        let recorded = [
            (Binding::Semantic, [1773978634u64, 384655842, 294999589, 1673679358, 228006917, 1314500707, 1408979141, 851131018]),
            (Binding::Bound, [463599477, 1112163925, 541462878, 1485602053, 736039150, 1630584522, 230137302, 1981838388]),
            (Binding::Legacy, [228825302, 1995195332, 1399604520, 922024243, 1544049975, 1169568391, 1127353679, 1729298590]),
        ];
        // The same circuits under the `zk` feature: hiding-PCS VKs, recorded on the
        // zk-logup-mask forks (Plonky3 280b1a07, Plonky3_RangeAir 3acdc06), equal
        // across separate processes. The LogUp masks do not move them (main-trace
        // columns; see `config::tests::leaf_opens_logup_mask_columns`).
        #[cfg(feature = "zk")]
        let recorded = [
            (Binding::Semantic, [701891560u64, 1553654348, 625590183, 1637796432, 1111255607, 277584737, 1732842313, 25210588]),
            (Binding::Bound, [826685437, 134741180, 95614928, 153540057, 759225782, 498247850, 810342931, 918297598]),
            (Binding::Legacy, [981977393, 1685632322, 140073096, 1201236892, 1461686164, 852152570, 86405302, 608570410]),
        ];
        let seed = SaltSeed::for_tests(61);
        let (rho, rho2) = (rho_state_bb(&seed, CommitFamily::CountMin, 4), rho_state_bb(&seed, CommitFamily::CountMin, 5));
        for (binding, vk) in recorded {
            let s = state_with(binding);
            let plain = prove_cm_decode_with(P4, s.clone(), 7, binding);
            let want: Vec<u64> = vk.iter().flat_map(|&x| [x, 0, 0, 0]).collect();
            assert_eq!(flat(&vk_pin_values(&plain.output.0)), want, "{binding:?}: Plain decode VK drifted");
            let hid = prove_cm_decode_commit(P4, s.clone(), 7, binding, CommitMode::Hiding, &rho);
            assert_eq!(hid.answer, native_estimate(&s, 7, binding) as u64, "{binding:?}");
            assert_eq!(hid.answer, plain.answer, "{binding:?}");
            let hid2 = prove_cm_decode_commit(P4, s.clone(), 7, binding, CommitMode::Hiding, &rho2);
            assert_eq!(vk_pin_values(&hid.output.0), vk_pin_values(&hid2.output.0), "{binding:?}");
            assert_ne!(vk_pin_values(&hid.output.0), vk_pin_values(&plain.output.0), "{binding:?}");
            if binding.is_bound() {
                let pv = exposed16(&hid);
                assert_eq!(&pv[0..8], &commit_countmin_with(&s, CommitMode::Hiding, &rho).0[..], "{binding:?}");
                assert_ne!(&pv[0..8], &commit_countmin(&s).0[..], "{binding:?}");
                assert_ne!(exposed16(&hid2)[0..8], pv[0..8], "{binding:?}: another version, another commitment");
            }
        }

        // Query at version t == leaf t's final commitment.
        let binding = Binding::Semantic;
        let t = 2u64;
        let mut leaf = build_countmin_omc_leaf_commit(CmOmcParams { d: 4, w: 8, batch: 2 }, Expose::Interval, binding, CommitMode::Hiding);
        let s_prev = state_with(binding);
        let ups = vec![CountMinUpdate { key: 7, value: 2 }, CountMinUpdate { key: 5, value: 1 }];
        let r = leaf.prove_epoch_commit(t, s_prev.clone(), ups.clone(), &Openings::for_leaf(&seed, CommitFamily::CountMin, t));
        let mut s_t = s_prev;
        for u in &ups {
            apply_update_prf_with(&mut s_t, u, binding);
        }
        let q = prove_cm_decode_commit(P4, s_t.clone(), 7, binding, CommitMode::Hiding, &rho_state_bb(&seed, CommitFamily::CountMin, t));
        assert_eq!(&exposed16(&q)[0..8], &r.final_commit.0[..], "query at t opens leaf t's final commitment");
        let wrong = prove_cm_decode_commit(P4, s_t, 7, binding, CommitMode::Hiding, &rho_state_bb(&seed, CommitFamily::CountMin, t + 1));
        assert_ne!(&exposed16(&wrong)[0..8], &r.final_commit.0[..], "a wrong salt exposes another commitment");
    }

    /// (F3, F5) Decoder twin of the leaf's overhead test: a Hiding decode
    /// costs exactly +2 Poseidon2 rows and +3 ALU rows (one commitment)
    /// under every binding, and none of its 12 salt values is a public value
    /// of the proof.
    #[test]
    fn hiding_decode_row_overhead_and_no_salt_in_public_values() {
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows, trace_rows};
        use crate::commitment::hiding::{CommitFamily, SaltSeed, rho_state_bb};
        let rho = rho_state_bb(&SaltSeed::for_tests(62), CommitFamily::CountMin, 3);
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let s = state_with(binding);
            let (p0, a0) = trace_rows(&build_cm_decode(P4, &s, 7, binding).run());
            let (p1, a1) = trace_rows(&build_cm_decode_commit(P4, &s, 7, binding, CommitMode::Hiding, &rho).run());
            println!("B2 decode rows {binding:?}: Poseidon2 {p0} -> {p1}, ALU {a0} -> {a1}");
            assert_eq!(p1, p0 + 2, "{binding:?}: Poseidon2 rows");
            assert_eq!(a1, a0 + 3, "{binding:?}: ALU rows");
            let hid = prove_cm_decode_commit(P4, s, 7, binding, CommitMode::Hiding, &rho);
            assert_eq!(proof_alu_rows(&hid.output.0), a1, "{binding:?}: the proof's ALU height");
            assert_eq!(leaked_salts(&hid.output.0, &[rho]), vec![], "{binding:?}");
        }
    }

    /// Under `Hiding` the public zero salt opens only the empty genesis
    /// state, the one state commitment the verifier recomputes itself
    /// (`Com(S_0; 0)`; a continued history's version 0 opens with its
    /// anchor salt). A real state handed the zero salt (a forgotten opening
    /// at `t >= 1`) panics instead of publishing the guess-checkable
    /// `Com(S_t; 0)`, from the builder and the proving entry point alike
    /// (the twin of `decode::gk_bandmerge`'s test). Controls: the empty state
    /// with the zero salt (a genesis query; the Hiding VK derivation), a
    /// real state with a real salt, and `Plain` (salt ignored) still build,
    /// and the genesis query proves and exposes `Com(S_0; 0)`.
    #[test]
    fn hiding_decode_refuses_zero_salt_on_a_real_state() {
        use crate::commitment::hiding::{SaltSeed, rho_state_bb};
        let rho = rho_state_bb(&SaltSeed::for_tests(64), CommitFamily::CountMin, 2);
        let empty = CountMin::new(&CountMinParams { d: P4.d, w: P4.w });
        for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
            let s = state_with(binding);
            let msg = forge::catch_msg(|| {
                build_cm_decode_commit(P4, &s, 7, binding, CommitMode::Hiding, &SaltBb::ZERO).answer
            })
            .unwrap_err();
            assert!(msg.contains("public zero salt"), "{binding:?}: {msg}");
            let _ = build_cm_decode_commit(P4, &empty, 7, binding, CommitMode::Hiding, &SaltBb::ZERO);
            let _ = build_cm_decode_commit(P4, &s, 7, binding, CommitMode::Hiding, &rho);
            let _ = build_cm_decode_commit(P4, &s, 7, binding, CommitMode::Plain, &SaltBb::ZERO);
        }
        let msg = forge::catch_msg(|| {
            prove_cm_decode_commit(P4, state_with(Binding::Semantic), 7, Binding::Semantic, CommitMode::Hiding, &SaltBb::ZERO)
                .answer
        })
        .unwrap_err();
        assert!(msg.contains("public zero salt"), "{msg}");
        let genesis = prove_cm_decode_commit(P4, empty.clone(), 7, Binding::Semantic, CommitMode::Hiding, &SaltBb::ZERO);
        assert_eq!(genesis.answer, 0);
        assert_eq!(
            &exposed16(&genesis)[0..8],
            &commit_countmin_with(&empty, CommitMode::Hiding, &SaltBb::ZERO).0[..],
            "a genesis query opens the public anchor Com(S_0; 0)"
        );
    }

    /// Keys congruent mod `p`: decode `k` on a state holding one occurrence of
    /// `k + p` only (both 32-bit keys). `Legacy` hashes the key mod `p` and
    /// reads `k + p`'s cells, a verified false positive (answer 1, the
    /// documented control). `Semantic`/`Bound` hash the exact limbs and
    /// answer 0; they also expose different key limbs for the two keys.
    #[test]
    fn congruent_keys_decode_legacy_collides_semantic_bound_separate() {
        let p = <Val as p3_field::PrimeField64>::ORDER_U64;
        let (k, k_twin) = (12_345u64, 12_345 + p);
        assert!(k_twin < 1 << 32);
        let params = CmDecodeParams { d: 4, w: 64, release: ReleasePolicy::Identity };
        for binding in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            let mut s = CountMin::new(&CountMinParams { d: 4, w: 64 });
            apply_update_prf_with(&mut s, &CountMinUpdate { key: k_twin, value: 1 }, binding);
            let proof = prove_cm_decode_with(params, s.clone(), k, binding);
            let want = if binding.is_bound() { 0 } else { 1 };
            assert_eq!(proof.answer, want, "{binding:?}");
            if binding.is_bound() {
                let twin = prove_cm_decode_with(params, s, k_twin, binding);
                assert_eq!(twin.answer, 1, "{binding:?}: the twin itself is counted");
                assert_ne!(exposed16(&proof)[8..12], exposed16(&twin)[8..12]);
            }
        }
    }

    /// FORGED STATE (transplant): decode key 7 honestly on `S'`, where every
    /// cell key 7 routes to is raised by 100, then recommit the cells to the
    /// real state `S` and rehash. Returns the in-circuit answer if the forged
    /// proof verifies. Every call first runs the positive control
    /// ([`forge::forged_with_control`]): decode on `S` itself and write the
    /// same cells back through the same plumbing; it must verify with the
    /// honest answer.
    fn forged_state_answer(binding: Binding) -> Option<u64> {
        let want = native_estimate(&state_with(binding), 7, binding) as u64;
        forge::forged_with_control(
            &format!("cm decode forged state ({binding:?})"),
            |f| forged_state_answer_run(binding, f),
            |a| assert_eq!(*a, want, "control certifies the honest answer"),
        )
    }

    fn forged_state_answer_run(binding: Binding, forge_it: bool) -> Option<u64> {
        let s = state_with(binding);
        let mut s_forged = s.clone();
        for i in 0..P4.d {
            s_forged.counters[i][hash_cell_prf_with(i, 7, P4.w, binding)] += 100;
        }
        let honest_packed = pack_cells(&s);
        let forged_packed = pack_cells(&s_forged);
        let dc = build_cm_decode(P4, if forge_it { &s_forged } else { &s }, 7, binding);
        let mut traces = dc.run();
        for (q, (h, f)) in honest_packed.iter().zip(&forged_packed).enumerate() {
            if h != f {
                let wid = traces.tag_to_witness[&format!("cm_dec_cell_{q}")];
                forge::set_wid::<Val, Challenge>(&mut traces, wid, *h);
            }
        }
        forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, Poseidon2Config::BABY_BEAR_D4_W16, &make_perm());
        let ok = forge::accepted(|| dc.prove_traces(&traces).map(|_| ()));
        ok.then(|| dc.answer)
    }

    /// Legacy ACCEPTS a decode proof for `Com(S)` whose answer is the estimate
    /// of a different state (true + 100): the cells are unbound from the
    /// commitment. Bound rejects it.
    #[test]
    fn forged_state_legacy_accepts_bound_rejects() {
        if !bind::probe::fork_binds_decompose() {
            let s = state_with(Binding::Legacy);
            let forged =
                forged_state_answer(Binding::Legacy).expect("Legacy accepts the forged decode (PoC)");
            assert_eq!(forged, native_estimate(&s, 7, Binding::Legacy) as u64 + 100, "answer inflated by 100");
        }
        assert!(forged_state_answer(Binding::Bound).is_none(), "Bound must reject the forged decode");
        // Merged soundness fork: the fork itself binds decompose coefficients, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if bind::probe::fork_binds_decompose() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(forged_state_answer(b).is_none(), "fork binds decompose coefficients: {b:?} must reject too");
            }
        }
    }

    /// FREE SPONGE IV on the query-key hash (bump a capacity input, rehash).
    /// Legacy accepts positions that are not those of `MyHash(key)`; Bound
    /// feeds the zero constant into the capacity, so the CTL read fails.
    #[test]
    fn forged_query_iv_legacy_accepts_bound_rejects() {
        let run_iv = |binding: Binding, forge_it: bool| -> bool {
            let dc = build_cm_decode(P4, &state_with(binding), 7, binding);
            let mut traces = dc.run();
            let kw = traces.tag_to_witness["cm_dec_key"].0;
            let key = NpoTypeId::poseidon2_perm(Poseidon2Config::BABY_BEAR_D4_W16);
            let mut pt = traces.non_primitive_trace::<Poseidon2Trace<Val>>(&key).expect("p2").clone();
            let row = pt
                .operations
                .iter_mut()
                .find(|r| r.new_start && r.in_ctl[0] && r.input_indices[0] == kw)
                .expect("query hash row");
            if forge_it {
                row.input_values[8] += Val::ONE;
            }
            traces.non_primitive_traces.insert(key, Box::new(pt));
            forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, Poseidon2Config::BABY_BEAR_D4_W16, &make_perm());
            forge::accepted(|| dc.prove_traces(&traces).map(|_| ()))
        };
        // Positive control first: the same row edit with a zero bump.
        let run = |binding: Binding| -> bool {
            forge::accepted_with_control(&format!("cm decode forged IV ({binding:?})"), |forge_it| {
                run_iv(binding, forge_it)
            })
        };
        if !bind::probe::fork_binds_iv() && !bind::probe::fork_binds_decompose() {
            assert!(run(Binding::Legacy), "Legacy accepts the free-IV query digest (PoC)");
        }
        assert!(!run(Binding::Bound), "Bound must reject the IV forgery");
        // Merged soundness fork: the fork itself binds the sponge IV, so the
        // DEFAULT `Semantic` mode (and even `Legacy`) must reject as well.
        if bind::probe::fork_binds_iv() {
            for b in [Binding::Semantic, Binding::Legacy] {
                assert!(!run(b), "fork binds the sponge IV: {b:?} must reject too");
            }
        }
    }
}
