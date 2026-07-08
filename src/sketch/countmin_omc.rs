//! **Offline-memory-checking count-min leaf (`omc`)** — the sound,
//! cross-state realization of zk1.tex §"Pattern A" Step 5 that proves
//! `N[a] = O[a] + Δ_a` at the touched cells AND that every *untouched*
//! cell is unchanged, by a single read/write **multiset equality**
//! against the real committed prior state — no Merkle path, no
//! timestamps, and (unlike [`super::countmin_memcheck`]) **no empty-init
//! assumption**.
//!
//! ## The check
//!
//! Treat the `d×w` array as memory; address `a = i·w + b`, value
//! `S[a]`. With the full old/new memories
//! `M_old = {(a, S_{t-1}[a])}` and `M_new = {(a, S_t[a])}`, the touched
//! reads `R = {(a_z, O_z)}` and writes `W = {(a_z, N_z)}`, the leaf
//! proves
//!
//! ```text
//!     M_old ⊎ W  ==  M_new ⊎ R       (as multisets)
//! ```
//!
//! For a touched address the pair `(M_old[a_z], W) = (enc(a_z,O[a_z]),
//! enc(a_z,N_z))` must equal `(M_new[a_z], R) = (enc(a_z,N[a_z]),
//! enc(a_z,O_z))`. Because `enc` binds the address, the only matching is
//! `O_z = O[a_z]` and `N[a_z] = O_z + Δ_z` — i.e. the multiset **forces
//! the prover's claimed old value `O_z` to be the genuinely committed old
//! value** (membership) and the new committed cell to be `old + Δ`. For
//! an untouched address nothing is added, so `O[u] = N[u]` is forced.
//! `O[a]` / `N[a]` are bound to the public `(init_commit, final_commit)`
//! by decomposing the same Poseidon-committed cells the dense `one_hot`
//! leaf uses.
//!
//! ## Why this is the honest "maintained accumulator"
//!
//! The "accumulator carried across versions" here is simply the
//! **committed dense state itself**: `init_commit = Com(S_{t-1})` is the
//! certified digest of the whole old memory, established by the previous
//! transition's `final_commit`. This leaf reconciles the touched
//! reads/writes against it. A *scalar grand-product* accumulator carried
//! across separately-proven batches is NOT sound in a hash-based STARK
//! (its binding challenge is per-proof Fiat–Shamir; a fixed challenge is
//! not binding), and an `O(1)`-membership algebraic accumulator needs
//! hidden-order groups we do not have — so the committed-state-plus-
//! multiset realization below is the strongest sound option here.
//!
//! ## Cost
//!
//! The rebind is one [`CircuitBuilder::add_permute`] over `dw + n_ctr`
//! tagged `(addr,val)` elements plus the dense commit/decompose of both
//! ends: **`Θ(dw + n_ctr)`**. This is `Θ(dw)` — it does *not* beat the
//! sparse [`merkle`](super::countmin_c_merkle) /
//! [`memcheck`](super::countmin_memcheck) rebinds when `T ≪ dw` — but it
//! replaces `one_hot`'s `Θ(batch·d·dw)` one-hot selector matrix with a
//! single `dw`-length permutation, so it sits far below `one_hot` while
//! remaining the only variant that reconciles touched **old values
//! against a non-trivial committed prior state** with no Merkle path.
//!
//! Each touched address appears once (canonical group-by + sortedness
//! range-check), and inactive rows are zero on both the `W` and `R` side
//! so they cancel; real elements carry a `1` tag in coordinate 2 so they
//! can never collide with the zero dummies. Shape depends only on
//! `(d, w, batch)` — Property-4 oblivious.

use std::collections::HashMap;
use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_permute_trace, generate_poseidon2_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use p3_symmetric::CryptographicHasher;

use crate::commitment::CountMinCommit;
use crate::commitment::countmin::commit_countmin;
use crate::commitment::countmin_batch::commit_batch;
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::countmin_final::{apply_update_prf, hash_cell_prf};
use crate::sketch::countmin_v9::CountMinV9;

const LOG_FINAL_POLY_LEN: usize = 6;
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

thread_local! {
    /// When set, the prover commits to a CORRUPTED final state (one cell
    /// bumped) while the patch/multiset are built from the honest one, so
    /// `M_old ⊎ W = M_new ⊎ R` fails and the self-verify rejects. Drives
    /// [`tests::tamper_rejected`].
    static TAMPER_FINAL_CELL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmOmcParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CmOmcParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    fn addr_bits(&self) -> usize {
        let n = self.num_cells();
        (usize::BITS - n.saturating_sub(1).leading_zeros()).max(1) as usize
    }
    pub fn validate(&self) {
        assert!(
            self.d >= 1 && self.d <= 8,
            "d must be in 1..=8, got {}",
            self.d
        );
        assert!(
            self.w.is_power_of_two() && self.w >= 2,
            "w must be a power of two ≥ 2, got {}",
            self.w
        );
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(
            self.num_cells() % 4 == 0,
            "d·w must be a multiple of 4 (Challenge packing)"
        );
    }
}

/// A self-verified `omc` leaf proof. Commitments are the dense
/// `commit_countmin` digests on both ends (so this DOES chain against a
/// real prior state, unlike `memcheck`).
pub struct CountMinOmcProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: CountMinCommit,
    pub final_commit: CountMinCommit,
    pub batch_commit: CountMinCommit,
    pub params: CmOmcParams,
}

impl CountMinOmcProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = state
        .counters
        .iter()
        .flatten()
        .map(|&c| Val::from_u32(c))
        .collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

fn pack_batch_to_challenge(batch: &[CountMinUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    let flat: Vec<Val> = batch
        .iter()
        .flat_map(|r| {
            let key_lo = (r.key & 0xFFFF_FFFF) as u32;
            let key_hi = (r.key >> 32) as u32;
            [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(r.value),
                Val::ZERO,
            ]
        })
        .collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

/// Prove one count-min epoch from an arbitrary committed `initial_state`
/// via the `M_old ⊎ W = M_new ⊎ R` multiset rebind.
///
/// # Panics
/// - `params.validate()` failures, `initial_state.params != (d, w)`,
///   `batch.len() != params.batch`.
pub fn prove_countmin_omc(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    prove_countmin_omc_impl(params, initial_state, batch, false)
}

/// Like [`prove_countmin_omc`] but additionally surfaces the `(initial, final)`
/// boundary commitments via the **Expose NPO**, so the leaf proof can be folded
/// by the in-circuit boundary-bound forest
/// ([`crate::recursion::recursive::expose_forest::prove_forest_over`]) — which
/// binds `left.final == right.initial` in-circuit rather than natively. The
/// commitments and proof are otherwise identical to [`prove_countmin_omc`].
pub fn prove_countmin_omc_exposed(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    prove_countmin_omc_impl(params, initial_state, batch, true)
}

/// A built, reusable `omc` Count-Min leaf: the circuit graph, its prover
/// data, and a registered prover. Build once per `(params, expose_boundary)`
/// and call [`Self::prove_epoch`] per batch — the graph is a pure function of
/// the shape except for the two Permute ops’ trace-generation hints, which
/// each prove swaps in via `Circuit::update_permute_witnesses`. This hoists
/// the dominant per-leaf costs (graph build + AIR/`ProverData` prep) out of
/// the epoch loop.
pub struct CmOmcLeafCircuit {
    params: CmOmcParams,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
}

/// Build the reusable `omc` Count-Min leaf circuit for a shape.
pub fn build_countmin_omc_leaf(params: CmOmcParams, expose_boundary: bool) -> CmOmcLeafCircuit {
    params.validate();
    let CmOmcParams { d, w, batch: m } = params;
    let num_cells = params.num_cells();
    let cell_packing = num_cells / 4;
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let addr_bits = params.addr_bits();
    let l = num_cells + n_ctr; // multiset side length

    // ─── Circuit ─────────────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    if expose_boundary {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    let init_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    // Surface (initial, final) via the Expose NPO so the boundary propagates into
    // recursion (consumed by the in-circuit boundary-bound forest). These PI
    // wires are connected to the hashed dense-state commitments below, so the
    // exposed values equal the real commitments.
    if expose_boundary {
        b.add_expose(&[
            init_commit_pis[0],
            init_commit_pis[1],
            final_commit_pis[0],
            final_commit_pis[1],
        ])
        .expect("add_expose boundary");
    }
    let batch_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
    let two_pow_32_const = b.alloc_const(Challenge::from_u64(1u64 << 32), "2^32");
    let row_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "row_i"))
        .collect();
    let cell_idx_consts: Vec<ExprId> = (0..num_cells)
        .map(|idx| b.alloc_const(Challenge::from_u64(idx as u64), "cell_idx"))
        .collect();
    let pow2_consts: Vec<ExprId> = (0..w_log2)
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();

    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();
    let mut key_lo = Vec::with_capacity(m);
    let mut key_hi = Vec::with_capacity(m);
    let mut value_w = Vec::with_capacity(m);
    for _ in 0..m {
        key_lo.push(b.alloc_private_input("key_lo"));
        key_hi.push(b.alloc_private_input("key_hi"));
        value_w.push(b.alloc_private_input("value"));
    }
    let combined_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("combined_sorted"))
        .collect();
    let val_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("val_sorted"))
        .collect();
    let eq_tag: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("eq_tag"))
        .collect();
    let inv_diff: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("inv_diff"))
        .collect();
    let op_old: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("op_old"))
        .collect();

    // Stage A — bind both states + batch to commitments.
    let digest_init = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &initial_packed, true)
        .expect("hash init");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], init_commit_pis[i]);
    }
    let digest_final = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
    }
    let digest_batch = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_batch[i], batch_commit_pis[i]);
    }
    let o_cells: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    let n_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    for k in 0..m {
        let coeffs = b
            .decompose_ext_to_base_coeffs::<Val>(batch_packed[k])
            .expect("decompose batch");
        b.connect(coeffs[0], key_lo[k]);
        b.connect(coeffs[1], key_hi[k]);
        b.connect(coeffs[2], value_w[k]);
        b.connect(coeffs[3], zero);
    }
    let mut key_field = Vec::with_capacity(m);
    for k in 0..m {
        let hi = b.mul(key_hi[k], two_pow_32_const);
        key_field.push(b.add(key_lo[k], hi));
    }

    // Stage F — per-record PRF hash → payload.
    let mut h_w = Vec::with_capacity(m);
    for _ in 0..m {
        h_w.push((b.alloc_private_input("h0"), b.alloc_private_input("h1")));
    }
    let mut payload = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let hashed = b
            .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &[key_field[k]], true)
            .expect("hash key");
        let (h0, h1) = h_w[k];
        b.connect(hashed[0], h0);
        b.connect(hashed[1], h1);
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(h0).expect("d h0");
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(h1).expect("d h1");
        let hv = [c0[0], c0[1], c0[2], c0[3], c1[0], c1[1], c1[2], c1[3]];
        for i in 0..d {
            let bits = b
                .decompose_to_bits::<Val>(hv[i], Val::bits())
                .expect("bits");
            let mut pos = b.mul(bits[0], pow2_consts[0]);
            for jb in 1..w_log2 {
                let t = b.mul(bits[jb], pow2_consts[jb]);
                pos = b.add(pos, t);
            }
            let rw = b.mul(row_consts[i], w_const);
            let comb = b.add(rw, pos);
            let cs = b.mul(comb, shift_val_const);
            payload.push(b.add(cs, value_w[k]));
        }
        for kk in d..8 {
            let _ = b
                .decompose_to_bits::<Val>(hv[kk], Val::bits())
                .expect("bits unused");
        }
    }

    // Stage G — counter sort.
    // Placeholder identity permutation — `prove_epoch` swaps in the real
    // per-batch sigma via `update_permute_witnesses` before each run.
    let payload_sorted = b
        .add_permute(&payload, (0..n_ctr).collect::<Vec<_>>())
        .expect("permute ctr");
    for r in 0..n_ctr {
        let cs = b.mul(combined_sorted[r], shift_val_const);
        let rec = b.add(cs, val_sorted[r]);
        b.connect(rec, payload_sorted[r]);
    }

    // Stage H — adjacency / running sum / sortedness / segment flags.
    b.connect(eq_tag[0], zero);
    b.connect(inv_diff[0], zero);
    for r in 1..n_ctr {
        let diff = b.sub(combined_sorted[r - 1], combined_sorted[r]);
        let l1 = b.mul(eq_tag[r], diff);
        b.connect(l1, zero);
        let omt = b.sub(one, eq_tag[r]);
        let di = b.mul(diff, inv_diff[r]);
        let omdi = b.sub(one, di);
        let l2 = b.mul(omt, omdi);
        b.connect(l2, zero);
        // sortedness: gap ∈ [0, 2^addr_bits) (canonical 1-entry-per-address).
        let gap = b.sub(combined_sorted[r], combined_sorted[r - 1]);
        let gb = b
            .decompose_to_bits::<Val>(gap, Val::bits())
            .expect("gap bits");
        for &bit in gb.iter().skip(addr_bits) {
            b.connect(bit, zero);
        }
    }
    let mut acc = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        acc.push(b.add(val_sorted[r], carried));
    }
    let mut a_active = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        a_active.push(if r == n_ctr - 1 {
            one
        } else {
            b.sub(one, eq_tag[r + 1])
        });
    }

    // ─── Build the multiset sides and check M_old ⊎ W == M_new ⊎ R ───────
    // enc(a,v) = recompose([a, v, 1, 0]) — the `1` tag in coord 2 keeps real
    // elements disjoint from the zero dummies that inactive W/R rows produce.
    let enc = |b: &mut CircuitBuilder<Challenge>, a: ExprId, v: ExprId| -> ExprId {
        b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[a, v, one, zero])
            .expect("enc")
    };
    let mut input: Vec<ExprId> = Vec::with_capacity(l);
    let mut target: Vec<ExprId> = Vec::with_capacity(l);
    for a in 0..num_cells {
        input.push(enc(&mut b, cell_idx_consts[a], o_cells[a]));
        target.push(enc(&mut b, cell_idx_consts[a], n_cells[a]));
    }
    for r in 0..n_ctr {
        let n_z = b.add(op_old[r], acc[r]); // N_z = O_z + Δ
        let enc_w = enc(&mut b, combined_sorted[r], n_z);
        let w_elem = b.mul(a_active[r], enc_w); // active → enc, inactive → 0
        input.push(w_elem);
        let enc_r = enc(&mut b, combined_sorted[r], op_old[r]);
        let r_elem = b.mul(a_active[r], enc_r);
        target.push(r_elem);
    }
    let permuted = b
        .add_permute(&input, (0..l).collect::<Vec<_>>())
        .expect("permute mset");
    for r in 0..l {
        b.connect(permuted[r], target[r]);
    }

    let circuit = b.build().expect("build countmin_omc circuit");

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
    if expose_boundary {
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
        .expect("get_airs_and_degrees_with_prep (omc)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_permute_table::<4>();
    if expose_boundary {
        prover.register_expose_table::<4>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();

    CmOmcLeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
    }
}

impl CmOmcLeafCircuit {
    /// Prove one epoch on the prebuilt circuit.
    pub fn prove_epoch(
        &mut self,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> CountMinOmcProof {
        let params = self.params;
        assert_eq!(initial_state.params.d, params.d);
        assert_eq!(initial_state.params.w, params.w);
        assert_eq!(batch.len(), params.batch, "batch.len() != params.batch");

        let CmOmcParams { d, w, batch: m } = params;
        let num_cells = params.num_cells();
        let n_ctr = m * d;
        let l = num_cells + n_ctr; // multiset side length

        // ─── Native side ─────────────────────────────────────────────────────
        let mut final_state = initial_state.clone();
        for u in &batch {
            apply_update_prf(&mut final_state, u);
        }
        // Optionally corrupt the COMMITTED final state for the tamper test (the
        // patch is still built from the honest evolution below).
        let mut committed_final = final_state.clone();
        if TAMPER_FINAL_CELL.with(|f| f.get()) {
            committed_final.counters[0][0] = committed_final.counters[0][0].wrapping_add(1);
        }
        let initial_commit = commit_countmin(&initial_state);
        let final_commit = commit_countmin(&committed_final);
        let batch_commit = commit_batch(&batch);

        // U_ctr (per record, no key-grouping) + counter sort.
        let mut u_ctr_data: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
        for u in &batch {
            let kh = <Val as p3_field::PrimeField64>::as_canonical_u64(&Val::from_u64(u.key));
            for i in 0..d {
                let bucket = hash_cell_prf(i, kh, w);
                u_ctr_data.push(((i * w + bucket) as u64, u.value));
            }
        }
        let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr_data.iter().enumerate().collect();
        indexed.sort_by_key(|(_, (combined, _))| *combined);
        let sigma_ctr: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
        let combined_sorted_native: Vec<u64> = indexed.iter().map(|(_, (c, _))| *c).collect();
        let val_sorted_native: Vec<u32> = indexed.iter().map(|(_, (_, v))| *v).collect();

        let mut tag_native: Vec<u32> = vec![0; n_ctr];
        for r in 1..n_ctr {
            if combined_sorted_native[r] == combined_sorted_native[r - 1] {
                tag_native[r] = 1;
            }
        }
        let mut acc_native: Vec<u32> = vec![0; n_ctr];
        if n_ctr > 0 {
            acc_native[0] = val_sorted_native[0];
            for r in 1..n_ctr {
                acc_native[r] = if tag_native[r] == 1 {
                    acc_native[r - 1].saturating_add(val_sorted_native[r])
                } else {
                    val_sorted_native[r]
                };
            }
        }
        let mut a_active_native: Vec<u32> = vec![0; n_ctr];
        for r in 0..n_ctr {
            let ends = if r == n_ctr - 1 {
                true
            } else {
                tag_native[r + 1] == 0
            };
            a_active_native[r] = u32::from(ends);
        }
        // Old value at each row's address (from the HONEST initial state).
        let op_old_native: Vec<u32> = (0..n_ctr)
            .map(|r| {
                let a = combined_sorted_native[r] as usize;
                initial_state.counters[a / w][a % w]
            })
            .collect();

        // Native multiset elements. None = zero dummy (inactive W/R row); a real
        // element is keyed by (addr, value) and carries the coord-2 tag in-circuit.
        let o_cells_native: Vec<u32> = initial_state.counters.iter().flatten().copied().collect();
        let n_cells_native: Vec<u32> = committed_final.counters.iter().flatten().copied().collect();
        let mut input_native: Vec<Option<(u64, u64)>> = Vec::with_capacity(l);
        let mut target_native: Vec<Option<(u64, u64)>> = Vec::with_capacity(l);
        for a in 0..num_cells {
            input_native.push(Some((a as u64, o_cells_native[a] as u64)));
            target_native.push(Some((a as u64, n_cells_native[a] as u64)));
        }
        for r in 0..n_ctr {
            if a_active_native[r] == 1 {
                let addr = combined_sorted_native[r];
                let o = op_old_native[r] as u64;
                let n = o + acc_native[r] as u64;
                input_native.push(Some((addr, n))); // W
                target_native.push(Some((addr, o))); // R
            } else {
                input_native.push(None);
                target_native.push(None);
            }
        }
        // Build sigma s.t. input[sigma[r]] == target[r] (multiset matching).
        let mut buckets: HashMap<Option<(u64, u64)>, Vec<usize>> = HashMap::new();
        for (i, v) in input_native.iter().enumerate() {
            buckets.entry(*v).or_default().push(i);
        }
        let sigma_mset: Vec<usize> = target_native
            .iter()
            .map(|t| {
                buckets
                    .get_mut(t)
                    .and_then(|v| v.pop())
                    .expect("honest multiset matching exists")
            })
            .collect();

        // Swap the real per-batch permutation hints into the prebuilt graph
        // (op order: counter-sort permute, then multiset permute).
        self.circuit
            .update_permute_witnesses(&[sigma_ctr, sigma_mset])
            .expect("update permute witnesses (countmin_omc)");

        // ─── Public + private values ─────────────────────────────────────────
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&initial_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&final_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&CountMinCommit(batch_commit.0)));

        let mut private_inputs: Vec<Challenge> = Vec::new();
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&initial_state));
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&committed_final));
        private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
        for u in &batch {
            private_inputs.push(Challenge::from_u32((u.key & 0xFFFF_FFFF) as u32));
            private_inputs.push(Challenge::from_u32((u.key >> 32) as u32));
            private_inputs.push(Challenge::from_u32(u.value));
        }
        for r in 0..n_ctr {
            private_inputs.push(Challenge::from_u64(combined_sorted_native[r]));
        }
        for r in 0..n_ctr {
            private_inputs.push(Challenge::from_u32(val_sorted_native[r]));
        }
        for r in 0..n_ctr {
            private_inputs.push(Challenge::from_u64(tag_native[r] as u64));
        }
        for r in 0..n_ctr {
            let inv = if r == 0 || combined_sorted_native[r - 1] == combined_sorted_native[r] {
                Challenge::ZERO
            } else {
                (Challenge::from_u64(combined_sorted_native[r - 1])
                    - Challenge::from_u64(combined_sorted_native[r]))
                .try_inverse()
                .expect("nonzero diff inverts")
            };
            private_inputs.push(inv);
        }
        for r in 0..n_ctr {
            private_inputs.push(Challenge::from_u32(op_old_native[r]));
        }
        {
            use p3_field::BasedVectorSpace;
            let hasher = MyHash::new(make_perm());
            for u in &batch {
                let input = [Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO];
                let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
                private_inputs.push(
                    Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 coeffs"),
                );
                private_inputs.push(
                    Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 coeffs"),
                );
            }
        }

        // ─── Run + prove ─────────────────────────────────────────────────────
        let __t_w = std::time::Instant::now();
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&public_inputs).expect("set pubs");
            runner
                .set_private_inputs(&private_inputs)
                .expect("set privs");
            runner.run().expect("run countmin_omc")
        };
        let __witness = __t_w.elapsed();

        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (omc)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify countmin_omc leaf");
        crate::recursion::recursive::timing::record(
            crate::recursion::recursive::timing::LeafTiming {
                witness: __witness,
                prove: __prove,
                verify: __t_v.elapsed(),
                trace_rows: self.trace_rows,
            },
        );

        CountMinOmcProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial_commit,
            final_commit,
            batch_commit: CountMinCommit(batch_commit.0),
            params,
        }
    }
}

fn prove_countmin_omc_impl(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    expose_boundary: bool,
) -> CountMinOmcProof {
    build_countmin_omc_leaf(params, expose_boundary).prove_epoch(initial_state, batch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(d: usize, w: usize) -> CountMinState {
        CountMinV9::new(&CountMinParams { d, w })
    }

    /// Round-trip against a **non-empty** prior state — the whole point:
    /// the touched old values `O_z` are reconciled against a real
    /// committed `M_old`, not assumed 0. Self-verify (incl. the multiset
    /// equality) passing IS the soundness witness.
    #[test]
    fn omc_round_trip_nonempty_prior() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        // Seed a non-trivial prior state with a real prior batch.
        let mut prior = empty(2, 4);
        for u in &[
            CountMinUpdate { key: 3, value: 4 },
            CountMinUpdate { key: 9, value: 2 },
        ] {
            apply_update_prf(&mut prior, u);
        }
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 9, value: 5 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior.clone(), updates);
        assert_eq!(r.initial_commit.0, commit_countmin(&prior).0);
        assert_eq!(r.final_commit.0, commit_countmin(&expect_final).0);
        assert_ne!(r.initial_commit.0, r.final_commit.0);
    }

    /// **Correctness at the reported shape** (`d=7, w=128`, large batch) where
    /// `omc` beats `merkle` — the regime where touched cells approach
    /// the whole small row. Asserts the certified final commitment equals the
    /// natively-applied Count-Min, i.e. the speed is NOT a degenerate shortcut:
    /// the cheaper proof still commits to the correct state. `#[ignore]`d (a real
    /// STARK prove at a larger shape).
    ///
    /// Run: `cargo test --release --lib countmin_omc::tests::omc_correct_d7_w128_large_batch -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn omc_correct_d7_w128_large_batch() {
        let (d, w, m) = (7usize, 128usize, 128usize);
        let params = CmOmcParams { d, w, batch: m };
        let mut prior = empty(d, w);
        for k in 0..60u64 {
            apply_update_prf(
                &mut prior,
                &CountMinUpdate {
                    key: k.wrapping_mul(0x9E37_79B9) ^ 0x55,
                    value: 1 + (k as u32 % 4),
                },
            );
        }
        let updates: Vec<CountMinUpdate> = (0..m)
            .map(|i| CountMinUpdate {
                key: (i as u64).wrapping_mul(0xABCD_1234) ^ 0x7,
                value: 1 + (i as u32 % 5),
            })
            .collect();
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior.clone(), updates);
        assert_eq!(r.initial_commit.0, commit_countmin(&prior).0);
        assert_eq!(
            r.final_commit.0,
            commit_countmin(&expect_final).0,
            "omc final commit must equal natively-applied Count-Min at d=7,w=128,m=128"
        );
        println!(
            "omc d=7 w=128 m=128: certified final commitment == native Count-Min (sound, not a shortcut)."
        );
    }

    /// **Tamper.** Commit a corrupted final state (one cell bumped) while
    /// the patch is built from the honest evolution: `M_new` then has an
    /// untouched cell that disagrees with `M_old`, so the multiset
    /// equality cannot hold and the self-verify rejects.
    #[test]
    fn tamper_rejected() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        let prior = empty(2, 4);
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let _ok = prove_countmin_omc(params, prior.clone(), updates.clone());

        TAMPER_FINAL_CELL.with(|f| f.set(true));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prove_countmin_omc(params, prior.clone(), updates.clone());
        }));
        std::panic::set_hook(prev);
        TAMPER_FINAL_CELL.with(|f| f.set(false));
        assert!(
            res.is_err(),
            "corrupted final state must break the multiset equality"
        );
    }

    /// Repeated keys across a non-empty prior: the running sum folds the
    /// duplicates into one read/write pair, reconciled against the prior.
    #[test]
    fn omc_repeated_keys_nonempty() {
        let params = CmOmcParams {
            d: 4,
            w: 8,
            batch: 4,
        };
        let mut prior = empty(4, 8);
        apply_update_prf(&mut prior, &CountMinUpdate { key: 7, value: 10 });
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior, updates);
        assert_eq!(r.final_commit.0, commit_countmin(&expect_final).0);
    }
}
