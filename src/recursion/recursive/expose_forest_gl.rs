//! In-circuit **boundary-bound** recursive streaming forest, via the Expose NPO.
//!
//! [`countmin_forest_v9`](super::countmin_forest_v9) already folds the
//! intermediates away (O(1) root, no `Com(S_i)` exposed) but binds the *outer*
//! boundaries natively. This module closes that gap: each leaf surfaces its
//! `(Com_before, Com_after)` via the Expose NPO, and each merge
//!
//! 1. recursively verifies both children in-circuit,
//! 2. reads the children's surfaced boundaries as `air_public_targets`,
//! 3. binds `left.final == right.initial` **in-circuit** (`connect`),
//! 4. re-exposes only `(left.initial, right.final)` via its *own* Expose NPO.
//!
//! Composed in a Bentley–Saxe cascade, the single root proof's public values
//! are exactly `(Com(S_0), Com(S_E))` — bound to the verified leaves, with the
//! intermediates neither exposed nor natively trusted.
//!
//! The leaf here ([`prove_boundary_leaf`]) is a *minimal* leaf that exposes a
//! claimed `(initial, final)` boundary — it demonstrates the binding mechanism
//! independent of any sketch's internal update logic. Any real leaf (e.g. the
//! v9 Count-Min leaf) participates by adding the same `add_expose` of its
//! boundary commitments; the merge/forest below compose it unchanged.
//!
//! Goldilocks (D = 2, Poseidon2 width-8) port of
//! [`crate::recursion::recursive::expose_forest`] (BabyBear D = 4). The
//! algorithmic body is identical; only the config/leaf bindings and the
//! digest width (`[Val; 4]`, so `COMMIT_LEN = 4`, D = 2 base coeffs per wire)
//! change.

use std::rc::Rc;

use p3_batch_stark::common::GlobalPreprocessed;
use p3_batch_stark::{CommonData, Commitment, ProverData};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::generate_expose_trace;
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    common::get_airs_and_degrees_with_prep,
};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::pcs::MerkleCapTargets;
use p3_recursion::{
    BatchOnly, PcsRecursionBackend, Poseidon2Config, ProveNextLayerParams, RecursionInput,
    RecursionOutput, Recursive, Target, VerifierCircuitResult, prove_aggregation_layer,
};
use p3_uni_stark::StarkGenericConfig;

use crate::config_gl::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::backend_gl::{Backend, make_backend};
use crate::recursion::recursive::config_gl::{
    ConfigWithFriParamsGl as ConfigWithFriParams, DIGEST_ELEMS, D as EXT_D,
};
use crate::recursion::recursive::leaf_gl::GlCommit;
use crate::recursion::recursive::leaf_gl::{make_leaf_config, pack_commit_to_challenge};
use crate::recursion::recursive::root_vk::{ForestShape, RootVk, ShapeVkDeriver, bound_proof_shape};
use crate::recursion::recursive::statement::{
    BatchLog, Expose, Layout, Statement, TAG_MERGE, check_leaf_statements_against_log,
    check_root_statement, hash_gl, parse_statement,
};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Number of base-field elements per commitment (`GlCommit` is `[Val; 4]`).
const COMMIT_LEN: usize = 4;

fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// The observation-ordered field values of a bound proof's **preprocessed
/// commitment** — its verification key (VK). The recursion backend bakes each
/// child's VK into its parent merge's preprocessed trace as constants (so the
/// merge's own VK depends on its children's); the auditor pins the *root*
/// proof's VK to a trusted copy of these values (see [`verify_bound_stark_proof`]),
/// which transitively anchors the whole tree. The VK is a deterministic,
/// transparent function of the circuit *structure* alone — independent of the
/// exposed boundary values — so it is a legitimate public parameter, not a
/// trusted setup.
pub fn vk_pin_values(proof: &BatchStarkProof<ConfigWithFriParams>) -> Vec<Challenge> {
    let commitment = &proof
        .stark_common
        .preprocessed
        .as_ref()
        .expect("a boundary-bound proof carries a preprocessed commitment")
        .commitment;
    <MerkleCapTargets<Val, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(commitment)
}

/// Build a `RecursionInput::BatchStark` that carries the proof's per-table
/// public values (so surfaced Expose values reach the next layer's
/// `air_public_targets`). The stock `RecursionOutput::into_recursion_input`
/// empties them; this reconstructs them from the proof: primitive tables
/// contribute nothing, each non-primitive table contributes its recorded
/// `public_values`.
pub fn recursion_input_with_public_values(
    output: &RecursionOutput<ConfigWithFriParams>,
) -> RecursionInput<'_, ConfigWithFriParams, BatchOnly> {
    recursion_input_from_proof(&output.0)
}

/// [`recursion_input_with_public_values`] from a bare proof. Everything the
/// next layer's verifier circuit needs lives in the `BatchStarkProof` itself
/// (`proof`, `stark_common`, the non-primitives' recorded `public_values`) —
/// the `Rc<CircuitProverData>` half of a `RecursionOutput` is never consumed.
/// This is what makes proofs **portable across machines**: a merge node can
/// deserialize a peer's proof bytes and fold them without any local circuit
/// state from the producing process. (Wire-crossing proofs additionally need
/// their `CommonData` rebuilt — see [`rebuilt_common_for`].)
pub fn recursion_input_from_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> RecursionInput<'_, ConfigWithFriParams, BatchOnly> {
    recursion_input_with_common(proof, &proof.stark_common)
}

/// [`recursion_input_from_proof`] with an explicit [`CommonData`] — the
/// deserialized-proof path, where `proof.stark_common` lost its lookups on
/// the wire and a rebuilt copy must be supplied.
pub fn recursion_input_with_common<'a>(
    proof: &'a BatchStarkProof<ConfigWithFriParams>,
    common: &'a CommonData<ConfigWithFriParams>,
) -> RecursionInput<'a, ConfigWithFriParams, BatchOnly> {
    let n_instances = proof.proof.opened_values.instances.len();
    let n_non_prim = proof.non_primitives.len();
    let n_prim = n_instances - n_non_prim;

    let mut table_public_inputs: Vec<Vec<Val>> = vec![Vec::new(); n_prim];
    for entry in &proof.non_primitives {
        table_public_inputs.push(entry.public_values.clone());
    }

    RecursionInput::BatchStark { proof, common_data: common, table_public_inputs }
}

/// Rebuild a wire-crossing proof's [`CommonData`], or `None` when the proof's
/// own `stark_common` is intact (in-process proofs). Serialization
/// intentionally drops the lookup contexts (`serde_stark_common` in the
/// fork), so a deserialized proof carries an empty `lookups` and would fail
/// the recursive verifier's shape check; the fork's
/// `BatchStarkProver::rebuild_common_data` re-derives them from AIRs
/// reconstructed out of proof metadata. Every non-primitive any zkSketch
/// proof can carry is registered (aggregation trio + the sketch leaves'
/// permute/range), so leaves and merge roots both rebuild.
pub fn rebuilt_common_for(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> Option<CommonData<ConfigWithFriParams>> {
    let n_instances = proof.proof.opened_values.instances.len();
    if proof.stark_common.lookups.len() == n_instances {
        return None;
    }
    let mut prover = BatchStarkProver::new(make_leaf_config());
    prover.register_poseidon2_table::<EXT_D>(Poseidon2Config::GOLDILOCKS_D2_W8);
    prover.register_recompose_table::<EXT_D>(Poseidon2Config::GOLDILOCKS_D2_W8.d() != EXT_D);
    prover.register_expose_table::<EXT_D>();
    prover.register_permute_table::<EXT_D>();
    prover.register_range_table::<EXT_D>();
    Some(prover.rebuild_common_data(proof).expect("rebuild common data for deserialized proof"))
}

/// Prove a minimal leaf that exposes the given Challenge values via the Expose
/// NPO (each becomes `D` surfaced base public values).
pub fn prove_exposing_leaf(values: &[Challenge]) -> RecursionOutput<ConfigWithFriParams> {
    let config = make_leaf_config();

    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_expose(generate_expose_trace::<Val, Challenge>);
    let wires: Vec<_> = values.iter().map(|&v| b.alloc_const(v, "exposed")).collect();
    b.add_expose(&wires).expect("add_expose");
    let circuit = b.build().expect("build exposing leaf");

    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("set_public_inputs");
        runner.run().expect("run exposing circuit")
    };

    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![p3_circuit_prover::expose_preprocessor::<Val>()];
    let air_builders = p3_circuit_prover::expose_air_builders::<ConfigWithFriParams, EXT_D>();

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, EXT_D>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (exposing leaf)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_expose_table::<EXT_D>();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (exposing leaf)");
    prover.verify_all_tables(&proof).expect("self-verify exposing leaf");

    RecursionOutput(proof, Rc::new(circuit_prover_data))
}

/// Prove a boundary leaf: surface `(initial, final)` commitments via Expose.
/// Each commitment packs into `DIGEST_PACKING = 2` Challenge wires, so the
/// leaf exposes 4 wires → 8 surfaced base values laid out as
/// `[initial[0..4], final[0..4]]`.
pub fn prove_boundary_leaf(
    initial: GlCommit,
    final_: GlCommit,
) -> RecursionOutput<ConfigWithFriParams> {
    let iv = pack_commit_to_challenge(&initial);
    let fv = pack_commit_to_challenge(&final_);
    prove_exposing_leaf(&[iv[0], iv[1], fv[0], fv[1]])
}

/// The exposed statement targets of a verified child and their [`Layout`]:
/// `Boundary` = `[initial[0..4], final[0..4]]` (8 base-field targets);
/// `Interval` = additionally `[idx (lo, hi), H[0..4]]` (14 targets).
fn statement_targets(
    result: &impl VerifierCircuitResult<ConfigWithFriParams, BatchOnly>,
) -> (Layout, Vec<Target>) {
    let all = result.air_public_targets();
    all.into_iter()
        .find_map(|t| Layout::of_len(t.len(), COMMIT_LEN, EXT_D).map(|l| (l, t)))
        .expect("verified child must surface an 8-element (Boundary) or 14-element (Interval) statement")
}

/// The exposed public values of a proof's Expose table.
fn exposed_values(proof: &BatchStarkProof<ConfigWithFriParams>) -> &[Val] {
    proof
        .non_primitives
        .iter()
        .map(|e| e.public_values.as_slice())
        .find(|v| Layout::of_len(v.len(), COMMIT_LEN, EXT_D).is_some())
        .expect("proof must surface an 8-element (Boundary) or 14-element (Interval) statement")
}

/// Read the `(initial, final)` commitments a proof surfaced via its Expose
/// table (the first `2 * COMMIT_LEN` values of either layout).
pub fn read_exposed_boundary(
    output: &RecursionOutput<ConfigWithFriParams>,
) -> (GlCommit, GlCommit) {
    read_exposed_boundary_proof(&output.0)
}

/// [`read_exposed_boundary`] from a bare proof (e.g. one deserialized from a
/// peer machine's bytes).
pub fn read_exposed_boundary_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> (GlCommit, GlCommit) {
    let pv = exposed_values(proof);
    let mut initial = [Val::ZERO; COMMIT_LEN];
    let mut final_ = [Val::ZERO; COMMIT_LEN];
    initial.copy_from_slice(&pv[0..COMMIT_LEN]);
    final_.copy_from_slice(&pv[COMMIT_LEN..2 * COMMIT_LEN]);
    (GlCommit(initial), GlCommit(final_))
}

/// The full statement a proof surfaced (either layout).
pub fn read_exposed_statement(proof: &BatchStarkProof<ConfigWithFriParams>) -> Statement<Val> {
    parse_statement(exposed_values(proof), COMMIT_LEN, EXT_D).expect("statement layout")
}

/// In-circuit hiding merge of two adjacent children: verify both, bind
/// `left.final == right.initial` in-circuit, and re-expose only
/// `(left.initial, right.final)`. The returned proof surfaces exactly the
/// outer boundary `(Com_before, Com_after)`.
pub fn prove_hiding_merge(
    left: &RecursionOutput<ConfigWithFriParams>,
    right: &RecursionOutput<ConfigWithFriParams>,
) -> RecursionOutput<ConfigWithFriParams> {
    prove_hiding_merge_proofs(&left.0, &right.0)
}

/// [`prove_hiding_merge`] over bare proofs. The merge circuit consumes only
/// the children's `BatchStarkProof`s (see [`recursion_input_from_proof`]), so
/// either child may have been produced by a **different process/machine** and
/// deserialized from wire bytes — the enabling property for distributed
/// composition (each machine folds its own slice, then subtree roots cross
/// machines as serialized proofs).
pub fn prove_hiding_merge_proofs(
    left: &BatchStarkProof<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
) -> RecursionOutput<ConfigWithFriParams> {
    let config = make_leaf_config();
    let backend = make_backend();
    let params = agg_params();

    // Deserialized children carry no lookup contexts — rebuild before wiring
    // the verifier circuits (in-process children skip this, `None`).
    let left_common = rebuilt_common_for(left);
    let right_common = rebuilt_common_for(right);
    let left_input =
        recursion_input_with_common(left, left_common.as_ref().unwrap_or(&left.stark_common));
    let right_input =
        recursion_input_with_common(right, right_common.as_ref().unwrap_or(&right.stark_common));

    let (circuit, left_result, right_result) =
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Real);

    prove_aggregation_layer::<ConfigWithFriParams, BatchOnly, BatchOnly, Backend, EXT_D>(
        &left_input,
        &right_input,
        &left_result,
        &right_result,
        &circuit,
        &config,
        &backend,
        &params,
        None,
    )
    .expect("prove hiding merge")
}

/// DERIVATION ONLY: prove the twin of the hiding merge (see
/// `expose_forest::prove_twin_merge_proofs`, BabyBear).
fn prove_twin_merge_proofs(
    left: &BatchStarkProof<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
) -> BatchStarkProof<ConfigWithFriParams> {
    let config = make_leaf_config();
    let backend = make_backend();
    let params = agg_params();
    let left_input = recursion_input_from_proof(left);
    let right_input = recursion_input_from_proof(right);
    let (circuit, left_result, right_result) =
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Twin);
    prove_aggregation_layer::<ConfigWithFriParams, BatchOnly, BatchOnly, Backend, EXT_D>(
        &left_input,
        &right_input,
        &left_result,
        &right_result,
        &circuit,
        &config,
        &backend,
        &params,
        None,
    )
    .expect("prove twin merge (VK derivation)")
    .0
}

type MergeVerifierResult =
    <Backend as PcsRecursionBackend<ConfigWithFriParams, BatchOnly, EXT_D>>::VerifierResult;

/// Which merge circuit [`build_hiding_merge_circuit`] emits (see
/// `expose_forest::MergeMode`, BabyBear).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MergeMode {
    Real,
    Twin,
}

/// The hiding-merge circuit over two children (shared by
/// [`prove_hiding_merge_proofs`] and [`hiding_merge_vk`]). Layout-dispatched
/// exactly as `expose_forest::build_hiding_merge_circuit` (BabyBear): the
/// Boundary atom is unchanged op for op; the Interval atom adds the index
/// adjacency and the merge digest `H = Poseidon2([TAG_MERGE, i], [h, j], H_L, H_R)`.
fn build_hiding_merge_circuit(
    left_input: &RecursionInput<'_, ConfigWithFriParams, BatchOnly>,
    right_input: &RecursionInput<'_, ConfigWithFriParams, BatchOnly>,
    config: &ConfigWithFriParams,
    backend: &Backend,
    mode: MergeMode,
) -> (p3_circuit::Circuit<Challenge>, MergeVerifierResult, MergeVerifierResult) {
    // Assemble a custom aggregation circuit: verify both children, then bind +
    // re-expose their boundaries.
    let mut cb = CircuitBuilder::<Challenge>::new();
    cb.enable_expose(generate_expose_trace::<Val, Challenge>);
    // `prepare_circuit` enables the verifier's NPOs (challenger perm, recompose,
    // poseidon2); recompose is reused below to repack the outer boundary.
    PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::prepare_circuit(
        backend, config, &mut cb,
    )
    .expect("prepare merge circuit");

    let left_result = PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::build_verifier_circuit(
        backend, left_input, config, &mut cb,
    )
    .expect("verify left child");
    let right_result = PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::build_verifier_circuit(
        backend, right_input, config, &mut cb,
    )
    .expect("verify right child");

    // VK anchor: each verified child's preprocessed commitment (its VK) is baked
    // into this merge's circuit as constants by the recursion backend
    // (`Comm::new_const`, via `CommonDataTargets::new`), rather than left as a free
    // public input. That makes this merge's own preprocessed trace — hence its VK —
    // depend on its children's VKs, so the auditor's single trusted root-VK pin
    // ([`verify_bound_stark_proof`]) transitively anchors every child in the tree.
    // Without it a malicious prover could feed a forged child (e.g. an Expose table
    // with `is_real = 0`, decoupling the surfaced boundary from any witness) and
    // re-expose an arbitrary `(Com_before, Com_after)`.

    // [left.initial 0..4, left.final 4..8 (, idx 8..10, H 10..14)]
    let (left_layout, lb) = statement_targets(&left_result);
    let (right_layout, rb) = statement_targets(&right_result);
    assert_eq!(
        left_layout, right_layout,
        "hiding merge: children expose different statement layouts"
    );

    // (3) Contiguity, in-circuit: left.final == right.initial (4 base elements).
    // Assert via subtraction (`connect(sub(a,b), zero)`) rather than connecting
    // the two verification-created targets directly — a direct connect would
    // double-create on the WitnessChecks bus; the sub *reads* both operands so
    // the bus balances.
    let zero = cb.alloc_const(Challenge::ZERO, "zero");
    for k in 0..COMMIT_LEN {
        let diff = cb.sub(lb[COMMIT_LEN + k], rb[k]);
        cb.connect(diff, zero);
    }

    // Interval layout: index adjacency `right.lo - left.hi == 1` (the twin
    // asserts `== 0`); same op list and constant set in both modes. A
    // Goldilocks leaf pins `t < 2^32` and every `(lo, hi)` is a leaf index, so
    // this field equation cannot wrap here (it can on BabyBear; see
    // `expose_forest`).
    if left_layout == Layout::Interval {
        let one = cb.alloc_const(Challenge::ONE, "one");
        let step = if mode == MergeMode::Twin { zero } else { one };
        let (lo, hi) = (2 * COMMIT_LEN, 2 * COMMIT_LEN + 1);
        let gap = cb.sub(rb[lo], lb[hi]);
        cb.connect(gap, step);
    }

    // (4) Repack the outer boundary into 2+2 Challenge wires (each wire = 2
    // base coeffs) so the re-exposed representation stays O(1) — without the
    // repack, the surfaced values would blow up D× per layer.
    let out_init_lo = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&lb[0..2])
        .expect("recompose init_lo");
    let out_init_hi = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&lb[2..4])
        .expect("recompose init_hi");
    let out_final_lo = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&rb[COMMIT_LEN..COMMIT_LEN + 2])
        .expect("recompose final_lo");
    let out_final_hi = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&rb[COMMIT_LEN + 2..COMMIT_LEN + 4])
        .expect("recompose final_hi");

    match left_layout {
        Layout::Boundary => {
            cb.add_expose(&[out_init_lo, out_init_hi, out_final_lo, out_final_hi])
                .expect("re-expose outer boundary");
        }
        Layout::Interval => {
            let (lo, hi, h) = (2 * COMMIT_LEN, 2 * COMMIT_LEN + 1, 2 * COMMIT_LEN + EXT_D);
            let out_idx = cb
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[lb[lo], rb[hi]])
                .expect("recompose idx");
            let tag = cb.alloc_const(Challenge::from(Val::from_u64(TAG_MERGE)), "tag_merge");
            let tag_i = cb
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[tag, lb[lo]])
                .expect("recompose (tag, i)");
            let h_j = cb
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[lb[hi], rb[hi]])
                .expect("recompose (h, j)");
            let mut inputs = vec![tag_i, h_j];
            for (targets, off) in [(&lb, h), (&lb, h + 2), (&rb, h), (&rb, h + 2)] {
                inputs.push(
                    cb.recompose_base_coeffs_to_ext_via_alu::<Val>(&targets[off..off + 2])
                        .expect("recompose child digest"),
                );
            }
            let digest = cb
                .add_hash_slice(&Poseidon2Config::GOLDILOCKS_D2_W8, &inputs, true)
                .expect("merge digest");
            let mut exposed = vec![out_init_lo, out_init_hi, out_final_lo, out_final_hi, out_idx];
            exposed.extend_from_slice(&digest);
            cb.add_expose(&exposed).expect("re-expose interval statement");
        }
    }

    let circuit = cb.build().expect("build hiding-merge circuit");
    (circuit, left_result, right_result)
}

/// VK of `merge(left, right)` **without proving it** (Goldilocks analog of
/// `expose_forest::hiding_merge_vk`): builds the hiding-merge circuit and
/// commits to its preprocessed trace exactly as `prove_aggregation_layer`
/// prepares its prover data.
pub fn hiding_merge_vk(
    left: &BatchStarkProof<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
) -> Vec<Challenge> {
    let config = make_leaf_config();
    let backend = make_backend();
    let left_common = rebuilt_common_for(left);
    let right_common = rebuilt_common_for(right);
    let left_input =
        recursion_input_with_common(left, left_common.as_ref().unwrap_or(&left.stark_common));
    let right_input =
        recursion_input_with_common(right, right_common.as_ref().unwrap_or(&right.stark_common));
    let (circuit, _, _) =
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Real);
    commitment_values(&aggregation_circuit_commitment(&circuit, &config, &backend))
}

/// The preprocessed commitment object (VK) of an aggregation circuit.
fn aggregation_circuit_commitment(
    circuit: &p3_circuit::Circuit<Challenge>,
    config: &ConfigWithFriParams,
    backend: &Backend,
) -> Commitment<ConfigWithFriParams> {
    let params = agg_params();
    let preprocessors =
        PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::non_primitive_preprocessors(backend);
    let air_builders =
        PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::non_primitive_air_builders(backend);
    let (airs_degrees, _, _) = get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, EXT_D>(
        circuit,
        &params.table_packing,
        &preprocessors,
        &air_builders,
        params.constraint_profile,
    )
    .expect("get_airs_and_degrees_with_prep (merge VK)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
    prover_data
        .common
        .preprocessed
        .as_ref()
        .expect("a merge circuit has preprocessed columns")
        .commitment
        .clone()
}

/// [`vk_pin_values`] order of a preprocessed commitment object.
fn commitment_values(commitment: &Commitment<ConfigWithFriParams>) -> Vec<Challenge> {
    <MerkleCapTargets<Val, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(commitment)
}

/// A copy of `common` with its preprocessed commitment replaced by `vk`.
fn common_with_vk(
    common: &CommonData<ConfigWithFriParams>,
    vk: &Commitment<ConfigWithFriParams>,
) -> CommonData<ConfigWithFriParams> {
    let pre = common.preprocessed.as_ref().expect("a bound proof has preprocessed columns");
    CommonData::new(
        Some(GlobalPreprocessed {
            commitment: vk.clone(),
            instances: pre.instances.clone(),
            matrix_to_instance: pre.matrix_to_instance.clone(),
        }),
        common.lookups.clone(),
    )
}

/// DERIVATION: the REAL merge VK over children of the given proof shapes
/// (twin dummies allowed) and real VKs (see `expose_forest`, BabyBear).
fn hiding_merge_vk_with(
    left: &BatchStarkProof<ConfigWithFriParams>,
    left_vk: &Commitment<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
    right_vk: &Commitment<ConfigWithFriParams>,
) -> Commitment<ConfigWithFriParams> {
    let config = make_leaf_config();
    let backend = make_backend();
    let left_common = common_with_vk(
        rebuilt_common_for(left).as_ref().unwrap_or(&left.stark_common),
        left_vk,
    );
    let right_common = common_with_vk(
        rebuilt_common_for(right).as_ref().unwrap_or(&right.stark_common),
        right_vk,
    );
    let left_input = recursion_input_with_common(left, &left_common);
    let right_input = recursion_input_with_common(right, &right_common);
    let (circuit, _, _) =
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Real);
    aggregation_circuit_commitment(&circuit, &config, &backend)
}

/// Goldilocks analog of `expose_forest::root_vk_deriver`: derives root VKs of
/// any [`ForestShape`] from one no-op leaf (`initial == final`), via twin
/// dummies under the Interval layout.
pub fn root_vk_deriver(
    noop_leaf: BatchStarkProof<ConfigWithFriParams>,
) -> ShapeVkDeriver<ConfigWithFriParams, Challenge> {
    let (initial, final_) = read_exposed_boundary_proof(&noop_leaf);
    assert_eq!(initial, final_, "the VK-derivation leaf must be a no-op (initial == final boundary)");
    if let Some(iv) = read_exposed_statement(&noop_leaf).interval {
        assert_eq!(iv.lo, iv.hi, "the VK-derivation leaf must cover one batch (lo == hi)");
    }
    ShapeVkDeriver::new(
        noop_leaf,
        Box::new(prove_twin_merge_proofs),
        Box::new(hiding_merge_vk_with),
        Box::new(commitment_values),
    )
}

/// Trusted root VK of the [`prove_forest_over`] root over `t` leaves of
/// `noop_leaf`'s circuit, from public parameters only.
pub fn derive_forest_root_vk(
    noop_leaf: BatchStarkProof<ConfigWithFriParams>,
    t: usize,
) -> RootVk<Challenge> {
    root_vk_deriver(noop_leaf).root_vk(&ForestShape::forest(t))
}

/// Verify a boundary-bound proof's STARK tables (the boundary itself is read
/// from the proof via [`read_exposed_boundary`] — it is bound in-circuit, not
/// natively trusted).
///
/// LEGACY (pre-H2 `verify_bound_proof`), kept for side-by-side use: the
/// "trusted" root VK is read from the proof being verified, so the root-VK
/// pin is vacuous. An auditor calls [`verify_bound_proof`] with a VK it holds
/// independently (e.g. from [`root_vk_deriver`]).
pub fn verify_bound_proof_self_pinned_legacy(output: &RecursionOutput<ConfigWithFriParams>) {
    let expected = vk_pin_values(&output.0);
    verify_bound_stark_proof(&output.0, &expected);
}

/// Verify a boundary-bound root against an **externally supplied** trusted
/// root VK (commitment + optional metadata pin) — see
/// `expose_forest::verify_bound_proof`.
pub fn verify_bound_proof(
    output: &RecursionOutput<ConfigWithFriParams>,
    expected_root_vk: &RootVk<Challenge>,
) {
    verify_bound_stark_proof_pinned(&output.0, expected_root_vk);
}

/// [`verify_bound_stark_proof`] plus the metadata pin (`expected.shape`).
pub fn verify_bound_stark_proof_pinned(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    expected: &RootVk<Challenge>,
) {
    if let Some(shape) = &expected.shape {
        assert!(
            &bound_proof_shape(proof) == shape,
            "root proof metadata mismatch: the proof's table packing / row counts / \
             non-primitive manifest / degree bits / preprocessed layout differ from the \
             trusted root VK"
        );
    }
    verify_bound_stark_proof(proof, &expected.commitment);
}

/// Verify a boundary-bound proof against a **trusted root verification key**
/// (`expected_root_vk`, in [`vk_pin_values`] order) — the auditor path for a
/// root that arrived as serialized bytes from another machine.
///
/// The VK is a deterministic, transparent public-profile parameter the auditor
/// holds independently; it is **not** read from the (untrusted) proof. This
/// top-level pin, together with the in-circuit child-VK pins each merge applies
/// ([`pin_child_vk`]), forces the whole proof tree to be structurally honest:
/// the root VK transitively encodes every subtree's VK, so a forged leaf or
/// merge (whose VK differs) cannot appear anywhere in the tree. Panics on a VK
/// mismatch or a STARK-table failure.
pub fn verify_bound_stark_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    expected_root_vk: &[Challenge],
) {
    // (P2) Root VK anchor.
    let got = vk_pin_values(proof);
    assert!(
        got == expected_root_vk,
        "root VK mismatch: the proof's preprocessed commitment does not match the trusted \
         verification key (a forged or wrong-shape root proof)"
    );
    let config = make_leaf_config();
    let params = agg_params();
    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::GOLDILOCKS_D2_W8);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::GOLDILOCKS_D2_W8.d() != EXT_D);
    verifier.register_expose_table::<EXT_D>();
    verifier.verify_all_tables(proof).expect("verify bound proof");
}

/// Goldilocks analog of `expose_forest::check_root_against_log`.
pub fn check_root_against_log(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    log: &BatchLog<Val>,
    shape: &ForestShape,
) -> Result<(), String> {
    check_root_statement(&read_exposed_statement(proof), log, shape, &hash_gl, EXT_D)
}

/// Goldilocks analog of `expose_forest::verify_bound_stark_proof_against_log`:
/// root-VK + metadata pin, STARK verification, then the batch-log check.
pub fn verify_bound_stark_proof_against_log(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    expected_root_vk: &RootVk<Challenge>,
    log: &BatchLog<Val>,
    shape: &ForestShape,
) {
    verify_bound_stark_proof_pinned(proof, expected_root_vk);
    if let Err(e) = check_root_against_log(proof, log, shape) {
        panic!("root statement rejected against the batch log: {e}");
    }
}

// ─── Standalone LEAF verification (per-batch mode, lone leaf `t == 1`) ──────
//
// Goldilocks analog of the `expose_forest` section of the same name: a leaf
// proof that reaches the auditor directly is pinned to a trusted leaf VK
// derived from public parameters, and verified by a verifier configured from
// public parameters (never from the proof).

/// Goldilocks analog of `expose_forest::leaf_verifier`: [`make_leaf_config`]
/// plus the union of the tables the Goldilocks leaf circuits register
/// (Poseidon2 D = 2 W8, Recompose, Permute, Range, Expose).
pub fn leaf_verifier() -> BatchStarkProver<ConfigWithFriParams> {
    let mut v = BatchStarkProver::new(make_leaf_config())
        .with_table_packing(TablePacking::new(1, 1).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP));
    v.register_poseidon2_table::<EXT_D>(Poseidon2Config::GOLDILOCKS_D2_W8);
    v.register_recompose_table::<EXT_D>(Poseidon2Config::GOLDILOCKS_D2_W8.d() != EXT_D);
    v.register_permute_table::<EXT_D>();
    v.register_range_table::<EXT_D>();
    v.register_expose_table::<EXT_D>();
    v
}

/// Goldilocks analog of `expose_forest::leaf_vk`: the trusted leaf VK read off
/// a no-op leaf proof (public, data-free input).
pub fn leaf_vk(noop_leaf: &BatchStarkProof<ConfigWithFriParams>) -> RootVk<Challenge> {
    RootVk { commitment: vk_pin_values(noop_leaf), shape: Some(bound_proof_shape(noop_leaf)) }
}

/// Goldilocks analog of `expose_forest::verify_leaf_proof_pinned`.
pub fn verify_leaf_proof_pinned(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    leaf_vk: &RootVk<Challenge>,
) -> Result<(), String> {
    pin_and_verify_leaf(&leaf_verifier(), proof, leaf_vk)
}

fn pin_and_verify_leaf(
    verifier: &BatchStarkProver<ConfigWithFriParams>,
    proof: &BatchStarkProof<ConfigWithFriParams>,
    leaf_vk: &RootVk<Challenge>,
) -> Result<(), String> {
    if let Some(shape) = &leaf_vk.shape {
        if &bound_proof_shape(proof) != shape {
            return Err("leaf proof metadata (table packing / rows / non-primitive manifest / \
                        degree bits / preprocessed layout) differs from the trusted leaf VK"
                .into());
        }
    }
    if vk_pin_values(proof) != leaf_vk.commitment {
        return Err("leaf VK mismatch: the proof's preprocessed commitment is not the trusted \
                    leaf circuit's (a proof of a different circuit)"
            .into());
    }
    verifier
        .verify_all_tables_for_field::<Challenge>(proof)
        .map_err(|e| format!("leaf STARK rejected: {e:?}"))
}

/// Goldilocks analog of `expose_forest::verify_leaves_against_log`.
pub fn verify_leaves_against_log(
    proofs: &[&BatchStarkProof<ConfigWithFriParams>],
    leaf_vk: &RootVk<Challenge>,
    log: &BatchLog<Val>,
    layout: Expose,
) -> Result<(), String> {
    let verifier = leaf_verifier();
    for (i, p) in proofs.iter().enumerate() {
        pin_and_verify_leaf(&verifier, p, leaf_vk).map_err(|e| format!("leaf {}: {e}", i + 1))?;
    }
    check_leaves_against_log(proofs, log, layout)
}

/// Goldilocks analog of `expose_forest::check_leaves_against_log` (values
/// only; authenticates nothing on its own).
pub fn check_leaves_against_log(
    proofs: &[&BatchStarkProof<ConfigWithFriParams>],
    log: &BatchLog<Val>,
    layout: Expose,
) -> Result<(), String> {
    let stmts: Vec<Statement<Val>> = proofs.iter().map(|p| read_exposed_statement(p)).collect();
    check_leaf_statements_against_log(&stmts, log, layout, &hash_gl, EXT_D)
}

/// The published log of a Goldilocks stream.
pub fn batch_log(
    init: &[Val; COMMIT_LEN],
    final_: &[Val; COMMIT_LEN],
    batch_commits: &[[Val; COMMIT_LEN]],
) -> BatchLog<Val> {
    BatchLog {
        init: init.to_vec(),
        final_: final_.to_vec(),
        batch_commits: batch_commits.iter().map(|c| c.to_vec()).collect(),
    }
}

/// Bentley–Saxe cascade over boundary leaves, producing one root proof whose
/// surfaced public values are exactly `(Com(S_0), Com(S_E))`, bound in-circuit.
/// `commits` is the boundary chain `[Com(S_0), Com(S_1), ..., Com(S_E)]`
/// (`E + 1` entries); leaf `i` exposes `(commits[i], commits[i+1])`.
pub fn prove_bound_forest(commits: &[GlCommit]) -> RecursionOutput<ConfigWithFriParams> {
    assert!(commits.len() >= 3, "need >= 2 leaves (>= 3 boundary commits)");
    let leaves: Vec<_> = (0..commits.len() - 1)
        .map(|i| prove_boundary_leaf(commits[i], commits[i + 1]))
        .collect();
    prove_forest_over(leaves)
}

/// Bentley–Saxe cascade over **any** boundary-exposing leaves (boundary leaves
/// or real Count-Min v9-exposed leaves — see
/// `prove_countmin_leaf_v9_exposed_with_params`). Adjacent leaves must form a
/// contiguous boundary chain; the hiding merge enforces it in-circuit. The
/// returned root surfaces exactly `(Com(S_0), Com(S_E))`.
pub fn prove_forest_over(
    leaves: Vec<RecursionOutput<ConfigWithFriParams>>,
) -> RecursionOutput<ConfigWithFriParams> {
    assert!(leaves.len() >= 2, "need >= 2 leaves");
    // (size, output) subtree stack — binary-counter cascade.
    let mut roots: Vec<(u64, RecursionOutput<ConfigWithFriParams>)> = Vec::new();
    for leaf in leaves {
        let mut node = (1u64, leaf);
        while let Some((sz, _)) = roots.last() {
            if *sz == node.0 {
                let (_, left) = roots.pop().unwrap();
                let merged = prove_hiding_merge(&left, &node.1);
                node = (node.0 * 2, merged);
            } else {
                break;
            }
        }
        roots.push(node);
    }
    // Finalize: chain surviving roots left-to-right.
    let mut acc = roots.remove(0).1;
    for (_, r) in roots {
        acc = prove_hiding_merge(&acc, &r);
    }
    acc
}

/// Left-leaning **linear chain** fold over any boundary-exposing leaves — the
/// family-agnostic analog of `countmin_chain_v9::prove_countmin_chain_v9`, but
/// consuming the same exposed `RecursionOutput` leaves as [`prove_forest_over`].
/// Folds `Π^(t) = merge(Π^(t-1), leaf_t)` strictly left-to-right (`O(t)` depth,
/// vs the tree's `O(log t)`), so it is the sequential comparison baseline for the
/// streaming forest. Same in-circuit child verification + boundary binding per
/// merge as the tree; the returned root surfaces exactly `(Com(S_0), Com(S_E))`
/// and verifies with [`verify_bound_proof`].
pub fn prove_chain_over(
    leaves: Vec<RecursionOutput<ConfigWithFriParams>>,
) -> RecursionOutput<ConfigWithFriParams> {
    assert!(leaves.len() >= 2, "need >= 2 leaves");
    let mut iter = leaves.into_iter();
    let mut acc = iter.next().unwrap();
    for leaf in iter {
        acc = prove_hiding_merge(&acc, &leaf);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REAL Goldilocks Greenwald–Khanna (band-merge) bound forest: two
    /// `gk_bandmerge_gl` exposed leaves composed via the hiding merge; the root
    /// surfaces only the real `(Com(S_0), Com(S_2))`, bound in-circuit, and
    /// natively self-verifies. This is the end-to-end Goldilocks forest the
    /// `gk_gl` experiment token runs.
    #[test]
    fn real_gk_gl_bound_forest() {
        use crate::sketch::gk_bandmerge_gl::{
            GkbParams, Gk2State, apply_batch2, commit_gk2_state, prove_gkb2_exposed,
        };
        let params = GkbParams {
            capacity: 8,
            batch: 4,
            s: 2,
        };
        let s0 = Gk2State::empty(params);
        let b1 = vec![50u32, 100, 200, 300];
        let leaf1 = prove_gkb2_exposed(params, s0.clone(), b1.clone());
        let s1 = apply_batch2(&s0, &b1);
        let b2 = vec![60u32, 110, 210, 310];
        let leaf2 = prove_gkb2_exposed(params, s1.clone(), b2.clone());
        let s2 = apply_batch2(&s1, &b2);

        // Trusted root VK derived from a public no-op leaf, never read from
        // the root proof.
        let root_vk = derive_forest_root_vk(prove_gkb2_exposed(params, Gk2State::empty(params), Vec::new()).output.0, 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_gk2_state(&s0).0, "root initial = Com(S_0)");
        assert_eq!(final_.0, commit_gk2_state(&s2).0, "root final = Com(S_2)");
    }

    /// REAL Goldilocks SpaceSaving bound forest: two `ss_final_full_gl` exposed
    /// leaves — the `ss_gl` experiment token's forest path.
    #[test]
    fn real_ss_gl_bound_forest() {
        use crate::sketch::ss_final_full_gl::{
            SsFullParams, SsFullState, SsFullUpdate, apply_batch_ss_full, commit_ss_state,
            prove_ss_full_exposed,
        };
        let params = SsFullParams {
            capacity: 4,
            batch: 2,
        };
        let s0 = SsFullState::empty(params);
        let b1 = vec![SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)];
        let leaf1 = prove_ss_full_exposed(params, s0.clone(), b1.clone());
        let (s1, _) = apply_batch_ss_full(&s0, &b1);
        let b2 = vec![SsFullUpdate::real(13, 1), SsFullUpdate::real(7, 1)];
        let leaf2 = prove_ss_full_exposed(params, s1.clone(), b2.clone());
        let (s2, _) = apply_batch_ss_full(&s1, &b2);

        // Trusted root VK derived from a public no-op leaf, never read from
        // the root proof.
        let root_vk = derive_forest_root_vk(prove_ss_full_exposed(params, SsFullState::empty(params), vec![SsFullUpdate::dummy(); 2]).output.0, 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_ss_state(&s0).0, "root initial = Com(S_0)");
        assert_eq!(final_.0, commit_ss_state(&s2).0, "root final = Com(S_2)");
    }

    /// REAL Goldilocks HyperLogLog (omc) bound forest: two `hll_omc_gl` exposed
    /// leaves chained through a real intermediate register array — the `hll_gl`
    /// experiment token's forest path.
    #[test]
    fn real_hll_gl_bound_forest() {
        use crate::sketch::hll_omc_gl::{
            HllOmcParams, commit_hll_omc, hll_omc_advance, hll_omc_empty, prove_hll_omc_exposed,
        };
        let params = HllOmcParams { b: 3, batch: 4 };
        let m = params.m();
        let s0 = hll_omc_empty(params.b);
        let b1: Vec<u64> = vec![7, 11, 13, 17];
        let leaf1 = prove_hll_omc_exposed(params, s0.clone(), b1.clone());
        let mut s1 = s0.clone();
        hll_omc_advance(&mut s1, &b1, m);
        let b2: Vec<u64> = vec![19, 7, 23, 29];
        let leaf2 = prove_hll_omc_exposed(params, s1.clone(), b2.clone());
        let mut s2 = s1.clone();
        hll_omc_advance(&mut s2, &b2, m);

        // Trusted root VK derived from a public no-op leaf (re-inserting a key
        // already present — `max` is idempotent), never read from the root.
        let mut s7 = hll_omc_empty(params.b);
        hll_omc_advance(&mut s7, &[7], m);
        let noop = prove_hll_omc_exposed(params, s7, vec![7; params.batch]).output.0;
        let root_vk = derive_forest_root_vk(noop, 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(
            initial.0,
            commit_hll_omc(&s0, params.b),
            "root initial = Com(S_0)"
        );
        assert_eq!(
            final_.0,
            commit_hll_omc(&s2, params.b),
            "root final = Com(S_2)"
        );
    }

    /// REAL Goldilocks Count-Min (omc) bound forest: two `countmin_omc_gl`
    /// exposed leaves chained through a real intermediate state — the `cm_gl`
    /// experiment token's forest path.
    #[test]
    fn real_cm_gl_bound_forest() {
        use crate::sketch::countmin::CountMinUpdate;
        use crate::sketch::countmin_omc_gl::{
            CmOmcParams, apply_update_prf, cm_gl_empty, commit_countmin,
            prove_countmin_omc_exposed,
        };
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        let s0 = cm_gl_empty(2, 4);
        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let leaf1 = prove_countmin_omc_exposed(params, s0.clone(), b1.clone());
        let mut s1 = s0.clone();
        for u in &b1 {
            apply_update_prf(&mut s1, u);
        }
        let b2 = vec![
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let leaf2 = prove_countmin_omc_exposed(params, s1.clone(), b2.clone());
        let mut s2 = s1.clone();
        for u in &b2 {
            apply_update_prf(&mut s2, u);
        }

        // Trusted root VK derived from a public no-op leaf, never read from
        // the root proof.
        let root_vk = derive_forest_root_vk(prove_countmin_omc_exposed(params, cm_gl_empty(2, 4), vec![CountMinUpdate { key: 0, value: 0 }; 2]).output.0, 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_countmin(&s0).0, "root initial = Com(S_0)");
        assert_eq!(final_.0, commit_countmin(&s2).0, "root final = Com(S_2)");
    }
}
