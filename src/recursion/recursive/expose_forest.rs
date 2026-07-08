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

use std::rc::Rc;

use p3_batch_stark::{CommonData, ProverData};
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

use crate::commitment::countmin::CountMinCommit;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, DIGEST_ELEMS, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::{make_leaf_config, pack_commit_to_challenge};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Number of base-field elements per commitment (`CountMinCommit` is `[Val; 8]`).
const COMMIT_LEN: usize = 8;

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
    prover.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
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
/// leaf exposes 4 wires → 16 surfaced base values laid out as
/// `[initial[0..8], final[0..8]]`.
pub fn prove_boundary_leaf(
    initial: CountMinCommit,
    final_: CountMinCommit,
) -> RecursionOutput<ConfigWithFriParams> {
    let iv = pack_commit_to_challenge(&initial);
    let fv = pack_commit_to_challenge(&final_);
    prove_exposing_leaf(&[iv[0], iv[1], fv[0], fv[1]])
}

/// The exposed boundary targets of a verified child: the (unique) non-empty
/// per-instance `air_public_targets` entry — `[initial[0..8], final[0..8]]`
/// (16 base-field targets).
fn boundary_targets(result: &impl VerifierCircuitResult<ConfigWithFriParams, BatchOnly>) -> Vec<Target> {
    let all = result.air_public_targets();
    all.into_iter()
        .find(|t| t.len() == 2 * COMMIT_LEN)
        .expect("verified child must surface a 16-element (initial, final) boundary")
}

/// Read the `(initial, final)` commitments a proof surfaced via its Expose
/// table (the unique non-primitive with `2 * COMMIT_LEN` public values).
pub fn read_exposed_boundary(
    output: &RecursionOutput<ConfigWithFriParams>,
) -> (CountMinCommit, CountMinCommit) {
    read_exposed_boundary_proof(&output.0)
}

/// [`read_exposed_boundary`] from a bare proof (e.g. one deserialized from a
/// peer machine's bytes).
pub fn read_exposed_boundary_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> (CountMinCommit, CountMinCommit) {
    let pv = proof
        .non_primitives
        .iter()
        .map(|e| &e.public_values)
        .find(|v| v.len() == 2 * COMMIT_LEN)
        .expect("proof must surface a 16-element boundary");
    let mut initial = [Val::ZERO; COMMIT_LEN];
    let mut final_ = [Val::ZERO; COMMIT_LEN];
    initial.copy_from_slice(&pv[0..COMMIT_LEN]);
    final_.copy_from_slice(&pv[COMMIT_LEN..2 * COMMIT_LEN]);
    (CountMinCommit(initial), CountMinCommit(final_))
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

    // Assemble a custom aggregation circuit: verify both children, then bind +
    // re-expose their boundaries.
    let mut cb = CircuitBuilder::<Challenge>::new();
    cb.enable_expose(generate_expose_trace::<Val, Challenge>);
    // `prepare_circuit` enables the verifier's NPOs (challenger perm, recompose,
    // poseidon2); recompose is reused below to repack the outer boundary.
    PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::prepare_circuit(
        &backend, &config, &mut cb,
    )
    .expect("prepare merge circuit");

    let left_result = PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::build_verifier_circuit(
        &backend, &left_input, &config, &mut cb,
    )
    .expect("verify left child");
    let right_result = PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::build_verifier_circuit(
        &backend, &right_input, &config, &mut cb,
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

    let lb = boundary_targets(&left_result); // [left.initial 0..8, left.final 8..16]
    let rb = boundary_targets(&right_result); // [right.initial 0..8, right.final 8..16]

    // (3) Contiguity, in-circuit: left.final == right.initial (8 base elements).
    // Assert via subtraction (`connect(sub(a,b), zero)`) rather than connecting
    // the two verification-created targets directly — a direct connect would
    // double-create on the WitnessChecks bus; the sub *reads* both operands so
    // the bus balances.
    let zero = cb.alloc_const(Challenge::ZERO, "zero");
    for k in 0..COMMIT_LEN {
        let diff = cb.sub(lb[COMMIT_LEN + k], rb[k]);
        cb.connect(diff, zero);
    }

    // (4) Repack the outer boundary into 2+2 Challenge wires (each wire = 4
    // base coeffs) so the re-exposed representation stays O(1) — without the
    // repack, the surfaced values would blow up D× per layer.
    let out_init_lo = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&lb[0..4])
        .expect("recompose init_lo");
    let out_init_hi = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&lb[4..8])
        .expect("recompose init_hi");
    let out_final_lo = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&rb[COMMIT_LEN..COMMIT_LEN + 4])
        .expect("recompose final_lo");
    let out_final_hi = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&rb[COMMIT_LEN + 4..COMMIT_LEN + 8])
        .expect("recompose final_hi");

    cb.add_expose(&[out_init_lo, out_init_hi, out_final_lo, out_final_hi])
        .expect("re-expose outer boundary");

    let circuit = cb.build().expect("build hiding-merge circuit");

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

/// Verify a boundary-bound proof's STARK tables (the boundary itself is read
/// from the proof via [`read_exposed_boundary`] — it is bound in-circuit, not
/// natively trusted).
///
/// In-process convenience for the honest producer: the trusted root VK is the
/// honestly produced root's own VK. A cross-machine auditor instead calls
/// [`verify_bound_stark_proof`] with a trusted VK it holds independently (from
/// the declared public profile), which is what actually anchors the root.
pub fn verify_bound_proof(output: &RecursionOutput<ConfigWithFriParams>) {
    let expected = vk_pin_values(&output.0);
    verify_bound_stark_proof(&output.0, &expected);
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
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier.register_expose_table::<EXT_D>();
    verifier.verify_all_tables(proof).expect("verify bound proof");
}

/// Bentley–Saxe cascade over boundary leaves, producing one root proof whose
/// surfaced public values are exactly `(Com(S_0), Com(S_E))`, bound in-circuit.
/// `commits` is the boundary chain `[Com(S_0), Com(S_1), ..., Com(S_E)]`
/// (`E + 1` entries); leaf `i` exposes `(commits[i], commits[i+1])`.
pub fn prove_bound_forest(commits: &[CountMinCommit]) -> RecursionOutput<ConfigWithFriParams> {
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
    use p3_recursion::{build_aggregation_layer_circuit, build_and_prove_aggregation_layer};

    /// AUDIT EXPERIMENT: does a const VALUE land in the VK (preprocessed
    /// commitment), or only in the main-trace commitment? Two structurally
    /// identical exposing leaves that differ ONLY in their exposed (const)
    /// values. If the VKs are equal while the trace commitments differ, then
    /// const values are NOT part of the VK -> baking a child commitment as a
    /// const does not make the child's commitment VALUE part of the parent VK.
    #[test]
    fn audit_const_value_independence_of_vk() {
        use p3_field::PrimeCharacteristicRing;
        let a = prove_exposing_leaf(&[
            Challenge::from(Val::from_u32(0x1111_1111)),
            Challenge::from(Val::from_u32(0x2222_2222)),
        ]);
        let b = prove_exposing_leaf(&[
            Challenge::from(Val::from_u32(0x3333_3333)),
            Challenge::from(Val::from_u32(0x4444_4444)),
        ]);
        let vk_a = vk_pin_values(&a.0);
        let vk_b = vk_pin_values(&b.0);
        let trace = |p: &BatchStarkProof<ConfigWithFriParams>| {
            <MerkleCapTargets<Val, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(
                &p.proof.commitments.main,
            )
        };
        let tr_a = trace(&a.0);
        let tr_b = trace(&b.0);
        println!("AUDIT VK_EQUAL={}", vk_a == vk_b);
        println!("AUDIT TRACE_EQUAL={}", tr_a == tr_b);
        assert_ne!(tr_a, tr_b, "sanity: different const values must change the main-trace commitment");
        // The load-bearing observation for the audit:
        assert_eq!(
            vk_a, vk_b,
            "AUDIT: const values do NOT affect the VK (preprocessed commitment)"
        );
    }

    /// VALIDATION GATE: a value exposed via the Expose NPO surfaces as the
    /// aggregation's public input (unlike a primitive `public_input`) AND the
    /// aggregation verifies. Confirms the `public_values → air_public_targets
    /// → recursion` pathway works.
    #[test]
    fn expose_value_surfaces_through_aggregation() {
        let v0 = Challenge::from(Val::from_u32(0x1234_5678));
        let v1 = Challenge::from(Val::from_u32(0x0BAD_F00D));
        let left = prove_exposing_leaf(&[v0, v1]);
        let right = prove_exposing_leaf(&[v0, v1]);

        let config = make_leaf_config();
        let backend = make_backend();
        let left_input = recursion_input_with_public_values(&left);
        let right_input = recursion_input_with_public_values(&right);

        let (_circuit, (lr, _rr)) = build_aggregation_layer_circuit::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            EXT_D,
        >(&left_input, &right_input, &config, &backend)
        .expect("build aggregation circuit");
        let lpis = lr.pack_public_inputs(&left_input).expect("left pis");
        assert!(lpis.contains(&v0) && lpis.contains(&v1), "exposed values must surface");

        let params = agg_params();
        let out = build_and_prove_aggregation_layer::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            EXT_D,
        >(&left_input, &right_input, &config, &backend, &params, None)
        .expect("aggregate exposing leaves");
        verify_bound_proof(&out);
    }

    /// Deterministic synthetic boundary commitment for state index `k`.
    fn commit(k: u64) -> CountMinCommit {
        CountMinCommit(std::array::from_fn(|i| {
            Val::from_u64(k.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64) + 1)
        }))
    }

    /// 2-leaf hiding merge: the merged proof surfaces ONLY the outer boundary
    /// (Com(S_0), Com(S_2)) — bound in-circuit — and verifies.
    #[test]
    fn hiding_merge_exposes_only_outer_boundary() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let merged = prove_hiding_merge(&l0, &l1);
        verify_bound_proof(&merged);

        let (initial, final_) = read_exposed_boundary(&merged);
        assert_eq!(initial, commit(0), "outer initial = Com(S_0)");
        assert_eq!(final_, commit(2), "outer final = Com(S_2)");
    }

    /// A boundary break is rejected in-circuit (the `connect` is unsatisfiable),
    /// so the merge prover fails — contiguity is enforced by the proof, not a
    /// native check.
    #[test]
    #[should_panic]
    fn hiding_merge_rejects_boundary_break() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        // l1 starts from commit(99), not commit(1) — non-contiguous.
        let l1 = prove_boundary_leaf(commit(99), commit(2));
        let _ = prove_hiding_merge(&l0, &l1);
    }

    /// VK ANCHOR (accept): the honest root verifies against its own trusted VK.
    #[test]
    fn root_vk_pin_accepts_correct_vk() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let merged = prove_hiding_merge(&l0, &l1);
        let root_vk = vk_pin_values(&merged.0);
        verify_bound_stark_proof(&merged.0, &root_vk); // must not panic
    }

    /// VK ANCHOR (reject): the auditor's trusted root-VK pin rejects a proof
    /// whose preprocessed commitment does not equal the expected verification
    /// key — a forged or wrong-circuit root. A leaf's VK differs from a merge's,
    /// so verifying a merge proof against a leaf VK must be rejected. This is the
    /// single trusted check that, together with each merge baking its children's
    /// VKs into its own preprocessed trace, transitively anchors the whole tree.
    #[test]
    #[should_panic(expected = "root VK mismatch")]
    fn root_vk_pin_rejects_wrong_vk() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let merged = prove_hiding_merge(&l0, &l1);
        let leaf_vk = vk_pin_values(&l0.0); // a leaf VK != the merge (root) VK
        verify_bound_stark_proof(&merged.0, &leaf_vk);
    }

    /// VK ANCHOR (distinctness): the verification keys of the distinct circuit
    /// types in a forest are all different — a leaf, a one-level merge (over two
    /// leaves), and a two-level merge (over two one-level merges). This is a
    /// necessary property for the root-VK pin to distinguish circuits.
    ///
    /// The *baking* property itself — that a merge's VK now depends on its
    /// children's VKs (via `Comm::new_const`, versus the pre-fix bug where child
    /// VKs were free public inputs outside the parent's preprocessed) — was
    /// confirmed empirically against the pre-fix commitments: the leaf VK is
    /// unchanged (a leaf verifies no children) while every merge VK changed once
    /// its children's commitments became preprocessed constants.
    #[test]
    fn merge_vk_depends_on_children() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let l2 = prove_boundary_leaf(commit(2), commit(3));
        let l3 = prove_boundary_leaf(commit(3), commit(4));
        let leaf_vk = vk_pin_values(&l0.0);
        let m01 = prove_hiding_merge(&l0, &l1); // level-1: children are leaves
        let m23 = prove_hiding_merge(&l2, &l3);
        let root = prove_hiding_merge(&m01, &m23); // level-2: children are merges
        let m01_vk = vk_pin_values(&m01.0);
        let root_vk = vk_pin_values(&root.0);
        assert_ne!(leaf_vk, m01_vk, "leaf VK must differ from a merge VK");
        assert_ne!(m01_vk, root_vk, "a level-2 merge VK must differ from level-1");
    }

    /// REAL Count-Min bound forest: two v9-exposed CM leaves (proving actual
    /// sketch updates) composed via the hiding merge. The root surfaces ONLY
    /// the real outer boundary (Com(S_0), Com(S_2)) — bound in-circuit.
    #[test]
    fn real_v9_bound_forest_exposes_outer_boundary() {
        use crate::commitment::countmin::commit_countmin;
        use crate::recursion::recursive::countmin_leaf::{CountMinLeafParams, D, W};
        use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_exposed_with_params;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_v9::CountMinV9;

        let params = CountMinLeafParams::default(); // (d, w, batch) = (2, 4, 2)
        let mut s = CountMinV9::new(&CountMinParams { d: D, w: W });
        let c0 = commit_countmin(&s);

        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let leaf1 = prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b1.clone());
        for u in &b1 {
            CountMinV9::update(&mut s, u);
        }

        let b2 = vec![
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let leaf2 = prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b2.clone());
        for u in &b2 {
            CountMinV9::update(&mut s, u);
        }
        let c2 = commit_countmin(&s);

        // Sanity: the leaves expose their real commitments.
        assert_eq!(read_exposed_boundary(&leaf1.output).0, c0);

        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial, c0, "root initial = real Com(S_0)");
        assert_eq!(final_, c2, "root final = real Com(S_2)");
    }

    /// REAL HyperLogLog bound forest: two `hll_final_full` exposed leaves
    /// (real §A update circuit) composed via the hiding merge; root surfaces
    /// only the real (Com(S_0), Com(S_2)), bound in-circuit.
    #[test]
    fn real_hll_bound_forest_exposes_outer_boundary() {
        use crate::sketch::hll_final_full::{
            HllFullParams, HllFullState, HllFullUpdate, apply_batch, commit_hll_state,
            prove_hll_full_exposed,
        };
        let params = HllFullParams { b: 4, batch: 2 };
        let s0 = HllFullState::empty(params);
        let b1 = vec![HllFullUpdate::real(7), HllFullUpdate::real(11)];
        let leaf1 = prove_hll_full_exposed(params, s0.clone(), b1.clone());
        let s1 = apply_batch(&s0, &b1);
        let b2 = vec![HllFullUpdate::real(13), HllFullUpdate::real(7)];
        let leaf2 = prove_hll_full_exposed(params, s1.clone(), b2.clone());
        let s2 = apply_batch(&s1, &b2);

        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_hll_state(&s0).0, "root initial = real Com(S_0)");
        assert_eq!(final_.0, commit_hll_state(&s2).0, "root final = real Com(S_2)");
    }

    /// REAL SpaceSaving bound forest: two `ss_final_full` exposed leaves.
    #[test]
    fn real_ss_bound_forest_exposes_outer_boundary() {
        use crate::sketch::ss_final_full::{
            SsFullParams, SsFullState, SsFullUpdate, apply_batch_ss_full, commit_ss_state,
            prove_ss_full_exposed,
        };
        let params = SsFullParams { capacity: 4, batch: 2 };
        let s0 = SsFullState::empty(params);
        let b1 = vec![SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)];
        let leaf1 = prove_ss_full_exposed(params, s0.clone(), b1.clone());
        let (s1, _) = apply_batch_ss_full(&s0, &b1);
        let b2 = vec![SsFullUpdate::real(13, 1), SsFullUpdate::real(7, 1)];
        let leaf2 = prove_ss_full_exposed(params, s1.clone(), b2.clone());
        let (s2, _) = apply_batch_ss_full(&s1, &b2);

        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_ss_state(&s0).0, "root initial = real Com(S_0)");
        assert_eq!(final_.0, commit_ss_state(&s2).0, "root final = real Com(S_2)");
    }

    /// REAL Greenwald--Khanna bound forest: two `gk_final_full` exposed leaves.
    #[test]
    fn real_gk_bound_forest_exposes_outer_boundary() {
        use crate::sketch::gk_final_full::{
            GKFullParams, GKFullState, GKFullUpdate, apply_batch_full, commit_gk_state,
            prove_gk_full_exposed,
        };
        let params = GKFullParams { capacity: 4, batch: 2 };
        let s0 = GKFullState::empty(params);
        let b1 = vec![GKFullUpdate::real(10), GKFullUpdate::real(11)];
        let leaf1 = prove_gk_full_exposed(params, s0.clone(), b1.clone());
        let (s1, _) = apply_batch_full(&s0, &b1);
        let b2 = vec![GKFullUpdate::real(20), GKFullUpdate::real(21)];
        let leaf2 = prove_gk_full_exposed(params, s1.clone(), b2.clone());
        let (s2, _) = apply_batch_full(&s1, &b2);

        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_gk_state(&s0).0, "root initial = real Com(S_0)");
        assert_eq!(final_.0, commit_gk_state(&s2).0, "root final = real Com(S_2)");
    }

    /// Two-sided band-merge (bandmerge2) leaf, boundary-exposed via the NEW
    /// `prove_gkb2_exposed`: the generic forest fold composes two real gk2 leaves
    /// and surfaces the outer boundary — confirms the added Expose wiring is
    /// sound and the gk2 leaf is foldable by the family-agnostic path.
    #[test]
    fn real_gk2_bandmerge_bound_forest_exposes_outer_boundary() {
        use crate::sketch::gk_bandmerge::{
            apply_batch2, commit_gk2_state, prove_gkb2_exposed, Gk2State, GkbParams,
        };
        let params = GkbParams { capacity: 4, batch: 2, s: 2 };
        let s0 = Gk2State::empty(params);
        let b1 = vec![10u32, 11];
        let leaf1 = prove_gkb2_exposed(params, s0.clone(), b1.clone());
        let s1 = apply_batch2(&s0, &b1);
        let b2 = vec![20u32, 21];
        let leaf2 = prove_gkb2_exposed(params, s1.clone(), b2.clone());
        let s2 = apply_batch2(&s1, &b2);

        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_gk2_state(&s0).0, "root initial = real Com(S_0)");
        assert_eq!(final_.0, commit_gk2_state(&s2).0, "root final = real Com(S_2)");
    }

    /// WIRE-MERGEABILITY GATE (distributed composition): proofs round-trip
    /// through postcard serialization and merge as bare `BatchStarkProof`s —
    /// no `CircuitProverData` from the producing context. This is exactly what
    /// a multi-machine deployment does: leaves/subtree roots cross machines as
    /// bytes and the receiving machine folds them. A regression here breaks
    /// `experiments::dist_compose`.
    #[test]
    fn merge_from_deserialized_proof_bytes() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));

        // Simulate the machine boundary: serialize, drop the originals'
        // prover halves, deserialize on "the other side".
        let b0 = postcard::to_allocvec(&l0.0).expect("serialize left");
        let b1 = postcard::to_allocvec(&l1.0).expect("serialize right");
        drop((l0, l1));
        let p0: BatchStarkProof<ConfigWithFriParams> =
            postcard::from_bytes(&b0).expect("deserialize left");
        let p1: BatchStarkProof<ConfigWithFriParams> =
            postcard::from_bytes(&b1).expect("deserialize right");

        let merged = prove_hiding_merge_proofs(&p0, &p1);
        verify_bound_proof(&merged);
        let (initial, final_) = read_exposed_boundary(&merged);
        assert_eq!(initial, commit(0), "outer initial survives the wire");
        assert_eq!(final_, commit(2), "outer final survives the wire");

        // Second hop: the merged root itself round-trips and re-merges (the
        // forest's cross-machine reduction rounds fold fold-outputs).
        let rb = postcard::to_allocvec(&merged.0).expect("serialize root");
        let rp: BatchStarkProof<ConfigWithFriParams> =
            postcard::from_bytes(&rb).expect("deserialize root");
        let l2 = prove_boundary_leaf(commit(2), commit(3));
        let l3 = prove_boundary_leaf(commit(3), commit(4));
        let right = prove_hiding_merge(&l2, &l3);
        let root = prove_hiding_merge_proofs(&rp, &right.0);
        verify_bound_proof(&root);
        let (ri, rf) = read_exposed_boundary(&root);
        assert_eq!((ri, rf), (commit(0), commit(4)), "fold-of-folds over the wire");
    }

    /// 4-leaf bound forest (exercises `agg + agg`): the single root proof
    /// surfaces ONLY (Com(S_0), Com(S_4)), bound in-circuit, and verifies.
    #[test]
    fn bound_forest_four_exposes_only_outer() {
        let commits: Vec<_> = (0..=4).map(commit).collect();
        let root = prove_bound_forest(&commits);
        verify_bound_proof(&root);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial, commit(0), "root initial = Com(S_0)");
        assert_eq!(final_, commit(4), "root final = Com(S_4)");
    }

    /// AUDIT PROBE (bypass hunter): a leaf's VK (preprocessed commitment) is
    /// INVARIANT to the `alloc_const` values it exposes.
    #[test]
    fn probe_leaf_vk_ignores_exposed_const_value() {
        let a = prove_boundary_leaf(commit(0), commit(1));
        let b = prove_boundary_leaf(commit(40), commit(41));
        let vk_a = vk_pin_values(&a.0);
        let vk_b = vk_pin_values(&b.0);
        assert_ne!(read_exposed_boundary(&a), read_exposed_boundary(&b));
        assert_eq!(vk_a, vk_b, "leaf VK must be independent of the exposed const values");
    }

}
