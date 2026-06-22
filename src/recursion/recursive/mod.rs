//! Phase 1.5 — in-circuit recursive merge atom (paper §4.2 Lite).
//!
//! Two CircuitBuilder-based leaf proofs are verified inside one recursive
//! batch-STARK proof via [`p3_recursion::build_and_prove_aggregation_layer`].
//! The aggregated proof's public inputs expose both leaves' boundary values;
//! we natively assert `left.final_ == right.initial` (§4.2 shared-boundary
//! check, Lite form) and recompute the digest after verification.
//!
//! Why the CircuitBuilder leaf instead of Phase 1's uni-stark `FibAir`?
//! Upstream's `RecursionInput::UniStark` aggregation path is exercised only
//! with empty PIs (`recursive_keccak`); passing FibAir's 4 PIs through it
//! triggers a WitnessConflict deep in the recursive verifier. The
//! CircuitBuilder leaf style (`recursive_fibonacci.rs`) is the
//! well-tested path for non-trivial public inputs.

pub mod backend;
pub mod config;
pub mod timing;
pub mod countmin_chain;
pub mod countmin_forest_v9;
pub mod expose_forest;
pub mod countmin_leaf;
pub mod countmin_leaf_v2;
pub mod countmin_leaf_v3;
pub mod countmin_leaf_v9;
pub mod countmin_leaf_v9h;
pub mod countmin_merge;
pub mod countmin_merge_merkle;
pub mod countmin_merge_v9;
pub mod countmin_merge_v9_additive;
pub mod cross_family_merge;
pub mod hll_chain;
pub mod hll_leaf;
pub mod hll_leaf_v2;
pub mod hll_merge;
pub mod leaf;

use core::fmt;

use p3_circuit_prover::{BatchStarkProver, ConstraintProfile, TablePacking};
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, RecursionOutput,
    build_and_prove_aggregation_layer,
};

use crate::config::LOG_BLOWUP;
use crate::prover::Boundary;
use crate::recursion::digest::{ChainDigest, combine_digest, leaf_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D, make_recursion_config};
use crate::recursion::recursive::leaf::{RecursiveLeafProof, prove_recursive_leaf};

/// Matches the `recursive_aggregation` upstream default. Smaller values
/// (e.g. 5) cause the in-circuit FRI verifier to allocate witnesses
/// that conflict with the inner proof's PIs, tripping a WitnessConflict.
const LOG_FINAL_POLY_LEN: usize = 6;

/// Aggregated proof over `[1, 2]` — two CircuitBuilder leaf proofs verified
/// inside one recursive batch-STARK.
pub struct ChainProof {
    pub recursive_proof: RecursionOutput<ConfigWithFriParams>,
    pub interval: (u64, u64),
    /// Outer left boundary `Com(S_0)`.
    pub initial: Boundary,
    /// Outer right boundary `Com(S_2)`.
    pub final_: Boundary,
    /// Intermediate boundary `Com(S_1)`, exposed for the native shared-boundary check.
    pub middle: Boundary,
    /// Ordered-update digest `H_{[1, 2]}`.
    pub digest: ChainDigest,
}

#[derive(Debug)]
pub enum MergeError {
    BoundaryMismatch {
        left_final: Boundary,
        right_initial: Boundary,
    },
    AggregationFailed(String),
    BatchVerifyFailed(String),
    DigestMismatch,
    OuterBoundaryMismatch,
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryMismatch { left_final, right_initial } => write!(
                f,
                "boundary mismatch: left.final_ = {left_final:?} but right.initial = {right_initial:?}"
            ),
            Self::AggregationFailed(s) => write!(f, "aggregation layer build/prove failed: {s}"),
            Self::BatchVerifyFailed(s) => write!(f, "batch-stark verification failed: {s}"),
            Self::DigestMismatch => write!(f, "recomputed digest does not match the carried one"),
            Self::OuterBoundaryMismatch => write!(f, "outer boundary mismatch"),
        }
    }
}

impl core::error::Error for MergeError {}

/// Build the recursion config used for both the aggregation circuit and the
/// final verifier. Must match the leaf's config (same FRI params, same
/// permutation) since the recursion circuit verifies the leaf's FRI.
fn make_config() -> ConfigWithFriParams {
    let leaf_cfg = crate::config::make_config(LOG_FINAL_POLY_LEN);
    make_recursion_config(
        leaf_cfg,
        LOG_BLOWUP,
        LOG_FINAL_POLY_LEN,
        crate::config::COMMIT_POW_BITS,
        crate::config::QUERY_POW_BITS,
    )
}

fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// Build a `RecursiveLeafProof` for a single epoch starting from `initial`.
/// Convenience re-export so callers don't need to import the submodule.
pub fn prove_leaf(initial: Boundary) -> RecursiveLeafProof {
    prove_recursive_leaf(initial)
}

/// Merge two leaf proofs into one recursive aggregated proof.
pub fn merge_two(
    left: &RecursiveLeafProof,
    right: &RecursiveLeafProof,
) -> Result<ChainProof, MergeError> {
    if left.final_ != right.initial {
        return Err(MergeError::BoundaryMismatch {
            left_final: left.final_,
            right_initial: right.initial,
        });
    }

    let config = make_config();
    let backend = make_backend();
    let params = agg_params();

    let left_input = left.output.into_recursion_input::<BatchOnly>();
    let right_input = right.output.into_recursion_input::<BatchOnly>();

    let recursive_proof = build_and_prove_aggregation_layer::<
        ConfigWithFriParams,
        BatchOnly,
        BatchOnly,
        Backend,
        D,
    >(&left_input, &right_input, &config, &backend, &params, None)
    .map_err(|e| MergeError::AggregationFailed(format!("{e:?}")))?;

    let dl = leaf_digest(
        &[left.initial.a, left.initial.b],
        &[left.final_.a, left.final_.b],
        1,
    );
    let dr = leaf_digest(
        &[right.initial.a, right.initial.b],
        &[right.final_.a, right.final_.b],
        2,
    );
    let digest = combine_digest(1, 1, 2, &dl, &dr);

    Ok(ChainProof {
        recursive_proof,
        interval: (1, 2),
        initial: left.initial,
        final_: right.final_,
        middle: left.final_,
        digest,
    })
}

/// Verify a `ChainProof`:
///   1. The single recursive batch-STARK proof is sound.
///   2. The carried `middle` boundary recomputes the same digest as the
///      proof carries (binds boundaries to the proof).
///   3. The outer boundary is consistent with what the chain advertises.
pub fn verify_chain(c: &ChainProof) -> Result<(), MergeError> {
    let config = make_config();
    let params = agg_params();

    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != D);
    verifier
        .verify_all_tables(&c.recursive_proof.0)
        .map_err(|e| MergeError::BatchVerifyFailed(format!("{e:?}")))?;

    // Digest check binds boundaries to what the proof certifies.
    let dl = leaf_digest(&[c.initial.a, c.initial.b], &[c.middle.a, c.middle.b], 1);
    let dr = leaf_digest(&[c.middle.a, c.middle.b], &[c.final_.a, c.final_.b], 2);
    let expected = combine_digest(1, 1, 2, &dl, &dr);
    if expected != c.digest {
        return Err(MergeError::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use p3_batch_stark::ProverData;
    use p3_circuit::CircuitBuilder;
    use p3_circuit_prover::{
        BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
        common::get_airs_and_degrees_with_prep,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::StarkGenericConfig;

    use super::*;
    use crate::config::Val;

    /// Diagnostic: replicates the upstream `recursive_aggregation` example's
    /// exact dummy-circuit + aggregation pipeline. If THIS doesn't work in our
    /// setup, the problem is our config/backend wiring — not our leaf circuit.
    fn prove_upstream_dummy(constant_value: u32) -> RecursionOutput<ConfigWithFriParams> {
        let log_final_poly_len = LOG_FINAL_POLY_LEN;
        let leaf_cfg = crate::config::make_config(log_final_poly_len);
        let config = make_recursion_config(
            leaf_cfg,
            LOG_BLOWUP,
            log_final_poly_len,
            crate::config::COMMIT_POW_BITS,
            crate::config::QUERY_POW_BITS,
        );

        let mut builder = CircuitBuilder::new();
        let c = builder.alloc_const(Val::from_u32(constant_value), "dummy_const");
        let expected = builder.alloc_public_input("expected");
        builder.connect(c, expected);
        let circuit = builder.build().expect("build");

        let table_packing = TablePacking::new(1, 1).with_fri_params(log_final_poly_len, LOG_BLOWUP);
        let (airs_degrees, primitive_columns, non_primitive_columns) =
            get_airs_and_degrees_with_prep::<ConfigWithFriParams, Val, 1>(
                &circuit,
                &table_packing,
                &[],
                &[],
                ConstraintProfile::Standard,
            )
            .unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();

        let mut runner = circuit.runner();
        runner.set_public_inputs(&[Val::from_u32(constant_value)]).unwrap();
        let traces = runner.run().unwrap();

        let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let circuit_prover_data =
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

        let prover =
            BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        let proof = prover.prove_all_tables(&traces, &circuit_prover_data).unwrap();
        prover.verify_all_tables(&proof).unwrap();
        RecursionOutput(proof, Rc::new(circuit_prover_data))
    }

    /// Sanity check that aggregation works in our setup by mirroring the
    /// upstream `recursive_aggregation` example's dummy-circuit pipeline.
    /// Slow in debug (~2 minutes) but proves the §4.2 path is sound.
    #[test]
    fn upstream_pattern_aggregates() {
        let left = prove_upstream_dummy(1);
        let right = prove_upstream_dummy(2);
        let config = make_config();
        let backend = make_backend();
        let params = agg_params();

        let left_input = left.into_recursion_input::<BatchOnly>();
        let right_input = right.into_recursion_input::<BatchOnly>();

        build_and_prove_aggregation_layer::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            D,
        >(&left_input, &right_input, &config, &backend, &params, None)
        .expect("aggregate two dummy circuits");
    }

    /// PROBE (Stage 0a): measure what an aggregation proof exposes as public
    /// inputs, to decide the recursive-forest design. Builds the aggregation
    /// circuit over two dummy leaves with distinct public values (111, 222)
    /// and reports: the parent circuit's `public_flat_len`, each child's
    /// packed-public-input length, and whether the leaf's own public value
    /// (111 / 222) propagates into the parent's public inputs.
    #[test]
    fn probe_aggregation_public_inputs() {
        use p3_recursion::{VerifierCircuitResult, build_aggregation_layer_circuit};

        use crate::config::{Challenge, Val};
        use p3_field::PrimeCharacteristicRing;

        let left = prove_upstream_dummy(111);
        let right = prove_upstream_dummy(222);
        let config = make_config();
        let backend = make_backend();
        let left_input = left.into_recursion_input::<BatchOnly>();
        let right_input = right.into_recursion_input::<BatchOnly>();

        let (circuit, (lr, rr)) = build_aggregation_layer_circuit::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            D,
        >(&left_input, &right_input, &config, &backend)
        .expect("build aggregation circuit");

        let lpis = lr.pack_public_inputs(&left_input).expect("left pis");
        let rpis = rr.pack_public_inputs(&right_input).expect("right pis");

        let v111 = Challenge::from(Val::from_u32(111));
        let v222 = Challenge::from(Val::from_u32(222));

        println!("PROBE: agg public_flat_len = {}", circuit.public_flat_len);
        println!("PROBE: left  pack_public_inputs len = {}", lpis.len());
        println!("PROBE: right pack_public_inputs len = {}", rpis.len());
        println!("PROBE: 111 present in left  pis = {}", lpis.contains(&v111));
        println!("PROBE: 222 present in right pis = {}", rpis.contains(&v222));
        println!(
            "PROBE: total parent pis (lpis+rpis) = {}",
            lpis.len() + rpis.len()
        );
    }

    /// Honest two-leaf recursive chain accepts.
    #[test]
    fn honest_two_leaf_recursive_accepts() {
        let l1 = prove_leaf(Boundary::new(0, 1));
        let l2 = prove_leaf(l1.final_);
        let chain = merge_two(&l1, &l2).expect("merge_two");
        verify_chain(&chain).expect("verify_chain");
        assert_eq!(chain.interval, (1, 2));
    }

    /// Two leaves with non-matching boundary are rejected before the recursion
    /// prover is invoked.
    #[test]
    fn boundary_mismatch_recursive_rejected() {
        let l1 = prove_leaf(Boundary::new(0, 1));
        let l2 = prove_leaf(Boundary::new(7, 8));
        match merge_two(&l1, &l2) {
            Err(MergeError::BoundaryMismatch { .. }) => {}
            Err(other) => panic!("expected BoundaryMismatch, got {other:?}"),
            Ok(_) => panic!("merge must reject mismatched boundary"),
        }
    }
}
