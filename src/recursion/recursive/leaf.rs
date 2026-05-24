//! CircuitBuilder-based Fibonacci leaf for the recursive merge atom.
//!
//! Why a separate leaf representation here (vs Phase 1's uni-stark `FibAir`)?
//!
//! The `RecursionInput::UniStark` aggregation path in plonky3-recursion is
//! exercised upstream only with **empty public inputs** (the `recursive_keccak`
//! example). Passing 4 PIs — as our uni-stark `FibAir` does — trips a
//! WitnessConflict at WitnessId(0) inside the recursive verifier. The
//! well-tested upstream pattern for non-trivial PIs is the
//! `recursive_fibonacci` style: build the leaf computation directly with
//! `CircuitBuilder` and prove it via `BatchStarkProver::prove_all_tables`.
//!
//! We keep the uni-stark `FibAir` and the Phase 1 §4.1 flat chain intact as
//! the comparison baseline. This file provides the Phase 1.5 §4.2 path.

use std::rc::Rc;

use p3_batch_stark::ProverData;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    common::get_airs_and_degrees_with_prep,
};
use p3_recursion::RecursionOutput;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{LOG_BLOWUP, Val};
use crate::prover::Boundary;
use crate::recursion::recursive::config::{ConfigWithFriParams, make_recursion_config};

/// Number of Fibonacci steps inside one leaf.
///
/// Kept small so the demo runs in seconds. Has to be large enough that the
/// circuit table doesn't fall below the FRI minimum trace height of
/// `2^(log_final_poly_len + log_blowup + 1)`.
pub const LEAF_STEPS: usize = 16;

/// A recursive leaf proof — output of one Fibonacci epoch built via
/// `CircuitBuilder` and proved by `BatchStarkProver`.
///
/// Carries everything the next layer (the recursive merge) needs as inputs:
/// the proof itself plus the carried prover data, plus the boundary
/// `(initial, final)` so the merge can natively check chain consistency.
pub struct RecursiveLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: Boundary,
    pub final_: Boundary,
}

impl RecursiveLeafProof {
    /// Public-values vector this proof was bound to:
    /// `[initial.a, initial.b, final_.a, final_.b]`.
    pub fn public_values(&self) -> Vec<Val> {
        vec![self.initial.a, self.initial.b, self.final_.a, self.final_.b]
    }
}

/// Build the leaf-level CircuitBuilder Fibonacci, allocate PIs for boundary,
/// then prove via BatchStarkProver. Mirrors `recursive_fibonacci.rs` lines
/// 315–375 with our extra `a0/b0` PIs instead of hardcoded `F::ZERO/ONE`.
pub fn prove_recursive_leaf(initial: Boundary) -> RecursiveLeafProof {
    // Phase 1.5 uses a fixed log_final_poly_len matching keccak's defaults so
    // the recursion verifier's circuit shape stays comfortably within tested
    // territory.
    let log_final_poly_len = 6usize;

    let leaf_cfg = crate::config::make_config(log_final_poly_len);
    let config = make_recursion_config(
        leaf_cfg,
        LOG_BLOWUP,
        log_final_poly_len,
        crate::config::COMMIT_POW_BITS,
        crate::config::QUERY_POW_BITS,
    );

    // Build the per-epoch circuit.
    //
    // We allocate the F::ZERO / F::ONE constants up-front to match the
    // upstream Fibonacci example's expression-graph shape. The recursive
    // verifier's compiled circuit allocates a witness for each `Expr::Const`
    // in the inner circuit; if the inner doesn't include ONE but the
    // verifier-side circuit does, witness IDs misalign and the runner trips
    // a WitnessConflict at WitnessId(0).
    let mut builder = CircuitBuilder::new();
    let _zero = builder.alloc_const(Val::ZERO, "F(0)");
    let _one = builder.alloc_const(Val::ONE, "F(1)");

    let a0_t = builder.alloc_public_input("a0");
    let b0_t = builder.alloc_public_input("b0");
    let a_final_t = builder.alloc_public_input("aT");
    let b_final_t = builder.alloc_public_input("bT");

    let mut a = a0_t;
    let mut b = b0_t;
    for _ in 0..LEAF_STEPS {
        let next = builder.add(a, b);
        a = b;
        b = next;
    }
    builder.connect(a, a_final_t);
    builder.connect(b, b_final_t);

    let circuit = builder.build().expect("build leaf circuit");

    // Compute the expected final boundary so we can pass it as a PI.
    let (a_t, b_t) = fib_step(initial.a, initial.b, LEAF_STEPS);
    let final_ = Boundary { a: a_t, b: b_t };

    // Run the circuit to produce traces.
    let traces = {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[initial.a, initial.b, final_.a, final_.b])
            .expect("set_public_inputs");
        runner.run().expect("run circuit")
    };

    // Prepare prover data — copied from recursive_fibonacci.rs.
    let table_packing = TablePacking::new(1, 1).with_fri_params(log_final_poly_len, LOG_BLOWUP);
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Val, 1>(
            &circuit,
            &table_packing,
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep");

    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let prover =
        BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables");
    prover
        .verify_all_tables(&proof)
        .expect("self-verify recursive leaf");

    RecursiveLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial,
        final_,
    }
}

/// Native Fibonacci step in the field, used to compute the expected final
/// boundary outside the circuit.
fn fib_step(a: Val, b: Val, n: usize) -> (Val, Val) {
    let mut x = a;
    let mut y = b;
    for _ in 0..n {
        let z = x + y;
        x = y;
        y = z;
    }
    (x, y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_leaf_round_trip() {
        let leaf = prove_recursive_leaf(Boundary::new(0, 1));
        // Boundary chain check: starting from (0, 1) and stepping LEAF_STEPS=16
        // times gives (F_16, F_17). Verify against the native computation.
        let (a_expected, b_expected) = fib_step(Boundary::new(0, 1).a, Boundary::new(0, 1).b, LEAF_STEPS);
        assert_eq!(leaf.final_.a, a_expected);
        assert_eq!(leaf.final_.b, b_expected);
    }
}
