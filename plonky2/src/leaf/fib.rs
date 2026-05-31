//! Toy Fibonacci leaf — validates the plonky2 prove/verify + recursion plumbing
//! before the real sketch circuits (mirrors zkSketch Phase 1, `src/air/fib.rs`).
//!
//! Public inputs (in order): `[a0, b0, a_final, b_final]`.

use anyhow::Result;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::config::{C, D, F};

/// A built Fibonacci leaf circuit plus the input targets to populate.
pub struct FibLeaf {
    pub data: CircuitData<F, C, D>,
    pub a0: Target,
    pub b0: Target,
}

/// Build a circuit that advances the Fibonacci recurrence `num_steps` times.
pub fn build_fib_leaf(num_steps: usize) -> FibLeaf {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let a0 = builder.add_virtual_target();
    let b0 = builder.add_virtual_target();
    builder.register_public_input(a0);
    builder.register_public_input(b0);

    let mut a = a0;
    let mut b = b0;
    for _ in 0..num_steps {
        let c = builder.add(a, b);
        a = b;
        b = c;
    }
    builder.register_public_input(a);
    builder.register_public_input(b);

    let data = builder.build::<C>();
    FibLeaf { data, a0, b0 }
}

/// Prove one leaf from the given starting pair.
pub fn prove_fib_leaf(leaf: &FibLeaf, a0: F, b0: F) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::<F>::new();
    pw.set_target(leaf.a0, a0)?;
    pw.set_target(leaf.b0, b0)?;
    leaf.data.prove(pw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;

    #[test]
    fn fib_leaf_round_trip() -> Result<()> {
        let leaf = build_fib_leaf(8);
        let proof = prove_fib_leaf(&leaf, F::ZERO, F::ONE)?;
        // (0, 1) advanced 8 steps -> (21, 34).
        assert_eq!(proof.public_inputs[2], F::from_canonical_u64(21));
        assert_eq!(proof.public_inputs[3], F::from_canonical_u64(34));
        leaf.data.verify(proof)
    }

    #[test]
    fn fib_leaf_recursive_verify() -> Result<()> {
        // Inner proof.
        let leaf = build_fib_leaf(8);
        let inner = prove_fib_leaf(&leaf, F::ZERO, F::ONE)?;

        // Outer circuit that verifies the inner proof — the §4.2 recursion primitive.
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let pt = builder.add_virtual_proof_with_pis(&leaf.data.common);
        let vdt = builder.add_virtual_verifier_data(leaf.data.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&pt, &vdt, &leaf.data.common);
        let outer = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&pt, &inner)?;
        pw.set_verifier_data_target(&vdt, &leaf.data.verifier_only)?;
        let outer_proof = outer.prove(pw)?;
        outer.verify(outer_proof)
    }
}
