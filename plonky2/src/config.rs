//! Proof-system configuration.
//!
//! The plonky3 original (`../src/config.rs`) uses BabyBear + Poseidon2 +
//! two-adic FRI. Here we use plonky2's recursion-friendly defaults: the
//! **Goldilocks** field with the **Poseidon** config. Goldilocks is 64-bit, so
//! sketch counters / register values fit in a single field element — there is no
//! need for the BabyBear "pack 4 cells into one degree-4 extension element"
//! alignment trick the original required.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

/// Base field — Goldilocks, `p = 2^64 - 2^32 + 1`.
pub type F = GoldilocksField;

/// Proof config — Poseidon over Goldilocks (recursion-friendly).
pub type C = PoseidonGoldilocksConfig;

/// FRI extension degree.
pub const D: usize = 2;

/// The one `CircuitConfig` every circuit in this crate builds with, pinned to
/// the SAME conjectured-security target as the plonky3 backend
/// (`../src/config.rs` `SECURITY_LEVEL = 124`) so cross-stack rows compare at
/// parity. Conjectured FRI soundness is
/// `proof_of_work_bits + rate_bits · num_query_rounds`: plonky2's stock
/// `standard_recursion_config` is 100-bit (16 + 3·28); raising the query count
/// to 36 gives 16 + 3·36 = 124. Challenge-space soundness already clears the
/// target (degree-2 Goldilocks extension ≈ 128 bits, `num_challenges = 2`).
/// Everything else (wires, arity, cap height) keeps the recursion-friendly
/// defaults.
///
/// Zero knowledge follows the `zk` cargo feature (on by default, like the
/// plonky3 backend): plonky2 then adds random blinding rows for the wires and
/// for Z / the partial products, and salts the wires, Z and quotient Merkle
/// leaves. That makes every circuit at least 2^14 rows (about 10.7k blinding
/// rows at 36 queries). The Z blinding needs plonky2's `blind()` fix
/// (`connect`, not `generate_copy`, between each blinding pair);
/// `tests/zk_blinding.rs` checks it. The hiding is plonky2's standard heuristic
/// ZK: quotient chunks are only salted, and lookup polynomials are not blinded
/// at all, which [`build_circuit`] guards against.
pub fn circuit_config() -> CircuitConfig {
    let mut config = CircuitConfig::standard_recursion_config();
    config.security_bits = 124;
    config.fri_config.num_query_rounds = 36;
    config.zero_knowledge = cfg!(feature = "zk");
    config
}

/// Build a circuit, checking that it is safe to publish under zero knowledge.
/// Every circuit in this crate is built through this function.
pub fn build_circuit(builder: CircuitBuilder<F, D>) -> CircuitData<F, C, D> {
    let data = builder.build::<C>();
    assert_zk_safe(&data.common);
    data
}

/// Under `zero_knowledge`, require that the circuit uses no plonky2 lookups:
/// plonky2 computes its lookup polynomials (RE and the partial SLDCs) only from
/// the lookup and table rows, so the blinding rows do not randomize them and they
/// would leak the looked-up witness values.
pub fn assert_zk_safe(common: &CommonCircuitData<F, D>) {
    if common.config.zero_knowledge {
        assert!(
            common.num_lookup_polys == 0 && common.luts.is_empty(),
            "zero-knowledge circuit uses plonky2 lookups ({} lookup polys, {} tables), \
             whose polynomials plonky2 does not blind",
            common.num_lookup_polys,
            common.luts.len()
        );
    }
}
