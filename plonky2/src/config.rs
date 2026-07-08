//! Proof-system configuration.
//!
//! The plonky3 original (`../src/config.rs`) uses BabyBear + Poseidon2 +
//! two-adic FRI. Here we use plonky2's recursion-friendly defaults: the
//! **Goldilocks** field with the **Poseidon** config. Goldilocks is 64-bit, so
//! sketch counters / register values fit in a single field element — there is no
//! need for the BabyBear "pack 4 cells into one degree-4 extension element"
//! alignment trick the original required.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::circuit_data::CircuitConfig;
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
pub fn circuit_config() -> CircuitConfig {
    let mut config = CircuitConfig::standard_recursion_config();
    config.security_bits = 124;
    config.fri_config.num_query_rounds = 36;
    config
}
