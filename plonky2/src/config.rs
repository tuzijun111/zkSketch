//! Proof-system configuration.
//!
//! The plonky3 original (`../src/config.rs`) uses BabyBear + Poseidon2 +
//! two-adic FRI. Here we use plonky2's recursion-friendly defaults: the
//! **Goldilocks** field with the **Poseidon** config. Goldilocks is 64-bit, so
//! sketch counters / register values fit in a single field element — there is no
//! need for the BabyBear "pack 4 cells into one degree-4 extension element"
//! alignment trick the original required.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

/// Base field — Goldilocks, `p = 2^64 - 2^32 + 1`.
pub type F = GoldilocksField;

/// Proof config — Poseidon over Goldilocks (recursion-friendly).
pub type C = PoseidonGoldilocksConfig;

/// FRI extension degree.
pub const D: usize = 2;
