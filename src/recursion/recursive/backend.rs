//! `FriRecursionBackend` wired up for BabyBear + Poseidon2 width-16 / D=4.
//!
//! Mirrors `recursive_keccak.rs::baby_bear::run` (lines 537–541):
//!
//! ```ignore
//! let backend = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::BABY_BEAR_D4_W16)
//!     .for_extension_degree::<4>();
//! ```

use p3_recursion::{FriRecursionBackend, FriRecursionBackendForExt, Poseidon2Config};

use crate::recursion::recursive::config::D;

/// Concrete backend type used by [`crate::recursion::recursive::merge_two`].
///
/// `D` (the binomial extension degree) is fixed at 4 to match the leaf
/// `StarkCfg`'s `BinomialExtensionField<BabyBear, 4>`.
pub type Backend = FriRecursionBackendForExt<D, 16, 8, Poseidon2Config>;

/// Build the backend used for both the aggregation circuit and the
/// `BatchStarkProver` that verifies the aggregated proof. The two must use
/// the same backend so the recursive verifier and the prover agree on the
/// non-primitive op table layout.
pub fn make_backend() -> Backend {
    FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::BABY_BEAR_D4_W16).for_extension_degree::<D>()
}
