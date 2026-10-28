//! FRI recursion backend for Goldilocks, Poseidon2 width 8, D = 2.

use p3_recursion::{FriRecursionBackend, FriRecursionBackendForExt, Poseidon2Config};

use crate::recursion::recursive::config_gl::D;

/// Concrete backend type used by the Goldilocks aggregation circuit.
///
/// `D` (the binomial extension degree) is fixed at 2 to match the leaf
/// `StarkCfg`'s `BinomialExtensionField<Goldilocks, 2>`.
pub type Backend = FriRecursionBackendForExt<D, 8, 4, Poseidon2Config>;

/// Build the Goldilocks backend used for both the aggregation circuit and the
/// `BatchStarkProver` that verifies the aggregated proof.
pub fn make_backend() -> Backend {
    FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<D>()
}
