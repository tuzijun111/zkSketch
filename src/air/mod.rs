//! Leaf AIRs and the `LeafAir` trait that the prover and recursion code are generic over.

pub mod fib;

pub use fib::{FibAir, NUM_FIB_COLS};

use p3_field::PrimeCharacteristicRing;

use crate::config::Val;

/// Trait every leaf AIR must implement so `prove_leaf` and the recursive merge
/// can stay generic. In Phase 1 only `FibAir` implements this; Phase 2 will
/// add Count-Min, CountSketch, etc.
///
/// The `Boundary` associated type is the paper's `Com(S_t)` for the underlying
/// state — for the toy `FibAir` it is the pair `(a, b)`. Public values of the
/// leaf STARK are exactly `[initial.flatten(), final.flatten()]`.
pub trait LeafAir {
    type Boundary: Copy + Clone;

    fn boundary_to_public_values(initial: Self::Boundary, final_: Self::Boundary) -> Vec<Val>;

    fn boundary_from_public_values(pis: &[Val]) -> (Self::Boundary, Self::Boundary);
}

/// Convenience constant for the zero boundary.
pub fn zero_pair() -> [Val; 2] {
    [Val::ZERO, Val::ZERO]
}
