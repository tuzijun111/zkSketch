//! Leaf prover/verifier wrappers and the `LeafProof` type that the recursion
//! layer chains over.

pub mod leaf;

pub use leaf::{Boundary, LeafProof, LeafProveError, LeafVerifyError, prove_fib_leaf, verify_fib_leaf};
