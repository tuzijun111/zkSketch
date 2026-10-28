//! Composition of leaf proofs: `flat` keeps every leaf proof, `recursive`
//! verifies them inside recursive STARK proofs.

pub mod chain;
pub mod countmin_flat;
pub mod digest;
pub mod flat;
pub mod framework;
pub mod hll_flat;
pub mod mmr;
pub mod recursive;

pub use chain::ChainState;
pub use digest::{ChainDigest, combine_digest, leaf_digest};

// Phase 1 re-exports — older call sites keep working, but new code should
// pick `flat::*` or `recursive::*` explicitly to make the choice visible.
pub use flat::{ChainProof, MergeError, merge_two, verify_chain};
