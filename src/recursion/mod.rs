//! Recursive composition over `LeafProof`s.
//!
//! Two variants live side-by-side, matching the paper's discussion in §4.1 and
//! §4.2 of `paper/zkSketch.pdf`:
//!
//! - [`flat`] — Phase 1 §4.1 *flat proof chain*: `ChainProof` bundles all
//!   participating leaf proofs and exposes only the outer boundary plus a
//!   combined digest. Verification re-checks every leaf proof and asserts the
//!   boundary equalities. Verifier work is `Θ(E)` in the number of epochs.
//!
//! - [`recursive`] — Phase 1.5 §4.2 *recursive merge atom*: two adjacent leaf
//!   proofs are verified inside a single recursive STARK circuit. The verifier
//!   sees one batch-STARK proof and natively checks the shared-boundary
//!   equality on the exposed public inputs. Verifier work is `O(1)` regardless
//!   of how many leaves were merged.
//!
//! Both code paths are kept so prove/verify timings and proof sizes can be
//! compared directly — see `examples/chain_two.rs`.

pub mod chain;
pub mod countmin_flat;
pub mod digest;
pub mod flat;
pub mod framework;
pub mod hll_flat;
pub mod recursive;

pub use chain::ChainState;
pub use digest::{ChainDigest, combine_digest, leaf_digest};

// Phase 1 re-exports — older call sites keep working, but new code should
// pick `flat::*` or `recursive::*` explicitly to make the choice visible.
pub use flat::{ChainProof, MergeError, merge_two, verify_chain};
