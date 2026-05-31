//! Plaintext sketches + their native Poseidon commitments.
//!
//! Each sketch defines an update rule and a Pattern-A delta aggregation (the
//! per-cell merge is associative/commutative, so epochs can be proven
//! independently and recursively merged). Mirrors `../src/sketch/`.

pub mod countmin;
pub mod hyperloglog;
