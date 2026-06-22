//! In-circuit update leaves — each proves one epoch of a sketch.
//!
//! [`fib`] is a toy leaf that validates the plonky2 prove/verify + recursion
//! plumbing (mirrors zkSketch Phase 1). The real sketch leaves (Count-Min,
//! HyperLogLog) build on the same pattern.

pub mod countmin;
pub mod countmin_final;
pub mod countmin_merkle;
pub mod fib;
pub mod gadgets;
pub mod greenwald_khanna;
pub mod hll_merkle;
pub mod hyperloglog;
pub mod spacesaving;
