//! zkSketch: recursive STARK proofs (Plonky3) for streaming sketches.

pub mod air;
pub mod commitment;
pub mod config;
pub mod config_gl;
pub mod dataset;
pub mod decode;
pub mod experiments;
pub mod prover;
pub mod recompose_binding;
pub mod recursion;
pub mod sketch;
pub mod zk_rng;

pub use config::{StarkCfg, Val};
