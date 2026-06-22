//! # zkSketch
//!
//! Research prototype for recursive ZKP experiments based on the zkSketch paper.
//! Phase 1 stands up the plonky3 + plonky3-recursion plumbing with a toy
//! Fibonacci-style leaf AIR, then proves a two-leaf recursive chain that
//! mirrors the paper's merge atom (§4.2).

pub mod air;
pub mod commitment;
pub mod config;
pub mod dataset;
pub mod decode;
pub mod experiments;
pub mod prover;
pub mod recursion;
pub mod sketch;

pub use config::{StarkCfg, Val};
