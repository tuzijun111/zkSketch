//! # zkSketch_SNARK
//!
//! A SNARK re-implementation of the [`zkSketch`](..) framework — non-interactive,
//! verifiable, privacy-preserving sketch-based analytics with recursive proof
//! aggregation. The original is built on **plonky3 + plonky3-recursion** (recursive
//! STARKs over BabyBear). This crate rebuilds the same architecture on **plonky2**
//! (PLONK-ish + FRI over Goldilocks, with first-class recursion).
//!
//! ## Why plonky2 counts as the "SNARK" version
//!
//! plonky2 is, like plonky3, a hash-based / FRI proof system (transparent,
//! post-quantum) — but it is a *succinct non-interactive argument of knowledge*
//! with **native, cheap recursion**, and its proofs can be wrapped to a
//! pairing-SNARK (Groth16/PLONK over BN254) for constant-size on-chain
//! verification. The recursion primitive (`builder.verify_proof`) is the direct
//! analog of plonky3-recursion's `build_and_prove_aggregation_layer`, which is
//! exactly what zkSketch's §4.2 merge / §4.3 chain need.
//!
//! ## Architecture (mirrors the paper / the plonky3 original)
//!
//! - [`sketch`] — plaintext sketches (Count-Min, HyperLogLog) + delta aggregation.
//! - [`commitment`] — Poseidon state commitments + §4.2 boundary digests.
//! - [`leaf`] — in-circuit update leaves (one epoch of a sketch).
//! - [`recursion`] — §4.1 flat chain, §4.2 two-leaf recursive merge, §4.3 chain.

pub mod commitment;
pub mod config;
pub mod dataset;
pub mod decode;
pub mod experiments;
pub mod leaf;
pub mod metrics;
pub mod recursion;
pub mod sketch;
