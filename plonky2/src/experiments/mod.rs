//! Evaluation harness for the plonky2 (SNARK) backend.
//!
//! [`dist_compose`] is the plonky2 port of the plonky3 distributed
//! streaming-composition experiment (`../../../src/experiments/dist_compose.rs`):
//! the three modes (per_batch / chain / forest) over a stream of `t` batch
//! leaves, with the same `DistCell`/CSV schema so p2 and p3 numbers compare
//! directly.
//!
//! Phased port (see the plonky3 engine for the full multi-process design):
//! - **Phase 0** (landed): cross-process merge codec — `recursion::MergeInput` /
//!   `merge_wire` + the `merge_from_wire_round_trips` gate test.
//! - **Phase 1** (this file): single-machine, in-process forest/chain/per_batch
//!   over Count-Min, verified end-to-end, emitting a `DistCell`.
//! - **Phase 2** (next): the pinned multi-process coordinator/worker/socket
//!   layer + cross-machine reduction rounds shipping `MergeInput` bytes.

pub mod dist_compose;
