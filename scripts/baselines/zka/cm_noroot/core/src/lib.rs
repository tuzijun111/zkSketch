#![no_std]
//! zk-Analytics' Count-Min aggregation WITHOUT its per-epoch Merkle roots (the "noroot"
//! variant of the six-sketch comparison, ../../README.md "Six-sketch comparison").
//!
//! Their aggregation guest aggr_cm (aggregator/methods/guest_cm @ d4a5a9a) runs
//! `process_cm_aggr_with_state` (aggregator/core/src/lib.rs:1215-1301). Besides the flat
//! SHA-256 `state_commit` that the epoch chain and every query guest use, it builds three
//! Merkle roots that no query guest or verifier reads: `row_roots` (one SHA-256 leaf per
//! counter, 3 x 1024 leaves), `cm_root` and `heap_root`. Executed, they cost about 11.3M
//! cycles per epoch whatever the number of records. zkSketch publishes no such root, so the
//! apples-to-apples zk-Analytics number is the same aggregation without them:
//!
//! * [`noroot`]  `process_cm_aggr_with_state` with ONLY the Merkle block (lines 1262-1274)
//!   replaced by zeros: same chain verification, flattening, table and heap update, state
//!   commitment, epoch link and journal type (`CmAggrOutput`). For the same input its
//!   journal equals theirs with row_roots, cm_root and heap_root set to zero.
//! * [`twin`]    the same functions with nothing replaced. VALIDATION ONLY (guest
//!   aggr_cm_twin, never a reported number): it shows that copying their code into this
//!   crate leaves its cost unchanged outside the Merkle work. Measured 2026-10-13 (executor,
//!   AOL, epoch 0): aggr_cm_twin = aggr_cm + 402,100 / 402,052 / 401,956 cycles at 64 / 128 /
//!   256 records, a constant. A pprof profile (RISC0_PPROF_OUT) at 128 records puts all of it
//!   inside their generic `merkle::MerkleTree<Digest>`, which the twin monomorphizes in this
//!   crate with different inlining (ShaHasher's Hasher impl +415K flat, MerkleTree::new -129K
//!   flat, Hashable::hash no longer inlined); everything else costs the same (crate-local flat
//!   cycles 154,486 vs 155,055; memset, SHA-256, input deserialisation identical). So the
//!   noroot copy costs what their aggregation costs without its Merkle work, and
//!   aggr_cm - aggr_cm_noroot (11.09M cycles at 64-256 records) is that work.
//!
//! Both modules include!, byte for byte, the line ranges that ../gen_upstream.sh cuts from
//! the clone (`gen_upstream.sh --check` re-verifies them).

extern crate alloc;

pub use aggregator_core::{CmAggrInput, CmAggrOutput, CmState};

/// Their CM aggregation with the three Merkle roots left out (journal fields zero).
pub mod noroot {
    #![allow(unused_imports)]
    use aggregator_core::{
        BatchInput, CmAggrInput, CmAggrOutput, CmState, EpochChainLink, CM_COLS, CM_ROWS, CM_SEEDS, CM_TOPK_SLOTS,
    };
    use alloc::boxed::Box;
    use alloc::format;
    use alloc::vec::Vec;
    use hashbrown::HashMap;
    #[cfg(target_os = "zkvm")]
    use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
    #[cfg(not(target_os = "zkvm"))]
    use rust_crypto::{Digest as _, Sha256};
    use zkvm_common::{Event, HASH_BYTES_LEN, KEY_BYTES_LEN};

    include!("upstream_noroot.rs");
}

/// Their CM aggregation, unedited (validation twin of aggr_cm; never a reported number).
pub mod twin {
    #![allow(unused_imports)]
    use aggregator_core::merkle::MerkleTree;
    use aggregator_core::{
        BatchInput, CmAggrInput, CmAggrOutput, CmState, EpochChainLink, CM_COLS, CM_ROWS, CM_SEEDS, CM_TOPK_SLOTS,
    };
    use alloc::boxed::Box;
    use alloc::format;
    use alloc::vec::Vec;
    use hashbrown::HashMap;
    #[cfg(target_os = "zkvm")]
    use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
    #[cfg(not(target_os = "zkvm"))]
    use rust_crypto::{Digest as _, Sha256};
    use risc0_zkvm::sha::Digest;
    use zkvm_common::{Event, HASH_BYTES_LEN, KEY_BYTES_LEN};

    include!("upstream_twin.rs");
}

/// `out` with the three Merkle-root fields set to zero: what the noroot journal must be
/// for an input whose shipped journal is `out`.
pub fn zero_roots(out: &CmAggrOutput) -> CmAggrOutput {
    let mut o = out.clone();
    o.row_roots = [[0u8; 32]; aggregator_core::CM_ROWS];
    o.cm_root = [0u8; 32];
    o.heap_root = [0u8; 32];
    o
}
