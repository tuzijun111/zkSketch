#![no_std]
//! zk-Analytics' CM aggregation without the Merkle roots no query reads (`noroot`), plus an
//! unedited copy (`twin`, validation only). Both include! code cut by ../gen_upstream.sh.

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
