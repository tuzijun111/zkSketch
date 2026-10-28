//! State and batch commitments (Poseidon2; plain and hiding).

pub mod boundary;
pub mod countmin;
pub mod countmin_batch;
pub mod greenwald_khanna;
pub mod hiding;
pub mod hyperloglog;
pub mod spacesaving;

#[cfg(test)]
mod plain_vk_pins;

pub use boundary::Boundary;
pub use countmin::CountMinCommit;
pub use countmin_batch::CountMinBatchCommit;
pub use greenwald_khanna::GKCommit;
pub use hiding::{
    CommitFamily, CommitKind, CommitMode, Openings, OpeningsGl, SaltBb, SaltGl, SaltSeed,
    commit_mode_from_env,
};
pub use hyperloglog::HyperLogLogCommit;
pub use spacesaving::SpaceSavingCommit;

use crate::config::Val;

/// A committer for some sketch state. The associated `Commit` type is what
/// the leaf AIR exposes as its boundary, and what the recursive merge atom
/// checks equality on.
pub trait StateCommit {
    type State;
    type Commit: Copy + Clone + Eq + AsRef<[Val]>;

    fn commit(state: &Self::State) -> Self::Commit;
}
