//! Commitment-related traits used by the paper's per-epoch transition proofs.
//!
//! Phase 1 only needs a stand-in for the paper's `Com(S_t)`: the toy `FibAir`
//! exposes its boundary `(a, b)` directly, with no real state commitment.
//! Phase 2 will plug a Poseidon2 vector commitment over the Count-Min counter
//! table behind the same trait so the recursive merge code does not have to
//! change.

pub mod boundary;
pub mod countmin;
pub mod countmin_batch;
pub mod greenwald_khanna;
pub mod hiding;
pub mod hyperloglog;
pub mod spacesaving;

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
