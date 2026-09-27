//! BabyBear + Poseidon2 + two-adic FRI StarkConfig for leaf STARKs.
//!
//! The Poseidon2 permutation is the canonical
//! `p3_baby_bear::default_babybear_poseidon2_16` — same round constants the
//! recursive verifier circuit uses. Earlier versions of this file used a
//! `SmallRng`-seeded permutation; that produced a different set of round
//! constants from the recursive verifier's hardcoded `Poseidon2Config::
//! BABY_BEAR_D4_W16`, and the mismatch broke the §4.2 in-circuit aggregation
//! (the verifier circuit recomputed leaf hashes under the canonical constants
//! and disagreed with the leaf proof, surfacing as `WitnessConflict` at the
//! first compared witness).
//!
//! ### Zero knowledge (`--features zk`)
//!
//! The default build is **not hiding**: `Pcs` is the plain `TwoAdicFriPcs`.
//! The `zk` Cargo feature (off by default) swaps in `HidingFriPcs` over the
//! SAME plain `MerkleTreeMmcs`, with the OS-seeded `ZkRng`
//! ([`crate::zk_rng`]) as its mask RNG and `NUM_RANDOM_CODEWORDS` random
//! codewords per commitment. Every leaf, merge, root and query proof is then
//! produced by the hiding PCS (the whole crate uses this one `Pcs`; the
//! recursion side follows in `recursion::recursive::config`). Degrees are
//! unchanged but every committed trace doubles (`is_zk`), so a table fits
//! only while its base height is `<= 2^24` (see `experiments::table_probe`).
//!
//! Salted Merkle leaves are NOT used. `HidingFriPcs` documents that both
//! MMCSs "must also be hiding" (`MerkleTreeHidingMmcs`), but that MMCS draws
//! fresh salts for EVERY commitment, the preprocessed one included, so each
//! build of a circuit gets a different VK: the no-op-leaf VK derivation
//! (`expose_forest::root_vk_deriver`, derived root VK == real root VK) and
//! the auditor's root-VK pin both break. Shipping salted leaves needs a
//! setup/prove config split (a fixed-public-salt instance for every
//! `ProverData::from_airs_and_degrees`, an OS-seeded one for proving, and a
//! bypass of the fork's single-config `prove_aggregation_layer`), which is not
//! implemented. With the plain MMCS, each committed leaf row still carries
//! its `NUM_RANDOM_CODEWORDS` random-codeword values (about 124 bits of
//! randomness on BabyBear), which play the salt's role for the unopened
//! Merkle siblings in a random-oracle argument; that argument is a heuristic
//! of ours, not an upstream guarantee.
//!
//! Known ZK gaps even with the feature on: the per-table LogUp cumulative
//! sums (`BatchProof::global_lookup_data`) are revealed unblinded, and
//! upstream calls the construction only statistically zero-knowledge.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriParameters;
#[cfg(feature = "zk")]
use p3_fri::HidingFriPcs;
#[cfg(not(feature = "zk"))]
use p3_fri::TwoAdicFriPcs;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;

pub type Perm = Poseidon2BabyBear<16>;
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type Dft = Radix2DitParallel<Val>;
/// Non-hiding PCS (default build).
#[cfg(not(feature = "zk"))]
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// Hiding PCS (`--features zk`; see the module docs).
#[cfg(feature = "zk")]
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, ZkRng>;

#[cfg(feature = "zk")]
pub use crate::zk_rng::ZkRng;

/// Random codewords `HidingFriPcs` appends to every commitment (`zk` only):
/// `[Challenge : Val] = 4`.
///
/// They are base-field columns, and FRI batches every opened column with
/// powers of an extension-field challenge `α`; the FRI transcript (the batched
/// codeword at every query and fold layer) is simulatable only if that
/// batch is a uniformly random extension-valued codeword at each height. A
/// base column `c` scaled by `α^k` spans one `Val`-dimension of it, so each
/// matrix needs `[Challenge : Val]` of them (`α^k, ..., α^(k+3)` are
/// `Val`-independent unless `α` lies in a proper subfield). Upstream
/// Plonky3's own ZK tests and example over degree-4 fields all use 4
/// (`batch-stark/tests/simple.rs`, `uni-stark/tests/{fib_air,mul_air,
/// mul_fib_pair,periodic_air}.rs`, `poseidon2-air/examples/
/// prove_poseidon2_baby_bear_keccak_zk.rs`); the recursion fork's examples use
/// 2 in functional tests. The cost is 4 extra columns per commitment (the
/// randomization polynomial gets `4 + 4`), negligible next to the traces.
#[cfg(feature = "zk")]
pub const NUM_RANDOM_CODEWORDS: usize =
    <Challenge as p3_field::BasedVectorSpace<Val>>::DIMENSION;

/// The StarkConfig used for every leaf STARK in Phase 1.
pub type StarkCfg = StarkConfig<Pcs, Challenge, Challenger>;

/// Build the canonical Poseidon2 permutation used by both the leaf STARK and
/// the recursive verifier. Wraps the upstream `default_babybear_poseidon2_16`
/// in a single name so other modules don't have to import the BabyBear crate
/// directly.
pub fn make_perm() -> Perm {
    default_babybear_poseidon2_16()
}

/// FRI parameters used everywhere — leaf prove, leaf verify, and the
/// recursive merge layer's verifier-of-the-leaf — all use this same shape.
///
/// Aligned with the recursive_keccak example's defaults (log_blowup=2,
/// max_log_arity=2, query_pow_bits=15, num_queries derived from security
/// level). This is what plonky3-recursion's verifier circuit was tested
/// against; smaller values like log_arity=1 / num_queries=2 trip a
/// WitnessConflict deep in the FRI verifier circuit's witness layout.
pub const LOG_BLOWUP: usize = 2;
pub const MAX_LOG_ARITY: usize = 2;
pub const CAP_HEIGHT: usize = 0;
pub const COMMIT_POW_BITS: usize = 0;
pub const QUERY_POW_BITS: usize = 15;
pub const SECURITY_LEVEL: usize = 124;

pub fn num_queries() -> usize {
    (SECURITY_LEVEL - QUERY_POW_BITS) / LOG_BLOWUP
}

/// Construct the default Poseidon2-based BabyBear StarkConfig with two-adic FRI.
///
/// `log_final_poly_len` controls the FRI final polynomial size; a larger value
/// terminates folding earlier and reduces the per-leaf prover cost.
pub fn make_config(log_final_poly_len: usize) -> StarkCfg {
    let perm = make_perm();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, CAP_HEIGHT);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len,
        max_log_arity: MAX_LOG_ARITY,
        num_queries: num_queries(),
        commit_proof_of_work_bits: COMMIT_POW_BITS,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs: challenge_mmcs,
    };
    #[cfg(not(feature = "zk"))]
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    // A fresh OS seed per config (hence per leaf and per merge prover).
    #[cfg(feature = "zk")]
    let pcs = Pcs::new(dft, val_mmcs, fri_params, NUM_RANDOM_CODEWORDS, ZkRng::from_os());
    let challenger = Challenger::new(perm);
    StarkCfg::new(pcs, challenger)
}
