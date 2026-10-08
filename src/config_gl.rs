//! Goldilocks + Poseidon2-width-8 + D=2 two-adic FRI StarkConfig for leaf STARKs.
//!
//! Parallel to [`crate::config`] (BabyBear D=4 width-16). Used by the `_gl`
//! SpaceSaving / Greenwald-Khanna circuits so callers can select the Goldilocks
//! field instead of BabyBear.
//!
//! ### Poseidon2 constants — must match the fork's in-circuit AIR
//!
//! The permutation is the **seeded** `Poseidon2Goldilocks::<8>::new_from_rng_128`
//! (`SmallRng::seed_from_u64(1)`) — the *same* constants the fork's
//! `GoldilocksD2Width8` in-circuit AIR uses (`poseidon2-circuit-air`'s
//! `goldilocks_d2_width8_round_constants`). Using upstream *canonical*
//! `default_goldilocks_poseidon2_8` would disagree with the AIR and break the
//! in-circuit aggregation with a `WitnessConflict` (the same failure mode the
//! BabyBear [`crate::config`] header documents). Mirrors the fork's
//! `recursion/tests/goldilocks.rs` reference wiring exactly.
//!
//! ### Zero knowledge (`--features zk`)
//!
//! Mirrors [`crate::config`]: `HidingFriPcs` over the plain Merkle MMCS, the
//! OS-seeded [`crate::zk_rng::ZkRng`], and `NUM_RANDOM_CODEWORDS`
//! `= [Challenge : Val] = 2` random codewords per committed matrix. As on the
//! BabyBear side the FRI batch is masked by batch-stark's randomization
//! polynomial, not by these; they give each committed Merkle leaf row 2
//! random Goldilocks values (about 128 bits) for the plain-MMCS argument. The
//! salted-MMCS caveat and the LogUp / statistical-ZK gaps documented there
//! apply here too.

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
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::SmallRng;

pub type Val = Goldilocks;
/// Challenge extension degree D = 2 (Goldilocks² ≈ 2¹²⁸). Contrast BabyBear's D = 4.
pub type Challenge = BinomialExtensionField<Val, 2>;

pub type Perm = Poseidon2Goldilocks<8>;
pub type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 4>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
pub type Dft = Radix2DitParallel<Val>;
/// Non-hiding PCS (default build).
#[cfg(not(feature = "zk"))]
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// Hiding PCS (`--features zk`; see [`crate::config`]).
#[cfg(feature = "zk")]
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, crate::zk_rng::ZkRng>;

/// Random codewords per committed matrix under `zk`: `[Challenge : Val] = 2`
/// (see `crate::config::NUM_RANDOM_CODEWORDS`).
#[cfg(feature = "zk")]
pub const NUM_RANDOM_CODEWORDS: usize =
    <Challenge as p3_field::BasedVectorSpace<Val>>::DIMENSION;

/// The StarkConfig used for every Goldilocks leaf STARK.
pub type StarkCfg = StarkConfig<Pcs, Challenge, Challenger>;

/// Build the canonical (seeded) Goldilocks Poseidon2 permutation used by both
/// the leaf STARK and the recursive verifier. Matches `GOLDILOCKS_D2_W8`.
pub fn make_perm() -> Perm {
    let mut rng = SmallRng::seed_from_u64(1);
    Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng)
}

/// FRI parameters — kept identical in shape to the BabyBear side
/// ([`crate::config`]) so `num_queries` (54) matches and the only variable in a
/// SS/GK verify-time comparison is the field/D/width, not the FRI budget.
/// Goldilocks² ≈ 2¹²⁸ ≥ BabyBear⁴ ≈ 2¹²⁴, so `SECURITY_LEVEL = 124` is sound here too.
pub const LOG_BLOWUP: usize = 2;
pub const MAX_LOG_ARITY: usize = 2;
pub const CAP_HEIGHT: usize = 0;
pub const COMMIT_POW_BITS: usize = 0;
pub const QUERY_POW_BITS: usize = 15;
pub const SECURITY_LEVEL: usize = 124;

pub fn num_queries() -> usize {
    (SECURITY_LEVEL - QUERY_POW_BITS) / LOG_BLOWUP
}

/// Construct the Poseidon2-based Goldilocks StarkConfig with two-adic FRI.
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
    #[cfg(feature = "zk")]
    let pcs = Pcs::new(
        dft,
        val_mmcs,
        fri_params,
        NUM_RANDOM_CODEWORDS,
        crate::zk_rng::ZkRng::from_os(),
    );
    let challenger = Challenger::new(perm);
    StarkCfg::new(pcs, challenger)
}
