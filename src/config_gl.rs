//! Goldilocks + Poseidon2 (width 8) + D=2 FRI StarkConfig for the `_gl` circuits.
//! Poseidon2 constants are seeded (`SmallRng::seed_from_u64(1)`) to match the fork's in-circuit AIR.

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
/// Non-hiding PCS (`--no-default-features`).
#[cfg(not(feature = "zk"))]
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// Hiding PCS (the default `zk` feature; see [`crate::config`]).
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

pub const fn num_queries() -> usize {
    (SECURITY_LEVEL - QUERY_POW_BITS) / LOG_BLOWUP
}

// The recursion fork's hiding budget on Goldilocks (`D = 2`, points `ζ`, `gζ`):
// `2(54 + 2·2) = 116 -> 128` rows, within the padded table height.
#[cfg(feature = "zk")]
const _: () = assert!(
    p3_circuit_prover::TablePacking::zk_hiding_budget(
        num_queries(),
        <Challenge as p3_field::BasedVectorSpace<Val>>::DIMENSION,
        2
    ) <= crate::config::MIN_TABLE_HEIGHT,
    "Goldilocks tables padded below the ZK hiding budget"
);

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
