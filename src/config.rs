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

use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
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
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

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
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    StarkCfg::new(pcs, challenger)
}
