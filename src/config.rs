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
//! ### Zero knowledge (the `zk` feature, on by default)
//!
//! The default build is **hiding**: the `zk` Cargo feature (a default
//! feature; `--no-default-features` gives the plain `TwoAdicFriPcs`) swaps
//! in `HidingFriPcs` over the
//! SAME plain `MerkleTreeMmcs`, with the OS-seeded `ZkRng`
//! ([`crate::zk_rng`]) as its mask RNG and `NUM_RANDOM_CODEWORDS` random
//! codewords per commitment. Every leaf, merge, root and query proof is then
//! produced by the hiding PCS (the whole crate uses this one `Pcs`; the
//! recursion side follows in `recursion::recursive::config`). Degrees are
//! unchanged but every committed trace doubles (`is_zk`), so a table fits
//! only while its base height is `<= 2^24` (for `lq <= LOG_BLOWUP`; see
//! `experiments::table_probe`).
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
//! ### LogUp sums: masked per global interaction
//!
//! A batch proof reveals one LogUp cumulative sum per GLOBAL INTERACTION
//! (one `LookupData` in `BatchProof::global_lookup_data` per
//! `push_interaction` on a global bus, so several per table), not one per
//! table. Unmasked, each sum is a deterministic function of the witness and
//! of the lookup challenges, which anyone can recompute by replaying the
//! transcript, so a verifier could test witness guesses against it
//! (`tests/zk_logup_blinding.rs` runs that replay). Under `zk`, the Plonky3
//! core fork this crate builds against (branch `zk-logup-mask`, with the
//! matching `zk-logup-mask` branch of the recursion fork; README, "Zero
//! knowledge") masks every revealed sum:
//!
//! - each global interaction gets an extension-field mask `ρ`, whose
//!   `[Challenge : Val] = 4` base coefficients are appended to its table's
//!   main trace as constant columns (so 4 extra main columns per global
//!   interaction), committed in the main commitment strictly BEFORE the lookup
//!   challenges are sampled;
//! - the masks are drawn from the hiding PCS's RNG (the OS-seeded [`ZkRng`],
//!   which reseeds on clone) so that the masks of each bus sum to zero over
//!   the batch (a bus with one member gets `ρ = 0`);
//! - the proof reveals `c' = ρ + c` instead of the true sum `c`, the
//!   last-row LogUp constraint reads the mask, `(c' − ρ − s[n−1])·den − num
//!   = 0`, and the per-bus check `Σ c' = 0` is unchanged. For a bus with `t`
//!   members, the revealed sums are uniform on `{x ∈ EF^t : Σ x = 0}`,
//!   independent of the witness and of the challenges;
//! - every verifier (native, and the fork's in-circuit verifier) derives
//!   the masked main width from its own rebuilt lookups and its own `Pcs::ZK`,
//!   never from the proof.
//!
//! The non-ZK build (`--no-default-features`) does not mask and is
//! byte-identical to the unforked core (proofs and VKs). The ZK build's VKs
//! differ (wider main traces); the VK pin tests carry a table per build.
//!
//! ### Hiding budget (precondition)
//!
//! A randomized column of base height `n` stays hidden only while `n`
//! exceeds the number of linear functionals the verifier learns about it:
//! `D = 4` coefficients at each of the 2 out-of-domain points (`ζ`, `gζ`)
//! plus one value per FRI query, `q + 2D`. The fork requires the margin
//! `2(q + 2D)` rounded up to a power of two, `2(54 + 8) = 124 → 128`, and its
//! prover refuses a ZK proof whose packing pads tables to fewer rows
//! (`BatchStarkProverError::ZkTraceHeightBelowHidingBudget`). The pinned
//! `HidingFriPcs` does not check this itself. zkSketch pads every table to at
//! least `2^(6 + LOG_BLOWUP + 1) = 512` rows (`TablePacking::with_fri_params(6,
//! LOG_BLOWUP)`), and the fork's guard assumes 54 FRI queries, the value of
//! [`num_queries`]; `tests::hiding_budget_*` keeps both in step. A smaller
//! `log_final_poly_len`, `LOG_BLOWUP` or security level must re-check it.
//!
//! ### What is still not hidden, or only heuristic
//!
//! - Upstream calls `HidingFriPcs` only statistically zero-knowledge, and the
//!   plain-MMCS argument above is our heuristic, not an upstream guarantee.
//! - The masking is our construction on a fork, not upstream code; its
//!   argument assumes the opened functionals are independent on the random
//!   rows (the budget's factor 2 is a margin, not a proven tight bound).
//! - Table heights (`degree_bits`), hence operation and batch counts, are
//!   public; so are every Expose / NPO public value of a proof.
//! - Statement-level guess-and-check: with `ZKSKETCH_COMMIT=plain` the
//!   published state and batch commitments are unsalted Poseidon2 hashes.
//! - Masks share the PCS RNG: a seeded test RNG (or any RNG that replays on
//!   clone) must never be used for real proofs.
//! - Masking leaves LogUp soundness as it was, including the upstream gap
//!   that net multiplicities only balance mod `p` (an interaction's
//!   `count_weight` is not enforced); it neither creates nor fixes it.

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
/// Non-hiding PCS (`--no-default-features`).
#[cfg(not(feature = "zk"))]
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// Hiding PCS (the default `zk` feature; see the module docs).
#[cfg(feature = "zk")]
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, ZkRng>;

#[cfg(feature = "zk")]
pub use crate::zk_rng::ZkRng;

/// Random codewords `HidingFriPcs` appends to every committed matrix (`zk`
/// only): `[Challenge : Val] = 4` base-field columns.
///
/// The value follows upstream Plonky3: its ZK tests and example over
/// degree-4 fields all pass 4 (`batch-stark/tests/simple.rs`,
/// `uni-stark/tests/{fib_air,mul_air,mul_fib_pair,periodic_air}.rs`,
/// `poseidon2-air/examples/prove_poseidon2_baby_bear_keccak_zk.rs`); the
/// recursion fork's examples use 2 in functional tests.
///
/// It is not what masks the FRI batch. batch-stark does that with the
/// randomization polynomial `R` (core `batch-stark/src/prover.rs`, the
/// optional ZK commitment round): `HidingFriPcs` commits `R` once per
/// extended trace domain with `NUM_RANDOM_CODEWORDS + [Challenge : Val]`
/// random base columns (`get_opt_randomization_poly_commitment`), so every
/// FRI height carries at least `[Challenge : Val]` random columns whatever
/// this constant is. What it buys here is the entropy of each committed
/// Merkle leaf row: 4 random BabyBear values (about 124 bits) per row of every
/// trace, permutation and quotient matrix, which the plain-MMCS argument in
/// the module docs uses in place of a salt. The cost is 4 extra columns per
/// matrix (and `R` gets `4 + 4`), negligible next to the traces.
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

#[cfg(test)]
mod tests {
    use p3_circuit_prover::TablePacking;
    use p3_field::BasedVectorSpace;

    use super::{Challenge, LOG_BLOWUP, Val, num_queries};

    /// `log_final_poly_len` of every zkSketch `TablePacking`
    /// (`with_fri_params(6, LOG_BLOWUP)`).
    const LOG_FINAL_POLY_LEN: usize = 6;

    /// Hiding budget of the ZK LogUp masks and of the hiding PCS (see the
    /// module docs): `2(q + 2D) <= 2^(6 + LOG_BLOWUP + 1)`, the height every
    /// table is padded to, on BabyBear (`D = 4`: 124 <= 512).
    #[test]
    fn hiding_budget_fits_the_padded_table_height() {
        let d = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
        let budget = 2 * (num_queries() + 2 * d);
        let padded = 1usize << (LOG_FINAL_POLY_LEN + LOG_BLOWUP + 1);
        assert_eq!((num_queries(), d, budget, padded), (54, 4, 124, 512));
        assert!(budget <= padded);
    }

    /// The fork's prover-side guard (`ZkTraceHeightBelowHidingBudget`) is
    /// computed for a DECLARED FRI query count (default 54), which must be
    /// this config's real one, and it must accept zkSketch's packing, on both
    /// fields (BabyBear `D = 4`, Goldilocks `D = 2`).
    #[test]
    fn hiding_budget_matches_the_fork_guard() {
        let packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        assert_eq!(packing.zk_num_queries(), num_queries(), "declare the real FRI query count");
        assert_eq!(crate::config_gl::num_queries(), num_queries());
        assert_eq!(crate::config_gl::LOG_BLOWUP, LOG_BLOWUP);
        for d in [
            <Challenge as BasedVectorSpace<Val>>::DIMENSION,
            <crate::config_gl::Challenge as BasedVectorSpace<crate::config_gl::Val>>::DIMENSION,
        ] {
            let required = packing.zk_min_trace_height(d);
            assert!(required >= 2 * (num_queries() + 2 * d), "D = {d}");
            assert!(
                packing.min_trace_height() >= required,
                "D = {d}: tables padded to {} < hiding budget {required}",
                packing.min_trace_height()
            );
        }
        assert_eq!(packing.zk_min_trace_height(4), 128);
    }
}
