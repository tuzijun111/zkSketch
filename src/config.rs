//! BabyBear + Poseidon2 + two-adic FRI StarkConfig.
//! The default `zk` feature uses `HidingFriPcs` with masked LogUp sums (zk-logup-mask forks).

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
/// Hiding PCS (the default `zk` feature).
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
/// trace, permutation and quotient matrix, which plays the role of a salt for
/// the unsalted Merkle MMCS (our heuristic, not an upstream guarantee). The
/// cost is 4 extra columns per matrix (and `R` gets `4 + 4`), negligible next
/// to the traces.
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

pub const fn num_queries() -> usize {
    (SECURITY_LEVEL - QUERY_POW_BITS) / LOG_BLOWUP
}

/// `log_final_poly_len` of every zkSketch `TablePacking`
/// (`with_fri_params(6, LOG_BLOWUP)`), hence the minimum table height
/// [`MIN_TABLE_HEIGHT`].
pub const PACKING_LOG_FINAL_POLY_LEN: usize = 6;

/// Height every circuit-prover table is padded to at least:
/// `2^(PACKING_LOG_FINAL_POLY_LEN + LOG_BLOWUP + 1) = 512`.
pub const MIN_TABLE_HEIGHT: usize = 1 << (PACKING_LOG_FINAL_POLY_LEN + LOG_BLOWUP + 1);

/// Whether this build's PCS is hiding (`zk` feature: `HidingFriPcs`).
pub const PCS_IS_HIDING: bool = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::ZK;

/// Provenance label of this build's PCS, `hiding` or `nonhiding` (env.json
/// and CSV `pcs`).
pub const fn pcs_label() -> &'static str {
    if PCS_IS_HIDING { "hiding" } else { "nonhiding" }
}

/// Base-field columns the core fork appends to a table's main trace per
/// global LogUp interaction in this build's proofs: `[Challenge : Val] = 4`
/// under `zk` (the masks), 0 without. Computed by the fork's own
/// `lookup_mask_width` under `zk`, so it reports what the linked fork does.
pub fn logup_mask_cols_per_interaction() -> usize {
    #[cfg(feature = "zk")]
    {
        zk_fork::mask_cols_per_interaction()
    }
    #[cfg(not(feature = "zk"))]
    {
        0
    }
}

/// Provenance label of the LogUp masking, `on` or `off` (env.json and CSV
/// `logup_mask`).
pub fn logup_mask_label() -> &'static str {
    if logup_mask_cols_per_interaction() > 0 { "on" } else { "off" }
}

/// The recursion fork's hiding budget for this configuration (`zk` only):
/// `2(q + D·2)` rounded up to a power of two, `2(54 + 8) = 124 -> 128` rows.
/// A `const` assertion checks it against [`MIN_TABLE_HEIGHT`].
#[cfg(feature = "zk")]
pub const ZK_HIDING_BUDGET: usize = zk_fork::HIDING_BUDGET;

/// Every non-test reference to the LogUp-mask forks: without them a `zk`
/// build does not compile.
#[cfg(feature = "zk")]
mod zk_fork {
    // An unresolved `lookup_mask_width` or `TablePacking::zk_hiding_budget`
    // here means a `zk` (default) build against the unforked Plonky3 /
    // Plonky3_RangeAir pins, which would prove with unmasked LogUp sums. Wire
    // in the `zk-logup-mask` forks (docs/build.md, "Zero knowledge";
    // `.cargo/config.toml.example`, Option 3) or build `--no-default-features`.
    use p3_circuit_prover::TablePacking;
    use p3_lookup::{Kind, Lookup, lookup_mask_width};

    use super::{Challenge, MIN_TABLE_HEIGHT, PCS_IS_HIDING, Val, num_queries};

    /// `[Challenge : Val]`.
    const CHALLENGE_DEGREE: usize = <Challenge as p3_field::BasedVectorSpace<Val>>::DIMENSION;
    /// Out-of-domain opening points of every zkSketch proof: `ζ` and `gζ`.
    const OPENING_POINTS: usize = 2;

    pub(super) const HIDING_BUDGET: usize =
        TablePacking::zk_hiding_budget(num_queries(), CHALLENGE_DEGREE, OPENING_POINTS);
    const _: () = assert!(HIDING_BUDGET <= MIN_TABLE_HEIGHT, "tables padded below the ZK hiding budget");

    /// The fork's masked width of one global interaction under this PCS.
    pub(super) fn mask_cols_per_interaction() -> usize {
        let probe = Lookup::<Val> {
            kind: Kind::Global(String::new()),
            elements: Vec::new(),
            multiplicities: Vec::new(),
            column: 0,
        };
        lookup_mask_width(core::slice::from_ref(&probe), CHALLENGE_DEGREE, PCS_IS_HIDING)
    }
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
    use p3_air::BaseAir;
    use p3_circuit_prover::PrimitiveTable;
    use p3_circuit_prover::air::{AluAir, ConstAir, PublicAir};
    use p3_field::BasedVectorSpace;
    use p3_lookup::Kind;

    use super::{
        Challenge, LOG_BLOWUP, MIN_TABLE_HEIGHT, PACKING_LOG_FINAL_POLY_LEN, PCS_IS_HIDING, Val,
        logup_mask_cols_per_interaction, logup_mask_label, num_queries, pcs_label,
    };

    /// Hiding budget of the ZK LogUp masks and of the hiding PCS:
    /// `2(q + 2D) <= 2^(6 + LOG_BLOWUP + 1)`, the height every table is padded
    /// to, on BabyBear (`D = 4`: 124 <= 512).
    #[test]
    fn hiding_budget_fits_the_padded_table_height() {
        let d = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
        let budget = 2 * (num_queries() + 2 * d);
        let padded = 1usize << (PACKING_LOG_FINAL_POLY_LEN + LOG_BLOWUP + 1);
        assert_eq!((num_queries(), d, budget, padded, MIN_TABLE_HEIGHT), (54, 4, 124, 512, 512));
        assert!(budget <= padded);
    }

    /// The fork's prover-side guard (`ZkTraceHeightBelowHidingBudget`) is
    /// computed for a DECLARED FRI query count (default 54), which must be
    /// this config's real one, and it must accept zkSketch's packing, on both
    /// fields (BabyBear `D = 4`, Goldilocks `D = 2`). `zk` only: it calls the
    /// recursion fork's budget API, which the non-ZK build does not need.
    #[cfg(feature = "zk")]
    #[test]
    fn hiding_budget_matches_the_fork_guard() {
        let packing = p3_circuit_prover::TablePacking::new(1, 2)
            .with_fri_params(PACKING_LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        assert_eq!(packing.zk_num_queries(), num_queries(), "declare the real FRI query count");
        assert_eq!(crate::config_gl::num_queries(), num_queries());
        assert_eq!(crate::config_gl::LOG_BLOWUP, LOG_BLOWUP);
        assert_eq!(packing.min_trace_height(), MIN_TABLE_HEIGHT);
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
        assert_eq!(super::ZK_HIDING_BUDGET, 128);
    }

    /// The masks are really in the proof: on a real Count-Min `omc` leaf,
    /// each primitive table's opened main width (`trace_local`, `trace_next`)
    /// is its AIR width (rebuilt from the proof's metadata, as the verifier
    /// does) plus `D = 4` columns per global interaction under `zk`, and
    /// exactly the AIR width without it; one revealed sum per global
    /// interaction. A `zk` build against unmasked forks would open the bare
    /// AIR width (it does not compile against them), so
    /// this is the lib suite's own check of the masks; the VK pins are not
    /// one.
    #[test]
    fn leaf_opens_logup_mask_columns() {
        use crate::recursion::recursive::statement::Expose;
        use crate::sketch::bind::Binding;
        use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
        use crate::sketch::countmin_omc::{CmOmcParams, build_countmin_omc_leaf_expose};

        const D: usize = 4;
        let cols = logup_mask_cols_per_interaction();
        assert_eq!(cols, if PCS_IS_HIDING { D } else { 0 });
        assert_eq!(
            (pcs_label(), logup_mask_label()),
            if PCS_IS_HIDING { ("hiding", "on") } else { ("nonhiding", "off") }
        );

        let params = CmOmcParams { d: 4, w: 8, batch: 4 };
        let prior = CountMinState {
            counters: vec![vec![0; params.w]; params.d],
            params: CountMinParams { d: params.d, w: params.w },
        };
        let batch = vec![
            CountMinUpdate { key: 5, value: 2 },
            CountMinUpdate { key: 2741, value: 7 },
            CountMinUpdate { key: 77, value: 1 },
            CountMinUpdate { key: 5, value: 4 },
        ];
        let leaf = build_countmin_omc_leaf_expose(params, Expose::None, Binding::Semantic).prove_epoch(prior, batch);
        let (proof, data) = (&leaf.output.0, &*leaf.output.1);
        let packing = &proof.table_packing;
        let w = proof.w_binomial.expect("degree-4 binomial extension");
        let air_widths = [
            (PrimitiveTable::Const, ConstAir::<Val, D>::new(proof.rows[PrimitiveTable::Const]).width()),
            (
                PrimitiveTable::Public,
                PublicAir::<Val, D>::new(proof.rows[PrimitiveTable::Public], packing.public_lanes()).width(),
            ),
            (
                PrimitiveTable::Alu,
                AluAir::<Val, D>::new_binomial(proof.rows[PrimitiveTable::Alu], packing.alu_lanes(), w)
                    .with_horner_pack_k(packing.horner_packed_steps())
                    .width(),
            ),
        ];
        for (i, (table, air_width)) in air_widths.into_iter().enumerate() {
            let globals = data.prover_data.common.lookups[i]
                .iter()
                .filter(|l| matches!(l.kind, Kind::Global(_)))
                .count();
            assert!(globals > 0, "{table:?}: has global interactions");
            assert_eq!(proof.proof.global_lookup_data[i].len(), globals, "{table:?}: one revealed sum each");
            let opened = &proof.proof.opened_values.instances[i].base_opened_values;
            let want = air_width + cols * globals;
            assert_eq!(opened.trace_local.len(), want, "{table:?}: opened main width (AIR {air_width}, {globals} globals)");
            assert_eq!(opened.trace_next.as_ref().map_or(want, Vec::len), want, "{table:?}: trace_next width");
        }
    }
}
